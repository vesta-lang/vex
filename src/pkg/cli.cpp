/**
 * @file cli.cpp
 * @brief Implementacion del despachador @c vm pkg ....
 */
#include "pkg/cli.h"
#include "pkg/ui.h"
#include "pkg/paths.h"
#include "pkg/manifest.h"
#include "pkg/lockfile.h"
#include "pkg/signature.h"
#include "pkg/resolver.h"
#include "pkg/fetcher.h"
#include "pkg/sha256.h"
#include "pkg/auditor.h"

#include "util/cache_paths.h" // el reparto de la cache por tipo y alcance

#include "vx/module/vxi_format.h"
#include <cstdio>
#include <cstdlib>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace pkg::cli {

namespace {
std::string read_file(const std::string &p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return std::string();
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
bool write_file(const std::string &p, const std::string &content) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return out.good();
}

/**
 * @brief Localiza el manifest del proyecto actual (toml o json).
 */
std::string find_project_manifest(std::string &out_format) {
    std::string root = paths::project_root("");
    if (root.empty()) return std::string();
    std::string toml_p = paths::join(root, "vx.toml");
    std::string json_p = paths::join(root, "vx.json");
    bool has_toml = paths::is_file(toml_p);
    bool has_json = paths::is_file(json_p);
    if (has_toml && has_json) {
        ui::error("ambos vx.toml y vx.json existen; elige uno y borra el otro");
        return std::string();
    }
    if (has_toml) {
        out_format = "toml";
        return toml_p;
    }
    if (has_json) {
        out_format = "json";
        return json_p;
    }
    return std::string();
}

std::string lockfile_path() {
    std::string root = paths::project_root("");
    if (root.empty()) return std::string();
    return paths::join(root, "vx.lock");
}

bool save_manifest(const std::string &path, const std::string &format,
                   const Manifest &m) {
    if (format == "toml") {
        return write_file(path, serialize_manifest_toml(m));
    }
    return write_file(path, serialize_manifest_json(m));
}
} // namespace

// ------------------------------------------------------------------
// init
// ------------------------------------------------------------------
static int cmd_init(const std::vector<std::string> &args) {
    bool json = false;
    for (const auto &a : args) {
        if (a == "--json") json = true;
    }
    std::string ext = json ? ".json" : ".toml";
    std::string out = "vx" + ext;
    if (paths::exists(out)) {
        ui::error("ya existe " + out + " en este directorio");
        return 1;
    }

    Manifest m;
    m.name = ui::prompt_line("nombre del paquete", "@me/app");
    m.version = ui::prompt_line("version", "0.1.0");
    std::string lic = ui::prompt_line("license", "MIT");
    m.license = lic;
    std::string author = ui::prompt_line("autor", "");
    if (!author.empty()) m.authors.push_back(author);
    m.edition = 1;

    std::string content =
        json ? serialize_manifest_json(m) : serialize_manifest_toml(m);

    if (!write_file(out, content)) {
        ui::error("no se pudo escribir " + out);
        return 1;
    }
    ui::ok("creado " + out);

    // Tambien crear .gitignore con vx_modules + caches.
    std::string gi = ".gitignore";
    if (!paths::exists(gi)) {
        /* Un solo directorio de cache: todo lo que el compilador y el gestor
         * generan vive dentro de `.cache`, repartido por tipo. */
        std::string body = "# Vesta package manager\n"
                           "vx_modules/\n"
                           ".cache/\n"
                           "*.velb\n"
                           "*.vel\n";
        write_file(gi, body);
        ui::info("creado .gitignore con vx_modules/ + caches");
    }
    return 0;
}

// ------------------------------------------------------------------
// install
// ------------------------------------------------------------------
static int cmd_install(const std::vector<std::string> &args) {
    bool allow_unsigned = false;
    for (const auto &a : args) {
        if (a == "--allow-unsigned") allow_unsigned = true;
    }

    std::string fmt;
    std::string mani_path = find_project_manifest(fmt);
    if (mani_path.empty()) {
        ui::error("no se encontro vx.toml ni vx.json en este proyecto");
        return 1;
    }

    ui::step("cargando manifest desde " + mani_path);
    auto pr = parse_manifest_file(mani_path);
    if (!pr.ok) {
        ui::error("manifest invalido: " + pr.error_msg);
        return 1;
    }

    auto vr = validate_manifest(pr.manifest);
    for (const auto &w : vr.warnings)
        ui::warn(w);
    if (!vr.ok) {
        for (const auto &e : vr.errors)
            ui::error(e);
        return 1;
    }

    ui::step("resolviendo dependencias");
    std::string work = util::cache_dir_under(paths::project_root(""),
                                             util::CacheKind::Work);
    paths::ensure_dir(work);

    auto pins = signing::load_trust_pins();
    auto res = resolver::resolve(pr.manifest, work, pins, allow_unsigned);
    for (const auto &w : res.warnings)
        ui::warn(w);
    if (!res.ok) {
        ui::error("resolucion fallida: " + res.error_msg);
        return 1;
    }

    ui::info("paquetes resueltos: " + std::to_string(res.deps.size()));

    // Construir lockfile + audit comparativo si existe lockfile previo.
    Lockfile new_lock = resolver::build_lockfile(res);
    Lockfile old_lock;
    std::string lp = lockfile_path();
    if (paths::exists(lp)) {
        auto lpr = parse_lockfile_file(lp);
        if (lpr.ok) old_lock = lpr.lock;
    }

    auto rep = audit::audit_lockfile(new_lock, old_lock, pins);
    if (!rep.findings.empty()) audit::print_report(rep);
    if (rep.critical_count > 0 && !allow_unsigned) {
        ui::error("auditoria critica detecto issues; usa --allow-unsigned para "
                  "forzar");
        return 1;
    }

    // Install: copiar/symlink al vx_modules.
    std::string vx_mods = paths::project_modules_dir("");
    paths::ensure_dir(vx_mods);

    ui::step("instalando paquetes a " + vx_mods);
    ui::Progress prog("installing", res.deps.size());
    size_t idx = 0;
    for (const auto &d : res.deps) {
        std::string dest = paths::join(vx_mods, d.name);
        std::replace(dest.begin(), dest.end(), '/', '_');
        fetcher::SourceSpec src;
        if (d.source_url.rfind("http", 0) == 0 ||
            d.source_url.rfind("git", 0) == 0 ||
            d.source_url.rfind("github.com/", 0) == 0) {
            src = fetcher::resolve_github_import(d.source_url);
            if (src.url.empty()) {
                src.kind = fetcher::SourceSpec::Git;
                src.url = d.source_url;
                src.rev = d.resolved_rev;
            }
        } else {
            src.kind = fetcher::SourceSpec::Path;
            src.url = d.source_url;
        }
        auto fr = fetcher::fetch(src, dest);
        if (!fr.ok) {
            ui::warn("dep " + d.name + ": " + fr.error_msg);
        }
        prog.set(++idx);
    }
    prog.done();

    // Persistir lockfile.
    if (!write_file(lp, serialize_lockfile(new_lock))) {
        ui::error("no se pudo escribir vx.lock");
        return 1;
    }
    ui::ok("vx.lock actualizado");
    return 0;
}

// ------------------------------------------------------------------
// list
// ------------------------------------------------------------------
static int cmd_list(const std::vector<std::string> &) {
    std::string lp = lockfile_path();
    if (!paths::exists(lp)) {
        ui::warn("sin vx.lock; ejecuta `vm pkg install` primero");
        return 1;
    }
    auto lpr = parse_lockfile_file(lp);
    if (!lpr.ok) {
        ui::error("lockfile invalido: " + lpr.error_msg);
        return 1;
    }
    ui::header("Dependencias instaladas");
    for (const auto &p : lpr.lock.packages) {
        std::cout << "  " << ui::pkg_name(p.name) << " "
                  << ui::pkg_version(p.version);
        if (!p.resolved_rev.empty() && p.resolved_rev != "local") {
            std::cout << " " << ui::short_hash(p.resolved_rev);
        }
        if (!p.author_fp.empty()) {
            std::cout << " by " << ui::short_hash(p.author_fp);
        }
        if (p.unsafe) {
            std::cout << " " << ui::yellow() << "[unsafe]" << ui::reset();
        }
        std::cout << "\n";
    }
    return 0;
}

// ------------------------------------------------------------------
// verify
// ------------------------------------------------------------------
static int cmd_verify(const std::vector<std::string> &) {
    std::string lp = lockfile_path();
    if (!paths::exists(lp)) {
        ui::warn("sin vx.lock; nada que verificar");
        return 1;
    }
    auto lpr = parse_lockfile_file(lp);
    if (!lpr.ok) {
        ui::error("lockfile invalido: " + lpr.error_msg);
        return 1;
    }
    std::string vx_mods = paths::project_modules_dir("");
    ui::header("Verificando integridad de paquetes");
    size_t ok_count = 0, fail = 0;
    for (const auto &p : lpr.lock.packages) {
        std::string dest = paths::join(vx_mods, p.name);
        std::replace(dest.begin(), dest.end(), '/', '_');
        if (!paths::exists(dest)) {
            ui::warn(p.name + ": no instalado");
            fail++;
            continue;
        }
        std::string actual = hash::sha256_tree(dest);
        if (!p.sha256.empty() && !hash::hash_equal_ct(actual, p.sha256)) {
            ui::error(p.name + ": sha256 mismatch -- posible tampering");
            fail++;
        } else {
            ui::ok(p.name + " verificado");
            ok_count++;
        }
    }
    ui::kv("ok", std::to_string(ok_count));
    ui::kv("fail", std::to_string(fail));
    return fail == 0 ? 0 : 1;
}

// ------------------------------------------------------------------
// audit
// ------------------------------------------------------------------
static int cmd_audit(const std::vector<std::string> &) {
    std::string lp = lockfile_path();
    if (!paths::exists(lp)) {
        ui::warn("sin vx.lock; nada que auditar");
        return 1;
    }
    auto lpr = parse_lockfile_file(lp);
    if (!lpr.ok) {
        ui::error("lockfile invalido: " + lpr.error_msg);
        return 1;
    }
    auto pins = signing::load_trust_pins();
    // Sin lockfile previo, comparar contra vacio (solo flags actuales).
    auto rep = audit::audit_lockfile(lpr.lock, Lockfile{}, pins);
    audit::print_report(rep);
    return rep.critical_count == 0 ? 0 : 2;
}

// ------------------------------------------------------------------
// keygen
// ------------------------------------------------------------------
static int cmd_keygen(const std::vector<std::string> &args) {
    std::string out;
    for (size_t i = 0; i + 1 < args.size(); ++i) {
        if (args[i] == "--out") out = args[i + 1];
    }
    if (out.empty()) {
        std::string keys = paths::private_keys_dir();
        paths::ensure_dir(keys);
        out = paths::join(keys, "default.pem");
    }

    signing::KeyPair kp;
    ui::Spinner sp("generando par Ed25519");
    if (!signing::generate_keypair(kp)) {
        sp.fail("EVP_PKEY_keygen fallo");
        return 1;
    }
    sp.done("OK");

    if (!signing::save_private_key(out, kp)) {
        ui::error("no se pudo escribir clave privada en " + out);
        return 1;
    }
    std::string fp = signing::fingerprint(kp.pub);
    ui::ok("clave privada guardada en " + out + " (chmod 600 en POSIX)");
    ui::kv("fingerprint", fp);
    ui::info(
        "comparte esta fingerprint con quienes vayan a verificar tus paquetes");
    return 0;
}

// ------------------------------------------------------------------
// trust list/add/revoke
// ------------------------------------------------------------------
static int cmd_trust(const std::vector<std::string> &args) {
    if (args.empty()) {
        ui::error("uso: vm pkg trust <list|add|revoke> ...");
        return 1;
    }
    const std::string &sub = args[0];
    if (sub == "list") {
        auto pins = signing::load_trust_pins();
        ui::header("Trust pins activos");
        if (pins.empty()) ui::info("(ninguno)");
        for (const auto &p : pins) {
            std::cout << "  "
                      << ui::pkg_name(p.author_name.empty() ? "(anonimo)"
                                                            : p.author_name)
                      << "  " << ui::short_hash(p.fingerprint);
            if (p.revoked)
                std::cout << " " << ui::red() << "[revoked]" << ui::reset();
            if (!p.pinned_at.empty())
                std::cout << "  " << ui::gray() << p.pinned_at << ui::reset();
            std::cout << "\n";
        }
        return 0;
    }
    if (sub == "add" && args.size() >= 2) {
        signing::TrustPin p;
        p.fingerprint = args[1];
        // optional --name
        for (size_t i = 2; i + 1 < args.size(); ++i) {
            if (args[i] == "--name") p.author_name = args[i + 1];
        }
        p.pinned_at = current_utc_iso8601();
        if (!signing::add_trust_pin(p)) {
            ui::error("no se pudo guardar trust pin");
            return 1;
        }
        ui::ok("pin guardado para " + p.fingerprint);
        return 0;
    }
    if (sub == "revoke" && args.size() >= 2) {
        if (!signing::revoke_trust_pin(args[1])) {
            ui::warn("no se encontro el pin " + args[1]);
            return 1;
        }
        ui::ok("pin revocado: " + args[1]);
        return 0;
    }
    ui::error("subcomando de trust desconocido");
    return 1;
}

// ------------------------------------------------------------------
// convert (toml<->json)
// ------------------------------------------------------------------
static int cmd_convert(const std::vector<std::string> &args) {
    if (args.empty()) {
        ui::error("uso: vm pkg convert <toml|json>");
        return 1;
    }
    const std::string &fmt = args[0];
    if (fmt != "toml" && fmt != "json") {
        ui::error("formato debe ser 'toml' o 'json'");
        return 1;
    }
    std::string cur_fmt;
    std::string mani = find_project_manifest(cur_fmt);
    if (mani.empty()) {
        ui::error("no hay manifest en este proyecto");
        return 1;
    }
    if (cur_fmt == fmt) {
        ui::info("manifest ya esta en formato " + fmt);
        return 0;
    }
    auto pr = parse_manifest_file(mani);
    if (!pr.ok) {
        ui::error("manifest invalido: " + pr.error_msg);
        return 1;
    }
    std::string new_path =
        paths::join(paths::project_root(""), std::string("vx.") + fmt);
    std::string body = fmt == "toml" ? serialize_manifest_toml(pr.manifest)
                                     : serialize_manifest_json(pr.manifest);
    if (!write_file(new_path, body)) {
        ui::error("no se pudo escribir " + new_path);
        return 1;
    }
    std::remove(mani.c_str());
    ui::ok("convertido a " + new_path);
    return 0;
}

// ------------------------------------------------------------------
// inspect <ruta.vxi>: dump del contenido de un fichero .vxi
// ------------------------------------------------------------------
static const char *kind_to_str(vx::VxiSymbolKind k) {
    switch (k) {
    case vx::VxiSymbolKind::TYPEDEF_ALIAS: return "typedef";
    case vx::VxiSymbolKind::TYPEDEF_NEW: return "typedef-new";
    case vx::VxiSymbolKind::STRUCT: return "struct";
    case vx::VxiSymbolKind::CLASS: return "class";
    case vx::VxiSymbolKind::ENUM: return "enum";
    case vx::VxiSymbolKind::GLOBAL_VAR: return "global";
    case vx::VxiSymbolKind::FUNCTION: return "fn";
    }
    return "?";
}

static const char *blob_kind_to_str(uint32_t k) {
    switch (static_cast<vx::VxiBlobKind>(k)) {
    case vx::VxiBlobKind::STRING: return "string";
    case vx::VxiBlobKind::ARRAY_PRIM: return "array_prim";
    case vx::VxiBlobKind::STRUCT_PRIM: return "struct_prim";
    case vx::VxiBlobKind::STRUCT_NESTED: return "struct_nested";
    case vx::VxiBlobKind::ARRAY_REF: return "array_ref";
    case vx::VxiBlobKind::TYPE_DESC: return "type_desc";
    case vx::VxiBlobKind::NONE: return "none";
    }
    return "?";
}

static int cmd_inspect(const std::vector<std::string> &args) {
    if (args.empty()) {
        ui::error("uso: vm pkg inspect <ruta.vxi>");
        return 1;
    }
    const std::string &path = args[0];
    if (!paths::is_file(path)) {
        ui::error("no es un fichero: " + path);
        return 1;
    }
    // Leer todo el fichero.
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        ui::error("no se pudo abrir: " + path);
        return 1;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string raw = ss.str();
    auto pr = vx::vxi_parse(reinterpret_cast<const uint8_t *>(raw.data()),
                            raw.size());
    if (!pr.ok) {
        ui::error("parse fallo: " + pr.error_message);
        return 1;
    }
    const vx::VxiModule &mod = pr.module_;

    ui::header("Inspeccion de " + path);
    ui::kv("format_version", std::to_string(mod.format_version));
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%016llx",
                      (unsigned long long)mod.abi_hash);
        ui::kv("abi_hash", buf);
        std::snprintf(buf, sizeof(buf), "0x%016llx",
                      (unsigned long long)mod.source_hash);
        ui::kv("source_hash", buf);
        std::snprintf(buf, sizeof(buf), "0x%016llx",
                      (unsigned long long)mod.compiler_version_hash);
        ui::kv("compiler_version_hash", buf);
    }
    ui::kv("package_id",
           mod.package_id.empty() ? std::string("(anonimo)") : mod.package_id);
    ui::kv("symbols", std::to_string(mod.symbols.size()));
    ui::kv("deps", std::to_string(mod.deps.size()));
    ui::kv("blob_pool_bytes", std::to_string(mod.blob_pool.size()));
    ui::kv("blob_pool_align",
           std::to_string(static_cast<unsigned>(mod.blob_pool_alignment)));

    // Dep table.
    if (!mod.deps.empty()) {
        ui::header("Dependencias");
        for (const auto &d : mod.deps) {
            char hh[32];
            std::snprintf(hh, sizeof(hh), "0x%016llx",
                          (unsigned long long)d.abi_hash);
            std::cout << "  " << ui::pkg_name(d.name) << "  "
                      << ui::short_hash(hh) << "\n";
        }
    }

    // Symbol table.
    ui::header("Simbolos");
    for (const auto &s : mod.symbols) {
        std::cout << "  " << ui::magenta() << kind_to_str(s.kind) << ui::reset()
                  << "  " << ui::pkg_name(s.name);
        // Tipo / firma.
        if (s.kind == vx::VxiSymbolKind::FUNCTION) {
            std::cout << "  " << ui::gray() << "(";
            for (size_t i = 0; i < s.param_types.size(); ++i) {
                if (i) std::cout << ", ";
                std::cout << s.param_types[i];
            }
            std::cout << ") -> " << s.return_type << ui::reset();
            if (s.is_extern) {
                std::cout << "  " << ui::yellow() << "[extern " << s.extern_lib
                          << "]" << ui::reset();
            }
        } else if (s.kind == vx::VxiSymbolKind::GLOBAL_VAR) {
            std::cout << "  " << ui::gray() << ": " << s.underlying_type
                      << ui::reset();
            if (s.is_const)
                std::cout << "  " << ui::cyan() << "const" << ui::reset();
            if (s.has_init_value) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), " = 0x%llx",
                              (unsigned long long)s.init_value);
                std::cout << ui::gray() << buf << ui::reset();
            }
            if (s.has_blob_ref) {
                std::cout << "  " << ui::cyan() << "[blob @" << s.blob_offset
                          << " " << blob_kind_to_str(s.blob_kind_hint) << "]"
                          << ui::reset();
                // Si es STRING, mostrar el contenido decodificado.
                if (s.blob_kind_hint ==
                    static_cast<uint8_t>(vx::VxiBlobKind::STRING)) {
                    const vx::VxiBlobHeader *bh =
                        vx::vxi_blob_read(mod.blob_pool, s.blob_offset);
                    const uint8_t *bp =
                        vx::vxi_blob_payload(mod.blob_pool, s.blob_offset);
                    if (bh && bp) {
                        std::string sv(reinterpret_cast<const char *>(bp),
                                       bh->count);
                        if (sv.size() > 60) sv = sv.substr(0, 60) + "...";
                        std::cout << "  " << ui::green() << "= \"" << sv << "\""
                                  << ui::reset();
                    }
                }
            }
            // Atributos (@hot/@cold/@align/@section).
            if ((s.attr_flags & 0x01) != 0)
                std::cout << "  " << ui::red() << "@hot" << ui::reset();
            if ((s.attr_flags & 0x02) != 0)
                std::cout << "  " << ui::blue() << "@cold" << ui::reset();
            if (s.attr_align != 0)
                std::cout << "  " << ui::cyan() << "@align(" << s.attr_align
                          << ")" << ui::reset();
            if (!s.attr_section.empty())
                std::cout << "  " << ui::cyan() << "@section(\""
                          << s.attr_section << "\")" << ui::reset();
        } else if (s.kind == vx::VxiSymbolKind::CLASS) {
            std::cout << "  " << ui::gray() << "size=" << s.size_bytes
                      << " fields=" << s.fields.size()
                      << " methods=" << s.methods.size() << ui::reset();
            if (!s.super_class.empty()) {
                std::cout << "  " << ui::cyan() << "extends " << s.super_class
                          << ui::reset();
            }
        } else if (s.kind == vx::VxiSymbolKind::ENUM) {
            std::cout << "  " << ui::gray() << "variants=" << s.variants.size()
                      << ui::reset();
        } else if (s.kind == vx::VxiSymbolKind::STRUCT) {
            std::cout << "  " << ui::gray() << "size=" << s.size_bytes
                      << " fields=" << s.fields.size() << ui::reset();
        }
        std::cout << "\n";
    }

    // Blob pool detalle si hay blobs.
    if (!mod.blob_pool.empty()) {
        ui::header("Blob pool");
        size_t off = 0;
        int blob_idx = 0;
        while (off + sizeof(vx::VxiBlobHeader) <= mod.blob_pool.size()) {
            const vx::VxiBlobHeader *bh =
                vx::vxi_blob_read(mod.blob_pool, static_cast<uint32_t>(off));
            if (!bh || bh->kind == 0) break;
            char hh[32];
            std::snprintf(hh, sizeof(hh), "0x%016llx",
                          (unsigned long long)bh->content_hash);
            std::cout << "  [" << blob_idx << "] @" << off << "  "
                      << ui::magenta() << blob_kind_to_str(bh->kind)
                      << ui::reset() << "  count=" << bh->count
                      << " bytes=" << bh->total_bytes << "  "
                      << ui::short_hash(hh) << "\n";
            off += sizeof(vx::VxiBlobHeader) + bh->total_bytes;
            // Padding al multiplo de 8.
            while (off % 8 != 0 && off < mod.blob_pool.size())
                ++off;
            blob_idx++;
            if (blob_idx > 1024) break; // defensa
        }
    }
    return 0;
}

// ------------------------------------------------------------------
// run <script>
// Ejecuta una entrada de @c [scripts] del manifest del proyecto
// actual.  Por seguridad solo se permiten comandos que invocan
// @c vm <args> (no shell arbitrario, no @c rm/curl/etc.).
// ------------------------------------------------------------------
static int cmd_run(const std::vector<std::string> &args) {
    if (args.empty()) {
        ui::error("uso: vm pkg run <nombre-script>");
        return 1;
    }
    std::string format;
    std::string mpath = find_project_manifest(format);
    if (mpath.empty()) {
        ui::error("no se encontro vx.toml ni vx.json en este proyecto");
        return 1;
    }
    ParseResult pr = parse_manifest_file(mpath);
    if (!pr.ok) {
        ui::error("manifest invalido: " + pr.error_msg);
        return 1;
    }
    const std::string &name = args[0];
    std::string cmdline;
    for (const auto &kv : pr.manifest.scripts) {
        if (kv.first == name) {
            cmdline = kv.second;
            break;
        }
    }
    if (cmdline.empty()) {
        ui::error("script '" + name + "' no esta en [scripts] del manifest");
        if (!pr.manifest.scripts.empty()) {
            ui::info("scripts disponibles:");
            for (const auto &kv : pr.manifest.scripts) {
                std::cerr << "  " << kv.first << "  =  " << kv.second << "\n";
            }
        }
        return 1;
    }
    // Soporte multi-comando via `&&`: scripts pueden encadenar
    // varios `vm ...` separados por ` && `.  Util para tests que
    // necesitan compilar + ejecutar en un solo comando.  Cada
    // sub-comando se valida individualmente con la misma whitelist
    // (debe empezar con "vm ").  Si cualquier sub-comando falla
    // (exit != 0), abortamos sin ejecutar los siguientes (semantica
    // shell estandar de @c && ).
    //
    // Resolver path absoluto del binario @c vm que esta ejecutando
    // ahora.  Asi @c vm pkg run build invoca al mismo binario sin
    // depender del PATH.
    std::string vm_exe;
#ifdef _WIN32
    {
        char buf[1024];
        DWORD n = GetModuleFileNameA(nullptr, buf, sizeof(buf));
        if (n > 0 && n < sizeof(buf)) vm_exe = std::string(buf, n);
    }
#else
    vm_exe = "vm";
#endif
    if (vm_exe.empty()) vm_exe = "vm";
    const bool need_quote = vm_exe.find(' ') != std::string::npos;

    // Helper: dividir cmdline en sub-comandos por " && ".  El delimitador
    // tiene espacios alrededor para no partir argumentos con "&&" interno.
    std::vector<std::string> sub_cmds;
    {
        std::string buf;
        size_t pos = 0;
        while (pos < cmdline.size()) {
            size_t found = cmdline.find(" && ", pos);
            if (found == std::string::npos) {
                sub_cmds.push_back(cmdline.substr(pos));
                break;
            }
            sub_cmds.push_back(cmdline.substr(pos, found - pos));
            pos = found + 4;
        }
    }

    // Args extra del usuario aplican solo al ULTIMO sub-comando
    // (semantica intuitiva: `vesta pkg run tests -v` -> el -v va al
    // comando final que es el que produce output).
    std::string extra_args;
    for (size_t i = 1; i < args.size(); ++i) {
        extra_args += " ";
        extra_args += args[i];
    }

    for (size_t si = 0; si < sub_cmds.size(); ++si) {
        std::string sub = sub_cmds[si];
        // Trim leading/trailing whitespace.
        while (!sub.empty() && (sub.front() == ' ' || sub.front() == '\t'))
            sub.erase(sub.begin());
        while (!sub.empty() && (sub.back() == ' ' || sub.back() == '\t'))
            sub.pop_back();
        // Seguridad: cada sub-comando debe empezar con "vm " o "vesta "
        // (la VM puede instalarse como cualquiera de los dos nombres).
        // Sin esto cualquier paquete podria ejecutar @c rm/curl/etc.
        size_t off = 0;
        if (sub.size() >= 3 && sub.rfind("vm ", 0) == 0) {
            off = 3;
        } else if (sub.size() >= 6 && sub.rfind("vesta ", 0) == 0) {
            off = 6;
        } else {
            ui::error("scripts solo pueden invocar 'vm <args>' o 'vesta "
                      "<args>'; recibido: " +
                      sub);
            return 1;
        }
        std::string args_str = sub.substr(off);
        std::string full;
        if (need_quote)
            full = "\"" + vm_exe + "\"";
        else
            full = vm_exe;
        full += " ";
        full += args_str;
        // Solo el ULTIMO sub-comando recibe los args extra del CLI.
        if (si + 1 == sub_cmds.size()) full += extra_args;
        ui::info("ejecutando: " + full);
        int rc = std::system(full.c_str());
        if (rc != 0) {
            ui::error("sub-comando fallo (rc=" + std::to_string(rc) +
                      "): " + full);
            return rc == 0 ? 1 : (rc & 0xFF);
        }
    }
    return 0;
}

// ------------------------------------------------------------------
// dispatcher
// ------------------------------------------------------------------
int run_args(const std::vector<std::string> &args) {
    ui::init();
    if (args.empty()) {
        ui::error("uso: vm pkg <subcomando>");
        ui::info("subcomandos: init, install, list, verify, audit, trust, "
                 "keygen, convert, inspect, run");
        return 1;
    }
    std::vector<std::string> rest(args.begin() + 1, args.end());
    const std::string &cmd = args[0];

    if (cmd == "init") return cmd_init(rest);
    if (cmd == "install") return cmd_install(rest);
    if (cmd == "list") return cmd_list(rest);
    if (cmd == "verify") return cmd_verify(rest);
    if (cmd == "audit") return cmd_audit(rest);
    if (cmd == "trust") return cmd_trust(rest);
    if (cmd == "keygen") return cmd_keygen(rest);
    if (cmd == "convert") return cmd_convert(rest);
    if (cmd == "inspect") return cmd_inspect(rest);
    if (cmd == "run") return cmd_run(rest);

    ui::error("subcomando desconocido: " + cmd);
    return 1;
}

int run(int argc, char **argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i)
        args.emplace_back(argv[i]);
    return run_args(args);
}

} // namespace pkg::cli
