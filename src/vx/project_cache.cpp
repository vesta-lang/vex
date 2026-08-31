/**
 * @file project_cache.cpp
 * @brief Implementacion del cache de proyecto a nivel @c .velb ( M5.B).
 *
 * Cache file con magic VPCK + lista de (path, source_hash) de cada modulo
 * participante en el compile + el @c .velb final.  Lookup rapido:
 * leer la lista, recomputar FNV-1a de cada source, comparar con
 * cacheado.  Si todo matchea, cache hit; el caller copia el @c .velb
 * cacheado al output.
 */

#include "util/fnv.h"       // la semilla y el primo, en UN sitio
#include "util/env_flags.h" // los mandos que cambian lo emitido
#include "vx/project_cache.h"

#include "analysis/asa/fact_file.h"

#include <cstdio>
#include "util/fs_utils.h"
#include "vx/source_hash.h"
#include "vx/module/vxi_format.h" // para vxi_compiler_version_hash() (L.15)

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace vx {

namespace {

constexpr uint32_t VPC_MAGIC = 0x4B435056; // 'VPCK' LE
// v2 (M.L14+L15): añade compiler_version_hash u64 tras opts_hash.
constexpr uint16_t VPC_FORMAT_VERSION = 2;

void write_u16_le(std::vector<uint8_t> &out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}
void write_u32_le(std::vector<uint8_t> &out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}
void write_u64_le(std::vector<uint8_t> &out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

bool read_u16_le(const uint8_t *data, size_t size, size_t &off, uint16_t &v) {
    if (off + 2 > size) return false;
    v = static_cast<uint16_t>(data[off]) |
        (static_cast<uint16_t>(data[off + 1]) << 8);
    off += 2;
    return true;
}
bool read_u32_le(const uint8_t *data, size_t size, size_t &off, uint32_t &v) {
    if (off + 4 > size) return false;
    v = static_cast<uint32_t>(data[off]) |
        (static_cast<uint32_t>(data[off + 1]) << 8) |
        (static_cast<uint32_t>(data[off + 2]) << 16) |
        (static_cast<uint32_t>(data[off + 3]) << 24);
    off += 4;
    return true;
}
bool read_u64_le(const uint8_t *data, size_t size, size_t &off, uint64_t &v) {
    if (off + 8 > size) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(data[off + i]) << (i * 8);
    }
    off += 8;
    return true;
}

bool read_file_bytes_internal(const std::string &path,
                              std::vector<uint8_t> &out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    const std::streamsize sz = f.tellg();
    if (sz < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(sz));
    if (sz > 0) f.read(reinterpret_cast<char *>(out.data()), sz);
    return f.good();
}

bool write_file_atomic_internal(const std::string &path,
                                const std::vector<uint8_t> &bytes) {
    namespace fs = std::filesystem;
    static std::atomic<uint64_t> tmp_counter{0};
    try {
        fs::create_directories(fs::path(path).parent_path());
    } catch (...) { /* ignorar */
    }
    std::ostringstream suffix;
    suffix << ".tmp."
#ifdef _WIN32
           << static_cast<uint64_t>(GetCurrentProcessId())
#else
           << static_cast<uint64_t>(getpid())
#endif
           << "." << tmp_counter.fetch_add(1, std::memory_order_relaxed);
    const std::string tmp_path = path + suffix.str();
    {
        std::ofstream f(tmp_path, std::ios::binary);
        if (!f.is_open()) return false;
        if (!bytes.empty()) {
            f.write(reinterpret_cast<const char *>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
        }
        if (!f.good()) {
            f.close();
            std::error_code ec;
            fs::remove(tmp_path, ec);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp_path, path, ec);
    if (ec) {
        fs::copy_file(tmp_path, path, fs::copy_options::overwrite_existing, ec);
        fs::remove(tmp_path, ec);
        return !ec;
    }
    return true;
}

} // namespace

uint64_t fnv1a64_bytes(const uint8_t *data, size_t size) noexcept {
    // La semilla y el primo viven en util/fnv.h, no aqui.
    return util::fnv_bytes(util::kFnvOffset, data, size);
}

static uint32_t fnv1a32_str(const std::string &s) noexcept {
    uint32_t h = 0x811c9dc5U;
    for (char c : s) {
        h ^= static_cast<uint8_t>(c);
        h *= 0x01000193U;
    }
    return h;
}

std::string default_project_cache_dir() {
    namespace fs = std::filesystem;
    // Preferencia: VX_HOME/cache/projects, fallback ./.vx_cache/projects.
    if (const char *vh = std::getenv("VX_HOME")) {
        if (vh && vh[0]) {
            return (fs::path(vh) / "cache" / "projects").string();
        }
    }
    // Fallback al cwd actual.
    return (fs::current_path() / ".vx_cache" / "projects").string();
}

std::string project_cache_path(const std::string &root_path,
                               const std::string &cache_dir) {
    namespace fs = std::filesystem;
    // root_hash = FNV-1a 64 del path canonico.  Asi cada root tiene
    // su propio cache file estable.
    const uint64_t h = fnv1a64_bytes(
        reinterpret_cast<const uint8_t *>(root_path.data()), root_path.size());
    std::ostringstream fname;
    fname << std::hex << h << ".vpc";
    return (fs::path(cache_dir) / fname.str()).string();
}

uint32_t project_cache_opts_hash(const ProjectCacheKey &key) {
    // Concatenamos los campos en un string y hashing FNV-1a 32.  El
    // formato exacto del string no importa mientras sea estable.
    std::ostringstream os;
    os << "opt=" << key.opt_level << "|debug=" << (key.emit_debug ? 1 : 0)
       << "|base=0x" << std::hex << key.vx_base
       << "|instr=" << key.instrument_mode << "|port="
       << key.port_target
       /* Mismo motivo que en la clave por modulo: lo compilado SIN la maquina
        * de compilacion cargada es provisional (las funciones comptime no se
        * pudieron ejecutar) y no vale para la pasada buena. */
       << "|mc="
       << (key.comptime_prebuilt ? 1 : 0)
       /* De donde salen los modulos ajenos: con otro arbol de stdlib se
        * compilan OTROS ficheros, y los de antes siguen en su sitio -- la
        * comprobacion de las rutas guardadas pasaba igual. */
       << "|std=" << key.stdlib_dir << "|vxpath="
       << key.vx_path
       /* Que artefacto se pidio.  Va en la clave porque el cache guarda el
        * fichero FINAL: un `.velb` y un `.exe` no son intercambiables, ni un
        * `.exe` de x86-64 con uno de aarch64. */
       << "|aot=" << (key.aot ? 1 : 0) << "|arch=" << key.aot_arch
       << "|fmt=" << key.aot_format << "|emit=" << key.aot_emit
       << "|tgt=" << key.aot_target << "|tier=" << key.aot_tier << "|perfil="
       << key.aot_perfil
       /* Y los mandos del entorno que cambian lo EMITIDO.  Es la tercera lista
        * escrita a mano de "que cambia el artefacto", y ninguna de las tres
        * consultaba la huella que existe para justo eso.  Sin ella, compilar
        * con `VESTA_NO_SPEC_DEVIRT=1` y despues sin el devolvia el artefacto de
        * la primera vez, byte a byte: un binario que no corresponde a la
        * configuracion con la que se pidio, y sin un aviso.
        *
        * Vale cero cuando no hay ninguno puesto -- el caso normal --, asi que
        * no invalida nada de lo ya guardado. */
       << "|env=" << util::emitted_fingerprint();
    return fnv1a32_str(os.str());
}

uint32_t project_cache_diag_hash(const ProjectCacheKey &key) {
    /* Solo lo que cambia QUE CODIGO SE MIRA.  Ver la explicacion completa en
     * la cabecera: lo que unicamente cambia el envoltorio del artefacto
     * (formato, tipo de emision, direccion base, perfil) no altera ni un
     * aviso, y meterlo aqui guardaria lo mismo una vez por backend. */
    std::ostringstream os;
    os << "opt=" << key.opt_level << "|debug=" << (key.emit_debug ? 1 : 0)
       << "|instr=" << key.instrument_mode << "|port=" << key.port_target
       << "|mc=" << (key.comptime_prebuilt ? 1 : 0) << "|std=" << key.stdlib_dir
       << "|vxpath="
       << key.vx_path
       /* El OBJETIVO NO ENTRA.  Que un aviso venga de una rama que solo existe
        * en una arquitectura lo dice EL AVISO, en su ambito, y el lector lo
        * filtra.  Meterlo aqui obligaba a partir el fichero por lo mas grueso:
        * se duplicaba tambien todo lo universal -- que es la mayor parte --
        * para proteger lo poco que de verdad es especifico.  El nivel de
        * runtime SI entra, porque cambia que codigo se baja, no donde vale lo
        * sabido. */
       << "|tier=" << key.aot_tier << "|env=" << util::emitted_fingerprint();
    return fnv1a32_str(os.str());
}

bool project_cache_load(const std::string &cache_path, uint32_t &out_opts_hash,
                        std::vector<ProjectCacheDep> &out_deps,
                        std::vector<uint8_t> &out_velb) {
    out_opts_hash = 0;
    out_deps.clear();
    out_velb.clear();

    std::vector<uint8_t> buf;
    if (!read_file_bytes_internal(cache_path, buf)) return false;
    if (buf.size() < 24)
        return false; // header v2: magic+ver+pad+opts+cvh+dep_count

    size_t off = 0;
    uint32_t magic = 0;
    uint16_t version = 0, reserved = 0;
    uint32_t dep_count = 0;
    if (!read_u32_le(buf.data(), buf.size(), off, magic)) return false;
    if (!read_u16_le(buf.data(), buf.size(), off, version)) return false;
    if (!read_u16_le(buf.data(), buf.size(), off, reserved)) return false;
    if (!read_u32_le(buf.data(), buf.size(), off, out_opts_hash)) return false;
    //  M.L15: compiler_version_hash.  Si el binario del compilador
    // cambio (build distinto, version distinta), invalidar el cache.
    uint64_t cached_cvh = 0;
    if (!read_u64_le(buf.data(), buf.size(), off, cached_cvh)) return false;
    if (!read_u32_le(buf.data(), buf.size(), off, dep_count)) return false;
    if (magic != VPC_MAGIC) return false;
    if (version != VPC_FORMAT_VERSION) return false;
    if (cached_cvh != vxi_compiler_version_hash()) return false;
    if (dep_count > 100000) return false; // sanity

    out_deps.reserve(dep_count);
    for (uint32_t i = 0; i < dep_count; ++i) {
        uint32_t path_len = 0;
        if (!read_u32_le(buf.data(), buf.size(), off, path_len)) return false;
        if (path_len > 32768) return false;
        if (off + path_len > buf.size()) return false;
        ProjectCacheDep d;
        d.path.assign(reinterpret_cast<const char *>(buf.data() + off),
                      path_len);
        off += path_len;
        if (!read_u64_le(buf.data(), buf.size(), off, d.source_hash))
            return false;
        out_deps.push_back(std::move(d));
    }

    uint32_t velb_size = 0;
    if (!read_u32_le(buf.data(), buf.size(), off, velb_size)) return false;
    if (off + velb_size > buf.size()) return false;
    out_velb.assign(buf.data() + off, buf.data() + off + velb_size);
    return true;
}

bool project_cache_save(const std::string &cache_path, uint32_t opts_hash,
                        const std::vector<ProjectCacheDep> &deps,
                        const std::vector<uint8_t> &velb) {
    std::vector<uint8_t> buf;
    // Reserva pesimista para evitar reallocs.
    size_t est = 16;
    for (const auto &d : deps)
        est += 4 + d.path.size() + 8;
    est += 4 + velb.size();
    buf.reserve(est);

    write_u32_le(buf, VPC_MAGIC);
    write_u16_le(buf, VPC_FORMAT_VERSION);
    write_u16_le(buf, 0); // reserved
    write_u32_le(buf, opts_hash);
    //  M.L15: compiler_version_hash u64.  Si el compiler cambia
    // (cambio de version, reglas de mangling, ABI invariantes), el
    // cache se invalida automaticamente.  Reusa el mismo hash que
    // vxi_format.h usa para verificacion del .vxi (M5.b).
    write_u64_le(buf, vxi_compiler_version_hash());
    write_u32_le(buf, static_cast<uint32_t>(deps.size()));
    for (const auto &d : deps) {
        write_u32_le(buf, static_cast<uint32_t>(d.path.size()));
        buf.insert(buf.end(), d.path.begin(), d.path.end());
        write_u64_le(buf, d.source_hash);
    }
    write_u32_le(buf, static_cast<uint32_t>(velb.size()));
    buf.insert(buf.end(), velb.begin(), velb.end());

    return write_file_atomic_internal(cache_path, buf);
}

bool project_cache_validate(const std::vector<ProjectCacheDep> &cached_deps,
                            bool con_lineas) {
    // Para cada dep, abre el path en disco, calcula la huella de su CONTENIDO
    // CON SIGNIFICADO y la compara con la cacheada.  Si CUALQUIER archivo no
    // existe o la huella difiere, cache miss.
    for (const auto &d : cached_deps) {
        std::vector<uint8_t> bytes;
        if (!read_file_bytes_internal(d.path, bytes)) return false;
        const uint64_t h = hash_de_tokens(
            std::string(reinterpret_cast<const char *>(bytes.data()),
                        bytes.size()),
            con_lineas);
        if (h != d.source_hash) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  Diagnosticos que sobreviven al acierto de cache
// ---------------------------------------------------------------------------

namespace {

/// Dominio con el que se guardan.  Literal estable: el ASA compara por
/// direccion, asi que se da de alta como canonico antes de leer nada.
const char *const kDominioDiag = "vx.diagnosticos";

/// Separador entre el mensaje y los argumentos dentro de un solo campo.  Un
/// byte de control que no aparece en texto de usuario.
constexpr char kSep = '\x1f';

/**
 * @brief Ruta del fichero de diagnosticos que acompana a @p cache_path.
 *
 * La huella va en el NOMBRE y no solo dentro: asi el mismo proyecto compilado
 * para dos objetivos guarda los avisos de cada uno sin que el segundo pise los
 * del primero.  Si estuviera solo dentro, alternar entre objetivos seria un
 * fallo de cache permanente.
 */
std::string ruta_diags_(const std::string &cache_path, uint32_t diag_hash) {
    char hex[9];
    std::snprintf(hex, sizeof hex, "%08x", diag_hash);
    return cache_path + "." + hex + ".diags";
}

} // namespace

namespace {
/// Donde vive la nota de diagnostico de una entrada del cache.
std::string vxdbg_side_path(const std::string &cache_path) {
    return cache_path + ".vxdbg";
}
} // namespace

bool project_cache_save_vxdbg(const std::string &cache_path,
                              const std::string &map_hex,
                              const std::string &spans_hex) {
    // Sin mapa no hay nada que republicar; los tramos si son opcionales.
    if (map_hex.empty()) return false;
    const std::string body = map_hex + "\n" + spans_hex + "\n";
    return fs::write_file_atomic(
        vxdbg_side_path(cache_path),
        std::vector<uint8_t>(body.begin(), body.end()));
}

bool project_cache_load_vxdbg(const std::string &cache_path,
                              std::string &out_map_hex,
                              std::string &out_spans_hex) {
    out_map_hex.clear();
    out_spans_hex.clear();
    std::vector<uint8_t> bytes;
    if (!fs::read_file_bytes(vxdbg_side_path(cache_path), bytes)) return false;
    const std::string body(bytes.begin(), bytes.end());
    const size_t nl = body.find('\n');
    if (nl == std::string::npos) return false;
    out_map_hex = body.substr(0, nl);
    const size_t nl2 = body.find('\n', nl + 1);
    out_spans_hex = nl2 == std::string::npos
                        ? body.substr(nl + 1)
                        : body.substr(nl + 1, nl2 - nl - 1);
    return !out_map_hex.empty();
}

bool project_cache_save_diags(const std::string &cache_path, uint32_t diag_hash,
                              const std::vector<Diagnostic> &diags,
                              const analysis::asa::Scope &donde) {
    if (diags.empty()) return false;
    analysis::asa::register_canonical_name(kDominioDiag);
    analysis::asa::FactStore almacen;
    almacen.reserve(diags.size());
    for (const Diagnostic &d : diags) {
        analysis::asa::Fact f;
        f.what.domain = kDominioDiag;
        /* El CODIGO del catalogo, no el texto: es lo que permite volver a
         * formatearlo en el idioma de quien compile despues. */
        f.what.code = almacen.intern(d.code);
        /* Los cuatro numeros de la posicion en los dos campos que un hecho
         * tiene para ellos.  Empaquetados y no en el texto: son datos, y
         * meterlos en la cadena obligaria a parsearlos para volver a usarlos.
         * Hacen falta los cuatro -- sin el desplazamiento y la longitud, al
         * rehacer el aviso no se puede subrayar el trozo de codigo. */
        f.what.a = static_cast<int64_t>(
            (static_cast<uint64_t>(d.loc.offset) << 32) | d.loc.line);
        f.what.b = static_cast<int64_t>(
            (static_cast<uint64_t>(d.loc.length) << 32) | d.loc.column);
        std::string junto = d.message;
        for (const std::string &a : d.args) {
            junto.push_back(kSep);
            junto += a;
        }
        f.what.detail = almacen.intern(junto);
        f.about.kind = analysis::asa::Subject::Kind::Symbol;
        f.about.function = almacen.intern(d.loc.file);
        f.about.id = static_cast<uint32_t>(d.level);
        /* Certeza demostrada: no es una suposicion sobre el programa, es lo que
         * el compilador dijo.  Y la fuente es lo que lo distingue de un hecho
         * que alguien deduzca despues. */
        f.seal.certainty = analysis::asa::Certainty::Proven;
        f.seal.origin.producer = kDominioDiag;
        /* Donde vale.  Las cadenas se internan en el almacen: el ambito viaja
         * con el hecho, que es justo lo que permite que un solo fichero sirva a
         * todos los objetivos. */
        f.scope.isa = almacen.intern(donde.isa);
        f.scope.os = almacen.intern(donde.os);
        f.scope.backend = almacen.intern(donde.backend);
        /* Y por que se restringe, cuando se restringe: un diagnostico depende
         * del objetivo porque `@Target` descarta declaraciones segun el, asi
         * que lo que se avisa de un programa no tiene por que ser lo mismo en
         * otra arquitectura o en otro sistema. */
        if (!f.scope.universal()) f.scope.why = "diag.depende_del_objetivo";
        almacen.add(std::move(f));
    }
    /* Nivel maximo a proposito: esto NO se puede recalcular sin recompilar, que
     * es justo lo que el acierto de cache se ahorra. */
    const std::vector<uint8_t> bytes = analysis::asa::serialize(
        almacen, static_cast<uint64_t>(diag_hash),
        analysis::asa::CacheLevel::All, {{kDominioDiag, 0, false, 0}});
    if (bytes.empty()) return false;
    return ::fs::write_file_atomic(ruta_diags_(cache_path, diag_hash), bytes);
}

bool project_cache_load_diags(const std::string &cache_path, uint32_t diag_hash,
                              std::vector<Diagnostic> &out,
                              const analysis::asa::Scope &aqui) {
    out.clear();
    analysis::asa::register_canonical_name(kDominioDiag);
    analysis::asa::FactStore almacen;
    const analysis::asa::ReadResult r = analysis::asa::read_facts_file(
        ruta_diags_(cache_path, diag_hash), static_cast<uint64_t>(diag_hash),
        almacen, {}, 0, aqui);
    if (!r.ok) return false;
    out.reserve(almacen.size());
    for (analysis::asa::FactId i = 0; i < almacen.size(); ++i) {
        const analysis::asa::Fact &f = almacen.at(i);
        Diagnostic d;
        d.level = static_cast<DiagLevel>(f.about.id);
        d.loc.file = f.about.function;
        const uint64_t pa = static_cast<uint64_t>(f.what.a);
        const uint64_t pb = static_cast<uint64_t>(f.what.b);
        d.loc.line = static_cast<uint32_t>(pa & 0xFFFFFFFFu);
        d.loc.offset = static_cast<uint32_t>(pa >> 32);
        d.loc.column = static_cast<uint32_t>(pb & 0xFFFFFFFFu);
        d.loc.length = static_cast<uint32_t>(pb >> 32);
        d.code = f.what.code;
        const std::string junto = f.what.detail;
        size_t ini = junto.find(kSep);
        d.message = junto.substr(0, ini);
        while (ini != std::string::npos) {
            const size_t fin = junto.find(kSep, ini + 1);
            d.args.push_back(junto.substr(ini + 1, fin == std::string::npos
                                                       ? std::string::npos
                                                       : fin - ini - 1));
            ini = fin;
        }
        out.push_back(std::move(d));
    }
    return !out.empty();
}

} // namespace vx
