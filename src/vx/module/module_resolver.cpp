/**
 * @file module_resolver.cpp
 * @brief Implementacion del resolver de paths + dep graph ( M).
 *
 * Optimizaciones aplicadas:
 *   - Cache de resolucion por path-hash (FNV-1a 64): segunda resolucion
 *     del mismo modulo es O(1) sin tocar el filesystem.
 *   - Single-pass normalization: la version canonica del path se computa
 *     UNA vez por modulo y se reusa.
 *   - DFS coloreado WHITE/GRAY/BLACK: O(V+E) para ciclos + topo en una
 *     sola pasada.
 *   - Lectura de fichero binary-safe (no asume \0 terminator interno).
 *   - Reserva anticipada de vectores (avoids realloc en hot paths).
 */

#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include "vx/source_text.h"
#include "util/env_flags.h"
#include "vx/module/module_resolver.h"

#include "vx/lexer.h"
#include "vx/parser.h"
#include "vx/token.h"
#include "vx/diag/diag_format.h" // los mensajes salen del catalogo
#include "pkg/paths.h"           // $VX_HOME: el override del usuario

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_set>

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#define VX_PATH_SEP_ENV ';'
#define VX_F_OK 0
// _access en Windows.
static inline bool vx_file_access_ok(const char *p) {
    return _access(p, 0) == 0;
}
#else
#include <unistd.h>
#define VX_PATH_SEP_ENV ':'
static inline bool vx_file_access_ok(const char *p) {
    return access(p, F_OK) == 0;
}
#endif

#include "vx/ast.h"
#include "vx/lexer.h"
#include "vx/parser.h"
#include "util/fs_utils.h"

namespace vx {

/**
 * @brief De que PAQUETE es un fichero: el manifiesto que lo cobija.
 *
 * Sube por los directorios desde @p root_path buscando `vx.toml` / `vx.json` y
 * saca su identidad (`id` explicito, o `name@version` resumido).  Sin
 * manifiesto, anonimo.
 *
 * Vive aqui y no en el compilador de proyecto porque la identidad de un paquete
 * es parte de RESOLVER que modulo es cual: dos arboles que declaran el mismo
 * namespace son la misma libreria encontrada dos veces si dicen ser el mismo
 * paquete, y dos librerias distintas si no.  Quien resuelve necesita saberlo.
 *
 * @param root_path Ruta de un fichero (se empieza por su directorio).
 * @return Identidad del paquete, o cadena vacia si no hay manifiesto.
 */
std::string derive_package_id(const std::string &root_path,
                              std::string *manifiesto_usado) {
    namespace fs = std::filesystem;
    if (manifiesto_usado) manifiesto_usado->clear();
    // Normalizar + obtener el directorio del root.
    std::string norm = root_path;
    for (char &c : norm)
        if (c == '\\') c = '/';
    std::error_code ec;
    /* ABSOLUTA antes de subir.  Con una ruta relativa -- `memory.vx`, o la
     * raiz `.` -- el primer `parent_path()` ya da vacio y el bucle sale sin
     * mirar nada: el paquete salia ANoNIMO aunque tuviera su manifiesto justo
     * encima.  Se noto porque dos arboles distintos parecian el mismo paquete
     * (los dos anonimos) y la regla que los distingue acertaba por casualidad.
     */
    fs::path abs = fs::absolute(fs::path(norm), ec);
    if (ec) abs = fs::path(norm);
    fs::path dir = abs.lexically_normal().parent_path();
    std::string manifest;
    for (int depth = 0; depth < 32 && !dir.empty(); ++depth) {
        for (const char *fname : {"vx.toml", "vx.json"}) {
            fs::path cand = dir / fname;
            if (fs::exists(cand, ec) && fs::is_regular_file(cand, ec)) {
                std::ifstream f(cand.string(), std::ios::binary);
                if (f) {
                    std::stringstream ss;
                    ss << f.rdbuf();
                    manifest = ss.str();
                }
                if (manifiesto_usado)
                    *manifiesto_usado = cand.lexically_normal().string();
                break;
            }
        }
        if (!manifest.empty()) break;
        fs::path parent = dir.parent_path();
        if (parent == dir) break; // llegamos a la raiz del FS
        dir = parent;
    }
    if (manifest.empty()) return {}; // sin manifest -> anonimo

    // Scan minimo del [package]: name / version / id.  Acepta TOML
    // (`key = "val"`) y JSON (`"key": "val"`) de forma tolerante: extraemos
    // el primer string tras el nombre de la clave.
    auto extract = [&](const std::string &key) -> std::string {
        // Buscar la clave como token de palabra.
        size_t pos = 0;
        while ((pos = manifest.find(key, pos)) != std::string::npos) {
            // Verificar que es un limite de palabra por la izquierda.
            bool lok = (pos == 0) ||
                       (!std::isalnum((unsigned char)manifest[pos - 1]) &&
                        manifest[pos - 1] != '_');
            size_t after = pos + key.size();
            bool rok = after >= manifest.size() ||
                       (!std::isalnum((unsigned char)manifest[after]) &&
                        manifest[after] != '_');
            if (lok && rok) {
                // Buscar el primer '"' tras la clave en la misma logica linea.
                size_t q1 = manifest.find('"', after);
                size_t nl = manifest.find('\n', after);
                if (q1 != std::string::npos &&
                    (nl == std::string::npos || q1 < nl)) {
                    size_t q2 = manifest.find('"', q1 + 1);
                    if (q2 != std::string::npos) {
                        return manifest.substr(q1 + 1, q2 - q1 - 1);
                    }
                }
            }
            pos = after;
        }
        return {};
    };
    const std::string explicit_id = extract("id");
    if (!explicit_id.empty()) return explicit_id;
    const std::string name = extract("name");
    if (name.empty()) return {};
    const std::string version = extract("version");
    const std::string ident = name + "@" + version;
    // FNV-1a 64 sobre name@version -> hex.  Mismo esquema que abi_hash.
    const uint64_t h =
        util::fnv_bytes(util::kFnvOffset, ident.data(), ident.size());
    char buf[19];
    std::snprintf(buf, sizeof(buf), "pkg:%012llx",
                  (unsigned long long)(h & 0xFFFFFFFFFFFFull));
    return std::string(buf);
}

std::string override_de_paquete(const std::string &nombre) {
    /* Se lee UNA vez: es un fichero por maquina que no cambia a mitad de una
     * compilacion, y consultarlo por cada dependencia seria abrirlo N veces. */
    static const std::map<std::string, std::string> tabla = [] {
        std::map<std::string, std::string> t;
        const std::string home = pkg::paths::vx_home();
        if (home.empty()) return t;
        std::ifstream f(home + "/config.toml", std::ios::binary);
        if (!f) return t;
        std::string linea;
        bool dentro = false;
        while (std::getline(f, linea)) {
            // Recortar espacios por los dos lados.
            size_t a = linea.find_first_not_of(" \t\r");
            if (a == std::string::npos) continue;
            size_t b = linea.find_last_not_of(" \t\r");
            const std::string s = linea.substr(a, b - a + 1);
            if (s.empty() || s[0] == '#') continue;
            if (s[0] == '[') {
                dentro = (s == "[override]");
                continue;
            }
            if (!dentro) continue;
            const size_t eq = s.find('=');
            if (eq == std::string::npos) continue;
            std::string clave = s.substr(0, eq);
            while (!clave.empty() &&
                   (clave.back() == ' ' || clave.back() == '\t'))
                clave.pop_back();
            const size_t q1 = s.find('"', eq);
            if (q1 == std::string::npos) continue;
            const size_t q2 = s.find('"', q1 + 1);
            if (q2 == std::string::npos) continue;
            if (!clave.empty()) t[clave] = s.substr(q1 + 1, q2 - q1 - 1);
        }
        return t;
    }();
    auto it = tabla.find(nombre);
    return it == tabla.end() ? std::string() : it->second;
}

// Autodetecta el directorio de la stdlib Vesta.  Misma logica que usaba
// compiler_project.cpp inline; factorizada aqui para que el LSP (indices de
// modulos importados) la reuse sin duplicar la sonda.
/**
 * @brief Deja una ruta en forma absoluta y sin `.` ni `..`.
 *
 * La ruta de la stdlib acaba siendo la base de la @c canonical_path de cada
 * modulo de la biblioteca, y esa se documenta -- y se usa -- como absoluta:
 * es la que viaja al editor como ubicacion de un simbolo y la que entra en la
 * clave de la cache.  Una relativa solo significa lo mismo mientras nadie
 * cambie de directorio de trabajo, y quien la recibe ya no esta en el proceso
 * que la resolvio.
 *
 * @param ruta Ruta candidata, absoluta o relativa al directorio de trabajo.
 * @return La misma ubicacion en forma absoluta; la ruta original si el sistema
 *         no puede resolverla.
 */
static std::string absolutizar_(const std::string &ruta) {
    if (ruta.empty()) return ruta;
    std::error_code ec;
    std::filesystem::path abs =
        std::filesystem::absolute(std::filesystem::path(ruta), ec);
    if (ec) return ruta;
    return abs.lexically_normal().string();
}

std::string detect_stdlib_vx_dir() {
    std::string sd;
    /* (1) La variable de entorno: lo mas inmediato, para un script o una
     * prueba suelta.  Manda sobre todo lo demas justamente por eso. */
    sd = util::flag_text(util::FlagId::StdlibDir);
    if (!sd.empty()) return absolutizar_(sd);
    /* (2) El override del usuario: se dice UNA vez por maquina y vale para
     * todos sus proyectos sin tocar ninguno.  Es lo que necesita quien
     * desarrolla el propio compilador, que tiene la stdlib de trabajo en un
     * sitio y la instalada en otro. */
    {
        const std::string ov = override_de_paquete("std");
        if (!ov.empty()) return absolutizar_(ov);
    }
    // (2) Candidatos relativos al cwd.
    static const char *cands[] = {"stdlib/vx", "../stdlib/vx",
                                  "../../stdlib/vx"};
    for (const char *c : cands) {
        std::ifstream test(std::string(c) + "/simd_string.vx");
        if (test.good()) return absolutizar_(c);
    }
    // (3) Candidatos relativos al ejecutable (instalacion + build-tree).
    std::string exe = fs::get_executable_path();
    if (!exe.empty()) {
        std::filesystem::path ed = std::filesystem::path(exe).parent_path();
        const std::filesystem::path exe_cands[] = {
            ed / "stdlib" / "vx", ed.parent_path() / "stdlib" / "vx"};
        for (const auto &c : exe_cands) {
            std::ifstream test((c / "simd_string.vx").string());
            if (test.good()) return absolutizar_(c.string());
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// FNV-1a 64-bit.  Constante recomendada por Eric Niebler / FNV reference.
// Coste hot path: ~1ns por byte en CPUs modernos.  No usamos xxhash/wyhash
// para no añadir dep externa; FNV-1a es suficiente para path hashing
// (sin colisiones esperadas en proyectos de <1M modulos).
// ---------------------------------------------------------------------------
uint64_t ModuleGraph::fnv1a_(const std::string &s) noexcept {
    constexpr uint64_t OFFSET = 0xCBF29CE484222325ULL;
    constexpr uint64_t PRIME = 0x100000001B3ULL;
    uint64_t h = OFFSET;
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= PRIME;
    }
    return h;
}

// ---------------------------------------------------------------------------
// Detection de path absoluto: cross-platform.
//   POSIX: empieza con '/'
//   Windows: empieza con '/' o '\\' o tiene drive letter "X:" en pos 1.
// ---------------------------------------------------------------------------
bool ModuleGraph::is_absolute_(const std::string &path) noexcept {
    if (path.empty()) return false;
    if (path[0] == '/' || path[0] == '\\') return true;
#if defined(_WIN32)
    if (path.size() >= 2 &&
        ((path[0] >= 'A' && path[0] <= 'Z') ||
         (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':') {
        return true;
    }
#endif
    return false;
}

// ---------------------------------------------------------------------------
// Lectura de fichero a string.  Lee binary-safe.  Devuelve false en error.
// ---------------------------------------------------------------------------
void ModuleGraph::set_source_overlay(const std::string &path,
                                     const std::string &text) {
    // Normalizar igual que los paths canonicos (build_from_root usa
    // normalize_path_(root_file, "")), asi la clave del overlay coincide con
    // el @c canonical_path que llega a read_file_.
    source_overlay_[normalize_path_(path, "")] = text;
}

bool ModuleGraph::read_file_(const std::string &path, std::string &out) {
    /* Por el MISMO lector que todo lo demas, con los fines de linea ya
     * normalizados.
     *
     * Aqui se leia el fichero en crudo, asi que en Windows el parser veia un
     * texto con `
` y sus offsets eran de ESE texto -- mientras que quien
     * luego recortaba fuente por offset leia el normalizado.  Dos textos, uno
     * mas corto que el otro, y las posiciones de uno aplicadas al otro: cada
     * fin de linea anterior corria el corte un byte, asi que caia DENTRO de un
     * token y cuanto mas avanzado el fichero, peor.  Se veia como un conjunto
     * comptime extraido que no compilaba, con cadenas cortadas por la mitad.
     *
     * Normalizar en un solo sitio es ademas lo que hace que las posiciones que
     * se citan en los diagnosticos no dependan del sistema donde se compile. */
    return vx::leer_fuente(path, out);
}

bool ModuleGraph::file_exists_(const std::string &path) noexcept {
    return vx_file_access_ok(path.c_str());
}

namespace {

/// Identidad de un fichero: donde ESTA, no como se escribio.
///
/// El mismo fichero se alcanza por varias rutas -- relativa desde el directorio
/// del root, absoluta desde la stdlib -- y tomando la escritura como identidad
/// entraba dos veces en el grafo.  Eso duplicaba cada diagnostico suyo y, en un
/// namespace repartido entre varios ficheros, dejaba una de las dos copias sin
/// fusionar: sus tipos no resolvian aunque el fichero hermano estuviera
/// cargado.
///
/// Se usa SOLO para decidir si dos rutas son el mismo fichero; los mensajes
/// siguen mostrando la ruta tal y como se escribio, que es la que el usuario
/// reconoce.
std::string identidad_fichero_(const std::string &ruta) {
    namespace fs = std::filesystem;
    /* Camino rapido: una ruta que ya es absoluta y no arrastra `.` ni `..` no
     * necesita ni consultar el directorio actual ni normalizarse otra vez.  Es
     * el caso de casi todas las llamadas -- llegan de `normalize_path_`, que ya
     * hizo ese trabajo -- y aquellas dos operaciones, repetidas una vez por
     * fichero del arbol, eran la mayor parte del escaneo. */
    std::string s;
    const bool absoluta =
        !ruta.empty() && (ruta[0] == '/' || ruta[0] == '\\' ||
                          (ruta.size() >= 2 && ruta[1] == ':' &&
                           ((ruta[0] >= 'A' && ruta[0] <= 'Z') ||
                            (ruta[0] >= 'a' && ruta[0] <= 'z'))));
    if (absoluta && ruta.find("/.") == std::string::npos &&
        ruta.find("\\.") == std::string::npos) {
        s = ruta;
    } else {
        std::error_code ec;
        fs::path p = fs::absolute(fs::path(ruta), ec);
        if (ec) p = fs::path(ruta);
        s = p.lexically_normal().string();
    }
    for (char &c : s) {
        if (c == '\\') c = '/';
#if defined(_WIN32)
        // El sistema de ficheros no distingue mayusculas: dos escrituras que
        // solo difieren en eso son el mismo fichero.
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
#endif
    }
    return s;
}

} // namespace

// ---------------------------------------------------------------------------
// Normalizacion de paths.  Pasos:
//   1. Si no es absoluto, prefijar con base_dir + "/".
//   2. Reemplazar '\\' por '/'.
//   3. Colapsar '//' a '/'.
//   4. Resolver "./" (eliminarlos).
//   5. Resolver "../" subiendo un nivel.  Si excede la raiz, error
//      silente (deja el path tal cual; el filesystem lo rechazara).
// ---------------------------------------------------------------------------
std::string ModuleGraph::normalize_path_(const std::string &raw,
                                         const std::string &base_dir) const {
    std::string p;
    p.reserve(raw.size() + base_dir.size() + 8);

    // Paso 1: combinar con base_dir si raw es relativo.
    if (is_absolute_(raw)) {
        p = raw;
    } else {
        if (!base_dir.empty()) {
            p = base_dir;
            if (p.back() != '/' && p.back() != '\\') {
                p += '/';
            }
        }
        p += raw;
    }
    // Paso 2: normalizar separadores.
    for (char &c : p) {
        if (c == '\\') c = '/';
    }
    // Paso 3 + 4 + 5: tokenizar por '/' y reconstruir.
    std::vector<std::string> parts;
    parts.reserve(16);
    std::string cur;
#if defined(_WIN32)
    // Preservar drive letter "X:" como primer token (no procesarlo).
    std::string drive;
    if (p.size() >= 2 && p[1] == ':') {
        drive = p.substr(0, 2);
        p.erase(0, 2);
    }
#endif
    const bool root_abs = !p.empty() && p[0] == '/';

    for (size_t i = 0; i <= p.size(); ++i) {
        if (i == p.size() || p[i] == '/') {
            if (!cur.empty()) {
                if (cur == ".") {
                    // skip
                } else if (cur == "..") {
                    if (!parts.empty() && parts.back() != "..") {
                        parts.pop_back();
                    } else if (!root_abs) {
                        parts.push_back(cur);
                    }
                    // Si root_abs y stack vacio, descartamos ".." (no se
                    // puede subir mas alla de '/').
                } else {
                    parts.push_back(std::move(cur));
                }
                cur.clear();
            }
        } else {
            cur += p[i];
        }
    }

    // Reconstruir.
    std::string out;
    out.reserve(p.size());
#if defined(_WIN32)
    out += drive;
#endif
    if (root_abs) out += '/';
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out += '/';
        out += parts[i];
    }
    if (out.empty()) out = ".";
    return out;
}

// ---------------------------------------------------------------------------
// ModuleGraph: ctor + config de search paths.
// ---------------------------------------------------------------------------
ModuleGraph::ModuleGraph(Diagnostics &diags) : diags_(diags) {
    modules_.reserve(32); // pre-reservar para evitar reallocs tempranas
    search_paths_.reserve(8);
}

void ModuleGraph::add_search_path(const std::string &dir) {
    if (dir.empty()) return;
    search_paths_.push_back(normalize_path_(dir, ""));
}

void ModuleGraph::add_vx_path_env() {
    /* El registro ya devuelve cadena vacia cuando no esta puesta, en los dos
     * sistemas: sobraba la rama condicional, que hacia lo mismo dos veces. */
    const std::string s = util::flag_text(util::FlagId::VxPath);
    if (s.empty()) return;
    // Tokenizar por VX_PATH_SEP_ENV.
    std::string cur;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == VX_PATH_SEP_ENV) {
            if (!cur.empty()) {
                add_search_path(cur);
                cur.clear();
            }
        } else {
            cur += s[i];
        }
    }
}

void ModuleGraph::set_stdlib_dir(const std::string &dir) {
    stdlib_dir_ = normalize_path_(dir, "");
}

// ---------------------------------------------------------------------------
// collect_expr_param_fns_: recorre las decls de un modulo (recursivo dentro de
// NamespaceDecl) y anota, por cada FunctionDecl con params @c expr, el mapa
// `nombre -> [posiciones]`.  Usado para sembrar el parser de los modulos que
// importan estas funciones (cross-module expr-capture).  Reusa el AST YA
// parseado del dep; no re-parsea nada.
// ---------------------------------------------------------------------------
static void collect_expr_param_fns_(
    const std::vector<std::unique_ptr<ast::Node>> &decls,
    std::unordered_map<std::string, std::vector<int>> &out) {
    for (const auto &d : decls) {
        if (!d) continue;
        if (d->kind == ast::NodeKind::FunctionDecl) {
            auto *fd = static_cast<ast::FunctionDecl *>(d.get());
            std::vector<int> pos;
            for (size_t i = 0; i < fd->params.size(); ++i) {
                if (fd->params[i] && fd->params[i]->is_expr_capture)
                    pos.push_back(static_cast<int>(i));
            }
            if (!pos.empty()) out[fd->name] = std::move(pos);
        } else if (d->kind == ast::NodeKind::StructDecl) {
            // Un struct cuyo constructor recibe la expresion sin evaluar
            // cuenta igual que una funcion: al ver `T(algo)` el parser tiene
            // que capturar el TEXTO en vez de interpretarlo.  Faltaba, asi
            // que con el tipo importado se interpretaba -- y un numero mas
            // ancho que la palabra se truncaba antes de llegar al
            // constructor.
            auto *sd = static_cast<ast::StructDecl *>(d.get());
            for (const auto &m_up : sd->methods) {
                const auto *m = m_up.get();
                if (!m || !m->is_constructor) continue;
                std::vector<int> pos;
                for (size_t i = 0; i < m->params.size(); ++i) {
                    if (m->params[i] && m->params[i]->is_expr_capture)
                        pos.push_back(static_cast<int>(i));
                }
                if (!pos.empty()) {
                    // Se registra por los DOS nombres: el consumidor escribe
                    // el local (`U`) y el declarado puede venir ya cualificado
                    // (`test__uu__U`).  El parser busca por lo que se escribio,
                    // asi que registrar solo uno deja el otro sin capturar.
                    out[sd->name] = pos;
                    const size_t sep = sd->name.rfind("__");
                    if (sep != std::string::npos && sep + 2 < sd->name.size())
                        out[sd->name.substr(sep + 2)] = pos;
                    break;
                }
            }
        } else if (d->kind == ast::NodeKind::NamespaceDecl) {
            collect_expr_param_fns_(
                static_cast<ast::NamespaceDecl *>(d.get())->decls, out);
        }
    }
}

// ---------------------------------------------------------------------------
// collect_type_names_: recorre las decls de un modulo ya parseado (recursivo
// dentro de NamespaceDecl) y anota el NOMBRE de cada tipo que declara.
//
// El parser necesita saber que nombres son tipos para reconocer `(T) x` como un
// CAST y no como una expresion entre parentesis, y por si solo unicamente
// conoce los declarados en el fichero que esta parseando.  Sin esto, un cast a
// un tipo de otro fichero --incluso del MISMO namespace, partido en varios--
// no parseaba y el usuario recibia un error de sintaxis que no apuntaba a nada
// ("se esperaba ';'").
//
// Reusa el AST YA parseado del dep, igual que collect_expr_param_fns_: no
// re-parsea nada.
// ---------------------------------------------------------------------------
static void
collect_type_names_(const std::vector<std::unique_ptr<ast::Node>> &decls,
                    std::unordered_set<std::string> &out) {
    for (const auto &d : decls) {
        if (!d) continue;
        switch (d->kind) {
        case ast::NodeKind::TypeAliasDecl:
            out.insert(static_cast<ast::TypeAliasDecl *>(d.get())->name);
            break;
        case ast::NodeKind::StructDecl:
            out.insert(static_cast<ast::StructDecl *>(d.get())->name);
            break;
        case ast::NodeKind::ClassDecl:
            out.insert(static_cast<ast::ClassDecl *>(d.get())->name);
            break;
        case ast::NodeKind::EnumDecl:
            out.insert(static_cast<ast::EnumDecl *>(d.get())->name);
            break;
        case ast::NodeKind::NamespaceDecl:
            collect_type_names_(
                static_cast<ast::NamespaceDecl *>(d.get())->decls, out);
            break;
        default: break;
        }
    }
}

// gather_public_reexports_: recolecta (path, by_namespace) de las sentencias
// `public import` (re-export) de un modulo ya parseado (recursivo dentro de
// NamespaceDecl).  Sirve para seguir la CADENA de re-exports al sembrar los
// params @c expr: una fn `source(expr)` re-exportada por std.comptime desde
// std.comptime.basics debe seguir siendo capturada como texto crudo en el
// modulo que importa std.comptime.
static void
gather_public_reexports_(const std::vector<std::unique_ptr<ast::Node>> &decls,
                         std::vector<std::pair<std::string, bool>> &out) {
    for (const auto &d : decls) {
        if (!d) continue;
        if (d->kind == ast::NodeKind::ImportDecl) {
            auto *im = static_cast<ast::ImportDecl *>(d.get());
            if (im->is_public_reexport && !im->path.empty())
                out.emplace_back(im->path, im->by_namespace);
        } else if (d->kind == ast::NodeKind::NamespaceDecl) {
            gather_public_reexports_(
                static_cast<ast::NamespaceDecl *>(d.get())->decls, out);
        }
    }
}

// ---------------------------------------------------------------------------
// scan_import_paths_: escaneo BARATO (solo lex, sin parse) de las sentencias
// `import` de un fichero.  Devuelve (path, by_namespace) por cada import.
// Permite resolver los deps ANTES de parsear el cuerpo del modulo, para
// sembrar los params @c expr de las fns importadas.  Cubre `import a.b.c;`,
// `import "path";`, `public import ...;` y la forma selectiva `a.b.{...}`.
// ---------------------------------------------------------------------------
static std::vector<std::pair<std::string, bool>>
scan_import_paths_(const std::string &source) {
    std::vector<std::pair<std::string, bool>> out;
    Diagnostics tmp; // sumidero desechable: no reportamos errores de lex aqui
    Lexer lex(source, "<import-scan>", tmp);
    Token t = lex.next();
    // `@Target("...")` que precede a un import: si la condicion NO aplica al
    // target activo, ese import no es una dependencia.  El parser completo ya
    // lo descarta, pero este escaneo (solo-lex) alimenta el GRAFO de deps, asi
    // que sin esto el modulo se compilaba y se mezclaba igualmente -- p.ej. la
    // variante x86-32 de un modulo por-arch acababa en un binario x86-64.
    bool skip_next_import = false;
    while (t.kind != TokenKind::END_OF_FILE) {
        if (t.kind == TokenKind::AT) {
            Token name = lex.next();
            if (name.kind != TokenKind::IDENTIFIER || name.lexeme != "Target") {
                t = name;
                continue;
            }
            Token lp = lex.next();
            if (lp.kind != TokenKind::LPAREN) {
                t = lp;
                continue;
            }
            const Token sp = lex.next();
            std::string spec;
            if (sp.kind == TokenKind::STRING_LIT ||
                sp.kind == TokenKind::RAW_STRING_LIT)
                spec = sp.str_val;
            if (sp.kind != TokenKind::RPAREN) (void)lex.next(); // ')'
            if (!spec.empty() && !target_expr_matches(spec))
                skip_next_import = true;
            t = lex.next();
            continue;
        }
        if (t.kind == TokenKind::KW_IMPORT) {
            if (skip_next_import) {
                // Descartar la sentencia entera (hasta el `;`).
                while (t.kind != TokenKind::SEMICOLON &&
                       t.kind != TokenKind::END_OF_FILE)
                    t = lex.next();
                skip_next_import = false;
                if (t.kind != TokenKind::END_OF_FILE) t = lex.next();
                continue;
            }
            Token nxt = lex.next();
            if (nxt.kind == TokenKind::STRING_LIT ||
                nxt.kind == TokenKind::RAW_STRING_LIT) {
                out.emplace_back(nxt.str_val, /*by_namespace=*/false);
                t = lex.next();
                continue;
            }
            if (nxt.kind == TokenKind::IDENTIFIER) {
                std::string ns = nxt.lexeme;
                t = lex.next();
                // path punteado a.b.c; parar en `.{` (lista selectiva).
                while (t.kind == TokenKind::DOT) {
                    Token after = lex.next();
                    if (after.kind != TokenKind::IDENTIFIER) {
                        t = after; // `.{...}` o error: cerrar el path
                        break;
                    }
                    ns += ".";
                    ns += after.lexeme;
                    t = lex.next();
                }
                out.emplace_back(std::move(ns), /*by_namespace=*/true);
                continue;
            }
            t = nxt;
            continue;
        }
        // Cualquier token que no sea `public` rompe la adyacencia
        // `@Target(...) [public] import` -> el pendiente caduca.
        if (t.kind != TokenKind::KW_PUBLIC) skip_next_import = false;
        t = lex.next();
    }
    return out;
}

// ---------------------------------------------------------------------------
// Carga + parse de un modulo.  Crea ResolvedModule, computa hashes,
// invoca lex + parse.  No procesa las deps todavia (eso lo hace
// process_dependencies_ tras añadir el modulo al graph).
// ---------------------------------------------------------------------------
uint32_t ModuleGraph::load_and_parse_(const std::string &canonical_path) {
    // La clave es DONDE esta el fichero, no como se escribio la ruta: la misma
    // unidad alcanzada por dos rutas distintas tiene que ser un solo modulo.
    const uint64_t path_hash = fnv1a_(identidad_fichero_(canonical_path));

    // Hit del cache: ya cargado antes (cada modulo se parsea una sola vez).
    auto it = by_path_hash_.find(path_hash);
    if (it != by_path_hash_.end()) {
        return it->second;
    }

    // Leer fichero.  Overlay LSP: si hay texto inyectado en memoria para este
    // path (buffer del editor con ediciones sin guardar), usarlo en vez del
    // disco.  read_file_ es static, asi que el overlay se resuelve aqui.
    std::string source;
    bool got_source = false;
    if (!source_overlay_.empty()) {
        auto ov = source_overlay_.find(canonical_path);
        if (ov != source_overlay_.end()) {
            source = ov->second;
            got_source = true;
        }
    }
    if (!got_source && !read_file_(canonical_path, source)) {
        SourceLoc l;
        l.set_file(canonical_path);
        diags_.error(l, "no se pudo leer el modulo: '" + canonical_path + "'");
        return UINT32_MAX;
    }

    // Crear entrada.  Reservar id ANTES de parsear para que un import
    // del propio fichero (auto-import) detecte el ciclo correctamente.
    auto mod = std::make_unique<ResolvedModule>();
    mod->module_id = static_cast<uint32_t>(modules_.size());
    mod->canonical_path = canonical_path;
    mod->path_hash = path_hash;
    mod->source_hash = fnv1a_(source);

    // Extraer module_name = ultimo segmento sin extension.
    size_t slash = canonical_path.find_last_of('/');
    std::string base = (slash == std::string::npos)
                           ? canonical_path
                           : canonical_path.substr(slash + 1);
    size_t dot = base.find_last_of('.');
    mod->module_name = (dot == std::string::npos) ? base : base.substr(0, dot);

    //  M.L22: paquete-dir.  Si el filename es `mod.vx`, el modulo
    // logico es el directorio parent.  Asi `pkg_lib/mod.vx` se llama
    // `pkg_lib` (no `mod`), coincidiendo con el nombre que el consumer
    // usa al hacer `import "pkg_lib"`.
    if (mod->module_name == "mod" && slash != std::string::npos) {
        const std::string parent = canonical_path.substr(0, slash);
        const size_t parent_slash = parent.find_last_of('/');
        const std::string parent_name = (parent_slash == std::string::npos)
                                            ? parent
                                            : parent.substr(parent_slash + 1);
        if (!parent_name.empty()) {
            mod->module_name = parent_name;
        }
    }

    const uint32_t id = mod->module_id;
    by_path_hash_.emplace(path_hash, id);
    modules_.push_back(std::move(mod));

    // Cross-module expr-capture: ANTES de parsear el cuerpo, resolver los
    // imports (barato: solo lex) y cargar los deps para conocer sus fns con
    // param @c expr.  El parser las necesita para capturar el texto crudo del
    // argumento en vez de parsearlo como expresion (un `source(asm ...)`
    // importado no parsearia).  load_and_parse_ DEDUPLICA (by_path_hash_) ->
    // cada modulo se parsea UNA sola vez: reusa la cache de parseo, no
    // re-parsea.  Coste en el caso comun (imports sin fns expr) = un lookup
    // por dep.  La entrada de ESTE modulo ya esta reservada (id arriba), asi
    // que un ciclo de imports se corta por el dedup.
    std::unordered_map<std::string, std::vector<int>> imported_expr_params;
    // Nombres de TIPO visibles desde este modulo (typedefs, structs, clases,
    // enums de los deps).  El parser los necesita para reconocer `(T) x` como
    // un cast: sin ellos solo conoce los tipos declarados en el FICHERO
    // actual, asi que un `(tag) 10` con `tag` declarado en otro fichero --del
    // mismo namespace, incluso-- no parseaba y daba un error de sintaxis
    // desconcertante ("se esperaba ';'").
    std::unordered_set<std::string> imported_type_names;
    {
        // Worklist de module_ids a inspeccionar: los imports directos + la
        // cadena de `public import` (re-exports) transitiva.  Asi una fn `expr`
        // re-exportada (std.comptime -> std.comptime.basics::source) tambien se
        // siembra en el importador de std.comptime.
        std::unordered_set<uint32_t> visited_dep;
        std::vector<uint32_t> worklist;
        auto resolve_to_id = [&](const std::string &p, bool by_ns,
                                 const std::string &importer) -> uint32_t {
            ResolveResult r =
                by_ns ? resolve_namespace_(p, importer) : resolve(p, importer);
            if (r.status != ResolveResult::Status::OK) return UINT32_MAX;
            if (r.module_id >= modules_.size()) return UINT32_MAX;
            return r.module_id;
        };
        for (const auto &ip : scan_import_paths_(source)) {
            uint32_t did = resolve_to_id(ip.first, ip.second, canonical_path);
            if (did != UINT32_MAX) worklist.push_back(did);
        }
        while (!worklist.empty()) {
            const uint32_t dep_id = worklist.back();
            worklist.pop_back();
            if (!visited_dep.insert(dep_id).second) continue;
            ResolvedModule *dep = modules_[dep_id].get();
            if (!dep || !dep->parsed_ast) continue;
            collect_expr_param_fns_(dep->parsed_ast->decls,
                                    imported_expr_params);
            collect_type_names_(dep->parsed_ast->decls, imported_type_names);
            // Seguir los `public import` del dep (re-export transitivo).
            std::vector<std::pair<std::string, bool>> reexp;
            gather_public_reexports_(dep->parsed_ast->decls, reexp);
            for (const auto &rp : reexp) {
                uint32_t rid =
                    resolve_to_id(rp.first, rp.second, dep->canonical_path);
                if (rid != UINT32_MAX) worklist.push_back(rid);
            }
        }
    }

    // Namespaces parciales: los tipos que declaran los ficheros HERMANOS --los
    // que contribuyen al mismo namespace que este-- son visibles aqui sin
    // ningun import, asi que el parser tambien tiene que conocerlos.
    {
        std::vector<std::string> mis_ns;
        extract_namespaces_(source, mis_ns);
        if (!mis_ns.empty()) {
            build_namespace_index_();
            for (const auto &ns : mis_ns) {
                auto itt = ns_types_.find(ns);
                if (itt == ns_types_.end()) continue;
                for (const auto &n : itt->second)
                    imported_type_names.insert(n);
            }
        }
    }

    // Lex + parse.  Cada modulo reusa el mismo Diagnostics del graph para
    // que los errores aparezcan agregados al final del build.
    Lexer lexer(source, canonical_path, diags_);
    Parser parser(lexer, diags_);
    if (!imported_expr_params.empty())
        parser.seed_imported_expr_params(imported_expr_params);
    // Los tipos visibles desde los deps: sin esto `(T) x` con T de otro
    // fichero no se reconoce como cast.
    for (const auto &tn : imported_type_names)
        parser.add_known_alias(tn);
    auto ast = parser.parse_program();
    if (!ast) {
        SourceLoc l;
        l.set_file(canonical_path);
        diags_.error(l, "error al parsear el modulo: '" + canonical_path + "'");
        return UINT32_MAX;
    }
    modules_[id]->parsed_ast = std::move(ast);
    return id;
}

// ---------------------------------------------------------------------------
// resolve(): aplica las reglas de busqueda en orden y devuelve el primer
// candidato existente, o NOT_FOUND con la lista de paths intentados.
// ---------------------------------------------------------------------------
ResolveResult ModuleGraph::resolve(const std::string &raw_path,
                                   const std::string &importer_file) {
    ResolveResult res;

    // Derivar el directorio del importador.
    std::string importer_dir;
    if (!importer_file.empty()) {
        std::string norm = importer_file;
        for (char &c : norm)
            if (c == '\\') c = '/';
        size_t slash = norm.find_last_of('/');
        if (slash != std::string::npos) {
            importer_dir = norm.substr(0, slash);
        }
    }

    // Construir lista ordenada de candidatos.
    std::vector<std::string> candidates;
    candidates.reserve(4 + search_paths_.size());

    //  M.L22: paquete-dir.  Para cada base_dir, intentamos primero
    // `base_dir/raw_path.vx` (modulo single-file) y luego
    // `base_dir/raw_path/mod.vx` (paquete-dir).  El segundo convenio
    // permite agrupar varios .vx bajo `std/io/` con un entry point.
    // El nombre del modulo importado sigue siendo `raw_path` (e.g.
    // `std/io`) -- no cambia la semantica del consumer.
    auto add_candidate = [&](const std::string &base_dir) {
        // (a) modulo single-file.  La extension del lenguaje Vesta es `.vx`.
        candidates.push_back(normalize_path_(raw_path + ".vx", base_dir));
        // (b) paquete-dir: base_dir/raw_path/mod.vx (entry point del paquete).
        candidates.push_back(normalize_path_(raw_path + "/mod.vx", base_dir));
    };

    // 1. Carpeta del importador.
    add_candidate(importer_dir);
    // 2. Search paths añadidos (VX_PATH + adds explicitos).
    for (const auto &sp : search_paths_) {
        add_candidate(sp);
    }
    // 3. Stdlib (solo si raw_path empieza con "std/" o si se busca el resto).
    if (!stdlib_dir_.empty()) {
        add_candidate(stdlib_dir_);
    }

    // Probar cada candidato.
    for (const auto &c : candidates) {
        res.tried_paths.push_back(c);
        if (file_exists_(c)) {
            const uint32_t id = load_and_parse_(c);
            if (id == UINT32_MAX) {
                res.status = ResolveResult::Status::PARSE_ERROR;
                res.error_message = "fallo al cargar/parsear: " + c;
                return res;
            }
            res.status = ResolveResult::Status::OK;
            res.module_id = id;
            return res;
        }
    }

    // NOT_FOUND con lista de paths intentados.
    res.status = ResolveResult::Status::NOT_FOUND;
    std::string msg =
        "modulo '" + raw_path + "' no encontrado. Paths probados:";
    for (const auto &c : res.tried_paths) {
        msg += "\n  - " + c;
    }
    res.error_message = std::move(msg);
    return res;
}

// ---------------------------------------------------------------------------
// process_dependencies_: recorre el AST buscando ImportDecls, los resuelve,
// y popula mod.dependencies con los module_ids correspondientes.
//
// Recursivo: cada modulo importado se parsea (via load_and_parse_) y luego
// se procesan sus deps tambien.  La proteccion contra ciclos vive en
// topological_order via DFS coloreado (no aqui).
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
//  NS.2-full: extraccion ligera de los namespaces declarados en un
// source .vx.  Lexemos (sin parsear) y buscamos el patron:
//   KW_NAMESPACE IDENT (DOT IDENT)* (SEMICOLON | LBRACE)
// Cubre la forma statement `namespace a.b.c;` y la forma bloque
// `namespace a.b.c { ... }`.  Un mismo fichero puede declarar varios.
// ---------------------------------------------------------------------------
void ModuleGraph::extract_namespaces_(
    const std::string &source, std::vector<std::string> &out,
    std::unordered_map<std::string, std::vector<std::string>> *types_by_ns) {
    // Namespace en curso mientras recorremos el fichero: los tipos se atribuyen
    // al que este vigente, no a todos los del fichero.
    std::string cur_ns;
    auto anota_tipo = [&](const std::string &nombre) {
        if (!types_by_ns || nombre.empty() || cur_ns.empty()) return;
        auto &v = (*types_by_ns)[cur_ns];
        if (std::find(v.begin(), v.end(), nombre) == v.end())
            v.push_back(nombre);
    };
    // Diagnostics throwaway: el lex no debe emitir errores relevantes aqui;
    // si los hay, los ignoramos (el parse real reportara).
    Diagnostics scratch;
    Lexer lex(source, "<ns-scan>", scratch);
    Token t = lex.next();
    while (t.kind != TokenKind::END_OF_FILE) {
        if (t.kind == TokenKind::KW_NAMESPACE) {
            Token id = lex.next();
            if (id.kind != TokenKind::IDENTIFIER) {
                t = id;
                continue;
            }
            std::string ns = id.lexeme;
            Token nxt = lex.next();
            while (nxt.kind == TokenKind::DOT) {
                Token seg = lex.next();
                if (seg.kind != TokenKind::IDENTIFIER) break;
                ns += ".";
                ns += seg.lexeme;
                nxt = lex.next();
            }
            // nxt deberia ser SEMICOLON o LBRACE; en cualquier caso el ns ya
            // esta completo.  Registramos si no esta duplicado.
            if (std::find(out.begin(), out.end(), ns) == out.end()) {
                out.push_back(ns);
            }
            cur_ns = ns;
            t = nxt;
            continue;
        }
        if (types_by_ns) {
            if (t.kind == TokenKind::KW_TYPEDEF) {
                // El nombre es el ultimo identificador a nivel 0 antes del
                // `;`.  Saltar el interior de las llaves cubre de una vez las
                // tres formas: alias plano (`typedef u64 size_t;`), newtype con
                // bloque (`typedef X Y new { ... };`) y el typedef C-style
                // (`typedef struct { ... } Nombre;`), cuyo nombre va al final.
                int prof = 0;
                std::string ultimo;
                Token c = lex.next();
                while (c.kind != TokenKind::END_OF_FILE) {
                    if (c.kind == TokenKind::LBRACE) {
                        ++prof;
                    } else if (c.kind == TokenKind::RBRACE) {
                        if (prof > 0) --prof;
                    } else if (prof == 0) {
                        if (c.kind == TokenKind::SEMICOLON) break;
                        if (c.kind == TokenKind::IDENTIFIER) ultimo = c.lexeme;
                    }
                    c = lex.next();
                }
                anota_tipo(ultimo);
                t = lex.next();
                continue;
            }
            if (t.kind == TokenKind::KW_STRUCT ||
                t.kind == TokenKind::KW_CLASS || t.kind == TokenKind::KW_ENUM) {
                Token id = lex.next();
                if (id.kind == TokenKind::IDENTIFIER) anota_tipo(id.lexeme);
                t = id;
                continue;
            }
        }
        t = lex.next();
    }
}

// ---------------------------------------------------------------------------
//  NS.2-full: construye el indice namespace -> fichero(s) escaneando
// recursivamente los .vx bajo las source roots (dir del root, search paths,
// stdlib).  Lazy + idempotente.
// ---------------------------------------------------------------------------
void ModuleGraph::build_namespace_index_() {
    if (ns_index_built_) return;
    ns_index_built_ = true;

    namespace fs = std::filesystem;

    /* Reparto del coste del escaneo, para decidir con datos si merece la pena
     * cachearlo y con que criterio: leer cada fichero es una cosa y lexarlo
     * otra, y el remedio no es el mismo. */
    long us_leer = 0, us_lexar = 0, n_ficheros = 0, n_entradas = 0;
    const auto t_indice = std::chrono::steady_clock::now();

    /* Que ficheros lleva ya cada namespace, por identidad.  Antes esto se
     * preguntaba recorriendo la lista y recalculando la identidad de cada uno
     * -- que consulta el sistema de ficheros -- por cada fichero nuevo: coste
     * cuadratico con una llamada al sistema dentro.  Medido, era mas de la
     * mitad del escaneo, mas que leer y lexar los 757 ficheros juntos. */
    std::unordered_map<std::string, std::unordered_set<std::string>> vistos;
    for (const auto &kv : ns_index_) {
        auto &s = vistos[kv.first];
        for (const auto &f : kv.second)
            s.insert(identidad_fichero_(f));
    }

    // Recolectar las raices a escanear (sin duplicados).
    std::vector<std::string> roots;
    /* Las raices se dejan TAL COMO LLEGAN.  Absolutizarlas aqui se probo -- la
     * idea era ahorrar la resolucion por fichero -- y no dio velocidad: la que
     * la dio fue el recorrido.  Lo que si hacia era cambiar la ruta con la que
     * cada fichero entra en el indice, y esa ruta es la del MODULO: cambiarla
     * invalida de golpe lo que ya estuviera cacheado a su nombre.  Un cambio
     * que no gana nada no vale una invalidacion. */
    auto add_root = [&](const std::string &d) {
        if (d.empty()) return;
        if (std::find(roots.begin(), roots.end(), d) == roots.end()) {
            roots.push_back(d);
        }
    };
    add_root(root_dir_);
    for (const auto &sp : search_paths_)
        add_root(sp);
    add_root(stdlib_dir_);

    /* De que raiz salio cada namespace, y de que paquete es esa raiz.
     *
     * Un namespace REPARTIDO es normal dentro de un arbol: `types.vx` y su
     * variante por arquitectura declaran el mismo y hay que fusionarlos.  Lo
     * que no es normal es fusionarlo entre DOS arboles, y pasa en cuanto se
     * compila algo estando dentro de una copia de la libreria mientras existe
     * otra instalada: se cargan las dos y sus tipos se pelean por la misma
     * identidad ("tipo no resuelto en alias 'std__types__offset'").
     *
     * Se descarta la segunda SOLO si dice ser el MISMO paquete, que es lo que
     * la convierte en "la misma libreria encontrada dos veces" en vez de en dos
     * librerias distintas.  Sin esa comprobacion, quedarse con la primera raiz
     * romperia a quien reparte un namespace suyo entre varios sitios. */
    struct Procedencia {
        std::string id; ///< Identidad declarada del paquete ("" = anonimo).
        std::string manifiesto; ///< Fichero que la declara ("" = ninguno).
    };
    /// Dos sitios que ofrecen los mismos namespaces, para avisar UNA vez.
    struct Choque {
        std::string gana, pierde, ejemplo, id_gana, id_pierde;
        int cuantos = 0;
    };
    std::map<std::string, Choque> choques;
    std::unordered_map<std::string, std::string> raiz_del_ns;
    std::unordered_map<std::string, Procedencia> procedencia_de_raiz;
    auto procedencia_de = [&](const std::string &raiz) -> const Procedencia & {
        auto it = procedencia_de_raiz.find(raiz);
        if (it != procedencia_de_raiz.end()) return it->second;
        // Se pregunta por un fichero DENTRO de la raiz: el manifiesto se busca
        // hacia arriba desde su directorio.
        Procedencia p;
        p.id = derive_package_id(raiz + "/x", &p.manifiesto);
        return procedencia_de_raiz.emplace(raiz, std::move(p)).first->second;
    };

    for (const auto &root : roots) {
        ::fs::recorrer_arbol(root, [&](const std::string &ruta, bool es_dir) {
            ++n_entradas;
            /* No bajar a directorios ocultos.  Ahi es donde viven las caches
             * de la propia construccion (`.cache`, `.vx_cache`), que jamas
             * contienen fuentes y en cambio tienen miles de ficheros
             * repartidos en subdirectorios: en un proyecto de 21 modulos, el
             * recorrido veia 1620 entradas para encontrar 21 `.vx`.  Es la
             * misma convencion que sigue cualquier herramienta que recorre un
             * arbol de fuentes. */
            const size_t barra = ruta.find_last_of('/');
            const char *nombre =
                ruta.c_str() + (barra == std::string::npos ? 0 : barra + 1);
            if (es_dir) return !(nombre[0] == '.' && nombre[1] != '\0');
            /* Junto a los fuentes conviven los .vxi/.vxir/.vel generados: en la
             * stdlib son ~1500 entradas para 56 fuentes.  Que sea un fichero
             * regular ya lo dijo el listado, asi que aqui solo queda mirar el
             * nombre. */
            const size_t n = ruta.size();
            // `> 3` y no `>= 3`: un fichero llamado solo `.vx` no tiene nombre,
            // es una extension suelta, y tampoco lo cogia el criterio anterior.
            if (n <= 3 || ruta.compare(n - 3, 3, ".vx") != 0 ||
                ruta[n - 4] == '/')
                return false;
            std::string canonical = normalize_path_(ruta, "");
            std::string source;
            const auto t_leer = std::chrono::steady_clock::now();
            if (!read_file_(canonical, source)) return false;
            const auto t_lexar = std::chrono::steady_clock::now();
            std::vector<std::string> namespaces;
            std::unordered_map<std::string, std::vector<std::string>> tipos;
            extract_namespaces_(source, namespaces, &tipos);
            us_leer += std::chrono::duration_cast<std::chrono::microseconds>(
                           t_lexar - t_leer)
                           .count();
            us_lexar += std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - t_lexar)
                            .count();
            ++n_ficheros;
            for (auto &kv : tipos) {
                auto &dst = ns_types_[kv.first];
                for (const auto &nt : kv.second) {
                    if (std::find(dst.begin(), dst.end(), nt) == dst.end())
                        dst.push_back(nt);
                }
            }
            const std::string ident = identidad_fichero_(canonical);
            for (const auto &ns : namespaces) {
                auto itr = raiz_del_ns.find(ns);
                if (itr == raiz_del_ns.end()) {
                    raiz_del_ns.emplace(ns, root);
                } else if (itr->second != root) {
                    /* Otro arbol declara este mismo namespace.  Lo que decide
                     * no es el ID del paquete sino DE QUE MANIFIESTO viene cada
                     * raiz, porque el id no distingue los dos casos:
                     *
                     *   - mismo manifiesto -> es UN paquete cuyos ficheros
                     *     estan repartidos entre varias raices (un proyecto con
                     *     `src/` y `lib/`).  Se fusionan: para eso existe el
                     *     namespace parcial.
                     *   - manifiestos distintos -> son dos INSTALACIONES.  Si
                     *     dicen ser el mismo paquete, es la misma libreria
                     *     encontrada dos veces; si dicen ser distintos, son dos
                     *     librerias que se disputan el namespace.  En los dos
                     *     casos manda la raiz que llego primero, que es la de
                     *     mayor prioridad (el directorio del fuente, luego los
                     *     caminos de busqueda, luego la stdlib).  Fusionarlas
                     *     no puede salir bien: sus tipos acaban peleandose por
                     *     la misma identidad. */
                    const Procedencia &pa = procedencia_de(itr->second);
                    const Procedencia &pb = procedencia_de(root);
                    const bool mismo_paquete = !pa.manifiesto.empty() &&
                                               pa.manifiesto == pb.manifiesto;
                    if (!mismo_paquete) {
                        /* Se anota y se avisa UNA vez por par de sitios, no por
                         * namespace: dos arboles de la stdlib comparten decenas
                         * y el aviso repetido tapa el resto de la salida.
                         * Callarselo es peor -- es lo que costo descubrir a
                         * mano por que un tipo "no resolvia". */
                        Choque &ch = choques[itr->second + "\n" + root];
                        if (ch.ejemplo.empty()) {
                            ch.gana = itr->second;
                            ch.pierde = root;
                            ch.ejemplo = ns;
                            ch.id_gana = pa.id;
                            ch.id_pierde = pb.id;
                        }
                        ++ch.cuantos;
                        continue;
                    }
                }
                // Dos raices que se solapan (el directorio del root y la
                // stdlib) recorren los MISMOS ficheros con escrituras
                // distintas.  Comparar por identidad evita que el namespace
                // parezca repartido entre el doble de ficheros de los que hay.
                if (vistos[ns].insert(ident).second)
                    ns_index_[ns].push_back(canonical);
            }
            return false;
        });
    }
    /* Los sitios que se disputan un namespace.  Se dice al final y una vez por
     * par: cual manda, cual se ignora, y por que -- que no es lo mismo dos
     * copias de la misma libreria que dos librerias distintas, y lo que hay que
     * hacer tampoco. */
    for (const auto &kv : choques) {
        const Choque &c = kv.second;
        /* En absoluto: la raiz puede ser `.` -- el directorio desde el que se
         * invoco --, y decirle a alguien que se usa "el de '.'" no le dice
         * donde esta. */
        auto legible = [](const std::string &r) -> std::string {
            std::error_code ec;
            std::filesystem::path p =
                std::filesystem::absolute(std::filesystem::path(r), ec);
            if (ec) return r;
            std::string s = p.lexically_normal().string();
            for (char &ch : s)
                if (ch == '\\') ch = '/';
            while (s.size() > 1 && s.back() == '/')
                s.pop_back();
            return s;
        };
        SourceLoc loc;
        loc.set_file(legible(c.pierde));
        diags_.diag(loc, DiagLevel::WARN, "VX4003",
                    {c.ejemplo, legible(c.gana), legible(c.pierde),
                     std::to_string(c.cuantos)});
        if (c.id_gana == c.id_pierde) {
            diags_.note(loc, vx::diag::format("VX4004", {}));
        } else {
            diags_.note(
                loc, vx::diag::format(
                         "VX4005", {c.id_gana.empty() ? "?" : c.id_gana,
                                    c.id_pierde.empty() ? "?" : c.id_pierde}));
        }
    }

    if (util::flag_on(util::FlagId::Times)) {
        const long us_total = static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t_indice)
                .count());
        std::cerr << "[resolver] indice de namespaces: " << n_entradas
                  << " entradas, " << n_ficheros << " ficheros | recorrer "
                  << (us_total - us_leer - us_lexar) << " us | leer " << us_leer
                  << " us | lexar " << us_lexar << " us | total " << us_total
                  << " us\n";
    }
}

// ---------------------------------------------------------------------------
//  NS.2-full: resuelve `import a.b.c;` consultando el indice.  Si el
// namespace lo declaran varios ficheros (namespace parcial), devuelve el
// PRIMERO (el resto se cargan como deps adicionales por process_dependencies_
// via un segundo lookup).  MVP: un fichero por namespace es el caso comun.
// ---------------------------------------------------------------------------
ResolveResult
ModuleGraph::resolve_namespace_(const std::string &ns,
                                const std::string & /*importer_file*/) {
    ResolveResult res;
    build_namespace_index_();
    auto it = ns_index_.find(ns);
    if (it == ns_index_.end() || it->second.empty()) {
        res.status = ResolveResult::Status::NOT_FOUND;
        res.error_message =
            "namespace '" + ns +
            "' no encontrado. Ningun .vx bajo las source roots lo declara.";
        return res;
    }
    const std::string &file = it->second.front();
    const uint32_t id = load_and_parse_(file);
    if (id == UINT32_MAX) {
        res.status = ResolveResult::Status::PARSE_ERROR;
        res.error_message = "fallo al cargar/parsear: " + file;
        return res;
    }
    res.status = ResolveResult::Status::OK;
    res.module_id = id;
    return res;
}

void ModuleGraph::process_dependencies_(ResolvedModule &mod) {
    if (!mod.parsed_ast) return;

    // NS.1 fix: los imports pueden estar ANIDADOS dentro de un NamespaceDecl
    // (forma statement `namespace a.b.c;` que envuelve el resto del fichero,
    // imports incluidos).  Recolectarlos recursivamente; si no, el grafo de
    // modulos no ve el import -> el dep no se compila -> "funcion no
    // declarada".
    std::vector<ast::ImportDecl *> imports;
    std::function<void(std::vector<std::unique_ptr<ast::Node>> &)> gather =
        [&](std::vector<std::unique_ptr<ast::Node>> &decls) {
            for (auto &decl : decls) {
                if (!decl) continue;
                if (decl->kind == ast::NodeKind::ImportDecl) {
                    imports.push_back(
                        static_cast<ast::ImportDecl *>(decl.get()));
                } else if (decl->kind == ast::NodeKind::NamespaceDecl) {
                    gather(
                        static_cast<ast::NamespaceDecl *>(decl.get())->decls);
                }
            }
        };
    gather(mod.parsed_ast->decls);

    for (auto *imp : imports) {
        ResolveResult r =
            imp->by_namespace
                ? resolve_namespace_(imp->path, mod.canonical_path)
                : resolve(imp->path, mod.canonical_path);
        if (r.status == ResolveResult::Status::NOT_FOUND) {
            diags_.error(imp->loc, r.error_message);
            continue;
        }
        if (r.status == ResolveResult::Status::PARSE_ERROR ||
            r.status == ResolveResult::Status::IO_ERROR) {
            diags_.error(imp->loc, r.error_message);
            continue;
        }
        // Helper: registra un module_id como dependencia (dedup + recursion).
        auto add_dep = [&](uint32_t mid) {
            if (mid == UINT32_MAX || mid == mod.module_id) return;
            for (uint32_t d : mod.dependencies)
                if (d == mid) return; // dup
            mod.dependencies.push_back(mid);
            ResolvedModule *child = modules_[mid].get();
            if (child && child->dependencies.empty() && child->parsed_ast)
                process_dependencies_(*child);
        };
        add_dep(r.module_id);
        // Namespace PARCIAL: un mismo `namespace X;` puede estar declarado por
        // VARIOS ficheros (p.ej. std.types + std/types/x86_64.vx).
        // resolve_namespace_ devuelve solo el PRIMERO; aqui cargamos el RESTO
        // para que sus simbolos (tipos/fns) tambien se fusionen en el namespace
        // que ve el importador.  Sin esto, `import std.types` solo veia el
        // primer fichero y `sizeof<std.types.uintptr>` (definido en el arch
        // file) daba "tipo no reconocido".
        if (imp->by_namespace) {
            build_namespace_index_();
            auto itns = ns_index_.find(imp->path);
            if (itns != ns_index_.end()) {
                for (const auto &file : itns->second) {
                    const uint32_t mid = load_and_parse_(file);
                    add_dep(mid);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// build_from_root: punto de entrada.  Carga el modulo raiz y procesa
// recursivamente todas las dependencias.  Devuelve el module_id del root
// o UINT32_MAX si error fatal.
// ---------------------------------------------------------------------------
uint32_t ModuleGraph::build_from_root(const std::string &root_file) {
    // Resolver el path absoluto del root.
    std::string canonical = normalize_path_(root_file, "");
    /* Un fuente puesto por el llamante (overlay) NO esta en disco, y no tiene
     * por que estarlo: es texto que se acaba de generar.  Preguntar solo al
     * disco hacia imposible compilar uno como raiz -- que es justo lo que hace
     * falta para compilar el conjunto comptime, generado en memoria, sin
     * dejarlo en el arbol donde competiria con la stdlib por su namespace. */
    if (!file_exists_(canonical) && source_overlay_.count(canonical) == 0) {
        SourceLoc l;
        l.set_file(root_file);
        diags_.error(l, "el fichero raiz no existe: '" + root_file + "'");
        return UINT32_MAX;
    }
    //  NS.2-full: recordar el directorio del root para el indice de
    // namespaces (escaneo recursivo del arbol del proyecto).
    {
        size_t slash = canonical.find_last_of('/');
        if (slash != std::string::npos) {
            root_dir_ = canonical.substr(0, slash);
        } else {
            // Sin separador el root es un nombre SUELTO (`vx main.vx`), asi que
            // vive en el directorio actual.  Dejarlo vacio hacia que
            // `add_root("")` saliera de inmediato y el indice de namespaces NO
            // escaneara el directorio del propio fichero raiz: el mismo
            // proyecto compilaba con ruta absoluta y fallaba con relativa,
            // diciendo "ningun .vx bajo las source roots lo declara" con el
            // fichero justo al lado.
            root_dir_ = ".";
        }
    }
    const uint32_t id = load_and_parse_(canonical);
    if (id == UINT32_MAX) return UINT32_MAX;

    /* Si la RAIZ declara un namespace que esta repartido entre varios ficheros
     * -- el base y uno por arquitectura --, hay que traerse a sus hermanos.
     *
     * Al IMPORTAR un namespace parcial ya se hacia (mas arriba); faltaba
     * cuando el fichero analizado ES uno de ellos.  Sin esto, `std/types.vx`
     * suelto no se sostiene: usa `usize`, que declara el fichero de su
     * arquitectura, y el resultado era "tipo no resuelto en alias" -- o sea que
     * la base de tipos de la que depende media stdlib no se podia ni analizar,
     * y con ella todo lo que arrastra. */
    if (ResolvedModule *raiz = modules_[id].get()) {
        std::vector<std::string> mis_ns;
        std::string texto;
        if (read_file_(canonical, texto)) extract_namespaces_(texto, mis_ns);
        if (!mis_ns.empty()) {
            build_namespace_index_();
            for (const auto &ns : mis_ns) {
                auto itns = ns_index_.find(ns);
                if (itns == ns_index_.end()) continue;
                const std::string yo = identidad_fichero_(canonical);
                for (const auto &file : itns->second) {
                    // Comparar por identidad: el indice puede tener la misma
                    // unidad escrita de otra forma que el root.
                    if (identidad_fichero_(file) == yo) continue;
                    const uint32_t mid = load_and_parse_(file);
                    if (mid == UINT32_MAX) continue;
                    raiz->dependencies.push_back(mid);
                    ResolvedModule *herm = modules_[mid].get();
                    if (herm && herm->dependencies.empty() && herm->parsed_ast)
                        process_dependencies_(*herm);
                }
            }
        }
    }

    process_dependencies_(*modules_[id]);
    return id;
}

// ---------------------------------------------------------------------------
// topological_order: DFS coloreado.  WHITE = no visitado, GRAY = en pila
// DFS actual (si encontramos otro GRAY -> ciclo), BLACK = procesado.
// El output queda en orden: las deps salen ANTES de sus dependents.
// ---------------------------------------------------------------------------
std::vector<uint32_t> ModuleGraph::topological_order() const {
    std::vector<uint32_t> order;
    order.reserve(modules_.size());
    if (modules_.empty()) return order;

    // Reset colors.  Modificamos los modulos (color es mutable conceptual,
    // pero const_cast aqui es seguro porque este metodo no es thread-safe
    // y el caller no ejecuta multiples topological_order concurrentes).
    auto *self = const_cast<ModuleGraph *>(this);
    for (auto &m : self->modules_)
        m->color = ResolveColor::WHITE;
    self->cycle_detected_ = false;

    // DFS iterativa con stack explicita para evitar stack overflow en
    // proyectos profundos (mas de ~1000 niveles raros pero defensivo).
    struct Frame {
        uint32_t mod_id;
        size_t dep_idx;
    };
    std::vector<Frame> stack;
    stack.reserve(128);

    for (uint32_t root = 0; root < modules_.size(); ++root) {
        if (self->modules_[root]->color != ResolveColor::WHITE) continue;

        stack.push_back({root, 0});
        self->modules_[root]->color = ResolveColor::GRAY;

        while (!stack.empty()) {
            Frame &top = stack.back();
            ResolvedModule *m = self->modules_[top.mod_id].get();

            if (top.dep_idx < m->dependencies.size()) {
                const uint32_t next = m->dependencies[top.dep_idx++];
                ResolvedModule *child = self->modules_[next].get();

                if (child->color == ResolveColor::WHITE) {
                    child->color = ResolveColor::GRAY;
                    stack.push_back({next, 0});
                } else if (child->color == ResolveColor::GRAY) {
                    // Ciclo: child esta en la pila DFS actual.
                    self->cycle_detected_ = true;
                    // Construir mensaje del ciclo recorriendo la pila.
                    std::string cycle_msg = "ciclo de imports detectado: ";
                    bool found_start = false;
                    for (const auto &f : stack) {
                        if (!found_start && f.mod_id == next)
                            found_start = true;
                        if (found_start) {
                            cycle_msg +=
                                self->modules_[f.mod_id]->module_name + " -> ";
                        }
                    }
                    cycle_msg += child->module_name;
                    SourceLoc l;
                    l.set_file(m->canonical_path);
                    self->diags_.error(l, cycle_msg);
                    // No re-entramos: marcamos el child como BLACK temporal
                    // para que el resto del topo no vuelva a quejarse.
                    child->color = ResolveColor::BLACK;
                }
                // Si BLACK: ya procesado, skip.
            } else {
                // Todas las deps procesadas: emitir m y pop.
                m->color = ResolveColor::BLACK;
                order.push_back(top.mod_id);
                stack.pop_back();
            }
        }
    }

    return order;
}

} // namespace vx
