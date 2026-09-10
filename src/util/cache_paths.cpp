/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file cache_paths.cpp
 * @brief La tabla de cajones de la cache: nombre y alcance de cada tipo.
 */

#include "util/cache_paths.h"

#include "util/env_flags.h"

#include <array>
#include <filesystem>
#include <system_error>

namespace fs = std::filesystem;

namespace util {

namespace {

/**
 * @brief Una fila de la tabla: como se llama el cajon y hasta donde vale.
 */
struct KindRow {
    const char *dir;   ///< nombre del directorio dentro de la raiz.
    CacheScope scope;  ///< alcance de lo que guarda.
};

/**
 * @brief La tabla, en el orden del enum.
 *
 * Es la UNICA fuente de verdad de la disposicion en disco.  Un tipo nuevo sin
 * fila aqui no compila -- la comprobacion de tamano de abajo lo caza --, que
 * es justo lo que evita que alguien anada un artefacto y lo deje suelto.
 */
constexpr KindRow kKinds[] = {
    /* Interfaz e intermedio: salen del fuente, de la version del compilador y
     * del objetivo, y los tres entran en la clave.  Es la mitad que interesa
     * conservar y compartir. */
    {"ir", CacheScope::Portable},       // CacheKind::ModuleIr
    /* Lo que el ASA supo del modulo, con el mismo criterio que el intermedio:
     * es conocimiento DERIVADO del fuente, no de esta maquina. */
    {"facts", CacheScope::Portable},    // CacheKind::Facts
    {"analysis", CacheScope::Portable}, // CacheKind::Analysis
    {"vel", CacheScope::Portable},      // CacheKind::Vel
    /* El `.velb` de un fuente, con la clave sacada de su contenido: sirve en
     * otra maquina siempre que coincida el objetivo. */
    {"velb", CacheScope::Portable},     // CacheKind::Bytecode
    /* Ejecutar al compilar da un valor, y la clave es el hash del intermedio
     * del modulo: el mismo intermedio da el mismo valor en cualquier sitio. */
    {"ctpe", CacheScope::Portable},     // CacheKind::Comptime
    /* El unico repartido: `packs` va por contenido y viaja, `roots` son
     * apuntadores con rutas absolutas y no.  @see CacheScope::Mixed */
    {"vxdbg", CacheScope::Mixed},       // CacheKind::DebugInfo
    /* Lo descargado es el paquete tal cual, con su firma: viaja. */
    {"pkg", CacheScope::Portable},      // CacheKind::Packages
    /* Guarda por donde estan los artefactos de ESTE arbol.  En otra maquina
     * las entradas apuntan a sitios que no existen. */
    {"projects", CacheScope::Local},    // CacheKind::Projects
    {"work", CacheScope::Transient},    // CacheKind::Work
    {"tmp", CacheScope::Transient},     // CacheKind::Temp
};

static_assert(sizeof(kKinds) / sizeof(kKinds[0]) == kCacheKindCount,
              "cada CacheKind necesita su fila: nombre de cajon y alcance");

/**
 * @brief Resuelve la raiz de la cache.  La llama @ref cache_root una vez.
 *
 * @return Ruta de la raiz; nunca vacia.
 */
std::string resolve_cache_root() {
    /* La valvula gana siempre: es la que permite que varios proyectos
     * compartan la cache de las librerias comunes. */
    const std::string &forced = util::flag_text(util::FlagId::CacheDir);
    if (!forced.empty()) return forced;
    /* Y si no, la raiz del arbol al que pertenece el directorio de trabajo.
     * Sin esto, cada directorio desde el que alguien invocara el compilador
     * estrenaba SU cache: en este mismo repositorio habia noventa `.cache`
     * repartidos por el arbol -- uno por cada banco de pruebas, por cada
     * carpeta de herramientas y por cada caso --, todos con el mismo trabajo
     * repetido dentro y ninguno enterandose de los demas. */
    const std::string root = tree_root_from(std::string());
    if (!root.empty()) return (fs::path(root) / cache_root_name()).string();
    return std::string(cache_root_name());
}

/**
 * @brief Construye la tabla de rutas.  La llama @ref cache_dir una vez.
 *
 * @return Un directorio por tipo, en el orden del enum.
 */
std::array<std::string, kCacheKindCount> build_kind_dirs() {
    std::array<std::string, kCacheKindCount> dirs;
    const std::string &root = cache_root();
    for (size_t i = 0; i < kCacheKindCount; ++i)
        dirs[i] = (fs::path(root) / kKinds[i].dir).string();
    return dirs;
}

/// Indice seguro dentro de la tabla; el 0 hace de respaldo visible.
size_t kind_index(CacheKind kind) noexcept {
    const size_t i = static_cast<size_t>(kind);
    return i < kCacheKindCount ? i : 0;
}

} // namespace

const char *cache_root_name() noexcept { return ".cache"; }

const char *cache_kind_dir(CacheKind kind) noexcept {
    return kKinds[kind_index(kind)].dir;
}

CacheScope cache_kind_scope(CacheKind kind) noexcept {
    return kKinds[kind_index(kind)].scope;
}

const char *cache_scope_name(CacheScope scope) noexcept {
    switch (scope) {
    case CacheScope::Portable:
        return "portable";
    case CacheScope::Local:
        return "local";
    case CacheScope::Transient:
        return "transitorio";
    case CacheScope::Mixed:
        return "mixto";
    }
    return "desconocido";
}

namespace {

/**
 * @brief Sube desde @p start_dir hasta encontrar una raiz.
 *
 * @param start_dir  Desde donde subir; vacio para el directorio de trabajo.
 * @param acepta_vcs Si tambien cuenta el directorio de una copia de trabajo de
 *                   control de versiones, ademas del manifiesto de paquete.
 * @return Ruta absoluta de la raiz, o vacio si no hay ninguna.
 */
std::string ascend_to_root(const std::string &start_dir, bool acepta_vcs) {
    std::error_code ec;
    fs::path p = start_dir.empty() ? fs::current_path(ec) : fs::path(start_dir);
    if (ec) return std::string();
    p = fs::absolute(p, ec);
    if (ec) return std::string();
    /* Hasta 64 niveles.  Es una cota defensiva: la comprobacion de abajo cubre
     * llegar a la raiz del volumen, pero no un enlace que se muerda la cola. */
    for (int i = 0; i < 64; ++i) {
        /* El manifiesto primero: un paquete es lo mas especifico que hay, y si
         * uno vive dentro de otro arbol manda el paquete. */
        if (fs::exists(p / "vx.toml", ec) || fs::exists(p / "vx.json", ec))
            return p.string();
        if (acepta_vcs && fs::exists(p / ".git", ec)) return p.string();
        const fs::path parent = p.parent_path();
        if (parent.empty() || parent == p) break;
        p = parent;
    }
    return std::string();
}

} // namespace

std::string project_root_from(const std::string &start_dir) {
    /* Solo el manifiesto.  Aqui "proyecto" significa PAQUETE -- es lo que el
     * gestor necesita para saber que instalar y donde --, y una copia de
     * trabajo de git no lo es. */
    return ascend_to_root(start_dir, /*acepta_vcs=*/false);
}

std::string tree_root_from(const std::string &start_dir) {
    return ascend_to_root(start_dir, /*acepta_vcs=*/true);
}

const std::string &cache_root() {
    /* UNA vez por proceso.  Ni el entorno ni el directorio de trabajo cambian
     * a mitad de una compilacion, y subir buscando el manifiesto son varias
     * consultas al sistema de ficheros que no hay por que repetir. */
    static const std::string root = resolve_cache_root();
    return root;
}

const std::string &cache_dir(CacheKind kind) {
    static const std::array<std::string, kCacheKindCount> dirs =
        build_kind_dirs();
    return dirs[kind_index(kind)];
}

std::string cache_dir_under(const std::string &root, CacheKind kind) {
    if (root.empty()) return std::string();
    return (fs::path(root) / cache_root_name() / cache_kind_dir(kind)).string();
}

} // namespace util
