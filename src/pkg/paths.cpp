/**
 * @file paths.cpp
 * @brief Implementacion de la resolucion de rutas estandar del PM Vesta.
 */
#include "pkg/paths.h"

#include "util/cache_paths.h" // el reparto de la cache por tipo y alcance

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

namespace fs = std::filesystem;

namespace pkg::paths {

namespace {
/**
 * @brief Lee una env var; devuelve cadena vacia si no existe.
 */
std::string get_env(const char *name) {
    // MinGW + MSVC ambos soportan getenv (despues de los warnings).
    const char *v = std::getenv(name);
    return v ? std::string(v) : std::string();
}
} // namespace

std::string vx_home() {
    // 1) VX_HOME explicito gana siempre.
    std::string env = get_env("VX_HOME");
    if (!env.empty()) {
        return normalize(env);
    }
    // 2) Per-usuario por defecto.
#ifdef _WIN32
    // En Windows usamos APPDATA (e.g. C:\Users\me\AppData\Roaming).
    std::string appdata = get_env("APPDATA");
    if (appdata.empty()) {
        // Fallback al USERPROFILE.
        appdata = get_env("USERPROFILE");
    }
    if (appdata.empty()) {
        return std::string();
    }
    return join(appdata, "Vesta");
#else
    std::string home = get_env("HOME");
    if (home.empty()) return std::string();
    return join(home, ".vesta");
#endif
}

std::string system_install_dir() {
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return std::string();
    // El ejecutable suele estar en <install>/bin/vm.exe; el install_dir es
    // el parent del parent.
    fs::path exe(buf);
    fs::path install = exe.parent_path();
    // Si el parent se llama "bin", subimos uno mas.
    if (install.filename() == "bin") {
        install = install.parent_path();
    }
    return install.string();
#else
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return std::string();
    buf[n] = '\0';
    fs::path exe(buf);
    fs::path install = exe.parent_path();
    if (install.filename() == "bin") {
        install = install.parent_path();
    }
    return install.string();
#endif
}

std::string project_root(const std::string &start_dir) {
    /* Subir buscando `vx.toml` o `vx.json` lo hace `util::project_root_from`.
     * No esta ahi por reparto de capas: es que la CACHE tambien necesita saber
     * cual es la raiz del proyecto -- es lo que hace que compilar desde una
     * subcarpeta y desde la raiz usen la misma --, y dos copias de esta
     * busqueda serian dos ideas distintas de donde empieza el proyecto. */
    return util::project_root_from(start_dir);
}

std::string project_modules_dir(const std::string &start_dir) {
    std::string root = project_root(start_dir);
    if (root.empty()) return std::string();
    return join(root, "vx_modules");
}

std::string packages_dir(Scope scope, const std::string &proj_root) {
    switch (scope) {
    case Scope::Project: {
        std::string r = proj_root.empty() ? project_root("") : proj_root;
        if (r.empty()) return std::string();
        return join(r, "vx_modules");
    }
    case Scope::User: {
        std::string vh = vx_home();
        if (vh.empty()) return std::string();
        return join(vh, "packages");
    }
    case Scope::System: {
        std::string si = system_install_dir();
        if (si.empty()) return std::string();
        return join(join(si, "share"), "vesta-packages");
    }
    }
    return std::string();
}

std::string cache_dir(Scope scope, const std::string &proj_root) {
    switch (scope) {
    case Scope::Project: {
        std::string r = proj_root.empty() ? project_root("") : proj_root;
        if (r.empty()) return std::string();
        /* Anclada en la raiz del PROYECTO, no en el directorio de trabajo:
         * instalar desde una subcarpeta tiene que llenar la misma cache.  El
         * nombre del cajon sale de `cache_paths.h`, que es donde vive el
         * reparto entero. */
        return util::cache_dir_under(r, util::CacheKind::Packages);
    }
    case Scope::User: {
        std::string vh = vx_home();
        if (vh.empty()) return std::string();
        return join(vh, "cache");
    }
    case Scope::System: {
        std::string si = system_install_dir();
        if (si.empty()) return std::string();
        return join(join(si, "share"), "vesta-cache");
    }
    }
    return std::string();
}

std::string keys_dir() {
    std::string vh = vx_home();
    if (vh.empty()) return std::string();
    return join(vh, "keys");
}

std::string private_keys_dir() {
    std::string vh = vx_home();
    if (vh.empty()) return std::string();
    return join(join(vh, "keys"), "private");
}

bool ensure_dir(const std::string &path) {
    if (path.empty()) return false;
    std::error_code ec;
    if (fs::exists(path, ec)) {
        return fs::is_directory(path, ec);
    }
    fs::create_directories(path, ec);
    return !ec;
}

std::string normalize(const std::string &path) {
    if (path.empty()) return path;
    std::error_code ec;
    fs::path p(path);
    fs::path lp = p.lexically_normal();
    return lp.string();
}

std::string join(const std::string &a, const std::string &b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    fs::path p(a);
    p /= b;
    return p.string();
}

std::string installed_manifest(Scope scope, const std::string &name,
                               const std::string &version,
                               const std::string &proj_root) {
    std::string pkgs = packages_dir(scope, proj_root);
    if (pkgs.empty()) return std::string();
    std::string folder = name + "@" + version;
    // Sanitizar / en el name (por org/pkg).
    std::replace(folder.begin(), folder.end(), '/', '_');
    return join(join(pkgs, folder), "vx.toml");
}

bool exists(const std::string &path) {
    std::error_code ec;
    return fs::exists(path, ec);
}

bool is_directory(const std::string &path) {
    std::error_code ec;
    return fs::is_directory(path, ec);
}

bool is_file(const std::string &path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec);
}

} // namespace pkg::paths
