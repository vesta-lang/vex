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
 * @file fs_utils.h
 * @brief Utilidades portables para comprobacion de rutas y permisos (Windows /
 * POSIX).
 *
 * Este fichero contiene utilidades ligeras basadas en std::filesystem para:
 *   - Comprobar existencia de rutas (archivo o directorio).
 *   - Normalizar rutas a forma absoluta o canonica.
 *   - Comprobar permisos de lectura/escritura (heuristico en Windows).
 *   - Buscar ejecutables en el PATH del sistema.
 *   - Obtener la ruta del ejecutable actual.
 *
 * @note Requiere compilador con soporte para <filesystem> (C++17 o posterior).
 */

#ifndef FS_UTILS_H
#define FS_UTILS_H

#include "util/env_flags.h"
#include <algorithm>
#include <mutex>
#include <cstdlib>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// Evitar que las macros de windows.h (VOID, IN, OUT, interface, ...) contaminen
// los TUs que incluyen este header (c_backend.cpp / compiler_project.cpp usan
// esos identificadores como nombres).
#undef VOID
#undef CONST
#undef IN
#undef OUT
#undef OPTIONAL
#undef ERROR
#undef interface
#else
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace fs {
/// Alias al namespace de la libreria estandar para evitar colisiones de nombre.
namespace fs = std::filesystem;

/**
 * @brief Comprueba si una ruta existe (archivo o directorio).
 *
 * @param p Ruta a comprobar.
 * @return true si la ruta existe; false en caso contrario o si ocurre un error.
 */
static bool file_exists(const fs::path &p) {
    std::error_code ec;
    return fs::exists(p, ec) && !ec;
}

/**
 * @brief Comprueba si una ruta existe y es un archivo regular (no directorio).
 *
 * @param p Ruta a comprobar.
 * @return true si existe y es archivo regular; false en caso contrario.
 */
static bool is_regular_file(const fs::path &p) {
    std::error_code ec;
    return fs::exists(p, ec) && !ec && fs::is_regular_file(p, ec) && !ec;
}

/**
 * @brief Divide una cadena tipo PATH por el separador de plataforma.
 *
 * En Windows el separador es ';' y en POSIX ':'.
 *
 * @param s Cadena PATH a dividir.
 * @return Vector con cada entrada del PATH (sin entradas vacias).
 */
static std::vector<std::string> split_path_env(const std::string &s) {
    char sep =
#ifdef _WIN32
        ';';
#else
        ':';
#endif
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else
            cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

/**
 * @brief Normaliza una ruta y la convierte a forma absoluta cuando es posible.
 *
 * Usa fs::weakly_canonical para resolver '.' y '..'. Si la ruta no existe
 * o weakly_canonical lanza, se devuelve una ruta lexically_normal relativa
 * al directorio actual.
 *
 * @param p Ruta a normalizar.
 * @return Ruta normalizada (absoluta si es posible).
 */
static fs::path normalize_path_safe(const fs::path &p) {
    try {
        if (p.is_absolute()) return fs::weakly_canonical(p);
        return fs::weakly_canonical(fs::current_path() / p);
    } catch (const fs::filesystem_error &) {
        // weakly_canonical puede fallar si la ruta no existe; devolver una
        // forma razonable
        return (fs::current_path() / p).lexically_normal();
    }
}

/**
 * @brief Comprueba de forma tentativa si el archivo es legible.
 *
 * En POSIX se comprueban los bits de permiso; en Windows se intenta abrir el
 * fichero en modo lectura (heuristica).
 *
 * @param p Ruta del fichero.
 * @return true si parece legible; false en caso contrario.
 */
static bool can_read(const fs::path &p) {
    std::error_code ec;
    if (!fs::exists(p, ec) || ec) return false;
#ifdef _WIN32
    // Intentamos abrir en modo lectura sin lanzar excepcion
    std::ifstream f(p.string(), std::ios::binary);
    return f.is_open();
#else
    auto perms = fs::status(p, ec).permissions();
    if (ec) return false;
    using perms_t = fs::perms;
    // owner/group/others read
    return (perms & perms_t::owner_read) != perms_t::none ||
           (perms & perms_t::group_read) != perms_t::none ||
           (perms & perms_t::others_read) != perms_t::none;
#endif
}

/**
 * @brief Comprueba de forma tentativa si se puede escribir en la ruta.
 *
 * - Si el fichero no existe, se comprueba si el directorio padre es escribible.
 * - En Windows se intenta crear y borrar un fichero temporal como heuristica.
 *
 * @param p Ruta del fichero a comprobar.
 * @return true si parece escribible; false en caso contrario.
 */
static bool can_write(const fs::path &p) {
    std::error_code ec;
    // Si no existe, comprobar si el directorio padre es escribible
    if (!fs::exists(p, ec) || ec) {
        fs::path parent = p.parent_path();
        if (parent.empty()) parent = fs::current_path();
#ifdef _WIN32
        // heuristica: intentar crear y borrar un fichero temporal
        fs::path tmp = parent / ".vesta_tmp_write_test";
        std::ofstream f(tmp.string(), std::ios::binary);
        if (!f.is_open()) return false;
        f.close();
        std::error_code rem;
        fs::remove(tmp, rem);
        return true;
#else
        auto perms = fs::status(parent, ec).permissions();
        if (ec) return false;
        using perms_t = fs::perms;
        return (perms & perms_t::owner_write) != perms_t::none ||
               (perms & perms_t::group_write) != perms_t::none ||
               (perms & perms_t::others_write) != perms_t::none;
#endif
    }
    // Si existe, comprobar bits/abrir para escritura
#ifdef _WIN32
    std::ofstream f(p.string(), std::ios::app | std::ios::binary);
    return f.is_open();
#else
    auto perms = fs::status(p, ec).permissions();
    if (ec) return false;
    using perms_t = fs::perms;
    return (perms & perms_t::owner_write) != perms_t::none ||
           (perms & perms_t::group_write) != perms_t::none ||
           (perms & perms_t::others_write) != perms_t::none;
#endif
}

/**
 * @brief Helper: comprobar una ruta dada por string (absoluta o relativa).
 *
 * Normaliza la ruta y comprueba existencia.
 *
 * @param s Ruta en forma de cadena.
 * @return true si el archivo existe.
 */
static bool file_exists_str(const std::string &s) {
    return file_exists(normalize_path_safe(fs::path(s)));
}

/**
 * @brief Comprueba si la ruta existe y es ejecutable (heuristica
 * multiplataforma).
 *
 * - En POSIX se comprueban los bits de ejecucion.
 * - En Windows se comprueba la extension contra PATHEXT.
 *
 * @param p Ruta a comprobar.
 * @return true si el fichero existe y parece ejecutable.
 */
static bool path_exists_and_executable(const fs::path &p) {
    std::error_code ec;
    if (!fs::exists(p, ec) || ec) return false;
    if (fs::is_directory(p, ec) || ec) return false;

#ifdef _WIN32
    // En Windows: si existe el fichero y su extension esta en PATHEXT,
    // considerarlo ejecutable.
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::toupper);

    const char *pathext_c = std::getenv("PATHEXT");
    if (!pathext_c) {
        // valor por defecto razonable
        static const std::vector<std::string> default_ext = {".COM", ".EXE",
                                                             ".BAT", ".CMD"};
        for (auto &e : default_ext)
            if (e == ext) return true;
        return false;
    }
    std::string pathext(pathext_c);
    std::transform(pathext.begin(), pathext.end(), pathext.begin(), ::toupper);
    auto parts = split_path_env(pathext); // reutiliza split (usa ; en Windows)
    for (auto &pe : parts) {
        if (pe == ext) return true;
    }
    return false;
#else
    // POSIX: comprobar bits de ejecucion (owner/group/others)
    fs::perms pr = fs::status(p, ec).permissions();
    if (ec) return false;
    using perms = fs::perms;
    if ((pr & perms::owner_exec) != perms::none) return true;
    if ((pr & perms::group_exec) != perms::none) return true;
    if ((pr & perms::others_exec) != perms::none) return true;
    return false;
#endif
}

/**
 * @brief Comprueba si una cadena contiene separador de directorios.
 *
 * Util para decidir si tratar la cadena como ruta o como nombre simple.
 *
 * @param s Cadena a comprobar.
 * @return true si contiene separador de directorios.
 */
static bool contains_dir_separator(const std::string &s) {
#ifdef _WIN32
    return s.find('\\') != std::string::npos ||
           s.find('/') != std::string::npos;
#else
    return s.find('/') != std::string::npos;
#endif
}

/**
 * @brief Busca un ejecutable en PATH o comprueba la ruta si se paso una.
 *
 * @param cmd Nombre o ruta del ejecutable.
 * @return Ruta absoluta encontrada o std::nullopt si no existe.
 */
static std::optional<fs::path> find_executable(const std::string &cmd) {
    if (cmd.empty()) return std::nullopt;

    // Si parece una ruta (contiene separador), verifique directamente.
    if (contains_dir_separator(cmd)) {
        fs::path p = normalize_path_safe(cmd);
#ifdef _WIN32
        // En Windows, si el usuario paso una ruta sin extension, pruebe con
        // PATHEXT.
        if (path_exists_and_executable(p)) return p;
        if (!p.has_extension()) {
            const char *pathext_c = std::getenv("PATHEXT");
            std::string pathext = pathext_c ? pathext_c : ".COM;.EXE;.BAT;.CMD";
            std::transform(pathext.begin(), pathext.end(), pathext.begin(),
                           ::toupper);
            auto exts = split_path_env(pathext);
            for (auto &e : exts) {
                fs::path cand = p;
                cand += e; // append extension
                if (path_exists_and_executable(cand)) return cand;
            }
        }
        return std::nullopt;
#else
        return path_exists_and_executable(p) ? std::optional<fs::path>(p)
                                             : std::nullopt;
#endif
    }

    // No es una ruta: buscar en PATH
    const char *path_c = std::getenv("PATH");
    if (!path_c) return std::nullopt;
    std::string path_env(path_c);
    auto dirs = split_path_env(path_env);
#ifdef _WIN32
    // Windows: Considera PATHEXT
    const char *pathext_c = std::getenv("PATHEXT");
    std::string pathext = pathext_c ? pathext_c : ".COM;.EXE;.BAT;.CMD";
    std::transform(pathext.begin(), pathext.end(), pathext.begin(), ::toupper);
    auto exts = split_path_env(pathext);
    for (auto &d : dirs) {
        if (d.empty()) continue;
        fs::path base = fs::path(d) / cmd;
        // if cmd already has extension, check directly
        if (base.has_extension()) {
            if (path_exists_and_executable(base))
                return normalize_path_safe(base);
        } else {
            for (auto &e : exts) {
                fs::path cand = base;
                cand += e;
                if (path_exists_and_executable(cand))
                    return normalize_path_safe(cand);
            }
        }
    }
#else
    for (auto &d : dirs) {
        if (d.empty()) continue;
        fs::path cand = fs::path(d) / cmd;
        if (path_exists_and_executable(cand)) return normalize_path_safe(cand);
    }
#endif
    return std::nullopt;
}

/**
 * @brief Devuelve la ruta absoluta/canonical de una ruta existente.
 *
 * Si la ruta existe, intenta devolver su forma canonica (resolviendo enlaces
 * simbolicos y eliminando `.`/`..`) usando `fs::weakly_canonical` o
 * `fs::canonical`. Si la ruta no existe o no puede resolverse, devuelve
 * std::nullopt.
 *
 * @param p Ruta (absoluta o relativa).
 * @return std::optional<fs::path> con la ruta absoluta/canonical si existe;
 * std::nullopt en caso contrario.
 *
 * @note Esta funcion no lanza excepciones en el flujo normal: en caso de error
 *       devuelve std::nullopt. Entre la comprobacion y el uso real del fichero
 *       puede producirse una condicion TOCTOU; siempre maneja errores al
 * abrir/usar.
 *
 * @code{.cpp}
 * // Ejemplo 1: archivo relativo existente
 * auto maybe_abs = vfs::get_existing_absolute_path("data/config.json");
 * if (maybe_abs) {
 *     std::cout << "Ruta absoluta: " << maybe_abs->string() << "\n";
 * } else {
 *     std::cout << "No existe o no se pudo resolver\n";
 * }
 *
 * // Ejemplo 2: ruta absoluta
 * auto maybe_abs2 = vfs::get_existing_absolute_path("/etc/hosts");
 * if (maybe_abs2) {
 *     // puede devolver la forma canonica (resolviendo symlinks)
 *     std::cout << "Canonical: " << maybe_abs2->string() << "\n";
 * }
 * @endcode
 */
static std::optional<fs::path> get_existing_absolute_path(const fs::path &p) {
    std::error_code ec;
    if (!fs::exists(p, ec) || ec) return std::nullopt;

    try {
        fs::path can = fs::weakly_canonical(p);
        return can;
    } catch (const fs::filesystem_error &) {
        try {
            fs::path can2 = fs::canonical(p);
            return can2;
        } catch (const fs::filesystem_error &) {
            try {
                fs::path abs = fs::absolute(p);
                return abs.lexically_normal();
            } catch (...) {
                return std::nullopt;
            }
        }
    }
}

/**
 * @brief Comprueba si la ruta existe y es un directorio.
 *
 * @param p Ruta a comprobar.
 * @return true si existe y es un directorio; false en caso contrario o si
 * ocurre un error.
 *
 * @code{.cpp}
 * // Ejemplo: comprobar directorio
 * if (vfs::is_directory("/var/log")) {
 *     std::cout << "/var/log es un directorio\n";
 * } else {
 *     std::cout << "/var/log no es un directorio o no existe\n";
 * }
 * @endcode
 */
static bool is_directory(const fs::path &p) {
    std::error_code ec;
    if (!fs::exists(p, ec) || ec) return false;
    return fs::is_directory(p, ec) && !ec;
}

/**
 * @brief Version que acepta std::string (normaliza y comprueba).
 *
 * Normaliza la cadena (relativa/absoluta) y devuelve la ruta absoluta/canonical
 * si el fichero o directorio existe.
 *
 * @param s Ruta en forma de cadena (absoluta o relativa).
 * @return std::optional<fs::path> con la ruta absoluta si existe; std::nullopt
 * si no existe.
 *
 * @code{.cpp}
 * // Ejemplo: uso con std::string
 * std::string user_path = "./logs/app.log";
 * auto abs = vfs::get_existing_absolute_path_str(user_path);
 * if (abs) {
 *     std::cout << "Archivo existe en: " << abs->string() << "\n";
 * } else {
 *     std::cout << "Archivo no encontrado: " << user_path << "\n";
 * }
 * @endcode
 */
static std::optional<fs::path>
get_existing_absolute_path_str(const std::string &s) {
    return get_existing_absolute_path(normalize_path_safe(fs::path(s)));
}

/**
 * @brief Version string para is_directory (normaliza y comprueba).
 *
 * @param s Ruta en forma de cadena.
 * @return true si la ruta existe y es directorio.
 *
 * @code{.cpp}
 * // Ejemplo: comprobar si una entrada del usuario es directorio
 * std::string candidate = "build";
 * if (vfs::is_directory_str(candidate)) {
 *     std::cout << candidate << " es un directorio\n";
 * } else {
 *     std::cout << candidate << " no es un directorio o no existe\n";
 * }
 * @endcode
 */
static bool is_directory_str(const std::string &s) {
    return fs::is_directory(normalize_path_safe(fs::path(s)));
}

/**
 * @brief Recorre un arbol de directorios usando lo que el listado del sistema
 *        ya devuelve, sin volver a preguntarle por cada entrada.
 *
 * `std::filesystem::recursive_directory_iterator` vuelve a consultar el disco
 * por cada entrada para saber si es un directorio o un fichero regular, cosa
 * que la propia enumeracion acaba de decirle.  Medido sobre las 1989 entradas
 * de un arbol de fuentes: 46 ms con el iterador estandar, 35 con
 * `directory_iterator` y pila propia, y 1,7 asi.  En Linux sobre ext4 la
 * diferencia es menor porque alli el iterador estandar ya es rapido: 1,0 ms
 * contra 0,5.
 *
 * SALVEDAD medida en WSL sobre `/mnt` (9p): ahi `readdir` devuelve
 * `DT_UNKNOWN`, asi que hay que preguntar por cada entrada y esto sale algo mas
 * caro que el iterador estandar (85 ms contra 70), que solo pregunta por las
 * entradas que le interesan.  Es propio de ese puente -- cualquier sistema de
 * ficheros nativo (ext4, btrfs, xfs, tmpfs) informa del tipo en el listado --,
 * y en ese escenario todo el recorrido esta dominado por el propio puente.
 *
 * @param raiz Directorio de partida.  Si no se puede abrir, no se llama a
 *             @p ver ni una vez (no es un error: una raiz de busqueda puede
 *             perfectamente no existir).
 * @param ver  Se invoca por cada entrada con (ruta, es_directorio).  Cuando la
 *             entrada es un directorio, devolver @c false para no bajar a el;
 *             en un fichero el valor devuelto se ignora.  Las entradas `.` y
 *             `..` nunca se pasan.
 */
static void
recorrer_arbol(const std::string &raiz,
               const std::function<bool(const std::string &, bool)> &ver) {
    std::vector<std::string> pendientes;
    pendientes.push_back(raiz);
    while (!pendientes.empty()) {
        std::string dir = std::move(pendientes.back());
        pendientes.pop_back();
        // Sin barra final: las rutas se componen anadiendola nosotros.
        while (dir.size() > 1 && (dir.back() == '/' || dir.back() == '\\'))
            dir.pop_back();
#ifdef _WIN32
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            const char *nombre = fd.cFileName;
            // `.` y `..` no son entradas del arbol.
            if (nombre[0] == '.' &&
                (nombre[1] == '\0' || (nombre[1] == '.' && nombre[2] == '\0')))
                continue;
            const bool es_dir =
                (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            std::string ruta = dir + "/" + nombre;
            const bool bajar = ver(ruta, es_dir);
            if (es_dir && bajar) pendientes.push_back(std::move(ruta));
        } while (FindNextFileA(h, &fd));
        FindClose(h);
#else
        DIR *d = ::opendir(dir.c_str());
        if (!d) continue;
        while (struct dirent *e = ::readdir(d)) {
            const char *nombre = e->d_name;
            if (nombre[0] == '.' &&
                (nombre[1] == '\0' || (nombre[1] == '.' && nombre[2] == '\0')))
                continue;
            std::string ruta = dir + "/" + nombre;
            bool es_dir;
            // `d_type` viene con el listado en los sistemas de ficheros que lo
            // soportan; solo cuando no lo sabe hay que preguntar al disco.
            if (e->d_type != DT_UNKNOWN) {
                es_dir = (e->d_type == DT_DIR);
            } else {
                struct stat st;
                if (::stat(ruta.c_str(), &st) != 0) continue;
                es_dir = S_ISDIR(st.st_mode);
            }
            const bool bajar = ver(ruta, es_dir);
            if (es_dir && bajar) pendientes.push_back(std::move(ruta));
        }
        ::closedir(d);
#endif
    }
}

/**
 * Obtener la ruta del ejecutable actual con el nombre del ejecutable includo
 * @return
 */
static std::string get_executable_path() {
#ifdef _WIN32
    char buffer[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer, len);
#elif __APPLE__
    char buffer[4096];
    uint32_t size = sizeof(buffer);
    _NSGetExecutablePath(buffer, &size);
    return std::string(buffer);
#else
    char buffer[4096];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    buffer[len] = '\0';
    return std::string(buffer);
#endif
}

/**
 * obtener nombre del ejecutable unicamente
 * @return nombre del ejecutable
 */
static std::string get_executable_name() {
    std::string path = get_executable_path();
    return std::filesystem::path(path).filename().string();
}

/**
 * @brief Escribe un fichero de forma ATOMICA: quien lo lea vera el contenido
 *        viejo o el nuevo, nunca uno a medias.
 *
 * Escribe a un temporal unico (proceso + contador, para que dos compilaciones
 * simultaneas no colisionen) y renombra encima.  El renombrado es atomico en
 * los sistemas de ficheros que usamos (NTFS, ext4, btrfs, APFS), y es lo que
 * impide que un corte a mitad de la escritura deje una cache corrupta que
 * ademas parece valida.
 *
 * @param path  Destino.
 * @param bytes Contenido.
 * @return @c true si el destino quedo escrito.
 */
/**
 * @brief Donde van los temporales de las escrituras atomicas.
 *
 * En un directorio propio y NO al lado del destino.  El motivo no es el orden:
 * es que un proceso que muere a mitad de una escritura no puede limpiar detras
 * de si -- eso ES morir --, asi que el temporal se queda.  Al lado del destino
 * eso ensucia el ARBOL DE FUENTES: aparecen `atomic.vxir.tmp.27756.4` junto a
 * `atomic.vx`, salen en `git status` mezclados con lo del proyecto, y quien los
 * vea no sabe si son basura o hacen falta.  En un directorio de cache, en
 * cambio, ya se sabe que todo lo de dentro se puede borrar entero.
 *
 * Se resuelve UNA vez: no cambia durante la vida del proceso.
 */
static const std::string &temp_write_dir() {
    static const std::string dir = [] {
        const std::string &v = util::flag_text(util::FlagId::CacheDir);
        if (!v.empty()) return v + "/tmp";
        return std::string(".cache/tmp");
    }();
    return dir;
}

/**
 * @brief Estan @p a y @p b en el mismo volumen?
 *
 * De esto depende que el renombrado siga siendo atomico.  Renombrar dentro de
 * un volumen es una operacion del sistema de ficheros; entre volumenes no se
 * puede, y quien lo intenta acaba copiando y borrando -- que es exactamente
 * perder la atomicidad que motivaba todo esto, y ademas EN SILENCIO.
 *
 * Por eso no se supone: se pregunta.  Si la respuesta es que no, el temporal se
 * queda al lado del destino y se acepta ensuciar ese directorio antes que
 * arriesgar una escritura a medias.
 */
static bool same_volume(const std::string &a, const std::string &b) {
    std::error_code e1, e2;
#ifdef _WIN32
    char va[MAX_PATH] = {0}, vb[MAX_PATH] = {0};
    if (!GetVolumePathNameA(a.c_str(), va, MAX_PATH)) return false;
    if (!GetVolumePathNameA(b.c_str(), vb, MAX_PATH)) return false;
    return _stricmp(va, vb) == 0;
#else
    struct stat sa, sb;
    if (::stat(a.c_str(), &sa) != 0) return false;
    if (::stat(b.c_str(), &sb) != 0) return false;
    (void)e1;
    (void)e2;
    return sa.st_dev == sb.st_dev;
#endif
}

static bool write_file_atomic(const std::string &path,
                              const std::vector<uint8_t> &bytes) {
    static std::atomic<uint64_t> contador{0};
    std::error_code ec;
    /* El directorio, UNA vez.  Pedirlo en cada escritura son dos llamadas al
     * sistema de ficheros (`stat` + `mkdir`) para saber lo que ya sabiamos:
     * medido en una compilacion en frio, 2.030 escrituras preguntando por los
     * mismos directorios. */
    const std::string dir_padre = fs::path(path).parent_path().string();
    auto asegurar_dir = [&](bool forzar) {
        static std::mutex mx_dirs;
        static std::unordered_set<std::string> hechos;
        bool crear = forzar;
        {
            std::lock_guard<std::mutex> g(mx_dirs);
            if (forzar) hechos.erase(dir_padre);
            crear = hechos.insert(dir_padre).second || forzar;
        }
        if (crear) {
            std::error_code e2;
            fs::create_directories(dir_padre, e2);
        }
    };
    asegurar_dir(false);

    /* DONDE va el temporal.  En el directorio comun si esta en el mismo volumen
     * que el destino; si no, al lado del destino como siempre.
     *
     * La comprobacion se hace UNA vez por directorio de destino y se recuerda,
     * en la misma linea que el memo de arriba: preguntarlo en cada escritura
     * seria otra llamada al sistema por fichero, y la respuesta no cambia. */
    static std::mutex mx_vol;
    static std::unordered_map<std::string, bool> vol_comun;
    bool usar_comun = false;
    {
        std::lock_guard<std::mutex> g(mx_vol);
        auto it = vol_comun.find(dir_padre);
        if (it != vol_comun.end()) {
            usar_comun = it->second;
        } else {
            std::error_code e3;
            fs::create_directories(temp_write_dir(), e3);
            // Si el directorio comun no se pudo crear, no hay nada que
            // comparar: al lado del destino, que siempre funciona.
            usar_comun = fs::exists(temp_write_dir(), e3) &&
                         same_volume(temp_write_dir(), dir_padre);
            vol_comun.emplace(dir_padre, usar_comun);
        }
    }

    /* El nombre lleva el del destino aunque vaya a otro directorio: si un dia
     * queda uno huerfano, se puede saber de que era.  Y lleva el identificador
     * del proceso, que es lo que despues permite decir con certeza que sobra --
     * si ese proceso ya no existe, nadie va a terminarlo. */
    std::string tmp;
    if (usar_comun)
        tmp = temp_write_dir() + "/" + fs::path(path).filename().string() +
              ".tmp.";
    else
        tmp = path + ".tmp.";
#ifdef _WIN32
    tmp += std::to_string(static_cast<uint64_t>(GetCurrentProcessId()));
#else
    tmp += std::to_string(static_cast<uint64_t>(getpid()));
#endif
    tmp +=
        "." + std::to_string(contador.fetch_add(1, std::memory_order_relaxed));
    /* Escritura con las llamadas del SISTEMA, no con las de la biblioteca.
     *
     * `std::ofstream` mete una capa de buffer propia encima: reserva, copia los
     * bytes a su buffer y los vuelca al cerrar.  Para un fichero que se escribe
     * ENTERO de una vez eso no aporta nada -- ya tenemos todos los bytes en un
     * vector -- y se paga en cada uno.  MEDIDO con VTune en una compilacion en
     * frio: `fclose` 0,566 s y `fsopen` 0,118 s de 1,22 s de CPU, mas de la
     * mitad del tiempo, escribiendo 2.030 ficheros pequenos.
     *
     * Aqui se abre, se escribe y se cierra, sin intermediarios. */
    {
#ifdef _WIN32
        HANDLE h = CreateFileA(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            /* El directorio pudo desaparecer despues de crearlo: alguien limpio
             * el cache, o el arbol se borro entre dos escrituras.  El memo de
             * arriba diria que ya existe, asi que se rehace y se reintenta UNA
             * vez.  Sin esto la escritura falla en silencio y el artefacto se
             * pierde sin que nadie se entere. */
            asegurar_dir(true);
            h = CreateFileA(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
        }
        bool ok = true;
        size_t off = 0;
        while (ok && off < bytes.size()) {
            // `WriteFile` toma un contador de 32 bits: los ficheros grandes van
            // en varias tandas en vez de truncarse en silencio.
            const DWORD trozo = static_cast<DWORD>(
                std::min<size_t>(bytes.size() - off, 32u * 1024u * 1024u));
            DWORD escritos = 0;
            ok = WriteFile(h, bytes.data() + off, trozo, &escritos, nullptr) !=
                     0 &&
                 escritos == trozo;
            off += escritos;
        }
        CloseHandle(h);
        if (!ok) {
            fs::remove(tmp, ec);
            return false;
        }
#else
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            // Ver el comentario de la rama de Windows: el memo de directorios
            // puede haber quedado obsoleto si alguien limpio el arbol.
            asegurar_dir(true);
            fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) return false;
        }
        bool ok = true;
        size_t off = 0;
        while (ok && off < bytes.size()) {
            const ssize_t n =
                ::write(fd, bytes.data() + off, bytes.size() - off);
            if (n <= 0)
                ok = false;
            else
                off += static_cast<size_t>(n);
        }
        ::close(fd);
        if (!ok) {
            fs::remove(tmp, ec);
            return false;
        }
#endif
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        // En Windows hay una carrera rara en la que el renombrado falla si otro
        // proceso tiene el destino abierto.  Copiar y borrar como segundo
        // recurso: deja de ser atomico, pero es preferible a no escribir.
        fs::copy_file(tmp, path, fs::copy_options::overwrite_existing, ec);
        std::error_code ec2;
        fs::remove(tmp, ec2);
        return !ec;
    }
    return true;
}

/**
 * @brief Lee un fichero entero a bytes.
 * @param path Ruta.
 * @param out  Destino; queda vacio si no se pudo leer.
 * @return @c true si se leyo entero.
 */
static bool read_file_bytes(const std::string &path,
                            std::vector<uint8_t> &out) {
    out.clear();
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    const std::streamoff tam = f.tellg();
    if (tam < 0) return false;
    out.resize(static_cast<size_t>(tam));
    if (out.empty()) return true;
    f.seekg(0);
    f.read(reinterpret_cast<char *>(out.data()),
           static_cast<std::streamsize>(out.size()));
    if (!f) {
        out.clear();
        return false;
    }
    return true;
}

/**
 * @brief Le pone el bit de ejecucion a un artefacto recien escrito.
 *
 * Los emisores abren el fichero con @c fopen(path,"wb"), que en POSIX lo crea
 * con 0666 & ~umask -- o sea 0644 -- y por tanto SIN permiso de ejecucion.  El
 * resultado es un ELF perfectamente valido que NO se puede ejecutar:
 * `Permission denied` al lanzarlo, sin que nada en la construccion haya
 * fallado.  En Windows no se ve, porque ese bit no existe, asi que el fallo
 * solo aparece en Linux y parece un problema de permisos del usuario.
 *
 * Quien decide es el LLAMANTE, no esta funcion: los mismos emisores escriben
 * `.o` y binarios planos, que NO deben ser ejecutables, y solo arriba se sabe
 * que clase de artefacto se pidio.  Aqui solo esta el COMO, en un sitio, para
 * que los dos caminos que producen ejecutables -- el compilador nativo y el
 * enlazador suelto -- no lo escriban cada uno por su cuenta.
 *
 * Anade el bit a los tres grupos respetando lo que ya haya (0644 -> 0755).  Un
 * fallo no aborta nada: el fichero esta bien escrito, y avisar es mas util que
 * tirar un build entero por un permiso.
 *
 * @param path Artefacto a marcar.  En Windows no hace nada.
 * @return true si se marco (o si el sistema no tiene ese bit).
 */
static bool mark_executable(const std::string &path) {
#ifndef _WIN32
    std::error_code ec;
    fs::permissions(path,
                    fs::perms::owner_exec | fs::perms::group_exec |
                        fs::perms::others_exec,
                    fs::perm_options::add, ec);
    return !ec;
#else
    (void)path;
    return true;
#endif
}
} // namespace fs

#endif // FS_UTILS_H
