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
 * @file cli.cpp
 * @brief Implementacion del interprete interactivo (REPL) de VestaVM.
 *
 * Implementa @c cli::VestaViewManager y @c cli::VestaInterprete:
 * lectura de linea con historial, despacho de comandos mediante tabla de
 * registros (@c CmdEntry), callbacks y parseo de parametros con comillas.
 *
 * Para anadir un nuevo comando basta con:
 *   1. Escribir una funcion @c static void mi_cmd(const std::string &args).
 *   2. Anadir una entrada @c CmdEntry en @c cmd_table con el nombre, uso,
 * descripcion y handler. No se necesita modificar el bucle principal de @c
 * VestaViewManager::run().
 */
#include "cli/cli.h"
#include <algorithm> // UCRT64: no transitivo
#include "cli/vsh.h"

#include <cstdio>

#include "cli/cli_init_manager_and_server.h"
#include "cli/sync_io.h"
#include "emmit/parser_to_bytecode.h"
#include "util/assembler_multiprocess.h"
#include "assembly/assembly.h"
#include "runtime/decode_table.h"
#include "runtime/proceso_runtime.h"
#include "distrib/dist_runtime.h"
#include "distrib/node_registry.h"
#include "loader/oop_types.h"
#include "gc/gc_heap.h"
#include "disasm/disasm.h"
#include "util/ansi.h"
#include "util/fs_utils.h"
#include <cstring>
#include <iomanip>
#include <unordered_set>
#include <chrono>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <openssl/sha.h>
#ifdef VESTA_HAS_PREPROCESSOR
#include "preprocessor/preprocessor.h"
#endif

#if defined(_WIN32)
#include <conio.h>
#include <windows.h> // Sleep()
#else
#include <termios.h>
#include <unistd.h>
#include <cerrno>
#include <poll.h> // poll() para readline_impl no-bloqueante
#endif

#include "vx/source_text.h" // un solo fin de linea para todo el pipeline

namespace cli {
#ifndef _WIN32
// POSIX: recorrer el array 'environ' terminado en NULL
using ::environ;
#endif
static ManagerOfManagersAndServer mgr = ManagerOfManagersAndServer();

// ---- almacen persistente de aliases ----

/**
 * @brief Mapa de aliases del REPL con ruta del fichero de persistencia.
 *
 * Acceso concurrente protegido por @c mtx.  Los comandos alias/unalias
 * guardan inmediatamente tras cada modificacion para que la siguiente sesion
 * vea los cambios.
 */
struct AliasStore {
    std::map<std::string, std::string> map; ///< nombre -> expansion
    std::string file = "vm_aliases.txt";    ///< ruta del fichero
    std::mutex mtx;
};

static AliasStore g_aliases;

// ---- registro de tareas en background (jobs) ----

/** @brief Entrada de un job lanzado con run/exec. */
struct JobEntry {
    size_t id;
    std::string name;
    std::atomic<bool> done{false};
    std::string result_msg;
    std::chrono::steady_clock::time_point start_time;
};

/** @brief Almacen global de jobs con condvar para command_wait. */
struct JobStore {
    std::map<size_t, std::shared_ptr<JobEntry>> jobs;
    std::mutex mtx;
    std::condition_variable cv;
    size_t next_id = 1;
};
static JobStore g_jobs;

/** @brief Registra un nuevo job y devuelve su entrada (shared_ptr). */
static std::shared_ptr<JobEntry> job_register(const std::string &name) {
    auto e = std::make_shared<JobEntry>();
    std::lock_guard<std::mutex> lk(g_jobs.mtx);
    e->id = g_jobs.next_id++;
    e->name = name;
    e->start_time = std::chrono::steady_clock::now();
    g_jobs.jobs[e->id] = e;
    return e;
}

/** @brief Marca el job como terminado y notifica a wait. */
static void job_done(std::shared_ptr<JobEntry> e, const std::string &msg) {
    e->result_msg = msg;
    e->done = true;
    g_jobs.cv.notify_all();
}

// ---- fichero de variables de entorno persistentes ----

static std::string g_env_file = "vm_env.txt";

/** @brief Carga vm_env.txt: cada linea KEY=VALUE se aplica al entorno. */
static void env_load_file(const std::string &path) {
    std::ifstream f(path);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
#if defined(_WIN32)
        SetEnvironmentVariableA(k.c_str(), v.c_str());
#else
        setenv(k.c_str(), v.c_str(), 1);
#endif
    }
}

/** @brief Guarda el entorno completo en @p path. */
static void env_save_file(const std::string &path) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return;
    f << "# VestaVM env persistente\n";
#if defined(_WIN32)
    char *block = GetEnvironmentStringsA();
    if (block) {
        for (char *p = block; *p; p += std::strlen(p) + 1) {
            std::string e(p);
            auto eq = e.find('=');
            if (eq == 0 || eq == std::string::npos) continue;
            f << e << "\n";
        }
        FreeEnvironmentStringsA(block);
    }
#else
    for (char **ep = environ; ep && *ep; ++ep) {
        std::string e(*ep);
        if (e.find('=') == std::string::npos) continue;
        f << e << "\n";
    }
#endif
}

// ---- puntero al Impl activo (para command_set) ----
static Impl *g_current_impl = nullptr;

// ---- helpers de aliases ----

/**
 * @brief Carga el fichero de aliases en @p a.
 *
 * Formato: una linea por alias, "nombre=expansion".
 * Las lineas vacias o que empiezan por '#' se ignoran.
 */
static void aliases_load(AliasStore &a) {
    std::lock_guard<std::mutex> lk(a.mtx);
    std::ifstream f(a.file);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        a.map[line.substr(0, eq)] = line.substr(eq + 1);
    }
}

/**
 * @brief Guarda el mapa de aliases de @p a en el fichero de persistencia.
 *
 * Sobreescribe el fichero completo; se llama tras cada cambio.
 */
static void aliases_save(AliasStore &a) {
    std::lock_guard<std::mutex> lk(a.mtx);
    std::ofstream f(a.file, std::ios::trunc);
    if (!f) return;
    f << "# VestaVM aliases - no editar mientras el REPL esta activo\n";
    for (auto &[k, v] : a.map)
        f << k << "=" << v << "\n";
}

using namespace Assembly::Bytecode;

/**
 * @brief Estado interno del REPL: configuracion, historial, cola de comandos y
 * worker.
 */
struct Impl {
    Config cfg;

    // estado
    std::atomic<bool> running{false};
    std::atomic<bool> interrupted_flag{false};

    // historial
    std::vector<std::string> history;
    std::mutex hist_m;
    int history_cursor = -1;

    // cola de comandos
    std::deque<std::string> cmd_queue;
    std::mutex q_m;
    std::condition_variable q_cv;
    bool q_closed = false;

    // worker
    std::thread worker_thread;

    // callback
    std::function<void(const std::string &)> vm_execute_cb;
    std::mutex cb_m;

    Impl(Config c) : cfg(std::move(c)) {}
};

// ---- utilidades generales ----

/**
 * @brief Divide una cadena en palabras separadas por espacios.
 * @param s Cadena de entrada.
 * @return Vector de palabras.
 */
static std::vector<std::string> split_words(const std::string &s) {
    std::istringstream iss(s);
    std::vector<std::string> out;
    std::string w;
    while (iss >> w)
        out.push_back(w);
    return out;
}

/**
 * @brief Expande variables de entorno ($VAR) y "~" (HOME) en una cadena de
 * ruta.
 *
 * Orden de expansion:
 *   1. Sustituye cada token $VAR o ${VAR} por el valor de la variable de
 * entorno.
 *   2. Si la cadena resultante empieza por '~', la sustituye por
 * HOME/USERPROFILE.
 *
 * @param p Cadena de ruta, opcionalmente con '$VAR' y/o '~'.
 * @return Ruta expandida; directorio actual si @p p esta vacio.
 */
static std::filesystem::path expand_path(const std::string &p) {
    if (p.empty()) return std::filesystem::current_path();

    // paso 1: expandir $VAR y ${VAR}
    std::string expanded;
    expanded.reserve(p.size());
    for (size_t i = 0; i < p.size();) {
        if (p[i] == '$') {
            ++i;
            bool braced = (i < p.size() && p[i] == '{');
            if (braced) ++i;
            size_t start = i;
            while (
                i < p.size() &&
                (std::isalnum(static_cast<unsigned char>(p[i])) || p[i] == '_'))
                ++i;
            if (braced && i < p.size() && p[i] == '}') ++i; // consumir '}'
            std::string varname = p.substr(start, i - start);
            if (!varname.empty()) {
                const char *v = std::getenv(varname.c_str());
                if (v) expanded += v;
            } else {
                expanded += '$'; // '$' sin nombre de variable: literal
            }
        } else {
            expanded += p[i++];
        }
    }

    // paso 2: expandir '~' al directorio HOME
    if (!expanded.empty() && expanded[0] == '~') {
        const char *home = std::getenv(
#if defined(_WIN32)
            "USERPROFILE"
#else
            "HOME"
#endif
        );
        std::string home_s = home ? home : "";
        if (expanded.size() == 1) return std::filesystem::path(home_s);
        if (!home_s.empty())
            return std::filesystem::path(home_s) / expanded.substr(2);
        return std::filesystem::path(expanded.substr(1));
    }
    return std::filesystem::path(expanded);
}

/**
 * @brief Limpia la pantalla de la consola de forma portatil.
 *
 * En POSIX usa la secuencia ANSI ESC[2J ESC[H.
 * En Windows intenta habilitar Virtual Terminal Processing y, si falla,
 * recurre a system("cls").
 */
static void clear_screen() {
#if defined(_WIN32)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            if ((dwMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0) {
                if (SetConsoleMode(
                        hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
                    std::cout << "\x1B[2J\x1B[H" << std::flush;
                    return;
                }
            } else {
                std::cout << "\x1B[2J\x1B[H" << std::flush;
                return;
            }
        }
    }
    std::system("cls");
#else
    std::cout << "\x1B[2J\x1B[H" << std::flush;
#endif
}

/**
 * @brief Ejecuta un comando de shell y devuelve su salida completa
 * (stdout+stderr).
 * @param cmd Comando a ejecutar.
 * @return Salida combinada del proceso, con el codigo de retorno al final.
 * @throws std::runtime_error si no se puede abrir el proceso.
 */
static std::string execute_shell_command(const std::string &cmd) {
    std::string full_cmd;
#if defined(_WIN32)
    full_cmd = "cmd.exe /C \"" + cmd + "\" 2>&1";
    FILE *pipe = _popen(full_cmd.c_str(), "r");
#else
    full_cmd = cmd + " 2>&1";
    FILE *pipe = popen(full_cmd.c_str(), "r");
#endif
    if (!pipe) throw std::runtime_error("failed to open pipe for command");

    std::string result;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe))
        result.append(buf);

#if defined(_WIN32)
    int rc = _pclose(pipe);
#else
    int rc = pclose(pipe);
#endif
    result += "\n[exit code: " + std::to_string(rc) + "]";
    return result;
}

// ---- implementaciones de comandos ----
// Cada funcion recibe la cadena de argumentos que sigue al nombre del comando.

// hook noop: activa la medicion de time_exec en el scheduler sin hacer nada
static void noop_debug_hook(runtime::ProcessVM *, runtime::DebugStage) {}

/**
 * @brief Lista todos los managers activos con su ID, nombre y numero de VMs.
 * @param args Sin uso (puede estar vacio).
 */
static void command_vms(const std::string &) {
    auto snaps = mgr.snapshot();
    if (snaps.empty()) {
        std::cout << "(no hay managers activos)\n";
        return;
    }
    for (auto &[id, snap] : snaps) {
        std::cout << "[" << id << "] " << snap.name_manager
                  << "  VMs=" << snap.vm_count
                  << (snap.has_listener ? "  TCP=si" : "  TCP=no") << "\n";
    }
}

/**
 * @brief Ejecuta un .velb en background creando un manager temporal.
 *
 * Formato: <nombre> <ruta.velb> [--schedulers N]
 *
 * @param args Argumentos del comando: nombre, ruta y opciones opcionales.
 */
static void command_run(const std::string &args) {
    CmdParams p = parse_cmd_params(args);
    if (!p.valid) {
        vesta::scout()
            << "Uso: run <nombre> <ruta.velb> [--schedulers N] [--stats]\n";
        return;
    }

    auto path = fs::normalize_path_safe(p.path);
    if (!fs::file_exists(path)) {
        vesta::scout() << "No existe el archivo: " << path.string() << "\n";
        return;
    }
    if (!fs::is_regular_file(path)) {
        vesta::scout() << "No es archivo regular: " << path.string() << "\n";
        return;
    }
    if (!fs::can_read(path)) {
        vesta::scout() << "No se puede leer: " << path.string() << "\n";
        return;
    }
    auto maybe_abs = fs::get_existing_absolute_path(path);
    if (!maybe_abs) {
        vesta::scout() << "No se pudo resolver la ruta: " << path.string()
                       << "\n";
        return;
    }

    // leer opciones --schedulers y --stats del resto de la linea
    size_t num_schedulers = 1;
    bool show_stats = false;
    {
        auto ws = split_words(p.rest);
        for (auto it = ws.begin(); it != ws.end(); ++it) {
            if (*it == "--schedulers" && std::next(it) != ws.end()) {
                try {
                    num_schedulers = std::stoul(*std::next(it));
                } catch (...) {
                }
            }
            if (*it == "--stats") show_stats = true;
        }
    }

    std::string abs_path = maybe_abs->string();
    std::string name = p.name;

    // registrar en mgr global para que sea visible por mgrinfo/vmstat/schedtop
    runtime::ManageVM *vm_mgr_raw = mgr.add_manager(name, nullptr);
    size_t registered_id = vm_mgr_raw->id;

    // lanzar en hilo separado para no bloquear el REPL
    std::thread([abs_path, name, num_schedulers, show_stats, vm_mgr_raw,
                 registered_id]() {
        try {
            auto t0 = std::chrono::steady_clock::now();
            runtime::VM *vm =
                vm_mgr_raw->loader.create_vm_instance(num_schedulers);
            if (!vm) {
                vesta::scout() << "[run] '" << name << "': error al crear VM\n";
                mgr.remove_manager(registered_id);
                return;
            }
            runtime::ProcessVM *proc =
                vm_mgr_raw->loader.load_executable(*vm, abs_path);
            if (!proc) {
                vesta::scout() << "[run] '" << name << "': error al cargar\n";
                mgr.remove_manager(registered_id);
                return;
            }
            // activar hooks de medicion solo si el usuario pidio --stats
            if (show_stats) {
                for (auto &sched : vm->schedulers)
                    sched->add_debug_hook(noop_debug_hook);
            }
            vm->make_ready(proc->pid);
            vm->start();
            while (vm->has_alive_processes())
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            auto t1 = std::chrono::steady_clock::now();
            vm->stop();
            if (show_stats) {
                double elapsed_ms =
                    std::chrono::duration<double, std::milli>(t1 - t0).count();
                /* Sin factor de escala: el contador se incrementa una vez por
                 * instruccion retirada.  Llevaba un `* 256` que salia de un
                 * comentario equivocado en su declaracion. */
                uint64_t total_instr = 0;
                for (auto &sched : vm->schedulers)
                    total_instr += sched->profiler_instr_counter;
                double mips = (elapsed_ms > 0)
                                  ? (total_instr / 1e6) / (elapsed_ms / 1000.0)
                                  : 0.0;
                std::ostringstream ss;
                ss << ansi::c(ansi::BOLD) << ansi::c(ansi::BR_CYAN)
                   << "[stats] '" << name << "'" << ansi::c(ansi::RESET)
                   << "\n";
                ss << "  Tiempo:              " << std::fixed
                   << std::setprecision(2) << elapsed_ms << " ms\n";
                ss << "  Instrucciones aprox: " << total_instr << "\n";
                ss << "  MIPS aprox:          " << std::fixed
                   << std::setprecision(2) << mips << "\n";
                ss << "  Schedulers:          " << vm->schedulers.size()
                   << "\n";
                for (size_t i = 0; i < vm->schedulers.size(); ++i) {
                    auto &sched = *vm->schedulers[i];
                    ss << "    [sched " << i << "]"
                       << "  instr=" << sched.profiler_instr_counter
                       << "  time_exec=" << sched.time_exec << " ns\n";
                }
                vesta::scout() << ss.str();
            }
            vesta::scout() << "[run] '" << name << "' finalizado\n";
        } catch (const std::exception &e) {
            vesta::scout() << "[run] '" << name << "' error: " << e.what()
                           << "\n";
        }
        mgr.remove_manager(registered_id); // limpiar del registro al terminar
    }).detach();

    vesta::scout() << "[run] '" << name
                   << "' lanzado en background (id=" << registered_id << ")\n";
}

/**
 * @brief Compara un nombre de archivo contra un patron glob (solo nombre, sin
 * separadores).
 *
 * Soporta:
 *   '*' — cualquier secuencia de caracteres (incluyendo vacia)
 *   '?' — exactamente un caracter cualquiera
 *
 * @param pattern Patron glob (e.g. "*.vel", "test_??.velb", "build*").
 * @param name    Nombre de archivo a comparar.
 * @return true si @p name coincide con @p pattern.
 */
static bool glob_match(const std::string &pattern, const std::string &name) {
    size_t p = 0, n = 0;
    // posicion del ultimo '*' visto y la posicion en name en ese momento
    size_t star_p = std::string::npos, star_n = 0;
    while (n < name.size()) {
        if (p < pattern.size() &&
            (pattern[p] == '?' || pattern[p] == name[n])) {
            ++p;
            ++n; // caracter literal o '?' coinciden: avanzar ambos
        } else if (p < pattern.size() && pattern[p] == '*') {
            star_p = p++; // guardar posicion del '*' y avanzar patron
            star_n = n;   // '*' consume cero caracteres inicialmente
        } else if (star_p != std::string::npos) {
            p = star_p + 1; // retroceder al patron tras el ultimo '*'
            n = ++star_n;   // el '*' consume un caracter mas de name
        } else {
            return false; // sin '*' disponible para retroceder: no coincide
        }
    }
    // consumir '*' finales del patron (e.g. "*.vel*")
    while (p < pattern.size() && pattern[p] == '*')
        ++p;
    return p == pattern.size();
}

/**
 * @brief Lista el contenido de un directorio con soporte de patrones glob.
 *
 * Directorios en azul brillante, archivos en verde brillante.
 * Columnas: tipo (D/F), tamano, fecha de modificacion, nombre.
 * Orden: directorios primero, luego archivos, ambos alfabeticos.
 *
 * Formatos soportados:
 *   ls                  lista el directorio actual
 *   ls <dir>            lista <dir>
 *   ls *.vel            archivos que coincidan con el patron en el dir actual
 *   ls src/*.velb       archivos que coincidan con el patron en src/
 *   ls test_??.vel      patron con '?' (un caracter cualquiera)
 *
 * @param args Ruta, patron glob, o ruta + patron glob.
 */
static void command_ls(const std::string &args) {
    namespace fsp = std::filesystem;

    // detectar si el argumento contiene un caracter glob
    bool has_glob = args.find('*') != std::string::npos ||
                    args.find('?') != std::string::npos;

    fsp::path target;
    std::string pattern; // vacio = sin filtro

    if (has_glob) {
        // separar la parte de directorio de la parte de patron
        // e.g. "src/*.vel" -> parent="src", filename="*.vel"
        // e.g. "*.vel"     -> parent="",    filename="*.vel"
        fsp::path raw(args);
        fsp::path parent = raw.parent_path();
        pattern = raw.filename().string();
        target =
            parent.empty() ? fsp::current_path() : expand_path(parent.string());
    } else {
        target = args.empty() ? fsp::current_path() : expand_path(args);
    }

    if (!fsp::exists(target) || !fsp::is_directory(target)) {
        std::cout << "ls: no es un directorio: " << target.string() << "\n";
        return;
    }

    struct Entry {
        bool is_dir;
        std::string name;
        uintmax_t size_bytes;
        std::string mtime_str;
    };

    std::vector<Entry> entries;
    std::error_code ec;
    for (const auto &e : fsp::directory_iterator(target, ec)) {
        std::string fname = e.path().filename().string();

        // aplicar filtro glob si se especifico patron
        if (!pattern.empty() && !glob_match(pattern, fname)) continue;

        Entry ent;
        ent.is_dir = fsp::is_directory(e);
        ent.name = fname;
        ent.size_bytes = 0;
        if (!ent.is_dir) {
            try {
                ent.size_bytes = fsp::file_size(e);
            } catch (...) {
            }
        }
        // convertir file_time_type a system_clock para formatear con strftime
        try {
            auto ft = fsp::last_write_time(e);
            auto diff = ft - fsp::file_time_type::clock::now();
            auto stp =
                std::chrono::system_clock::now() +
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    diff);
            auto tt = std::chrono::system_clock::to_time_t(stp);
            char buf[32] = "?";
            struct tm *tmi = std::localtime(&tt);
            if (tmi) std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", tmi);
            ent.mtime_str = buf;
        } catch (...) {
            ent.mtime_str = "?";
        }
        entries.push_back(std::move(ent));
    }

    // ordenar: directorios primero, luego archivos; alfabetico dentro de cada
    // grupo
    std::sort(entries.begin(), entries.end(),
              [](const Entry &a, const Entry &b) {
                  if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;
                  return a.name < b.name;
              });

    // cabecera: mostrar patron activo si se uso glob
    if (!pattern.empty()) {
        std::cout << ansi::c(ansi::DIM) << "Patron: " << ansi::c(ansi::RESET)
                  << ansi::c(ansi::BOLD) << pattern << ansi::c(ansi::RESET)
                  << ansi::c(ansi::DIM) << "  en: " << target.string()
                  << ansi::c(ansi::RESET) << "\n";
    }

    if (entries.empty()) {
        std::cout << ansi::c(ansi::DIM) << "(sin resultados)\n"
                  << ansi::c(ansi::RESET);
        return;
    }

    // formatea tamano en unidades legibles
    auto fmt_size = [](uintmax_t sz) -> std::string {
        if (sz < 1024) return std::to_string(sz) + " B";
        if (sz < 1024 * 1024) return std::to_string(sz / 1024) + " KB";
        return std::to_string(sz / (1024 * 1024)) + " MB";
    };

    std::cout << ansi::c(ansi::BOLD) << std::left << std::setw(4) << "T"
              << std::setw(12) << "Tamano" << std::setw(20) << "Modificado"
              << "Nombre" << ansi::c(ansi::RESET) << "\n"
              << std::string(60, '-') << "\n";

    for (auto &e : entries) {
        const char *col =
            e.is_dir ? ansi::c(ansi::BR_BLUE) : ansi::c(ansi::BR_GREEN);
        std::string type_s = e.is_dir ? "D" : "F";
        std::string size_s = e.is_dir ? "<DIR>" : fmt_size(e.size_bytes);
        std::string name_s = e.is_dir ? e.name + "/" : e.name;
        std::cout << col << std::left << std::setw(4) << type_s << std::setw(12)
                  << size_s << std::setw(20) << e.mtime_str << name_s
                  << ansi::c(ansi::RESET) << "\n";
    }

    // pie con conteo cuando se usa patron
    if (!pattern.empty()) {
        std::cout << ansi::c(ansi::DIM) << std::string(60, '-') << "\n"
                  << entries.size() << " resultado(s)\n"
                  << ansi::c(ansi::RESET);
    }
}

/**
 * @brief Compila un archivo .vel a .velb usando el ensamblador en modo worker.
 * @param args "<archivo.vel> [-o <salida>]"
 */
static void command_build(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: build <archivo.vel> [-o <salida>]\n";
        return;
    }
    std::string src = words[0];
    std::string out = "out"; // prefijo por defecto
    for (size_t i = 1; i + 1 < words.size(); ++i) {
        if (words[i] == "-o") {
            out = words[i + 1];
            break;
        }
    }
    int rc = asm_multi_process::run_worker(src, out);
    if (rc == EXIT_SUCCESS)
        std::cout << "[build] OK -> " << out << ".velb\n";
    else
        std::cout << "[build] error (codigo " << rc << ")\n";
}

/**
 * @brief Preprocesa un archivo .vel con vpp y muestra o guarda el resultado.
 *
 * Expande macros, directivas #define/#if/#foreach/#import, etc. sin compilar.
 * Util para depurar macros y verificar la salida del preprocesador.
 *
 * Formato: <archivo.vel> [-o <salida>] [-D NAME[=val]] [-I ruta] [-M ruta]
 *
 * @param args Argumentos del comando.
 */
static void command_vpp(const std::string &args) {
#ifndef VESTA_HAS_PREPROCESSOR
    vesta::scout() << "[vpp] El preprocesador no esta disponible en esta build "
                      "(recompilar con VESTA_BUILD_PREPROCESSOR=ON)\n";
    (void)args;
#else
    // --- parsear argumentos ---
    auto words = split_words(args);
    if (words.empty()) {
        vesta::scout() << "Uso: vpp <archivo.vel> [-o <salida>] "
                          "[-D NAME[=val]] [-I ruta] [-M ruta]\n";
        return;
    }

    std::string src_file;
    std::string out_file; // vacio = stdout del REPL
    std::vector<std::string> defines;
    std::vector<std::string> inc_paths;
    std::vector<std::string> imp_paths;

    for (size_t i = 0; i < words.size(); ++i) {
        const auto &w = words[i];
        if (w == "-o" && i + 1 < words.size()) {
            out_file = words[++i];
        } else if (w.size() > 2 && w.substr(0, 2) == "-D") {
            defines.push_back(w.substr(2));
        } else if (w == "-D" && i + 1 < words.size()) {
            defines.push_back(words[++i]);
        } else if (w.size() > 2 && w.substr(0, 2) == "-I") {
            inc_paths.push_back(w.substr(2));
        } else if (w == "-I" && i + 1 < words.size()) {
            inc_paths.push_back(words[++i]);
        } else if (w.size() > 2 && w.substr(0, 2) == "-M") {
            imp_paths.push_back(w.substr(2));
        } else if (w == "-M" && i + 1 < words.size()) {
            imp_paths.push_back(words[++i]);
        } else if (src_file.empty()) {
            src_file = w;
        }
    }

    // --- leer el archivo fuente ---
    // Con un solo fin de linea: lo que entra al preprocesador tiene que verse
    // igual venga de donde venga (ver @ref vx::leer_fuente).
    std::string source;
    if (!vx::leer_fuente(src_file, source)) {
        vesta::scout() << "[vpp] No se puede abrir: " << src_file << "\n";
        return;
    }

    // --- configurar el preprocesador ---
    bool had_error = false;
    vpp::Preprocessor pp([&had_error](const vpp::Diagnostic &d) {
        vesta::scout() << d.format() << "\n";
        if (d.level >= vpp::DiagLevel::ERR) had_error = true;
    });

    // directorio del archivo fuente para #include relativos
    std::string src_dir =
        std::filesystem::path(src_file).parent_path().string();
    if (src_dir.empty()) src_dir = ".";
    pp.options().include_paths.push_back(src_dir);

    // rutas de stdlib (igual que en run_worker)
    std::string exe_dir =
        std::filesystem::path(fs::get_executable_path()).parent_path().string();
    // Relativo al exe (dev: vm.exe junto a preprocessor/include_lib o al repo).
    pp.options().import_paths.push_back(exe_dir + "/preprocessor/include_lib");
    pp.options().import_paths.push_back(exe_dir + "/include_lib");
    // Relativo al PADRE del exe: instalacion con vesta.exe en <prefix>/bin y el
    // include_lib (fuente VPP, no binario) en <prefix>/include_lib.
    {
        std::string parent =
            std::filesystem::path(exe_dir).parent_path().string();
        if (!parent.empty()) {
            pp.options().import_paths.push_back(parent + "/include_lib");
            pp.options().import_paths.push_back(parent +
                                                "/preprocessor/include_lib");
        }
    }
    pp.options().import_paths.push_back(src_dir);

    // rutas adicionales del usuario
    for (auto &p : inc_paths)
        pp.options().include_paths.push_back(p);
    for (auto &p : imp_paths)
        pp.options().import_paths.push_back(p);
    for (auto &d : defines)
        pp.options().predefines.push_back(d);

    // macros de plataforma
#ifdef _WIN32
    pp.options().predefines.push_back("__VPP_WINDOWS__");
#elif defined(__linux__)
    pp.options().predefines.push_back("__VPP_LINUX__");
#elif defined(__APPLE__)
    pp.options().predefines.push_back("__VPP_MACOS__");
#endif
#if defined(__x86_64__) || defined(_M_X64)
    pp.options().predefines.push_back("__VPP_X86_64__");
#elif defined(__i386__) || defined(_M_IX86)
    pp.options().predefines.push_back("__VPP_X86_32__");
#elif defined(__aarch64__) || defined(_M_ARM64)
    pp.options().predefines.push_back("__VPP_AARCH64__");
#endif

    // --- ejecutar el preprocesador ---
    std::string result = pp.process(source, src_file);

    if (had_error) {
        vesta::scout() << "[vpp] preprocesado fallido con "
                       << pp.diagnostics().error_count() << " error(es)\n";
        return;
    }

    if (pp.diagnostics().warning_count() > 0)
        vesta::scout() << "[vpp] " << pp.diagnostics().warning_count()
                       << " advertencia(s)\n";

    // --- escribir resultado ---
    if (out_file.empty()) {
        // sin -o: imprimir directamente en el REPL con numeracion de lineas
        std::istringstream ss(result);
        std::string line;
        size_t n = 1;
        vesta::scout() << ansi::c(ansi::DIM) << "--- " << src_file
                       << " (preprocesado) ---\n"
                       << ansi::c(ansi::RESET);
        while (std::getline(ss, line)) {
            vesta::scout() << ansi::c(ansi::DIM) << std::setw(4) << n++ << "  "
                           << ansi::c(ansi::RESET) << line << "\n";
        }
        vesta::scout() << ansi::c(ansi::DIM) << "---\n" << ansi::c(ansi::RESET);
    } else {
        std::ofstream ofs(out_file, std::ios::binary);
        if (!ofs) {
            vesta::scout() << "[vpp] No se puede crear: " << out_file << "\n";
            return;
        }
        ofs << result;
        vesta::scout() << "[vpp] OK -> " << out_file << "  (" << result.size()
                       << " bytes)\n";
    }
#endif
}

/**
 * @brief Desensambla un archivo .velb usando las tablas internas de VestaVM.
 *
 * Delega en disasm::disasm_velb() del modulo src/disasm/disasm.cpp.
 *
 * @param args "<archivo.velb>"
 */
static void command_disasm(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: disasm <archivo.velb>\n";
        return;
    }
    try {
        disasm::disasm_velb(words[0], std::cout);
    } catch (const std::exception &e) {
        std::cout << "[disasm] error: " << e.what() << "\n";
    }
}

/**
 * @brief Ejecuta un .velb en una VM temporal en segundo plano.
 * @param args "<archivo.velb> [--schedulers N]"
 */
static void command_exec(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: exec <archivo.velb> [--schedulers N]\n";
        return;
    }
    std::string file = words[0];
    size_t schedulers_ = 1;
    for (size_t i = 1; i + 1 < words.size(); ++i) {
        if (words[i] == "--schedulers") {
            try {
                schedulers_ = std::stoul(words[i + 1]);
            } catch (...) {
            }
        }
    }
    // registrar en mgr global para monitorear con mgrinfo/vmstat/schedtop
    runtime::ManageVM *exec_mgr = mgr.add_manager(file, nullptr);
    size_t exec_id = exec_mgr->id;
    vesta::scout() << "[exec] lanzando '" << file << "' (id=" << exec_id
                   << ")...\n";

    std::thread([file, schedulers_, exec_mgr, exec_id]() {
        try {
            runtime::VM *vm = exec_mgr->loader.create_vm_instance(schedulers_);
            if (!vm) {
                vesta::scout() << "[exec] error: no se pudo crear VM\n";
                mgr.remove_manager(exec_id);
                return;
            }
            runtime::ProcessVM *proc =
                exec_mgr->loader.load_executable(*vm, file);
            if (!proc) {
                vesta::scout()
                    << "[exec] error: no se pudo cargar el archivo\n";
                mgr.remove_manager(exec_id);
                return;
            }
            vm->make_ready(proc->pid);
            vm->start();
            while (vm->has_alive_processes())
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            vm->stop();
            vesta::scout() << "[exec] '" << file << "' finalizado\n";
        } catch (const std::exception &e) {
            vesta::scout() << "[exec] error: " << e.what() << "\n";
        }
        mgr.remove_manager(exec_id); // limpiar del registro al terminar
    }).detach();
}

/**
 * @brief Detiene y elimina el manager con el ID indicado.
 * @param args "<id>"
 */
static void command_kill(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: kill <id>\n";
        return;
    }
    try {
        size_t id = std::stoul(words[0]);
        if (mgr.remove_manager(id))
            std::cout << "[kill] manager " << id << " eliminado\n";
        else
            std::cout << "[kill] ID " << id << " no encontrado\n";
    } catch (...) {
        std::cout << "Uso: kill <id>  (ID debe ser un numero entero)\n";
    }
}

/**
 * @brief Muestra el directorio de trabajo actual.
 * @param args Sin uso.
 */
static void command_pwd(const std::string &) {
    std::lock_guard<std::mutex> lk(vesta::cout_mutex);
    std::cout << std::filesystem::current_path().string() << "\n";
}

/**
 * @brief Limpia la pantalla de la consola.
 * @param args Sin uso.
 */
static void command_clear(const std::string &) {
    std::lock_guard<std::mutex> lk(vesta::cout_mutex);
    clear_screen();
}

/**
 * @brief Cambia el directorio de trabajo actual.
 *
 * Soporta: sin argumentos (ir a HOME), "-" (volver al anterior) y rutas
 * normales.
 *
 * @param args Ruta destino, "-" o cadena vacia para HOME.
 */
static void command_cd(const std::string &args) {
    // directorio anterior memorizado entre llamadas
    static std::filesystem::path previous_dir = std::filesystem::current_path();

    try {
        std::filesystem::path target;
        if (args.empty()) {
            // sin argumentos: ir al HOME
            const char *home = std::getenv(
#if defined(_WIN32)
                "USERPROFILE"
#else
                "HOME"
#endif
            );
            if (!home) {
                std::lock_guard<std::mutex> lk(vesta::cout_mutex);
                std::cerr << "cd: HOME no definido\n";
                return;
            }
            target = std::filesystem::path(home);
        } else if (args == "-") {
            target = previous_dir; // volver al directorio anterior
        } else {
            target = expand_path(args);
            if (target.is_relative())
                target = std::filesystem::current_path() / target;
        }

        target = std::filesystem::weakly_canonical(target);

        if (!std::filesystem::exists(target) ||
            !std::filesystem::is_directory(target)) {
            std::lock_guard<std::mutex> lk(vesta::cout_mutex);
            std::cerr << "cd: no existe o no es directorio: " << target.string()
                      << "\n";
            return;
        }

        // cambiar directorio y actualizar el anterior
        std::filesystem::path old = std::filesystem::current_path();
        std::filesystem::current_path(target);
        previous_dir = old;

        std::lock_guard<std::mutex> lk(vesta::cout_mutex);
        std::cout << "Directorio actual: "
                  << std::filesystem::current_path().string() << "\n";
    } catch (const std::exception &e) {
        std::lock_guard<std::mutex> lk(vesta::cout_mutex);
        std::cerr << "cd: error: " << e.what() << "\n";
    }
}

/**
 * @brief Ejecuta un comando de shell en un hilo separado (no bloquea el REPL).
 * @param args Comando de shell a ejecutar.
 */
static void command_cmd(const std::string &args) {
    if (args.empty()) {
        std::cout << "Uso: cmd <comando de shell>\n";
        return;
    }
    // IMPORTANTE: ejecutar SINCRONICAMENTE.  Antes este comando spawneaba
    // un std::thread detached y retornaba al instante, lo que rompia
    // `execute_repl_line` (el cliente TCP perdia toda la salida porque
    // la captura via rdbuf ya se habia restaurado cuando el thread
    // escribia a cout).  Ahora bloqueamos hasta tener el output completo
    // del shell, lo emitimos a cout (que execute_repl_line redirige a su
    // buffer) y solo entonces volvemos.
    try {
        std::string out = execute_shell_command(args);
        std::lock_guard<std::mutex> lk(vesta::cout_mutex);
        std::cout << out << std::endl;
    } catch (const std::exception &e) {
        std::lock_guard<std::mutex> lk(vesta::cout_mutex);
        std::cerr << "Error ejecutando shell: " << e.what() << std::endl;
    }
}

/**
 * @brief Muestra informacion detallada de un manager de VM.
 * @param args "<id>"
 */
static void command_mgrinfo(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: mgrinfo <id>\n";
        return;
    }
    size_t id;
    try {
        id = std::stoul(words[0]);
    } catch (...) {
        std::cout << "Uso: mgrinfo <id>  (ID debe ser un numero)\n";
        return;
    }
    std::string info;
    bool found =
        mgr.modify_manager(id, [&](std::unique_ptr<runtime::ManageVM> &m) {
            info = m->to_string_vm_manager_info();
        });
    if (!found) {
        std::cout << "[mgrinfo] manager " << id << " no encontrado\n";
        return;
    }
    std::cout << info << "\n";
}

/**
 * @brief Muestra estadisticas de una instancia VM y sus schedulers.
 * @param args "<mgr_id> <vm_id>"
 */
static void command_vmstat(const std::string &args) {
    auto words = split_words(args);
    if (words.size() < 2) {
        std::cout << "Uso: vmstat <mgr_id> <vm_id>\n";
        return;
    }
    size_t mgr_id, vm_id;
    try {
        mgr_id = std::stoul(words[0]);
        vm_id = std::stoul(words[1]);
    } catch (...) {
        std::cout << "Uso: vmstat <mgr_id> <vm_id>\n";
        return;
    }
    std::string result;
    bool found =
        mgr.modify_manager(mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
            runtime::VM *vm = m->get_vm(vm_id);
            if (!vm) {
                result =
                    "[vmstat] VM " + std::to_string(vm_id) + " no encontrada\n";
                return;
            }
            std::ostringstream ss;
            ss << vm->to_string() << "\n";
            ss << "Schedulers: " << vm->schedulers.size() << "\n";
            for (auto &sched : vm->schedulers) {
                ss << "  [sched " << sched->id_scheduler << "]"
                   << "  alive=" << sched->alive_count.load()
                   << "  instr_ctr=" << sched->profiler_instr_counter
                   << "  time_exec=" << sched->time_exec << "ns"
                   << (sched->is_waiting.load() ? "  [IDLE]" : "  [RUN]")
                   << "\n";
            }
            result = ss.str();
        });
    if (!found) {
        std::cout << "[vmstat] manager " << mgr_id << " no encontrado\n";
        return;
    }
    std::cout << result;
}

/**
 * @brief Vista htop interactiva de schedulers y procesos de una VM.
 *
 * Navegacion de dos niveles:
 *   SCHEDULERS -> PROCESSES -> PROC_INFO
 *
 * Teclas en vista SCHEDULERS:
 *   j / flecha abajo : bajar cursor
 *   k / flecha arriba: subir cursor
 *   Enter            : entrar en lista de procesos del scheduler seleccionado
 *   q / ESC          : salir
 *
 * Teclas en vista PROCESSES:
 *   j/k / flechas    : navegar procesos
 *   Enter / i        : ver info completa del proceso
 *   x                : matar proceso seleccionado
 *   q / ESC          : volver a SCHEDULERS
 *
 * Teclas en vista PROC_INFO:
 *   cualquier tecla  : volver a PROCESSES
 *
 * @param args "<mgr_id> <vm_id>"
 */
static void command_schedtop(const std::string &args) {
    auto words = split_words(args);
    if (words.size() < 2) {
        std::cout << "Uso: schedtop <mgr_id> <vm_id>\n";
        return;
    }
    size_t mgr_id, vm_id;
    try {
        mgr_id = std::stoul(words[0]);
        vm_id = std::stoul(words[1]);
    } catch (...) {
        std::cout << "Uso: schedtop <mgr_id> <vm_id>\n";
        return;
    }

    // obtener puntero a la VM sin mantener mutex durante el bucle de display
    runtime::VM *vm_ptr = nullptr;
    bool found =
        mgr.modify_manager(mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
            vm_ptr = m->get_vm(vm_id);
        });
    if (!found) {
        std::cout << "[schedtop] manager " << mgr_id << " no encontrado\n";
        return;
    }
    if (!vm_ptr) {
        std::cout << "[schedtop] VM " << vm_id << " no encontrada\n";
        return;
    }

    size_t n = vm_ptr->schedulers.size();
    if (n == 0) {
        std::cout << "[schedtop] VM sin schedulers\n";
        return;
    }

    // activar hooks de medicion de tiempo (noop, pero necesario para acumular
    // time_exec)
    for (auto &s : vm_ptr->schedulers)
        s->add_debug_hook(noop_debug_hook);

    // --- setup terminal raw (lectura de teclas sin bloqueo) ---
#if !defined(_WIN32)
    struct termios term_old;
    bool term_ok = (tcgetattr(STDIN_FILENO, &term_old) == 0);
    if (term_ok) {
        struct termios raw = term_old;
        raw.c_lflag &= ~(unsigned)(ICANON | ECHO);
        raw.c_cc[VMIN] = 0; // lectura no bloqueante
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }
    // leer una tecla sin bloquear; devuelve -1 si no hay entrada
    // flechas se codifican como -72 (arriba) y -80 (abajo) para unificar con
    // Windows
    auto read_key = [&]() -> int {
        unsigned char c;
        if (::read(STDIN_FILENO, &c, 1) != 1) return -1;
        if (c == 27) { // posible secuencia ESC+[+letra para flechas
            unsigned char b1, b2;
            if (::read(STDIN_FILENO, &b1, 1) == 1 && b1 == '[') {
                if (::read(STDIN_FILENO, &b2, 1) == 1) {
                    if (b2 == 'A') return -72; // flecha arriba
                    if (b2 == 'B') return -80; // flecha abajo
                }
            }
            return 27; // ESC solitario
        }
        return (int)c;
    };
#else
    // en Windows _kbhit/_getch son no bloqueantes y no requieren setup
    auto read_key = [&]() -> int {
        if (!_kbhit()) return -1;
        int c = _getch();
        if (c == 0 || c == 224) { // prefijo de tecla especial (flechas, F-keys)
            if (!_kbhit()) return -1;
            int c2 = _getch();
            if (c2 == 72) return -72; // flecha arriba
            if (c2 == 80) return -80; // flecha abajo
            return -c2; // otras teclas especiales descartadas con valor
                        // negativo
        }
        return c;
    };
#endif

    // --- estado de navegacion ---
    enum class View { SCHEDULERS, PROCESSES, PROC_INFO };
    View view = View::SCHEDULERS;
    size_t sched_cursor = 0;
    size_t proc_cursor = 0;

    struct ProcSnap {
        uint32_t sched_id;
        uint64_t local_pid;
        runtime::vm_state state;
    };
    std::vector<ProcSnap> proc_list; // procesos visibles en vista PROCESSES
    std::string proc_info;           // texto completo para vista PROC_INFO

    // estadisticas para calculo de deltas
    std::vector<uint64_t> prev_instr(n, 0), prev_time(n, 0);
    bool first_frame = true;
    int frame_tick = 0; // incrementa cada 50ms; redibuja cada 10 ticks (500ms)

    bool top_running = true;
    while (top_running) {
        // --- procesar entrada de teclado (no bloqueante) ---
        bool key_pressed = false;
        int key = read_key();
        if (key != -1) {
            key_pressed = true;
            switch (view) {
            case View::SCHEDULERS:
                if ((key == 'j' || key == -80) && sched_cursor + 1 < n)
                    ++sched_cursor;
                else if ((key == 'k' || key == -72) && sched_cursor > 0)
                    --sched_cursor;
                else if (key == '\r' || key == '\n') {
                    // entrar en la lista de procesos del scheduler seleccionado
                    view = View::PROCESSES;
                    proc_cursor = 0;
                    proc_list.clear();
                    if (sched_cursor < n) {
                        auto &s = *vm_ptr->schedulers[sched_cursor];
                        for (auto &p : s.processes)
                            if (p)
                                proc_list.push_back({p->pid.scheduler_id,
                                                     p->pid.local_pid,
                                                     p->state});
                    }
                } else if (key == 'q' || key == 27)
                    top_running = false;
                break;

            case View::PROCESSES:
                if ((key == 'j' || key == -80) &&
                    proc_cursor + 1 < proc_list.size())
                    ++proc_cursor;
                else if ((key == 'k' || key == -72) && proc_cursor > 0)
                    --proc_cursor;
                else if ((key == '\r' || key == '\n' || key == 'i') &&
                         !proc_list.empty()) {
                    // mostrar informacion detallada del proceso seleccionado
                    auto &ps = proc_list[proc_cursor];
                    GlobalPID gpid{ps.sched_id, ps.local_pid};
                    proc_info = "[proceso no encontrado]\n";
                    if (sched_cursor < n) {
                        auto &sched = *vm_ptr->schedulers[sched_cursor];
                        auto it = sched.pid_index.find(gpid);
                        if (it != sched.pid_index.end())
                            proc_info = it->second->to_string();
                    }
                    view = View::PROC_INFO;
                } else if ((key == 'x' || key == 'X') && !proc_list.empty()) {
                    // matar el proceso seleccionado
                    auto &ps = proc_list[proc_cursor];
                    GlobalPID gpid{ps.sched_id, ps.local_pid};
                    if (sched_cursor < n)
                        vm_ptr->schedulers[sched_cursor]->kill(gpid);
                    // reconstruir lista de procesos tras el kill
                    proc_list.clear();
                    if (sched_cursor < n) {
                        auto &s = *vm_ptr->schedulers[sched_cursor];
                        for (auto &p : s.processes)
                            if (p)
                                proc_list.push_back({p->pid.scheduler_id,
                                                     p->pid.local_pid,
                                                     p->state});
                    }
                    if (!proc_list.empty() && proc_cursor >= proc_list.size())
                        proc_cursor = proc_list.size() - 1;
                } else if (key == 'q' || key == 27) {
                    view = View::SCHEDULERS;
                    proc_cursor = 0;
                }
                break;

            case View::PROC_INFO:
                view = View::PROCESSES; // cualquier tecla vuelve atras
                break;
            }
        }

        // --- redibujado cada 500ms o inmediatamente tras pulsacion de tecla
        // ---
        ++frame_tick;
        if (frame_tick >= 10 || key_pressed) {
            if (frame_tick >= 10) frame_tick = 0;

            // snapshot de estadisticas de los schedulers
            std::vector<uint64_t> curr_instr(n), curr_time(n);
            std::vector<int> alive(n);
            std::vector<bool> waiting(n);
            std::vector<std::vector<ProcSnap>> procs_snap(n);

            for (size_t i = 0; i < n; ++i) {
                auto &s = *vm_ptr->schedulers[i];
                curr_instr[i] = s.profiler_instr_counter;
                curr_time[i] = s.time_exec;
                alive[i] = s.alive_count.load();
                waiting[i] = s.is_waiting.load();
                for (auto &p : s.processes)
                    if (p)
                        procs_snap[i].push_back(
                            {p->pid.scheduler_id, p->pid.local_pid, p->state});
            }

            // calcular IPS y CPU% a partir de deltas (no disponible en primer
            // frame)
            std::vector<double> ips(n, 0.0), cpu(n, 0.0);
            if (!first_frame) {
                for (size_t i = 0; i < n; ++i) {
                    uint64_t di =
                        curr_instr[i] - prev_instr[i]; // instrucciones, 1 a 1
                    uint64_t dt =
                        curr_time[i] - prev_time[i]; // ns en exec en ~500ms
                    ips[i] = (double)di * 256.0;
                    cpu[i] = std::min(100.0, (double)dt /
                                                 5e6); // dt_ns / 500ms_ns * 100
                }
            }
            prev_instr = curr_instr;
            prev_time = curr_time;
            first_frame = false;

            // refrescar lista de procesos en vista PROCESSES (para que refleje
            // cambios)
            if (view == View::PROCESSES && !key_pressed && sched_cursor < n) {
                proc_list = procs_snap[sched_cursor];
                if (!proc_list.empty() && proc_cursor >= proc_list.size())
                    proc_cursor = proc_list.size() - 1;
            }

            // construir pantalla completa en buffer antes de escribir (evita
            // parpadeo)
            std::ostringstream screen;
            screen << "\x1B[2J\x1B[H";

            if (view == View::SCHEDULERS) {
                screen << ansi::c(ansi::BOLD) << ansi::c(ansi::BR_CYAN)
                       << "=== schedtop | mgr=" << mgr_id << "  vm=" << vm_id
                       << " ===" << ansi::c(ansi::RESET) << " "
                       << ansi::c(ansi::DIM)
                       << "[j/k=nav  Enter=procesos  q=salir]"
                       << ansi::c(ansi::RESET) << "\n\n";

                screen << ansi::c(ansi::BOLD) << std::left << std::setw(6)
                       << " " << std::setw(8) << "SCHED" << std::setw(8)
                       << "ESTADO" << std::setw(8) << "VIVOS" << std::setw(16)
                       << "IPS/500ms" << std::setw(10) << "CPU%"
                       << "PROCESOS" << ansi::c(ansi::RESET) << "\n";
                screen << std::string(75, '-') << "\n";

                for (size_t i = 0; i < n; ++i) {
                    bool sel = (i == sched_cursor);
                    if (sel)
                        screen << ansi::c(ansi::BR_YELLOW) << "> ";
                    else
                        screen << "  ";

                    screen << std::left << std::setw(8) << i;
                    if (waiting[i])
                        screen << ansi::c(ansi::DIM) << std::setw(8) << "IDLE"
                               << ansi::c(ansi::RESET);
                    else
                        screen << ansi::c(ansi::BR_GREEN) << std::setw(8)
                               << "RUN" << ansi::c(ansi::RESET);

                    screen << std::setw(8) << alive[i];

                    char ips_buf[32], cpu_buf[16];
                    snprintf(ips_buf, sizeof(ips_buf), "%.0f", ips[i]);
                    snprintf(cpu_buf, sizeof(cpu_buf), "%.1f%%", cpu[i]);
                    screen << std::setw(16) << ips_buf << std::setw(10)
                           << cpu_buf;

                    for (auto &ps : procs_snap[i])
                        screen << " " << ansi::c(ansi::CYAN) << "("
                               << ps.sched_id << "," << ps.local_pid << ")"
                               << ansi::c(ansi::RESET) << "["
                               << runtime::vm_state_to_str(ps.state) << "]";
                    if (procs_snap[i].empty())
                        screen << ansi::c(ansi::DIM) << " (ninguno)"
                               << ansi::c(ansi::RESET);
                    if (sel) screen << ansi::c(ansi::RESET);
                    screen << "\n";
                }

            } else if (view == View::PROCESSES) {
                screen << ansi::c(ansi::BOLD) << ansi::c(ansi::BR_CYAN)
                       << "=== schedtop | sched=" << sched_cursor
                       << " ===" << ansi::c(ansi::RESET) << " "
                       << ansi::c(ansi::DIM)
                       << "[j/k=nav  Enter/i=info  x=matar  q=volver]"
                       << ansi::c(ansi::RESET) << "\n\n";

                if (proc_list.empty()) {
                    screen << ansi::c(ansi::DIM) << "(sin procesos)"
                           << ansi::c(ansi::RESET) << "\n";
                } else {
                    screen << ansi::c(ansi::BOLD) << std::left << std::setw(6)
                           << " " << std::setw(14) << "PID (sched,loc)"
                           << "ESTADO" << ansi::c(ansi::RESET) << "\n";
                    screen << std::string(40, '-') << "\n";
                    for (size_t i = 0; i < proc_list.size(); ++i) {
                        auto &ps = proc_list[i];
                        bool sel = (i == proc_cursor);
                        if (sel)
                            screen << ansi::c(ansi::BR_YELLOW) << "> ";
                        else
                            screen << "  ";

                        char pid_buf[32];
                        snprintf(pid_buf, sizeof(pid_buf), "(%u,%llu)",
                                 ps.sched_id, (unsigned long long)ps.local_pid);
                        screen << std::left << std::setw(14) << pid_buf
                               << runtime::vm_state_to_str(ps.state);
                        if (sel) screen << ansi::c(ansi::RESET);
                        screen << "\n";
                    }
                }

            } else { // PROC_INFO
                screen << ansi::c(ansi::BOLD) << ansi::c(ansi::BR_CYAN)
                       << "=== schedtop | info de proceso ==="
                       << ansi::c(ansi::RESET) << " " << ansi::c(ansi::DIM)
                       << "[cualquier tecla = volver]" << ansi::c(ansi::RESET)
                       << "\n\n";
                screen << proc_info << "\n";
            }

            screen << "\n"
                   << ansi::c(ansi::DIM) << "Actualizacion: 500ms"
                   << ansi::c(ansi::RESET) << "\n";

            {
                std::lock_guard<std::mutex> lk(vesta::cout_mutex);
                std::cout << screen.str() << std::flush;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // restaurar terminal en POSIX
#if !defined(_WIN32)
    if (term_ok) tcsetattr(STDIN_FILENO, TCSANOW, &term_old);
#endif

    // desactivar hooks al salir para no penalizar el rendimiento
    for (auto &s : vm_ptr->schedulers) {
        s->has_hooks = false;   // desactiva la invocacion de los hooks
        s->debug_hooks.clear(); // libera el vector (miembro publico)
    }

    std::cout << "\x1B[2J\x1B[H" << std::flush;
    std::cout << ansi::c(ansi::BR_CYAN) << "[schedtop]" << ansi::c(ansi::RESET)
              << " saliendo\n";
}

/**
 * @brief Muestra el estado completo de un proceso virtual especifico.
 * @param args "<mgr_id> <vm_id> <sched_id> <pid>"
 */
static void command_procinfo(const std::string &args) {
    auto words = split_words(args);
    if (words.size() < 4) {
        std::cout << "Uso: procinfo <mgr_id> <vm_id> <sched_id> <pid>\n";
        return;
    }
    size_t mgr_id, vm_id, sched_id;
    uint64_t local_pid;
    try {
        mgr_id = std::stoul(words[0]);
        vm_id = std::stoul(words[1]);
        sched_id = std::stoul(words[2]);
        local_pid = std::stoull(words[3]);
    } catch (...) {
        std::cout << "Uso: procinfo <mgr_id> <vm_id> <sched_id> <pid>  (todos "
                     "numericos)\n";
        return;
    }
    std::string result;
    bool found =
        mgr.modify_manager(mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
            runtime::VM *vm = m->get_vm(vm_id);
            if (!vm) {
                result = "[procinfo] VM " + std::to_string(vm_id) +
                         " no encontrada\n";
                return;
            }
            if (sched_id >= vm->schedulers.size()) {
                result = "[procinfo] scheduler " + std::to_string(sched_id) +
                         " no existe\n";
                return;
            }
            auto &sched = *vm->schedulers[sched_id];
            GlobalPID gpid{(uint32_t)sched_id, local_pid};
            auto it = sched.pid_index.find(gpid);
            if (it == sched.pid_index.end()) {
                result = "[procinfo] proceso (" + std::to_string(sched_id) +
                         "," + std::to_string(local_pid) + ") no encontrado\n";
                return;
            }
            result = it->second->to_string();
        });
    if (!found) {
        std::cout << "[procinfo] manager " << mgr_id << " no encontrado\n";
        return;
    }
    std::cout << result;
}

// ---- comando dist: gestion del runtime distribuido ----

/**
 * @brief Calcula SHA-256 de un token en texto plano y rellena NodeAuthConfig.
 *
 * @param token    Token en texto plano.
 * @param use_tls  true para activar TLS.
 * @param cert     Ruta al certificado PEM.
 * @param key      Ruta a la clave privada PEM.
 * @param ca       Ruta al CA bundle PEM.
 * @return NodeAuthConfig relleno.
 */
static distrib::NodeAuthConfig
dist_build_auth(const std::string &token, bool use_tls, const std::string &cert,
                const std::string &key, const std::string &ca) {
    distrib::NodeAuthConfig auth{};
    if (!token.empty()) {
        auth.use_token = true;
        SHA256(reinterpret_cast<const unsigned char *>(token.c_str()),
               token.size(), auth.token_hash);
    }
    if (use_tls) {
        auth.use_tls = true;
        std::snprintf(auth.cert_path, sizeof(auth.cert_path), "%s",
                      cert.c_str());
        std::snprintf(auth.key_path, sizeof(auth.key_path), "%s", key.c_str());
        std::snprintf(auth.ca_path, sizeof(auth.ca_path), "%s", ca.c_str());
    }
    return auth;
}

/**
 * @brief Convierte NodeState a cadena legible en espanol.
 * @param s Estado del nodo.
 * @return Cadena con el nombre del estado.
 */
static const char *dist_node_state_str(distrib::NodeState s) {
    switch (s) {
    case distrib::NodeState::UNKNOWN: return "DESCONOCIDO";
    case distrib::NodeState::CONNECTING: return "CONECTANDO";
    case distrib::NodeState::AUTHENTICATED: return "ACTIVO";
    case distrib::NodeState::DISCONNECTED: return "DESCONECTADO";
    case distrib::NodeState::BANNED: return "BANEADO";
    }
    return "?";
}

/**
 * @brief Imprime la ayuda completa del subcomando dist.
 */
static void dist_print_help() {
    auto H = [](const char *s) {
        vesta::scout() << ansi::c(ansi::BOLD) << ansi::c(ansi::BR_CYAN) << s
                       << ansi::c(ansi::RESET) << "\n";
    };
    auto C = [](const char *usage, const char *desc) {
        vesta::scout() << "  " << ansi::c(ansi::BR_YELLOW) << std::left
                       << std::setw(52) << usage << ansi::c(ansi::RESET) << " "
                       << desc << "\n";
    };
    H("Comandos distribuidos (dist <subcomando> ...):");
    C("dist new  [--port P] [--discover] [--discover-port P]",
      "Crear y arrancar un nodo servidor distribuido persistente");
    C("          [--name NOMBRE] [--node-id ID] [--schedulers N]",
      "  Imprime el mgr_id asignado para usar con otros subcomandos");
    C("          [--token T] [--tls] [--cert C] [--key K] [--ca CA]", "");
    C("dist start  <id> [--port P] [--discover] [--discover-port P]",
      "Iniciar DistRuntime en la VM del manager indicado");
    C("            [--name NOMBRE] [--node-id ID] [--vm-id N]",
      "  (vm-id por defecto = 1)");
    C("dist stop   <id> [--vm-id N]",
      "Detener DistRuntime (cierra sesiones y servidor VDP)");
    C("dist info   <id> [--vm-id N]",
      "Mostrar estado del DistRuntime (node-id, puerto, nodos)");
    C("dist list   <id> [--vm-id N]",
      "Listar todos los nodos del registro con su estado");
    C("dist add-node <id> <ip> <puerto> [--name N] [--vm-id N]",
      "Registrar y conectar a un nodo estatico");
    C("             [--token TOKEN] [--tls] [--cert C] [--key K] [--ca CA]",
      "");
    C("dist connect  <id> <node_idx> [--vm-id N]",
      "Conectar a un nodo ya registrado (por indice)");
    C("dist discover <id> [--vm-id N]",
      "Emitir broadcast UDP de descubrimiento de nodos");
    C("dist run <id> <node_idx> <archivo.velb> [--wait] [--timeout MS]",
      "Cargar .velb y enviarlo a ejecutar en el nodo remoto indicado");
    C("         [--vm-id N]",
      "  --wait bloquea hasta recibir el resultado (r0 del proceso remoto)");
    vesta::scout()
        << "\n"
        << ansi::c(ansi::DIM)
        << "Nota: <id> es el mgr_id que muestra 'vms'. "
           "--dist-server en linea de comandos lanza un nodo servidor puro.\n"
        << ansi::c(ansi::RESET);
}

/**
 * @brief Gestiona el runtime distribuido desde el REPL.
 *
 * Subcomandos: new, start, stop, info, list, add-node, connect, discover, run.
 *
 * Formato general: dist <subcomando> <mgr_id> [--vm-id N] [opciones]
 *
 * @param args Cadena de argumentos que sigue al nombre del comando "dist".
 */
static void command_dist(const std::string &args) {
    auto words = split_words(args);

    // sin argumentos o peticion de ayuda
    if (words.empty() || words[0] == "help" || words[0] == "--help") {
        dist_print_help();
        return;
    }

    std::string subcmd = words[0];

    // verificar que se proporciona mgr_id
    if (words.size() < 2) {
        vesta::scout() << "[dist] Se requiere mgr_id: dist " << subcmd
                       << " <mgr_id> ...\n"
                       << "  Usa 'dist help' para ver todos los subcomandos.\n";
        return;
    }

    // opciones de autenticacion y vm-id (comunes a todos los subcomandos con
    // mgr_id)
    uint64_t vm_id = 1; // create_vm() usa ++counter_vm: primer VM = id 1
    std::string token_str;
    bool use_tls = false;
    std::string cert_str, key_str, ca_str;

    // ---- dist new ----
    // No requiere mgr_id: crea uno nuevo.
    // dist new [--port P] [--discover] [--discover-port P] [--name N]
    //          [--node-id ID] [--schedulers N] [--token T] [--tls] [--cert C]
    //          ...
    if (subcmd == "new") {
        uint16_t port = 0;
        uint16_t disc_port = 7790;
        bool discover = false;
        std::string name = "dist-node";
        uint64_t node_id_v = 0;
        size_t num_scheds = 1;

        for (size_t i = 1; i < words.size(); ++i) {
            if (words[i] == "--port" && i + 1 < words.size()) {
                try {
                    port = (uint16_t)std::stoul(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--discover") discover = true;
            if (words[i] == "--discover-port" && i + 1 < words.size()) {
                try {
                    disc_port = (uint16_t)std::stoul(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--name" && i + 1 < words.size()) name = words[++i];
            if (words[i] == "--node-id" && i + 1 < words.size()) {
                try {
                    node_id_v = std::stoull(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--schedulers" && i + 1 < words.size()) {
                try {
                    num_scheds = std::stoul(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--token" && i + 1 < words.size())
                token_str = words[++i];
            if (words[i] == "--tls") use_tls = true;
            if (words[i] == "--cert" && i + 1 < words.size())
                cert_str = words[++i];
            if (words[i] == "--key" && i + 1 < words.size())
                key_str = words[++i];
            if (words[i] == "--ca" && i + 1 < words.size()) ca_str = words[++i];
        }

        // registrar un manager persistente (no se auto-elimina)
        runtime::ManageVM *new_mgr = mgr.add_manager(name, nullptr);
        size_t new_id = new_mgr->id;

        runtime::VM *vm = new_mgr->loader.create_vm_instance(num_scheds);
        if (!vm) {
            mgr.remove_manager(new_id);
            vesta::scout() << "[dist] Error al crear la instancia VM\n";
            return;
        }

        distrib::DistRuntimeConfig cfg{};
        cfg.local_node_id = node_id_v;
        cfg.vdp_listen_port = port;
        cfg.discover_port = disc_port;
        cfg.enable_discovery = discover;
        std::snprintf(cfg.local_node_name, sizeof(cfg.local_node_name), "%s",
                      name.c_str());
        cfg.server_auth =
            dist_build_auth(token_str, use_tls, cert_str, key_str, ca_str);

        vm->dist_runtime = std::make_unique<distrib::DistRuntime>(*vm, cfg);
        bool ok = vm->dist_runtime->start();

        // arrancar schedulers en modo persistente para ejecutar procesos
        // remotos (rspawn)
        vm->vm_persistent = true;
        vm->start();

        std::ostringstream oss;
        oss << "[dist] Nodo creado (mgr_id=" << new_id << " vm_id=" << vm->id
            << ")";
        if (ok) {
            if (port) oss << " puerto=" << port;
            if (discover) oss << " + descubrimiento UDP (:" << disc_port << ")";
        } else {
            oss << " [ADVERTENCIA: start() fallo; solo IPC local]";
        }
        vesta::scout() << oss.str() << "\n"
                       << "  dist info " << new_id << "           -> estado\n"
                       << "  dist add-node " << new_id
                       << " <ip> <p>  -> conectar nodo\n"
                       << "  dist stop " << new_id
                       << "           -> detener servidor VDP\n"
                       << "  kill " << new_id << "           -> eliminar\n";
        return;
    }

    // ---- subcomandos que requieren mgr_id ----
    if (words.size() < 2) {
        vesta::scout() << "[dist] Se requiere mgr_id: dist " << subcmd
                       << " <mgr_id> ...\n"
                       << "  Usa 'dist help' para ver todos los subcomandos.\n";
        return;
    }

    // parsear mgr_id
    size_t mgr_id = 0;
    try {
        mgr_id = std::stoul(words[1]);
    } catch (...) {
        vesta::scout() << "[dist] mgr_id debe ser un numero entero\n";
        return;
    }

    for (size_t i = 2; i < words.size(); ++i) {
        if (words[i] == "--vm-id" && i + 1 < words.size()) {
            try {
                vm_id = std::stoull(words[++i]);
            } catch (...) {
            }
        }
        if (words[i] == "--token" && i + 1 < words.size())
            token_str = words[++i];
        if (words[i] == "--tls") use_tls = true;
        if (words[i] == "--cert" && i + 1 < words.size()) cert_str = words[++i];
        if (words[i] == "--key" && i + 1 < words.size()) key_str = words[++i];
        if (words[i] == "--ca" && i + 1 < words.size()) ca_str = words[++i];
    }

    // ---- dist start ----
    // dist start <mgr_id> [--vm-id N] [--port P] [--discover] [--discover-port
    // P]
    //            [--name NOMBRE] [--node-id ID] [--token T] [--tls] [--cert C]
    //            ...
    if (subcmd == "start") {
        uint16_t port = 0;
        uint16_t disc_port = 7790;
        bool discover = false;
        std::string name;
        uint64_t node_id = 0;

        for (size_t i = 2; i < words.size(); ++i) {
            if (words[i] == "--port" && i + 1 < words.size()) {
                try {
                    port = (uint16_t)std::stoul(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--discover") discover = true;
            if (words[i] == "--discover-port" && i + 1 < words.size()) {
                try {
                    disc_port = (uint16_t)std::stoul(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--name" && i + 1 < words.size()) name = words[++i];
            if (words[i] == "--node-id" && i + 1 < words.size()) {
                try {
                    node_id = std::stoull(words[++i]);
                } catch (...) {
                }
            }
        }

        bool ok = false;
        std::string msg;
        bool found = mgr.modify_manager(
            mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
                runtime::VM *vm = m->get_vm(vm_id);
                if (!vm) {
                    msg = "VM " + std::to_string(vm_id) +
                          " no encontrada en mgr " + std::to_string(mgr_id);
                    return;
                }

                distrib::DistRuntimeConfig cfg{};
                cfg.local_node_id = node_id;
                cfg.vdp_listen_port = port;
                cfg.discover_port = disc_port;
                cfg.enable_discovery = discover;
                if (!name.empty())
                    std::snprintf(cfg.local_node_name,
                                  sizeof(cfg.local_node_name), "%s",
                                  name.c_str());
                cfg.server_auth = dist_build_auth(token_str, use_tls, cert_str,
                                                  key_str, ca_str);

                // reemplazar el dist_runtime minimal por uno completamente
                // configurado
                vm->dist_runtime =
                    std::make_unique<distrib::DistRuntime>(*vm, cfg);
                ok = vm->dist_runtime->start();

                if (ok) {
                    msg = "DistRuntime iniciado";
                    if (port) msg += " en puerto " + std::to_string(port);
                    if (discover)
                        msg += " + descubrimiento UDP (:" +
                               std::to_string(disc_port) + ")";
                } else {
                    msg = "Error al iniciar DistRuntime (verificar puerto o "
                          "certificados)";
                }
            });
        if (!found)
            vesta::scout() << "[dist] Manager " << mgr_id << " no encontrado\n";
        else
            vesta::scout() << "[dist] " << msg << "\n";
        return;
    }

    // ---- dist stop ----
    if (subcmd == "stop") {
        bool found = mgr.modify_manager(
            mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
                runtime::VM *vm = m->get_vm(vm_id);
                if (!vm || !vm->dist_runtime) {
                    vesta::scout()
                        << "[dist] dist_runtime no disponible en mgr=" << mgr_id
                        << " vm=" << vm_id << "\n";
                    return;
                }
                vm->dist_runtime->stop();
                vesta::scout() << "[dist] DistRuntime detenido (mgr=" << mgr_id
                               << " vm=" << vm_id << ")\n";
            });
        if (!found)
            vesta::scout() << "[dist] Manager " << mgr_id << " no encontrado\n";
        return;
    }

    // ---- dist info ----
    if (subcmd == "info") {
        bool found = mgr.modify_manager(
            mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
                runtime::VM *vm = m->get_vm(vm_id);
                if (!vm || !vm->dist_runtime) {
                    vesta::scout() << "[dist] dist_runtime no disponible\n";
                    return;
                }
                auto *dr = vm->dist_runtime.get();
                auto &reg = dr->registry();

                std::ostringstream ss;
                ss << ansi::c(ansi::BOLD) << ansi::c(ansi::BR_CYAN)
                   << "=== DistRuntime | mgr=" << mgr_id << "  vm=" << vm_id
                   << " ===" << ansi::c(ansi::RESET) << "\n"
                   << "  Node ID local : 0x" << std::hex << std::setw(16)
                   << std::setfill('0') << dr->local_node_id() << std::dec
                   << std::setfill(' ') << "\n"
                   << "  Nodos en registro : " << reg.count() << "\n";

                // mostrar resumen de nodos activos
                size_t n = reg.count();
                for (uint32_t i = 0; i < (uint32_t)n; ++i) {
                    auto *ni = reg.get(i);
                    if (!ni) continue;
                    const char *col =
                        (ni->state == distrib::NodeState::AUTHENTICATED)
                            ? ansi::c(ansi::BR_GREEN)
                            : ansi::c(ansi::DIM);
                    ss << "    [" << i << "] " << col << ni->ip << ":"
                       << ni->port << "  " << dist_node_state_str(ni->state)
                       << ansi::c(ansi::RESET)
                       << (ni->name[0] ? std::string("  (") + ni->name + ")"
                                       : "")
                       << "\n";
                }
                vesta::scout() << ss.str();
            });
        if (!found)
            vesta::scout() << "[dist] Manager " << mgr_id << " no encontrado\n";
        return;
    }

    // ---- dist list / dist nodes ----
    if (subcmd == "list" || subcmd == "nodes") {
        bool found = mgr.modify_manager(
            mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
                runtime::VM *vm = m->get_vm(vm_id);
                if (!vm || !vm->dist_runtime) {
                    vesta::scout() << "[dist] dist_runtime no disponible\n";
                    return;
                }
                auto &reg = vm->dist_runtime->registry();
                size_t n = reg.count();
                if (n == 0) {
                    vesta::scout() << "[dist] Sin nodos registrados\n";
                    return;
                }

                std::ostringstream ss;
                ss << ansi::c(ansi::BOLD) << std::left << std::setw(5) << "IDX"
                   << std::setw(22) << "IP:PUERTO" << std::setw(18) << "NOMBRE"
                   << std::setw(15) << "ESTADO"
                   << "TIPO" << ansi::c(ansi::RESET) << "\n"
                   << std::string(70, '-') << "\n";

                for (uint32_t i = 0; i < (uint32_t)n; ++i) {
                    auto *ni = reg.get(i);
                    if (!ni) continue;
                    const char *col =
                        (ni->state == distrib::NodeState::AUTHENTICATED)
                            ? ansi::c(ansi::BR_GREEN)
                            : ansi::c(ansi::DIM);
                    std::string addr =
                        std::string(ni->ip) + ":" + std::to_string(ni->port);
                    ss << col << std::left << std::setw(5) << ni->idx
                       << std::setw(22) << addr << std::setw(18) << ni->name
                       << std::setw(15) << dist_node_state_str(ni->state)
                       << (ni->is_static ? "estatico" : "dinamico")
                       << ansi::c(ansi::RESET) << "\n";
                }
                vesta::scout() << ss.str();
            });
        if (!found)
            vesta::scout() << "[dist] Manager " << mgr_id << " no encontrado\n";
        return;
    }

    // ---- dist add-node ----
    // dist add-node <mgr_id> <ip> <puerto> [--vm-id N] [--name N]
    //               [--token T] [--tls] [--cert C] [--key K] [--ca CA]
    if (subcmd == "add-node") {
        if (words.size() < 4) {
            vesta::scout() << "Uso: dist add-node <mgr_id> <ip> <puerto> "
                              "[--vm-id N] [--name NOMBRE] [--token TOKEN] "
                              "[--tls] [--cert C] [--key K] [--ca CA]\n";
            return;
        }
        std::string node_ip = words[2];
        uint16_t node_port = 0;
        std::string node_name;
        try {
            node_port = (uint16_t)std::stoul(words[3]);
        } catch (...) {
            vesta::scout() << "[dist] Puerto invalido: " << words[3] << "\n";
            return;
        }
        for (size_t i = 4; i < words.size(); ++i)
            if (words[i] == "--name" && i + 1 < words.size())
                node_name = words[++i];

        distrib::NodeAuthConfig auth =
            dist_build_auth(token_str, use_tls, cert_str, key_str, ca_str);

        std::string msg;
        bool found = mgr.modify_manager(
            mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
                runtime::VM *vm = m->get_vm(vm_id);
                if (!vm || !vm->dist_runtime) {
                    msg = "dist_runtime no disponible";
                    return;
                }
                uint32_t idx = vm->dist_runtime->add_node(
                    node_ip.c_str(), node_port, auth,
                    node_name.empty() ? node_ip.c_str() : node_name.c_str());
                msg = "Nodo registrado: " + node_ip + ":" +
                      std::to_string(node_port) +
                      "  (idx=" + std::to_string(idx) + ")";
            });
        if (!found)
            vesta::scout() << "[dist] Manager " << mgr_id << " no encontrado\n";
        else
            vesta::scout() << "[dist] " << msg << "\n";
        return;
    }

    // ---- dist connect ----
    // dist connect <mgr_id> <node_idx> [--vm-id N]
    if (subcmd == "connect") {
        if (words.size() < 3) {
            vesta::scout()
                << "Uso: dist connect <mgr_id> <node_idx> [--vm-id N]\n";
            return;
        }
        uint32_t node_idx = 0;
        try {
            node_idx = (uint32_t)std::stoul(words[2]);
        } catch (...) {
            vesta::scout() << "[dist] node_idx invalido: " << words[2] << "\n";
            return;
        }

        bool ok = false;
        std::string msg;
        bool found = mgr.modify_manager(
            mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
                runtime::VM *vm = m->get_vm(vm_id);
                if (!vm || !vm->dist_runtime) {
                    msg = "dist_runtime no disponible";
                    return;
                }
                ok = vm->dist_runtime->connect_node(node_idx);
                msg = ok ? "Conectado a nodo idx=" + std::to_string(node_idx)
                         : "Fallo al conectar con nodo idx=" +
                               std::to_string(node_idx);
            });
        if (!found)
            vesta::scout() << "[dist] Manager " << mgr_id << " no encontrado\n";
        else
            vesta::scout() << "[dist] " << msg << "\n";
        return;
    }

    // ---- dist discover ----
    if (subcmd == "discover") {
        bool found = mgr.modify_manager(
            mgr_id, [&](std::unique_ptr<runtime::ManageVM> &m) {
                runtime::VM *vm = m->get_vm(vm_id);
                if (!vm || !vm->dist_runtime) {
                    vesta::scout() << "[dist] dist_runtime no disponible\n";
                    return;
                }
                // activar el hilo de descubrimiento si aun no esta corriendo;
                // start_discovery() es idempotente (exchange atomico lo
                // protege)
                uint16_t dport = vm->dist_runtime->config().discover_port;
                if (!dport) dport = distrib::VDP_DISCOVER_PORT;
                vm->dist_runtime->registry().start_discovery(dport);
                // emitir un broadcast inmediato sin esperar los 30 segundos del
                // ciclo
                vm->dist_runtime->registry().broadcast_discover();
                vesta::scout()
                    << "[dist] Descubrimiento UDP activo (puerto " << dport
                    << "). Escuchando respuestas NODE_ANNOUNCE...\n";
            });
        if (!found)
            vesta::scout() << "[dist] Manager " << mgr_id << " no encontrado\n";
        return;
    }

    // ---- dist new ----
    // Crea un manager con una VM y arranca DistRuntime en ella.
    // El manager se registra en el mgr global y persiste hasta que el usuario
    // llame a "dist stop <id>" seguido de "kill <id>".
    // Formato: dist new [--port P] [--discover] [--discover-port P]
    //                   [--name NOMBRE] [--node-id ID]
    //                   [--token T] [--tls] [--cert C] [--key K] [--ca CA]
    //                   [--schedulers N]
    if (subcmd == "new") {
        uint16_t port = 0;
        uint16_t disc_port = 7790;
        bool discover = false;
        std::string name = "dist-node";
        uint64_t node_id_v = 0;
        size_t num_scheds = 1;

        for (size_t i = 1; i < words.size(); ++i) {
            if (words[i] == "--port" && i + 1 < words.size()) {
                try {
                    port = (uint16_t)std::stoul(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--discover") discover = true;
            if (words[i] == "--discover-port" && i + 1 < words.size()) {
                try {
                    disc_port = (uint16_t)std::stoul(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--name" && i + 1 < words.size()) name = words[++i];
            if (words[i] == "--node-id" && i + 1 < words.size()) {
                try {
                    node_id_v = std::stoull(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--schedulers" && i + 1 < words.size()) {
                try {
                    num_scheds = std::stoul(words[++i]);
                } catch (...) {
                }
            }
            if (words[i] == "--token" && i + 1 < words.size())
                token_str = words[++i];
            if (words[i] == "--tls") use_tls = true;
            if (words[i] == "--cert" && i + 1 < words.size())
                cert_str = words[++i];
            if (words[i] == "--key" && i + 1 < words.size())
                key_str = words[++i];
            if (words[i] == "--ca" && i + 1 < words.size()) ca_str = words[++i];
        }

        // crear un nuevo manager persistente
        runtime::ManageVM *new_mgr = mgr.add_manager(name, nullptr);
        size_t new_id = new_mgr->id;

        // crear la VM y arrancar DistRuntime en el hilo actual
        runtime::VM *vm = new_mgr->loader.create_vm_instance(num_scheds);
        if (!vm) {
            mgr.remove_manager(new_id);
            vesta::scout() << "[dist] Error al crear la instancia VM\n";
            return;
        }

        distrib::DistRuntimeConfig cfg{};
        cfg.local_node_id = node_id_v;
        cfg.vdp_listen_port = port;
        cfg.discover_port = disc_port;
        cfg.enable_discovery = discover;
        std::snprintf(cfg.local_node_name, sizeof(cfg.local_node_name), "%s",
                      name.c_str());
        cfg.server_auth =
            dist_build_auth(token_str, use_tls, cert_str, key_str, ca_str);

        vm->dist_runtime = std::make_unique<distrib::DistRuntime>(*vm, cfg);
        bool ok = vm->dist_runtime->start();

        // arrancar schedulers en modo persistente para ejecutar procesos
        // remotos (rspawn)
        vm->vm_persistent = true;
        vm->start();

        std::ostringstream oss;
        oss << "[dist] Nodo creado (mgr_id=" << new_id << " vm_id=" << vm->id
            << ")";
        if (ok) {
            if (port) oss << " puerto=" << port;
            if (discover) oss << " descubrimiento UDP (:" << disc_port << ")";
        } else {
            oss << " [ADVERTENCIA: start() fallo, solo IPC local disponible]";
        }
        vesta::scout() << oss.str() << "\n"
                       << "  Usa 'dist info " << new_id
                       << "' para ver el estado.\n"
                       << "  Usa 'dist add-node " << new_id
                       << " <ip> <puerto>' para conectar nodos.\n"
                       << "  Usa 'kill " << new_id << "' para eliminarlo.\n";
        return;
    }

    // ---- dist run ----
    // dist run <mgr_id> <node_idx> <archivo.velb> [--vm-id N]
    // Carga el .velb en la VM local, obtiene la direccion de entrada y envia el
    // bytecode al nodo remoto indicado por node_idx mediante rspawn
    // (VDP_RSPAWN). Devuelve el GcHandle del FutureObject (0xFFFFFFFF si
    // error).
    if (subcmd == "run") {
        if (words.size() < 4) {
            vesta::scout()
                << "[dist run] Uso: dist run <mgr_id> <node_idx> <archivo.velb>"
                   " [--wait] [--timeout MS] [--vm-id N]\n";
            return;
        }

        // parsear node_idx, ruta del .velb y opciones adicionales
        uint32_t node_idx = 0;
        std::string velb_arg = words[3];
        bool wait_mode = false;
        uint64_t timeout_ms = 10000; // 10 s por defecto

        try {
            node_idx = (uint32_t)std::stoul(words[2]);
        } catch (...) {
            vesta::scout() << "[dist run] node_idx debe ser un numero entero\n";
            return;
        }
        for (size_t i = 4; i < words.size(); ++i) {
            if (words[i] == "--wait") wait_mode = true;
            if (words[i] == "--timeout" && i + 1 < words.size()) {
                try {
                    timeout_ms = std::stoull(words[++i]);
                } catch (...) {
                }
            }
        }

        // resolver ruta absoluta del archivo
        auto velb_path = std::filesystem::weakly_canonical(
            std::filesystem::current_path() / velb_arg);
        if (!std::filesystem::exists(velb_path) ||
            !std::filesystem::is_regular_file(velb_path)) {
            vesta::scout() << "[dist run] Archivo no encontrado: "
                           << velb_path.string() << "\n";
            return;
        }
        std::string abs_path = velb_path.string();

        // estas variables se rellenan dentro del lambda para usarlas en el wait
        // externo
        std::string run_result;
        runtime::ProcessVM *wait_proc = nullptr;
        uint32_t wait_handle = 0xFFFFFFFFu;
        // variables para limpiar el proceso temporal de carga tras recibir el
        // ACK
        runtime::VM *cleanup_vm = nullptr;
        runtime::ProcessVM *cleanup_proc = nullptr;
        GlobalPID cleanup_pid = {};
        uint32_t cleanup_gc = 0xFFFFFFFFu;

        bool found = mgr.modify_manager(mgr_id, [&](std::unique_ptr<
                                                    runtime::ManageVM> &m) {
            runtime::VM *vm = m->get_vm(vm_id);
            if (!vm) {
                run_result = "[dist run] VM " + std::to_string(vm_id) +
                             " no encontrada en manager " +
                             std::to_string(mgr_id) + "\n";
                return;
            }
            if (!vm->dist_runtime) {
                run_result =
                    "[dist run] dist_runtime no disponible en esta VM\n";
                return;
            }

            // verificar estado del nodo antes de cargar el .velb
            auto &reg = vm->dist_runtime->registry();
            auto *ni = reg.get(node_idx);
            if (!ni) {
                run_result = "[dist run] Nodo " + std::to_string(node_idx) +
                             " no existe en el registro\n" +
                             "  Usa 'dist add-node " + std::to_string(mgr_id) +
                             " <ip> <puerto>' para registrarlo.\n";
                return;
            }
            if (ni->state != distrib::NodeState::AUTHENTICATED) {
                run_result = "[dist run] Nodo " + std::to_string(node_idx) +
                             " no esta activo (estado: " +
                             dist_node_state_str(ni->state) + ")\n" +
                             "  Usa 'dist connect " + std::to_string(mgr_id) +
                             " " + std::to_string(node_idx) +
                             "' para reconectar.\n";
                return;
            }

            // leer el fichero .velb en bruto para enviarlo al nodo remoto
            // (no usar load_executable aqui: resolveria importaciones con
            //  las bibliotecas locales del cliente, invalidas en el servidor)
            std::vector<uint8_t> velb_bytes;
            {
                std::ifstream vf(abs_path, std::ios::binary | std::ios::ate);
                if (!vf.is_open()) {
                    run_result =
                        "[dist run] No se puede abrir: " + abs_path + "\n";
                    return;
                }
                auto fsz = vf.tellg();
                if (fsz <= 0) {
                    run_result =
                        "[dist run] Fichero vacio o error de lectura: " +
                        abs_path + "\n";
                    return;
                }
                velb_bytes.resize(static_cast<size_t>(fsz));
                vf.seekg(0);
                vf.read(reinterpret_cast<char *>(velb_bytes.data()), fsz);
            }

            // crear un proceso temporal solo para que su gc_heap albergue el
            // FutureObject
            runtime::ProcessVM *proc = nullptr;
            try {
                proc = m->loader.load_executable(*vm, abs_path);
            } catch (const std::exception &e) {
                run_result =
                    std::string("[dist run] Error creando proceso temporal: ") +
                    e.what() + "\n";
                return;
            }
            if (!proc) {
                run_result = "[dist run] load_executable devolvio nullptr\n";
                return;
            }

            // enviar el .velb completo al nodo remoto via rspawn_velb
            // (VDP_RSPAWN con RSPAWN_FLAG_VELB)
            uint32_t gc_handle =
                vm->dist_runtime->rspawn_velb(proc, velb_bytes, node_idx);

            if (gc_handle == 0xFFFFFFFFu) {
                run_result =
                    "[dist run] Error: rspawn fallo al enviar a nodo[" +
                    std::to_string(node_idx) +
                    "]\n"
                    "  La sesion puede haberse cerrado; usa 'dist connect " +
                    std::to_string(mgr_id) + " " + std::to_string(node_idx) +
                    "' para reconectar.\n";
                // proc fue creado por load_executable pero rspawn fallo;
                // eliminar ahora
                vm->schedulers[proc->pid.scheduler_id]->kill(proc->pid);
                return;
            }

            // guardar info de limpieza: el proceso local solo sirvio para leer
            // el bytecode
            cleanup_vm = vm;
            cleanup_proc = proc;
            cleanup_pid = proc->pid;
            cleanup_gc = gc_handle;

            std::ostringstream oss;
            oss << "[dist run] Bytecode enviado a nodo[" << node_idx
                << "] desde " << velb_arg << "\n"
                << "  FutureObject GcHandle = 0x" << std::hex << gc_handle
                << std::dec << "\n";
            if (wait_mode) {
                oss << "  Esperando resultado (timeout " << timeout_ms
                    << " ms)...\n";
                wait_proc = proc;
                wait_handle = gc_handle;
            } else {
                oss << "  Usa '--wait' para bloquear hasta recibir el "
                       "resultado del nodo.\n";
            }
            run_result = oss.str();
        });

        if (!found) {
            vesta::scout() << "[dist run] Manager " << mgr_id
                           << " no encontrado\n";
            return;
        }
        vesta::scout() << run_result;
        if (run_result.empty() || run_result[0] == '\0') return;

        // ---- espera fuera del lambda (no bloquea el mutex del manager) ----
        if (wait_mode && wait_proc && wait_handle != 0xFFFFFFFFu) {
            auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(timeout_ms);
            loader::FutureState final_state = loader::FutureState::PENDING;
            uint64_t final_result = 0;

            while (std::chrono::steady_clock::now() < deadline) {
                // leer el FutureObject directamente del GC del proceso
                uint8_t *ptr = wait_proc->gc_heap.deref(
                    static_cast<gc::GcHandle>(wait_handle));
                if (ptr) {
                    auto *fut = reinterpret_cast<loader::FutureObject *>(ptr);
                    if (fut->state != loader::FutureState::PENDING) {
                        final_state = fut->state;
                        final_result = fut->result;
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            std::ostringstream oss;
            if (final_state == loader::FutureState::RESOLVED) {
                oss << "[dist run] Resultado: " << final_result << " (0x"
                    << std::hex << final_result << std::dec << ")\n";
            } else if (final_state == loader::FutureState::REJECTED) {
                oss << "[dist run] Nodo rechazo la ejecucion (error=0x"
                    << std::hex << final_result << std::dec << ")\n";
            } else {
                oss << "[dist run] Timeout: el nodo no respondio en "
                    << timeout_ms << " ms\n";
            }
            vesta::scout() << oss.str();
        }

        // Eliminar el proceso temporal que load_executable creo en el scheduler
        // local. Solo existia para mapear el bytecode; no debe ejecutarse aqui.
        // Se elimina en un hilo auxiliar para esperar a que resolve_future_()
        // haya terminado de acceder al GC del proceso antes de destruirlo.
        if (cleanup_vm && cleanup_proc) {
            std::thread([vm = cleanup_vm, pid = cleanup_pid,
                         proc = cleanup_proc, gch = cleanup_gc]() {
                // esperar hasta que el future deje de estar PENDING (ACK
                // recibido) o hasta 5 s como maximo para evitar que el hilo
                // quede huerfano
                for (int i = 0; i < 500; i++) {
                    uint8_t *ptr = proc->gc_heap.deref(gch);
                    if (ptr) {
                        auto *fut =
                            reinterpret_cast<loader::FutureObject *>(ptr);
                        if (fut->state != loader::FutureState::PENDING) break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                // el proceso ya no esta en ningun estado activo (NEW); safe
                // kill
                vm->schedulers[pid.scheduler_id]->kill(pid);
            }).detach();
        }
        return;
    }

    // subcomando desconocido
    vesta::scout() << "[dist] Subcomando desconocido: '" << subcmd << "'\n"
                   << "  Subcomandos validos: new, start, stop, info, list, "
                      "add-node, connect, discover, run\n"
                   << "  Usa 'dist help' para ver la ayuda completa.\n";
}

// ---- comandos alias / unalias ----

/**
 * @brief Define, lista o consulta aliases del REPL.
 *
 * Formas de uso:
 *   alias                        Lista todos los aliases definidos.
 *   alias <nombre>               Muestra la expansion del alias indicado.
 *   alias <nombre>='<expansion>' Define (o redefine) un alias.
 *   alias <nombre>=<expansion>   Igual, sin comillas.
 *
 * Los aliases se guardan en @c vm_aliases.txt al terminar cada operacion
 * de escritura, y se cargan automaticamente al iniciar el REPL.
 *
 * @param args Cadena de argumentos tras "alias".
 */
static void command_alias(const std::string &args) {
    // alias sin argumentos: listar todos
    if (args.empty()) {
        std::lock_guard<std::mutex> lk(g_aliases.mtx);
        if (g_aliases.map.empty()) {
            std::cout << ansi::c(ansi::DIM) << "(no hay aliases definidos)\n"
                      << ansi::c(ansi::RESET);
            return;
        }
        for (auto &[k, v] : g_aliases.map) {
            std::cout << "alias " << ansi::c(ansi::BR_YELLOW) << k
                      << ansi::c(ansi::RESET) << "='" << ansi::c(ansi::BR_GREEN)
                      << v << ansi::c(ansi::RESET) << "'\n";
        }
        return;
    }

    // buscar '=' para distinguir consulta de definicion
    auto eq_pos = args.find('=');
    if (eq_pos != std::string::npos) {
        // alias nombre=valor  o  alias nombre='valor'
        std::string name = args.substr(0, eq_pos);
        std::string val = args.substr(eq_pos + 1);

        // trim espacios del nombre
        auto ns = name.find_first_not_of(" \t");
        auto ne = name.find_last_not_of(" \t");
        if (ns != std::string::npos) name = name.substr(ns, ne - ns + 1);

        // quitar comillas envolventes del valor (' o ")
        if (val.size() >= 2) {
            char q = val.front();
            if ((q == '\'' || q == '"') && val.back() == q) {
                val = val.substr(1, val.size() - 2);
            }
        }

        if (name.empty() || name.find(' ') != std::string::npos) {
            std::cout << "[alias] Nombre de alias invalido: '" << name << "'\n";
            return;
        }

        {
            std::lock_guard<std::mutex> lk(g_aliases.mtx);
            g_aliases.map[name] = val;
        }
        aliases_save(g_aliases);

        std::cout << "alias " << ansi::c(ansi::BR_YELLOW) << name
                  << ansi::c(ansi::RESET) << "='" << ansi::c(ansi::BR_GREEN)
                  << val << ansi::c(ansi::RESET) << "'\n";
    } else {
        // alias nombre  -> consultar valor
        auto words = split_words(args);
        if (words.empty()) return;
        std::lock_guard<std::mutex> lk(g_aliases.mtx);
        auto it = g_aliases.map.find(words[0]);
        if (it == g_aliases.map.end()) {
            std::cout << "[alias] '" << words[0] << "' no esta definido\n";
        } else {
            std::cout << "alias " << ansi::c(ansi::BR_YELLOW) << words[0]
                      << ansi::c(ansi::RESET) << "='" << ansi::c(ansi::BR_GREEN)
                      << it->second << ansi::c(ansi::RESET) << "'\n";
        }
    }
}

/**
 * @brief Elimina uno o varios aliases.
 *
 * Formato: unalias <nombre> [nombre2 ...]
 *
 * @param args Nombres de aliases a eliminar (separados por espacios).
 */
static void command_unalias(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: unalias <nombre> [nombre2 ...]\n";
        return;
    }
    bool changed = false;
    for (auto &name : words) {
        std::lock_guard<std::mutex> lk(g_aliases.mtx);
        auto it = g_aliases.map.find(name);
        if (it == g_aliases.map.end()) {
            std::cout << "[unalias] '" << name << "' no esta definido\n";
        } else {
            g_aliases.map.erase(it);
            std::cout << "[unalias] '" << name << "' eliminado\n";
            changed = true;
        }
    }
    if (changed) aliases_save(g_aliases);
}

// ---- forward declarations (se definen tras cmd_table) ----
static bool dispatch_table_cmd(const std::string &line);
static bool
cmd_table_has(const std::string &name); // comprueba si name esta en cmd_table

// ---- helper interno: expande $VAR en una cadena arbitraria ----

/**
 * @brief Sustituye cada token $VAR o ${VAR} en @p s por el valor de la variable
 * de entorno.
 * @param s Cadena de entrada con posibles referencias a variables.
 * @return Cadena con todas las referencias expandidas.
 */
static std::string expand_vars(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '$') {
            ++i;
            bool braced = (i < s.size() && s[i] == '{');
            if (braced) ++i;
            size_t start = i;
            while (
                i < s.size() &&
                (std::isalnum(static_cast<unsigned char>(s[i])) || s[i] == '_'))
                ++i;
            if (braced && i < s.size() && s[i] == '}') ++i;
            std::string name = s.substr(start, i - start);
            if (!name.empty()) {
                const char *v = std::getenv(name.c_str());
                if (v) out += v;
            } else {
                out += '$';
            }
        } else {
            out += s[i++];
        }
    }
    return out;
}

// ---- comando env: gestion de variables de entorno ----

/**
 * @brief Gestiona las variables de entorno del proceso desde el REPL.
 *
 * Subcomandos:
 *   env [list]              Lista todas las variables de entorno.
 *   env get  KEY            Muestra el valor de una variable.
 *   env set  KEY VALUE      Establece KEY=VALUE (crea o sobreescribe).
 *   env set  KEY=VALUE      Forma alternativa con signo igual.
 *   env unset KEY           Elimina la variable KEY del entorno.
 *
 * @param args Cadena de argumentos tras "env".
 */
static void command_env(const std::string &args) {
    auto words = split_words(args);

    // env  /  env list  -> listar todo el entorno
    if (words.empty() || words[0] == "list") {
#if defined(_WIN32)
        // GetEnvironmentStringsA devuelve un bloque de pares KEY=VALUE
        // separados por '\0' y terminado con '\0\0'
        char *block = GetEnvironmentStringsA();
        if (!block) {
            std::cout << "[env] Error al obtener el entorno\n";
            return;
        }
        for (char *p = block; *p; p += std::strlen(p) + 1) {
            std::string entry(p);
            auto eq = entry.find('=');
            // ignorar entradas internas que empiezan por '=' (Windows las usa
            // internamente)
            if (eq == std::string::npos || eq == 0) continue;
            std::string key = entry.substr(0, eq);
            std::string val = entry.substr(eq + 1);
            std::cout << ansi::c(ansi::BR_YELLOW) << key << ansi::c(ansi::RESET)
                      << "=" << ansi::c(ansi::BR_GREEN) << val
                      << ansi::c(ansi::RESET) << "\n";
        }
        FreeEnvironmentStringsA(block);
#else
        for (char **ep = environ; ep && *ep; ++ep) {
            std::string entry(*ep);
            auto eq = entry.find('=');
            if (eq == std::string::npos) continue;
            std::string key = entry.substr(0, eq);
            std::string val = entry.substr(eq + 1);
            std::cout << ansi::c(ansi::BR_YELLOW) << key << ansi::c(ansi::RESET)
                      << "=" << ansi::c(ansi::BR_GREEN) << val
                      << ansi::c(ansi::RESET) << "\n";
        }
#endif
        return;
    }

    // env get KEY
    if (words[0] == "get") {
        if (words.size() < 2) {
            std::cout << "Uso: env get KEY\n";
            return;
        }
        const char *v = std::getenv(words[1].c_str());
        if (!v)
            std::cout << ansi::c(ansi::DIM) << "[env] '" << words[1]
                      << "' no esta definida\n"
                      << ansi::c(ansi::RESET);
        else
            std::cout << ansi::c(ansi::BR_YELLOW) << words[1]
                      << ansi::c(ansi::RESET) << "=" << ansi::c(ansi::BR_GREEN)
                      << v << ansi::c(ansi::RESET) << "\n";
        return;
    }

    // env set KEY VALUE  o  env set KEY=VALUE
    if (words[0] == "set") {
        std::string key, val;
        if (words.size() >= 3) {
            key = words[1];
            val = words[2];
        } else if (words.size() == 2) {
            auto eq = words[1].find('=');
            if (eq == std::string::npos) {
                std::cout << "Uso: env set KEY VALUE  o  env set KEY=VALUE\n";
                return;
            }
            key = words[1].substr(0, eq);
            val = words[1].substr(eq + 1);
        } else {
            std::cout << "Uso: env set KEY VALUE  o  env set KEY=VALUE\n";
            return;
        }
        if (key.empty()) {
            std::cout << "[env] Nombre de variable vacio\n";
            return;
        }
#if defined(_WIN32)
        if (!SetEnvironmentVariableA(key.c_str(), val.c_str())) {
            std::cout << "[env] Error al establecer '" << key << "'\n";
            return;
        }
#else
        if (setenv(key.c_str(), val.c_str(), 1) != 0) {
            std::cout << "[env] Error al establecer '" << key << "'\n";
            return;
        }
#endif
        std::cout << ansi::c(ansi::BR_YELLOW) << key << ansi::c(ansi::RESET)
                  << "=" << ansi::c(ansi::BR_GREEN) << val
                  << ansi::c(ansi::RESET) << "\n";
        return;
    }

    // env unset KEY
    if (words[0] == "unset") {
        if (words.size() < 2) {
            std::cout << "Uso: env unset KEY\n";
            return;
        }
#if defined(_WIN32)
        SetEnvironmentVariableA(words[1].c_str(), nullptr); // NULL = eliminar
#else
        unsetenv(words[1].c_str());
#endif
        std::cout << "[env] '" << words[1] << "' eliminada\n";
        return;
    }

    // env save [fichero]  -> persistir entorno actual
    if (words[0] == "save") {
        std::string path = (words.size() > 1) ? words[1] : g_env_file;
        env_save_file(path);
        std::cout << "[env] Entorno guardado en: " << path << "\n";
        return;
    }

    // env load [fichero]  -> cargar entorno desde fichero
    if (words[0] == "load") {
        std::string path = (words.size() > 1) ? words[1] : g_env_file;
        env_load_file(path);
        std::cout << "[env] Entorno cargado desde: " << path << "\n";
        return;
    }

    std::cout << "Uso: env [list|get KEY|set KEY VALUE|unset KEY|save [f]|load "
                 "[f]]\n";
}

// ---- comando echo: imprime con expansion de variables ----

/**
 * @brief Imprime el texto dado expandiendo referencias $VAR y ${VAR}.
 * @param args Texto a imprimir (puede contener $VARIABLE).
 */
static void command_echo(const std::string &args) {
    std::cout << expand_vars(args) << "\n";
}

// ---- comando mkdir: crear directorios ----

/**
 * @brief Crea uno o mas directorios (incluyendo padres intermedios).
 *
 * Formato: mkdir <dir1> [dir2 ...]
 *
 * @param args Rutas de los directorios a crear.
 */
static void command_mkdir(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: mkdir <directorio> [directorio2 ...]\n";
        return;
    }
    for (auto &w : words) {
        std::error_code ec;
        auto target = expand_path(w);
        bool created = std::filesystem::create_directories(target, ec);
        if (ec) {
            std::cout << "[mkdir] Error en '" << w << "': " << ec.message()
                      << "\n";
        } else if (created) {
            std::cout << "[mkdir] Creado: " << target.string() << "\n";
        } else {
            std::cout << "[mkdir] Ya existe: " << target.string() << "\n";
        }
    }
}

// ---- comando cat: mostrar contenido de archivos ----

/**
 * @brief Muestra el contenido de uno o varios archivos de texto.
 *
 * Formato: cat [-n] <archivo> [archivo2 ...]
 *   -n  Numerar lineas.
 *
 * @param args Opciones y rutas de archivo.
 */
/**
 * @brief Aplica coloreado de sintaxis a una linea de codigo .vel/.velb.
 *
 * Colorea comentarios (;...), mnemonicos, registros (r0-r15, rip, rsp, rbp),
 * directivas (@...), etiquetas (...:) y literales numericos.
 */
static std::string vel_highlight(const std::string &line) {
    // sin colores si la linea esta vacia
    if (line.empty()) return line;

    // comentario: toda la linea desde ';'
    auto semi = line.find(';');
    std::string code_part =
        (semi != std::string::npos) ? line.substr(0, semi) : line;
    std::string comment_part =
        (semi != std::string::npos) ? line.substr(semi) : "";

    // etiqueta al comienzo de la linea (token que termina en ':')
    std::string out;
    size_t i = 0;
    // saltar espacios iniciales
    while (i < code_part.size() && std::isspace((unsigned char)code_part[i])) {
        out += code_part[i++];
    }
    // detectar etiqueta (primer token termina en ':')
    size_t tok_start = i;
    while (i < code_part.size() && !std::isspace((unsigned char)code_part[i]) &&
           code_part[i] != ';')
        ++i;
    std::string first_tok = code_part.substr(tok_start, i - tok_start);
    if (!first_tok.empty() && first_tok.back() == ':') {
        out += ansi::c(ansi::BR_YELLOW) + first_tok + ansi::c(ansi::RESET);
    } else if (!first_tok.empty() && first_tok[0] == '@') {
        // directiva (@Module, @Export, @Generic, @Lib, @Method, @Absolute...)
        out += ansi::c(ansi::BR_CYAN) + first_tok + ansi::c(ansi::RESET);
    } else {
        // mnemonico: colorear en cian brillante
        static const std::unordered_set<std::string> mnemonics = {
            "mov",         "movh",         "movc",
            "movch",       "add",          "sub",
            "mul",         "div",          "cmp",
            "and",         "or",           "xor",
            "not",         "shl",          "shr",
            "sar",         "jmp",          "jz",
            "jnz",         "je",           "jne",
            "jl",          "jle",          "jg",
            "jge",         "ja",           "jb",
            "call",        "ret",          "hlt",
            "nop",         "push",         "pop",
            "inc",         "dec",          "mkclosure",
            "callclosure", "mkrawclosure", "callrawclosure",
            "tailcall",    "isnull",       "unwrap",
            "jumptable",   "typeswitch",   "future",
            "await",       "fulfill",      "reject",
            "subsp",       "addsp",        "weakref",
            "deref_weak",  "free_weak",    "monenter",
            "monexit",     "monwait",      "monnoti",
            "monnota",     "specialize",   "rspawn",
            "msgsend",     "msgrecv",      "memsync",
            "yield",       "resume",       "spawn",
            "swapctx",     "getproc",      "getvm",
            "getmgr",      "calln",        "db",
            "dw",          "dd",           "dq",
            "align"};
        // normalizar a minusculas para la busqueda
        std::string lc = first_tok;
        std::transform(lc.begin(), lc.end(), lc.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        // quitar sufijo de condicion (jmp.jne -> jmp)
        auto dot = lc.find('.');
        std::string base = (dot != std::string::npos) ? lc.substr(0, dot) : lc;
        if (mnemonics.count(base) || mnemonics.count(lc))
            out += std::string(ansi::c(ansi::BOLD)) + ansi::c(ansi::BR_CYAN) +
                   first_tok + ansi::c(ansi::RESET);
        else
            out += first_tok;
    }

    // resto de tokens: registros y literales
    while (i < code_part.size()) {
        // copiar espacios y separadores literalmente
        while (i < code_part.size() &&
               (std::isspace((unsigned char)code_part[i]) ||
                code_part[i] == ',' || code_part[i] == '[' ||
                code_part[i] == ']' || code_part[i] == '+' ||
                code_part[i] == '-' || code_part[i] == '*')) {
            out += code_part[i++];
        }
        if (i >= code_part.size()) break;
        // leer token
        tok_start = i;
        while (i < code_part.size() &&
               !std::isspace((unsigned char)code_part[i]) &&
               code_part[i] != ',' && code_part[i] != '[' &&
               code_part[i] != ']' && code_part[i] != '+' &&
               code_part[i] != '*')
            ++i;
        std::string tok = code_part.substr(tok_start, i - tok_start);
        if (tok.empty()) {
            ++i;
            continue;
        }

        // registros: r0-r15, rip, rsp, rbp, rfl
        std::string tlc = tok;
        std::transform(tlc.begin(), tlc.end(), tlc.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        bool is_reg = false;
        if (tlc == "rip" || tlc == "rsp" || tlc == "rbp" || tlc == "rfl") {
            is_reg = true;
        } else if (tlc.size() >= 2 && tlc[0] == 'r') {
            size_t d = 1;
            while (d < tlc.size() && std::isdigit((unsigned char)tlc[d]))
                ++d;
            if (d > 1 && d == tlc.size()) {
                int rn = std::stoi(tlc.substr(1));
                is_reg = (rn >= 0 && rn <= 15);
            }
        }
        if (is_reg) {
            out += ansi::c(ansi::BR_GREEN) + tok + ansi::c(ansi::RESET);
        } else if (!tok.empty() && (std::isdigit((unsigned char)tok[0]) ||
                                    (tok.size() > 1 && tok[0] == '-' &&
                                     std::isdigit((unsigned char)tok[1])) ||
                                    (tok.size() > 2 && tok[0] == '0' &&
                                     (tok[1] == 'x' || tok[1] == 'X')))) {
            // literal numerico
            out += ansi::c(ansi::BR_YELLOW) + tok + ansi::c(ansi::RESET);
        } else if (!tok.empty() && tok[0] == '"') {
            // literal cadena
            out += ansi::c(ansi::BR_YELLOW) + tok + ansi::c(ansi::RESET);
        } else {
            out += tok;
        }
    }

    // anadir comentario en gris
    if (!comment_part.empty())
        out += ansi::c(ansi::DIM) + comment_part + ansi::c(ansi::RESET);

    return out;
}

static void command_cat(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: cat [-n] [-h] <archivo> [archivo2 ...]\n";
        return;
    }

    bool line_nums = false;
    bool no_highlight = false;
    std::vector<std::string> files;
    for (auto &w : words) {
        if (w == "-n")
            line_nums = true;
        else if (w == "--raw")
            no_highlight = true;
        else
            files.push_back(w);
    }
    if (files.empty()) {
        std::cout << "Uso: cat [-n] [--raw] <archivo>\n";
        return;
    }

    for (auto &f : files) {
        auto path = expand_path(f);
        std::ifstream ifs(path);
        if (!ifs) {
            std::cout << ansi::c(ansi::BR_RED)
                      << "cat: no se puede abrir: " << path.string()
                      << ansi::c(ansi::RESET) << "\n";
            continue;
        }
        if (files.size() > 1) {
            // cabecera separadora cuando hay varios archivos
            std::cout << ansi::c(ansi::BOLD) << ansi::c(ansi::DIM) << "==> "
                      << path.string() << " <==" << ansi::c(ansi::RESET)
                      << "\n";
        }
        // detectar si el archivo es .vel o .velb para activar highlighting
        bool do_hl = !no_highlight;
        if (do_hl) {
            std::string ext = path.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            do_hl = (ext == ".vel");
        }
        std::string line;
        size_t n = 1;
        while (std::getline(ifs, line)) {
            if (line_nums) {
                std::cout << ansi::c(ansi::DIM) << std::setw(6) << n++ << "\t"
                          << ansi::c(ansi::RESET);
            }
            std::cout << (do_hl ? vel_highlight(line) : line) << "\n";
        }
    }
}

// ---- comando rm: eliminar archivos o directorios ----

/**
 * @brief Elimina archivos o directorios.
 *
 * Formato: rm [-r] <ruta> [ruta2 ...]
 *   -r  Borrar directorio recursivamente.
 *
 * Pide confirmacion antes de borrar directorios no vacios.
 *
 * @param args Opciones y rutas a eliminar.
 */
static void command_rm(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: rm [-r] <ruta> [ruta2 ...]\n";
        return;
    }

    bool recursive = false;
    std::vector<std::string> targets;
    for (auto &w : words) {
        if (w == "-r" || w == "-rf" || w == "-fr")
            recursive = true;
        else
            targets.push_back(w);
    }
    if (targets.empty()) {
        std::cout << "Uso: rm [-r] <ruta>\n";
        return;
    }

    for (auto &t : targets) {
        auto path = expand_path(t);
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            std::cout << "[rm] No existe: " << path.string() << "\n";
            continue;
        }
        bool is_dir = std::filesystem::is_directory(path, ec);
        if (is_dir && !recursive) {
            std::cout
                << "[rm] '" << path.string()
                << "' es un directorio; usa -r para borrar recursivamente\n";
            continue;
        }
        if (is_dir) {
            // pedir confirmacion para directorios
            std::cout << ansi::c(ansi::BR_YELLOW) << "Borrar directorio '"
                      << path.string() << "' y todo su contenido? [s/N] "
                      << ansi::c(ansi::RESET) << std::flush;
            std::string resp;
            if (!std::getline(std::cin, resp) || (resp != "s" && resp != "S")) {
                std::cout << "[rm] Cancelado\n";
                continue;
            }
            uintmax_t removed = std::filesystem::remove_all(path, ec);
            if (ec)
                std::cout << "[rm] Error: " << ec.message() << "\n";
            else
                std::cout << "[rm] Eliminados " << removed << " elemento(s)\n";
        } else {
            std::filesystem::remove(path, ec);
            if (ec)
                std::cout << "[rm] Error: " << ec.message() << "\n";
            else
                std::cout << "[rm] Eliminado: " << path.string() << "\n";
        }
    }
}

// ---- comando touch ----
static void command_touch(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: touch <archivo> [archivo2 ...]\n";
        return;
    }
    for (auto &w : words) {
        auto p = expand_path(w);
        std::error_code ec;
        if (std::filesystem::exists(p, ec)) {
            // actualizar timestamp con escritura vacia
            std::ofstream ofs(p, std::ios::app);
            if (!ofs)
                std::cout << "[touch] No se puede actualizar: " << p.string()
                          << "\n";
        } else {
            std::ofstream ofs(p);
            if (!ofs)
                std::cout << "[touch] No se puede crear: " << p.string()
                          << "\n";
            else
                std::cout << "[touch] Creado: " << p.string() << "\n";
        }
    }
}

// ---- comando cp ----
/** @brief Copia archivos o directorios.  Formato: cp [-r] <src> <dst> */
static void command_cp(const std::string &args) {
    auto words = split_words(args);
    bool recursive = false;
    std::vector<std::string> targets;
    for (auto &w : words) {
        if (w == "-r" || w == "-R")
            recursive = true;
        else
            targets.push_back(w);
    }
    if (targets.size() < 2) {
        std::cout << "Uso: cp [-r] <src> <dst>\n";
        return;
    }
    auto src = expand_path(targets[0]);
    auto dst = expand_path(targets[1]);
    std::error_code ec;
    if (!std::filesystem::exists(src, ec)) {
        std::cout << "[cp] No existe: " << src.string() << "\n";
        return;
    }
    if (std::filesystem::is_directory(src)) {
        if (!recursive) {
            std::cout << "[cp] Usa -r para copiar directorios\n";
            return;
        }
        std::filesystem::copy(
            src, dst,
            std::filesystem::copy_options::recursive |
                std::filesystem::copy_options::overwrite_existing,
            ec);
    } else {
        // si dst es directorio, copiar dentro
        if (std::filesystem::is_directory(dst, ec)) dst = dst / src.filename();
        std::filesystem::copy_file(
            src, dst, std::filesystem::copy_options::overwrite_existing, ec);
    }
    if (ec)
        std::cout << "[cp] Error: " << ec.message() << "\n";
    else
        std::cout << "[cp] " << src.string() << " -> " << dst.string() << "\n";
}

// ---- comando mv ----
/** @brief Mueve o renombra archivos/directorios. Formato: mv <src> <dst> */
static void command_mv(const std::string &args) {
    auto words = split_words(args);
    if (words.size() < 2) {
        std::cout << "Uso: mv <src> <dst>\n";
        return;
    }
    auto src = expand_path(words[0]);
    auto dst = expand_path(words[1]);
    std::error_code ec;
    if (!std::filesystem::exists(src, ec)) {
        std::cout << "[mv] No existe: " << src.string() << "\n";
        return;
    }
    if (std::filesystem::is_directory(dst, ec)) dst = dst / src.filename();
    std::filesystem::rename(src, dst, ec);
    if (ec)
        std::cout << "[mv] Error: " << ec.message() << "\n";
    else
        std::cout << "[mv] " << src.string() << " -> " << dst.string() << "\n";
}

// ---- comando head ----
/** @brief Muestra las primeras N lineas de un archivo. Formato: head [-n N]
 * <archivo> */
static void command_head(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: head [-n N] <archivo>\n";
        return;
    }
    size_t n = 10;
    std::vector<std::string> files;
    for (size_t i = 0; i < words.size(); ++i) {
        if (words[i] == "-n" && i + 1 < words.size()) {
            try {
                n = std::stoul(words[++i]);
            } catch (...) {
            }
        } else {
            files.push_back(words[i]);
        }
    }
    for (auto &f : files) {
        auto p = expand_path(f);
        std::ifstream ifs(p);
        if (!ifs) {
            std::cout << "head: no se puede abrir: " << p.string() << "\n";
            continue;
        }
        if (files.size() > 1)
            std::cout << ansi::c(ansi::BOLD) << "==> " << p.string()
                      << " <==" << ansi::c(ansi::RESET) << "\n";
        std::string line;
        for (size_t i = 0; i < n && std::getline(ifs, line); ++i)
            std::cout << line << "\n";
    }
}

// ---- comando tail ----
/** @brief Muestra las ultimas N lineas de un archivo; -f sigue en tiempo real.
 */
static void command_tail(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: tail [-n N] [-f] <archivo>\n";
        return;
    }
    size_t n = 10;
    bool follow = false;
    std::vector<std::string> files;
    for (size_t i = 0; i < words.size(); ++i) {
        if (words[i] == "-n" && i + 1 < words.size()) {
            try {
                n = std::stoul(words[++i]);
            } catch (...) {
            }
        } else if (words[i] == "-f") {
            follow = true;
        } else {
            files.push_back(words[i]);
        }
    }
    if (files.empty()) {
        std::cout << "Uso: tail [-n N] [-f] <archivo>\n";
        return;
    }

    for (auto &f : files) {
        auto p = expand_path(f);
        std::ifstream ifs(p);
        if (!ifs) {
            std::cout << "tail: no se puede abrir: " << p.string() << "\n";
            continue;
        }
        if (files.size() > 1)
            std::cout << ansi::c(ansi::BOLD) << "==> " << p.string()
                      << " <==" << ansi::c(ansi::RESET) << "\n";

        // leer todas las lineas y mostrar las ultimas n
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(ifs, line))
            lines.push_back(line);
        size_t start = (lines.size() > n) ? lines.size() - n : 0;
        for (size_t i = start; i < lines.size(); ++i)
            std::cout << lines[i] << "\n";

        if (follow) {
            std::cout << ansi::c(ansi::DIM) << "[tail -f] Siguiendo "
                      << p.string() << " (pulsa cualquier tecla para salir)..."
                      << ansi::c(ansi::RESET) << "\n";
            // reposicionarse al final del archivo
            ifs.clear();
            ifs.seekg(0, std::ios::end);
            while (true) {
                // comprobar si hay nueva entrada de teclado (no bloqueante)
#if defined(_WIN32)
                if (_kbhit()) {
                    _getch();
                    break;
                }
#else
                // usar select con timeout cero para stdin
                struct timeval tv{0, 0};
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(STDIN_FILENO, &fds);
                if (select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) > 0) {
                    char c;
                    ::read(STDIN_FILENO, &c, 1);
                    break;
                }
#endif
                // leer nuevas lineas del archivo
                while (std::getline(ifs, line))
                    std::cout << line << "\n" << std::flush;
                ifs.clear(); // limpiar eofbit para proxima lectura
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }
        }
    }
}

// ---- comando type ----
/** @brief Muestra si un nombre es alias, comando interno, o desconocido. */
static void command_type(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: type <nombre> [nombre2 ...]\n";
        return;
    }
    for (auto &name : words) {
        // comprobar alias primero
        {
            std::lock_guard<std::mutex> lk(g_aliases.mtx);
            auto it = g_aliases.map.find(name);
            if (it != g_aliases.map.end()) {
                std::cout << ansi::c(ansi::BR_YELLOW) << name
                          << ansi::c(ansi::RESET) << " es un alias -> '"
                          << ansi::c(ansi::BR_GREEN) << it->second
                          << ansi::c(ansi::RESET) << "'\n";
                continue;
            }
        }
        // comprobar comandos especiales del REPL
        static const char *specials[] = {"exit",       "help",     "history",
                                         "interprete", "complete", "source",
                                         "!N",         ":prev",    ":next"};
        bool is_special = false;
        for (auto &s : specials)
            if (name == s) {
                is_special = true;
                break;
            }
        if (is_special) {
            std::cout << ansi::c(ansi::BR_CYAN) << name << ansi::c(ansi::RESET)
                      << " es un comando especial del REPL\n";
            continue;
        }
        // comprobar cmd_table via forward declaration
        if (cmd_table_has(name)) {
            std::cout << ansi::c(ansi::BR_CYAN) << name << ansi::c(ansi::RESET)
                      << " es un comando interno\n";
        } else {
            std::cout << ansi::c(ansi::DIM) << name << ansi::c(ansi::RESET)
                      << ": no encontrado\n";
        }
    }
}

// ---- comando source ----
/** @brief Ejecuta linea a linea un fichero de comandos del REPL. */
static void command_source(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: source <archivo>\n";
        return;
    }
    auto path = expand_path(words[0]);
    std::ifstream f(path);
    if (!f) {
        std::cout << "[source] No se puede abrir: " << path.string() << "\n";
        return;
    }
    std::string line;
    size_t count = 0, ok = 0;
    while (std::getline(f, line)) {
        ++count;
        auto s0 = line.find_first_not_of(" \t\r\n");
        if (s0 == std::string::npos || line[s0] == '#') continue;
        if (dispatch_table_cmd(line)) ++ok;
    }
    vesta::scout() << "[source] " << path.filename().string() << ": " << ok
                   << "/" << count << " lineas ejecutadas\n";
}

// ---- env persistente: subcomandos save / load ----
// (la funcion command_env completa esta mas arriba; se amplia con estos
// helpers)

// ---- comando set ----
/**
 * @brief Configura parametros del REPL en caliente.
 *
 * Parametros disponibles: history_max, multiline_end, aliases_file, env_file.
 * Formato: set [clave] [= valor]
 */
static void command_set(const std::string &args) {
    // sin argumentos: listar todos
    if (args.empty() || args == "list") {
        if (!g_current_impl) {
            std::cout << "[set] REPL no activo\n";
            return;
        }
        auto &cfg = g_current_impl->cfg;
        auto P = [](const char *k, const std::string &v) {
            std::cout << ansi::c(ansi::BR_YELLOW) << std::left << std::setw(20)
                      << k << ansi::c(ansi::RESET) << "= "
                      << ansi::c(ansi::BR_GREEN) << v << ansi::c(ansi::RESET)
                      << "\n";
        };
        P("history_max", std::to_string(cfg.history_max));
        P("multiline_end", cfg.multiline_end);
        P("aliases_file", cfg.aliases_file);
        P("env_file", g_env_file);
        return;
    }

    // separar clave y valor: "key = value" o "key=value" o "key value"
    std::string key, val;
    auto eq = args.find('=');
    if (eq != std::string::npos) {
        key = args.substr(0, eq);
        val = args.substr(eq + 1);
    } else {
        auto sp = args.find(' ');
        if (sp == std::string::npos) {
            // solo clave: mostrar valor actual
            key = args;
            val = "";
        } else {
            key = args.substr(0, sp);
            val = args.substr(sp + 1);
        }
    }
    // trim
    auto trim = [](std::string &s) {
        auto s0 = s.find_first_not_of(" \t'\"");
        auto s1 = s.find_last_not_of(" \t'\"");
        s = (s0 == std::string::npos) ? "" : s.substr(s0, s1 - s0 + 1);
    };
    trim(key);
    trim(val);

    if (!g_current_impl) {
        std::cout << "[set] REPL no activo\n";
        return;
    }
    auto &cfg = g_current_impl->cfg;

    if (val.empty()) {
        // solo mostrar
        if (key == "history_max")
            std::cout << cfg.history_max << "\n";
        else if (key == "multiline_end")
            std::cout << cfg.multiline_end << "\n";
        else if (key == "aliases_file")
            std::cout << cfg.aliases_file << "\n";
        else if (key == "env_file")
            std::cout << g_env_file << "\n";
        else
            std::cout << "[set] Clave desconocida: " << key << "\n";
        return;
    }

    // aplicar cambio
    if (key == "history_max") {
        try {
            cfg.history_max = std::stoul(val);
            std::cout << "[set] history_max=" << cfg.history_max << "\n";
        } catch (...) {
            std::cout << "[set] Valor invalido\n";
        }
    } else if (key == "multiline_end") {
        cfg.multiline_end = val;
        std::cout << "[set] OK\n";
    } else if (key == "aliases_file") {
        cfg.aliases_file = val;
        g_aliases.file = val;
        std::cout << "[set] OK (recarga con 'source " << val << "')\n";
    } else if (key == "env_file") {
        g_env_file = val;
        std::cout << "[set] OK\n";
    } else
        std::cout << "[set] Clave desconocida: " << key
                  << "\n  Claves: history_max, multiline_end, aliases_file, "
                     "env_file\n";
}

// ---- comando jobs ----
/** @brief Lista todas las tareas en background con su estado y duracion. */
static void command_jobs(const std::string &) {
    std::lock_guard<std::mutex> lk(g_jobs.mtx);
    if (g_jobs.jobs.empty()) {
        std::cout << ansi::c(ansi::DIM) << "(no hay tareas en background)\n"
                  << ansi::c(ansi::RESET);
        return;
    }
    auto now = std::chrono::steady_clock::now();
    std::cout << ansi::c(ansi::BOLD) << std::left << std::setw(6) << "ID"
              << std::setw(8) << "ESTADO" << std::setw(12) << "DURACION"
              << "NOMBRE" << ansi::c(ansi::RESET) << "\n"
              << std::string(50, '-') << "\n";
    for (auto &[id, e] : g_jobs.jobs) {
        double elapsed =
            std::chrono::duration<double>(now - e->start_time).count();
        char dur[32];
        snprintf(dur, sizeof(dur), "%.1fs", elapsed);
        bool done = e->done.load();
        std::cout << std::setw(6) << id
                  << (done ? ansi::c(ansi::DIM) : ansi::c(ansi::BR_GREEN))
                  << std::setw(8) << (done ? "DONE" : "RUN")
                  << ansi::c(ansi::RESET) << std::setw(12) << dur << e->name
                  << (done ? std::string("  [") + e->result_msg + "]" : "")
                  << "\n";
    }
}

// ---- comando wait ----
/** @brief Bloquea hasta que el job indicado termine. */
static void command_wait(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: wait <job_id>\n";
        return;
    }
    size_t id;
    try {
        id = std::stoul(words[0]);
    } catch (...) {
        std::cout << "[wait] ID invalido\n";
        return;
    }
    std::shared_ptr<JobEntry> entry;
    {
        std::lock_guard<std::mutex> lk(g_jobs.mtx);
        auto it = g_jobs.jobs.find(id);
        if (it == g_jobs.jobs.end()) {
            std::cout << "[wait] Job " << id << " no encontrado\n";
            return;
        }
        entry = it->second;
    }
    if (entry->done.load()) {
        std::cout << "[wait] Job " << id << " ya termino: " << entry->result_msg
                  << "\n";
        return;
    }
    std::cout << "[wait] Esperando job " << id << " (" << entry->name
              << ")...\n"
              << std::flush;
    std::unique_lock<std::mutex> lk(g_jobs.mtx);
    g_jobs.cv.wait(lk, [&] { return entry->done.load(); });
    std::cout << "[wait] Job " << id << " completado: " << entry->result_msg
              << "\n";
}

// ---- comando watch ----
/**
 * @brief Ejecuta un comando del REPL repetidamente con intervalo.
 * Formato: watch <ms> <comando args...>
 * Cualquier tecla detiene el bucle.
 */
static void command_watch(const std::string &args) {
    auto words = split_words(args);
    if (words.size() < 2) {
        std::cout << "Uso: watch <intervalo_ms> <comando ...>\n";
        return;
    }
    size_t ms = 1000;
    try {
        ms = std::stoul(words[0]);
    } catch (...) {
        std::cout << "[watch] Intervalo invalido\n";
        return;
    }
    // reconstruir el comando completo (todo tras el primer token)
    std::string watch_cmd = args.substr(args.find(words[0]) + words[0].size());
    auto ws = watch_cmd.find_first_not_of(" \t");
    if (ws != std::string::npos) watch_cmd = watch_cmd.substr(ws);

    std::cout << ansi::c(ansi::DIM) << "[watch] Intervalo " << ms
              << "ms. Pulsa cualquier tecla para salir.\n"
              << ansi::c(ansi::RESET);

    while (true) {
        clear_screen();
        // cabecera
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        char tbuf[64];
        struct tm *tmi = std::localtime(&t);
        if (tmi)
            std::strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tmi);
        else
            tbuf[0] = 0;
        std::cout << ansi::c(ansi::BOLD) << ansi::c(ansi::DIM) << "watch ("
                  << ms << "ms)  " << tbuf << "  '" << watch_cmd << "'"
                  << ansi::c(ansi::RESET) << "\n\n";

        dispatch_table_cmd(watch_cmd);

        // esperar ms en trozos de 50ms, comprobando teclado
        for (size_t t2 = 0; t2 < ms; t2 += 50) {
#if defined(_WIN32)
            if (_kbhit()) {
                _getch();
                goto watch_exit;
            }
#else
            struct timeval tv{0, 0};
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(STDIN_FILENO, &fds);
            if (select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) > 0) {
                char c2;
                ::read(STDIN_FILENO, &c2, 1);
                goto watch_exit;
            }
#endif
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
watch_exit:
    std::cout << "\n[watch] Detenido\n";
}

// ---- tabla de comandos ----

/**
 * @brief Descriptor de un comando del REPL.
 *
 * Cada entrada asocia un nombre de comando a su handler y su documentacion.
 * Anadir un comando nuevo = anadir una entrada a @c cmd_table.
 */
struct CmdEntry {
    const char *name;  ///< Nombre exacto del comando (primer token).
    const char *usage; ///< Linea de uso para help.
    const char *brief; ///< Descripcion breve para help.
    void (*fn)(const std::string
                   &args); ///< Handler; args = todo lo que sigue al nombre.
};

// ---- interprete VestaShell (.vsh) global ----

/** @brief Instancia global del interprete VestaShell. Se crea con lazy-init. */
static vsh::VshInterpreter *g_vsh_interp = nullptr;

/**
 * @brief Devuelve (o crea) el interprete VestaShell con el callback de despacho
 * REPL.
 *
 * El callback permite que las funciones .vsh sin nombre definido en el scope
 * se reenvien al despachador de la tabla de comandos del REPL.
 */
static vsh::VshInterpreter &get_vsh_interp() {
    if (!g_vsh_interp) {
        g_vsh_interp =
            new vsh::VshInterpreter([](const std::string &line) -> bool {
                return dispatch_table_cmd(line);
            });
    }
    return *g_vsh_interp;
}

/**
 * @brief Ejecuta un fichero .vsh con el interprete VestaShell.
 *
 * @param args  Ruta al fichero .vsh a ejecutar.
 */
static void command_script(const std::string &args) {
    auto words = split_words(args);
    if (words.empty()) {
        std::cout << "Uso: script <archivo.vsh> [args...]\n";
        return;
    }
    const std::string &path = words[0];

    // Construir ARGV: [path, words[1..]]
    std::vector<std::string> script_args;
    script_args.push_back(path);
    for (size_t i = 1; i < words.size(); ++i) {
        script_args.push_back(words[i]);
    }

    try {
        auto &interp = get_vsh_interp();
        interp.set_argv(script_args);
        interp.exec_file(path);
    } catch (const vsh::VshRuntimeError &e) {
        std::cout << ansi::c(ansi::BR_RED) << "[script] Error: " << e.what()
                  << ansi::c(ansi::RESET) << "\n";
    } catch (const vsh::VshParseError &e) {
        std::cout << ansi::c(ansi::BR_RED)
                  << "[script] Error de sintaxis: " << e.what()
                  << ansi::c(ansi::RESET) << "\n";
    } catch (const std::exception &e) {
        std::cout << ansi::c(ansi::BR_RED) << "[script] " << e.what()
                  << ansi::c(ansi::RESET) << "\n";
    }
}

/**
 * @brief Abre el REPL interactivo de VestaShell.
 *
 * @param args  No se usa (se ignora).
 */
static void command_vsh(const std::string & /*args*/) {
    try {
        get_vsh_interp().run_interactive();
    } catch (const std::exception &e) {
        std::cout << ansi::c(ansi::BR_RED) << "[vsh] " << e.what()
                  << ansi::c(ansi::RESET) << "\n";
    }
}

/**
 * @brief Tabla de todos los comandos despachables por nombre.
 *
 * El bucle principal de @c VestaViewManager::run() busca en esta tabla el
 * primer token del comando introducido y llama a @c fn con el resto de la
 * linea.
 */
static const CmdEntry cmd_table[] = {
    // nombre      uso                                         descripcion breve
    // handler
    {"ls", "ls [ruta|patron]  (e.g. *.vel, src/*.velb)",
     "Listar directorio con soporte de patrones glob", command_ls},
    {"vms", "vms", "Listar managers activos con ID y estado", command_vms},
    {"kill", "kill <id>", "Detener y eliminar manager por ID", command_kill},
    {"build", "build <archivo.vel> [-o <salida>]", "Compilar .vel a .velb",
     command_build},
    {"vpp", "vpp <archivo.vel> [-o <salida>] [-D N] [-I r] [-M r]",
     "Preprocesar .vel y mostrar/guardar resultado expandido", command_vpp},
    {"disasm", "disasm <archivo.velb>", "Desensamblar bytecode VestaVM",
     command_disasm},
    {"exec", "exec <archivo.velb> [--schedulers N]",
     "Ejecutar .velb en background", command_exec},
    {"run", "run <nombre> <ruta.velb> [--schedulers N] [--stats]",
     "Ejecutar .velb con manager nombrado (--stats para estadisticas)",
     command_run},
    {"pwd", "pwd", "Mostrar directorio de trabajo actual", command_pwd},
    {"cls", "cls", "Limpiar pantalla", command_clear},
    {"clear", "clear", "Limpiar pantalla", command_clear},
    {"cd", "cd [ruta|-]", "Cambiar directorio (- = anterior, vacio = HOME)",
     command_cd},
    {"cmd", "cmd <comando>", "Ejecutar comando de shell (asincrono)",
     command_cmd},
    {"mgrinfo", "mgrinfo <id>", "Info detallada de un manager de VM",
     command_mgrinfo},
    {"vmstat", "vmstat <mgr_id> <vm_id>", "Estadisticas de una instancia VM",
     command_vmstat},
    {"schedtop", "schedtop <mgr_id> <vm_id>",
     "Vista htop de schedulers (ENTER para salir)", command_schedtop},
    {"procinfo", "procinfo <mgr_id> <vm_id> <sched_id> <pid>",
     "Info de un proceso virtual", command_procinfo},
    {"dist", "dist <subcmd> <mgr_id> [opciones]  (dist help para mas info)",
     "Gestionar el runtime distribuido "
     "(start/stop/info/list/add-node/connect/discover/run)",
     command_dist},
    {"alias", "alias [nombre[='expansion']]",
     "Definir o listar aliases persistentes entre sesiones", command_alias},
    {"unalias", "unalias <nombre> [nombre2 ...]",
     "Eliminar uno o varios aliases", command_unalias},
    {"env", "env [list|get KEY|set KEY=VALUE|unset KEY|save [f]|load [f]]",
     "Gestionar variables de entorno del proceso (save/load persiste en disco)",
     command_env},
    {"echo", "echo <texto con $VARS>",
     "Imprimir texto expandiendo variables de entorno ($VAR, ${VAR})",
     command_echo},
    {"mkdir", "mkdir <directorio> [directorio2 ...]",
     "Crear directorios (con padres intermedios)", command_mkdir},
    {"cat", "cat [-n] [--raw] <archivo> [archivo2 ...]",
     "Mostrar archivos (.vel con syntax highlight; --raw desactiva colores)",
     command_cat},
    {"rm", "rm [-r] <ruta> [ruta2 ...]",
     "Eliminar archivos o directorios (-r para recursivo)", command_rm},
    {"touch", "touch <archivo> [archivo2 ...]",
     "Crear archivo vacio o actualizar su timestamp", command_touch},
    {"cp", "cp [-r] <src> <dst>",
     "Copiar archivo o directorio (-r para recursivo)", command_cp},
    {"mv", "mv <src> <dst>", "Mover o renombrar archivo/directorio",
     command_mv},
    {"head", "head [-n N] <archivo> [archivo2 ...]",
     "Mostrar las primeras N lineas de un archivo (defecto: 10)", command_head},
    {"tail", "tail [-n N] [-f] <archivo> [archivo2 ...]",
     "Mostrar las ultimas N lineas; -f sigue el archivo en tiempo real",
     command_tail},
    {"type", "type <nombre> [nombre2 ...]",
     "Mostrar si un nombre es alias, comando interno o desconocido",
     command_type},
    {"source", "source <archivo>",
     "Ejecutar linea a linea un fichero de comandos del REPL", command_source},
    {"set", "set [clave [= valor]]",
     "Leer o modificar parametros del REPL en caliente (history_max, "
     "multiline_end...)",
     command_set},
    {"jobs", "jobs", "Listar tareas en background con estado y duracion",
     command_jobs},
    {"wait", "wait <job_id>", "Bloquear hasta que el job indicado termine",
     command_wait},
    {"watch", "watch <intervalo_ms> <comando ...>",
     "Ejecutar un comando repetidamente con intervalo; cualquier tecla detiene",
     command_watch},
    {"script", "script <archivo.vsh>",
     "Ejecutar un fichero VestaShell (.vsh) con el interprete integrado",
     command_script},
    {"vsh", "vsh", "Abrir el interprete interactivo VestaShell (REPL .vsh)",
     command_vsh},
};

// numero de entradas en la tabla
static constexpr size_t CMD_TABLE_SIZE =
    sizeof(cmd_table) / sizeof(cmd_table[0]);

/** @brief Devuelve true si @p name existe como entrada en cmd_table. */
static bool cmd_table_has(const std::string &name) {
    for (size_t i = 0; i < CMD_TABLE_SIZE; ++i)
        if (name == cmd_table[i].name) return true;
    return false;
}

// ---- dispatch_table_cmd: despacho reutilizable para source/watch ----

/**
 * @brief Trim, expande aliases y despacha @p raw_line via cmd_table.
 *
 * Ignora lineas vacias y comentarios (#). No procesa comandos especiales
 * del REPL (exit, interprete, etc.) para evitar efectos secundarios en source.
 *
 * @return true si fue manejado por cmd_table.
 */
static bool dispatch_table_cmd(const std::string &raw_line) {
    auto s0 = raw_line.find_first_not_of(" \t\r\n");
    if (s0 == std::string::npos) return false;
    auto s1 = raw_line.find_last_not_of(" \t\r\n");
    std::string line = raw_line.substr(s0, s1 - s0 + 1);
    if (line.empty() || line[0] == '#') return false;

    auto sp = line.find(' ');
    std::string cmd_name =
        (sp == std::string::npos) ? line : line.substr(0, sp);
    std::string cmd_args =
        (sp == std::string::npos) ? std::string{} : line.substr(sp + 1);

    // expansion de aliases (mismo algoritmo que run())
    for (int depth = 0; depth < 16; ++depth) {
        std::string expanded;
        {
            std::lock_guard<std::mutex> lk(g_aliases.mtx);
            auto it = g_aliases.map.find(cmd_name);
            if (it == g_aliases.map.end()) break;
            expanded = it->second;
        }
        auto exp_w = split_words(expanded);
        if (!exp_w.empty() && exp_w[0] == cmd_name) break;
        std::string full =
            cmd_args.empty() ? expanded : expanded + " " + cmd_args;
        auto sp2 = full.find(' ');
        cmd_name = (sp2 == std::string::npos) ? full : full.substr(0, sp2);
        cmd_args =
            (sp2 == std::string::npos) ? std::string{} : full.substr(sp2 + 1);
    }

    for (size_t i = 0; i < CMD_TABLE_SIZE; ++i) {
        if (cmd_name == cmd_table[i].name) {
            cmd_table[i].fn(cmd_args);
            return true;
        }
    }
    return false;
}

// ---- senal global Ctrl+C ----

static std::atomic<bool> *global_interrupt_ptr = nullptr;

static void global_sigint_handler(int) {
    if (global_interrupt_ptr) *global_interrupt_ptr = true;
}

// ---- helpers de historial ----

static void load_history_impl(Impl &I) {
    std::lock_guard lk(I.hist_m);
    std::ifstream f(I.cfg.history_file);
    if (!f) return;
    std::string line;
    while (std::getline(f, line))
        if (!line.empty()) I.history.push_back(line);
}

static void save_history_impl(Impl &I) {
    std::lock_guard lk(I.hist_m);
    std::ofstream f(I.cfg.history_file, std::ios::trunc);
    if (!f) return;
    size_t start = I.history.size() > I.cfg.history_max
                       ? I.history.size() - I.cfg.history_max
                       : 0;
    for (size_t i = start; i < I.history.size(); ++i)
        f << I.history[i] << "\n";
}

static void add_history_entry_impl(Impl &I, const std::string &line) {
    if (line.empty()) return;
    std::lock_guard lk(I.hist_m);
    if (!I.history.empty() && I.history.back() == line)
        return; // deduplicar consecutivos
    I.history.push_back(line);
    if (I.history.size() > I.cfg.history_max)
        I.history.erase(I.history.begin());
}

// ---- helpers de cola de comandos ----

static void cmd_queue_push_impl(Impl &I, std::string cmd) {
    {
        std::lock_guard lk(I.q_m);
        if (I.q_closed) return;
        I.cmd_queue.push_back(std::move(cmd));
    }
    I.q_cv.notify_one();
}

static bool cmd_queue_pop_impl(Impl &I, std::string &out) {
    std::unique_lock lk(I.q_m);
    I.q_cv.wait(lk, [&] { return !I.cmd_queue.empty() || I.q_closed; });
    if (I.cmd_queue.empty()) return false;
    out = std::move(I.cmd_queue.front());
    I.cmd_queue.pop_front();
    return true;
}

static void cmd_queue_close_impl(Impl &I) {
    {
        std::lock_guard lk(I.q_m);
        I.q_closed = true;
    }
    I.q_cv.notify_all();
}

// ---- worker loop ----

static void worker_loop_impl(Impl &I) {
    while (I.running) {
        std::string cmd;
        if (!cmd_queue_pop_impl(I, cmd)) break;
        std::function<void(const std::string &)> cb;
        {
            std::lock_guard lk(I.cb_m);
            cb = I.vm_execute_cb;
        }
        if (cb) {
            cb(cmd);
        } else {
            // fallback mientras no hay callback registrado
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            std::cout << "[VM] ejecutado: " << cmd << std::endl;
        }
    }
}

// ---- comandos especiales del REPL ----

/**
 * @brief Imprime la ayuda del REPL generada a partir de cmd_table.
 * @param I Estado del REPL (para leer cfg.multiline_end).
 */
static void print_help_impl(const Impl &I) {
    // cabecera con color
    auto H = [](const char *s) {
        std::cout << ansi::c(ansi::BOLD) << ansi::c(ansi::BR_CYAN) << s
                  << ansi::c(ansi::RESET) << "\n";
    };
    auto CMD = [](const char *usage, const char *brief) {
        std::cout << "  " << ansi::c(ansi::BR_YELLOW) << std::left
                  << std::setw(46) << usage << ansi::c(ansi::RESET) << " "
                  << brief << "\n";
    };

    H("Comandos especiales:");
    CMD("exit", "salir");
    CMD("help", "mostrar esta ayuda");
    CMD("history", "listar historial con indices");
    CMD("!N", "ejecutar entrada N del historial  (ej: !3)");
    CMD(":prev / :next", "historial anterior / siguiente");
    CMD("complete PREF", "listar completions para PREF");
    CMD("interprete", "abrir el interprete interactivo de Vesta");
    std::cout << "\n";
    H("Comandos:");
    for (size_t i = 0; i < CMD_TABLE_SIZE; ++i) {
        if (std::string(cmd_table[i].name) == "clear") continue; // alias de cls
        CMD(cmd_table[i].usage, cmd_table[i].brief);
    }
    // seccion de aliases solo si hay alguno definido
    {
        std::lock_guard<std::mutex> lk(g_aliases.mtx);
        if (!g_aliases.map.empty()) {
            std::cout << "\n";
            H("Aliases activos:");
            for (auto &[k, v] : g_aliases.map) {
                std::string entry = k + "='" + v + "'";
                std::cout << "  " << ansi::c(ansi::BR_YELLOW) << std::left
                          << std::setw(46) << entry << ansi::c(ansi::RESET)
                          << "\n";
            }
        }
    }

    std::cout << "\n"
              << ansi::c(ansi::DIM) << "Multilinea: termina con '"
              << I.cfg.multiline_end << "' para enviar bloque.\n"
              << "Nota: 'run' y 'exec' lanzan la VM en segundo plano; 'cmd' "
                 "ejecuta shell.\n"
              << "      'dist help' muestra la ayuda completa de los comandos "
                 "distribuidos.\n"
              << "      Los aliases se guardan en '" << g_aliases.file
              << "' y persisten entre sesiones.\n"
              << ansi::c(ansi::RESET);
}

static void print_history_impl(Impl &I) {
    std::lock_guard lk(I.hist_m);
    for (size_t i = 0; i < I.history.size(); ++i)
        std::cout << i << ": " << I.history[i] << "\n";
}

static void handle_history_exec_impl(Impl &I, const std::string &cmd) {
    std::string num = cmd.substr(1);
    try {
        size_t idx = std::stoul(num);
        std::lock_guard lk(I.hist_m);
        if (idx < I.history.size()) {
            std::string hcmd = I.history[idx];
            std::cout << "[exec] " << hcmd << "\n";
            add_history_entry_impl(I, hcmd);
            cmd_queue_push_impl(I, hcmd);
        } else {
            std::cout << "Indice fuera de rango\n";
        }
    } catch (...) {
        std::cout << "Uso: !N  (N = indice de history)\n";
    }
}

static void show_prev_history_impl(Impl &I) {
    std::lock_guard lk(I.hist_m);
    if (I.history.empty()) {
        std::cout << "(historial vacio)\n";
        return;
    }
    if (I.history_cursor < 0) I.history_cursor = (int)I.history.size() - 1;
    std::cout << I.history[I.history_cursor] << "\n";
    I.history_cursor =
        (I.history_cursor - 1 + (int)I.history.size()) % (int)I.history.size();
}

static void show_next_history_impl(Impl &I) {
    std::lock_guard<std::mutex> lk(I.hist_m);
    if (I.history.empty()) {
        std::cout << "(historial vacio)\n";
        return;
    }
    I.history_cursor = (I.history_cursor + 1) % (int)I.history.size();
    std::cout << I.history[I.history_cursor] << "\n";
}

/**
 * @brief Sugiere completions para un prefijo dado.
 * @param I   Estado del REPL (no usado actualmente; reservado para futura
 * consulta de simbolos).
 * @param pref Prefijo para el que se buscan candidatos.
 */
static void handle_complete_impl(const Impl &I, const std::string &pref) {
    // candidatos: comandos especiales + tabla + aliases definidos por el
    // usuario
    std::vector<std::string> candidates = {"exit", "help", "history",
                                           "interprete", "complete"};
    for (size_t i = 0; i < CMD_TABLE_SIZE; ++i)
        candidates.push_back(cmd_table[i].name);
    // incluir los aliases actuales como candidatos adicionales
    {
        std::lock_guard<std::mutex> lk(g_aliases.mtx);
        for (auto &[k, _] : g_aliases.map)
            candidates.push_back(k);
    }

    bool any = false;
    for (auto &c : candidates)
        if (c.rfind(pref, 0) == 0) {
            std::cout << c << " ";
            any = true;
        }
    if (!any) std::cout << "(no hay candidatos)";
    std::cout << "\n";
    (void)I;
}

// ---- helpers del bucle de lectura ----

// devuelve true si la linea parece iniciar un bloque multilinea
static bool likely_start_block(const std::string &line) {
    std::string s = line;
    auto p = s.find_first_not_of(" \t");
    if (p != std::string::npos) s = s.substr(p);
    if (s.rfind("func ", 0) == 0) return true;
    if (s.find('{') != std::string::npos) return true;
    return false;
}

// balance de llaves en una linea: +1 por '{', -1 por '}'
static int brace_delta(const std::string &line) {
    int d = 0;
    for (char c : line) {
        if (c == '{')
            ++d;
        else if (c == '}')
            --d;
    }
    return d;
}

// ---- readline interactivo con historial y flechas ----

// codigos internos para teclas especiales (fuera del rango ASCII positivo)
static constexpr int RL_UP = -1;
static constexpr int RL_DOWN = -2;
static constexpr int RL_LEFT = -3;
static constexpr int RL_RIGHT = -4;
static constexpr int RL_HOME = -5;
static constexpr int RL_END = -6;
static constexpr int RL_DEL = -7;

/**
 * @brief Lee una linea con edicion interactiva, historial con flechas y atajos
 * bash.
 *
 * Teclas soportadas:
 *   Arriba / Abajo   : navegar historial (restaura el borrador al volver a -1)
 *   Izq / Der        : mover cursor caracter a caracter
 *   Home / Fin       : inicio / fin de linea
 *   Supr             : borrar caracter bajo el cursor
 *   Backspace        : borrar caracter anterior
 *   Ctrl+A / Ctrl+E  : inicio / fin (alias de Home/Fin al estilo bash)
 *   Ctrl+K           : borrar desde cursor hasta fin de linea
 *   Ctrl+U           : borrar desde inicio hasta cursor
 *   Ctrl+W           : borrar palabra anterior
 *   Ctrl+L           : limpiar pantalla y repintar la linea actual
 *   Ctrl+C           : cancelar (activa interrupted_flag, devuelve cadena
 * vacia) Ctrl+D           : EOF en linea vacia (pone eof_out = true) Enter :
 * confirmar y devolver la linea
 *
 * @param I          Estado del REPL (historial, interrupted_flag).
 * @param prompt_str Texto del prompt ya formateado con codigos ANSI.
 * @param eof_out    Se establece a true si se detecta EOF.
 * @return           Linea introducida por el usuario (sin '\n').
 */
// ---- helper de TAB completion ----

/**
 * @brief Devuelve la lista de completions para el prefijo @p prefix.
 *
 * Si @p is_first_token es true completa con nombres de comandos y aliases;
 * si es false completa con rutas del sistema de ficheros.
 */
static std::vector<std::string>
tab_completions(const Impl &I, const std::string &prefix, bool is_first_token) {
    std::vector<std::string> out;
    if (is_first_token) {
        // completar con nombres de comandos de cmd_table
        for (size_t i = 0; i < CMD_TABLE_SIZE; ++i) {
            std::string n(cmd_table[i].name);
            if (n.rfind(prefix, 0) == 0) out.push_back(n);
        }
        // comandos especiales del REPL
        for (auto &sp :
             {"exit", "help", "history", "interprete", "complete", "source"}) {
            std::string n(sp);
            if (n.rfind(prefix, 0) == 0) out.push_back(n);
        }
        // aliases
        std::lock_guard<std::mutex> lk(const_cast<std::mutex &>(g_aliases.mtx));
        for (auto &[k, v] : g_aliases.map)
            if (k.rfind(prefix, 0) == 0) out.push_back(k);
    } else {
        // completar con rutas: separar directorio y prefijo de nombre de
        // archivo
        std::string dir_part, name_part;
        auto slash = prefix.rfind('/');
#if defined(_WIN32)
        auto bslash = prefix.rfind('\\');
        if (bslash != std::string::npos &&
            (slash == std::string::npos || bslash > slash))
            slash = bslash;
#endif
        if (slash != std::string::npos) {
            dir_part = prefix.substr(0, slash + 1);
            name_part = prefix.substr(slash + 1);
        } else {
            dir_part = "";
            name_part = prefix;
        }
        std::string search_dir = dir_part.empty() ? "." : dir_part;
        std::error_code ec;
        for (auto &entry :
             std::filesystem::directory_iterator(expand_path(search_dir), ec)) {
            std::string fname = entry.path().filename().string();
            if (fname.rfind(name_part, 0) == 0) {
                std::string candidate = dir_part + fname;
                if (entry.is_directory(ec)) candidate += "/";
                out.push_back(candidate);
            }
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

/**
 * @brief Calcula el prefijo comun mas largo de un vector de strings.
 */
static std::string common_prefix(const std::vector<std::string> &v) {
    if (v.empty()) return {};
    std::string prefix = v[0];
    for (size_t i = 1; i < v.size(); ++i) {
        size_t j = 0;
        while (j < prefix.size() && j < v[i].size() && prefix[j] == v[i][j])
            ++j;
        prefix = prefix.substr(0, j);
    }
    return prefix;
}

static std::string readline_impl(Impl &I, const std::string &prompt_str,
                                 bool &eof_out) {
    eof_out = false;

    std::string buf;       // buffer de texto actual
    size_t cur = 0;        // posicion del cursor dentro de buf
    int hist_pos = -1;     // -1 = no navegando historial
    std::string hist_save; // guarda el borrador antes de navegar historial

#if !defined(_WIN32)
    // activar modo raw: lectura caracter a caracter sin eco
    struct termios old_tios, raw_tios;
    bool tios_ok = (tcgetattr(STDIN_FILENO, &old_tios) == 0);
    if (tios_ok) {
        raw_tios = old_tios;
        raw_tios.c_lflag &= ~(unsigned)(ICANON | ECHO | IEXTEN | ISIG);
        raw_tios.c_iflag &= ~(unsigned)(IXON | ICRNL | BRKINT);
        raw_tios.c_cc[VMIN] = 1;
        raw_tios.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &raw_tios);
    }
    auto restore_tios = [&]() {
        if (tios_ok) tcsetattr(STDIN_FILENO, TCSANOW, &old_tios);
    };
#endif

    // muestra el prompt
    std::cout << prompt_str << std::flush;

    // repinta toda la linea y deja el cursor en la posicion correcta
    auto redraw = [&]() {
        // \r: volver al inicio de la linea fisica
        // prompt_str + buf: repintar contenido completo
        // \x1B[K: borrar desde cursor hasta fin de linea (limpia sobrantes)
        std::cout << "\r" << prompt_str << buf << "\x1B[K";
        size_t after = buf.size() - cur;
        if (after > 0)
            std::cout << "\x1B[" << after << "D"; // retroceder cursor
        std::cout << std::flush;
    };

    for (;;) {
        // ---- leer tecla: normalizar a codigo entero ----
        //
        // El bucle de poll permite que stop() externo desbloquee el
        // readline sin necesidad de inyectar un caracter sintetico en
        // stdin.  Cada ~50 ms despierta para chequear el flag
        // I.running; si paso a false (server_shutdown remoto, etc.)
        // salimos limpiamente devolviendo @c eof_out=true.  La latencia
        // añadida al input interactivo es indistinguible para el
        // usuario y el coste CPU es nulo (el thread duerme).
        int key;

#if defined(_WIN32)
        {
            // Espera no bloqueante via _kbhit() + Sleep.
            while (!_kbhit()) {
                if (!I.running.load(std::memory_order_acquire)) {
                    std::cout << "\n" << std::flush;
                    eof_out = true;
                    return buf;
                }
                Sleep(50);
            }
            int c = _getch();
            if (c == 0 || c == 224) { // prefijo de tecla especial en Windows
                int c2 = _getch();
                switch (c2) {
                case 72: key = RL_UP; break;    // flecha arriba
                case 80: key = RL_DOWN; break;  // flecha abajo
                case 75: key = RL_LEFT; break;  // flecha izquierda
                case 77: key = RL_RIGHT; break; // flecha derecha
                case 71: key = RL_HOME; break;  // Inicio
                case 79: key = RL_END; break;   // Fin
                case 83: key = RL_DEL; break;   // Supr
                default: key = 0; break;        // ignorar resto
                }
            } else {
                key = c;
            }
        }
#else
        {
            unsigned char c;
            ssize_t n = -1;
            // Esperar input via poll() con timeout para permitir el
            // chequeo periodico del flag I.running.
            struct pollfd pfd{STDIN_FILENO, POLLIN, 0};
            for (;;) {
                int pr = ::poll(&pfd, 1, 50); // 50 ms
                if (pr > 0 && (pfd.revents & POLLIN)) {
                    do {
                        n = ::read(STDIN_FILENO, &c, 1);
                    } while (n < 0 && errno == EINTR);
                    break;
                }
                if (!I.running.load(std::memory_order_acquire)) {
                    restore_tios();
                    std::cout << "\n" << std::flush;
                    eof_out = true;
                    return buf;
                }
                // pr == 0 (timeout) o EINTR: re-poll.
            }

            if (n <= 0) { // EOF o error irrecuperable
                restore_tios();
                std::cout << "\n" << std::flush;
                eof_out = true;
                return buf;
            }

            if (c == 0x1B) {
                // secuencia de escape: leer el resto con timeout de 100 ms
                struct termios t_nb = raw_tios;
                t_nb.c_cc[VMIN] = 0;
                t_nb.c_cc[VTIME] = 1; // unidades de 1/10 s
                tcsetattr(STDIN_FILENO, TCSANOW, &t_nb);

                unsigned char seq[4] = {0};
                int nr = (int)::read(STDIN_FILENO, seq, sizeof(seq));

                tcsetattr(STDIN_FILENO, TCSANOW, &raw_tios); // restaurar raw

                key = 0; // tecla desconocida por defecto
                if (nr >= 2 && seq[0] == '[') {
                    if (seq[1] == 'A')
                        key = RL_UP;
                    else if (seq[1] == 'B')
                        key = RL_DOWN;
                    else if (seq[1] == 'C')
                        key = RL_RIGHT;
                    else if (seq[1] == 'D')
                        key = RL_LEFT;
                    else if (seq[1] == 'H')
                        key = RL_HOME;
                    else if (seq[1] == 'F')
                        key = RL_END;
                    else if (seq[1] == '1' && nr >= 3 && seq[2] == '~')
                        key = RL_HOME;
                    else if (seq[1] == '3' && nr >= 3 && seq[2] == '~')
                        key = RL_DEL;
                    else if (seq[1] == '4' && nr >= 3 && seq[2] == '~')
                        key = RL_END;
                }
                // ESC solitario o secuencia desconocida: ignorar
            } else {
                key = (int)c;
            }
        }
#endif

        // ---- procesar tecla ----

        // Enter: confirmar y devolver
        if (key == '\r' || key == '\n') {
#if !defined(_WIN32)
            restore_tios();
#endif
            std::cout << "\n" << std::flush;
            return buf;
        }

        // Ctrl+C: cancelar linea actual
        if (key == 3) {
            buf.clear();
            cur = 0;
            std::cout << "^C\n" << std::flush;
#if !defined(_WIN32)
            restore_tios();
#endif
            I.interrupted_flag = true;
            return {};
        }

        // Ctrl+D: EOF en linea vacia
        if (key == 4 && buf.empty()) {
#if !defined(_WIN32)
            restore_tios();
#endif
            std::cout << "\n" << std::flush;
            eof_out = true;
            return {};
        }

        // Ctrl+A: inicio de linea
        if (key == 1) {
            cur = 0;
            redraw();
            continue;
        }
        // Ctrl+E: fin de linea
        if (key == 5) {
            cur = buf.size();
            redraw();
            continue;
        }
        // Ctrl+K: borrar desde cursor hasta fin
        if (key == 11) {
            buf.erase(cur);
            redraw();
            continue;
        }
        // Ctrl+U: borrar desde inicio hasta cursor
        if (key == 21) {
            buf.erase(0, cur);
            cur = 0;
            redraw();
            continue;
        }
        // Ctrl+W: borrar palabra anterior
        if (key == 23) {
            if (cur > 0) {
                size_t e = cur;
                while (cur > 0 && buf[cur - 1] == ' ')
                    --cur;
                while (cur > 0 && buf[cur - 1] != ' ')
                    --cur;
                buf.erase(cur, e - cur);
                redraw();
            }
            continue;
        }
        // Ctrl+L: limpiar pantalla y repintar
        if (key == 12) {
            clear_screen();
            std::cout << prompt_str << buf;
            size_t a = buf.size() - cur;
            if (a > 0) std::cout << "\x1B[" << a << "D";
            std::cout << std::flush;
            continue;
        }

        // Backspace (127 POSIX, 8 Windows)
        if (key == 127 || key == 8) {
            if (cur > 0) {
                buf.erase(--cur, 1);
                redraw();
            }
            continue;
        }

        // flechas y teclas de navegacion
        if (key == RL_LEFT) {
            if (cur > 0) {
                --cur;
                redraw();
            }
            continue;
        }
        if (key == RL_RIGHT) {
            if (cur < buf.size()) {
                ++cur;
                redraw();
            }
            continue;
        }
        if (key == RL_HOME) {
            cur = 0;
            redraw();
            continue;
        }
        if (key == RL_END) {
            cur = buf.size();
            redraw();
            continue;
        }
        if (key == RL_DEL) {
            if (cur < buf.size()) {
                buf.erase(cur, 1);
                redraw();
            }
            continue;
        }

        // flecha arriba: retroceder en historial
        if (key == RL_UP) {
            std::lock_guard<std::mutex> lk(I.hist_m);
            if (I.history.empty()) continue;
            if (hist_pos == -1) {
                hist_save = buf; // guardar borrador actual
                hist_pos = (int)I.history.size() -
                           1; // apuntar a la entrada mas reciente
            } else if (hist_pos > 0) {
                --hist_pos;
            }
            buf = I.history[hist_pos];
            cur = buf.size();
            redraw();
            continue;
        }

        // flecha abajo: avanzar en historial (o restaurar borrador)
        if (key == RL_DOWN) {
            if (hist_pos == -1) continue; // ya estamos en el borrador
            std::lock_guard<std::mutex> lk(I.hist_m);
            ++hist_pos;
            if (hist_pos < (int)I.history.size()) {
                buf = I.history[hist_pos];
            } else {
                hist_pos = -1;   // salir del historial
                buf = hist_save; // restaurar el borrador guardado
            }
            cur = buf.size();
            redraw();
            continue;
        }

        // TAB: completar comando o ruta
        if (key == 9) {
            // determinar si estamos completando el primer token o una ruta
            std::string before_cur = buf.substr(0, cur);
            auto first_space = before_cur.find(' ');
            bool is_first = (first_space == std::string::npos);
            std::string prefix =
                is_first ? before_cur
                         : before_cur.substr(before_cur.rfind(' ') + 1);
            auto candidates = tab_completions(I, prefix, is_first);
            if (candidates.empty()) {
                // sin completions: pitido visual (blink)
                std::cout << "\x07" << std::flush;
            } else if (candidates.size() == 1) {
                // completar directamente: reemplazar prefijo con el unico
                // candidato
                buf.erase(cur - prefix.size(), prefix.size());
                cur -= prefix.size();
                buf.insert(cur, candidates[0]);
                cur += candidates[0].size();
                redraw();
            } else {
                // varios candidatos: extender al prefijo comun y mostrar lista
                std::string cp = common_prefix(candidates);
                if (cp.size() > prefix.size()) {
                    // hay extension: rellenar hasta el prefijo comun
                    buf.erase(cur - prefix.size(), prefix.size());
                    cur -= prefix.size();
                    buf.insert(cur, cp);
                    cur += cp.size();
                    redraw();
                } else {
                    // mostrar lista debajo del prompt
                    std::cout << "\n";
                    for (auto &c : candidates)
                        std::cout << ansi::c(ansi::BR_CYAN) << c
                                  << ansi::c(ansi::RESET) << "  ";
                    std::cout << "\n";
                    redraw();
                }
            }
            continue;
        }

        // Ctrl+R: busqueda incremental inversa en historial
        if (key == 18) {
            std::string search;
            int match_idx = -1;
            // sub-bucle de busqueda inversa
            for (;;) {
                // repintar prompt de busqueda
                std::string rprompt = std::string(ansi::c(ansi::DIM)) +
                                      "(reverse-search)`" + search +
                                      "': " + ansi::c(ansi::RESET);
                std::cout << "\r" << rprompt;
                if (match_idx >= 0) {
                    std::lock_guard<std::mutex> lk(I.hist_m);
                    std::cout << I.history[match_idx];
                }
                std::cout << "\x1B[K" << std::flush;

                // leer tecla para la busqueda
                int k2;
#if defined(_WIN32)
                k2 = _getch();
                if (k2 == 0 || k2 == 224) {
                    _getch();
                    k2 = 0;
                }
#else
                unsigned char c2;
                ssize_t nr2;
                do {
                    nr2 = ::read(STDIN_FILENO, &c2, 1);
                } while (nr2 < 0 && errno == EINTR);
                k2 = (nr2 <= 0) ? 4 : (int)c2;
#endif
                if (k2 == 18) {
                    // Ctrl+R de nuevo: buscar siguiente coincidencia anterior
                    if (!search.empty() && match_idx > 0) {
                        std::lock_guard<std::mutex> lk(I.hist_m);
                        for (int j = match_idx - 1; j >= 0; --j) {
                            if (I.history[j].find(search) !=
                                std::string::npos) {
                                match_idx = j;
                                break;
                            }
                        }
                    }
                } else if (k2 == 127 || k2 == 8) {
                    // borrar ultimo caracter de la busqueda
                    if (!search.empty()) {
                        search.pop_back();
                        // re-buscar desde el final
                        match_idx = -1;
                        std::lock_guard<std::mutex> lk(I.hist_m);
                        for (int j = (int)I.history.size() - 1; j >= 0; --j) {
                            if (I.history[j].find(search) !=
                                std::string::npos) {
                                match_idx = j;
                                break;
                            }
                        }
                    }
                } else if (k2 == '\r' || k2 == '\n') {
                    // confirmar: cargar la entrada encontrada en el buffer
                    if (match_idx >= 0) {
                        std::lock_guard<std::mutex> lk(I.hist_m);
                        buf = I.history[match_idx];
                        cur = buf.size();
                    }
                    std::cout << "\n" << std::flush;
                    break;
                } else if (k2 == 7 || k2 == 27) {
                    // Ctrl+G o ESC: cancelar busqueda, restaurar buffer
                    // original
                    std::cout << "\n" << std::flush;
                    break;
                } else if (k2 >= 32 && k2 <= 126) {
                    // anadir caracter a la cadena de busqueda
                    search += static_cast<char>(k2);
                    match_idx = -1;
                    std::lock_guard<std::mutex> lk(I.hist_m);
                    for (int j = (int)I.history.size() - 1; j >= 0; --j) {
                        if (I.history[j].find(search) != std::string::npos) {
                            match_idx = j;
                            break;
                        }
                    }
                } else {
                    // cualquier otra tecla: salir de busqueda
                    if (match_idx >= 0) {
                        std::lock_guard<std::mutex> lk(I.hist_m);
                        buf = I.history[match_idx];
                        cur = buf.size();
                    }
                    std::cout << "\n" << std::flush;
                    break;
                }
            }
            redraw();
            continue;
        }

        // caracter imprimible (ASCII basico)
        if (key >= 32 && key <= 126) {
            buf.insert(cur++, 1, static_cast<char>(key));
            redraw();
        }
    } // for(;;)
}

// ---- VestaViewManager ----

VestaViewManager::VestaViewManager(Config cfg) {
    impl_ = new Impl(std::move(cfg));
}

VestaViewManager::~VestaViewManager() {
    stop();
    delete impl_;
    impl_ = nullptr;
}

void VestaViewManager::set_execute_callback(
    std::function<void(const std::string &)> cb) {
    std::lock_guard lk(impl_->cb_m);
    impl_->vm_execute_cb = std::move(cb);
}

/**
 * @brief Bucle principal del REPL: lee lineas, despacha comandos via cmd_table.
 *
 * Flujo por iteracion:
 *   1. Leer linea (con soporte de bloque multilinea).
 *   2. Trim y verificar comandos especiales (exit, help, history, !N, :prev,
 * :next, interprete, complete).
 *   3. Separar primer token (nombre del comando) del resto (args).
 *   4. Buscar en cmd_table y llamar al handler si hay coincidencia.
 *   5. Si no hay coincidencia, encolar para el callback de VM.
 */
void VestaViewManager::run() {
    if (impl_->running) return;
    impl_->running = true;

    global_interrupt_ptr = &impl_->interrupted_flag;
    std::signal(SIGINT, global_sigint_handler);

    ansi::init(); // habilitar colores si el terminal lo soporta

    // anclar ficheros de estado al directorio del ejecutable (evita que cd los
    // mueva)
    {
        std::string exe_dir = std::filesystem::path(fs::get_executable_path())
                                  .parent_path()
                                  .string();
        auto fix_rel = [&](std::string &p) {
            if (!std::filesystem::path(p).is_absolute()) p = exe_dir + "/" + p;
        };
        fix_rel(g_env_file);
        fix_rel(impl_->cfg.history_file);
        fix_rel(impl_->cfg.aliases_file);
    }

    // sincronizar la ruta del fichero de aliases con la configuracion
    g_aliases.file = impl_->cfg.aliases_file;

    // exponer impl_ para command_set y otras funciones que necesitan acceso al
    // cfg
    g_current_impl = impl_;

    load_history_impl(*impl_);
    aliases_load(g_aliases);
    env_load_file(
        g_env_file); // cargar variables de entorno persistentes al arrancar

    // ejecutar el script de inicio si existe (~/.vestarc o ./vm_init.vel/.vsh)
    {
        // ejecuta linea a linea un fichero de comandos REPL
        auto run_startup_repl = [](const std::string &path) {
            std::ifstream f(path);
            if (!f) return false;
            std::string line;
            while (std::getline(f, line))
                dispatch_table_cmd(line);
            return true;
        };
        // ejecuta un fichero VestaShell .vsh
        auto run_startup_vsh = [](const std::string &path) {
            std::ifstream f(path);
            if (!f) return false;
            try {
                get_vsh_interp().exec_file(path);
            } catch (...) {
            }
            return true;
        };
        // prioridad: vm_init.vsh > vm_init.vel > ~/.vestarc.vsh > ~/.vestarc
        bool loaded = run_startup_vsh("vm_init.vsh");
        if (!loaded) loaded = run_startup_repl("vm_init.vel");
        if (!loaded) {
            const char *home = std::getenv("HOME");
#if defined(_WIN32)
            if (!home) home = std::getenv("USERPROFILE");
#endif
            if (home) {
                std::string base = std::string(home);
                if (!run_startup_vsh(base + "/.vestarc.vsh"))
                    run_startup_repl(base + "/.vestarc");
            }
        }
    }

    impl_->worker_thread = std::thread(worker_loop_impl, std::ref(*impl_));

    while (impl_->running) {
        // construir el prompt dinamico como cadena ANSI (lo pinta
        // readline_impl)
        std::string prompt_str;
        {
            std::string cwd_name;
            try {
                auto cwd = std::filesystem::current_path();
                cwd_name = cwd.filename().string();
                if (cwd_name.empty())
                    cwd_name = cwd.root_name().string() +
                               cwd.root_directory().string();
            } catch (...) {
                cwd_name = "?";
            }

            prompt_str = std::string(ansi::c(ansi::BOLD)) +
                         ansi::c(ansi::BR_CYAN) + "vesta" +
                         ansi::c(ansi::RESET) + ansi::c(ansi::DIM) + " [" +
                         ansi::c(ansi::RESET) + ansi::c(ansi::BR_GREEN) +
                         cwd_name + ansi::c(ansi::RESET) + ansi::c(ansi::DIM) +
                         "]" + ansi::c(ansi::RESET) + ansi::c(ansi::BOLD) +
                         "> " + ansi::c(ansi::RESET);
        }

        // leer linea con edicion interactiva y navegacion de historial
        bool eof_flag = false;
        std::string line = readline_impl(*impl_, prompt_str, eof_flag);
        if (eof_flag) {
            std::cout << "\n";
            break;
        }
        if (impl_->interrupted_flag.exchange(false)) continue; // Ctrl+C

        // --- acumulacion multilinea ---
        std::string full = line;
        const std::string &term = impl_->cfg.multiline_end;

        if (full.size() >= term.size() &&
            full.substr(full.size() - term.size()) == term) {
            // la linea ya tiene el terminador: quitar y usar tal cual
            full = full.substr(0, full.size() - term.size());
        } else if (likely_start_block(full)) {
            int balance = brace_delta(full);
            while (balance > 0) {
                bool more_eof = false;
                std::string more = readline_impl(*impl_, "... ", more_eof);
                if (more_eof || impl_->interrupted_flag.exchange(false)) {
                    full.clear();
                    break;
                }
                if (more.size() >= term.size() &&
                    more.substr(more.size() - term.size()) == term) {
                    std::string part =
                        more.substr(0, more.size() - term.size());
                    full += "\n" + part;
                    balance += brace_delta(part);
                    break;
                } else {
                    full += "\n" + more;
                    balance += brace_delta(more);
                }
            }
        }

        // --- trim ---
        auto s0 = full.find_first_not_of(" \t\r\n");
        if (s0 == std::string::npos) continue;
        auto s1 = full.find_last_not_of(" \t\r\n");
        std::string cmd = full.substr(s0, s1 - s0 + 1);

        // --- comandos especiales (no despachables por tabla) ---
        if (cmd == "exit") {
            add_history_entry_impl(*impl_, cmd);
            break;
        }

        if (cmd == "help") {
            print_help_impl(*impl_);
            continue;
        }
        if (cmd == "history") {
            print_history_impl(*impl_);
            continue;
        }
        if (!cmd.empty() && cmd[0] == '!') {
            handle_history_exec_impl(*impl_, cmd);
            continue;
        }
        if (cmd == ":prev") {
            show_prev_history_impl(*impl_);
            continue;
        }
        if (cmd == ":next") {
            show_next_history_impl(*impl_);
            continue;
        }
        if (cmd == "interprete") {
            VestaInterprete interp{};
            interp.run_interprete();
            continue;
        }

        // --- despacho via cmd_table ---
        // separar primer token (nombre del comando) del resto (args)
        auto sp = cmd.find(' ');
        std::string cmd_name =
            (sp == std::string::npos) ? cmd : cmd.substr(0, sp);
        std::string cmd_args =
            (sp == std::string::npos) ? std::string{} : cmd.substr(sp + 1);

        // expandir aliases (maximo 16 niveles para evitar recursion infinita)
        // patron: "alias ls='ls -la'" -> cmd_name="ls" se sustituye por "ls
        // -la" autoreferencia ("alias ls='ls -l'"): se detecta comparando el
        // primer token de la expansion con el nombre del alias para romper el
        // ciclo
        for (int _alias_depth = 0; _alias_depth < 16; ++_alias_depth) {
            std::string expanded;
            {
                std::lock_guard<std::mutex> lk(g_aliases.mtx);
                auto it = g_aliases.map.find(cmd_name);
                if (it == g_aliases.map.end())
                    break; // no hay alias para este nombre
                expanded = it->second;
            }
            // si la expansion empieza con el mismo nombre, es autoreferencia:
            // parar para no entrar en bucle infinito (permite "alias ls='ls
            // -l'")
            auto exp_words = split_words(expanded);
            if (!exp_words.empty() && exp_words[0] == cmd_name) break;
            // reconstruir cmd_name, cmd_args y cmd con la expansion
            // cmd debe reflejar la expansion para que el fallback al worker
            // envie el comando expandido, no el nombre del alias original
            std::string full =
                cmd_args.empty() ? expanded : expanded + " " + cmd_args;
            auto sp2 = full.find(' ');
            cmd_name = (sp2 == std::string::npos) ? full : full.substr(0, sp2);
            cmd_args = (sp2 == std::string::npos) ? std::string{}
                                                  : full.substr(sp2 + 1);
            cmd = full; // sincronizar cmd para el worker
        }

        // complete es especial porque necesita acceso a Impl
        if (cmd_name == "complete") {
            if (cmd_args.empty()) {
                std::cout << "Uso: complete <prefijo>\n";
            } else {
                handle_complete_impl(*impl_, cmd_args);
            }
            continue;
        }

        // buscar en la tabla de comandos
        bool handled = false;
        for (size_t i = 0; i < CMD_TABLE_SIZE; ++i) {
            if (cmd_name == cmd_table[i].name) {
                cmd_table[i].fn(cmd_args);
                handled = true;
                break;
            }
        }

        // anadir al historial siempre
        add_history_entry_impl(*impl_, cmd);

        if (!handled) {
            // comportamiento bash-like: ejecutar como comando de shell del SO.
            // Los comandos de VM (run, exec, build...) estan en cmd_table y ya
            // se despachan arriba. Lo que llega aqui es aliases expandidos a
            // comandos externos o comandos del SO sin registrar en la tabla.
            std::string out;
            try {
                out = execute_shell_command(cmd);
            } catch (const std::exception &e) {
                out = std::string(ansi::c(ansi::BR_RED)) + e.what() +
                      ansi::c(ansi::RESET);
            }
            if (!out.empty()) {
                // quitar el "[exit code: N]" al final si el codigo es 0
                auto ec_pos = out.rfind("\n[exit code: 0]");
                if (ec_pos != std::string::npos) out = out.substr(0, ec_pos);
                std::cout << out;
                if (!out.empty() && out.back() != '\n') std::cout << "\n";
            }
        }
    }

    stop();
}

void VestaViewManager::stop() {
    // Compare-exchange atomico para serializar el shutdown cuando
    // stop() se llama desde varios hilos a la vez (caso server-mode:
    // el watcher remoto + el propio run() al terminar el bucle).
    bool expected = true;
    if (!impl_->running.compare_exchange_strong(expected, false)) return;
    cmd_queue_close_impl(*impl_);
    if (impl_->worker_thread.joinable()) impl_->worker_thread.join();
    save_history_impl(*impl_);
    env_save_file(g_env_file); // persistir entorno al cerrar
    g_current_impl = nullptr;
    global_interrupt_ptr = nullptr;
    std::signal(SIGINT, SIG_DFL);
}

/* =====================================================================
 * execute_repl_line: enruta una linea hacia el dispatcher del REPL
 * local y devuelve la salida capturada.
 *
 * Por que existe: el debugger TCP (servidor persistente) tiene un
 * comando @c repl_exec que permite al cliente remoto enviar lineas
 * al MISMO motor que ejecuta el prompt `vesta>` local.  Asi el
 * cliente Electron no tiene que reimplementar `ps`, `regs`, `mem`,
 * `build`, `disasm`, etc.: enruta y muestra lo que el local
 * imprimiria.
 *
 * Concurrencia: redirigir @c std::cout es un cambio global del
 * proceso; usamos un mutex para serializar entre clientes
 * remotos.  Los comandos del REPL no son CPU-bound, asi que la
 * contencion es despreciable.
 * ===================================================================== */
std::string execute_repl_line(const std::string &line) {
    static std::mutex repl_mu;
    std::lock_guard<std::mutex> lk(repl_mu);

    // Trim defensivo de la linea para los matches de comandos
    // especiales (help, history, etc.).
    auto trim = [](const std::string &s) -> std::string {
        auto a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) return "";
        auto b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    };
    const std::string trimmed = trim(line);

    // Capturar stdout y stderr a una ostringstream.  Restauramos el
    // rdbuf ORIGINAL siempre (incluso si dispatch_table_cmd lanza).
    std::ostringstream captured;
    std::streambuf *old_out = std::cout.rdbuf(captured.rdbuf());
    std::streambuf *old_err = std::cerr.rdbuf(captured.rdbuf());

    bool handled = false;
    std::string err_msg;
    try {
        // Comandos ESPECIALES del REPL que no estan en cmd_table:
        // los manejamos aqui imprimiendo a stdout (que ya esta
        // redirigido al buffer).
        if (trimmed == "help" || trimmed == "?") {
            std::cout << "Comandos disponibles via repl_exec:\n";
            for (size_t i = 0; i < CMD_TABLE_SIZE; ++i) {
                std::cout << "  " << std::left << std::setw(40)
                          << cmd_table[i].usage << "  " << cmd_table[i].brief
                          << "\n";
            }
            std::cout << "\nNota: los comandos interactivos del REPL "
                         "local (`exit`, `history`, `interprete`) NO se "
                         "enrutan al cliente remoto.\n";
            handled = true;
        } else if (trimmed == "history" || trimmed == "exit" ||
                   trimmed == "interprete" || trimmed.rfind("!", 0) == 0) {
            std::cout << "comando interactivo '" << trimmed
                      << "' no se enruta al cliente remoto.\n";
            handled = true;
        } else {
            handled = dispatch_table_cmd(line);
        }
    } catch (const std::exception &e) {
        err_msg = std::string("\nexcepcion: ") + e.what();
    } catch (...) {
        err_msg = "\nexcepcion desconocida";
    }

    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);

    std::string out = captured.str();
    if (!handled && out.empty()) {
        // El dispatcher no reconocio la linea (comando no
        // registrado) y nadie escribio nada al stdout capturado.
        out = "comando no reconocido por el REPL local: '" + line +
              "' -- prueba con 'help'.";
    }
    if (!err_msg.empty()) out += err_msg;
    return out;
}
} // namespace cli
