/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file debugger.cpp
 * @brief Implementacion del servidor de depuracion TCP de VestaVM.
 *
 * Protocolo de framing:
 *   [uint32_t len LE (4 bytes)][payload JSON UTF-8 (len bytes)]
 *
 * El servidor acepta multiples clientes simultaneos.  Cada cliente se
 * atiende en un hilo independiente.  Las operaciones sobre breakpoints
 * y estados de proceso estan protegidas por mutex.
 *
 * El metodo on_before_exec() es el punto de intercepcion critico: se
 * llama desde el hilo del scheduler antes de cada instruccion.  Su
 * implementacion usa un atomic<bool> (any_bp_) como fast path para el
 * caso sin breakpoints, evitando contention de mutex en produccion.
 *
 * Plataformas soportadas:
 *   - POSIX (Linux, macOS): sockets BSD via sys/socket.h
 *   - Windows: Winsock2 via winsock2.h
 *     La abstraccion se hace con las macros SOCK_T y CLOSE_SOCK.
 */

#include "util/env_flags.h"
#include "debug/debugger.h"
#include "debug/auth.h"
#include "runtime/proceso_runtime.h"
#include "runtime/runtime.h"
#include "runtime/manager_runtime.h"
#include "runtime/scheduler.h"
#include "loader/loader.h"
#include "emmit/emmit_decl.h"
#include "runtime/decode_instruction.h"
#include "loader/oop_types.h"
#include "cli/runtime_api_commands.h"
#include "cli/cli.h"

#include <cstring>
#include <cstdio>
#include <cstdlib> // std::getenv para diagnostico VESTA_DBG_BP_TRACE
#include <sstream>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <unordered_set>

// Tablas externas de decodificacion (definidas en
// src/runtime/decode_table.cpp).
namespace runtime {
extern InstrFormat decode_table_primary[0x100];
extern InstrFormat decode_table_extended[0x100];
} // namespace runtime

/* =========================================================================
 * Abstraccion de sockets multiplataforma
 * ========================================================================= */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET SOCK_T;
#define CLOSE_SOCK(s) closesocket(s)
#define INVALID_SOCK INVALID_SOCKET
#define SOCK_ERR SOCKET_ERROR
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
typedef int SOCK_T;
#define CLOSE_SOCK(s) ::close(s)
#define INVALID_SOCK (-1)
#define SOCK_ERR (-1)
#endif

namespace debug {

/* =====================================================================
 * Flag global de apagado del servidor persistente.
 *
 * En modo --server-mode, main.cpp registra un puntero a su atomic<bool>
 * g_server_running aqui via set_server_shutdown_flag().  El comando
 * SERVER_SHUTDOWN del protocolo lo pone a false para que el bucle de
 * espera del main termine y la VM se cierre limpiamente sin necesidad
 * de Ctrl+C en el lado del servidor.  Si el puntero es nullptr (el
 * caso por defecto fuera de --server-mode), el comando responde con
 * error explicativo.
 * ===================================================================== */
static std::atomic<bool> *g_server_shutdown_flag = nullptr;

void set_server_shutdown_flag(std::atomic<bool> *flag) {
    g_server_shutdown_flag = flag;
}

/* =====================================================================
 * Marca de tiempo de inicio del servidor (para SERVER_INFO::uptime).
 * Se actualiza la primera vez que Debugger::start() se llama.
 * ===================================================================== */
static std::chrono::steady_clock::time_point g_server_start_time =
    std::chrono::steady_clock::now();

/* =====================================================================
 * Codificacion / decodificacion base64 (sin dependencias externas).
 *
 * El protocolo de file-transfer empaqueta el contenido binario como
 * base64 dentro del JSON.  Se eligio base64 frente a un frame binario
 * dedicado porque (a) preserva el framing actual length-prefix +
 * JSON, (b) sobrevive a clientes que escriben JSON pretty-printed y
 * (c) la sobrecarga del ~33% es aceptable para archivos < 16 MB que
 * son el caso esperado (codigo, .velb pequenos, configuracion).
 * ===================================================================== */

static const char *B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64_encode(const uint8_t *data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) |
                     uint32_t(data[i + 2]);
        out.push_back(B64_CHARS[(n >> 18) & 0x3F]);
        out.push_back(B64_CHARS[(n >> 12) & 0x3F]);
        out.push_back(B64_CHARS[(n >> 6) & 0x3F]);
        out.push_back(B64_CHARS[n & 0x3F]);
        i += 3;
    }
    // padding del resto (0, 1 o 2 bytes restantes)
    if (i < len) {
        uint32_t n = uint32_t(data[i]) << 16;
        if (i + 1 < len) n |= uint32_t(data[i + 1]) << 8;
        out.push_back(B64_CHARS[(n >> 18) & 0x3F]);
        out.push_back(B64_CHARS[(n >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? B64_CHARS[(n >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

static int b64_char_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/**
 * @brief Decodifica una cadena base64 a bytes.
 *
 * Tolerante a whitespace (espacios y saltos de linea) que algunos
 * clientes incluyen al formatear el JSON.  Devuelve false si encuentra
 * caracteres invalidos distintos del padding @c '='.
 */
static bool b64_decode(const std::string &in, std::vector<uint8_t> &out) {
    out.clear();
    out.reserve((in.size() / 4) * 3);
    uint32_t buf = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || std::isspace(static_cast<unsigned char>(c))) continue;
        int v = b64_char_index(c);
        if (v < 0) return false;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return true;
}

/* =====================================================================
 * Resolucion segura de rutas contra el sandbox @c server_root_.
 *
 * Si @p root es vacio se permite cualquier ruta (modo back-compat),
 * pero la ruta debe seguir siendo absoluta para no depender del cwd
 * del proceso VM (que es impredecible cuando se invoca como servicio).
 *
 * Si @p root no es vacio:
 *   1. La ruta del cliente se trata como RELATIVA al root.  Cualquier
 *      prefijo absoluto del cliente se descarta y se reanchora al root.
 *   2. Tras canonicalizar (collapse de ".." y links) se verifica que
 *      el resultado siga dentro del root.  Si no, se rechaza.
 *
 * Devuelve true si la ruta resultante (@p out) es segura.  En caso
 * de error escribe el motivo en @p err_msg.
 * ===================================================================== */
static bool resolve_sandbox_path(const std::string &root,
                                 const std::string &requested,
                                 std::filesystem::path &out,
                                 std::string &err_msg) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (root.empty()) {
        // Sin sandbox: aceptamos la ruta tal cual, pero exigimos algo no vacio.
        if (requested.empty()) {
            err_msg = "path vacio";
            return false;
        }
        out = fs::weakly_canonical(fs::path(requested), ec);
        if (ec) out = fs::path(requested);
        return true;
    }
    fs::path root_path = fs::weakly_canonical(fs::path(root), ec);
    if (ec) root_path = fs::path(root);

    // Reanclar la ruta del cliente en el root, eliminando cualquier
    // raiz absoluta para que no se pueda especificar "C:/Windows".
    fs::path rel = fs::path(requested);
    if (rel.is_absolute()) {
        // tomar solo el "relative_path()" para colapsar el drive/root
        rel = rel.relative_path();
    }
    fs::path combined = root_path / rel;
    fs::path canon = fs::weakly_canonical(combined, ec);
    if (ec) canon = combined;

    // Verificacion de contencion: canon debe empezar con root_path.
    auto root_it = root_path.begin();
    auto canon_it = canon.begin();
    for (; root_it != root_path.end() && canon_it != canon.end();
         ++root_it, ++canon_it) {
        if (*root_it != *canon_it) {
            err_msg = "path fuera del sandbox";
            return false;
        }
    }
    if (root_it != root_path.end()) {
        err_msg = "path fuera del sandbox";
        return false;
    }

    out = canon;
    return true;
}

/* =====================================================================
 * Inicializacion de Winsock (no-op en POSIX)
 * ===================================================================== */

#ifdef _WIN32
/**
 * @brief RAII para inicializar y finalizar Winsock en Windows.
 */
struct WinsockInit {
    WinsockInit() {
        WSADATA wd;
        WSAStartup(MAKEWORD(2, 2), &wd);
    }
    ~WinsockInit() { WSACleanup(); }
};
static WinsockInit g_winsock_init;
#endif

/* =====================================================================
 * Serializacion JSON minima (sin dependencias externas)
 *
 * Para el protocolo de depuracion usamos una serializacion JSON manual
 * simple: suficiente para los mensajes del protocolo sin vincular una
 * libreria externa.
 * ===================================================================== */

/**
 * @brief Escapa una cadena para incluirla en JSON.
 * @param s Cadena de entrada.
 * @return Cadena con backslashes y comillas escapados.
 */
static std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
            if (c < 0x20) {
                // Control char: escape como \u00XX (JSON exige
                // que cualquier U+0000..U+001F este escapado).
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
            break;
        }
    }
    return out;
}

/**
 * @brief Extrae el valor de un campo JSON simple: {"key": "value"}.
 *
 * Implementacion basica para el protocolo: busca la clave y extrae
 * el valor entre comillas o numerico que le sigue.
 *
 * @param json  Cadena JSON.
 * @param key   Nombre del campo (sin comillas).
 * @return Valor extraido como cadena, o "" si no se encuentra.
 */
static std::string json_get(const std::string &json, const std::string &key) {
    // buscar "key":
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    // saltar espacios y ':'
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':'))
        pos++;
    if (pos >= json.size()) return "";
    if (json[pos] == '"') {
        // valor de cadena
        pos++;
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return json.substr(pos);
        return json.substr(pos, end - pos);
    }
    // valor numerico o booleano: hasta ',', '}' o whitespace
    size_t end = json.find_first_of(",} \t\n", pos);
    return json.substr(pos, end == std::string::npos ? std::string::npos
                                                     : end - pos);
}

/* =====================================================================
 * debug_cmd_parse
 * ===================================================================== */

/**
 * @brief Convierte el nombre de un comando a DebugCmd.
 */
DebugCmd debug_cmd_parse(const std::string &name) {
    static const struct {
        const char *n;
        DebugCmd c;
    } table[] = {
        {"attach", DebugCmd::ATTACH},
        {"detach", DebugCmd::DETACH},
        {"list_procs", DebugCmd::LIST_PROCS},
        {"set_break", DebugCmd::SET_BREAK},
        {"del_break", DebugCmd::DEL_BREAK},
        {"list_breaks", DebugCmd::LIST_BREAKS},
        {"set_break_src", DebugCmd::SET_BREAK_SRC},
        {"info_source", DebugCmd::INFO_SOURCE},
        {"gc_stats", DebugCmd::GC_STATS},
        {"gc_handles", DebugCmd::GC_HANDLES},
        {"gc_inspect", DebugCmd::GC_INSPECT},
        {"flags", DebugCmd::FLAGS},
        {"fregs", DebugCmd::FREGS},
        {"dump_stack", DebugCmd::DUMP_STACK},
        {"frame_info", DebugCmd::FRAME_INFO},
        {"backtrace", DebugCmd::BACKTRACE},
        {"continue", DebugCmd::CONTINUE},
        {"step", DebugCmd::STEP},
        {"next", DebugCmd::NEXT},
        {"registers", DebugCmd::REGISTERS},
        {"memory", DebugCmd::MEMORY},
        {"stack", DebugCmd::STACK},
        {"info_proc", DebugCmd::INFO_PROC},
        {"eval", DebugCmd::EVAL},
        {"pause", DebugCmd::PAUSE},
        {"disasm", DebugCmd::DISASM},
        {"locals", DebugCmd::LOCALS},
        {"gc_run", DebugCmd::GC_RUN},
        {"step_out", DebugCmd::STEP_OUT},
        {"finish", DebugCmd::STEP_OUT},
        {"step_until", DebugCmd::STEP_UNTIL},
        {"until", DebugCmd::STEP_UNTIL},
        {"set_watch", DebugCmd::SET_WATCH},
        {"del_watch", DebugCmd::DEL_WATCH},
        {"list_watches", DebugCmd::LIST_WATCHES},
        {"trace_msgs", DebugCmd::TRACE_MSGS},
        {"break_mon", DebugCmd::BREAK_MON},
        {"load_velb", DebugCmd::LOAD_VELB},
        {"kill_proc", DebugCmd::KILL_PROC},
        {"server_info", DebugCmd::SERVER_INFO},
        {"server_shutdown", DebugCmd::SERVER_SHUTDOWN},
        {"auth_login", DebugCmd::AUTH_LOGIN},
        {"auth_logout", DebugCmd::AUTH_LOGOUT},
        {"auth_whoami", DebugCmd::AUTH_WHOAMI},
        {"auth_create_user", DebugCmd::AUTH_CREATE_USER},
        {"auth_delete_user", DebugCmd::AUTH_DELETE_USER},
        {"auth_list_users", DebugCmd::AUTH_LIST_USERS},
        {"auth_change_pass", DebugCmd::AUTH_CHANGE_PASS},
        {"fs_write", DebugCmd::FS_WRITE},
        {"fs_read", DebugCmd::FS_READ},
        {"fs_list", DebugCmd::FS_LIST},
        {"fs_stat", DebugCmd::FS_STAT},
        {"fs_delete", DebugCmd::FS_DELETE},
        {"fs_mkdir", DebugCmd::FS_MKDIR},
        {"fs_rename", DebugCmd::FS_RENAME},
        {"load_velb_bytes", DebugCmd::LOAD_VELB_BYTES},
        {"repl_exec", DebugCmd::REPL_EXEC},
        {"repl", DebugCmd::REPL_EXEC},
        {"mem_write", DebugCmd::MEM_WRITE},
    };
    for (const auto &e : table) {
        if (name == e.n) return e.c;
    }
    return DebugCmd::UNKNOWN;
}

/* =====================================================================
 * Debugger: constructor / destructor
 * ===================================================================== */

Debugger::Debugger(runtime::VM &vm)
    : vm_(vm), port_(DBG_DEFAULT_PORT), server_fd_(INVALID_SOCK) {}

Debugger::~Debugger() {
    stop();
}

/* =====================================================================
 * start / stop
 * ===================================================================== */

/**
 * @brief Inicia el servidor TCP de depuracion.
 */
bool Debugger::start(uint16_t port) {
    if (running_.load()) return true; // ya activo

    port_ = port;

    // crear socket de escucha
    server_fd_ = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (server_fd_ == static_cast<int>(INVALID_SOCK)) return false;

    // SO_REUSEADDR para reiniciar rapido
    int opt = 1;
    ::setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char *>(&opt), sizeof(opt));

    // desactivar Nagle para baja latencia en mensajes pequenos
    ::setsockopt(server_fd_, IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char *>(&opt), sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (::bind(server_fd_, reinterpret_cast<struct sockaddr *>(&addr),
               sizeof(addr)) == SOCK_ERR) {
        CLOSE_SOCK(server_fd_);
        server_fd_ = static_cast<int>(INVALID_SOCK);
        return false;
    }
    if (::listen(server_fd_, 4) == SOCK_ERR) {
        CLOSE_SOCK(server_fd_);
        server_fd_ = static_cast<int>(INVALID_SOCK);
        return false;
    }

    running_.store(true);
    accept_thread_ = std::thread(&Debugger::accept_loop, this);
    return true;
}

/**
 * @brief Detiene el servidor y cierra todas las conexiones.
 */
void Debugger::stop() {
    if (!running_.exchange(false)) return; // ya parado

    // cerrar socket de escucha para desbloquear accept()
    if (server_fd_ != static_cast<int>(INVALID_SOCK)) {
        CLOSE_SOCK(server_fd_);
        server_fd_ = static_cast<int>(INVALID_SOCK);
    }

    if (accept_thread_.joinable()) accept_thread_.join();

    // cerrar sockets de clientes
    {
        std::lock_guard<std::mutex> lk(client_mutex_);
        for (int fd : client_fds_)
            CLOSE_SOCK(fd);
        client_fds_.clear();
    }

    // reanudar todos los procesos pausados
    {
        std::lock_guard<std::mutex> lk(proc_mutex_);
        for (auto &kv : proc_ctx_) {
            kv.second.state = DbgProcState::DETACHED;
            kv.second.step_mode = false;
            kv.second.pause_cv.notify_all();
        }
    }
}

/* =====================================================================
 * accept_loop
 * ===================================================================== */

/**
 * @brief Bucle de aceptacion de conexiones TCP.
 */
void Debugger::accept_loop() {
    while (running_.load()) {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = static_cast<int>(::accept(
            server_fd_, reinterpret_cast<struct sockaddr *>(&client_addr),
            &client_len));
        if (client_fd == static_cast<int>(INVALID_SOCK)) {
            if (!running_.load()) break; // servidor detenido
            continue;
        }
        // registrar cliente
        {
            std::lock_guard<std::mutex> lk(client_mutex_);
            client_fds_.push_back(client_fd);
        }
        // lanzar hilo por cliente
        std::thread t(&Debugger::client_loop, this, client_fd);
        t.detach(); // se limpia solo al cerrar
    }
}

/* =====================================================================
 * Funciones de envio/recepcion con framing de longitud
 * ===================================================================== */

/**
 * @brief Lee exactamente n bytes del socket.
 * @return true si se leyeron todos los bytes.
 */
static bool recv_exact(int fd, void *buf, size_t n) {
    size_t total = 0;
    char *p = static_cast<char *>(buf);
    while (total < n) {
        int r = static_cast<int>(
            ::recv(fd, p + total, static_cast<int>(n - total), 0));
        if (r <= 0) return false;
        total += static_cast<size_t>(r);
    }
    return true;
}

/**
 * @brief Envia exactamente n bytes por el socket.
 * @return true si se enviaron todos.
 */
static bool send_exact(int fd, const void *buf, size_t n) {
    size_t total = 0;
    const char *p = static_cast<const char *>(buf);
    while (total < n) {
        int s = static_cast<int>(
            ::send(fd, p + total, static_cast<int>(n - total), 0));
        if (s <= 0) return false;
        total += static_cast<size_t>(s);
    }
    return true;
}

/**
 * @brief Lee un mensaje con framing de longitud del socket.
 * @param fd  Socket.
 * @param out Cadena de salida con el payload JSON.
 * @return true si se leyo el mensaje completo.
 */
static bool recv_msg(int fd, std::string &out) {
    uint32_t len_le = 0;
    if (!recv_exact(fd, &len_le, 4)) return false;
    // convertir de LE a host
    uint32_t len = ((len_le) & 0xFF) | ((len_le >> 8) & 0xFF) << 8 |
                   ((len_le >> 16) & 0xFF) << 16 |
                   ((len_le >> 24) & 0xFF) << 24;
    if (len == 0 || len > DBG_MAX_MSG_SIZE) return false;
    out.resize(len);
    return recv_exact(fd, &out[0], len);
}

/**
 * @brief Envia un payload JSON con framing de longitud.
 */
void Debugger::send_msg(int client_fd, const std::string &json) {
    // Adquirir client_mutex_ alrededor del envio completo (header +
    // body) para evitar interleaving entre las respuestas sincronas
    // de un cliente y los eventos broadcast desde otro hilo.  Sin
    // este lock, dos hilos enviando simultaneamente al mismo fd
    // pueden intercalar sus bytes y corromper el framing.
    std::lock_guard<std::mutex> lk(client_mutex_);
    uint32_t len = static_cast<uint32_t>(json.size());
    uint8_t hdr[4] = {static_cast<uint8_t>(len & 0xFF),
                      static_cast<uint8_t>((len >> 8) & 0xFF),
                      static_cast<uint8_t>((len >> 16) & 0xFF),
                      static_cast<uint8_t>((len >> 24) & 0xFF)};
    send_exact(client_fd, hdr, 4);
    send_exact(client_fd, json.c_str(), len);
}

/**
 * @brief Emite un evento JSON a todos los clientes conectados.
 *
 * Llama a send_msg para cada cliente conectado.  send_msg adquiere
 * client_mutex_ internamente y serializa la copia ENTERA del marco
 * (header + body), evitando interleaving con las respuestas sincronas.
 */
void Debugger::broadcast_event(const std::string &json) {
    // Snapshot de los fds bajo lock para evitar acceder al vector
    // mientras otro hilo lo modifica (accept_loop / cleanup).  Una
    // vez tenemos la copia, send_msg adquiere el mismo lock por fd.
    std::vector<int> fds_copy;
    {
        std::lock_guard<std::mutex> lk(client_mutex_);
        fds_copy = client_fds_;
    }
    for (int fd : fds_copy) {
        send_msg(fd, json);
    }
}

/* =====================================================================
 * client_loop
 * ===================================================================== */

/**
 * @brief Bucle de atencion a un cliente conectado.
 */
void Debugger::client_loop(int client_fd) {
    // handshake: enviar magic de identificacion
    char handshake[8];
    uint32_t magic = DBG_HANDSHAKE_MAGIC;
    std::memcpy(handshake, &magic, 4);
    // version del protocolo en los 4 bytes siguientes
    uint32_t proto_ver = 1;
    std::memcpy(handshake + 4, &proto_ver, 4);
    send_exact(client_fd, handshake, 8);

    // bucle de comandos
    std::string msg;
    while (running_.load()) {
        if (!recv_msg(client_fd, msg)) break; // cliente cerro la conexion
        handle_command(msg, client_fd);
    }

    // limpiar
    {
        std::lock_guard<std::mutex> lk(client_mutex_);
        client_fds_.erase(
            std::remove(client_fds_.begin(), client_fds_.end(), client_fd),
            client_fds_.end());
    }
    CLOSE_SOCK(client_fd);
}

/* =====================================================================
 * get_or_create_ctx
 * ===================================================================== */

/**
 * @brief Obtiene o crea el contexto de depuracion de un proceso.
 */
DbgProcCtx &Debugger::get_or_create_ctx(uint64_t pid) {
    auto it = proc_ctx_.find(pid);
    if (it != proc_ctx_.end()) return it->second;
    // emplace construye en-sitio: mutex y condition_variable no son movibles
    auto res =
        proc_ctx_.emplace(std::piecewise_construct, std::forward_as_tuple(pid),
                          std::forward_as_tuple());
    DbgProcCtx &ctx = res.first->second;
    ctx.pid = pid;
    ctx.state = DbgProcState::DETACHED;
    ctx.step_mode = false;
    ctx.next_mode = false;
    ctx.call_depth = 0;
    return ctx;
}

/* =====================================================================
 * find_breakpoint
 * ===================================================================== */

Breakpoint *Debugger::find_breakpoint(uint64_t pc, uint64_t pid) {
    // Diagnostico temporal: si VESTA_DBG_BP_TRACE=1, log cada lookup.
    // Activable solo bajo demanda para no spammear el stderr en prod.
    static const bool trace = []() {
        return util::flag_on(util::FlagId::DbgBpTrace);
    }();
    if (trace) {
        std::fprintf(
            stderr,
            "[bp-trace] find_breakpoint(pc=0x%llx, pid=%llu) breakpoints=%zu\n",
            (unsigned long long)pc, (unsigned long long)pid,
            breakpoints_.size());
        for (auto &bp : breakpoints_) {
            std::fprintf(
                stderr, "[bp-trace]   #%u enabled=%d addr=0x%llx pid=%llu %s\n",
                bp.id, bp.enabled ? 1 : 0, (unsigned long long)bp.addr,
                (unsigned long long)bp.pid,
                (bp.enabled && bp.addr == pc && (bp.pid == 0 || bp.pid == pid))
                    ? "<-- MATCH"
                    : "");
        }
        std::fflush(stderr);
    }
    for (auto &bp : breakpoints_) {
        if (!bp.enabled) continue;
        if (bp.addr != pc) continue;
        if (bp.pid != 0 && bp.pid != pid) continue;
        return &bp;
    }
    return nullptr;
}

/* =====================================================================
 * eval_simple_condition
 *
 * Evalua una condicion sencilla del estilo "<reg> <op> <num>" donde
 * <reg> puede ser r0..r15 / rsp / rbp / rip / pc, <op> uno de
 *   == != < <= > >= (signed por defecto)
 * y <num> es un entero (decimal, 0x..., 0b..., 0o..., '-' opcional).
 *
 * Devuelve true si la condicion se cumple.  Si la cadena no se puede
 * parsear, devuelve true tambien (fail-open: no silenciar bps por
 * errores de sintaxis -- mejor pausar y que el usuario vea).
 *
 * Coste: una sola comparacion en runtime; usado SOLO cuando un bp con
 * condicion no vacia hace match en pc.  Cero overhead en bps incond.
 * ===================================================================== */
static int reg_index_from_name(const std::string &n) {
    if (n.empty()) return -1;
    if (n == "rsp" || n == "sp") return 100;
    if (n == "rbp" || n == "bp") return 101;
    if (n == "rip" || n == "pc") return 102;
    if (n[0] == 'r' && n.size() <= 3) {
        try {
            int v = std::stoi(n.substr(1));
            if (v >= 0 && v <= 15) return v;
        } catch (...) {
        }
    }
    return -1;
}

static bool eval_simple_condition(const std::string &cond,
                                  runtime::ProcessVM *p) {
    if (cond.empty() || !p) return true;
    // Tokenizar muy basico: trim, split por espacios.
    std::string s = cond;
    // colapsar espacios para simplificar
    std::string out;
    out.reserve(s.size());
    bool prev_space = true;
    for (char c : s) {
        if (c == ' ' || c == '\t') {
            if (!prev_space) {
                out.push_back(' ');
                prev_space = true;
            }
        } else {
            out.push_back(c);
            prev_space = false;
        }
    }
    s = out;
    if (!s.empty() && s.back() == ' ') s.pop_back();
    // separar operador: buscar primero un op de 2 chars, luego 1 char
    const char *ops2[] = {"==", "!=", "<=", ">="};
    size_t op_pos = std::string::npos;
    size_t op_len = 0;
    for (const char *op : ops2) {
        size_t k = s.find(op);
        if (k != std::string::npos) {
            op_pos = k;
            op_len = 2;
            break;
        }
    }
    if (op_pos == std::string::npos) {
        for (char c : std::string("<>")) {
            size_t k = s.find(c);
            if (k != std::string::npos) {
                op_pos = k;
                op_len = 1;
                break;
            }
        }
    }
    if (op_pos == std::string::npos) return true; // sin op -> fail-open
    std::string lhs = s.substr(0, op_pos);
    std::string op = s.substr(op_pos, op_len);
    std::string rhs = s.substr(op_pos + op_len);
    // trim
    while (!lhs.empty() && lhs.back() == ' ')
        lhs.pop_back();
    while (!rhs.empty() && rhs.front() == ' ')
        rhs.erase(rhs.begin());
    int idx = reg_index_from_name(lhs);
    if (idx < 0) return true;
    int64_t lv = 0;
    if (idx >= 0 && idx <= 15)
        lv = static_cast<int64_t>(p->registers.regs[idx].qword());
    else if (idx == 100)
        lv = static_cast<int64_t>(p->registers.stack_pointer.raw());
    else if (idx == 101)
        lv = static_cast<int64_t>(p->registers.base_pointer.raw());
    else if (idx == 102)
        lv = static_cast<int64_t>(p->registers.rip.raw());
    int64_t rv = 0;
    try {
        if (rhs.size() >= 2 && rhs[0] == '0' &&
            (rhs[1] == 'x' || rhs[1] == 'X'))
            rv = std::stoll(rhs.substr(2), nullptr, 16);
        else if (rhs.size() >= 2 && rhs[0] == '0' &&
                 (rhs[1] == 'b' || rhs[1] == 'B'))
            rv = std::stoll(rhs.substr(2), nullptr, 2);
        else if (rhs.size() >= 2 && rhs[0] == '0' &&
                 (rhs[1] == 'o' || rhs[1] == 'O'))
            rv = std::stoll(rhs.substr(2), nullptr, 8);
        else
            rv = std::stoll(rhs, nullptr, 10);
    } catch (...) {
        return true;
    }
    if (op == "==") return lv == rv;
    if (op == "!=") return lv != rv;
    if (op == "<") return lv < rv;
    if (op == "<=") return lv <= rv;
    if (op == ">") return lv > rv;
    if (op == ">=") return lv >= rv;
    return true;
}

/* =====================================================================
 * find_process_by_pid: busca el ProcessVM por su local_pid en todos
 * los schedulers de la VM.  Devuelve nullptr si no existe.
 *
 * No adquirimos lock sobre los procesos: estamos asumiendo que el
 * cliente del debugger quiere leer estado de un proceso que esta
 * pausado (PAUSED) y por tanto no esta siendo modificado por el
 * scheduler.  Para procesos en RUNNING, los reads pueden leer
 * estado parcial pero seguro (registros son atomic, memoria VM es
 * accesible read-only).  El uso tipico es: cliente recibe evento
 * BREAK con pid + pc, luego pide REGISTERS/MEMORY del mismo pid.
 * ===================================================================== */
static runtime::ProcessVM *find_process_by_pid(runtime::VM &vm, uint64_t pid) {
    for (auto &sched : vm.schedulers) {
        for (auto &p : sched->processes) {
            if (p && p->pid.local_pid == pid) {
                return p.get();
            }
        }
    }
    return nullptr;
}

/* =====================================================================
 * recompute_any_step
 *
 * Llamado tras cualquier cambio de estado que pueda haber limpiado el
 * ultimo step_mode o pausa.  Si NINGUN proceso queda en step_mode ni
 * PAUSED, baja el flag global y el fast path de on_before_exec puede
 * retornar inmediatamente sin tocar mutex.
 *
 * Debe llamarse con `proc_mutex_` ya adquirido por el caller.
 * ===================================================================== */
static bool
any_step_or_paused_locked(const std::unordered_map<uint64_t, DbgProcCtx> &m) {
    for (const auto &kv : m) {
        if (kv.second.step_mode) return true;
        if (kv.second.state == DbgProcState::PAUSED) return true;
    }
    return false;
}

/* =====================================================================
 * on_before_exec: punto de intercepcion critico
 * ===================================================================== */

/**
 * @brief Llamado antes de ejecutar cada instruccion.
 *
 * Fast path: si any_bp_ es false y el proceso no esta en step_mode,
 * retorna inmediatamente sin adquirir ningun mutex.
 */
void Debugger::on_before_exec(runtime::ProcessVM *proc) {
    if (!proc) return;

    // FAST PATH: zero-lock, zero-allocation.  Solo dos atomic loads.
    // Si NO hay breakpoints registrados Y NO hay procesos en
    // step/pause, retornamos inmediatamente sin tocar mutex.  Cuando
    // el cliente emite SET_BREAK por primera vez, `any_bp_` pasa a
    // true y entramos en el slow path; cuando emite STEP/NEXT/PAUSE,
    // `any_step_` pasa a true.  Ambos flags se desactivan cuando el
    // ultimo break/step/pause termina (CONTINUE limpia step_mode y
    // recomputa any_step_ -> false si no quedan procesos pausados).
    // Coste runtime con debugger inactivo: 2 loads relaxed + 1 branch
    // (~1 ns por instruccion VM).  Equivale a `if (!has_hooks) return`.
    if (__builtin_expect(!any_bp_.load(std::memory_order_relaxed) &&
                             !any_step_.load(std::memory_order_relaxed) &&
                             !any_watch_.load(std::memory_order_relaxed),
                         1)) {
        return;
    }

    // Loop: tras un wait (el usuario hizo continue/step), debemos
    // RE-chequear si hay un breakpoint en el PC actual antes de
    // ejecutar la siguiente instruccion.  Esto cubre el caso comun:
    //   1. Proceso PAUSED por pause_at_start (step_mode=true).
    //   2. Cliente conecta, agrega bp en pc=N.
    //   3. Cliente envia continue.
    //   4. on_before_exec retorna -- pero si pc actual == N, deberia
    //      pausar de nuevo por el bp.  Sin loop, perderiamos ese bp.
    // El loop se repite hasta que no haya bp/step pendiente, momento
    // en el que retornamos para ejecutar la instruccion.
    uint64_t pid = proc->pid.local_pid; // PID local del proceso
    // Diagnostico temporal: si VESTA_DBG_BP_TRACE=1, log cada slow path.
    static const bool _bp_trace = []() {
        return util::flag_on(util::FlagId::DbgBpTrace);
    }();
    int _recheck_iter = 0;
recheck:
    uint64_t pc = proc->registers.rip.raw(); // Program Counter actual
    if (_bp_trace) {
        std::fprintf(
            stderr,
            "[bp-trace] on_before_exec ENTER pid=%llu pc=0x%llx iter=%d "
            "any_bp=%d any_step=%d\n",
            (unsigned long long)pid, (unsigned long long)pc, _recheck_iter,
            any_bp_.load(std::memory_order_relaxed) ? 1 : 0,
            any_step_.load(std::memory_order_relaxed) ? 1 : 0);
        std::fflush(stderr);
    }
    _recheck_iter++;

    // slow path: verificar breakpoints y step mode
    bool should_pause = false;
    std::string pause_reason;

    {
        // Chequeo del skip-bp-pc: si el proceso fue pausado por un
        // bp en ESTE pc en la iteracion anterior y el usuario emitio
        // continue, NO debemos re-pausar -- ejecutamos la instruccion
        // y limpiamos el flag.  Sin esto, "continue" tras hit de bp
        // causaria loop infinito.
        uint64_t skip_pc = UINT64_MAX;
        {
            std::lock_guard<std::mutex> lk2(proc_mutex_);
            auto it = proc_ctx_.find(pid);
            if (it != proc_ctx_.end()) {
                skip_pc = it->second.last_bp_pc;
                it->second.last_bp_pc = UINT64_MAX; // consumir
            }
        }
        std::lock_guard<std::mutex> lk(bp_mutex_);
        Breakpoint *bp = (pc == skip_pc) ? nullptr : find_breakpoint(pc, pid);
        if (bp) {
            // Evaluar condicion (vacio = incondicional).  Si la cond
            // se evalua a false, NO pausamos, NO incrementamos hits.
            bool cond_ok = bp->condition.empty() ||
                           eval_simple_condition(bp->condition, proc);
            if (cond_ok) {
                bp->hit_count++;
                should_pause = true;
                pause_reason = "break";
                uint32_t bp_id_for_event = bp->id;
                bool was_one_shot = bp->one_shot;
                {
                    std::lock_guard<std::mutex> lk2(proc_mutex_);
                    DbgProcCtx &ctx = get_or_create_ctx(pid);
                    ctx.last_bp_pc = pc;
                }
                // emitir evento de breakpoint
                std::ostringstream ev;
                ev << "{\"event\":\"break\","
                   << "\"pid\":" << pid << ","
                   << "\"pc\":" << pc << ","
                   << "\"bp_id\":" << bp_id_for_event << "}";
                broadcast_event(ev.str());
                // Auto-delete si one_shot.  Hacemos esto AHORA mientras
                // tenemos el mutex; el iterador `bp` quedara invalidado
                // pero ya no lo usamos.
                if (was_one_shot) {
                    breakpoints_.erase(
                        std::remove_if(breakpoints_.begin(), breakpoints_.end(),
                                       [bp_id_for_event](const Breakpoint &b) {
                                           return b.id == bp_id_for_event;
                                       }),
                        breakpoints_.end());
                    any_bp_.store(!breakpoints_.empty(),
                                  std::memory_order_relaxed);
                }
            }
        }
    }

    // Watchpoints: chequeo polling.  Solo si any_watch_=true y solo
    // dentro del slow path (ya estamos aqui por any_bp_/any_step_).
    // Esto significa que si NO hay bps ni step, los watchpoints
    // necesitan que algo mas active el slow path.  En la practica,
    // poner un watchpoint setea any_watch_ y FORZA una pausa-step
    // implicita en el primer chequeo (el cliente recibe el evento).
    if (any_watch_.load(std::memory_order_relaxed)) {
        std::lock_guard<std::mutex> lk(watch_mutex_);
        for (auto &wp : watchpoints_) {
            if (!wp.enabled) continue;
            if (wp.pid != 0 && wp.pid != pid) continue;
            bool alive = proc->gc_heap.is_handle_live(
                static_cast<gc::GcHandle>(wp.handle));
            uint64_t addr = 0;
            if (alive) {
                addr = reinterpret_cast<uint64_t>(
                    proc->gc_heap.deref(static_cast<gc::GcHandle>(wp.handle)));
            }
            bool moved = (alive && addr != wp.last_addr && wp.was_alive);
            bool died = (!alive && wp.was_alive);
            bool resurr = (alive && !wp.was_alive);
            if (moved || died || resurr) {
                std::ostringstream ev;
                ev << "{\"event\":\"watch\","
                   << "\"pid\":" << pid << ","
                   << "\"pc\":" << pc << ","
                   << "\"wp_id\":" << wp.id << ","
                   << "\"handle\":" << wp.handle << ","
                   << "\"reason\":\""
                   << (died ? "died" : (moved ? "moved" : "alive")) << "\","
                   << "\"old_addr\":" << wp.last_addr << ","
                   << "\"new_addr\":" << addr << "}";
                broadcast_event(ev.str());
                wp.last_addr = addr;
                wp.was_alive = alive;
                should_pause = true;
                pause_reason = "watch";
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(proc_mutex_);
        DbgProcCtx &ctx = get_or_create_ctx(pid);
        // Skip-step-pc: si en la iteracion anterior pausamos por
        // step_mode en este mismo pc y el cliente emitio STEP de
        // nuevo, NO debemos re-pausar -- ejecutamos la instruccion
        // y limpiamos el flag.  Sin esto, "step" tras stepped causa
        // bucle: pausa-stepped -> wake -> pausa-stepped -> ...
        // siempre en el mismo PC (la instruccion nunca corre).
        uint64_t skip_step_pc = ctx.last_step_pc;
        ctx.last_step_pc = UINT64_MAX; // consumir el flag
        if (ctx.step_mode && pc != skip_step_pc) {
            should_pause = true;
            pause_reason = "stepped";
            ctx.step_mode = false; // consumir el step
            ctx.last_step_pc = pc; // recordar para evitar re-pausa
            // Recompute any_step_ tras consumir el step_mode.
            any_step_.store(any_step_or_paused_locked(proc_ctx_),
                            std::memory_order_release);
            std::ostringstream ev;
            ev << "{\"event\":\"stepped\","
               << "\"pid\":" << pid << ","
               << "\"pc\":" << pc << "}";
            broadcast_event(ev.str());
        }
    }

    if (!should_pause) return;

    // pausar el proceso hasta que el depurador emita continue/step
    if (_bp_trace) {
        std::fprintf(stderr,
                     "[bp-trace] on_before_exec PAUSE pid=%llu pc=0x%llx "
                     "reason='%s'\n",
                     (unsigned long long)pid, (unsigned long long)pc,
                     pause_reason.c_str());
        std::fflush(stderr);
    }
    {
        std::unique_lock<std::mutex> lk(proc_mutex_);
        DbgProcCtx &ctx = get_or_create_ctx(pid);
        ctx.state = DbgProcState::PAUSED;
        // PAUSED activa el fast-path de on_before_exec.
        any_step_.store(true, std::memory_order_release);
        // bloquear hasta que state cambie a RUNNING
        ctx.pause_cv.wait(
            lk, [&ctx]() { return ctx.state != DbgProcState::PAUSED; });
        if (_bp_trace) {
            const char *st = "OTHER";
            if (ctx.state == DbgProcState::RUNNING) st = "RUNNING";
            if (ctx.state == DbgProcState::DETACHED) st = "DETACHED";
            std::fprintf(stderr,
                         "[bp-trace] on_before_exec RESUME pid=%llu state=%s "
                         "step_mode=%d\n",
                         (unsigned long long)pid, st, ctx.step_mode ? 1 : 0);
            std::fflush(stderr);
        }
        // Tras despertar (el cliente envio CONTINUE/STEP), recompute
        // any_step_: si quedan otros procesos en PAUSED o step_mode,
        // sigue true; si no, vuelve a false y el fast path retorna.
        any_step_.store(any_step_or_paused_locked(proc_ctx_),
                        std::memory_order_release);
    }
    // Re-check: tras el wait, el usuario podria haber agregado un bp
    // que matchea el pc actual.  Sin esta re-iteracion el bp se
    // perderia (el caso clasico: pause_at_start -> cliente agrega
    // bp en pc=0 -> cliente continue -> debiamos hit el bp).
    goto recheck;
}

/* =====================================================================
 * Notificaciones de eventos de proceso
 * ===================================================================== */

void Debugger::on_process_exit(uint64_t pid) {
    std::ostringstream ev;
    ev << "{\"event\":\"exit\",\"pid\":" << pid << "}";
    broadcast_event(ev.str());
    // limpiar contexto
    std::lock_guard<std::mutex> lk(proc_mutex_);
    proc_ctx_.erase(pid);
}

void Debugger::on_exception(uint64_t pid, const std::string &exc_class) {
    std::ostringstream ev;
    ev << "{\"event\":\"exception\","
       << "\"pid\":" << pid << ","
       << "\"class\":\"" << json_escape(exc_class) << "\"}";
    broadcast_event(ev.str());
}

void Debugger::pause_at_start(uint64_t pid) {
    // Marca el proceso para que se detenga ANTES de ejecutar su
    // primera instruccion.  Como state=PAUSED + step_mode=true,
    // la primera entrada a on_before_exec para este pid:
    //   1. Detecta step_mode -> emite evento "stepped" + clear step_mode.
    //   2. Detecta should_pause=true -> setea state=PAUSED.
    //   3. Bloquea en cv.wait hasta que llegue CONTINUE.
    //
    // Cuando el cliente envia "continue", el handler del CONTINUE
    // setea state=RUNNING + notifica el cv y el proceso sigue.
    // Entre tanto el cliente puede setear breakpoints, listar
    // procesos, leer registros, etc.
    {
        std::lock_guard<std::mutex> lk(proc_mutex_);
        DbgProcCtx &ctx = get_or_create_ctx(pid);
        ctx.state = DbgProcState::PAUSED;
        ctx.step_mode = true;
        any_step_.store(true, std::memory_order_release);
    }
    // pause_at_start activa el step_mode: los schedulers necesitan
    // has_hooks=true para que on_before_exec se invoque y haga la
    // pausa real.
    refresh_scheduler_hooks();
}

void Debugger::on_process_spawn(uint64_t parent_pid, uint64_t child_pid) {
    std::ostringstream ev;
    ev << "{\"event\":\"spawned\","
       << "\"parent\":" << parent_pid << ","
       << "\"child\":" << child_pid << "}";
    broadcast_event(ev.str());
}

void Debugger::on_message(uint64_t pid, bool is_send, uint64_t target,
                          uint64_t payload64) {
    // Fast path: si nadie esta tracing nada, retornamos.
    if (!any_msg_trace_.load(std::memory_order_relaxed)) return;
    // Slow path: comprobar si ESTE pid esta en la lista.
    bool active = false;
    {
        std::lock_guard<std::mutex> lk(trace_mutex_);
        active = (traced_msg_pids_.count(pid) != 0);
    }
    if (!active) return;
    std::ostringstream ev;
    ev << "{\"event\":\"msg_trace\","
       << "\"pid\":" << pid << ","
       << "\"dir\":\"" << (is_send ? "send" : "recv") << "\","
       << "\"peer\":" << target << ","
       << "\"value\":" << payload64 << "}";
    broadcast_event(ev.str());
}

void Debugger::on_monitor_contention(uint64_t pid, uint64_t handle,
                                     uint64_t owner) {
    if (!break_on_mon_.load(std::memory_order_relaxed)) return;
    // Emitir evento.
    std::ostringstream ev;
    ev << "{\"event\":\"mon_block\","
       << "\"pid\":" << pid << ","
       << "\"handle\":" << handle << ","
       << "\"owner\":" << owner << "}";
    broadcast_event(ev.str());
    // Forzar pausa: ponemos step_mode + state=PAUSED.  El proceso ya
    // esta en WAIT_IO esperando al monitor; cuando el scheduler lo
    // re-active tras un monexit, on_before_exec lo pausara aqui.
    std::lock_guard<std::mutex> lk(proc_mutex_);
    DbgProcCtx &ctx = get_or_create_ctx(pid);
    ctx.state = DbgProcState::PAUSED;
    ctx.step_mode = true;
    any_step_.store(true, std::memory_order_release);
}

/* =====================================================================
 * Helpers de serializacion
 * ===================================================================== */

/**
 * @brief Serializa los registros de un proceso a JSON.
 */
std::string Debugger::regs_to_json(runtime::ProcessVM *proc) {
    if (!proc) return "{}";
    std::ostringstream o;
    o << "{";
    // registros r0-r15
    for (int i = 0; i < 16; i++) {
        if (i) o << ",";
        o << "\"r" << i << "\":" << proc->registers.regs[i].qword();
    }
    // cursor regs cur0..cur3 (registros internos del intérprete)
    for (int i = 0; i < 4; i++) {
        o << ",\"cur" << i << "\":" << proc->registers.cur[i].qword();
    }
    // PC, SP, BP, FL
    o << ",\"pc\":" << proc->registers.rip.raw();
    o << ",\"sp\":" << proc->registers.stack_pointer.raw();
    o << ",\"bp\":" << proc->registers.base_pointer.raw();
    o << ",\"flags\":" << proc->registers.flags.raw();
    // Tambien expongo PID y reductions actuales: utiles para el cliente
    // y caben de sobra en el mismo JSON.
    o << ",\"pid\":" << proc->pid.local_pid;
    o << ",\"reductions\":" << proc->reductions_remaining;
    // Numero de frames OOP encolados (depth aproximado del stack VM).
    uint32_t depth = 0;
    for (loader::FrameHeader *f = proc->frame_stack;
         f != nullptr && depth < 1024; f = f->prev, ++depth) {
    }
    o << ",\"frame_depth\":" << depth;
    o << "}";
    return o.str();
}

/**
 * @brief Serializa un volcado de memoria VM a JSON.
 */
std::string Debugger::mem_to_json(runtime::ProcessVM *proc, uint64_t addr,
                                  uint32_t length) {
    if (!proc || length == 0) return "[]";
    // limitar a 4096 bytes por peticion
    if (length > 4096) length = 4096;
    std::vector<uint8_t> buf(length);
    // leer via la interfaz de memoria VM del proceso
    proc->vm_mem.read_bytes(addr, buf.data(), length);
    std::ostringstream o;
    o << "[";
    for (uint32_t i = 0; i < length; i++) {
        if (i) o << ",";
        char hex[5];
        std::snprintf(hex, sizeof(hex), "%u", static_cast<unsigned>(buf[i]));
        o << hex;
    }
    o << "]";
    return o.str();
}

/* =====================================================================
 * handle_command: dispatch de comandos
 * ===================================================================== */

/**
 * @brief Procesa un mensaje JSON de comando del cliente.
 */
void Debugger::handle_command(const std::string &json_msg, int client_fd) {
    std::string cmd_name = json_get(json_msg, "cmd");
    std::string seq_str = json_get(json_msg, "seq");
    uint32_t seq =
        seq_str.empty() ? 0u : static_cast<uint32_t>(std::stoul(seq_str));

    DebugCmd cmd = debug_cmd_parse(cmd_name);

    // plantilla de respuesta
    auto ok_resp = [&](const std::string &data) {
        std::ostringstream r;
        r << "{\"ok\":true,\"seq\":" << seq << ",\"data\":" << data << "}";
        send_msg(client_fd, r.str());
    };
    auto err_resp = [&](const std::string &msg) {
        std::ostringstream r;
        r << "{\"ok\":false,\"seq\":" << seq << ",\"error\":\""
          << json_escape(msg) << "\"}";
        send_msg(client_fd, r.str());
    };

    /* ----------------------------------------------------------------
     * Gate de autenticacion.
     *
     * Si auth_required_ esta activo:
     *   - Los comandos AUTH_LOGIN, AUTH_LOGOUT y SERVER_INFO son
     *     publicos (cualquiera puede consultar uptime / hacer login).
     *   - El resto exige un campo "session_token" valido en el JSON.
     *   - Los comandos sensibles (definidos abajo) exigen ademas un
     *     rol minimo: ADMIN o DEVELOPER segun el caso.
     *
     * Si auth_required_ esta desactivado, se mantiene el comportamiento
     * anterior (cualquier cliente puede ejecutar cualquier comando).
     * ---------------------------------------------------------------- */
    auto requires_min_role = [](DebugCmd c) -> Role {
        switch (c) {
        // ADMIN
        case DebugCmd::SERVER_SHUTDOWN:
        case DebugCmd::AUTH_CREATE_USER:
        case DebugCmd::AUTH_DELETE_USER:
        case DebugCmd::AUTH_LIST_USERS:
        case DebugCmd::FS_WRITE:
        case DebugCmd::FS_DELETE:
        case DebugCmd::FS_MKDIR:
        case DebugCmd::FS_RENAME: return Role::ADMIN;
        // DEVELOPER
        case DebugCmd::LOAD_VELB:
        case DebugCmd::LOAD_VELB_BYTES:
        case DebugCmd::KILL_PROC:
        case DebugCmd::SET_BREAK:
        case DebugCmd::SET_BREAK_SRC:
        case DebugCmd::DEL_BREAK:
        case DebugCmd::SET_WATCH:
        case DebugCmd::DEL_WATCH:
        case DebugCmd::STEP:
        case DebugCmd::NEXT:
        case DebugCmd::CONTINUE:
        case DebugCmd::PAUSE:
        case DebugCmd::STEP_OUT:
        case DebugCmd::STEP_UNTIL:
        case DebugCmd::GC_RUN:
        case DebugCmd::TRACE_MSGS:
        case DebugCmd::BREAK_MON: return Role::DEVELOPER;
        // VIEWER (default para todo lo demas)
        default: return Role::VIEWER;
        }
    };
    if (auth_required_) {
        // Lista blanca: comandos publicos que NO requieren token.
        bool is_public =
            cmd == DebugCmd::AUTH_LOGIN || cmd == DebugCmd::AUTH_LOGOUT ||
            cmd == DebugCmd::SERVER_INFO ||
            cmd == DebugCmd::UNKNOWN; /* dejar pasar para err_resp */
        // Bootstrap: si la BD esta vacia (cero usuarios), aceptamos UNA
        // sola llamada a AUTH_CREATE_USER sin token para que el IDE/
        // operador pueda crear el primer admin.  Tras eso la cuenta
        // existe y vuelve a aplicarse la regla normal.  Esto evita
        // el callejon sin salida de "auth-on + DB vacia => imposible
        // crear el primer usuario".
        if (cmd == DebugCmd::AUTH_CREATE_USER &&
            AuthManager::instance().list_users().empty()) {
            is_public = true;
        }
        if (!is_public) {
            std::string tok = json_get(json_msg, "session_token");
            if (tok.empty()) tok = json_get(json_msg, "token");
            if (tok.empty()) {
                err_resp("auth required: falta campo 'session_token'");
                return;
            }
            Session sess;
            if (!AuthManager::instance().validate_token(tok, &sess)) {
                err_resp("auth required: session_token invalido o expirado");
                return;
            }
            Role need = requires_min_role(cmd);
            if (static_cast<uint8_t>(sess.role) < static_cast<uint8_t>(need)) {
                std::ostringstream m;
                m << "permiso denegado: se requiere rol >= "
                  << role_to_string(need)
                  << " (tu rol: " << role_to_string(sess.role) << ")";
                err_resp(m.str());
                return;
            }
        }
    }

    switch (cmd) {
    case DebugCmd::ATTACH: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        {
            std::lock_guard<std::mutex> lk(proc_mutex_);
            DbgProcCtx &ctx = get_or_create_ctx(pid);
            ctx.state = DbgProcState::RUNNING;
        }
        ok_resp("{\"pid\":" + pid_s + "}");
        break;
    }

    case DebugCmd::DETACH: {
        std::string pid_s = json_get(json_msg, "pid");
        if (!pid_s.empty()) {
            uint64_t pid = std::stoull(pid_s);
            std::lock_guard<std::mutex> lk(proc_mutex_);
            auto it = proc_ctx_.find(pid);
            if (it != proc_ctx_.end()) {
                it->second.state = DbgProcState::DETACHED;
                it->second.step_mode = false;
                it->second.pause_cv.notify_all(); // reanudar si pausado
                any_step_.store(any_step_or_paused_locked(proc_ctx_),
                                std::memory_order_release);
            }
        }
        ok_resp("{}");
        break;
    }

    case DebugCmd::SET_BREAK: {
        std::string addr_s = json_get(json_msg, "addr");
        if (addr_s.empty()) {
            err_resp("falta campo 'addr'");
            return;
        }
        std::string pid_s = json_get(json_msg, "pid");
        std::string cond_s = json_get(json_msg, "cond");
        std::string one_s = json_get(json_msg, "one_shot");
        Breakpoint bp{};
        {
            std::lock_guard<std::mutex> lk(bp_mutex_);
            bp.id = next_bp_id_++;
            bp.addr = std::stoull(addr_s);
            bp.pid = pid_s.empty() ? 0 : std::stoull(pid_s);
            bp.enabled = true;
            bp.hit_count = 0;
            bp.condition = cond_s;
            bp.one_shot = (one_s == "true" || one_s == "1");
            breakpoints_.push_back(bp);
            any_bp_.store(true, std::memory_order_relaxed);
        }
        std::ostringstream d;
        d << "{\"id\":" << bp.id << ",\"addr\":" << bp.addr << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::DEL_BREAK: {
        std::string id_s = json_get(json_msg, "id");
        if (id_s.empty()) {
            err_resp("falta campo 'id'");
            return;
        }
        uint32_t bp_id = static_cast<uint32_t>(std::stoul(id_s));
        {
            std::lock_guard<std::mutex> lk(bp_mutex_);
            breakpoints_.erase(std::remove_if(breakpoints_.begin(),
                                              breakpoints_.end(),
                                              [bp_id](const Breakpoint &b) {
                                                  return b.id == bp_id;
                                              }),
                               breakpoints_.end());
            any_bp_.store(!breakpoints_.empty(), std::memory_order_relaxed);
        }
        ok_resp("{}");
        break;
    }

    case DebugCmd::LIST_BREAKS: {
        std::ostringstream d;
        d << "[";
        {
            std::lock_guard<std::mutex> lk(bp_mutex_);
            bool first = true;
            for (const auto &bp : breakpoints_) {
                if (!first) d << ",";
                first = false;
                d << "{\"id\":" << bp.id << ",\"addr\":" << bp.addr
                  << ",\"pid\":" << bp.pid
                  << ",\"enabled\":" << (bp.enabled ? "true" : "false")
                  << ",\"hits\":" << bp.hit_count
                  << ",\"one_shot\":" << (bp.one_shot ? "true" : "false")
                  << ",\"cond\":\"" << json_escape(bp.condition) << "\"}";
            }
        }
        d << "]";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::CONTINUE: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        {
            std::lock_guard<std::mutex> lk(proc_mutex_);
            auto it = proc_ctx_.find(pid);
            if (it != proc_ctx_.end()) {
                it->second.state = DbgProcState::RUNNING;
                it->second.step_mode = false;
                it->second.pause_cv.notify_all();
                any_step_.store(any_step_or_paused_locked(proc_ctx_),
                                std::memory_order_release);
            }
        }
        ok_resp("{}");
        break;
    }

    case DebugCmd::STEP: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        {
            std::lock_guard<std::mutex> lk(proc_mutex_);
            DbgProcCtx &ctx = get_or_create_ctx(pid);
            ctx.step_mode = true;
            ctx.state = DbgProcState::RUNNING; // reanudar para un paso
            ctx.pause_cv.notify_all();
            // step_mode activo => fast path debe entrar en slow.
            any_step_.store(true, std::memory_order_release);
        }
        ok_resp("{}");
        break;
    }

    case DebugCmd::REGISTERS: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        ok_resp(regs_to_json(p));
        break;
    }

    case DebugCmd::MEMORY: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string addr_s = json_get(json_msg, "addr");
        std::string len_s = json_get(json_msg, "len");
        if (pid_s.empty() || addr_s.empty() || len_s.empty()) {
            err_resp("memory requiere pid, addr y len");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        uint64_t addr = std::stoull(addr_s);
        uint32_t length = static_cast<uint32_t>(std::stoul(len_s));
        if (length > 4096) {
            err_resp("len max 4096");
            return;
        }
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        ok_resp(mem_to_json(p, addr, length));
        break;
    }

    case DebugCmd::STACK: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        // Stack trace: recorrer frame_stack para devolver pares (pc,
        // return_pc).
        std::ostringstream d;
        d << "{\"frames\":[";
        bool first = true;
        d << "{\"pc\":" << p->registers.rip.raw() << ",\"is_top\":true}";
        first = false;
        for (loader::FrameHeader *f = p->frame_stack; f != nullptr;
             f = f->prev) {
            d << ",{\"return_pc\":" << f->return_pc << "}";
        }
        d << "]}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::LIST_PROCS: {
        std::ostringstream d;
        d << "[";
        bool first = true;
        for (auto &sched : vm_.schedulers) {
            for (auto &p : sched->processes) {
                if (!p) continue;
                if (!first) d << ",";
                first = false;
                d << "{\"pid\":" << p->pid.local_pid
                  << ",\"sched_id\":" << p->pid.scheduler_id << ",\"state\":\""
                  << runtime::vm_state_to_str(p->state.load())
                  << "\",\"pc\":" << p->registers.rip.raw()
                  << ",\"reductions\":" << p->reductions_remaining << "}";
            }
        }
        d << "]";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::INFO_PROC: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        std::ostringstream d;
        d << "{\"pid\":" << p->pid.local_pid
          << ",\"sched_id\":" << p->pid.scheduler_id << ",\"state\":\""
          << runtime::vm_state_to_str(p->state.load())
          << "\",\"pc\":" << p->registers.rip.raw()
          << ",\"reductions\":" << p->reductions_remaining
          << ",\"err_thread\":" << static_cast<int>(p->err_thread)
          << ",\"tsc\":" << p->tsc << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::EVAL: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string expr = json_get(json_msg, "expr");
        if (pid_s.empty() || expr.empty()) {
            err_resp("eval requiere pid y expr");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        // Soporte minimo: si expr empieza con 'r' y un digito,
        // devolvemos el valor del registro (r0..r15, rip, rsp, rbp).
        std::ostringstream d;
        if (expr == "rip" || expr == "pc") {
            d << "{\"name\":\"" << expr
              << "\",\"value\":" << p->registers.rip.raw() << "}";
        } else if (expr.size() >= 2 && expr[0] == 'r' &&
                   std::isdigit(static_cast<unsigned char>(expr[1]))) {
            int idx = std::atoi(expr.c_str() + 1);
            if (idx < 0 || idx > 15) {
                err_resp("indice de registro fuera de rango (0..15)");
                return;
            }
            d << "{\"name\":\"" << expr
              << "\",\"value\":" << p->registers.regs[idx].qword() << "}";
        } else {
            err_resp("eval soporta r0..r15 / rip / pc por ahora");
            return;
        }
        ok_resp(d.str());
        break;
    }

    case DebugCmd::SET_BREAK_SRC: {
        std::string file_s = json_get(json_msg, "file");
        std::string line_s = json_get(json_msg, "line");
        std::string pid_s = json_get(json_msg, "pid");
        if (file_s.empty() || line_s.empty()) {
            err_resp("set_break_src requiere 'file' y 'line'");
            return;
        }
        uint32_t target_line = static_cast<uint32_t>(std::stoul(line_s));
        // Recorrer todos los Executable cargados y preguntar a su
        // DebugInfo si tienen un offset para (file, line).  El
        // primer match gana.  Si ninguno tiene info de debug,
        // devolver error claro pidiendo recompilar con --vx-debug.
        uint32_t best_off = UINT32_MAX;
        for (const auto &exe : vm_.loader_public.executables) {
            if (!exe || !exe->debug_info) continue;
            uint32_t off =
                exe->debug_info->lookup_offset_for_line(file_s, target_line);
            if (off != UINT32_MAX) {
                best_off = off;
                break;
            }
        }
        if (best_off == UINT32_MAX) {
            err_resp("set_break_src: no se encontro (file, line) en "
                     "la info de debug.  Compila con --vx-debug "
                     "para incluir la tabla bytecode->source-line.");
            return;
        }
        // Crear el breakpoint con el addr resuelto.
        std::string cond_s = json_get(json_msg, "cond");
        std::string one_s = json_get(json_msg, "one_shot");
        Breakpoint bp{};
        uint64_t bp_pid_v = pid_s.empty() ? 0 : std::stoull(pid_s);
        bool collides = false;
        uint32_t existing_id = 0;
        {
            std::lock_guard<std::mutex> lk(bp_mutex_);
            // Defensa contra colisiones: si ya existe un BP en
            // ESTE addr para el mismo pid (o pid=0=global), NO
            // creamos un duplicado.  Dos BPs al mismo addr causan
            // que solo el primero registrado dispare (el segundo
            // queda enmascarado por last_bp_pc tras un continue),
            // dando la falsa sensacion de que "ese BP no funciona".
            for (const auto &eb : breakpoints_) {
                if (eb.enabled && eb.addr == best_off &&
                    (eb.pid == 0 || bp_pid_v == 0 || eb.pid == bp_pid_v)) {
                    collides = true;
                    existing_id = eb.id;
                    break;
                }
            }
            if (!collides) {
                bp.id = next_bp_id_++;
                bp.addr = best_off;
                bp.pid = bp_pid_v;
                bp.enabled = true;
                bp.hit_count = 0;
                bp.condition = cond_s;
                bp.one_shot = (one_s == "true" || one_s == "1");
                breakpoints_.push_back(bp);
                any_bp_.store(true, std::memory_order_relaxed);
            }
        }
        std::ostringstream d;
        if (collides) {
            // Reportamos OK porque, semanticamente, ya hay un BP
            // que dispara en ese punto -- equivale al BP solicitado.
            // Devolvemos `aliased_to` para que el cliente sepa que
            // no se creo entry nuevo y pueda mostrarlo claro al user.
            d << "{\"id\":" << existing_id << ",\"addr\":" << best_off
              << ",\"file\":\"" << json_escape(file_s) << "\""
              << ",\"line\":" << target_line
              << ",\"aliased_to\":" << existing_id << "}";
        } else {
            d << "{\"id\":" << bp.id << ",\"addr\":" << bp.addr
              << ",\"file\":\"" << json_escape(file_s) << "\""
              << ",\"line\":" << target_line << "}";
        }
        ok_resp(d.str());
        break;
    }

    case DebugCmd::INFO_SOURCE: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        uint64_t pc = p->registers.rip.raw();
        // Buscar en TODOS los executables el que tiene info de
        // debug para ese PC.  Devolvemos el primero que matchea.
        for (const auto &exe : vm_.loader_public.executables) {
            if (!exe || !exe->debug_info) continue;
            debug::LineInfo li =
                exe->debug_info->lookup_line(static_cast<uint32_t>(pc));
            if (li.found) {
                std::ostringstream d;
                d << "{\"file\":\"" << json_escape(li.file ? li.file : "")
                  << "\",\"line\":" << li.line << ",\"pc\":" << pc << "}";
                ok_resp(d.str());
                return;
            }
        }
        // No hay info de debug -> respuesta vacia indicando addr
        // pero sin file/line.
        std::ostringstream d;
        d << "{\"file\":null,\"line\":0,\"pc\":" << pc << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::GC_STATS: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        const gc::GcStats &s = p->gc_heap.stats();
        // Conteo de handles vivos: scan O(N) sobre el slot
        // table.  Aceptable porque debugger no es hot path.
        uint64_t live_count = 0;
        const size_t total_slots = p->gc_heap.handle_table_size();
        for (size_t i = 0; i < total_slots; ++i) {
            if (p->gc_heap.is_handle_live(static_cast<gc::GcHandle>(i))) {
                live_count++;
            }
        }
        std::ostringstream d;
        d << "{"
          << "\"alloc_count\":" << s.alloc_count
          << ",\"alloc_bytes\":" << s.alloc_bytes
          << ",\"freed_count\":" << s.freed_count
          << ",\"freed_bytes\":" << s.freed_bytes
          << ",\"promoted_count\":" << s.promoted_count
          << ",\"promoted_bytes\":" << s.promoted_bytes
          << ",\"minor_gc_count\":" << s.minor_gc_count
          << ",\"major_gc_count\":" << s.major_gc_count
          << ",\"peak_nursery\":" << s.peak_nursery
          << ",\"peak_old\":" << s.peak_old
          << ",\"old_reserved_bytes\":" << s.old_reserved_bytes
          << ",\"old_freelist_bytes\":" << s.old_freelist_bytes
          << ",\"nursery_used\":" << p->gc_heap.nursery_used()
          << ",\"nursery_total\":" << p->gc_heap.nursery_total()
          << ",\"live_handles\":" << live_count
          << ",\"handle_slots\":" << total_slots << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::GC_HANDLES: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string limit_s = json_get(json_msg, "limit");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        size_t limit =
            limit_s.empty() ? 256 : static_cast<size_t>(std::stoul(limit_s));
        if (limit > 4096) limit = 4096; // proteccion
        const size_t total_slots = p->gc_heap.handle_table_size();
        std::ostringstream d;
        d << "[";
        size_t printed = 0;
        for (size_t i = 0; i < total_slots && printed < limit; ++i) {
            auto h = static_cast<gc::GcHandle>(i);
            if (!p->gc_heap.is_handle_live(h)) continue;
            uint8_t *payload = p->gc_heap.deref(h);
            uint32_t sz = p->gc_heap.handle_payload_size(h);
            gc::GcGen gen = p->gc_heap.handle_generation(h);
            // class_ptr -> ClassInfo -> name (puede ser null si
            // el payload no es un ObjectHeader-prefixed).
            std::string cname = "?";
            if (payload && sz >= sizeof(loader::ObjectHeader)) {
                const auto *oh =
                    reinterpret_cast<const loader::ObjectHeader *>(payload);
                if (oh->class_ptr && oh->class_ptr->name.data &&
                    oh->class_ptr->name.size > 0) {
                    cname.assign(reinterpret_cast<const char *>(
                                     oh->class_ptr->name.data),
                                 oh->class_ptr->name.size);
                }
            }
            if (printed > 0) d << ",";
            d << "{\"h\":" << static_cast<unsigned long long>(h)
              << ",\"size\":" << sz << ",\"gen\":\""
              << (gen == gc::GcGen::YOUNG ? "young" : "old") << "\""
              << ",\"addr\":" << reinterpret_cast<uintptr_t>(payload)
              << ",\"class\":\"" << json_escape(cname) << "\"}";
            printed++;
        }
        d << "]";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::GC_INSPECT: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string h_s = json_get(json_msg, "h");
        if (pid_s.empty() || h_s.empty()) {
            err_resp("gc_inspect requiere pid y h");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        gc::GcHandle h = static_cast<gc::GcHandle>(std::stoul(h_s));
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        if (!p->gc_heap.is_handle_live(h)) {
            err_resp("handle muerto o invalido");
            return;
        }
        uint8_t *payload = p->gc_heap.deref(h);
        uint32_t sz = p->gc_heap.handle_payload_size(h);
        if (!payload) {
            err_resp("payload null");
            return;
        }
        // Cap dump a 256 bytes para no sobrecargar el frame del
        // protocolo TCP (4 MB max pero queremos respuestas
        // pequenas para REPL fluido).
        uint32_t dump_n = sz > 256 ? 256 : sz;
        std::ostringstream d;
        d << "{\"h\":" << static_cast<unsigned long long>(h)
          << ",\"size\":" << sz << ",\"gen\":\""
          << (p->gc_heap.handle_generation(h) == gc::GcGen::YOUNG ? "young"
                                                                  : "old")
          << "\",\"addr\":" << reinterpret_cast<uintptr_t>(payload);
        // Header del objeto (24 B).
        if (sz >= sizeof(loader::ObjectHeader)) {
            const auto *oh =
                reinterpret_cast<const loader::ObjectHeader *>(payload);
            std::string cname = "?";
            if (oh->class_ptr && oh->class_ptr->name.data &&
                oh->class_ptr->name.size > 0) {
                cname.assign(
                    reinterpret_cast<const char *>(oh->class_ptr->name.data),
                    oh->class_ptr->name.size);
            }
            // Monitor word empaqueta owner_encoded (48 bits) y lock_depth (16
            // bits). Lo desempacamos via los helpers de loader::ObjectHeader
            // para mantener el campo JSON estable aunque el layout interno
            // cambie.
            const uint64_t mw =
                oh->monitor_word.load(std::memory_order_relaxed);
            d << ",\"class\":\"" << json_escape(cname) << "\""
              << ",\"flags\":" << oh->flags
              << ",\"hash_code\":" << oh->hash_code
              << ",\"owner_pid\":" << loader::monitor_owner(mw)
              << ",\"lock_depth\":" << loader::monitor_depth(mw);
        }
        // Bytes raw (en hex como array).
        d << ",\"bytes\":[";
        for (uint32_t i = 0; i < dump_n; i++) {
            if (i) d << ",";
            d << static_cast<unsigned>(payload[i]);
        }
        d << "],\"truncated\":" << (sz > dump_n ? "true" : "false") << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FLAGS: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        const auto &fl = p->registers.flags;
        std::ostringstream d;
        d << "{\"raw\":" << fl.raw()
          << ",\"sf\":" << static_cast<unsigned>(fl.bits.SF)
          << ",\"zf\":" << static_cast<unsigned>(fl.bits.ZF)
          << ",\"cf\":" << static_cast<unsigned>(fl.bits.CF)
          << ",\"of\":" << static_cast<unsigned>(fl.bits.OF)
          << ",\"dm\":" << static_cast<unsigned>(fl.DM) << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FREGS: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        std::ostringstream d;
        d << "{";
        for (int i = 0; i < 16; i++) {
            if (i) d << ",";
            // bytes bajos = double scalar; los emitimos como bits
            // y como valor f64.  El cliente decide formato.  El
            // banco ZMM tiene 64 bytes; nos quedamos con los 8
            // primeros (representacion f64 escalar en bytes bajos).
            uint64_t bits = 0;
            const uint8_t *raw = p->registers.zmm[i].raw();
            if (raw) std::memcpy(&bits, raw, sizeof(uint64_t));
            double as_f64 = 0.0;
            std::memcpy(&as_f64, &bits, sizeof(double));
            d << "\"f" << i << "_bits\":" << bits;
            // f64 puede ser NaN/Inf -> protegemos con %.17g
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.17g", as_f64);
            d << ",\"f" << i << "_f64\":\"" << buf << "\"";
        }
        d << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::DUMP_STACK: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string n_s = json_get(json_msg, "n");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        uint32_t n = n_s.empty() ? 16 : static_cast<uint32_t>(std::stoul(n_s));
        if (n > 256) n = 256;
        uint64_t rsp = p->registers.stack_pointer.raw();
        uint64_t rbp = p->registers.base_pointer.raw();
        std::ostringstream d;
        d << "{\"rsp\":" << rsp << ",\"rbp\":" << rbp << ",\"qwords\":[";
        for (uint32_t i = 0; i < n; i++) {
            uint64_t addr = rsp + static_cast<uint64_t>(i) * 8;
            uint64_t v = 0;
            p->vm_mem.read_bytes(addr, &v, sizeof(uint64_t));
            if (i) d << ",";
            d << "{\"off\":" << (i * 8) << ",\"addr\":" << addr
              << ",\"v\":" << v << "}";
        }
        d << "]}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FRAME_INFO: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        uint64_t rsp = p->registers.stack_pointer.raw();
        uint64_t rbp = p->registers.base_pointer.raw();
        // Saved rbp esta en [rbp] (push rbp del prologue).
        // ret_addr en [rbp+8] (push del callvm previo).
        uint64_t saved_rbp = 0, ret_addr = 0;
        p->vm_mem.read_bytes(rbp, &saved_rbp, sizeof(uint64_t));
        p->vm_mem.read_bytes(rbp + 8, &ret_addr, sizeof(uint64_t));
        std::ostringstream d;
        d << "{\"rsp\":" << rsp << ",\"rbp\":" << rbp
          << ",\"saved_rbp\":" << saved_rbp << ",\"ret_addr\":" << ret_addr
          << ",\"frame_size\":" << (rbp >= rsp ? rbp - rsp : 0) << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::BACKTRACE: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        // Helper: resolver pc -> {file, line} via DebugInfo.
        auto resolve_src = [&](uint64_t pc) -> std::string {
            for (const auto &exe : vm_.loader_public.executables) {
                if (!exe || !exe->debug_info) continue;
                debug::LineInfo li =
                    exe->debug_info->lookup_line(static_cast<uint32_t>(pc));
                if (li.found) {
                    std::ostringstream s;
                    s << "\"" << json_escape(li.file ? li.file : "") << "\","
                      << "\"line\":" << li.line;
                    return s.str();
                }
            }
            return "null,\"line\":0";
        };
        std::ostringstream d;
        d << "{\"frames\":[";
        // Frame 0 = top (PC actual).
        uint64_t pc0 = p->registers.rip.raw();
        d << "{\"depth\":0,\"pc\":" << pc0 << ",\"file\":" << resolve_src(pc0);
        // Tratar de obtener nombre del metodo del frame_stack si existe.
        if (p->frame_stack && p->frame_stack->method &&
            p->frame_stack->method->name.data &&
            p->frame_stack->method->name.size > 0) {
            std::string mn(reinterpret_cast<const char *>(
                               p->frame_stack->method->name.data),
                           p->frame_stack->method->name.size);
            d << ",\"method\":\"" << json_escape(mn) << "\"";
        } else {
            d << ",\"method\":null";
        }
        d << "}";
        int depth = 1;
        for (loader::FrameHeader *f = p->frame_stack;
             f != nullptr && depth < 64; f = f->prev, depth++) {
            d << ",{\"depth\":" << depth << ",\"return_pc\":" << f->return_pc
              << ",\"file\":" << resolve_src(f->return_pc);
            if (f->method && f->method->name.data && f->method->name.size > 0) {
                std::string mn(
                    reinterpret_cast<const char *>(f->method->name.data),
                    f->method->name.size);
                d << ",\"method\":\"" << json_escape(mn) << "\"";
            } else {
                d << ",\"method\":null";
            }
            d << "}";
        }
        d << "]}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::DISASM: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string addr_s = json_get(json_msg, "addr");
        std::string count_s = json_get(json_msg, "count");
        if (pid_s.empty()) {
            err_resp("falta 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        uint64_t addr =
            addr_s.empty() ? p->registers.rip.raw() : std::stoull(addr_s);
        uint32_t count =
            count_s.empty() ? 16 : static_cast<uint32_t>(std::stoul(count_s));
        if (count > 256) count = 256;
        static constexpr size_t size_bytes_table[] = {1, 2, 4, 6, 8, 10, 11};
        std::ostringstream d;
        d << "{\"start\":" << addr << ",\"items\":[";
        bool first = true;
        // Si encontramos varios opcodes invalidos consecutivos
        // (placeholders edmw4/edmw6 con decode==null) cortamos el
        // walk: estamos leyendo fuera de codigo valido.
        int invalid_streak = 0;
        for (uint32_t i = 0; i < count; ++i) {
            uint8_t b0 = 0;
            p->vm_mem.read_bytes(addr, &b0, 1);
            runtime::InstrFormat *fmt = nullptr;
            uint8_t op_ext = 0;
            bool ext = (b0 == 0x00);
            if (ext) {
                p->vm_mem.read_bytes(addr + 1, &op_ext, 1);
                fmt = &runtime::decode_table_extended[op_ext];
            } else {
                fmt = &runtime::decode_table_primary[b0];
            }
            size_t sz = 1;
            int sm = static_cast<int>(fmt->size);
            if (fmt->size == Assembly::Bytecode::InstrSizeMode::MIXED_SIZE) {
                // MIXED_SIZE: el ctrl byte tras el header lleva el
                // ancho del inmediato en sus bits 7-6
                //   00=8b 01=16b 10=32b 11=64b -> 1/2/4/8 bytes.
                // Tamano total = header (1 o 2) + ctrl + reg? + imm.
                // Para primary: [op][ctrl][imm...]      -> 2 + N
                // Para extended:[0x00][op2][ctrl][imm..] -> 3 + N
                const uint8_t hdr = ext ? 2 : 1;
                uint8_t ctrl = 0;
                p->vm_mem.read_bytes(addr + hdr, &ctrl, 1);
                const uint8_t mode_bits = (ctrl >> 6) & 0x3;
                const size_t imm_n = (mode_bits == 0)   ? 1
                                     : (mode_bits == 1) ? 2
                                     : (mode_bits == 2) ? 4
                                                        : 8;
                sz = static_cast<size_t>(hdr) + 1 + imm_n;
            } else if (sm >= 0 && sm < (int)(sizeof(size_bytes_table) /
                                             sizeof(size_bytes_table[0]))) {
                sz = size_bytes_table[sm];
            }
            if (sz < 1) sz = 1;
            if (sz > 16) sz = 16;
            uint8_t bytes[16] = {0};
            p->vm_mem.read_bytes(addr, bytes, sz);
            if (!first) d << ",";
            first = false;
            const std::string mnemonic =
                fmt && fmt->name ? std::string(fmt->name) : "?";

            // ----------------------------------------------------
            // Decodificacion semantica de operandos.
            //
            // El bytecode VM tiene 7 layouts fisicos posibles
            // (FIXED_1..FIXED_11) y varias "convenciones" para
            // el orden de regs/ctrl/imm.  Aqui los decodificamos
            // sin invocar el decoder real (que requiere un PC
            // mutable y avanza el cursor).
            //
            // Formato comun:
            //   - prefijo: 1 byte (primaria) o 2 bytes (extendida)
            //   - despues vienen N bytes (regs / ctrl / imm)
            //
            // Convenciones de bytes tras el prefijo:
            //   A. ALU (add/sub/mul/...): [ctrl][regs]  donde
            //      ctrl tiene mode/signed/dir y regs = (r2<<4)|r1.
            //   B. String/setcc/tryenter/etc.: [regs1][regs2_o_extra].
            //   C. SIB (FIXED_6): [ctrl][regs] + 4 bytes mas (extra).
            //   D. INMED (MIXED): [ctrl_o_reg][imm de N bytes].
            //
            // Decodificamos por NOMBRE de instruccion + tamano,
            // que es lo mas robusto contra esta heterogeneidad.
            // ----------------------------------------------------
            std::string operands;
            uint64_t jump_target = 0;
            bool has_jump = false;

            auto read_imm_le = [&](size_t off, size_t width) -> uint64_t {
                uint64_t v = 0;
                for (size_t k = 0; k < width && off + k < sz; ++k)
                    v |= static_cast<uint64_t>(bytes[off + k]) << (8 * k);
                return v;
            };

            const uint8_t hdr_len = ext ? 2 : 1;
            auto reg_name = [](uint8_t n) -> std::string {
                return "r" + std::to_string(static_cast<int>(n & 0xF));
            };
            // Convention A (ALU): byte tras el header es ctrl,
            // el siguiente son regs con nibbles (r2<<4)|r1.
            auto regs_alu = [&]() -> std::pair<int, int> {
                if (sz <= hdr_len + 1) return {0, 0};
                const uint8_t regs = bytes[hdr_len + 1];
                return {regs & 0xF, (regs >> 4) & 0xF};
            };
            // Convention B (string/setcc/etc.): primer byte tras el
            // header ya tiene los regs con nibbles (r2<<4)|r1, el
            // segundo es "extra" (encoding, cond, etc.).
            auto regs_b = [&]() -> std::pair<int, int> {
                if (sz <= hdr_len) return {0, 0};
                const uint8_t regs = bytes[hdr_len];
                return {regs & 0xF, (regs >> 4) & 0xF};
            };
            auto width_for_mode = [](uint8_t mode_bits) -> int {
                switch (mode_bits & 0x3) {
                case 0: return 8;
                case 1: return 16;
                case 2: return 32;
                case 3: return 64;
                }
                return 64;
            };

            // ============== Decodificacion por nombre =============

            // ALU reg-reg (FIXED_4, Convention A): add/sub/mul/div/
            // cmp/and/or/xor/shl/shr/sar/mods/mov/movc + variantes
            // signed/unsigned.  Suelen tener size 4.
            static const std::unordered_set<std::string> ALU_REG_REG = {
                "adds", "addu", "subs", "subu", "muls", "mulu", "divs",
                "divu", "mods", "modu", "cmps", "cmpu", "cmp",  "and",
                "or",   "xor",  "not",  "shl",  "shr",  "sar",  "neg",
                "mov",  "movc", "add",  "sub",  "mul",  "div",
            };
            // ALU 3-operandos (FIXED_4, Convention B): byte2=(r_src1<<4)|r_dst,
            // byte3=(r_src2<<4)|flags.
            static const std::unordered_set<std::string> ALU_3OP = {
                "adds3", "subs3", "muls3", "addu3", "subu3",
                "mulu3", "and3",  "or3",   "xor3",
            };
            // String / setcc / tryenter / etc. (FIXED_4, Convention B).
            static const std::unordered_set<std::string> CONV_B_REG_REG = {
                "strmake",     "strcat",     "strcmp",       "strconv",
                "strlen",      "strraw",     "strgetbytes",  "strgetkind",
                "strgetenc",   "strslice",   "strflat",      "strhash",
                "strintern",   "strreserve", "strfinalize",  "strflag",
                "setcc",       "tryenter",   "gchandle",     "loadz",
                "loadzh",      "callvirt",   "callm",        "defclass",
                "deffield",    "defmethod",  "findclass",    "findmethod",
                "findfield",   "addadvice",  "msgsend",      "msgrecv",
                "memsync",     "spawnon",    "spawnargs",    "weakref",
                "deref_weak",  "free_weak",  "monenter",     "monexit",
                "monwait",     "monnoti",    "monnota",      "specialize",
                "rspawn",      "future",     "await",        "fulfill",
                "reject",      "fulfillhlt", "panic",        "setmethdbg",
                "loadmod",     "fextend",    "fnarrow",      "dlopen",
                "dlsym",       "callni",     "gcallocp",     "checkcast",
                "instanceof",  "newobj",     "alloc",        "free",
                "fadd",        "fsub",       "fmul",         "fdiv",
                "fmin",        "fmax",       "fcmp",         "fsqrt",
                "fabs",        "fneg",       "fcvt",         "fmov",
                "fload",       "fstore",     "ldarg",        "starg",
                "mvtake",      "jumptable",  "typeswitch",   "mkclosure",
                "callclosure", "tailcall",   "mkrawclosure", "callrawclosure",
                "isnull",      "unwrap",     "decjnz",
            };

            // Deteccion de opcodes invalidos / placeholders.
            // edmw4 / edmw6 son entradas de relleno en la tabla
            // extendida (decode_table_extended[0x00..0x01]), no
            // representan instrucciones reales.  Si hay 3 o mas
            // consecutivos asumimos que cruzamos la frontera del
            // codigo valido y abortamos el desensamblado.
            const bool is_invalid_placeholder =
                (mnemonic == "edmw4" || mnemonic == "edmw6" ||
                 mnemonic == "?" ||
                 fmt->mode == Assembly::Bytecode::AddressingMode::COUNT);
            if (is_invalid_placeholder) {
                ++invalid_streak;
                if (invalid_streak >= 3) {
                    // El comma + first=false ya se emitieron arriba
                    // (justo despues de leer bytes); aqui solo
                    // añadimos el item sentinel y rompemos el walk.
                    d << "{\"addr\":" << addr << ",\"opcode\":0,\"ext\":false,"
                      << "\"name\":\"(fin)\",\"size\":0,"
                      << "\"bytes\":\"\","
                      << "\"operands\":\"--- fin de codigo valido ---\"}";
                    break;
                }
            } else {
                invalid_streak = 0;
            }

            // Atajo: instrucciones sin operandos segun InstrFormat.
            // Cubre vminfo, vminfomanager, hlt, ret, nop, proceed,
            // tryleave, getproc/getvm/getmgr/getpid y futuras
            // sin necesidad de mantener una lista de mnemonics.
            if (fmt->mode == Assembly::Bytecode::AddressingMode::NONE) {
                // sin operandos visibles
            }
            // Saltos.
            else if (mnemonic == "jmpr") {
                // jmpr rN: 2 bytes [0x15][reg]
                if (sz >= 2) {
                    operands = reg_name(bytes[1]);
                }
            } else if (mnemonic.rfind("jmp", 0) == 0 && mnemonic != "jmpr") {
                // jmp.cc target_imm: el imm sigue al header.  Su
                // tamano depende del FIXED_*: para FIXED_2 es u8,
                // FIXED_4 -> u16/u32, FIXED_8 -> u32/u64, ...
                const size_t imm_n = sz > hdr_len ? sz - hdr_len : 0;
                if (imm_n > 0) {
                    jump_target = read_imm_le(hdr_len, imm_n);
                    has_jump = true;
                }
            } else if (mnemonic == "callvm" || mnemonic == "callvmr") {
                // callvm @Absolute(...): u64 en bytes[hdr_len..]
                if (sz >= hdr_len + 8) {
                    jump_target = read_imm_le(hdr_len, 8);
                    has_jump = true;
                }
            } else if (mnemonic.rfind("cmpjmp", 0) == 0 && sz >= hdr_len + 6) {
                // [hdr][b2=(r_a<<4)|r_b][cond][target_u32_LE]
                const uint8_t b2 = bytes[hdr_len];
                const uint8_t cond = bytes[hdr_len + 1];
                jump_target = read_imm_le(hdr_len + 2, 4);
                has_jump = true;
                std::ostringstream s;
                s << "r" << (b2 & 0xF) << ", r" << ((b2 >> 4) & 0xF)
                  << ", cc=" << (int)cond;
                operands = s.str();
            } else if (mnemonic == "subsp" || mnemonic == "addsp") {
                if (sz >= hdr_len + 1 + 8) {
                    const uint8_t ctrl = bytes[hdr_len];
                    const uint64_t imm = read_imm_le(hdr_len + 1, 8);
                    const char *which = (ctrl & 1) ? "rbp" : "rsp";
                    std::ostringstream s;
                    s << which << ", 0x" << std::hex << imm << std::dec;
                    operands = s.str();
                }
            } else if (mnemonic == "push" || mnemonic == "pop") {
                if (sz >= 2) operands = reg_name(bytes[1]);
            } else if (mnemonic == "getstatic" || mnemonic == "setstatic") {
                if (sz >= hdr_len + 6) {
                    const uint8_t regs = bytes[hdr_len];
                    const uint64_t off = read_imm_le(hdr_len + 2, 4);
                    std::ostringstream s;
                    s << "r" << (regs & 0xF) << ", r" << ((regs >> 4) & 0xF)
                      << ", +0x" << std::hex << off << std::dec;
                    operands = s.str();
                }
            } else if (ALU_REG_REG.count(mnemonic) > 0 && sz >= hdr_len + 2) {
                // Convention A: byte ctrl + byte regs.
                const uint8_t ctrl = bytes[hdr_len];
                const auto rr = regs_alu();
                const int w = width_for_mode((ctrl >> 6) & 0x3);
                std::ostringstream s;
                s << "r" << rr.first << ", r" << rr.second << "  (w=" << w
                  << ")";
                operands = s.str();
            } else if (ALU_3OP.count(mnemonic) > 0 && sz >= hdr_len + 2) {
                // [hdr][b2=(r_src1<<4)|r_dst][b3=(r_src2<<4)|flags]
                const uint8_t b2 = bytes[hdr_len];
                const uint8_t b3 = bytes[hdr_len + 1];
                std::ostringstream s;
                s << "r" << (b2 & 0xF) << ", r" << ((b2 >> 4) & 0xF) << ", r"
                  << ((b3 >> 4) & 0xF);
                operands = s.str();
            } else if (CONV_B_REG_REG.count(mnemonic) > 0 &&
                       sz >= hdr_len + 1) {
                // Convention B: regs = (r2<<4)|r1 en byte tras hdr.
                const auto rr = regs_b();
                std::ostringstream s;
                s << "r" << rr.first << ", r" << rr.second;
                if (sz >= hdr_len + 2) {
                    const uint8_t extra = bytes[hdr_len + 1];
                    if (extra != 0) {
                        s << ", 0x" << std::hex << static_cast<int>(extra)
                          << std::dec;
                    }
                }
                operands = s.str();
            }

            // Caso especial: ALU con immediate (MIXED_SIZE).
            // El primer byte tras hdr es ctrl, le sigue el reg, luego imm.
            if (operands.empty() && sz >= hdr_len + 3 && sz <= 11) {
                // Heuristica generica para los formatos largos:
                //   [hdr][ctrl][reg_byte][imm de N bytes]
                const uint8_t ctrl = bytes[hdr_len];
                const uint8_t reg = bytes[hdr_len + 1];
                const size_t imm_n = sz - hdr_len - 2;
                if (imm_n >= 1 && imm_n <= 8) {
                    const uint64_t imm = read_imm_le(hdr_len + 2, imm_n);
                    const int w = width_for_mode((ctrl >> 6) & 0x3);
                    std::ostringstream s;
                    s << "r" << (reg & 0xF) << ", 0x" << std::hex << imm
                      << std::dec << "  (w=" << w << ")";
                    operands = s.str();
                }
            }

            // Salida final: si quedo vacio, al menos volcamos los
            // bytes raw post-header para que NO se vea linea pelada.
            if (operands.empty() && sz > hdr_len) {
                std::ostringstream s;
                s << "raw=";
                for (size_t k = hdr_len; k < sz; ++k) {
                    char buf[4];
                    std::snprintf(buf, sizeof(buf), "%02x", bytes[k]);
                    s << buf;
                }
                operands = s.str();
            }

            if (has_jump) {
                std::ostringstream s;
                s << "-> 0x" << std::hex << jump_target << std::dec;
                if (operands.empty())
                    operands = s.str();
                else
                    operands += "   " + s.str();
            }

            d << "{\"addr\":" << addr
              << ",\"opcode\":" << (ext ? (int)op_ext : (int)b0)
              << ",\"ext\":" << (ext ? "true" : "false") << ",\"name\":\""
              << json_escape(mnemonic) << "\",\"size\":" << sz
              << ",\"bytes\":\"";
            for (size_t k = 0; k < sz; ++k) {
                char buf[4];
                std::snprintf(buf, sizeof(buf), "%02x", bytes[k]);
                d << buf;
            }
            d << "\"";
            if (!operands.empty()) {
                d << ",\"operands\":\"" << json_escape(operands) << "\"";
            }
            if (has_jump) {
                d << ",\"jump_target\":" << jump_target;
            }
            d << "}";
            addr += sz;
        }
        d << "]}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::LOCALS: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        uint64_t pc = p->registers.rip.raw();
        uint64_t rbp = p->registers.base_pointer.raw();
        std::vector<debug::VarInfo> vars;
        for (const auto &exe : vm_.loader_public.executables) {
            if (!exe || !exe->debug_info) continue;
            auto v = exe->debug_info->lookup_vars(static_cast<uint32_t>(pc));
            if (!v.empty()) {
                vars = std::move(v);
                break;
            }
        }
        std::ostringstream d;
        d << "{\"pc\":" << pc << ",\"rbp\":" << rbp << ",\"vars\":[";
        bool first = true;
        for (const auto &v : vars) {
            if (!first) d << ",";
            first = false;
            int64_t off = static_cast<int64_t>(v.stack_offset);
            uint64_t addr = (off >= 0) ? rbp + static_cast<uint64_t>(off)
                                       : rbp - static_cast<uint64_t>(-off);
            uint64_t value = 0;
            p->vm_mem.read_bytes(addr, &value, sizeof(uint64_t));
            d << "{\"name\":\"" << json_escape(v.name ? v.name : "")
              << "\",\"offset\":" << off << ",\"addr\":" << addr
              << ",\"value\":" << value << ",\"type\":" << (int)v.type_kind
              << ",\"flags\":" << (int)v.var_flags << "}";
        }
        d << "]}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::GC_RUN: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        auto count_live = [&]() -> size_t {
            size_t n = 0;
            size_t total = p->gc_heap.handle_table_size();
            for (size_t i = 0; i < total; ++i) {
                if (p->gc_heap.is_handle_live(static_cast<gc::GcHandle>(i)))
                    ++n;
            }
            return n;
        };
        size_t before = count_live();
        p->gc_heap.major_gc();
        size_t after = count_live();
        std::ostringstream d;
        d << "{\"before\":" << before << ",\"after\":" << after
          << ",\"freed\":" << (before > after ? before - after : 0) << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::STEP_OUT: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        if (!p->frame_stack) {
            err_resp("step_out: el proceso no tiene frame OOP activo");
            return;
        }
        uint64_t ret_pc = p->frame_stack->return_pc;
        Breakpoint bp{};
        {
            std::lock_guard<std::mutex> lk(bp_mutex_);
            bp.id = next_bp_id_++;
            bp.addr = ret_pc;
            bp.pid = pid;
            bp.enabled = true;
            bp.hit_count = 0;
            bp.one_shot = true;
            breakpoints_.push_back(bp);
            any_bp_.store(true, std::memory_order_relaxed);
        }
        {
            std::lock_guard<std::mutex> lk(proc_mutex_);
            auto it = proc_ctx_.find(pid);
            if (it != proc_ctx_.end()) {
                it->second.state = DbgProcState::RUNNING;
                it->second.step_mode = false;
                it->second.pause_cv.notify_all();
                any_step_.store(any_step_or_paused_locked(proc_ctx_),
                                std::memory_order_release);
            }
        }
        std::ostringstream d;
        d << "{\"target_pc\":" << ret_pc << ",\"bp_id\":" << bp.id << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::STEP_UNTIL: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string file_s = json_get(json_msg, "file");
        std::string line_s = json_get(json_msg, "line");
        std::string addr_s = json_get(json_msg, "addr");
        if (pid_s.empty()) {
            err_resp("falta 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        uint64_t target = 0;
        if (!addr_s.empty()) {
            target = std::stoull(addr_s);
        } else if (!file_s.empty() && !line_s.empty()) {
            uint32_t target_line = (uint32_t)std::stoul(line_s);
            uint32_t off = UINT32_MAX;
            for (const auto &exe : vm_.loader_public.executables) {
                if (!exe || !exe->debug_info) continue;
                off = exe->debug_info->lookup_offset_for_line(file_s,
                                                              target_line);
                if (off != UINT32_MAX) break;
            }
            if (off == UINT32_MAX) {
                err_resp("until: file:line no encontrado en debug info");
                return;
            }
            target = off;
        } else {
            err_resp("until: requiere 'addr' o ('file'+'line')");
            return;
        }
        Breakpoint bp{};
        {
            std::lock_guard<std::mutex> lk(bp_mutex_);
            bp.id = next_bp_id_++;
            bp.addr = target;
            bp.pid = pid;
            bp.enabled = true;
            bp.hit_count = 0;
            bp.one_shot = true;
            breakpoints_.push_back(bp);
            any_bp_.store(true, std::memory_order_relaxed);
        }
        {
            std::lock_guard<std::mutex> lk(proc_mutex_);
            auto it = proc_ctx_.find(pid);
            if (it != proc_ctx_.end()) {
                it->second.state = DbgProcState::RUNNING;
                it->second.step_mode = false;
                it->second.pause_cv.notify_all();
                any_step_.store(any_step_or_paused_locked(proc_ctx_),
                                std::memory_order_release);
            }
        }
        std::ostringstream d;
        d << "{\"target_pc\":" << target << ",\"bp_id\":" << bp.id << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::SET_WATCH: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string h_s = json_get(json_msg, "handle");
        if (h_s.empty()) {
            err_resp("falta 'handle'");
            return;
        }
        uint64_t pid = pid_s.empty() ? 0 : std::stoull(pid_s);
        uint64_t h = std::stoull(h_s);
        Watchpoint wp{};
        {
            std::lock_guard<std::mutex> lk(watch_mutex_);
            wp.id = next_watch_id_++;
            wp.pid = pid;
            wp.handle = h;
            wp.enabled = true;
            runtime::ProcessVM *p =
                pid ? find_process_by_pid(vm_, pid) : nullptr;
            if (!p) {
                for (auto &sched : vm_.schedulers) {
                    for (auto &px : sched->processes) {
                        if (px) {
                            p = px.get();
                            break;
                        }
                    }
                    if (p) break;
                }
            }
            if (p && p->gc_heap.is_handle_live(static_cast<gc::GcHandle>(h))) {
                wp.was_alive = true;
                wp.last_addr = reinterpret_cast<uint64_t>(
                    p->gc_heap.deref(static_cast<gc::GcHandle>(h)));
            } else {
                wp.was_alive = false;
                wp.last_addr = 0;
            }
            watchpoints_.push_back(wp);
            any_watch_.store(true, std::memory_order_relaxed);
        }
        std::ostringstream d;
        d << "{\"id\":" << wp.id << ",\"handle\":" << wp.handle
          << ",\"alive\":" << (wp.was_alive ? "true" : "false")
          << ",\"addr\":" << wp.last_addr << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::DEL_WATCH: {
        std::string id_s = json_get(json_msg, "id");
        if (id_s.empty()) {
            err_resp("falta 'id'");
            return;
        }
        uint32_t wid = (uint32_t)std::stoul(id_s);
        {
            std::lock_guard<std::mutex> lk(watch_mutex_);
            watchpoints_.erase(std::remove_if(watchpoints_.begin(),
                                              watchpoints_.end(),
                                              [wid](const Watchpoint &w) {
                                                  return w.id == wid;
                                              }),
                               watchpoints_.end());
            any_watch_.store(!watchpoints_.empty(), std::memory_order_relaxed);
        }
        ok_resp("{}");
        break;
    }

    case DebugCmd::LIST_WATCHES: {
        std::ostringstream d;
        d << "[";
        {
            std::lock_guard<std::mutex> lk(watch_mutex_);
            bool first = true;
            for (const auto &w : watchpoints_) {
                if (!first) d << ",";
                first = false;
                d << "{\"id\":" << w.id << ",\"pid\":" << w.pid
                  << ",\"handle\":" << w.handle
                  << ",\"enabled\":" << (w.enabled ? "true" : "false")
                  << ",\"alive\":" << (w.was_alive ? "true" : "false")
                  << ",\"addr\":" << w.last_addr << "}";
            }
        }
        d << "]";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::TRACE_MSGS: {
        std::string pid_s = json_get(json_msg, "pid");
        std::string en_s = json_get(json_msg, "enabled");
        if (pid_s.empty()) {
            err_resp("falta 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        bool en = (en_s == "true" || en_s == "1");
        {
            std::lock_guard<std::mutex> lk(trace_mutex_);
            if (en)
                traced_msg_pids_.insert(pid);
            else
                traced_msg_pids_.erase(pid);
            any_msg_trace_.store(!traced_msg_pids_.empty(),
                                 std::memory_order_relaxed);
        }
        ok_resp("{}");
        break;
    }

    case DebugCmd::BREAK_MON: {
        std::string en_s = json_get(json_msg, "enabled");
        bool en = (en_s == "true" || en_s == "1");
        break_on_mon_.store(en, std::memory_order_relaxed);
        ok_resp("{}");
        break;
    }

    case DebugCmd::PAUSE: {
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        {
            std::lock_guard<std::mutex> lk(proc_mutex_);
            DbgProcCtx &ctx = get_or_create_ctx(pid);
            ctx.state = DbgProcState::PAUSED;
            ctx.step_mode = true; // parar en la proxima instruccion
            any_step_.store(true, std::memory_order_release);
        }
        ok_resp("{}");
        break;
    }

        /* ============================================================
         * Comandos del modo --server-mode (servidor persistente).
         *
         * Estos comandos solo tienen sentido cuando la VM se arranca
         * con --server-mode (vm_persistent=true), pero son seguros de
         * invocar en cualquier modo: load_velb añade un nuevo proceso
         * a un scheduler existente y kill_proc marca uno DEAD.
         * ============================================================ */

    case DebugCmd::LOAD_VELB: {
        // Cargar un .velb desde el filesystem del servidor.
        // Campos JSON:
        //   path       (string, requerido) - ruta al .velb
        //   start      (bool, opcional, default true) - si true,
        //              hace make_ready inmediatamente; si false,
        //              el proceso queda en NEW para que el cliente
        //              pueda preparar breakpoints antes de arrancar
        //   pause      (bool, opcional, default false) - si true,
        //              ademas marca pause_at_start (state=PAUSED
        //              en el primer on_before_exec).
        //   args       (array de strings, opcional) - se pasan al
        //              programa como script_args (vm->script_args).
        std::string path = json_get(json_msg, "path");
        if (path.empty()) {
            err_resp("falta campo 'path'");
            return;
        }
        std::string start_s = json_get(json_msg, "start");
        bool do_start =
            (start_s.empty() || start_s == "true" || start_s == "1");
        std::string pause_s = json_get(json_msg, "pause");
        bool do_pause = (pause_s == "true" || pause_s == "1");

        // Resolver el path a traves del sandbox.  Si no hay
        // sandbox, se mantiene la ruta tal cual (back-compat).
        std::filesystem::path resolved_path;
        std::string sb_err;
        if (!resolve_sandbox_path(server_root_, path, resolved_path, sb_err)) {
            err_resp(sb_err);
            return;
        }
        try {
            runtime::ProcessVM *p =
                vm_.mgr_vm.loader.load_executable(vm_, resolved_path.string());
            if (!p) {
                err_resp("load_executable devolvio nullptr");
                return;
            }
            if (do_pause) {
                // PAUSE_AT_START antes de make_ready: cuando el
                // scheduler invoque on_before_exec por primera vez,
                // el proceso quedara bloqueado en cv.wait hasta que
                // el cliente emita 'continue <pid>'.
                pause_at_start(p->pid.local_pid);
            }
            if (do_start) {
                vm_.make_ready(p->pid);
            }
            std::ostringstream d;
            d << "{\"pid\":" << p->pid.local_pid
              << ",\"sched_id\":" << p->pid.scheduler_id << ",\"state\":\""
              << runtime::vm_state_to_str(p->state.load())
              << "\",\"started\":" << (do_start ? "true" : "false")
              << ",\"paused\":" << (do_pause ? "true" : "false")
              << ",\"path\":\"" << json_escape(resolved_path.string()) << "\"}";
            ok_resp(d.str());
        } catch (const std::exception &e) {
            err_resp(std::string("load_velb fallo: ") + e.what());
        }
        break;
    }

    case DebugCmd::KILL_PROC: {
        // Marca el proceso indicado como DEAD para que el scheduler
        // lo libere en su proxima iteracion.  Si esta pausado en el
        // debugger, ademas notifica su pause_cv para que salga del
        // cv.wait y observe que esta DEAD/DETACHED.
        std::string pid_s = json_get(json_msg, "pid");
        if (pid_s.empty()) {
            err_resp("falta campo 'pid'");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        // Transicion directa a DEAD via store atomico.  El
        // scheduler ve el estado en su proxima vuelta y lo deja de
        // ejecutar.  El recurso se libera cuando el scheduler
        // limpie la lista de procesos.
        p->state.store(runtime::DEAD, std::memory_order_release);
        // Despertar el cv.wait del debugger si el proceso esta
        // pausado en breakpoint o step.
        {
            std::lock_guard<std::mutex> lk(proc_mutex_);
            auto it = proc_ctx_.find(pid);
            if (it != proc_ctx_.end()) {
                it->second.state = DbgProcState::DETACHED;
                it->second.step_mode = false;
                it->second.pause_cv.notify_all();
            }
        }
        // Si el scheduler estaba bloqueado en su semaforo (no
        // tenia procesos READY), tambien lo despertamos por si
        // este era el unico proceso vivo y debe re-evaluar.
        for (auto &sched : vm_.schedulers) {
            if (sched && sched->is_waiting) {
                sched->sem.release();
            }
        }
        ok_resp("{\"pid\":" + pid_s + ",\"state\":\"DEAD\"}");
        break;
    }

    case DebugCmd::SERVER_INFO: {
        // Informacion del servidor: uptime, numero de schedulers,
        // numero de procesos en cada estado, modo persistente.
        using namespace std::chrono;
        auto uptime =
            duration_cast<seconds>(steady_clock::now() - g_server_start_time)
                .count();
        size_t n_procs = 0;
        size_t n_alive = 0;
        size_t n_dead = 0;
        size_t n_halt = 0;
        for (auto &sched : vm_.schedulers) {
            for (auto &p : sched->processes) {
                if (!p) continue;
                ++n_procs;
                auto st = p->state.load();
                if (st == runtime::DEAD)
                    ++n_dead;
                else if (st == runtime::HALT)
                    ++n_halt;
                else
                    ++n_alive;
            }
        }
        std::ostringstream d;
        d << "{\"uptime_sec\":" << uptime
          << ",\"schedulers\":" << vm_.schedulers.size()
          << ",\"persistent\":" << (vm_.vm_persistent.load() ? "true" : "false")
          << ",\"vm_running\":" << (vm_.vm_running.load() ? "true" : "false")
          << ",\"clients\":";
        {
            std::lock_guard<std::mutex> lk(client_mutex_);
            d << client_fds_.size();
        }
        d << ",\"procs\":{"
          << "\"total\":" << n_procs << ",\"alive\":" << n_alive
          << ",\"halt\":" << n_halt << ",\"dead\":" << n_dead
          << "},\"port\":" << port_ << ",\"shutdown_hooked\":"
          << (g_server_shutdown_flag != nullptr ? "true" : "false")
          << ",\"auth_required\":" << (auth_required_ ? "true" : "false")
          << ",\"auth_enabled\":"
          << (AuthManager::instance().is_enabled() ? "true" : "false")
          << ",\"sandbox\":\""
          << (server_root_.empty() ? "" : json_escape(server_root_)) << "\"}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::SERVER_SHUTDOWN: {
        // Apagar el servidor persistente.  Si el hook esta
        // registrado (main.cpp lo hace en --server-mode), pone el
        // atomic a false y el bucle de espera del main termina.
        // Si NO esta registrado, devolvemos error claro -- la VM
        // no se cerraria sola y dejariamos al cliente colgado.
        if (g_server_shutdown_flag == nullptr) {
            err_resp("server_shutdown solo es valido en modo "
                     "--server-mode (hook no registrado)");
            return;
        }
        ok_resp("{\"shutdown\":true}");
        g_server_shutdown_flag->store(false, std::memory_order_release);
        break;
    }

        /* ============================================================
         * Autenticacion y gestion de usuarios.
         * ============================================================ */

    case DebugCmd::AUTH_LOGIN: {
        if (!AuthManager::instance().is_enabled()) {
            err_resp("auth no esta habilitado en este servidor");
            return;
        }
        std::string user = json_get(json_msg, "username");
        std::string pass = json_get(json_msg, "password");
        std::string ttl_s = json_get(json_msg, "ttl");
        uint32_t ttl = 3600;
        if (!ttl_s.empty()) {
            try {
                ttl = static_cast<uint32_t>(std::stoul(ttl_s));
            } catch (...) { /* ignore, mantener default */
            }
        }
        AuthResult r = AuthManager::instance().login(user, pass, ttl);
        if (!r.ok) {
            err_resp(r.error);
            return;
        }
        std::ostringstream d;
        d << "{\"token\":\"" << json_escape(r.token) << "\""
          << ",\"username\":\"" << json_escape(r.username) << "\""
          << ",\"role\":\"" << role_to_string(r.role) << "\""
          << ",\"ttl_sec\":" << ttl << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::AUTH_LOGOUT: {
        std::string tok = json_get(json_msg, "session_token");
        if (tok.empty()) tok = json_get(json_msg, "token");
        if (tok.empty()) {
            err_resp("falta campo 'session_token'");
            return;
        }
        AuthManager::instance().logout(tok);
        ok_resp("{\"logged_out\":true}");
        break;
    }

    case DebugCmd::AUTH_WHOAMI: {
        std::string tok = json_get(json_msg, "session_token");
        if (tok.empty()) tok = json_get(json_msg, "token");
        Session sess;
        if (!AuthManager::instance().validate_token(tok, &sess)) {
            err_resp("session_token invalido o expirado");
            return;
        }
        std::ostringstream d;
        d << "{\"username\":\"" << json_escape(sess.username) << "\""
          << ",\"role\":\"" << role_to_string(sess.role) << "\"}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::AUTH_CREATE_USER: {
        std::string user = json_get(json_msg, "username");
        std::string pass = json_get(json_msg, "password");
        std::string role_s = json_get(json_msg, "role");
        if (user.empty() || pass.empty()) {
            err_resp("faltan 'username' y/o 'password'");
            return;
        }
        Role role = role_s.empty() ? Role::VIEWER : role_from_string(role_s);
        std::string e;
        if (!AuthManager::instance().create_user(user, pass, role, &e)) {
            err_resp("no se pudo crear usuario: " + e);
            return;
        }
        std::ostringstream d;
        d << "{\"username\":\"" << json_escape(user) << "\""
          << ",\"role\":\"" << role_to_string(role) << "\"}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::AUTH_DELETE_USER: {
        std::string user = json_get(json_msg, "username");
        if (user.empty()) {
            err_resp("falta 'username'");
            return;
        }
        std::string e;
        if (!AuthManager::instance().delete_user(user, &e)) {
            err_resp("no se pudo eliminar: " + e);
            return;
        }
        ok_resp("{\"deleted\":true}");
        break;
    }

    case DebugCmd::AUTH_LIST_USERS: {
        auto users = AuthManager::instance().list_users();
        std::ostringstream d;
        d << "[";
        bool first = true;
        for (auto &u : users) {
            if (!first) d << ",";
            first = false;
            d << "{\"username\":\"" << json_escape(u.first) << "\""
              << ",\"role\":\"" << role_to_string(u.second) << "\"}";
        }
        d << "]";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::AUTH_CHANGE_PASS: {
        // Si el cliente pasa "username", debe tener rol ADMIN
        // (ya verificado por el gate).  Si no, cambia su propia
        // contrasenya leyendo el username de la sesion.
        std::string user = json_get(json_msg, "username");
        std::string pass = json_get(json_msg, "password");
        if (pass.empty()) {
            err_resp("falta 'password'");
            return;
        }
        if (user.empty()) {
            // sin username explicito: la propia
            std::string tok = json_get(json_msg, "session_token");
            if (tok.empty()) tok = json_get(json_msg, "token");
            Session s;
            if (!AuthManager::instance().validate_token(tok, &s)) {
                err_resp("falta 'username' o session valida");
                return;
            }
            user = s.username;
        }
        std::string e;
        if (!AuthManager::instance().change_password(user, pass, &e)) {
            err_resp("no se pudo cambiar: " + e);
            return;
        }
        ok_resp("{\"changed\":true,\"username\":\"" + json_escape(user) +
                "\"}");
        break;
    }

        /* ============================================================
         * Transferencia de archivos.
         *
         * Todas las rutas pasan por resolve_sandbox_path() que valida
         * el sandbox @c server_root_.  El contenido binario se
         * empaqueta en base64 dentro del JSON.
         * ============================================================ */

    case DebugCmd::FS_WRITE: {
        std::string path = json_get(json_msg, "path");
        std::string b64 = json_get(json_msg, "content_b64");
        std::string app_s = json_get(json_msg, "append");
        if (path.empty()) {
            err_resp("falta 'path'");
            return;
        }
        std::filesystem::path resolved;
        std::string e;
        if (!resolve_sandbox_path(server_root_, path, resolved, e)) {
            err_resp(e);
            return;
        }
        std::vector<uint8_t> bytes;
        if (!b64.empty() && !b64_decode(b64, bytes)) {
            err_resp("content_b64 invalido");
            return;
        }
        bool append = (app_s == "true" || app_s == "1");
        std::error_code ec;
        std::filesystem::create_directories(resolved.parent_path(), ec);
        std::ofstream ofs(resolved,
                          std::ios::binary |
                              (append ? std::ios::app : std::ios::trunc));
        if (!ofs) {
            err_resp("no se pudo abrir para escritura");
            return;
        }
        if (!bytes.empty()) {
            ofs.write(reinterpret_cast<const char *>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        }
        ofs.close();
        std::ostringstream d;
        d << "{\"path\":\"" << json_escape(resolved.string()) << "\""
          << ",\"bytes\":" << bytes.size()
          << ",\"append\":" << (append ? "true" : "false") << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FS_READ: {
        std::string path = json_get(json_msg, "path");
        std::string off_s = json_get(json_msg, "offset");
        std::string len_s = json_get(json_msg, "length");
        if (path.empty()) {
            err_resp("falta 'path'");
            return;
        }
        std::filesystem::path resolved;
        std::string e;
        if (!resolve_sandbox_path(server_root_, path, resolved, e)) {
            err_resp(e);
            return;
        }
        std::ifstream ifs(resolved, std::ios::binary);
        if (!ifs) {
            err_resp("no se pudo abrir para lectura");
            return;
        }
        ifs.seekg(0, std::ios::end);
        std::streamsize total = ifs.tellg();
        if (total < 0) {
            err_resp("tamano invalido");
            return;
        }
        uint64_t off = 0, len = static_cast<uint64_t>(total);
        if (!off_s.empty()) {
            try {
                off = std::stoull(off_s);
            } catch (...) {
            }
        }
        if (!len_s.empty()) {
            try {
                len = std::stoull(len_s);
            } catch (...) {
            }
        }
        if (off > static_cast<uint64_t>(total)) off = total;
        uint64_t avail = static_cast<uint64_t>(total) - off;
        if (len > avail) len = avail;
        // Limite defensivo: 16 MB por lectura (clientes mayores hacen chunks).
        constexpr uint64_t MAX_READ = 16ull * 1024 * 1024;
        if (len > MAX_READ) {
            err_resp("length > 16MB; usa chunks (offset/length)");
            return;
        }
        ifs.seekg(static_cast<std::streamoff>(off), std::ios::beg);
        std::vector<uint8_t> buf(static_cast<size_t>(len));
        if (len > 0)
            ifs.read(reinterpret_cast<char *>(buf.data()),
                     static_cast<std::streamsize>(len));
        std::string enc = b64_encode(buf.data(), buf.size());
        std::ostringstream d;
        d << "{\"path\":\"" << json_escape(resolved.string()) << "\""
          << ",\"total_size\":" << total << ",\"offset\":" << off
          << ",\"length\":" << len << ",\"content_b64\":\"" << enc << "\"}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FS_LIST: {
        std::string path = json_get(json_msg, "path");
        if (path.empty()) path = ".";
        std::filesystem::path resolved;
        std::string e;
        if (!resolve_sandbox_path(server_root_, path, resolved, e)) {
            err_resp(e);
            return;
        }
        std::error_code ec;
        if (!std::filesystem::is_directory(resolved, ec)) {
            err_resp("no es un directorio");
            return;
        }
        std::ostringstream d;
        d << "{\"path\":\"" << json_escape(resolved.string()) << "\""
          << ",\"entries\":[";
        bool first = true;
        for (auto &ent : std::filesystem::directory_iterator(resolved, ec)) {
            if (!first) d << ",";
            first = false;
            std::error_code lec;
            auto status = ent.status(lec);
            const char *kind = "other";
            if (std::filesystem::is_directory(status))
                kind = "dir";
            else if (std::filesystem::is_regular_file(status))
                kind = "file";
            else if (std::filesystem::is_symlink(status))
                kind = "symlink";
            uintmax_t sz = 0;
            if (std::filesystem::is_regular_file(status)) {
                sz = std::filesystem::file_size(ent.path(), lec);
                if (lec) sz = 0;
            }
            d << "{\"name\":\"" << json_escape(ent.path().filename().string())
              << "\""
              << ",\"kind\":\"" << kind << "\""
              << ",\"size\":" << sz << "}";
        }
        d << "]}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FS_STAT: {
        std::string path = json_get(json_msg, "path");
        if (path.empty()) {
            err_resp("falta 'path'");
            return;
        }
        std::filesystem::path resolved;
        std::string e;
        if (!resolve_sandbox_path(server_root_, path, resolved, e)) {
            err_resp(e);
            return;
        }
        std::error_code ec;
        bool exists = std::filesystem::exists(resolved, ec);
        std::ostringstream d;
        d << "{\"path\":\"" << json_escape(resolved.string()) << "\""
          << ",\"exists\":" << (exists ? "true" : "false");
        if (exists) {
            auto st = std::filesystem::status(resolved, ec);
            const char *kind = "other";
            if (std::filesystem::is_directory(st))
                kind = "dir";
            else if (std::filesystem::is_regular_file(st))
                kind = "file";
            else if (std::filesystem::is_symlink(st))
                kind = "symlink";
            uintmax_t sz = 0;
            if (std::filesystem::is_regular_file(st)) {
                sz = std::filesystem::file_size(resolved, ec);
                if (ec) sz = 0;
            }
            d << ",\"kind\":\"" << kind << "\""
              << ",\"size\":" << sz;
        }
        d << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FS_DELETE: {
        std::string path = json_get(json_msg, "path");
        std::string rec_s = json_get(json_msg, "recursive");
        if (path.empty()) {
            err_resp("falta 'path'");
            return;
        }
        std::filesystem::path resolved;
        std::string e;
        if (!resolve_sandbox_path(server_root_, path, resolved, e)) {
            err_resp(e);
            return;
        }
        std::error_code ec;
        uintmax_t removed = 0;
        if (rec_s == "true" || rec_s == "1") {
            removed = std::filesystem::remove_all(resolved, ec);
        } else {
            removed = std::filesystem::remove(resolved, ec) ? 1 : 0;
        }
        if (ec) {
            err_resp("remove fallo: " + ec.message());
            return;
        }
        std::ostringstream d;
        d << "{\"removed\":" << removed << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FS_MKDIR: {
        std::string path = json_get(json_msg, "path");
        std::string rec_s = json_get(json_msg, "recursive");
        if (path.empty()) {
            err_resp("falta 'path'");
            return;
        }
        std::filesystem::path resolved;
        std::string e;
        if (!resolve_sandbox_path(server_root_, path, resolved, e)) {
            err_resp(e);
            return;
        }
        std::error_code ec;
        bool ok2 = false;
        if (rec_s == "true" || rec_s == "1") {
            ok2 = std::filesystem::create_directories(resolved, ec);
        } else {
            ok2 = std::filesystem::create_directory(resolved, ec);
        }
        if (ec) {
            err_resp("mkdir fallo: " + ec.message());
            return;
        }
        std::ostringstream d;
        d << "{\"created\":" << (ok2 ? "true" : "false") << ",\"path\":\""
          << json_escape(resolved.string()) << "\"}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::FS_RENAME: {
        std::string src = json_get(json_msg, "src");
        std::string dst = json_get(json_msg, "dst");
        if (src.empty() || dst.empty()) {
            err_resp("faltan 'src' y/o 'dst'");
            return;
        }
        std::filesystem::path rs, rd;
        std::string e;
        if (!resolve_sandbox_path(server_root_, src, rs, e)) {
            err_resp("src: " + e);
            return;
        }
        if (!resolve_sandbox_path(server_root_, dst, rd, e)) {
            err_resp("dst: " + e);
            return;
        }
        std::error_code ec;
        std::filesystem::rename(rs, rd, ec);
        if (ec) {
            err_resp("rename fallo: " + ec.message());
            return;
        }
        ok_resp("{\"renamed\":true}");
        break;
    }

    case DebugCmd::LOAD_VELB_BYTES: {
        // Identico a LOAD_VELB pero el contenido viene en
        // content_b64; no se escribe a disco.  Util cuando el
        // cliente (IDE Electron) quiere ejecutar codigo recien
        // compilado sin pasar por el filesystem del server.
        std::string b64 = json_get(json_msg, "content_b64");
        std::string start_s = json_get(json_msg, "start");
        std::string pause_s = json_get(json_msg, "pause");
        if (b64.empty()) {
            err_resp("falta 'content_b64'");
            return;
        }
        std::vector<uint8_t> bytes;
        if (!b64_decode(b64, bytes)) {
            err_resp("content_b64 invalido");
            return;
        }
        bool do_start =
            (start_s.empty() || start_s == "true" || start_s == "1");
        bool do_pause = (pause_s == "true" || pause_s == "1");
        try {
            runtime::ProcessVM *p =
                vm_.mgr_vm.loader.load_executable(vm_, std::move(bytes));
            if (!p) {
                err_resp("load_executable devolvio nullptr");
                return;
            }
            if (do_pause) pause_at_start(p->pid.local_pid);
            if (do_start) vm_.make_ready(p->pid);
            std::ostringstream d;
            d << "{\"pid\":" << p->pid.local_pid
              << ",\"sched_id\":" << p->pid.scheduler_id << ",\"state\":\""
              << runtime::vm_state_to_str(p->state.load())
              << "\",\"started\":" << (do_start ? "true" : "false")
              << ",\"paused\":" << (do_pause ? "true" : "false") << "}";
            ok_resp(d.str());
        } catch (const std::exception &ex) {
            err_resp(std::string("load_velb_bytes fallo: ") + ex.what());
        }
        break;
    }

    case DebugCmd::MEM_WRITE: {
        // Escribe bytes a memoria VM (hex editor del debugger).
        // Campos:
        //   pid   (requerido)
        //   addr  (requerido) - direccion VM absoluta
        //   bytes (requerido) - string hex sin espacios, ej "deadbeef"
        std::string pid_s = json_get(json_msg, "pid");
        std::string addr_s = json_get(json_msg, "addr");
        std::string bytes_s = json_get(json_msg, "bytes");
        if (pid_s.empty() || addr_s.empty() || bytes_s.empty()) {
            err_resp("mem_write requiere pid, addr y bytes");
            return;
        }
        uint64_t pid = std::stoull(pid_s);
        uint64_t addr = std::stoull(addr_s);
        runtime::ProcessVM *p = find_process_by_pid(vm_, pid);
        if (!p) {
            err_resp("proceso no encontrado");
            return;
        }
        if (bytes_s.size() % 2 != 0) {
            err_resp("bytes debe tener longitud par (hex sin espacios)");
            return;
        }
        std::vector<uint8_t> buf;
        buf.reserve(bytes_s.size() / 2);
        for (size_t k = 0; k + 1 < bytes_s.size(); k += 2) {
            auto hexval = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hexval(bytes_s[k]);
            int lo = hexval(bytes_s[k + 1]);
            if (hi < 0 || lo < 0) {
                err_resp("bytes contiene caracteres no hex");
                return;
            }
            buf.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        // Limite defensivo de 4 KiB por write.
        if (buf.size() > 4096) {
            err_resp("max 4096 bytes por mem_write");
            return;
        }
        p->vm_mem.write_bytes(addr, buf.data(), buf.size());
        std::ostringstream d;
        d << "{\"written\":" << buf.size() << ",\"addr\":" << addr << "}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::REPL_EXEC: {
        // Enruta una linea cruda al REPL real del servidor
        // (runtime::run_command_async).  Es el mismo motor que
        // ejecuta los comandos del prompt `vesta>` cuando el
        // operador esta en consola local.
        //
        // Campos:
        //   line     (string, requerido) - linea cruda a ejecutar
        //   timeout_ms (number, opcional) - default 10000ms.  Si
        //              expira devolvemos error con la salida
        //              parcial que haya llegado.
        //
        // Respuesta: { output: string }
        std::string line = json_get(json_msg, "line");
        if (line.empty()) line = json_get(json_msg, "cmd_line");
        if (line.empty()) {
            err_resp("falta 'line'");
            return;
        }
        std::string to_s = json_get(json_msg, "timeout_ms");
        uint32_t timeout_ms = 10000;
        if (!to_s.empty()) {
            try {
                timeout_ms = static_cast<uint32_t>(std::stoul(to_s));
            } catch (...) { /* default */
            }
        }
        std::string output;
        try {
            // Ejecutar la linea en otro thread via std::async para
            // no bloquear el hilo del cliente si un comando
            // tarda (build/disasm de un .velb grande).
            auto fut = std::async(std::launch::async, [line]() {
                return cli::execute_repl_line(line);
            });
            if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) ==
                std::future_status::ready) {
                output = fut.get();
            } else {
                // Timeout: abandonamos el future (el codigo del
                // REPL terminara y descartara su salida).
                output = "(timeout " + std::to_string(timeout_ms) +
                         "ms; el comando sigue ejecutandose en segundo plano)";
            }
        } catch (const std::exception &ex) {
            err_resp(std::string("repl_exec fallo: ") + ex.what());
            return;
        }
        // Escapar el output para el JSON de respuesta.
        std::ostringstream d;
        d << "{\"output\":\"" << json_escape(output) << "\"}";
        ok_resp(d.str());
        break;
    }

    case DebugCmd::UNKNOWN:
    default: err_resp("comando desconocido: " + cmd_name); break;
    }

    // Tras cualquier comando, asegurar que has_hooks de los
    // schedulers refleja el estado actual de breakpoints/step/watch.
    // Asi cuando el cliente termina su sesion (sin breakpoints, todos
    // los procesos en RUNNING, ningun watch ni tracing) los
    // schedulers vuelven al fast path automaticamente, sin coste
    // adicional para el codigo de produccion.
    refresh_scheduler_hooks();
}

void Debugger::refresh_scheduler_hooks() {
    // El gate cubre los 5 caminos que pueden disparar on_before_exec.
    // break_on_mon_ aplica desde monenter (no desde on_before_exec)
    // pero se incluye para coherencia: si alguno cambia, los
    // schedulers deben estar dispuestos a recibir hooks.
    const bool needed = any_bp_.load(std::memory_order_relaxed) ||
                        any_step_.load(std::memory_order_relaxed) ||
                        any_watch_.load(std::memory_order_relaxed) ||
                        any_msg_trace_.load(std::memory_order_relaxed) ||
                        break_on_mon_.load(std::memory_order_relaxed);
    for (auto &sched : vm_.schedulers) {
        if (!sched) continue;
        sched->has_hooks = needed;
    }
}

} // namespace debug
