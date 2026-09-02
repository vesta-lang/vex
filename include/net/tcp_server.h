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
 * @file tcp_server.h
 * @brief Servidor TCP con soporte TLS opcional basado en OpenSSL.
 *
 * TCPServer acepta conexiones entrantes en un puerto TCP y crea un objeto
 * Connection (o subclase) por cada cliente aceptado.  Si se proporciona un
 * TLSContext, las conexiones se cifran con TLS usando SSL_accept().
 *
 * Para personalizar el tipo de conexion creado, sobreescribir
 * create_connection() en una subclase (patron Factory Method).
 *
 * Portabilidad: define socket_t e INVALID_SOCKET_VALUE de forma compatible
 * con Windows (SOCKET / INVALID_SOCKET) y sistemas POSIX (int / -1).
 */

#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

#include "controller/tls_connection.h"
#include "controller/tls_context.h"
#include "net/connection.h"

// ---------------------------------------------------------------------------
// Portabilidad de sockets
// ---------------------------------------------------------------------------

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
typedef SOCKET socket_t;
#define INVALID_SOCKET_VALUE                                                   \
    INVALID_SOCKET ///< Valor centinela de socket invalido (Windows)
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
typedef int socket_t;
#define INVALID_SOCKET_VALUE -1 ///< Valor centinela de socket invalido (POSIX)
#endif

/**
 * @brief Cierra un socket de forma compatible con la plataforma.
 *
 * Usa closesocket() en Windows y close() en POSIX.  Ignora descriptores
 * invalidos.
 *
 * @param s Descriptor de socket a cerrar.
 */
inline void close_socket(socket_t s) {
#ifdef _WIN32
    if (s != INVALID_SOCKET) closesocket(s); // cerrar socket Windows
#else
    if (s >= 0) close(s); // cerrar socket POSIX
#endif
}

/**
 * @brief Servidor TCP que acepta conexiones y crea objetos Connection por
 * cliente.
 *
 * Escucha en el puerto indicado y genera un hilo nativo por cada conexion
 * aceptada. Si se proporciona un TLSContext en el constructor, realiza el
 * handshake TLS antes de crear la conexion.  Las subclases pueden sobreescribir
 * create_connection() para instanciar tipos de conexion especializados.
 */
class TCPServer {
  protected:
    socket_t server_fd{
        INVALID_SOCKET_VALUE}; ///< Descriptor del socket de escucha
    uint16_t port;             ///< Puerto TCP en el que escucha el servidor
    std::atomic<bool> running{false}; ///< true mientras el servidor esta activo

    bool tls_enabled{false}; ///< true si TLS esta habilitado para este servidor
    TLSContext *tls_ctx{
        nullptr}; ///< Contexto TLS (puede ser nullptr para TCP plano)

    std::vector<std::thread> threads; ///< Hilos de los clientes activos

    /* El hilo que acepta conexiones.
     *
     * Estaba SUELTO (`.detach()`), asi que nadie podia esperarlo: `stop()`
     * cerraba el socket y volvia, y el hilo seguia vivo tocando `threads` --
     * un miembro de este objeto -- que para entonces podia estar ya destruido.
     * Y el vector se destruia con hilos aun por unir, que es lo que abortaba
     * el proceso con "terminate called without an active exception", despues
     * de que el servidor hubiera hecho su trabajo bien. */
    std::thread accept_thread;

  public:
    /**
     * @brief Construye el servidor TCP sin TLS en el puerto indicado.
     *
     * @param port Puerto TCP en el que escuchar conexiones entrantes.
     */
    TCPServer(uint16_t port);

    /**
     * @brief Construye el servidor TCP con TLS opcional en el puerto indicado.
     *
     * Si @p ctx es nullptr el servidor opera sin cifrado.
     * Si @p ctx es valido, tls_enabled se pone a true y se usa el contexto para
     * el handshake de cada conexion entrante.
     *
     * @param port Puerto TCP en el que escuchar conexiones entrantes.
     * @param ctx  Contexto TLS (puede ser nullptr para TCP plano).
     */
    TCPServer(uint16_t port, TLSContext *ctx);

    /**
     * @brief Destructor: llama a stop() y espera a que todos los hilos de
     * clientes terminen.
     */
    virtual ~TCPServer();

    /**
     * @brief Crea el socket de escucha, lo vincula al puerto y lanza el bucle
     * de aceptacion.
     *
     * @return true si el servidor se inicio correctamente; false en caso de
     * error.
     */
    bool start();

    /**
     * @brief Detiene el servidor cerrando el socket de escucha y esperando a
     * los hilos.
     */
    void stop();

  protected:
    /**
     * @brief Crea una conexion para el cliente aceptado.
     *
     * Implementacion por defecto: si TLS esta habilitado realiza el handshake
     * SSL_accept() y crea un TLSConnection; en caso contrario crea un
     * Connection TCP plano. Las subclases pueden sobreescribir este metodo para
     * usar tipos de conexion especializados.
     *
     * @param client_fd Descriptor de socket del cliente aceptado.
     * @param tls_ctx   Contexto TLS del servidor (puede ser nullptr).
     * @return Nuevo objeto Connection (o subclase) listo para start(); nullptr
     * si el handshake fallo.
     */
    virtual Connection *create_connection(socket_t client_fd,
                                          TLSContext *tls_ctx) {
        if (tls_enabled && tls_ctx) {
            // realizar handshake TLS para la nueva conexion
            SSL *ssl = SSL_new(tls_ctx->get());
            SSL_set_fd(ssl, (int)client_fd);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr); // imprimir errores de OpenSSL
                SSL_free(ssl); // liberar SSL si el handshake fallo
                return nullptr;
            }
            return new TLSConnection(client_fd, ssl); // conexion TLS aceptada
        } else {
            return new Connection(client_fd); // conexion TCP plana
        }
    }

    /**
     * @brief Bucle de aceptacion: espera clientes y crea un hilo por cada
     * conexion.
     *
     * Se ejecuta hasta que running sea false o el socket de escucha se cierre.
     * Por cada cliente aceptado llama a create_connection() y lanza un
     * std::thread que invoca start() sobre la conexion resultante.
     */
    virtual void accept_loop();
};

#endif // TCP_SERVER_H
