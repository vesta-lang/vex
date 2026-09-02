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
 * @file tcp_server.cpp
 * @brief Implementacion del servidor TCP (con soporte TLS opcional) de VestaVM.
 *
 * Implementa @c TCPServer: apertura del socket servidor, bucle de aceptacion
 * de conexiones entrantes, creacion de objetos @c Connection (o @c
 * TLSConnection), y shutdown ordenado.  Usa OpenSSL si el servidor se construye
 * con TLS habilitado.
 */
#include "net/tcp_server.h"
#include <iostream>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#endif

TCPServer::TCPServer(uint16_t port) : port(port) {}
TCPServer::TCPServer(uint16_t port, TLSContext *ctx)
    : port(port), tls_enabled(true), tls_ctx(ctx) {}
TCPServer::~TCPServer() {
    stop();
}

bool TCPServer::start() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "socket() failed\n";
        return false;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char *>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cerr << "bind() failed\n";
        return false;
    }
    if (listen(server_fd, 128) < 0) {
        std::cerr << "listen() failed\n";
        return false;
    }

    running.store(true);
    std::cout << "[TCPServer] listening on port " << port << std::endl;

    accept_thread = std::thread(&TCPServer::accept_loop, this);
    return true;
}

void TCPServer::stop() {
    if (!running.load()) return;
    running.store(false);
    /* Cerrar el socket PRIMERO: es lo que desbloquea el `accept()` en el que
     * esta parado el hilo de aceptacion, y sin eso el `join` de abajo no
     * volveria nunca. */
    if (server_fd >= 0) {
        close_socket(server_fd);
        server_fd = -1;
    }

    /* Y esperarlo.  Es la diferencia entre "he pedido que pare" y "ha
     * parado": mientras ese hilo vive sigue tocando `threads`, que es un
     * miembro de este objeto, asi que volver de aqui sin unirlo deja a alguien
     * leyendo un objeto que el llamador cree ya terminado -- y si el que
     * llamo fue el destructor, directamente destruido. */
    if (accept_thread.joinable()) accept_thread.join();

#ifdef _WIN32
    WSACleanup();
#endif
}

void TCPServer::accept_loop() {
    while (running.load()) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        socket_t client_fd = accept(server_fd, (sockaddr *)&client_addr, &len);
        if (client_fd < 0) continue;

        std::cout << "[TCPServer] client connected\n";

        threads.emplace_back([this, client_fd]() {
            Connection *conn = create_connection(client_fd, tls_ctx);
            if (!conn) {
                close_socket(client_fd);
                return;
            }

            conn->start();
            delete conn;
        });
    }

    // Esperar a que los hilos terminen antes de salir
    for (auto &t : threads)
        if (t.joinable()) t.join();
}