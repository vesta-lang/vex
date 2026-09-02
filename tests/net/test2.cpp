/*
 * VestaVM - Máquina Virtual Distribuida
 *
 * Copyright © 2026 David López.T (DesmonHak) (Castilla y León, ES)
 * Licencia VMProject
 *
 * USO LIBRE NO COMERCIAL con atribución obligatoria.
 * PROHIBIDO lucro sin permiso escrito.
 *
 * Descargo: Autor no responsable por modificaciones.
 */

#include "net/tcp_server.h"
#include "controller/tls_context.h"
#include "controller/tls_connection.h"

#include "../test_support.h"

#include <iostream>
#include <thread>
#include <vector>
#include <chrono>

// ---------------- Conexión TLS personalizada ----------------
class HelloTLSConnection : public TLSConnection {
  public:
    HelloTLSConnection(socket_t fd, SSL *ssl) : TLSConnection(fd, ssl) {}

    void start() override {
        // Enviar mensaje
        std::string msg = "Hola Mundo desde TLS!\n";
        std::vector<uint8_t> buf(msg.begin(), msg.end());
        write_data(buf);

        // Cierre TLS seguro
        int ret = 0;
        do {
            ret = SSL_shutdown(get_ssl());
        } while (ret == 0);

        stop();
    }
};

// ---------------- Servidor usando TCPServer generico ----------------
class HelloTCPServer : public TCPServer {
  public:
    HelloTCPServer(uint16_t port, TLSContext *ctx) : TCPServer(port, ctx) {}

  protected:
    Connection *create_connection(socket_t client_fd,
                                  TLSContext *ctx) override {
        SSL *ssl = nullptr;
        if (tls_enabled && ctx) {
            ssl = SSL_new(ctx->get());
            SSL_set_fd(ssl, (int)client_fd);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                return nullptr;
            }
        }
        return new HelloTLSConnection(client_fd, ssl);
    }
};

// ---------------- Cliente TLS simple ----------------
bool run_client(const std::string &host, int port, int id) {
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return false;

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == SOCKET_INVALID) {
        SSL_CTX_free(ctx);
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host.c_str());

    if (connect(sock, (sockaddr *)&addr, sizeof(addr)) < 0) {
        close_socket(sock);
        SSL_CTX_free(ctx);
        return false;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sock);
    SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close_socket(sock);
        SSL_CTX_free(ctx);
        return false;
    }

    char buf[1024];
    int len = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = 0;
        std::cout << "[Cliente " << id << "] Recibido: " << buf;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close_socket(sock);
    SSL_CTX_free(ctx);
    return true;
}

// ---------------- Main ----------------
int main() {
    TLSContext::initialize();
    TLSContext tls_ctx("server_cert.pem", "server_key.pem");

    // Servidor TLS
    /* Puerto PROPIO de esta ejecucion: estaba fijo en 9000, el MISMO que
     * tests/net/test1.cpp, y el lanzador corre los dos a la vez. */
    const uint16_t port = vesta_test::puerto_unico();

    HelloTCPServer server(port, &tls_ctx);
    if (!server.start()) {
        std::cerr << "Servidor falló\n";
        return 1;
    }

    // Clientes concurrentes
    std::vector<std::thread> clients;
    for (int i = 0; i < 5; i++) {
        clients.emplace_back([i, port]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * i));
            run_client("127.0.0.1", port, i);
        });
    }

    for (auto &t : clients)
        t.join();

    // Detener servidor y limpiar TLS
    server.stop();
    TLSContext::cleanup();

    std::cout << "Todos los clientes recibieron su mensaje.\n";
    return 0;
}