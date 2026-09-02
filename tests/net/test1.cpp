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

#include "../test_support.h"

#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "Starting TCP server test..." << std::endl;

    /* Puerto PROPIO de esta ejecucion.  Estaba fijo en 9000, igual que en
     * tests/net/test2.cpp, y el lanzador corre los dos A LA VEZ: el segundo
     * en llegar no podia enlazar.  Aislados pasaban los dos, que es la peor
     * forma de fallar porque parece cosa del azar. */
    const uint16_t port = vesta_test::puerto_unico();

    TCPServer server(port);

    // Ejecutar el servidor en un hilo
    std::thread server_thread([&server]() {
        if (!server.start()) {
            std::cerr << "Failed to start server\n";
            return;
        }
    });

    std::cout << "Server running on port " << port << "\n";
    std::cout << "Connect using:\n";
    std::cout << "   telnet 127.0.0.1 " << port << "\n";
    std::cout << "   nc 127.0.0.1 " << port << "\n\n";

    // Mantener el servidor activo 30 segundos
    std::this_thread::sleep_for(std::chrono::seconds(30));

    std::cout << "Stopping server...\n";

    server.stop();

    server_thread.join();

    std::cout << "Server stopped\n";

    return 0;
}
