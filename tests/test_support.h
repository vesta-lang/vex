/**
 * @file tests/test_support.h
 * @brief Utilidades compartidas por los tests: nombres de recurso que NO
 *        chocan entre procesos.
 *
 * El lanzador (@c tools/run_unit_tests.py) corre los tests EN PARALELO, asi
 * que dos que usen el mismo fichero temporal o el mismo puerto se pisan.  Ese
 * fallo es de los peores que hay: **aislados pasan siempre**, asi que parece
 * cosa del azar y se le echa la culpa a la maquina.  Ya mordio dos veces --
 * dos tests del almacen de hechos escribiendo el mismo fichero, y los dos de
 * red escuchando los dos en el puerto 9000.
 *
 * Que estas funciones vivan aqui y no copiadas en cada test no es orden: una
 * copia que se quede atras vuelve a traer el fallo, y no se nota hasta que dos
 * tests coinciden en el tiempo.
 */
#ifndef VESTA_TESTS_TEST_SUPPORT_H
#define VESTA_TESTS_TEST_SUPPORT_H

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>

/* Sockets: hacen falta para pedirle al sistema un puerto libre. */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace vesta_test {

/**
 * @brief Un valor distinto en cada proceso e hilo, para construir nombres de
 *        recurso que no choquen.
 *
 * Mezcla el identificador del hilo con el reloj monotono: dos procesos
 * lanzados a la vez tienen relojes distintos, y dos hilos del mismo proceso
 * tienen identificadores distintos.
 */
inline uint64_t marca_unica() {
    const auto hilo = std::hash<std::thread::id>{}(std::this_thread::get_id());
    const auto ahora = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    return static_cast<uint64_t>(hilo) ^ ahora;
}

/**
 * @brief Un directorio temporal propio de esta ejecucion.
 * @param nombre Prefijo legible, para saber de quien es al mirarlo.
 */
inline std::string dir_unico(const char *nombre) {
    return (std::filesystem::temp_directory_path() /
            (std::string(nombre) + "_" + std::to_string(marca_unica())))
        .string();
}

/**
 * @brief Un fichero temporal propio de esta ejecucion.
 * @param nombre Prefijo legible.
 * @param ext    Extension con punto, por ejemplo ".bin".
 */
inline std::string fichero_unico(const char *nombre, const char *ext) {
    return (std::filesystem::temp_directory_path() /
            (std::string(nombre) + "_" + std::to_string(marca_unica()) + ext))
        .string();
}

/**
 * @brief Un puerto TCP LIBRE, preguntandoselo al sistema.
 *
 * Enlazar al puerto 0 hace que el sistema elija uno que no este en uso, y
 * `getsockname` dice cual toco.  Se cierra en el acto y se devuelve el numero.
 *
 * Elegir uno al azar en el rango efimero no basta: choca de vez en cuando y el
 * test falla con `bind() failed` una vez de cada muchas -- un intermitente,
 * que es la peor clase de fallo porque parece cosa del azar.  Aqui queda una
 * ventana minuscula (que otro proceso coja ESE puerto entre este cierre y el
 * enlace de verdad), pero es lo que hace todo el mundo y es incomparablemente
 * mas estrecha.
 *
 * @return Un puerto libre, o 0 si el sistema no pudo dar ninguno.
 */
inline uint16_t puerto_unico() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 0;
#else
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // 0 = "elige tu"
    uint16_t puerto = 0;
    if (bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0) {
        socklen_t len = sizeof(addr);
        if (getsockname(s, reinterpret_cast<sockaddr *>(&addr), &len) == 0)
            puerto = ntohs(addr.sin_port);
    }
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    return puerto;
}

} // namespace vesta_test

#endif // VESTA_TESTS_TEST_SUPPORT_H
