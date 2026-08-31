/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/test_threadpool_rafaga.cpp
 * @brief Encolar en rafaga nada mas construir el pool, que es lo que lo
 * colgaba.
 *
 * El patron que revienta -- y que ningun test cubria -- es este: construir el
 * pool y encolar N tareas de golpe.  Los workers acaban de arrancar y estan
 * justo en la ventana entre mirar la cola y dormirse, que es donde se perdia el
 * aviso.
 *
 * El fallo era un bloqueo con 0% de CPU: la tarea quedaba en la cola y todos
 * los hilos dormidos esperando un aviso que ya se habia emitido.  Como no
 * gasta CPU ni lanza nada, no se distingue de "va lento" salvo mirando.
 *
 * Por eso este test tiene LIMITE DE TIEMPO: sin el, un pool que se cuelga hace
 * que el test se cuelgue tambien, y una suite parada parece una suite lenta.
 * Con limite, el sintoma es inequivoco.
 *
 * Se repite muchas veces porque es una carrera: acertar la ventana depende de
 * como caiga el planificador, y una sola vuelta puede pasar de largo.
 */

#include "util/ThreadPool.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

namespace {

/// Cuantas veces se repite el intento.  Es una carrera: con una sola vuelta el
/// fallo aparecia una de cada varias ejecuciones.
constexpr int kVueltas = 200;
/// Tareas por vuelta.  Mas que hilos, para que haya cola de verdad.
constexpr int kTareas = 64;
/// Lo que se espera como MUCHO por vuelta.  Holgado a proposito: lo que se
/// detecta es un bloqueo permanente, no una lentitud.
constexpr auto kLimite = std::chrono::seconds(10);

bool una_vuelta(int vuelta) {
    ThreadPool pool(4);
    std::atomic<int> hechas{0};
    for (int i = 0; i < kTareas; ++i)
        pool.enqueue([&hechas] { hechas.fetch_add(1); });

    const auto tope = std::chrono::steady_clock::now() + kLimite;
    while (hechas.load() < kTareas) {
        if (std::chrono::steady_clock::now() > tope) {
            std::printf("  FALLO en la vuelta %d: %d/%d tareas tras %llds.\n"
                        "  Es el aviso perdido: quedan tareas en la cola con "
                        "los workers dormidos.\n",
                        vuelta, hechas.load(), kTareas,
                        (long long)kLimite.count());
            return false;
        }
        std::this_thread::yield();
    }
    return true;
}

} // namespace

int main() {
    std::printf("ThreadPool: %d vueltas de %d tareas encoladas en rafaga\n",
                kVueltas, kTareas);
    for (int v = 0; v < kVueltas; ++v) {
        if (!una_vuelta(v)) {
            std::printf("FAIL\n");
            return 1;
        }
    }
    std::printf("OK: %d vueltas sin perder ningun aviso\n", kVueltas);
    return 0;
}
