/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/test_threadpool_tag.cpp
 * @brief La etiqueta de reservas tiene que llegar del hilo que encola al que
 *        trabaja.
 *
 * QUE PASA SI NO LLEGA.  Un `util::AllocScope` vale para SU hilo, y este
 * compilador reparte casi todo.  Una fase etiquetada cuyo trabajo se reparta
 * por el pool contaria como "no se" TODO lo que reserven los trabajadores --
 * que en un reparto son casi todas las reservas de esa fase --.  Eso no es un
 * dato que falta: es un dato FALSO, y el reparto por proposito, que existe
 * justamente para decidir que memoria se puede encaminar a una arena, diria lo
 * contrario de la verdad.
 *
 * POR QUE ESTE TEST Y NO MIRAR EL VOLCADO.  Porque el volcado sale al terminar
 * el proceso y hoy nadie abre un ambito en el compilador, asi que el reparto es
 * 100% "no se" y esta propagacion no se ve funcionar ni fallar.  Aqui se abre
 * el ambito a proposito y se comprueba el efecto que importa: que una RESERVA
 * hecha dentro del trabajador acaba contada bajo la etiqueta de quien encolo.
 *
 * Lo que se comprueba, en orden de lo que se romperia primero:
 *
 *  1. El trabajador VE la etiqueta del que encolo.
 *  2. Una reserva suya se CUENTA bajo esa etiqueta -- que es para lo que sirve.
 *  3. Cada tarea ve la SUYA: el pool restaura al terminar, asi que una tarea no
 *     hereda la etiqueta de la anterior que corriera en ese mismo hilo.  Sin
 *     esto la propagacion seria peor que no tenerla: contaria mal en vez de no
 *     contar.
 *  4. Sin ambito abierto sigue saliendo "no se", y no una etiqueta inventada.
 */

#include "util/ThreadPool.h"
#include "util/alloc/host_allocator.h"

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

namespace {

int g_failures = 0;

void check(bool ok, const char *what) {
    std::printf("  [%s] %s\n", ok ? "OK  " : "FALLO", what);
    if (!ok) ++g_failures;
}

/// Cuantas tareas se encolan.  Bastantes para que las reparta mas de un hilo.
constexpr int kTasks = 64;

} // namespace

int main() {
    std::printf("== la etiqueta de reservas viaja con la tarea del pool ==\n");

    const util::AllocTag phase{util::AllocUse::Instant, util::AllocShape::Fixed};
    const util::AllocTag other{util::AllocUse::Long, util::AllocShape::Growing};

    /* 1 y 2. Con el ambito abierto, lo que vean y reserven los trabajadores. */
    {
        /* CADA TAREA RESERVA MUCHAS VECES, y esa cifra es lo que hace que la
         * comprobacion signifique algo.  Con una sola reserva por tarea el
         * contador subia igual SIN la propagacion, porque el hilo principal
         * tambien reserva con el ambito abierto -- al encolar, sin ir mas
         * lejos -- y esas tapaban el resultado.  Con 100 por tarea, lo que
         * pueda aportar el principal es ruido frente a 6.400. */
        constexpr int kAllocsPerTask = 100;
        std::vector<uint8_t> seen(kTasks, 0xFF);
        const util::HostAllocStats before = util::host_alloc_stats();

        {
            ThreadPool pool(4);
            /* El ambito se CIERRA antes de esperar a las tareas: asi se
             * comprueba ademas que la etiqueta se capturo al ENCOLAR y no se
             * lee del hilo que reparte cuando la tarea corre -- que para
             * entonces ya no la tendria. */
            {
                const util::AllocScope scope(phase);
                for (int i = 0; i < kTasks; ++i)
                    pool.enqueue([i, &seen] {
                        seen[size_t(i)] = util::AllocScope::current().raw();
                        for (int k = 0; k < kAllocsPerTask; ++k)
                            util::host_free(util::host_alloc(64));
                    });
            }
            // El destructor del pool espera a que terminen; nadie gira aqui.
        }

        bool all = true;
        for (uint8_t v : seen)
            if (v != phase.raw()) all = false;
        check(all, "el trabajador ve la etiqueta del hilo que encolo");

        const util::HostAllocStats after = util::host_alloc_stats();
        const uint64_t counted =
            after.by_tag[phase.raw()] - before.by_tag[phase.raw()];
        check(counted >= uint64_t(kTasks) * kAllocsPerTask,
              "y lo que reserva se CUENTA bajo esa etiqueta");
    }

    /* 3. Cada tarea ve la suya: el pool restaura al terminar. */
    {
        std::vector<uint8_t> seen(kTasks, 0xFF);
        std::atomic<int> done{0};
        ThreadPool pool(4);
        for (int i = 0; i < kTasks; ++i) {
            /* El ambito se abre y se CIERRA alrededor de cada encolado, que es
             * el caso que destapa una restauracion que falte: si el trabajador
             * no devolviera la etiqueta al acabar, las tareas pares heredarian
             * la de las impares. */
            const util::AllocScope scope((i % 2) == 0 ? phase : other);
            pool.enqueue([i, &seen, &done] {
                seen[size_t(i)] = util::AllocScope::current().raw();
                done.fetch_add(1, std::memory_order_release);
            });
        }
        while (done.load(std::memory_order_acquire) < kTasks)
            std::this_thread::yield();

        bool each_its_own = true;
        for (int i = 0; i < kTasks; ++i)
            if (seen[size_t(i)] != ((i % 2) == 0 ? phase.raw() : other.raw()))
                each_its_own = false;
        check(each_its_own, "cada tarea ve la SUYA, no la de la anterior");
    }

    /* 4. Sin ambito, "no se" -- no una etiqueta inventada. */
    {
        std::atomic<uint8_t> seen{0xFF};
        std::atomic<bool> done{false};
        ThreadPool pool(2);
        pool.enqueue([&seen, &done] {
            seen.store(util::AllocScope::current().raw());
            done.store(true, std::memory_order_release);
        });
        while (!done.load(std::memory_order_acquire))
            std::this_thread::yield();
        check(seen.load() == util::AllocTag{}.raw(),
              "sin ambito abierto sigue siendo \"no se\"");
    }

    std::printf("%s\n", g_failures == 0 ? "TODO OK" : "HAY FALLOS");
    return g_failures == 0 ? 0 : 1;
}
