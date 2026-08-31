/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir/parallel_for.cpp
 * @brief Implementacion del recorrido paralelo (contrato en paralelo.h).
 *
 * Esta separacion no es estilo: `ThreadPool.h` arrastra `windows.h`, que define
 * `VOID` como macro y rompe cualquier cabecera con un `enum class` que use ese
 * nombre.  Aqui dentro no molesta.
 */
#include "util/env_flags.h"
#include "ir/parallel_for.h"

#include "util/ThreadPool.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <mutex>
#include <cstdlib>
#include <thread>

namespace ir {

namespace {

/**
 * @brief Contadores del reparto, para diagnosticar (VESTA_PARALELO_STATS=1).
 *
 * Sin la variable de entorno no imprime nada y lo que cuesta son un par de
 * sumas atomicas por reparto -- despreciable frente a lo que se mide.
 */
struct DispatchStats {
    std::atomic<size_t> parallel_dispatches{0}; ///< Repartos hechos en paralelo
    std::atomic<size_t> serial_walks{0}; ///< Recorridos hechos en fila de uno
    std::atomic<size_t> functions{0};    ///< Funciones repartidas en paralelo
    std::atomic<long long> wait_us{0};   ///< Microsegundos girando al final
    std::atomic<long long> total_us{0};  ///< Microsegundos dentro del reparto

    /// Vuelca el resumen al terminar el proceso, si se pidio.
    ~DispatchStats() {
        if (!util::flag_on(util::FlagId::ParaleloStats)) return;
        std::fprintf(stderr,
                     "[reparto] paralelos=%zu en_fila=%zu funciones=%zu "
                     "total=%lld us espera=%lld us\n",
                     parallel_dispatches.load(), serial_walks.load(),
                     functions.load(), total_us.load(), wait_us.load());
    }
};

/// Instancia unica; se vuelca en su destructor al salir del proceso.
DispatchStats g_stats;

} // namespace

unsigned compile_threads() {
    // Se lee UNA vez: consultar el entorno recorre su bloque entero, y esto se
    // pregunta en cada pase.
    static const unsigned n = [] {
        /* PUESTO, con `VESTA_PARALELO=0` para quitarlo.
         *
         * Nacio opt-in por un cuelgue, y el cuelgue no era lo que parecia: no
         * habia estado compartido sin proteger en ningun pase, sino que se
         * bloqueaba la propia INSTRUMENTACION.  `util::tramos_medidos()` pedia
         * la calibracion con el cerrojo del registro ya tomado, y medirla
         * recorre la ruta real, que vuelve a pedir ese mismo cerrojo para dar
         * de alta al hilo.  Solo se veia al repartir, porque en secuencial el
         * hilo principal ya estaba dado de alta y no llegaba a pedirlo.  Ver el
         * comentario de ese sitio.
         *
         * La condicion para encenderlo era pasar el corpus entero, y lo pasa:
         * los 440 ejemplos dan un `.velb` identico BYTE A BYTE al secuencial, y
         * los 41 comprobados en AOT tambien.
         *
         * Pero no lo pasaba solo: hubo que arreglar antes el tope del punto
         * fijo del optimizador.  Repartido, los hechos interprocedurales tardan
         * una vuelta mas en propagarse, y con el tope en 8 vueltas 38 de los
         * 440 se quedaban sin converger y salian hasta 21 KB MAS GRANDES.  No
         * era una carrera -- la salida era estable, solo peor -- y no se veia
         * porque agotar el tope no se contaba.  Ver @c kAntiHangCap.
         *
         * Medido en un proyecto de 21 modulos: el bucle por funcion baja de
         * ~443 ms a ~247 (1,8x) e `ir_optimize` de ~602 a ~417 (1,44x).
         *
         * Se deja la salida a mano porque comparar con el secuencial es como se
         * comprueba que un pase nuevo no metio estado compartido. */
        if (!util::flag_on(util::FlagId::Paralelo)) return 1u;
        unsigned h = std::thread::hardware_concurrency();
        if (h <= 1) return 1u;
        // Uno menos que los nucleos: dejar la maquina sin margen hace que el
        // propio reparto compita con lo repartido.
        return h - 1;
    }();
    return n;
}

void for_each_function(IrModule &mod,
                       const std::function<void(IrFunction &)> &f) {
    const size_t n = mod.functions.size();
    const unsigned hilos = compile_threads();
    /* Reentrada: si esto ya esta repartiendo mas arriba en la pila, aqui se
     * trabaja en fila de uno.  Encolar en el mismo pool desde dentro de una de
     * sus tareas es un bloqueo clasico: los workers estan todos ocupados con
     * las tareas de fuera, las de dentro no arrancan nunca, y las de fuera no
     * terminan porque esperan a las de dentro. */
    static thread_local bool dispatching = false;
    if (hilos <= 1 || n < 8 || dispatching) {
        g_stats.serial_walks.fetch_add(1, std::memory_order_relaxed);
        for (auto &fn : mod.functions)
            f(fn);
        return;
    }

    const auto start_time = std::chrono::steady_clock::now();
    g_stats.parallel_dispatches.fetch_add(1, std::memory_order_relaxed);
    g_stats.functions.fetch_add(n, std::memory_order_relaxed);

    /* UN pool para todo el proceso, no uno por llamada.
     *
     * Crearlo aqui dentro costaba lanzar y recoger hilos del sistema en cada
     * vuelta del punto fijo, en cada bucle de modulo y en cada recompilacion
     * de CTPE.  Para un modulo grande se diluye -- de ahi el -24% medido --,
     * pero un programa de 50 lineas pasaba de 187 ms a 49 SEGUNDOS: montar el
     * pool costaba muchisimo mas que el trabajo que repartia. */
    static ThreadPool pool(hilos);

    std::atomic<size_t> next{0};
    std::atomic<size_t> done{0};
    /* Tareas que aun no han SALIDO.  Esperar solo a que `done` llegue a `n` no
     * basta y costo una violacion de segmento: el ultimo worker sube el
     * contador, el principal lo ve y RETORNA, y los demas siguen dentro de la
     * tarea usando `next`, `done`, `f` y `mod` -- que son locales del marco que
     * acaba de morir.
     *
     * Con el pool creado aqui dentro no ocurria, porque destruirlo esperaba a
     * los hilos.  Al hacerlo estatico -- para no montarlo en cada llamada --
     * esa espera desaparecio y hubo que ponerla a mano. */
    std::atomic<unsigned> alive{0};

    /* Reparto por indice atomico y no por trozos iguales: las funciones no
     * cuestan lo mismo -- una de trescientas lineas junto a diez de cinco --,
     * asi que trocear a partes iguales deja hilos parados esperando al que le
     * toco la grande. */
    /* La primera excepcion que salga de un pase.  El pool se las TRAGA -- lo
     * dice su documentacion --, asi que sin guardarla aqui un fallo se
     * convierte en un cuelgue mudo: el contador no avanza, el que espera gira
     * para siempre y nadie sabe que paso.  Es exactamente lo que ocurrio. */
    std::mutex m_error;
    std::exception_ptr primer_error;

    auto trabajar = [&] {
        /* Avisa al salir, salga por donde salga. */
        struct OnExit {
            std::atomic<unsigned> &v;
            ~OnExit() { v.fetch_sub(1); }
        } on_exit{alive};
        for (;;) {
            const size_t i = next.fetch_add(1);
            if (i >= n) return;
            /* El contador sube al SALIR, pase lo que pase.  Contarlo despues
             * de `f()` dejaba de contar cuando `f()` lanzaba, y entonces la
             * espera de abajo no podia terminar nunca. */
            struct Contar {
                std::atomic<size_t> &c;
                ~Contar() { c.fetch_add(1); }
            } contar{done};
            try {
                f(mod.functions[i]);
            } catch (...) {
                std::lock_guard<std::mutex> lk(m_error);
                if (!primer_error) primer_error = std::current_exception();
                return; // este hilo se retira; los demas siguen y acaban
            }
        }
    };

    /* Los workers son uno MENOS que los hilos, porque el principal tambien
     * trabaja.  Antes se quedaba girando en `yield()` mientras los demas
     * trabajaban, asi que con `nucleos-1` workers mas el principal girando se
     * sobresuscribia la maquina: el que espera le roba el nucleo al que
     * trabaja. */
    alive.store(hilos);
    dispatching = true;
    struct OnDone {
        bool &r;
        ~OnDone() { r = false; }
    } on_done{dispatching};
    for (unsigned h = 0; h + 1 < hilos; ++h)
        pool.enqueue(trabajar);
    trabajar();

    /* Y al terminar su parte, el principal espera a que acaben los demas.  Se
     * espera a que TODAS esten hechas y no a que la cola se vacie: una tarea
     * encolada que aun no arranco tambien cuenta, y salir antes dejaria el
     * pase a medias sin que nadie lo notara. */
    /* Se espera a que TODAS hayan SALIDO, no a que el trabajo este hecho: una
     * tarea que ya conto su ultima funcion sigue tocando este marco hasta que
     * retorna de verdad. */
    const auto wait_start = std::chrono::steady_clock::now();
    while (alive.load() > 0)
        std::this_thread::yield();

    {
        using namespace std::chrono;
        const auto end_time = steady_clock::now();
        g_stats.wait_us.fetch_add(
            duration_cast<microseconds>(end_time - wait_start).count(),
            std::memory_order_relaxed);
        g_stats.total_us.fetch_add(
            duration_cast<microseconds>(end_time - start_time).count(),
            std::memory_order_relaxed);
    }

    /* Y se relanza en el hilo que espera.  Tragarse un fallo del compilador es
     * peor que caerse: el programa sale mal y nadie lo sabe. */
    if (primer_error) std::rethrow_exception(primer_error);
}

} // namespace ir
