/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/ooo.h
 * @brief Ejecutar en PARALELO dos mitades independientes de un paquete.
 *
 * QUE SE ESTA PROBANDO
 * --------------------
 * Si entregarle trabajo a otro hilo compensa a la granularidad que tiene un
 * paquete.  No se da por sabido: se construye y se mide.  Por eso el traspaso
 * esta hecho lo mas rapido que se puede -- espera ACTIVA sobre una atomica, sin
 * cerrojo, sin futex y sin cola --, para que si aun asi pierde, la conclusion
 * sea del mecanismo y no de la implementacion.
 *
 * El hilo se arranca UNA vez y se queda girando: crear un hilo cuesta unos
 * microsegundos y un paquete son decenas de nanosegundos, asi que crearlo por
 * uso no seria una prueba de nada.
 *
 * POR QUE EL TRASPASO ESTA EN LA CABECERA
 * ---------------------------------------
 * `ooo_dispatch` y `ooo_join` se llaman POR PAQUETE EJECUTADO, o sea en el
 * camino caliente.  Una llamada entre unidades de traduccion ahi se comeria
 * justo lo que se intenta medir: el traspaso son unas pocas decenas de
 * nanosegundos y una llamada que no se puede plegar es una parte apreciable de
 * eso.  Ademas `ooo_join` es un bucle de espera sobre una atomica, y en cabecera
 * el compilador lo deja en un registro en vez de rehacer la carga cada vuelta.
 *
 * En el `.cpp` se queda solo lo que corre UNA vez: arrancar el hilo, su bucle y
 * pararlo.
 *
 * QUE HACE FALTA PARA QUE SEA CORRECTO
 * ------------------------------------
 * Las dos mitades tienen que ser INDEPENDIENTES de verdad, y eso es mas que no
 * compartir registros:
 *
 *   - registros disjuntos -- son ranuras distintas de un array, asi que sin
 *     solape no hay carrera;
 *   - la segunda mitad NO toca memoria de la VM.  Sin desambiguar direcciones,
 *     dos accesos cualesquiera pueden ser al mismo sitio;
 *   - la segunda mitad NO lee ni escribe banderas: son un byte compartido;
 *   - ninguna transfiere control, se bloquea o puede abortar.  Si la primera
 *     salta, la segunda NO debia haberse ejecutado, y para entonces ya corrio.
 *
 * Con eso no hace falta ninguna sincronizacion entre las dos: no comparten ni
 * un byte.  La unica atomica es la del traspaso.
 *
 * LO QUE NO ES
 * ------------
 * No es un motor fuera de orden con marcador ni renombrado.  El fuera de orden
 * DENTRO de un manejador ya lo hace el anfitrion; esto prueba la otra via, la de
 * repartir entre nucleos.
 */

#ifndef VESTA_RUNTIME_BUNDLE_OOO_H
#define VESTA_RUNTIME_BUNDLE_OOO_H

#include <atomic>
#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
#include <immintrin.h> // _mm_pause: ceder el hilo hermano mientras se espera
#endif

#include "runtime/bundle.h"

#if VM_BUNDLES

namespace runtime {

/// En que anda el ayudante.
enum : uint32_t {
    kOooIdle = 0, ///< sin trabajo, girando
    kOooBusy = 1, ///< hay trabajo puesto y todavia no ha terminado
    kOooStop = 2, ///< que se pare
};

/**
 * @brief El traspaso: una atomica y tres punteros.
 *
 * Sin cola y sin cerrojo.  Una cola haria falta con varios productores; aqui
 * hay UNO -- el hilo que ejecuta el paquete -- y un consumidor, asi que la
 * atomica de estado ordena por si sola: el productor escribe los punteros y
 * DESPUES publica el estado con `release`; el consumidor lo ve con `acquire` y
 * para entonces los punteros ya estan.
 *
 * Alineado a linea de cache para que el estado no comparta linea con nada del
 * llamante.  Si la compartiera, cada escritura suya invalidaria la linea en el
 * otro nucleo y el traspaso costaria mas que el trabajo -- que es justo lo que
 * se esta midiendo, asi que falsearlo aqui invalidaria la prueba.
 */
struct alignas(64) OooHandoff {
    std::atomic<uint32_t> state{kOooIdle};
    ProcessVM *proc = nullptr;
    const DecodedInstr *instr = nullptr;
    uint32_t n = 0;
};

/// Uno solo: se esta probando si UN ayudante compensa.  Si no compensa con uno,
/// con mas tampoco.
inline OooHandoff g_ooo;
inline std::atomic<bool> g_ooo_started{false};

/// Ceder el SMT mientras se espera.  Sin esto, dos hilos girando en el mismo
/// nucleo fisico se quitan el sitio y la espera sale mas cara que el trabajo.
[[gnu::always_inline]] inline void ooo_pause() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    _mm_pause();
#endif
}

/// Arranca el ayudante.  Fuera de linea a proposito: corre UNA vez.
void ooo_start();

/**
 * @brief Lanza @p n instrucciones desde @p instr en el hilo ayudante.
 *
 * No espera: el llamante sigue con SU mitad y despues llama a @ref ooo_join.
 *
 * @return true si el ayudante lo cogio; false si estaba ocupado o aun no
 *         existe, y entonces el llamante las ejecuta el mismo.
 */
[[gnu::always_inline]] inline bool ooo_dispatch(ProcessVM *process,
                                                const DecodedInstr *instr,
                                                uint32_t n) {
    if (__builtin_expect(!g_ooo_started.load(std::memory_order_acquire), 0)) {
        ooo_start();
        return false; // esta vez en serie: arrancar un hilo no es instantaneo
    }
    /* Ocupado: lo hace el llamante.  Sin cola no hay donde encolarlo, y
     * encolarlo seria pagar justo lo que se intenta evitar. */
    if (g_ooo.state.load(std::memory_order_relaxed) != kOooIdle) return false;

    g_ooo.proc = process;
    g_ooo.instr = instr;
    g_ooo.n = n;
    // `release`: los tres de arriba tienen que verse ANTES que el estado.
    g_ooo.state.store(kOooBusy, std::memory_order_release);
    return true;
}

/// Espera a que el ayudante termine.  Espera ACTIVA: es lo que se esta midiendo.
[[gnu::always_inline]] inline void ooo_join() {
    while (g_ooo.state.load(std::memory_order_acquire) != kOooIdle) ooo_pause();
}

/// Para el hilo ayudante.  Se llama al terminar el proceso.
void ooo_shutdown();

} // namespace runtime

#endif // VM_BUNDLES
#endif // VESTA_RUNTIME_BUNDLE_OOO_H
