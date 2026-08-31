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
 * @file mem_stats.h
 * @brief Cuanta memoria gasto un test, leida del asignador del proyecto.
 *
 * Cuatro tests (lexer, linker, loader, runtime) llevaban CADA UNO su propia
 * copia de un `operator new` global que sumaba los bytes pedidos.  Dos cosas
 * iban mal con eso:
 *
 *   - **Chocaba.**  El proyecto tiene su propio asignador
 *     (@c src/util/host_allocator.cpp) que tambien define `operator new` y
 *     `operator delete`, y `vmcore` entra con `--whole-archive`, asi que la
 *     definicion se fuerza dentro y el enlazador ve DOS.  Los cuatro tests
 *     dejaron de enlazar, y con ellos el objetivo `all` -- del que cuelga el
 *     paso previo de CPack, o sea el instalador.
 *   - **Y no medía lo que decia.**  El `operator delete` no recibe el tamano,
 *     asi que solo sumaba: el contador no bajaba nunca al liberar.  "Memoria
 *     actual" y "maximo" eran forzosamente el mismo numero, y ese numero era
 *     el TOTAL PEDIDO en toda la ejecucion, no lo que hubiera vivo.
 *
 * Los contadores de verdad ya existen y son por hilo, asi que contarlos no
 * cuesta sincronizacion: @c util::host_alloc_stats().  Un solo mecanismo, en
 * un solo sitio.
 */

#ifndef VESTA_TESTS_UTIL_MEM_STATS_H
#define VESTA_TESTS_UTIL_MEM_STATS_H

#include "util/host_allocator.h"

#include <iostream>

/**
 * @brief Imprime lo que el asignador del proyecto lleva contado.
 *
 * Si el asignador esta apagado (@c VESTA_NO_HOST_SLAB=1) lo dice en vez de
 * imprimir ceros, que se leerian como "no reservo nada".
 */
inline void print_memory_stats() {
    if (!util::host_alloc_active()) {
        std::cout << "Memoria: asignador propio desactivado "
                     "(VESTA_NO_HOST_SLAB), sin contadores\n";
        return;
    }
    const util::HostAllocStats s = util::host_alloc_stats();
    // Vivas = pedidas - devueltas, contando las que libero otro hilo: un bloque
    // devuelto desde fuera esta igual de libre que uno devuelto por su dueno.
    const uint64_t alive =
        (s.small_allocs + s.large_allocs) - (s.small_frees + s.remote_frees);
    std::cout << "Memoria: " << alive << " reservas vivas de "
              << (s.small_allocs + s.large_allocs) << ", " << s.bytes_reserved
              << " bytes comprometidos\n";
}

#endif // VESTA_TESTS_UTIL_MEM_STATS_H
