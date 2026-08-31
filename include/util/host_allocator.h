/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/host_allocator.h
 * @brief Asignador propio del proceso anfitrion, detras de `operator new`.
 *
 * POR QUE EXISTE.  Al compilar, `malloc`+`free` del sistema son el 18,5% del
 * tiempo (medido con VTune sobre 24k lineas: 3,108 s de 16,795 s) y estan
 * REPARTIDOS -- el mayor sitio suelto es el 8,7% de esa cifra --, asi que
 * ningun arreglo puntual los mueve.  Lo que los mueve es cambiar el asignador,
 * porque afecta a todos los sitios a la vez.
 *
 * Y compensa: medido cara a cara con el `malloc` de msvcrt en el patron del
 * compilador (rafagas de reservas pequenas que se sueltan juntas), el nuestro
 * va a 13,5 ns por operacion frente a 44,3 -- **3,3x**.
 *
 * SIN CERROJOS, POR DISENO.  Poner un mutex para hacerlo hilo-seguro se comeria
 * justo la ventaja que se busca.  En su lugar cada hilo tiene sus propias
 * listas libres y el camino rapido no sincroniza NADA: sacar un bloque son dos
 * lecturas y una escritura sobre memoria del propio hilo.
 *
 * LIBERAR ENTRE HILOS.  Es el caso que hunde a los asignadores por hilo
 * ingenuos: lo que reserva un hilo lo suelta otro.  Aqui no se pierde ni se
 * corrompe.  Todos los trozos salen de UNA region reservada de antemano y
 * alineada, asi que:
 *
 *   - saber si un puntero es nuestro son DOS comparaciones (esta o no en la
 *     region), sin buscar en ninguna tabla ni tomar ningun cerrojo;
 *   - de un puntero se saca su trozo con una mascara, y del trozo su cabecera,
 *     que dice el tamano y QUIEN lo posee.
 *
 * Si el que libera no es el dueno, el bloque va a una pila atomica del dueno
 * (un `compare_exchange`, sin bloquear a nadie) y el dueno la recoge entera de
 * un golpe cuando se queda sin bloques.  Es el modelo de tcmalloc / mimalloc.
 *
 * QUE NO HACE.  Lo grande (por encima de @c kMaxSmall) va al asignador del
 * sistema tal cual: ahi el reparto en clases no aporta y el sistema ya sabe
 * hacerlo.  Tampoco devuelve memoria al sistema; la reusa.
 *
 * Se puede desactivar con `VESTA_NO_HOST_SLAB=1`, que hace que todo vaya al
 * sistema.  No es un escape: sin poder apagarlo no hay con que comparar, que
 * es la unica forma de saber si un asignador mejora algo.
 */
#ifndef VESTA_UTIL_HOST_ALLOCATOR_H
#define VESTA_UTIL_HOST_ALLOCATOR_H

#include <cstddef>
#include <cstdint>

namespace util {

/**
 * @brief Contadores de uso del asignador, para diagnostico.
 *
 * Se llevan POR HILO y se suman al pedirlos, para que contarlos no obligue a
 * sincronizar en el camino rapido.
 */
struct HostAllocStats {
    uint64_t small_allocs = 0;   ///< reservas servidas por las clases
    uint64_t small_frees = 0;    ///< liberaciones del propio hilo
    uint64_t remote_frees = 0;   ///< liberaciones hechas por OTRO hilo
    uint64_t large_allocs = 0;   ///< reservas que fueron al sistema
    uint64_t chunks = 0;         ///< trozos pedidos a la region
    uint64_t bytes_reserved = 0; ///< bytes comprometidos de la region
    /// Reparto de los tamanos PEDIDOS, por tramos: <=64, <=128, <=256, <=512,
    /// <=1K, <=4K, <=64K, >64K.  Solo se llena con VESTA_HOST_ALLOC_STATS=1.
    uint64_t size_hist[8] = {};
};

/// Sirve @p n bytes con la garantia de alineacion de `operator new`.  Devuelve
/// nullptr solo si tampoco pudo el asignador del sistema.
void *host_alloc(size_t n) noexcept;

/// Devuelve un bloque de @c host_alloc.  Vale aunque lo reservara OTRO hilo.
void host_free(void *p) noexcept;

/// Suma los contadores de todos los hilos.
HostAllocStats host_alloc_stats();

/// true si el asignador esta sirviendo (false con `VESTA_NO_HOST_SLAB=1`).
bool host_alloc_active();

} // namespace util

#endif // VESTA_UTIL_HOST_ALLOCATOR_H
