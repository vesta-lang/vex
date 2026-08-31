/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/fnv.h
 * @brief Hashing FNV-1a, compartido por quien computa huellas.
 *
 * Vivia dentro del asignador de banco ancho, que fue quien lo necesito primero.
 * Al hacerle falta tambien al subsistema de depuracion habia dos salidas malas
 * -- que la depuracion dependiera del asignador de registros, o copiar el
 * algoritmo -- y una buena: subirlo a un sitio comun.  Quien lo usaba antes lo
 * sigue viendo donde estaba.
 *
 * FNV-1a no es criptografico y aqui no hace falta que lo sea: se usa para dar
 * identidad a datos propios, no para resistir a nadie que intente provocar una
 * colision.
 */

#ifndef VESTA_UTIL_FNV_H
#define VESTA_UTIL_FNV_H

#include <cstddef>
#include <cstdint>

namespace util {

/**
 * @brief Semilla y primo FNV-1a de 64 bits.
 *
 * Los dos numeros son los que define el algoritmo, no unos cualesquiera: la
 * semilla es 0xcbf29ce484222325 y el primo 0x100000001b3.  Estuvieron mal --
 * a la semilla le faltaba un digito, 1469598103934665603 en vez de
 * 14695981039346656037 -- y el hash seguia funcionando, porque como identidad
 * de datos propios sirve cualquier par razonable mientras TODOS usen el mismo.
 *
 * Que funcionara es justo lo que lo hizo durar: nadie tenia motivo para
 * mirarlo, y mientras tanto el algoritmo se copiaba a mano por el proyecto con
 * el numero equivocado y el comentario diciendo "FNV-1a".  Se corrigio el
 * 2026-08-29, y con el todas las copias pasaron a usar ESTAS constantes.
 *
 * Cambiar el valor mueve cualquier cosa guardada con el hash viejo, asi que al
 * corregirlo hubo que tirar las caches.  Si vuelve a cambiar, lo mismo.
 */
static constexpr uint64_t kFnvOffset =
    14695981039346656037ull;                            // 0xcbf29ce484222325
static constexpr uint64_t kFnvPrime = 1099511628211ull; // 0x100000001b3

/**
 * @brief Mezcla un entero de 64 bits (byte a byte) en un acumulador.
 * @param h Acumulador.
 * @param v Valor a mezclar.
 * @return El acumulador actualizado.
 */
inline uint64_t fnv_mix(uint64_t h, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        h ^= (v & 0xff);
        h *= kFnvPrime;
        v >>= 8;
    }
    return h;
}

/**
 * @brief Mezcla una secuencia de bytes en un acumulador.
 * @param h Acumulador.
 * @param data Bytes.
 * @param size Cuantos.
 * @return El acumulador actualizado.
 */
inline uint64_t fnv_bytes(uint64_t h, const void *data, size_t size) noexcept {
    const auto *p = static_cast<const unsigned char *>(data);
    for (size_t i = 0; i < size; ++i) {
        h ^= p[i];
        h *= kFnvPrime;
    }
    return h;
}

} // namespace util

#endif // VESTA_UTIL_FNV_H
