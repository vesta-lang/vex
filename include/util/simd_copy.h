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
 * @file simd_copy.h
 * @brief Copia de memoria acelerada por SIMD con deteccion de capacidades en
 * tiempo de ejecucion.
 *
 * Expone una funcion de copia eficiente que selecciona automaticamente el mejor
 * camino disponible segun las capacidades del procesador (detectadas una sola
 * vez al inicio del programa):
 *
 *   - AVX-512F : bloques de 64 bytes con _mm512_loadu_si512 /
 * _mm512_storeu_si512.
 *   - AVX2     : bloques de 32 bytes con _mm256_loadu_si256 /
 * _mm256_storeu_si256.
 *   - SSE2     : bloques de 16 bytes con _mm_loadu_si128   / _mm_storeu_si128.
 *   - Escalar  : std::memcpy estandar (fallback para arquitecturas sin SIMD).
 *
 * La deteccion se realiza con __builtin_cpu_supports() (GCC/Clang) o con
 * __cpuid/__cpuidex (MSVC).  El nivel detectado se almacena en una variable
 * estatica para evitar el coste de CPUID en cada llamada.
 *
 * Uso tipico (vmcopy / vcopyh):
 * @code
 *   #include "util/simd_copy.h"
 *   simd_copy::fast_copy(dst_host_ptr, src_host_ptr, len_bytes);
 * @endcode
 */

#ifndef SIMD_COPY_H
#define SIMD_COPY_H

#include <cstdint>
#include <cstddef>
#include <cstring>

// --- cabeceras de intrinsecos por nivel ---
#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h> // __get_cpuid / __get_cpuid_count
#endif
#if defined(__SSE2__) || defined(_M_X64) || defined(_M_AMD64)
#include <emmintrin.h> // SSE2
#endif
#if defined(__AVX2__)
#include <immintrin.h> // AVX2 / AVX-512
#endif

// Nivel SIMD detectado en tiempo de ejecucion (cacheado estaticamente)
//   0 = sin SIMD (memcpy escalar)
//   1 = SSE2  (bloques 16 B)
//   2 = AVX2  (bloques 32 B)
//   3 = AVX-512F (bloques 64 B)

namespace simd_copy {

/**
 * @brief Detecta el nivel SIMD maximo del procesador actual.
 *
 * Ejecuta CPUID una sola vez y almacena el resultado en una variable
 * estatica para consultas posteriores.  Hilo-seguro (inicializacion
 * garantizada una sola vez por el compilador para static locales en C++11).
 *
 * @return Nivel SIMD: 0=escalar, 1=SSE2, 2=AVX2, 3=AVX512F.
 */
inline int detect_level() {
    static int level = []() -> int {
        int lvl = 0;
#if defined(__GNUC__) || defined(__clang__)
        // GCC/Clang: __builtin_cpu_supports funciona en tiempo de ejecucion
        // incluso si el binario no fue compilado con -mavx2
        if (__builtin_cpu_supports("avx512f")) {
            lvl = 3;
        } else if (__builtin_cpu_supports("avx2")) {
            lvl = 2;
        } else if (__builtin_cpu_supports("sse2")) {
            lvl = 1;
        }
#elif defined(_MSC_VER)
        // MSVC: __cpuid/__cpuidex
        int info[4];
        __cpuid(info, 1);
        if (info[3] & (1 << 26)) lvl = 1; // SSE2: EDX bit 26
        __cpuidex(info, 7, 0);
        if (info[1] & (1 << 5)) lvl = 2;  // AVX2: EBX bit 5
        if (info[1] & (1 << 16)) lvl = 3; // AVX512F: EBX bit 16
#endif
        return lvl;
    }();
    return level;
}

// -------------------------------------------------------------------------
// Implementaciones por nivel (compiladas con el target adecuado)
// -------------------------------------------------------------------------

/**
 * @brief Copia usando registros SSE2 (bloques de 16 bytes).
 *
 * @param dst  Puntero destino (memoria host, puede ser no alineado).
 * @param src  Puntero origen  (memoria host, puede ser no alineado).
 * @param len  Numero de bytes a copiar.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("sse2")))
#endif
inline void copy_sse2(uint8_t *__restrict dst, const uint8_t *__restrict src,
                      size_t len) {
#if defined(__SSE2__) || defined(_M_X64) || defined(_M_AMD64)
    size_t i = 0;
    // bucle principal: bloques de 16 bytes con stores no temporales para
    // evitar la contaminacion de cache en copias grandes
    for (; i + 16 <= len; i += 16) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i *>(src + i));
        _mm_storeu_si128(reinterpret_cast<__m128i *>(dst + i), v);
    }
    // resto de bytes que no caben en un registro completo
    std::memcpy(dst + i, src + i, len - i);
#else
    std::memcpy(dst, src, len);
#endif
}

/**
 * @brief Copia usando registros AVX2 (bloques de 32 bytes).
 *
 * @param dst  Puntero destino (no alineado permitido).
 * @param src  Puntero origen  (no alineado permitido).
 * @param len  Numero de bytes a copiar.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("avx2")))
#endif
inline void copy_avx2(uint8_t *__restrict dst, const uint8_t *__restrict src,
                      size_t len) {
#if defined(__AVX2__)
    size_t i = 0;
    for (; i + 32 <= len; i += 32) {
        __m256i v =
            _mm256_loadu_si256(reinterpret_cast<const __m256i *>(src + i));
        _mm256_storeu_si256(reinterpret_cast<__m256i *>(dst + i), v);
    }
    // remanente con SSE2 para aprovechar los 16 bytes sobrantes si existen
    if (i + 16 <= len) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i *>(src + i));
        _mm_storeu_si128(reinterpret_cast<__m128i *>(dst + i), v);
        i += 16;
    }
    std::memcpy(dst + i, src + i, len - i);
#else
    copy_sse2(dst, src, len);
#endif
}

/**
 * @brief Copia usando registros AVX-512F (bloques de 64 bytes).
 *
 * @param dst  Puntero destino (no alineado permitido).
 * @param src  Puntero origen  (no alineado permitido).
 * @param len  Numero de bytes a copiar.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("avx512f")))
#endif
inline void copy_avx512(uint8_t *__restrict dst, const uint8_t *__restrict src,
                        size_t len) {
#if defined(__AVX512F__)
    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        __m512i v = _mm512_loadu_si512(reinterpret_cast<const void *>(src + i));
        _mm512_storeu_si512(reinterpret_cast<void *>(dst + i), v);
    }
    // remanente con AVX2 si quedan >= 32 bytes
    copy_avx2(dst + i, src + i, len - i);
#else
    copy_avx2(dst, src, len);
#endif
}

// -------------------------------------------------------------------------
// Punto de entrada publico
// -------------------------------------------------------------------------

/**
 * @brief Copia @p len bytes de @p src a @p dst usando el mejor nivel SIMD
 * disponible.
 *
 * Para copias pequenas (< 16 bytes) usa directamente std::memcpy para evitar
 * el overhead de los registros SIMD.  Para copias mayores selecciona el nivel
 * detectado en la primera llamada.
 *
 * @param dst Puntero destino (memoria host).
 * @param src Puntero origen  (memoria host).
 * @param len Numero de bytes a copiar.
 */
/**
 * @brief Copia de MENOS de 16 bytes sin llamar a nadie.
 *
 * `std::memcpy` con un tamano VARIABLE es una llamada a la biblioteca del
 * sistema, y la de Windows no despacha por capacidad de la CPU: se queda en el
 * camino escalar y ademas cuesta la llamada.  Para uno, dos, cuatro u ocho
 * bytes -- que es el tamano de una carga o un almacenamiento de la VM, o sea el
 * caso comun con diferencia -- eso es todo coste y ningun trabajo.
 *
 * La tecnica es la de BLOQUES SOLAPADOS: dos accesos del mayor ancho que quepa,
 * uno al principio y otro al final, cubren cualquier longitud de su rango sin
 * bucle y sin ramas por byte.  Se solapan en el medio, y eso da igual: se
 * escribe dos veces el mismo dato.
 *
 * Sin bucle, sin llamada y sin registros vectoriales que montar.
 */
inline void copy_small(uint8_t *__restrict d, const uint8_t *__restrict s,
                       size_t n) noexcept {
    if (n >= 8) {
        uint64_t a, b;
        std::memcpy(&a, s, 8);
        std::memcpy(&b, s + n - 8, 8);
        std::memcpy(d, &a, 8);
        std::memcpy(d + n - 8, &b, 8);
        return;
    }
    if (n >= 4) {
        uint32_t a, b;
        std::memcpy(&a, s, 4);
        std::memcpy(&b, s + n - 4, 4);
        std::memcpy(d, &a, 4);
        std::memcpy(d + n - 4, &b, 4);
        return;
    }
    if (n >= 2) {
        uint16_t a, b;
        std::memcpy(&a, s, 2);
        std::memcpy(&b, s + n - 2, 2);
        std::memcpy(d, &a, 2);
        std::memcpy(d + n - 2, &b, 2);
        return;
    }
    if (n == 1) *d = *s;
}

inline void fast_copy(void *__restrict dst, const void *__restrict src,
                      size_t len) {
    if (len == 0) return;

    /* Por debajo de 16 bytes no compensan los registros vectoriales, pero
     * tampoco una llamada a la biblioteca: se copia aqui mismo.  Ver
     * `copy_small`. */
    if (len < 16) {
        copy_small(static_cast<uint8_t *>(dst),
                   static_cast<const uint8_t *>(src), len);
        return;
    }

    auto *d = static_cast<uint8_t *>(dst);
    const auto *s = static_cast<const uint8_t *>(src);

    switch (detect_level()) {
    case 3: copy_avx512(d, s, len); break;
    case 2: copy_avx2(d, s, len); break;
    case 1: copy_sse2(d, s, len); break;
    default: std::memcpy(d, s, len); break;
    }
}

} // namespace simd_copy

#endif // SIMD_COPY_H
