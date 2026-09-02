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
 * @file exec_instruction_float.cpp
 * @brief Implementacion con despacho SIMD en tiempo de ejecucion de las
 *        instrucciones de punto flotante de VestaVM.
 *
 * Arquitectura de despacho en tiempo de ejecucion:
 *
 *   Al primer uso se detecta el nivel ISA del CPU mediante
 * __builtin_cpu_supports (GCC) y se almacena en un atomic para lecturas
 * lock-free posteriores. Cada instruccion packed elige la implementacion mas
 * eficiente disponible:
 *
 *   | Nivel    | Ancho max | Intrinsico           | Requisito de CPU | |
 * -------- | --------- | -------------------- | --------------------------- |
 *   | SCALAR   |  64 bits  | C++ estandar         | cualquier x86-64 | | SSE2
 * | 128 bits  | _mm_*_pd / _mm_*_ps  | universal en x86-64         | | AVX |
 * 256 bits  | _mm256_*_pd/ps       | Intel SandyBridge / AMD BD  | | FMA      |
 * 256 bits  | _mm256_fmadd_*       | Intel Haswell / AMD Piledr. | | AVX512   |
 * 512 bits  | _mm512_*_pd/ps       | Intel Skylake-X / Ice Lake  |
 *
 * Los datos de ZmmRegister::data estan alineados a 64 bytes (alignas(64)),
 * lo que permite el uso de cargas/almacenamientos alineados en todos los
 * niveles: _mm_load_pd   (requiere 16 bytes)  -- siempre valido
 *   _mm256_load_pd(requiere 32 bytes)  -- siempre valido
 *   _mm512_load_pd(requiere 64 bytes)  -- siempre valido
 *
 * Instrucciones implementadas (opcodes extendidos 0xF0-0xFC):
 *   FMOV  (0xF0): copia ZMM->ZMM con zeroing de bytes superiores.
 *   FADD  (0xF1): suma flotante escalar o packed.
 *   FSUB  (0xF2): resta flotante escalar o packed.
 *   FMUL  (0xF3): multiplicacion flotante escalar o packed.
 *   FDIV  (0xF4): division flotante escalar o packed.
 *   FCMP  (0xF5): comparacion escalar; establece flags ZF/SF/CF.
 *   FSQRT (0xF6): raiz cuadrada escalar o packed.
 *   FABS  (0xF7): valor absoluto via AND de mascara de signo.
 *   FNEG  (0xF8): negacion via XOR del bit de signo.
 *   FCVT  (0xF9): conversion int<->float entre bancos GP y ZMM.
 *   FMOWI (0xFA): carga inmediato IEEE 754 en registro ZMM.
 *   FLOAD (0xFB): carga f64/packed desde memoria VM.
 *   FSTORE(0xFC): almacena f64/packed en memoria VM.
 */

#include <immintrin.h> /* SSE2 hasta AVX-512: un solo encabezado con target por funcion */
#include <atomic>
#include <cmath>
#include <cstring>

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"

namespace runtime {

// =========================================================================
// Deteccion de nivel ISA en tiempo de ejecucion
// =========================================================================

/**
 * @brief Nivel SIMD maximo disponible en el CPU actual.
 *
 * Ordenado de menor a mayor capacidad; cada nivel implica los anteriores.
 */
enum class FloatISA : uint8_t {
    SCALAR = 0, ///< Fallback portable: operaciones C++ puras
    SSE2 = 1,   ///< SSE2 128-bit: 2xf64 o 4xf32 por instruccion
    AVX = 2,    ///< AVX  256-bit: 4xf64 o 8xf32 por instruccion
    FMA = 3,    ///< AVX + FMA3: misma anchura, operaciones fusionadas
    AVX512 = 4, ///< AVX-512F 512-bit: 8xf64 o 16xf32 por instruccion
};

/**
 * @brief Nivel ISA detectado; -1 indica que aun no se ha detectado.
 *
 * Acceso con memory_order_relaxed es suficiente: la deteccion es idempotente
 * y no protege ninguna region critica (todos los hilos llegan al mismo
 * resultado).
 */
static std::atomic<int8_t> g_float_isa{-1};

/**
 * @brief Devuelve el nivel ISA del CPU, detectandolo la primera vez.
 *
 * El hot-path (cached >= 0) es un unico load relaxed sin ninguna rama.
 *
 * @return Nivel FloatISA maximo disponible.
 */
static inline FloatISA float_isa() {
    int8_t cached = g_float_isa.load(std::memory_order_relaxed);
    if (__builtin_expect(cached >= 0, 1)) return static_cast<FloatISA>(cached);

    /* primera llamada: detectar (posible carrera benigna, resultado es el
     * mismo) */
    FloatISA level;
    if (__builtin_cpu_supports("avx512f"))
        level = FloatISA::AVX512;
    else if (__builtin_cpu_supports("fma"))
        level = FloatISA::FMA;
    else if (__builtin_cpu_supports("avx"))
        level = FloatISA::AVX;
    else if (__builtin_cpu_supports("sse2"))
        level = FloatISA::SSE2;
    else
        level = FloatISA::SCALAR;

    g_float_isa.store(static_cast<int8_t>(level), std::memory_order_relaxed);
    return level;
}

/**
 * @brief Calcula el numero de bytes segun el campo mode (0-3).
 *
 * mode 0 -> 8  bytes (escalar f64)
 * mode 1 -> 16 bytes (XMM)
 * mode 2 -> 32 bytes (YMM)
 * mode 3 -> 64 bytes (ZMM)
 *
 * @param mode Campo de 2 bits (0-3).
 * @return Numero de bytes correspondiente.
 */
static inline int fmode_bytes(uint8_t mode) {
    return 8 << mode;
}

// =========================================================================
// Macros para generar implementaciones SIMD de operaciones binarias
//
// Cada macro genera una funcion estatica con el atributo [[gnu::target(...)]]
// correcto para compilar instrucciones SIMD aunque la unidad de traduccion
// use -march=x86-64 como base.
//
// Convenio de nombres generados:
//   <op>_sse2_f64 / <op>_sse2_f32  -- usa bucle de instrucciones XMM (128b)
//   <op>_avx_f64  / <op>_avx_f32   -- usa YMM (256b), XMM para modo<2
//   <op>_avx512_f64/<op>_avx512_f32 -- usa ZMM (512b), YMM/XMM para modos<3
//
// Parametros de las funciones generadas:
//   d     -- puntero al buffer de destino (ZmmRegister::data, alignas(64))
//   s     -- puntero al buffer de fuente  (ZmmRegister::data, alignas(64))
//   bytes -- numero de bytes a procesar (16, 32 o 64)
//
// El zeroing de bytes superiores (necesario para mode<3) se realiza con
// __builtin_memset de tamano constante; el compilador lo convierte en
// almacenamientos SIMD cuando la funcion ya tiene el target apropiado.
// =========================================================================

/* --- SSE2: bucle de instrucciones XMM de 128 bits --- */

#define DEF_BINARY_SSE2_F64(fname, op128)                                      \
    [[gnu::target("sse2")]]                                                    \
    static void fname##_sse2_f64(uint8_t *__restrict__ d,                      \
                                 const uint8_t *__restrict__ s, int bytes) {   \
        for (int i = 0; i < bytes; i += 16) {                                  \
            __m128d vd = _mm_load_pd(reinterpret_cast<const double *>(d + i)); \
            __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s + i)); \
            _mm_store_pd(reinterpret_cast<double *>(d + i), op128(vd, vs));    \
        }                                                                      \
        if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);            \
    }

#define DEF_BINARY_SSE2_F32(fname, op128)                                      \
    [[gnu::target("sse2")]]                                                    \
    static void fname##_sse2_f32(uint8_t *__restrict__ d,                      \
                                 const uint8_t *__restrict__ s, int bytes) {   \
        for (int i = 0; i < bytes; i += 16) {                                  \
            __m128 vd = _mm_load_ps(reinterpret_cast<const float *>(d + i));   \
            __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s + i));   \
            _mm_store_ps(reinterpret_cast<float *>(d + i), op128(vd, vs));     \
        }                                                                      \
        if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);            \
    }

/* --- AVX: YMM (256b) para bytes>=32, XMM para bytes==16 --- */

#define DEF_BINARY_AVX_F64(fname, op128, op256)                                \
    [[gnu::target("avx")]]                                                     \
    static void fname##_avx_f64(uint8_t *__restrict__ d,                       \
                                const uint8_t *__restrict__ s, int bytes) {    \
        if (__builtin_expect(bytes < 32, 0)) {                                 \
            __m128d vd = _mm_load_pd(reinterpret_cast<const double *>(d));     \
            __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s));     \
            _mm_store_pd(reinterpret_cast<double *>(d), op128(vd, vs));        \
            __builtin_memset(d + 16, 0, 48);                                   \
            return;                                                            \
        }                                                                      \
        for (int i = 0; i < bytes; i += 32) {                                  \
            __m256d vd =                                                       \
                _mm256_load_pd(reinterpret_cast<const double *>(d + i));       \
            __m256d vs =                                                       \
                _mm256_load_pd(reinterpret_cast<const double *>(s + i));       \
            _mm256_store_pd(reinterpret_cast<double *>(d + i), op256(vd, vs)); \
        }                                                                      \
        if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);            \
    }

#define DEF_BINARY_AVX_F32(fname, op128, op256)                                \
    [[gnu::target("avx")]]                                                     \
    static void fname##_avx_f32(uint8_t *__restrict__ d,                       \
                                const uint8_t *__restrict__ s, int bytes) {    \
        if (__builtin_expect(bytes < 32, 0)) {                                 \
            __m128 vd = _mm_load_ps(reinterpret_cast<const float *>(d));       \
            __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s));       \
            _mm_store_ps(reinterpret_cast<float *>(d), op128(vd, vs));         \
            __builtin_memset(d + 16, 0, 48);                                   \
            return;                                                            \
        }                                                                      \
        for (int i = 0; i < bytes; i += 32) {                                  \
            __m256 vd =                                                        \
                _mm256_load_ps(reinterpret_cast<const float *>(d + i));        \
            __m256 vs =                                                        \
                _mm256_load_ps(reinterpret_cast<const float *>(s + i));        \
            _mm256_store_ps(reinterpret_cast<float *>(d + i), op256(vd, vs));  \
        }                                                                      \
        if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);            \
    }

/* --- AVX-512: ZMM (512b) para bytes==64, YMM/XMM para bytes menores --- */

#define DEF_BINARY_AVX512_F64(fname, op128, op256, op512)                      \
    [[gnu::target("avx512f")]]                                                 \
    static void fname##_avx512_f64(uint8_t *__restrict__ d,                    \
                                   const uint8_t *__restrict__ s, int bytes) { \
        if (bytes == 64) {                                                     \
            __m512d vd = _mm512_load_pd(reinterpret_cast<const double *>(d));  \
            __m512d vs = _mm512_load_pd(reinterpret_cast<const double *>(s));  \
            _mm512_store_pd(reinterpret_cast<double *>(d), op512(vd, vs));     \
        } else if (bytes == 32) {                                              \
            __m256d vd = _mm256_load_pd(reinterpret_cast<const double *>(d));  \
            __m256d vs = _mm256_load_pd(reinterpret_cast<const double *>(s));  \
            _mm256_store_pd(reinterpret_cast<double *>(d), op256(vd, vs));     \
            __builtin_memset(d + 32, 0, 32);                                   \
        } else {                                                               \
            __m128d vd = _mm_load_pd(reinterpret_cast<const double *>(d));     \
            __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s));     \
            _mm_store_pd(reinterpret_cast<double *>(d), op128(vd, vs));        \
            __builtin_memset(d + 16, 0, 48);                                   \
        }                                                                      \
    }

#define DEF_BINARY_AVX512_F32(fname, op128, op256, op512)                      \
    [[gnu::target("avx512f")]]                                                 \
    static void fname##_avx512_f32(uint8_t *__restrict__ d,                    \
                                   const uint8_t *__restrict__ s, int bytes) { \
        if (bytes == 64) {                                                     \
            __m512 vd = _mm512_load_ps(reinterpret_cast<const float *>(d));    \
            __m512 vs = _mm512_load_ps(reinterpret_cast<const float *>(s));    \
            _mm512_store_ps(reinterpret_cast<float *>(d), op512(vd, vs));      \
        } else if (bytes == 32) {                                              \
            __m256 vd = _mm256_load_ps(reinterpret_cast<const float *>(d));    \
            __m256 vs = _mm256_load_ps(reinterpret_cast<const float *>(s));    \
            _mm256_store_ps(reinterpret_cast<float *>(d), op256(vd, vs));      \
            __builtin_memset(d + 32, 0, 32);                                   \
        } else {                                                               \
            __m128 vd = _mm_load_ps(reinterpret_cast<const float *>(d));       \
            __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s));       \
            _mm_store_ps(reinterpret_cast<float *>(d), op128(vd, vs));         \
            __builtin_memset(d + 16, 0, 48);                                   \
        }                                                                      \
    }

/* =========================================================================
 * Instanciacion de las 4 operaciones binarias en los 3 niveles ISA
 * para f64 (pd) y f32 (ps): 4 ops x 3 niveles x 2 tipos = 24 funciones.
 * ========================================================================= */

DEF_BINARY_SSE2_F64(fadd, _mm_add_pd)
DEF_BINARY_SSE2_F64(fsub, _mm_sub_pd)
DEF_BINARY_SSE2_F64(fmul, _mm_mul_pd)
DEF_BINARY_SSE2_F64(fdiv, _mm_div_pd)

DEF_BINARY_AVX_F64(fadd, _mm_add_pd, _mm256_add_pd)
DEF_BINARY_AVX_F64(fsub, _mm_sub_pd, _mm256_sub_pd)
DEF_BINARY_AVX_F64(fmul, _mm_mul_pd, _mm256_mul_pd)
DEF_BINARY_AVX_F64(fdiv, _mm_div_pd, _mm256_div_pd)

DEF_BINARY_AVX512_F64(fadd, _mm_add_pd, _mm256_add_pd, _mm512_add_pd)
DEF_BINARY_AVX512_F64(fsub, _mm_sub_pd, _mm256_sub_pd, _mm512_sub_pd)
DEF_BINARY_AVX512_F64(fmul, _mm_mul_pd, _mm256_mul_pd, _mm512_mul_pd)
DEF_BINARY_AVX512_F64(fdiv, _mm_div_pd, _mm256_div_pd, _mm512_div_pd)

DEF_BINARY_SSE2_F32(fadd, _mm_add_ps)
DEF_BINARY_SSE2_F32(fsub, _mm_sub_ps)
DEF_BINARY_SSE2_F32(fmul, _mm_mul_ps)
DEF_BINARY_SSE2_F32(fdiv, _mm_div_ps)

DEF_BINARY_AVX_F32(fadd, _mm_add_ps, _mm256_add_ps)
DEF_BINARY_AVX_F32(fsub, _mm_sub_ps, _mm256_sub_ps)
DEF_BINARY_AVX_F32(fmul, _mm_mul_ps, _mm256_mul_ps)
DEF_BINARY_AVX_F32(fdiv, _mm_div_ps, _mm256_div_ps)

DEF_BINARY_AVX512_F32(fadd, _mm_add_ps, _mm256_add_ps, _mm512_add_ps)
DEF_BINARY_AVX512_F32(fsub, _mm_sub_ps, _mm256_sub_ps, _mm512_sub_ps)
DEF_BINARY_AVX512_F32(fmul, _mm_mul_ps, _mm256_mul_ps, _mm512_mul_ps)
DEF_BINARY_AVX512_F32(fdiv, _mm_div_ps, _mm256_div_ps, _mm512_div_ps)

/* =========================================================================
 * Macro de despacho para operaciones binarias packed
 *
 * Elige la implementacion correcta segun el nivel ISA detectado, el numero
 * de bytes a procesar y el tipo de elemento (f32/f64).
 * ========================================================================= */

#define DISPATCH_BINARY_PACKED(dp, sp, bytes, is_f32, fname)                   \
    do {                                                                       \
        switch (float_isa()) {                                                 \
        case FloatISA::AVX512:                                                 \
            (is_f32) ? fname##_avx512_f32(dp, sp, bytes)                       \
                     : fname##_avx512_f64(dp, sp, bytes);                      \
            break;                                                             \
        case FloatISA::FMA:                                                    \
        case FloatISA::AVX:                                                    \
            (is_f32) ? fname##_avx_f32(dp, sp, bytes)                          \
                     : fname##_avx_f64(dp, sp, bytes);                         \
            break;                                                             \
        default:                                                               \
            (is_f32) ? fname##_sse2_f32(dp, sp, bytes)                         \
                     : fname##_sse2_f64(dp, sp, bytes);                        \
            break;                                                             \
        }                                                                      \
    } while (0)

// =========================================================================
// FSQRT: raiz cuadrada packed
//
// Para FSQRT no existe el patron binario; se generan funciones separadas
// porque el operando fuente (src) puede diferir del destino (dst).
// VSQRTPD/VSQRTPS son instrucciones de un solo operando fuente.
// =========================================================================

#define DEF_SQRT_SSE2_F64(unused)                                              \
    [[gnu::target("sse2")]]                                                    \
    static void fsqrt_sse2_f64(uint8_t *__restrict__ d,                        \
                               const uint8_t *__restrict__ s, int bytes) {     \
        for (int i = 0; i < bytes; i += 16) {                                  \
            __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s + i)); \
            _mm_store_pd(reinterpret_cast<double *>(d + i), _mm_sqrt_pd(vs));  \
        }                                                                      \
        if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);            \
    }

DEF_SQRT_SSE2_F64(unused)

[[gnu::target("sse2")]]
static void fsqrt_sse2_f32(uint8_t *__restrict__ d,
                           const uint8_t *__restrict__ s, int bytes) {
    for (int i = 0; i < bytes; i += 16) {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s + i));
        _mm_store_ps(reinterpret_cast<float *>(d + i), _mm_sqrt_ps(vs));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx")]]
static void fsqrt_avx_f64(uint8_t *__restrict__ d,
                          const uint8_t *__restrict__ s, int bytes) {
    if (__builtin_expect(bytes < 32, 0)) {
        __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s));
        _mm_store_pd(reinterpret_cast<double *>(d), _mm_sqrt_pd(vs));
        __builtin_memset(d + 16, 0, 48);
        return;
    }
    for (int i = 0; i < bytes; i += 32) {
        __m256d vs = _mm256_load_pd(reinterpret_cast<const double *>(s + i));
        _mm256_store_pd(reinterpret_cast<double *>(d + i), _mm256_sqrt_pd(vs));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx")]]
static void fsqrt_avx_f32(uint8_t *__restrict__ d,
                          const uint8_t *__restrict__ s, int bytes) {
    if (__builtin_expect(bytes < 32, 0)) {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s));
        _mm_store_ps(reinterpret_cast<float *>(d), _mm_sqrt_ps(vs));
        __builtin_memset(d + 16, 0, 48);
        return;
    }
    for (int i = 0; i < bytes; i += 32) {
        __m256 vs = _mm256_load_ps(reinterpret_cast<const float *>(s + i));
        _mm256_store_ps(reinterpret_cast<float *>(d + i), _mm256_sqrt_ps(vs));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx512f")]]
static void fsqrt_avx512_f64(uint8_t *__restrict__ d,
                             const uint8_t *__restrict__ s, int bytes) {
    if (bytes == 64) {
        __m512d vs = _mm512_load_pd(reinterpret_cast<const double *>(s));
        _mm512_store_pd(reinterpret_cast<double *>(d), _mm512_sqrt_pd(vs));
    } else if (bytes == 32) {
        __m256d vs = _mm256_load_pd(reinterpret_cast<const double *>(s));
        _mm256_store_pd(reinterpret_cast<double *>(d), _mm256_sqrt_pd(vs));
        __builtin_memset(d + 32, 0, 32);
    } else {
        __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s));
        _mm_store_pd(reinterpret_cast<double *>(d), _mm_sqrt_pd(vs));
        __builtin_memset(d + 16, 0, 48);
    }
}

[[gnu::target("avx512f")]]
static void fsqrt_avx512_f32(uint8_t *__restrict__ d,
                             const uint8_t *__restrict__ s, int bytes) {
    if (bytes == 64) {
        __m512 vs = _mm512_load_ps(reinterpret_cast<const float *>(s));
        _mm512_store_ps(reinterpret_cast<float *>(d), _mm512_sqrt_ps(vs));
    } else if (bytes == 32) {
        __m256 vs = _mm256_load_ps(reinterpret_cast<const float *>(s));
        _mm256_store_ps(reinterpret_cast<float *>(d), _mm256_sqrt_ps(vs));
        __builtin_memset(d + 32, 0, 32);
    } else {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s));
        _mm_store_ps(reinterpret_cast<float *>(d), _mm_sqrt_ps(vs));
        __builtin_memset(d + 16, 0, 48);
    }
}

// =========================================================================
// FABS: valor absoluto flotante via mascara de bit de signo
//
// Tecnica: limpiar el bit de signo con ANDNOT(sign_mask, v).
//   -0.0 como double = 0x8000000000000000 (solo el bit 63).
//   _mm_andnot_pd(sign, v) = v & ~sign = v con bit de signo a 0.
//
// Para AVX-512, _mm512_andnot_pd no esta disponible en todas las
// implementaciones de AVX-512F, por lo que se usa la version entera:
//   _mm512_castpd_si512 (cast sin instruccion) + _mm512_and_epi64.
// =========================================================================

[[gnu::target("sse2")]]
static void fabs_sse2_f64(uint8_t *__restrict__ d,
                          const uint8_t *__restrict__ s, int bytes) {
    const __m128d sign = _mm_set1_pd(-0.0); /* mascara: bit 63 a 1, resto 0 */
    for (int i = 0; i < bytes; i += 16) {
        __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s + i));
        _mm_store_pd(reinterpret_cast<double *>(d + i),
                     _mm_andnot_pd(sign, vs));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("sse2")]]
static void fabs_sse2_f32(uint8_t *__restrict__ d,
                          const uint8_t *__restrict__ s, int bytes) {
    const __m128 sign = _mm_set1_ps(-0.0f);
    for (int i = 0; i < bytes; i += 16) {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s + i));
        _mm_store_ps(reinterpret_cast<float *>(d + i), _mm_andnot_ps(sign, vs));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx")]]
static void fabs_avx_f64(uint8_t *__restrict__ d, const uint8_t *__restrict__ s,
                         int bytes) {
    const __m256d sign = _mm256_set1_pd(-0.0);
    if (__builtin_expect(bytes < 32, 0)) {
        __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s));
        _mm_store_pd(reinterpret_cast<double *>(d),
                     _mm_andnot_pd(_mm256_castpd256_pd128(sign), vs));
        __builtin_memset(d + 16, 0, 48);
        return;
    }
    for (int i = 0; i < bytes; i += 32) {
        __m256d vs = _mm256_load_pd(reinterpret_cast<const double *>(s + i));
        _mm256_store_pd(reinterpret_cast<double *>(d + i),
                        _mm256_andnot_pd(sign, vs));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx")]]
static void fabs_avx_f32(uint8_t *__restrict__ d, const uint8_t *__restrict__ s,
                         int bytes) {
    const __m256 sign = _mm256_set1_ps(-0.0f);
    if (__builtin_expect(bytes < 32, 0)) {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s));
        _mm_store_ps(reinterpret_cast<float *>(d),
                     _mm_andnot_ps(_mm256_castps256_ps128(sign), vs));
        __builtin_memset(d + 16, 0, 48);
        return;
    }
    for (int i = 0; i < bytes; i += 32) {
        __m256 vs = _mm256_load_ps(reinterpret_cast<const float *>(s + i));
        _mm256_store_ps(reinterpret_cast<float *>(d + i),
                        _mm256_andnot_ps(sign, vs));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx512f")]]
static void fabs_avx512_f64(uint8_t *__restrict__ d,
                            const uint8_t *__restrict__ s, int bytes) {
    /* mascara de valor absoluto: todos los bits a 1 excepto el bit de signo */
    const __m512i abs_mask =
        _mm512_set1_epi64(static_cast<int64_t>(0x7FFFFFFFFFFFFFFF));
    if (bytes == 64) {
        __m512i vi = _mm512_castpd_si512(
            _mm512_load_pd(reinterpret_cast<const double *>(s)));
        _mm512_store_pd(reinterpret_cast<double *>(d),
                        _mm512_castsi512_pd(_mm512_and_epi64(vi, abs_mask)));
    } else if (bytes == 32) {
        __m256d vs = _mm256_load_pd(reinterpret_cast<const double *>(s));
        _mm256_store_pd(reinterpret_cast<double *>(d),
                        _mm256_andnot_pd(_mm256_set1_pd(-0.0), vs));
        __builtin_memset(d + 32, 0, 32);
    } else {
        __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s));
        _mm_store_pd(reinterpret_cast<double *>(d),
                     _mm_andnot_pd(_mm_set1_pd(-0.0), vs));
        __builtin_memset(d + 16, 0, 48);
    }
}

[[gnu::target("avx512f")]]
static void fabs_avx512_f32(uint8_t *__restrict__ d,
                            const uint8_t *__restrict__ s, int bytes) {
    const __m512i abs_mask =
        _mm512_set1_epi32(static_cast<int32_t>(0x7FFFFFFF));
    if (bytes == 64) {
        __m512i vi = _mm512_castps_si512(
            _mm512_load_ps(reinterpret_cast<const float *>(s)));
        _mm512_store_ps(reinterpret_cast<float *>(d),
                        _mm512_castsi512_ps(_mm512_and_epi32(vi, abs_mask)));
    } else if (bytes == 32) {
        __m256 vs = _mm256_load_ps(reinterpret_cast<const float *>(s));
        _mm256_store_ps(reinterpret_cast<float *>(d),
                        _mm256_andnot_ps(_mm256_set1_ps(-0.0f), vs));
        __builtin_memset(d + 32, 0, 32);
    } else {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s));
        _mm_store_ps(reinterpret_cast<float *>(d),
                     _mm_andnot_ps(_mm_set1_ps(-0.0f), vs));
        __builtin_memset(d + 16, 0, 48);
    }
}

// =========================================================================
// FNEG: negacion flotante via XOR del bit de signo
//
// Tecnica: XOR con -0.0 invierte unicamente el bit de signo IEEE 754.
//   _mm_xor_pd(-0.0, v) = v con bit de signo invertido.
// =========================================================================

[[gnu::target("sse2")]]
static void fneg_sse2_f64(uint8_t *__restrict__ d,
                          const uint8_t *__restrict__ s, int bytes) {
    const __m128d sign = _mm_set1_pd(-0.0);
    for (int i = 0; i < bytes; i += 16) {
        __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s + i));
        _mm_store_pd(reinterpret_cast<double *>(d + i), _mm_xor_pd(vs, sign));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("sse2")]]
static void fneg_sse2_f32(uint8_t *__restrict__ d,
                          const uint8_t *__restrict__ s, int bytes) {
    const __m128 sign = _mm_set1_ps(-0.0f);
    for (int i = 0; i < bytes; i += 16) {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s + i));
        _mm_store_ps(reinterpret_cast<float *>(d + i), _mm_xor_ps(vs, sign));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx")]]
static void fneg_avx_f64(uint8_t *__restrict__ d, const uint8_t *__restrict__ s,
                         int bytes) {
    const __m256d sign = _mm256_set1_pd(-0.0);
    if (__builtin_expect(bytes < 32, 0)) {
        __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s));
        _mm_store_pd(reinterpret_cast<double *>(d),
                     _mm_xor_pd(vs, _mm256_castpd256_pd128(sign)));
        __builtin_memset(d + 16, 0, 48);
        return;
    }
    for (int i = 0; i < bytes; i += 32) {
        __m256d vs = _mm256_load_pd(reinterpret_cast<const double *>(s + i));
        _mm256_store_pd(reinterpret_cast<double *>(d + i),
                        _mm256_xor_pd(vs, sign));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx")]]
static void fneg_avx_f32(uint8_t *__restrict__ d, const uint8_t *__restrict__ s,
                         int bytes) {
    const __m256 sign = _mm256_set1_ps(-0.0f);
    if (__builtin_expect(bytes < 32, 0)) {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s));
        _mm_store_ps(reinterpret_cast<float *>(d),
                     _mm_xor_ps(vs, _mm256_castps256_ps128(sign)));
        __builtin_memset(d + 16, 0, 48);
        return;
    }
    for (int i = 0; i < bytes; i += 32) {
        __m256 vs = _mm256_load_ps(reinterpret_cast<const float *>(s + i));
        _mm256_store_ps(reinterpret_cast<float *>(d + i),
                        _mm256_xor_ps(vs, sign));
    }
    if (bytes < 64) __builtin_memset(d + bytes, 0, 64 - bytes);
}

[[gnu::target("avx512f")]]
static void fneg_avx512_f64(uint8_t *__restrict__ d,
                            const uint8_t *__restrict__ s, int bytes) {
    /* XOR con la mascara de signo invierte el bit 63 de cada lane f64 */
    const __m512i sign_mask =
        _mm512_set1_epi64(static_cast<int64_t>(0x8000000000000000));
    if (bytes == 64) {
        __m512i vi = _mm512_castpd_si512(
            _mm512_load_pd(reinterpret_cast<const double *>(s)));
        _mm512_store_pd(reinterpret_cast<double *>(d),
                        _mm512_castsi512_pd(_mm512_xor_epi64(vi, sign_mask)));
    } else if (bytes == 32) {
        __m256d vs = _mm256_load_pd(reinterpret_cast<const double *>(s));
        _mm256_store_pd(reinterpret_cast<double *>(d),
                        _mm256_xor_pd(vs, _mm256_set1_pd(-0.0)));
        __builtin_memset(d + 32, 0, 32);
    } else {
        __m128d vs = _mm_load_pd(reinterpret_cast<const double *>(s));
        _mm_store_pd(reinterpret_cast<double *>(d),
                     _mm_xor_pd(vs, _mm_set1_pd(-0.0)));
        __builtin_memset(d + 16, 0, 48);
    }
}

[[gnu::target("avx512f")]]
static void fneg_avx512_f32(uint8_t *__restrict__ d,
                            const uint8_t *__restrict__ s, int bytes) {
    const __m512i sign_mask =
        _mm512_set1_epi32(static_cast<int32_t>(0x80000000));
    if (bytes == 64) {
        __m512i vi = _mm512_castps_si512(
            _mm512_load_ps(reinterpret_cast<const float *>(s)));
        _mm512_store_ps(reinterpret_cast<float *>(d),
                        _mm512_castsi512_ps(_mm512_xor_epi32(vi, sign_mask)));
    } else if (bytes == 32) {
        __m256 vs = _mm256_load_ps(reinterpret_cast<const float *>(s));
        _mm256_store_ps(reinterpret_cast<float *>(d),
                        _mm256_xor_ps(vs, _mm256_set1_ps(-0.0f)));
        __builtin_memset(d + 32, 0, 32);
    } else {
        __m128 vs = _mm_load_ps(reinterpret_cast<const float *>(s));
        _mm_store_ps(reinterpret_cast<float *>(d),
                     _mm_xor_ps(vs, _mm_set1_ps(-0.0f)));
        __builtin_memset(d + 16, 0, 48);
    }
}

// =========================================================================
// Decodificador especial para FMOWI
// =========================================================================

/**
 * @brief Descodifica la instruccion FMOWI (inmediato IEEE 754 de 64 bits).
 *
 * Formato (11 bytes):
 *   Byte 0: 0x00  (prefijo extendido)
 *   Byte 1: 0xFA  (opcode2)
 *   Byte 2: ctrl  (bits[7:6]=ancho, bit[5]=is_f32, bits[3:0]=zmm_idx)
 *   Bytes 3..10: imm64 (IEEE 754 double o float zero-extended)
 *
 * @param vm    Proceso virtual.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_fmowi(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 11; /* tamano fijo FIXED_11 */

    const uint64_t base = c.addr + 2; /* saltar prefijo y opcode2 */
    const uint8_t ctrl = static_cast<uint8_t>(c.read_u16(base) & 0xFF);
    const uint64_t imm = c.read_u64(base + 1);

    instr.flags_info.mode = (ctrl >> 6) & 0x3;
    instr.flags_info._signed_instruct = (ctrl >> 5) & 0x1;
    instr.data_instruction.inmmed_data.reg = ctrl & 0x0F;
    instr.data_instruction.inmmed_data.inmmed = imm;
}

// =========================================================================
// FMOV  (0x00 0xF0)
// =========================================================================

/**
 * @brief Ejecuta FMOV: copia ZMM con zeroing de bytes superiores.
 *
 * mode 0 -> write_f64  (zeros bytes 8..63)
 * mode 1 -> write_xmm  (zeros bytes 16..63)
 * mode 2 -> write_ymm  (zeros bytes 32..63)
 * mode 3 -> write_zmm  (copia completa)
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = destino, reg2 = fuente; mode = ancho.
 */
void exec_instr_fmov(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;

    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];

    /* los metodos write_* ya realizan el zeroing; __builtin_memcpy interno
     * se vectoriza con el nivel de optimizacion del compilador */
    switch (mode) {
    case 0: d.write_f64(s.read_f64()); break;
    case 1: d.write_xmm(s.raw()); break;
    case 2: d.write_ymm(s.raw()); break;
    default: d.write_zmm(s.raw()); break;
    }
}

// =========================================================================
// FADD  (0x00 0xF1)
// =========================================================================

/**
 * @brief Ejecuta FADD con despacho SIMD segun el nivel ISA detectado.
 *
 * mode==0: escalar; el compilador genera ADDSD/ADDSS.
 * mode>0:  packed; despacha a SSE2/AVX/AVX-512 segun disponibilidad.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 += reg2.
 */
void exec_instr_fadd(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];

    if (mode == 0) {
        if (is_f32)
            d.write_f32(d.read_f32() + s.read_f32());
        else
            d.write_f64(d.read_f64() + s.read_f64());
        return;
    }

    DISPATCH_BINARY_PACKED(d.raw(), s.raw(), fmode_bytes(mode), is_f32, fadd);
}

// =========================================================================
// FSUB  (0x00 0xF2)
// =========================================================================

/**
 * @brief Ejecuta FSUB con despacho SIMD.
 * @param vm    Proceso virtual.
 * @param instr reg1 -= reg2.
 */
void exec_instr_fsub(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];

    if (mode == 0) {
        if (is_f32)
            d.write_f32(d.read_f32() - s.read_f32());
        else
            d.write_f64(d.read_f64() - s.read_f64());
        return;
    }

    DISPATCH_BINARY_PACKED(d.raw(), s.raw(), fmode_bytes(mode), is_f32, fsub);
}

// =========================================================================
// FMUL  (0x00 0xF3)
// =========================================================================

/**
 * @brief Ejecuta FMUL con despacho SIMD.
 * @param vm    Proceso virtual.
 * @param instr reg1 *= reg2.
 */
void exec_instr_fmul(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];

    if (mode == 0) {
        if (is_f32)
            d.write_f32(d.read_f32() * s.read_f32());
        else
            d.write_f64(d.read_f64() * s.read_f64());
        return;
    }

    DISPATCH_BINARY_PACKED(d.raw(), s.raw(), fmode_bytes(mode), is_f32, fmul);
}

// =========================================================================
// FDIV  (0x00 0xF4)
// =========================================================================

/**
 * @brief Ejecuta FDIV con despacho SIMD.
 * @param vm    Proceso virtual.
 * @param instr reg1 /= reg2.
 */
void exec_instr_fdiv(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];

    if (mode == 0) {
        if (is_f32)
            d.write_f32(d.read_f32() / s.read_f32());
        else
            d.write_f64(d.read_f64() / s.read_f64());
        return;
    }

    DISPATCH_BINARY_PACKED(d.raw(), s.raw(), fmode_bytes(mode), is_f32, fdiv);
}

// =========================================================================
// FCMP  (0x00 0xF5)
// =========================================================================

/**
 * @brief Ejecuta FCMP: comparacion escalar flotante; actualiza flags ZF/SF/CF.
 *
 * Compara el primer escalar de reg1 con reg2:
 *   ZF = 1 si reg1 == reg2
 *   SF = 1 si reg1 <  reg2
 *   CF = 1 si alguno es NaN (condicion sin orden; equivale a carry en enteros)
 *   OF = 0 siempre
 *
 * El compilador genera UCOMISD/UCOMISS para la ruta escalar, que ya es optimo.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 cmp reg2.
 */
void exec_instr_fcmp(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r1 = instr.data_instruction.reg_data.reg1;
    const uint8_t r2 = instr.data_instruction.reg_data.reg2;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    const ZmmRegister &a = vm->registers.zmm[r1];
    const ZmmRegister &b = vm->registers.zmm[r2];

    bool zf, sf, cf;

    /* Sprint edge-bugs (2026-06-02): semantica IEEE 754 correcta para
     * unordered (NaN).  Antes el codigo emulaba x86 UCOMISD que setea
     * ZF=1 para unordered (junto con PF=1) -- pero Vesta no expone PF,
     * asi que el frontend trataba "NaN == NaN" como TRUE (ZF=1 -> je
     * salta a then).
     *
     * Fix: IEEE 754 dice TODAS las comparaciones con NaN son false
     * EXCEPT `!=` que es true.  Para que `jmp.je` no salte erroneamente
     * en NaN, ZF=0; SF=0 hace que `jl/jg` tampoco salten.  CF=1 marca
     * el estado unordered (para codigo futuro que quiera detectarlo). */
    if (is_f32) {
        const float va = a.read_f32();
        const float vb = b.read_f32();
        cf = std::isnan(va) || std::isnan(vb);
        if (cf) {
            zf = false;
            sf = false;
        } else {
            zf = (va == vb);
            sf = (va < vb);
        }
    } else {
        const double va = a.read_f64();
        const double vb = b.read_f64();
        cf = std::isnan(va) || std::isnan(vb);
        if (cf) {
            zf = false;
            sf = false;
        } else {
            zf = (va == vb);
            sf = (va < vb);
        }
    }

    vm->registers.flags.bits.ZF = zf ? 1 : 0;
    vm->registers.flags.bits.SF = sf ? 1 : 0;
    vm->registers.flags.bits.CF = cf ? 1 : 0;
    vm->registers.flags.bits.OF = 0;
}

// =========================================================================
// FSQRT  (0x00 0xF6)
// =========================================================================

/**
 * @brief Ejecuta FSQRT con despacho SIMD.
 *
 * fDst = sqrt(fSrc); dst y src pueden ser distintos o el mismo registro.
 * El compilador genera SQRTSD/SQRTSS para la ruta escalar.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = sqrt(reg2).
 */
void exec_instr_fsqrt(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];

    if (mode == 0) {
        if (is_f32)
            d.write_f32(sqrtf(s.read_f32()));
        else
            d.write_f64(std::sqrt(s.read_f64()));
        return;
    }

    const int bytes = fmode_bytes(mode);
    switch (float_isa()) {
    case FloatISA::AVX512:
        is_f32 ? fsqrt_avx512_f32(d.raw(), s.raw(), bytes)
               : fsqrt_avx512_f64(d.raw(), s.raw(), bytes);
        break;
    case FloatISA::FMA:
    case FloatISA::AVX:
        is_f32 ? fsqrt_avx_f32(d.raw(), s.raw(), bytes)
               : fsqrt_avx_f64(d.raw(), s.raw(), bytes);
        break;
    default:
        is_f32 ? fsqrt_sse2_f32(d.raw(), s.raw(), bytes)
               : fsqrt_sse2_f64(d.raw(), s.raw(), bytes);
        break;
    }
}

// =========================================================================
// FABS  (0x00 0xF7)
// =========================================================================

/**
 * @brief Ejecuta FABS con despacho SIMD.
 *
 * fDst = |fSrc|; implementado como ANDNOT(sign_mask, fSrc) sin ramas FP.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = |reg2|.
 */
void exec_instr_fabs(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];

    if (mode == 0) {
        if (is_f32)
            d.write_f32(fabsf(s.read_f32()));
        else
            d.write_f64(std::fabs(s.read_f64()));
        return;
    }

    const int bytes = fmode_bytes(mode);
    switch (float_isa()) {
    case FloatISA::AVX512:
        is_f32 ? fabs_avx512_f32(d.raw(), s.raw(), bytes)
               : fabs_avx512_f64(d.raw(), s.raw(), bytes);
        break;
    case FloatISA::FMA:
    case FloatISA::AVX:
        is_f32 ? fabs_avx_f32(d.raw(), s.raw(), bytes)
               : fabs_avx_f64(d.raw(), s.raw(), bytes);
        break;
    default:
        is_f32 ? fabs_sse2_f32(d.raw(), s.raw(), bytes)
               : fabs_sse2_f64(d.raw(), s.raw(), bytes);
        break;
    }
}

// =========================================================================
// FNEG  (0x00 0xF8)
// =========================================================================

/**
 * @brief Ejecuta FNEG con despacho SIMD.
 *
 * fDst = -fSrc; implementado como XOR(fSrc, sign_mask) sin ramas FP.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = -reg2.
 */
void exec_instr_fneg(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];

    if (mode == 0) {
        if (is_f32)
            d.write_f32(-s.read_f32());
        else
            d.write_f64(-s.read_f64());
        return;
    }

    const int bytes = fmode_bytes(mode);
    switch (float_isa()) {
    case FloatISA::AVX512:
        is_f32 ? fneg_avx512_f32(d.raw(), s.raw(), bytes)
               : fneg_avx512_f64(d.raw(), s.raw(), bytes);
        break;
    case FloatISA::FMA:
    case FloatISA::AVX:
        is_f32 ? fneg_avx_f32(d.raw(), s.raw(), bytes)
               : fneg_avx_f64(d.raw(), s.raw(), bytes);
        break;
    default:
        is_f32 ? fneg_sse2_f32(d.raw(), s.raw(), bytes)
               : fneg_sse2_f64(d.raw(), s.raw(), bytes);
        break;
    }
}

// =========================================================================
// FCVT  (0x00 0xF9)
// =========================================================================

/**
 * @brief Ejecuta FCVT: conversion escalar entre banco GP y banco ZMM.
 *
 * direction == 0 (fcvt fDst, rSrc):    GP int64 -> ZMM double/float
 *   El compilador genera VCVTSI2SD o VCVTSI2SS.
 *
 * direction == 1 (fcvt.ps rDst, fSrc): ZMM double/float -> GP int64 (truncado a
 * cero) El compilador genera VCVTTSD2SI o VCVTTSS2SI.
 *
 * @param vm    Proceso virtual.
 * @param instr zmm_reg = nibble_bajo(reg1), gp_reg = nibble_alto(reg2).
 */
void exec_instr_fcvt(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t zmm_reg = instr.data_instruction.reg_data.reg1;
    const uint8_t gp_reg = instr.data_instruction.reg_data.reg2;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);
    const bool gp_to_zmm = (instr.flags_info.direction == 0);

    if (gp_to_zmm) {
        const int64_t int_val =
            static_cast<int64_t>(vm->registers.regs[gp_reg].qword());
        if (is_f32)
            vm->registers.zmm[zmm_reg].write_f32(static_cast<float>(int_val));
        else
            vm->registers.zmm[zmm_reg].write_f64(static_cast<double>(int_val));
    } else {
        int64_t int_val;
        if (is_f32)
            int_val =
                static_cast<int64_t>(vm->registers.zmm[zmm_reg].read_f32());
        else
            int_val =
                static_cast<int64_t>(vm->registers.zmm[zmm_reg].read_f64());
        vm->registers.regs[gp_reg].qword(static_cast<uint64_t>(int_val));
    }
}

// =========================================================================
// FMOWI  (0x00 0xFA)
// =========================================================================

/**
 * @brief Ejecuta FMOWI: carga inmediato IEEE 754 en registro ZMM.
 *
 * El inmediato ya fue decodificado en inmmed_data por decode_instr_fmowi.
 *
 * @param vm    Proceso virtual.
 * @param instr inmmed_data.reg = ZMM destino; inmmed_data.inmmed = bits IEEE
 * 754.
 */
void exec_instr_fmovi(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t zmm_idx = instr.data_instruction.inmmed_data.reg;
    const uint64_t raw_imm = instr.data_instruction.inmmed_data.inmmed;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);

    if (is_f32) {
        uint32_t bits32 = static_cast<uint32_t>(raw_imm & 0xFFFFFFFF);
        float fval;
        __builtin_memcpy(&fval, &bits32, 4);
        vm->registers.zmm[zmm_idx].write_f32(fval);
    } else {
        double dval;
        __builtin_memcpy(&dval, &raw_imm, 8);
        vm->registers.zmm[zmm_idx].write_f64(dval);
    }
}

// =========================================================================
// FLOAD  (0x00 0xFB)
// =========================================================================

/**
 * @brief Ejecuta FLOAD: carga flotante desde memoria VM al registro ZMM.
 *
 * Lee (8/16/32/64) bytes desde vm_mem[gp_reg] usando read_u64 de 8 en 8
 * bytes, evitando el bucle byte a byte de la version anterior (8x menos
 * llamadas a la interfaz de memoria VM).
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = ZMM destino, reg2 = GP con la direccion VM.
 */
void exec_instr_fload(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t zmm_idx = instr.data_instruction.reg_data.reg1;
    const uint8_t gp_idx = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const uint64_t vm_addr = vm->registers.regs[gp_idx].qword();

    ZmmRegister &dst = vm->registers.zmm[zmm_idx];
    alignas(64) uint8_t buf[64] = {};

    const int bytes = fmode_bytes(mode);

    /* leer en bloques de 8 bytes (read_u64): 8x menos llamadas que read_u8 */
    for (int i = 0; i < bytes; i += 8) {
        const uint64_t qw =
            vm->vm_mem.read_u64(vm_addr + static_cast<uint64_t>(i));
        __builtin_memcpy(buf + i, &qw, 8);
    }

    switch (mode) {
    case 0: {
        double v;
        __builtin_memcpy(&v, buf, 8);
        dst.write_f64(v);
        break;
    }
    case 1: dst.write_xmm(buf); break;
    case 2: dst.write_ymm(buf); break;
    default: dst.write_zmm(buf); break;
    }
}

// =========================================================================
// FSTORE  (0x00 0xFC)
// =========================================================================

/**
 * @brief Ejecuta FSTORE: almacena registro ZMM en memoria VM.
 *
 * Escribe en bloques de 8 bytes usando write_u64, igual que FLOAD pero
 * en sentido inverso.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = ZMM fuente, reg2 = GP con la direccion VM.
 */
void exec_instr_fstore(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t zmm_idx = instr.data_instruction.reg_data.reg1;
    const uint8_t gp_idx = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const uint64_t vm_addr = vm->registers.regs[gp_idx].qword();

    const ZmmRegister &src = vm->registers.zmm[zmm_idx];
    const int bytes = fmode_bytes(mode);

    /* escribir en bloques de 8 bytes (write_u64): 8x menos llamadas que
     * write_u8 */
    for (int i = 0; i < bytes; i += 8) {
        uint64_t qw;
        __builtin_memcpy(&qw, src.raw() + i, 8);
        vm->vm_mem.write_u64(vm_addr + static_cast<uint64_t>(i), qw);
    }
}

// =========================================================================
// FEXTEND  (0x00 0x5C)
// FNARROW  (0x00 0x5D)
//
// Conversion de ancho float-a-float dentro del banco ZMM.  Necesario para
// implementar IrOp::F32TOF64 y F64TOF32 en el IR emitter sin reglas
// software complejas (la conversion del bit pattern de IEEE 754 entre f32
// y f64 requiere redo del exponente y mantissa, no es un simple shift).
//
// Encoding identico a fmov/fadd/fsub/...: ctrl byte mode(2)|isf32(1)|0...,
// regs byte (zmm_src<<4)|zmm_dst.  El emit usa emit_instr_freg.  El
// runtime ignora el bit isf32 en estos opcodes (la direccion de la
// conversion esta hardcoded en el opcode mismo).
// =========================================================================

/**
 * @brief Ejecuta FEXTEND: convierte f32 -> f64 dentro del banco ZMM.
 *
 * Lee el f32 escalar (4 bytes bajos) del registro fuente, lo extiende
 * a double y lo escribe como f64 en el destino.  write_f64 zerifica los
 * bytes altos del registro destino.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = ZMM destino, reg2 = ZMM fuente.
 */
void exec_instr_fextend(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];
    d.write_f64(static_cast<double>(s.read_f32()));
}

/**
 * @brief Ejecuta FNARROW: convierte f64 -> f32 dentro del banco ZMM.
 *
 * Lee el f64 escalar (8 bytes bajos) del registro fuente, lo trunca
 * a float y lo escribe como f32 en el destino.  write_f32 zerifica los
 * bytes altos del registro destino.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = ZMM destino, reg2 = ZMM fuente.
 */
void exec_instr_fnarrow(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];
    d.write_f32(static_cast<float>(s.read_f64()));
}

/**
 * @brief Ejecuta FMADD escalar fusionado: fd = fma(fa, fb, fd).
 *
 * Multiplica-acumula con UN SOLO redondeo (C @c std::fma / @c std::fmaf), igual
 * que la instruccion nativa VFMADD231PD que emite el JIT para la
 * auto-vectorizacion de dot-products (@c acc += a[i]*b[i]).  Asi el interprete
 * (oraculo) coincide bit-a-bit con el JIT; un mul+add separado daria DOS
 * redondeos y divergiria.  Convention B (decode_instr_raw_bytes): reg1=byte2,
 * reg2=byte3; fd=byte2&0xF, fa=(byte2>>4)&0xF, fb=(byte3>>4)&0xF,
 * isf32=byte3&1.
 */
void exec_instr_fmadd(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t b2 = instr.data_instruction.reg_data.reg1;
    const uint8_t b3 = instr.data_instruction.reg_data.reg2;
    const uint8_t fd = b2 & 0xF;
    const uint8_t fa = (b2 >> 4) & 0xF;
    const uint8_t fb = (b3 >> 4) & 0xF;
    const bool is_f32 = (b3 & 1) != 0;
    ZmmRegister &d = vm->registers.zmm[fd];
    const ZmmRegister &a = vm->registers.zmm[fa];
    const ZmmRegister &bb = vm->registers.zmm[fb];
    if (is_f32)
        d.write_f32(std::fma(a.read_f32(), bb.read_f32(), d.read_f32()));
    else
        d.write_f64(std::fma(a.read_f64(), bb.read_f64(), d.read_f64()));
}

// =========================================================================
// Sprint string-perf-5 (2026-06-02): opcodes FP nativos para fmin/fmax/
// ffloor/fceil/fround/ftrunc.  Antes el interp pagaba CALLN (~150 ns) por
// cada op via Math-IR-promote -> vmath_*.  Ahora son ~3 ns escalares.
// Solo escalar (mode=0); packed cae a path generico via std::fmin etc.
// =========================================================================

void exec_instr_fmin(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);
    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];
    if (is_f32)
        d.write_f32(std::fmin(d.read_f32(), s.read_f32()));
    else
        d.write_f64(std::fmin(d.read_f64(), s.read_f64()));
}

void exec_instr_fmax(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);
    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];
    if (is_f32)
        d.write_f32(std::fmax(d.read_f32(), s.read_f32()));
    else
        d.write_f64(std::fmax(d.read_f64(), s.read_f64()));
}

void exec_instr_ffloor(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);
    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];
    if (is_f32)
        d.write_f32(std::floor(s.read_f32()));
    else
        d.write_f64(std::floor(s.read_f64()));
}

void exec_instr_fceil(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);
    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];
    if (is_f32)
        d.write_f32(std::ceil(s.read_f32()));
    else
        d.write_f64(std::ceil(s.read_f64()));
}

void exec_instr_fround(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);
    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];
    if (is_f32)
        d.write_f32(std::round(s.read_f32()));
    else
        d.write_f64(std::round(s.read_f64()));
}

void exec_instr_ftrunc(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst = instr.data_instruction.reg_data.reg1;
    const uint8_t src = instr.data_instruction.reg_data.reg2;
    const bool is_f32 = (instr.flags_info._signed_instruct != 0);
    ZmmRegister &d = vm->registers.zmm[dst];
    const ZmmRegister &s = vm->registers.zmm[src];
    if (is_f32)
        d.write_f32(std::trunc(s.read_f32()));
    else
        d.write_f64(std::trunc(s.read_f64()));
}

// =========================================================================
// Sprint string-perf-5: bitcast GP<->ZMM directo (sin memory roundtrip).
// Reemplaza la secuencia de 5 instrucciones (subsp/mov/mov/fload/addsp)
// por 1 sola op.  Speedup ~5x en FP-heavy loops del interp.
// =========================================================================

/** @brief BITG2Z (0x86): mueve bits IEEE de GP reg a ZMM reg (sin memoria).
 * Encoding: reg1 (nibble bajo) = ZMM dst, reg2 (nibble alto) = GP src. */
void exec_instr_bitg2z(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t zmm_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t gp_src = instr.data_instruction.reg_data.reg2;
    auto &z = vm->registers.zmm[zmm_dst];
    uint64_t bits = vm->registers.regs[gp_src].qword();
    __builtin_memcpy(z.data, &bits, 8);
    __builtin_memset(z.data + 8, 0, 56);
}

/** @brief BITZ2G (0x87): mueve bits IEEE de ZMM reg a GP reg (sin memoria).
 * Encoding: reg1 (nibble bajo) = ZMM src, reg2 (nibble alto) = GP dst. */
void exec_instr_bitz2g(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t zmm_src = instr.data_instruction.reg_data.reg1;
    const uint8_t gp_dst = instr.data_instruction.reg_data.reg2;
    uint64_t bits;
    __builtin_memcpy(&bits, vm->registers.zmm[zmm_src].data, 8);
    vm->registers.regs[gp_dst].qword(bits);
}

} // namespace runtime
