/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file exec_instruction_string.cpp
 * @brief Implementacion del sistema de cadenas de texto de VestaVM.
 *
 * == Instrucciones implementadas ==
 *
 *   0x46  STRMAKE  r_dst, r_src, r_len, enc
 *         Crea un StringObject FLAT desde un buffer en memoria VM.
 *         Aplica compactacion automatica de codificacion (HotSpot-style).
 *         Interna automaticamente strings <= STR_INTERN_THRESHOLD bytes.
 *
 *   0x47  STRLEN   r_dst, r_src
 *         Devuelve el numero de code points.  Funciona para FLAT/ROPE/SLICE.
 *
 *   0x48  STRCAT   r_dst, r_a, r_b
 *         Crea un nodo ROPE (concatenacion perezosa O(1)) si ambos operandos
 *         tienen contenido; devuelve el otro si uno es vacio.
 *
 *   0x49  STRCMP   r_dst, r_a, r_b
 *         Comparacion lexicografica.  Materializa ROPE/SLICE si es necesario.
 *
 *   0x4A  STRCONV  r_dst, r_src, enc
 *         Convierte la codificacion.  Implementa UTF-8 <-> UTF-16LE completo.
 *
 *   0x4B  STRRAW   r_dst, r_src
 *         Devuelve puntero host al buffer.  Materializa ROPE/SLICE primero.
 *
 *   0x4C  STRSLICE r_dst, r_src, r_start, r_len
 *         Crea un nodo SLICE (vista sin copia O(1)).  Materializa si el padre
 *         es ROPE.  r_start y r_len son en code points.
 *
 *   0x4D  STRFLAT  r_dst, r_src
 *         Materializa cualquier ROPE o SLICE a FLAT.  Operacion identidad
 *         si el origen ya es FLAT.  Internado automatico tras materializacion.
 *
 *   0x4E  STRHASH  r_dst, r_src
 *         Devuelve el hash FNV-1a (calcula y cachea si es necesario).
 *         Materializa ROPE/SLICE antes de calcular.
 *
 *   0x4F  STRINTERN r_dst, r_src
 *         Interna el string en el pool del proceso.  Devuelve el GcHandle
 *         canonico (puede ser distinto de r_src si ya habia un identico).
 *
 *   0x50  STRGETENC  r_dst, r_src   -> encoding byte (0-4)
 *   0x51  STRGETBYTES r_dst, r_src  -> byte_len
 *   0x52  STRGETKIND  r_dst, r_src  -> kind (0=FLAT 1=ROPE 2=SLICE)
 *   0x53  STRRESERVE  r_dst, r_cap  -> GcHandle de FLAT con capacidad reservada
 *         Crea un FLAT vacio con byte_len=0 pero capacidad interna = r_cap
 * bytes. El programa escribe en el buffer via STRRAW + instrucciones nativas.
 *         Tras escribir, usa STRFINALIZE para establecer la longitud final.
 *   0x54  STRFINALIZE r_dst, r_newlen -> actualiza byte_len+length+hash de un
 * FLAT mutable
 */

#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "runtime/runtime.h" // para acceder a vm->scheduler.vm_reference.script_args
#include "runtime/scheduler.h"
#include "runtime/string_intern.h"
#include "runtime/string_runtime.h" //  MC.13: API publica make_string_flat
#include "gc/gc_heap.h"
#include "loader/oop_types.h"
#include "loader/string_object.h"

#include <cstring> // memcpy, memcmp
#include <vector>
#include <string>
#include <algorithm> // std::min

namespace runtime {

// =========================================================================
// Forward declarations internas
// =========================================================================

static gc::GcHandle flatten_string(ProcessVM *vm, gc::GcHandle h);
static gc::GcHandle auto_intern(ProcessVM *vm, gc::GcHandle h,
                                const uint8_t *data, uint32_t byte_len,
                                loader::StringEncoding enc);

// =========================================================================
// Helper: obtener o crear el pool de interning del proceso
// =========================================================================

/**
 * @brief Devuelve el pool de interning del proceso, creandolo si no existe.
 *
 * El pool se crea de forma lazy la primera vez que se necesita.
 *
 * @param vm  Proceso virtual propietario del pool.
 * @return    Referencia al StringInternPool del proceso.
 */
static StringInternPool &get_intern_pool(ProcessVM *vm) {
    if (!vm->str_intern_pool)
        vm->str_intern_pool = new StringInternPool(); // creacion lazy del pool
    return *vm->str_intern_pool;
}

// =========================================================================
// Helper: construir clave de interning
// =========================================================================

/**
 * @brief Construye la clave de busqueda del pool a partir de bytes + encoding.
 *
 * @param data      Buffer de bytes del string.
 * @param byte_len  Numero de bytes.
 * @param enc       Codificacion del string.
 * @return          Clave std::string (bytes del string + byte de encoding).
 */
static std::string make_intern_key(const uint8_t *data, uint32_t byte_len,
                                   loader::StringEncoding enc) {
    std::string key(reinterpret_cast<const char *>(data),
                    byte_len); // raw bytes
    key += static_cast<char>(
        static_cast<uint8_t>(enc)); // byte de codificacion al final
    return key;
}

// =========================================================================
// Helper: alocar y construir un StringObject FLAT en el GcHeap
// =========================================================================

/**
 * @brief Aloca un StringObject FLAT en el GcHeap con los bytes dados.
 *
 * Asigna sizeof(StringObject) + byte_len + 1 bytes.
 * El byte extra al final garantiza la terminacion nula para Win32 FFI.
 *
 * @param vm        Proceso virtual propietario del heap.
 * @param src_data  Buffer de entrada (puede ser nullptr para string vacio).
 * @param byte_len  Numero de bytes del contenido (sin el nulo extra).
 * @param length    Numero de code points.
 * @param enc       Codificacion del string.
 * @param capacity  Si > byte_len, reserva espacio adicional (para STRRESERVE).
 * @return          GcHandle del nuevo StringObject o GC_NULL_HANDLE.
 */
/**
 * @brief Sprint string-perf-2 (2026-06-02): @c alloc_flat extendido con
 * hash precomputado opcional.
 *
 * Si @p precomputed_hash != 0, el caller ya lo calculo (single-pass en
 * STRMAKE/STRCAT), evitamos una segunda pasada sobre los bytes.  El hash
 * se almacena en @c s->str_hash (32-bit truncado del FNV-1a 64-bit).
 *
 * Si @p precomputed_hash == 0, computamos el hash via @c str_hash_compute
 * para TODOS los strings (no solo cortos como antes).  Coste pequeno
 * vs ahorro grande en STRCMP fast-reject.
 */
static gc::GcHandle alloc_flat(ProcessVM *vm, const uint8_t *src_data,
                               uint32_t byte_len, uint32_t length,
                               loader::StringEncoding enc,
                               uint32_t capacity = 0,
                               uint64_t precomputed_hash = 0) {
    uint32_t buf_size =
        (capacity > byte_len) ? capacity : byte_len; // usar el mayor
    size_t total =
        sizeof(loader::StringObject) + buf_size + 1; // +1 para nulo Win32

    // alloc_pinned: aloca directo en OldGen (non-moving).  Necesario porque
    // STRRAW exporta el host_ptr al buffer y este se preserva via push/pop a
    // traves de calls que pueden disparar GC.  Si el StringObject estuviera
    // en young y se evacuara, el host_ptr quedaria dangling.
    gc::GcHandle h = vm->gc_heap.alloc_pinned(total);
    if (__builtin_expect(h == gc::GC_NULL_HANDLE, 0)) return gc::GC_NULL_HANDLE;

    uint8_t *payload = vm->gc_heap.deref(h);
    if (__builtin_expect(!payload, 0)) return gc::GC_NULL_HANDLE;

    auto *s = reinterpret_cast<loader::StringObject *>(payload);

    // inicializar cabecera ObjectHeader (todos los campos en una pasada)
    s->header.class_ptr = nullptr;
    s->header.flags = loader::OBJ_FLAG_GC_OWNED;
    s->header.hash_code = static_cast<uint32_t>(h);
    s->header.monitor_word.store(0, std::memory_order_relaxed);

    s->encoding = static_cast<uint8_t>(enc);
    s->kind = static_cast<uint8_t>(loader::StringKind::FLAT);
    s->_pad[0] = s->_pad[1] = 0;
    s->length = length;
    s->byte_len = byte_len;
    // Sprint string-perf-3 fix: precomputed_hash YA es FNV-1a 32-bit
    // puro (mismo algoritmo que str_hash_compute fallback).  Solo
    // truncar y proteger contra 0 sentinel.  Garantiza que dos strings
    // con mismos bytes tienen el MISMO str_hash sin importar el path
    // (fast STRMAKE vs slow STRMAKE vs STRCAT FLAT-FLAT).
    if (precomputed_hash != 0) {
        s->str_hash = static_cast<uint32_t>(precomputed_hash & 0xFFFFFFFFu);
        if (s->str_hash == 0) s->str_hash = 1;
    } else {
        s->str_hash = 0;
    }

    uint8_t *dst = loader::str_data(s);
    if (src_data && byte_len > 0) std::memcpy(dst, src_data, byte_len);
    dst[byte_len] = 0; // terminador nulo siempre presente

    // Sprint string-perf-2: precomputar hash para TODOS los strings
    // (antes solo <= INTERN_THRESHOLD).  Coste lineal en byte_len (~1ns/byte)
    // pero permite STRCMP fast-reject sin recomputar.  Para strings de
    // 64 bytes son ~64 ns adicionales en alloc -- ampliamente amortizados
    // si hay >=1 STRCMP posterior (que skipea memcmp completo via hash).
    if (s->str_hash == 0 && byte_len > 0) {
        loader::str_hash_compute(s);
    }

    return h;
}

/**
 * @brief Aloca un nodo ROPE en el GcHeap.
 *
 * El rope no tiene buffer de datos; almacena RopeData (left/right handles).
 * La concatenacion es perezosa: no se copia ningun byte.
 *
 * @param vm     Proceso virtual.
 * @param left   GcHandle del string izquierdo.
 * @param right  GcHandle del string derecho.
 * @param enc    Codificacion del rope (hereda del hijo izquierdo).
 * @return       GcHandle del nuevo nodo ROPE.
 */
static gc::GcHandle alloc_rope(ProcessVM *vm, gc::GcHandle left,
                               gc::GcHandle right, uint32_t total_length,
                               uint32_t total_byte_len,
                               loader::StringEncoding enc, uint32_t depth) {
    size_t total = sizeof(loader::StringObject) + sizeof(loader::RopeData);
    // Vease nota en alloc_flat: alloc_pinned -> OldGen non-moving para que el
    // host_ptr exportado via STRRAW no quede dangling tras un GC menor.
    gc::GcHandle h = vm->gc_heap.alloc_pinned(total);
    if (h == gc::GC_NULL_HANDLE) return gc::GC_NULL_HANDLE;

    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) return gc::GC_NULL_HANDLE;

    auto *s = reinterpret_cast<loader::StringObject *>(payload);

    s->header.class_ptr = nullptr;
    s->header.flags = loader::OBJ_FLAG_GC_OWNED;
    s->header.hash_code = static_cast<uint32_t>(h);
    // monitor_word empaqueta owner + lock_depth; cero = unlocked.
    s->header.monitor_word.store(0, std::memory_order_relaxed);

    s->encoding = static_cast<uint8_t>(enc);
    s->kind = static_cast<uint8_t>(loader::StringKind::ROPE);
    s->_pad[0] = s->_pad[1] = 0;
    s->length = total_length;
    s->byte_len = total_byte_len;
    s->str_hash = 0;

    auto *rd = loader::str_rope(s);
    rd->left_handle = left;
    rd->right_handle = right;
    rd->depth = depth;
    rd->_pad = 0;

    return h;
}

/**
 * @brief Aloca un nodo SLICE en el GcHeap.
 *
 * El slice es una vista zero-copy sobre un segmento de un StringObject FLAT.
 *
 * @param vm          Proceso virtual.
 * @param parent      GcHandle del StringObject FLAT padre.
 * @param byte_offset Offset en bytes dentro del buffer del padre.
 * @param byte_len    Numero de bytes del slice.
 * @param length      Numero de code points del slice.
 * @param enc         Codificacion (heredada del padre).
 * @return            GcHandle del nuevo nodo SLICE.
 */
static gc::GcHandle alloc_slice(ProcessVM *vm, gc::GcHandle parent,
                                uint32_t byte_offset, uint32_t byte_len,
                                uint32_t length, loader::StringEncoding enc) {
    size_t total = sizeof(loader::StringObject) + sizeof(loader::SliceData);
    // Vease nota en alloc_flat: alloc_pinned -> OldGen non-moving.
    gc::GcHandle h = vm->gc_heap.alloc_pinned(total);
    if (h == gc::GC_NULL_HANDLE) return gc::GC_NULL_HANDLE;

    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) return gc::GC_NULL_HANDLE;

    auto *s = reinterpret_cast<loader::StringObject *>(payload);

    s->header.class_ptr = nullptr;
    s->header.flags = loader::OBJ_FLAG_GC_OWNED;
    s->header.hash_code = static_cast<uint32_t>(h);
    // monitor_word empaqueta owner + lock_depth; cero = unlocked.
    s->header.monitor_word.store(0, std::memory_order_relaxed);

    s->encoding = static_cast<uint8_t>(enc);
    s->kind = static_cast<uint8_t>(loader::StringKind::SLICE);
    s->_pad[0] = s->_pad[1] = 0;
    s->length = length;
    s->byte_len = byte_len;
    s->str_hash = 0;

    auto *sd = loader::str_slice(s);
    sd->parent_handle = parent;
    sd->byte_offset = byte_offset;

    return h;
}

// =========================================================================
// Helper: interning automatico post-alocation
// =========================================================================

/**
 * @brief Intenta internar un string recien creado si es elegible.
 *
 * Solo se internan strings FLAT con byte_len <= STR_INTERN_THRESHOLD.
 * Si ya existe un identico, devuelve el GcHandle canonico del pool.
 *
 * @param vm       Proceso virtual.
 * @param h        GcHandle del string recien creado.
 * @param data     Puntero a los bytes del string.
 * @param byte_len Numero de bytes.
 * @param enc      Codificacion.
 * @return         GcHandle canonico (puede ser h u otro preexistente).
 */
static gc::GcHandle auto_intern(ProcessVM *vm, gc::GcHandle h,
                                const uint8_t *data, uint32_t byte_len,
                                loader::StringEncoding enc) {
    if (byte_len > loader::STR_INTERN_THRESHOLD)
        return h; // demasiado largo para internar

    StringInternPool &pool = get_intern_pool(vm);
    std::string key = make_intern_key(data, byte_len, enc);

    gc::GcHandle canonical = pool.intern(key, h); // buscar o insertar

    if (canonical == h) {
        // recien insertado: marcar el objeto como internado
        uint8_t *payload = vm->gc_heap.deref(h);
        if (payload) {
            auto *s = reinterpret_cast<loader::StringObject *>(payload);
            s->kind |= loader::STR_INTERNED_FLAG; // activar flag de interning
        }
    }
    // si canonical != h, el objeto h es redundante pero el GC lo recolectara

    return canonical;
}

// =========================================================================
// Helper: materializar ROPE/SLICE a FLAT (flatten recursivo)
// =========================================================================

/**
 * @brief Acumula los bytes de un string (recursivo para ROPE) en un vector.
 *
 * @param vm    Proceso virtual.
 * @param h     GcHandle del string a recolectar.
 * @param out   Vector de salida donde se acumulan los bytes.
 * @return      true si la recoleccion tuvo exito.
 */
static bool collect_bytes(ProcessVM *vm, gc::GcHandle h,
                          std::vector<uint8_t> &out) {
    if (h == gc::GC_NULL_HANDLE) return false;

    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) return false;

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    using loader::StringKind;

    switch (loader::str_kind(s)) {
    case StringKind::FLAT: {
        const uint8_t *d = loader::str_data(s);
        out.insert(out.end(), d, d + s->byte_len); // copiar bytes del flat
        return true;
    }
    case StringKind::ROPE: {
        auto *rd = loader::str_rope(s);
        if (!collect_bytes(vm, rd->left_handle, out))
            return false; // hijo izquierdo
        if (!collect_bytes(vm, rd->right_handle, out))
            return false; // hijo derecho
        return true;
    }
    case StringKind::SLICE: {
        // re-deref necesario porque collect_bytes puede haber hecho allocs
        // internos
        payload = vm->gc_heap.deref(h);
        if (!payload) return false;
        s = reinterpret_cast<loader::StringObject *>(payload);
        auto *sd = loader::str_slice(s);

        uint8_t *pp = vm->gc_heap.deref(sd->parent_handle);
        if (!pp) return false;
        auto *parent = reinterpret_cast<loader::StringObject *>(pp);

        const uint8_t *d = loader::str_data(parent) + sd->byte_offset;
        out.insert(out.end(), d, d + s->byte_len); // copiar segmento del padre
        return true;
    }
    }
    return false;
}

/**
 * @brief Materializa cualquier string a FLAT, con interning automatico.
 *
 * - FLAT: devuelve el mismo handle (sin copia si ya esta bien).
 * - ROPE: recolecta todos los bytes recursivamente y crea un FLAT nuevo.
 * - SLICE: copia el segmento a un FLAT nuevo.
 *
 * Tras materializacion, el nuevo FLAT es internado si es elegible.
 *
 * @param vm  Proceso virtual.
 * @param h   GcHandle del string a materializar.
 * @return    GcHandle del FLAT resultante, o GC_NULL_HANDLE en fallo.
 */
static gc::GcHandle flatten_string(ProcessVM *vm, gc::GcHandle h) {
    if (h == gc::GC_NULL_HANDLE) return h;

    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) return gc::GC_NULL_HANDLE;

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    if (loader::str_kind(s) == loader::StringKind::FLAT)
        return h; // ya es plano

    // recolectar todos los bytes en un vector
    std::vector<uint8_t> buf;
    buf.reserve(s->byte_len);
    if (!collect_bytes(vm, h, buf)) return gc::GC_NULL_HANDLE;

    auto enc = loader::str_encoding(s);
    uint32_t length = s->length; // preservar el numero de code points

    // crear el nuevo FLAT
    gc::GcHandle flat = alloc_flat(
        vm, buf.data(), static_cast<uint32_t>(buf.size()), length, enc);
    if (flat == gc::GC_NULL_HANDLE) return flat;

    // internado automatico del nuevo flat
    flat = auto_intern(vm, flat, buf.data(), static_cast<uint32_t>(buf.size()),
                       enc);

    return flat;
}

// =========================================================================
// Helper: compactacion de codificacion (Compact Strings estilo HotSpot)
// =========================================================================

/**
 * @brief Detecta si un buffer puede representarse en una codificacion mas
 * compacta.
 *
 * Reglas:
 *   - UTF-8  con todos los bytes <= 0x7F -> ASCII (ahorra mem, mismo puntero
 * Win32)
 *   - UTF-16 con todos los code units <= 0x7F -> ASCII
 *   - UTF-16 con todos los code units <= 0xFF -> ANSI
 *
 * @param data      Buffer de entrada.
 * @param byte_len  Longitud en bytes.
 * @param enc       Codificacion de entrada.
 * @param[out] new_enc  Codificacion mas compacta posible.
 * @param[out] new_data Buffer recodificado (solo rellenado si cambia
 * codificacion).
 * @param[out] new_len  Longitud del buffer recodificado.
 * @return  true si se puede compactar.
 */
static bool try_compact(const uint8_t *data, uint32_t byte_len,
                        loader::StringEncoding enc,
                        loader::StringEncoding &new_enc,
                        std::vector<uint8_t> &new_data, uint32_t &new_len) {
    if (enc == loader::StringEncoding::UTF8) {
        bool all_ascii = true;
        for (uint32_t i = 0; i < byte_len; ++i)
            if (data[i] > 0x7F) {
                all_ascii = false;
                break;
            }
        if (all_ascii) {
            new_enc = loader::StringEncoding::ASCII; // compactar UTF-8 a ASCII
            new_data = std::vector<uint8_t>(data, data + byte_len);
            new_len = byte_len;
            return true;
        }
    } else if (enc == loader::StringEncoding::UTF16) {
        if (byte_len % 2 != 0) return false; // longitud invalida para UTF-16
        bool all_ansi = true;
        bool all_ascii = true;
        const uint16_t *u = reinterpret_cast<const uint16_t *>(data);
        uint32_t count = byte_len / 2;
        for (uint32_t i = 0; i < count; ++i) {
            if (u[i] > 0xFF) {
                all_ansi = false;
                break;
            }
            if (u[i] > 0x7F) all_ascii = false;
        }
        if (all_ansi) {
            new_enc = all_ascii ? loader::StringEncoding::ASCII
                                : loader::StringEncoding::ANSI;
            new_data.resize(count);
            for (uint32_t i = 0; i < count; ++i)
                new_data[i] =
                    static_cast<uint8_t>(u[i] & 0xFF); // extraer byte bajo
            new_len = count;
            return true;
        }
    }
    return false;
}

// =========================================================================
// Helper: calculo de code points para una codificacion y buffer
// =========================================================================

/**
 * @brief Cuenta los code points en un buffer segun la codificacion.
 *
 * @param data      Buffer de bytes.
 * @param byte_len  Longitud en bytes.
 * @param enc       Codificacion.
 * @return          Numero de code points.
 */
static uint32_t count_codepoints(const uint8_t *data, uint32_t byte_len,
                                 loader::StringEncoding enc) {
    switch (enc) {
    case loader::StringEncoding::ASCII:
    case loader::StringEncoding::ANSI: return byte_len; // 1 byte por caracter
    case loader::StringEncoding::UTF8: {
        uint32_t count = 0;
        for (uint32_t i = 0; i < byte_len;) {
            uint8_t b = data[i];
            if ((b & 0x80) == 0) {
                ++count;
                i += 1;
            } else if ((b & 0xE0) == 0xC0) {
                ++count;
                i += 2;
            } else if ((b & 0xF0) == 0xE0) {
                ++count;
                i += 3;
            } else {
                ++count;
                i += 4;
            }
        }
        return count;
    }
    case loader::StringEncoding::UTF16:
        return byte_len / 2; // aproximado (ignora surrogates)
    case loader::StringEncoding::UTF32: return byte_len / 4;
    }
    return byte_len;
}

// =========================================================================
// 0x46  STRMAKE r_dst, r_src, r_len, enc
// Encoding FIXED_4: [0x00][0x46][ctrl][byte3]
//   ctrl  = (r_dst<<4) | r_src    r_src = direccion VM del buffer
//   byte3 = (encoding<<4) | r_len  r_len = longitud en bytes
// =========================================================================

/**
 * @brief Helper compartido: STRMAKE desde memoria VM.  Usado por
 * @c exec_instr_strmake (interp) y @c vrt_str_make (JIT).  Fast path con
 * stack buf + FNV-1a 64-bit + intern lookup-first.
 */
gc::GcHandle make_string_from_vm_mem(ProcessVM *vm, uint64_t vm_addr,
                                     uint32_t byte_len) noexcept {
    constexpr uint32_t SMALL_LIMIT = 256;
    if (byte_len <= SMALL_LIMIT) {
        uint8_t stack_buf[SMALL_LIMIT];
        if (byte_len > 0) {
            vm->vm_mem.read_bytes(vm_addr, stack_buf, byte_len);
        }
        // Single-pass FNV-1a 64-bit (mismo algoritmo que str_hash_compute).
        // En x86-64 multiplica con un solo IMUL (~3 ciclos).
        bool all_ascii = true;
        uint32_t cp_count = 0;
        uint64_t fnv64 = util::kFnvOffset;
        for (uint32_t i = 0; i < byte_len;) {
            uint8_t b = stack_buf[i];
            fnv64 ^= b;
            fnv64 *= util::kFnvPrime;
            if ((b & 0x80) == 0) {
                ++cp_count;
                i += 1;
            } else {
                all_ascii = false;
                if ((b & 0xE0) == 0xC0) {
                    ++cp_count;
                    i += 2;
                } else if ((b & 0xF0) == 0xE0) {
                    ++cp_count;
                    i += 3;
                } else {
                    ++cp_count;
                    i += 4;
                }
            }
        }
        const auto final_enc = all_ascii ? loader::StringEncoding::ASCII
                                         : loader::StringEncoding::UTF8;
        // str_hash := low 32 bits of fnv64 (paridad con str_hash_compute).
        // cache key := fnv64 con encoding mixed (distinto enc no colisiona).
        const uint32_t str_hash32 = static_cast<uint32_t>(fnv64 & 0xFFFFFFFFu);
        uint64_t fnv = fnv64;
        fnv ^= static_cast<uint8_t>(final_enc);
        fnv *= util::kFnvPrime;

        // Sprint string-perf: intern lookup ANTES de alloc.  Si hit y
        // bytes matchean, evitamos TODO el alloc + memset + intern map
        // insert.  Para strings literales en hot paths este es el caso
        // mas comun (95%+ de STRMAKEs).
        if (byte_len > 0 && byte_len <= loader::STR_INTERN_THRESHOLD) {
            StringInternPool &pool = get_intern_pool(vm);
            gc::GcHandle cached = pool.lookup_by_hash(fnv);
            if (cached != gc::GC_NULL_HANDLE) {
                uint8_t *cp = vm->gc_heap.deref(cached);
                if (cp) {
                    auto *cs = reinterpret_cast<loader::StringObject *>(cp);
                    if (cs->byte_len == byte_len &&
                        cs->encoding == static_cast<uint8_t>(final_enc) &&
                        std::memcmp(loader::str_data(cs), stack_buf,
                                    byte_len) == 0) {
                        // Cache hit + bytes match: cero alloc, retorno directo.
                        return cached;
                    }
                }
            }
        }

        gc::GcHandle h = alloc_flat(
            vm, stack_buf, byte_len, cp_count, final_enc, /*capacity=*/0,
            /*precomputed_hash=*/static_cast<uint64_t>(str_hash32));
        if (__builtin_expect(h == gc::GC_NULL_HANDLE, 0)) {
            return gc::GC_NULL_HANDLE;
        }
        if (byte_len > 0 && byte_len <= loader::STR_INTERN_THRESHOLD) {
            // Sprint string-perf-3 bug fix (2026-06-02): pinear el handle
            // como root externo del GC.  Sin esto, el intern hash cache
            // retiene un GcHandle al StringObject pero el GC no sabe que
            // hay una referencia activa.  Tras un major_gc, el handle
            // puede ser liberado/reusado y la proxima lookup_by_hash
            // devuelve un handle stale -> bytes equivocados -> JIT
            // diverge en bench string_workout a partir de ~110K iter.
            // gc_addref es O(1); incrementa external_refs_ que el GC
            // marca como root durante el mark phase.
            get_intern_pool(vm).insert_by_hash(fnv, h);
            vm->gc_heap.gc_addref(h);
        }
        h = auto_intern(vm, h, stack_buf, byte_len, final_enc);
        return h;
    }

    // Slow path: strings grandes (> 256 B) usan heap buf + path generico.
    auto enc = loader::StringEncoding::UTF8;
    std::vector<uint8_t> buf(byte_len);
    vm->vm_mem.read_bytes(vm_addr, buf.data(), byte_len);

    loader::StringEncoding final_enc = enc;
    std::vector<uint8_t> compact_buf;
    uint32_t compact_len = byte_len;
    bool compacted = try_compact(buf.data(), byte_len, enc, final_enc,
                                 compact_buf, compact_len);
    const uint8_t *final_data = compacted ? compact_buf.data() : buf.data();
    uint32_t final_byte_len = compacted ? compact_len : byte_len;

    uint32_t length = count_codepoints(final_data, final_byte_len, final_enc);

    gc::GcHandle h =
        alloc_flat(vm, final_data, final_byte_len, length, final_enc);
    if (h == gc::GC_NULL_HANDLE) {
        return gc::GC_NULL_HANDLE;
    }

    h = auto_intern(vm, h, final_data, final_byte_len, final_enc);
    return h;
}

/**
 * @brief Ejecuta STRMAKE: crea un StringObject FLAT desde un buffer de VM.
 *
 * Aplica compactacion de codificacion automatica (HotSpot Compact Strings).
 * Interna el string automaticamente si byte_len <= STR_INTERN_THRESHOLD.
 */
void exec_instr_strmake(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;
    const uint8_t r_len = (instr.data_instruction.reg_data.reg2 >> 4) & 0xF;

    uint64_t vm_addr = vm->registers.regs[r_src].qword();
    uint32_t byte_len =
        static_cast<uint32_t>(vm->registers.regs[r_len].qword());

    gc::GcHandle h = make_string_from_vm_mem(vm, vm_addr, byte_len);
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(h));
}

// =========================================================================
// 0x55  STRMAKE_H r_dst, r_src, r_len
// Encoding FIXED_4: ctrl=(r_dst<<4)|r_src, byte3=(enc<<4)|r_len
// =========================================================================

/**
 * @brief Helper compartido: crea un StringObject FLAT desde un buffer HOST.
 *
 * Lee directamente desde la memoria del proceso host (puntero crudo, no
 * direccion VM).  Util cuando el buffer fuente proviene de @c malloc,
 * @c gcallocp, @c str_cstr, o de un ALLOCA promovido a heap host que fluye
 * a un CALLN de stringify (interpolacion `${expr}` en contexto string).
 * Consumido por @c exec_instr_strmake_h (interp) y por @c vrt_str_make_h
 * (JIT).  Aplica las mismas reglas que STRMAKE: FNV-1a, internado
 * automatico, encoding ASCII/UTF-8 auto-detectado.
 */
gc::GcHandle make_string_from_host_mem(ProcessVM *vm, uint64_t host_addr,
                                       uint32_t byte_len) noexcept {
    const uint8_t *src = reinterpret_cast<const uint8_t *>(host_addr);

    // Sprint string-perf-3: FNV-1a 64-bit consistente con todos los paths.
    bool all_ascii = true;
    uint32_t cp_count = 0;
    uint64_t fnv64 = util::kFnvOffset;
    for (uint32_t i = 0; i < byte_len;) {
        uint8_t b = src[i];
        fnv64 ^= b;
        fnv64 *= util::kFnvPrime;
        if ((b & 0x80) == 0) {
            ++cp_count;
            i += 1;
        } else {
            all_ascii = false;
            if ((b & 0xE0) == 0xC0) {
                ++cp_count;
                i += 2;
            } else if ((b & 0xF0) == 0xE0) {
                ++cp_count;
                i += 3;
            } else {
                ++cp_count;
                i += 4;
            }
        }
    }
    const auto final_enc = all_ascii ? loader::StringEncoding::ASCII
                                     : loader::StringEncoding::UTF8;
    const uint32_t str_hash32 = static_cast<uint32_t>(fnv64 & 0xFFFFFFFFu);
    uint64_t fnv = fnv64;
    fnv ^= static_cast<uint8_t>(final_enc);
    fnv *= util::kFnvPrime;

    // Intern lookup-first (idem STRMAKE).
    if (byte_len > 0 && byte_len <= loader::STR_INTERN_THRESHOLD) {
        StringInternPool &pool = get_intern_pool(vm);
        gc::GcHandle cached = pool.lookup_by_hash(fnv);
        if (cached != gc::GC_NULL_HANDLE) {
            uint8_t *cp = vm->gc_heap.deref(cached);
            if (cp) {
                auto *cs = reinterpret_cast<loader::StringObject *>(cp);
                if (cs->byte_len == byte_len &&
                    cs->encoding == static_cast<uint8_t>(final_enc) &&
                    std::memcmp(loader::str_data(cs), src, byte_len) == 0) {
                    return cached;
                }
            }
        }
    }

    gc::GcHandle h =
        alloc_flat(vm, src, byte_len, cp_count, final_enc,
                   /*capacity=*/0,
                   /*precomputed_hash=*/static_cast<uint64_t>(str_hash32));
    if (__builtin_expect(h == gc::GC_NULL_HANDLE, 0)) {
        return gc::GC_NULL_HANDLE;
    }
    if (byte_len > 0 && byte_len <= loader::STR_INTERN_THRESHOLD) {
        get_intern_pool(vm).insert_by_hash(fnv, h);
        vm->gc_heap.gc_addref(h); // pin como GC root (idem fix STRMAKE)
    }
    h = auto_intern(vm, h, src, byte_len, final_enc);
    return h;
}

/**
 * @brief Ejecuta STRMAKE_H: crea un StringObject FLAT desde un buffer HOST.
 *
 * Variante de STRMAKE (0x46) que lee directamente desde la memoria del
 * proceso host (puntero crudo, no direccion VM).  Delega en el helper
 * compartido @c make_string_from_host_mem (mismo path que @c vrt_str_make_h
 * del JIT).
 */
void exec_instr_strmake_h(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;
    const uint8_t r_len = (instr.data_instruction.reg_data.reg2 >> 4) & 0xF;

    uint64_t host_addr = vm->registers.regs[r_src].qword();
    uint32_t byte_len =
        static_cast<uint32_t>(vm->registers.regs[r_len].qword());

    gc::GcHandle h = make_string_from_host_mem(vm, host_addr, byte_len);
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(h));
}

// =========================================================================
// 0x47  STRLEN r_dst, r_src
// =========================================================================

/** @brief Ejecuta STRLEN: devuelve el numero de code points del string. */
void exec_instr_strlen(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword());
    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    vm->registers.regs[r_dst].qword(
        static_cast<uint64_t>(s->length)); // valido para FLAT/ROPE/SLICE
}

// =========================================================================
// 0x48  STRCAT r_dst, r_a, r_b
// Encoding FIXED_4: ctrl=(r_dst<<4)|r_a, byte3=r_b
// =========================================================================

/**
 * @brief Ejecuta STRCAT: crea un nodo ROPE (concatenacion perezosa O(1)).
 *
 * Si uno de los operandos es un string vacio, devuelve el otro directamente
 * sin crear un nodo rope (optimizacion de identidad).
 * Si la concatenacion resultaria en un rope de profundidad >
 * STR_ROPE_MAX_DEPTH, materializa inmediatamente a FLAT para evitar degradacion
 * de rendimiento.
 */
void exec_instr_strcat(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_a = instr.data_instruction.reg_data.reg1 & 0xF;
    const uint8_t r_b = (instr.data_instruction.reg_data.reg2 >> 4) &
                        0xF; // nibble alto (emit_instr_three_reg)

    gc::GcHandle ha =
        static_cast<gc::GcHandle>(vm->registers.regs[r_a].qword());
    gc::GcHandle hb =
        static_cast<gc::GcHandle>(vm->registers.regs[r_b].qword());

    uint8_t *pa = vm->gc_heap.deref(ha);
    uint8_t *pb = vm->gc_heap.deref(hb);

    if (!pa || !pb) {
        vm->registers.regs[r_dst].qword(
            static_cast<uint64_t>(gc::GC_NULL_HANDLE));
        return;
    }

    auto *sa = reinterpret_cast<loader::StringObject *>(pa);
    auto *sb = reinterpret_cast<loader::StringObject *>(pb);

    // optimizacion de identidad: concatenar con string vacio devuelve el otro
    if (sa->byte_len == 0) {
        vm->registers.regs[r_dst].qword(hb);
        return;
    }
    if (sb->byte_len == 0) {
        vm->registers.regs[r_dst].qword(ha);
        return;
    }

    // calcular profundidad del nuevo rope
    uint32_t depth_a = 0, depth_b = 0;
    if (loader::str_kind(sa) == loader::StringKind::ROPE)
        depth_a = loader::str_rope(sa)->depth;
    if (loader::str_kind(sb) == loader::StringKind::ROPE)
        depth_b = loader::str_rope(sb)->depth;
    uint32_t new_depth = std::max(depth_a, depth_b) + 1;

    uint32_t total_len = sa->length + sb->length;
    uint32_t total_byte_len = sa->byte_len + sb->byte_len;
    auto enc = loader::str_encoding(sa); // hereda encoding del hijo izquierdo

    gc::GcHandle result;

    // Sprint string-perf (2026-06-02): fast path FLAT-FLAT pequeno.
    // Si ambos operandos son FLAT, encoding compatible, y el resultado
    // total cabe en stack buffer (<= 256 B), materializar directamente
    // a FLAT en lugar de crear un nodo ROPE.  Beneficios:
    //   - 1 sola alloc (vs 1 ROPE + posterior flatten en STRLEN/STRCMP).
    //   - El subsiguiente STRCMP/STRLEN no necesita flatten_string.
    //   - Hash precomputable en alloc_flat para strings cortos.
    // Para strings grandes o ROPE recursivos, mantener el ROPE perezoso.
    constexpr uint32_t SMALL_CONCAT_LIMIT = 256;
    if (loader::str_kind(sa) == loader::StringKind::FLAT &&
        loader::str_kind(sb) == loader::StringKind::FLAT &&
        loader::str_encoding(sa) == loader::str_encoding(sb) &&
        total_byte_len <= SMALL_CONCAT_LIMIT) {
        uint8_t stack_buf[SMALL_CONCAT_LIMIT];
        std::memcpy(stack_buf, loader::str_data(sa), sa->byte_len);
        std::memcpy(stack_buf + sa->byte_len, loader::str_data(sb),
                    sb->byte_len);

        // Sprint string-perf-3: FNV-1a 64-bit identico a str_hash_compute
        // y a STRMAKE.  str_hash = low 32 bits; cache key = full 64 + enc mix.
        uint64_t fnv64 = util::kFnvOffset;
        for (uint32_t i = 0; i < total_byte_len; ++i) {
            fnv64 ^= stack_buf[i];
            fnv64 *= util::kFnvPrime;
        }
        const uint32_t str_hash32 = static_cast<uint32_t>(fnv64 & 0xFFFFFFFFu);
        uint64_t fnv = fnv64;
        fnv ^= static_cast<uint8_t>(enc);
        fnv *= util::kFnvPrime;

        if (total_byte_len <= loader::STR_INTERN_THRESHOLD) {
            StringInternPool &pool = get_intern_pool(vm);
            gc::GcHandle cached = pool.lookup_by_hash(fnv);
            if (cached != gc::GC_NULL_HANDLE) {
                uint8_t *cp = vm->gc_heap.deref(cached);
                if (cp) {
                    auto *cs = reinterpret_cast<loader::StringObject *>(cp);
                    if (cs->byte_len == total_byte_len &&
                        cs->encoding == static_cast<uint8_t>(enc) &&
                        std::memcmp(loader::str_data(cs), stack_buf,
                                    total_byte_len) == 0) {
                        vm->registers.regs[r_dst].qword(
                            static_cast<uint64_t>(cached));
                        return;
                    }
                }
            }
        }

        result =
            alloc_flat(vm, stack_buf, total_byte_len, total_len, enc,
                       /*capacity=*/0,
                       /*precomputed_hash=*/static_cast<uint64_t>(str_hash32));
        if (__builtin_expect(result == gc::GC_NULL_HANDLE, 0)) {
            vm->registers.regs[r_dst].qword(
                static_cast<uint64_t>(gc::GC_NULL_HANDLE));
            return;
        }
        if (total_byte_len > 0 &&
            total_byte_len <= loader::STR_INTERN_THRESHOLD) {
            get_intern_pool(vm).insert_by_hash(fnv, result);
            vm->gc_heap.gc_addref(result); // pin como GC root
        }
        result = auto_intern(vm, result, stack_buf, total_byte_len, enc);
    } else if (new_depth > loader::STR_ROPE_MAX_DEPTH) {
        // arbol demasiado profundo: materializar de inmediato
        gc::GcHandle fa = flatten_string(vm, ha);
        gc::GcHandle fb = flatten_string(vm, hb);
        uint8_t *pfa = vm->gc_heap.deref(fa);
        uint8_t *pfb = vm->gc_heap.deref(fb);
        if (!pfa || !pfb) {
            vm->registers.regs[r_dst].qword(gc::GC_NULL_HANDLE);
            return;
        }

        auto *sfa = reinterpret_cast<loader::StringObject *>(pfa);
        auto *sfb = reinterpret_cast<loader::StringObject *>(pfb);

        std::vector<uint8_t> buf(sfa->byte_len + sfb->byte_len);
        std::memcpy(buf.data(), loader::str_data(sfa), sfa->byte_len);
        std::memcpy(buf.data() + sfa->byte_len, loader::str_data(sfb),
                    sfb->byte_len);

        result = alloc_flat(vm, buf.data(), static_cast<uint32_t>(buf.size()),
                            total_len, enc);
        result = auto_intern(vm, result, buf.data(),
                             static_cast<uint32_t>(buf.size()), enc);
    } else {
        // crear nodo ROPE perezoso (concat de ropes grandes)
        result =
            alloc_rope(vm, ha, hb, total_len, total_byte_len, enc, new_depth);
    }

    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(result));
}

// =========================================================================
// 0x49  STRCMP r_dst, r_a, r_b
// =========================================================================

/**
 * @brief Ejecuta STRCMP: comparacion lexicografica de bytes entre dos strings.
 *
 * Materializa ROPE/SLICE antes de comparar.
 * r_dst recibe -1, 0 o 1 como int64_t con signo.
 * ZF=1 si iguales; SF=1 si a < b.
 */
void exec_instr_strcmp(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_a = instr.data_instruction.reg_data.reg1 & 0xF;
    const uint8_t r_b = (instr.data_instruction.reg_data.reg2 >> 4) & 0xF;

    gc::GcHandle ha_in =
        static_cast<gc::GcHandle>(vm->registers.regs[r_a].qword());
    gc::GcHandle hb_in =
        static_cast<gc::GcHandle>(vm->registers.regs[r_b].qword());

    // Sprint string-perf (2026-06-02): fast path identity.  Si los
    // handles son identicos (e.g. ambos son el mismo string internado),
    // 0 sin flatten ni deref.  Cubre el patron `if (s == s)` y los
    // strings hoisted por LICM comparados consigo mismos.
    if (ha_in == hb_in && ha_in != gc::GC_NULL_HANDLE) {
        vm->registers.regs[r_dst].qword(0);
        vm->registers.flags.bits.ZF = 1;
        vm->registers.flags.bits.SF = 0;
        return;
    }

    // Fast path: skip flatten_string si ambos ya son FLAT.  flatten_string
    // hace deref + chequea kind; si es FLAT retorna el mismo handle.  Para
    // strings creados via STRMAKE o STRCAT fast-path-flat, esto evita la
    // funcion call extra.
    uint8_t *pa_raw = vm->gc_heap.deref(ha_in);
    uint8_t *pb_raw = vm->gc_heap.deref(hb_in);
    gc::GcHandle ha, hb;
    if (pa_raw && reinterpret_cast<loader::StringObject *>(pa_raw)->kind ==
                      static_cast<uint8_t>(loader::StringKind::FLAT)) {
        ha = ha_in;
    } else {
        ha = flatten_string(vm, ha_in);
    }
    if (pb_raw && reinterpret_cast<loader::StringObject *>(pb_raw)->kind ==
                      static_cast<uint8_t>(loader::StringKind::FLAT)) {
        hb = hb_in;
    } else {
        hb = flatten_string(vm, hb_in);
    }

    uint8_t *pa = vm->gc_heap.deref(ha);
    uint8_t *pb = vm->gc_heap.deref(hb);

    if (!pa || !pb) {
        vm->registers.regs[r_dst].qword(static_cast<uint64_t>(-1LL));
        vm->registers.flags.bits.ZF = 0;
        vm->registers.flags.bits.SF = 1;
        return;
    }

    auto *sa = reinterpret_cast<loader::StringObject *>(pa);
    auto *sb = reinterpret_cast<loader::StringObject *>(pb);

    // comparacion rapida por hash si ambos estan calculados
    if (sa->str_hash != 0 && sb->str_hash != 0 &&
        sa->str_hash != sb->str_hash) {
        int64_t result = -1LL; // hashes distintos => no iguales; asumir a < b
        vm->registers.regs[r_dst].qword(static_cast<uint64_t>(result));
        vm->registers.flags.bits.ZF = 0;
        vm->registers.flags.bits.SF = 1;
        return;
    }

    uint32_t min_len = std::min(sa->byte_len, sb->byte_len);
    int cmp = std::memcmp(loader::str_data(sa), loader::str_data(sb), min_len);
    if (cmp == 0) {
        if (sa->byte_len < sb->byte_len)
            cmp = -1;
        else if (sa->byte_len > sb->byte_len)
            cmp = 1;
    }

    int64_t result = (cmp < 0) ? -1LL : (cmp > 0) ? 1LL : 0LL;
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(result));
    vm->registers.flags.bits.ZF = (result == 0);
    vm->registers.flags.bits.SF = (result < 0);
}

// =========================================================================
// 0x4A  STRCONV r_dst, r_src, enc
// =========================================================================

/**
 * @brief Ejecuta STRCONV: convierte la codificacion de un StringObject.
 *
 * Si la codificacion origen y destino coinciden devuelve el mismo handle.
 * Implementa conversion completa UTF-8 <-> UTF-16LE con surrogates.
 * Materializa ROPE/SLICE antes de convertir.
 */
/* Core de STRCONV compartido por el opcode (exec_instr_strconv) y el runtime
 * entry vrt_str_conv (JIT/AOT).  Toma el handle fuente + codificacion destino
 * y devuelve el handle convertido; sin tocar registros VM. */
gc::GcHandle strconv_public(ProcessVM *vm, gc::GcHandle src_h,
                            uint32_t enc) noexcept {
    auto new_enc = static_cast<loader::StringEncoding>(enc & 0xFu);
    gc::GcHandle hs = flatten_string(vm, src_h);

    uint8_t *payload = vm->gc_heap.deref(hs);
    if (!payload) return gc::GC_NULL_HANDLE;

    auto *src_str = reinterpret_cast<loader::StringObject *>(payload);
    auto src_enc = loader::str_encoding(src_str);

    if (src_enc == new_enc) return hs; // sin cambio

    const uint8_t *src_data = loader::str_data(src_str);
    const uint32_t src_len = src_str->byte_len;

    /* Conversion GENERICA: se decodifica a code points y se recodifica.  Antes
     * solo existian las ramas UTF8->UTF16 y UTF16->UTF8, y cualquier otro par
     * caia en un `else` que se limitaba a RE-ETIQUETAR los mismos bytes: por
     * eso UTF-32 no convertia y una cadena ASCII (que es como se etiqueta todo
     * literal sin bytes altos) salia de aqui en UTF-8 marcado como UTF-16. */
    std::vector<uint32_t> cps;
    cps.reserve(src_len);
    switch (src_enc) {
    case loader::StringEncoding::UTF16:
        for (uint32_t i = 0; i + 1 < src_len; i += 2) {
            uint32_t u = static_cast<uint32_t>(src_data[i]) |
                         (static_cast<uint32_t>(src_data[i + 1]) << 8);
            if (u >= 0xD800u && u <= 0xDBFFu && i + 3 < src_len) {
                const uint32_t lo =
                    static_cast<uint32_t>(src_data[i + 2]) |
                    (static_cast<uint32_t>(src_data[i + 3]) << 8);
                if (lo >= 0xDC00u && lo <= 0xDFFFu) {
                    u = 0x10000u + ((u - 0xD800u) << 10) + (lo - 0xDC00u);
                    i += 2;
                }
            }
            cps.push_back(u);
        }
        break;
    case loader::StringEncoding::UTF32:
        for (uint32_t i = 0; i + 3 < src_len; i += 4)
            cps.push_back(static_cast<uint32_t>(src_data[i]) |
                          (static_cast<uint32_t>(src_data[i + 1]) << 8) |
                          (static_cast<uint32_t>(src_data[i + 2]) << 16) |
                          (static_cast<uint32_t>(src_data[i + 3]) << 24));
        break;
    case loader::StringEncoding::ANSI:
        /* Sin tabla de codepage: se trata como Latin-1, que coincide con
         * CP1252 en el rango bajo.  La conversion FIEL de ANSI necesita la
         * codepage del sistema y no se hace aqui. */
        for (uint32_t i = 0; i < src_len; ++i)
            cps.push_back(src_data[i]);
        break;
    default: /* ASCII y UTF8: ASCII es un subconjunto de UTF-8. */
        for (uint32_t i = 0; i < src_len;) {
            const uint8_t bb = src_data[i];
            uint32_t cp;
            uint32_t n;
            if ((bb & 0x80u) == 0) {
                cp = bb;
                n = 1;
            } else if ((bb & 0xE0u) == 0xC0u) {
                cp = bb & 0x1Fu;
                n = 2;
            } else if ((bb & 0xF0u) == 0xE0u) {
                cp = bb & 0x0Fu;
                n = 3;
            } else {
                cp = bb & 0x07u;
                n = 4;
            }
            if (i + n > src_len) break;
            for (uint32_t k = 1; k < n; ++k)
                cp = (cp << 6) | (src_data[i + k] & 0x3Fu);
            cps.push_back(cp);
            i += n;
        }
        break;
    }

    std::vector<uint8_t> out;
    switch (new_enc) {
    case loader::StringEncoding::UTF16:
        for (uint32_t cp : cps) {
            if (cp < 0x10000u) {
                out.push_back(static_cast<uint8_t>(cp & 0xFFu));
                out.push_back(static_cast<uint8_t>((cp >> 8) & 0xFFu));
            } else {
                const uint32_t v = cp - 0x10000u;
                const uint32_t hi = 0xD800u + (v >> 10);
                const uint32_t lo = 0xDC00u + (v & 0x3FFu);
                out.push_back(static_cast<uint8_t>(hi & 0xFFu));
                out.push_back(static_cast<uint8_t>((hi >> 8) & 0xFFu));
                out.push_back(static_cast<uint8_t>(lo & 0xFFu));
                out.push_back(static_cast<uint8_t>((lo >> 8) & 0xFFu));
            }
        }
        break;
    case loader::StringEncoding::UTF32:
        for (uint32_t cp : cps) {
            out.push_back(static_cast<uint8_t>(cp & 0xFFu));
            out.push_back(static_cast<uint8_t>((cp >> 8) & 0xFFu));
            out.push_back(static_cast<uint8_t>((cp >> 16) & 0xFFu));
            out.push_back(static_cast<uint8_t>((cp >> 24) & 0xFFu));
        }
        break;
    case loader::StringEncoding::ASCII:
        /* Lo no representable se sustituye por '?', como hacen las APIs de
         * conversion con perdida. */
        for (uint32_t cp : cps)
            out.push_back(static_cast<uint8_t>(cp < 0x80u ? cp : '?'));
        break;
    case loader::StringEncoding::ANSI:
        for (uint32_t cp : cps)
            out.push_back(static_cast<uint8_t>(cp < 0x100u ? cp : '?'));
        break;
    default: /* UTF8 */
        for (uint32_t cp : cps) {
            if (cp < 0x80u) {
                out.push_back(static_cast<uint8_t>(cp));
            } else if (cp < 0x800u) {
                out.push_back(static_cast<uint8_t>(0xC0u | (cp >> 6)));
                out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
            } else if (cp < 0x10000u) {
                out.push_back(static_cast<uint8_t>(0xE0u | (cp >> 12)));
                out.push_back(
                    static_cast<uint8_t>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
            } else {
                out.push_back(static_cast<uint8_t>(0xF0u | (cp >> 18)));
                out.push_back(
                    static_cast<uint8_t>(0x80u | ((cp >> 12) & 0x3Fu)));
                out.push_back(
                    static_cast<uint8_t>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
            }
        }
        break;
    }

    gc::GcHandle result =
        alloc_flat(vm, out.data(), static_cast<uint32_t>(out.size()),
                   static_cast<uint32_t>(cps.size()), new_enc);

    if (result != gc::GC_NULL_HANDLE) {
        uint8_t *rp = vm->gc_heap.deref(result);
        if (rp) {
            auto *rs = reinterpret_cast<loader::StringObject *>(rp);
            result = auto_intern(vm, result, loader::str_data(rs), rs->byte_len,
                                 loader::str_encoding(rs));
        }
    }
    return result;
}

void exec_instr_strconv(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;
    const uint8_t enc_bits = (instr.data_instruction.reg_data.reg2 >> 4) & 0xF;
    const gc::GcHandle r = strconv_public(
        vm, static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword()),
        enc_bits);
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(r));
}

// =========================================================================
// 0x4B  STRRAW r_dst, r_src
// =========================================================================

/**
 * @brief Ejecuta STRRAW: devuelve la direccion host del buffer interno.
 *
 * Materializa ROPE/SLICE a FLAT antes de devolver el puntero.
 * El buffer siempre tiene un byte nulo extra al final para Win32 FFI.
 */
void exec_instr_strraw(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h = flatten_string(
        vm, static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword()));

    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(
        loader::str_data(s))); // puntero host al buffer
}

// =========================================================================
// 0x4C  STRSLICE r_dst, r_src, r_range
// Encoding FIXED_4: ctrl=(r_dst<<4)|r_src, byte3=r_range (nibble)
// r_range contiene (cp_start << 32) | cp_len como valor de 64 bits
// =========================================================================

/**
 * @brief Ejecuta STRSLICE: crea una vista SLICE sin copia sobre un string.
 *
 * r_range = (cp_start << 32) | cp_len (ambos en code points).
 * Si el padre es ROPE, se materializa primero (el slice solo puede apuntar a
 * FLAT). Si r_start + r_len > length del padre, se recorta al maximo valido.
 */
/**
 * @brief Calcula el SLICE de una cadena.  Cuerpo compartido por el interprete
 *        (@c exec_instr_strslice) y el JIT (@c vrt_str_slice).
 *
 * Se factorizo al anadir la op al selector vreg: mantener dos copias de la
 * aritmetica de puntos de codigo (que para UTF-8 recorre bytes) era garantia
 * de que interprete y JIT acabasen discrepando.
 *
 * @param vm    Proceso propietario del heap.
 * @param src_h Cadena de la que se toma la vista.
 * @param range (cp_start << 32) | cp_len, empaquetado como en el bytecode.
 * @return Handle del SLICE, o el propio padre si la vista lo abarca entero.
 */
gc::GcHandle strslice_public(ProcessVM *vm, gc::GcHandle src_h,
                             uint64_t range) noexcept {
    gc::GcHandle parent_h = flatten_string(vm, src_h);

    uint8_t *payload = vm->gc_heap.deref(parent_h);
    if (!payload) {
        return gc::GC_NULL_HANDLE;
    }

    auto *parent = reinterpret_cast<loader::StringObject *>(payload);
    auto enc = loader::str_encoding(parent);

    uint32_t cp_start = static_cast<uint32_t>(range >> 32);
    uint32_t cp_len = static_cast<uint32_t>(range & 0xFFFFFFFFu);

    // clamp a los limites del padre
    if (cp_start >= parent->length) cp_start = parent->length;
    if (cp_start + cp_len > parent->length) cp_len = parent->length - cp_start;

    // calcular byte_offset y byte_len segun la codificacion
    uint32_t byte_offset = 0;
    uint32_t byte_len = 0;
    const uint8_t *data = loader::str_data(parent);

    switch (enc) {
    case loader::StringEncoding::ASCII:
    case loader::StringEncoding::ANSI:
        byte_offset = cp_start;
        byte_len = cp_len;
        break;
    case loader::StringEncoding::UTF32:
        byte_offset = cp_start * 4;
        byte_len = cp_len * 4;
        break;
    case loader::StringEncoding::UTF16:
        byte_offset = cp_start * 2; // aproximado, ignora surrogates
        byte_len = cp_len * 2;
        break;
    case loader::StringEncoding::UTF8: {
        // para UTF-8 hay que contar bytes recorriendo
        uint32_t i = 0, cp = 0;
        while (cp < cp_start && i < parent->byte_len) {
            uint8_t b = data[i];
            if ((b & 0x80) == 0) {
                i += 1;
            } else if ((b & 0xE0) == 0xC0) {
                i += 2;
            } else if ((b & 0xF0) == 0xE0) {
                i += 3;
            } else {
                i += 4;
            }
            ++cp;
        }
        byte_offset = i;
        uint32_t j = i;
        cp = 0;
        while (cp < cp_len && j < parent->byte_len) {
            uint8_t b = data[j];
            if ((b & 0x80) == 0) {
                j += 1;
            } else if ((b & 0xE0) == 0xC0) {
                j += 2;
            } else if ((b & 0xF0) == 0xE0) {
                j += 3;
            } else {
                j += 4;
            }
            ++cp;
        }
        byte_len = j - i;
        break;
    }
    }

    // si el slice es todo el padre, devolver el padre directamente
    if (byte_offset == 0 && byte_len == parent->byte_len) {
        return parent_h;
    }

    return alloc_slice(vm, parent_h, byte_offset, byte_len, cp_len, enc);
}

/**
 * @brief Ejecuta STRSLICE: vista de una subcadena por puntos de codigo.
 */
void exec_instr_strslice(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;
    const uint8_t r_range = (instr.data_instruction.reg_data.reg2 >> 4) &
                            0xF; // nibble alto (emit_instr_three_reg)

    const gc::GcHandle h = strslice_public(
        vm, static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword()),
        vm->registers.regs[r_range].qword());
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(h));
}

// =========================================================================
// 0x4D  STRFLAT r_dst, r_src
// =========================================================================

/**
 * @brief Ejecuta STRFLAT: materializa ROPE/SLICE a FLAT.
 *
 * Si el origen ya es FLAT, devuelve el mismo handle sin copiar.
 * Tras materializacion aplica interning automatico.
 */
void exec_instr_strflat(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h = flatten_string(
        vm, static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword()));
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(h));
}

// =========================================================================
// 0x4E  STRHASH r_dst, r_src
// =========================================================================

/**
 * @brief Ejecuta STRHASH: devuelve el hash FNV-1a del string.
 *
 * Materializa ROPE/SLICE antes de calcular.
 * El resultado se cachea en str_hash del StringObject.
 */
void exec_instr_strhash(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h = flatten_string(
        vm, static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword()));

    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    uint32_t hv = loader::str_hash_compute(s); // calcula y cachea si necesario
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(hv));
}

// =========================================================================
// 0x4F  STRINTERN r_dst, r_src
// =========================================================================

/**
 * @brief Ejecuta STRINTERN: interna el string en el pool del proceso.
 *
 * Si ya existe un string identico en el pool, devuelve su GcHandle.
 * Solo strings FLAT pueden internarse; ROPE/SLICE se materializan primero.
 * r_dst puede ser distinto de r_src si el string ya estaba en el pool.
 */
void exec_instr_strintern(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h = flatten_string(
        vm, static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword()));

    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) {
        vm->registers.regs[r_dst].qword(gc::GC_NULL_HANDLE);
        return;
    }

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    auto enc = loader::str_encoding(s);
    const uint8_t *data = loader::str_data(s);

    h = auto_intern(vm, h, data, s->byte_len,
                    enc); // interna y devuelve canonico
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(h));
}

// =========================================================================
// 0x50  STRGETENC r_dst, r_src
// =========================================================================

/** @brief Ejecuta STRGETENC: devuelve el byte de codificacion del string. */
void exec_instr_strgetenc(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword());
    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(s->encoding));
}

// =========================================================================
// 0x51  STRGETBYTES r_dst, r_src
// =========================================================================

/** @brief Ejecuta STRGETBYTES: devuelve el byte_len del string. */
void exec_instr_strgetbytes(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword());
    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(s->byte_len));
}

// =========================================================================
// 0x52  STRGETKIND r_dst, r_src
// =========================================================================

/** @brief Ejecuta STRGETKIND: devuelve el kind del string (0=FLAT 1=ROPE
 * 2=SLICE). */
void exec_instr_strgetkind(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_src].qword());
    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    vm->registers.regs[r_dst].qword(
        static_cast<uint64_t>(s->kind & loader::STR_KIND_MASK));
}

// =========================================================================
// 0x53  STRRESERVE r_dst, r_capacity
// Encoding FIXED_4: ctrl=(r_dst<<4)|r_capacity
// =========================================================================

/**
 * @brief Ejecuta STRRESERVE: aloca un FLAT vacio con capacidad reservada.
 *
 * Crea un StringObject FLAT con byte_len=0 pero con capacidad interna
 * de r_capacity bytes.  El programa puede escribir directamente en el
 * buffer via STRRAW y luego llamar a STRFINALIZE para fijar la longitud.
 *
 * Util para el patron de string builder: reservar, escribir bytes, finalizar.
 */
void exec_instr_strreserve(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_cap = instr.data_instruction.reg_data.reg1 & 0xF;

    uint32_t capacity =
        static_cast<uint32_t>(vm->registers.regs[r_cap].qword());

    // string vacio con capacidad reservada; encoding ASCII por defecto
    gc::GcHandle h =
        alloc_flat(vm, nullptr, 0, 0, loader::StringEncoding::ASCII, capacity);
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(h));
}

// =========================================================================
// 0x54  STRFINALIZE r_dst, r_newlen
// Encoding FIXED_4: ctrl=(r_dst<<4)|r_newlen
// =========================================================================

/**
 * @brief Ejecuta STRFINALIZE: actualiza byte_len, length y hash de un FLAT
 * mutable.
 *
 * Debe usarse despues de STRRESERVE + escritura directa en el buffer para
 * registrar la longitud real del contenido.  El hash se recalcula.
 * Solo valido para strings FLAT; no opera sobre ROPE/SLICE.
 */
void exec_instr_strfinalize(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
    const uint8_t r_newlen = instr.data_instruction.reg_data.reg1 & 0xF;

    gc::GcHandle h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_dst].qword());
    uint8_t *payload = vm->gc_heap.deref(h);
    if (!payload) return;

    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    if (loader::str_kind(s) != loader::StringKind::FLAT)
        return; // solo para FLAT

    uint32_t new_byte_len =
        static_cast<uint32_t>(vm->registers.regs[r_newlen].qword());
    auto enc = loader::str_encoding(s);

    s->byte_len = new_byte_len;
    s->length = count_codepoints(loader::str_data(s), new_byte_len, enc);
    s->str_hash = 0;             // invalida el cache para que se recalcule
    loader::str_hash_compute(s); // calcular inmediatamente
    // garantizar terminador nulo tras el nuevo contenido
    loader::str_data(s)[new_byte_len] = 0;
}

// =========================================================================
// 0x6B  GETARGC   r_dst                  - argv: numero de argumentos
// 0x6C  GETARG    r_dst, r_idx           - argv: arg[i] como StringObject
// =========================================================================

/**
 * @brief Ejecuta GETARGC: deposita el numero de argumentos del script en r_dst.
 *
 * Lee `vm->scheduler.vm_reference.script_args.size()` y lo escribe como
 * uint64 en el registro destino.  Permite que un programa Vesta consulte
 * argc via el builtin `args_count()` que baja a esta instruccion.
 *
 * No falla nunca; si no hay args, devuelve 0.
 *
 * @param vm    Proceso virtual.
 * @param instr Instruccion decodificada.  reg1 = registro destino.
 */
void exec_instr_getargc(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const auto &args = vm->scheduler.vm_reference.script_args;
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(args.size()));
}

// =========================================================================
// 0x6E  GETMETHAT r_class, r_idx       - variante reg-reg de getmethod
// 0x6F  GETFLDAT  r_class, r_idx       - variante reg-reg de getfield
// =========================================================================
// El opcode existente getmethod 0xD9 toma idx como inmediato (rango 0..255)
// lo cual no permite iteracion dinamica desde Vesta.  Estos opcodes nuevos
// toman idx en registro para que `getMethodAt(cls, i)` funcione con i
// runtime.  Mismo comportamiento: R00 = &cls->methods[idx] o 0 si fuera de
// rango / nulo.

void exec_instr_getmethat(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data.reg1;
    const uint8_t r_idx = instr.data_instruction.reg_data.reg2;
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());
    const uint64_t idx = vm->registers.regs[r_idx].qword();
    if (cls == nullptr || idx >= cls->method_count) {
        vm->registers.regs[R00].qword(0);
        return;
    }
    vm->registers.regs[R00].qword(
        reinterpret_cast<uint64_t>(&cls->methods[idx]));
}

void exec_instr_getfldat(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data.reg1;
    const uint8_t r_idx = instr.data_instruction.reg_data.reg2;
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());
    const uint64_t idx = vm->registers.regs[r_idx].qword();
    if (cls == nullptr || idx >= cls->field_count) {
        vm->registers.regs[R00].qword(0);
        return;
    }
    vm->registers.regs[R00].qword(
        reinterpret_cast<uint64_t>(&cls->fields[idx]));
}

/**
 * @brief Ejecuta GETARG: aloca un StringObject con el contenido del arg
 * i-esimo.
 *
 * Lee el indice de `r_idx`, valida rango, y aloca un StringObject FLAT
 * en el GcHeap (via alloc_pinned) con los bytes del arg correspondiente.
 * Encoding por defecto: UTF-8 (la VM asume args UTF-8 desde main.cpp).
 *
 * En caso de indice fuera de rango o fallo de alocacion, devuelve
 * GC_NULL_HANDLE (0) que el frontend Vesta interpretara como string vacio /
 * nulo (la verificacion de rango debe hacerla el llamador con
 * `args_count()` antes).
 *
 * @param vm    Proceso virtual.
 * @param instr Instruccion decodificada.  reg1 = dst, reg2 = idx.
 */
void exec_instr_getarg(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_idx = instr.data_instruction.reg_data.reg2;
    const auto &args = vm->scheduler.vm_reference.script_args;
    const uint64_t idx = vm->registers.regs[r_idx].qword();

    if (idx >= args.size()) {
        vm->registers.regs[r_dst].qword(0); // GC_NULL_HANDLE
        return;
    }

    const std::string &s = args[idx];
    // Conteo de code points UTF-8.  Para ASCII puro coincide con byte_len;
    // para UTF-8 multi-byte lo recalcula la helper count_codepoints.
    const auto *data = reinterpret_cast<const uint8_t *>(s.data());
    uint32_t byte_len = static_cast<uint32_t>(s.size());
    uint32_t length =
        count_codepoints(data, byte_len, loader::StringEncoding::UTF8);

    gc::GcHandle h =
        alloc_flat(vm, data, byte_len, length, loader::StringEncoding::UTF8);
    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(h));
}

/* =========================================================================
 *  MC.13: API publica `make_string_flat` -- reusa el mismo path
 * que las instrucciones STRMAKE/STRCAT/STRCONV de la VM para construir
 * un StringObject FLAT desde C++.  Sin reimplementar nada: delega al
 * helper `alloc_flat` interno (alloc_pinned + populacion de header +
 * hash precomputado para strings cortos).
 *
 * Usado por @c vx::ComptimeRuntime para marshalar args @c string del
 * compile-time al VM antes de invocar @Macros lowered.
 * =========================================================================
 */
gc::GcHandle make_string_flat(ProcessVM *vm, const uint8_t *data,
                              uint32_t byte_len, uint32_t length,
                              loader::StringEncoding enc) noexcept {
    if (!vm) return gc::GC_NULL_HANDLE;
    /* Si el caller no proveio length (UINT32_MAX sentinela), asumimos
     * ASCII puro y usamos byte_len.  Para UTF-8 multi-byte el caller
     * deberia computar el code-point count con count_codepoints. */
    const uint32_t effective_length =
        (length == UINT32_MAX) ? byte_len : length;
    return alloc_flat(vm, data, byte_len, effective_length, enc);
}

/* =========================================================================
 * Sprint JIT-cobertura (2026-06-01): exposicion publica de helpers
 * internos de strings para que los wrappers vrt_str_* (en
 * src/vesta_rt/public_wrapper.cpp) puedan delegar sin necesidad de
 * construir DecodedInstr falsos.
 *
 * Las funciones publicas son thin wrappers sobre las helpers static
 * `flatten_string` y `alloc_rope` ya implementadas arriba.
 * =========================================================================
 */
gc::GcHandle flatten_string_public(ProcessVM *vm, gc::GcHandle h) noexcept {
    if (!vm || h == gc::GC_NULL_HANDLE) return gc::GC_NULL_HANDLE;
    return flatten_string(vm, h);
}

gc::GcHandle strcat_public(ProcessVM *vm, gc::GcHandle a,
                           gc::GcHandle b) noexcept {
    if (!vm) return gc::GC_NULL_HANDLE;
    uint8_t *pa = vm->gc_heap.deref(a);
    uint8_t *pb = vm->gc_heap.deref(b);
    if (!pa || !pb) return gc::GC_NULL_HANDLE;
    auto *sa = reinterpret_cast<loader::StringObject *>(pa);
    auto *sb = reinterpret_cast<loader::StringObject *>(pb);
    if (sa->byte_len == 0) return b;
    if (sb->byte_len == 0) return a;
    const uint32_t total_len = sa->length + sb->length;
    const uint32_t total_bytes = sa->byte_len + sb->byte_len;
    const auto enc =
        (sa->encoding == static_cast<uint8_t>(loader::StringEncoding::ASCII) &&
         sb->encoding == static_cast<uint8_t>(loader::StringEncoding::ASCII))
            ? loader::StringEncoding::ASCII
            : loader::StringEncoding::UTF8;

    // Sprint string-perf-3 bug fix (2026-06-02): mismo fast path FLAT-FLAT
    // que exec_instr_strcat.  Sin esto el JIT (via vrt_str_cat ->
    // strcat_public) creaba siempre ROPE -> str_hash compute diferente que
    // STRMAKE -> str_equals(c, pat) daba falso negativo aleatorio.  Ahora
    // ambos paths producen FLAT identico cuando son operands son FLAT
    // pequenos, y el intern hash cache los unifica al canonical handle.
    constexpr uint32_t SMALL_CONCAT_LIMIT = 256;
    if (loader::str_kind(sa) == loader::StringKind::FLAT &&
        loader::str_kind(sb) == loader::StringKind::FLAT &&
        loader::str_encoding(sa) == loader::str_encoding(sb) &&
        total_bytes <= SMALL_CONCAT_LIMIT) {
        uint8_t stack_buf[SMALL_CONCAT_LIMIT];
        std::memcpy(stack_buf, loader::str_data(sa), sa->byte_len);
        std::memcpy(stack_buf + sa->byte_len, loader::str_data(sb),
                    sb->byte_len);

        uint64_t fnv64 = util::kFnvOffset;
        for (uint32_t i = 0; i < total_bytes; ++i) {
            fnv64 ^= stack_buf[i];
            fnv64 *= util::kFnvPrime;
        }
        const uint32_t str_hash32 = static_cast<uint32_t>(fnv64 & 0xFFFFFFFFu);
        uint64_t fnv = fnv64;
        fnv ^= static_cast<uint8_t>(enc);
        fnv *= util::kFnvPrime;

        if (total_bytes <= loader::STR_INTERN_THRESHOLD) {
            StringInternPool &pool = get_intern_pool(vm);
            gc::GcHandle cached = pool.lookup_by_hash(fnv);
            if (cached != gc::GC_NULL_HANDLE) {
                uint8_t *cp = vm->gc_heap.deref(cached);
                if (cp) {
                    auto *cs = reinterpret_cast<loader::StringObject *>(cp);
                    if (cs->byte_len == total_bytes &&
                        cs->encoding == static_cast<uint8_t>(enc) &&
                        std::memcmp(loader::str_data(cs), stack_buf,
                                    total_bytes) == 0) {
                        return cached;
                    }
                }
            }
        }

        gc::GcHandle result =
            alloc_flat(vm, stack_buf, total_bytes, total_len, enc,
                       /*capacity=*/0,
                       /*precomputed_hash=*/static_cast<uint64_t>(str_hash32));
        if (result == gc::GC_NULL_HANDLE) return gc::GC_NULL_HANDLE;
        if (total_bytes <= loader::STR_INTERN_THRESHOLD) {
            get_intern_pool(vm).insert_by_hash(fnv, result);
            vm->gc_heap.gc_addref(result);
        }
        return auto_intern(vm, result, stack_buf, total_bytes, enc);
    }

    return alloc_rope(vm, a, b, total_len, total_bytes, enc, /*depth=*/0);
}

int64_t strcmp_public(ProcessVM *vm, gc::GcHandle a, gc::GcHandle b) noexcept {
    if (!vm) return -1;
    gc::GcHandle fa = flatten_string(vm, a);
    gc::GcHandle fb = flatten_string(vm, b);
    uint8_t *pa = vm->gc_heap.deref(fa);
    uint8_t *pb = vm->gc_heap.deref(fb);
    if (!pa || !pb) return -1;
    auto *sa = reinterpret_cast<loader::StringObject *>(pa);
    auto *sb = reinterpret_cast<loader::StringObject *>(pb);
    const uint8_t *da =
        reinterpret_cast<const uint8_t *>(sa) + 40; // data offset
    const uint8_t *db = reinterpret_cast<const uint8_t *>(sb) + 40;
    const uint32_t la = sa->byte_len;
    const uint32_t lb = sb->byte_len;
    const uint32_t lmin = la < lb ? la : lb;
    int c = std::memcmp(da, db, lmin);
    if (c != 0) return (c < 0) ? -1 : 1;
    if (la == lb) return 0;
    return (la < lb) ? -1 : 1;
}

} // namespace runtime
