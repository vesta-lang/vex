/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ssa_ir_serialize.h
 * @brief Serializacion binaria compacta de @c IrFunction para persistir
 *        IR junto al bytecode en `.velb`
 *
 * = Diseno =
 *
 * Formato binario little-endian, sin padding, sin alineacion (cada
 * lectura va con memcpy 1/2/4/8 bytes).  Las cstrings llevan u32 length
 * + bytes (sin terminador nulo).  Las constantes pequenas son u8/u16
 * donde caben; los IDs de valores/blocks van como u32.
 *
 * = Layout =
 *
 *   IrFunction:
 *     name            cstring  (u32 len + bytes)
 *     ret_type        u8       (IrType enum value)
 *     flags           u8       (bit0=is_native, bit1=is_variadic)
 *     param_count     u32
 *     params          u32 * param_count
 *     value_count     u32
 *     for each value: u8 type + u8
 * flags(host_ptr|gc_object|pointee_host_ptr|...)
 *                     + u64 const_val (solo si bit is_const)
 *     block_count     u32
 *     for each block:
 *         name        cstring
 *         instr_count u32
 *         for each instr:
 *             op           u16
 *             type         u8
 *             dst          u32 (IR_NO_VALUE = 0xFFFFFFFF)
 *             flags        u8 (bit0=preserve, bit1=is_call_site)
 *             source_line  u32
 *             imm          u64
 *             operand_count u8
 *             operands     u32 * operand_count
 *             func_name    cstring (vacia si no aplica)
 *             func_ptr     u32 (IR_NO_VALUE si no aplica)
 *             target_block u32 (IR_NO_BLOCK si no aplica)
 *             false_block  u32 (idem)
 *             phi_count    u8
 *             phi_args     (u32 value + u32 block) * phi_count
 *         pred_count       u32
 *         preds            u32 * pred_count
 *         succ_count       u32
 *         succs            u32 * succ_count
 *     template_name        cstring (vacia si no aplica - B.3)
 *     type_args_count      u32
 *     type_args            cstring * type_args_count
 *
 * = Tamano tipico =
 *
 *   Funcion pequena (~10 instrs): ~300 bytes serializada.
 *   Funcion media (100 instrs): ~3 KB.
 *   Modulo Vesta tipico (`vxed_modular.vx` ~30 fns x 50 instrs/fn):
 *      ~30 * 1.5 KB = 45 KB de IR vs ~150 KB de bytecode -> 1.3x total.
 *
 *   La compresion LZ4 (no implementada en v1) reduce IR ~3x adicional.
 */

#ifndef VESTA_IR_SSA_IR_SERIALIZE_H
#define VESTA_IR_SSA_IR_SERIALIZE_H

#include <cstdint>
#include <vector>

#include "ir/ssa_ir.h"

namespace ir {

/**
 * @brief Serializa una @c IrFunction a bytes en @p out.
 *        Append (no clear) -- permite serializar varias funciones
 *        a un mismo buffer.
 * @return numero de bytes escritos para esta funcion.
 */
size_t serialize_function(const IrFunction &fn, std::vector<uint8_t> &out);

/**
 * @brief Deserializa una @c IrFunction desde @p in empezando en
 *        @p offset.  Avanza @p offset a la posicion siguiente.
 * @return true si la deserializacion fue exitosa.  En caso de
 *         error, @p out puede quedar en estado parcial.
 */
bool deserialize_function(const std::vector<uint8_t> &in, size_t &offset,
                          IrFunction &out);

/* ===================================================================== */
/* Seccion @ir del archivo .velb                                         */
/* ===================================================================== */

/**
 * @brief Magic "VEIR" (little-endian) que abre la seccion @ir.
 *        El loader valida esto antes de deserializar para detectar
 *        corrupcion / version incorrecta de manera temprana.
 */
static constexpr uint32_t IR_SECTION_MAGIC = 0x52494556U; /* 'V''E''I''R' */

/**
 * @brief Version del formato @ir.  Bump cuando cambia el layout.
 */
static constexpr uint16_t IR_SECTION_VERSION =
    14; // v14: el cuerpo va COMPRIMIDO (deflate).  v13: + clase declarada de
        // cada ligadura de asm (AsmRegBinding::reg_class); comparte
        // serialize_function con la cache, asi que su formato cambia a la vez

/**
 * @brief Banderas del campo reservado de la cabecera de la seccion.
 *
 * El hueco estaba puesto desde el principio "para futuras flags" y el lector
 * comprobaba que fuera cero; esta es la primera que se usa.
 */
static constexpr uint16_t kIrFlagDeflate = 0x0001; ///< el cuerpo va comprimido

/**
 * @brief Con que fuerza se comprime la seccion.
 *
 * Sale de medir sobre una seccion REAL de 5,75 MiB extraida de un artefacto:
 *
 *     nivel 1    5,94x    21,4 ms comprimir    6,3 ms descomprimir
 *     nivel 3   13,80x    22,9 ms              4,1 ms
 *     nivel 6   15,18x    56,8 ms              3,5 ms
 *     nivel 9   15,73x   191,4 ms              4,3 ms
 *
 * El 3 gana por lo que NO cuesta: frente al 6, la diferencia de tamano son 40
 * KiB sobre un artefacto de 7,5 MiB -- nada -- y tarda menos de la mitad.  El 1
 * comprime la mitad por el mismo tiempo que el 3, asi que no tiene sitio.
 */
static constexpr int kIrCompressionLevel = 3;

/**
 * @brief Emit del bytes de la seccion @c @ir lista para append a
 *        un `.velb`.  Layout:
 *
 *            +0  [4]  magic "VEIR"
 *            +4  [2]  version (u16, IR_SECTION_VERSION)
 *            +6  [2]  reserved (0)
 *            +8  [4]  function_count
 *            +12 [..] functions (concat de serialize_function output)
 *
 * @param functions IR functions a incluir en la seccion.
 * @return bytes serializados.  El caller los añade al .velb y
 *         escribe el offset/size en el header.
 */
std::vector<uint8_t> emit_ir_section(const std::vector<IrFunction> &functions);

/**
 * @brief Parse de la seccion @c @ir desde @p data leyendo
 *        @p section_size bytes a partir de @p offset.
 *
 * Valida magic + version antes de deserializar las funciones.
 * Si magic/version no coinciden, retorna false y deja @c functions
 * vacio (puede ser un .velb v2 sin IR -> graceful degradation).
 *
 * @return true si parseo exitoso; false si magic/version invalido
 *         o si alguna funcion fallo deserializacion.
 */
bool parse_ir_section(const std::vector<uint8_t> &data, size_t offset,
                      size_t section_size, std::vector<IrFunction> &functions);

/* ===================================================================== */
/* Cache de IR por modulo (.vxir)                                       */
/* ===================================================================== */

/**
 * @brief Magic "VXMC" del cache de IR por modulo (`.vxir`).
 *        DISTINTO de @c IR_SECTION_MAGIC ("VEIR") a proposito: un
 *        `.vxir` viejo (formato solo-funciones, magic "VEIR") falla
 *        el check de magic en @c parse_ir_module_cache y fuerza
 *        recompilar el dep (auto-invalidacion del cache obsoleto).
 */
static constexpr uint32_t IR_MODULE_CACHE_MAGIC =
    0x434D5856U; /* 'V''X''M''C' */
static constexpr uint16_t IR_MODULE_CACHE_VERSION =
    14; // v14: + los ejes `blocks` y `traps` de una nativa declarada

/**
 * @brief Serializa el IR de UN modulo COMPLETO para el cache `.vxir`.
 *
 * A diferencia de @c emit_ir_section (que solo guarda @c functions y
 * sirve para la seccion @c @ir del `.velb` consumida por el JIT), este
 * formato persiste TODO lo que el merge cross-module necesita del dep:
 *   - functions    (via @c emit_ir_section, con su header VEIR).
 *   - static_data  (pool + entries + meta).  CRITICO: sin esto, un dep
 *                  cache-hit aporta sus `code.s_N` refs pero no sus
 *                  slots -> relocaciones colgadas en el `.velb`.
 *   - globals      (map nombre -> IrValueId).
 *
 * @param mod  IrModule del dep a cachear.
 * @return     bytes listos para escribir al `.vxir`.
 */
std::vector<uint8_t> emit_ir_module_cache(const IrModule &mod);

/**
 * @brief Reconstruye un @c IrModule completo desde un buffer `.vxir`
 *        producido por @c emit_ir_module_cache.
 *
 * Rellena @c out.functions, @c out.static_data y @c out.globals.
 *
 * @return @c true si el parseo fue exitoso; @c false si magic/version
 *         no coinciden (p.ej. un `.vxir` del formato viejo) o el
 *         buffer esta truncado.  En false, el caller debe recompilar.
 */
bool parse_ir_module_cache(const std::vector<uint8_t> &data, IrModule &out);

/**
 * @brief Serializa una @c StaticDataStore verbatim (pool + entries + meta).
 *
 * Expuesto para el driver incremental (fragmentos de IR por-simbolo): los
 * blobs de static_data que referencia una funcion forman un mini-store que
 * viaja con su fragmento.  Round-trip byte-exacto con @c
 * deserialize_static_data.
 */
void serialize_static_data(const IrModule::StaticDataStore &sd,
                           std::vector<uint8_t> &out);

/**
 * @brief Reconstruye una @c StaticDataStore desde @p in empezando en @p off.
 * @return @c false si el buffer esta truncado o un rango cae fuera del pool.
 */
bool deserialize_static_data(const std::vector<uint8_t> &in, size_t &off,
                             IrModule::StaticDataStore &sd);

/* Helpers expuestos para tests / linker (escritura en buffer). */
inline void write_u8(std::vector<uint8_t> &o, uint8_t v) {
    o.push_back(v);
}
inline void write_u16(std::vector<uint8_t> &o, uint16_t v) {
    o.push_back(static_cast<uint8_t>(v));
    o.push_back(static_cast<uint8_t>(v >> 8));
}
inline void write_u32(std::vector<uint8_t> &o, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        o.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
inline void write_u64(std::vector<uint8_t> &o, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        o.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
inline void write_str(std::vector<uint8_t> &o, const std::string &s) {
    write_u32(o, static_cast<uint32_t>(s.size()));
    o.insert(o.end(), s.begin(), s.end());
}

/* Helpers de lectura (con bounds checking). */
inline bool read_u8(const std::vector<uint8_t> &in, size_t &off, uint8_t &out) {
    if (off >= in.size()) return false;
    out = in[off];
    ++off;
    return true;
}
inline bool read_u16(const std::vector<uint8_t> &in, size_t &off,
                     uint16_t &out) {
    if (off + 2 > in.size()) return false;
    out = static_cast<uint16_t>(in[off]) |
          (static_cast<uint16_t>(in[off + 1]) << 8);
    off += 2;
    return true;
}
inline bool read_u32(const std::vector<uint8_t> &in, size_t &off,
                     uint32_t &out) {
    if (off + 4 > in.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) {
        out |= static_cast<uint32_t>(in[off + i]) << (i * 8);
    }
    off += 4;
    return true;
}
inline bool read_u64(const std::vector<uint8_t> &in, size_t &off,
                     uint64_t &out) {
    if (off + 8 > in.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= static_cast<uint64_t>(in[off + i]) << (i * 8);
    }
    off += 8;
    return true;
}
inline bool read_str(const std::vector<uint8_t> &in, size_t &off,
                     std::string &out) {
    uint32_t len = 0;
    if (!read_u32(in, off, len)) return false;
    if (off + len > in.size()) return false;
    out.assign(reinterpret_cast<const char *>(in.data() + off), len);
    off += len;
    return true;
}

} // namespace ir

#endif // VESTA_IR_SSA_IR_SERIALIZE_H
