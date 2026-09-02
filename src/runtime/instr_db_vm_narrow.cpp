/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/instr_db_vm_narrow.cpp
 * @brief Estrechar los efectos de una instruccion con sus OPERANDOS.
 *
 * Esto NO se genera, y a proposito: la tabla son datos, y esto es la logica de
 * cada regla.  Las reglas son pocas y estan documentadas en
 * `src/runtime/instr_effects_decl.json`, que es donde se declara cual usa cada
 * opcode; aqui esta lo que hace cada una.
 *
 * Por que existe
 * --------------
 * Hay tres momentos en los que se puede saber que toca una instruccion, y solo
 * el primero es el que la tabla puede guardar:
 *
 *   1. Por OPCODE, al generar la base de datos.  Vale para TODAS las
 *      instancias, asi que tiene que decir todo lo que PODRIA tocar.
 *   2. Por INSTANCIA, al formar el paquete.  Los operandos ya estan
 *      descodificados y muchas veces lo deciden del todo.  Es esto.
 *   3. Observando la EJECUCION, cuando ni los operandos bastan --el destino de
 *      un despacho dinamico--.  Eso pide guarda y abandono.
 *
 * El segundo es el que mas rinde por lo que cuesta: es exacto, no necesita
 * guarda y no cuesta nada donde se usa.  El caso que lo justifica es `mov`, que
 * era el 80-100% del peso de lo desconocido y por instancia no tiene ninguna
 * duda.
 */

#include "runtime/instr_db_vm.h"

namespace runtime {
namespace vm_isa {

namespace {

/**
 * @brief Regla `special_reg`: `mov` contra un registro especial.
 *
 * `mov r_ext, r` y `mov r, r_ext` mueven contra uno de los registros
 * especiales, y CUAL sale del nibble bajo de `reg2`.  El reparto es el de
 * `read_special_table`/`write_special_table`:
 *
 *     0..3   cursores -- no tocan ninguno de los cuatro campos
 *     4..7   reservados
 *     8      RIP     -> contador de programa
 *     9      RBP     -> marco
 *     10     RSP     -> pila
 *     11     RFLAGS  -> banderas
 *
 * Y `s` decide si hay registro especial en juego: con `s == 0` es un `mov`
 * normal entre registros generales, que no toca NINGUNO.  `direction` dice si
 * se escribe (0) o se lee (1).
 */
uint16_t narrow_special_reg(uint16_t base, uint8_t signed_bit,
                            uint8_t direction, uint8_t reg2) {
    // Se conservan los bits que no son efectos (implementada, control, ...) y
    // se recalculan los cuatro campos.
    const uint16_t keep = static_cast<uint16_t>(base & ~0x00FFu);

    if (signed_bit == 0) return keep; // mov normal: ningun campo implicito

    uint16_t campo = 0;
    switch (reg2 & 0x0F) {
    case 8: campo = VE_W_PC; break;
    case 9: campo = VE_W_FRAME; break;
    case 10: campo = VE_W_STACK; break;
    case 11: campo = VE_W_FLAGS; break;
    default: return keep; // cursor o ranura reservada: ningun campo
    }
    // Leer el especial es leerlo; escribirlo, escribirlo.  Los bits de lectura
    // estan cuatro posiciones por encima de los de escritura.
    return static_cast<uint16_t>(
        keep | (direction == 1 ? static_cast<uint16_t>(campo << 4) : campo));
}

} // namespace

uint16_t vm_narrow_effects(const VmInstr *v, uint8_t signed_bit,
                           uint8_t direction, uint8_t reg2) {
    if (v == nullptr) return 0;
    switch (v->narrow) {
    case VN_SPECIAL_REG:
        return narrow_special_reg(v->effects, signed_bit, direction, reg2);
    case VN_NONE:
    default:
        return v->effects;
    }
}

} // namespace vm_isa
} // namespace runtime
