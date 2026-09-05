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
 * @file exec_instruction_spimm.cpp
 * @brief Implementacion de las instrucciones de aritmetica de pila SUBSP y
 * ADDSP.
 *
 * Estas instrucciones son variantes especializadas de SUB/ADD que operan
 * exclusivamente sobre RSP o RBP con un inmediato de 64 bits.  Se introducen
 * para evitar el caso en que la instruccion generica SUB intentara codificar
 * un registro especial (RSP=10, RBP=9) mediante el codificador de registros
 * generales, que solo acepta r0-r15.
 *
 *  SUBSP rsp|rbp, imm  (opcode 0x00 0x2E)
 *  ADDSP rsp|rbp, imm  (opcode 0x00 0x2F)
 *
 * Formato del bytecode (MIXED_SIZE, siempre 11 bytes para registros de 64
 * bits): [0x00][0x2E|0x2F][ctrl][imm64] ctrl: bits 7-6 = 3 (modo 64 bits), bits
 * 1-0 = sp_bp (0=RSP, 1=RBP)
 */

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"

namespace runtime {

// =========================================================================
//  0x2E  SUBSP  rsp|rbp, imm
// =========================================================================

/**
 * @brief Ejecuta SUBSP: resta un inmediato a RSP o RBP.
 *
 * Tipicamente se usa al inicio de una funcion para reservar espacio en la
 * pila para variables locales sin necesidad de un push explicito.
 *
 * Semantica:
 *   sp_bp == 0 -> RSP -= inmmed
 *   sp_bp == 1 -> RBP -= inmmed
 *
 * @param vm    Proceso virtual que ejecuta SUBSP.
 * @param instr inmmed_data.reg=sp_bp (0=RSP,1=RBP); inmmed_data.inmmed=delta.
 */
void exec_instr_subsp(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t sp_bp = instr.data_instruction.inmmed_data.reg; // 0=RSP 1=RBP
    const uint64_t delta =
        instr.data_instruction.inmmed_data.inmmed; // valor a restar

    if (sp_bp == 0) {
        // restar delta al puntero de pila RSP
        const uint64_t new_rsp = read_rsp(vm) - delta;
        write_rsp(vm, new_rsp);
        // fix8 - tracking de low-water-mark del stack para el GC
        // scan.  Solo cuando rsp baja (subsp); addsp NO lo actualiza
        // porque liberar slots no significa que ya no contengan refs
        // a objetos GC potencialmente alcanzables (defensivo).  Reset
        // tras GC para limitar el scan al rango realmente activo.
        if (new_rsp < vm->stack_low_water) {
            vm->stack_low_water = new_rsp;
        }
    } else {
        // restar delta al puntero base de pila RBP
        write_rbp(vm, read_rbp(vm) - delta);
    }
}

// =========================================================================
//  0x2F  ADDSP  rsp|rbp, imm
// =========================================================================

/**
 * @brief Ejecuta ADDSP: suma un inmediato a RSP o RBP.
 *
 * Tipicamente se usa al final de una funcion para liberar el espacio de
 * variables locales reservado por SUBSP, antes del RET.
 *
 * Semantica:
 *   sp_bp == 0 -> RSP += inmmed
 *   sp_bp == 1 -> RBP += inmmed
 *
 * @param vm    Proceso virtual que ejecuta ADDSP.
 * @param instr inmmed_data.reg=sp_bp (0=RSP,1=RBP); inmmed_data.inmmed=delta.
 */
void exec_instr_addsp(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t sp_bp = instr.data_instruction.inmmed_data.reg; // 0=RSP 1=RBP
    const uint64_t delta =
        instr.data_instruction.inmmed_data.inmmed; // valor a sumar

    if (sp_bp == 0) {
        // sumar delta al puntero de pila RSP
        write_rsp(vm, read_rsp(vm) + delta);
    } else {
        // sumar delta al puntero base de pila RBP
        write_rbp(vm, read_rbp(vm) + delta);
    }
}

} // namespace runtime
