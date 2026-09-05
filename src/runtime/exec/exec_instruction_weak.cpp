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
 * @file exec_instruction_weak.cpp
 * @brief Implementacion de las instrucciones de referencias debiles de VestaVM.
 *
 * Las referencias debiles (weak references) permiten observar un objeto GC sin
 * impedirle ser recolectado.  Durante el barrido del major GC, las entradas de
 * la tabla de weak refs que apuntan a objetos muertos se anulan
 * automaticamente.
 *
 *  WEAKREF   r_handle          (0x00 0x30): registra GcHandle; R0 = indice
 * opaco. DEREF_WEAK r_dst, r_idx     (0x00 0x32): r_dst = GcHandle si vivo,
 * GC_NULL_HANDLE si muerto. FREE_WEAK  r_idx            (0x00 0x34): libera la
 * entrada de la tabla de weak refs.
 */

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "gc/gc_heap.h"

namespace runtime {

// =========================================================================
//  0x30  WEAKREF  r_handle
// =========================================================================

/**
 * @brief Ejecuta WEAKREF: crea una referencia debil a un objeto GC.
 *
 * Registra el GcHandle del objeto en la tabla de weak refs del GcHeap y
 * devuelve el indice opaco resultante en R0.  El GC anula automaticamente
 * la entrada si el objeto es recolectado.
 *
 * @param vm    Proceso virtual que ejecuta WEAKREF.
 * @param instr reg1 = GcHandle del objeto referenciado.
 */
void exec_instr_weakref(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_handle = instr.data_instruction.reg_data.reg1;
    const uint32_t handle =
        static_cast<uint32_t>(vm->registers.regs[r_handle].qword());

    // registrar el handle en la tabla de referencias debiles
    uint32_t idx = vm->gc_heap.alloc_weak(handle);

    // devolver el indice opaco en R0
    vm->registers.regs[0].qword(static_cast<uint64_t>(idx));
}

// =========================================================================
//  0x32  DEREF_WEAK  r_dst, r_idx
// =========================================================================

/**
 * @brief Ejecuta DEREF_WEAK: resuelve una referencia debil.
 *
 * Si el objeto referenciado sigue vivo devuelve su GcHandle en r_dst.
 * Si el objeto fue recolectado (la entrada fue anulada por el GC) devuelve
 * GC_NULL_HANDLE en r_dst.
 *
 * @param vm    Proceso virtual que ejecuta DEREF_WEAK.
 * @param instr reg1 = destino, reg2 = indice opaco de la weak ref.
 */
void exec_instr_deref_weak(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1; // destino
    const uint8_t r_idx = instr.data_instruction.reg_data.reg2; // indice

    const uint32_t idx =
        static_cast<uint32_t>(vm->registers.regs[r_idx].qword());

    // obtener el GcHandle asociado al indice; GC_NULL_HANDLE si fue recolectado
    gc::GcHandle result = vm->gc_heap.deref_weak(idx);

    vm->registers.regs[r_dst].qword(static_cast<uint64_t>(result));
}

// =========================================================================
//  0x34  FREE_WEAK  r_idx
// =========================================================================

/**
 * @brief Ejecuta FREE_WEAK: libera una entrada de la tabla de weak refs.
 *
 * Debe llamarse cuando ya no se necesita la weak ref para evitar que la
 * tabla crezca sin limite.  Llamar a FREE_WEAK con un indice ya liberado
 * es un no-op (la implementacion lo ignora silenciosamente).
 *
 * @param vm    Proceso virtual que ejecuta FREE_WEAK.
 * @param instr reg1 = indice opaco de la weak ref a liberar.
 */
void exec_instr_free_weak(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_idx = instr.data_instruction.reg_data.reg1;
    const uint32_t idx =
        static_cast<uint32_t>(vm->registers.regs[r_idx].qword());

    vm->gc_heap.free_weak(idx); // liberar la entrada de la tabla
}

} // namespace runtime
