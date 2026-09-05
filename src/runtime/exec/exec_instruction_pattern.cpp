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
 * @file exec_instruction_pattern.cpp
 * @brief Implementacion de las instrucciones de despacho por patron JUMPTABLE y
 * TYPESWITCH.
 *
 * Ambas instrucciones permiten despachar el flujo de ejecucion a diferentes
 * ramas de codigo segun el valor de un registro o el tipo de un objeto.
 *
 * JUMPTABLE r_val, r_table, count  (opcode 0x00 0x27)
 *   Realiza un salto O(1): lee la direccion en la posicion r_val de la tabla
 *   de 64 bits apuntada por r_table y salta a ella.  Si r_val >= count no
 * salta. La tabla en memoria VM es un array de uint64 (8 bytes por entrada).
 *
 * TYPESWITCH r_obj, r_table, count  (opcode 0x00 0x28)
 *   Realiza un despacho O(n) por tipo: obtiene el ClassInfo* del objeto en
 * r_obj y lo compara con la tabla de pares [ClassInfo*(8B), target_addr(8B)]
 * (16B cada entrada).  Si encuentra coincidencia salta al target_addr
 * correspondiente. Si no hay coincidencia no salta (cae al siguiente opcode).
 */

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "loader/oop_types.h"

namespace runtime {

// =========================================================================
//  0x27  JUMPTABLE  r_val, r_table, count
// =========================================================================

/**
 * @brief Ejecuta JUMPTABLE: salto O(1) por valor entero.
 *
 * Lee vm_mem[r_table + r_val * 8] como un uint64 y salta a esa direccion.
 * No salta si r_val >= count (rango invalido).
 *
 * @param vm    Proceso virtual que ejecuta JUMPTABLE.
 * @param instr mem_data.reg_base=r_val, mem_data.reg_index=r_table,
 * mem_data.scale=count.
 */
void exec_instr_jumptable(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_val =
        instr.data_instruction.mem_data.reg_base; // registro con el indice
    const uint8_t r_table =
        instr.data_instruction.mem_data.reg_index; // registro con la tabla
    const uint8_t count =
        instr.data_instruction.mem_data.scale; // numero de entradas

    const uint64_t val = vm->registers.regs[r_val].qword(); // valor del indice
    const uint64_t table_addr =
        vm->registers.regs[r_table].qword(); // direccion de la tabla

    if (val >= (uint64_t)count) return; // indice fuera de rango: no saltar

    // leer la direccion de salto en la posicion val de la tabla (8 bytes por
    // entrada)
    uint64_t target = vm->vm_mem.read_u64(table_addr + val * 8);
    write_rip(vm, target); // actualizar el PC al destino
    const_cast<DecodedInstr &>(instr).flags_info.did_jump =
        true; // indicar que hubo salto
}

// =========================================================================
//  0x28  TYPESWITCH  r_obj, r_table, count
// =========================================================================

/**
 * @brief Ejecuta TYPESWITCH: despacho por tipo de objeto (O(n)).
 *
 * La tabla es un array de pares [ClassInfo*(8B), target_addr(8B)] = 16B por
 * entrada. El GcHandle del objeto se desreferencia para obtener el ObjectHeader
 * y su ClassInfo*. Si la clase coincide con una entrada de la tabla salta al
 * target_addr de esa entrada.
 *
 * @param vm    Proceso virtual que ejecuta TYPESWITCH.
 * @param instr mem_data.reg_base=r_obj, mem_data.reg_index=r_table,
 * mem_data.scale=count.
 */
void exec_instr_typeswitch(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_obj =
        instr.data_instruction.mem_data.reg_base; // registro con objeto
    const uint8_t r_table =
        instr.data_instruction.mem_data.reg_index; // registro con tabla
    const uint8_t count =
        instr.data_instruction.mem_data.scale; // entradas en la tabla

    const uint32_t obj_handle = static_cast<uint32_t>(
        vm->registers.regs[r_obj].qword()); // GcHandle del objeto

    // desreferenciar el handle para obtener el ObjectHeader
    const auto *hdr = reinterpret_cast<const loader::ObjectHeader *>(
        vm->gc_heap.deref(obj_handle));
    if (!hdr) return; // handle invalido: no saltar

    const loader::ClassInfo *cls = hdr->class_ptr; // clase del objeto

    const uint64_t table_addr =
        vm->registers.regs[r_table].qword(); // tabla de despacho

    // recorrer las entradas [ClassInfo*, target_addr] en busca de la clase
    for (uint8_t i = 0; i < count; ++i) {
        uint64_t entry_cls_raw =
            vm->vm_mem.read_u64(table_addr + (uint64_t)i * 16);
        uint64_t target =
            vm->vm_mem.read_u64(table_addr + (uint64_t)i * 16 + 8);

        const auto *entry_cls =
            reinterpret_cast<const loader::ClassInfo *>(entry_cls_raw);
        if (entry_cls == cls) {
            // clase encontrada: saltar al handler correspondiente
            write_rip(vm, target);
            const_cast<DecodedInstr &>(instr).flags_info.did_jump = true;
            return;
        }
    }
    // ninguna entrada coincidio: caer al siguiente opcode (no saltar)
}

} // namespace runtime
