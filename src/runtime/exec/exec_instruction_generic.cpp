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
 * @file exec_instruction_generic.cpp
 * @brief Implementacion de la instruccion de instanciacion de genericos en
 * runtime.
 *
 * SPECIALIZE (0x00 0x3A): instancia una clase generica con tipos concretos.
 *
 * Codificacion (FIXED_4, modo REG):
 *   byte0 = 0x00  (prefijo tabla extendida)
 *   byte1 = 0x3A  (opcode specialize)
 *   byte2 = (r_dst << 4) | r_class
 *   byte3 = (r_types << 4) | count
 *
 * Operandos:
 *   r_class  -- registro con puntero host a ClassInfo generica
 * (CLASS_FLAG_GENERIC). r_types  -- registro con puntero host a array de
 * ClassInfo* (tipos concretos). count    -- nibble bajo de byte3; numero de
 * parametros de tipo (0-15). r_dst    -- registro destino; recibe el ClassInfo*
 * de la especializacion.
 *
 * La instruccion delega en Loader::specialize_class(), que mantiene una cache
 * interna por nombre calificado ("ClassName<T1,T2,...>") para evitar duplicar
 * especializaciones identicas.
 */

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "loader/loader.h"
#include "loader/oop_types.h"

namespace runtime {

/**
 * @brief Ejecuta SPECIALIZE: instancia una clase generica con tipos concretos.
 *
 * Lee r_class (ClassInfo* generica), r_types (array de ClassInfo*) y count
 * del campo mem_data de la instruccion descodificada.  Llama a
 * Loader::specialize_class() para obtener (o crear) la especializacion
 * y almacena el puntero resultante en r_dst.
 *
 * Si r_class es nulo, r_dst recibe 0.
 * Si count excede type_param_count de la clase generica, se usa
 * type_param_count.
 *
 * @param vm    Proceso virtual que ejecuta SPECIALIZE.
 * @param instr byte2=(r_dst<<4)|r_class, byte3=(r_types<<4)|count.
 */
void exec_instr_specialize(ProcessVM *vm, const DecodedInstr &instr) {
    // desempaquetar operandos del campo mem_data (reutiliza
    // decode_instr_jumptable)
    const uint8_t r_dst =
        instr.data_instruction.mem_data.reg_base; // nibble alto byte2
    const uint8_t r_class =
        instr.data_instruction.mem_data.reg_index; // nibble bajo byte2
    const uint8_t r_types = (instr.data_instruction.mem_data.scale >> 4) &
                            0x0Fu; // nibble alto byte3
    const size_t count = static_cast<size_t>(
        instr.data_instruction.mem_data.scale & 0x0Fu); // nibble bajo byte3

    // obtener el ClassInfo* de la clase generica desde el registro
    auto *generic = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_class].qword());

    if (generic == nullptr) {
        vm->registers.regs[r_dst].qword(0); // puntero nulo: resultado nulo
        return;
    }

    // obtener el array de ClassInfo* con los tipos concretos
    auto **type_args = reinterpret_cast<loader::ClassInfo **>(
        vm->registers.regs[r_types].qword());

    // delegar en el Loader para obtener (o crear) la especializacion cacheada
    loader::ClassInfo *specialized =
        vm->scheduler.vm_reference.loader_public.specialize_class(
            generic, type_args, count);

    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(
        specialized)); // r_dst = ClassInfo* especializado
}

} // namespace runtime
