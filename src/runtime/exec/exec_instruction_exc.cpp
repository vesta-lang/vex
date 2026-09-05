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
 * @file exec_instruction_exc.cpp
 * @brief Implementacion de las instrucciones TRYENTER y TRYLEAVE de VestaVM.
 *
 * TRYENTER apila un ExceptionFrame ligero en ProcessVM::exc_frame_stack.
 * TRYLEAVE desapila el frame del tope.  do_throw (exec_instruction_oop.cpp)
 * comprueba esta pila antes de recorrer MethodInfo.handlers, lo que permite
 * a compiladores de alto nivel instalar handlers dinamicos sin anotaciones
 * en el bytecode.
 *
 * Encoding:
 *   TRYENTER FIXED_4 REG: [0x00][0x44][ctrl][byte3]
 *     ctrl  = (r_handler<<4)|r_type   (r_handler=PC handler, r_type=ClassInfo*
 * o 0) byte3 = reservado (0x00) TRYLEAVE FIXED_2:     [0x00][0x45]
 */
#include "runtime/exec_instruction.h"

namespace runtime {

/**
 * @brief Ejecuta TRYENTER r_handler, r_type: instala un frame de excepcion
 * dinamico.
 *
 * Apila un nuevo ExceptionFrame en exc_frame_stack del proceso con:
 *   - handler_pc = valor del registro r_handler (direccion absoluta VM)
 *   - type       = valor del registro r_type interpretado como ClassInfo*
 *                  (0 = catch-all, captura cualquier excepcion)
 *
 * El frame se destruye cuando TRYLEAVE lo desapila o cuando do_throw lo
 * consume.
 *
 * @param vm    Proceso virtual que ejecuta la instruccion.
 * @param instr Instruccion descodificada; reg1=r_handler, reg2=r_type.
 */
void exec_instr_tryenter(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_handler = (instr.data_instruction.reg_data.reg1 >> 4) &
                              0xF; // nibble alto de byte2
    const uint8_t r_type =
        instr.data_instruction.reg_data.reg1 & 0xF; // nibble bajo de byte2

    uint64_t handler_pc =
        vm->registers.regs[r_handler].qword(); // direccion absoluta del handler
    auto *class_ptr = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_type]
            .qword()); // tipo capturado (puede ser nullptr)

    // Acquire del free list (reciclado por previas tryleave) si tiene
    // frames; sino alocar nuevo via new.  Elimina malloc/free pressure
    // en programas con try/catch en loops (e.g. 1M iter de try -> 0 mallocs
    // tras el primer ciclo, vs 1M antes).
    ProcessVM::ExceptionFrame *ef;
    if (vm->exc_free_list != nullptr) {
        ef = vm->exc_free_list;
        vm->exc_free_list = ef->prev;
    } else {
        ef = new ProcessVM::ExceptionFrame();
    }
    ef->handler_pc = handler_pc; // guardar PC del handler
    ef->type = class_ptr;        // guardar tipo capturado
    // snapshot RSP/RBP/frame_stack al momento del tryenter.
    // do_throw los restaura para descartar pushes del regalloc y
    // frames de calls anidados que no retornaron normalmente por el
    // throw.  Sin esto, los registros vivos guardados en stack quedan
    // corruptos despues del catch (caso visto: callvirt en obj null
    // dentro del try, push r1 sin pop -> r1 corrupto en el merge).
    ef->saved_rsp = vm->registers.stack_pointer.qword();
    ef->saved_rbp = vm->registers.base_pointer.qword();
    ef->saved_frame_stack = (uint64_t)(uintptr_t)vm->frame_stack;
    // Snapshot de R0..R15 para que do_throw los restaure antes de
    // saltar al handler.  Resuelve el problema clasico de regs
    // clobreados durante el try-body que dejaban variables vivas
    // del catch con valores stale (incluido `this` y parametros).
    // Coste: 16 store de qword en tryenter (raro) + 16 load qword
    // en do_throw (raro tambien).  Despreciable comparado con un
    // AV/throw real.
    for (int i = 0; i < 16; ++i) {
        ef->saved_regs[i] = vm->registers.regs[i].qword();
    }
    ef->prev = vm->exc_frame_stack; // encadenar con el frame anterior
    vm->exc_frame_stack = ef;       // empujar al tope de la pila

    // Optimizacion AV recovery (fix19 ext): forzar fin de batch
    // para que el scheduler arme @c setjmp en el siguiente.
    if (vm->reductions_remaining > 1) {
        vm->reductions_remaining = 1;
    }
}

/**
 * @brief Ejecuta TRYLEAVE: desinstala el frame de excepcion del tope de
 * exc_frame_stack.
 *
 * Se debe llamar al salir del bloque try de forma normal (sin excepcion).
 * Si la pila esta vacia la instruccion es un no-op silencioso.
 *
 * @param vm    Proceso virtual que ejecuta la instruccion.
 * @param instr Instruccion descodificada (sin operandos).
 */
void exec_instr_tryleave(ProcessVM *vm, const DecodedInstr & /*instr*/) {
    if (vm->exc_frame_stack == nullptr) return; // pila vacia: no-op silencioso

    ProcessVM::ExceptionFrame *top = vm->exc_frame_stack; // frame del tope
    vm->exc_frame_stack = top->prev;                      // desapilar
    // Reciclar via free list en lugar de delete (elimina malloc/free
    // pressure y leak por programas con many try/catch en loops).
    top->prev = vm->exc_free_list;
    vm->exc_free_list = top;
}

} // namespace runtime
