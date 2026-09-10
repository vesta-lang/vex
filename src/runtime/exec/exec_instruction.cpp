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
/**                                                                            \
 * @file exec_instruction.cpp                                                  \
 * @brief Implementacion del executor principal de instrucciones de VestaVM.   \
 *                                                                             \
 * Implementa exec_instruction(): el bucle principal de ejecucion con despacho \
 * por tabla de punteros a funcion.  Incluye instrucciones de pila, control    \
 * de flujo (JMP, JCC, JREL, CALL, RET, ENTER, LEAVE), llamadas nativas        \
 * (CALLN, CALLVM), syscall, interrupcion (INT) y OOP (CALLVIRT, etc.).        \
 */                                                                            \
#include "runtime/exec_instruction.h"
#include "runtime/decode_instruction.h"
#include "runtime/exception_runtime.h"
#include "runtime/native_invoke.h"
#include <cstdio>
#include "runtime/host_alloca_tracker.h" // Sprint MMM-ext leak-fix
#include "loader/oop_types.h"
#include "loader/loader.h"         //  M.sandbox: check_cap_at_pc + Caps
#include "jit/auto_jit.h"          // D.5-callvm-hook: lookup_jit_code_at_pc
#include "jit/interp_jit_bridge.h" // D.5-callvm-hook: enter_jit
#include "jit/naked_native.h"      // Bug 198: fp nativo (naked) via callvmr
#include "vesta_rt/public.h"       // D.5-callvm-hook: vrt_proc
#include "runtime/profile.h"       // Sprint D.6 (2026-06-03): PGO counters

#include "ffi/native_ffi.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace runtime {

/// Sentinel de retorno para el mini run-loop de reentrada.  Igual patron que
/// @c vrt_run_method_in_interp: el CALL empuja este PC como direccion de
/// retorno; el bucle para cuando RIP vuelve a el.  Valor imposible como PC
/// real de bytecode.
static constexpr uint64_t GC_FINALIZER_RET_SENTINEL = 0xFDFDFDFD00000000ULL;

/**
 * @brief Reentra al interprete para ejecutar la funcion de bytecode en @p
 *        entry_vaddr con un unico argumento en R1 (convencion VM_ABI).
 *
 * Salva/restaura el estado del proceso (RIP/RSP/frame_stack/decoded_ptr),
 * empuja un sentinel de retorno, coloca @p arg en R1 y R15=1 (argc), salta a
 * @p entry_vaddr y corre un mini run-loop hasta que RIP vuelve al sentinel o
 * el proceso entra en HALT/DEAD/error.  Mismo mecanismo probado que usa el
 * fallback de CALLVIRT desde JIT (@c vrt_run_method_in_interp): portable y
 * arch-independiente (ejecuta bytecode, no codigo nativo).
 *
 * @note Se invoca desde el drenado de finalizadores GC, que corre en un safe
 *       point tras completar un collect.  El deleter NO debe entrar en IO
 *       (no hay como esperar sincronicamente); si lo hace se aborta el bucle.
 */
static void gc_finalizer_call_bytecode(ProcessVM *p, uint64_t entry_vaddr,
                                       uint64_t arg) {
    if (entry_vaddr == 0) return;
    // Salvar TODO el estado del proceso que el deleter puede tocar: RIP, RSP,
    // RBP (el deleter usa enter/leave que manipulan RBP), frame_stack,
    // decoded_ptr y los 16 GP regs.  El finalizador corre en medio del ciclo
    // de alocacion del mutator; todo debe quedar intacto al volver.
    const uint64_t saved_rip = p->registers.rip.raw();
    const uint64_t saved_rsp = p->registers.stack_pointer.qword();
    const uint64_t saved_rbp = p->registers.base_pointer.raw();
    const uint64_t saved_flags = p->registers.flags.raw();
    auto *saved_frame_stack = p->frame_stack;
    auto *saved_decoded_ptr = p->decoded_ptr;
    uint64_t saved_regs[16];
    for (int i = 0; i < 16; ++i)
        saved_regs[i] = p->registers.regs[i].qword();

    // Empujar el sentinel como direccion de retorno (mismo mecanismo que
    // CALLVM: push ret_addr; jump).  El deleter crece su pila por debajo de
    // aqui; el caller conserva su pila por encima intacta.
    const uint64_t new_rsp = saved_rsp - 8;
    p->vm_mem.write_u64_fast(new_rsp, GC_FINALIZER_RET_SENTINEL);
    p->registers.stack_pointer.qword(new_rsp);

    // Convencion CALLVM/VM_ABI: arg en R1, argc en R15.  El deleter monta su
    // propio frame (enter/subsp) y setea los registros que usa; no depende de
    // los valores entrantes salvo R1.  NO limpiamos el resto (CALLVM tampoco).
    p->registers.regs[1].qword(arg); // R1 = arg
    p->registers.regs[15].qword(1);  // R15 = argc

    // Saltar al deleter y forzar fresh decode.
    p->registers.rip.qword(entry_vaddr);
    p->decoded_ptr = &p->icache[0];
    p->decoded_ptr->pc = UINT64_MAX;

    // Mini run-loop.  Cota defensiva.
    const uint64_t MAX_ITERS = 10'000'000;
    uint64_t iters = 0;
    while (iters++ < MAX_ITERS) {
        if (p->registers.rip.raw() == GC_FINALIZER_RET_SENTINEL) break;
        if (p->state == HALT || p->state == DEAD) break;
        if (p->err_thread != THREAD_NO_ERROR) break;
        decode_instruction(p);
        vm_event ev = execute_instruction(p);
        if (ev == EVT_HALT || ev == EVT_ERROR) break;
        if (ev == EVT_IO_WAIT) break; // no soportado en el drenado sincronico
    }

    // Restaurar TODO el estado del proceso.
    p->registers.rip.qword(saved_rip);
    p->registers.stack_pointer.qword(saved_rsp);
    p->registers.base_pointer.raw(saved_rbp);
    p->registers.flags.set_raw(saved_flags);
    p->frame_stack =
        saved_frame_stack; // por si el deleter dejo frames colgando
    for (int i = 0; i < 16; ++i)
        p->registers.regs[i].qword(saved_regs[i]);
    // El deleter decodifico instrucciones en el icache (indexado por PC): las
    // entradas que colisionan con las del caller quedan pobladas con datos del
    // deleter.  Invalidar el icache entero fuerza que el interprete re-decode
    // fresco al reanudar, evitando ejecutar una instruccion del deleter en el
    // slot del caller (bug observado: `return C.libs` justo tras gc_collect
    // leia basura).  Coste aceptable: los finalizadores son poco frecuentes.
    for (uint32_t k = 0; k < ICACHE_SIZE; ++k)
        p->icache[k].pc = UINT64_MAX;
    p->decoded_ptr = saved_decoded_ptr;
}

/**
 * @brief Runner de finalizadores GC (interp bytecode, portable).
 *
 * Lo instala el ctor de ProcessVM via @c gc_heap.set_finalizer_runner.  El GC
 * lo invoca (una vez por objeto colectado con recurso interno) en el safe
 * point post-collect.  Ejecuta EXACTAMENTE el mismo deleter/dtor customizable
 * que el cleanup determinista de scope, resuelto por el contenido del propio
 * box (deleter en slot+8 para unique, control block para shared).
 *
 * @param owner ProcessVM* propietario (contexto opaco).
 * @param box   Puntero host al payload del box colectado.
 * @param kind  Clase de finalizador.
 */
static void gc_finalizer_run(void *owner, const gc::GcPendingFinalizer &f) {
    if (owner == nullptr) return;
    auto *p = static_cast<ProcessVM *>(owner);
    switch (f.kind) {
    case gc::GcFinalizerKind::UNIQUE: {
        // f.a0 = inner_ptr, f.a1 = deleter_vaddr (0 = default free).
        const uint64_t inner_ptr = f.a0;
        const uint64_t deleter = f.a1;
        // Anti-doble-free: si el slot fue movido/liberado ya se zerifico.
        if (inner_ptr == 0) return;
        if (deleter != 0) {
            // Deleter Vesta: correr bytecode deleter(inner_ptr).
            gc_finalizer_call_bytecode(p, deleter, inner_ptr);
        } else {
            // Default (unique_box): liberar el bloque raw.  null-safe.
            p->raw_alloc.free(inner_ptr);
        }
        break;
    }
    case gc::GcFinalizerKind::SHARED: {
        // f.a0 = ctrl_block_ptr.  Modelo refcount puro: decrementar refcount
        // @ctrl+0; liberar el ctrl block cuando llega a 0.
        const uint64_t ctrl = f.a0;
        if (ctrl == 0) return;
        uint64_t *rc = reinterpret_cast<uint64_t *>(ctrl);
        if (*rc > 0) (*rc)--;
        if (*rc == 0) p->raw_alloc.free(ctrl);
        break;
    }
    case gc::GcFinalizerKind::CLASS_DTOR: {
        // f.a0 = dtor_vaddr (<Clase>____dtor concreto, dispatch estatico),
        // f.a1 = obj_host_ptr (la instancia).  Correr bytecode dtor(obj) --
        // EXACTAMENTE el mismo <Clase>____dtor que el cleanup determinista
        // CALL_DTOR del caso no-escape (portable en interp,
        // arch-independiente). NO se libera memoria aqui: el GC ya reclamo el
        // slot de la instancia; el dtor solo libera los RECURSOS internos
        // (campos owned, file handles, etc.).
        const uint64_t dtor_vaddr = f.a0;
        const uint64_t obj = f.a1;
        if (dtor_vaddr == 0 || obj == 0) return;
        gc_finalizer_call_bytecode(p, dtor_vaddr, obj);
        break;
    }
    case gc::GcFinalizerKind::NONE:
    default: break;
    }
}

void install_gc_finalizer_runner(ProcessVM *vm) {
    vm->gc_heap.set_finalizer_runner(&gc_finalizer_run, vm);
}

/**
 * @brief Ejecuta la instruccion HLT: detiene el proceso de forma cooperativa.
 *
 * Marca la instruccion como bloqueante antes de notificar al scheduler
 * mediante EVT_HALT.  Sin el marcado previo, el scheduler podria volver
 * a la fase execute y acceder a memoria ya liberada.
 *
 * @param vm    Proceso virtual que ejecuta HLT.
 * @param instr Instruccion descodificada (no se usan sus campos).
 */
void exec_instr_hlt(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr;
    // Si hay un loadmod activo, el HLT al final del main del plugin se
    // trata como RET para regresar al caller.  Reemplaza el viejo
    // `patch_first_hlt_to_ret` que escaneaba bytes y rompia cuando algun
    // imm de mov/callvm contenia la secuencia 0x00 0x03.
    if (vm->loadmod_call_depth > 0) {
        vm->loadmod_call_depth -= 1;
        // Pop ret_addr del stack y saltar a el (mismo flujo que RET).
        uint64_t ret_addr = 0;
        vm->vm_mem.read_bytes(vm->registers.stack_pointer.raw(), &ret_addr, 8);
        const uint64_t cur_rsp = vm->registers.stack_pointer.qword();
        vm->registers.stack_pointer.qword(cur_rsp + 8);
        vm->registers.rip.qword(ret_addr);
        vm->decoded_ptr->flags_info.did_jump = true;
        // BugFix M.dyn (2026-06-05): restaurar R0 = init_pc del load
        // correspondiente, para que `loadmodule` devuelva un indicador
        // de exito FIABLE (el __module_init del plugin clobbea R0 con
        // el resultado de su ultimo op, que en un reload con defclass
        // idempotente puede ser 0).
        if (!vm->loadmod_r0_stack.empty()) {
            vm->registers.regs[0].qword(vm->loadmod_r0_stack.back());
            vm->loadmod_r0_stack.pop_back();
        }
        return;
    }
    // FINALIZADORES exit-time: el proceso termina.  Con el interprete todavia
    // vivo, finalizar todo objeto GC con recurso interno que siga vivo -- cubre
    // los que ESCAPARON su scope (sin cleanup determinista) y que el GC no
    // colecto todavia.  Garantiza cero fuga del recurso interno ANTES del exit.
    // Idempotente (limpia el bit al encolar) y guardado contra reentrada.
    vm->gc_heap.finalize_all_live();

    // bloquear la instruccion ANTES de notificar al scheduler para evitar
    // re-entradas
    vm->scheduler.on_event(EVT_HALT);
    vm->decoded_ptr->flags_info.blocking =
        true; // impedir el avance del PC tras exec
}

/**
 * @brief Ejecuta la instruccion PUSH: apila un valor en la pila del proceso.
 *
 * Soporta registros especiales (siempre 8 bytes) y registros generales
 * (tamano determinado por el modo codificado).  Decrementa RSP en el numero
 * de bytes del valor y escribe el contenido en la memoria virtual.
 *
 * @param vm    Proceso virtual que ejecuta PUSH.
 * @param instr Instruccion descodificada con reg_ext, reg_data.reg1 y mode.
 */
void exec_instr_push(ProcessVM *vm, const DecodedInstr &instr) {
    uint8_t reg_ext =
        instr.flags_info.reg_ext; // indica si es registro especial
    uint8_t reg_code =
        instr.data_instruction.reg_data.reg1; // codigo de registro

    uint64_t value; // valor a apilar
    size_t size;    // numero de bytes del valor

    if (reg_ext) {
        // registro especial (RIP, RSP, RBP, CURn...): siempre 8 bytes
        value = read_special(vm, reg_code);
        size = 8;
    } else {
        // registro general: tamano determinado por el modo
        uint8_t mode = instr.flags_info.mode;
        size = Assembly::Bytecode::mode_to_bytes(mode);
        value = read_reg_table[mode](vm, reg_code); // leer segun tamano
    }

    // decrementar la pila y escribir el valor
    vm->registers.stack_pointer.qword(vm->registers.stack_pointer.qword() -
                                      size);
    // Caso comun (spill de un registro de 8 bytes bajo presion, p.ej. el
    // unroll de un VEC_BINOP): el slot cae en la pagina del frame que el
    // page-cache ya tiene mapeada -> write_u64_fast evita el TLB/page walk
    // completo de write_bytes (~50x).  Semanticamente identico (write_u64_fast
    // cae a write_bytes si la pagina no esta cacheada).
    if (size == 8) {
        vm->vm_mem.write_u64_fast(vm->registers.stack_pointer.raw(), value);
    } else {
        vm->vm_mem.write_bytes(vm->registers.stack_pointer.raw(), &value, size);
    }
}

/**
 * @brief Ejecuta la instruccion MOV con inmediato.
 *
 * Tres variantes segun los campos direction y _signed_instruct:
 *   1. direction=1, signed=1 -> escribir en registro especial
 * (RIP/RSP/RBP/CURn)
 *   2. direction=0, signed=0 -> mov reg, imm (registro general)
 *   3. direction=1, signed=0 -> mov [reg], imm (escritura en memoria)
 *
 * @param vm    Proceso virtual que ejecuta MOV imm.
 * @param instr Instruccion descodificada con inmmed_data.reg, inmmed y mode.
 */
void exec_instr_inmed_mov(ProcessVM *vm, const DecodedInstr &instr) {
    const int rdst = instr.data_instruction.inmmed_data.reg; // registro destino
    uint64_t imm = instr.data_instruction.inmmed_data.inmmed; // valor inmediato
    uint8_t direction = instr.flags_info.direction;           // modo de acceso
    uint8_t is_signed =
        instr.flags_info._signed_instruct; // indicador de registro especial

    // variante 1: registro especial (RIP provoca un salto implicito)
    if (direction == 1 && is_signed == 1) {
        write_special(vm, rdst, imm);
        return;
    }

    // variante 2: mov reg, imm -> escritura directa en registro general
    if (direction == 0 && is_signed == 0) {
        write_reg_table[instr.flags_info.mode](vm, rdst, imm);
        return;
    }

    // variante 3: mov [reg], imm -> escritura del inmediato en la direccion
    // apuntada por reg
    uint64_t addr = vm->registers.regs[rdst].raw(); // direccion destino
    size_t size = Assembly::Bytecode::mode_to_bytes(
        instr.flags_info.mode); // bytes a escribir
    vm->vm_mem.write_bytes(addr, &imm, size);
}

/**
 * @brief Ejecuta la instruccion POP: desapila un valor de la pila del proceso.
 *
 * Lee el numero de bytes indicado por el modo desde la direccion RSP actual,
 * incrementa RSP y escribe el valor en el registro destino.  Soporta tanto
 * registros especiales como generales.
 *
 * @param vm    Proceso virtual que ejecuta POP.
 * @param instr Instruccion descodificada con reg_ext, reg_data.reg1 y mode.
 */
void exec_instr_pop(ProcessVM *vm, const DecodedInstr &instr) {
    uint8_t reg_ext =
        instr.flags_info.reg_ext; // indicador de registro especial
    uint8_t reg_code =
        instr.data_instruction.reg_data.reg1; // codigo de registro destino

    // tamano: siempre 8 bytes para especiales, o segun el modo para generales
    size_t size =
        reg_ext ? 8 : Assembly::Bytecode::mode_to_bytes(instr.flags_info.mode);

    uint64_t value = 0;
    // Caso comun (restaurar un registro de 8 bytes): mismo page-cache que push.
    if (size == 8) {
        value = vm->vm_mem.read_u64_fast(vm->registers.stack_pointer.raw());
    } else {
        vm->vm_mem.read_bytes(vm->registers.stack_pointer.raw(), &value,
                              size); // leer de la pila
    }
    vm->registers.stack_pointer.qword(vm->registers.stack_pointer.qword() +
                                      size); // avanzar RSP

    if (reg_ext) {
        write_special(vm, reg_code, value); // restaurar en registro especial
    } else {
        uint8_t mode = instr.flags_info.mode;
        write_reg_table[mode](vm, reg_code,
                              value); // restaurar en registro general
    }
}

/**
 * @brief Ejecuta la instruccion CALLN: llama a una funcion nativa del host.
 *
 * El puntero de funcion y el numero de argumentos (argc) provienen de la
 * icache para evitar accesos extra a registros en cada llamada.  Los
 * argumentos se leen de R01..R12 segun argc (hasta 12 parametros).
 * El valor de retorno se escribe en R00.
 *
 * El switch compila a tabla de saltos con el mismo costo de indireccion
 * que dispatch[], pero cada case llama directamente a fn sin frame
 * intermedio, leyendo solo los registros necesarios.
 *
 * @param vm    Proceso virtual que ejecuta CALLN.
 * @param instr Instruccion descodificada con inmmed_data.inmmed (fn) y reg
 * (argc).
 */
// el helper @c invoke_native_unchecked se movio a
// include/runtime/native_invoke.h para compartirlo con
// exec_instr_callni (FFI dinamico runtime).  Manten la inclusion para
// que exec_instr_calln siga inlinandolo igual que antes (header inline,
// cero indireccion adicional).

/**
 * @brief Ejecuta la instruccion CALLN con proteccion de crashes.
 *
 * anade aislamiento para crashes en plugins nativos:
 *   - C++ exceptions escapando (`throw` desde el plugin) -> capturado
 *     y convertido en @c FATAL_NATIVE_EXCEPTION via @c throw_fatal.
 *   - SEH crashes en MSVC/MinGW-SEH (segfault, div0 hardware,
 *     access violation) -> capturado por @c __try/__except y
 *     convertido en @c FATAL_NATIVE_CRASH.
 *
 * Coste runtime: el bloque try/__try es esencialmente cero overhead
 * en el camino feliz (no setea registros, solo registra un EH frame
 * que el unwinder solo recorre si hay throw).  Medido: < 2 ns por
 * call, despreciable comparado con la propia llamada nativa.
 *
 * Si el plugin crashea sin handler activo en Vesta, igual mata el
 * proceso (camino antiguo); pero la VM y los demas procesos siguen
 * vivos.  Con handler activo, el throw es capturable.
 *
 * El SEH en MinGW: GCC con --enable-sjlj o SEH soporta @c __try /
 * @c __except cuando se compila con esos flags.  En el TDM-GCC usado
 * por este proyecto SI esta soportado.  Si tu compilador GCC no lo
 * soporta, defina @c VESTA_DISABLE_SEH para fallback a solo C++
 * exception catching (no captura segfault crudo).
 */
#if defined(_WIN32) && defined(_MSC_VER) && !defined(VESTA_DISABLE_SEH)
/**
 * @brief Invoca la funcion nativa capturando lo que lance el C++.
 *
 * Existe por una razon de sintaxis, no de diseno: `__try` y el `try` de C++ no
 * pueden convivir en la MISMA funcion, asi que la mitad de C++ se saca aqui y
 * el `__try` del llamante envuelve la LLAMADA a este ayudante.
 *
 * Esta rama nunca se habia compilado -- el arbol se construye con MinGW, donde
 * no hay SEH --, de modo que el error llevaba dentro desde que se escribio.
 *
 * @param fn    Puntero a la funcion nativa a invocar.
 * @param argc  Cuantos argumentos lleva (R01..R12).
 * @param vm    Proceso que hace la llamada; recibe el FatalError si lo hay.
 * @param out   Valor devuelto por la funcion nativa, solo si retorna true.
 * @return true si la llamada termino; false si ya se lanzo un FatalError y el
 *         llamante debe volver sin tocar R00.
 */
static bool calln_invoke_guarded_cpp(void *fn, uint64_t argc, ProcessVM *vm,
                                     uint64_t &out) {
    try {
        out = invoke_native_unchecked(fn, argc, vm);
        return true;
    } catch (const std::exception &e) {
        runtime::throw_fatalf(vm, runtime::FATAL_NATIVE_EXCEPTION,
                              "CALLN: plugin lanzo std::exception: %s",
                              e.what());
        return false;
    } catch (...) {
        runtime::throw_fatal(vm, runtime::FATAL_NATIVE_EXCEPTION,
                             "CALLN: plugin lanzo excepcion C++ desconocida");
        return false;
    }
}
#endif

void exec_instr_calln(ProcessVM *vm, const DecodedInstr &instr) {
    //  M.sandbox: comprobar la capability FFI_CALL del modulo
    // propietario del PC actual.  En modo default (sin --vx-caps) el
    // check es un fast path (todos los modulos unrestricted) y permite
    // siempre.  Si el sandbox del modulo NO concede ffi:call, abortar
    // con FatalError (el proceso queda DEAD salvo que un try/catch lo
    // capture) en lugar de invocar la funcion nativa.
    if (!vm->scheduler.vm_reference.loader_public.check_cap_at_pc(
            vm->registers.rip.raw(), ::loader::Caps::FFI_CALL)) {
        runtime::throw_fatal(
            vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
            "CALLN denegado por sandbox: falta la capability 'ffi:call'");
        return;
    }
    void *fn =
        reinterpret_cast<void *>(instr.data_instruction.inmmed_data.inmmed);
    uint64_t argc = instr.data_instruction.inmmed_data.reg;
    uint64_t r = 0;

#if defined(_WIN32) && defined(_MSC_VER) && !defined(VESTA_DISABLE_SEH)
    // MSVC: SEH nativo via __try/__except.
    // El `try` de C++ vive en `calln_invoke_guarded_cpp`: aqui no puede estar,
    // MSVC no admite las dos formas en la misma funcion.
    __try {
        if (!calln_invoke_guarded_cpp(fn, argc, vm, r)) return;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        runtime::throw_fatalf(vm, runtime::FATAL_NATIVE_CRASH,
                              "CALLN: plugin nativo crasheo (SEH code=0x%lX)",
                              (unsigned long)GetExceptionCode());
        return;
    }
#else
    // MinGW / GCC / Clang sin SEH: solo C++ exception catching.
    // Los segfault crudos NO se capturan aqui; el plugin debe
    // contenerlos internamente o esa rama mata la VM como antes.
    try {
        r = invoke_native_unchecked(fn, argc, vm);
    } catch (const std::exception &e) {
        runtime::throw_fatalf(vm, runtime::FATAL_NATIVE_EXCEPTION,
                              "CALLN: plugin lanzo std::exception: %s",
                              e.what());
        return;
    } catch (...) {
        runtime::throw_fatal(vm, runtime::FATAL_NATIVE_EXCEPTION,
                             "CALLN: plugin lanzo excepcion C++ desconocida");
        return;
    }
#endif
    vm->registers.regs[R00].qword(r);
}

/**
 * @brief Ejecuta la instruccion XCHG: intercambia dos valores entre registros.
 *
 * Cada operando puede ser un registro general o especial segun su flag.
 * Lee ambos valores, escribe el del registro 1 en el registro 2 y viceversa.
 * El modo del registro general se codifica en los bits 7-4 de su campo.
 *
 * @param vm    Proceso virtual que ejecuta XCHG.
 * @param instr Instruccion descodificada con regs_data_extent.
 */
void exec_instr_xchg(ProcessVM *vm, const DecodedInstr &instr) {
    uint64_t val1 = 0; // valor leido del registro 1
    uint64_t val2 = 0; // valor leido del registro 2

    bool reg1_is_general = false; // true si reg1 es un registro general
    uint8_t reg1_mode = 0;        // modo de acceso del registro general 1
    uint8_t reg1_general = 0;     // codigo del registro general 1

    if (instr.data_instruction.regs_data_extent.reg1_flags == 1) {
        // reg1 es un registro especial: leer directamente
        val1 = read_special(vm, instr.data_instruction.regs_data_extent.reg1);
        reg1_is_general = false;
    } else {
        // reg1 es un registro general: extraer modo y numero del codigo de 6
        // bits
        reg1_mode = instr.data_instruction.regs_data_extent.reg1 >>
                    4; // nibble alto = modo
        reg1_general = instr.data_instruction.regs_data_extent.reg1 &
                       0b1111; // nibble bajo = registro
        val1 = read_reg_table[reg1_mode](vm, reg1_general);
        reg1_is_general = true;
    }

    if (instr.data_instruction.regs_data_extent.reg2_flags == 1) {
        // reg2 es un registro especial
        val2 = read_special(vm, instr.data_instruction.regs_data_extent.reg2);
        // escribir el valor del registro 1 en el registro 2
        write_special(vm, instr.data_instruction.regs_data_extent.reg2, val1);
    } else {
        // reg2 es un registro general
        uint8_t mode = instr.data_instruction.regs_data_extent.reg2 >> 4;
        uint8_t reg_general =
            instr.data_instruction.regs_data_extent.reg2 & 0b1111;

        val2 = read_reg_table[mode](vm, reg_general);
        // escribir el valor del registro 1 en el registro 2
        write_reg_table[mode](vm, reg_general, val1);
    }

    // completar el intercambio: escribir el valor del registro 2 en el registro
    // 1
    if (reg1_is_general == 1) {
        write_reg_table[reg1_mode](vm, reg1_general, val2); // registro general
    } else {
        write_special(vm, instr.data_instruction.regs_data_extent.reg1,
                      val2); // registro especial
    }
}

/**
 * @brief Ejecuta la instruccion JMP: salto absoluto condicional o
 * incondicional.
 *
 * Evalua la condicion codificada en el campo cond usando los flags del proceso.
 * Si la condicion es verdadera, actualiza RIP a la direccion absoluta destino.
 * El codigo 0x0F (y cualquier otro no listado) equivale a salto incondicional.
 *
 * @param vm    Proceso virtual que ejecuta JMP.
 * @param instr Instruccion descodificada con inmmed_data.reg (cond) e inmmed
 * (addr).
 */
void exec_instr_jmp(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t cond =
        instr.data_instruction.inmmed_data.reg; // codigo de condicion
    const uint64_t addr =
        instr.data_instruction.inmmed_data.inmmed; // direccion absoluta destino
    auto &fl = vm->registers.flags.bits;           // referencia a los flags

    bool taken; // resultado de la evaluacion de la condicion
    switch (cond) {
    case 0x00: taken = COND_EQ(fl); break;                    // ZF==1
    case 0x01: taken = COND_NE(fl); break;                    // ZF==0
    case 0x02: taken = COND_CS(fl); break;                    // CF==1
    case 0x03: taken = COND_CC(fl); break;                    // CF==0
    case 0x04: taken = COND_MI(fl); break;                    // SF==1
    case 0x05: taken = COND_PL(fl); break;                    // SF==0
    case 0x06: taken = COND_VS(fl); break;                    // OF==1
    case 0x07: taken = COND_VC(fl); break;                    // OF==0
    case 0x08: taken = COND_HI(fl); break;                    // CF==0 && ZF==0
    case 0x09: taken = COND_LS(fl); break;                    // CF==1 || ZF==1
    case 0x0A: taken = COND_GE(fl); break;                    // SF==OF
    case 0x0B: taken = COND_LT(fl); break;                    // SF!=OF
    case 0x0C: taken = (fl.ZF == 0 && fl.SF == fl.OF); break; // GT
    case 0x0D: taken = (fl.ZF == 1 || fl.SF != fl.OF); break; // LE
    default: taken = true; break; // incondicional (0x0F y otros)
    }

    // Sprint D.6 (2026-06-03): branch frequency counter para PGO.
    // Solo registramos branches CONDICIONALES (cond < 0x0E); los
    // incondicionales (0x0F+) no aportan info al C2.
    if (cond < 0x0E) {
        const uint64_t bpc = vm->registers.rip.raw();
        // Profiler ligero (auto-PGO del JIT): self-guarded, ~1 ciclo cuando
        // OFF.
        profile::lite_profile_branch(bpc, taken);
        // Profiler pesado D.6 (--profile): solo cuando activo.
        if (__builtin_expect(
                profile::g_profile.active.load(std::memory_order_relaxed), 0)) {
            profile::profile_branch(bpc, taken);
        }
    }

    if (taken) write_rip(vm, addr); // actualizar RIP al destino del salto
}

/**
 * @brief Ejecuta la instruccion CALLVM: llamada a subrutina de bytecode.
 *
 * Empuja la direccion de retorno (PC + size_instr) en la pila del proceso
 * y salta a la direccion indicada en el campo inmediato de la instruccion.
 *
 * @param vm    Proceso virtual que ejecuta CALLVM.
 * @param instr Instruccion descodificada con inmmed_data.inmmed (addr) y
 * size_instr.
 */
void exec_instr_callvm(ProcessVM *vm, const DecodedInstr &instr) {
    const uint64_t addr =
        instr.data_instruction.inmmed_data.inmmed; // direccion del callee
    const uint64_t ret_addr =
        vm->registers.rip.raw() + instr.flags_info.size_instr; // siguiente PC

    // D.5-callvm-hook: si el callee tiene codigo JIT compilado, despachar
    // directo a el en lugar de interpretar el bytecode.  El JIT respeta
    // la calling convention VM_ABI: lee args de proc->registers.regs[1..N],
    // escribe el resultado a proc->registers.regs[0], y NO toca la pila VM
    // (su prologo/epilogo opera sobre el host stack via host push/pop).
    //
    // Por eso saltamos completo el push del ret_addr: tras el retorno del
    // JIT, ponemos RIP en ret_addr y continuamos en interp.  La pila VM
    // del proceso queda intacta, identica a un CALLVM-y-RET secuencial.
    //
    // Fast path coste cuando @c g_pc_jit_active == false: 1 load + 1 branch
    // predicted-not-taken = ~1 ns.  Programs sin JIT no pagan overhead real.
    if (jit::g_pc_jit_active) {
        if (void *jit_fn = jit::lookup_jit_code_at_pc(addr)) {
            // RIP al sitio de retorno ANTES de entrar al JIT: si el callee JIT
            // dispara un GC, el scan preciso de raices del interprete halla el
            // frame de este caller (aun en interp) via el stackmap del @sm que
            // el emisor puso tras el CALLVM -- igual que el caso interp->interp
            // (caller hallado por el return_pc del callee).  Sin esto RIP
            // seguiria en el propio CALLVM (sin stackmap) y las raices GC vivas
            // de este frame se perderian (UAF con el GC movible).  El JIT
            // VM_ABI no lee RIP.
            write_rip(vm, ret_addr);
            jit::enter_jit(reinterpret_cast<jit::JitFn>(jit_fn),
                           reinterpret_cast<vrt_proc *>(vm));
            return;
        }
    }

    // D.5-callvm-trigger: si el JIT esta activo y no hay codigo
    // compilado para este PC todavia, incrementar el counter del PC
    // y maybe disparar el compile.  El check de threshold + lookup
    // estan dentro de maybe_compile_callvm_target.  Fast path: si JIT
    // off (threshold = UINT32_MAX), la funcion sale en O(1).  Si JIT
    // on pero counter por debajo, ~30ns lock + increment.  Tras el
    // compile exitoso, el siguiente CALLVM hace HIT en el pc-map y
    // skipea el trigger por completo.
    if (jit::g_jit_threshold != UINT32_MAX) {
        jit::maybe_compile_callvm_target(vm, addr);
        /* Re-check del pc-map tras el trigger: si justo cruzo el
         * threshold Y la compilacion tuvo exito, podemos dispatchar
         * a JIT en ESTA misma invocacion en lugar de esperar a la
         * siguiente -- elimina la latencia de 1 invocacion. */
        if (void *jit_fn = jit::lookup_jit_code_at_pc(addr)) {
            // RIP al sitio de retorno ANTES de entrar al JIT: si el callee JIT
            // dispara un GC, el scan preciso de raices del interprete halla el
            // frame de este caller (aun en interp) via el stackmap del @sm que
            // el emisor puso tras el CALLVM -- igual que el caso interp->interp
            // (caller hallado por el return_pc del callee).  Sin esto RIP
            // seguiria en el propio CALLVM (sin stackmap) y las raices GC vivas
            // de este frame se perderian (UAF con el GC movible).  El JIT
            // VM_ABI no lee RIP.
            write_rip(vm, ret_addr);
            jit::enter_jit(reinterpret_cast<jit::JitFn>(jit_fn),
                           reinterpret_cast<vrt_proc *>(vm));
            return;
        }
    }

    // apilar la direccion de retorno para que RET pueda recuperarla
    const uint64_t new_rsp = vm->registers.stack_pointer.qword() - 8;
    vm->registers.stack_pointer.qword(new_rsp);
    vm->vm_mem.write_u64_fast(new_rsp, ret_addr); // page-cache hot path
    write_rip(vm, addr);                          // saltar al callee
}

/**
 * @brief Ejecuta la instruccion RET: retorno de subrutina.
 *
 * Si existe un frame OOP activo en frame_stack lo elimina antes de
 * desapilar la direccion de retorno y saltar a ella.
 *
 * @param vm    Proceso virtual que ejecuta RET.
 * @param instr Instruccion descodificada (no se usan sus campos).
 */
void exec_instr_ret(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr;
    // fix13 - distinguir RET de callvirt/callm/callsuper/callclosure
    // (que tiene frame OOP) vs RET de callvm puro anidado dentro de un
    // metodo virtual (que NO debe consumir el frame del caller).
    //
    // Heuristica: el frame OOP guarda `frame_base` = RSP justo ANTES del
    // CALL correspondiente.  Tras el CALL: RSP = frame_base - 8 (slot
    // del ret_addr).  Cuando el callee retorna por su propio RET,
    // primero ejecuta `leave` que restaura RSP al valor post-CALL =
    // frame_base - 8.  Si en ese momento current_rsp == frame_base - 8,
    // este RET corresponde al CALL del frame OOP head.
    //
    // Si NO coincide (RSP es menor por un callvm interno o mayor por
    // unwind imperfecto), este RET viene de un callvm puro: leer el
    // ret_addr del stack y NO consumir el frame OOP.
    const uint64_t cur_rsp = vm->registers.stack_pointer.qword();
    uint64_t ret_addr;
    loader::FrameHeader *frame = vm->frame_stack;
    if (frame != nullptr && frame->frame_base == cur_rsp + 8) {
        // RET corresponde al CALL del frame OOP head: usar return_pc
        // cacheado, evitar la lectura desde vm_mem.
        ret_addr = frame->return_pc;
        // BugFix P0-E2: si este frame fue pushed con save_regs (caso
        // AOP advice chain dispatch), restaurar r1..r12 del snapshot
        // para que el siguiente paso del chain vea la calling
        // convention original (r1=this, r2..rN=args).  El RET del
        // ULTIMO paso del chain restaura tambien (no daña: el caller
        // del CALLVIRT original ya respaldo sus regs vivos si los
        // necesitaba via su propio regalloc).
        if (frame->has_saved_regs) {
            for (int i = 0; i < 12; ++i) {
                vm->registers.regs[i + 1].qword(frame->saved_r1_r12[i]);
            }
        }
        // B5 multi-AROUND: si este frame OWNS el around_chain (es el
        // outer-most AROUND del callsite), liberar el array heap.
        if (frame->around_chain_owns && frame->around_chain != nullptr) {
            delete[] frame->around_chain;
        }
        // Sprint MMM-ext leak-fix: liberar host_allocas registrados
        // en este frame antes de devolverlo al pool.  No-op si el
        // frame no contiene ningun host_alloca.
        host_alloca_release_all(vm, frame);
        // LR3: si el NEXT step es un AFTER_RETURNING (inject_r0_to_reg!=0),
        // copiar R0 actual (return value del current frame) al reg destino
        // del next.  Asi el advice ve el return value como su arg.
        loader::FrameHeader *next_frame = frame->prev;
        const uint8_t inject_reg =
            (next_frame ? next_frame->inject_r0_to_reg : 0);
        const uint64_t r0_value = vm->registers.regs[R00].qword();
        vm->frame_stack = frame->prev;
        vm->frame_pool.release(frame);
        if (inject_reg >= 1 && inject_reg <= 12) {
            vm->registers.regs[inject_reg].qword(r0_value);
        }
    } else {
        // RET de callvm puro (sin frame OOP, o anidado dentro de uno):
        // leer ret_addr desde el slot del stack VM.
        ret_addr = vm->vm_mem.read_u64_fast(cur_rsp); // page-cache hot path
    }
    // Avanzar RSP para liberar el slot reservado por el CALL correspondiente.
    vm->registers.stack_pointer.qword(cur_rsp + 8);
    write_rip(vm, ret_addr); // saltar a la direccion de retorno
}

/**
 * @brief Ejecuta la instruccion ENTER: crea un nuevo marco de pila.
 *
 * Secuencia clasica de prologo: push RBP, mov RBP RSP, sub RSP frame_size.
 * El campo inmediato de la instruccion indica el tamano del nuevo frame.
 *
 * @param vm    Proceso virtual que ejecuta ENTER.
 * @param instr Instruccion descodificada con inmmed_data.inmmed (frame_size).
 */
void exec_instr_enter(ProcessVM *vm, const DecodedInstr &instr) {
    const uint64_t frame_size =
        instr.data_instruction.inmmed_data.inmmed; // tamano del frame en bytes
    const uint64_t rbp_val =
        vm->registers.base_pointer.raw(); // valor actual de RBP

    // push rbp: guardar el frame base del llamador (con page-cache fast path)
    const uint64_t rsp_after_push = vm->registers.stack_pointer.qword() - 8;
    vm->vm_mem.write_u64_fast(rsp_after_push, rbp_val);

    // mov rbp, rsp: establecer el nuevo frame base
    vm->registers.base_pointer.raw(rsp_after_push);

    // sub rsp, frame_size: reservar espacio para las variables locales
    const uint64_t new_rsp = rsp_after_push - frame_size;
    vm->registers.stack_pointer.qword(new_rsp);

    // fix8 - tracking de low-water-mark del stack para el GC scan.
    if (new_rsp < vm->stack_low_water) {
        vm->stack_low_water = new_rsp;
    }
}

/**
 * @brief Ejecuta la instruccion LEAVE: destruye el marco de pila actual.
 *
 * Secuencia clasica de epilogo: mov RSP RBP, pop RBP.
 * Inversa de ENTER: libera el espacio de variables locales y restaura RBP.
 *
 * @param vm    Proceso virtual que ejecuta LEAVE.
 * @param instr Instruccion descodificada (no se usan sus campos).
 */
void exec_instr_leave(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr;
    // mov rsp, rbp: liberar el espacio del frame actual
    const uint64_t rsp_at_rbp = vm->registers.base_pointer.raw();
    // pop rbp: restaurar el frame base del llamador (page-cache fast path)
    const uint64_t rbp_val = vm->vm_mem.read_u64_fast(rsp_at_rbp);
    vm->registers.stack_pointer.qword(rsp_at_rbp + 8);
    vm->registers.base_pointer.raw(rbp_val);
}

/**
 * @brief Ejecuta la instruccion JMPR: salto absoluto a la direccion contenida
 * en un registro.
 *
 * Si reg_ext esta activo el registro es especial, de lo contrario es un
 * registro general de 64 bits.
 *
 * @param vm    Proceso virtual que ejecuta JMPR.
 * @param instr Instruccion descodificada con reg_ext y reg_data.reg1.
 */
void exec_instr_jmpr(ProcessVM *vm, const DecodedInstr &instr) {
    // obtener la direccion del registro segun si es especial o general
    const uint64_t addr =
        instr.flags_info.reg_ext
            ? read_special(
                  vm, instr.data_instruction.reg_data.reg1) // registro especial
            : read_reg64(vm, instr.data_instruction.reg_data
                                 .reg1); // registro general de 64 bits
    write_rip(vm, addr);                 // saltar a la direccion obtenida
}

/**
 * @brief Ejecuta la instruccion CALLVMR: llamada indirecta a subrutina via
 * registro.
 *
 * Igual que CALLVM pero la direccion del callee se obtiene de un registro
 * (general o especial segun reg_ext).  Empuja ret_addr en la pila antes de
 * saltar.
 *
 * @param vm    Proceso virtual que ejecuta CALLVMR.
 * @param instr Instruccion descodificada con reg_ext, reg_data.reg1 y
 * size_instr.
 */
void exec_instr_callvmr(ProcessVM *vm, const DecodedInstr &instr) {
    // obtener la direccion del callee desde el registro indicado
    const uint64_t addr =
        instr.flags_info.reg_ext
            ? read_special(vm, instr.data_instruction.reg_data.reg1)
            : read_reg64(vm, instr.data_instruction.reg_data.reg1);
    const uint64_t ret_addr =
        vm->registers.rip.raw() + instr.flags_info.size_instr; // PC de retorno

    // Bug/feature 198: puntero a funcion NATIVO (naked).  Si @c addr cae dentro
    // del code cache de funciones naked-native (comprobacion de rango precisa),
    // la invocamos con ABI del host: args en R1..R15 (mismo puente que CALLN),
    // resultado a R0.  Las direcciones VM de bytecode nunca caen en ese rango
    // (son VAs del espacio VM, no punteros host), asi que el fast-path normal
    // no se ve afectado.
    if (jit::is_naked_native_addr(addr)) {
        const uint64_t argc = vm->registers.regs[15].qword();
        const uint64_t r = runtime::invoke_native_unchecked(
            reinterpret_cast<void *>(addr), argc, vm);
        vm->registers.regs[0].qword(r);
        write_rip(vm, ret_addr);
        return;
    }

    // D.5-callvm-hook: dispatch a JIT si el target tiene codigo nativo
    // compilado.  Mismo razonamiento que exec_instr_callvm: la calling
    // convention VM_ABI hace que el JIT lea args de proc->registers y
    // escriba el resultado ahi, sin tocar la pila VM.
    if (jit::g_pc_jit_active) {
        if (void *jit_fn = jit::lookup_jit_code_at_pc(addr)) {
            // RIP al sitio de retorno ANTES de entrar al JIT: si el callee JIT
            // dispara un GC, el scan preciso de raices del interprete halla el
            // frame de este caller (aun en interp) via el stackmap del @sm que
            // el emisor puso tras el CALLVM -- igual que el caso interp->interp
            // (caller hallado por el return_pc del callee).  Sin esto RIP
            // seguiria en el propio CALLVM (sin stackmap) y las raices GC vivas
            // de este frame se perderian (UAF con el GC movible).  El JIT
            // VM_ABI no lee RIP.
            write_rip(vm, ret_addr);
            jit::enter_jit(reinterpret_cast<jit::JitFn>(jit_fn),
                           reinterpret_cast<vrt_proc *>(vm));
            return;
        }
    }
    // D.5-callvm-trigger (mismo razonamiento que en exec_instr_callvm).
    if (jit::g_jit_threshold != UINT32_MAX) {
        jit::maybe_compile_callvm_target(vm, addr);
        if (void *jit_fn = jit::lookup_jit_code_at_pc(addr)) {
            // RIP al sitio de retorno ANTES de entrar al JIT: si el callee JIT
            // dispara un GC, el scan preciso de raices del interprete halla el
            // frame de este caller (aun en interp) via el stackmap del @sm que
            // el emisor puso tras el CALLVM -- igual que el caso interp->interp
            // (caller hallado por el return_pc del callee).  Sin esto RIP
            // seguiria en el propio CALLVM (sin stackmap) y las raices GC vivas
            // de este frame se perderian (UAF con el GC movible).  El JIT
            // VM_ABI no lee RIP.
            write_rip(vm, ret_addr);
            jit::enter_jit(reinterpret_cast<jit::JitFn>(jit_fn),
                           reinterpret_cast<vrt_proc *>(vm));
            return;
        }
    }

    // apilar la direccion de retorno (page-cache fast path)
    const uint64_t new_rsp = vm->registers.stack_pointer.qword() - 8;
    vm->registers.stack_pointer.qword(new_rsp);
    vm->vm_mem.write_u64_fast(new_rsp, ret_addr);
    write_rip(vm, addr); // saltar al callee
}

/**
 * @brief Ejecuta la instruccion JREL: salto relativo condicional o
 * incondicional.
 *
 * El desplazamiento de 32 bits con signo se suma a (PC + size_instr), lo que
 * permite saltos hacia atras y hacia adelante respecto a la instruccion
 * siguiente. La condicion se evalua igual que en JMP.
 *
 * @param vm    Proceso virtual que ejecuta JREL.
 * @param instr Instruccion descodificada con inmmed_data.reg (cond) e inmmed
 * (disp32 extendido).
 */
void exec_instr_jrel(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t cond =
        instr.data_instruction.inmmed_data.reg; // codigo de condicion
    const int64_t disp = static_cast<int64_t>(
        instr.data_instruction.inmmed_data.inmmed); // desplazamiento con signo
    auto &fl = vm->registers.flags.bits;            // referencia a los flags

    bool taken; // resultado de la evaluacion de la condicion
    switch (cond) {
    case 0x00: taken = COND_EQ(fl); break;
    case 0x01: taken = COND_NE(fl); break;
    case 0x02: taken = COND_CS(fl); break;
    case 0x03: taken = COND_CC(fl); break;
    case 0x04: taken = COND_MI(fl); break;
    case 0x05: taken = COND_PL(fl); break;
    case 0x06: taken = COND_VS(fl); break;
    case 0x07: taken = COND_VC(fl); break;
    case 0x08: taken = COND_HI(fl); break;
    case 0x09: taken = COND_LS(fl); break;
    case 0x0A: taken = COND_GE(fl); break;
    case 0x0B: taken = COND_LT(fl); break;
    case 0x0C: taken = (fl.ZF == 0 && fl.SF == fl.OF); break;
    case 0x0D: taken = (fl.ZF == 1 || fl.SF != fl.OF); break;
    default: taken = true; break; // incondicional
    }

    if (taken)
        // destino = PC + size_instr + desplazamiento (relativo a la instruccion
        // siguiente)
        write_rip(vm, vm->registers.rip.raw() + instr.flags_info.size_instr +
                          static_cast<uint64_t>(disp));
}

} // namespace runtime
