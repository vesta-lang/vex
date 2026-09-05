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
 * @file exec_instruction_async.cpp
 * @brief Implementacion de las instrucciones de async/await de VestaVM.
 *
 * Implementa un modelo de concurrencia basado en promesas:
 *
 *  FUTURE  (0x00 0x29): crea un FutureObject en el GC (estado PENDING).
 *                        R0 = GcHandle del future.
 *
 *  AWAIT   (0x00 0x2A): suspende el proceso hasta que el future sea resuelto.
 *                        Si ya esta resuelto, escribe el resultado en R0 y
 * continua. Si sigue PENDING, registra el PID y bloquea (blocking=true); cuando
 * FULFILL/REJECT lo despierte, re-ejecuta AWAIT que encuentra el estado
 * resuelto y retorna el valor.
 *
 *  FULFILL (0x00 0x2B): resuelve el future con un valor (RESOLVED).
 *                        Si hay un proceso esperando (waiter_pid != 0) lo
 * despierta.
 *
 *  REJECT  (0x00 0x2C): rechaza el future con un codigo de error (REJECTED).
 *                        Si hay un proceso esperando (waiter_pid != 0) lo
 * despierta.
 */

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "runtime/scheduler.h"
#include "runtime/runtime.h"
#include "gc/gc_heap.h"
#include "loader/oop_types.h"

namespace runtime {

// =========================================================================
//  0x29  FUTURE  (sin operandos)
// =========================================================================

/**
 * @brief Ejecuta FUTURE: aloca un FutureObject GC en estado PENDING.
 *
 * El GcHandle devuelto en R0 debe pasarse a AWAIT para esperar el resultado
 * o a FULFILL/REJECT para resolverlo desde otro proceso.
 *
 * @param vm    Proceso virtual que ejecuta FUTURE.
 * @param instr Sin operandos (FIXED_2).
 */
void exec_instr_future(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr; // sin operandos

    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    uint64_t idx;
    {
        std::lock_guard<std::mutex> lk(vm_ref.shared_futures_mtx);
        idx = vm_ref.shared_futures.size();
        vm_ref.shared_futures.emplace_back();
        auto &fut = vm_ref.shared_futures.back();
        fut.header.flags = 0;
        fut.header.hash_code = static_cast<uint32_t>(idx);
        fut.header.class_ptr = nullptr;
        fut.state = loader::FutureState::PENDING;
        fut.result = 0;
        // CRITICO: el sentinel "no waiter" debe ser UINT64_MAX, NO 0,
        // porque el primer proceso (main) tiene PID encoded = 0 y
        // 0==0 lo confundiria con "no waiter".  Con UINT64_MAX como
        // sentinel, cualquier PID valido (incluido 0) se distingue.
        fut.waiter_pid = UINT64_MAX;
    }
    vm->registers.regs[0].qword(idx);
}

// =========================================================================
//  0x2A  AWAIT  r_fut
// =========================================================================

/**
 * @brief Ejecuta AWAIT: suspende el proceso hasta que el future se resuelva.
 *
 * Primera ejecucion (state == PENDING):
 *   Registra el PID del proceso llamante en waiter_pid y activa blocking=true.
 *   El PC no avanza; AWAIT sera re-ejecutado cuando FULFILL/REJECT lo
 * despierte.
 *
 * Re-ejecucion (state != PENDING):
 *   Escribe fut->result en R0 y retorna normalmente.
 *
 * @param vm    Proceso virtual que ejecuta AWAIT.
 * @param instr reg1 = GcHandle del FutureObject.
 */
void exec_instr_await(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_fut = instr.data_instruction.reg_data.reg1;
    const uint64_t h = vm->registers.regs[r_fut].qword();

    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    bool is_pending = false;
    uint64_t result_val = 0;
    {
        std::lock_guard<std::mutex> lk(vm_ref.shared_futures_mtx);
        if (h >= vm_ref.shared_futures.size()) {
            vm->registers.regs[0].qword(0); // handle invalido
            return;
        }
        loader::FutureObject &fut = vm_ref.shared_futures[h];
        if (fut.state == loader::FutureState::PENDING) {
            // registrar al waiter DENTRO del lock para evitar race con
            // fulfill (que lee waiter_pid bajo el mismo mutex).
            const uint64_t my_pid =
                (static_cast<uint64_t>(vm->pid.scheduler_id) << 32) |
                static_cast<uint64_t>(vm->pid.local_pid);
            fut.waiter_pid = my_pid;
            is_pending = true;
        } else {
            result_val = fut.result;
        }
    }

    if (is_pending) {
        // bloquear el proceso sin avanzar el PC (AWAIT sera re-ejecutado)
        vm->decoded_ptr->flags_info.blocking = true;
        vm->scheduler.on_event(EVT_IO_WAIT); // transicion a WAIT_IO
        return;
    }

    // future ya resuelto: escribir resultado en R0 y continuar.
    // CRITICO: si la primera llamada a await (icache miss) seteo
    // blocking=true por estado PENDING, ese flag queda CACHEADO en
    // la entrada de icache.  En la re-ejecucion (post-wake)
    // decode_instruction devuelve cache HIT con el blocking=true
    // viejo; tras leer el resultado DEBEMOS limpiar el flag para
    // que execute_instruction devuelva EVT_EXEC_DONE y el scheduler
    // continue al siguiente opcode.  Mismo patron que el fix de
    // msgrecv.
    vm->decoded_ptr->flags_info.blocking = false;
    vm->registers.regs[0].qword(result_val);
}

// =========================================================================
//  0x2B  FULFILL  r_fut, r_val
// =========================================================================

/**
 * @brief Ejecuta FULFILL: resuelve un future con un valor.
 *
 * Escribe state=RESOLVED y result=r_val en el FutureObject.
 * Si habia un proceso esperando (waiter_pid != 0) llama a make_ready() para
 * despertarlo y que re-ejecute su AWAIT.
 *
 * @param vm    Proceso virtual que ejecuta FULFILL.
 * @param instr reg1 = GcHandle del FutureObject, reg2 = valor de resolucion.
 */
void exec_instr_fulfill(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_fut =
        instr.data_instruction.reg_data.reg1; // handle del future
    const uint8_t r_val =
        instr.data_instruction.reg_data.reg2; // valor de resolucion

    const uint64_t h = vm->registers.regs[r_fut].qword();
    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    loader::FutureObject *fut = nullptr;
    uint64_t waiter = UINT64_MAX;
    const uint64_t val = vm->registers.regs[r_val].qword();
    {
        std::lock_guard<std::mutex> lk(vm_ref.shared_futures_mtx);
        if (h >= vm_ref.shared_futures.size()) return;
        fut = &vm_ref.shared_futures[h];
        fut->state = loader::FutureState::RESOLVED;
        fut->result = val;
        waiter = fut->waiter_pid;
        fut->waiter_pid = UINT64_MAX; // limpiar para evitar wake repetido
    }
    if (waiter != UINT64_MAX) {
        GlobalPID target;
        target.scheduler_id = static_cast<uint32_t>(waiter >> 32);
        target.local_pid = static_cast<uint64_t>(waiter & 0xFFFFFFFF);
        vm_ref.make_ready(target);
    }
}

// =========================================================================
//  0x2C  REJECT  r_fut, r_err
// =========================================================================

/**
 * @brief Ejecuta REJECT: rechaza un future con un codigo de error.
 *
 * Escribe state=REJECTED y result=r_err en el FutureObject.
 * Si habia un proceso esperando (waiter_pid != 0) llama a make_ready() para
 * despertarlo y que obtenga el codigo de error desde su AWAIT.
 *
 * @param vm    Proceso virtual que ejecuta REJECT.
 * @param instr reg1 = GcHandle del FutureObject, reg2 = codigo de error.
 */
void exec_instr_reject(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_fut =
        instr.data_instruction.reg_data.reg1; // handle del future
    const uint8_t r_err =
        instr.data_instruction.reg_data.reg2; // codigo de error

    const uint64_t h = vm->registers.regs[r_fut].qword();
    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    loader::FutureObject *fut = nullptr;
    uint64_t waiter = UINT64_MAX;
    const uint64_t err = vm->registers.regs[r_err].qword();
    {
        std::lock_guard<std::mutex> lk(vm_ref.shared_futures_mtx);
        if (h >= vm_ref.shared_futures.size()) return;
        fut = &vm_ref.shared_futures[h];
        fut->state = loader::FutureState::REJECTED;
        fut->result = err;
        waiter = fut->waiter_pid;
        fut->waiter_pid = UINT64_MAX;
    }
    if (waiter != UINT64_MAX) {
        GlobalPID target;
        target.scheduler_id = static_cast<uint32_t>(waiter >> 32);
        target.local_pid = static_cast<uint64_t>(waiter & 0xFFFFFFFF);
        vm_ref.make_ready(target);
    }
}

// =========================================================================
//  0x67  FULFILLHLT  r_fut, r_val   (fulfill + hlt fusionados)
// =========================================================================

/**
 * @brief Ejecuta FULFILLHLT: resuelve future + termina el proceso.
 *
 * Operacion atomic equivalente a la secuencia:
 *   fulfill r_fut, r_val   ; setea RESOLVED + wake waiter
 *   hlt                     ; transiciona el proceso a HALT
 *
 * Usado por el helper sintetico de @Async para que cada `return X`
 * del body genere 1 instruccion VM en lugar de 2 en el path critico.
 * Sin coste runtime extra: solo amortiza el decode + advance PC del
 * hlt separado (1 byte extra de bytecode + 1 dispatch del decoder).
 *
 * @param vm    Proceso virtual que ejecuta FULFILLHLT.
 * @param instr reg1 = handle del FutureObject, reg2 = valor de resolucion.
 */
void exec_instr_fulfillhlt(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_fut = instr.data_instruction.reg_data.reg1;
    const uint8_t r_val = instr.data_instruction.reg_data.reg2;

    const uint64_t h = vm->registers.regs[r_fut].qword();
    const uint64_t val = vm->registers.regs[r_val].qword();

    //   misma logica que exec_instr_fulfill (resolver future +
    // capturar waiter bajo lock).
    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    uint64_t waiter = UINT64_MAX;
    {
        std::lock_guard<std::mutex> lk(vm_ref.shared_futures_mtx);
        if (h < vm_ref.shared_futures.size()) {
            loader::FutureObject &fut = vm_ref.shared_futures[h];
            fut.state = loader::FutureState::RESOLVED;
            fut.result = val;
            waiter = fut.waiter_pid;
            fut.waiter_pid = UINT64_MAX;
        }
    }
    // Wake del waiter FUERA del lock para no contender.
    if (waiter != UINT64_MAX) {
        GlobalPID target;
        target.scheduler_id = static_cast<uint32_t>(waiter >> 32);
        target.local_pid = static_cast<uint64_t>(waiter & 0xFFFFFFFF);
        vm_ref.make_ready(target);
    }

    //   misma logica que exec_instr_hlt.  Notificar HALT al
    // scheduler ANTES de marcar blocking, mismo orden que hlt regular.
    vm->scheduler.on_event(EVT_HALT);
    vm->decoded_ptr->flags_info.blocking = true;
}

} // namespace runtime
