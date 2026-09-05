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
 * @file exec_instruction_sync.cpp
 * @brief Implementacion de las instrucciones de sincronizacion de VestaVM.
 *
 * Implementa monitores reentrantes (como synchronized de Java) sobre objetos
 * GC:
 *
 *  MONENTER (0x00 0x35): adquiere el monitor del objeto GC.
 *                         Si esta libre o ya lo posee el proceso: lock_depth++.
 *                         Si lo posee otro: el proceso se bloquea y re-ejecuta
 * MONENTER cuando sea despertado por MONEXIT.
 *
 *  MONEXIT  (0x00 0x36): libera el monitor.  Si lock_depth llega a 0, despierta
 * al primer proceso de la cola de espera.
 *
 *  MONWAIT  (0x00 0x37): libera completamente el monitor (lock_depth -> 0) y
 * suspende el proceso en la cola de espera del objeto.  El proceso debe llamar
 * MONENTER de nuevo tras ser despertado.
 *
 *  MONNOTI  (0x00 0x38): despierta exactamente un proceso de la cola de espera.
 *
 *  MONNOTA  (0x00 0x39): despierta todos los procesos de la cola de espera.
 *
 * Estado del monitor en ObjectHeader (24 bytes):
 *   owner_pid  (uint32_t) -- local_pid del proceso propietario; 0 = libre.
 *   lock_depth (uint16_t) -- contador de bloqueos reentrantes.
 *
 * PID codificado: (scheduler_id << 32) | local_pid  (uint64_t).
 */

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "runtime/scheduler.h"
#include "runtime/runtime.h"
#include "gc/gc_heap.h"
#include "loader/oop_types.h"
#include "debug/debugger.h" // Debugger::on_monitor_contention

namespace runtime {

// -------------------------------------------------------------------------
// Utilitario: codificar/decodificar PID del proceso actual
// -------------------------------------------------------------------------

/** @brief Codifica el PID del proceso como uint64_t para almacenarlo en colas.
 */
static inline uint64_t encode_pid(const ProcessVM *vm) {
    return (static_cast<uint64_t>(vm->pid.scheduler_id) << 32) |
           static_cast<uint64_t>(vm->pid.local_pid);
}

/** @brief Decodifica un PID codificado y llama make_ready en el scheduler
 * padre. */
static inline void wake_pid(ProcessVM *vm, uint64_t encoded_pid) {
    // B4.3 fix: sentinel "no waiter" es UINT64_MAX, NO 0.  PID 0
    // (sched=0, local=0) es valido (main process en scheduler 0).
    // Mismo fix que A.7.3 fase 1 para futures.
    if (encoded_pid == UINT64_MAX) return;
    GlobalPID target;
    target.scheduler_id = static_cast<uint32_t>(encoded_pid >> 32);
    target.local_pid = static_cast<uint64_t>(encoded_pid & 0xFFFFFFFFu);
    vm->scheduler.vm_reference.make_ready(target);
}

// B4.3: wake + set condvar_notified.  Usado por monnoti/monnota
// para que el receiver sepa "fui notificado" y monwait no re-bloquee.
static inline void wake_pid_with_notify(ProcessVM *vm, uint64_t encoded_pid) {
    if (encoded_pid == UINT64_MAX) return;
    GlobalPID target;
    target.scheduler_id = static_cast<uint32_t>(encoded_pid >> 32);
    target.local_pid = static_cast<uint64_t>(encoded_pid & 0xFFFFFFFFu);
    // Resolver el ProcessVM target y set su flag ANTES de make_ready.
    // make_ready encolara el proceso; cuando vuelva a ejecutar monwait,
    // el flag se consumira via exchange.
    auto &vmr = vm->scheduler.vm_reference;
    if (target.scheduler_id < vmr.schedulers.size()) {
        auto &sched = *vmr.schedulers[target.scheduler_id];
        auto it = sched.pid_index.find(target);
        if (it != sched.pid_index.end() && it->second) {
            it->second->condvar_notified.store(true, std::memory_order_release);
        }
    }
    vmr.make_ready(target);
}

// -------------------------------------------------------------------------
// MONENTER (0x35)
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta MONENTER: adquiere el monitor del objeto GC.
 *
 * Llama a gc_heap.monitor_try_acquire(handle, local_pid):
 *   - Retorna true  -> monitor adquirido; continua normalmente.
 *   - Retorna false -> monitor ocupado; el proceso se registra en la cola de
 *     espera y se bloquea (blocking=true) sin avanzar el PC.
 *     Cuando MONEXIT lo despierte, MONENTER se re-ejecuta.
 *
 * @param vm    Proceso virtual que ejecuta MONENTER.
 * @param instr reg1 = GcHandle del objeto cuyo monitor se quiere adquirir.
 */
void exec_instr_monenter(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_handle = instr.data_instruction.reg_data.reg1;
    const auto h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_handle].qword());

    if (vm->gc_heap.monitor_try_acquire(h, encode_pid(vm))) {
        // B4.3 fix: limpiar el flag blocking cacheado en icache.  Si
        // la llamada PREVIA a monenter (mismo PC) bloqueo, el decoded
        // entry tiene blocking=true persistente.  Sin reset, el
        // scheduler ve blocking=true tras EXEC y vuelve a WAIT_IO,
        // entrando en bucle infinito.  Mismo patron que await/msgrecv.
        vm->decoded_ptr->flags_info.blocking = false;
        return; // monitor adquirido correctamente
    }

    // monitor ocupado: registrar en la cola de espera y bloquear
    vm->gc_heap.monitor_add_waiter(h, encode_pid(vm));
    // Hook del debugger: notificar contention al monitor.  Sin overhead
    // si break_on_mon_=false (atomic load + branch).
    if (vm->scheduler.vm_reference.debugger) {
        // Leer owner_pid del ObjectHeader del objeto referenciado (offset
        // 16 dentro del header v2: class_ptr@0, flags@8, hash@12, owner@16).
        uint64_t owner_pid = 0;
        uint8_t *payload = vm->gc_heap.deref(h);
        if (payload) {
            uint8_t *header = payload - 24; // ObjectHeader v2 size = 24
            owner_pid = *reinterpret_cast<uint32_t *>(header + 16);
        }
        vm->scheduler.vm_reference.debugger->on_monitor_contention(
            vm->pid.local_pid, static_cast<uint64_t>(h), owner_pid);
    }
    vm->decoded_ptr->flags_info.blocking = true; // bloquear sin avanzar PC
    vm->scheduler.on_event(EVT_IO_WAIT);         // transicion al estado WAIT_IO
}

// -------------------------------------------------------------------------
// MONEXIT (0x36)
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta MONEXIT: libera el monitor del objeto GC.
 *
 * Decrementa lock_depth.  Si llega a 0, despierta al primer proceso de la
 * cola de espera (si la hay) llamando make_ready().
 *
 * @param vm    Proceso virtual que ejecuta MONEXIT.
 * @param instr reg1 = GcHandle del objeto cuyo monitor se libera.
 */
void exec_instr_monexit(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_handle = instr.data_instruction.reg_data.reg1;
    const auto h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_handle].qword());

    const uint64_t next = vm->gc_heap.monitor_release(h, encode_pid(vm));
    if (next != UINT64_MAX) {
        wake_pid(vm, next); // despertar al siguiente proceso en cola
    }
}

// -------------------------------------------------------------------------
// MONWAIT (0x37)
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta MONWAIT: libera completamente el monitor y suspende el
 * proceso.
 *
 * Libera el monitor independientemente de lock_depth (vaciado completo).
 * El proceso queda en la cola de espera del monitor.  Cuando MONNOTI o
 * MONNOTA lo despierten, el proceso debe llamar MONENTER de nuevo para
 * readquirir el lock antes de operar sobre el objeto protegido.
 *
 * @param vm    Proceso virtual que ejecuta MONWAIT.
 * @param instr reg1 = GcHandle del objeto.
 */
void exec_instr_monwait(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_handle = instr.data_instruction.reg_data.reg1;
    const auto h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_handle].qword());

    // B4.3: si fuimos notificados (monnoti/monnota nos popeo de CONDVAR
    // y nos hizo wake), NO re-bloqueamos.  Limpiar el flag y avanzar
    // PC normalmente.  Mismo patron que await consulta el state del
    // future tras wake.
    if (vm->condvar_notified.exchange(false, std::memory_order_acq_rel)) {
        vm->decoded_ptr->flags_info.blocking = false;
        return;
    }

    // limpiar el monitor directamente (forzar lock_depth = 0)
    uint8_t *ptr = vm->gc_heap.deref(h);
    if (ptr != nullptr) {
        auto *hdr = reinterpret_cast<loader::ObjectHeader *>(ptr);
        const uint64_t mw = hdr->monitor_word.load(std::memory_order_acquire);
        if (loader::monitor_owner(mw) ==
            (encode_pid(vm) & loader::MONITOR_OWNER_MASK)) {
            // despertar al proximo en la cola de MONENTER antes de ceder el
            // lock
            uint64_t next = vm->gc_heap.monitor_pop_waiter(h);
            // monitor_word a cero libera el monitor (owner=0, depth=0).
            hdr->monitor_word.store(0, std::memory_order_release);
            if (next != UINT64_MAX) {
                wake_pid(vm,
                         next); // si alguien esperaba en MONENTER, despertarlo
            }
        }
    }

    // B4.3 fix: registrar en la cola CONDVAR (separada de MONITOR).
    // Si usaramos MONITOR, habria race: el notifier popearia desde
    // la misma cola que usa MONENTER, mezclando semanticas (alguien
    // bloqueado en MONENTER seria popeado por NOTIFY).  Peor aun:
    // si pop_waiter retorna empty justo antes de que add_waiter
    // termine, NOTIFY perderia el wakeup.  Las dos colas separan
    // los dos protocolos.
    vm->gc_heap.condvar_add_waiter(h, encode_pid(vm));
    vm->decoded_ptr->flags_info.blocking = true; // suspender el proceso
    vm->scheduler.on_event(EVT_IO_WAIT);
}

// -------------------------------------------------------------------------
// MONNOTI (0x38)
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta MONNOTI: despierta un proceso de la cola de espera del
 * monitor.
 *
 * Extrae el primer PID de la cola de espera del objeto y llama make_ready.
 * No transfiere la propiedad del monitor; el proceso despertado debe llamar
 * MONENTER para adquirirlo.
 *
 * @param vm    Proceso virtual que ejecuta MONNOTI.
 * @param instr reg1 = GcHandle del objeto.
 */
void exec_instr_monnoti(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_handle = instr.data_instruction.reg_data.reg1;
    const auto h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_handle].qword());

    // B4.3 fix: NOTIFY pop desde cola CONDVAR (donde MONWAIT registra
    // los waiters).  La cola MONITOR es solo para procesos bloqueados
    // en MONENTER esperando el lock.
    const uint64_t next = vm->gc_heap.condvar_pop_waiter(h);
    wake_pid_with_notify(vm, next); // set condvar_notified + make_ready
}

// -------------------------------------------------------------------------
// MONNOTA (0x39)
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta MONNOTA: despierta todos los procesos de la cola de espera.
 *
 * Extrae todos los PIDs de la cola de espera del objeto y llama make_ready
 * en cada uno.  La cola queda vacia tras la llamada.
 *
 * @param vm    Proceso virtual que ejecuta MONNOTA.
 * @param instr reg1 = GcHandle del objeto.
 */
void exec_instr_monnota(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_handle = instr.data_instruction.reg_data.reg1;
    const auto h =
        static_cast<gc::GcHandle>(vm->registers.regs[r_handle].qword());

    // B4.3 fix: notifyAll desde cola CONDVAR (mismo razonamiento que
    // monnoti).  MONITOR es solo para monenter waiters.
    std::vector<uint64_t> waiters = vm->gc_heap.condvar_pop_all_waiters(h);
    for (uint64_t pid : waiters) {
        wake_pid_with_notify(vm, pid); // set condvar_notified + wake
    }
}

} // namespace runtime
