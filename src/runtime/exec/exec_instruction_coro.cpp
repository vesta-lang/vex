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
 * @file exec_instruction_coro.cpp
 * @brief Implementacion de las instrucciones de corutinas y fibras de VestaVM.
 *
 * Implementa dos modelos de concurrencia cooperativa:
 *
 * Modelo A (scheduler-aware):
 *   - YIELD  (0x00 0xEC): el proceso cede voluntariamente el quantum actual.
 *   - RESUME (0x00 0xED): reactiva un proceso en BLOCKED/WAITING.
 *   - SPAWN  (0x00 0xEE): crea un nuevo ProcessVM a partir de una direccion.
 *
 * Modelo B (stack-switching, fibras):
 *   - SWAPCTX (0x00 0xEF): intercambio de contexto entre dos fibras sin
 *     intervencion del scheduler.  El contexto (152 bytes) se almacena en
 *     memoria VM: [0..7]=PC, [8..15]=SP, [16..23]=BP, [24..151]=R0..R15.
 */
#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "loader/loader.h" // Loader::copy_executables_to en spawn
#include "runtime/scheduler.h"
#include "runtime/runtime.h"
#include "runtime/exception_runtime.h" // throw_fatalf en spawnargs (argc > 12)

namespace runtime {

// =========================================================================
// YIELD  (0x00 0xEC)
// =========================================================================

/**
 * @brief Ejecuta la instruccion YIELD.
 *
 * Decrementa reductions_remaining a cero para que el scheduler detecte el
 * fin del quantum en el proximo ciclo y elija otro proceso.  La instruccion
 * solo avanza el PC (did_jump = false); el cambio de contexto lo hace el
 * scheduler cuando comprueba el contador de reducciones.
 *
 * @param vm    Proceso virtual que ejecuta YIELD.
 * @param instr Instruccion descodificada (sin operandos utiles).
 */
void exec_instr_yield(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr;                  // sin operandos
    vm->reductions_remaining = 0; // forzar fin de quantum en el proximo chequeo
}

// =========================================================================
// RESUME  (0x00 0xED)
// =========================================================================

/**
 * @brief Ejecuta la instruccion RESUME.
 *
 * Lee el PID del proceso a reactivar desde el registro operando (reg1) y
 * llama a vm->make_ready() para insertarlo en la cola del scheduler.  El
 * proceso llamante continua ejecutandose sin bloquearse.
 *
 * @param vm    Proceso virtual que ejecuta RESUME.
 * @param instr reg1 = indice del registro GP que contiene el PID codificado.
 */
void exec_instr_resume(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t reg_idx =
        instr.data_instruction.reg_data.reg1; // registro con el PID
    const uint64_t raw_pid =
        vm->registers.regs[reg_idx].qword(); // valor del PID codificado

    // el PID codificado lleva scheduler_id en los 32 bits altos y pid local en
    // los bajos
    GlobalPID target_pid;
    target_pid.scheduler_id = static_cast<uint32_t>(raw_pid >> 32);
    target_pid.local_pid = static_cast<uint64_t>(raw_pid & 0xFFFFFFFF);

    // reactivar el proceso en la VM propietaria del scheduler
    vm->scheduler.vm_reference.make_ready(target_pid);
}

// =========================================================================
// SPAWN  (0x00 0xEE)
// =========================================================================

/**
 * @brief Ejecuta la instruccion SPAWN.
 *
 * Crea un nuevo ProcessVM en el mismo scheduler, establece su PC al valor
 * del registro operando y lo pone en estado READY.  El PID del nuevo proceso
 * se codifica en 64 bits (scheduler_id << 32 | local_pid) y se almacena en
 * el registro R0 del proceso llamante.
 *
 * El nuevo proceso hereda la memoria virtual del scheduler (espacio compartido
 * del loader); su pila se inicializa a cero (SP = BP = 0 hasta que el proceso
 * configurne su propio marco de pila con ENTER o similar).
 *
 * @param vm    Proceso virtual que ejecuta SPAWN.
 * @param instr reg1 = registro GP que contiene la direccion de inicio del
 * proceso.
 */
void exec_instr_spawn(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t reg_idx =
        instr.data_instruction.reg_data.reg1; // registro con fn_addr
    const uint64_t fn_addr =
        vm->registers.regs[reg_idx].qword(); // direccion de inicio

    // si la VM tiene mas de un scheduler, distribuir
    // hijos round-robin entre TODOS los schedulers (paralelismo
    // OS-thread real).  Si solo hay uno, mantener el comportamiento
    // single-scheduler (modo cooperativo, sin overhead de cross-thread
    // IPC).  El usuario controla el modo via `--schedulers N`.
    //
    // El IPC cross-scheduler ya es thread-safe: state es atomic + CAS,
    // make_ready usa wake_pending double-check (rev2), y msgsend
    // siempre invoca make_ready en lugar de inspeccionar state.
    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    GlobalPID new_pid =
        (vm_ref.schedulers.size() > 1)
            ? vm_ref.spawn_process() // round-robin multi-thread
            : vm->scheduler.spawn(); // single-thread cooperativo

    // localizar el nuevo proceso por PID en el indice del scheduler propietario
    Scheduler *owner_sched = vm_ref.schedulers[new_pid.scheduler_id].get();
    ProcessVM *child = owner_sched->pid_index.at(new_pid);

    // establecer PC del proceso hijo a la direccion solicitada
    child->registers.rip.qword(fn_addr);
    // Fondo de la cadena del hijo: su cuerpo, no el main (ver entry_pc).
    child->entry_pc = fn_addr;

    // Inicializar RSP/RBP del hijo para que pueda ejecutar `enter N` y
    // operaciones de pila.  Cada hijo recibe una region unica derivada
    // de su local_pid: 1 MiB de separacion entre hijos.
    const uint64_t stack_base =
        0x10000000ULL + (new_pid.local_pid % 0x1000ULL) * 0x100000ULL;
    child->registers.stack_pointer.qword(stack_base);
    child->registers.base_pointer.qword(stack_base);
    // Limites para el GC stack scanner conservativo del proceso hijo:
    // el sweep solo escanea el rango [stack_low_water, stack_high] en
    // busca de roots vivas, ahorrando tiempo cuando la pila no esta
    // llena.  Inicializamos ambos al base; @c subsp actualiza
    // @c stack_low_water con cada empuje real.
    child->stack_high = stack_base;
    child->stack_low_water = stack_base;

    // CRITICO: el child tiene su propio vm_mem privado (vacio) porque
    // ProcessVM aisla la memoria entre procesos.  Sin copia del codigo
    // del parent, el child intentaria decodificar bytecode al PC dado
    // y solo encontraria zeros (extended opcode 0x00 0x00 = edmw4
    // sin exec_fn -> tratado como invalido -> halt silente).
    //
    // Replicamos via el Loader la MISMA copia que hizo load_executable
    // al cargar el binario: itera todos los executables cargados y
    // cada una de sus secciones, copiando bytecode al rango de VAs
    // original.  Asi copiamos EXACTAMENTE lo que el loader cargo (sin
    // depender de un tamano fijo arbitrario), y soportamos modulos
    // adicionales cargados dinamicamente con @c loadmodule.
    vm_ref.loader_public.copy_executables_to(*child, vm);

    // activar el proceso: pasa de NEW a READY y se inserta en la cola
    // del scheduler propietario.  En multi-scheduler, VM::make_ready
    // tambien dispara sem.release() del scheduler propietario para
    // sacarlo del semaforo si estaba esperando trabajo.
    vm_ref.make_ready(new_pid);

    // devolver el PID codificado al proceso padre en R0
    const uint64_t encoded_pid =
        (static_cast<uint64_t>(new_pid.scheduler_id) << 32) |
        static_cast<uint64_t>(new_pid.local_pid & 0xFFFFFFFF);
    vm->registers.regs[0].qword(encoded_pid); // resultado en R0
}

// =========================================================================
// SPAWN_ON (0x00 0x58) - spawn con hint de scheduler
// =========================================================================

/**
 * @brief Implementa la instruccion SPAWN_ON con hint explicito de scheduler.
 *
 * Es la version "controlada" de SPAWN: el programador Vesta puede dictar
 * en que OS-thread (scheduler) corre el hijo.  Sirve a:
 *   - `spawn here { body }`  -> hint = -1 -> mismo scheduler que el padre.
 *   - `spawn on(N) { body }` -> hint = N  -> scheduler N % num_schedulers.
 *
 * Resto de inicializacion identica a SPAWN: PC, RSP/RBP separados, copia
 * de bytecode con @c Loader::copy_executables_to, @c make_ready y retorno
 * del PID encoded en R0.
 *
 * @param vm    Proceso virtual que ejecuta SPAWN_ON.
 * @param instr reg1 = registro con direccion de inicio; reg2 = registro
 *              con scheduler hint (interpretado como int64 signed).
 */
void exec_instr_spawn_on(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t reg_fn = instr.data_instruction.reg_data.reg1;
    const uint8_t reg_hint = instr.data_instruction.reg_data.reg2;
    const uint64_t fn_addr = vm->registers.regs[reg_fn].qword();
    const int64_t hint =
        static_cast<int64_t>(vm->registers.regs[reg_hint].qword());

    runtime::VM &vm_ref = vm->scheduler.vm_reference;

    // Resolver scheduler propietario segun hint.
    Scheduler *target_sched = nullptr;
    if (hint < 0) {
        // Here: spawn en el mismo scheduler que el padre (sin overhead
        // cross-thread; util para corutinas cooperativas dentro de un
        // sched aunque el VM tenga --schedulers N>1).
        target_sched = &vm->scheduler;
    } else {
        // Pinned: indice modulo num_schedulers para evitar fuera de rango
        // si el programador escribio un valor mayor que el numero real
        // de schedulers de la VM (configurable via --schedulers N).
        const size_t n = vm_ref.schedulers.size();
        const size_t idx = static_cast<size_t>(hint) % (n == 0 ? 1 : n);
        target_sched = vm_ref.schedulers[idx].get();
    }

    // Crear el proceso en el scheduler elegido (no usar
    // VM::spawn_process porque ese forza round-robin).
    GlobalPID new_pid = target_sched->spawn();
    Scheduler *owner_sched = vm_ref.schedulers[new_pid.scheduler_id].get();
    ProcessVM *child = owner_sched->pid_index.at(new_pid);

    // PC, stack, code copy: idem exec_instr_spawn.
    child->registers.rip.qword(fn_addr);
    // Fondo de la cadena del hijo: su cuerpo, no el main (ver entry_pc).
    child->entry_pc = fn_addr;
    const uint64_t stack_base =
        0x10000000ULL + (new_pid.local_pid % 0x1000ULL) * 0x100000ULL;
    child->registers.stack_pointer.qword(stack_base);
    child->registers.base_pointer.qword(stack_base);
    // Limites para el GC stack scanner conservativo del proceso hijo:
    // el sweep solo escanea el rango [stack_low_water, stack_high] en
    // busca de roots vivas, ahorrando tiempo cuando la pila no esta
    // llena.  Inicializamos ambos al base; @c subsp actualiza
    // @c stack_low_water con cada empuje real.
    child->stack_high = stack_base;
    child->stack_low_water = stack_base;

    vm_ref.loader_public.copy_executables_to(*child, vm);
    vm_ref.make_ready(new_pid);

    const uint64_t encoded_pid =
        (static_cast<uint64_t>(new_pid.scheduler_id) << 32) |
        static_cast<uint64_t>(new_pid.local_pid & 0xFFFFFFFF);
    vm->registers.regs[0].qword(encoded_pid);
}

// =========================================================================
// SPAWNARGS (0x00 0x66) - spawn que copia R1..R[R15] del padre al child
// =========================================================================

/**
 * @brief Implementa @c spawnargs r_pc: spawn + copy de regs (calling conv
 * CALLVM).
 *
 * Identico a @c exec_instr_spawn salvo que ANTES de @c make_ready copia
 * los regs R1..R[R15] del padre a los mismos slots del child.  Calling
 * convention identica a CALLVM: argc en R15 (rango 0..12), args en
 * R1..R12.  Permite a @Async (lower_async_function) eliminar la
 * serializacion via msgsend/msgrecv: pasamos los args directamente por
 * los registros del proceso, ahorrando ~26 instr VM por @Async call y
 * el lock del mailbox.
 *
 * El child encuentra los params en sus regs sin necesidad de decode +
 * deserializacion en el body.  R15 del padre se preserva (no se copia
 * porque sino el child interpretaria su contenido como argc, conflicto).
 */
void exec_instr_spawnargs(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t reg_idx = instr.data_instruction.reg_data.reg1;
    const uint64_t fn_addr = vm->registers.regs[reg_idx].qword();
    const uint64_t argc = vm->registers.regs[R15].qword();

    // Validar argc: max 12 (R1..R12 segun calling convention).
    if (argc > 12) {
        throw_fatalf(vm, FATAL_ILLEGAL_INSTRUCTION,
                     "spawnargs: argc=%llu excede el maximo de 12 args",
                     static_cast<unsigned long long>(argc));
        return;
    }

    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    GlobalPID new_pid = (vm_ref.schedulers.size() > 1) ? vm_ref.spawn_process()
                                                       : vm->scheduler.spawn();
    Scheduler *owner_sched = vm_ref.schedulers[new_pid.scheduler_id].get();
    ProcessVM *child = owner_sched->pid_index.at(new_pid);

    // PC, stack, code copy: idem spawn.
    child->registers.rip.qword(fn_addr);
    // Fondo de la cadena del hijo: su cuerpo, no el main (ver entry_pc).
    child->entry_pc = fn_addr;
    const uint64_t stack_base =
        0x10000000ULL + (new_pid.local_pid % 0x1000ULL) * 0x100000ULL;
    child->registers.stack_pointer.qword(stack_base);
    child->registers.base_pointer.qword(stack_base);
    child->stack_high = stack_base;
    child->stack_low_water = stack_base;
    vm_ref.loader_public.copy_executables_to(*child, vm);

    // CRITICO: copiar args ANTES de make_ready, para que el child los
    // vea desde su primer ciclo de instruccion (sin race con el
    // scheduler).  Copiamos R1..R[argc] (no incluimos R0 que sera el
    // PID encoded del child que el padre recibe; el child no lo
    // necesita).  R15 del child queda en 0 (default), asi el child no
    // hereda el "argc" del padre.
    for (uint64_t i = 1; i <= argc && i <= 12; ++i) {
        child->registers.regs[i].qword(vm->registers.regs[i].qword());
    }

    // Activar el child y devolver PID encoded al padre en R0.
    vm_ref.make_ready(new_pid);
    const uint64_t encoded_pid =
        (static_cast<uint64_t>(new_pid.scheduler_id) << 32) |
        static_cast<uint64_t>(new_pid.local_pid & 0xFFFFFFFF);
    vm->registers.regs[0].qword(encoded_pid);
}

// =========================================================================
// SWAPCTX  (0x00 0xEF)
// =========================================================================

/**
 * @brief Ejecuta la instruccion SWAPCTX (intercambio de contexto de fibra).
 *
 * Operacion atomica de dos fases:
 *   1. Guarda el contexto actual en el buffer VM apuntado por reg2.
 *   2. Carga el contexto desde el buffer VM apuntado por reg1.
 *
 * El PC guardado apunta a la instruccion siguiente a SWAPCTX para que la
 * fibra reanudada continue en el punto correcto.
 *
 * Layout del buffer de contexto (152 bytes), en memoria del ANFITRION:
 *   Offset  0: PC   (8 bytes, uint64)
 *   Offset  8: SP   (8 bytes, uint64)
 *   Offset 16: BP   (8 bytes, uint64)
 *   Offset 24: R0   (8 bytes, uint64) ... R15 (offset 24 + 15*8 = 144)
 *
 * Los dos buffers son punteros HOST, igual que en @c atomicld / @c atomicst /
 * @c atomiccas / @c atomicadd (0xA9-0xAC).  Antes exigian direccion VM, lo que
 * ataba las fibras a la memoria de la VM: sus pilas y contextos son variables
 * globales, y el storage de un global vive en memoria host (seccion `gdata`).
 * Con host_ptr el mismo codigo Vesta vale en interprete, JIT y AOT -- en AOT el
 * context switch ya era nativo sobre memoria host.  De paso es mas rapido: 19
 * accesos directos por conmutacion en vez de 19 traducciones por el TLB.
 *
 * @param vm    Proceso virtual que ejecuta SWAPCTX.
 * @param instr reg1 = host_ptr del contexto destino (a cargar),
 *              reg2 = host_ptr del contexto origen (a guardar).
 */
void exec_instr_swapctx(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst =
        instr.data_instruction.reg_data.reg1; // reg con addr del ctx destino
    const uint8_t r_src =
        instr.data_instruction.reg_data.reg2; // reg con addr del ctx origen
    const uint64_t dst_addr =
        vm->registers.regs[r_dst].qword(); // host_ptr del ctx destino
    const uint64_t src_addr =
        vm->registers.regs[r_src].qword(); // host_ptr del ctx origen
    // Un contexto nulo no es recuperable: sin PC destino no hay a donde saltar.
    if (dst_addr == 0 || src_addr == 0) {
        throw_fatal(vm, FatalKind::FATAL_NULL_POINTER,
                    "swapctx: contexto nulo (dst o src)");
        return;
    }
    uint64_t *const src_ctx = reinterpret_cast<uint64_t *>(src_addr);
    uint64_t *const dst_ctx = reinterpret_cast<uint64_t *>(dst_addr);

    // ----   guardar contexto actual en src_addr ----

    // PC guardado = PC de la instruccion siguiente (instr.pc + size_instr)
    const uint64_t next_pc = instr.pc + instr.flags_info.size_instr;
    src_ctx[0] = next_pc;                             // PC
    src_ctx[1] = vm->registers.stack_pointer.qword(); // SP
    src_ctx[2] = vm->registers.base_pointer.qword();  // BP

    // guardar R0..R15 en offsets 24..151 (indices 3..18 del qword array)
    for (int i = 0; i < 16; ++i)
        src_ctx[3 + i] = vm->registers.regs[i].qword();

    // ----   cargar contexto desde dst_addr ----

    const uint64_t new_pc = dst_ctx[0]; // PC del destino
    const uint64_t new_sp = dst_ctx[1]; // SP del destino
    const uint64_t new_bp = dst_ctx[2]; // BP del destino

    vm->registers.rip.qword(new_pc);
    vm->registers.stack_pointer.qword(new_sp);
    vm->registers.base_pointer.qword(new_bp);

    // restaurar R0..R15
    for (int i = 0; i < 16; ++i)
        vm->registers.regs[i].qword(dst_ctx[3 + i]);

    // marcar que el PC ya fue actualizado manualmente para que el scheduler
    // no lo incremente automaticamente al final del ciclo EXECUTE
    const_cast<DecodedInstr &>(instr).flags_info.did_jump = true;
}

} // namespace runtime
