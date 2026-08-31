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
 * @file scheduler.cpp                                                         \
 * @brief Implementacion del planificador de procesos de VestaVM.              \
 *                                                                             \
 * Implementa @c Scheduler: asignacion de procesos a hilos nativos, bucle      \
 * principal de planificacion con balance de carga, ganchos de temporalizacion \
 * y transiciones de estado de proceso (READY -> RUNNING -> BLOCKED/DEAD).     \
 */                                                                            \
#include "vx/diag/diag_catalog.h"
#include "runtime/scheduler.h"

#include "runtime/decode_instruction.h"
#include "runtime/exception_runtime.h"
#include "runtime/profile.h" // Sprint D.6 (2026-06-03): PGO counters
#include "distrib/dist_runtime.h"
#include "distrib/dist_debug.h"
#include "runtime/runtime.h"
#include "debug/debugger.h"
#include "jit/interp_jit_bridge.h" // D.3-E: dispatch a jit_entry_fn al iniciar main

#include <csetjmp>
#include <cstdio>

namespace runtime {

/**
 * @brief Convierte en fallo del programa lo que capturo el sistema.
 *
 * Estaba escrito dos veces, palabra por palabra, en los dos sitios que arman la
 * recuperacion.  Duplicado asi, arreglar uno y olvidar el otro es cuestion de
 * tiempo -- y el segundo solo se nota cuando alguien falla por ese camino.
 *
 * El mensaje no se escribe aqui: el TIPO de fallo ya lo cuenta el catalogo en
 * el idioma de quien lee.  Lo unico que se anade es la direccion del acceso,
 * que si aporta, y tambien por catalogo.
 *
 * Devuelve si un `catch` del programa se hizo cargo.  Sin esto, quien recupera
 * daba el proceso por muerto SIEMPRE, asi que un fallo del sistema rodeado de
 * `try` no ejecutaba su `catch`: el programa terminaba sin mensaje y diciendo
 * que todo fue bien.  Peor que no capturarlo, porque el `try` estaba puesto.
 *
 * @param p Proceso que fallo.
 * @return true si el fallo se convirtio en excepcion y alguien la atrapo -- el
 *         proceso SIGUE VIVO en el `catch` y no hay que cerrarlo.
 */
static bool lanzar_fallo_del_sistema(runtime::ProcessVM *p) {
    /* Que haya un `try` activo es lo que decide si esto puede terminar en un
     * `catch`; se mira ANTES porque `throw_fatal` consume la pila de marcos. */
    const bool hay_try = (p->exc_frame_stack != nullptr);
    /* Y que el proceso salga sin error es lo que confirma que el salto al
     * handler ocurrio: la ruta sin capturar marca `err_thread`. */
    auto atrapado = [&]() {
        return hay_try && p->err_thread == runtime::THREAD_NO_ERROR;
    };
    if (p->pending_av_kind == 1 || p->pending_av_kind == 2) {
        runtime::throw_fatal(p, runtime::FATAL_DIVISION_BY_ZERO, nullptr);
        return atrapado();
    }
    char dir[32];
    std::snprintf(dir, sizeof(dir), "0x%llx",
                  (unsigned long long)p->pending_av_addr);
    /* Los fallos que NO son un acceso invalido se cuentan con la misma calidad
     * que los demas: por catalogo, con su sitio, y por la misma via -- asi
     * heredan la cadena de llamadas y el `fichero:linea` que arma
     * `throw_fatal`. Contar unos bien y otros con un silencio es peor que no
     * contar ninguno: el que calla parece que no ocurrio. */
    if (p->pending_av_kind == 3) {
        // Una instruccion que este procesador no sabe ejecutar.
        const std::string detalle = vx::diag::format("VX7019", {dir});
        runtime::throw_fatal(p, runtime::FATAL_ILLEGAL_INSTRUCTION,
                             detalle.c_str());
        return atrapado();
    }
    if (p->pending_av_kind == 4) {
        // Cualquier otro fallo del sistema: se nombra por su codigo, que es lo
        // unico que se sabe de el, pero se cuenta igual.
        char codigo[32];
        std::snprintf(codigo, sizeof(codigo), "0x%llx",
                      (unsigned long long)p->pending_av_os_code);
        const std::string detalle = vx::diag::format("VX7020", {codigo, dir});
        /* El tipo es el del anfitrion abortandonos: es lo unico honesto que se
         * puede decir cuando el fallo no cae en ninguna de nuestras categorias.
         * El codigo del sistema, que si lo identifica, va en el detalle. */
        runtime::throw_fatal(p, runtime::FATAL_NATIVE_CRASH, detalle.c_str());
        return atrapado();
    }
    const std::string detalle = vx::diag::format("VX7013", {dir});
    runtime::throw_fatal(p, runtime::FATAL_SEGMENTATION_FAULT, detalle.c_str());
    return atrapado();
}

/**
 * @brief Construye el scheduler, lo asocia a la VM indicada e inicializa la
 * FSM.
 *
 * @param id_scheduler Identificador unico del scheduler dentro de su VM.
 * @param vm_reference Referencia a la instancia VM propietaria.
 */
Scheduler::Scheduler(uint32_t id_scheduler, VM &vm_reference)
    : id_scheduler(id_scheduler), vm_reference(vm_reference) {
    init_fsm(); // inicializar la tabla de transiciones antes de aceptar
                // procesos
}

/**
 * @brief Ejecuta un unico paso de la FSM para el proceso activo (instance).
 *
 * Usa "computed goto" para despachar al bloque de codigo del estado actual
 * sin penalizar el predictor de ramas con un switch.  Ejecuta exactamente
 * una transicion y retorna al scheduler.
 *
 * Estados y su comportamiento:
 *   - READY    -> genera EVT_SCHEDULED y salta a RUNNING.
 *   - RUNNING  -> genera EVT_SCHEDULED y salta a DECODE.
 *   - DECODE   -> genera EVT_DECODE_DONE (descodifica) y salta a EXECUTE.
 *   - EXECUTE  -> ejecuta la instruccion y retorna.
 *   - BLOCKED  -> retorna sin hacer nada (espera evento externo).
 *   - WAIT_IO  -> retorna sin hacer nada (espera E/S).
 *   - HALT     -> retorna inmediatamente.
 *   - DEAD     -> retorna inmediatamente.
 *   - NEW      -> retorna sin hacer nada.
 *
 * @param process Proceso sobre el que se ejecutara el paso de la FSM.
 */
void Scheduler::run_fsm_step(ProcessVM *process) {
    // deshabilitar advertencias de GNU sobre "computed goto" (extension de GCC)
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

    /**
     * Tabla de despacho por estado.  Cada entrada es la etiqueta de destino
     * del goto calculado.  El orden debe coincidir exactamente con el enum
     * vm_state. Referencia sobre prediccion de ramas en emuladores:
     *   https://stackoverflow.com/questions/11668090/how-to-deal-with-branch-prediction-when-using-a-switch-case-in-cpu-emulation
     */
    static void *dispatch_table[NUM_STATES] = {
        &&READY_LABEL,   // READY
        &&RUNNING_LABEL, // RUNNING
        &&BLOCKED_LABEL, // BLOCKED
        &&DEAD_LABEL,    // DEAD
        &&DECODE_LABEL,  // DECODE
        &&EXECUTE_LABEL, // EXECUTE
        &&WAIT_IO_LABEL, // WAIT_IO
        &&HALT_LABEL,    // HALT
        &&NEW_LABEL      // NEW
    };

    goto *dispatch_table[instance->state]; // saltar al bloque del estado actual

READY_LABEL:
    on_event(EVT_SCHEDULED);               // READY -> RUNNING
    goto *dispatch_table[instance->state]; // redispachar al nuevo estado

RUNNING_LABEL:
    on_event(EVT_SCHEDULED);               // RUNNING -> DECODE
    goto *dispatch_table[instance->state]; // redispachar al nuevo estado

BLOCKED_LABEL:
    return; // esperar evento externo, no hay nada que hacer

DECODE_LABEL:
    on_event(EVT_DECODE_DONE); // descodificar la instruccion y pasar a EXECUTE
    // una sola llamada cubre decode+execute; 1 llamada = 1 instruccion = 1
    // reduccion
    goto *dispatch_table[instance->state];

EXECUTE_LABEL:
    // hook del debugger ANTES de cada instruccion del slow path.
    // En el caso comun (sin breakpoints ni step) el fast path interno
    // de on_before_exec se resuelve en 2 atomic loads + 1 branch
    // (~1 ns).  Cuando hay breakpoint en el PC actual, esta llamada
    // bloquea el hilo del scheduler hasta que el cliente envie
    // CONTINUE/STEP/NEXT.
    if (vm_reference.debugger != nullptr) {
        vm_reference.debugger->on_before_exec(process);
    }
    // ejecutar la instruccion; si es bloqueante retorna EVT_IO_WAIT, si no
    // EVT_EXEC_DONE
    on_event(execute_instruction(process));
    return;

WAIT_IO_LABEL:
    return; // esperar finalizacion de E/S; el manejador de E/S llamara
            // on_event(EVT_IO_READY)

HALT_LABEL:
DEAD_LABEL:
    return; // estado terminal; el scheduler no volvera a llamar a este metodo

NEW_LABEL:
    return; // proceso recien creado; no ejecutar hasta que make_ready() lo
            // active

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
}

/**
 * @brief Inicializa la tabla de transiciones de la FSM (fsm[][]).
 *
 * Rellena la tabla con el estado por defecto (sin cambio de estado, sin accion)
 * y luego sobreescribe las transiciones validas:
 *
 *   READY  -> EVT_SCHEDULED   -> RUNNING
 *   RUNNING-> EVT_SCHEDULED   -> DECODE
 *   DECODE -> EVT_DECODE_DONE -> EXECUTE  (accion: descodificar instruccion)
 *   EXECUTE-> EVT_EXEC_DONE   -> DECODE
 *   EXECUTE-> EVT_IO_WAIT     -> WAIT_IO
 *   WAIT_IO-> EVT_IO_READY    -> READY
 *   EXECUTE-> EVT_HALT        -> HALT
 *   *      -> EVT_ERROR       -> DEAD
 *   *      -> EVT_YIELD       -> READY
 *   NEW    -> EVT_SCHEDULED   -> READY
 */
void Scheduler::init_fsm() {
    // inicializar toda la tabla con "sin cambio de estado, sin accion"
    for (uint64_t s = 0; s < NUM_STATES; s++) {
        for (uint64_t e = 0; e < NUM_EVENTS; e++) {
            fsm[s][e].next = (vm_state)s; // por defecto el estado no cambia
            fsm[s][e].action = nullptr;   // sin accion por defecto
        }
    }

    // READY -> RUNNING al ser seleccionado por el scheduler
    fsm[READY][EVT_SCHEDULED] = {RUNNING, nullptr};

    // RUNNING -> DECODE: comenzar el ciclo de instruccion
    fsm[RUNNING][EVT_SCHEDULED] = {DECODE, nullptr};

    // DECODE -> EXECUTE: descodificar la instruccion en PC
    fsm[DECODE][EVT_DECODE_DONE] =
        Transition{EXECUTE, [](ProcessVM *vm) {
                       decode_instruction(
                           vm); // descodificar la instruccion apuntada por PC
                   }};

    // EXECUTE -> DECODE: instruccion completada sin bloqueos
    fsm[EXECUTE][EVT_EXEC_DONE] = Transition{DECODE, [](ProcessVM *vm) {
                                                 // la ejecucion avanza el PC en
                                                 // run_loop; aqui no se
                                                 // necesita accion
                                             }};

    // EXECUTE -> WAIT_IO: instruccion bloqueante, esperar finalizacion de E/S
    fsm[EXECUTE][EVT_IO_WAIT] = Transition{WAIT_IO, [](ProcessVM *vm) {
                                               // el subsistema de E/S
                                               // notificara con EVT_IO_READY
                                               // cuando termine
                                           }};

    // WAIT_IO -> READY: la operacion de E/S termino, volver a planificar
    fsm[WAIT_IO][EVT_IO_READY] = Transition{READY, [](ProcessVM *vm) {
                                                // el proceso puede continuar en
                                                // el proximo quantum
                                            }};

    // EXECUTE -> HALT: instruccion HALT encontrada
    fsm[EXECUTE][EVT_HALT] = Transition{HALT, [](ProcessVM *vm) {
                                            // la VM no ejecutara mas
                                            // instrucciones hasta ser
                                            // reiniciada
                                        }};

    // EVT_YIELD: ceder la CPU voluntariamente desde cualquier fase de ejecucion
    fsm[EXECUTE][EVT_YIELD] = {READY,
                               nullptr}; // fin de quantum en EXECUTE -> READY
    fsm[DECODE][EVT_YIELD] = {READY,
                              nullptr}; // fin de quantum en DECODE  -> READY
    fsm[RUNNING][EVT_YIELD] = {READY,
                               nullptr}; // fin de quantum en RUNNING -> READY

    // NEW -> READY al ser activado por make_ready()
    fsm[NEW][EVT_SCHEDULED] = {READY, nullptr};

    // cualquier estado -> DEAD al producirse un error fatal
    for (int s = 0; s < NUM_STATES; s++) {
        fsm[s][EVT_ERROR] = Transition{DEAD, [](ProcessVM *vm) {
                                           // el proceso sera eliminado por el
                                           // scheduler; no hay accion de
                                           // recuperacion
                                       }};
    }
}

/**
 * @brief Indica si hay al menos un proceso vivo en este scheduler.
 * @return true si alive_count > 0.
 */
bool Scheduler::has_alive_processes() const {
    return alive_count > 0; // consulta O(1) del contador atomico
}

/**
 * @brief Destructor: marca todos los procesos como DEAD y libera recursos.
 *
 * Pone la bandera de parada y marca la instruccion activa como bloqueante
 * para evitar que el scheduler intente ejecutar instrucciones durante la
 * destruccion.
 */
Scheduler::~Scheduler() {
    should_kill = true; // indicar al run_loop que debe terminar

    for (auto &p : processes) {
        if (p->decoded_ptr != nullptr) {
            // marcar la instruccion activa como bloqueante para interrumpir
            // ejecucion
            p->decoded_ptr->flags_info.blocking = true;
            p->state = DEAD; // transicionar a estado terminal
        }
    }
}

/**
 * @brief Bucle principal del planificador de procesos.
 *
 * Implementa el ciclo de planificacion cooperativa/preemptiva:
 *   1. Obtiene el proximo proceso listo (schedule_next).
 *   2. Si no hay procesos listos:
 *        - Si no hay procesos vivos en toda la VM, la detiene y sale.
 *        - Si hay procesos vivos en otros schedulers, duerme en el semaforo.
 *   3. En fast-path (sin hooks): decode + execute directo sin FSM completa.
 *   4. En slow-path (con hooks): run_fsm_step completo con todos los eventos.
 *   5. Al agotar reducciones: genera EVT_YIELD y reencola el proceso en READY.
 *
 * @note Este metodo debe ejecutarse en un hilo dedicado del ThreadPool.
 */
// Pragma local: el threaded dispatch usa la extension GCC `&&label`
// (Labels as Values).  Es portable en GCC y Clang, no en MSVC -- el
// proyecto target principal es MinGW-GCC.  `-pedantic-errors` lo
// rechaza por defecto; suprimimos -Wpedantic en este archivo.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

void Scheduler::run_loop() {
    // continuar mientras no se solicite parada y la VM siga activa
    while (!should_kill && vm_reference.vm_running) {
        //  Z.10 ext: STW poll para shared GC.  Si shared_gc_active
        // esta set, ACK + dormir hasta que el GC termine.  Esto es un
        // safe point: estamos entre batches, sin instr en flight, regs
        // y stack del proceso anterior ya commiteados a memoria.
        if (vm_reference.shared_gc_active.load(std::memory_order_acquire)) {
            std::unique_lock<std::mutex> lk(vm_reference.shared_gc_mtx);
            // ACK: incrementar contador y notificar al GC thread.
            vm_reference.shared_gc_acks.fetch_add(1, std::memory_order_acq_rel);
            vm_reference.shared_gc_cv.notify_all();
            // Esperar hasta que GC limpie el flag.
            vm_reference.shared_gc_cv.wait(lk, [&] {
                return !vm_reference.shared_gc_active.load(
                    std::memory_order_acquire);
            });
            // Restar nuestro ACK del contador para que el GC pueda
            // re-usar el contador en una collection futura.
            vm_reference.shared_gc_acks.fetch_sub(1, std::memory_order_acq_rel);
        }
        // Limpiar el TLS del proc en ejecucion al inicio de cada
        // iteracion.  Si entre batches ocurre un AV (codigo del
        // scheduler accediendo memoria invalida), el handler vera
        // TLS=null y delegara al SEH normal en lugar de hacer
        // longjmp a un jmp_buf stale.  Tambien reseteamos
        // av_recovery_active del proc anterior para evitar que un
        // AV entre el sigsetjmp y el set_current_executing_process
        // del proximo batch se desvie a la jmp_buf vieja.
        if (instance != nullptr) {
            instance->av_recovery_active = false;
        }
        set_current_executing_process(nullptr);

        instance = schedule_next(); // obtener el proximo proceso listo

        if (!instance) {
            // no hay procesos listos; verificar si quedan procesos vivos en
            // toda la VM
            if (!vm_reference.has_alive_processes()) {
                if (!vm_reference.vm_persistent) {
                    // perf: notificar al hilo principal
                    // via condition_variable para evitar el polling
                    // sleep_for(1ms) en main.  El predicado del cv es
                    // !vm_running, asi que primero set, luego notify.
                    {
                        std::lock_guard<std::mutex> lk(vm_reference.done_mtx);
                        vm_reference.vm_running = false;
                    }
                    vm_reference.done_cv.notify_all();
                    break; // terminar este scheduler
                }
                // modo persistente (servidor distribuido): esperar a que llegue
                // un proceso
            }

            // hay procesos vivos en otros schedulers (o modo persistente);
            // dormir hasta que haya trabajo
            is_waiting = true;
            sem.acquire(); // bloquear hasta que make_ready() o stop() libere el
                           // semaforo
            is_waiting = false;

            // verificar si nos despertaron porque la VM debe detenerse
            if (should_kill || !vm_reference.vm_running) break;

            // (BUG FIX): tras despertar, NO consumir el
            // proceso aqui con un schedule_next + continue, porque la
            // siguiente iteracion del while exterior llamaria
            // schedule_next OTRA VEZ, encontraria la cola vacia (el
            // proceso ya fue dequeued por la llamada de aqui) y volveria
            // a dormir, perdiendo el proceso recien encolado.  El bucle
            // exterior se encarga del schedule_next.
            continue;
        }

        // ---- JIT entry dispatch para el main del proceso ----
        // Si el proceso tiene jit_entry_fn (Loader eager-compilo main),
        // ejecutarlo UNA VEZ directamente en codigo nativo.  Al retornar,
        // marcar como HALT y continuar.  Esto cierra el gap "main es
        // free function y nunca dispara CALLVIRT".
        if (instance->jit_entry_fn != nullptr && instance->tsc == 0) {
            void *fn_ptr = instance->jit_entry_fn;
            instance->jit_entry_fn = nullptr; /* one-shot */
            instance->state.store(EXECUTE, std::memory_order_relaxed);
            /* Llamar al codigo nativo de main.  R0 al retornar contendra
             * el return value de main (escrito por el RET con VM_ABI).
             * El JIT-eated main puede invocar metodos via CALLVIRT
             * (que en el selector baja a vrt_callvirt -> enter_jit). */
            jit::JitFn jf = reinterpret_cast<jit::JitFn>(fn_ptr);
            /* Armar el setjmp de recuperacion tambien alrededor del
             * jit_entry_fn (no solo del batch interp de mas abajo): asi el
             * watchdog CTPE puede abortar main via longjmp desde el poll de
             * safepoint, y ademas un SIGSEGV dentro de main compilado se
             * recupera igual que en el batch. setjmp==0: ejecucion normal; !=0:
             * se hizo longjmp (aborto) -> saltar la ejecucion y dejar el
             * proceso HALT. */
            /* Y quien esta ejecutando, que el manejador del sistema lo necesita
             * para saber a quien avisar.  La vuelta del bucle empieza
             * poniendolo a nulo (mas arriba) y solo el lote del interprete lo
             * volvia a poner; por aqui se armaba la recuperacion sin registrar
             * el proceso, asi que el manejador se retiraba -- no tenia a quien
             * avisar -- y un fallo dentro de `main` compilado mataba al proceso
             * con 0xC0000005 y la salida de error VACiA.  El mismo fallo dentro
             * del lote interpretado si salia contado, con su codigo, su
             * fichero:linea y su cadena de llamadas: el mismo programa fallando
             * de dos maneras segun como se ejecute. */
            set_current_executing_process(instance);
            instance->pending_av_kind = 0xFFFFFFFFu;
            instance->av_recovery_active = true;
            bool atrapado_por_el_programa = false;
            if (setjmp(instance->av_recovery_jmpbuf) == 0) {
                (void)jit::enter_jit(jf,
                                     reinterpret_cast<vrt_proc *>(instance));
            } else {
                /* Se volvio aqui por un fallo del procesador dentro del codigo
                 * compilado: division entre cero, desbordamiento entero o un
                 * acceso invalido.  El codigo nativo no comprueba el divisor
                 * antes de dividir -- lo hace el procesador -- asi que el fallo
                 * llega por aqui y no por `throw_fatal`.
                 *
                 * Sin mirarlo, el proceso pasaba a HALT y el programa terminaba
                 * en silencio: la division entre cero no decia nada en JIT
                 * mientras que en el interprete si.  El mismo programa fallando
                 * de dos maneras distintas segun como se ejecute es peor que
                 * cualquiera de las dos. */
                /* Por el MISMO sitio que el batch del interprete: el fallo se
                 * cuenta una sola vez, escrito una sola vez.  Antes esto era
                 * una copia palabra por palabra del otro camino, y solo cubria
                 * dos de los fallos -- una instruccion que el procesador no
                 * tiene moria aqui sin decir nada. */
                atrapado_por_el_programa = lanzar_fallo_del_sistema(instance);
            }
            instance->av_recovery_active = false;
            if (atrapado_por_el_programa) {
                /* Un `catch` del programa se hizo cargo: el proceso no ha
                 * muerto, esta dentro del handler.  Cerrarlo aqui era lo que
                 * hacia que un fallo del sistema rodeado de `try` terminara el
                 * programa en silencio, con el `catch` sin ejecutar. */
                instance->state.store(READY, std::memory_order_release);
                instance->tsc = 1;
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    ready_queue.push_back(instance);
                }
                continue;
            }
            /* Marcar el proceso como HALT.  No hay mas ejecucion interp. */
            instance->state.store(HALT, std::memory_order_release);
            instance->tsc = 1; /* marcar que ya ejecuto algo */
            /* BUG FIX 2026-05-16: decrementar alive_count.  El fast/slow
             * path normales decrementan cuando el proceso pasa a HALT
             * (lineas ~671 y ~767), pero el JIT entry path olvidaba
             * hacerlo.  Sin esto, alive_count queda en >0 aunque el
             * proceso ya termino -> has_alive_processes() retorna true
             * -> outer loop bloquea en sem.acquire() esperando un
             * make_ready() que nunca llega -> main thread bloqueado en
             * done_cv.wait() -> deadlock visible como "[jit] eager-
             * compiled main (...)" + cuelgue. */
            alive_count--;
            continue; /* volver al outer loop a buscar otro proceso */
        }

        if (!has_hooks) {
            // === FAST PATH: threaded computed-goto dispatch ===
            //
            // Reemplaza el patron switch+continue por un threaded
            // interpreter clasico: cada handler del fast path acaba con
            // su propio `goto *table[next_op]`, dando al branch predictor
            // del CPU una entrada BTB unica por handler.  Para hot loops
            // donde la secuencia de opcodes es repetitiva (mov;add;cmp;
            // jcc), el predictor especializa cada sucesion y elimina los
            // mispredicts del switch centralizado.
            //
            // Gana ~10-30% en MIPS sobre el switch + indirect call previo
            // para benches dispatch-bound (tight_loop, struct_field).
            //
            // Requiere GCC/Clang (computed goto: `&&label` y `goto *p`).
            // MSVC no lo soporta; si se compila con MSVC habria que
            // mantener una alternativa con switch (no critica: el target
            // primario es MinGW + GCC en TDM-GCC-64).
            //
            // El slow path (exec_cached para opcodes no inlineados)
            // tambien se threadea: tras ejecutar, decode el siguiente y
            // dispatch.  Solo se sale del chain cuando reductions llega
            // a 0 o cuando un exec_fn transiciona a HALT/WAIT_IO.
            instance->state.store(EXECUTE, std::memory_order_relaxed);

            // traza de primera ejecucion del proceso para depuracion
            // distribuida
            if (instance->tsc == 0) {
                DIST_DBG(
                    "SCHED %u: primera ejecucion PID=(sched=%u local=%llu) "
                    "PC=0x%llX rspawn_fid=%llu estado=%d",
                    id_scheduler, instance->pid.scheduler_id,
                    (unsigned long long)instance->pid.local_pid,
                    (unsigned long long)instance->registers.rip.raw(),
                    (unsigned long long)instance->rspawn_future_id,
                    (int)instance->state);
            }

            // OPTIMIZACION (overhead): solo armar el recovery point
            // cuando el proceso tiene una pila de try/catch activa.
            // Programas sin try/catch (caso comun) no pagan el coste
            // de @c setjmp (~10-15 ns por batch, ~1% del runtime).
            //
            // Cuando el proceso ENTRA a un try mid-batch via la
            // instruccion @c tryenter, esa instruccion fuerza
            // @c reductions_remaining = 1 para terminar el batch
            // actual.  El proximo batch ya verá @c exc_frame_stack
            // no-null y armará el recovery.  Asi cubrimos toda la
            // ventana de vulnerabilidad sin overhead permanente.
            set_current_executing_process(instance);
            /* La recuperacion se arma SIEMPRE, haya o no un `try` alrededor.
             *
             * Antes solo se armaba con un `try` activo, con lo que un deref de
             * un puntero nulo sin `try` no se convertia en fallo del programa:
             * se lo llevaba por delante el proceso ENTERO de la maquina
             * virtual, sin mensaje, sin traza y sin decir en que linea.  La
             * maquina no puede morirse porque el programa que ejecuta tenga un
             * error, igual que un navegador no se cierra porque una pagina
             * falle.
             *
             * Cuesta un `setjmp` por lote -- decenas de instrucciones, no una
             * -- y el camino compilado ya lo pagaba sin discutirlo. */
            const bool armed_fast = true;
            if (armed_fast) {
                instance->pending_av_kind = 0xFFFFFFFFu;
                instance->av_recovery_active = true;
                if (setjmp(instance->av_recovery_jmpbuf) != 0) {
                    /* Lo captura el sistema a mitad de instruccion: el PC
                     * apunta a la que fallo, no a la siguiente. */
                    instance->fatal_pc_exact = true;
                    if (lanzar_fallo_del_sistema(instance)) {
                        /* Lo atrapo un `catch` del programa: el proceso sigue
                         * vivo, parado en el handler.
                         *
                         * Pero NO se sigue el lote desde aqui.  Se llego por un
                         * salto largo, y despues de uno las variables locales
                         * de esta funcion -- que se han ido modificando desde
                         * que se armo el salto -- valen lo que valgan: seguir
                         * hacia el bucle de despacho es entrar en el con
                         * `instance`, el contador de vivos y la tabla en un
                         * estado que nadie garantiza, y eso terminaba
                         * llevandose la maquina entera justo despues de contar
                         * el fallo. Se deja el proceso listo y se vuelve a
                         * entrar limpio por el camino de siempre, que es el
                         * unico que arma sus locales desde cero. */
                        instance->av_recovery_active = false;
                        instance->state.store(READY, std::memory_order_release);
                        instance->tsc = 1;
                        {
                            /* Y se vuelve a la COLA.  Dejarlo listo sin
                             * encolarlo es dejarlo listo para nadie: el
                             * planificador se dormia esperando trabajo que ya
                             * existia pero que no estaba donde lo busca. */
                            std::lock_guard<std::mutex> lock(queue_mutex);
                            ready_queue.push_back(instance);
                        }
                        continue; /* se retoma en el handler, con marco nuevo */
                    } else {
                        /* Y se cierra el proceso AQUI, con el mismo cierre que
                         * usa la entrada al codigo compilado.
                         *
                         * Sin `try`, `throw_fatal` deja el proceso muerto y
                         * RETORNA
                         * -- no salta a ningun sitio --, asi que seguir el lote
                         * significaba volver a ejecutar la instruccion que
                         * acaba de reventar y repetirlo sin fin.  Pero cortar
                         * el lote a secas tampoco vale: el descuento de
                         * procesos vivos esta DENTRO del despacho, asi que
                         * saltarselo deja el contador en alto, los
                         * planificadores esperando a alguien que ya no existe y
                         * la maquina colgada.  Hay que marcar HALT y soltarlo.
                         */
                        instance->av_recovery_active = false;
                        instance->state.store(HALT, std::memory_order_release);
                        instance->tsc = 1;
                        alive_count--;
                        continue; /* a por otro proceso */
                    }
                }
            }

            if (instance->reductions_remaining > 0) {
                /* === DISPATCH TABLE (built once per scheduler thread) ===
                 * Indice:  bits 0-7 = opcode primario (is_not_extended)
                 *          bit 8    = 1 si es opcode extendido
                 * Default = L_SLOW para todo opcode sin fast path.
                 * Solo opcodes con condicion fast-path-friendly listados. */
                /* Tabla read-only.  La inicializamos UNA vez por thread
                 * via thread_local bool flag.  Las direcciones de label
                 * son thread-local (cada thread ve su propio code
                 * segment via PIC? -- en realidad mismo segmento, pero
                 * la inicializacion es trivial y se beneficia de la
                 * proteccion natural por flag local).  El acceso a
                 * dispatch_table en sí es static (sin TLS overhead). */
                static void *dispatch_table[512];
                static bool dispatch_initialized = false;
                if (__builtin_expect(!dispatch_initialized, 0)) {
                    for (int i = 0; i < 512; ++i)
                        dispatch_table[i] = &&L_SLOW;
                    /* Extended (is_not_extended==0x00): idx = 0x100 | opcode2
                     */
                    dispatch_table[0x100 | 0x14] = &&L_MOV_RR;
                    dispatch_table[0x100 | 0x15] = &&L_MOV_RI;
                    dispatch_table[0x100 | 0x05] = &&L_ADD_RR;
                    dispatch_table[0x100 | 0x08] = &&L_SUB_RR;
                    dispatch_table[0x100 | 0x11] = &&L_CMP_RR;
                    dispatch_table[0x100 | 0x17] = &&L_AND_RR;
                    dispatch_table[0x100 | 0x18] = &&L_OR_RR;
                    dispatch_table[0x100 | 0x19] = &&L_XOR_RR;
                    dispatch_table[0x100 | 0x68] = &&L_CMPJMP_S;
                    dispatch_table[0x100 | 0x69] = &&L_CMPJMP_U;
                    /* Super-instrucciones ALU 3-operandos (0x73-0x7B) */
                    dispatch_table[0x100 | 0x73] = &&L_ALU3;
                    dispatch_table[0x100 | 0x74] = &&L_ALU3;
                    dispatch_table[0x100 | 0x75] = &&L_ALU3;
                    dispatch_table[0x100 | 0x76] = &&L_ALU3;
                    dispatch_table[0x100 | 0x77] = &&L_ALU3;
                    dispatch_table[0x100 | 0x78] = &&L_ALU3;
                    dispatch_table[0x100 | 0x79] = &&L_ALU3;
                    dispatch_table[0x100 | 0x7A] = &&L_ALU3;
                    dispatch_table[0x100 | 0x7B] = &&L_ALU3;
                    /* Shifts (mode=3) + setcc: hot en loops FNV/hash. */
                    dispatch_table[0x100 | 0x1B] = &&L_SHL;
                    dispatch_table[0x100 | 0x1C] = &&L_SHR;
                    dispatch_table[0x100 | 0x1D] = &&L_SAR;
                    dispatch_table[0x100 | 0x43] = &&L_SETCC;
                    dispatch_table[0x100 | 0x92] = &&L_SEXT;
                    /* Carga/almacen universal: las mem-ops mas frecuentes. */
                    dispatch_table[0x100 | 0x90] = &&L_MLD;
                    dispatch_table[0x100 | 0x91] = &&L_MST;
                    /* loadz / loadzh (0x7C / 0x7D) caen al SLOW path:
                     * el inlining provoca icache/BTB pressure que regresa
                     * benches con muchos opcodes (poly, callvirt_hot).
                     * El exec_cached(exec_instr_loadz) tiene call overhead
                     * compensado por la reduccion drastica de instr count
                     * (la mitad de ops por LOAD i32). */
                    /* Primary opcode jmp/jcc */
                    dispatch_table[0x11] = &&L_JCC;
                    dispatch_initialized = true;
                }

                /* Inicial dispatch: decode + jump-table goto.  Inline
                 * el icache hit-path igual que en NEXT_DISPATCH. */
                DecodedInstr *d = nullptr;
                decltype(instance->decoded_ptr->flags_info) fl_inl{};
                unsigned dispatch_idx;
                {
                    const uint64_t _pc = instance->registers.rip.raw();
                    DecodedInstr *_c = icache_lookup(instance, _pc);
                    if (__builtin_expect(_c != nullptr &&
                                             instance->decoded_ptr != nullptr,
                                         1)) {
                        instance->decoded_ptr = _c;
                    } else {
                        decode_instruction(instance);
                    }
                }
                d = instance->decoded_ptr;
                fl_inl = d->flags_info;
                dispatch_idx = (fl_inl.is_not_extended == 0x00)
                                   ? (0x100u | fl_inl.opcode_index)
                                   : fl_inl.is_not_extended;
                goto *dispatch_table[dispatch_idx];

/* Macro NEXT: tail-call equivalente al dispatch inicial.
 * Decrementa reductions, sale si llego a 0, y hace el
 * goto indirecto al siguiente handler.  Inlineado al
 * final de cada handler -> cada uno tiene su PROPIO
 * indirect-jump-site -> BTB especializa por handler. */
/* NEXT_DISPATCH inline el icache HIT path de
 * decode_instruction (~90% de los dispatches en hot
 * loops): pc -> icache_index -> cached entry + check.
 * Solo cae a la funcion en cache MISS.  Ahorra la
 * sobrecarga de la llamada (~1ns x N dispatches).
 * Sin LTO en MinGW el compilador no puede inlinear
 * decode_instruction automaticamente desde otra TU. */
#define NEXT_DISPATCH()                                                        \
    do {                                                                       \
        if (__builtin_expect(--instance->reductions_remaining == 0, 0))        \
            goto BATCH_END;                                                    \
        const uint64_t _pc = instance->registers.rip.raw();                    \
        DecodedInstr *_c = icache_lookup(instance, _pc);                       \
        if (__builtin_expect(                                                  \
                _c != nullptr && instance->decoded_ptr != nullptr, 1)) {       \
            instance->decoded_ptr = _c;                                        \
        } else {                                                               \
            decode_instruction(instance);                                      \
        }                                                                      \
        d = instance->decoded_ptr;                                             \
        fl_inl = d->flags_info;                                                \
        dispatch_idx = (fl_inl.is_not_extended == 0x00)                        \
                           ? (0x100u | fl_inl.opcode_index)                    \
                           : fl_inl.is_not_extended;                           \
        goto *dispatch_table[dispatch_idx];                                    \
    } while (0)

                /* ===================== HANDLERS FAST PATH
                 * ===================== */

            L_MOV_RR: {
                if (fl_inl.mode != 3 || fl_inl._signed_instruct != 0)
                    goto L_SLOW;
                const uint8_t r1 = d->data_instruction.reg_data.reg1;
                const uint8_t r2 = d->data_instruction.reg_data.reg2;
                instance->registers.regs[r1].qword(
                    instance->registers.regs[r2].qword());
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_MOV_RI: {
                if (fl_inl.mode != 3 || fl_inl.direction != 0 ||
                    fl_inl._signed_instruct != 0)
                    goto L_SLOW;
                const uint8_t r = d->data_instruction.inmmed_data.reg;
                instance->registers.regs[r].qword(
                    d->data_instruction.inmmed_data.inmmed);
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_ADD_RR: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t r1 = d->data_instruction.reg_data.reg1;
                const uint8_t r2 = d->data_instruction.reg_data.reg2;
                const uint64_t a = regs[r1].qword();
                const uint64_t b = regs[r2].qword();
                const uint64_t res = a + b;
                regs[r1].qword(res);
                fl.ZF = (res == 0);
                fl.SF = (int64_t)res < 0;
                if (fl_inl._signed_instruct) {
                    fl.OF = (((int64_t)a ^ (int64_t)res) &
                             ((int64_t)b ^ (int64_t)res)) < 0;
                    fl.CF = 0;
                } else {
                    fl.CF = res < a;
                    fl.OF = 0;
                }
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_SUB_RR: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t r1 = d->data_instruction.reg_data.reg1;
                const uint8_t r2 = d->data_instruction.reg_data.reg2;
                const uint64_t a = regs[r1].qword();
                const uint64_t b = regs[r2].qword();
                const uint64_t res = a - b;
                regs[r1].qword(res);
                fl.ZF = (res == 0);
                fl.SF = (int64_t)res < 0;
                if (fl_inl._signed_instruct) {
                    fl.OF = (((int64_t)a ^ (int64_t)b) &
                             ((int64_t)a ^ (int64_t)res)) < 0;
                    fl.CF = 0;
                } else {
                    fl.CF = a < b;
                    fl.OF = 0;
                }
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_CMP_RR: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t r1 = d->data_instruction.reg_data.reg1;
                const uint8_t r2 = d->data_instruction.reg_data.reg2;
                const uint64_t a = regs[r1].qword();
                const uint64_t b = regs[r2].qword();
                const uint64_t res = a - b;
                fl.ZF = (res == 0);
                fl.SF = (int64_t)res < 0;
                if (fl_inl._signed_instruct) {
                    fl.OF = (((int64_t)a ^ (int64_t)b) &
                             ((int64_t)a ^ (int64_t)res)) < 0;
                    fl.CF = 0;
                } else {
                    fl.CF = a < b;
                    fl.OF = 0;
                }
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_AND_RR: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t r1 = d->data_instruction.reg_data.reg1;
                const uint8_t r2 = d->data_instruction.reg_data.reg2;
                const uint64_t res = regs[r1].qword() & regs[r2].qword();
                regs[r1].qword(res);
                fl.ZF = (res == 0);
                fl.SF = (int64_t)res < 0;
                fl.CF = 0;
                fl.OF = 0;
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_OR_RR: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t r1 = d->data_instruction.reg_data.reg1;
                const uint8_t r2 = d->data_instruction.reg_data.reg2;
                const uint64_t res = regs[r1].qword() | regs[r2].qword();
                regs[r1].qword(res);
                fl.ZF = (res == 0);
                fl.SF = (int64_t)res < 0;
                fl.CF = 0;
                fl.OF = 0;
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_XOR_RR: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t r1 = d->data_instruction.reg_data.reg1;
                const uint8_t r2 = d->data_instruction.reg_data.reg2;
                const uint64_t res = regs[r1].qword() ^ regs[r2].qword();
                regs[r1].qword(res);
                fl.ZF = (res == 0);
                fl.SF = (int64_t)res < 0;
                fl.CF = 0;
                fl.OF = 0;
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_CMPJMP_S:
            L_CMPJMP_U: {
                const auto &sd = d->data_instruction.static_data;
                auto &regs2 = instance->registers.regs;
                auto &fl2 = instance->registers.flags.bits;
                const uint64_t a = regs2[sd.r0].qword();
                const uint64_t b = regs2[sd.r1].qword();
                const uint64_t res = a - b;
                fl2.ZF = (res == 0);
                fl2.SF = static_cast<int64_t>(res) < 0;
                if (fl_inl.opcode_index == 0x68) { // signed
                    fl2.OF =
                        ((static_cast<int64_t>(a) ^ static_cast<int64_t>(b)) &
                         (static_cast<int64_t>(a) ^
                          static_cast<int64_t>(res))) < 0;
                    fl2.CF = 0;
                } else { // unsigned (0x69)
                    fl2.CF = a < b;
                    fl2.OF = 0;
                }
                const uint8_t cond = static_cast<uint8_t>(sd._pad);
                bool taken;
                switch (cond) {
                case 0x00: taken = (fl2.ZF == 1); break;
                case 0x01: taken = (fl2.ZF == 0); break;
                case 0x02: taken = (fl2.CF == 1); break;
                case 0x03: taken = (fl2.CF == 0); break;
                case 0x04: taken = (fl2.SF == 1); break;
                case 0x05: taken = (fl2.SF == 0); break;
                case 0x06: taken = (fl2.OF == 1); break;
                case 0x07: taken = (fl2.OF == 0); break;
                case 0x08: taken = (fl2.CF == 0 && fl2.ZF == 0); break;
                case 0x09: taken = (fl2.CF == 1 || fl2.ZF == 1); break;
                case 0x0A: taken = (fl2.SF == fl2.OF); break;
                case 0x0B: taken = (fl2.SF != fl2.OF); break;
                case 0x0C: taken = (fl2.ZF == 0 && fl2.SF == fl2.OF); break;
                case 0x0D: taken = (fl2.ZF == 1 || fl2.SF != fl2.OF); break;
                default: taken = true; break;
                }
                // Sprint D.6: profile counter (fast path threaded).
                {
                    const uint64_t bpc = instance->registers.rip.raw();
                    runtime::profile::lite_profile_branch(bpc, taken);
                    if (__builtin_expect(
                            runtime::profile::g_profile.active.load(
                                std::memory_order_relaxed),
                            0)) {
                        runtime::profile::profile_branch(bpc, taken);
                    }
                }
                if (taken) {
                    instance->registers.rip.qword(
                        static_cast<uint64_t>(sd.offset));
                } else {
                    instance->registers.rip.qword(
                        instance->registers.rip.raw() + fl_inl.size_instr);
                }
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_JCC: {
                const uint8_t cond = d->data_instruction.inmmed_data.reg;
                const uint64_t addr = d->data_instruction.inmmed_data.inmmed;
                const auto &fl = instance->registers.flags.bits;
                bool taken;
                switch (cond) {
                case 0x00: taken = (fl.ZF == 1); break;
                case 0x01: taken = (fl.ZF == 0); break;
                case 0x02: taken = (fl.CF == 1); break;
                case 0x03: taken = (fl.CF == 0); break;
                case 0x04: taken = (fl.SF == 1); break;
                case 0x05: taken = (fl.SF == 0); break;
                case 0x06: taken = (fl.OF == 1); break;
                case 0x07: taken = (fl.OF == 0); break;
                case 0x08: taken = (fl.CF == 0 && fl.ZF == 0); break;
                case 0x09: taken = (fl.CF == 1 || fl.ZF == 1); break;
                case 0x0A: taken = (fl.SF == fl.OF); break;
                case 0x0B: taken = (fl.SF != fl.OF); break;
                case 0x0C: taken = (fl.ZF == 0 && fl.SF == fl.OF); break;
                case 0x0D: taken = (fl.ZF == 1 || fl.SF != fl.OF); break;
                default: taken = true; break;
                }
                // Sprint D.6: profile counter (fast path threaded JCC).
                // Solo branches condicionales (cond < 0x0E).
                if (cond < 0x0E) {
                    const uint64_t bpc = instance->registers.rip.raw();
                    runtime::profile::lite_profile_branch(bpc, taken);
                    if (__builtin_expect(
                            runtime::profile::g_profile.active.load(
                                std::memory_order_relaxed),
                            0)) {
                        runtime::profile::profile_branch(bpc, taken);
                    }
                }
                if (taken) {
                    instance->registers.rip.qword(addr);
                } else {
                    instance->registers.rip.qword(
                        instance->registers.rip.raw() + fl_inl.size_instr);
                }
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            /* Super-instruccion ALU 3-operandos.  Una sola entrada
             * para los 9 opcodes (0x73-0x7B): switch interno por
             * opcode_index.  Convention B (decode_instr_raw_bytes):
             *   byte2 (reg1) = (r_src1<<4) | r_dst
             *   byte3 (reg2) = (r_src2<<4) | flags (low=0) */
            L_ALU3: {
                const uint8_t b2 = d->data_instruction.reg_data.reg1;
                const uint8_t b3 = d->data_instruction.reg_data.reg2;
                const uint8_t r_dst = b2 & 0x0F;
                const uint8_t r_src1 = (b2 >> 4) & 0x0F;
                const uint8_t r_src2 = (b3 >> 4) & 0x0F;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint64_t a = regs[r_src1].qword();
                const uint64_t b = regs[r_src2].qword();
                uint64_t res;
                switch (fl_inl.opcode_index) {
                case 0x73: /* adds3 */
                    res = a + b;
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.OF =
                        ((static_cast<int64_t>(a) ^ static_cast<int64_t>(res)) &
                         (static_cast<int64_t>(b) ^
                          static_cast<int64_t>(res))) < 0;
                    fl.CF = 0;
                    break;
                case 0x76: /* addu3 */
                    res = a + b;
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.CF = res < a;
                    fl.OF = 0;
                    break;
                case 0x74: /* subs3 */
                    res = a - b;
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.OF =
                        ((static_cast<int64_t>(a) ^ static_cast<int64_t>(b)) &
                         (static_cast<int64_t>(a) ^
                          static_cast<int64_t>(res))) < 0;
                    fl.CF = 0;
                    break;
                case 0x77: /* subu3 */
                    res = a - b;
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.CF = a < b;
                    fl.OF = 0;
                    break;
                case 0x75: /* muls3 */
                    res = static_cast<uint64_t>(static_cast<int64_t>(a) *
                                                static_cast<int64_t>(b));
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.CF = 0;
                    fl.OF = 0;
                    break;
                case 0x78: /* mulu3 */
                    res = a * b;
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.CF = 0;
                    fl.OF = 0;
                    break;
                case 0x79: /* and3 */
                    res = a & b;
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.CF = 0;
                    fl.OF = 0;
                    break;
                case 0x7A: /* or3 */
                    res = a | b;
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.CF = 0;
                    fl.OF = 0;
                    break;
                case 0x7B: /* xor3 */
                    res = a ^ b;
                    regs[r_dst].qword(res);
                    fl.ZF = (res == 0);
                    fl.SF = static_cast<int64_t>(res) < 0;
                    fl.CF = 0;
                    fl.OF = 0;
                    break;
                default: goto L_SLOW;
                }
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            /* SHL/SHR/SAR reg,reg (mode=3, 64-bit): compute inline + flags
             * IDENTICAS al path generico (ShlOp/ShrOp/SarOp): solo CF/OF, ZF/SF
             * quedan intactos.  Modos parciales caen a L_SLOW.  Ataca los loops
             * FNV/hash/shift-heavy (hash_lookup: 5 shifts/iter iban a L_SLOW).
             */
            L_SHL: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t rdst = d->data_instruction.reg_data.reg1;
                const uint8_t rsrc = d->data_instruction.reg_data.reg2;
                const uint64_t a = regs[rdst].qword();
                const uint32_t sh =
                    static_cast<uint32_t>(regs[rsrc].qword()) & 63u;
                const uint64_t res = a << sh;
                regs[rdst].qword(res);
                if (sh == 0) {
                    fl.CF = 0;
                    fl.OF = 0;
                } else {
                    const uint64_t cf = (a >> (64 - sh)) & 1;
                    fl.CF = cf;
                    fl.OF = cf ^ (res >> 63);
                }
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_SHR: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t rdst = d->data_instruction.reg_data.reg1;
                const uint8_t rsrc = d->data_instruction.reg_data.reg2;
                const uint64_t a = regs[rdst].qword();
                const uint32_t sh =
                    static_cast<uint32_t>(regs[rsrc].qword()) & 63u;
                regs[rdst].qword(a >> sh);
                if (sh == 0) {
                    fl.CF = 0;
                } else {
                    fl.CF = (a >> (sh - 1)) & 1;
                }
                fl.OF = 0;
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_SAR: {
                if (fl_inl.mode != 3) goto L_SLOW;
                auto &regs = instance->registers.regs;
                auto &fl = instance->registers.flags.bits;
                const uint8_t rdst = d->data_instruction.reg_data.reg1;
                const uint8_t rsrc = d->data_instruction.reg_data.reg2;
                const uint64_t a = regs[rdst].qword();
                const uint32_t sh =
                    static_cast<uint32_t>(regs[rsrc].qword()) & 63u;
                regs[rdst].qword(
                    static_cast<uint64_t>(static_cast<int64_t>(a) >> sh));
                if (sh == 0) {
                    fl.CF = 0;
                } else {
                    fl.CF = (a >> (sh - 1)) & 1;
                }
                fl.OF = 0;
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            /* SETCC r_dst, cond: escribe 0/1 segun la condicion.  reg1
             * empaqueta (cond<<4)|dst.  No toca flags (identico a
             * exec_instr_setcc). */
            L_SETCC: {
                auto &regs = instance->registers.regs;
                const auto &fl = instance->registers.flags.bits;
                const uint8_t packed = d->data_instruction.reg_data.reg1;
                const uint8_t cond = (packed >> 4) & 0xF;
                const uint8_t rdst = packed & 0xF;
                bool taken;
                switch (cond) {
                case 0x00: taken = fl.OF; break;
                case 0x01: taken = !fl.OF; break;
                case 0x02: taken = fl.CF; break;
                case 0x03: taken = !fl.CF; break;
                case 0x04: taken = fl.ZF; break;
                case 0x05: taken = !fl.ZF; break;
                case 0x06: taken = fl.CF || fl.ZF; break;
                case 0x07: taken = !fl.CF && !fl.ZF; break;
                case 0x08: taken = fl.SF; break;
                case 0x09: taken = !fl.SF; break;
                case 0x0A: taken = fl.ZF && !(fl.SF ^ fl.OF); break;
                case 0x0B: taken = !fl.ZF; break;
                case 0x0C: taken = (fl.SF ^ fl.OF); break;
                case 0x0D: taken = !(fl.SF ^ fl.OF); break;
                case 0x0E: taken = fl.ZF || (fl.SF ^ fl.OF); break;
                case 0x0F: taken = true; break;
                default: taken = false; break;
                }
                regs[rdst].qword(taken ? 1 : 0);
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            /* SEXT r_dst, N: sign-extiende r_dst desde N bits (8/16/32) a 64.
             * b2=r_dst (nibble bajo), b3=N.  Hot en casts de enteros con signo
             * (loop counters `(u64)i`, etc.); replica exec_instr_sext. */
            L_SEXT: {
                auto &regs = instance->registers.regs;
                const uint8_t rdst = d->data_instruction.reg_data.reg1 & 0xF;
                const uint8_t width = d->data_instruction.reg_data.reg2;
                const uint64_t v = regs[rdst].qword();
                uint64_t res;
                switch (width) {
                case 8:
                    res = static_cast<uint64_t>(
                        static_cast<int64_t>(static_cast<int8_t>(v)));
                    break;
                case 16:
                    res = static_cast<uint64_t>(
                        static_cast<int64_t>(static_cast<int16_t>(v)));
                    break;
                case 32:
                    res = static_cast<uint64_t>(
                        static_cast<int64_t>(static_cast<int32_t>(v)));
                    break;
                default: {
                    const uint32_t sh =
                        (64u - (static_cast<uint32_t>(width) & 63u)) & 63u;
                    res = static_cast<uint64_t>(static_cast<int64_t>(v << sh) >>
                                                sh);
                    break;
                }
                }
                regs[rdst].qword(res);
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            /* MLD/MST: carga/almacen UNIVERSAL (arrays, locales, campos).  Son
             * las instrucciones de memoria mas frecuentes del hot loop; iban a
             * L_SLOW (decode + call por puntero) aunque el acceso interno ya
             * usaba el page-cache.  Handler inline: replica exec_instr_mld/mst
             * (base +/- index*scale +/- disp, host/VM, sign-ext, anchos
             * 1/2/4/8). El banco FP (flags b4) y anchos >8 (SIMD) caen a L_SLOW
             * (raros en codigo entero). */
            L_MLD: {
                const auto &m = d->data_instruction.mem_full;
                if ((m.flags & 0x10) || m.width > 8) goto L_SLOW;
                auto &regs = instance->registers.regs;
                uint64_t addr =
                    m.base < 16
                        ? regs[m.base].qword()
                        : (m.base == 16
                               ? instance->registers.base_pointer.raw()
                               : instance->registers.stack_pointer.raw());
                addr += static_cast<uint64_t>(static_cast<int64_t>(m.disp));
                if (m.flags & 0x02) {
                    const uint64_t idx = regs[m.index].qword() << m.scale;
                    if (m.flags & 0x04)
                        addr -= idx;
                    else
                        addr += idx;
                }
                uint64_t val;
                if (m.flags & 0x01) { // host
                    val = 0;
                    std::memcpy(&val, reinterpret_cast<const void *>(addr),
                                m.width);
                } else {
                    switch (m.width) {
                    case 1: val = instance->vm_mem.read_u8(addr); break;
                    case 2: val = instance->vm_mem.read_u16(addr); break;
                    case 4: val = instance->vm_mem.read_u32(addr); break;
                    default: val = instance->vm_mem.read_u64_fast(addr); break;
                    }
                }
                if (m.flags & 0x08) { // sign-extend anchos < 8
                    switch (m.width) {
                    case 1:
                        val = static_cast<uint64_t>(
                            static_cast<int64_t>(static_cast<int8_t>(val)));
                        break;
                    case 2:
                        val = static_cast<uint64_t>(
                            static_cast<int64_t>(static_cast<int16_t>(val)));
                        break;
                    case 4:
                        val = static_cast<uint64_t>(
                            static_cast<int64_t>(static_cast<int32_t>(val)));
                        break;
                    default: break;
                    }
                }
                regs[m.reg].qword(val);
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            L_MST: {
                const auto &m = d->data_instruction.mem_full;
                if ((m.flags & 0x10) || m.width > 8) goto L_SLOW;
                auto &regs = instance->registers.regs;
                uint64_t addr =
                    m.base < 16
                        ? regs[m.base].qword()
                        : (m.base == 16
                               ? instance->registers.base_pointer.raw()
                               : instance->registers.stack_pointer.raw());
                addr += static_cast<uint64_t>(static_cast<int64_t>(m.disp));
                if (m.flags & 0x02) {
                    const uint64_t idx = regs[m.index].qword() << m.scale;
                    if (m.flags & 0x04)
                        addr -= idx;
                    else
                        addr += idx;
                }
                const uint64_t val = regs[m.reg].qword();
                if (m.flags & 0x01) { // host
                    std::memcpy(reinterpret_cast<void *>(addr), &val, m.width);
                } else {
                    switch (m.width) {
                    case 1:
                        instance->vm_mem.write_u8(addr,
                                                  static_cast<uint8_t>(val));
                        break;
                    case 2:
                        instance->vm_mem.write_u16(addr,
                                                   static_cast<uint16_t>(val));
                        break;
                    case 4:
                        instance->vm_mem.write_u32(addr,
                                                   static_cast<uint32_t>(val));
                        break;
                    default: instance->vm_mem.write_u64_fast(addr, val); break;
                    }
                }
                instance->registers.rip.qword(instance->registers.rip.raw() +
                                              fl_inl.size_instr);
                ++profiler_instr_counter;
                NEXT_DISPATCH();
            }

            /* ===================== SLOW PATH ===================== */
            L_SLOW: {
                vm_event evt;
                if (__builtin_expect(d->exec_cached != nullptr, 1)) {
                    d->exec_cached(instance, *d);
                    if (__builtin_expect(d->flags_info.blocking, 0)) {
                        evt = EVT_IO_WAIT;
                    } else {
                        if (!d->flags_info.did_jump) {
                            instance->registers.rip.qword(
                                instance->registers.rip.raw() +
                                d->flags_info.size_instr);
                        } else {
                            d->flags_info.did_jump = false;
                        }
                        ++profiler_instr_counter;
                        evt = EVT_EXEC_DONE;
                    }
                } else {
                    on_event(EVT_HALT);
                    evt = EVT_HALT;
                }
                instance->reductions_remaining--;

                // La instruccion puede haber lanzado un FatalError SIN handler
                // (division por cero, unwrap de null, panic...).  En ese caso
                // `throw_fatal` deja el proceso en HALT y RETORNA -- no salta
                // a ningun sitio --, asi que sin este corte el lote seguia
                // ejecutando instrucciones de un programa ya muerto: la
                // division por cero imprimia su resultado y el proceso acababa
                // con codigo 0, como si nada hubiera pasado.
                // La instruccion puede haber lanzado un FatalError SIN handler
                // (division por cero, unwrap de null, panic...).  `throw_fatal`
                // deja el proceso en HALT y RETORNA -- no salta a ningun sitio
                // --, asi que sin mirar el estado aqui el lote seguia
                // ejecutando instrucciones de un programa ya muerto: la
                // division por cero imprimia su resultado y el proceso
                // terminaba con codigo 0, como si nada.  No se puede saltar
                // directamente al final del lote: hay que caer al bloque
                // HALT/DEAD de abajo, que es el que descuenta `alive_count` y
                // suelta el proceso (si no, vuelve a la cola y repite la
                // instruccion que lo mato, en bucle).
                const vm_state st_after =
                    instance->state.load(std::memory_order_relaxed);
                const bool died_now = (st_after == HALT || st_after == DEAD);

                if (__builtin_expect(evt == EVT_EXEC_DONE && !died_now, 1)) {
                    if (instance->reductions_remaining == 0) goto BATCH_END;
                    {
                        const uint64_t _pc = instance->registers.rip.raw();
                        DecodedInstr *_c = icache_lookup(instance, _pc);
                        if (__builtin_expect(_c != nullptr &&
                                                 instance->decoded_ptr !=
                                                     nullptr,
                                             1)) {
                            instance->decoded_ptr = _c;
                        } else {
                            decode_instruction(instance);
                        }
                    }
                    d = instance->decoded_ptr;
                    fl_inl = d->flags_info;
                    dispatch_idx = (fl_inl.is_not_extended == 0x00)
                                       ? (0x100u | fl_inl.opcode_index)
                                       : fl_inl.is_not_extended;
                    goto *dispatch_table[dispatch_idx];
                }

                /* HALT / DEAD: salir del dispatch chain con cleanup. */
                if (instance->state.load(std::memory_order_relaxed) == HALT ||
                    instance->state.load(std::memory_order_relaxed) == DEAD) {
                    alive_count--;
                    DIST_DBG(
                        "SCHED %u: proceso PID=(sched=%u local=%llu) -> %s  "
                        "r0=%llu err=%d tsc=%llu PC=0x%llX",
                        id_scheduler, instance->pid.scheduler_id,
                        (unsigned long long)instance->pid.local_pid,
                        instance->state == HALT ? "HALT" : "DEAD",
                        (unsigned long long)instance->registers.regs[0].qword(),
                        (int)instance->err_thread,
                        (unsigned long long)instance->tsc,
                        (unsigned long long)instance->registers.rip.raw());
                    if (instance->rspawn_future_id != 0 &&
                        instance->rspawn_origin_node != 0xFFFFFFFFu &&
                        vm_reference.dist_runtime) {
                        vm_reference.dist_runtime->notify_rspawn_halt(instance);
                    }
                    instance = nullptr;
                    goto BATCH_END;
                }

                /* WAIT_IO genuino: registro + wake_pending double-check. */
                DIST_DBG(
                    "SCHED %u: proceso PID=(sched=%u local=%llu) -> WAIT_IO "
                    "tsc=%llu PC=0x%llX err=%d",
                    id_scheduler, instance->pid.scheduler_id,
                    (unsigned long long)instance->pid.local_pid,
                    (unsigned long long)instance->tsc,
                    (unsigned long long)instance->registers.rip.raw(),
                    (int)instance->err_thread);
                {
                    vm_state expected = EXECUTE;
                    instance->state.compare_exchange_strong(
                        expected, WAIT_IO, std::memory_order_acq_rel,
                        std::memory_order_acquire);
                    if (instance->wake_pending.exchange(
                            false, std::memory_order_acq_rel)) {
                        vm_state cur =
                            instance->state.load(std::memory_order_acquire);
                        if (cur == WAIT_IO || cur == BLOCKED) {
                            instance->state.store(READY,
                                                  std::memory_order_release);
                            std::lock_guard<std::mutex> lock(queue_mutex);
                            ready_queue.push_back(instance);
                        }
                    }
                }
                instance = nullptr;
                goto BATCH_END;
            }

            BATCH_END:;
#undef NEXT_DISPATCH
                // FINALIZADORES GC: safe point de fin de batch.  Ninguna
                // instruccion esta en vuelo; los regs/stack del proceso estan
                // commiteados y la instruccion decodificada ya no se usa.  Si
                // un GC disparado durante el batch stageo finalizadores
                // (objetos con recurso interno escapados y muertos), drenarlos
                // AHORA reentrando al interprete para correr sus deleters --
                // seguro fuera de cualquier handler. Fast path: 1 branch
                // predicho-no-tomado cuando no hay pendientes.
                if (instance != nullptr &&
                    __builtin_expect(instance->gc_heap.has_pending_finalizers(),
                                     0))
                    instance->gc_heap.run_pending_finalizers();
            }
            /* DEAD CODE STUB BELOW: el codigo entre aqui y `} else {`
             * (slow path FSM hooks) son los restos del while+switch viejo
             * que ya estan reemplazados por el threaded dispatch arriba.
             * Mantenemos la envolvente `if (false) {...}` para que el
             * compilador elimine via DCE sin romper el balance de braces.
             * Eliminar completamente requiere un refactor mas grande
             * (re-balancear el cierre de `if (!has_hooks)`); deferido.
             * El `if (false)` es zero-cost en runtime (eliminado por DCE
             * a O2/O3 que es como compilamos). */
            if (false) {
                DecodedInstr *d = instance ? instance->decoded_ptr : nullptr;
                auto fl_inl = d->flags_info;
                (void)d;
                (void)fl_inl;

                // Predicate: instruccion extendida i64 SIN special-reg
                // (s=0 para mov, signed/unsigned para ALU).
                if (__builtin_expect(fl_inl.is_not_extended == 0x00 &&
                                         fl_inl.mode == 3,
                                     1)) {
                    auto &regs = instance->registers.regs;
                    auto &fl = instance->registers.flags.bits;
                    bool hit = true;
                    switch (fl_inl.opcode_index) {
                    case 0x14: { // mov reg-reg i64 (s=0 standard)
                        if (fl_inl._signed_instruct == 0) {
                            const uint8_t r1 =
                                d->data_instruction.reg_data.reg1;
                            const uint8_t r2 =
                                d->data_instruction.reg_data.reg2;
                            regs[r1].qword(regs[r2].qword());
                        } else {
                            hit = false; // s=1 = special reg, slow path
                        }
                        break;
                    }
                    case 0x15: { // mov reg-imm i64 (direction=0, signed=0 = reg
                                 // dst general)
                        // El fast path solo cubre el caso "mov reg, imm"
                        // (variant 2 del exec): direction=0 Y signed=0.  Si
                        // signed=1 con direction=0 es "mov [reg], imm"
                        // (escritura a memoria, variant 3); si direction=1 es
                        // write a registro especial (variant 1).  Ambos casos
                        // van por slow path.
                        if (fl_inl.direction == 0 &&
                            fl_inl._signed_instruct == 0) {
                            const uint8_t r =
                                d->data_instruction.inmmed_data.reg;
                            regs[r].qword(
                                d->data_instruction.inmmed_data.inmmed);
                        } else {
                            hit =
                                false; // mem dst o special reg dst -> slow path
                        }
                        break;
                    }
                    case 0x05: { // add reg-reg i64 (signed o unsigned)
                        const uint8_t r1 = d->data_instruction.reg_data.reg1;
                        const uint8_t r2 = d->data_instruction.reg_data.reg2;
                        const uint64_t a = regs[r1].qword();
                        const uint64_t b = regs[r2].qword();
                        const uint64_t res = a + b;
                        regs[r1].qword(res);
                        fl.ZF = (res == 0);
                        fl.SF = (int64_t)res < 0;
                        if (fl_inl._signed_instruct) {
                            fl.OF = (((int64_t)a ^ (int64_t)res) &
                                     ((int64_t)b ^ (int64_t)res)) < 0;
                            fl.CF = 0;
                        } else {
                            fl.CF = res < a; // unsigned wrap
                            fl.OF = 0;
                        }
                        break;
                    }
                    case 0x11: { // cmp reg-reg i64 (subtract w/o store)
                        const uint8_t r1 = d->data_instruction.reg_data.reg1;
                        const uint8_t r2 = d->data_instruction.reg_data.reg2;
                        const uint64_t a = regs[r1].qword();
                        const uint64_t b = regs[r2].qword();
                        const uint64_t res = a - b;
                        fl.ZF = (res == 0);
                        fl.SF = (int64_t)res < 0;
                        if (fl_inl._signed_instruct) {
                            fl.OF = (((int64_t)a ^ (int64_t)b) &
                                     ((int64_t)a ^ (int64_t)res)) < 0;
                            fl.CF = 0;
                        } else {
                            fl.CF = a < b; // unsigned borrow
                            fl.OF = 0;
                        }
                        break;
                    }
                    // Optimizacion C (expanded fast-path): mas opcodes
                    // muy comunes en hot loops aritmeticos y bitwise.
                    // Cubren ~10-15% adicional vs el fast path previo.
                    case 0x08: { // sub reg-reg i64
                        const uint8_t r1 = d->data_instruction.reg_data.reg1;
                        const uint8_t r2 = d->data_instruction.reg_data.reg2;
                        const uint64_t a = regs[r1].qword();
                        const uint64_t b = regs[r2].qword();
                        const uint64_t res = a - b;
                        regs[r1].qword(res);
                        fl.ZF = (res == 0);
                        fl.SF = (int64_t)res < 0;
                        if (fl_inl._signed_instruct) {
                            fl.OF = (((int64_t)a ^ (int64_t)b) &
                                     ((int64_t)a ^ (int64_t)res)) < 0;
                            fl.CF = 0;
                        } else {
                            fl.CF = a < b;
                            fl.OF = 0;
                        }
                        break;
                    }
                    case 0x17: { // and reg-reg i64
                        const uint8_t r1 = d->data_instruction.reg_data.reg1;
                        const uint8_t r2 = d->data_instruction.reg_data.reg2;
                        const uint64_t res =
                            regs[r1].qword() & regs[r2].qword();
                        regs[r1].qword(res);
                        fl.ZF = (res == 0);
                        fl.SF = (int64_t)res < 0;
                        fl.CF = 0;
                        fl.OF = 0;
                        break;
                    }
                    case 0x18: { // or reg-reg i64
                        const uint8_t r1 = d->data_instruction.reg_data.reg1;
                        const uint8_t r2 = d->data_instruction.reg_data.reg2;
                        const uint64_t res =
                            regs[r1].qword() | regs[r2].qword();
                        regs[r1].qword(res);
                        fl.ZF = (res == 0);
                        fl.SF = (int64_t)res < 0;
                        fl.CF = 0;
                        fl.OF = 0;
                        break;
                    }
                    case 0x19: { // xor reg-reg i64
                        const uint8_t r1 = d->data_instruction.reg_data.reg1;
                        const uint8_t r2 = d->data_instruction.reg_data.reg2;
                        const uint64_t res =
                            regs[r1].qword() ^ regs[r2].qword();
                        regs[r1].qword(res);
                        fl.ZF = (res == 0);
                        fl.SF = (int64_t)res < 0;
                        fl.CF = 0;
                        fl.OF = 0;
                        break;
                    }
                    default: hit = false;
                    }
                    if (hit) {
                        instance->registers.rip.qword(
                            instance->registers.rip.raw() + fl_inl.size_instr);
                        ++profiler_instr_counter;
                        --instance->reductions_remaining;
                        continue;
                    }
                }
                // Optimizacion C (cmpjmp/cmpjmpu fast path): ambos opcodes
                // son extendidos (is_not_extended == 0x00) con opcode2
                // 0x68/0x69.  Tras la fusion CMP+BR_COND del IR emitter
                // estos son ahora EXTREMADAMENTE comunes en hot loops
                // (bound check de while/for).  Inline aqui evita el
                // indirect call a exec_cached + el switch del cond_byte
                // en exec_instruction_alu.cpp.
                if (__builtin_expect(fl_inl.is_not_extended == 0x00 &&
                                         (fl_inl.opcode_index == 0x68 ||
                                          fl_inl.opcode_index == 0x69),
                                     0)) {
                    const auto &sd = d->data_instruction.static_data;
                    auto &regs2 = instance->registers.regs;
                    auto &fl2 = instance->registers.flags.bits;
                    const uint64_t a = regs2[sd.r0].qword();
                    const uint64_t b = regs2[sd.r1].qword();
                    const uint64_t res = a - b;
                    fl2.ZF = (res == 0);
                    fl2.SF = static_cast<int64_t>(res) < 0;
                    if (fl_inl.opcode_index == 0x68) { // signed
                        fl2.OF = ((static_cast<int64_t>(a) ^
                                   static_cast<int64_t>(b)) &
                                  (static_cast<int64_t>(a) ^
                                   static_cast<int64_t>(res))) < 0;
                        fl2.CF = 0;
                    } else { // unsigned (0x69)
                        fl2.CF = a < b;
                        fl2.OF = 0;
                    }
                    const uint8_t cond = static_cast<uint8_t>(sd._pad);
                    bool taken;
                    switch (cond) {
                    case 0x00: taken = (fl2.ZF == 1); break;
                    case 0x01: taken = (fl2.ZF == 0); break;
                    case 0x02: taken = (fl2.CF == 1); break;
                    case 0x03: taken = (fl2.CF == 0); break;
                    case 0x04: taken = (fl2.SF == 1); break;
                    case 0x05: taken = (fl2.SF == 0); break;
                    case 0x06: taken = (fl2.OF == 1); break;
                    case 0x07: taken = (fl2.OF == 0); break;
                    case 0x08: taken = (fl2.CF == 0 && fl2.ZF == 0); break;
                    case 0x09: taken = (fl2.CF == 1 || fl2.ZF == 1); break;
                    case 0x0A: taken = (fl2.SF == fl2.OF); break;
                    case 0x0B: taken = (fl2.SF != fl2.OF); break;
                    case 0x0C: taken = (fl2.ZF == 0 && fl2.SF == fl2.OF); break;
                    case 0x0D: taken = (fl2.ZF == 1 || fl2.SF != fl2.OF); break;
                    default: taken = true; break;
                    }
                    // Sprint D.6: profile counter (fast path non-threaded
                    // cmpjmp).
                    {
                        const uint64_t bpc = instance->registers.rip.raw();
                        runtime::profile::lite_profile_branch(bpc, taken);
                        if (__builtin_expect(
                                runtime::profile::g_profile.active.load(
                                    std::memory_order_relaxed),
                                0)) {
                            runtime::profile::profile_branch(bpc, taken);
                        }
                    }
                    if (taken) {
                        instance->registers.rip.qword(
                            static_cast<uint64_t>(sd.offset));
                    } else {
                        instance->registers.rip.qword(
                            instance->registers.rip.raw() + fl_inl.size_instr);
                    }
                    ++profiler_instr_counter;
                    --instance->reductions_remaining;
                    continue;
                }
                // Fast path para jmp/jcc primary 0x11 (independiente del mode).
                if (__builtin_expect(fl_inl.is_not_extended == 0x11, 0)) {
                    const uint8_t cond = d->data_instruction.inmmed_data.reg;
                    const uint64_t addr =
                        d->data_instruction.inmmed_data.inmmed;
                    const auto &fl = instance->registers.flags.bits;
                    bool taken;
                    switch (cond) {
                    case 0x00: taken = (fl.ZF == 1); break; // EQ
                    case 0x01: taken = (fl.ZF == 0); break; // NE
                    case 0x02: taken = (fl.CF == 1); break; // CS/AE
                    case 0x03: taken = (fl.CF == 0); break; // CC/B
                    case 0x04: taken = (fl.SF == 1); break; // MI
                    case 0x05: taken = (fl.SF == 0); break; // PL
                    case 0x06: taken = (fl.OF == 1); break; // VS
                    case 0x07: taken = (fl.OF == 0); break; // VC
                    case 0x08: taken = (fl.CF == 0 && fl.ZF == 0); break; // HI
                    case 0x09: taken = (fl.CF == 1 || fl.ZF == 1); break; // LS
                    case 0x0A: taken = (fl.SF == fl.OF); break;           // GE
                    case 0x0B: taken = (fl.SF != fl.OF); break;           // LT
                    case 0x0C:
                        taken = (fl.ZF == 0 && fl.SF == fl.OF);
                        break; // GT
                    case 0x0D:
                        taken = (fl.ZF == 1 || fl.SF != fl.OF);
                        break;                    // LE
                    default: taken = true; break; // 0x0F y otros
                    }
                    // Sprint D.6: profile counter (fast path non-threaded jcc).
                    // Solo branches condicionales (cond < 0x0E).
                    if (cond < 0x0E) {
                        const uint64_t bpc = instance->registers.rip.raw();
                        runtime::profile::lite_profile_branch(bpc, taken);
                        if (__builtin_expect(
                                runtime::profile::g_profile.active.load(
                                    std::memory_order_relaxed),
                                0)) {
                            runtime::profile::profile_branch(bpc, taken);
                        }
                    }
                    if (taken) {
                        instance->registers.rip.qword(addr);
                    } else {
                        instance->registers.rip.qword(
                            instance->registers.rip.raw() + fl_inl.size_instr);
                    }
                    ++profiler_instr_counter;
                    --instance->reductions_remaining;
                    continue;
                }

                // Slow path: opcode no inlineable -> exec_cached.  Igual que
                // antes.
                vm_event evt;
                if (__builtin_expect(d->exec_cached != nullptr, 1)) {
                    d->exec_cached(instance, *d);
                    if (__builtin_expect(d->flags_info.blocking, 0)) {
                        evt = EVT_IO_WAIT;
                    } else {
                        // avanzar PC si la instruccion no fue salto.
                        if (!d->flags_info.did_jump) {
                            instance->registers.rip.qword(
                                instance->registers.rip.raw() +
                                d->flags_info.size_instr);
                        } else {
                            d->flags_info.did_jump = false;
                        }
                        ++profiler_instr_counter;
                        evt = EVT_EXEC_DONE;
                    }
                } else {
                    on_event(EVT_HALT);
                    evt = EVT_HALT;
                }
                instance->reductions_remaining--;

                // camino rapido: instruccion normal completada -> continuar
                if (__builtin_expect(evt == EVT_EXEC_DONE, 1)) {
                    continue;
                }

                // la instruccion cambio el estado de forma autonoma (ej. HLT
                // via on_event). Lectura relaxed: el state lo escribieron
                // exec_fns en este mismo thread (HLT/DEAD) o nosotros antes
                // (EXECUTE).  Cross-thread no relevante aqui.
                if (instance->state.load(std::memory_order_relaxed) == HALT ||
                    instance->state.load(std::memory_order_relaxed) == DEAD) {
                    alive_count--; // decrementar el contador de procesos vivos
                    DIST_DBG(
                        "SCHED %u: proceso PID=(sched=%u local=%llu) -> %s  "
                        "r0=%llu err=%d tsc=%llu PC=0x%llX",
                        id_scheduler, instance->pid.scheduler_id,
                        (unsigned long long)instance->pid.local_pid,
                        instance->state == HALT ? "HALT" : "DEAD",
                        (unsigned long long)instance->registers.regs[0].qword(),
                        (int)instance->err_thread,
                        (unsigned long long)instance->tsc,
                        (unsigned long long)instance->registers.rip.raw());
                    // si el proceso fue creado por rspawn remoto, notificar al
                    // nodo origen con r0
                    if (instance->rspawn_future_id != 0 &&
                        instance->rspawn_origin_node != 0xFFFFFFFFu &&
                        vm_reference.dist_runtime) {
                        vm_reference.dist_runtime->notify_rspawn_halt(instance);
                    }
                    instance = nullptr;
                    break;
                }

                // E/S genuina: poner en WAIT_IO y dejar de procesar este
                // proceso
                DIST_DBG(
                    "SCHED %u: proceso PID=(sched=%u local=%llu) -> WAIT_IO "
                    "tsc=%llu PC=0x%llX err=%d",
                    id_scheduler, instance->pid.scheduler_id,
                    (unsigned long long)instance->pid.local_pid,
                    (unsigned long long)instance->tsc,
                    (unsigned long long)instance->registers.rip.raw(),
                    (int)instance->err_thread);
                // transicion a WAIT_IO con double-check
                // de wake_pending para resolver el race "lost wakeup".
                //
                // Algunas exec_fns (await, msgrecv, monwait, msgsend al
                // bloquear por buffer remoto) llaman on_event(EVT_IO_WAIT)
                // explicitamente antes de retornar, dejando state ya en
                // WAIT_IO.  Otras dejan state=EXECUTE.  La CAS aqui es
                // condicional para cubrir ambos casos sin dobles
                // transiciones.
                //
                // Despues, INDEPENDIENTEMENTE de quien transiciono,
                // exchange wake_pending: si era true significa que un
                // hilo remoto (msgsend/fulfill/notify) intento despertar
                // mientras decidiamos dormir.  Revertir a READY para no
                // perder la senal.  Si estado actual es READY (porque
                // make_ready remoto ya lo cambio + encolo), no hay nada
                // que deshacer.
                {
                    vm_state expected = EXECUTE;
                    instance->state.compare_exchange_strong(
                        expected, WAIT_IO, std::memory_order_acq_rel,
                        std::memory_order_acquire);
                    // Limpiar y leer wake_pending.
                    if (instance->wake_pending.exchange(
                            false, std::memory_order_acq_rel)) {
                        // Solo revertir si seguimos en WAIT_IO/BLOCKED:
                        // si ya esta READY (make_ready remoto exitoso),
                        // no hay nada que tocar (ya esta encolado).
                        vm_state cur =
                            instance->state.load(std::memory_order_acquire);
                        if (cur == WAIT_IO || cur == BLOCKED) {
                            instance->state.store(READY,
                                                  std::memory_order_release);
                            std::lock_guard<std::mutex> lock(queue_mutex);
                            ready_queue.push_back(instance);
                        }
                    }
                }
                instance = nullptr;
                break;
            }
        } else {
            // === SLOW PATH: FSM completo con hooks de depuracion ===
            // Misma optimizacion que en fast path: solo armar
            // recovery cuando hay try/catch activo.
            set_current_executing_process(instance);
            const bool armed_slow = (instance->exc_frame_stack != nullptr);
            if (armed_slow) {
                instance->pending_av_kind = 0xFFFFFFFFu;
                instance->av_recovery_active = true;
                if (setjmp(instance->av_recovery_jmpbuf) != 0) {
                    /* Lo captura el sistema a mitad de instruccion: el PC
                     * apunta a la que fallo, no a la siguiente. */
                    instance->fatal_pc_exact = true;
                    lanzar_fallo_del_sistema(instance);
                }
            }
            while (instance->reductions_remaining > 0) {
                run_fsm_step(instance); // ejecutar un paso de la FSM
                instance->reductions_remaining--;

                // comprobar si el proceso alcanzo un estado terminal o
                // bloqueante
                if (instance->state == DEAD || instance->state == HALT) {
                    alive_count--; // decrementar el contador de procesos vivos
                    DIST_DBG(
                        "SCHED %u (slow): proceso PID=(sched=%u local=%llu) -> "
                        "%s  "
                        "r0=%llu err=%d tsc=%llu PC=0x%llX",
                        id_scheduler, instance->pid.scheduler_id,
                        (unsigned long long)instance->pid.local_pid,
                        instance->state == HALT ? "HALT" : "DEAD",
                        (unsigned long long)instance->registers.regs[0].qword(),
                        (int)instance->err_thread,
                        (unsigned long long)instance->tsc,
                        (unsigned long long)instance->registers.rip.raw());
                    // Notificar al debugger del fin del proceso.  Los
                    // clientes conectados reciben evento "exit" con el
                    // PID y el codigo en R0 + err_thread para que
                    // distingan HALT normal de DEAD/abort.
                    if (vm_reference.debugger != nullptr) {
                        vm_reference.debugger->on_process_exit(
                            instance->pid.local_pid);
                    }
                    // notificar al nodo origen si el proceso vino de un rspawn
                    // remoto
                    if (instance->rspawn_future_id != 0 &&
                        instance->rspawn_origin_node != 0xFFFFFFFFu &&
                        vm_reference.dist_runtime) {
                        vm_reference.dist_runtime->notify_rspawn_halt(instance);
                    }
                    instance = nullptr;
                    break;
                }
                if (instance->state == WAIT_IO || instance->state == BLOCKED) {
                    // (slow path): mismo double-check que
                    // en fast path.  Si un make_ready remoto seteo
                    // wake_pending entre EXECUTE y aqui, abortar la
                    // dormida y reencolar.
                    if (instance->wake_pending.exchange(
                            false, std::memory_order_acq_rel)) {
                        instance->state.store(READY, std::memory_order_release);
                        std::lock_guard<std::mutex> lock(queue_mutex);
                        ready_queue.push_back(instance);
                        instance = nullptr;
                        break;
                    }
                    instance = nullptr; // el proceso espera un evento externo
                    break;
                }
            }
        }

        // si instance es nulo el proceso ya fue gestionado en el bloque
        // anterior
        if (instance == nullptr) {
            continue;
        }

        // el proceso agoto sus reducciones: ceder la CPU y reencolar en READY
        if (instance->reductions_remaining == 0) {
            on_event(EVT_YIELD); // transicion a READY por fin de quantum
        }

        // reencolar el proceso si sigue en estado ejecutable
        if (instance->state == READY) {
            std::lock_guard<std::mutex> lock(queue_mutex);
            ready_queue.push_back(
                instance); // volver a poner al final de la cola FIFO
        }
    }
}

#pragma GCC diagnostic pop

/**
 * @brief Genera una representacion textual del scheduler para depuracion.
 * @return Cadena con el ID, estado, contadores de procesos y tiempos.
 */
std::string Scheduler::to_string() const {
    std::ostringstream ss;

    ss << "Scheduler[" << id_scheduler << "] {\n"
       << "  waiting: " << (is_waiting ? "yes" : "no") << "\n"
       << "  should_kill: " << (should_kill ? "yes" : "no") << "\n"
       << "  profiler_running: " << (profiler_running ? "yes" : "no") << "\n"
       << "  processes_total: " << processes.size() << "\n"
       << "  ready_queue: " << ready_queue.size() << "\n"
       << "  alive_processes: " << vm_reference.has_alive_processes() << "\n"
       << "  reductions_now: " << reductions_now << "\n"
       << "  profiler_instr_counter: " << profiler_instr_counter << "\n"
       << "  time_exec(ns): " << time_exec << "\n"
       << "  time_decode(ns): " << time_decode << "\n"
       << "  time_event(ns): " << time_event << "\n"
       << "}";

    return ss.str();
}

/**
 * @brief Reinicia el estado interno del scheduler sin destruirlo.
 *
 * Limpia colas, indices, procesos, contadores y banderas para que el
 * scheduler pueda reutilizarse en un nuevo ciclo de ejecucion.
 */
void Scheduler::reset() {
    // limpiar estructuras de datos del scheduler
    ready_queue.clear(); // vaciar la cola de procesos listos
    pid_index.clear();   // limpiar el indice PID -> proceso
    processes.clear();   // liberar todos los procesos (unique_ptr los destruye)

    // reiniciar contadores de ejecucion
    next_pid = 0;       // reiniciar generador de PIDs locales
    reductions_now = 0; // reiniciar contador de reducciones del quantum actual
    profiler_instr_counter = 0; // reiniciar muestras del profiler
    time_exec = 0;              // reiniciar tiempo de ejecucion acumulado
    time_decode = 0;            // reiniciar tiempo de descodificacion acumulado
    time_event = 0;             // reiniciar tiempo de transiciones acumulado

    // reiniciar banderas de control
    is_waiting = false;       // no estamos esperando en el semaforo
    should_kill = false;      // no hay solicitud de parada
    profiler_running = false; // profiler desactivado hasta nueva configuracion
    alive_count = 0;          // ningun proceso vivo

    instance = nullptr; // ninguna instancia activa
}

/**
 * @brief Extrae el proximo proceso de la cola FIFO de procesos listos.
 *
 * Reinicia el contador de reducciones del proceso seleccionado al valor
 * por defecto y actualiza el puntero instance.
 *
 * @return Puntero al proximo proceso listo, o nullptr si la cola esta vacia.
 */
ProcessVM *Scheduler::schedule_next() {
    std::lock_guard<std::mutex> lock(
        queue_mutex); // proteger el acceso concurrente a ready_queue
    if (ready_queue.empty())
        return nullptr; // no hay procesos listos en la cola

    ProcessVM *p =
        ready_queue.front(); // obtener el proceso al frente de la cola FIFO
    ready_queue.pop_front(); // eliminarlo de la cola

    p->reductions_remaining =
        reductions_remaining_default; // reiniciar el quantum del proceso
    instance = p; // actualizar el puntero de instancia activa
    return p;
}

/**
 * @brief Crea un nuevo proceso virtual en este scheduler.
 *
 * Asigna un PID local, construye el ProcessVM, lo registra en el indice
 * de PIDs y devuelve su GlobalPID.  El proceso nace en estado NEW.
 *
 * @return PID global del proceso recien creado.
 */
GlobalPID Scheduler::spawn() {
    GlobalPID pid = {id_scheduler,
                     next_pid++}; // construir PID global con nuevo ID local

    auto proc = std::make_unique<ProcessVM>(*this, pid); // crear el proceso
    ProcessVM *raw = proc.get(); // guardar raw pointer antes de mover

    processes.push_back(std::move(proc)); // transferir propiedad al vector
    pid_index[pid] = raw; // registrar en el indice para busqueda O(1)

    return pid;
}

/**
 * @brief Pone el proceso con el PID indicado en estado READY y lo encola.
 *
 * Si el proceso estaba en NEW, HALT o DEAD se incrementa alive_count.
 * Las llamadas posteriores (p.ej. tras WAIT_IO) no modifican el contador.
 *
 * @param pid PID global del proceso que debe pasar a estado READY.
 */
void Scheduler::make_ready(GlobalPID pid) {
    ProcessVM *p = pid_index[pid]; // buscar el proceso por PID en O(1)

    // poner wake_pending=true ANTES de leer state.  Esto
    // garantiza que si el scheduler propietario observa wake_pending
    // tras CAS EXECUTE->WAIT_IO, ve la senal y aborta la transicion.
    p->wake_pending.store(true, std::memory_order_release);

    // CAS-loop: solo transicionar a READY desde un estado durmiente
    // (NEW, HALT, DEAD, WAIT_IO, BLOCKED).  Si esta activo
    // (READY/RUNNING/DECODE/EXECUTE), no tocar el state: el wake_pending
    // ya quedo marcado para el scheduler propietario.
    vm_state prev = p->state.load(std::memory_order_acquire);
    while (prev == NEW || prev == HALT || prev == DEAD || prev == WAIT_IO ||
           prev == BLOCKED) {
        if (p->state.compare_exchange_weak(prev, READY,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
            // Transicion exitosa.  El wake_pending lo limpiamos porque
            // la accion de despertar ya esta consumida (encolaremos abajo).
            p->wake_pending.store(false, std::memory_order_release);

            // incrementar alive_count solo la primera vez o al reactivar
            if (prev == NEW || prev == HALT || prev == DEAD)
                alive_count++; // el proceso pasa a contar como "vivo"

            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                ready_queue.push_back(p); // insertar al final de la cola FIFO
            }
            return;
        }
        // CAS fallo: prev fue actualizado por compare_exchange_weak con
        // el valor real; reintentar.
    }
    // Estado activo: no reencolar, pero wake_pending queda marcado para
    // que el scheduler propietario lo respete antes de dormirse.
}

/**
 * @brief Elimina el proceso con el PID indicado del scheduler.
 *
 * Decrementa alive_count si el proceso era "vivo", elimina su entrada del
 * indice y lo borra del vector con la tecnica swap-and-pop O(1).
 *
 * @param pid PID global del proceso a eliminar.
 */
void Scheduler::kill(GlobalPID pid) {
    auto it = pid_index.find(pid);     // buscar por PID en el indice
    if (it == pid_index.end()) return; // PID no encontrado; nada que hacer

    ProcessVM *p = it->second;

    // decrementar alive_count solo si el proceso era "vivo"
    if (p->state != NEW && p->state != DEAD && p->state != HALT) alive_count--;

    pid_index.erase(it); // eliminar del indice de PIDs

    // swap-and-pop O(1): mover el ultimo elemento al hueco y eliminar el ultimo
    for (size_t i = 0; i < processes.size(); i++) {
        if (processes[i].get() == p) {
            if (i != processes.size() - 1)
                processes[i] = std::move(
                    processes.back()); // llenar el hueco con el ultimo
            processes
                .pop_back(); // eliminar el ultimo (que era el proceso a borrar)
            break;
        }
    }
}

/**
 * @brief Registra un hook de depuracion sin sincronizacion (solo antes del
 * inicio).
 *
 * @param hook Callback de depuracion a anadir.
 */
void Scheduler::free_add_debug_hook(DebugHook hook) {
    debug_hooks.push_back(hook); // anadir al vector de hooks sin sincronizacion
    has_hooks = true;            // activar el slow path en run_loop
}

/**
 * @brief Registra un hook de depuracion de forma thread-safe.
 *
 * Actualmente delega en free_add_debug_hook(); anadir mutex si se necesita
 * registrar hooks mientras el scheduler ya esta en ejecucion.
 *
 * @param hook Callback de depuracion a anadir.
 */
void Scheduler::add_debug_hook(DebugHook hook) {
    free_add_debug_hook(hook); // delegar en la version sin sincronizacion
}

#ifdef PROFILE_FAST
// vm_hook sustituida por macro vacia cuando PROFILE_FAST esta definido
#else
/**
 * @brief Invoca todos los hooks de depuracion del scheduler del proceso.
 *
 * Si el scheduler no tiene hooks activos (has_hooks=false) retorna
 * inmediatamente sin iterarlos para minimizar la penalizacion en el hot path.
 *
 * @param process Proceso cuyo scheduler contiene los hooks.
 * @param stage   Fase del pipeline en la que se disparan los hooks.
 */
void vm_hook(ProcessVM *process, DebugStage stage) {
    if (!process->scheduler.has_hooks)
        return; // salida rapida si no hay hooks registrados

    for (auto &hook : process->scheduler.debug_hooks)
        hook(process,
             stage); // invocar cada hook con el proceso y la fase actual
}
#endif

/**
 * @brief Ejecuta la transicion de la FSM correspondiente al evento @p e.
 *
 * Consulta fsm[instance->state][e], ejecuta la accion asociada (si existe)
 * y actualiza el estado del proceso al estado siguiente de la tabla.
 *
 * @param e Evento que desencadena la transicion.
 */
void Scheduler::on_event(vm_event e) {
    const Transition &t =
        fsm[instance->state][e]; // obtener la transicion de la tabla

    if (t.action)
        t.action(instance); // ejecutar la accion de la transicion si existe

    instance->state = t.next; // cambiar el proceso al estado siguiente
}

/**
 * @brief Hilo de perfilado continuo para un scheduler.
 *
 * Duerme un segundo, calcula IPS (instrucciones por segundo) y el porcentaje
 * de CPU consumido por la fase de ejecucion, e imprime los resultados con
 * vesta::scout() (thread-safe).
 *
 * Se detiene cuando should_kill, !profiler_running o !vm_running sean true,
 * o cuando el scheduler este esperando (is_waiting=true).
 *
 * @param scheduler Puntero al scheduler que se va a perfilar.
 */
void profiler_thread(Scheduler *scheduler) {
    uint64_t last_instr = 0; // ultimo valor del contador de instrucciones leido
    uint64_t last_exec = 0;  // ultimo valor del tiempo de ejecucion leido (ns)

    while (scheduler->profiler_running && !scheduler->should_kill &&
           scheduler->vm_reference.vm_running &&
           scheduler->is_waiting != true) {
        std::this_thread::sleep_for(
            std::chrono::seconds(1)); // muestrear cada segundo

        // calcular delta de instrucciones en el ultimo segundo
        uint64_t now_instr = scheduler->profiler_instr_counter;
        uint64_t delta_instr =
            now_instr - last_instr; // variacion desde la ultima muestra
        last_instr = now_instr;     // actualizar el ultimo valor

        // IPS: profiler_instr_counter se incrementa cada 256 instrucciones
        uint64_t ips = delta_instr;

        // calcular porcentaje de CPU usando el tiempo de ejecucion acumulado
        uint64_t now_exec = scheduler->time_exec;
        uint64_t delta_exec =
            now_exec - last_exec; // nanosegundos ocupados en el ultimo segundo
        last_exec = now_exec;

        double cpu = ((double(delta_exec) / 1e9) *
                      100.0);         // convertir ns a porcentaje de segundo
        if (cpu > 100.0) cpu = 100.0; // saturar al maximo fisico posible

        // imprimir estadisticas usando la salida thread-safe
        vesta::scout() << "[scheduler " << scheduler->id_scheduler << "] "
                       << "IPS=" << ips << " | CPU=" << cpu << "%\n";
    }
}

} // namespace runtime
