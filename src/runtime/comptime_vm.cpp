/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file comptime_vm.cpp
 * @brief Implementacion del scaffolding de @c ComptimeRuntime (  ).
 *
 * En este sprint la clase es funcional pero la ejecucion via VM esta
 * stub-eada -- el @c try_invoke siempre retorna @c false (caller
 * fallback al AST evaluator).  Esto permite construir, registrar
 * macros, contar invocaciones, sin necesitar la VM operativa.
 *
 *   implementara la VM real (bootstrap del runtime::VM con un
 * .velb in-memory que contenga los `__macro_*` lowered).
 */

#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include "util/env_flags.h"
#include "vx/comptime/comptime_vm.h"
#include "vx/type_checker.h" // report_comptime_fatal

/* Headers runtime full: estos pueden cascade-incluir openssl/capstone
 * pero solo se compilan en este TU (no se filtran al header publico
 * de @c ComptimeRuntime gracias al pimpl). */
#include "runtime/manager_runtime.h"
#include "runtime/runtime.h"
#include "runtime/exception_runtime.h" // build_stack_trace del fallo
#include "runtime/string_runtime.h"    /*   : make_string_flat */
#include "loader/loader.h"
#include "distrib/dist_runtime.h" /* dtor de VM destruye DistRuntime via unique_ptr */
#include "jit/auto_jit.h"         /*   : eager-compile macros */
#include "ffi/virtual_lib_registry.h" /* #3: resolver vrt:* en el JIT del CV */
#include "jit/interp_jit_bridge.h"    /* CTPE: enter_jit (invocacion directa) */
#include "jit/jit_compile_options.h"  /* CompileResult */
#include "jit/vreg_pipeline.h" /* CTPE: vreg_set_ctpe_safepoint_handler */

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib> //   : snprintf para hex-encode del hash
#include <cstring>
#include <thread>
#include <vector>

namespace vx {

std::string comptime_read_vm_string(uint64_t proc_ptr, uint64_t addr,
                                    uint64_t len) {
    auto *proc = reinterpret_cast<runtime::ProcessVM *>(proc_ptr);
    if (!proc || len == 0 || len > 4096) return std::string();
    std::vector<char> buf(len + 1, 0);
    proc->vm_mem.read_bytes(addr, buf.data(), len);
    return std::string(buf.data(), len);
}

/**
 * @brief Pimpl interno de @c ComptimeRuntime.  Contiene todo el
 * estado runtime necesario para ejecutar @Macros lowered al IR.
 *
 *   (este sprint): bootstrap del runtime::VM + ManageVM in-process,
 * sin file I/O.  Lazy-init en el primer @c try_invoke().
 *
 *   (proximo): @c load_macros_from_bytes() cargara el bytecode
 * de los @Macros via @c Loader::load_executable(vm, bytes) y
 * registrara los entry PCs reales por nombre.
 *
 * @note Una sola VM cross-macro per-compile: no se reinstancia.
 */
struct ComptimeVmImpl {
    /**
     * @brief Manager-VM minimo (listener=nullptr -> modo local sin
     * red).  Owner del Loader, que se usa para load_executable
     * desde un buffer in-memory de bytes.
     */
    runtime::ManageVM mgr;

    /**
     * @brief VM dedicada a ejecucion comptime.  1 scheduler (single
     * threaded) suficiente para evaluacion sequential de macros.
     */
    runtime::VM vm;

    /**
     * @brief Bytecode de los @Macros cargados.  Sera populado en
     *   con los bytes resultantes del linker sobre las
     * IrFunction __macro_*.  En   queda vacio (no se carga nada
     * todavia, solo se valida que el VM ciclo de vida funciona).
     */
    std::vector<uint8_t> macros_bytecode;

    /**
     * @brief Proceso recien creado por @c Loader::load_executable.
     * Reusado entre invocaciones ( ): tras HALT, lo reactivamos
     * con make_ready + nuevo entry_pc + nuevos args.  Permite N
     * invocaciones por @c ComptimeRuntime sin overhead de spawning
     * fresco ni file I/O.
     */
    runtime::ProcessVM *proc = nullptr;

    /**
     * @brief PID global del proceso, requerido por @c make_ready.
     */
    ::GlobalPID proc_pid{};

    /**
     * @brief RSP inicial (= stack base - 8) populado por Loader.
     *   lo re-aplica al inicio de cada call para que el stack
     * empiece limpio con la direccion del sentinel HLT pre-pushed.
     */
    uint64_t initial_rsp = 0;

    /**
     * @brief Los argumentos AGREGADOS de la llamada en curso.
     *
     * Un struct, un enum, un `Optional` o un `Result` no caben en un registro:
     * se pasan por DIRECCION.  Y la direccion es del HOST, no de la maquina:
     * el codigo del conjunto los toca con accesos de host -- igual que el
     * bufer de RETORNO, que es `out_bytes.data()` --, asi que darle una
     * direccion de la maquina es darle un puntero que no sabe leer.
     *
     * Viven aqui, y no en la pila del macro, porque asi es exactamente el
     * mismo trato que el bufer de retorno, que ya funcionaba.  Se sueltan al
     * terminar cada llamada: valen para UNA, que es lo que dura el argumento.
     */
    std::vector<std::vector<uint8_t>> agg_args;

    /**
     * @brief VA donde Loader escribio los bytes HLT (0x00 0x03) que
     * actuan como direccion de retorno final del macro.    lo
     * re-pushea en cada call para garantizar HLT clean al ret.
     */
    uint64_t hlt_sentinel_va = 0;

    /**
     * @brief Flag: ¿hemos llamado @c vm.start() ya?  Lazy: la primera
     * @c invoke_simple_macro lo activa.  Schedulers se quedan vivos
     * mientras el proceso este en estado HALT (no DEAD), permitiendo
     * re-activarlo con make_ready en subsequent calls.
     */
    bool vm_started = false;

    /**
     * @brief   : cache `entry_pc -> jit_code_ptr`.  Populado
     * por @c load_macros_from_bytes con eager-compile de cada macro
     * registrado.  Si la compile JIT falla (unsupported IR ops, etc.)
     * la entrada queda en @c nullptr y la macro corre via interp.
     *
     * En @c invoke_simple_macro consultamos este mapa con el entry_pc
     * del macro a invocar; si hay fn_ptr, lo asignamos a
     * @c proc->jit_entry_fn antes de @c vm.start() asi el scheduler
     * salta directo al codigo nativo (sin overhead de dispatch interp).
     */
    std::unordered_map<uint64_t, void *> jit_code_by_pc;

    /**
     * @brief    (A: Lazy GC): contador de invocaciones desde
     * el ultimo @c major_gc().  El GC sweep se ejecuta solo cuando
     * supera el threshold (default 64), no en CADA invocacion.
     *
     * Costo amortizado: ~10us / 64 calls = ~0.15us por call vs ~10us
     * en el modelo per-call.  Para macros invocados muchas veces
     * (caso de cache memo o composicion), reduce overhead GC en
     * ~98%.  El peak memory queda bounded a ~64 * 128 B = 8 KB lo
     * cual es perfectamente aceptable.
     *
     * Override via env var @c VESTA_MC_GC_INTERVAL.  Valor 0 = GC
     * cada call (modo original); valor grande = menos GCs pero
     * mayor peak memory.
     */
    uint64_t invocations_since_gc = 0;
    uint64_t gc_interval = 64; /* Default threshold. */

    /**
     * @brief Construye la VM con configuracion minimal: 1 scheduler,
     * sin TCP listener.  Maneja la cadena de inicializacion en el
     * orden correcto (mgr antes que vm).
     *
     * @param mgr_id   ID arbitrario para el manager (cualquier valor).
     * @param vm_id    ID arbitrario para la VM.
     * @param n_sched  Numero de schedulers (1 = single threaded, lo
     *                 mas ligero posible).
     */
    ComptimeVmImpl()
        : mgr(/*listener=*/nullptr, /*id=*/0xC03171EULL),
          vm(mgr, /*id_vm=*/0xC03171EULL, /*num_schedulers=*/1) {
        /*   : configurar GC interval desde env var.
         * Default = 64 (good tradeoff entre peak memory y overhead). */
        {
            const long v = util::flag_int(util::FlagId::McGcInterval, -1);
            if (v >= 0) gc_interval = static_cast<uint64_t>(v);
        }
    }
};

ComptimeRuntime::ComptimeRuntime() noexcept = default;

ComptimeRuntime::~ComptimeRuntime() = default;

void ComptimeRuntime::register_macro(const std::string &macro_name,
                                     uint64_t entry_pc) {
    /* Un marcador nunca pisa una direccion ya resuelta.  El lowering registra
     * el nombre ANTES de que exista bytecode -- para que el chequeo de tipos
     * sepa que el macro existe --, y si el artefacto ya se cargo y trajo la
     * direccion real, ese registro tardio no tiene nada que aportar.  Sin esta
     * guarda, al recompilar en caliente el marcador borraba la direccion buena
     * y la invocacion saltaba al principio del modulo. */
    if (entry_pc == kPcUnresolved) {
        macro_entry_pc_.emplace(macro_name, kPcUnresolved);
        return;
    }
    macro_entry_pc_[macro_name] = entry_pc;
}

bool ComptimeRuntime::try_invoke(const std::string &macro_name) noexcept {
    /*   : VM lifecycle bootstrap funcional pero la ejecucion
     * real todavia no esta wired (  añade load + marshalling +
     * call).  El caller debe seguir interpretando @c false como
     * "fallback al AST evaluator".
     *
     * Despues de   esto sera:
     *   1. Lookup en macro_entry_pc_.  Si no esta -> false.
     *   2. ensure_vm_initialized() -- lazy bootstrap.
     *   3. Verificar que el bytecode esta cargado.
     *   4. Marshalling args -> VM regs.
     *   5. Spawn process en entry_pc, run hasta retorno.
     *   6. Read R0 -> out_result.
     *   7. Cache si @Pure.
     */
    (void)macro_name;
    return false;
}

void ComptimeRuntime::ensure_vm_initialized() noexcept {
    if (impl_) return;
    try {
        impl_.reset(new ComptimeVmImpl());
    } catch (...) {
        /* Bootstrap fallo (e.g., out-of-memory creando Loader).
         * Dejamos impl_ en nullptr para que try_invoke devuelva
         * false y el caller use el AST evaluator. */
        impl_.reset();
    }
}

bool ComptimeRuntime::invoke_simple_macro(const std::string &macro_name,
                                          const std::vector<uint64_t> &args,
                                          uint64_t &out_r0) noexcept {
    out_r0 = 0;
    /* El hueco de los argumentos agregados se devuelve al SALIR, pase lo que
     * pase: sus bufers valen para esta llamada y solo para esta.  Devolverlo al
     * entrar borraria lo que el llamante acaba de dejar ahi. */
    struct DevolverHueco {
        ComptimeVmImpl *im;
        ~DevolverHueco() {
            if (im) im->agg_args.clear();
        }
    } devolver{impl_.get()};
    if (args.size() > 12) return false;       /* CALLVM max */
    if (!impl_ || !impl_->proc) return false; /* No VM cargado. */
    auto it = macro_entry_pc_.find(macro_name);
    if (it == macro_entry_pc_.end()) return false;
    const uint64_t entry_pc = it->second;
    /* Sin direccion no hay invocacion.  Antes ni se miraba: el marcador valia
     * 0, que es una direccion legitima, asi que la VM saltaba al principio del
     * modulo y ejecutaba la primera funcion que hubiera con los argumentos de
     * esta en los registros.  Devolver `false` es el contrato de siempre para
     * "todavia no se puede": el llamante lo reintenta cuando el artefacto este
     * cargado. */
    if (entry_pc == kPcUnresolved) return false;

    try {
        runtime::ProcessVM *proc = impl_->proc;

        /*  : reset estado del proceso para soportar multi-call.
         * Tras un HALT previo, el RSP puede estar desplazado y el
         * stack puede tener data residual.  Restauramos al estado
         * inicial que setup load_executable, re-pusheando el
         * sentinel HLT como direccion de retorno final del macro. */
        proc->registers.stack_pointer.qword(impl_->initial_rsp);
        proc->registers.base_pointer.qword(impl_->initial_rsp);
        proc->vm_mem.vm_to_host_memcpy(impl_->initial_rsp,
                                       &impl_->hlt_sentinel_va,
                                       sizeof(impl_->hlt_sentinel_va));
        proc->stack_high = impl_->initial_rsp;
        proc->stack_low_water = impl_->initial_rsp;

        /* Set RIP + args (CALLVM convention). */
        proc->registers.rip.qword(entry_pc);
        for (size_t i = 0; i < args.size(); ++i) {
            proc->registers.regs[i + 1].qword(args[i]);
        }
        proc->registers.regs[15].qword(args.size());

        /*   multi-call pattern -- aprovecha el single-scheduler
         * sync bypass de vm.start() (runtime.cpp:140-151): con 1
         * scheduler + non-persistent, start() ejecuta run_loop
         * SINCRONAMENTE en el thread llamante, bloqueando hasta
         * que el proceso HALT.  start() es idempotente: cada call
         * vm_running=true al entrar, =false al salir.  No necesita
         * vm.wait().
         *
         * Beneficios:
         *   - Cero coste de thread spawn (mismo thread).
         *   - Multi-call funciona out-of-the-box (cada call es una
         *     sesion completa start->halt->return).
         *   - Determinista: no hay race conditions inter-call.
         */
        /*   : si la macro fue eager-compilada via JIT,
         * setear @c jit_entry_fn antes del start.  El scheduler
         * salta directo al codigo nativo (skip interp dispatch).
         * Cero impacto si la macro no compilo (jit_entry_fn=null). */
        auto jit_it = impl_->jit_code_by_pc.find(entry_pc);
        if (jit_it != impl_->jit_code_by_pc.end() && jit_it->second) {
            proc->jit_entry_fn = jit_it->second;
        } else {
            /* BUG FIX: si ESTE macro no tiene codigo JIT eager, hay que LIMPIAR
             * jit_entry_fn -- si no, un valor STALE de un macro anterior (o de
             * otra fn eager-compilada) haria que el scheduler salte a codigo
             * nativo AJENO (JIT-ENTRY path), ejecutando la fn equivocada y
             * devolviendo basura (p.ej. un macro string que devolvia el entero
             * 40+2=42 en vez del handle).  Con jit_entry_fn=null el proceso
             * ejecuta ESTE macro por interp, que es correcto. */
            proc->jit_entry_fn = nullptr;
        }
        proc->err_thread = runtime::THREAD_NO_ERROR;
        impl_->vm.make_ready(impl_->proc_pid);
        impl_->vm.start();
        impl_->vm_started = true;

        /* Si el codigo comptime murio -- un `panic`, una asercion incumplida,
         * una division por cero -- hay que DECIRLO.  Sin esto el proceso
         * quedaba muerto en silencio y se leia R0 igual, con lo que el valor
         * que se horneaba en el binario era basura de un calculo que nunca
         * termino.  Se imprime el mensaje y el curso de llamadas que llevo
         * hasta el fallo, que es lo que permite localizarlo. */
        if (proc->err_thread != runtime::THREAD_NO_ERROR) {
            const char *msg = (proc->fatal_msg_buf && proc->fatal_msg_buf[0])
                                  ? proc->fatal_msg_buf
                                  : "la ejecucion en tiempo de compilacion "
                                    "termino con un error";
            std::fprintf(stderr, "error: %s\n", msg);
            /* Y que la compilacion falle: el valor que se hubiera horneado
             * viene de un calculo que no llego a terminar. */
            report_comptime_fatal(msg);
            /* La traza la dejo escrita el propio fallo, cuando el proceso
             * aun estaba coherente.  Reconstruirla ahora seria recorrer
             * marcos que ya no son de fiar. */
            if (proc->fatal_trace_buf && proc->fatal_trace_buf[0])
                std::fprintf(stderr, "%s\n", proc->fatal_trace_buf);
            std::fflush(stderr);
            return false;
        }

        /* Lee R0 del proceso completado. */
        out_r0 = proc->registers.regs[0].qword();
        ++call_count_;
        return true;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
//  CTPE (Compile-Time Program Execution) -- modo RESTRINGIDO.
//
//  A diferencia de la invocacion de @Macro (sin restriccion, responsabilidad
//  del programador), el CTPE inferido corre en SANDBOX: capacidades externas
//  DENEGADAS.  Reusa el MISMO ComptimeRuntime (motor global) pero con caps
//  restringidas SOLO durante esta invocacion; se restauran al salir para no
//  afectar a los @Macro.  El trap del sandbox + el catch(...) de
//  invoke_simple_macro garantizan el fallback si la ejecucion real toca algo
//  prohibido.
//
//  Pendiente (siguiente incremento): watchdog de TIEMPO (safepoint_flag +
//  throw_fatal/longjmp) y tope de HEAP (GcHeap max_bytes).  El presupuesto ya
//  se recibe; hoy solo se aplican las caps.
// ---------------------------------------------------------------------------
bool ComptimeRuntime::try_invoke_ctpe(const std::string &fn_name,
                                      const std::vector<uint64_t> &args,
                                      const CtpeBudget &budget,
                                      uint64_t &out_r0) noexcept {
    if (!impl_ || !impl_->proc) return false;
    auto &execs = impl_->mgr.loader.executables;
    if (execs.empty()) return false;
    auto &exe = execs.back();

    // 1) Registrar + eager-compilar la funcion regular on-demand (una vez).  El
    //    Executable ya esta en memoria (cero ficheros): su entry_pc sale del
    //    symbol_table (`code.<fn>`) y su IR del ir_lookup/ir_functions.
    if (!macro_entry_pc_.count(fn_name)) {
        auto sit = exe->symbol_table.find("code." + fn_name);
        if (sit == exe->symbol_table.end()) return false;
        register_macro(fn_name, sit->second);
        auto fnit = exe->ir_lookup.find(fn_name);
        if (fnit != exe->ir_lookup.end() &&
            fnit->second < exe->ir_functions.size()) {
            const uint32_t saved_th = jit::g_jit_threshold;
            if (saved_th == UINT32_MAX) jit::g_jit_threshold = 1;
            // El handler de safepoint (watchdog) lo activa el orquestador CTPE
            // (compiler.cpp) ANTES de load_macros_from_bytes -- porque main se
            // JIT-compila al cargar el .velb, antes de este eager_compile. Aqui
            // solo compilamos; el codigo ya lleva los polls.
            try {
                jit::CompileResult res = jit::eager_compile_function(
                    exe->ir_functions[fnit->second], &exe->ir_lookup,
                    &exe->ir_functions, &exe->symbol_table);
                if (res.fn)
                    impl_->jit_code_by_pc[sit->second] =
                        reinterpret_cast<void *>(res.fn);
            } catch (...) {
            }
            jit::g_jit_threshold = saved_th;
        }
    }

    // 1.5) Requerir JIT: CTPE solo ejecuta el programa si su entry (main)
    //      JIT-compilo.  El watchdog de tiempo vive en el poll de safepoint que
    //      emite el JIT en cada back-edge; el interprete no lo tiene, asi que
    //      un main NO-JIT-able podria colgar la compilacion sin abortar.  Si no
    //      hay codigo nativo -> no plegar (fallback: corre en runtime normal).
    auto pcit = macro_entry_pc_.find(fn_name);
    if (pcit == macro_entry_pc_.end()) return false;
    if (!impl_->jit_code_by_pc.count(pcit->second)) return false;

    // 2) Sandbox CTPE: DENEGAR las capacidades externas.  Cualquier op que las
    //    use (CALLN/dlopen/spawn/msgsend-remoto/loadmod/...) trapea ->
    //    FatalError
    //    -> el catch(...) de invoke_simple_macro devuelve false -> fallback. Se
    //    conserva MEM_HOST (acceso normal a objetos) y CLASSREG (inofensivo: el
    //    pre-filtro ya excluye la metaprogramacion).
    const uint32_t deny = loader::Caps::FS_READ | loader::Caps::FS_WRITE |
                          loader::Caps::NET | loader::Caps::FFI_CALL |
                          loader::Caps::FFI_OPEN | loader::Caps::SPAWN |
                          loader::Caps::DISTRIB | loader::Caps::LOADMOD;
    const uint32_t saved_bits = exe->caps.bits;
    exe->caps.bits = saved_bits & ~deny;

    // 3) Watchdog de tiempo: hilo temporizador que, al vencer el presupuesto,
    //    pide abortar (vrt_ctpe_request_abort) y patea el safepoint_flag.  El
    //    poll del JIT lo consulta en el proximo back-edge -> throw_fatal ->
    //    invoke_simple_macro devuelve false -> no se pliega.  Configurable por
    //    VESTA_CTPE_MS (default = budget.millis, o 3000).
    uint32_t ms = budget.millis ? budget.millis : 3000;
    {
        /* Si no es un numero, el registro devuelve el valor por defecto que se
         * le pide, que es lo mismo que hacia antes al no poder convertirlo. */
        const long v = util::flag_int(util::FlagId::CtpeMs, -1);
        if (v >= 0) ms = static_cast<uint32_t>(v);
    }
    std::atomic<bool> done{false};
    runtime::ProcessVM *proc_ptr = impl_->proc;
    proc_ptr->ctpe_abort = 0;
    proc_ptr->ctpe_did_abort = 0;
    std::thread watch([&done, ms, proc_ptr]() {
        uint32_t waited = 0;
        while (waited < ms) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            if (done.load(std::memory_order_relaxed)) return;
            waited += 5;
        }
        // Deadline: marcar aborto ANTES de patear el flag (evita la carrera en
        // que el poll ve el flag pero aun no el aborto).  Ambos viven en el
        // ProcessVM -> el handler (en vesta_rt) ve la misma instancia.
        proc_ptr->ctpe_abort = 1;
        proc_ptr->safepoint_flag = 1;
    });

    // Invocacion DIRECTA del codigo JIT: sin make_ready, sin scheduler y sin el
    // run-loop de la VM.  CTPE es JIT; el interprete solo es fallback.
    //
    // Hay que replicar la red de recuperacion que el scheduler arma alrededor
    // de `jit_entry_fn` (scheduler.cpp): sin ella, un throw del propio programa
    // --o el longjmp con que el watchdog aborta desde el poll de safepoint--
    // escapa y se lleva por delante la compilacion entera.  Quitar el
    // envoltorio de VM no puede significar quitar tambien esa red.
    //
    // `ok` es volatile: lo escribe la rama normal y lo lee codigo alcanzable
    // por longjmp, donde una local no-volatile queda indeterminada.
    volatile bool ok = false;
    out_r0 = 0;
    {
        runtime::ProcessVM *proc = impl_->proc;
        // Estado inicial de pila: lo consume el bajado de VM para sus ALLOCA.
        proc->registers.stack_pointer.qword(impl_->initial_rsp);
        proc->registers.base_pointer.qword(impl_->initial_rsp);
        proc->vm_mem.vm_to_host_memcpy(impl_->initial_rsp,
                                       &impl_->hlt_sentinel_va,
                                       sizeof(impl_->hlt_sentinel_va));
        proc->stack_high = impl_->initial_rsp;
        proc->stack_low_water = impl_->initial_rsp;

        proc->registers.rip.qword(pcit->second);
        for (size_t i = 0; i < args.size(); ++i)
            proc->registers.regs[i + 1].qword(args[i]);
        proc->registers.regs[15].qword(args.size());
        proc->jit_entry_fn = nullptr; // no se pasa por el scheduler.

        jit::JitFn jf =
            reinterpret_cast<jit::JitFn>(impl_->jit_code_by_pc[pcit->second]);
        proc->state.store(runtime::EXECUTE, std::memory_order_relaxed);
        proc->av_recovery_active = true;
        // setjmp == 0: ejecucion normal.  != 0: hubo longjmp (aborto del
        // watchdog o fallo recuperado) -> no hay resultado fiable, no se
        // pliega.
        if (setjmp(proc->av_recovery_jmpbuf) == 0) {
            try {
                (void)jit::enter_jit(jf, reinterpret_cast<vrt_proc *>(proc));
                out_r0 = proc->registers.regs[0].qword();
                ok = true;
            } catch (...) {
                ok = false;
            }
        }
        proc->av_recovery_active = false;
        proc->state.store(runtime::HALT, std::memory_order_release);
    }

    done.store(true, std::memory_order_relaxed);
    watch.join();
    const bool aborted = proc_ptr->ctpe_did_abort != 0;
    proc_ptr->ctpe_abort = 0;
    proc_ptr->safepoint_flag = 0;
    proc_ptr->ctpe_did_abort = 0;
    // Restaurar SIEMPRE, tambien en los caminos de fallo: antes se salia por el
    // `return false` del aborto sin restaurarlas y el ejecutable se quedaba con
    // las capacidades denegadas durante el resto de la compilacion, afectando a
    // los @Macro posteriores.
    exe->caps.bits = saved_bits;

    // El watchdog aborto la ejecucion (longjmp): el resultado seria parcial ->
    // NO plegar (fallback: main corre en runtime).
    if (aborted) return false;

    // El proceso murio por error FATAL (una capacidad denegada por el sandbox,
    // un deref invalido, cualquier trap).  @c invoke_simple_macro NO se entera:
    // la VM AISLA el fallo -- mata el proceso y retorna con normalidad, sin
    // lanzar ninguna excepcion que su `catch (...)` pueda ver -- asi que
    // devuelve true y R0 conserva un valor RESIDUAL.  Plegar eso hornea un
    // numero inventado en el binario, y el sintoma aparece lejisimos: en el
    // resultado del programa ya compilado.  Regla: si el programa no termino
    // LIMPIO no se pliega nada; esa funcion se compila con normalidad.
    if (impl_->proc->state.load(std::memory_order_relaxed) == runtime::DEAD)
        return false;

    return ok;
}

/**
 * @brief    -- construye la clave del cache memoization.
 *
 * Hash FNV-1a 64-bit sobre @c args concatenado al @c macro_name con
 * separador.  Suficientemente determinista para que dos call sites
 * con misma firma colisionen en la misma entrada.  No criptografica
 * pero rapida (~2 ns por arg).
 */
static std::string build_memo_key(const std::string &macro_name,
                                  const std::vector<uint64_t> &args) {
    constexpr uint64_t FNV_OFFSET = util::kFnvOffset;
    constexpr uint64_t FNV_PRIME = util::kFnvPrime;
    uint64_t h = FNV_OFFSET;
    for (char c : macro_name) {
        h ^= static_cast<uint8_t>(c);
        h *= FNV_PRIME;
    }
    h ^= 0xFF; /* separador entre name y args. */
    h *= FNV_PRIME;
    for (uint64_t w : args) {
        for (int b = 0; b < 8; ++b) {
            h ^= (w >> (b * 8)) & 0xFFu;
            h *= FNV_PRIME;
        }
    }
    /* Hex-encode el hash para que sea un string utilizable como key
     * en el unordered_map.  Tambien añadimos el name para diag. */
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx",
                  static_cast<unsigned long long>(h));
    std::string key;
    key.reserve(macro_name.size() + 17);
    key.assign(macro_name);
    key.push_back(':');
    key.append(buf);
    return key;
}

bool ComptimeRuntime::marshal_string(const std::string &s,
                                     uint64_t &out_handle) noexcept {
    out_handle = 0;
    if (!impl_ || !impl_->proc) return false;
    try {
        /* Delegar al helper publico del runtime: mismo path que la
         * instruccion STRMAKE usa internamente (alloc_pinned + populacion
         * del header + hash precomputado).  El handle resultante
         * sobrevive cross-call y se puede pasar como uint64 en R1..R12. */
        const auto *data = reinterpret_cast<const uint8_t *>(s.data());
        const auto h = runtime::make_string_flat(
            impl_->proc, data, static_cast<uint32_t>(s.size()),
            /*length=UINT32_MAX -> auto*/ UINT32_MAX,
            loader::StringEncoding::UTF8);
        if (h == gc::GC_NULL_HANDLE) return false;
        out_handle = static_cast<uint64_t>(h);
        return true;
    } catch (...) {
        return false;
    }
}

bool ComptimeRuntime::marshal_aggregate(const std::vector<uint8_t> &bytes,
                                        uint64_t &out_vm_addr) noexcept {
    out_vm_addr = 0;
    if (!impl_ || bytes.empty()) return false;
    /* Tope: esto es para un valor, no para un array.  Sin el, un tamano absurdo
     * se comeria la memoria y el fallo saldria mucho despues y en otro sitio.
     */
    if (bytes.size() > 64u * 1024u) return false;
    try {
        impl_->agg_args.emplace_back(bytes);
    } catch (...) {
        return false;
    }
    out_vm_addr = static_cast<uint64_t>(
        reinterpret_cast<uintptr_t>(impl_->agg_args.back().data()));
    return true;
}

bool ComptimeRuntime::invoke_string_macro_memoized(
    const std::string &macro_name, const std::vector<uint64_t> &args,
    std::string &out_str, bool pure) noexcept {
    if (!pure) {
        /* No-cache path: redirige a la version basica. */
        return invoke_string_macro(macro_name, args, out_str);
    }
    try {
        const std::string key = build_memo_key(macro_name, args);
        auto it = memo_cache_.find(key);
        if (it != memo_cache_.end()) {
            out_str = it->second;
            ++memo_hit_count_;
            return true;
        }
        const bool ok = invoke_string_macro(macro_name, args, out_str);
        if (ok) {
            memo_cache_.emplace(key, out_str);
            ++memo_miss_count_;
        }
        return ok;
    } catch (...) {
        return false;
    }
}

bool ComptimeRuntime::make_vm_string(const std::string &s,
                                     uint64_t &out_handle) noexcept {
    out_handle = 0;
    ensure_vm_initialized();
    if (impl_ == nullptr || impl_->proc == nullptr) return false;
    try {
        /* Cabecera de `StringObject` (40 bytes) + los datos + un nulo de
         * cortesia, que es lo que espera cualquier consumidor que la pase a una
         * API de C.  El layout esta en `include/loader/string_object.h` y no se
         * escribe a mano campo por campo aqui: se usa el propio tipo, para que
         * si crece la cabecera esto no se quede corto en silencio. */
        const size_t n = s.size();
        const size_t total = sizeof(loader::StringObject) + n + 1;
        /* Fijado a proposito: el handle se entrega y se usa DESPUES.  Si el
         * recolector moviera el objeto entre crearlo y la llamada, el argumento
         * apuntaria a otro sitio. */
        const gc::GcHandle h = impl_->proc->gc_heap.alloc_pinned(total);
        if (h == gc::GC_NULL_HANDLE) return false;
        uint8_t *payload = impl_->proc->gc_heap.deref(h);
        if (payload == nullptr) return false;
        std::memset(payload, 0, total);
        auto *so = reinterpret_cast<loader::StringObject *>(payload);
        /* UTF-8 y `length` en bytes: la cadena viene del FUENTE, que es ASCII
         * salvo la enye, asi que contar puntos de codigo aqui seria pagar un
         * recorrido por un caso que este camino no produce.  Si algun dia entra
         * texto multibyte por aqui, `length` hay que contarlo de verdad. */
        so->encoding = (uint8_t)loader::StringEncoding::UTF8;
        so->length = (uint32_t)n;
        so->byte_len = (uint32_t)n;
        so->str_hash = 0; // 0 = sin calcular; lo cachea quien lo pida
        if (n != 0)
            std::memcpy(payload + sizeof(loader::StringObject), s.data(), n);
        out_handle = (uint64_t)h;
        return true;
    } catch (...) {
        return false;
    }
}

bool ComptimeRuntime::invoke_raw(const std::string &macro_name,
                                 const std::vector<uint64_t> &args,
                                 size_t n_bytes, unsigned addr_reg,
                                 std::vector<uint8_t> &out_bytes) noexcept {
    out_bytes.clear();
    if (n_bytes == 0 || n_bytes > (16u << 20)) return false; // tope defensivo
    if (addr_reg > 15) return false;

    // Ejecuta el codigo comptime, que va compilado (JIT).
    uint64_t r0 = 0;
    if (!invoke_simple_macro(macro_name, args, r0)) return false;
    if (!impl_ || !impl_->proc) return false;

    try {
        // Direccion del resultado: R0 salvo que se pida otro registro (un
        // constructor, por ejemplo, deja el valor donde apuntaba su `this`).
        const uint64_t addr =
            (addr_reg == 0) ? r0
                            : impl_->proc->registers.regs[addr_reg].qword();
        if (addr == 0) return false;

        // La direccion puede ser de la VM o del anfitrion (un buffer
        // reservado por quien invoca).  Se intenta primero como direccion de
        // la VM, que valida el rango; si no lo es, se lee como puntero.
        out_bytes.resize(n_bytes);
        bool leido = false;
        try {
            impl_->proc->vm_mem.read_bytes(addr, out_bytes.data(), n_bytes);
            leido = true;
        } catch (...) {
            leido = false;
        }
        if (!leido) {
            const uint8_t *src = reinterpret_cast<const uint8_t *>(addr);
            if (src == nullptr) return false;
            std::memcpy(out_bytes.data(), src, n_bytes);
        }

        for (int i = 0; i < 16; ++i)
            impl_->proc->registers.regs[i].qword(0);
        return true;
    } catch (...) {
        return false;
    }
}

bool ComptimeRuntime::invoke_string_macro(const std::string &macro_name,
                                          const std::vector<uint64_t> &args,
                                          std::string &out_str) noexcept {
    out_str.clear();
    /*   : capturamos old_used pre-call solo si trace activo. */
    size_t old_used_before = 0;
    const bool gc_trace_active = []() {
        return util::flag_on(util::FlagId::McGcTrace);
    }();
    if (gc_trace_active && impl_ && impl_->proc) {
        old_used_before = impl_->proc->gc_heap.old_used();
    }
    uint64_t r0 = 0;
    if (!invoke_simple_macro(macro_name, args, r0)) return false;
    if (r0 == 0) return false;
    if (!impl_ || !impl_->proc) return false;

    try {
        /* Deref handle -> payload host_ptr.  El payload es el
         * StringObject completo (sin GcHeader). */
        /* El macro pudo devolver un StringObject ROPE (STRCAT) o SLICE
         * (STRSLICE): sus bytes NO estan contiguos en data[40], sino en una
         * estructura de arbol/vista.  Leerlo como FLAT daria basura (incl. NUL
         * bytes -> "caracter inesperado" al parsear el codigo generado).
         * Materializar a FLAT primero. */
        gc::GcHandle handle = runtime::flatten_string_public(
            impl_->proc, static_cast<gc::GcHandle>(r0));
        uint8_t *payload = impl_->proc->gc_heap.deref(handle);
        if (!payload) return false;

        /* Layout StringObject (vease include/vesta_rt/abi.h):
         *   +0   ObjectHeader (24 bytes)
         *   +24  encoding (u8)
         *   +25  kind     (u8)
         *   +28  length   (u32, code-points)
         *   +32  byte_len (u32, bytes en data[])
         *   +36  hash     (u32)
         *   +40  data[]   (byte_len bytes contiguos)
         */
        uint32_t byte_len = 0;
        std::memcpy(&byte_len, payload + 32, sizeof(uint32_t));
        if (byte_len > (16u << 20)) return false; /* cap defensivo 16 MB */

        out_str.assign(reinterpret_cast<const char *>(payload + 40), byte_len);

        /*    +   (A: Lazy GC):  Los strings intermedios
         * (args marshalados, returns ya extraidos) viven en OldGen
         * pinned pero son colectables.  Sin esto crecen linealmente.
         *
         *   mejora  : en lugar de major_gc en CADA call,
         * acumulamos hasta @c gc_interval invocaciones y barremos
         * en batch.  Cost amortizado ~10us / 64 calls = 0.15us/call
         * (vs 10us/call original) -> 98% reduccion overhead GC.
         *
         * Peak memory queda bounded a ~gc_interval * 128 B (~8KB
         * con default 64), aceptable.  Override via
         * @c VESTA_MC_GC_INTERVAL.
         *
         * Limpiar R0..R15 SIEMPRE (no en batch) -- esos handles
         * deben morir inmediatamente para que el siguiente call
         * empiece limpio.  Solo el major_gc se difiere. */
        for (int i = 0; i < 16; ++i) {
            impl_->proc->registers.regs[i].qword(0);
        }
        ++impl_->invocations_since_gc;
        if (impl_->gc_interval == 0 ||
            impl_->invocations_since_gc >= impl_->gc_interval) {
            impl_->proc->gc_heap.major_gc();
            impl_->invocations_since_gc = 0;
        }

        if (gc_trace_active) {
            const size_t after = impl_->proc->gc_heap.old_used();
            std::cerr << "[mc-gc] " << macro_name
                      << " old_used: " << old_used_before << " -> " << after
                      << " (post-gc)\n";
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool ComptimeRuntime::invoke_struct_macro(
    const std::string &macro_name, const std::vector<uint64_t> &args,
    size_t struct_size, std::vector<uint8_t> &out_bytes) noexcept {
    /* Una funcion que devuelve un struct por valor lo hace por SRET: el
     * llamante aloca el buffer del resultado y lo pasa como primer parametro
     * oculto (host_ptr), y la funcion lo rellena con `movh`.  Aqui hacemos de
     * llamante: alocamos el buffer en memoria del proceso (out_bytes), no en la
     * pila de la funcion -- que se libera al retornar --, lo anteponemos a los
     * argumentos reales y ejecutamos.  Al ser out_bytes memoria ajena al
     * GcHeap, el barrido de invoke_simple_macro no la toca. */
    /* El caller puede PRE-SEMBRAR out_bytes con los valores por defecto de los
     * campos: la semantica de un ctor es "defaults primero, cuerpo del ctor
     * encima" (igual que C++), asi que un campo que el ctor no toca debe
     * conservar su default.  Si el caller no siembra (tamano distinto), se
     * arranca a ceros como antes. */
    if (out_bytes.size() != struct_size) out_bytes.assign(struct_size, 0);
    /* El buffer de retorno mas los argumentos reales no pueden exceder los 12
     * registros de la convencion de llamada. */
    if (args.size() + 1 > 12) return false;
    std::vector<uint64_t> vm_args;
    vm_args.reserve(args.size() + 1);
    vm_args.push_back(
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(out_bytes.data())));
    for (uint64_t a : args) {
        vm_args.push_back(a);
    }
    uint64_t r0 = 0;
    /* Tras la invocacion, out_bytes ya contiene los bytes del struct escritos
     * por la funcion a traves del buffer.  R0 (el propio buffer) se ignora. */
    if (!invoke_simple_macro(macro_name, vm_args, r0)) {
        return false;
    }
    return true;
}

void ComptimeRuntime::record_expectation(const std::string &macro_name,
                                         std::vector<uint64_t> args,
                                         std::string expected_str,
                                         std::string src_loc) {
    /*   : el TypeChecker llama aqui justo despues de evaluar
     * un @Macro via el AST evaluator.  Guardamos la tripleta
     * (canonical_name, args, expected) para validacion posterior
     * via VM.  Cero overhead durante type-check: solo push_back.
     *
     * Nota: el nombre del macro CANONICO en el IR es
     * "__macro_<original>"; el TypeChecker conoce solo "<original>"
     * (el nombre escrito por el usuario).  Aqui aceptamos cualquiera
     * de los dos: el shadow_validate prueba ambos al lookup. */
    ShadowExpectation e;
    e.macro_name = macro_name;
    e.args = std::move(args);
    e.expected_str = std::move(expected_str);
    e.src_loc = std::move(src_loc);
    shadow_expectations_.push_back(std::move(e));
}

size_t
ComptimeRuntime::shadow_validate(std::vector<ShadowMismatch> &report) noexcept {
    size_t mismatches = 0;
    for (const auto &exp : shadow_expectations_) {
        ShadowMismatch m;
        m.macro_name = exp.macro_name;
        m.src_loc = exp.src_loc;
        m.expected = exp.expected_str;

        /* Resolver nombre canonico: aceptamos tanto "<original>"
         * como "__macro_<original>".  Lookup en macro_entry_pc_. */
        std::string canonical = exp.macro_name;
        if (macro_entry_pc_.find(canonical) == macro_entry_pc_.end()) {
            const std::string alt = "__macro_" + exp.macro_name;
            if (macro_entry_pc_.find(alt) != macro_entry_pc_.end()) {
                canonical = alt;
            }
        }

        std::string got;
        const bool ok = invoke_string_macro(canonical, exp.args, got);
        if (!ok) {
            m.match = false;
            m.reason = "invoke_string_macro fallo (macro '" + canonical +
                       "' no resolvio o el VM crasheo)";
            ++mismatches;
        } else if (got != exp.expected_str) {
            m.match = false;
            m.got = got;
            m.reason = "discrepancia AST vs VM (longitudes " +
                       std::to_string(exp.expected_str.size()) + " vs " +
                       std::to_string(got.size()) + ")";
            ++mismatches;
        } else {
            m.match = true;
            m.got = got;
            m.reason = "ok";
        }
        report.push_back(std::move(m));
    }
    return mismatches;
}

bool ComptimeRuntime::load_macros_from_bytes(
    std::vector<uint8_t> bytecode) noexcept {
    if (bytecode.empty()) return false;
    ensure_vm_initialized();
    if (!impl_) return false;
    try {
        /* Cargar el .velb completo desde memoria.  El Loader parsea
         * el header, valida magic/version, mapea las secciones al
         * vm_mem de un nuevo ProcessVM y devuelve el handle.  Cero
         * file I/O: todo se hace sobre el buffer ya en memoria. */
        runtime::ProcessVM *proc =
            impl_->mgr.loader.load_executable(impl_->vm, std::move(bytecode));
        if (!proc) return false;
        impl_->proc = proc;
        impl_->proc_pid = proc->pid;

        /*  : capturar initial_rsp + hlt_sentinel_va para poder
         * reusar el proceso entre llamadas.  Loader setupó la pila
         * con stack_base_main = 0x10000000 + (local_pid % 0x1000) * 0x100000,
         * con la VA del sentinel HLT a stack_base + 16 y el RSP
         * apuntando a stack_base - 8 (donde se escribio la sentinel VA
         * como direccion de retorno final). */
        impl_->initial_rsp = proc->registers.stack_pointer.qword();
        const uint64_t stack_base_main =
            0x10000000ULL + (proc->pid.local_pid % 0x1000ULL) * 0x100000ULL;
        impl_->hlt_sentinel_va = stack_base_main + 16;

        /*   : resolver entry PC de cada `__macro_<X>` desde
         * el symbol_table del Executable recien cargado.  Itera la
         * tabla VSYM (populada por linker en el .velb v3), filtra
         * por prefijo `code.__macro_` y registra cada uno en el
         * mapa @c macro_entry_pc_ con la direccion real. */
        const auto &execs = impl_->mgr.loader.executables;
        if (execs.empty()) return true;
        const auto &exe = execs.back(); /* el recien cargado */
        const std::string PREFIX = "code.__macro_";
        for (const auto &kv : exe->symbol_table) {
            if (kv.first.size() <= 5) continue;
            if (kv.first.compare(0, PREFIX.size(), PREFIX) != 0) continue;
            /* kv.first = "code.__macro_my_fn" -> "__macro_my_fn" tras
             * descartar el prefijo "code." (5 chars). */
            const std::string clean = kv.first.substr(5);
            macro_entry_pc_[clean] = kv.second;
            /* Un fichero con `namespace` compila sus funciones con el prefijo
             * del modulo (`__macro_mi_modulo__gen`), pero desde su propio
             * fichero se las llama por el nombre desnudo (`gen`).  Se registra
             * TAMBIEN esa forma corta para que ese nombre encuentre su codigo;
             * si no, la funcion se daba por no ejecutable y devolvia el valor
             * VACiO sin decir nada.
             *
             * Si dos modulos traen el mismo nombre corto, la forma corta deja
             * de identificar a uno solo: se retira en vez de elegir al azar,
             * porque llamar a la funcion equivocada seria peor. */
            const size_t sep = clean.rfind("__");
            if (sep != std::string::npos && sep > 8) {
                const std::string corto = "__macro_" + clean.substr(sep + 2);
                if (corto != clean) {
                    auto prev = macro_entry_pc_.find(corto);
                    if (prev == macro_entry_pc_.end()) {
                        macro_entry_pc_[corto] = kv.second;
                        macro_corto_origen_[corto] = clean;
                    } else if (macro_corto_origen_.count(corto) != 0 &&
                               macro_corto_origen_[corto] != clean) {
                        macro_entry_pc_.erase(prev); /* ambiguo */
                    }
                }
            }
        }

        /* Eager-compile cada macro/fn comptime via JIT: es lo que acelera
         * TODO el proceso comptime.  JIT-FIRST por defecto; el interprete
         * queda como fallback automatico (si @c eager_compile_function no
         * puede compilar una fn -- op IR no soportada -- @c res.fn es null y
         * @c jit_code_by_pc no se setea, asi que el scheduler la ejecuta por
         * interp).  Opt-out completo via @c VESTA_MC_NO_JIT=1 (fuerza interp
         * puro, util para diagnostico o A/B).
         *
         * El coste del compile (~5-15ms por fn) se amortiza con el cache del
         * codigo comptime (compilado aparte, cacheado aparte): el comptime
         * casi nunca cambia y se reusa mucho, asi que se paga una vez. */
        const bool mc_jit_on = !util::flag_on(util::FlagId::McNoJit);
        if (mc_jit_on) {
            const uint32_t saved_threshold = jit::g_jit_threshold;
            if (saved_threshold == UINT32_MAX) {
                jit::g_jit_threshold = 1;
            }
            try {
                for (const auto &kv : macro_entry_pc_) {
                    const std::string &macro_name = kv.first;
                    const uint64_t entry_pc = kv.second;
                    auto fnit = exe->ir_lookup.find(macro_name);
                    if (fnit == exe->ir_lookup.end()) continue;
                    if (fnit->second >= exe->ir_functions.size()) continue;
                    const ir::IrFunction &ir_fn =
                        exe->ir_functions[fnit->second];
                    try {
                        /* #3: resolver de FFI nativo para que el JIT del
                         * ComptimeVM pueda compilar CALLNs a virtual fns
                         * `vrt:*` (p.ej. `vrt:naked_dispatch` cuando una
                         * comptime fn llama a un helper @Naked).  Sin esto el
                         * CALLN caia a "no-resolver" -> bail a interp (que no
                         * ejecuta bien el inline-asm/naked en el ComptimeVM)
                         * -> valor 0 silencioso. */
                        auto native_resolver =
                            [](const std::string &name) -> uint64_t {
                            size_t colon = name.find(':');
                            if (colon == std::string::npos) return 0;
                            void *vfn = ffi::lookup_virtual_fn(
                                name.substr(0, colon), name.substr(colon + 1));
                            return reinterpret_cast<uint64_t>(vfn);
                        };
                        jit::CompileResult res = jit::eager_compile_function(
                            ir_fn, &exe->ir_lookup, &exe->ir_functions,
                            &exe->symbol_table, native_resolver);
                        if (res.fn) {
                            impl_->jit_code_by_pc[entry_pc] =
                                reinterpret_cast<void *>(res.fn);
                        } else if (util::flag_on(util::FlagId::ComptimeDebug)) {
                            /* El comptime corre por el JIT; interpretarlo es
                             * el camino LENTO, no el habitual.  En teoria solo
                             * cuesta tiempo de COMPILACION, porque los dos
                             * caminos deberian dar lo mismo.
                             *
                             * En la practica eso hay que comprobarlo, no darlo
                             * por hecho: aqui ponia que "no cambia lo que el
                             * programa hace", y durante un tiempo si lo
                             * cambiaba.  Dos fallos que solo vivian en el
                             * camino interpretado -- el acierto falso del cache
                             * de instrucciones en la direccion 0, y la primera
                             * macro cerrada con `hlt` -- hacian que una macro
                             * que llamara a otra devolviera un valor vacio.  Se
                             * tardo en verlos porque este aviso los tapaba: se
                             * leia como "solo va mas lento".
                             *
                             * Asi que si un resultado del comptime sale raro,
                             * este mensaje SI es una pista, y `VESTA_MC_NO_JIT`
                             * fuerza el mismo camino para compararlos.
                             *
                             * Se decia en CADA compilacion de cualquier fichero
                             * con generadores, y eso es ruido: un aviso que
                             * sale siempre y no pide ninguna accion entrena a
                             * no leer los avisos.  Y ahi hay avisos que SI
                             * piden accion -- el de alineacion, sin ir mas
                             * lejos, quedaba enterrado entre estos.
                             *
                             * Se conserva tras `VESTA_COMPTIME_DEBUG` porque a
                             * quien mire el coste del comptime si le interesa:
                             * interpretado es mas lento que compilado. */
                            std::fprintf(stderr,
                                         "[comptime] no se pudo compilar '%s'; "
                                         "se ejecuta interpretado\n",
                                         kv.first.c_str());
                        }
                    } catch (...) {
                        std::fprintf(stderr,
                                     "[comptime] aviso: fallo al compilar "
                                     "'%s'\n",
                                     kv.first.c_str());
                    }
                }
            } catch (...) {
            }
            jit::g_jit_threshold = saved_threshold;
        }
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace vx
