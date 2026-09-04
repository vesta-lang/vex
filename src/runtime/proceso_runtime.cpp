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
 * @file proceso_runtime.cpp                                                   \
 * @brief Implementacion del contexto de proceso virtual (ProcessVM) de        \
 * VestaVM.                                                                    \
 *                                                                             \
 * Implementa @c ProcessVM: inicializacion de registros y pila, gestion del    \
 * estado del proceso (NEW, READY, RUNNING, BLOCKED, DEAD) y utilidades de     \
 * inspeccion del proceso en ejecucion.                                        \
 */                                                                            \
#include "runtime/proceso_runtime.h"

#include "runtime/bundle.h" // bundle_release: la arena de paquetes del proceso

#include <atomic>
#include <cstdint>
#include <cstdlib> // getenv (gate VESTA_OSR_COUNT del osr_buffer)
#include <functional>
#include <queue>
#include <thread>
#include <vector>

#include "arena/arena.h"
#include "arena/VirtualMemory.h"
#include "vesta_rt/abi.h" // VESTA_OSR_BUFFER_N (tamano del osr_buffer)
#include "cli/sync_io.h"
#include "jit/jit_call.h"
#include "profiler/timer.h"
#include "runtime/exec_instruction.h" // install_gc_finalizer_runner
#include "runtime/rflags.h"
// Inc 0b: los cuerpos de ProcessVMRootProvider necesitan la def completa de la
// VM (scheduler.vm_reference.shared_*) + las tablas shared ( Z).
#include "gc/shared_handle_table.h"
#include "gc/shared_heap.h"
#include "loader/loader.h" // Loader completo (executables + interp_stackmaps)
#include "runtime/runtime.h"

namespace loader {
class Loader; ///< Declaracion adelantada del cargador de bytecode
}

namespace runtime {
struct InstrFormat; ///< Declaracion adelantada del formato de instruccion
class ManageVM;     ///< Declaracion adelantada del gestor de instancias
class VM;           ///< Declaracion adelantada de la instancia VM

/**
 * @brief hook function pointer para auto-JIT trigger.
 *        Default nullptr (sin JIT).  El main binario lo setea a
 *        @c &jit::maybe_compile_method en VM init si quiere habilitar
 *        JIT.  Ver @c include/runtime/proceso_runtime.h para detalle.
 */
void (*g_callvirt_post_hook)(ProcessVM *vm,
                             loader::MethodInfo *method) = nullptr;

/**
 * @brief Puntero a la llamada nativa en curso (si existe alguna).
 *
 * Se usa para coordinar llamadas FFI desde instrucciones que necesitan
 * suspender el proceso hasta recibir el resultado de la funcion nativa.
 * El valor nullptr indica que no hay ninguna llamada pendiente.
 */
PendingCall_t *pending_call = nullptr;

/**
 * @brief Construye un proceso virtual y lo conecta al scheduler y al TLB.
 *
 * Inicializa vm_mem con el TLB y el ArenaManager privados del proceso.
 * El estado inicial es NEW hasta que se llame a make_ready().
 *
 * @param scheduler Scheduler propietario que ejecutara este proceso.
 * @param pid       Identificador global unico del proceso.
 */
ProcessVM::ProcessVM(Scheduler &scheduler, GlobalPID pid)
    : pid(pid),
      vm_mem(tlb,
             manager_mem_priv), // combinar TLB privado con ArenaManager privado
      scheduler(scheduler) {
    // fix8 - el GC necesita conocer el ProcessVM owner para escanear stack/regs
    // durante major_gc.  Inc 0b: ahora via la interfaz GcRootProvider (no un
    // ProcessVM* directo) -> gc_heap.cpp no depende de la VM.  El provider solo
    // guarda `this`; permanece valido durante toda la vida del proceso.
    gc_heap.set_root_provider(&gc_root_provider_);
    // Finalizadores GC: instalar el runner que ejecuta el deleter/dtor
    // customizable de objetos GC con recurso interno que escapan su scope.
    // Reentra al interprete (bytecode portable) en el safe point post-collect.
    install_gc_finalizer_runner(this);
    //  D.7: cachear la direccion estable de la HandleTable para que
    // el JIT inline-e deref (handle -> host_ptr) sin CALL al runtime.
    jit_handle_table = gc_heap.jit_handle_table_ptr();
    // OSR ( D.8): alocar el buffer del state-transfer SOLO cuando
    // VESTA_OSR_COUNT esta activo (off por defecto -> osr_buffer = nullptr,
    // cero coste).  El check del env se cachea (1 getenv por proceso solo
    // cuando se construye el primero).  El JIT lee este buffer via RBX al
    // disparar/reanudar un OSR; debe ser no-nulo antes de ejecutar codigo
    // JIT con OSR instrumentado, garantizado aqui.
    {
        static const bool osr_on = [] {
            const char *v = std::getenv("VESTA_OSR_COUNT");
            return v && v[0] != '\0' && v[0] != '0';
        }();
        if (osr_on) {
            osr_buffer = new uint64_t[VESTA_OSR_BUFFER_N](); // zero-init
        }
    }
    /* El icache nace a ceros, y una entrada a ceros dice `pc == 0`.  Como el
     * acierto se decide comparando el PC con ese campo, la direccion 0 -- que
     * es una direccion de codigo legitima: es donde cae la PRIMERA funcion del
     * modulo -- acertaba contra una entrada VACIA y se ejecutaba una
     * instruccion de ceros en lugar de la que hay ahi.
     *
     * Solo se notaba al SALTAR a la 0 con el cache ya en uso: al arrancar el
     * proceso, `decoded_ptr` todavia es nulo y la condicion del acierto pide
     * las dos cosas, asi que la primera instruccion se descodificaba de verdad
     * y dejaba la entrada buena.  Por eso un programa que EMPIEZA en la 0
     * funcionaba y uno que LLAMA a la 0 no; y por eso solo pasaba interpretado,
     * porque el codigo compilado no consulta este cache.
     *
     * `reset_cache()` ya usa UINT64_MAX para decir "vacia", que no es una
     * direccion posible.  Lo que faltaba era nacer asi. */
    reset_cache();
}

/**
 * @brief Destructor: marca el proceso como DEAD y libera su memoria.
 *
 * Libera todas las arenas del ArenaManager privado.  En teoria el
 * destructor de ArenaManager ya lo hace, pero la llamada explicita
 * garantiza la liberacion antes de que el objeto sea destruido.
 */
ProcessVM::~ProcessVM() {
    state = DEAD;        // marcar estado terminal
    delete[] osr_buffer; // OSR: liberar el buffer del state-transfer
                         // (nullptr-safe)
    osr_buffer = nullptr;
#if VM_BUNDLES
    /* La arena de paquetes.  `bundle_release` existia, estaba definida y NO LA
     * LLAMABA NADIE: cada proceso que llegara a formar un paquete se dejaba la
     * arena entera sin liberar -- hasta `CAPACITY` paquetes de ~2 KB --, y como
     * el proceso muere igual y el programa termina, no se notaba en ningun
     * sitio salvo en la memoria de quien lanza muchos procesos.
     *
     * Es tambien lo que hacia inalcanzable el volcado de la telemetria de
     * paquetes, que vive ahi dentro. */
    bundle_release(this);
#endif
    manager_mem_priv.free_all(); // liberar toda la memoria privada del proceso
    // Liberar @c ExceptionFrames del free list (reciclados por
    // @c tryleave).  El @c exc_frame_stack activo solo deberia tener
    // frames si el proceso muere mid-try (no normal, pero defensivo).
    while (exc_frame_stack != nullptr) {
        ExceptionFrame *tmp = exc_frame_stack;
        exc_frame_stack = tmp->prev;
        delete tmp;
    }
    while (exc_free_list != nullptr) {
        ExceptionFrame *tmp = exc_free_list;
        exc_free_list = tmp->prev;
        delete tmp;
    }
}

/**
 * @brief Invalida todas las entradas de la cache de instrucciones
 * descodificadas.
 *
 * Pone el campo pc de cada entrada a UINT64_MAX (valor invalido) y
 * anula decoded_ptr para que el descodificador no reutilice instrucciones
 * de una ejecucion anterior o de codigo que haya cambiado.
 */
void ProcessVM::reset_cache() {
    for (auto &entry : icache) {
        entry.pc = UINT64_MAX; // marcar como entrada invalida
    }
    decoded_ptr = nullptr; // invalidar el puntero de descodificacion activo
}

/**
 * @brief Carga codigo en bruto en la memoria virtual del proceso.
 *
 * Copia @p code a partir de la direccion virtual @p address usando
 * vm_to_host_memcpy() y configura el registro RIP para apuntar al inicio
 * del codigo cargado.
 *
 * @note No cambia el estado del proceso: debe estar en NEW cuando se llama.
 *       El scheduler cambiara el estado a READY cuando se llame a make_ready().
 *
 * @param address Direccion virtual de inicio donde se escribira el codigo.
 * @param code    Vector de bytes con las instrucciones a cargar.
 */
void ProcessVM::load_raw_code(uint64_t address,
                              const std::vector<uint8_t> &code) {
    vm_mem.vm_to_host_memcpy(address, code.data(),
                             code.size()); // copiar codigo a memoria virtual

    registers.rip.qword(address); // apuntar el PC al inicio del codigo cargado

    // El estado permanece en NEW hasta que make_ready() lo ponga en READY.
    // make_ready() requiere que el proceso este en NEW para incrementar
    // alive_count.
}

/**
 * @brief Genera una representacion textual detallada del proceso.
 * @return Cadena con el volcado completo del estado del proceso.
 */
std::string ProcessVM::to_string() const {
    return vm_summary(); // delegar en vm_summary
}

/**
 * @brief Genera un resumen de diagnostico del proceso en texto.
 *
 * Incluye PID, registros generales R00-R15, registros ZMM f0..f15 con sus
 * bits IEEE 754 y valor double, registros cursor CUR0-CUR3, RIP/RSP/RBP,
 * banderas, reducciones, TSC, estado del icache y bytes de memoria asignados.
 * Util para depuracion e informes de crash.
 *
 * @return Cadena con el resumen formateado del proceso.
 */
std::string ProcessVM::vm_summary() const {
    std::ostringstream ss;

    // encabezado: PID, ID del scheduler y estado actual
    ss << "PID LOCAL=" << vesta::hex64((uint64_t)pid.local_pid)
       << " ID SCHEDULER=" << vesta::hex64((uint64_t)pid.scheduler_id)
       << " st=" << vm_state_to_str(state) << "\n";

    // registros de proposito general R00-R15 (dos por linea)
    for (int i = 0; i < 16; ++i) {
        ss << " R" << std::setw(2) << std::setfill('0') << i << "="
           << vesta::hex64(registers.regs[i].qword());
        if (i % 2 == 1) ss << "\n"; // salto de linea cada dos registros
    }
    ss << "\n";

    // registros ZMM f0..f15: bits crudos y valor double (dos por linea)
    for (int i = 0; i < 16; ++i) {
        double dv = registers.zmm[i].read_f64(); // valor como double IEEE 754
        uint64_t raw = 0;
        __builtin_memcpy(&raw, registers.zmm[i].data, 8); // bits crudos
        ss << " F" << std::setw(2) << std::setfill('0') << i << "="
           << vesta::hex64(raw) << " (" << std::setfill(' ') << dv << ")";
        if (i % 2 == 1) ss << "\n";
    }
    ss << "\n";

    // registros cursor CUR0-CUR3 (dos por linea)
    for (int i = 0; i < 4; ++i) {
        ss << " CUR" << i << "=" << vesta::hex64(registers.cur[i].qword());
        if (i % 2 == 1) ss << "\n";
    }
    ss << "\n";

    // contadores de programa y pila
    ss << " RIP=" << vesta::component_to_string(registers.rip)
       << " RSP=" << vesta::component_to_string(registers.stack_pointer)
       << " RBP=" << vesta::component_to_string(registers.base_pointer) << "\n";

    // registro de banderas
    ss << " FLAGS=["
       << "CF=" << (int)registers.flags.bits.CF << " "
       << "OF=" << (int)registers.flags.bits.OF << " "
       << "SF=" << (int)registers.flags.bits.SF << " "
       << "ZF=" << (int)registers.flags.bits.ZF << " "
       << "DM=" << (int)registers.flags.DM << "]\n";

    // contadores de ejecucion
    ss << " Reductions=" << reductions_remaining << " TSC=" << tsc
       << " SleepUntil=" << time_sleep << " LastErr=" << err_thread << "\n";

    // instruccion activa si decoded_ptr es valido
    if (decoded_ptr) {
        ss << " Instr: opcode=" << (int)decoded_ptr->flags_info.opcode_index
           << " size=" << (int)decoded_ptr->flags_info.size_instr
           << " mode=" << (int)decoded_ptr->flags_info.mode
           << " did_jump=" << decoded_ptr->flags_info.did_jump
           << " blocking=" << decoded_ptr->flags_info.blocking
           << " pc=" << vesta::hex64(decoded_ptr->pc) << "\n";
    }

    // estadisticas del icache
    size_t valid = 0;
    for (const auto &entry : icache)
        if (entry.metadata != nullptr)
            valid++; // contar entradas con metadatos validos

    ss << " ICACHE: valid=" << valid << "/" << ICACHE_SIZE << " ("
       << (100 * valid / ICACHE_SIZE) << "%)\n";

    // memoria privada del proceso
    ss << " MEM: total_allocated_bytes="
       << manager_mem_priv.total_allocated_bytes_ << "\n";

    // estado del scheduler propietario
    ss << " SchedulerID=" << scheduler.id_scheduler
       << " Ready=" << scheduler.ready_queue.size() << "\n";

    ss << " Sleep=" << time_sleep << "\n";

    return ss.str();
}

// ---------------------------------------------------------------------------
// ProcessVMRootProvider: la impl de gc::GcRootProvider sobre el ProcessVM.
// Aqui (no en el header) porque accede a scheduler.vm_reference.shared_* (la
// def completa de la VM, incluida arriba via runtime.h).
// ---------------------------------------------------------------------------

bool ProcessVMRootProvider::vm_stack_regs(uint64_t &rsp, uint64_t &stack_high,
                                          uint64_t regs[16]) {
    rsp = proc_->registers.stack_pointer.qword();
    stack_high = proc_->stack_high;
    for (int i = 0; i < 16; ++i)
        regs[i] = proc_->registers.regs[i].qword();
    return true; // el ProcessVM siempre tiene stack VM
}

uint64_t ProcessVMRootProvider::stack_low_water() const {
    return proc_->stack_low_water;
}

void ProcessVMRootProvider::set_stack_low_water(uint64_t v) {
    proc_->stack_low_water = v;
}

void ProcessVMRootProvider::write_back_regs(const uint64_t regs[16]) {
    for (int i = 0; i < 16; ++i)
        proc_->registers.regs[i].qword(regs[i]);
}

vm::VirtualMemory *ProcessVMRootProvider::vm_mem() {
    return &proc_->vm_mem;
}

uint64_t ProcessVMRootProvider::scan_interp_precise_roots(InterpRootCallback cb,
                                                          void *cb_ctx) {
    if (!cb) return 0;

    // Coleccion de executables cargados (cada uno con su tabla VSMP).
    auto &executables = proc_->scheduler.vm_reference.loader_public.executables;

    // Helper: busca el stackmap del PC @p pc en cualquier executable.
    auto lookup = [&](uint64_t pc) -> const loader::InterpStackmap * {
        const uint32_t pc32 = static_cast<uint32_t>(pc);
        for (const auto &exe_ptr : executables) {
            if (!exe_ptr || exe_ptr->interp_stackmaps.empty()) continue;
            if (const auto *sm = exe_ptr->interp_stackmaps.lookup_exact(pc32))
                return sm;
        }
        return nullptr;
    };

    // Snapshot de los 16 GP regs del frame TOP (los unicos accesibles como
    // registros; los frames caller ya spillaron sus GC vivos a la pila).
    uint64_t regs[16];
    for (int i = 0; i < 16; ++i)
        regs[i] = proc_->registers.regs[i].qword();

    uint64_t marked = 0;

    // Helper: materializa un stackmap.  @p frame_rbp es el rbp del frame que el
    // stackmap describe (para registros del top y slots de spill).  @p
    // callee_rbp es el rbp del frame CALLEE cuyo return_pc selecciono este
    // stackmap (para handles empujados a traves del call, que viven por encima
    // del saved_rbp/return_pc del callee).  Para el frame TOP, callee_rbp==0
    // (sus safepoints directos no tienen handles empujados).  @p is_top indica
    // si @p frame_rbp es el frame top (los slots de registro solo valen ahi).
    auto apply = [&](const loader::InterpStackmap *sm, uint64_t frame_rbp,
                     uint64_t callee_rbp, bool is_top) {
        for (const auto &slot : sm->slots) {
            uint64_t value = 0;
            if (slot.is_reg()) {
                // Registro VM: solo valido en el frame top.  Los frames
                // caller tienen sus GC vivos en slots de spill (handles),
                // no en registros -> saltamos los slots de registro alli.
                if (!is_top) continue;
                const uint8_t r = slot.reg_index();
                if (r >= 16) continue;
                value = regs[r];
            } else if (slot.is_pushed()) {
                // Handle empujado a traves de un call: vive en
                // [callee_rbp + 16 + 8*push_index].  Robusto ante ALLOCA en el
                // frame del caller.  Sin callee_rbp (frame top) no aplica.
                if (callee_rbp == 0) continue;
                const uint64_t addr =
                    callee_rbp + loader::INTERP_SM_PUSH_FIRST_OFF +
                    static_cast<uint64_t>(slot.push_index()) * 8;
                value = proc_->vm_mem.read_u64(addr);
            } else {
                // Slot de spill: valor en [frame_rbp - (slot+1)*8].
                const uint64_t addr =
                    frame_rbp -
                    static_cast<uint64_t>(slot.slot_index() + 1) * 8;
                value = proc_->vm_mem.read_u64(addr);
            }
            if (value == 0) continue;
            cb(cb_ctx, value, static_cast<uint8_t>(slot.gc_kind));
            ++marked;
        }
    };

    // Frame TOP: PC = rip, rbp = base_pointer.  Sin callee_rbp (es el frame mas
    // interno; sus safepoints directos -newobj/gcalloc- no empujan handles).
    const uint64_t top_pc = proc_->registers.rip.raw();
    const uint64_t top_rbp = proc_->registers.base_pointer.qword();
    if (const auto *sm = lookup(top_pc)) {
        apply(sm, top_rbp, /*callee_rbp=*/0, /*is_top=*/true);
    }

    // Frames CALLER: caminamos la CADENA DE RBP guardada en vm_mem (el
    // frame-pointer clasico).  Para un frame que hizo `enter` (push rbp;
    // mov rbp,rsp), la memoria en:
    //   [rbp]     = rbp del caller (saved_rbp).
    //   [rbp + 8] = return_pc (el ret_addr que `callvm` empujo antes de que
    //               este frame ejecutara `enter`).
    // Ese return_pc es EXACTAMENTE el PC del caller (el sitio inmediatamente
    // posterior al call), donde el emisor coloco el marcador `// @sm`.  No
    // usamos @c frame_stack porque solo lo mantienen los CALL virtuales
    // (CALLVIRT/CALLM/...), no el CALLVM plano del camino de alocacion.
    //
    // Requiere que las funciones relevantes (las que alocan o retienen raices
    // GC a traves de un call) tengan FRAME; el emisor lo garantiza forzando
    // `enter` en esos casos (ver force_frame_gc en ir_emitter).  Las funciones
    // hoja sin frame no delimitan un rbp propio; sus raices (si las hubiera)
    // las cubre el scan conservador en modo aditivo -> soundness.  Cota
    // defensiva de 256 frames.
    uint64_t rbp = top_rbp;
    for (uint32_t depth = 0; depth < 256; ++depth) {
        if (rbp == 0 || (rbp & 7)) break;
        const uint64_t caller_rbp = proc_->vm_mem.read_u64(rbp);
        const uint64_t return_pc = proc_->vm_mem.read_u64(rbp + 8);
        // Fin de la cadena: rbp del caller invalido, no crece, o cae fuera
        // de la region de pila valida.
        if (caller_rbp == 0 || caller_rbp <= rbp) break;
        if (const auto *sm = lookup(return_pc)) {
            // El stackmap del sitio de retorno describe raices en el frame del
            // CALLER (caller_rbp): sus slots de spill sobre caller_rbp, y sus
            // handles empujados a traves del call sobre el rbp del CALLEE (este
            // frame, @c rbp) -- por encima del saved_rbp/return_pc que su enter
            // dejo, offset fijo aun con ALLOCA en el caller.
            apply(sm, caller_rbp, /*callee_rbp=*/rbp, /*is_top=*/false);
        }
        rbp = caller_rbp;
    }

    return marked;
}

bool ProcessVMRootProvider::all_interp_frames_have_stackmaps() {
    // Decision de cobertura precisa POR EJECUTABLE (backward-compat del flip a
    // preciso-primario).  Un frame del interprete pertenece a algun ejecutable
    // cargado; ese ejecutable soporta stackmaps precisos (seccion VSMP) sii su
    // formato es >= VERSION_VELB 0x4 -- la version del linker que emite la
    // seccion VSMP para CUALQUIER safepoint GC.  Un .velb con format_v < 4
    // (compilado antes del scan preciso) NO lleva stackmaps -> sus frames deben
    // escanearse con el conservador para no perder raices (UAF).
    //
    // Regla sound: preciso-primario SOLO si TODOS los ejecutables cargados son
    // format_v >= 4.  Basta un .velb viejo para mantener el conservador como
    // primario en todo el proceso.  Modelo "velb nuevo=preciso, viejo=
    // conservador" a granularidad de ejecutable (la unica robusta sin mapear
    // PC->modulo, que el loader fusiona en un solo espacio de direcciones).
    //
    // Un ejecutable format_v>=4 SIN entradas VSMP (modulo puramente aritmetico
    // sin ops GC) sigue siendo preciso-capaz: el linker omite la seccion solo
    // cuando NO hay safepoints, es decir cuando no hay raices GC que perder.
    const auto &executables =
        proc_->scheduler.vm_reference.loader_public.executables;
    if (executables.empty())
        return false; // sin ejecutables -> no asumir preciso
    for (const auto &exe_ptr : executables) {
        if (!exe_ptr) continue;
        if (exe_ptr->header.format_v < 0x4)
            return false; // legacy -> conservador
    }
    return true;
}

bool ProcessVMRootProvider::shared_contains(const uint8_t *ptr) {
    return proc_->scheduler.vm_reference.shared_heap.contains(ptr);
}

uint8_t *ProcessVMRootProvider::shared_lookup(gc::GcHandle h) {
    return proc_->scheduler.vm_reference.shared_handle_table.lookup(h);
}

gc::WaitTable *ProcessVMRootProvider::shared_wait_table() {
    return &proc_->scheduler.vm_reference.shared_wait_table;
}

} // namespace runtime
