/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file public_wrapper.cpp
 * @brief Implementacion de la API C estable @c vesta_rt/public.h.
 *
 * Cada wrapper es un thin shim que delega a la implementacion C++
 * interna.  Coste de la frontera: cero overhead (las funciones son
 * @c inline o llamadas directas; el compilador elimina la indirec-
 * cion cuando hay LTO o inlines).
 *
 * Los punteros opacos del header publico se castean a los tipos
 * reales del runtime:
 *
 *   vrt_proc*   -> runtime::ProcessVM*
 *   vrt_vm*     -> runtime::VM*
 *   vrt_class*  -> loader::ClassInfo*
 *   vrt_method* -> loader::MethodInfo*
 *   vrt_handle  -> gc::GcHandle (uint32_t)
 *
 * Por construccion (`extern "C"` + tipos POD-like), este modulo es
 * linkable contra cualquier toolchain (Cranelift, ensamblador a mano,
 * plugins terceros).
 */

#include "vesta_rt/public.h"
#include "vesta_rt/abi.h"

#include <cstdio>
#include <cstring>
#include <new> // placement-new (vrt_newobjs)
#include <string>
#include <csetjmp> // longjmp del watchdog CTPE

/* FFI runtime (vrt_dlopen): API de carga dinamica del SO. */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "gc/gc_heap.h"
#include "jit/auto_jit.h"
#include "jit/interp_jit_bridge.h"
#include "loader/class_registry.h"
#include "loader/loader.h"
#include "loader/oop_types.h"
#include "runtime/decode_instruction.h"
#include "runtime/exception_runtime.h"
#include "runtime/host_alloca_tracker.h"
#include "runtime/manager_runtime.h"
#include "runtime/native_invoke.h"
#include "runtime/proceso_runtime.h"
#include "runtime/string_runtime.h"
#include "runtime/runtime.h"
#include "runtime/string_runtime.h"
#include "loader/string_object.h"

#include <cstring>

/* Forward-decl SOLO de la fn que necesitamos para el dispatch de advices desde
 * codigo JIT (no incluimos exec_instruction.h entero para no arrastrar sus
 * definiciones inline a este TU -> evita choques de ODR/layout).  Debe estar a
 * scope GLOBAL (::runtime), no dentro del namespace anonimo de abajo. */
namespace runtime {
void exec_instr_callvirt(ProcessVM *vm, const DecodedInstr &instr);
}

namespace {
/* Cast helpers locales para mantener legible el resto del codigo. */
inline runtime::ProcessVM *as_proc(vrt_proc *p) noexcept {
    return reinterpret_cast<runtime::ProcessVM *>(p);
}
inline runtime::VM *as_vm(vrt_vm *v) noexcept {
    return reinterpret_cast<runtime::VM *>(v);
}
inline loader::ClassInfo *as_class(vrt_class *c) noexcept {
    return reinterpret_cast<loader::ClassInfo *>(c);
}

/*
 * Guard del boundary del scan preciso de GC para el modo interp+JIT.
 *
 * Se construye AL INICIO de cada runtime-entry (@c vrt_*) que (a) el codigo
 * JIT llama DIRECTAMENTE y (b) puede disparar una coleccion (alloc en el
 * @c gc_heap del proceso).  Captura la frontera C<-JIT:
 *
 *   pc = __builtin_return_address(0)   -> direccion de retorno al codigo JIT.
 *   sp = __builtin_frame_address(0)+16 -> RSP del frame JIT antes del @c call.
 *
 * El GC (@c scan_jit_roots_precise / @c scan_jit_forwards) sube por la pila con
 * @c frame_size (@c scan_aot_frames) desde ese par, saltando los frames C++ del
 * runtime que a -O0 rompen la cadena RBP (p.ej. @c lea rbp,[rsp+N]).  El dtor
 * restaura el boundary previo -> solo es valido DURANTE esta llamada (nunca
 * camina un frame JIT ya retornado; nesting seguro via save/restore).
 *
 * El @c +16 vale porque la entry hace @c push rbp; mov rbp,rsp (forzado por
 * @c VRT_FORCE_FP): @c frame_address(0)=RBP, @c [RBP+8]=retorno,
 * @c RBP+16=RSP del llamador justo antes del @c call.
 */
struct JitBoundaryGuard {
    gc::GcHeap &h;
    gc::GcHeap::JitScanBoundary prev;
    JitBoundaryGuard(gc::GcHeap &heap, uint64_t pc, uint64_t sp) noexcept
        : h(heap), prev(heap.jit_scan_boundary()) {
        h.set_jit_scan_boundary(pc, sp);
    }
    ~JitBoundaryGuard() noexcept { h.restore_jit_scan_boundary(prev); }
    JitBoundaryGuard(const JitBoundaryGuard &) = delete;
    JitBoundaryGuard &operator=(const JitBoundaryGuard &) = delete;
};
} // namespace

/* Fuerza frame pointer en la entry para que @c __builtin_frame_address(0) sea
 * fiable (mismo mecanismo que @c VX_GC_FORCE_FP en libvesta_gc). */
#if defined(__GNUC__)
#define VRT_FORCE_FP __attribute__((optimize("no-omit-frame-pointer")))
#else
#define VRT_FORCE_FP
#endif

/* Declara un @c JitBoundaryGuard local que captura el frame JIT llamador.  Los
 * builtins se evaluan en el contexto de la entry (retorno + RBP de la entry).
 */
#if defined(__GNUC__)
#define VRT_CAPTURE_JIT_FRAME(p)                                               \
    JitBoundaryGuard _jit_bnd(                                                 \
        (p)->gc_heap, reinterpret_cast<uint64_t>(__builtin_return_address(0)), \
        reinterpret_cast<uint64_t>(__builtin_frame_address(0)) + 16u)
#else
#define VRT_CAPTURE_JIT_FRAME(p) ((void)0)
#endif

extern "C" {

/* ----------------------------------------------------------------------- */
/* Version                                                                  */
/* ----------------------------------------------------------------------- */

uint32_t vrt_api_version(void) {
    /* version encoded como (major << 16) | (minor << 8) | patch */
    return (static_cast<uint32_t>(VRT_API_VERSION_MAJOR) << 16) |
           (static_cast<uint32_t>(VRT_API_VERSION_MINOR) << 8) |
           static_cast<uint32_t>(VRT_API_VERSION_PATCH);
}

/* ----------------------------------------------------------------------- */
/* GC                                                                       */
/* ----------------------------------------------------------------------- */

VRT_FORCE_FP vrt_handle vrt_gc_alloc(vrt_proc *proc, size_t size) {
    if (!proc) return VRT_NULL_HANDLE;
    runtime::ProcessVM *p = as_proc(proc);
    /* Capturar el frame JIT llamador: el alloc puede disparar minor/major_gc y
     * el scan preciso necesita el par (pc,sp) para caminar por frame_size. */
    VRT_CAPTURE_JIT_FRAME(p);
    return p->gc_heap.alloc(size);
}

VRT_FORCE_FP vrt_handle vrt_gc_alloc_pinned(vrt_proc *proc, size_t size) {
    if (!proc) return VRT_NULL_HANDLE;
    runtime::ProcessVM *p = as_proc(proc);
    VRT_CAPTURE_JIT_FRAME(p);
    return p->gc_heap.alloc_pinned(size);
}

/* Raw heap host (malloc/free): bloque no-GC, dereferenciable directo
 * por codigo C nativo.  Usado por callbacks que necesitan alocar
 * structs Win32/POSIX para pasar a APIs nativas. */
uint8_t *vrt_raw_alloc(vrt_proc *proc, size_t size) {
    if (!proc) return nullptr;
    auto *p = as_proc(proc);
    /* El asignador del PROGRAMA, si lo hay: el monton tiene que ser uno solo
     * para todos los caminos, o un bloque acaba pidiendose por uno y
     * soltandose por otro. */
    if (p->alloc_del_programa != 0) {
        p->registers.regs[runtime::R01].qword(size);
        auto fn = reinterpret_cast<uint64_t (*)(void *)>(
            static_cast<uintptr_t>(p->alloc_del_programa));
        fn(p);
        return reinterpret_cast<uint8_t *>(
            p->registers.regs[runtime::R00].qword());
    }
    uint64_t ptr = p->raw_alloc.alloc(size);
    return reinterpret_cast<uint8_t *>(ptr);
}

void vrt_raw_free(vrt_proc *proc, uint8_t *ptr) {
    if (!proc || !ptr) return;
    auto *p = as_proc(proc);
    if (p->free_del_programa != 0) {
        p->registers.regs[runtime::R01].qword(reinterpret_cast<uint64_t>(ptr));
        auto fn = reinterpret_cast<uint64_t (*)(void *)>(
            static_cast<uintptr_t>(p->free_del_programa));
        fn(p);
        return;
    }
    p->raw_alloc.free(reinterpret_cast<uint64_t>(ptr));
}

uint8_t *vrt_gc_deref(vrt_proc *proc, vrt_handle h) {
    if (!proc || h == VRT_NULL_HANDLE) return nullptr;
    return as_proc(proc)->gc_heap.deref(h);
}

vrt_handle vrt_gc_handle_for_ptr(vrt_proc *proc, const uint8_t *payload) {
    if (!proc || !payload) return VRT_NULL_HANDLE;
    return as_proc(proc)->gc_heap.handle_for_ptr(payload);
}

void vrt_gc_drop(vrt_proc *proc, vrt_handle h) {
    if (!proc || h == VRT_NULL_HANDLE) return;
    as_proc(proc)->gc_heap.drop(h);
}

void vrt_gc_addref(vrt_proc *proc, vrt_handle h) {
    if (!proc || h == VRT_NULL_HANDLE) return;
    as_proc(proc)->gc_heap.gc_addref(h);
}

void vrt_gc_release(vrt_proc *proc, vrt_handle h) {
    if (!proc || h == VRT_NULL_HANDLE) return;
    as_proc(proc)->gc_heap.gc_release(h);
}

void vrt_gc_write_barrier(vrt_proc *proc, vrt_handle old_handle) {
    if (!proc || old_handle == VRT_NULL_HANDLE) return;
    as_proc(proc)->gc_heap.write_barrier(old_handle);
}

/* ----------------------------------------------------------------------- */
/* Monitores                                                                */
/* ----------------------------------------------------------------------- */
/*
 * Los monitores en VestaVM viven en el ObjectHeader (owner_pid +
 * lock_depth).  GcHeap expone metodos C++ para adquirir/liberar; aqui
 * los wrappeamos con la signatura C estable.
 *
 * NOTE v1: el wake-up del proximo waiter requiere coordinacion con el
 * scheduler (vm.make_ready).  En v1 los wrappers solo implementan el
 * fast path (lock disponible o reentrante).  El slow path (cola de
 * espera + wake) seguira pasando por el bytecode interpretado hasta
 *  E (D.2).
 */

int32_t vrt_monitor_enter(vrt_proc *proc, vrt_handle obj) {
    if (!proc || obj == VRT_NULL_HANDLE) return 0;
    runtime::ProcessVM *p = as_proc(proc);
    //  Z.11 ext: usamos el PID encoded (sched<<32|local) de 48 bits para
    // evitar la colision local_pid cross-scheduler.
    const uint64_t pid = (static_cast<uint64_t>(p->pid.scheduler_id) << 32) |
                         static_cast<uint64_t>(p->pid.local_pid);
    return p->gc_heap.monitor_try_acquire(obj, pid) ? 1 : 0;
}

void vrt_monitor_exit(vrt_proc *proc, vrt_handle obj) {
    if (!proc || obj == VRT_NULL_HANDLE) return;
    runtime::ProcessVM *p = as_proc(proc);
    const uint64_t pid = (static_cast<uint64_t>(p->pid.scheduler_id) << 32) |
                         static_cast<uint64_t>(p->pid.local_pid);
    (void)p->gc_heap.monitor_release(obj, pid);
    /* TODO  E (D.2): si monitor_release devuelve un waiter,
     * llamar vm.make_ready(next).  Por ahora el bytecode handler
     * en exec_instruction_sync.cpp se encarga. */
}

void vrt_monitor_wait(vrt_proc *proc, vrt_handle obj) {
    /* Slow path: queda como stub.  El JIT en v1 cae al interprete
     * via el trampoline @c jit_to_interp para llamar al bytecode
     * MONWAIT.  En  E expondremos un wait completo aqui. */
    (void)proc;
    (void)obj;
}

void vrt_monitor_notify(vrt_proc *proc, vrt_handle obj) {
    if (!proc || obj == VRT_NULL_HANDLE) return;
    /* monitor_pop_waiter devuelve UN waiter o GC_NULL_HANDLE; el
     * caller debe propagarlo al scheduler.  Stub minimo. */
    (void)as_proc(proc)->gc_heap.monitor_pop_waiter(obj);
}

void vrt_monitor_notify_all(vrt_proc *proc, vrt_handle obj) {
    if (!proc || obj == VRT_NULL_HANDLE) return;
    (void)as_proc(proc)->gc_heap.monitor_pop_all_waiters(obj);
}

/* ----------------------------------------------------------------------- */
/* Excepciones                                                              */
/* ----------------------------------------------------------------------- */

/**
 * @brief Deja apuntado DESDE DONDE se rindio el codigo compilado.
 *
 * Cuando el programa se rinde por su cuenta -- un `throw`, un `panic`, un
 * desenvolver que no tenia nada -- no hay ningun fallo que el sistema avise,
 * asi que no queda ninguna direccion capturada.  Y el PC de la maquina virtual
 * no sirve: dentro del codigo compilado no se va actualizando, asi que la traza
 * acababa senalando una sentencia cualquiera de mas arriba -- o la primera
 * funcion del programa.
 *
 * Lo que SI se sabe es quien llamo a este ayudante, y esa es exactamente la
 * instruccion que se rindio.
 *
 * No pisa lo que ya hubiera: si el sistema aviso de un fallo, esa direccion es
 * mas precisa que esta.
 *
 * @param p     Proceso.
 * @param ret   Direccion de RETORNO del llamante (apunta al byte de despues de
 *              la llamada, de ahi @c pending_fault_native_is_return).
 * @param frame Por donde iba la pila nativa, para recorrer la cadena.
 */
static void anotar_origen_nativo(runtime::ProcessVM *p, void *ret,
                                 void *frame) {
    if (!p || p->pending_fault_native_pc != 0) return;
    p->pending_fault_native_pc = reinterpret_cast<uint64_t>(ret);
    p->pending_fault_native_sp = reinterpret_cast<uint64_t>(frame);
    p->pending_fault_native_is_return = true;
}

/* Los dos builtins tienen que evaluarse EN el llamante -- dentro del ayudante
 * darian la direccion del ayudante --, por eso se toman aqui y se pasan. */
#if defined(__GNUC__) || defined(__clang__)
#define VESTA_ANOTAR_ORIGEN(p)                                                 \
    anotar_origen_nativo((p), __builtin_return_address(0),                     \
                         __builtin_frame_address(0))
#else
#define VESTA_ANOTAR_ORIGEN(p) ((void)0)
#endif

void vrt_throw_fatal(vrt_proc *proc, uint32_t kind, const char *message) {
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);
    VESTA_ANOTAR_ORIGEN(p);
    runtime::throw_fatal(p, kind, message);
}

void vrt_unwrap_throw(vrt_proc *proc) {
    if (!proc) return;
    VESTA_ANOTAR_ORIGEN(as_proc(proc));
    /* Lo MISMO que exec_instr_unwrap (bytecode 0x26), y ahi esta explicado por
     * que no es capturable: desenvolver es afirmar que hay algo, y fallar la
     * afirmacion es un bug, no una condicion recuperable.  El nativo ya se
     * comportaba asi (aborta por `__vx_panic_null`); esto hace que los tres
     * modos coincidan. */
    runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                         "unwrap sobre Optional/Result/referencia null",
                         /*catchable=*/false);
}

/* Forward decl: do_throw vive en exec_instruction_oop.cpp con C++ mangling.
 * NO debe estar en el extern "C" envolvente; usamos un alias que pueda ser
 * llamado desde las funciones C. */
void vrt_internal_do_throw(runtime::ProcessVM *vm, uint64_t exc_handle);

void vrt_tryenter(vrt_proc *proc, uint64_t handler_pc, vrt_class *type_class) {
    /* Replica EXACTA de @c exec_instr_tryenter sin la parte de
     * @c reductions_remaining (irrelevante en frame JIT: el batch ya
     * lo controla el scheduler enclosing).
     *
     * Aloca un ExceptionFrame en heap raw + lo inicializa con:
     *   - handler_pc: direccion del catch (absoluta VM)
     *   - type:        ClassInfo* del catch (nullptr = catch-all)
     *   - saved_rsp/rbp/frame_stack: snapshot para descartar
     *     pushes del regalloc + frames OOP inacabados durante throw.
     *   - saved_regs[0..15]: snapshot de R0..R15 para que el catch
     *     vea el mismo estado que el try entry (igual que C/C++ exc). */
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);

    /* Acquire del free list si tiene frames recicladas; sino alloca.
     * El free list lo popula @c tryleave (bytecode + JIT inline),
     * eliminando malloc/free pressure y leak por programas con many
     * try/catch en loops. */
    runtime::ProcessVM::ExceptionFrame *ef;
    if (p->exc_free_list != nullptr) {
        ef = p->exc_free_list;
        p->exc_free_list = ef->prev;
    } else {
        ef = new runtime::ProcessVM::ExceptionFrame();
    }
    ef->handler_pc = handler_pc;
    ef->type = reinterpret_cast<loader::ClassInfo *>(type_class);
    ef->saved_rsp = p->registers.stack_pointer.qword();
    ef->saved_rbp = p->registers.base_pointer.qword();
    ef->saved_frame_stack = reinterpret_cast<uint64_t>(p->frame_stack);
    for (int i = 0; i < 16; ++i) {
        ef->saved_regs[i] = p->registers.regs[i].qword();
    }
    ef->prev = p->exc_frame_stack;
    p->exc_frame_stack = ef;
}

void vrt_tryleave(vrt_proc *proc) {
    /* Pop del tope + push al free list para reciclar.  El JIT inlinea
     * la misma logica en 7 instrucciones x86-64 cuando @c
     * exc_frame_stack_offset
     * + @c exc_free_list_offset estan configurados (~3x mas rapido que
     * llegar aqui via call).  Esta version C es fallback para bytecode
     * interp + JIT en modo testing sin offsets. */
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);
    if (p->exc_frame_stack == nullptr) return;
    auto *top = p->exc_frame_stack;
    p->exc_frame_stack = top->prev;
    /* Push al free list (reusar campo prev). */
    top->prev = p->exc_free_list;
    p->exc_free_list = top;
}

void vrt_tryenter_jit(vrt_proc *proc, vrt_class *type_class,
                      uint64_t native_catch_addr) {
    /* Frame de excepcion in-JIT: el handler vive en codigo JIT (no bytecode).
     * Igual que @c vrt_tryenter pero ademas registra native_catch_addr +
     * native_rsp/rbp para que @c do_throw resuma via @c vrt_resume_jit.  El
     * snapshot de regs/VM-rsp/rbp/frame_stack se mantiene (lo usa do_throw
     * para la limpieza VM antes del salto y para restaurar R1..R15 del catch
     * que el frontend reload-ea desde slots). */
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);
    runtime::ProcessVM::ExceptionFrame *ef;
    if (p->exc_free_list != nullptr) {
        ef = p->exc_free_list;
        p->exc_free_list = ef->prev;
    } else {
        ef = new runtime::ProcessVM::ExceptionFrame();
    }
    ef->handler_pc = 0; /* no se usa: el resume es nativo */
    ef->type = reinterpret_cast<loader::ClassInfo *>(type_class);
    ef->saved_rsp = p->registers.stack_pointer.qword();
    ef->saved_rbp = p->registers.base_pointer.qword();
    ef->saved_frame_stack = reinterpret_cast<uint64_t>(p->frame_stack);
    for (int i = 0; i < 16; ++i)
        ef->saved_regs[i] = p->registers.regs[i].qword();
    ef->native_catch_addr = native_catch_addr;
    /* RSP/RBP host del frame del try: handoff transitorio escrito por el JIT
     * justo antes de esta llamada (evita un 5o arg en pila Win64). */
    ef->native_rsp = p->jit_exc_rsp;
    ef->native_rbp = p->jit_exc_rbp;
    ef->prev = p->exc_frame_stack;
    p->exc_frame_stack = ef;
}

#if defined(__GNUC__)
__attribute__((noreturn))
#endif
void vrt_resume_jit(uint64_t catch_addr, uint64_t native_rsp,
                    uint64_t native_rbp, uint64_t proc) {
    /* Restaura el frame host del try y salta al bloque catch JIT.  Abandona
     * los frames nativos intermedios reseteando RSP.
     *
     * CRITICO: restaurar RBX = proc.  En VM_ABI el JIT mantiene el ProcessVM*
     * en RBX (callee-saved, fijado en el prologue).  El path del throw
     * (vrt_throw_user/do_throw, funciones C) salvo el RBX del JIT en SUS frames
     * y nunca lo restauro (no retornan, saltamos desde aqui) -> RBX trae basura
     * al llegar al catch.  El catch usa RBX para acceder a proc, asi que lo
     * recargamos.  El epilogue del catch restaura los demas callee-saved
     * (r12-r15) desde su home en el frame (memoria intacta, rbp-relativo).
     *
     * Los operandos viven en registros (constraint "r"), distintos de
     * RSP/RBP/RBX, asi que siguen validos tras cambiarlos.  Orden: RBX, RBP,
     * RSP, JMP (cada paso solo toca su destino). */
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile("mov %3, %%rbx\n\t"
                     "mov %0, %%rbp\n\t"
                     "mov %1, %%rsp\n\t"
                     "jmp *%2\n\t"
                     :
                     : "r"(native_rbp), "r"(native_rsp), "r"(catch_addr),
                       "r"(proc)
                     : "memory");
#else
    (void)catch_addr;
    (void)native_rsp;
    (void)native_rbp;
    (void)proc;
#endif
    __builtin_unreachable();
}

void vrt_throw_user(vrt_proc *proc, uint64_t exc_handle) {
    /* Delega a do_throw.  Nunca retorna normalmente -- do_throw modifica
     * RIP/RSP/RBP/regs del proceso y el JIT-eado debe detectar el cambio
     * via... bueno, no puede.  El throw rompe el flujo normal: tras este
     * call, el JIT frame queda en estado inconsistente.
     *
     * v1: confiamos en que do_throw setea el RIP al handler.  El JIT
     * NO debe ejecutar nada despues de esta llamada (el lowering del
     * frontend marca el bloque como terminator post-throw, asi que no
     * habra mas instrucciones JIT en ese bloque).
     *
     * BUG conocido v1: si el handler PC esta en codigo bytecode (no JIT),
     * el control regresa al interp via el scheduler.  Pero el JIT frame
     * sigue activo en host stack -> stale frame.  Cuando el handler
     * eventualmente RET-ea, salta a la direccion de retorno bytecode
     * (sentinel del trampoline o frame OOP) y todo funciona.  Si el handler
     * RET-ea a la JIT frame original... unwinding cruzado no soportado.
     *
     * Para v1 SOLO soportamos: throw desde JIT cuando el catch esta TAMBIEN
     * en codigo bytecode (caso comun: el frontend emite catch como bloque
     * de bytecode, NO como JIT-callable function). */
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);
    VESTA_ANOTAR_ORIGEN(p);
    vrt_internal_do_throw(p, exc_handle);
}

void vrt_rethrow(vrt_proc *proc) {
    /* Relanza la excepcion activa.  El frontend la emite tras hacer monexit
     * en el handler de un synchronized: el flujo es body -> throw -> catch
     * (frame del synchronized) -> monexit -> rethrow -> outer catch.
     *
     * Mismas limitaciones que vrt_throw_user. */
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);
    VESTA_ANOTAR_ORIGEN(p);
    vrt_internal_do_throw(p, p->current_exception);
}

/* ----------------------------------------------------------------------- */
/* FFI nativo                                                               */
/* ----------------------------------------------------------------------- */

uint64_t vrt_invoke_native(void *fn, uint64_t argc, vrt_proc *proc) {
    if (!fn || !proc) return 0;
    return runtime::invoke_native_unchecked(fn, argc, as_proc(proc));
}

/* ----------------------------------------------------------------------- */
/* Dispatch dinamico (CALLVIRT desde JIT)                                  */
/* ----------------------------------------------------------------------- */

/* Forward decl: definido mas abajo (compartido entre vrt_callvirt y vrt_callm).
 */
static uint64_t vrt_run_method_in_interp(runtime::ProcessVM *p,
                                         loader::MethodInfo *mi);
static uint64_t vrt_run_callvirt_with_advices(runtime::ProcessVM *p,
                                              uint8_t *obj_payload,
                                              uint32_t vtbl_idx);

uint64_t vrt_callvirt(vrt_proc *proc, uint8_t *obj_payload, uint32_t vtbl_idx) {
    if (!proc || !obj_payload) {
        if (proc) {
            runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                                 "callvirt: obj payload nulo");
        }
        return 0;
    }
    runtime::ProcessVM *p = as_proc(proc);

    /* Convencion bytecode/Vesta: obj_payload APUNTA al ObjectHeader (NO al
     * payload de campos).  El gcderef del bytecode devuelve `addr +
     * sizeof(GcHeader)` que ES la direccion del ObjectHeader; y los campos
     * siguen DESPUES del header a offset >= sizeof(ObjectHeader).  Tratar
     * obj_payload directamente como ObjectHeader* es lo consistente con el
     * resto del runtime. */
    loader::ObjectHeader *hdr =
        reinterpret_cast<loader::ObjectHeader *>(obj_payload);
    loader::ClassInfo *cls = hdr->class_ptr;
    if (!cls || vtbl_idx >= cls->vtable_size) {
        runtime::throw_fatal(
            p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
            "callvirt: clase nula o vtable_idx fuera de rango");
        return 0;
    }
    loader::MethodInfo *method = cls->vtable[vtbl_idx];
    if (!method) {
        runtime::throw_fatal(p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
                             "callvirt: vtable slot vacio (metodo abstracto?)");
        return 0;
    }

    /* Si el metodo aun no esta JIT-compilado, intentar compilarlo ahora.
     * Esto fuerza el camino lazy: cualquier callvirt desde JIT compila
     * tambien la callee (con threshold=1 efectivo) para que la proxima
     * invocacion sea directa. */
    if (method->jit_code == nullptr) {
        const uint32_t saved = method->invocation_count;
        method->invocation_count = jit::g_jit_threshold;
        jit::maybe_compile_method(p, method);
        /* maybe_compile_method puede haber seteado invocation_count
         * a UINT32_MAX si fallo - no resetear en ese caso. */
        if (method->jit_code == nullptr) {
            method->invocation_count = saved;
        }
    }

    /* Si el metodo tiene advices (AOP @Before/@After/@Around), NO podemos
     * llamar directo al JIT-eated body porque eso salta la cadena
     * advice_chain.  Caemos al bytecode interp que SI recorre la cadena
     * correctamente (ver exec_instr_callvirt slow path).
     *
     * NOTA (raw_asm-elim Fase 2c): este fallback (vrt_run_method_in_interp)
     * salta al cuerpo del metodo y TAMBIEN se salta los advices, lo que es un
     * bug latente del JIT con AOP.  Por eso el frontend marca las funciones que
     * REGISTRAN advices (addadvice) como no-JIT-compilables (ver vreg_select /
     * selector), forzando que el programa AOP corra `main` en interp -> los
     * CALLVIRT recorren la cadena correctamente y este path no se ejercita.  Un
     * fix completo (dispatch de la cadena desde JIT) queda como trabajo futuro.
     */
    if (method->advice_chain != nullptr) {
        return vrt_run_callvirt_with_advices(p, obj_payload, vtbl_idx);
    }

    if (method->jit_code != nullptr) {
        /* Dispatch directo a codigo nativo.  VM_ABI: args ya en
         * proc->registers.regs[1..N] (el caller los puso antes de invocar
         * vrt_callvirt).  Solo necesitamos asegurar R1 = obj_payload. */
        p->registers.regs[1].qword(reinterpret_cast<uint64_t>(obj_payload));
        jit::JitFn fn = reinterpret_cast<jit::JitFn>(method->jit_code);
        return jit::enter_jit(fn, proc);
    }

    /* Metodo no compilable (raw_asm complejo, float ops, synchronized, etc).
     * FALLBACK 2026-05-16: ejecutar el bytecode del metodo en mini-interp
     * sincronico.  Mismo flujo que vrt_callm fallback.  Lento pero CORRECTO. */
    p->registers.regs[1].qword(reinterpret_cast<uint64_t>(obj_payload));
    return vrt_run_method_in_interp(p, method);
}

/* INLINE CACHE variant: igual que vrt_callvirt pero al final escribe
 * (class_ptr, jit_code) en el slot de cache pasado.  Si el slot ya tiene
 * el mismo class_ptr (hit), el JIT-eated code ya hizo dispatch directo
 * sin llamar esta funcion.  Solo se invoca en MISS path o primera
 * invocacion (slot a 0).  Layout del slot (16 bytes):
 *   +0  [8] cached_class_ptr
 *   +8  [8] cached_jit_code (o vrt_run_method_in_interp_addr para fallback)
 */
uint64_t vrt_callvirt_ic(vrt_proc *proc, uint8_t *obj_payload,
                         uint32_t vtbl_idx, uint64_t ic_slot_addr) {
    if (!proc || !obj_payload) {
        if (proc) {
            runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                                 "callvirt_ic: obj payload nulo");
        }
        return 0;
    }
    runtime::ProcessVM *p = as_proc(proc);
    loader::ObjectHeader *hdr =
        reinterpret_cast<loader::ObjectHeader *>(obj_payload);
    loader::ClassInfo *cls = hdr->class_ptr;
    if (!cls || vtbl_idx >= cls->vtable_size) {
        runtime::throw_fatal(
            p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
            "callvirt_ic: clase nula o vtable_idx fuera de rango");
        return 0;
    }
    loader::MethodInfo *method = cls->vtable[vtbl_idx];
    if (!method) {
        runtime::throw_fatal(
            p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
            "callvirt_ic: vtable slot vacio (metodo abstracto?)");
        return 0;
    }

    if (method->jit_code == nullptr) {
        const uint32_t saved = method->invocation_count;
        method->invocation_count = jit::g_jit_threshold;
        jit::maybe_compile_method(p, method);
        if (method->jit_code == nullptr) {
            method->invocation_count = saved;
        }
    }

    /* Actualizar el slot PIC (Polymorphic Inline Cache, 4 entries de
     * 16 bytes cada una).  Layout:
     *   slot[0,1]  -> entry 0: [class_ptr, jit_code]
     *   slot[2,3]  -> entry 1
     *   slot[4,5]  -> entry 2
     *   slot[6,7]  -> entry 3
     *
     * Politica de reemplazo:
     *   1. Si hay alguna entry con class==0 (libre), poner ahi.
     *   2. Si todas estan ocupadas (4 tipos distintos vistos en este
     *      call site = megamorfico), rotar: shift entries 1..3 a 0..2
     *      y poner la nueva en [3].  Esto mantiene la "ultima vista"
     *      al final, beneficiando el orden de chequeo del JIT (que
     *      prueba entry 0 primero).
     *
     * Solo se actualiza si hay jit_code Y NO hay advices.  Sin
     * jit_code el inline cache no sirve (no podriamos llamar
     * directo); con advices necesitamos el slow path siempre. */
    if (ic_slot_addr != 0 && method->jit_code != nullptr &&
        method->advice_chain == nullptr) {
        uint64_t *slot = reinterpret_cast<uint64_t *>(ic_slot_addr);
        const uint64_t cls_u = reinterpret_cast<uint64_t>(cls);
        const uint64_t code_u = reinterpret_cast<uint64_t>(method->jit_code);
        /* Buscar entry vacia.  Si la clase YA esta cacheada (caso raro
         * de race en multi-thread), actualizar su jit_code. */
        int free_idx = -1;
        for (int i = 0; i < 4; ++i) {
            const uint64_t s_cls = slot[i * 2];
            if (s_cls == cls_u) {
                slot[i * 2 + 1] = code_u;
                free_idx = -2; /* sentinel: ya cacheada, no insertar */
                break;
            }
            if (free_idx < 0 && s_cls == 0) {
                free_idx = i;
            }
        }
        if (free_idx >= 0) {
            slot[free_idx * 2] = cls_u;
            slot[free_idx * 2 + 1] = code_u;
        } else if (free_idx == -1) {
            /* Todas ocupadas con otras clases -> rotar.  Entry 0 cae,
             * 1->0, 2->1, 3->2, nueva clase en 3. */
            slot[0] = slot[2];
            slot[1] = slot[3];
            slot[2] = slot[4];
            slot[3] = slot[5];
            slot[4] = slot[6];
            slot[5] = slot[7];
            slot[6] = cls_u;
            slot[7] = code_u;
        }
    }

    if (method->jit_code != nullptr && method->advice_chain == nullptr) {
        p->registers.regs[1].qword(reinterpret_cast<uint64_t>(obj_payload));
        jit::JitFn fn = reinterpret_cast<jit::JitFn>(method->jit_code);
        return jit::enter_jit(fn, proc);
    }

    p->registers.regs[1].qword(reinterpret_cast<uint64_t>(obj_payload));
    return vrt_run_method_in_interp(p, method);
}

/* Sentinel para el fallback bytecode sincronico: cuando un metodo
 * invocado desde JIT no se puede JIT-compilar, ejecutamos su bytecode
 * en un mini-loop interno hasta que el RET del frame haga PC =
 * VRT_BYTECODE_RET_SENTINEL.  Usamos un valor alto (>4GB, fuera del
 * rango de VAs del .velb) para que sea distinguible.  Si por algun
 * motivo el bytecode itera fuera del codigo (e.g. corrupcion), el
 * proceso saldra por EVT_HALT/EVT_ERROR antes. */
static constexpr uint64_t VRT_BYTECODE_RET_SENTINEL = 0xFEFEFEFE00000000ULL;

/* Helper compartido: ejecuta el bytecode VM en @p p comenzando en
 * @p bc_va, en un mini run-loop sincronico, hasta que el RET final pop
 * el sentinel y salte a el.  No pushea frame OOP (uso para funciones
 * libres / closures; los metodos virtuales usan vrt_run_method_in_interp
 * que SI pushea el frame OOP).
 *
 * Args y resultado pasan por la convencion VM_ABI estandar:
 *   - args en proc->registers.regs[1..N] (puestos por el caller)
 *   - argc en proc->registers.regs[15]
 *   - retorno en proc->registers.regs[0] (devuelto a este helper)
 *
 * Restaura rip/rsp/frame_stack/decoded_ptr al estado previo asi que
 * el JIT caller puede continuar normalmente.
 */
static uint64_t vrt_run_bc_at(runtime::ProcessVM *p, uint64_t bc_va) {
    const uint64_t saved_rip = p->registers.rip.raw();
    const uint64_t saved_rsp = p->registers.stack_pointer.qword();
    auto *saved_frame_stack = p->frame_stack;
    auto *saved_decoded_ptr = p->decoded_ptr;

    const uint64_t new_rsp = saved_rsp - 8;
    p->vm_mem.write_u64_fast(new_rsp, VRT_BYTECODE_RET_SENTINEL);
    p->registers.stack_pointer.qword(new_rsp);
    p->registers.rip.qword(bc_va);
    p->decoded_ptr = &p->icache[0];
    p->decoded_ptr->pc = UINT64_MAX;

    const uint64_t MAX_ITERS = 100'000'000;
    uint64_t iters = 0;
    while (iters++ < MAX_ITERS) {
        if (p->registers.rip.raw() == VRT_BYTECODE_RET_SENTINEL) break;
        if (p->state == runtime::HALT || p->state == runtime::DEAD) break;
        if (p->err_thread != runtime::THREAD_NO_ERROR) break;
        runtime::decode_instruction(p);
        runtime::vm_event ev = runtime::execute_instruction(p);
        if (ev == runtime::EVT_HALT || ev == runtime::EVT_ERROR) break;
        if (ev == runtime::EVT_IO_WAIT) {
            runtime::throw_fatal(p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
                                 "vrt trampoline JIT->interp: IO_WAIT no "
                                 "soportado en sync interp");
            break;
        }
    }

    p->registers.rip.qword(saved_rip);
    p->registers.stack_pointer.qword(saved_rsp);
    p->frame_stack = saved_frame_stack;
    p->decoded_ptr = saved_decoded_ptr;
    return p->registers.regs[0].qword();
}

/* Mini-interp sincronico: ejecuta el bytecode del metodo @p mi en el
 * proceso @p p.  Args ya estan en regs[1..N] (calling convention).
 * Pushea un frame OOP + ret_addr=SENTINEL, salta a mi->code_vaddr, y
 * loop hasta que RIP vuelva al SENTINEL (RET final del metodo).
 * Retorna regs[0] al terminar.
 *
 * Restaura RIP, RSP, frame_stack y decoded_ptr al estado previo para
 * que el JIT caller pueda continuar normalmente. */
static uint64_t vrt_run_method_in_interp(runtime::ProcessVM *p,
                                         loader::MethodInfo *mi) {
    /* Salvar estado del proceso. */
    const uint64_t saved_rip = p->registers.rip.raw();
    const uint64_t saved_rsp = p->registers.stack_pointer.qword();
    auto *saved_frame_stack = p->frame_stack;
    auto *saved_decoded_ptr = p->decoded_ptr;

    /* Push ret_addr sentinel al stack VM. */
    const uint64_t new_rsp = saved_rsp - 8;
    p->vm_mem.write_u64_fast(new_rsp, VRT_BYTECODE_RET_SENTINEL);
    p->registers.stack_pointer.qword(new_rsp);

    /* Push frame OOP (necesario para que callvirt/proceed funcionen
     * desde dentro del metodo si los usa). */
    auto *frame = p->frame_pool.acquire();
    frame->prev = p->frame_stack;
    frame->method = mi;
    frame->return_pc = VRT_BYTECODE_RET_SENTINEL;
    frame->frame_base = saved_rsp;
    frame->proceed_target = nullptr;
    /* CRITICO: inicializar los campos AOP/save-regs del frame.  El
     * frame_pool reusa frames y NO los limpia; sin esta inicializacion,
     * el frame hereda basura del uso anterior y @c exec_instr_ret puede
     * hacer @c delete[] de un @c around_chain corrupto (heap corruption)
     * o restaurar r1..r12 desde un snapshot basura.  Mismo conjunto de
     * campos que inicializa el push_step normal (exec_instruction_oop.cpp). */
    frame->around_chain = nullptr;
    frame->around_chain_len = 0;
    frame->around_chain_owns = 0;
    frame->has_saved_regs = 0;
    frame->inject_r0_to_reg = 0;
    p->frame_stack = frame;

    /* Saltar al code del metodo. */
    p->registers.rip.qword(mi->code_vaddr);

    /* Reset decoded_ptr para forzar fresh decode. */
    p->decoded_ptr = &p->icache[0];
    p->decoded_ptr->pc =
        UINT64_MAX; /* invalidar para que decode no haga HIT erroneo */

    /* Mini run-loop: ejecutar hasta que el frame retorne al sentinel
     * o el proceso entre en HALT/DEAD/error.  Max iters defensivo. */
    const uint64_t MAX_ITERS = 100'000'000;
    uint64_t iters = 0;
    while (iters++ < MAX_ITERS) {
        if (p->registers.rip.raw() == VRT_BYTECODE_RET_SENTINEL) break;
        if (p->state == runtime::HALT || p->state == runtime::DEAD) break;
        if (p->err_thread != runtime::THREAD_NO_ERROR) break;
        runtime::decode_instruction(p);
        runtime::vm_event ev = runtime::execute_instruction(p);
        if (ev == runtime::EVT_HALT || ev == runtime::EVT_ERROR) break;
        if (ev == runtime::EVT_IO_WAIT) {
            /* No podemos esperar IO sincronicamente desde JIT.
             * Abortar el fallback con error. */
            runtime::throw_fatal(
                p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
                "vrt_callm fallback: IO_WAIT no soportado en sync interp");
            break;
        }
    }

    /* Restaurar RSP (descartar el sentinel push si quedo).  El bytecode
     * RET normal lo habria pop-eado; si paramos por error, lo limpiamos
     * aqui.  Lo mismo para frame_stack. */
    p->registers.rip.qword(saved_rip);
    p->registers.stack_pointer.qword(saved_rsp);
    if (p->frame_stack == frame) {
        /* No se hizo pop -- liberar el frame manualmente. */
        p->frame_stack = saved_frame_stack;
        /* Sprint MMM-ext leak-fix. */
        runtime::host_alloca_release_all(p, frame);
        p->frame_pool.release(frame);
    }
    p->decoded_ptr = saved_decoded_ptr;

    return p->registers.regs[0].qword();
}

static uint64_t vrt_run_callvirt_with_advices(runtime::ProcessVM *p,
                                              uint8_t *obj_payload,
                                              uint32_t vtbl_idx) {
    /* Salvar estado del proceso (igual que vrt_run_method_in_interp). */
    const uint64_t saved_rip = p->registers.rip.raw();
    const uint64_t saved_rsp = p->registers.stack_pointer.qword();
    auto *saved_frame_stack = p->frame_stack;
    auto *saved_decoded_ptr = p->decoded_ptr;

    /* obj en R1 (this).  Los args ya estan en regs[2..N] (puestos por el
     * caller JIT antes de invocar vrt_callvirt). */
    p->registers.regs[1].qword(reinterpret_cast<uint64_t>(obj_payload));

    /* Construir un CALLVIRT sintetico: reg1=R1 (obj), reg2=vtbl_idx, size=0.
     * Ponemos rip = sentinel ANTES, para que exec_instr_callvirt calcule
     * ret_addr = rip + size_instr = sentinel; cuando la cadena de advices
     * retorne a ese ret_addr, el mini run-loop para. */
    p->registers.rip.qword(VRT_BYTECODE_RET_SENTINEL);
    runtime::DecodedInstr di{};
    di.data_instruction.reg_data.reg1 = 1;
    di.data_instruction.reg_data.reg2 = static_cast<uint8_t>(vtbl_idx);
    di.flags_info.size_instr = 0;
    /* cached_class/cached_method a 0 (di zero-init) -> resuelve via vtable. */

    /* decoded_ptr a un slot fresco ANTES de exec_instr_callvirt (que puede
     * referenciar vm->decoded_ptr al pushear los steps). */
    p->decoded_ptr = &p->icache[0];
    p->decoded_ptr->pc = UINT64_MAX;

    /* exec_instr_callvirt recorre la cadena de advices, pushea los frames
     * (BEFORE -> metodo -> AFTER) via push_step y deja rip en el primer
     * step (seq[0]->code_vaddr). */
    runtime::exec_instr_callvirt(p, di);

    /* Mini run-loop: ejecuta los steps hasta volver al sentinel. */
    const uint64_t MAX_ITERS = 100'000'000;
    uint64_t iters = 0;
    while (iters++ < MAX_ITERS) {
        if (p->registers.rip.raw() == VRT_BYTECODE_RET_SENTINEL) break;
        if (p->state == runtime::HALT || p->state == runtime::DEAD) break;
        if (p->err_thread != runtime::THREAD_NO_ERROR) break;
        runtime::decode_instruction(p);
        runtime::vm_event ev = runtime::execute_instruction(p);
        if (ev == runtime::EVT_HALT || ev == runtime::EVT_ERROR) break;
        if (ev == runtime::EVT_IO_WAIT) {
            runtime::throw_fatal(
                p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
                "vrt_callvirt advices: IO_WAIT no soportado en sync interp");
            break;
        }
    }

    const uint64_t result = p->registers.regs[0].qword();

    /* Restaurar estado.  Si la cadena completo limpiamente, sus `ret`
     * popearon todos los frames hasta saved_frame_stack.  Si paro por
     * error, liberar los frames colgantes hasta saved_frame_stack. */
    p->registers.rip.qword(saved_rip);
    p->registers.stack_pointer.qword(saved_rsp);
    while (p->frame_stack != saved_frame_stack && p->frame_stack != nullptr) {
        auto *f = p->frame_stack;
        p->frame_stack = f->prev;
        runtime::host_alloca_release_all(p, f);
        p->frame_pool.release(f);
    }
    p->decoded_ptr = saved_decoded_ptr;
    return result;
}

uint64_t vrt_callm(vrt_proc *proc, uint8_t *obj_payload, void *method) {
    if (!proc || !method) {
        if (proc) {
            runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                                 "callm: method o proc nulo");
        }
        return 0;
    }
    runtime::ProcessVM *p = as_proc(proc);
    loader::MethodInfo *mi = reinterpret_cast<loader::MethodInfo *>(method);

    /* Si el metodo no esta JIT-compilado, intentar compilar on-demand. */
    if (mi->jit_code == nullptr) {
        const uint32_t saved = mi->invocation_count;
        mi->invocation_count = jit::g_jit_threshold;
        jit::maybe_compile_method(p, mi);
        if (mi->jit_code == nullptr) {
            mi->invocation_count = saved;
        }
    }

    if (mi->jit_code != nullptr) {
        if (obj_payload != nullptr) {
            p->registers.regs[1].qword(reinterpret_cast<uint64_t>(obj_payload));
        }
        jit::JitFn fn = reinterpret_cast<jit::JitFn>(mi->jit_code);
        return jit::enter_jit(fn, proc);
    }

    /* JIT fallo (e.g. raw_asm complejo, callee no soportado).
     * FALLBACK 2026-05-16: ejecutar el bytecode del metodo en un
     * mini-loop sincronico.  Lento pero CORRECTO (no devuelve 0
     * silenciosamente). */
    if (obj_payload != nullptr) {
        p->registers.regs[1].qword(reinterpret_cast<uint64_t>(obj_payload));
    }
    return vrt_run_method_in_interp(p, mi);
}

uint64_t vrt_callitf(vrt_proc *proc, uint8_t *obj_payload, uint64_t params_addr,
                     uint64_t ic_slot_addr) {
    if (!proc || !obj_payload) {
        if (proc) {
            runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                                 "callitf: proc u objeto nulo");
        }
        return 0;
    }
    runtime::ProcessVM *p = as_proc(proc);

    /* Leer el ItfCallParams (32 bytes) de vm_mem.  Mismo layout que
     * @c ItfCallParamsLayout en exec_instruction_oop.cpp / el frontend. */
    struct ItfP {
        uint64_t iface_name_addr;
        uint32_t iface_name_len;
        uint32_t method_index;
        uint64_t method_name_addr;
        uint32_t method_name_len;
        uint32_t count;
    } pr;
    p->vm_mem.read_bytes(params_addr, &pr, sizeof(pr));

    auto &reg = p->scheduler.vm_reference.loader_public.class_registry();

    /* Resolver la interfaz por nombre. */
    char ibuf[256];
    uint32_t ilen = pr.iface_name_len < 255 ? pr.iface_name_len : 255;
    if (ilen > 0) p->vm_mem.read_bytes(pr.iface_name_addr, ibuf, ilen);
    loader::ClassInfo *iface = reg.find_class(std::string(ibuf, ilen));
    if (!iface) {
        runtime::throw_fatal(p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
                             "callitf: interfaz no encontrada en el registry");
        return 0;
    }
    /* F3b: poblar el IC slot del call site con el iface_ptr resuelto, para que
     * los dispatch siguientes tomen el scan inline (saltando este wrapper). */
    if (ic_slot_addr != 0) {
        *reinterpret_cast<uint64_t *>(ic_slot_addr) =
            reinterpret_cast<uint64_t>(iface);
    }

    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(obj_payload);
    loader::ClassInfo *cls = hdr->class_ptr;
    if (!cls) {
        runtime::throw_fatal(p, VESTA_FATAL_NULL_POINTER,
                             "callitf: objeto sin class_ptr");
        return 0;
    }

    /* Resolver el metodo concreto via la itable (cold: por nombre). */
    char mbuf[256];
    uint32_t mlen = pr.method_name_len < 255 ? pr.method_name_len : 255;
    if (mlen > 0) p->vm_mem.read_bytes(pr.method_name_addr, mbuf, mlen);
    loader::MethodInfo *mi = reg.resolve_itable_method(
        cls, iface, pr.count, pr.method_index, mbuf, mlen);
    if (!mi || mi->code_vaddr == 0) {
        runtime::throw_fatal(p, VESTA_FATAL_ILLEGAL_INSTRUCTION,
                             "callitf: metodo de interfaz sin implementacion");
        return 0;
    }

    /* Dispatch identico a vrt_callm: si el metodo no esta JIT-compilado,
     * intentar on-demand; luego enter_jit o mini-interp sincronico.
     * (AOP: igual que vrt_callm, el advice_chain se maneja en el path interp;
     * los metodos con advices no se inline-an en el JIT -- ver F3b.) */
    if (mi->jit_code == nullptr) {
        const uint32_t saved = mi->invocation_count;
        mi->invocation_count = jit::g_jit_threshold;
        jit::maybe_compile_method(p, mi);
        if (mi->jit_code == nullptr) mi->invocation_count = saved;
    }
    p->registers.regs[1].qword(reinterpret_cast<uint64_t>(obj_payload));
    if (mi->jit_code != nullptr) {
        jit::JitFn fn = reinterpret_cast<jit::JitFn>(mi->jit_code);
        return jit::enter_jit(fn, proc);
    }
    return vrt_run_method_in_interp(p, mi);
}

uint64_t vrt_callclosure(vrt_proc *proc, uint64_t fn_addr, uint64_t env_addr) {
    if (!proc || fn_addr == 0) {
        if (proc) {
            runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                                 "callclosure: fn_addr o proc nulo");
        }
        return 0;
    }
    runtime::ProcessVM *p = as_proc(proc);
    /* Convencion de closures: env_addr en R14 antes de la llamada. */
    p->registers.regs[14].qword(env_addr);

    /* fn_addr puede ser:
     *   (a) una direccion bytecode VM (< 4GB; helper sintetico
     *       __lambda_<N> que el frontend emite con @Absolute("code.X")).
     *   (b) un ptr nativo (> 4GB) si el closure fue eager-compilado.
     *
     * Heuristica de rango: VM vaddr < 4GB, host ptr > 4GB en x64.
     * BUG FIX 2026-05-16: el codigo anterior siempre asumia (b) y
     * crasheaba con segfault al saltar a una VM addr como si fuera host.
     */
    if (fn_addr > 0x100000000ULL) {
        /* Host ptr a codigo JIT. */
        jit::JitFn fn = reinterpret_cast<jit::JitFn>(fn_addr);
        return jit::enter_jit(fn, proc);
    }
    /* VM bytecode addr: ejecutar via mini-interp delegando al helper
     * compartido vrt_run_bc_at.  El env_addr ya esta en R14 (linea
     * arriba), por lo que el lambda body lo encontrara como espera la
     * convencion de closures. */
    return vrt_run_bc_at(p, fn_addr);
}

uint64_t vrt_call_bc_function(vrt_proc *proc, uint64_t bc_entry_va) {
    /* Trampoline JIT->interp para CALL/CALLVM cuando la callee no se
     * pudo JIT-compilar.  El selector emite esta llamada en lugar de
     * marcar el caller como unsupported, permitiendo que main y otros
     * metodos JIT-compilen aunque algunas callees caigan a interp.
     *
     * Args ya stagedos en proc->registers.regs[1..N] por el caller JIT
     * (convencion VM_ABI), argc en R15.  Resultado en R0 tras retorno. */
    if (!proc || bc_entry_va == 0) {
        if (proc) {
            runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                                 "vrt_call_bc_function: bc_entry_va nulo");
        }
        return 0;
    }
    return vrt_run_bc_at(as_proc(proc), bc_entry_va);
}

uint64_t vrt_calln(vrt_proc *proc, const char *lib_name, const char *fn_name) {
    /* CALLN desde JIT: stub que lanza fatal.  La resolucion de
     * (lib, fn) -> fn_ptr requiere acceso al Loader y al cache de
     * native_imports.   D.3-G+ implementara esto plenamente.
     * Por ahora cualquier funcion con CALLN no se compila (el selector
     * marca unsupported antes de llegar aqui via warn).
     *
     * Alternativa para programs que necesitan FFI desde JIT: usar
     * ffi_open/ffi_sym/ffi_call (CALLNI dinamico) que tampoco esta
     * soportado todavia, o no usar -m jit. */
    (void)lib_name;
    (void)fn_name;
    if (proc) {
        runtime::throw_fatal(as_proc(proc), VESTA_FATAL_ILLEGAL_INSTRUCTION,
                             "calln desde JIT no implementado en v1 ( D.3-G+)");
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Safepoint                                                                */
/* ----------------------------------------------------------------------- */

void vrt_safepoint_poll(vrt_proc *proc) {
    /* Camino lento explicito (rara vez usado): el JIT normalmente emite
     * el poll inline como @c cmp byte [rbx], 0; jne handler.  Esta
     * funcion existe para fallback / debugging. */
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);
    if (p->safepoint_flag) {
        vrt_safepoint_handler(proc);
    }
}

void vrt_safepoint_handler(vrt_proc *proc) {
    /* D.2-foundation v1: implementacion minima del handler.
     *
     * El handler corre cuando el GC del propio proceso quiere pausar
     * para hacer stack scan.  En esta fase:
     *
     *   1. Limpiamos el flag para que el JIT no quede en bucle al
     *      retornar (en cada poll comprobara y vera 0).
     *   2. Reservamos espacio para que la integracion GC (Phase
     *      D.2-integration) capture RIP/RBP aqui y coordine con el GC.
     *
     * Como en D.2-foundation aun no hay GC integration, el handler
     * simplemente limpia el flag y retorna.  La proxima iteracion del
     * codigo JIT continuara normalmente. */
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);
    p->safepoint_flag = 0;
    /* Watchdog CTPE: si el presupuesto de tiempo vencio (el hilo temporizador
     * puso proc->ctpe_abort=1), abortar la ejecucion del programa precomputado.
     * El throw_fatal hace longjmp al scheduler -> el proceso muere ->
     * invoke_simple_macro devuelve false -> el pase de plegado NO pliega
     * (fallback: la funcion corre en runtime).  El flag vive en el ProcessVM
     * (una instancia) -> sin el problema de globales duplicados cross-modulo.
     */
    // Watchdog CTPE: si el presupuesto vencio, ABORTAR la ejecucion del
    // programa precomputado via longjmp al setjmp que el scheduler armo
    // alrededor del jit_entry_fn (mismo mecanismo que la recuperacion de
    // SIGSEGV).  throw_fatal NO sirve aqui: solo marca err_thread y RETORNA ->
    // el codigo JIT de main continuaria hasta terminar.  El longjmp desenrolla
    // el frame JIT y devuelve el control al scheduler, que marca el proceso
    // HALT sin ejecutar main.
    if (p->ctpe_abort && p->av_recovery_active) {
        p->ctpe_did_abort = 1;
        std::longjmp(p->av_recovery_jmpbuf, 2); // 2 = aborto CTPE (1 = AV/div0)
    }
    /* TODO D.2-integration:
     *   - Capturar RBP del caller (necesita assembly inline o
     *     llamada con __builtin_frame_address).
     *   - Notificar al GC que llegamos al safepoint.
     *   - Esperar sobre condvar hasta que el GC termine.
     *   - Restaurar y retornar. */
}

/* ----------------------------------------------------------------------- */
/* Introspeccion                                                            */
/* ----------------------------------------------------------------------- */

vrt_vm *vrt_proc_vm(vrt_proc *proc) {
    if (!proc) return nullptr;
    /* ProcessVM.scheduler -> Scheduler.vm_reference */
    return reinterpret_cast<vrt_vm *>(&as_proc(proc)->scheduler.vm_reference);
}

uint64_t vrt_proc_pid(vrt_proc *proc) {
    if (!proc) return 0;
    const runtime::ProcessVM *p = as_proc(proc);
    /* PID encoded: (scheduler_id << 32) | local_pid */
    return (static_cast<uint64_t>(p->pid.scheduler_id) << 32) |
           static_cast<uint64_t>(p->pid.local_pid);
}

/* ----------------------------------------------------------------------- */
/* Acceso a memoria VM ( D.3-G)                                       */
/* ----------------------------------------------------------------------- */

uint64_t vrt_vm_read_u64(vrt_proc *proc, uint64_t vaddr) {
    if (!proc) return 0;
    return as_proc(proc)->vm_mem.read_u64_fast(vaddr);
}

void vrt_vm_write_u64(vrt_proc *proc, uint64_t vaddr, uint64_t value) {
    if (!proc) return;
    as_proc(proc)->vm_mem.write_u64_fast(vaddr, value);
}

/* Variantes por tamano para LOAD/STORE de tipos menores que 8 bytes.
 * El JIT las usa segun el ancho del IR LOAD/STORE para evitar:
 *   (a) leer pagina no mapeada al final de la region (read_u64 sobre los
 *       ultimos 4 bytes de una pagina cruzaria el limite).
 *   (b) escribir 8 bytes sobrescribiendo el siguiente elemento del array
 *       (4 bytes adyacentes corruptos).
 * Cada variante delega al metodo size-specifico de @c VirtualMemory. */
uint32_t vrt_vm_read_u32(vrt_proc *proc, uint64_t vaddr) {
    if (!proc) return 0;
    return as_proc(proc)->vm_mem.read_u32(vaddr);
}
uint16_t vrt_vm_read_u16(vrt_proc *proc, uint64_t vaddr) {
    if (!proc) return 0;
    return as_proc(proc)->vm_mem.read_u16(vaddr);
}
uint8_t vrt_vm_read_u8(vrt_proc *proc, uint64_t vaddr) {
    if (!proc) return 0;
    return as_proc(proc)->vm_mem.read_u8(vaddr);
}
void vrt_vm_write_u32(vrt_proc *proc, uint64_t vaddr, uint32_t value) {
    if (!proc) return;
    as_proc(proc)->vm_mem.write_u32(vaddr, value);
}
void vrt_vm_write_u16(vrt_proc *proc, uint64_t vaddr, uint16_t value) {
    if (!proc) return;
    as_proc(proc)->vm_mem.write_u16(vaddr, value);
}
void vrt_vm_write_u8(vrt_proc *proc, uint64_t vaddr, uint8_t value) {
    if (!proc) return;
    as_proc(proc)->vm_mem.write_u8(vaddr, value);
}

uint8_t *vrt_vm_translate(vrt_proc *proc, uint64_t vaddr) {
    /*  D.jit-mem-model FULL: traduccion VM-addr -> host_ptr.
     *
     * Diseno portable: confiamos en que el frontend marca
     * is_host_ptr correctamente en el IR.  El JIT emite la llamada
     * a vrt_vm_translate SOLO para LOAD/STORE de ptrs con
     * is_host_ptr=false (VM-addrs).  Para is_host_ptr=true (malloc
     * /new/fields GC) usa native mov directo, sin traduccion.
     *
     * Asi evitamos range checks arbitrarios (no portables a
     * arquitecturas distintas o programas con address layouts
     * inusuales) y nos apoyamos en la informacion semantica que
     * el frontend ya tiene.
     *
     * El JIT garantiza llamar solo con un VM-addr; aqui asumimos
     * eso y delegamos a vm_mem.  Si vaddr == 0 retornamos null
     * para mantener la semantica de deref nulo. */
    if (vaddr == 0) return nullptr;
    if (!proc) return nullptr;
    return &as_proc(proc)->vm_mem[vaddr];
}

/* ----------------------------------------------------------------------- */
/* Class registry runtime entries ( D.3-G)                            */
/* ----------------------------------------------------------------------- */

vrt_class *vrt_findclass(vrt_proc *proc, uint64_t params_vaddr) {
    if (!proc) return nullptr;
    runtime::ProcessVM *p = as_proc(proc);
    /* FindClassParams: +0 name_vaddr [8], +8 name_len [4]. */
    uint64_t name_vaddr = p->vm_mem.read_u64_fast(params_vaddr);
    uint32_t name_len = 0;
    p->vm_mem.read_bytes(params_vaddr + 8, &name_len, 4);
    if (name_len == 0 || name_len > 4096) return nullptr;
    /* Leer el nombre desde vm_mem a buffer local. */
    char buf[4097];
    p->vm_mem.read_bytes(name_vaddr, buf, name_len);
    buf[name_len] = '\0';
    /* Lookup en el class registry del Loader. */
    auto &reg = p->scheduler.vm_reference.loader_public.class_registry();
    auto *cls = reg.find_class(buf);
    return reinterpret_cast<vrt_class *>(cls);
}

VRT_FORCE_FP uint8_t *vrt_newobj(vrt_proc *proc, vrt_class *cls) {
    if (!proc || !cls) {
        if (proc) {
            runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                                 "newobj: clase nula");
        }
        return nullptr;
    }
    runtime::ProcessVM *p = as_proc(proc);
    /* El alloc de abajo puede disparar GC; capturar el frame JIT llamador. */
    VRT_CAPTURE_JIT_FRAME(p);
    loader::ClassInfo *ci = reinterpret_cast<loader::ClassInfo *>(cls);
    /* gc_heap.alloc devuelve un GcHandle; deref para obtener host_ptr al
     * payload. */
    const uint32_t handle = p->gc_heap.alloc(ci->instance_size);
    if (handle == VRT_NULL_HANDLE) {
        runtime::throw_fatal(p, VESTA_FATAL_NULL_POINTER, "newobj: OOM");
        return nullptr;
    }
    uint8_t *payload = p->gc_heap.deref(handle);
    if (!payload) return nullptr;
    /* Inicializar header: class_ptr = ci, flags = OBJ_FLAG_GC_OWNED.
     * Replica exacto del bytecode exec_instr_newobj. */
    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(payload);
    hdr->class_ptr = ci;
    hdr->flags = loader::OBJ_FLAG_GC_OWNED;
    /* El resto del header viene zeroed por el alloc. */
    /* Retornar el host_ptr al ObjectHeader (convencion bytecode/Vesta:
     * gcderef devuelve addr+sizeof(GcHeader) = ObjectHeader start, NO
     * FIELDS start).  Los accesos a campos en Vesta usan offset >=
     * sizeof(ObjectHeader) desde este puntero. */
    return payload;
}

VRT_FORCE_FP vrt_handle vrt_newobj_handle(vrt_proc *proc, vrt_class *cls) {
    /* Misma logica que vrt_newobj + vrt_gc_handle_for_ptr combinados.
     * Optimizacion clave: gc_heap.alloc YA devuelve el handle, asi que
     * NO necesitamos hacer el lookup de ptr_to_handle_ que haria
     * vrt_gc_handle_for_ptr.  Ahorra ~30-50 ns por @c new X(). */
    if (!proc || !cls) {
        if (proc) {
            runtime::throw_fatal(as_proc(proc), VESTA_FATAL_NULL_POINTER,
                                 "newobj: clase nula");
        }
        return VRT_NULL_HANDLE;
    }
    runtime::ProcessVM *p = as_proc(proc);
    /* Frontera C<-JIT: el codigo JIT llama aqui directo para @c new X().  El
     * alloc puede disparar minor/major_gc; el scan preciso de los frames JIT
     * (roots young/old) arranca desde el par (pc,sp) que captura este guard. */
    VRT_CAPTURE_JIT_FRAME(p);
    loader::ClassInfo *ci = reinterpret_cast<loader::ClassInfo *>(cls);
    const uint32_t handle = p->gc_heap.alloc(ci->instance_size);
    if (handle == VRT_NULL_HANDLE) {
        runtime::throw_fatal(p, VESTA_FATAL_NULL_POINTER, "newobj: OOM");
        return VRT_NULL_HANDLE;
    }
    uint8_t *payload = p->gc_heap.deref(handle);
    if (!payload) return VRT_NULL_HANDLE;
    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(payload);
    hdr->class_ptr = ci;
    hdr->flags = loader::OBJ_FLAG_GC_OWNED;
    return handle;
}

/* NEWOBJS: aloca en SharedHeap (cross-process) + registra en
 * SharedHandleTable.  Replica exec_instr_newobjs; devuelve el handle con
 * SHARED_HANDLE_BIT.  Sin tocar proc->registers (args/retorno C). */
vrt_handle vrt_newobjs(vrt_proc *proc, vrt_class *cls) {
    if (!proc || !cls) return VRT_NULL_HANDLE;
    runtime::ProcessVM *p = as_proc(proc);
    auto *ci = reinterpret_cast<loader::ClassInfo *>(cls);
    auto &vmr = p->scheduler.vm_reference;
    const uint32_t sz = ci->instance_size;
    uint8_t *payload = vmr.shared_heap.alloc(static_cast<size_t>(sz));
    if (!payload) return VRT_NULL_HANDLE; // OOM SharedHeap
    const uint32_t sh = vmr.shared_handle_table.register_object(payload, sz);
    if (sh == 0) { // tabla llena
        vmr.shared_heap.free(payload);
        return VRT_NULL_HANDLE;
    }
    auto *hdr = new (payload) loader::ObjectHeader();
    hdr->class_ptr = ci;
    hdr->flags = loader::OBJ_FLAG_GC_OWNED;
    hdr->hash_code = sh; // SHARED_HANDLE_BIT | shared_idx
    return static_cast<vrt_handle>(sh);
}

/* DLOPEN: lee el path (UTF-8) de vm_mem y carga la libreria via API del SO.
 * Replica exec_instr_dlopen; lanza FatalError capturable si falla. */
uint64_t vrt_dlopen(vrt_proc *proc, uint64_t path_vaddr, uint32_t path_len) {
    if (!proc) return 0;
    runtime::ProcessVM *p = as_proc(proc);
    std::string path(static_cast<size_t>(path_len), '\0');
    if (path_len) p->vm_mem.read_bytes(path_vaddr, &path[0], path_len);
    void *handle = nullptr;
#if defined(_WIN32)
    handle = static_cast<void *>(LoadLibraryA(path.c_str()));
#else
    handle = dlopen(path.c_str(), RTLD_LAZY);
#endif
    if (handle == nullptr) {
        runtime::throw_fatal(p, VESTA_FATAL_NULL_POINTER,
                             "dlopen: no se pudo cargar la libreria");
        return 0;
    }
    return reinterpret_cast<uint64_t>(handle);
}

/* STRCONV: convierte un StringObject a otra codificacion.  Delega en el core
 * compartido strconv_public (mismo algoritmo que el opcode 0x4A). */
vrt_handle vrt_str_conv(vrt_proc *proc, vrt_handle src, uint32_t enc) {
    if (!proc) return VRT_NULL_HANDLE;
    return static_cast<vrt_handle>(runtime::strconv_public(
        as_proc(proc), static_cast<gc::GcHandle>(src), enc));
}

/* ===================================================================== */
/* vrt_register_alloc                                      */
/* ===================================================================== */
/* Llamado por codigo JIT-eated tras INLINE bump-pointer alloc para
 * registrar el handle del objeto recien alocado.  El JIT inlineea:
 *   - bump-pointer (lee/escribe @c nursery_bump_)
 *   - init GcHeader (size, color, gen)
 *   - init ObjectHeader (class_ptr, flags)
 *   - memset payload
 *
 * Pero la creacion del handle (push a @c handles_ + insert a @c
 * ptr_to_handle_) es demasiado compleja para inlinear -- delegada
 * a este helper.  Coste medido: ~7-8 ns (vs ~25 ns de @c vrt_newobj
 * full).
 *
 * @param proc ProcessVM cuyo gc_heap se va a actualizar.
 * @param raw  Puntero host al GcHeader del objeto recien alocado.
 * @return Handle creado o @c VRT_NULL_HANDLE si fallo.
 */
uint64_t vrt_register_alloc(vrt_proc *proc, uint8_t *raw) {
    if (!proc || !raw) return VRT_NULL_HANDLE;
    runtime::ProcessVM *p = as_proc(proc);
    return p->gc_heap.register_alloc(raw);
}

vrt_class *vrt_defclass(vrt_proc *proc, uint64_t params_vaddr) {
    if (!proc) return nullptr;
    runtime::ProcessVM *p = as_proc(proc);
    /* DefClassParams ABI (32 bytes):
     *   +0  name_addr     [8]
     *   +8  name_len      [4]
     *   +12 flags         [4]
     *   +16 super_class   [8]  ptr o 0
     *   +24 _reserved     [8]  */
    struct Params {
        uint64_t name_addr;
        uint32_t name_len;
        uint32_t flags;
        uint64_t super_ptr;
        uint64_t _rsv;
    };
    Params pr{};
    p->vm_mem.read_bytes(params_vaddr, &pr, sizeof(pr));
    if (pr.name_len == 0 || pr.name_len > 4096) return nullptr;
    char buf[4097];
    p->vm_mem.read_bytes(pr.name_addr, buf, pr.name_len);
    buf[pr.name_len] = '\0';
    auto &reg = p->scheduler.vm_reference.loader_public.class_registry();
    loader::ClassInfo *super_cls =
        reinterpret_cast<loader::ClassInfo *>(pr.super_ptr);
    /* define_class signature: (name, super, interfaces[], fields[], methods[],
     * flags) */
    auto *cls = reg.define_class(buf, super_cls, {}, {}, {}, pr.flags);
    return reinterpret_cast<vrt_class *>(cls);
}

int32_t vrt_deffield(vrt_proc *proc, vrt_class *cls, uint64_t params_vaddr) {
    if (!proc || !cls) return 0;
    runtime::ProcessVM *p = as_proc(proc);
    /* DefFieldParams (32 bytes):
     *   +0  name_addr   [8]
     *   +8  name_len    [4]
     *   +12 kind        [1]
     *   +13 access      [1]
     *   +14 is_static   [1]
     *   +15 _pad
     *   +16 size_bytes  [4]
     *   +20 _pad2
     *   +24 type_class  [8]
     */
    struct Params {
        uint64_t name_addr;
        uint32_t name_len;
        uint8_t kind;
        uint8_t access;
        uint8_t is_static;
        uint8_t _pad;
        uint32_t size_bytes;
        uint32_t _pad2;
        uint64_t type_class;
    };
    Params pr{};
    p->vm_mem.read_bytes(params_vaddr, &pr, sizeof(pr));
    if (pr.name_len == 0 || pr.name_len > 4096) return 0;
    char buf[4097];
    p->vm_mem.read_bytes(pr.name_addr, buf, pr.name_len);
    buf[pr.name_len] = '\0';
    auto &reg = p->scheduler.vm_reference.loader_public.class_registry();
    loader::FieldDecl fd{};
    fd.name = buf;
    fd.kind = static_cast<loader::FieldKind>(pr.kind);
    fd.access = static_cast<loader::FieldAccess>(pr.access);
    fd.is_static = pr.is_static != 0;
    fd.size_bytes = pr.size_bytes;
    fd.type_class = reinterpret_cast<loader::ClassInfo *>(pr.type_class);
    auto *ci = reinterpret_cast<loader::ClassInfo *>(cls);
    return reg.add_field(ci, fd) ? 1 : 0;
}

uint32_t vrt_defmethod(vrt_proc *proc, vrt_class *cls, uint64_t params_vaddr) {
    if (!proc || !cls) return UINT32_MAX;
    runtime::ProcessVM *p = as_proc(proc);
    /* DefMethodParams (40 bytes):
     *   +0  name_addr      [8]
     *   +8  name_len       [4]
     *   +12 descriptor_len [4]
     *   +16 descriptor_addr[8]
     *   +24 code_vaddr     [8]
     *   +32 flags          [8]
     */
    struct Params {
        uint64_t name_addr;
        uint32_t name_len;
        uint32_t descriptor_len;
        uint64_t descriptor_addr;
        uint64_t code_vaddr;
        uint64_t flags;
    };
    Params pr{};
    p->vm_mem.read_bytes(params_vaddr, &pr, sizeof(pr));
    if (pr.name_len == 0 || pr.name_len > 4096) return UINT32_MAX;
    char buf[4097];
    p->vm_mem.read_bytes(pr.name_addr, buf, pr.name_len);
    buf[pr.name_len] = '\0';
    char desc_buf[4097];
    if (pr.descriptor_len > 0 && pr.descriptor_len <= 4096) {
        p->vm_mem.read_bytes(pr.descriptor_addr, desc_buf, pr.descriptor_len);
        desc_buf[pr.descriptor_len] = '\0';
    } else {
        desc_buf[0] = '\0';
    }
    auto &reg = p->scheduler.vm_reference.loader_public.class_registry();
    loader::MethodDecl md{};
    md.name = buf;
    md.descriptor = desc_buf;
    md.code_vaddr = pr.code_vaddr;
    md.flags = pr.flags;
    auto *ci = reinterpret_cast<loader::ClassInfo *>(cls);
    return reg.add_method(ci, md);
}

int32_t vrt_addadvice(vrt_proc *proc, void *target_method, void *advice_method,
                      uint8_t kind) {
    if (!proc || !target_method || !advice_method) {
        return 0;
    }
    runtime::ProcessVM *p = as_proc(proc);
    auto &reg = p->scheduler.vm_reference.loader_public.class_registry();
    auto *target = reinterpret_cast<loader::MethodInfo *>(target_method);
    auto *advice = reinterpret_cast<loader::MethodInfo *>(advice_method);
    return reg.add_advice(target, kind, advice) ? 1 : 0;
}

/* Helper compartido: detecta si @p ptr es una direccion HOST (>4GB) o
 * VM vaddr (<=4GB) y lee @p size bytes a @p dst.  El JIT pasa host_ptr
 * desde ALLOCA stack-nativo; el bytecode interp pasa VM vaddr.  La
 * heuristica de rango funciona porque el VM mem se mapea siempre a
 * direcciones <4GB y el host stack siempre vive >4GB en x64.
 *
 * Coste: 1 cmp + 1 branch (~1 ciclo predicho).  Despreciable comparado
 * con el FFI overhead que ya tiene cada CALLN.
 */
static inline void read_params_unified(runtime::ProcessVM *p, uint64_t ptr,
                                       void *dst, size_t size) {
    if (ptr > 0x100000000ULL) {
        /* Host stack ptr -> memcpy directo. */
        std::memcpy(dst, reinterpret_cast<const void *>(ptr), size);
    } else {
        p->vm_mem.read_bytes(ptr, dst, size);
    }
}

void *vrt_findmethod(vrt_proc *proc, uint64_t params_vaddr) {
    if (!proc) return nullptr;
    runtime::ProcessVM *p = as_proc(proc);
    /* FindMethodParams (24 bytes): +0 class_ptr, +8 name_addr, +16 name_len */
    struct Params {
        uint64_t class_ptr;
        uint64_t name_addr;
        uint32_t name_len;
        uint32_t _pad;
    };
    Params pr{};
    read_params_unified(p, params_vaddr, &pr, sizeof(pr));
    if (!pr.class_ptr || pr.name_len == 0 || pr.name_len > 4096) return nullptr;

    /* CACHE ( D.8): el dispatch de interfaz (shape.area()) llama a este
     * findmethod POR ITERACION, y resolverlo cuesta 2 lecturas de vm_mem
     * (params
     * + nombre) + copia del nombre + hash lookup -- pero (class_ptr, name_addr)
     * casi siempre se repite (el nombre es constante; la clase rota entre pocos
     * tipos).  Un cache thread_local pequeno (8 entradas, LRU-ish por reemplazo
     * del mas viejo) keyed por (class_ptr, name_addr) salta TODO el trabajo
     * caro en hit, dejando solo la lectura de params (24 B) para la key.  Esto
     * cierra el grueso del 115x de pic_real sin tocar el codegen.  thread_local
     * = seguro sin locks (el resultado find_method es verdad global, no
     * por-proc). Las (class_ptr, name_addr) son estables durante el run;
     * defmethod en runtime (raro, solo en __module_init que corre antes del hot
     * path) podria stalear una entrada -> aceptable (el cache se llena tras
     * __module_init). */
    struct FmEntry {
        uint64_t cls;
        uint64_t name_addr;
        void *method;
    };
    static thread_local FmEntry g_fm_cache[8] = {};
    static thread_local unsigned g_fm_next = 0;
    for (const FmEntry &e : g_fm_cache) {
        if (e.cls == pr.class_ptr && e.name_addr == pr.name_addr && e.method)
            return e.method;
    }

    char buf[4097];
    /* name_addr sigue siendo VM vaddr (static_data del .velb). */
    p->vm_mem.read_bytes(pr.name_addr, buf, pr.name_len);
    buf[pr.name_len] = '\0';
    auto &reg = p->scheduler.vm_reference.loader_public.class_registry();
    auto *ci = reinterpret_cast<loader::ClassInfo *>(pr.class_ptr);
    void *m = reg.find_method(ci, buf);
    if (m) { /* cachear (reemplazo round-robin del slot mas viejo). */
        g_fm_cache[g_fm_next & 7u] = FmEntry{pr.class_ptr, pr.name_addr, m};
        ++g_fm_next;
    }
    return m;
}

void *vrt_findfield(vrt_proc *proc, uint64_t params_vaddr) {
    if (!proc) return nullptr;
    runtime::ProcessVM *p = as_proc(proc);
    struct Params {
        uint64_t class_ptr;
        uint64_t name_addr;
        uint32_t name_len;
        uint32_t _pad;
    };
    Params pr{};
    read_params_unified(p, params_vaddr, &pr, sizeof(pr));
    if (!pr.class_ptr || pr.name_len == 0 || pr.name_len > 4096) return nullptr;
    char buf[4097];
    p->vm_mem.read_bytes(pr.name_addr, buf, pr.name_len);
    buf[pr.name_len] = '\0';
    auto &reg = p->scheduler.vm_reference.loader_public.class_registry();
    auto *ci = reinterpret_cast<loader::ClassInfo *>(pr.class_ptr);
    return reg.find_field(ci, buf);
}

void vrt_setmethdbg(vrt_proc *proc, uint64_t params_vaddr) {
    if (!proc || params_vaddr == 0) return;
    runtime::ProcessVM *p = as_proc(proc);
    /* Mismo layout que SetMethDebugParams en exec_instr_setmethdbg. */
    struct DebugParams {
        uint64_t method_ptr;
        uint64_t file_addr;
        uint32_t file_len;
        uint32_t start_line;
    };
    DebugParams sp{};
    p->vm_mem.read_bytes(params_vaddr, &sp, sizeof(sp));
    if (sp.method_ptr == 0) return;
    char fbuf[256];
    size_t flen = (size_t)sp.file_len;
    if (flen > 255) flen = 255;
    if (sp.file_addr != 0 && flen > 0) {
        p->vm_mem.read_bytes(sp.file_addr, fbuf, flen);
    }
    fbuf[flen] = '\0';
    runtime::register_method_debug(
        reinterpret_cast<loader::MethodInfo *>(sp.method_ptr), fbuf, flen,
        sp.start_line);
}

/* =========================================================================
 * Sprint JIT-cobertura (2026-06-01): wrappers para string ops.
 *
 * Cada wrapper recibe handles/args directos del codigo JIT (Native ABI:
 * proc en RCX/RDI, args en RDX/RSI/R8/RDX/...).  Delega a las helpers
 * publicas expuestas en @c runtime/string_runtime.h.
 * =========================================================================
 */

/* PANIC: lanza FatalError(USER_ABORT, msg) leyendo el mensaje de
 * vm_mem[msg_addr, msg_addr+msg_len).  Equivalente al opcode bytecode
 * panic.  Convierte el path FATAL_USER_ABORT del runtime entry
 * throw_fatal a una API mas directa para el JIT. */
void vrt_panic_str(vrt_proc *proc, uint64_t msg_vaddr, uint32_t msg_len) {
    if (!proc) return;
    runtime::ProcessVM *p = as_proc(proc);
    char msg[512];
    if (msg_len >= sizeof(msg)) msg_len = sizeof(msg) - 1;
    if (msg_len > 0 && msg_vaddr != 0) {
        p->vm_mem.read_bytes(msg_vaddr, msg, msg_len);
    }
    msg[msg_len] = '\0';
    VESTA_ANOTAR_ORIGEN(p);
    /* throw_fatal(proc, FATAL_USER_ABORT, msg) -- nunca retorna.  El
     * handler del JIT (run_jit -> longjmp) propaga la excepcion al
     * frame de tryenter mas cercano o termina el proceso si no hay
     * uno. */
    runtime::throw_fatal(p, runtime::FATAL_USER_ABORT, msg);
}

/* GC_ALLOCP: alloc en GC heap + deref + devuelve host_ptr al payload.
 * Combinacion atomica que el opcode bytecode gcallocp implementa en
 * 1 instr.  Para el JIT usamos 1 CALL nativo en lugar de 2. */
VRT_FORCE_FP uint8_t *vrt_gc_alloc_payload(vrt_proc *proc, size_t size) {
    if (!proc) return nullptr;
    runtime::ProcessVM *p = as_proc(proc);
    /* Capturar el frame JIT ANTES del alloc (dispara GC).  Se hace el alloc
     * DIRECTO sobre gc_heap (no via vrt_gc_alloc) para no anidar dos guards:
     * el interno pondria un boundary con retorno a ESTA funcion C++ (no al
     * codigo JIT), rompiendo el walk mientras el GC corre. */
    VRT_CAPTURE_JIT_FRAME(p);
    const vrt_handle h = p->gc_heap.alloc(size);
    if (h == VRT_NULL_HANDLE) return nullptr;
    return p->gc_heap.deref(h);
}

/* STRMAKE: %dst = strmake.handle vm_addr, byte_len.  La codificacion la
 * detectamos como UTF-8 por defecto (mismo path que el opcode bytecode);
 * el helper interno auto-compacta a ASCII si todos los bytes son < 0x80. */
VRT_FORCE_FP vrt_handle vrt_str_make(vrt_proc *proc, uint64_t vm_addr,
                                     uint32_t byte_len) {
    if (!proc) return VRT_NULL_HANDLE;
    runtime::ProcessVM *p = as_proc(proc);
    /* La alocacion del StringObject puede disparar GC; capturar el frame JIT.
     */
    VRT_CAPTURE_JIT_FRAME(p);
    if (byte_len > (1u << 24)) return VRT_NULL_HANDLE; /* sanity: 16 MB cap */
    /* Sprint string-perf-4 (2026-06-02): bypass del path antiguo
     * (heap std::vector + make_string_flat sin cache).  Delega al
     * helper compartido con exec_instr_strmake -> stack buf <=256 B,
     * single-pass FNV-1a 64-bit, intern lookup-first, alloc_flat con
     * precomputed_hash.  Speedup esperado en JIT: ~3-5x en hot loops
     * porque el 95%+ de STRMAKEs hit cache. */
    return static_cast<vrt_handle>(
        runtime::make_string_from_vm_mem(p, vm_addr, byte_len));
}

/* STRMAKE_H: crea StringObject FLAT desde un buffer en memoria HOST.
 * Variante de vrt_str_make para cuando el buffer fuente es un host_ptr
 * (ALLOCA promovido a heap host que fluye a un CALLN de stringify). */
VRT_FORCE_FP vrt_handle vrt_str_make_h(vrt_proc *proc, uint64_t host_addr,
                                       uint32_t byte_len) {
    if (!proc) return VRT_NULL_HANDLE;
    runtime::ProcessVM *p = as_proc(proc);
    /* La alocacion del StringObject puede disparar GC; capturar el frame JIT.
     */
    VRT_CAPTURE_JIT_FRAME(p);
    if (byte_len > (1u << 24)) return VRT_NULL_HANDLE; /* sanity: 16 MB cap */
    return static_cast<vrt_handle>(
        runtime::make_string_from_host_mem(p, host_addr, byte_len));
}

/* STRLEN: numero de code points del StringObject. */
uint64_t vrt_str_len(vrt_proc *proc, vrt_handle h) {
    if (!proc || h == VRT_NULL_HANDLE) return 0;
    runtime::ProcessVM *p = as_proc(proc);
    uint8_t *payload = p->gc_heap.deref(static_cast<gc::GcHandle>(h));
    if (!payload) return 0;
    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    return static_cast<uint64_t>(s->length);
}

/* STRGETBYTES: byte_len del StringObject. */
uint64_t vrt_str_get_bytes(vrt_proc *proc, vrt_handle h) {
    if (!proc || h == VRT_NULL_HANDLE) return 0;
    runtime::ProcessVM *p = as_proc(proc);
    uint8_t *payload = p->gc_heap.deref(static_cast<gc::GcHandle>(h));
    if (!payload) return 0;
    auto *s = reinterpret_cast<loader::StringObject *>(payload);
    return static_cast<uint64_t>(s->byte_len);
}

/* STRRAW: host pointer al buffer de bytes (offset 40 dentro del payload
 * del StringObject).  Materializa ROPE/SLICE primero. */
uint64_t vrt_str_raw(vrt_proc *proc, vrt_handle h) {
    if (!proc || h == VRT_NULL_HANDLE) return 0;
    runtime::ProcessVM *p = as_proc(proc);
    gc::GcHandle flat =
        runtime::flatten_string_public(p, static_cast<gc::GcHandle>(h));
    uint8_t *payload = p->gc_heap.deref(flat);
    if (!payload) return 0;
    /* StringObject layout: header(24) + encoding(1) + pad(3) + length(4)
     *                       + byte_len(4) + hash(4) + data[] @ offset 40. */
    return reinterpret_cast<uint64_t>(payload + 40);
}

/* STRCAT: %dst = strcat.handle a, b.  Crea un ROPE O(1) (lazy concat). */
VRT_FORCE_FP vrt_handle vrt_str_cat(vrt_proc *proc, vrt_handle a,
                                    vrt_handle b) {
    if (!proc) return VRT_NULL_HANDLE;
    runtime::ProcessVM *p = as_proc(proc);
    /* El nuevo StringObject concatenado se aloca en el GC; capturar el frame.
     */
    VRT_CAPTURE_JIT_FRAME(p);
    return static_cast<vrt_handle>(runtime::strcat_public(
        p, static_cast<gc::GcHandle>(a), static_cast<gc::GcHandle>(b)));
}

/* STRSLICE: vista de una subcadena.  Puede alocar (SLICE) -> captura frame. */
VRT_FORCE_FP vrt_handle vrt_str_slice(vrt_proc *proc, vrt_handle src,
                                      uint64_t range) {
    if (!proc) return VRT_NULL_HANDLE;
    runtime::ProcessVM *p = as_proc(proc);
    VRT_CAPTURE_JIT_FRAME(p);
    return static_cast<vrt_handle>(
        runtime::strslice_public(p, static_cast<gc::GcHandle>(src), range));
}

/* STRCMP: comparacion lexicografica.  Returns -1, 0 o 1. */
int64_t vrt_str_cmp(vrt_proc *proc, vrt_handle a, vrt_handle b) {
    if (!proc) return -1;
    runtime::ProcessVM *p = as_proc(proc);
    return runtime::strcmp_public(p, static_cast<gc::GcHandle>(a),
                                  static_cast<gc::GcHandle>(b));
}

} /* extern "C" */

/* ------------------------------------------------------------------------- */
/* Alias C++ namespaced para invocar @c runtime::do_throw desde las funciones
 * C wrapper @c vrt_throw_user / @c vrt_rethrow.  No esta en extern "C" para
 * preservar el name-mangling de C++.                                        */
/* ------------------------------------------------------------------------- */
namespace runtime {
void do_throw(ProcessVM *vm, uint64_t exception_ptr);
}

void vrt_internal_do_throw(runtime::ProcessVM *vm, uint64_t exc_handle) {
    runtime::do_throw(vm, exc_handle);
}
