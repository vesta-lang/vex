/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/runtime_entries.h
 * @brief Tabla de punteros a las funciones runtime que codigo JIT puede
 *        invocar (call sites de los wrappers @c vesta_rt/public.h).
 *
 * = Diseno =
 *
 * El JIT necesita emitir @c CALL hacia funciones del runtime
 * (@c vrt_gc_alloc, @c vrt_throw_fatal, etc.) sin tener acceso al
 * linker en compile-time.  Esta tabla resuelve los simbolos UNA VEZ
 * (al construir @c RuntimeEntries) y los expone como direcciones
 * raw que el emisor JIT incrusta en el codigo nativo.
 *
 * Patron de uso desde el emisor:
 *
 *   const RuntimeEntries &rt = vm.runtime_entries();
 *   // emitir: mov rdi, proc ; mov rsi, 64 ; call rt.gc_alloc
 *
 * Las direcciones son ESTABLES durante la vida del proceso (las
 * funciones viven en el binario; no se mueven).  Por eso podemos
 * incrustarlas como inmediatos 64-bit o como @c call rel32 si el
 * code cache esta dentro del rango +-2GB del binario.
 *
 * = añadir un nuevo entry =
 *
 * 1. Declarar la funcion en @c vesta_rt/public.h.
 * 2. Implementarla en @c src/vesta_rt/public_wrapper.cpp.
 * 3. añadir un campo aqui en @c RuntimeEntries.
 * 4. Inicializar el campo en el constructor.
 * 5. Documentar la convencion (args + return) en su Doxygen.
 */

#ifndef VESTA_JIT_RUNTIME_ENTRIES_H
#define VESTA_JIT_RUNTIME_ENTRIES_H

#include <cstdint>

#include "vesta_rt/public.h"

namespace jit {

/**
 * @struct RuntimeEntries
 * @brief Tabla de punteros resueltos a las funciones runtime.
 *
 * Una instancia por VM.  Inicializa los campos en su constructor
 * con las direcciones de los simbolos @c vrt_* exportados por
 * @c libvesta_rt.  El JIT lee estas direcciones y las incrusta
 * como inmediatos @c mov rax, imm64 ; call rax, o como @c call
 * rel32 cuando el code cache esta cerca del binario.
 */
struct RuntimeEntries {
    /* ----- GC ----- */
    vrt_handle (*gc_alloc)(vrt_proc *, size_t) = nullptr;
    vrt_handle (*gc_alloc_pinned)(vrt_proc *, size_t) = nullptr;
    uint8_t *(*gc_deref)(vrt_proc *, vrt_handle) = nullptr;
    vrt_handle (*gc_handle_for_ptr)(vrt_proc *, const uint8_t *) = nullptr;
    void (*gc_drop)(vrt_proc *, vrt_handle) = nullptr;
    void (*gc_addref)(vrt_proc *, vrt_handle) = nullptr;
    void (*gc_release)(vrt_proc *, vrt_handle) = nullptr;
    void (*gc_write_barrier)(vrt_proc *, vrt_handle) = nullptr;

    /* ----- Memoria HOST raw (malloc/free no-GC) ----- */
    uint8_t *(*raw_alloc)(vrt_proc *, size_t) = nullptr;
    void (*raw_free)(vrt_proc *, uint8_t *) = nullptr;

    /* ----- Monitores ----- */
    int32_t (*monitor_enter)(vrt_proc *, vrt_handle) = nullptr;
    void (*monitor_exit)(vrt_proc *, vrt_handle) = nullptr;
    void (*monitor_wait)(vrt_proc *, vrt_handle) = nullptr;
    void (*monitor_notify)(vrt_proc *, vrt_handle) = nullptr;
    void (*monitor_notify_all)(vrt_proc *, vrt_handle) = nullptr;

    /* ----- Excepciones ----- */
    void (*throw_fatal)(vrt_proc *, uint32_t, const char *) = nullptr;
    void (*unwrap_throw)(vrt_proc *) = nullptr; ///< UNWRAP null (1-arg)
    uint64_t (*proc_pid)(vrt_proc *) = nullptr; ///< GETPID -> PID encoded
    void (*tryenter)(vrt_proc *, uint64_t, vrt_class *) = nullptr;
    void (*tryleave)(vrt_proc *) = nullptr;
    /* Excepciones in-JIT (Opcion B): handler en codigo JIT.  El throw resume
     * via do_throw -> vrt_resume_jit (no por el interp). */
    void (*tryenter_jit)(vrt_proc *, vrt_class *, uint64_t) = nullptr;
    /* Lanza una excepcion user-defined dado su GcHandle (i64).  Delega
     * a @c do_throw que recorre @c exc_frame_stack para encontrar el
     * catch matching y salta al handler.  Nunca retorna normalmente. */
    void (*throw_user)(vrt_proc *, uint64_t) = nullptr;
    /* Relanza la excepcion activa (@c proc->current_exception).  Usado
     * por el rethrow de los synchronized handlers tras hacer monexit. */
    void (*rethrow)(vrt_proc *) = nullptr;

    /* ----- FFI ----- */
    uint64_t (*invoke_native)(void *, uint64_t, vrt_proc *) = nullptr;

    /* ----- Dispatch dinamico (CALLVIRT desde JIT) ----- */
    uint64_t (*callvirt)(vrt_proc *, uint8_t *, uint32_t) = nullptr;

    /* ----- CALLM (interfaces, reflexion) ----- */
    uint64_t (*callm)(vrt_proc *, uint8_t *, void *) = nullptr;

    /* ----- CALLITF (dispatch de interfaz via itable) ----- */
    uint64_t (*callitf)(vrt_proc *, uint8_t *, uint64_t, uint64_t) = nullptr;

    /* ----- CALLCLOSURE (closures) ----- */
    uint64_t (*callclosure)(vrt_proc *, uint64_t, uint64_t) = nullptr;

    /* ----- CALLN (FFI estatico) ----- */
    uint64_t (*calln)(vrt_proc *, const char *, const char *) = nullptr;

    /* ----- Trampoline JIT->interp para CALL/CALLVM unsupported (D.4-fix) -----
     */
    /* Cuando una callee user-defined no se puede JIT-compilar, el
     * selector emite call a este wrapper que ejecuta el bytecode
     * en mini-interp sincronico.  Args ya stagedos en
     * proc->registers.regs[1..N], retorno en R0. */
    uint64_t (*call_bc_function)(vrt_proc *, uint64_t) = nullptr;

    /* ----- VM memory access ( D.3-G) ----- */
    uint64_t (*vm_read_u64)(vrt_proc *, uint64_t) = nullptr;
    void (*vm_write_u64)(vrt_proc *, uint64_t, uint64_t) = nullptr;
    /* Variantes por tamano (LOAD/STORE de i8/i16/i32 desde VM-ptr). */
    uint32_t (*vm_read_u32)(vrt_proc *, uint64_t) = nullptr;
    uint16_t (*vm_read_u16)(vrt_proc *, uint64_t) = nullptr;
    uint8_t (*vm_read_u8)(vrt_proc *, uint64_t) = nullptr;
    void (*vm_write_u32)(vrt_proc *, uint64_t, uint32_t) = nullptr;
    void (*vm_write_u16)(vrt_proc *, uint64_t, uint16_t) = nullptr;
    void (*vm_write_u8)(vrt_proc *, uint64_t, uint8_t) = nullptr;
    /* Y las de BLOQUE sobre la memoria de la maquina.  Faltaban, y lo que
     * pasaba no era que el codigo compilado fuera mas lento: es que rellenaba
     * o copiaba en OTRO SITIO, porque se emitia la variante del ANFITRION
     * sobre una direccion virtual sin mirar de que memoria era.  Una direccion
     * virtual no es un puntero del proceso -- hay traduccion y paginas por
     * medio --, asi que no da un error, da otro resultado. */
    void (*vm_memset)(vrt_proc *, uint64_t, uint64_t, uint64_t) = nullptr;
    void (*vm_memcpy)(vrt_proc *, uint64_t, uint64_t, uint64_t) = nullptr;
    /*  D.jit-mem-model FULL: translate VM-addr/host_ptr -> host_ptr. */
    uint8_t *(*vm_translate)(vrt_proc *, uint64_t) = nullptr;

    /* ----- Class registry ( D.3-G: findclass/newobj/defclass/...) -----
     */
    vrt_class *(*findclass)(vrt_proc *, uint64_t) = nullptr;
    uint8_t *(*newobj)(vrt_proc *, vrt_class *) = nullptr;
    /* Combinado newobj + gc_handle_for_ptr en una sola call (fast path JIT). */
    vrt_handle (*newobj_handle)(vrt_proc *, vrt_class *) = nullptr;
    /* NEWOBJS: alloc en SharedHeap -> handle (bit 31). */
    vrt_handle (*newobjs)(vrt_proc *, vrt_class *) = nullptr;
    /* DLOPEN: carga libreria nativa -> handle host. */
    uint64_t (*dlopen)(vrt_proc *, uint64_t, uint32_t) = nullptr;
    /* STRCONV: convierte StringObject a otra codificacion -> handle. */
    vrt_handle (*str_conv)(vrt_proc *, vrt_handle, uint32_t) = nullptr;
    /* CALLVIRT con Inline Cache (actualiza slot tras dispatch). */
    uint64_t (*callvirt_ic)(vrt_proc *, uint8_t *, uint32_t,
                            uint64_t) = nullptr;
    vrt_class *(*defclass)(vrt_proc *, uint64_t) = nullptr;
    int32_t (*deffield)(vrt_proc *, vrt_class *, uint64_t) = nullptr;
    uint32_t (*defmethod)(vrt_proc *, vrt_class *, uint64_t) = nullptr;
    int32_t (*addadvice)(vrt_proc *, void *, void *, uint8_t) = nullptr;
    void *(*findmethod)(vrt_proc *, uint64_t) = nullptr;
    void *(*findfield)(vrt_proc *, uint64_t) = nullptr;
    void (*setmethdbg)(vrt_proc *, uint64_t) = nullptr;

    /* ----- String ops (Sprint JIT-cobertura 2026-06-01) ----- */
    vrt_handle (*str_make)(vrt_proc *, uint64_t, uint32_t) = nullptr;
    vrt_handle (*str_make_h)(vrt_proc *, uint64_t, uint32_t) = nullptr;
    uint64_t (*str_len)(vrt_proc *, vrt_handle) = nullptr;
    uint64_t (*str_get_bytes)(vrt_proc *, vrt_handle) = nullptr;
    uint64_t (*str_raw)(vrt_proc *, vrt_handle) = nullptr;
    vrt_handle (*str_cat)(vrt_proc *, vrt_handle, vrt_handle) = nullptr;
    /// vrt_str_slice(proc, src, range) -> handle del SLICE
    vrt_handle (*str_slice)(vrt_proc *, vrt_handle, uint64_t) = nullptr;
    int64_t (*str_cmp)(vrt_proc *, vrt_handle, vrt_handle) = nullptr;

    /* ----- Panic + GC alloc payload (Sprint JIT-cobertura) ----- */
    void (*panic_str)(vrt_proc *, uint64_t, uint32_t) = nullptr;
    uint8_t *(*gc_alloc_payload)(vrt_proc *, size_t) = nullptr;

    /* ----- Safepoint ----- */
    void (*safepoint_poll)(vrt_proc *) = nullptr;
    void (*safepoint_handler)(vrt_proc *) = nullptr;

    /**
     * @brief Resuelve todos los campos a las direcciones de las
     *        funciones @c vrt_* enlazadas con el binario.
     *
     * Llamado UNA VEZ en el constructor de @c VM.  El JIT lee los
     * campos durante el lifetime de la VM; nunca se mutan.
     */
    void resolve();

    /**
     * @brief Verifica que todos los entries esten resueltos.
     * @return true si todos no-null; false si algun campo quedo en NULL
     *         (indica error de link, debug temprano).
     */
    bool all_resolved() const noexcept;
};

} // namespace jit

#endif // VESTA_JIT_RUNTIME_ENTRIES_H
