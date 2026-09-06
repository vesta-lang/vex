/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/vreg_select.h
 * @brief Instruction selection IR -> MachineIR en forma de registros
 *        VIRTUALES ( D.7, commit 4b).  Ver doc/REGALLOC.md.
 *
 * A diferencia del selector v1 (slot-per-value, template load/op/store), este
 * emite operandos VREG directos en forma de TRES operandos
 * (@c "add dst, src1, src2" -> dst = src1 OP src2), MUCHO mas simple: el
 * register allocator + el rewrite (commits 2-4a) se encargan del resto.
 *
 * Mapeo: vreg id == IrValueId (1:1).  La salida pasa por
 * @c build_intervals -> @c linear_scan -> @c rewrite_to_physical -> encoder.
 *
 * Cobertura commit 4b: CONST, ALU entera binaria (ADD/SUB/MUL) y unaria
 * (NEG/NOT), RET; funciones de UN bloque (sin control de flujo todavia).  Si
 * encuentra un op fuera del subset, devuelve @c false y el caller hace
 * fallback (al path de slots o al interprete).  Control de flujo, PHI, calls,
 * floats y la integracion VM_ABI llegan en commits posteriores.
 */

#ifndef VESTA_JIT_VREG_SELECT_H
#define VESTA_JIT_VREG_SELECT_H

#include "jit/machine_ir.h"

#include <functional>
#include <string>

namespace ir {
struct IrFunction;
}

namespace jit {

/**
 * @brief Backend de punto flotante para el codegen (AOT, seleccionable por el
 *        usuario con @c --float-isa).  La mayoria de CPUs modernas tienen AVX
 *        pero NO AVX512F, por eso son modos distintos.  @c AUTO emite varias
 *        variantes + un dispatch por CPUID al arranque (portabilidad).
 */
enum class FloatIsa : uint8_t {
    X87 = 0,     ///< FPU x87 (todo x86 incluso 386; pila ST, sin XMM).
    SSE2 = 1,    ///< SSE2 (baseline x86-64; XMM, ADDSD/MULSD).  Default.
    AVX = 2,     ///< AVX (VX, 3-operandos VADDSD; mayoria de CPUs modernas).
    AVX512F = 3, ///< AVX-512 Foundation (EVEX; server/HEDT recientes).
    AUTO = 4,    ///< deteccion en runtime via CPUID -> la mejor disponible.
};

/**
 * @brief Resolver de @c CALL: dado el nombre de la funcion destino,
 *        devuelve su direccion nativa (0 si no resoluble -> fallback).
 */
using CallResolver = std::function<uint64_t(const std::string &)>;

/**
 * @brief Resuelve la ABI custom (param_abi_regs) de un callee por NOMBRE, para
 *        el CALL directo.  Devuelve puntero al vector de registros por
 * parametro (alineado con los args), o nullptr si el callee usa la ABI
 * estandar. El puntero debe seguir vivo durante la compilacion (el driver lo
 *        respalda con su indice de IrFunctions).
 */
using AbiResolver =
    std::function<const std::vector<std::string> *(const std::string &)>;

/**
 * @brief Registra (thread-local) el resolver de ABI custom para el CALL
 * directo. Lo llama el driver AOT antes de compilar cada funcion.  Pasar {} lo
 *        limpia.  El CALLIND no lo usa (su ABI viaja en la instruccion).
 */
void vreg_set_abi_resolver(AbiResolver resolver) noexcept;

/**
 * @struct VregEntries
 * @brief Direcciones de runtime entries que el selector vreg necesita para
 *        bajar ops que llaman al runtime.  0 = no disponible (esos ops caen
 *        a fallback).  Se construye desde @c RuntimeEntries en @c auto_jit.
 */
struct VregEntries {
    /// Auto-PGO tier-2: entry-point que el prologo del metodo llama al cruzar
    /// el umbral de invocaciones (proc, method_ptr).  0 = no emitir el
    /// contador.
    uint64_t tier2_request = 0;
    /// Direccion de method->invocation_count del metodo en compilacion (para el
    /// contador del prologo).  0 = no emitir (compilacion sin MethodInfo o
    /// AOT).
    uint64_t tier2_ctr_addr = 0;
    /// MethodInfo* (arg del entry-point tier2_request).
    uint64_t tier2_method_ptr = 0;
    /// Umbral absoluto (invocation_count) al que disparar tier-2.
    uint32_t tier2_threshold = 0;
    uint64_t callvirt = 0; ///< vrt_callvirt(proc, obj, vtbl_idx)
    uint64_t callm = 0;    ///< vrt_callm(proc, obj, method_ptr)
    uint64_t callitf = 0;  ///< vrt_callitf(proc, obj, params, method_idx)
    uint64_t unwrap_throw =
        0;                  ///< vrt_unwrap_throw(proc) -- UNWRAP null (VM_ABI)
    uint64_t proc_pid = 0;  ///< vrt_proc_pid(proc) -> PID encoded (GETPID)
    uint64_t gc_deref = 0;  ///< vrt_gc_deref(proc, handle)
    uint64_t gc_handle = 0; ///< vrt_gc_handle_for_ptr(proc, host_ptr)
    uint64_t gc_write_barrier =
        0; ///< vrt_gc_write_barrier(proc, container_handle) -- GCWB_IR
    uint64_t raw_alloc = 0; ///< vrt_raw_alloc(proc, size)
    /**
     * @brief El asignador de ESTE programa, ya compilado (0 = no hay).
     *
     * Cuando lo hay, el monton es el suyo y no el de la maquina, asi que el
     * atajo que replica el asignador de la maquina en linea deja de valer:
     * seria un camino mas al monton equivocado, y un bloque acabaria pidiendose
     * por uno y soltandose por otro.
     */
    uint64_t alloc_del_programa = 0;
    /// El que libera, del mismo programa (0 = no hay).  Va con el de arriba:
    /// quien reserva, libera, o el monton se corrompe.
    uint64_t free_del_programa = 0;
    uint64_t raw_free = 0;  ///< vrt_raw_free(proc, host_ptr)
    uint64_t gc_allocp = 0; ///< vrt_gc_alloc_payload(proc, size) -> host_ptr
    uint64_t newobj = 0;  ///< vrt_newobj_handle(proc, cls) -> GcHandle (NEWOBJ)
    uint64_t newobjs = 0; ///< vrt_newobjs(proc, cls) -> handle (NEWOBJS shared)
    uint64_t dlopen = 0;  ///< vrt_dlopen(proc, path_vaddr, len) -> host handle
    uint64_t str_conv = 0; ///< vrt_str_conv(proc, str, enc) -> handle (STRCONV)
    uint64_t panic_str = 0; ///< vrt_panic_str(proc, msg_vaddr, len) (PANIC)
    /* Excepciones in-JIT (Opcion B).  tryenter_jit registra el frame con la
     * direccion nativa del catch + rsp/rbp host; tryleave hace el pop normal;
     * throw_user lanza (do_throw resume via vrt_resume_jit). */
    uint64_t tryenter_jit = 0; ///< vrt_tryenter_jit(proc,type,catch_addr)
    uint64_t tryleave = 0;     ///< vrt_tryleave(proc)
    uint64_t throw_user = 0;   ///< vrt_throw_user(proc, exc_handle)
    /* Offsets (desde ProcessVM*) de los campos handoff RSP/RBP del tryenter
     * in-JIT.  -1 = no disponible -> TRYENTER baila. */
    int32_t jit_exc_rsp_off = -1; ///< offsetof(ProcessVM, jit_exc_rsp)
    int32_t jit_exc_rbp_off = -1; ///< offsetof(ProcessVM, jit_exc_rbp)
    uint64_t calln = 0; ///< vrt_calln(proc, lib_id, fn_id) -- FFI native
    /* Class registry (Fase 2).  Todos 1-arg (proc, params_vaddr) salvo
     * deffield/defmethod (2-arg: cls, params) y addadvice (3-arg). */
    uint64_t findclass = 0;  ///< vrt_findclass(proc, params) -> ClassInfo*
    uint64_t findmethod = 0; ///< vrt_findmethod(proc, params) -> MethodInfo*
    uint64_t findfield = 0;  ///< vrt_findfield(proc, params) -> FieldInfo*
    uint64_t defclass = 0;   ///< vrt_defclass(proc, params) -> ClassInfo*
    uint64_t setmethdbg = 0; ///< vrt_setmethdbg(proc, params) -> void
    uint64_t deffield = 0;   ///< vrt_deffield(proc, cls, params) -> i32
    uint64_t defmethod = 0;  ///< vrt_defmethod(proc, cls, params) -> u32
    uint64_t addadvice =
        0; ///< vrt_addadvice(proc, target, advice, kind) -> i32
    /* String ops (cluster cobertura 2026-06-09).  Todas via CALL al
     * runtime; STRMAKE/STRCAT devuelven GcHandle (root de tipo HANDLE). */
    uint64_t str_make = 0; ///< vrt_str_make(proc, vm_addr, byte_len) -> handle
    uint64_t str_make_h =
        0; ///< vrt_str_make_h(proc, host_addr, byte_len) -> handle (buf host)
    uint64_t str_len = 0;   ///< vrt_str_len(proc, handle) -> i64 (code points)
    uint64_t str_cat = 0;   ///< vrt_str_cat(proc, a, b) -> handle (ROPE)
    uint64_t str_slice = 0; ///< vrt_str_slice(proc, src, range) -> handle
    uint64_t str_cmp = 0;   ///< vrt_str_cmp(proc, a, b) -> i64 (-1/0/1)
    uint64_t str_raw = 0;   ///< vrt_str_raw(proc, handle) -> host_ptr a data[]
    uint64_t str_get_bytes =
        0; ///< vrt_str_get_bytes(proc, handle) -> i64 byte_len
    uint64_t call_bc_function =
        0; ///< vrt_call_bc_function(proc, vm_addr) -- deleter dinamico
    uint64_t callclosure =
        0; ///< vrt_callclosure(proc, fn_addr, env_addr) -> result
    /* Fibras nativas en JIT (FN.3).  swapctx = direccion NATIVA de
     * @c __vx_swapctx (@Naked, compilado via compile_native_fn en el
     * force-eager del grafo de fibra); el vreg emite un CALL nativo a el
     * para @c IrOp::SWAPCTX.  callind = @c vrt_callind(proc, func_ptr), el
     * helper de runtime que replica @c exec_instr_callvmr (distingue
     * naked-native/jit-VM_ABI/VA por rango) para @c IrOp::CALLIND en JIT. */
    uint64_t swapctx = 0; ///< addr nativa de __vx_swapctx (SWAPCTX en JIT)
    uint64_t callind = 0; ///< vrt_callind(proc, func_ptr) (CALLIND en JIT)
    /* Fallback page-miss de LOAD_VM/STORE_VM (acceso a vm_mem).  0 = no
     * disponible -> esos ops caen a fallback. */
    uint64_t vm_read_u8 = 0;   ///< vrt_vm_read_u8(proc, vaddr)  -> u8
    uint64_t vm_read_u16 = 0;  ///< vrt_vm_read_u16(proc, vaddr) -> u16
    uint64_t vm_read_u32 = 0;  ///< vrt_vm_read_u32(proc, vaddr) -> u32
    uint64_t vm_read_u64 = 0;  ///< vrt_vm_read_u64(proc, vaddr) -> u64
    uint64_t vm_write_u8 = 0;  ///< vrt_vm_write_u8(proc, vaddr, val)
    uint64_t vm_write_u16 = 0; ///< vrt_vm_write_u16(proc, vaddr, val)
    uint64_t vm_write_u32 = 0; ///< vrt_vm_write_u32(proc, vaddr, val)
    uint64_t vm_write_u64 = 0; ///< vrt_vm_write_u64(proc, vaddr, val)
    /* Y las de BLOQUE sobre la memoria de la maquina.  Faltaban, y lo que
     * pasaba no era que el codigo compilado fuera mas lento: es que rellenaba
     * o copiaba en OTRO SITIO, porque se emitia la variante del ANFITRION
     * sobre una direccion virtual sin mirar de que memoria era.  0 = no
     * disponible -> el selector se RINDE en vez de emitir la del anfitrion,
     * que es lo que hacia. */
    uint64_t vm_memset = 0; ///< vrt_vm_memset(proc, vaddr, byte, len)
    uint64_t vm_memcpy = 0; ///< vrt_vm_memcpy(proc, dst, src, len)
};

/**
 * @brief Selecciona MachineIR de vregs desde @p fn.
 *
 * @param fn   Funcion IR (subset soportado: ver arriba).
 * @param out  MFunction destino (se sobrescribe).
 * @param ent  Direcciones de runtime entries (callvirt/gc/raw_alloc/calln).
 * @param resolve_symbol  Resolver de simbolos del linker ( D.3-H):
 *             dado @c "code.s_<N>" / @c "code.<fn>" devuelve la direccion
 *             VM absoluta.  Lo usan @c STR_LIT_ADDR / @c LABEL_ADDR.  Si es
 *             nullptr o retorna 0, esos ops caen a fallback (igual que el
 *             selector de slots).
 * @return     @c true si TODOS los ops estan soportados y @p out es
 *             valido; @c false si encuentra un op fuera del subset (en
 *             ese caso @p out queda indefinido y el caller hace fallback).
 */
/**
 * @brief Opciones del callback-ABI para el path vreg (jubilacion de slots).
 *
 * Cuando @c callback_entry es true y el @c AbiKind es @c VM, la funcion se
 * compila como un ENTRY de ABI C nativo: los argumentos llegan por la
 * convencion del host (arg_regs), no en @c proc->registers; el prologo carga el
 * @c ProcessVM* en RBX (TLS-direct @c gs:[disp] o el call de fallback),
 * marshalea los args nativos a @c proc->registers.regs[1..N] (+ argc en R15) y,
 * en modo SAFE (cuerpo no hoja-puro), salva/restaura @c proc->registers[0..15]
 * para re-entrancia; el RET escribe el retorno tanto en @c regs[0] como en RAX
 * (retorno nativo).  Replica el @c callback_entry del selector-slots que se
 * esta jubilando, para que los callbacks (qsort, WndProc, ...) los compile
 * vreg.
 */
struct VregCallbackOpts {
    bool callback_entry = false;
    /// Direccion de @c runtime::get_current_executing_process (fallback del
    /// LOAD_PROC cuando no hay TLS-direct).
    uint64_t get_proc_addr = 0;
    /// Desplazamiento @c gs:[disp] para leer @c ProcessVM* en TLS-direct
    /// (Win64).  -1 = usar el fallback por call.
    int32_t tls_gs_disp = -1;
};

/** @brief Fija si el vreg puede emitir VFMADD231 escalar (FMA3).  El AOT lo
 *  pone a target.caps.fma; sin fijar, el JIT usa las caps del host. */
void set_vreg_fma(bool ok);

bool vreg_select(const ir::IrFunction &fn, MFunction &out,
                 AbiKind abi = AbiKind::HOST_LEAF,
                 const CallResolver &resolve_call = {},
                 const VregEntries &ent = {},
                 const CallResolver &resolve_native = {},
                 const CallResolver &resolve_symbol = {}, bool pic = true,
                 bool target_sysv =
#if defined(_WIN32)
                     false
#else
                     true
#endif
                 ,
                 bool mode32 = false, FloatIsa fisa = FloatIsa::SSE2,
                 bool emit_line_map = false, const VregCallbackOpts &cb = {});

/**
 * @brief La ultima razon por la que el selector abandono una funcion.
 *
 * Vacia si no abandono.  La lee quien compila para poder DECIR que le sobro en
 * vez de un "no pude" a secas: sin ese dato hay que recompilar con una variable
 * de entorno puesta y adivinar de que funcion se hablaba.
 */
std::string &vreg_last_reason();

} // namespace jit

#endif // VESTA_JIT_VREG_SELECT_H
