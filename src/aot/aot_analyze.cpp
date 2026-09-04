/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file aot/aot_analyze.cpp
 * @brief Implementacion de  AOT.1 -- analisis is_pure_native.
 *
 * La clasificacion vive en un @c switch sobre @c ir::IrOp.  No es un hot path
 * (corre una vez por compilacion AOT, no por instruccion ejecutada), por lo
 * que un switch -- que el compilador baja a tabla de saltos o cadena de
 * comparaciones -- es lo mas claro y mantenible; no viola la regla de "tablas
 * planas en dispatch hot" (esa aplica al despacho de opcodes en runtime).
 *
 * = Nota de diseno (POO en Bare/Embed, modelo C++) =
 *   En tier BARE/EMBED la POO debe materializarse como en C++: objetos en
 *   STACK (value-type via ALLOCA + RAII) o en HEAP (via allocator: malloc en
 *   Embed, hook @AllocatorOverride en freestanding), con punteros CRUDOS y
 *   acceso a campos directo (@c mov [obj+off]).  Sin GC tracing, sin
 *   indireccion de GcHandle.  Esa re-bajada (NEWOBJ -> alloc raw + ctor;
 *   GETFIELD/SETFIELD -> LOAD/STORE directos; destructor determinista) es
 *   trabajo de AOT.2.  Aqui (AOT.1) las ops OOP del IR actual (que emiten
 *   acceso GC-handle) se marcan RUNTIME_DEPENDENT; EMBED las admite via el
 *   mini-runtime, BARE las rechaza hasta que AOT.2 provea la re-bajada raw.
 */

#include "aot/aot_analyze.h"

#include <sstream>

namespace aot {

using ir::IrOp;

// =========================================================================
//  Clasificacion de operaciones
// =========================================================================

AotOpClass aot_classify_op(IrOp op) noexcept {
    switch (op) {
    // -- constantes / movimiento / referencias estaticas --
    // STR_LIT_ADDR y LABEL_ADDR bajan a una relocacion contra .rodata
    // o un simbolo (resuelta por el linker AOT): nativas.
    case IrOp::CONST:
    case IrOp::MOV:
    case IrOp::NOP:
    case IrOp::STR_LIT_ADDR:
    case IrOp::LABEL_ADDR:
    // Simbolo de seccion (dev OS): el writer AOT lo resuelve via reloc.
    case IrOp::SECTION_REF:
    // -- markers semanticos (no emiten codigo; el backing real
    //    -- ALLOCA/STORE o GC_ALLOC -- se clasifica por separado) --
    case IrOp::MAKE_VARIANT:
    case IrOp::MATCH_VARIANT:
    case IrOp::MAKE_CLOSURE:
    // -- aritmetica entera --
    case IrOp::ADD:
    case IrOp::SUB:
    case IrOp::MUL:
    case IrOp::DIV:
    case IrOp::MOD:
    case IrOp::NEG:
    case IrOp::IABS:
    case IrOp::IMIN:
    case IrOp::IMAX:
    case IrOp::IMINU:
    case IrOp::IMAXU:
    case IrOp::ILOG2:
    // -- aritmetica flotante --
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FNEG:
    case IrOp::FABS:
    case IrOp::FSQRT:
    case IrOp::FMIN:
    case IrOp::FMAX:
    case IrOp::FMA:
    case IrOp::FFLOOR:
    case IrOp::FCEIL:
    case IrOp::FROUND:
    case IrOp::FTRUNC:
    // -- logica / desplazamientos / bit ops --
    case IrOp::AND:
    case IrOp::OR:
    case IrOp::XOR:
    case IrOp::NOT:
    case IrOp::SHL:
    case IrOp::SHR:
    case IrOp::SAR:
    case IrOp::CLZ:
    case IrOp::CTZ:
    case IrOp::POPCNT:
    case IrOp::BYTESWAP:
    case IrOp::ROTL:
    case IrOp::ROTR:
    // -- comparaciones --
    case IrOp::CMP_EQ:
    case IrOp::CMP_NE:
    case IrOp::CMP_LT:
    case IrOp::CMP_GT:
    case IrOp::CMP_LE:
    case IrOp::CMP_GE:
    case IrOp::CMP_ULT:
    case IrOp::CMP_UGT:
    case IrOp::CMP_ULE:
    case IrOp::CMP_UGE:
    case IrOp::FCMP_EQ:
    case IrOp::FCMP_NE:
    case IrOp::FCMP_LT:
    case IrOp::FCMP_GT:
    case IrOp::FCMP_LE:
    case IrOp::FCMP_GE:
    // -- conversiones --
    case IrOp::CAST:
    case IrOp::ZEXT:
    case IrOp::SEXT:
    case IrOp::TRUNC:
    case IrOp::ITOF:
    case IrOp::UITOF:
    case IrOp::FTOI:
    case IrOp::FTOUI:
    case IrOp::F32TOF64:
    case IrOp::F64TOF32:
    case IrOp::BITCAST:
    // -- seleccion sin salto (baja a cmov/csel en nativo) --
    case IrOp::SELECT:
    // -- multiprecision: bajan a la suma/resta y el setcc de la maquina --
    case IrOp::ADDC:
    case IrOp::SUBB:
    case IrOp::CARRYOF:
    // -- flujo de control / SSA --
    case IrOp::BR:
    case IrOp::BR_COND:
    case IrOp::RET:
    case IrOp::UNREACHABLE:
    case IrOp::PHI:
    // -- llamadas resueltas por el linker (intra-modulo, FFI extern a
    //    simbolos del kernel/usuario, o puntero de funcion).  El "lib"
    //    de CALLN es irrelevante en AOT estatico: el simbolo lo resuelve
    //    el linker contra lo que el usuario enlace (libc, kernel, etc.) --
    case IrOp::CALL:
    case IrOp::CALLIND:
    // CALLCLOSURE: en bare baja a una llamada indirecta plana al fn_addr de
    // la closure (se ignora el env).  Las lambdas SIN capturas compilan asi
    // (nivel puntero-de-funcion C); las capturantes usan READ_VM_REG en su
    // helper, que sigue siendo RUNTIME_DEPENDENT -> el modulo se rechaza.
    case IrOp::CALLCLOSURE:
    case IrOp::TAILCALL:
    case IrOp::CALLN:
    // -- memoria local / punteros crudos / copia inline --
    // MEMCPY baja a `rep movsb` inline: no necesita libc.
    case IrOp::ALLOCA:
    case IrOp::LOAD:
    case IrOp::STORE:
    case IrOp::GEP:
    case IrOp::MVTAKE_IR:
    case IrOp::ISNULL:
    // UNWRAP: el selector AOT lo baja a inline `test v,v; jne ok; call
    // __vx_panic_null; ok: mov dst,v` (los provably-non-null ya los elimino
    // ir_pass_elide_unwrap).  El call al hook lo resuelve el linker (como
    // cualquier extern); en freestanding el usuario provee __vx_panic_null.
    case IrOp::UNWRAP:
    case IrOp::MEMCPY:
    case IrOp::MEMSET:
    // -- ops vectoriales fusionadas (SIMD nativo / packed) --
    case IrOp::VEC_UNOP:
    case IrOp::VEC_BINOP:
    case IrOp::VEC_FMA:
    case IrOp::VEC_ACC_ZERO:
    case IrOp::VEC_ACC_ADD:
    case IrOp::VEC_ACC_FMA:
    case IrOp::VEC_ACC_STORE:
    case IrOp::VEC_ACC_COMBINE:
    case IrOp::VEC_BINOP_S:
    case IrOp::VEC_FMA_S:
    case IrOp::VEC_BCAST:
    // -- atomicos enteros (lock-prefixed nativos) --
    case IrOp::ATOMIC_LD:
    case IrOp::ATOMIC_ST:
    case IrOp::ATOMIC_CAS:
    case IrOp::ATOMIC_ADD:
    // -- ensamblador host incrustado ( AS) --
    case IrOp::INLINE_ASM:
    // -- asm opaco liftado: emite bytes nativos (ensamblados de su plantilla)
    // --
    case IrOp::ASM_MICRO:
    // -- handle<->ptr en native (AOT.2 sin handle table): el GcHandle ES el
    //    host_ptr crudo (objetos = ptr de calloc/malloc) -> el selector
    //    HOST_LEAF los baja a un MOV (passthrough).  PURE_NATIVE. --
    case IrOp::GC_HANDLE_FOR_PTR:
    case IrOp::GC_DEREF_HOST:
    // -- jump table densa (match/switch sobre enum): el selector HOST_LEAF la
    //    baja a una tabla SELF-RELATIVE (PIC-safe, sin reloc) + dispatch nativo
    //    (lea+movsxd+add+jmp).  PURE_NATIVE. --
    // -- a donde volvera la funcion: la dejo ahi la propia instruccion `call`,
    //    y el prologo (`push rbp; mov rbp, rsp`) la deja en [rbp+8].  Un MOV.
    //    No pide runtime NI mantener ninguna cadena de marcos, asi que vale
    //    igual en un binario sin libc.  PURE_NATIVE. --
    case IrOp::RETURN_ADDR:
    case IrOp::SWITCH_DENSE: return AotOpClass::PURE_NATIVE;

    // -- dependencias de libc que el COMPILADOR sintetiza por
    //    semantica del lenguaje (el usuario no escribio la llamada) --
    case IrOp::RAW_ALLOC:     // malloc<T>() -> malloc
    case IrOp::RAW_FREE:      // free(p)     -> free
    case IrOp::PANIC:         // panic(msg)  -> fputs(stderr)+exit
    case IrOp::SMARTPTR_FREE: // unique<T> cleanup -> free / deleter
    // FFI dinamico: ffi_open/ffi_sym -> CALL __vx_dlopen/__vx_dlsym (Vesta,
    // bundled vx_ffi.vx; LoadLibraryA/dlopen via extern al SO).  No necesita
    // la VM -> compilable a nativo.  En freestanding se rechaza salvo que el
    // usuario provea las funciones.
    case IrOp::DLOPEN:
    case IrOp::DLSYM: return AotOpClass::LIBC_MAPPED;

    // -- todo lo demas necesita libvesta_rt --
    default: return AotOpClass::RUNTIME_DEPENDENT;
    }
}

const char *aot_libc_symbol(IrOp op) noexcept {
    switch (op) {
    case IrOp::RAW_ALLOC: return "malloc";
    case IrOp::RAW_FREE: return "free";
    case IrOp::PANIC: return "fputs/exit";
    case IrOp::SMARTPTR_FREE: return "free";
    default: return "";
    }
}

/**
 * @brief Subsistema de runtime requerido por una op RUNTIME_DEPENDENT.
 * @return Cadena ASCII; "" si la op no es RUNTIME_DEPENDENT.
 */
static const char *aot_runtime_subsystem(IrOp op) noexcept {
    switch (op) {
    // GC tracing / objetos managed
    case IrOp::NEWOBJ:
    case IrOp::NEWOBJS:
    case IrOp::GETFIELD:
    case IrOp::SETFIELD:
    case IrOp::GC_ALLOC:
    case IrOp::GC_ALLOCP:
    case IrOp::GCWB_IR:
    case IrOp::GCDEREF_IR:
        return "GC heap (libvesta_rt; en Bare/Embed: heap+stack estilo C++ via "
               "AOT.2)";
    // GC_HANDLE_FOR_PTR / GC_DEREF_HOST: en native (AOT.2 sin handle table) son
    // PASSTHROUGH (el handle ES el host_ptr crudo) -> el selector HOST_LEAF los
    // baja a un MOV.  PURE_NATIVE (no caen aqui).
    case IrOp::GC_PROMOTE:
    case IrOp::GC_DEMOTE:
    case IrOp::SHARED_STAT: return "memoria compartida ( Z runtime)";
    case IrOp::GETSTATIC:
    case IrOp::SETSTATIC:
        return "campos estaticos de clase (ClassInfo runtime)";
    case IrOp::CALLVIRT:
    case IrOp::CALLM:
    case IrOp::CALLITF:
    case IrOp::CALLSUPER:
    case IrOp::PROCEED:
        return "dispatch virtual/interfaz (vtable/itable runtime)";
    case IrOp::CALLCLOSURE:
    case IrOp::READ_VM_REG: return "closures con entorno (heap/VM-ABI)";
    case IrOp::INSTANCEOF:
    case IrOp::CHECKCAST:
    case IrOp::SPECIALIZE: return "introspeccion de tipos runtime";
    case IrOp::ARRAY_ALLOC:
    case IrOp::ARRAY_LEN:
    case IrOp::ARRAY_LOAD:
    case IrOp::ARRAY_STORE: return "arrays managed (helper runtime)";
    case IrOp::STRMAKE:
    case IrOp::STRLEN:
    case IrOp::STRCAT:
    case IrOp::STRCMP:
    case IrOp::STRSLICE:
    case IrOp::STRFLAT:
    case IrOp::STRHASH:
    case IrOp::STRINTERN:
    case IrOp::STRRAW:
    case IrOp::STRCONV:
    case IrOp::STRRESERVE:
    case IrOp::STRFINALIZE:
    case IrOp::STRGETBYTES: return "strings GC (StringObject)";
    case IrOp::THROW:
    case IrOp::TRYENTER:
    case IrOp::TRYLEAVE:
    case IrOp::LANDINGPAD:
    case IrOp::RETHROW:
    case IrOp::UNWRAP: return "excepciones (unwinding runtime; ver AOT.7)";
    case IrOp::FUTURE:
    case IrOp::AWAIT:
    case IrOp::FULFILL:
    case IrOp::REJECT:
    case IrOp::FULFILL_HLT: return "async/futures (scheduler)";
    case IrOp::MSGSEND:
    case IrOp::MSGRECV:
    case IrOp::RSPAWN:
    case IrOp::RSPAWN_RETURN: return "distribucion (mailbox/VDP)";
    case IrOp::MONENTER:
    case IrOp::MONEXIT:
    case IrOp::MONWAIT:
    case IrOp::MONNOTI:
    case IrOp::MONNOTA: return "monitores/synchronized (runtime)";
    case IrOp::GETPROC:
    case IrOp::GETVM:
    case IrOp::GETMGR: return "contexto VM (ProcessVM/VM)";
    case IrOp::SPAWN:
    case IrOp::RESUME:
    case IrOp::YIELD:
    case IrOp::SWAPCTX:
    case IrOp::SPAWN_ARGS:
    case IrOp::SPAWN_ON:
    case IrOp::HLT:
    case IrOp::GETPID: return "scheduler/procesos (runtime)";
    /* Los argumentos del programa NO son cosa del planificador: es que el
     * arranque nativo nunca los recoge.  Decir "runtime" mandaba a buscarlo
     * al sitio equivocado. */
    case IrOp::GETARGC:
    case IrOp::GETARG:
        return "los argumentos del programa, que el arranque nativo todavia "
               "no recoge";
    case IrOp::FINDCLASS:
    case IrOp::DEFCLASS:
    case IrOp::DEFFIELD:
    case IrOp::DEFMETHOD:
    case IrOp::ADDADVICE:
    case IrOp::FINDMETHOD:
    case IrOp::FINDFIELD:
    case IrOp::SETMETHDBG: return "classregistry/AOP (runtime)";
    case IrOp::REFLECT_COUNT:
    case IrOp::REFLECT_AT: return "reflexion (runtime)";
    case IrOp::MOD_LOAD:
    case IrOp::DLOPEN:
    case IrOp::DLSYM: return "carga dinamica de modulos (runtime/FFI dlopen)";
    case IrOp::RAW_ASM:
        return "ensamblador VM (.vel opaco; no compilable a nativo)";
    default: return "";
    }
}

/**
 * @brief Subset de ops RUNTIME_DEPENDENT que el mini-runtime EMBED soporta.
 *
 * EMBED mantiene POO con heap+stack estilo C++ (objetos con allocator, sin
 * GC tracing), strings, closures, excepciones y monitores; rechaza async,
 * distribucion, scheduler, reflexion, classregistry dinamico, carga de
 * modulos y memoria compartida.
 */
static bool aot_op_embed_supported(IrOp op) noexcept {
    switch (op) {
    // POO: objetos (heap allocator / stack), campos, dispatch
    case IrOp::NEWOBJ:
    case IrOp::GETFIELD:
    case IrOp::SETFIELD:
    case IrOp::GC_ALLOC:
    case IrOp::GC_ALLOCP:
    case IrOp::GC_HANDLE_FOR_PTR:
    case IrOp::GC_DEREF_HOST:
    case IrOp::GCWB_IR:
    case IrOp::GCDEREF_IR:
    case IrOp::GETSTATIC:
    case IrOp::SETSTATIC:
    case IrOp::CALLVIRT:
    case IrOp::CALLM:
    case IrOp::CALLITF:
    case IrOp::CALLSUPER:
    case IrOp::PROCEED:
    // closures: CALLCLOSURE ya es PURE_NATIVE (arriba); READ_VM_REG (lectura
    // del env en R14 por el helper de una lambda CAPTURANTE) sigue siendo
    // runtime -> las lambdas con capturas se rechazan limpio en bare.
    case IrOp::READ_VM_REG:
    // tipos
    case IrOp::INSTANCEOF:
    case IrOp::CHECKCAST:
    // arrays managed
    case IrOp::ARRAY_ALLOC:
    case IrOp::ARRAY_LEN:
    case IrOp::ARRAY_LOAD:
    case IrOp::ARRAY_STORE:
    // strings
    case IrOp::STRMAKE:
    case IrOp::STRLEN:
    case IrOp::STRCAT:
    case IrOp::STRCMP:
    case IrOp::STRSLICE:
    case IrOp::STRFLAT:
    case IrOp::STRHASH:
    case IrOp::STRINTERN:
    case IrOp::STRRAW:
    case IrOp::STRCONV:
    case IrOp::STRRESERVE:
    case IrOp::STRFINALIZE:
    case IrOp::STRGETBYTES:
    // excepciones
    case IrOp::THROW:
    case IrOp::TRYENTER:
    case IrOp::TRYLEAVE:
    case IrOp::LANDINGPAD:
    case IrOp::RETHROW:
    case IrOp::UNWRAP:
    // monitores
    case IrOp::MONENTER:
    case IrOp::MONEXIT:
    case IrOp::MONWAIT:
    case IrOp::MONNOTI:
    case IrOp::MONNOTA: return true;
    // async/distrib/scheduler/reflexion/classregistry/loadmod/
    // memoria-compartida/specialize/raw_asm -> NO en EMBED.
    default: return false;
    }
}

bool aot_op_allowed(IrOp op, const AotTarget &target) noexcept {
    // RAW_ASM es ensamblador de la VM (texto .vel): no tiene equivalente
    // nativo en NINGUN tier (ni siquiera FULL, que enlaza el runtime pero
    // igual compila el codigo a maquina).  El IR moderno no deberia
    // emitirlo ( 2c lo elimino); defensa por si reaparece.
    if (op == IrOp::RAW_ASM) return false;
    // Excepciones auto-hospedadas ( AOT, vx_exc.vx): el THROW baja a
    // un CALL a __vx_throw (setjmp/longjmp, sin VM runtime) -> es un simbolo
    // del linker, valido en CUALQUIER tier (Bare/Embed/Full) cuando las
    // excepciones estan habilitadas.  El try/catch lowering ya no emite
    // TRYENTER/TRYLEAVE/LANDINGPAD en native_poo_ (baja a CALLs __vx_*).
    if (op == IrOp::THROW) return target.exceptions_enabled;
    const AotOpClass cls = aot_classify_op(op);
    if (cls == AotOpClass::PURE_NATIVE)
        return true; // stack/aritmetica/control/llamadas-linker: siempre.
    if (cls == AotOpClass::LIBC_MAPPED) {
        if (!target.freestanding) return true; // libc disponible.
        // freestanding: admitir SOLO si el usuario aporta el rol via
        // @AllocatorOverride / @PanicHandler (el simbolo lo da el, no la libc).
        switch (op) {
        case IrOp::RAW_ALLOC: return target.alloc_provided;
        case IrOp::RAW_FREE:
        case IrOp::SMARTPTR_FREE: return target.free_provided;
        case IrOp::PANIC: return target.panic_provided;
        default: return false;
        }
    }
    // RUNTIME_DEPENDENT:
    switch (target.tier) {
    case Tier::FULL: return true;
    case Tier::EMBED: return aot_op_embed_supported(op);
    case Tier::BARE: return false;
    }
    return false;
}

const char *aot_op_requirement(IrOp op, const AotTarget &target) noexcept {
    if (aot_op_allowed(op, target)) return "";
    const AotOpClass cls = aot_classify_op(op);
    if (cls == AotOpClass::LIBC_MAPPED) {
        // Solo cae aqui en freestanding: libc no disponible.
        switch (op) {
        case IrOp::RAW_ALLOC:
            return "libc malloc (usa @AllocatorOverride en --freestanding)";
        case IrOp::RAW_FREE:
        case IrOp::SMARTPTR_FREE:
            return "libc free (usa @AllocatorOverride en --freestanding)";
        case IrOp::PANIC:
            return "libc fputs/exit (usa @PanicHandler en --freestanding)";
        default: return "libc (no disponible en --freestanding)";
        }
    }
    // RUNTIME_DEPENDENT no admitida en el tier.
    return aot_runtime_subsystem(op);
}

// =========================================================================
//  Analisis de funciones y modulos
// =========================================================================

bool aot_analyze_function(const ir::IrFunction &fn, const AotTarget &target,
                          std::vector<AotIncompat> &out_issues) {
    // Los stubs de funciones nativas no tienen cuerpo IR; se resuelven como
    // simbolos externos en el linker -> siempre compatibles.
    if (fn.is_native) return true;

    bool ok = true;
    for (const ir::IrBlock &blk : fn.blocks) {
        for (const ir::IrInstr &ins : blk.instrs) {
            if (aot_op_allowed(ins.op, target)) continue;
            ok = false;
            AotIncompat issue;
            issue.fn_name = fn.name;
            issue.source_line = ins.source_line;
            issue.op = ins.op;
            const char *req = aot_op_requirement(ins.op, target);
            issue.reason =
                (req[0] != '\0')
                    ? std::string(req)
                    : std::string("no admisible en el target seleccionado");
            out_issues.push_back(std::move(issue));
        }
    }
    return ok;
}

AotCompatReport aot_analyze_module(const ir::IrModule &mod,
                                   const AotTarget &target) {
    AotCompatReport report;
    report.target = target;
    for (const ir::IrFunction &fn : mod.functions) {
        if (aot_analyze_function(fn, target, report.issues))
            report.ok_functions.push_back(fn.name);
        else
            report.compatible = false;
    }
    return report;
}

std::string AotCompatReport::render() const {
    if (compatible) return std::string();
    std::ostringstream os;
    const char *tier_name = (target.tier == Tier::BARE)    ? "bare"
                            : (target.tier == Tier::EMBED) ? "embed"
                                                           : "full";
    os << "AOT: el modulo no es compilable en --target=" << tier_name;
    if (target.freestanding) os << " --freestanding";
    os << " (" << issues.size() << " incompatibilidad(es)):\n";
    for (const AotIncompat &it : issues) {
        os << "  fn '" << it.fn_name << "'";
        if (it.source_line != 0) os << " linea " << it.source_line;
        os << ": op '" << ir::ir_op_name(it.op) << "' requiere " << it.reason
           << "\n";
    }
    if (target.tier == Tier::BARE) {
        os << "  hint: usa struct value-type / punteros crudos / malloc, "
              "o cambia a --target=embed o --target=full.\n";
    }
    return os.str();
}

} // namespace aot
