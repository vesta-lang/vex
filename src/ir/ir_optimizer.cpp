/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir_optimizer.cpp
 * @brief Implementacion de los pases de optimizacion sobre la SSA IR.
 */

#include "ir/ir_optimizer.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include "ir/ir_vec_ops.h"   // cuales son las operaciones vectoriales

#include "ir/parallel_for.h"

#include "util/env_flags.h"
#include "util/crono_tramo.h"

#include "util/reloj.h"

#include "loader/oop_types.h" // ADVICE_*: los tipos de la cadena de aspectos

#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include "ir/ir_facts.h"
#include "ir/ir_pattern.h"
#include "ctpe/evaluable.h"
#include "ir/passes/if_conversion.h" // diamante/if-anidado -> SELECT (Capa 1)
#include "ir/passes/bulk_memory_lower.h" // bucle que mueve memoria -> operacion de bloque
#include "ir/passes/unroll.h" // desenrollado de bucles (factor automatico)
#include "ir/passes/select_simplify.h" // canonicalizacion algebraica de SELECT
#include "analysis/facts/alignment.h"  // de cuanto es multiplo un valor
#include "analysis/facts/asm_bindings.h" // de que valor habla un operando de asm
#include "analysis/facts/ir_facts.h" // hechos (def-use) para el modelo de efectos
#include "analysis/effects/ir_effects.h" // modelo unico de efectos (consumidor DCE, A/B)
#include "analysis/effects/effect_analysis.h" // cierre interproc: callees puros (DSE Fase 4)
#include "analysis/memory/memory_access.h" // vocabulario UNICO de acceso a memoria
#include "analysis/memory/points_to.h"     // que valor contiene un hueco
#include "vx/asm/asm_analyze.h"            // que memoria toca un bloque asm
#include "vx/asm/asm_effects.h"            // canonicalizar el registro base
#include "vx/parser.h"                     // arquitectura del objetivo
#include <unordered_map>
#include <map>
#include <optional>
#include <set>
#include <unordered_set>
#include <vector>
#include <queue>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdlib>
#include <cmath>
#include <limits>
#include <functional>
#include <sstream>
#include <algorithm>

namespace ir {
/* Helpers locales para constant folding de math IR ops (Math-IR-promote
 * v2.2c).  Preservan bits IEEE 754 via memcpy para no perder precision
 * en el round-trip uint64 <-> double que el IR usa. */
namespace {
inline double bits_to_f64(uint64_t b) noexcept {
    double d;
    std::memcpy(&d, &b, sizeof(d));
    return d;
}

inline uint64_t f64_to_bits(double d) noexcept {
    uint64_t b;
    std::memcpy(&b, &d, sizeof(b));
    return b;
}

inline float bits_to_f32(uint32_t b) noexcept {
    float f;
    std::memcpy(&f, &b, sizeof(f));
    return f;
}

inline uint32_t f32_to_bits(float f) noexcept {
    uint32_t b;
    std::memcpy(&b, &f, sizeof(b));
    return b;
}
} // namespace

// =========================================================================
//  Utilidades internas
// =========================================================================

/** @brief Devuelve true si la instruccion tiene efectos laterales visibles. */
/**
 * @brief Ops de cadena cuyo UNICO efecto es alocar el resultado.
 *
 * Estan en @ref is_side_effecting porque alocan (y una alocacion puede disparar
 * el GC), lo que impide deduplicarlas o moverlas.  Pero si NADIE usa el handle
 * que devuelven, no hay nada que observar: alocar una cadena que no se lee no
 * cambia el resultado del programa, solo gasta.  Asi que el DCE si puede
 * quitarlas -- ver su uso alli.
 *
 * Hace falta desde que se pliega `a + b` con `a`/`b` conocidas: el STRMAKE de
 * la parte que solo aparecia en el concat se queda sin usar, y sin esto seguia
 * alocando una cadena que ya no lee nadie.
 *
 * Deja fuera a las que MUTAN algo ajeno: @c STRFINALIZE reescribe la cabecera
 * de un FLAT existente, asi que su efecto no es solo el retorno.
 */
/**
 * @brief Suma @p desplazamiento a cada marcador `$N` del cuerpo @p cuerpo.
 *
 * Los operandos que elige el compilador se nombran en el cuerpo de un bloque
 * asm por `$N`, donde N indexa la lista de ligaduras de la FUNCION.  Al traer
 * el bloque a otra funcion hay que correr esos numeros para que no pisen a los
 * que ya habia; el texto es lo unico que hay que tocar, porque el resto del
 * bloque no menciona registros.
 *
 * @param cuerpo Texto del bloque asm.
 * @param desplazamiento Cuanto sumar a cada numero.
 * @return El cuerpo con los marcadores corridos.
 */
static std::string vx_desplazar_marcadores(const std::string &cuerpo,
                                           int desplazamiento) {
    std::string out;
    out.reserve(cuerpo.size() + 8);
    for (size_t i = 0; i < cuerpo.size();) {
        if (cuerpo[i] != '$') {
            out += cuerpo[i++];
            continue;
        }
        size_t j = i + 1;
        int n = 0;
        bool hay = false;
        while (j < cuerpo.size() && cuerpo[j] >= '0' && cuerpo[j] <= '9') {
            n = n * 10 + (cuerpo[j] - '0');
            ++j;
            hay = true;
        }
        if (!hay) {
            out += cuerpo[i++];
            continue;
        } // '$' suelto: verbatim
        out += '$';
        out += std::to_string(n + desplazamiento);
        i = j;
    }
    return out;
}

static bool alloc_only_string_op(IrOp op) {
    switch (op) {
    case IrOp::STRMAKE:
    case IrOp::STRCAT:
    case IrOp::STRCONV:
    case IrOp::STRFLAT:
    case IrOp::STRINTERN:
    case IrOp::STRRESERVE: return true;
    default: return false;
    }
}

static bool is_side_effecting(IrOp op) {
    switch (op) {
    // llamadas (pueden lanzar excepciones o modificar estado)
    case IrOp::CALL:
    case IrOp::CALLIND:
    case IrOp::CALLVIRT:
    case IrOp::CALLN:
    case IrOp::TAILCALL:
    case IrOp::CALLM:
    case IrOp::CALLITF:
    case IrOp::CALLCLOSURE:
    // para C2 (escape analysis + case-splitting);
    // NUNCA eliminar aunque dst sea IR_NO_VALUE.  Sin efecto en codegen
    // (emitter los trata como no-op), pero deben sobrevivir DCE.
    case IrOp::MAKE_CLOSURE:
    case IrOp::MAKE_VARIANT:
    case IrOp::MATCH_VARIANT:
    case IrOp::SWITCH_DENSE:
    // control de flujo
    case IrOp::BR:
    case IrOp::BR_COND:
    case IrOp::RET:
    case IrOp::UNREACHABLE:
    // excepciones
    case IrOp::THROW:
    case IrOp::TRYENTER:
    case IrOp::TRYLEAVE:
    case IrOp::LANDINGPAD:
    // async / distribucion
    // BugFix audit B-future: FUTURE aloca una NUEVA entry en
    // vm.shared_futures cada vez.  Sin marcarlo side-effecting,
    // CSE deduplica multiples `future` ops creyendo que producen
    // el mismo valor, lo que rompe @Async chain (todos los awaits
    // se quedan esperando el MISMO future fulfilled una sola vez).
    case IrOp::FUTURE:
    case IrOp::AWAIT:
    case IrOp::FULFILL:
    case IrOp::REJECT:
    case IrOp::MSGSEND:
    case IrOp::MSGRECV:
    case IrOp::RSPAWN:
    // monitores
    case IrOp::MONENTER:
    case IrOp::MONEXIT:
    case IrOp::MONWAIT:
    case IrOp::MONNOTI:
    case IrOp::MONNOTA:
    // memoria
    case IrOp::STORE:
    case IrOp::MEMCPY:
    case IrOp::MEMSET:
    case IrOp::VEC_UNOP:
    case IrOp::VEC_BINOP:
    case IrOp::VEC_FMA:
    case IrOp::VEC_ACC_ZERO:
    case IrOp::VEC_ACC_ADD:
    case IrOp::VEC_ACC_FMA:
    case IrOp::VEC_ACC_STORE:
    case IrOp::VEC_ACC_COMBINE:
    case IrOp::VEC_FMA_S:
    case IrOp::VEC_BINOP_S:
    case IrOp::VEC_BCAST:
    case IrOp::SETFIELD:
    // OOP con efectos
    case IrOp::NEWOBJ:
    case IrOp::NEWOBJS:
    case IrOp::CHECKCAST:
    case IrOp::UNWRAP:
    case IrOp::SPECIALIZE:
    // GC_ALLOC: consume memoria del heap GC + puede disparar minor/major
    // GC + el payload puede ser referenciado posteriormente.  Tratarlo
    // como CALL evita que el DCE elimine el alloc cuando el dst es
    // temporariamente parecido a "no usado" en algun analisis local.
    case IrOp::GC_ALLOC:
    // arrays con efectos
    case IrOp::ARRAY_ALLOC:
    case IrOp::ARRAY_STORE:
    case IrOp::GCWB_IR:
    case IrOp::GCDEREF_IR:
    // raw_alloc/raw_free: cada alloc devuelve un host_ptr UNICO; no
    // se pueden deduplicar.  raw_free libera memoria (side-effect).
    case IrOp::RAW_ALLOC:
    case IrOp::RAW_FREE:
    // cadenas con efectos (alloc o mutacion)
    case IrOp::STRMAKE:
    case IrOp::STRCAT:
    case IrOp::STRCONV:
    case IrOp::STRFLAT:
    case IrOp::STRINTERN:
    case IrOp::STRRESERVE:
    case IrOp::STRFINALIZE:
    // scheduler / proceso
    case IrOp::SPAWN:
    case IrOp::RESUME:
    case IrOp::YIELD:
    case IrOp::SWAPCTX:
    case IrOp::SPAWN_ARGS:
    case IrOp::SPAWN_ON:
    case IrOp::HLT:
    case IrOp::PANIC:
    // asignacion
    case IrOp::ALLOCA:
    // recuperados   lecturas/escrituras que consultan estado
    // global del runtime y NO pueden reordenarse contra los STOREs
    // que arman sus structs de parametros.  Tratarlos como llamadas.
    case IrOp::MVTAKE_IR:
    case IrOp::GC_SET_FINALIZER: // muta el GcHeader (bit finalizer);
                                 // side-effect
    case IrOp::GC_COLLECT:       // dispara GC + finalizadores; side-effect
    case IrOp::GC_ALLOCP:
    case IrOp::GC_PROMOTE:
    case IrOp::GC_DEMOTE:
    case IrOp::GC_HANDLE_FOR_PTR:
    // GC_DEREF_HOST: handle -> host_ptr.  Conservative: marked side-effecting
    // porque el host_ptr puede cambiar tras un major_gc (moving GC) y CSE
    // erroneamente fusionaria dos derefs separados por un CALL.  Cuando
    // llegue  D.8 con CSE block-aware con clobber model, se puede
    // relajar a "pure within block until next CALL/alloc".
    case IrOp::GC_DEREF_HOST:
    case IrOp::ATOMIC_LD:
    case IrOp::ATOMIC_ST:
    case IrOp::ATOMIC_CAS:
    case IrOp::ATOMIC_ADD:
    case IrOp::GETSTATIC:
    case IrOp::SETSTATIC:
    case IrOp::FINDCLASS:
    case IrOp::DEFCLASS:
    case IrOp::DEFFIELD:
    case IrOp::DEFMETHOD:
    case IrOp::ADDADVICE:
    case IrOp::FINDMETHOD:
    case IrOp::FINDFIELD:
    case IrOp::SETMETHDBG:
    case IrOp::CALLSUPER:
    case IrOp::PROCEED:
    case IrOp::FULFILL_HLT:
    case IrOp::STRGETBYTES:
    // Sprint edge-bugs (2026-06-02): ops que pueden lanzar FatalError
    // capturable o disparar AV recovery.  DCE no debe eliminarlas aunque
    // su dst quede no-usado: el side-effect (fault) es observable.  La
    // penalizacion en perf es modesta porque mem-CSE/constant-fold ya
    // simplifican casos seguros (e.g. DIV por constante != 0 se folde).
    case IrOp::LOAD:
    case IrOp::DIV:
    case IrOp::MOD:
    case IrOp::FDIV:
    // raw_asm-elim wave 3: nuevos ops con efecto observable.
    case IrOp::RETHROW:     // relanza excepcion (side-effect explicito)
    case IrOp::SHARED_STAT: // op=2 (gc_collect) dispara STW + sweep
    case IrOp::READ_VM_REG: // lee reg arbitrario; el optimizer no debe asumir
    // purity
    case IrOp::RSPAWN_RETURN: // mov r0 + hlt fusionado, terminator
    // raw_asm-elim wave 2: cleanup deterministico de smart pointers.
    case IrOp::SMARTPTR_FREE: // invoca deleter (free/CALLN/CALLVM); side-effect
    // raw_asm-elim wave 2: reflexion queries (escriben a R0, consultan estado).
    case IrOp::REFLECT_COUNT:
    case IrOp::REFLECT_AT:
    // raw_asm-elim wave 2: FFI runtime ops (cargan/descargan DLLs,
    // side-effects).
    case IrOp::MOD_LOAD: // loadmod ejecuta main del plugin (call site)
    case IrOp::DLOPEN:   // LoadLibrary/dlopen (side-effect en OS)
    case IrOp::DLSYM:    // GetProcAddress/dlsym (lookup en DLL state)
    case IrOp::GETPID:
    case IrOp::GETARGC:
    case IrOp::GETARG:
    // ensamblador incrustado (nunca eliminar; semantica opaca)
    case IrOp::RAW_ASM:
    // asm opaco liftado: efecto conocido por la DB, pero conservador aqui
    // (nunca eliminar).  Los eff bits permitiran DCE de las puras muertas.
    case IrOp::ASM_MICRO: return true;
    default: return false;
    }
}

/** @brief Devuelve true si la instruccion es un terminador de bloque. */
static bool is_terminator(IrOp op) {
    return op == IrOp::BR || op == IrOp::BR_COND || op == IrOp::RET ||
           op == IrOp::UNREACHABLE || op == IrOp::THROW ||
           op == IrOp::RETHROW || op == IrOp::RSPAWN_RETURN ||
           op == IrOp::FULFILL_HLT;
}

/** @brief Devuelve true si la instruccion es pura (apta para DCE y CSE). */
static bool is_pure(IrOp op) {
    return !is_side_effecting(op);
}

/**
 * @brief Sprint mem-perf string_hot (2026-06-02): ops "alloc-pure"
 * hoistables por LICM.
 *
 * Algunas operaciones de strings (STRMAKE, STRCAT, STRINTERN, STRCONV,
 * STRRESERVE) son side-effecting (alocan en GcHeap) PERO su semantica
 * solo depende del CONTENIDO de los operandos.  Es decir, dos invocaciones
 * con los mismos operandos producen StringObjects con identical bytes;
 * solo difieren en el handle (GcHandle es opaco al programador y los
 * builtins de string tipo STRLEN/STRCMP/STRRAW/STRGETBYTES operan sobre
 * bytes, no comparan handles).
 *
 * Por tanto LICM puede hoistar estas ops cuando sus operandos son
 * loop-invariant.  Beneficio masivo en patrones como
 *
 *   while (i < N) {
 *       string s = base + suffix;     // STRCAT con bases invariant
 *       if (str_equals(s, "lit")) {   // STRMAKE "lit" invariant
 *           ...
 *       }
 *   }
 *
 * donde la version sin hoist hace N allocs de ROPEs identicos; con hoist
 * 1 sola alloc.  El bench string_hot pasa de 393 ms a sub-100 ms en interp.
 *
 * NO incluye STRCMP/STRLEN/STRRAW/STRGETBYTES/STRHASH (esos NO alocan;
 * ya son @c is_pure y LICM los toma).  NO incluye STRFLAT/STRFINALIZE
 * (mutan estructuras compartidas).
 */
static bool is_licm_hoistable_alloc(IrOp op) {
    switch (op) {
    // STRCAT/STRINTERN/STRCONV/STRFLAT operan SOBRE HANDLES (GcHandles),
    // no leen memoria mutable; alocacion idempotente con resultado
    // content-equal por args.  Safe para hoist.
    case IrOp::STRCAT:
    case IrOp::STRINTERN:
    case IrOp::STRCONV:
    case IrOp::STRRESERVE: return true;
    // STRMAKE requiere chequeo extra (ver @c strmake_reads_immutable).
    case IrOp::STRMAKE: return true;
    default: return false;
    }
}

/**
 * @brief Verifica si el vm_addr operand de un STRMAKE viene de
 * memoria INMUTABLE (STR_LIT_ADDR -> static_data).
 *
 * Sprint string-perf-2 bug fix (2026-06-02): LICM solo puede hoistar
 * STRMAKE si el operand vm_addr apunta a memoria que NO muta dentro
 * del loop.  STR_LIT_ADDR retorna un offset al static_data del modulo
 * (read-only por convencion).  Cualquier otro origen (ALLOCA, malloc,
 * field load, etc.) puede ser mutable.
 *
 * Tracing simple: busca el IrOp que produce @p vm_addr.  Si es
 * STR_LIT_ADDR, safe.  Si es ADD entre STR_LIT_ADDR y CONST (offset
 * dentro del bloque literal), tambien safe.  Otros casos -> unsafe.
 */
static bool strmake_reads_immutable(const IrFunction &fn, IrValueId vm_addr) {
    if (vm_addr == IR_NO_VALUE || vm_addr >= fn.values.size()) return false;
    // Buscar el IrOp que define vm_addr.
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.dst != vm_addr) continue;
            switch (ins.op) {
            case IrOp::STR_LIT_ADDR: return true;
            case IrOp::ADD:
            case IrOp::SUB: {
                // ADD/SUB de STR_LIT_ADDR + const -> tambien immutable.
                if (ins.operands.size() != 2) return false;
                // Recurse en operand[0] (asumiendo que es la base ptr).
                if (strmake_reads_immutable(fn, ins.operands[0])) {
                    // operand[1] debe ser CONST (offset literal).
                    IrValueId off = ins.operands[1];
                    if (off < fn.values.size() && fn.values[off].is_const) {
                        return true;
                    }
                }
                return false;
            }
            case IrOp::BITCAST:
            case IrOp::MOV:
                if (ins.operands.size() == 1) {
                    return strmake_reads_immutable(fn, ins.operands[0]);
                }
                return false;
            default: return false;
            }
        }
    }
    return false;
}

// =========================================================================
//  Pase DCE (Dead Code Elimination)
// =========================================================================

// =========================================================================
//  Pase Dead Alloc Elimination
// =========================================================================
//
// Elimina CALLs a funciones synthetic @c __new_<X> (helpers de allocacion
// emitidos por el frontend Vesta para @c new ClassName()) cuyo resultado
// nunca se usa.  Estos calls solo hacen @c newobj + @c gcderef + @c mov
// internos y no tienen otros efectos secundarios observables salvo
// presion GC -- que es aceptable eliminar para casos no referenciados.
//
// Patron tipico:
//   pruebas() { Calculadora a = new Calculadora(); return 0; }
//   IR:
//     %0 = call.ptr @__new_Calculadora()
//     %1 = const.i64 0
//     %2 = trunc.i32 %1
//     ret.i32 %2
// %0 nunca se usa.  La call a @c __new_Calculadora se puede eliminar.
//
// Tambien aplica a calls a @c vrt_newobj y otros allocators puros.

/** @brief True si el nombre identifica un allocator puro (sin efectos
 *  observables salvo presion GC). */
static bool is_pure_allocator_name(const std::string &name) {
    /* Allocs SHARED (@c __new_<X>_shared) NO son puros: registran el objeto en
     * la @c SharedHandleTable, un efecto OBSERVABLE via @c
     * shared_heap_live_count(). Eliminar un @c new shared X() no usado
     * cambiaria el conteo de objetos shared vivos (regresion del bug de
     * 167_z_gc_sweep: con DCE, crear 6 shared sin usar 4 dejaba before=2 en vez
     * de 6).  Debe ir ANTES del check __new_. */
    if (name.size() >= 7 && name.compare(name.size() - 7, 7, "_shared") == 0)
        return false;
    /* Y `__new_<Clase>` TAMPOCO es puro, aunque el frontend lo emita para cada
     * `new X()`: dentro corre el CONSTRUCTOR, que puede hacer cualquier cosa --
     * llevar una cuenta, escribir, abrir un fichero --.  Aqui se daba por hecho
     * que lo unico observable era el puntero, y con eso un `new X()` cuyo
     * resultado no se usa se borraba CON su constructor dentro.
     *
     * Ya habia mordido una vez: la excepcion de `_shared` de arriba se anadio
     * por eso mismo, pero tapando el caso concreto en vez del supuesto.  Salio
     * otra vez al quitar los huecos de pila muertos: al quedarse el objeto sin
     * usuarios, esta regla se llevaba por delante un constructor que contaba
     * cuantos se creaban (`165_unique_dtor`).
     *
     * Para volver a quitarlos hace falta PREGUNTAR si ese constructor escribe
     * fuera del objeto, y eso lo sabe el analisis de efectos
     * (@c MemEffect::Kind::Global), que hoy no llega hasta aqui. */
    (void)0;
    /* Runtime entries de alloc puros. */
    if (name == "vrt_newobj") return true;
    if (name == "vrt_newobj_handle") return true;
    if (name == "vrt_register_alloc") return true;
    return false;
}

bool ir_pass_dead_alloc_elim(IrFunction &fn) {
    /* Pasada 1: encontrar valores usados (mismo que DCE). */
    std::unordered_set<IrValueId> used;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            for (IrValueId op : ins.operands) {
                if (op != IR_NO_VALUE) used.insert(op);
            }
            if ((ins.op == IrOp::CALLIND || ins.op == IrOp::CALLCLOSURE) &&
                ins.func_ptr != IR_NO_VALUE) {
                used.insert(ins.func_ptr);
            }
            for (const auto &pa : ins.phi_args) {
                if (pa.value != IR_NO_VALUE) used.insert(pa.value);
            }
        }
    }

    /* Pasada 2: eliminar CALLs a allocators puros cuyo dst no se usa. */
    bool changed = false;
    for (auto &bb : fn.blocks) {
        auto &instrs = bb.instrs;
        size_t write = 0;
        for (size_t i = 0; i < instrs.size(); ++i) {
            const IrInstr &ins = instrs[i];
            bool keep = true;
            if (ins.op == IrOp::CALL && ins.dst != IR_NO_VALUE &&
                !used.count(ins.dst) && !ins.preserve &&
                is_pure_allocator_name(ins.func_name)) {
                /* CALL a allocator puro, resultado no usado -> eliminar.
                 * El frontend Vesta no espera efectos secundarios visibles
                 * de @c new X() salvo el handle/host_ptr (que se descarta). */
                keep = false;
                changed = true;
            }
            if (keep) {
                if (write != i) instrs[write] = std::move(instrs[i]);
                ++write;
            }
        }
        instrs.resize(write);
    }
    return changed;
}

bool ir_pass_dead_stack_slot_elim(IrFunction &fn) {
    /* Huecos de pila que nadie LEE: se van, y con ellos lo que se escribia
     * dentro.
     *
     * Lo destapo comparar un bucle con C++.  Al promover una reserva del monton
     * a la pila, el valor se queda en un hueco y su direccion en otro; si
     * despues nadie los lee -- porque la lectura ya se resolvio en el sitio --,
     * lo unico que queda son dos escrituras que no las ve nadie.  C++ las borra
     * y aqui se quedaban: once instrucciones por vuelta donde el hacia cuatro.
     *
     * Lo que las mantenia vivas era la LIBERACION.  Al promover se conserva a
     * proposito -- sin ella un hueco dentro de un bucle acumulaba punteros sin
     * soltar en el interprete --, los backends la quitan porque soltar pila no
     * es nada, pero en el IR sigue contando como usar el hueco.  Asi que aqui
     * NO cuenta: soltar un hueco de pila no es leerlo.
     *
     * Tampoco cuenta escribir DENTRO de el.  Si cuenta guardar su DIRECCION en
     * otro sitio, pero solo si ese otro sitio esta vivo -- y de ahi el punto
     * fijo: al morir un hueco, el de al lado puede quedarse sin lectores. */
    const size_t NV = fn.values.size();
    std::vector<bool> es_hueco(NV, false);
    std::vector<bool> vivo(NV, false);
    bool hay = false;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::ALLOCA && ins.dst != IR_NO_VALUE &&
                ins.dst < NV && !ins.preserve) {
                es_hueco[ins.dst] = true;
                hay = true;
            }
        }
    }
    if (!hay) return false;

    // Guardar la direccion de un hueco DENTRO de otro: si el de fuera vive, el
    // de dentro tambien.
    std::vector<std::vector<IrValueId>> arrastra(NV);
    std::vector<IrValueId> pendientes;
    const auto marcar = [&](IrValueId v) {
        if (v != IR_NO_VALUE && v < NV && es_hueco[v] && !vivo[v]) {
            vivo[v] = true;
            pendientes.push_back(v);
        }
    };

    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            const bool es_store = (ins.op == IrOp::STORE);
            const bool es_free = (ins.op == IrOp::RAW_FREE);
            for (size_t k = 0; k < ins.operands.size(); ++k) {
                const IrValueId v = ins.operands[k];
                if (v == IR_NO_VALUE || v >= NV || !es_hueco[v]) continue;
                // Escribir DENTRO (`store val, hueco`) no es leerlo.
                if (es_store && k == 1) continue;
                // Soltarlo tampoco: es pila.
                if (es_free && k == 0) continue;
                // Guardar su direccion en otro hueco: depende de aquel.
                if (es_store && k == 0 && ins.operands.size() >= 2) {
                    const IrValueId dest = ins.operands[1];
                    if (dest != IR_NO_VALUE && dest < NV && es_hueco[dest]) {
                        arrastra[dest].push_back(v);
                        continue;
                    }
                }
                marcar(v);
            }
            for (const auto &pa : ins.phi_args)
                marcar(pa.value);
            marcar(ins.func_ptr);
        }
    }
    // Punto fijo: lo que arrastra un hueco vivo, vive.
    while (!pendientes.empty()) {
        const IrValueId v = pendientes.back();
        pendientes.pop_back();
        for (const IrValueId d : arrastra[v])
            marcar(d);
    }

    const auto muerto = [&](IrValueId v) {
        return v != IR_NO_VALUE && v < NV && es_hueco[v] && !vivo[v];
    };
    bool changed = false;
    for (auto &bb : fn.blocks) {
        auto &is = bb.instrs;
        const size_t antes = is.size();
        is.erase(std::remove_if(
                     is.begin(), is.end(),
                     [&](const IrInstr &i) {
                         if (i.op == IrOp::ALLOCA) return muerto(i.dst);
                         // Escribir en un hueco muerto, y soltarlo.
                         if (i.op == IrOp::STORE && i.operands.size() >= 2)
                             return muerto(i.operands[1]);
                         if (i.op == IrOp::RAW_FREE && !i.operands.empty())
                             return muerto(i.operands[0]);
                         return false;
                     }),
                 is.end());
        if (is.size() != antes) changed = true;
    }
    return changed;
}

// =========================================================================
//  Pase ir_pass_promote_callned_allocas
//
//   D.jit-mem-model AUTO-PROMOTE: detecta `&local` (ALLOCAs) que
//  fluyen a CALLN (funciones nativas).  Esos ALLOCAs SE PROMUEVEN a host
//  stack via marca `is_host_ptr=true` en el dst del ALLOCA.  El JIT
//  selector consulta esa marca y emite host stack en lugar de VM-stack.
//
//  Sin esta promocion, &local seria una VM-addr que la funcion nativa
//  trataria como host_ptr -> garbage/crash.  Con la promocion, &local
//  es un host_ptr genuino dereferenciable directamente por code C.
//
//  Permite escribir codigo natural C-style:
//
//      u8[1024] buf;
//      ReadFile(handle, &buf[0], 1024, &bytes_read, null);
//
//  El frontend NO necesita anotaciones del usuario (@host etc).  El
//  analisis es backward-flow desde args PTR de cada CALLN.
//
//  Algoritmo:
//    1. Forward seed: por cada CALLN, marca todos sus operands como
//       "reaches_calln".
//    2. Backward fix-point: si dst ya marcado, propagar a operands a
//       traves de ADD/SUB/BITCAST/MOV/CAST/SEXT/ZEXT/TRUNC/PHI/LOAD.
//    3. Final: ALLOCAs cuyo dst esta marcado -> set is_host_ptr=true.
//       Tambien propagar is_host_ptr forward por la cadena de uses para
//       que LOAD/STORE de pointers derivados emita native mov.
// =========================================================================

bool ir_pass_promote_callned_allocas(IrFunction &fn) {
    if (fn.is_native) return false;
    if (fn.values.empty()) return false;

    /* Step 1: detectar valores que llegan a args de CALLN. */
    std::vector<bool> reaches_calln(fn.values.size(), false);
    bool found_any_calln = false;
    for (const auto &blk : fn.blocks) {
        for (const auto &ins : blk.instrs) {
            if (ins.op == IrOp::CALLN) {
                found_any_calln = true;
                for (auto opv : ins.operands) {
                    if (opv != IR_NO_VALUE && opv < reaches_calln.size()) {
                        reaches_calln[opv] = true;
                    }
                }
            }
        }
    }
    if (!found_any_calln) return false;

    /* Step 2: backward fix-point a traves de ops ptr-arithmetic. */
    bool changed_bp = true;
    int max_iter = 16;
    while (changed_bp && max_iter-- > 0) {
        changed_bp = false;
        for (const auto &blk : fn.blocks) {
            for (const auto &ins : blk.instrs) {
                if (ins.dst == IR_NO_VALUE) continue;
                if (ins.dst >= reaches_calln.size()) continue;
                if (!reaches_calln[ins.dst]) continue;
                /* Propagar a operands segun op. */
                switch (ins.op) {
                case IrOp::ADD:
                case IrOp::SUB:
                case IrOp::BITCAST:
                case IrOp::MOV:
                case IrOp::CAST:
                case IrOp::SEXT:
                case IrOp::ZEXT:
                case IrOp::TRUNC:
                case IrOp::LOAD:
                    for (auto opv : ins.operands) {
                        if (opv != IR_NO_VALUE && opv < reaches_calln.size() &&
                            !reaches_calln[opv]) {
                            reaches_calln[opv] = true;
                            changed_bp = true;
                        }
                    }
                    break;
                case IrOp::PHI:
                    for (const auto &pa : ins.phi_args) {
                        if (pa.value != IR_NO_VALUE &&
                            pa.value < reaches_calln.size() &&
                            !reaches_calln[pa.value]) {
                            reaches_calln[pa.value] = true;
                            changed_bp = true;
                        }
                    }
                    break;
                default: break;
                }
            }
        }
    }

    /* Step 3: marcar ALLOCAs cuyo dst alcanza CALLN con
     * `host_alloca=true` y recolectar sus dsts para insertar
     * `RAW_FREE` antes de cada RET de la funcion.  El interp YA respeta
     * `host_alloca` en su bytecode emit: emite `alloc N` (RAW_ALLOC
     * bytecode) en lugar de `subsp`, y el `free` correspondiente lo
     * provee el RAW_FREE insertado aqui. */
    bool changed = false;
    std::vector<IrValueId> promoted_dsts;
    for (auto &blk : fn.blocks) {
        for (auto &ins : blk.instrs) {
            if (ins.op == IrOp::ALLOCA && ins.dst != IR_NO_VALUE &&
                ins.dst < reaches_calln.size() && reaches_calln[ins.dst] &&
                !ins.host_alloca) {
                ins.host_alloca = true;
                promoted_dsts.push_back(ins.dst);
                changed = true;
            }
        }
    }

    /* Step 4 (post-leak-fix 2026-06-01): el cleanup en exit-points
     * ahora lo hace el runtime via `htrack` + cleanup automatico al
     * destruir el frame.  El bytecode emit del case ALLOCA emite
     * `htrack r_dst` tras el `alloc`; el frame guarda los ptrs en una
     * lista lazy y los libera en RET / do_throw / TAILCALL.
     *
     * Ventajas vs la version anterior (RAW_FREE inserted en IR):
     *   - Cubre THROW cross-frame correctamente (do_throw libera al
     *     pop frames durante unwind).
     *   - Cubre todos los exit paths sin enumerar IR ops (los exits
     *     del runtime son responsables del cleanup).
     *   - Sin transformaciones IR extra: el IR queda mas limpio. */

    /* Step 5: propagar is_host_ptr=true forward por las ops derivadas
     * (ADD/SUB/BITCAST/MOV/CAST/*EXT/TRUNC/PHI) desde el dst de cada
     * ALLOCA promovida.  Necesario para que LOAD/STORE downstream
     * emitan `movh` (host mem) en lugar de `mov` (vm mem).
     *
     * Ahora que el interp tambien respeta `host_alloca` y emite `alloc
     * N` (RAW_ALLOC bytecode) en lugar de `subsp` VM-stack, el ptr ES
     * host genuino: propagar es seguro y correcto tanto para interp
     * como para JIT. */
    if (!promoted_dsts.empty()) {
        /* Seed: marcar los dsts promovidos. */
        for (auto vid : promoted_dsts) {
            if (vid < fn.values.size()) {
                fn.values[vid].is_host_ptr = true;
            }
        }
        /* Fix-point forward propagation. */
        bool prop_changed = true;
        while (prop_changed) {
            prop_changed = false;
            for (auto &blk : fn.blocks) {
                for (auto &ins : blk.instrs) {
                    if (ins.dst == IR_NO_VALUE || ins.dst >= fn.values.size())
                        continue;
                    auto &dst_v = fn.values[ins.dst];
                    if (dst_v.is_host_ptr) continue;
                    bool any_host = false;
                    auto check = [&](IrValueId v) {
                        if (v == IR_NO_VALUE || v >= fn.values.size()) return;
                        if (fn.values[v].is_host_ptr) any_host = true;
                    };
                    switch (ins.op) {
                    case IrOp::ADD:
                    case IrOp::SUB:
                    case IrOp::BITCAST:
                    case IrOp::MOV:
                    case IrOp::CAST:
                    case IrOp::SEXT:
                    case IrOp::ZEXT:
                    case IrOp::TRUNC:
                        for (auto v : ins.operands)
                            check(v);
                        break;
                    case IrOp::PHI:
                        for (auto &pa : ins.phi_args)
                            check(pa.value);
                        break;
                    default: break;
                    }
                    if (any_host) {
                        dst_v.is_host_ptr = true;
                        prop_changed = true;
                    }
                }
            }
        }
    }

    return changed;
}

//==============================================================================
//  Sprint string-perf-8 (2026-06-02): ir_pass_promote_local_allocas
//
//  Promueve ALLOCAs LOCALES (no escapan al interp, no se pasan a CALL*,
//  no se almacenan en memoria heap) a `host_alloca=true`.  Esto permite
//  que el JIT emita `sub rsp, N` en host stack y los LOAD/STORE
//  derivados usen `mov [rbp+offset]` nativo (1 instr) en lugar del
//  inline page cache hit + fallback runtime call (~10 instr).
//
//  Caso tipico: struct value-type local (e.g. `Vec3 v = {1,2,3};` con
//  field access en hot loop).  bench_struct_field paga ~10 instrs por
//  cada `v.x` o `v.x = ...`; tras la promocion, 1 instr.
//
//  Algoritmo:
//    1. Recolectar ALLOCAs candidatas (no `host_alloca` ya, dst valido).
//    2. Por cada candidate, calcular el set transitivo `derived` via
//       forward-flow desde su dst a traves de ADD/SUB/BITCAST/MOV/etc.
//    3. Por cada uso del candidate o sus derivados, clasificar:
//       - SAFE: LOAD/STORE addr/ADD/SUB/CMP/BITCAST/MOV/CAST/etc.
//       - UNSAFE: CALL*/RET/THROW/TAILCALL si operand esta en derived;
//         STORE val (no addr) en derived implica escape.
//    4. Si TODOS los usos son SAFE, set host_alloca=true.
//
//  Diferencias con `ir_pass_promote_callned_allocas`:
//    - Aquel promueve para CALLN nativos (host_ptr REQUERIDO para
//      pasarlo a la fn nativa).  Este promueve por OPORTUNIDAD (host
//      stack es mas rapido que VM stack en JIT).
//    - Aquel marca ALLOCAs que ALCANZAN un CALLN.  Este marca ALLOCAs
//      que NO escapan a ningun sitio.
//==============================================================================

bool ir_pass_promote_local_allocas(IrFunction &fn, bool force_all) {
    if (fn.is_native) return false;
    if (fn.values.empty()) return false;

    /* Step 1: identificar ALLOCAs candidatas (no host_alloca ya). */
    std::vector<IrValueId> candidates;
    candidates.reserve(8);
    for (const auto &blk : fn.blocks) {
        for (const auto &ins : blk.instrs) {
            if (ins.op == IrOp::ALLOCA && ins.dst != IR_NO_VALUE &&
                !ins.host_alloca) {
                candidates.push_back(ins.dst);
            }
        }
    }
    if (candidates.empty()) return false;

    /* Step 2: forward-flow del conjunto "derivado" desde TODAS las
     * ALLOCAs candidatas.  Mantenemos una map vid -> origen (uno de los
     * candidates) para que el escape de UN candidato no contamine los
     * otros.
     *
     * Simplificacion: usamos un solo set "all_derived" + map dst->src.
     * Si un dst tiene multiple sources (PHI con args de distintos
     * candidates), conservativo: marcamos AMBOS como unsafe. */
    std::vector<int8_t> derived_from(fn.values.size(),
                                     -1); /* -1 = no, >=0 = idx en candidates */
    std::vector<bool> ambiguous(fn.values.size(),
                                false); /* derivado de >1 candidate */

    auto set_derived = [&](IrValueId v, int8_t origin) {
        if (v >= fn.values.size()) return false;
        if (derived_from[v] == -1) {
            derived_from[v] = origin;
            return true;
        }
        if (derived_from[v] != origin) {
            ambiguous[v] = true;
        }
        return false;
    };
    /* Seed: cada candidate es derived from itself. */
    for (size_t i = 0; i < candidates.size(); ++i) {
        set_derived(candidates[i], static_cast<int8_t>(i & 0x7F));
    }

    /* Propagacion forward.  Cota dura 16 iter para convergencia. */
    bool changed = true;
    int it = 16;
    while (changed && it-- > 0) {
        changed = false;
        for (const auto &blk : fn.blocks) {
            for (const auto &ins : blk.instrs) {
                if (ins.dst == IR_NO_VALUE || ins.dst >= fn.values.size())
                    continue;
                if (derived_from[ins.dst] >= 0) continue; /* ya marcado */
                auto from_op = [&](IrValueId v) -> int {
                    if (v == IR_NO_VALUE || v >= fn.values.size()) return -1;
                    return derived_from[v];
                };
                switch (ins.op) {
                case IrOp::ADD:
                case IrOp::SUB:
                case IrOp::BITCAST:
                case IrOp::MOV:
                case IrOp::CAST:
                case IrOp::SEXT:
                case IrOp::ZEXT:
                case IrOp::TRUNC:
                    for (auto opv : ins.operands) {
                        int from = from_op(opv);
                        if (from >= 0) {
                            if (set_derived(ins.dst, static_cast<int8_t>(from)))
                                changed = true;
                            break;
                        }
                    }
                    break;
                case IrOp::PHI:
                    for (const auto &pa : ins.phi_args) {
                        int from = from_op(pa.value);
                        if (from >= 0) {
                            if (set_derived(ins.dst, static_cast<int8_t>(from)))
                                changed = true;
                            break;
                        }
                    }
                    break;
                default: break;
                }
            }
        }
    }

    /* Step 3: clasificar usos.  Para cada candidate, escape=true si
     * cualquier uso del candidate o sus derivados es UNSAFE.
     *
     * UNSAFE ops:
     *   - CALL/CALLVIRT/CALLM/CALLN/CALLIND/CALLCLOSURE: cualquier operand
     *     que sea derived es escape (el callee puede ser interp).
     *   - RET/THROW/TAILCALL: cualquier operand derived es escape.
     *   - STORE: si el VAL (operands[0]) es derived (pero NO el addr en
     *     operands[1]), escapa a memoria fuera del candidato.  Si addr
     *     ES derived, OK (es access local).
     *
     * SAFE ops sobre derived:
     *   - LOAD addr=derived: OK (lee del slot local).
     *   - STORE addr=derived val=non-derived: OK (escribe al slot local).
     *   - ADD/SUB/BITCAST/MOV/CAST/SEXT/ZEXT/TRUNC/PHI: ya tracked.
     *   - CMP: read-only.
     *   - ALLOCA itself: el propio seed.
     */
    /* uint8_t en lugar de bool para evitar std::vector<bool>::reference. */
    std::vector<uint8_t> escapes(candidates.size(), 0u);
    auto mark_escape = [&](IrValueId v) {
        if (v == IR_NO_VALUE || v >= derived_from.size()) return;
        if (derived_from[v] < 0) return;
        if (ambiguous[v]) {
            /* multiple candidates -> escapan TODOS por conservadurismo. */
            for (size_t k = 0; k < escapes.size(); ++k)
                escapes[k] = 1u;
            return;
        }
        int idx = derived_from[v];
        if (idx >= 0 && static_cast<size_t>(idx) < escapes.size()) {
            escapes[idx] = 1u;
        }
    };

    auto is_derived = [&](IrValueId v) -> bool {
        if (v == IR_NO_VALUE || v >= derived_from.size()) return false;
        return derived_from[v] >= 0;
    };

    /* Whitelist de SAFE ops: solo estas pueden tener operands derived
     * sin que el ptr "escape" del alcance JIT-local.  Cualquier OTRA op
     * (RAW_ASM, CALL*, GC_*, FINDCLASS, etc.) se trata como UNSAFE por
     * defecto (los operands derived marcan escape). */
    auto is_safe_op = [](IrOp op) -> bool {
        switch (op) {
        /* ALLOCA: seed.  No escapa por si misma. */
        case IrOp::ALLOCA:
        /* Aritmetica entera: produce nuevo valor, tracked via
         * derived_from. */
        case IrOp::ADD:
        case IrOp::SUB:
        case IrOp::MUL:
        case IrOp::DIV:
        case IrOp::MOD:
        case IrOp::NEG:
        case IrOp::AND:
        case IrOp::OR:
        case IrOp::XOR:
        case IrOp::NOT:
        case IrOp::SHL:
        case IrOp::SHR:
        case IrOp::SAR:
        /* Casts: forward. */
        case IrOp::BITCAST:
        case IrOp::MOV:
        case IrOp::CAST:
        case IrOp::SEXT:
        case IrOp::ZEXT:
        case IrOp::TRUNC:
        /* CMP: read-only. */
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
        /* Control flow: no escapa el ptr. */
        case IrOp::BR:
        case IrOp::BR_COND:
        case IrOp::NOP:
        case IrOp::CONST: return true;
        default: return false;
        }
    };

    for (const auto &blk : fn.blocks) {
        for (const auto &ins : blk.instrs) {
            if (ins.op == IrOp::LOAD) {
                /* LOAD addr=operands[0]: addr derived OK (lee slot).
                 * dst NO se considera derived del candidate (es el
                 * valor cargado de memoria, no el ptr). */
                continue;
            }
            if (ins.op == IrOp::STORE) {
                /* STORE val=operands[0], addr=operands[1].
                 * addr derived -> OK (escribe al slot).
                 * val derived -> ESCAPA (escribe el PTR a memoria). */
                if (ins.operands.size() >= 2 && is_derived(ins.operands[0])) {
                    mark_escape(ins.operands[0]);
                }
                continue;
            }
            if (ins.op == IrOp::PHI) {
                /* PHI: si el dst NO es derived pero phi_args SI lo son,
                 * los args "salen" del dominio local -> escape. */
                if (ins.dst < derived_from.size() &&
                    derived_from[ins.dst] < 0) {
                    for (const auto &pa : ins.phi_args)
                        mark_escape(pa.value);
                }
                continue;
            }
            if (is_safe_op(ins.op)) continue;

            /* UNSAFE op (CALL*, RAW_ASM, GC_*, FINDCLASS, RET, THROW, ...).
             * Cualquier operand derived escapa. */
            for (auto opv : ins.operands)
                mark_escape(opv);
            for (const auto &pa : ins.phi_args)
                mark_escape(pa.value);
        }
    }

    /* Step 4: promover ALLOCAs que NO escapan (o TODAS si force_all: bare
     * AOT no tiene VM stack, asi que incluso las que "escapan" a un CALL
     * deben vivir en la pila nativa -- el host stack ES addressable cross
     * call, a diferencia del modelo VM). */
    bool any_promoted = false;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (!force_all && escapes[i]) continue;
        IrValueId v = candidates[i];
        for (auto &blk : fn.blocks) {
            for (auto &ins : blk.instrs) {
                if (ins.op == IrOp::ALLOCA && ins.dst == v &&
                    !ins.host_alloca) {
                    ins.host_alloca = true;
                    /* NO explicit_free: el JIT libera con leave/ret;
                     * el interp con htrack + frame cleanup. */
                    any_promoted = true;
                    /* Propagar is_host_ptr al dst para que el dataflow
                     * de host_in_jit del JIT lo recoja. */
                    if (v < fn.values.size()) {
                        fn.values[v].is_host_ptr = true;
                    }
                }
            }
        }
    }
    if (!any_promoted) return false;

    /* Step 5: propagar is_host_ptr forward por las cadenas de derived. */
    bool prop = true;
    int p_it = 16;
    while (prop && p_it-- > 0) {
        prop = false;
        for (auto &blk : fn.blocks) {
            for (auto &ins : blk.instrs) {
                if (ins.dst == IR_NO_VALUE || ins.dst >= fn.values.size())
                    continue;
                auto &dv = fn.values[ins.dst];
                if (dv.is_host_ptr) continue;
                bool any_host = false;
                auto chk = [&](IrValueId v) {
                    if (v != IR_NO_VALUE && v < fn.values.size() &&
                        fn.values[v].is_host_ptr)
                        any_host = true;
                };
                switch (ins.op) {
                case IrOp::ADD:
                case IrOp::SUB:
                case IrOp::BITCAST:
                case IrOp::MOV:
                case IrOp::CAST:
                case IrOp::SEXT:
                case IrOp::ZEXT:
                case IrOp::TRUNC:
                    for (auto opv : ins.operands) {
                        chk(opv);
                        if (any_host) break;
                    }
                    break;
                case IrOp::PHI:
                    for (const auto &pa : ins.phi_args) {
                        chk(pa.value);
                        if (any_host) break;
                    }
                    break;
                default: break;
                }
                if (any_host) {
                    dv.is_host_ptr = true;
                    prop = true;
                }
            }
        }
    }
    return true;
}

//==============================================================================
//  Pase ir_pass_promote_local_raw_alloc
//
//  Convierte `malloc(N_const) + ... + free(p)` locales sin escape a un
//  `ALLOCA host_alloca`.  El JIT selector emite `sub rsp, N` (host stack);
//  el RAW_FREE correspondiente se reemplaza por NOP porque el stack se
//  libera automaticamente al exit de la funcion (mov rsp, rbp + pop rbp).
//
//  Beneficio: malloc/free de ~200-500 ns por iter en hot loops -> ~1 ns
//  (sub/add rsp).  Speedup del alloc puro ~100-500x.
//==============================================================================

//==============================================================================
//  Pase ir_pass_propagate_host_ptr (bug host-vs-VM, 2026-07-15)
//
//  Propaga @c is_host_ptr hacia adelante por las cadenas de aritmetica de
//  punteros (ADD/SUB/casts/PHI), para CUALQUIER value ya marcado como host,
//  sin importar quien lo marco.
//
//  Motivacion: @c ir_pass_promote_local_allocas hacia esta propagacion como su
//  Step 5, pero SOLO para las ALLOCAs que el mismo promovia (su Step 1 filtra
//  por `!ins.host_alloca`).  Cuando es el LOWERING quien marca una ALLOCA como
//  host -- caso de los locales address-taken, ver @c lower_var_decl -- ese pase
//  la salta y la propagacion no ocurria: `&p.x` (offset 0) emitia movh pero
//  `&p.y` (offset != 0, un ADD) perdia la naturaleza host y emitia `mov` (VM),
//  de modo que el struct se inicializaba a medias (`p.y` iba a la pila VM y el
//  callee leia 0 en su sitio).
//
//  Es el mismo "patron is_host_ptr en add(ptr,off)" ya visto en otros bugs.
//  Idempotente y conservador: solo añade el flag, nunca lo quita, asi que se
//  puede correr las veces que haga falta.
//==============================================================================

bool ir_pass_propagate_host_ptr(IrFunction &fn) {
    if (fn.is_native) return false;
    if (fn.values.empty()) return false;

    bool any = false;
    bool changed = true;
    int it = 16; // cota dura de convergencia (igual que el resto de pases)
    while (changed && it-- > 0) {
        changed = false;
        for (auto &blk : fn.blocks) {
            for (auto &ins : blk.instrs) {
                if (ins.dst == IR_NO_VALUE || ins.dst >= fn.values.size())
                    continue;
                auto &dv = fn.values[ins.dst];
                if (dv.is_host_ptr) continue; // ya marcado
                bool any_host = false;
                auto chk = [&](IrValueId v) {
                    if (v != IR_NO_VALUE && v < fn.values.size() &&
                        fn.values[v].is_host_ptr)
                        any_host = true;
                };
                switch (ins.op) {
                /* Aritmetica de punteros y casts: el resultado apunta al mismo
                 * espacio de direcciones que el operando base. */
                case IrOp::ADD:
                case IrOp::SUB:
                case IrOp::BITCAST:
                case IrOp::MOV:
                case IrOp::CAST:
                case IrOp::SEXT:
                case IrOp::ZEXT:
                case IrOp::TRUNC:
                    for (auto opv : ins.operands) {
                        chk(opv);
                        if (any_host) break;
                    }
                    break;
                case IrOp::PHI:
                    for (const auto &pa : ins.phi_args) {
                        chk(pa.value);
                        if (any_host) break;
                    }
                    break;
                default: break;
                }
                if (any_host) {
                    dv.is_host_ptr = true;
                    changed = true;
                    any = true;
                }
            }
        }
    }
    return any;
}

bool ir_pass_promote_local_raw_alloc(IrFunction &fn) {
    if (fn.is_native) return false;
    if (fn.values.empty()) return false;

    // 4 KB: cubre boxes de unique<T>/shared<T> y structs locales pequenos,
    // pero EXCLUYE arrays grandes (p.ej. f64[4096]=32KB) que NO deben ir a la
    // pila -- promoverlos desbordaba la pila de la VM (interp) -> SIGSEGV en
    // vec_axpy.  El host stack del AOT/JIT aguanta mas, pero un array grande en
    // pila es mala practica igualmente; los grandes se quedan en heap (malloc).
    constexpr uint64_t MAX_PROMOTE_SIZE = 4096; // bytes

    // Collect RAW_ALLOC candidates (CONST size, size razonable).
    struct AllocSite {
        size_t block_idx;
        size_t ins_idx;
        IrValueId dst;
        uint64_t size_bytes;
    };
    std::vector<AllocSite> candidates;

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto &blk = fn.blocks[bi];
        for (size_t ii = 0; ii < blk.instrs.size(); ++ii) {
            const auto &ins = blk.instrs[ii];
            if (ins.op != IrOp::RAW_ALLOC) continue;
            if (ins.operands.empty()) continue;
            if (ins.dst == IR_NO_VALUE) continue;
            const IrValueId size_vid = ins.operands[0];
            if (size_vid >= fn.values.size()) continue;
            const auto &size_v = fn.values[size_vid];
            if (!size_v.is_const) continue;
            const uint64_t bytes = size_v.const_val;
            if (bytes == 0 || bytes > MAX_PROMOTE_SIZE) continue;
            candidates.push_back({bi, ii, ins.dst, bytes});
        }
    }
    if (candidates.empty()) return false;

    // ---- Stack-first (slot muerto): analisis de SLOTS LOCALES ----
    //
    // El idiom @c unique<T> Tier-1 hace `STORE box_ptr -> slot[+0]` donde
    // `slot` es un ALLOCA local de 16 B.  El escape-check ingenuo marca ese
    // STORE como escape (el ptr "sale" a memoria) y bloquea la promocion a
    // pila, AUN cuando ese slot nunca se vuelve a LEER (el cleanup usa el
    // SSA value del box directamente).  Resultado: `malloc`/`free` que
    // podrian ser puro stack.
    //
    // Regla SOLIDA (sin analisis de offsets, por eso no confunde el box con
    // el campo deleter en slot[+8]): un `STORE box -> A` NO escapa si `A`
    // apunta a un SLOT LOCAL `S` (ALLOCA de esta fn) que es WRITE-ONLY --
    // nunca es el addr de ningun LOAD, y su propia direccion nunca se pasa a
    // CALL*/RET/THROW ni se almacena como valor.  Si S nunca se lee, el ptr
    // guardado jamas se recupera => el box no escapa por ese STORE; sus usos
    // DIRECTOS (deref, free) los cubre el escape-check normal.  Cualquier
    // duda (S se lee, S escapa, A no enraiza en un ALLOCA local) => regla
    // inactiva => comportamiento previo (heap).  Cero riesgo de UAF.
    const size_t NV = fn.values.size();
    std::vector<IrValueId> slot_root(NV, IR_NO_VALUE); // raiz ALLOCA de cada v
    {
        // Semilla: ALLOCA dst -> raiz de si misma.
        for (const auto &blk : fn.blocks)
            for (const auto &ins : blk.instrs)
                if (ins.op == IrOp::ALLOCA && ins.dst != IR_NO_VALUE &&
                    ins.dst < NV)
                    slot_root[ins.dst] = ins.dst;
        // Forward-flow por aritmetica de punteros / casts (cota 32 iter).
        bool prop = true;
        int it2 = 32;
        while (prop && it2-- > 0) {
            prop = false;
            for (const auto &blk : fn.blocks) {
                for (const auto &ins : blk.instrs) {
                    if (ins.dst == IR_NO_VALUE || ins.dst >= NV) continue;
                    if (slot_root[ins.dst] != IR_NO_VALUE) continue;
                    switch (ins.op) {
                    case IrOp::ADD:
                    case IrOp::SUB:
                    case IrOp::BITCAST:
                    case IrOp::MOV:
                    case IrOp::CAST:
                    case IrOp::SEXT:
                    case IrOp::ZEXT:
                    case IrOp::TRUNC:
                        for (auto v : ins.operands) {
                            if (v != IR_NO_VALUE && v < NV &&
                                slot_root[v] != IR_NO_VALUE) {
                                slot_root[ins.dst] = slot_root[v];
                                prop = true;
                                break;
                            }
                        }
                        break;
                    default: break;
                    }
                }
            }
        }
    }
    // slot_loaded[S]=1 si S es la raiz del addr de algun LOAD.
    // slot_escapes[S]=1 si la direccion de S sale del frame (operand de
    // CALL*/RET/THROW/... o STORE-as-val).
    std::vector<uint8_t> slot_loaded(NV, 0u), slot_escapes(NV, 0u);
    {
        auto root_of = [&](IrValueId v) -> IrValueId {
            return (v != IR_NO_VALUE && v < NV) ? slot_root[v] : IR_NO_VALUE;
        };
        for (const auto &blk : fn.blocks) {
            for (const auto &ins : blk.instrs) {
                if (ins.op == IrOp::LOAD && !ins.operands.empty()) {
                    IrValueId s = root_of(ins.operands[0]);
                    if (s != IR_NO_VALUE) slot_loaded[s] = 1u;
                    continue;
                }
                if (ins.op == IrOp::STORE) {
                    // STORE val,addr: si la propia direccion del slot es el
                    // VAL almacenado, ese slot escapa (su ptr sale).  El addr
                    // (operands[1]) NO escapa por escribir en el slot.
                    if (!ins.operands.empty()) {
                        IrValueId sv = root_of(ins.operands[0]);
                        if (sv != IR_NO_VALUE) slot_escapes[sv] = 1u;
                    }
                    continue;
                }
                if (ins.op == IrOp::ALLOCA) continue;
                // Lista-blanca de PRODUCTORES/CONSUMIDORES seguros de la
                // direccion de un slot: aritmetica de punteros + casts (campo
                // addr, ya cubiertos por slot_root-forward), CMP/BR/NOP/CONST
                // (read-only / control).  CUALQUIER otra op (CALL*, RET, THROW,
                // MEMCPY, MVTAKE_IR, ...) que reciba la direccion de un slot
                // como operand puede SACAR/copiar su contenido fuera del frame
                // -> el slot escapa.  Invertir a lista-blanca (vs enumerar
                // consumidores escapantes) evita olvidar ops nuevas como
                // mvtake_ir (el `move` smuggla el box a otro slot).
                bool safe_consumer = false;
                switch (ins.op) {
                case IrOp::ADD:
                case IrOp::SUB:
                case IrOp::BITCAST:
                case IrOp::MOV:
                case IrOp::CAST:
                case IrOp::SEXT:
                case IrOp::ZEXT:
                case IrOp::TRUNC:
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
                case IrOp::BR:
                case IrOp::BR_COND:
                case IrOp::NOP:
                case IrOp::CONST: safe_consumer = true; break;
                default:
                    break; // PHI incluido: slot_root no lo rastrea -> escape
                }
                if (!safe_consumer) {
                    for (auto v : ins.operands) {
                        IrValueId s = root_of(v);
                        if (s != IR_NO_VALUE) slot_escapes[s] = 1u;
                    }
                    if (ins.func_ptr != IR_NO_VALUE) {
                        IrValueId s = root_of(ins.func_ptr);
                        if (s != IR_NO_VALUE) slot_escapes[s] = 1u;
                    }
                    for (const auto &pa : ins.phi_args) {
                        IrValueId s = root_of(pa.value);
                        if (s != IR_NO_VALUE) slot_escapes[s] = 1u;
                    }
                }
            }
        }
    }
    // ---- Slot CARRIER limpio (offset-0): idiom unique<T> + borrow ----
    //
    // El box vive en slot[+0] y los borrows lo RE-LEEN del slot[+0] (el slot SI
    // se lee, asi que la regla "slot muerto" no aplica).  Pero si el slot:
    //   (a) es local + no-escapante,  (b) recibe EXACTAMENTE UN store en
    //   offset 0 (el del box),  (c) TODOS sus loads son offset 0,
    // entonces los valores leidos del slot son alias del MISMO box -> el box
    // sigue siendo frame-local.  El guard offset-0 evita confundir el box con
    // el campo deleter en slot[+8].  Los free de esos aliases se reescriben al
    // dst del ALLOCA en la promocion (para que la NOP-detection de aot_lower /
    // JIT los elide -> nunca free(stack_ptr)).
    //
    // slot_off_zero[v]: v es alias de offset-0 de su slot raiz (ALLOCA o
    // MOV/cast de el; NUNCA un ADD con desplazamiento).
    std::vector<uint8_t> slot_off_zero(NV, 0u);
    {
        for (const auto &blk : fn.blocks)
            for (const auto &ins : blk.instrs)
                if (ins.op == IrOp::ALLOCA && ins.dst != IR_NO_VALUE &&
                    ins.dst < NV)
                    slot_off_zero[ins.dst] = 1u;
        bool prop = true;
        int it3 = 32;
        while (prop && it3-- > 0) {
            prop = false;
            for (const auto &blk : fn.blocks)
                for (const auto &ins : blk.instrs) {
                    if (ins.dst == IR_NO_VALUE || ins.dst >= NV) continue;
                    if (slot_off_zero[ins.dst]) continue;
                    switch (ins.op) {
                    // solo casts/MOV preservan offset 0
                    case IrOp::BITCAST:
                    case IrOp::MOV:
                    case IrOp::CAST:
                        for (auto v : ins.operands)
                            if (v != IR_NO_VALUE && v < NV &&
                                slot_off_zero[v]) {
                                slot_off_zero[ins.dst] = 1u;
                                prop = true;
                                break;
                            }
                        break;
                    default: break;
                    }
                }
        }
    }
    // slot_loads_off0[S]=1 si TODOS los loads que enraizan en S son offset-0.
    // slot_store0_count[S]=numero de STOREs offset-0 que enraizan en S.
    std::vector<uint8_t> slot_loads_off0(NV, 1u);
    std::vector<uint32_t> slot_store0_count(NV, 0u);
    {
        auto root_of = [&](IrValueId v) -> IrValueId {
            return (v != IR_NO_VALUE && v < NV) ? slot_root[v] : IR_NO_VALUE;
        };
        for (const auto &blk : fn.blocks)
            for (const auto &ins : blk.instrs) {
                if (ins.op == IrOp::LOAD && !ins.operands.empty()) {
                    IrValueId a = ins.operands[0], s = root_of(a);
                    if (s != IR_NO_VALUE && !(a < NV && slot_off_zero[a]))
                        slot_loads_off0[s] = 0u;
                } else if (ins.op == IrOp::STORE && ins.operands.size() >= 2) {
                    IrValueId a = ins.operands[1], s = root_of(a);
                    if (s != IR_NO_VALUE && a < NV && slot_off_zero[a])
                        slot_store0_count[s]++;
                }
            }
    }
    auto is_clean_carrier = [&](IrValueId s) -> bool {
        return s != IR_NO_VALUE && s < NV && !slot_escapes[s] &&
               slot_loads_off0[s] && slot_store0_count[s] == 1u;
    };

    // store_to_dead_local_slot(addr): true si `addr` apunta a un slot local
    // WRITE-ONLY no-escapante, O a un carrier limpio offset-0 (el box se
    // recupera como alias trackeado).  En ambos el STORE del box no lo hace
    // escapar.
    auto store_to_dead_local_slot = [&](IrValueId addr) -> bool {
        if (addr == IR_NO_VALUE || addr >= NV) return false;
        IrValueId s = slot_root[addr];
        if (s == IR_NO_VALUE) return false; // no enraiza en ALLOCA local
        if (slot_escapes[s]) return false;  // la direccion del slot escapa
        if (!slot_loaded[s]) return true;   // write-only muerto
        return slot_off_zero[addr] && is_clean_carrier(s); // carrier off-0
    };

    // Para cada candidato, hacer escape analysis:
    //   - forward fix-point: marcar valores derivados del dst.
    //   - rechazar si algun derivado llega a un uso prohibido (RETURN,
    //     STORE a memoria GC, CALL externo distinto del RAW_FREE).
    bool changed = false;
    for (auto &c : candidates) {
        // derivados[v] = true si v puede ser un alias del dst (forward
        // flow desde el RAW_ALLOC dst a traves de ADD/SUB/BITCAST/MOV/
        // CAST/*EXT/TRUNC/PHI).
        std::vector<bool> derivados(fn.values.size(), false);
        derivados[c.dst] = true;
        // box_carrier[S]=1: el slot S guarda ESTE box en offset 0 (carrier
        // limpio) -> sus loads off-0 son alias del box.
        // carrier_alias[v]=1: v es un load off-0 desde un carrier -> su free
        // debe reescribirse al ALLOCA del box (NOP-able por aot_lower/JIT).
        std::vector<uint8_t> box_carrier(NV, 0u), carrier_alias(NV, 0u);
        bool prop = true;
        int iters = 0;
        while (prop && iters++ < 32) {
            prop = false;
            for (const auto &blk : fn.blocks) {
                for (const auto &ins : blk.instrs) {
                    auto check = [&](IrValueId v) -> bool {
                        return v != IR_NO_VALUE && v < derivados.size() &&
                               derivados[v];
                    };
                    // STORE box -> carrier-slot[+0]: registra el carrier.
                    if (ins.op == IrOp::STORE && ins.operands.size() >= 2) {
                        IrValueId val = ins.operands[0], addr = ins.operands[1];
                        if (check(val) && addr < NV && slot_off_zero[addr]) {
                            IrValueId s = slot_root[addr];
                            if (is_clean_carrier(s) && !box_carrier[s]) {
                                box_carrier[s] = 1u;
                                prop = true;
                            }
                        }
                        continue; // STORE no define dst
                    }
                    if (ins.dst == IR_NO_VALUE) continue;
                    if (ins.dst >= derivados.size()) continue;
                    if (derivados[ins.dst]) continue;
                    // LOAD off-0 desde un carrier de este box -> alias del box.
                    if (ins.op == IrOp::LOAD && !ins.operands.empty()) {
                        IrValueId a = ins.operands[0];
                        if (a < NV && slot_off_zero[a]) {
                            IrValueId s = slot_root[a];
                            if (s != IR_NO_VALUE && box_carrier[s]) {
                                derivados[ins.dst] = true;
                                carrier_alias[ins.dst] = 1u;
                                prop = true;
                            }
                        }
                        continue;
                    }
                    bool any_d = false;
                    switch (ins.op) {
                    case IrOp::ADD:
                    case IrOp::SUB:
                    case IrOp::BITCAST:
                    case IrOp::MOV:
                    case IrOp::CAST:
                    case IrOp::SEXT:
                    case IrOp::ZEXT:
                    case IrOp::TRUNC:
                        for (auto v : ins.operands)
                            if (check(v)) {
                                any_d = true;
                                break;
                            }
                        break;
                    case IrOp::PHI:
                        for (auto &pa : ins.phi_args)
                            if (check(pa.value)) {
                                any_d = true;
                                break;
                            }
                        break;
                    default: break;
                    }
                    if (any_d) {
                        derivados[ins.dst] = true;
                        prop = true;
                    }
                }
            }
        }

        // Escape check: contar RAW_FREEs que reciben un derivado, y
        // rechazar si hay usos prohibidos.
        bool escapes = false;
        std::vector<std::pair<size_t, size_t>>
            free_sites; // (block_idx, ins_idx)

        auto is_derived = [&](IrValueId v) -> bool {
            return v != IR_NO_VALUE && v < derivados.size() && derivados[v];
        };

        for (size_t bi = 0; bi < fn.blocks.size() && !escapes; ++bi) {
            const auto &blk = fn.blocks[bi];
            for (size_t ii = 0; ii < blk.instrs.size() && !escapes; ++ii) {
                const auto &ins = blk.instrs[ii];

                switch (ins.op) {
                case IrOp::RET:
                case IrOp::TAILCALL:
                case IrOp::RSPAWN_RETURN:
                case IrOp::FULFILL_HLT:
                    // El ptr llega a return / tailcall / fulfill -> escapa.
                    for (auto v : ins.operands) {
                        if (is_derived(v)) {
                            escapes = true;
                            break;
                        }
                    }
                    break;

                case IrOp::RAW_FREE:
                    // Free directo: marca el site para eliminar
                    // si la promocion procede.  NO marca escape.
                    if (!ins.operands.empty() && is_derived(ins.operands[0])) {
                        free_sites.push_back({bi, ii});
                    }
                    break;

                case IrOp::STORE: {
                    // STORE val, addr.  Si val es derivado y la addr
                    // apunta a memoria GC o globals, ESCAPA.  Si addr
                    // es local (otro ALLOCA / RAW_ALLOC del mismo
                    // scope), tracking conservativo: marcar escape
                    // SOLO si la addr es is_host_ptr=false (= memoria
                    // GC) o si el target es un global.
                    //
                    // MVP conservativo: cualquier STORE de un derivado
                    // a una direccion que NO sea otro derivado del
                    // mismo ALLOCA cuenta como escape.
                    if (ins.operands.size() >= 2) {
                        const IrValueId val_v = ins.operands[0];
                        const IrValueId addr_v = ins.operands[1];
                        if (is_derived(val_v) && !is_derived(addr_v)) {
                            // Stack-first: si el box se guarda en un slot
                            // local muerto (write-only, no-escapante), el
                            // ptr nunca se recupera -> NO escapa por aqui.
                            if (!store_to_dead_local_slot(addr_v)) {
                                escapes = true;
                            }
                        }
                    }
                    break;
                }

                case IrOp::CALL:
                case IrOp::CALLVIRT:
                case IrOp::CALLM:
                case IrOp::CALLITF:
                case IrOp::CALLIND:
                case IrOp::CALLCLOSURE:
                case IrOp::CALLN: {
                    // El ptr pasado a otra fn ESCAPA conservativamente.
                    // Excepcion: si fuera el callee es de tipo "trampoline
                    // pure" (no toca el ptr), seria seguro -- pero no
                    // tenemos esa info aqui.  Conservador: escape.
                    for (auto v : ins.operands) {
                        if (is_derived(v)) {
                            escapes = true;
                            break;
                        }
                    }
                    if (ins.func_ptr != IR_NO_VALUE &&
                        is_derived(ins.func_ptr)) {
                        escapes = true;
                    }
                    break;
                }

                case IrOp::THROW:
                    // El ptr llega a throw -> escapa cross-frame.
                    for (auto v : ins.operands) {
                        if (is_derived(v)) {
                            escapes = true;
                            break;
                        }
                    }
                    break;

                default: break;
                }
            }
        }

        if (escapes) continue;
        if (free_sites.empty()) continue; // sin free -> es leak, no promovemos

        // Promote: convertir RAW_ALLOC en ALLOCA con host_alloca=true.
        // El bytecode emitter ya respeta host_alloca y emite el path
        // de `alloc N + htrack` (que el runtime libera al RET del frame
        // automaticamente).  El JIT selector emite `sub rsp, N` (host
        // stack directo, sin allocator).
        auto &alloc_ins = fn.blocks[c.block_idx].instrs[c.ins_idx];
        alloc_ins.op = IrOp::ALLOCA;
        alloc_ins.imm = c.size_bytes;
        alloc_ins.type = IrType::I8; // ALLOCA convencion: type=I8, imm=N bytes
        alloc_ins.host_alloca = true;
        alloc_ins.operands.clear(); // ALLOCA no toma operands (tamano en imm)

        // Marcar el dst como is_host_ptr para que LOAD/STORE emitan movh.
        if (c.dst < fn.values.size()) {
            fn.values[c.dst].is_host_ptr = true;
        }

        // Carrier: los free de un box recuperado via load(slot) tienen como
        // operando un ALIAS (carrier_alias), no el ALLOCA.  aot_lower / JIT
        // solo elidan el free si el operando viene DIRECTO de un ALLOCA; si
        // no, emitirian free(stack_ptr) -> abort.  Reescribimos el operando
        // del free al dst del ALLOCA (semanticamente el mismo box) para que
        // la NOP-detection existente lo elide uniformemente.
        for (const auto &fs : free_sites) {
            IrInstr &fi = fn.blocks[fs.first].instrs[fs.second];
            if (!fi.operands.empty() && fi.operands[0] < NV &&
                carrier_alias[fi.operands[0]]) {
                fi.operands[0] = c.dst;
            }
        }

        // Sprint mem-loop-fix (2026-06-02): PRESERVAR los RAW_FREE
        // explicitos en lugar de eliminarlos.  Bottleneck encontrado
        // en bench mem_malloc_free: el path original eliminaba RAW_FREE
        // y dependia de `host_alloca_release_all` al RET del frame,
        // pero si el ALLOCA esta DENTRO de un loop (inlineado o no),
        // el vector @c host_allocas del frame acumula N punteros
        // tracked sin liberar -- O(N) memoria + O(N) cleanup al RET.
        //
        // Con el RAW_FREE preservado, el alloc/free emparejan
        // correctamente DENTRO de cada iteracion del loop.  El ALLOCA
        // se marca con @c host_alloca_explicit_free=true para que el
        // bytecode emit del interp SKIPE el `htrack` (porque el free
        // explicito ya libera el ptr en su sitio).
        alloc_ins.host_alloca_explicit_free = true;
        // NO eliminar los RAW_FREE: dejarlos para que el bytecode emit
        // los convierta en `free` opcodes correctamente.

        changed = true;
    }

    // Compactar bloques: eliminar instrucciones NOP introducidas por
    // este pass.  El bytecode emitter de NOP emite `nop1` que NO esta
    // soportado correctamente por el decoder (decode_fn=nullptr).
    // Mas seguro eliminar fisicamente las RAW_FREE convertidas.
    if (changed) {
        for (auto &blk : fn.blocks) {
            auto &is = blk.instrs;
            is.erase(std::remove_if(is.begin(), is.end(),
                                    [](const IrInstr &i) {
                                        return i.op == IrOp::NOP &&
                                               i.operands.empty() &&
                                               i.dst == IR_NO_VALUE;
                                    }),
                     is.end());
        }
    }

    return changed;
}

//==============================================================================
//  Pase ir_pass_promote_closure_env  (AOT / native_poo)
//
//  Promueve el env de una closure de HEAP (GC_ALLOC / RAW_ALLOC) a STACK
//  (ALLOCA) cuando el env NO escapa del frame.  Es closure-aware: relaja el
//  escape-check del pase generico para los 2 patrones seguros propios de una
//  closure (que el generico marca como escape):
//    (1) STORE R, closure_slot[+k]  con closure_slot un ALLOCA LOCAL  -> R
//        fluye a un slot local; se "tinta" ese slot y se siguen sus loads.
//    (2) CALLCLOSURE con R como env (operands[0]) o func_ptr -> uso SiNCRONO.
//  Cualquier OTRO uso de un valor tintado (RET, STORE a no-local, arg de CALL,
//  THROW, op desconocida) -> ESCAPA -> NO se promueve (queda GC_ALLOC, que en
//  bare se rechaza limpio; NUNCA se deja un heap sin liberar -> sin leak, y al
//  ser conservador el peor caso es no-promover, jamas un use-after-free).
//==============================================================================
bool ir_pass_promote_closure_env(IrFunction &fn) {
    if (fn.is_native || fn.values.empty()) return false;

    // value -> instruccion definidora (para resolver bases de direcciones).
    std::vector<const IrInstr *> def_of(fn.values.size(), nullptr);
    for (const auto &b : fn.blocks)
        for (const auto &ins : b.instrs)
            if (ins.dst != IR_NO_VALUE && ins.dst < def_of.size())
                def_of[ins.dst] = &ins;

    auto is_const_v = [&](IrValueId v) -> bool {
        return v != IR_NO_VALUE && v < fn.values.size() &&
               fn.values[v].is_const;
    };
    // Raiz de una direccion: sigue cadenas ADD(base, const) / MOV.
    auto resolve_base = [&](IrValueId v) -> IrValueId {
        for (int g = 0; g < 64 && v != IR_NO_VALUE && v < def_of.size(); ++g) {
            const IrInstr *d = def_of[v];
            if (!d) break;
            if (d->op == IrOp::ADD && d->operands.size() == 2) {
                const IrValueId a = d->operands[0], b = d->operands[1];
                if (is_const_v(a) && !is_const_v(b))
                    v = b;
                else if (is_const_v(b) && !is_const_v(a))
                    v = a;
                else
                    break;
            } else if (d->op == IrOp::MOV && d->operands.size() == 1) {
                v = d->operands[0];
            } else
                break;
        }
        return v;
    };

    // ALLOCAs locales (candidatos a slot tintado).
    std::unordered_set<IrValueId> local_alloca;
    for (const auto &b : fn.blocks)
        for (const auto &ins : b.instrs)
            if (ins.op == IrOp::ALLOCA && ins.dst != IR_NO_VALUE)
                local_alloca.insert(ins.dst);

    bool changed = false;
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        for (size_t ii = 0; ii < fn.blocks[bi].instrs.size(); ++ii) {
            IrInstr &A = fn.blocks[bi].instrs[ii];
            if (A.op != IrOp::GC_ALLOC && A.op != IrOp::RAW_ALLOC) continue;
            if (A.dst == IR_NO_VALUE) continue;
            if (A.operands.empty()) continue;
            const IrValueId size_vid = A.operands[0];
            if (!is_const_v(size_vid)) continue;
            const uint64_t size_bytes = fn.values[size_vid].const_val;
            if (size_bytes == 0 || size_bytes > 65536) continue;

            // Fixpoint: tinta = {R, derivados, loads desde slots tintados};
            // tainted_slots = ALLOCAs locales donde se guarda un valor tintado.
            std::vector<bool> taint(fn.values.size(), false);
            std::unordered_set<IrValueId> tainted_slots;
            taint[A.dst] = true;
            auto is_t = [&](IrValueId v) -> bool {
                return v != IR_NO_VALUE && v < taint.size() && taint[v];
            };
            bool prop = true;
            int iters = 0;
            while (prop && iters++ < 128) {
                prop = false;
                for (const auto &b : fn.blocks) {
                    for (const auto &ins : b.instrs) {
                        // (a) propagar taint a valores derivados / loads.
                        if (ins.dst != IR_NO_VALUE && ins.dst < taint.size() &&
                            !taint[ins.dst]) {
                            bool d = false;
                            switch (ins.op) {
                            case IrOp::ADD:
                            case IrOp::SUB:
                            case IrOp::MOV:
                            case IrOp::CAST:
                            case IrOp::BITCAST:
                            case IrOp::SEXT:
                            case IrOp::ZEXT:
                            case IrOp::TRUNC:
                                for (auto v : ins.operands)
                                    if (is_t(v)) {
                                        d = true;
                                        break;
                                    }
                                break;
                            case IrOp::PHI:
                                for (auto &pa : ins.phi_args)
                                    if (is_t(pa.value)) {
                                        d = true;
                                        break;
                                    }
                                break;
                            case IrOp::LOAD: {
                                const IrValueId addr = ins.operands.empty()
                                                           ? IR_NO_VALUE
                                                           : ins.operands[0];
                                if (is_t(addr))
                                    d = true;
                                else if (tainted_slots.count(
                                             resolve_base(addr)))
                                    d = true;
                                break;
                            }
                            default: break;
                            }
                            if (d) {
                                taint[ins.dst] = true;
                                prop = true;
                            }
                        }
                        // (b) descubrir slots tintados: STORE val-tintado en
                        //     un ALLOCA local -> tintar el slot (loads futuros
                        //     desde el se vuelven tintados).
                        if (ins.op == IrOp::STORE && ins.operands.size() >= 2 &&
                            is_t(ins.operands[0])) {
                            const IrValueId base =
                                resolve_base(ins.operands[1]);
                            if (local_alloca.count(base) &&
                                !tainted_slots.count(base)) {
                                tainted_slots.insert(base);
                                prop = true;
                            }
                        }
                    }
                }
            }

            // Escape check sobre la tinta FINAL.
            bool escapes = false;
            for (const auto &b : fn.blocks) {
                if (escapes) break;
                for (const auto &ins : b.instrs) {
                    if (escapes) break;
                    switch (ins.op) {
                    case IrOp::RET:
                    case IrOp::TAILCALL:
                    case IrOp::THROW:
                    case IrOp::RSPAWN_RETURN:
                    case IrOp::FULFILL_HLT:
                        for (auto v : ins.operands)
                            if (is_t(v)) {
                                escapes = true;
                                break;
                            }
                        break;
                    case IrOp::STORE:
                        // val tintado: seguro solo si addr base es ALLOCA local
                        // (ya tintado en el fixpoint); si no -> escapa.
                        if (ins.operands.size() >= 2 && is_t(ins.operands[0])) {
                            const IrValueId base =
                                resolve_base(ins.operands[1]);
                            if (!local_alloca.count(base)) escapes = true;
                        }
                        // val NO tintado pero addr tintada = escribir EN R
                        // (capture store) -> seguro, no hacemos nada.
                        break;
                    case IrOp::CALLCLOSURE:
                        // operands[0]=env (sincrono, seguro), func_ptr seguro;
                        // operands[1..]=args: si tintado -> podria guardarse.
                        for (size_t k = 1; k < ins.operands.size(); ++k)
                            if (is_t(ins.operands[k])) {
                                escapes = true;
                                break;
                            }
                        break;
                    case IrOp::CALL:
                    case IrOp::CALLVIRT:
                    case IrOp::CALLM:
                    case IrOp::CALLITF:
                    case IrOp::CALLIND:
                    case IrOp::CALLN:
                    case IrOp::CALLSUPER:
                        for (auto v : ins.operands)
                            if (is_t(v)) {
                                escapes = true;
                                break;
                            }
                        if (is_t(ins.func_ptr)) escapes = true;
                        break;
                    case IrOp::LOAD:
                    case IrOp::ADD:
                    case IrOp::SUB:
                    case IrOp::MOV:
                    case IrOp::CAST:
                    case IrOp::BITCAST:
                    case IrOp::SEXT:
                    case IrOp::ZEXT:
                    case IrOp::TRUNC:
                    case IrOp::PHI:
                    case IrOp::GC_ALLOC:
                    case IrOp::RAW_ALLOC:
                        break; // ya cubiertos por la propagacion / inofensivos
                    default:
                        // op desconocida que toca un valor tintado -> escape.
                        for (auto v : ins.operands)
                            if (is_t(v)) {
                                escapes = true;
                                break;
                            }
                        if (is_t(ins.func_ptr)) escapes = true;
                        break;
                    }
                }
            }

            if (escapes) continue;
            // Promover a ALLOCA (stack host).  Cualquier RAW_FREE del env
            // (no deberia haberlo aun) se volveria no-op sobre stack: por
            // seguridad NO promovemos si hay un RAW_FREE de un valor tintado.
            bool has_free = false;
            for (const auto &b : fn.blocks)
                for (const auto &ins : b.instrs)
                    if (ins.op == IrOp::RAW_FREE && !ins.operands.empty() &&
                        is_t(ins.operands[0]))
                        has_free = true;
            if (has_free) continue;

            A.op = IrOp::ALLOCA;
            A.imm = size_bytes;
            A.type = IrType::I8;
            A.host_alloca = true;
            A.operands.clear();
            if (A.dst < fn.values.size()) fn.values[A.dst].is_host_ptr = true;
            changed = true;
        }
    }
    return changed;
}

//==============================================================================
//  ir_pass_own_closure_envs (opcion 1: heap + RAII para escapes cross-function)
//==============================================================================
//
// Ver doc en el header.  Corre tras inline+promote (solo ve envs RAW_ALLOC
// etiquetados "__closure_env" que sobrevivieron = escapes reales).  Resuelve
// el dueno terminal de cada closure e inserta el RAW_FREE; revierte a
// GC_ALLOC (-> rechazo en bare) lo que no tenga dueno limpio.  Conservador.

namespace {
/* Una closure que se retorna va por SRET: el buffer de 16 bytes {fn,env} es el
 * PRIMER param de la funcion productora (su __retbuf), y cada call site pasa el
 * buffer como operands[0].  Un "forward" (threading del SRET) es una CALL cuyo
 * buffer es el propio __retbuf del caller.  El DUENO terminal es quien ALOCA el
 * buffer (ALLOCA 16) y lo pasa a la productora sin reenviarlo ni dejarlo
 * escapar; ahi va el RAW_FREE de [buffer+8]. */

/* buf es un DUENO LIMPIO en C: C single-block, buf es una ALLOCA local (no el
 * __retbuf de C), y sus unicos usos son: arg0 de la CALL constructora a
 * `yname`, LOAD(buf) [fn_addr] y ADD(buf,const) [dir del env].  Cualquier otro
 * uso (STORE, otro arg de CALL, RET, PHI, func_ptr) -> no limpio. */
bool ic_clean_owner_buf(const IrFunction &C, IrValueId buf,
                        const std::string &yname) {
    if (buf == IR_NO_VALUE) return false;
    if (C.blocks.size() != 1) return false; /* dominancia trivial */
    if (!C.params.empty() && C.params[0] == buf) return false; /* es retbuf */
    bool is_alloca = false;
    for (const auto &in : C.blocks[0].instrs)
        if (in.dst == buf && in.op == IrOp::ALLOCA) is_alloca = true;
    if (!is_alloca) return false;
    for (const auto &in : C.blocks[0].instrs) {
        bool as_ctor = (in.op == IrOp::CALL && in.func_name == yname &&
                        !in.operands.empty() && in.operands[0] == buf);
        bool as_load = (in.op == IrOp::LOAD && !in.operands.empty() &&
                        in.operands[0] == buf);
        bool as_addr = (in.op == IrOp::ADD && in.operands.size() == 2 &&
                        in.operands[0] == buf);
        for (size_t k = 0; k < in.operands.size(); ++k) {
            if (in.operands[k] != buf) continue;
            if (as_ctor && k == 0) continue;
            if (as_load && k == 0) continue;
            if (as_addr && k == 0) continue;
            return false; /* uso no reconocido -> escape/alias */
        }
        if (in.func_ptr == buf) return false;
    }
    return true;
}
} // namespace

bool ir_pass_fold_strcat(IrModule &mod) {
    bool changed = false;
    for (auto &fn : mod.functions) {
        // Definicion de cada SSA value, para reconocer `%a = strmake(lit, N)`.
        // Una sola pasada: el IR es SSA, cada value se define una vez.
        std::unordered_map<IrValueId, const IrInstr *> def;
        for (const auto &bb : fn.blocks)
            for (const auto &in : bb.instrs)
                if (in.dst != IR_NO_VALUE) def.emplace(in.dst, &in);

        // Si @p v es un STRMAKE sobre un literal de tamano constante, devuelve
        // el indice de su entrada en static_data y su longitud.
        auto literal_de = [&](IrValueId v, uint64_t &slot,
                              uint64_t &len) -> bool {
            auto it = def.find(v);
            if (it == def.end() || it->second->op != IrOp::STRMAKE)
                return false;
            const IrInstr &mk = *it->second;
            if (mk.operands.size() != 2) return false;
            auto ia = def.find(mk.operands[0]);
            auto il = def.find(mk.operands[1]);
            if (ia == def.end() || il == def.end()) return false;
            if (ia->second->op != IrOp::STR_LIT_ADDR) return false;
            if (il->second->op != IrOp::CONST) return false;
            slot = ia->second->imm;
            len = il->second->imm;
            if (slot >= mod.static_data.size()) return false;
            // La longitud tiene que ser la del literal: si el codigo pide otra
            // (una vista parcial), no es "la cadena entera" y no se pliega.
            return len == mod.static_data.len(slot);
        };

        for (auto &bb : fn.blocks) {
            for (auto &in : bb.instrs) {
                if (in.op != IrOp::STRCAT || in.operands.size() != 2) continue;
                if (in.dst == IR_NO_VALUE) continue;
                uint64_t sa = 0, la = 0, sb = 0, lb = 0;
                if (!literal_de(in.operands[0], sa, la)) continue;
                if (!literal_de(in.operands[1], sb, lb)) continue;
                // Las dos mitades se conocen -> internar la union.  El intern
                // dedupea, asi que dos `"aaa" + "bbb"` comparten entrada.
                auto [pa, na] = mod.static_data.bytes_at(sa);
                auto [pb, nb] = mod.static_data.bytes_at(sb);
                std::vector<uint8_t> junto;
                junto.reserve(na + nb);
                junto.insert(junto.end(), pa, pa + na);
                junto.insert(junto.end(), pb, pb + nb);
                const uint64_t slot = mod.intern_static_data(std::move(junto));

                // El STRCAT pasa a ser el STRMAKE de la cadena entera.  Sus dos
                // instrucciones nuevas (la direccion y la longitud) van al
                // mismo sitio: se insertan justo antes, en el segundo pase de
                // abajo.
                in.op = IrOp::STRMAKE;
                in.operands.clear();
                in.imm = slot; // marca para el pase de insercion
                in.func_name = "__fold_strcat";
                changed = true;
                // Los STRMAKE de las partes NO se tocan: si nadie mas los usa,
                // quedan muertos y los quita el DCE; si se usan, siguen.
            }
        }
        // Segundo pase: dar a cada STRMAKE plegado sus operandos (la direccion
        // del literal nuevo y su longitud), insertados justo delante.
        for (auto &bb : fn.blocks) {
            for (size_t i = 0; i < bb.instrs.size(); ++i) {
                IrInstr &in = bb.instrs[i];
                if (in.op != IrOp::STRMAKE || in.func_name != "__fold_strcat")
                    continue;
                const uint64_t slot = in.imm;
                const IrValueId v_addr = fn.new_value(IrType::PTR);
                const IrValueId v_len = fn.new_value(IrType::I64);
                IrInstr ad{};
                ad.op = IrOp::STR_LIT_ADDR;
                ad.type = IrType::PTR;
                ad.dst = v_addr;
                ad.imm = slot;
                ad.source_line = in.source_line;
                IrInstr ln{};
                ln.op = IrOp::CONST;
                ln.type = IrType::I64;
                ln.dst = v_len;
                ln.imm = mod.static_data.len(slot);
                ln.source_line = in.source_line;
                in.operands = {v_addr, v_len};
                in.imm = 0; // encoding por defecto, como cualquier literal
                in.func_name.clear();
                bb.instrs.insert(bb.instrs.begin() + i, std::move(ln));
                bb.instrs.insert(bb.instrs.begin() + i, std::move(ad));
                i += 2;
            }
        }
    }
    return changed;
}

bool ir_pass_own_closure_envs(IrModule &mod) {
    std::unordered_map<std::string, size_t> name_to_idx;
    for (size_t i = 0; i < mod.functions.size(); ++i)
        name_to_idx[mod.functions[i].name] = i;

    /* 1. yielders: funciones que CREAN un env etiquetado o que REENVIAN el
     *    resultado de una CALL a otra yielder.  Fixpoint. */
    const size_t NF = mod.functions.size();
    std::vector<bool> creates_env(NF, false), yielder(NF, false);
    for (size_t i = 0; i < NF; ++i) {
        for (const auto &bb : mod.functions[i].blocks)
            for (const auto &in : bb.instrs)
                if (in.op == IrOp::RAW_ALLOC && in.func_name == "__closure_env")
                    creates_env[i] = true;
        if (creates_env[i]) yielder[i] = true;
    }
    bool grew = true;
    while (grew) {
        grew = false;
        for (size_t i = 0; i < NF; ++i) {
            if (yielder[i]) continue;
            const IrFunction &F = mod.functions[i];
            if (F.params.empty()) continue; /* sin __retbuf no reenvia SRET */
            const IrValueId retbuf = F.params[0];
            for (const auto &bb : F.blocks)
                for (const auto &c : bb.instrs) {
                    /* forward SRET: CALL a yielder pasando el propio retbuf. */
                    if (c.op != IrOp::CALL || c.operands.empty() ||
                        c.operands[0] != retbuf)
                        continue;
                    auto it = name_to_idx.find(c.func_name);
                    if (it != name_to_idx.end() && yielder[it->second]) {
                        yielder[i] = true;
                        grew = true;
                    }
                }
        }
    }

    /* 2. ownable[F] (solo yielders): cada call-site que provee buffer es un
     *    forward-a-ownable o un dueno-limpio.  Fixpoint (true -> false). */
    std::vector<bool> ownable(NF, true);
    grew = true;
    while (grew) {
        grew = false;
        for (size_t fy = 0; fy < NF; ++fy) {
            if (!yielder[fy] || !ownable[fy]) continue;
            const std::string &yname = mod.functions[fy].name;
            bool ok = true;
            for (size_t ci = 0; ci < NF && ok; ++ci) {
                const IrFunction &C = mod.functions[ci];
                const IrValueId cret =
                    C.params.empty() ? IR_NO_VALUE : C.params[0];
                for (const auto &bb : C.blocks) {
                    for (const auto &in : bb.instrs) {
                        if (in.op != IrOp::CALL || in.func_name != yname ||
                            in.operands.empty())
                            continue;
                        const IrValueId buf = in.operands[0];
                        if (buf != IR_NO_VALUE && buf == cret) {
                            /* forward: el caller (yielder) debe ser ownable. */
                            if (!yielder[ci] || !ownable[ci]) ok = false;
                        } else if (!ic_clean_owner_buf(C, buf, yname)) {
                            ok = false; /* ni forward ni dueno limpio */
                        }
                        if (!ok) break;
                    }
                    if (!ok) break;
                }
            }
            if (!ok) {
                ownable[fy] = false;
                grew = true;
            }
        }
    }

    bool changed = false;

    /* 3. Revertir envs de yielders NO-ownable a GC_ALLOC (-> rechazo bare). */
    for (size_t i = 0; i < NF; ++i) {
        if (!creates_env[i] || ownable[i]) continue;
        for (auto &bb : mod.functions[i].blocks)
            for (auto &in : bb.instrs)
                if (in.op == IrOp::RAW_ALLOC &&
                    in.func_name == "__closure_env") {
                    in.op = IrOp::GC_ALLOC;
                    in.func_name.clear();
                    changed = true;
                }
    }

    /* 4. Para yielders ownable: quitar el tag (RAW_ALLOC normal) e insertar el
     *    RAW_FREE en cada dueno terminal (call-site no-forward + limpio). */
    for (size_t i = 0; i < NF; ++i) {
        if (!creates_env[i] || !ownable[i]) continue;
        for (auto &bb : mod.functions[i].blocks)
            for (auto &in : bb.instrs)
                if (in.op == IrOp::RAW_ALLOC &&
                    in.func_name == "__closure_env") {
                    in.func_name.clear();
                    changed = true;
                }
    }
    /* Insertar frees: recorrer todas las funciones; en cada CALL a una yielder
     *   ownable cuyo resultado NO se reenvia y es dueno limpio, anadir
     *   `ea=ADD(dst,8); ep=LOAD ea; RAW_FREE ep` antes de cada RET. */
    for (size_t ci = 0; ci < NF; ++ci) {
        IrFunction &C = mod.functions[ci];
        if (C.blocks.size() != 1) continue; /* solo duenos single-block */
        /* recolectar los dst a liberar (dueno limpio de yielder ownable). */
        const IrValueId cret = C.params.empty() ? IR_NO_VALUE : C.params[0];
        std::vector<IrValueId> to_free;
        for (const auto &in : C.blocks[0].instrs) {
            if (in.op != IrOp::CALL || in.operands.empty()) continue;
            auto it = name_to_idx.find(in.func_name);
            if (it == name_to_idx.end()) continue;
            const size_t fy = it->second;
            if (!yielder[fy] || !ownable[fy]) continue;
            const IrValueId buf = in.operands[0];
            if (buf != IR_NO_VALUE && buf == cret) continue; /* forward */
            if (!ic_clean_owner_buf(C, buf, in.func_name)) continue;
            to_free.push_back(buf);
        }
        if (to_free.empty()) continue;

        /* reconstruir el bloque insertando los frees antes de cada RET. */
        std::vector<IrInstr> out;
        out.reserve(C.blocks[0].instrs.size() + to_free.size() * 3);
        for (auto &in : C.blocks[0].instrs) {
            if (in.op == IrOp::RET) {
                for (IrValueId dst : to_free) {
                    /* ea = dst + 8 (host). */
                    IrValueId c8 = static_cast<IrValueId>(C.values.size());
                    {
                        IrValue v{};
                        v.id = c8;
                        v.type = IrType::I64;
                        v.name = "%cef_off" + std::to_string(c8);
                        v.is_const = true;
                        v.const_val = 8;
                        C.values.push_back(v);
                    }
                    IrValueId ea = static_cast<IrValueId>(C.values.size());
                    {
                        IrValue v{};
                        v.id = ea;
                        v.type = IrType::PTR;
                        v.name = "%cef_ea" + std::to_string(ea);
                        v.is_host_ptr = true;
                        C.values.push_back(v);
                    }
                    IrValueId ep = static_cast<IrValueId>(C.values.size());
                    {
                        IrValue v{};
                        v.id = ep;
                        v.type = IrType::PTR;
                        v.name = "%cef_ep" + std::to_string(ep);
                        v.is_host_ptr = true;
                        C.values.push_back(v);
                    }
                    IrInstr k8{};
                    k8.op = IrOp::CONST;
                    k8.type = IrType::I64;
                    k8.dst = c8;
                    k8.imm = 8;
                    out.push_back(std::move(k8));
                    IrInstr ad{};
                    ad.op = IrOp::ADD;
                    ad.type = IrType::I64;
                    ad.dst = ea;
                    ad.operands = {dst, c8};
                    out.push_back(std::move(ad));
                    IrInstr ld{};
                    ld.op = IrOp::LOAD;
                    ld.type = IrType::I64;
                    ld.dst = ep;
                    ld.operands = {ea};
                    out.push_back(std::move(ld));
                    IrInstr rf{};
                    rf.op = IrOp::RAW_FREE;
                    rf.type = IrType::VOID;
                    rf.operands = {ep};
                    out.push_back(std::move(rf));
                }
                changed = true;
            }
            out.push_back(std::move(in));
        }
        C.blocks[0].instrs = std::move(out);
    }

    return changed;
}

//==============================================================================
//   C2.13: Escape Analysis + Scalar Replacement de objetos GC
//
//  Detecta objetos `new X(...)` (emitidos como `call @__new_X(args)`) que NO
//  ESCAPAN del frame en el que se crean: su host_ptr solo se usa para leer/
//  escribir campos locales, nunca se retorna, almacena en memoria heap, ni
//  pasa a otra funcion.  Un objeto asi puede materializarse SIN tocar el GC
//  heap (scalar replacement): el alloc se elimina y los `load (obj+off)` se
//  reemplazan por el valor con el que el ctor inicializo ese campo.
//
//  ADVERTENCIA DE SEGURIDAD: marcar como no-escapante un objeto que SI escapa
//  produce use-after-free / corrupcion de heap silenciosa.  El analisis es
//  CONSERVADOR por diseno: asume que el objeto escapa salvo prueba explicita.
//  La clasificacion de usos reusa exactamente el patron validado de
//  @c ir_pass_promote_local_allocas (whitelist de safe-ops; cualquier op no
//  reconocida marca escape).
//
//  Esta primera parte implementa SOLO la DETECCION (log-only via la env var
//  VESTA_ESCAPE_DEBUG).  La transformacion (scalar replacement) se construye
//  encima del mismo analisis una vez validada la deteccion.
//==============================================================================

namespace {
/** @brief Un sitio `call @__new_X(...)` candidato a scalar replacement. */
struct GcAllocSite {
    size_t block_idx = 0;        ///< indice del bloque del CALL
    size_t ins_idx = 0;          ///< indice de la instr dentro del bloque
    IrValueId dst = IR_NO_VALUE; ///< SSA value del objeto (host_ptr)
    std::string class_name;      ///< "Foo" extraido de "__new_Foo"
    bool escapes = true;         ///< veredicto del analisis (conservador: true)
};

/**
 * @brief Devuelve true si @p name tiene la forma "__new_<ClassName>".
 *        Si lo es, escribe el ClassName en @p out_class.
 */
bool is_new_helper_name(const std::string &name, std::string *out_class) {
    if (name.size() <= 6) return false;
    if (name.rfind("__new_", 0) != 0) return false;
    /* Excluir variantes shared (`__new_X_shared`) que registran el objeto en
     * la SharedHandleTable -- eliminar ese alloc cambia shared_heap_live_count
     * (efecto observable), igual que en is_pure_allocator_name. */
    if (name.size() >= 7 && name.compare(name.size() - 7, 7, "_shared") == 0)
        return false;
    if (out_class) *out_class = name.substr(6);
    return true;
}

/**
 * @brief Analisis de escape para los objetos `new X()` de una funcion.
 *
 * Para cada `call @__new_X` con dst valido, calcula si el host_ptr del objeto
 * escapa.  Algoritmo identico al de @c ir_pass_promote_local_allocas pero
 * seedeado en los dsts de los CALL `__new_*` en lugar de los dsts de ALLOCA:
 *
 *   1. Forward-flow del conjunto "derivado" desde cada candidato a traves de
 *      ADD/SUB/BITCAST/MOV/CAST/*EXT/TRUNC/PHI/GEP.  Un dst derivado de >1
 *      candidato distinto se marca @c ambiguous (escapan todos).
 *   2. Clasificacion de usos:
 *        - SEED (el propio `call __new_X`): no escapa su dst.  Sus OPERANDS
 *          (los args del ctor) SI pueden escapar otros candidatos (p.ej.
 *          `new Outer(inner)` -> inner escapa).
 *        - LOAD/GETFIELD addr=derivado: SAFE (lee campo; el valor leido NO
 *          es derivado).
 *        - STORE/SETFIELD addr=derivado, val=NO-derivado: SAFE (escribe campo).
 *          val=derivado -> ESCAPA (el ptr se guarda en memoria).
 *        - ADD/SUB/CAST/.../PHI sobre derivados: tracked, no escapa.
 *        - CMP/BR: read-only, no escapa.
 *        - Cualquier OTRA op con un operand derivado: ESCAPA (conservador).
 *
 * @return vector de @c GcAllocSite con el campo @c escapes resuelto.
 */
std::vector<GcAllocSite> analyze_gc_escape(const IrFunction &fn) {
    std::vector<GcAllocSite> sites;
    if (fn.is_native || fn.values.empty()) return sites;

    /* Step 1: recolectar candidatos `call __new_X`. */
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto &blk = fn.blocks[bi];
        for (size_t ii = 0; ii < blk.instrs.size(); ++ii) {
            const auto &ins = blk.instrs[ii];
            if (ins.op != IrOp::CALL) continue;
            if (ins.dst == IR_NO_VALUE || ins.dst >= fn.values.size()) continue;
            std::string cls;
            if (!is_new_helper_name(ins.func_name, &cls)) continue;
            GcAllocSite s;
            s.block_idx = bi;
            s.ins_idx = ii;
            s.dst = ins.dst;
            s.class_name = std::move(cls);
            s.escapes = true; /* default conservador */
            sites.push_back(std::move(s));
        }
    }
    if (sites.empty()) return sites;

    /* Cota dura de candidatos por funcion (indice cabe en int8 del map). */
    if (sites.size() > 127) sites.resize(127);

    /* Step 2: forward-flow del set derivado.  derived_from[v] = idx del
     * candidato del que v deriva (-1 = ninguno); ambiguous[v] si >1. */
    std::vector<int8_t> derived_from(fn.values.size(), -1);
    std::vector<bool> ambiguous(fn.values.size(), false);

    auto set_derived = [&](IrValueId v, int8_t origin) -> bool {
        if (v == IR_NO_VALUE || v >= fn.values.size()) return false;
        if (derived_from[v] == -1) {
            derived_from[v] = origin;
            return true;
        }
        if (derived_from[v] != origin) ambiguous[v] = true;
        return false;
    };
    for (size_t i = 0; i < sites.size(); ++i) {
        set_derived(sites[i].dst, static_cast<int8_t>(i & 0x7F));
    }

    bool changed = true;
    int it = 16;
    while (changed && it-- > 0) {
        changed = false;
        for (const auto &blk : fn.blocks) {
            for (const auto &ins : blk.instrs) {
                if (ins.dst == IR_NO_VALUE || ins.dst >= fn.values.size())
                    continue;
                if (derived_from[ins.dst] >= 0) continue; /* ya marcado */
                auto from_op = [&](IrValueId v) -> int {
                    if (v == IR_NO_VALUE || v >= fn.values.size()) return -1;
                    return derived_from[v];
                };
                switch (ins.op) {
                case IrOp::ADD:
                case IrOp::SUB:
                case IrOp::BITCAST:
                case IrOp::MOV:
                case IrOp::CAST:
                case IrOp::SEXT:
                case IrOp::ZEXT:
                case IrOp::TRUNC:
                case IrOp::GEP:
                    for (auto opv : ins.operands) {
                        int from = from_op(opv);
                        if (from >= 0) {
                            if (set_derived(ins.dst, static_cast<int8_t>(from)))
                                changed = true;
                            break;
                        }
                    }
                    break;
                case IrOp::PHI:
                    for (const auto &pa : ins.phi_args) {
                        int from = from_op(pa.value);
                        if (from >= 0) {
                            if (set_derived(ins.dst, static_cast<int8_t>(from)))
                                changed = true;
                            break;
                        }
                    }
                    break;
                default: break;
                }
            }
        }
    }

    /* Step 3: clasificar usos.  escapes[i]=1 si algun uso de un derivado del
     * candidato i es UNSAFE. */
    std::vector<uint8_t> escapes(sites.size(), 0u);

    auto mark_escape = [&](IrValueId v) {
        if (v == IR_NO_VALUE || v >= derived_from.size()) return;
        if (derived_from[v] < 0) return;
        if (ambiguous[v]) {
            for (size_t k = 0; k < escapes.size(); ++k)
                escapes[k] = 1u;
            return;
        }
        int idx = derived_from[v];
        if (idx >= 0 && static_cast<size_t>(idx) < escapes.size())
            escapes[idx] = 1u;
    };
    auto is_derived = [&](IrValueId v) -> bool {
        return v != IR_NO_VALUE && v < derived_from.size() &&
               derived_from[v] >= 0;
    };

    /* Whitelist de SAFE ops (identica a promote_local_allocas).  Cualquier op
     * fuera de esta lista (RAW_ASM, CALL*, GC_*, FINDCLASS, RET, THROW, ...)
     * con un operand derivado marca escape. */
    auto is_safe_op = [](IrOp op) -> bool {
        switch (op) {
        case IrOp::ADD:
        case IrOp::SUB:
        case IrOp::MUL:
        case IrOp::DIV:
        case IrOp::MOD:
        case IrOp::NEG:
        case IrOp::AND:
        case IrOp::OR:
        case IrOp::XOR:
        case IrOp::NOT:
        case IrOp::SHL:
        case IrOp::SHR:
        case IrOp::SAR:
        case IrOp::BITCAST:
        case IrOp::MOV:
        case IrOp::CAST:
        case IrOp::SEXT:
        case IrOp::ZEXT:
        case IrOp::TRUNC:
        case IrOp::GEP:
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
        case IrOp::BR:
        case IrOp::BR_COND:
        case IrOp::NOP:
        case IrOp::CONST: return true;
        default: return false;
        }
    };

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto &blk = fn.blocks[bi];
        for (size_t ii = 0; ii < blk.instrs.size(); ++ii) {
            const auto &ins = blk.instrs[ii];

            /* El propio CALL seed NO escapa su dst (es el alloc); pero sus
             * operands (args del ctor) PUEDEN escapar OTROS candidatos. */
            if (ins.op == IrOp::CALL) {
                std::string cls;
                if (ins.dst != IR_NO_VALUE &&
                    is_new_helper_name(ins.func_name, &cls)) {
                    for (auto opv : ins.operands)
                        mark_escape(opv);
                    continue;
                }
            }

            if (ins.op == IrOp::LOAD || ins.op == IrOp::GETFIELD) {
                /* addr=operands[0] derivado -> lee campo, SAFE.  El dst (valor
                 * leido) NO se considera derivado del objeto. */
                continue;
            }
            if (ins.op == IrOp::STORE) {
                /* STORE val=operands[0], addr=operands[1].
                 * val derivado -> el ptr se escribe en memoria -> ESCAPA. */
                if (ins.operands.size() >= 2 && is_derived(ins.operands[0])) {
                    mark_escape(ins.operands[0]);
                }
                continue;
            }
            if (ins.op == IrOp::SETFIELD) {
                /* SETFIELD obj=operands[0], val=operands[1].
                 * val derivado -> ESCAPA. obj derivado -> SAFE (escribe
                 * campo).*/
                if (ins.operands.size() >= 2 && is_derived(ins.operands[1])) {
                    mark_escape(ins.operands[1]);
                }
                continue;
            }
            if (ins.op == IrOp::PHI) {
                /* Si el dst NO es derivado pero algun phi_arg SI -> escapa. */
                if (ins.dst < derived_from.size() &&
                    derived_from[ins.dst] < 0) {
                    for (const auto &pa : ins.phi_args)
                        mark_escape(pa.value);
                }
                continue;
            }
            if (ins.op == IrOp::RAW_FREE) {
                /* free(obj) (solo native_poo; en GC los objetos no se liberan
                 * con RAW_FREE) NO hace escapar al objeto: es su dealloc.  Si
                 * el sitio se escalariza, scalar_replace elimina este free.
                 * En GC este caso nunca se alcanza (no hay raw_free de objetos
                 * `new X()`), asi que no afecta al path interp/jit. */
                continue;
            }
            if (is_safe_op(ins.op)) continue;

            /* UNSAFE op: cualquier operand derivado escapa. */
            for (auto opv : ins.operands)
                mark_escape(opv);
            for (const auto &pa : ins.phi_args)
                mark_escape(pa.value);
            if (ins.func_ptr != IR_NO_VALUE) mark_escape(ins.func_ptr);
        }
    }

    for (size_t i = 0; i < sites.size(); ++i)
        sites[i].escapes = (escapes[i] != 0u);
    return sites;
}

} // namespace

/**
 * @brief Pase de DETECCION de objetos GC no-escapantes (log-only).
 *
 * Ejecuta @c analyze_gc_escape y, si VESTA_ESCAPE_DEBUG esta activo, loguea
 * cada sitio `new X()` con su veredicto (ESCAPA / NO-ESCAPA).  NO transforma
 * el IR: siempre devuelve false.  Sirve para validar el analisis con cero
 * riesgo antes de habilitar la transformacion (scalar replacement).
 */
bool ir_pass_escape_detect_gc(IrFunction &fn) {
    static const bool dbg_det = util::flag_on(util::FlagId::EscapeDebug);
    if (!dbg_det) return false;
    auto sites = analyze_gc_escape(fn);
    if (sites.empty()) return false;
    for (const auto &s : sites) {
        std::fprintf(
            stderr, "[escape] fn '%s': new %s() (dst %%%u) -> %s\n",
            fn.name.c_str(), s.class_name.c_str(), static_cast<unsigned>(s.dst),
            s.escapes ? "ESCAPA" : "NO-ESCAPA (candidato scalar-replace)");
    }
    return false;
}

//==============================================================================
//   C2.13: Scalar Replacement (transformacion)
//
//  Para un `%obj = call @__new_X(args)` NO-ESCAPANTE cuyo constructor es un
//  "inicializador trivial de campos", elimina el alloc GC y reemplaza cada
//  `load.T (obj + off)` por el valor con el que el ctor inicializo ese campo
//  (un arg del `new` o una constante), convertido al tipo del campo.
//==============================================================================

namespace {
/* El tamano en bytes del tipo, si es entero y si lleva signo los contesta el
 * vocabulario unico (ir/ir_type_info.h) -- aqui vivian tres copias de esas
 * tablas.  El eje que este pase necesita es el de RANURA: elige entre truncar
 * y ensanchar, que es una decision sobre el registro, no sobre la memoria. */

/** @brief Inicializacion de un campo por parte del ctor. */
struct SrFieldInit {
    enum Kind { PARAM, CONST } kind = PARAM;

    uint32_t offset = 0; ///< offset del campo desde la base del objeto
    IrType field_type =
        IrType::I64;        ///< tipo con el que el ctor escribio el campo
    int new_arg_index = -1; ///< (PARAM) indice en los args de __new_X
    uint64_t const_val = 0; ///< (CONST) valor literal
};

/** @brief Modelo de un ctor "inicializador trivial de campos". */
struct SrCtorModel {
    bool valid = false;
    uint32_t num_new_args = 0;      ///< params del ctor sin contar `this`
    std::vector<SrFieldInit> inits; ///< una entrada por campo inicializado

    const SrFieldInit *find(uint32_t off) const {
        for (const auto &i : inits)
            if (i.offset == off) return &i;
        return nullptr;
    }
};

/** @brief Busca una IrFunction por nombre exacto. */
const IrFunction *sr_find_fn(const IrModule &mod, const std::string &name) {
    for (const auto &f : mod.functions)
        if (f.name == name) return &f;
    return nullptr;
}

/**
 * @brief Construye el modelo del ctor de la clase @p class_name.
 *
 * Solo tiene exito si:
 *   - La clase existe en @p mod.classes, NO tiene destructor ni campos
 *     destructibles, y NO es un aspecto (AOP).
 *   - Tiene EXACTAMENTE un metodo @c is_constructor (sin sobrecargas).
 *   - El cuerpo del ctor es un unico bloque cuyas unicas ops son:
 *     CONST, ADD(this, const_offset) para direcciones de campo, STORE de un
 *     param/const a una de esas direcciones, y RET.  @c this solo puede
 *     usarse como base de esas direcciones.  Cualquier otra op -> invalido.
 */
bool sr_build_ctor_model(const IrModule &mod, const std::string &class_name,
                         SrCtorModel &out, std::string *reason = nullptr) {
    out = SrCtorModel{};
    auto bail = [&](const char *r) -> bool {
        if (reason) *reason = r;
        return false;
    };

    /* 1) Localizar la clase + checks de seguridad. */
    const IrClass *cls = nullptr;
    for (const auto &c : mod.classes) {
        if (c.name == class_name) {
            cls = &c;
            break;
        }
    }
    if (!cls) return bail("clase no encontrada en mod.classes");
    if (cls->has_destructor) return bail("clase con destructor");
    if (cls->has_destructible_field)
        return bail("clase con campo destructible");
    if (cls->is_aspect) return bail("clase es @Aspect");

    /* Solo importa si algun metodo de ESTA clase lleva aspectos: sustituirla
     * por escalares elimina su constructor, y con el la cadena que se hubiera
     * recorrido al llamarlo.
     *
     * Antes se miraba si el modulo -- que es el programa entero -- usaba AOP en
     * cualquier sitio, y entonces NINGUN objeto se sustituia por escalares.
     * Medido en bench_polymorphic: con un aspecto que no tocaba ninguna de sus
     * clases pasaba de 120 a 280 millones de instrucciones, porque sus tres
     * objetos dejaban de plegarse a constantes.  Y no se veia como lo que era
     * -- se leia como si el coste viniera del despacho -- porque el numero de
     * `callvirt` emitidos era exactamente el mismo con aspecto y sin el. */
    if (!mod.all_advices_attributed) return bail("hay aspectos sin atribuir");
    for (const auto &m : cls->methods) {
        if (!m.ir_fn_name.empty() && mod.advice_chains.count(m.ir_fn_name) != 0)
            return bail("un metodo de la clase lleva aspectos");
    }

    /* 2) Un unico constructor DEFINIDO en esta clase (los heredados tienen
     * defining_class distinto -> no cuentan; las sobrecargas reales si). */
    const IrMethod *ctor_m = nullptr;
    int ctor_count = 0;
    for (const auto &m : cls->methods) {
        if (!m.is_constructor) continue;
        /* Filtrar constructores heredados: solo el de esta clase.  Si
         * defining_class esta vacio (metadata incompleta), usar el match por
         * nombre ir_fn_name == "<clase>__ctor". */
        const bool own = m.defining_class.empty()
                             ? (m.ir_fn_name == class_name + "__ctor")
                             : (m.defining_class == class_name);
        if (!own) continue;
        ctor_m = &m;
        ++ctor_count;
    }
    if (ctor_count != 1) return bail("0 o >1 constructores propios");
    if (!ctor_m || ctor_m->ir_fn_name.empty())
        return bail("ctor sin ir_fn_name");

    const IrFunction *ctor = sr_find_fn(mod, ctor_m->ir_fn_name);
    if (!ctor || ctor->is_native)
        return bail("ctor IrFunction no hallada/native");
    if (ctor->blocks.size() != 1)
        return bail("ctor con control de flujo (>1 bloque)");
    if (ctor->params.empty()) return bail("ctor sin param this");

    const IrValueId this_vid = ctor->params[0];
    out.num_new_args = static_cast<uint32_t>(ctor->params.size() - 1);

    /* indice de param (en ctor->params) -> ; -1 si no es param. */
    auto param_index_of = [&](IrValueId v) -> int {
        for (size_t i = 0; i < ctor->params.size(); ++i) {
            if (ctor->params[i] == v) return static_cast<int>(i);
        }
        return -1;
    };

    /* Mapa fieldaddr_vid -> offset (direcciones `this + const`). */
    std::unordered_map<IrValueId, uint32_t> field_addr;
    /* CONST values definidos en el ctor (para resolver offsets y store-vals).
     */
    std::unordered_map<IrValueId, uint64_t> const_vals;

    const auto &blk = ctor->blocks[0];

    /* Pasada 1: recolectar consts. */
    for (const auto &ins : blk.instrs) {
        if (ins.op == IrOp::CONST && ins.dst != IR_NO_VALUE) {
            const_vals[ins.dst] = ins.imm;
        }
    }

    /* Pasada 2: validar cada instr + recolectar field addrs + stores. */
    for (const auto &ins : blk.instrs) {
        switch (ins.op) {
        case IrOp::CONST:
        case IrOp::NOP: break; /* inocuos */

        case IrOp::RET:
            /* ret.void: no debe retornar `this` ni un derivado. */
            for (auto v : ins.operands) {
                if (v == this_vid || field_addr.count(v))
                    return bail("ctor retorna this/field-addr");
            }
            break;

        case IrOp::ADD: {
            /* Solo permitido como `add this, const` -> direccion de campo.
             * Cualquier otro ADD que toque `this` invalida el modelo. */
            if (ins.operands.size() != 2) {
                /* ADD que no toca this es inocuo; si toca this, invalido. */
                for (auto v : ins.operands)
                    if (v == this_vid) return bail("ADD raro sobre this");
                break;
            }
            const IrValueId a = ins.operands[0];
            const IrValueId b = ins.operands[1];
            IrValueId base = IR_NO_VALUE, offv = IR_NO_VALUE;
            if (a == this_vid) {
                base = a;
                offv = b;
            } else if (b == this_vid) {
                base = b;
                offv = a;
            }
            if (base == this_vid) {
                auto it = const_vals.find(offv);
                if (it == const_vals.end())
                    return bail("offset de campo no const");
                if (ins.dst == IR_NO_VALUE) return bail("field-addr sin dst");
                field_addr[ins.dst] = static_cast<uint32_t>(it->second);
            } else {
                /* ADD sin this; pero si algun operando es una field-addr
                 * derivada, no lo soportamos. */
                if (field_addr.count(a) || field_addr.count(b))
                    return bail("aritmetica sobre field-addr");
            }
            break;
        }

        case IrOp::STORE: {
            /* store val=operands[0], addr=operands[1]. */
            if (ins.operands.size() < 2) return bail("STORE mal formado");
            const IrValueId val = ins.operands[0];
            const IrValueId addr = ins.operands[1];
            uint32_t off;
            if (addr == this_vid) {
                off = 0;
            } else {
                auto it = field_addr.find(addr);
                if (it == field_addr.end())
                    return bail("STORE a addr no-campo");
                off = it->second;
            }
            /* val debe ser un param (>=1) o un const. */
            SrFieldInit fi;
            fi.offset = off;
            int pidx = param_index_of(val);
            if (pidx == 0) {
                return bail("ctor guarda this en un campo (self-ref)");
            } else if (pidx >= 1) {
                fi.kind = SrFieldInit::PARAM;
                fi.new_arg_index = pidx - 1;
                if (val >= ctor->values.size())
                    return bail("param fuera de rango");
                fi.field_type = ctor->values[val].type;
            } else {
                auto cit = const_vals.find(val);
                if (cit == const_vals.end())
                    return bail("store-val no es param ni const (cast/expr)");
                fi.kind = SrFieldInit::CONST;
                fi.const_val = cit->second;
                fi.field_type = (val < ctor->values.size())
                                    ? ctor->values[val].type
                                    : IrType::I64;
            }
            /* No permitir dos stores al mismo offset (ambiguo). */
            if (out.find(off)) return bail("dos stores al mismo campo");
            out.inits.push_back(fi);
            break;
        }

        default:
            /* Cualquier otra op (CALL, LOAD, NEWOBJ, GC*, RAW_ASM, MOV,
             * casts, super-ctor, ...) invalida el modelo trivial. */
            return bail("ctor con op no-trivial (CALL/LOAD/cast/super/...)");
        }
    }

    out.valid = true;
    return true;
}

/**
 * @brief Adelantar un valor a una lectura NO puede tirar DE QUE MEMORIA era.
 *
 * Quien LEE un campo sabe en que memoria vive lo que hay dentro -- se lo dice
 * el TIPO del campo --, y quien lo ESCRIBIO puede no saberlo: una copia palabra
 * a palabra de un struct mueve punteros sin enterarse de que lo son.  Al
 * sustituir la lectura por el valor, esa marca se PASA al valor; borrarla deja
 * el acceso leyendo de la memoria equivocada, y eso no da un error, da otro
 * valor.
 *
 * NO se usa cuando la lectura pasa a ser una CONSTANTE.  Ahi el valor es un
 * literal y no una direccion, asi que borrar la marca es lo correcto -- y por
 * eso esos sitios NO llaman aqui, a proposito.
 *
 * Esta escrito una vez porque las tres reescrituras que adelantan un valor
 * -- desde un argumento del constructor, desde una escritura previa, y la de
 * @c sr_mem2reg_object -- tenian la misma linea copiada, y solo una se
 * arreglo la primera vez.
 *
 * @param fn       Funcion.
 * @param load_dst Destino de la lectura que se sustituye (el que SABE).
 * @param fwd      Valor que pasa a ocupar su lugar.
 */
inline void sr_forward_mem_marks(IrFunction &fn, IrValueId load_dst,
                                 IrValueId fwd) {
    if (load_dst == IR_NO_VALUE || load_dst >= fn.values.size()) return;
    if (fwd == IR_NO_VALUE || fwd >= fn.values.size()) return;
    if (fn.values[load_dst].is_host_ptr) fn.values[fwd].is_host_ptr = true;
    if (fn.values[load_dst].is_gc_object) fn.values[fwd].is_gc_object = true;
}

/**
 * @brief Reescribe (o solo valida) la instr @p ld (un LOAD) para producir el
 *        valor del campo a partir del arg/const con el que el ctor lo
 * inicializo.
 *
 * Con @p apply == false NO muta nada (ni @p ld ni @c fn.values): solo
 * comprueba si la reescritura es posible.  Con @p apply == true aplica la
 * reescritura (asume que la validacion previa devolvio true).  Esto permite
 * un transform transaccional: validar TODOS los loads antes de tocar nada.
 *
 * @return true si la reescritura es posible / se aplico; false -> abortar.
 */
bool sr_rewrite_load(IrInstr &ld, const SrFieldInit &fi,
                     const std::vector<IrValueId> &args, IrFunction &fn,
                     bool apply) {
    const IrType T = ld.type; /* tipo leido del campo */
    /* Solo enteros por ahora (float/ptr/handle -> abortar, conservador). */
    if (!type_is_integer(T)) return false;
    /* El ctor escribio el campo con field_type; debe coincidir con el read. */
    if (fi.field_type != T) return false;

    if (fi.kind == SrFieldInit::CONST) {
        uint64_t v = fi.const_val;
        int sz = type_slot_bytes(T);
        if (sz < 8) v &= ((uint64_t{1} << (sz * 8)) - 1);
        if (apply) {
            /* Reescribir el LOAD como CONST T value (truncado al ancho de T).
             */
            ld.op = IrOp::CONST;
            ld.imm = v;
            ld.operands.clear();
            ld.func_name.clear();
            if (ld.dst != IR_NO_VALUE && ld.dst < fn.values.size()) {
                fn.values[ld.dst].is_const = true;
                fn.values[ld.dst].const_val = v;
                /* Aqui SI se borra, y es lo correcto: lo que queda es un
                 * literal, no una direccion.  Los sitios que ADELANTAN un
                 * valor no pueden hacer esto -- ver @c sr_forward_mem_marks. */
                fn.values[ld.dst].is_host_ptr = false;
            }
        }
        return true;
    }

    /* PARAM: el valor del campo = convert(args[new_arg_index], T). */
    if (fi.new_arg_index < 0 ||
        static_cast<size_t>(fi.new_arg_index) >= args.size())
        return false;
    const IrValueId arg = args[fi.new_arg_index];
    if (arg == IR_NO_VALUE || arg >= fn.values.size()) return false;
    const IrType Ta = fn.values[arg].type;
    if (!type_is_integer(Ta)) return false; /* arg no entero -> abortar */

    const int szA = type_slot_bytes(Ta);
    const int szT = type_slot_bytes(T);
    /* arg mas estrecho que el campo: widening (raro al pasar literales).
     * v1 no lo modela con seguridad -> abortar. */
    if (szA < szT) return false;

    if (apply) {
        ld.operands.clear();
        ld.operands.push_back(arg);
        ld.func_name.clear();
        if (ld.dst != IR_NO_VALUE && ld.dst < fn.values.size())
            fn.values[ld.dst].is_const = false;
        /* De que memoria era se PASA al argumento, no se borra.  Si hay que
         * truncar, el campo mide menos de una palabra y no cabe una direccion,
         * asi que la lectura no llevaba marca y esto no hace nada. */
        sr_forward_mem_marks(fn, ld.dst, arg);
        /* szA > szT -> truncar; szA == szT -> copia directa. */
        ld.op = (szA > szT) ? IrOp::TRUNC : IrOp::MOV;
    }
    return true;
}

/**
 * @brief Reescribe (o solo valida) un LOAD de un campo que el ctor NO
 *        inicializo, produciendo @c CONST 0 (valor por defecto).
 *
 * SOUND: @c NEWOBJ / @c GC_ALLOC zero-inicializan el payload del objeto
 * (@c gc_heap.alloc hace @c memset(payload, 0, size)), asi que un campo
 * accedido pero no escrito por el ctor lee deterministamente 0.  Esto amplia
 * la cobertura del scalar-replace al "18% v2" (campos default-0) sin riesgo.
 * Solo enteros (float/ptr/handle -> abortar, conservador como el resto del
 * pase).
 *
 * @param ld    Instruccion LOAD a reescribir.
 * @param fn    Funcion contenedora (para actualizar @c fn.values del dst).
 * @param apply false = solo validar (no muta); true = aplicar.
 * @return true si es posible / se aplico; false -> tipo no soportado.
 */
/* Tamano del @c ObjectHeader (ABI v2/v3 = 24 bytes: class_ptr, flags,
 * hash_code, owner_pid, lock_depth/_pad).  Los campos de USUARIO empiezan en
 * este offset; los reads de offset < 24 son metadata de cabecera (class_ptr,
 * etc.) puesta por NEWOBJ -> NUNCA son default-0 (ver sr default-0). */
static constexpr uint32_t SR_OBJ_HEADER_SIZE = 24;

bool sr_rewrite_load_zero(IrInstr &ld, IrFunction &fn, bool apply) {
    const IrType T = ld.type;
    if (!type_is_integer(T)) return false; /* solo enteros */
    if (apply) {
        ld.op = IrOp::CONST;
        ld.imm = 0;
        ld.operands.clear();
        ld.func_name.clear();
        if (ld.dst != IR_NO_VALUE && ld.dst < fn.values.size()) {
            fn.values[ld.dst].is_const = true;
            fn.values[ld.dst].const_val = 0;
            /* Un campo sin inicializar vale CERO, que no es una direccion:
             * borrar la marca es lo correcto.  Ver @c sr_forward_mem_marks. */
            fn.values[ld.dst].is_host_ptr = false;
        }
    }
    return true;
}

//==============================================================================
//  Dominancia: idom + dominance frontier + dom-tree (para SROA/mem2reg).
//==============================================================================

struct SrDom {
    size_t N = 0;
    IrBlockId UNDEF = 0;
    std::vector<std::vector<IrBlockId>> preds, succs;
    std::vector<IrBlockId> idom;                      ///< inmediato dominador
    std::vector<std::vector<IrBlockId>> df;           ///< dominance frontier
    std::vector<std::vector<IrBlockId>> dom_children; ///< hijos en el dom-tree
    std::vector<uint8_t> reachable; ///< alcanzable desde entry

    bool dominates(IrBlockId T, IrBlockId B) const {
        if (T == B) return true;
        if (T >= N || B >= N || idom[B] == UNDEF) return false;
        IrBlockId cur = B;
        while (idom[cur] != cur) {
            cur = idom[cur];
            if (cur == T) return true;
        }
        return false;
    }
};

/**
 * @brief Computa CFG + dominadores (Cooper-Harvey-Kennedy) + dominance frontier
 *        (Cytron) + dom-tree para @p fn.  Convencion: bloque 0 = entry.
 */
SrDom sr_compute_dom(const IrFunction &fn) {
    SrDom d;
    const size_t N = fn.blocks.size();
    d.N = N;
    d.UNDEF = static_cast<IrBlockId>(N);
    d.preds.assign(N, {});
    d.succs.assign(N, {});
    d.idom.assign(N, d.UNDEF);
    d.df.assign(N, {});
    d.dom_children.assign(N, {});
    d.reachable.assign(N, 0);
    if (N == 0) return d;

    /* CFG desde los terminadores. */
    for (size_t b = 0; b < N; ++b) {
        const auto &bb = fn.blocks[b];
        if (bb.instrs.empty()) continue;
        const auto &last = bb.instrs.back();
        IrBlockId t1 = IR_NO_BLOCK, t2 = IR_NO_BLOCK;
        if (last.op == IrOp::BR) {
            t1 = last.target_block;
        } else if (last.op == IrOp::BR_COND) {
            t1 = last.target_block;
            t2 = last.false_block;
        }
        if (t1 != IR_NO_BLOCK && t1 < N) {
            d.preds[t1].push_back((IrBlockId)b);
            d.succs[b].push_back(t1);
        }
        if (t2 != IR_NO_BLOCK && t2 < N) {
            d.preds[t2].push_back((IrBlockId)b);
            d.succs[b].push_back(t2);
        }
    }

    const IrBlockId entry = 0;
    /* Reverse postorder via DFS iterativo (evita stack overflow en CFGs
     * grandes). */
    std::vector<IrBlockId> rpo;
    {
        std::vector<uint8_t> vis(N, 0);
        std::vector<std::pair<IrBlockId, size_t>> st; /* (bloque, idx_succ) */
        st.push_back({entry, 0});
        vis[entry] = 1;
        d.reachable[entry] = 1;
        std::vector<IrBlockId> post;
        while (!st.empty()) {
            auto &top = st.back();
            if (top.second < d.succs[top.first].size()) {
                IrBlockId s = d.succs[top.first][top.second++];
                if (s < N && !vis[s]) {
                    vis[s] = 1;
                    d.reachable[s] = 1;
                    st.push_back({s, 0});
                }
            } else {
                post.push_back(top.first);
                st.pop_back();
            }
        }
        rpo.assign(post.rbegin(), post.rend());
    }
    std::vector<uint32_t> rpo_pos(N, UINT32_MAX);
    for (size_t i = 0; i < rpo.size(); ++i)
        rpo_pos[rpo[i]] = (uint32_t)i;

    d.idom[entry] = entry;
    auto intersect = [&](IrBlockId b1, IrBlockId b2) -> IrBlockId {
        while (b1 != b2) {
            while (b1 != d.UNDEF && rpo_pos[b1] > rpo_pos[b2])
                b1 = d.idom[b1];
            while (b2 != d.UNDEF && rpo_pos[b2] > rpo_pos[b1])
                b2 = d.idom[b2];
            if (b1 == d.UNDEF || b2 == d.UNDEF) return d.UNDEF;
        }
        return b1;
    };
    bool ch = true;
    while (ch) {
        ch = false;
        for (IrBlockId b : rpo) {
            if (b == entry) continue;
            IrBlockId nd = d.UNDEF;
            for (IrBlockId p : d.preds[b]) {
                if (d.idom[p] != d.UNDEF) {
                    nd = (nd == d.UNDEF) ? p : intersect(nd, p);
                    if (nd == d.UNDEF) break;
                }
            }
            if (nd != d.UNDEF && nd != d.idom[b]) {
                d.idom[b] = nd;
                ch = true;
            }
        }
    }

    /* Dom-tree children. */
    for (IrBlockId b = 0; b < N; ++b) {
        if (b != entry && d.idom[b] != d.UNDEF)
            d.dom_children[d.idom[b]].push_back(b);
    }

    /* Dominance frontier (Cytron): por cada bloque b con >=2 preds, por cada
     * pred p, sube en el dom-tree desde p hasta idom[b] añadiendo b al DF. */
    for (IrBlockId b = 0; b < N; ++b) {
        if (d.preds[b].size() < 2) continue;
        for (IrBlockId p : d.preds[b]) {
            IrBlockId runner = p;
            while (runner != d.UNDEF && runner != d.idom[b]) {
                d.df[runner].push_back(b);
                if (d.idom[runner] == runner) break; /* entry */
                runner = d.idom[runner];
            }
        }
    }
    return d;
}

//==============================================================================
//  SROA/mem2reg de los campos de un objeto GC no-escapante.
//
//  Promueve cada campo (offset) del objeto a forma SSA a traves del control de
//  flujo (incluyendo loops): inserta PHIs en el dominance frontier de las
//  definiciones (ctor-init + stores) y renombra (Cytron) reemplazando cada load
//  por la definicion que lo alcanza.  Tras esto el objeto no toca memoria -> el
//  alloc + los stores se borran.
//
//  Precondiciones (el caller las garantiza salvo lo que se revalida aqui):
//    - El objeto NO escapa y TODOS sus usos son field-access (load/store de
//      `obj` o de `add obj, Kconst`), nunca en phi_args/func_ptr/CALL/RET.
//    - El ctor es un inicializador trivial (modelo @p model).
//    - CFG reducible (el frontend Vesta lo garantiza).
//
//  Conservador: si cualquier campo accedido no esta en el modelo, no es entero,
//  o los tipos no son consistentes -> bail (no muta nada).
//==============================================================================

//  @p stack_mode: cuando true, el "alloc" es un ALLOCA de PILA (struct
//  value-type), NO un objeto GC.  Diferencias: (1) @p model puede ser nullptr
//  (no hay ctor -- los STORE del init-list siembran los defs); (2) el alloc NO
//  provee valor inicial de ningun campo -> una lectura de un campo antes de que
//  un store lo domine hace bail ("load sin def alcanzante"), que es CORRECTO
//  (la pila no se zero-inicializa); (3) el paso final NOPea el ALLOCA en vez de
//  un CALL de helper.  El GC-mode (stack_mode=false) queda byte-identico.
bool sr_mem2reg_object(
    IrFunction &fn, const SrCtorModel *model, size_t call_bi, size_t call_ii,
    IrValueId obj, const std::vector<IrValueId> &args,
    const std::unordered_map<IrValueId, uint32_t> &fieldaddr_off,
    std::string &reason, bool stack_mode = false) {
    const size_t N = fn.blocks.size();
    if (N == 0) {
        reason = "fn vacia";
        return false;
    }

    /* Helper: la instr es un load/store de un campo del objeto?  Devuelve
     * offset + si es store + el valor almacenado. */
    auto classify = [&](const IrInstr &in, uint32_t &off, bool &is_ld,
                        bool &is_st, IrValueId &sval) -> bool {
        is_ld = is_st = false;
        if (in.op == IrOp::LOAD && !in.operands.empty()) {
            IrValueId a = in.operands[0];
            if (a == obj) {
                off = 0;
                is_ld = true;
                return true;
            }
            auto it = fieldaddr_off.find(a);
            if (it != fieldaddr_off.end()) {
                off = it->second;
                is_ld = true;
                return true;
            }
        } else if (in.op == IrOp::STORE && in.operands.size() >= 2) {
            IrValueId a = in.operands[1];
            if (a == obj) {
                off = 0;
                is_st = true;
                sval = in.operands[0];
                return true;
            }
            auto it = fieldaddr_off.find(a);
            if (it != fieldaddr_off.end()) {
                off = it->second;
                is_st = true;
                sval = in.operands[0];
                return true;
            }
        }
        return false;
    };

    /* 1) Recolectar offsets accedidos + tipo por offset + bloques con store. */
    std::unordered_map<uint32_t, IrType> field_type; /* offset -> tipo */
    std::unordered_map<uint32_t, std::vector<IrBlockId>> store_blocks;
    std::vector<uint32_t> offsets;
    for (size_t bi = 0; bi < N; ++bi) {
        for (const auto &in : fn.blocks[bi].instrs) {
            uint32_t off;
            bool ld, st;
            IrValueId sv;
            if (!classify(in, off, ld, st, sv)) continue;
            /* Tipo del campo: para load = in.type; para store = tipo del valor.
             */
            IrType t =
                ld ? in.type
                   : (sv < fn.values.size() ? fn.values[sv].type : IrType::I64);
            if (!type_is_integer(t)) {
                reason = "campo no-entero en mem2reg";
                return false;
            }
            auto fit = field_type.find(off);
            if (fit == field_type.end()) {
                field_type[off] = t;
                offsets.push_back(off);
            } else if (fit->second != t) {
                reason = "tipo inconsistente del campo";
                return false;
            }
            if (st) store_blocks[off].push_back((IrBlockId)bi);
        }
    }
    if (offsets.empty()) {
        reason = "sin accesos a campos";
        return false;
    }

    /* Cada offset accedido o bien lo inicializa el ctor (tipo debe coincidir) o
     * bien NO -> default-0 (el objeto GC se zero-inicializa al alocar; el init
     * sera un CONST 0 materializado abajo).  En stack_mode NO hay ctor: los
     * defs vienen de los STORE explicitos (init-list); si un campo se lee antes
     * de escribirse, el renaming hace bail (pila no zero-inicializada). */
    for (uint32_t off : offsets) {
        if (stack_mode) continue; /* sin modelo: los stores siembran los defs */
        const SrFieldInit *fi = model->find(off);
        if (!fi) {
            /* Campo de usuario no inicializado -> default-0 (init = CONST 0,
             * materializado abajo).  Pero un read de la CABECERA (offset < 24:
             * class_ptr, etc.) NO es default-0 -> bail (identidad/reflexion).
             */
            if (off < SR_OBJ_HEADER_SIZE) {
                reason =
                    "lectura de cabecera no inicializada (identidad/class_ptr)";
                return false;
            }
            continue; /* default-0 permitido para campo de usuario */
        }
        if (fi->field_type != field_type[off]) {
            reason = "tipo ctor/acceso difiere";
            return false;
        }
    }

    SrDom dom = sr_compute_dom(fn);
    /* El bloque del alloc debe ser alcanzable (lo es: contiene el call). */
    if (call_bi >= N || !dom.reachable[call_bi]) {
        reason = "call_bi inalcanzable";
        return false;
    }
    /* Todos los bloques con acceso a campos deben ser alcanzables + dominados
     * por el alloc (garantizado por SSA, pero revalidamos defensivamente). */

    /* 2) Materializar el valor de construccion (init) de cada campo como un
     * SSA value disponible en el sitio del alloc.  Si requiere conversion
     * (trunc) o es const, se insertara una instruccion JUSTO antes del call. */
    std::unordered_map<uint32_t, IrValueId> init_val; /* offset -> SSA value */
    std::vector<IrInstr> init_instrs; /* a insertar antes del call */
    for (uint32_t off : offsets) {
        if (stack_mode)
            break; /* pila: sin init; los stores siembran los defs */
        const SrFieldInit *fi = model->find(off);
        const IrType T = field_type[off];
        if (!fi) {
            /* default-0: campo no inicializado por el ctor -> init = CONST 0.
             * Sound porque el payload del objeto GC se zero-inicializa. */
            IrInstr ci;
            ci.op = IrOp::CONST;
            ci.type = T;
            ci.imm = 0;
            IrValue nv;
            nv.id = (IrValueId)fn.values.size();
            nv.type = T;
            nv.is_const = true;
            nv.const_val = 0;
            nv.name = "%m2ri" + std::to_string(nv.id);
            ci.dst = nv.id;
            fn.values.push_back(nv);
            init_val[off] = nv.id;
            init_instrs.push_back(std::move(ci));
            continue;
        }
        if (fi->kind == SrFieldInit::CONST) {
            uint64_t v = fi->const_val;
            int sz = type_slot_bytes(T);
            if (sz < 8) v &= ((uint64_t{1} << (sz * 8)) - 1);
            IrInstr ci;
            ci.op = IrOp::CONST;
            ci.type = T;
            ci.imm = v;
            IrValue nv;
            nv.id = (IrValueId)fn.values.size();
            nv.type = T;
            nv.is_const = true;
            nv.const_val = v;
            nv.name = "%m2ri" + std::to_string(nv.id);
            ci.dst = nv.id;
            fn.values.push_back(nv);
            init_val[off] = nv.id; /* antes del move de ci */
            init_instrs.push_back(std::move(ci));
        } else {
            /* PARAM. */
            if (fi->new_arg_index < 0 ||
                (size_t)fi->new_arg_index >= args.size()) {
                reason = "arg index fuera de rango";
                return false;
            }
            IrValueId arg = args[fi->new_arg_index];
            if (arg == IR_NO_VALUE || arg >= fn.values.size()) {
                reason = "arg invalido";
                return false;
            }
            IrType Ta = fn.values[arg].type;
            if (!type_is_integer(Ta)) {
                reason = "arg no entero";
                return false;
            }
            int szA = type_slot_bytes(Ta), szT = type_slot_bytes(T);
            if (szA == szT) {
                init_val[off] = arg; /* sin conversion */
            } else if (szA > szT) {
                IrInstr ti;
                ti.op = IrOp::TRUNC;
                ti.type = T;
                ti.operands.push_back(arg);
                IrValue nv;
                nv.id = (IrValueId)fn.values.size();
                nv.type = T;
                nv.name = "%m2ri" + std::to_string(nv.id);
                ti.dst = nv.id;
                fn.values.push_back(nv);
                init_val[off] = nv.id; /* antes del move de ti */
                init_instrs.push_back(std::move(ti));
            } else {
                reason = "widening arg->campo no soportado";
                return false; /* szA < szT */
            }
        }
    }

    /* 2.5) Deteccion de loops (headers + bloques in-loop) desde back-edges.
     * Necesario para el COST-MODEL: un PHI in-loop que NO esta en un loop
     * header (= escritura condicional de campo dentro de un loop) añade copies
     * en el path no-tomado por iteracion.  Medido: regresiona el interp (16
     * registros VM -> presion + copies).  Los PHIs de loop-header (acumuladores
     * incondicionales) y los if-merge FUERA de loops (coste unico) SI son win.
     */
    std::vector<uint8_t> is_loop_header(N, 0), in_loop(N, 0);
    for (IrBlockId b = 0; b < N; ++b) {
        for (IrBlockId h : dom.succs[b]) {
            if (!dom.dominates(h, b)) continue; /* back-edge b->h */
            is_loop_header[h] = 1;
            in_loop[h] = 1;
            std::vector<IrBlockId> stk;
            if (!in_loop[b]) {
                in_loop[b] = 1;
                stk.push_back(b);
            }
            while (!stk.empty()) {
                IrBlockId x = stk.back();
                stk.pop_back();
                if (x == h) continue;
                for (IrBlockId p : dom.preds[x]) {
                    if (!in_loop[p]) {
                        in_loop[p] = 1;
                        if (p != h) stk.push_back(p);
                    }
                }
            }
        }
    }

    /* 3) Insercion de PHIs: por cada offset, iterated dominance frontier de los
     * def-blocks (= {call_bi} U store_blocks).  Crea SSA values para los phis.
     */
    /* phi_value[offset][block] = SSA value del phi (IR_NO_VALUE = no hay). */
    std::unordered_map<uint64_t, IrValueId>
        phi_value; /* key = (off<<32)|block */
    std::unordered_map<IrValueId, uint32_t> phi_dst_off; /* phi dst -> offset */
    auto pkey = [](uint32_t off, IrBlockId b) -> uint64_t {
        return ((uint64_t)off << 32) | (uint64_t)b;
    };
    /* COST-MODEL (default-on): permitir VESTA_ESCAPE_MEM2REG_FORCE para
     * saltarlo y promover siempre (util para medir / casos JIT-only). */
    static const bool force = util::flag_on(util::FlagId::EscapeMem2RegForce);
    for (uint32_t off : offsets) {
        std::vector<IrBlockId> worklist;
        std::unordered_set<IrBlockId> on_work, has_phi;
        /* En GC-mode el alloc inicializa TODOS los campos -> es def-block.  En
         * stack_mode el alloc no define nada (los stores del init-list si). */
        if (!stack_mode) {
            worklist.push_back((IrBlockId)call_bi);
            on_work.insert((IrBlockId)call_bi);
        }
        for (IrBlockId b : store_blocks[off]) {
            if (!on_work.count(b)) {
                worklist.push_back(b);
                on_work.insert(b);
            }
        }
        size_t wp = 0;
        while (wp < worklist.size()) {
            IrBlockId b = worklist[wp++];
            if (b >= N) continue;
            for (IrBlockId f : dom.df[b]) {
                if (has_phi.count(f)) continue;
                if (!dom.reachable[f]) continue;
                /* Solo PHIs en bloques DOMINADOS por el alloc: ahi todos los
                 * preds estan dominados por el call -> el objeto existe en cada
                 * pred -> el operando del phi siempre tiene def alcanzante.  Un
                 * merge no-dominado no puede leer el campo (violaria SSA), asi
                 * que su phi seria muerto; lo omitimos. */
                if (!dom.dominates((IrBlockId)call_bi, f)) continue;
                /* COST-MODEL: if-merge DENTRO de un loop = escritura
                 * condicional en el loop -> pessimiza el interp.  Bail (a menos
                 * que FORCE). */
                if (!force && in_loop[f] && !is_loop_header[f]) {
                    reason =
                        "escritura condicional de campo en loop (cost-model)";
                    return false;
                }
                has_phi.insert(f);
                /* Crear el SSA value del phi. */
                IrValue nv;
                nv.id = (IrValueId)fn.values.size();
                nv.type = field_type[off];
                nv.name = "%m2rphi" + std::to_string(nv.id);
                fn.values.push_back(nv);
                phi_value[pkey(off, f)] = nv.id;
                phi_dst_off[nv.id] = off;
                if (!on_work.count(f)) {
                    worklist.push_back(f);
                    on_work.insert(f);
                }
            }
        }
    }

    /* 4) Renaming (Cytron) DFS sobre el dom-tree.  current[off] = def
     * alcanzante. Se construyen: load_repl (load dst -> valor), store_remove
     * (posiciones), y los phi_args de cada phi insertado.  NO se muta el IR
     * todavia. */
    /* Plan de mutacion: */
    std::unordered_map<IrValueId, IrValueId>
        load_repl; /* load.dst -> valor reemplazo */
    /* phi_args[phi_dst] = lista de (pred_block, value). */
    std::unordered_map<IrValueId, std::vector<IrPhiArg>> phi_args_plan;

    std::unordered_map<uint32_t, std::vector<IrValueId>>
        stack; /* off -> pila de defs */
    auto cur = [&](uint32_t off) -> IrValueId {
        auto it = stack.find(off);
        return (it != stack.end() && !it->second.empty()) ? it->second.back()
                                                          : IR_NO_VALUE;
    };

    bool rename_ok = true;
    const char *rfail = nullptr;
    std::function<void(IrBlockId, int)> rename = [&](IrBlockId b, int depth) {
        if (!rename_ok) return;
        if (depth > 4096) {
            rename_ok = false;
            rfail = "dom-tree demasiado profundo";
            return;
        }
        std::vector<uint32_t>
            pushed; /* offsets con un push en este bloque (para pop) */

        /* (a) PHIs planeados para este bloque (aun NO insertados como
         * instrucciones): definen current[off].  Se consultan via phi_value, no
         * escaneando instrucciones (que no existen todavia en esta fase). */
        for (uint32_t off : offsets) {
            auto it = phi_value.find(pkey(off, b));
            if (it == phi_value.end()) continue;
            stack[off].push_back(it->second);
            pushed.push_back(off);
        }

        /* (b) instrucciones en orden. */
        for (size_t ii = 0; ii < fn.blocks[b].instrs.size(); ++ii) {
            const IrInstr &in = fn.blocks[b].instrs[ii];
            /* El alloc: en GC-mode define todos los campos = init_val.  En
             * stack_mode no define nada (el ALLOCA no es un load/store de campo
             * -> classify lo ignora, y aqui no empujamos ningun def). */
            // GC-mode: el call site (helper `__new_X`) siembra los init de cada
            // campo; se identifica por (call_bi, call_ii) y se salta.
            // stack_mode: el ALLOCA no siembra nada y `classify` ya lo ignora
            // (solo reconoce LOAD/STORE) -> NO saltar por indice.  Saltarlo era
            // redundante Y peligroso: `call_ii` se calcula al recolectar los
            // sites, pero las promociones PREVIAS de otros ALLOCAs pueden
            // reindexar el bloque, con lo que (call_bi, call_ii) acaba
            // apuntando a un STORE de ESTE objeto
            // -> el renaming lo saltaba y el valor se perdia (bug del patron
            // `S r = this; r.x = v; return r`).
            if (b == call_bi && ii == call_ii && !stack_mode) {
                for (uint32_t off : offsets) {
                    stack[off].push_back(init_val[off]);
                    pushed.push_back(off);
                }
                continue;
            }
            uint32_t off;
            bool ld, st;
            IrValueId sv;
            if (!classify(in, off, ld, st, sv)) continue;
            if (ld) {
                IrValueId rv = cur(off);
                if (rv == IR_NO_VALUE) {
                    rename_ok = false;
                    rfail = "load sin def alcanzante";
                    return;
                }
                if (in.dst != IR_NO_VALUE) load_repl[in.dst] = rv;
            } else if (st) {
                stack[off].push_back(sv);
                pushed.push_back(off);
            }
        }

        /* (c) rellenar operandos de los phis planeados de los sucesores. */
        for (IrBlockId s : dom.succs[b]) {
            for (uint32_t off : offsets) {
                auto it = phi_value.find(pkey(off, s));
                if (it == phi_value.end()) continue;
                IrValueId rv = cur(off);
                if (rv == IR_NO_VALUE) {
                    rename_ok = false;
                    rfail = "phi operand sin def";
                    return;
                }
                phi_args_plan[it->second].push_back(IrPhiArg{rv, b});
            }
        }

        /* (d) recursion en hijos del dom-tree. */
        for (IrBlockId c : dom.dom_children[b])
            rename(c, depth + 1);

        /* (e) pop. */
        for (auto it = pushed.rbegin(); it != pushed.rend(); ++it)
            stack[*it].pop_back();
    };
    rename(0, 0);
    if (!rename_ok) {
        reason = rfail ? rfail : "rename fallo";
        return false;
    }

    /* ====================================================================
     * 5) APLICAR el plan (todas las precondiciones validadas).
     * ==================================================================== */
    /* (a) Reescribir loads -> MOV del valor reemplazo (copy_prop lo limpia). */
    for (auto &bb : fn.blocks) {
        for (auto &in : bb.instrs) {
            if ((in.op == IrOp::LOAD) && in.dst != IR_NO_VALUE) {
                auto it = load_repl.find(in.dst);
                if (it == load_repl.end()) continue;
                /* Confirmar que es un load de un campo del objeto. */
                uint32_t off;
                bool ld, st;
                IrValueId sv;
                if (!classify(in, off, ld, st, sv) || !ld) continue;
                in.op = IrOp::MOV;
                in.operands.clear();
                in.operands.push_back(it->second);
                in.func_name.clear();
                if (in.dst < fn.values.size())
                    fn.values[in.dst].is_const = false;
                /* De que memoria era se PASA al valor adelantado, no se borra.
                 * Ver  sr_forward_mem_marks: fue asi como el indice 0 de un
                 * buffer salia a basura y el 1 bien. */
                sr_forward_mem_marks(fn, in.dst, it->second);
            }
        }
    }

    /* (b) Insertar los PHIs al frente de sus bloques con sus operandos. */
    for (const auto &kv : phi_dst_off) {
        IrValueId phidst = kv.first;
        uint32_t off = kv.second;
        /* Localizar el bloque (clave inversa: buscar en phi_value). */
        IrBlockId blk = dom.UNDEF;
        for (IrBlockId b = 0; b < N; ++b) {
            auto it = phi_value.find(pkey(off, b));
            if (it != phi_value.end() && it->second == phidst) {
                blk = b;
                break;
            }
        }
        if (blk >= N) continue;
        IrInstr phi;
        phi.op = IrOp::PHI;
        phi.type = field_type[off];
        phi.dst = phidst;
        auto pit = phi_args_plan.find(phidst);
        if (pit != phi_args_plan.end()) phi.phi_args = pit->second;
        fn.blocks[blk].instrs.insert(fn.blocks[blk].instrs.begin(),
                                     std::move(phi));
    }

    /* (c) Eliminar TODOS los stores a campos del objeto (NOP).  Tras mem2reg
     * ningun store es necesario (el valor fluye por SSA).  Se re-localizan por
     * contenido (no por indice) porque (b) inserto phis al frente. */
    for (auto &bb : fn.blocks) {
        for (auto &in : bb.instrs) {
            uint32_t off;
            bool ld, st;
            IrValueId sv;
            if (in.op == IrOp::STORE && classify(in, off, ld, st, sv) && st) {
                in.op = IrOp::NOP;
                in.operands.clear();
                in.dst = IR_NO_VALUE;
                in.func_name.clear();
            }
        }
    }

    /* (d) GC-mode: insertar init_instrs antes del call + NOPear el call.
     *     stack_mode: NOPear el ALLOCA (dst==obj), sin init_instrs. */
    if (stack_mode) {
        for (auto &bb : fn.blocks) {
            for (auto &in : bb.instrs) {
                if (in.op == IrOp::ALLOCA && in.dst == obj) {
                    in.op = IrOp::NOP;
                    in.operands.clear();
                    in.dst = IR_NO_VALUE;
                    in.func_name.clear();
                    goto done_call;
                }
            }
        }
    } else
        for (auto &bb : fn.blocks) {
            for (size_t ii = 0; ii < bb.instrs.size(); ++ii) {
                IrInstr &in = bb.instrs[ii];
                if (in.op == IrOp::CALL && in.dst == obj &&
                    is_new_helper_name(in.func_name, nullptr)) {
                    /* Insertar init_instrs justo antes. */
                    if (!init_instrs.empty()) {
                        bb.instrs.insert(bb.instrs.begin() + ii,
                                         init_instrs.begin(),
                                         init_instrs.end());
                        ii += init_instrs.size();
                    }
                    IrInstr &call = bb.instrs[ii];
                    call.op = IrOp::NOP;
                    call.operands.clear();
                    call.dst = IR_NO_VALUE;
                    call.func_name.clear();
                    goto done_call;
                }
            }
        }
done_call:;

    /* (e) NOPear las field-addr (add obj, K) -- ahora muertas. */
    for (auto &bb : fn.blocks) {
        for (auto &in : bb.instrs) {
            if (in.op == IrOp::ADD && in.dst != IR_NO_VALUE &&
                fieldaddr_off.count(in.dst)) {
                in.op = IrOp::NOP;
                in.operands.clear();
                in.dst = IR_NO_VALUE;
                in.func_name.clear();
            }
        }
    }

    /* (f) compactar NOPs sin dst/operandos. */
    for (auto &bb : fn.blocks) {
        auto &is = bb.instrs;
        is.erase(std::remove_if(is.begin(), is.end(),
                                [](const IrInstr &i) {
                                    return i.op == IrOp::NOP &&
                                           i.operands.empty() &&
                                           i.dst == IR_NO_VALUE;
                                }),
                 is.end());
    }
    return true;
}
} // namespace

/**
 * @brief  C2.13: Scalar Replacement de objetos GC no-escapantes.
 *
 * Elimina los `new X()` que no escapan y cuyo ctor es un inicializador
 * trivial de campos, reemplazando los field-reads por los valores de
 * construccion.  Resultado: el alloc GC desaparece por completo (tanto en
 * interp como en JIT, porque ambos consumen el mismo IR optimizado).
 *
 * Conservador por diseno: cada sitio se transforma SOLO si todas las
 * precondiciones de seguridad se cumplen; en caso de duda, no se toca.
 *
 * @return true si se transformo algun sitio.
 */
bool ir_pass_scalar_replace_gc(IrFunction &fn, const IrModule &mod) {
    if (fn.is_native || fn.values.empty()) return false;

    auto sites = analyze_gc_escape(fn);
    if (sites.empty()) return false;

    static const bool dbg = util::flag_on(util::FlagId::EscapeDebug);
    auto diag = [&](const GcAllocSite &s, const std::string &why) {
        if (dbg)
            std::fprintf(
                stderr,
                "[escape] fn '%s': new %s() (dst %%%u) NO transformado: %s\n",
                fn.name.c_str(), s.class_name.c_str(),
                static_cast<unsigned>(s.dst), why.c_str());
    };

    /* Cache de modelos de ctor por clase (validos e invalidos) + razon. */
    struct CachedModel {
        SrCtorModel m;
        std::string reason;
    };
    std::unordered_map<std::string, CachedModel> model_cache;
    auto get_model = [&](const std::string &cls,
                         std::string &out_reason) -> const SrCtorModel * {
        auto it = model_cache.find(cls);
        if (it == model_cache.end()) {
            CachedModel cm;
            sr_build_ctor_model(mod, cls, cm.m, &cm.reason);
            it = model_cache.emplace(cls, std::move(cm)).first;
        }
        out_reason = it->second.reason;
        return it->second.m.valid ? &it->second.m : nullptr;
    };

    bool changed = false;

    for (const auto &site : sites) {
        if (site.escapes) continue;
        const IrValueId obj = site.dst;

        std::string mreason;
        const SrCtorModel *model = get_model(site.class_name, mreason);
        if (!model) {
            diag(site, "ctor: " + mreason);
            continue;
        }

        /* La instr del CALL seed (para leer sus args + NOPearla luego). */
        if (site.block_idx >= fn.blocks.size()) continue;
        auto &seed_blk = fn.blocks[site.block_idx];
        if (site.ins_idx >= seed_blk.instrs.size()) continue;
        IrInstr &call_ins = seed_blk.instrs[site.ins_idx];
        if (call_ins.op != IrOp::CALL || call_ins.dst != obj) continue;
        const std::vector<IrValueId> args = call_ins.operands; /* copia */
        if (args.size() != model->num_new_args) continue; /* arity mismatch */

        /* --- Recolectar TODOS los usos de obj.  Deben ser solo
         * `add.ptr obj, Kconst` (direccion de campo) o `load obj` (offset 0).
         * Cada field-addr solo puede usarse en LOADs.  Si algo no encaja ->
         * abortar este sitio (no transformar). --- */
        struct LoadRef {
            size_t bi;
            size_t ii;
            uint32_t off;
        };
        struct StoreRef {
            size_t ii;
            uint32_t off;
        };
        std::vector<LoadRef> loads; /* loads a reescribir */
        std::vector<std::pair<size_t, size_t>> dead_addr; /* add.ptr a NOPear */
        std::vector<std::pair<size_t, size_t>>
            dead_free; /* raw_free(obj) a NOPear (native_poo) */
        std::unordered_map<IrValueId, uint32_t>
            fieldaddr_off; /* addr_vid -> off */
        bool ok = true;
        bool single_block = true; /* todos los usos en el bloque del call */
        bool has_writes = false;  /* algun STORE a un campo del objeto */
        const char *use_reason = "uso no soportado de obj";

        /* Helper: lee el offset const de un `add.ptr obj, K`. */
        auto const_value_of = [&](IrValueId v, uint64_t &out_k) -> bool {
            if (v == IR_NO_VALUE || v >= fn.values.size()) return false;
            if (fn.values[v].is_const) {
                out_k = fn.values[v].const_val;
                return true;
            }
            /* Buscar la CONST que produjo v. */
            for (const auto &b : fn.blocks)
                for (const auto &in : b.instrs)
                    if (in.dst == v && in.op == IrOp::CONST) {
                        out_k = in.imm;
                        return true;
                    }
            return false;
        };

        /* Pasada A: localizar field-addrs derivadas de obj + loads/stores
         * directos (offset 0).  Trackea single_block + has_writes. */
        for (size_t bi = 0; bi < fn.blocks.size() && ok; ++bi) {
            const auto &b = fn.blocks[bi];
            for (size_t ii = 0; ii < b.instrs.size() && ok; ++ii) {
                const auto &in = b.instrs[ii];
                /* obj usado en phi_args o func_ptr -> uso no modelable como
                 * field-access (p.ej. `x = phi(a, b)`).  El escape analysis lo
                 * considera no-escapante pero el transform no sabe materializar
                 * el campo a traves de un merge -> abortar (necesitaria SROA
                 * con PHI de los valores de campo). */
                bool bad_use = false;
                for (const auto &pa : in.phi_args)
                    if (pa.value == obj) {
                        bad_use = true;
                        break;
                    }
                if (in.func_ptr == obj) bad_use = true;
                if (bad_use) {
                    ok = false;
                    use_reason =
                        "obj usado en PHI/func_ptr (necesita SROA con PHI)";
                    break;
                }
                bool uses_obj = false;
                for (auto v : in.operands)
                    if (v == obj) {
                        uses_obj = true;
                        break;
                    }
                if (!uses_obj) continue;

                if (in.op == IrOp::ADD && in.operands.size() == 2 &&
                    in.dst != IR_NO_VALUE) {
                    /* `add obj, Kconst` o `add Kconst, obj`. */
                    if (in.operands[0] == obj && in.operands[1] == obj) {
                        ok = false;
                        use_reason = "obj en ambos operandos de add";
                        break;
                    }
                    IrValueId other = (in.operands[0] == obj) ? in.operands[1]
                                                              : in.operands[0];
                    uint64_t k;
                    if (!const_value_of(other, k)) {
                        ok = false;
                        use_reason = "field-addr con offset no-const";
                        break;
                    }
                    fieldaddr_off[in.dst] = static_cast<uint32_t>(k);
                    dead_addr.push_back({bi, ii});
                    if (bi != site.block_idx) single_block = false;
                } else if (in.op == IrOp::LOAD && !in.operands.empty() &&
                           in.operands[0] == obj) {
                    loads.push_back({bi, ii, 0}); /* load directo -> offset 0 */
                    if (bi != site.block_idx) single_block = false;
                } else if (in.op == IrOp::STORE && in.operands.size() >= 2 &&
                           in.operands[1] == obj && in.operands[0] != obj) {
                    has_writes = true; /* store directo -> offset 0 */
                    if (bi != site.block_idx) single_block = false;
                } else if (in.op == IrOp::RAW_FREE && !in.operands.empty() &&
                           in.operands[0] == obj) {
                    /* free(obj) (native_poo): si escalarizamos, el objeto
                     * deja de existir -> el free es dead.  Lo recolectamos
                     * para NOPearlo en el transform; NO marca uso no-soportado.
                     * El modelo de ctor ya descarta clases con dtor, asi que
                     * aqui el unico efecto del free es liberar el calloc. */
                    dead_free.push_back({bi, ii});
                } else {
                    ok = false;
                    use_reason = "obj usado fuera de field-access "
                                 "(CMP/callvirt/store-val/GEP/...)";
                    break;
                }
            }
        }
        if (!ok) {
            diag(site, use_reason);
            continue;
        }

        /* Pasada B: cada field-addr solo puede usarse en LOAD o STORE-addr.
         * Recolecta loads + marca has_writes; trackea single_block. */
        for (size_t bi = 0; bi < fn.blocks.size() && ok; ++bi) {
            const auto &b = fn.blocks[bi];
            for (size_t ii = 0; ii < b.instrs.size() && ok; ++ii) {
                const auto &in = b.instrs[ii];
                /* field-addr usada en phi_args/func_ptr -> no soportado. */
                for (const auto &pa : in.phi_args)
                    if (fieldaddr_off.count(pa.value)) {
                        ok = false;
                        break;
                    }
                if (in.func_ptr != IR_NO_VALUE &&
                    fieldaddr_off.count(in.func_ptr))
                    ok = false;
                if (!ok) {
                    use_reason = "field-addr usada en PHI/func_ptr";
                    break;
                }
                /* Es field-addr operando de esta instr? */
                bool touches_fa = false;
                IrValueId fav = IR_NO_VALUE;
                uint32_t foff = 0;
                for (auto v : in.operands) {
                    auto it = fieldaddr_off.find(v);
                    if (it != fieldaddr_off.end()) {
                        touches_fa = true;
                        fav = v;
                        foff = it->second;
                        break;
                    }
                }
                if (!touches_fa) continue;

                if (in.op == IrOp::LOAD && !in.operands.empty() &&
                    in.operands[0] == fav) {
                    loads.push_back({bi, ii, foff});
                    if (bi != site.block_idx) single_block = false;
                } else if (in.op == IrOp::STORE && in.operands.size() >= 2 &&
                           in.operands[1] == fav && in.operands[0] != fav) {
                    /* field-write: la field-addr es la DIRECCION (operand 1),
                     * no el valor.  Si la field-addr fuera el VALOR -> escape.
                     */
                    has_writes = true;
                    if (bi != site.block_idx) single_block = false;
                } else {
                    ok = false;
                    use_reason =
                        "field-addr usado por op no-LOAD/STORE (o como valor)";
                }
            }
        }
        if (!ok) {
            diag(site, use_reason);
            continue;
        }

        /* ====================================================================
         * Caso A: SIN escrituras -> path read-only (cross-block OK).
         * Reemplaza cada load por el valor de construccion del campo. */
        if (!has_writes) {
            struct PendingRewrite {
                size_t bi;
                size_t ii;
                const SrFieldInit *fi;
            };
            std::vector<PendingRewrite> pending;
            for (const auto &lr : loads) {
                const SrFieldInit *fi = model->find(lr.off);
                IrInstr &probe = fn.blocks[lr.bi].instrs[lr.ii];
                if (!fi) {
                    /* Read de la cabecera del objeto (class_ptr offset 0,
                     * etc.): NO es default-0 (lo pone NEWOBJ).  Tratar como
                     * antes: bail (protege identidad/reflexion -- getClass lee
                     * offset 0). */
                    if (lr.off < SR_OBJ_HEADER_SIZE) {
                        ok = false;
                        use_reason = "lectura de cabecera del objeto no "
                                     "inicializada (identidad/class_ptr)";
                        break;
                    }
                    /* Campo de usuario no inicializado por el ctor -> default-0
                     * (el objeto GC se zero-inicializa al alocar). */
                    if (!sr_rewrite_load_zero(probe, fn, /*apply=*/false)) {
                        ok = false;
                        use_reason =
                            "default-0 de tipo no soportado (float/ptr/handle)";
                        break;
                    }
                    pending.push_back({lr.bi, lr.ii, nullptr});
                    continue;
                }
                if (!sr_rewrite_load(probe, *fi, args, fn, /*apply=*/false)) {
                    ok = false;
                    use_reason = "tipo de campo no soportado "
                                 "(float/ptr/handle/widening)";
                    break;
                }
                pending.push_back({lr.bi, lr.ii, fi});
            }
            if (!ok) {
                diag(site, use_reason);
                continue;
            }

            for (const auto &pr : pending) {
                IrInstr &ld = fn.blocks[pr.bi].instrs[pr.ii];
                if (pr.fi)
                    sr_rewrite_load(ld, *pr.fi, args, fn, /*apply=*/true);
                else
                    sr_rewrite_load_zero(ld, fn, /*apply=*/true);
            }
            for (const auto &da : dead_addr) {
                IrInstr &ai = fn.blocks[da.first].instrs[da.second];
                ai.op = IrOp::NOP;
                ai.operands.clear();
                ai.dst = IR_NO_VALUE;
                ai.func_name.clear();
            }
            for (const auto &df : dead_free) {
                IrInstr &fi = fn.blocks[df.first].instrs[df.second];
                fi.op = IrOp::NOP;
                fi.operands.clear();
                fi.dst = IR_NO_VALUE;
                fi.func_name.clear();
            }
            call_ins.op = IrOp::NOP;
            call_ins.operands.clear();
            call_ins.dst = IR_NO_VALUE;
            call_ins.func_name.clear();
            changed = true;
            continue;
        }

        /* ====================================================================
         * Caso B: CON escrituras.
         *
         * B.1 single-block -> field versioning LINEAL: un walk lineal hace
         *     store-to-load forwarding, elimina los stores y borra el alloc.
         *
         * B.2 cross-block / loop -> SROA/mem2reg: promueve los campos a SSA con
         *     insercion de PHI (Cytron) + renaming.
         *
         *     Default-on con COST-MODEL: el propio @c sr_mem2reg_object baila
         * si promover añadiria un if-merge PHI DENTRO de un loop (= escritura
         *     condicional de campo en el loop), que pessimiza el interp (16
         *     registros VM -> copies + presion).  Los casos que SI promueve son
         *     win (acumuladores incondicionales en loop: +14..41% interp;
         * cross- block fuera de loops: coste unico + elimina el alloc).
         *     VESTA_NO_ESCAPE_MEM2REG=1 lo desactiva entero;
         *     VESTA_ESCAPE_MEM2REG_FORCE=1 ignora el cost-model. */
        if (!single_block) {
            static const bool mem2reg_off =
                util::flag_on(util::FlagId::NoEscapeMem2Reg);
            if (!mem2reg_off) {
                std::string mr;
                if (sr_mem2reg_object(fn, model, site.block_idx, site.ins_idx,
                                      obj, args, fieldaddr_off, mr)) {
                    changed = true;
                    continue;
                }
                diag(site, "mem2reg: " + mr);
            } else {
                diag(site, "field-write cross-block (mem2reg off)");
            }
            continue;
        }
        {
            auto &blkv = fn.blocks[site.block_idx].instrs;
            /* DRY-RUN: simular current[offset] en orden de bloque + validar. */
            struct LdPlan {
                size_t ii;
                bool from_store;
                IrValueId stored;
                const SrFieldInit *fi;
                bool zero_init;
            };
            std::vector<LdPlan> ld_plan;
            std::vector<size_t> store_iis;
            std::unordered_map<uint32_t, IrValueId>
                sim; /* offset -> ultimo valor escrito */
            const char *vreason = "versioning";
            bool vok = true;

            for (size_t ii = 0; ii < blkv.size() && vok; ++ii) {
                const auto &in = blkv[ii];
                uint32_t off = 0;
                bool is_ld = false, is_st = false;
                IrValueId sval = IR_NO_VALUE;
                if (in.op == IrOp::LOAD && !in.operands.empty()) {
                    IrValueId addr = in.operands[0];
                    if (addr == obj) {
                        off = 0;
                        is_ld = true;
                    } else {
                        auto it = fieldaddr_off.find(addr);
                        if (it != fieldaddr_off.end()) {
                            off = it->second;
                            is_ld = true;
                        }
                    }
                } else if (in.op == IrOp::STORE && in.operands.size() >= 2) {
                    IrValueId addr = in.operands[1];
                    if (addr == obj) {
                        off = 0;
                        is_st = true;
                        sval = in.operands[0];
                    } else {
                        auto it = fieldaddr_off.find(addr);
                        if (it != fieldaddr_off.end()) {
                            off = it->second;
                            is_st = true;
                            sval = in.operands[0];
                        }
                    }
                }
                if (is_ld) {
                    /* Solo enteros: el forwarding via MOV de un valor float/
                     * ptr/handle podria mezclar bancos GP/ZMM en codegen.
                     * Consistente con el path read-only (int-only). */
                    if (!type_is_integer(in.type)) {
                        vok = false;
                        vreason = "campo no-entero con field-write "
                                  "(float/ptr/handle)";
                        break;
                    }
                    auto sit = sim.find(off);
                    if (sit != sim.end()) {
                        /* forward del ultimo store: el tipo del valor debe
                         * coincidir con el tipo leido. */
                        IrValueId v = sit->second;
                        if (v == IR_NO_VALUE || v >= fn.values.size() ||
                            fn.values[v].type != in.type) {
                            vok = false;
                            vreason = "tipo store/load no coincide";
                            break;
                        }
                        ld_plan.push_back({ii, true, v, nullptr, false});
                    } else {
                        /* primer load del campo: valor de construccion. */
                        const SrFieldInit *fi = model->find(off);
                        if (!fi) {
                            /* read de cabecera (class_ptr offset 0, etc.) NO es
                             * default-0 -> bail (protege identidad/reflexion).
                             */
                            if (off < SR_OBJ_HEADER_SIZE) {
                                vok = false;
                                vreason = "lectura de cabecera no inicializada "
                                          "(identidad/class_ptr)";
                                break;
                            }
                            /* campo de usuario no inicializado -> default-0
                             * (el objeto GC se zero-inicializa al alocar). */
                            IrInstr probe =
                                blkv[ii]; /* copia: apply=false no muta */
                            if (!sr_rewrite_load_zero(probe, fn,
                                                      /*apply=*/false)) {
                                vok = false;
                                vreason = "default-0 de tipo no soportado "
                                          "(float/ptr/handle)";
                                break;
                            }
                            ld_plan.push_back(
                                {ii, false, IR_NO_VALUE, nullptr, true});
                        } else {
                            IrInstr probe =
                                blkv[ii]; /* copia: apply=false no muta */
                            if (!sr_rewrite_load(probe, *fi, args, fn,
                                                 /*apply=*/false)) {
                                vok = false;
                                vreason = "tipo de campo no soportado "
                                          "(float/ptr/handle/widening)";
                                break;
                            }
                            ld_plan.push_back(
                                {ii, false, IR_NO_VALUE, fi, false});
                        }
                    }
                } else if (is_st) {
                    sim[off] = sval;
                    store_iis.push_back(ii);
                }
            }
            if (!vok) {
                diag(site, vreason);
                continue;
            }

            /* APLICAR: reescribir loads, NOPear stores + field-addrs + call. */
            for (const auto &lp : ld_plan) {
                IrInstr &ld = blkv[lp.ii];
                if (lp.from_store) {
                    ld.op = IrOp::MOV;
                    ld.operands.clear();
                    ld.operands.push_back(lp.stored);
                    ld.func_name.clear();
                    if (ld.dst != IR_NO_VALUE && ld.dst < fn.values.size())
                        fn.values[ld.dst].is_const = false;
                    sr_forward_mem_marks(fn, ld.dst, lp.stored);
                } else if (lp.zero_init) {
                    sr_rewrite_load_zero(ld, fn, /*apply=*/true);
                } else {
                    sr_rewrite_load(ld, *lp.fi, args, fn, /*apply=*/true);
                }
            }
            for (size_t sii : store_iis) {
                IrInstr &st = blkv[sii];
                st.op = IrOp::NOP;
                st.operands.clear();
                st.dst = IR_NO_VALUE;
                st.func_name.clear();
            }
            for (const auto &da : dead_addr) {
                IrInstr &ai = fn.blocks[da.first].instrs[da.second];
                ai.op = IrOp::NOP;
                ai.operands.clear();
                ai.dst = IR_NO_VALUE;
                ai.func_name.clear();
            }
            for (const auto &df : dead_free) {
                IrInstr &fi = fn.blocks[df.first].instrs[df.second];
                fi.op = IrOp::NOP;
                fi.operands.clear();
                fi.dst = IR_NO_VALUE;
                fi.func_name.clear();
            }
            call_ins.op = IrOp::NOP;
            call_ins.operands.clear();
            call_ins.dst = IR_NO_VALUE;
            call_ins.func_name.clear();
            changed = true;
        }
    }

    /* Compactar NOPs introducidos (mismo patron que promote_local_raw_alloc).
     */
    if (changed) {
        for (auto &blk : fn.blocks) {
            auto &is = blk.instrs;
            is.erase(std::remove_if(is.begin(), is.end(),
                                    [](const IrInstr &i) {
                                        return i.op == IrOp::NOP &&
                                               i.operands.empty() &&
                                               i.dst == IR_NO_VALUE;
                                    }),
                     is.end());
        }
    }

    return changed;
}

// =========================================================================
//  Pase ir_pass_sroa_stack_structs -- SROA/mem2reg de structs value-type en
//  PILA (ALLOCA), analogo a ir_pass_scalar_replace_gc pero sembrado en un
//  ALLOCA en vez de un `new`.
//
//  Motivacion (bench struct_field 8.88x vs C): `Vec3 v = {..}; while(..) {
//  v.x = v.x+1; ... }` mantiene los campos en MEMORIA (load/add/store por
//  iteracion) mientras C los promueve a registros.  Este pase escalariza cada
//  campo (offset) del ALLOCA no-capturado a forma SSA (PHIs en la frontera de
//  dominancia + renaming Cytron), eliminando todos los load/store del loop.
//
//  Precondicion (whitelist estricto, MAS fuerte que "no escapa"): TODOS los
//  usos del ALLOCA son field-access con offset CONSTANTE (`load base`,
//  `store _, base`, o `add base, Kconst` seguido de load/store).  Cualquier
//  otro uso (CALL, MEMCPY, PHI, func_ptr, comparacion, store-como-valor,
//  index no-const) -> bail para ese ALLOCA.  El whitelist garantiza que
//  vemos y podemos reemplazar TODOS los accesos a esa memoria.
//
//  Coste natural: nivel IR (la info -- offsets constantes + no-captura -- solo
//  existe aqui; el codegen maquina ya no sabe que el struct no escapa).
//  Reusa toda la maquina de sr_mem2reg_object (stack_mode=true).
// =========================================================================
bool ir_pass_sroa_stack_structs(IrFunction &fn) {
    if (fn.is_native || fn.values.empty()) return false;
    static const bool sroa_off = util::flag_on(util::FlagId::NoSroaStack);
    if (sroa_off) return false;

    // GUARD SOUND: si la funcion tiene control de excepcion LOCAL
    // (TRYENTER/LANDINGPAD -> catch handler), el CFG de sr_compute_dom NO
    // modela la arista implicita `try-region -> handler`.  Un campo escrito
    // antes de un punto que puede lanzar y leido en el catch parece tener def
    // alcanzante por el edge normal, pero en el path de excepcion NO lo tiene
    // -> mem2reg produciria un valor equivocado en el handler.  Bail la fn
    // entera (los hot loops de perf no tienen try/catch; la ganancia se
    // preserva).  Cuando el CFG modele aristas de excepcion, se puede afinar.
    for (const auto &b : fn.blocks)
        for (const auto &in : b.instrs)
            if (in.op == IrOp::TRYENTER || in.op == IrOp::LANDINGPAD ||
                in.op == IrOp::RETHROW)
                return false;

    static const bool dbg = util::flag_on(util::FlagId::EscapeDebug);
    bool changed = false;

    // Recolectar ALLOCAs candidatos (dst valido, no ya host_alloca -- esos van
    // a host-stack por pasar a CALLN y el whitelist los descartaria igual).
    struct AllocSite {
        size_t bi, ii;
        IrValueId base;
    };
    std::vector<AllocSite> sites;
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto &b = fn.blocks[bi];
        for (size_t ii = 0; ii < b.instrs.size(); ++ii) {
            const auto &in = b.instrs[ii];
            // NO filtramos host_alloca: en AOT el auto-promote marca las
            // ALLOCAs locales como host-stack, y son justamente las que
            // queremos escalarizar.  Si el ALLOCA escapa de verdad (p.ej. a
            // CALLN), el whitelist de usos baila mas abajo.
            if (in.op == IrOp::ALLOCA && in.dst != IR_NO_VALUE)
                sites.push_back({bi, ii, in.dst});
        }
    }
    if (sites.empty()) return false;

    // Helper: lee el offset const de `add base, K` (o `add K, base`).
    auto const_value_of = [&](IrValueId v, uint64_t &out_k) -> bool {
        if (v == IR_NO_VALUE || v >= fn.values.size()) return false;
        if (fn.values[v].is_const) {
            out_k = fn.values[v].const_val;
            return true;
        }
        for (const auto &b : fn.blocks)
            for (const auto &in : b.instrs)
                if (in.dst == v && in.op == IrOp::CONST) {
                    out_k = in.imm;
                    return true;
                }
        return false;
    };

    for (const auto &site : sites) {
        const IrValueId base = site.base;

        // --- Whitelist de usos (identico en espiritu al de scalar_replace_gc):
        // field-addr (`add base, Kconst`) o load/store directo (offset 0);
        // cada field-addr solo en load/store-addr.  Cualquier otro uso -> bail.
        std::unordered_map<IrValueId, uint32_t> fieldaddr_off;
        bool ok = true, has_writes = false;
        const char *why = "uso no soportado";

        // Pasada A: field-addrs + load/store directos sobre `base`.
        for (size_t bi = 0; bi < fn.blocks.size() && ok; ++bi) {
            const auto &b = fn.blocks[bi];
            for (size_t ii = 0; ii < b.instrs.size() && ok; ++ii) {
                const auto &in = b.instrs[ii];
                // base en phi_args / func_ptr -> captura no modelable.
                for (const auto &pa : in.phi_args)
                    if (pa.value == base) {
                        ok = false;
                        why = "base en PHI";
                    }
                if (in.func_ptr == base) {
                    ok = false;
                    why = "base en func_ptr";
                }
                if (!ok) break;
                bool uses_base = false;
                for (auto v : in.operands)
                    if (v == base) {
                        uses_base = true;
                        break;
                    }
                if (!uses_base) continue;
                if (in.op == IrOp::ADD && in.operands.size() == 2 &&
                    in.dst != IR_NO_VALUE && in.operands[0] != in.operands[1]) {
                    IrValueId other = (in.operands[0] == base) ? in.operands[1]
                                                               : in.operands[0];
                    uint64_t k;
                    if (!const_value_of(other, k)) {
                        ok = false;
                        why = "field-addr offset no-const";
                        break;
                    }
                    fieldaddr_off[in.dst] = (uint32_t)k;
                } else if (in.op == IrOp::LOAD && !in.operands.empty() &&
                           in.operands[0] == base) {
                    // load directo (offset 0) -- ok.
                } else if (in.op == IrOp::STORE && in.operands.size() >= 2 &&
                           in.operands[1] == base && in.operands[0] != base) {
                    has_writes = true; // store directo (offset 0)
                } else {
                    ok = false;
                    why = "base fuera de field-access (CALL/CMP/store-val/...)";
                    break;
                }
            }
        }
        // Pasada B: cada field-addr solo en LOAD o STORE-addr.
        for (size_t bi = 0; bi < fn.blocks.size() && ok; ++bi) {
            const auto &b = fn.blocks[bi];
            for (size_t ii = 0; ii < b.instrs.size() && ok; ++ii) {
                const auto &in = b.instrs[ii];
                for (const auto &pa : in.phi_args)
                    if (fieldaddr_off.count(pa.value)) {
                        ok = false;
                    }
                if (in.func_ptr != IR_NO_VALUE &&
                    fieldaddr_off.count(in.func_ptr))
                    ok = false;
                if (!ok) {
                    why = "field-addr en PHI/func_ptr";
                    break;
                }
                IrValueId fav = IR_NO_VALUE;
                for (auto v : in.operands)
                    if (fieldaddr_off.count(v)) {
                        fav = v;
                        break;
                    }
                if (fav == IR_NO_VALUE) continue;
                if (in.op == IrOp::LOAD && !in.operands.empty() &&
                    in.operands[0] == fav) {
                    // ok
                } else if (in.op == IrOp::STORE && in.operands.size() >= 2 &&
                           in.operands[1] == fav && in.operands[0] != fav) {
                    has_writes = true;
                } else {
                    ok = false;
                    why = "field-addr en op no-LOAD/STORE (o como valor)";
                }
            }
        }
        if (!ok) {
            if (dbg)
                std::fprintf(stderr,
                             "[sroa-stack] fn '%s': ALLOCA %%%u NO: %s\n",
                             fn.name.c_str(), (unsigned)base, why);
            continue;
        }
        // Sin escrituras => struct de pila leido sin inicializar (undef) O
        // escalar que promote_local_allocas ya cubre -> nada que ganar.
        if (!has_writes) continue;

        std::string mr;
        // args vacio (stack_mode ignora el modelo/args); model = nullptr.
        if (sr_mem2reg_object(fn, /*model=*/nullptr, site.bi, site.ii, base,
                              /*args=*/{}, fieldaddr_off, mr,
                              /*stack_mode=*/true)) {
            changed = true;
        } else if (dbg) {
            std::fprintf(stderr,
                         "[sroa-stack] fn '%s': ALLOCA %%%u mem2reg: %s\n",
                         fn.name.c_str(), (unsigned)base, mr.c_str());
        }
    }
    return changed;
}

// =========================================================================
//  Pase ir_pass_simplify
// =========================================================================
//
// Aplica identidades algebraicas, plegado de constantes a traves de
// casts, y simplificacion de phis triviales.  Beneficia IGUAL al JIT
// (menos instrucciones emitidas) y a los port targets (codigo C mas
// limpio).
//
// Patrones reconocidos:
//   (A) Algebraic identities:
//       add x, 0     -> x
//       sub x, 0     -> x
//       mul x, 1     -> x
//       mul x, 0     -> 0
//       and x, 0     -> 0
//       and x, -1    -> x
//       or  x, 0     -> x
//       or  x, -1    -> -1
//       xor x, 0     -> x
//       sub x, x     -> 0
//       xor x, x     -> 0
//       shl x, 0, shr x, 0, sar x, 0 -> x
//
//   (B) Cast de constantes:
//       sext.T (const.U K)   -> const.T sign_extend(K)
//       zext.T (const.U K)   -> const.T zero_extend(K)
//       trunc.T (const.U K)  -> const.T K & mask(T)
//       bitcast.T (const.U K) -> const.T K  (mismo ancho ya)
//       cast.T (const.U K)   -> const.T K   (best-effort)
//
//   (C) Phi simplification:
//       %a = phi(b, b, b)   -> %a = mov b   (todos iguales)
//       %a = phi(a, x, y)   -> ignorar self-ref; si solo queda 1 unique -> %a =
//       mov ese
//
// Helpers para Trabajar con CONST + sus valores.

namespace {
bool is_const_with_value(const IrFunction &fn, IrValueId vid, int64_t &out) {
    if (vid == IR_NO_VALUE) return false;
    /* Solo CONST inicializa SSA con un imm conocido.  Buscar la instr
     * que produjo @p vid en cualquier bloque. */
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.dst == vid && ins.op == IrOp::CONST) {
                out = static_cast<int64_t>(ins.imm);
                return true;
            }
        }
    }
    return false;
}

/* La mascara de truncado y el signo del tipo salen del vocabulario unico
 * (ir/ir_type_info.h); aqui habia otra copia de ambas tablas. */

/** @brief Sign-extiende @p v desde @p from_t a 64-bit. */
int64_t sign_extend_from(int64_t v, IrType from_t) {
    switch (from_t) {
    case IrType::I8: return static_cast<int8_t>(v);
    case IrType::I16: return static_cast<int16_t>(v);
    case IrType::I32: return static_cast<int32_t>(v);
    default: return v;
    }
}

/** @brief Sustituye @p ins por un MOV de @p src_vid (mantiene dst).
 *  Devuelve true. */
void rewrite_as_mov(IrInstr &ins, IrValueId src_vid) {
    ins.op = IrOp::MOV;
    ins.operands.clear();
    ins.operands.push_back(src_vid);
    ins.phi_args.clear();
    ins.imm = 0;
    ins.func_name.clear();
    ins.func_ptr = IR_NO_VALUE;
    ins.target_block = IR_NO_BLOCK;
    ins.false_block = IR_NO_BLOCK;
}

/** @brief Convierte @p ins en un CONST con valor @p imm.  No cambia tipo. */
void rewrite_as_const(IrInstr &ins, uint64_t imm) {
    ins.op = IrOp::CONST;
    ins.imm = imm;
    ins.operands.clear();
    ins.phi_args.clear();
    ins.func_name.clear();
    ins.func_ptr = IR_NO_VALUE;
    ins.target_block = IR_NO_BLOCK;
    ins.false_block = IR_NO_BLOCK;
}

/** @brief Como @c rewrite_as_const pero ademas marca @c is_const + @c const_val
 *         en el @c IrValue correspondiente para que consumers downstream
 *         (regalloc/selector imm32 fold) detecten la constante. */
void rewrite_as_const_with_value(IrFunction &fn, IrInstr &ins, uint64_t imm) {
    rewrite_as_const(ins, imm);
    if (ins.dst != IR_NO_VALUE && ins.dst < fn.values.size()) {
        fn.values[ins.dst].is_const = true;
        fn.values[ins.dst].const_val = imm;
    }
}
} // namespace

// ==========================================================================
//  Pase ir_pass_fuse_fma -- contraccion fmul+fadd -> FMA (round(a*b+c))
// ==========================================================================
//
// Solo en funciones @fp(fast) (fn.fp_contract).  Semantica: FMA = 1 SOLO
// redondeo (distinto de fmul+fadd = 2).  Es una transformacion fast-math, por
// eso va gated por la politica FP.  Se decide UNA vez aqui (IR compartido) para
// que interp/JIT/AOT queden consistentes (todos 1 redondeo).
//
// Patron: `%t = fmul a,b` (SINGLE-USE, mismo tipo float) + `%d = fadd %t,c`
// (o conmutado `fadd c,%t`) -> `%d = fma a,b,c`.  El fmul queda muerto -> DCE.
// Single-use garantiza que el valor intermedio redondeado no se observa en
// ningun otro sitio (correcto contraer).  Coordinado con ir_pass_simplify: este
// pase corre DESPUES de simplify (que ya elimino a*0/a*1/+0), asi opera sobre
// los fmul+fadd genuinos.
// Gate global del driver: el pase solo contrae si el TARGET puede materializar
// el FMA sin divergencia.  velb (interp+JIT) = true (el JIT emite VFMADD si el
// host tiene FMA, o cae a interp/std::fma).  AOT lo pone = target.caps.fma (si
// el target no tiene FMA, no se crean nodos FMA -> AOT nunca ve lo que no puede
// emitir).  Default true.
static bool g_fma_contract_allowed = true;

void ir_set_fma_contract_allowed(bool v) {
    g_fma_contract_allowed = v;
}

bool ir_fma_contract_allowed() {
    return g_fma_contract_allowed;
}

bool ir_pass_fuse_fma(IrFunction &fn) {
    if (!fn.fp_contract || !g_fma_contract_allowed || fn.is_native)
        return false;
    const size_t nv = fn.values.size();
    if (nv == 0) return false;
    std::vector<int> uc(nv, 0);
    std::vector<IrInstr *> def_fmul(nv, nullptr);
    for (auto &bb : fn.blocks) {
        for (auto &in : bb.instrs) {
            for (IrValueId op : in.operands)
                if (op != IR_NO_VALUE && static_cast<size_t>(op) < nv) uc[op]++;
            for (auto &pa : in.phi_args)
                if (pa.value != IR_NO_VALUE &&
                    static_cast<size_t>(pa.value) < nv)
                    uc[pa.value]++;
            if (in.op == IrOp::FMUL && in.dst != IR_NO_VALUE &&
                static_cast<size_t>(in.dst) < nv && in.operands.size() >= 2)
                def_fmul[in.dst] = &in;
        }
    }
    bool changed = false;
    for (auto &bb : fn.blocks) {
        for (auto &in : bb.instrs) {
            if (in.op != IrOp::FADD || in.operands.size() < 2) continue;
            // @fp(strict) inlineado en un caller fast: el fadd copiado del
            // callee strict lleva no_fp_contract -> no fusionar (preservar 2
            // redondeos).
            if (in.no_fp_contract) continue;
            for (int k = 0; k < 2; ++k) {
                const IrValueId t = in.operands[k];
                const IrValueId cval = in.operands[1 - k];
                if (t == IR_NO_VALUE || static_cast<size_t>(t) >= nv) continue;
                if (uc[t] != 1) // %t solo lo usa este fadd
                    continue;
                IrInstr *mul = def_fmul[t];
                if (mul == nullptr || mul->type != in.type) continue;
                if (mul->no_fp_contract) // el fmul tambien debe ser contraible
                    continue;
                const IrValueId a = mul->operands[0];
                const IrValueId b = mul->operands[1];
                in.op = IrOp::FMA;
                in.operands.assign({a, b, cval});
                // El fmul queda muerto (t sin usos) -> lo elimina el DCE.
                changed = true;
                break;
            }
        }
    }
    return changed;
}

// Crea un nuevo SSA value CONST de tipo @c type con valor @c imm y devuelve
// (new_vid, instr).  El caller debe INSERTAR la instr en un bloque (antes del
// uso) para que el IR quede bien-formado.  Version libre de la lambda homonima
// de strength_reduction, usada por ir_pass_narrow_cmp.
static std::pair<IrValueId, IrInstr>
make_new_narrow_const(IrFunction &fn, IrType type, uint64_t imm) {
    const IrValueId new_id = static_cast<IrValueId>(fn.values.size());
    IrValue v{};
    v.id = new_id;
    v.type = type;
    v.name = "%nc" + std::to_string(new_id);
    v.is_const = true;
    v.const_val = imm;
    fn.values.push_back(v);
    IrInstr ci{};
    ci.op = IrOp::CONST;
    ci.type = type;
    ci.dst = new_id;
    ci.imm = imm;
    return {new_id, ci};
}

// ==========================================================================
//  Pase ir_pass_narrow_cmp -- estrechar comparaciones extendidas
// ==========================================================================
//
// El frontend promueve un operando estrecho (i8/i16/i32) a i64 con SEXT/ZEXT
// cuando el otro operando es un literal i64, y compara a 64 bits:
//
//     %c = const.i64 35
//     %s = sext.i64 %a        (%a : i32)
//     %r = cmp.ne.bool %s, %c
//
// Como el backend compara al ANCHO de los operandos (verificado: `i32 == i32`
// emite un compare de 32 bits width-aware, correcto aun con bits altos sucios),
// esto equivale a comparar %a (i32) contra un const.i32 35 -> se elimina el
// SEXT y el const.i64 (los mata el DCE):
//
//     %r = cmp.ne.bool %a, %nc   (%nc = const.i32 35)
//
// Soundness:
//   - EQ/NE: sext(x)==K <=> x==(W)K si K cabe en el rango del ancho W; idem
//   ZEXT.
//   - LT/GT/LE/GE (signed): SEXT preserva el orden con signo -> narrow si K
//   cabe
//     en el rango SIGNED de W.
//   - ULT/UGT/ULE/UGE (unsigned): ZEXT preserva el orden sin signo -> narrow si
//     K cabe en [0, 2^W-1].
//   - cmp(ext(x), ext(y)) con el MISMO kind y ancho -> cmp(x, y) al ancho W.
//   Cualquier caso que no encaje se deja intacto (conservador).
bool ir_pass_narrow_cmp(IrFunction &fn) {
    const size_t nv = fn.values.size();
    if (nv == 0) return false;

    // Mapa de definiciones: por cada value, si es SEXT/ZEXT (con su fuente +
    // ancho) o CONST (con su valor).
    std::vector<IrValueId> ext_src(nv, IR_NO_VALUE);
    std::vector<uint8_t> ext_kind(nv, 0); // 1=SEXT, 2=ZEXT
    std::vector<IrType> src_type(nv, IrType::I64);
    std::vector<int64_t> cval(nv, 0);
    std::vector<uint8_t> is_c(nv, 0);
    for (auto &bb : fn.blocks) {
        for (auto &in : bb.instrs) {
            if (in.dst == IR_NO_VALUE || static_cast<size_t>(in.dst) >= nv)
                continue;
            if ((in.op == IrOp::SEXT || in.op == IrOp::ZEXT) &&
                !in.operands.empty()) {
                const IrValueId s = in.operands[0];
                if (s != IR_NO_VALUE && static_cast<size_t>(s) < nv) {
                    ext_src[in.dst] = s;
                    ext_kind[in.dst] = (in.op == IrOp::SEXT) ? 1 : 2;
                    src_type[in.dst] = fn.values[s].type;
                }
            } else if (in.op == IrOp::CONST) {
                is_c[in.dst] = 1;
                cval[in.dst] = static_cast<int64_t>(in.imm);
            }
        }
    }

    // Ancho en bits de un tipo entero estrecho (0 = no aplicable:
    // i64/u64/no-int).  Lo contesta el vocabulario unico.
    auto narrow_bits = [](IrType t) -> int {
        return static_cast<int>(type_narrow_bits(t));
    };
    auto is_signed_cmp = [](IrOp op) -> bool {
        switch (op) {
        case IrOp::CMP_LT:
        case IrOp::CMP_GT:
        case IrOp::CMP_LE:
        case IrOp::CMP_GE: return true;
        default: return false; // EQ/NE agnostico; U* son unsigned
        }
    };
    auto is_unsigned_cmp = [](IrOp op) -> bool {
        switch (op) {
        case IrOp::CMP_ULT:
        case IrOp::CMP_UGT:
        case IrOp::CMP_ULE:
        case IrOp::CMP_UGE: return true;
        default: return false;
        }
    };
    auto is_eqne = [](IrOp op) -> bool {
        return op == IrOp::CMP_EQ || op == IrOp::CMP_NE;
    };
    // K cabe en el rango representable del ancho W segun el kind del ext.
    auto const_fits = [&](int64_t K, IrType W, uint8_t kind) -> bool {
        const int bits = narrow_bits(W);
        if (bits <= 0 || bits >= 64) return false;
        if (kind == 1) {
            // SEXT: rango con signo [-2^(b-1), 2^(b-1)-1]
            const int64_t lo = -(int64_t{1} << (bits - 1));
            const int64_t hi = (int64_t{1} << (bits - 1)) - 1;
            return K >= lo && K <= hi;
        }
        // ZEXT: rango sin signo [0, 2^b-1]
        if (K < 0) return false;
        const uint64_t hi = (uint64_t{1} << bits) - 1;
        return static_cast<uint64_t>(K) <= hi;
    };

    struct Insertion {
        size_t bb_idx;
        size_t pos;
        IrInstr instr;
    };
    std::vector<Insertion> pending;
    bool changed = false;

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto &bb = fn.blocks[bi];
        for (size_t i = 0; i < bb.instrs.size(); ++i) {
            IrInstr &ins = bb.instrs[i];
            const bool sgn = is_signed_cmp(ins.op);
            const bool uns = is_unsigned_cmp(ins.op);
            const bool eqne = is_eqne(ins.op);
            if (!(sgn || uns || eqne) || ins.operands.size() < 2) continue;
            const IrValueId o0 = ins.operands[0], o1 = ins.operands[1];
            if (o0 == IR_NO_VALUE || o1 == IR_NO_VALUE ||
                static_cast<size_t>(o0) >= nv || static_cast<size_t>(o1) >= nv)
                continue;

            // El kind de ext requerido: signed->SEXT, unsigned->ZEXT, EQ/NE->
            // cualquiera pero CONSISTENTE entre ambos operandos.
            const uint8_t k0 = ext_kind[o0], k1 = ext_kind[o1];

            // --- Caso A: ambos operandos son ext del MISMO kind y ancho. ---
            if (k0 && k1 && k0 == k1 && src_type[o0] == src_type[o1] &&
                narrow_bits(src_type[o0]) > 0) {
                const uint8_t want = sgn ? 1 : (uns ? 2 : k0);
                if (k0 == want) {
                    ins.operands[0] = ext_src[o0];
                    ins.operands[1] = ext_src[o1];
                    changed = true;
                    continue;
                }
            }

            // --- Caso B: un operando es ext, el otro es const que cabe. ---
            IrValueId ext_v = IR_NO_VALUE, const_v = IR_NO_VALUE;
            int ext_pos = -1;
            if (k0 && is_c[o1]) {
                ext_v = o0;
                const_v = o1;
                ext_pos = 0;
            } else if (k1 && is_c[o0]) {
                ext_v = o1;
                const_v = o0;
                ext_pos = 1;
            }
            if (ext_v == IR_NO_VALUE) continue;
            const uint8_t kind = ext_kind[ext_v];
            const uint8_t want = sgn ? 1 : (uns ? 2 : kind);
            if (kind != want)
                continue; // signed cmp necesita SEXT; unsigned necesita ZEXT
            const IrType W = src_type[ext_v];
            if (narrow_bits(W) <= 0) continue;
            const int64_t K = cval[const_v];
            if (!const_fits(K, W, kind)) continue;
            // Reescribir: ext_operand -> fuente estrecha; const -> const.<W> K.
            auto p = make_new_narrow_const(fn, W, static_cast<uint64_t>(K));
            pending.push_back({bi, i, p.second});
            ins.operands[ext_pos] = ext_src[ext_v];
            ins.operands[1 - ext_pos] = p.first;
            changed = true;
        }
    }

    // Insertar los CONST nuevos (de atras hacia delante para no invalidar pos).
    std::sort(pending.begin(), pending.end(),
              [](const Insertion &a, const Insertion &b) {
                  if (a.bb_idx != b.bb_idx) return a.bb_idx > b.bb_idx;
                  return a.pos > b.pos;
              });
    for (const auto &ins : pending) {
        auto &blk = fn.blocks[ins.bb_idx];
        blk.instrs.insert(blk.instrs.begin() + ins.pos, ins.instr);
    }
    return changed;
}

bool ir_pass_simplify(IrFunction &fn) {
    bool changed = false;

    /* Pre-build: vid -> CONST imm (si lo es).  Evita el escaneo lineal
     * dentro del bucle principal. */
    std::unordered_map<IrValueId, int64_t> const_vids;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::CONST && ins.dst != IR_NO_VALUE) {
                const_vids[ins.dst] = static_cast<int64_t>(ins.imm);
            }
        }
    }
    auto get_const = [&](IrValueId v, int64_t &out) -> bool {
        if (v == IR_NO_VALUE) return false;
        auto it = const_vids.find(v);
        if (it == const_vids.end()) return false;
        out = it->second;
        return true;
    };

    /* Mapa value -> instr definidora (para reescrituras estructurales
     * op-sobre-op como fneg(fneg x)->x).  Se lee EN VIVO (def->op actual):
     * simplify reescribe in-place sin redimensionar los vectores, asi que los
     * punteros siguen validos y nunca se toma una op stale. */
    std::unordered_map<IrValueId, IrInstr *> def_of;
    for (auto &bb : fn.blocks)
        for (auto &ins : bb.instrs)
            if (ins.dst != IR_NO_VALUE) def_of[ins.dst] = &ins;

    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            switch (ins.op) {
            /* ---- (A) Algebraic identities ---- */
            case IrOp::ADD: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                if (get_const(ins.operands[1], c) && c == 0) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                } else if (get_const(ins.operands[0], c) && c == 0) {
                    rewrite_as_mov(ins, ins.operands[1]);
                    changed = true;
                }
                break;
            }
            case IrOp::SUB: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                if (get_const(ins.operands[1], c) && c == 0) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                } else if (ins.operands[0] == ins.operands[1]) {
                    rewrite_as_const_with_value(fn, ins, 0);
                    const_vids[ins.dst] = 0;
                    changed = true;
                }
                break;
            }
            case IrOp::MUL: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                if (get_const(ins.operands[1], c)) {
                    if (c == 1) {
                        rewrite_as_mov(ins, ins.operands[0]);
                        changed = true;
                    } else if (c == 0) {
                        rewrite_as_const_with_value(fn, ins, 0);
                        const_vids[ins.dst] = 0;
                        changed = true;
                    }
                } else if (get_const(ins.operands[0], c)) {
                    if (c == 1) {
                        rewrite_as_mov(ins, ins.operands[1]);
                        changed = true;
                    } else if (c == 0) {
                        rewrite_as_const_with_value(fn, ins, 0);
                        const_vids[ins.dst] = 0;
                        changed = true;
                    }
                }
                break;
            }
            case IrOp::DIV: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                /* x / 1 = x */
                if (get_const(ins.operands[1], c) && c == 1) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                } else if (ins.operands[0] == ins.operands[1]) {
                    /* x / x = 1 (cuidado con x = 0 -> division by zero,
                     * pero el codigo SSA implica que ya se ha dividido,
                     * asi que x != 0; seguro reescribir como const 1) */
                    rewrite_as_const_with_value(fn, ins, 1);
                    const_vids[ins.dst] = 1;
                    changed = true;
                }
                break;
            }
            case IrOp::MOD: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                /* x % 1 = 0 */
                if (get_const(ins.operands[1], c) && c == 1) {
                    rewrite_as_const_with_value(fn, ins, 0);
                    const_vids[ins.dst] = 0;
                    changed = true;
                } else if (ins.operands[0] == ins.operands[1]) {
                    /* x % x = 0 (x != 0 implicito) */
                    rewrite_as_const_with_value(fn, ins, 0);
                    const_vids[ins.dst] = 0;
                    changed = true;
                }
                break;
            }
            case IrOp::AND: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                /* commutative: probar ambos operandos */
                if (get_const(ins.operands[1], c)) {
                    if (c == 0) {
                        rewrite_as_const_with_value(fn, ins, 0);
                        const_vids[ins.dst] = 0;
                        changed = true;
                    } else if (c == -1) {
                        rewrite_as_mov(ins, ins.operands[0]);
                        changed = true;
                    }
                } else if (get_const(ins.operands[0], c)) {
                    if (c == 0) {
                        rewrite_as_const_with_value(fn, ins, 0);
                        const_vids[ins.dst] = 0;
                        changed = true;
                    } else if (c == -1) {
                        rewrite_as_mov(ins, ins.operands[1]);
                        changed = true;
                    }
                } else if (ins.operands[0] == ins.operands[1]) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                }
                break;
            }
            case IrOp::OR: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                if (get_const(ins.operands[1], c)) {
                    if (c == 0) {
                        rewrite_as_mov(ins, ins.operands[0]);
                        changed = true;
                    } else if (c == -1) {
                        rewrite_as_const_with_value(fn, ins,
                                                    static_cast<uint64_t>(-1));
                        const_vids[ins.dst] = -1;
                        changed = true;
                    }
                } else if (get_const(ins.operands[0], c)) {
                    if (c == 0) {
                        rewrite_as_mov(ins, ins.operands[1]);
                        changed = true;
                    } else if (c == -1) {
                        rewrite_as_const_with_value(fn, ins,
                                                    static_cast<uint64_t>(-1));
                        const_vids[ins.dst] = -1;
                        changed = true;
                    }
                } else if (ins.operands[0] == ins.operands[1]) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                }
                break;
            }
            case IrOp::XOR: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                if (get_const(ins.operands[1], c) && c == 0) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                } else if (get_const(ins.operands[0], c) && c == 0) {
                    rewrite_as_mov(ins, ins.operands[1]);
                    changed = true;
                } else if (ins.operands[0] == ins.operands[1]) {
                    rewrite_as_const_with_value(fn, ins, 0);
                    const_vids[ins.dst] = 0;
                    changed = true;
                }
                break;
            }
            case IrOp::SHL:
            case IrOp::SHR:
            case IrOp::SAR: {
                if (ins.operands.size() < 2) break;
                int64_t c = 0;
                if (get_const(ins.operands[1], c) && c == 0) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                }
                break;
            }

            /* ---- (B) Cast de constantes ---- */
            case IrOp::SEXT: {
                if (ins.operands.empty()) break;
                /* Identidad: si src_type == dst_type, es un MOV. */
                IrType from_t = (ins.operands[0] < fn.values.size())
                                    ? fn.values[ins.operands[0]].type
                                    : IrType::I64;
                if (from_t == ins.type) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                    break;
                }
                int64_t c = 0;
                if (get_const(ins.operands[0], c)) {
                    int64_t ext = sign_extend_from(c, from_t);
                    rewrite_as_const_with_value(fn, ins,
                                                static_cast<uint64_t>(ext));
                    const_vids[ins.dst] = ext;
                    changed = true;
                }
                break;
            }
            case IrOp::ZEXT: {
                if (ins.operands.empty()) break;
                IrType from_t = (ins.operands[0] < fn.values.size())
                                    ? fn.values[ins.operands[0]].type
                                    : IrType::I64;
                if (from_t == ins.type) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                    break;
                }
                int64_t c = 0;
                if (get_const(ins.operands[0], c)) {
                    uint64_t z = static_cast<uint64_t>(c) & type_mask(from_t);
                    rewrite_as_const_with_value(fn, ins, z);
                    const_vids[ins.dst] = static_cast<int64_t>(z);
                    changed = true;
                }
                break;
            }
            case IrOp::TRUNC: {
                if (ins.operands.empty()) break;
                IrType from_t = (ins.operands[0] < fn.values.size())
                                    ? fn.values[ins.operands[0]].type
                                    : IrType::I64;
                if (from_t == ins.type) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                    break;
                }
                int64_t c = 0;
                if (get_const(ins.operands[0], c)) {
                    uint64_t m = type_mask(ins.type);
                    uint64_t v = static_cast<uint64_t>(c) & m;
                    /* Si el tipo destino es signed, sign-extender de
                     * vuelta a i64 para preservar el valor logico. */
                    int64_t out_val;
                    if (type_is_signed(ins.type)) {
                        out_val =
                            sign_extend_from(static_cast<int64_t>(v), ins.type);
                    } else {
                        out_val = static_cast<int64_t>(v);
                    }
                    rewrite_as_const_with_value(fn, ins,
                                                static_cast<uint64_t>(out_val));
                    const_vids[ins.dst] = out_val;
                    changed = true;
                }
                break;
            }
            case IrOp::BITCAST:
            case IrOp::CAST: {
                if (ins.operands.empty()) break;
                IrType from_t = (ins.operands[0] < fn.values.size())
                                    ? fn.values[ins.operands[0]].type
                                    : IrType::I64;
                if (from_t == ins.type) {
                    rewrite_as_mov(ins, ins.operands[0]);
                    changed = true;
                    break;
                }
                int64_t c = 0;
                if (get_const(ins.operands[0], c)) {
                    rewrite_as_const_with_value(fn, ins,
                                                static_cast<uint64_t>(c));
                    const_vids[ins.dst] = c;
                    changed = true;
                }
                break;
            }

            /* ---- (D) Math IR ops constant folding (sprint v2.2c) ----
             *
             * Cuando todos los operandos son CONST conocidos, evaluamos
             * la operacion en compile-time y reemplazamos por CONST
             * literal.  Float ops preservan bits IEEE 754 via memcpy.
             * Habilita propagacion downstream (e.g. `sqrt(25.0) + 3.0`
             * pliega a CONST 8.0 directamente). */
            case IrOp::FSQRT:
            case IrOp::FABS:
            case IrOp::FNEG:
            case IrOp::FFLOOR:
            case IrOp::FCEIL:
            case IrOp::FROUND:
            case IrOp::FTRUNC: {
                if (ins.operands.empty()) break;
                /* Idempotencia ESTRUCTURAL de fneg/fabs: bit-exacta para TODO x
                 * (NaN/Inf/+-0 incluidos), asi que es sound incluso bajo
                 * @fp(strict).  fneg solo voltea el bit de signo; fabs lo pone
                 * a 0.  fneg(fneg x)=x; fabs(fabs x)=fabs x; fabs(fneg x)=fabs
                 * x. */
                if (ins.op == IrOp::FNEG || ins.op == IrOp::FABS) {
                    auto dit = def_of.find(ins.operands[0]);
                    if (dit != def_of.end() && dit->second != &ins &&
                        !dit->second->operands.empty()) {
                        const IrOp dop = dit->second->op;
                        const IrValueId inner = dit->second->operands[0];
                        if (ins.op == IrOp::FNEG && dop == IrOp::FNEG) {
                            rewrite_as_mov(ins, inner);
                            changed = true;
                            break;
                        }
                        if (ins.op == IrOp::FABS &&
                            (dop == IrOp::FABS || dop == IrOp::FNEG)) {
                            ins.operands[0] = inner; // sigue siendo fabs, con x
                            changed = true;
                            break;
                        }
                    }
                }
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                const bool is_f32 = (ins.type == IrType::F32);
                double in_v = is_f32 ? static_cast<double>(bits_to_f32(
                                           static_cast<uint32_t>(c0)))
                                     : bits_to_f64(static_cast<uint64_t>(c0));
                double out_v = 0.0;
                switch (ins.op) {
                case IrOp::FSQRT: out_v = std::sqrt(in_v); break;
                case IrOp::FABS: out_v = std::fabs(in_v); break;
                case IrOp::FNEG: out_v = -in_v; break;
                case IrOp::FFLOOR: out_v = std::floor(in_v); break;
                case IrOp::FCEIL: out_v = std::ceil(in_v); break;
                case IrOp::FROUND: out_v = std::nearbyint(in_v); break;
                case IrOp::FTRUNC: out_v = std::trunc(in_v); break;
                default: break;
                }
                uint64_t out_bits = is_f32 ? static_cast<uint64_t>(f32_to_bits(
                                                 static_cast<float>(out_v)))
                                           : f64_to_bits(out_v);
                rewrite_as_const_with_value(fn, ins, out_bits);
                const_vids[ins.dst] = static_cast<int64_t>(out_bits);
                changed = true;
                break;
            }
            case IrOp::FADD:
            case IrOp::FSUB:
            case IrOp::FMUL:
            case IrOp::FDIV:
            case IrOp::FMIN:
            case IrOp::FMAX: {
                if (ins.operands.size() < 2) break;
                int64_t c0 = 0, c1 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                if (!get_const(ins.operands[1], c1)) break;
                const bool is_f32 = (ins.type == IrType::F32);
                auto bits_to_dbl = [&](int64_t v) -> double {
                    return is_f32 ? static_cast<double>(
                                        bits_to_f32(static_cast<uint32_t>(v)))
                                  : bits_to_f64(static_cast<uint64_t>(v));
                };
                double a = bits_to_dbl(c0);
                double b = bits_to_dbl(c1);
                double r = 0.0;
                bool ok = true;
                switch (ins.op) {
                case IrOp::FADD: r = a + b; break;
                case IrOp::FSUB: r = a - b; break;
                case IrOp::FMUL: r = a * b; break;
                case IrOp::FDIV:
                    /* Folding de FDIV por 0 produciria NaN/Inf
                     * deterministico en IEEE 754; aceptable. */
                    r = a / b;
                    break;
                case IrOp::FMIN: r = std::fmin(a, b); break;
                case IrOp::FMAX: r = std::fmax(a, b); break;
                default: ok = false; break;
                }
                if (!ok) break;
                uint64_t out_bits = is_f32 ? static_cast<uint64_t>(f32_to_bits(
                                                 static_cast<float>(r)))
                                           : f64_to_bits(r);
                rewrite_as_const_with_value(fn, ins, out_bits);
                const_vids[ins.dst] = static_cast<int64_t>(out_bits);
                changed = true;
                break;
            }
            // FoldCompareConstants (entero): cmp.<cc> const, const -> const
            // bool. Signed via int64, unsigned via uint64.  El resultado (0/1)
            // deja al BR_COND siguiente foldearse a un salto incondicional
            // (ir_pass_ simplify) -> unreachable-elim + DCE colapsan las ramas
            // muertas.
            case IrOp::CMP_EQ:
            case IrOp::CMP_NE:
            case IrOp::CMP_LT:
            case IrOp::CMP_GT:
            case IrOp::CMP_LE:
            case IrOp::CMP_GE:
            case IrOp::CMP_ULT:
            case IrOp::CMP_UGT:
            case IrOp::CMP_ULE:
            case IrOp::CMP_UGE: {
                if (ins.operands.size() < 2) break;
                int64_t c0 = 0, c1 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                if (!get_const(ins.operands[1], c1)) break;
                const uint64_t u0 = static_cast<uint64_t>(c0);
                const uint64_t u1 = static_cast<uint64_t>(c1);
                bool r = false;
                switch (ins.op) {
                case IrOp::CMP_EQ: r = (c0 == c1); break;
                case IrOp::CMP_NE: r = (c0 != c1); break;
                case IrOp::CMP_LT: r = (c0 < c1); break;
                case IrOp::CMP_GT: r = (c0 > c1); break;
                case IrOp::CMP_LE: r = (c0 <= c1); break;
                case IrOp::CMP_GE: r = (c0 >= c1); break;
                case IrOp::CMP_ULT: r = (u0 < u1); break;
                case IrOp::CMP_UGT: r = (u0 > u1); break;
                case IrOp::CMP_ULE: r = (u0 <= u1); break;
                case IrOp::CMP_UGE: r = (u0 >= u1); break;
                default: break;
                }
                rewrite_as_const_with_value(fn, ins, r ? 1u : 0u);
                const_vids[ins.dst] = r ? 1 : 0;
                changed = true;
                break;
            }
            // FoldCompareConstants (float): fcmp.<cc> const, const -> const
            // bool. Se interpreta segun ins.type (F32/F64).  GUARD NaN: si
            // algun operando es NaN, NO foldear (dejar al runtime) -- asi el
            // fold es SOUND sea cual sea la semantica ordered/unordered de FCMP
            // en el backend (sin riesgo de divergencia en el diff_harness). Sin
            // NaN, ordered == C.
            case IrOp::FCMP_EQ:
            case IrOp::FCMP_NE:
            case IrOp::FCMP_LT:
            case IrOp::FCMP_GT:
            case IrOp::FCMP_LE:
            case IrOp::FCMP_GE: {
                if (ins.operands.size() < 2) break;
                int64_t c0 = 0, c1 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                if (!get_const(ins.operands[1], c1)) break;
                const bool is_f32 = (ins.type == IrType::F32);
                const double a =
                    is_f32 ? static_cast<double>(
                                 bits_to_f32(static_cast<uint32_t>(c0)))
                           : bits_to_f64(static_cast<uint64_t>(c0));
                const double b =
                    is_f32 ? static_cast<double>(
                                 bits_to_f32(static_cast<uint32_t>(c1)))
                           : bits_to_f64(static_cast<uint64_t>(c1));
                if (std::isnan(a) || std::isnan(b))
                    break; // sound: no foldear NaN
                bool r = false;
                switch (ins.op) {
                case IrOp::FCMP_EQ: r = (a == b); break;
                case IrOp::FCMP_NE: r = (a != b); break;
                case IrOp::FCMP_LT: r = (a < b); break;
                case IrOp::FCMP_GT: r = (a > b); break;
                case IrOp::FCMP_LE: r = (a <= b); break;
                case IrOp::FCMP_GE: r = (a >= b); break;
                default: break;
                }
                rewrite_as_const_with_value(fn, ins, r ? 1u : 0u);
                const_vids[ins.dst] = r ? 1 : 0;
                changed = true;
                break;
            }
            case IrOp::IABS: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                /* INT_MIN -> UB en C; el IR doc dice "undef".  Para no
                 * crashear, dejar como esta (no foldear). */
                if (c0 == std::numeric_limits<int64_t>::min()) break;
                int64_t r = c0 < 0 ? -c0 : c0;
                rewrite_as_const_with_value(fn, ins, static_cast<uint64_t>(r));
                const_vids[ins.dst] = r;
                changed = true;
                break;
            }
            case IrOp::IMIN:
            case IrOp::IMAX: {
                if (ins.operands.size() < 2) break;
                int64_t c0 = 0, c1 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                if (!get_const(ins.operands[1], c1)) break;
                int64_t r = (ins.op == IrOp::IMIN) ? (c0 < c1 ? c0 : c1)
                                                   : (c0 > c1 ? c0 : c1);
                rewrite_as_const_with_value(fn, ins, static_cast<uint64_t>(r));
                const_vids[ins.dst] = r;
                changed = true;
                break;
            }
            case IrOp::IMINU:
            case IrOp::IMAXU: {
                if (ins.operands.size() < 2) break;
                int64_t c0 = 0, c1 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                if (!get_const(ins.operands[1], c1)) break;
                uint64_t u0 = static_cast<uint64_t>(c0);
                uint64_t u1 = static_cast<uint64_t>(c1);
                uint64_t r = (ins.op == IrOp::IMINU) ? (u0 < u1 ? u0 : u1)
                                                     : (u0 > u1 ? u0 : u1);
                rewrite_as_const_with_value(fn, ins, r);
                const_vids[ins.dst] = static_cast<int64_t>(r);
                changed = true;
                break;
            }
            case IrOp::ILOG2: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                uint64_t u = static_cast<uint64_t>(c0);
                if (u == 0) break; /* undef segun doc IR; no foldear. */
                int r = 63;
#if defined(__GNUC__) || defined(__clang__)
                r = 63 - __builtin_clzll(u);
#else
                for (r = 63; r >= 0 && ((u >> r) & 1ULL) == 0; --r) {
                }
#endif
                rewrite_as_const_with_value(fn, ins, static_cast<uint64_t>(r));
                const_vids[ins.dst] = r;
                changed = true;
                break;
            }
            case IrOp::POPCNT: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                uint64_t u = static_cast<uint64_t>(c0);
                int r;
#if defined(__GNUC__) || defined(__clang__)
                r = __builtin_popcountll(u);
#else
                r = 0;
                for (; u; u &= u - 1)
                    ++r;
#endif
                rewrite_as_const_with_value(fn, ins, static_cast<uint64_t>(r));
                const_vids[ins.dst] = r;
                changed = true;
                break;
            }
            case IrOp::CLZ: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                uint64_t u = static_cast<uint64_t>(c0);
                if (u == 0) break; /* clz(0) undef en x86 lzcnt; no foldear. */
                int r;
#if defined(__GNUC__) || defined(__clang__)
                r = __builtin_clzll(u);
#else
                r = 0;
                while (((u >> 63) & 1ULL) == 0) {
                    u <<= 1;
                    ++r;
                }
#endif
                rewrite_as_const_with_value(fn, ins, static_cast<uint64_t>(r));
                const_vids[ins.dst] = r;
                changed = true;
                break;
            }
            case IrOp::CTZ: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                uint64_t u = static_cast<uint64_t>(c0);
                if (u == 0) break; /* ctz(0) undef. */
                int r;
#if defined(__GNUC__) || defined(__clang__)
                r = __builtin_ctzll(u);
#else
                r = 0;
                while ((u & 1ULL) == 0) {
                    u >>= 1;
                    ++r;
                }
#endif
                rewrite_as_const_with_value(fn, ins, static_cast<uint64_t>(r));
                const_vids[ins.dst] = r;
                changed = true;
                break;
            }
            case IrOp::BYTESWAP: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                uint64_t u = static_cast<uint64_t>(c0);
#if defined(__GNUC__) || defined(__clang__)
                u = __builtin_bswap64(u);
#else
                u = ((u & 0xFF00000000000000ULL) >> 56) |
                    ((u & 0x00FF000000000000ULL) >> 40) |
                    ((u & 0x0000FF0000000000ULL) >> 24) |
                    ((u & 0x000000FF00000000ULL) >> 8) |
                    ((u & 0x00000000FF000000ULL) << 8) |
                    ((u & 0x0000000000FF0000ULL) << 24) |
                    ((u & 0x000000000000FF00ULL) << 40) |
                    ((u & 0x00000000000000FFULL) << 56);
#endif
                rewrite_as_const_with_value(fn, ins, u);
                const_vids[ins.dst] = static_cast<int64_t>(u);
                changed = true;
                break;
            }
            case IrOp::ROTL:
            case IrOp::ROTR: {
                if (ins.operands.size() < 2) break;
                int64_t c0 = 0, c1 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                if (!get_const(ins.operands[1], c1)) break;
                uint64_t u = static_cast<uint64_t>(c0);
                unsigned n = static_cast<unsigned>(c1) & 63u;
                uint64_t r = (ins.op == IrOp::ROTL)
                                 ? ((u << n) | (n ? (u >> (64 - n)) : 0))
                                 : ((u >> n) | (n ? (u << (64 - n)) : 0));
                rewrite_as_const_with_value(fn, ins, r);
                const_vids[ins.dst] = static_cast<int64_t>(r);
                changed = true;
                break;
            }
            case IrOp::ITOF: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                const bool is_f32 = (ins.type == IrType::F32);
                double d = static_cast<double>(c0);
                uint64_t b = is_f32 ? static_cast<uint64_t>(
                                          f32_to_bits(static_cast<float>(d)))
                                    : f64_to_bits(d);
                rewrite_as_const_with_value(fn, ins, b);
                const_vids[ins.dst] = static_cast<int64_t>(b);
                changed = true;
                break;
            }
            case IrOp::UITOF: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                const bool is_f32 = (ins.type == IrType::F32);
                double d = static_cast<double>(static_cast<uint64_t>(c0));
                uint64_t b = is_f32 ? static_cast<uint64_t>(
                                          f32_to_bits(static_cast<float>(d)))
                                    : f64_to_bits(d);
                rewrite_as_const_with_value(fn, ins, b);
                const_vids[ins.dst] = static_cast<int64_t>(b);
                changed = true;
                break;
            }
            case IrOp::FTOI:
            case IrOp::FTOUI: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                /* El tipo de la SOURCE (no del dst) decide ancho.  Para
                 * conservar correctness, leemos el tipo del operando. */
                IrType src_t = (ins.operands[0] < fn.values.size())
                                   ? fn.values[ins.operands[0]].type
                                   : IrType::F64;
                double v = (src_t == IrType::F32)
                               ? static_cast<double>(
                                     bits_to_f32(static_cast<uint32_t>(c0)))
                               : bits_to_f64(static_cast<uint64_t>(c0));
                /* Out-of-range -> UB en C; saltar fold para NaN/Inf y
                 * valores que no entran en int64.  Conservador. */
                if (!std::isfinite(v)) break;
                if (ins.op == IrOp::FTOI) {
                    if (v < -9.2233720368547758e18 || v > 9.2233720368547758e18)
                        break;
                    int64_t r = static_cast<int64_t>(v);
                    rewrite_as_const_with_value(fn, ins,
                                                static_cast<uint64_t>(r));
                    const_vids[ins.dst] = r;
                } else {
                    if (v < 0.0 || v > 1.8446744073709552e19) break;
                    uint64_t r = static_cast<uint64_t>(v);
                    rewrite_as_const_with_value(fn, ins, r);
                    const_vids[ins.dst] = static_cast<int64_t>(r);
                }
                changed = true;
                break;
            }
            case IrOp::F32TOF64: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                double d =
                    static_cast<double>(bits_to_f32(static_cast<uint32_t>(c0)));
                uint64_t b = f64_to_bits(d);
                rewrite_as_const_with_value(fn, ins, b);
                const_vids[ins.dst] = static_cast<int64_t>(b);
                changed = true;
                break;
            }
            case IrOp::F64TOF32: {
                if (ins.operands.empty()) break;
                int64_t c0 = 0;
                if (!get_const(ins.operands[0], c0)) break;
                float f =
                    static_cast<float>(bits_to_f64(static_cast<uint64_t>(c0)));
                uint64_t b = static_cast<uint64_t>(f32_to_bits(f));
                rewrite_as_const_with_value(fn, ins, b);
                const_vids[ins.dst] = static_cast<int64_t>(b);
                changed = true;
                break;
            }

            /* ---- (C) Phi simplification ---- */
            case IrOp::PHI: {
                if (ins.phi_args.empty()) break;
                /* Recolectar VIDs unicos (excluyendo self-ref). */
                IrValueId unique = IR_NO_VALUE;
                bool multi = false;
                for (const auto &arg : ins.phi_args) {
                    if (arg.value == IR_NO_VALUE) continue;
                    if (arg.value == ins.dst) continue; /* self-ref */
                    if (unique == IR_NO_VALUE) {
                        unique = arg.value;
                    } else if (unique != arg.value) {
                        multi = true;
                        break;
                    }
                }
                if (!multi && unique != IR_NO_VALUE) {
                    /* Todos los args no-self apuntan al mismo VID. */
                    rewrite_as_mov(ins, unique);
                    changed = true;
                }
                break;
            }

            default: break;
            }
        }
    }

    return changed;
}

// =========================================================================
//  Pase ir_pass_strength_reduction ( D.7.opt)
// =========================================================================
//
// Reemplaza operaciones MUL/DIV/MOD por constante potencia-de-2 con
// shifts/AND, que son significativamente mas baratas:
//   x * 2^k        -> x << k
//   x / 2^k (uN)   -> x >> k       (unsigned: shift logico)
//   x / 2^k (iN)   -> x >> k       (sar para preservar signo)
//   x % 2^k (uN)   -> x & (2^k-1)  (unsigned solo, signed tiene round-bias)
//
// Beneficios:
//   - JIT: skip IMUL (3-5 ciclos) / IDIV (~20-30 ciclos) -> SHL/SHR (1 ciclo).
//   - port-C: el compilador C tambien hace esto pero IR limpio ayuda.
//
// La identificacion de "power of 2" usa popcount (== 1).

namespace {
/** @brief Si @p v es potencia de 2 positiva, devuelve log2(v).  Sino -1. */
int log2_if_power_of_two(uint64_t v) {
    if (v == 0) return -1;
    if ((v & (v - 1)) != 0) return -1; /* mas de un bit set */
    /* Encontrar el bit set.  Usar __builtin_ctzll si disponible. */
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_ctzll(v);
#else
    int k = 0;
    while ((v & 1) == 0) {
        v >>= 1;
        ++k;
    }
    return k;
#endif
}
} // namespace

// =========================================================================
//  Fuente de conocimiento: ValueFacts (Range + KnownBits) por valor SSA.
// =========================================================================
//
// Analisis SOUND (over-aproximacion) que demuestra PROPIEDADES de cada valor;
// los pases las CONSUMEN sin re-deducir (como KnownBits+ConstantRange de LLVM).
// Vive en `ir_optimize`, ANTES de la divergencia interp vs vreg -> lo comparten
// los 3 backends.  Dos hechos DISTINTOS por valor:
//   - `range`  = el VALOR MATEMATICO del registro de 64 bits: [lo, hi].
//   - `kz`/`ko` = KnownBits, la REPRESENTACION FISICA: bits provablemente 0
//   / 1.
// Son propiedades relacionadas pero NO equivalentes (un i32 con rango [0,200]
// podria vivir en un registro de 64 con bits altos basura; eliminar un SEXT
// necesita probar la REPRESENTACION, no solo el rango).  Por eso KnownBits es
// lo que autoriza eliminar SEXT/ZEXT/TRUNC/AND-mask; el rango sirve de PUENTE:
// un valor con `range subset [0, 2^k)` tiene los bits [k,64) en 0 (el valor de
// registro cabe), lo que SI es un hecho fisico.  Cualquier duda -> desconocido.
struct ValueFacts {
    int64_t lo = INT64_MIN;
    int64_t hi = INT64_MAX;
    uint64_t kz = 0; // bits provablemente 0  (siempre fisicos, sound)
    uint64_t ko = 0; // bits provablemente 1  (siempre fisicos, sound)
    // reg_exact = el par [lo,hi] describe FIELMENTE el registro de 64 bits, no
    // un valor matematico abstracto.  SOLO lo ponen las ops cuyo registro ES su
    // valor matematico (CONST, ADD, SUB, AND-mask, SHL/SHR/SAR, PHI,
    // induccion). Un futuro LOAD que solo acote el valor logico (pero deje
    // basura en los bits altos del registro) NO debe ponerlo -> ni el puente
    // rango->bits ni el folding de comparaciones lo consumiran (evita
    // reintroducir un SEXT/CMP no-sound).  kz/ko NO dependen de esto: son
    // hechos fisicos por construccion.
    bool reg_exact = false;

    bool range_full() const { return lo == INT64_MIN && hi == INT64_MAX; }

    // Rango USABLE = presente Y fiel al registro.  Todos los consumidores de
    // lo/hi deben pasar por aqui.
    bool has_range() const { return reg_exact && !range_full(); }
};

// Deriva bits known-zero altos del rango del VALOR DE REGISTRO: si el valor es
// no-negativo y cabe en k bits, los bits [k, 64) del registro son 0.  Es el
// PUENTE sound rango -> representacion fisica, y SOLO se aplica a rangos que
// describen el registro (reg_exact); si no, no toca los bits.
static inline void facts_derive_bits_from_range(ValueFacts &f) {
    if (!f.reg_exact) return; // rango no-fiel al registro: no derivar bits
    if (f.lo < 0) return;     // negativo: los bits altos son signo, no 0 (skip)
    if (f.hi == 0) {
        f.kz = ~0ULL; // el valor es 0: todos los bits en 0
        return;
    }
    if (f.hi < 0) return; // hi desbordado / desconocido
    const int hb = 63 - __builtin_clzll(static_cast<uint64_t>(f.hi));
    const uint64_t known_zero_above =
        (hb + 1 >= 64) ? 0ULL : ~((1ULL << (hb + 1)) - 1ULL);
    f.kz |= known_zero_above;
}

// Computa ValueFacts de cada valor SSA (forward, over-aproximacion sound).
static std::unordered_map<IrValueId, ValueFacts>
compute_value_facts(const IrFunction &fn) {
    std::unordered_map<IrValueId, ValueFacts> facts;
    auto get = [&](IrValueId v) -> ValueFacts {
        auto it = facts.find(v);
        return it != facts.end() ? it->second : ValueFacts{};
    };
    auto have = [&](IrValueId v) -> bool { return facts.count(v) > 0; };

    // --- Semilla: constantes + variables de induccion acotadas. ---
    std::unordered_map<IrValueId, int64_t> const_vids;
    for (const auto &bb : fn.blocks)
        for (const auto &ins : bb.instrs)
            if (ins.op == IrOp::CONST && ins.dst != IR_NO_VALUE) {
                const int64_t c = static_cast<int64_t>(ins.imm);
                const_vids[ins.dst] = c;
                ValueFacts f;
                f.lo = f.hi = c;
                f.reg_exact = true; // una constante ES su registro
                // KnownBits exactos de una constante.
                f.kz = ~static_cast<uint64_t>(c);
                f.ko = static_cast<uint64_t>(c);
                facts[ins.dst] = f;
            }
    auto cst_of = [&](IrValueId v, int64_t &o) -> bool {
        auto it = const_vids.find(v);
        if (it == const_vids.end()) return false;
        o = it->second;
        return true;
    };
    struct AddDef {
        IrValueId base;
        int64_t c;
    };
    std::unordered_map<IrValueId, AddDef> add_defs;
    struct CmpBound {
        IrValueId v;
        int64_t K;
        bool inclusive;
    };
    std::unordered_map<IrValueId, CmpBound> cmp_bound;
    for (const auto &bb : fn.blocks)
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::ADD && ins.operands.size() == 2 &&
                ins.dst != IR_NO_VALUE) {
                int64_t c;
                if (cst_of(ins.operands[1], c))
                    add_defs[ins.dst] = {ins.operands[0], c};
                else if (cst_of(ins.operands[0], c))
                    add_defs[ins.dst] = {ins.operands[1], c};
            }
            if ((ins.op == IrOp::CMP_LT || ins.op == IrOp::CMP_LE) &&
                ins.operands.size() == 2 && ins.dst != IR_NO_VALUE) {
                int64_t k;
                if (cst_of(ins.operands[1], k))
                    cmp_bound[ins.dst] = {ins.operands[0], k,
                                          ins.op == IrOp::CMP_LE};
            }
        }
    // Induccion: phi(init>=0, %v+c>0) guardada por el br_cond del PROPIO header
    // (loop natural canonico).  El maximo valor de %v es el ultimo incremento
    // antes de salir (Kmax+c-1); esa cota GLOBAL da los bits altos known-zero.
    // Es la PROCEDENCIA (no solo el rango) lo que garantiza la canonicidad: el
    // registro empieza en CONST 0 (canonico) y solo suma positivos pequenos que
    // no tocan los bits altos -> sigue canonico.
    for (const auto &bb : fn.blocks) {
        const IrInstr *term = nullptr;
        for (auto it = bb.instrs.rbegin(); it != bb.instrs.rend(); ++it) {
            if (it->op == IrOp::BR_COND) {
                term = &*it;
                break;
            }
            if (it->op == IrOp::BR || it->op == IrOp::RET ||
                it->op == IrOp::THROW || it->op == IrOp::TAILCALL)
                break;
        }
        if (term == nullptr || term->operands.empty()) continue;
        auto cb = cmp_bound.find(term->operands[0]);
        if (cb == cmp_bound.end()) continue;
        const IrValueId guarded = cb->second.v;
        const int64_t Kmax =
            cb->second.inclusive ? cb->second.K + 1 : cb->second.K;
        for (const auto &ins : bb.instrs) {
            if (ins.op != IrOp::PHI || ins.dst != guarded) continue;
            if (ins.phi_args.size() != 2) continue;
            int64_t init = 0, c = 0;
            auto try_pair = [&](IrValueId mi, IrValueId minc) -> bool {
                int64_t ic;
                if (!cst_of(mi, ic) || ic < 0) return false;
                auto it = add_defs.find(minc);
                if (it == add_defs.end() || it->second.base != ins.dst ||
                    it->second.c <= 0)
                    return false;
                init = ic;
                c = it->second.c;
                return true;
            };
            if (!try_pair(ins.phi_args[0].value, ins.phi_args[1].value) &&
                !try_pair(ins.phi_args[1].value, ins.phi_args[0].value))
                continue;
            int64_t maxv;
            if (Kmax <= 0) continue;
            if (__builtin_add_overflow(Kmax, c - 1, &maxv)) continue;
            ValueFacts f;
            f.lo = init;
            f.hi = maxv;
            // La PROCEDENCIA (phi(0,+c) canonico) garantiza el registro exacto.
            f.reg_exact = true;
            facts_derive_bits_from_range(f);
            facts[ins.dst] = f;
        }
    }

    // --- Pase forward: cada instr computa sus hechos de los operandos. ---
    // Orden de bloques del layout (RPO-ish); operando sin hechos (back-edge de
    // PHI recursivo no-induccion) = desconocido (over-aproximacion sound).
    auto sat_add = [](int64_t a, int64_t b, int64_t &o) -> bool {
        return __builtin_add_overflow(a, b, &o);
    };
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.dst == IR_NO_VALUE || have(ins.dst)) continue;
            ValueFacts r; // por defecto: FULL / desconocido
            switch (ins.op) {
            case IrOp::ADD:
                if (ins.operands.size() == 2) {
                    ValueFacts a = get(ins.operands[0]),
                               b = get(ins.operands[1]);
                    // Solo si AMBOS rangos son fieles al registro: la suma de
                    // registros exactos es un registro exacto (ADD produce el
                    // valor real de 64 bits).
                    if (a.has_range() && b.has_range()) {
                        int64_t lo, hi;
                        if (!sat_add(a.lo, b.lo, lo) &&
                            !sat_add(a.hi, b.hi, hi)) {
                            r.lo = lo;
                            r.hi = hi;
                            r.reg_exact = true;
                        }
                    }
                }
                break;
            case IrOp::SUB:
                if (ins.operands.size() == 2) {
                    ValueFacts a = get(ins.operands[0]),
                               b = get(ins.operands[1]);
                    if (a.has_range() && b.has_range()) {
                        int64_t lo, hi;
                        if (!__builtin_sub_overflow(a.lo, b.hi, &lo) &&
                            !__builtin_sub_overflow(a.hi, b.lo, &hi)) {
                            r.lo = lo;
                            r.hi = hi;
                            r.reg_exact = true;
                        }
                    }
                }
                break;
            case IrOp::AND: {
                if (ins.operands.size() != 2) break;
                // KnownBits: un bit es 0 si lo es en CUALQUIER operando.
                ValueFacts a = get(ins.operands[0]), b = get(ins.operands[1]);
                r.kz = a.kz | b.kz;
                r.ko = a.ko & b.ko;
                // x & mask (mask CONST >= 0) -> range [0, mask].
                int64_t m;
                if ((cst_of(ins.operands[1], m) && m >= 0) ||
                    (cst_of(ins.operands[0], m) && m >= 0)) {
                    r.lo = 0;
                    r.hi = m;
                    r.reg_exact = true; // AND produce el registro real
                }
                break;
            }
            case IrOp::OR: {
                if (ins.operands.size() != 2) break;
                // Un bit es 1 si lo es en cualquiera; 0 si lo es en AMBOS.
                ValueFacts a = get(ins.operands[0]), b = get(ins.operands[1]);
                r.ko = a.ko | b.ko;
                r.kz = a.kz & b.kz;
                break;
            }
            case IrOp::XOR: {
                if (ins.operands.size() != 2) break;
                ValueFacts a = get(ins.operands[0]), b = get(ins.operands[1]);
                r.kz = (a.kz & b.kz) | (a.ko & b.ko); // 0^0 o 1^1 -> 0
                r.ko = (a.kz & b.ko) | (a.ko & b.kz); // 0^1 o 1^0 -> 1
                break;
            }
            case IrOp::SHL: {
                // a << c (c CONST 0..63): los c bits bajos entran a 0.
                int64_t c;
                if (ins.operands.size() == 2 && cst_of(ins.operands[1], c) &&
                    c >= 0 && c < 64) {
                    ValueFacts a = get(ins.operands[0]);
                    const uint64_t low = (c == 0) ? 0ULL : ((1ULL << c) - 1ULL);
                    r.kz = (a.kz << c) | low;
                    r.ko = a.ko << c;
                    if (a.has_range() && a.lo >= 0 && a.hi >= 0) {
                        int64_t hi;
                        if (!__builtin_mul_overflow(a.hi, int64_t(1) << c,
                                                    &hi)) {
                            r.lo = a.lo << c;
                            r.hi = hi;
                            r.reg_exact = true;
                        }
                    }
                }
                break;
            }
            case IrOp::SHR: {
                // a >>u c (logico, c CONST): los c bits altos entran a 0.
                int64_t c;
                if (ins.operands.size() == 2 && cst_of(ins.operands[1], c) &&
                    c >= 0 && c < 64) {
                    ValueFacts a = get(ins.operands[0]);
                    const uint64_t high =
                        (c == 0) ? 0ULL : ~(~0ULL >> c); // top c bits
                    r.kz = (a.kz >> c) | high;
                    r.ko = a.ko >> c;
                    if (a.has_range() && a.lo >= 0 && a.hi >= 0) {
                        r.lo = static_cast<int64_t>(
                            static_cast<uint64_t>(a.lo) >> c);
                        r.hi = static_cast<int64_t>(
                            static_cast<uint64_t>(a.hi) >> c);
                        r.reg_exact = true;
                    }
                }
                break;
            }
            case IrOp::SAR: {
                // a >>s c (aritmetico).  Si a es no-negativo (bit signo=0) es
                // igual que SHR; si no, se rellena con el signo (skip: full).
                int64_t c;
                if (ins.operands.size() == 2 && cst_of(ins.operands[1], c) &&
                    c >= 0 && c < 64) {
                    ValueFacts a = get(ins.operands[0]);
                    if ((a.kz & (1ULL << 63)) || (a.has_range() && a.lo >= 0)) {
                        const uint64_t high = (c == 0) ? 0ULL : ~(~0ULL >> c);
                        r.kz = (a.kz >> c) | high;
                        r.ko = a.ko >> c;
                        if (a.has_range() && a.lo >= 0 && a.hi >= 0) {
                            r.lo = a.lo >> c;
                            r.hi = a.hi >> c;
                            r.reg_exact = true;
                        }
                    }
                }
                break;
            }
            case IrOp::PHI: {
                // KnownBits del PHI = interseccion (bit conocido solo si lo es
                // en TODOS los ingresos) -- SIEMPRE sound aunque falte el
                // rango. El rango solo se toma si TODOS los ingresos tienen
                // rango fiel.
                bool have_all = !ins.phi_args.empty();
                bool range_all = have_all;
                int64_t lo = INT64_MAX, hi = INT64_MIN;
                uint64_t kz = ~0ULL, ko = ~0ULL;
                for (const auto &pa : ins.phi_args) {
                    if (!have(pa.value)) {
                        have_all = false;
                        range_all = false;
                        break;
                    }
                    ValueFacts pf = get(pa.value);
                    kz &= pf.kz;
                    ko &= pf.ko;
                    if (pf.has_range()) {
                        lo = std::min(lo, pf.lo);
                        hi = std::max(hi, pf.hi);
                    } else {
                        range_all = false;
                    }
                }
                if (have_all) {
                    r.kz = kz;
                    r.ko = ko;
                }
                if (range_all && lo <= hi) {
                    r.lo = lo;
                    r.hi = hi;
                    r.reg_exact = true;
                }
                break;
            }
            default: break; // FULL para lo no modelado
            }
            facts_derive_bits_from_range(r); // puente rango -> bits altos
            facts[ins.dst] = r;
        }
    }
    return facts;
}

// =========================================================================
//  Pase ir_pass_elim_redundant_casts: consumidor de ValueFacts.  Elimina
//  SEXT/ZEXT/AND-mascara redundantes que los KnownBits prueban identidad.
// =========================================================================
//
// Elimina `sext.i64 (iN v)` cuando KnownBits PRUEBA que los bits [63:N] del
// registro de v ya son 0 (valor no-negativo canonico) -> el sign-extend es la
// identidad.  NO se decide por el rango solo: se exige el hecho FISICO
// (bits[63:N]==0), que el rango del valor de registro proporciona via
// facts_derive_bits_from_range.  Generaliza el caso de induccion a CUALQUIER
// valor cuya representacion se pruebe canonica.  Sound: cualquier duda -> no
// transforma.  Beneficia `seed ^ (u64)i` de los hash-loops (elimina 1 op/iter
// en los 3 backends).  Verificacion: e2e (compara resultados; diff_harness NO
// valdria -- el pase es compartido, los 3 backends coincidirian aun mal).
// Impl interna: opera sobre ValueFacts YA computados (los comparte el runner
// de consumidores para no recalcular).  El wrapper publico los computa.
static bool
elim_casts_with_facts(IrFunction &fn,
                      const std::unordered_map<IrValueId, ValueFacts> &facts) {
    /* Aqui el estrechable tiene que llevar SIGNO, a diferencia del resto del
     * fichero: este pase razona sobre extensiones con signo, y admitir los u*
     * cambiaria lo que elimina.  Se escribe sobre el vocabulario unico en vez
     * de con otra tabla, pero conservando esa condicion extra. */
    auto narrow_bits = [](IrType t) -> int {
        return type_is_signed(t) ? static_cast<int>(type_narrow_bits(t)) : 0;
    };
    auto facts_of = [&](IrValueId v) -> ValueFacts {
        auto it = facts.find(v);
        return it != facts.end() ? it->second : ValueFacts{};
    };
    // Valor CONST de un vid (para la mascara del AND).
    std::unordered_map<IrValueId, int64_t> const_vids;
    for (const auto &bb : fn.blocks)
        for (const auto &ins : bb.instrs)
            if (ins.op == IrOp::CONST && ins.dst != IR_NO_VALUE)
                const_vids[ins.dst] = static_cast<int64_t>(ins.imm);
    auto cst_of = [&](IrValueId v, int64_t &o) -> bool {
        auto it = const_vids.find(v);
        if (it == const_vids.end()) return false;
        o = it->second;
        return true;
    };

    // Cada cast/mascara cuya redundancia PRUEBAN los KnownBits se reescribe a
    // su valor fuente.  dst_redundante -> valor_equivalente.
    std::unordered_map<IrValueId, IrValueId> replace;
    for (const auto &bb : fn.blocks)
        for (const auto &ins : bb.instrs) {
            if (ins.dst == IR_NO_VALUE) continue;
            switch (ins.op) {
            case IrOp::SEXT: {
                // SEXT(v, iN->i64) == v si bits [N-1, 64) de v son known-zero
                // (valor no-negativo, cabe en N-1 bits, registro canonico).
                if (ins.operands.size() != 1) break;
                const IrValueId src = ins.operands[0];
                const int N = narrow_bits(fn.values[src].type);
                if (N == 0 || N >= 64) break;
                const uint64_t upper = ~((1ULL << (N - 1)) - 1ULL);
                if ((facts_of(src).kz & upper) == upper) replace[ins.dst] = src;
                break;
            }
            case IrOp::ZEXT: {
                // ZEXT(v, iN->i64) == v si bits [N, 64) de v YA son known-zero
                // (el zero-extend no cambia nada).
                if (ins.operands.size() != 1) break;
                const IrValueId src = ins.operands[0];
                const int N = narrow_bits(fn.values[src].type);
                if (N == 0 || N >= 64) break;
                const uint64_t upper = ~((1ULL << N) - 1ULL); // bits [N, 64)
                if ((facts_of(src).kz & upper) == upper) replace[ins.dst] = src;
                break;
            }
            case IrOp::AND: {
                // v & mask == v si TODOS los bits fuera de mask son known-zero
                // en v (v no tiene bits que la mascara borre).
                if (ins.operands.size() != 2) break;
                int64_t m;
                IrValueId val = IR_NO_VALUE;
                if (cst_of(ins.operands[1], m))
                    val = ins.operands[0];
                else if (cst_of(ins.operands[0], m))
                    val = ins.operands[1];
                if (val == IR_NO_VALUE) break;
                const uint64_t nm =
                    ~static_cast<uint64_t>(m); // bits fuera de mask
                if (nm != 0 && (facts_of(val).kz & nm) == nm)
                    replace[ins.dst] = val;
                break;
            }
            default: break;
            }
        }
    if (replace.empty()) return false;

    auto remap = [&](IrValueId v) -> IrValueId {
        auto it = replace.find(v);
        return it != replace.end() ? it->second : v;
    };
    for (auto &bb : fn.blocks)
        for (auto &ins : bb.instrs) {
            for (IrValueId &o : ins.operands)
                o = remap(o);
            for (auto &pa : ins.phi_args)
                pa.value = remap(pa.value);
            if (ins.func_ptr != IR_NO_VALUE) ins.func_ptr = remap(ins.func_ptr);
        }
    // Borrar los casts/mascaras ahora muertos (su dst esta en replace; en SSA
    // el dst es unico, asi que basta el dst).
    for (auto &bb : fn.blocks)
        bb.instrs.erase(std::remove_if(bb.instrs.begin(), bb.instrs.end(),
                                       [&](const IrInstr &ins) {
                                           return ins.dst != IR_NO_VALUE &&
                                                  replace.count(ins.dst) > 0;
                                       }),
                        bb.instrs.end());
    return true;
}

// =========================================================================
//  Modelo relacional de comparaciones (para folding por rango Y por guardas).
//  Cada comparacion se describe como el conjunto de resultados {<,=,>} que la
//  hacen verdadera, mas su DOMINIO (con o sin signo).  El bit EQ es universal
//  (la igualdad de bits no depende del signo); los bits LT/GT solo son
//  comparables dentro del mismo dominio.
// =========================================================================
namespace {
enum class CmpDom { SIGNED, UNSIGNED, ANY };

constexpr unsigned OUT_LT = 1u, OUT_EQ = 2u, OUT_GT = 4u;

struct CmpModel {
    unsigned mask;
    CmpDom dom;
    bool valid;
};

inline CmpModel cmp_model(IrOp op) {
    switch (op) {
    case IrOp::CMP_LT: return {OUT_LT, CmpDom::SIGNED, true};
    case IrOp::CMP_LE: return {OUT_LT | OUT_EQ, CmpDom::SIGNED, true};
    case IrOp::CMP_GT: return {OUT_GT, CmpDom::SIGNED, true};
    case IrOp::CMP_GE: return {OUT_GT | OUT_EQ, CmpDom::SIGNED, true};
    case IrOp::CMP_ULT: return {OUT_LT, CmpDom::UNSIGNED, true};
    case IrOp::CMP_ULE: return {OUT_LT | OUT_EQ, CmpDom::UNSIGNED, true};
    case IrOp::CMP_UGT: return {OUT_GT, CmpDom::UNSIGNED, true};
    case IrOp::CMP_UGE: return {OUT_GT | OUT_EQ, CmpDom::UNSIGNED, true};
    case IrOp::CMP_EQ: return {OUT_EQ, CmpDom::ANY, true};
    case IrOp::CMP_NE: return {OUT_LT | OUT_GT, CmpDom::ANY, true};
    default: return {0u, CmpDom::ANY, false};
    }
}

// Intercambia operandos (a op b) == (b swap(op) a).
inline IrOp cmp_swap(IrOp op) {
    switch (op) {
    case IrOp::CMP_LT: return IrOp::CMP_GT;
    case IrOp::CMP_GT: return IrOp::CMP_LT;
    case IrOp::CMP_LE: return IrOp::CMP_GE;
    case IrOp::CMP_GE: return IrOp::CMP_LE;
    case IrOp::CMP_ULT: return IrOp::CMP_UGT;
    case IrOp::CMP_UGT: return IrOp::CMP_ULT;
    case IrOp::CMP_ULE: return IrOp::CMP_UGE;
    case IrOp::CMP_UGE: return IrOp::CMP_ULE;
    default: return op; // EQ, NE simetricas
    }
}

// Negacion logica: !(a op b) == (a negate(op) b).
inline IrOp cmp_negate(IrOp op) {
    switch (op) {
    case IrOp::CMP_LT: return IrOp::CMP_GE;
    case IrOp::CMP_GE: return IrOp::CMP_LT;
    case IrOp::CMP_LE: return IrOp::CMP_GT;
    case IrOp::CMP_GT: return IrOp::CMP_LE;
    case IrOp::CMP_ULT: return IrOp::CMP_UGE;
    case IrOp::CMP_UGE: return IrOp::CMP_ULT;
    case IrOp::CMP_ULE: return IrOp::CMP_UGT;
    case IrOp::CMP_UGT: return IrOp::CMP_ULE;
    case IrOp::CMP_EQ: return IrOp::CMP_NE;
    case IrOp::CMP_NE: return IrOp::CMP_EQ;
    default: return op;
    }
}

// Dado que `krel` es CIERTO sobre (x,y), decide si `qop` sobre (x,y) esta
// determinado: 1 -> siempre true, 0 -> siempre false, -1 -> indeterminado.
inline int cmp_implies(IrOp krel, IrOp qop) {
    CmpModel k = cmp_model(krel), q = cmp_model(qop);
    if (!k.valid || !q.valid) return -1;
    // Los bits LT/GT solo son comparables dentro del mismo dominio; EQ/NE (ANY)
    // hacen de puente porque la igualdad de bits no depende del signo.
    if (!(k.dom == CmpDom::ANY || q.dom == CmpDom::ANY || k.dom == q.dom))
        return -1;
    if ((k.mask & ~q.mask) == 0u) return 1; // resultados de k subset de q
    if ((k.mask & q.mask) == 0u) return 0;  // disjuntos
    return -1;
}
} // namespace

// =========================================================================
//  Pase ir_pass_fold_compares: otro consumidor de ValueFacts.  Pliega un CMP
//  a CONST 0/1 cuando el RANGE de sus operandos prueba el resultado (siempre
//  true / siempre false).  El const_fold + unreachable ya existentes propagan
//  la constante y podan la rama muerta del BR_COND.
// =========================================================================
//
// Razona sobre el VALOR MATEMATICO (range), no sobre bits.  Sound: el range es
// una over-aproximacion, asi que `a.hi < b.lo` implica a < b para TODOS los
// valores reales.  Solo enteros con signo (los rangos son i64 con signo); los
// CMP_U* se dejan (su semantica unsigned no encaja con el rango signed).
static bool fold_compares_with_facts(
    IrFunction &fn, const std::unordered_map<IrValueId, ValueFacts> &facts) {
    auto facts_of = [&](IrValueId v) -> ValueFacts {
        auto it = facts.find(v);
        return it != facts.end() ? it->second : ValueFacts{};
    };
    constexpr uint64_t SIGN = 1ULL << 63; // bit de signo del registro i64
    // Un valor es provablemente no-negativo si su bit de signo es known-zero o
    // su rango arranca en >=0 (el registro unsigned == signed en ese caso).
    auto nonneg = [&](const ValueFacts &f) -> bool {
        return (f.kz & SIGN) || (f.has_range() && f.lo >= 0);
    };

    bool changed = false;
    for (auto &bb : fn.blocks)
        for (auto &ins : bb.instrs) {
            if (ins.operands.size() != 2 || ins.dst == IR_NO_VALUE) continue;
            const ValueFacts fa = facts_of(ins.operands[0]);
            const ValueFacts fb = facts_of(ins.operands[1]);
            const int64_t alo = fa.lo, ahi = fa.hi, blo = fb.lo, bhi = fb.hi;
            // Rango USABLE = fiel al registro (reg_exact) y no-full.
            const bool a_rng = fa.has_range(), b_rng = fb.has_range();
            // `b == 0` (constante) usado por varios plegados unsigned.
            const bool b_is0 = b_rng && blo == 0 && bhi == 0;
            // Ambos no-negativos -> las comparaciones unsigned coinciden con
            // las signed sobre el mismo rango.
            const bool both_nn = nonneg(fa) && nonneg(fb);

            std::optional<bool> res; // vacio = indeterminado
            switch (ins.op) {
            case IrOp::CMP_LT:
                // 1) Range: a<b probado si ahi<blo (siempre) o alo>=bhi
                // (nunca).
                if (a_rng && b_rng) {
                    if (ahi < blo)
                        res = true;
                    else if (alo >= bhi)
                        res = false;
                }
                // 2) KnownBits para `a < 0`: el bit de signo lo decide aunque
                // el
                //    rango sea impreciso.  kz(signo) -> a>=0 -> false;
                //    ko(signo) -> a<0 -> true.
                if (!res && b_rng && blo == 0 && bhi == 0) {
                    if (fa.kz & SIGN)
                        res = false;
                    else if (fa.ko & SIGN)
                        res = true;
                }
                break;
            case IrOp::CMP_LE:
                if (a_rng && b_rng) {
                    if (ahi <= blo)
                        res = true;
                    else if (alo > bhi)
                        res = false;
                }
                break;
            case IrOp::CMP_GT:
                if (a_rng && b_rng) {
                    if (alo > bhi)
                        res = true;
                    else if (ahi <= blo)
                        res = false;
                }
                break;
            case IrOp::CMP_GE:
                if (a_rng && b_rng) {
                    if (alo >= bhi)
                        res = true;
                    else if (ahi < blo)
                        res = false;
                }
                // `a >= 0`: kz(signo) -> true; ko(signo) -> false.
                if (!res && b_rng && blo == 0 && bhi == 0) {
                    if (fa.kz & SIGN)
                        res = true;
                    else if (fa.ko & SIGN)
                        res = false;
                }
                break;
            case IrOp::CMP_EQ:
                if (a_rng && b_rng) {
                    if (alo == ahi && blo == bhi && alo == blo)
                        res = true;
                    else if (ahi < blo || bhi < alo)
                        res = false; // disjuntos
                }
                // KnownBits: si difieren en un bit conocido (uno lo tiene a 1 y
                // el otro a 0) nunca son iguales, aunque los rangos se solapen.
                if (!res && ((fa.ko & fb.kz) | (fa.kz & fb.ko)) != 0)
                    res = false;
                break;
            case IrOp::CMP_NE:
                if (a_rng && b_rng) {
                    if (ahi < blo || bhi < alo)
                        res = true; // disjuntos
                    else if (alo == ahi && blo == bhi && alo == blo)
                        res = false;
                }
                if (!res && ((fa.ko & fb.kz) | (fa.kz & fb.ko)) != 0)
                    res = true; // bits en conflicto -> siempre distintos
                break;
            // --- Comparaciones sin signo ---
            // `x <u 0` es imposible y `x >=u 0` siempre cierto (independiente
            // del rango).  El resto coincide con la logica signed si ambos
            // operandos son no-negativos (registro unsigned == signed).
            case IrOp::CMP_ULT:
                if (b_is0)
                    res = false;
                else if (both_nn && a_rng && b_rng) {
                    if (ahi < blo)
                        res = true;
                    else if (alo >= bhi)
                        res = false;
                }
                break;
            case IrOp::CMP_UGE:
                if (b_is0)
                    res = true;
                else if (both_nn && a_rng && b_rng) {
                    if (alo >= bhi)
                        res = true;
                    else if (ahi < blo)
                        res = false;
                }
                break;
            case IrOp::CMP_UGT:
                if (both_nn && a_rng && b_rng) {
                    if (alo > bhi)
                        res = true;
                    else if (ahi <= blo)
                        res = false;
                }
                break;
            case IrOp::CMP_ULE:
                if (both_nn && a_rng && b_rng) {
                    if (ahi <= blo)
                        res = true;
                    else if (alo > bhi)
                        res = false;
                }
                break;
            default: break;
            }
            if (!res) continue;
            // Reescribir el CMP a CONST: const_fold/unreachable propagan y
            // podan la rama muerta.  Actualizar TAMBIEN el flag is_const del
            // value: get_const (usado por el branch-fold de const_fold) lo lee
            // de fn.values, no del opcode de la instr.
            ins.op = IrOp::CONST;
            ins.imm = *res ? 1u : 0u;
            ins.operands.clear();
            if (ins.dst < fn.values.size()) {
                fn.values[ins.dst].is_const = true;
                fn.values[ins.dst].const_val = ins.imm;
            }
            changed = true;
        }
    return changed;
}

// =========================================================================
//  Pase ir_pass_fold_guarded_compares: rango RELACIONAL simbolico.  Pliega un
//  CMP cuando una GUARDA DOMINANTE ya establece una relacion sobre el MISMO par
//  de valores SSA (predicate propagation / correlated-branch, como el
//  LazyValueInfo de LLVM o los ASSERT_EXPR de GCC).  Cierra los bounds-checks
//  escritos por el usuario con longitud VARIABLE: en un cuerpo de bucle
//  `for i in 0..len` (guardado por `i < len`), un `if (i >= len) panic` interno
//  se prueba imposible aunque `len` no sea constante.
//
//  Sound: si el bloque B tiene un unico predecesor P que termina en
//  `br_cond(cmp)` y B es su sucesor true/false, entonces TODO camino a B pasa
//  por esa arista -> la relacion (o su negacion) se cumple en B y en todo lo
//  que B domina.  Los valores SSA son unicos, asi que comparar el mismo par
//  (x,y) es comparar los mismos valores en runtime.
// =========================================================================
static bool fold_guarded_compares(IrFunction &fn) {
    const size_t N = fn.blocks.size();
    if (N < 2) return false;

    // Mapa cond-value -> (op, a, b) de su CMP definidor.
    struct CmpDef {
        IrOp op;
        IrValueId a, b;
    };
    std::unordered_map<IrValueId, CmpDef> cmp_defs;
    for (const auto &bb : fn.blocks)
        for (const auto &ins : bb.instrs) {
            if (ins.dst == IR_NO_VALUE || ins.operands.size() != 2) continue;
            if (cmp_model(ins.op).valid)
                cmp_defs[ins.dst] = {ins.op, ins.operands[0], ins.operands[1]};
        }
    if (cmp_defs.empty()) return false;

    SrDom d = sr_compute_dom(fn);

    // Predicado activo: relacion CIERTA sobre (a,b).
    struct Pred {
        IrOp op;
        IrValueId a, b;
    };
    std::vector<std::vector<Pred>> active(N);

    // Propagacion descendente por el dom-tree (padre antes que hijo): cada
    // bloque hereda las guardas de su idom y anade la propia (si su unico
    // predecesor lo guarda con un br_cond sobre un CMP conocido).
    std::vector<IrBlockId> order;
    order.reserve(N);
    {
        std::vector<IrBlockId> stack{0};
        while (!stack.empty()) {
            IrBlockId b = stack.back();
            stack.pop_back();
            order.push_back(b);
            for (IrBlockId c : d.dom_children[b])
                stack.push_back(c);
        }
    }
    for (IrBlockId b : order) {
        if (b != 0 && d.idom[b] != d.UNDEF && d.idom[b] != b)
            active[b] = active[d.idom[b]]; // hereda del dominador inmediato
        // Guarda propia: unico predecesor P con br_cond sobre un CMP conocido.
        if (d.preds[b].size() != 1) continue;
        IrBlockId p = d.preds[b][0];
        if (p >= N || fn.blocks[p].instrs.empty()) continue;
        const IrInstr &term = fn.blocks[p].instrs.back();
        if (term.op != IrOp::BR_COND || term.operands.empty()) continue;
        if (term.target_block == term.false_block) continue; // ambos = mismo bb
        auto it = cmp_defs.find(term.operands[0]);
        if (it == cmp_defs.end()) continue;
        bool holds;
        if (b == term.target_block)
            holds = true; // rama true
        else if (b == term.false_block)
            holds = false; // rama false
        else
            continue;
        IrOp op = it->second.op;
        if (!holds) op = cmp_negate(op); // rama false -> negacion del CMP
        active[b].push_back({op, it->second.a, it->second.b});
    }

    // Plegar cada CMP usando los predicados activos de su bloque.
    bool changed = false;
    for (IrBlockId bi = 0; bi < N; ++bi) {
        if (active[bi].empty()) continue;
        for (auto &ins : fn.blocks[bi].instrs) {
            if (ins.dst == IR_NO_VALUE || ins.operands.size() != 2) continue;
            if (!cmp_model(ins.op).valid) continue;
            const IrValueId x = ins.operands[0], y = ins.operands[1];
            int res = -1;
            for (const auto &pr : active[bi]) {
                IrOp krel;
                if (pr.a == x && pr.b == y)
                    krel = pr.op;
                else if (pr.a == y && pr.b == x)
                    krel = cmp_swap(pr.op);
                else
                    continue;
                int r = cmp_implies(krel, ins.op);
                if (r >= 0) {
                    res = r;
                    break;
                }
            }
            if (res < 0) continue;
            ins.op = IrOp::CONST;
            ins.imm = res ? 1u : 0u;
            ins.operands.clear();
            if (ins.dst < fn.values.size()) {
                fn.values[ins.dst].is_const = true;
                fn.values[ins.dst].const_val = ins.imm;
            }
            changed = true;
        }
    }
    return changed;
}

// --- Wrappers publicos (uso standalone): computan los ValueFacts al vuelo. ---
bool ir_pass_fold_guarded_compares(IrFunction &fn) {
    return fold_guarded_compares(fn);
}

bool ir_pass_elim_redundant_casts(IrFunction &fn) {
    return elim_casts_with_facts(fn, compute_value_facts(fn));
}

bool ir_pass_fold_compares(IrFunction &fn) {
    return fold_compares_with_facts(fn, compute_value_facts(fn));
}

// Fwd: strength reduction que consume ValueFacts (definida mas abajo).
static bool strength_reduce_with_facts(
    IrFunction &fn, const std::unordered_map<IrValueId, ValueFacts> &facts);

// Runner de los consumidores de ValueFacts: computa el analisis UNA vez y lo
// comparte; solo lo RECOMPUTA (invalida) si un consumidor muto el IR.  Es el
// AnalysisCache minimo -- evita re-demostrar las mismas propiedades por pase, y
// escala a mas consumidores sin multiplicar el coste del analisis.
bool ir_pass_valuefacts_consumers(IrFunction &fn) {
    auto facts = compute_value_facts(fn);
    bool c1 = elim_casts_with_facts(fn, facts);
    if (c1) facts = compute_value_facts(fn); // invalidado por la mutacion
    bool c2 = fold_compares_with_facts(fn, facts);
    // 3er consumidor: strength reduction (MUL/DIV/MOD por 2^k -> shift/and).
    // El caso signed DIV/MOD solo aplica si los facts prueban el dividendo
    // no-negativo.  fold_compares no altera los facts del dividendo (solo
    // reescribe CMP->CONST), asi que los `facts` siguen validos para el.
    bool c3 = strength_reduce_with_facts(fn, facts);
    // 4o consumidor: rango relacional simbolico (guardas dominantes).  No usa
    // ValueFacts sino dominadores + predicados de guardas; cierra los
    // bounds-checks de longitud VARIABLE que el rango concreto no ve.
    bool c4 = fold_guarded_compares(fn);
    return c1 || c2 || c3 || c4;
}

static bool strength_reduce_with_facts(
    IrFunction &fn, const std::unordered_map<IrValueId, ValueFacts> &facts) {
    bool changed = false;
    constexpr uint64_t SR_SIGN = 1ULL << 63; // bit de signo del registro i64
    // Un dividendo es provablemente no-negativo si su bit de signo es
    // known-zero o su rango arranca en >=0.  En ese caso `x / 2^k == x >> k` y
    // `x % 2^k == x & (2^k-1)` SIN la correccion de redondeo que exige el
    // signo.
    auto nonneg_val = [&](IrValueId v) -> bool {
        auto it = facts.find(v);
        if (it == facts.end()) return false;
        const ValueFacts &f = it->second;
        return (f.kz & SR_SIGN) || (f.has_range() && f.lo >= 0);
    };

    /* Pre-build vid -> CONST imm. */
    std::unordered_map<IrValueId, int64_t> const_vids;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::CONST && ins.dst != IR_NO_VALUE) {
                const_vids[ins.dst] = static_cast<int64_t>(ins.imm);
            }
        }
    }
    auto get_const_pos = [&](IrValueId v, uint64_t &out) -> bool {
        if (v == IR_NO_VALUE) return false;
        auto it = const_vids.find(v);
        if (it == const_vids.end()) return false;
        if (it->second <= 0) return false; /* solo positivos para SR */
        out = static_cast<uint64_t>(it->second);
        return true;
    };

    /* Crea un nuevo SSA value de tipo CONST y devuelve (new_vid,
     * const_instr).  El caller debe INSERTAR la instr en algun bloque
     * para que el IR sea bien-formado.  Tipicamente justo antes del
     * uso (en el mismo bloque). */
    auto make_new_const = [&](IrType type,
                              uint64_t imm) -> std::pair<IrValueId, IrInstr> {
        const IrValueId new_id = static_cast<IrValueId>(fn.values.size());
        IrValue v{};
        v.id = new_id;
        v.type = type;
        v.name = "%sr" + std::to_string(new_id);
        v.is_const = true;
        v.const_val = imm;
        fn.values.push_back(v);
        const_vids[new_id] = static_cast<int64_t>(imm);

        IrInstr ci{};
        ci.op = IrOp::CONST;
        ci.type = type;
        ci.dst = new_id;
        ci.imm = imm;
        return {new_id, ci};
    };

    /* Recolectar (bb, pos) -> [list of CONST instrs a insertar ANTES].
     * Lo hacemos en una segunda pasada para no invalidar indices durante
     * el iteracion principal. */
    struct Insertion {
        size_t bb_idx;
        size_t pos;
        IrInstr instr;
    };
    std::vector<Insertion> pending_insertions;

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto &bb = fn.blocks[bi];
        for (size_t i = 0; i < bb.instrs.size(); ++i) {
            IrInstr &ins = bb.instrs[i];
            if (ins.operands.size() < 2) continue;

            switch (ins.op) {
            case IrOp::MUL: {
                uint64_t cv = 0;
                IrValueId rhs_const = IR_NO_VALUE;
                IrValueId other = IR_NO_VALUE;
                if (get_const_pos(ins.operands[1], cv)) {
                    rhs_const = ins.operands[1];
                    other = ins.operands[0];
                } else if (get_const_pos(ins.operands[0], cv)) {
                    rhs_const = ins.operands[0];
                    other = ins.operands[1];
                }
                if (rhs_const == IR_NO_VALUE) break;
                int k = log2_if_power_of_two(cv);
                if (k <= 0) break;
                auto p = make_new_const(IrType::I64, static_cast<uint64_t>(k));
                pending_insertions.push_back({bi, i, p.second});
                ins.op = IrOp::SHL;
                ins.operands = {other, p.first};
                changed = true;
                break;
            }
            case IrOp::DIV: {
                // Unsigned: siempre; signed: solo si el dividendo es
                // provablemente no-negativo (sin correccion de signo).
                const bool is_unsigned =
                    ins.type == IrType::U8 || ins.type == IrType::U16 ||
                    ins.type == IrType::U32 || ins.type == IrType::U64;
                if (!is_unsigned && !nonneg_val(ins.operands[0])) break;
                uint64_t cv = 0;
                if (!get_const_pos(ins.operands[1], cv)) break;
                int k = log2_if_power_of_two(cv);
                if (k <= 0) break;
                auto p = make_new_const(IrType::I64, static_cast<uint64_t>(k));
                pending_insertions.push_back({bi, i, p.second});
                ins.op = IrOp::SHR;
                ins.operands = {ins.operands[0], p.first};
                changed = true;
                break;
            }
            case IrOp::MOD: {
                const bool is_unsigned =
                    ins.type == IrType::U8 || ins.type == IrType::U16 ||
                    ins.type == IrType::U32 || ins.type == IrType::U64;
                if (!is_unsigned && !nonneg_val(ins.operands[0])) break;
                uint64_t cv = 0;
                if (!get_const_pos(ins.operands[1], cv)) break;
                int k = log2_if_power_of_two(cv);
                if (k <= 0) break;
                const uint64_t mask = cv - 1;
                auto p = make_new_const(ins.type, mask);
                pending_insertions.push_back({bi, i, p.second});
                ins.op = IrOp::AND;
                ins.operands = {ins.operands[0], p.first};
                changed = true;
                break;
            }
            default: break;
            }
        }
    }

    /* Aplicar inserciones en orden inverso para no invalidar pos. */
    std::sort(pending_insertions.begin(), pending_insertions.end(),
              [](const Insertion &a, const Insertion &b) {
                  if (a.bb_idx != b.bb_idx) return a.bb_idx > b.bb_idx;
                  return a.pos > b.pos;
              });
    for (const auto &ins_req : pending_insertions) {
        auto &bb = fn.blocks[ins_req.bb_idx];
        bb.instrs.insert(bb.instrs.begin() + ins_req.pos, ins_req.instr);
    }

    return changed;
}

// Wrapper publico (uso standalone): computa los ValueFacts al vuelo.
bool ir_pass_strength_reduction(IrFunction &fn) {
    return strength_reduce_with_facts(fn, compute_value_facts(fn));
}

// =========================================================================
//  Pase ir_pass_reassoc
// =========================================================================
//
// Reasocia operaciones binarias asociativas para combinar constantes:
//   (x + c1) + c2  ->  x + (c1+c2)        donde c1+c2 se folda
//   (x * c1) * c2  ->  x * (c1*c2)
//   Idem para AND/OR/XOR.
//
// Permite que const-fold colapse cadenas de operaciones que el const-fold
// local no veria (por no estar en la misma instruccion).
//
// Implementacion: para cada binop con rhs CONST, mira si el lhs es la
// MISMA op con un CONST rhs.  Si si, fusiona y deja la nueva instr.

bool ir_pass_reassoc(IrFunction &fn) {
    bool changed = false;

    /* Build vid -> instr (defining instr) para reassoc lookups. */
    struct DefInfo {
        IrBlockId bb;
        size_t idx;
    };
    std::unordered_map<IrValueId, DefInfo> defs;
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto &bb = fn.blocks[bi];
        for (size_t i = 0; i < bb.instrs.size(); ++i) {
            const auto &ins = bb.instrs[i];
            if (ins.dst != IR_NO_VALUE) {
                defs[ins.dst] = {static_cast<IrBlockId>(bi), i};
            }
        }
    }
    std::unordered_map<IrValueId, int64_t> const_vids;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::CONST && ins.dst != IR_NO_VALUE) {
                const_vids[ins.dst] = static_cast<int64_t>(ins.imm);
            }
        }
    }

    auto is_const = [&](IrValueId v, int64_t &out) -> bool {
        auto it = const_vids.find(v);
        if (it == const_vids.end()) return false;
        out = it->second;
        return true;
    };

    auto make_new_const = [&](IrType type,
                              uint64_t imm) -> std::pair<IrValueId, IrInstr> {
        const IrValueId new_id = static_cast<IrValueId>(fn.values.size());
        IrValue v{};
        v.id = new_id;
        v.type = type;
        v.name = "%ra" + std::to_string(new_id);
        v.is_const = true;
        v.const_val = imm;
        fn.values.push_back(v);
        const_vids[new_id] = static_cast<int64_t>(imm);

        IrInstr ci{};
        ci.op = IrOp::CONST;
        ci.type = type;
        ci.dst = new_id;
        ci.imm = imm;
        return {new_id, ci};
    };

    auto is_assoc = [](IrOp op) {
        return op == IrOp::ADD || op == IrOp::MUL || op == IrOp::AND ||
               op == IrOp::OR || op == IrOp::XOR;
    };

    auto fold_consts = [](IrOp op, int64_t a, int64_t b, int64_t &out) -> bool {
        switch (op) {
        case IrOp::ADD: out = a + b; return true;
        case IrOp::MUL: out = a * b; return true;
        case IrOp::AND: out = a & b; return true;
        case IrOp::OR: out = a | b; return true;
        case IrOp::XOR: out = a ^ b; return true;
        default: return false;
        }
    };

    struct ReassocInsert {
        size_t bb_idx;
        size_t pos;
        IrInstr instr;
    };
    std::vector<ReassocInsert> pending;

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto &bb = fn.blocks[bi];
        for (size_t i = 0; i < bb.instrs.size(); ++i) {
            IrInstr &ins = bb.instrs[i];
            if (!is_assoc(ins.op) || ins.operands.size() < 2) continue;
            int64_t c2 = 0;
            IrValueId lhs = ins.operands[0];
            IrValueId rhs = ins.operands[1];
            /* Normalizar: queremos `(x op c1) op c2` con c2 en RHS. */
            if (is_const(lhs, c2) && !is_const(rhs, c2)) {
                std::swap(lhs, rhs);
            }
            if (!is_const(rhs, c2)) continue;
            auto dit = defs.find(lhs);
            if (dit == defs.end()) continue;
            if (dit->second.bb >= fn.blocks.size()) continue;
            const auto &inner_bb = fn.blocks[dit->second.bb];
            if (dit->second.idx >= inner_bb.instrs.size()) continue;
            const IrInstr &inner = inner_bb.instrs[dit->second.idx];
            if (inner.op != ins.op || inner.operands.size() < 2) continue;
            int64_t c1 = 0;
            IrValueId x = inner.operands[0];
            IrValueId rhs_inner = inner.operands[1];
            if (is_const(x, c1) && !is_const(rhs_inner, c1)) {
                std::swap(x, rhs_inner);
            }
            if (!is_const(rhs_inner, c1)) continue;
            int64_t combined = 0;
            if (!fold_consts(ins.op, c1, c2, combined)) continue;
            auto p = make_new_const(ins.type, static_cast<uint64_t>(combined));
            pending.push_back({bi, i, p.second});
            ins.operands = {x, p.first};
            changed = true;
        }
    }
    std::sort(pending.begin(), pending.end(),
              [](const ReassocInsert &a, const ReassocInsert &b) {
                  if (a.bb_idx != b.bb_idx) return a.bb_idx > b.bb_idx;
                  return a.pos > b.pos;
              });
    for (const auto &ins_req : pending) {
        auto &bb = fn.blocks[ins_req.bb_idx];
        bb.instrs.insert(bb.instrs.begin() + ins_req.pos, ins_req.instr);
    }
    return changed;
}

// Elision COMPTIME de UNWRAP: cuando el operando es provably non-null, el
// chequeo es innecesario.  Convierte el UNWRAP en MOV (dst = operando); el
// copy_prop/DCE posterior lo eliminan -> cero codigo.
//
// Dos fuentes de "non-null":
//   1) GLOBAL (vale en cualquier punto, por dominancia del def en SSA):
//      constante != 0, ALLOCA (&local), STR_LIT_ADDR (.rodata),
//      LABEL_ADDR (codigo/dato), o el resultado de otro UNWRAP.
//   2) FLOW-SENSITIVE: dentro de la rama de un null-check.  P.ej.
//      `if (x != null) { ... !!x ... }` -> x es non-null en esa rama.
//      Se resuelve con un dataflow "must-be-non-null" sobre el CFG:
//      greatest fixpoint con init TOP (todo non-null) e interseccion en
//      los merges; los hechos se generan en las aristas de BR_COND cuyo
//      cond es CMP_NE/CMP_EQ contra 0 o ISNULL.  Captura tambien loops.
bool ir_pass_elide_unwrap(IrFunction &fn) {
    std::unordered_map<IrValueId, IrOp> def_op;
    std::unordered_map<IrValueId, const IrInstr *> def_instr;
    for (const auto &bb : fn.blocks)
        for (const auto &in : bb.instrs)
            if (in.dst != IR_NO_VALUE) {
                def_op[in.dst] = in.op;
                def_instr[in.dst] = &in;
            }

    auto globally_nonnull = [&](IrValueId v) -> bool {
        if (v < fn.values.size() && fn.values[v].is_const &&
            fn.values[v].const_val != 0)
            return true;
        auto it = def_op.find(v);
        if (it == def_op.end()) return false;
        // Allocaciones de OBJETO (clase) NUNCA devuelven null por contrato del
        // lenguaje: OOM lanza un fatal, no un null (`new X()` es non-null,
        // nunca se null-chequea).  Asi el unwrap del `!!`/nonnull sobre un
        // `new X()` recien creado es siempre non-null -> elidible.  Esto ademas
        // desbloquea el scalar-replacement (sin elidir, el UNWRAP cuenta como
        // escape).  NOTA: RAW_ALLOC (malloc) SI puede devolver null en OOM ->
        // NO se incluye (su null-check debe preservarse).
        if (it->second == IrOp::NEWOBJ || it->second == IrOp::NEWOBJS ||
            it->second == IrOp::GC_ALLOC || it->second == IrOp::GC_ALLOCP)
            return true;
        if (it->second == IrOp::CALL) {
            auto di = def_instr.find(v);
            if (di != def_instr.end() &&
                is_new_helper_name(di->second->func_name, nullptr))
                return true;
        }
        return it->second == IrOp::ALLOCA || it->second == IrOp::STR_LIT_ADDR ||
               it->second == IrOp::LABEL_ADDR || it->second == IrOp::UNWRAP;
    };

    auto is_zero = [&](IrValueId v) -> bool {
        return v < fn.values.size() && fn.values[v].is_const &&
               fn.values[v].const_val == 0;
    };

    // Sigue cadenas BITCAST/MOV hasta la raiz: estas ops copian los bits del
    // valor, asi que preservan la null-ness (un ptr es null sii su bitcast a
    // i64 es 0).  El frontend compara `bitcast(maybe) != 0` pero el unwrap usa
    // `maybe` directo -> hay que normalizar ambos a la misma raiz.
    auto resolve_alias = [&](IrValueId v) -> IrValueId {
        for (int g = 0; g < 64; ++g) {
            auto it = def_instr.find(v);
            if (it == def_instr.end()) break;
            const IrInstr *d = it->second;
            if ((d->op == IrOp::BITCAST || d->op == IrOp::MOV) &&
                !d->operands.empty())
                v = d->operands[0];
            else
                break;
        }
        return v;
    };

    // Hecho de arista de un terminador BR_COND: si su cond compara un valor
    // contra null, devuelve ese valor probado (normalizado) y si la arista
    // TRUE implica non-null.  false si no se reconoce el patron.
    auto edge_fact = [&](const IrInstr &term, IrValueId &tested,
                         bool &true_nonnull) -> bool {
        if (term.op != IrOp::BR_COND || term.operands.empty()) return false;
        auto it = def_instr.find(term.operands[0]);
        if (it == def_instr.end()) return false;
        const IrInstr *c = it->second;
        if (c->op == IrOp::ISNULL && !c->operands.empty()) {
            tested = resolve_alias(c->operands[0]); // isnull true => ES null
            true_nonnull = false;
            return true;
        }
        if ((c->op == IrOp::CMP_EQ || c->op == IrOp::CMP_NE) &&
            c->operands.size() >= 2) {
            const IrValueId a = c->operands[0], b = c->operands[1];
            if (is_zero(b))
                tested = resolve_alias(a);
            else if (is_zero(a))
                tested = resolve_alias(b);
            else
                return false;
            true_nonnull = (c->op == IrOp::CMP_NE); // x!=0 true => non-null
            return true;
        }
        return false;
    };

    const size_t nb = fn.blocks.size();
    // Mapa id de bloque -> indice (no asumimos id==indice).
    std::unordered_map<IrBlockId, size_t> idx_of;
    for (size_t i = 0; i < nb; ++i)
        idx_of[fn.blocks[i].id] = i;

    // Reticulo: para cada bloque, conjunto de valores non-null en su entrada.
    // top=true representa TOP (universo: todo non-null) para seedear el gfp.
    struct Facts {
        bool top = true;
        std::unordered_set<IrValueId> s;
    };
    std::vector<Facts> in_facts(nb);
    // Anclas: bloques sin preds (entry + inalcanzables) -> nada conocido.
    for (size_t i = 0; i < nb; ++i)
        if (fn.blocks[i].preds.empty()) in_facts[i] = Facts{false, {}};

    bool stable = false;
    int guard = 0;
    while (!stable && guard++ < 4096) {
        stable = true;
        for (size_t bi = 0; bi < nb; ++bi) {
            const IrBlock &bb = fn.blocks[bi];
            if (bb.preds.empty()) continue; // ancla fija
            Facts merged;
            merged.top = true; // identidad de la interseccion
            bool any = false;
            for (IrBlockId pid : bb.preds) {
                auto pit = idx_of.find(pid);
                if (pit == idx_of.end()) continue;
                const size_t pp = pit->second;
                // out[pp -> bi] = in[pp] (+ hecho de arista).
                Facts out = in_facts[pp];
                const IrBlock &pbb = fn.blocks[pp];
                if (!pbb.instrs.empty()) {
                    const IrInstr &term = pbb.instrs.back();
                    IrValueId tested = IR_NO_VALUE;
                    bool tnn = false;
                    if (edge_fact(term, tested, tnn)) {
                        const bool to_true =
                            (term.target_block == fn.blocks[bi].id);
                        const bool to_false =
                            (term.false_block == fn.blocks[bi].id);
                        const bool implies_nonnull =
                            (to_true && tnn) || (to_false && !tnn);
                        if (implies_nonnull && tested != IR_NO_VALUE) {
                            if (!out.top) out.s.insert(tested);
                            // si out.top, ya incluye tested (universo)
                        }
                    }
                }
                // merged = merged  interseccion  out
                if (!any) {
                    merged = std::move(out);
                    any = true;
                } else if (out.top) {
                    //  interseccion  TOP = merged (sin cambio)
                } else if (merged.top) {
                    merged = std::move(out);
                } else {
                    std::unordered_set<IrValueId> inter;
                    for (IrValueId v : merged.s)
                        if (out.s.count(v)) inter.insert(v);
                    merged.s = std::move(inter);
                }
            }
            // Comparar con el valor previo.
            Facts &cur = in_facts[bi];
            bool same = (cur.top == merged.top) && (cur.s == merged.s);
            if (!same) {
                cur = std::move(merged);
                stable = false;
            }
        }
    }

    bool changed = false;
    for (size_t bi = 0; bi < nb; ++bi) {
        auto &bb = fn.blocks[bi];
        const Facts &facts = in_facts[bi];
        for (auto &in : bb.instrs) {
            if (in.op != IrOp::UNWRAP || in.operands.empty()) continue;
            const IrValueId v = in.operands[0];
            const IrValueId vr = resolve_alias(v); // normalizar a la raiz
            // TOP en bloques alcanzables converge a no-top; si quedo top es
            // inalcanzable -> no aplicamos el hecho de flujo.
            const bool flow_nn =
                !facts.top && (facts.s.count(v) || facts.s.count(vr));
            if (globally_nonnull(v) || globally_nonnull(vr) || flow_nn) {
                in.op = IrOp::MOV; // dst = v ; copy_prop/DCE lo limpian
                changed = true;
            }
        }
    }
    return changed;
}

// Consumidor del MODELO UNICO de efectos: ¿la instruccion @p ins no tiene
// NINGUN efecto observable (segun el modelo) -> se puede eliminar si su dst
// esta muerto? Es la version del modelo de @c is_side_effecting, pero
// instruccion-aware. SOUND-conservador: exige analisis Complete + ningun may_*
// + sin escritura de memoria + control local (FallThrough).
//
// Es el DEFAULT (el compilador consume el modelo unico): se valido A/B contra
// is_side_effecting (salida .velb BYTE-IDeNTICA en el corpus + e2e 724/0 en
// interp/jit/aot).  VESTA_DCE_EFFECTS=0 revierte a la tabla is_side_effecting
// (escape-hatch para diagnostico/comparacion).
static bool g_dce_effects = util::flag_on(util::FlagId::DceEffects);

// Unificacion del modelo de memoria (Fase 3): cuando esta activo, el DSE
// construye su resolucion de direcciones (addr_of/root_kind) desde el
// RESOLVEDOR COMPARTIDO (analysis::compute_points_to) en lugar de su fixpoint
// privado -- misma fuente que el modelo de efectos.  Toda la logica downstream
// (cobertura, barreras, forwarding, heap/stack) queda IGUAL.  A/B via
// VESTA_DSE_UNIFIED=1; default OFF hasta validar e2e 3 modos + patrones de
// regresion (copy-alias, STRMAKE, mvtake, buffer meta-OOP).
/**
 * @brief ¿Se trata un bloque `asm` por lo que TOCA en vez de como barrera?
 *
 * `VESTA_ASM_DSE=0` vuelve a la barrera total de siempre.  El analisis del asm
 * ya sabe decir que memoria toca cada bloque; esto es lo que hace que sirva de
 * algo, porque hasta ahora ningun consumidor lo miraba.
 */
static bool asm_dse_activo() {
    static const bool on = util::flag_on(util::FlagId::AsmDse);
    return on;
}

// ENCENDIDO por defecto (2026-08-06).  Medido: no cambia el codigo generado en
// NINGUNO de los 29 programas del corpus -- toma las mismas decisiones que la
// resolucion propia que tenia el DSE --, y la suite pasa 878/0 en los tres
// modos.  Encenderlo no es una apuesta de rendimiento: es que deje de haber dos
// resoluciones de direcciones distintas.  `VESTA_DSE_UNIFIED=0` vuelve atras.
static bool g_dse_unified = util::flag_on(util::FlagId::DseUnified);

// Fase 4 (valor INTERPROCEDURAL del modelo de efectos): cuando esta activo, una
// CALL a un callee TOTALMENTE PURO (segun EffectAnalysis: sin mem, sin may_*,
// sin tags, Complete) deja de ser barrera de memoria en el DSE.  Es informacion
// que el DSE por si solo NO puede tener (requiere el cierre interprocedural).
// A/B via VESTA_DSE_PURE_CALLS=1.  Se queda APAGADO, y no por dudas de
// correccion -- la suite pasa 878/0 con el encendido -- sino porque MEDIDO no
// cambia el codigo generado en ninguno de los 29 programas del corpus: no hay
// ninguna llamada totalmente pura que hoy este haciendo de barrera.  Cuando la
// haya, el mecanismo ya esta.
static bool g_dse_pure_calls = util::flag_on(util::FlagId::DsePureCalls);

// Scheduling alias-aware (consumidor del modelo de memoria UNICO): el DAG de
// dependencias del list-scheduler modela las hazards de memoria por may_alias
// (dos accesos a raices DISJUNTAS no se ordenan entre si -> mas ILP) en lugar
// del orden total conservador.  El scheduler CONSERVA su DAG/critical-path;
// solo AFINA las aristas de memoria con la alias compartida.  A/B via
// VESTA_SCHED_ALIAS=1; default OFF hasta validar e2e 3 modos + bench.
// ENCENDIDO por defecto (2026-08-06), una vez arreglado el acarreo (ver la
// guarda de `blk_has_carry` mas abajo, que era lo que lo tenia parado: con mas
// libertad para reordenar se colaba algo entre una suma y su acarreo).
// Medido: cambia el codigo en 16 de los 29 programas del corpus -- es el unico
// consumidor del modelo de memoria con alcance real -- y sale mejor en 6 de 8
// benches, ~2% en los dos largos, que son donde el arranque diluye menos.
// Suite 878/0 en los tres modos.  `VESTA_SCHED_ALIAS=0` vuelve atras.
static bool g_sched_alias = util::flag_on(util::FlagId::SchedAlias);

// Load-to-load CSE (nuevo consumidor del alias): el DSE ya forwardea
// store->load (last_store_val); con esto un LOAD que NO forwardea registra su
// valor como disponible para su direccion -> un LOAD POSTERIOR de la MISMA
// direccion (must-alias, sin store aliasante entre medias) reusa el primero
// (LOAD -> MOV). Reusa la invalidacion probada del DSE (stores/barreras limpian
// last_store_val). A/B via VESTA_LOAD_CSE=1.  APAGADO por lo mismo: la suite
// pasa con el, pero medido solo cambia el codigo en 1 de los 29 programas del
// corpus y no quita ni una instruccion ejecutada.  La condicion que exige --
// misma direccion, sin ningun store en medio, y se invalida en CUALQUIER store
// -- casi no se da.
static bool g_load_cse = util::flag_on(util::FlagId::LoadCse);

// LICM alias-aware (consumidor del modelo de memoria UNICO): hoistear un LOAD
// invariante aunque el loop tenga escrituras, si NINGUN store del loop puede
// aliasar su localizacion Y toda call del loop es pura.  Hoy LICM bloquea TODOS
// los loads si hay CUALQUIER escritura/call ("sin alias analysis").  A/B via
// VESTA_LICM_ALIAS=1.  APAGADO: suite en verde con el, pero medido no cambia
// el codigo en ninguno de los 29 programas -- los loads invariantes que quedan
// dentro de un loop con escrituras no aparecen en el corpus.
static bool g_licm_alias = util::flag_on(util::FlagId::LicmAlias);

/// Localizaciones que ALGUIEN de la funcion lee, o donde puede leer.
///
/// Sirve para responder a "¿le importa a alguien lo que esta escritura deja?".
/// Una instruccion opaca en cualquier punto de la funcion colapsa el conjunto a
/// TOP y entonces la respuesta es siempre "si", que es lo correcto: no se sabe
/// que lee.
static analysis::effects::LocSet
locs_leidas(const IrFunction &fn, const analysis::IrFacts &facts,
            const analysis::PointsTo &pt,
            const analysis::effects::EffectEnv &env) {
    analysis::effects::LocSet leidas;
    for (const IrBlock &bb : fn.blocks) {
        for (const IrInstr &in : bb.instrs) {
            const analysis::effects::EffectAnalysisResult r =
                analysis::effects::effects_of_instr(fn, facts, pt, in, env);
            /* Lo que no se pudo analizar cuenta como "lee cualquier cosa": el
             * conjunto describe de que memoria depende el programa, y algo
             * incompleto puede depender de toda. */
            if (r.completeness !=
                analysis::effects::AnalysisCompleteness::Complete) {
                leidas.is_top = true;
                leidas.locs.clear();
                leidas.indice_obsoleto(); // se toco el vector por fuera
                return leidas;
            }
            leidas.unite(r.effects.mem.reads);
            if (leidas.is_top) return leidas;
        }
    }
    return leidas;
}

/* Para partir un pase caro POR DENTRO se usa `util::CronoTramo`: el reparto por
 * pase dice cual lo es, y el tramo dice por que.
 *
 * Aqui habia una copia con el mismo nombre.  Existia porque en su dia
 * alimentaba otro acumulador, pero acabo reenviando al de `util` -- o sea, dos
 * clases para el mismo destino.  Dos formas de medir lo mismo acaban dando dos
 * numeros distintos y no hay manera de saber cual creerse. */
using util::CronoTramo;

static bool model_removable(const IrFunction &fn,
                            const analysis::IrFacts &facts,
                            const analysis::PointsTo &pt, const IrInstr &ins,
                            const analysis::effects::EffectEnv &env,
                            const analysis::effects::LocSet &leidas) {
    CronoTramo crono__("  dce:efectos-por-instr");
    const analysis::effects::EffectAnalysisResult r =
        analysis::effects::effects_of_instr(fn, facts, pt, ins, env);
    if (r.completeness != analysis::effects::AnalysisCompleteness::Complete)
        return false;
    const analysis::effects::SemanticEffects &e = r.effects;
    if (e.may_trap || e.may_throw || e.may_panic || e.may_allocate ||
        e.may_block || e.may_io || !e.tags.empty() || !e.determinism.empty() ||
        e.atomic.order != analysis::effects::MemOrder::None ||
        e.atomic.is_fence)
        return false;
    if (e.control.kind != analysis::effects::ControlKind::FallThrough) {
        /* Una llamada cede el control, y su efecto LOCAL es solo eso: lo que
         * hace el destino lo pone el cierre interprocedural.  Asi que aqui no
         * se puede leer "sin efectos locales" como "no hace nada" -- una nativa
         * de la que nadie ha dicho nada tiene exactamente esa pinta.
         *
         * La excepcion es la nativa DECLARADA: ahi la declaracion SI es todo lo
         * que hace, resuelta ademas a memoria concreta en este sitio de
         * llamada.  Es el unico caso en que una llamada se puede juzgar por su
         * efecto local. */
        if (ins.op != IrOp::CALLN || env.decls == nullptr) return false;
        if (env.decls->find(ins.func_name) == env.decls->end()) return false;
        if (e.control.kind != analysis::effects::ControlKind::Call)
            return false;
    }
    if (!e.mem.writes_memory()) return true;

    /* Escribir no es, por si solo, un efecto observable: lo es dejar algo que
     * alguien va a leer.  Una nativa DECLARADA que solo llena un buffer que
     * nadie mira no cambia nada de lo que el programa hace, y conservarla
     * porque "toca memoria" es tratar la declaracion como si no existiera.
     *
     * La condicion se comprueba contra el conjunto de lo que lee TODA la
     * funcion, incluida ella misma: una escritura que se lee a si misma no se
     * quita, y basta una instruccion opaca en cualquier sitio para que el
     * conjunto sea TOP y no se quite nada.  Lo que escapa tampoco se pierde:
     * pasar la direccion a algo que no se puede analizar es justo lo que
     * vuelve TOP el conjunto. */
    if (leidas.is_top || e.mem.writes.is_top) return false;
    for (const analysis::effects::AbstractLoc &w : e.mem.writes.locs) {
        /* SOLO pila, y de una raiz concreta.  El conjunto de lecturas se
         * calcula dentro de esta funcion, asi que solo puede decir la ultima
         * palabra sobre memoria que no sobrevive a la funcion: lo que se
         * escribe en el heap, en una global o a traves de un parametro lo lee
         * quien llama, y aqui no se ve.  Un marco de pila, en cambio, muere al
         * volver: si nadie lo lee aqui, no lo lee nadie. */
        if (w.kind != analysis::effects::AbstractLoc::Kind::Stack) return false;
        if (!w.concrete()) return false;
        if (leidas.may_alias_any(w)) return false;
    }
    return !e.mem.writes.locs.empty();
}

bool ir_pass_dce(IrFunction &fn, const analysis::effects::NativeDecls *decls,
                 const analysis::AsmBindingFacts *asm_bindings,
                 CacheEfectosDce *cache) {
    // Modelo de efectos: hechos + points-to por-funcion para el consumidor del
    // DCE (el mismo resolvedor de direcciones que usa todo el tooling).
    analysis::IrFacts fx_facts;
    analysis::PointsTo fx_pt;
    const analysis::IrFacts &hechos = fx_facts;
    const analysis::PointsTo &apunta_a = fx_pt;
    analysis::effects::EffectEnv fx_env;
    fx_env.decls = decls;
    /* Las ligaduras del asm, si quien llama las tiene cacheadas.  Sin esto el
     * modelo de efectos las recalcula por instruccion. */
    fx_env.asm_bindings = asm_bindings;
    /* Y los rangos, por lo mismo: sin esto el modelo recorre la funcion ENTERA
     * una vez por bloque de asm.  Se sujeta el puntero mientras dure el pase.
     */
    std::shared_ptr<const analysis::RangeFacts> fx_rangos;
    analysis::effects::LocSet fx_leidas;
    fx_leidas.is_top = true; // sin modelo, se supone que todo se lee
    if (g_dce_effects) {
        CronoTramo crono__("  dce:hechos");
        /* Los hechos y el points-to se reconstruyen en CADA llamada, y el pase
         * corre una vez por funcion y por vuelta del punto fijo.
         *
         * INTENTADO DOS VECES Y DESCARTADO, y las dos por motivos distintos --
         * conviene no repetirlas:
         *
         *   1. Prestarle los que el orquestador ya tiene cacheados
         *      (`facts_of`/`pt_of`) daba FALLO DE SEGMENTACION en 3 de cada 6
         *      ejecuciones.  `IrFacts::def_of` guarda PUNTEROS a instrucciones
         * y los cacheados sobrevivian a mutaciones del IR.  Eso YA NO PASA: lo
         * cerro el sello de version (`IrFunction::version` +
         *      `AnalysisManager::get_or_compute_v`), con el que las mismas seis
         *      ejecuciones dan cero fallos.
         *
         *   2. Aun siendo seguro, NO COMPENSA: prestarselos sube el optimizador
         *      de 2.440-2.482 ms a 2.560-2.594 ms.  El motivo lo dijo este
         * mismo tramo -- al prestarlos NO bajo --: lo que cuesta aqui no es el
         *      def-use ni el points-to, es el calculo de rangos del guarda de
         *      asm que viene despues.  Se pagaban dos consultas mas por llamada
         *      para ahorrar algo que ya era barato.
         *
         * O sea: la via esta abierta y medida, y no vale la pena por ahora. */
        fx_facts = analysis::build_ir_facts(fn);
        fx_pt = analysis::compute_points_to(fn, fx_facts);
        /* Cuantas veces se piden los rangos de una misma funcion.  El arreglo
         * del EffectEnv movio el coste de "una vez por bloque de asm" a "una
         * vez por pasada del DCE"; si esa cuenta es alta, lo que sobra es la
         * invalidacion en cascada, no el calculo. */
        /* Solo si hay asm: es lo unico que los consume aqui.  Calcularlos para
         * TODA funcion salia carisimo -- recorrer la funcion entera, por
         * funcion y por vuelta del punto fijo, para que nadie los mirara
         * (medido con las pilas: 40 % del tiempo, y lo habia metido este mismo
         * arreglo). */
        if (analysis::effects::funcion_tiene_asm(fn)) {
            static std::atomic<long long> n_peticiones{0};
            static std::atomic<long long> ns_peticiones{0};
            // Reloj del proyecto (TSC calibrado): ~5 ns por lectura frente a
            // ~50 del de la biblioteca estandar, que es la diferencia entre ver
            // esto y no.
            const uint64_t t_r = util::reloj::ahora();
            fx_rangos = analysis::compute_ranges_ptr(fn, hechos);
            fx_env.rangos = fx_rangos.get();
            fx_env.rangos_de = &fn;
            ns_peticiones += util::reloj::a_ns(util::reloj::ahora() - t_r);
            if ((++n_peticiones % 500) == 0 &&
                util::flag_on(util::FlagId::Times))
                std::fprintf(stderr, "[dce-rangos] %lld peticiones | %lld ms\n",
                             n_peticiones.load(),
                             ns_peticiones.load() / 1000000);
        }
        fx_leidas = locs_leidas(fn, hechos, apunta_a, fx_env);
    }

    // Construir conjunto de valores que son usados en algun operando
    std::unordered_set<IrValueId> used;
    {
        /* Cada tramo en SU bloque: un cronometro de ambito mide hasta que
         * termina el suyo, y suelto acaba midiendo el resto de la funcion. */
        CronoTramo crono_usados__("  dce:usados");
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                for (IrValueId op : ins.operands) {
                    if (op != IR_NO_VALUE) used.insert(op);
                }
                // CALLIND y CALLCLOSURE referencian el callee via func_ptr (no
                // via operands), asi que DCE debe contarlo como uso para que el
                // SSA value que produjo el puntero (e.g. RAW_ASM `mov rN,
                // @Abs(...)` o LOAD del slot del function value) NO sea
                // eliminado. Sin esto, las closures se rompen: el optimizer
                // purga la instr que materializa fn_addr y el regalloc deja r14
                // (asignado a fn_addr_v) sin inicializar -> callvmr salta a 0 y
                // crash.
                if ((ins.op == IrOp::CALLIND || ins.op == IrOp::CALLCLOSURE) &&
                    ins.func_ptr != IR_NO_VALUE) {
                    used.insert(ins.func_ptr);
                }
                for (const auto &pa : ins.phi_args) {
                    if (pa.value != IR_NO_VALUE) used.insert(pa.value);
                }
            }
        }
        /* Los punteros de clase de la devirtualizacion especulativa, por lo
         * mismo que el `func_ptr` de arriba: se referencian desde una tabla
         * lateral (@c spec_devirt_sites), no desde un operando, asi que aqui no
         * se ven usados -- y todavia no lo estan, porque las guardas que los
         * comparan las crea @c ir_pass_spec_devirt DESPUES de este pase.
         *
         * Sin esto se borraban por muertos, las guardas nacian apuntando a
         * valores que ya no existian, y al emitir esos operandos caian en un
         * registro de scratch con lo que hubiera dentro.  El resultado: NINGUNA
         * guarda acertaba nunca, cada llamada pagaba las K comparaciones
         * fallidas Y el despacho original.
         *
         * No lo delataba ningun test porque la especulacion es correcta por
         * construccion -- si nada casa, se cae al despacho de siempre --, asi
         * que el programa daba el resultado bueno y solo perdia tiempo:
         * `bench_pic_real` tardaba un 77% mas que sin el pase. */
        for (const auto &kv : fn.spec_devirt_sites)
            for (const DevirtCandidate &c : kv.second)
                if (c.cls_value != IR_NO_VALUE) used.insert(c.cls_value);
    }
    /* La cache se valida por TAMANO: si la funcion tiene otras instrucciones
     * que cuando se lleno, las posiciones ya no significan lo mismo y se tira
     * entera.  Es la comprobacion mas barata que es SOUND -- quedarse corto
     * (tirarla de mas) solo cuesta volver a preguntar. */
    size_t total_instrs = 0;
    for (const auto &bb : fn.blocks)
        total_instrs += bb.instrs.size();
    /* Y por OBJETIVO: la misma instruccion no tiene los mismos efectos en la
     * maquina virtual que compilando a nativo, ni un bloque de asm dice lo
     * mismo leido con la tabla de x86 que con la de ARM.  Servir lo guardado
     * para otro objetivo seria contestar de otro programa. */
    const int backend_actual = static_cast<int>(fx_env.backend);
    const std::string isa_actual = vx::asm_arch_actual();
    if (cache != nullptr &&
        (cache->n != total_instrs || cache->resp.size() != total_instrs ||
         cache->backend != backend_actual || cache->isa != isa_actual)) {
        cache->n = total_instrs;
        cache->backend = backend_actual;
        cache->isa = isa_actual;
        cache->resp.assign(total_instrs, -1);
    }
    size_t idx_lineal = 0;  ///< posicion de la instruccion al LEERLA.
    size_t idx_escrito = 0; ///< posicion que ocupara tras compactar.

    bool changed = false;
    {
        CronoTramo crono_barrer__("  dce:barrer");
        for (auto &bb : fn.blocks) {
            auto &instrs = bb.instrs;
            size_t write = 0;
            for (size_t i = 0; i < instrs.size(); ++i) {
                const IrInstr &ins = instrs[i];
                bool keep = true;
                // Una instruccion con resultado no usado y sin efectos
                // laterales se elimina, EXCEPTO si lleva el flag @c preserve
                // (barreras del codegen). Sin efectos: por defecto la tabla
                // is_side_effecting (op-only); con VESTA_DCE_EFFECTS, el MODELO
                // unico (instruccion-aware).  El caso alloc-only-string se
                // mantiene en ambos (el modelo lo veria como may_allocate y no
                // lo quitaria; se conserva la optimizacion).
                /* Lo que el modelo dijo de ESTA instruccion, si ya se le
                 * pregunto y la funcion no ha cambiado desde entonces.  No es
                 * un criterio paralelo ni una lista aparte: es su propia
                 * respuesta, guardada. Se pregunta una vez y se reusa en las
                 * pasadas siguientes. */
                const size_t pos = idx_lineal++;
                bool modelo_dice = false;
                if (g_dce_effects) {
                    int8_t guardado =
                        (cache != nullptr && pos < cache->resp.size())
                            ? cache->resp[pos]
                            : static_cast<int8_t>(-1);
                    if (guardado < 0) {
                        modelo_dice = model_removable(fn, hechos, apunta_a, ins,
                                                      fx_env, fx_leidas);
                        if (cache != nullptr && pos < cache->resp.size())
                            cache->resp[pos] = modelo_dice ? 1 : 0;
                    } else {
                        modelo_dice = (guardado == 1);
                    }
                }
                const bool no_effect =
                    g_dce_effects
                        ? (modelo_dice || alloc_only_string_op(ins.op))
                        : (!is_side_effecting(ins.op) ||
                           alloc_only_string_op(ins.op));
                /* Una llamada nativa puede no devolver nada y aun asi sobrar:
                 * si lo unico que hacia era escribir donde nadie lee, no queda
                 * de ella nada que observar.
                 *
                 * Se limita a CALLN A PROPOSITO.  "No produce valor" no es, en
                 * general, motivo para quitar nada: hay ops cuyo efecto ES lo
                 * que dejan en el runtime (registrar un campo o un metodo de
                 * una clase, por ejemplo) y que el modelo todavia describe como
                 * neutras. Generalizarlo borraba el arranque de los modulos con
                 * clases. */
                const bool sin_resultado_util =
                    ins.dst != IR_NO_VALUE
                        ? used.count(ins.dst) == 0
                        : (g_dce_effects && ins.op == IrOp::CALLN);
                if (sin_resultado_util && no_effect && !ins.preserve) {
                    keep = false;
                    changed = true;
                }
                if (keep) {
                    /* La respuesta guardada viaja con su instruccion. Compactar
                     * la cache en vez de tirarla es lo que hace que sirva de
                     * una pasada a la siguiente: quitar codigo muerto solo
                     * ENCOGE lo que la funcion lee, asi que un "no se puede
                     * quitar" guardado sigue siendo cierto -- a lo sumo se
                     * queda corto y se vuelve a preguntar mas adelante.  Nunca
                     * al reves. */
                    if (cache != nullptr && pos < cache->resp.size() &&
                        idx_escrito < cache->resp.size())
                        cache->resp[idx_escrito] = cache->resp[pos];
                    ++idx_escrito;
                    if (write != i) instrs[write] = std::move(instrs[i]);
                    ++write;
                }
            }
            instrs.resize(write);
        }
        /* La cache queda del tamano de lo que ha sobrevivido, para que la
         * proxima pasada la de por buena en vez de tirarla por no cuadrar el
         * tamano. */
        if (cache != nullptr) {
            cache->resp.resize(idx_escrito);
            cache->n = idx_escrito;
        }
    }
    return changed;
}

// =========================================================================
//  Pase de propagacion de copias
// =========================================================================

bool ir_pass_copy_prop(IrFunction &fn) {
    // Construir mapa de sustituciones: %b -> %a para cada "%b = mov %a"
    std::unordered_map<IrValueId, IrValueId> subst;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::MOV && !ins.preserve &&
                ins.dst != IR_NO_VALUE && ins.operands.size() == 1 &&
                ins.operands[0] != IR_NO_VALUE) {
                // seguir la cadena de sustituciones
                IrValueId src = ins.operands[0];
                while (subst.count(src))
                    src = subst[src];
                subst[ins.dst] = src;
            }
        }
    }
    if (subst.empty()) return false;

    // Aplicar sustituciones en todos los operandos
    bool changed = false;
    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            // sustituir operandos normales
            for (auto &op : ins.operands) {
                auto it = subst.find(op);
                if (it != subst.end() && it->second != op) {
                    op = it->second;
                    changed = true;
                }
            }
            // sustituir func_ptr en CALLIND
            if (ins.func_ptr != IR_NO_VALUE) {
                auto it = subst.find(ins.func_ptr);
                if (it != subst.end() && it->second != ins.func_ptr) {
                    ins.func_ptr = it->second;
                    changed = true;
                }
            }
            // sustituir argumentos phi
            for (auto &pa : ins.phi_args) {
                auto it = subst.find(pa.value);
                if (it != subst.end() && it->second != pa.value) {
                    pa.value = it->second;
                    changed = true;
                }
            }
        }
    }
    // Eliminar los MOV que ahora son copias triviales (%a = mov %a)
    /* Etiquetado: el DCE tambien se llama DESDE otros pases para limpiar lo
     * que acaban de generar.  Sin contarlo, su tramo interno (`dce:hechos`)
     * salia con mas tomas que el propio pase y el reparto no cuadraba. */
    if (changed) {
        util::CronoTramo crono__("  dce:limpieza-en-pase");
        ir_pass_dce(fn);
    }
    return changed;
}

// =========================================================================
//  Pase de plegado de constantes
// =========================================================================

/** @brief Devuelve el valor constante de un IrValue, o UNDEF si no es const. */
static bool get_const(const IrFunction &fn, IrValueId id, uint64_t &val) {
    if (id == IR_NO_VALUE || id >= static_cast<IrValueId>(fn.values.size()))
        return false;
    const IrValue &v = fn.values[id];
    if (!v.is_const) return false;
    val = v.const_val;
    return true;
}

bool ir_pass_const_fold(IrFunction &fn) {
    bool changed = false;

    /* Alineacion demostrable de cada valor.  Sirve para plegar `p & (k-1)`
     * cuando se sabe que `p` es multiplo de k: el resultado es cero, y con el
     * se cae la comparacion y la rama que colgaba de ella.
     *
     * Es la pregunta que un programa se hace en EJECUCION teniendo aqui la
     * respuesta -- `if ((dir & 31) == 0) usar_la_alineada()` --, y responderla
     * al compilar convierte dos caminos en uno.  No hace falta que el
     * programador escriba nada distinto: escribe la comprobacion, que es lo
     * correcto, y desaparece cuando sobra. */
    const analysis::AlignmentFacts alin = analysis::compute_alignment(fn);
    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            if (ins.op != IrOp::AND || ins.dst == IR_NO_VALUE ||
                ins.operands.size() != 2)
                continue;
            // Uno de los dos lados es la mascara `k-1`.
            for (int lado = 0; lado < 2; ++lado) {
                const IrValueId m = ins.operands[lado];
                const IrValueId p = ins.operands[1 - lado];
                uint64_t mk = 0;
                if (!get_const(fn, m, mk)) continue;
                if (mk == 0 || mk == ~0ull) continue;
                const uint64_t k = mk + 1;
                // Solo mascaras de la forma k-1 con k potencia de dos.
                if ((k & (k - 1)) != 0) continue;
                if (k > 0xFFFFFFFFull) continue;
                if (!alin.multiplo_de(p, (uint32_t)k)) continue;
                // Multiplo de k -> los bits bajos son cero.
                ins.op = IrOp::CONST;
                ins.imm = 0;
                ins.operands.clear();
                if (ins.dst < fn.values.size()) {
                    fn.values[ins.dst].is_const = true;
                    fn.values[ins.dst].const_val = 0;
                }
                changed = true;
                break;
            }
        }
    }

    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            if (ins.dst == IR_NO_VALUE) continue;
            if (!is_pure(ins.op)) continue;

            // --- Operaciones binarias enteras ---
            if (ins.operands.size() == 2) {
                uint64_t a, b;
                bool ca = get_const(fn, ins.operands[0], a);
                bool cb = get_const(fn, ins.operands[1], b);
                if (!ca || !cb) continue;

                uint64_t res = 0;
                bool folded = true;
                int64_t sa = static_cast<int64_t>(a);
                int64_t sb = static_cast<int64_t>(b);

                switch (ins.op) {
                case IrOp::ADD: res = a + b; break;
                case IrOp::SUB: res = a - b; break;
                case IrOp::MUL: res = a * b; break;
                /* Sprint edge-bugs (2026-06-02): si el divisor es CONST 0,
                 * NO foldear -- dejar la operacion en runtime para que el
                 * interp/JIT lance FatalError capturable.  Antes esto se
                 * foldeaba a 0 silencioso ocultando el bug del programa. */
                case IrOp::DIV:
                    if (sb == 0) {
                        folded = false;
                        break;
                    }
                    res = (uint64_t)(sa / sb);
                    break;
                case IrOp::MOD:
                    if (sb == 0) {
                        folded = false;
                        break;
                    }
                    res = (uint64_t)(sa % sb);
                    break;
                case IrOp::AND: res = a & b; break;
                case IrOp::OR: res = a | b; break;
                case IrOp::XOR: res = a ^ b; break;
                case IrOp::SHL: res = a << (b & 63); break;
                case IrOp::SHR: res = a >> (b & 63); break;
                case IrOp::SAR: res = (uint64_t)(sa >> (b & 63)); break;
                // comparaciones enteras -> resultado bool (0 o 1)
                case IrOp::CMP_EQ: res = (a == b) ? 1 : 0; break;
                case IrOp::CMP_NE: res = (a != b) ? 1 : 0; break;
                case IrOp::CMP_LT: res = (sa < sb) ? 1 : 0; break;
                case IrOp::CMP_GT: res = (sa > sb) ? 1 : 0; break;
                case IrOp::CMP_LE: res = (sa <= sb) ? 1 : 0; break;
                case IrOp::CMP_GE: res = (sa >= sb) ? 1 : 0; break;
                case IrOp::CMP_ULT: res = (a < b) ? 1 : 0; break;
                case IrOp::CMP_UGT: res = (a > b) ? 1 : 0; break;
                case IrOp::CMP_ULE: res = (a <= b) ? 1 : 0; break;
                case IrOp::CMP_UGE: res = (a >= b) ? 1 : 0; break;
                default: folded = false; break;
                }

                if (folded) {
                    ins.op = IrOp::CONST;
                    ins.imm = res;
                    ins.operands.clear();
                    ins.type =
                        (ins.op == IrOp::CMP_EQ) ? IrType::BOOL : ins.type;
                    // marcar el valor destino como constante
                    if (ins.dst < static_cast<IrValueId>(fn.values.size())) {
                        fn.values[ins.dst].is_const = true;
                        fn.values[ins.dst].const_val = res;
                    }
                    changed = true;
                }
            }

            // --- Operaciones unarias enteras ---
            if (ins.operands.size() == 1) {
                uint64_t a;
                if (!get_const(fn, ins.operands[0], a)) continue;

                uint64_t res = 0;
                bool folded = true;
                int64_t sa = static_cast<int64_t>(a);

                switch (ins.op) {
                case IrOp::NEG: res = (uint64_t)(-sa); break;
                case IrOp::NOT: res = ~a; break;
                case IrOp::ZEXT: res = a; break;
                case IrOp::TRUNC: {
                    /* Sprint edge-bugs (2026-06-02): TRUNC debe
                     * preservar el signo si el tipo destino es
                     * signed (i8/i16/i32).  Antes hacia
                     * `a & 0xFFFFFFFF` lo que para `-7` (signed i32)
                     * truncado dejaba `0x00000000FFFFFFF9` -- valor
                     * UNSIGNED 4294967289, no -7.  Operaciones
                     * downstream (e.g. const-fold de `mod.i32`) lo
                     * interpretaban como positivo -> resultado
                     * equivocado del modulo signed.
                     *
                     * Fix: para tipos signed, sign-extender el bit
                     * mas alto del ancho destino al resto del u64.
                     * Para unsigned, mask simple. */
                    uint64_t mask;
                    bool sign_extend = false;
                    switch (ins.type) {
                    case IrType::I8:
                        mask = 0xFFULL;
                        sign_extend = true;
                        break;
                    case IrType::I16:
                        mask = 0xFFFFULL;
                        sign_extend = true;
                        break;
                    case IrType::I32:
                        mask = 0xFFFFFFFFULL;
                        sign_extend = true;
                        break;
                    case IrType::U8: mask = 0xFFULL; break;
                    case IrType::U16: mask = 0xFFFFULL; break;
                    case IrType::U32: mask = 0xFFFFFFFFULL; break;
                    case IrType::BOOL: mask = 0x1ULL; break;
                    default:
                        /* Sin truncacion real (mismo ancho). */
                        mask = 0xFFFFFFFFFFFFFFFFULL;
                        break;
                    }
                    res = a & mask;
                    if (sign_extend) {
                        const uint64_t sign_bit = (mask >> 1) + 1;
                        if (res & sign_bit) {
                            /* Bit alto del ancho destino set -> negativo.
                             * Or-ear los bits altos para sign-extend a u64. */
                            res |= ~mask;
                        }
                    }
                    break;
                }
                case IrOp::MOV: res = a; break;
                default: folded = false; break;
                }

                if (folded) {
                    ins.op = IrOp::CONST;
                    ins.imm = res;
                    ins.operands.clear();
                    if (ins.dst < static_cast<IrValueId>(fn.values.size())) {
                        fn.values[ins.dst].is_const = true;
                        fn.values[ins.dst].const_val = res;
                    }
                    changed = true;
                }
            }
        }
    }

    /* Terminador con condicion CONSTANTE: `BR_COND const -> t, f` es un salto
     * incondicional al lado que toca, y el otro deja de tener esta arista.
     *
     * Sin esto, TODO `if` resuelto en comptime dejaba sus dos ramas en el
     * binario: `ir_pass_unreachable` marca alcanzables los DOS destinos de un
     * BR_COND sin mirar la condicion, asi que el lado muerto sobrevivia entero.
     * Se veia en `atomic<i64>::fetch_add`: el `if (is_float<T>())` foldea a
     * CONST 0, pero el bucle CAS de la rama float se quedaba dentro -- codigo
     * muerto en cada metodo, y un Big-O inferido de O(n) sobre algo que es un
     * `lock xadd`.  Plegar aqui deja que `unreachable` haga su trabajo detras.
     *
     * Al perder la arista `bi -> dropped` hay que quitar de los PHI de
     * `dropped` los args que vinieran de `bi`: si `dropped` sigue siendo
     * alcanzable por otro camino, `unreachable` no lo tocaria y el PHI se
     * quedaria citando a un predecesor que ya no salta ahi. */
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto &bb = fn.blocks[bi];
        if (bb.instrs.empty()) continue;
        IrInstr &term = bb.instrs.back();
        if (term.op != IrOp::BR_COND || term.operands.empty()) continue;
        uint64_t c = 0;
        if (!get_const(fn, term.operands[0], c)) continue;

        const IrBlockId taken = (c != 0) ? term.target_block : term.false_block;
        const IrBlockId dropped =
            (c != 0) ? term.false_block : term.target_block;

        term.op = IrOp::BR;
        term.target_block = taken;
        term.false_block = IR_NO_BLOCK;
        term.operands.clear();
        changed = true;

        /* Los dos lados iban al mismo sitio: no se pierde ninguna arista. */
        if (dropped == taken || dropped == IR_NO_BLOCK ||
            dropped >= fn.blocks.size())
            continue;

        auto &dst = fn.blocks[dropped];
        dst.preds.erase(std::remove(dst.preds.begin(), dst.preds.end(),
                                    static_cast<IrBlockId>(bi)),
                        dst.preds.end());
        for (auto &ins : dst.instrs) {
            if (ins.op != IrOp::PHI) continue;
            ins.phi_args.erase(
                std::remove_if(ins.phi_args.begin(), ins.phi_args.end(),
                               [&](const IrPhiArg &pa) {
                                   return pa.block ==
                                          static_cast<IrBlockId>(bi);
                               }),
                ins.phi_args.end());
        }
        bb.succs.erase(std::remove(bb.succs.begin(), bb.succs.end(), dropped),
                       bb.succs.end());
    }
    return changed;
}

// =========================================================================
//  Pase de eliminacion de bloques inalcanzables
// =========================================================================

// =========================================================================
//  Pase Dead Store Elimination
// =========================================================================
//
// Para cada bloque basico, detecta STOREs sucesivos a la MISMA direccion
// sin lecturas intermedias.  El primer STORE es muerto: su valor sera
// sobrescrito sin ser leido.
//
// Es conservador con side-effects: cualquier CALL/RAW_ASM/CALLN limpia el
// estado (no podemos garantizar que el callee no lea la memoria).
//
// Patron comun en frontend Vesta:
//   %a = const.i64 0
//   store %a, %slot
//   ...   (sin LOAD de %slot, sin CALL)
//   %b = const.i64 42
//   store %b, %slot   <-- valor que persiste; el store anterior es dead
//
// Bajo esto a IR:
//   - El primer STORE se marca para eliminar
//   - La CONST que solo alimentaba al store dead queda dead -> DCE la quita
//
// Ahorro: en codigo generado por frontend Vesta se ven STOREs de zero seguidos
// de STOREs reales (init list, alloca cleared, etc).  ~10-15% reduccion.
bool ir_pass_dse(IrFunction &fn, const analysis::PointsTo *pt,
                 const std::unordered_set<std::string> *pure_callees,
                 const HechosDeAsmParaDse *hechos_asm) {
    bool changed = false;

    // ¿Es esta CALL/TAILCALL a un callee TOTALMENTE PURO?  Entonces NO es
    // barrera de memoria (conocimiento INTERPROCEDURAL del modelo de efectos:
    // el DSE por si solo no puede saber que hace el callee).
    auto is_pure_call = [&](const IrInstr &ins) -> bool {
        if (!g_dse_pure_calls || !pure_callees) return false;
        if (ins.op != IrOp::CALL && ins.op != IrOp::TAILCALL) return false;
        return !ins.func_name.empty() && pure_callees->count(ins.func_name) > 0;
    };

    // Alias-safety del store-to-load forwarding.
    //
    // CANONICALIZACION DE DIRECCIONES (bug fix 2026-07-15): una direccion se
    // representa por su par (RAIZ, OFFSET constante), NO por su IrValueId.
    // La raiz es el dst de un ALLOCA (stack) o de un allocador (heap); el
    // offset se acumula al derivar por ADD con constante.  Las COPIAS
    // (MOV/BITCAST) heredan RAIZ Y OFFSET, es decir, la MISMA direccion.
    //
    // Antes se indexaba el forwarding por IrValueId crudo y las copias se
    // metian en el conjunto de "direcciones precisas" como valores NUEVOS.
    // Dos ids distintos se asumian NO aliasados, pero `%b2 = mov %b` es la
    // MISMA direccion -> un STORE via la copia no invalidaba el valor
    // conocido de la original y el LOAD posterior reenviaba un valor STALE
    // (silenciosamente incorrecto en interp/JIT/AOT).  Repro: binding de un
    // @overlay (que copia el puntero) escribiendo un campo, leido despues
    // por el puntero original.
    //
    // Con (raiz, offset): la copia colapsa a la MISMA clave -> el store la
    // invalida/sobreescribe correctamente.  Dos claves distintas siguen sin
    // aliasar solo cuando es DEMOSTRABLE (raices distintas, u offsets const
    // del mismo root cuyos rangos de bytes no se solapan).  Si no se puede
    // probar, se es CONSERVADOR (no se reenvia).
    //
    // Un STORE a un puntero cuya raiz es DESCONOCIDA (resultado de un LOAD,
    // parametro, PHI, calculo con offset variable) puede aliasar cualquier
    // direccion local -> barrera que invalida todo el forwarding.  Sin esto,
    // `(*p).x = v` (p cargado que en runtime == &s) no invalidaba `s.x`.
    enum class RootKind : uint8_t { NONE = 0, STACK = 1, HEAP = 2 };
    struct AddrInfo {
        IrValueId root = IR_NO_VALUE; ///< raiz (ALLOCA o allocador)
        int64_t off = 0;              ///< offset constante desde la raiz
    };
    std::unordered_map<IrValueId, AddrInfo>
        addr_of; // solo direcciones conocidas
    std::unordered_map<IrValueId, RootKind> root_kind;

    if (g_dse_unified) {
        //   resolucion desde el RESOLVEDOR COMPARTIDO.  El DSE NO
        // construye la tabla points-to: la RECIBE del AnalysisManager (Regla
        // 1); si no se la dan (llamada suelta), la construye localmente como
        // fallback.  Solo las raices que el DSE razona con precision (Stack=
        // ALLOCA, Heap=alloc-site) con OFFSET EXACTO entran en addr_of; el
        // resto (Global/ArgDerived/Unknown/inexacto) no tiene entrada ->
        // barrera.
        analysis::PointsTo local_pt;
        const analysis::PointsTo &upt =
            pt ? *pt
               : (local_pt = analysis::compute_points_to(
                      fn, analysis::build_ir_facts(fn)));
        using MK = analysis::effects::AbstractLoc::Kind;
        for (IrValueId v = 0; v < static_cast<IrValueId>(upt.loc.size()); ++v) {
            const analysis::PointsToEntry &e = upt.loc[v];
            if (!e.off_exact) continue; // whole-root/inexact -> barrera
            RootKind k = RootKind::NONE;
            if (e.kind == MK::Stack)
                k = RootKind::STACK;
            else if (e.kind == MK::Heap)
                k = RootKind::HEAP;
            else
                continue; // Global/ArgDerived/Unknown -> barrera (sin entrada)
            addr_of[v] = AddrInfo{e.root, e.off};
            root_kind[e.root] = k; // la raiz misma se resuelve a off 0 exacto
        }
    } else {
        for (auto &bb : fn.blocks)
            for (auto &ins : bb.instrs) {
                if (ins.dst == IR_NO_VALUE) continue;
                RootKind k = RootKind::NONE;
                if (ins.op == IrOp::ALLOCA)
                    k = RootKind::STACK;
                else if (ins.op == IrOp::RAW_ALLOC ||
                         ins.op == IrOp::GC_ALLOC || ins.op == IrOp::NEWOBJ ||
                         ins.op == IrOp::NEWOBJS)
                    k = RootKind::HEAP;
                if (k == RootKind::NONE) continue;
                addr_of[ins.dst] = AddrInfo{ins.dst, 0};
                root_kind[ins.dst] = k;
            }
        // Fix-point: propagar (raiz, offset) por las cadenas derivadas.
        // Cota dura de 16 iteraciones para garantizar convergencia.
        bool grew = true;
        int guard = 0;
        while (grew && guard++ < 16) {
            grew = false;
            for (auto &bb : fn.blocks)
                for (auto &ins : bb.instrs) {
                    if (ins.dst == IR_NO_VALUE) continue;
                    if (addr_of.count(ins.dst)) continue; // ya resuelta
                    if (ins.operands.empty()) continue;
                    auto base = addr_of.find(ins.operands[0]);
                    if (base == addr_of.end()) continue;
                    if (ins.op == IrOp::BITCAST || ins.op == IrOp::MOV) {
                        // COPIA: misma direccion exacta que el operando.
                        addr_of[ins.dst] = base->second;
                        grew = true;
                    } else if (ins.op == IrOp::ADD &&
                               ins.operands.size() == 2) {
                        uint64_t off;
                        if (!get_const(fn, ins.operands[1], off)) continue;
                        AddrInfo a = base->second;
                        a.off += static_cast<int64_t>(off);
                        addr_of[ins.dst] = a;
                        grew = true;
                    }
                }
        }
    }

    /* Tamano en bytes accedido por un LOAD/STORE segun su IrType.  Se usa
     * para decidir SOLAPAMIENTO entre dos accesos al mismo root con offsets
     * constantes distintos. */
    // Bytes accedidos: delega en la UNICA verdad compartida.
    auto access_bytes = [](IrType t) -> int64_t {
        return static_cast<int64_t>(type_access_bytes(t));
    };

    /* Clave canonica de direccion: (raiz, offset const).  Dos punteros con
     * la misma clave son la MISMA direccion aunque sean IrValueId distintos
     * (copias via MOV/BITCAST). */
    using AddrKey = std::pair<IrValueId, int64_t>;

    /* STORE pendiente de veredicto: aun no se ha demostrado que sea dead ni
     * se ha leido.  @c covered es una mascara de 1 bit por byte escrito por
     * stores POSTERIORES: cuando cubre el rango entero, este store es dead
     * (nadie puede observar sus bytes).  Esto recupera el DSE del zero-init
     * ancho que luego se sobreescribe por campos estrechos (`{i32 x; i32 y}`
     * inicializado a 0 y luego x=..., y=...), pero SOLO cuando la cobertura
     * es COMPLETA -- a diferencia del codigo anterior, que mataba el store
     * ancho en cuanto veia UNO estrecho a la misma direccion (incorrecto:
     * los bytes no cubiertos seguian siendo observables). */
    struct PendingStore {
        size_t idx;       ///< indice de la instruccion STORE en el bloque
        IrValueId root;   ///< raiz de la direccion
        int64_t off;      ///< offset desde la raiz
        int64_t size;     ///< bytes escritos
        uint64_t covered; ///< bitmask de bytes ya sobreescritos (bit i = off+i)
    };

    for (auto &bb : fn.blocks) {
        // STOREs vivos del bloque, pendientes de veredicto de DSE.
        std::vector<PendingStore> pending;
        //  D.7.opt: STORE-TO-LOAD FORWARDING.
        // Mapa paralelo: addr_key -> (stored_value_vid, store_type) del
        // ultimo STORE.  Cuando un LOAD lee de esa misma direccion CON EL
        // MISMO tipo, podemos reemplazar el LOAD por MOV del valor
        // almacenado (ahorra la lectura de memoria + cualquier conversion).
        std::map<AddrKey, std::pair<IrValueId, IrType>> last_store_val;
        // Load-to-load CSE (g_load_cse): claves cuyo valor lo registro un LOAD
        // (no un STORE).  Un valor cargado solo vale mientras NADIE escriba
        // memoria -- un STORE puede aliasar via roots imprecisos (reborrow) que
        // la invalidacion por-clave del DSE no cubre.  Por eso se invalidan en
        // CUALQUIER store (conservador y sound; el store->load exacto no se
        // toca).
        std::set<AddrKey> load_recorded;
        // Set de indices marcados como dead
        std::vector<bool> dead(bb.instrs.size(), false);

        /* Invalida el forwarding de toda direccion del MISMO root cuyo rango
         * de bytes se solape con [off, off+size) sin ser la clave exacta (esa
         * la sobreescribe el propio store).  Roots distintos (alloca vs
         * alloca, alloca vs heap, malloc vs malloc) NUNCA aliasan -> intactos.
         * Se asume el ancho maximo (8 B) de la entrada trackeada: conservador.
         */
        auto kill_val_overlapping = [&](const AddrKey &k, int64_t size) {
            CronoTramo crono__("  dse:kill_val_overlapping");
            for (auto it = last_store_val.begin();
                 it != last_store_val.end();) {
                bool ov = it->first.first == k.first && it->first != k &&
                          it->first.second < k.second + size &&
                          k.second < it->first.second + 8;
                if (ov)
                    it = last_store_val.erase(it);
                else
                    ++it;
            }
        };

        /* Un STORE posterior [off, off+size) marca como cubiertos esos bytes
         * en los stores pendientes del mismo root; el que quede TOTALMENTE
         * cubierto es dead.  Si el rango excede 64 B no se modela la mascara
         * (se descarta el pendiente: conservador, no se mata). */
        auto note_write = [&](IrValueId root, int64_t off, int64_t size) {
            CronoTramo crono__("  dse:note_write");
            for (auto it = pending.begin(); it != pending.end();) {
                if (it->root != root || it->off >= off + size ||
                    off >= it->off + it->size) {
                    ++it;
                    continue;
                }
                if (it->size > 64) {
                    /* no modelable -> olvidar (no matar) */
                    it = pending.erase(it);
                    continue;
                }
                const int64_t lo = std::max(it->off, off);
                const int64_t hi = std::min(it->off + it->size, off + size);
                for (int64_t b = lo; b < hi; ++b)
                    it->covered |= (1ull << (b - it->off));
                const uint64_t full =
                    (it->size >= 64) ? ~0ull : ((1ull << it->size) - 1ull);
                if ((it->covered & full) == full) {
                    dead[it->idx] = true; /* sobreescrito por completo */
                    changed = true;
                    it = pending.erase(it);
                } else
                    ++it;
            }
        };

        /* Un LOAD de [off, off+size) LEE los stores pendientes que solapa ->
         * dejan de ser candidatos a dead. */
        auto note_read = [&](IrValueId root, int64_t off, int64_t size) {
            CronoTramo crono__("  dse:note_read");
            for (auto it = pending.begin(); it != pending.end();) {
                if (it->root == root && it->off < off + size &&
                    off < it->off + it->size)
                    it = pending.erase(it);
                else
                    ++it;
            }
        };

        /**
         * @brief Trata un bloque `asm` por lo que TOCA, en vez de como barrera.
         *
         * @return true si se pudo; false = no se sabe lo suficiente y el caller
         *         debe seguir tratandolo como barrera total.
         */
        /* Los hechos que el trato preciso del asm necesita se calculan UNA vez
         * por pase, no una por bloque.  Estaban DENTRO del helper de abajo, que
         * se llama por CADA instruccion de asm, y cada llamada rehacia las
         * ligaduras (dos veces), la estructura de la funcion y un punto fijo de
         * rangos COMPLETO: n_asm x O(funcion).  En un programa lleno de asm eso
         * son segundos -- y es el mismo error que el ASA existe para quitar, un
         * consumidor construyendo su base de hechos en el sitio.
         *
         * Describen la funcion al ENTRAR al pase, y es lo correcto: marcar un
         * store como muerto no cambia ni de que valor habla cada operando del
         * asm ni los rangos de nadie.
         *
         * Perezosos: un programa sin un solo bloque de asm no paga nada. */
        bool hechos_asm_listos = false;
        analysis::AsmBindingFacts lig_asm_fn;
        analysis::IrFacts hechos_fn;
        analysis::RangeFacts rangos_fn;
        /* Las clases de operando en la forma que pide el analizador de bloques.
         * Salen enteras de las ligaduras, que no cambian durante el pase, y
         * armarlas cuesta una copia de DOS cadenas por ligadura: hacerlo por
         * cada instruccion de asm era pagar esa copia n_asm veces. */
        std::vector<std::pair<std::string, std::string>> clases_asm_fn;
        /* Punteros a los que se usan de verdad: los de fuera si llegaron, los
         * de aqui si hubo que calcularlos.  Sin copiar: son grandes. */
        const analysis::AsmBindingFacts *lig_usar = nullptr;
        const analysis::IrFacts *hechos_usar = nullptr;
        const analysis::RangeFacts *rangos_usar = nullptr;
        auto asegurar_hechos_asm = [&]() {
            if (hechos_asm_listos) return;
            hechos_asm_listos = true;
            if (hechos_asm != nullptr && hechos_asm->ligaduras != nullptr &&
                hechos_asm->estructura != nullptr &&
                hechos_asm->rangos != nullptr) {
                /* Ya los tiene quien llama, cacheados: no se toca nada. */
                lig_usar = hechos_asm->ligaduras;
                hechos_usar = hechos_asm->estructura;
                rangos_usar = hechos_asm->rangos;
            } else {
                CronoTramo crono__("  dse:hechos(calculados aqui)");
                lig_asm_fn = analysis::compute_asm_bindings(fn);
                hechos_fn = analysis::build_ir_facts(fn);
                rangos_fn = analysis::compute_ranges(fn, hechos_fn);
                lig_usar = &lig_asm_fn;
                hechos_usar = &hechos_fn;
                rangos_usar = &rangos_fn;
            }
            clases_asm_fn.reserve(lig_usar->ligaduras.size());
            for (const analysis::LigaduraAsm &l : lig_usar->ligaduras)
                clases_asm_fn.emplace_back(l.marcador, l.clase);
        };
        /* Y el analisis de CADA bloque, memorizado por su nombre.  El texto del
         * bloque y las clases son los mismos toda la pasada, asi que volver a
         * analizarlo por cada instruccion que lo menciona es rehacer un trabajo
         * cuyo resultado ya se tiene. */
        std::unordered_map<std::string, vx::AsmBlockEffects> efectos_de_bloque;

        auto dse_asm_preciso = [&](const IrInstr &ins) -> bool {
            CronoTramo crono__("  dse:asm");
            asegurar_hechos_asm();
            /* Con las clases de operando: esto pregunta QUE memoria toca el
             * bloque, que es exactamente lo que no se puede responder sin
             * saber cuantos bytes mide cada `$N`. */
            auto it_ef = efectos_de_bloque.find(ins.func_name);
            if (it_ef == efectos_de_bloque.end())
                it_ef = efectos_de_bloque
                            .emplace(ins.func_name,
                                     vx::asm_analyze_block(
                                         ins.func_name, vx::asm_arch_actual(),
                                         clases_asm_fn))
                            .first;
            const vx::AsmBlockEffects &e = it_ef->second;
            if (!e.known() || e.is_call || e.has_atomic) return false;
            if (e.accesos_incompletos) return false;

            /* PRIMERO lo que no depende de los accesos: el bloque lee el VALOR
             * de cada variable ligada.  Sus huecos son los operandos. */
            for (IrValueId op : ins.operands) {
                if (op == IR_NO_VALUE) return false;
                auto ai = addr_of.find(op);
                if (ai == addr_of.end()) return false; // hueco no localizable
                note_read(ai->second.root, ai->second.off, 8);
            }

            /* Y el bloque puede CAMBIAR el valor de una variable ligada sin
             * tocar memoria (`inc rax` sobre un `register("rax") u64 v`).  Lo
             * que hubiera guardado en su hueco deja de valer, asi que no se
             * puede seguir reusando: sin esto, leer la variable despues del
             * bloque devolvia el valor de ANTES (41 en vez de 42). */
            /* De que valor habla cada operando lo responde UN solo sitio (ver
             * @ref analysis::compute_asm_bindings); este recorrido estaba
             * copiado aqui y en el modelo de efectos. */
            const analysis::AsmBindingFacts &lig = *lig_usar;
            /* Y los rangos, que son los que cierran la extension de un acceso
             * cuando la determina un operando en vez de una constante. */
            const analysis::IrFacts &hechos_dse = *hechos_usar;
            const analysis::RangeFacts &rangos_dse = *rangos_usar;
            for (const std::string &w : e.escritos) {
                /* Si dos variables comparten registro no se sabe a cual de las
                 * dos escribio -- asi que dejan de valer LAS DOS.  Invalidar de
                 * mas es correcto (solo impide reusar un valor); rendirse y
                 * tratar el bloque como barrera total tira ademas todo lo que
                 * si se sabia de lo demas que toca. */
                for (const analysis::LigaduraAsm &l : lig.candidatas(w)) {
                    auto ai = addr_of.find(l.hueco);
                    if (ai == addr_of.end()) return false;
                    last_store_val.erase({ai->second.root, ai->second.off});
                }
            }

            /* Y ahora la memoria que toca A TRAVES de ellos: del registro base
             * al hueco, del hueco a lo que contiene, y de ahi a la direccion
             * que el DSE ya sabe seguir. */
            for (const vx::AsmBlockEffects::Acceso &a : e.accesos) {
                /* Con varias candidatas el acceso va por UNA de ellas, y como
                 * no se sabe cual, se tratan todas: se da por leido lo que
                 * apunta cada una y, si escribe, se invalida el reenvio de
                 * todas.  Es la misma logica de siempre aplicada a un conjunto
                 * en vez de a un valor. */
                const auto cands = lig.candidatas(a.base);
                if (cands.empty()) return false;
                /* Cuanto toca de verdad.  Aqui habia un 8 fijo, y no era una
                 * imprecision: un `movdqa` escribe DIECISEIS, asi que los ocho
                 * de arriba no se invalidaban y la siguiente lectura reusaba un
                 * valor que el bloque ya habia pisado.  Cuando no se puede
                 * acotar se usa un ancho grande a proposito -- pasarse invalida
                 * de mas, que solo cuesta una optimizacion. */
                const analysis::ExtensionResuelta ext =
                    a.valida && !a.desde_memoria.hay
                        ? analysis::resolver_extension(lig, rangos_dse,
                                                       a.extension)
                        : analysis::ExtensionResuelta{};
                if (!ext.acotada) return false;
                const int32_t ancho = (int32_t)ext.bytes();
                for (const analysis::LigaduraAsm &l : cands) {
                    if (l.valor == IR_NO_VALUE) return false;
                    auto ai = addr_of.find(l.valor);
                    if (ai == addr_of.end()) return false; // no seguible
                    const int64_t off = ai->second.off + ext.desde;
                    // Leer lo apuntado, y si escribe, invalidar el reenvio de
                    // esa direccion, con la extension que de verdad tiene.
                    note_read(ai->second.root, off, ancho);
                    if (a.escribe) {
                        const AddrKey k{ai->second.root, off};
                        kill_val_overlapping(k, ancho);
                        /* Y la clave EXACTA tambien.  @c kill_val_overlapping
                         * se la salta a proposito porque quien lo llama es un
                         * STORE, que la sobrescribe acto seguido con el valor
                         * nuevo; aqui no hay tal cosa -- el asm escribio por su
                         * cuenta y no sabemos que dejo --, asi que dejarla viva
                         * hace que la siguiente lectura reuse el valor
                         * ANTERIOR. Costo: el programa devolvia 0 en vez de 42.
                         */
                        last_store_val.erase(k);
                    }
                }
            }
            return true;
        };

        for (size_t i = 0; i < bb.instrs.size(); ++i) {
            auto &ins = bb.instrs[i];
            switch (ins.op) {
            case IrOp::STORE: {
                if (ins.operands.size() < 2) break;
                IrValueId ptr = ins.operands[1];
                IrValueId val = ins.operands[0];
                if (ptr == IR_NO_VALUE) break;
                // Store a traves de un puntero que NO es una direccion local
                // precisa (alloca + offset const).  Dos casos:
                //  - puntero de HEAP (malloc/gc/newobj derivado): NO aliasa
                //    ningun slot alloca de stack -> el contenido de los slots
                //    trackeados no cambia; conservar su forwarding (test 82:
                //    `p[i]=v` no toca el slot host-ptr de p).  No registramos
                //    el store de heap (aliasing heap-heap desconocido).
                //  - puntero UNKNOWN (load/param/calculo): podria ser la
                //    direccion de un alloca escapado (`&s` cargado de vuelta)
                //    -> barrera de alias, invalida TODO el forwarding (i5).
                auto ai = addr_of.find(ptr);
                if (ai == addr_of.end()) {
                    // Raiz DESCONOCIDA -> puede aliasar cualquier cosa.
                    pending.clear();
                    last_store_val.clear();
                    break;
                }
                // Load-to-load CSE: un store (heap O stack) puede aliasar una
                // entrada registrada por LOAD via roots imprecisos (reborrow)
                // -> invalidar TODAS las load-recorded (conservador, sound).
                if (g_load_cse && !load_recorded.empty()) {
                    for (const AddrKey &k : load_recorded)
                        last_store_val.erase(k);
                    load_recorded.clear();
                }
                if (root_kind[ai->second.root] == RootKind::HEAP) {
                    // Puntero de HEAP: no aliasa ningun slot de STACK, y las
                    // direcciones de heap no se trackean -> ni invalida ni
                    // registra (test 82: `p[i]=v` no toca el slot de p).
                    break;
                }
                const AddrKey key{ai->second.root, ai->second.off};
                const int64_t sz = access_bytes(ins.type);
                // Acumula cobertura sobre los stores pendientes que solapa
                // (mata solo los que quedan cubiertos POR COMPLETO) e
                // invalida el forwarding de las direcciones solapadas.
                note_write(ai->second.root, ai->second.off, sz);
                kill_val_overlapping(key, sz);
                pending.push_back(
                    PendingStore{i, ai->second.root, ai->second.off, sz, 0ull});
                if (val != IR_NO_VALUE) {
                    last_store_val[key] = {val, ins.type};
                } else {
                    last_store_val.erase(key);
                }
                break;
            }
            case IrOp::LOAD: {
                if (ins.operands.empty()) break;
                IrValueId ptr = ins.operands[0];
                if (ptr == IR_NO_VALUE) break;
                auto ai = addr_of.find(ptr);
                if (ai == addr_of.end()) {
                    // LOAD por un puntero de raiz DESCONOCIDA: puede leer
                    // cualquier slot trackeado -> ningun STORE previo puede
                    // declararse dead.  (El forwarding no se invalida: leer
                    // no muta memoria.)
                    pending.clear();
                    break;
                }
                const AddrKey lkey{ai->second.root, ai->second.off};
                // Un load LEE los stores pendientes que solapa -> dejan de
                // ser candidatos a dead.
                note_read(ai->second.root, ai->second.off,
                          access_bytes(ins.type));
                auto it = last_store_val.find(lkey);
                if (it != last_store_val.end() &&
                    it->second.second == ins.type) {
                    // SLF: reemplazar LOAD por MOV del valor almacenado.
                    // copy_prop posterior substituye los usos del LOAD dst
                    // por el stored value y DCE elimina el MOV.
                    //
                    // Bug fix is_host_ptr propagation: el LOAD dst pudo
                    // estar marcado is_host_ptr=true por el frontend (e.g.
                    // lend() lowering marca el load del slot[0] de un
                    // unique<T> como host_ptr).  Al substituir uses con
                    // el stored value, ESE value debe tambien tener
                    // is_host_ptr=true para que LOAD/STORE posteriores
                    // emitan movh (host mem) en vez de mov (VM mem).
                    // Semanticamente: load(store(v, p)) == v, asi que
                    // el LOAD result Y el stored value son el MISMO
                    // value runtime y deben compartir flags.
                    if (ins.dst < fn.values.size() &&
                        it->second.first < fn.values.size()) {
                        const auto &dst_v = fn.values[ins.dst];
                        auto &val_v = fn.values[it->second.first];
                        if (dst_v.is_host_ptr && !val_v.is_host_ptr) {
                            val_v.is_host_ptr = true;
                        }
                        if (dst_v.is_gc_object && !val_v.is_gc_object) {
                            val_v.is_gc_object = true;
                        }
                        if (dst_v.pointee_is_host_ptr &&
                            !val_v.pointee_is_host_ptr) {
                            val_v.pointee_is_host_ptr = true;
                        }
                    }
                    ins.op = IrOp::MOV;
                    ins.operands = {it->second.first};
                    changed = true;
                }
                // note_read ya retiro los stores leidos de 'pending'
                // (no son dead: acabamos de demostrar que ESTE LOAD los lee).
                //
                // LOAD-TO-LOAD CSE: si este LOAD no forwardeo (sigue siendo
                // LOAD), su valor queda DISPONIBLE en su direccion -> un LOAD
                // posterior de la misma direccion (must-alias) lo reusara.  La
                // invalidacion (kill_val_overlapping en stores, clear en
                // barreras) ya la hace el DSE -> sound.  Gated.
                if (g_load_cse && ins.op == IrOp::LOAD &&
                    ins.dst != IR_NO_VALUE) {
                    last_store_val[lkey] = {ins.dst, ins.type};
                    load_recorded.insert(lkey);
                }
                break;
            }
            case IrOp::ARRAY_LOAD:
            case IrOp::GETFIELD:
            case IrOp::ARRAY_LEN:
                // Cualquier LOAD desde un ptr que tenemos seguido invalida
                // la posibilidad de eliminar el STORE previo (no sabemos
                // alias).  Conservador: limpiar todo el mapa.
                pending.clear();
                last_store_val.clear();
                break;
            // CALL/TAILCALL a callee TOTALMENTE PURO: NO es barrera (el modelo
            // de efectos prueba que no toca memoria ni observa nada). Cualquier
            // otra CALL cae al grupo de barrera de abajo.
            case IrOp::CALL:
            case IrOp::TAILCALL:
                if (is_pure_call(ins)) break; // no barrera
                pending.clear();
                last_store_val.clear();
                break;
            // Side-effects/calls: limpiar (memoria puede cambiar dentro).
            case IrOp::CALLN:
            case IrOp::CALLVIRT:
            case IrOp::CALLIND:
            case IrOp::CALLM:
            case IrOp::CALLITF:
            case IrOp::CALLCLOSURE:
            /* Un `asm` puede decir QUE memoria toca, y entonces no tiene por
             * que ser una barrera para todo lo demas.  Si se sabe -- todos sus
             * accesos atribuidos a un operando ligado --, se trata como lo que
             * es: unas lecturas y unas escrituras concretas.
             *
             * CUIDADO, y es lo que hace este caso distinto de un LOAD/STORE
             * normal: el bloque LEE EL VALOR de todas sus variables ligadas,
             * toque memoria o no.  `add $0, 1` no accede a memoria y aun asi
             * lee lo que se guardo en el hueco de esa variable, asi que esa
             * escritura NO esta muerta.  Por eso se marcan como leidos TODOS
             * los operandos, no solo los que sirven de direccion.
             *
             * Ante cualquier cosa que no encaje se cae a la barrera de siempre.
             * `VESTA_ASM_DSE=0` la fuerza.
             *
             * Los TRES niveles de asm entran aqui: en este lenguaje NO HAY
             * CAJAS NEGRAS.  Un bloque de asm no es codigo incrustado, es
             * codigo del lenguaje con vida propia -- se analiza, se optimiza y
             * se adapta al sitio donde acaba.
             *
             * Lo unico que `volatile` cambia es que sus BYTES no se reescriben;
             * inspeccionarlo se inspecciona igual, que es lo que permite no
             * penalizar a todo lo que tenga alrededor.  Asi que lo que decide
             * si aqui se puede afinar no es el nivel del bloque, sino si el
             * analisis alcanza a explicar TODOS sus accesos. */
            case IrOp::RAW_ASM:
            case IrOp::INLINE_ASM:
            case IrOp::ASM_MICRO:
                if (asm_dse_activo() && dse_asm_preciso(ins))
                    break; // tratado con precision: no es barrera
                pending.clear();
                last_store_val.clear();
                break;
            case IrOp::MEMCPY:
            case IrOp::MEMSET:
            case IrOp::VEC_UNOP:
            case IrOp::VEC_BINOP:
            case IrOp::VEC_FMA:
            case IrOp::VEC_ACC_ZERO:
            case IrOp::VEC_ACC_ADD:
            case IrOp::VEC_ACC_FMA:
            case IrOp::VEC_ACC_STORE:
            case IrOp::VEC_ACC_COMBINE:
            case IrOp::VEC_FMA_S:
            case IrOp::VEC_BINOP_S:
            case IrOp::VEC_BCAST:
            case IrOp::SETFIELD:
            case IrOp::ARRAY_STORE:
            case IrOp::STRFINALIZE:
            case IrOp::GCWB_IR:
            case IrOp::NEWOBJ:
            case IrOp::NEWOBJS:
            case IrOp::GC_ALLOC:
            case IrOp::RAW_ALLOC:
            /* `RAW_FREE` es barrera TOTAL a proposito, y esta MEDIDO
             * (2026-08-07).  El modelo de efectos ya dice con precision que
             * region invalida un `free`, asi que se probo a usarlo aqui:
             * conservar lo que se sabe de OTRAS raices en vez de borrarlo todo.
             *
             * Sobre los 453 programas del corpus: 13079 sitios de `free`, 8044
             * con el puntero resuelto, y 4340 en los que SI habia estado de
             * otras raices que la barrera estaba tirando.  El codigo generado
             * salio IDENTICO en los 453.  El motivo es que un `free` cae al
             * final de su bloque -- salida de ambito --, asi que lo que se
             * conserva ya no lo consulta nadie despues.
             *
             * Asi que se queda como estaba por BENEFICIO CERO, y por nada mas.
             * Y cuando toque revisarlo, el desalojador no se da por opaco: un
             * `@AllocatorOverride` es codigo Vesta que cumple un contrato, o
             * sea que sus efectos se ANALIZAN como los de cualquier otra
             * funcion del programa -- suponer que "puede tocar cualquier cosa"
             * seria el mismo mundo cerrado que se quito de las llamadas
             * nativas.
             *
             * Donde SI paga esta precision es en el consumidor de SEGURIDAD: la
             * seccion de conflictos de `--analyze` la usa para senalar un
             * acceso a memoria ya liberada.  Si algun dia el `free` deja de
             * estar al final del bloque (por hundimiento) o el DSE cruza
             * bloques, hay que volver a medir. */
            case IrOp::RAW_FREE:
            case IrOp::THROW:
            case IrOp::TRYENTER:
            case IrOp::TRYLEAVE:
            // Sprint string-perf-2 bug fix (2026-06-02): STRMAKE/STRCAT/
            // STRCONV LEEN memoria en runtime (STRMAKE lee vm_mem para
            // construir el StringObject; STRCAT puede materializar bytes;
            // STRCONV lee el src y escribe el converted).  Sin invalidar
            // last_store_val, DSE elimina STOREs previos pensando que
            // nadie los lee, pero STRMAKE LOS LEE en runtime.
            // Bug reproducido en patron `buf[i]=X; STRMAKE(buf); buf[i]=Y;
            // STRMAKE(buf)`: el primer set de stores se eliminaba.
            case IrOp::STRMAKE:
            case IrOp::STRCAT:
            case IrOp::STRCONV:
            case IrOp::STRFLAT:
            case IrOp::STRINTERN:
            case IrOp::STRRESERVE:
            // Sprint edge-bugs (2026-06-02): MVTAKE_IR muta memoria
            // (copia src->dst + zerifica src), por lo que invalida
            // last_store_val para ambos punteros.  Conservadoramente
            // clearamos todo el mapa.  Sin esto, ptr_of() despues de
            // move() retornaba el host_ptr ORIGINAL (SLF leia el store
            // anterior al mvtake) en vez del 0 que el runtime escribio.
            case IrOp::MVTAKE_IR:
            // GC_PROMOTE/GC_DEMOTE copian memoria cross-heap.
            case IrOp::GC_PROMOTE:
            case IrOp::GC_DEMOTE:
            // ATOMIC_ST / ATOMIC_CAS / ATOMIC_ADD escriben
            // memoria; ATOMIC_LD lee (que es OK para SLF si no hay
            // store intermedio, pero conservativo clearamos).
            case IrOp::ATOMIC_LD:
            case IrOp::ATOMIC_ST:
            case IrOp::ATOMIC_CAS:
            case IrOp::ATOMIC_ADD:
            // SMARTPTR_FREE invoca deleter que puede tocar memoria.
            case IrOp::SMARTPTR_FREE:
            // FFI runtime puede mutar cualquier cosa.
            case IrOp::DLOPEN:
            case IrOp::DLSYM:
            case IrOp::MOD_LOAD:
            // raw_asm-elim Fase 2 (__module_init -> IR): los ops de meta-OOP
            // LEEN su struct de parametros desde vm_mem (params_vaddr) en
            // runtime (defclass/deffield/defmethod leen el buffer; findclass/
            // findmethod tambien).  Sin invalidar last_store_idx, DSE elimina
            // los STORE que arman ese buffer creyendo que nadie los lee,
            // PERO el op de meta-OOP los LEE en runtime.  Critico para el
            // patron de buffer REUSADO entre defs: STORE(buf+0,A); deffield;
            // STORE(buf+0,B) -- sin esto el primer STORE se marca dead.
            // Mismo razonamiento que STRMAKE/STRCAT (que leen vm_mem).
            case IrOp::DEFCLASS:
            case IrOp::DEFFIELD:
            case IrOp::DEFMETHOD:
            case IrOp::FINDCLASS:
            case IrOp::FINDMETHOD:
            case IrOp::FINDFIELD:
            case IrOp::ADDADVICE:
            case IrOp::SETMETHDBG:
            // GETSTATIC/SETSTATIC consultan/mutan cls->static_data (estado
            // global del runtime); conservativo: invalidar el mapa.
            case IrOp::GETSTATIC:
            case IrOp::SETSTATIC:
                pending.clear();
                last_store_val.clear();
                break;
            default: break;
            }
        }

        // Compactar: eliminar instrucciones marcadas dead.
        if (changed) {
            std::vector<IrInstr> kept;
            kept.reserve(bb.instrs.size());
            for (size_t i = 0; i < bb.instrs.size(); ++i) {
                if (!dead[i]) kept.push_back(std::move(bb.instrs[i]));
            }
            bb.instrs = std::move(kept);
        }
    }

    // DCE para limpiar valores que solo alimentaban los stores eliminados,
    // y copy_prop para resolver los MOVs generados por SLF.
    if (changed) {
        ir_pass_copy_prop(fn);
        util::CronoTramo crono__("  dce:limpieza-en-pase");
        ir_pass_dce(fn);
    }
    return changed;
}

/**
 * @brief Mapa nombre-completo -> bloque, para resolver las referencias por
 *        NOMBRE que hace un @c LABEL_ADDR a un bloque de la propia funcion.
 *
 * La clave es la que compone @c emit_label_addr para un handler local:
 * `<funcion>_<bloque>`.  Los @c LABEL_ADDR que apuntan a funciones, lambdas o
 * destructores externos llevan el nombre de la funcion a secas, asi que no
 * entran en este mapa y no se confunden con un bloque.
 */
static std::unordered_map<std::string, IrBlockId>
bloques_por_nombre(const IrFunction &fn) {
    std::unordered_map<std::string, IrBlockId> name2id;
    for (size_t b = 0; b < fn.blocks.size(); ++b)
        if (!fn.blocks[b].name.empty())
            name2id.emplace(fn.name + "_" + fn.blocks[b].name,
                            static_cast<IrBlockId>(b));
    return name2id;
}

/**
 * @brief Sucesores REALES de un bloque, aristas implicitas incluidas.
 *
 * Un handler de `try/catch` no cuelga de ningun salto: se alcanza cuando salta
 * la excepcion, y lo unico que lo referencia es el @c LABEL_ADDR que el
 * @c tryenter guarda.  Esa arista es tan real como un @c br, y quien la ignora
 * da el handler por muerto.
 *
 * Estaba escrita solo en el reordenador de bloques.  El pase que borra lo
 * inalcanzable no la conocia, asi que en cuanto el inlinado le daba una razon
 * para volver a correr, se llevaba por delante el handler y dejaba el
 * @c tryenter apuntando a una etiqueta que ya no existia -- el enlazador
 * terminaba diciendo "simbolo no resuelto" y el programa no llegaba a
 * construirse.  Ahora la regla vive en un solo sitio y la usan los dos.
 *
 * @param fn      Funcion.
 * @param name2id Mapa de @c bloques_por_nombre.
 * @param b       Bloque del que se quieren los sucesores.
 * @param out     Se limpia y se rellena con los sucesores.
 */
static void
sucesores_de(const IrFunction &fn,
             const std::unordered_map<std::string, IrBlockId> &name2id,
             size_t b, std::vector<IrBlockId> &out) {
    out.clear();
    if (b >= fn.blocks.size() || fn.blocks[b].instrs.empty()) return;
    /* Se miran TODAS las instrucciones, no solo la ultima.  Un bloque bien
     * formado tiene su salto al final, pero los que salen de un `asm` llevan un
     * `br` en medio seguido del propio bloque de ensamblador; quedarse con la
     * ultima instruccion da ese salto por inexistente y su destino, por muerto.
     * Contar de mas solo conserva un bloque que quiza sobra; contar de menos
     * borra uno que hace falta. */
    for (const IrInstr &ins : fn.blocks[b].instrs) {
        switch (ins.op) {
        case IrOp::LABEL_ADDR: {
            auto it = name2id.find(ins.func_name);
            if (it != name2id.end() && it->second != b)
                out.push_back(it->second);
            break;
        }
        case IrOp::BR:
            if (ins.target_block != IR_NO_BLOCK)
                out.push_back(ins.target_block);
            break;
        case IrOp::BR_COND:
            if (ins.target_block != IR_NO_BLOCK)
                out.push_back(ins.target_block);
            if (ins.false_block != IR_NO_BLOCK) out.push_back(ins.false_block);
            break;
        case IrOp::SWITCH_DENSE:
            /* El default va en target_block y un caso por entrada en
             * jump_targets[]: omitirlos deja los bloques del match colgando. */
            if (ins.target_block != IR_NO_BLOCK)
                out.push_back(ins.target_block);
            for (IrBlockId s : ins.jump_targets)
                if (s != IR_NO_BLOCK) out.push_back(s);
            break;
        default: break;
        }
    }
}

bool ir_pass_unreachable(IrFunction &fn) {
    if (fn.blocks.empty()) return false;

    const size_t nblocks = fn.blocks.size();
    std::vector<bool> reachable(nblocks, false);

    // BFS desde el bloque de entrada (bloque 0)
    const std::unordered_map<std::string, IrBlockId> name2id =
        bloques_por_nombre(fn);
    std::vector<IrBlockId> succs;
    std::queue<IrBlockId> worklist;
    worklist.push(0);
    reachable[0] = true;

    while (!worklist.empty()) {
        IrBlockId bid = worklist.front();
        worklist.pop();

        if (bid >= nblocks) continue;
        const IrBlock &bb = fn.blocks[bid];

        // Los sucesores, con las mismas reglas que usa el reordenador: saltos,
        // casos de un match, y el handler que solo nombra un LABEL_ADDR.
        sucesores_de(fn, name2id, bid, succs);
        for (IrBlockId s : succs) {
            if (s < nblocks && !reachable[s]) {
                reachable[s] = true;
                worklist.push(s);
            }
        }
        // Usar sucesores precalculados si existen
        for (IrBlockId s : bb.succs) {
            if (s < nblocks && !reachable[s]) {
                reachable[s] = true;
                worklist.push(s);
            }
        }
    }

    // Verificar si hay bloques inalcanzables
    bool any_unreachable = false;
    for (size_t b = 0; b < nblocks; ++b) {
        if (!reachable[b]) {
            any_unreachable = true;
            break;
        }
    }
    if (!any_unreachable) return false;

    // Construir mapa de reindexacion: viejo_id -> nuevo_id
    std::vector<IrBlockId> remap(nblocks, IR_NO_BLOCK);
    IrBlockId new_id = 0;
    for (size_t b = 0; b < nblocks; ++b) {
        if (reachable[b]) remap[b] = new_id++;
    }

    // Reescribir los bloques: eliminar los inalcanzables y actualizar
    // referencias
    std::vector<IrBlock> new_blocks;
    new_blocks.reserve(new_id);
    for (size_t b = 0; b < nblocks; ++b) {
        if (!reachable[b]) continue;
        IrBlock bb = fn.blocks[b];
        bb.id = remap[b];

        // Actualizar predecesores y sucesores
        std::vector<IrBlockId> new_preds, new_succs;
        for (IrBlockId p : bb.preds) {
            if (p < nblocks && reachable[p]) new_preds.push_back(remap[p]);
        }
        for (IrBlockId s : bb.succs) {
            if (s < nblocks && reachable[s]) new_succs.push_back(remap[s]);
        }
        bb.preds = std::move(new_preds);
        bb.succs = std::move(new_succs);

        // Actualizar referencias de bloques en instrucciones
        for (auto &ins : bb.instrs) {
            if (ins.target_block != IR_NO_BLOCK && ins.target_block < nblocks)
                ins.target_block = remap[ins.target_block];
            if (ins.false_block != IR_NO_BLOCK && ins.false_block < nblocks)
                ins.false_block = remap[ins.false_block];
            // Eliminar argumentos phi que vienen de bloques inalcanzables
            std::vector<IrPhiArg> new_phi;
            for (const auto &pa : ins.phi_args) {
                if (pa.block < nblocks && reachable[pa.block]) {
                    IrPhiArg na = pa;
                    na.block = remap[pa.block];
                    new_phi.push_back(na);
                }
            }
            ins.phi_args = std::move(new_phi);
            // SWITCH_DENSE: remapear la tabla de bloques destino (campo
            // jump_targets) igual que target_block.  Sin esto, tras la
            // renumeracion la jump table apunta a ids viejos -> dispatch
            // permutado.
            for (uint32_t &t : ins.jump_targets)
                if (t < nblocks && remap[t] != IR_NO_BLOCK) t = remap[t];
        }
        new_blocks.push_back(std::move(bb));
    }
    fn.blocks = std::move(new_blocks);
    return true;
}

// =========================================================================
//  Pase CSE (Common Subexpression Elimination, local)
// =========================================================================

/* Global const CSE: deduplicar CONSTs en bloques no-entry contra los
 * de entry (que dominan a todos los demas).  Pase separado, seguro a O2.
 *
 * Implementacion: en vez de rewrite-CONST-to-MOV-then-copy-prop (que
 * dejaba el is_const flag stale en fn.values y causaba interaccion mala
 * con simplify/const_fold), hacemos un DIRECT REWRITE:
 *
 *   1. Recolectar mapa {(type, imm) -> entry_vid} de entry.
 *   2. Recolectar mapa {dup_vid -> canon_vid} para CONSTs duplicados en
 *      bloques no-entry.
 *   3. Aplicar sustitucion en TODOS los operandos / func_ptr / phi_args.
 *   4. Eliminar las instrucciones CONST duplicadas (no las convertimos a
 *      MOV; las quitamos del bloque directamente -- DCE no es necesario).
 *
 * Esto evita el camino MOV+copy_prop que dejaba is_const stale.  La
 * IrValue del dup_vid queda huerfana (sin instr definidora), pero como
 * todos sus usos se substituyen, no se referencia mas. */
bool ir_pass_const_cse_entry(IrFunction &fn) {
    if (fn.blocks.empty()) return false;
    /* Pase 1: en entry, recolectar el PRIMER vid por (type,imm) y registrar
     * duplicados subsiguientes -> subst (apuntan al primer vid). */
    std::unordered_map<std::string, IrValueId> entry_const_table;
    std::unordered_map<IrValueId, IrValueId> subst;
    for (const auto &ins : fn.blocks[0].instrs) {
        if (ins.op != IrOp::CONST || ins.dst == IR_NO_VALUE) continue;
        std::ostringstream key;
        key << static_cast<int>(ins.type) << ":" << ins.imm;
        std::string k = key.str();
        auto it = entry_const_table.find(k);
        if (it == entry_const_table.end()) {
            entry_const_table[k] = ins.dst;
        } else if (it->second != ins.dst) {
            /* Duplicado dentro de entry -- redirige al primero. */
            subst[ins.dst] = it->second;
        }
    }
    if (entry_const_table.empty()) return false;

    /* Pase 2: en bloques no-entry, identificar duplicados y agregar subst. */
    for (size_t bi = 1; bi < fn.blocks.size(); ++bi) {
        for (const auto &ins : fn.blocks[bi].instrs) {
            if (ins.op != IrOp::CONST || ins.dst == IR_NO_VALUE) continue;
            std::ostringstream key;
            key << static_cast<int>(ins.type) << ":" << ins.imm;
            auto it = entry_const_table.find(key.str());
            if (it != entry_const_table.end() && it->second != ins.dst) {
                subst[ins.dst] = it->second;
            }
        }
    }
    if (subst.empty()) return false;

    /* Aplicar sustitucion en operandos / func_ptr / phi_args. */
    auto canon = [&](IrValueId v) -> IrValueId {
        IrValueId cur = v;
        int hops = 0;
        while (subst.count(cur) && hops++ < 8)
            cur = subst[cur];
        return cur;
    };
    bool changed = false;
    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            for (auto &op : ins.operands) {
                IrValueId c = canon(op);
                if (c != op) {
                    op = c;
                    changed = true;
                }
            }
            if (ins.func_ptr != IR_NO_VALUE) {
                IrValueId c = canon(ins.func_ptr);
                if (c != ins.func_ptr) {
                    ins.func_ptr = c;
                    changed = true;
                }
            }
            for (auto &pa : ins.phi_args) {
                IrValueId c = canon(pa.value);
                if (c != pa.value) {
                    pa.value = c;
                    changed = true;
                }
            }
        }
    }

    /* Eliminar las instrucciones CONST duplicadas EN TODOS LOS BLOQUES
     * (incluyendo entry: si entry tiene dups internos, los quitamos). */
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto &instrs = fn.blocks[bi].instrs;
        std::vector<IrInstr> kept;
        kept.reserve(instrs.size());
        for (auto &ins : instrs) {
            if (ins.op == IrOp::CONST && ins.dst != IR_NO_VALUE &&
                subst.count(ins.dst)) {
                /* skip: duplicado eliminado */
                changed = true;
            } else {
                kept.push_back(std::move(ins));
            }
        }
        instrs = std::move(kept);
    }
    return changed;
}

bool ir_pass_cse(IrFunction &fn) {
    bool changed = false;

    /* ============================================================
     * GLOBAL const CSE.
     *
     * Antes del CSE local per-block, deduplicar CONSTs cross-block
     * recolectando el PRIMER CONST por (type, imm) en orden lineal de
     * bloques y registrando un mapa global de sustitucion.  Como el
     * bloque 0 (entry) domina a todos los demas, si el primer CONST
     * esta en entry, todos los duplicados en bloques posteriores
     * pueden referirse a el sin violar SSA dominance.
     *
     * Para CONSTs no en entry: solo deduplicamos si el primer CONST
     * encontrado en orden lineal de bloques domina a los duplicados.
     * Aproximacion conservadora: solo dedupe si el primer CONST esta
     * en el bloque 0 (entry).  Mas casos requeririan dominator analysis,
     * pero como SR/reassoc/LICM insertan CONSTs en entry por construccion,
     * esta heuristica cubre el 95% de los casos reales.
     * ============================================================ */
    {
        std::unordered_map<std::string, IrValueId> entry_const_table;
        /* Pase 1: recolectar CONSTs en entry (bloque 0). */
        if (!fn.blocks.empty()) {
            for (const auto &ins : fn.blocks[0].instrs) {
                if (ins.op != IrOp::CONST) continue;
                if (ins.dst == IR_NO_VALUE) continue;
                std::ostringstream key;
                key << static_cast<int>(ins.type) << ":" << ins.imm;
                std::string k = key.str();
                if (!entry_const_table.count(k)) {
                    entry_const_table[k] = ins.dst;
                }
            }
        }
        /* Pase 2: en otros bloques, deduplicar CONSTs cuyo (type, imm)
         * matchea uno de entry.  Convertir a MOV. */
        if (!entry_const_table.empty()) {
            for (size_t bi = 1; bi < fn.blocks.size(); ++bi) {
                for (auto &ins : fn.blocks[bi].instrs) {
                    if (ins.op != IrOp::CONST) continue;
                    if (ins.dst == IR_NO_VALUE) continue;
                    std::ostringstream key;
                    key << static_cast<int>(ins.type) << ":" << ins.imm;
                    auto it = entry_const_table.find(key.str());
                    if (it != entry_const_table.end() &&
                        it->second != ins.dst) {
                        ins.op = IrOp::MOV;
                        ins.operands = {it->second};
                        ins.imm = 0;
                        changed = true;
                    }
                }
            }
        }
    }
    /* Tras el global const CSE, copy_prop limpiara los MOVs. */

    auto is_mem_read = [](IrOp op) -> bool {
        return op == IrOp::LOAD || op == IrOp::ARRAY_LOAD ||
               op == IrOp::GETFIELD || op == IrOp::ARRAY_LEN;
    };

    for (auto &bb : fn.blocks) {
        // Tabla: hash de (op, type, operands) -> IrValueId del primer calculo
        std::unordered_map<std::string, IrValueId> expr_table;
        // Mapa paralelo: clave -> bool (es memory-read?) para invalidar
        // rapido al ver side-effects.
        std::unordered_set<std::string> mem_read_keys;
        // Mapa de sustituciones para aplicar
        std::unordered_map<IrValueId, IrValueId> subst;

        for (auto &ins : bb.instrs) {
            /* Bug fix: instrucciones SIN dst (STORE/BR/RET/CALL-void)
             * pueden tener side-effects que invalidan memory-read entries.
             * Procesar invalidacion ANTES del `continue` por dst==NO_VALUE. */
            if (!is_pure(ins.op)) {
                for (const auto &mk : mem_read_keys)
                    expr_table.erase(mk);
                mem_read_keys.clear();
                continue;
            }
            if (ins.dst == IR_NO_VALUE) continue;
            if (ins.op == IrOp::PHI) continue; /* phi no se dedupea */

            /* dedupe CONSTs por (type, imm).  Antes el
             * pase ignoraba CONSTs explicitamente; los port targets
             * (e.g. port-C) y el JIT se beneficiaban de tener un solo
             * SSA value por (type, imm).  Reduce el numero de slots
             * stack alocados y el output destino es mas limpio. */
            if (ins.op == IrOp::CONST) {
                std::ostringstream key;
                key << "C:" << static_cast<int>(ins.type) << ":" << ins.imm;
                std::string k = key.str();
                auto it = expr_table.find(k);
                if (it != expr_table.end()) {
                    subst[ins.dst] = it->second;
                    ins.op = IrOp::MOV;
                    ins.operands = {it->second};
                    ins.imm = 0;
                    changed = true;
                } else {
                    expr_table[k] = ins.dst;
                }
                continue;
            }

            // Construir clave canonica: "op:type:imm:func_name:op0:op1:..."
            //
            // Bug fix: imm es semanticamente significativo para STR_LIT_ADDR
            // (indice del string), GETFIELD (offset del campo), ALLOCA (size),
            // y posiblemente otros.  Incluirlo en la clave evita dedupe falso
            // (e.g., dos str_lit_addr con strings distintos parecian iguales).
            //
            // Bug fix   @c func_name es CRITICO para LABEL_ADDR y los
            // CALL-like ops (CALL, CALLN, etc).  Sin esto, dos LABEL_ADDR con
            // labels distintos se deduplican incorrectamente (handler_pc del
            // tryenter se mezcla con el name_addr del findclass, p.ej.).
            std::ostringstream key;
            key << static_cast<int>(ins.op) << ":" << static_cast<int>(ins.type)
                << ":" << ins.imm << ":" << ins.func_name;
            /* Y DE QUE MEMORIA es el resultado.  Dos instrucciones que se leen
             * igual pero producen una direccion de memorias distintas NO son la
             * misma expresion: quien use la superviviente decidira el acceso
             * mirando esa marca, y si se quedo la que no la lleva, leera de la
             * memoria equivocada -- lo que no da un error, da otro valor.
             *
             * Se vio asi: dos cargas de la misma direccion, una marcada como
             * puntero del anfitrion y otra no, se fundieron en la que no lo
             * estaba.  El indice 0 de un buffer salia a basura y el 1 bien,
             * porque el 1 pasa por una suma que si conserva la marca.  Lo mismo
             * vale para saber si es un objeto del recolector. */
            if (ins.dst < static_cast<IrValueId>(fn.values.size())) {
                key << ":" << (fn.values[ins.dst].is_host_ptr ? 'h' : '-')
                    << (fn.values[ins.dst].is_gc_object ? 'g' : '-');
            }
            for (IrValueId op : ins.operands) {
                // Resolver sustituciones previas en los operandos
                IrValueId canonical = op;
                while (subst.count(canonical))
                    canonical = subst[canonical];
                key << ":" << canonical;
            }
            std::string k = key.str();

            auto it = expr_table.find(k);
            if (it != expr_table.end()) {
                // Expresion ya calculada: sustituir dst con el valor anterior
                subst[ins.dst] = it->second;
                ins.op = IrOp::MOV;
                ins.operands = {it->second};
                changed = true;
            } else {
                // Primera ocurrencia: registrarla
                expr_table[k] = ins.dst;
                if (is_mem_read(ins.op)) mem_read_keys.insert(k);
                // Aplicar sustituciones previas a los operandos de esta
                // instruccion
                for (auto &op : ins.operands) {
                    auto sit = subst.find(op);
                    if (sit != subst.end()) op = sit->second;
                }
            }
        }
    }
    if (changed) ir_pass_copy_prop(fn); // limpiar los MOV generados por CSE
    return changed;
}

// =========================================================================
//  Pase TCO (Tail Call Optimization)
// =========================================================================

// =========================================================================
//  Helper: detectar si un IrValueId deriva (transitivamente) de una ALLOCA
//
//  Usado por TCO para descartar la transformacion CALL->TAILCALL cuando
//  algun argumento referencia memoria asignada en el frame del caller.
//  Razon: TAILCALL emite `leave` antes del salto al callee, lo que
//  restaura RSP=RBP y libera el bloque ALLOCA.  Si el callee dereferencia
//  un puntero que apuntaba a esa region, lee basura (o memoria del
//  callee).  Demo regresion: 17_ecs_basico.vx pasaba arrays
//  i32[8] (ALLOCA) por valor a system_sum_positions y obtenia R0=0
//  en vez de 100 con TCO activo.
//
//  La deteccion es conservadora: marcamos un valor como "alloca-derived"
//  si su def es ALLOCA, MEMBER (que devuelve direccion en frame), o
//  cualquier ADD/SUB/MOV/STORE/STR_LIT_ADDR cuyo operando ya este marcado.
//  No intenta tracking flow-sensitive: una sobreestimacion implica
//  perder TCO en ese caller, no incorrectness.
// =========================================================================
static bool collect_alloca_derived(const IrFunction &fn,
                                   std::unordered_set<IrValueId> &out) {
    out.clear();
    // Pase 1: identificar las definiciones ALLOCA directas.
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::ALLOCA && ins.dst != IR_NO_VALUE) {
                out.insert(ins.dst);
            }
        }
    }
    if (out.empty()) return false;

    // Pase 2: propagar la marca por aritmetica de punteros y MOV/PHI.
    // Iteramos hasta punto fijo (cota: numero de blocks * instrs por block).
    bool changed = true;
    int guard = 1024;
    while (changed && guard-- > 0) {
        changed = false;
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.dst == IR_NO_VALUE) continue;
                if (out.count(ins.dst)) continue;
                bool any_op_tainted = false;
                for (auto op : ins.operands) {
                    if (op != IR_NO_VALUE && out.count(op)) {
                        any_op_tainted = true;
                        break;
                    }
                }
                if (!any_op_tainted) {
                    for (const auto &pa : ins.phi_args) {
                        if (out.count(pa.value)) {
                            any_op_tainted = true;
                            break;
                        }
                    }
                }
                if (any_op_tainted) {
                    // Solo propagamos por ops que SI pueden producir una
                    // direccion derivada: aritmetica (ADD/SUB), copias
                    // (MOV, PHI), o casts/cargas/loads que conserven el
                    // puntero.  Para ALU "verdadera" sobre escalares no
                    // hay riesgo, asi que la lista blanca es restrictiva
                    // pero suficiente para el patron observado.
                    switch (ins.op) {
                    case IrOp::ADD:
                    case IrOp::SUB:
                    case IrOp::MOV:
                    case IrOp::PHI:
                        out.insert(ins.dst);
                        changed = true;
                        break;
                    default: break;
                    }
                }
            }
        }
    }
    return true;
}

bool ir_pass_tailcall(IrFunction &fn) {
    // Detecta el patron: CALL @f(args) seguido inmediatamente de RET %resultado
    // y convierte el CALL en TAILCALL (elimina la RET subsiguiente).
    // Tambien maneja RET void inmediatamente despues de CALL void.
    //
    // SAFETY: NO se promueve a TAILCALL si algun argumento es derivado
    // de una ALLOCA del caller.  TAILCALL emite `leave` (que restaura
    // RSP=RBP y libera el frame), invalidando los punteros que apuntan
    // al area de allocas.  El callee leeria basura.  La deteccion se
    // hace una vez por funcion y la cache se reutiliza para todos los
    // CALLs candidatos.
    bool changed = false;

    std::unordered_set<IrValueId> alloca_derived;
    const bool fn_has_alloca = collect_alloca_derived(fn, alloca_derived);

    for (auto &bb : fn.blocks) {
        auto &instrs = bb.instrs;
        for (size_t i = 0; i + 1 < instrs.size();) {
            IrInstr &call = instrs[i];
            IrInstr &ret = instrs[i + 1];

            // Solo CALL directo (no CALLVIRT, CALLN, CALLIND)
            if (call.op != IrOp::CALL) {
                ++i;
                continue;
            }
            if (ret.op != IrOp::RET) {
                ++i;
                continue;
            }

            // Verificar que RET usa directamente el resultado del CALL (o es
            // void)
            bool ret_uses_call =
                (!ret.operands.empty() && ret.operands[0] == call.dst);
            bool ret_is_void = ret.operands.empty();

            if (!ret_uses_call && !ret_is_void) {
                ++i;
                continue;
            }

            // Bloqueo de seguridad: si CUALQUIER arg es derivado de
            // ALLOCA del caller, NO promover a TAILCALL.  El leave
            // posterior liberaria la memoria todavia referenciada.
            if (fn_has_alloca) {
                bool unsafe = false;
                for (auto op : call.operands) {
                    if (op != IR_NO_VALUE && alloca_derived.count(op)) {
                        unsafe = true;
                        break;
                    }
                }
                if (unsafe) {
                    ++i;
                    continue;
                }
            }

            // Convertir: CALL -> TAILCALL, eliminar RET
            call.op = IrOp::TAILCALL;
            call.dst = IR_NO_VALUE; // TAILCALL no tiene destino
            instrs.erase(instrs.begin() + static_cast<ptrdiff_t>(i + 1));
            changed = true;
            // No avanzar 'i': re-examinar la misma posicion por si hay otro
            // patron
        }
    }
    return changed;
}

// =========================================================================
//  Pase inline_loop_header (peephole pre-codegen)
// =========================================================================

/**
 * @brief Inline de header trivial de loop para habilitar fusion decjnz.
 *
 * Detecta el patron:
 *   B: ...; <SUB>; br H
 *   H: %cmp = CMP_X(...); br.cond %cmp, T, F
 * con H teniendo UN SOLO predecesor (B).  Mueve las 2 instrs de H al
 * final de B (reemplazando el br) y vacia H.  Despues, B queda con
 * SUB+CMP+BR_COND consecutivos -> el peephole de same-block del IR
 * emitter aplica decjnz fusion.
 *
 * Generaliza a cualquier patron "header trivial con un predecesor", no
 * solo a decjnz.  Otros peepholes (cmpjmp) tambien se benefician.
 *
 * Coste: O(N_blocks * N_predecessors).  El check de predecesores es
 * lineal pero solo se ejecuta cuando el header tiene exactamente 2
 * instr (raro fuera de loop headers).
 *
 * @return true si se hizo al menos una fusion (puede dispararse otro DCE).
 */
bool ir_pass_inline_loop_header(IrFunction &fn) {
    bool changed = false;
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        IrBlock &B = fn.blocks[bi];
        if (B.instrs.empty()) continue;
        IrInstr &term = B.instrs.back();
        if (term.op != IrOp::BR) continue; // solo BR incondicional
        IrBlockId hid = term.target_block;
        if (hid >= fn.blocks.size() || hid == static_cast<IrBlockId>(bi))
            continue;
        IrBlock &H = fn.blocks[hid];
        // H debe terminar en BR_COND.  Las instrs pueden incluir CONSTs
        // literales que materializan valores usados solo por el CMP final.
        // Patron tipico: %k = const.i64 0; %z = cmp.ne.bool %x, %k; br.cond %z,
        // T, F. Tambien permitimos el CMP en penultima posicion con 0..N CONSTs
        // antes.
        if (H.instrs.size() < 2) continue;
        const IrInstr &h_last = H.instrs.back();
        if (h_last.op != IrOp::BR_COND) continue;
        // Buscar el CMP penultimo (h_last - 1) o anterior.  Las instrs
        // entre el CMP y el BR_COND deben ser CONST puros (sin side effects).
        size_t cmp_idx = H.instrs.size() - 2;
        const IrInstr &h_cmp = H.instrs[cmp_idx];
        bool is_cmp = (h_cmp.op == IrOp::CMP_EQ || h_cmp.op == IrOp::CMP_NE ||
                       h_cmp.op == IrOp::CMP_LT || h_cmp.op == IrOp::CMP_GT ||
                       h_cmp.op == IrOp::CMP_LE || h_cmp.op == IrOp::CMP_GE ||
                       h_cmp.op == IrOp::CMP_ULT || h_cmp.op == IrOp::CMP_UGT ||
                       h_cmp.op == IrOp::CMP_ULE || h_cmp.op == IrOp::CMP_UGE);
        if (!is_cmp) continue;
        // Verificar que las instrs antes del CMP sean todas CONST (puras).
        bool only_consts = true;
        for (size_t k = 0; k < cmp_idx; ++k) {
            if (H.instrs[k].op != IrOp::CONST) {
                only_consts = false;
                break;
            }
        }
        if (!only_consts) continue;
        // El cmp.dst debe ser el unico operand del BR_COND.
        if (h_last.operands.empty() || h_last.operands[0] != h_cmp.dst)
            continue;
        // Contar predecesores de H.
        int preds = 0;
        for (size_t pi = 0; pi < fn.blocks.size(); ++pi) {
            if (fn.blocks[pi].instrs.empty()) continue;
            const IrInstr &pterm = fn.blocks[pi].instrs.back();
            if (pterm.op == IrOp::BR && pterm.target_block == hid)
                ++preds;
            else if (pterm.op == IrOp::BR_COND &&
                     (pterm.target_block == hid || pterm.false_block == hid))
                ++preds;
        }
        if (preds != 1) continue; // mas de 1 pred o 0 -> no fusionar
        // No tocar entry block: si H es entry, no podemos fusionarlo
        // (entry no tiene predecesores; ya filtrado por preds!=1, pero
        // doble check defensivo).
        if (hid == 0) continue;
        // El header NO debe tener PHI nodes (el primer instr debe ser CMP, no
        // PHI). Ya implicito en H.instrs.size() == 2 con h0 = CMP.

        // Aplicar la fusion:
        //   1. Eliminar BR de B.
        //   2. Append todas las instrs de H (CONSTs + CMP + BR_COND) al final
        //   de B.
        //   3. Hoist de CONSTs: mover todas las IrOp::CONST justo despues de
        //      las PHI nodes (CONSTs son puros, su orden es irrelevante para
        //      la semantica).  Esto agrupa los CONSTs y deja a SUB+CMP+BR_COND
        //      consecutivos en el final, habilitando peepholes como decjnz.
        //   4. Limpiar H (queda inalcanzable, lo barren los demas pases).
        //   5. Reescribir phi_args en sucesores de BR_COND: ref a H debe pasar
        //   a B.
        IrBlockId t_true = h_last.target_block;
        IrBlockId t_false = h_last.false_block;

        std::vector<IrInstr> moved;
        moved.reserve(H.instrs.size());
        for (auto &ins : H.instrs)
            moved.push_back(std::move(ins));
        B.instrs.pop_back(); // remover BR de B
        for (auto &ins : moved)
            B.instrs.push_back(std::move(ins));
        H.instrs.clear();

        // Hoist de CONSTs: estabilizamos el orden en B asi:
        //   [PHIs...] [CONSTs...] [resto en orden original]
        // Stable_partition mantiene el orden relativo de cada grupo.  Los
        // CONSTs no tienen side effects ni dependen de instrucciones
        // anteriores (su unico operand_id es @c imm), asi que moverlos
        // hacia adelante no rompe SSA dominance: si un CONST se usaba a
        // X, ahora esta definido aun antes que X.
        {
            std::vector<IrInstr> phis, consts, rest;
            phis.reserve(4);
            consts.reserve(8);
            rest.reserve(B.instrs.size());
            for (auto &ins : B.instrs) {
                if (ins.op == IrOp::PHI)
                    phis.push_back(std::move(ins));
                else if (ins.op == IrOp::CONST)
                    consts.push_back(std::move(ins));
                else
                    rest.push_back(std::move(ins));
            }
            B.instrs.clear();
            B.instrs.reserve(phis.size() + consts.size() + rest.size());
            for (auto &ins : phis)
                B.instrs.push_back(std::move(ins));
            for (auto &ins : consts)
                B.instrs.push_back(std::move(ins));
            for (auto &ins : rest)
                B.instrs.push_back(std::move(ins));
        }

        auto rewrite_phi_block_ref = [&](IrBlockId target_id) {
            if (target_id >= fn.blocks.size()) return;
            IrBlock &T = fn.blocks[target_id];
            for (auto &ins : T.instrs) {
                if (ins.op != IrOp::PHI) break;
                for (auto &pa : ins.phi_args) {
                    if (pa.block == hid) pa.block = static_cast<IrBlockId>(bi);
                }
            }
        };
        rewrite_phi_block_ref(t_true);
        rewrite_phi_block_ref(t_false);

        changed = true;
        // No avanzar bi: re-procesar B porque puede haber cadena
        // (B -> H1 -> H2 inlinable transitivamente).
        --bi;
    }
    return changed;
}

// =========================================================================
//  Pase ir_pass_inline
// =========================================================================
//
// Function inlining a nivel modulo.  Para cada CALL site, si el callee
// cumple las heuristicas de inlineabilidad, sustituye la CALL con el
// cuerpo del callee, renombrando SSA values + bloques.
//
// = v1: Single-block callees =
//
// El callee debe tener exactamente 1 bloque que termine con RET (o no
// terminar si vacio).  Esto cubre casos muy comunes:
//   - Wrappers triviales: `i32 f() { return 0; }`
//   - Getters: `i32 get_x(T this) { return this.x; }`
//   - Helpers pequenos sin control de flujo.
//
// Multi-block callees y recursion requieren CFG manipulation mas
// compleja (CFG merge + phi insertion) -- deferred a v2.
//
// = Heuristica =
//
// Inlineable si:
//   - Callee esta definido en nuestro IrModule (no @c is_native).
//   - Callee tiene 1 bloque exactamente y termina con RET.
//   - Body del callee tiene < INLINE_THRESHOLD instrucciones.
//   - Callee NO es el caller (no self-inline).
//
// = Beneficios =
//
// JIT: skip CALL/RET overhead, regalloc puede ver mas contexto,
// const-fold se propaga a traves de la call.  Ejemplo: pruebas() en
// 100_reflection_full despues de dead-alloc elim queda como
// `return 0`.  Si se inline en main, la asignacion a val es trivial
// y el loop body se reduce a la comparacion + incremento.
//
// port-C: codigo destino mas legible, sin auxiliary functions ni
// goto-style returns.

/**
 * @brief Registra en @p caller la llamada que se va a aplanar y devuelve por
 *        donde traducir los sitios que el llamado ya traia dentro.
 *
 * Al inlinar, el codigo del llamado pasa a vivir en quien llama pero conserva
 * las lineas de SU fuente; sin dejar constancia, la traza atribuye esas lineas
 * a la funcion equivocada.  Se apunta un sitio para esta llamada y, si el
 * llamado ya tenia inlinados dentro, se copian sus sitios colgando del nuevo,
 * de modo que las cadenas anidadas siguen encajando.
 *
 * @param caller Funcion que absorbe el codigo.
 * @param callee Funcion cuyo codigo se copia.
 * @param call Instruccion CALL que se sustituye.
 * @param[out] base Indice donde empiezan los sitios trasladados del llamado.
 * @return Indice del sitio de esta llamada.
 */
static uint32_t inline_note_site(IrFunction &caller, const IrFunction &callee,
                                 const IrInstr &call, uint32_t &base) {
    const uint32_t site = static_cast<uint32_t>(caller.inline_sites.size());
    InlineSite s;
    s.callee = callee.name;
    s.line = call.source_line;
    s.column = call.source_column;
    // Si la propia llamada venia ya inlinada, cuelga de aquella.
    s.parent = call.inline_site;
    caller.inline_sites.push_back(std::move(s));

    base = static_cast<uint32_t>(caller.inline_sites.size());
    for (const InlineSite &cs : callee.inline_sites) {
        InlineSite n = cs;
        // Los de mas afuera del llamado pasan a colgar de esta llamada.
        n.parent = (cs.parent == IR_NO_INLINE_SITE) ? site : (base + cs.parent);
        caller.inline_sites.push_back(std::move(n));
    }
    return site;
}

/**
 * @brief Traduce el sitio de una instruccion copiada al espacio del llamador.
 *
 * @param original Sitio que traia en el llamado.
 * @param site Sitio de la llamada que se aplana.
 * @param base Origen de los sitios trasladados (ver @c inline_note_site).
 * @return Sitio equivalente ya en el llamador.
 */
static inline uint32_t inline_map_site(uint32_t original, uint32_t site,
                                       uint32_t base) {
    return (original == IR_NO_INLINE_SITE) ? site : (base + original);
}

bool ir_pass_inline(IrModule &mod, size_t threshold) {
    /* Threshold de tamano del body del callee para inlinar.
     *
     * Por que 12 por defecto (en lugar de 8 o 16): el overhead del CALLVM (push
     * regs vivos, mov r1..rN args, callvm, pop regs, mov dst r0) en el peor
     * caso son ~24 instrucciones VM.  Cualquier callee cuyo cuerpo cabe en
     * menos de eso es candidato directo a inline ya que ahorramos mas de lo que
     * crece el caller.  12 es el balance que captura getters, setters y helpers
     * aritmeticos pequenos sin causar bloat material en el .velb de programas
     * tipicos.  El C2/OSR pasa un threshold mayor para inlinear las CALLs de un
     * loop CALIENTE (el code-size no importa cuando el loop domina el tiempo).
     *
     * NOTA (barrido stack-first): subir a 16 se probo para desbloquear el
     * scalar-replacement de objetos cuya unica fuga es pasar `this` a un metodo
     * pequeno (operadores `__add__`/`__eq__`, ~16 instrs).  Resultado: solo +1
     * ejemplo del corpus a puro-stack, a cambio de +code-size en TODOS los
     * programas, y SIN destrabar el caso motivante (40_operator_overload tiene
     * 3 objetos + varios operadores -> necesitaria ~20+).  Mal tradeoff: el
     * metodo-call necesita scalar-replace-driven inlining (inlinar SOLO cuando
     * habilita la eliminacion del objeto), no un threshold global.  Revertido.
     */
    const size_t INLINE_THRESHOLD = threshold;
    bool changed = false;

    /* Build name -> index map. */
    std::unordered_map<std::string, size_t> name_to_idx;
    for (size_t i = 0; i < mod.functions.size(); ++i) {
        name_to_idx[mod.functions[i].name] = i;
    }

    /* Funciones que NUNCA se deben inlinear (entry points alternativos
     * o sintetic functions con calling conventions especiales). */
    auto is_blacklisted = [](const std::string &name) -> bool {
        /* __module_init: el Loader lo invoca via init_pc, no es un CALL
         * normal.  Inlinearlo en main duplica el defclass + deffield
         * + defmethod del bytecode. */
        /* Por PREFIJO, no por igualdad: ademas de la propia hay dos familias
         * mas -- las tandas en que se parte (`__module_init_partN`) y la de
         * cada dependencia al fusionar modulos (`__module_init_<modulo>`).
         * Inlinear las tandas las devolveria a una sola funcion gigante, que
         * es justo lo que se parte para evitar. */
        if (name.rfind("__module_init", 0) == 0) return true;
        /* Lambda helpers: invocados via function pointer en CALLCLOSURE.
         * Sus IR son single-block + RET pero el calling convention es
         * distinta (env_addr en r14, etc). */
        if (name.rfind("__lambda_", 0) == 0) return true;
        /* Spawn helpers: invocados por SPAWN op, no por CALL. */
        if (name.rfind("__spawn_", 0) == 0) return true;
        /* Async helpers: invocados por @Async machinery. */
        if (name.rfind("__async_", 0) == 0) return true;
        /* rspawn body helpers. */
        if (name.rfind("__rspawn_", 0) == 0) return true;
        /* Helpers de string value-type (Vesta Embed): __vx_strlen,
         * __vx_strdata,
         * __vx_strcmp.  Se mantienen como funciones APARTE: cada accesor de
         * longitud/data inline expandia ~10 instrs (AND-mask select heap/SSO);
         * sumar varias en una funcion reventaba el regalloc SysV (4
         * callee-saved vs 6 en Win64) -> resultado erroneo en ELF.  Una sola
         * CALL por uso elimina la presion y unifica el codegen PE/ELF. */
        if (name.rfind("__vx_str", 0) == 0) return true;
        /* `__uncaught`: es un GANCHO.  Existe para que el usuario lo pueda
         * sustituir y para que el driver lo pueda completar -- ahi le antepone
         * el volcado del buffer de salida cuando hay runtime de I/O, para que
         * un programa que se rinde no se lleve por delante lo que llevaba
         * impreso.  Un gancho inlinado dentro de su unico llamante deja de ser
         * las dos cosas: ya no hay funcion a la que apuntar. */
        if (name == "__uncaught") return true;
        return false;
    };

    /* Pre-classify cada function: es inlineable? */
    // ¿El cuerpo de una funcion tiene una SALIDA MANUAL en su inline asm
    // (`ret`/`iret`/`iretq`)?  Esas instrucciones retornan al caller por si
    // mismas, asi que inlinar el cuerpo cambiaria la semantica (retornaria en
    // medio del caller).  Una funcion asi NO se inlina; si por lo demas seria
    // inlinable, el usuario debe QUITAR el `ret` (se avisa con un warning en el
    // frontend).  Los args con register() SI se inlinan cuando no hay salida
    // manual: cada arg del cast va a su registro y los params no pasados se
    // eliminan (ver aridad reducida arriba) -> se emite solo el asm justo.
    auto asm_has_manual_return = [](const IrFunction &fn) -> bool {
        for (const auto &blk : fn.blocks)
            for (const auto &in : blk.instrs) {
                if (in.op != IrOp::INLINE_ASM) continue;
                const std::string &body = in.func_name;
                size_t p = 0;
                while (p <= body.size()) {
                    size_t nl = body.find('\n', p);
                    std::string ln = body.substr(p, nl == std::string::npos
                                                        ? std::string::npos
                                                        : nl - p);
                    size_t cm = ln.find(';');
                    if (cm != std::string::npos) ln.resize(cm);
                    cm = ln.find("//");
                    if (cm != std::string::npos) ln.resize(cm);
                    size_t a = ln.find_first_not_of(" \t");
                    if (a != std::string::npos) {
                        size_t e = ln.find_first_of(" \t", a);
                        std::string tok = ln.substr(a, e == std::string::npos
                                                           ? std::string::npos
                                                           : e - a);
                        if (tok == "ret" || tok == "iret" || tok == "iretq" ||
                            tok == "retf" || tok == "sysret")
                            return true;
                    }
                    if (nl == std::string::npos) break;
                    p = nl + 1;
                }
            }
        return false;
    };
    /* Cierto si el modulo trae una variante para otro motor de esta funcion.
     * Se reconoce por el nombre: la del interprete conserva el desnudo y la
     * del JIT lleva el sufijo, que es el mismo contrato que usa el JIT al
     * elegir.  Sin tabla ni campo nuevo. */
    auto tiene_variante_por_motor = [&](const std::string &nombre) -> bool {
        static constexpr const char *kSufijo = "__jit";
        const std::string con_sufijo = nombre + kSufijo;
        for (const auto &f : mod.functions)
            if (f.name == con_sufijo) return true;
        return false;
    };
    auto is_inlineable = [&](const IrFunction &fn) -> bool {
        if (fn.is_native) return false;
        if (fn.is_naked) return false; // @Naked: standalone, no inlinable
        /* Con variantes por motor (@Target("mode:jit")), la eleccion de cual
         * usar la hace el JIT al compilar la funcion.  Si el inliner la expande
         * antes, esa eleccion queda COCIDA en el llamante y ya no hay funcion
         * que sustituir -- el codigo del interprete acaba corriendo tambien en
         * JIT.  Por eso una funcion con variante no se inlina: se cambia una
         * llamada por poder elegir, que es justo lo que el usuario pidio al
         * escribir dos versiones. */
        if (tiene_variante_por_motor(fn.name)) return false;
        // Salida manual (`ret`/`iret`) en el asm -> no inlinable (ver helper).
        if (asm_has_manual_return(fn)) return false;
        if (is_blacklisted(fn.name)) return false;
        /* AOT 2b (dev OS): una funcion con @section explicito debe permanecer
         * como funcion REAL en esa seccion (el usuario la quiere fisicamente
         * ahi: trampoline de boot, handler en .text.isr, etc.).  Inlinearla
         * borraria su presencia en la seccion -> NO inlinear. */
        if (!fn.section.empty()) return false;
        /*  C2.13 fix (2026-06-16): NO inlinear los helpers __new_X cuando
         * el scalar-replacement de objetos GC esta activo.  El pase siembra en
         * `call __new_X` (is_new_helper_name); si el inliner lo expande antes a
         * `newobj` + `callvirt ctor`, el seed desaparece y el objeto ademas
         * escapa via el callvirt -> scalar_replace queda INERTE (regresion del
         * feature C2.13: 178_escape_scalar_repl no transformaba nada). Mantener
         * __new_X como una call preserva el seed: el propio scalar_replace
         * elimina la call de los objetos NO-escapantes; los escapantes
         * conservan una call barata a un helper trivial (coste despreciable vs
         * habilitar la eliminacion completa del alloc para los no-escapantes).
         * Gated por VESTA_NO_ESCAPE_SCALAR para A/B testing limpio (con el pase
         * OFF, el comportamiento de inline previo se mantiene). */
        static const bool sr_on = !util::flag_on(util::FlagId::NoEscapeScalar);
        if (sr_on && is_new_helper_name(fn.name, nullptr)) return false;
        /* Resolvedores de overlay `__ovl_resolve_<S>_<f>(self)`: devuelven la
         * DIRECCION (host) de un campo de una vista.  El marcado is_host_ptr
         * del resultado vive en el CALL del caller; si se inlinan, el valor de
         * la direccion pierde is_host_ptr y el STORE/LOAD del campo emite `mov`
         * (VM) en vez de `movh` (host) -> lee/escribe la memoria equivocada.
         * Mantenerlos como CALL preserva la naturaleza host del acceso. */
        if (fn.name.rfind("__ovl_resolve_", 0) == 0) return false;
        if (fn.blocks.size() != 1) return false;
        if (fn.blocks[0].instrs.empty()) return false;
        /* Ultima instr debe ser RET. */
        const auto &last = fn.blocks[0].instrs.back();
        if (last.op != IrOp::RET) return false;
        /* Factoria de closures (construye una closure, tipicamente para
         * devolverla): inlinar con threshold MAYOR.  Inlinar la factoria en
         * el caller hace que el env nazca en el frame del caller -> si la
         * closure no escapa de ahi, un pase posterior promueve el env de
         * heap a stack (cero alocacion, cero leak).  Es la base de las
         * lambdas capturantes que escapan SIN heap (opcion 3). */
        size_t eff_threshold = INLINE_THRESHOLD;
        for (const auto &ins : fn.blocks[0].instrs)
            if (ins.op == IrOp::MAKE_CLOSURE) {
                eff_threshold = INLINE_THRESHOLD * 3 + 8; // holgura p/ factoria
                break;
            }
        // El desugar de register() (un ALLOCA + un STORE por binding) es
        // boilerplate: al inlinar se coalesce (mov reg,reg no-op) o se elimina
        // (aridad reducida).  No debe contar para el limite de tamano, o un
        // wrapper de asm minimo (`{ syscall }`) con 6 params-register pareceria
        // "grande" (14 instrs de puro boilerplate) y no se inlinaria.
        size_t body_size = fn.blocks[0].instrs.size();
        const size_t desugar = 2 * fn.asm_reg_bindings.size();
        body_size -= (desugar < body_size ? desugar : 0);
        if (body_size > eff_threshold) return false;
        /* No inlinear funciones que contengan CALLs recursivas a si mismas. */
        for (const auto &ins : fn.blocks[0].instrs) {
            if ((ins.op == IrOp::CALL || ins.op == IrOp::TAILCALL) &&
                ins.func_name == fn.name) {
                return false;
            }
        }
        /* No inlinear funciones que tengan @c RAW_ASM en su body cuando
         * el RAW_ASM podria depender del calling convention especifico
         * de la callee.  Conservadoramente: skip si hay raw_asm.
         *  AS inc.5: idem INLINE_ASM -- sus @c asm_reg_bindings viven
         * en @c IrFunction::asm_reg_bindings (per-funcion); el inliner copia
         * el op pero NO los bindings, dejando el INLINE_ASM sin pin de
         * registros en el caller -> el JIT no podria compilarlo.  Mantener la
         * funcion separada (cada una conserva sus bindings + se eager-compila).
         */
        for (const auto &ins : fn.blocks[0].instrs) {
            // RAW_ASM (@Asm verbatim) asume la calling convention VM -> no
            // inlinable.  INLINE_ASM (asm{} con register-bindings) SI: el copy
            // logic remapea asm_reg_bindings + clobber-lists al caller, asi el
            // helper asm caliente (popcnt/rdtsc/...) se inlinea sin perder el
            // pin de registros.  La unica restriccion es que el helper no
            // recurse ni tenga RAW_ASM (ya cubierto arriba).
            if (ins.op == IrOp::RAW_ASM) return false;
        }
        return true;
    };

    /* NOTA (barrido stack-first): se intento un scalar-replace-driven inlining
     * (inlinar metodos this-field-only sobre objetos frescos ELIMINABLES para
     * que scalar_replace los elimine).  El concepto funciona en sintetico
     * (`Point p = new Point(..); p.sumxy()` -> return const, heap 0) PERO:
     * (1) CERO ejemplos del corpus se benefician (sus casos method-call usan
     * metodos MULTI-bloque -- `__eq__` con `&&` -- que el inliner single-block
     * no toca; el inline multi-bloque es trabajo aparte); (2) rompio
     * 101_raii_casos_limite de TRES formas distintas en tres intentos (hang
     * determinista y luego NO-determinista, por interaccion con dtors via
     * CALLVIRT + reflexion newInstance), senal de que la eliminacion de objetos
     * en presencia de RAII/reflexion tiene aristas sutiles.  Mal tradeoff
     * (regresion fragil + cero beneficio de corpus) -> NO incluido.  El unlock
     * real necesita inline MULTI-bloque + analisis de eliminabilidad robusto
     * frente a dtor/reflexion; queda como feature dedicada documentada. */

    /* Cache de classification. */
    std::vector<bool> can_inline(mod.functions.size(), false);
    for (size_t i = 0; i < mod.functions.size(); ++i) {
        can_inline[i] = is_inlineable(mod.functions[i]);
    }

    for (size_t fi = 0; fi < mod.functions.size(); ++fi) {
        IrFunction &caller = mod.functions[fi];
        if (caller.is_native) continue;

        for (auto &bb : caller.blocks) {
            /* Procesar in-place; recolectar lista de cambios primero
             * para no invalidar iterators. */
            std::vector<IrInstr> new_instrs;
            new_instrs.reserve(bb.instrs.size());

            for (size_t i = 0; i < bb.instrs.size(); ++i) {
                IrInstr &ins = bb.instrs[i];
                if (ins.op != IrOp::CALL) {
                    new_instrs.push_back(std::move(ins));
                    continue;
                }
                /* CALL a function user.  Verificar si el callee esta
                 * en el modulo y es inlineable. */
                auto it = name_to_idx.find(ins.func_name);
                if (it == name_to_idx.end() || it->second == fi ||
                    !can_inline[it->second]) {
                    new_instrs.push_back(std::move(ins));
                    continue;
                }
                const IrFunction &callee = mod.functions[it->second];
                const IrBlock &cbody = callee.blocks[0];
                /* Aridad: el CALL puede pasar MENOS args que params del callee
                 * (un cast a un cfn de menor aridad sobre una funcion con
                 * register() por-argumento -- p.ej. un `invoke` de syscall de 6
                 * args llamado con solo 3).  Los params NO pasados y su desugar
                 * de register() (ALLOCA + STORE + binding) se ELIMINAN al
                 * inlinar
                 * -> el asm inlinado emite SOLO los movs de los args que si
                 * llegaron.  Mas args que params (variadico) no se inlina aqui.
                 */
                if (callee.params.size() < ins.operands.size()) {
                    new_instrs.push_back(std::move(ins));
                    continue;
                }

                /* Params NO pasados por el cast: indices [operands, params). */
                std::unordered_set<IrValueId> dropped_params;
                for (size_t pi = ins.operands.size(); pi < callee.params.size();
                     ++pi)
                    dropped_params.insert(callee.params[pi]);
                /* Variables register() de esos params (su ALLOCA): el desugar
                 * emite `STORE(param, addr)` (operands[0]=param,
                 * operands[1]=addr). Si el param se elimina, su
                 * variable/ALLOCA/binding tambien.  El INLINE_ASM que las
                 * tuviera como operando las pierde -> el asm no toca esos
                 * registros. */
                std::unordered_set<IrValueId> dropped_vars;
                if (!dropped_params.empty())
                    for (const auto &c_ins : cbody.instrs)
                        if (c_ins.op == IrOp::STORE &&
                            c_ins.operands.size() == 2 &&
                            dropped_params.count(c_ins.operands[0]))
                            dropped_vars.insert(c_ins.operands[1]);

                /* Mapeo callee_vid -> caller_vid. */
                std::unordered_map<IrValueId, IrValueId> vmap;
                /* Params del callee se mapean a operandos del CALL (solo los
                 * pasados; los dropped quedan sin mapeo -> se eliminan). */
                for (size_t pi = 0; pi < ins.operands.size(); ++pi) {
                    vmap[callee.params[pi]] = ins.operands[pi];
                }

                /* Helper: para cada SSA value que el callee DEFINE,
                 * allocar fresh en el caller. */
                auto remap_dst =
                    [&](IrValueId cvid, IrType type,
                        const std::string &name_hint) -> IrValueId {
                    if (cvid == IR_NO_VALUE) return IR_NO_VALUE;
                    auto vit = vmap.find(cvid);
                    if (vit != vmap.end()) return vit->second;
                    const IrValueId new_vid =
                        static_cast<IrValueId>(caller.values.size());
                    IrValue nv{};
                    nv.id = new_vid;
                    nv.type = type;
                    nv.name = "%inl_" + std::to_string(new_vid);
                    (void)name_hint;
                    if (cvid < callee.values.size()) {
                        const auto &cv = callee.values[cvid];
                        nv.is_const = cv.is_const;
                        nv.const_val = cv.const_val;
                        nv.is_host_ptr = cv.is_host_ptr;
                        nv.pointee_is_host_ptr = cv.pointee_is_host_ptr;
                        nv.is_gc_object = cv.is_gc_object;
                        nv.narrow_only = cv.narrow_only;
                    }
                    caller.values.push_back(nv);
                    vmap[cvid] = new_vid;
                    return new_vid;
                };

                auto remap_op = [&](IrValueId cvid) -> IrValueId {
                    if (cvid == IR_NO_VALUE) return IR_NO_VALUE;
                    auto vit = vmap.find(cvid);
                    if (vit != vmap.end()) return vit->second;
                    /* Valor del callee que no fue param ni dst previo.
                     * Esto no deberia pasar si procesamos en orden. */
                    return IR_NO_VALUE;
                };

                /* Constancia de la llamada que se aplana, para que la traza
                 * pueda volver a contarla (ver inline_note_site). */
                uint32_t sitio_base = 0;
                const uint32_t sitio =
                    inline_note_site(caller, callee, ins, sitio_base);

                /* Replicar todas las instrs del callee EXCEPTO el RET final. */
                IrValueId ret_value = IR_NO_VALUE;
                bool inline_ok = true;
                bool inlined_inline_asm = false;
                /// Cuanto se desplazaron los marcadores `$N` de los bloques
                /// asm que se traen del callee (ver mas abajo).
                int ph_desplazamiento = 0;
                for (const auto &c_ins : cbody.instrs) {
                    if (c_ins.op == IrOp::RET) {
                        if (!c_ins.operands.empty()) {
                            ret_value = remap_op(c_ins.operands[0]);
                        }
                        continue; /* skip RET; ret value resolved */
                    }
                    /* Desugar de un param NO pasado por el cast: eliminarlo.
                     * ALLOCA de su variable register() + STORE inicial que la
                     * carga con el param ausente.  Asi el asm inlinado no
                     * referencia -- ni el codegen genera movs para -- ese
                     * registro (arg no usado por esta syscall). */
                    if (c_ins.op == IrOp::ALLOCA &&
                        dropped_vars.count(c_ins.dst))
                        continue;
                    if (c_ins.op == IrOp::STORE && c_ins.operands.size() == 2 &&
                        dropped_params.count(c_ins.operands[0]))
                        continue;
                    /* Clonar c_ins y remap operandos + dst. */
                    IrInstr ni = c_ins;
                    ni.inline_site =
                        inline_map_site(c_ins.inline_site, sitio, sitio_base);
                    /* INLINE_ASM: quitar de sus operandos las variables
                     * register() de params dropped (el asm ya no las usa). */
                    if (ni.op == IrOp::INLINE_ASM && !dropped_vars.empty()) {
                        std::vector<IrValueId> kept;
                        kept.reserve(ni.operands.size());
                        for (IrValueId op : ni.operands)
                            if (!dropped_vars.count(op)) kept.push_back(op);
                        ni.operands = std::move(kept);
                    }
                    /* @fp(strict) sound bajo inlining: si el callee es STRICT,
                     * marcar sus ops copiadas para que el fuse del caller
                     * (fast) NO las contraiga a FMA -- preserva los 2 redondeos
                     * IEEE del callee.  El fuse chequea el flag en el fmul Y el
                     * fadd, asi que basta marcar las del callee (aunque el fadd
                     * combinante fuera del caller, el fmul marcado bloquea la
                     * fusion). */
                    if (!callee.fp_contract) ni.no_fp_contract = true;
                    /* dst: si tiene resultado, mapear a nuevo VID en caller. */
                    if (ni.dst != IR_NO_VALUE) {
                        const IrType dst_type = (ni.dst < callee.values.size())
                                                    ? callee.values[ni.dst].type
                                                    : ni.type;
                        ni.dst = remap_dst(ni.dst, dst_type, "");
                    }
                    /* operands. */
                    for (auto &op : ni.operands) {
                        op = remap_op(op);
                    }
                    /* func_ptr (CALLIND/CALLCLOSURE). */
                    if (ni.func_ptr != IR_NO_VALUE) {
                        ni.func_ptr = remap_op(ni.func_ptr);
                    }
                    /* phi_args: callee es single-block, no phis razonables.
                     * Si los hay, skip inline. */
                    if (!ni.phi_args.empty()) {
                        inline_ok = false;
                        break;
                    }
                    /* INLINE_ASM: el asm-id (imm bits 8..31) indexa el
                     * @c asm_clobber_lists del CALLEE.  Tras inlinar debe
                     * indexar el del CALLER -> apendamos la clobber-list y
                     * reescribimos el asm-id.  Los registros del bloque asm
                     * (rax/rdi/...) viajan en el texto verbatim; los pins de
                     * los register-vars viajan en asm_reg_bindings (abajo). */
                    if (ni.op == IrOp::INLINE_ASM) {
                        const uint32_t old_id =
                            static_cast<uint32_t>((ni.imm >> 8) & 0xFFFFFFu);
                        const uint32_t new_id = static_cast<uint32_t>(
                            caller.asm_clobber_lists.size());
                        if (old_id < callee.asm_clobber_lists.size())
                            caller.asm_clobber_lists.push_back(
                                callee.asm_clobber_lists[old_id]);
                        else
                            caller.asm_clobber_lists.emplace_back();
                        /* Se sustituye SOLO el campo del asm-id (bits 8..31).
                         * Antes la mascara era `& 0xFF`, que ademas de quitar
                         * el id viejo -- lo buscado -- borraba el bit 32, o
                         * sea "la lista de clobbers es autoritativa".  Al
                         * perderlo, el bloque pasaba a "no se sabe que
                         * destruye" y el backend lo trataba como posicion de
                         * llamada; entonces sus PROPIOS operandos salian
                         * exigiendo un carril preservado, y en x86-64 ninguna
                         * xmm/ymm lo es: cero carriles admisibles, ningun
                         * registro asignado y el bloque emitido VACiO.  Se
                         * veia como un `movdqa` que no escribia nada, y solo
                         * despues de inlinar. */
                        ni.imm = (ni.imm & ~(UINT64_C(0xFFFFFF) << 8)) |
                                 (static_cast<uint64_t>(new_id) << 8);
                        /* Los operandos que elige el compilador se nombran en
                         * el cuerpo por un marcador `$N`, y ese numero indexa
                         * la lista de ligaduras de la FUNCION.  Al traer el
                         * bloque a otra funcion que ya tiene las suyas, los
                         * numeros se pisarian y un bloque acabaria usando el
                         * registro de otro -- se veia como un `movdqu zmm0`,
                         * mezcla de dos bloques distintos.  Se desplazan aqui,
                         * igual que el id de la lista de clobbers. */
                        int desplazamiento = 0;
                        for (const auto &pb : caller.asm_reg_bindings)
                            if (pb.reg_auto && pb.ph_index >= desplazamiento)
                                desplazamiento = pb.ph_index + 1;
                        if (desplazamiento > 0)
                            ni.func_name = vx_desplazar_marcadores(
                                ni.func_name, desplazamiento);
                        ph_desplazamiento = desplazamiento;
                        inlined_inline_asm = true;
                    }
                    /* ASM_MICRO: @c imm indexa el @c asm_micros del CALLEE.
                     * Tras inlinar debe indexar el del CALLER -> apendamos la
                     * entrada y reescribimos @c imm.  Los SSA de entrada/salida
                     * de la side-table (si los hay) se remapean via vmap como
                     * el resto de operandos. */
                    if (ni.op == IrOp::ASM_MICRO) {
                        const uint32_t old_id = static_cast<uint32_t>(ni.imm);
                        const uint32_t new_id =
                            static_cast<uint32_t>(caller.asm_micros.size());
                        if (old_id < callee.asm_micros.size()) {
                            ir::AsmMicro am = callee.asm_micros[old_id];
                            for (auto &op : am.operands)
                                op.value = remap_op(op.value);
                            caller.asm_micros.push_back(std::move(am));
                        } else {
                            caller.asm_micros.emplace_back();
                        }
                        ni.imm = new_id;
                    }
                    new_instrs.push_back(std::move(ni));
                }

                if (!inline_ok) {
                    /* Cancelar el inline: revertir lo que añadimos.
                     * Conservativo: push el CALL original. */
                    /* Quitar las instrs recien añadidas relacionadas con
                     * inline. Para simplicidad: NO retroceder; quedaria un mix
                     * incorrecto.  Marcar y emit CALL original al final. */
                    /* Reset estrategia: para evitar IR corrupto, hacemos un
                     * passthrough simple: no haber comenzado a añadir.
                     * Como ya empezamos, no podemos limpiar facilmente.
                     * Por seguridad: rebuild new_instrs desde scratch
                     * usando bb.instrs[0..i]. */
                    new_instrs.clear();
                    for (size_t k = 0; k <= i; ++k) {
                        new_instrs.push_back(bb.instrs[k]);
                    }
                    continue;
                }

                /* INLINE_ASM inlineado: apendar los register-bindings del
                 * callee al caller, remapeando @c alloca_value via vmap (los
                 * ALLOCA de los register-vars ya se copiaron al caller).  El
                 * regalloc del caller (vreg_fixed por-vreg) los pinea al
                 * registro fisico alrededor del bloque asm; dos inlines del
                 * mismo helper pinean dos vregs distintos al mismo phys en
                 * puntos NO solapados -> sin conflicto. */
                if (inlined_inline_asm) {
                    for (const auto &b : callee.asm_reg_bindings) {
                        // Binding de la variable register() de un param
                        // dropped: no copiar (su ALLOCA/STORE ya se
                        // eliminaron).
                        if (dropped_vars.count(b.alloca_value)) continue;
                        ir::AsmRegBinding nb = b;
                        nb.alloca_value = remap_op(b.alloca_value);
                        // Mismo desplazamiento que se aplico a los marcadores
                        // del cuerpo, para que sigan apuntando a su ligadura.
                        if (nb.reg_auto && nb.ph_index >= 0)
                            nb.ph_index += ph_desplazamiento;
                        if (nb.alloca_value != IR_NO_VALUE)
                            caller.asm_reg_bindings.push_back(std::move(nb));
                    }
                }

                /* Emitir el "resultado" del inline: si el CALL tenia dst,
                 * MOV dst <- ret_value. */
                if (ins.dst != IR_NO_VALUE && ret_value != IR_NO_VALUE) {
                    IrInstr mv{};
                    mv.op = IrOp::MOV;
                    mv.type = ins.type;
                    mv.dst = ins.dst;
                    mv.operands = {ret_value};
                    new_instrs.push_back(std::move(mv));
                } else if (ins.dst != IR_NO_VALUE) {
                    /* Callee no retorno valor pero CALL expected uno.
                     * Conservativo: CONST 0 placeholder. */
                    IrInstr cz{};
                    cz.op = IrOp::CONST;
                    cz.type = ins.type;
                    cz.dst = ins.dst;
                    cz.imm = 0;
                    new_instrs.push_back(std::move(cz));
                }

                changed = true;
            }
            bb.instrs = std::move(new_instrs);
        }
    }
    return changed;
}

// =========================================================================
//  Pase ir_pass_licm
// =========================================================================
//
// Loop-Invariant Code Motion.  Para cada loop simple detectado, mueve
// instrucciones cuyos operandos son TODOS invariantes (definidos fuera
// del loop O constantes) al predecesor del loop header.
//
// Beneficio: las invariantes se calculan UNA vez (en el predecesor) en
// vez de N veces (en cada iteracion del loop).  Tipico para patrones
// como `for(i; i<size; i++)` donde `size` es invariant.
//
// = v1: simple algorithm =
//
// 1. Detectar loops via back-edges (JMP/BR_COND a un bloque ANTERIOR
//    en orden lineal o via dataflow simple).
// 2. Para cada loop header H y back-edge from B:
//    - Conjunto de bloques en el loop: { H, ..., B } (BFS desde B
//      hasta H siguiendo predecesores).
//    - Pre-header: bloque que cae a H pero NO esta en el loop.
//      Si hay multiples, abortar (necesita split, deferred).
// 3. Para cada instr en el loop:
//    - Si pure_op AND todos los operands son CONSTs o definidos fuera
//      del loop AND la instr no es phi AND no tiene side effects:
//      Mover al pre-header.
//
// v1 conservativo: solo loops simples con UN solo back-edge y UN pre-
// header (case clasico while/for).

bool ir_pass_licm(IrFunction &fn, const analysis::PointsTo *pt,
                  const std::unordered_set<std::string> *pure_callees) {
    if (fn.blocks.size() < 3)
        return false; /* necesita pre-header + body + header */
    const size_t N = fn.blocks.size();

    // Modelo de memoria UNICO (alias-aware LICM, gated): LICM NO construye la
    // tabla points-to -- la RECIBE (Regla 1: base de hechos compartida).  Usa
    // el vocabulario compartido analysis::memory_access (misma verdad que DSE/
    // scheduler/EffectAnalysis) para decidir si un store del loop puede aliasar
    // un load candidato a hoist.
    const bool licm_alias = g_licm_alias && pt && pure_callees;
    auto licm_is_pure_call = [&](const IrInstr &ins) -> bool {
        if (!pure_callees) return false;
        if (ins.op != IrOp::CALL && ins.op != IrOp::TAILCALL) return false;
        return !ins.func_name.empty() && pure_callees->count(ins.func_name) > 0;
    };

    /* Construir CFG: para cada bloque, sus sucesores y predecesores. */
    std::vector<std::vector<IrBlockId>> preds(N);
    std::vector<std::vector<IrBlockId>> succs(N);
    for (size_t b = 0; b < N; ++b) {
        const auto &bb = fn.blocks[b];
        if (bb.instrs.empty()) continue;
        const auto &last = bb.instrs.back();
        IrBlockId t1 = IR_NO_BLOCK, t2 = IR_NO_BLOCK;
        if (last.op == IrOp::BR) {
            t1 = last.target_block;
        } else if (last.op == IrOp::BR_COND) {
            t1 = last.target_block;
            t2 = last.false_block;
        }
        if (t1 != IR_NO_BLOCK && t1 < N) {
            preds[t1].push_back(static_cast<IrBlockId>(b));
            succs[b].push_back(t1);
        }
        if (t2 != IR_NO_BLOCK && t2 < N) {
            preds[t2].push_back(static_cast<IrBlockId>(b));
            succs[b].push_back(t2);
        }
    }

    /* Dominadores via Cooper-Harvey-Kennedy iterativo.
     * dom[entry] = entry, otros = UNDEF.  Procesar en reverse postorder
     * hasta punto fijo.  intersect(b1, b2) sube en el dom-tree hasta
     * encontrar el ancestro comun mas cercano. */
    const IrBlockId UNDEF = static_cast<IrBlockId>(N);
    const IrBlockId entry = 0; /* convencion: bloque 0 es entry */

    /* DFS para reverse postorder. */
    std::vector<IrBlockId> rpo;
    rpo.reserve(N);
    {
        std::vector<bool> visited(N, false);
        std::function<void(IrBlockId)> dfs = [&](IrBlockId b) {
            if (b >= N || visited[b]) return;
            visited[b] = true;
            for (IrBlockId s : succs[b])
                dfs(s);
            rpo.push_back(b);
        };
        dfs(entry);
        std::reverse(rpo.begin(), rpo.end());
    }
    /* rpo_pos[b] = posicion de b en rpo (mayor = mas adelante = mas alto).
     * Usado por intersect_dom.  Bloques no alcanzables tienen UNDEF rpo_pos. */
    std::vector<uint32_t> rpo_pos(N, UINT32_MAX);
    for (size_t i = 0; i < rpo.size(); ++i)
        rpo_pos[rpo[i]] = static_cast<uint32_t>(i);

    /* idom[b] = inmediato dominador.  UNDEF = no computado todavia. */
    std::vector<IrBlockId> idom(N, UNDEF);
    idom[entry] = entry;

    auto intersect_dom = [&](IrBlockId b1, IrBlockId b2) -> IrBlockId {
        while (b1 != b2) {
            while (b1 != UNDEF && rpo_pos[b1] > rpo_pos[b2])
                b1 = idom[b1];
            while (b2 != UNDEF && rpo_pos[b2] > rpo_pos[b1])
                b2 = idom[b2];
            if (b1 == UNDEF || b2 == UNDEF) return UNDEF;
        }
        return b1;
    };

    bool dom_changed = true;
    while (dom_changed) {
        dom_changed = false;
        for (IrBlockId b : rpo) {
            if (b == entry) continue;
            IrBlockId new_idom = UNDEF;
            for (IrBlockId p : preds[b]) {
                if (idom[p] != UNDEF) {
                    new_idom =
                        (new_idom == UNDEF) ? p : intersect_dom(new_idom, p);
                    if (new_idom == UNDEF) break;
                }
            }
            if (new_idom != UNDEF && new_idom != idom[b]) {
                idom[b] = new_idom;
                dom_changed = true;
            }
        }
    }

    /* Helper: T domina B?  Camina la cadena idom desde B hasta entry o T. */
    auto dominates = [&](IrBlockId T, IrBlockId B) -> bool {
        if (T == B) return true;
        if (T >= N || B >= N || idom[B] == UNDEF) return false;
        IrBlockId cur = B;
        while (idom[cur] != cur) {
            cur = idom[cur];
            if (cur == T) return true;
        }
        return false;
    };

    /* Back-edge real: arista B->T donde T domina a B. */
    struct BackEdge {
        IrBlockId pred;
        IrBlockId header;
    };
    std::vector<BackEdge> backs;
    for (size_t b = 0; b < N; ++b) {
        for (IrBlockId s : succs[b]) {
            if (dominates(s, static_cast<IrBlockId>(b))) {
                backs.push_back({static_cast<IrBlockId>(b), s});
            }
        }
    }

    if (backs.empty()) return false;

    bool changed = false;

    /* Procesar cada back-edge (= 1 loop). */
    for (const auto &be : backs) {
        const IrBlockId header = be.header;
        const IrBlockId back = be.pred;

        /* Bloques en el loop: BFS reverse desde back hasta header via
         * preds (en CFG reducible). */
        std::unordered_set<IrBlockId> loop_set;
        loop_set.insert(header);
        loop_set.insert(back);
        std::vector<IrBlockId> stack{back};
        while (!stack.empty()) {
            IrBlockId b = stack.back();
            stack.pop_back();
            if (b == header) continue;
            for (IrBlockId p : preds[b]) {
                if (!loop_set.count(p)) {
                    loop_set.insert(p);
                    stack.push_back(p);
                }
            }
        }

        /* Pre-header: predecesor de @c header que NO esta en el loop.
         * Tipicamente entry o un bloque previo al while. */
        IrBlockId pre_header = IR_NO_BLOCK;
        for (IrBlockId p : preds[header]) {
            if (!loop_set.count(p)) {
                if (pre_header == IR_NO_BLOCK) {
                    pre_header = p;
                } else {
                    /* Multiples pre-headers: skip (necesita split). */
                    pre_header = IR_NO_BLOCK;
                    break;
                }
            }
        }
        if (pre_header == IR_NO_BLOCK) continue;

        /* Conjunto de VIDs definidos DENTRO del loop. */
        std::unordered_set<IrValueId> defined_in_loop;
        for (IrBlockId b : loop_set) {
            for (const auto &ins : fn.blocks[b].instrs) {
                if (ins.dst != IR_NO_VALUE) {
                    defined_in_loop.insert(ins.dst);
                }
            }
        }

        /* Detectar si hay STORE/MEMCPY/SETFIELD/ARRAY_STORE/RAW_ASM/CALL
         * dentro del loop.  Si los hay, los LOADs no son hoistables sin
         * alias analysis (la memoria pudo cambiar entre iteraciones). */
        bool loop_has_memory_writes = false; // modo clasico (crudo)
        // Modo alias-aware: en vez de un unico bool, colecciona las
        // localizaciones ESCRITAS por stores precisos del loop + una bandera de
        // escritura OPACA (call no-pura, memcpy, vec, raw_asm...).  Un load se
        // podra hoistar si ninguna store-loc lo aliasa y no hay escritura
        // opaca.
        bool loop_opaque_write = false;
        std::vector<analysis::effects::AbstractLoc> loop_store_locs;
        for (IrBlockId b : loop_set) {
            for (const auto &ins : fn.blocks[b].instrs) {
                // Las vectoriales que escriben memoria las decide
                // vec_op_writes_memory: son todas menos VEC_BCAST, que solo
                // reparte un escalar por los carriles de un registro.
                bool is_write = vec_op_writes_memory(ins.op);
                switch (ins.op) {
                case IrOp::STORE:
                case IrOp::MEMCPY:
                case IrOp::MEMSET:
                case IrOp::SETFIELD:
                case IrOp::ARRAY_STORE:
                case IrOp::STRFINALIZE:
                case IrOp::RAW_ASM:
                case IrOp::CALL:
                case IrOp::CALLN:
                case IrOp::CALLVIRT:
                case IrOp::CALLIND:
                case IrOp::CALLM:
                case IrOp::CALLITF:
                case IrOp::CALLCLOSURE:
                case IrOp::TAILCALL: is_write = true; break;
                default: break;
                }
                if (!is_write) continue;
                loop_has_memory_writes = true;
                if (licm_alias) {
                    // Vocabulario compartido memory_access: STORE/SETFIELD/
                    // ARRAY_STORE/MEMCPY + VEC data-ops dan write-locs
                    // localizables (16/32/64 en los vectoriales); VEC_ACC_*
                    // son opacas; los calls no son accesos de memory_access
                    // (su efecto lo da EffectAnalysis) -> pura=skip, else
                    // opaca.
                    const analysis::MemoryAccess ma =
                        analysis::memory_access(ins, *pt);
                    if (ma.touches) {
                        if (ma.opaque)
                            loop_opaque_write = true;
                        else
                            for (const auto &wloc : ma.writes) {
                                if (wloc.kind == analysis::effects::
                                                     AbstractLoc::Kind::Unknown)
                                    loop_opaque_write = true;
                                else
                                    loop_store_locs.push_back(wloc);
                            }
                    } else if (licm_is_pure_call(ins)) {
                        /* call PURA: no escribe memoria -> no aporta */
                    } else
                        loop_opaque_write =
                            true; // call no-pura / raw_asm / str
                }
                // Modo clasico: con una escritura basta.  Modo alias: seguir
                // acumulando (salvo que ya haya escritura opaca -> nada que
                // refinar).
                if (!licm_alias || loop_opaque_write) break;
            }
            if ((!licm_alias && loop_has_memory_writes) || loop_opaque_write)
                break;
        }

        /* Helper: instr es candidato para mover? */
        auto is_invariant_candidate = [&](const IrInstr &ins) -> bool {
            /* Sprint mem-perf string_hot: añadir STRMAKE/STRCAT/STRINTERN/
             * STRCONV/STRRESERVE como hoistables a pesar de side-effecting.
             * El alloc-identity no es observable; el contenido si.  Ver
             * @c is_licm_hoistable_alloc. */
            if (!is_pure(ins.op) && !is_licm_hoistable_alloc(ins.op))
                return false;
            if (ins.op == IrOp::PHI) return false;
            if (ins.preserve) return false;
            if (ins.dst == IR_NO_VALUE) return false;
            /* Sprint string-perf-2 bug fix: STRMAKE solo es seguro hoistar
             * si su vm_addr operand apunta a memoria immutable (literal
             * en static_data via STR_LIT_ADDR).  Para mutable buffers
             * (ALLOCA + stores), hoistar = capturar bytes en momento
             * incorrecto. */
            if (ins.op == IrOp::STRMAKE) {
                if (ins.operands.empty()) return false;
                if (!strmake_reads_immutable(fn, ins.operands[0])) return false;
            }
            /* Ops que LEEN memoria: solo hoistables si NO hay writes en el
             * loop (v1 sin alias analysis).  Conservador pero correcto. */
            switch (ins.op) {
            case IrOp::LOAD:
            case IrOp::ARRAY_LOAD:
            case IrOp::GETFIELD:
            case IrOp::ARRAY_LEN:
                if (licm_alias) {
                    // Alias-aware: hoistable si NINGUN store del loop puede
                    // aliasar este load y no hay escritura opaca.
                    if (loop_opaque_write) return false;
                    const analysis::MemoryAccess ma =
                        analysis::memory_access(ins, *pt);
                    for (const auto &rloc : ma.reads)
                        for (const auto &sloc : loop_store_locs)
                            if (analysis::effects::may_alias(rloc, sloc))
                                return false;
                } else {
                    if (loop_has_memory_writes) return false;
                }
                break;
            default: break;
            }
            /* Todos los operands deben ser invariant (CONST o definidos fuera).
             */
            for (IrValueId op : ins.operands) {
                if (op == IR_NO_VALUE) continue;
                if (defined_in_loop.count(op)) return false;
            }
            return true;
        };

        /* Recolectar instrucciones a mover (en orden) + remover de sus
         * bloques originales. */
        std::vector<IrInstr> moved;
        for (IrBlockId b : loop_set) {
            auto &bb = fn.blocks[b];
            std::vector<IrInstr> remaining;
            remaining.reserve(bb.instrs.size());
            for (auto &ins : bb.instrs) {
                if (is_invariant_candidate(ins)) {
                    /* Mover.  Despues de mover, el VID ya no esta
                     * definido en el loop -> otros usos del mismo
                     * VID dentro del loop necesitan que la def este
                     * en pre-header (ok, sera invariant alli). */
                    moved.push_back(std::move(ins));
                    defined_in_loop.erase(moved.back().dst);
                    changed = true;
                } else {
                    remaining.push_back(std::move(ins));
                }
            }
            bb.instrs = std::move(remaining);
        }

        if (moved.empty()) continue;

        /* Insertar las moved instrs al final del pre-header, ANTES de
         * su terminador (JMP a header). */
        auto &ph_bb = fn.blocks[pre_header];
        size_t insert_at = ph_bb.instrs.size();
        if (!ph_bb.instrs.empty()) {
            const auto &term = ph_bb.instrs.back();
            if (term.op == IrOp::BR || term.op == IrOp::BR_COND ||
                term.op == IrOp::RET || term.op == IrOp::THROW) {
                insert_at = ph_bb.instrs.size() - 1;
            }
        }
        ph_bb.instrs.insert(ph_bb.instrs.begin() + insert_at,
                            std::make_move_iterator(moved.begin()),
                            std::make_move_iterator(moved.end()));
    }

    return changed;
}

// =========================================================================
//  Pase ir_pass_devirt_monomorphic ( D.7.opt)
// =========================================================================

/**
 * @brief Detecta si el modulo usa AOP escaneando raw_asm por "addadvice".
 *
 * Conservador: si encuentra cualquier raw_asm con texto "addadvice", el
 * modulo se considera AOP-enabled y se skip-ea el devirt.  Sin esto las
 * callvirt convertidas a call directo saltarian el advice chain runtime.
 */
static bool module_has_unattributed_aop(const IrModule &mod) {
    /* Los aspectos declarados en Vesta SI se atribuyen: el frontend apunta a
     * que metodo va cada uno en @c advice_chains, y entonces basta con
     * saltarse esos sitios.  Lo que no se puede atribuir es un `addadvice`
     * escrito a mano en ensamblador: ahi no se sabe a quien apunta, asi que se
     * renuncia al pase entero, que es lo unico seguro. */
    for (const auto &fn : mod.functions) {
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op == IrOp::RAW_ASM &&
                    ins.func_name.find("addadvice") != std::string::npos) {
                    return true;
                }
            }
        }
    }
    return false;
}

// =========================================================================
//  Pase ir_pass_devirt_cfn
// =========================================================================
//
// Devirtualizacion de llamadas a PUNTERO A FUNCION crudo (cfn) constante.
// Si un CALLIND tiene su @c func_ptr definido por un LABEL_ADDR (la direccion
// cruda de una funcion conocida en compile-time), lo reescribimos a un CALL
// directo a esa funcion.  Beneficios:
//   - elimina la rama indirecta (callvmr -> callvm): mejor branch prediction.
//   - habilita el INLINER (ir_pass_inline solo procesa CALL directos), asi el
//     callback conocido se puede inlinar.
// La direccion fluye al call site tras mem2reg + copy_prop (el caso comun es
// `cfn c = &add1; c(x)` -> el func_ptr ES el LABEL_ADDR).  Propagamos tambien
// a traves de MOV por robustez.  La firma del cfn es solo compile-time; la
// convencion de llamada de CALL y CALLIND es identica (args en R1.., ret R0),
// asi que el rewrite preserva la semantica.
bool ir_pass_devirt_cfn(IrFunction &fn) {
    if (fn.is_native || fn.blocks.empty()) return false;
    // vid -> label de funcion (desde LABEL_ADDR, propagado por MOV).
    std::unordered_map<IrValueId, std::string> label_of;
    // Primero recolectar LABEL_ADDR; luego propagar por MOV en orden lineal.
    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            if (ins.dst == IR_NO_VALUE) continue;
            if (ins.op == IrOp::LABEL_ADDR && !ins.func_name.empty()) {
                label_of[ins.dst] = ins.func_name;
            } else if (ins.op == IrOp::MOV && !ins.operands.empty()) {
                auto it = label_of.find(ins.operands[0]);
                if (it != label_of.end()) label_of[ins.dst] = it->second;
            }
        }
    }
    if (label_of.empty()) return false;
    bool changed = false;
    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            if (ins.op != IrOp::CALLIND) continue;
            if (ins.func_ptr == IR_NO_VALUE) continue;
            auto it = label_of.find(ins.func_ptr);
            if (it == label_of.end()) continue;
            // Reescribir a CALL directo: func_name = label, sin func_ptr.
            ins.op = IrOp::CALL;
            ins.func_name = it->second;
            ins.func_ptr = IR_NO_VALUE;
            changed = true;
        }
    }
    return changed;
}

bool ir_pass_devirt_monomorphic(IrModule &mod) {
    /* Solo se renuncia al pase ENTERO cuando hay aspectos que no se pueden
     * atribuir a un metodo concreto -- hoy, un `addadvice` escrito a mano en
     * ensamblador, que no dice a quien apunta.  Cuando todos estan atribuidos,
     * cada sitio se mira por separado contra @c advice_chains.
     *
     * Renunciar por modulo salia caro y es el programa entero: medido en los
     * bancos de despacho, un aspecto que no tocaba ninguna de las clases del
     * programa costaba entre 1,2x y 9,5x. */
    if (!mod.all_advices_attributed || module_has_unattributed_aop(mod))
        return false;

    /* Indice por nombre de clase. */
    std::unordered_map<std::string, const IrClass *> class_by_name;
    for (const auto &c : mod.classes)
        class_by_name[c.name] = &c;
    if (class_by_name.empty()) return false;

    /* "Effectively final": clase sin subclases dentro del modulo.
     * Conservador (closed world).  El loadmodule dinamico podria
     * cargar una subclase, pero los tests/e2e no usan ese patron. */
    std::unordered_set<std::string> has_subclass;
    for (const auto &c : mod.classes) {
        if (!c.super_name.empty() && c.super_name != "Object") {
            has_subclass.insert(c.super_name);
        }
    }

    bool changed = false;
    for (auto &fn : mod.functions) {
        if (fn.is_native) continue;
        if (fn.blocks.empty()) continue;

        /* class_of: para cada SSA value cuyo origen es conocido como una
         * clase concreta, mapea vid -> class_name.  Se construye iterando
         * en orden lineal de bloques con propagacion a traves de MOV y
         * PHI (si todos los inputs comparten clase). */
        std::unordered_map<IrValueId, std::string> class_of;

        /* Multiples pasadas para propagar a traves de PHIs (loops). */
        const int MAX_ITERS = 4;
        for (int iter = 0; iter < MAX_ITERS; ++iter) {
            bool grew = false;
            for (auto &bb : fn.blocks) {
                for (auto &ins : bb.instrs) {
                    if (ins.dst == IR_NO_VALUE) continue;
                    if (class_of.count(ins.dst)) continue;

                    /* Origen: call @__new_<X> */
                    if (ins.op == IrOp::CALL &&
                        ins.func_name.rfind("__new_", 0) == 0) {
                        std::string cn = ins.func_name.substr(6);
                        if (class_by_name.count(cn)) {
                            class_of[ins.dst] = cn;
                            grew = true;
                        }
                        continue;
                    }
                    /* NEWOBJ no carga class_name directamente; ignorar. */
                    /* MOV: hereda clase del source */
                    if (ins.op == IrOp::MOV && !ins.operands.empty()) {
                        auto it = class_of.find(ins.operands[0]);
                        if (it != class_of.end()) {
                            class_of[ins.dst] = it->second;
                            grew = true;
                        }
                        continue;
                    }
                    /* PHI: si TODOS los inputs comparten clase, hereda. */
                    if (ins.op == IrOp::PHI && !ins.phi_args.empty()) {
                        std::string c;
                        bool ok = true;
                        for (const auto &pa : ins.phi_args) {
                            if (pa.value == IR_NO_VALUE || pa.value == ins.dst)
                                continue;
                            auto it = class_of.find(pa.value);
                            if (it == class_of.end()) {
                                ok = false;
                                break;
                            }
                            if (c.empty())
                                c = it->second;
                            else if (c != it->second) {
                                ok = false;
                                break;
                            }
                        }
                        if (ok && !c.empty()) {
                            class_of[ins.dst] = c;
                            grew = true;
                        }
                        continue;
                    }
                }
            }
            if (!grew) break;
        }

        /* Sitios cuyo objetivo lleva aspectos: en vez de renunciar a
         * optimizarlos, se TEJE la cadena aqui (ver mas abajo).  Se apuntan y
         * se aplican despues porque tejer INSERTA instrucciones, y hacerlo
         * mientras se recorre el bloque invalidaria el recorrido. */
        struct WeaveSite {
            size_t block;
            size_t instr;
            std::string target;
        };
        std::vector<WeaveSite> to_weave;

        /* Aplicar devirt. */
        for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
            auto &bb = fn.blocks[bi];
            for (size_t ii = 0; ii < bb.instrs.size(); ++ii) {
                auto &ins = bb.instrs[ii];
                if (ins.op != IrOp::CALLVIRT) continue;
                if (ins.operands.empty()) continue;
                auto it = class_of.find(ins.operands[0]);
                if (it == class_of.end()) continue;
                const std::string &cn = it->second;
                auto ct = class_by_name.find(cn);
                if (ct == class_by_name.end()) continue;
                const IrClass *cls = ct->second;
                /* Safe: clase final O sin subclases EN ESTE MODULO. */
                const bool safe_class =
                    cls->is_final || !has_subclass.count(cn);
                /* Buscar el metodo en el vtable_index. */
                const IrMethod *mtd = nullptr;
                for (const auto &m : cls->methods) {
                    if (m.vtable_index == static_cast<int32_t>(ins.imm)) {
                        mtd = &m;
                        break;
                    }
                }
                if (!mtd) continue;
                if (mtd->ir_fn_name.empty()) continue;
                const bool safe_method = mtd->is_final || safe_class;
                if (!safe_method) continue;

                /* Un metodo con aspectos se despacha recorriendo su cadena, asi
                 * que llamarlo directo se los saltaria.  Pero aqui se sabe QUE
                 * cadena es, y el receptor tambien: en vez de renunciar, se
                 * apunta para tejerla. */
                if (mod.advice_chains.count(mtd->ir_fn_name) != 0) {
                    to_weave.push_back({bi, ii, mtd->ir_fn_name});
                    continue;
                }

                /* Rewrite CALLVIRT -> CALL */
                ins.op = IrOp::CALL;
                ins.func_name = mtd->ir_fn_name;
                ins.imm = 0;
                /* operands sin cambio: [obj, args...] */
                changed = true;
            }
        }

        /* TEJER la cadena en el sitio de llamada.
         *
         * Donde se conoce el receptor se conoce el despacho entero, asi que en
         * vez de dejar el `callvirt` -- que recorreria la cadena en ejecucion,
         * un marco por paso -- se emite la secuencia:
         *
         *     call before_1(obj, args...)      ; su valor se descarta
         *     ...
         *     r = call m_slot(obj, args...)    ; el @Around mas externo, o el
         *                                      ; metodo si no hay ninguno
         *     r = call after_1(obj, args...)   ; recibe los args ORIGINALES y
         *     ...                              ; su retorno REEMPLAZA
         *     r = call after_ret(obj, r, ...)  ; este recibe el RESULTADO
         *
         * Los `@Around` interiores NO van en la secuencia: al mas externo se
         * llega directo y el encadena con los suyos por su `proceed`, que ya se
         * emite como llamada (ver @c Lowering::emit_proceed).
         *
         * Todo son llamadas directas, asi que el inliner se las come.  La
         * semantica que se reproduce esta fijada en los ejemplos 379, 380 y
         * 381.
         *
         * Los sitios con receptor DESCONOCIDO siguen por el `callvirt` y su
         * cadena en ejecucion, que se sigue registrando: es lo que hara falta
         * el dia que los advices se puedan anadir o alterar sobre la marcha.  Y
         * este es el unico punto que habria que revisar entonces, el mismo que
         * la devirtualizacion de arriba. */
        for (size_t k = to_weave.size(); k-- > 0;) {
            const WeaveSite &s = to_weave[k];
            auto itc = mod.advice_chains.find(s.target);
            if (itc == mod.advice_chains.end()) continue;
            const auto &chain = itc->second;
            if (chain.empty()) continue;
            auto &instrs = fn.blocks[s.block].instrs;
            if (s.instr >= instrs.size()) continue;
            const IrInstr orig = instrs[s.instr]; // copia: se va a sustituir

            /* El paso central: el `@Around` mas externo, o el metodo. */
            std::string m_slot = s.target;
            for (const auto &a : chain)
                if (a.kind == loader::ADVICE_AROUND) {
                    m_slot = a.method_ir_name;
                    break;
                }

            std::vector<IrInstr> woven;
            auto emit_call = [&](const std::string &callee,
                                 std::vector<IrValueId> ops, IrValueId dst) {
                IrInstr c{};
                c.op = IrOp::CALL;
                c.type = orig.type;
                c.dst = dst;
                c.func_name = callee;
                c.operands = std::move(ops);
                c.is_call_site = true;
                c.source_line = orig.source_line;
                woven.push_back(std::move(c));
            };

            for (const auto &a : chain)
                if (a.kind == loader::ADVICE_BEFORE)
                    emit_call(a.method_ir_name, orig.operands,
                              fn.new_value(orig.type));

            IrValueId r = fn.new_value(orig.type);
            emit_call(m_slot, orig.operands, r);

            for (const auto &a : chain) {
                if (a.kind != loader::ADVICE_AFTER &&
                    a.kind != loader::ADVICE_AFTER_RETURNING)
                    continue;
                std::vector<IrValueId> ops = orig.operands;
                /* `@AfterReturning` recibe el RESULTADO en el sitio del primer
                 * argumento declarado; un `@After` a secas ve los originales.
                 */
                if (a.kind == loader::ADVICE_AFTER_RETURNING) {
                    if (ops.size() >= 2)
                        ops[1] = r;
                    else
                        ops.push_back(r);
                }
                const IrValueId r2 = fn.new_value(orig.type);
                emit_call(a.method_ir_name, std::move(ops), r2);
                r = r2;
            }

            /* Lo que la llamada original dejaba, lo deja ahora el ultimo paso.
             */
            if (orig.dst != IR_NO_VALUE) woven.back().dst = orig.dst;

            instrs.erase(instrs.begin() + static_cast<long>(s.instr));
            instrs.insert(instrs.begin() + static_cast<long>(s.instr),
                          woven.begin(), woven.end());
            changed = true;
        }
    }
    return changed;
}

// =========================================================================
//  Pase ir_pass_speculative_devirt (C2): devirt especulativa guiada por IC
// =========================================================================

bool ir_pass_speculative_devirt(IrFunction &fn,
                                const std::vector<SpecDevirtSite> &sites) {
    if (fn.blocks.empty() || sites.empty()) return false;
    bool changed = false;

    /* Reservar de antemano para evitar realocaciones de fn.blocks durante la
     * cirugia (3 bloques nuevos por site).  Aun asi accedemos por INDICE, no
     * por referencia, por seguridad. */
    fn.blocks.reserve(fn.blocks.size() + sites.size() * 3 + 4);

    for (const auto &site : sites) {
        if (site.callvirt_dst == IR_NO_VALUE) continue; /* void: sin PHI */

        /* Localizar el CALLVIRT objetivo por su dst (unico + estable). */
        IrBlockId bidx = IR_NO_BLOCK;
        size_t i = 0;
        for (size_t b = 0; b < fn.blocks.size() && bidx == IR_NO_BLOCK; ++b) {
            auto &bb = fn.blocks[b];
            for (size_t k = 0; k < bb.instrs.size(); ++k) {
                if (bb.instrs[k].op == IrOp::CALLVIRT &&
                    bb.instrs[k].dst == site.callvirt_dst) {
                    bidx = static_cast<IrBlockId>(b);
                    i = k;
                    break;
                }
            }
        }
        if (bidx == IR_NO_BLOCK) continue; /* no encontrado: skip */

        /* Capturar datos del CALLVIRT (copia) antes de la cirugia. */
        const IrInstr cv = fn.blocks[bidx].instrs[i];
        const IrType rtype = cv.type;
        const IrValueId orig_dst = cv.dst;
        const std::vector<IrValueId> ops = cv.operands; /* [obj, args...] */
        const uint32_t srcline = cv.source_line;
        if (ops.empty()) continue; /* sin receptor: no especulable */

        /* Capturar los sucesores ORIGINALES de B (los del terminador que va
         * en el tail) antes de sobreescribir B.succs. */
        const std::vector<IrBlockId> orig_succs = fn.blocks[bidx].succs;

        /* Crear los 3 bloques (append; los indices existentes no se mueven). */
        const IrBlockId fastb = fn.new_block("spec_fast");
        const IrBlockId slowb = fn.new_block("spec_slow");
        const IrBlockId mergeb = fn.new_block("spec_merge");

        /* Mover el tail [i+1 ..] al merge; truncar B a [0 .. i-1]. */
        {
            auto &Binstrs = fn.blocks[bidx].instrs;
            std::vector<IrInstr> tail(
                Binstrs.begin() + static_cast<long>(i) + 1, Binstrs.end());
            fn.blocks[mergeb].instrs = std::move(tail);
            Binstrs.resize(i); /* descarta el CALLVIRT en i + el tail */
        }

        /* --- Guard en B: cls = load[obj]; cmp cls, T; br_cond fast/slow --- */
        const IrValueId vcls = fn.new_value(IrType::I64, "spec_cls");
        {
            IrInstr ld;
            ld.op = IrOp::LOAD;
            ld.type = IrType::I64;
            ld.dst = vcls;
            ld.operands = {ops[0]};
            ld.source_line = srcline;
            fn.blocks[bidx].instrs.push_back(ld);
        }
        const IrValueId vt = fn.new_value(IrType::I64, "spec_T");
        {
            IrInstr c;
            c.op = IrOp::CONST;
            c.type = IrType::I64;
            c.dst = vt;
            c.imm = site.class_ptr;
            c.source_line = srcline;
            fn.blocks[bidx].instrs.push_back(c);
        }
        const IrValueId vg = fn.new_value(IrType::BOOL, "spec_g");
        {
            IrInstr cm;
            cm.op = IrOp::CMP_EQ;
            cm.type = IrType::BOOL;
            cm.dst = vg;
            cm.operands = {vcls, vt};
            cm.source_line = srcline;
            fn.blocks[bidx].instrs.push_back(cm);
        }
        {
            IrInstr br;
            br.op = IrOp::BR_COND;
            br.operands = {vg};
            br.target_block = fastb;
            br.false_block = slowb;
            br.source_line = srcline;
            fn.blocks[bidx].instrs.push_back(br);
        }
        fn.blocks[bidx].succs = {fastb, slowb};

        /* --- Fast: CALL directo al callee (ir_pass_inline lo inlinea). --- */
        const IrValueId rfast = fn.new_value(rtype, "spec_rfast");
        {
            IrInstr call;
            call.op = IrOp::CALL;
            call.type = rtype;
            call.dst = rfast;
            call.func_name = site.callee_ir_name;
            call.operands = ops;
            call.source_line = srcline;
            fn.blocks[fastb].instrs.push_back(call);
        }
        {
            IrInstr br;
            br.op = IrOp::BR;
            br.target_block = mergeb;
            fn.blocks[fastb].instrs.push_back(br);
        }
        fn.blocks[fastb].preds = {bidx};
        fn.blocks[fastb].succs = {mergeb};

        /* --- Slow: CALLVIRT original (copia) -> r_slow. --- */
        const IrValueId rslow = fn.new_value(rtype, "spec_rslow");
        {
            IrInstr cv2 = cv;
            cv2.dst = rslow;
            fn.blocks[slowb].instrs.push_back(cv2);
        }
        {
            IrInstr br;
            br.op = IrOp::BR;
            br.target_block = mergeb;
            fn.blocks[slowb].instrs.push_back(br);
        }
        fn.blocks[slowb].preds = {bidx};
        fn.blocks[slowb].succs = {mergeb};

        /* --- Merge: PHI(orig_dst) = [r_fast@fast, r_slow@slow] + tail. --- */
        {
            IrInstr phi;
            phi.op = IrOp::PHI;
            phi.type = rtype;
            phi.dst = orig_dst;
            phi.phi_args = {IrPhiArg{rfast, fastb}, IrPhiArg{rslow, slowb}};
            phi.source_line = srcline;
            fn.blocks[mergeb].instrs.insert(fn.blocks[mergeb].instrs.begin(),
                                            phi);
        }
        fn.blocks[mergeb].preds = {fastb, slowb};
        fn.blocks[mergeb].succs = orig_succs;

        /* Repuntar los sucesores originales de B: ahora su predecesor es
         * merge (el terminador del tail vive ahi).  Tambien sus PHIs. */
        for (IrBlockId s : orig_succs) {
            if (s == IR_NO_BLOCK || s >= fn.blocks.size()) continue;
            auto &sb = fn.blocks[s];
            for (auto &p : sb.preds)
                if (p == bidx) p = mergeb;
            for (auto &ins : sb.instrs) {
                if (ins.op != IrOp::PHI) continue;
                for (auto &pa : ins.phi_args)
                    if (pa.block == bidx) pa.block = mergeb;
            }
        }

        changed = true;
    }

    return changed;
}

// =========================================================================
//  Pase ir_pass_spec_devirt (TAREA 2 / C2): devirt especulativa ESTATICA
//  via guard-chain de K candidatos + fallback al dispatch original.
// =========================================================================

// Reordena los bloques de la funcion a Reverse Post-Order (RPO) desde el
// entry (bloque 0), siguiendo los sucesores derivados de los terminadores.
// Necesario tras la cirugia de spec_devirt: esta crea bloques (guards/fast/
// fallback/merge) en orden de procesamiento de los sites (un unordered_map,
// no determinista), dejando el array de bloques en orden NO topologico.  El
// emisor de bytecode + su regalloc/liveness asumen orden ~control-flow (p.ej.
// el fall-through a `bid+1` y la liveness lineal), por lo que un orden mezclado
// producia codigo incorrecto (resultados que aliasaban entre sites) y no
// determinista.  RPO da el orden canonico y deterministico (independiente del
// orden de iteracion del map).  El path JIT/vreg ya lo toleraba; esto arregla
// el interprete.
static void reorder_blocks_rpo(IrFunction &fn) {
    const size_t N = fn.blocks.size();
    if (N <= 1) return;
    /* Los sucesores salen de `sucesores_de`, que ya incluye la arista implicita
     * del LABEL_ADDR al handler de un try/catch.  Sin esa arista el handler
     * queda inalcanzable en el recorrido y el orden inverso lo empuja AL
     * PRINCIPIO, desplazando al bloque de entrada de la posicion 0 -- se
     * empezaria a ejecutar por el bloque equivocado. */
    const std::unordered_map<std::string, IrBlockId> name2id =
        bloques_por_nombre(fn);
    auto succs_of = [&](size_t b, std::vector<IrBlockId> &out) {
        sucesores_de(fn, name2id, b, out);
    };
    std::vector<std::vector<IrBlockId>> sc(N);
    for (size_t b = 0; b < N; ++b)
        succs_of(b, sc[b]);
    std::vector<int> state(N, 0); // 0=sin visitar, 1=en pila, 2=hecho
    std::vector<IrBlockId> post;
    post.reserve(N);
    std::vector<std::pair<size_t, size_t>> stk; // (bloque, indice de sucesor)
    stk.push_back({0, 0});
    state[0] = 1;
    while (!stk.empty()) {
        auto &top = stk.back();
        if (top.second < sc[top.first].size()) {
            const IrBlockId s = sc[top.first][top.second++];
            if (s < N && state[s] == 0) {
                state[s] = 1;
                stk.push_back({static_cast<size_t>(s), 0});
            }
        } else {
            post.push_back(static_cast<IrBlockId>(top.first));
            state[top.first] = 2;
            stk.pop_back();
        }
    }
    // Nuevo orden fisico: RPO de los ALCANZABLES (= reverse del post-order,
    // deja el entry SIEMPRE en la posicion 0) seguido de los bloques no
    // alcanzables al FINAL.  Antes se hacia post.push_back(inalcanzable) y
    // luego reverse(post) -> los inalcanzables quedaban AL PRINCIPIO,
    // desplazando el entry de la posicion 0 (el interprete/emisor arrancaban
    // por el bloque equivocado -> resultados corruptos en funciones con
    // cualquier bloque que succs_of no alcanzara).
    std::vector<IrBlockId> order;
    order.reserve(N);
    for (size_t i = 0; i < post.size(); ++i)
        order.push_back(post[post.size() - 1 - i]);
    size_t unreachable = 0;
    for (size_t b = 0; b < N; ++b)
        if (state[b] != 2) {
            order.push_back(static_cast<IrBlockId>(b));
            ++unreachable;
        }
    std::vector<IrBlockId> remap(N, IR_NO_BLOCK);
    for (size_t i = 0; i < order.size(); ++i)
        remap[order[i]] = static_cast<IrBlockId>(i);
    static const bool rpo_dump = util::flag_on(util::FlagId::RpoDump);
    if (rpo_dump)
        std::fprintf(stderr, "[rpo] %s: N=%zu inalcanzables=%zu entry->%u\n",
                     fn.name.c_str(), N, unreachable,
                     static_cast<unsigned>(remap[0]));
    bool identity = true;
    for (size_t b = 0; b < N; ++b)
        if (remap[b] != static_cast<IrBlockId>(b)) {
            identity = false;
            break;
        }
    if (identity) return; // ya esta en RPO
    std::vector<IrBlock> nb(N);
    for (size_t b = 0; b < N; ++b) {
        IrBlock bb = std::move(fn.blocks[b]);
        bb.id = remap[b];
        for (auto &p : bb.preds)
            if (p < N) p = remap[p];
        for (auto &s : bb.succs)
            if (s < N) s = remap[s];
        for (auto &ins : bb.instrs) {
            if (ins.target_block != IR_NO_BLOCK && ins.target_block < N)
                ins.target_block = remap[ins.target_block];
            if (ins.false_block != IR_NO_BLOCK && ins.false_block < N)
                ins.false_block = remap[ins.false_block];
            /* Remapear tambien los destinos del SWITCH_DENSE: sin esto, aun
             * con el DFS corregido, los jump_targets[] apuntaban a indices de
             * bloque VIEJOS tras el reorden -> saltos a bloques equivocados. */
            for (auto &jt : ins.jump_targets)
                if (jt != IR_NO_BLOCK && jt < N) jt = remap[jt];
            for (auto &pa : ins.phi_args)
                if (pa.block < N) pa.block = remap[pa.block];
        }
        nb[remap[b]] = std::move(bb);
    }
    fn.blocks = std::move(nb);
}

// =========================================================================
//  Pase ir_pass_inline_multiblock: inline de callees MULTI-bloque (con `if`,
//  loops sin back-edge propio, etc.) que el inliner single-block rechaza.
//  Cirugia de CFG identica en espiritu a spec_devirt: split del bloque caller
//  en el CALL, insertar copia de los bloques del callee (valores + block-ids
//  remapeados), cada RET -> BR al merge + PHI del resultado, repuntar los
//  sucesores originales, recomputar preds/succs y reordenar a RPO.
//  Semantica-preservante (no toca objetos ni scalar-replace); habilita inlinar
//  metodos/funciones pequenas con ramas.  Gated por VESTA_NO_MB_INLINE.
// =========================================================================

// Recomputa preds/succs de TODA la funcion desde los terminadores (robusto
// tras cirugia de CFG; evita bugs de mantenimiento manual).
/* Las aristas las rehace la propia funcion (@c IrFunction::recompute_edges):
 * son informacion derivada del terminador y tenerlas escritas dos veces es
 * tener dos respuestas a la misma pregunta en cuanto una se quede atras. */
static void recompute_preds_succs(IrFunction &fn) {
    fn.recompute_edges();
}

// Inlinea el callee MULTI-bloque en caller.blocks[bi].instrs[ii] (un CALL).
static void inline_one_multiblock(IrFunction &caller, size_t bi, size_t ii,
                                  const IrFunction &callee) {
    caller.blocks.reserve(caller.blocks.size() + callee.blocks.size() + 2);
    const IrInstr call = caller.blocks[bi].instrs[ii]; // copia
    const IrValueId call_dst = call.dst;
    const IrType ret_type = call.type;
    const uint32_t srcline = call.source_line;
    /* Constancia de la llamada que se aplana (ver inline_note_site). */
    uint32_t sitio_base = 0;
    const uint32_t sitio = inline_note_site(caller, callee, call, sitio_base);

    // --- remap de valores: params -> args; resto -> fresh (copia atributos)
    // ---
    std::unordered_map<IrValueId, IrValueId> vmap;
    for (size_t p = 0; p < callee.params.size() && p < call.operands.size();
         ++p)
        vmap[callee.params[p]] = call.operands[p];
    for (size_t v = 0; v < callee.values.size(); ++v) {
        if (vmap.count(static_cast<IrValueId>(v))) continue;
        const IrValue &cv = callee.values[v];
        const IrValueId nv = caller.new_value(cv.type, "");
        IrValue &dv = caller.values[nv];
        dv.is_const = cv.is_const;
        dv.const_val = cv.const_val;
        dv.is_host_ptr = cv.is_host_ptr;
        dv.pointee_is_host_ptr = cv.pointee_is_host_ptr;
        dv.is_gc_object = cv.is_gc_object;
        dv.narrow_only = cv.narrow_only;
        vmap[static_cast<IrValueId>(v)] = nv;
    }
    auto rv = [&](IrValueId v) -> IrValueId {
        if (v == IR_NO_VALUE) return v;
        auto it = vmap.find(v);
        return it != vmap.end() ? it->second : v;
    };

    // --- remap de bloques: cada bloque del callee -> nuevo bloque del caller
    // ---
    std::unordered_map<IrBlockId, IrBlockId> bmap;
    std::vector<IrBlockId> copy_ids;
    copy_ids.reserve(callee.blocks.size());
    for (size_t k = 0; k < callee.blocks.size(); ++k) {
        const IrBlockId nb = caller.new_block("inl_" + callee.blocks[k].name);
        bmap[callee.blocks[k].id] = nb;
        copy_ids.push_back(nb);
    }
    const IrBlockId mergeb = caller.new_block("inl_merge");
    auto rb = [&](IrBlockId b) -> IrBlockId {
        auto it = bmap.find(b);
        return it != bmap.end() ? it->second : b;
    };

    // --- capturar succs originales + mover el tail [ii+1..] al merge ---
    const std::vector<IrBlockId> orig_succs = caller.blocks[bi].succs;
    {
        auto &Bi = caller.blocks[bi].instrs;
        std::vector<IrInstr> tail(Bi.begin() + static_cast<long>(ii) + 1,
                                  Bi.end());
        caller.blocks[mergeb].instrs = std::move(tail);
        Bi.resize(ii); // descarta el CALL + el tail
    }

    // --- copiar los bloques del callee (remap valores + block-refs) ---
    std::vector<IrPhiArg> ret_args;
    for (size_t k = 0; k < callee.blocks.size(); ++k) {
        const IrBlock &cb = callee.blocks[k];
        const IrBlockId nbid = copy_ids[k];
        for (IrInstr in : cb.instrs) {
            // copia por valor
            in.inline_site = inline_map_site(in.inline_site, sitio, sitio_base);
            if (in.op == IrOp::RET) {
                if (call_dst != IR_NO_VALUE && !in.operands.empty())
                    ret_args.push_back(IrPhiArg{rv(in.operands[0]), nbid});
                IrInstr br{};
                br.op = IrOp::BR;
                br.target_block = mergeb;
                br.source_line = in.source_line;
                caller.blocks[nbid].instrs.push_back(std::move(br));
                continue;
            }
            in.dst = rv(in.dst);
            for (auto &op : in.operands)
                op = rv(op);
            if (in.func_ptr != IR_NO_VALUE) in.func_ptr = rv(in.func_ptr);
            for (auto &pa : in.phi_args) {
                pa.value = rv(pa.value);
                pa.block = rb(pa.block);
            }
            if (in.target_block != IR_NO_BLOCK)
                in.target_block = rb(in.target_block);
            if (in.false_block != IR_NO_BLOCK)
                in.false_block = rb(in.false_block);
            /* La FICHA de un micro asm se muda con el.
             *
             * `imm` no es un numero: indexa la tabla de fichas de SU funcion,
             * de donde salen todos sus efectos.  Al traer la instruccion sin la
             * ficha, el indice apunta a la tabla del que la recibe -- fuera de
             * rango o, peor, a la ficha de otra instruccion --.  El inlinador
             * de un solo bloque ya lo hacia; este no, asi que un `asm` liftado
             * que cruzara un inline multi-bloque perdia su identidad y el
             * compilador nativo abandonaba la funcion entera sin decir por que.
             *
             * Lo mismo que el resto: los SSA de la ficha se remapean con `rv`.
             */
            if (in.op == IrOp::ASM_MICRO) {
                const uint32_t viejo = static_cast<uint32_t>(in.imm);
                const uint32_t nuevo =
                    static_cast<uint32_t>(caller.asm_micros.size());
                if (viejo < callee.asm_micros.size()) {
                    ir::AsmMicro am = callee.asm_micros[viejo];
                    for (auto &op : am.operands)
                        op.value = rv(op.value);
                    caller.asm_micros.push_back(std::move(am));
                } else {
                    caller.asm_micros.emplace_back();
                }
                in.imm = nuevo;
            }
            caller.blocks[nbid].instrs.push_back(std::move(in));
        }
    }

    // --- B salta a la entry del callee copiado ---
    {
        IrInstr br{};
        br.op = IrOp::BR;
        br.target_block = copy_ids[0];
        br.source_line = srcline;
        caller.blocks[bi].instrs.push_back(std::move(br));
    }

    // --- merge: PHI(call_dst) = ret_args (al inicio) + tail (ya movido) ---
    if (call_dst != IR_NO_VALUE && !ret_args.empty()) {
        IrInstr phi{};
        phi.op = IrOp::PHI;
        phi.type = ret_type;
        phi.dst = call_dst;
        phi.phi_args = std::move(ret_args);
        phi.source_line = srcline;
        caller.blocks[mergeb].instrs.insert(
            caller.blocks[mergeb].instrs.begin(), std::move(phi));
    }

    // --- repuntar los succs originales: pred bi -> mergeb (PHIs incluidas) ---
    for (IrBlockId s : orig_succs) {
        if (s == IR_NO_BLOCK || s >= caller.blocks.size()) continue;
        for (auto &in : caller.blocks[s].instrs) {
            if (in.op != IrOp::PHI) continue;
            for (auto &pa : in.phi_args)
                if (pa.block == static_cast<IrBlockId>(bi)) pa.block = mergeb;
        }
    }

    recompute_preds_succs(caller);
}

// true si el callee multi-bloque es seguro de inlinar.
static bool is_inlineable_mb(const IrFunction &fn, size_t threshold) {
    if (fn.is_native) return false;
    if (fn.is_naked)
        return false; // @Naked: sin prologo/epilogo/ret, standalone
    if (!fn.section.empty()) return false;
    if (fn.blocks.empty()) return false;
    // Por prefijo: cubre tambien las tandas y las de las dependencias (ver
    // @c is_blacklisted).
    if (fn.name.rfind("__module_init", 0) == 0) return false;
    if (fn.name.rfind("__lambda", 0) == 0) return false;
    if (is_new_helper_name(fn.name, nullptr)) return false;
    /* Resolvedores de overlay: inlinarlos pierde la naturaleza host de la
     * direccion del campo -> `mov`/`loadz` (VM) en vez de `movh`/`loadzh`
     * (host).  Mantener como CALL (mismo motivo que en @c is_inlineable). */
    if (fn.name.rfind("__ovl_resolve_", 0) == 0) return false;
    size_t total = 0;
    bool has_ret = false;
    for (size_t k = 0; k < fn.blocks.size(); ++k) {
        const IrBlock &b = fn.blocks[k];
        if (b.instrs.empty()) return false;
        total += b.instrs.size();
        const IrInstr &last = b.instrs.back();
        if (last.op != IrOp::BR && last.op != IrOp::BR_COND &&
            last.op != IrOp::RET)
            return false; // bloque sin terminador limpio
        if (last.op == IrOp::RET) has_ret = true;
        for (const auto &in : b.instrs) {
            if ((in.op == IrOp::CALL || in.op == IrOp::TAILCALL) &&
                in.func_name == fn.name)
                return false; // recursion
            if (in.op == IrOp::RAW_ASM || in.op == IrOp::INLINE_ASM)
                return false;
            if (in.op == IrOp::SWITCH_DENSE || !in.jump_targets.empty())
                return false; // jump tables: no soportado v1
            // ALLOCA: inlinar una fn con ALLOCA dentro de un loop del caller
            // crece la pila monotonicamente (bug P0.6).  El single-block
            // inliner ya lo rechaza; replicamos aqui.
            if (in.op == IrOp::ALLOCA) return false;
            // Cleanup RAII / liberacion explicita: inlinar una fn que libera
            // recursos (dtor via CALLVIRT, free) puede duplicar/reordenar el
            // cleanup respecto al modelo de scope del caller -> resultado
            // incorrecto (visto en 101_raii).  Conservador: no inlinar.
            if (in.op == IrOp::RAW_FREE || in.op == IrOp::SMARTPTR_FREE)
                return false;
            // Ops con semantica de FRAME/scope/runtime que inlinar puede
            // romper (anidamiento de exception frames, save_live_regs del GC,
            // registros de reflexion ligados al scope, dispatch dinamico):
            // conservador, no inlinar el callee que las contenga.  En
            // particular la CREACION de objetos (NEWOBJ/__new_X) + dtor
            // (CALLVIRT) DENTRO de un callee con loop rompia el save_live_regs
            // del GC al inlinarse (101_raii caso_6).  Esto sigue permitiendo
            // inlinar metodos PUROS (getters/setters/operadores field-only) que
            // es el objetivo del bucket method-call.
            switch (in.op) {
            case IrOp::THROW:
            case IrOp::TRYENTER:
            case IrOp::TRYLEAVE:
            case IrOp::RETHROW:
            case IrOp::FINDCLASS:
            case IrOp::REFLECT_COUNT:
            case IrOp::REFLECT_AT:
            case IrOp::NEWOBJ:
            case IrOp::NEWOBJS:
            case IrOp::GC_ALLOC:
            case IrOp::GC_ALLOCP:
            case IrOp::CALLVIRT:
            case IrOp::CALLM:
            case IrOp::CALLITF: return false;
            default: break;
            }
            // CALL a un helper __new_X (constructor de objeto): misma razon.
            if (in.op == IrOp::CALL &&
                is_new_helper_name(in.func_name, nullptr))
                return false;
            if (k == 0 && in.op == IrOp::PHI) return false; // entry con PHI
        }
    }
    if (!has_ret) return false;
    // Single-block <=12: ya lo cubre el inliner single-block (threshold 12).
    // El MB inliner rellena el GAP: single-block 13..threshold (metodos puros
    // que el single-block rechaza por tamano, p.ej. operadores `__add__`) +
    // cualquier multi-bloque <=threshold.
    if (fn.blocks.size() == 1 && total <= 12) return false;
    return total <= threshold;
}

bool ir_pass_inline_multiblock(IrModule &mod, size_t threshold) {
    // Activo por defecto.  Desactivable con VESTA_NO_MB_INLINE=1 (A/B).
    // El guard de is_inlineable_mb rechaza callees con NEWOBJ/__new_X/CALLVIRT
    // (creacion de objetos + dtor en loop rompia el save_live_regs del GC) +
    // ALLOCA/free/excepciones/reflexion, dejando solo metodos/funciones PUROS
    // (compute + field-access) que es donde el inline multi-bloque aporta.
    static const bool mb_off = util::flag_on(util::FlagId::NoMbInline);
    if (mb_off) return false;
    std::unordered_map<std::string, size_t> name_to_idx;
    for (size_t i = 0; i < mod.functions.size(); ++i)
        name_to_idx[mod.functions[i].name] = i;
    /* Con variantes por motor (@Target("mode:jit")) la eleccion la hace el JIT
     * al compilar la funcion; inlinarla la deja COCIDA en el llamante y el
     * codigo del interprete acabaria corriendo tambien en JIT.  Se reconoce
     * por el nombre -- la del JIT lleva sufijo -- que es el mismo contrato que
     * usa el JIT al elegir. */
    auto tiene_variante_por_motor = [&](const std::string &nombre) -> bool {
        return name_to_idx.count(nombre + "__jit") != 0;
    };
    std::vector<bool> ok(mod.functions.size(), false);
    for (size_t i = 0; i < mod.functions.size(); ++i)
        ok[i] = is_inlineable_mb(mod.functions[i], threshold) &&
                !tiene_variante_por_motor(mod.functions[i].name);

    bool any = false;
    for (size_t fi = 0; fi < mod.functions.size(); ++fi) {
        IrFunction &caller = mod.functions[fi];
        if (caller.is_native) continue;
        bool changed = false;
        int cap = 128; // backstop anti-runaway
        bool found = true;
        while (found && cap-- > 0) {
            found = false;
            for (size_t bi = 0; bi < caller.blocks.size() && !found; ++bi)
                for (size_t ii = 0; ii < caller.blocks[bi].instrs.size();
                     ++ii) {
                    const IrInstr &in = caller.blocks[bi].instrs[ii];
                    if (in.op != IrOp::CALL) continue;
                    auto it = name_to_idx.find(in.func_name);
                    if (it == name_to_idx.end() || it->second == fi ||
                        !ok[it->second])
                        continue;
                    const IrFunction &callee = mod.functions[it->second];
                    if (callee.params.size() != in.operands.size()) continue;
                    inline_one_multiblock(caller, bi, ii, callee);
                    found = true;
                    changed = true;
                    any = true;
                    break;
                }
        }
        if (changed) reorder_blocks_rpo(caller);
    }
    return any;
}

bool ir_pass_spec_devirt(IrFunction &fn) {
    if (fn.blocks.empty() || fn.spec_devirt_sites.empty()) return false;
    bool changed = false;

    /* Reservar de antemano espacio para los bloques nuevos (2K+1 por site:
     * K fast + K-1 guard + 1 fallback + 1 merge) para evitar realocaciones de
     * fn.blocks durante la cirugia.  Accedemos por INDICE igualmente. */
    size_t extra = 4;
    for (const auto &kv : fn.spec_devirt_sites)
        extra += kv.second.size() * 2 + 1;
    fn.blocks.reserve(fn.blocks.size() + extra);

    for (const auto &kv : fn.spec_devirt_sites) {
        const IrValueId site_dst = kv.first;
        const std::vector<DevirtCandidate> &cands = kv.second;
        if (site_dst == IR_NO_VALUE || cands.empty()) continue; /* void: skip */

        /* Localizar el call dinamico objetivo por su dst (unico + estable). */
        IrBlockId bidx = IR_NO_BLOCK;
        size_t i = 0;
        IrOp callop = IrOp::NOP;
        for (size_t b = 0; b < fn.blocks.size() && bidx == IR_NO_BLOCK; ++b) {
            auto &bb = fn.blocks[b];
            for (size_t k = 0; k < bb.instrs.size(); ++k) {
                const IrOp o = bb.instrs[k].op;
                if ((o == IrOp::CALLITF || o == IrOp::CALLVIRT ||
                     o == IrOp::CALLM) &&
                    bb.instrs[k].dst == site_dst) {
                    bidx = static_cast<IrBlockId>(b);
                    i = k;
                    callop = o;
                    break;
                }
            }
        }
        if (bidx == IR_NO_BLOCK) continue; /* no encontrado: skip */

        /* Capturar datos del call (copia) antes de la cirugia. */
        const IrInstr callins = fn.blocks[bidx].instrs[i];
        const IrType rtype = callins.type;
        const IrValueId orig_dst = callins.dst;
        const std::vector<IrValueId> ops =
            callins.operands; /* [obj, (meta), args...] */
        const uint32_t srcline = callins.source_line;
        if (ops.empty()) continue; /* sin receptor: no especulable */

        /* Operands del CALL directo del fast path: receptor + args, sin el
         * operando de metadata del dispatch.  CALLITF lleva params_ptr en
         * ops[1] y CALLM lleva el method_ptr en ops[1] -> se quitan; CALLVIRT
         * no tiene metadata -> se mantienen todos.  El SRET retbuf (cuando
         * aplica) va tras ops[1], asi que se conserva. */
        std::vector<IrValueId> call_ops;
        if (callop == IrOp::CALLVIRT) {
            call_ops = ops;
        } else {
            call_ops.push_back(ops[0]);
            for (size_t a = 2; a < ops.size(); ++a)
                call_ops.push_back(ops[a]);
        }

        /* Capturar los sucesores ORIGINALES de B antes de sobreescribirlos. */
        const std::vector<IrBlockId> orig_succs = fn.blocks[bidx].succs;

        const size_t K = cands.size();

        /* Crear los bloques nuevos (append; los indices existentes no se
         * mueven gracias al reserve previo). */
        std::vector<IrBlockId> fastb(K);
        std::vector<IrBlockId> gblk(
            K, IR_NO_BLOCK); /* gblk[0]=B; gblk[n>=1] nuevos */
        for (size_t n = 0; n < K; ++n)
            fastb[n] = fn.new_block("spec_fast");
        for (size_t n = 1; n < K; ++n)
            gblk[n] = fn.new_block("spec_guard");
        const IrBlockId fbackb = fn.new_block("spec_fallback");
        const IrBlockId mergeb = fn.new_block("spec_merge");
        gblk[0] = bidx; /* el primer guard va en B (in-place) */

        /* Mover el tail [i+1 ..] al merge; truncar B a [0 .. i-1]. */
        {
            auto &Binstrs = fn.blocks[bidx].instrs;
            std::vector<IrInstr> tail(
                Binstrs.begin() + static_cast<long>(i) + 1, Binstrs.end());
            fn.blocks[mergeb].instrs = std::move(tail);
            Binstrs.resize(i); /* descarta el call en i + el tail */
        }

        /* cls = load[obj], computado UNA vez en B (domina toda la cadena). */
        const IrValueId vcls = fn.new_value(IrType::I64, "spec_cls");
        {
            IrInstr ld;
            ld.op = IrOp::LOAD;
            ld.type = IrType::I64;
            ld.dst = vcls;
            ld.operands = {ops[0]};
            ld.source_line = srcline;
            fn.blocks[bidx].instrs.push_back(ld);
        }

        /* Cadena de guardas: por candidato n en gblk[n]:
         *   g = (cls == cls_value_n);  br_cond fast_n / next
         * donde next = gblk[n+1] (si lo hay) o el fallback. */
        std::vector<IrValueId> rfast(K);
        for (size_t n = 0; n < K; ++n) {
            const IrBlockId gb = gblk[n];
            const IrBlockId next = (n + 1 < K) ? gblk[n + 1] : fbackb;

            const IrValueId vg = fn.new_value(IrType::BOOL, "spec_g");
            {
                IrInstr cm;
                cm.op = IrOp::CMP_EQ;
                cm.type = IrType::BOOL;
                cm.dst = vg;
                cm.operands = {vcls, cands[n].cls_value};
                cm.source_line = srcline;
                fn.blocks[gb].instrs.push_back(cm);
            }
            {
                IrInstr br;
                br.op = IrOp::BR_COND;
                br.operands = {vg};
                br.target_block = fastb[n];
                br.false_block = next;
                br.source_line = srcline;
                fn.blocks[gb].instrs.push_back(br);
            }
            fn.blocks[gb].succs = {fastb[n], next};
            if (n > 0)
                fn.blocks[gb].preds = {
                    gblk[n - 1]}; /* gblk[0]=B: preds intactos */

            /* fast_n: CALL directo al callee (ir_pass_inline lo inlinea) + br
             * merge. */
            rfast[n] = fn.new_value(rtype, "spec_rfast");
            {
                IrInstr call;
                call.op = IrOp::CALL;
                call.type = rtype;
                call.dst = rfast[n];
                call.func_name = cands[n].callee_ir_name;
                call.operands = call_ops;
                call.source_line = srcline;
                fn.blocks[fastb[n]].instrs.push_back(call);
            }
            {
                IrInstr br;
                br.op = IrOp::BR;
                br.target_block = mergeb;
                fn.blocks[fastb[n]].instrs.push_back(br);
            }
            fn.blocks[fastb[n]].preds = {gb};
            fn.blocks[fastb[n]].succs = {mergeb};
        }

        /* Fallback: el call dinamico ORIGINAL (copia) -> r_slow + br merge. */
        const IrValueId rslow = fn.new_value(rtype, "spec_rslow");
        {
            IrInstr cv2 = callins;
            cv2.dst = rslow;
            fn.blocks[fbackb].instrs.push_back(cv2);
        }
        {
            IrInstr br;
            br.op = IrOp::BR;
            br.target_block = mergeb;
            fn.blocks[fbackb].instrs.push_back(br);
        }
        fn.blocks[fbackb].preds = {gblk[K - 1]};
        fn.blocks[fbackb].succs = {mergeb};

        /* Merge: PHI(orig_dst) = [rfast_n@fast_n..., rslow@fallback] + tail. */
        {
            IrInstr phi;
            phi.op = IrOp::PHI;
            phi.type = rtype;
            phi.dst = orig_dst;
            phi.phi_args.reserve(K + 1);
            for (size_t n = 0; n < K; ++n)
                phi.phi_args.push_back(IrPhiArg{rfast[n], fastb[n]});
            phi.phi_args.push_back(IrPhiArg{rslow, fbackb});
            phi.source_line = srcline;
            fn.blocks[mergeb].instrs.insert(fn.blocks[mergeb].instrs.begin(),
                                            phi);
        }
        {
            std::vector<IrBlockId> mpreds;
            mpreds.reserve(K + 1);
            for (size_t n = 0; n < K; ++n)
                mpreds.push_back(fastb[n]);
            mpreds.push_back(fbackb);
            fn.blocks[mergeb].preds = std::move(mpreds);
        }
        fn.blocks[mergeb].succs = orig_succs;

        /* Repuntar los sucesores originales de B: ahora su predecesor es merge
         * (el terminador del tail vive ahi).  Tambien sus PHIs. */
        for (IrBlockId s : orig_succs) {
            if (s == IR_NO_BLOCK || s >= fn.blocks.size()) continue;
            auto &sb = fn.blocks[s];
            for (auto &p : sb.preds)
                if (p == bidx) p = mergeb;
            for (auto &ins : sb.instrs) {
                if (ins.op != IrOp::PHI) continue;
                for (auto &pa : ins.phi_args)
                    if (pa.block == bidx) pa.block = mergeb;
            }
        }

        changed = true;
    }

    // Tras la cirugia, los bloques nuevos quedaron en orden NO topologico
    // (orden de iteracion del unordered_map de sites).  Reordenar a RPO para
    // que el emisor de bytecode + regalloc/liveness (sensibles al orden) y el
    // fall-through emitan codigo correcto y DETERMINISTA.
    if (changed) reorder_blocks_rpo(fn);

    return changed;
}

// =========================================================================
//  Pase Load Narrow: elide SEXT redundante tras LOAD i8/i16/i32
// =========================================================================

bool ir_pass_load_narrow(IrFunction &fn) {
    if (fn.blocks.empty()) return false;

    /* Ops "narrow-safe": dado inputs con bits bajos correctos (sin importar
     * bits altos), producen un resultado cuyos bits bajos siguen siendo
     * correctos.  ADD/SUB/MUL/AND/OR/XOR son bit-parallel en los bits bajos. */
    auto is_narrow_safe_arith = [](IrOp op) -> bool {
        switch (op) {
        case IrOp::ADD:
        case IrOp::SUB:
        case IrOp::MUL:
        case IrOp::AND:
        case IrOp::OR:
        case IrOp::XOR: return true;
        default: return false;
        }
    };

    /* Construir lista de usos (vid -> [(block_idx, instr_idx, kind)]).
     * kind: 0=operands, 1=phi_args.  Solo necesitamos saber QUE instrucciones
     * referencian cada valor para inspeccionar su op. */
    struct UseRef {
        size_t bi;
        size_t ii;
    };
    std::unordered_map<IrValueId, std::vector<UseRef>> uses;
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto &bb = fn.blocks[bi];
        for (size_t ii = 0; ii < bb.instrs.size(); ++ii) {
            const auto &ins = bb.instrs[ii];
            for (IrValueId op : ins.operands) {
                if (op != IR_NO_VALUE) uses[op].push_back({bi, ii});
            }
            for (const auto &pa : ins.phi_args) {
                if (pa.value != IR_NO_VALUE) uses[pa.value].push_back({bi, ii});
            }
        }
    }

    /* Para cada LOAD i8/i16/i32 (signed), computar el cierre transitivo
     * de valores derivados via ops narrow-safe.  Si TODOS los usos terminales
     * son STORE/RET del mismo tipo y todos los usos intermedios son ops
     * narrow-safe o STORE/RET, marcar el LOAD como narrow_only. */
    /* Re-analizar en cada invocacion: el flag puede REVOCARSE si pasos
     * posteriores (CSE/copy_prop) exponen usos que antes no eran visibles
     * (e.g. %42 = add %38, %41 cuya operand %41 luego se rewrite a %29). */
    bool changed = false;
    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            if (ins.op != IrOp::LOAD) continue;
            if (ins.dst == IR_NO_VALUE) continue;
            if (ins.type != IrType::I8 && ins.type != IrType::I16 &&
                ins.type != IrType::I32)
                continue;

            const IrType narrow_type = ins.type;

            /* Cierre transitivo via BFS. */
            std::unordered_set<IrValueId> closure;
            std::vector<IrValueId> worklist;
            closure.insert(ins.dst);
            worklist.push_back(ins.dst);

            bool safe = true;
            while (safe && !worklist.empty()) {
                IrValueId v = worklist.back();
                worklist.pop_back();

                auto it = uses.find(v);
                if (it == uses.end()) continue; // no uses -> trivially safe

                for (const UseRef &u : it->second) {
                    const IrInstr &user = fn.blocks[u.bi].instrs[u.ii];

                    /* STORE del mismo tipo: el valor solo se usa como
                     * operand[0] (val).  Truncar al ancho de tipo es seguro. */
                    if (user.op == IrOp::STORE) {
                        if (user.type != narrow_type) {
                            safe = false;
                            break;
                        }
                        /* El valor solo es seguro si esta en operand[0] (val);
                         * si esta en operand[1] (ptr), eso seria un puntero
                         * derivado del LOAD lo cual es UNSAFE (no es nuestro
                         * caso esperado pero por seguridad). */
                        if (user.operands.size() < 2) {
                            safe = false;
                            break;
                        }
                        if (user.operands[0] != v) {
                            safe = false;
                            break;
                        }
                        continue;
                    }

                    /* RET del mismo tipo: el caller espera el ancho declarado,
                     * el VM trunca al hacer return.  Conservadoramente solo
                     * permitimos cuando fn.ret_type coincide. */
                    if (user.op == IrOp::RET) {
                        if (fn.ret_type != narrow_type) {
                            safe = false;
                            break;
                        }
                        continue;
                    }

                    /* Op narrow-safe del mismo tipo: propagar al closure. */
                    if (is_narrow_safe_arith(user.op) &&
                        user.type == narrow_type) {
                        if (user.dst != IR_NO_VALUE &&
                            closure.insert(user.dst).second) {
                            worklist.push_back(user.dst);
                        }
                        continue;
                    }

                    /* PHI del mismo tipo: el PHI mismo produce un valor i32
                     * cuyos bits altos pueden ser garbage si NUESTRO valor
                     * llega.  Pero si TODOS los usos del PHI son seguros, el
                     * garbage no importa.  Propagar el dst del PHI al closure
                     * para que la BFS verifique sus usos transitivamente.
                     * Los ciclos en PHIs de loops se manejan via el set
                     * @c closure (no se re-procesa lo ya visitado).
                     * Otros inputs del PHI no nos importan: solo nos
                     * preocupa como nuestro valor se propaga a partir del
                     * PHI hacia adelante. */
                    if (user.op == IrOp::PHI && user.type == narrow_type) {
                        if (user.dst != IR_NO_VALUE &&
                            closure.insert(user.dst).second) {
                            worklist.push_back(user.dst);
                        }
                        continue;
                    }

                    /* MOV del mismo tipo (e.g. copy_prop residual): propagar.
                     */
                    if (user.op == IrOp::MOV && user.type == narrow_type) {
                        if (user.dst != IR_NO_VALUE &&
                            closure.insert(user.dst).second) {
                            worklist.push_back(user.dst);
                        }
                        continue;
                    }

                    /* Cualquier otro uso (CMP, SEXT, ZEXT, CAST, BITCAST,
                     * TRUNC, SHL/SHR/SAR, NEG/NOT, SDIV/UDIV/SMOD/UMOD,
                     * CALL, STORE/LOAD/RET de tipo distinto, etc.) aborta
                     * la elision -- los bits altos pueden ser necesarios. */
                    safe = false;
                    break;
                }
            }

            /* Establecer/revocar el flag segun analisis actual. */
            const bool prev = fn.values[ins.dst].narrow_only;
            if (prev != safe) {
                fn.values[ins.dst].narrow_only = safe;
                changed = true;
            }
        }
    }

    return changed;
}

// =========================================================================
//  Pase List Scheduling: reordena para exponer ILP
// =========================================================================

/* Determina si la instruccion es una "barrera" (no se puede reordenar
 * a traves de ella en NINGUNA direccion: ni mover instrucciones hacia
 * arriba de la barrera, ni hacia abajo).  Usado para CALLs, RAW_ASM,
 * NEWOBJ, etc. donde el side-effect es opaco al scheduler. */
static bool is_sched_barrier(IrOp op) {
    switch (op) {
    case IrOp::CALL:
    case IrOp::CALLN:
    case IrOp::CALLVIRT:
    case IrOp::CALLIND:
    case IrOp::CALLM:
    case IrOp::CALLITF:
    case IrOp::CALLCLOSURE:
    case IrOp::TAILCALL:
    case IrOp::CALLSUPER:
    case IrOp::RAW_ASM:
    //  AS inc.3: INLINE_ASM lee/escribe los registros register() y
    // posiblemente memoria.  Barrera de scheduling para que el scheduler
    // NO mueva LOADs/STOREs de las vars register-bound a traves del asm
    // (un LOAD post-asm debe leer lo que el asm escribio, no el init).
    case IrOp::INLINE_ASM:
    case IrOp::NEWOBJ:
    case IrOp::NEWOBJS:
    case IrOp::GC_ALLOC:
    case IrOp::GC_ALLOCP:
    case IrOp::RAW_ALLOC:
    case IrOp::RAW_FREE:
    case IrOp::THROW:
    case IrOp::TRYENTER:
    case IrOp::TRYLEAVE:
    /* El punto de aterrizaje del `catch` recibe la excepcion en un REGISTRO
     * FIJO, puesto por quien la lanzo.  Eso no se ve en el IR -- no tiene
     * operandos --, asi que nada impedia colocar instrucciones delante; y la
     * primera que escribiera ese registro se llevaba la excepcion por delante.
     * Bastaba con que el cuerpo del `try` tuviera una rama para que el
     * planificador encontrara una carga que subir, y entonces el `catch` leia
     * los campos de un puntero nulo.  Es una barrera: aqui empieza el handler y
     * lo primero que pasa es recoger la excepcion. */
    case IrOp::LANDINGPAD:
    case IrOp::SETFIELD:
    case IrOp::ARRAY_STORE:
    case IrOp::MEMCPY:
    case IrOp::MEMSET:
    case IrOp::VEC_UNOP:
    case IrOp::VEC_BINOP:
    case IrOp::VEC_FMA:
    case IrOp::VEC_ACC_ZERO:
    case IrOp::VEC_ACC_ADD:
    case IrOp::VEC_ACC_FMA:
    case IrOp::VEC_ACC_STORE:
    case IrOp::VEC_ACC_COMBINE:
    case IrOp::VEC_FMA_S:
    case IrOp::VEC_BINOP_S:
    case IrOp::VEC_BCAST:
    case IrOp::STRFINALIZE:
    case IrOp::GCWB_IR:
    // Sprint string-perf-2 bug fix (2026-06-02): STRMAKE LEE
    // bytes desde vm_mem en runtime (via vm_addr).  Sin marcarla
    // como barrera, el scheduler podia reordenar STOREs a vm_mem
    // PASADO la STRMAKE, leyendo bytes stale.  Bug capturado en
    // patron `buf[i]=X; STRMAKE(buf); buf[i]=Y; STRMAKE(buf)`
    // donde el segundo STORE quedaba post-STRMAKE.
    // STRCAT/STRCONV/STRFLAT NO leen vm_mem (operan sobre handles),
    // pero pueden disparar alloc -> GC -> rearrange objects.  Mas
    // seguro tratar TODAS las str ops alloc-side como barreras
    // hasta confirmar safety por op.
    case IrOp::STRMAKE:
    case IrOp::STRCAT:
    case IrOp::STRCONV:
    case IrOp::STRFLAT:
    case IrOp::STRINTERN:
    case IrOp::STRRESERVE:
    case IrOp::FUTURE:
    case IrOp::AWAIT:
    case IrOp::FULFILL:
    case IrOp::REJECT:
    case IrOp::FULFILL_HLT:
    case IrOp::MSGSEND:
    case IrOp::MSGRECV:
    // Recuperados   instrucciones que LEEN structs de params
    // construidos por STOREs previos.  Sin barrera, el scheduler puede
    // moverlas antes de los STOREs y leer basura.  Cubre tambien las
    // operaciones GC/atomic/static que mutan estado global.
    case IrOp::MVTAKE_IR:
    case IrOp::GC_PROMOTE:
    case IrOp::GC_DEMOTE:
    case IrOp::GC_HANDLE_FOR_PTR:
    case IrOp::ATOMIC_LD:
    case IrOp::ATOMIC_ST:
    case IrOp::ATOMIC_CAS:
    case IrOp::ATOMIC_ADD:
    case IrOp::GETSTATIC:
    case IrOp::SETSTATIC:
    case IrOp::FINDCLASS:
    case IrOp::DEFCLASS:
    case IrOp::DEFFIELD:
    case IrOp::DEFMETHOD:
    case IrOp::ADDADVICE:
    case IrOp::FINDMETHOD:
    case IrOp::FINDFIELD:
    case IrOp::SETMETHDBG:
    case IrOp::PROCEED:
    case IrOp::SPAWN_ON:
    // Fibras/corutinas (FN.1): SWAPCTX cede el control a OTRO contexto (fibra)
    // que puede leer/escribir memoria global (y, en el interp, restaura TODOS
    // los registros al volver).  DEBE ser barrera: un LOAD post-swapctx tiene
    // que releer memoria (no reusar un valor cacheado antes del switch), y el
    // scheduler no puede mover LOADs/STOREs a traves del switch.  SPAWN/YIELD/
    // RESUME mutan estado del scheduler (crean/ceden/reactivan procesos).
    case IrOp::SWAPCTX:
    case IrOp::SPAWN:
    case IrOp::SPAWN_ARGS:
    case IrOp::YIELD:
    case IrOp::RESUME:
    case IrOp::HLT:
    case IrOp::PANIC:
    case IrOp::GETPID:
    case IrOp::GETARGC:
    case IrOp::GETARG:
    case IrOp::STRGETBYTES: return true;
    default: return false;
    }
}

/* STORE no es barrera total pero sirve de "memory barrier" suave:
 * LOADs posteriores podrian alias, asi que LOAD depende de todos los
 * STOREs previos del mismo bloque (conservativo).  Otros STOREs tambien
 * dependen del previo (orden de escritura es observable). */
/* Esta lista NO se sustituye por analysis::memory_access_kind, y la diferencia
 * es de nivel, no un descuido: aquel vocabulario describe la memoria DEL
 * PROGRAMA, y esto es una barrera para el PLANIFICADOR, que ordena lo que se va
 * a emitir.  Un VEC_BCAST no toca memoria del programa -- difunde un escalar a
 * un registro --, pero en el interprete baja pasando por un scratch en la pila
 * de la VM; quitarlo de aqui porque el nivel IR diga que no toca memoria seria
 * perder una barrera que el codigo emitido si necesita.  Marcar de mas aqui
 * cuesta una reordenacion que no se hace; marcar de menos cuesta correccion.
 *
 * Lo que cerraria esta duplicidad de verdad es una capa de efectos POR
 * OBJETIVO -- MachineIR + la base de instrucciones, que ya sabe que lee y
 * escribe cada forma en cada ISA --, no forzar a este consumidor a un nivel que
 * no es el suyo. */
static bool is_store_like(IrOp op) {
    // VEC_UNOP/VEC_BINOP escriben memoria (dst) y ademas leen (a/b): tratarlas
    // como store-like es la barrera conservativa correcta.
    return op == IrOp::STORE || op == IrOp::SETFIELD ||
           op == IrOp::ARRAY_STORE || op == IrOp::MEMCPY ||
           op == IrOp::MEMSET || op == IrOp::VEC_UNOP ||
           op == IrOp::VEC_BINOP || op == IrOp::VEC_FMA ||
           op == IrOp::VEC_ACC_ZERO || op == IrOp::VEC_ACC_ADD ||
           op == IrOp::VEC_ACC_FMA || op == IrOp::VEC_ACC_STORE ||
           op == IrOp::VEC_ACC_COMBINE || op == IrOp::VEC_BINOP_S ||
           op == IrOp::VEC_FMA_S || op == IrOp::VEC_BCAST;
}

static bool is_load_like(IrOp op) {
    return op == IrOp::LOAD || op == IrOp::GETFIELD || op == IrOp::ARRAY_LOAD ||
           op == IrOp::ARRAY_LEN;
}

/* Terminadores: deben quedar al final del bloque. */
static bool is_sched_terminator(IrOp op) {
    return op == IrOp::BR || op == IrOp::BR_COND || op == IrOp::RET ||
           op == IrOp::THROW;
}

bool ir_pass_schedule(IrFunction &fn, const analysis::PointsTo *pt,
                      const std::unordered_set<std::string> *pure_callees) {
    bool changed = false;

    // Pure-call advance (SCHEDULER SEMANTICO): una CALL/TAILCALL a un callee
    // TOTALMENTE PURO deja de ser BARRERA de scheduling -> el scheduler puede
    // mover instrucciones a traves de ella (mas ILP expuesto).  La pureza NO
    // existe NATURALMENTE a nivel maquina: un scheduler maquina trata toda
    // llamada como barrera porque no la conoce.  En IR, en cambio, la pureza la
    // da EffectAnalysis de forma NATURAL y BARATA (la maquinaria -- ASA que
    // liftea asm->IR + EffectAnalysis + base de hechos -- ya esta construida).
    // Por la regla "cada opt en el nivel donde la info esta disponible de forma
    // natural y con menor coste de obtencion", vive AQUI.  Ademas es
    // ISA-INDEPENDIENTE (una vez, todos los targets).
    auto is_pure_sched_call = [&](const IrInstr &ins) -> bool {
        if (!pure_callees) return false;
        if (ins.op != IrOp::CALL && ins.op != IrOp::TAILCALL) return false;
        return !ins.func_name.empty() && pure_callees->count(ins.func_name) > 0;
    };

    // Modelo de memoria UNICO para las hazards del DAG (alias-aware, gated). El
    // scheduler NO construye la tabla points-to: la RECIBE del AnalysisManager
    // (Regla 1); fallback local si es una llamada suelta.
    analysis::PointsTo sched_local_pt;
    const analysis::PointsTo &sched_pt =
        pt ? *pt
           : (g_sched_alias ? (sched_local_pt = analysis::compute_points_to(
                                   fn, analysis::build_ir_facts(fn)))
                            : sched_local_pt);
    // La MEMORIA de cada acceso la da el vocabulario UNICO memory_access (Regla
    // 1: no se reimplementa el switch).  memcpy y VEC se modelan con PRECISION
    // (no opacos) -- opaco seria EVITAR la optimizacion.
    //
    // Deps de REGISTRO FISICO de los VEC de broadcast (lo que memory_access NO
    // modela, porque no es memoria): VEC_BCAST ESCRIBE XMM13-((imm>>8)&7);
    // VEC_BINOP_S hoisted (bit 16) LEE XMM13-((imm>>17)&7).  Se MODELAN con un
    // tracker de 8 registros (abajo) -> el scheduler reordena la memoria
    // libremente y SOLO ordena el par BCAST->BINOP_S por su registro; el codigo
    // viejo los trataba OPACOS (evitaba toda reordenacion = perdia ILP).
    auto vec_reg_write = [](const IrInstr &ins) -> int {
        return ins.op == IrOp::VEC_BCAST
                   ? int((static_cast<uint64_t>(ins.imm) >> 8) & 0x7)
                   : -1;
    };
    auto vec_reg_read = [](const IrInstr &ins) -> int {
        if ((ins.op == IrOp::VEC_BINOP_S || ins.op == IrOp::VEC_FMA_S) &&
            ((static_cast<uint64_t>(ins.imm) >> 16) & 1))
            return int((static_cast<uint64_t>(ins.imm) >> 17) & 0x7);
        return -1;
    };

    for (auto &bb : fn.blocks) {
        const size_t N = bb.instrs.size();
        if (N <= 2) continue; // nada que reordenar

        // Guard de SOUNDNESS del alias-aware: un bloque con asm (INLINE_ASM/
        // ASM_MICRO/RAW_ASM) tiene ops de memoria LIGADAS A REGISTROS FISICOS
        // (register(...)) cuyo orden es una dependencia de REGISTRO, no de
        // alias
        // -> el modelo de memoria no la ve.  En esos bloques se usa el orden
        // total conservador (asm es raro; el win alias-aware es para bloques
        // de memoria normales).
        // El ACARREO entra en la misma categoria y es MAS estricto.  `carryof`
        // lee el flag que dejo su `addc`/`subb`; el grafo de valores liga los
        // dos nodos -- el operando de `carryof` ES lo que produjo `addc` --, y
        // eso garantiza que va DESPUES, pero no que no se cuele nada en medio:
        // el flag no vive en el grafo, asi que cualquier operacion que lo pise
        // entre los dos hace leer el acarreo de OTRA suma, en silencio.
        //
        // Por eso aqui no basta con quitar el modo alias-aware: hay que dejar
        // el bloque COMO ESTA.  Son bloques de aritmetica multiprecision, donde
        // conservar el orden importa mas que el paralelismo que se pierde.
        //
        // Esto ya estaba escrito arriba y NO estaba hecho -- solo se miraba el
        // asm --, y por eso el modo alias-aware daba mal `wideint_signed`: con
        // menos aristas de memoria el planificador tenia mas libertad y acababa
        // colando algo entre la suma y su acarreo.

        bool blk_has_asm = false;
        bool blk_has_carry = false;
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::INLINE_ASM || ins.op == IrOp::RAW_ASM) {
                blk_has_asm = true; // opaco: sus accesos no se ven
            } else if (ins.op == IrOp::ASM_MICRO) {
                /* Un micro asm SI se sabe lo que hace, asi que solo estorba si
                 * de verdad toca memoria.  Antes cualquier asm apagaba el modo
                 * alias-aware del bloque entero: un `pause`, que no lee ni
                 * escribe nada, costaba el paralelismo de todo lo que hubiera
                 * alrededor.  Lo que decide es la base, no la etiqueta. */
                const uint8_t e = ins.imm < fn.asm_micros.size()
                                      ? fn.asm_micros[ins.imm].eff
                                      : 0xFFu; // sin ficha: conservador
                if ((e & 0x01) != 0 || (e & 0x10) != 0) blk_has_asm = true;
            }
            if (ins.op == IrOp::ADDC || ins.op == IrOp::SUBB ||
                ins.op == IrOp::CARRYOF)
                blk_has_carry = true;
        }
        if (blk_has_carry) continue; // el orden ES la semantica; no se toca
        const bool use_alias = g_sched_alias && !blk_has_asm;

        /* Identificar prefijo de PHIs (fijo al inicio) y terminador. */
        size_t first_movable = 0;
        while (first_movable < N && bb.instrs[first_movable].op == IrOp::PHI) {
            ++first_movable;
        }
        size_t last_movable = N;
        if (last_movable > 0 &&
            is_sched_terminator(bb.instrs[last_movable - 1].op)) {
            --last_movable;
        }
        if (last_movable - first_movable < 2)
            continue; // <2 instrucciones movibles

        const size_t M = last_movable - first_movable;

        /* Construir DAG de dependencias.  Nodos = indices [0..M) en el
         * rango movible.  Edges: pred[i] = lista de nodos que i depende.
         * succ[i] = lista de nodos que dependen de i. */
        std::vector<std::vector<size_t>> preds(M);
        std::vector<std::vector<size_t>> succs(M);
        std::vector<size_t> in_degree(M, 0);

        /* Map: def_vid -> index dentro de [0..M) que lo define. */
        std::unordered_map<IrValueId, size_t> def_of;
        for (size_t i = 0; i < M; ++i) {
            const auto &ins = bb.instrs[first_movable + i];
            if (ins.dst != IR_NO_VALUE) def_of[ins.dst] = i;
        }

        /* Tracking de "ultima barrera/store/load" para deps de memoria. */
        long last_barrier = -1;
        long last_store = -1;
        std::vector<size_t>
            loads_after_last_store; // LOADs posteriores al ultimo store
        // Alias-aware (gated): accesos de memoria vivos desde la ultima
        // barrera, con su localizacion; solo se anade arista si may_alias.  Se
        // limpian en cada barrera (la arista a la barrera subsume lo anterior).
        struct MemAcc {
            size_t idx;
            analysis::effects::AbstractLoc loc;
        };
        std::vector<MemAcc> prior_stores; // escrituras vivas (idx + loc)
        std::vector<MemAcc> prior_loads;  // lecturas vivas
        // Tracker de deps de REGISTRO FISICO de los VEC de broadcast
        // (XMM13-0..7): ultimo VEC_BCAST que escribio cada registro + lectores
        // desde entonces.
        long reg_writer[8];
        std::vector<size_t> reg_readers[8];
        for (int r = 0; r < 8; ++r)
            reg_writer[r] = -1;

        auto add_edge = [&](size_t from, size_t to) {
            /* Evitar duplicados.  Sanity: from != to. */
            if (from == to) return;
            for (size_t p : preds[to])
                if (p == from) return;
            preds[to].push_back(from);
            succs[from].push_back(to);
        };

        for (size_t i = 0; i < M; ++i) {
            const auto &ins = bb.instrs[first_movable + i];

            /* Data deps: para cada operando con def en este bloque, edge
             * def->i. */
            for (IrValueId op : ins.operands) {
                if (op == IR_NO_VALUE) continue;
                auto it = def_of.find(op);
                if (it != def_of.end() && it->second < i) {
                    add_edge(it->second, i);
                }
            }
            for (const auto &pa : ins.phi_args) {
                if (pa.value == IR_NO_VALUE) continue;
                auto it = def_of.find(pa.value);
                if (it != def_of.end() && it->second < i) {
                    add_edge(it->second, i);
                }
            }
            if (ins.func_ptr != IR_NO_VALUE) {
                auto it = def_of.find(ins.func_ptr);
                if (it != def_of.end() && it->second < i) {
                    add_edge(it->second, i);
                }
            }

            /* Memory/side-effect deps. */
            // Una pure-call NO es barrera (movimiento semantico unico); gated
            // bajo el scheduler semantico y con el guard de asm (use_alias).
            /* Y una instruccion de asm liftada es barrera SEGUN LO QUE HAGA,
             * no por ser asm.
             *
             * `ASM_MICRO` no estaba en la lista, asi que un `mfence` liftado no
             * frenaba al planificador: podia colarse una lectura o una
             * escritura al otro lado de una barrera de memoria, en silencio y
             * solo cuando el bloque se hubiera podido elevar.  Hasta ahora eso
             * no se notaba porque quien escribe una barrera pone `volatile` y
             * con `volatile` el bloque no se eleva -- o sea que la correccion
             * dependia de una marca del programador en vez del analisis.
             *
             * Lo que decide es la propia instruccion: la base dice si es
             * barrera (bit 3 de `eff`), y un `pause` liftado no frena nada
             * mientras que un `mfence` lo frena todo. */
            bool micro_barr_mem = false;   // ordena la MEMORIA
            bool micro_barr_total = false; // ordena TODO (efecto desconocido)
            if (ins.op == IrOp::ASM_MICRO && ins.imm < fn.asm_micros.size()) {
                const uint8_t e = fn.asm_micros[ins.imm].eff;
                micro_barr_total = (e & 0x10) != 0; // call
                /* Ordena la memoria tanto si es una barrera como si simplemente
                 * la TOCA.  Solo se miraba lo primero, asi que un `mov [d], b`
                 * elevado no contaba como acceso y la lectura de esa misma
                 * variable se adelantaba por delante de la escritura: el
                 * programa leia lo de antes.  Donde escribe no se sabe -- la
                 * direccion la trae un registro --, asi que cuenta como acceso
                 * opaco, que es lo que hace esta rama. */
                /* Y tambien cuando MODIFICA alguno de sus valores.
                 *
                 * Un operando de lectura-escritura cambia el valor donde esta,
                 * y eso el IR no lo dice: la instruccion lo declara como USO,
                 * no como definicion, asi que un `store` de ese mismo valor a
                 * su hueco parecia otra lectura mas y se podia adelantar.  Se
                 * guardaba el valor viejo, el asm modificaba el suyo y ya nadie
                 * lo devolvia: `add a, 2` sobre 40 seguia dando 40.
                 *
                 * Ordenarlo contra la memoria basta, porque es por el hueco por
                 * donde el valor entra y sale. */
                bool micro_escribe_valor = false;
                for (const AsmMicroOperand &o : fn.asm_micros[ins.imm].operands)
                    if (o.writes() && o.value != IR_NO_VALUE) {
                        micro_escribe_valor = true;
                        break;
                    }
                micro_barr_mem = !micro_barr_total &&
                                 (((e & 0x08) != 0) || ((e & 0x01) != 0) ||
                                  micro_escribe_valor);
            }
            const bool is_barr =
                (is_sched_barrier(ins.op) || micro_barr_total) &&
                !(use_alias && is_pure_sched_call(ins));
            const bool is_st = is_store_like(ins.op);
            const bool is_ld = is_load_like(ins.op);

            if (is_barr) {
                /* Barrera: depende de todo lo previo, bloquea todo lo
                 * posterior. Conservador: añadir edge desde TODOS los nodos
                 * previos. */
                for (size_t j = 0; j < i; ++j)
                    add_edge(j, i);
                last_barrier = static_cast<long>(i);
                last_store = static_cast<long>(i);
                loads_after_last_store.clear();
                prior_stores.clear();
                prior_loads.clear();
                for (int r = 0; r < 8; ++r) {
                    reg_writer[r] = -1;
                    reg_readers[r].clear();
                }
            } else if (micro_barr_mem) {
                /* Una barrera de MEMORIA ordena memoria, no aritmetica.
                 *
                 * Tratarla como barrera total serializaba el bloque entero:
                 * una suma que no toca memoria no puede cruzar un `mfence` mal,
                 * porque no hay nada que cruzar.  Frenar tambien esas es pagar
                 * paralelismo por nada, y quien escribe una barrera a mano
                 * suele estar justo en el camino caliente.
                 *
                 * Asi que se ordena contra lo que SI le afecta -- lecturas,
                 * escrituras y otras barreras --, y lo demas queda libre. */
                for (const MemAcc &st : prior_stores)
                    add_edge(st.idx, i);
                for (const MemAcc &ld : prior_loads)
                    add_edge(ld.idx, i);
                if (last_barrier >= 0)
                    add_edge(static_cast<size_t>(last_barrier), i);
                last_barrier = static_cast<long>(i);
                /* Y lo de despues ordena contra ella: se apunta como acceso
                 * opaco para que cualquier memoria posterior la vea delante. */
                const analysis::effects::AbstractLoc U{
                    analysis::effects::AbstractLoc::Kind::Unknown,
                    analysis::effects::LOC_GENERIC, 0, 0};
                prior_stores.push_back({i, U});
                prior_loads.push_back({i, U});
            } else if (use_alias && (is_st || is_ld)) {
                /* ALIAS-AWARE (modelo UNICO memory_access): se ordena SOLO
                 * contra accesos previos que PUEDEN aliasar; raices disjuntas
                 * quedan libres para reordenar -> mas ILP.  memcpy y VEC se
                 * modelan con PRECISION (reads/writes multi-loc), no opacos.
                 * Sound: may_alias solo dice "no" cuando es DEMOSTRABLE. */
                const analysis::MemoryAccess ma =
                    analysis::memory_access(ins, sched_pt);
                if (last_barrier >= 0)
                    add_edge(static_cast<size_t>(last_barrier), i);
                if (ma.opaque) {
                    // Memoria NO localizable: ordena contra TODO lo previo vivo
                    // y los futuros ordenan contra ella (mini-barrera de mem).
                    for (const MemAcc &s : prior_stores)
                        add_edge(s.idx, i);
                    for (const MemAcc &l : prior_loads)
                        add_edge(l.idx, i);
                    const analysis::effects::AbstractLoc U{
                        analysis::effects::AbstractLoc::Kind::Unknown,
                        analysis::effects::LOC_GENERIC, 0, 0};
                    prior_stores.push_back({i, U});
                    prior_loads.push_back({i, U});
                } else {
                    // WRITES: WAW vs writes previos, WAR vs reads previos.
                    for (const auto &w : ma.writes) {
                        for (const MemAcc &s : prior_stores)
                            if (analysis::effects::may_alias(w, s.loc))
                                add_edge(s.idx, i);
                        for (const MemAcc &l : prior_loads)
                            if (analysis::effects::may_alias(w, l.loc))
                                add_edge(l.idx, i);
                    }
                    // READS: RAW vs writes previos.
                    for (const auto &r : ma.reads)
                        for (const MemAcc &s : prior_stores)
                            if (analysis::effects::may_alias(r, s.loc))
                                add_edge(s.idx, i);
                    for (const auto &w : ma.writes)
                        prior_stores.push_back({i, w});
                    for (const auto &r : ma.reads)
                        prior_loads.push_back({i, r});
                }
                // Deps de REGISTRO FISICO (VEC_BCAST escribe / VEC_BINOP_S
                // lee).
                const int rw = vec_reg_write(ins);
                const int rr = vec_reg_read(ins);
                if (rr >= 0) {
                    // lectura de registro: RAW vs el ultimo BCAST
                    if (reg_writer[rr] >= 0)
                        add_edge(static_cast<size_t>(reg_writer[rr]), i);
                    reg_readers[rr].push_back(i);
                }
                if (rw >= 0) {
                    // escritura de registro: WAW + WAR
                    if (reg_writer[rw] >= 0)
                        add_edge(static_cast<size_t>(reg_writer[rw]), i);
                    for (size_t rd : reg_readers[rw])
                        add_edge(rd, i);
                    reg_writer[rw] = static_cast<long>(i);
                    reg_readers[rw].clear();
                }
            } else if (is_st) {
                /* STORE depende de la ultima barrera, del ultimo store, y de
                 * todos los LOADs posteriores al ultimo store (orden
                 * W-after-R). */
                if (last_barrier >= 0)
                    add_edge(static_cast<size_t>(last_barrier), i);
                if (last_store >= 0)
                    add_edge(static_cast<size_t>(last_store), i);
                for (size_t ld_idx : loads_after_last_store)
                    add_edge(ld_idx, i);
                last_store = static_cast<long>(i);
                loads_after_last_store.clear();
            } else if (is_ld) {
                /* LOAD depende de la ultima barrera y del ultimo store. */
                if (last_barrier >= 0)
                    add_edge(static_cast<size_t>(last_barrier), i);
                if (last_store >= 0)
                    add_edge(static_cast<size_t>(last_store), i);
                loads_after_last_store.push_back(i);
            } else {
                /* Pure ops: data deps + dep contra ultima barrera para
                 * evitar hoist sobre CALL/etc.  Sin esto, un @c const.i32
                 * declarado DESPUES de un CALL podria moverse ANTES del
                 * CALL, aumentando register pressure (el const queda vivo
                 * across el call y debe salvarse en push/pop).  El bench
                 * fib regresiono al hoistar @c const.i32 2 sobre el call
                 * recursivo.  La barrera actua como "muro de scheduling"
                 * en ambas direcciones (no entran ni salen ops a traves). */
                if (last_barrier >= 0)
                    add_edge(static_cast<size_t>(last_barrier), i);
            }
        }

        /* Computar in_degree desde preds. */
        for (size_t i = 0; i < M; ++i)
            in_degree[i] = preds[i].size();

        /* Computar critical path length (CPL): CPL[i] = 1 + max(CPL[succ]).
         * Calculado en orden topologico inverso (de hojas a raices).
         * Hacemos topo sort primero. */
        std::vector<size_t> topo;
        topo.reserve(M);
        std::vector<size_t> in_deg_copy = in_degree;
        std::vector<size_t> q;
        for (size_t i = 0; i < M; ++i) {
            if (in_deg_copy[i] == 0) q.push_back(i);
        }
        while (!q.empty()) {
            size_t n = q.back();
            q.pop_back();
            topo.push_back(n);
            for (size_t s : succs[n]) {
                if (--in_deg_copy[s] == 0) q.push_back(s);
            }
        }
        if (topo.size() != M)
            continue; // ciclo detectado (no deberia pasar en SSA + DAG)

        std::vector<uint32_t> cpl(M, 0);
        for (auto it = topo.rbegin(); it != topo.rend(); ++it) {
            size_t n = *it;
            uint32_t best = 0;
            for (size_t s : succs[n]) {
                if (cpl[s] > best) best = cpl[s];
            }
            cpl[n] = best + 1;
        }

        /* List scheduling: ready set ordenado por (CPL desc, indice asc para
         * estable). */
        std::vector<size_t> new_order;
        new_order.reserve(M);
        std::vector<size_t> ready;
        ready.reserve(M);
        std::vector<size_t> rem_in = in_degree;
        for (size_t i = 0; i < M; ++i) {
            if (rem_in[i] == 0) ready.push_back(i);
        }

        while (!ready.empty()) {
            /* Elegir el de mayor CPL (criterio clasico de Sethi-Ullman /
             * critical-path scheduling).  Tie-break:
             *   (a) menos sucesores primero -- "leaf" nodes que rellenan
             *       latencia sin extender el chain critico;
             *   (b) indice original menor para estabilidad. */
            size_t best_idx = 0;
            for (size_t j = 1; j < ready.size(); ++j) {
                const size_t a = ready[best_idx];
                const size_t b = ready[j];
                if (cpl[b] > cpl[a]) {
                    best_idx = j;
                } else if (cpl[b] == cpl[a]) {
                    if (succs[b].size() < succs[a].size()) {
                        best_idx = j;
                    } else if (succs[b].size() == succs[a].size() && b < a) {
                        best_idx = j;
                    }
                }
            }
            size_t pick = ready[best_idx];
            ready[best_idx] = ready.back();
            ready.pop_back();
            new_order.push_back(pick);
            for (size_t s : succs[pick]) {
                if (--rem_in[s] == 0) ready.push_back(s);
            }
        }

        if (new_order.size() != M) continue; // sanity

        /* Detectar si el orden cambio.  Si no, skip. */
        bool different = false;
        for (size_t i = 0; i < M; ++i) {
            if (new_order[i] != i) {
                different = true;
                break;
            }
        }
        if (!different) continue;

        /* Aplicar reordenamiento: mover bb.instrs[first_movable + new_order[i]]
         * a posicion first_movable + i.  Hacer una copia temporal porque las
         * indices originales se invalidan al mover. */
        std::vector<IrInstr> reordered;
        reordered.reserve(M);
        for (size_t i = 0; i < M; ++i) {
            reordered.push_back(
                std::move(bb.instrs[first_movable + new_order[i]]));
        }
        for (size_t i = 0; i < M; ++i) {
            bb.instrs[first_movable + i] = std::move(reordered[i]);
        }
        changed = true;
    }

    return changed;
}

// =========================================================================
//  Pase ir_pass_loop_memcpy_idiom (Sprint mem-perf 2026-06-02)
// =========================================================================
//
// Reconocimiento de loop-idiom byte-a-byte de la forma:
//
//   while_header:
//       %i_phi = phi.u64 [%i_init, pred]  [%i_next, body]
//       %cond  = cmp.ult.bool %i_phi, %N_ub
//       br.cond %cond, body, exit
//   body:
//       (%i_or_cast = bitcast %i_phi)?
//       %src_p = add.ptr %src_base, %i_or_cast
//       %dst_p = add.ptr %dst_base, %i_or_cast
//       %v     = load.u8 %src_p
//       store %v, %dst_p
//       %i_next = add %i_phi, %1_const
//       br while_header
//
// Lo reemplaza por una sola @c IrOp::MEMCPY -- la instruccion de la VM, no
// una llamada a nadie.  Cada backend la materializa por su via mas rapida
// (`memcpy`/`memcpyh` en el interprete, `rep movsb` en el JIT), y el hecho
// queda EN el IR, donde efectos, alias y escape pueden razonar sobre el.
//
// Pre-condiciones:
//   - El bloque body tiene EXACTAMENTE los 6-7 instrs del patron.
//   - El PHI del header solo tiene un valor de loop-carry (no PHIs
//     multiples).
//   - %i_init es CONST 0 (o cualquier const; usado como offset inicial
//     que ignoramos -- el memcpy copia [0, N)).  Por simplicidad
//     exigimos 0.
//   - %i_next = add %i_phi, 1 (step de 1).
//
// Tras el match: el body se reemplaza por `MEMCPY(dst, src, N) + br exit`.  El
// header sigue invocando body solo la primera vez; la siguiente iteracion el
// cond falla porque body cambio el flow. Mas correcto: el body NO retorna a
// header (br exit directo), asi el loop nunca itera.
/**
 * @brief True si la operacion deja su propio resultado en los flags de la CPU.
 *
 * El acarreo de una suma sobrevive solo hasta la siguiente operacion que
 * escriba flags.  Sirve para saber hasta donde se puede mirar cuando se busca
 * la comparacion que lo deduce.
 *
 * @param op Operacion SSA.
 * @return true si al bajar a codigo escribe flags.
 */
static bool ir_op_touches_flags(IrOp op) noexcept {
    switch (op) {
    case IrOp::ADD:
    case IrOp::SUB:
    case IrOp::MUL:
    case IrOp::DIV:
    case IrOp::AND:
    case IrOp::OR:
    case IrOp::XOR:
    case IrOp::SHL:
    case IrOp::SHR:
    case IrOp::SAR:
    case IrOp::NEG:
    case IrOp::NOT:
    case IrOp::ADDC:
    case IrOp::SUBB:
    case IrOp::CMP_EQ:
    case IrOp::CMP_NE:
    case IrOp::CMP_LT:
    case IrOp::CMP_LE:
    case IrOp::CMP_GT:
    case IrOp::CMP_GE:
    case IrOp::CMP_ULT:
    case IrOp::CMP_ULE:
    case IrOp::CMP_UGT:
    case IrOp::CMP_UGE: return true;
    default: return false;
    }
}

/**
 * @brief Reconoce la suma o resta cuyo acarreo se deduce comparando, y la
 *        marca para que el generador de codigo lea el acarreo que la maquina
 *        ya calcula.
 *
 * Quien compone enteros mas anchos que la palabra arrastra el acarreo de un
 * limb al siguiente, y como el lenguaje no expone el flag lo deduce asi:
 *
 * @code
 *   lo = a + b;
 *   if (lo < a) { carry = 1; }      // sin signo
 * @endcode
 *
 * La comparacion es redundante: la suma ya dejo esa respuesta en un flag.  El
 * patron se reescribe a la forma que lo aprovecha (@c ADDC mas @c CARRYOF),
 * que los tres emisores bajan a una suma seguida de leer el flag.
 *
 * Para la resta el patron equivalente es @c a-b junto a @c a<b (pidio prestado
 * si el minuendo era menor).
 *
 * Se exige que la comparacion este en el MISMO bloque que la operacion y que
 * entre ambas no haya nada que toque los flags, porque el acarreo se pisa con
 * cualquier otra operacion aritmetica.  Cuando no se cumple, no se toca nada y
 * el codigo sigue deduciendolo como hasta ahora -- correcto, solo mas largo.
 *
 * @param fn Funcion SSA a examinar.
 * @return true si se reescribio algun patron.
 */
/**
 * @brief El patron de la suma cuyo acarreo se deduce comparando.
 *
 * Quien compone enteros mas anchos que la palabra arrastra el acarreo de un
 * limb al siguiente, y como el lenguaje no expone el flag lo deduce asi:
 *
 * @code
 *   lo = a + b;
 *   if (lo < a) { carry = 1; }      // sin signo
 * @endcode
 *
 * La comparacion es redundante: la suma ya dejo esa respuesta en un flag.  Para
 * la resta el patron equivalente es @c a-b junto a @c a<b (pidio prestado si el
 * minuendo era menor).
 *
 * @return El patron listo para registrar.
 */
static Pattern carry_idiom_pattern() {
    Pattern p;
    p.name = "acarreo";

    // QUE busca.  Los operandos se comparan por HECHOS (ir_same_value), no por
    // identidad de valor SSA: leer un campo dos veces produce dos valores que
    // valen lo mismo, y exigir el mismo valor dejaba el patron sin reconocer
    // casos que solo se diferencian en como se escribieron.
    p.match = [](const IrFunction &fn, IrBlockId b, size_t i) -> PatternMatch {
        PatternMatch m{};
        const IrBlock &bb = fn.blocks[b];
        const IrInstr &op = bb.instrs[i];
        if (op.op != IrOp::ADD && op.op != IrOp::SUB) return m;
        if (op.dst == IR_NO_VALUE || op.operands.size() != 2) return m;
        // Solo enteros de la anchura de la palabra: por debajo, el acarreo de
        // la maquina es el del registro entero y no el del tipo.
        if (op.type != IrType::I64 && op.type != IrType::U64) return m;
        const IrValueId a = op.operands[0];
        const IrValueId bb_op = op.operands[1];

        for (size_t k = i + 1; k < bb.instrs.size(); ++k) {
            const IrInstr &c = bb.instrs[k];
            if (c.op == IrOp::CMP_ULT && c.operands.size() == 2) {
                const bool suma_ok = (op.op == IrOp::ADD) &&
                                     c.operands[0] == op.dst &&
                                     (ir_same_value(fn, c.operands[1], a) ||
                                      ir_same_value(fn, c.operands[1], bb_op));
                const bool resta_ok = (op.op == IrOp::SUB) &&
                                      ir_same_value(fn, c.operands[0], a) &&
                                      ir_same_value(fn, c.operands[1], bb_op);
                if (suma_ok || resta_ok) {
                    m.block = b;
                    m.index = i;
                    m.aux_index = k;
                    m.valid = true;
                    return m;
                }
            }
            // Lo que haya en medio no impide reconocerlo: la relacion es de
            // DATOS.  Solo corta que algo REDEFINA uno de los tres valores en
            // juego, porque entonces ya no se hablaria de la misma suma.
            if (c.dst != IR_NO_VALUE &&
                (c.dst == op.dst || c.dst == a || c.dst == bb_op))
                break;
        }
        return m;
    };

    // Que el acarreo siga vivo al leerlo NO se comprueba aqui: es cosa del
    // emisor, que materializa la lectura pegada a la suma y, si no puede, la
    // recalcula con una comparacion equivalente.  Atar ambas cosas fue lo que
    // dejo este patron reconociendo uno de cada siete casos.
    p.legal = [](const IrFunction &, const PatternMatch &) { return true; };

    // La comparacion desaparece: una instruccion menos.
    p.benefit = [](const IrFunction &, const PatternMatch &) {
        PatternBenefit pb;
        pb.instructions_saved = 1;
        return pb;
    };

    p.rewrite = [](IrFunction &fn, const PatternMatch &m) {
        IrBlock &bb = fn.blocks[m.block];
        IrInstr &op = bb.instrs[m.index];
        IrInstr &c = bb.instrs[m.aux_index];
        op.op = (op.op == IrOp::ADD) ? IrOp::ADDC : IrOp::SUBB;
        c.op = IrOp::CARRYOF;
        c.type = op.type;
        c.operands = {op.dst};
        return true;
    };
    return p;
}

bool ir_pass_carry_idiom(IrFunction &fn) {
    /* Valvula para aislar el pase al depurar.  Se lee UNA vez: esto corre una
     * vez por funcion y por ronda del punto fijo -- decenas de miles de veces
     * en un modulo grande --, y consultar el entorno recorre el bloque entero
     * de variables en cada consulta.  Medido, era el 45% de lo que costaba
     * este pase, todo el gasto en preguntar si estaba apagado. */
    static const bool apagado = util::flag_on(util::FlagId::NoCarryIdiom);
    if (apagado) return false;
    static const std::vector<Pattern> pats = {carry_idiom_pattern()};
    return ir_apply_patterns(fn, pats);
}

bool ir_pass_loop_memcpy_idiom(IrFunction &fn) {
    bool changed = false;
    if (fn.is_native) return false;
    // @NoIdiom: quien IMPLEMENTA la copia no puede ver su bucle reescrito a
    // una llamada a la copia -- seria una llamada a si mismo.
    if (fn.no_idiom) return false;

    for (size_t hi = 0; hi < fn.blocks.size(); ++hi) {
        IrBlock &header = fn.blocks[hi];
        // Header debe tener exactamente: 1 phi, 1 cmp, 1 br.cond.
        if (header.instrs.size() != 3) continue;
        const IrInstr &phi = header.instrs[0];
        const IrInstr &cmp_in = header.instrs[1];
        const IrInstr &brc = header.instrs[2];
        if (phi.op != IrOp::PHI) continue;
        if (phi.phi_args.size() != 2) continue;
        if (cmp_in.op != IrOp::CMP_ULT && cmp_in.op != IrOp::CMP_LT) continue;
        if (brc.op != IrOp::BR_COND) continue;
        if (brc.operands.empty() || brc.operands[0] != cmp_in.dst) continue;
        if (cmp_in.operands.size() != 2 || cmp_in.operands[0] != phi.dst)
            continue;
        IrValueId v_N = cmp_in.operands[1];
        IrBlockId body_id = brc.target_block;
        IrBlockId exit_id = brc.false_block;
        if (body_id >= fn.blocks.size() || exit_id >= fn.blocks.size())
            continue;

        // Identificar el predecessor (entry) y el body en los phi_args.
        IrValueId v_init = IR_NO_VALUE;
        IrBlockId pred_id = IR_NO_VALUE;
        IrValueId v_next = IR_NO_VALUE;
        IrBlockId loop_pred = IR_NO_VALUE;
        for (const auto &pa : phi.phi_args) {
            if (pa.block == body_id) {
                v_next = pa.value;
                loop_pred = pa.block;
            } else {
                v_init = pa.value;
                pred_id = pa.block;
            }
        }
        if (v_init == IR_NO_VALUE || v_next == IR_NO_VALUE) continue;

        // %i_init debe ser CONST 0.
        if (v_init >= fn.values.size() || !fn.values[v_init].is_const) continue;
        if (fn.values[v_init].const_val != 0) continue;

        // Body matching.
        IrBlock &body = fn.blocks[body_id];
        // Patron flexible: 5 o 6 instrs (con o sin bitcast).
        if (body.instrs.size() < 5 || body.instrs.size() > 7) continue;
        // Ultima instr debe ser br header.
        const IrInstr &body_term = body.instrs.back();
        if (body_term.op != IrOp::BR) continue;
        if (body_term.target_block != header.id) continue;

        // Buscar: load.u8, store, add (= i+1).
        IrValueId v_src_p = IR_NO_VALUE, v_dst_p = IR_NO_VALUE;
        IrValueId v_loaded = IR_NO_VALUE;
        IrValueId v_inc_step = IR_NO_VALUE;
        IrValueId v_index_used = IR_NO_VALUE;
        bool found_load = false, found_store = false, found_inc = false;
        IrValueId v_src_base = IR_NO_VALUE, v_dst_base = IR_NO_VALUE;
        for (const auto &ins : body.instrs) {
            if (ins.op == IrOp::LOAD && ins.type == IrType::U8 &&
                ins.operands.size() == 1) {
                v_src_p = ins.operands[0];
                v_loaded = ins.dst;
                found_load = true;
            } else if (ins.op == IrOp::STORE && ins.operands.size() >= 2) {
                if (ins.operands[0] != v_loaded) {
                    found_store = false;
                    break;
                }
                v_dst_p = ins.operands[1];
                found_store = true;
            } else if (ins.op == IrOp::ADD && ins.operands.size() == 2 &&
                       ins.dst == v_next) {
                if (ins.operands[0] != phi.dst) continue;
                v_inc_step = ins.operands[1];
                found_inc = true;
            } else if (ins.op == IrOp::ADD && ins.operands.size() == 2) {
                // posible add.ptr base + index -- lo procesamos despues.
            } else if (ins.op == IrOp::BITCAST && ins.operands.size() == 1 &&
                       ins.operands[0] == phi.dst) {
                // ok, lo trataremos como un alias del index.
            } else if (ins.op == IrOp::BR) {
                // terminator OK
            } else {
                // instr inesperada -> rechazar.
                found_load = false;
                break;
            }
        }
        if (!found_load || !found_store || !found_inc) continue;

        // v_inc_step debe ser const 1.
        if (v_inc_step >= fn.values.size() || !fn.values[v_inc_step].is_const)
            continue;
        if (fn.values[v_inc_step].const_val != 1) continue;

        // Identificar bases via los ADDs.  Cada add.ptr produce v_src_p o
        // v_dst_p. operands son (base, index).  Index debe ser phi.dst o un
        // bitcast de phi.dst.
        auto resolve_base = [&](IrValueId pv) -> IrValueId {
            for (const auto &ins : body.instrs) {
                if (ins.op == IrOp::ADD && ins.dst == pv &&
                    ins.operands.size() == 2) {
                    IrValueId idx = ins.operands[1];
                    bool ok = (idx == phi.dst);
                    if (!ok) {
                        // chequear bitcast
                        for (const auto &b2 : body.instrs) {
                            if (b2.op == IrOp::BITCAST && b2.dst == idx &&
                                !b2.operands.empty() &&
                                b2.operands[0] == phi.dst) {
                                ok = true;
                                break;
                            }
                        }
                    }
                    if (ok) return ins.operands[0];
                }
            }
            return IR_NO_VALUE;
        };
        v_src_base = resolve_base(v_src_p);
        v_dst_base = resolve_base(v_dst_p);
        if (v_src_base == IR_NO_VALUE || v_dst_base == IR_NO_VALUE) continue;

        /* OK match completo.  Reemplazar el body por:  MEMCPY(dst, src, N) + br
         *
         * El op del IR, NO una llamada nativa.  Antes esto emitia
         * `CALLN vio_memcpy`, que ademas de pagar el sobrecoste de la llamada
         * ataba el pase a un helper de plugin -- inexistente en freestanding y
         * fuera del alcance del optimizer, que ya no podia razonar sobre lo que
         * la copia hace.  Con @c IrOp::MEMCPY el hecho queda EN el IR (efectos,
         * alias y escape lo entienden) y cada backend lo materializa por su via
         * mas rapida: instruccion `memcpy`/`memcpyh` en el interprete,
         * `rep movsb` en el JIT. */
        IrInstr call_ins;
        call_ins.op = IrOp::MEMCPY;
        call_ins.type = IrType::VOID;
        call_ins.dst = IR_NO_VALUE;
        call_ins.operands = {v_dst_base, v_src_base, v_N};
        call_ins.source_line = body.instrs.front().source_line;

        IrInstr br_exit;
        br_exit.op = IrOp::BR;
        br_exit.target_block = exit_id;
        br_exit.dst = IR_NO_VALUE;

        body.instrs.clear();
        body.instrs.push_back(call_ins);
        body.instrs.push_back(br_exit);

        // Fix succs/preds: body ya no apunta a header.
        body.succs.clear();
        body.succs.push_back(exit_id);
        // Quitar body de header.preds (mantener el original pred).
        auto &hpreds = header.preds;
        hpreds.erase(std::remove(hpreds.begin(), hpreds.end(), body_id),
                     hpreds.end());
        // añadir body a exit.preds si no esta.
        IrBlock &exit_blk = fn.blocks[exit_id];
        if (std::find(exit_blk.preds.begin(), exit_blk.preds.end(), body_id) ==
            exit_blk.preds.end()) {
            exit_blk.preds.push_back(body_id);
        }
        // Quitar el phi_arg de body en el PHI del header (ahora 1-arg).
        IrInstr &header_phi = fn.blocks[hi].instrs[0];
        header_phi.phi_args.erase(std::remove_if(header_phi.phi_args.begin(),
                                                 header_phi.phi_args.end(),
                                                 [body_id](const IrPhiArg &pa) {
                                                     return pa.block == body_id;
                                                 }),
                                  header_phi.phi_args.end());

        changed = true;
    }
    return changed;
}

// =========================================================================
//  Pase ir_pass_inline_closures
// =========================================================================
//
// Inline del CUERPO de la lambda en el CALLCLOSURE.  Ver doc en el header.
// Estrategia conservadora: 1 MAKE_CLOSURE + 1 CALLCLOSURE en el MISMO
// bloque, capturas by-value, helper single-block terminado en RET.  El
// emparejamiento es trivial (solo hay una closure) -> sin alias analysis.

bool ir_pass_inline_closures(IrModule &mod) {
    bool changed = false;

    std::unordered_map<std::string, size_t> name_to_idx;
    for (size_t i = 0; i < mod.functions.size(); ++i)
        name_to_idx[mod.functions[i].name] = i;

    for (size_t fi = 0; fi < mod.functions.size(); ++fi) {
        IrFunction &caller = mod.functions[fi];
        if (caller.is_native) continue;

        /* 1. Localizar el unico MAKE_CLOSURE y el unico CALLCLOSURE. */
        int mc_b = -1, mc_i = -1, cc_b = -1, cc_i = -1, n_mc = 0, n_cc = 0;
        for (size_t b = 0; b < caller.blocks.size(); ++b) {
            const auto &ins = caller.blocks[b].instrs;
            for (size_t k = 0; k < ins.size(); ++k) {
                if (ins[k].op == IrOp::MAKE_CLOSURE) {
                    ++n_mc;
                    mc_b = static_cast<int>(b);
                    mc_i = static_cast<int>(k);
                } else if (ins[k].op == IrOp::CALLCLOSURE) {
                    ++n_cc;
                    cc_b = static_cast<int>(b);
                    cc_i = static_cast<int>(k);
                }
            }
        }
        if (n_mc != 1 || n_cc != 1) continue;
        if (mc_b != cc_b || mc_i >= cc_i) continue; /* mc antes del cc */

        IrBlock &bb = caller.blocks[cc_b];
        const IrInstr mc = bb.instrs[mc_i]; /* copia: vamos a reescribir bb */
        const IrInstr cc = bb.instrs[cc_i];

        /* by-value only: bits 1.. de imm = mutable_mask. */
        if ((mc.imm >> 1) != 0ULL) continue;

        auto it = name_to_idx.find(mc.func_name);
        if (it == name_to_idx.end() || it->second == fi) continue;
        const IrFunction &h = mod.functions[it->second];
        if (h.is_native || h.blocks.size() != 1) continue;
        const IrBlock &hb = h.blocks[0];
        if (hb.instrs.empty() || hb.instrs.back().op != IrOp::RET) continue;

        const size_t n_args = cc.operands.empty() ? 0 : cc.operands.size() - 1;
        const size_t n_caps = mc.operands.size();

        /* params del helper = [declarados...] (+ [env] en native_poo). */
        IrValueId env_param = IR_NO_VALUE;
        std::vector<IrValueId> decl_params;
        if (h.params.size() == n_args) {
            decl_params = h.params;
        } else if (h.params.size() == n_args + 1) {
            decl_params.assign(h.params.begin(), h.params.end() - 1);
            env_param = h.params.back();
        } else {
            continue; /* aridad no encaja */
        }

        /* env_ptr: param oculto (native_poo) o READ_VM_REG 14 (VM/JIT). */
        IrValueId env_ptr = env_param;
        std::unordered_set<size_t> skip; /* instrs del prologo a omitir */
        if (env_ptr == IR_NO_VALUE && n_caps > 0) {
            for (size_t k = 0; k < hb.instrs.size(); ++k) {
                if (hb.instrs[k].op == IrOp::READ_VM_REG &&
                    hb.instrs[k].imm == 14) {
                    env_ptr = hb.instrs[k].dst;
                    skip.insert(k);
                    break;
                }
            }
            if (env_ptr == IR_NO_VALUE) continue; /* capturas sin env -> bail */
        }

        /* Direcciones de captura: env_ptr (offset 0) + ADD(env_ptr,const). */
        std::unordered_set<IrValueId> cap_addr;
        if (env_ptr != IR_NO_VALUE) cap_addr.insert(env_ptr);
        for (size_t k = 0; k < hb.instrs.size(); ++k) {
            const auto &in = hb.instrs[k];
            if (in.op == IrOp::ADD && in.operands.size() == 2 &&
                in.operands[0] == env_ptr) {
                cap_addr.insert(in.dst);
                skip.insert(k);
            }
        }

        /* LOADs de captura en orden de fuente -> raw_v_i. */
        std::vector<IrValueId> cap_loads;
        for (size_t k = 0; k < hb.instrs.size(); ++k) {
            const auto &in = hb.instrs[k];
            if (in.op == IrOp::LOAD && in.operands.size() == 1 &&
                cap_addr.count(in.operands[0])) {
                cap_loads.push_back(in.dst);
                skip.insert(k);
            }
        }
        if (cap_loads.size() != n_caps) continue;

        /* vmap: params -> args; capturas -> valores del MAKE_CLOSURE. */
        std::unordered_map<IrValueId, IrValueId> vmap;
        for (size_t k = 0; k < decl_params.size(); ++k)
            vmap[decl_params[k]] = cc.operands[k + 1];
        for (size_t i = 0; i < n_caps; ++i) {
            vmap[cap_loads[i]] = mc.operands[i];
            /* TRUNC que estrecha la captura (by-value narrow): mapear su
             * dst tambien al valor original y omitir el TRUNC. */
            for (size_t k = 0; k < hb.instrs.size(); ++k) {
                const auto &in = hb.instrs[k];
                if (in.op == IrOp::TRUNC && in.operands.size() == 1 &&
                    in.operands[0] == cap_loads[i]) {
                    vmap[in.dst] = mc.operands[i];
                    skip.insert(k);
                    break;
                }
            }
        }

        /* Seguridad: env_ptr SOLO usado por ADD(env_ptr,..) / LOAD(env_ptr);
         * ningun READ_VM_REG fuera del prologo. */
        bool ok = true;
        for (size_t k = 0; k < hb.instrs.size() && ok; ++k) {
            const auto &in = hb.instrs[k];
            auto used = [&](IrValueId u) {
                if (u != env_ptr || env_ptr == IR_NO_VALUE) return;
                const bool as_add =
                    (in.op == IrOp::ADD && in.operands.size() == 2 &&
                     in.operands[0] == env_ptr);
                const bool as_ld =
                    (in.op == IrOp::LOAD && in.operands.size() == 1 &&
                     in.operands[0] == env_ptr);
                if (!as_add && !as_ld) ok = false;
            };
            for (auto u : in.operands)
                used(u);
            if (in.func_ptr != IR_NO_VALUE) used(in.func_ptr);
            if (in.op == IrOp::READ_VM_REG && !skip.count(k)) ok = false;
        }
        if (!ok) continue;

        /* Construir el cuerpo inlineado (sin commit hasta saber que es OK). */
        std::vector<IrInstr> body;
        auto remap_dst = [&](IrValueId cvid, IrType type) -> IrValueId {
            if (cvid == IR_NO_VALUE) return IR_NO_VALUE;
            auto vit = vmap.find(cvid);
            if (vit != vmap.end()) return vit->second;
            const IrValueId nid = static_cast<IrValueId>(caller.values.size());
            IrValue nv{};
            nv.id = nid;
            nv.type = type;
            nv.name = "%clo_" + std::to_string(nid);
            if (cvid < h.values.size()) {
                const auto &cv = h.values[cvid];
                nv.is_const = cv.is_const;
                nv.const_val = cv.const_val;
                nv.is_host_ptr = cv.is_host_ptr;
                nv.pointee_is_host_ptr = cv.pointee_is_host_ptr;
                nv.is_gc_object = cv.is_gc_object;
                nv.narrow_only = cv.narrow_only;
            }
            caller.values.push_back(nv);
            vmap[cvid] = nid;
            return nid;
        };
        auto remap_op = [&](IrValueId cvid) -> IrValueId {
            if (cvid == IR_NO_VALUE) return IR_NO_VALUE;
            auto vit = vmap.find(cvid);
            return (vit != vmap.end()) ? vit->second : IR_NO_VALUE;
        };

        /* Constancia de la llamada que se aplana (ver inline_note_site).  El
         * cuerpo de la lambda es codigo de otro sitio igual que cualquier otro
         * inlinado; sin esto su linea se atribuye a quien la invoca. */
        uint32_t sitio_base = 0;
        const uint32_t sitio = inline_note_site(caller, h, cc, sitio_base);

        IrValueId ret_value = IR_NO_VALUE;
        for (size_t k = 0; k < hb.instrs.size() && ok; ++k) {
            if (skip.count(k)) continue;
            const IrInstr &ci = hb.instrs[k];
            if (ci.op == IrOp::RET) {
                if (!ci.operands.empty()) {
                    ret_value = remap_op(ci.operands[0]);
                    if (ret_value == IR_NO_VALUE) ok = false;
                }
                continue;
            }
            if (!ci.phi_args.empty()) {
                ok = false;
                break;
            }
            IrInstr ni = ci;
            ni.inline_site = inline_map_site(ci.inline_site, sitio, sitio_base);
            if (ni.dst != IR_NO_VALUE) {
                const IrType dt = (ni.dst < h.values.size())
                                      ? h.values[ni.dst].type
                                      : ni.type;
                ni.dst = remap_dst(ni.dst, dt);
            }
            bool op_ok = true;
            for (auto &op : ni.operands) {
                const IrValueId before = op;
                op = remap_op(op);
                if (before != IR_NO_VALUE && op == IR_NO_VALUE) op_ok = false;
            }
            if (ni.func_ptr != IR_NO_VALUE) {
                const IrValueId before = ni.func_ptr;
                ni.func_ptr = remap_op(ni.func_ptr);
                if (before != IR_NO_VALUE && ni.func_ptr == IR_NO_VALUE)
                    op_ok = false;
            }
            if (!op_ok) {
                ok = false;
                break;
            }
            body.push_back(std::move(ni));
        }
        if (!ok) continue; /* anomalia -> no transformar (bb intacto) */

        /* Commit: reescribir bb = [0..cc) sin el marcador, + body con MOV
         * del retorno al dst, + (cc_i, fin) sin el CALLCLOSURE. */
        std::vector<IrInstr> rebuilt;
        rebuilt.reserve(bb.instrs.size() + body.size());
        for (int k = 0; k < cc_i; ++k) {
            if (k == mc_i) continue; /* drop marker */
            rebuilt.push_back(bb.instrs[k]);
        }
        for (auto &bi : body)
            rebuilt.push_back(std::move(bi));
        if (cc.dst != IR_NO_VALUE && ret_value != IR_NO_VALUE) {
            IrInstr mv{};
            mv.op = IrOp::MOV;
            mv.type = cc.type;
            mv.dst = cc.dst;
            mv.operands = {ret_value};
            mv.source_line = cc.source_line;
            rebuilt.push_back(std::move(mv));
        } else if (cc.dst != IR_NO_VALUE) {
            IrInstr cz{};
            cz.op = IrOp::CONST;
            cz.type = cc.type;
            cz.dst = cc.dst;
            cz.imm = 0;
            cz.source_line = cc.source_line;
            rebuilt.push_back(std::move(cz));
        }
        for (size_t k = cc_i + 1; k < bb.instrs.size(); ++k)
            rebuilt.push_back(bb.instrs[k]);
        bb.instrs = std::move(rebuilt);
        changed = true;
    }

    return changed;
}

// =========================================================================
//  Punto de entrada principal
// =========================================================================

namespace {
/* Acumulador por pase.  Tabla asociativa y no una lista: hay del orden de
 * cuarenta pases y el punto fijo los repite hasta ocho veces por funcion, asi
 * que se busca muchisimas mas veces de las que se inserta.  La clave es el
 * literal del nombre, que es estable. */
/// Lo acumulado de un (pase, funcion).
struct EntradaFn {
    long long us = 0;
    long long veces = 0;
    long long instrs = 0;
};

/**
 * @brief Lo que un hilo acumula sobre los pases.  SIN cerrojo, a proposito.
 *
 * Antes habia una sola tabla con un mutex, tomado "una vez por pase, no por
 * instruccion" -- que suena barato hasta que se cuentan: 72.016 tomas en un
 * modulo de 24k lineas.  Mientras todo era secuencial daba igual; en cuanto se
 * reparte el bucle de pases entre hilos, ese cerrojo pasa a ser el cuello y
 * serializa justo lo que se queria repartir.
 *
 * Ahora cada hilo acumula en el SUYO y se fusionan al leer.  El cerrojo solo se
 * toma al dar de alta un acumulador (una vez por hilo) y al pedir el total,
 * nunca al acumular.  Es la instrumentacion la que se aparta del camino, no al
 * reves.
 */
struct AcumuladorPases {
    std::unordered_map<const char *, std::pair<long long, long long>> t;
    /* Y el mismo reparto abierto por funcion.  Clave compuesta en texto: se
     * construye una vez por llamada a pase (miles, no millones) y ahorra tener
     * que inventar un hash de par. */
    std::unordered_map<std::string, EntradaFn> por_fn;
};

/// Todos los acumuladores vivos, uno por hilo que haya corrido algun pase.
struct PassTimeRegistry {
    std::mutex m;
    std::vector<std::unique_ptr<AcumuladorPases>> todos;
};

PassTimeRegistry &pass_time_registry() {
    static PassTimeRegistry r;
    return r;
}

/// El acumulador de ESTE hilo.  Se da de alta la primera vez y ya no vuelve a
/// tocar el cerrojo.
AcumuladorPases &acumulador_pases() {
    /* Puntero a nulo y alta perezosa, y NO un `thread_local` con inicializador
     * dinamico.  Este ultimo genera una variable de GUARDA, y en MinGW esa
     * guarda cuelga: con hilos que nacen y mueren -- justo lo que hace el
     * reparto del compilador -- el hilo principal se queda esperandola para
     * siempre.  Visto en una pila: bloqueado en `pthread_mutex_lock` dentro de
     * esta misma funcion.
     *
     * Un puntero inicializado a `nullptr` es de inicializacion CONSTANTE: no
     * hay guarda que generar, y el alta se hace a mano la primera vez. */
    thread_local AcumuladorPases *mio = nullptr;
    if (mio == nullptr) {
        auto nuevo = std::make_unique<AcumuladorPases>();
        mio = nuevo.get();
        PassTimeRegistry &r = pass_time_registry();
        std::lock_guard<std::mutex> lk(r.m);
        r.todos.push_back(std::move(nuevo));
    }
    return *mio;
}

/// Suma de todos los hilos, para quien pregunte por el total.
AcumuladorPases merge_pass_times() {
    AcumuladorPases total;
    PassTimeRegistry &r = pass_time_registry();
    std::lock_guard<std::mutex> lk(r.m);
    for (const auto &a : r.todos) {
        for (const auto &kv : a->t) {
            auto &d = total.t[kv.first];
            d.first += kv.second.first;
            d.second += kv.second.second;
        }
        for (const auto &kv : a->por_fn) {
            EntradaFn &d = total.por_fn[kv.first];
            d.us += kv.second.us;
            d.veces += kv.second.veces;
            d.instrs += kv.second.instrs;
        }
    }
    return total;
}

/**
 * @brief Corre @p f cronometrandola contra @p nombre.
 *
 * Plantilla para no pagar una indireccion por pase: se instancia con el lambda
 * de cada sitio y el compilador lo mete en linea.
 *
 * @param nombre Literal estable del pase.
 * @param f      Lo que hace el pase; devuelve si cambio algo.
 * @return Lo que devolviera @p f.
 */
template <typename F>
auto cronometrar_pase(const char *nombre, const IrFunction &fn, F &&f)
    -> decltype(f()) {
    const uint64_t t0 = util::reloj::ahora();
    auto r = f();
    // Reloj del proyecto: ~5 ns de resolucion frente a los ~100 del estandar.
    const long long us = util::reloj::a_ns(util::reloj::ahora() - t0) / 1000;
    /* El tamano se mide DESPUES del pase: es el que tiene la funcion cuando se
     * vuelva a mirar, y lo que interesa es como se relaciona el coste con lo
     * que hay, no con lo que habia. */
    long long instrs = 0;
    for (const auto &b : fn.blocks)
        instrs += static_cast<long long>(b.instrs.size());

    // Sin cerrojo: cada hilo acumula en el suyo (ver AcumuladorPases).
    AcumuladorPases &a = acumulador_pases();
    auto &e = a.t[nombre];
    e.first += us;
    e.second += 1;
    std::string clave = nombre;
    clave.push_back('\0');
    clave += fn.name;
    EntradaFn &q = a.por_fn[clave];
    q.us += us;
    q.veces += 1;
    q.instrs = instrs;
    return r;
}
} // namespace

/* Aplica un pase: lo cronometra, propaga si cambio algo al punto fijo, y marca
 * la funcion como SUCIA para los analisis cacheados.
 *
 * Lo de marcar es lo que permite dejar de invalidar "por si acaso": un analisis
 * cacheado solo deja de valer si el IR se ha tocado DESDE que se calculo, y
 * quien lo sabe es el propio pase por su valor de retorno.  Sin esto, cada
 * consumidor tiraba el points-to y los hechos de la funcion entera aunque en
 * esa vuelta no hubiera cambiado nada. */
/* `++fn.version` en las tres: un pase que dice haber cambiado algo avanza la
 * version de la funcion, y con eso un analisis cacheado deja de poder
 * entregarse -- su sello ya no coincide y se recalcula solo.  Es lo que
 * sustituye a "acordarse de invalidar", que es una obligacion que no se puede
 * comprobar y que ya fallaba: hay caminos donde el IR se modifica sin aviso y
 * el cache servia punteros a instrucciones borradas. */
#define APLICA(llamada)                                                        \
    do {                                                                       \
        const bool cambio__ = PASE(llamada);                                   \
        if (cambio__) any.store(true, std::memory_order_relaxed);              \
        sucia = sucia || cambio__;                                             \
        efectos_sucios = efectos_sucios || cambio__;                           \
        if (cambio__) ++fn.version;                                            \
    } while (0)

/**
 * Igual, pero para un pase que DECLARA preservar los efectos: lo que el modelo
 * dijo de las instrucciones que sobreviven sigue valiendo.
 *
 * Hoy solo lo declara el eliminador de codigo muerto, y esta demostrado: quitar
 * una instruccion muerta solo ENCOGE lo que la funcion lee, asi que un "no se
 * puede quitar" guardado sigue siendo cierto -- a lo sumo se queda corto.  Casi
 * ningun otro pase puede decir lo mismo: reescribir un operando cambia la
 * memoria que toca la instruccion, y estrechar una carga cambia su ancho.
 *
 * Es lo minimo del "cada pase declara que preserva", puesto donde se puede
 * demostrar y no donde suena bien.
 */
#define APLICA_PRESERVA_EFECTOS(llamada)                                       \
    do {                                                                       \
        const bool cambio__ = PASE(llamada);                                   \
        if (cambio__) any.store(true, std::memory_order_relaxed);              \
        sucia = sucia || cambio__;                                             \
        if (cambio__) ++fn.version;                                            \
    } while (0)

/* Igual, para los pases que devuelven cuantos cambios hicieron en vez de un
 * si/no. */
#define APLICA_N(llamada)                                                      \
    do {                                                                       \
        const bool cambio__ = (PASE(llamada) > 0);                             \
        if (cambio__) any.store(true, std::memory_order_relaxed);              \
        sucia = sucia || cambio__;                                             \
        efectos_sucios = efectos_sucios || cambio__;                           \
        if (cambio__) ++fn.version;                                            \
    } while (0)

/* Cronometra un pase sin repetir su nombre: `PASE(ir_pass_dse(fn))` mide y
 * devuelve lo mismo que la llamada.  Con el nombre escrito a mano se acabaria
 * midiendo un pase bajo la etiqueta de otro al mover una linea. */
#define PASE(llamada) cronometrar_pase(#llamada, fn, [&] { return (llamada); })

long long &vueltas_punto_fijo() {
    static long long v = 0;
    return v;
}

long long &visitas_a_funcion() {
    static long long n = 0;
    return n;
}

long long &fixpoint_truncations() {
    static long long n = 0;
    return n;
}

std::vector<TiempoPase> tiempos_de_pases() {
    const AcumuladorPases a = merge_pass_times();
    std::vector<TiempoPase> v;
    v.reserve(a.t.size());
    for (const auto &kv : a.t)
        v.push_back({kv.first, kv.second.first, kv.second.second});
    /* Y los tramos medidos FUERA del optimizador -- el modelo de efectos, por
     * ejemplo --, que van a su propio acumulador porque no son un pase.  Se
     * juntan aqui para que el reparto salga completo en un solo sitio: quien
     * lee un tiempo quiere ver donde se va, no en que libreria vive. */
    for (const util::Tramo &t : util::tramos_medidos())
        v.push_back({t.nombre, t.us, t.veces});
    std::sort(v.begin(), v.end(), [](const TiempoPase &a, const TiempoPase &b) {
        return a.us > b.us;
    });
    return v;
}

std::vector<TiempoPaseFuncion> tiempos_por_funcion() {
    const AcumuladorPases a = merge_pass_times();
    std::vector<TiempoPaseFuncion> v;
    v.reserve(a.por_fn.size());
    /* Los nombres de pase se devuelven como punteros estables: viven en esta
     * arena, que no invalida al crecer. */
    static std::deque<std::string> nombres;
    for (const auto &kv : a.por_fn) {
        const size_t corte = kv.first.find('\0');
        TiempoPaseFuncion x;
        x.funcion = (corte == std::string::npos) ? std::string()
                                                 : kv.first.substr(corte + 1);
        x.us = kv.second.us;
        x.veces = kv.second.veces;
        x.instrucciones = kv.second.instrs;
        nombres.push_back(kv.first.substr(0, corte));
        x.pase = nombres.back().c_str();
        v.push_back(std::move(x));
    }
    std::sort(v.begin(), v.end(),
              [](const TiempoPaseFuncion &a2, const TiempoPaseFuncion &b2) {
                  return a2.us > b2.us;
              });
    return v;
}

void reiniciar_tiempos_de_pases() {
    // Se vacian TODOS, no solo el del hilo que llama: quien reinicia quiere
    // empezar de cero, no dejar dentro lo que acumularon los demas.
    PassTimeRegistry &r = pass_time_registry();
    std::lock_guard<std::mutex> lk(r.m);
    for (const auto &a : r.todos) {
        a->t.clear();
        a->por_fn.clear();
    }
}

namespace {
/// Marcador de identidad de las ligaduras de asm en el gestor de analisis.
struct AsmBindingsAnalysis {
    static char ID;
};

char AsmBindingsAnalysis::ID = 0;

const bool g_no_promote_local_allocas =
    util::flag_on(util::FlagId::NoPromoteLocalAllocas);
const bool g_no_promote_raw_alloc =
    util::flag_on(util::FlagId::NoPromoteRawAlloc);
const bool g_no_spec_devirt = util::flag_on(util::FlagId::NoSpecDevirt);
const bool g_no_escape_scalar = util::flag_on(util::FlagId::NoEscapeScalar);
const bool g_no_dead_stack_slot = util::flag_on(util::FlagId::NoDeadStackSlot);

} // namespace

void ir_optimize(IrModule &mod, OptLevel level, bool allow_inline) {
    if (level == OptLevel::O0) return; // sin optimizacion

    /* Lo declarado sobre las nativas del modulo.  Se recoge UNA vez y se pasa
     * a los pases que preguntan por efectos: sin esto el optimizador trataba
     * toda CALLN como opaca aunque el modulo dijera exactamente lo que hace, y
     * la declaracion solo servia para el informe. */
    const analysis::effects::NativeDecls decls_nativas =
        analysis::effects::collect_native_decls({&mod});

    /*  D.7.opt: inline a nivel modulo ANTES del fix-point loop.
     * Despues del inline, los passes per-function se re-aplican sobre
     * el codigo expandido.
     *
     * `allow_inline=false` lo usa el modo --analyze: el coste PARCIAL de una
     * funcion es su cuerpo PROPIO, sin los callees ni el codigo que estos
     * meterian al inlinear (`return this.swap(v)` es parcial O(1), no O(n) por
     * el bucle de swap).  Post-inline no se puede distinguir el codigo propio
     * del inyectado, asi que para analizar se optimiza sin inline; el coste
     * interprocedural (TOTAL) lo compone el analizador via el callgraph. */
    if (level >= OptLevel::O1 && allow_inline) {
        CronoTramo crono__("opt:inline-prologo (pared)");
        ir_pass_inline(mod);
        /* Tras inlinar las factorias, la closure se construye y se invoca
         * en el mismo bloque -> inlinar tambien el CUERPO de la lambda en
         * el CALLCLOSURE (elimina el call indirecto + el env; el DCE limpia
         * las stores/allocs muertas).  Cross-backend: interp, JIT y AOT. */
        ir_pass_inline_closures(mod);
    }

    /*  D.jit-mem-model AUTO-PROMOTE: marca ALLOCAs que fluyen a
     * CALLN como is_host_ptr=true.  El JIT selector las emite en host
     * stack; el ptr resultante es directamente dereferenciable por
     * funciones nativas (Win API, libc, etc.).  Sin esto, `&local`
     * pasado a CALLN seria VM-addr -> garbage.  Cero anotaciones del
     * usuario: el analisis es backward-flow desde args PTR de CALLN.
     * UNA pasada (no se itera con el resto). */
    /* Bug host-vs-VM (2026-07-15): propagar is_host_ptr por las cadenas de
     * aritmetica de punteros ANTES que el resto de pases, para que las ALLOCAs
     * que marco el lowering (locales address-taken) tengan la naturaleza host
     * en TODOS sus derivados (`&p.campo` con offset != 0).  Se corre en todos
     * los niveles de opt (tambien O0): no es una optimizacion, es correctness
     * del emit -- de este flag depende que se elija movh (host) o mov (VM). */
    for_each_function(mod, [](IrFunction &fn) {
        if (!fn.is_native) ir_pass_propagate_host_ptr(fn);
    });

    if (level >= OptLevel::O1) {
        for_each_function(mod, [](IrFunction &fn) {
            if (!fn.is_native) ir_pass_promote_callned_allocas(fn);
        });
    }

    /* Sprint string-perf-8 (2026-06-02): promueve ALLOCAs LOCALES (no
     * escapan a CALL*, RET, THROW, etc.) a `host_alloca=true`.  El JIT
     * emite `sub rsp, N` en host stack y los LOAD/STORE usan native mov
     * directo (1 instr) en lugar del inline cache check (~10 instr).
     * Skippable via VESTA_NO_PROMOTE_LOCAL_ALLOCAS=1 para A/B testing.
     *
     * NOTA (bug host-vs-VM, 2026-07-15): NO usar force_all aqui.  Promover
     * TODAS las ALLOCAs (tambien las escapantes) rompe a los consumidores que
     * leen de memoria VM por diseno: los structs de params de los opcodes meta
     * (DefClassParams/DefMethodParams que `__module_init` construye en la pila
     * VM y pasa a defclass/defmethod via RAW_ASM) se leen con vm_mem, asi que
     * moverlos a host les da basura.  Por eso RAW_ASM cuenta como op UNSAFE y
     * su ALLOCA debe quedarse en la pila VM.
     *
     * La coherencia host/VM de los punteros del USUARIO no se resuelve aqui
     * (a nivel IR ya no existen los tipos Vesta y no se puede distinguir un
     * consumidor host de uno VM), sino en el lowering, que si conoce el tipo:
     * ver @c mark_addr_taken_local_as_host en src/vx/lowering.cpp. */
    if (level >= OptLevel::O1) {
        if (!g_no_promote_local_allocas) {
            for_each_function(mod, [](IrFunction &fn) {
                if (!fn.is_native) ir_pass_promote_local_allocas(fn);
            });
        }
    }

    /* Promocionar malloc(N_const)+free(p) locales sin escape a
     * ALLOCA host_alloca.  Convierte ~200-500 ns por alloc/free en
     * loops a ~1 ns (sub/add rsp del host stack).  UNA pasada.
     * Skippable via VESTA_NO_PROMOTE_RAW_ALLOC=1 para A/B testing. */
    if (level >= OptLevel::O1) {
        if (!g_no_promote_raw_alloc) {
            for_each_function(mod, [](IrFunction &fn) {
                if (!fn.is_native) ir_pass_promote_local_raw_alloc(fn);
            });
        }
    }

    //   conjunto de callees TOTALMENTE PUROS (cierre interproc del modelo
    // de efectos) para relajar la barrera de CALL en el DSE.  Se computa UNA
    // vez (la pureza total se PRESERVA bajo optimizacion -> sound usar el
    // pre-opt). Conocimiento que el DSE por si solo no puede tener; se lo da
    // EffectAnalysis.
    std::unordered_set<std::string> pure_callees;
    if (g_dse_pure_calls || g_sched_alias || g_licm_alias) {
        analysis::effects::EffectAnalysis ea;
        const analysis::effects::ModuleSummary &ms = ea.module_summary(mod);
        /* La condicion -- "no toca memoria en absoluto" -- es el contrato
         * `mem_free` del catalogo, no una regla de aqui.  Estaba escrita a mano
         * en este sitio, con lo que el informe de `--analyze` no podia decir
         * que funciones la cumplen: quien miraba por que una llamada seguia
         * siendo una barrera no tenia donde verlo.  Ahora es la misma fila para
         * los dos. */
        for (const auto &kv : ms.fns) {
            for (const auto &c : analysis::effects::derive_contracts(
                     kv.second, analysis::effects::ContractProfile::Default))
                if (c.name == "mem_free" && c.holds) {
                    pure_callees.insert(kv.first);
                    break;
                }
        }
    }

    // =====================================================================
    // REGLAS RECTORAS del framework de analisis/optimizacion (cerradas
    // 2026-07-20).  Condicionan todo el codigo de aqui en adelante:
    //
    // REGLA 1 (base de hechos compartida): "un solo modelo" NO es "un solo
    //   analisis".  Es UNA infraestructura donde cada analisis aporta
    //   conocimiento DISTINTO (Effect: que efectos; Alias/PointsTo: pueden
    //   aliasar; Escape: escapa; Range: que valores) y TODOS comparten la misma
    //   BASE DE HECHOS (IRFacts, PointsTo).  Un analisis nuevo debe APORTAR
    //   algo que ninguno existente pueda conocer; NUNCA reemplazar a un
    //   especializado (el DSE consume la alias compartida pero conserva su
    //   cobertura/ forwarding).  Corolario: un pase CONSUME la base de hechos,
    //   no la CONSTRUYE (por eso el AnalysisManager la provee aqui, en UN
    //   sitio).
    //
    // REGLA 2 (nivel de la optimizacion): cada optimizacion se hace en el NIVEL
    //   donde la informacion esta disponible de forma NATURAL y con MENOR COSTE
    //   de obtencion.  IR = semantico, ISA-INDEPENDIENTE (pureza, alias, DSE,
    //   LICM, GVN, escape: la info existe aqui de forma natural y barata --
    //   incluso la ASA liftea asm->IR a la misma base de hechos).  MachineIR =
    //   microarquitectural, POR-target (latencias, puertos, register pressure,
    //   renaming, spill).  Los DOS schedulers -- semantico (IR, definitivo para
    //   el interprete) y microarquitectural (machine_sched) -- COOPERAN: el
    //   semantico expone ILP que el de maquina no puede reconstruir; el de
    //   maquina lo explota segun la microarquitectura.  No compiten.
    // =====================================================================
    //
    // AnalysisManager: PROVEE la tabla points-to (base de hechos compartida)
    // cacheada por funcion.  Ningun consumidor (LICM/DSE/scheduler) la
    // construye -- la RECIBEN de aqui (Regla 1).  pt_invalidate se llama antes
    // de cada consumidor porque los pases previos mutaron el IR (los hechos
    // caducan); asi cada uno recibe una tabla FRESCA.  El manager cachea la
    // construccion en UN sitio y prepara la incrementalidad futura.
    analysis::AnalysisManager am;
    auto pt_of = [&](IrFunction &fn) -> const analysis::PointsTo & {
        return am
            .get_or_compute_v<analysis::PointsToAnalysis, analysis::PointsTo>(
                fn.name, fn.version, [&]() {
                    const analysis::IrFacts &f =
                        am.get_or_compute_v<analysis::IRFactsAnalysis,
                                            analysis::IrFacts>(
                            fn.name, fn.version,
                            [&]() { return analysis::build_ir_facts(fn); });
                    return analysis::compute_points_to(fn, f);
                });
    };
    /* Sucia = tocada DESDE que se calcularon sus analisis.  Vive entre vueltas
     * del punto fijo a proposito: lo que importa no es si cambio en esta vuelta
     * sino si cambio desde el ultimo calculo.  Arranca en true porque la
     * primera vez no hay nada cacheado. */
    std::unordered_map<std::string, bool> sucias;
    /* Las ligaduras del asm, cacheadas como todo lo demas.  Marcador propio
     * para que el gestor no las mezcle con otro analisis de la misma unidad. */
    auto asm_of = [&](IrFunction &fn) -> const analysis::AsmBindingFacts & {
        return am
            .get_or_compute_v<AsmBindingsAnalysis, analysis::AsmBindingFacts>(
                fn.name, fn.version,
                [&]() { return analysis::compute_asm_bindings(fn); });
    };
    auto facts_of = [&](IrFunction &fn) -> const analysis::IrFacts & {
        return am
            .get_or_compute_v<analysis::IRFactsAnalysis, analysis::IrFacts>(
                fn.name, fn.version,
                [&]() { return analysis::build_ir_facts(fn); });
    };
    auto ranges_of = [&](IrFunction &fn) -> const analysis::RangeFacts & {
        return am
            .get_or_compute_v<analysis::RangeAnalysis, analysis::RangeFacts>(
                fn.name, fn.version,
                [&]() { return analysis::compute_ranges(fn, facts_of(fn)); });
    };
    auto hechos_asm_de = [&](IrFunction &fn) {
        HechosDeAsmParaDse h;
        h.ligaduras = &asm_of(fn);
        h.estructura = &facts_of(fn);
        h.rangos = &ranges_of(fn);
        return h;
    };
    /* Lo que el modelo de efectos contesto de cada funcion, guardado entre
     * pasadas.  Vive aqui porque aqui se sabe cuando una funcion cambia, que es
     * lo unico que puede invalidarlo. */
    std::unordered_map<std::string, CacheEfectosDce> cache_efectos;
    /* Por funcion: ¿cambio algo que afecte a los EFECTOS desde el ultimo
     * calculo?  Va aparte de la marca general porque hay un pase que cambia la
     * funcion sin tocarlos, y con una sola bandera cada consumidor acaba
     * tirando lo suyo por lo que le hizo otro. */
    std::unordered_map<std::string, bool> efectos_sucios_de;
    auto pt_invalidate = [&](IrFunction &fn) {
        /* Lo que el modelo dijo de sus instrucciones se apoya en estos mismos
         * hechos, asi que cae con ellos.  Una sola senal de invalidacion para
         * todo lo que depende de la funcion, no una por consumidor. */
        cache_efectos[fn.name].invalidar();
        am.invalidate<analysis::IRFactsAnalysis>(fn.name); // cascada a PointsTo
    };

    // Iterar hasta punto fijo o maximo 8 pasadas
    /* Las tres tablas se llenan ANTES del bucle.
     *
     * Hasta ahora se insertaba dentro, al tocar cada funcion, lo que es
     * correcto en fila de uno pero imposible de repartir: insertar en un
     * `unordered_map` puede rehacerlo entero, y otro hilo leyendo a la vez ve
     * basura.  Pre-llenadas, cada hilo solo ESCRIBE su propia entrada y ninguna
     * insercion ocurre durante el bucle, que es lo que lo hace seguro sin
     * ningun cerrojo.
     *
     * `true` de arranque porque la primera vez no hay nada calculado, que es lo
     * mismo que hacia el `emplace(fn.name, true)` de dentro. */
    for (auto &fn : mod.functions) {
        if (fn.is_native) continue;
        sucias.emplace(fn.name, true);
        efectos_sucios_de.emplace(fn.name, true);
        cache_efectos[fn.name];
    }

    /* Tope ANTI-CUELGUE, no un mando de cuanto optimizar.
     *
     * El bucle sale solo en cuanto ninguna funcion cambia, asi que lo normal es
     * no acercarse: cada programa da las vueltas que pide.  Esto solo esta para
     * que dos pases que se deshagan el trabajo mutuamente no dejen al
     * compilador girando para siempre.
     *
     * Estuvo en 8, y ese numero SI decidia calidad: con el reparto por hilos
     * los hechos interprocedurales tardan una vuelta mas en propagarse, 38 de
     * los 440 ejemplos se quedaban cortos, y el binario salia hasta 21 KB mas
     * grande -- callando, porque agotar el tope no se contaba.  Ahora se cuenta
     * (@c fixpoint_truncations): si esto se toca, el aviso es que hay dos
     * pases peleandose, y la respuesta es mirarlos, no subir el numero. */
    constexpr int kAntiHangCap = 64;
    for (int pass = 0; pass < kAntiHangCap; ++pass) {
        // Atomico: lo escriben todos los hilos y solo se pone a true, nunca a
        // false, asi que basta un `store` relajado -- lo que importa es que se
        // vea al cerrar la vuelta, y ahi hay una barrera de por medio.
        std::atomic<bool> any{false};

        /* Repartido entre hilos.  Cada funcion se optimiza sola: las tres
         * tablas estan pre-llenadas -- ninguna insercion durante el bucle --
         * y el gestor de analisis protege las suyas sin tener el cerrojo
         * puesto mientras calcula.  `VESTA_PARALELO=0` vuelve a fila de uno,
         * que es con lo que se comprueba que el `.velb` sale identico. */
        {
            /* El bucle en su propio ambito para que el cronometro mida SOLO el
             * bucle: declarado suelto mediria hasta el final de la vuelta y se
             * comeria el tramo cross-modulo que viene detras.
             *
             * (pared) en el nombre porque esto reparte entre hilos: lo que mide
             * es reloj de pared de la region, mientras que los contadores por
             * pase de mas abajo suman CPU de TODOS los hilos.  Restar unos de
             * otros no significa nada, y confundirlos ya llevo a buscar 330 ms
             * que no existian. */
            CronoTramo crono_fn__("opt:bucle-por-funcion (pared)");
            for_each_function(mod, [&](IrFunction &fn) {
                if (fn.is_native) return; // no optimizar stubs nativos

                /* Referencia, no copia: la marca tiene que sobrevivir a la
                 * vuelta. La primera vez se inserta en true (no hay nada
                 * calculado aun). */
                auto it_sucia = sucias.emplace(fn.name, true).first;
                bool &sucia = it_sucia->second;
                /* Referencia, no busqueda por vuelta: esto esta en el bucle por
                 * funcion y se consulta en cada pase.  Empieza en true porque
                 * al principio no hay nada guardado. */
                auto it_ef = efectos_sucios_de.emplace(fn.name, true).first;
                bool &efectos_sucios = it_ef->second;

                // O1: copy + simplify + SR + reassoc + dead-alloc + DCE
                APLICA(ir_pass_copy_prop(fn));
                APLICA(ir_pass_simplify(
                    fn)); /* algebraic + cast fold + phi simp */
                APLICA(
                    ir_pass_narrow_cmp(fn)); /* cmp(ext(x),K) -> cmp.<W>(x,K) */
                // Contraccion FMA (fmul+fadd -> fma) DESPUES de simplify, que
                // ya quito a*0/a*1/+0.  Gated por @fp(fast) (fn.fp_contract).
                // Decision unica en el IR -> interp/JIT/AOT consistentes (1
                // redondeo).
                APLICA(ir_pass_fuse_fma(fn));
                /* Consumidores de ValueFacts: computan el analisis UNA vez y lo
                 * comparten -- elim SEXT/ZEXT/AND-mask + fold de CMP probado +
                 * strength reduction (MUL/DIV/MOD por 2^k -> shift/and,
                 * incluido el caso signed cuando el dividendo se prueba
                 * no-negativo). */
                APLICA(ir_pass_valuefacts_consumers(fn));
                APLICA(ir_pass_reassoc(
                    fn)); /* (x op c1) op c2 -> x op (c1 op c2) */
                // LICM RECIBE la tabla points-to del AnalysisManager (no la
                // construye).  Solo se pide si el LICM alias-aware esta activo
                // (coste 0 en el default: el manager no computa nada).
                if (g_licm_alias) {
                    /* Solo si algo la ha tocado desde el ultimo calculo. */
                    if (sucia) {
                        pt_invalidate(fn);
                        sucia = false;
                    }
                    APLICA(ir_pass_licm(fn, &pt_of(fn), &pure_callees));
                } else {
                    APLICA(ir_pass_licm(fn)); /* LICM con dominators reales */
                }
                APLICA(ir_pass_dead_alloc_elim(fn));
                /* Y detras, los huecos de PILA que nadie lee.  Va aqui y no
                 * antes porque necesita que la promocion a pila y el reenvio de
                 * lecturas ya hayan corrido: hasta entonces el hueco TIENE
                 * lectores. Se apaga con VESTA_NO_DEAD_STACK_SLOT=1 para poder
                 * comparar. */
                if (!g_no_dead_stack_slot)
                    APLICA(ir_pass_dead_stack_slot_elim(fn));
                /* Si algo toco la funcion desde el ultimo calculo, lo guardado
                 * del modelo ya no describe estas instrucciones.  Hay que
                 * mirarlo AQUI y no solo en `pt_invalidate`: esa senal se emite
                 * antes de LICM y del DSE, y entre ella y este punto corren mas
                 * pases que pueden cambiar una instruccion SIN cambiar cuantas
                 * hay -- con lo que ni la comprobacion de tamano lo veria. */
                if (efectos_sucios) {
                    cache_efectos[fn.name].invalidar();
                    efectos_sucios = false; // queda refrescada en esta ronda
                }
                APLICA_PRESERVA_EFECTOS(ir_pass_dce(
                    fn, &decls_nativas, &asm_of(fn), &cache_efectos[fn.name]));
                /* Punto seguro: terminado con esta funcion, ya no se va a usar
                 * ninguna referencia que diera el gestor.  Sin soltarlas, el
                 * respaldo que las mantiene vivas frente a una invalidacion
                 * ajena creceria hasta el final del proceso. */
                am.release_retained();

                if (level >= OptLevel::O2) {
                    // O2: plegado de constantes + bloques inalcanzables + TCO.
                    APLICA(ir_pass_const_fold(fn));
                    // If-conversion: diamante/if-anidado/ternario -> SELECT
                    // (solo legalidad; la rentabilidad la decide el pase de
                    // coste cercano al backend).  Debe preceder a `unreachable`
                    // para que este limpie los bloques de rama que quedan
                    // vacios.  El SELECT es una primitiva SEMANTICA: el JIT/AOT
                    // lo bajan a cmov, y el INTERPRETE a la super-instruccion
                    // `csel` (1 despacho).
                    APLICA_N(ir_pass_if_conversion(fn));
                    // Canonicalizacion algebraica de los SELECT recien creados
                    // (select(c,x,x)->x, ->imin/imax, anidados, ...) antes de
                    // que el resto de pases (DCE/CSE) los vean.
                    APLICA_N(ir_pass_select_simplify(fn));
                    APLICA(ir_pass_unreachable(fn));
                    APLICA(ir_pass_tailcall(fn));
                    // Inline de header trivial de loop -> habilita decjnz
                    // fusion.
                    APLICA(ir_pass_inline_loop_header(fn));
                    // Dead store elimination: limpia STOREs muertos
                    // consecutivos. Con Fase 4, las CALL a callees puros no
                    // cortan el forwarding. Recibe la tabla points-to del
                    // manager (no la construye).
                    if (g_dse_unified) {
                        /* Solo si algo la ha tocado desde el ultimo calculo. */
                        if (sucia) {
                            pt_invalidate(fn);
                            sucia = false;
                        }
                        {
                            const HechosDeAsmParaDse h__ = hechos_asm_de(fn);
                            APLICA(ir_pass_dse(fn, &pt_of(fn), &pure_callees,
                                               &h__));
                        }
                    } else {
                        {
                            const HechosDeAsmParaDse h__ = hechos_asm_de(fn);
                            APLICA(
                                ir_pass_dse(fn, nullptr, &pure_callees, &h__));
                        }
                    }
                    // Global const CSE solamente (safer than full CSE).
                    // El full CSE local tiene bugs sutiles con LOAD/STORE alias
                    // que necesitan alias analysis (deferido a O3+).
                    // Global const dedup via DIRECT rewrite (no MOV+copy_prop
                    // intermedio).  La version vieja con MOV dejaba is_const
                    // stale en fn.values causando fallos no-deterministicos en
                    // test 110 (smart pointers SRET).  Esta version sustituye
                    // operandos directamente y elimina las CONSTs duplicadas.
                    APLICA(ir_pass_const_cse_entry(fn));
                    // CSE local de aritmetica pura (ADD/SUB/MUL/etc.) --
                    // dedupea `add.ptr this, off` triplicados en
                    // getters/setters.  Tiene invalidacion correcta para LOAD
                    // via side-effects.  Habilita store-to-load forwarding al
                    // unificar punteros equivalentes.
                    APLICA(ir_pass_cse(fn));
                    // Load Narrow: elide SEXT redundante tras LOAD i8/i16/i32
                    // cuando todos los usos son arith narrow-safe (ADD/SUB/MUL/
                    // AND/OR/XOR) + STORE/RET del mismo ancho.  Ahorra 3 instr
                    // VM por LOAD elidido.  Bench struct_field: ~270M instr
                    // ahorradas.
                    APLICA(ir_pass_load_narrow(fn));
                    // Elision COMPTIME de unwrap: si el valor es provably
                    // non-null (CONST!=0, &local/ALLOCA, STR_LIT_ADDR,
                    // LABEL_ADDR, Some(const) tras const-prop/SLF) el UNWRAP se
                    // vuelve MOV -> copy_prop/DCE lo borran -> cero overhead.
                    // Beneficia VM/JIT/AOT.
                    APLICA(ir_pass_elide_unwrap(fn));
                    // Suma/resta cuyo acarreo se deduce comparando el resultado
                    // con un sumando: la maquina ya dejo esa respuesta en un
                    // flag, asi que se marca el par para leerla en vez de
                    // recalcularla. Va despues del CSE porque este unifica los
                    // operandos y deja la comparacion pegada a su suma, que es
                    // lo que el patron necesita.
                    APLICA(ir_pass_carry_idiom(fn));
                    // Segunda ronda de DCE tras plegado/TCO/loop header
                    // inline/CSE.
                    /* Misma razon que arriba: entre medias han corrido pases
                     * que pueden haber cambiado instrucciones sin cambiar su
                     * numero. */
                    if (efectos_sucios) {
                        cache_efectos[fn.name].invalidar();
                        efectos_sucios = false;
                    }
                    APLICA_PRESERVA_EFECTOS(
                        ir_pass_dce(fn, &decls_nativas, &asm_of(fn),
                                    &cache_efectos[fn.name]));
                }

                if (level >= OptLevel::O3) {
                    // O3: pasadas mas costosas (GVN, scheduling, etc.) -- TBD.
                }
            });
        } // fin del ambito del cronometro del bucle

        CronoTramo crono_cross__("opt:cross-modulo devirt+inline (pared)");
        /* Devirt + inline @ O2 al final de cada iteracion del fix-point.
         * Importante hacerlo despues de las per-function passes para que
         * la inline pass vea las callees OPTIMIZADAS (e.g. Counter.inc
         * con 6 instrs en vez de 12), aprobando inline bajo el threshold. */
        if (level >= OptLevel::O2) {
            // Devirt de cfn constante (CALLIND a LABEL_ADDR -> CALL directo),
            // antes del inline para que el callback conocido se pueda inlinar.
            for (auto &fn : mod.functions) {
                if (ir_pass_devirt_cfn(fn)) any = true;
            }
            if (ir_pass_devirt_monomorphic(mod)) any = true;

            /* (C2): devirt especulativa ESTATICA via guard-chain.
             * Corre tras el devirt monomorfico (que ya resolvio los sites
             * de clase concreta) y ANTES del inline, para que este ultimo
             * procese los CALL directos del fast path.  Lee los candidatos
             * que el lowering registro en fn.spec_devirt_sites.
             * Skippable via VESTA_NO_SPEC_DEVIRT=1 para A/B testing. */
            {
                if (!g_no_spec_devirt) {
                    for (auto &fn : mod.functions) {
                        if (fn.is_native) continue;
                        if (ir_pass_spec_devirt(fn)) any = true;
                    }
                }
            }

            if (allow_inline && ir_pass_inline(mod)) any = true;

            /* Plegado de `a + b` cuando las dos son literales conocidos.  En el
             * fix-point y DESPUES del inline: asi ve tambien las cadenas que
             * llegan por variables (tras promover los allocas, `%a` es el
             * STRMAKE) o desde otra funcion ya inlineada.  Y como el resultado
             * es otro STRMAKE de literal, `a + b + c` se pliega en dos vueltas.
             * El DCE de mas abajo se lleva los STRMAKE que queden sin usar. */
            if (ir_pass_fold_strcat(mod)) any = true;

            /* Inline MULTI-bloque: tras el single-block, inlinar callees con
             * ramas (`if`, etc.) pequenos.  Junta mas codigo en la misma fn
             * (habilita const-fold/CSE/scalar-replace cross-call de funciones
             * con control de flujo).  Semantica-preservante. */
            if (allow_inline && ir_pass_inline_multiblock(mod)) any = true;

            /*  C2.13: Scalar Replacement de objetos GC no-escapantes.
             * Corre DESPUES del inline (que junta el alloc + los field-access
             * en la misma fn).  Sus reescrituras (loads -> trunc/mov/const)
             * las limpia el const_fold/dce de la siguiente iteracion del
             * fix-point; el alloc GC desaparece por completo.
             * Skippable via VESTA_NO_ESCAPE_SCALAR=1 para A/B testing. */
            {
                if (!g_no_escape_scalar) {
                    for (auto &fn : mod.functions) {
                        if (fn.is_native) continue;
                        if (ir_pass_scalar_replace_gc(fn, mod)) any = true;
                    }
                }
            }

            /* SROA/mem2reg de structs value-type en PILA (ALLOCA).  GC-free:
             * escalariza campos a registros, quita load/store del hot loop.
             * Beneficia AOT (sin GC) y JIT por igual.  Kill:
             * VESTA_NO_SROA_STACK. */
            for (auto &fn : mod.functions) {
                if (fn.is_native) continue;
                if (ir_pass_sroa_stack_structs(fn)) any = true;
            }
        }

        /* Cuantas vueltas se dieron de verdad, y sobre cuantas funciones.  Sin
         * estos dos numeros el coste por pase no se puede interpretar: mil
         * llamadas pueden ser muchas funciones baratas o pocas carisimas
         * repetidas, y se arreglan de formas opuestas.  Llegar al tope sin
         * converger es ademas un sintoma por si solo. */
        /* ACUMULAN, no se asignan: `ir_optimize` corre una vez por MODULO y
         * antes cada llamada pisaba a la anterior, con lo que el numero no
         * cuadraba con las llamadas contadas por pase (244 frente a 822) y
         * hacia parecer que un pase se llamaba de mas.  Un contador que no
         * cuadra con lo que mide es peor que no tenerlo. */
        vueltas_punto_fijo() += 1;
        visitas_a_funcion() += static_cast<long long>(mod.functions.size());
        if (!any.load(std::memory_order_relaxed)) break; // punto fijo
        /* Se agoto el tope y algo seguia cambiando: el optimizador se rinde a
         * medias.  Queda anotado porque un binario peor sin ninguna senal es
         * exactamente lo que costo descubrir esto. */
        if (pass + 1 == kAntiHangCap) fixpoint_truncations() += 1;
    }

    /* Stack-first (2a pasada): re-correr la promocion malloc->stack TRAS el
     * fix-point.  El idiom @c unique<T> carga el box de vuelta desde su slot
     * en la version sin optimizar; la primera pasada (pre-fixpoint) ve ese
     * LOAD y descarta el slot como "vivo".  DSE/copy-prop dentro del
     * fix-point eliminan ese LOAD -> aqui el slot ya es write-only y la regla
     * "slot local muerto" dispara, convirtiendo el malloc en `sub rsp, N`.
     * Skippable con el mismo VESTA_NO_PROMOTE_RAW_ALLOC. */
    if (level >= OptLevel::O1) {
        if (!g_no_promote_raw_alloc) {
            bool any2 = false;
            for (auto &fn : mod.functions) {
                if (!fn.is_native) any2 |= ir_pass_promote_local_raw_alloc(fn);
            }
            /* Si promovio algo, una limpieza DCE para barrer valores muertos
             * (size const del malloc, etc.). */
            if (any2) {
                for (auto &fn : mod.functions) {
                    if (fn.is_native) continue;
                    util::CronoTramo crono__("  dce:limpieza-orquestada");
                    ir_pass_dce(fn, &decls_nativas);
                }
            }
        }
    }

    /*  C2.13: DETECCION (log-only) de objetos GC no-escapantes.  Corre
     * tras el fix-point (con el IR ya inlineado + optimizado, que es donde el
     * escape es visible: el alloc + los field-access estan en la misma fn).
     * No transforma el IR; solo loguea bajo VESTA_ESCAPE_DEBUG. */
    if (level >= OptLevel::O2) {
        for (auto &fn : mod.functions) {
            if (fn.is_native) continue;
            ir_pass_escape_detect_gc(fn);
        }
    }

    /* Desenrollado de bucles: tras el fix-point (el cuerpo ya esta inlineado/
     * optimizado -> las metricas reflejan el cuerpo FINAL) y ANTES del
     * scheduling (que vera el cuerpo desenrollado con mas ILP).  El
     * transformador NO decide el factor: lo hace la politica (unroll_policy)
     * sobre metricas NEUTRALES.  Beneficia a los 3 backends: el interprete
     * ahorra despachos de la guarda/incremento, JIT/AOT exponen ILP y rompen la
     * dependencia del acumulador de los bucles reducidos.  Tras clonar, una
     * limpieza local (copy-prop + CSE + const-fold + DCE) optimiza las copias
     * (dedup de direcciones, plegado de indices).  Kill: VESTA_NO_UNROLL=1. */
    /* Un bucle que resulta ser un movimiento de memoria se reduce a la
     * operacion de bloque.  ANTES del desenrollador, y el orden es parte del
     * arreglo: desenrollar primero multiplica el codigo de un bucle que iba a
     * desaparecer entero. */
    if (level >= OptLevel::O1) {
        for (auto &fn : mod.functions) {
            if (fn.is_native) continue;
            if (ir_pass_bulk_memory_lower(fn)) {
                ir_pass_unreachable(fn);
                util::CronoTramo crono__("  dce:limpieza-orquestada");
                ir_pass_dce(fn);
            }
        }
    }

    if (level >= OptLevel::O2) {
        for (auto &fn : mod.functions) {
            if (fn.is_native) continue;
            if (ir_pass_unroll(fn)) {
                ir_pass_copy_prop(fn);
                ir_pass_cse(fn);
                ir_pass_const_fold(fn);
                util::CronoTramo crono__("  dce:limpieza-orquestada");
                ir_pass_dce(fn, &decls_nativas);
            }
        }
    }

    /* Final pass: list scheduling para ILP.  Una sola pasada despues del
     * fix-point porque el reordenamiento NO produce mas oportunidades de
     * optimizacion (es semanticamente neutro -- mismo DAG, distinto orden).
     * Solo aplica @ O2+ por seguridad. */
    if (level >= OptLevel::O2) {
        for (auto &fn : mod.functions) {
            if (fn.is_native) continue;
            // El scheduler RECIBE la tabla points-to del manager (no la
            // construye).  Solo se pide si el scheduler alias-aware esta
            // activo.
            if (g_sched_alias) {
                pt_invalidate(fn); // fresca: el fix-point muto el IR
                ir_pass_schedule(fn, &pt_of(fn), &pure_callees);
            } else {
                ir_pass_schedule(fn, nullptr, &pure_callees);
            }
        }
    }

    /* NOTA DE ARQUITECTURA (coalescencia de PHI): NO se reescribe el SSA aqui.
     *
     * El approach de "IR-rewrite" (fusionar valores congruentes en un vreg
     * multi-def a nivel IR) es FRAGIL: crea multi-def y expone bugs latentes en
     * el out-of-SSA de cada backend (rematerializacion de const en vreg_select,
     * arg de entrada de un phi de loop, merges transitivos).  Cada uno era un
     * parche a un sintoma de la MISMA causa: reescribir el SSA cuando no se
     * debe.
     *
     * Modelo ROBUSTO: la DECISION de congruencia se computa una sola vez sobre
     * el IR (jit::ssa_phi_coalesce_remap, funcion pura del IR) y cada backend
     * la CONSUME en su out-of-SSA/regalloc SIN tocar el SSA:
     *   - CTPE (debug, env-gated): loguea que funciones son EVALUABLES en
     *     compile-time.  Valida el analisis de evaluabilidad sin ejecutar nada.
     *     Cero coste sin VESTA_CTPE_DEBUG.  (bloque justo antes del cierre.)
     *   - interp: allocate_regs opera sobre valores canonicos (root de cada
     *     clase, intervalos unidos) y expande reg_map a los miembros -> valores
     *     congruentes comparten registro VM, las copias phi intra-clase quedan
     *     no-op.  (Ver src/ir/ir_emitter.cpp + src/ir/regalloc.cpp.)
     *   - JIT/AOT: apply_ssa_coalesce remapea los vregs de la MachineIR tras el
     *     lowering, manteniendo el IR en SSA (sound, default-on).
     * Sin multi-def -> sin ninguno de los edge cases.  El copy coalescing
     * especifico de maquina (2-address `mov dst,src1`) lo hace ademas el
     * coalesce_hint del linear-scan (otro nivel, copias que el IR no ve). */

    // Orden canonico topologico (RPO) de los bloques de CADA funcion antes de
    // que el IR se use (emit al .velb, JIT/vreg, CTPE).  El emisor de bytecode
    // y el codegen del JIT vreg asumen orden ~control-flow (fall-through a
    // bid+1, liveness lineal); una funcion con cadenas if/else-if que RETORNA
    // STRUCT (SRET) podia quedar con el bloque EPILOGO en medio (orden NO
    // topologico) -> el JIT la compilaba mal (retbuf/PHIs perdidos) aunque el
    // interprete la ejecutara bien.  RPO lo canoniza para AMBOS backends (y
    // para CTPE, que usa el JIT).  Solo reordena; no cambia la semantica.
    for (auto &fn : mod.functions)
        reorder_blocks_rpo(fn);

    // --- CTPE (debug): validacion del analisis de evaluabilidad + candidatos.
    // ---
    if (util::flag_on(util::FlagId::CtpeDebug)) {
        ctpe::Evaluability ev = ctpe::compute_evaluability(mod);
        for (const auto &fn : mod.functions) {
            if (ev.is_evaluable(fn.name)) {
                fprintf(stderr, "[ctpe] EVALUABLE  %s\n", fn.name.c_str());
            } else {
                auto it = ev.reason.find(fn.name);
                if (it != ev.reason.end())
                    fprintf(stderr,
                            "[ctpe] no         %s  (op=%d pol=%d callee='%s' "
                            "L%u)\n",
                            fn.name.c_str(), (int)it->second.op,
                            (int)it->second.policy, it->second.callee.c_str(),
                            it->second.source_line);
                else
                    fprintf(stderr, "[ctpe] no         %s\n", fn.name.c_str());
            }
        }
        std::vector<ctpe::Candidate> cands = ctpe::find_candidates(mod, ev);
        for (const auto &c : cands)
            fprintf(stderr, "[ctpe] CANDIDATO  %s  (ret escalar=%d)\n",
                    c.fn.c_str(), (int)c.ret_type);
    }

    /* Cuanto se REUSA de verdad.  Es lo que dice si cachear analisis por
     * funcion puede servir de algo aqui: si casi todo sale CADUCADO, la funcion
     * cambia entre consultas y no hay reuso posible por mucho que se afine. */
    if (util::flag_on(util::FlagId::Times)) {
        const auto c = am.cuentas();
        const long long total = c.aciertos + c.caducados + c.nuevos;
        std::fprintf(stderr,
                     "[gestor] consultas=%lld aciertos=%lld (%.0f %%) "
                     "caducados=%lld nuevos=%lld\n",
                     total, c.aciertos,
                     total ? 100.0 * double(c.aciertos) / double(total) : 0.0,
                     c.caducados, c.nuevos);
    }
}

// Set global de helpers @c __new_<X> marcados como puros por el frontend.
// El frontend lo invoca cuando detecta un ctor trivial (sin @c callvirt al
// ctor user-defined); el DCE puede eliminar la llamada si el handle no se
// usa.  Coste: lookup O(1) amortizado en una sola posicion del pipeline.
static std::unordered_set<std::string> g_pure_new_helpers;

void register_pure_new_helper(const std::string &fn_name) {
    g_pure_new_helpers.insert(fn_name);
}

bool is_pure_new_helper(const std::string &fn_name) {
    return g_pure_new_helpers.count(fn_name) != 0;
}
} // namespace ir
