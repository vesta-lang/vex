/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file if_conversion.cpp
 * @brief Implementacion del pase de if-conversion (diamante/triangulo ->
 * SELECT).
 *
 * Ver @c include/ir/passes/if_conversion.h para el contrato y la separacion de
 * responsabilidades.  Este pase SOLO decide legalidad + presupuesto de tamano;
 * la rentabilidad (cmov vs salto, por microarquitectura) la decide un pase
 * posterior cercano al backend.
 *
 * Ademas del diamante simple @c if/else y el triangulo @c if sin @c else,
 * detecta los IF ANIDADOS / TERNARIOS ENCADENADOS
 * (@c (a==b)?c:(d==k)?q:h): bajan a diamantes anidados y se convierten en
 * SELECT anidados (@c select(a==b, c, select(d==k, q, h))).  Para ello, cada
 * rama se sigue como una CADENA straight-line especulable hasta el bloque de
 * merge; el diamante interno se convierte primero y en la siguiente pasada el
 * externo ya ve una cadena limpia (bucle de punto fijo interno).
 */

#include "util/env_flags.h"
#include "ir/passes/if_conversion.h"
#include "ir/passes/select_policy.h"
#include "ir/ssa_ir.h"

#include <cstdlib>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ir {
namespace {

/// Presupuesto de instrucciones especulables acumuladas en la CADENA de una
/// rama.  Es un tope de cordura (evita crear SELECT de regiones enormes), NO
/// una decision de rentabilidad: esa la afina el pase de coste cercano al
/// backend.  Generoso para permitir ternarios encadenados razonables.
constexpr int kMaxChainInstrs = 12;

/**
 * @brief Indica si @p op puede ejecutarse ESPECULATIVAMENTE al hoistearla.
 *
 * Debe carecer de efecto observable y no poder atrapar (trap) cuando la rama
 * NO se hubiera tomado.  Se excluyen: DIV y MOD (division por cero), LOAD,
 * GETFIELD y ARRAY_LOAD (fallo de pagina), STORE, las llamadas, THROW, ALLOCA
 * (efectos), y la aritmetica flotante (sus valores viven en el banco ZMM y el
 * lowering de SELECT opera sobre registros de proposito general).
 */
bool is_speculable(IrOp op) {
    switch (op) {
    case IrOp::CONST:
    case IrOp::BORROW: // copia del puntero: sin efectos, especulable
    case IrOp::MOV:
    case IrOp::ADD:
    case IrOp::SUB:
    case IrOp::MUL:
    case IrOp::NEG:
    case IrOp::IABS:
    case IrOp::IMIN:
    case IrOp::IMAX:
    case IrOp::IMINU:
    case IrOp::IMAXU:
    case IrOp::AND:
    case IrOp::OR:
    case IrOp::XOR:
    case IrOp::NOT:
    case IrOp::SHL:
    case IrOp::SHR:
    case IrOp::SAR:
    case IrOp::ROTL:
    case IrOp::ROTR:
    case IrOp::CLZ:
    case IrOp::CTZ:
    case IrOp::POPCNT:
    case IrOp::BYTESWAP:
    case IrOp::ILOG2:
    case IrOp::SEXT:
    case IrOp::ZEXT:
    case IrOp::TRUNC:
    case IrOp::CAST:
    case IrOp::BITCAST:
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
    case IrOp::SELECT: return true;
    default: return false;
    }
}

/**
 * @brief true si @p t es un tipo por el que el SELECT baja en registro GP.
 *
 * Solo enteros, booleano y puntero.  Se excluyen EXPLICITAMENTE:
 *   - @c VOID: no produce valor.
 *   - @c F32 / @c F64: viven en el banco ZMM; un SELECT flotante requiere un
 *     lowering distinto (blend/cmov de coma flotante), extension planificada.
 *   - @c HANDLE: es un GcHandle; la seleccion bit a bit es correcta pero se
 *     excluye por prudencia en esta version (el enraizado GC del resultado se
 *     validara antes de habilitarlo).
 */
bool is_gp_type(IrType t) {
    switch (t) {
    case IrType::I8:
    case IrType::I16:
    case IrType::I32:
    case IrType::I64:
    case IrType::U8:
    case IrType::U16:
    case IrType::U32:
    case IrType::U64:
    case IrType::BOOL:
    case IrType::PTR: return true;
    case IrType::VOID:
    case IrType::F32:
    case IrType::F64:
    case IrType::HANDLE: return false;
    }
    // Switch exhaustivo sobre IrType (sin default): anadir un IrType nuevo
    // dispara -Wswitch aqui y OBLIGA a decidir si el SELECT lo soporta, en
    // lugar de colarlo silenciosamente por un default.
    __builtin_unreachable();
}

/// @brief Indice id -> posicion en @c fn.blocks (robusto a ids no
/// secuenciales).
using BlockIndex = std::unordered_map<IrBlockId, size_t>;

BlockIndex build_index(const IrFunction &fn) {
    BlockIndex idx;
    idx.reserve(fn.blocks.size() * 2);
    for (size_t i = 0; i < fn.blocks.size(); ++i)
        idx[fn.blocks[i].id] = i;
    return idx;
}

/// @brief El terminador de un bloque (ultima instruccion), o nullptr si vacio.
const IrInstr *terminator(const IrBlock &b) {
    return b.instrs.empty() ? nullptr : &b.instrs.back();
}

/**
 * @brief Resultado de seguir una rama del BR_COND hasta el bloque de merge.
 *
 * @c hoist son los bloques de la cadena straight-line cuyo cuerpo hay que
 * hoistear al bloque condicion (vacio en el caso triangulo, donde la rama va
 * directa al merge).  @c lastPred es el predecesor del merge por este lado (el
 * ultimo bloque de la cadena, o el propio bloque condicion en el triangulo):
 * de el se toma el valor del phi correspondiente.
 */
struct BranchChain {
    bool ok = false;
    IrBlockId mergeId = IR_NO_VALUE;
    IrBlockId lastPred = IR_NO_VALUE;
    std::vector<IrBlock *> hoist;
    int ninstr = 0;
};

/**
 * @brief Sigue una cadena straight-line especulable desde @p startId (destino
 *        de una rama del BR_COND del bloque @p condId) hasta el bloque de merge
 *        (primer join con >= 2 predecesores).
 *
 * - Si @p startId es directamente un join (rama que va al merge sin bloque
 *   propio) devuelve una cadena vacia con @c mergeId = startId y
 *   @c lastPred = condId (caso triangulo).
 * - En otro caso recorre bloques con predecesor unico, cuerpo especulable y
 *   terminador BR incondicional, acumulandolos en @c hoist, hasta que el
 *   sucesor es un join.
 * - Devuelve @c ok=false si la cadena no es limpia (rama con salto condicional,
 *   phi, op no especulable, presupuesto excedido, o no converge en un join).
 */
BranchChain trace_branch(IrFunction &fn, const BlockIndex &idx,
                         IrBlockId startId, IrBlockId condId) {
    auto blk = [&](IrBlockId id) -> IrBlock * {
        auto it = idx.find(id);
        return it == idx.end() ? nullptr : &fn.blocks[it->second];
    };
    BranchChain r;
    IrBlock *cur = blk(startId);
    if (!cur) return r;

    // Caso triangulo: la rama va directa a un bloque de join.
    if (!(cur->preds.size() == 1 && cur->preds[0] == condId)) {
        r.ok = true;
        r.mergeId = startId;
        r.lastPred = condId;
        return r;
    }

    IrBlockId prev = condId;
    while (true) {
        // El bloque de cadena debe tener predecesor unico = prev.
        if (!(cur->preds.size() == 1 && cur->preds[0] == prev)) return r;
        const IrInstr *term = terminator(*cur);
        if (!term || term->op != IrOp::BR) return r; // sin salto condicional
        for (const auto &ins : cur->instrs) {
            if (&ins == term) break; // el BR terminal no cuenta
            if (ins.op == IrOp::PHI) return r;
            if (!is_speculable(ins.op)) return r;
            if (++r.ninstr > kMaxChainInstrs) return r;
        }
        r.hoist.push_back(cur);
        const IrBlockId succId =
            cur->succs.empty() ? IR_NO_VALUE : cur->succs[0];
        IrBlock *succ = blk(succId);
        if (!succ) return r;
        if (succ->preds.size() >= 2) { // el sucesor es el join -> merge
            r.ok = true;
            r.mergeId = succId;
            r.lastPred = cur->id;
            return r;
        }
        prev = cur->id;
        cur = succ; // el sucesor tiene pred unico -> continua la cadena
    }
}

/// @brief Devuelve el valor de un phi cuyo arg proviene de @p from, o
///        IR_NO_VALUE si el phi no tiene un arg exactamente de @p from.
IrValueId phi_arg_from(const IrInstr &phi, IrBlockId from) {
    for (const auto &pa : phi.phi_args)
        if (pa.block == from) return pa.value;
    return IR_NO_VALUE;
}

/// @brief Mapa valor -> instruccion que lo define (para reachability rapido).
using DefIndex = std::unordered_map<IrValueId, const IrInstr *>;

DefIndex build_def_index(const IrFunction &fn) {
    DefIndex di;
    for (const auto &b : fn.blocks)
        for (const auto &ins : b.instrs)
            if (ins.dst != IR_NO_VALUE) di[ins.dst] = &ins;
    return di;
}

/// @brief true si @p start depende (backward, transitivamente) de @p target;
///        es decir, el valor @p target se usa para calcular @p start.  Cota de
///        presupuesto para no recorrer todo el grafo en funciones grandes.
bool value_reaches(const DefIndex &di, IrValueId start, IrValueId target) {
    if (start == IR_NO_VALUE || target == IR_NO_VALUE) return false;
    std::vector<IrValueId> stack{start};
    std::unordered_set<IrValueId> seen;
    int budget = 512;
    while (!stack.empty() && budget-- > 0) {
        const IrValueId v = stack.back();
        stack.pop_back();
        if (v == target) return true;
        if (!seen.insert(v).second) continue;
        auto it = di.find(v);
        if (it == di.end()) continue;
        const IrInstr *d = it->second;
        for (IrValueId op : d->operands)
            stack.push_back(op);
        for (const auto &pa : d->phi_args)
            stack.push_back(pa.value);
    }
    return false;
}

/// @brief true si algun phi del merge es RECURSIVO: uno de sus args (el valor
///        del lado true o false) depende del propio dst del phi, lo que indica
///        que el resultado realimenta una recurrencia de loop (el cmov quedaria
///        en el camino critico cada iteracion).
bool merge_phi_loop_carried(const IrFunction &fn, const IrBlock &M,
                            IrBlockId truePred, IrBlockId falsePred) {
    const DefIndex di = build_def_index(fn);
    for (const auto &ins : M.instrs) {
        if (ins.op != IrOp::PHI) continue;
        const IrValueId a = phi_arg_from(ins, truePred);
        const IrValueId b = phi_arg_from(ins, falsePred);
        if (value_reaches(di, a, ins.dst) || value_reaches(di, b, ins.dst))
            return true;
    }
    return false;
}

/**
 * @brief Intenta convertir el diamante/triangulo/anidado que arranca en el
 *        bloque @p ci (indice en @c fn.blocks) si termina en BR_COND.
 * @return true si convirtio (reescribio el CFG in situ).
 */
bool try_convert(IrFunction &fn, const BlockIndex &idx, size_t ci) {
    auto blk = [&](IrBlockId id) -> IrBlock * {
        auto it = idx.find(id);
        return it == idx.end() ? nullptr : &fn.blocks[it->second];
    };

    IrBlock &C = fn.blocks[ci];
    IrInstr *term = C.instrs.empty() ? nullptr : &C.instrs.back();
    if (!term || term->op != IrOp::BR_COND) return false;
    if (term->operands.empty()) return false;
    const IrValueId cond = term->operands[0];
    if (cond == IR_NO_VALUE) return false;
    const IrBlockId tb = term->target_block; // rama cond==true
    const IrBlockId fb = term->false_block;  // rama cond==false

    // Seguir ambas ramas hasta su merge; deben converger en el MISMO bloque.
    const BranchChain tc = trace_branch(fn, idx, tb, C.id);
    const BranchChain fc = trace_branch(fn, idx, fb, C.id);
    if (!tc.ok || !fc.ok) return false;
    if (tc.mergeId != fc.mergeId) return false;

    const IrBlockId mergeId = tc.mergeId;
    if (mergeId == C.id) return false;
    const IrBlockId truePred = tc.lastPred;  // origen del valor si cond=true
    const IrBlockId falsePred = fc.lastPred; // origen del valor si cond=false
    if (truePred == falsePred) return false; // ambos caminos convergerian

    IrBlock *M = blk(mergeId);
    if (!M) return false;

    // El merge debe tener EXACTAMENTE los dos predecesores del patron; si otro
    // camino alcanza M no se puede colapsar el control de flujo.
    if (M->preds.size() != 2) return false;
    const bool preds_ok =
        (M->preds[0] == truePred && M->preds[1] == falsePred) ||
        (M->preds[0] == falsePred && M->preds[1] == truePred);
    if (!preds_ok) return false;

    // Todos los phi de M deben ser convertibles (2 args de {truePred,
    // falsePred}, tipo GP, no objeto GC).  Si alguno no lo es, se aborta.
    for (const auto &ins : M->instrs) {
        if (ins.op != IrOp::PHI) continue;
        if (ins.phi_args.size() != 2) return false;
        if (!is_gp_type(ins.type)) return false;
        if (ins.dst != IR_NO_VALUE &&
            static_cast<size_t>(ins.dst) < fn.values.size() &&
            fn.values[ins.dst].is_gc_object)
            return false;
        if (phi_arg_from(ins, truePred) == IR_NO_VALUE ||
            phi_arg_from(ins, falsePred) == IR_NO_VALUE)
            return false;
    }

    // --- Politica de rentabilidad (modelo mixto) ---------------------------
    // La LEGALIDAD ya esta comprobada; ahora se decide si CONVIENE la forma
    // SELECT o mantener el branch.  El coste de cada rama es su numero de
    // instrucciones especulables (proxy); loop-carried = el resultado
    // realimenta una recurrencia (cmov en el camino critico).  El escape
    // VESTA_IF_CONVERSION_ALL=1 fuerza convertir siempre (A/B testing).
    static const bool force_all = util::flag_on(util::FlagId::IfConversionAll);
    if (!force_all) {
        const bool loop_carried =
            merge_phi_loop_carried(fn, *M, truePred, falsePred);
        // Linea fuente del branch (para el predictor de perfil/PGO): la del
        // BR_COND, o la de la definicion del cond si aquel no la lleva.
        uint32_t src_line = term->source_line;
        if (src_line == 0) {
            for (const auto &bb : fn.blocks)
                for (const auto &ii : bb.instrs)
                    if (ii.dst == cond) {
                        src_line = ii.source_line;
                        break;
                    }
        }
        if (!prefer_select(fn, cond, src_line, tc.ninstr, fc.ninstr,
                           loop_carried))
            return false; // el modelo prefiere el branch -> no convertir
    }

    // --- Reescritura -------------------------------------------------------
    // 1. Recolectar el cuerpo (sin terminador) de todos los bloques de ambas
    //    cadenas, en orden, y vaciar esos bloques (quedan inalcanzables tras
    //    desconectar C; los elimina el pase de bloques inalcanzables).
    std::vector<IrInstr> hoisted;
    auto drain = [&](const std::vector<IrBlock *> &chain) {
        for (IrBlock *B : chain) {
            if (B->instrs.empty()) continue;
            const size_t n = B->instrs.size() - 1; // excluye el BR terminal
            for (size_t i = 0; i < n; ++i)
                hoisted.push_back(std::move(B->instrs[i]));
            IrInstr br;
            br.op = IrOp::BR;
            br.type = IrType::VOID;
            br.dst = IR_NO_VALUE;
            br.target_block = mergeId;
            B->instrs.clear();
            B->instrs.push_back(br);
            B->preds.clear();
            B->succs.clear();
        }
    };
    drain(tc.hoist);
    drain(fc.hoist);

    IrBlock &Cref = fn.blocks[ci];
    // Insertar el cuerpo hoisteado justo ANTES del terminador BR_COND de C.
    if (!hoisted.empty())
        Cref.instrs.insert(Cref.instrs.end() - 1,
                           std::make_move_iterator(hoisted.begin()),
                           std::make_move_iterator(hoisted.end()));

    IrBlock *Mref = blk(mergeId);
    // 2. Convertir cada phi de M en un SELECT.
    for (auto &ins : Mref->instrs) {
        if (ins.op != IrOp::PHI) continue;
        const IrValueId a = phi_arg_from(ins, truePred);  // valor si cond
        const IrValueId b = phi_arg_from(ins, falsePred); // valor si !cond
        ins.op = IrOp::SELECT;
        ins.operands.clear();
        ins.operands.push_back(cond);
        ins.operands.push_back(a);
        ins.operands.push_back(b);
        ins.phi_args.clear();
    }

    // 3. Colapsar el control de flujo: C -> M directo.
    IrInstr &cterm = Cref.instrs.back();
    cterm.op = IrOp::BR;
    cterm.operands.clear();
    cterm.target_block = mergeId;
    cterm.false_block = IR_NO_VALUE;

    // 4. Actualizar el CFG: C sucede solo a M; M solo desde C.
    Cref.succs.clear();
    Cref.succs.push_back(mergeId);
    Mref->preds.clear();
    Mref->preds.push_back(C.id);
    return true;
}

} // namespace

int ir_pass_if_conversion(IrFunction &fn) {
    // Escape de emergencia (diagnostico / bisecar regresiones).
    static const bool disabled = util::flag_on(util::FlagId::NoIfConversion);
    if (disabled) return 0;

    int total = 0;
    // Punto fijo interno: cada pasada convierte los diamantes cuyas ramas ya
    // son cadenas limpias.  Un IF anidado necesita que el interno se convierta
    // primero (pasada N) para que el externo vea una cadena limpia (pasada
    // N+1).  Se rehace el indice en cada pasada porque los CFG cambian.
    bool changed = true;
    while (changed) {
        changed = false;
        const BlockIndex idx = build_index(fn);
        for (size_t ci = 0; ci < fn.blocks.size(); ++ci) {
            if (try_convert(fn, idx, ci)) {
                ++total;
                changed = true;
            }
        }
    }
    return total;
}

} // namespace ir
