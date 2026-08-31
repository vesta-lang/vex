/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file escape.cpp
 * @brief Implementacion de EscapeAnalysis: COMPLETA (cada op modelado, sin
 * bail)
 *        + INTERPROCEDURAL (los CALL resuelven captura via el summary del
 *        callee, cerrado por punto-fijo).
 */
#include "analysis/escape/escape.h"

#include "ir/ir_vec_ops.h" // cuales son las operaciones vectoriales
#include "ir/ssa_ir.h"

#include <deque>

namespace analysis {

char EscapeAnalysis::ID = 0;

namespace {

using ir::IrOp;

// ¿La posicion (op, idx) usa el operando como DIRECCION de memoria
// (leer/escribir su CONTENIDO, sin capturar el puntero)?  Lista COMPLETA de
// accesos a memoria.
bool is_address_operand(IrOp op, size_t idx) {
    // Ops VECTORIALES: todos sus operandos-puntero son DIRECCIONES (leen/
    // escriben memoria, no capturan el puntero), asi que la posicion da igual.
    // Se resuelven antes del switch para no repetir la lista: enumerarlas a
    // mano ya dejo fuera VEC_FMA_S, y una operacion que falte aqui cae al
    // `default` -- se da su puntero por capturado y el objeto escapa, que es
    // el lado seguro, pero pierde la optimizacion sin decirlo.
    if (is_vec_op(op)) {
        (void)idx;
        return true;
    }
    switch (op) {
    case IrOp::LOAD: return idx == 0;
    case IrOp::STORE: return idx == 1; // [0]=valor (captura), [1]=addr
    case IrOp::GETFIELD: return idx == 0;
    case IrOp::SETFIELD: return idx == 0; // base; el valor es captura
    case IrOp::GCWB_IR: return idx == 0;
    case IrOp::ARRAY_LOAD: return idx == 0;
    case IrOp::ARRAY_STORE: return idx == 0; // base; index/valor no-address
    case IrOp::ARRAY_LEN: return idx == 0;
    case IrOp::STRLEN:
    case IrOp::STRGETBYTES:
    case IrOp::STRHASH: return idx == 0;
    case IrOp::MEMCPY: return idx == 0 || idx == 1; // dst, src (contenido)
    case IrOp::MEMSET: return idx == 0; // dst (contenido); val es escalar
    default: return false;
    }
}

// ¿op es una DERIVACION de puntero (su resultado es un puntero derivado cuya
// raiz decide points_to)?  Se resuelve TRANSITIVAMENTE: el operando no captura
// si el resultado sigue siendo la MISMA raiz.
bool is_derivation(IrOp op) {
    switch (op) {
    case IrOp::GEP:
    case IrOp::ADD:
    case IrOp::SUB:
    case IrOp::BITCAST:
    case IrOp::CAST:
    case IrOp::MOV:
    case IrOp::GCDEREF_IR:
    case IrOp::GC_DEREF_HOST:
    case IrOp::GC_HANDLE_FOR_PTR:
    case IrOp::UNWRAP:
    case IrOp::MVTAKE_IR: return true;
    default: return false;
    }
}

// ¿op LEE el valor del puntero sin capturarlo (comparacion / test)?  No escapa.
bool is_comparison(IrOp op) {
    switch (op) {
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
    case IrOp::ISNULL:
    case IrOp::INSTANCEOF: return true;
    default: return false;
    }
}

// ¿op es una llamada ESTATICA (callee conocido por nombre) cuyos args resuelven
// captura via el summary del callee?
bool is_static_call(IrOp op) {
    return op == IrOp::CALL || op == IrOp::TAILCALL;
}
// ¿op es una llamada DINAMICA/nativa (callee desconocido -> captura todos)?
bool is_dynamic_call(IrOp op) {
    switch (op) {
    case IrOp::CALLVIRT:
    case IrOp::CALLM:
    case IrOp::CALLITF:
    case IrOp::CALLIND:
    case IrOp::CALLCLOSURE:
    case IrOp::CALLN:
    case IrOp::CALLSUPER: return true;
    default: return false;
    }
}

} // namespace

EscapeInfo compute_escape(const ir::IrFunction &fn, const IrFacts &facts,
                          const PointsTo &pt,
                          const CalleeEscapesParam &callee) {
    (void)facts;
    EscapeInfo out;
    using K = effects::AbstractLoc::Kind;

    // Marca la raiz de @p v (si es Stack ALLOCA o param) como escapante.
    auto mark_escape = [&](ir::IrValueId v) {
        const PointsToEntry &e = pt.at(v);
        if (e.kind == K::Stack && e.root != effects::LOC_GENERIC)
            out.escaping_stack.insert(e.root);
        else if (e.kind == K::ArgDerived)
            out.escaping_params.insert(static_cast<int32_t>(e.root));
    };
    // ¿@p v resuelve a una raiz TRACKED (Stack local o param)?
    auto tracked_root = [&](ir::IrValueId v) -> bool {
        const PointsToEntry &e = pt.at(v);
        return (e.kind == K::Stack && e.root != effects::LOC_GENERIC) ||
               e.kind == K::ArgDerived;
    };
    auto same_root = [&](ir::IrValueId a, ir::IrValueId b) -> bool {
        const PointsToEntry &ea = pt.at(a), &eb = pt.at(b);
        return ea.kind == eb.kind && ea.root == eb.root &&
               ea.kind != K::Unknown;
    };

    for (const ir::IrBlock &b : fn.blocks) {
        for (const ir::IrInstr &ins : b.instrs) {
            for (size_t p = 0; p < ins.operands.size(); ++p) {
                const ir::IrValueId o = ins.operands[p];
                if (o == ir::IR_NO_VALUE) continue;
                if (!tracked_root(o)) continue; // solo alloca/param

                // 1) DIRECCION de memoria: lee/escribe contenido, no captura.
                if (is_address_operand(ins.op, p)) continue;
                // 2) COMPARACION: lee el valor, no captura.
                if (is_comparison(ins.op)) continue;
                // 3) DERIVACION: no captura SI el resultado sigue siendo la
                //    MISMA raiz (se decidira en los usos del resultado); si la
                //    derivacion PIERDE la raiz (dst Unknown), la direccion fue
                //    a un calculo no rastreable -> escapa.
                if (is_derivation(ins.op)) {
                    if (ins.dst != ir::IR_NO_VALUE && same_root(o, ins.dst))
                        continue;
                    mark_escape(o);
                    continue;
                }
                // 4) CALL estatico: el arg escapa SOLO si el callee captura ese
                //    parametro (interproc).  El indice de param = posicion del
                //    operando (los args de CALL son operands[0..N-1]).
                if (is_static_call(ins.op)) {
                    if (callee(ins.func_name, static_cast<int32_t>(p)))
                        mark_escape(o);
                    continue;
                }
                // 5) CALL dinamico/nativo: callee desconocido -> captura todos.
                if (is_dynamic_call(ins.op)) {
                    mark_escape(o);
                    continue;
                }
                // 6) Cualquier otra posicion (STORE valor, RET, THROW,
                // SETSTATIC
                //    valor, atomic store, MAKE_CLOSURE, aritmetica
                //    no-derivacion sobre el puntero, ...): el VALOR del puntero
                //    se usa/guarda
                //    -> CAPTURA -> escapa.  Es el caso CORRECTO, no un bail.
                mark_escape(o);
            }
            // Valores retornados/lanzados que no van por operands (RET/THROW ya
            // usan operands, cubiertos arriba).
        }
    }
    return out;
}

std::unordered_map<std::string, EscapeInfo> compute_escape_module(
    const ir::IrModule &mod,
    const std::function<const IrFacts &(const ir::IrFunction &)> &facts_of,
    const std::function<const PointsTo &(const ir::IrFunction &)> &pt_of) {
    std::unordered_map<std::string, EscapeInfo> res;

    // Punto-fijo: escaping_params(fn) crece monotono (un param escapa si se usa
    // en captura O se pasa a un callee que captura su param).  Oraculo: un
    // param de un callee CONOCIDO escapa segun res; un callee DESCONOCIDO
    // captura todo.
    auto oracle = [&](const std::string &name, int32_t pidx) -> bool {
        auto it = res.find(name);
        if (it == res.end()) return true; // externo/no analizado -> captura
        return it->second.escaping_params.count(pidx) > 0;
    };

    // Inicial: todas vacias (nada escapa) -> el fixpoint solo ANADE.
    for (const ir::IrFunction &fn : mod.functions)
        if (!fn.is_native) res[fn.name] = EscapeInfo{};

    bool changed = true;
    int guard = 0;
    const int cap = static_cast<int>(mod.functions.size()) * 2 + 8;
    while (changed && guard++ < cap) {
        changed = false;
        for (const ir::IrFunction &fn : mod.functions) {
            if (fn.is_native) continue;
            EscapeInfo e = compute_escape(fn, facts_of(fn), pt_of(fn), oracle);
            EscapeInfo &cur = res[fn.name];
            // Crece monotono: comparar tamanos basta (solo se anaden).
            if (e.escaping_params.size() != cur.escaping_params.size() ||
                e.escaping_stack.size() != cur.escaping_stack.size()) {
                cur = std::move(e);
                changed = true;
            }
        }
    }
    return res;
}

} // namespace analysis
