/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_metrics.cpp
 * @brief Implementacion del medidor NEUTRAL del cuerpo de un bucle.
 */

#include "analysis/facts/loop_metrics.h"
#include "analysis/memory/memory_access.h" // quien decide si una op toca memoria
#include "ir/ir_vec_ops.h" // cuales son las operaciones vectoriales

#include <unordered_set>

namespace analysis {

using ir::IR_NO_VALUE;
using ir::IrBlockId;
using ir::IrInstr;
using ir::IrOp;
using ir::IrValueId;

namespace {

/* Si una op lee o escribe memoria lo contesta el vocabulario de acceso, no una
 * lista propia.  Aqui habia dos, y no coincidian con las del optimizador: a
 * estas les faltaban ARRAY_LEN, VEC_ACC_ZERO y VEC_ACC_COMBINE, de modo que un
 * bucle que solo hiciera eso se contaba como si no tocara memoria.
 *
 * Es la clase de acceso EN EL IR: a donde baje cada op depende del objetivo, y
 * eso lo cubre la capa por backend, no este contador. */
bool is_load_like(IrOp op) {
    return analysis::memory_access_kind(op).is_load;
}
bool is_store_like(IrOp op) {
    return analysis::memory_access_kind(op).is_store;
}
bool is_call_like(IrOp op) {
    switch (op) {
    case IrOp::CALL:
    case IrOp::CALLN:
    case IrOp::CALLIND:
    case IrOp::CALLVIRT:
    case IrOp::CALLM:
    case IrOp::CALLITF:
    case IrOp::CALLCLOSURE:
    case IrOp::CALLSUPER:
    case IrOp::TAILCALL: return true;
    default: return false;
    }
}
bool is_vec(IrOp op) {
    return ir::is_vec_op(op);
}
bool is_fp(IrOp op) {
    switch (op) {
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FNEG:
    case IrOp::FABS:
    case IrOp::FSQRT:
    case IrOp::FMIN:
    case IrOp::FMAX:
    case IrOp::FMA: return true;
    default: return false;
    }
}
bool is_expensive(IrOp op) {
    switch (op) {
    case IrOp::DIV:
    case IrOp::MOD:
    case IrOp::FDIV:
    case IrOp::FSQRT: return true;
    default: return false;
    }
}

} // namespace

LoopMetrics compute_loop_metrics(const ir::IrFunction &fn,
                                 const std::vector<IrBlockId> &body) {
    LoopMetrics m;
    std::unordered_set<IrValueId> body_defs;
    std::unordered_set<IrBlockId> body_set(body.begin(), body.end());

    for (IrBlockId b : body) {
        if (b >= fn.blocks.size()) continue;
        ++m.basic_blocks;
        for (const IrInstr &in : fn.blocks[b].instrs) {
            const bool is_term = (in.op == IrOp::BR || in.op == IrOp::BR_COND ||
                                  in.op == IrOp::RET || in.op == IrOp::THROW ||
                                  in.op == IrOp::UNREACHABLE);
            if (is_term) ++m.terminators;
            if (in.op == IrOp::PHI) {
                ++m.phis;
            } else if (!is_term) {
                ++m.instructions;
                if (is_load_like(in.op)) ++m.loads;
                if (is_store_like(in.op)) {
                    ++m.stores;
                    m.has_side_effects = true;
                }
                if (is_call_like(in.op)) {
                    ++m.calls;
                    m.has_side_effects = true;
                }
                if (is_vec(in.op)) ++m.vector_ops;
                if (is_fp(in.op)) ++m.fp_ops;
                if (is_expensive(in.op)) ++m.expensive_ops;
                // Efectos no capturados por los conteos: atomics, io, barreras.
                if (in.op == IrOp::ATOMIC_LD || in.op == IrOp::ATOMIC_ST ||
                    in.op == IrOp::ATOMIC_CAS || in.op == IrOp::ATOMIC_ADD ||
                    in.op == IrOp::RAW_ASM)
                    m.has_side_effects = true;
            }
            if (in.op == IrOp::BR_COND) ++m.branches;
            if (in.dst != IR_NO_VALUE) body_defs.insert(in.dst);
        }
    }

    // Presion de registros (proxy): valores DEFINIDOS en el cuerpo que se usan
    // FUERA del cuerpo -- los back-args de las PHIs del header (loop-carried)
    // mas los live-out.  Son los unicos que cada copia del unroll mantiene
    // vivos a la vez; los temporales intra-iteracion se consumen dentro de su
    // copia y NO cuentan.  (El proxy anterior miraba el latch: en un bucle de
    // un solo bloque latch == cuerpo, contaba los temporales intra-iteracion e
    // inflaba la presion, capando el factor.)
    std::unordered_set<IrValueId> live;
    for (size_t b = 0; b < fn.blocks.size(); ++b) {
        if (body_set.count((IrBlockId)b))
            continue; // solo bloques FUERA del cuerpo
        for (const IrInstr &in : fn.blocks[b].instrs) {
            for (IrValueId o : in.operands)
                if (body_defs.count(o)) live.insert(o);
            for (const auto &pa : in.phi_args)
                if (body_defs.count(pa.value)) live.insert(pa.value);
        }
    }
    m.live_across = (int)live.size();
    return m;
}

} // namespace analysis
