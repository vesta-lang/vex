/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir_facts.cpp
 * @brief Constructor de los hechos IR (def-use + call-sites + estructura) en un
 *        solo recorrido.  Consolida lo que antes reconstruian por separado el
 *        motor de efectos (def-use) y el resumen estructural.
 */
#include "analysis/facts/ir_facts.h"

#include "ir/ssa_ir.h"

namespace analysis {

char IRFactsAnalysis::ID = 0;

IrFacts build_ir_facts(const ir::IrFunction &fn) {
    IrFacts f;
    f.def_of.assign(fn.values.size(), nullptr);
    f.def_block.assign(fn.values.size(), -1);
    f.param_of.assign(fn.values.size(), -1);
    for (size_t i = 0; i < fn.params.size(); ++i) {
        const ir::IrValueId p = fn.params[i];
        if (p < f.param_of.size()) f.param_of[p] = static_cast<int32_t>(i);
    }
    f.block_count = static_cast<uint32_t>(fn.blocks.size());

    for (uint32_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const ir::IrBlock &b = fn.blocks[bi];
        for (const ir::IrInstr &in : b.instrs) {
            // def-use: QUE instruccion lo define, y en QUE bloque.
            if (in.dst != ir::IR_NO_VALUE && in.dst < f.def_of.size()) {
                f.def_of[in.dst] = &in;
                f.def_block[in.dst] = static_cast<int32_t>(bi);
            }
            // call-sites.
            switch (in.op) {
            case ir::IrOp::CALL:
            case ir::IrOp::TAILCALL:
                if (!in.func_name.empty()) {
                    f.static_callees.push_back(in.func_name);
                    if (in.func_name == fn.name) f.recursive = true;
                } else {
                    f.has_dynamic_call = true;
                }
                break;
            case ir::IrOp::CALLVIRT:
            case ir::IrOp::CALLM:
            case ir::IrOp::CALLITF:
            case ir::IrOp::CALLCLOSURE:
            case ir::IrOp::CALLIND:
            case ir::IrOp::CALLN: f.has_dynamic_call = true; break;
            default: break;
            }
            // back-edges (bucles).
            auto is_back = [&](ir::IrBlockId t) {
                return t != ir::IR_NO_BLOCK && t <= bi;
            };
            if (in.op == ir::IrOp::BR) {
                if (is_back(in.target_block)) ++f.loop_count;
            } else if (in.op == ir::IrOp::BR_COND) {
                if (is_back(in.target_block) || is_back(in.false_block))
                    ++f.loop_count;
            } else if (in.op == ir::IrOp::SWITCH_DENSE ||
                       in.op == ir::IrOp::MATCH_VARIANT) {
                for (uint32_t t : in.jump_targets)
                    if (is_back(t)) {
                        ++f.loop_count;
                        break;
                    }
            }
        }
    }
    return f;
}

} // namespace analysis
