/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/jit_facts.cpp
 * @brief La pregunta que el JIT le hace a la base de hechos del ASA (ver
 *        @c jit/jit_facts.h).  La base en si vive en
 *        @c src/analysis/asa/fact_base.cpp.
 */

#include "jit/jit_facts.h"

#include "ir/ssa_ir.h"

namespace jit {

CotasDeLosSitios cotas_de_los_sitios(const ir::IrFunction &fn,
                                     const analysis::RangeFacts &rangos) {
    CotasDeLosSitios r;
    for (const auto &bb : fn.blocks)
        for (const auto &in : bb.instrs) {
            /* Los sitios donde el conocimiento se puede aprovechar: una llamada
             * con cuerpo conocido y una reserva, que es una llamada al
             * asignador escrita como instruccion. */
            const bool interesa =
                in.op == ir::IrOp::RAW_ALLOC ||
                (in.op == ir::IrOp::CALL && !in.func_name.empty());
            if (!interesa) continue;
            ++r.sitios;
            bool este_sitio = false;
            for (ir::IrValueId a : in.operands) {
                ++r.operandos;
                const analysis::ValueRange &rg = rangos.at(a);
                if (!rg.acotada() || rg.es_todo()) continue;
                ++r.operandos_con_cota;
                este_sitio = true;
                if (!r.hay) { // la primera es la que sostiene el veredicto
                    r.hay = true;
                    r.sitio =
                        in.op == ir::IrOp::RAW_ALLOC ? "reserva" : in.func_name;
                    r.valor = a;
                    r.rango = rg;
                }
            }
            if (este_sitio) ++r.sitios_con_cota;
        }
    return r;
}

} // namespace jit
