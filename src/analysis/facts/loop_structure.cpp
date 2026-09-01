/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_structure.cpp
 * @brief Implementacion del verificador estructural de bucles
 * (loop_structure.h).
 */

#include "analysis/facts/loop_structure.h"

#include "analysis/memory/memory_access.h" // "toca memoria?", en UN solo sitio

#include <unordered_set>

namespace analysis {

using ir::IR_NO_BLOCK;
using ir::IR_NO_VALUE;
using ir::IrBlockId;
using ir::IrInstr;
using ir::IrOp;
using ir::IrValueId;

LoopStructure detect_loop_structure(const ir::IrFunction &fn,
                                    const analysis::LoopFacts &lf,
                                    uint32_t loop_id) {
    LoopStructure st;
    const IrBlockId H = lf.header_block_of(loop_id);
    if (H == (IrBlockId)IR_NO_BLOCK || H >= fn.blocks.size()) return st;
    if (fn.blocks[H].no_unroll) return st;
    st.header = H;

    // Bloques del bucle (innermost == loop_id).  Cuerpo = todos salvo H.
    const size_t Nb = fn.blocks.size();
    st.loop_blocks.insert(H);
    for (size_t bi = 0; bi < Nb; ++bi) {
        if (lf.innermost((IrBlockId)bi) == loop_id) {
            st.loop_blocks.insert((IrBlockId)bi);
            if ((IrBlockId)bi != H) st.body.push_back((IrBlockId)bi);
        }
    }
    if (st.body.empty()) return st; // self-loop degenerado.

    // Header limpio: [PHIs...] + [instr que define cond] + [br_cond].  El
    // BR_COND debe tener exactamente un sucesor DENTRO y otro FUERA del bucle.
    const auto &hins = fn.blocks[H].instrs;
    if (hins.size() < 2) return st;
    const IrInstr &term = hins.back();
    if (term.op != IrOp::BR_COND || term.operands.empty()) return st;
    const IrValueId cond = term.operands[0];
    const bool t_in = st.contains(term.target_block);
    const bool f_in = st.contains(term.false_block);
    if (t_in == f_in) return st; // exactamente uno dentro, uno fuera.
    st.body_entry = t_in ? term.target_block : term.false_block;
    st.exit = t_in ? term.false_block : term.target_block;

    /* En el header solo PHIs y el CALCULO DE LA GUARDA.
     *
     * El criterio lo dice el parrafo de arriba -- efectos laterales que el
     * clonado no pueda replicar --, asi que se comprueba eso y no una lista de
     * opcodes: la instruccion no puede tocar memoria ni ser una llamada, y su
     * resultado tiene que acabar alimentando la condicion.  Lo primero se
     * pregunta al vocabulario compartido (@c memory_access_kind, @c
     * ir_op_is_call); escribir aqui otra lista era como se acaba con dos
     * criterios que se separan.
     *
     * Antes solo pasaban PHI, CONST, MOV y la que define `cond`, y esa lista
     * dejaba fuera formas perfectamente contadas:
     *
     *   - ANTES de optimizar, el limite esta materializado dentro del header
     *     (`const.i64 64`) y la construccion de SSA deja una copia del PHI;
     *   - DESPUES, el desenrollador emite la guarda como `iv + (U-1) < N`, o
     *     sea un `add` en el header -- que este mismo fichero sabe leer, en
     *     `cmp_offset` -- y aun asi lo rechazaba por la puerta de entrada.
     *
     * El resultado era que el mismo bucle no se reconocia ni antes ni despues,
     * y el analisis de coste heredaba el hueco: declaraba O(?) una funcion
     * cuyo coste sabia perfectamente.  Un analisis que renuncia por esto esta
     * midiendo al optimizador, no al programa. */
    {
        /* Que valores del header alimentan la condicion.  Se recorre al reves
         * porque en SSA un valor se define antes de usarse: una sola pasada
         * basta para cerrar la dependencia. */
        std::unordered_set<IrValueId> feeds_cond;
        feeds_cond.insert(cond);
        for (size_t i = hins.size(); i-- > 0;) {
            const IrInstr &in = hins[i];
            if (in.dst == IR_NO_VALUE || !feeds_cond.count(in.dst)) continue;
            for (IrValueId o : in.operands)
                feeds_cond.insert(o);
        }
        /* Calculo PURO admitido en la guarda.
         *
         * Es una lista de PERMITIDOS y no de prohibidos, a proposito: lo que
         * no se conoce se rechaza, asi que una op nueva del IR no se cuela
         * sola en un sitio donde hay que poder CLONAR sin cambiar nada.  Crece
         * cuando aparezca una guarda que la necesite, no antes.
         *
         * Lo de "no toca memoria" se pregunta al vocabulario compartido y no se
         * repite aqui. */
        auto pure_compute = [](IrOp op) {
            switch (op) {
            case IrOp::CONST:
            case IrOp::MOV:
            case IrOp::ADD:
            case IrOp::SUB:
            case IrOp::MUL:
            case IrOp::SHL:
            case IrOp::TRUNC:
            case IrOp::ZEXT:
            case IrOp::SEXT: return true;
            default: return false;
            }
        };
        for (size_t i = 0; i + 1 < hins.size(); ++i) { // sin el terminador.
            const IrInstr &in = hins[i];
            if (in.op == IrOp::PHI) continue;
            if (in.dst == cond) continue; // la que define la condicion
            if (in.dst == IR_NO_VALUE || !feeds_cond.count(in.dst))
                return st; // no aporta a la guarda: el header hace mas cosas.
            if (!pure_compute(in.op)) return st;
            if (analysis::memory_access_kind(in.op).touches) return st;
        }
    }

    // Latch: unico bloque del bucle cuyo terminador salta (BR) al header.
    for (IrBlockId b : st.body) {
        const auto &bi = fn.blocks[b].instrs;
        if (bi.empty()) continue;
        const IrInstr &bt = bi.back();
        if (bt.op == IrOp::BR && bt.target_block == H) {
            if (st.latch != IR_NO_BLOCK) return st; // >1 latch.
            st.latch = b;
        }
    }
    if (st.latch == IR_NO_BLOCK) return st;

    // Salida UNICA: ningun bloque del cuerpo salta FUERA del bucle.
    for (IrBlockId b : st.body) {
        const auto &bi = fn.blocks[b].instrs;
        if (bi.empty()) return st;
        const IrInstr &bt = bi.back();
        if (bt.op == IrOp::BR) {
            if (!st.contains(bt.target_block)) return st;
        } else if (bt.op == IrOp::BR_COND) {
            if (!st.contains(bt.target_block) || !st.contains(bt.false_block))
                return st;
        } else {
            return st; // RET/THROW/etc. -> multi-salida.
        }
    }

    // Preheader: unico pred del header FUERA del bucle.  Se calcula LOCALMENTE
    // desde los terminadores (no desde fn.blocks[].preds, que un pase previo
    // pudo dejar obsoletos) para no depender de mutar el CFG de la funcion.
    for (size_t p = 0; p < Nb; ++p) {
        if (st.contains((IrBlockId)p)) continue;
        const auto &pins = fn.blocks[p].instrs;
        if (pins.empty()) continue;
        const IrInstr &pt = pins.back();
        const bool goes_to_H = (pt.op == IrOp::BR && pt.target_block == H) ||
                               (pt.op == IrOp::BR_COND &&
                                (pt.target_block == H || pt.false_block == H));
        if (goes_to_H) {
            if (st.preheader != IR_NO_BLOCK) return st; // >1 entrada.
            st.preheader = (IrBlockId)p;
        }
    }
    if (st.preheader == IR_NO_BLOCK) return st;

    // PHIs del header: cada una con {arg preheader, arg latch}.
    for (const IrInstr &in : hins) {
        if (in.op != IrOp::PHI) continue;
        if (in.phi_args.size() != 2) return st;
        HeaderPhi hp;
        hp.dst = in.dst;
        for (const auto &pa : in.phi_args) {
            if (pa.block == st.preheader)
                hp.init = pa.value;
            else if (pa.block == st.latch)
                hp.back = pa.value;
            else
                return st; // arg desde un bloque inesperado.
        }
        if (hp.init == IR_NO_VALUE || hp.back == IR_NO_VALUE) return st;
        st.phis.push_back(hp);
    }
    if (st.phis.empty()) return st;

    // Loop-closed SSA: ningun valor del CUERPO se usa fuera del bucle (los
    // live-out salen por las PHIs del header).  Sin esto el remainder podria
    // dejar un valor indefinido en el exit.
    std::unordered_set<IrValueId> body_defs;
    for (IrBlockId b : st.body)
        for (const IrInstr &in : fn.blocks[b].instrs)
            if (in.dst != IR_NO_VALUE) body_defs.insert(in.dst);
    for (size_t bi = 0; bi < Nb; ++bi) {
        if (st.contains((IrBlockId)bi)) continue; // dentro del bucle: OK.
        for (const IrInstr &in : fn.blocks[bi].instrs) {
            for (IrValueId o : in.operands)
                if (body_defs.count(o)) return st;
            for (const auto &pa : in.phi_args) {
                if (st.contains(pa.block) && body_defs.count(pa.value))
                    return st;
                if (body_defs.count(pa.value) && !st.contains(pa.block))
                    return st;
            }
        }
    }

    st.valid = true;
    return st;
}

} // namespace analysis
