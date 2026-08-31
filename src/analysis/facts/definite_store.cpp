/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/definite_store.cpp
 * @brief Implementacion de @ref analysis::DefiniteStoreFacts.
 *
 * Un "para todos los caminos" clasico: se propaga hacia adelante si el puntero
 * YA se ha escrito, juntando por los predecesores con Y logico -- un camino
 * que no escribe basta para que deje de estar garantizado --, y al final se
 * mira si algun retorno se alcanza sin ello.
 *
 * Lo que tiene de particular no es el algoritmo sino cuando se CALLA.  Ver la
 * cabecera: si algo de la funcion se sale de lo que este analisis entiende, la
 * respuesta no es ni si ni no.
 */

#include "analysis/facts/definite_store.h"

#include <vector>

namespace analysis {

namespace {

/// @c true si la instruccion puede escribir memoria que no se ve aqui.
///
/// No hace falta saber SI escribe el puntero: basta con que pudiera.  Una
/// llamada que lo recibe puede rellenarlo -- es justamente para lo que se pasa
/// un `out` a otra funcion -- y entonces afirmar que falta seria falso.
bool may_write_anything(ir::IrOp op) noexcept {
    using Op = ir::IrOp;
    switch (op) {
    case Op::CALL:
    case Op::CALLIND:
    case Op::CALLN:
    case Op::CALLVIRT:
    case Op::CALLM:
    case Op::CALLITF:
    case Op::CALLCLOSURE:
    case Op::TAILCALL:
    case Op::RAW_ASM:
    case Op::INLINE_ASM:
    case Op::ASM_MICRO:
    case Op::MEMCPY:
    case Op::MEMSET: return true;
    default: return false;
    }
}

} // namespace

DefiniteStoreFacts compute_definite_store(const ir::IrFunction &fn,
                                          ir::IrValueId target) {
    DefiniteStoreFacts f;
    if (target == ir::IR_NO_VALUE || fn.blocks.empty()) {
        f.verdict = DefiniteStoreFacts::Verdict::Unknown;
        f.reason = asa::UnknownReason::NothingToSay;
        f.reason_code = "definite_store.no_target";
        return f;
    }

    /* Las COPIAS del puntero cuentan como el mismo sitio: `mov %a, %x` y luego
     * `store v, %a` escribe donde apunta `%x`.  Solo copias EXACTAS: `%x + 8`
     * es otra direccion, y contarla como si fuera esta convertiria el analisis
     * en una fuente de respuestas falsas. */
    std::vector<uint8_t> is_alias(fn.values.size(), 0u);
    if (target < is_alias.size()) is_alias[target] = 1u;
    for (bool changed = true; changed;) {
        changed = false;
        for (const ir::IrBlock &bb : fn.blocks)
            for (const ir::IrInstr &ins : bb.instrs) {
                if (ins.op != ir::IrOp::MOV && ins.op != ir::IrOp::BITCAST)
                    continue;
                if (ins.dst == ir::IR_NO_VALUE || ins.operands.empty()) continue;
                const ir::IrValueId src = ins.operands[0];
                if (src >= is_alias.size() || ins.dst >= is_alias.size())
                    continue;
                if (is_alias[src] && !is_alias[ins.dst]) {
                    is_alias[ins.dst] = 1u;
                    changed = true;
                }
            }
    }

    /* Si el puntero SALE de aqui, quien lo reciba puede escribirlo, y entonces
     * no se puede afirmar que falte.  Se mira antes que nada: una funcion que
     * delega el relleno en otra es correcta, y acusarla seria el peor fallo
     * que este analisis puede tener. */
    for (const ir::IrBlock &bb : fn.blocks) {
        for (const ir::IrInstr &ins : bb.instrs) {
            const bool escribe_opaco = may_write_anything(ins.op);
            // Como VALOR de un store, el puntero se guarda en algun sitio y
            // deja de estar solo en nuestras manos.
            const bool guardado =
                ins.op == ir::IrOp::STORE && !ins.operands.empty() &&
                ins.operands[0] < is_alias.size() && is_alias[ins.operands[0]];
            bool lo_toca = guardado;
            if (escribe_opaco)
                for (ir::IrValueId op : ins.operands)
                    if (op < is_alias.size() && is_alias[op]) lo_toca = true;
            if (!lo_toca) continue;
            f.verdict = DefiniteStoreFacts::Verdict::Unknown;
            f.reason = asa::UnknownReason::OpaqueBoundary;
            f.reason_code = "definite_store.escapes";
            return f;
        }
    }

    // Por bloque: si escribe el puntero en algun punto de el.
    const size_t n = fn.blocks.size();
    std::vector<uint8_t> writes(n, 0u);
    for (size_t b = 0; b < n; ++b)
        for (const ir::IrInstr &ins : fn.blocks[b].instrs)
            if (ins.op == ir::IrOp::STORE && ins.operands.size() >= 2 &&
                ins.operands[1] < is_alias.size() && is_alias[ins.operands[1]])
                writes[b] = 1u;

    /* Punto fijo.  Se empieza SUPONIENDO que si esta escrito en todas partes
     * menos en la entrada, y se va quitando: es la forma de que un bucle
     * converja sin que su arista de vuelta -- que aun no se ha calculado --
     * decida el resultado. */
    std::vector<uint8_t> out_(n, 1u);
    std::vector<uint8_t> reachable(n, 0u);
    reachable[0] = 1u;
    for (bool changed = true; changed;) {
        changed = false;
        for (size_t b = 0; b < n; ++b) {
            for (ir::IrBlockId s : fn.blocks[b].succs)
                if (s < n && reachable[b] && !reachable[s]) {
                    reachable[s] = 1u;
                    changed = true;
                }
            uint8_t in_ = 1u;
            if (b == 0) {
                in_ = 0u; // a la entrada no se ha escrito nada todavia
            } else {
                for (ir::IrBlockId p : fn.blocks[b].preds)
                    if (p < n && !out_[p]) in_ = 0u;
                // Un bloque sin predecesores al que no se llega no dice nada;
                // uno al que si se llega y no los tiene es la entrada, ya vista.
                if (fn.blocks[b].preds.empty()) in_ = 0u;
            }
            const uint8_t nuevo = (in_ || writes[b]) ? 1u : 0u;
            if (nuevo != out_[b]) {
                out_[b] = nuevo;
                changed = true;
            }
        }
    }

    // Y el veredicto: cada retorno alcanzable tiene que llegar con el escrito.
    for (size_t b = 0; b < n; ++b) {
        if (!reachable[b] || fn.blocks[b].instrs.empty()) continue;
        const ir::IrInstr &last = fn.blocks[b].instrs.back();
        if (last.op != ir::IrOp::RET) continue;
        if (out_[b]) continue;
        f.verdict = DefiniteStoreFacts::Verdict::MissingOnSomePath;
        f.witness_line = last.source_line;
        return f;
    }

    f.verdict = DefiniteStoreFacts::Verdict::Always;
    return f;
}

} // namespace analysis
