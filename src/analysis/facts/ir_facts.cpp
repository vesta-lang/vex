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

#include "analysis/manager/analysis_codec.h" // lo COMUN de guardar un analisis
#include "ir/ssa_ir.h"

namespace analysis {

char IRFactsAnalysis::ID = 0;

namespace {

/// @brief Va @p target hacia ATRAS desde el bloque @p from?
///
/// Es la aproximacion de bucle que usa este recorrido: un salto a un bloque que
/// ya se paso.  Funcion con nombre y no una lambda dentro del bucle -- se prueba
/// sola, sale con su nombre en un perfil, y no captura nada cuya vida haya que
/// razonar.
bool is_back_edge(ir::IrBlockId target, uint32_t from) {
    return target != ir::IR_NO_BLOCK && target <= from;
}

} // namespace

IrFacts build_ir_facts(const ir::IrFunction &fn) {
    IrFacts f;
    /* La funcion que se describe: es lo que permite resolver `def` sin guardar
     * punteros, y lo unico que hay que volver a poner si estos hechos vuelven
     * de disco. */
    f.owner = &fn;
    f.def_idx.assign(fn.values.size(), -1);
    f.def_block.assign(fn.values.size(), -1);
    f.param_of.assign(fn.values.size(), -1);
    f.used.assign(fn.values.size(), 0);
    for (size_t i = 0; i < fn.params.size(); ++i) {
        const ir::IrValueId p = fn.params[i];
        if (p < f.param_of.size()) f.param_of[p] = static_cast<int32_t>(i);
    }
    f.block_count = static_cast<uint32_t>(fn.blocks.size());

    for (uint32_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const ir::IrBlock &b = fn.blocks[bi];
        for (size_t ii = 0; ii < b.instrs.size(); ++ii) {
            const ir::IrInstr &in = b.instrs[ii];
            /* def-use: en QUE bloque lo define y en que POSICIoN dentro de el.
             * Los dos, porque juntos localizan la instruccion en O(1) sin
             * guardar un puntero que nadie mantiene. */
            if (in.dst != ir::IR_NO_VALUE && in.dst < f.def_idx.size()) {
                f.def_idx[in.dst] = static_cast<int32_t>(ii);
                f.def_block[in.dst] = static_cast<int32_t>(bi);
            }
            /* Y QUIEN lo lee.  Es la mitad que faltaba para poder decir si un
             * valor EXISTE aqui: la tabla de valores no encoge cuando el
             * optimizador borra una instruccion, asi que sin esto una ranura
             * vacia y algo que de verdad viene de fuera se ven igual. */
            for (const ir::IrValueId op : in.operands)
                if (op != ir::IR_NO_VALUE && op < f.used.size()) f.used[op] = 1;
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
            if (in.op == ir::IrOp::BR) {
                if (is_back_edge(in.target_block, bi)) ++f.loop_count;
            } else if (in.op == ir::IrOp::BR_COND) {
                if (is_back_edge(in.target_block, bi) ||
                    is_back_edge(in.false_block, bi))
                    ++f.loop_count;
            } else if (in.op == ir::IrOp::SWITCH_DENSE ||
                       in.op == ir::IrOp::MATCH_VARIANT) {
                for (uint32_t t : in.jump_targets)
                    if (is_back_edge(t, bi)) {
                        ++f.loop_count;
                        break;
                    }
            }
        }
    }
    return f;
}

const char *const kIrFactsAnalysisName = "analysis.ir_facts";

std::vector<uint8_t> serialize_ir_facts(const IrFacts &f) {
    util::ByteWriter w;
    write_analysis_header(w, kIrFactsAnalysisName, kIrFactsFormat);
    write_pod_vector(w, f.def_idx);
    write_pod_vector(w, f.def_block);
    write_pod_vector(w, f.param_of);
    write_pod_vector(w, f.used);
    w.u32(static_cast<uint32_t>(f.static_callees.size()));
    for (const std::string &s : f.static_callees)
        w.str(s);
    w.u8(f.has_dynamic_call ? 1u : 0u);
    w.u32(f.block_count);
    w.u32(f.loop_count);
    w.u8(f.recursive ? 1u : 0u);
    return w.take();
}

bool deserialize_ir_facts(const uint8_t *data, size_t n,
                          const ir::IrFunction &owner, IrFacts &out) {
    if (data == nullptr || n == 0) return false;
    util::ByteReader r(data, n);
    if (!read_analysis_header(r, kIrFactsAnalysisName, kIrFactsFormat))
        return false;

    /* Se arma APARTE y solo se entrega al final.  Si los bytes se cortan a
     * medias, quien pregunta se queda con lo que tenia y computa; dejarle una
     * estructura a medio llenar seria servirle hechos que nadie afirmo. */
    IrFacts f;
    if (!read_pod_vector(r, f.def_idx)) return false;
    if (!read_pod_vector(r, f.def_block)) return false;
    if (!read_pod_vector(r, f.param_of)) return false;
    if (!read_pod_vector(r, f.used)) return false;

    const uint32_t n_callees = r.u32();
    /* Un nombre ocupa como minimo su longitud (4 bytes), asi que mas de eso es
     * imposible por muchos que diga el fichero. */
    if (!r.ok() || !fits_in(r, n_callees, 4)) return false;
    f.static_callees.reserve(n_callees);
    for (uint32_t i = 0; i < n_callees && r.ok(); ++i)
        f.static_callees.push_back(r.str());

    f.has_dynamic_call = r.u8() != 0;
    f.block_count = r.u32();
    f.loop_count = r.u32();
    f.recursive = r.u8() != 0;
    if (!r.ok()) return false;

    /* Y la COHERENCIA con la funcion que se dice que describen.  Sin esto, unos
     * hechos de otra funcion con la misma clave -- que no deberia pasar, pero
     * el modo de fallar decide cuanto cuesta equivocarse -- se aceptarian y
     * contestarian sobre valores que no existen. */
    if (f.def_idx.size() != owner.values.size()) return false;
    if (f.block_count != owner.blocks.size()) return false;

    f.owner = &owner;
    out = std::move(f);
    return true;
}

const ir::IrInstr *IrFacts::def(ir::IrValueId v) const {
    /* Cada limite se comprueba, y no por prudencia: estos hechos pueden ser de
     * un IR que ya cambio -- o venir de disco --, y ahi un indice pasado de
     * rango tiene que dar "no lo se", no la instruccion que caiga en esa
     * posicion.  Es la diferencia con el puntero de antes, que no fallaba: leia
     * memoria liberada y contestaba. */
    if (owner == nullptr || v >= def_idx.size() || v >= def_block.size())
        return nullptr;
    const int32_t b = def_block[v];
    const int32_t i = def_idx[v];
    if (b < 0 || i < 0) return nullptr;
    if (static_cast<size_t>(b) >= owner->blocks.size()) return nullptr;
    const std::vector<ir::IrInstr> &ins =
        owner->blocks[static_cast<size_t>(b)].instrs;
    if (static_cast<size_t>(i) >= ins.size()) return nullptr;
    return &ins[static_cast<size_t>(i)];
}

} // namespace analysis
