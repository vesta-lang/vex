/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file unroll.cpp
 * @brief Implementacion del desenrollador de bucles GENERAL (ver unroll.h).
 *
 * Clona el CUERPO COMPLETO del bucle (todos los bloques salvo el header) U
 * veces, encadenando los valores loop-carried, y deja el bucle original como
 * REMAINDER.  Factor automatico por metricas del cuerpo.  Usa LoopFacts.
 */

#include "util/env_flags.h"
#include "ir/passes/unroll.h"

#include "analysis/asa/observed.h" // publicar lo que se sabe ANTES de deshacerlo
#include "analysis/facts/ir_facts.h" // def_block: el hecho, no un recorrido propio
#include "analysis/facts/loop_facts.h"
#include "analysis/facts/loop_iv.h"
#include "analysis/facts/loop_metrics.h"
#include "analysis/facts/loop_structure.h"
#include "analysis/facts/loop_trip_count.h"
#include "ir/passes/unroll_policy.h"
#include "ir/ssa_ir.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ir {

namespace {

// VESTA_NO_UNROLL=1 desactiva el pase (A/B testing).
bool unroll_disabled() {
    static const bool v = util::flag_on(util::FlagId::NoUnroll);
    return v;
}

// Descriptor de un bucle ELEGIBLE: agrega los HECHOS (analysis/facts).  El pase
// no descubre nada; solo los ensambla y transforma.
struct LoopInfo {
    analysis::LoopStructure st;  // forma del CFG + PHIs del header.
    analysis::LoopIV iv;         // IV contado (incluye su phi_index).
    analysis::LoopTripInfo trip; // numero de iteraciones (si constante).
};

// Reconstruye preds/succs de TODA la funcion desde los terminadores.
//
// Ademas de las aristas normales (BR/BR_COND), preserva la arista de HANDLER:
// un `tryenter %handler_pc` instala un bloque catch al que NO se salta por un
// terminador (solo al lanzarse una excepcion).  Si no la anadieramos, el bloque
// handler quedaria sin pred (huerfano) y un consumidor del CFG podria tratarlo
// como muerto.  El handler_pc es un LABEL_ADDR cuyo @c func_name es el nombre
// del bloque catch; se resuelve val -> nombre -> id y se anade `bloque_tryenter
// -> bloque_handler`.
void rebuild_cfg(IrFunction &fn) {
    for (auto &b : fn.blocks) {
        b.preds.clear();
        b.succs.clear();
    }
    auto add_edge = [&](IrBlockId from, IrBlockId to) {
        if (to == IR_NO_BLOCK || to >= fn.blocks.size()) return;
        fn.blocks[from].succs.push_back(to);
        fn.blocks[to].preds.push_back(from);
    };

    // val -> nombre de bloque (de cada LABEL_ADDR) y nombre de bloque -> id.
    std::unordered_map<IrValueId, std::string> label_of_val;
    std::unordered_map<std::string, IrBlockId> block_by_name;
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        block_by_name[fn.blocks[bi].name] = (IrBlockId)bi;
        for (const IrInstr &in : fn.blocks[bi].instrs)
            if (in.op == IrOp::LABEL_ADDR && in.dst != IR_NO_VALUE &&
                !in.func_name.empty())
                label_of_val[in.dst] = in.func_name;
    }

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto &instrs = fn.blocks[bi].instrs;
        if (instrs.empty()) continue;
        const IrInstr &t = instrs.back();
        if (t.op == IrOp::BR) {
            add_edge((IrBlockId)bi, t.target_block);
        } else if (t.op == IrOp::BR_COND) {
            add_edge((IrBlockId)bi, t.target_block);
            add_edge((IrBlockId)bi, t.false_block);
        }
        // Arista de handler: tryenter %handler_pc -> bloque catch.
        for (const IrInstr &in : instrs) {
            if (in.op != IrOp::TRYENTER || in.operands.empty()) continue;
            auto lv = label_of_val.find(in.operands[0]);
            if (lv == label_of_val.end()) continue;
            auto bn = block_by_name.find(lv->second);
            if (bn != block_by_name.end()) add_edge((IrBlockId)bi, bn->second);
        }
        // RET/THROW/UNREACHABLE/TAILCALL/etc.: sin sucesores normales.
    }
}

// Ensambla los HECHOS de un bucle innermost en @p out.  Toda la logica de
// analisis vive en analysis/facts; aqui solo se piden los hechos y se agregan.
bool analyze_loop(const IrFunction &fn, const analysis::LoopFacts &lf,
                  const std::vector<int> &def_block, uint32_t L,
                  LoopInfo &out) {
    // 1) Estructura del CFG: reducible, 1 latch, 1 salida, header limpio,
    // LCSSA.
    out.st = analysis::detect_loop_structure(fn, lf, L);
    if (!out.st.valid) return false;

    // 2) Variable de induccion contada (creciente, stride constante > 0).
    if (!analysis::detect_loop_iv(fn, def_block, out.st.header,
                                  out.st.preheader, out.st.latch, out.iv))
        return false;

    // 3) La cota N debe ser INVARIANTE (no definida dentro del bucle).  Es una
    //    comprobacion estructural: usa la membresia del bucle.
    if (out.iv.bound != IR_NO_VALUE && out.iv.bound < def_block.size()) {
        const int db = def_block[out.iv.bound];
        if (db >= 0 && out.st.contains((IrBlockId)db)) return false;
    }

    // 4) Trip-count (hecho derivado del IV).
    out.trip = analysis::compute_trip_count(fn, def_block, out.iv);
    return true;
}

// Clona un valor NUEVO copiando los atributos relevantes del original.
IrValueId clone_value(IrFunction &fn, IrValueId orig, IrType type) {
    IrValueId nd = fn.new_value(type);
    if (orig != IR_NO_VALUE && orig < fn.values.size() &&
        nd < fn.values.size()) {
        fn.values[nd].is_host_ptr = fn.values[orig].is_host_ptr;
        fn.values[nd].is_const = fn.values[orig].is_const;
        fn.values[nd].const_val = fn.values[orig].const_val;
    }
    return nd;
}

// Transforma (desenrolla) el bucle @p li por factor U.
void do_unroll(IrFunction &fn, const LoopInfo &li, int U) {
    const IrBlockId H = li.st.header;
    const IrType iv_ty = (li.st.phis[li.iv.phi_index].dst < fn.values.size())
                             ? fn.values[li.st.phis[li.iv.phi_index].dst].type
                             : IrType::I64;

    // --- 1) Crear TODOS los bloques nuevos primero (new_block redimensiona
    //     fn.blocks -> despues solo indexamos por id, sin new_block). ---
    const IrBlockId UH = fn.new_block("unroll_hdr");
    // blk_clone[k][orig_body_block] = clon en la copia k.
    std::vector<std::unordered_map<IrBlockId, IrBlockId>> blk_clone(U);
    for (int k = 0; k < U; ++k)
        for (IrBlockId b : li.st.body)
            blk_clone[k][b] = fn.new_block("unroll_c" + std::to_string(k) +
                                           "_" + fn.blocks[b].name);

    // --- 2) PHIs de UH (una por PHI del header): dst nuevo. ---
    std::vector<IrValueId> uphi(li.st.phis.size());
    for (size_t i = 0; i < li.st.phis.size(); ++i)
        uphi[i] = clone_value(fn, li.st.phis[i].dst,
                              fn.values[li.st.phis[i].dst].type);

    // --- 3) Clonar el cuerpo U veces, encadenando los valores loop-carried.
    // --- back_prev[phi_dst] = valor loop-carried de la copia anterior (o UH
    // phi).
    std::unordered_map<IrValueId, IrValueId> back_prev;
    for (size_t i = 0; i < li.st.phis.size(); ++i)
        back_prev[li.st.phis[i].dst] =
            uphi[i]; // copia 0 arranca en las UH phis

    for (int k = 0; k < U; ++k) {
        const IrBlockId incoming =
            (k == 0) ? UH : blk_clone[k - 1].at(li.st.latch);
        std::unordered_map<IrValueId, IrValueId> vmap;
        // Las PHIs del header mapean al valor loop-carried ENTRANTE de esta
        // copia.
        for (size_t i = 0; i < li.st.phis.size(); ++i)
            vmap[li.st.phis[i].dst] = back_prev[li.st.phis[i].dst];

        // Pase 1: crear los dst clon de TODAS las instrs del cuerpo (para poder
        // remapear referencias intra-copia en cualquier orden).
        for (IrBlockId b : li.st.body)
            for (const IrInstr &in : fn.blocks[b].instrs)
                if (in.dst != IR_NO_VALUE)
                    vmap[in.dst] = clone_value(fn, in.dst, in.type);

        auto rv = [&](IrValueId v) -> IrValueId {
            auto it = vmap.find(v);
            return it != vmap.end() ? it->second : v; // invariante -> igual
        };
        auto rb = [&](IrBlockId b) -> IrBlockId {
            if (b == H) return incoming; // arista desde el header
            auto it = blk_clone[k].find(b);
            return it != blk_clone[k].end() ? it->second : b;
        };

        // Pase 2: clonar cada instr con operandos/bloques remapeados.
        for (IrBlockId b : li.st.body) {
            const IrBlockId nb = blk_clone[k].at(b);
            std::vector<IrInstr> out_instrs;
            out_instrs.reserve(fn.blocks[b].instrs.size());
            for (const IrInstr &in : fn.blocks[b].instrs) {
                IrInstr ni = in; // copia (op, type, imm, func_name, flags...)
                if (in.dst != IR_NO_VALUE) ni.dst = vmap.at(in.dst);
                for (IrValueId &o : ni.operands)
                    o = rv(o);
                if (ni.func_ptr != IR_NO_VALUE) ni.func_ptr = rv(ni.func_ptr);
                for (auto &pa : ni.phi_args) {
                    pa.value = rv(pa.value);
                    pa.block = rb(pa.block);
                }
                // Terminadores: remapear destinos.
                if (ni.op == IrOp::BR) {
                    if (in.target_block == H) {
                        // Latch: encadenar a la siguiente copia (o volver a
                        // UH).
                        ni.target_block =
                            (k + 1 < U) ? blk_clone[k + 1].at(li.st.body_entry)
                                        : UH;
                    } else {
                        ni.target_block = rb(in.target_block);
                    }
                } else if (ni.op == IrOp::BR_COND) {
                    ni.target_block = rb(in.target_block);
                    ni.false_block = rb(in.false_block);
                }
                out_instrs.push_back(std::move(ni));
            }
            fn.blocks[nb].instrs = std::move(out_instrs);
        }

        // Valores loop-carried al final de esta copia (para encadenar).
        std::unordered_map<IrValueId, IrValueId> back_now;
        for (const auto &p : li.st.phis)
            back_now[p.dst] = rv(p.back);
        back_prev = std::move(back_now);
    }

    // --- 4) Rellenar las PHIs de UH: init desde preheader, back desde la
    //     ultima copia (blk_clone[U-1][latch]). ---
    {
        std::vector<IrInstr> uh;
        for (size_t i = 0; i < li.st.phis.size(); ++i) {
            IrInstr phi{};
            phi.op = IrOp::PHI;
            phi.type = fn.values[li.st.phis[i].dst].type;
            phi.dst = uphi[i];
            phi.phi_args.push_back({li.st.phis[i].init, li.st.preheader});
            phi.phi_args.push_back({back_prev[li.st.phis[i].dst],
                                    blk_clone[U - 1].at(li.st.latch)});
            uh.push_back(std::move(phi));
        }
        // Guarda: replica la del header con lookahead de (U-1) iteraciones.
        // Original: cmp(iv + cmp_offset, N).  Unrollada: las U iteraciones son
        // validas si cmp(iv + (U-1)*S + cmp_offset, N) -> iv_last = iv_uh + K.
        const IrValueId c_uh = fn.new_value(iv_ty);
        {
            IrInstr c{};
            c.op = IrOp::CONST;
            c.type = iv_ty;
            c.dst = c_uh;
            c.imm =
                (uint64_t)((int64_t)(U - 1) * li.iv.stride + li.iv.cmp_offset);
            fn.values[c_uh].is_const = true;
            fn.values[c_uh].const_val = c.imm;
            uh.push_back(std::move(c));
        }
        const IrValueId iv_last = fn.new_value(iv_ty);
        {
            IrInstr a{};
            a.op = IrOp::ADD;
            a.type = iv_ty;
            a.dst = iv_last;
            a.operands = {uphi[li.iv.phi_index], c_uh};
            uh.push_back(std::move(a));
        }
        const IrValueId guard = fn.new_value(IrType::BOOL);
        {
            IrInstr g{};
            g.op = li.iv.cmp_op;
            g.type = IrType::BOOL;
            g.dst = guard;
            g.operands = {iv_last, li.iv.bound}; // iv_first: (iv_last, N)
            uh.push_back(std::move(g));
        }
        {
            IrInstr br{};
            br.op = IrOp::BR_COND;
            br.operands = {guard};
            br.target_block = blk_clone[0].at(li.st.body_entry);
            br.false_block = H; // remainder
            uh.push_back(std::move(br));
        }
        fn.blocks[UH].instrs = std::move(uh);
        fn.blocks[UH].no_unroll = true;
    }

    // --- 5) Rewire del preheader y del header (remainder). ---
    // preheader: su terminador apuntaba a H -> ahora a UH.
    {
        IrInstr &pt = fn.blocks[li.st.preheader].instrs.back();
        if (pt.op == IrOp::BR && pt.target_block == H)
            pt.target_block = UH;
        else if (pt.op == IrOp::BR_COND) {
            if (pt.target_block == H) pt.target_block = UH;
            if (pt.false_block == H) pt.false_block = UH;
        }
    }
    // header (remainder): la PHI arg de entrada (desde preheader) ahora viene
    // de UH con el valor de la UH phi correspondiente.
    for (IrInstr &in : fn.blocks[H].instrs) {
        if (in.op != IrOp::PHI) continue;
        for (size_t i = 0; i < li.st.phis.size(); ++i) {
            if (in.dst != li.st.phis[i].dst) continue;
            for (auto &pa : in.phi_args) {
                if (pa.block == li.st.preheader) {
                    pa.block = UH;
                    pa.value = uphi[i];
                }
            }
        }
    }
    fn.blocks[H].no_unroll = true;
}

} // namespace

bool ir_pass_unroll(IrFunction &fn, int factor,
                    analysis::asa::FactStore *facts) {
    if (unroll_disabled()) return false;
    if (fn.blocks.size() < 3) return false;

    // NO se reconstruye el CFG de la funcion aqui: rebuild_cfg solo mira los
    // terminadores y perderia las aristas de handler (tryenter -> bloque
    // catch), dejando el bloque handler sin pred y expuesto a que un pase
    // posterior lo borre.  detect_loop_structure calcula los preds del header
    // localmente.

    /* Lo PRIMERO, lo que decide si hay algo que hacer: sin bucles no hay nada
     * que desenrollar, asi que preparar antes las tablas era recorrer la
     * funcion entera para tirarlo. */
    analysis::LoopFacts lf = analysis::compute_loop_facts(fn);
    if (lf.loop_count == 0) return false;

    /* def_block[v] = bloque que define v (para distinguir invariante vs
     * interno).  Sale de los hechos, no de un recorrido propio: era el mismo
     * doble bucle que ya hace `build_ir_facts`, y lo repetian ademas el
     * resolvedor de punteros y el reconocedor de memoria por lotes. */
    const analysis::IrFacts ir_facts = analysis::build_ir_facts(fn);
    const std::vector<int32_t> &def_block = ir_facts.def_block;

    // Solo bucles INNERMOST (sin hijos): los que tienen cuerpo cloneable
    // simple.
    std::vector<uint8_t> has_child(lf.loop_count, 0);
    for (uint32_t l = 0; l < lf.loop_count; ++l) {
        uint32_t p = lf.parent_of(l);
        if (p != analysis::LoopFacts::NO_LOOP && p < has_child.size())
            has_child[p] = 1;
    }

    // Recolectar los elegibles (ids estables; innermost disjuntos).
    std::vector<LoopInfo> eligible;
    for (uint32_t L = 0; L < lf.loop_count; ++L) {
        if (has_child[L]) continue; // no innermost
        /* La marca de "no desenrollar" se mira AQUI, que es de quien es.
         *
         * La ponemos nosotros en lo que generamos, para no deshacerlo otra
         * vez.  Estaba dentro de `detect_loop_structure`, que es un HECHO
         * sobre la forma del codigo y no la politica de este pase: alli dejaba
         * ciego a todo el mundo despues de desenrollar -- el coste declaraba
         * O(n^2) una funcion constante y el dominio de bucles no podia contar
         * las vueltas --, porque "no lo desenrolles" se leia como "no es un
         * bucle". */
        const ir::IrBlockId h = lf.header_block_of(L);
        if (h != IR_NO_BLOCK && h < fn.blocks.size() && fn.blocks[h].no_unroll)
            continue;
        LoopInfo li;
        if (analyze_loop(fn, lf, def_block, L, li))
            eligible.push_back(std::move(li));
    }
    if (eligible.empty()) return false;

    // Tamano estimado de la funcion (proxy: instrucciones no-terminadoras) para
    // la presion de I-cache del presupuesto.
    int fn_size = 0;
    for (const auto &b : fn.blocks)
        fn_size += (int)b.instrs.size();

    // Target del IR compartido (antes del split de backend): punto medio.  El
    // pase rellena el tamano de la funcion; el resto son parametros del target.
    UnrollTargetInfo target = UnrollTargetInfo::generic();
    target.code_size = fn_size;

    static UnrollStats g_stats;
    static const bool want_stats = util::flag_on(util::FlagId::UnrollStats);

    /* Lo que se sabe de cada bucle, DICHO antes de tocarlo.
     *
     * Aqui esta lo que el pase averiguo -- forma, induccion y vueltas -- y
     * dentro de un momento no va a estar: desenrollar reescribe el bucle, y
     * despues ya no hay bucle que contar.  Ese conocimiento se tiraba.
     *
     * Se publica de TODOS los elegibles, incluso de los que luego no se
     * desenrollen: que la politica decida que no compensa no lo hace menos
     * cierto, y quien pregunte "cuantas vueltas da esto" quiere el numero,
     * no la decision del optimizador. */
    if (facts != nullptr) {
        for (const LoopInfo &li : eligible) {
            analysis::asa::Fact f;
            if (analysis::asa::loop_trip_fact(
                    *facts, fn, li.st.header, li.trip,
                    analysis::asa::kStageDuringOpt,
                    analysis::asa::Source::Static, f))
                facts->add(std::move(f));
        }
    }

    bool changed = false;
    for (const LoopInfo &li : eligible) {
        int U;
        if (factor > 0) { // override manual (testing).
            U = factor;
        } else {
            // Metricas NEUTRALES del cuerpo -> POLITICA (la inteligencia).  El
            // transformador no decide nada: solo clona U veces.
            analysis::LoopMetrics m =
                analysis::compute_loop_metrics(fn, li.st.body);
            UnrollDecision d = choose_unroll_factor(m, li.trip.trip, target);
            if (want_stats) g_stats.account(d);
            if (!d.allow()) continue;
            U = d.factor;
        }
        if (U < 2) continue;
        do_unroll(fn, li, U);
        changed = true;
    }
    if (want_stats) {
        static const bool registered = [] {
            std::atexit([] { g_stats.dump(); });
            return true;
        }();
        (void)registered;
    }
    if (changed) rebuild_cfg(fn);
    return changed;
}

} // namespace ir
