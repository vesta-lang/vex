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
    /* Salir DICIENDO cual de las condiciones fallo.  Eran siete y todas
     * contestaban lo mismo, asi que quien preguntaba no podia distinguir un
     * bucle con dos salidas de uno cuya cabecera hace de mas -- y se arreglan
     * de formas distintas: una es un hueco de este analisis y la otra del
     * programa. */
    auto bail = [&st](const char *code) -> LoopStructure {
        st.why = code;
        return st;
    };
    const IrBlockId H = lf.header_block_of(loop_id);
    if (H == (IrBlockId)IR_NO_BLOCK || H >= fn.blocks.size())
        return bail("loop.no_header");
    /* `no_unroll` NO se mira aqui.
     *
     * La marca dice "no desenrolles ESTE", y la pone el propio desenrollador
     * en lo que genera para no volver a deshacerlo.  Este analisis la trataba
     * como "esto no es un bucle", y con eso se quedaba ciego TODO el mundo
     * despues de desenrollar: el dominio de bucles no podia decir nada del
     * bucle resultante y el coste declaraba O(n^2) una funcion constante.
     *
     * Y no es que la marca no importe: importa MUCHO, pero a quien transforma.
     * Desenrollar CAMBIA el bucle -- 64 vueltas por 8 se convierten en 8 de un
     * cuerpo ocho veces mayor, mas un resto --, asi que lo que hay despues es
     * otro bucle con otra cuenta.  Justamente por eso hay que poder MIRARLO:
     * para medir la cuenta NUEVA, no para heredar la vieja.  El momento en que
     * viaja cada hecho es lo que impide confundirlas.
     *
     * Quien no quiera desenrollar mira la marca el mismo; el desenrollador lo
     * hace antes de elegir candidatos. */
    st.header = H;

    /* Membresia y CUERPO son dos cosas, y confundirlas era lo que impedia
     * reconocer un bucle externo.
     *
     *   - dentro del bucle esta todo lo que cuelga de el, bucles anidados
     *     incluidos: se sube por el arbol de anidamiento hasta encontrarlo;
     *   - el CUERPO es solo su nivel, que es lo que clona el desenrollado.
     *
     * Con las dos cosas mezcladas, el bloque que entra al bucle de dentro
     * saltaba a algo "de fuera" y el analisis se rendia con `body_exits`. */
    const size_t Nb = fn.blocks.size();
    st.loop_blocks.insert(H);
    for (size_t bi = 0; bi < Nb; ++bi) {
        const uint32_t mio = lf.innermost((IrBlockId)bi);
        if (mio == LoopFacts::NO_LOOP) continue;
        if (mio == loop_id) {
            st.loop_blocks.insert((IrBlockId)bi);
            if ((IrBlockId)bi != H) st.body.push_back((IrBlockId)bi);
            continue;
        }
        /* De un bucle de dentro?  Se sube por los padres.  El tope es por si
         * el arbol llegara con un ciclo: un analisis no debe colgar el
         * compilador ni cuando le mienten. */
        uint32_t p = lf.parent_of(mio);
        for (int saltos = 0; saltos < 64 && p != LoopFacts::NO_LOOP; ++saltos) {
            if (p == loop_id) {
                st.loop_blocks.insert((IrBlockId)bi);
                break;
            }
            p = lf.parent_of(p);
        }
    }
    for (uint32_t L = 0; L < lf.loop_count; ++L)
        if (lf.parent_of(L) == loop_id) ++st.inner_loops;
    /* Un bucle de UN SOLO BLOQUE que salta a si mismo esta tan contado como
     * cualquiera: las PHIs, el cuerpo y la guarda viven todos ahi.  Es en lo
     * que el optimizador convierte un `do { } while (...)` pequeno, asi que
     * rechazarlo dejaba sin contar despues de optimizar lo que si se contaba
     * antes -- y el informe acusaba al optimizador de haber empeorado el coste.
     *
     * Se marca a proposito y no se mete en `body`: quien CLONE tiene que
     * saberlo (el latch es la propia cabecera), y por eso mas abajo no llega a
     * `valid`. */
    st.self_loop = st.body.empty();
    if (st.self_loop) {
        const auto &t = fn.blocks[H].instrs;
        const bool vuelve_a_si =
            !t.empty() && t.back().op == IrOp::BR_COND &&
            (t.back().target_block == H || t.back().false_block == H);
        if (!vuelve_a_si) return bail("loop.degenerate");
    }

    /* El LATCH primero, porque en un bucle ROTADO la guarda vive en el.
     *
     * Se admiten las dos formas de volver: `BR` al header -- el `for` de toda
     * la vida, con la guarda arriba -- y `BR_COND` cuyo destino verdadero es
     * el header, que es como se compila un `do { } while (...)`: el cuerpo va
     * primero y la comprobacion al final. */
    if (st.self_loop) {
        st.latch = H; // se vuelve por si mismo
    } else {
        for (IrBlockId b : st.body) {
            const auto &bi = fn.blocks[b].instrs;
            if (bi.empty()) continue;
            const IrInstr &bt = bi.back();
            const bool vuelve = (bt.op == IrOp::BR && bt.target_block == H) ||
                                (bt.op == IrOp::BR_COND &&
                                 (bt.target_block == H || bt.false_block == H));
            if (vuelve) {
                if (st.latch != IR_NO_BLOCK) return bail("loop.two_latches");
                st.latch = b;
            }
        }
    }
    if (st.latch == IR_NO_BLOCK) return bail("loop.no_latch");

    /* Header limpio: [PHIs...] + [calculo de la guarda] + [br_cond].
     *
     * Salvo si el bucle esta ROTADO: entonces la cabecera termina en un salto
     * incondicional -- se entra siempre, el cuerpo va antes que la
     * comprobacion -- y quien decide si se sigue es el latch.  Un
     * `do { } while (i < 24)` es exactamente eso, y sin reconocerlo el coste
     * declaraba O(n) veinticuatro vueltas fijas. */
    const auto &hins = fn.blocks[H].instrs;
    if (hins.size() < 2) return bail("loop.header_too_small");
    const IrInstr &hterm = hins.back();
    st.rotated = hterm.op != IrOp::BR_COND;
    const IrBlockId G = st.rotated ? st.latch : H; // donde esta la guarda
    const auto &gins = fn.blocks[G].instrs;
    const IrInstr &term = gins.back();
    if (term.op != IrOp::BR_COND || term.operands.empty())
        return bail("loop.header_not_conditional");
    const IrValueId cond = term.operands[0];
    const bool t_in = st.contains(term.target_block);
    const bool f_in = st.contains(term.false_block);
    // Exactamente uno dentro y uno fuera.
    if (t_in == f_in) return bail("loop.header_branch_not_exit");
    st.body_entry = t_in ? term.target_block : term.false_block;
    st.exit = t_in ? term.false_block : term.target_block;
    /* Rotado, la cabecera no se comprueba: no hay guarda que mirar en ella, y
     * lo que la limpieza de abajo exige -- que todo lo que hay alimente a la
     * condicion -- no tiene sentido ahi.  Se cuenta igual; lo que no se puede
     * es clonar, y eso lo dice `valid`. */
    if (st.rotated) {
        st.body_entry = hterm.op == IrOp::BR ? hterm.target_block : H;
    }

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
            if (st.preheader != IR_NO_BLOCK)
                return bail("loop.two_entries"); // >1 entrada.
            st.preheader = (IrBlockId)p;
        }
    }
    if (st.preheader == IR_NO_BLOCK) return bail("loop.no_preheader");

    // PHIs del header: cada una con {arg preheader, arg latch}.
    for (const IrInstr &in : hins) {
        if (in.op != IrOp::PHI) continue;
        if (in.phi_args.size() != 2) return bail("loop.phi_not_binary");
        HeaderPhi hp;
        hp.dst = in.dst;
        for (const auto &pa : in.phi_args) {
            if (pa.block == st.preheader)
                hp.init = pa.value;
            else if (pa.block == st.latch)
                hp.back = pa.value;
            else
                return bail("loop.phi_from_elsewhere");
        }
        if (hp.init == IR_NO_VALUE || hp.back == IR_NO_VALUE)
            return bail("loop.phi_incomplete");
        st.phis.push_back(hp);
    }
    if (st.phis.empty()) return bail("loop.header_without_phis");

    /* Hasta aqui, la propiedad DEBIL: cabecera con guarda contada, un solo
     * latch, un solo preheader y PHIs completas.  Con eso el numero de vueltas
     * esta ACOTADO por la cuenta, y eso ya es conocimiento util.
     *
     * Lo que queda por comprobar -- que ningun valor del cuerpo se use fuera y
     * que no haya mas salidas -- hace falta para TRANSFORMAR el bucle, no para
     * contarlo: una salida anticipada solo puede hacer que de menos vueltas, y
     * un valor que escapa no cambia cuantas da. */
    st.countable = true;

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
                if (body_defs.count(o)) return bail("loop.value_escapes");
            for (const auto &pa : in.phi_args) {
                if (st.contains(pa.block) && body_defs.count(pa.value))
                    return bail("loop.value_escapes");
                if (body_defs.count(pa.value) && !st.contains(pa.block))
                    return bail("loop.value_escapes");
            }
        }
    }

    /* En el header solo PHIs y el CALCULO DE LA GUARDA -- para CLONARLO.
     *
     * Esta comprobacion iba antes de todo, y por eso descartaba bucles
     * perfectamente contados: un `do { } while` colapsado a un solo bloque
     * lleva el acumulador en la cabecera -- claro, si la cabecera ES el cuerpo
     * --, y salia con "la cabecera hace de mas" sobre veinticuatro vueltas
     * fijas.  Lo que la cabecera haga no cambia CUANTAS veces se cumple la
     * guarda; cambia si se puede duplicar sin repetir efectos. */
    if (!st.rotated) {
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
                return bail("loop.header_does_more"); // no aporta a la guarda
            if (!pure_compute(in.op)) return bail("loop.header_impure");
            if (analysis::memory_access_kind(in.op).touches)
                return bail("loop.header_touches_memory");
        }
    }

    /* Salida UNICA: nada de lo que hay dentro salta FUERA del bucle.
     *
     * Se recorre `loop_blocks` y no `body`: con un bucle anidado dentro, el
     * cuerpo es solo el nivel de este, y un `break` escrito en el bucle de
     * DENTRO se saltaria la comprobacion.  Quien clona necesita que no lo
     * haya; quien cuenta se queda con una cota, que es lo que dice
     * `countable`. */
    for (IrBlockId b : st.loop_blocks) {
        if (b == H) continue; // el header sale a proposito: es la guarda
        const auto &bi = fn.blocks[b].instrs;
        if (bi.empty()) return bail("loop.empty_body_block");
        const IrInstr &bt = bi.back();
        if (bt.op == IrOp::BR) {
            if (!st.contains(bt.target_block)) return bail("loop.body_exits");
        } else if (bt.op == IrOp::BR_COND) {
            if (!st.contains(bt.target_block) || !st.contains(bt.false_block))
                return bail("loop.body_exits");
        } else {
            // RET/THROW/etc. dentro del cuerpo: mas de una salida.
            return bail("loop.body_terminates");
        }
    }

    /* Rotado se CUENTA pero no se transforma: quien desenrolla da por hecho
     * que la guarda esta en la cabecera y que puede no entrar ninguna vez, y
     * aqui se entra siempre al menos una. */
    if (st.rotated) return bail("loop.rotated");
    /* Y el de un solo bloque tampoco se clona: el latch es la propia cabecera,
     * asi que no hay cuerpo que copiar sin copiar tambien la guarda. */
    if (st.self_loop) return bail("loop.self_loop");

    st.valid = true;
    return st;
}

} // namespace analysis
