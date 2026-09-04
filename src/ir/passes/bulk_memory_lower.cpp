/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file bulk_memory_lower.cpp
 * @brief Implementacion del pase (ver el header para el porque de la division).
 */

#include "util/env_flags.h"
#include "ir/passes/bulk_memory_lower.h"

#include "analysis/asa/observed.h" // decirlo ANTES de deshacerlo
#include "analysis/facts/bulk_memory.h"
#include "ir/ssa_ir.h"

#include <algorithm>
#include <cstdlib>

namespace ir {

namespace {

/**
 * @brief Reduce a UNA operacion de bloque los grupos de escrituras seguidas
 *        que, juntas, rellenan un tramo contiguo.
 *
 * Es la otra mitad de este pase: arriba se reducen los bucles, aqui las
 * tiradas en recta.  La transformacion es distinta -- alli hay que recablear
 * el grafo, aqui solo sustituir instrucciones dentro de un bloque -- pero lo
 * que se produce es lo MISMO, un @c MEMSET, asi que el backend no distingue de
 * cual de las dos formas venia.
 *
 * De donde salen: los campos de una vista estan pegados por construccion, y
 * ponerlos a cero uno a uno es escribir largo lo que la maquina hace de una
 * vez.  El bloque de contexto de un cambio de tarea son diecinueve escrituras
 * que son 152 bytes seguidos.
 *
 * La direccion de destino NO se calcula: se REUSA la del primer almacenamiento
 * del grupo, que ya esta computada y ya domina el punto donde va la operacion.
 * Calcularla otra vez dejaria la vieja viva hasta que alguien la limpiara, y
 * ademas obligaria a decidir donde insertarla.
 *
 * @param fn    Funcion a transformar.
 * @param facts Base de hechos donde DECIR lo reconocido antes de deshacerlo, o
 *              nullptr.
 * @return true si se cambio algo.
 */
bool lower_straight_line_runs(IrFunction &fn, analysis::asa::FactStore *facts) {
    const analysis::StraightLineBulkReport rep =
        analysis::analyze_straight_line_bulk(fn);
    /* Lo que se sabe, DICHO antes de tocarlo: dos lineas mas abajo el grupo ya
     * no existe y no hay nada que reconocer.  Mismo motivo que arriba. */
    if (facts != nullptr) {
        for (const analysis::StraightLineBulkFact &f : rep.facts) {
            analysis::asa::Fact h;
            if (analysis::asa::straight_line_bulk_fact(
                    *facts, fn, f, analysis::asa::kStageDuringOpt,
                    analysis::asa::Source::Static, h))
                facts->add(std::move(h));
        }
    }
    if (rep.facts.empty()) return false;

    bool changed = false;
    /* Un solo grupo por bloque en cada pasada: al reconstruir el bloque, los
     * indices que llevan los demas hechos de ese mismo bloque dejan de
     * corresponder con nada.  El pase se vuelve a llamar, asi que el segundo
     * grupo entra en la vuelta siguiente -- y con indices ya recalculados. */
    std::vector<bool> done(fn.blocks.size(), false);
    for (const analysis::StraightLineBulkFact &f : rep.facts) {
        if (f.block >= fn.blocks.size() || f.instrs.empty()) continue;
        if (done[f.block]) continue;
        done[f.block] = true;
        IrBlock &bb = fn.blocks[f.block];
        if (f.instrs.back() >= bb.instrs.size()) continue;

        /* El byte que se repite, y cuantos.  Los dos como constantes nuevas:
         * las que habia guardaban un valor del ancho del CAMPO, y lo que la
         * operacion de bloque quiere es un byte y una longitud. */
        const IrValueId v_fill = fn.new_value(IrType::I64);
        fn.values[v_fill].is_const = true;
        fn.values[v_fill].const_val = f.fill;
        IrInstr k_fill{};
        k_fill.op = IrOp::CONST;
        k_fill.type = IrType::I64;
        k_fill.dst = v_fill;
        k_fill.imm = f.fill;

        const IrValueId v_len = fn.new_value(IrType::I64);
        fn.values[v_len].is_const = true;
        fn.values[v_len].const_val = f.bytes;
        IrInstr k_len{};
        k_len.op = IrOp::CONST;
        k_len.type = IrType::I64;
        k_len.dst = v_len;
        k_len.imm = f.bytes;

        const IrInstr &first = bb.instrs[f.instrs.front()];
        IrInstr op{};
        op.op = IrOp::MEMSET;
        op.type = IrType::VOID;
        op.dst = IR_NO_VALUE;
        op.operands = {first.operands[1], v_fill, v_len};
        op.source_line = first.source_line;

        /* Se reconstruye el bloque: en el sitio del PRIMER almacenamiento van
         * las dos constantes y la operacion, y los demas del grupo desaparecen.
         * En el primero y no al final porque ahi es donde estaba la primera
         * escritura, y adelantar o atrasar el conjunto respecto de lo que haya
         * alrededor es justo lo que el detector se ha cuidado de no permitir. */
        std::vector<bool> drop(bb.instrs.size(), false);
        for (uint32_t i : f.instrs)
            if (i < drop.size()) drop[i] = true;
        std::vector<IrInstr> out;
        out.reserve(bb.instrs.size() + 3);
        for (size_t i = 0; i < bb.instrs.size(); ++i) {
            if (i == f.instrs.front()) {
                out.push_back(std::move(k_fill));
                out.push_back(std::move(k_len));
                out.push_back(std::move(op));
                continue;
            }
            if (drop[i]) continue;
            out.push_back(std::move(bb.instrs[i]));
        }
        bb.instrs = std::move(out);
        changed = true;
    }
    return changed;
}

} // namespace

bool ir_pass_bulk_memory_lower(IrFunction &fn,
                               analysis::asa::FactStore *facts) {
    if (fn.is_native || fn.blocks.empty()) return false;
    /* Quien IMPLEMENTA el movimiento de memoria no puede ver su bucle
     * reducido a un movimiento de memoria: seria una llamada a si mismo.  Es
     * la misma marca que usan los demas reconocedores. */
    if (fn.no_idiom) return false;
    /* Interruptor, como el resto de pases de este nivel: permite comparar el
     * mismo programa con y sin la reduccion sin recompilar el compilador, que
     * es lo unico que distingue "esto lo rompio el pase" de "esto ya estaba
     * roto". */
    if (util::flag_on(util::FlagId::NoBulkMemory)) return false;

    const std::vector<analysis::BulkMemoryFact> hechos =
        analysis::detect_bulk_memory(fn);

    /* Lo que se sabe, DICHO antes de tocarlo.
     *
     * Que este bucle es una copia solo se sabe mientras el bucle existe: dos
     * lineas mas abajo queda una instruccion de bloque y no hay nada que
     * reconocer.  Antes ese conocimiento moria con la transformacion que lo
     * produjo, y con el la unica forma de distinguir "el pase no vio el
     * bucle" de "lo vio y decidio no tocarlo".
     *
     * Se publica de TODOS los reconocidos, incluso de los que luego no se
     * reduzcan: que falte el preheader no hace menos cierto que el bucle sea
     * una copia. */
    if (facts != nullptr) {
        for (const analysis::BulkMemoryFact &f : hechos) {
            /* El hecho lo arma el MISMO sitio que lo arma para el dominio.
             * Lo que cambia entre los dos es el MOMENTO y la procedencia, no
             * lo que el hecho dice. */
            analysis::asa::Fact h;
            if (analysis::asa::bulk_memory_fact(
                    *facts, fn, f, analysis::asa::kStageDuringOpt,
                    analysis::asa::Source::Static, h))
                facts->add(std::move(h));
        }
    }

    /* Las dos mitades son INDEPENDIENTES: una funcion sin bucles puede tener
     * perfectamente una tirada de escrituras seguidas, que es justo el caso de
     * poner a cero una vista.  Salir aqui las dejaba fuera a todas. */
    bool cambiado = lower_straight_line_runs(fn, facts);
    if (hechos.empty()) return cambiado;

    for (const analysis::BulkMemoryFact &f : hechos) {
        if (f.st.preheader >= fn.blocks.size() || f.st.exit >= fn.blocks.size())
            continue;

        /* La operacion va en el PREHEADER, no donde estaba el bucle.  Ahi es
         * donde ya estan disponibles las bases y la cota, y donde el flujo
         * pasa exactamente una vez -- que es cuantas veces debe hacerse el
         * movimiento. */
        IrBlock &pre = fn.blocks[f.st.preheader];
        if (pre.instrs.empty()) continue;

        // Bytes = elementos * ancho.  Con ancho 1 la multiplicacion sobra y no
        // se emite: la cuenta de elementos YA son los bytes.
        IrValueId v_bytes = f.n_elems;
        std::vector<IrInstr> previas;
        if (f.width != 1) {
            const IrValueId v_w = fn.new_value(IrType::I64);
            fn.values[v_w].is_const = true;
            fn.values[v_w].const_val = f.width;
            IrInstr k{};
            k.op = IrOp::CONST;
            k.type = IrType::I64;
            k.dst = v_w;
            k.imm = f.width;
            previas.push_back(std::move(k));

            const IrValueId v_n = fn.new_value(IrType::I64);
            IrInstr mul{};
            mul.op = IrOp::MUL;
            mul.type = IrType::I64;
            mul.dst = v_n;
            mul.operands = {f.n_elems, v_w};
            previas.push_back(std::move(mul));
            v_bytes = v_n;
        }

        IrInstr op{};
        op.op = (f.kind == analysis::BulkMemoryFact::Kind::Copy)
                    ? IrOp::MEMCPY
                    : IrOp::MEMSET;
        op.type = IrType::VOID;
        op.dst = IR_NO_VALUE;
        op.operands = {f.dst_base,
                       (f.kind == analysis::BulkMemoryFact::Kind::Copy)
                           ? f.src_base
                           : f.value,
                       v_bytes};
        op.source_line = pre.instrs.back().source_line;
        previas.push_back(std::move(op));

        // Se insertan ANTES del terminador del preheader, que es quien salta
        // a la cabecera.
        pre.instrs.insert(pre.instrs.end() - 1,
                          std::make_move_iterator(previas.begin()),
                          std::make_move_iterator(previas.end()));

        /* Y el preheader deja de entrar al bucle: salta directo a la salida.
         * Los bloques del bucle quedan sin alcanzar y los barre la limpieza --
         * no hace falta desmontarlos a mano, y hacerlo seria arriesgarse a
         * dejar el grafo a medias. */
        IrInstr &term = pre.instrs.back();
        term.op = IrOp::BR;
        term.operands.clear();
        term.target_block = f.st.exit;
        term.false_block = IR_NO_BLOCK;
        pre.succs.clear();
        pre.succs.push_back(f.st.exit);

        IrBlock &salida = fn.blocks[f.st.exit];
        if (std::find(salida.preds.begin(), salida.preds.end(),
                      f.st.preheader) == salida.preds.end())
            salida.preds.push_back(f.st.preheader);
        // La cabecera pierde al preheader como predecesor, y con el su PHI de
        // entrada: el valor del indice al entrar ya no existe.
        IrBlock &cab = fn.blocks[f.st.header];
        cab.preds.erase(
            std::remove(cab.preds.begin(), cab.preds.end(), f.st.preheader),
            cab.preds.end());
        for (IrInstr &in : cab.instrs) {
            if (in.op != IrOp::PHI) break;
            in.phi_args.erase(
                std::remove_if(in.phi_args.begin(), in.phi_args.end(),
                               [&f](const IrPhiArg &pa) {
                                   return pa.block == f.st.preheader;
                               }),
                in.phi_args.end());
        }
        cambiado = true;
    }
    return cambiado;
}

} // namespace ir
