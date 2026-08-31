/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file bulk_memory.cpp
 * @brief Implementacion del hecho de movimiento de memoria en bloque.
 */

#include "analysis/facts/bulk_memory.h"

#include "analysis/facts/loop_facts.h"
#include "analysis/facts/ir_facts.h"
#include "analysis/memory/memory_access.h"
#include "analysis/memory/points_to.h"
#include "ir/ssa_ir.h"

#include <algorithm>

namespace analysis {

namespace {

/// Bytes que mueve un acceso escalar segun su tipo IR.  Se pide al vocabulario
/// comun en vez de tener aqui una segunda tabla de anchos.
int64_t ancho_de(const ir::IrInstr &ins) {
    return (int64_t)analysis::memory_access_size(ins.type);
}

/**
 * @brief Resuelve una direccion como @c base + iv * escala.
 *
 * Es lo unico que este fichero deriva por su cuenta, y solo porque describe
 * una RELACION -- "esta direccion avanza con el indice" -- que ningun analisis
 * publica todavia en esa forma.  Se admiten las tres maneras en que el
 * frontend y el optimizador la escriben:
 *
 *     base + iv                (elementos de un byte)
 *     base + (iv * k)          (elementos de k bytes)
 *     base + (iv << s)         (lo mismo, con la multiplicacion plegada)
 *
 * y el @c bitcast que suele haber en medio, que no cambia el valor.
 *
 * @param fn Funcion.
 * @param def Instruccion que define cada valor (nullptr si es parametro).
 * @param dir Valor de la direccion.
 * @param iv Valor del indice.
 * @param base_out Base resuelta.
 * @param escala_out Bytes que avanza la direccion por vuelta.
 * @return true si la direccion es exactamente esa forma.
 */
bool resolve_direccion(const ir::IrFunction &fn,
                       const std::vector<const ir::IrInstr *> &def,
                       ir::IrValueId dir, ir::IrValueId iv,
                       ir::IrValueId &base_out, int64_t &escala_out) {
    if (dir >= def.size() || def[dir] == nullptr) return false;
    const ir::IrInstr *d = def[dir];
    // Un bitcast no cambia la direccion: se atraviesa.
    while (d != nullptr && d->op == ir::IrOp::BITCAST &&
           d->operands.size() == 1) {
        const ir::IrValueId v = d->operands[0];
        if (v >= def.size()) return false;
        d = def[v];
    }
    if (d == nullptr || d->op != ir::IrOp::ADD || d->operands.size() != 2)
        return false;

    // El indice puede venir directo o multiplicado/desplazado.  Se prueba por
    // los dos lados de la suma: la base es el otro.
    auto es_indice = [&](ir::IrValueId v, int64_t &escala) -> bool {
        // Directo (posiblemente con bitcast en medio).
        ir::IrValueId cur = v;
        while (cur < def.size() && def[cur] != nullptr &&
               def[cur]->op == ir::IrOp::BITCAST &&
               def[cur]->operands.size() == 1)
            cur = def[cur]->operands[0];
        if (cur == iv) {
            escala = 1;
            return true;
        }
        if (cur >= def.size() || def[cur] == nullptr) return false;
        const ir::IrInstr *m = def[cur];
        // iv * k
        if (m->op == ir::IrOp::MUL && m->operands.size() == 2) {
            ir::IrValueId a = m->operands[0], b = m->operands[1];
            ir::IrValueId otro = ir::IR_NO_VALUE;
            if (a == iv)
                otro = b;
            else if (b == iv)
                otro = a;
            else
                return false;
            if (otro >= fn.values.size() || !fn.values[otro].is_const)
                return false;
            escala = fn.values[otro].const_val;
            return escala > 0;
        }
        // iv << s
        if (m->op == ir::IrOp::SHL && m->operands.size() == 2 &&
            m->operands[0] == iv) {
            const ir::IrValueId s = m->operands[1];
            if (s >= fn.values.size() || !fn.values[s].is_const) return false;
            const int64_t sh = fn.values[s].const_val;
            if (sh < 0 || sh > 6) return false;
            escala = (int64_t)1 << sh;
            return true;
        }
        return false;
    };

    int64_t esc = 0;
    if (es_indice(d->operands[1], esc)) {
        base_out = d->operands[0];
        escala_out = esc;
        return true;
    }
    if (es_indice(d->operands[0], esc)) {
        base_out = d->operands[1];
        escala_out = esc;
        return true;
    }
    return false;
}

} // namespace

std::vector<BulkMemoryFact> detect_bulk_memory(const ir::IrFunction &fn) {
    std::vector<BulkMemoryFact> out;
    if (fn.blocks.empty()) return out;

    /* Lo PRIMERO, lo que decide si hay algo que hacer.  Sin un bucle no puede
     * haber un movimiento de memoria, asi que preparar antes las tablas era
     * recorrer la funcion entera para tirarlo. */
    const LoopFacts lf = compute_loop_facts(fn);
    if (lf.loop_count == 0) return out;

    // Bucles que contienen a otro: hacen mas cosas que mover memoria.
    std::vector<bool> tiene_hijo(lf.loop_count, false);
    for (uint32_t l = 0; l < lf.loop_count; ++l)
        if (lf.parent_loop[l] != LoopFacts::NO_LOOP &&
            lf.parent_loop[l] < tiene_hijo.size())
            tiene_hijo[lf.parent_loop[l]] = true;

    const IrFacts hechos = build_ir_facts(fn);
    const PointsTo pt = compute_points_to(fn, hechos);

    /* En QUE BLOQUE se define cada valor.  Solo esto: quien lo define ya lo
     * sabe `hechos.def_of`, y se construia aqui otra vez a mano por delante
     * -- el mismo recorrido, el mismo resultado, dos veces.  El bloque no lo
     * lleva `IrFacts`, asi que ese si hay que sacarlo. */
    std::vector<int> def_block(fn.values.size(), -1);
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi)
        for (const ir::IrInstr &in : fn.blocks[bi].instrs)
            if (in.dst != ir::IR_NO_VALUE && in.dst < def_block.size())
                def_block[in.dst] = (int)bi;

    for (uint32_t L = 0; L < lf.loop_count; ++L) {
        if (tiene_hijo[L]) continue;

        BulkMemoryFact f;
        f.loop_id = L;
        f.st = detect_loop_structure(fn, lf, L);
        if (!f.st.valid) continue;
        if (!detect_loop_iv(fn, def_block, f.st.header, f.st.preheader,
                            f.st.latch, f.iv))
            continue;
        // Solo el recorrido de uno en uno: con otro paso, el tramo tocado
        // tiene huecos y no es un bloque contiguo.
        if (f.iv.stride != 1) continue;
        // El indice arranca en 0 y la cota es invariante: el tramo va de la
        // base a la base mas la cota.  Un arranque distinto seria un tramo
        // desplazado -- se puede describir, pero hoy no hace falta y admitirlo
        // sin usarlo solo daria ocasion de equivocarse.
        if (f.iv.init >= fn.values.size() || !fn.values[f.iv.init].is_const ||
            fn.values[f.iv.init].const_val != 0)
            continue;
        if (f.iv.cmp_offset != 0) continue;
        if (f.iv.bound == ir::IR_NO_VALUE) continue;
        if (f.iv.bound < def_block.size() && def_block[f.iv.bound] >= 0 &&
            f.st.contains((ir::IrBlockId)def_block[f.iv.bound]))
            continue; // la cota cambia dentro: no hay tramo fijo.
        // La comparacion tiene que ser estricta: con `<=` el tramo llega uno
        // mas alla de la cota y la cuenta de elementos no seria la cota.
        if (f.iv.cmp_op != ir::IrOp::CMP_LT && f.iv.cmp_op != ir::IrOp::CMP_ULT)
            continue;
        f.n_elems = f.iv.bound;

        // Recorrer TODO el bucle y clasificar lo que hace.  Lo que no sea
        // parte de "recorrer y mover" descarta el bucle entero.
        const ir::IrInstr *el_store = nullptr;
        const ir::IrInstr *el_load = nullptr;
        bool descartado = false;
        for (const ir::IrBlockId b : f.st.loop_blocks) {
            if (descartado) break;
            for (const ir::IrInstr &in : fn.blocks[b].instrs) {
                const MemoryAccess acc = memory_access(in, pt);
                if (acc.opaque) {
                    descartado = true;
                    break;
                }
                if (acc.is_store) {
                    if (el_store != nullptr) {
                        descartado = true;
                        break;
                    }
                    el_store = &in;
                    continue;
                }
                if (acc.is_load) {
                    if (el_load != nullptr) {
                        descartado = true;
                        break;
                    }
                    el_load = &in;
                    continue;
                }
                if (acc.touches) {
                    descartado = true;
                    break;
                }
                // Sin tocar memoria: solo se admite el andamiaje del recorrido
                // -- indices, direcciones, la guarda y los saltos.
                switch (in.op) {
                case ir::IrOp::PHI:
                case ir::IrOp::ADD:
                case ir::IrOp::SUB:
                case ir::IrOp::MUL:
                case ir::IrOp::SHL:
                case ir::IrOp::BITCAST:
                case ir::IrOp::MOV:
                case ir::IrOp::CONST:
                case ir::IrOp::CMP_LT:
                case ir::IrOp::CMP_ULT:
                case ir::IrOp::CMP_LE:
                case ir::IrOp::CMP_ULE:
                case ir::IrOp::BR:
                case ir::IrOp::BR_COND: break;
                default: descartado = true; break;
                }
                if (descartado) break;
            }
        }
        if (descartado || el_store == nullptr) continue;
        if (el_store->operands.size() < 2) continue;

        const int64_t w = ancho_de(*el_store);
        if (w <= 0) continue;

        // La direccion escrita tiene que avanzar EXACTAMENTE el ancho del
        // acceso: asi las escrituras se tocan sin solaparse y cubren un tramo
        // continuo.  Si avanza mas, hay huecos; si menos, se pisan.
        ir::IrValueId base_d = ir::IR_NO_VALUE;
        int64_t esc_d = 0;
        if (!resolve_direccion(fn, hechos.def_of, el_store->operands[1],
                               f.iv.phi, base_d, esc_d))
            continue;
        if (esc_d != w) continue;
        // Y la base no puede moverse dentro del bucle.
        if (base_d < def_block.size() && def_block[base_d] >= 0 &&
            f.st.contains((ir::IrBlockId)def_block[base_d]))
            continue;
        f.dst_base = base_d;
        f.ancho = w;

        const ir::IrValueId v_escrito = el_store->operands[0];
        if (el_load == nullptr) {
            // RELLENO: el valor tiene que venir de fuera.  Uno calculado
            // dentro cambiaria en cada vuelta y no seria un relleno.
            if (v_escrito < def_block.size() && def_block[v_escrito] >= 0 &&
                f.st.contains((ir::IrBlockId)def_block[v_escrito]))
                continue;
            /* Y el valor tiene que caber en un BYTE, porque eso es lo que la
             * operacion de bloque repite.  Un bucle que escribe un f64 o un
             * entero ancho invariante recorre un tramo contiguo igual, pero
             * reducirlo a un relleno de bytes escribe otra cosa: repetiria el
             * byte bajo en vez del valor entero.
             *
             * Se admite cuando el acceso YA es de un byte, o cuando el valor
             * es una constante con todos sus bytes iguales -- que es el caso
             * de poner a cero, con diferencia el mas comun.  Cualquier otro
             * ancho no es un relleno por mucho que lo parezca. */
            bool cabe_en_byte = (w == 1);
            if (!cabe_en_byte && v_escrito < fn.values.size() &&
                fn.values[v_escrito].is_const) {
                const uint64_t k = (uint64_t)fn.values[v_escrito].const_val;
                const uint64_t b = k & 0xFFull;
                uint64_t repetido = 0;
                for (int i = 0; i < 8; ++i)
                    repetido |= b << (i * 8);
                // Solo se comparan los bytes que el acceso escribe de verdad.
                const uint64_t mascara =
                    (w >= 8) ? ~0ull : (((uint64_t)1 << (w * 8)) - 1);
                cabe_en_byte = ((k & mascara) == (repetido & mascara));
            }
            if (!cabe_en_byte) continue;
            f.clase = BulkMemoryFact::Clase::Relleno;
            f.valor = v_escrito;
            out.push_back(std::move(f));
            continue;
        }

        // COPIA: lo que se escribe es justo lo que se acaba de leer, y el
        // origen recorre su tramo con el mismo paso.
        if (el_load->dst != v_escrito) continue;
        if (el_load->operands.empty()) continue;
        if (ancho_de(*el_load) != w) continue;
        ir::IrValueId base_s = ir::IR_NO_VALUE;
        int64_t esc_s = 0;
        if (!resolve_direccion(fn, hechos.def_of, el_load->operands[0],
                               f.iv.phi, base_s, esc_s))
            continue;
        if (esc_s != w) continue;
        if (base_s < def_block.size() && def_block[base_s] >= 0 &&
            f.st.contains((ir::IrBlockId)def_block[base_s]))
            continue;
        f.clase = BulkMemoryFact::Clase::Copia;
        f.src_base = base_s;
        out.push_back(std::move(f));
    }
    return out;
}

} // namespace analysis
