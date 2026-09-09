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

#include "analysis/effects/ir_effects.h" // que puede pasar entre dos escrituras
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
int64_t access_bytes(const ir::IrInstr &ins) {
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
bool resolve_direccion(const ir::IrFunction &fn, const IrFacts &facts,
                       ir::IrValueId dir, ir::IrValueId iv,
                       ir::IrValueId &base_out, int64_t &escala_out) {
    /* Se pregunta por la PUERTA (`facts.def`) y no por la tabla: ahi dentro ya
     * no hay punteros, sino el bloque y la posicion, y quien resuelve eso es
     * ella.  Ademas comprueba los limites, asi que un valor de un IR que ya
     * cambio da "no lo se" en vez de una instruccion cualquiera. */
    const ir::IrInstr *d = facts.def(dir);
    if (d == nullptr) return false;
    // Un bitcast no cambia la direccion: se atraviesa.
    while (d != nullptr && d->op == ir::IrOp::BITCAST &&
           d->operands.size() == 1) {
        d = facts.def(d->operands[0]);
    }
    if (d == nullptr || d->op != ir::IrOp::ADD || d->operands.size() != 2)
        return false;

    // El indice puede venir directo o multiplicado/desplazado.  Se prueba por
    // los dos lados de la suma: la base es el otro.
    auto es_indice = [&](ir::IrValueId v, int64_t &escala) -> bool {
        // Directo (posiblemente con bitcast en medio).
        ir::IrValueId cur = v;
        for (const ir::IrInstr *bc = facts.def(cur);
             bc != nullptr && bc->op == ir::IrOp::BITCAST &&
             bc->operands.size() == 1;
             bc = facts.def(cur))
            cur = bc->operands[0];
        if (cur == iv) {
            escala = 1;
            return true;
        }
        const ir::IrInstr *m = facts.def(cur);
        if (m == nullptr) return false;
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

BulkMemoryReport analyze_bulk_memory(const ir::IrFunction &fn) {
    BulkMemoryReport out;
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

    /* Donde se define cada valor lo trae `hechos`: es el mismo recorrido que
     * ya hizo `build_ir_facts` tres lineas mas arriba.  Se construia aqui a
     * mano por delante -- el mismo doble bucle, el mismo resultado. */
    const std::vector<int32_t> &def_block = hechos.def_block;

    for (uint32_t L = 0; L < lf.loop_count; ++L) {
        BulkMemoryFact f;
        f.loop_id = L;

        /* Cada renuncia con SU codigo.  Eran quince `continue` mudos, y un
         * analisis que calla al renunciar parece que funciona: "no hay ningun
         * memcpy aqui" y "habia uno y me falto un byte para verlo" salian
         * igual.  El codigo es lo que dice DONDE mirar -- y, de cara al
         * usuario, la diferencia entre un consejo y un silencio. */
        const ir::IrBlockId cab =
            static_cast<ir::IrBlockId>(lf.header_block_of(L));
        auto rendirse = [&](const char *code) {
            out.declines.push_back(BulkMemoryDecline{L, cab, code});
        };

        if (tiene_hijo[L]) {
            rendirse("bulk.has_inner_loop");
            continue;
        }
        f.st = detect_loop_structure(fn, lf, L);
        if (!f.st.valid) {
            /* El motivo lo da el reconocedor de forma, que tiene veinticuatro
             * codigos propios.  Repetirlo aqui con uno generico seria tirar lo
             * que el otro acaba de averiguar. */
            rendirse((f.st.why != nullptr && f.st.why[0] != '\0')
                         ? f.st.why
                         : "bulk.shape_unsupported");
            continue;
        }
        if (!detect_loop_iv(fn, def_block, f.st.header, f.st.preheader,
                            f.st.latch, f.iv)) {
            rendirse("bulk.no_induction");
            continue;
        }
        // Solo el recorrido de uno en uno: con otro paso, el tramo tocado
        // tiene huecos y no es un bloque contiguo.
        if (f.iv.stride != 1) {
            rendirse("bulk.stride_not_one");
            continue;
        }
        // El indice arranca en 0 y la cota es invariante: el tramo va de la
        // base a la base mas la cota.  Un arranque distinto seria un tramo
        // desplazado -- se puede describir, pero hoy no hace falta y admitirlo
        // sin usarlo solo daria ocasion de equivocarse.
        if (f.iv.init >= fn.values.size() || !fn.values[f.iv.init].is_const ||
            fn.values[f.iv.init].const_val != 0) {
            rendirse("bulk.index_not_from_zero");
            continue;
        }
        if (f.iv.cmp_offset != 0) {
            rendirse("bulk.guard_has_offset");
            continue;
        }
        if (f.iv.bound == ir::IR_NO_VALUE) {
            rendirse("bulk.no_bound");
            continue;
        }
        if (f.iv.bound < def_block.size() && def_block[f.iv.bound] >= 0 &&
            f.st.contains((ir::IrBlockId)def_block[f.iv.bound])) {
            rendirse("bulk.bound_varies"); // cambia dentro: no hay tramo fijo
            continue;
        }
        // La comparacion tiene que ser estricta: con `<=` el tramo llega uno
        // mas alla de la cota y la cuenta de elementos no seria la cota.
        if (f.iv.cmp_op != ir::IrOp::CMP_LT &&
            f.iv.cmp_op != ir::IrOp::CMP_ULT) {
            rendirse("bulk.guard_not_strict");
            continue;
        }
        f.n_elems = f.iv.bound;

        // Recorrer TODO el bucle y clasificar lo que hace.  Lo que no sea
        // parte de "recorrer y mover" descarta el bucle entero.
        const ir::IrInstr *el_store = nullptr;
        const ir::IrInstr *el_load = nullptr;
        const char *descartado = nullptr;
        for (const ir::IrBlockId b : f.st.loop_blocks) {
            if (descartado != nullptr) break;
            for (const ir::IrInstr &in : fn.blocks[b].instrs) {
                const MemoryAccess acc = memory_access(in, pt);
                if (acc.opaque) {
                    descartado = "bulk.opaque_access";
                    break;
                }
                if (acc.is_store) {
                    if (el_store != nullptr) {
                        descartado = "bulk.two_stores";
                        break;
                    }
                    el_store = &in;
                    continue;
                }
                if (acc.is_load) {
                    if (el_load != nullptr) {
                        descartado = "bulk.two_loads";
                        break;
                    }
                    el_load = &in;
                    continue;
                }
                if (acc.touches) {
                    descartado = "bulk.other_memory_effect";
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
                case ir::IrOp::BORROW: // copia del puntero, no toca memoria
                case ir::IrOp::MOV:
                case ir::IrOp::CONST:
                case ir::IrOp::CMP_LT:
                case ir::IrOp::CMP_ULT:
                case ir::IrOp::CMP_LE:
                case ir::IrOp::CMP_ULE:
                case ir::IrOp::BR:
                case ir::IrOp::BR_COND: break;
                default: descartado = "bulk.body_does_more"; break;
                }
                if (descartado != nullptr) break;
            }
        }
        if (descartado != nullptr) {
            rendirse(descartado);
            continue;
        }
        if (el_store == nullptr) {
            rendirse("bulk.no_store");
            continue;
        }
        if (el_store->operands.size() < 2) {
            rendirse("bulk.malformed_store");
            continue;
        }

        const int64_t w = access_bytes(*el_store);
        if (w <= 0) {
            rendirse("bulk.unknown_width");
            continue;
        }

        // La direccion escrita tiene que avanzar EXACTAMENTE el ancho del
        // acceso: asi las escrituras se tocan sin solaparse y cubren un tramo
        // continuo.  Si avanza mas, hay huecos; si menos, se pisan.
        ir::IrValueId base_d = ir::IR_NO_VALUE;
        int64_t esc_d = 0;
        if (!resolve_direccion(fn, hechos, el_store->operands[1],
                               f.iv.phi, base_d, esc_d)) {
            rendirse("bulk.dst_address_not_resolved");
            continue;
        }
        if (esc_d != w) {
            rendirse("bulk.dst_stride_not_width");
            continue;
        }
        // Y la base no puede moverse dentro del bucle.
        if (base_d < def_block.size() && def_block[base_d] >= 0 &&
            f.st.contains((ir::IrBlockId)def_block[base_d])) {
            rendirse("bulk.dst_base_varies");
            continue;
        }
        f.dst_base = base_d;
        f.width = w;

        const ir::IrValueId v_escrito = el_store->operands[0];
        if (el_load == nullptr) {
            // RELLENO: el valor tiene que venir de fuera.  Uno calculado
            // dentro cambiaria en cada vuelta y no seria un relleno.
            if (v_escrito < def_block.size() && def_block[v_escrito] >= 0 &&
                f.st.contains((ir::IrBlockId)def_block[v_escrito])) {
                rendirse("bulk.fill_value_varies");
                continue;
            }
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
            if (!cabe_en_byte) {
                rendirse("bulk.fill_value_not_byte_repeatable");
                continue;
            }
            f.kind = BulkMemoryFact::Kind::Fill;
            f.value = v_escrito;
            out.facts.push_back(std::move(f));
            continue;
        }

        // COPIA: lo que se escribe es justo lo que se acaba de leer, y el
        // origen recorre su tramo con el mismo paso.
        if (el_load->dst != v_escrito) {
            rendirse("bulk.stored_value_not_loaded");
            continue;
        }
        if (el_load->operands.empty()) {
            rendirse("bulk.malformed_load");
            continue;
        }
        if (access_bytes(*el_load) != w) {
            rendirse("bulk.width_mismatch");
            continue;
        }
        ir::IrValueId base_s = ir::IR_NO_VALUE;
        int64_t esc_s = 0;
        if (!resolve_direccion(fn, hechos, el_load->operands[0],
                               f.iv.phi, base_s, esc_s)) {
            rendirse("bulk.src_address_not_resolved");
            continue;
        }
        if (esc_s != w) {
            rendirse("bulk.src_stride_not_width");
            continue;
        }
        if (base_s < def_block.size() && def_block[base_s] >= 0 &&
            f.st.contains((ir::IrBlockId)def_block[base_s])) {
            rendirse("bulk.src_base_varies");
            continue;
        }
        f.kind = BulkMemoryFact::Kind::Copy;
        f.src_base = base_s;
        out.facts.push_back(std::move(f));
    }
    return out;
}

std::vector<BulkMemoryFact> detect_bulk_memory(const ir::IrFunction &fn) {
    return analyze_bulk_memory(fn).facts;
}

// ===========================================================================
//  El mismo movimiento de bloque, escrito EN RECTA
// ===========================================================================

namespace {

/**
 * @brief Es @p v un valor cuyos @p bytes bajos son todos el MISMO byte?
 *
 * Es lo que separa un relleno de una tirada de escrituras cualquiera: la
 * instruccion de bloque repite UN byte, asi que guardar `0x0000000000000000`
 * se puede reducir y guardar `0x1234` no.  El cero, que es el caso que
 * aparece siempre, cumple.
 *
 * @param v     Valor guardado.
 * @param bytes Cuantos bytes se escriben.
 * @param out   Sale con el byte que se repite.
 * @return false si los bytes no son todos iguales.
 */
bool repeated_byte(uint64_t v, uint32_t bytes, uint8_t &out) {
    const uint8_t b = static_cast<uint8_t>(v & 0xFFu);
    for (uint32_t i = 1; i < bytes; ++i)
        if (static_cast<uint8_t>((v >> (i * 8)) & 0xFFu) != b) return false;
    out = b;
    return true;
}

} // namespace

StraightLineBulkReport analyze_straight_line_bulk(const ir::IrFunction &fn) {
    StraightLineBulkReport out;
    if (fn.is_native || fn.no_idiom || fn.blocks.empty()) return out;

    /* La base de hechos compartida, UNA vez para toda la funcion: la necesita
     * el modelo de efectos para saber que puede pasar entre dos escrituras del
     * mismo grupo. */
    const IrFacts ir_facts = build_ir_facts(fn);
    const PointsTo pt = compute_points_to(fn, ir_facts);

    /* Las constantes de TODA la funcion: el desplazamiento de un campo y el
     * valor guardado suelen estar definidos fuera del bloque que los usa --
     * el optimizador los saca --, asi que mirar solo el bloque dejaria de
     * reconocer justo los casos ya optimizados. */
    std::unordered_map<ir::IrValueId, int64_t> const_val;
    for (const ir::IrBlock &bb : fn.blocks)
        for (const ir::IrInstr &in : bb.instrs)
            if (in.op == ir::IrOp::CONST && in.dst != ir::IR_NO_VALUE)
                const_val[in.dst] = static_cast<int64_t>(in.imm);

    /* Y de que base cuelga cada direccion.  `add.ptr base, constante` es la
     * forma en que baja el acceso a un campo de una vista; una direccion que
     * no sea eso es su propia base con desplazamiento cero. */
    struct Addr {
        ir::IrValueId base;
        int64_t off;
    };
    std::unordered_map<ir::IrValueId, Addr> addr_of;
    for (const ir::IrBlock &bb : fn.blocks) {
        for (const ir::IrInstr &in : bb.instrs) {
            if (in.op != ir::IrOp::ADD || in.dst == ir::IR_NO_VALUE ||
                in.operands.size() != 2)
                continue;
            auto c1 = const_val.find(in.operands[1]);
            if (c1 == const_val.end()) continue;
            /* Encadenado: `(base + a) + b` es `base + (a+b)`.  Sin esto, un
             * campo de un elemento de un array de vistas nunca se reconoceria,
             * porque su direccion se arma en dos pasos. */
            auto prev = addr_of.find(in.operands[0]);
            if (prev != addr_of.end())
                addr_of[in.dst] = Addr{prev->second.base,
                                       prev->second.off + c1->second};
            else
                addr_of[in.dst] = Addr{in.operands[0], c1->second};
        }
    }
    const auto resolve = [&](ir::IrValueId v) -> Addr {
        auto it = addr_of.find(v);
        return it == addr_of.end() ? Addr{v, 0} : it->second;
    };

    /* Que valores salen de una LECTURA.  Solo para poder decir, cuando un
     * grupo se corta, que lo que hay ahi es una COPIA y que le falta -- ver
     * mas abajo --, en vez de dar el motivo generico. */
    std::vector<bool> loaded(fn.values.size(), false);
    for (const ir::IrBlock &bb : fn.blocks)
        for (const ir::IrInstr &in : bb.instrs)
            if (in.op == ir::IrOp::LOAD && in.dst != ir::IR_NO_VALUE &&
                in.dst < loaded.size())
                loaded[in.dst] = true;

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const ir::IrBlock &bb = fn.blocks[bi];
        StraightLineBulkFact cur;
        bool open = false;
        const auto close_run = [&](const char *reason) {
            if (!open) return;
            open = false;
            /* Un tramo mas corto que la lane mas estrecha no gana nada: la
             * instruccion de bloque tiene su propio arranque, y por debajo de
             * eso sale peor que las escrituras sueltas.  Se cuenta igual, que
             * es lo que distingue "no habia" de "habia y no compensaba". */
            if (cur.bytes >= 16 && cur.instrs.size() >= 2) {
                cur.block = static_cast<ir::IrBlockId>(bi);
                out.facts.push_back(std::move(cur));
            } else if (!cur.instrs.empty()) {
                BulkMemoryDecline d;
                d.header = static_cast<ir::IrBlockId>(bi);
                d.code = reason;
                out.declines.push_back(d);
            }
            cur = StraightLineBulkFact{};
        };

        for (size_t ii = 0; ii < bb.instrs.size(); ++ii) {
            const ir::IrInstr &in = bb.instrs[ii];
            /* Que se puede dejar pasar entre dos escrituras del grupo se le
             * pregunta al MODELO DE EFECTOS, no al opcode.
             *
             * Preguntarselo a `memory_access_kind` parecia bastar y no bastaba:
             * ese vocabulario contesta desde el opcode SOLO, y una llamada cae
             * en su caso por defecto -- "no toca memoria" --, cuando lo que
             * toca depende enteramente de a quien llame.  Con eso, el grupo se
             * fusionaba POR ENCIMA de las llamadas, y las escrituras que iban
             * detras pasaban a ir delante.
             *
             * No es teorico: `__module_init` construye los parametros de cada
             * clase escribiendo campo a campo y llama a `defclass` en medio.
             * Adelantar las escrituras de la clase siguiente hacia que la
             * llamada leyera otros datos, la clase no se registraba y el
             * programa devolvia CERO en vez de su resultado.  Ciento treinta y
             * seis casos, y ninguno decia por que. */
            const analysis::effects::EffectAnalysisResult ef =
                analysis::effects::effects_of_instr(fn, ir_facts, pt, in);
            const bool memory_free =
                ef.completeness ==
                    analysis::effects::AnalysisCompleteness::Complete &&
                !ef.effects.mem.reads_memory() &&
                !ef.effects.mem.writes_memory() && !ef.effects.may_allocate &&
                !ef.effects.may_block;
            if (memory_free) continue; // constantes y aritmetica: no estorban
            /* Cualquier otra cosa CORTA el grupo: juntarlo lo adelantaria o lo
             * atrasaria respecto de algo que puede mirar la misma memoria, y
             * eso no da un error, da otro resultado. */
            if (in.op != ir::IrOp::STORE || in.operands.size() != 2) {
                close_run("bulk.other_access_between");
                continue;
            }
            const Addr a = resolve(in.operands[1]);
            const uint32_t w = static_cast<uint32_t>(access_bytes(in));
            auto cv = const_val.find(in.operands[0]);
            uint8_t b = 0;
            if (cv == const_val.end() ||
                !repeated_byte(static_cast<uint64_t>(cv->second), w, b)) {
                /* Guardar algo que no es un byte repetido no es un relleno, y
                 * el motivo importa porque son tres casos distintos con tres
                 * salidas distintas:
                 *
                 *  - Viene de una LECTURA: entonces esto es una COPIA, y una
                 *    copia de bloque exige saber que las dos regiones no se
                 *    solapan.  Con dos punteros que llegan como parametros eso
                 *    no se puede demostrar aqui, asi que se dice cual es el
                 *    hecho que falta en vez de suponerlo -- suponerlo daria
                 *    otro resultado cuando de verdad se solapen.
                 *  - Es un valor CALCULADO: no hay nada que juntar; cada campo
                 *    lleva un numero distinto.
                 *  - Es una constante que no cabe en un byte: la operacion de
                 *    bloque repite UN byte, y `0x1234` no lo es. */
                const char *why = "bulk.stored_value_computed";
                if (cv != const_val.end())
                    why = "bulk.stored_value_not_a_byte";
                else if (in.operands[0] < loaded.size() &&
                         loaded[in.operands[0]])
                    why = "bulk.would_be_a_copy_needs_no_overlap";
                close_run(why);
                /* Y se dice AUNQUE no hubiera grupo abierto.  `close_run` no
                 * puede hacerlo: sale antes si no habia nada que cerrar, y eso
                 * dejaba mudo justo el caso que mas informa -- una copia entera
                 * campo a campo no abre ningun grupo de relleno, asi que no
                 * quedaba ni rastro de que se hubiera mirado.
                 *
                 * Una vez por bloque y motivo: repetirlo diecinueve veces, una
                 * por campo, ahoga el recuento sin decir nada nuevo. */
                if (std::find_if(out.declines.begin(), out.declines.end(),
                                 [&](const BulkMemoryDecline &d) {
                                     return d.header ==
                                                static_cast<ir::IrBlockId>(bi) &&
                                            d.code == why;
                                 }) == out.declines.end()) {
                    BulkMemoryDecline d;
                    d.header = static_cast<ir::IrBlockId>(bi);
                    d.code = why;
                    out.declines.push_back(d);
                }
                continue;
            }
            const bool extends = open && a.base == cur.dst_base &&
                                 b == cur.fill &&
                                 a.off == cur.begin + cur.bytes;
            if (!extends) {
                close_run("bulk.run_too_short");
                cur.kind = BulkMemoryFact::Kind::Fill;
                cur.dst_base = a.base;
                cur.begin = a.off;
                cur.bytes = 0;
                cur.fill = b;
                open = true;
            }
            cur.bytes += w;
            cur.instrs.push_back(static_cast<uint32_t>(ii));
        }
        close_run("bulk.run_too_short");
    }
    return out;
}

} // namespace analysis
