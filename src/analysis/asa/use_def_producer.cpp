/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/use_def_producer.cpp
 * @brief El dominio `asa.use_def`: cuantas veces se usa cada valor, donde esta
 *        su ultimo uso, y cuales no se usan NUNCA.
 *
 * Los hechos los calcula @ref analysis::compute_use_def -- una funcion pura,
 * las mismas posiciones lineales que la vivacidad -- y hasta ahora los
 * consumia solo el asignador de registros, que es quien pregunta "cual es el
 * proximo uso" para elegir victima.
 *
 * QUE GANA CON ESTAR AQUI, mas alla del asignador:
 *
 *   - **"Esto no se usa" es un AVISO, no solo una heuristica.**  Un valor sin
 *     ningun uso es exactamente lo que el linter quiere senyalar, y el editor
 *     atenuar.  Hoy hay que recalcularlo para saberlo.
 *   - **"Se usa una sola vez" habilita cosas.**  Es la condicion de fondo del
 *     inline de un temporal, del hundimiento de un calculo hasta su uso y de
 *     no reservarle registro; producido una vez, sirve a los tres.
 *   - **Donde MUERE un valor** es lo que hace falta para colocar una
 *     liberacion, y es la misma pregunta que responde el ultimo uso.
 *
 * Lo que NO se publica: la lista entera de posiciones de uso.  Es grande, se
 * recalcula en microsegundos y quien de verdad la necesita -- el asignador --
 * la pide directa.  Al almacen va lo que se CONSULTA, no todo lo que se sabe;
 * llenarlo de datos que nadie pregunta lo unico que hace es encarecer
 * guardarlo y cargarlo.
 */

#include "analysis/asa/producers.h"
#include "analysis/facts/use_def_facts.h"
#include "ir/ssa_ir.h"

#include <string>

namespace analysis {
namespace asa {

namespace {

const char *const kProducerUseDef = "asa.use_def";

/// El sujeto es el VALOR: se afirma de el, no de la funcion.
Subject value_subject_(Production &p, const ir::IrFunction &fn,
                       ir::IrValueId v) {
    Subject s;
    s.kind = Subject::Kind::Value;
    s.function = p.store.intern(fn.name);
    s.id = v;
    return s;
}

/// El nombre legible de un valor, para el detalle del hecho.
std::string value_name_(const ir::IrFunction &fn, ir::IrValueId v) {
    if (v < fn.values.size() && !fn.values[v].name.empty())
        return fn.values[v].name;
    return "%" + std::to_string(v);
}

void produce_use_def(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const UseDefFacts u = compute_use_def(fn);
        const Seal s = p.base.seal(kProducerUseDef, fn);
        if (u.num_values() == 0) {
            Subject sf;
            sf.kind = Subject::Kind::Function;
            sf.function = p.store.intern(fn.name);
            p.say_unknown(sf, UnknownReason::NothingToSay, "use_def.no_values",
                          kProducerUseDef, "");
            continue;
        }
        for (ir::IrValueId v = 0; v < u.num_values(); ++v) {
            const uint32_t n = u.off[v + 1] - u.off[v];
            Fact f;
            f.what.domain = kProducerUseDef;
            /* Un valor sin usos puede ser codigo muerto, pero tambien un
             * parametro que la funcion no mira: por eso lo que se afirma es
             * "no se usa" y no "sobra".  Lo segundo es una CONCLUSION, y
             * sacarla es de quien consuma el hecho, no de quien lo produce. */
            if (n == 0)
                f.what.code = "use_def.unused";
            else
                f.what.code =
                    (n == 1) ? "use_def.single_use" : "use_def.multi_use";
            /* Cuantos usos y donde esta el ULTIMO -- que es donde el valor
             * muere -- van en los numeros, no en una frase: el hecho es dato y
             * el texto lo pone quien lo pinta, desde el catalogo.  El detalle
             * lleva solo COMO SE LLAMA el valor, que no se traduce. */
            f.what.a = static_cast<int64_t>(n);
            f.what.b =
                n ? static_cast<int64_t>(u.use_pos[u.off[v] + n - 1]) : -1;
            f.what.detail = p.store.intern(value_name_(fn, v));
            f.about = value_subject_(p, fn, v);
            /* DEMOSTRADO: contar usos es recorrer la funcion, no estimar.  Aqui
             * no cabe un "no se": o el valor esta en la lista o no esta. */
            f.seal = s;
            f.seal.certainty = Certainty::Proven;
            f.proof.rule = "use_def.count-uses";
            p.assert_fact(std::move(f));
        }
    }
}

} // namespace

void register_use_def_producer() {
    register_producer(kProducerUseDef, &produce_use_def);
}

} // namespace asa
} // namespace analysis
