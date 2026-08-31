/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/value_shape_producer.cpp
 * @brief Dominio del ASA: la FORMA de un valor con componentes.
 *
 * El analisis existia entero -- `aggregate_facts.cpp`, con su modelo de tres
 * niveles y sus hechos ya SELLADOS con procedencia y certeza -- y **no estaba
 * dado de alta como productor**.  O sea que calculaba, concluia, y su
 * conocimiento no llegaba al almacen: ni al volcado, ni al linter, ni al MCP.
 * Es exactamente el fallo que el informe de "nadie consulto" existe para
 * cazar, en su version peor -- nadie podia consultarlo porque no estaba.
 *
 * Aqui NO se decide nada nuevo.  Se traduce lo que el dominio ya dijo:
 *
 *   - la FORMA de cada valor, con la certeza que el propio analisis calculo
 *     (que depende de si pudo observar el universo entero);
 *   - por donde se ESCAPA, que es conocimiento del PROGRAMA -- una direccion
 *     que se va se va -- y por eso se afirma, no se lamenta;
 *   - y lo que NO se pudo seguir, que es conocimiento del ANALISIS y va como
 *     "no lo se" con su clase.
 *
 * Esa separacion entre escape y limitacion es del dominio, no mia: la hace
 * `aggregate_facts.h` en su cabecera, y meterlas en el mismo saco impediria
 * saber cual de las dos cosas hay que arreglar.
 */

#include "analysis/asa/aggregate_facts.h"
#include "analysis/asa/producers.h"

#include "ir/ssa_ir.h"

#include <sstream>
#include <string>

namespace analysis {
namespace asa {

namespace {

const char *const kProducerValueShape = "asa.value_shape";

/// El sujeto es el VALOR: la forma es suya, no de la funcion que lo contiene.
Subject value_subject(Production &p, const ir::IrFunction &fn,
                      ir::IrValueId v) {
    Subject s;
    s.kind = Subject::Kind::Value;
    s.function = p.store.intern(fn.name);
    s.id = v;
    return s;
}

/// Codigo estable de la forma.  El nombre para volcados lo da el dominio
/// (`nombre_forma`); esto es el vocabulario del hecho, que viaja al disco.
const char *shape_code(FormaDeValor f) {
    switch (f) {
    case FormaDeValor::Agregado: return "value_shape.aggregate";
    case FormaDeValor::Compuesto: return "value_shape.composite";
    default: return "value_shape.unknown";
    }
}

void produce_value_shape(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        /* Los dos hechos comunes se PIDEN A LA BASE, no se construyen: la
         * estructura y el points-to de esta funcion ya estan calculados para
         * los dominios de estructura y memoria, y volver a calcularlos seria
         * pagar dos veces por la misma respuesta. */
        const AggregateFactsMap m = observar_agregados(
            p.mod, fn, p.base.structure(fn), p.base.memory(fn), &p.base);
        if (m.agregados.empty()) {
            /* Ni un valor con componentes: se sabe, y no es ignorancia.  Sin
             * esto el dominio saldria con "0 hechos de 0 miradas" y no habria
             * forma de distinguirlo de que no llegara a correr. */
            Subject s;
            s.kind = Subject::Kind::Function;
            s.function = p.store.intern(fn.name);
            p.say_unknown(s, UnknownReason::NothingToSay, "value_shape.none",
                          kProducerValueShape,
                          "no tiene valores con componentes");
            continue;
        }

        for (const AggregateFacts &a : m.agregados) {
            const FormaDeValor f = a.forma();
            const Subject about = value_subject(p, fn, a.ancla);

            if (f == FormaDeValor::SinEvidencia ||
                f == FormaDeValor::Desconocida) {
                /* El dominio distingue las dos: sin evidencia es que no se
                 * observo NADA de el -- no se pregunto --, y desconocida es que
                 * lo observado no permite decidir, que depende de por donde
                 * pase la ejecucion. */
                p.say_unknown(about,
                              f == FormaDeValor::SinEvidencia
                                  ? UnknownReason::NotAsked
                                  : UnknownReason::RuntimeDependent,
                              f == FormaDeValor::SinEvidencia
                                  ? "value_shape.not_observed"
                                  : "value_shape.undecided",
                              kProducerValueShape,
                              f == FormaDeValor::SinEvidencia
                                  ? "no se observo nada de este valor"
                                  : "lo observado no decide su forma");
            } else {
                Fact shape;
                shape.what.domain = kProducerValueShape;
                shape.what.code = shape_code(f);
                shape.what.a = a.bytes;
                shape.what.b = static_cast<int64_t>(a.offsets_tocados());
                std::ostringstream o;
                o << nombre_forma(f) << ", " << a.offsets_tocados()
                  << " desplazamientos tocados";
                if (a.bytes >= 0) o << ", " << a.bytes << " bytes";
                shape.what.detail = p.store.intern(o.str());
                shape.about = about;
                /* El sello lo puso el ANALISIS, no este productor: depende de
                 * si pudo observar el universo entero, y eso solo lo sabe el.
                 * Copiarlo -- en vez de decidirlo aqui -- es lo que impide que
                 * el mismo hecho tenga dos certezas segun quien lo mire. */
                shape.seal = a.seal;
                shape.seal.origin.producer = kProducerValueShape;
                shape.seal.origin.function = about.function;
                shape.proof.rule = "value_shape.observed-uses";
                p.assert_fact(std::move(shape));
            }

            /* POR DONDE SE ESCAPA.  Es del PROGRAMA: una direccion que se va se
             * va, y seguira yendose por mucho que el analisis mejore.  Por eso
             * se AFIRMA con certeza demostrada en vez de contarse como algo que
             * no se supo -- confundirlo haria creer que ampliando el analisis
             * desapareceria. */
            for (const Frontera &fr : a.fronteras) {
                Fact e;
                e.what.domain = kProducerValueShape;
                e.what.code = "value_shape.escapes";
                e.what.a = static_cast<int64_t>(fr.sitio.linea);
                std::ostringstream o;
                o << "sale por " << nombre_frontera(fr.codigo) << " en "
                  << fr.sitio.funcion << ":" << fr.sitio.linea;
                e.what.detail = p.store.intern(o.str());
                e.about = about;
                e.seal.certainty = Certainty::Proven;
                e.seal.origin.source = Source::Static;
                e.seal.origin.producer = kProducerValueShape;
                e.seal.origin.function = about.function;
                e.proof.rule = "value_shape.observed-escape";
                p.assert_fact(std::move(e));
            }

            /* Y lo que NO se pudo seguir, que es del ANALISIS.  La clase ya
             * viaja dentro de la limitacion desde que el resolvedor de destinos
             * la dice; aqui solo se pasa. */
            for (const Limitacion &l : a.limitaciones) {
                std::ostringstream o;
                o << nombre_limitacion(l.codigo) << " en " << l.sitio.funcion
                  << ":" << l.sitio.linea;
                if (!l.destino.empty()) o << " -> " << l.destino;
                p.say_unknown(about, l.reason,
                              l.reason_code != nullptr &&
                                      l.reason_code[0] != '\0'
                                  ? l.reason_code
                                  : "value_shape.not_followed",
                              kProducerValueShape, p.store.intern(o.str()));
            }
        }
    }
}

} // namespace

void register_value_shape_producer() {
    register_producer(kProducerValueShape, &produce_value_shape);
}

} // namespace asa
} // namespace analysis
