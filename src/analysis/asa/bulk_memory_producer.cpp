/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/bulk_memory_producer.cpp
 * @brief El dominio `asa.bulk_memory`: que bucles son en realidad UNA
 *        operacion de bloque, y de los que no, por que no.
 *
 * El hecho lo calcula @ref analysis::analyze_bulk_memory; esto lo mete en el
 * almacen, que es lo que lo convierte en conocimiento COMPARTIDO en vez de en
 * la respuesta privada del pase que baja el bucle a `memcpy`.
 *
 * QUE GANA CON ESTAR AQUI:
 *
 *   - **Se ve.**  `--asa` ensena "este bucle es una copia de N elementos de 4
 *     bytes".  Que el compilador reconociera el bucle era invisible: si el
 *     pase no disparaba, no habia forma de saber si es que no lo vio o es que
 *     decidio no tocarlo.
 *   - **Se puede preguntar.**  El linter puede decirle al usuario "esto es un
 *     `std.memory.copy` escrito largo", y el editor ensenarlo mientras se
 *     escribe, sin que ninguno vuelva a analizar nada.
 *   - **Y sobre todo, se sabe POR QUE NO.**  Las renuncias eran quince
 *     `continue` mudos: "no hay ningun memcpy en este programa" y "habia uno y
 *     me falto un byte para verlo" salian exactamente igual.  Con el motivo,
 *     lo segundo es un consejo accionable -- "seria una copia si la base no
 *     cambiara dentro del bucle" -- y ademas se puede MEDIR cuanto se pierde
 *     por cada causa, en vez de intuirlo.
 *
 * El pase que transforma sigue pidiendo @ref analysis::detect_bulk_memory, que
 * devuelve solo lo reconocido: quien va a cambiar el codigo no tiene nada que
 * hacer con los motivos.
 */

#include "analysis/asa/observed.h" // el hecho, armado en UN sitio
#include "analysis/asa/producers.h"
#include "analysis/facts/bulk_memory.h"
#include "ir/ssa_ir.h"

namespace analysis {
namespace asa {

namespace {

/// El sujeto es el BLOQUE cabecera, igual que en el dominio de bucles: de un
/// bucle se habla por su cabecera, y asi los dos hechos se cruzan solos.
Subject header_subject(Production &p, const ir::IrFunction &fn,
                       ir::IrBlockId header) {
    Subject s;
    s.kind = Subject::Kind::Block;
    s.function = p.store.intern(fn.name);
    s.id = header;
    return s;
}

void produce_bulk_memory(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const BulkMemoryReport r = analyze_bulk_memory(fn);
        if (r.facts.empty() && r.declines.empty()) {
            /* Ni un bucle que mirar.  Se dice, porque "no hay bucles" y "los
             * habia y ninguno era una operacion de bloque" son dos cosas, y
             * sin distinguirlas el dominio saldria con "0 hechos" en los dos
             * casos. */
            Subject s;
            s.kind = Subject::Kind::Function;
            s.function = p.store.intern(fn.name);
            p.say_unknown(s, UnknownReason::NothingToSay, "bulk.no_loops",
                          kProducerBulkMemory, "");
            continue;
        }
        for (const BulkMemoryFact &b : r.facts) {
            /* El hecho lo arma UN solo sitio, el mismo que usa el pase que
             * reduce el bucle.  Con dos constructores bastaria que uno se
             * quedara atras para que el mismo bucle se describiera distinto
             * segun quien lo mirara. */
            Fact f;
            if (bulk_memory_fact(p.store, fn, b, p.stage, Source::Static, f))
                p.assert_fact(std::move(f));
        }
        for (const BulkMemoryDecline &d : r.declines) {
            /* Todas son la MISMA clase de hueco: el bucle hace algo que este
             * reconocedor no modela.  Lo que las separa es el codigo, que es
             * lo que dice donde mirar -- y de cara al usuario, lo que hay que
             * cambiar para que si lo sea. */
            p.say_unknown(header_subject(p, fn, d.header),
                          UnknownReason::ShapeNotRecognized, d.code,
                          kProducerBulkMemory, "");
        }
    }
}

} // namespace

void register_bulk_memory_producer() {
    register_producer(kProducerBulkMemory, &produce_bulk_memory);
}

} // namespace asa
} // namespace analysis
