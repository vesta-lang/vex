/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/definite_store_producer.cpp
 * @brief El dominio `asa.definite_store`: que punteros se escriben SIEMPRE
 *        antes de retornar, y de los que no, por que no se sabe.
 *
 * El hecho lo calcula @ref analysis::compute_definite_stores; esto lo mete en
 * el almacen del ASA, que es lo que lo convierte en conocimiento COMPARTIDO en
 * vez de en la respuesta privada de un consumidor.
 *
 * QUE GANA CON ESTAR AQUI, que es la razon de registrarlo y no dejarlo como
 * una funcion suelta:
 *
 *   - **Se puede preguntar.**  El editor puede decir "por aqui sales sin
 *     rellenarlo" mientras se escribe, y el linter contarlo, sin que ninguno
 *     de los dos vuelva a calcularlo.
 *   - **Se cuenta lo que NO se supo, y por que.**  Un puntero que se escapa
 *     deja un motivo con su codigo, asi que se puede medir cuanto conocimiento
 *     se pierde por fronteras opacas en vez de intuirlo.
 *   - **Sirve para optimizar, no solo para avisar.**  "Este puntero esta
 *     escrito con seguridad al llegar aqui" es justo lo que necesita quien
 *     quiera eliminar una inicializacion redundante o adelantar una lectura; y
 *     "no se escribe nunca en este camino" lo que necesita quien quiera
 *     eliminar un almacen muerto.  Producido una vez, sirve a los tres.
 *   - **Persiste.**  El almacen se guarda entre compilaciones, asi que lo que
 *     no cambio no se vuelve a calcular.
 *
 * Lo PEREZOSO es la otra mitad y vive en @ref analysis::DefiniteStoreAnalysis:
 * quien pregunta durante la optimizacion lo pide al gestor de analisis, que lo
 * calcula la primera vez y lo reutiliza mientras la funcion no cambie.
 */

#include "analysis/asa/producers.h"
#include "analysis/facts/definite_store.h"
#include "ir/ssa_ir.h"

#include <sstream>
#include <string>

namespace analysis {
namespace asa {

namespace {

const char *const kProducerDefiniteStore = "asa.definite_store";

/// El sujeto es el VALOR: la garantia es del puntero, no de la funcion.
Subject pointer_subject(Production &p, const ir::IrFunction &fn,
                        ir::IrValueId v) {
    Subject s;
    s.kind = Subject::Kind::Value;
    s.function = p.store.intern(fn.name);
    s.id = v;
    return s;
}

/// El nombre legible del puntero, para el detalle del hecho.
std::string pointer_name(const ir::IrFunction &fn, ir::IrValueId v) {
    if (v < fn.values.size() && !fn.values[v].name.empty())
        return fn.values[v].name;
    return "%" + std::to_string(v);
}

void produce_definite_store(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const DefiniteStoreMap m = compute_definite_stores(fn);
        if (m.per_pointer.empty()) {
            /* Ni un parametro que apunte: se sabe, y no es ignorancia.  Sin
             * decirlo, el dominio saldria con "0 hechos" y no habria forma de
             * distinguir esto de que no llegara a correr. */
            Subject s;
            s.kind = Subject::Kind::Function;
            s.function = p.store.intern(fn.name);
            p.say_unknown(s, UnknownReason::NothingToSay,
                          "definite_store.no_pointer_params",
                          kProducerDefiniteStore,
                          "ningun parametro suyo apunta a nada");
            continue;
        }
        for (const auto &e : m.per_pointer) {
            const DefiniteStoreFacts &d = e.second;
            const Subject about = pointer_subject(p, fn, e.first);
            if (d.verdict == DefiniteStoreFacts::Verdict::Unknown) {
                p.say_unknown(about, d.reason, d.reason_code,
                              kProducerDefiniteStore,
                              "no se pudo decidir si se escribe siempre");
                continue;
            }
            Fact f;
            f.what.domain = kProducerDefiniteStore;
            const bool siempre =
                d.verdict == DefiniteStoreFacts::Verdict::Always;
            f.what.code =
                siempre ? "definite_store.always" : "definite_store.missing";
            f.what.a = static_cast<int64_t>(d.witness_line);
            std::ostringstream o;
            o << pointer_name(fn, e.first);
            if (siempre)
                o << " se escribe en todos los caminos que retornan";
            else
                o << " no se escribe en el camino que retorna en la linea "
                  << d.witness_line;
            f.what.detail = p.store.intern(o.str());
            f.about = about;
            /* DEMOSTRADO en los dos casos, y conviene entender por que tambien
             * el negativo: no es "no encontre la escritura", es que se
             * recorrieron todos los caminos y hay uno que llega al retorno sin
             * ella.  Lo que no se pudo demostrar salio arriba como un "no se"
             * con su motivo, que es otra cosa. */
            f.seal.certainty = Certainty::Proven;
            f.seal.origin.source = Source::Static;
            f.seal.origin.producer = kProducerDefiniteStore;
            f.seal.origin.function = about.function;
            f.proof.rule = "definite_store.all-paths-to-return";
            p.assert_fact(std::move(f));
        }
    }
}

} // namespace

void register_definite_store_producer() {
    register_producer(kProducerDefiniteStore, &produce_definite_store);
}

} // namespace asa
} // namespace analysis
