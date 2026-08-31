/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analyze/asa_fingerprint.cpp
 * @brief Dominio del ASA: QUE HACE de verdad una funcion.
 *
 * Lo que sale de aqui es la VERDAD INFERIDA -- si lanza, si entra en panico, si
 * es pura, cuanto reserva, cuanta pila gasta --, y NO tiene nada que ver con lo
 * que el programador haya declarado.  Esa separacion es el motivo de que este
 * dominio exista:
 *
 *   - el ANALISIS descubre lo que el codigo hace;
 *   - el CONTRATO es lo que alguien prometio;
 *   - compararlos es cosa de un CONSUMIDOR (el linter), no del productor.
 *
 * Si el productor mirara los contratos, el mismo hecho diria una cosa u otra
 * segun lo que el usuario hubiera escrito, y entonces dejaria de ser un hecho.
 *
 * Vive en @c analyze/ y no en @c analysis/asa/ por la misma razon que el
 * dominio del asm: necesita la maquinaria de huellas
 * (@c analyze/fingerprint.h), que no esta en el nucleo.  Se da de alta con
 * @c register_fingerprint_producer desde quien la tenga disponible; para eso
 * existe el registro de productores.
 *
 * LO QUE NO SE SABE TAMBIEN SE DICE.  Cuando el cierre del grafo de llamadas
 * cruza algo que no se ve -- una llamada dinamica, un `extern` sin efectos
 * declarados --, los totales son conservadores y no se puede afirmar nada: eso
 * es una FRONTERA OPACA, se dice como tal, y es justo el hecho que permite al
 * linter avisar de un contrato que nadie esta comprobando.
 */

#include "analyze/fingerprint.h"

#include "analysis/asa/producers.h"
#include "ir/ssa_ir.h"

#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace analyze {

namespace {

using analysis::asa::Certainty;
using analysis::asa::Fact;
using analysis::asa::Production;
using analysis::asa::Source;
using analysis::asa::Subject;
using analysis::asa::UnknownReason;

const char *const kProducerFingerprint = "asa.fingerprint";

/// El sujeto es la FUNCION entera: la huella es una propiedad suya, no de un
/// valor ni de un bloque.
Subject function_subject(Production &p, const ir::IrFunction &fn) {
    Subject s;
    s.kind = Subject::Kind::Function;
    s.function = p.store.intern(fn.name);
    return s;
}

/// Arma un hecho con lo comun ya puesto.  Los cinco de este dominio comparten
/// procedencia, regla y apoyo, y repetirlo cinco veces es la forma de que uno
/// se quede distinto sin que nadie lo note.
Fact base_fact(Production &p, const ir::IrFunction &fn, const char *code) {
    Fact f;
    f.what.domain = kProducerFingerprint;
    f.what.code = code;
    f.about = function_subject(p, fn);
    f.seal.certainty = Certainty::Proven;
    f.seal.origin.source = Source::Static;
    f.seal.origin.producer = kProducerFingerprint;
    f.seal.origin.function = f.about.function;
    f.seal.support.add(analysis::asa::kProducerStructure);
    /* La regla dice de DONDE sale: no es una propiedad local, es el cierre
     * transitivo del grafo de llamadas.  Sin eso, "no lanza" se leeria como
     * "no tiene un throw escrito", que es otra cosa. */
    f.proof.rule = "fingerprint.callgraph-closure";
    auto it = p.structure_of.find(fn.name);
    if (it != p.structure_of.end()) f.proof.from.push_back(it->second);
    return f;
}

void produce_fingerprint(Production &p) {
    /* Las huellas se calculan para el modulo ENTERO de una vez: los totales son
     * interprocedurales -- lo que una funcion puede hacer incluye lo que hagan
     * las que llama --, asi que no hay una version "por funcion" que valga. */
    std::vector<FunctionFingerprint> fps = compute_module_fingerprints(p.mod);
    /* Sin los contratos a proposito: aqui se afirma lo MEDIDO.  Pasarlos haria
     * que una funcion con marco opaco contribuyera con su `@stack` DECLARADO, y
     * entonces el hecho dejaria de ser independiente de lo que el usuario
     * escribio -- que es justo lo que este dominio no puede permitirse. */
    /* CON el modulo: asi un callee que no esta en el programa pero cuya
     * importacion declara lo que hace deja de volver opaco el cierre.  Sin
     * esto, declarar no cambiaba nada de lo que este dominio afirma. */
    compose_fingerprints(fps, nullptr, &p.mod);

    /* Por nombre: `compose_fingerprints` conserva el orden de
     * `mod.functions`, pero apoyarse en eso ataria este dominio a un detalle
     * que nadie promete. */
    std::unordered_map<std::string, const FunctionFingerprint *> by_name;
    by_name.reserve(fps.size());
    for (const FunctionFingerprint &fp : fps)
        by_name.emplace(fp.function, &fp);

    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        auto it = by_name.find(fn.name);
        if (it == by_name.end()) {
            /* No deberia pasar -- las huellas salen del mismo modulo --, pero
             * callarselo dejaria una funcion sin ninguna linea y nadie sabria
             * si es que no tiene efectos o que no se miro. */
            p.say_unknown(function_subject(p, fn), UnknownReason::NotAsked,
                          "fingerprint.not_computed", kProducerFingerprint,
                          "no se calculo la huella de esta funcion");
            continue;
        }
        const FunctionFingerprint &fp = *it->second;

        /* LA FRONTERA.  Si el cierre cruza algo que no se ve, los totales son
         * cotas conservadoras y no demuestran nada: no se puede afirmar que no
         * lanza, solo que no se ha visto lanzar.  Decirlo como frontera opaca
         * -- y no callarse -- es lo que permite despues avisar de un contrato
         * que nadie esta comprobando. */
        if (!fp.effects_known) {
            /* Y se dice QUIEN, no solo que pasa.  "No se pueden demostrar tus
             * efectos" sin el culpable es un callejon sin salida: el usuario no
             * sabe a que funcion mirar, y el compilador SI lo sabe -- lo acaba
             * de decidir al componer el cierre --.
             *
             * El culpable va como DATO -- el nombre pelado -- y no como frase.
             * Un hecho que lleva prosa obliga a quien lo consuma a parsearla
             * para decidir, y ademas se queda en un idioma; con el nombre
             * suelto, el consumidor filtra por el (el linter se calla si la
             * frontera es de la stdlib, que no la arregla el usuario) y el
             * texto lo pone el catalogo. */
            p.say_unknown(function_subject(p, fn),
                          UnknownReason::OpaqueBoundary,
                          "fingerprint.effects_not_visible",
                          kProducerFingerprint,
                          p.store.intern(fp.opaque_callee));
            continue;
        }

        /* Y con el cierre entero a la vista, lo que se afirma esta demostrado.
         * Solo se afirma lo POSITIVO -- "no lanza" --: que algo lance no es un
         * hecho util aqui, es lo normal, y llenaria el almacen de ruido. */
        if (!fp.throws_total) {
            Fact f = base_fact(p, fn, "fingerprint.does_not_throw");
            f.what.detail = "no lanza en todo su cierre de llamadas";
            p.assert_fact(std::move(f));
        }
        if (!fp.panics_total) {
            Fact f = base_fact(p, fn, "fingerprint.does_not_panic");
            f.what.detail = "no entra en panico en todo su cierre de llamadas";
            p.assert_fact(std::move(f));
        }
        if (fp.pure) {
            Fact f = base_fact(p, fn, "fingerprint.pure");
            f.what.detail = "sin efectos de dato observables en su cierre";
            p.assert_fact(std::move(f));
        }
        {
            /* Las reservas SI se afirman siempre, con su numero: cero es tan
             * informativo como cualquier otro -- es lo que hace verificable un
             * `@alloc(0)` --, y un numero no es ruido. */
            Fact f = base_fact(p, fn, "fingerprint.allocations");
            f.what.a = static_cast<int64_t>(fp.alloc_sites_total);
            std::ostringstream o;
            o << fp.alloc_sites_total << " sitios de reserva alcanzables";
            f.what.detail = p.store.intern(o.str());
            p.assert_fact(std::move(f));
        }
        if (fp.stack_bytes_total != STACK_UNBOUNDED) {
            Fact f = base_fact(p, fn, "fingerprint.stack");
            f.what.a = static_cast<int64_t>(fp.stack_bytes_total);
            std::ostringstream o;
            o << fp.stack_bytes_total << " bytes de pila en el peor caso";
            f.what.detail = p.store.intern(o.str());
            p.assert_fact(std::move(f));
        } else {
            /* Recursion o un ciclo: la pila no esta acotada, y eso no es un
             * fallo del analisis sino del programa.  Es `RuntimeDependent`
             * porque depende de cuantas veces se entre de verdad. */
            p.say_unknown(
                function_subject(p, fn), UnknownReason::RuntimeDependent,
                "fingerprint.stack_unbounded", kProducerFingerprint,
                fp.recursive ? "es recursiva: la pila depende de la ejecucion"
                             : "la pila no se puede acotar");
        }
    }
}

} // namespace

void register_fingerprint_producer() {
    analysis::asa::register_producer(kProducerFingerprint,
                                     &produce_fingerprint);
}

} // namespace analyze
