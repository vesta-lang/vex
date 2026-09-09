/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/backend_producer.cpp
 * @brief El dominio `asa.backend`: que operaciones NO puede compilar un modo de
 *        ejecucion, y por que.
 *
 * El analisis no es nuevo: @ref aot::aot_analyze_module clasifica cada
 * operacion del intermedio contra un objetivo nativo y devuelve, por cada una
 * que no cabe, la funcion, la LINEA de fuente, la operacion y el motivo en
 * texto.  Lo que era nuevo es a quien llega: lo consumia un solo sitio, el
 * inspector del editor.
 *
 * QUE GANA CON ESTAR AQUI:
 *
 *   - **Deja de ser privado de un consumidor.**  El editor te dice que tu
 *     codigo no compilaria a nativo y el linter no; la misma pregunta tenia dos
 *     respuestas segun quien la hiciera, que es justo lo que el ASA existe para
 *     impedir.  Ahora hay UN hecho y dos lectores.
 *   - **Se ve.**  `--asa` ensena "esta funcion usa `malloc` de libc, que en
 *     `bare` no esta".  Antes eso solo existia dentro de una respuesta JSON del
 *     servidor de lenguaje.
 *   - **Viaja con su AMBITO.**  El hecho se sella con el backend al que se
 *     refiere, asi que un consumidor que pregunte desde el interprete no lo
 *     encuentra -- y no debe: ahi la operacion vale.  El eje `backend` del
 *     ambito llevaba tiempo en el vocabulario con un solo hecho usandolo.
 *
 * LO QUE ESTE DOMINIO NO HACE: decidir si eso es un problema.  Un programa que
 * solo se ejecuta interpretado usa `malloc` con toda la razon.  El hecho dice
 * "en nativo `bare` esto no cabe, por esto"; que hacer con eso es del que
 * pregunta.
 */

#include "analysis/asa/producers.h"
#include "aot/aot_analyze.h"
#include "ir/ssa_ir.h"

namespace analysis {
namespace asa {

namespace {

void produce_backend(Production &p) {
    /* El objetivo mas RESTRICTIVO, que es el que hace la pregunta util.
     *
     * `bare` es freestanding-capable: solo admite lo que baja 1:1 a la maquina.
     * Preguntar por `full` -- que lleva el runtime entero -- casi nunca dice
     * nada, y lo que diga ya lo dice el enlazador.  Es el mismo objetivo con el
     * que lo pregunta el editor, a proposito: dos consumidores del mismo hecho
     * no pueden estar mirando objetivos distintos sin saberlo. */
    aot::AotTarget objetivo;
    objetivo.tier = aot::Tier::BARE;

    const aot::AotCompatReport informe =
        aot::aot_analyze_module(p.mod, objetivo);

    /* Nada que decir tambien SE DICE.  "este modulo compila entero a nativo" y
     * "nadie ha mirado si compila" son dos cosas, y sin distinguirlas el
     * dominio sale con cero hechos en los dos casos. */
    if (informe.issues.empty()) {
        Subject s;
        s.kind = Subject::Kind::Function;
        s.function = p.store.intern(kModuleUnit);
        /* "Todo cabe en nativo" vale mirado desde donde sea: es una propiedad
         * del modulo, no del sitio desde el que se pregunta. */
        p.say_unknown(s, UnknownReason::NothingToSay, "backend.todo_cabe",
                      kProducerBackend, "", Scope::everywhere());
        return;
    }

    for (const aot::AotIncompat &inc : informe.issues) {
        Fact f;
        f.what.domain = kProducerBackend;
        /* El codigo dice QUE clase de dependencia es, no el detalle: el detalle
         * va en el texto del motivo, que es lo que el analisis ya redacta y no
         * conviene volver a redactar aqui con otras palabras. */
        f.what.code = "backend.unsupported_op";
        f.what.a = static_cast<int64_t>(inc.op);
        f.what.detail = p.store.intern(inc.reason);

        f.about.kind = Subject::Kind::Function;
        f.about.function = p.store.intern(inc.fn_name);

        /* Una LINEA sin entidad del intermedio a la que colgarla: el informe de
         * compatibilidad trae la suya y aqui ya no se tiene delante la
         * instruccion que la produjo.  Es el ultimo recurso del ancla -- la
         * unica clase que puede quedarse rancia al mover texto --, y se acepta
         * porque no hay a que anclar; si algun dia el informe traiga tambien la
         * posicion de la operacion, esto pasa a @c Anchor::Kind::Instruction. */
        f.seal.origin.site = Anchor{Anchor::Kind::Line, inc.source_line};
        /* DEMOSTRADO: la clasificacion es un `switch` sobre la operacion, no
         * una estimacion.  O la operacion baja a maquina o necesita algo que en
         * este objetivo no hay. */
        f.seal.certainty = Certainty::Proven;
        f.seal.origin.source = Source::Static;
        f.seal.origin.producer = kProducerBackend;
        f.seal.origin.function = f.about.function;

        /* El AMBITO es la mitad del hecho: esto NO vale en cualquier sitio,
         * vale hablando del nativo.  Un consumidor que pregunte desde el
         * interprete no debe encontrarlo. */
        f.scope.backend = kBackendAot;
        f.scope.stage = p.stage;
        f.proof.rule = "aot-op-classification";
        p.assert_fact(std::move(f));
    }
}

} // namespace

void register_backend_producer() {
    /* Que operaciones NO puede compilar un backend: se clasifica cada op del
     * intermedio, asi que depende del codigo.
     *
     * OJO -- tambien depende del OBJETIVO, y eso no es una entrada del modulo
     * sino de la configuracion: entra por la clave del fichero de hechos, que
     * ya lleva `BuildConfig`.  Declararlo aqui seria mezclar los dos ejes. */
    register_producer(kProducerBackend, &produce_backend,
                      DomainInput::FunctionCode);
}

} // namespace asa
} // namespace analysis
