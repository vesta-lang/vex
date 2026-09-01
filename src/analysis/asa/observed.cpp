/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/observed.cpp
 * @brief Implementacion de @c analysis/asa/observed.h.
 */

#include "analysis/asa/observed.h"

namespace analysis {
namespace asa {

bool loop_trip_fact(FactStore &store, const ir::IrFunction &fn,
                    ir::IrBlockId header, const LoopTripInfo &trip,
                    const char *stage, Source source, Fact &out) {
    /* Sin cota no hay nada que afirmar, y se dice con el valor de retorno.
     * El no-saber tiene su propio camino (`say_unknown`), con su motivo: un
     * hecho vacio colado en el almacen seria ruido que ademas se cuenta. */
    if (!trip.bounded()) return false;

    Fact f;
    f.what.domain = kProducerLoops;
    /* "Da N vueltas" y "da como mucho N" son hechos DISTINTOS, no el mismo con
     * menos confianza: con el primero se puede quitar una comprobacion, con el
     * segundo solo elegir. */
    const bool is_exact = trip.known();
    f.what.code = is_exact ? "loop.trip_count" : "loop.trip_at_most";
    f.what.a = static_cast<int64_t>(is_exact ? trip.trip : trip.trip_max);

    f.about.kind = Subject::Kind::Block;
    f.about.function = store.intern(fn.name);
    f.about.id = header;

    /* La certeza la trae el ANALISIS, no la pone quien publica: llegar por los
     * `CONST` que el programa escribe esta demostrado; llegar por un punto
     * fijo de rangos, que puede pararse por presupuesto, se infiere. */
    f.seal.certainty = trip.certainty;
    f.seal.origin.source = source;
    f.seal.origin.producer = kProducerLoops;
    f.seal.origin.function = f.about.function;
    f.seal.support.add(kProducerStructure);

    f.scope.stage = stage;

    f.proof.rule =
        is_exact ? "induction-variable" : "induction-variable+ranges";
    out = std::move(f);
    return true;
}

bool bulk_memory_fact(FactStore &store, const ir::IrFunction &fn,
                      const BulkMemoryFact &b, const char *stage, Source source,
                      Fact &out) {
    if (b.st.header == ir::IR_NO_BLOCK) return false;

    /* Cuantos elementos, SI se sabe.  La cota de un bucle suele ser un valor
     * del programa; publicar su identificador como si fuera la cuenta es dar
     * un numero equivocado, que es peor que no darlo. */
    bool cuenta_conocida = false;
    int64_t elementos = 0;
    if (b.n_elems != ir::IR_NO_VALUE && b.n_elems < fn.values.size() &&
        fn.values[b.n_elems].is_const) {
        elementos = static_cast<int64_t>(fn.values[b.n_elems].const_val);
        cuenta_conocida = true;
    }

    Fact f;
    f.what.domain = kProducerBulkMemory;
    /* Relleno y copia son hechos DISTINTOS, no el mismo con una bandera: quien
     * los consuma emite instrucciones distintas, y el segundo ademas necesita
     * saber que las dos regiones no se solapan.  Y cada uno en dos formas,
     * segun se sepa la longitud o se dimensione al ejecutar: la clase de
     * conocimiento no es la misma y quien decida especializar lo necesita. */
    const bool relleno = b.clase == BulkMemoryFact::Clase::Relleno;
    if (relleno)
        f.what.code = cuenta_conocida ? "bulk.fill" : "bulk.fill_runtime";
    else
        f.what.code = cuenta_conocida ? "bulk.copy" : "bulk.copy_runtime";
    /* Los numeros por SEPARADO, no ya multiplicados: quien lea el hecho no
     * podria recuperar ninguno de los dos de su producto. */
    f.what.a = cuenta_conocida ? elementos : b.ancho;
    f.what.b = b.ancho;

    f.about.kind = Subject::Kind::Block;
    f.about.function = store.intern(fn.name);
    f.about.id = b.st.header;

    /* DEMOSTRADO: no es que lo parezca, es que se recorrio el bucle entero y
     * todo lo que hace es recorrer y mover.  Cualquier duda salio por el otro
     * camino, como una renuncia con su motivo. */
    f.seal.certainty = Certainty::Proven;
    f.seal.origin.source = source;
    f.seal.origin.producer = kProducerBulkMemory;
    f.seal.origin.function = f.about.function;
    f.seal.support.add(kProducerLoops);
    f.seal.support.add(kProducerMemory);

    f.scope.stage = stage;
    f.proof.rule = "loop-shape+induction+memory-effects";
    out = std::move(f);
    return true;
}

} // namespace asa
} // namespace analysis
