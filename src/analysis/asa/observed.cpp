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

} // namespace asa
} // namespace analysis
