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
    if (b.st.header == ir::IR_NO_BLOCK || b.st.header >= fn.blocks.size())
        return false;

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
    const bool is_fill = b.kind == BulkMemoryFact::Kind::Fill;
    if (is_fill)
        f.what.code = cuenta_conocida ? "bulk.fill" : "bulk.fill_runtime";
    else
        f.what.code = cuenta_conocida ? "bulk.copy" : "bulk.copy_runtime";
    /* Los numeros por SEPARADO, no ya multiplicados: quien lea el hecho no
     * podria recuperar ninguno de los dos de su producto. */
    f.what.a = cuenta_conocida ? elementos : b.width;
    f.what.b = b.width;

    f.about.kind = Subject::Kind::Block;
    f.about.function = store.intern(fn.name);
    f.about.id = b.st.header;

    /* Y DONDE, como LINEA ya resuelta y no como ancla al intermedio.
     *
     * Es la excepcion, y tiene motivo: este hecho es de MITAD de la
     * optimizacion y quien lo consume -- el linter -- tiene delante el codigo
     * de DESPUES, ya renumerado.  Un ancla solo se resuelve contra el
     * intermedio de su propio momento, asi que aqui no habria contra que
     * resolverla: mirar ese bloque en el codigo de despues no encuentra un
     * bloque parecido, encuentra OTRO, y el aviso salia senalando lineas donde
     * no hay ningun bucle.
     *
     * O sea que @c Anchor::Kind::Line no es solo "no hay entidad a la que
     * anclar": es tambien "este hecho esta hecho para SOBREVIVIR a su
     * momento".  Se paga que la posicion caduque al mover texto, y se paga a
     * sabiendas, porque la alternativa es no poder senalar nada. */
    for (const ir::IrInstr &in : fn.blocks[b.st.header].instrs)
        if (in.source_line > 0) {
            f.seal.origin.site = Anchor{Anchor::Kind::Line, in.source_line};
            break;
        }

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

bool straight_line_bulk_fact(FactStore &store, const ir::IrFunction &fn,
                             const StraightLineBulkFact &b, const char *stage,
                             Source source, Fact &out) {
    if (b.block >= fn.blocks.size() || b.instrs.empty()) return false;

    Fact f;
    f.what.domain = kProducerBulkMemory;
    /* Codigo propio, y no el del bucle: la CLASE de conocimiento es la misma
     * -- de ahi que compartan @c Kind -- pero el sujeto no, y el mensaje lo
     * nota.  Reusar `bulk.fill` salia diciendo "este bucle escribe..." sobre
     * una tirada de asignaciones donde no hay ningun bucle, y ademas sus dos
     * numeros son elementos y ancho, que aqui no significan nada.
     *
     * Sin variante `_runtime`: en recta las direcciones son constantes, asi
     * que la longitud SIEMPRE se sabe.  No es un detalle -- es lo que permite
     * elegir el ancho de lane al emitir, en vez de llamar a una rutina
     * dimensionada al ejecutar. */
    f.what.code = b.kind == BulkMemoryFact::Kind::Fill ? "bulk.fill_run"
                                                       : "bulk.copy_run";
    /* Los bytes del tramo y el byte que se repite.  Aqui `a` son BYTES y no
     * elementos porque en recta no hay elemento: hay un tramo. */
    f.what.a = b.bytes;
    f.what.b = b.fill;

    f.about.kind = Subject::Kind::Block;
    f.about.function = store.intern(fn.name);
    f.about.id = b.block;

    /* DONDE, por lo mismo que en el de bucles: LINEA ya resuelta, porque este
     * hecho tambien esta hecho para sobrevivir a su momento y quien lo lea
     * tendra otro codigo delante.  Se coge la de la PRIMERA escritura del
     * grupo, que es donde el programador escribio el primero de los campos. */
    const ir::IrBlock &bb = fn.blocks[b.block];
    if (b.instrs.front() < bb.instrs.size())
        f.seal.origin.site =
            Anchor{Anchor::Kind::Line,
                   bb.instrs[b.instrs.front()].source_line};

    f.seal.certainty = Certainty::Proven;
    f.seal.origin.source = source;
    f.seal.origin.producer = kProducerBulkMemory;
    f.seal.origin.function = f.about.function;
    f.seal.support.add(kProducerMemory);

    f.scope.stage = stage;
    f.proof.rule = "adjacent-stores-tile-the-range";
    out = std::move(f);
    return true;
}

} // namespace asa
} // namespace analysis
