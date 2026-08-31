/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_trip_count.h
 * @brief Hecho reutilizable: numero de iteraciones (trip count) de un bucle
 *        contado, a partir del descriptor de su variable de induccion.
 *
 * Es INFRAESTRUCTURA DE ANALISIS, no de transformacion: lo consumen el
 * desenrollado, la vectorizacion, el peeling y el unswitch por igual.  El
 * transformador no calcula el trip; solo pide este hecho.
 */
#ifndef ANALYSIS_FACTS_LOOP_TRIP_COUNT_H
#define ANALYSIS_FACTS_LOOP_TRIP_COUNT_H

#include "analysis/asa/fact.h"      // UnknownReason/Certainty: que se sabe y como
#include "analysis/facts/loop_iv.h" // LoopIV (descriptor del IV)
#include "analysis/facts/value_range.h" // RangeFacts: la SEGUNDA fuente
#include "ir/ssa_ir.h"

#include <cstdint>
#include <vector>

namespace analysis {

/// Numero de iteraciones del header si es CONSTANTE conocido.  Un solo campo
/// para el VALOR: el estado no puede contradecirse (nunca "known pero
/// trip=-1").
struct LoopTripInfo {
    int64_t trip = -1; ///< iteraciones del header (>= 0); < 0 = desconocido.
    bool known() const { return trip >= 0; }

    /**
     * @brief Cota SUPERIOR de vueltas cuando no se puede dar el numero exacto.
     *
     * "Como mucho da N vueltas" no es lo mismo que "da N vueltas", pero
     * tampoco es no saber nada: con una cota se puede decidir si compensa
     * desenrollar, acotar un coste o descartar un desbordamiento.  Antes esos
     * casos caian en el mismo `-1` que "no tengo ni idea", asi que el
     * consumidor no podia distinguir un bucle acotado de uno sin acotar.
     *
     * < 0 = tampoco hay cota.  Si @c known(), sobra: el exacto ya la implica.
     */
    int64_t trip_max = -1;
    bool bounded() const { return trip >= 0 || trip_max >= 0; }

    /**
     * @brief Con que CERTEZA se afirma, que depende de DE DONDE salio.
     *
     * Hay dos fuentes para el mismo hecho y no valen lo mismo:
     *
     *   - los `CONST` que definen el inicio y el limite: es lo que el programa
     *     DICE, asi que el numero esta demostrado;
     *   - el analisis de RANGOS: es un punto fijo sobre un reticulo, y cuando
     *     no converge se para por presupuesto.  Un rango de un solo valor es
     *     tan cierto como el literal, pero llegar a el por aproximaciones
     *     sucesivas admite que el analisis se haya parado antes de tiempo.
     *
     * La certeza viaja DENTRO del hecho porque no la decide quien pregunta:
     * un consumidor que quiera quitar una comprobacion necesita @c Proven, y
     * uno que solo vaya a elegir una heuristica se conforma con @c Inferred.
     */
    asa::Certainty certainty = asa::Certainty::Proven;

    /**
     * @brief POR QUE no se supo.  Solo tiene sentido con @c !known().
     *
     * Antes las CUATRO renuncias de este analisis daban el mismo `-1`, y quien
     * preguntaba no podia distinguirlas -- aunque se arreglan de formas
     * distintas y de eso depende que puede hacer:
     *
     *   - el limite es un valor de EJECUCION -> se puede desenrollar con una
     *     guarda, o pedir una precondicion;
     *   - el bucle decrece, o la guarda no es `<`/`<=` -> el analisis no cubre
     *     esa FORMA, y eso se puede ampliar (o decirle al usuario que escriba);
     *
     * y la diferencia entre las dos es justo la que decide si el consumidor
     * especula o se rinde.  Con un solo bit, todos se rendian.
     */
    asa::UnknownReason reason = asa::UnknownReason::NotAsked;

    /// Codigo estable del caso EXACTO, del vocabulario de este dominio.  La
    /// clase de arriba dice de que tipo es -- que es lo unico que puede leer
    /// quien no conoce este analisis --; esto dice cual de ellos fue.
    const char *code = "";
};

/**
 * @brief Calcula el trip count constante de un bucle a partir de su IV.
 *
 * Resuelve @c iv.init y @c iv.bound a constantes (via las CONST que los definen
 * en @p def_block).  Si ambas lo son y el stride es positivo:
 *   - `<`  (CMP_LT/ULT):  trip = ceil((bound - offset - init) / stride)
 *   - `<=` (CMP_LE/ULE):  trip = floor((bound - offset - init) / stride) + 1
 * Cualquier duda deja @c known=false Y DICE POR QUE (@c LoopTripInfo::reason y
 * @c code): un consumidor puede especular con guarda ante un limite de
 * ejecucion y no ante una forma que el analisis no cubre.
 *
 * Si se le dan los RANGOS, son una SEGUNDA FUENTE para lo mismo: cuando el
 * inicio o el limite no son un `CONST` literal, su rango puede seguir fijando
 * el valor -- un intervalo de un solo punto es un valor -- o, si no lo fija,
 * acotar cuantas vueltas se dan COMO MUCHO.  Es conocimiento que el compilador
 * ya tiene y que este analisis tiraba: `for (i = 0; i < n; ...)` con `n`
 * acotado arriba es un bucle acotado, aunque `n` no sea una constante escrita.
 *
 * @param fn        funcion SSA.
 * @param def_block def_block[v] = bloque que define v (-1 si ninguno).
 * @param iv        descriptor de la variable de induccion.
 * @param ranges    rangos de la funcion, o nullptr si no se tienen.  Solo se
 *                  consultan cuando el camino de las constantes no llega: si
 *                  el programa lo dice, no hace falta deducirlo.
 */
LoopTripInfo compute_trip_count(const ir::IrFunction &fn,
                                const std::vector<int> &def_block,
                                const LoopIV &iv,
                                const RangeFacts *ranges = nullptr);

} // namespace analysis

#endif // ANALYSIS_FACTS_LOOP_TRIP_COUNT_H
