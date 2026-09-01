/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_iv_bounds.h
 * @brief Hecho reutilizable: hasta donde llega la variable de un bucle
 *        CONTADO, deducido de la FORMA del bucle y no de los rangos.
 *
 * Un bucle contado dice cuanto vale su variable con solo mirarlo: empieza en
 * un sitio, avanza un paso fijo, y la guarda dice donde para.  Eso acota el
 * valor y no hace falta ningun punto fijo para verlo.
 *
 * Es lo que el analisis de rangos NO puede sacar por su cuenta, y no por
 * flojo: la guarda de un bucle desenrollado compara `i + 7`, y despejar la `i`
 * de ahi es INCORRECTO con aritmetica que envuelve -- `i` grande hace que
 * `i + 7` de la vuelta y pase la guarda --.  El despeje solo vale sabiendo que
 * la cuenta no envuelve, y eso lo sabe el bucle, no el reticulo.
 *
 * El precio de no tenerlo se pagaba entero al final de la cadena: la variable
 * del bucle principal valia TODO SU TIPO, con lo que el bucle de resto que
 * fabrica el desenrollado entraba sin cota, no se le podian contar las
 * vueltas, y una funcion de 64 vueltas fijas se declaraba O(n) DESPUES de
 * optimizar -- por culpa del bucle que el optimizador acababa de crear.
 *
 * Va SEPARADO de los rangos a proposito, y en este orden: esto no los
 * consulta -- solo lee `CONST` del programa --, asi que puede alimentarlos sin
 * que se muerdan la cola.  Al reves si: los rangos lo reciben como suelo, y de
 * ahi lo hereda todo lo que venga detras (la guarda, el bucle de resto, la
 * alineacion, el coste).
 */
#ifndef ANALYSIS_FACTS_LOOP_IV_BOUNDS_H
#define ANALYSIS_FACTS_LOOP_IV_BOUNDS_H

#include "analysis/facts/ir_facts.h"
#include "analysis/facts/loop_facts.h"
#include "analysis/facts/value_range.h"
#include "ir/ssa_ir.h"

#include <vector>

namespace analysis {

/// Una variable acotada: quien es y entre que valores va.
struct IvBound {
    ir::IrValueId value = ir::IR_NO_VALUE;
    ValueRange range;
};

/**
 * @brief Las variables de induccion acotadas de una funcion.
 *
 * DISPERSO y ordenado por identificador, no un vector por valor: en una
 * funcion de mil valores llevan cota los dos o tres de sus bucles, asi que un
 * vector denso serian mil intervalos de 24 bytes guardados -- y cacheados
 * mientras viva la base -- para leer tres.  Con tan pocas entradas la busqueda
 * es lineal sobre memoria contigua, que ademas es mas rapida que una tabla
 * asociativa a este tamano.
 */
struct LoopIvBounds {
    std::vector<IvBound> bounds; ///< ordenado por @c value.
    uint32_t not_counted = 0;    ///< bucles que no son contados simples.
    uint32_t no_shape = 0;       ///< contados, pero sin la forma que se despeja.

    bool empty() const { return bounds.empty(); }
};

/**
 * @brief Acota las variables de induccion de los bucles contados de @p fn.
 *
 * Reconoce la forma `for (i = I; i + C < N; i += S)` con @c I, @c N y @c S
 * constantes ESCRITAS (`CONST`), que es la unica de la que se puede despejar
 * sin fiarse de nadie.  Sale:
 *
 *   `i` en `[I, max(I, N - C - 1 + S)]`   con `<`
 *   `i` en `[I, max(I, N - C + S)]`       con `<=`
 *
 * El extremo alto es el valor con el que se SALE, que es una vuelta mas alla
 * de la ultima que entro: la guarda se comprueba con el valor ya avanzado.
 *
 * Cualquier duda -- que la cuenta se salga del tipo, que el paso sea negativo,
 * que el limite no sea constante -- deja ese valor sin cota.  No acotar de
 * menos es perder precision; acotar de mas es dar OTRO NUMERO.
 *
 * @param fn     funcion SSA.
 * @param facts  def_of / def_block (para resolver las constantes).
 * @param loops  bucles de la funcion, ya detectados.
 */
LoopIvBounds compute_loop_iv_bounds(const ir::IrFunction &fn,
                                    const IrFacts &facts,
                                    const LoopFacts &loops);

} // namespace analysis

#endif // ANALYSIS_FACTS_LOOP_IV_BOUNDS_H
