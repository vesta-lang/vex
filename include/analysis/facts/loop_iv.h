/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_iv.h
 * @brief Hecho reutilizable: variable de induccion (IV) CONTADA de un bucle.
 *
 * Es INFRAESTRUCTURA DE ANALISIS, no de transformacion.  La consumen el
 * desenrollado, la vectorizacion, el peeling, el strength-reduction, etc.  El
 * transformador no descubre el IV; solo pide este hecho.
 */
#ifndef ANALYSIS_FACTS_LOOP_IV_H
#define ANALYSIS_FACTS_LOOP_IV_H

#include "ir/ssa_ir.h"

#include <cstdint>
#include <vector>

namespace analysis {

/// Hacia donde avanza la variable.  @c stride es siempre POSITIVO: es el
/// TAMANO del paso, y esto dice el sentido.  Guardar un paso negativo obligaria
/// a cada consumidor a acordarse del signo, y olvidarse no da un error: da una
/// direccion calculada al reves.
enum class IvDir : uint8_t {
    Up = 0, ///< `i += S`, guarda `<` o `<=`.
    Down    ///< `i -= S`, guarda `>` o `>=`.
};

/**
 * @brief Descriptor de la variable de induccion CONTADA de un bucle.
 *
 * El header itera mientras @c cmp_op(iv + cmp_offset, bound) y en cada vuelta
 * @c iv avanza @c stride en el sentido de @c dir.  El @c cmp_offset != 0
 * modela el lookahead del vectorizador (guarda @c cmp(iv + W, N)).
 *
 * OJO al pedirlo: @c detect_loop_iv devuelve SOLO los crecientes, y no por
 * comodidad -- quien lo consume desenrolla, vectoriza o reconoce un recorrido
 * de memoria, y todos dan por hecho que se sube --.  Los dos sentidos se piden
 * con @c detect_counted_iv, que es lo que usa el camino de CONTAR VUELTAS.
 */
struct LoopIV {
    ir::IrValueId phi = ir::IR_NO_VALUE; ///< PHI del header (el IV).
    int phi_index = -1;                  ///< indice de esa PHI entre las del
                                         ///< header (para no re-localizarla).
    ir::IrValueId init =
        ir::IR_NO_VALUE;             ///< valor inicial (desde el preheader).
    int64_t stride = 0;              ///< TAMANO del paso (> 0); el sentido en
                                     ///< @c dir.
    IvDir dir = IvDir::Up;           ///< hacia donde avanza.
    ir::IrOp cmp_op = ir::IrOp::NOP; ///< la guarda: LT/LE/ULT/ULE si sube,
                                     ///< GT/GE/UGT/UGE si baja.
    int64_t cmp_offset = 0;          ///< c de cmp(iv + c, bound) (0 = iv).
    ir::IrValueId bound = ir::IR_NO_VALUE; ///< cota N (invariante del bucle).
};

/**
 * @brief Descubre el IV canonico creciente de un bucle reducible.
 *
 * Lee las PHIs del @p header (init = arg desde @p preheader, back = arg desde
 * @p latch) y la guarda (el cmp que define la condicion del BR_COND del
 * header). Identifica la PHI cuyo valor de retorno es `phi + S` con S constante
 * > 0 (el IV), y la cota N del cmp (que puede comparar `iv` o `iv + c`).
 * Rellena @p out (incluido @c out.phi_index, el indice del IV entre las PHIs
 * del header en orden de aparicion).
 *
 * NO verifica que @c out.bound sea invariante del bucle: eso es una
 * comprobacion ESTRUCTURAL (necesita el conjunto de bloques del bucle) que hace
 * el llamante.
 *
 * @return true si hay un IV canonico creciente con cota reconocible.
 */
bool detect_loop_iv(const ir::IrFunction &fn, const std::vector<int> &def_block,
                    ir::IrBlockId header, ir::IrBlockId preheader,
                    ir::IrBlockId latch, LoopIV &out);

/**
 * @brief Igual, pero admitiendo TAMBIEN los que bajan.
 *
 * `for (i = 32; i > 0; i--)` esta tan contado como su version creciente, y
 * hasta que esto existio no lo reconocia nadie: sin variable de induccion no
 * se pueden contar sus vueltas, asi que un bucle de 32 vueltas FIJAS se
 * declaraba O(n).  Es el mismo fallo que ya mordio con los bucles externos y
 * con los que multiplican -- una forma que el analisis no cubre acaba siendo
 * una respuesta equivocada, no una duda.
 *
 * Va SEPARADO de @c detect_loop_iv, que sigue devolviendo solo los crecientes,
 * porque quien consume aquel calcula direcciones de memoria a partir del paso:
 * darle uno que baja haria que tocara lo que el bucle no toca.  Quien solo
 * quiere CONTAR pide este.
 */
bool detect_counted_iv(const ir::IrFunction &fn,
                       const std::vector<int> &def_block, ir::IrBlockId header,
                       ir::IrBlockId preheader, ir::IrBlockId latch,
                       LoopIV &out);

/**
 * @brief Variable de induccion GEOMETRICA: la que MULTIPLICA en vez de sumar.
 *
 * `for (i = 1; i < n; i = i * 2)` no da `n` vueltas: da del orden de `log n`.
 * Es una CLASE distinta, no una constante distinta, y sin reconocerla el coste
 * contestaba O(n) donde la respuesta es O(log n) -- y O(n^2) donde es
 * O(n log n), que es la diferencia entre una busqueda y un barrido.
 *
 * Va aparte de @c LoopIV a proposito.  Quien consume el IV lo hace para
 * DESENROLLAR, VECTORIZAR o reconocer un recorrido de memoria, y todos esos
 * dan por hecho el paso constante que dice @c LoopIV::stride; meter aqui un
 * paso multiplicativo haria que trataran como lineal algo que no lo es --
 * calcularian direcciones que el bucle no toca.  Se pregunta cuando la
 * aritmetica NO encaja, no en su lugar.
 */
struct GeoIV {
    ir::IrValueId phi = ir::IR_NO_VALUE;   ///< PHI del header.
    ir::IrValueId init = ir::IR_NO_VALUE;  ///< valor inicial (del preheader).
    int64_t ratio = 0;                     ///< por cuanto se multiplica (>= 2).
    ir::IrOp cmp_op = ir::IrOp::NOP;       ///< guarda del header.
    ir::IrValueId bound = ir::IR_NO_VALUE; ///< la cota con la que compara.
};

/**
 * @brief Descubre una induccion geometrica creciente del @p header.
 *
 * Reconoce que el valor que vuelve por el latch es `phi * K` o `phi << k`, con
 * el factor CONSTANTE y >= 2 -- con 1 no avanza y el bucle no termina, y con 0
 * o negativo esto no lo modela.  El desplazamiento cuenta porque es en lo que
 * el propio compilador convierte una multiplicacion por potencia de dos: no
 * reconocerlo haria que el mismo bucle fuera logaritmico antes de optimizar y
 * lineal despues.
 *
 * @return true si la hay.  No se comprueba que la guarda compare ESE valor:
 *         eso lo mira quien lo use, igual que con @c detect_loop_iv.
 */
bool detect_geometric_iv(const ir::IrFunction &fn,
                         const std::vector<int> &def_block,
                         ir::IrBlockId header, ir::IrBlockId preheader,
                         ir::IrBlockId latch, GeoIV &out);

} // namespace analysis

#endif // ANALYSIS_FACTS_LOOP_IV_H
