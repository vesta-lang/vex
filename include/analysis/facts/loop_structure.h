/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_structure.h
 * @brief Hecho reutilizable: forma estructural de un bucle CONTADO simple.
 *
 * Verifica que un bucle (identificado por LoopFacts) es reducible, con un unico
 * latch, una unica salida, un unico preheader y un header "limpio" (solo PHIs +
 * la condicion + el BR_COND), y que esta en forma loop-closed SSA (ningun valor
 * del cuerpo se usa fuera del bucle salvo por las PHIs del header).  Es
 * INFRAESTRUCTURA DE ANALISIS: la consumen el desenrollado, el peeling, el
 * versioning, etc.  No transforma nada.
 */
#ifndef ANALYSIS_FACTS_LOOP_STRUCTURE_H
#define ANALYSIS_FACTS_LOOP_STRUCTURE_H

#include "analysis/facts/loop_facts.h"
#include "ir/ssa_ir.h"

#include <cstdint>
#include <unordered_set>
#include <vector>

namespace analysis {

/// PHI del header: valor + su arg de entrada (preheader) y de retorno (latch).
struct HeaderPhi {
    ir::IrValueId dst = ir::IR_NO_VALUE;
    ir::IrValueId init = ir::IR_NO_VALUE; ///< arg desde el preheader.
    ir::IrValueId back =
        ir::IR_NO_VALUE; ///< arg desde el latch (loop-carried).
};

/// Forma estructural de un bucle contado.  @c valid=false si no es elegible.
struct LoopStructure {
    /**
     * @brief Elegible para TRANSFORMARLO: salida unica, sin valores que
     *        escapen, cuerpo clonable.
     *
     * Es lo que necesita quien va a desenrollar o a reducir el bucle a una
     * operacion de bloque, y no ha cambiado de significado.
     */
    bool valid = false;
    /**
     * @brief Elegible para CONTARLO, que es una propiedad mas DEBIL.
     *
     * La cabecera es una guarda contada y hay un solo latch, asi que el numero
     * de vueltas esta acotado por la cuenta.  Lo que sobra respecto a
     * @c valid -- salidas de mas y valores del cuerpo usados fuera -- no
     * afecta a esa cota: **una salida anticipada solo puede hacer que de MENOS
     * vueltas.**
     *
     * Sin esta distincion, un `for (i = 0; i < 32; i++)` con un `break` o un
     * `return` dentro no se contaba en absoluto, y el coste declaraba O(n) una
     * funcion que da como mucho 32 vueltas -- que es de las formas mas
     * corrientes que hay.
     *
     * OJO al consumirlo: lo que sale de un bucle asi es una COTA, nunca el
     * numero exacto.  Quien vaya a quitar una comprobacion necesita @c valid.
     */
    bool countable = false;
    /**
     * @brief CUAL de las condiciones rechazo el bucle.  Vacio si @c valid.
     *
     * Son siete y todas salian con el mismo "su forma no es un bucle contado
     * simple", asi que quien preguntaba no podia distinguir un bucle con dos
     * salidas de uno cuya cabecera hace de mas -- que se arreglan de formas
     * distintas, y una es un hueco del analisis y la otra del programa --.
     *
     * Codigo estable del vocabulario del dominio: lo lee el catalogo
     * multi-idioma, no se ensena tal cual.
     */
    const char *why = "";
    ir::IrBlockId header = ir::IR_NO_BLOCK;
    ir::IrBlockId preheader = ir::IR_NO_BLOCK; ///< unico pred del header fuera.
    ir::IrBlockId latch = ir::IR_NO_BLOCK;     ///< unico bloque con back-edge.
    ir::IrBlockId body_entry = ir::IR_NO_BLOCK; ///< sucesor del header DENTRO.
    ir::IrBlockId exit = ir::IR_NO_BLOCK;       ///< sucesor del header FUERA.
    std::vector<ir::IrBlockId> body;            ///< bloques del bucle salvo H.
    /**
     * @brief TODO lo que esta dentro, bucles anidados INCLUIDOS.
     *
     * Es la membresia de verdad -- un bloque del bucle de dentro esta dentro
     * del de fuera --, y no coincide con @c body: ahi solo van los del NIVEL
     * de este bucle.  Antes eran lo mismo, y por eso ningun bucle externo
     * podia reconocerse jamas: el bloque que entra al de dentro saltaba a algo
     * que no estaba en el conjunto, asi que el analisis lo declaraba "sale del
     * cuerpo" y se rendia.  Un `for` dentro de otro `for` no tenia forma
     * reconocible, y de ahi que el coste no supiera descontar el de fuera
     * cuando sus vueltas eran fijas.
     */
    std::unordered_set<ir::IrBlockId> loop_blocks;
    /**
     * @brief Bucles anidados DENTRO de este.  0 = cuerpo plano.
     *
     * Quien vaya a CLONAR el cuerpo tiene que mirarlo: @c body trae solo el
     * nivel de este bucle, asi que con anidados dentro no es el cuerpo entero
     * y clonarlo dejaria el bucle de dentro compartido entre las copias.  Los
     * que solo LEEN -- contar vueltas, acotar la induccion, el coste -- no
     * necesitan mirarlo.
     */
    uint32_t inner_loops = 0;
    /**
     * @brief La guarda vive en el LATCH, no en la cabecera.
     *
     * Es la forma de un `do { } while (...)`: el cuerpo va primero y la
     * comprobacion al final, asi que se entra siempre al menos una vez.  Sin
     * reconocerla, el reconocedor se rendia con "la cabecera no es
     * condicional" y el coste declaraba O(n) un bucle de vueltas fijas.
     *
     * Importa a quien CUENTE -- da una vuelta mas que veces se cumple la
     * guarda -- y descarta a quien TRANSFORME, que da por hecho lo contrario.
     */
    bool rotated = false;
    /**
     * @brief El bucle es UN SOLO BLOQUE que salta a si mismo.
     *
     * Las PHIs, el cuerpo y la guarda viven todos en la cabecera.  Es en lo
     * que el optimizador convierte un `do { } while (...)` pequeno, asi que
     * rechazarlo dejaba sin contar DESPUES de optimizar lo que si se contaba
     * antes.  Se cuenta; lo que no se puede es clonar, porque el latch es la
     * propia cabecera.
     */
    bool self_loop = false;
    std::vector<HeaderPhi> phis; ///< PHIs del header, en orden.

    bool contains(ir::IrBlockId b) const { return loop_blocks.count(b) != 0; }
    /// Cuerpo PLANO: sin bucles dentro.  Lo que necesita quien clona.
    bool flat() const { return inner_loops == 0; }
    /// Se sale SOLO por la guarda.  Lo que necesita quien afirma un numero
    /// EXACTO de vueltas -- con mas salidas, lo que hay es una cota.
    bool single_exit() const { return valid; }
};

/**
 * @brief Analiza la forma estructural del bucle @p loop_id (innermost).
 * @param fn      funcion SSA.
 * @param lf      hechos de bucles ya calculados.
 * @param loop_id id del bucle (innermost) en @p lf.
 * @return LoopStructure con @c valid=true si es un bucle contado simple.
 */
LoopStructure detect_loop_structure(const ir::IrFunction &fn,
                                    const analysis::LoopFacts &lf,
                                    uint32_t loop_id);

} // namespace analysis

#endif // ANALYSIS_FACTS_LOOP_STRUCTURE_H
