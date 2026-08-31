/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/ir_facts.h
 * @brief HECHOS objetivos de una funcion IR: lo que se deriva con UN recorrido,
 *        SIN reticulo, punto-fijo ni interpretacion.  Es la base compartida que
 *        consumen todos los analisis (no re-recorren el IR).  Criterio: si
 *        necesita reticulo/punto-fijo/eleccion-de-precision es ANALISIS, no
 *        hecho -- por eso aqui NO hay efectos, points-to ni alias (eso lo
 * produce EffectAnalysis/AliasAnalysis sobre estos hechos).
 *
 * Incluye: def-use (value -> instr que lo define; value -> indice de
 * parametro), call-SITES estaticos + flag de llamada dinamica (el callgraph
 * RESUELTO es un analisis aparte), y estructura minima (bloques, back-edges =
 * bucles, recursion directa).  Se invalida al MUTAR el IR (default: solo
 * sobrevive a preserve-all).
 */
#ifndef VESTA_ANALYSIS_IR_FACTS_H
#define VESTA_ANALYSIS_IR_FACTS_H

#include <cstdint>
#include <string>
#include <vector>

namespace ir {
struct IrFunction;
struct IrInstr;
using IrValueId = uint32_t;
} // namespace ir

namespace analysis {

/// Marcador del analisis de hechos IR (identidad para el AnalysisManager).
struct IRFactsAnalysis {
    static char ID;
};

/// Hechos de una funcion.  Resultado value-type (sin gancho survives -> por
/// defecto solo sobrevive a preserve-all, correcto: cualquier mutacion del IR
/// invalida los def-use/CFG).
struct IrFacts {
    // --- def-use ---
    std::vector<const ir::IrInstr *>
        def_of; ///< value id -> instr que lo define.
    /**
     * @brief value id -> BLOQUE donde se define, -1 si no lo define nadie.
     *
     * La otra mitad de la misma pregunta: `def_of` dice QUE instruccion, esto
     * dice DONDE.  Se saca del mismo recorrido, asi que no cuesta nada de
     * mas, y hace falta para lo que se pregunta constantemente -- si un valor
     * es invariante en un bucle es, literalmente, si su bloque de definicion
     * cae fuera --.
     *
     * Estaba, pero repartido: el desenrollador, el resolvedor de punteros y
     * el reconocedor de memoria por lotes se lo construian CADA UNO por su
     * cuenta con el mismo doble bucle.  Tres recorridos por funcion para el
     * mismo hecho, que es justo lo que el ASA existe para no hacer.
     */
    std::vector<int32_t> def_block;
    std::vector<int32_t>
        param_of; ///< value id -> indice de parametro, -1 si no.

    // --- call-sites (sintacticos; el callgraph resuelto es otro analisis) ---
    std::vector<std::string>
        static_callees;            ///< nombres de CALL/TAILCALL estaticos.
    bool has_dynamic_call = false; ///< CALLVIRT/CALLN/CALLIND/...

    // --- estructura ---
    uint32_t block_count = 0;
    uint32_t loop_count = 0; ///< back-edges (aproximacion de bucles).
    bool recursive = false;  ///< se llama a si misma directamente.

    /// Hay def para @p v?  (helper de conveniencia.)
    const ir::IrInstr *def(ir::IrValueId v) const {
        return v < def_of.size() ? def_of[v] : nullptr;
    }
    int32_t param_index(ir::IrValueId v) const {
        return v < param_of.size() ? param_of[v] : -1;
    }
};

/// Construye los hechos de @p fn (un recorrido).
IrFacts build_ir_facts(const ir::IrFunction &fn);

} // namespace analysis

#endif // VESTA_ANALYSIS_IR_FACTS_H
