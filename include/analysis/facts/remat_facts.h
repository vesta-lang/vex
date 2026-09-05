/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/remat_facts.h
 * @brief RematFacts (Tipo A, IR-driven): por cada valor SSA, si su definicion
 * es RECOMPUTABLE (rematerializable) y con que RECETA.  Un hecho del programa
 *        que el asignador consulta -- no lo posee: query<RematFacts>() sobre el
 *        FunctionSnapshot, como LoopFacts / Liveness.
 *
 * POR QUE ESTE FACT: el asignador clasico, cuando un valor no cabe en registro,
 * solo sabe spill+reload (trafico de memoria).  Pero si el IR sabe que la
 * definicion es `const` / `lea` / una op PURA, el valor se puede RECOMPUTAR en
 * el punto de uso en vez de recargarlo -- a menudo mas barato.  Ese
 * conocimiento vive en el IR y se pierde en el nivel maquina; hay que
 * CAPTURARLO donde existe.
 *
 * FORMA DE RECETA (por diseno, desde el inicio, aunque la implementacion sea
 * minima): la receta describe COMO reconstruir el valor -- la op + su literal +
 * sus operandos.  Hoy la implementacion es de PROFUNDIDAD 1 (recomputable si la
 * op es pura value-only; los operandos se asumen disponibles, lo verifica la
 * DECISION con liveness en el punto de uso).  La generalizacion a CADENAS (un
 * operando no vivo pero el mismo recomputable -> expandir su receta -> arbol)
 * es anadir PROFUNDIDAD, no cambiar el tipo.  Por eso el Fact nace con receta y
 * no con un bool.
 *
 * SEPARACION DE NIVELES (multi-nivel): RematFacts es IR-driven
 * (recomputabilidad + receta).  El COSTE de recomputar (vs reload) NO vive aqui
 * -- vive en MachineCostFacts (ASM/uarch).  La DECISION (remat vs spill)
 * FUSIONA los dos.  El Fact no decide; solo aporta lo que el IR sabe.
 *
 * i18n: produce DATOS.  ADITIVO, sin consumidores de produccion todavia.
 */

#ifndef VESTA_ANALYSIS_FACTS_REMAT_FACTS_H
#define VESTA_ANALYSIS_FACTS_REMAT_FACTS_H

#include "ir/ssa_ir.h"

#include <cstdint>
#include <vector>

namespace analysis {

/**
 * @brief ¿La op @p op es RECOMPUTABLE value-only? (pura, sin leer memoria
 * mutable, sin efectos, sin trap).  Criterio CONSERVADOR del peldano minimo:
 * incluye constantes/direcciones y aritmetica-logica-conversion enteras;
 * EXCLUYE memoria (LOAD/STORE/GETFIELD), llamadas, DIV/MOD (trap div-by-zero),
 * PHI, ALLOCA y todo lo que dependa del contexto de ejecucion.  El float y las
 *        cadenas quedan para extensiones (la receta ya lo soporta).
 */
inline bool is_rematerializable_op(ir::IrOp op) noexcept {
    switch (op) {
    // Constantes y direcciones constantes: el caso mas seguro y comun
    // (recomputar = mov reg,imm / lea reg,[sim]).
    case ir::IrOp::CONST:
    case ir::IrOp::STR_LIT_ADDR:
    case ir::IrOp::LABEL_ADDR:
    case ir::IrOp::SECTION_REF:
    // Aritmetica entera pura (sin trap): NO DIV/MOD.
    case ir::IrOp::ADD:
    case ir::IrOp::SUB:
    case ir::IrOp::MUL:
    case ir::IrOp::NEG:
    case ir::IrOp::IABS:
    case ir::IrOp::IMIN:
    case ir::IrOp::IMAX:
    case ir::IrOp::IMINU:
    case ir::IrOp::IMAXU:
    // Logica y desplazamientos.
    case ir::IrOp::AND:
    case ir::IrOp::OR:
    case ir::IrOp::XOR:
    case ir::IrOp::SHL:
    case ir::IrOp::SHR:
    // Conversiones (value-only).
    case ir::IrOp::SEXT:
    case ir::IrOp::ZEXT:
    case ir::IrOp::TRUNC:
    case ir::IrOp::BITCAST: return true;
    default: return false;
    }
}

/**
 * @struct RematRecipe
 * @brief COMO reconstruir un valor: la op + su literal + sus operandos.  @c
 * valid = false si el valor NO es recomputable (su def no es value-only pura).
 *
 * Profundidad 1 hoy: @c operands son los SSA que la receta necesita disponibles
 * en el punto de uso; la DECISION comprueba su liveness alli.  Manana, un
 * operando no vivo pero el mismo recomputable expande SU receta -> la receta se
 * vuelve un arbol sin cambiar este tipo.
 */
struct RematRecipe {
    ir::IrOp op = ir::IrOp::NOP;         ///< op que recomputa el valor.
    uint64_t imm = 0;                    ///< literal (CONST/direcciones).
    /// SSA que la receta necesita.  MISMO tipo que los de una instruccion:
    /// asi copiarlos aqui no reserva cuando son pocos, que es siempre.
    ir::IrOperands operands;
    bool valid = false;                  ///< el valor es recomputable.
};

/**
 * @struct RematFacts
 * @brief Por valor SSA (indexado por @c IrValueId), su @c RematRecipe.  Hecho
 * del programa; el asignador lo CONSULTA (no lo posee).
 */
struct RematFacts {
    std::vector<RematRecipe>
        recipe; ///< recipe[value_id]; size == fn.values.size().

    /** @brief ¿El valor @p v es recomputable? */
    bool is_rematerializable(ir::IrValueId v) const noexcept {
        return v < recipe.size() && recipe[v].valid;
    }
    /** @brief Receta de @p v (vacia/invalida si no recomputable). */
    const RematRecipe &recipe_of(ir::IrValueId v) const noexcept {
        static const RematRecipe kNone;
        return v < recipe.size() ? recipe[v] : kNone;
    }
};

/**
 * @brief Produce @c RematFacts de una funcion: por cada instruccion con destino
 *        cuya op es @c is_rematerializable_op, guarda su receta.  Funcion PURA
 *        (mismo IR -> mismos hechos), IR-driven, sin coste maquina (eso es otro
 * Fact).
 */
inline RematFacts compute_remat_facts(const ir::IrFunction &fn) {
    RematFacts f;
    f.recipe.resize(fn.values.size());
    for (const auto &b : fn.blocks)
        for (const ir::IrInstr &in : b.instrs) {
            if (in.dst == ir::IR_NO_VALUE || in.dst >= f.recipe.size())
                continue;
            if (!is_rematerializable_op(in.op)) continue;
            RematRecipe &r = f.recipe[in.dst];
            r.op = in.op;
            r.imm = in.imm;
            r.operands = in.operands;
            r.valid = true;
        }
    return f;
}

} // namespace analysis

#endif // VESTA_ANALYSIS_FACTS_REMAT_FACTS_H
