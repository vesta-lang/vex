/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/borrow/borrow_ir_check.cpp
 * @brief Cruzar la promesa de exclusividad con lo que se ve en las llamadas.
 */

#include "vx/borrow/borrow_ir_check.h"

#include "analysis/asa/fact_base.h"
#include "analysis/effects/param_aliasing.h"
#include "ir/ssa_ir.h"

namespace vx {
namespace borrow {

namespace {

/// @brief Si ese parametro es un puntero que promete no ser alcanzado por otro.
bool promises_exclusive(const ir::IrFunction &fn, size_t i) {
    const ir::IrValueId v = fn.params[i];
    if (v >= fn.values.size()) return false;
    if (fn.values[v].type != ir::IrType::PTR) return false;
    /* Habla lo APUNTADO: la exclusividad es sobre la region, no sobre la
     * variable que la senala. */
    return i < fn.param_contracts.size() &&
           fn.param_contracts[i].pointee().has(
               ir::IrParamClaim::ExclusiveCall);
}

/// @brief Si esa promesa la escribio el PROGRAMADOR, no el compilador.
///
/// El mismo bit lo puede poner la direccion del parametro (`out`, `inout`) o
/// el tipo (`unique<T>`, `borrow_mut<T>`), y de donde salga decide que se le
/// puede aconsejar a quien lo lee.  El contrato lleva los dos ejes separados
/// justo para esto.
bool promise_is_declared(const ir::IrFunction &fn, size_t i) {
    return i < fn.param_contracts.size() &&
           fn.param_contracts[i].pointee().is_declared(
               ir::IrParamClaim::ExclusiveCall);
}

/// @brief Si ese parametro es un puntero (con o sin promesa).
bool is_pointer_param(const ir::IrFunction &fn, size_t i) {
    const ir::IrValueId v = fn.params[i];
    return v < fn.values.size() && fn.values[v].type == ir::IrType::PTR;
}

} // namespace

std::vector<ExclusiveViolation>
check_exclusive_across_calls(const ir::IrModule &mod,
                             analysis::asa::FactBase &base) {
    std::vector<ExclusiveViolation> out;
    for (const ir::IrFunction &fn : mod.functions) {
        /* Primero: hay alguna promesa que comprobar?  Es un recorrido de los
         * parametros y sale antes de mirar ningun par.  La mayoria de las
         * funciones no prometen nada y no pagan nada mas que esto. */
        bool any = false;
        for (size_t i = 0; i < fn.params.size() && !any; ++i)
            any = promises_exclusive(fn, i);
        if (!any) continue;

        /* La base solo resuelve las funciones que se le preguntan, asi que
         * pedirla aqui -- ya filtrado -- no arrastra el modulo entero. */
        /* ANTES de optimizar, que es el momento del que habla esta
         * comprobacion: el inline se lleva por delante las llamadas que la
         * demuestran, asi que preguntar por el codigo de despues seria
         * preguntar por uno donde el sitio ya no existe. */
        const analysis::effects::ParamAliasing &aliasing =
            base.param_aliasing(mod, analysis::asa::kStagePreOpt);

        /* Por PARES sin repetir, no por parametro contra todos.  Que 0 alcance
         * a 1 y que 1 alcance a 0 son el mismo problema dicho al reves, y
         * contarlo dos veces esconde los demas: quien lee dos errores cree que
         * tiene dos cosas que arreglar.
         *
         * Basta con que UNO de los dos prometa: lo prometido es que la region
         * no la alcanza ningun otro parametro, asi que un puntero cualquiera
         * que la alcance ya lo incumple.
         *
         * Coste: los pares de UNA funcion, y solo de las que prometen algo.  No
         * crece con el programa sino con la aridad de esa funcion -- que se
         * dice porque en el camino nativo no esta acotada. */
        for (size_t a = 0; a < fn.params.size(); ++a) {
            if (!is_pointer_param(fn, a)) continue;
            for (size_t b = a + 1; b < fn.params.size(); ++b) {
                if (!is_pointer_param(fn, b)) continue;
                const bool pa = promises_exclusive(fn, a);
                const bool pb = promises_exclusive(fn, b);
                if (!pa && !pb) continue;
                const analysis::effects::ParamPairInfo pi =
                    aliasing.of(fn.name, a, b);
                /* SOLO lo demostrado acusa.  Un `Unknown` es "no se pudo
                 * decidir", y tratarlo como violacion seria justo el error que
                 * el segundo invariante del ASA prohibe: no poder demostrar que
                 * algo es seguro no es demostrar que es inseguro. */
                if (pi.verdict != analysis::effects::ParamPairVerdict::Overlaps)
                    continue;
                ExclusiveViolation v;
                v.function = fn.name;
                /* El que PROMETIO va primero: es de quien se incumplio la
                 * palabra, y es el que hay que mirar.  Si prometen los dos, da
                 * igual cual, porque el arreglo es el mismo. */
                v.promised = pa ? a : b;
                v.other = pa ? b : a;
                v.line = pi.line;
                v.declared = promise_is_declared(fn, v.promised);
                out.push_back(std::move(v));
            }
        }
    }
    return out;
}

} // namespace borrow
} // namespace vx
