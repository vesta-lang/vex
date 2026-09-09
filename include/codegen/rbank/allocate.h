/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/rbank/allocate.h
 * @brief ENTRADA de alto nivel del allocator rbank: intervalos del backend ->
 * banco del path -> coloreo -> codegen::RegAlloc.  Es el allocator de
 * PRODUCCION UNICO (linear_scan jubilado); el orquestador (vreg_pipeline) solo
 * LLAMA aqui, no contiene el allocator.
 *
 *     IntervalResult + TargetRegInfo         (del backend, por-path)
 *              |
 *     intervals_to_problem  (backend_bridge: traduce hazards -> Facts del
 * valor)
 *              |
 *     color_smart_spill     (el modelo decide: coloreo por lane, spill por
 * coste)
 *              |
 *     regalloc_from_lanes   (backend_bridge: LaneAssignment ->
 * codegen::RegAlloc)
 *
 * El banco se construye DESDE @p tri (el mismo del path: VM_ABI del JIT o
 * @c target.reg_info() del AOT) -> el modelo describe EXACTAMENTE el problema
 * que ve el backend/rewrite de ese path.  rbank es la fuente de conocimiento
 * CENTRALIZADA: si un caso no se puede representar, la politica es ABORTAR y
 * anyadir el soporte al MODELO (no un fallback legacy).
 *
 * DESACOPLADO del IR: recibe @p vec_active como bool (lo calcula el caller:
 * detectar ops VEC_* es del frontend/pipeline, no del allocator) -> este modulo
 * solo depende de jit
 * (IntervalResult/codegen::RegAlloc/TargetRegInfo/BackendCaps) + el modelo
 * rbank.
 */

#ifndef VESTA_CODEGEN_RBANK_ALLOCATE_H
#define VESTA_CODEGEN_RBANK_ALLOCATE_H

#include "codegen/assignment_plan.h" // AssignmentPlan (salida del splitting)
#include "codegen/rbank/backend_bridge.h" // intervals_to_problem, regalloc_from_lanes
#include "codegen/rbank/fragmentation_recovery.h" // build_fragmentation_plan (splitting)
#include "codegen/rbank/optimization_context.h"
#include "codegen/rbank/physical_bank.h"
#include "codegen/rbank/recovery_pass.h" // recover_spills (2a pasada)
#include "codegen/rbank/smart_spill.h"   // color_smart_spill
#include "jit/backend_caps.h"
#include "jit/interval.h"
#include "codegen/regalloc.h"
#include "jit/target_reginfo.h"

#include <algorithm>
#include <cstdint>

namespace codegen {
namespace rbank {

/**
 * @brief Resuelve un @c AbstractProblem YA construido: greedy + taxonomia +
 *        Recovery + puente a @c codegen::RegAlloc.
 *
 * Es el NUCLEO del allocator, y esta separado del punto de entrada a proposito.
 * Los tres modos llegan aqui, pero por PUERTAS distintas: el JIT y el AOT desde
 * los intervalos del MachineIR (@c intervals_to_problem), el interprete desde
 * la vivacidad del IR (@c liveness_to_problem) -- son espacios de posiciones
 * distintos, no el mismo adaptador.  Lo que NO puede diferir es lo que viene
 * despues: si esta secuencia se copiara para el segundo consumidor, cada mejora
 * y cada fallo del asignador habria que hacerlos dos veces, que es exactamente
 * lo que este refactor elimina.
 *
 * El splitting (3a pasada) NO esta aqui: necesita los intervalos del MachineIR
 * para construir el plan, asi que vive en el punto de entrada que los tiene.
 *
 * @param vreg_count  tamano DENSO del vector @c assign del resultado.
 */
inline codegen::RegAlloc
rbank_solve(const AbstractProblem &p, uint32_t vreg_count,
            const PhysicalRegisterBank &bank, bool vec_active,
            const jit::MachineNextUseFacts *next_use, SpillTrace *trace,
            bool recover, LaneAssignment *la_out = nullptr,
            const ConstraintSet *cs_in = nullptr) {
    /* Restricciones de FORMA: las que impone la instruccion aunque las vidas
     * permitan compartir lane.  Vacio = ninguna (comportamiento de siempre). */
    ConstraintSet cs_vacio;
    const ConstraintSet &cs = cs_in ? *cs_in : cs_vacio;
    OptimizationContext ctx =
        make_context(const_cast<PhysicalRegisterBank &>(bank),
                     const_cast<ConstraintSet &>(cs));
    ctx.next_use =
        next_use; // Fact MachineIR (Belady); nullptr = fallback duracion.
    ctx.spill_trace = trace; // instrumento opcional (razon de victima).
    LaneAssignment la = color_smart_spill(p, ctx, vec_active);
    // Taxonomia de los spills del greedy (PRE-recovery):
    // fully/partially/structural
    // -- el "mapa" que dirige el siguiente escalon (Fragmentation Recovery
    // ataca los partially).  Diagnostico; solo si el instrumento pidio el
    // trace.
    if (trace) {
        // Taxonomia de los spills del greedy (PRE-recovery): fully(grafo)
        // descompuesto en partially/structural.  Lo que el greedy recupere de
        // fully se cuenta abajo en rec_greedy -> KPI Fully / Recovered /
        // Potential.
        const SpillTaxonomy tx = classify_spills(p, la, bank, vec_active);
        trace->tax_fully += tx.fully;
        trace->tax_partially += tx.partially;
        trace->tax_structural += tx.structural;
        trace->tax_splitting_potential += tx.splitting_potential;
    }
    // 2a pasada (Recovery): repara la asignacion incompleta del greedy
    // reasignando a registro los spills que caben en una lane libre en TODO su
    // intervalo.  NO recolorea nada existente -> imposible introducir
    // regresiones.  VESTA_RECOVERY=0 lo desactiva (A/B).  El diagnostico
    // AllocatorDiagnostics es el oraculo.
    if (recover) {
        const uint32_t rec = recover_spills(p, la, bank, vec_active);
        if (trace) trace->rec_greedy += rec;
    }
    codegen::RegAlloc ra = regalloc_from_lanes(la, p, bank, vreg_count);
    if (la_out) *la_out = std::move(la);
    return ra;
}

/**
 * @brief Punto de entrada del JIT y el AOT: parte de los intervalos del
 *        MachineIR.  @p vreg_count = tamano DENSO (mf.vreg_count); @p tri =
 *        descriptor del path; @p vec_active = usa el path vectorial (afecta a
 *        las lanes VEC_ACC demand-driven).  El ssa_coalesce del backend ya
 *        elimino las copias -> el modelo NO re-coalesce.
 */
inline codegen::RegAlloc
rbank_allocate(const jit::IntervalResult &ivs, uint32_t vreg_count,
               const jit::TargetRegInfo &tri, bool vec_active,
               const jit::MachineNextUseFacts *next_use = nullptr,
               SpillTrace *trace = nullptr, bool recover = true,
               codegen::AssignmentPlan *plan_out = nullptr,
               const ConstraintSet *cs_in = nullptr) {
    /* Memoizado: la geometria es inmutable (invariante I4) y esto corre una vez
     * por funcion.  La referencia vale durante toda la funcion porque nada
     * aguas abajo pide otro banco -- ver la nota de la propia cache. */
    const PhysicalRegisterBank &bank =
        physical_bank_x86_64_from_reginfo_cached(tri, jit::backend_caps_host());
    const AbstractProblem p = intervals_to_problem(ivs);
    LaneAssignment la;
    codegen::RegAlloc ra = rbank_solve(p, vreg_count, bank, vec_active,
                                       next_use, trace, recover, &la, cs_in);

    /* 3a pasada (Fragmentation Recovery / splitting): los spills que NO caben
     * enteros en una lane pueden volver a registro POR TRAMOS.  No toca @c la
     * ni @c ra: produce un plan que materializa el TimelineBuilder aguas abajo.
     * Sin @p plan_out el splitting ni siquiera se calcula (coste cero para los
     * callers que no lo consumen). */
    if (plan_out) {
        const RecoveryCostModel cost;
        FragmentationStats fs;
        *plan_out =
            build_fragmentation_plan(p, la, bank, vec_active, ivs, cost, &fs);
        /* CONSECUENCIA MECANICA (no una decision): si un tramo usa una lane
         * PRESERVADA, el prologo/epilogo TIENE que salvarla -- el plan la
         * escribe igual que si fuese una asignacion normal.  Derivar el frame
         * del plan es del puente, no del productor: la Fragmentation Recovery
         * solo afirma "aqui vive en esta lane". */
        for (const codegen::AssignmentInterval &si : plan_out->intervals) {
            if (!si.location.is_register()) continue;
            const uint8_t id = si.location.register_id();
            const ViewWidth w =
                (si.vreg < ivs.intervals.size() &&
                 ivs.intervals[si.vreg].cls == jit::RegClass::FP)
                    ? ViewWidth::W16
                    : ViewWidth::W8;
            if (bank.preservation(id, w) == SavePolicy::PRESERVED &&
                std::find(ra.callee_saved_used.begin(),
                          ra.callee_saved_used.end(),
                          id) == ra.callee_saved_used.end()) {
                ra.callee_saved_used.push_back(id);
                std::sort(ra.callee_saved_used.begin(),
                          ra.callee_saved_used.end());
            }
        }
        if (trace) {
            trace->split_values += fs.values_split;
            trace->split_intervals += fs.intervals;
            trace->split_area += fs.recovered_area;
            trace->split_uses += fs.uses_recovered;
            trace->split_rej_cost += fs.rejected_cost;
            trace->split_acc_gain += fs.accepted_gain;
            trace->split_rej_area += fs.rejected_area;
            trace->split_rej_uses += fs.rejected_uses;
            trace->split_rej_gain += fs.rejected_gain;
            trace->split_rej_shape += fs.rejected_shape;
        }
    }
    return ra;
}

} // namespace rbank
} // namespace codegen

#endif // VESTA_CODEGEN_RBANK_ALLOCATE_H
