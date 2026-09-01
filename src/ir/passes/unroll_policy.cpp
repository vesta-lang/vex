/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file unroll_policy.cpp
 * @brief Implementacion de la politica de desenrollado (la INTELIGENCIA).
 *
 * La funcion de coste del UNROLL vive aqui (no en las metricas, que son
 * neutrales): pondera la call (~10), el load/store (~2), la rama (~3), el
 * cuerpo ya vectorizado (~2/op) y la presion de registros @c live_across de
 * forma NO lineal.  Otras optimizaciones (vectorizar, peel, unswitch)
 * reutilizan las MISMAS metricas con OTRA funcion de coste.
 */

#include "ir/passes/unroll_policy.h"

#include "analysis/facts/loop_metrics.h"

#include <cstdio>

namespace ir {

namespace {

// Iteraciones a partir de las cuales un trip constante se replica ENTERO
// (full).
constexpr int64_t FULL_UNROLL_LIMIT = 16;

// FUNCION DE COSTE DEL UNROLL (propia del pase) = coste aproximado de una
// iteracion.  La presion de registros crece NO linealmente: desenrollar xN
// multiplica los vivos y pasado cierto punto dispara spills -> termino
// cuadratico suave (live*(live-1)/16).  NO se penaliza el cuerpo vectorizado:
// ya tiene menos instrucciones y es justo donde el unroll (romper la
// dependencia del acumulador) mas ayuda.
int unroll_cost(const analysis::LoopMetrics &m) {
    int c = m.instructions + 2 * m.loads + 2 * m.stores + 10 * m.calls +
            3 * m.branches + 4 * m.expensive_ops;
    c += m.live_across * (m.live_across - 1) / 16; // presion no-lineal
    return c;
}

// Factor base por coste ponderado de la iteracion.  Cuerpo mas barato -> el
// overhead del bucle (cmp/branch/incremento) pesa mas -> mas unroll.
int base_factor(int cost) {
    if (cost <= 12) return 8;
    if (cost <= 28) return 4;
    if (cost <= 55) return 2;
    return 1;
}

int floor_pow2(int x) {
    int p = 1;
    while ((p << 1) <= x)
        p <<= 1;
    return p;
}

// Presupuesto EFECTIVO: la base del target recortada por el tamano de la
// funcion (presion de I-cache, como LLVM/GCC).  Una funcion enorme baja el
// presupuesto aunque el bucle sea diminuto, porque el problema pasa a ser la
// I-cache y no el overhead del bucle.  Piso para no anular el unroll de cuerpos
// triviales en funciones grandes.
int effective_budget(const UnrollTargetInfo &t) {
    int b = t.code_budget;
    if (t.code_size > 256) b = (int)((int64_t)b * 256 / t.code_size);
    if (b < 24) b = 24;
    return b;
}

UnrollDecision reject(UnrollReject why) {
    UnrollDecision d;
    d.reject = why;
    return d;
}

} // namespace

const char *unroll_reject_code(UnrollReject r) {
    switch (r) {
    case UnrollReject::Trivial: return "unroll.trivial";
    case UnrollReject::Calls: return "unroll.calls";
    case UnrollReject::RegisterPressure: return "unroll.register_pressure";
    case UnrollReject::CodeGrowth: return "unroll.code_growth";
    case UnrollReject::CostTooHigh: return "unroll.cost_too_high";
    case UnrollReject::Cold: return "unroll.cold";
    default: return "unroll.none";
    }
}

UnrollDecision choose_unroll_factor(const analysis::LoopMetrics &m,
                                    int64_t trip_count,
                                    const UnrollTargetInfo &target) {
    if (m.instructions <= 0 || trip_count == 0)
        return reject(UnrollReject::Trivial);

    // Peso de ejecucion (PGO futuro): un bucle frio no merece crecer el codigo.
    if (target.hotness <= 0.0) return reject(UnrollReject::Cold);

    const int cost = unroll_cost(m);
    // Presupuesto de crecimiento de codigo (en unidades de COSTE, la misma que
    // usa unroll_cost), recortado por el tamano de la funcion (I-cache) y
    // escalado por el peso de ejecucion.  El target ya trae la base adecuada;
    // la politica no sabe de que backend viene.
    int budget = effective_budget(target);
    if (target.hotness > 0.0 && target.hotness != 1.0)
        budget = (int)((double)budget * target.hotness);

    // --- Full-unroll: trip constante corto cuyo cuerpo replicado cabe. ---
    // Se permite AUNQUE haya calls (el cuerpo entero, sin bucle ni guarda,
    // expone constantes e inlining; es lo que hace LLVM con trips pequenos).
    if (trip_count > 0 && trip_count <= FULL_UNROLL_LIMIT &&
        (int64_t)cost * trip_count <= budget) {
        UnrollDecision d;
        d.mode = UnrollMode::Full;
        d.factor = (int)trip_count;
        return d;
    }

    // --- Partial/Remainder: aqui una call SI arruina el unroll (no expone ILP
    //     y el remainder mantiene el bucle con la call). ---
    if (m.calls > 0) return reject(UnrollReject::Calls);

    int f = base_factor(cost);
    if (f < 2) return reject(UnrollReject::CostTooHigh);

    // Tope por microarquitectura (ARM vs AVX512 no tienen el mismo margen).
    if (target.max_unroll >= 2 && f > target.max_unroll)
        f = floor_pow2(target.max_unroll);

    // CFG fragmentado (ifs internos): clonar explota -> limitar.
    if (m.basic_blocks > 6 && f > 2) f = 2;
    if (m.expensive_ops > 2 && f > 2) f = 2;

    // Presupuesto de crecimiento de codigo (misma unidad de COSTE que el full).
    while (f >= 2 && (int64_t)cost * f > budget)
        f >>= 1;
    if (f < 2) return reject(UnrollReject::CodeGrowth);

    // UNICO filtro de presion de registros: recortar el factor (no rechazar de
    // golpe).  Un cuerpo con live alto aun puede acabar en factor 2 en vez
    // de 1.
    //
    // Modelo: el unroll CONCATENA copias (cadena serial), no las paraleliza;
    // los loop-carried (live_across) se enhebran y NO coexisten x factor.  Solo
    // coexisten hasta `ilp_width` copias si el scheduler las interleava.  Por
    // eso la presion es  live_across * min(factor, ilp_width), no  live_across
    // * factor: un bucle de dependencia serial (poco live) puede desenrollar
    // mucho sin spills; uno con muchos carried se acota.  (El interprete no
    // interleava
    // -> ilp_width 1 -> practicamente sin tope de presion.)
    if (m.live_across > 0) {
        const int ilp = target.ilp_width < 1 ? 1 : target.ilp_width;
        while (f >= 2) {
            const int eff = f < ilp ? f : ilp; // copias que coexisten a la vez
            if ((int64_t)m.live_across * eff <= target.registers) break;
            f >>= 1;
        }
        if (f < 2) return reject(UnrollReject::RegisterPressure);
    }

    // --- Trip conocido: nunca mas que el trip; partial si lo divide exacto.
    // ---
    if (trip_count > 0) {
        if ((int64_t)f > trip_count) f = floor_pow2((int)trip_count);
        if (f < 2) return reject(UnrollReject::CostTooHigh);
        if (trip_count % f == 0) {
            UnrollDecision d;
            d.mode = UnrollMode::Partial;
            d.factor = f;
            return d;
        }
    }

    UnrollDecision d;
    d.mode = UnrollMode::Remainder;
    d.factor = f;
    return d;
}

void UnrollStats::account(const UnrollDecision &d) {
    ++loops_seen;
    switch (d.mode) {
    case UnrollMode::Full: ++full; return;
    case UnrollMode::Partial: ++partial; return;
    case UnrollMode::Remainder: ++remainder; return;
    case UnrollMode::None: break;
    }
    switch (d.reject) {
    case UnrollReject::Trivial: ++rej_trivial; break;
    case UnrollReject::Calls: ++rej_calls; break;
    case UnrollReject::RegisterPressure: ++rej_pressure; break;
    case UnrollReject::CodeGrowth: ++rej_growth; break;
    case UnrollReject::CostTooHigh: ++rej_cost; break;
    case UnrollReject::Cold: ++rej_cold; break;
    case UnrollReject::None: break;
    }
}

void UnrollStats::dump() const {
    if (loops_seen == 0) return;
    std::fprintf(
        stderr,
        "== UNROLL == seen:%d full:%d partial:%d remainder:%d | "
        "rej calls:%d pressure:%d growth:%d cost:%d cold:%d trivial:%d\n",
        loops_seen, full, partial, remainder, rej_calls, rej_pressure,
        rej_growth, rej_cost, rej_cold, rej_trivial);
}

} // namespace ir
