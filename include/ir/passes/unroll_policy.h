/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file unroll_policy.h
 * @brief Politica de desenrollado: DECIDE el factor y el modo.
 *
 * La INTELIGENCIA del unroll (nada de un factor fijo).  Consume las metricas
 * NEUTRALES (@c analysis::LoopMetrics) y les aplica la FUNCION DE COSTE PROPIA
 * del unroll (una call pesa ~10, un load/store ~2, una rama ~3, un cuerpo ya
 * vectorizado ~2/op, y la presion de registros @c live_across crece de forma NO
 * lineal) mas:
 *   - PRESUPUESTO de crecimiento de codigo y de registros: viven en el TARGET,
 *     no los pasa el que invoca el pase (el interprete es dispatch-bound y
 *     tolera mas; el JIT modera por I-cache; el AOT compila una vez y se
 * permite mas que el JIT).
 *   - TRIP-COUNT (si es constante): full de bucles cortos (incluso con call si
 *     el cuerpo cabe), partial si el trip es multiplo del factor, y nunca
 *     desenrollar mas que el trip.
 *
 * El coste NO vive en las metricas (esas son neutrales y las reutilizan
 * vectorizacion / peeling / unswitch con OTRA ponderacion): vive AQUI, en el
 * pase.  El transformador (unroll.cpp) no conoce ninguna heuristica.
 */
#ifndef IR_PASSES_UNROLL_POLICY_H
#define IR_PASSES_UNROLL_POLICY_H

#include <cstdint>

namespace analysis {
struct LoopMetrics;
}

namespace ir {

/**
 * @brief Descripcion del backend objetivo (coste distinto por microarquitectura
 *        de ejecucion Y por presupuesto de codigo/registros).
 *
 * El presupuesto vive AQUI y no lo pasa el que invoca el pase: cada backend
 * sabe cuanto codigo/registros puede permitirse.  Se amplia sin tocar la firma.
 */
struct UnrollTargetInfo {
    int registers = 14; ///< GP asignables (presion; AArch64/AVX512 mas).
    int code_budget =
        128;            ///< tope de tamano estimado del cuerpo tras el unroll.
    int max_unroll = 8; ///< tope de factor por microarquitectura.
    int code_size = 0; ///< tamano estimado de la funcion (proxy: instrucciones;
                       ///< presion de I-cache).  Una funcion enorme recorta el
                       ///< presupuesto aunque el bucle sea diminuto.  Lo
                       ///< rellena el pase.
    int ilp_width = 4; ///< profundidad de interleave que el motor puede
                       ///< explotar (ventana OoO / del scheduler).  El unroll
                       ///< CONCATENA copias (cadena serial): los loop-carried
                       ///< se enhebran y NO coexisten x factor; solo coexisten
                       ///< hasta ilp_width copias si el scheduler las
                       ///< paraleliza.  El interprete ejecuta en serie -> 1.
    double hotness =
        1.0; ///< peso de ejecucion (PGO futuro).  1.0 neutro; >1 mas
             ///< caliente; <1 mas frio; 0.0 = NO se ejecuta nunca.

    // La politica NO conoce el backend: cada target es solo un conjunto de
    // parametros cuantitativos.  El interprete es dispatch-bound (el overhead
    // del bucle domina) -> presupuesto y factor mayores, y NO interleava (ilp
    // 1); JIT/AOT moderan por I-cache y interleavan (ilp 4).
    static UnrollTargetInfo interp() { return {14, 256, 16, 0, 1, 1.0}; }
    static UnrollTargetInfo jit() { return {14, 96, 8, 0, 4, 1.0}; }
    static UnrollTargetInfo aot() { return {14, 160, 8, 0, 4, 1.0}; }
    /// IR compartido, antes del split de backend: punto medio (interleave del
    /// scheduler, presupuesto intermedio).
    static UnrollTargetInfo generic() { return {14, 128, 8, 0, 4, 1.0}; }
};

/// Modo de desenrollado elegido.
enum class UnrollMode {
    None,    ///< no desenrollar.
    Full,    ///< trip constante y pequeno: replicar TODO (sin bucle ni guarda).
    Partial, ///< trip % factor == 0: unroll sin remainder.
    Remainder ///< general: guarda + U copias + bucle original de remainder.
};

/// Motivo por el que NO se desenrolla (depuracion de heuristicas).
enum class UnrollReject {
    None,             ///< se desenrolla.
    Trivial,          ///< cuerpo vacio o trip == 0.
    Calls,            ///< call en cuerpo (y no cabe full de trip corto).
    RegisterPressure, ///< tras recortar por registros, el factor cae a 1.
    CodeGrowth,       ///< no cabe en el presupuesto de codigo.
    CostTooHigh,      ///< cuerpo demasiado caro para exponer ILP util.
    Cold              ///< peso de ejecucion insuficiente (PGO).
};

/**
 * @brief El codigo ESTABLE de un rechazo, para el catalogo y para el almacen.
 *
 * Los motivos existian desde el principio y solo salian como un TOTAL a
 * stderr detras de un flag: "3 rechazados por llamadas" no dice CUAL, y el
 * usuario que se pregunta por que su bucle no se desenrollo se queda igual.
 * Con el codigo, la decision es un hecho por bucle y se puede preguntar.
 *
 * En ingles y estable, como el resto del vocabulario: viaja al fichero de
 * hechos y al volcado.  La frase la pone el catalogo multi-idioma.
 */
const char *unroll_reject_code(UnrollReject r);

/// Decision de la politica.
struct UnrollDecision {
    UnrollMode mode = UnrollMode::None;
    int factor = 1;
    UnrollReject reject = UnrollReject::None;
    bool allow() const { return mode != UnrollMode::None && factor >= 2; }
};

/// Estadisticas agregadas del pase (estilo LLVM -stats; via
/// VESTA_UNROLL_STATS).
struct UnrollStats {
    int loops_seen = 0;
    int full = 0, partial = 0, remainder = 0;
    int rej_trivial = 0, rej_calls = 0, rej_pressure = 0;
    int rej_growth = 0, rej_cost = 0, rej_cold = 0;
    void account(const UnrollDecision &d);
    void dump() const; ///< imprime a stderr si hubo bucles vistos.
};

/**
 * @brief Decide como desenrollar un bucle a partir de sus metricas neutrales.
 * @param m          metricas del cuerpo (analysis::LoopMetrics).
 * @param trip_count iteraciones si es CONSTANTE conocido; <0 = desconocido.
 * @param target     backend objetivo (lleva el presupuesto y los registros).
 */
UnrollDecision choose_unroll_factor(const analysis::LoopMetrics &m,
                                    int64_t trip_count,
                                    const UnrollTargetInfo &target);

} // namespace ir

#endif // IR_PASSES_UNROLL_POLICY_H
