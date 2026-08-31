/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file contracts.cpp
 * @brief Generacion DECLARATIVA de contratos.  Cada contrato es una REGLA
 *        (nombre + predicado) registrada en una tabla.  Anadir un contrato
 *        nuevo = anadir una entrada aqui; el motor @c derive_contracts no
 *        cambia.  Los predicados leen el @c FunctionSummary completo (efectos
 *        local/closure + estructura + interproc), asi los contratos que
 *        necesitan analisis interprocedural o estructural tambien encajan.
 */
#include "analysis/effects/summary.h"

namespace analysis {
namespace effects {

// --------------------------------------------------------------------------
// Predicados.  Cada uno decide UN contrato desde el summary.  Son funciones
// libres (puntero de funcion, sin captura) para que la tabla sea estatica.
// --------------------------------------------------------------------------

/* Cada predicado ACUMULA sus motivos: el veredicto es "no hay motivos".  Nadie
 * explica el criterio por segunda vez, que es como se acaba teniendo dos. */
using R = ContractReason;

/// Anade @p r si @p cond.
static inline void si(ContractCheck &k, bool cond, R r) {
    if (cond) k.motivos.push_back(r);
}

/// pure: sin efectos de dato observables en TODO el cierre.  La definicion
/// depende del PERFIL (misma base de hechos, distinta opinion):
///   - Default : no escribe mem, no lanza/aloca/io/bloquea, sin tags.
///   - Strict  : ademas DETERMINISTA (sin lecturas de reloj/random/...).
///   - Relaxed : tolera may_trap (los traps 'no deberian pasar').
static ContractCheck p_pure(const FunctionSummary &s, ContractProfile profile) {
    ContractCheck k;
    si(k, s.completeness == AnalysisCompleteness::Unknown,
       R::AnalisisIncompleto);
    const SemanticEffects &c = s.semantic.closure;
    si(k, c.mem.writes_memory(), R::EscribeMemoria);
    si(k, c.may_throw, R::PuedeLanzar);
    /* Abortar tambien cuenta.  Una llamada que puede matar el proceso no se
     * puede quitar ni mover como si no hiciera nada, y en nativo un panic ya
     * no enciende `may_throw`: sin esto, una funcion que aborta salia pura. */
    si(k, c.may_panic, R::PuedeAbortar);
    si(k, c.may_allocate, R::Aloca);
    si(k, c.may_io, R::HaceIO);
    si(k, c.may_block, R::Bloquea);
    /* Y fallar en el PROCESADOR cuenta salvo en Relaxed, que es lo que la
     * cabecera de aqui arriba lleva diciendo desde el principio -- y no se
     * miraba en NINGuN perfil, asi que `Relaxed` no se distinguia de `Default`
     * en el unico eje que lo separaba, y una funcion que puede reventar salia
     * pura.  Como siempre: lo que nadie comprueba se lee como demostrado. */
    si(k, profile != ContractProfile::Relaxed && c.may_trap, R::PuedeAtrapar);
    si(k, !c.tags.empty(), R::TieneEtiquetas);
    si(k, profile == ContractProfile::Strict && !c.determinism.empty(),
       R::NoDeterminista);
    return k;
}

/**
 * @brief mem_free: la funcion NO TOCA memoria en absoluto, ni para leer.
 *
 * Es mas fuerte que @c pure -- que si admite lecturas -- y es justo la
 * condicion que permite que una LLAMADA deje de ser una barrera de memoria: si
 * no lee ni escribe nada, ni atrapa, ni aloca, ni tiene atomicas, lo que
 * hubiera antes y despues de ella se puede mover libremente.
 *
 * El optimizador ya usaba esta condicion, escrita a mano dentro de el.  Al ser
 * una fila mas de esta tabla, la usan LOS DOS y ademas sale en el informe de
 * `--analyze`: se puede ver que funciones cumplen y por que una llamada sigue
 * siendo una barrera, en vez de tener que adivinarlo.
 *
 * Exige @c Complete (no basta con "no Unknown"): una funcion analizada solo en
 * parte podria tocar memoria en el trozo que no se miro.
 */
static ContractCheck p_mem_free(const FunctionSummary &s,
                                ContractProfile profile) {
    (void)profile; // no es opinable: o toca memoria o no
    ContractCheck k;
    si(k, s.completeness != AnalysisCompleteness::Complete,
       R::AnalisisIncompleto);
    const SemanticEffects &c = s.semantic.closure;
    si(k, !c.mem.reads.empty(), R::LeeMemoria);
    si(k, !c.mem.writes.empty(), R::EscribeMemoria);
    si(k, c.may_trap, R::PuedeAtrapar);
    si(k, c.may_throw, R::PuedeLanzar);
    si(k, c.may_allocate, R::Aloca);
    si(k, c.may_block, R::Bloquea);
    si(k, c.may_io, R::HaceIO);
    si(k, !c.tags.empty(), R::TieneEtiquetas);
    si(k, c.atomic.order != MemOrder::None || c.atomic.is_fence, R::EsAtomica);
    return k;
}

/// readonly: no escribe memoria en el cierre (puede leer).
static ContractCheck p_readonly(const FunctionSummary &s,
                                ContractProfile profile) {
    (void)profile;
    ContractCheck k;
    si(k, s.completeness == AnalysisCompleteness::Unknown,
       R::AnalisisIncompleto);
    si(k, s.semantic.closure.mem.writes_memory(), R::EscribeMemoria);
    return k;
}

/// leaf: no llama a nadie (ni estatica ni dinamicamente).
static ContractCheck p_leaf(const FunctionSummary &s, ContractProfile profile) {
    (void)profile;
    ContractCheck k;
    si(k, s.interproc.has_calls, R::Llama);
    return k;
}

/// nothrow: no lanza en el cierre.
static ContractCheck p_nothrow(const FunctionSummary &s,
                               ContractProfile profile) {
    (void)profile;
    ContractCheck k;
    si(k, s.completeness == AnalysisCompleteness::Unknown,
       R::AnalisisIncompleto);
    si(k, s.semantic.closure.may_throw, R::PuedeLanzar);
    return k;
}

/// nopanic: no aborta por `panic` en el cierre.
///
/// Era un alias de `nothrow`, y dejo de valer al separar las dos senales: en
/// nativo un panic no lanza nada -- llama al hook y no vuelve --, asi que con
/// la senal de lanzar una funcion que aborta salia como `nopanic`.
static ContractCheck p_nopanic(const FunctionSummary &s,
                               ContractProfile profile) {
    (void)profile;
    ContractCheck k;
    si(k, s.completeness == AnalysisCompleteness::Unknown,
       R::AnalisisIncompleto);
    si(k, s.semantic.closure.may_panic, R::PuedeAbortar);
    return k;
}

/// deterministic: sin lecturas de reloj/random/pid/entorno ni I/O externa.
static ContractCheck p_deterministic(const FunctionSummary &s,
                                     ContractProfile profile) {
    (void)profile;
    ContractCheck k;
    const SemanticEffects &c = s.semantic.closure;
    si(k, s.completeness == AnalysisCompleteness::Unknown,
       R::AnalisisIncompleto);
    si(k, !c.determinism.empty(), R::NoDeterminista);
    si(k, c.may_io, R::HaceIO);
    return k;
}

/// heap_free: no aloca heap en el cierre.
static ContractCheck p_heap_free(const FunctionSummary &s,
                                 ContractProfile profile) {
    (void)profile;
    ContractCheck k;
    si(k, s.completeness == AnalysisCompleteness::Unknown,
       R::AnalisisIncompleto);
    si(k, s.semantic.closure.may_allocate, R::UsaMonton);
    return k;
}

/// gc_free: no aloca GC (hoy = no aloca heap; se afinara cuando el MemEffect
/// distinga GC de raw).
static ContractCheck p_gc_free(const FunctionSummary &s,
                               ContractProfile profile) {
    ContractCheck k = p_heap_free(s, profile);
    for (auto &m : k.motivos)
        if (m == R::UsaMonton) m = R::UsaRecolector;
    return k;
}

/// freestanding: no toca estado de maquina privilegiado ni I/O (candidato a
/// Bare).
static ContractCheck p_freestanding(const FunctionSummary &s,
                                    ContractProfile profile) {
    (void)profile;
    ContractCheck k;
    const SemanticEffects &c = s.semantic.closure;
    const bool machine = c.tags.has(CapabilityTag::PortIO) ||
                         c.tags.has(CapabilityTag::MSR) ||
                         c.tags.has(CapabilityTag::Privileged) ||
                         c.tags.has(CapabilityTag::InterruptState);
    si(k, s.completeness == AnalysisCompleteness::Unknown,
       R::AnalisisIncompleto);
    si(k, machine, R::NecesitaRuntime);
    si(k, c.may_io, R::HaceIO);
    return k;
}

const char *contract_reason_code(ContractReason r) {
    switch (r) {
    case R::LeeMemoria: return "VX2010";
    case R::EscribeMemoria: return "VX2011";
    case R::PuedeAtrapar: return "VX2012";
    case R::PuedeLanzar: return "VX2013";
    case R::Aloca: return "VX2014";
    case R::Bloquea: return "VX2015";
    case R::HaceIO: return "VX2016";
    case R::TieneEtiquetas: return "VX2017";
    case R::EsAtomica: return "VX2018";
    case R::NoDeterminista: return "VX2019";
    case R::AnalisisIncompleto: return "VX2020";
    case R::Llama: return "VX2021";
    case R::UsaMonton: return "VX2022";
    case R::UsaRecolector: return "VX2023";
    case R::NecesitaRuntime: return "VX2024";
    case R::PuedeAbortar: return "VX2025";
    }
    return "VX2020";
}

// --------------------------------------------------------------------------
// La TABLA.  Anadir un contrato = anadir una fila.  El motor no cambia.
// --------------------------------------------------------------------------
const std::vector<ContractRule> &contract_rules() {
    static const std::vector<ContractRule> rules = {
        {"pure", p_pure},
        {"mem_free", p_mem_free},
        {"readonly", p_readonly},
        {"leaf", p_leaf},
        {"nothrow", p_nothrow},
        {"nopanic", p_nopanic},
        {"deterministic", p_deterministic},
        {"heap_free", p_heap_free},
        {"gc_free", p_gc_free},
        {"freestanding", p_freestanding},
    };
    return rules;
}

std::vector<EvaluatedContract> derive_contracts(const FunctionSummary &s,
                                                ContractProfile profile) {
    std::vector<EvaluatedContract> out;
    const auto &rules = contract_rules();
    out.reserve(rules.size());
    for (const ContractRule &r : rules) {
        ContractCheck k = r.predicate(s, profile);
        const bool ok = k.holds();
        out.push_back({r.name, ok, std::move(k.motivos)});
    }
    return out;
}

} // namespace effects
} // namespace analysis
