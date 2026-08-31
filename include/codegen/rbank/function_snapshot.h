/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/rbank/function_snapshot.h
 * @brief FunctionSnapshot: el REPOSITORIO DE CONOCIMIENTO del compilador sobre
 *        una funcion, con QUERY SYSTEM lazy (demand-driven, estilo rustc).
 *
 * Vesta deja de ser una cadena de passes.  Tiene DOS representaciones del
 * programa: el IR y el CONOCIMIENTO (Programa -> Hechos -> Decisiones).  El
 * @c FunctionSnapshot es ese conocimiento: un objeto de PRIMER NIVEL que
 * consultan los 3 modos (interp/JIT/AOT) y todo motor de decision.
 *
 *      IR
 *       |
 *       v
 *   Repositorio de conocimiento (FunctionSnapshot)   <-- este objeto
 *       |
 *       +--> interp / JIT / AOT / scheduler / allocator / vectorizer / ...
 *       |
 *       v
 *   Autovalidacion (cada Fact se autocertifica; el snapshot se AUDITA)
 *
 * QUERY SYSTEM (lazy + cache): no se construye todo de golpe.  Cada hecho se
 * COMPUTA LA PRIMERA VEZ que se pide, se CACHEA y se devuelve.  Las
 * dependencias se resuelven SOLAS porque los accessors se llaman entre si:
 *
 *      value_reqs()  --calls-->  liveness(), loop_facts(), profile_facts()
 *      profile_facts() --calls--> loop_facts()
 *
 *      snapshot.loop_facts()      // si no existe -> compute_loop_facts ->
 * cache snapshot.value_reqs()      // arrastra liveness + loops + profile
 *
 * Los campos-cache son publicos (para serializacion / warm-load / inspeccion);
 * la interfaz RECOMENDADA es la de accessors (demand-driven).  Se construye
 * eager un subconjunto con @c SnapshotBuilder (snapshot_builder.h) cuando
 * interese (p.ej. para serializar).
 *
 * CRECE sin tocar consumidores: cada Fact nuevo (DomFacts/AliasFacts/Escape/
 * Memory/MachineCostFacts/...) es una celda @c LazyFact + un @c
 * QueryProducer<T>;
 * @c query<T>() NO cambia.  El @c FunctionSnapshot practicamente no se toca.
 *
 * DIRECCION (no ahora): hoy cada Fact necesita DOS especializaciones -- @c
 * cell<T> (donde se almacena) y @c QueryProducer<T> (como se produce).  Con
 * 4-20 Facts es llevadero; con 50 empieza a pesar.  La evolucion natural es que
 * un Fact sea una ENTIDAD completa (un Tag) que lleva ambas cosas:
 *   @code struct LoopFactsTag { using value_type = analysis::LoopFacts;
 *                               static value_type produce(const
 * FunctionSnapshot&); }; @endcode y entonces @c query<LoopFactsTag>() ya sabe
 * DONDE almacenarse (p.ej. un mapa type_index -> celda generico) y COMO
 * producirse, sin mantener dos especializaciones separadas.  El mecanismo @c
 * query<T>() se queda igual.
 *
 * CONTINUIDAD DE ESCALA: el mismo mecanismo @c query<T>() sirve a cualquier
 * AMBITO sin cambiar -- @c ModuleSnapshot.query<CallGraphFacts>() /
 * @c query<FunctionSnapshot>(), @c ProgramSnapshot.query<GlobalAliasFacts>().
 * Solo cambia el alcance del conocimiento, no la forma de consultarlo (senal de
 * que la abstraccion soporta crecer).
 *
 * SEPARACION DATO / MECANISMO (HECHO -- query system): el snapshot es DATO y ya
 * NO conoce los ALGORITMOS.  @c query<T>() es generico: pide el Fact a su celda
 * @c LazyFact<T> y, si falta, al productor REGISTRADO @c QueryProducer<T>
 * (donde viven @c compute_loop_facts / @c assemble_value_requirements / ...).
 * El snapshot solo ALMACENA (celdas) y CONSULTA; la PRODUCCION esta aislada por
 * tipo.  Anadir un Fact = registrar su @c QueryProducer + su celda, SIN tocar
 * el mecanismo.  (Estilo query system de rustc: @c snapshot.query<LoopFacts>()
 * sin saber quien lo calcula.)  Los accessors nombrados (@c loop_facts()...)
 * quedan como azucar sobre @c query<T>().
 *
 * SERIALIZACION (futura, cuando haya consumidor): al ser DATOS, el snapshot es
 * serializable -> IR -> Snapshot -> cache.  Casi un "core dump" del
 * conocimiento: reproducir bugs, comparar snapshots entre versiones, regresion
 * de analisis, herramientas externas.
 *
 * ===========================================================================
 *  RELACION CON EL MOTOR (@c analysis/manager/analysis_manager.h)
 * ===========================================================================
 * El @c FunctionSnapshot es la CAPA DE CONSULTA del motor de conocimiento, NO
 * un motor aparte.  El @c AnalysisManager es la CAPA DE GESTION (ciclo de vida
 * + invalidacion en cascada, transversal a IR y MachineIR); este snapshot es la
 * VISTA demand-driven que usan allocator / scheduler / codegen.  El mapa global
 * de capas esta en @c analysis_manager.h.  Misma familia, distinto estilo: el
 * manager indexa por @c (AnalysisID, unit) con @c PreservedAnalyses; el
 * snapshot ofrece @c query<T>() por tipo con @c LazyFact.  Hoy el snapshot
 * cachea por su cuenta; que pida sus hechos AL manager (para heredar su
 * invalidacion) son los HUECOS documentados en @c optimization_context.h.  No
 * compiten: uno gestiona QUE sobrevive a un cambio del IR; el otro, COMO se
 * pide un hecho.
 *
 * ===========================================================================
 *  ARBOL DE DEPENDENCIAS (emerge solo: cada produce() llama a otros query<U>())
 * ===========================================================================
 *      value_reqs()                          [Values]
 *        |-- liveness()                       [Liveness]  compute_liveness
 *        |-- loop_facts()                     [Loops]     compute_loop_facts
 *        |-- profile_facts()                  [Profile]
 *        |     '-- loop_facts()   (cache hit)
 *        '-- call positions <- liveness()   (cache hit)
 *
 *      remat_facts()                          [Remat]     compute_remat_facts
 *                                             (IR-driven, sin dependencias)
 *
 * Pedir @c value_reqs() arrastra Liveness + Loops + Profile UNA vez cada uno
 * (cache); pedir @c remat_facts() no arrastra nada.  El grafo NO se declara en
 * ningun sitio: EMERGE de que cada @c produce() consulta solo lo que necesita.
 *
 * ===========================================================================
 *  CATALOGO DE HECHOS (los registrados HOY; crece sin tocar el mecanismo)
 * ===========================================================================
 *   Fact      value_type                   productor           capa
 *   -------   --------------------------   -----------------   ----------
 *   Liveness  ir::LivenessResult           compute_liveness    STRUCTURAL
 *   Loops     analysis::LoopFacts          compute_loop_facts  DERIVED
 *   Profile   analysis::ProfileFacts       compute_profile..   DERIVED
 *   Values    vector<ValueRequirements>    assemble_value..    adaptador
 *   Remat     analysis::RematFacts         compute_remat..     DERIVED
 *
 * Pendientes con MODULO ya existente en @c analysis/ (solo falta registrar su
 * @c QueryProducer + su celda para consultarlos por aqui): PointsTo + alias
 * (@c analysis/memory/), EscapeInfo (@c analysis/escape/), SemanticEffects
 * (@c analysis/effects/), MachineCostFacts (@c analysis/hw/).  Pendientes POR
 * construir: DomFacts (extraer del optimizer) y next-use / UseDef (habilita
 * seleccion de victima estilo Belady).  Cada uno = una celda + un
 * @c QueryProducer; ni @c query<T>() ni los consumidores se tocan.
 *
 * ESCALADO (mismo modelo mental, sin cambiarlo; cada nivel cuando tenga
 * consumidor real -- NO por prevision):
 *
 *      ValueRequirements   (valor)
 *            ^
 *      FunctionSnapshot    (funcion)   <-- HOY
 *            ^
 *      ModuleSnapshot      (modulo: Functions + Globals + CallGraph + alias/
 *            ^              escape/ownership GLOBALES + PGO + Inlining)
 *      ProgramSnapshot     (programa: LTO)
 *
 * Que el mismo objeto escale de valor -> funcion -> modulo -> programa sin
 * cambiar el modelo (Facts lazy + autocertificacion + query) es senal de que la
 * arquitectura es correcta.
 */

#ifndef VESTA_CODEGEN_RBANK_FUNCTION_SNAPSHOT_H
#define VESTA_CODEGEN_RBANK_FUNCTION_SNAPSHOT_H

#include "analysis/derived/profile_facts.h"
#include "analysis/fact_validation.h"
#include "analysis/facts/loop_facts.h"
#include "analysis/facts/remat_facts.h"
#include "analysis/facts/use_def_facts.h"
#include "codegen/rbank/build_requirements.h"
#include "codegen/rbank/lazy_fact.h"
#include "codegen/rbank/physical_bank.h"
#include "codegen/rbank/value_requirements.h"
#include "ir/liveness.h"
#include "ir/ssa_ir.h"

#include <cstdint>
#include <vector>

namespace codegen {
namespace rbank {

/**
 * @enum Fact
 * @brief Que hechos puede contener/computar el snapshot (mascara de bits).
 *        Crece anadiendo entradas (Dom/Alias/Escape/Memory...) sin tocar el
 *        punto de entrada ni los consumidores.
 */
enum class Fact : uint32_t {
    None = 0,
    Liveness = 1u << 0, ///< intervalos de vida (Tipo A).
    Loops = 1u << 1,    ///< LoopFacts (Tipo A).
    Profile = 1u << 2,  ///< ProfileFacts (Tipo B; depende de Loops + perfil).
    Values = 1u << 3, ///< ValueRequirements (adaptadores; dep. Liveness+Loops).
    Remat =
        1u << 4, ///< RematFacts (Tipo A, IR-driven: recomputabilidad + receta).
    UseDef = 1u << 5, ///< UseDefFacts (Tipo A, IR-driven: next-use por valor).
    // Futuro: Dom = 1u<<6, Alias = 1u<<7, Escape = 1u<<8, Memory = 1u<<9, ...
    All = Liveness | Loops | Profile | Values | Remat | UseDef,
};

/**
 * @struct QueryProducer
 * @brief REGISTRO por tipo de COMO se produce un Fact (query system estilo
 * rustc).
 *
 * Cada Fact @c T especializa @c QueryProducer<T> con
 * @c "static T produce(const FunctionSnapshot&)".  AQUI vive el CONOCIMIENTO
 * del algoritmo (compute_loop_facts / assemble_value_requirements / ...), NO en
 * el snapshot.  El snapshot solo PIDE @c query<T>(); no sabe quien calcula.
 *
 *      snapshot.query<LoopFacts>()
 *              |
 *        cell<LoopFacts>() (celda LazyFact)  --miss--> QueryProducer<LoopFacts>
 *              | ::produce(snapshot) cache hit (compute_loop_facts)
 *
 * Anadir un Fact = registrar su @c QueryProducer + su celda, SIN tocar el
 * mecanismo @c query<T>().  El primario NO tiene definicion: pedir un Fact no
 * registrado es un error de compilacion (no un fallo silencioso).
 */
/// El AMBITO va como segundo parametro para que el mecanismo sea UNO.
///
/// "Continuidad de escala" (ver la cabecera de este fichero) dice que el mismo
/// @c query<T>() sirve a cualquier ambito y que solo cambia el alcance del
/// conocimiento.  Con un solo parametro eso no se podia cumplir: un ambito
/// nuevo -- la funcion ya seleccionada a instrucciones de maquina, el modulo,
/// el programa -- necesitaba su PROPIA familia de productores, y con ella su
/// propia copia de @c query<T>().  Dos copias del mismo mecanismo acaban
/// respondiendo distinto.
///
/// El defecto conserva lo escrito: `QueryProducer<LoopFacts>` sigue nombrando
/// al productor de una funcion IR.
template <typename T, typename Scope = struct FunctionSnapshot>
struct QueryProducer;

/**
 * @struct FunctionSnapshot
 * @brief Repositorio de conocimiento de una funcion con query system lazy.
 *
 * DATO desacoplado de MECANISMO: el snapshot ALMACENA (celdas @c LazyFact) y
 * CONSULTA (@c query<T>()); la PRODUCCION vive en @c QueryProducer<T>.  El
 * snapshot no menciona ningun algoritmo.
 */
struct FunctionSnapshot {
    const ir::IrFunction *fn = nullptr; ///< funcion de la que es foto.
    const analysis::BranchProfile *prof =
        nullptr; ///< perfil (debe sobrevivir al snapshot si Profile es lazy).

    // --- Celdas LazyFact (encapsulan almacenamiento + cache; el mutable vive
    //     DENTRO de LazyFact, no aqui).  Publicas para serializacion/inspeccion
    //     (via peek()/ready()); la interfaz recomendada es la de accessors. ---
    LazyFact<ir::LivenessResult> live;   ///< Tipo A.
    LazyFact<analysis::LoopFacts> loops; ///< Tipo A.
    LazyFact<analysis::ProfileFacts>
        profile; ///< Tipo B (vacio si no hay perfil).
    LazyFact<std::vector<ValueRequirements>> values; ///< requisitos por valor.
    LazyFact<analysis::RematFacts>
        remat; ///< Tipo A (recomputabilidad + receta).
    LazyFact<analysis::UseDefFacts> use_def; ///< Tipo A (next-use por valor).
    // Futuro: LazyFact<analysis::DomFacts> dom;  LazyFact<analysis::AliasFacts>
    // alias; ...

    /** @brief True si el hecho @p f ya esta materializado en su celda. */
    bool is_computed(Fact f) const noexcept {
        switch (f) {
        case Fact::Liveness: return live.ready();
        case Fact::Loops: return loops.ready();
        case Fact::Profile: return profile.ready();
        case Fact::Values: return values.ready();
        case Fact::Remat: return remat.ready();
        case Fact::UseDef: return use_def.ready();
        default: return false;
        }
    }

    // --- QUERY SYSTEM (lazy + cache).  El snapshot NO conoce los algoritmos:
    // el
    //     query<T>() generico pide el Fact a su celda LazyFact<T> y, si falta,
    //     al productor REGISTRADO QueryProducer<T> (donde vive
    //     compute_*/assemble_*). Las dependencias se resuelven SOLAS: produce()
    //     llama a otros query<U>(). ---

    /** @brief Celda @c LazyFact<T> de este snapshot (mapeo tipo ->
     * almacenamiento). Especializada fuera de la clase por cada Fact
     * registrado. */
    template <typename T> const LazyFact<T> &cell() const;

    /**
     * @brief Consulta un Fact @c T: cache-hit en su celda, o lo PRODUCE via el
     *        @c QueryProducer<T> registrado (demand-driven).  El snapshot no
     *        menciona ningun algoritmo -> DATO desacoplado de MECANISMO.
     */
    template <typename T> const T &query() const {
        return cell<T>().get([&] { return QueryProducer<T>::produce(*this); });
    }

    // --- Accessors de conveniencia (azucar sobre query<T>(); nombres
    // estables). ---
    /** @brief Intervalos de vida. */
    const ir::LivenessResult &liveness() const {
        return query<ir::LivenessResult>();
    }
    /** @brief LoopFacts. */
    const analysis::LoopFacts &loop_facts() const {
        return query<analysis::LoopFacts>();
    }
    /** @brief ProfileFacts (vacio si no hay perfil). */
    const analysis::ProfileFacts &profile_facts() const {
        return query<analysis::ProfileFacts>();
    }
    /** @brief ValueRequirements (arrastra liveness + loops + profile). */
    const std::vector<ValueRequirements> &value_reqs() const {
        return query<std::vector<ValueRequirements>>();
    }
    /** @brief RematFacts (recomputabilidad + receta por valor; IR-driven). */
    const analysis::RematFacts &remat_facts() const {
        return query<analysis::RematFacts>();
    }
    /** @brief UseDefFacts (posiciones de uso -> next-use por valor; IR-driven).
     */
    const analysis::UseDefFacts &use_def_facts() const {
        return query<analysis::UseDefFacts>();
    }

    /**
     * @struct ValidationReport
     * @brief Resultado de la autocertificacion agregada (DATOS).
     */
    struct ValidationReport {
        std::vector<analysis::FactIssue>
            fact_issues; ///< de Loop/Profile/Liveness.
        std::vector<RequirementIssue> value_issues; ///< valores imposibles.
        bool ok() const noexcept {
            return fact_issues.empty() && value_issues.empty();
        }
    };

    /**
     * @brief AUDITA el snapshot: autocertifica cada Fact + comprueba que ningun
     *        valor es imposible en @p bank.  El compilador auditandose (fuerza
     *        el computo de los hechos que audita).
     */
    ValidationReport validate(const PhysicalRegisterBank &bank,
                              bool vec_reduction_active = false) const {
        ValidationReport rep;
        for (const analysis::FactIssue &i : analysis::validate(loop_facts()))
            rep.fact_issues.push_back(i);
        for (const analysis::FactIssue &i : analysis::validate(profile_facts()))
            rep.fact_issues.push_back(i);
        for (const ir::LiveInterval &iv : liveness().intervals)
            if (iv.def > iv.end)
                rep.fact_issues.push_back(
                    {analysis::FactCheck::LIVE_DEF_AFTER_END, iv.id, 0});
        rep.value_issues =
            audit_requirements(value_reqs(), bank, vec_reduction_active);
        return rep;
    }
};

// ===========================================================================
//  RECETA -- anadir un Fact NUEVO (patron de 4 puntos; el mecanismo no cambia).
//  Ejemplo real que seguir: RematFacts (busca "Remat" en este archivo).
//    1. Una celda LazyFact<T> como miembro de FunctionSnapshot (seccion de
//       celdas) + su bit en el enum Fact + su case en is_computed().
//    2. La especializacion cell<T>() -> devuelve esa celda (mapeo
//    tipo->almacen).
//    3. La especializacion QueryProducer<T>::produce(snap) -> AQUI el
//    algoritmo;
//       para sus dependencias llama a snap.query<U>() (el grafo emerge solo).
//    4. (Opcional) un accessor nombrado como azucar sobre query<T>().
//  query<T>() y los consumidores NO se tocan.  Pedir un T sin los pasos 2+3 es
//  un ERROR DE COMPILACION (el primario QueryProducer<T> no tiene definicion),
//  nunca un fallo silencioso.
// ===========================================================================

// ---------------------------------------------------------------------------
//  Mapeo tipo -> celda (cell<T>): parte del ALMACENAMIENTO del snapshot.  Es la
//  unica pieza que conoce que miembro guarda cada Fact; el resto es generico.
// ---------------------------------------------------------------------------
template <>
inline const LazyFact<ir::LivenessResult> &
FunctionSnapshot::cell<ir::LivenessResult>() const {
    return live;
}
template <>
inline const LazyFact<analysis::LoopFacts> &
FunctionSnapshot::cell<analysis::LoopFacts>() const {
    return loops;
}
template <>
inline const LazyFact<analysis::ProfileFacts> &
FunctionSnapshot::cell<analysis::ProfileFacts>() const {
    return profile;
}
template <>
inline const LazyFact<std::vector<ValueRequirements>> &
FunctionSnapshot::cell<std::vector<ValueRequirements>>() const {
    return values;
}
template <>
inline const LazyFact<analysis::RematFacts> &
FunctionSnapshot::cell<analysis::RematFacts>() const {
    return remat;
}
template <>
inline const LazyFact<analysis::UseDefFacts> &
FunctionSnapshot::cell<analysis::UseDefFacts>() const {
    return use_def;
}

// ---------------------------------------------------------------------------
//  Productores registrados por tipo (QueryProducer<T>): AQUI vive el ALGORITMO.
//  El snapshot no los conoce; solo llama query<T>() ->
//  QueryProducer<T>::produce. Las dependencias se resuelven SOLAS (produce
//  llama a s.query<U>()).
// ---------------------------------------------------------------------------
template <> struct QueryProducer<ir::LivenessResult> {
    static ir::LivenessResult produce(const FunctionSnapshot &s) {
        return ir::compute_liveness(*s.fn);
    }
};
template <> struct QueryProducer<analysis::LoopFacts> {
    static analysis::LoopFacts produce(const FunctionSnapshot &s) {
        return analysis::compute_loop_facts(*s.fn);
    }
};
template <> struct QueryProducer<analysis::ProfileFacts> {
    static analysis::ProfileFacts produce(const FunctionSnapshot &s) {
        if (s.prof && !s.prof->empty())
            return analysis::compute_profile_facts(
                *s.fn, s.query<analysis::LoopFacts>(), *s.prof);
        return analysis::ProfileFacts{};
    }
};
template <> struct QueryProducer<std::vector<ValueRequirements>> {
    static std::vector<ValueRequirements> produce(const FunctionSnapshot &s) {
        std::vector<uint32_t> calls =
            collect_call_positions(*s.fn, s.query<ir::LivenessResult>());
        return assemble_value_requirements(
            *s.fn, s.query<ir::LivenessResult>(), calls,
            s.query<analysis::LoopFacts>(), s.query<analysis::ProfileFacts>());
    }
};
template <> struct QueryProducer<analysis::RematFacts> {
    static analysis::RematFacts produce(const FunctionSnapshot &s) {
        return analysis::compute_remat_facts(*s.fn);
    }
};
template <> struct QueryProducer<analysis::UseDefFacts> {
    static analysis::UseDefFacts produce(const FunctionSnapshot &s) {
        return analysis::compute_use_def(*s.fn);
    }
};

} // namespace rbank
} // namespace codegen

#endif // VESTA_CODEGEN_RBANK_FUNCTION_SNAPSHOT_H
