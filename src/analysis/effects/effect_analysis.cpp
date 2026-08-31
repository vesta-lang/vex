/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file effect_analysis.cpp
 * @brief Esqueleto del gestor de analisis de efectos (Fase 0).  Cache local por
 *        nodo + summaries por funcion + invalidacion.  El mapeo real IrOp ->
 *        SemanticEffects (local) llega en Fase 1; el punto-fijo del callgraph
 *        (summary) en Fase 2.  Aqui devolvemos valores NEUTROS Complete para no
 *        alterar comportamiento (  cero regresion).
 */
#include "util/env_flags.h"
#include "analysis/effects/effect_analysis.h"

#include "analysis/facts/value_range.h"

#include "ir/ssa_ir.h"
#include "analysis/effects/ir_effects.h"
#include "analysis/escape/escape.h"
#include "aot/aot_analyze.h" // que necesita cada op para correr (backend AOT)

#include <chrono>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <unordered_set>
#include <utility>

namespace analysis {
namespace effects {

const IrFacts &EffectAnalysis::facts_of(const ir::IrFunction &fn) {
    // Hechos fundacionales cacheados por el AnalysisManager: se computan una
    // vez por funcion y se reusan (antes se reconstruian en cada consulta local
    // -> O(n^2) por funcion; ahora O(n)).
    return facts_mgr_.get_or_compute<IRFactsAnalysis, IrFacts>(
        fn.name, [&]() { return build_ir_facts(fn); });
}

const RangeFacts &EffectAnalysis::ranges_of(const ir::IrFunction &fn) {
    // Otro hecho fundacional cacheado por el gestor: un productor, muchos
    // consumidores (points-to lo usa para acotar; el comprobador de limites,
    // para juzgar).
    /* El PUNTERO, no una copia: ver la nota de `ranges_of` en el optimizador.
     * `RangeFacts` lleva dentro el estado de entrada de cada bloque, y debajo
     * ya existe una sola instancia en la cache por dependencias. */
    return *facts_mgr_.get_or_compute<RangeAnalysis,
                                      std::shared_ptr<const RangeFacts>>(
        fn.name, [&]() {
            /* Con los resumenes si alguien los dio.  Es lo que convierte esto
             * en el unico productor: quien necesita rangos acotados por lo que
             * cruza las fronteras -- el comprobador de limites -- ya no tiene
             * que calcularse los suyos aparte.  Y de paso points-to trabaja con
             * rangos mas estrechos, que solo puede mejorar lo que distingue. */
            return compute_ranges_ptr(fn, facts_of(fn), RangeOptions{},
                                      resumenes_);
        });
}

const PointsTo &EffectAnalysis::points_to_of(const ir::IrFunction &fn) {
    // Tabla points-to cacheada; su factory consume facts_of (via el manager),
    // registrando la dependencia PointsTo -> IRFacts para la invalidacion.
    /* Con los RANGOS: un desplazamiento variable deja de ser "en algun sitio"
     * y pasa a ser un intervalo.  Se piden por el mismo gestor, asi que se
     * calculan una vez por funcion y los comparte quien los necesite. */
    return facts_mgr_.get_or_compute<PointsToAnalysis, PointsTo>(
        fn.name, [&]() {
            const IrFacts &f = facts_of(fn);
            const RangeFacts &rg = ranges_of(fn);
            return compute_points_to(fn, f, &rg);
        });
}

EffectAnalysisResult EffectAnalysis::local(const ir::IrFunction &fn,
                                           const ir::IrInstr &ins) {
    const void *key = static_cast<const void *>(&ins);
    auto it = local_cache_.find(key);
    if (it != local_cache_.end()) return it->second;
    EffectAnalysisResult r =
        effects_of_instr(fn, facts_of(fn), points_to_of(fn), ins, env_);
    local_cache_.emplace(key, r);
    return r;
}

EfectoEnLlamada EffectAnalysis::at_call_site(const ir::IrFunction &caller,
                                             const ir::IrInstr &call) {
    EfectoEnLlamada r;
    if (call.op != ir::IrOp::CALL && call.op != ir::IrOp::TAILCALL &&
        call.op != ir::IrOp::CALLN) {
        r.completo = false;
        return r;
    }
    if (call.func_name.empty()) {
        r.completo = false;
        return r;
    }

    /* El cierre del destino.  Se busca en lo que ya se calculo: primero el
     * programa (varios modulos) y si no el modulo.  Sin resumen no hay nada que
     * instanciar -- una funcion de fuera del programa no dice lo que hace --, y
     * eso lo trata quien pregunta como lo que es: falta de conocimiento, no
     * ausencia de efecto. */
    const FunctionSummary *s = nullptr;
    auto buscar = [&](const ModuleSummary &ms) {
        auto it = ms.fns.find(call.func_name);
        if (it != ms.fns.end())
            s = &it->second;
        else {
            // Una nativa se nombra "lib:fn" y tambien "fn" a secas.
            const size_t sep = call.func_name.rfind(':');
            if (sep != std::string::npos && sep + 1 < call.func_name.size()) {
                it = ms.fns.find(call.func_name.substr(sep + 1));
                if (it != ms.fns.end()) s = &it->second;
            }
        }
    };
    buscar(program_cache_);
    if (s == nullptr) buscar(module_cache_);
    if (s == nullptr) {
        r.completo = false; // no hay resumen: no se sabe lo que hace.
        return r;
    }

    /* Se traduce el CIERRE: lo que la funcion hace por si misma y lo que hacen
     * las que llama.
     *
     * Se puede porque el cierre ya viene en terminos de los parametros de ESTA
     * funcion: al construirlo, lo que aporta cada callee se traduce con los
     * argumentos de su sitio de llamada.  Antes no era asi -- se copiaban los
     * `arg#N` del callee tal cual, que son los suyos, no los de aqui -- y por
     * eso esto miraba solo el efecto propio: lo unico entonces interpretable.
     *
     * Con el cierre, lo que hace una funcion tres niveles mas abajo llega hasta
     * el sitio donde se puede juzgar. */
    r = instanciar_en_llamada(s->semantic.closure, call.operands,
                              points_to_of(caller));
    /* Un resumen que ya venia incompleto no se vuelve completo por traducirlo:
     * lo que no se supo alli sigue sin saberse aqui. */
    if (s->completeness != AnalysisCompleteness::Complete) r.completo = false;
    return r;
}

// Extrae la faceta ESTRUCTURAL de una funcion (bloques, back-edges = bucles,
// recursion directa).  El detalle de trip-counts (para Big-O) lo afina el
// subsistema de coste; aqui damos la forma.
static StructuralSummary structural_of(const ir::IrFunction &fn) {
    StructuralSummary st;
    st.block_count = static_cast<uint32_t>(fn.blocks.size());
    // Back-edge = arista a un bloque de indice <= el actual (aproximacion de
    // bucle sobre el orden de bloques).  Recursion directa = se llama a si
    // misma.
    for (uint32_t bi = 0; bi < fn.blocks.size(); ++bi) {
        for (const ir::IrInstr &in : fn.blocks[bi].instrs) {
            auto is_back = [&](ir::IrBlockId t) {
                return t != ir::IR_NO_BLOCK && t <= bi;
            };
            if (in.op == ir::IrOp::BR) {
                if (is_back(in.target_block)) ++st.loop_count;
            } else if (in.op == ir::IrOp::BR_COND) {
                if (is_back(in.target_block) || is_back(in.false_block))
                    ++st.loop_count;
            } else if (in.op == ir::IrOp::SWITCH_DENSE ||
                       in.op == ir::IrOp::MATCH_VARIANT) {
                for (uint32_t t : in.jump_targets)
                    if (is_back(t)) {
                        ++st.loop_count;
                        break;
                    }
            }
            if ((in.op == ir::IrOp::CALL || in.op == ir::IrOp::TAILCALL) &&
                in.func_name == fn.name)
                st.recursive = true;
        }
    }
    if (st.loop_count > 0)
        st.has_unbounded_loop = true; // conservador sin trip-count
    return st;
}

FunctionSummary EffectAnalysis::compute_summary(const ir::IrModule & /*mod*/,
                                                const ir::IrFunction &fn) {
    // Summary SIN cierre (se usa como fallback; el cierre real lo calcula
    // module_summary por punto-fijo).  compute_summary se mantiene para el
    // acceso por-funcion aislado.
    FunctionSummary s;
    s.symbol = fn.name;
    EffectAnalysisResult loc = function_local_effects(fn);
    s.semantic.local = loc.effects;
    s.semantic.closure =
        loc.effects; // sin interproc; module_summary lo completa
    s.structural = structural_of(fn);
    s.completeness = loc.completeness;
    return s;
}

const FunctionSummary &EffectAnalysis::summary(const ir::IrModule &mod,
                                               const ir::IrFunction &fn) {
    auto d = dirty_.find(fn.name);
    const bool is_dirty = (d == dirty_.end()) || d->second;
    auto it = summary_cache_.find(fn.name);
    if (!is_dirty && it != summary_cache_.end()) return it->second;
    FunctionSummary s = compute_summary(mod, fn);
    dirty_[fn.name] = false;
    auto res = summary_cache_.insert_or_assign(fn.name, std::move(s));
    return res.first->second;
}

// Callees de una funcion: nombres estaticos (CALL/TAILCALL) + si hace alguna
// llamada DINAMICA/nativa (callee desconocido -> el cierre toma el efecto TOP
// robusto: puede hacer cualquier cosa, con el motivo registrado para el
// reporte).
namespace {
struct CallInfo {
    /**
     * @brief Los SITIOS de llamada, con sus argumentos.
     *
     * El cierre se calcula por NOMBRE, y por nombre no se puede traducir lo que
     * el llamado dice de sus parametros: `arg#1` de el no es `arg#1` de quien
     * llama.  Con los argumentos de CADA sitio si -- y es lo que hace que lo
     * que toca una funcion de tres niveles abajo llegue arriba hablando de la
     * memoria de aqui, en vez de perderse en "toca algo".
     */
    struct Sitio {
        std::string callee;
        std::vector<ir::IrValueId> args;
    };
    std::vector<Sitio> sitios;
    /// La funcion donde estan esos sitios, para resolver sus argumentos.
    const ir::IrFunction *fn = nullptr;

    std::vector<std::string> static_callees;
    bool dynamic = false; // CALLVIRT/CALLIND/CALLN/...
    /// En AOT, una op que depende del runtime ES una llamada a libvesta_rt.
    /// No es un callee desconocido -- el helper hace exactamente esa op, y su
    /// efecto ya esta modelado --, pero la funcion deja de ser hoja.
    bool runtime = false;
    /// Llamadas NATIVAS por su nombre completo "lib:fn".  Van aparte porque
    /// resuelven en DOS pasos (ver el cierre): el nombre completo y, si no
    /// esta, el simbolo a secas -- que es como acaba llamandose cuando la
    /// implementacion resulta ser codigo del propio lenguaje.
    std::vector<std::string> native_callees;
};
CallInfo callees_of(const ir::IrFunction &fn, const EffectEnv &env) {
    CallInfo ci;
    ci.fn = &fn;
    const NativeDecls *decls = env.decls;
    for (const ir::IrBlock &b : fn.blocks)
        for (const ir::IrInstr &in : b.instrs) {
            if (env.backend == Backend::Aot &&
                ::aot::aot_classify_op(in.op) ==
                    ::aot::AotOpClass::RUNTIME_DEPENDENT)
                ci.runtime = true;
            switch (in.op) {
            case ir::IrOp::CALL:
            case ir::IrOp::TAILCALL:
                if (!in.func_name.empty()) {
                    ci.static_callees.push_back(in.func_name);
                    ci.sitios.push_back({in.func_name, in.operands});
                } else {
                    ci.dynamic = true;
                }
                break;
            /* Una llamada NATIVA con nombre se resuelve como cualquier otra: si
             * la funcion esta en el programa, se ANALIZA -- no se dan por
             * supuestas sus capacidades ni se espera a que alguien las declare.
             * Solo cuando el destino no aparece (codigo verdaderamente ajeno)
             * el cierre sube al efecto maximo, que es donde ya lo hace.
             *
             * Antes se marcaba dinamica SIEMPRE, asi que aunque el destino
             * estuviera delante, su resumen no se miraba nunca. */
            case ir::IrOp::CALLN:
                /* Si alguien DIJO lo que hace, ya esta contado: el efecto
                 * declarado se aplico en el sitio de llamada, con su memoria
                 * resuelta.  Anadirla como callee ausente la volveria a subir
                 * al efecto maximo y la declaracion no habria servido de nada.
                 */
                if (decls && decls->count(in.func_name)) break;
                if (!in.func_name.empty())
                    ci.native_callees.push_back(in.func_name);
                else
                    ci.dynamic = true;
                break;
            case ir::IrOp::CALLVIRT:
            case ir::IrOp::CALLM:
            case ir::IrOp::CALLITF:
            case ir::IrOp::CALLCLOSURE:
            case ir::IrOp::CALLIND: ci.dynamic = true; break;
            default: break;
            }
        }
    return ci;
}
/// Busca la implementacion de una nativa "lib:fn" entre las funciones del
/// programa: primero por el nombre completo, luego por el simbolo a secas.
/// nullptr = no esta, y entonces si es codigo ajeno.
const FunctionSummary *resolver_nativa(const ModuleSummary &ms,
                                       const std::string &lib_fn) {
    auto it = ms.fns.find(lib_fn);
    if (it != ms.fns.end()) return &it->second;
    const size_t sep = lib_fn.rfind(':');
    if (sep == std::string::npos || sep + 1 >= lib_fn.size()) return nullptr;
    it = ms.fns.find(lib_fn.substr(sep + 1));
    return it == ms.fns.end() ? nullptr : &it->second;
}

/**
 * @brief Une el cierre del callee en el del caller.
 *
 * Lo que el callee dice de SUS parametros no significa nada aqui: `arg#1` es el
 * primero de EL, no del que llama, y copiarlo tal cual hace que una funcion de
 * tres parametros acabe afirmando que escribe en su `arg#6`.  No es impreciso,
 * es falso -- y se estaba imprimiendo en el informe.
 *
 * Traducirlo requiere los ARGUMENTOS, que solo existen en el sitio de llamada;
 * este cierre se calcula por NOMBRE, asi que aqui lo unico honesto es decir que
 * toca memoria sin saber cual.  Quien quiera la version traducida la pide donde
 * se puede dar: @ref EffectAnalysis::at_call_site.
 */
void merge_callee(SemanticEffects &caller, const SemanticEffects &callee) {
    SemanticEffects c = callee;
    auto despersonalizar = [](LocSet &s) {
        if (s.is_top) return;
        bool hay_arg = false;
        for (const AbstractLoc &l : s.locs)
            if (l.kind == AbstractLoc::Kind::ArgDerived) hay_arg = true;
        if (!hay_arg) return;
        LocSet out;
        for (const AbstractLoc &l : s.locs) {
            if (l.kind == AbstractLoc::Kind::ArgDerived) {
                // Sus parametros no se pueden nombrar desde aqui.
                out.add(AbstractLoc{AbstractLoc::Kind::Unknown, LOC_GENERIC});
                continue;
            }
            out.add(l);
        }
        s = std::move(out);
    };
    despersonalizar(c.mem.reads);
    despersonalizar(c.mem.writes);
    caller = join(caller, c);
}

// Filtra de un LocSet las Stack locs cuya raiz NO escapa (scratch LOCAL, no
// observable por el caller).  El resto (Stack escapante, Heap, Global,
// ArgDerived, Unknown/top) se conserva.
LocSet filter_local_stack(const LocSet &s, const analysis::EscapeInfo &esc) {
    if (s.is_top) return s;
    LocSet out;
    for (const AbstractLoc &l : s.locs) {
        if (l.kind == AbstractLoc::Kind::Stack && l.id != LOC_GENERIC &&
            !esc.stack_escapes(l.id))
            continue; // scratch local -> no observable
        out.add(l);
    }
    return out;
}
// Aplica el filtro a reads + writes de un SemanticEffects (el efecto OBSERVABLE
// por el caller).  may_*/control/tags/determinism se conservan.
SemanticEffects observable_effect(SemanticEffects e,
                                  const analysis::EscapeInfo &esc) {
    e.mem.reads = filter_local_stack(e.mem.reads, esc);
    e.mem.writes = filter_local_stack(e.mem.writes, esc);
    return e;
}
} // namespace

ModuleSummary
EffectAnalysis::build_summary(const std::vector<const ir::IrModule *> &mods) {
    ModuleSummary out;

    /* Reparto del coste, por fases.  Se publica con VESTA_TIMES porque "el
     * analisis tarda" no se puede atacar sin saber cual de las cuatro es. */
    const bool medir = util::flag_on(util::FlagId::Times);
    using RelojFase = std::chrono::steady_clock;
    auto marca = RelojFase::now();
    long us_escape = 0, us_local = 0, us_punto_fijo = 0, us_nativas = 0;
    long n_fns = 0, n_pasos = 0;
    auto cerrar = [&](long &destino) {
        const auto ahora = RelojFase::now();
        destino += static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(ahora - marca)
                .count());
        marca = ahora;
    };

    // Recorre TODAS las funciones de TODOS los modulos (interproc
    // cross-modulo).
    auto for_each_fn = [&](auto &&f) {
        for (const ir::IrModule *m : mods)
            if (m)
                for (const ir::IrFunction &fn : m->functions)
                    f(fn);
    };

    // 0) EscapeAnalysis del programa: que Stack roots locales escapan (sus
    //    escrituras SI son observables por el caller).  Provee la base de
    //    hechos via el manager (facts_of/points_to_of), no la construye aqui.
    //    Para varios modulos se computa por-modulo (un callee de otro modulo se
    //    trata como externo = captura, sound).
    std::unordered_map<std::string, analysis::EscapeInfo> escape_all;
    {
        auto facts_fn = [this](const ir::IrFunction &fn) -> const IrFacts & {
            return facts_of(fn);
        };
        auto pt_fn =
            [this](const ir::IrFunction &fn) -> const analysis::PointsTo & {
            return points_to_of(fn);
        };
        for (const ir::IrModule *m : mods) {
            if (!m) continue;
            auto em = analysis::compute_escape_module(*m, facts_fn, pt_fn);
            for (auto &kv : em)
                escape_all[kv.first] = std::move(kv.second);
        }
    }
    cerrar(us_escape);

    // 1) Summary LOCAL de cada funcion (efecto propio, estructura) + lagunas.
    //    Antes se recogen las declaraciones de nativas: son parte de la entrada
    //    del analisis local (una nativa declarada aporta su efecto exacto ahi
    //    mismo, no una laguna).
    native_decls_ = collect_native_decls(mods);
    env_.decls = &native_decls_;
    gaps_ = EffectGaps{};
    std::unordered_map<std::string, CallInfo> calls;
    // El efecto/completeness LOCAL se preserva aparte: el cierre (paso 2) se
    // recomputa SIEMPRE desde el local + callees (idempotente para el
    // worklist).
    std::unordered_map<std::string, SemanticEffects> local_eff;
    std::unordered_map<std::string, AnalysisCompleteness> local_comp;
    for_each_fn([&](const ir::IrFunction &fn) {
        /* Los rangos de la funcion, UNA vez.  Sin esto, cada bloque de asm los
         * recalcula recorriendo la funcion entera desde dentro del modelo de
         * efectos -- el mismo derroche que ya se cerro en el eliminador de
         * codigo muerto y en el analisis de limites; este era el tercer sitio.
         * Salen de la cache si algun otro consumidor ya los pidio. */
        // Solo si hay asm: es lo unico que los mira.  Ver funcion_tiene_asm.
        if (funcion_tiene_asm(fn)) {
            env_.rangos = &ranges_of(fn); // el accesor cacheado de la clase
            env_.rangos_de = &fn;
        }
        /* Se retiran al salir: prestados a la SIGUIENTE funcion serian una
         * respuesta incorrecta en silencio.  El dueno anotado ya lo impide,
         * pero dejar el puntero colgando a unos rangos que mueren aqui, no. */
        struct Retirar {
            EffectEnv &e;
            ~Retirar() {
                e.rangos = nullptr;
                e.rangos_de = nullptr;
            }
        } retirar{env_};
        EffectAnalysisResult loc = function_local_effects(fn, &gaps_, env_);
        FunctionSummary s;
        s.symbol = fn.name;
        s.semantic.local = loc.effects; // CRUDO (lo muestra --analyze "local")
        // El cierre parte del efecto OBSERVABLE: sin las escrituras/lecturas a
        // Stack scratch LOCAL (no las ve el caller) -> una reduccion que
        // escribe solo Stack#acc_slot pasa a readonly.
        SemanticEffects obs =
            observable_effect(loc.effects, escape_all[fn.name]);
        s.semantic.closure = obs;
        s.structural = structural_of(fn);
        s.completeness = loc.completeness;
        calls[fn.name] = callees_of(fn, env_);
        s.interproc.reaches_dynamic_call = calls[fn.name].dynamic;
        s.interproc.has_calls = calls[fn.name].dynamic ||
                                calls[fn.name].runtime ||
                                !calls[fn.name].static_callees.empty();
        local_eff[fn.name] =
            obs; // OBSERVABLE (sin scratch local) = semilla del cierre
        local_comp[fn.name] = loc.completeness;
        out.fns.emplace(fn.name, std::move(s));
        ++n_fns;
    });
    cerrar(us_local);

    // 2) Punto-fijo EFICIENTE por WORKLIST (dataflow interprocedural clasico):
    //    closure(fn) = local(fn) U closure(callee) para cada callee.  Solo se
    //    re-procesa una funcion cuando el cierre de ALGUN callee suyo cambia
    //    -> O(aristas del callgraph x altura del reticulo), NO O(n^2).  Un
    //    callee ausente del mapa (externo al PROGRAMA / dinamico / nativo) hace
    //    el cierre CONSERVADOR (TOP robusto).  Con varios modulos, un callee de
    //    otro modulo SI esta en el mapa -> se resuelve (interproc
    //    cross-modulo).
    // Reverse-callgraph: callee -> callers (para re-encolar dependientes).
    std::unordered_map<std::string, std::vector<std::string>> callers;
    for (const auto &kv : calls) {
        for (const std::string &callee : kv.second.static_callees)
            callers[callee].push_back(kv.first);
        /* Las nativas cuentan igual: si su implementacion esta en el programa,
         * cuando su cierre cambie hay que volver a mirar a quien la llama.  Por
         * los DOS nombres, que no se sabe todavia cual resolvera. */
        for (const std::string &callee : kv.second.native_callees) {
            callers[callee].push_back(kv.first);
            const size_t sep = callee.rfind(':');
            if (sep != std::string::npos && sep + 1 < callee.size())
                callers[callee.substr(sep + 1)].push_back(kv.first);
        }
    }

    // Recomputa el cierre de una funcion desde su local + los cierres de
    // callees. Devuelve true si cambio (para propagar a sus callers).
    auto recompute = [&](const std::string &name) -> bool {
        FunctionSummary &s = out.fns[name];
        SemanticEffects nc = local_eff[name];
        AnalysisCompleteness comp = local_comp[name];
        const CallInfo &ci = calls[name];
        auto raise = [&] {
            if (comp == AnalysisCompleteness::Complete)
                comp = AnalysisCompleteness::Conservative;
        };
        if (ci.dynamic) {
            nc = join(nc, SemanticEffects::top());
            raise();
        }
        /* Lo que hace cada llamada, TRADUCIDO a la memoria de aqui.
         *
         * Por nombre no se puede: `arg#1` del llamado no es `arg#1` de quien
         * llama.  Con los argumentos del SITIO si, y eso es lo que hace que un
         * `memcpy` que reparte a una variante interna siga diciendo, tres
         * niveles mas arriba, que escribe en lo que le pasaron -- en vez de
         * perderse en "toca algo".
         *
         * Lo que no se pueda traducir (la pila del llamado, su monton) sube a
         * desconocido, que es lo unico cierto: aqui esos nombres no significan
         * nada. */
        for (const CallInfo::Sitio &sitio : ci.sitios) {
            auto it = out.fns.find(sitio.callee);
            if (it == out.fns.end()) {
                /* El destino NO esta en el programa: es codigo ajeno de verdad
                 * y no hay nada que analizar, asi que efecto maximo.  Se apunta
                 * su NOMBRE, que es lo unico que permite hacer algo al
                 * respecto -- traerlo al analisis o declarar sus efectos. */
                nc = join(nc, SemanticEffects::top());
                raise();
                continue;
            }
            const SemanticEffects &ce = it->second.semantic.closure;
            if (ci.fn != nullptr) {
                const EfectoEnLlamada e =
                    instanciar_en_llamada(ce, sitio.args, points_to_of(*ci.fn));
                SemanticEffects trad = ce;
                trad.mem.reads = e.lee;
                trad.mem.writes = e.escribe;
                if (!e.completo) {
                    // Habia algo que no se pudo nombrar: se dice, sin tirar lo
                    // demas por el camino equivocado -- el join lo absorbera si
                    // hace falta.
                    trad.mem.reads.add(
                        AbstractLoc{AbstractLoc::Kind::Unknown, LOC_GENERIC});
                    trad.mem.writes.add(
                        AbstractLoc{AbstractLoc::Kind::Unknown, LOC_GENERIC});
                }
                nc = join(nc, trad);
            } else {
                merge_callee(nc, ce);
            }
            if (uint8_t(it->second.completeness) > uint8_t(comp))
                comp = it->second.completeness;
        }
        /* Las nativas, en dos pasos: "lib:fn" y, si no esta, "fn" a secas.  El
         * segundo no es un apano: es como se llama la funcion cuando la
         * implementacion resulta ser codigo del lenguaje -- el usuario redefine
         * una primitiva en Vesta, o en nativo el runtime de I/O se trae de
         * `vx_io.vx` y esas CALLN acaban siendo CALL a sus funciones.  Si esta
         * delante hay que analizarla, no darla por ajena. */
        for (const std::string &callee : ci.native_callees) {
            const FunctionSummary *cs = resolver_nativa(out, callee);
            if (!cs) {
                nc = join(nc, SemanticEffects::top());
                raise();
                continue;
            }
            merge_callee(nc, cs->semantic.closure);
            if (uint8_t(cs->completeness) > uint8_t(comp))
                comp = cs->completeness;
        }
        /* TOPE.  Traducir en cada sitio hace que una funcion recursiva sobre
         * punteros genere una posicion nueva por vuelta -- `f(p+8)` da p+0,
         * p+8, p+16... -- y el punto fijo dejaria de terminar.  Pasado el tope
         * se colapsan las de una misma raiz a "el objeto entero": se pierde
         * precision, no correccion, y el calculo termina.  Es el limite
         * DECLARADO que cualquier analisis con punto fijo necesita. */
        {
            constexpr size_t kTopeLocs = 64;
            auto podar = [](LocSet &s) {
                if (s.is_top || s.locs.size() <= kTopeLocs) return;
                LocSet out;
                for (const AbstractLoc &l : s.locs)
                    out.add(AbstractLoc{l.kind, l.id, 0, 0}); // toda la raiz
                s = std::move(out);
            };
            podar(nc.mem.reads);
            podar(nc.mem.writes);
        }
        if (!(nc == s.semantic.closure) || comp != s.completeness) {
            s.semantic.closure = nc;
            s.completeness = comp;
            return true;
        }
        return false;
    };

    std::deque<std::string> work;
    std::unordered_set<std::string> in_work;
    for (const auto &kv : out.fns) {
        work.push_back(kv.first);
        in_work.insert(kv.first);
    }
    while (!work.empty()) {
        std::string name = std::move(work.front());
        work.pop_front();
        in_work.erase(name);
        ++n_pasos;
        if (recompute(name)) {
            // El cierre de 'name' cambio -> sus callers pueden cambiar.
            auto cit = callers.find(name);
            if (cit != callers.end())
                for (const std::string &caller : cit->second)
                    if (in_work.insert(caller).second) work.push_back(caller);
        }
    }

    cerrar(us_punto_fijo);

    /* Ya convergido, se apunta UNA vez cada llamada a codigo que no esta en el
     * programa.  Hacerlo dentro del punto fijo contaba la misma llamada tantas
     * veces como vueltas diera. */
    for (const auto &kv : calls) {
        for (const std::string &callee : kv.second.static_callees)
            if (out.fns.find(callee) == out.fns.end())
                gaps_.record_nativa(callee);
        for (const std::string &callee : kv.second.native_callees)
            if (!resolver_nativa(out, callee)) gaps_.record_nativa(callee);
    }
    cerrar(us_nativas);
    if (medir)
        std::cerr << "[efectos] " << n_fns << " funciones, " << n_pasos
                  << " pasos del punto fijo | escape " << us_escape
                  << " us | local " << us_local << " us | punto-fijo "
                  << us_punto_fijo << " us | nativas " << us_nativas << " us\n";
    return out;
}

const ModuleSummary &EffectAnalysis::module_summary(const ir::IrModule &mod) {
    if (!module_dirty_) return module_cache_;
    module_cache_ = build_summary({&mod});
    module_dirty_ = false;
    return module_cache_;
}

const ModuleSummary &
EffectAnalysis::program_summary(const std::vector<const ir::IrModule *> &mods) {
    // Interprocedural a nivel de PROGRAMA (varios modulos).  No se cachea por
    // dirty (se recomputa: se invoca puntualmente para el analisis
    // whole-program).
    program_cache_ = build_summary(mods);
    return program_cache_;
}

void EffectAnalysis::invalidate_node(const ir::IrFunction &fn,
                                     const ir::IrInstr &ins) {
    local_cache_.erase(static_cast<const void *>(&ins));
    invalidate_function(fn.name);
}

void EffectAnalysis::invalidate_function(const std::string &fn_name) {
    dirty_[fn_name] = true;
    module_dirty_ = true;
    // Los hechos (def-use/CFG) de la funcion cambiaron -> invalidar en el
    // manager para que se recomputen la proxima vez que se pidan.
    facts_mgr_.invalidate<IRFactsAnalysis>(fn_name);
    // TODO: propagar a los callers transitivos por el callgraph (SCC) cuando el
    // cierre interprocedural se cachee por-funcion (hoy module_summary lo
    // rehace).
}

void EffectAnalysis::clear() {
    local_cache_.clear();
    summary_cache_.clear();
    dirty_.clear();
    module_cache_.fns.clear();
    facts_mgr_.clear(); // invalida los hechos cacheados
    module_dirty_ = true;
}

} // namespace effects
} // namespace analysis
