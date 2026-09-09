/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/effects/param_aliasing.cpp
 * @brief Mirar las llamadas para saber si dos parametros reciben la misma
 *        region.
 *
 * Esto vivia DENTRO del productor de contratos de parametro, que era su unico
 * consumidor.  Al aparecer el segundo -- la comprobacion de prestamos, que
 * necesita lo mismo para cruzarlo con la exclusividad prometida -- dejarlo alli
 * habria significado calcularlo dos veces: dos productores del mismo hecho, y
 * el dia que uno cambiara, el mismo programa juzgado de dos maneras.
 *
 * Al subirlo se le cambiaron dos cosas, y las dos son de COSTE:
 *
 *  1. Se resuelve por ARGUMENTO y no por par.  Por par obliga a recorrer los
 *     sitios una vez por cada uno, y los pares son el cuadrado de los
 *     parametros -- que no estan acotados en el camino nativo --.  Por argumento
 *     es una resolucion por argumento y sitio: sumado, las listas de argumentos
 *     del modulo.
 *  2. Se resuelve la funcion QUE SE PREGUNTA, no el modulo.  Lo demas seria
 *     pagar por todas para contestar por una.
 */

#include "analysis/effects/param_aliasing.h"

#include "analysis/asa/fact_base.h"
#include "analysis/asa/producers.h"
#include "analysis/effects/effect_analysis.h" // el resumen del llamado
#include "analysis/effects/ir_effects.h"      // proyeccion por parametro
#include "analysis/memory/points_to.h"
#include "ir/ssa_ir.h"
#include "util/env_flags.h"

namespace analysis {
namespace effects {

namespace {

/// @brief Ancho de la region que el parametro @p i de @p fn promete tener.
///
/// Sale del contrato, que es donde el lenguaje ya lo deja: un `T[N]` de
/// parametro decae a puntero pero la N no se pierde.  Cero = no se dijo, y
/// entonces la region vale lo que se pueda demostrar sin ella.
int32_t declared_extent(const ir::IrFunction *fn, size_t i) {
    if (fn == nullptr || i >= fn->param_contracts.size()) return 0;
    const int64_t bytes = fn->param_contracts[i].pointee().extent_bytes;
    /* Una extension que no cabe en el ancho se deja en "no se dijo".  Truncarla
     * daria un rango MAS CORTO que el prometido, y con el se podria dar por
     * disjunto lo que no lo es. */
    if (bytes <= 0 || bytes > 0x7FFFFFFF) return 0;
    return static_cast<int32_t>(bytes);
}

/**
 * @brief Se DEMUESTRA que los dos parametros llegan a algun byte comun?
 *
 * Basta UN par de posiciones que se corten.  Con los alcances no hace falta que
 * esten completos: cada byte que llevan es memoria que la llamada alcanza de
 * verdad, asi que uno solo ya prueba el solape.  Sin resumen del llamado se cae
 * al respaldo -- las bases --, que es lo unico que hay entonces.
 */
bool proven_overlap(const ParamReach &a, const ParamReach &b) {
    if (!a.known || !b.known) return must_overlap(a.base, b.base);
    if (a.reached.is_top || b.reached.is_top) return false;
    for (const AbstractLoc &la : a.reached.locs)
        for (const AbstractLoc &lb : b.reached.locs)
            if (must_overlap(la, lb)) return true;
    return false;
}

/**
 * @brief Se DEMUESTRA que no comparten ni un byte?
 *
 * Aqui SI hacen falta completos, y es la asimetria que define esto: para
 * afirmar que dos conjuntos no se tocan hay que tenerlos ENTEROS -- si falta
 * una posicion por nombrar, puede ser justo la que coincide --, mientras que
 * para afirmar que se tocan basta con una que si.
 *
 * Un alcance vacio y completo es la respuesta buena, no un hueco: quiere decir
 * que por ese parametro no se llega a ninguna parte, y entonces no puede chocar
 * con nadie.
 */
bool proven_disjoint(const ParamReach &a, const ParamReach &b) {
    /* El respaldo primero: dos raices distintas ya son disjuntas y no hace
     * falta mirar ningun cuerpo. */
    if (no_alias(a.base, b.base)) return true;
    if (!a.known || !b.known || !a.complete || !b.complete) return false;
    if (a.reached.is_top || b.reached.is_top) return false;
    for (const AbstractLoc &la : a.reached.locs)
        for (const AbstractLoc &lb : b.reached.locs)
            if (may_alias(la, lb)) return false;
    return true;
}

} // namespace

const ir::IrFunction *
ParamAliasing::function_named(const std::string &name) const {
    if (mod_ == nullptr) return nullptr;
    if (by_name_.empty()) {
        by_name_.reserve(mod_->functions.size());
        for (const ir::IrFunction &f : mod_->functions)
            by_name_.emplace(f.name, &f);
    }
    const auto it = by_name_.find(name);
    return it == by_name_.end() ? nullptr : it->second;
}

const std::vector<CallSiteLocs> *
ParamAliasing::sites_of(const std::string &function) const {
    const auto done = resolved_.find(function);
    if (done != resolved_.end()) return &done->second;
    if (walk_ == nullptr || base_ == nullptr) return nullptr;

    const auto it = walk_->calls.find(function);
    if (it == walk_->calls.end()) return nullptr;

    /* El contrato del LLAMADO, una vez para todos sus sitios: es el que dice
     * hasta donde llega la region de cada parametro cuando la firma lo declara
     * (`i64 p[3]`).  Es la mitad DECLARADA; la otra sale del cuerpo, abajo. */
    const ir::IrFunction *callee = function_named(function);

    /* Y el efecto del llamado, que es lo que de verdad cierra la pregunta: que
     * bytes alcanza por cada parametro.  Se pide UNA vez para todos sus sitios.
     *
     * Es lo unico caro de aqui, y por eso se pide en este punto y no antes: a
     * `sites_of` solo se llega preguntando por una funcion concreta, y a esta
     * funcion solo se pregunta si alguien prometio exclusividad en ella.  Un
     * programa que no use `out` / `inout` / `unique<T>` / `borrow_mut<T>` no
     * llega hasta aqui y no paga el punto fijo. */
    const FunctionSummary *callee_sum = nullptr;
    if (callee != nullptr && mod_ != nullptr &&
        !util::flag_on(util::FlagId::NoParamReach))
        callee_sum = &base_->effects(*mod_, stage_).summary(*mod_, *callee);

    std::vector<CallSiteLocs> sites;
    sites.reserve(it->second.size());
    for (const asa::ModuleWalk::Site &cs : it->second) {
        const ir::IrInstr &in = *cs.instr;
        /* El points-to del LLAMANTE.  La base lo cachea por funcion, asi que
         * pedirlo por sitio no lo recalcula. */
        const PointsTo &pt = base_->memory(*cs.fn);
        CallSiteLocs site;
        site.line = in.source_line;
        site.arg.reserve(in.operands.size());
        /* UNA resolucion por argumento.  Es lo que hace que esto sea lineal en
         * el tamano del programa: sumado sobre las funciones que se preguntan,
         * esto son sus listas de argumentos y nada mas.
         *
         * Y cada una con el ANCHO que el llamado promete para ese parametro.
         * Pasar cero era tirar un dato que ya estaba delante: sin ancho, dos
         * posiciones de la misma reserva no se pueden separar ni juntar. */
        for (size_t i = 0; i < in.operands.size(); ++i) {
            ParamReach r;
            r.base = loc_of(pt, in.operands[i], declared_extent(callee, i));
            if (callee_sum != nullptr) {
                r.complete = true; // hasta que la proyeccion diga lo contrario
                r.reached = reach_through_param(callee_sum->semantic.closure,
                                                in.operands, pt, i, r.complete);
                /* Y lo que el propio resumen no supo, que es OTRA laguna:
                 * `reach_through_param` habla de la traduccion, esto de si el
                 * analisis del llamado llego al final. */
                if (callee_sum->completeness != AnalysisCompleteness::Complete)
                    r.complete = false;
                r.known = true;
            }
            site.arg.push_back(std::move(r));
        }
        sites.push_back(std::move(site));
    }
    return &(resolved_[function] = std::move(sites));
}

ParamPairInfo ParamAliasing::of(const std::string &function, size_t a,
                                size_t b) const {
    ParamPairInfo out;
    const std::vector<CallSiteLocs> *sites = sites_of(function);
    if (sites == nullptr || sites->empty()) {
        /* Nadie la llama.  No se afirma nada: un hecho sobre codigo que no se
         * usa no ayuda y ensucia el recuento. */
        return out;
    }
    /* Se recorren TODOS los sitios aunque uno salga indeciso, y no es un
     * detalle: un solape demostrado en la llamada de abajo es lo accionable, y
     * pararse en la de arriba porque no se supo decidir lo tiraba.  El coste no
     * cambia -- son los mismos sitios de esa funcion, una vez -- y el veredicto
     * mejora. */
    bool undecided = false;
    uint32_t undecided_line = 0;
    for (const CallSiteLocs &site : *sites) {
        if (a >= site.arg.size() || b >= site.arg.size()) {
            /* Una llamada con menos argumentos de los que se preguntan: no se
             * puede decidir con ella, y con una que no decida ya no hay
             * disyuncion que afirmar. */
            if (!undecided) undecided_line = site.line;
            undecided = true;
            continue;
        }
        const ParamReach &ra = site.arg[a];
        const ParamReach &rb = site.arg[b];
        if (proven_overlap(ra, rb)) {
            /* Se solapan de verdad: NO es una limitacion del analisis, es un
             * dato del programa, y con su linea, que es lo accionable.
             *
             * Se pregunta por lo DEMOSTRADO y no por @c may_alias, que era el
             * fallo: aquella contesta "no se puede demostrar que sean
             * disjuntas", y con la raiz comun y los anchos sin conocer eso sale
             * que si para dos posiciones a sesenta bytes una de otra.  Un
             * programa correcto quedaba rechazado, que es la forma mas cara de
             * romper el segundo invariante del ASA. */
            out.verdict = ParamPairVerdict::Overlaps;
            out.line = site.line;
            return out;
        }
        /* Ni solape demostrado ni disyuncion demostrada: no se sabe.  Una
         * posicion sin raiz concreta cae aqui igual. */
        if (!proven_disjoint(ra, rb)) {
            if (!undecided) undecided_line = site.line;
            undecided = true;
        }
    }
    if (undecided) {
        out.verdict = ParamPairVerdict::Unknown;
        out.line = undecided_line;
        return out;
    }
    out.verdict = ParamPairVerdict::Disjoint;
    return out;
}

} // namespace effects
} // namespace analysis
