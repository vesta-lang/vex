/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact_base.cpp
 * @brief Implementacion de la base de hechos (ver @c
 * analysis/asa/fact_base.h).
 */

#include "util/env_flags.h"
#include "analysis/asa/fact_base.h"

#include "analysis/asa/fact_store.h"
#include "ir/ssa_ir.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace analysis {
namespace asa {

/* El VOCABULARIO va en ingles, como los identificadores: estos nombres viajan
 * al fichero de hechos, al volcado y al MCP, y ahi los lee gente y herramientas
 * que no tienen por que saber espanol.  La PROSA -- comentarios, y el texto que
 * ve el usuario, que sale del catalogo multi-idioma -- es lo unico que no. */
const char *const kProducerStructure = "asa.structure";
const char *const kProducerRanges = "asa.ranges";
const char *const kProducerMemory = "asa.memory";
const char *const kProducerLayout = "asa.layout";
const char *const kProducerAsmFlow = "asa.asm_flow";
const char *const kProducerBoundary = "asa.boundary";
const char *const kProducerLoops = "asa.loops";
const char *const kModuleUnit = "<module>";

void register_asa_canonical_names() {
    /* Perezoso y una sola vez, NO un objeto global.  Un inicializador estatico
     * reservaria memoria antes de main aunque nadie fuera a leer hechos de
     * disco, y eso corre las direcciones de todo lo que se reserve despues --
     * en un programa que dependa de la alineacion de lo suyo, algo asi cambia
     * si funciona o no.  Ademas evita el orden de inicializacion entre ficheros
     * objeto, que aqui importa porque la tabla vive en otro. */
    static const bool done = [] {
        register_canonical_name(kProducerStructure);
        register_canonical_name(kProducerRanges);
        register_canonical_name(kProducerMemory);
        register_canonical_name(kProducerLayout);
        register_canonical_name(kProducerAsmFlow);
        register_canonical_name(kProducerBoundary);
        register_canonical_name(kProducerLoops);
        register_canonical_name(kModuleUnit);
        return true;
    }();
    (void)done;
}

/// Marcadores de identidad para el gestor.  Uno por dominio: la cache va por
/// (analisis, unidad), asi que dos dominios distintos no se pisan.
namespace {
struct MemoryAnalysis {
    static char ID;
};
struct LoopsAnalysis {
    static char ID;
};
struct IvBoundsAnalysis {
    static char ID;
};
struct BoundaryAnalysis {
    static char ID;
};
char MemoryAnalysis::ID = 0;
char LoopsAnalysis::ID = 0;
char IvBoundsAnalysis::ID = 0;
char BoundaryAnalysis::ID = 0;
} // namespace

FactBase::FactBase() {
    register_asa_canonical_names();
}

FactBase::~FactBase() {
    static const bool log_it = util::flag_on(util::FlagId::AsaHechosDebug);
    if (!log_it || queries_ == 0) return;
    dump_facts(dump(), stderr);
    std::fprintf(stderr,
                 "[hechos] %zu preguntas atendidas, %zu analisis ejecutados\n",
                 queries_, computations_);
}

std::string FactBase::key_of(const ir::IrFunction &fn) {
    if (!fn.name.empty()) return fn.name;
    /* Anonima: la direccion la identifica sin ambiguedad mientras viva, y una
     * base no sobrevive al modulo cuyas funciones consulta. */
    char buf[40];
    std::snprintf(buf, sizeof buf, "<anonima:%p>",
                  static_cast<const void *>(&fn));
    return std::string(buf);
}

void FactBase::mark(const char *producer, const std::string &key, Certainty c,
                    const char *support) {
    Seal s;
    s.certainty = c;
    s.origin.producer = producer;
    if (support != nullptr) s.support.add(support);
    auto &table = seals_[producer];
    auto &stored = table[key];
    stored = s;
    /* La procedencia apunta a la CLAVE, no al nombre de la funcion: la clave
     * vive en el mapa tanto como el sello, y el nodo no se mueve al crecer.
     * Apuntar al nombre de la funcion dejaria un puntero colgando en cuanto la
     * funcion consultada muriera antes que la base. */
    stored.origin.function = table.find(key)->first.c_str();
}

const IrFacts &FactBase::structure(const ir::IrFunction &fn) {
    ++queries_;
    const std::string key = key_of(fn);
    if (!manager_.cached<IRFactsAnalysis>(key)) {
        ++computations_;
        /* Un recorrido, sin reticulo ni punto fijo: lo que sale de aqui esta
         * DEMOSTRADO, no inferido.  Los def-use y el CFG son lo que el IR dice,
         * no una aproximacion de lo que podria pasar. */
        mark(kProducerStructure, key, Certainty::Proven);
    }
    return manager_.get_or_compute<IRFactsAnalysis, IrFacts>(
        key, [&fn]() { return build_ir_facts(fn); });
}

const RangeFacts &FactBase::ranges(const ir::IrFunction &fn) {
    ++queries_;
    const std::string key = key_of(fn);
    const bool fresh = !manager_.cached<RangeAnalysis>(key);
    if (fresh) ++computations_;
    /* La factoria pide la estructura POR LA BASE, no por su cuenta: asi el
     * gestor anota que los rangos dependen de ella y una invalidacion arrastra
     * a los dos.  Pedirla aparte dejaria rangos vivos sobre hechos muertos. */
    /* El gestor guarda el PUNTERO, no una copia.  `RangeFacts` lleva dentro el
     * estado de entrada de cada bloque, asi que copiarlo es duplicar el
     * analisis entero, y debajo ya existe UNA instancia en la cache por
     * dependencias.  Los otros dos gestores que piden rangos -- el del
     * optimizador y el de efectos -- apuntan a la MISMA. */
    const RangeFacts &rf =
        *manager_.get_or_compute<RangeAnalysis,
                                 std::shared_ptr<const RangeFacts>>(
            key, [this, &fn]() {
                /* Con las cotas de induccion.  Es conocimiento que el
                 * compilador YA tiene y que los rangos no pueden sacar solos:
                 * la guarda de un bucle desenrollado compara `i + 7`, y
                 * despejar la `i` con aritmetica que envuelve es incorrecto.
                 * Sin esto, la variable del bucle valia todo su tipo. */
                return compute_ranges_ptr(fn, structure(fn), RangeOptions{},
                                          nullptr, &iv_bounds(fn));
            });
    if (fresh) {
        /* La certeza sale del propio analisis, no de quien pregunta: llegar a
         * punto fijo es haber visto todo lo que podia contradecirlo; pararse
         * por presupuesto es "hasta aqui he llegado", que sostiene una decision
         * con red pero no permite quitar una comprobacion. */
        mark(kProducerRanges, key,
             rf.convergio ? Certainty::Proven : Certainty::Inferred,
             kProducerStructure);
    }
    return rf;
}

const PointsTo &FactBase::memory(const ir::IrFunction &fn) {
    ++queries_;
    const std::string key = key_of(fn);
    if (!manager_.cached<MemoryAnalysis>(key)) {
        ++computations_;
        /* El conjunto de sitios a los que un puntero PUEDE referirse es una
         * sobre-aproximacion COMPLETA: nada que no este dentro puede ocurrir.
         * Que un puntero concreto quede en "cualquier cosa" no rebaja el hecho
         * -- eso lo dice la propia entrada, no su certeza. */
        mark(kProducerMemory, key, Certainty::Proven, kProducerStructure);
    }
    return manager_.get_or_compute<MemoryAnalysis, PointsTo>(
        key, [this, &fn]() { return compute_points_to(fn, structure(fn)); });
}

const LoopFacts &FactBase::loops(const ir::IrFunction &fn) {
    ++queries_;
    const std::string key = key_of(fn);
    if (!manager_.cached<LoopsAnalysis>(key)) {
        ++computations_;
        mark(kProducerLoops, key, Certainty::Proven);
    }
    return manager_.get_or_compute<LoopsAnalysis, LoopFacts>(
        key, [&fn]() { return compute_loop_facts(fn); });
}

const LoopIvBounds &FactBase::iv_bounds(const ir::IrFunction &fn) {
    ++queries_;
    const std::string key = key_of(fn);
    if (!manager_.cached<IvBoundsAnalysis>(key)) {
        ++computations_;
        /* Demostrado: sale de la FORMA del bucle y de constantes escritas, sin
         * punto fijo que pueda pararse por presupuesto ni aproximacion que
         * pueda quedarse corta.  Por eso puede alimentar a los rangos y no al
         * reves -- si preguntara, se morderian la cola. */
        mark(kProducerLoops, key, Certainty::Proven, kProducerStructure);
    }
    return manager_.get_or_compute<IvBoundsAnalysis, LoopIvBounds>(
        key, [this, &fn]() {
            return compute_loop_iv_bounds(fn, structure(fn), loops(fn));
        });
}

const RangeSummaries &FactBase::boundary(const ir::IrModule &mod) {
    ++queries_;
    const std::string key = kModuleUnit;
    const bool fresh = !manager_.cached<BoundaryAnalysis>(key);
    if (fresh) ++computations_;
    const RangeSummaries &rs =
        manager_.get_or_compute<BoundaryAnalysis, RangeSummaries>(
            key, [&mod]() { return compute_range_summaries(mod); });
    if (fresh) {
        /* Sin punto fijo del grafo de llamadas los resumenes se abren solos, y
         * entonces lo que se sabe es nada -- no algo menos preciso. */
        mark(kProducerBoundary, key,
             rs.convergio ? Certainty::Proven : Certainty::Unknown,
             kProducerStructure);
    }
    return rs;
}

void FactBase::invalidate(const ir::IrFunction &fn) {
    const std::string key = key_of(fn);
    /* La estructura arrastra en cascada a todo lo que se derivo de ella; los
     * demas se descartan tambien de forma explicita por si alguien los pidio
     * antes de que existiera esa dependencia. */
    manager_.invalidate<IRFactsAnalysis>(key);
    manager_.invalidate<RangeAnalysis>(key);
    manager_.invalidate<MemoryAnalysis>(key);
    manager_.invalidate<LoopsAnalysis>(key);
    /* Y su sello con ellos: un hecho muerto que deja su procedencia atras hace
     * que el volcado afirme lo que ya no se sabe. */
    for (auto &domain : seals_)
        domain.second.erase(key);
}

Seal FactBase::seal(const char *producer, const ir::IrFunction &fn) const {
    auto d = seals_.find(producer);
    if (d == seals_.end()) return Seal{};
    auto it = d->second.find(key_of(fn));
    /* Nadie ha preguntado todavia: no se sabe nada, que no es lo mismo que
     * saber que no hay nada. */
    if (it == d->second.end()) return Seal{};
    return it->second;
}

Seal FactBase::module_seal(const char *producer) const {
    auto d = seals_.find(producer);
    if (d == seals_.end()) return Seal{};
    auto it = d->second.find(kModuleUnit);
    if (it == d->second.end()) return Seal{};
    return it->second;
}

std::vector<RecordedFact> FactBase::dump() const {
    std::vector<RecordedFact> out;
    for (const auto &domain : seals_)
        for (const auto &pair : domain.second)
            out.push_back({domain.first, pair.first, pair.second});
    /* Orden estable: dos volcados del mismo programa deben poder compararse. */
    std::sort(out.begin(), out.end(),
              [](const RecordedFact &a, const RecordedFact &b) {
                  if (a.function != b.function) return a.function < b.function;
                  return std::strcmp(a.domain, b.domain) < 0;
              });
    return out;
}

void dump_facts(const std::vector<RecordedFact> &entries, FILE *out) {
    for (const RecordedFact &h : entries) {
        std::fprintf(out, "[hechos] %-16s %-32s certeza=%s", h.domain,
                     h.function.c_str(), certainty_name(h.seal.certainty));
        for (int i = 0; i < Support::kMax; ++i)
            if (h.seal.support.on[i] != nullptr)
                std::fprintf(out, " sobre=%s", h.seal.support.on[i]);
        std::fprintf(out, "\n");
    }
}

} // namespace asa
} // namespace analysis
