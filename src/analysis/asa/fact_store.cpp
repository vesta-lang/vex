/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact_store.cpp
 * @brief Implementacion del almacen de hechos (ver @c
 * analysis/asa/fact_store.h).
 */

#include "analysis/asa/fact_store.h"

#include <cstring>

namespace analysis {
namespace asa {

const FactId kNoFact = 0xFFFFFFFFu;

/* Los nombres ESTABLES van en ingles, como todo el vocabulario: viajan al
 * volcado, al fichero de hechos y al MCP, donde los lee gente y herramientas
 * que no tienen por que saber espanol.  Lo que ve el usuario NO sale de aqui --
 * sale del catalogo multi-idioma --, y por eso estos no se traducen nunca. */
const char *source_name(Source s) {
    switch (s) {
    case Source::Runtime: return "runtime";
    case Source::Profile: return "profile";
    case Source::Declared: return "declared";
    default: return "static";
    }
}

const char *unknown_reason_name(UnknownReason r) {
    switch (r) {
    case UnknownReason::NothingToSay: return "nothing-to-say";
    case UnknownReason::RuntimeDependent: return "runtime-dependent";
    case UnknownReason::ShapeNotRecognized: return "shape-not-recognized";
    case UnknownReason::BudgetExceeded: return "budget-exceeded";
    case UnknownReason::OpaqueBoundary: return "opaque-boundary";
    case UnknownReason::MissingDependency: return "missing-dependency";
    case UnknownReason::SourcesDisagree: return "sources-disagree";
    default: return "not-asked";
    }
}

const char *unknown_reason_code(UnknownReason r) {
    switch (r) {
    case UnknownReason::NothingToSay: return "VXA061";
    case UnknownReason::RuntimeDependent: return "VXA062";
    case UnknownReason::ShapeNotRecognized: return "VXA063";
    case UnknownReason::BudgetExceeded: return "VXA064";
    case UnknownReason::OpaqueBoundary: return "VXA065";
    case UnknownReason::MissingDependency: return "VXA066";
    case UnknownReason::SourcesDisagree: return "VXA067";
    default: return "VXA060"; // NotAsked
    }
}

const char *subject_kind_name(Subject::Kind k) {
    switch (k) {
    case Subject::Kind::Module: return "module";
    case Subject::Kind::Function: return "function";
    case Subject::Kind::Value: return "value";
    case Subject::Kind::Block: return "block";
    case Subject::Kind::Instruction: return "instruction";
    default: return "symbol";
    }
}

/* Los nombres canonicos son POCOS -- un punado de productores y dominios -- y
 * se consultan una vez por hecho leido.  Tabla asociativa, no lista: la lectura
 * de un modulo grande hace cientos de miles de consultas. */
static std::unordered_map<std::string, const char *> &canonical_table() {
    static std::unordered_map<std::string, const char *> t;
    return t;
}

void register_canonical_name(const char *name) {
    if (name == nullptr || name[0] == '\0') return;
    /* El PRIMERO que se registra manda: si dos sitios dieran de alta el mismo
     * texto con literales distintos, cambiar de opinion a mitad partiria la
     * identidad justo de los hechos ya leidos. */
    canonical_table().emplace(std::string(name), name);
}

const char *canonical_name(const std::string &s) {
    auto it = canonical_table().find(s);
    return it == canonical_table().end() ? nullptr : it->second;
}

namespace {
/// Una cadena de OTRO almacen, traida al propio: literal canonico si lo tiene
/// -- el ASA compara por direccion --, y si no, copia en el arena.
const char *adopt(FactStore &dest, const char *s) {
    if (s == nullptr) return nullptr;
    if (s[0] == '\0') return "";
    if (const char *c = canonical_name(s)) return c;
    return dest.intern(s);
}

/// Repunta TODAS las cadenas de @p f al arena de @p dest.  Si se anade un
/// campo de texto a `Fact`, tiene que entrar aqui: lo que se olvide seguira
/// apuntando al almacen de origen y no dara error hasta que ese muera.
void adopt_strings(FactStore &dest, Fact &f) {
    f.what.domain = adopt(dest, f.what.domain);
    f.what.code = adopt(dest, f.what.code);
    f.what.detail = adopt(dest, f.what.detail);
    f.about.function = adopt(dest, f.about.function);
    f.scope.isa = adopt(dest, f.scope.isa);
    f.scope.os = adopt(dest, f.scope.os);
    f.scope.backend = adopt(dest, f.scope.backend);
    f.scope.stage = adopt(dest, f.scope.stage);
    f.scope.why = adopt(dest, f.scope.why);
    f.seal.origin.producer = adopt(dest, f.seal.origin.producer);
    f.seal.origin.function = adopt(dest, f.seal.origin.function);
    for (size_t i = 0; i < Support::kMax; ++i)
        f.seal.support.on[i] = adopt(dest, f.seal.support.on[i]);
    f.proof.rule = adopt(dest, f.proof.rule);
}
} // namespace

FactStore::FactStore(const FactStore &other) {
    *this = other;
}

FactStore &FactStore::operator=(const FactStore &other) {
    if (this == &other) return *this;
    facts_.clear();
    names_.clear();
    interned_.clear();
    by_function_.clear();
    by_domain_.clear();
    queried_.clear();
    produced_.clear();
    /* Se re-DEPOSITAN uno a uno en vez de copiar los indices: asi las tablas
     * por funcion y por dominio quedan indexadas por LOS PUNTEROS DE ESTE
     * almacen, que es lo que despues se compara al consultarlas. */
    facts_.reserve(other.facts_.size());
    for (const Fact &src : other.facts_) {
        Fact f = src;
        adopt_strings(*this, f);
        add(std::move(f));
    }
    /* Y lo que ya se miro, y que dominios corrieron: sin esto una copia decia
     * que nadie ha consultado nada y que no ha corrido ningun dominio -- y lo
     * segundo haria producirlos otra vez. */
    queried_ = other.queried_;
    for (const ProducedDomain &d : other.produced_)
        mark_domain(adopt(*this, d.domain), adopt(*this, d.stage));
    return *this;
}

const char *FactStore::intern(const std::string &s) {
    auto it = interned_.find(s);
    if (it != interned_.end()) return it->second;
    names_.push_back(s);
    const char *p = names_.back().c_str();
    interned_.emplace(s, p);
    return p;
}

FactId FactStore::add(Fact f) {
    const FactId id = static_cast<FactId>(facts_.size());
    if (f.about.function != nullptr && f.about.function[0] != '\0')
        by_function_[f.about.function].push_back(id);
    by_domain_[f.what.domain].push_back(id);
    facts_.push_back(std::move(f));
    queried_.push_back(0); // nadie lo ha mirado todavia
    return id;
}

FactStore::Query FactStore::find(const char *code, const Scope &here) const {
    return find(code, nullptr, here);
}

FactStore::Query FactStore::find(const char *code, const char *function,
                                 const Scope &here) const {
    Query r;
    if (code == nullptr) return r;
    /* Se recorren TODOS los del codigo aunque el primero valga: lo que se
     * devuelve no es solo el hecho, es tambien cuantos habia que no valian. Ese
     * numero es la mitad util de la respuesta cuando no hay hecho, y sin
     * contarlo la consulta no sabria distinguir "no existe" de "existe y no
     * vale aqui" -- que es exactamente el fallo que esta puerta viene a
     * impedir. */
    for (size_t i = 0; i < facts_.size(); ++i) {
        const Fact &f = facts_[i];
        if (f.what.code == nullptr) continue;
        if (f.what.code != code && std::strcmp(f.what.code, code) != 0)
            continue;
        /* Y de la funcion pedida, si se pidio una.  Por texto y no por puntero:
         * quien pregunta suele tener el nombre a mano, no el mismo literal que
         * el almacen interno, y exigir la misma direccion convertiria una
         * consulta correcta en un "no hay nada" mudo. */
        if (function != nullptr) {
            if (f.about.function == nullptr) continue;
            if (f.about.function != function &&
                std::strcmp(f.about.function, function) != 0)
                continue;
        }
        if (!f.scope.holds_in(here)) {
            ++r.out_of_scope;
            continue;
        }
        if (r.fact == nullptr) {
            r.fact = &f;
            queried_[i] = 1;
        }
    }
    return r;
}

std::vector<const Fact *> FactStore::find_all(const char *code,
                                              const char *function,
                                              const Scope &here) const {
    std::vector<const Fact *> r;
    if (code == nullptr) return r;
    for (size_t i = 0; i < facts_.size(); ++i) {
        const Fact &f = facts_[i];
        if (f.what.code == nullptr) continue;
        if (f.what.code != code && std::strcmp(f.what.code, code) != 0)
            continue;
        /* Igual que en `find`: por texto y no por puntero.  Quien pregunta
         * tiene el nombre a mano, no el literal que guardo el almacen. */
        if (function != nullptr) {
            if (f.about.function == nullptr) continue;
            if (f.about.function != function &&
                std::strcmp(f.about.function, function) != 0)
                continue;
        }
        /* Lo que no vale AQUI no entra.  No se cuenta aparte como en `find`:
         * alli el numero distingue "no existe" de "existe y no vale aqui", que
         * es una respuesta; aqui la respuesta es la lista, y una lista vacia ya
         * lo dice. */
        if (!f.scope.holds_in(here)) continue;
        queried_[i] = 1;
        r.push_back(&f);
    }
    return r;
}

std::vector<const Fact *> FactStore::find_unknown(const char *domain,
                                                  const char *function,
                                                  UnknownReason reason,
                                                  const Scope &here) const {
    std::vector<const Fact *> r;
    if (domain == nullptr) return r;
    /* Por el indice del dominio, que ya existe: recorrer el almacen entero
     * para esto seria pagar todos los dominios por preguntar por uno. */
    for (FactId id : of_domain(domain)) {
        if (id >= facts_.size()) continue;
        const Fact &f = facts_[id];
        if (f.seal.certainty != Certainty::Unknown) continue;
        if (f.seal.unknown_reason != reason) continue;
        /* Por texto y no por puntero, igual que en `find`: quien pregunta
         * tiene el nombre a mano, no el literal que guardo el almacen. */
        if (function != nullptr) {
            if (f.about.function == nullptr) continue;
            if (f.about.function != function &&
                std::strcmp(f.about.function, function) != 0)
                continue;
        }
        if (!f.scope.holds_in(here)) continue;
        queried_[id] = 1;
        r.push_back(&f);
    }
    return r;
}

bool FactStore::has_domain(const char *domain, const char *stage) const {
    if (domain == nullptr) return false;
    /* Por texto y no por puntero: quien pregunta suele tener el literal a mano,
     * no el mismo que guardo el registro, y comparar direcciones convertiria un
     * "ya esta hecho" en un "hazlo otra vez" sin que nadie lo note. */
    const char *s = stage != nullptr ? stage : "";
    for (const ProducedDomain &d : produced_) {
        if (d.domain != domain && std::strcmp(d.domain, domain) != 0) continue;
        const char *ds = d.stage != nullptr ? d.stage : "";
        if (ds == s || std::strcmp(ds, s) == 0) return true;
    }
    return false;
}

void FactStore::mark_domain(const char *domain, const char *stage) {
    if (domain == nullptr || has_domain(domain, stage)) return;
    produced_.push_back(ProducedDomain{domain, stage != nullptr ? stage : ""});
}

std::vector<FactId> FactStore::never_queried() const {
    std::vector<FactId> unseen;
    for (size_t i = 0; i < queried_.size(); ++i)
        if (queried_[i] == 0) unseen.push_back(static_cast<FactId>(i));
    return unseen;
}

const std::vector<FactId> &
FactStore::of_function(const std::string &function) const {
    static const std::vector<FactId> kEmpty;
    auto it = by_function_.find(function);
    return it == by_function_.end() ? kEmpty : it->second;
}

const std::vector<FactId> &FactStore::of_domain(const char *domain) const {
    static const std::vector<FactId> kEmpty;
    auto it = by_domain_.find(domain);
    return it == by_domain_.end() ? kEmpty : it->second;
}

std::vector<FactId> FactStore::explain(FactId id) const {
    std::vector<FactId> order;
    if (id >= facts_.size()) return order;
    /* Anchura y sin repetir: la derivacion es un grafo, no un arbol -- dos
     * hechos pueden apoyarse en el mismo --, y repetirlo haria crecer la
     * explicacion sin anadir nada. */
    std::vector<uint8_t> seen(facts_.size(), 0);
    order.push_back(id);
    seen[id] = 1;
    for (size_t i = 0; i < order.size(); ++i) {
        const Fact &f = facts_[order[i]];
        for (FactId d : f.proof.from) {
            if (d >= facts_.size() || seen[d]) continue;
            seen[d] = 1;
            order.push_back(d);
        }
    }
    return order;
}

FactStore::Counts FactStore::counts() const {
    Counts c;
    for (const Fact &f : facts_) {
        switch (f.seal.certainty) {
        case Certainty::Proven: ++c.proven; break;
        case Certainty::Inferred: ++c.inferred; break;
        default: ++c.unknown; break;
        }
    }
    return c;
}

} // namespace asa
} // namespace analysis
