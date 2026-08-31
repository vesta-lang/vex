/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/dump.cpp
 * @brief La vista del almacen de hechos (ver @c analysis/asa/dump.h).
 *
 * Ni calcula ni decide: ordena, filtra y escribe.  Todo lo que sale de aqui ya
 * estaba en el almacen, puesto por el productor de su dominio.
 */

#include "analysis/asa/dump.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace analysis {
namespace asa {

namespace {

/// Nombre corto: `asa.rangos` se ensena como `rangos`.
const char *short_name(const char *s) {
    const char *dot = std::strrchr(s, '.');
    return dot != nullptr ? dot + 1 : s;
}

/// Como se nombra al sujeto de un hecho.
std::string subject_text(const Subject &s) {
    std::ostringstream o;
    if (s.function == nullptr || s.function[0] == '\0') return "<module>";
    o << s.function;
    switch (s.kind) {
    case Subject::Kind::Value: o << ":v" << s.id; break;
    case Subject::Kind::Block: o << ":b" << s.id; break;
    case Subject::Kind::Instruction: o << ":i" << s.id; break;
    default: break;
    }
    return o.str();
}

/// Orden estable: por sujeto y, dentro, por dominio.  Dos volcados del mismo
/// programa tienen que poder compararse linea a linea.
std::vector<FactId> sorted(const FactStore &a) {
    std::vector<FactId> ids;
    ids.reserve(a.size());
    for (FactId i = 0; i < a.size(); ++i)
        ids.push_back(i);
    std::stable_sort(ids.begin(), ids.end(), [&a](FactId x, FactId y) {
        const std::string sx = subject_text(a.at(x).about);
        const std::string sy = subject_text(a.at(y).about);
        if (sx != sy) return sx < sy;
        return std::strcmp(a.at(x).what.domain, a.at(y).what.domain) < 0;
    });
    return ids;
}

void write_fact(const FactStore &a, FactId id, FILE *out) {
    const Fact &f = a.at(id);
    std::fprintf(out, "      %-12s %-24s", short_name(f.what.domain),
                 short_name(f.what.code));
    if (f.what.detail != nullptr && f.what.detail[0] != '\0')
        std::fprintf(out, " %s", f.what.detail);
    /* Certeza, fuente y regla, en ese orden y siempre.  La certeza es lo que
     * decide al consumidor; la fuente y la regla son para entenderlo.  Cuando
     * entren los hechos observados en ejecucion o medidos en corridas
     * anteriores, apareceran aqui al lado de los estaticos, con su certeza
     * propia y sin que la vista tenga que cambiar. */
    std::fprintf(out, "   [%s, de %s", certainty_name(f.seal.certainty),
                 source_name(f.seal.origin.source));
    if (f.proof.rule != nullptr && f.proof.rule[0] != '\0')
        std::fprintf(out, ", por %s", f.proof.rule);
    std::fprintf(out, "]\n");
    if (f.proof.from.empty()) return;
    /* La derivacion: de que hechos CONCRETOS se sigue este.  Es lo que
     * convierte "confia en mi" en algo comprobable. */
    for (FactId d : a.explain(id)) {
        if (d == id) continue;
        const Fact &o = a.at(d);
        std::fprintf(out, "          <- %s %s %s\n",
                     subject_text(o.about).c_str(), short_name(o.what.code),
                     o.what.detail != nullptr ? o.what.detail : "");
    }
}

} // namespace

void print_dump(const FactStore &store,
                const std::vector<ProductionSummary> &summaries, FILE *out) {
    std::fprintf(out, "Lo que se sabe del programa (ASA)\n");
    std::fprintf(out, "Cada linea: dominio | que se afirma | detalle | cuanto "
                      "fiarse.\n");
    std::fprintf(out, "%s\n", std::string(78, '=').c_str());

    const std::vector<FactId> ids = sorted(store);
    std::string last;
    for (FactId id : ids) {
        const std::string s = subject_text(store.at(id).about);
        if (s != last) {
            std::fprintf(out, "\n  %s\n", s.c_str());
            last = s;
        }
        write_fact(store, id, out);
    }

    std::fprintf(out, "\n%s\n", std::string(78, '=').c_str());
    std::fprintf(out, "Por dominio:\n");
    for (const ProductionSummary &r : summaries) {
        std::fprintf(out,
                     "  %-12s %6u hechos de %6u miradas (%u sin sacar nada, "
                     "%u ni miradas), %ld us\n",
                     short_name(r.domain), r.facts, r.looked_at, r.silent,
                     r.skipped, r.micros);
        /* El POR QUE de lo que no se supo, con su CLASE delante: dos codigos
         * distintos de la misma clase se arreglan igual, y la clase es lo unico
         * que puede leer quien no conoce el dominio.  "nothing-to-say" no es no
         * saber -- se sabe, y no hay nada que arreglar --, y se distingue.
         *
         * Un dominio que se calla sin motivo no se puede arreglar: no se
         * distingue "puede valer cualquier cosa" de "no me dio tiempo" ni de
         * "no lo mire".  Por eso NINGuN sitio puede callarse sin reportar. */
        for (const UnknownEntry &m : r.reasons)
            std::fprintf(out, "                 %-24s %6u  %s\n",
                         unknown_reason_name(m.reason), m.times,
                         short_name(m.code));
    }
    /* Y de que fuente viene lo que se sabe.  Hoy todo es estatico; el dia que
     * entren la observacion en ejecucion y el perfil, se veran aqui repartidos
     * -- que es la prueba de que entraron como una fuente mas y no como otro
     * sistema. */
    uint32_t by_source[4] = {0, 0, 0, 0};
    for (FactId id : ids) {
        const uint8_t f = static_cast<uint8_t>(store.at(id).seal.origin.source);
        if (f < 4) ++by_source[f];
    }
    std::fprintf(out,
                 "Por fuente: estatico=%u ejecucion=%u perfil=%u "
                 "declarado=%u\n",
                 by_source[0], by_source[1], by_source[2], by_source[3]);

    const FactStore::Counts c = store.counts();
    std::fprintf(out,
                 "\nEn total %zu hechos: %u demostrados, %u inferidos, %u sin "
                 "certeza.\n",
                 store.size(), c.proven, c.inferred, c.unknown);
    std::fprintf(out, "Lo que se miro sin sacar nada es donde hay sitio para "
                      "saber mas.\n");

    /* Alcances restringidos SIN decir por que.
     *
     * Restringir es afirmar "esto no vale alli", y afirmar sin prueba es lo
     * unico que el ASA no se permite.  Se lista y no se aborta: que falte el
     * motivo no invalida el hecho, solo lo deja sin explicar. */
    uint32_t unjustified = 0;
    for (const Fact &f : store.all())
        if (!f.scope.justified()) ++unjustified;
    if (unjustified != 0)
        std::fprintf(out,
                     "\n%u hechos restringen su alcance sin decir por que.\n"
                     "  Restringir es afirmar que algo NO vale en otro sitio, "
                     "y eso tambien se explica.\n",
                     unjustified);

    /* Y lo que NADIE MIRO.
     *
     * Es la otra mitad, y la que no se puede descubrir con tests: un test cubre
     * lo que ya sospechabas, y esto sale justo de lo que no sospechaba nadie.
     * Un hecho que no consulta nadie es una de dos cosas, y las dos interesan:
     *
     *   - trabajo tirado: se calcula y no le sirve a ningun consumidor;
     *   - conocimiento bien calculado y MAL SELLADO, que nadie encuentra.
     *
     * Lo segundo es lo que estuvo meses escondido: el hecho de la alineacion
     * valia tambien con el JIT y estaba sellado solo para el interprete.  No
     * dio ningun resultado equivocado -- dio silencio --, y el silencio no se
     * distingue de "no se sabe" hasta que alguien lo cuenta.
     *
     * Se listan los primeros y se resume el resto: la cifra es la senal, la
     * lista solo sirve para empezar a tirar del hilo. */
    const std::vector<FactId> unseen = store.never_queried();
    std::fprintf(out, "\nNadie consulto %zu de %zu hechos.\n", unseen.size(),
                 store.size());
    if (!unseen.empty()) {
        constexpr size_t kSample = 10;
        const size_t n = unseen.size() < kSample ? unseen.size() : kSample;
        for (size_t i = 0; i < n; ++i) {
            const Fact &f = store.at(unseen[i]);
            std::fprintf(out, "    %-12s %s\n", short_name(f.what.domain),
                         short_name(f.what.code));
        }
        if (unseen.size() > n)
            std::fprintf(out, "    ... y %zu mas\n", unseen.size() - n);
        std::fprintf(out, "  Un hecho que no mira nadie es trabajo tirado, o "
                          "esta mal sellado y no se encuentra.\n");
    }
}

} // namespace asa
} // namespace analysis
