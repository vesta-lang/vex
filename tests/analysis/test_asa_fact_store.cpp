/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_asa_fact_store.cpp
 * @brief La frontera comun del ASA: que un hecho lleve encima su certeza, su
 *        origen y su PRUEBA, que la prueba se pueda recorrer, y que producir y
 *        mirar sean cosas distintas.
 *
 * El test EXIGE las propiedades que hacen util al sistema, no que compile:
 * que un consumidor pueda preguntar POR QUE y recibir la derivacion; que dos
 * hechos del mismo texto compartan UNA copia (o el almacen crece con el
 * programa); y que un hecho observado en ejecucion se distinga de uno
 * demostrado SIN que el consumidor tenga que saber quien lo produjo.
 */

#include "analysis/asa/fact_store.h"
#include "analysis/asa/producers.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <string>

using namespace analysis::asa;

static int g_checks = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  [FALLO] %s (linea %d)\n", (msg), __LINE__);         \
        }                                                                      \
    } while (0)

/// Un hecho cualquiera, para no repetir el armado en cada prueba.
static Fact hecho(FactStore &a, const char *dominio, const char *codigo,
                  const char *funcion, Certainty c) {
    Fact f;
    f.what.domain = dominio;
    f.what.code = codigo;
    f.what.detail = a.intern("detalle repetido que no cabe en la pila");
    f.about.kind = Subject::Kind::Function;
    f.about.function = a.intern(funcion);
    f.seal.certainty = c;
    f.seal.origin.producer = dominio;
    return f;
}

// ===========================================================================
// 1. Un hecho lleva su prueba, y la prueba se recorre
// ===========================================================================
static void probar_derivacion() {
    FactStore a;
    const FactId base = a.add(
        hecho(a, "asa.structure", "structure.shape", "f", Certainty::Proven));

    Fact rango =
        hecho(a, "asa.ranges", "range.bounded", "f", Certainty::Proven);
    rango.proof.rule = "flujo-de-datos";
    rango.proof.from.push_back(base);
    const FactId r = a.add(std::move(rango));

    Fact derivado =
        hecho(a, "asa.memory", "memory.points_to", "f", Certainty::Proven);
    derivado.proof.rule = "propagacion";
    derivado.proof.from.push_back(r);
    const FactId d = a.add(std::move(derivado));

    const std::vector<FactId> cadena = a.explain(d);
    CHECK(cadena.size() == 3, "la derivacion llega hasta el hecho fundacional");
    CHECK(cadena[0] == d && cadena[1] == r && cadena[2] == base,
          "y viene en orden: primero el hecho, detras aquello de lo que se "
          "sigue");

    /* Un grafo, no un arbol: dos hechos pueden apoyarse en el mismo y la
     * explicacion no debe repetirlo. */
    Fact otro = hecho(a, "asa.loops", "loop.header", "f", Certainty::Proven);
    otro.proof.from.push_back(base);
    otro.proof.from.push_back(r);
    const FactId o = a.add(std::move(otro));
    const std::vector<FactId> c2 = a.explain(o);
    CHECK(c2.size() == 3, "un apoyo compartido no se cuenta dos veces");
}

// ===========================================================================
// 2. Los textos se comparten: un almacen no crece con lo que se repite
// ===========================================================================
static void probar_internado() {
    FactStore a;
    const char *x = a.intern("mismo texto");
    const char *y = a.intern("mismo texto");
    CHECK(x == y, "dos textos iguales son UNA copia, no dos");
    CHECK(std::string(x) == "mismo texto", "y el texto es el que se guardo");
    CHECK(a.intern("otro") != x, "textos distintos no se confunden");
}

// ===========================================================================
// 3. Se consulta por sujeto y por dominio sin recorrerlo todo
// ===========================================================================
static void probar_consulta() {
    FactStore a;
    a.add(hecho(a, "asa.ranges", "range.bounded", "uno", Certainty::Proven));
    a.add(hecho(a, "asa.ranges", "range.bounded", "dos", Certainty::Proven));
    a.add(hecho(a, "asa.memory", "memory.points_to", "uno", Certainty::Proven));

    CHECK(a.of_function("uno").size() == 2, "lo que se sabe de una funcion");
    CHECK(a.of_function("dos").size() == 1, "y de otra, sin mezclarse");
    CHECK(a.of_function("ninguna").empty(),
          "preguntar por algo que no esta no inventa nada");
    CHECK(a.of_domain("asa.ranges").size() == 2, "lo que dijo un dominio");
}

// ===========================================================================
// 4. La certeza distingue al hecho observado del demostrado -- y el consumidor
//    NO necesita saber quien lo produjo
// ===========================================================================
static void probar_certeza_agnostica() {
    FactStore a;
    /* El mismo hecho, dicho por dos fuentes distintas.  El consumidor mira la
     * certeza: sobre lo demostrado puede quitar la comprobacion; sobre lo
     * observado tiene que dejar red (una guarda). */
    a.add(hecho(a, "asa.ranges", "range.bounded", "f", Certainty::Proven));
    a.add(hecho(a, "asa.observed", "range.bounded", "f", Certainty::Inferred));

    const FactStore::Counts c = a.counts();
    CHECK(c.proven == 1 && c.inferred == 1,
          "los dos conviven: nada se sobreescribe");

    int con_red = 0, sin_red = 0;
    for (FactId id : a.of_function("f")) {
        /* Asi decide un consumidor: por la certeza, sin mirar la procedencia.
         */
        if (a.at(id).seal.certainty == Certainty::Proven)
            ++sin_red;
        else
            ++con_red;
    }
    CHECK(sin_red == 1 && con_red == 1,
          "la decision sale de la certeza, no de quien lo dijo");
}

// ===========================================================================
// 5. Producir y mirar son cosas distintas: los dominios se dan de alta
// ===========================================================================
static void probar_registro() {
    const std::vector<const char *> ds = registered_producers();
    CHECK(ds.size() >= 5,
          "los dominios de casa estan dados de alta (estructura, rangos, "
          "frontera, memoria, bucles)");
    bool estructura_primero =
        ds.empty() ? false : std::string(ds[0]) == "asa.structure";
    CHECK(estructura_primero,
          "la estructura va primero: los demas apoyan sus hechos en el suyo");
}

int main() {
    std::printf("=== test_asa_fact_store (la frontera comun del ASA) ===\n");
    probar_derivacion();
    probar_internado();
    probar_consulta();
    probar_certeza_agnostica();
    probar_registro();
    std::printf("%s: %d comprobaciones, %d fallos\n",
                g_fail == 0 ? "OK" : "FALLO", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
