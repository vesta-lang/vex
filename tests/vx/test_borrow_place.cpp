/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/vx/test_borrow_place.cpp
 * @brief El LUGAR de un prestamo: cuando dos se pisan y cuando no.
 *
 * Los dos lados importan igual y por eso estan juntos.  Separar de menos deja
 * pasar un error de verdad; separar de mas rechaza un programa correcto, y eso
 * es lo caro, porque quien lo sufre no puede hacer nada -- su codigo ya esta
 * bien --.  Un test que solo mirara uno de los dos lados se puede satisfacer
 * contestando siempre lo mismo.
 */

#include "vx/borrow/place.h"

#include <cstdio>

using namespace vx::borrow;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("FALLO [%s:%d]: %s\n", __FILE__, __LINE__, msg);       \
        }                                                                      \
    } while (0)

/// @brief `raiz` a secas.
static Place P(const char *root) {
    Place p;
    p.root = root;
    return p;
}
/// @brief `raiz.campo`.
static Place F(const char *root, const char *field) {
    Place p = P(root);
    p.path.push_back(PlaceStep::of_field(field));
    return p;
}

// --------------------------------------------------------------------------
// 1) Campos distintos del mismo struct NO se pisan.  Es el falso positivo que
//    todo esto viene a quitar: `mueve(p.a, p.b)` se rechazaba porque los dos
//    nombres eran `p`.
// --------------------------------------------------------------------------
static void test_disjoint_fields() {
    CHECK(!places_may_overlap(F("p", "a"), F("p", "b")),
          "p.a y p.b son campos distintos: no se pisan");
    CHECK(places_may_overlap(F("p", "a"), F("p", "a")),
          "p.a consigo mismo si");
    CHECK(places_same(F("p", "a"), F("p", "a")), "y ademas es EL MISMO lugar");
    CHECK(!places_same(F("p", "a"), F("p", "b")), "p.a y p.b no son el mismo");
}

// --------------------------------------------------------------------------
// 2) El contenedor choca con lo contenido.  Prestar `p.a` y mover `p` rompe el
//    prestamo, asi que tienen que chocar aunque `p` sea "mas grande".
// --------------------------------------------------------------------------
static void test_prefix() {
    CHECK(places_may_overlap(P("p"), F("p", "a")),
          "p contiene a p.a: chocan");
    CHECK(places_may_overlap(F("p", "a"), P("p")), "y da igual el orden");
    CHECK(!places_same(P("p"), F("p", "a")),
          "pero no son el MISMO lugar: contener no es ser");
}

// --------------------------------------------------------------------------
// 3) Raices distintas, con todo resuelto, son memoria distinta.
// --------------------------------------------------------------------------
static void test_roots() {
    CHECK(!places_may_overlap(P("x"), P("y")), "dos variables distintas");
    CHECK(!places_may_overlap(F("x", "a"), F("y", "a")),
          "el mismo campo de dos variables distintas");
}

// --------------------------------------------------------------------------
// 4) Indices: los constantes separan, el de ejecucion no, y lo DICE.
// --------------------------------------------------------------------------
static void test_indices() {
    Place a0 = P("arr"), a1 = P("arr"), ai = P("arr");
    a0.path.push_back(PlaceStep::of_const_index(0));
    a1.path.push_back(PlaceStep::of_const_index(1));
    ai.path.push_back(PlaceStep::of_unknown_index());

    CHECK(!places_may_overlap(a0, a1), "arr[0] y arr[1] no se pisan");
    CHECK(places_may_overlap(a0, a0), "arr[0] consigo mismo si");

    PlaceUnknown why = PlaceUnknown::None;
    CHECK(places_may_overlap(a0, ai, &why),
          "un indice de ejecucion no se puede separar de arr[0]");
    CHECK(why == PlaceUnknown::RuntimeIndex,
          "y el motivo es que el indice no es constante");

    CHECK(!places_same(ai, ai),
          "dos indices de ejecucion PUEDEN ser el mismo, pero no consta");
}

// --------------------------------------------------------------------------
// 5) Cuando falta la REGION de un puntero, la raiz deja de decidir: `*q` y
//    `*r` son dos variables distintas que pueden nombrar la misma memoria.
//    Separarlas seria el falso negativo, que es peor que el positivo.
//
//    Lo que falta es UNA cosa y en ESTE nivel -- del puntero se siguen sabiendo
//    su contrato y sus efectos --, y por eso el motivo se llama por la pieza
//    que le falta y no por una supuesta opacidad.
// --------------------------------------------------------------------------
static void test_region_unresolved() {
    Place q = P("q"), r = P("r");
    q.path.push_back(PlaceStep::of_deref());
    r.path.push_back(PlaceStep::of_deref());

    CHECK(place_region_unresolved(q), "a `*q` le falta la region");
    CHECK(!place_region_unresolved(F("p", "a")), "a un campo no le falta nada");

    PlaceUnknown why = PlaceUnknown::None;
    CHECK(places_may_overlap(q, r, &why),
          "dos punteros sin region resuelta pueden nombrar lo mismo");
    CHECK(why == PlaceUnknown::RegionNotResolvedHere,
          "y el motivo dice QUE falta, no que sea opaco");
    CHECK(places_may_overlap(q, P("x")),
          "tampoco se separa de una variable cualquiera");
    CHECK(places_may_overlap(q, P("q")),
          "*q choca con q: lo apuntado se DERIVA del puntero");
}

// --------------------------------------------------------------------------
// 6) Como se escribe para el usuario.  El diagnostico tiene que citar el lugar
//    exacto que estorba, no la raiz.
// --------------------------------------------------------------------------
static void test_text() {
    CHECK(F("p", "a").text() == "p.a", "p.a");
    Place m = F("p", "a");
    m.path.push_back(PlaceStep::of_const_index(2));
    CHECK(m.text() == "p.a[2]", "p.a[2]");
    Place q = P("q");
    q.path.push_back(PlaceStep::of_deref());
    CHECK(q.text() == "(*q)", "(*q)");
    CHECK(!P("").valid(), "sin raiz no hay lugar que registrar");
}

int main() {
    test_disjoint_fields();
    test_prefix();
    test_roots();
    test_indices();
    test_region_unresolved();
    test_text();
    std::printf("=== borrow place: %d checks, %d fallos ===\n", g_checks,
                g_fail);
    return g_fail == 0 ? 0 : 1;
}
