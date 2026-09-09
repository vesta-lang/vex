/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/borrow/place.cpp
 * @brief El lugar de un prestamo, y cuando dos lugares pueden pisarse.
 */

#include "vx/borrow/place.h"

#include <cstdio>

namespace vx {
namespace borrow {

bool place_region_unresolved(const Place &p) noexcept {
    /* Un paso `Deref` que sigue puesto es un puntero cuya REGION no se resolvio
     * aqui.  Los que si se resuelven -- prestamo, `unique<T>`, `shared<T>` --
     * no llegan a tener este paso: quien construye el lugar los sustituye por
     * el del dueno. */
    for (const PlaceStep &s : p.path)
        if (s.kind == PlaceStep::Kind::Deref) return true;
    return false;
}

std::string Place::text() const {
    std::string out = root;
    for (const PlaceStep &s : path) {
        switch (s.kind) {
        case PlaceStep::Kind::Field:
            out += '.';
            out += s.field;
            break;
        case PlaceStep::Kind::ConstIndex: {
            char buf[24];
            std::snprintf(buf, sizeof(buf), "[%lld]",
                          static_cast<long long>(s.index));
            out += buf;
            break;
        }
        case PlaceStep::Kind::UnknownIndex:
            /* Se escribe con corchetes vacios y no con el nombre del indice: el
             * lugar habla de MEMORIA, y dos indices con nombres distintos que no
             * se pueden separar son el mismo lugar.  Poner el nombre daria dos
             * textos para una sola cosa. */
            out += "[]";
            break;
        case PlaceStep::Kind::Deref:
            /* Delante y con parentesis, que es como se lee: `(*p).a`. */
            out.insert(0, "(*");
            out += ')';
            break;
        }
    }
    return out;
}

bool places_same(const Place &a, const Place &b) noexcept {
    if (a.root != b.root || a.path.size() != b.path.size()) return false;
    for (size_t i = 0; i < a.path.size(); ++i) {
        /* Un indice de ejecucion NO es igual a otro indice de ejecucion: puede
         * serlo, que es otra cosa.  Esto contesta "es", asi que ahi es que no.
         * Lo mismo un deref opaco: dos punteros sin procedencia pueden apuntar
         * al mismo sitio, pero no consta. */
        if (a.path[i].kind == PlaceStep::Kind::UnknownIndex ||
            a.path[i].kind == PlaceStep::Kind::Deref ||
            b.path[i].kind == PlaceStep::Kind::UnknownIndex ||
            b.path[i].kind == PlaceStep::Kind::Deref)
            return false;
        if (!(a.path[i] == b.path[i])) return false;
    }
    return true;
}

bool places_may_overlap(const Place &a, const Place &b, PlaceUnknown *why) {
    if (why != nullptr) *why = PlaceUnknown::None;

    /* Si a alguno le falta la region de su puntero, la raiz deja de decidir:
     * `*q` y `*r` son dos variables distintas que pueden nombrar la misma
     * memoria.  Va lo primero, antes de comparar raices, justo porque la raiz
     * es lo que aqui no vale.  No es el final de la pregunta: es que la
     * contesta otro. */
    if (place_region_unresolved(a) || place_region_unresolved(b)) {
        if (why != nullptr) *why = PlaceUnknown::RegionNotResolvedHere;
        return true;
    }

    // Resueltos los dos: la raiz ya es una identidad.
    if (a.root != b.root) return false;

    const size_t n = a.path.size() < b.path.size() ? a.path.size()
                                                   : b.path.size();
    for (size_t i = 0; i < n; ++i) {
        const PlaceStep &x = a.path[i];
        const PlaceStep &y = b.path[i];
        /* Un indice de ejecucion no separa: puede valer lo que el otro.  Se
         * dice el motivo y se sigue por lo conservador. */
        if (x.kind == PlaceStep::Kind::UnknownIndex ||
            y.kind == PlaceStep::Kind::UnknownIndex) {
            if (why != nullptr) *why = PlaceUnknown::RuntimeIndex;
            return true;
        }
        /* Pasos de clase distinta sobre la misma raiz no los produce un
         * programa que compila -- un campo y un indice sobre lo mismo --, pero
         * si llegara, no separa. */
        if (x.kind != y.kind) return true;
        if (!(x == y)) return false; // AQUI se separan: campos o indices ok
    }
    /* Se acabo el camino de uno sin separarlos: ese contiene al otro.  Y
     * contener basta, porque lo que se persigue es la DERIVACION -- prestar
     * `p.a` y mover `p` rompe el prestamo aunque no compartan bytes. */
    return true;
}

} // namespace borrow
} // namespace vx
