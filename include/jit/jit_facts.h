/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/jit_facts.h
 * @brief Lo que el compilador en caliente PREGUNTA a la base de hechos.
 *
 * La base no vive aqui: es del ASA (@c analysis/asa/fact_base.h) y el JIT es
 * UNO de sus consumidores, igual que el volcado, el nativo o una herramienta.
 * Lo que si es del JIT es la pregunta que se hace en sus decisiones, y eso es
 * lo que declara este fichero.
 *
 * @c JitFactBase es el nombre con el que el JIT llama a esa base.  Se mantiene
 * porque es como la nombran sus consumidores, no porque haya dos cosas.
 */
#ifndef VESTA_JIT_JIT_FACTS_H
#define VESTA_JIT_JIT_FACTS_H

#include "analysis/asa/fact_base.h"

#include <cstdint>
#include <string>

namespace ir {
struct IrFunction;
}

namespace jit {

/// La base de hechos del ASA, vista desde el JIT.  No es un tipo aparte.
using JitFactBase = analysis::asa::FactBase;
using RecordedFact = analysis::asa::RecordedFact;

/// Atajos a los productores que el JIT consulta hoy.
using analysis::asa::dump_facts;
using analysis::asa::kProducerRanges;
using analysis::asa::kProducerStructure;

/**
 * @brief Lo que se sabe de los argumentos con los que se llega a cada llamada y
 *        a cada reserva de una funcion -- CON LA PRUEBA, no solo el veredicto.
 *
 * Un si/no no se puede depurar: cuando el especializador renuncia hay que poder
 * ver si es que no habia ningun sitio donde aprovechar nada, o que los habia y
 * de sus argumentos no se sabia nada.  Son dos cosas distintas y se arreglan de
 * forma distinta, asi que se cuentan por separado (invariante 4 de ASA: todo
 * veredicto lleva su derivacion, en datos).
 */
struct CotasDeLosSitios {
    bool hay = false;                ///< veredicto: algun argumento acotado.
    uint32_t sitios = 0;             ///< llamadas y reservas miradas.
    uint32_t sitios_con_cota = 0;    ///< de esas, cuantas traian algo sabido.
    uint32_t operandos = 0;          ///< argumentos mirados en total.
    uint32_t operandos_con_cota = 0; ///< de esos, cuantos estaban acotados.

    /// La primera prueba concreta: que sitio, que valor y que se sabia de el.
    /// Vacia si el veredicto es que no.
    std::string sitio;
    uint32_t valor = 0;
    analysis::ValueRange rango;
};

/**
 * @brief Mira los sitios de @p fn donde una cota se podria aprovechar.
 *
 * "Saber algo" no es "ser una constante": es estar ACOTADO y que la cota diga
 * mas que el tipo.  Un tamano del que solo se sabe que no pasa del tope del
 * bloque pequeno ya poda la rama de los bloques grandes sin ser constante.
 *
 * Es una PREGUNTA sobre el programa, no una decision: responde que se sabe, y
 * quien pregunta decide que hacer con ello.
 *
 * @param fn     Funcion IR a examinar.
 * @param rangos Rangos de @p fn, recibidos de la base de hechos.
 * @return El recuento y la prueba.
 */
CotasDeLosSitios cotas_de_los_sitios(const ir::IrFunction &fn,
                                     const analysis::RangeFacts &rangos);

/// Azucar sobre @c cotas_de_los_sitios cuando solo interesa el veredicto.
inline bool hay_argumento_acotado(const ir::IrFunction &fn,
                                  const analysis::RangeFacts &rangos) {
    return cotas_de_los_sitios(fn, rangos).hay;
}

} // namespace jit

#endif // VESTA_JIT_JIT_FACTS_H
