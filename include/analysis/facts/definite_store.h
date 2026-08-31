/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/definite_store.h
 * @brief DefiniteStoreFacts: si un puntero recibe una ESCRITURA en TODOS los
 *        caminos que llegan a un retorno.
 *
 * Es la pregunta de "asignacion definitiva" de toda la vida, y aqui hace falta
 * porque `out T x` PROMETE que quien llama recibira un valor.  Escribirlo en
 * una rama y no en la otra es exactamente el caso que el llamante paga: lee lo
 * que hubiera en su hueco.
 *
 * POR QUE VIVE EN EL IR, y no en el comprobador de tipos.  La pregunta es de
 * FLUJO, y el grafo de flujo ya existe aqui: bloques, predecesores, retornos.
 * Escribir un segundo recorrido sobre el AST seria producir dos veces un hecho
 * que ya se puede producir una -- y el segundo se quedaria atras en cuanto el
 * lenguaje ganara una forma de saltar.
 *
 * TRES RESPUESTAS, NO DOS.  Un analisis de tipo "para todos los caminos" que
 * solo dijera si/no tendria que elegir que contestar cuando no entiende algo, y
 * las dos elecciones son malas: decir "si" aprueba lo que no ha mirado, y decir
 * "no" acusa a codigo correcto.  Asi que dice tambien "no lo se", con el motivo
 * -- el vocabulario cerrado del ASA, no uno propio --, y quien lo consume
 * decide.  El diagnostico solo habla cuando esta DEMOSTRADO que falta.
 *
 * Y LLEVA SU PRUEBA: cuando falta, dice por que RETORNO se sale sin haber
 * escrito.  Esa linea es mejor sitio para el mensaje que la declaracion del
 * parametro -- es donde el programa incumple --, y ademas es lo que hace que el
 * veredicto se pueda comprobar en vez de creer.
 */

#ifndef ANALYSIS_FACTS_DEFINITE_STORE_H
#define ANALYSIS_FACTS_DEFINITE_STORE_H

#include <cstdint>

#include "analysis/asa/fact.h" // UnknownReason: el vocabulario del "no se"
#include "ir/ssa_ir.h"

namespace analysis {

/**
 * @struct DefiniteStoreFacts
 * @brief Lo que se sabe de si un puntero se escribe siempre antes de retornar.
 */
struct DefiniteStoreFacts {
    /// Que se pudo demostrar.
    enum class Verdict : uint8_t {
        /// Todos los caminos que llegan a un retorno escriben.
        Always,
        /// Hay un retorno al que se llega sin haber escrito, y se ha visto.
        MissingOnSomePath,
        /// No se pudo demostrar ninguna de las dos cosas.
        Unknown,
    };

    Verdict verdict = Verdict::Unknown;

    /// Por que no se sabe.  Solo vale cuando @c verdict es @c Unknown.
    asa::UnknownReason reason = asa::UnknownReason::NotAsked;
    /// Codigo estable del motivo, para el informe y el linter.
    const char *reason_code = "";

    /// La linea del RETORNO por el que se sale sin escribir.  Es la PRUEBA del
    /// veredicto @c MissingOnSomePath; cero si no aplica o no se conoce.
    uint32_t witness_line = 0;

    /// @c true si esta demostrado que falta.  Es lo unico sobre lo que un
    /// diagnostico puede hablar: ni el "no se" ni el "no mirado" acusan.
    bool proven_missing() const noexcept {
        return verdict == Verdict::MissingOnSomePath;
    }
};

/**
 * @brief Calcula si @p target se escribe en todos los caminos hasta un retorno.
 * @param fn     La funcion, ya construida.
 * @param target El puntero por el que se pregunta (normalmente un parametro).
 * @return El veredicto, con su motivo o su prueba.
 */
DefiniteStoreFacts compute_definite_store(const ir::IrFunction &fn,
                                          ir::IrValueId target);

} // namespace analysis

#endif // ANALYSIS_FACTS_DEFINITE_STORE_H
