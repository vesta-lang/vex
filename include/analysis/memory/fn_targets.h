/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/memory/fn_targets.h
 * @brief A que funcion apunta un puntero a funcion, y donde acaba su direccion.
 *
 * "No se a quien llama esto" es una respuesta demasiado facil.  Muchas veces la
 * informacion ESTA en el modulo y solo hay que seguirla: la direccion se toma
 * en un sitio, viaja por un par de copias, y se llama en otro.  Rendirse ahi
 * obliga a cualquier consumidor a suponer lo peor sobre codigo que se puede
 * leer entero.
 *
 * Dos preguntas, que son las dos caras de lo mismo:
 *
 *   DESDE LA LLAMADA   `¿a que funcion apunta este valor?`  La usa quien esta
 * en un `call` indirecto y quiere el destino concreto. DESDE LA FUNCION   `¿se
 * ven TODOS los sitios que pueden llamarme?`  La usa quien quiere afirmar algo
 * sobre los parametros, que solo es licito conociendo a todos los llamantes.
 *
 * El limite esta declarado, no escondido: se sigue por copias,
 * reinterpretaciones y huecos escritos UNA sola vez.  En cuanto la direccion se
 * guarda en un sitio que se escribe mas de una vez, se pasa como argumento o se
 * devuelve, se dice que no se sabe.  Es preferible quedarse corto a afirmar de
 * mas: sobre esto se apoyan comprobaciones que pueden rechazar un programa.
 */
#ifndef ANALYSIS_MEMORY_FN_TARGETS_H
#define ANALYSIS_MEMORY_FN_TARGETS_H

#include "analysis/asa/fact.h" // UnknownReason: por que no se supo
#include "analysis/facts/ir_facts.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ir {
struct IrFunction;
struct IrInstr;
struct IrModule;
} // namespace ir

namespace analysis {

/**
 * @brief POR QUE no se pudo decir a donde apunta.  Solo vale con nombre vacio.
 *
 * El resolvedor tiene SIETE formas de rendirse y todas devolvian la misma
 * cadena vacia.  Quien pregunta -- la devirtualizacion, el inline, el analisis
 * de efectos -- no podia distinguirlas, y de la diferencia depende que puede
 * hacer:
 *
 *   - dos caminos con destinos distintos, o un hueco escrito varias veces, son
 *     `RuntimeDependent`: hay algo concreto que especular con guarda, y ahi es
 *     donde nace una cache de llamada;
 *   - una op que no modelamos es `ShapeNotRecognized`: el programa esta bien y
 *     es el analisis el que hay que ampliar;
 *   - un valor sin definicion viene de FUERA (`OpaqueBoundary`);
 *   - y pararse a los 16 saltos es `BudgetExceeded`: ni una cosa ni la otra.
 *
 * Con una cadena vacia, los cuatro se trataban igual: no especular nunca.
 */
struct FnTargetUnknown {
    asa::UnknownReason reason = asa::UnknownReason::NotAsked;
    /// Codigo estable del caso EXACTO, del vocabulario de este dominio.
    const char *code = "";
};

/**
 * @brief Nombre de la funcion a la que apunta @p v, o cadena vacia.
 *
 * Vacio significa "no se puede afirmar", nunca "no apunta a nada".
 *
 * @param why Opcional: si se da y el nombre sale vacio, recibe POR QUE.
 */
std::string pointed_function(const ir::IrFunction &fn, const IrFacts &facts,
                             ir::IrValueId v, FnTargetUnknown *why = nullptr);

/// Un sitio desde el que se llama, cuando la llamada es indirecta.
struct IndirectSite {
    const ir::IrFunction *fn = nullptr;
    const ir::IrInstr *instr = nullptr;
};

/// Que pasa con la direccion de una funcion en todo el modulo.
struct AddressTaken {
    /// Si su nombre aparece en algun sitio que no sea un `call` directo.
    bool taken = false;
    /// Si TODOS esos sitios acaban en llamadas indirectas que se ven.  Cuando
    /// es cierto, la lista de abajo completa el censo de llamantes.
    bool all_visible = false;
    std::vector<IndirectSite> indirect;
};

/**
 * @brief Sigue la direccion de @p name por todo @p mod.
 *
 * Responde si se pueden enumerar todos sus llamantes, y cuales son los
 * indirectos.  Los directos los ve cualquiera buscando `call`.
 */
AddressTaken follow_address(const ir::IrModule &mod, const std::string &name);

/**
 * @brief Lo mismo para VARIOS nombres a la vez, recorriendo el modulo UNA vez.
 *
 * Preguntar de uno en uno recorre el modulo entero por cada nombre, con una
 * comparacion de cadena en cada instruccion.  Quien pregunta suele tener ya la
 * lista completa -- los resumenes de frontera la tienen --, y entonces el coste
 * pasa de "nombres por instrucciones" a "instrucciones", porque cada
 * instruccion se resuelve con una consulta a tabla en vez de con una
 * comparacion por nombre.
 *
 * Los bloques de ensamblador siguen mirandose nombre a nombre: ahi no hay
 * simbolo que consultar, solo texto donde buscar.  Pero son pocos, y el coste
 * pasa a ser "nombres por bloques de asm" en lugar de por el modulo entero.
 *
 * @return Una entrada por cada nombre pedido, con el mismo contenido que daria
 *         @c follow_address llamada por separado.
 */
std::unordered_map<std::string, AddressTaken>
follow_addresses(const ir::IrModule &mod,
                 const std::unordered_set<std::string> &names);

} // namespace analysis

#endif // ANALYSIS_MEMORY_FN_TARGETS_H
