/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file comptime_collect.h
 * @brief Recolector del "conjunto comptime" de un modulo (P1 fase 1).
 *
 * Identifica TODO el codigo que se evalua en compile-time (comptime fns,
 * @Macros, globales comptime/const) y sus dependencias TRANSITIVAS (funciones
 * no-comptime que ese codigo llama).  Es el primer paso de la migracion "todo
 * comptime corre en la ComptimeVM": el conjunto recolectado es lo que se
 * compilara en un ARTEFACTO SEPARADO y se cargara en la ComptimeVM antes del
 * modulo, para resolver todos los call sites comptime por ejecucion real (sin
 * el tree-walker AST y sin el path "block -> module_init").
 *
 * Analisis PURO: no muta el AST ni el estado del compilador.
 */

#ifndef VX_COMPTIME_COLLECT_H
#define VX_COMPTIME_COLLECT_H

#include <ostream>
#include <string>
#include <unordered_set>
#include <vector>

#include "vx/ast.h"

namespace vx {

/**
 * @brief Descriptor del conjunto de codigo comptime de un modulo.
 *
 * Las cuatro listas son disjuntas por categoria; @c helper_deps son las
 * funciones NO-comptime que el codigo comptime necesita para ejecutarse en la
 * ComptimeVM (deben viajar en el mismo artefacto).
 */
struct ComptimeUnit {
    std::vector<std::string> comptime_fns;    ///< `comptime fn` (no @Macro).
    std::vector<std::string> macros;          ///< `@Macro`.
    std::vector<std::string> comptime_consts; ///< globales `comptime`/`const`.
    /**
     * @brief Lo que el codigo comptime llama y NO esta en este modulo.
     *
     * Viene de otro por un `import`.  El cierre de aqui es LOCAL -- solo ve las
     * decls de este fichero --, asi que estas se perdian: la funcion no viajaba
     * en el conjunto de quien la DEFINE, y al compilar el conjunto el modulo
     * que la exporta ya no la tenia ("el modulo 'atomic' no exporta
     * 'vx_cpu_relax'").  Publicarlas deja que quien orquesta cierre el circulo:
     * junta las de todos y vuelve a pedir el conjunto de cada modulo diciendole
     * que ademas incluya las suyas.
     */
    std::vector<std::string> external_calls;
    std::vector<std::string> helper_deps; ///< fns no-comptime llamadas por el
                                          ///< codigo comptime (transitivo).

    /// FNV-1a 64 del TEXTO FUENTE de todas las decls del conjunto (comptime +
    /// deps).  Es la CLAVE DE CACHE del futuro artefacto comptime separado:
    /// cambia si y solo si cambia alguna decl comptime o una dep; los cambios
    /// en codigo no-comptime (main, helpers no usados por comptime) NO lo
    /// alteran -> el artefacto comptime se reusa entre builds.  0 si @c
    /// empty().
    uint64_t content_hash = 0;

    /// TEXTO FUENTE del conjunto: los `import` del modulo mas las decls
    /// comptime y sus dependencias, en orden de aparicion.  Es lo que hay que
    /// compilar para producir el artefacto comptime SEPARADO, y sale del mismo
    /// recorrido que computa @c content_hash (los spans se calculaban ya y se
    /// tiraban).  Los `import` viajan porque sin ellos el texto no compila por
    /// si solo, pero NO entran en el hash: anadir un import que el codigo
    /// comptime no usa no debe invalidar el cache.  Vacio si @c source estaba
    /// vacio o el conjunto es @c empty().
    std::string unit_source;

    /**
     * @brief Declaraciones comptime que el recolector VIO y NO se llevo.
     *
     * No saber algo es un resultado y se dice POR QUE.  Sin esto, un conjunto
     * vacio se lee igual en los dos casos que hay -- "este modulo no tiene nada
     * comptime" y "tiene comptime de una forma que no recojo" -- y son
     * opuestos: el primero es correcto y el segundo deja al artefacto sin algo
     * que hace falta.  Y no da error: da un artefacto incompleto, que falla
     * mucho mas tarde y lejos de aqui.
     *
     * Hoy la unica forma conocida es el CONSTRUCTOR comptime de un struct
     * (`comptime T(expr)`), que es un metodo de tipo y no una declaracion de
     * nivel superior.  Que hoy funcione no contradice esto: funciona porque el
     * artefacto es el PROGRAMA ENTERO y su bytecode esta dentro por eso.  En
     * cuanto el artefacto sea la particion, deja de estarlo.
     */
    std::vector<std::string> not_collected;

    /// @return true si el modulo no tiene nada comptime QUE ESTE RECOLECTOR
    /// RECOJA.  Ojo: no es lo mismo que "no tiene comptime" -- para eso hay que
    /// mirar ademas @c not_collected.
    bool empty() const {
        return comptime_fns.empty() && macros.empty() &&
               comptime_consts.empty();
    }
};

/**
 * @brief Recolecta el conjunto comptime del modulo.
 *
 * Clasifica las decls top-level y hace un BFS sobre los cuerpos del codigo
 * comptime para arrastrar las funciones llamadas (dependencias) que no son
 * ellas mismas comptime.  El cierre transitivo garantiza que el artefacto
 * separado sea auto-suficiente.
 *
 * @param mod    Modulo ya parseado (post-namespace-flatten preferentemente,
 *               para que los nombres esten mangled y las llamadas resuelvan).
 * @param source Texto fuente original del modulo.  Si no esta vacio, se computa
 *               @c content_hash a partir de los spans de las decls del
 *               conjunto (clave de cache del artefacto).  Vacio -> hash 0.
 * @return El conjunto comptime.  @c empty() si no hay nada que compilar aparte.
 */
ComptimeUnit
collect_comptime_unit(const ast::ModuleNode &mod,
                      const std::string &source = "",
                      const std::unordered_set<std::string> *tambien = nullptr);

/**
 * @brief Vuelca el conjunto a un stream, legible, para diagnostico.
 *
 * Activado por el driver via la env var @c VESTA_DUMP_COMPTIME_UNIT=1.
 */
void dump_comptime_unit(const ComptimeUnit &u, std::ostream &os);

} // namespace vx

#endif // VX_COMPTIME_COLLECT_H
