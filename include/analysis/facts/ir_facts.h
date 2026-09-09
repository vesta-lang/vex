/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/ir_facts.h
 * @brief HECHOS objetivos de una funcion IR: lo que se deriva con UN recorrido,
 *        SIN reticulo, punto-fijo ni interpretacion.  Es la base compartida que
 *        consumen todos los analisis (no re-recorren el IR).  Criterio: si
 *        necesita reticulo/punto-fijo/eleccion-de-precision es ANALISIS, no
 *        hecho -- por eso aqui NO hay efectos, points-to ni alias (eso lo
 * produce EffectAnalysis/AliasAnalysis sobre estos hechos).
 *
 * Incluye: def-use (value -> instr que lo define; value -> indice de
 * parametro), call-SITES estaticos + flag de llamada dinamica (el callgraph
 * RESUELTO es un analisis aparte), y estructura minima (bloques, back-edges =
 * bucles, recursion directa).  Se invalida al MUTAR el IR (default: solo
 * sobrevive a preserve-all).
 */
#ifndef VESTA_ANALYSIS_IR_FACTS_H
#define VESTA_ANALYSIS_IR_FACTS_H

#include <cstdint>
#include <string>
#include <vector>

namespace ir {
struct IrFunction;
struct IrInstr;
using IrValueId = uint32_t;
} // namespace ir

namespace analysis {

/// Marcador del analisis de hechos IR (identidad para el AnalysisManager).
struct IRFactsAnalysis {
    static char ID;
};

/// Hechos de una funcion.  Resultado value-type (sin gancho survives -> por
/// defecto solo sobrevive a preserve-all, correcto: cualquier mutacion del IR
/// invalida los def-use/CFG).
struct IrFacts {
    // --- def-use ---
    /**
     * @brief value id -> POSICIoN de la instruccion que lo define dentro de su
     *        bloque, o -1 si no la define ninguna.
     *
     * Con @ref def_block -- que dice en QUE bloque -- localiza la instruccion en
     * O(1).  Aqui habia un `std::vector<const ir::IrInstr *>`, y guardar
     * PUNTEROS era un riesgo real, no teorico:
     *
     * - **Un puntero colgante no se nota.**  La validez de estos hechos no
     *   estaba atada a ninguna version del IR, asi que servir unos viejos no era
     *   imprecision: era leer memoria liberada.  Un indice fuera de rango da
     *   `nullptr` -- falla SEGURO --, que es la diferencia entre "no lo se" y un
     *   resultado inventado.
     * - **Y con punteros dentro esto no se puede guardar en disco.**  Un
     *   analisis que no se puede persistir se rehace entero en cada
     *   compilacion, que es de donde sale que hoy se cacheen las CONCLUSIONES y
     *   no el RAZONAMIENTO.
     *
     * Que el indice caduque al mutar el IR no es peor que antes: estos hechos
     * ya se invalidan con cualquier mutacion (lo dice la nota de arriba y lo
     * hace cumplir la version de la funcion).  Lo que cambia es COMO fallan.
     */
    std::vector<int32_t> def_idx;
    /**
     * @brief La funcion que estos hechos describen.  NO la posee.
     *
     * Hace falta para resolver @ref def sin que quien pregunta tenga que llevar
     * la funcion a todas partes -- son once sitios --.  Al volver de disco se
     * vuelve a poner: es lo unico que hay que rehidratar.
     *
     * @warning Sigue siendo UN puntero, y conviene no vender el arreglo por mas
     * de lo que es.  Lo que desaparece son los N punteros a INSTRUCCIONES, que
     * es el caso que mordia: insertar o borrar una instruccion realoja el
     * vector del bloque y los deja colgando en una mutacion NORMAL.  Este otro
     * solo cuelga si muere o se mueve la funcion entera, que es una pregunta de
     * vida distinta -- y la misma que ya gobierna la cache de la base --.
     */
    const ir::IrFunction *owner = nullptr;
    /**
     * @brief value id -> BLOQUE donde se define, -1 si no lo define nadie.
     *
     * La otra mitad de la misma pregunta: `def_of` dice QUE instruccion, esto
     * dice DONDE.  Se saca del mismo recorrido, asi que no cuesta nada de
     * mas, y hace falta para lo que se pregunta constantemente -- si un valor
     * es invariante en un bucle es, literalmente, si su bloque de definicion
     * cae fuera --.
     *
     * Estaba, pero repartido: el desenrollador, el resolvedor de punteros y
     * el reconocedor de memoria por lotes se lo construian CADA UNO por su
     * cuenta con el mismo doble bucle.  Tres recorridos por funcion para el
     * mismo hecho, que es justo lo que el ASA existe para no hacer.
     */
    std::vector<int32_t> def_block;
    std::vector<int32_t>
        param_of; ///< value id -> indice de parametro, -1 si no.

    // --- call-sites (sintacticos; el callgraph resuelto es otro analisis) ---
    std::vector<std::string>
        static_callees;            ///< nombres de CALL/TAILCALL estaticos.
    bool has_dynamic_call = false; ///< CALLVIRT/CALLN/CALLIND/...

    // --- estructura ---
    uint32_t block_count = 0;
    uint32_t loop_count = 0; ///< back-edges (aproximacion de bucles).
    bool recursive = false;  ///< se llama a si misma directamente.

    /// value id -> alguien lo LEE (aparece como operando).
    ///
    /// Con la def y el parametro completa la unica pregunta que importa antes
    /// de analizar nada: @ref exists.  Sale del mismo recorrido, asi que no
    /// cuesta una pasada mas.
    std::vector<uint8_t> used;

    /// Cuantos valores describen estos hechos.
    size_t value_count() const { return def_idx.size(); }

    /**
     * @brief La instruccion que define @p v, o @c nullptr si no la hay.
     *
     * O(1): el bloque sale de @ref def_block y la posicion de @ref def_idx.
     * Comprueba los limites en vez de fiarse -- un indice de un IR que ya
     * cambio tiene que dar "no lo se", no una instruccion cualquiera --.
     *
     * Fuera de linea porque necesita la definicion completa del intermedio, y
     * esta cabecera lo declara ADELANTADO a proposito: meterla aqui obligaria a
     * arrastrar la cabecera gorda del IR a todo el que solo quiera preguntar
     * por los hechos de una funcion.
     */
    const ir::IrInstr *def(ir::IrValueId v) const;
    int32_t param_index(ir::IrValueId v) const {
        return v < param_of.size() ? param_of[v] : -1;
    }
    /**
     * @brief EXISTE este valor en el codigo que se esta mirando?
     *
     * La tabla de valores de una funcion no encoge cuando el optimizador borra
     * una instruccion: la ranura se queda, sin nada que la defina y sin nadie
     * que la lea.  Preguntarle algo a esa ranura es trabajo sobre un dato
     * muerto, y peor, se contesta -- el resolutor de punteros respondia "no
     * tiene definicion aqui, asi que viene de fuera", que es FALSO: no viene de
     * ningun sitio porque ya no esta.
     *
     * Un valor existe si algo lo define, si es un parametro (lo define la
     * llamada) o si alguien lo lee.  Lo ultimo es lo que distingue al que de
     * verdad viene de fuera -- ese SI se usa -- del hueco que quedo.
     */
    bool exists(ir::IrValueId v) const {
        /* Mira @ref def_idx y no @ref def: "algo lo define" es que haya indice,
         * y asi esto se queda en linea y sin tocar el intermedio.  Se pregunta
         * una vez por valor en los recorridos de memoria y de rangos. */
        return (v < def_idx.size() && def_idx[v] >= 0) || param_index(v) >= 0 ||
               (v < used.size() && used[v] != 0);
    }
};

/// Construye los hechos de @p fn (un recorrido).
IrFacts build_ir_facts(const ir::IrFunction &fn);

// ===========================================================================
//  Guardarlos y recuperarlos entre compilaciones
// ===========================================================================
//
// Estas dos viven AQUI, junto al analisis, y no en el almacen: el almacen es
// generico y no conoce a ningun analisis, y quien sabe que hay que escribir --
// y sobre todo que hay que REHIDRATAR -- es el propio.
//
// @see analysis/manager/analysis_store.h

/// Nombre estable con el que este analisis se identifica en el almacen.
extern const char *const kIrFactsAnalysisName;

/**
 * @brief Version del FORMATO de @ref serialize_ir_facts.
 *
 * Sube cuando cambie lo que se escribe.  Es propia y no global a proposito:
 * cambiar este analisis no puede tirar lo guardado de los demas.  Y entra en la
 * clave, asi que lo escrito por una version anterior no se llega a leer -- que
 * es lo unico que importa, porque interpretarlo como propio no daria error,
 * daria hechos inventados.
 */
constexpr uint32_t kIrFactsFormat = 1;

/// Empaqueta @p f en bytes.  No escribe @c owner: es un puntero y se rehidrata.
std::vector<uint8_t> serialize_ir_facts(const IrFacts &f);

/**
 * @brief Reconstruye en @p out lo empaquetado por @ref serialize_ir_facts.
 *
 * @param data  Bytes leidos del almacen.
 * @param n     Cuantos.
 * @param owner La funcion que describen.  Es lo UNICO que hay que rehidratar,
 *              y va aqui y no despues para que no se pueda olvidar: unos hechos
 *              con @c owner nulo contestan `nullptr` a todo, que se lee como
 *              "esta funcion no define nada" -- correcto de tipo y falso de
 *              contenido.
 * @return @c false si los bytes no cuadran; entonces @p out queda intacto y
 *         quien pregunta computa, que es lo de siempre.
 */
bool deserialize_ir_facts(const uint8_t *data, size_t n,
                          const ir::IrFunction &owner, IrFacts &out);

} // namespace analysis

#endif // VESTA_ANALYSIS_IR_FACTS_H
