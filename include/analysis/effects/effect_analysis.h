/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/effects/effect_analysis.h
 * @brief Gestor de analisis de efectos: DOS niveles.  (a) efecto LOCAL por nodo
 *        IR, barato y CACHEADO, invalidado cuando el nodo muta; (b) resumen por
 *        FUNCION, resultado de un pase de punto-fijo sobre el callgraph.  Los
 *        optimizadores y el tooling preguntan aqui; NUNCA re-leen el IR ni
 *        computan efectos por su cuenta (ese es el invariante que garantiza que
 *        `--analyze`, diagramas y LSP muestren lo mismo que consume el
 * compilador).
 *
 * Invalidacion (especificada desde el inicio para evitar bugs de staleness):
 *   mutacion del IR de un nodo
 *     -> invalidate_node(node)         (borra el cache local del nodo)
 *     -> invalidate_function(fn)       (el summary de la funcion queda sucio)
 *     -> invalidate transitiva por el callgraph (los callers dentro de la SCC y
 *        aguas arriba tambien quedan sucios)
 *   El recomputo es perezoso: summary(fn) recomputa si esta sucio.
 *
 *   esqueleto (interfaz + cache local + invalidacion).  La logica de
 * `local(node)` (mapa IrOp -> SemanticEffects) entra en Fase 1; el punto-fijo
 * de `summary(fn)` en Fase 2.
 */
#ifndef ANALYSIS_EFFECTS_EFFECT_ANALYSIS_H
#define ANALYSIS_EFFECTS_EFFECT_ANALYSIS_H

#include "analysis/effects/effects.h"
#include "analysis/effects/ir_effects.h"
#include "analysis/effects/summary.h"
#include "analysis/facts/ir_facts.h"
#include "analysis/facts/range_summary.h"
#include "analysis/facts/value_range.h"
#include "analysis/manager/analysis_manager.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ir {
struct IrModule;
struct IrFunction;
struct IrInstr;
} // namespace ir

namespace analysis {
namespace effects {

/**
 * @brief Gestor de analisis de efectos de un modulo IR.  Mantiene el cache
 *        local por nodo y los summaries por funcion, con invalidacion.
 */
class EffectAnalysis {
  public:
    EffectAnalysis() = default;

    /// Efecto LOCAL de un nodo IR (intrinseco al opcode + operandos). Cacheado.
    /// Fase 1 rellena el mapeo real; Fase 0 devuelve el neutro Complete.
    EffectAnalysisResult local(const ir::IrFunction &fn,
                               const ir::IrInstr &ins);

    /**
     * @brief Presta los rangos de una funcion que el llamante YA tiene.
     *
     * Sin esto, el efecto de cada bloque de asm los recalcula recorriendo la
     * funcion entera: medido con las pilas de VTune, el 22,7 % del tiempo de
     * compilar un programa con mucho ensamblador.  Van con su dueno para que
     * usarlos en otra funcion sea imposible (ver @c EffectEnv::rangos_de).
     *
     * @param fn      Funcion de la que son.  Nulo los retira.
     * @param rangos  Sus rangos.  Deben seguir vivos mientras esten prestados.
     */
    void prestar_rangos(const ir::IrFunction *fn,
                        const analysis::RangeFacts *rangos) {
        env_.rangos = rangos;
        env_.rangos_de = fn;
    }

    /**
     * @brief Los resumenes de frontera que debe usar al calcular rangos.
     *
     * Sin ellos, un parametro vale lo que su tipo y el resultado de una llamada
     * es desconocido: todo lo que cruza una funcion queda sin acotar.  Quien
     * los tenga calculados hace bien en darlos, y por dos motivos.
     *
     * El primero es PRECISION: los rangos salen mas estrechos, y de ellos vive
     * points-to.
     *
     * El segundo es que asi hay UN productor de rangos y no dos.  El
     * comprobador de limites los pedia por su cuenta con los resumenes puestos
     * mientras el motor los calculaba sin ellos, o sea que el mismo analisis
     * corria dos veces sobre cada funcion respondiendo a preguntas distintas.
     *
     * Deben seguir vivos mientras el motor los use.  Nulo vuelve a no usarlos.
     */
    void usar_resumenes(const analysis::RangeSummaries *r) { resumenes_ = r; }

    /**
     * @brief Que memoria DEL LLAMANTE toca un sitio de llamada concreto.
     *
     * El efecto de una funcion habla de sus parametros; aqui se sustituyen por
     * los argumentos de ESTA llamada, con lo que pasa a hablar de la memoria
     * del que llama -- que es la unica donde se puede juzgar si un acceso cabe.
     *
     * Va aparte de @ref local a proposito: el efecto local de una llamada es
     * ceder el control, y meterle dentro lo que hace el destino convertiria el
     * calculo del cierre en una definicion circular.  Esto es una PROYECCION
     * sobre un cierre ya calculado, no una parte de el.
     *
     * @param caller Funcion donde esta la llamada.
     * @param call   La instruccion de llamada.
     * @return Lo que la llamada toca de la memoria de @p caller.  Vacio y NO
     *         completo si no hay resumen del destino (una funcion de fuera del
     *         programa, o un destino que no se conoce): no saber lo que hace no
     *         es saber que no hace nada.
     */
    EfectoEnLlamada at_call_site(const ir::IrFunction &caller,
                                 const ir::IrInstr &call);

    /// Resumen COMPLETO de una funcion (efectos local/closure + estructura +
    /// interproc).  Recomputa por punto-fijo si esta sucio.  Fase 2 rellena la
    /// logica; Fase 0 devuelve un summary vacio Complete.
    const FunctionSummary &summary(const ir::IrModule &mod,
                                   const ir::IrFunction &fn);

    /// Resumen del modulo entero (mapa symbol -> summary).
    const ModuleSummary &module_summary(const ir::IrModule &mod);

    /// Resumen interprocedural de TODO UN PROGRAMA (varios modulos): el cierre
    /// del callgraph CRUZA fronteras de modulo -- un CALL a una funcion de otro
    /// modulo se resuelve contra el mapa COMBINADO (no como externa -> top). Es
    /// el analisis interprocedural A NIVEL DE MoDULOS; module_summary(mod) es
    /// el caso particular de un solo modulo.  Necesario para la compilacion
    /// SEPARADA (cuando el IR no viene ya fusionado): el consumidor pasa todos
    /// los modulos del programa (o sus summaries) y obtiene el cierre global.
    const ModuleSummary &
    program_summary(const std::vector<const ir::IrModule *> &mods);

    /// Lagunas de precision acumuladas (que ops faltan por modelar, donde la
    /// opacidad es fundamental).  Se puebla al construir los summaries.
    const EffectGaps &gaps() const { return gaps_; }

    /// Fija para QUE backend se analiza.  Invalida lo ya calculado: cambiar de
    /// backend cambia las respuestas, y devolver las de antes seria describir
    /// un programa que no es el que se va a ejecutar.
    void set_backend(Backend b) {
        if (env_.backend == b) return;
        env_.backend = b;
        local_cache_.clear();
        summary_cache_.clear();
        dirty_.clear();
        module_dirty_ = true;
    }
    Backend backend() const { return env_.backend; }

    /// Tabla points-to (con las extensiones de region) para quien la necesite
    /// FUERA del motor -- hoy el informe, que enseña las regiones.  Sale de la
    /// misma cache que usa el analisis: una sola tabla, no dos.
    const PointsTo &points_to_publico(const ir::IrFunction &fn) {
        return points_to_of(fn);
    }

    /// Los hechos fundacionales (def-use) de una funcion, por la misma razon y
    /// desde la misma cache.  Quien los reconstruye por su cuenta -- lo hacia
    /// el comprobador de limites -- paga otra vez lo que el motor ya tiene
    /// hecho.
    const IrFacts &facts_publico(const ir::IrFunction &fn) {
        return facts_of(fn);
    }

    /// Y los rangos, por lo mismo: son el hecho del que viven points-to y el
    /// comprobador de limites, y calcularlos es lo mas caro que hace el motor.
    /// Salen de la misma cache y con los mismos resumenes, de modo que los dos
    /// juzgan sobre exactamente la misma informacion.
    const RangeFacts &ranges_publico(const ir::IrFunction &fn) {
        return ranges_of(fn);
    }


    // ---- Invalidacion ----
    /// Un nodo muto: borra su cache local + marca su funcion sucia.
    void invalidate_node(const ir::IrFunction &fn, const ir::IrInstr &ins);
    /// Una funcion muto: su summary + el de sus callers transitivos quedan
    /// sucios.
    void invalidate_function(const std::string &fn_name);
    /// Borra TODO (reconstruccion completa).
    void clear();

  private:
    // Clave de nodo: (funcion, indice-de-instruccion estable).  En Fase 0
    // usamos la direccion del IrInstr como clave provisional; Fase 1 fija una
    // clave estable (id de instruccion) cuando el IR lo exponga.
    /// Resumenes de frontera con los que calcular rangos, si alguien los dio.
    /// Nulo = se calculan sin ellos, que es lo que valia antes de tenerlos.
    const analysis::RangeSummaries *resumenes_ = nullptr;
    std::unordered_map<const void *, EffectAnalysisResult> local_cache_;
    std::unordered_map<std::string, FunctionSummary> summary_cache_;
    std::unordered_map<std::string, bool> dirty_; // fn -> sucio
    ModuleSummary module_cache_;
    ModuleSummary program_cache_;
    EffectGaps gaps_;
    /// Lo declarado sobre las nativas del programa (lo llena build_summary con
    /// las declaraciones de los modulos que se le pasan).  Vacio = ninguna
    /// nativa declarada, que es como estaba antes de que se pudiera declarar.
    NativeDecls native_decls_;
    /// Entorno del analisis (backend + las declaraciones de arriba).  El
    /// backend lo fija quien pregunta: el mismo IR analizado para el AOT y para
    /// el interprete no da la misma respuesta.
    EffectEnv env_;
    bool module_dirty_ = true;

    /// Nucleo interprocedural COMPARTIDO: computa el summary (local + cierre
    /// por punto-fijo del callgraph) sobre las funciones de TODOS los @p mods.
    /// Un solo modulo -> module_summary; varios -> program_summary
    /// (cross-modulo).
    ModuleSummary build_summary(const std::vector<const ir::IrModule *> &mods);

    /// Gestor de analisis: cachea los IrFacts (hechos fundacionales) por
    /// funcion para no reconstruir el def-use en cada consulta.  EffectAnalysis
    /// es el primer consumidor del AnalysisManager.
    AnalysisManager facts_mgr_;
    const IrFacts &facts_of(const ir::IrFunction &fn);
    /// Tabla points-to cacheada por funcion (depende de IRFacts; el manager
    /// invalida en cascada cuando la funcion muta).
    const PointsTo &points_to_of(const ir::IrFunction &fn);
    /// Rangos de valor cacheados por funcion (los consume points-to y el
    /// comprobador de limites).
    const RangeFacts &ranges_of(const ir::IrFunction &fn);

    FunctionSummary compute_summary(const ir::IrModule &mod,
                                    const ir::IrFunction &fn);
};

} // namespace effects
} // namespace analysis

#endif // ANALYSIS_EFFECTS_EFFECT_ANALYSIS_H
