/**
 * @file bigo.h
 * @brief Subsistema de coste: analisis de complejidad algoritmica (Big-O).
 *
 * Modulo del MODO ANALISIS del compilador (opt-in, activado por
 * @c vm --analyze).  Es un subsistema PARALELO: NO afecta el codegen
 * normal (interp/JIT/AOT) ni el path de compilacion estandar.  Mide el
 * coste computacional del codigo Vesta sobre el SSA IR.
 *
 * Niveles ("Subsistema de coste / Big-O"):
 *   1. ESTATICO ESTRUCTURAL (este modulo, increment 1): sobre el
 *      @c ir::IrFunction sin ejecutar.  Detecta loops via back-edges del
 *      CFG -> grado polinomico segun profundidad de anidamiento; detecta
 *      recursion (la fn se llama a si misma) -> O(n) lineal, con intento
 *      best-effort de reconocer el patron divide-y-venceras -> O(n log n).
 *      Conservador: donde no reconoce, devuelve O(?).
 *   2. ESTATICO sobre el CODIGO FINAL (mismo algoritmo, sobre el IR
 *      post-optimizador): complejidad EFECTIVA tras inline/loop-elim.
 *      Hoy ambos niveles usan la misma funcion porque el modo --analyze
 *      consume el IR ya optimizado (O2).  El hook para diferenciarlos
 *      queda en @c analyze_module (pasar dos IrModules).
 *   3. EMPIRICO (--measure): ejecuta con tamanos crecientes contando
 *      instrucciones y ajusta la clase de complejidad.  DISENO documentado
 *      en bigo.cpp; el hook @c MeasureResult queda reservado.
 *
 * El resultado @c CostResult es una estructura de DATOS para que un
 * renderer de diagramas (Graphviz/Mermaid/HTML, ver src/vx/*_diagrams.cpp)
 * lo consuma.  @c cost_result_to_json produce la forma serializada.
 */
#ifndef VESTA_ANALYZE_BIGO_H
#define VESTA_ANALYZE_BIGO_H

#include <cstdint>
#include <string>
#include <vector>

namespace analysis {
namespace asa {
/// Lo que el compilador sabe del modulo.  Declarado y no incluido: el coste lo
/// CONSULTA, no lo construye.
class FactStore;
} // namespace asa
} // namespace analysis

namespace ir {
struct IrFunction;
struct IrModule;
} // namespace ir

namespace analyze {

/**
 * @brief Confianza del analizador en la cota inferida.
 *
 * Critico para la VALIDACION CONSERVADORA: solo se avisa de una
 * discrepancia con @c @complexity cuando la confianza es @c EXACT (el
 * analizador esta seguro de la cota).  Con @c UNKNOWN nunca se avisa.
 */
enum class Confidence : uint8_t {
    EXACT = 0, ///< cota cerrada, alta confianza (e.g. 2 loops -> O(n^2)).
    HEURISTIC, ///< inferida por heuristica (e.g. recursion -> O(n)).
    UNKNOWN    ///< no se pudo determinar (O(?)); nunca genera warning.
};

/**
 * @brief Clase de complejidad canonica reconocida por el analizador.
 *
 * Forma un orden total (de menor a mayor coste) que permite COMPARAR
 * la cota inferida contra la declarada en @c @complexity.
 */
enum class CostClass : uint8_t {
    O_1 = 0,  ///< O(1) constante
    O_LOGN,   ///< O(log n)
    O_N,      ///< O(n) lineal
    O_NLOGN,  ///< O(n log n)
    O_N2,     ///< O(n^2)
    O_N3,     ///< O(n^3)
    O_NK,     ///< O(n^k) polinomico, k > 3
    O_2N,     ///< O(2^n) exponencial
    O_UNKNOWN ///< desconocida (O(?))
};

/// @brief Devuelve la forma legible canonica de una clase (e.g. "O(n^2)").
const char *cost_class_str(CostClass c);

/**
 * @brief Nombre de una confianza (@c "exacta", @c "heuristica",
 *        @c "desconocida").
 *
 * Existia y no estaba declarada, asi que quien la necesitaba fuera del modulo
 * -- el servidor de lenguaje -- mandaba el numero del enum.  Un "2" no dice
 * nada a quien lee el informe, y ademas obligaba a que el otro lado supiera la
 * numeracion: dos sitios sabiendo lo mismo, que es como empiezan a discrepar.
 *
 * @param c Confianza.
 * @return Su nombre.
 */
const char *confidence_str(Confidence c);

/**
 * @brief Normaliza una expresion de coste textual a una @c CostClass.
 *
 * Acepta las formas que el parser captura en @c @complexity:
 *   O(1), O(n), O(n^2), O(n^3), O(n log n), O(log n), O(2^n), O(n*m)
 * (insensible a mayusculas y a espacios).  @c O(n*m) se mapea a O(n^2)
 * como aproximacion de coste polinomico de grado 2 con dos variables.
 * Lo desconocido -> @c O_UNKNOWN.
 */
CostClass parse_cost_class(const std::string &expr);

/**
 * @brief Coste de un loop individual dentro de una funcion.
 *
 * Dato estructural para los diagramas (anotar cada loop con su grado de
 * anidamiento y la clase polinomica que aporta).
 */
struct LoopCost {
    uint32_t header_block = 0; ///< id del bloque cabecera del loop (back-edge).
    uint32_t depth = 1;       ///< profundidad de anidamiento (1 = mas externo).
    uint32_t source_line = 0; ///< linea fuente aproximada (0 = desconocida).
};

/**
 * @brief Una llamada (CALL/TAILCALL) dentro del cuerpo de una funcion,
 *        anotada con la profundidad de loop EN LA QUE OCURRE.
 *
 * Es la informacion clave para la composicion interprocedural: el coste
 * del callee se multiplica por n^depth (el factor de los loops que
 * contienen el call site).
 */
struct CallSite {
    std::string callee;      ///< nombre de la funcion invocada (func_name).
    uint32_t loop_depth = 0; ///< profundidad de loop del call site (0 = top).
};

/**
 * @brief Resultado del analisis de coste de UNA funcion.
 *
 * Estructura de datos consumible por:
 *   - el modo --analyze (impresion legible + validacion del contrato);
 *   - un renderer de diagramas (via @c cost_result_to_json).
 *
 * Distingue DOS niveles de coste:
 *   - PARCIAL (@c big_o): el coste del CUERPO de la funcion tratando cada
 *     CALL a otra funcion como O(1) unitario.
 *   - TOTAL (@c total_class): el coste componiendo transitivamente el coste
 *     de las funciones que llama (call-graph bottom-up).  Solo se llena
 *     tras @c analyze_module_interproc; antes vale igual que el parcial.
 */
struct CostResult {
    std::string function;             ///< nombre de la funcion analizada.
    CostClass big_o = CostClass::O_1; ///< clase PARCIAL (cuerpo, calls=O(1)).
    Confidence confidence =
        Confidence::EXACT;          ///< confianza en la cota parcial.
    uint32_t max_loop_depth = 0;    ///< maxima profundidad de loop.
    bool is_recursive = false;      ///< la fn se llama a si misma.
    bool is_divide_conquer = false; ///< patron divide-y-venceras.
    std::vector<LoopCost> loops;    ///< coste por loop (diagramas).
    std::string detail;             ///< explicacion legible breve.

    /// Coste TOTAL (interprocedural): el cuerpo compuesto con el coste TOTAL
    /// de los callees.  Igual al parcial hasta que corre la composicion.
    CostClass total_class = CostClass::O_1;
    Confidence total_confidence = Confidence::EXACT; ///< confianza del total.
    std::string total_detail; ///< explicacion legible del total.

    /// Call sites del cuerpo (callee + profundidad de loop), para que la
    /// composicion interprocedural sepa que coste multiplicar por que factor.
    std::vector<CallSite> calls;

    /// Contrato declarado por el usuario (@complexity), si lo hay.
    /// @c declared_expr/@c declared_class corresponden a la dimension que
    /// este @c CostResult representa (PARCIAL o TOTAL del modulo PRE o POST
    /// que se analizo).  Para los 4 contratos crudos (independientes del
    /// nivel) ver los campos @c decl_* de abajo.
    std::string declared_expr; ///< vacio => sin contrato.
    CostClass declared_class =
        CostClass::O_UNKNOWN; ///< parseado de declared_expr.
    /// true si HAY contrato Y el analizador esta CONFIADO de que la cota
    /// real difiere de la declarada.  Validacion conservadora: solo se
    /// pone a true con @c confidence == EXACT y clases distintas.  Se
    /// compara contra el coste TOTAL (la complejidad real efectiva).
    bool contract_mismatch = false;

    /// Contratos por DIMENSION declarados en @complexity (texto crudo tal
    /// como lo escribio el usuario; vacio => esa dimension no se declara).
    /// Son los MISMOS cuatro valores en el CostResult PRE y en el POST de
    /// una funcion (viajan en la IrFunction).  La VALIDACION de cada
    /// dimension la hace el consumidor (main.cpp) que dispone de los cuatro
    /// costes inferidos (PARCIAL/TOTAL x PRE/POST).
    std::string decl_partial_pre;
    std::string decl_partial_post;
    std::string decl_total_pre;
    std::string decl_total_post;
};

/// @brief Resultado del analisis de un modulo completo.
struct ModuleCost {
    std::vector<CostResult> functions;
};

/**
 * @brief Analiza el coste estatico estructural de una funcion (nivel 1/2).
 *
 * Recorre el CFG de @c fn: cuenta loops (back-edges) y su anidamiento,
 * detecta recursion (CALL/TAILCALL a su propio nombre) e intenta el
 * patron divide-y-venceras.  Compara contra @c fn.complexity_expr si la
 * funcion declara un contrato (validacion conservadora).
 *
 * @param fn  Funcion IR a analizar (no se modifica).
 * @return    Resultado de coste con la cota inferida + estado del contrato.
 *
 * @param facts Lo que el ASA sabe del modulo, o nulo.
 *
 *        Con hechos, un bucle cuyas vueltas estan DEMOSTRADAS constantes deja
 *        de contar como profundidad: da las mismas vueltas den lo que den las
 *        entradas, asi que multiplica por una constante y no por `n`.  Sin
 *        ellos se comporta como siempre -- estructural puro --, que es lo
 *        correcto para quien llama sin ASA.
 *
 *        No lo deduce por su cuenta: quien cuenta vueltas es el dominio de
 *        bucles, y el coste es un consumidor mas.  Con dos respuestas a la
 *        misma pregunta, una se queda vieja sin que nadie se entere.
 *
 * @param stage MOMENTO del que es @p fn (@c analysis::asa::kStage*).  Es
 *        obligatorio con hechos, y no un detalle: un hecho de bucle nombra su
 *        cabecera por ID DE BLOQUE y el optimizador los renumera, asi que uno
 *        de antes leido sobre el codigo de despues no habla de un bloque
 *        parecido -- habla de OTRO --.
 */
CostResult analyze_function(const ir::IrFunction &fn,
                            const analysis::asa::FactStore *facts = nullptr,
                            const char *stage = nullptr);

/**
 * @brief Analiza el coste de todas las funciones de un modulo (PARCIAL).
 *
 * Salta los stubs nativos (@c is_native) y las funciones macro-compiladas
 * (existen solo en compile-time).  Conserva el orden de @c mod.functions.
 * Solo computa el coste PARCIAL (cuerpo, calls=O(1)); el coste TOTAL queda
 * igual al parcial salvo que se llame despues @c compose_interproc.
 */
ModuleCost analyze_module(const ir::IrModule &mod,
                          const analysis::asa::FactStore *facts = nullptr,
                          const char *stage = nullptr);

/**
 * @brief Composicion interprocedural: rellena @c total_class / @c
 *        total_confidence de cada @c CostResult de @c mc usando el
 *        call-graph del modulo.
 *
 * Algoritmo (bottom-up sobre el call-graph, con memoizacion y deteccion de
 * ciclos):
 *   - El coste TOTAL de @c f = MAX (clase dominante) sobre todos sus call
 *     sites del coste-TOTAL del callee multiplicado por @c n^loop_depth del
 *     call site, combinado tambien con el coste PARCIAL de @c f (sus propios
 *     loops/recursion).  En Big-O sumar terminos = tomar el dominante.
 *   - Recursion / ciclos en el call-graph: conservador, se usa el coste
 *     PARCIAL de @c f (no se entra en bucle infinito; se marca visitado).
 *   - Callees externos / nativos sin cuerpo: O(1) por defecto, salvo que
 *     declaren @c @complexity (se respeta su clase declarada).
 *
 * La validacion del contrato (@c contract_mismatch) se RE-evalua contra el
 * coste TOTAL (la complejidad efectiva real), de forma conservadora.
 *
 * @param mc   Resultado de @c analyze_module (se modifica in-place).
 */
void compose_interproc(ModuleCost &mc);

/**
 * @brief Serializa un @c CostResult a JSON (hook para diagramas).
 *
 * Forma estable para que un renderer de diagramas (Graphviz/Mermaid/HTML)
 * anote cada nodo-funcion con su coste.  Sin dependencias externas: emite
 * el JSON a mano (claves: function, big_o (parcial), total, confidence,
 * total_confidence, max_loop_depth, is_recursive, declared, mismatch,
 * calls[], loops[]).
 */
std::string cost_result_to_json(const CostResult &r);

/// @brief Serializa un @c ModuleCost completo como array JSON.
std::string module_cost_to_json(const ModuleCost &m);

/**
 * @brief Etiqueta de coste compacta de una funcion (hook para diagramas).
 *
 * Busca la funcion @p name en @p mc y devuelve una linea legible con su
 * coste PARCIAL y TOTAL, e.g. "coste: parcial O(n) | total O(n^2)".  Si
 * la funcion declara @c @complexity y hay discrepancia confirmada,
 * añade un marcador "[!= declarada]".  Si la funcion no esta en @p mc
 * devuelve cadena vacia (el renderer no anota nada).  Pensada para
 * anexar al titulo del nodo-funcion en Graphviz/Mermaid/HTML.
 */
std::string cost_label_for_function(const ModuleCost &mc,
                                    const std::string &name);

} // namespace analyze

#endif // VESTA_ANALYZE_BIGO_H
