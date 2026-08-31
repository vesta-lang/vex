/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file inspector.h
 * @brief Inspector del ecosistema Vesta para el LSP (Fase 3).
 *
 * Implementa las peticiones a medida @c vesta/* que el editor llama
 * BAJO DEMANDA (el usuario pulsa "ver IR / bytecode / JIT / AOT / ...")
 * para visualizar cada fase del pipeline sobre el documento abierto:
 *
 *   - @c vesta/bytecode    -> texto @c .vel del modulo.
 *   - @c vesta/ir          -> SSA IR pre/post optimizacion.
 *   - @c vesta/complexity  -> coste Big-O por funcion (parcial + total).
 *   - @c vesta/diagram     -> diagrama AST/IR/VEL en mermaid/graphviz/html.
 *   - @c vesta/functions   -> lista de funciones (nombre + linea).
 *   - @c vesta/aotCompat   -> reporte de compatibilidad AOT (bare/embed/full).
 *   - @c vesta/jitAsm      -> desensamblado x86-64 del codigo JIT de una fn.
 *   - @c vesta/aotAsm      -> desensamblado x86-64 del codigo AOT de una fn.
 *
 * Diseno:
 *  - Reutiliza el @c CompileResult cacheado por @c AnalysisEngine para las
 *    vistas baratas (bytecode, ir-post, complexity, functions, aotCompat).
 *  - Para las vistas caras que exigen recompilar con flags concretos
 *    (ir-pre con @c emit_ir_preopt, diagramas con @c dump_*), mantiene una
 *    cache PROPIA por (uri, hash del texto, clave de la vista) para no
 *    recompilar en cada peticion identica.
 *  - El codigo nativo del JIT y del AOT se desensambla con Capstone
 *    (x86-64).  El subsistema JIT del inspector es PROPIO (CodeCache +
 *    RuntimeEntries + JitCompiler dedicados) para no interferir con el
 *    runtime; se instancia perezosamente en la primera peticion @c jitAsm.
 *  - TODA peticion se sirve bajo try/catch en el caller: ante un fallo el
 *    inspector devuelve un resultado con @c error / @c unsupported en lugar
 *    de propagar la excepcion (el servidor NUNCA muere).
 */

#ifndef VESTA_LSP_INSPECTOR_H
#define VESTA_LSP_INSPECTOR_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "json.hpp"

#include "lsp/analysis_engine.h"

namespace lsp {

class DocumentStore;

/**
 * @struct InspectTarget
 * @brief Target OS/arquitectura para las vistas del inspector.
 *
 * Permite ver el IR / bytecode / asm nativo / JIT / diagrama que el compilador
 * genera para un target concreto (Linux/Windows, x86-64/x86-32).  Campos vacios
 * => host (comportamiento previo).  El @c os selecciona las ramas
 * @c @Target("os:...") del fuente; @c arch determina el codegen nativo (x86-64
 * vs x86-32) y la ABI (SysV vs Win64) de las vistas de asm.
 */
struct InspectTarget {
    std::string os;   ///< "windows"|"linux"|"macos"; vacio = host.
    std::string arch; ///< "x86-64"|"x86-32"; vacio = "x86-64".
    /// Nivel de optimizacion con el que compilar la vista, 0..3.  -1 = el que
    /// use el analisis normal.  Mirar el mismo codigo a dos niveles es como se
    /// ve QUE hizo el optimizador, que es media pregunta de por que algo va
    /// como va.
    int opt = -1;
    /// Juego de instrucciones de coma flotante del codigo generado:
    /// "sse2"|"avx"|"avx512".  Vacio = el de por defecto.
    std::string float_isa;
    /// Microarquitectura concreta ("znver3", "skylake", ...).  Vacia = lo que
    /// se deduzca del juego de instrucciones.  Cambia lo que el generador se
    /// permite emitir, asi que forma parte de la identidad de la vista.
    std::string cpu;
    /// @return true si hay un override real (no es el host por defecto).
    bool active() const {
        return !os.empty() ||
               (!arch.empty() && arch != "x86-64" && arch != "x86_64");
    }
    /// @return true si algo de lo pedido cambia lo que se compila o se emite.
    bool any_override() const {
        return active() || opt >= 0 || !float_isa.empty() || !cpu.empty();
    }
    /// @return clave estable para el cache de vistas ("" si nada se cambio).
    std::string cache_key() const {
        if (!any_override()) return std::string();
        return "@" + os + "-" + arch + "-o" + std::to_string(opt) + "-" +
               float_isa + "-" + cpu;
    }
};

/**
 * @class Inspector
 * @brief Sirve las peticiones @c vesta/* del LSP (vistas del ecosistema).
 *
 * SE PUEDE USAR DESDE VARIOS HILOS: dos vistas de documentos distintos se
 * atienden a la vez.  Sus caches van con cerrojo, que solo se tiene para mirar
 * y guardar -- nunca mientras se compila, que es lo que se quiere solapar --.
 *
 * Cada metodo devuelve un @c nlohmann::json con la forma de respuesta del
 * protocolo (campos documentados en cada metodo); ante un error controlado
 * devuelve un objeto con @c {"error": "<motivo>"} para que el cliente lo
 * muestre sin tumbar la sesion.
 */
class Inspector {
  public:
    /**
     * @brief Construye el inspector sobre el motor de analisis y el almacen
     *        de documentos del servidor.
     * @param engine Motor de analisis (cache del CompileResult).  Debe vivir
     *               mas que el inspector.
     * @param docs   Almacen de documentos abiertos.  Debe vivir mas que el
     *               inspector.
     */
    Inspector(AnalysisEngine &engine, DocumentStore &docs) noexcept;

    ~Inspector();

    Inspector(const Inspector &) = delete;
    Inspector &operator=(const Inspector &) = delete;

    /**
     * @brief @c vesta/bytecode: texto @c .vel del modulo o de una funcion.
     * @param uri      URI del documento abierto.
     * @param function Nombre de funcion a aislar (vacio = modulo entero).
     *                 Para el hover se pasa el simbolo para ver solo SU
     *                 bytecode; tambien resuelve funciones comptime via el
     *                 prefijo @c __macro_.
     * @return @c { "text": "<bytecode .vel>" } o @c { "error": "..." }.
     */
    nlohmann::json bytecode(const std::string &uri,
                            const std::string &function = "",
                            const InspectTarget &target = {});

    /**
     * @brief @c vesta/ir: SSA IR del modulo.
     * @param uri   URI del documento.
     * @param  "pre" (antes de optimizar) o "post" (default, optimizado).
     * @return @c { "text": "<IR legible>" } o @c { "error": "..." }.
     */
    nlohmann::json ir(const std::string &uri, const std::string &phase,
                      const InspectTarget &target = {});

    /**
     * @brief @c vesta/irDiff: diff del IR pre-opt vs post-opt de una funcion.
     *
     * Extrae el bloque @c @function de @p function en ambas fases y produce un
     * diff unificado por lineas (prefijos @c "- " eliminado por el optimizador,
     * @c "+ " generado, @c "  " sin cambios).  Si @p function esta vacio,
     * compara el modulo entero.
     *
     * @return @c { "text": "<diff>" } o @c { "error": "..." }.
     */
    nlohmann::json ir_diff(const std::string &uri, const std::string &function);

    /**
     * @brief @c vesta/complexity: coste Big-O por funcion.
     * @param uri URI del documento.
     * @return @c { "functions": [ { name, partial, total, confidence,
     *         total_confidence, max_loop_depth, recursive, declared,
     *         contract_mismatch }, ... ] } o @c { "error": "..." }.
     */
    nlohmann::json complexity(const std::string &uri);

    /**
     * @brief @c vesta/functionReport: lo DECLARADO frente a lo MEDIDO.
     *
     * Una funcion declara cosas -- @c \@pure, @c \@nothrow, @c \@alloc(N),
     * @c \@stack(N), @c \@complexity -- y el compilador MIDE esas mismas cosas
     * sobre el codigo que sale.  Lo interesante no es ninguna de las dos listas
     * por separado: es ponerlas una al lado de la otra y ver donde no cuadran,
     * que es exactamente lo que un contrato existe para detectar.
     *
     * Se responde por funcion y en datos, no en texto: lo declarado, lo medido,
     * el veredicto de cada contrato y si el modo nativo puede con ella.  Como
     * se ensena es cosa de quien lo ensena.
     *
     * @param uri URI del documento.
     * @return @c { "functions": [ { name, display, line, cost{...},
     *         measured{...}, declared{...}, checks[...], aot{...} } ] }.
     */
    nlohmann::json function_report(const std::string &uri);

    /**
     * @brief @c vesta/diagram: diagrama de una fase en un formato.
     * @param uri    URI del documento.
     * @param kind   "ast" | "ir-pre" | "ir-post" | "vel" | "asm".
     * @param format "mermaid" | "graphviz" | "html".
     * @param cost   Si true, anota los nodos-funcion con su coste Big-O.
     * @param target OS/arch para las ramas @Target y la ABI.
     * @param function Para @c kind="asm": funcion a diagramar (vacio = la
     *                 primera compilable / @c main).  Ignorado para el resto.
     * @return @c { "text": "<diagrama>" } o @c { "error": "..." }.
     */
    nlohmann::json diagram(const std::string &uri, const std::string &kind,
                           const std::string &format, bool cost,
                           const InspectTarget &target = {},
                           const std::string &function = std::string());

    /**
     * @brief @c vesta/functions: lista de funciones del modulo.
     * @param uri URI del documento.
     * @return @c { "functions": [ { name, line }, ... ] } o
     *         @c { "error": "..." }.
     */
    nlohmann::json functions(const std::string &uri);

    /**
     * @brief @c vesta/aotCompat: reporte de compatibilidad AOT.
     * @param uri  URI del documento.
     * @param tier "bare" (default) | "embed" | "full".
     * @return @c { "compatible": bool, "issues": [ { fn_name, source_line,
     *         op, reason } ], "ok_functions": [ ... ] } o @c { "error": ... }.
     */
    nlohmann::json aot_compat(const std::string &uri, const std::string &tier);

    /**
     * @brief @c vesta/jitAsm: desensamblado x86-64 del codigo JIT de una
     *        funcion.
     * @param uri      URI del documento.
     * @param function Nombre de la funcion a compilar (vacio = la primera /
     *                 @c main si existe).
     * @return En exito @c { "text": "<disasm>", "function": "<name>",
     *         "bytes": N, "instructions": M }.  Si la funcion usa ops no
     *         soportadas por el selector JIT @c { "unsupported": true,
     *         "reason": "..." }.  Ante otro fallo @c { "error": "..." }.
     */
    nlohmann::json jit_asm(const std::string &uri, const std::string &function,
                           const InspectTarget &target = {});

    /**
     * @brief @c vesta/aotAsm: desensamblado x86-64 del codigo AOT de una
     *        funcion.
     * @param uri      URI del documento.
     * @param function Nombre de la funcion (vacio = la primera / @c main).
     * @return En exito @c { "text": "<disasm>", "function": "<name>",
     *         "bytes": N, "relocs": [ { offset, kind, symbol, addend } ] }.
     *         Si la funcion no es AOT-compatible @c { "incompatible": true,
     *         "reason": "..." }.  Ante otro fallo @c { "error": "..." }.
     */
    nlohmann::json aot_asm(const std::string &uri, const std::string &function,
                           const InspectTarget &target = {});

    /**
     * @brief @c vesta/modes: reporte del modulo en los tres modos de ejecucion.
     *
     * El LSP no conoce (ni asume) el modo de ejecucion del programa: reporta
     * los TRES -- interprete/VM, JIT y AOT nativo -- para que el cliente los
     * muestre en paralelo.  Si se pide un @p mode concreto, devuelve solo ese.
     *
     * - @c interp: diagnosticos del frontend con semantica de VM (runtime
     *   completo).  Es el analisis siempre-activo (mismo que
     * publishDiagnostics).
     * - @c jit: reusa el IR del interprete y clasifica cada funcion en
     *   compilable por el backend vreg vs con fallback al interprete.
     * - @c aot: recompila con POO nativa (native_poo) y ejecuta el analisis de
     *   compatibilidad AOT al @p tier pedido, mas los diagnosticos propios de
     *   ese modo (asi los constructos AOT-only no aparecen como errores).
     *
     * @param uri  URI del documento.
     * @param mode "interp"|"jit"|"aot" para uno solo; vacio = los tres.
     * @param tier Tier AOT (bare|embed|full); solo afecta al modo aot.
     * @return @c { "modes": [ { "mode": ..., ... por modo }, ... ] } o
     *         @c { "error": "..." }.
     */
    nlohmann::json modes(const std::string &uri, const std::string &mode,
                         const std::string &tier);

    /**
     * @brief @c vesta/macroExpand: codigo que generan los @Macro del modulo.
     *
     * Lee las expectaciones de @Macro capturadas por el TypeChecker
     * (@c CompileResult::macro_expectations, ya cacheadas por el motor: no
     * requiere flag ni recompilar).  Cada entrada describe un call site con
     * su nombre, args y el codigo Vesta generado por la expansion.  Incluye
     * tambien los @Macro que NO se pudieron expandir
     * (@c macro_skip_reasons) y por que.
     *
     * @param uri URI del documento abierto.
     * @return @c { "expansions": [ { macro_name, call_site_loc, args:[...],
     *         generated_code } ], "skipped": [ { name, reason } ] } o
     *         @c { "error": "..." }.  Listas vacias si no hay macros.
     */
    nlohmann::json macro_expand(const std::string &uri);

    /**
     * @brief @c vesta/comptimeValues: valores @c comptime computados.
     *
     * Recompila el documento con @c CompileOptions::dump_comptime_values
     * (vista on-demand: NO se hace en el analyze por pulsacion) y cachea el
     * JSON por (uri, hash) en @c view_cache_.  Devuelve el snapshot de las
     * constantes @c comptime top-level que el compilador resolvio.
     *
     * @param uri URI del documento abierto.
     * @return @c { "values": [ { name, scope, type_kind, value_str } ] } o
     *         @c { "error": "..." }.  Lista vacia si no hay valores comptime.
     */
    nlohmann::json comptime_values(const std::string &uri);

    /**
     * @brief @c vesta/asa: todo lo que el compilador SABE del modulo.
     *
     * Es el mismo volcado que la linea de ordenes: los hechos, de donde sale
     * cada uno y con que certeza, lo que se miro sin sacar nada y por que, y el
     * resumen por dominio.  Se pide entero y sin variantes, igual que alli: un
     * volcado que hay que pedir por partes obliga a saber que se busca ANTES de
     * mirarlo, que es lo contrario de para lo que sirve.
     *
     * Aqui no se decide que es un hecho ni como se ordena -- eso es del
     * productor de cada dominio y de la vista del propio subsistema --; esto
     * solo lo hace llegar al editor.
     *
     * @param uri URI del documento abierto.
     * @return @c { "text": "<volcado>" } o @c { "error": "..." }.
     */
    nlohmann::json asa(const std::string &uri);

    /**
     * @brief @c vesta/asaFacts: lo que el compilador sabe, ATADO al fuente.
     *
     * El volcado de @ref asa se lee entero, de arriba abajo, cuando uno va a
     * auditar.  Esto es lo contrario: cada hecho con la LINEA a la que
     * pertenece, para que el editor lo ensene ahi mismo mientras se escribe --
     * los limites de un valor, la alineacion, a donde apunta un puntero -- sin
     * que haya que ir a buscarlo.
     *
     * Devuelve DATOS: el dominio, el codigo del vocabulario y sus numeros.  La
     * etiqueta corta viene ya resuelta en el idioma activo para los codigos que
     * el catalogo conoce; para los que no, se manda el codigo tal cual antes
     * que inventar una frase.
     *
     * Incluye tambien lo que cada dominio NO pudo saber y por que: sin eso no
     * se distingue "aqui no hay nada que decir" de "nadie ha mirado".
     *
     * @param uri URI del documento abierto.
     * @return @c { "facts": [...], "domains": [...] } o @c { "error": "..." }.
     */
    nlohmann::json asa_facts(const std::string &uri);

    /**
     * @brief @c vesta/targets: para que se puede compilar y mirar.
     *
     * Las arquitecturas que el generador cubre y, por cada una, las
     * microarquitecturas y las CPU que el compilador tiene cronometradas en su
     * base de datos de instrucciones.
     *
     * Sale de esa base y no de una lista escrita aparte a proposito: la lista
     * escrita aparte envejece en cuanto alguien anade una microarquitectura, y
     * el sintoma es que el editor ofrece menos de lo que el compilador sabe
     * hacer, sin que nada avise.  No depende del documento.
     *
     * @return @c { "architectures": [ { id, name, codegen, microarchs: [...],
     *         cpus: [...] } ], "floatIsas": [...], "optLevels": [...] }.
     */
    nlohmann::json targets();

    /**
     * @brief @c vesta/instruction: lo que el compilador sabe de UNA
     * instruccion.
     *
     * Lo mismo que consulta el planificador para decidir si puede mover una
     * instruccion respecto de otra: cuanto tarda, cuanto ocupa, por que puertos
     * pasa, que registros y que banderas toca, y que estado del procesador lee
     * o escribe.  Con eso, leer un bloque de ensamblador deja de ser adivinar
     * el coste.
     *
     * El coste depende de la MICROARQUITECTURA: la misma instruccion no cuesta
     * lo mismo en dos maquinas, asi que se responde para la que se pida y se
     * dice cual fue.
     *
     * NO se vuelve a emparejar el texto: se busca la instruccion que el
     * compilador YA elevo para esa linea, que lleva su identidad en la base
     * (ISA y forma) resuelta por el mismo elevado que usa el optimizador.  Es
     * la diferencia entre decir lo que el compilador entendio y decir lo que
     * otro emparejador cree que pone.
     *
     * Una instruccion que la base NO conoce se responde igual, diciendo que no
     * la conoce (@c known=false) y por que: callarse la deja indistinguible de
     * una linea que no es una instruccion, y son cosas distintas -- de la
     * segunda no hay nada que decir, y la primera es justo la que conviene
     * mirar, porque el compilador la trata como barrera y no mueve nada a su
     * alrededor.
     *
     * @param uri  Documento abierto.
     * @param line Linea del fuente, contando desde uno.
     * @param cpu  Microarquitectura; vacia = la primera que tenga la base.
     * @param arch Arquitectura del bloque (@c x86-64, @c aarch64...); decide a
     *             que ISA se pregunta cuando no hay micro que ya lo diga.
     *             Vacia = x86-64.
     * @return La ficha de la instruccion, o @c { "found": false } si esa linea
     *         no es una instruccion (etiqueta, comentario, vacia).
     */
    nlohmann::json instruction(const std::string &uri, uint32_t line,
                               const std::string &cpu, const std::string &arch);

    /**
     * @brief @c vesta/asmBlock: un bloque de ensamblador entero, con su FLUJO.
     *
     * Un bloque escrito a mano se lee saltando: se mira un salto y hay que
     * buscar su etiqueta arriba o abajo, y volver.  El compilador ya construye
     * el grafo de flujo de ese bloque para poder analizarlo -- sabe que
     * instruccion salta a cual --, y con eso se pueden dibujar las flechas en
     * vez de obligar a seguirlas con el dedo.
     *
     * Se devuelve ademas lo que se sabe de CADA instruccion: su clase en la
     * base, lo que cuesta en la microarquitectura pedida, que toca y si es
     * barrera.  Y lo que el grafo NO pudo resolver -- un salto indirecto, una
     * etiqueta que no esta -- porque es justo donde el analisis deja de valer.
     *
     * @param uri  Documento abierto.
     * @param line Una linea CUALQUIERA dentro del bloque.
     * @param cpu  Microarquitectura para el coste; vacia = la primera.
     * @param arch Arquitectura del bloque; vacia = x86-64.
     * @return El bloque con sus instrucciones, o @c { "found": false }.
     */
    nlohmann::json asm_block(const std::string &uri, uint32_t line,
                             const std::string &cpu, const std::string &arch);

    /**
     * @brief @c vesta/asmFlow: el flujo de TODOS los bloques del fichero.
     *
     * Lo mismo que @ref asm_block pero de todo el documento y solo con lo que
     * hace falta para DIBUJAR: que linea salta a que linea.  Es lo que permite
     * pintar las flechas sobre el propio codigo, que es donde se leen -- en un
     * panel aparte obligan a mirar a otro sitio, que es lo que se queria
     * evitar --.
     *
     * @param uri  Documento abierto.
     * @param arch Arquitectura de los bloques; vacia = x86-64.
     * @return @c { "blocks": [ { firstLine, lastLine, jumps: [...] } ] }.
     */
    nlohmann::json asm_flow(const std::string &uri, const std::string &arch);

  private:
    AnalysisEngine &engine_; ///< Motor de analisis (cache CompileResult).
    DocumentStore &docs_;    ///< Almacen de documentos abiertos.

    /// Cerrojo de las dos caches de abajo.  Solo cubre mirar y guardar, jamas
    /// la compilacion: si se tuviera mientras se compila, dos vistas de
    /// documentos distintos harian cola y no se ganaria nada por tener hilos.
    mutable std::mutex caches_;

    /// Cache propia de vistas caras (diagramas + ir-pre) por clave compuesta
    /// "<uri>|<hash>|<vista>".  Evita recompilar peticiones identicas.
    std::unordered_map<std::string, std::string> view_cache_;

    /**
     * @brief Lo guardado para @p key, si esta.
     *
     * Se copia lo guardado en vez de devolver una referencia dentro del mapa:
     * quien lo pide lo usa despues de soltar el cerrojo, y para entonces otra
     * peticion puede haber metido una entrada y realojado el mapa.
     *
     * @param key  Clave de la vista.
     * @param out  Recibe lo guardado si estaba.
     * @return true si estaba.
     */
    bool view_cached(const std::string &key, std::string &out) const;

    /**
     * @brief Guarda el resultado de una vista.
     * @param key   Clave de la vista.
     * @param value Texto a guardar.
     */
    void view_store(const std::string &key, std::string value);

    /**
     * @struct AotBuild
     * @brief El documento compilado con la semantica del modo NATIVO.
     *
     * El modo nativo no compila el mismo IR que el interprete: el mismo fuente
     * baja distinto.  Un literal de cadena, por ejemplo, es un @c StringObject
     * gestionado para el interprete y una vista sobre @c .rodata para el modo
     * nativo, de modo que el primero emite @c strmake y el segundo no.
     *
     * Por eso las vistas que hablan del modo nativo tienen que mirar ESTE IR:
     * juzgar su compatibilidad sobre el del interprete responde por un binario
     * que no es el que se va a generar, y la respuesta no falla -- simplemente
     * es de otro programa.
     */
    struct AotBuild {
        /// IR post-optimizacion serializado; vacio si la compilacion no lo
        /// produjo (errores en el fuente).
        std::vector<uint8_t> ir_bytes;
        size_t errors = 0;   ///< diagnosticos de error en este modo.
        size_t warnings = 0; ///< avisos en este modo.
    };

    /// Compilaciones nativas ya hechas, por "<uri>|<hash>".  Cuesta una
    /// compilacion entera y mas de una vista pregunta lo mismo.
    ///
    /// Por puntero compartido y no por valor: quien la recibe la usa despues de
    /// soltar el cerrojo, y para entonces otra peticion puede haber metido una
    /// entrada nueva y realojado el mapa.  Con el puntero, cada uno conserva la
    /// suya.
    std::unordered_map<std::string, std::shared_ptr<const AotBuild>> aot_cache_;

    /**
     * @brief Compila el documento como lo hace el modo nativo, y lo cachea.
     *
     * @param uri        Documento.
     * @param text       Texto vivo del documento.
     * @param target_key Clave del objetivo activo (vacia = el anfitrion).  El
     *                   objetivo cambia lo que sale -- decide las ramas
     *                   @c \@Target y la convencion de llamada --, asi que
     *                   forma parte de la identidad de la compilacion.  Quien
     *                   pase una clave no vacia debe tener el objetivo puesto
     *                   durante la llamada.
     * @param opt_level  Nivel de optimizacion pedido (0..3); -1 = el de por
     *                   defecto.  Va tambien en @p target_key, porque compilar
     *                   lo mismo a otro nivel es otra compilacion.
     * @return La compilacion; reutilizada si ya se hizo para este mismo texto,
     *         el mismo objetivo y el mismo nivel.
     */
    std::shared_ptr<const AotBuild>
    aot_build(const std::string &uri, const std::string &text,
              const std::string &target_key = std::string(),
              int opt_level = -1);
};

} // namespace lsp

#endif // VESTA_LSP_INSPECTOR_H
