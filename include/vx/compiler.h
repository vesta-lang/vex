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
 * @file compiler.h
 * @brief Facade del compilador Vesta: encadena los pases
 * lex/parse/check/lower/emit.
 *
 * Esta es la interfaz que el dispatcher CLI llama cuando recibe
 * @c --vx archivo.vx.  Convierte el codigo fuente .vx en texto
 * .vel listo para ser pasado al ensamblador del proyecto.
 *
 * No realiza I/O por si misma (lo hace el caller); solo opera sobre
 * cadenas en memoria.  Esto facilita los tests unitarios sin tocar
 * el sistema de ficheros.
 */

#ifndef VX_COMPILER_H
#define VX_COMPILER_H

#include <map>
#include <unordered_map>
#include <string>
#include <vector>

#include "vx/diagnostic.h"
#include "port/port_options.h"
#include "analyze/fingerprint.h"     // FunctionContracts
#include "analysis/asa/fact_store.h" // lo que se supo del modulo al compilarlo
#include "vxdbg/ids.h"               // huella del mapa de simbolos

/// El almacen de hechos del ASA viaja por referencia; no hace falta su
/// definicion aqui, y traerla obligaria a todo el que incluya esto a compilar
/// el nucleo del ASA.
namespace analysis {
namespace asa {
class FactStore;
} // namespace asa
} // namespace analysis

namespace ir {
struct IrModule;
}

namespace vx {

/**
 * @struct CompileOptions
 * @brief Opciones del compilador Vesta.
 */
struct CompileOptions {
    std::string module_name; ///< Nombre logico del modulo (por defecto "main").
    /**
     * @brief Dominios del ASA que alguien va a consultar.  Vacio = ninguno.
     *
     * Vacio POR DEFECTO, y eso es la mitad del diseno: producir conocimiento
     * que nadie pide no es prevision, es tiempo tirado.  Medido en
     * `199_cfn_vs_lambda`, producirlo todo llevaba la compilacion de 200 ms a
     * 1,5 s -- siete veces --, y no habia un solo consumidor esperandolo.
     *
     * Quien lo necesite lo pide, y entonces ademas se GUARDA: la proxima
     * compilacion del mismo modulo lo lee en vez de rehacerlo.  Asi el coste lo
     * paga quien lo usa y solo la primera vez.
     */
    std::vector<const char *> asa_domains;
    bool emit_debug =
        false; ///< Emitir comentarios @line N en el .vel generado.
    /// Carpeta donde volcar la base de conocimiento de depuracion (@c vxdbg).
    /// Vacia = la de por defecto, dentro del cache del compilador.
    ///
    /// NO es opcional: se emite siempre.  Es informacion APARTE del ejecutable
    /// -- no cambia ni un byte de lo que se genera -- y su valor esta en estar
    /// ahi cuando algo falla, que es precisamente cuando nadie penso en
    /// pedirla.  Un programa compilado "sin depuracion" es el que despues no
    /// se puede explicar.
    std::string vxdbg_dir;
    /// Solo-LSP: si true, las funciones @c comptime (no-macro) tambien se
    /// bajan a IR como funciones normales para poder inspeccionar su codegen
    /// (JIT/AOT/bytecode del hover).  En compilacion normal estas funciones se
    /// evaluan en compile-time y se eliden -> OFF por defecto.
    bool emit_comptime_fns = false;
    int opt_level = 2; ///< 0..3, mapea a ir::OptLevel.  Default O2 (DCE + copy
                       ///< prop + const fold + unreachable + TCO).
    /// si true, ademas del .vel, generar el dump
    /// textual del @c IrModule completo (post-optimizacion) en
    /// @c CompileResult::ir_text.  Util para inspeccionar lo que el
    /// frontend produce antes del backend, debug y verificacion de
    /// fixes (PHIs, SSA, CALLCLOSURE, etc.).
    bool dump_ir = false;

    /// Cuando true, ademas del @c ir_module_cache_bytes (modulo POST-opt),
    /// llena @c CompileResult::ir_module_cache_bytes_preopt con el modulo
    /// IR completo ANTES de la optimizacion O2.  Lo consume el modo
    /// @c --analyze para reportar el coste PRE-opt (complejidad algoritmica
    /// del fuente) junto al POST-opt (complejidad efectiva tras inline/
    /// loop-elim).  Cero impacto en el codegen (rama de debug/analisis).
    bool emit_ir_preopt = false;

    /**
     * @brief Ademas, el modulo optimizado CON inline.
     *
     * Solo tiene sentido junto a @c emit_ir_preopt, que optimiza SIN inline
     * porque el coste parcial es propiedad del cuerpo escrito.  Quien ademas
     * necesita ver el codigo que de verdad se construye -- el informe de
     * efectos -- pedia antes una SEGUNDA compilacion entera del fuente para
     * obtenerlo.  Sale de la misma bajada: basta optimizar una copia.
     *
     * Ademas de costar la mitad, quita un fallo: aquella segunda compilacion
     * corria sin @c emit_ir_preopt, o sea que un contrato incumplido la hacia
     * abortar y el informe se quedaba callado justo cuando tenia algo que
     * ensenar.
     *
     * Lo deja en @c CompileResult::ir_module_cache_bytes_inlined.
     */
    bool emit_ir_inlined = false;

    /**
     * @brief Parar tras optimizar el IR: no emitir el texto @c .vel.
     *
     * Para quien solo quiere el IR y tira el resto.  Medido en un fuente
     * pequeno: analizar, comprobar tipos y bajar cuestan 2,4 ms entre los tres,
     * optimizar 3,4 ms, y EMITIR 52 ms -- el noventa por ciento, casi todo
     * asignacion de registros.  El informe de @c --analyze pagaba eso cuatro
     * veces para no leer ni una linea del @c .vel.
     *
     * Lo que se pierde: @c vel_text queda vacio, y con el @c ir_section_bytes y
     * la anotacion de registro de cada valor (@c IrValue::reg) -- la pone el
     * emisor, que es quien la sabe.  @c ir_module_cache_bytes SI se llena; es
     * el mismo modulo, sin esa anotacion.  Quien necesite un artefacto no debe
     * pedir esto.
     */
    bool ir_only = false;

    /**
     * @brief Bytecode del conjunto comptime, ya compilado, para usarlo SIN
     *        pasar por disco.
     *
     * El codigo que se ejecuta al compilar (los `@Macro`, las `comptime fn`)
     * necesita bytecode que ejecutar.  Hasta ahora ese bytecode viajaba por una
     * variable de entorno con la RUTA de un fichero, que cada modulo volvia a
     * leer del disco.  Por aqui viaja el contenido, que es lo que de verdad
     * hace falta: se construye una vez, antes de compilar ningun modulo, y
     * todos lo ven ya cargado.
     *
     * Apunta a bytes que son del llamante y tienen que vivir mientras dure la
     * compilacion.  @c nullptr = no hay, y se cae a la variable de entorno.
     */
    const std::vector<uint8_t> *comptime_artifact = nullptr;

    /**
     * @brief Esta compilacion ES la del conjunto comptime.
     *
     * Sirve para no morderse la cola: el conjunto comptime SE CONTIENE A Si
     * MISMO -- `inject` es un `@Macro`, o sea que forma parte del conjunto --,
     * asi que compilarlo vuelve a entrar por el mismo sitio y construye el
     * artefacto DEL artefacto.  Se llego a observar con tres niveles,
     * encogiendo en cada uno.  Con esto puesto no se recolecta ni se construye
     * nada.
     */
    bool building_comptime_artifact = false;

    /// Cuando true, llena @c CompileResult::mermaid_ast con un diagrama
    /// Mermaid del AST Vesta post type-check.  Util para visualizar la
    /// estructura del codigo fuente: clases, herencia, anotaciones.
    bool dump_mermaid_ast = false;
    /// Cuando true, llena @c CompileResult::mermaid_ir_pre con el
    /// diagrama Mermaid del SSA IR ANTES de optimizar.  Captura el
    /// output crudo del lowering (todos los PHIs, todos los CONSTs,
    /// blocks como los emite el frontend).
    bool dump_mermaid_ir_pre = false;
    /// Cuando true, llena @c CompileResult::mermaid_ir_post con el
    /// diagrama Mermaid del SSA IR DESPUES de optimizar.  Permite
    /// comparar contra ir_pre para ver que hizo el optimizer (DCE,
    /// inline_loop_header, const fold, TCO).
    bool dump_mermaid_ir_post = false;
    /// Cuando true, llena @c CompileResult::mermaid_vel con el
    /// diagrama Mermaid del bytecode .vel final.  Independiente de
    /// dump_ir / dump_mermaid_ir_*: opera solo sobre el texto del .vel.
    bool dump_mermaid_vel = false;
    /// Cuando true, llena @c CompileResult::mermaid_types con un diagrama
    /// de tipos (mermaid classDiagram): clases con sus campos/metodos +
    /// herencia + interfaces implementadas + structs + enums (con su tipo
    /// base y variantes).  Vista de alto nivel de la POO del modulo.
    bool dump_mermaid_types = false;

    /// Variantes Graphviz (DOT) de los flags Mermaid.  Producen archivos
    /// .dot listos para `dot -Tpng/-Tsvg`, con la misma topologia y
    /// MAS informacion (tooltips, atributos arbitrarios, formas
    /// distintas por tipo de nodo).  Usar cuando Mermaid se quede corto
    /// para grafos grandes (>200 nodos) o se quiera exportar a PDF/SVG
    /// con control fino del layout.  Coexisten con los flags Mermaid:
    /// activar ambos genera ambos formatos en paralelo.
    bool dump_graphviz_ast = false;
    bool dump_graphviz_ir_pre = false;
    bool dump_graphviz_ir_post = false;
    bool dump_graphviz_vel = false;
    /// Variante Graphviz del diagrama de tipos (ver dump_mermaid_types).
    bool dump_graphviz_types = false;

    /// Variantes HTML interactivas (CSS+JS embebidos, sin dependencias).
    /// Producen un .html autocontenido por vista que el usuario abre en
    /// el navegador para analizar el flujo de codigo con pan/zoom, panel
    /// de detalle por nodo, busqueda y filtros de aristas.  Internamente
    /// reutilizan el generador Graphviz (paridad de info garantizada).
    /// Coexisten con los flags Mermaid/Graphviz.
    bool dump_html_ast = false;
    bool dump_html_ir_pre = false;
    bool dump_html_ir_post = false;
    bool dump_html_vel = false;
    /// Variante HTML del diagrama de tipos (ver dump_mermaid_types).
    bool dump_html_types = false;

    /// Lenguaje destino del transpiler IR -> codigo fuente.  Vacio = no
    /// transpilar (default).  Valores soportados: "c" ( 1).
    /// Futuros: "java", "js", "rust", etc.
    std::string port_target;

    /// Opciones del transpiler (GC, EH, type style).  Solo se consulta
    /// si @c port_target != "".  Default segun PortOptions::PortOptions.
    port::PortOptions port_options;

    /// Fase 4 interop C: si @c true, genera el header C publico del modulo
    /// (structs C-compat + prototipos de funciones C-representables) en
    /// @c CompileResult::header_text.  Activado por `vx --emit-header`.
    bool emit_header = false;

    /// Instrumentacion para debugging: cuando esta activa, el lowering
    /// emite CALLs sinteticas a @c "vx_trace:enter" y @c "vx_trace:exit"
    /// al inicio y antes de cada @c RET de cada funcion del usuario.
    /// Como las trazas estan en el IR (no en un backend especifico),
    /// el bytecode VM, el JIT y todos los ports (C, futuro Java, JS)
    /// las heredan automaticamente.
    ///   "none" (default) - sin instrumentacion (cero overhead).
    ///   "trace"          - imprime "ENTER name" y "EXIT name = value"
    ///                      con indentacion segun call depth.
    ///   "profile"        - mide tiempo per-funcion (rdtsc); imprime
    ///                      estadisticas al exit del programa.
    std::string instrument_mode;

    ///  AOT.2.b: modo POO NATIVA (sin runtime VM).  Cuando true, el
    /// lowering de clases baja a layout estilo C-struct (offsets estaticos)
    /// + new->malloc(size)/alloca + ctor directo, SIN __module_init/
    /// ClassRegistry/GcHeap (no se emiten defclass/newobj/findclass/
    /// gc_deref_host).  Lo activa el driver @c -m aot.  Default false
    /// (ruta runtime historica, intacta para la VM/JIT).
    bool native_poo = false;

    /**
     * @brief No traer el asignador escrito en el lenguaje a este modulo.
     *
     * El binario nativo lo usa y el JIT no, asi que un fallo que solo se ve en
     * el nativo hay que perseguirlo alli.  Compartiendo mecanismo se puede
     * recorrer el mismo camino dentro de la maquina, con el depurador delante.
     *
     * Se pone a @c true al compilar el PROPIO asignador, que no puede traerse a
     * si mismo.
     */
    bool sin_asignador_vesta = false;

    /**
     * @brief Convertir en ERROR los accesos demostrablemente fuera de region.
     *
     * Al CONSTRUIR, si.  Al ANALIZAR, no: `--analyze` los enseña en su propia
     * seccion con la prueba delante, y abortar ahi dejaria sin analisis justo
     * al programa que mas falta le hace.  Mismo comprobador en los dos casos;
     * lo que cambia es que se hace con el veredicto.
     */
    bool report_bounds = true;

    /// C3 (AOT): habilita el mecanismo de excepciones NATIVO (setjmp/longjmp,
    /// sin runtime/GC/libc).  CONFIGURABLE: el usuario puede DESACTIVARLO
    /// (--no-exceptions) para kernels/freestanding donde no se quiere ningun
    /// runtime de excepciones; entonces un try/catch/throw da error claro.
    /// Default true.  Coste cero si el programa no usa excepciones (el runtime
    /// solo se emite si hay try/catch/throw).  Solo afecta a @c native_poo
    /// (AOT).
    bool exceptions_enabled = true;

    /// Bits del target para el ensamblado del inline-asm (@Naked / asm{}): 64
    /// (defecto), 32 (--aot-arch x86-32) o 16.  La validacion compile-time del
    /// asm debe usar el modo del TARGET, no del host -- si no, instrucciones de
    /// 32 bits (p.ej. `jmp ecx`) fallan en KS_MODE_64.
    uint8_t asm_target_bits = 64;

    /// Ancho del chunk SIMD (bytes) que el matcher del vectorizador hornea en
    /// AOT (native_poo): 16 (SSE2/defecto), 32 (AVX), 64 (AVX512).  En AOT lo
    /// fija el TARGET (--float-isa), no el host de build -> cross-compile
    /// correcto (no emitir AVX2 si el target es solo-SSE2) y ancho
    /// seleccionable. El codegen (vreg) deriva el mismo ancho de @c FloatIsa.
    /// Fuera de AOT el matcher sigue usando el host (vec_chunk_isa) para
    /// portabilidad del .velb.
    uint8_t aot_vec_width = 16;

    /// --float-isa auto: el binario multiversiona las funciones vectorizadas y
    /// elige sse2/avx2/avx512 en runtime por cpuid.  El matcher hornea el chunk
    /// con estrategia DUAL para que UN IR compile a las 3 variantes: element-
    /// wise/unary/scalar-bcast a 64 (cada variante decompone
    /// 4x128/2x256/1x512), reduccion/FMA a 16 (el acumulador no splittea ->
    /// 128b en todas).
    bool aot_auto_vec = false;

    /// Fase 3.5 LSP: cuando true, @c compile_vx_source vuelca un snapshot
    /// de los valores @c comptime computados (constantes top-level) a
    /// @c CompileResult::comptime_values.  Estrictamente ADITIVO y gateado:
    /// con el default false el flujo de compilacion es EXACTAMENTE el
    /// historico (cero coste, cero cambio de codegen).  Lo consume el
    /// metodo @c vesta/comptimeValues del LSP, on-demand.
    bool dump_comptime_values = false;

    /// LSP "notebook" (valores runtime): cuando true, el lowering instrumenta
    /// cada declaracion/asignacion de variable ESCALAR (int/bool/char)
    /// emitiendo un CALLN a @c vesta_io:vio_lsp_value(source_line, valor) que
    /// vuelca
    /// @c __LSPVAL__:linea:valor a stderr.  El LSP compila con este flag,
    /// ejecuta el @c .velb en un subproceso con timeout y parsea esos
    /// marcadores para mostrar los valores reales de las variables inline.
    /// Estrictamente ADITIVO y gateado: con el default false el codegen es
    /// EXACTAMENTE el historico (cero coste).  NUNCA se activa en compilacion
    /// normal.
    bool lsp_value_trace = false;

    /// Politica de contraccion de coma flotante a nivel de MODULO (CLI
    /// -ffp-contract).  true (default) = fast: se permite contraer a*b+c en
    /// FMA (1 redondeo).  false = off (IEEE estricto, 2 redondeos).  Se AND-ea
    /// con el @c fp_contract por-funcion (@fp(strict) pone la funcion a false)
    /// -> off global fuerza TODO a false.  Se aplica a @c
    /// IrFunction::fp_contract en el lowering (misma unidad de traduccion que
    /// el optimizer), en vez de depender de un global mutable que se duplica
    /// entre vm.exe/DLL/vmcore.
    bool fp_contract = true;
};

/**
 * @brief Deja el asignador escrito en el lenguaje DENTRO del modulo, sin tocar
 *        las reservas.
 *
 * La comparten los dos caminos de compilacion -- fichero suelto y proyecto --
 * porque de que mecanismos dispone el codigo no puede depender de por cual se
 * entro a compilar.
 *
 * @param mod Modulo ya fusionado, antes de optimizar.
 * @param opts Opciones de la compilacion en curso.
 * @param root_path Fuente raiz, para no traerse a si mismo.
 */
void traer_asignador_del_lenguaje(ir::IrModule &mod, const CompileOptions &opts,
                                  const std::string &root_path);

/**
 * @struct CompileResult
 * @brief Resultado de la compilacion Vesta.
 *
 * @c ok == true implica @c vel_text valido y diagnosticos sin errores
 * (puede haber warnings).
 * @c ok == false implica errores en diagnostics; @c vel_text puede
 * estar vacio o ser parcial.
 */
struct CompileResult {
    bool ok = false; ///< Exito global.
    /**
     * @brief Lo que se supo del modulo al compilarlo.
     *
     * Sale de la compilacion en vez de morir con ella, que es la diferencia
     * entre una capa de conocimiento y un analisis de usar y tirar.  Quien
     * compile puede consultarlo -- el editor, el linter -- sin volver a
     * producirlo, y lo que costo producir queda ademas en disco para la
     * siguiente compilacion del mismo modulo.
     */
    analysis::asa::FactStore facts;
    /// Huella del mapa que liga los simbolos del artefacto con las entidades
    /// del grafo de depuracion.  Quien produzca el artefacto final la publica
    /// bajo su identificador de construccion: es lo que permite, desde una
    /// direccion de ejecucion, llegar a la declaracion que la origino.
    vxdbg::ContentHash vxdbg_artifact_map;
    /// Y la del mapa de TRAMOS de fuente, que va aparte porque cambia con
    /// cualquier reformateo mientras que el de simbolos no.
    vxdbg::ContentHash vxdbg_span_map;
    std::string vel_text; ///< Texto .vel generado a partir del IR.
    std::string
        ir_text; ///< dump del IrModule (solo si CompileOptions::dump_ir).
    /// AOT.2.d: simbolos de override (@AllocatorOverride / @PanicHandler).
    /// Vacio = sin override (convencion calloc/free/abort).  El driver
    /// @c -m aot los pasa a @c AotLowerConfig y habilita LIBC_MAPPED en
    /// --freestanding para el rol cubierto.
    std::string aot_alloc_sym; ///< @AllocatorOverride que devuelve ptr.
    std::string aot_free_sym;  ///< @AllocatorOverride que devuelve void.
    std::string aot_panic_sym; ///< @PanicHandler.
    /// C-3: @StringConcat / @StringEq -- nombres de las funciones libres
    /// que reemplazan el `+` (concat) y `==` (eq) del string built-in.
    /// Vacios => comportamiento por defecto (STRCAT/STRCMP o value-string).
    std::string string_concat_override;
    std::string string_eq_override;
    /// @SyncImpl -- nombres de las funciones libres que reemplazan la
    /// primitiva de monitor de `synchronized` (enter/exit).  Vacios =>
    /// comportamiento por defecto (opcode MONENTER/MONEXIT en interp/JIT,
    /// __vx_monenter/monexit en AOT).  Cuando estan set, `synchronized`
    /// baja a un CALL a estas funciones en LOS 3 MODOS.
    std::string sync_enter_override;
    std::string sync_exit_override;
    /// CPU dispatch Inc 4: @HelperOverride(<helper>) -- mapea el nombre del
    /// helper objetivo (hoy solo "memcpy") al nombre de la fn libre del
    /// usuario que lo reemplaza.  Vacio => sin override (dispatch por cpuid).
    /// Disenado para escalar a strcmp/strlen/itoa sin tocar el schema.
    std::map<std::string, std::string> aot_helper_override_syms;
    /// Diagrama Mermaid del AST post type-check.  Llenado solo si
    /// @c CompileOptions::dump_mermaid_ast == true.  Vacio en caso
    /// contrario para no pagar el coste de generacion en builds prod.
    std::string mermaid_ast;
    std::string mermaid_ir_pre;  ///< Mermaid del IR pre-optimizacion
                                 ///< (dump_mermaid_ir_pre).
    std::string mermaid_ir_post; ///< Mermaid del IR post-optimizacion
                                 ///< (dump_mermaid_ir_post).
    std::string
        mermaid_vel; ///< Mermaid del bytecode .vel final (dump_mermaid_vel).
    std::string mermaid_types; ///< classDiagram de tipos (dump_mermaid_types).
    /// Variantes Graphviz (DOT) llenas cuando los flags @c dump_graphviz_*
    /// estan activos.  Vacias en otro caso.  El contenido es texto DOT
    /// completo (con `digraph G { ... }`), listo para `dot -Tpng/-Tsvg`.
    std::string graphviz_ast;
    std::string graphviz_ir_pre;
    std::string graphviz_ir_post;
    std::string graphviz_vel;
    std::string graphviz_types; ///< DOT del diagrama de tipos.
    /// Variantes HTML interactivas (documento completo `<!DOCTYPE html>...`)
    /// llenas cuando los flags @c dump_html_* estan activos.  Vacias en
    /// otro caso.  Cada una es una pagina autocontenida lista para abrir.
    std::string html_ast;
    std::string html_ir_pre;
    std::string html_ir_post;
    std::string html_vel;
    std::string html_types;  ///< HTML del diagrama de tipos.
    Diagnostics diagnostics; ///< Errores y warnings acumulados.

    /**
     * @struct TiemposFrontend
     * @brief Cuanto costo cada fase del frontend, en microsegundos.
     *
     * La construccion ya publicaba lo que tardan ensamblar y enlazar, pero de
     * la mitad delantera -- que es la que crece con el tamano del fuente -- no
     * decia nada, asi que "por que tarda tanto en compilar" no se podia
     * responder sin instrumentar a mano.
     *
     * Se mide SIEMPRE, no bajo una opcion: el coste son cinco lecturas de
     * reloj por compilacion, y una medida que hay que pedir es una medida que
     * nadie mira.  Ademas responde a la pregunta de "cuanto tardo en ver el
     * error" sin necesidad de un modo aparte: es @c comprobar_us, que abarca
     * hasta el final del analisis de tipos.
     */
    struct TiemposFrontend {
        long analisis_us = 0;  ///< Lexico + sintaxis: fuente -> AST.
        long tipos_us = 0;     ///< Comprobacion de tipos sobre el AST.
        long bajada_us = 0;    ///< AST -> IR.
        long optimizar_us = 0; ///< Pases sobre el IR.
        long emitir_us = 0;    ///< IR -> texto .vel.

        /** Resolver el grafo de dependencias: averiguar QUE modulos entran en
         *  la compilacion.  Solo se llena al compilar un proyecto (varios
         *  modulos); en un fichero suelto no hay nada que resolver y vale 0.
         *  Va aparte de @c analisis_us porque no es el mismo trabajo ni crece
         *  igual: uno depende del tamano del fuente y este del NUMERO de
         *  modulos y de si hay que redescubrirlos. */
        long resolver_us = 0;
        /** Compilar cada modulo del proyecto y fusionar su IR.  Incluye los
         *  que se saltan por estar en cache, que es justo lo que se quiere
         *  poder comparar. */
        long modulos_us = 0;

        /// Hasta donde llega el diagnostico: analisis + tipos.  Es lo que
        /// esperaria quien solo quiere saber si su codigo esta bien.
        long comprobar_us() const { return analisis_us + tipos_us; }
        long total_us() const {
            return analisis_us + tipos_us + bajada_us + optimizar_us +
                   emitir_us + resolver_us + modulos_us;
        }
    };
    TiemposFrontend tiempos; ///< Reparto del coste del frontend.

    /**
     * @brief Opcion W: IR serializado en bytes para embebido en `.velb`.
     *
     * Llenado por @c compile_vx_source con el resultado de
     * @c ir::emit_ir_section sobre el @c IrModule optimizado.  El
     * caller (main.cpp + assembler) pasa estos bytes al Linker
     * via @c Linker::set_ir_section_bytes.  El Linker los appendea
     * a la seccion @c @ir del `.velb` v3.
     *
     * Asi habilita auto-JIT: al cargar un `.velb`,
     * el Loader deserializa esta seccion y mantiene un mapping
     * @c MethodInfo* -> @c IrFunction.  Cuando una funcion se
     * vuelve "hot" (invocation_count >= threshold), el JIT compila
     * el IR y se patcha @c MethodInfo::jit_code.
     *
     * Vacio si la compilacion no produjo IR (caso de errores).
     */
    std::vector<uint8_t> ir_section_bytes;

    /**
     * @brief  AOT: IR del modulo COMPLETO serializado (functions +
     * static_data + globals) via @c ir::emit_ir_module_cache (magic VXMC).
     *
     * A diferencia de @c ir_section_bytes (solo functions, lo consume el
     * JIT/loader), esto round-trippea tambien el @c static_data -- que el
     * codegen AOT necesita para materializar los literales en @c .rodata
     * (las refs @c STR_LIT_ADDR/@c LABEL_ADDR se resuelven contra el).  Lo
     * consume el driver @c -m aot con @c ir::parse_ir_module_cache.  NO toca
     * la seccion @c @ir del @c .velb (cero impacto en el path JIT).
     *
     * Vacio si la compilacion no produjo IR (caso de errores).
     */
    std::vector<uint8_t> ir_module_cache_bytes;

    /// Contratos de huella (@pure/@nothrow/@nopanic/@alloc/@stack) declarados
    /// por el usuario, por nombre de funcion.  Se llevan aqui (no en el IR)
    /// porque son metadata compile-time que el codegen no necesita.  El modo
    /// --analyze los verifica contra la huella inferida.  Ver
    /// @c analyze::FunctionContracts.
    std::unordered_map<std::string, analyze::FunctionContracts> contracts;

    /// Contratos de TIPO (@pod/@no_heap/@size) declarados sobre struct/clase/
    /// enum, por nombre de tipo.  Verificados contra @c type_fingerprints.
    std::unordered_map<std::string, analyze::TypeContracts> type_contracts;

    /// Huella de cada TIPO agregado (layout + propiedades de recurso) inferida
    /// de los layouts del type checker.  La consume --analyze (reporte +
    /// checks).
    std::vector<analyze::TypeFingerprint> type_fingerprints;

    /**
     * @brief Modo --analisis: IR del modulo completo serializado ANTES de
     * la optimizacion O2 (mismo formato magic VXMC que
     * @c ir_module_cache_bytes).  Llenado SOLO si
     * @c CompileOptions::emit_ir_preopt esta activo.
     *
     * El modo @c --analyze lo usa para computar el coste PRE-opt (la
     * complejidad algoritmica del codigo tal como se escribio) y
     * contrastarlo con el POST-opt (la complejidad efectiva del codigo
     * final, que puede ser MENOR si el optimizer elimina/folda loops).
     *
     * Vacio si la compilacion no produjo IR o si @c emit_ir_preopt es
     * false (caso comun en builds de produccion: cero coste extra).
     */
    std::vector<uint8_t> ir_module_cache_bytes_preopt;

    /**
     * @brief El modulo optimizado CON inline (mismo formato magic VXMC).
     *
     * Llenado SOLO con @c CompileOptions::emit_ir_inlined.  Es el codigo que de
     * verdad se construye, frente a @c ir_module_cache_bytes que bajo
     * @c emit_ir_preopt se optimiza sin inline para medir el cuerpo escrito.
     * Los dos salen de la misma bajada.
     */
    std::vector<uint8_t> ir_module_cache_bytes_inlined;

    /// Codigo fuente generado por el transpiler IR -> lenguaje destino.
    /// Lleno solo si @c CompileOptions::port_target != "".  El contenido
    /// es C/Java/JS/etc segun el target elegido, listo para escribir
    /// a archivo y compilar con la toolchain nativa.
    std::string port_text;

    /// Fase 4 interop C: texto del header C publico generado, lleno solo si
    /// @c CompileOptions::emit_header.  Listo para escribir a `<out>.h`.
    std::string header_text;

    /// Warnings emitidos por el transpiler (IR ops no soportadas por
    /// el backend, etc.).  Vacio si no hubo issues.
    std::vector<std::string> port_warnings;

    /**
     * @brief expectaciones capturadas por el
     * TypeChecker al evaluar @Macros via el AST evaluator.
     *
     * Cada entrada describe un call site con su (nombre, args,
     * resultado AST esperado, ubicacion).  El caller las pasa a
     * @c ComptimeRuntime::record_expectation tras cargar el
     * bytecode con @c load_macros_from_bytes, y luego invoca
     * @c shadow_validate para comparar AST vs VM end-to-end.
     *
     * Si los conteos del shadow validate divergen, indica un bug
     * en la lowering del @Macro a IR (o en el AST evaluator).
     * Cuando todo coincide, MC.9 podra hacer el switch a VM-only
     * con confianza.
     */
    struct MacroExpectation {
        std::string macro_name;
        std::vector<uint64_t> args;
        std::string expected_str;
        std::string src_loc;
    };
    std::vector<MacroExpectation> macro_expectations;

    /**
     * @brief @c true si el modulo contiene AL MENOS
     * UNA declaracion @Macro que fue lowereada al IR.  Independiente
     * de @c macro_expectations (que solo se popula con call sites
     * cuyos args son codificables como uint64 directo).
     *
     * Usado por @c main.cpp como gate para disparar el two-phase
     * compile + cache populate.  Esto permite que macros con args
     * @c string (marshalados con @c runtime::make_string_flat) o
     * structs/arrays (futuros) tambien se beneficien del path VM.
     */
    bool has_lowerable_macros = false;

    /**
     * @brief Quedo un `inject(...)` de un bloque asm sin resolver.
     *
     * El cuerpo de ese bloque se genera EJECUTANDO codigo en compilacion; si
     * esa ejecucion no llega a ocurrir, el bloque sale VACiO.  Hasta ahora eso
     * se compilaba sin decir nada y el sintoma aparecia lejos del sitio: una
     * copia que no copia, o un `hlt` a mitad de una funcion de la biblioteca.
     *
     * Se mira sobre el artefacto QUE SE ENTREGA, no sobre una pasada concreta:
     * da igual cuantas veces se compile por dentro -- y el dia que se compile
     * una sola, la comprobacion vale igual.
     */
    bool unresolved_inject = false;

    /**
     * @brief Fuente del CONJUNTO COMPTIME de la compilacion: las decls que se
     *        ejecutan al compilar (`comptime` y `@Macro`), sus dependencias y
     *        los `import` que necesitan, concatenadas.
     *
     * Lo que alimenta hoy a la ComptimeVM se obtiene compilando el PROYECTO
     * ENTERO -- 704 KB, 182 macros, ~800 ms, el 43% de una compilacion en frio
     * --, cuando las raices comptime reales de ese mismo programa son ocho
     * funciones.  Devolviendo aqui su fuente, quien orquesta puede compilar
     * SOLO eso, que ademas debe hacerse desde FUERA: construir el artefacto
     * dentro de la compilacion que lo necesita RECURSA (`inject` es un
     * `@Macro`, asi que el conjunto se contiene a si mismo).
     *
     * Vacio si el modulo no tiene nada comptime.
     */
    std::string comptime_unit_source;
    /// Nombres de las funciones del conjunto comptime, tal como los da el
    /// recolector (comptime + `@Macro` + sus dependencias).  Es el criterio de
    /// pertenencia: sin el habria que adivinarlo del texto, y una busqueda de
    /// subcadena acierta por accidente.
    std::vector<std::string> comptime_unit_names;
    /**
     * @brief Declaraciones comptime que el recolector VIO y NO se llevo.
     *
     * Hoy son los metodos `comptime` de un tipo (el constructor
     * `comptime T(expr)`, sobre todo): el recolector recoge declaraciones de
     * nivel superior y un metodo no lo es.
     *
     * Se cuenta porque un conjunto vacio no puede significar a la vez "este
     * modulo no tiene nada comptime" y "tiene comptime que no recojo".  Lo
     * segundo dejaria el artefacto SEPARADO sin algo que hace falta, y no daria
     * error: fallaria mucho despues.  Hoy no se nota porque el artefacto es el
     * PROGRAMA ENTERO y ese bytecode esta dentro por eso.
     */
    std::vector<std::string> comptime_unit_not_collected;
    /// Texto `.vel` de SOLO el conjunto comptime, emitido filtrando el IR ya
    /// bajado y optimizado del modulo.  Es lo que hay que ensamblar para la
    /// ComptimeVM, en vez del programa entero: medido sobre
    /// `367_std_memory_variantes`, 8 funciones y 245 KB frente a 61 y 543 KB.
    /// Vacio si el modulo no tiene nada comptime.
    std::string comptime_vel_text;
    /// Seccion `@ir` que acompana a @c comptime_vel_text.
    std::vector<uint8_t> comptime_ir_section_bytes;
    /// Clave de contenido de @c comptime_unit_source: cambia si y solo si
    /// cambia una decl comptime o una de sus dependencias.  Tocar codigo de
    /// runtime NO la mueve, que es lo que permite reusar el artefacto entre
    /// compilaciones. 0 si no hay conjunto.
    uint64_t comptime_unit_hash = 0;
    /// true si el modulo tiene candidatos de precomputo CTPE (fn evaluable
    /// zero-param con retorno escalar).  Informativo; el plegado ocurre dentro
    /// del emisor cuando VESTA_CTPE esta activo.
    bool has_ctpe_candidates = false;

    /**
     * @brief por cada @Macro que el lowering rechazo
     * por usar features no soportados en el path VM (builtins
     * comptime-only, comptime globals, etc.), guarda
     * @c (macro_name, reason).  El main.cpp los imprime via
     * @c VESTA_MC_VERBOSE para diagnostico.
     */
    std::vector<std::pair<std::string, std::string>> macro_skip_reasons;

    /**
     * @brief  M5.B: rutas canonicas (absolutas + normalizadas) de
     * TODOS los modulos que participaron en el compile (root + deps
     * recursivos).  El main.cpp las usa para persistir el project
     * cache: tras un compile exitoso guarda
     * @c (paths, source_hashes, .velb final) para que el siguiente
     * compile pueda hacer cache hit instantaneo si nada cambio.
     *
     * Vacio si la compilacion fue single-file (sin imports) o si
     * @c compile_vx_source en lugar de @c compile_vx_project se uso.
     */
    std::vector<std::string> dep_paths;

    /**
     * @brief Fase 3.5 LSP: snapshot de los valores @c comptime computados.
     *
     * Cada entrada describe una constante @c comptime (top-level) con su
     * nombre, el ambito donde vive (best-effort), la clase de valor y una
     * representacion legible.  Llenado SOLO si
     * @c CompileOptions::dump_comptime_values esta activo (default false,
     * cero coste en builds normales).  Lo consume el metodo LSP
     * @c vesta/comptimeValues para mostrar al usuario los valores que el
     * compilador resolvio en tiempo de compilacion.
     */
    struct ComptimeValueSnapshot {
        std::string name;  ///< Nombre de la constante comptime.
        std::string scope; ///< Ambito (best-effort; "" = global/desconocido).
        std::string type_kind;    ///< "int"|"string"|"array"|"struct"|"type".
        std::string value_str;    ///< Representacion legible del valor.
        SourceLoc loc;            ///< Ubicacion de la expresion (para hover);
                                  ///< line==0 si no aplica (consts top-level).
        std::string builtin_kind; ///< "sizeof"/"alignof"/"kind"/"type_id"/
                                  ///< "typename" si proviene de un builtin; ""
                                  ///< para constantes comptime normales.
    };
    std::vector<ComptimeValueSnapshot> comptime_values;
};

/**
 * @brief Compila una cadena .vx a texto .vel.
 *
 * Pipeline interno:
 *
 *   .vx source
 *     -> Lexer (token stream)
 *     -> Parser  (AST)
 *     -> TypeChecker (rellena result_type, valida)
 *     -> Lowering (AST -> ir::IrModule)
 *     -> ir::ir_emit_module (IR -> texto .vel)
 *
 * No aplica VPP; el caller debe haberlo aplicado antes si quiere
 * habilitar la metaprogramacion.
 *
 * @param source   Codigo fuente Vesta.
 * @param filename Nombre logico del fichero para diagnosticos.
 * @param opts     Opciones de compilacion.
 * @return CompileResult con el .vel y el set de diagnosticos.
 */
CompileResult compile_vx_source(const std::string &source,
                                const std::string &filename,
                                const CompileOptions &opts = {});

/**
 * @brief Compila un proyecto multi-modulo ( M.2.e).
 *
 * Resuelve los @c import del fichero raiz via @c ModuleGraph,
 * compila cada modulo en orden topologico (deps primero), inyecta
 * los .vxi entre dependientes, y emite un unico @c .vel con todas
 * las funciones mergeadas.
 *
 * Restricciones MVP:
 *   - Solo @c "only A, B" imports inyectan simbolos (alias y namespace
 *     son features posteriores).
 *   - Sin mangling automatico: el usuario es responsable de que los
 *     nombres de funciones no colisionen entre modulos.
 *   - Sin link separado: todos los modulos se mergean en un solo .vel.
 *
 * @param root_path Path absoluto o relativo del @c .vx raiz.
 * @param opts      Opciones de compilacion.
 * @param source_overlay Opcional: mapa path->texto en memoria (overlay).  Usado
 *        por el LSP para analizar el buffer del editor (root) resolviendo los
 *        imports del disco.  @c nullptr => todo del disco (ruta normal).
 * @param extra_search_paths Opcional: directorios extra donde resolver imports.
 *        Usado por el LSP para resolver imports relativos al root del proyecto
 *        (p.ej. `import "modules/buffer"`) cuando se analiza un fichero-modulo
 *        que no es la raiz (se le pasan sus directorios ancestros).
 * @return CompileResult con el @c .vel mergeado + diagnostics.
 */
CompileResult compile_vx_project(
    const std::string &root_path, const CompileOptions &opts = {},
    const std::unordered_map<std::string, std::string> *source_overlay =
        nullptr,
    const std::vector<std::string> *extra_search_paths = nullptr);

/**
 * @brief Detecta si el source @c .vx contiene @c import declaraciones
 * top-level.  Heuristica permisiva (string-scanner que respeta
 * comentarios y strings).  Usado por @c main.cpp para decidir si
 * dispatchar a @c compile_vx_project en lugar de @c compile_vx_source.
 *
 * @param source Texto Vesta.
 * @return @c true si encuentra al menos un @c import top-level.
 */
bool vx_source_has_imports(const std::string &source);

/**
 * @brief El fuente declara un `namespace`?
 *
 * Se pregunta para saber si hay que compilarlo como PROYECTO aunque no importe
 * nada: un namespace puede estar repartido entre varios ficheros -- el base y
 * uno por arquitectura --, y entonces el fichero suelto no se sostiene, porque
 * usa tipos que declaran sus hermanos.
 *
 * Sin esto, `--analyze` sobre `std/types.vx` moria en "tipo no resuelto en
 * alias": el criterio era "tiene imports?", y ese fichero no importa nada.
 * O sea que la base de tipos de la que depende media stdlib era invisible para
 * el analisis.
 *
 * @param source Texto Vesta.
 * @return true si aparece la palabra `namespace` fuera de comentarios y
 * cadenas.
 */
bool vx_source_declara_namespace(const std::string &source);

/**
 * @brief Convierte en diagnosticos los accesos que se salen DEMOSTRABLEMENTE
 *        de su region.
 *
 * Los fallos que el analisis puede demostrar no pueden vivir solo en
 * `--analyze`: tienen que salir AL COMPILAR, que es cuando se leen.  Consume el
 * mismo comprobador que usa el informe
 * (`analysis::effects::check_region_bounds`) para que no haya dos criterios.
 *
 * @param mod   Modulo IR ya optimizado (el codigo que de verdad se va a
 * emitir).
 * @param diags Bolsa donde se acumulan.
 */
/**
 * @brief Comprueba las PRECONDICIONES de los bloques de asm sobre el IR.
 *
 * Hoy solo una, la que costo un fallo: hay instrucciones que EXIGEN su
 * direccion alineada, y una direccion que no lo esta no las hace ir mas
 * lentas, hace caer el programa.
 *
 * Se hace aqui y no al bajar el asm porque aqui SI se puede responder: el
 * hecho de alineacion necesita la funcion entera, y al bajar todavia se esta
 * construyendo.  Con el hecho hay tres respuestas y no una:
 *
 *   - se demuestra que cumple  -> nada que decir;
 *   - se demuestra que NO      -> error, con la prueba;
 *   - no se puede demostrar    -> aviso, diciendo que no se pudo.
 *
 * La de en medio es la que faltaba: cuando se SABE que esta mal, avisar no
 * basta.
 *
 * @param mod Modulo ya bajado.
 * @param diags Donde reportar.
 * @param file Fichero al que atribuir la posicion.
 * @param facts Almacen del ASA de ESTA compilacion.  Se recibe, no se crea:
 *               el conocimiento es de la compilacion y no de quien pregunta, y
 *               fabricarse uno propio haria que dos consumidores del mismo
 *               dominio pagaran el calculo dos veces.  Aqui dentro se pide
 *               unicamente el dominio que se va a consultar, y pedirlo es
 *               idempotente: si otro ya lo produjo, no se vuelve a correr.
 */
void vx_report_asm_preconditions(const ir::IrModule &mod, Diagnostics &diags,
                                 const std::string &file, bool programa_cerrado,
                                 bool decir_lo_no_acotado, const char *backend,
                                 analysis::asa::FactStore &facts);

void vx_report_bounds(const ir::IrModule &mod, Diagnostics &diags,
                      const std::string &file);

} // namespace vx

#endif // VX_COMPILER_H
