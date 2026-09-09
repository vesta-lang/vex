/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact_base.h
 * @brief La base de hechos: lo que se sabe del programa, en UN sitio, con su
 *        procedencia y su certeza, para que quien lo necesite CONSULTE en vez
 *        de redescubrirlo.
 *
 * Es la Regla 1 hecha objeto: un pase CONSUME la base, no la CONSTRUYE.  Vive
 * en @c analysis/ y no en @c jit/ porque no es del JIT: el compilador en
 * caliente es UN consumidor, y lo mismo valen el volcado
 * (@c analysis/asa/dump.h), el nativo o una herramienta.
 *
 * POR QUE IMPORTA MAS ALLA DE AHORRAR UN COMPUTO.  Un consumidor que construye
 * lo que necesita solo puede preguntar por lo que sabe construir: se queda con
 * un dominio y con la precision que ese sitio del codigo se molesto en pedir.
 * Uno que CONSULTA puede cruzar dominios sin cambiar, y sobre todo puede
 * recibir hechos que EL no sabe producir -- los que solo existen ejecutando,
 * que es lo que aportara el C2.  Anadir una fuente de conocimiento pasa a ser
 * anadir un productor, no tocar a cada consumidor.
 *
 * DE DONDE VIENE UN HECHO NO ES ASUNTO DEL CONSUMIDOR.  Analisis estatico,
 * observacion en ejecucion o perfil de corridas anteriores alimentan la MISMA
 * base.  Lo que el consumidor mira es el hecho y su certeza -- que viaja DENTRO
 * del hecho, no la pone quien pregunta.  De ahi sale la guarda: no porque el
 * especulador lo decida, sino porque un hecho observado nace sin demostrar.
 *
 * AMBITO Y VIDA.  Una base vale para UN modulo: dentro de el un nombre
 * identifica una funcion, que es lo que hace legitimo cachear por nombre. Quien
 * la crea la mantiene viva mientras trabaja sobre ese modulo y se la pasa a
 * cada consumidor; el conocimiento se calcula una vez y se reparte.  Sin base,
 * el consumidor se monta la suya como ultimo recurso: correcto, solo sin
 * reparto.
 *
 * MUTAR EL IR CADUCA LOS HECHOS.  Ya no hace falta acordarse: la version de la
 * funcion entra en la consulta y un resultado de otra version no se entrega.
 * @c invalidate sigue existiendo para tirar algo a proposito.
 *
 * ===========================================================================
 * LOS TRES NIVELES DE CACHE, Y QUE GUARDA CADA UNO
 * ===========================================================================
 *
 * Esto esta dibujado porque el fallo que se repite NO es cachear mal: es
 * cachear en el nivel equivocado, o construir un mecanismo y no adoptarlo.  Han
 * aparecido SEIS mecanismos correctos y sin usar mientras se investigaba esto.
 * Antes de anadir uno nuevo, mirar aqui cual es su nivel.
 *
 *   fuente .vx                                       QUE SE GUARDA
 *      |                                             -------------
 *      v
 *   [3] CAS / cache de proyecto ................... el IR y los artefactos
 *      |    clave: BuildConfig POR CAPAS               (.vxir, .vxi, .velb)
 *      |      ir_fingerprint()   -> lo pre-optimize
 *      |      full_fingerprint() -> + opt/codegen
 *      |    + hash del fuente + deps + mandos `Emitted`
 *      v
 *   IrModule  --------------------------------------------------------+
 *      |                                                              |
 *      v                                                              |
 *   [1] FactBase / AnalysisManager (ESTA CLASE) ... los ANALISIS       |
 *      |    clave: (analisis, funcion|modulo, MOMENTO) + VERSION       |
 *      |    vida: la de la base.  NO va a disco.                       |
 *      |                                                              |
 *      |  IrFacts, PointsTo, RangeFacts, LoopFacts, DemandedBits,      |
 *      |  EffectAnalysis, Escape, ModuleWalk, ParamAliasing...         |
 *      v                                                              |
 *   productores  ->  FactStore  ->  [2] fichero .vxfacts ..... los HECHOS
 *                                        clave: POR CAPAS, ver abajo
 *                                        vida: entre compilaciones
 *
 * LAS TRES CAPAS DE CLAVE DE [2].  De gruesa a fina; cada una decide un
 * descarte mas pequeno, y por eso importa que existan las tres:
 *
 *   modulo    -> `asa_facts_key`: fuente + BuildConfig (la CAPA que toque:
 *                `ir_fingerprint` pre-opt, `full_fingerprint` post-opt) + el
 *                momento.  Si no cuadra se tira el fichero ENTERO -- habla de
 *                otro programa o de otra configuracion.
 *   dominio   -> `DomainCost::fingerprint`, el plegado de las ENTRADAS que ese
 *                dominio declara mirar (`DomainInput`).  Si no cuadra se tira
 *                SU registro y los demas siguen: tocar codigo no invalida a
 *                quien solo mira los datos estaticos.
 *   funcion   -> `DomainCost::by_function`, la misma cuenta pero tomando de la
 *                funcion lo suyo y del modulo lo del modulo.  Si no cuadra se
 *                tiran los hechos de ESA funcion y entran los de las demas.
 *
 * LA CARGA PARCIAL, Y POR QUE NECESITA DOS MARCAS.  Cuando solo unas funciones
 * caducan, el lector trae el resto y el productor tiene que rehacer lo que
 * falta.  Eso obliga a distinguir dos cosas que antes eran una:
 *
 *   `FactStore::mark_domain(dom, momento)`     -> "este dominio esta COMPLETO"
 *   `FactStore::mark_function(dom, mom, fn)`   -> "de este dominio, esta funcion
 *                                                  ya vino de disco"
 *
 * En carga parcial se marcan las FUNCIONES y NO el dominio.  Asi `produce`
 * corre -- porque el dominio no esta completo -- y `Production::is_interesting`
 * le salta una a una las que ya estan.  Las dos marcas mal puestas fallan en
 * silencio y de formas opuestas: marcar el dominio deja un AGUJERO que nadie
 * produce; no marcar las funciones DUPLICA lo que se acaba de cargar.
 *

 * QUE SE REUTILIZA HOY, Y QUE NO
 *
 *   [1] SI, dentro de una compilacion.  Pregunta la misma cosa dos veces y se
 *       computa una.  Lo garantiza `tests/analysis/test_fact_base_reuse.cpp`,
 *       que ademas comprueba lo contrario: que al subir la version SI se
 *       recalcula, y que tocar una funcion no invalida a su vecina.
 *
 *   [2] SI, entre compilaciones, pero SOLO lo publicado.
 *
 *   [1] entre compilaciones: NO.  Y ahi esta el trabajo tirado: en una
 *       recompilacion sin cambios se rehace TODO el razonamiento -- points-to,
 *       rangos, efectos -- y solo se ahorra el publicar.  Se cachean las
 *       CONCLUSIONES y no el RAZONAMIENTO.  Ver el plan del ASA incremental.
 *
 * LAS TRAMPAS QUE YA MORDIERON.  Todas daban silencio, no error:
 *
 *   - **El MOMENTO tiene que estar en la clave.**  Sin el, lo analizado antes
 *     de optimizar se sirve despues, sobre un codigo que ya no existe.  Ocho de
 *     diez accesores no lo llevaban.
 *   - **La VERSION tambien.**  Estos analisis guardan punteros a instrucciones:
 *     servir uno viejo no es imprecision, es leer memoria liberada.  Esta clase
 *     hacia ONCE llamadas a la puerta sin versionar y cero a la versionada.
 *   - **`cached()` no mira la version**; contesta "hay algo guardado", que no es
 *     "se va a reutilizar".  Para contar reuso o refrescar sellos, @c cached_v.
 *   - **La capa de `BuildConfig` importa**: `ir_fingerprint()` excluye el
 *     `opt_level` A PROPoSITO porque describe el IR pre-optimize.  Usarla para
 *     keyar hechos POST-opt sirve los de otro nivel de optimizacion.
 *   - **Un mecanismo sin adoptar parece uno que funciona.**  La validacion por
 *     dominio del lector de [2] existe y solo UN dominio de dieciseis la usa;
 *     los demas entran con huella nula, que ademas les impide caducar.
 *   - **Sellar y comprobar tienen que salir de la MISMA cuenta.**  Lo que se
 *     escribia en [2] salia de los resumenes de produccion, que solo traen lo
 *     recien producido; un dominio servido desde la cache se reescribia con
 *     huella CERO, o sea que su validacion se borraba sola en cuanto acertaba
 *     una vez.  El sintoma era el contrario del problema: acertaba SIEMPRE.
 *   - **La carga parcial solo vale si alguien va a producir lo que falta.**  Se
 *     le ofrece unicamente a los dominios pedidos (`wanted`); uno cargado a
 *     medias que nadie produce se reescribiria sellado como completo.
 *
 * COMO SE ANADE UN ANALISIS NUEVO A [1]
 *
 *   1. Un accesor aqui que tome `(unidad, stage = nullptr)`.
 *   2. La clave con @c key_of / @c module_key y @c stage_or_default.
 *   3. La version: @c IrFunction::version si es por funcion,
 *      @c module_version si es del modulo.
 *   4. Pedir por @c get_or_compute_v -- NUNCA la variante sin version -- y
 *      contar lo fresco con @c cached_v.
 *   5. Lo que ese analisis necesite de otros, pedirlo POR LA BASE: asi el
 *      gestor anota la dependencia solo y una invalidacion arrastra.
 */
#ifndef ANALYSIS_ASA_FACT_BASE_H
#define ANALYSIS_ASA_FACT_BASE_H

#include "analysis/asa/fact.h"
#include "analysis/facts/ir_facts.h"
#include "analysis/facts/loop_facts.h"
#include "analysis/facts/loop_iv_bounds.h"
#include "analysis/facts/range_summary.h"
#include "analysis/facts/demanded_bits.h"
#include "analysis/facts/value_range.h"
#include "analysis/manager/analysis_manager.h"
#include "analysis/manager/analysis_store.h" // el nivel [1] a DISCO, entre compilaciones
#include "analysis/effects/effect_analysis.h" // el motor de efectos, compartido
#include "analysis/effects/param_aliasing.h"  // que le llega a cada parametro
#include "analysis/escape/escape.h"          // que sobrevive a la funcion
#include "analysis/memory/points_to.h"

#include <cstddef>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

namespace ir {
struct IrFunction;
struct IrModule;
} // namespace ir

namespace analysis {
namespace asa {

/// El recorrido del modulo; su definicion vive con los productores, que son
/// quienes lo llenan.  Aqui solo se cachea y se reparte.
struct ModuleWalk;

/// Los dominios que hoy guarda la base.  Nombres ESTABLES: son la procedencia
/// que aparece en el volcado, no texto de usuario.
///
/// Se DECLARAN aqui y se definen una sola vez en el .cpp, y eso no es
/// cosmetico: ASA identifica al productor por la DIRECCION del literal
/// (@c Support::depends_on compara punteros).  Con @c constexpr cada unidad de
/// traduccion plegaria la lectura a SU propio literal -- los literales no se
/// unifican entre ficheros objeto -- y el mismo productor dejaria de
/// reconocerse a si mismo visto desde otro fichero.
extern const char *const kProducerStructure;
extern const char *const kProducerRanges;
extern const char *const kProducerMemory;

/// Que efectos tiene cada funcion del modulo -- que memoria toca, si puede
/// fallar, si puede lanzar --, cerrado sobre el grafo de llamadas.  Lo pedian
/// el optimizador y el comprobador de regiones, y cada uno se lo calculaba
/// ENTERO por su cuenta: casi un siete por ciento del tiempo de compilar
/// gastado dos veces en lo mismo.
extern const char *const kProducerEffects;

/// Que se ESCAPA de cada funcion: reservas locales que sobreviven y parametros
/// que la funcion deja sueltos.  Lo calculaba el motor de efectos y lo TIRABA
/// en una variable local; cuesta un punto fijo sobre el modulo entero.
extern const char *const kProducerEscape;
extern const char *const kProducerBoundary;
extern const char *const kProducerLoops;
/// Como se COLOCA la memoria del programa: lo unico que un compilador con
/// enlazador propio sabe y uno tradicional no.
extern const char *const kProducerLayout;
/// El FLUJO DE CONTROL dentro de un bloque `asm`: cuantos bloques basicos
/// tiene, de que clase es cada terminador y que destinos quedan sin resolver.
extern const char *const kProducerAsmFlow;
/// Que un bucle es en realidad UNA operacion de bloque -- un relleno o una
/// copia escritos largos.  Publico y no interno del productor porque lo
/// afirman DOS sitios: el dominio, mirando el codigo, y el pase que lo reduce,
/// que lo dice justo antes de que el bucle deje de existir.
extern const char *const kProducerBulkMemory;
/// Que operaciones NO puede compilar un backend, y por que.  El analisis lo
/// hace `aot_analyze` desde hace tiempo -- clasifica cada op del intermedio
/// contra un objetivo nativo -- y lo consumia UN solo sitio, el editor.  Aqui
/// se convierte en conocimiento compartido: el mismo hecho lo lee tambien el
/// linter, y cualquiera que venga despues, sin volver a analizar nada.
extern const char *const kProducerBackend;
/// Que FORMA tiene un valor: si es un agregado, cual, y con que campos.  Se
/// exporta -- no se queda dentro de su unidad -- porque su alcance importa
/// fuera: su recorrido SIGUE LAS LLAMADAS, asi que es uno de los dos dominios
/// que no admiten clave por funcion.  @see DomainInput::CallGraph
extern const char *const kProducerValueShape;

/// La COBERTURA de una vista `@overlay`: que bytes ocupa cada campo, en el
/// marco de simbolos del que cuelga su offset.  Es conocimiento de TIPO -- lo
/// unico que lo sabe es el frontend, que tiene la expresion del offset
/// delante --, y sin publicarlo aqui la pregunta "puede esta escritura pisar a
/// aquel campo" no tenia a quien hacersela: ni el linter ni el optimizador ven
/// el layout de una vista.
extern const char *const kProducerOverlays;

/// Cuantos bits de cada valor LLEGA A MIRAR alguien.  La pregunta dual de los
/// rangos y los KnownBits: aquellos van hacia adelante -- que garantiza quien
/// produce --, este hacia atras -- que lee quien consume --.  Vivio escrito a
/// mano dentro de un pase del optimizador, con su propia lista de consumidores
/// tolerados, y por eso se quedaba corto sin que nadie lo notara.
extern const char *const kProducerDemandedBits;

/// Lo que cada PARAMETRO promete de la region a la que apunta: si se lee, si se
/// escribe, si esa region no la alcanza nadie mas, cuanto mide, como esta
/// alineada.  Varias formas del lenguaje escriben ahi -- `in`/`out`/`inout`,
/// `borrow`/`borrow_mut`, `unique<T>`, `nonnull` -- y son formas de decir lo
/// mismo, no mecanismos distintos.
///
/// Se publica porque su AUSENCIA es lo que mas dice: sin la marca, dos
/// parametros no se pueden dar por regiones distintas, y de eso depende que una
/// lectura pueda adelantar a una escritura o que una copia campo a campo se
/// reduzca a una operacion de bloque.  Callarlo dejaba al programador sin saber
/// que una palabra suya cambia el codigo que sale.
extern const char *const kProducerParamContracts;

/// Clave con la que se guarda lo que es del MODULO entero y no de una funcion.
extern const char *const kModuleUnit;

/**
 * @brief Da de alta los nombres de arriba como CANONICOS.
 *
 * Perezoso y a peticion: hace falta antes de leer hechos de disco, porque ASA
 * compara productores por direccion y una cadena recien leida no se
 * reconoceria a si misma.  No es un inicializador estatico a proposito --
 * reservar memoria antes de @c main corre las direcciones de todo lo demas.
 */
void register_asa_canonical_names();

/**
 * @brief Las POSICIONES de una funcion, indexadas para resolver anclas.
 *
 * La UNICA puerta que convierte un ancla en una linea, y por eso vive aqui y no
 * en cada consumidor: si cada uno lo resolviera a su manera, dos herramientas
 * senalarian sitios distintos para el mismo hecho -- que es exactamente la
 * bifurcacion que el ASA existe para quitar.
 *
 * Se resuelve AL CONSULTAR, contra el intermedio que el consumidor tiene
 * delante, no al producir.  Esa es la diferencia que hace que una posicion no
 * pueda quedarse rancia: no se guarda una linea, se guarda A QUE ENTIDAD
 * pertenece, y la linea sale del codigo que se esta mirando ahora.  De ahi que
 * mover texto -- reindentar, un comentario, una linea en blanco -- no invalide
 * NADA: la afirmacion depende del codigo, la posicion se deriva aparte.
 *
 * @par Por que es una CLASE y no una funcion suelta
 * Porque resolver un ancla suelta obliga a recorrer la funcion, y un consumidor
 * resuelve TODOS los hechos de esa funcion: eso seria O(hechos x
 * instrucciones), cuadratico en cuanto hay un hecho por valor -- que es el caso
 * normal --.  Construyendo el indice una vez sale O(instrucciones + hechos).
 * No hay version suelta A PROPoSITO: asi la forma cuadratica no se puede ni
 * escribir por descuido.
 *
 * Vive aqui y no en `fact.h` porque necesita el intermedio, y `fact.h` es la
 * FORMA del conocimiento: atarlo al IR obligaria a arrastrarlo a cualquiera que
 * solo quiera leer hechos.
 */
class AnchorLines {
  public:
    /// Recorre @p fn UNA vez.  El indice vale mientras @p fn no se toque.
    explicit AnchorLines(const ir::IrFunction &fn);

    /**
     * @brief La linea a la que apunta @p a.  O(1).
     * @return La linea, o 0 si no se puede decir -- que NO es la linea 1: cero
     *         significa "no consta", y quien pregunta decide si cae al
     *         principio de la funcion o se calla.  Confundirlos ya mordio en el
     *         linter, que acababa senalando lineas de otro fichero.
     */
    uint32_t of(const Anchor &a) const;

  private:
    /// Tres vectores planos indexados por id, no tablas asociativas: los ids
    /// son densos y consecutivos, asi que un mapa seria indireccion para nada.
    std::vector<uint32_t> by_value_; ///< value-id -> linea de su definicion.
    std::vector<uint32_t> by_block_; ///< bloque -> su primera linea con dato.
    std::vector<uint32_t> by_instr_; ///< posicion lineal -> su linea.
};

/**
 * @brief Una entrada de la base, tal y como se vuelca.
 *
 * Es DATO, no frase: quien quiera ensenarlo lo formatea.  Lleva el sello de ASA
 * -- certeza, procedencia y de que otros hechos se dedujo -- porque un hecho
 * sin origen no se puede explicar ni depurar, y porque de la certeza depende lo
 * que el consumidor tiene derecho a hacer con el.
 */
struct RecordedFact {
    const char *domain = kProducerStructure;
    std::string function;
    Seal seal;
};

/**
 * @brief Base de hechos compartida.
 *
 * Cachea por funcion y calcula bajo demanda.  Las dependencias entre dominios
 * las anota el @c AnalysisManager solo: cuando el computo de uno pide otro por
 * la base, queda registrado, y asi invalidar el de abajo arrastra al de arriba.
 */
class FactBase {
  public:
    /// Al morir cuenta lo que repartio si se pide con @c
    /// VESTA_ASA_HECHOS_DEBUG: una base compartida que no ahorra ninguna
    /// pregunta es un computo con otro nombre, y eso se ve o no se ve.
    /**
     * @brief Da de alta los nombres canonicos del ASA.
     *
     * Aqui y no en un inicializador estatico: reservar memoria antes de
     * @c main corre las direcciones de todo lo demas, y en un programa que
     * dependa de la alineacion de lo suyo eso cambia si funciona o no.  Y aqui
     * y no dentro del fichero de hechos, que es el formato y no tiene por que
     * conocer a los productores de nadie.
     */
    FactBase();
    /**
     * @brief Base con un momento POR DEFECTO.
     *
     * Es lo que evita repetir el momento en cada consulta cuando la base
     * describe un solo instante, que es el caso comun.  No lo cierra: cada
     * accesor admite el suyo, porque **la misma pregunta se puede hacer en dos
     * momentos distintos** y las dos respuestas son ciertas -- de codigos
     * distintos --.  Lo que no se puede es confundirlas, y por eso el momento
     * entra en la clave de la cache siempre, se pase o se herede.
     *
     * @param stage @see kStagePreOpt, kStageDuringOpt, kStagePostOpt.
     */
    explicit FactBase(const char *stage);
    ~FactBase();
    FactBase(const FactBase &) = delete;
    FactBase &operator=(const FactBase &) = delete;

    /**
     * @brief Conecta el almacen ENTRE compilaciones (el nivel [1] a disco).
     *
     * Sin el -- que es el defecto -- todo se computa, que es el comportamiento
     * de siempre: no tener cache nunca puede ser un error.  Quien compila abre
     * el almacen una vez y lo presta; la base no lo posee.
     *
     * @param s El almacen, o @c nullptr para no usar ninguno.
     */
    void set_analysis_store(AnalysisStore *s) noexcept { analysis_store_ = s; }

    /**
     * @brief Hechos estructurales de @p fn: def-use, sitios de llamada, bucles.
     * @param fn Funcion IR a consultar.
     * @return Los hechos, cacheados mientras viva la base.
     */
    const IrFacts &structure(const ir::IrFunction &fn,
                             const char *stage = nullptr);

    /**
     * @brief Entre que dos numeros esta cada valor de @p fn.
     * @param fn Funcion IR a consultar.
     * @return Los rangos por valor SSA, cacheados mientras viva la base.
     */
    const RangeFacts &ranges(const ir::IrFunction &fn,
                             const char *stage = nullptr);

    /**
     * @brief Cuantos bits de cada valor de @p fn llega a mirar alguien.
     *
     * La pregunta DUAL de los rangos y los KnownBits: aquellos dicen que
     * garantiza quien produce el valor, y esta que llegan a leer los que lo
     * consumen.  Ninguna implica a la otra -- de un parametro no se puede
     * probar nada por delante, y sin embargo si lo unico que se hace con una
     * cuenta es escribirla en un campo de cuatro bytes, los bits de arriba no
     * los mira nadie --.
     *
     * @param fn Funcion IR a consultar.
     * @return Los bits demandados por valor, cacheados mientras viva la base.
     */
    const DemandedBits &demanded(const ir::IrFunction &fn,
                                 const char *stage = nullptr);

    /**
     * @brief A que memoria puede referirse cada puntero de @p fn.
     * @param fn Funcion IR a consultar.
     * @return La tabla points-to, cacheada mientras viva la base.
     */
    const PointsTo &memory(const ir::IrFunction &fn,
                           const char *stage = nullptr);

    /**
     * @brief Forma del CFG de @p fn: bucles, cabeceras y profundidad.
     * @param fn Funcion IR a consultar.
     * @return Los hechos de bucle, cacheados mientras viva la base.
     */
    const LoopFacts &loops(const ir::IrFunction &fn,
                           const char *stage = nullptr);

    /**
     * @brief Hasta donde llega la variable de cada bucle CONTADO de @p fn.
     *
     * Se pide ANTES que los rangos y va DENTRO de ellos, como suelo.  El orden
     * no es casual: esto no consulta rangos -- solo la forma del bucle y las
     * constantes escritas --, asi que puede alimentarlos sin que se muerdan la
     * cola.  Al reves seria imposible.
     *
     * @param fn Funcion IR a consultar.
     * @return Las cotas por valor SSA, cacheadas mientras viva la base.
     */
    const LoopIvBounds &iv_bounds(const ir::IrFunction &fn,
                                  const char *stage = nullptr);

    /**
     * @brief Lo que cruza la frontera de cada funcion del modulo.
     *
     * Es conocimiento DEL MoDULO, no de una funcion: para saber que le llega a
     * un parametro hay que ver a todos los que llaman.  Por eso se cachea una
     * vez por base y no por funcion.
     *
     * @param mod Modulo completo.
     * @return Los resumenes de entrada y salida por funcion.
     */
    const RangeSummaries &boundary(const ir::IrModule &mod,
                                   const char *stage = nullptr);

    /**
     * @brief Si dos parametros puntero de una funcion reciben la misma region.
     *
     * Conocimiento DEL MoDULO por el mismo motivo que el de arriba: dentro de
     * la funcion sus parametros son dos nombres, y quien sabe que le llega a
     * cada uno es quien la llama.
     *
     * Vive aqui y no dentro de un consumidor porque lo preguntan DOS -- el
     * productor de contratos de parametro, que lo afirma, y la comprobacion de
     * prestamos, que lo cruza con la exclusividad prometida --, y calcularlo en
     * cada uno serian dos productores del mismo hecho.
     *
     * @param mod Modulo completo.
     * @param stage EN QUE MOMENTO se pregunta.  @see kStage*.  Va en la clave
     *              porque esto se apoya en los efectos, que ya se piden con el:
     *              el resumen de antes de optimizar describe otro codigo que el
     *              de despues, y darle uno al otro habla de memoria que ya no
     *              se toca.
     * @return Los veredictos por (funcion, par), cacheados una vez por momento.
     */
    const effects::ParamAliasing &param_aliasing(const ir::IrModule &mod,
                                                 const char *stage);

    /**
     * @brief El modulo recorrido UNA vez: quien llama a quien.
     *
     * Lo comparten los productores y quien necesite mirar los argumentos con
     * los que una funcion se usa de verdad.  Vive aqui porque si cada uno lo
     * construye por su cuenta vuelve la pasada de mas que `ModuleWalk` existe
     * justo para quitar.
     *
     * @param mod Modulo completo.
     * @return El indice de llamadas, cacheado una vez por base.
     */
    const ModuleWalk &walk(const ir::IrModule &mod,
                           const char *stage = nullptr);

    /**
     * @brief Que EFECTOS tiene cada funcion del modulo: que memoria toca, si
     *        puede fallar, si puede lanzar.
     *
     * Conocimiento DEL MoDULO, como el de arriba y por lo mismo: el efecto de
     * una funcion incluye el de todo lo que llama, asi que no se puede resolver
     * mirandola sola.
     *
     * Vive aqui porque lo piden VARIOS y cada uno se lo calculaba entero: el
     * optimizador -- para saber que llamadas son puras y no hacen de barrera --
     * y el comprobador de regiones -- para saber que puede escribir cada una --.
     * Cada uno construia su propio motor desde cero, y medido con VTune sobre
     * un programa de veintiocho mil lineas eso eran 3,4 % y 3,1 % del tiempo de
     * compilar: casi el siete por ciento gastado DOS veces en lo mismo.
     *
     * Es exactamente lo que el primer invariante prohibe -- un hecho, un
     * productor -- aplicado a algo que no estaba aqui.
     *
     * Se entrega el MOTOR y no solo el resumen porque hay quien necesita sus
     * tablas -- el comprobador de regiones pregunta despues por cada acceso --,
     * y devolver el resumen suelto obligaria a construir el motor otra vez para
     * eso.  El resumen ya viene calculado: pedirselo al motor no lo recalcula.
     *
     * **Va por MOMENTO, y eso no es un detalle de la cache**: el efecto de una
     * funcion CAMBIA al optimizarla.  Lo que el optimizador mira al empezar y
     * lo que el comprobador de regiones mira al acabar no son el mismo hecho
     * repetido, son dos hechos distintos, cada uno cierto en su momento.
     * Compartirlos entre momentos le daria a uno de los dos un resumen del
     * codigo que ya no existe -- y eso no falla: avisa de accesos que ya no
     * estan, o deja de avisar de uno real --.
     *
     * Lo que SI sobra es que dos consumidores del MISMO momento lo calculen
     * cada uno, que es lo que pasaba: medido con VTune sobre veintiocho mil
     * lineas, 3,4 % desde el optimizador y 3,1 % desde el comprobador.
     *
     * @param mod   Modulo completo.
     * @param stage En que momento se pregunta.  @see kStage*.
     * @return El motor con su resumen ya hecho, mientras viva la base.
     */
    effects::EffectAnalysis &effects(const ir::IrModule &mod,
                                     const char *stage);

    /**
     * @brief Que SE ESCAPA de cada funcion: que reservas locales sobreviven y
     *        que parametros deja sueltos.
     *
     * Conocimiento del MoDULO -- si un parametro escapa depende de a quien se
     * lo pase la funcion, y eso exige el punto fijo del grafo de llamadas --,
     * asi que se cachea una vez por base.
     *
     * Estaba: el motor de efectos lo calculaba para saber que puede observarse
     * desde fuera, lo usaba una vez y lo TIRABA en una variable local.  Cuesta
     * un punto fijo sobre el modulo entero y responde a mas de una pregunta --
     * si un puntero sobrevive a la llamada, si una reserva puede vivir en la
     * pila --, asi que dejarlo morir era pagarlo y no cobrarlo.
     *
     * @param mod Modulo completo.
     * @return Por nombre de funcion, lo que se le escapa.  Cacheado.
     */
    const std::unordered_map<std::string, EscapeInfo> &
    escape(const ir::IrModule &mod);

    /**
     * @brief Los hechos de @p fn han caducado porque su IR cambio.
     * @param fn Funcion IR cuyo conocimiento se descarta (en cascada).
     */
    void invalidate(const ir::IrFunction &fn);

    /**
     * @brief El sello del conocimiento de @p producer sobre @p fn.
     *
     * La certeza NO la pone quien pregunta, viaja DENTRO del hecho, y de ella
     * se sigue lo que el consumidor puede hacer: sobre un hecho @c Proven se
     * puede quitar una comprobacion; sobre uno @c Inferred -- el analisis paro
     * por presupuesto, o manana: lo observado en ejecucion -- hay que dejar
     * red, o sea una guarda.
     *
     * @param producer Uno de los @c kProducer*.
     * @param fn       Funcion IR consultada.
     * @return El sello, o uno @c Unknown si nadie ha preguntado todavia.
     */
    Seal seal(const char *producer, const ir::IrFunction &fn) const;

    /// Igual que @c seal pero para lo que es del modulo entero (la frontera).
    Seal module_seal(const char *producer) const;

    /**
     * @brief Todo lo que la base sabe, en DATOS y en orden estable.
     *
     * Un conocimiento que no se puede volcar no se puede auditar: ni explicar
     * un veredicto, ni ver por que un analisis se callo, ni comprobar que la
     * procedencia es la que se cree.  Ordenado por funcion y dominio para que
     * dos volcados se puedan comparar.
     *
     * @return Una entrada por hecho vivo.
     */
    std::vector<RecordedFact> dump() const;

    /// Preguntas atendidas.  Con @c computations mide el reparto de verdad, que
    /// es lo unico que distingue una base compartida de un computo con otro
    /// nombre.
    /**
     * @brief La VERSION del modulo: cuanto ha cambiado, como un solo numero.
     *
     * Lo que es @c IrFunction::version para una funcion, pero para lo que se
     * cachea del modulo ENTERO -- el recorrido de llamadas, los resumenes de
     * frontera, los efectos, que le llega a cada parametro --.  Pliega las
     * versiones de todas sus funciones: si cualquiera cambia, el resultado
     * puede cambiar, que es exactamente cuando esos analisis dejan de valer.
     *
     * @par Como se usa
     * No hace falta llamarla para consultar la base -- los accesores de modulo
     * ya lo hacen --.  Se expone porque es una pregunta legitima por si misma
     * ("ha cambiado algo de este modulo desde que mire") y porque sin ella no se
     * puede COMPROBAR que la reutilizacion funcione, que es la mitad del valor.
     *
     * @par Y no es una suma, a proposito
     * Dos funciones que se intercambiaran versiones -- una sube, otra baja --
     * darian la misma suma, y un modulo se serviria con los resumenes del otro.
     * Se pliega mezclando, asi que la posicion cuenta.
     *
     * Cuesta O(funciones) y se pide una vez por consulta, no por funcion: frente
     * a recalcular un punto fijo sobre el grafo de llamadas, no se nota.
     */
    static uint64_t module_version(const ir::IrModule &mod) noexcept;

    size_t queries() const { return queries_; }
    /// Analisis que hubo que ejecutar de verdad (los demas salieron de la
    /// cache).
    size_t computations() const { return computations_; }

  private:
    /// Identidad de @p fn dentro del modulo.  Sin nombre no hay identidad
    /// estable, y entonces vale su direccion: es unica mientras la funcion
    /// viva, que es lo que dura la base.
    /// La clave de @p fn: el nombre INTERNADO, no una copia.  Se llama al
    /// principio de cada accesor, asi que devolverlo por valor era una reserva
    /// por consulta.
    /// @brief La clave de @p fn EN @p stage.
    ///
    /// El momento va SIEMPRE en la clave.  Sin el, el analisis que se hizo
    /// antes de optimizar se sirve despues, y entonces se contesta sobre un
    /// codigo que ya no existe -- valores que el optimizador borro, bloques que
    /// fusiono -- sin dar ningun error: solo respuestas equivocadas.  Es el
    /// mismo motivo que el de @ref effects, que lo llevaba desde el principio,
    /// aplicado al resto, que se quedaron fuera cuando aquello se hizo.
    static const std::string *key_of(const ir::IrFunction &fn,
                                     const char *stage);
    /// @brief La clave del MoDULO en @p stage, para lo que no es por funcion.
    static const std::string *module_key(const char *stage);
    /// @brief El momento efectivo: el que se pide, o el de la base.
    const char *stage_or_default(const char *stage) const noexcept {
        return (stage != nullptr && stage[0] != '\0') ? stage : default_stage_;
    }


    /// Anota el sello de un hecho recien producido.
    void mark(const char *producer, const std::string &key, Certainty c,
              const char *support = nullptr);

    /// Sellos por (productor, unidad).  Se guardan aparte del resultado porque
    /// el gestor cachea el DATO del dominio; la procedencia es del hecho, y la
    /// llevan todos por igual.
    std::unordered_map<const char *, std::unordered_map<std::string, Seal>>
        seals_;

    AnalysisManager manager_;
    /// El momento que se usa cuando la consulta no trae el suyo.  Por defecto
    /// @c kStagePreOpt: es lo que el compilador tiene delante mientras no haya
    /// pasado el optimizador, asi que una base sin declarar habla de eso.
    const char *default_stage_ = kStagePreOpt;
    size_t queries_ = 0;
    size_t computations_ = 0;
    /// El almacen ENTRE compilaciones, o nulo.  @see set_analysis_store
    AnalysisStore *analysis_store_ = nullptr;

    /// Los hechos estructurales de @p fn: del almacen si estan, computados y
    /// depositados si no.  Aparte de @ref structure para que la puerta siga
    /// siendo una sola linea y el trato con el disco no se mezcle con el de la
    /// cache en memoria -- son dos niveles distintos.
    IrFacts structure_from_store_(const ir::IrFunction &fn, const char *stage);

    /// Idem para los rangos.  Devuelve el puntero que el gestor guarda: este
    /// analisis lleva dentro el estado de cada bloque, asi que copiarlo seria
    /// duplicar el analisis entero.
    std::shared_ptr<const RangeFacts>
    ranges_from_store_(const ir::IrFunction &fn, const char *stage);

    /// Idem para el points-to.
    PointsTo memory_from_store_(const ir::IrFunction &fn, const char *stage);
};

/**
 * @brief Vuelca @p entries por @p out en una linea por hecho.
 *
 * Formato de DEPURACION, no de usuario: los mensajes de usuario salen del
 * catalogo multi-idioma.
 *
 * @param entries Lo devuelto por @c FactBase::dump.
 * @param out     Fichero abierto donde escribir.
 */
void dump_facts(const std::vector<RecordedFact> &entries, FILE *out);

} // namespace asa
} // namespace analysis

#endif // ANALYSIS_ASA_FACT_BASE_H
