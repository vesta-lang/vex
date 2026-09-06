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
 * MUTAR EL IR CADUCA LOS HECHOS: quien lo toque avisa con @c invalidate.
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
#include "analysis/effects/effect_analysis.h" // el motor de efectos, compartido
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
    ~FactBase();
    FactBase(const FactBase &) = delete;
    FactBase &operator=(const FactBase &) = delete;

    /**
     * @brief Hechos estructurales de @p fn: def-use, sitios de llamada, bucles.
     * @param fn Funcion IR a consultar.
     * @return Los hechos, cacheados mientras viva la base.
     */
    const IrFacts &structure(const ir::IrFunction &fn);

    /**
     * @brief Entre que dos numeros esta cada valor de @p fn.
     * @param fn Funcion IR a consultar.
     * @return Los rangos por valor SSA, cacheados mientras viva la base.
     */
    const RangeFacts &ranges(const ir::IrFunction &fn);

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
    const DemandedBits &demanded(const ir::IrFunction &fn);

    /**
     * @brief A que memoria puede referirse cada puntero de @p fn.
     * @param fn Funcion IR a consultar.
     * @return La tabla points-to, cacheada mientras viva la base.
     */
    const PointsTo &memory(const ir::IrFunction &fn);

    /**
     * @brief Forma del CFG de @p fn: bucles, cabeceras y profundidad.
     * @param fn Funcion IR a consultar.
     * @return Los hechos de bucle, cacheados mientras viva la base.
     */
    const LoopFacts &loops(const ir::IrFunction &fn);

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
    const LoopIvBounds &iv_bounds(const ir::IrFunction &fn);

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
    const RangeSummaries &boundary(const ir::IrModule &mod);

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
    static const std::string *key_of(const ir::IrFunction &fn);

    /// Anota el sello de un hecho recien producido.
    void mark(const char *producer, const std::string &key, Certainty c,
              const char *support = nullptr);

    /// Sellos por (productor, unidad).  Se guardan aparte del resultado porque
    /// el gestor cachea el DATO del dominio; la procedencia es del hecho, y la
    /// llevan todos por igual.
    std::unordered_map<const char *, std::unordered_map<std::string, Seal>>
        seals_;

    AnalysisManager manager_;
    size_t queries_ = 0;
    size_t computations_ = 0;
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
