/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/manager/analysis_store.h
 * @brief Guardar y recuperar el RAZONAMIENTO, no solo las conclusiones.
 *
 * @par Que problema resuelve
 * A disco iba solo lo PUBLICADO -- los hechos del ASA --, asi que una
 * recompilacion rehacia TODO el razonamiento (def-use, points-to, rangos, el
 * cierre de efectos) y lo unico que se ahorraba era el publicar.  Se cacheaban
 * las CONCLUSIONES y no el CoMPUTO que las produce.
 *
 * Y eso pone un techo a todo lo demas: el lenguaje, los diagnosticos, el
 * optimizador, la generacion de codigo y las herramientas beben del ASA, asi
 * que si su conocimiento se rehace entero en cada compilacion, ese es el suelo
 * de lo que puede costar cualquier cosa.
 *
 * @par Por que se guarda AUNQUE hoy salga barato
 * Un analisis puede costar poco hoy y mucho manana -- se afina, se le pide mas
 * precision, o crece el programa --.  Guardarlo es la DECISIoN ARQUITECToNICA:
 * el trabajo hecho no se tira.  Medir sirve para elegir por cual empezar, no
 * para decidir si se hace.
 *
 * ===========================================================================
 * DoNDE ENCAJA: el nivel [1] del diagrama de caches (ver `fact_base.h`)
 * ===========================================================================
 *
 *   [3] CAS / cache de proyecto ......... el IR y los artefactos
 *        |
 *   [1] FactBase / AnalysisManager ...... los ANALISIS  <-- ESTO, a disco
 *        |    en memoria: dentro de UNA compilacion
 *        |    en disco:   ENTRE compilaciones            <-- lo que faltaba
 *        v
 *   [2] fichero .vxfacts ................ los HECHOS publicados
 *
 * Un fichero por MoDULO, con las entradas dentro y cada una keyada por el
 * CONTENIDO de su funcion.  Es la forma que el fichero de hechos ya tenia
 * probada al lado, y la eligio el banco: con una entrada por analisis en un
 * store direccionado por contenido, ABRIR costaba 30 us y COMPUTAR el analisis
 * 8 -- o sea una cache que ralentiza --.
 *
 * ===========================================================================
 * LA CLAVE, Y POR QUE CADA PIEZA
 * ===========================================================================
 *
 *   clave = H( nombre del analisis
 *            + version del formato de ESE analisis
 *            + clave de contenido de la funcion
 *            + momento
 *            + capa de configuracion que le corresponda al momento
 *            + identidad del compilador )
 *
 * - **El nombre y su version** separan analisis y evitan lo peor que puede
 *   pasar aqui: leer los bytes de otro analisis, o de una version anterior del
 *   mismo, e interpretarlos como propios.  Eso no da error, da un resultado
 *   inventado.  Cada analisis sube SU version cuando cambia lo que serializa,
 *   sin tocar a los demas.
 * - **La clave de contenido de la funcion** es lo que hace esto util: dos
 *   compilaciones de una funcion que no cambio dan la misma clave, aunque el
 *   resto del modulo si haya cambiado.
 * - **El momento** porque el mismo analisis sobre la misma funcion dice cosas
 *   distintas antes y despues de optimizar.
 * - **La capa de configuracion** porque lo de despues de optimizar depende del
 *   optimizador, y lo de antes no (@c BuildConfig es por capas a proposito).
 * - **La identidad del compilador** porque un compilador nuevo puede concluir
 *   otra cosa del mismo programa: leer las conclusiones del viejo como propias
 *   es creerse un analisis que nadie ha hecho.
 *
 * ===========================================================================
 * COMO SE ANADE UN ANALISIS
 * ===========================================================================
 *
 *   1. Que no guarde punteros.  Un puntero no viaja: hay que guardar indices y
 *      rehidratar lo que haga falta al volver (@c IrFacts::owner es el unico
 *      caso hoy).  Y de paso quita la clase de bug del puntero colgante.
 *   2. Dos funciones libres: una que escribe a bytes y otra que lee.  Se
 *      declaran junto al analisis, no aqui: este fichero es el ALMACEN y no
 *      conoce a ninguno.
 *   3. Una version propia del formato, que sube cuando cambie lo escrito.
 *   4. Pedirlo por @ref AnalysisStore::load antes de computar, y depositarlo
 *      con @ref AnalysisStore::store despues.
 *
 * @par Y se puede MIRAR
 * Un cache que no se puede observar no se distingue de uno roto: los dos
 * compilan igual.  @ref AnalysisStore::Stats cuenta aciertos, fallos y bytes,
 * y el volcado sale con la misma variable que el resto del ASA.  Este
 * subsistema ya estuvo mal mucho tiempo sin que nada lo dijera.
 */
#ifndef VESTA_ANALYSIS_ANALYSIS_STORE_H
#define VESTA_ANALYSIS_ANALYSIS_STORE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace analysis {

/**
 * @brief El almacen de analisis entre compilaciones.
 *
 * @par UN fichero por modulo, no uno por analisis
 * La primera version guardaba cada analisis en su propia entrada del CAS, y el
 * banco la tumbo: **abrir el fichero costaba 30 us y computar el analisis 8**.
 * Con cientos de funciones por modulo y varios analisis cada una, eso es una
 * cache que RALENTIZA -- la unica forma en que esto puede hacer dano --.
 *
 * La forma correcta ya estaba probada al lado: el fichero de hechos guarda un
 * fichero por MoDULO con los registros dentro.  Aqui igual -- se lee entero de
 * una y se sirve de memoria --, y la granularidad no se pierde porque cada
 * entrada sigue estando keyada por el CONTENIDO de su funcion.
 *
 * @par Que se conserva al escribir, y por que NO solo lo usado
 * La primera version volcaba unicamente lo que esta compilacion habia usado o
 * producido.  Parecia una recoleccion elegante y era un fallo: confundia *"no
 * se pidio esta vez"* con *"esta muerto"*.  Medido -- la corrida en frio guarda
 * estructura Y rangos; la siguiente sirve los hechos desde el fichero de
 * hechos, con lo que los productores que consultan rangos ni llegan a correr; y
 * al volcar se perdian los rangos PARA SIEMPRE.
 *
 * Ahora cada entrada lleva cuantas corridas SEGUIDAS lleva sin que se la pida.
 * Al usarla vuelve a cero; al no usarla sube una; pasada
 * @ref kDefaultUnusedRuns se cae.  Asi una entrada sobrevive a que su consumidor no
 * corra -- que es lo normal -- y lo que de verdad murio desaparece igual, solo
 * que un poco mas tarde.  Sin esto el almacen o bien se vacia solo, o bien
 * crece sin limite; con esto, ni una cosa ni la otra.
 *
 * Sin ruta -- @c open no llamado -- todo falla en frio y se computa, que es
 * exactamente el comportamiento de siempre: no tener cache nunca es un error.
 */
class AnalysisStore {
  public:
    /**
     * @brief Lo que ha pasado con el almacen, para poder MIRARLO.
     *
     * Sin esto, "no reutiliza nada" y "reutiliza todo" se leen igual -- que es
     * como el nivel [2] estuvo roto sin que nadie lo notara.
     */
    struct Stats {
        uint64_t hits = 0;    ///< se pidio y estaba.
        uint64_t misses = 0;  ///< se pidio y no estaba: hubo que computar.
        uint64_t stored = 0;  ///< se deposito tras computar.
        uint64_t rejected = 0; ///< estaba pero no se pudo leer (formato roto).
        uint64_t bytes_read = 0;
        uint64_t bytes_written = 0;
    };

    /**
     * @param compiler Identidad de esta version del compilador.
     * @param config   Huella de la capa de configuracion que corresponda.
     */
    AnalysisStore(uint64_t compiler, uint64_t config)
        : compiler_(compiler), config_(config) {}

    /**
     * @brief Abre el paquete de un modulo: UNA lectura, y ya todo de memoria.
     *
     * Que no exista NO es un error -- es la primera compilacion, o alguien
     * limpio la cache --: se empieza vacio y se llena.
     *
     * @param path Fichero del paquete.  Vacio = no usar cache.
     */
    void open(const std::string &path);

    /**
     * @brief Escribe el paquete: UNA escritura.
     *
     * Sale lo que esta compilacion uso o produjo, y ademas lo que lleva menos
     * de @ref kDefaultUnusedRuns corridas sin pedirse.  Ver la nota de la clase: no
     * usarse en una corrida NO es estar muerto, y confundirlo vaciaba el
     * almacen solo.
     */
    void flush();

    /**
     * @brief El defecto de cuantas corridas seguidas aguanta una entrada sin
     *        que se la pida.
     *
     * El numero sale de un compromiso, no de una intuicion: cada corrida de mas
     * es una entrada muerta ocupando sitio y bytes que leer; cada corrida de
     * menos es un analisis tirado que habra que recomputar.  Y los dos lados NO
     * cuestan igual -- perder trabajo hecho es justo lo que este subsistema
     * viene a evitar --, asi que se es generoso.
     *
     * Doce: aguanta de sobra que un consumidor no corra en varias
     * compilaciones seguidas -- lo normal cuando los hechos vienen del fichero
     * de hechos -- y aun asi lo que de verdad murio desaparece el mismo dia.
     */
    static constexpr uint32_t kDefaultUnusedRuns = 12;

    /**
     * @brief Cambia ese limite para ESTE almacen.
     *
     * Lo pone quien compila a partir de `[cache] analysis_unused_runs` del
     * manifiesto del paquete.  Es una propiedad del PROYECTO y no de quien
     * compila: una libreria que se recompila cada minuto y un binario que se
     * toca una vez al mes no quieren lo mismo, y quien lo sabe es el paquete.
     *
     * @param runs Corridas de gracia.  Cero deja el defecto -- asi un
     *             manifiesto que no lo dice no tiene que repetir el numero.
     */
    void set_unused_runs(uint32_t runs) noexcept {
        if (runs != 0) max_unused_runs_ = runs;
    }

    /**
     * @brief La clave de @p analysis sobre una funcion.
     *
     * Publica y pura para poder comprobarla en un test sin montar un almacen:
     * lo que decide si esto sirve o miente es exactamente que entre en la clave
     * todo lo que cambia el resultado.
     *
     * @param analysis Nombre estable del analisis (literal, no construido).
     * @param version  Version del formato de ESE analisis.
     * @param fn_key   Clave de contenido de la funcion.
     * @param stage    En que momento.  @see analysis::asa::kStage*.
     * @return La clave.
     */
    uint64_t key_of(const char *analysis, uint32_t version, uint64_t fn_key,
                    const char *stage) const;

    /**
     * @brief Lo guardado para @p key, si esta.
     * @return @c true si se leyo algo; @c false si no estaba (que NO es error).
     */
    bool load(uint64_t key, std::vector<uint8_t> &out);

    /**
     * @brief Deposita @p bytes para @p key.  Idempotente.
     * @return @c true si quedo escrito.
     */
    bool store(uint64_t key, const std::vector<uint8_t> &bytes);

    /*
     * NO hay un "guardar solo si compensa".  Se penso y se descarto: un umbral
     * ahi seria tapar con una heuristica la unica forma en que este mecanismo
     * puede hacer dano -- que leer salga mas caro que rehacer --, en vez de
     * arreglarla.  RECUPERAR TIENE QUE SALIR SIEMPRE MAS BARATO QUE COMPUTAR,
     * y si algun dia no lo es, es un fallo del almacen o del formato de ese
     * analisis.
     *
     * Y no se deja a la buena fe: lo mide `tests/analysis/test_analysis_store.cpp`,
     * que compara las dos vias intercaladas y falla si la de disco no gana.
     */

    /// Que ha pasado.  @see Stats
    const Stats &stats() const noexcept { return stats_; }

    /// Deja constancia de que lo guardado no se pudo interpretar.  Lo llama
    /// quien deserializa, que es el unico que lo sabe: para el almacen los
    /// bytes salieron bien.
    void note_rejected() noexcept { ++stats_.rejected; }

    /// Vuelca el resumen si esta pedido.  Se llama al terminar de compilar.
    void dump_if_asked() const;

  private:
    uint64_t compiler_ = 0;
    uint64_t config_ = 0;
    std::string path_;
    /// Una entrada del paquete: los bytes y cuanto lleva sin pedirse.
    struct Entry {
        std::vector<uint8_t> bytes;
        /// Corridas SEGUIDAS sin que nadie la pidiera.  Cero al usarla.
        uint32_t unused_runs = 0;
    };
    /// Lo que hay, por clave.  Tabla asociativa y no vector plano: se consulta
    /// una vez por (analisis x funcion), que en un modulo grande son miles.
    std::unordered_map<uint64_t, Entry> entries_;
    /// De esas, las que esta compilacion ha usado o producido.  No decide QUE se
    /// escribe -- eso lo decide @ref kDefaultUnusedRuns --, decide a cuales se les
    /// pone el contador a cero.
    std::unordered_set<uint64_t> live_;
    /// El limite en vigor.  @see kDefaultUnusedRuns, set_unused_runs
    uint32_t max_unused_runs_ = kDefaultUnusedRuns;
    Stats stats_;
};

} // namespace analysis

#endif // VESTA_ANALYSIS_ANALYSIS_STORE_H
