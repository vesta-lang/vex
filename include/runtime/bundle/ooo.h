/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/ooo.h
 * @brief Repartir paquetes ENTEROS a un hilo ayudante, en tuberia.
 *
 * QUE SE ESTA PROBANDO
 * --------------------
 * Si entregarle trabajo a otro nucleo compensa.  No se da por sabido: se
 * construye y se mide.
 *
 * LA PRIMERA VERSION PERDIA, Y SE SABE POR QUE
 * --------------------------------------------
 * Repartia MEDIO paquete y esperaba en el sitio.  Perfilado con contadores de
 * hardware sobre `float:1024`:
 *
 *     CPI                    0,237  ->  1,961      (8,3x peor)
 *     Retiring               44,5%  ->   6,9%      de las ranuras del pipeline
 *     Serializing Operations  3,9%  ->    100%     de los ciclos
 *     esperando / trabajando          0,755 s / 0,411 s
 *     racion por entrega              15,9 instrucciones  (~47 ns)
 *
 * La ultima linea es la que manda: un traspaso entre nucleos cuesta cientos de
 * nanosegundos y se le estaban dando cuarenta y siete.  El `Serializing
 * Operations` al 100% no dice "coordinar es caro", dice "aqui no se hace otra
 * cosa que coordinar".  O sea que lo medido NO fue si el reparto sirve: fue que
 * con esa racion no puede servir.
 *
 * COMO ERA -- fork-join por paquete
 * ---------------------------------
 * La barrera SIEMPRE en el camino critico.  El tiempo baja:
 *
 *       PRINCIPAL                              AYUDANTE
 *      +-----------+                          +-----------+
 *      | 16 instr  |==== entrega media ======>| 16 instr  |
 *      |           |                          |           |
 *      +-----+-----+                          +-----+-----+
 *            |                                      |
 *            v                                      |
 *      +===========+                                |
 *      |  E S P E  |<--------- termina -------------+
 *      |  R A      |    (65% del tiempo aqui)
 *      +-----+-----+
 *            |
 *            v          y vuelta a empezar, 46.000 veces
 *
 *      racion: 15,9 instr (~47 ns)   traspaso: cientos de ns
 *      => no puede ganar, y no es culpa del traspaso
 *
 *
 * COMO ES -- dos clases de encargo, y ninguna espera en el sitio
 * -------------------------------------------------------------
 *
 *       PRINCIPAL                  COLA                  AYUDANTE
 *      +-----------------+     +-----------+        +-----------------+
 *      | forma el paquete|     | [P][E][ ] |        |                 |
 *      | lo publica CRUDO|     | [ ][ ][ ] |        |                 |
 *      | y lo EJECUTA ya |     +-----------+        |                 |
 *      +--------+--------+        ^     |           |                 |
 *               |                 |     |           |                 |
 *               +---- [P] --------+     +--- [P] -->| reordena+fusiona|
 *               | preparar                          | una COPIA       |
 *               |                                   +--------+--------+
 *               | (sigue ejecutando, no espera)              |
 *               v                                            v
 *      +-----------------+                          +-----------------+
 *      | recoge la buena |<....... improved ........| publica puntero |
 *      | cambia la icache|      (release/acquire)   +-----------------+
 *      +--------+--------+
 *               |
 *               |  el paquete siguiente...
 *               |
 *        +------+------+
 *        |             |
 *   independiente   DEPENDE de lo que vuela
 *        |             |
 *        v             v
 *   +---------+   +---------+
 *   |  [E] -->|   |  vacia  |   <- la unica parada que queda
 *   | delega  |   | la cola |
 *   | y sigue |   +---------+
 *   +---------+
 *
 * Los DOS encargos existen por razones distintas:
 *
 *   [E] EJECUTAR  solo se puede delegar si hay dos paquetes seguidos
 *                 independientes, y en un bucle no los hay: el cuerpo
 *                 siguiente comparte el acumulador consigo mismo.  Medido:
 *                 1,00 paradas por entrega, o sea que la cola nunca tuvo dos.
 *
 *   [P] PREPARAR  no tiene ese problema.  Reordenar y fusionar no depende de
 *                 ningun registro ni de ninguna memoria del programa: es una
 *                 funcion de las instrucciones, y esas ya estan.  Siempre hay
 *                 que dar, y ademas es trabajo que hoy se paga en el camino
 *                 critico -- en cada fallo de icache, y en los bloques cortos
 *                 eso llego a medirse en un 8%.
 *
 * QUE CAMBIA
 * ----------
 * Tres cosas, y la tercera es la que importa:
 *
 *   1. La unidad es el paquete ENTERO, no media.  De ~16 instrucciones por
 *      entrega a ~450 (`instr_dentro/despacho` da 442,9 en el banco).
 *   2. Hay COLA, no una ranura.  Antes, en cuanto el ayudante estaba ocupado se
 *      dejaba de repartir; ahora caben ocho paquetes en vuelo.
 *   3. NO se espera por paquete.  Solo cuando lo que viene depende de lo que
 *      hay en vuelo.  Eso saca la barrera del camino critico, que es lo que
 *      convierte esto en una tuberia en vez de un fork-join.
 *
 * El hilo se arranca UNA vez y se queda girando: crearlo cuesta microsegundos y
 * un paquete son decenas de nanosegundos.
 *
 * POR QUE EL TRASPASO ESTA EN LA CABECERA
 * ---------------------------------------
 * `ooo_push` se llama por paquete ejecutado, o sea en el camino caliente.  Una
 * llamada entre unidades de traduccion ahi se comeria justo lo que se intenta
 * medir.  Y `ooo_drain` es un bucle de espera sobre una atomica: en cabecera el
 * compilador lo deja en un registro en vez de rehacer la carga cada vuelta.
 *
 * En el `.cpp` se queda solo lo que corre UNA vez: arrancar el hilo, su bucle y
 * pararlo.
 *
 * QUE HACE FALTA PARA QUE SEA CORRECTO
 * ------------------------------------
 * Un paquete solo se delega si es INDEPENDIENTE de todo lo que hay en vuelo, y
 * eso es mas que no compartir registros:
 *
 *   - registros disjuntos -- son ranuras distintas de un array, asi que sin
 *     solape no hay carrera;
 *   - no coinciden en memoria de la VM.  Sin desambiguar direcciones, dos
 *     accesos cualesquiera pueden ser al mismo sitio;
 *   - no coinciden en los campos implicitos: las banderas son un byte
 *     compartido;
 *   - el delegado no transfiere control, no se bloquea y no puede abortar.  Si
 *     abortara, lo que corriera en paralelo no debia haber corrido;
 *   - el delegado no lee `rip`: su valor depende de cuantas se hayan ejecutado
 *     ya, y eso lo sabe quien las lleva en orden.
 *
 * Con eso los dos hilos no comparten ni un byte y no hace falta sincronizacion
 * entre ellos.  Las unicas atomicas son las dos de la cola.
 *
 * LO QUE NO ES
 * ------------
 * No es un motor fuera de orden con marcador ni renombrado, y el nombre `ooo`
 * se le queda grande: nada se ejecuta fuera de orden.  Lo que hay es REPARTO --
 * trozos independientes a la vez en dos nucleos --, y el orden se respeta
 * escrupulosamente.  El fuera de orden DENTRO de un manejador ya lo hace el
 * anfitrion.
 */

#ifndef VESTA_RUNTIME_BUNDLE_OOO_H
#define VESTA_RUNTIME_BUNDLE_OOO_H

#include <atomic>
#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
#include <immintrin.h> // _mm_pause: ceder el hilo hermano mientras se espera
#endif

#include "runtime/bundle.h"

#if VM_BUNDLES

namespace runtime {

/// Cuantos paquetes caben en vuelo.  Potencia de dos para que el indice sea un
/// AND.  Ocho: bastantes para que el ayudante no se quede seco mientras el
/// principal busca el siguiente, y pocos para que la cola quepa holgada en L1.
constexpr uint32_t kOooSlots = 8;

/// Que clase de encargo es.
enum class OooKind : uint8_t {
    Execute, ///< ejecutar un paquete entero
    Prepare, ///< reordenar y fusionar una COPIA, y publicarla cuando este
    Decode,  ///< descodificar POR ADELANTADO el tramo que viene
};

/**
 * @brief Un encargo para el ayudante.
 *
 * Dos clases, y la segunda es la que hace que el ayudante no se quede parado.
 *
 * Delegar EJECUCION solo sirve cuando hay dos paquetes seguidos independientes,
 * y en un bucle no los hay: el cuerpo siguiente comparte el acumulador consigo
 * mismo.  Medido: 1,00 paradas por entrega, o sea que la cola nunca llegaba a
 * tener dos cosas dentro.
 *
 * Delegar ANaLISIS no tiene ese problema.  Reordenar y fusionar un paquete no
 * depende de ningun registro ni de ninguna memoria del programa: es una funcion
 * de las instrucciones, y esas ya estan.  Asi que siempre hay trabajo que dar,
 * y ademas es trabajo que hoy esta en el camino critico -- se paga en cada
 * fallo de icache, y en los bloques cortos eso llego a medirse en un 8%.
 */
struct alignas(64) OooJob {
    ProcessVM *proc = nullptr;
    OooKind kind = OooKind::Execute;
    /// `Execute`: las instrucciones.  `Prepare`: sin usar.
    const DecodedInstr *instr = nullptr;
    uint32_t n = 0;
    /// `Prepare`: el paquete YA publicado, donde se deja el resultado.
    Bundle *target = nullptr;
    /// `Prepare`: la copia sobre la que trabajar.  La reserva el principal
    /// porque la arena no es de varios hilos.
    Bundle *scratch = nullptr;
    /// `Prepare`: direccion siguiente al paquete.  La vivacidad NO viaja: el
    /// ayudante la mira el mismo, con su propia cache de pagina, y solo si un
    /// patron de fusion llega a pedirla.
    /// `Decode`: por donde empezar a descodificar por adelantado.
    uint64_t next_pc = 0;
};

/* UNA RANURA POR LINEA DE CACHE.
 *
 * Sin esto la estructura mide 56 bytes, y con el array alineado a 64 cada dos
 * ranuras seguidas caen en la misma linea:
 *
 *     linea 0 |<-- job[0] 0..55 -->|<- job[1] 56..63
 *     linea 1  job[1] 64..111 -->|<- job[2] 112..127
 *
 * Y la cola va casi VACIA por construccion -- se entrega una y el ayudante la
 * coge --, asi que el productor escribe la ranura `h` justo mientras el
 * ayudante lee la `h-1`.  Misma linea: cada entrega se la quitaban el uno al
 * otro sin compartir ni un dato.  Eso es false sharing, y del que no se ve: no
 * falla nada, solo va lento.
 *
 * Cuesta 64 bytes por ranura en vez de 56; con ocho ranuras, 512 bytes en
 * total. */
static_assert(sizeof(OooJob) <= 64,
              "una ranura tiene que caber en una linea de cache");

/**
 * @brief La cola: un anillo de un productor y un consumidor.
 *
 * POR QUE UNA COLA Y NO UNA RANURA
 * --------------------------------
 * Con una sola ranura, entregar y esperar caian en la misma vuelta: se le daba
 * media docena de instrucciones al ayudante y se le esperaba acto seguido.  Eso
 * es un fork-join por paquete, con la barrera SIEMPRE en el camino critico, y
 * no puede ganar por construccion -- medido: 0,755 s esperando contra 0,411 s
 * trabajando, `Serializing Operations` al 100% de los ciclos --.
 *
 * Con la cola, el principal deja el encargo y SIGUE.  La espera solo llega
 * cuando algo depende de lo que hay en vuelo, que es lo que convierte esto en
 * una tuberia en vez de una barrera.
 *
 * SIN CERROJO Y SIN CAS
 * ---------------------
 * Un productor y un consumidor, asi que los dos indices bastan: el productor
 * solo escribe `head` y el consumidor solo `tail`.  El productor rellena la
 * ranura y DESPUES publica `head` con `release`; el consumidor lo ve con
 * `acquire` y para entonces la ranura ya esta escrita.  Ni una operacion
 * atomica de lectura-modificacion-escritura en todo el camino.
 *
 * Los dos indices van en LINEAS DE CACHE DISTINTAS.  Compartiendola, cada
 * avance del consumidor invalidaria la linea del productor y el traspaso
 * costaria mas que el trabajo -- que es justo lo que se mide, asi que falsearlo
 * aqui invalidaria la prueba --.
 *
 * Los indices no se envuelven: crecen y se enmascaran al indexar.  Asi
 * `head - tail` es cuantos hay pendientes sin ningun caso especial, y con 32
 * bits no se agota en la vida del proceso.
 */
struct OooQueue {
    alignas(64) std::atomic<uint32_t> head{0}; ///< solo lo escribe el productor
    alignas(64) std::atomic<uint32_t> tail{0}; ///< solo lo escribe el consumidor
    alignas(64) std::atomic<uint32_t> stop{0}; ///< que se pare el ayudante
    /**
     * @brief El ayudante esta DORMIDO y hay que avisarle.
     *
     * Girar sin fin no es gratis aunque no se le de un solo encargo: medido en
     * la mezcla `independiente` con el motor escalar -- que ni forma paquetes,
     * o sea que no hay nada que delegar --, 291 MIPS sin ayudante contra 252
     * con el.  Entre un 6% y un 10% por un hilo que no hace nada.  El `pause`
     * cede el hermano SMT dentro del nucleo, pero no cede el NUCLEO: el sistema
     * sigue viendo un hilo listo y le da turno donde caiga.
     *
     * Asi que gira en caliente lo justo para no perder la tuberia y luego se
     * duerme, y esta bandera es lo que dice si hay que despertarlo.  La lee el
     * productor con `relaxed` DESPUES de publicar: en el caso normal -- el
     * ayudante despierto -- es una carga de una linea que nadie escribe.
     */
    alignas(64) std::atomic<uint32_t> parked{0};
    /* `alignas` en el ARRAY solo alinea el principio; lo que hace falta es que
     * cada ELEMENTO empiece en su linea, y eso lo da el `alignas` del tipo. */
    alignas(64) OooJob job[kOooSlots];
};

/// Una sola: se esta probando si UN ayudante compensa.  Si no compensa con uno,
/// con mas tampoco -- y con mas haria falta una cola por planificador.
inline OooQueue g_ooo;
inline std::atomic<bool> g_ooo_started{false};

/**
 * @brief Quien tiene cogido al ayudante.
 *
 * La cola es de UN productor, asi que solo un proceso puede estar entregando.
 * El primero que entrega se la queda; los demas ejecutan en serie, que es
 * correcto y ademas es lo que se quiere para la prueba -- se mide si el reparto
 * compensa, no si escala a varios procesos --.
 */
inline std::atomic<ProcessVM *> g_ooo_owner{nullptr};

/**
 * @brief Suelta el ayudante al morir el proceso que lo tenia.
 *
 * HAY QUE LLAMARLA.  Sin esto el primer proceso se lo queda para siempre y
 * todos los demas se quedan sin reparto Y SIN ANALISIS -- sus paquetes salen
 * crudos, o sea sin reordenar ni fusionar --, que es peor que no tener reparto.
 * Y no se nota: no falla nada, solo rinde menos.  Se vio porque los cuatro
 * motores con reparto daban MIPS identicos hasta el decimal, que es imposible
 * si de verdad estuvieran haciendo cosas distintas.
 */
/**
 * @brief Cambia de programa: lo que el ayudante tuviera cacheado ya no vale.
 *
 * El ayudante lee la memoria de la VM con una cache de pagina SUYA, que vive
 * fuera de su bucle para que dos encargos seguidos aprovechen la misma pagina.
 * Esa cache guarda un puntero del ANFITRION, y cuando el proceso muere sus
 * paginas se liberan: la entrada sigue ahi, apuntando a memoria que ya es de
 * otro.
 *
 * Y no falla, que es lo peor.  El proceso siguiente pide la misma direccion
 * virtual, la cache ACIERTA, y el ayudante descodifica lo que haya quedado en
 * esa memoria reciclada.  Lo publica bajo un `pc` legitimo y el principal lo
 * ejecuta como si fuera suyo.  Medido en la mezcla `memoria`: el adelanto de
 * `0x157` -- que es un `hlt` de 2 bytes -- salia como `mkclosure` de 4, que
 * escribe R0; el programa terminaba con R0=1 en vez de 25000 y sin pasar por
 * el `hlt`.  Una de cada cinco ejecuciones.
 *
 * Comparar el proceso por PUNTERO no sirve: los punteros se reciclan, y un
 * proceso nuevo en la direccion del anterior pasaria la comprobacion.  Por eso
 * es un contador que solo sube.
 *
 * Se sube con la cola VACIA -- el desmontaje espera a que lo este antes --, asi
 * que ningun encargo esta a medias de mirar la cache mientras cambia.
 */
inline std::atomic<uint32_t> g_ooo_epoch{0};

/// Anuncia que las paginas cacheadas por el ayudante ya no valen.
inline void ooo_new_epoch() {
    g_ooo_epoch.fetch_add(1, std::memory_order_release);
}

inline void ooo_release_owner(ProcessVM *process) {
    ProcessVM *mine = process;
    g_ooo_owner.compare_exchange_strong(mine, nullptr,
                                        std::memory_order_acq_rel);
}

/**
 * @brief Hasta donde hay que ver avanzada la cola para que no quede EJECUCION.
 *
 * Es el indice siguiente al ultimo encargo de ejecutar que se entrego.  Hay que
 * distinguirlo del resto porque las dos clases de encargo obligan a cosas muy
 * distintas: lo que se EJECUTA escribe registros del proceso, asi que no puede
 * quedar a medias cuando el planificador le da el turno a otro; lo que se
 * ANALIZA trabaja sobre una copia que nadie mas mira y puede seguir tranquilo.
 *
 * ANTES ERA UN CONTADOR ATOMICO, Y ESO COSTABA
 * --------------------------------------------
 * Un `std::atomic<uint32_t>` que el productor incrementaba al entregar y el
 * ayudante decrementaba al terminar.  O sea una SEGUNDA linea de cache
 * disputada entre los dos nucleos -- ademas de `head` y `tail` --, y dos
 * lectura-modificacion-escritura por entrega, que son mucho mas caras que una
 * lectura.  En el perfil de hardware, `fetch_add`/`fetch_sub` salian con 0,216 s
 * de los 2,30 s que costaba coordinar.
 *
 * Y era redundante: `tail` ya dice lo mismo.  El ayudante lo publica DESPUES de
 * terminar cada encargo y con `release`, asi que ver `tail` pasado de esta
 * marca es exactamente "el encargo de ejecutar ya acabo, y sus escrituras se
 * ven".  Se cambia una linea disputada y dos RMW por una comparacion sobre una
 * linea que los dos lados ya tocaban.
 *
 * Vive sin atomica porque SOLO la escribe el productor, que es el unico hilo
 * que entrega.
 */
inline uint32_t g_ooo_exec_mark = 0;

/**
 * @brief Hasta donde vio el productor la cola del consumidor, la ultima vez.
 *
 * `tail` la escribe el AYUDANTE, asi que leerla es traerse su linea de cache.
 * Y el productor solo la necesita para una cosa en el camino caliente: saber si
 * queda hueco.  Para eso basta un valor VIEJO -- `tail` solo crece, asi que si
 * con el valor viejo ya hay hueco, con el de verdad hay al menos tanto --, y
 * solo hay que mirar de verdad cuando el viejo dice que esta llena.
 *
 * Con una cola de ocho y entregas de una en una, eso quita la lectura
 * disputada de practicamente todas las entregas.
 *
 * Sin atomica porque SOLO la toca el productor.
 */
inline uint32_t g_ooo_tail_seen = 0;

/// Ceder el SMT mientras se espera.  Sin esto, dos hilos girando en el mismo
/// nucleo fisico se quitan el sitio y la espera sale mas cara que el trabajo.
[[gnu::always_inline]] inline void ooo_pause() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    _mm_pause();
#endif
}

/// Arranca el ayudante.  Fuera de linea a proposito: corre UNA vez.
void ooo_start();

/// Despierta al ayudante dormido.  Fuera de linea: es el camino raro, y llama
/// al sistema.
void ooo_wake();

/**
 * @brief Publica el encargo y despierta al ayudante SI dormia.
 *
 * DONDE ESTA LA CARRERA, Y POR QUE LA BARRERA VA SOLO AQUI
 * -------------------------------------------------------
 * Publicar y despues leer una marca que el otro hilo escribe es el patron
 * donde los DOS lados pueden quedarse con el valor viejo -- x86 deja adelantar
 * una lectura a una escritura anterior --, y eso es un aviso perdido: el
 * ayudante durmiendo con trabajo en la cola.  Cerrarlo pide una barrera
 * completa de un lado; ponerla en cada traspaso seria encarecer justo lo que
 * se esta intentando abaratar.
 *
 * Solo hace falta cuando la cola estaba VACIA, y con eso basta:
 *
 *   - el ayudante solo se duerme habiendo visto `head == tail`, o sea habiendo
 *     consumido todo lo que veia;
 *   - si la cola NO estaba vacia, el encargo que la lleno la encontro vacia, y
 *     ESE paso por aqui con barrera.  Por induccion, la transicion de vacia a
 *     con trabajo siempre avisa.
 *
 * Asi que el camino caliente -- entregar con la cola ya con cosas -- se queda
 * en una carga relajada de una linea que casi nunca cambia.
 *
 * Y el plazo de `ooo_idle_wait` sigue estando de red: si algun dia este
 * razonamiento se rompe, el sintoma es un retraso, no un bloqueo.
 *
 * @param next_head  El nuevo `head` a publicar.
 */
[[gnu::always_inline]] inline void ooo_publish(uint32_t next_head) {
    g_ooo.head.store(next_head, std::memory_order_release);
    /* La marca PRIMERO, y la barrera solo si dice que duerme.
     *
     * La barrera estaba antes de esta lectura, condicionada a que la cola
     * estuviera vacia.  El razonamiento era correcto y la condicion inutil: en
     * este reparto la cola SIEMPRE esta casi vacia -- se entrega uno y el
     * ayudante lo coge --, asi que la barrera saltaba en casi todas las
     * entregas.  Una barrera completa vacia el buffer de escrituras, y eso en
     * el camino que se esta intentando abaratar.
     *
     * Leer `parked` cuesta lo que una carga de una linea que nadie escribe
     * mientras el ayudante trabaja.  Solo cuando dice que duerme -- que es raro
     * por construccion: hay que llevar `kOooSpinIdle` vueltas sin encargos --
     * se paga la barrera, y ahi si hace falta: sin ella el productor podria ver
     * la marca vieja Y el ayudante ver `head` viejo, y el aviso se perderia.
     *
     * Que la lectura de fuera sea relajada deja abierta una ventana teorica --
     * verla a cero justo cuando se acaba de poner a uno --, y para eso esta el
     * plazo de `ooo_idle_wait`: el sintoma seria un retraso, no un bloqueo. */
    if (__builtin_expect(g_ooo.parked.load(std::memory_order_relaxed) != 0, 0)) {
        std::atomic_thread_fence(std::memory_order_seq_cst);
        if (g_ooo.parked.load(std::memory_order_relaxed) != 0) ooo_wake();
    }
}

/**
 * @brief Encola @p n instrucciones desde @p instr para el ayudante.
 *
 * NO espera.  El llamante deja el encargo y sigue con el paquete siguiente; la
 * espera solo llega cuando algo depende de lo que hay en vuelo, y para eso esta
 * @ref ooo_drain.
 *
 * @return true si entro en la cola; false si esta llena, si el ayudante todavia
 *         no existe o si lo tiene cogido otro proceso.  En los tres casos el
 *         llamante ejecuta el paquete el mismo, que siempre es correcto.
 */
[[gnu::always_inline]] inline bool ooo_push(ProcessVM *process,
                                            const DecodedInstr *instr,
                                            uint32_t n) {
    if (__builtin_expect(!g_ooo_started.load(std::memory_order_acquire), 0)) {
        /* Arrancarlo y SEGUIR.  No hace falta esperar a que el hilo este
         * girando: el encargo se queda en la cola y lo coge en cuanto arranque.
         *
         * Antes se devolvia `false` aqui, y eso dejaba el PRIMER paquete de
         * cada programa crudo para siempre -- nadie vuelve a preguntar por el
         * una vez formado --.  Si el hilo no se pudo crear, `g_ooo_started`
         * sigue en falso y entonces si hay que rendirse: encolar trabajo que
         * nadie va a consumir dejaria a `ooo_drain` girando sin fin. */
        ooo_start();
        if (!g_ooo_started.load(std::memory_order_acquire)) return false;
    }
    /* Un solo productor.  Se comprueba con `relaxed` porque el duenyo no cambia
     * en el camino caliente: lo pone el primero que entrega y ahi se queda. */
    ProcessVM *owner = g_ooo_owner.load(std::memory_order_relaxed);
    if (__builtin_expect(owner != process, 0)) {
        if (owner != nullptr) return false;
        ProcessVM *none = nullptr;
        if (!g_ooo_owner.compare_exchange_strong(none, process,
                                                 std::memory_order_acq_rel))
            return false;
    }

    const uint32_t h = g_ooo.head.load(std::memory_order_relaxed);
    /* Con el valor VIEJO de `tail` basta para ver que hay hueco: solo crece.
     * Solo si dice que esta llena hay que mirar de verdad, y entonces si con
     * `acquire` -- hay que ver hasta donde ha consumido antes de dar por libre
     * una ranura, o se pisaria un encargo vivo --.  Ver `g_ooo_tail_seen`. */
    if (h - g_ooo_tail_seen >= kOooSlots) {
        g_ooo_tail_seen = g_ooo.tail.load(std::memory_order_acquire);
        if (h - g_ooo_tail_seen >= kOooSlots)
            return false; // llena: lo hace el llamante y de paso deja respirar
    }

    OooJob &slot = g_ooo.job[h & (kOooSlots - 1)];
    slot.proc = process;
    slot.kind = OooKind::Execute;
    slot.instr = instr;
    slot.n = n;
    /* La marca, ANTES de publicar: si se pusiera despues, el ayudante podria
     * haber terminado y avanzado `tail` mientras la marca todavia apunta al
     * encargo anterior, y entonces se daria por terminado algo que acaba de
     * entregarse.  Es local al productor, asi que no cuesta nada. */
    g_ooo_exec_mark = h + 1;
    // `release`: la ranura tiene que verse ANTES que el indice que la publica.
    ooo_publish(h + 1);
    return true;
}

/**
 * @brief Encarga al ayudante que PREPARE @p scratch y lo publique en @p target.
 *
 * El principal ya ha publicado el paquete crudo y lo esta ejecutando; el
 * ayudante trabaja sobre una copia que nadie mas mira y, al terminar, deja el
 * puntero en `target->improved`.  Quien ejecuta lo recoge en su siguiente
 * pasada.  No hay carrera: el unico dato compartido es ese puntero, y va con
 * `release`/`acquire`.
 *
 * @return true si entro en la cola.  Si no, el paquete se queda crudo, que es
 *         correcto -- reordenar y fusionar son optimizaciones, no semantica --.
 */
[[gnu::always_inline]] inline bool
ooo_push_prepare(ProcessVM *process, Bundle *target, Bundle *scratch,
                 uint64_t next_pc) {
    if (__builtin_expect(!g_ooo_started.load(std::memory_order_acquire), 0)) {
        ooo_start();
        return false;
    }
    ProcessVM *owner = g_ooo_owner.load(std::memory_order_relaxed);
    if (__builtin_expect(owner != process, 0)) {
        if (owner != nullptr) return false;
        ProcessVM *none = nullptr;
        if (!g_ooo_owner.compare_exchange_strong(none, process,
                                                 std::memory_order_acq_rel))
            return false;
    }

    const uint32_t h = g_ooo.head.load(std::memory_order_relaxed);
    const uint32_t t = g_ooo.tail.load(std::memory_order_acquire);
    if (h - t >= kOooSlots)
        return false;

    OooJob &slot = g_ooo.job[h & (kOooSlots - 1)];
    slot.proc = process;
    slot.kind = OooKind::Prepare;
    slot.target = target;
    slot.scratch = scratch;
    slot.next_pc = next_pc;
    ooo_publish(h + 1);
    return true;
}

/**
 * @brief Encarga descodificar por adelantado @p n instrucciones desde @p pc.
 *
 * Es el encargo mas barato de justificar de los tres: descodificar cuesta el
 * 5,7% del banco -- cinco veces lo que cuesta formar paquetes -- y es
 * independiente por construccion, porque el bytecode ya esta.  Lo que el
 * ayudante deja en `g_predecode` el principal se lo lleva copiando, en vez de
 * descodificar.
 *
 * Si no cabe en la cola se pierde y no pasa nada: el principal descodifica como
 * siempre.  Por eso no se cuenta como fallo.
 */
[[gnu::always_inline]] inline bool ooo_push_decode(ProcessVM *process,
                                                   uint64_t pc, uint32_t n) {
    if (__builtin_expect(!g_ooo_started.load(std::memory_order_acquire), 0)) {
        ooo_start();
        if (!g_ooo_started.load(std::memory_order_acquire)) return false;
    }
    ProcessVM *owner = g_ooo_owner.load(std::memory_order_relaxed);
    if (__builtin_expect(owner != process, 0)) {
        if (owner != nullptr) return false;
        ProcessVM *none = nullptr;
        if (!g_ooo_owner.compare_exchange_strong(none, process,
                                                 std::memory_order_acq_rel))
            return false;
    }

    const uint32_t h = g_ooo.head.load(std::memory_order_relaxed);
    const uint32_t t = g_ooo.tail.load(std::memory_order_acquire);
    if (h - t >= kOooSlots)
        return false;

    OooJob &slot = g_ooo.job[h & (kOooSlots - 1)];
    slot.proc = process;
    slot.kind = OooKind::Decode;
    slot.next_pc = pc;
    slot.n = n;
    ooo_publish(h + 1);
    return true;
}

/**
 * @brief Queda algun encargo de EJECUTAR sin terminar?
 *
 * Una comparacion contra `tail`, que el ayudante publica con `release` al
 * acabar cada encargo.  Ver @ref g_ooo_exec_mark: esto sustituye a un contador
 * atomico aparte, o sea a una segunda linea de cache disputada.
 *
 * La resta va con signo para que el envolvimiento de los indices salga solo.
 */
[[gnu::always_inline]] inline bool ooo_exec_inflight() {
    return (int32_t)(g_ooo.tail.load(std::memory_order_acquire) -
                     g_ooo_exec_mark) < 0;
}

/// Cuantos encargos hay sin terminar.  Sirve para decidir sin esperar.
[[gnu::always_inline]] inline uint32_t ooo_pending() {
    return g_ooo.head.load(std::memory_order_relaxed) -
           g_ooo.tail.load(std::memory_order_acquire);
}

/**
 * @brief Espera a que termine todo lo que se puso a EJECUTAR.
 *
 * Espera ACTIVA, que es lo que se esta midiendo.  Al reves que la version de
 * una ranura, esto NO se llama por paquete: solo cuando lo siguiente depende de
 * lo que hay en vuelo, o cuando el proceso va a soltar el turno.
 *
 * No espera al ANALISIS: ese trabaja sobre una copia que nadie mas mira, y
 * esperarlo lo devolveria al camino critico.
 *
 * @return Vueltas que hubo que dar esperando.  NO es telemetria: es lo que
 *         distingue "hubo que juntarse" de "hubo que ESPERAR", y son cosas
 *         distintas.  Con reparto de uno en uno -- delegar un paquete y
 *         ejecutar el siguiente aqui -- juntarse al final del despacho ocurre
 *         SIEMPRE, por construccion, asi que contar juntadas daba una por
 *         entrega y la sonda se apagaba sola dandose por inutil.  Lo que dice
 *         si el solape sirvio es cuanto se espero: cero vueltas significa que
 *         el ayudante ya habia terminado, o sea solape completo.
 */
[[gnu::always_inline]] inline uint32_t ooo_drain() {
    uint32_t spins = 0;
    while (ooo_exec_inflight()) {
        ooo_pause();
        ++spins;
    }
    return spins;
}

/**
 * @brief Vueltas de espera a partir de las cuales se considera que NO hubo
 *        solape.
 *
 * Cada vuelta es un `pause`, que en las microarquitecturas recientes son ~140
 * ciclos.  Un paquete de 32 instrucciones de la VM cuesta del orden de 100 ns,
 * asi que con dos o tres vueltas ya se ha esperado tanto como duraba lo que se
 * delego -- y por encima de eso el reparto no esta adelantando trabajo, esta
 * haciendo cola.
 */
inline constexpr uint32_t kOooDrainSlack = 4;

/// Espera a que termine TODO, analisis incluido.  Solo al desmontar: mientras
/// haya un encargo vivo, el proceso al que apunta tiene que seguir existiendo.
[[gnu::always_inline]] inline void ooo_drain_all() {
    while (ooo_pending() != 0) ooo_pause();
}

/// Para el hilo ayudante.  Se llama al terminar el proceso.
void ooo_shutdown();

} // namespace runtime

#endif // VM_BUNDLES
#endif // VESTA_RUNTIME_BUNDLE_OOO_H
