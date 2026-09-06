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
struct OooJob {
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
inline void ooo_release_owner(ProcessVM *process) {
    ProcessVM *mine = process;
    g_ooo_owner.compare_exchange_strong(mine, nullptr,
                                        std::memory_order_acq_rel);
}

/**
 * @brief Encargos de EJECUCION sin terminar.
 *
 * Aparte de la cola porque las dos clases de encargo obligan a cosas muy
 * distintas.  Lo que se EJECUTA escribe registros del proceso, asi que no puede
 * quedar a medias cuando el planificador le da el turno a otro; lo que se
 * ANALIZA trabaja sobre una copia que nadie mas mira y puede seguir tranquilo.
 *
 * Sin este contador habria que esperar a los dos, y entonces el analisis
 * volveria a estar en el camino critico -- que es justo lo que se le quita
 * dandoselo al ayudante --.
 */
inline std::atomic<uint32_t> g_ooo_exec_pending{0};

/// Ceder el SMT mientras se espera.  Sin esto, dos hilos girando en el mismo
/// nucleo fisico se quitan el sitio y la espera sale mas cara que el trabajo.
[[gnu::always_inline]] inline void ooo_pause() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    _mm_pause();
#endif
}

/// Arranca el ayudante.  Fuera de linea a proposito: corre UNA vez.
void ooo_start();

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
    /* `acquire` sobre `tail`: hay que ver de verdad hasta donde ha consumido
     * antes de dar por libre una ranura, o se pisaria un encargo vivo. */
    if (h - g_ooo.tail.load(std::memory_order_acquire) >= kOooSlots)
        return false; // llena: lo hace el llamante y de paso deja respirar

    OooJob &slot = g_ooo.job[h & (kOooSlots - 1)];
    slot.proc = process;
    slot.kind = OooKind::Execute;
    slot.instr = instr;
    slot.n = n;
    // Se apunta ANTES de publicar: si se apuntara despues, el ayudante podria
    // haber terminado y decrementado antes de que esto llegara a sumar.
    g_ooo_exec_pending.fetch_add(1, std::memory_order_relaxed);
    // `release`: la ranura tiene que verse ANTES que el indice que la publica.
    g_ooo.head.store(h + 1, std::memory_order_release);
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
    if (h - g_ooo.tail.load(std::memory_order_acquire) >= kOooSlots)
        return false;

    OooJob &slot = g_ooo.job[h & (kOooSlots - 1)];
    slot.proc = process;
    slot.kind = OooKind::Prepare;
    slot.target = target;
    slot.scratch = scratch;
    slot.next_pc = next_pc;
    g_ooo.head.store(h + 1, std::memory_order_release);
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
    if (h - g_ooo.tail.load(std::memory_order_acquire) >= kOooSlots)
        return false;

    OooJob &slot = g_ooo.job[h & (kOooSlots - 1)];
    slot.proc = process;
    slot.kind = OooKind::Decode;
    slot.next_pc = pc;
    slot.n = n;
    g_ooo.head.store(h + 1, std::memory_order_release);
    return true;
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
 */
[[gnu::always_inline]] inline void ooo_drain() {
    while (g_ooo_exec_pending.load(std::memory_order_acquire) != 0) ooo_pause();
}

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
