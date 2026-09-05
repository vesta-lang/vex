/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle.h
 * @brief Paquetes de instrucciones: varias instrucciones de VM en un solo
 *        despacho, formados al RELLENAR la icache.
 *
 * El porque
 * ---------
 * Un interprete paga un salto indirecto por instruccion.  Fusionar k
 * instrucciones en un despacho quita k-1 de esos saltos, y de paso le da al
 * OoO del host un bloque recto mas largo del que extraer paralelismo.
 *
 * Lo que hace esto viable es DONDE se decide.  Formar el paquete cuesta
 * descodificar de mas, y eso solo se paga en el camino de FALLO de icache, que
 * esta medido: el 0,57% de las ejecuciones.  El otro 99,43% solo ejecuta.  Un
 * analisis que en el hot path seria ruinoso, amortizado por PC sale gratis.
 *
 * Y afecta a TODO el bytecode, lo emitiera quien lo emitiera, sin recompilar
 * nada -- que es la razon de hacerlo en la VM y no en el emisor.
 *
 * El hot path no cambia
 * ---------------------
 * El despacho ya es `d->exec_cached(proc, *d)`.  Una entrada de paquete tiene
 * `exec_cached` apuntando a @c exec_bundle.  Mismo salto indirecto, otro
 * destino: cero ramas nuevas, cero indirecciones nuevas.
 *
 * Donde vive el paquete
 * ---------------------
 * En una ARENA aparte, y la entrada de icache guarda un INDICE de 32 bits en el
 * hueco de `raw_data.raw1`.  Asi:
 *   - La icache sigue siendo de 64 KB con entradas de 64 bytes.  No se mueve la
 *     segunda variable que ya nos mordio al probar 2048 entradas.
 *   - El indice, al no ser puntero, permite compactar o realojar la arena sin
 *     recorrer la icache arreglando punteros.
 *
 * NO se uso la ranura contigua de la icache: las instrucciones son de tamano
 * VARIABLE, asi que la siguiente cae en `(pc + tam) & 1023`, que no es la de al
 * lado.  Ocuparla desalojaria a un tercero y dejaria a la segunda instruccion
 * sin entrada propia.
 *
 * Saltar a mitad de paquete es SEGURO
 * -----------------------------------
 * Si el flujo entra directamente al pc de la segunda instruccion, la busqueda
 * usa el pc de esa instruccion, no el de la cabecera: fallara, se descodificara
 * y se ejecutara suelta.  El paquete no la secuestra.
 *
 * Que pasa si la primera salta
 * ----------------------------
 * No hace falta saber de antemano que opcodes transfieren control.  El
 * manejador ejecuta, MIRA `did_jump` y `blocking`, y si la instruccion se fue a
 * otro sitio abandona el paquete ahi.  Es correcto por construccion en vez de
 * por una lista de opcodes que se queda vieja.
 *
 * Donde encaja esto: los tres niveles
 * ------------------------------------
 * Conviene tener el mapa delante, porque son tres cuellos DISTINTOS y se
 * confunden con facilidad -- reciclar la cache no arregla la localidad, y al
 * reves.
 *
 *                          BYTECODE
 *                             |
 *                             v
 *              +--------------------------------+
 *              |  Planificador de la VM         |
 *              |  dependencias y efectos        |   <- lo sabe el ASA:
 *              |  fusion y reordenacion         |      `instr_db_vm`
 *              +---------------+----------------+
 *                              |
 *                              v
 *              +--------------------------------+
 *              |  Cache de ejecucion            |
 *              |  paquetes / ventanas           |   <- esto es este fichero
 *              +---------------+----------------+
 *                              |
 *                    +---------+---------+
 *                    |                   |
 *                REGION A            REGION B
 *                ejecutando          recogiendo
 *                    |                   |
 *                    +---------+---------+
 *                              |
 *                              v
 *                    PROCESADOR ANFITRION
 *                    (su propio fuera de orden)
 *
 * QUE ARREGLA CADA NIVEL, que es lo que se confunde:
 *
 *   - La cache de doble region arregla CAPACIDAD y AGOTAMIENTO: antes se
 *     llenaba y dejaba de formar para siempre, o sea que el optimizador
 *     dinamico funcionaba un rato y se apagaba.  Medido en un tramo recto de
 *     8192 instrucciones: la cobertura pasa del 22% al 100% y aguanta quince
 *     ciclos de reciclaje sin degradarse.
 *   - NO arregla la LOCALIDAD del codigo.  Si la icache desaloja las cabeceras
 *     mas rapido de lo que se amortizan -- una formacion cada dos despachos --
 *     el limite es el tamano de la icache, y ninguna cantidad de reciclado lo
 *     mueve.  Son cuellos independientes y hay que atacarlos por separado.
 *
 * Los interruptores @c VM_BUNDLES y @c VM_BUNDLE_STATS se definen en
 * `proceso_runtime.h`, no aqui: anaden campos a @c ProcessVM y su defecto tiene
 * que verlo TODA unidad de traduccion, la incluya esta cabecera o no.
 */

#ifndef VESTA_RUNTIME_BUNDLE_H
#define VESTA_RUNTIME_BUNDLE_H

#include <cstdint>
#include <vector>

#include "runtime/proceso_runtime.h"

#if VM_BUNDLES

namespace runtime {

/// Vueltas que un paquete puede dar por dentro antes de soltar el despacho.
/// Acota el desenrollado: sin tope, un bucle largo se quedaria dentro sin dar
/// turno a nadie.  Las reducciones se descuentan igual, asi que la equidad del
/// planificador no depende de este numero, solo la latencia de reaccion.
/// Llamada directa para los opcodes mas frecuentes dentro del paquete, en vez
/// de la indirecta por `exec_cached`.  Ver el porque en `bundle.cpp`.
#ifndef BUNDLE_DIRECT_CALL
#define BUNDLE_DIRECT_CALL 0
#endif

#ifndef BUNDLE_SOLO_UNA
#define BUNDLE_SOLO_UNA 0
#endif

#ifndef BUNDLE_LOOP_MAX
#define BUNDLE_LOOP_MAX 64
#endif

/// Instrucciones por paquete.  Empieza en 2 (fusion de pares) y es lo unico que
/// hay que subir para pasar a superescalar de k.
#ifndef BUNDLE_MAX
#define BUNDLE_MAX 32
#endif

/**
 * @struct Bundle
 * @brief Un paquete: k instrucciones ya descodificadas, en orden de ejecucion.
 *
 * Cada instruccion lleva su `pc` REAL en su propio `DecodedInstr`, puesto al
 * formar.  Hoy, con
 * las instrucciones en su orden, seria deducible; en cuanto se reordenen (OoO)
 * deja de serlo, y sin el la traza de un fallo senalaria a la instruccion
 * equivocada.  @c build_stack_trace es lo que hace utiles los reventones: que
 * empiece a mentir por un cambio de rendimiento no es aceptable.
 */
struct Bundle {
    uint32_t k = 0; ///< cuantas instrucciones lleva AHORA MISMO (ver ajuste)

    /* --- Ajuste de k en ejecucion -------------------------------------------
     *
     * `k` no lo fija nadie de antemano porque no se puede: la longitud util de
     * un paquete es la del tramo recto en ESE sitio, y eso es propiedad del
     * programa.  Un k fijo o se queda corto donde el tramo es largo, o
     * descodifica de mas donde es corto.
     *
     * La senal para acertarlo ya la produce el propio paquete: el INDICE en el
     * que abandona.  Si un paquete se corta siempre en la instruccion 3, es que
     * la 3 salta y las que van detras nunca se ejecutan desde aqui.  Recortar
     * `k` a 4 deja el paquete terminando justo en el salto.
     *
     * Se exige que se repita (@c ABORT_SETTLE) antes de recortar: un salto
     * condicional que a veces se toma y a veces no NO debe encoger el paquete,
     * porque las veces que no se toma el resto si se ejecuta. */
    uint32_t abort_at = 0;   ///< ultimo indice en el que se abandono
    uint32_t abort_runs = 0; ///< veces seguidas abandonando en el mismo sitio
    /// Abandonos seguidos en el mismo indice antes de recortar.
    static constexpr uint32_t ABORT_SETTLE = 16;

    /* --- Retirada: el paquete decide si vale la pena -------------------------
     *
     * Entrar a un paquete cuesta.  Medido: los paquetes retiran un 41% mas de
     * instrucciones del host, y ese exceso solo se amortiza si cada entrada
     * ejecuta suficientes instrucciones.
     *
     * La correlacion sobre 10 benchmarks entre instrucciones por entrada y el
     * cambio de tiempo dio r = -0,765, con el corte alrededor de 5-6: por
     * debajo se pierde (`callvirt_hot` 3,00 -> +15%), por encima se gana
     * (`branch_unpredict` 25,67 -> -64%).
     *
     * Asi que el paquete se mide a si mismo y, si no llega, se retira: la
     * entrada de icache vuelve a ser la instruccion normal -- la que guarda
     * @ref head -- y el interprete la despacha otra vez por su manejador
     * rapido.  No hace falta acertar el umbral por programa ni decidirlo al
     * formar: cada sitio lo demuestra con su propia ejecucion.
     *
     * `entries` cuenta tambien los ENCADENADOS, no solo los despachos: fue el
     * denominador equivocado lo que me tuvo tres hipotesis persiguiendo la
     * causa. `callvirt_hot` hace 192 instrucciones por DESPACHO pero solo 3 por
     * ENTRADA, porque encadena 656.000 veces en trozos de tres. */
    uint32_t entries = 0;  ///< veces que se entro (despachos + encadenados)
    uint32_t executed = 0; ///< instrucciones ejecutadas en total

    /* --- Lo que hace falta para PONDERAR la fusion por ejecucion ------------
     *
     * Los dos de arriba no sirven: se reinician al juzgar si el paquete
     * compensa, asi que en cualquier momento valen lo que lleve la ventana
     * actual, no el total.
     *
     * Y sin ponderar, las cifras de fusion MIENTEN por el lado que mas duele:
     * un paquete formado una vez y entrado un millon de veces cuenta lo mismo
     * que uno de arranque que corre una sola vez.  Lo que importa es cuantas
     * instrucciones se ahorran EJECUTANDO, no cuantos pares se juntaron al
     * formar.
     *
     * Se llenan al FORMAR, nunca por instruccion, y quien los pondera es el
     * bucle de entrada: multiplicarlos AL FINAL recorriendo la icache no vale,
     * porque para entonces el paquete puede estar ya recogido.  Caben en un
     * byte porque un paquete tiene como mucho 31 pares. */
    /**
     * @brief Desde donde el paquete se puede partir en dos mitades
     *        INDEPENDIENTES, o 0 si no se puede.
     *
     * `instr[0..split)` y `instr[split..k)` no comparten nada: ni registros, ni
     * banderas, ni memoria, y ninguna transfiere control.  Con eso las dos se
     * pueden ejecutar A LA VEZ sin ninguna sincronizacion entre ellas.
     *
     * Se busca al FORMAR, que es donde se puede pensar; ejecutar solo mira este
     * campo.  Cero es "no se puede", que es el caso comun.
     */
    uint8_t split = 0;

    /// Donde ACABA la parte repartible.  Lo de aqui en adelante lo ejecuta el
    /// hilo principal en orden: es lo que hay de la primera barrera para alla,
    /// y una barrera no se puede adelantar.
    uint8_t split_end = 0;

    uint8_t fused_pairs = 0;    ///< pares que el fusionador junto aqui
    uint8_t newop_ready = 0;    ///< pares que un opcode nuevo capturaria
    uint8_t newop_livewall = 0; ///< ...y los que no, por seguir vivo el temporal
    bool retired = false;  ///< ya se devolvio la entrada de icache

    /// Entradas antes de juzgar.  Suficientes para que la media signifique algo
    /// y pocas para no arrastrar la perdida mucho tiempo.
    static constexpr uint32_t JUDGE_AFTER = 64;
    /// Instrucciones por entrada por debajo de las cuales no compensa.
    static constexpr uint32_t MIN_PER_ENTRY = 6;

    /**
     * @brief La instruccion que habia en la entrada de icache al formar.
     *
     * Es lo que se devuelve al retirar el paquete, y va APARTE porque `instr[0]`
     * ya no sirve para eso: el planificador reordena el paquete antes de
     * publicarlo, y entonces en el hueco cero hay OTRA instruccion -- la que
     * mejor puntuo --, no la de esta direccion.
     *
     * Restaurando `instr[0]` la entrada quedaba con una instruccion de otro
     * sitio, y eso rompe la CADENA: un paquete encadena mirando si el destino
     * del salto es cabecera de otro, y una entrada envenenada deja de serlo.
     * Un solo paquete reordenado corta el eslabon y todo lo que va detras se
     * vuelve a formar desde cero.  Medido en un tramo recto de 8192: 65
     * paquetes formados y 7806 encadenamientos pasaban a 513 y 970, con UN solo
     * paquete reordenado de 513.
     *
     * No se ve como un error porque la entrada lleva su propio `pc`: la
     * busqueda siguiente falla y se vuelve a formar, o sea que sale caro en vez
     * de salir mal.  Es justo el modo de fallo que no se detecta mirando si el
     * programa da el resultado correcto.
     */
    DecodedInstr head;

    DecodedInstr instr[BUNDLE_MAX]; ///< ya descodificadas, en orden de ejec.
};

/**
 * @struct BundleArena
 * @brief Cache copiadora y compactadora de DOBLE REGION, con publicacion por
 *        cambio de puntero.
 *
 * EN QUE SE PARECE A UN RECOLECTOR.  En la mecanica, y conviene decirlo porque
 * hace el diseno legible de golpe para quien conozca uno: hay dos semiespacios,
 * se copia lo VIVO al otro y se intercambia cual es el bueno.  Las RAICES son
 * las entradas de icache -- un paquete esta vivo si y solo si alguna lo
 * referencia, porque la cabecera es la UNICA puerta de entrada y no hay ningun
 * otro puntero duradero a un paquete --.  Y la region vieja no se toca hasta
 * que nadie puede estar dentro, que es el periodo de gracia de siempre.
 *
 * EN QUE NO SE PARECE, que es lo que de verdad importa aqui:
 *
 *   1. PERDER ALGO NO ES UN FALLO.  Un objeto recolectado que aun hacia falta
 *      es un bug; un paquete perdido es un fallo de cache y se vuelve a formar.
 *      Eso permite ser conservador sin red: no hay barreras de escritura, ni
 *      finalizadores, ni exigencia de precision.  Es la diferencia que borra
 *      casi toda la complejidad de un recolector de verdad.
 *   2. NO HAY GRAFO QUE RECORRER.  Un paquete no referencia a otro paquete: el
 *      alcance es de profundidad UNO, raiz -> paquete.  Sin ciclos, sin lista
 *      de trabajo, sin fase de marcado.  Recorrer las raices ES la recoleccion.
 *   3. LAS RAICES ESTAN ENUMERADAS.  Son exactamente `ICACHE_SIZE` entradas en
 *      un array.  Un recolector tiene que ir a buscarlas por pilas y registros
 *      -- el de este proyecto barre la pila de forma conservativa --; aqui se
 *      recorren en un bucle.
 *   4. EL CONJUNTO VIVO ESTA ACOTADO.  Como cada raiz apunta como mucho a un
 *      paquete, no puede haber mas vivos que raices.  Con `CAPACITY` >=
 *      `ICACHE_SIZE` la copia NUNCA se queda sin sitio: no hay caso degenerado
 *      que tratar, cosa que en un monton no se puede afirmar jamas.
 *   5. TODO MIDE LO MISMO.  `Bundle` es de tamano fijo, asi que no hay clases
 *      de tamano ni fragmentacion, y compactar es copiar en orden.
 *
 * En resumen: se coge la mecanica de un copiador y se tira todo lo que un
 * monton obliga a llevar y una cache no.
 *
 * LA PUBLICACION es un cambio de puntero, y es lo que evita parar el
 * interprete.  Repuntar una raiz es una escritura de 64 bits alineada -- o sea
 * atomica de por si en x86-64 --, asi que quien lee ve la vieja o la nueva y
 * las dos son validas mientras la vieja siga en pie.  Los lectores no
 * sincronizan NADA.
 *
 * DE DONDE VIENE.  Antes esto era un asignador que solo avanzaba y, al
 * llenarse, DEJABA DE FORMAR PARA SIEMPRE -- el comentario decia que se vaciaba
 * entero, pero el codigo no lo hacia, porque vaciar invalidaria las entradas de
 * icache que apuntan a paquetes muertos.  O sea que la cache funcionaba un rato
 * y luego se apagaba.  Copiar resuelve las dos cosas a la vez: recicla, y al
 * repuntar las raices no deja ninguna colgando.
 */
struct BundleArena {
    /* Bloques que NO se mueven, y asignacion por puntero que solo avanza.
     *
     * Dos requisitos, y los dos salieron de medir:
     *
     *  1. ESTABILIDAD.  `exec_bundle` sostiene un `Bundle*` mientras ejecuta, y
     *     una instruccion de dentro puede provocar un fallo de icache que forme
     *     otro paquete.  Con `std::vector` eso reubicaba el almacen y el
     *     puntero en uso quedaba colgando -- daba resultados distintos y
     *     reventones.
     *
     *  2. COSTE DE ENTRADA.  La biseccion midio que entrar a un paquete cuesta
     *     +133% sobre ejecutar una instruccion suelta, y ese coste es lo que
     *     fija el umbral de rentabilidad.  `std::deque` cumple (1) pero su
     *     `operator[]` es una indexacion de DOS niveles -- division incluida --
     *     que se paga en cada entrada Y en cada encadenado.
     *
     * Con bloques fijos que nunca se mueven, la entrada de icache puede guardar
     * el PUNTERO al paquete en vez de un indice, y la indexacion desaparece por
     * completo del camino caliente: leer el puntero y ya.
     *
     * `alloc` es un incremento y una comparacion.  Nada mas. */
    static constexpr uint32_t CHUNK = 16;      ///< paquetes por bloque
    static constexpr uint32_t CAPACITY = 8192; ///< paquetes por MITAD

    /* EL invariante que hace que esto no pueda desbordar, comprobado y no solo
     * escrito.  Cada raiz -- una entrada de icache -- apunta como mucho a un
     * paquete, asi que el conjunto vivo nunca pasa de `ICACHE_SIZE`; si una
     * mitad tiene sitio para mas, la copia siempre cabe y tras cada recoleccion
     * queda hueco para seguir formando.
     *
     * Con la desigualdad al reves no habria un error: `bundle_collect` se
     * quedaria sin sitio a mitad de la copia y su guarda -- `if (fresh ==
     * nullptr) break;` -- ABANDONARIA raices vivas apuntando a la region que se
     * esta vaciando.  O sea punteros colgando, en silencio.  Subir
     * `ICACHE_SIZE` por encima de `CAPACITY` es justo el cambio que alguien
     * haria sin sospecharlo, y por eso se para aqui. */
    static_assert(CAPACITY >= ICACHE_SIZE,
                  "una mitad tiene que poder alojar TODAS las raices vivas: "
                  "con menos, la copia deja raices apuntando a la region vieja");

    /// Bloques por mitad.  Array fijo, no `std::vector`: el numero maximo se
    /// sabe (CAPACITY/CHUNK) y una lista que crece en el corazon del
    /// interprete es una reserva de monton escondida.
    static constexpr uint32_t CHUNKS = CAPACITY / CHUNK;

    /**
     * @struct Half
     * @brief Una de las dos mitades que se turnan.
     *
     * Los bloques se piden al crecer y NO se sueltan jamas.  Reiniciar una
     * mitad es poner su contador a cero: los bloques se reutilizan.  Asi la
     * memoria se estabiliza en el maximo que el programa llego a necesitar y
     * el sistema no vuelve a ver una peticion.
     */
    struct Half {
        Bundle *chunks[CHUNKS] = {};
        uint32_t n_chunks = 0; ///< bloques pedidos hasta ahora
        uint32_t used = 0;     ///< paquetes ocupados AHORA

        /// Bytes de un bloque.  32 KB con los valores de hoy: un multiplo de
        /// pagina redondo para lo que hay debajo.
        static constexpr size_t CHUNK_BYTES = CHUNK * sizeof(Bundle);

        Bundle *alloc() {
            const uint32_t chunk = used / CHUNK;
            if (chunk >= n_chunks) {
                if (n_chunks >= CHUNKS) return nullptr; // mitad llena
                /* Al sistema por la puerta del proyecto -- VirtualAlloc en
                 * Windows, mmap en POSIX -- y no por `new Bundle[]`.  Se pide
                 * por bloques y NO se suelta nunca: reiniciar una mitad es
                 * poner su contador a cero, con lo que la memoria se estabiliza
                 * en el maximo que el programa llego a necesitar y el sistema
                 * no vuelve a ver una peticion. */
                void *mem = vm::allocate_memory(
                    CHUNK_BYTES, vm::MemPerm::READ | vm::MemPerm::WRITE);
                if (mem == nullptr) return nullptr;
                Bundle *c = static_cast<Bundle *>(mem);
                for (uint32_t i = 0; i < CHUNK; ++i) new (&c[i]) Bundle();
                chunks[n_chunks++] = c;
            }
            return &chunks[chunk][used++ % CHUNK];
        }

        /// Reinicia SIN soltar los bloques.  Lo que se reutiliza es el espacio.
        void reset() { used = 0; }

        /// @brief El paquete @p i de esta region, o nullptr si no existe.
        ///        Con esto se puede recorrer la region sin conocer los bloques.
        Bundle *at(uint32_t i) {
            if (i >= used) return nullptr;
            return &chunks[i / CHUNK][i % CHUNK];
        }
        const Bundle *at(uint32_t i) const {
            if (i >= used) return nullptr;
            return &chunks[i / CHUNK][i % CHUNK];
        }

        /// Si @p b vive en esta mitad.  Lo usa la copia para saber que mover.
        bool contains(const Bundle *b) const {
            for (uint32_t i = 0; i < n_chunks; ++i)
                if (b >= chunks[i] && b < chunks[i] + CHUNK) return true;
            return false;
        }

        ~Half() {
            for (uint32_t i = 0; i < n_chunks; ++i)
                vm::free_memory(chunks[i], CHUNK_BYTES);
        }
    };

    Half half[2];         ///< las dos, fijas
    uint32_t current = 0; ///< cual esta en uso
    /// La otra espera a poder reiniciarse: hay un `Bundle*` suyo en manos de
    /// `exec_bundle`.  Ver @ref bundle_in_use.
    /* La bandera de "hay region esperando" vive en `ProcessVM`, no aqui: se
     * mira al salir de CADA paquete y ahi una indireccion mas cuesta. */

    Half &live() { return half[current]; }
    Half &spare() { return half[current ^ 1u]; }

    /// Compatibilidad con quien preguntaba `total`: paquetes en la mitad viva.
    uint32_t total() const { return half[current].used; }

    Bundle *alloc() { return half[current].alloc(); }
};

/**
 * @brief Ranura de despacho por la que entra una cabecera de paquete.
 *
 * Hay TRES puertas de despacho, no dos, y esta era la que faltaba:
 *   1. `d->exec_cached(...)`            -- varios caminos.
 *   2. `decoded_ptr->metadata->exec()`  -- `execute_instruction`, el lento.
 *   3. `goto *dispatch_table[idx]`      -- el computed-goto del run_loop, que
 *      es EL HOT PATH, y cuyo indice sale de `flags_info` de la entrada:
 *          (is_not_extended == 0) ? (0x100 | opcode_index) : is_not_extended
 *
 * Dejando los flags de la primera instruccion, el run_loop saltaba a SU
 * manejador rapido -- `L_MOV_RR` y compania --, que lee los operandos de la
 * entrada... que aqui llevan el indice de arena.  Ejecutaba basura: los
 * programas terminaban antes y salia como una mejora del 88%.
 *
 * La tabla son 512 huecos, todos a `L_SLOW` salvo los pocos con manejador
 * rapido, y `L_SLOW` es precisamente quien llama a `exec_cached`.  Basta con
 * despachar por un hueco que nadie sobrescriba.  En el rango primario solo esta
 * cogido el `0x11` (`L_JCC`), asi que `0xFF` es libre.
 *
 * Si algun dia se anade un manejador rapido en `0xFF`, esto rompe -- de ahi que
 * sea una constante con nombre y no un numero suelto en medio del codigo.
 */
constexpr uint8_t BUNDLE_DISPATCH_SLOT = 0xFF;

/**
 * @brief El paquete que lleva una entrada de icache, en su hueco de `raw1`.
 *
 * Se guarda el PUNTERO y no un indice: los bloques de la arena no se mueven
 * nunca, asi que el puntero vale siempre, y leerlo es una carga.  Con indice
 * habia que indexar la arena en cada entrada y en cada encadenado, que es
 * justo el coste que la biseccion senalo.
 *
 * No hace falta marca de "esto es un paquete": eso se sabe por `metadata`, que
 * apunta al descriptor sintetico.
 */
inline Bundle *bundle_of(const DecodedInstr &d) {
    return reinterpret_cast<Bundle *>(
        static_cast<uintptr_t>(d.data_instruction.raw_data.raw1));
}

/// Guarda el paquete en la entrada de icache.
inline void bundle_store(DecodedInstr *d, Bundle *b) {
    d->data_instruction.raw_data.raw1 =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(b));
}

/**
 * @brief Intenta formar un paquete con la instruccion recien cacheada.
 *
 * Se llama SOLO desde el camino de fallo de @c decode_instruction, despues de
 * que la entrada este puesta.  Si no puede formar nada, deja la entrada tal
 * cual y el interprete sigue como siempre.
 *
 * @param process Proceso cuya icache se acaba de rellenar.
 * @param slot    Entrada recien escrita (la cabecera candidata).
 * @param pc      Direccion de la instruccion de la cabecera.
 */
void bundle_try_form(ProcessVM *process, DecodedInstr *slot, uint64_t pc);

/**
 * @brief Manejador de una entrada de paquete.  Es lo que apunta
 *        @c exec_cached de la cabecera.
 *
 * Ejecuta las instrucciones del paquete en orden, avanzando `rip` el mismo
 * tanto que avanzaria el interprete una a una, y abandona en cuanto una salta
 * o se bloquea.
 *
 * Al terminar marca `did_jump` en la ENTRADA para que el run_loop no vuelva a
 * avanzar `rip`: el paquete ya lo dejo donde toca.  Hace falta porque
 * `size_instr` es un campo de 4 BITS y el tamano total de un paquete se sale
 * de 15 en cuanto hay dos instrucciones largas.
 */
void exec_bundle(ProcessVM *process, const DecodedInstr &d);

/// Libera la arena de un proceso.  Idempotente.
/**
 * @brief Reordena las instrucciones DENTRO del paquete, al formarlo.
 *
 * No es el fuera-de-orden de un procesador: se reordena para poder FUSIONAR --
 * juntar productor y consumidor deja el par adyacente, y solo un par adyacente
 * se puede convertir en UNA instruccion --, que es lo unico que baja el
 * RECUENTO de instrucciones de VM.
 *
 * Corre una vez por sitio; lo que ahorra se cobra en cada entrada posterior.
 * Detalle del modelo y de por que es seguro, en `bundle_reorder.cpp`.
 *
 * @param process Proceso, para leer los bytes de cada instruccion.
 * @param b       Paquete recien formado, todavia sin publicar.
 * @param why     Si no es nulo, recibe POR QUE se eligio cada posicion: el
 *                identificador del criterio que decidio, o
 *                @ref kBundleReorderCriteria si ninguno tiro (orden natural).
 *                Tiene que caber @c BUNDLE_MAX.  Existe porque "se movio" no
 *                es una explicacion: al mirar un paquete reordenado hay que
 *                poder decir si fue para fusionar, para separar dependencias o
 *                para agrupar accesos, y eso solo lo sabe quien elige.
 * @return Cuantas instrucciones cambiaron de sitio; 0 si se dejo igual.
 */
struct BundleTouch; ///< `runtime/bundle/bundle_touch_all.h`

uint32_t bundle_reorder(ProcessVM *process, Bundle &b, BundleTouch &tc,
                        uint8_t *why = nullptr);

/**
 * @brief Convierte pares del paquete en UNA instruccion, y ACORTA `b.k`.
 *
 * Es lo unico que baja el RECUENTO, que es el cuello medido del interprete:
 * reordenar prepara el orden y empaquetar ahorra despachos, pero las
 * instrucciones siguen siendo las mismas.
 *
 * Va DESPUES de reordenar -- que es quien deja los pares pegados -- y ANTES de
 * publicar, mientras el paquete todavia es local.  Ver `bundle_fuse.cpp` para
 * que se fusiona y por que es seguro.
 *
 * @param b Paquete, ya reordenado.  Se modifica: la fusionada ocupa el hueco
 *          de las dos y `k` baja.
 * @return Cuantos pares se fusionaron.
 */
/**
 * @brief Donde apunta el fusionador su telemetria.  Nulo = apagada.
 *
 * Va en un struct y no en punteros sueltos para no dar por hecho que los
 * contadores del proceso esten pegados en memoria: el dia que alguien meta un
 * campo en medio, un puntero al primero dejaria de valer para el segundo y la
 * cuenta saldria mal SIN dar ningun error.
 */
struct FuseTelemetry {
    uint64_t *reject;         ///< kFuseRejectCount contadores, por razon
    uint64_t *uncovered;      ///< 512: que opcode encabeza un par sin patron
    uint64_t *unmatched_second; ///< 512: que opcode va SEGUNDO y no encaja
    uint64_t *newop_ready;    ///< pares que un opcode nuevo capturaria
    uint64_t *newop_livewall; ///< ...y los que no, por seguir vivo el temporal
};

uint32_t bundle_fuse(Bundle &b, BundleTouch &tc, ProcessVM *process,
                     uint64_t next_pc,
                     const FuseTelemetry *tel);

/**
 * @brief Que registros siguen VIVOS a partir de @p pc, mirando unas pocas
 *        instrucciones hacia delante.
 *
 * Lo pide `bundle_fuse` para saber si el temporal de un par muere.  Con la
 * respuesta trivial -- "todos" -- el patron de redirigir el destino no cuaja
 * nunca, porque a ese temporal lo mata la instruccion que vuelve a escribirlo y
 * esa cae fuera del paquete con facilidad.
 *
 * @param process Proceso del que leer el bytecode.
 * @param pc      Primera direccion DESPUES del paquete.
 * @return Mascara de registros generales vivos; 0xFFFF si no se pudo resolver.
 */
/**
 * @brief Por que NO se fusiono un par.
 *
 * Un fusionador que solo dice "no" es indistinguible de uno roto: si sale 0%,
 * no se sabe si es que no hay material, si el patron esta mal escrito o si lo
 * que falla es el modelo de efectos que trae los pares.  Cada renuncia dice
 * cual de las cinco razones fue, y la cuenta se imprime en el informe.
 *
 * Es la misma regla que rige los analisis del ASA: al renunciar, se dice POR
 * QUE.  Un analisis que calla al renunciar parece que funciona.
 */
enum class FuseReject : uint8_t {
    None = 0,      ///< se fusiona: no hay renuncia
    NotAMov,       ///< la primera no encaja en ningun patron: ni es `mov`
                   ///< reg,reg de 64 bits ni pisa su destino sin leerlo --
                   ///< tipicamente porque ya viene fusionada del compilador
    NoThreeOpForm, ///< la segunda no tiene variante de tres operandos
    WidthMismatch, ///< alguna no opera a 64 bits
    DestMismatch,  ///< la ALU no escribe lo que el `mov` acaba de dejar
    SrcIsDest,     ///< la segunda fuente ES el destino: `alu3` leeria otro valor
    TooMany,       ///< la fusionada no cabe en `absorbed` o en `size_instr`
    /* --- del patron de REDIRIGIR EL DESTINO ------------------------------- */
    CopyMismatch,  ///< la segunda no es un `mov` que copie lo que produjo la
                   ///< primera
    DestLiveOut    ///< el destino intermedio SIGUE VIVO al salir del paquete,
                   ///< asi que no se le puede quitar la escritura
};

/// Cuantas razones hay.  Fija el tamano de los contadores del proceso.
constexpr size_t kFuseRejectCount = 9;

/**
 * @brief Fusionaria el fusionador este par, y si no, por que no.
 *
 * No cambia nada: es la CONSULTA que responde `can_fuse`, expuesta para que el
 * informe de pares diga cuanto del material medido esta al alcance del ABI de
 * hoy sin volver a decidirlo por su cuenta.  Contestarla dos veces es como el
 * informe acabo diciendo que habia un 44,6% de trabajo pendiente en un patron
 * que el compilador ya emitia fusionado.
 *
 * @param a Primera del par (la que produce).
 * @param b Segunda del par (la que consume).
 * @return @c FuseReject::None si el par cae dentro de lo que hoy se sabe
 *         fusionar; en otro caso, la razon de la renuncia.
 */
FuseReject fuse_would_apply(const DecodedInstr &a, const DecodedInstr &b);

/**
 * @brief Merece la pena poner estas dos JUNTAS?
 *
 * La FORMA de cualquiera de los patrones, sin las condiciones que dependen del
 * contexto -- vivacidad, topes --.  Lo usa el REORDENADOR para decidir a quien
 * acercar: si al final no fusiona se pierde una reordenacion, y no acercarlas
 * pierde la fusion entera, asi que aqui sobra ser optimista.
 *
 * Existe para que el reordenador no tenga su propia idea de que es fusionable.
 * La suya solo conocia el patron productor -> consumidor, y por eso era ciega a
 * las TANDAS -- varios `mov` seguidos, varios accesos seguidos --, que no
 * tienen ninguna dependencia entre si y hoy son las que mas rinden.
 *
 * Reordenar PARA fusionar no es un coste que evitar: es para lo que esta.
 */
bool fuse_pairable(const DecodedInstr &a, const DecodedInstr &b);

/// Cuantos criterios pesa el planificador.  Ver `bundle_reorder.cpp`.
constexpr uint8_t kBundleReorderCriteria = 4;

/// @return El nombre del criterio @p id, o "orden" si no decidio ninguno.
const char *bundle_reorder_criterion(uint8_t id);

void bundle_release(ProcessVM *process);

/**
 * @brief Vuelca el ESTADO de las caches de este proceso.
 *
 * Ocupacion de la icache, cuantas entradas son cabeceras de paquete, cuanto
 * lleva cada region y cuantos paquetes siguen vivos frente a los reservados --
 * la diferencia es la basura pendiente de recoger.
 *
 * NO cuenta nada durante la ejecucion: recorre las estructuras cuando se le
 * pide, asi que el camino caliente no paga por que exista.  Sale solo al morir
 * el proceso con `VESTA_CACHE_DUMP=1`, y se puede llamar a mano desde un test o
 * desde el depurador.
 */
void bundle_dump(const ProcessVM *process);

/**
 * @brief Vuelca CADA cabecera viva con lo que su paquete ha hecho.
 *
 * Mas detallado que @ref bundle_dump y por eso no sale solo: con miles de
 * cabeceras seria ilegible.  Es lo que hay que mirar para entender por que un
 * paquete concreto se retiro -- las columnas `entradas` y `ejecutadas` son
 * justo las que decide `Bundle::MIN_PER_ENTRY`.
 *
 * @param max_lines Tope de lineas, para no inundar la salida.
 */
// No es `const` porque desensamblar LEE la memoria de la VM, que es lo unico
// que hace que el volcado sea util: sin eso solo saldrian nombres de opcode.
void bundle_dump_heads(ProcessVM *process, uint32_t max_lines = 64,
                       bool with_instructions = false);

/**
 * @brief Vuelca un paquete: lo que ha hecho, y su ENSAMBLADOR completo.
 *
 * Es lo que hace falta el dia que algo va mal.  El `pc` de cada instruccion se
 * guarda al formar y no se deduce del orden: en cuanto se reordene, deducirlo
 * daria la direccion equivocada, y un volcado que miente es peor que ninguno.
 *
 * Imprime la instruccion ENTERA, no su nombre.  Antes listaba `add  4 bytes`,
 * que no dice sobre que registros ni con que inmediato -- o sea, no dice nada
 * que sirva para depurar: con veinte `add` seguidos no se distingue cual es
 * cual.  Ahora es la misma linea que sacaria `--disasm-file`, y por eso se
 * puede contrastar contra el programa.
 */
void bundle_dump_one(ProcessVM *process, const Bundle *b);

/**
 * @brief Solo el ENSAMBLADOR de un paquete, sin la linea de estado.
 *
 * Lee los BYTES REALES de la memoria de la VM y los pasa por el mismo
 * desensamblador que `--disasm-file`, asi que se ve lo mismo que mirando el
 * programa.  Leer de `vm_mem` y no del `DecodedInstr` es deliberado: si alguna
 * vez el paquete guardara algo distinto de lo que hay en memoria, esto lo
 * ensenaria en vez de taparlo.
 */
void bundle_dump_asm(ProcessVM *process, const Bundle *b);

/**
 * @struct BundleStats
 * @brief Contadores de telemetria.  Existen SIEMPRE; lo que se pide en
 *        ejecucion es que se llenen (`ProcessVM::bundle_stats_on`).
 *
 * Van en el proceso y son enteros normales, no atomicos: cada proceso lleva los
 * suyos y se agregan al final.  Un contador atomico por instruccion falsearia
 * justo lo que se quiere medir.
 */
struct BundleStats {
    uint64_t formed = 0;            ///< paquetes construidos (una vez por PC)
    uint64_t not_formed = 0;        ///< intentos que no cuajaron
    uint64_t dispatches = 0;        ///< veces que se entro a un paquete
    uint64_t instrs_in_bundles = 0; ///< instrucciones ejecutadas dentro
    uint64_t aborts = 0;            ///< paquetes cortados por salto o bloqueo
    uint64_t flushes = 0;           ///< veces que la arena se lleno
    uint64_t shrinks = 0;           ///< paquetes recortados a su tramo real
    uint64_t chained = 0; ///< paquetes encadenados sin soltar despacho
    /// Cabeceras que NO se formaron porque su ranura ya tenia otra: la
    /// cabecera se corre a la instruccion siguiente.  Solo con
    /// `ICACHE_HEAD_SHIFT`; sin el vale cero y dice la verdad.
    uint64_t head_shifts = 0;

    /// Despachos AHORRADOS: cada instruccion de mas dentro de un paquete es un
    /// salto indirecto que el interprete no hizo.  Es la cifra que dice si esto
    /// sirve para algo.
    uint64_t saved() const { return instrs_in_bundles - dispatches; }
};

} // namespace runtime

#endif // VM_BUNDLES

#endif // VESTA_RUNTIME_BUNDLE_H
