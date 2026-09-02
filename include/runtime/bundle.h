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
     * entrada de icache vuelve a ser la instruccion normal -- que esta guardada
     * en `instr[0]` -- y el interprete la despacha otra vez por su manejador
     * rapido.  No hace falta acertar el umbral por programa ni decidirlo al
     * formar: cada sitio lo demuestra con su propia ejecucion.
     *
     * `entries` cuenta tambien los ENCADENADOS, no solo los despachos: fue el
     * denominador equivocado lo que me tuvo tres hipotesis persiguiendo la
     * causa. `callvirt_hot` hace 192 instrucciones por DESPACHO pero solo 3 por
     * ENTRADA, porque encadena 656.000 veces en trozos de tres. */
    uint32_t entries = 0;  ///< veces que se entro (despachos + encadenados)
    uint32_t executed = 0; ///< instrucciones ejecutadas en total
    bool retired = false;  ///< ya se devolvio la entrada de icache

    /// Entradas antes de juzgar.  Suficientes para que la media signifique algo
    /// y pocas para no arrastrar la perdida mucho tiempo.
    static constexpr uint32_t JUDGE_AFTER = 64;
    /// Instrucciones por entrada por debajo de las cuales no compensa.
    static constexpr uint32_t MIN_PER_ENTRY = 6;

    DecodedInstr instr[BUNDLE_MAX]; ///< ya descodificadas, en orden de ejec.
};

/**
 * @struct BundleArena
 * @brief Almacen de paquetes de un proceso.
 *
 * Asignador que solo avanza, y vaciado ENTERO cuando se llena -- lo mismo que
 * hace un cache de codigo de JIT.  Esta acotada por el numero de cabeceras de
 * traza distintas, o sea por el tamano del codigo, no por lo que se ejecute:
 * un bucle de mil millones de vueltas forma sus paquetes una vez.
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
    static constexpr uint32_t CHUNK = 16; ///< paquetes por bloque
    static constexpr uint32_t CAPACITY =
        8192; ///< tope antes de dejar de formar

    std::vector<Bundle *> chunks;
    uint32_t used = CHUNK; ///< usados en el ultimo bloque (fuerza el primero)
    uint32_t total = 0;    ///< paquetes vivos, para el tope

    Bundle *alloc() {
        if (used == CHUNK) {
            chunks.push_back(new Bundle[CHUNK]);
            used = 0;
        }
        ++total;
        return &chunks.back()[used++];
    }

    /// Vacia la arena.  Quien la llame DEBE invalidar tambien la icache: sus
    /// entradas de paquete quedan apuntando a memoria liberada.
    void clear() {
        for (Bundle *c : chunks)
            delete[] c;
        chunks.clear();
        used = CHUNK;
        total = 0;
    }

    ~BundleArena() { clear(); }
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
void bundle_release(ProcessVM *process);

#if VM_BUNDLE_STATS
/**
 * @struct BundleStats
 * @brief Contadores de telemetria.  Solo existen con @c VM_BUNDLE_STATS=1.
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

    /// Despachos AHORRADOS: cada instruccion de mas dentro de un paquete es un
    /// salto indirecto que el interprete no hizo.  Es la cifra que dice si esto
    /// sirve para algo.
    uint64_t saved() const { return instrs_in_bundles - dispatches; }
};
#endif // VM_BUNDLE_STATS

} // namespace runtime

#endif // VM_BUNDLES

#endif // VESTA_RUNTIME_BUNDLE_H
