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

/**                                                                            \
 * @file TLB.h                                                                 \
 * @brief Declaracion del Translation Lookaside Buffer (TLB) de VestaVM.       \
 *                                                                             \
 * Declara @c LazyHybridTLB: la traduccion de direcciones virtuales de la VM   \
 * a punteros del proceso anfitrion.  Es una TABLA PLANA con direccionamiento  \
 * abierto -- no un arbol por niveles, como fue hasta ahora --, y el porque    \
 * esta en la cabecera de la clase.  Incluye traduccion, insercion,            \
 * invalidacion y volcado.                                                     \
 */                                                                            \
#ifndef TLB_H
#define TLB_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <variant>
#include <memory_resource>
#if !defined(VESTA_GC_FREESTANDING)
#include <iomanip>
#include <sstream>
#endif

#include "arena/arena.h"

/**
 * @defgroup TLB_macros Descomposicion de una direccion virtual
 * @brief Los dos campos que tiene una direccion: pagina y desplazamiento.
 *
 *   Bits [11: 0]  OFFSET  desplazamiento dentro de la pagina
 *   Bits [63:12]  PAGINA  la pagina, que es lo que la TLB traduce
 *
 * Habia aqui tres macros mas -- `GET_PT`, `GET_PT1`, `GET_PT2` -- que partian
 * la pagina en tramos de 12, 16 y 24 bits para indexar los tres niveles de un
 * arbol.  Ese arbol ya no existe y con el se fueron los tramos: la tabla se
 * indexa con la pagina ENTERA, asi que ningun tramo tiene significado propio.
 * @{
 */
#define GET_OFFSET(address)                                                    \
    ((address) & 0xFFF) ///< Extrae los 12 bits de offset de pagina
#define GET_PAGE(address)                                                      \
    ((address) >> 12) ///< Extrae la pagina (bits 63-12)
/** @} */

namespace tlb {

/**
 * @brief Sobrecarga de operador de salida para vm_map_ptr.
 *
 * Escribe la direccion virtual en formato "0x<hex>" al flujo indicado.
 *
 * @param os  Flujo de salida destino.
 * @param ptr Puntero virtual a imprimir.
 * @return    Referencia al mismo flujo para encadenar operaciones.
 */
#if !defined(VESTA_GC_FREESTANDING)
inline std::ostream &operator<<(std::ostream &os, const vm::vm_map_ptr &ptr) {
    os << "0x" << std::hex << ptr.raw << std::dec;
    return os;
}
#endif

/**
 * @brief Dato almacenado en una hoja del arbol de traduccion (TLB).
 *
 * Cada entrada hoja del TLB mapea una pagina virtual a su destino real:
 * puede ser memoria del host (MAPPED_PTR_HOST), otra direccion virtual
 * local (MAPPED_PTR_VM) o una direccion en un nodo remoto (MAPPED_PTR_REMOTE).
 *
 * La estructura contiene ademas un metodo de diagnostico to_string() para
 * volcar el contenido en formato legible.
 */
typedef struct TLBEntryData {
    vm::type_ptr_mapped type_address =
        vm::NONE; ///< Tipo del destino mapeado (host/vm/remoto)
    vm::ptr_mapped address =
        {}; ///< Direccion destino (union de los tres tipos)

    /**
     * @brief Genera una representacion textual de la entrada para depuracion.
     *
     * Muestra el tipo (HOST / GUEST / REMOTE) seguido de la direccion
     * correspondiente en formato hexadecimal.
     *
     * @return Cadena descriptiva de la entrada.
     */
#if !defined(VESTA_GC_FREESTANDING)
    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;

        // mostrar etiqueta del tipo de mapeo
        switch (type_address) {
        case vm::MAPPED_PTR_HOST: oss << "HOST"; break;
        case vm::MAPPED_PTR_VM: oss << "GUEST"; break;
        case vm::MAPPED_PTR_REMOTE: oss << "REMOTE"; break;
        default: oss << "NONE(" << (int)type_address << ")";
        }

        oss << "{";

        // mostrar el valor de la direccion segun su tipo
        switch (type_address) {
        case vm::MAPPED_PTR_HOST:
            oss << "host=" << std::hex << address.ptr_host << std::dec;
            break;
        case vm::MAPPED_PTR_VM:
            oss << "guest=" << std::hex << address.ptr_vm << std::dec;
            break;
        case vm::MAPPED_PTR_REMOTE:
            oss << "remote{id=" << std::hex << address.ptr_remote
                << ", offset=" << address.ptr_remote << std::dec << "}";
            break;
        default: oss << "addr=" << std::hex << address.ptr_host << std::dec;
        }

        oss << "}";
        return oss.str();
    }
#endif
} TLBEntryData;

/* RETIRADO: `levelEntry`, que nombraba los niveles del arbol.  Ya no hay
 * niveles: la traduccion es una tabla plana indexada por la pagina entera. */

/* RETIRADO: `TLBEntry` y `TLBTable`, el arbol TLB *original*.
 *
 * Estaban marcados como "se mantiene por compatibilidad con codigo legado", y
 * no habia tal codigo: ni una sola referencia fuera de este fichero y su `.cpp`.
 * Lo unico que hacian era obligar a mantener vivo el enumerado de niveles y
 * dar la impresion de que habia dos implementaciones en uso. */

/* RETIRADO: `TLBNode`, el nodo del arbol de tres niveles.
 *
 * La traduccion ya no es un arbol indexado por tramos de bits sino una tabla
 * plana, asi que no hay nodos ni niveles.  El cambio no fue por gusto: el
 * arbol costaba SEIS accesos dependientes por consulta y reservaba hasta
 * 131.072 KB por una sola pagina en una direccion alta, porque el tramo de
 * arriba eran 24 bits y su vector crecia hasta el INDICE, no hasta el numero
 * de paginas.  Ver la cabecera de la clase.
 *
 * Vive en el historial de git. */

/**
 * @class LazyHybridTLB
 * @brief La traduccion de paginas: tabla plana, sondeo lineal, sin candados.
 *
 * QUE HABIA ANTES, Y POR QUE SE CAMBIO
 * ------------------------------------
 * Un arbol de tres niveles indexado por TRAMOS de la direccion: 12 bits para
 * el nivel de abajo, 16 para el de en medio y 24 para la raiz.  Tenia tres
 * problemas, y los tres estan medidos en `tests/arena/`:
 *
 *   - SEIS accesos dependientes por consulta.  Tres niveles, y cada uno
 *     costaba dos: la comprobacion de limite del vector y el salto a traves
 *     del puntero.  Medido: la consulta pasa de 0,518 ns a 2,339 en cuanto el
 *     bucle toca DOS paginas, porque la cache de pagina que hay delante solo
 *     guarda una.  Esos 1,8 ns se pagan en casi todo programa real.
 *   - La memoria dependia del VALOR de la direccion, no de cuantas paginas
 *     hubiera.  El vector de la raiz crecia hasta el INDICE, y con 24 bits eso
 *     son 131.072 KB reservados por UNA sola pagina en una direccion alta.
 *   - `translate` hacia `resize`, o sea que REALOJABA los vectores que
 *     `get_entry` estaba recorriendo.  Con un solo hilo daba igual; en cuanto
 *     un segundo hilo consulta, es una carrera de datos.
 *
 * COMO ES AHORA
 * -------------
 * Una tabla plana de `pagina -> traduccion`, con direccionamiento abierto y
 * sondeo lineal.  El indice sale de mezclar la pagina ENTERA (@ref mix), asi
 * que los 64 bits de direccion se cubren sin tramos y sin casos especiales:
 * una pagina en `0xFFFFFF...` cuesta exactamente lo mismo que una en `0x1000`.
 *
 * Una carga en el caso comun, y la memoria es proporcional a las paginas
 * VIVAS.
 *
 * POR QUE ES SEGURA PARA VARIOS LECTORES
 * --------------------------------------
 * La etiqueta de cada ranura se publica con `release` DESPUES de escribir la
 * traduccion, y se lee con `acquire`.  Y al crecer no se modifica la tabla en
 * curso: se construye una nueva y se publica el puntero; la vieja NO se libera
 * mientras viva la TLB.
 *
 * Un lector que se quedo con la tabla anterior sigue leyendo memoria valida.
 * Lo peor que le pasa es no encontrar una pagina anadida despues, y eso se
 * responde "no la tengo" -- lo mismo que una pagina sin mapear --.  Nunca
 * devuelve OTRA traduccion, que es lo que si seria un fallo.
 *
 * Escribir sigue siendo de UNO: `translate` y `clear_tlb_entry` las llama el
 * hilo duenyo del proceso.
 *
 * Uso tipico:
 *   1. translate()                  -- registrar la traduccion de una pagina.
 *   2. get_entry()                  -- consultar la traduccion de una
 * direccion.
 *   3. get_real_host_ptr_of_vptr()  -- obtener el puntero de host directamente.
 *   4. clear_tlb_entry()            -- invalidar una entrada (p.ej. tras
 * unmap).
 */
class LazyHybridTLB {
  public:
    /**
     * @brief Una ranura de la tabla: la etiqueta y su traduccion.
     *
     * La etiqueta se publica DESPUES de escribir la traduccion y con
     * `release`; quien lee la coge con `acquire` y para entonces la traduccion
     * ya esta entera.  Es lo unico que hace falta para que un segundo hilo
     * pueda consultar sin candados.
     *
     * Valores especiales de la etiqueta:
     *   0                 la ranura esta VACIA, y el sondeo se para ahi;
     *   kTombstone        estuvo ocupada y se invalido, el sondeo SIGUE.
     * Cualquier otro valor es `pagina + 1`, para que la pagina cero se pueda
     * representar sin confundirse con una ranura vacia.
     */
    struct Slot {
        std::atomic<uint64_t> tag{0};
        TLBEntryData entry;
    };

  private:
    /// Etiqueta de una ranura invalidada.  No puede chocar con ninguna pagina
    /// real: `pagina + 1` como mucho vale 2^52, y esto es 2^64 - 1.
    static constexpr uint64_t kTombstone = ~0ull;

    /**
     * @brief Una tabla, con su tamano y la anterior colgando.
     *
     * Las tablas viejas NO se liberan mientras vive la TLB, y esa es toda la
     * seguridad del diseno: un lector que cogio la tabla anterior sigue
     * leyendo memoria valida.  Lo peor que le puede pasar es no encontrar una
     * pagina que se anadio despues -- y eso se responde "no la tengo", que es
     * lo mismo que dice una pagina sin mapear --.  Nunca devuelve OTRA
     * traduccion, que es lo que si seria un fallo.
     *
     * Cuesta memoria: con crecimiento al doble, las tablas viejas suman como
     * mucho lo que ocupa la actual.  A cambio no hace falta ni un candado ni
     * saber cuando el ultimo lector termino.
     */
    struct Table {
        uint32_t mask = 0;      ///< tamano - 1, siempre potencia de dos
        uint32_t shift = 0;     ///< 64 - bits del indice, para @ref mix
        uint32_t used = 0;      ///< ocupadas, solo lo toca quien escribe
        Table *older = nullptr; ///< la anterior, viva para los rezagados
        Slot *slot = nullptr;   ///< `mask + 1` ranuras
    };

    std::atomic<Table *> table{nullptr};

    /// Ranuras de la primera tabla.  Pequena a proposito: un proceso que toca
    /// cuatro paginas no debe pagar por mil, y crecer es barato.
    static constexpr uint32_t kInitialSlots = 64;
    /// Se crece al pasar de la MITAD.  Con direccionamiento abierto y sondeo
    /// lineal, por encima de ahi el numero de sondeos se dispara.
    static constexpr uint32_t kMaxLoadNum = 1, kMaxLoadDen = 2;

    /**
     * @brief Mezcla la pagina para repartirla por la tabla.
     *
     * Hashing de FIBONACCI, que es el multiplicativo de Knuth: se multiplica
     * por `2^64 / razon_aurea` -- la misma constante que ya usan el recolector
     * y el perfilador -- y se toman los bits de ARRIBA.
     *
     * Por que los de arriba: al multiplicar, cada bit del resultado depende de
     * mas bits de la entrada cuanto mas alto esta, asi que los altos son los
     * que llevan la mezcla.  Y por que hace falta mezclar: las paginas
     * consecutivas solo se diferencian en los bits BAJOS, asi que usarlas tal
     * cual amontonaria un tramo recto en ranuras seguidas y los sondeos se
     * alargarian.  Con el paso aureo quedan repartidas.
     *
     * El desplazamiento viene DADO y no se calcula: `64 - bits_del_indice`
     * deja el valor ya en rango, asi que no hace falta enmascarar despues.
     * Guardarlo en la tabla cuesta cuatro bytes y quita una operacion de la
     * consulta, que corre en cada acceso a memoria de la VM.
     */
    static uint32_t mix(uint64_t page, uint32_t shift) {
        return (uint32_t)((page * 0x9E3779B97F4A7C15ull) >> shift);
    }

    /**
     * @brief Sigue el sondeo cuando la primera ranura no era la buena.
     *
     * FUERA DE LINEA a proposito, y no por tamano del codigo fuente sino por
     * lo que se midio: `get_entry` se inlina en `operator[]`, en `read_bytes`
     * y en el cursor del descodificador, o sea en el camino mas caliente del
     * interprete.  Con el bucle de sondeo dentro, esas tres crecieron y la
     * mezcla `memoria` perdio un 3,4% -- y eso que ahi la cache de pagina
     * acierta siempre y el sondeo no llega a ejecutarse ni una vez --.
     *
     * Asi que en linea se queda solo lo que casi siempre basta: una carga y
     * dos comparaciones.
     */
    [[gnu::noinline]] static TLBEntryData *probe(const Table *t, uint64_t page,
                                                 uint32_t i);

    /// Reserva una tabla de @p slots ranuras.  Fuera de linea: corre al crecer.
    static Table *make_table(uint32_t slots, Table *older);
    /// Duplica el tamano y REHACE las entradas vivas en la tabla nueva.
    void grow();
    /// Busca @p page para ESCRIBIR, creciendo si hace falta.  Solo el duenyo.
    Slot *slot_for_write(uint64_t page);

  public:
    /// Libera todas las tablas, incluida la cadena de las viejas.
    ~LazyHybridTLB();

    /**
     * @brief Bytes que ocupa ESTA estructura, contados por ella misma.
     *
     * Lo dice la TLB y no un contador de fuera porque es la unica que lo sabe
     * exactamente: las tablas que tiene vivas y las viejas que aun no ha
     * soltado.  Medirlo interceptando `operator new` seria contar OTRA cosa --
     * la memoria del anfitrion, que es de quien es ese asignador -- y ademas
     * mezclaria las reservas de todo lo demas que corra en el proceso.
     *
     * No incluye las paginas de la VM: eso es memoria del programa, la sirve
     * la arena, y confundirla con la del mapa es justo lo que hay que evitar.
     */
    /**
     * @brief Queda alguna tabla anterior por liberar?
     *
     * En linea y con una carga relajada porque quien lo pregunta lo hace en un
     * punto que se recorre a menudo, y la respuesta es que NO casi siempre: la
     * cadena solo existe entre que la tabla crece y el siguiente momento
     * tranquilo.
     */
    [[nodiscard]] bool has_older() const {
        const Table *t = table.load(std::memory_order_relaxed);
        return t != nullptr && t->older != nullptr;
    }

    /**
     * @brief Libera las tablas anteriores.
     *
     * SOLO puede llamarla quien pueda garantizar que ningun otro hilo esta
     * dentro de una consulta.  La tabla no sabe quien lee ni cuando -- eso es
     * politica del runtime --, asi que ofrece el mecanismo y la decision la
     * toma quien conoce a los lectores.
     *
     * POR QUE ASI Y NO CON EPOCAS NI CONTADORES.  Las tecnicas habituales para
     * liberar sin candados -- contar referencias, punteros de peligro, epocas
     * -- cobran una escritura al entrar y otra al salir de CADA consulta.  Una
     * consulta aqui es un nanosegundo, asi que costarian mas que lo que
     * protegen.  Cobrarlo por TRABAJO en vez de por consulta lo hace gratis:
     * el unico lector ajeno es el hilo ayudante, y tiene principio y final
     * naturales -- coger un encargo y terminarlo --.
     */
    void reclaim_older();

    [[nodiscard]] size_t memory_bytes() const {
        size_t total = 0;
        for (const Table *t = table.load(std::memory_order_acquire);
             t != nullptr; t = t->older)
            total += sizeof(Table) + (size_t)(t->mask + 1u) * sizeof(Slot);
        return total;
    }

    /**
     * @brief Registra o actualiza la traduccion de la pagina que contiene @p
     * ptr.
     *
     * Crea los nodos intermedios necesarios en los niveles PT2, PT1 y PT,
     * y almacena la entrada de datos en el nodo hoja correspondiente.
     *
     * @param ptr        Direccion virtual a mapear (se usa la pagina que la
     * contiene).
     * @param type       Tipo de destino (MAPPED_PTR_HOST, MAPPED_PTR_VM,
     * MAPPED_PTR_REMOTE).
     * @param ptr_mapped Union con la direccion real correspondiente al tipo.
     */
    void translate(uint64_t ptr, vm::type_ptr_mapped type,
                   vm::ptr_mapped ptr_mapped);

    /**
     * @brief Invalida la entrada TLB de la pagina indicada.
     *
     * Reemplaza la entrada por un mapeo a la direccion virtual cero,
     * marcandola como MAPPED_PTR_VM con valor 0.  La pagina quedara como
     * no mapeada hasta que se llame a translate() de nuevo.
     *
     * @param page_vaddr Direccion virtual dentro de la pagina a invalidar.
     */
    void clear_tlb_entry(uint64_t page_vaddr);

    /**
     * @brief Devuelve un puntero al dato de traduccion de la pagina indicada.
     *
     * Recorre el arbol PT2 -> PT1 -> PT buscando la hoja DATA.
     * Si cualquier nivel no existe devuelve nullptr (lazy miss).
     *
     * @param ptr Direccion virtual a consultar.
     * @return    Puntero al TLBEntryData de la pagina, o nullptr si no esta
     * mapeada.
     *
     * @note El puntero devuelto puede quedar invalidado si se llama a
     * translate() sobre la misma pagina (la reasignacion puede reubicar el
     * nodo).
     */
    /* Definida AQUI y no en el `.cpp`, a proposito.
     *
     * Es la funcion que se llama en CADA acceso a la memoria de la VM, y medida
     * con VTune sobre 68 bancos se lleva el 10,8% del tiempo del interprete
     * ella sola.  Pero el coste real es mayor: estando fuera de linea, tampoco
     * se inlinan las tres indexaciones de `unique_ptr` que hace (otro 11,0%
     * repartido en tres entradas de `std::vector<std::unique_ptr<TLBNode>>`) ni
     * `VirtualMemory::operator[]`, que SI esta en su cabecera y no se inlina
     * porque llama a esto.
     *
     * El cuerpo es tres indexaciones con comprobacion de rango y tres
     * desreferencias, sin bucles ni llamadas: cabe.
     *
     * Y va con `always_inline`, no solo en la cabecera.  Ponerla aqui deja al
     * compilador ELEGIR, y con veintitantas lineas y muchos llamantes elige que
     * no: quedaria igual que antes -- una llamada -- y ademas duplicada en cada
     * unidad de traduccion, que es lo peor de las dos opciones.
     *
     * @note El puntero devuelto puede quedar invalidado si se llama a
     * translate() sobre la misma pagina (la reasignacion puede reubicar el
     * nodo). */
/* Clang tambien lo entiende, con cualquier ABI, y hay que nombrarlo: con el de
 * MSVC no define `__GNUC__`, asi que sin esto se caia al `#else` y el camino
 * CALIENTE de la traduccion de direcciones perdia el inline forzado -- mas
 * lento, y sin que nada lo dijera. */
#if defined(__GNUC__) || defined(__clang__)
    [[nodiscard]] __attribute__((always_inline)) inline TLBEntryData *
    get_entry(uint64_t ptr_) const {
#else
    [[nodiscard]] TLBEntryData *get_entry(uint64_t ptr_) const {
#endif
        /* Una tabla plana con sondeo lineal: UNA carga en el caso comun.
         *
         * El arbol de tres niveles que habia aqui costaba seis accesos
         * dependientes -- tres comprobaciones de limite y tres saltos a traves
         * de vectores de punteros --, y medido eran 1,8 ns que se pagan en
         * cuanto el bucle toca dos paginas, porque la cache de pagina que hay
         * delante solo guarda UNA.
         *
         * Y ademas indexaba por tramos de bits, con el tramo alto de 24: una
         * pagina en una direccion alta reservaba 131.072 KB.  Aqui el coste no
         * depende del VALOR de la direccion sino de cuantas paginas hay vivas,
         * asi que los 64 bits se cubren enteros sin ningun caso especial. */
        const Table *t = table.load(std::memory_order_acquire);
        if (t == nullptr) return nullptr;

        const uint64_t page = ptr_ >> 12;
        const uint32_t i = mix(page, t->shift);
        const uint64_t tag = t->slot[i].tag.load(std::memory_order_acquire);
        /* `const_cast` justificado: quien llama puede necesitar ACTUALIZAR la
         * entrada, que es como se ha usado siempre. */
        if (tag == page + 1)
            return const_cast<TLBEntryData *>(&t->slot[i].entry);
        if (tag == 0) return nullptr; // hueco: no esta, y no hay que sondear
        return probe(t, page, i);     // colision: fuera de linea
    }

    /**
     * @brief Devuelve el puntero real del host para una direccion virtual.
     *
     * Combina get_entry() con el acceso al campo ptr_host de la union.
     * Solo funciona para entradas de tipo MAPPED_PTR_HOST.
     *
     * @param vptr_ Direccion virtual a resolver.
     * @return      Puntero del host correspondiente, o nullptr si la entrada no
     *              existe o no es de tipo MAPPED_PTR_HOST.
     */
    void *get_real_host_ptr_of_vptr(uint64_t vptr_) const;

    /**
     * @brief Vuelca en stdout la descomposicion de una direccion virtual y su
     * ruta TLB.
     *
     * Muestra PT2, PT1, PT y OFFSET de @p vpn_, la ruta de nodos que se
     * recorreria y el contenido de la hoja si existe.  Util para depuracion.
     *
     * @param vpn_ Direccion virtual a inspeccionar.
     */
    void dump_tree(uint64_t vpn_) const;

    /**
     * @brief Imprime estadisticas globales del arbol TLB en stdout.
     *
     * Contabiliza cuantos nodos PT2, PT1 y entradas DATA existen actualmente.
     * Util para evaluar el consumo de memoria del TLB en tiempo de ejecucion.
     */
    void dump_stats() const;

    /**
     * @brief Constructor: deja la primera tabla puesta.
     *
     * Se reserva ya y no en el primer `translate` para que la consulta no
     * tenga que preguntar si existe... salvo la comprobacion de null que si
     * queda, porque la reserva puede fallar y quedarse callado seria peor que
     * ir un poco mas lento.
     */
    LazyHybridTLB();
};

} // namespace tlb

#endif // TLB_H
