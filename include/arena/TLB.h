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
 * Declara @c LazyHybridTLB: cache de traduccion de direcciones virtuales      \
 * a punteros del proceso host, organizado en tres niveles.  Incluye           \
 * operaciones de traduccion, insercion, invalidacion y volcado.               \
 */                                                                            \
#ifndef TLB_H
#define TLB_H

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
 * @defgroup TLB_macros Macros de descomposicion de direccion virtual
 * @brief Extraen los distintos campos de una direccion virtual de 64 bits.
 *
 * La direccion virtual se descompone en cuatro campos:
 *
 *   Bits [11: 0]  OFFSET  12 bits  desplazamiento dentro de la pagina
 *   Bits [23:12]  PT      12 bits  indice en la tabla de paginas nivel 1
 *   Bits [39:24]  PT1     16 bits  indice en la tabla de paginas nivel 2
 *   Bits [63:40]  PT2     24 bits  indice en la tabla de paginas nivel 3 (raiz)
 * @{
 */
#define GET_OFFSET(address)                                                    \
    ((address) & 0xFFF) ///< Extrae los 12 bits de offset de pagina
#define GET_PT(address)                                                        \
    (((address) >> 12) & 0xFFF) ///< Extrae el indice de tabla de paginas (PT)
#define GET_PT1(address)                                                       \
    (((address) >> 24) & 0xFFFF) ///< Extrae el indice PT1 (bits 24-39)
#define GET_PT2(address)                                                       \
    (((address) >> 40) & 0xFFFFFF) ///< Extrae el indice PT2 raiz (bits 40-63)
/** @} */

namespace tlb {

struct TLBTable; // declaracion adelantada necesaria en TLBEntry

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

/**
 * @enum levelEntry
 * @brief Nivel de un nodo dentro del arbol de traduccion de direcciones.
 *
 *   DATA -- hoja: contiene un TLBEntryData con la traduccion final.
 *   PT   -- nivel 1: tabla de paginas (bits 23-12).
 *   PT1  -- nivel 2: tabla de paginas de segundo nivel (bits 39-24).
 *   PT2  -- nivel 3 raiz: tabla de paginas de tercer nivel (bits 63-40).
 */
typedef enum levelEntry { DATA, PT, PT1, PT2 } level;

/**
 * @brief Nodo del arbol TLB original (estructura plana con union).
 *
 * Cada entrada puede ser un nodo intermedio (is_table = true, payload.table)
 * o una hoja (is_table = false, payload.data).
 *
 * @note Esta estructura se mantiene por compatibilidad con codigo legado.
 *       El TLB activo usa TLBNode y LazyHybridTLB.
 */
typedef struct TLBEntry {
    levelEntry level; ///< Nivel del nodo en el arbol

    union {
        TLBEntryData data; ///< Datos de traduccion si es hoja (DATA)
        TLBTable *table;   ///< Puntero a tabla hija si es nodo intermedio
    } payload;

    bool is_table =
        false; ///< true si payload.table es valido; false si payload.data lo es

    /** @brief Construye una entrada hoja vacia. */
    TLBEntry() : level(DATA), payload({}) {}

    /**
     * @brief Libera la tabla hija si este nodo es un nodo intermedio.
     *
     * El destructor solo actua cuando is_table == true para evitar
     * liberar memoria union que no fue asignada como tabla.
     */
    ~TLBEntry() {
        if (is_table && payload.table) {
            delete payload.table; // liberar la tabla hija de forma recursiva
        }
    }
} TLBEntry;

/**
 * @brief Tabla de paginas plana (vector de TLBEntry).
 *
 * Cada nivel del arbol TLB original usa TLBTable como contenedor de
 * entradas hijas.  El constructor reserva una entrada inicial para que
 * el vector nunca este vacio tras la creacion.
 */
typedef struct TLBTable {
    std::vector<TLBEntry> entry; ///< Vector de entradas del nivel de pagina

    /** @brief Crea la tabla con una entrada vacia inicial. */
    TLBTable() : entry(1) {}
} TLBTable;

/**
 * @brief Nodo del arbol TLB lazy con propiedad unica sobre hijos.
 *
 * Implementacion moderna que usa unique_ptr para gestionar la memoria
 * de los hijos automaticamente.  Un nodo con children vacio o con
 * children[i] == nullptr es un nodo no inicializado (lazy allocation).
 *
 * type == DATA indica un nodo hoja cuya traduccion esta en el campo data.
 * type == PT/PT1/PT2 indica un nodo intermedio cuyos hijos son el siguiente
 * nivel.
 */
typedef struct TLBNode {
    levelEntry type = DATA; ///< Nivel de este nodo
    TLBEntryData data;      ///< Datos de traduccion (valido si type == DATA)
    std::vector<std::unique_ptr<TLBNode>>
        children; ///< Hijos de nivel inferior (nullptr = no inicializado)

    TLBNode() = default;  ///< Construye nodo DATA con hijos vacios
    ~TLBNode() = default; ///< Destruye recursivamente los hijos via unique_ptr
} TLBNode;

/**
 * @class LazyHybridTLB
 * @brief Translation Lookaside Buffer (TLB) perezoso de tres niveles.
 *
 * Implementa la traduccion de direcciones virtuales de 64 bits a
 * direcciones reales del host mediante un arbol de nodos creados
 * bajo demanda (lazy allocation).
 *
 * Jerarquia de niveles (de raiz a hoja):
 *   root (vector de TLBNode)
 *     -> PT2 (24 bits, hasta 16 M entradas)
 *       -> PT1 (16 bits, hasta 64 K entradas)
 *         -> PT  (12 bits, hasta 4 K entradas)
 *           -> DATA (TLBEntryData con la traduccion real)
 *
 * El arbol crece en amplitud solo cuando se accede a una pagina nueva,
 * manteniendo bajo el coste de memoria en espacios de direcciones dispersos.
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
    std::vector<std::unique_ptr<TLBNode>> root{
        1}; ///< Nivel raiz PT2; indice 0 inicializado en ctor

  public:
    ~LazyHybridTLB() =
        default; ///< Destructor; unique_ptr libera el arbol automaticamente

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
#if defined(__GNUC__)
    [[nodiscard]] __attribute__((always_inline)) inline TLBEntryData *
    get_entry(uint64_t ptr_) const {
#else
    [[nodiscard]] TLBEntryData *get_entry(uint64_t ptr_) const {
#endif
        const uint32_t pt2 = GET_PT2(ptr_); // indice PT2 de la direccion

        // verificar que el nodo PT2 existe
        if (pt2 >= root.size() || !root[pt2]) return nullptr;
        const TLBNode &pt2_node = *root[pt2];
        if (pt2_node.type != PT2) return nullptr; // corrupto o sin inicializar

        const uint16_t pt1 = GET_PT1(ptr_); // indice PT1 de la direccion

        // verificar que el nodo PT1 existe dentro del nodo PT2
        if (pt1 >= pt2_node.children.size() || !pt2_node.children[pt1])
            return nullptr;
        const TLBNode &pt1_node = *pt2_node.children[pt1];
        if (pt1_node.type != PT1) return nullptr; // corrupto o sin inicializar

        const uint16_t pt = GET_PT(ptr_); // indice PT de la direccion

        // verificar que el nodo hoja PT existe dentro del nodo PT1
        if (pt >= pt1_node.children.size() || !pt1_node.children[pt])
            return nullptr;
        const TLBNode &pt_node = *pt1_node.children[pt];
        if (pt_node.type != DATA) return nullptr; // no es hoja de datos

        // puntero mutable al dato de traduccion (const_cast justificado: quien
        // llama puede necesitar actualizar la entrada)
        return const_cast<TLBEntryData *>(&pt_node.data);
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
     * @brief Constructor: garantiza que el nodo raiz[0] este inicializado.
     *
     * El vector root se inicializa con tamanyo 1 pero el unique_ptr queda
     * a nullptr.  El constructor crea el primer TLBNode para evitar
     * comprobaciones extra en translate().
     */
    LazyHybridTLB() {
        if (!root[0])
            root[0] = std::make_unique<TLBNode>(); // nodo raiz PT2[0]
                                                   // preiniicializado
    }
};

} // namespace tlb

#endif // TLB_H
