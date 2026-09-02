/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (c) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */
#ifndef RAW_ALLOCATOR_H
#define RAW_ALLOCATOR_H

/**
 * @file raw_allocator.h
 * @brief Allocator manual por proceso para interoperabilidad nativa (FFI).
 *
 * @section rationale Fundamento de diseno
 *
 * VestaVM necesita dos regiones de memoria bien diferenciadas:
 *
 *   1. Memoria gestionada (gc_heap.h): objetos del lenguaje con ciclo de vida
 *      automatico, accedidos siempre a traves de handles opacos.
 *
 *   2. Memoria cruda (este archivo): bloques cuya direccion host real es
 *      visible y estable, necesarios para pasar punteros a funciones C
 *      via la instruccion CALLN (FFI).
 *
 * El RawAllocator cubre el caso 2: cada bloque retornado es un rango
 * contiguo de bytes en el espacio de direcciones del proceso host,
 * equivalente a lo que devuelve malloc(3) pero sin fragmentador intermedio.
 *
 * @section why_no_tlb Por que no se usa VirtualMemory ni TLB
 *
 * La capa VirtualMemory/TLB de VestaVM divide las reservas en paginas de
 * 4096 bytes y las mapea en rangos virtuales de la VM, no en el espacio
 * de direcciones del host.  Si un bloque de N bytes cruza un limite de
 * pagina, sus bytes fisicos pueden NO ser contiguos en la vista del host,
 * lo que provoca accesos invalidos cuando una API nativa espera un buffer
 * lineal (p. ej. WriteFile, SSL_write, memcpy desde C).
 *
 * vm::allocate_memory() llama directamente a VirtualAlloc (Windows) o
 * mmap (POSIX) con el tamano exacto solicitado, garantizando un rango
 * contiguo unico.  Por eso es la unica primitiva que usa este allocator.
 *
 * @section lifecycle Ciclo de vida de un bloque
 *
 * @code
 *   RawAllocator raw;
 *
 *   uint64_t buf = raw.alloc(1024);   // reserva 1 KiB; buf == puntero host
 * real void *p = reinterpret_cast<void *>(buf); std::memset(p, 0xAB, 1024); //
 * uso directo: sin wrappers
 *
 *   buf = raw.realloc(buf, 2048);     // crece a 2 KiB; buf puede cambiar
 *
 *   raw.free(buf);                    // libera; buf invalido a partir de aqui
 *   // destructor llama free_all() automaticamente
 * @endcode
 *
 * @section bytecode Instrucciones bytecode asociadas
 *
 *   ALLOC   <size>         -- Reserva <size> bytes; pone ptr en R0 (0 si
 * falla). FREE    <reg>          -- Libera el bloque cuyo ptr esta en <reg>.
 *   REALLOC <reg>, <size>  -- Redimensiona; pone nuevo ptr en R0.
 *
 * @section stats Estadisticas de rendimiento
 *
 * El campo stats_ (tipo RawStats) acumula contadores de uso sin ramas
 * adicionales ni atomics.  El allocator es per-proceso, por lo que no hay
 * carreras de datos.  Acceder via RawAllocator::stats().
 *
 * @section thread_safety Seguridad de hilos
 *
 * RawAllocator NO es hilo-seguro.  Cada ProcessVM tiene su propio
 * allocator; la sincronizacion externa la proporciona el planificador.
 */

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <unordered_map>
#include <vector>
#include <utility>

#include "arena/arena.h"

namespace gc {

// =========================================================================
// RawStats
// =========================================================================

/**
 * @brief Estadisticas acumuladas del RawAllocator.
 *
 * Todos los campos son uint64_t sin atomics: el allocator es per-proceso
 * y se actualiza desde un unico hilo de ejecucion VM.
 *
 * Los campos se leen via RawAllocator::stats() y son de solo lectura
 * para el consumidor.
 *
 * Campos de asignacion:
 *   - alloc_count   : numero total de llamadas exitosas a alloc().
 *   - alloc_bytes   : bytes totales asignados (suma de todos los alloc).
 *
 * Campos de liberacion:
 *   - free_count    : numero total de llamadas exitosas a free().
 *   - freed_bytes   : bytes totales liberados (suma de todos los free).
 *
 * Campos de reajuste:
 *   - realloc_count : numero de llamadas a realloc() (incluye caso
 * new_size==0).
 *
 * Pico de uso:
 *   - peak_bytes    : maximo de bytes vivos simultaneamente (high-water mark).
 *                     Util para dimensionar el presupuesto de memoria del
 * proceso.
 *
 * @note realloc() tambien incrementa alloc_count y free_count porque
 *       implementa alloc-nuevo + free-viejo internamente.
 */
struct RawStats {
    uint64_t alloc_count = 0;   ///< llamadas exitosas a alloc()
    uint64_t alloc_bytes = 0;   ///< bytes asignados acumulados
    uint64_t free_count = 0;    ///< llamadas exitosas a free()
    uint64_t freed_bytes = 0;   ///< bytes liberados acumulados
    uint64_t realloc_count = 0; ///< llamadas a realloc() ejecutadas
    uint64_t peak_bytes = 0;    ///< maximo bytes vivos en cualquier instante

    /* Los free RECHAZADOS, contados aparte de los buenos.  Un `free` que
     * devuelve `false` no rompe nada -- ese es el objetivo -- pero significa
     * que el programa tiene un error de gestion de memoria, y sin estas dos
     * cifras el aviso se lo queda quien llamo y nadie mas se entera. */
    uint64_t double_free_count = 0;  ///< frees de un bloque YA libre
    uint64_t invalid_free_count = 0; ///< frees de una direccion que no es el
                                     ///< principio de un slot
};

// =========================================================================
// RawAllocator
// =========================================================================

/**
 * @brief Allocator manual de memoria contigua para interoperabilidad nativa.
 *
 * Reserva bloques de bytes en el espacio de direcciones del host usando
 * vm::allocate_memory() / vm::free_memory().  Cada bloque esta en un rango
 * contiguo unico, directamente pasable a funciones C (FFI) sin conversion.
 *
 * @par Modelo de propiedad
 *
 * El RawAllocator es dueno de todos los bloques hasta que se liberen
 * explicitamente con free() o hasta que el destructor llame free_all().
 * No hay GC automatico: si el bytecode pierde la referencia al ptr sin
 * llamar a FREE, el bloque queda vivo hasta que el proceso termine.
 *
 * @par Garantia de contiguidad
 *
 * Para cualquier bloque de N bytes retornado por alloc(N):
 *   - bytes[0..N-1] son accesibles como un array C normal.
 *   - No hay huecos ni remapeos internos entre paginas.
 *   - El puntero es valido para pasar a memcpy, WriteFile, SSL_write, etc.
 *
 * @par Uso tipico desde el ejecutor de bytecode
 *
 * @code
 *   // ALLOC 256   -> R0
 *   uint64_t ptr = process->raw_alloc.alloc(256);
 *   process->registers.regs[0] = ptr;
 *
 *   // FREE R0
 *   uint64_t ptr = process->registers.regs[0].raw();
 *   process->raw_alloc.free(ptr);
 * @endcode
 *
 * @note No copiable ni movible.  Cada proceso crea su propia instancia.
 */
class RawAllocator {
  public:
    // ---------------------------------------------------------------------
    // Constructor / destructor
    // ---------------------------------------------------------------------

    /**
     * @brief Constructor por defecto.
     *
     * No reserva memoria en construccion; el allocator comienza vacio.
     */
    RawAllocator() = default;

    /**
     * @brief Destructor.
     *
     * Llama a free_all() para liberar cualquier bloque pendiente.
     * Es seguro destruir el allocator aunque queden bloques sin liberar;
     * no hay double-free porque el mapa se vacia en free_all().
     */
    ~RawAllocator() { free_all(); }

    RawAllocator(const RawAllocator &) = delete;            ///< No copiable
    RawAllocator &operator=(const RawAllocator &) = delete; ///< No asignable

    // ---------------------------------------------------------------------
    // API publica
    // ---------------------------------------------------------------------

    /**
     * @brief Reserva un bloque contiguo de `size` bytes con permisos
     * READ|WRITE.
     *
     * Llama a vm::allocate_memory(size, READ|WRITE) que invoca VirtualAlloc
     * o mmap con el tamano exacto.  El contenido se inicializa a cero.
     *
     * El valor de retorno es la direccion host real del bloque, codificada
     * como uint64_t para que la VM pueda almacenarla en un registro de 64 bits
     * y pasarla directamente a funciones nativas.
     *
     * @param size Numero de bytes a reservar.  Si es 0, retorna 0 sin error.
     * @return Puntero host real como uint64_t.  0 si la asignacion falla.
     *
     * @note Actualiza stats_.alloc_count, stats_.alloc_bytes y
     * stats_.peak_bytes.
     *
     * @warning El puntero retornado es valido solo mientras no se llame a
     *          free() o realloc() con ese mismo valor.  Guardar una copia
     *          y seguir usando el original tras free() es UB.
     */
    uint64_t alloc(size_t size);

    /**
     * @brief Libera el bloque cuya direccion host es `ptr`.
     *
     * Si `ptr` no fue asignado por este allocator (o ya fue liberado),
     * la funcion retorna false sin hacer nada: no hay double-free.
     *
     * @param ptr Puntero host como uint64_t (el mismo valor retornado por
     * alloc).
     * @return true si el bloque existia y se libero; false en caso contrario.
     *
     * @note Actualiza stats_.free_count y stats_.freed_bytes.
     */
    bool free(uint64_t ptr);

    /**
     * @brief Redimensiona el bloque en `ptr` a `new_size` bytes.
     *
     * Algoritmo:
     *   1. Reserva un nuevo bloque de new_size bytes.
     *   2. Copia min(old_size, new_size) bytes del bloque original.
     *   3. Si new_size > old_size, rellena el resto con ceros.
     *   4. Libera el bloque original.
     *
     * Casos especiales:
     *   - realloc(0, N)     : equivale a alloc(N).
     *   - realloc(ptr, 0)   : equivale a free(ptr); retorna 0.
     *   - new_ptr != ptr siempre (no hay reajuste in-place).
     *
     * El nuevo bloque conserva la garantia de contiguidad.
     *
     * @param ptr      Puntero host del bloque a redimensionar (puede ser 0).
     * @param new_size Nuevo tamano en bytes.
     * @return Nuevo puntero host como uint64_t.  0 si la asignacion falla.
     *
     * @note Incrementa stats_.realloc_count siempre, incluso en el caso
     *       free-por-realloc (new_size == 0).
     */
    uint64_t realloc(uint64_t ptr, size_t new_size);

    /**
     * @brief Libera todos los bloques activos.
     *
     * Itera el mapa interno y llama a vm::free_memory() por cada entrada.
     * Al finalizar, el allocator queda vacio (como recien construido).
     *
     * @note Llamado automaticamente por el destructor.
     * @note Actualiza stats_.free_count y stats_.freed_bytes por cada bloque.
     */
    void free_all();

    // ---------------------------------------------------------------------
    // Consultas
    // ---------------------------------------------------------------------

    /**
     * @brief Bytes totales actualmente vivos (suma de todos los bloques
     * activos).
     * @return Tamano acumulado en bytes.
     */
    size_t total_allocated() const { return total_bytes_; }

    /**
     * @brief Numero de bloques activos (aun no liberados).
     * @return Cuantos bloques hay vivos, sumando los DOS caminos: el
     *         catalogo y el slab.
     */
    size_t block_count() const {
        return allocations_.size() + slab_live_count_;
    }

    /**
     * @brief Referencia de solo lectura a las estadisticas acumuladas.
     *
     * Las estadisticas persisten entre llamadas y nunca se reinician
     * durante la vida del allocator.  Son acumulativas desde la
     * construccion hasta la destruccion del objeto.
     *
     * @return Referencia constante a RawStats.
     */
    const RawStats &stats() const { return stats_; }

    // ---------------------------------------------------------------------
    // Soporte para el inline-alloc del JIT ( D.7 perf, 2026-06-06).
    //
    // El JIT inline-a el fast-path del slab (pop del free list por size
    // class) sin CALL al runtime.  Necesita los offsets de los miembros
    // privados @c slab_free_list_ y @c total_bytes_ (offsetof sobre
    // miembros propios es legal aqui, dentro de la clase) y las constantes
    // del slab (SLAB_SIZES, slab_class_for).  El selector emite el pop +
    // zero-init + stat, con fallback CALL @c alloc cuando el free list de
    // esa clase esta vacio (grow).  Ver vreg_select.cpp::RAW_ALLOC.
    // ---------------------------------------------------------------------
    static size_t jit_slab_free_list_offset() noexcept {
        return offsetof(RawAllocator, slab_free_list_);
    }
    static size_t jit_total_bytes_offset() noexcept {
        return offsetof(RawAllocator, total_bytes_);
    }
    static constexpr size_t jit_slab_classes() noexcept { return SLAB_CLASSES; }
    static constexpr size_t jit_slab_size(size_t i) noexcept {
        return (i < SLAB_CLASSES) ? SLAB_SIZES[i] : 0;
    }
    static constexpr size_t jit_slab_class_for(size_t n) noexcept {
        return slab_class_for(n);
    }

  private:
    // ---------------------------------------------------------------------
    // Tipos internos
    // ---------------------------------------------------------------------

    /**
     * @brief Metadatos de un bloque asignado.
     *
     * Almacenado en el mapa interno indexado por el puntero host (uint64_t).
     * El campo host_ptr es redundante con la clave pero permite pasar el
     * puntero tipado a vm::free_memory() sin reinterpret_cast en el sitio.
     */
    struct AllocRecord {
        void *host_ptr; ///< puntero real del bloque (== clave del mapa)
        size_t size;    ///< tamano solicitado en bytes
    };

    // ---------------------------------------------------------------------
    // Estado interno
    // ---------------------------------------------------------------------

    /**
     * Mapa de bloques activos: puntero host (uint64_t) -> metadatos.
     *
     * Se usa unordered_map para busqueda O(1) en free() y realloc().
     * La clave es el uint64_t retornado por alloc() / realloc().
     */
    std::unordered_map<uint64_t, AllocRecord> allocations_;
    size_t total_bytes_ =
        0; ///< bytes vivos actualmente (los de los DOS caminos)

    /* Los bloques vivos del SLAB, que no estan en `allocations_`.
     *
     * El camino rapido no registra nada en el catalogo -- ese es justo su
     * ahorro --, asi que sin estas dos cifras el asignador no sabe cuantos
     * bloques tiene vivos: `block_count()` devolvia el tamano del catalogo, o
     * sea CERO para todo lo pequeno, y `free_all` no contaba lo que soltaba.
     *
     * Que la cuenta MIENTA es peor que no tenerla: la forma de ver una fuga es
     * mirar si los bloques vivos bajan, y un cero constante parece que todo se
     * libera siempre.  Cuestan un incremento en la misma linea de cache que
     * `total_bytes_`, que ya se toca ahi al lado. */
    size_t slab_live_count_ = 0; ///< slots del slab reservados ahora mismo
    size_t slab_live_bytes_ = 0; ///< y sus bytes

    RawStats stats_; ///< contadores de uso (ver RawStats)

    // ---------------------------------------------------------------------
    // Slab allocator (Sprint mem-loop-fix 2026-06-02)
    // ---------------------------------------------------------------------
    /// @brief Numero de size classes del slab.  Cubre 16, 32, 64, 128,
    /// 256, 512, 1024 bytes (potencias de 2).  Cualquier alloc <= 1024
    /// pasa por slab; > 1024 cae al path tradicional (VirtualAlloc).
    ///
    /// Bottleneck arreglado: bench mem_malloc_free (5M iter de
    /// malloc(96) + free) pasaba de 20s -> ~50-100ms al evitar
    /// 10M syscalls VirtualAlloc/VirtualFree.
    static constexpr size_t SLAB_CLASSES = 7;
    static constexpr size_t SLAB_SIZES[SLAB_CLASSES] = {
        16, 32, 64, 128, 256, 512, 1024,
    };
    /// @brief Tamano del chunk OS por slab class.  Cada chunk se
    /// trocea en N slots del tamano de la clase.  64 KB es el
    /// sweet spot: pocos chunks por clase, baja fragmentacion.
    static constexpr size_t SLAB_CHUNK_BYTES = 65536;

    /// @brief Encabezado del slot del slab.  Almacena el size_class
    /// del slot para que @c free pueda devolverlo al free list
    /// correcto sin lookup en el mapa.  Se aloca AL INICIO del slot
    /// (offset 0); el ptr devuelto al usuario apunta despues del header.
    struct SlabSlotHeader {
        uint8_t size_class_idx; ///< indice en SLAB_SIZES
        uint8_t pad[7];         ///< alinear a 8 bytes (header total = 8)
    };
    static_assert(sizeof(SlabSlotHeader) == 8,
                  "SlabSlotHeader debe ser 8 bytes para alinear payload");

    /// @brief Nodo del free list intrusivo (vive dentro del slot
    /// cuando esta libre).  Sobrescribe el payload del slot; en
    /// @c alloc se vuelve a usar como payload.  LIFO O(1).
    ///
    /// El segundo campo NO es parte de la lista: es la marca de "este slot
    /// esta libre", y es lo que permite que @c free reconozca un doble free.
    /// Vive DENTRO del slot a proposito, porque @c alloc zerifica el slot
    /// entero (@c memset) y con eso la marca se borra sola al reservarlo --
    /// sin tocar @c alloc, y sin tocar la copia que el JIT emite en linea, que
    /// hace ese mismo @c memset.
    struct SlabFreeNode {
        SlabFreeNode *next;
        uint64_t free_mark;
    };
    /* La clase mas pequena mide 16 bytes, justo lo que ocupa el nodo. */
    static_assert(sizeof(SlabFreeNode) <= 16,
                  "el nodo del free list tiene que caber en el slot mas "
                  "pequeno (SLAB_SIZES[0])");

    /// @brief Semilla de la marca de slot libre.
    ///
    /// La marca es @c SLAB_FREE_MARK^direccion, no una constante: asi un
    /// programa que casualmente guarde este valor en ese offset no hace que se
    /// rechace un @c free legitimo, y ademas la marca de un slot no vale para
    /// otro.
    static constexpr uint64_t SLAB_FREE_MARK = 0xF2EE'D0'12'34'56'78ULL;

    /// @brief Free list por size class.  Cabeza LIFO; @c free push,
    /// @c alloc pop.  Inicialmente nullptr; @c slab_grow_class
    /// aloca un chunk del SO + trocea + thread.
    SlabFreeNode *slab_free_list_[SLAB_CLASSES] = {nullptr};

    /**
     * @brief Bloques GRANDES ya liberados, guardados para volver a usarlos.
     *
     * El slab cubre lo pequeno; por encima de su tope, cada reserva pedia
     * memoria al sistema operativo y cada liberacion se la devolvia.  Un bucle
     * que pide y suelta un bloque grande -- que es lo que hace cualquier
     * programa que procesa por lotes -- pagaba dos llamadas al sistema y el
     * borrado de todo el bloque en CADA vuelta: medio millon de reservas de
     * 256 KB tardaban 35 segundos, contra 114 milisegundos del mismo programa
     * compilado, que usa el asignador escrito en el lenguaje y SI los recicla.
     *
     * Se guardan por tamano exacto, que es lo que hace util el reciclaje: el
     * patron real repite el mismo tamano una y otra vez.  Con un tope, porque
     * retener memoria sin limite cambia un problema por otro.
     */
    struct BloqueLibre {
        uint64_t host_ptr; ///< direccion del bloque.
        size_t size;       ///< su tamano exacto.
    };
    /// Bloques retenidos, los mas recientes al final (se reusa el ultimo).
    std::vector<BloqueLibre> grandes_libres_;
    /// Cuanta memoria se esta reteniendo sin usar.
    size_t grandes_libres_bytes_ = 0;
    /// Tope de lo retenido.  Pasado ese punto se devuelve al sistema: el
    /// reciclaje esta para ahorrar llamadas, no para acaparar.
    static constexpr size_t kGrandesLibresTope = 256u * 1024u * 1024u;
    /// Y un tope de cuantos, para que la busqueda siga siendo barata.
    static constexpr size_t kGrandesLibresMax = 64;

    /// @brief Metadata de un chunk del slab.  Sprint mem-perf
    /// (2026-06-02): eliminamos @c slab_payload_to_class_ (unordered_map
    /// costaba ~150-200 ns por insert/erase).  Ahora @c free localiza
    /// el chunk via binary search sobre @c slab_chunks_sorted_ y lee
    /// el class_idx de la entry del chunk.  Mantiene el vector
    /// ordenado por @c base para que el lookup sea O(log N_chunks).
    struct SlabChunkInfo {
        uint64_t base;     ///< chunk_base (host_ptr cast a u64)
        uint64_t end;      ///< chunk_base + chunk_size (exclusivo)
        uint8_t class_idx; ///< indice en SLAB_SIZES
        uint8_t _pad[7];   ///< alinear a 24 bytes para cache locality
    };
    static_assert(sizeof(SlabChunkInfo) == 24,
                  "SlabChunkInfo debe ser 24 bytes para cache locality");

    /// @brief Vector de chunks del slab, SIEMPRE ORDENADO por
    /// @c base ascendente.  @c slab_grow_class añade y reordena
    /// (inserts son raros: ~1 por cada 500+ allocs del mismo class).
    /// @c free hace binary search para encontrar el chunk que
    /// contiene un ptr dado.
    std::vector<SlabChunkInfo> slab_chunks_sorted_;

    /**
     * @brief El chunk del slab que contiene @p ptr, o nullptr si no es del
     *        slab.
     *
     * Busqueda binaria sobre @c slab_chunks_sorted_ (O(log N)).  Es la unica
     * forma de saber si una direccion salio del camino rapido, porque ese
     * camino NO registra nada en @c allocations_ -- y por eso todo el que
     * reciba un puntero del usuario tiene que preguntar aqui primero.
     *
     * Lo tenia solo @c free, escrito dentro.  @c realloc no preguntaba, no
     * encontraba el puntero en el catalogo y lo trataba como ajeno: reservaba
     * uno nuevo, SIN copiar los datos y SIN soltar el viejo.
     *
     * @param ptr Direccion a localizar.
     * @return El chunk que la contiene, o nullptr.
     */
    const SlabChunkInfo *slab_chunk_for(uint64_t ptr) const noexcept {
        if (slab_chunks_sorted_.empty() || ptr == 0) return nullptr;
        // upper_bound: primer chunk con base > ptr.  El candidato es el
        // anterior (si existe), que tiene base <= ptr.
        auto it = std::upper_bound(
            slab_chunks_sorted_.begin(), slab_chunks_sorted_.end(), ptr,
            [](uint64_t p, const SlabChunkInfo &c) { return p < c.base; });
        if (it == slab_chunks_sorted_.begin()) return nullptr;
        --it;
        return (ptr >= it->base && ptr < it->end) ? &*it : nullptr;
    }

    /// @brief Cache del env var @c VESTA_NO_SLAB para evitar
    /// @c getenv en el hot path del alloc.  Valor:
    ///   0 = no leido aun (lazy init en primera llamada)
    ///   1 = slab habilitado (default)
    ///   2 = slab deshabilitado (env var seteada)
    mutable uint8_t slab_env_cache_ = 0;

    // ---------------------------------------------------------------------
    // Helpers del slab (privados)
    // ---------------------------------------------------------------------
    /// @brief Encuentra el indice de size class apropiado para @p size.
    /// @return indice valido o SIZE_MAX si size > SLAB_SIZES[ultimo].
    static constexpr size_t slab_class_for(size_t size) noexcept {
        for (size_t i = 0; i < SLAB_CLASSES; ++i) {
            if (size <= SLAB_SIZES[i]) return i;
        }
        return SIZE_MAX;
    }
    /// @brief Aloca un chunk OS + trocea + push al free list.
    bool slab_grow_class(size_t class_idx);
    /// @brief Libera todos los chunks del slab.  Llamado por @c free_all.
    void slab_free_all();
};

} // namespace gc

#endif // RAW_ALLOCATOR_H
