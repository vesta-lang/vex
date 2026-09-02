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

/**
 * @file gc_heap.h
 * @brief Heap generacional de recoleccion de basura por proceso.
 *
 * @section architecture Arquitectura del GcHeap
 *
 * El GcHeap implementa un recolector de basura generacional de dos generaciones
 * (Young/Old) con los siguientes componentes:
 *
 *   Nursery (Young generation)
 *   --------------------------
 *   Bloque contiguo de memoria host asignado via ArenaManager al construir el
 *   heap. La asignacion usa un bump-pointer (puntero de avance lineal), lo que
 *   la hace O(1) y cache-friendly. Cuando el bump-pointer alcanza el limite del
 *   bloque se dispara el minor GC.
 *
 *   OldGen (Old generation)
 *   -----------------------
 *   Conjunto de bloques asignados dinamicamente via ArenaManager conforme se
 *   necesitan. Cada bloque es un array lineal de objetos precedidos por
 * GcHeader. La asignacion usa first-fit: primero busca slots DEAD
 * reutilizables; si no hay, avanza al final del ultimo bloque (bump); si
 * tampoco hay espacio pide un bloque nuevo al ArenaManager.
 *
 *   HandleTable
 *   -----------
 *   Vector de HandleEntry que mapea un GcHandle (uint32_t opaco) a la direccion
 *   host actual del objeto. Permite que el GC mueva objetos durante la
 * evacuacion sin invalidar ninguna referencia en registros o stack del
 * bytecode, ya que todo el bytecode usa handles, nunca punteros directos. Slots
 * libres se reciclan via free_handles_ (freelist LIFO).
 *
 *   RememberedSet
 *   -------------
 *   Vector de GcHandle de objetos OLD que contienen referencias a objetos
 * YOUNG. Necesario para que el minor GC sea completo sin escanear OldGen
 * entero. El programador (o el compilador del lenguaje Vesta) debe llamar a
 *   write_barrier() cada vez que escribe una referencia old->young.
 *
 * @section lifecycle Ciclo de vida de un objeto
 *
 * @code
 *   1. NEWOBJ  --> alloc() --> objeto en Nursery, color=WHITE, gen=YOUNG,
 * handle H.
 *   2. [uso]   --> deref(H) devuelve puntero al payload.
 *   3. [muerte]--> drop(H)  --> handle liberado; objeto permanece fisicamente
 *                               en Nursery/OldGen hasta el proximo GC.
 *   4. minor_gc()
 *        - Evacua objetos YOUNG con handle vivo --> OldGen, color=BLACK.
 *        - Objetos YOUNG sin handle (soltados) simplemente se abandonan;
 *          el nursery_bump_ se resetea, reclamando todo el espacio de golpe.
 *   5. major_gc()
 *        - PRE-MARK: todos los objetos OldGen no-DEAD --> WHITE.
 *        - MARK:     handles vivos en OldGen --> BLACK.
 *        - SWEEP:    WHITE --> DEAD (slot reutilizable, old_used_
 * decrementado).
 * @endcode
 *
 * @section tri_color Algoritmo tri-color
 *
 *   WHITE  -- no visitado; candidato a recolectar si sigue WHITE tras MARK.
 *   GREY   -- alcanzable pero referencias pendientes de procesar (reservado).
 *   BLACK  -- alcanzable y completamente procesado; sobrevive este ciclo.
 *   DEAD   -- liberado por sweep; slot fisico disponible para reutilizacion.
 *             El campo GcHeader::size se preserva para que el scanner pueda
 *             avanzar correctamente y alloc_in_old pueda calcular el tamano.
 *
 * @section stats Estadisticas sin overhead
 *
 * Todos los contadores de GcStats son plain uint64_t (sin atomics ni ramas
 * adicionales). Cada evento incrementa exactamente un campo, y el CPU ya tiene
 * el objeto GcHeap en L1 cache durante la asignacion. El costo adicional es
 * de una instruccion ADD por evento en el hot-path.
 *
 * @section thread_safety Seguridad de hilos
 *
 * GcHeap NO es thread-safe. Esta disenado para uso exclusivo del proceso
 * propietario (un ProcessVM). Si el scheduler migra el proceso a otro hilo
 * debe garantizar exclusion mutua antes de llamar a cualquier metodo del heap.
 */

#ifndef GC_HEAP_H
#define GC_HEAP_H

#include <cstdint>
#include <cstddef>
#include <cstdlib> // std::realloc/free/abort (HandleTable)
#include <utility> // std::move (HandleTable)
#include <vector>
#if !defined(VESTA_GC_FREESTANDING)
#include <unordered_map> // solo monitor_waiters_ (gateado, no-freestanding)
#endif

#include "arena/VirtualMemory.h"
#include "arena/arena_manager.h"
#include "gc/wait_table.h" // WaitTable (lock-free per-bucket)

// forward decl para no incluir el header completo (incluiria
// gc_heap.h indirectamente).  El puntero al owner se usa en major_gc para
// invocar scan_stack_roots con el rsp/stack_high/regs del proceso.
namespace runtime {
class ProcessVM;
}

namespace gc {
/**
 * @brief Handle opaco para referenciar objetos gestionados por el GcHeap.
 *
 * El bytecode de Vesta usa GcHandle en lugar de punteros directos. Esto
 * desacopla las referencias del proceso de la ubicacion fisica del objeto,
 * permitiendo que el GC mueva objetos (compactacion/evacuacion) sin
 * invalidar ningun registro de la VM.
 *
 * Un GcHandle es simplemente un indice en la HandleTable interna del heap.
 * El valor GC_NULL_HANDLE (UINT32_MAX) representa una referencia nula.
 *
 * @note Un GcHandle no es un puntero. Nunca hacer reinterpret_cast sobre el.
 */
using GcHandle = uint32_t;

/** @brief Valor centinela que representa un handle nulo o invalido. */
static constexpr GcHandle GC_NULL_HANDLE = UINT32_MAX;

/**
 * @class PtrHandleMap
 * @brief Hash table flat open-addressing optimizada para
 *        @c uint8_t* -> @c GcHandle.
 *
 * Reemplaza @c std::unordered_map<const uint8_t*, GcHandle> para el
 * hot path del GC: inserts en @c new_handle, erases en
 * @c release_handle / minor_gc sweep, finds en @c scan_stack_roots.
 * std::unordered_map usa node-based allocation (1 malloc por insert
 * ~10-15 ns).  Esta variante usa un solo @c std::vector<Entry>
 * contiguo (cache-friendly + cero allocs por insert despues del
 * grow inicial).
 *
 * = Algoritmo =
 * - Buckets potencia de 2 (mask = capacity - 1).
 * - Hash: @c (ptr >> 3) (los punteros host son 8-aligned).
 * - Linear probing.
 * - Tombstones para erase (key == reinterpret_cast<uint8_t*>(1)).
 * - Resize a 2x cuando load > 0.5.
 *
 * Coste medio por operacion: ~5 ns vs ~20-30 ns de @c unordered_map.
 */
class PtrHandleMap {
  public:
    struct Entry {
        const uint8_t *key;
        GcHandle value;
    };

    PtrHandleMap();
    ~PtrHandleMap() = default;

    /** @brief Inserta o sobreescribe.  Retorna true si era nuevo. */
    bool insert_or_assign(const uint8_t *key, GcHandle h);

    /** @brief Busca el handle.  Retorna @c GC_NULL_HANDLE si no existe. */
    GcHandle find(const uint8_t *key) const noexcept;

    /** @brief Elimina la entrada.  Retorna true si existia. */
    bool erase(const uint8_t *key);

    /** @brief Tamano actual (numero de entradas vivas). */
    size_t size() const noexcept { return live_count_; }

    /** @brief True si vacio. */
    bool empty() const noexcept { return live_count_ == 0; }

    /** @brief Limpia todas las entradas (mantiene la capacidad). */
    void clear();

    /** @brief Reserva capacidad para al menos @p n entries. */
    void reserve(size_t n);

  private:
    /// Sentinelas en el campo @c key.
    static constexpr const uint8_t *EMPTY = nullptr;
    static constexpr uintptr_t TOMB_RAW = 1;

    static inline const uint8_t *tombstone() {
        return reinterpret_cast<const uint8_t *>(TOMB_RAW);
    }
    static inline bool is_empty(const uint8_t *k) { return k == EMPTY; }
    static inline bool is_tomb(const uint8_t *k) {
        return reinterpret_cast<uintptr_t>(k) == TOMB_RAW;
    }
    static inline bool is_live(const uint8_t *k) {
        return !is_empty(k) && !is_tomb(k);
    }
    static inline size_t hash_ptr(const uint8_t *k) noexcept {
        const uintptr_t p = reinterpret_cast<uintptr_t>(k);
        /* Pointers son 8-aligned -> shift 3 bits removes redundancia. */
        return static_cast<size_t>(p >> 3);
    }

    void grow();

    std::vector<Entry> table_; ///< buckets (capacity = potencia de 2)
    size_t mask_ = 0;          ///< capacity - 1
    size_t live_count_ = 0;    ///< entradas vivas (no tombstones)
    size_t used_ = 0;          ///< slots ocupados (live + tombstones)
    size_t grow_at_ = 0;       ///< trigger grow cuando used > grow_at_
};

/**
 * @class GcHandleRefMap
 * @brief Mapa open-addressing GcHandle -> uint32 (refcount), cache-friendly.
 *
 * Reemplaza @c std::unordered_map<GcHandle, uint32_t> para @c external_refs_:
 * (a) elimina la dependencia de @c std::__detail::_Prime_rehash_policy de
 * libstdc++ (clave para el build FREESTANDING de libvesta_gc, que se enlaza con
 * NUESTRO linker sin g++); (b) es MAS rapido que @c std::unordered_map (sin
 * malloc por nodo, linear probing en un array contiguo).  Universal: mismo tipo
 * en el build de la VM (interp/JIT) y en el AOT -> sin perdida de rendimiento,
 * ganancia en ambos.
 *
 * Sentinelas en la clave (handles validos son < tamano de la HandleTable, muy
 * por debajo de estos): @c EMPTY = 0xFFFFFFFF (== GC_NULL_HANDLE), @c TOMB =
 * 0xFFFFFFFE.  API minima usada por el GC: find (-> uint32* o nullptr),
 * operator[] (insert-or-get), erase, size, e iteracion (kv.first/kv.second).
 */
class GcHandleRefMap {
  public:
    struct Slot {
        GcHandle first = 0xFFFFFFFFu; ///< clave (EMPTY por defecto)
        uint32_t second = 0;          ///< refcount
    };

    GcHandleRefMap() { rehash_to(8); }

    /// Puntero al refcount de @p h, o nullptr si no esta.
    uint32_t *find(GcHandle h) noexcept {
        size_t i = hash(h) & mask_;
        for (;;) {
            Slot &s = table_[i];
            if (s.first == EMPTY) return nullptr;
            if (s.first == h) return &s.second;
            i = (i + 1) & mask_;
        }
    }
    const uint32_t *find(GcHandle h) const noexcept {
        return const_cast<GcHandleRefMap *>(this)->find(h);
    }

    /// Refcount de @p h, insertando una entrada con 0 si no existe.
    uint32_t &operator[](GcHandle h) {
        if (used_ + 1 > grow_at_) grow();
        size_t i = hash(h) & mask_;
        size_t first_tomb = SIZE_MAX;
        for (;;) {
            Slot &s = table_[i];
            if (s.first == EMPTY) {
                const size_t at = (first_tomb != SIZE_MAX) ? first_tomb : i;
                if (table_[at].first != TOMB)
                    ++used_; // EMPTY -> ocupa slot nuevo
                table_[at].first = h;
                table_[at].second = 0;
                ++live_count_;
                return table_[at].second;
            }
            if (s.first == TOMB) {
                if (first_tomb == SIZE_MAX) first_tomb = i;
            } else if (s.first == h) {
                return s.second;
            }
            i = (i + 1) & mask_;
        }
    }

    /// Elimina la entrada de @p h (no-op si no esta).
    void erase(GcHandle h) noexcept {
        size_t i = hash(h) & mask_;
        for (;;) {
            Slot &s = table_[i];
            if (s.first == EMPTY) return;
            if (s.first == h) {
                s.first = TOMB; // mantiene la cadena de probing
                --live_count_;
                return;
            }
            i = (i + 1) & mask_;
        }
    }

    size_t size() const noexcept { return live_count_; }
    bool empty() const noexcept { return live_count_ == 0; }

    /// Iterador const que salta EMPTY/TOMB (yields Slot con first/second).
    struct const_iterator {
        const Slot *p;
        const Slot *e;
        void skip() noexcept {
            while (p != e && (p->first == EMPTY || p->first == TOMB))
                ++p;
        }
        const Slot &operator*() const noexcept { return *p; }
        const Slot *operator->() const noexcept { return p; }
        const_iterator &operator++() noexcept {
            ++p;
            skip();
            return *this;
        }
        bool operator!=(const const_iterator &o) const noexcept {
            return p != o.p;
        }
    };
    const_iterator begin() const noexcept {
        const_iterator it{table_.data(), table_.data() + table_.size()};
        it.skip();
        return it;
    }
    const_iterator end() const noexcept {
        return {table_.data() + table_.size(), table_.data() + table_.size()};
    }

  private:
    static constexpr GcHandle EMPTY = 0xFFFFFFFFu; ///< == GC_NULL_HANDLE
    static constexpr GcHandle TOMB = 0xFFFFFFFEu;

    static inline size_t hash(GcHandle h) noexcept {
        // Fibonacci hashing (mezcla rapida de un uint32).
        uint64_t x = static_cast<uint64_t>(h) * 0x9E3779B97F4A7C15ull;
        return static_cast<size_t>(x >> 32);
    }

    void rehash_to(size_t cap) {
        table_.assign(cap, Slot{});
        mask_ = cap - 1;
        grow_at_ = (cap * 3) / 4; // factor de carga 0.75
        used_ = 0;
        live_count_ = 0;
    }

    void grow() {
        std::vector<Slot> old = std::move(table_);
        rehash_to((mask_ + 1) * 2);
        for (const Slot &s : old)
            if (s.first != EMPTY && s.first != TOMB)
                (*this)[s.first] = s.second;
    }

    std::vector<Slot> table_;
    size_t mask_ = 0;
    size_t live_count_ = 0;
    size_t used_ = 0; ///< slots ocupados (live + tombstones)
    size_t grow_at_ = 0;
};

/**
 * @class GcHandleSet
 * @brief Conjunto open-addressing de GcHandle (reemplaza @c std::unordered_set
 *        <GcHandle> para @c remembered_set_).
 *
 * Mismas razones que @c GcHandleRefMap: cache-friendly + sin la dep libstdc++
 * @c _Prime_rehash_policy (freestanding) + mas rapido (universal VM/AOT).
 */
class GcHandleSet {
  public:
    GcHandleSet() { rehash_to(8); }

    void insert(GcHandle h) {
        if (used_ + 1 > grow_at_) grow();
        size_t i = hash(h) & mask_;
        size_t first_tomb = SIZE_MAX;
        for (;;) {
            GcHandle &k = table_[i];
            if (k == EMPTY) {
                const size_t at = (first_tomb != SIZE_MAX) ? first_tomb : i;
                if (table_[at] != TOMB) ++used_;
                table_[at] = h;
                ++live_count_;
                return;
            }
            if (k == TOMB) {
                if (first_tomb == SIZE_MAX) first_tomb = i;
            } else if (k == h) {
                return; // ya esta
            }
            i = (i + 1) & mask_;
        }
    }
    void clear() { rehash_to(8); }
    size_t size() const noexcept { return live_count_; }
    bool empty() const noexcept { return live_count_ == 0; }

    struct const_iterator {
        const GcHandle *p;
        const GcHandle *e;
        void skip() noexcept {
            while (p != e && (*p == EMPTY || *p == TOMB))
                ++p;
        }
        GcHandle operator*() const noexcept { return *p; }
        const_iterator &operator++() noexcept {
            ++p;
            skip();
            return *this;
        }
        bool operator!=(const const_iterator &o) const noexcept {
            return p != o.p;
        }
    };
    const_iterator begin() const noexcept {
        const_iterator it{table_.data(), table_.data() + table_.size()};
        it.skip();
        return it;
    }
    const_iterator end() const noexcept {
        return {table_.data() + table_.size(), table_.data() + table_.size()};
    }

  private:
    static constexpr GcHandle EMPTY = 0xFFFFFFFFu;
    static constexpr GcHandle TOMB = 0xFFFFFFFEu;
    static inline size_t hash(GcHandle h) noexcept {
        uint64_t x = static_cast<uint64_t>(h) * 0x9E3779B97F4A7C15ull;
        return static_cast<size_t>(x >> 32);
    }
    void rehash_to(size_t cap) {
        table_.assign(cap, EMPTY);
        mask_ = cap - 1;
        grow_at_ = (cap * 3) / 4;
        used_ = 0;
        live_count_ = 0;
    }
    void grow() {
        std::vector<GcHandle> old = std::move(table_);
        rehash_to((mask_ + 1) * 2);
        for (GcHandle h : old)
            if (h != EMPTY && h != TOMB) insert(h);
    }
    std::vector<GcHandle> table_;
    size_t mask_ = 0, live_count_ = 0, used_ = 0, grow_at_ = 0;
};

/**
 * @class PtrPtrMap
 * @brief Mapa open-addressing const uint8_t* -> const uint8_t* (reemplaza
 *        @c std::unordered_map<const uint8_t*, const uint8_t*> para
 *        @c forward_table_).  Mismas razones: cache-friendly + freestanding +
 *        mas rapido (universal VM/AOT).
 */
class PtrPtrMap {
  public:
    PtrPtrMap() { rehash_to(8); }

    /// Puntero al valor de @p k, o nullptr si no esta.
    const uint8_t *const *find(const uint8_t *k) const noexcept {
        size_t i = hash(k) & mask_;
        for (;;) {
            const Slot &s = table_[i];
            if (s.key == nullptr) return nullptr; // EMPTY
            if (s.key == k) return &s.val;
            i = (i + 1) & mask_;
        }
    }

    /// Valor de @p k, insertando con nullptr si no existe.
    const uint8_t *&operator[](const uint8_t *k) {
        if (used_ + 1 > grow_at_) grow();
        const uint8_t *const TOMB = tomb();
        size_t i = hash(k) & mask_;
        size_t first_tomb = SIZE_MAX;
        for (;;) {
            Slot &s = table_[i];
            if (s.key == nullptr) {
                const size_t at = (first_tomb != SIZE_MAX) ? first_tomb : i;
                if (table_[at].key != TOMB) ++used_;
                table_[at].key = k;
                table_[at].val = nullptr;
                ++live_count_;
                return table_[at].val;
            }
            if (s.key == TOMB) {
                if (first_tomb == SIZE_MAX) first_tomb = i;
            } else if (s.key == k) {
                return s.val;
            }
            i = (i + 1) & mask_;
        }
    }

    bool empty() const noexcept { return live_count_ == 0; }
    void clear() { rehash_to(8); }

  private:
    struct Slot {
        const uint8_t *key = nullptr; // EMPTY
        const uint8_t *val = nullptr;
    };
    static inline const uint8_t *tomb() noexcept {
        return reinterpret_cast<const uint8_t *>(1);
    }
    static inline size_t hash(const uint8_t *k) noexcept {
        uint64_t x = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(k) >> 3);
        x *= 0x9E3779B97F4A7C15ull;
        return static_cast<size_t>(x >> 32);
    }
    void rehash_to(size_t cap) {
        table_.assign(cap, Slot{});
        mask_ = cap - 1;
        grow_at_ = (cap * 3) / 4;
        used_ = 0;
        live_count_ = 0;
    }
    void grow() {
        std::vector<Slot> old = std::move(table_);
        rehash_to((mask_ + 1) * 2);
        const uint8_t *const TOMB = tomb();
        for (const Slot &s : old)
            if (s.key != nullptr && s.key != TOMB) (*this)[s.key] = s.val;
    }
    std::vector<Slot> table_;
    size_t mask_ = 0, live_count_ = 0, used_ = 0, grow_at_ = 0;
};

/**
 * @class U64U64Map
 * @brief Mapa open-addressing @c uint64_t -> @c uint64_t (reemplaza el antiguo
 *        @c std::vector<std::pair<uint64_t,uint64_t>> con busqueda LINEAL de la
 *        side-table de finalizadores @c CLASS_DTOR).
 *
 * Motivacion: register/unregister/stage sobre la side-table eran O(n) -> con
 * muchos @c gc<Clase> con @c ~Clase() el coste agregado era O(n^2).  Aqui el
 * lookup/insercion/borrado es O(1) amortizado.
 *
 * Diseno (mismo estilo que @c GcHandleSet / @c PtrPtrMap del mismo header,
 * freestanding-safe -- el libvesta_gc AOT lo compila igual que la VM):
 *   - Clave = puntero @c uint64_t (host_ptr del payload).
 *   - Hash multiplicativo de Fibonacci (@c splitmix / golden-ratio 64-bit), NO
 *     FNV (FNV es para secuencias de bytes; aqui la clave es un entero ya
 *     "denso" y la mezcla multiplicativa dispersa mejor los bits bajos del
 *     puntero, que suelen estar alineados a 8/16).
 *   - Linear probing (cache-friendly).
 *   - Tombstones para el borrado (@c erase / @c take) sin romper cadenas de
 *     probe.
 *   - Factor de carga <= 0.75 (crece con rehash al superarlo); capacidad
 *     siempre potencia de 2 (mask = cap-1).
 *
 * Las claves 0 y 1 estan reservadas como centinelas @c EMPTY / @c TOMB; un
 * host_ptr real jamas es 0 ni 1, asi que no colisionan con datos validos.
 */
class U64U64Map {
  public:
    U64U64Map() { rehash_to(8); }

    /// Inserta o sobrescribe: @p key -> @p val.
    void set(uint64_t key, uint64_t val) {
        if (used_ + 1 > grow_at_) grow();
        size_t i = hash(key) & mask_;
        size_t first_tomb = SIZE_MAX;
        for (;;) {
            Slot &s = table_[i];
            if (s.key == EMPTY) {
                const size_t at = (first_tomb != SIZE_MAX) ? first_tomb : i;
                if (table_[at].key != TOMB) ++used_;
                table_[at].key = key;
                table_[at].val = val;
                ++live_count_;
                return;
            }
            if (s.key == TOMB) {
                if (first_tomb == SIZE_MAX) first_tomb = i;
            } else if (s.key == key) {
                s.val = val; // sobrescribe (re-registro del mismo host_ptr)
                return;
            }
            i = (i + 1) & mask_;
        }
    }

    /// Borra la entrada @p key si existe (deja un tombstone).
    void erase(uint64_t key) {
        size_t i = hash(key) & mask_;
        for (;;) {
            Slot &s = table_[i];
            if (s.key == EMPTY) return; // no esta
            if (s.key == key) {
                s.key = TOMB;
                s.val = 0;
                --live_count_;
                return;
            }
            i = (i + 1) & mask_;
        }
    }

    /// Busca @p key: si esta, escribe el valor en @p out, borra la entrada y
    /// devuelve true; si no, devuelve false y no toca @p out.  Combina lookup +
    /// borrado en una sola pasada (usado por el stage del finalizador).
    bool take(uint64_t key, uint64_t &out) {
        size_t i = hash(key) & mask_;
        for (;;) {
            Slot &s = table_[i];
            if (s.key == EMPTY) return false; // no esta
            if (s.key == key) {
                out = s.val;
                s.key = TOMB;
                s.val = 0;
                --live_count_;
                return true;
            }
            i = (i + 1) & mask_;
        }
    }

    bool empty() const noexcept { return live_count_ == 0; }
    size_t size() const noexcept { return live_count_; }
    void clear() { rehash_to(8); }

  private:
    struct Slot {
        uint64_t key = EMPTY;
        uint64_t val = 0;
    };
    // Centinelas: un host_ptr real nunca es 0 (EMPTY) ni 1 (TOMB).
    static constexpr uint64_t EMPTY = 0;
    static constexpr uint64_t TOMB = 1;
    static inline size_t hash(uint64_t k) noexcept {
        // Fibonacci hashing (golden-ratio 64-bit); toma los bits altos tras la
        // multiplicacion (mejor dispersion que los bajos del puntero alineado).
        uint64_t x = k * 0x9E3779B97F4A7C15ull;
        return static_cast<size_t>(x >> 32);
    }
    void rehash_to(size_t cap) {
        table_.assign(cap, Slot{});
        mask_ = cap - 1;
        grow_at_ = (cap * 3) / 4; // factor de carga 0.75
        used_ = 0;
        live_count_ = 0;
    }
    void grow() {
        std::vector<Slot> old = std::move(table_);
        rehash_to((mask_ + 1) * 2);
        for (const Slot &s : old)
            if (s.key != EMPTY && s.key != TOMB) set(s.key, s.val);
    }
    std::vector<Slot> table_;
    size_t mask_ = 0, live_count_ = 0, used_ = 0, grow_at_ = 0;
};

/**
 * @brief Activa/desactiva el debug del GC en runtime.
 *
 * Cuando esta activado, las operaciones del GC (major_gc, minor_gc,
 * release_handle, scan_stack_roots, evacuate, etc.) emiten trazas a
 * stderr con prefijo @c [GC] indicando: que operacion, conteos, IDs de
 * handles afectados, y valores relevantes para diagnostico.
 *
 * Activacion via:
 *   - CLI: @c --gc-debug (afecta a todos los procesos de la VM)
 *   - Env: @c VESTA_GC_DEBUG=1 (mismo efecto, alternativa para scripts)
 *   - API: @c gc::set_gc_debug(true) desde codigo C++ o tests
 *
 * En modo debug: cada GC fire imprime `[GC] minor_gc count=N`,
 * `[GC] major_gc count=N`, `[GC] sweep killed h=N`, etc.  Los traces
 * usan @c fflush(stderr) por linea para sobrevivir a un crash.
 *
 * Default: false (silencioso).  Coste cuando esta apagado: cero
 * (un branch predicho por instruccion clave).
 */
void set_gc_debug(bool enabled) noexcept;
bool gc_debug_enabled() noexcept;

/**
 * @brief Modo BUFFERED del debug GC.  Acumula trazas en buffer
 *        thread-local de 64 KB y las flushea en bulk.
 *
 * Performance:
 *   - Modo default (unbuffered):  ~2 us / linea (write syscall directo).
 *   - Modo buffered:              ~100 ns / linea amortizado (memcpy +
 *                                 1 write syscall por 64 KB de trazas).
 *
 * Tradeoff: en modo buffered los ULTIMOS 64 KB de trazas pueden perderse
 * si el VM crashea (no estan flushed a disco).  El atexit handler hace
 * flush al salir limpio; gc_debug_flush() puede invocarse desde signal
 * handlers o pre-crash hooks para forzar flush.
 *
 * Activacion:
 *   - CLI: @c --gc-debug-buffered
 *   - Env: @c VESTA_GC_DEBUG_BUFFERED=1
 *   - API: @c set_gc_debug_buffered(true)
 *
 * Uso recomendado: BUFFERED para diagnosticos largos (millones de trazas)
 * en programas estables.  UNBUFFERED para diagnosticos de crash donde
 * cada linea importa.
 */
void set_gc_debug_buffered(bool enabled) noexcept;
bool gc_debug_buffered_enabled() noexcept;

/**
 * @brief Flush manual del buffer del GC debug.  Util para signal
 *        handlers o pre-crash hooks: garantiza que las trazas
 *        acumuladas en buffer vayan a disco antes de un posible crash.
 *
 * En modo unbuffered es no-op (las trazas ya estan en disco).
 */
void gc_debug_flush() noexcept;

/**
 * @brief Estado del objeto dentro del algoritmo de marcado tri-color.
 *
 * Los valores estan codificados en 2 bits dentro de GcHeader para minimizar
 * el tamano de la cabecera y mantener los objetos alineados a 8 bytes.
 *
 * Transiciones durante major_gc():
 * @code
 *   (todos los no-DEAD) --(PRE-MARK)--> WHITE
 *   WHITE (handle vivo)  --(MARK)-----> BLACK
 *   WHITE (sin handle)   --(SWEEP)----> DEAD
 *   BLACK                --(SWEEP)----> sin cambio (sobrevive)
 *   DEAD                 --(SWEEP)----> sin cambio (ya liberado)
 * @endcode
 */
enum class GcColor : uint8_t {
    WHITE = 0, /**< No visitado; candidato a recolectar. */
    GREY = 1,  /**< Alcanzable; referencias pendientes (reservado). */
    BLACK = 2, /**< Alcanzable y completamente procesado. */
    DEAD = 3   /**< Liberado por sweep; slot fisico reutilizable. */
};

/**
 * @brief Generacion del objeto dentro del heap generacional.
 */
enum class GcGen : uint8_t {
    YOUNG = 0, /**< Recien asignado; reside en Nursery. */
    OLD = 1    /**< Sobrevivio al menos un minor GC; reside en OldGen. */
};

/**
 * @brief Clase de finalizador GC de un objeto (side-table finalizer_kinds_).
 *
 * Un objeto GC que POSEE un recurso interno (un @c unique<T> con deleter, un
 * @c shared<T> con refcount, o una instancia de clase con @c ~Clase()) y que
 * ESCAPA su scope (return / almacenado en variable de vida mayor) NO puede
 * liberar ese recurso por el cleanup determinista de scope.  El sweep del GC,
 * al colectar el objeto, corre su FINALIZADOR: invoca EXACTAMENTE el mismo
 * deleter/dtor personalizable que corre en el caso no-escape (resuelto
 * estatico, CALL directo, portable en interp/JIT/AOT).
 *
 * El "kind" identifica QUE hay que hacer con el box colectado.  El deleter/
 * dtor concreto vive DENTRO del propio box (slot+8 en unique, control block en
 * shared, vtable del objeto en clase) -> el finalizador es generico por kind,
 * sin necesidad de un thunk por tipo.
 */
enum class GcFinalizerKind : uint8_t {
    NONE = 0,      /**< Sin finalizador (default: gc<primitivo>). */
    UNIQUE = 1,    /**< Box = slot unique<T> [ptr@0, deleter@8].  El finalizador
                    *   lee slot+8: si deleter!=0 llama deleter(slot[0]); si es 0
                    *   (default unique_box) libera slot[0] con free. */
    SHARED = 2,    /**< Box = slot shared<T> [ctrl_block_ptr@0].  El finalizador
                    *   decrementa el refcount del control block y lo libera con
                    *   free cuando llega a 0 (modelo refcount puro). */
    CLASS_DTOR = 3 /**< Box = instancia de clase gc<Clase> con ~Clase().  El
                    *   finalizador invoca el dtor concreto <Clase>____dtor
                    *   sobre el host_ptr del objeto (CALL directo, dispatch
                    *   estatico).  a0 = dtor_vaddr, a1 = obj_host_ptr. */
};

/**
 * @brief Firma del callback que EJECUTA un finalizador GC.
 *
 * GcHeap es agnostico del mecanismo de ejecucion (interp bytecode vs nativo):
 * solo recolecta los finalizadores pendientes durante el sweep y los DRENA
 * invocando este callback una vez por objeto colectado.  El runtime (VM) lo
 * implementa reentrando al interprete (portable, arch-independiente); el AOT
 * lo implementa con una llamada nativa directa.
 *
 * @param owner Contexto opaco del ejecutor (p.ej. el ProcessVM propietario).
 * @param box_payload Puntero host al payload del box colectado.
 * @param kind Clase de finalizador (UNIQUE / SHARED).
 */
/**
 * @brief Datos STAGEADOS de un finalizador pendiente.
 *
 * El sweep copia AQUI el contenido relevante del box ANTES de que su memoria se
 * reclame (reset del nursery / reuso del slot), para que el drenado posterior
 * (fuera del GC) no dependa de leer el box ya liberado.  Para UNIQUE:
 * a0=inner_ptr, a1=deleter_vaddr.  Para SHARED: a0=ctrl_block_ptr.
 */
struct GcPendingFinalizer {
    GcFinalizerKind kind;
    uint64_t a0; ///< inner_ptr (UNIQUE) o ctrl_block_ptr (SHARED)
    uint64_t a1; ///< deleter_vaddr (UNIQUE); 0 en SHARED
};

using GcFinalizerRunner = void (*)(void *owner, const GcPendingFinalizer &f);

/**
 * @brief Cabecera de metadatos que precede a cada objeto en el heap GC.
 *
 * Precede inmediatamente al payload del objeto en memoria. El layout es:
 * @code
 *   [GcHeader (8 bytes)] [payload (size bytes)] [padding hasta alinear a 8]
 * @endcode
 *
 * El tamano total de un slot es: (sizeof(GcHeader) + size + 7) & ~7
 *
 * @note alignas(8) garantiza que el payload que sigue a la cabecera este
 *       alineado a 8 bytes, lo que permite almacenar cualquier tipo primitivo
 *       sin violaciones de alineacion.
 *
 * @warning El campo size se preserva incluso cuando color == DEAD, porque
 *          alloc_in_old() necesita calcular el tamano del slot para decidir
 *          si puede reutilizarlo. Nunca poner size = 0 en un slot DEAD.
 */
struct alignas(8) GcHeader {
    uint32_t size;             /**< Bytes del payload (sin la cabecera). */
    GcColor color : 2;         /**< Estado tri-color mas DEAD. */
    GcGen gen : 1;             /**< Generacion: YOUNG o OLD. */
    uint8_t has_finalizer : 1; /**< 1 si el objeto tiene finalizador GC.  El
                                *   sweep, al colectar un objeto WHITE con este
                                *   bit, encola su finalizador para correrlo en
                                *   un safe point (drain post-collect). */
    uint8_t finalizer_kind
        : 2;                   /**< GcFinalizerKind del objeto (0-2).  Vive en
                                *   el propio header (sin side-table) para ser
                                *   freestanding-safe (libvesta_gc AOT) y
                                *   cache-friendly (el sweep ya lee el header).*/
    uint8_t host_ptr_only : 1; /**< 1 si el objeto SOLO es alcanzable por su
                                *   host_ptr (payload start), nunca por su
                                *   GcHandle numerico.  Lo ponen los boxes
                                *   @c gc_allocp (gc<T> por valor): el bytecode
                                *   los referencia unicamente via host_ptr
                                *   (add ptr,off / load / store), jamas via el
                                *   handle.  El scan conservador entonces NO
                                *   debe marcarlos por coincidencia numerica
                                *   valor==handle (falso positivo constante-vs-
                                *   handle-pequeno que impedia la colecta
                                *   determinista); SI se marcan por host_ptr
                                *   real (ptr_to_handle_ + interior scan). */
    uint8_t no_type_desc : 1;  /**< 1 si el payload NO empieza por un puntero
                                *   a descriptor de tipo.  Lo ponen los bloques
                                *   CRUDOS de la C-ABI (vx_gc_alloc): su
                                *   contrato es "size bytes de payload", sin
                                *   exigir forma alguna, asi que obj[0] es lo
                                *   que el consumidor escriba ahi.
                                *
                                *   Por defecto 0 = "tiene descriptor", que es
                                *   el comportamiento de siempre: el sentido
                                *   esta elegido para que olvidarse haga que un
                                *   objeto se TRACE de mas (vive un ciclo extra)
                                *   y nunca de menos (que seria colectar algo
                                *   alcanzable). */
    uint8_t _reserved[3];      /**< Padding hasta 8 bytes; reservado. */
};

static_assert(sizeof(GcHeader) == 8, "GcHeader debe medir exactamente 8 bytes");

/**
 * @brief Entrada en la tabla de handles del GcHeap.
 *
 * La HandleTable es un vector<HandleEntry> indexado por GcHandle.
 * Cuando un handle se libera (drop()), addr se pone a nullptr y live a false,
 * y el slot se recicla via free_handles_ para la siguiente asignacion.
 */
struct HandleEntry {
    uint8_t *addr; /**< Puntero host al inicio del GcHeader del objeto.
                    *   nullptr si el slot esta libre (live == false). */
    bool live;     /**< true si el handle referencia un objeto valido. */
};

/* El JIT ( D.7) inline-a @c deref leyendo @c HandleEntry con offsets
 * LITERALES (addr en 0, live en 8, stride 16).  Si el layout cambiase,
 * el codegen leeria basura -> corrupcion del heap.  Estos static_assert
 * fijan el contrato: cualquier cambio rompe el build en vez de corromper.
 * Ver doc en @c vreg_select.cpp (case GC_DEREF_HOST). */
static_assert(
    sizeof(HandleEntry) == 16,
    "HandleEntry debe medir 16 bytes (el JIT inline asume stride 16)");
static_assert(offsetof(HandleEntry, addr) == 0,
              "HandleEntry.addr debe estar en offset 0 (inline gc_deref)");
static_assert(offsetof(HandleEntry, live) == 8,
              "HandleEntry.live debe estar en offset 8 (inline gc_deref)");

/**
 * @brief Tabla de handles propia (POD), reemplaza @c std::vector<HandleEntry>.
 *
 * Motivacion ( D.7, principio "JIT inline > runtime"): el JIT necesita
 * leer @c data_ y @c count_ con offsets ESTABLES y controlados para inline-ar
 * @c deref (handle -> host_ptr) sin un CALL al runtime.  Con @c std::vector
 * habria que leer sus internals (@c _M_start/@c _M_finish), fragiles al
 * layout de libstdc++.  Esta estructura es POD con layout fijo:
 *   - offset 0:  @c data_  (HandleEntry*, 8 bytes)
 *   - offset 8:  @c count_ (uint32, 4 bytes)
 *   - offset 12: @c cap_   (uint32, 4 bytes)
 * y una sola fuente de verdad (sin campos cacheados que desincronizar).
 *
 * API drop-in compatible con @c std::vector (operator[], size, push_back,
 * reserve, empty, pop_back, back, data, begin, end) para minimizar el
 * impacto en los call sites.  @c push_back duplica @c cap_ via @c realloc;
 * los @c HandleEntry son POD (movibles con memcpy), igual que en un vector.
 * Como @c std::vector, un @c push_back que realloca INVALIDA punteros/refs
 * a entradas previas (el codigo accede siempre via @c handles_[h], nunca
 * guarda @c &handles_[h] a traves de un push).
 */
struct HandleTable {
    HandleEntry *data_ = nullptr; ///< offset 0
    uint32_t count_ = 0;          ///< offset 8
    uint32_t cap_ = 0;            ///< offset 12

    HandleTable() = default;
    ~HandleTable() { std::free(data_); }
    HandleTable(const HandleTable &) = delete;
    HandleTable &operator=(const HandleTable &) = delete;
    HandleTable(HandleTable &&o) noexcept
        : data_(o.data_), count_(o.count_), cap_(o.cap_) {
        o.data_ = nullptr;
        o.count_ = o.cap_ = 0;
    }
    HandleTable &operator=(HandleTable &&o) noexcept {
        if (this != &o) {
            std::free(data_);
            data_ = o.data_;
            count_ = o.count_;
            cap_ = o.cap_;
            o.data_ = nullptr;
            o.count_ = o.cap_ = 0;
        }
        return *this;
    }

    void reserve(uint32_t n) {
        if (n <= cap_) return;
        auto *nd = static_cast<HandleEntry *>(
            std::realloc(data_, static_cast<size_t>(n) * sizeof(HandleEntry)));
        if (!nd) std::abort(); // OOM en la tabla de handles: fatal
        data_ = nd;
        cap_ = n;
    }
    void push_back(const HandleEntry &e) {
        if (count_ == cap_) reserve(cap_ ? cap_ * 2u : 16u);
        data_[count_++] = e;
    }
    void pop_back() {
        if (count_) --count_;
    }
    HandleEntry &back() { return data_[count_ - 1]; }
    const HandleEntry &back() const { return data_[count_ - 1]; }
    HandleEntry &operator[](size_t i) { return data_[i]; }
    const HandleEntry &operator[](size_t i) const { return data_[i]; }
    size_t size() const { return count_; }
    bool empty() const { return count_ == 0; }
    HandleEntry *data() { return data_; }
    const HandleEntry *data() const { return data_; }
    HandleEntry *begin() { return data_; }
    HandleEntry *end() { return data_ + count_; }
    const HandleEntry *begin() const { return data_; }
    const HandleEntry *end() const { return data_ + count_; }
};

/* El JIT inline-a @c deref leyendo @c HandleTable::data_ (offset 0) y
 * @c count_ (offset 8) con LITERALES.  Fijar el contrato igual que con
 * @c HandleEntry: cualquier reordenacion rompe el build. */
static_assert(offsetof(HandleTable, data_) == 0,
              "HandleTable.data_ debe estar en offset 0 (inline gc_deref)");
static_assert(offsetof(HandleTable, count_) == 8,
              "HandleTable.count_ debe estar en offset 8 (inline gc_deref)");

/**
 * @brief Entrada en la tabla de referencias debiles del GcHeap.
 *
 * Una referencia debil apunta a un objeto sin impedir su recoleccion.
 * Durante la fase de barrido del major GC, si el objeto apuntado ha muerto,
 * target se pone a GC_NULL_HANDLE automaticamente.
 *
 * Se accede mediante un indice uint32_t (WeakHandle).
 */
struct WeakEntry {
    GcHandle target; ///< handle del objeto referenciado (GC_NULL_HANDLE si
                     ///< recolectado)
    bool live;       ///< true si esta entrada esta en uso
};

/**
 * @brief Estadisticas acumuladas del GcHeap.
 *
 * Todos los campos son plain uint64_t sin sincronizacion. El heap es
 * per-proceso (un solo hilo lo usa a la vez), por lo que no se necesitan
 * atomics. El overhead de actualizarlas es de una instruccion ADD por evento,
 * ya que el objeto GcHeap suele estar en L1 cache durante las operaciones
 * de asignacion y recoleccion.
 *
 * Se accede via GcHeap::stats() que devuelve una referencia const (sin copia).
 *
 * @note Los contadores son monotonicamente crecientes; nunca se resetean.
 *       Para medir un intervalo, tomar snapshot antes y despues.
 */
struct GcStats {
    uint64_t alloc_count = 0; /**< Llamadas a alloc() que tuvieron exito. */
    uint64_t alloc_bytes =
        0; /**< Bytes utiles asignados (lo pedido por el usuario). */
    uint64_t freed_count = 0;    /**< Objetos liberados por major GC (sweep). */
    uint64_t freed_bytes = 0;    /**< Bytes liberados por sweep (slot total). */
    uint64_t promoted_count = 0; /**< Objetos evacuados Nursery -> OldGen. */
    uint64_t promoted_bytes = 0; /**< Bytes de payload evacuados a OldGen. */
    uint64_t minor_gc_count = 0; /**< Ciclos de minor GC ejecutados. */
    uint64_t major_gc_count = 0; /**< Ciclos de major GC ejecutados. */
    uint64_t peak_nursery = 0;   /**< Uso maximo de Nursery en bytes. */
    uint64_t peak_old = 0;       /**< Uso maximo de OldGen en bytes. */
    // ---- GC no-moving en OldGen: metricas de fragmentacion ----
    uint64_t old_reserved_bytes =
        0; /**< Bytes reservados por bump pointer en bloques OldGen. */
    uint64_t old_freelist_bytes =
        0; /**< Bytes acumulados en free lists tras el ultimo sweep. */
    uint64_t old_alloc_freelist =
        0; /**< alloc_in_old satisfechos via free list (rapido). */
    uint64_t old_alloc_bump =
        0; /**< alloc_in_old satisfechos via bump pointer. */
    uint64_t old_alloc_newblock =
        0; /**< alloc_in_old que requirieron crear bloque nuevo. */

    /* ---- metricas de precise vs conservative scan ---- */
    /**
     * @brief Numero de roots GC marcados por el precise scan de JIT
     *        frames durante el ultimo major_gc.  Acumula a traves de
     *        multiples GC cycles.
     *
     * En coexistencia con el conservativo:
     *   - precise_roots_marked: handles encontrados en stackmaps de
     *     JIT frames.  Cero si no hay JIT frames activos.
     *   - conservative_roots_marked: handles encontrados por el scan
     *     conservativo (incluye los precise + otros del interp).
     *
     * Comparacion empirica: si `precise_roots_marked > 0` y
     * `conservative_roots_marked - precise_roots_marked` es razonable
     * (los del interp), la integracion es correcta.
     */
    uint64_t precise_roots_marked = 0;
    uint64_t conservative_roots_marked = 0;
    uint64_t precise_frames_scanned = 0; /**< JIT frames walked en total. */

    /**
     * Metricas del scan PRECISO del INTERPRETE (stackmaps VSMP), paralelas a
     * las del JIT.  En modo aditivo (junto al conservador) permiten comparar
     * empiricamente preciso-vs-conservador:
     *   - interp_precise_roots_marked: handles/host_ptrs marcados via los
     *     stackmaps del interprete.  0 si el .velb no lleva seccion VSMP.
     *   - interp_precise_notified: raices notificadas por el provider (antes
     *     de filtrar por vivas/OldGen/WHITE); util para ver la cobertura.
     */
    uint64_t interp_precise_roots_marked = 0;
    uint64_t interp_precise_notified = 0;

    /**
     * Objetos que el trazado preciso de AOT SOLTO por no poder fiarse de su
     * descriptor de tipo: obj[0] no era un puntero plausible, o no llevaba la
     * firma del descriptor, o su field-map declaraba mas campos de los que
     * caben en el objeto.
     *
     * Es la cifra que separa "no habia nada raro" de "hubo algo raro y nadie
     * lo vio".  Un objeto soltado NO se traza, asi que lo que solo el
     * referenciara se puede colectar: distinto de cero significa que hay un
     * bloque sin descriptor sin marcar, o memoria corrupta.
     */
    uint64_t tdesc_rejected = 0;

    /**
     * Verificador diferencial de COMPLETITUD (solo con VESTA_GC_VERIFY=1;
     * flag de DESARROLLO, no de producto).  Compara el conjunto PRECISO
     * (interp + JIT frames, cerrado transitivamente) contra las raices
     * REALES que el conservador retiene (objetos GC vivos de verdad).
     *
     *   - verify_gap_roots: raices GC vivas que el CONSERVADOR marca como
     *     raiz directa y que el PRECISO (ni su cierre transitivo) NO
     *     alcanzo -> HUECO de completitud (el preciso las perderia si
     *     fuera primario -> use-after-free).  Objetivo: 0.
     *   - verify_major_gc_checked: cuantos major_gc corrieron con el
     *     verificador activo (denominador de la tasa de huecos).
     */
    uint64_t verify_gap_roots = 0;
    uint64_t verify_major_gc_checked = 0;
};

/**
 * @brief Heap generacional de recoleccion de basura por proceso.
 *
 * Implementa un GC de dos generaciones (Nursery + OldGen) con los siguientes
 * algoritmos:
 *
 *   - minor_gc(): evacuacion estilo Cheney. Copia objetos YOUNG vivos a OldGen
 *     en un solo pase sobre la HandleTable. La Nursery se resetea atomicamente
 *     reseteando el bump-pointer, sin coste por objeto muerto.
 *
 *   - major_gc(): mark-and-sweep tri-color sobre OldGen. Tres fases:
 *     PRE-MARK (reset a WHITE), MARK (handles vivos -> BLACK),
 *     SWEEP (WHITE -> DEAD, actualizar old_used_).
 *
 * Uso tipico en bytecode Vesta:
 * @code
 *   GcHandle h = heap.alloc(sizeof(MyObject));
 *   MyObject *obj = reinterpret_cast<MyObject *>(heap.deref(h));
 *   obj->field = 42;
 *   // ... usar obj solo hasta el siguiente GC ...
 *   heap.drop(h);  // objeto elegible para recoleccion
 * @endcode
 *
 * @warning Los punteros devueltos por deref() son invalidos tras cualquier
 *          llamada a minor_gc() o major_gc(), ya que el GC puede mover los
 *          objetos. Siempre llamar a deref() de nuevo despues de un GC.
 *
 * @warning No es thread-safe. Un solo hilo debe usar el heap a la vez.
 */

/**
 * @brief Interfaz que abstrae lo que el GcHeap necesita de su "owner" para el
 *        scan conservativo (stack/regs del VM) y la sincronizacion shared
 *        ( Z, cross-proceso).
 *
 * Desacopla @c gc_heap.cpp de @c ProcessVM: el runtime aporta una impl que lee
 * el ProcessVM (vive en una TU del runtime, donde la VM esta definida); el GC
 * AOT standalone (libvesta_gc) pasa @c nullptr -> el GcHeap omite ambos caminos
 * y descubre las raices SOLO via stackmaps precisos sobre frames nativos.  Esto
 * permite compilar @c gc_heap.cpp sin arrastrar la VM (.o freestanding).
 */
class GcRootProvider {
  public:
    virtual ~GcRootProvider() = default;

    // --- Scan conservativo (raices en el stack/regs del VM) ---
    /// Llena @p rsp / @p stack_high / @p regs[16] con el estado del owner.
    /// Devuelve false si no hay stack VM (p.ej. AOT) -> el GC omite el scan.
    virtual bool vm_stack_regs(uint64_t &rsp, uint64_t &stack_high,
                               uint64_t regs[16]) = 0;
    /// Low-water-mark del stack (minimo rsp visto desde el ultimo GC).
    virtual uint64_t stack_low_water() const = 0;
    virtual void set_stack_low_water(uint64_t v) = 0;
    /// Escribe de vuelta los 16 GP regs tras el forwarding (GC moving).
    virtual void write_back_regs(const uint64_t regs[16]) = 0;
    /// Memoria virtual del VM para el scan (nullptr si no hay).
    virtual vm::VirtualMemory *vm_mem() = 0;

    // --- Scan PRECISO del interprete (stackmaps VSMP) ---
    /**
     * @brief Callback invocado por @c scan_interp_precise_roots para cada
     *        raiz GC precisa encontrada en un frame del interprete.
     * @param ctx    contexto opaco del caller (GcHeap).
     * @param value  valor leido de la ubicacion (handle o host_ptr).
     * @param kind   categoria (0=HANDLE, 1=HOSTPTR, 2=STRING) -- reusa
     *               @c jit::StackmapGcKind.
     */
    using InterpRootCallback = void (*)(void *ctx, uint64_t value,
                                        uint8_t kind);

    /**
     * @brief Escanea las raices GC PRECISAS de los frames del interprete
     *        usando los stackmaps (seccion VSMP) del ejecutable.
     *
     * Consulta el stackmap del PC de cada frame (rip del frame top +
     * return_pc de los callers) y, por cada ubicacion GC, lee el valor
     * (registro VM o slot de spill) e invoca @p cb.  La impl por defecto
     * es no-op (usada por el GC AOT y cualquier owner sin stackmaps del
     * interprete) -> el GcHeap cae al scan conservador.
     *
     * @param cb      callback por cada raiz encontrada.
     * @param cb_ctx  contexto opaco para @p cb.
     * @return numero de raices notificadas (0 si no hay stackmaps).
     */
    virtual uint64_t scan_interp_precise_roots(InterpRootCallback /*cb*/,
                                               void * /*cb_ctx*/) {
        return 0;
    }

    /**
     * @brief Indica si TODO frame vivo del interprete esta cubierto por
     *        stackmaps precisos (seccion @c VSMP).
     *
     * Camina la cadena de frames y comprueba, POR FRAME, que el ejecutable
     * al que pertenece su PC lleve una tabla @c VSMP no vacia.  Devuelve
     * @c false si ALGUN frame pertenece a un @c .velb SIN @c VSMP (binario
     * viejo, pre-scan-preciso, o modulo sin stackmaps).  En ese caso el
     * GcHeap mantiene el scan conservador como PRIMARIO -> soundness para
     * binarios mixtos (nuevos precisos + viejos conservadores).
     *
     * La impl por defecto devuelve @c false (owner sin frames de interprete
     * -- p.ej. GC AOT standalone): el GcHeap NO asume cobertura precisa y
     * cae al conservador salvo que este explicitamente desactivado.
     *
     * @return @c true si TODOS los frames del interprete tienen @c VSMP.
     */
    virtual bool all_interp_frames_have_stackmaps() { return false; }

    // ---  Z (shared / cross-proceso).  En AOT: false/nullptr. ---
    virtual bool shared_contains(const uint8_t *ptr) = 0;
    virtual uint8_t *shared_lookup(GcHandle h) = 0;
    virtual WaitTable *shared_wait_table() = 0;
};

class GcHeap {
  public:
    /**
     * @brief Construye el heap y reserva la Nursery.
     *
     * @param arena_mgr    ArenaManager del proceso propietario. OldGen pide
     *                     bloques a traves de el cuando necesita mas espacio.
     * @param nursery_bytes Tamano de la Nursery en bytes. Un tamano pequeno
     *                     provoca minor GC mas frecuentes pero pausas mas
     * cortas. Por defecto 1 MB.
     * @param old_threshold Bytes de OldGen usados que disparan un major GC
     *                      automatico al final de cada minor GC. Por defecto 8
     * MB.
     *
     * @note La Nursery se asigna como una Arena READ|WRITE en arena_mgr para
     *       que quede registrada en el proceso y sea liberada correctamente
     *       incluso si el proceso muere sin llamar al destructor.
     */
    explicit GcHeap(vm::ArenaManager &arena_mgr,
                    size_t nursery_bytes = 1 * 1024 * 1024,
                    size_t old_threshold = 8 * 1024 * 1024);

    /**
     * @brief Destructor. Libera la Nursery y todos los bloques de OldGen.
     *
     * Llama a arena_mgr_.free_arena() por cada bloque. No llama a ninguna
     * funcion de finalizacion de objetos (el lenguaje Vesta no tiene
     * destructores a nivel de VM en esta version).
     */
    ~GcHeap();

    GcHeap(const GcHeap &) = delete;

    GcHeap &operator=(const GcHeap &) = delete;

    /**
     * @brief Asigna un objeto de @p size bytes payload en el heap.
     *
     * Flujo de asignacion:
     * @code
     *   1. Fast-path: bump Nursery si hay espacio.        O(1)
     *   2. Nursery llena: disparar minor_gc() y reintentar.
     *   3. Sigue sin espacio: asignar directamente en OldGen.
     *   4. OOM en OldGen: devolver GC_NULL_HANDLE.
     * @endcode
     *
     * El payload se zero-inicializa siempre. El GcHeader se escribe con
     * color=WHITE, gen=YOUNG (o OLD si va directo a OldGen).
     *
     * @param size Bytes del payload (sin incluir GcHeader).
     * @return Handle valido, o GC_NULL_HANDLE si no hay memoria disponible.
     *
     * @note El handle devuelto permanece valido hasta que se llame a drop().
     *       La direccion fisica puede cambiar tras un minor_gc().
     */
    GcHandle alloc(size_t size);

    /**
     * @brief Aloca un objeto NO MOVIBLE (directo en OldGen).
     *
     * Variante de @c alloc que asigna el slot directamente en la
     * generacion vieja, evitando la promocion via @c do_evacuate.
     * El payload pointer obtenido via @c deref(h) permanece estable
     * durante toda la vida del handle: el major_gc no recolecta
     * objetos vivos (solo barre los DEAD), y la OldGen es non-moving.
     *
     * Util para objetos cuyo payload se exporta como @c host_ptr a
     * codigo que no se actualiza tras un GC, como @c StringObject
     * accedido via @c STRRAW para FFI / print / interpolacion.
     *
     * Coste: una llamada extra de overhead vs @c alloc en young (que
     * es bump O(1)); pero @c alloc_in_old usa free lists segregadas
     * por size class, asi que tambien es O(1) amortizado.
     *
     * @param size Tamano del payload en bytes (sin GcHeader).
     * @return Handle valido o GC_NULL_HANDLE si OOM en OldGen.
     */
    GcHandle alloc_pinned(size_t size);

    /**
     * @brief GC stack scanning conservativo con interior scan.
     *
     * Escanea el stack del proceso (rango [rsp, stack_high) leido de
     * @c vm_mem) y los GP regs R0..R15 buscando handles vivos y host_ptrs
     * (incluso interior pointers a objetos OldGen).  Cada uint64_t
     * encontrado pasa por filtros rapidos:
     *
     *   - skip si v == 0 o v < 256 (escalar pequeno, no puede ser handle)
     *   - check si v < handles_.size() y handles_[v].live  -> GcHandle
     *   - check si v esta en ptr_to_handle_ -> host_ptr al payload start
     *   - check si v cae dentro de algun bloque OldGen + buscar el header
     *     contenedor -> interior pointer (ej. STRRAW result al data[])
     *
     * Cada handle encontrado se marca BLACK + se anade al worklist BFS
     * para que mark_reachable lo procese transitivamente.
     *
     * Se llama desde @c major_gc() y @c minor_gc() ANTES del sweep,
     * para reemplazar el modelo "todo handle live = root" por uno
     * preciso basado en alcance real desde stack/regs.
     *
     * Coste: O(stack_size_active + 16 + N_old_blocks).  Para stack
     * tipico de 8 KB y 4 bloques OldGen: ~50-200 microsegundos por GC.
     * Mucho mas rapido que el modelo previo cuando hay muchos handles
     * vivos (que era O(N_handles) iterando handles_ entera).
     *
     * @param rsp        Stack pointer actual del proceso.
     * @param stack_high Limite superior del stack (inmutable post-spawn).
     * @param regs       Array de 16 GP regs (R0..R15).
     * @param vm_mem     VirtualMemory del proceso para leer slots stack.
     * @param worklist   Worklist BFS de mark phase; se anaden handles.
     */
    void scan_stack_roots(uint64_t rsp, uint64_t stack_high,
                          const uint64_t regs[16], vm::VirtualMemory &vm_mem,
                          std::vector<GcHandle> &worklist);

    /**
     * @brief precise scan de JIT frames.
     *
     * Camina la cadena RBP nativa desde @c __builtin_frame_address(0)
     * de @c major_gc.  Por cada JIT frame (identificado via
     * @c jit::JitRegistry::lookup), busca su stackmap y marca los
     * slots GC como roots vivos.
     *
     * Coexistencia con conservativo:
     *   - Ambos scans corren ADDITIVE: precise anade roots que el
     *     conservativo accidentalmente pudo no marcar (estabilidad
     *     adicional) y viceversa.
     *   - Cuando los stackmaps esten battle-tested, Fase 2-lean
     *     excluira rangos JIT del conservativo para eliminar false
     *     positives.
     *
     * Si @c jit::JitRegistry esta vacio (no hay JIT funcs cargadas)
     * la funcion retorna inmediatamente sin walk -- coste cero pre-D.3.
     *
     * @param worklist worklist BFS donde se anaden los handles
     *                 precise marcados como BLACK.
     * @param young    si true, enruta cada raiz a @c try_mark_precise_young
     *                 (solo marca objetos YOUNG del nursery -- lo usa el
     *                 minor_gc); si false (default), a @c
     * try_mark_precise_handle (marca OLD -- lo usa el major_gc).
     */
    void scan_jit_roots_precise(std::vector<GcHandle> &worklist,
                                bool young = false);

    /**
     * @brief Actualiza los host_ptrs GC guardados en frames JIT nativos tras
     * una evacuacion del minor_gc (analogo a @c update_stack_forwards pero para
     * la pila NATIVA del JIT, no la pila VM).
     *
     * Cuando el minor_gc evacua un objeto YOUNG a OldGen, su payload cambia de
     * direccion.  Los host_ptrs cacheados en slots de frames JIT-compilados
     * (p.ej. un `gc<Node> tail` vivo a traves de una alocacion que disparo el
     * minor) quedarian STALE -> el siguiente acceso al campo escribiria en
     * memoria del nursery ya reseteada.  Recorre los frames JIT via stackmaps
     * (usa el
     * @c slot_addr que reporta @c scan_jit_frames) y, para cada slot HOSTPTR/
     * STRING cuyo valor este en @c forward_table_, escribe la nueva direccion.
     * Los slots HANDLE no necesitan actualizacion (el GcHandle es estable).
     * No-op si @c forward_table_ esta vacio o no hay JIT funcs registradas.
     */
    void scan_jit_forwards();

    /**
     * @brief Si @c value esta en @c forward_table_, escribe la direccion
     *        forwarded en @c *slot_addr (8 bytes).  Helper de @c
     * scan_jit_forwards.
     * @return true si aplico un forward.
     */
    bool jit_forward_slot(uint64_t value, const uint8_t *slot_addr);

    /**
     * @brief Scan PRECISO de raices de los frames del INTERPRETE via los
     *        stackmaps (seccion VSMP).  Delega en
     *        @c GcRootProvider::scan_interp_precise_roots y marca cada raiz
     *        notificada (handle o host_ptr) como BLACK + worklist.
     *
     * Corre en modo ADITIVO junto al scan conservador (no lo reemplaza):
     * anade roots precisos.  Como es un SUBCONJUNTO de lo que el
     * conservador ya marca, nunca cambia que sobrevive -> cero cambio de
     * comportamiento.  Si el @c .velb no lleva VSMP o no hay provider, es
     * no-op.  Actualiza @c stats_.interp_precise_* .
     *
     * @param worklist worklist BFS donde se anaden los handles marcados.
     */
    void scan_interp_roots_precise(std::vector<GcHandle> &worklist);

    /**
     * @brief Verificador diferencial de COMPLETITUD del scan preciso
     *        (VESTA_GC_VERIFY=1, DEV-ONLY).  Cierra transitivamente el
     *        conjunto preciso ya acumulado en @p worklist y luego compara
     *        contra las raices reales que el conservador retiene: cualquier
     *        objeto GC vivo con referencia real (host_ptr en pila/regs) que
     *        el conservador marca pero el cierre preciso NO alcanzo es un
     *        HUECO (raiz real perdida).  Actualiza @c stats_.verify_gap_roots.
     *
     * ADITIVO: reusa el mismo coloreo (mark_reachable idempotente), no cambia
     * el conjunto de supervivientes.  Solo mide y reporta.
     *
     * @param worklist worklist BFS con los roots precisos ya acumulados; se
     *                 cierra in situ (BLACK) igual que haria el GC despues.
     */
    void verify_completeness(std::vector<GcHandle> &worklist);

    /**
     * @brief Intenta marcar un handle como root precise (BLACK + push
     *        worklist) si es valido + vivo + actualmente WHITE.
     * @return true si lo marco, false si no era root valido.
     */
    bool try_mark_precise_handle(GcHandle h, std::vector<GcHandle> &worklist);

    /**
     * @brief Variante YOUNG de @c try_mark_precise_handle usada por el scan
     *        preciso del NURSERY (minor_gc).
     *
     * Marca un handle como root precise (BLACK + push worklist) si es valido +
     * vivo + WHITE Y apunta a un objeto de la generacion YOUNG (dentro del
     * rango del nursery).  El scan preciso reporta TODAS las raices GC
     * independientemente de la generacion; para el minor_gc solo interesan las
     * YOUNG (las OLD las gobierna major_gc).  Simetrico a
     * @c try_mark_precise_handle (que filtra OLD) para el path del nursery.
     *
     * @return true si lo marco como root young, false si no aplica.
     */
    bool try_mark_precise_young(GcHandle h, std::vector<GcHandle> &worklist);

    /**
     * @brief Scan PRECISO de raices YOUNG de los frames del INTERPRETE via los
     *        stackmaps (seccion VSMP), para el minor_gc del nursery.
     *
     * Delega en @c GcRootProvider::scan_interp_precise_roots (el mismo que usa
     * el major_gc) pero enruta cada raiz notificada a
     * @c try_mark_precise_young, que solo marca objetos YOUNG.  Es el mecanismo
     * PRIMARIO de raices del nursery bajo el flip a preciso; el scan
     * conservador queda como fallback de dev (VESTA_GC_CONSERVATIVE=1) o para
     * ejecutables legacy sin VSMP.  No-op si no hay provider o stackmaps.
     *
     * @param worklist worklist BFS donde se anaden los handles YOUNG marcados.
     */
    void scan_interp_young_roots_precise(std::vector<GcHandle> &worklist);

    /**
     * @brief Recorre stack y GP regs reescribiendo host_ptrs de objetos
     * YoungGen evacuados a sus nuevas addresses en OldGen.
     *
     * Llamado al final de @c minor_gc(), DESPUES de @c do_evacuate.  Para
     * cada slot 8-bytes-aligned del stack y para cada GP reg (R0..R15),
     * comprueba si el valor es un host_ptr en @c forward_table_; si si,
     * escribe la nueva address.
     *
     * Esto elimina la limitacion historica "host_ptrs locales pueden
     * invalidarse tras GC": las locales CLASS del bytecode (cuyo valor
     * es el host_ptr al payload tras gcderef) quedan automaticamente
     * actualizados al evacuarse el objeto.  Sin esto, el bytecode
     * tenia que volver a llamar gcderef tras cada call que pudiera
     * disparar GC -> overhead inaceptable.
     *
     * Coste: O(stack_size_bytes/8) lookups en hashmap (typ. ~100 us)
     * + O(num_regs) (16 lookups).  Solo se llama si `forward_table_`
     * tiene entries (caso comun: pocos objetos sobrevivieron al minor).
     *
     * @param rsp_lo     RSP minimo visto desde el ultimo GC.  Limita el rango.
     * @param stack_high Top del stack (inmutable, configurado al spawn).
     * @param regs       Array de los 16 GP regs (R0..R15) modificable.
     * @param vm_mem     VirtualMemory del proceso para read/write 64-bit.
     */
    void update_stack_forwards(uint64_t rsp_lo, uint64_t stack_high,
                               uint64_t regs[16], vm::VirtualMemory &vm_mem);

    /**
     * @brief registra un handle como root temporal "en construccion".
     *
     * Usado por @c alloc() entre el momento de crear el handle y el
     * retorno al bytecode.  Si durante la construccion del objeto
     * compuesto se dispara otro alloc que hace GC, el handle todavia
     * NO esta en stack/regs del bytecode -> el scan no lo veria -> seria
     * barrido prematuramente.
     *
     * El sweep ignora cualquier handle que coincida con @c pending_alloc_root_.
     * El proximo alloc o cualquier instruccion VM que use el handle
     * efectivamente lo coloca en stack/regs y permite limpiar este pin.
     *
     * Usado tambien para proteger string objects en construccion durante
     * STRMAKE/STRCAT/STRSLICE/etc cuando alguno de esos puede disparar GC.
     */
    GcHandle pending_alloc_root_ = GC_NULL_HANDLE;

    /**
     * @brief asocia el GcHeap con su proveedor de raices (RootProvider).
     *
     * Llamado una vez al construir el ProcessVM (el runtime aporta una impl
     * sobre ProcessVM).  El GC AOT standalone pasa @c nullptr -> el major_gc
     * descubre raices solo via stackmaps precisos (scan_jit_roots_precise) y no
     * intenta el scan conservativo ni la sincronizacion shared.
     */
    void set_root_provider(GcRootProvider *p) noexcept { root_provider_ = p; }

    /**
     * @brief Activa el modo AOT (raices solo por stackmaps precisos +
     *        external_refs).  Sin owner ni este flag, el GC conserva todo.
     * @param v true para colectar de verdad usando raices precisas.
     */
    void set_aot_mode(bool v) noexcept { aot_precise_roots_ = v; }

    /**
     * @brief Fija el frame Vesta de ENTRADA para el WALK POR TAMANO DE FRAME
     * del scan preciso de AOT.
     *
     * Lo captura cada runtime-entry del GC que puede colectar (vx_gc_collect,
     * vx_gc_finalize_all) EN LA FRONTERA C<-Vesta: @p pc es la direccion de
     * retorno al frame Vesta llamador (dentro de la funcion nativa que llamo al
     * GC) y @p sp es el RSP de ese frame justo antes del @c call.  A partir de
     * ese par, @c scan_jit_roots_precise (en modo AOT) sube por la pila usando
     * el @c frame_size de cada funcion en lugar de la cadena RBP -> salta los
     * frames C++ no-walkables de libvesta_gc (que pueden usar
     * -fomit-frame-pointer) y arranca en el primer frame Vesta real.
     *
     * @param pc direccion de retorno al frame Vesta (0 = invalida el boundary).
     * @param sp RSP del frame Vesta llamador antes del @c call.
     */
    void set_aot_scan_boundary(uint64_t pc, uint64_t sp) noexcept {
        aot_boundary_pc_ = pc;
        aot_boundary_sp_ = sp;
        aot_boundary_valid_ = (pc != 0 && sp != 0);
    }

    /**
     * @brief Snapshot del boundary del scan preciso en modo interp+JIT.
     *
     * Lo usa el guard de la runtime-entry (@c vrt_*) para restaurar el estado
     * previo al salir, de modo que el boundary solo sea valido DURANTE la
     * llamada que lo fijo (no se camina un frame JIT ya retornado).
     */
    struct JitScanBoundary {
        uint64_t pc = 0;    ///< PC de retorno al codigo JIT.
        uint64_t sp = 0;    ///< RSP del frame JIT justo antes del @c call.
        bool valid = false; ///< true si @c pc y @c sp son utilizables.
    };

    /**
     * @brief Fija el boundary del WALK POR TAMANO DE FRAME en modo interp+JIT.
     *
     * Analogo a @c set_aot_scan_boundary pero para el proceso de la VM (interp
     * + JIT), donde @c aot_precise_roots_ es false.  Lo fija cada runtime-entry
     * @c vrt_* que puede colectar y que el codigo JIT llama DIRECTAMENTE,
     * capturado en la frontera C<-JIT: @p pc es la direccion de retorno al
     * codigo JIT y @p sp es el RSP de ese frame JIT justo antes del @c call.
     * Mientras sea valido, @c scan_jit_roots_precise y @c scan_jit_forwards
     * usan @c scan_aot_frames (reconstruye RBP con @c frame_size) en lugar de
     * la cadena RBP -> saltan los frames C++ del runtime, que a -O0 rompen la
     * cadena (p.ej. @c lea rbp,[rsp+N]).  Boundary SEPARADO del de AOT para no
     * pisar su estado.
     *
     * @param pc direccion de retorno al codigo JIT (0 = invalida el boundary).
     * @param sp RSP del frame JIT llamador antes del @c call.
     */
    void set_jit_scan_boundary(uint64_t pc, uint64_t sp) noexcept {
        jit_boundary_pc_ = pc;
        jit_boundary_sp_ = sp;
        jit_boundary_valid_ = (pc != 0 && sp != 0);
    }

    /**
     * @brief Devuelve el boundary JIT actual (para save/restore del guard).
     */
    JitScanBoundary jit_scan_boundary() const noexcept {
        return JitScanBoundary{jit_boundary_pc_, jit_boundary_sp_,
                               jit_boundary_valid_};
    }

    /**
     * @brief Restaura un boundary JIT previamente guardado.
     */
    void restore_jit_scan_boundary(const JitScanBoundary &s) noexcept {
        jit_boundary_pc_ = s.pc;
        jit_boundary_sp_ = s.sp;
        jit_boundary_valid_ = s.valid;
    }

    /**
     * @brief Devuelve un puntero al payload del objeto referenciado por @p
     * handle.
     *
     * El puntero apunta inmediatamente despues del GcHeader del objeto.
     * Es valido para leer y escribir hasta la proxima llamada a minor_gc()
     * o major_gc(), ya que el GC puede mover el objeto.
     *
     * @param handle Handle valido devuelto por alloc().
     * @return Puntero al payload, o nullptr si el handle es invalido o libre.
     *
     * @warning Nunca almacenar este puntero mas alla del siguiente GC.
     *          Usar el handle para reconvertir si es necesario.
     */
    uint8_t *deref(GcHandle handle);

    /**
     * @brief Numero total de slots de la HandleTable (incluye libres).
     *
     * Para iterar handles vivos:
     * @code
     *   for (size_t i = 0; i < heap.handle_table_size(); ++i) {
     *       if (heap.is_handle_live(static_cast<GcHandle>(i))) {
     *           uint8_t *p = heap.deref(static_cast<GcHandle>(i));
     *           ...
     *       }
     *   }
     * @endcode
     *
     * Coste O(1).  Util principalmente para el debugger TCP que
     * expone la lista de handles vivos al cliente VSH.
     */
    size_t handle_table_size() const noexcept { return handles_.size(); }

    /**
     * @brief @c true si el handle apunta a un objeto vivo.
     *
     * Usado por el debugger para iterar la HandleTable sin acceso
     * directo a los campos privados.  Coste O(1).
     */
    bool is_handle_live(GcHandle handle) const noexcept {
        return handle < handles_.size() && handles_[handle].live;
    }

    /**
     * @brief Direccion estable de la @c HandleTable interna, para el JIT.
     *
     *  D.7 (principio "JIT inline > runtime"): el codigo JIT-eado
     * inline-a @c deref leyendo @c data_/@c count_ de esta tabla en vez
     * de hacer un CALL a @c vrt_gc_deref.  La struct @c HandleTable vive
     * embebida en el GcHeap (no se mueve durante la vida del proceso),
     * por lo que su direccion es estable; lo que cambia (via realloc) es
     * el puntero @c data_ que ALMACENA, leido en cada deref.
     *
     * Se cachea una sola vez en @c ProcessVM::jit_handle_table (ctor).
     *
     * @return Puntero a la @c HandleTable (nunca nullptr).
     */
    HandleTable *jit_handle_table_ptr() noexcept { return &handles_; }

    /**
     * @brief Tamano del payload del objeto referenciado por handle.
     *
     * Lee el campo @c size del @c GcHeader inmediatamente antes del
     * payload.  Devuelve 0 si el handle es invalido o muerto.
     */
    uint32_t handle_payload_size(GcHandle handle) const noexcept {
        if (handle >= handles_.size() || !handles_[handle].live ||
            !handles_[handle].addr) {
            return 0;
        }
        const auto *h =
            reinterpret_cast<const GcHeader *>(handles_[handle].addr);
        return h->size;
    }

    /**
     * @brief Generacion del objeto (YOUNG/OLD).
     */
    GcGen handle_generation(GcHandle handle) const noexcept {
        if (handle >= handles_.size() || !handles_[handle].live ||
            !handles_[handle].addr) {
            return GcGen::OLD;
        }
        const auto *h =
            reinterpret_cast<const GcHeader *>(handles_[handle].addr);
        return h->gen;
    }

    /**
     * @brief Lookup inverso: dado un puntero host al payload, devuelve el
     * GcHandle.
     *
     * Es el inverso de @c deref(): si @c deref(h) devolvio @p host_payload_ptr,
     * entonces @c handle_for_ptr(host_payload_ptr) devuelve @p h.
     *
     * Usado por la instruccion bytecode @c gchandle (0x55) para que el
     * frontend Vesta pueda obtener el GcHandle de un objeto cuando solo
     * tiene el host pointer (caso comun: tras @c gcderef en un constructor).
     * El uso primario es @c synchronized(obj) en Vesta, que necesita el handle
     * para @c monenter / @c monexit.
     *
     * Coste O(1) amortizado (unordered_map lookup + bucket walk corto).
     * El mapa se mantiene incrementalmente en @c new_handle, @c release_handle
     * y @c do_evacuate, por lo que no hay coste adicional en @c handle_for_ptr.
     *
     * @param host_payload_ptr Puntero host al inicio del payload (justo tras
     * GcHeader), tipicamente el resultado de un @c deref previo.
     * @return GcHandle del objeto si lo encuentra, @c GC_NULL_HANDLE si no.
     */
    GcHandle handle_for_ptr(const uint8_t *host_payload_ptr) const noexcept;

    /**
     * @brief Registra una referencia old->young en el remembered set.
     *
     * Debe llamarse cada vez que el codigo de usuario (o el compilador del
     * lenguaje Vesta) escribe un GcHandle YOUNG dentro del payload de un
     * objeto OLD. Sin esta llamada, el minor GC podria no encontrar el objeto
     * YOUNG como alcanzable y recolectarlo prematuramente.
     *
     * No anade duplicados al remembered set.
     *
     * @param old_handle Handle del objeto OLD que contiene el campo modificado.
     *
     * @note Esta funcion solo es necesaria para referencias cross-generacion
     *       (OLD -> YOUNG). Referencias YOUNG -> YOUNG o OLD -> OLD no
     *       necesitan write barrier.
     */
    void write_barrier(GcHandle old_handle);

    /**
     * @brief Incrementa el refcount externo de @p h.
     *
     * Llamado por estructuras de datos NATIVAS que retienen un GcHandle
     * (ej. el plugin @c vesta_collections cuando hace push de un string
     * en un @c ArrayList<string>).  Mientras el refcount sea >0, el GC
     * trata el handle como root vivo durante el mark  del
     * major_gc, evitando que sea colectado aunque ningun root normal
     * (HandleTable bytecode) lo referencie.
     *
     * Coste: O(1) amortizado (1 lookup + increment).  Sin syscalls,
     * sin scan adicional.
     *
     * @param h Handle a pinnar.  Si @c h == GC_NULL_HANDLE no-op.
     */
    void gc_addref(GcHandle h);

    /**
     * @brief Decrementa el refcount externo de @p h.
     *
     * Llamado por la estructura nativa cuando deja de retener el handle
     * (ej. al hacer pop, remove, clear o destruir el contenedor).  Si
     * el refcount llega a 0, la entrada se elimina del map (el GC ya
     * NO lo trata como root externo).
     *
     * Coste: O(1) amortizado.  No llama al GC: solo desregistra; la
     * coleccion real ocurre en el proximo major_gc si nadie mas
     * referencia el handle.
     *
     * @param h Handle a despinnar.  Si no estaba registrado, no-op.
     */
    void gc_release(GcHandle h);

    /**
     * @brief Numero de handles actualmente pinnados externos.
     *        Util para debug / introspeccion.  Devuelve el size del map
     *        external_refs_, NO la suma de refcounts.
     */
    size_t external_pinned_count() const noexcept {
        return external_refs_.size();
    }

    /**
     * @brief Libera el handle indicando que el objeto ya no es alcanzable.
     *
     * Marca el slot en la HandleTable como libre (live=false, addr=nullptr)
     * y lo recicla para futuras asignaciones. El objeto permanece fisicamente
     * en Nursery u OldGen hasta que el GC lo recolecte.
     *
     * En la Nursery: el objeto es ignorado en la proxima evacuacion y su
     * memoria se reclama cuando el bump-pointer se resetea.
     *
     * En OldGen: el objeto permanece con su GcHeader intacto hasta el proximo
     * major_gc(), donde el PRE-MARK lo pone WHITE y el SWEEP lo marca DEAD.
     *
     * @param h Handle a liberar. Si es invalido o ya esta libre, no hace nada.
     */
    void drop(GcHandle h) { release_handle(h); }

    /**
     * @brief Crea una referencia debil al objeto indicado por @p target.
     *
     * La referencia debil no impide la recoleccion del objeto.
     * Durante el barrido del major GC, si el objeto es recolectado,
     * la entrada se pone automaticamente a GC_NULL_HANDLE.
     *
     * @param target Handle del objeto a referenciar debilmente.
     * @return Indice uint32_t de la entrada en weak_table_.
     */
    uint32_t alloc_weak(GcHandle target);

    /**
     * @brief Lee el handle apuntado por la referencia debil @p idx.
     *
     * @param idx Indice en weak_table_ obtenido de alloc_weak().
     * @return Handle del objeto si aun esta vivo; GC_NULL_HANDLE si fue
     * recolectado.
     */
    GcHandle deref_weak(uint32_t idx) const;

    /**
     * @brief Libera la entrada de referencia debil @p idx.
     *
     * Marca la entrada como libre para su reutilizacion.
     *
     * @param idx Indice en weak_table_ a liberar.
     */
    void free_weak(uint32_t idx);

    // =====================================================================
    //  Primitivas de monitor (sincronizacion por objeto)
    //
    //  Un monitor es un lock reentrante asociado a un objeto GC.  El estado
    //  del lock (propietario y profundidad) se almacena en ObjectHeader de
    //  cada objeto.  La cola de procesos en espera se almacena en esta clase.
    //
    //  Invariante:
    //    - ObjectHeader::owner_pid == 0  <=>  monitor libre
    //    - ObjectHeader::owner_pid != 0  <=>  monitor adquirido por ese pid
    //    - ObjectHeader::lock_depth >= 1 cuando owner_pid != 0
    //
    //  Los PID codificados en las colas usan el formato:
    //    encoded_pid = (scheduler_id << 32) | local_pid
    // =====================================================================

    /**
     * @brief Intenta adquirir el monitor del objeto referenciado por @p h.
     *
     * Si el monitor esta libre, lo asigna a @p local_pid y devuelve true.
     * Si ya lo posee @p local_pid (lock reentrante), incrementa lock_depth y
     * devuelve true.
     * Si lo posee otro proceso, devuelve false (el llamante debe bloquear).
     *
     * Toma @c owner_encoded de 48 bits (scheduler_id<<32 | local_pid).
     * Globalmente unico: evita la colision local_pid==local_pid entre
     * schedulers distintos (bug Z.11 ext: lock confundido como reentrante).
     *
     * @param h             Handle del objeto cuyo monitor se quiere adquirir.
     * @param owner_encoded PID encoded global del proceso solicitante.
     * @return true si el monitor fue adquirido o incrementado; false si
     * bloqueado.
     */
    bool monitor_try_acquire(GcHandle h, uint64_t owner_encoded);

    /**
     * @brief Libera el monitor del objeto referenciado por @p h.
     *
     * Decrementa lock_depth.  Si llega a 0, marca el monitor como libre y
     * extrae un proceso de la cola de espera para despertarlo.
     *
     * @param h             Handle del objeto cuyo monitor se libera.
     * @param owner_encoded PID encoded global del propietario actual.
     * @return PID codificado del siguiente proceso de la cola de espera
     *         (0 si la cola estaba vacia o el monitor sigue bloqueado).
     */
    uint64_t monitor_release(GcHandle h, uint64_t owner_encoded);

    /**
     * @brief Anade un PID codificado a la cola de espera del monitor de @p h.
     *
     * Se llama desde exec_instr_monenter cuando el monitor esta ocupado, o
     * desde exec_instr_monwait cuando el proceso libera el monitor para
     * esperar.
     *
     * @param h           Handle del objeto cuyo monitor espera el proceso.
     * @param encoded_pid PID codificado: (scheduler_id << 32) | local_pid.
     */
    void monitor_add_waiter(GcHandle h, uint64_t encoded_pid);

    /**
     * @brief Extrae y devuelve un PID codificado de la cola de espera de @p h.
     *
     * Devuelve 0 si la cola esta vacia.  Se usa en MONNOTI para despertar
     * exactamente un proceso.
     *
     * @param h Handle del objeto cuya cola de espera se consulta.
     * @return PID codificado del proceso despertado, o 0 si la cola estaba
     * vacia.
     */
    uint64_t monitor_pop_waiter(GcHandle h);

    /**
     * @brief Extrae y devuelve todos los PID codificados de la cola de @p h.
     *
     * La cola queda vacia tras la llamada.  Se usa en MONNOTA para despertar
     * a todos los procesos que esperan sobre el mismo objeto.
     *
     * @param h Handle del objeto cuya cola de espera se vacia.
     * @return Vector con todos los PID codificados (puede estar vacio).
     */
    std::vector<uint64_t> monitor_pop_all_waiters(GcHandle h);

    // -----------------------------------------------------------------
    // Wait queues con dispatch local-vs-shared ( Z).
    // -----------------------------------------------------------------
    // Cuando un handle tiene el @c SHARED_HANDLE_BIT, las wait queues
    // (monitor + condvar) se enrutan a @c vm.shared_wait_table en lugar
    // de la tabla local @c wait_table_, permitiendo que parent y child
    // que comparten el mismo objeto se coordinen cross-process.

    /// Encola @p encoded_pid en la wait queue CONDVAR de @p h.  Usada
    /// por @c monwait para distinguir esperantes que liberan el
    /// monitor (CONDVAR) de los que esperan reentrar (MONITOR).
    void condvar_add_waiter(GcHandle h, uint64_t encoded_pid);

    /// Despierta UN proceso de la wait queue CONDVAR de @p h.  Usada
    /// por @c monnoti.  Devuelve el PID codificado o 0 si vacia.
    uint64_t condvar_pop_waiter(GcHandle h);

    /// Despierta TODOS los procesos de la wait queue CONDVAR de @p h.
    /// Usada por @c monnota.  La cola queda vacia tras la llamada.
    std::vector<uint64_t> condvar_pop_all_waiters(GcHandle h);

    // set_owner_process ya declarada e inlineada arriba.

    /**
     * @brief Minor GC: evacua la Nursery copiando supervivientes a OldGen.
     *
     * Algoritmo (Cheney-style simplificado):
     * @code
     *   Para cada handle H en la HandleTable:
     *     Si H.live && H.addr en rango Nursery && gen == YOUNG:
     *       alloc_in_old(tamano del objeto)
     *       memcpy al nuevo slot
     *       H.addr = nuevo slot (handle actualizado)
     *       objeto original marcado BLACK (forward pointer en payload)
     *   remembered_set.clear()
     *   nursery_bump = nursery_base  (reset O(1))
     *   Si old_used >= old_threshold: major_gc()
     * @endcode
     *
     * Todos los objetos YOUNG sin handle vivo son abandonados en la Nursery
     * y su memoria se reclama gratis con el reset del bump-pointer. Este es el
     * beneficio central de la generacional: limpiar objetos muertos es O(1).
     *
     * @note Provoca una pausa del proceso propietario. Otros procesos de la
     *       VM no se ven afectados.
     */
    void minor_gc();

    /**
     * @brief Major GC: mark-and-sweep tri-color sobre OldGen.
     *
     * Tres fases:
     *
     *   PRE-MARK: recorre todos los objetos OldGen y los pone WHITE (excepto
     *             los ya DEAD). Necesario porque los objetos llegan a OldGen
     *             con color BLACK tras la evacuacion y no hay otro mecanismo
     *             que los resetee cuando su handle se suelta.
     *
     *   MARK:     recorre la HandleTable. Por cada handle vivo cuyo objeto
     *             esta en OldGen, pone el objeto BLACK (alcanzable).
     *
     *   SWEEP:    recorre los bloques de OldGen. Objetos WHITE (sin raiz) se
     *             marcan DEAD, se decrementa old_used_ y se actualizan stats.
     *             Objetos BLACK sobreviven. Objetos DEAD se ignoran.
     *
     * @note Actualmente el MARK no sigue punteros dentro de los objetos
     *       (no hay grafo de objetos en esta version). Toda la liveness se
     *       determina por la HandleTable. Para soportar grafos de objetos
     *       se debe implementar un MARK transitive que siga campos GcHandle.
     *
     * @note Provoca una pausa del proceso propietario. Puede ser largo si
     *       OldGen es grande. Para pausas acotadas considerar un major GC
     *       incremental en versiones futuras.
     */
    void major_gc();

    // ----------------------------------------------------------------------
    //  Finalizadores GC (recurso interno de objetos que escapan su scope)
    // ----------------------------------------------------------------------

    /**
     * @brief Registra un finalizador para el objeto cuyo payload es @p payload.
     *
     * Marca el bit @c has_finalizer y el @c finalizer_kind en el GcHeader del
     * objeto.  A partir de aqui, cuando el sweep colecte el objeto (WHITE,
     * inalcanzable), encolara su finalizador para correrlo en un safe point.
     * Idempotente: registrar dos veces sobreescribe el kind.  No-op si @p
     * payload no es un objeto GC vivo de este heap.
     *
     * @param payload Puntero host al payload del objeto (el que devuelve alloc
     *                + sizeof(GcHeader), es decir el que ve el programa).
     * @param kind Clase de finalizador (UNIQUE / SHARED / CLASS_DTOR).
     * @param dtor_vaddr Solo para CLASS_DTOR: direccion VM del <Clase>____dtor
     *                   concreto (dispatch estatico).  Ignorado para los demas
     *                   kinds (su deleter vive dentro del box).
     */
    void register_finalizer(uint8_t *payload, GcFinalizerKind kind,
                            uint64_t dtor_vaddr = 0);

    /**
     * @brief El GcHeader que precede a @p payload, o nullptr si es nulo.
     *
     * El layout [GcHeader][payload] lo sabe UN solo sitio.  Repetir la resta
     * en cada marcador es como se acaba con dos ideas distintas del mismo
     * layout, que es justo la clase de divergencia que no da error: da otro
     * objeto.
     */
    static GcHeader *header_of(uint8_t *payload) noexcept {
        if (payload == nullptr) return nullptr;
        return reinterpret_cast<GcHeader *>(payload - sizeof(GcHeader));
    }

    /**
     * @brief Marca el objeto @p payload como alcanzable SOLO por host_ptr.
     *
     * Lo llaman los boxes @c gc_allocp (gc<T> por valor): el bytecode los
     * referencia unicamente via el host_ptr al payload, nunca via el GcHandle
     * numerico.  El scan conservador entonces salta el marcado por coincidencia
     * numerica (valor == handle), eliminando el falso positivo constante-vs-
     * handle-pequeno que impedia la colecta determinista de boxes escapados.
     * No-op si @p payload no es un objeto GC vivo de este heap.
     *
     * @param payload Puntero host al payload del box (lo que devuelve
     * gcallocp).
     */
    void mark_host_ptr_only(uint8_t *payload) {
        if (GcHeader *hdr = header_of(payload)) hdr->host_ptr_only = 1;
    }

    /**
     * @brief Marca el objeto @p payload como BLOQUE CRUDO: su obj[0] no es un
     *        puntero a descriptor de tipo.
     *
     * Lo pone la C-ABI cruda (@c vx_gc_alloc), cuyo contrato publico es "size
     * bytes de payload" y no exige forma ninguna.  Sin esta marca el trazado
     * preciso de AOT lee obj[0] como descriptor y sigue lo que el consumidor
     * hubiera escrito ahi -- que no es un puntero.
     *
     * No-op si @p payload es nulo.
     *
     * @param payload Puntero host al payload del bloque.
     */
    void mark_no_type_desc(uint8_t *payload) {
        if (GcHeader *hdr = header_of(payload)) hdr->no_type_desc = 1;
    }

    /**
     * @brief Desregistra el finalizador del objeto @p payload
     * (anti-doble-free).
     *
     * Limpia el bit @c has_finalizer del GcHeader.  Lo llama el
     * cleanup determinista de scope (caso NO-escape): el recurso ya se libero
     * ahi, asi que el finalizador GC NO debe volver a correr.  No-op si el
     * objeto no tenia finalizador registrado.
     */
    void unregister_finalizer(uint8_t *payload);

    /**
     * @brief Instala el callback que EJECUTA los finalizadores encolados.
     *
     * GcHeap solo recolecta finalizadores durante el sweep; el runtime (VM) o
     * el AOT proveen la ejecucion concreta via este callback.  Si no hay
     * callback instalado, los finalizadores encolados se descartan (el recurso
     * se fuga, pero no hay crash) -- caso solo posible pre-inicializacion.
     *
     * @param runner Callback de ejecucion (ver GcFinalizerRunner).
     * @param owner Contexto opaco que se pasa al callback (p.ej. ProcessVM*).
     */
    void set_finalizer_runner(GcFinalizerRunner runner, void *owner) {
        finalizer_runner_ = runner;
        finalizer_owner_ = owner;
    }

    /**
     * @brief Drena la cola de finalizadores pendientes invocando el runner.
     *
     * Se llama en un SAFE POINT tras completar un collect (fin de major_gc) y
     * tambien al destruir el heap (para finalizar los objetos vivos-con-recurso
     * antes del exit).  Guardado contra reentrada (@c finalizing_): un GC
     * disparado DENTRO de un finalizador solo ENCOLA mas trabajo; el bucle de
     * drenado externo lo procesa.  Cada finalizador se corre EXACTAMENTE una
     * vez (se desencola antes de invocarlo).
     */
    void run_pending_finalizers();

    /** @brief true si hay finalizadores stageados pendientes de ejecutar. */
    bool has_pending_finalizers() const { return !pending_finalizers_.empty(); }

    /**
     * @brief Finaliza TODOS los objetos vivos con recurso interno (exit-time).
     *
     * Recorre la tabla de handles + los bloques OldGen buscando objetos con el
     * bit @c has_finalizer set y encola su finalizador; luego drena.  Se llama
     * cuando el proceso termina (HALT del main) mientras el interprete sigue
     * vivo, para garantizar que un objeto GC con recurso que ESCAPO su scope
     * (y por tanto no tuvo cleanup determinista) libere su recurso interno
     * ANTES del exit -- aunque el GC no lo haya colectado todavia. Idempotente:
     * limpia el bit al encolar, asi no re-finaliza en un segundo pase.
     */
    void finalize_all_live();

    /**
     * @brief Stagea (sin drenar) el finalizador de TODO objeto vivo con
     * recurso.
     *
     * Igual que @c finalize_all_live pero SIN llamar @c run_pending_finalizers:
     * solo encola.  Lo usa el opcode @c gcfinall (builtin gc_finalize_all) para
     * que el DRENADO ocurra despues, en el safe point del scheduler (reentrar
     * al interp para el deleter/dtor dentro del handler de la instruccion
     * corromperia la instruccion en curso).  Idempotente (limpia
     * has_finalizer).
     */
    void stage_all_live_finalizers();

    /**
     * @brief Configura el umbral de OldGen para major GC automatico.
     *
     * Cuando old_used_ >= old_threshold_ al finalizar un minor_gc(), se
     * dispara un major_gc() automaticamente. Un umbral bajo provoca mas
     * ciclos major GC pero mantiene OldGen mas compacto.
     *
     * @param bytes Umbral en bytes. Un valor de 0 deshabilita el major GC
     *              automatico (solo se puede disparar manualmente).
     */
    void set_old_threshold(size_t bytes) { old_threshold_ = bytes; }

    /** @brief Bytes actualmente usados en la Nursery (distancia bump-base). */
    size_t nursery_used() const {
        return static_cast<size_t>(nursery_bump_ - nursery_base_);
    }

    /** @brief Tamano total de la Nursery en bytes. */
    size_t nursery_total() const { return nursery_size_; }

    /** @brief Bytes actualmente contabilizados en OldGen. */
    size_t old_used() const { return old_used_; }

    /**
     * @brief Devuelve una referencia de solo lectura a las estadisticas
     * acumuladas.
     *
     * La referencia es valida mientras el GcHeap exista. No copia los datos.
     * Los contadores son monotonicamente crecientes; para medir un intervalo
     * tomar un snapshot antes y otro despues de la operacion de interes.
     *
     * @return Referencia const a GcStats.
     */
    const GcStats &stats() const { return stats_; }

    /**
     * @brief  D.7.opt: wrapper publico de @c new_handle para que
     *        @c vrt_register_alloc lo invoque tras inlinear bump-pointer.
     *
     * Solo debe usarse cuando el caller YA hizo bump-pointer + init de
     * @c GcHeader + @c ObjectHeader.  Esta funcion SOLO crea el handle.
     */
    GcHandle register_alloc(uint8_t *raw) { return new_handle(raw); }

  public:
    // --- Nursery (publicos para inline bump-pointer en JIT) ---
    //
    //  D.7.opt: el JIT inlinea el fast path de alloc emitiendo
    // accesos directos a @c nursery_bump_ y @c nursery_end_ via
    // offset compile-time desde @c ProcessVM* (rbx en VM_ABI).
    // Esto elimina la llamada a @c vrt_newobj para el caso comun
    // (~5 ns inline vs ~20 ns runtime call).  Los demas usuarios
    // siguen usando @c alloc() para preservar invariantes.
    uint8_t *nursery_base_ = nullptr; ///< Inicio del bloque Nursery.
    uint8_t *nursery_bump_ = nullptr; ///< Proximo byte libre (bump pointer).
    uint8_t *nursery_end_ = nullptr;  ///< Fin del bloque Nursery.

  private:
    vm::ArenaManager &arena_mgr_;
    size_t nursery_size_ = 0; ///< Tamano total de la Nursery.
    uint64_t nursery_arena_id_ =
        0; ///< ID en ArenaManager para liberar al destruir.

    // --- OldGen (modelo no-moving con free lists segregadas, ver gc_heap.cpp)
    // ---
    struct OldBlock {
        uint8_t *ptr;       ///< Inicio del bloque.
        size_t size;        ///< Tamano total del bloque en bytes.
        uint64_t arena_id;  ///< ID en ArenaManager para liberar al destruir.
        size_t bump_offset; ///< Bytes ya consumidos por bump-alloc (offset
                            ///< desde ptr). Si bump_offset == size: bloque
                            ///< lleno; reciclamos slots solo via free lists,
                            ///< sin compactar.
    };

    std::vector<OldBlock> old_blocks_;
    size_t old_used_ = 0;      ///< Bytes vivos contabilizados en OldGen.
    size_t old_threshold_ = 0; ///< Umbral para major GC automatico.

    /// proveedor de raices (stack/regs conservativos + shared  Z).
    /// Set via set_root_provider() en el ctor del ProcessVM.  Si es nullptr
    /// (AOT standalone), el GC omite scan conservativo + shared y usa solo
    /// stackmaps precisos.
    GcRootProvider *root_provider_ = nullptr;

    /// Modo AOT: las raices vienen SOLO de stackmaps precisos (frames nativos
    /// via JitRegistry) + external_refs + pending_alloc.  Cuando es true y NO
    /// hay root_provider_, el GC NO cae al fallback "todo handle = root" (que
    /// nunca colectaria) -> colecta de verdad lo no alcanzable.  Lo activa
    /// libvesta_gc (set_aot_mode).  Sin el flag, un heap sin owner conserva
    /// todo (comportamiento de tests/Inc 0).
    bool aot_precise_roots_ = false;

    /// Boundary del WALK POR TAMANO DE FRAME (scan preciso de AOT).  Lo fija
    /// @c set_aot_scan_boundary en cada runtime-entry del GC que puede
    /// colectar, capturado en la frontera C<-Vesta.  @c aot_boundary_pc_ es el
    /// PC de retorno al frame Vesta y @c aot_boundary_sp_ su RSP antes del @c
    /// call.  Mientras sea valido, @c scan_jit_roots_precise usa @c
    /// scan_aot_frames (frame_size) en vez de la cadena RBP.  Fresco en cada
    /// coleccion (cada entry lo re-fija).
    uint64_t aot_boundary_pc_ = 0;
    uint64_t aot_boundary_sp_ = 0;
    bool aot_boundary_valid_ = false;

    /// Boundary del WALK POR TAMANO DE FRAME para el modo interp+JIT.  Lo fija
    /// @c set_jit_scan_boundary en cada runtime-entry @c vrt_* que puede
    /// colectar y que el codigo JIT llama DIRECTAMENTE, capturado en la
    /// frontera C<-JIT.  Mientras sea valido, @c scan_jit_roots_precise y
    /// @c scan_jit_forwards usan @c scan_aot_frames (frame_size) en vez de la
    /// cadena RBP -> saltan los frames C++ del runtime (que a -O0 la rompen con
    /// @c lea rbp,[rsp+N]).  SEPARADO del boundary AOT para no pisar su estado.
    /// El guard de la runtime-entry lo fija al entrar y lo restaura al salir,
    /// asi que solo es valido durante ESA llamada (evita caminar un frame ya
    /// retornado).  A diferencia del AOT, NO se invalida dentro del scan porque
    /// una sola coleccion puede correr varias fases (minor: roots + forwards;
    /// major: roots) que comparten el mismo frame JIT llamador.
    uint64_t jit_boundary_pc_ = 0;
    uint64_t jit_boundary_sp_ = 0;
    bool jit_boundary_valid_ = false;

    // ---- (iv) Free lists segregadas para slots OldGen liberados ----
    // Cada slot DEAD reusa los primeros 8 bytes de su payload como
    // puntero al siguiente DEAD del mismo size class (LIFO O(1)).
    // Cero memoria extra por slot.  El tamano del slot esta en
    // hdr->size del propio header (ya existe).
    //
    // Hay 16 size classes para slots pequenyos (<=4096 bytes total) y
    // una free list general para slots grandes.  Los size classes
    // se eligieron para minimizar fragmentacion interna en patrones
    // tipicos de objetos Vesta (header 24B + N campos i32/i64).
    struct FreeNode {
        FreeNode *next;
    };
    static constexpr size_t SMALL_CLASS_COUNT = 16;
    static constexpr size_t SMALL_CLASS_SIZES[SMALL_CLASS_COUNT] = {
        16,  24,  32,  48,  64,   96,   128,  192,
        256, 384, 512, 768, 1024, 1536, 2048, 4096};
    FreeNode *small_free_lists_[SMALL_CLASS_COUNT] = {nullptr};

    // Slots con total > 4096: free list general (ptr, total).  Buscamos
    // first-fit lineal; en la practica es corta porque slots grandes
    // son raros.  Si crece mucho, considerar ordered insertion + binary
    // search (mejora futura, no critico en v1).
    struct LargeFree {
        uint8_t *ptr;
        size_t total;
    };
    std::vector<LargeFree> large_free_list_;

    // --- HandleTable ---
    HandleTable handles_; ///< Tabla propia (POD) -- JIT inline-friendly.
    std::vector<GcHandle>
        free_handles_; ///< Freelist LIFO de slots reciclables.

    /// Mapa inverso payload_ptr_host -> GcHandle.  Permite lookup O(1)
    /// cuando un objeto se accede por su host pointer pero se necesita
    /// el handle (caso: synchronized en Vesta, donde @c this es host_ptr
    /// pero @c monenter requiere GcHandle).  Se mantiene incrementalmente:
    ///   - new_handle()    => insert(addr+sizeof(GcHeader), h)
    ///   - release_handle() => erase
    ///   - do_evacuate()   => erase old + insert new tras mover el objeto
    /// El payload pointer es estable mientras el objeto no se evacue.
    /*  D.7.opt: reemplazado @c std::unordered_map por un flat
     * hash map open-addressing para el hot path del GC (new_handle/
     * release_handle ~20-30 ns -> ~5 ns por op). */
    PtrHandleMap ptr_to_handle_;

    // --- Finalizadores GC ---
    /// El kind del finalizador vive en el GcHeader (has_finalizer +
    /// finalizer_kind), no en una side-table -> freestanding-safe + zero
    /// overhead para objetos sin recurso (no llevan el bit).
    /// Cola de finalizadores STAGEADOS durante el sweep, pendientes de ejecutar
    /// en un safe point FUERA del GC (el sweep copia los datos del box antes de
    /// que su memoria se reclame; el drenado no vuelve a leer el box).
    std::vector<GcPendingFinalizer> pending_finalizers_;
    /// Helper: stagea un objeto colectado con recurso interno.  Lee el box (aun
    /// valido en el sweep) y encola sus datos.  Limpia el bit has_finalizer.
    void stage_finalizer(GcHeader *hdr, uint8_t *payload);
    /// Callback que ejecuta un finalizador (interp reentry en VM, call nativo
    /// en AOT).  nullptr = descartar (solo posible pre-init).
    GcFinalizerRunner finalizer_runner_ = nullptr;
    /// Contexto opaco pasado al runner (ProcessVM* en la VM).
    void *finalizer_owner_ = nullptr;
    /// Guard de reentrada: true mientras @c run_pending_finalizers drena.  Un
    /// GC disparado dentro de un finalizador NO re-drena (solo encola mas).
    bool finalizing_ = false;
    /// Side-table payload_host_ptr -> dtor_vaddr para finalizadores CLASS_DTOR
    /// (gc<Clase> con ~Clase()).  A diferencia de UNIQUE/SHARED (cuyo deleter
    /// vive DENTRO del box en slot+8 / control block), la instancia de clase no
    /// lleva el vaddr del dtor inline -- lo guardamos aqui al registrar.  El
    /// sweep lo lee para stagear (a0=dtor_vaddr) y borra la entrada.  Solo se
    /// usa para gc<Clase> con dtor (raro); no afecta el hot path del GC.
    ///
    /// Freestanding-safe: se usa @c U64U64Map (hash open-addressing propio, no
    /// @c unordered_map, que arrastra libstdc++).  El libvesta_gc AOT lo
    /// compila igual que la VM, asi que el finalizador CLASS_DTOR resuelve el
    /// dtor por el MISMO camino en interp/JIT/AOT (cierra la fuga de gc<Clase>
    /// con ~Clase() en AOT).  register/unregister/stage son O(1) amortizado
    /// (antes O(n) con busqueda lineal -> O(n^2) agregado con muchos
    /// gc<Clase>).
    /// A QUIEN llamar al finalizar, por objeto: el destructor de una clase o
    /// el liberador de un `unique`.  Los dos lo saben al COMPILAR -- uno por la
    /// clase y el otro por el TIPO del puntero --, asi que lo dejan puesto al
    /// registrar en vez de que el box tenga que llevarlo dentro.
    U64U64Map finalizer_target_;

    // --- Tabla de referencias debiles ---
    std::vector<WeakEntry>
        weak_table_; ///< Referencias debiles indexadas por uint32_t.

    // --- Colas de espera de monitores (LOCAL per-process) ---
    // Clave: GcHandle del objeto con el monitor ocupado.
    // Valor: lista FIFO de PID codificados ((scheduler_id<<32)|local_pid)
    // esperando.
    // Vestigial: el waiting real lo gestiona @c wait_table_ (WaitTable
    // lock-free).  Se mantiene solo en el build de la VM (no en el freestanding
    // de libvesta_gc, que no usa monitores) para no romper ABI/compat.
#if !defined(VESTA_GC_FREESTANDING)
    std::unordered_map<GcHandle, std::vector<uint64_t>> monitor_waiters_;
#endif

    // Wait queues lock-free per-bucket para objetos GC LOCALES.
    // Para objetos shared (handle con SHARED_HANDLE_BIT) se enruta a
    // @c vm.shared_wait_table via @c wait_table_for().
    WaitTable wait_table_;

    /// Devuelve la WaitTable apropiada para @p h: la local del heap si
    /// el handle es local, o la global del VM si es shared.
    inline WaitTable &wait_table_for(GcHandle h) noexcept;

    // --- RememberedSet ---
    /// Conjunto open-addressing (no @c std::unordered_set): cache-friendly +
    /// sin la dep libstdc++ _Prime_rehash_policy (freestanding).  Universal.
    GcHandleSet remembered_set_; ///< Handles OLD con referencias a YOUNG.

    // --- Tabla de forwarding pointers (Cheney-style) ---
    /// Mapa <young_payload_addr, old_payload_addr> poblado por do_evacuate
    /// cuando un objeto YoungGen se mueve a OldGen.  Sirve para que
    /// `update_stack_forwards` (llamado al final de minor_gc) recorra
    /// el stack del proceso y los GP regs, y reemplace cada slot que
    /// contenga un host_ptr a YoungGen evacuada por su nuevo address
    /// en OldGen (estable, non-moving).
    ///
    /// Sin esto, los locales del bytecode que mantienen host_ptrs a
    /// objetos CLASS (resultado de `gcderef` tras NEWOBJ) quedan
    /// dangling tras un minor_gc que evacua sus objetos -> SEGFAULT
    /// al siguiente field access.  La alternativa (mantener handles
    /// en lugar de host_ptrs) costaria 1 gcderef por field access.
    ///
    /// Se vacia al final de cada minor_gc.  Coste por GC:
    /// O(num_evacuated_objects) inserts + O(stack_size_bytes/8) lookups.
    /// Mapa open-addressing (no @c std::unordered_map): cache-friendly + sin la
    /// dep libstdc++ _Prime_rehash_policy (freestanding).  Universal.
    PtrPtrMap forward_table_;

    // --- External roots (write-barrier para colecciones nativas) ---
    /// Handles GC referenciados por estructuras nativas (ej. ArrayList<string>
    /// en el plugin vesta_collections).  Cada @c gc_addref incrementa el
    /// contador, @c gc_release lo decrementa.  Durante el mark phase,
    /// cualquier handle con refcount > 0 se trata como root vivo aunque
    /// no este referenciado por roots normales (HandleTable bytecode).
    ///
    /// Necesario porque el GC no escanea los slots internos del plugin
    /// (struct opaco desde el punto de vista del runtime).  Sin este
    /// mecanismo, un string almacenado solo en `xs.push(s)` quedaria
    /// invalidado al primer GC tras que el local que tenia s salga de
    /// scope.
    ///
    /// La entrada se elimina cuando el counter llega a 0 (lazy cleanup
    /// para evitar fragmentar el bucket de la hashmap).
    /// Mapa open-addressing custom (no @c std::unordered_map): cache-friendly,
    /// sin malloc por nodo, y sin la dep de libstdc++ @c _Prime_rehash_policy
    /// (clave para libvesta_gc freestanding).  Mismo tipo en VM y AOT.
    GcHandleRefMap external_refs_;

    // --- Estadisticas ---
    GcStats stats_;

    /**
     * @brief Crea un nuevo handle apuntando a @p addr.
     * Reutiliza un slot libre si existe; si no, anade uno nuevo al vector.
     */
    GcHandle new_handle(uint8_t *addr);

    /**
     * @brief Marca el handle @p h como libre y lo recicla en free_handles_.
     * No libera la memoria del objeto.
     */
    void release_handle(GcHandle h);

    /**
     * @brief Asigna @p total_bytes en OldGen.  Wrapper compatible que
     *        descarta el slot_total real (lo usa @c do_evacuate que ya
     *        copia exactamente el tamano original via @c hdr->size).
     *
     * @param total_bytes Tamano total incluyendo GcHeader y padding.
     * @return Puntero al inicio del slot, o nullptr si OOM.
     */
    uint8_t *alloc_in_old(size_t total_bytes);

    /**
     * @brief Variante de @c alloc_in_old que reporta el tamano real del slot.
     *
     * (iv) GC no-moving: el slot devuelto puede ser MAYOR que @p total_bytes
     * cuando se redondea al size class.  El llamante (alloc()) necesita
     * el tamano real para escribirlo en @c hdr->size, asi al re-free
     * el slot encaja exactamente en su size class.
     *
     * Orden de busqueda (todas O(1) excepto large freelist):
     *   1. Free list segregada del size class >= total_bytes.
     *   2. Free list large (slots >4096) con first-fit.
     *   3. Bump pointer en algun OldBlock con espacio.
     *   4. Crear bloque nuevo via ArenaManager.
     *
     * @param total_bytes      Tamano minimo requerido (header + payload + pad).
     * @param out_actual_total [out] Tamano real del slot devuelto (>=
     * total_bytes).
     * @return Puntero al inicio del slot, o nullptr si OOM.
     */
    uint8_t *alloc_in_old_with_total(size_t total_bytes,
                                     size_t &out_actual_total);

    /**
     * @brief Evacua el objeto referenciado por @p h de Nursery a OldGen.
     *
     * Si el objeto ya es BLACK o ya esta en OldGen, no hace nada.
     * Tras la evacuacion: el handle apunta al nuevo slot en OldGen,
     * el objeto original se marca BLACK (forward pointer en payload),
     * y se actualizan las estadisticas de promocion.
     *
     * @param h Handle del objeto a evacuar.
     */
    void do_evacuate(GcHandle h);

    /**
     * @brief Evacua el objeto referenciado por @p h de Nursery a OldGen.
     *
     * Wrapper que comprueba addr != nullptr antes de delegar en do_evacuate().
     * Los objetos ya en OldGen o ya marcados BLACK son ignorados.
     */
    void evacuate_object(GcHandle h);

    /**
     * @brief Escanea el payload del objeto @p h buscando handles YOUNG y los
     * evacua.
     *
     * Cada palabra de 4 bytes del payload se interpreta como potencial
     * GcHandle. Si apunta a un objeto YOUNG no evacuado, llama a do_evacuate()
     * y lo anade al worklist para escaneo transitivo posterior (Cheney-style).
     */
    void scan_young_refs(GcHandle h, std::vector<GcHandle> &worklist);

    /**
     * @brief Marca transitivamente todos los objetos OLD alcanzables desde @p
     * h.
     *
     * Escanea el payload de @p h. Si alguna palabra de 4 bytes es un handle
     * valido con addr != nullptr que apunta a un objeto OLD WHITE, lo marca
     * BLACK y lo anade al worklist para propagacion.
     */
    void mark_reachable(GcHandle h, std::vector<GcHandle> &worklist);

    // ---- (iv) Helpers de free list segregada ----

    /**
     * @brief Devuelve el indice del size class cuyo SIZE >= @p total.
     *
     * Para alloc: redondeo HACIA ARRIBA al primer class capaz de
     * contener @p total bytes.  Devuelve @c SMALL_CLASS_COUNT si
     * @p total > 4096 (slot grande, va a la free list general).
     */
    static size_t size_class_ceil(size_t total) noexcept;

    /**
     * @brief Inserta un slot DEAD en la free list correspondiente.
     *
     * Si total esta en rango small, usa el size class exacto (que
     * encaja con el slot porque alloc_in_old siempre redondea al class).
     * Si es grande, va a @c large_free_list_.  El slot se identifica
     * por el puntero al GcHeader y su total (header + payload + pad).
     *
     * Asume que @p hdr->size ya refleja el tamano completo del payload
     * del slot (no el pedido por el usuario).
     */
    void freelist_push(uint8_t *raw_header, size_t total);

    /**
     * @brief Vacia las free lists.  Se llama al inicio de cada sweep
     *        para reconstruirlas desde scratch (los slots DEAD se
     *        reinsertan al recorrer los bloques).
     *
     * No libera memoria; solo limpia los heads.  Los nodos viven
     * embebidos en los slots y se sobrescribiran al re-push.
     */
    void freelist_clear() noexcept;

    /**
     * @brief Compactacion mark-compact SLIDING in-place del OldGen.
     *
     * Desliza los objetos vivos (BLACK) hacia el inicio de su bloque,
     * eliminando los huecos de los objetos colectados (WHITE) y de los slots
     * ya DEAD.  Copia ESCALAR (@c memmove; sin SIMD).  Cero memoria extra: se
     * compacta EN EL MISMO espacio (no hay segundo semispace).  Reemplaza al
     * sweep cuando corre (el caller no debe barrer despues).
     *
     * Correccion del moving: los handles son ESTABLES (indices en la
     * HandleTable), asi que mover un objeto solo requiere actualizar
     * @c handles_[h].addr; las referencias-handle embebidas en los payloads NO
     * cambian.  Las UNICAS referencias crudas a payloads (host_ptrs) viven en
     * las raices del interprete (pila + regs del VM) y se reescriben aqui via
     * remap por rango de slot (cubre punteros al inicio del payload y punteros
     * interiores tipo STRRAW).  El mapa inverso @c ptr_to_handle_ se actualiza
     * al mover.
     *
     * SOLO es correcto para el camino INTERPRETE (fields = GcHandle).  El
     * caller
     * (@c major_gc) restringe su uso a ese camino (ver "GATE" alli): NO corre
     * en AOT (native_poo: los fields guardan host_ptrs crudos, sin tabla de
     * handles -> haria falta un field-map que no existe) ni con frames nativos
     * JIT activos (host_ptrs en la pila nativa sin reescritura implementada).
     *
     * @return true si compacto (el caller NO debe barrer); false si no aplica
     *         (fragmentacion por debajo del umbral, o abortado por seguridad)
     *         -> el caller corre el sweep normal.
     */
    bool compact_old_gen();

    /**
     * @brief Compactacion mark-compact del OldGen en modo AOT (libvesta_gc).
     *
     * Igual que @c compact_old_gen pero para native_poo (AOT), donde los
     * campos-referencia guardan host_ptrs CRUDOS (no GcHandles) y las raices
     * viven en la pila NATIVA (no en vm_mem).  Reescribe: (a) las raices via
     * @c scan_aot_frames (stackmaps) y (b) los punteros internos de cada objeto
     * vivo via su field-map (descriptor de tipo en obj[0]).  Copia escalar
     * (memmove).  Freestanding-safe.  OPT-IN (VESTA_GC_COMPACT_ALWAYS).
     *
     * @return true si compacto; false si no aplica -> el caller barre normal.
     */
    bool compact_old_gen_aot();
};
} // namespace gc

#endif // GC_HEAP_H
