/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/host_allocator.cpp
 * @brief Implementacion del asignador propio.  Los motivos, en la cabecera.
 */
#include "util/env_flags.h"
#include "util/host_allocator.h"

#include "util/thread_slot.h"

#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <new>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace util {

namespace {

// =========================================================================
//  Parametros
// =========================================================================

/**
 * @brief Mayor reserva que sirve el asignador; por encima va al sistema.
 *
 * Subido de 1 KiB a 2 KiB con la cuenta delante.  Con el tope en 1 KiB, 420.219
 * reservas se iban al sistema y costaban 0,476 s entre `malloc` y `free` --
 * **1,13 us por par** --, mientras las 43,9 millones que serviamos nosotros
 * iban a 5,5 ns.  Cada reserva grande costaba unas doscientas veces lo que una
 * pequena.
 *
 * POR QUE 2 KiB Y NO MAS.  Subir el tope tiene un precio en memoria, porque
 * este asignador NO devuelve nada al sistema mientras que el `malloc` del
 * sistema si suele devolver los bloques grandes.  Medida la curva entera:
 *
 *     tope    tiempo    pico de memoria
 *     1 KiB   ref.      779 MB
 *     2 KiB   -3,2%     788 MB   (+1,1%)
 *     4 KiB   -4,7%     836 MB   (+7,3%)
 *     8 KiB   empate    837 MB   (+7,4%)
 *
 * 2 KiB da casi toda la ganancia por la septima parte del coste.  Y de 8 KiB
 * hacia arriba ya no hay ganancia ninguna, que es lo esperable: pasada la
 * pagina de 4 KiB lo que se pide son paginas completas, y trocearlas en clases
 * dentro de un trozo solo anade desperdicio -- el sistema ya sabe entregar
 * paginas.
 */
constexpr size_t kMaxSmall = 2048;

/// Alineacion que garantiza `operator new` para cualquier tipo.
constexpr size_t kAlign = 16;

/**
 * @brief Clases de tamano.
 *
 * Paso de 16 bytes abajo y mas grueso arriba: lo que mas se pide son objetos
 * pequenos (un par de 32 bytes, un nodo de tabla), donde desperdiciar 16 bytes
 * ya es mucho, mientras que arriba las reservas son raras y el desperdicio
 * relativo es menor.  El mayor desperdicio interno queda en el 14%.
 */
constexpr uint32_t kSizes[] = {
    16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512,
    640, 768, 896, 1024,
    // De 1 KiB a 2 KiB el paso se abre un poco: son el 0,5% de las reservas,
    // asi que el desperdicio por redondeo pesa poco.  El mayor queda en un
    // 15% (1.537 bytes van a una clase de 1.792).
    1152, 1280, 1408, 1536, 1792, 2048};
constexpr uint32_t kClasses = sizeof(kSizes) / sizeof(kSizes[0]);

/// Trozo que se pide a la region cada vez que una clase se queda sin bloques.
constexpr size_t kChunkBytes = 64 * 1024;

/// Region virtual que se reserva de una vez.  Reservar NO es gastar: solo se
/// entrega memoria de verdad (commit) trozo a trozo segun hace falta.
constexpr size_t kRegionBytes = size_t(1) << 30; // 1 GiB

/// Tope de hilos con listas propias.  Al pasarse, ese hilo va al sistema.
constexpr uint32_t kMaxThreads = 64;

/// Marca de la cabecera de trozo, para no confundirla con nada.
constexpr uint32_t kChunkMagic = 0x56455354u; // 'VEST'

/// Topes del reparto de tamanos (solo con VESTA_HOST_ALLOC_STATS=1).
constexpr size_t kBucketLimit[] = {64,   256,  1024,  2048,
                                   4096, 8192, 16384, ~size_t(0)};
constexpr uint32_t kSizeBuckets =
    sizeof(kBucketLimit) / sizeof(kBucketLimit[0]);

// =========================================================================
//  Estado
// =========================================================================

/**
 * @brief Cabecera al principio de cada trozo.
 *
 * Ocupa una alineacion completa para que los bloques que van detras sigan
 * alineados a 16.  De aqui sale, con solo enmascarar el puntero, TODO lo que
 * hace falta para liberar: de que tamano es y de quien es.
 */
struct alignas(kAlign) ChunkHeader {
    uint32_t magic;
    uint32_t cls;
    uint32_t owner;
    uint32_t _pad;
};
static_assert(sizeof(ChunkHeader) == kAlign,
              "la cabecera descuadra los bloques");

/// Listas libres de un hilo.  Todo POD: se inicializa a cero sin codigo.
struct ThreadCache {
    void *free_list[kClasses];
    uint32_t id;
    bool used;
    HostAllocStats stats;
};

ThreadCache g_caches[kMaxThreads];
std::atomic<uint32_t> g_next_id{0};
ThreadSlot g_cache_slot;

/**
 * @brief Lo que otros hilos han soltado y su dueno todavia no ha recogido.
 *
 * Una pila atomica por (dueno, clase).  Quien libera algo ajeno empuja aqui con
 * un `compare_exchange` -- sin bloquear a nadie -- y el dueno se lleva la pila
 * ENTERA de un golpe cuando se queda sin bloques.  Es lo que hace que liberar
 * entre hilos no cueste ni fugue.
 */
std::atomic<void *> g_remote[kMaxThreads][kClasses];

std::atomic<uintptr_t> g_region_base{0};
std::atomic<uintptr_t> g_region_end{0};
std::atomic<size_t> g_chunk_next{0};
/// 0 sin tocar, 1 montandose, 2 lista, 3 no se pudo.
std::atomic<int> g_region_state{0};

/// 0 sin mirar, 1 activo, 2 apagado por entorno.
std::atomic<int> g_active_state{0};

/// Si se lleva el reparto de tamanos.  Se mira una vez; contar no puede salir
/// gratis, pero NO contar si.
bool g_measure = false;

/**
 * @brief Vuelca el reparto al terminar, si se pidio.
 *
 * Sin destructor no hay donde imprimirlo: los contadores viven en memoria
 * estatica que nadie recorre.  No esta en ningun camino caliente.
 */
struct StatsDump {
    ~StatsDump();
};
StatsDump g_stats_dump;

// =========================================================================
//  Utilidades
// =========================================================================

/// Tabla de tamano -> clase, en pasos de 16 bytes.  Un acceso, sin ramas.
uint8_t g_class_of[(kMaxSmall / kAlign) + 1];
std::atomic<bool> g_class_table_ready{false};

void build_class_table() noexcept {
    for (size_t step = 0; step <= kMaxSmall / kAlign; ++step) {
        const size_t want = step * kAlign;
        uint8_t k = 0;
        while (k + 1 < kClasses && kSizes[k] < want)
            ++k;
        g_class_of[step] = k;
    }
    g_class_table_ready.store(true, std::memory_order_release);
}

inline uint32_t class_of(size_t n) noexcept {
    return g_class_of[(n + kAlign - 1) / kAlign];
}

bool allocator_active() noexcept {
    const int s = g_active_state.load(std::memory_order_acquire);
    if (s != 0) return s == 1;
    /* Se deja APAGADO antes de preguntar al entorno: si `getenv` pidiera
     * memoria por dentro, esa peticion entraria aqui otra vez y se quedaria
     * dando vueltas.  Asi lo peor que pasa es que la primera reserva vaya al
     * sistema. */
    g_active_state.store(2, std::memory_order_release);
    /* A PELO, y no por el registro de mandos (`util/env_flags.h`), aunque los
     * dos esten declarados alli.
     *
     * El registro guarda el valor de los 167 mandos en cadenas, asi que
     * consultarlo la primera vez PIDE MEMORIA -- y pedir memoria entra aqui.
     * Con el estatico del registro a medio construir, esa reentrada se queda
     * esperando su guarda para siempre: el proceso cuelga antes de llegar a
     * `main`.  Costo encontrarlo.
     *
     * Es el mismo motivo que ya decia el comentario de arriba sobre `getenv`,
     * llevado un paso mas: quien resuelve las reservas no puede apoyarse en
     * nada que reserve. */
    const char *no_slab = std::getenv("VESTA_NO_HOST_SLAB");
    const bool off = no_slab != nullptr && no_slab[0] != '\0' &&
                     !(no_slab[0] == '0' && no_slab[1] == '\0');
    const char *stats = std::getenv("VESTA_HOST_ALLOC_STATS");
    g_measure = stats != nullptr && stats[0] != '\0' &&
                !(stats[0] == '0' && stats[1] == '\0');
    if (!off) {
        build_class_table();
        g_active_state.store(1, std::memory_order_release);
    }
    return !off;
}

/// Reserva (que no gasta) la region de la que salen todos los trozos.
bool ensure_region() noexcept {
    int s = g_region_state.load(std::memory_order_acquire);
    if (s == 2) return true;
    if (s == 3) return false;
    int expected = 0;
    if (!g_region_state.compare_exchange_strong(expected, 1,
                                                std::memory_order_acq_rel,
                                                std::memory_order_acquire)) {
        // Otro lo esta montando: se espera a que acabe.
        while ((s = g_region_state.load(std::memory_order_acquire)) == 1) {
        }
        return s == 2;
    }
    /* Aqui NO vale `vm::allocate_memory`, que es la capa portable del proyecto
     * y lo que usa la arena de fase.  Esa entrega memoria ya COMPROMETIDA, y lo
     * que hace falta en este punto es lo contrario: apalabrar un rango grande
     * de direcciones SIN gastar memoria, y entregarla trozo a trozo segun se
     * pide.  De esa reserva sale la propiedad que hace barato liberar -- saber
     * si un puntero es nuestro son dos comparaciones --, asi que no es un
     * detalle que se pueda ceder.
     *
     * Si algun dia hace falta en mas sitios, lo suyo es anadir reservar y
     * comprometer por separado a `vm::`, no repetir esto. */
#if defined(_WIN32)
    void *base =
        VirtualAlloc(nullptr, kRegionBytes, MEM_RESERVE, PAGE_READWRITE);
#else
    void *base = mmap(nullptr, kRegionBytes, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (base == MAP_FAILED) base = nullptr;
#endif
    if (base == nullptr) {
        g_region_state.store(3, std::memory_order_release);
        return false;
    }
    /* Los trozos se localizan enmascarando el puntero, asi que la base tiene
     * que estar alineada al tamano de trozo.  Windows ya reserva alineado a
     * 64 KiB; fuera de Windows se redondea hacia arriba y se pierde como mucho
     * un trozo. */
    uintptr_t b = reinterpret_cast<uintptr_t>(base);
    const uintptr_t aligned =
        (b + kChunkBytes - 1) & ~(uintptr_t)(kChunkBytes - 1);
    g_region_base.store(aligned, std::memory_order_relaxed);
    g_region_end.store(b + kRegionBytes, std::memory_order_relaxed);
    g_region_state.store(2, std::memory_order_release);
    return true;
}

inline bool in_region(const void *p) noexcept {
    const uintptr_t v = reinterpret_cast<uintptr_t>(p);
    return v >= g_region_base.load(std::memory_order_relaxed) &&
           v < g_region_end.load(std::memory_order_relaxed);
}

inline ChunkHeader *chunk_of(void *p) noexcept {
    return reinterpret_cast<ChunkHeader *>(reinterpret_cast<uintptr_t>(p) &
                                           ~(uintptr_t)(kChunkBytes - 1));
}

/// El cache de ESTE hilo; lo da de alta la primera vez.
ThreadCache *cache() noexcept {
    if (!g_cache_slot.ensure()) return nullptr;
    ThreadCache *c = static_cast<ThreadCache *>(g_cache_slot.get());
    if (c != nullptr) return c;
    const uint32_t id = g_next_id.fetch_add(1, std::memory_order_acq_rel);
    if (id >= kMaxThreads) return nullptr; // demasiados hilos: al sistema
    c = &g_caches[id];
    c->id = id;
    c->used = true;
    g_cache_slot.set(c);
    return c;
}

/// Recoge de un golpe lo que otros hilos soltaron de esta clase.
void *take_remote(ThreadCache *c, uint32_t k) noexcept {
    void *head =
        g_remote[c->id][k].exchange(nullptr, std::memory_order_acq_rel);
    return head;
}

/// Pide un trozo nuevo y lo parte en bloques de la clase @p k.
void *grow(ThreadCache *c, uint32_t k) noexcept {
    if (!ensure_region()) return nullptr;
    const size_t idx = g_chunk_next.fetch_add(1, std::memory_order_acq_rel);
    const uintptr_t base = g_region_base.load(std::memory_order_relaxed);
    const uintptr_t addr = base + idx * kChunkBytes;
    if (addr + kChunkBytes > g_region_end.load(std::memory_order_relaxed))
        return nullptr; // region agotada: se sigue con el sistema
#if defined(_WIN32)
    void *got = VirtualAlloc(reinterpret_cast<void *>(addr), kChunkBytes,
                             MEM_COMMIT, PAGE_READWRITE);
    if (got == nullptr) return nullptr;
#else
    if (mprotect(reinterpret_cast<void *>(addr), kChunkBytes,
                 PROT_READ | PROT_WRITE) != 0)
        return nullptr;
#endif
    ChunkHeader *h = reinterpret_cast<ChunkHeader *>(addr);
    h->magic = kChunkMagic;
    h->cls = k;
    h->owner = c->id;
    h->_pad = 0;

    const size_t slot = kSizes[k];
    const size_t count = (kChunkBytes - sizeof(ChunkHeader)) / slot;
    uintptr_t first = addr + sizeof(ChunkHeader);
    // Se encadenan al reves para que el primero que se entregue sea el de
    // menor direccion: recorre la memoria hacia delante, que es lo que le
    // gusta al prefetcher.
    void *head = nullptr;
    for (size_t i = count; i-- > 0;) {
        void *s = reinterpret_cast<void *>(first + i * slot);
        *reinterpret_cast<void **>(s) = head;
        head = s;
    }
    c->stats.chunks++;
    c->stats.bytes_reserved += kChunkBytes;
    return head;
}

} // namespace

// =========================================================================
//  Interfaz
// =========================================================================

/// Sirve @p n bytes.  nullptr solo si tampoco pudo el sistema.
void *host_alloc(size_t n) noexcept {
    if (!allocator_active()) return std::malloc(n);
    if (n == 0) n = 1;
    ThreadCache *c = cache();
    if (c != nullptr && g_measure) {
        // Reparto de tamanos pedidos.  Sirve para UNA pregunta concreta: si lo
        // que se pide cae fuera de las clases, subir el tope da mas de lo que
        // cuesta; si no, no.
        uint32_t b = 0;
        while (b + 1 < kSizeBuckets && n > kBucketLimit[b])
            ++b;
        c->stats.size_hist[b]++;
    }
    if (n > kMaxSmall || c == nullptr) {
        if (c != nullptr) c->stats.large_allocs++;
        return std::malloc(n);
    }
    const uint32_t k = class_of(n);
    void *p = c->free_list[k];
    if (p == nullptr) {
        p = take_remote(c, k);
        if (p == nullptr) p = grow(c, k);
        if (p == nullptr) return std::malloc(n);
    }
    c->free_list[k] = *reinterpret_cast<void **>(p);
    c->stats.small_allocs++;
    return p;
}

/// Devuelve @p p.  Vale aunque lo reservara otro hilo.
void host_free(void *p) noexcept {
    if (p == nullptr) return;
    if (!in_region(p)) {
        std::free(p);
        return;
    }
    ChunkHeader *h = chunk_of(p);
    if (h->magic != kChunkMagic) {
        // No deberia pasar: dentro de la region todo trozo tiene su marca.  Se
        // prefiere fugar un bloque a corromper una lista.
        return;
    }
    ThreadCache *c = cache();
    if (c != nullptr && h->owner == c->id) {
        *reinterpret_cast<void **>(p) = c->free_list[h->cls];
        c->free_list[h->cls] = p;
        c->stats.small_frees++;
        return;
    }
    // De otro hilo: a su pila, sin bloquear a nadie.
    std::atomic<void *> &head = g_remote[h->owner][h->cls];
    void *old = head.load(std::memory_order_relaxed);
    do {
        *reinterpret_cast<void **>(p) = old;
    } while (!head.compare_exchange_weak(old, p, std::memory_order_release,
                                         std::memory_order_relaxed));
    if (c != nullptr) c->stats.remote_frees++;
}

HostAllocStats host_alloc_stats() {
    HostAllocStats t;
    for (uint32_t i = 0; i < kMaxThreads; ++i) {
        if (!g_caches[i].used) continue;
        const HostAllocStats &s = g_caches[i].stats;
        t.small_allocs += s.small_allocs;
        t.small_frees += s.small_frees;
        t.remote_frees += s.remote_frees;
        t.large_allocs += s.large_allocs;
        t.chunks += s.chunks;
        t.bytes_reserved += s.bytes_reserved;
        for (uint32_t b = 0; b < kSizeBuckets; ++b)
            t.size_hist[b] += s.size_hist[b];
    }
    return t;
}

bool host_alloc_active() {
    return allocator_active();
}

namespace {

StatsDump::~StatsDump() {
    if (!g_measure) return;
    const HostAllocStats s = host_alloc_stats();
    std::fprintf(
        stderr,
        "[asignador] pequenas=%llu sueltas=%llu ajenas=%llu "
        "grandes=%llu trozos=%llu\n",
        (unsigned long long)s.small_allocs, (unsigned long long)s.small_frees,
        (unsigned long long)s.remote_frees, (unsigned long long)s.large_allocs,
        (unsigned long long)s.chunks);
    static const char *kNames[kSizeBuckets] = {
        "<=64", "<=256", "<=1K", "<=2K", "<=4K", "<=8K", "<=16K", ">16K"};
    uint64_t total = 0;
    for (uint32_t b = 0; b < kSizeBuckets; ++b)
        total += s.size_hist[b];
    if (total == 0) return;
    std::fprintf(stderr, "[asignador] reparto de tamanos pedidos:\n");
    for (uint32_t b = 0; b < kSizeBuckets; ++b)
        std::fprintf(stderr, "    %-6s %10llu  %5.1f%%\n", kNames[b],
                     (unsigned long long)s.size_hist[b],
                     100.0 * double(s.size_hist[b]) / double(total));
}

} // namespace

} // namespace util

// =========================================================================
//  operator new / delete globales
// =========================================================================
//
// Se reemplazan los del sistema para que TODO el proceso -- cada `std::vector`,
// cada cadena, cada nodo de tabla -- pase por aqui.  Es lo que hace que el
// cambio valga: en el perfil las reservas no estaban concentradas en ningun
// sitio, asi que solo se ganaba tocandolas todas a la vez.

void *operator new(size_t n) {
    void *p = util::host_alloc(n);
    if (p == nullptr) throw std::bad_alloc();
    return p;
}
void *operator new[](size_t n) {
    void *p = util::host_alloc(n);
    if (p == nullptr) throw std::bad_alloc();
    return p;
}
void *operator new(size_t n, const std::nothrow_t &) noexcept {
    return util::host_alloc(n);
}
void *operator new[](size_t n, const std::nothrow_t &) noexcept {
    return util::host_alloc(n);
}

void operator delete(void *p) noexcept {
    util::host_free(p);
}
void operator delete[](void *p) noexcept {
    util::host_free(p);
}
void operator delete(void *p, size_t) noexcept {
    util::host_free(p);
}
void operator delete[](void *p, size_t) noexcept {
    util::host_free(p);
}
void operator delete(void *p, const std::nothrow_t &) noexcept {
    util::host_free(p);
}
void operator delete[](void *p, const std::nothrow_t &) noexcept {
    util::host_free(p);
}
