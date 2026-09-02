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
/**
 * @file gc_heap.cpp
 * @brief Implementacion del heap generacional con GC tri-color de VestaVM.
 *
 * Implementa @c gc::GCHeap: asignacion en nursery, promocion a old-gen,
 * ciclos de recoleccion mayor/menor, write-barrier y las fases del algoritmo
 * tri-color mark-and-sweep (blanco/gris/negro).
 */
#include "gc/gc_heap.h"

#include "jit/jit_registry.h"
#include "jit/stack_scan.h"
// Inc 0b: gc_heap.cpp YA NO depende de ProcessVM/runtime.  El acceso al
// stack/regs del owner + la sincronizacion shared ( Z) se hacen via la
// interfaz GcRootProvider (gc_heap.h); el runtime aporta la impl.  Esto permite
// compilar el GC como .o freestanding (libvesta_gc) sin arrastrar la VM.
#include "gc/shared_handle_table.h" //  Z: SHARED_HANDLE_BIT
#include "loader/oop_types.h"

#include <cstring>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <algorithm>
#ifdef _WIN32
#include <io.h> // _write, _fileno
#define GC_DBG_WRITE _write
#define GC_DBG_FILENO _fileno
#else
#include <unistd.h> // write
#define GC_DBG_WRITE ::write
#define GC_DBG_FILENO fileno
#endif

// Limites del stack NATIVO del hilo actual, necesarios para acotar el walk de
// frames JIT (evita derefs fuera de rango cuando la cadena RBP no es fiable, p.
// ej. binarios compilados con -fomit-frame-pointer).  Solo en el build de la VM
// (freestanding/AOT usa scan_aot_frames por tamano de frame, no la cadena RBP).
#if !defined(VESTA_GC_FREESTANDING)
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h> // GetCurrentThreadStackLimits
#elif defined(__linux__) || defined(__GLIBC__)
#include <pthread.h> // pthread_getattr_np, pthread_attr_getstack
#endif
#endif

namespace gc {

// -------------------------------------------------------------------------
// Sistema de debug runtime del GC.
//
// Diseno orientado a CERO overhead en builds release con debug OFF:
//
//   1. Inicializacion via STATIC INITIALIZER (una vez antes de main).
//      Nada de lazy-init en cada call -- el env var se lee una vez al
//      cargar la libreria y `g_gc_debug` queda con su valor final.
//      `set_gc_debug()` desde CLI sobreescribe el valor (mismo global,
//      sin race porque GC es per-process single-threaded).
//
//   2. Macros LEEN EL GLOBAL DIRECTAMENTE (sin function call).  El
//      compilador ve un simple `if (variable) { ... }` y aplica todas
//      las optimizaciones posibles: hoisting fuera de loops, branch
//      layout con cold path, etc.
//
//   3. Hint de branch via `__builtin_expect(..., 0)` indica al compilador
//      que el path de log es FRIO (debug usualmente off).  GCC/Clang
//      colocan el codigo de fprintf en una pagina separada del hot path,
//      mejorando cache de instrucciones.
//
//   4. Compile-time disable: -DVESTA_GC_DEBUG_DISABLE convierte las
//      macros en no-op total.  Para builds donde se quiere CERO bytes
//      de codigo del subsistema de debug.  Default (sin define) deja
//      el sistema activable en runtime.
//
// Coste cuando debug esta OFF (default):
//   - 1 load de g_gc_debug (cacheable en L1, ~1 ciclo)
//   - 1 compare + branch predicho (~1 ciclo)
//   - Total: ~2 ciclos por trace point, fuera del hot path del programa
//     porque las macros solo viven en codigo del GC, no en bytecode exec.
//
// Coste cuando debug esta ON: dominado por fprintf+fflush (~10 us/linea
// en SSD, mucho mas lento que el branch).  Dominio de I/O, no overhead
// del sistema de debug en si.
// -------------------------------------------------------------------------

namespace {
// Inicializacion via lambda en static initializer: corre UNA vez
// antes de main(), lee VESTA_GC_DEBUG, y deja el global con valor
// final.  No hay lazy check en hot path.
bool g_gc_debug = []() noexcept -> bool {
    const char *env = std::getenv("VESTA_GC_DEBUG");
    return (env != nullptr && env[0] != '\0' && env[0] != '0');
}();

// Modo BUFFERED: acumula trazas en un buffer thread-local de 64 KB
// y las escribe en bulk cuando el buffer se llena.  Activable via
// env VESTA_GC_DEBUG_BUFFERED=1 o via gc::set_gc_debug_buffered().
// Coste: ~100x mas rapido que el modo unbuffered (default) cuando
// el GC dispara muchas veces.  Tradeoff: si el VM crashea, los
// ultimos 64 KB de trazas se pierden (no estan en disco).
// Para crash-survival pleno, dejar buffered=false (default).
bool g_gc_debug_buffered = []() noexcept -> bool {
    const char *env = std::getenv("VESTA_GC_DEBUG_BUFFERED");
    return (env != nullptr && env[0] != '\0' && env[0] != '0');
}();

// Buffer thread-local: cada scheduler thread tiene su propio buffer
// para evitar mutex contention.  64 KB amortiza syscalls de write
// sobre miles de trazas pequenias (~50 bytes c/u).
constexpr size_t GC_DBG_BUF_SIZE = 64 * 1024;
// En el build FREESTANDING (libvesta_gc para AOT) el GC es single-thread y no
// debe arrastrar TLS (genera _tls_index + relocs SECREL que el linker propio no
// resuelve sin una TLS directory).  thread_local -> global plano.
#if defined(VESTA_GC_FREESTANDING)
#define GC_DBG_TLS
#else
#define GC_DBG_TLS thread_local
#endif
GC_DBG_TLS char g_gc_dbg_buf[GC_DBG_BUF_SIZE];
GC_DBG_TLS size_t g_gc_dbg_pos = 0;

// File descriptor de stderr cacheado.  Lazy: el primer trace lo
// resuelve.  Asi no pagamos lookup por linea.
int g_gc_dbg_fd = -1;

inline int gc_dbg_get_fd() noexcept {
    if (g_gc_dbg_fd < 0) {
        g_gc_dbg_fd = GC_DBG_FILENO(stderr);
    }
    return g_gc_dbg_fd;
}

// Flush del buffer thread-local al fd de stderr (un solo write
// syscall por flush, amortizando coste sobre N trazas).
inline void gc_dbg_flush_tls() noexcept {
    if (g_gc_dbg_pos == 0) return;
    const int fd = gc_dbg_get_fd();
    if (fd >= 0) {
        GC_DBG_WRITE(fd, g_gc_dbg_buf, (unsigned)g_gc_dbg_pos);
    }
    g_gc_dbg_pos = 0;
}

// Emite una linea formateada al sink correcto segun modo.
//
// Modo unbuffered (default):
//   - vsnprintf a stack buffer (rapido, ~200ns)
//   - write() syscall directo al fd de stderr (~2us en SSD)
//   - Total: ~2us/linea, vs ~10us/linea de fprintf+fflush.
//   - Crash-safe: cada linea esta en disco antes de retornar.
//
// Modo buffered (VESTA_GC_DEBUG_BUFFERED=1):
//   - vsnprintf a stack buffer
//   - memcpy al buffer thread-local (~50ns)
//   - Si buffer lleno: write() en bulk (~10us para 64KB = ~10ns/linea)
//   - Total: ~100ns/linea amortizado.  100x mas rapido que unbuffered.
//   - NO crash-safe: ultimas N lineas pueden perderse en crash.
inline void gc_dbg_emit(const char *fmt, ...) noexcept {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    const size_t nlen =
        static_cast<size_t>(n < static_cast<int>(sizeof(tmp) - 1)
                                ? n
                                : static_cast<int>(sizeof(tmp) - 1));
    if (g_gc_debug_buffered) {
        if (g_gc_dbg_pos + nlen > GC_DBG_BUF_SIZE) {
            gc_dbg_flush_tls();
        }
        if (nlen > GC_DBG_BUF_SIZE) {
            // Linea inusualmente grande: escribir directo.
            const int fd = gc_dbg_get_fd();
            if (fd >= 0) GC_DBG_WRITE(fd, tmp, (unsigned)nlen);
            return;
        }
        std::memcpy(g_gc_dbg_buf + g_gc_dbg_pos, tmp, nlen);
        g_gc_dbg_pos += nlen;
    } else {
        // Unbuffered: write directo, crash-safe.
        const int fd = gc_dbg_get_fd();
        if (fd >= 0) GC_DBG_WRITE(fd, tmp, (unsigned)nlen);
    }
}

// Atexit handler: flush del buffer al salir del programa para no
// perder las ultimas trazas en modo buffered.
struct GcDebugAtExit {
    ~GcDebugAtExit() {
        if (g_gc_debug_buffered) gc_dbg_flush_tls();
    }
};
GC_DBG_TLS GcDebugAtExit g_gc_debug_at_exit;
} // namespace

// -------------------------------------------------------------------------
// DESCRIPTOR DE TIPO gc<X> (AOT) -- contrato con el codegen (lowering.cpp).
//
// Un objeto gc<X> compilado en modo nativo (native_poo) guarda en obj[0]
// (ObjectHeader.class_ptr) un puntero a &descriptor + 32.  El descriptor es
// un blob en .data.rel.ro con esta forma:
//   [desc+0 ]  field_map_ptr (8)   -> &field-map  (0 = sin campos-referencia)
//   [desc+8 ]  size_bytes    (8)
//   [desc+16]  dtor_ptr      (8)   -> 0 (reservado, unificacion futura)
//   [desc+24]  magic 'VXTD'  (4) + flags (4)
//   [desc+32]  vtable[0], vtable[1], ...   <- obj[0] apunta AQUI
// De modo que [obj[0] + idx*8] sigue siendo la entrada idx de la vtable
// (dispatch intacto) y el GC lee la metadata en [obj[0] - 32].
//
// El field-map (blob en .rodata) lista los offsets (desde obj[0], incluye
// el ObjectHeader de 24 bytes) de los campos que son referencias gc<Y>:
//   [fmap+0]  count (u32)   [fmap+4]  pad (u32)   [fmap+8]  off0, off1, ...
// Solo campos con Type.gc_managed == true (NUNCA unique/shared/raw/prim).
namespace {
constexpr uint32_t VX_TDESC_HDR = 32;            // cabecera antes de la vtable
constexpr uint32_t VX_TDESC_MAGIC = 0x44545856u; // 'VXTD' little-endian

/// Direccion por debajo de la cual un valor no puede ser un puntero real: la
/// primera pagina nunca esta mapeada.  Mismo umbral que usa el resto del
/// fichero al filtrar candidatos.
constexpr uint64_t VX_MIN_PLAUSIBLE_PTR = 65536u;

// Lee el field-map de un objeto gc<X> AOT a partir de su @p payload (= obj[0],
// inicio del ObjectHeader).  Devuelve el numero de campos-referencia en
// @p count y el array de offsets en @p offs.
//
// TODO LO QUE SE LEE AQUI SALIO DE LA MEMORIA DEL PROGRAMA, asi que se
// comprueba antes de seguirlo.  El descriptor lleva un numero magico
// precisamente para esto y durante un tiempo nadie lo miraba: un objeto cuyo
// obj[0] no fuera un descriptor -- un bloque crudo de la C-ABI, o uno
// corrupto -- se seguia igual y mataba el proceso con violacion de acceso, sin
// una linea que dijera donde.  Los filtros van de mas barato a mas caro y
// ninguno toca memoria ajena hasta que los anteriores pasan.
//
// @param sz       Bytes del payload: sin el, obj[0] se lee fuera en objetos
//                 de menos de 8 bytes.
// @param rejected Se incrementa cada vez que se suelta un objeto por no poder
//                 fiarse de su descriptor.  Un analisis que renuncia sin
//                 decirlo parece que funciona.
inline void read_gc_field_map(const uint8_t *payload, const GcHeader *hdr,
                              size_t sz, uint64_t &rejected, uint32_t &count,
                              const uint32_t *&offs) noexcept {
    count = 0;
    offs = nullptr;
    if (hdr->host_ptr_only) return; // box por valor (gc<primitivo>)
    if (hdr->no_type_desc) return;  // bloque crudo: obj[0] no es descriptor
    if (sz < 8) return;             // no cabe ni el puntero

    uint64_t obj0 = 0;
    std::memcpy(&obj0, payload, 8); // obj[0] = &descriptor + 32
    // Un descriptor real esta alineado a 8 y vive muy por encima de la pagina
    // nula.  Esto descarta casi todo lo que no lo sea sin desreferenciar nada.
    if (obj0 < VX_MIN_PLAUSIBLE_PTR || (obj0 & 7u) != 0) {
        if (obj0 != 0) ++rejected; // el 0 es legitimo: sin clase
        return;
    }

    const uint8_t *desc =
        reinterpret_cast<const uint8_t *>(obj0) - VX_TDESC_HDR;
    // La firma del descriptor, que es la comprobacion para la que se emitio.
    uint32_t magic = 0;
    std::memcpy(&magic, desc + 24, 4); // magic @ desc+24
    if (magic != VX_TDESC_MAGIC) {
        ++rejected;
        return;
    }

    uint64_t fmap_ptr = 0;
    std::memcpy(&fmap_ptr, desc, 8); // field_map_ptr @ desc+0
    if (fmap_ptr == 0) return;       // clase gc sin campos-referencia
    if (fmap_ptr < VX_MIN_PLAUSIBLE_PTR || (fmap_ptr & 3u) != 0) {
        ++rejected;
        return;
    }
    const uint8_t *fmap = reinterpret_cast<const uint8_t *>(fmap_ptr);
    uint32_t n = 0;
    std::memcpy(&n, fmap, 4); // count @ fmap+0
    // Cada campo-referencia ocupa 8 bytes DENTRO del payload, asi que no puede
    // haber mas de sz/8.  Un field-map plausible por casualidad casi siempre
    // cae aqui.
    if (n > sz / 8u) {
        ++rejected;
        return;
    }
    count = n;
    offs = reinterpret_cast<const uint32_t *>(fmap + 8); // offsets @ fmap+8
}

/**
 * @brief Recorre los campos-referencia gc<Y> de un objeto AOT.
 *
 * Los tres consumidores del field-map -- marcar, reescribir tras mover y
 * verificar -- hacian el MISMO bucle con la MISMA guarda de rango, cada uno
 * por su cuenta.  Aqui esta una sola vez: si manana el layout cambia, cambia
 * en un sitio en vez de en tres, que es como dos de ellos se quedan atras sin
 * que nada falle.
 *
 * @param fn Recibe (offset_en_payload, valor_del_campo).  Los campos nulos NO
 *           se entregan: ninguno de los tres tiene nada que hacer con ellos.
 */
template <typename Fn>
inline void for_each_gc_field(const GcHeader *hdr, uint8_t *payload, size_t sz,
                              GcStats &st, Fn &&fn) noexcept {
    uint32_t count = 0;
    const uint32_t *offs = nullptr;
    read_gc_field_map(payload, hdr, sz, st.tdesc_rejected, count, offs);
    for (uint32_t k = 0; k < count; ++k) {
        const uint32_t off = offs[k];
        if (off + 8 > sz) continue; // offset fuera del payload
        uint64_t value = 0;
        std::memcpy(&value, payload + off, 8);
        // Un campo que no puede ser un puntero no es un campo que seguir.
        // Los tres consumidores querian esto mismo y dos lo escribian a mano
        // con el umbral repetido; el tercero se apoyaba en que su busqueda
        // fallara.  Una sola idea de "puntero plausible" en el fichero.
        if (value < VX_MIN_PLAUSIBLE_PTR) continue;
        fn(off, value);
    }
}
/**
 * @brief Recorre los objetos vivos de los bloques de OldGen.
 *
 * El recorrido -- cursor, cabecera, tamano del hueco redondeado a 8 -- estaba
 * escrito dos veces palabra por palabra.  Es el layout del heap: tenerlo dos
 * veces es tener dos versiones de el en cuanto una cambie.
 *
 * @param fn Recibe (hdr, payload, sz) de cada objeto.
 */
template <typename Blocks, typename Fn>
inline void for_each_old_object(Blocks &blocks, Fn &&fn) noexcept {
    for (auto &block : blocks) {
        uint8_t *cursor = block.ptr;
        uint8_t *end = block.ptr + block.bump_offset;
        while (cursor + sizeof(GcHeader) <= end) {
            auto *hdr = reinterpret_cast<GcHeader *>(cursor);
            if (hdr->size == 0) break;
            const size_t total = (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;
            fn(hdr, cursor + sizeof(GcHeader), static_cast<size_t>(hdr->size));
            cursor += total;
        }
    }
}
} // namespace

void set_gc_debug(bool enabled) noexcept {
    g_gc_debug = enabled;
}

bool gc_debug_enabled() noexcept {
    return g_gc_debug;
}

void set_gc_debug_buffered(bool enabled) noexcept {
    if (g_gc_debug_buffered && !enabled) gc_dbg_flush_tls();
    g_gc_debug_buffered = enabled;
}

bool gc_debug_buffered_enabled() noexcept {
    return g_gc_debug_buffered;
}

void gc_debug_flush() noexcept {
    gc_dbg_flush_tls();
    std::fflush(stderr);
}

// Macros con hint de branch (cold path) y opcion de compile-time disable.
#ifdef VESTA_GC_DEBUG_DISABLE
#define GC_LOG(msg) ((void)0)
#define GC_LOGF(fmt, ...) ((void)0)
#else
// __builtin_expect convierte `if (g_gc_debug)` en hint de branch
// frio: el compilador coloca el codigo de log en una pagina aparte
// del hot path.  Sin debug, solo se ejecuta load + branch predicho
// (~2 ciclos), nunca el emit.
#define GC_LOG(msg)                                                            \
    do {                                                                       \
        if (__builtin_expect(g_gc_debug, 0)) {                                 \
            gc_dbg_emit("[GC] " msg "\n");                                     \
        }                                                                      \
    } while (0)
#define GC_LOGF(fmt, ...)                                                      \
    do {                                                                       \
        if (__builtin_expect(g_gc_debug, 0)) {                                 \
            gc_dbg_emit("[GC] " fmt "\n", __VA_ARGS__);                        \
        }                                                                      \
    } while (0)
#endif

// -------------------------------------------------------------------------
// Constructor / destructor
// -------------------------------------------------------------------------

GcHeap::GcHeap(vm::ArenaManager &arena_mgr, size_t nursery_bytes,
               size_t old_threshold)
    : arena_mgr_(arena_mgr), nursery_size_(nursery_bytes),
      old_threshold_(old_threshold) {
    nursery_arena_id_ = arena_mgr_.create_arena(
        nursery_bytes, vm::MemPerm::READ | vm::MemPerm::WRITE);
    const vm::Arena *a = arena_mgr_.get_arena(nursery_arena_id_);
    assert(a && a->ptr && "GcHeap: no se pudo crear la Nursery");

    nursery_base_ = static_cast<uint8_t *>(a->ptr);
    nursery_bump_ = nursery_base_;
    nursery_end_ = nursery_base_ + nursery_bytes;

    /* Sprint alloc-pool (2026-06-02): reserva inicial de capacidad
     * para evitar reallocs en hot paths de alocacion masiva.
     *
     * Estimacion: nursery_bytes / 40 (avg obj size incluyendo header)
     * = handles vivos esperados en un ciclo del nursery.  Pero como
     * los handles persisten cross-minor_gc hasta release, multiplicar
     * por ~8 para programas con vida media larga.
     *
     * 1 MB nursery -> 25K objetos -> ~200K handles cap = ~3 MB para
     * @c handles_ (struct HandleEntry = ~16 bytes).  Aceptable. */
    const size_t avg_obj_bytes = 40;
    const size_t live_obj_estimate = nursery_bytes / avg_obj_bytes;
    const size_t handles_reserve = std::min<size_t>(
        std::max<size_t>(live_obj_estimate * 8, 4096),
        1u << 20); /* cap 1M handles para no inflar al inicio */
    handles_.reserve(handles_reserve);
    free_handles_.reserve(handles_reserve / 4);
    ptr_to_handle_.reserve(handles_reserve);
}

GcHeap::~GcHeap() {
    for (auto &b : old_blocks_)
        arena_mgr_.free_arena(b.arena_id);
    old_blocks_.clear();

    arena_mgr_.free_arena(nursery_arena_id_);
    nursery_base_ = nursery_bump_ = nursery_end_ = nullptr;
}

// -------------------------------------------------------------------------
// Gestion de handles
// -------------------------------------------------------------------------

GcHandle GcHeap::new_handle(uint8_t *addr) {
    // GC_NULL_HANDLE = 0 colisiona con el indice 0 del array.
    // Reservamos handles_[0] como sentinela "no usado" en la primera
    // llamada para que ningun handle valido sea 0.  Sin esto, el
    // primer alloc del proceso retornaba 0, indistinguible de
    // "alloc fallo" -- causa real de strmake retornando NULL_HANDLE
    // en programas Vesta donde el primer use de string era el primer
    // alloc del GC heap (caso comun).
    if (handles_.empty()) {
        handles_.push_back({nullptr, false}); // sentinela inalcanzable
    }
    GcHandle h;
    if (!free_handles_.empty()) {
        h = free_handles_.back();
        free_handles_.pop_back();
        handles_[h] = {addr, true};
    } else {
        h = static_cast<GcHandle>(handles_.size());
        handles_.push_back({addr, true});
    }
    // Registrar el host pointer del payload (no del GcHeader) en el
    // mapa inverso.  Permite handle_for_ptr O(1) sin escanear handles_.
    if (addr != nullptr) {
        const uint8_t *payload = addr + sizeof(GcHeader);
        ptr_to_handle_.insert_or_assign(payload, h);
    }
    return h;
}

void GcHeap::release_handle(GcHandle h) {
    if (h >= handles_.size()) return;
    GC_LOGF("release_handle h=%u", (unsigned)h);
    // si el handle esta pinnado externamente (external_refs > 0),
    // NO liberamos: alguien tiene una referencia externa (ej. ArrayList
    // <string> del plugin) y necesita el objeto vivo.  El mismo handle
    // sera liberado automaticamente cuando el ultimo gc_release lo
    // saque del map.
    const uint32_t *rc_ext = external_refs_.find(h);
    if (rc_ext != nullptr && *rc_ext > 0) {
        return;
    }
    // Limpiar el mapa inverso ANTES de invalidar handles_[h].addr.
    // Necesitamos el addr para localizar el payload pointer que
    // registramos en new_handle/do_evacuate.
    const uint8_t *old_addr = handles_[h].addr;
    if (old_addr != nullptr) {
        ptr_to_handle_.erase(old_addr + sizeof(GcHeader));
    }
    handles_[h] = {nullptr, false};
    free_handles_.push_back(h);
}

GcHandle
GcHeap::handle_for_ptr(const uint8_t *host_payload_ptr) const noexcept {
    // Lookup directo O(1) amortizado.  El mapa se mantiene en
    // new_handle/release_handle/do_evacuate, asi que aqui no hay
    // escaneo lineal: una sola sonda en la tabla hash.
    if (host_payload_ptr == nullptr) return GC_NULL_HANDLE;
    GcHandle local = ptr_to_handle_.find(host_payload_ptr);
    if (local != GC_NULL_HANDLE) return local;

    // BugFix C (2026-06-04): el lookup secundario en SharedHeap
    // dereferencia @c host_payload_ptr como @c ObjectHeader*.  Si el
    // ptr no es memoria GC valida (e.g. el bytecode emite gchandle
    // sobre un i32 value reusado en el mismo reg por el regalloc,
    // patron del bug C del editor), ese deref es SEGV.  Hay que
    // validar PRIMERO que el ptr cae dentro del rango de algun bloque
    // del SharedHeap antes de dereferenciar.  Si no esta en ningun
    // bloque GC conocido, retornar GC_NULL_HANDLE sin tocar memoria.
    //
    // Defensa adicional: verificar alineamiento minimo (host_ptr GC
    // siempre alineado a 8 bytes via alloc).  Un value que aparenta
    // ser ptr pero no esta alineado nunca puede ser un payload valido.
    const uintptr_t ptr_addr = reinterpret_cast<uintptr_t>(host_payload_ptr);
    if ((ptr_addr & 7) != 0) return GC_NULL_HANDLE; // no-alineado: no es GC

    // Verificar que el ptr esta dentro de algun bloque GC conocido
    // (Nursery o cualquier old_block).  Sin esto, deref de basura.
    bool in_gc = false;
    if (host_payload_ptr >= nursery_base_ && host_payload_ptr < nursery_end_) {
        in_gc = true;
    } else {
        for (const auto &block : old_blocks_) {
            const uint8_t *block_end = block.ptr + block.bump_offset;
            if (host_payload_ptr >= block.ptr && host_payload_ptr < block_end) {
                in_gc = true;
                break;
            }
        }
    }
    //  Z (fix 2026-06-05): un objeto del @c SharedHeap (cross-process)
    // tiene su host_ptr en los chunks del SharedHeap, NO en el heap local
    // (nursery/old_blocks).  Si @c contains() confirma que el ptr cae en el
    // SharedHeap, permitir el deref + resolucion del handle shared abajo.
    //
    // Sin esto, el save/restore de registros vivos a traves de un CALL
    // (gchandle %p -> handle; ...; gcderef handle -> %p) sobre un host_ptr
    // SHARED devolvia GC_NULL_HANDLE (el ptr no esta en el heap local) ->
    // el restore hacia gcderef(NULL_HANDLE=0xFFFFFFFF) -> shared lookup de
    // 0xFFFFFFFF -> nullptr -> el host_ptr quedaba a 0 -> store a [0+offset]
    // = SEGV.  Reproducible con 2+ objetos shared vivos a traves de un call
    // y luego escritura a sus fields (a.v=10; b.v=20).
    if (!in_gc && root_provider_ != nullptr &&
        root_provider_->shared_contains(host_payload_ptr)) {
        in_gc = true;
    }
    if (!in_gc) return GC_NULL_HANDLE;

    //  Z.6: si no esta en el mapa local pero SI esta en un
    // bloque GC (local o SharedHeap), puede ser un objeto del
    // @c SharedHeap cuyo @c ObjectHeader.hash_code lleva bit 31 set.
    // Ahora es seguro hacer el deref porque sabemos que el ptr es
    // memoria GC valida.
    const auto *hdr =
        reinterpret_cast<const loader::ObjectHeader *>(host_payload_ptr);
    const uint32_t maybe_shared = hdr->hash_code;
    if (maybe_shared & SHARED_HANDLE_BIT) {
        // Validar que el handle realmente resuelve al mismo ptr
        // (defensa contra hash_code colisiones casuales con bit 31).
        if (root_provider_) {
            uint8_t *resolved = root_provider_->shared_lookup(maybe_shared);
            if (resolved == host_payload_ptr) {
                return maybe_shared;
            }
        }
    }
    return GC_NULL_HANDLE;
}

// -------------------------------------------------------------------------
// alloc
// -------------------------------------------------------------------------

/* ===================================================================== */
/* PtrHandleMap: hash table flat para ptr->handle.                        */
/* ===================================================================== */

PtrHandleMap::PtrHandleMap() {
    /* Capacidad inicial 64 (load < 0.5 => grow_at = 32). */
    table_.resize(64, Entry{nullptr, GC_NULL_HANDLE});
    mask_ = 63;
    grow_at_ = 32;
}

void PtrHandleMap::clear() {
    for (auto &e : table_) {
        e.key = nullptr;
        e.value = GC_NULL_HANDLE;
    }
    live_count_ = 0;
    used_ = 0;
}

void PtrHandleMap::reserve(size_t n) {
    /* Crecer hasta que grow_at_ >= n. */
    while (grow_at_ < n)
        grow();
}

void PtrHandleMap::grow() {
    const size_t new_cap = (table_.size() == 0) ? 64 : table_.size() * 2;
    std::vector<Entry> old_table = std::move(table_);
    table_.assign(new_cap, Entry{nullptr, GC_NULL_HANDLE});
    mask_ = new_cap - 1;
    grow_at_ = new_cap / 2;
    live_count_ = 0;
    used_ = 0;
    for (auto &e : old_table) {
        if (is_live(e.key)) {
            insert_or_assign(e.key, e.value);
        }
    }
}

bool PtrHandleMap::insert_or_assign(const uint8_t *key, GcHandle h) {
    if (used_ + 1 > grow_at_) grow();
    size_t idx = hash_ptr(key) & mask_;
    size_t first_tomb = SIZE_MAX;
    while (true) {
        const uint8_t *k = table_[idx].key;
        if (is_empty(k)) {
            /* Si vimos un tombstone antes, usamos ese para mejor
             * locality + reuso.  Si no, este slot vacio. */
            if (first_tomb != SIZE_MAX) {
                table_[first_tomb].key = key;
                table_[first_tomb].value = h;
            } else {
                table_[idx].key = key;
                table_[idx].value = h;
                ++used_;
            }
            ++live_count_;
            return true;
        }
        if (is_tomb(k)) {
            if (first_tomb == SIZE_MAX) first_tomb = idx;
        } else if (k == key) {
            table_[idx].value = h;
            return false;
        }
        idx = (idx + 1) & mask_;
    }
}

GcHandle PtrHandleMap::find(const uint8_t *key) const noexcept {
    if (table_.empty()) return GC_NULL_HANDLE;
    size_t idx = hash_ptr(key) & mask_;
    while (true) {
        const uint8_t *k = table_[idx].key;
        if (is_empty(k)) return GC_NULL_HANDLE;
        if (k == key) return table_[idx].value;
        idx = (idx + 1) & mask_;
    }
}

bool PtrHandleMap::erase(const uint8_t *key) {
    if (table_.empty()) return false;
    size_t idx = hash_ptr(key) & mask_;
    while (true) {
        const uint8_t *k = table_[idx].key;
        if (is_empty(k)) return false;
        if (k == key) {
            table_[idx].key = tombstone();
            table_[idx].value = GC_NULL_HANDLE;
            --live_count_;
            /* Mantenemos used_ contando este tombstone hasta el
             * proximo grow (compactara). */
            return true;
        }
        idx = (idx + 1) & mask_;
    }
}

/* ===================================================================== */
/* GcHeap::alloc                                                          */
/* ===================================================================== */

GcHandle GcHeap::alloc(size_t size) {
    constexpr size_t ALIGN = 8;
    // total = bytes que necesita el slot para cubrir cabecera + payload
    // pedido + padding hasta multiplo de 8.
    const size_t total = (sizeof(GcHeader) + size + ALIGN - 1) & ~(ALIGN - 1);

#if !defined(VESTA_GC_FREESTANDING)
    // STRESS GC (VESTA_GC_STRESS=1, DEV-ONLY): fuerza un ciclo COMPLETO
    // (minor + major) en CADA alocacion, ANTES de reservar el nuevo objeto.
    // Sirve al verificador (VESTA_GC_VERIFY) para ejercitar el scan preciso
    // en TODO safepoint de programas cortos que de otro modo nunca llenan el
    // nursery.  En este punto no hay objeto en construccion (pending_alloc_
    // root_ vacio); las raices vivas del caller estan en pila/regs.  No es un
    // flag de producto: sin la env var, cero coste (una lectura de bool).
    static const bool stress = [] {
        const char *v = std::getenv("VESTA_GC_STRESS");
        return v && v[0] == '1';
    }();
    if (stress) {
        minor_gc();
        major_gc();
    }
#endif

    // Lambda que inicializa un slot ya reservado.  Recibe el puntero
    // al GcHeader y el tamano REAL del slot (slot_total).
    //
    // Convencion de hdr->size:
    //   - Nursery: hdr->size = @p size (user payload).  Conserva la
    //     semantica clasica.  El slot fue alocado con bump pointer
    //     exacto (slot_total = round_up(header + size, 8)), no hay
    //     ambigueedad: SWEEP de OldGen no toca nursery, asi que da igual.
    //   - OldGen: hdr->size = slot_total - header (payload del slot,
    //     incluyendo padding hasta el size class).  Necesario para que
    //     al re-free el slot encaje exactamente en su size class via
    //     size_class_ceil(round_up(header + hdr->size, 8)).
    //
    // El zero-init memset solo cubre los bytes que pidio el usuario;
    // el padding interno queda en el estado previo (cero si bump fresh,
    // basura si reciclado de free list, pero inaccesible si el usuario
    // respeta @p size).
    auto init_obj = [&](uint8_t *raw, GcGen gen,
                        size_t slot_total) -> GcHandle {
        auto *hdr = reinterpret_cast<GcHeader *>(raw);
        if (gen == GcGen::OLD) {
            hdr->size = static_cast<uint32_t>(slot_total - sizeof(GcHeader));
        } else {
            hdr->size = static_cast<uint32_t>(size);
        }
        hdr->color = GcColor::WHITE;
        hdr->gen = gen;
        std::memset(raw + sizeof(GcHeader), 0, size);

        stats_.alloc_count++;
        stats_.alloc_bytes += size; // bytes utiles pedidos
        size_t nu = nursery_used();
        if (nu > stats_.peak_nursery) stats_.peak_nursery = nu;
        if (old_used_ > stats_.peak_old) stats_.peak_old = old_used_;

        return new_handle(raw);
    };

    // Fast-path: espacio en Nursery (bump pointer, sin redondeo a class).
    // La Nursery se evacua entera por minor_gc; no hay reuso individual
    // de slots, asi que no necesitamos size classes alli.
    if (nursery_bump_ + total <= nursery_end_) {
        uint8_t *raw = nursery_bump_;
        nursery_bump_ += total;
        return init_obj(raw, GcGen::YOUNG, total);
    }

    // Nursery llena: minor GC y reintentar.
    minor_gc();

    if (nursery_bump_ + total <= nursery_end_) {
        uint8_t *raw = nursery_bump_;
        nursery_bump_ += total;
        return init_obj(raw, GcGen::YOUNG, total);
    }

    // Sigue sin espacio: asignar directo en OldGen via free list o bump.
    // alloc_in_old puede devolver un slot >= total (redondeo al size class).
    size_t actual_total = 0;
    uint8_t *raw = alloc_in_old_with_total(total, actual_total);
    if (!raw) return GC_NULL_HANDLE;
    return init_obj(raw, GcGen::OLD, actual_total);
}

// -------------------------------------------------------------------------
// alloc_pinned - aloca directo en OldGen (non-moving) para objetos cuyo
// host_ptr al payload debe permanecer estable a traves del GC.
//
// Caso de uso primario: StringObject.  El bytecode obtiene el host_ptr
// del buffer de datos via STRRAW para pasarlo a FFI / print / interpolacion.
// Si el StringObject vive en young y un GC menor lo evacua a old, el
// host_ptr queda dangling.  Allocando directo en old desde el principio,
// el host_ptr es estable mientras el handle viva.
//
// Penalizacion: Old llena mas rapido y dispara major_gc antes.  Para
// strings tipicos (cortos, vida corta-media) esto es aceptable.
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Stack scanning conservativo con interior scan en OldGen.
//
// Fundamento: el GC anterior consideraba root a TODO handle vivo en la
// HandleTable.  Sin liberacion explicita (drop / RAII), los handles se
// acumulaban indefinidamente -> el major_gc nunca colectaba.
//
// Nuevo modelo: el GC escanea el stack del proceso + GP regs + external_refs
// + pending_alloc_root_ buscando handles y host_ptrs a objetos GC.  Solo
// los descubiertos son roots; los demas se barren.
//
// Los filtros descartan rapido los uint64_t que claramente NO son refs
// (cero, escalares pequenos, valores fuera de rango handle) sin pagar
// hash lookup.  Para los candidatos, lookup O(1) en handles_ o
// ptr_to_handle_ + interior scan en OldGen para casos como STRRAW que
// retorna ptr al data[] interno de un StringObject.
// -------------------------------------------------------------------------

/// Helper: dado un bloque OldGen y un host_ptr v dentro, encuentra el
/// ObjectHeader que lo contiene recorriendo desde block.ptr siguiendo
/// los headers consecutivos.  Retorna nullptr si v no cae en un objeto
/// vivo (entre objetos, en zona DEAD, o fuera de bump_offset).
///
/// Coste: O(N_objects_en_bloque).  Solo se llama si v ya cayo dentro
/// del rango [block.ptr, block.ptr + block.bump_offset).
static GcHeader *find_containing_header(uint8_t *block_start,
                                        size_t bump_offset,
                                        uint8_t *target_ptr) {
    uint8_t *cursor = block_start;
    uint8_t *end = block_start + bump_offset;
    while (cursor + sizeof(GcHeader) <= end) {
        auto *hdr = reinterpret_cast<GcHeader *>(cursor);
        if (hdr->size == 0) break;
        const size_t total = (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;
        uint8_t *slot_end = cursor + total;
        if (target_ptr >= cursor && target_ptr < slot_end) {
            // v cae dentro de este slot.
            if (hdr->color == GcColor::DEAD) return nullptr;
            return hdr;
        }
        cursor = slot_end;
    }
    return nullptr;
}

void GcHeap::scan_stack_roots(uint64_t rsp, uint64_t stack_high,
                              const uint64_t regs[16],
                              vm::VirtualMemory &vm_mem,
                              std::vector<GcHandle> &worklist) {
    // Helper local para procesar un uint64_t candidato a referencia.
    // Lookups orden: handles primero (cheap), ptr_to_handle_ despues.
    auto process_value = [&](uint64_t v) {
        // Solo descartamos NULL.  ANTES filtrabamos `v < 256` para
        // optimizar (escalares pequenos, loop counters), pero ese
        // filtro era un BUG critico: handles pequenos (1..255) se
        // generan tempranamente para clases del programa (e.g. el
        // Editor TUI tiene handle ~5).  El conservative scan los
        // saltaba -> Editor quedaba fuera del root set -> sweep
        // marcaba handles_[5].live=false -> gcderef post-strmake
        // devolvia addr para un handle muerto -> AV en el siguiente
        // CALLVIRT con r1 corrupto.  Sintoma: editor crasheaba justo
        // despues del primer render() al entrar al run loop.
        //
        // El check de handle (1) es O(1) cheap (comparar size +
        // array access), perfectamente aceptable hacerlo siempre.
        // El ptr_to_handle_.find (2) es hash lookup pero solo se
        // ejecuta si v NO es un handle valido.
        if (v == 0) return;

        // 1. Es un GcHandle directo?  Marcamos BLACK tanto YOUNG como
        //    OLD: minor_gc usa el flag para decidir que evacuar; major_gc
        //    solo barre OLD pero el flag en YOUNG no estorba (se descarta
        //    al reset nursery_bump al final del minor).
        if (v < handles_.size()) {
            const GcHandle h = static_cast<GcHandle>(v);
            if (handles_[h].live && handles_[h].addr) {
                auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
                // Un objeto marcado host_ptr_only (box gc_allocp) NUNCA es
                // referenciado por el bytecode via su handle numerico -- solo
                // por su host_ptr.  Saltamos el marcado por coincidencia
                // numerica valor==handle: es un falso positivo (una constante
                // pequena del programa que coincide con un handle pequeno).
                // El box SI se marca por host_ptr real en las fases 2/3a/3b de
                // abajo (ptr_to_handle_ + interior scan).  Sin esto, un box
                // escapado inalcanzable no se colectaba de forma determinista.
                if (hdr->host_ptr_only) return;
                if (hdr->color == GcColor::WHITE) {
                    hdr->color = GcColor::BLACK;
                    worklist.push_back(h);
                }
                return;
            }
        }

        // Para el ptr_to_handle_.find lookup, solo procesar valores
        // que pueden ser real host_ptrs.  En Windows 64-bit los heap
        // ptrs estan en upper canonical (>> 16-bit).  Filtrar valores
        // pequenos no triviales aqui ahorra hash lookups innecesarios
        // sin perder cobertura.
        if (v < 65536) return;

        // 2. Es un host_ptr al payload start de un objeto GC?
        //    (resultado de gcderef en CLASS instances o de strraw cuando
        //    apunta al inicio del StringObject).
        auto *ptr = reinterpret_cast<uint8_t *>(static_cast<uintptr_t>(v));
        {
            const GcHandle h = ptr_to_handle_.find(ptr);
            if (h != GC_NULL_HANDLE) {
                if (h < handles_.size() && handles_[h].live &&
                    handles_[h].addr) {
                    auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
                    if (hdr->color == GcColor::WHITE) {
                        hdr->color = GcColor::BLACK;
                        worklist.push_back(h);
                    }
                }
                return;
            }
        }

        // 3a. Interior scan en OldGen: el ptr puede caer DENTRO del
        //     payload de un objeto OldGen sin ser el inicio.  Caso
        //     clasico: STRRAW retorna data[] del StringObject que esta
        //     en offset 40 del payload start.
        for (auto &block : old_blocks_) {
            uint8_t *block_end = block.ptr + block.bump_offset;
            if (ptr < block.ptr || ptr >= block_end) continue;
            // v cae en este bloque -> encontrar el header contenedor.
            GcHeader *hdr =
                find_containing_header(block.ptr, block.bump_offset, ptr);
            if (hdr == nullptr) return;               // entre objetos / DEAD
            if (hdr->color != GcColor::WHITE) return; // ya BLACK o DEAD
            // Buscar el handle correspondiente al header.
            uint8_t *payload =
                reinterpret_cast<uint8_t *>(hdr) + sizeof(GcHeader);
            const GcHandle h = ptr_to_handle_.find(payload);
            if (h == GC_NULL_HANDLE) return;
            if (h >= handles_.size() || !handles_[h].live) return;
            hdr->color = GcColor::BLACK;
            worklist.push_back(h);
            return;
        }

        // 3b. Interior scan en Nursery: igual logica para objetos YOUNG
        //     que aun no se han evacuado.  Sin esto, un host_ptr derivado
        //     (e.g. data[] de StringObject recien creado) no marcaria el
        //     StringObject -> minor_gc lo descartaria.
        if (ptr >= nursery_base_ && ptr < nursery_bump_) {
            uint8_t *cursor = nursery_base_;
            while (cursor + sizeof(GcHeader) <= nursery_bump_) {
                auto *hdr = reinterpret_cast<GcHeader *>(cursor);
                if (hdr->size == 0) break;
                const size_t total = (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;
                uint8_t *slot_end = cursor + total;
                if (ptr >= cursor && ptr < slot_end) {
                    if (hdr->color != GcColor::WHITE) return;
                    uint8_t *payload = cursor + sizeof(GcHeader);
                    const GcHandle h = ptr_to_handle_.find(payload);
                    if (h == GC_NULL_HANDLE) return;
                    if (h >= handles_.size() || !handles_[h].live) return;
                    hdr->color = GcColor::BLACK;
                    worklist.push_back(h);
                    return;
                }
                cursor = slot_end;
            }
        }
        // Si no cae en ningun bloque, ignorar (escalar arbitrario).
    };

    // Escanear el stack del proceso: [rsp, stack_high) en pasos de 8 bytes.
    // Las direcciones son virtuales del proceso VM, leemos via vm_mem.
    // Limitamos a un rango razonable para evitar reads excesivos si el
    // stack_high sale corrupto.
    if (rsp < stack_high && (stack_high - rsp) < (16 * 1024 * 1024)) {
        for (uint64_t addr = rsp; addr + 8 <= stack_high; addr += 8) {
            const uint64_t v = vm_mem.read_u64(addr);
            process_value(v);
        }
    }

    // Escanear los GP regs R0..R15.  Cada reg puede contener un handle
    // o un host_ptr.  R13/R14/R15 son scratch del regalloc pero pueden
    // contener valores temporales que sean refs validas en este momento;
    // mejor escanearlos para no perder roots.
    for (int i = 0; i < 16; ++i) {
        process_value(regs[i]);
    }

    // pending_alloc_root_: handle en construccion durante un alloc que
    // disparo GC recursivo.  Lo marcamos como root para que no sea
    // barrido antes de que el alloc retorne y el bytecode lo guarde
    // en stack/regs.
    if (pending_alloc_root_ != GC_NULL_HANDLE &&
        pending_alloc_root_ < handles_.size() &&
        handles_[pending_alloc_root_].live &&
        handles_[pending_alloc_root_].addr) {
        auto *hdr =
            reinterpret_cast<GcHeader *>(handles_[pending_alloc_root_].addr);
        if (hdr->gen == GcGen::OLD && hdr->color == GcColor::WHITE) {
            hdr->color = GcColor::BLACK;
            worklist.push_back(pending_alloc_root_);
        }
    }
}

// -------------------------------------------------------------------------
//  precise scan de JIT frames + integracion con major_gc.
// -------------------------------------------------------------------------

/**
 * @brief Helper: marca un handle como BLACK root precise si es
 *        valido + vivo + actualmente WHITE.
 */
bool GcHeap::try_mark_precise_handle(GcHandle h,
                                     std::vector<GcHandle> &worklist) {
    if (h == GC_NULL_HANDLE) return false;
    if (h >= handles_.size()) return false;
    if (!handles_[h].live || !handles_[h].addr) return false;
    auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
    if (hdr->gen != GcGen::OLD) return false; /* young se cubre via minor_gc */
    if (hdr->color != GcColor::WHITE) return false;
    hdr->color = GcColor::BLACK;
    worklist.push_back(h);
    return true;
}

bool GcHeap::try_mark_precise_young(GcHandle h,
                                    std::vector<GcHandle> &worklist) {
    if (h == GC_NULL_HANDLE) return false;
    if (h >= handles_.size()) return false;
    if (!handles_[h].live || !handles_[h].addr) return false;
    uint8_t *raw = handles_[h].addr;
    // Solo objetos que viven en el nursery (rango YOUNG).  Un handle preciso
    // que apunte a OLD lo gobierna major_gc -> aqui se ignora.
    if (raw < nursery_base_ || raw >= nursery_end_) return false;
    auto *hdr = reinterpret_cast<GcHeader *>(raw);
    if (hdr->gen != GcGen::YOUNG) return false;
    if (hdr->color != GcColor::WHITE) return false;
    hdr->color = GcColor::BLACK;
    worklist.push_back(h);
    return true;
}

namespace {
/**
 * @brief Contexto pasado al callback de @c scan_jit_frames durante
 *        el precise scan iniciado desde major_gc.
 */
struct JitPreciseCtx {
    gc::GcHeap *heap;
    std::vector<gc::GcHandle> *worklist;
    uint64_t roots_marked;
    bool young = false; ///< true -> try_mark_precise_young (minor_gc)
};

/**
 * @brief Callback C-style invocado por @c scan_jit_frames para
 *        cada slot GC encontrado en un JIT frame.
 *
 * Para slots @c HANDLE: el valor es directamente un GcHandle.
 * Para slots @c HOSTPTR / @c STRING: el valor es un host_ptr al
 * payload; usamos @c handle_for_ptr para mapear inverso al handle.
 */
void jit_precise_root_cb(void *ctx, uint64_t value, jit::StackmapGcKind kind,
                         const uint8_t * /*slot_addr*/) {
    auto *c = static_cast<JitPreciseCtx *>(ctx);
    // Enrutar segun el modo: young (minor_gc) marca solo YOUNG; !young
    // (major_gc) marca OLD.  Mismo walk de frames y stackmaps.
    auto mark = [c](gc::GcHandle h) -> bool {
        return c->young ? c->heap->try_mark_precise_young(h, *c->worklist)
                        : c->heap->try_mark_precise_handle(h, *c->worklist);
    };
    switch (kind) {
    case jit::StackmapGcKind::HANDLE: {
        const auto h = static_cast<gc::GcHandle>(value);
        if (mark(h)) {
            ++c->roots_marked;
        }
        break;
    }
    case jit::StackmapGcKind::HOSTPTR:
    case jit::StackmapGcKind::STRING: {
        if (value == 0) break;
        const auto *ptr = reinterpret_cast<const uint8_t *>(value);
        const gc::GcHandle h = c->heap->handle_for_ptr(ptr);
        if (h != gc::GC_NULL_HANDLE && mark(h)) {
            ++c->roots_marked;
        }
        break;
    }
    }
}
} // namespace

namespace {
/**
 * @brief Obtiene los limites [low, high) del stack NATIVO del hilo actual.
 *
 * Necesario para acotar el walk de la cadena RBP en @c scan_jit_frames: sin
 * limites, un binario compilado con @c -fomit-frame-pointer no mantiene una
 * cadena de frame-pointers valida, por lo que seguir @c [rbp] lleva a
 * direcciones arbitrarias y su deref segfaultea.  Con los limites reales el
 * walk se detiene de forma segura en la frontera del stack.
 *
 * @return true si se pudieron determinar los limites (low < high).
 */
bool native_stack_bounds(const uint8_t *&low, const uint8_t *&high) noexcept {
#if defined(VESTA_GC_FREESTANDING)
    (void)low;
    (void)high;
    return false;
#elif defined(_WIN32)
    ULONG_PTR lo = 0, hi = 0;
    GetCurrentThreadStackLimits(&lo, &hi);
    if (lo == 0 || hi == 0 || lo >= hi) return false;
    low = reinterpret_cast<const uint8_t *>(lo);
    high = reinterpret_cast<const uint8_t *>(hi);
    return true;
#elif defined(__linux__) || defined(__GLIBC__)
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) return false;
    void *base = nullptr;
    size_t size = 0;
    const int rc = pthread_attr_getstack(&attr, &base, &size);
    pthread_attr_destroy(&attr);
    if (rc != 0 || base == nullptr || size == 0) return false;
    low = static_cast<const uint8_t *>(base);
    high = low + size;
    return true;
#else
    (void)low;
    (void)high;
    return false;
#endif
}
} // namespace

void GcHeap::scan_jit_roots_precise(std::vector<GcHandle> &worklist,
                                    bool young) {
    /* Optimizacion clave: si no hay JIT funcs registradas, la
     * funcion sale inmediatamente sin walk.  Pre-D.3 (no hay JIT
     * code real) este es el camino del 100% de los major_gc. */
    if (jit::JitRegistry::instance().size() == 0) return;

    JitPreciseCtx ctx{this, &worklist, 0, young};

    /* MODO AOT: WALK POR TAMANO DE FRAME desde el frame Vesta capturado en la
     * frontera C<-Vesta (set_aot_scan_boundary, fijado por cada runtime-entry
     * del GC que puede colectar).  Reconstruye cada RBP con frame_size en vez
     * de la cadena RBP -> salta los frames C++ de libvesta_gc (no-walkables por
     * -fomit-frame-pointer) y arranca en el primer frame Vesta real.  Es lo que
     * cierra el bug de raices vivas colectadas en AOT.  El path interp/JIT
     * (abajo) NO cambia. */
    if (aot_precise_roots_ && aot_boundary_valid_) {
        const jit::JitScanStats stats = jit::scan_aot_frames(
            &jit_precise_root_cb, &ctx, aot_boundary_pc_, aot_boundary_sp_);
        stats_.precise_roots_marked += ctx.roots_marked;
        stats_.precise_frames_scanned += stats.jit_frames;
        /* Invalidar el boundary: cada runtime-entry del GC lo re-captura antes
         * de colectar.  Asi un hipotetico major_gc que no pase por la frontera
         * nunca caminaria un frame Vesta ya muerto (defensa anti-corrupcion).
         */
        aot_boundary_valid_ = false;
        return;
    }

    /* INTERP+JIT: boundary capturado por la runtime-entry (@c vrt_*) que el
     * codigo JIT llamo DIRECTAMENTE para alocar.  Mismo WALK POR TAMANO DE
     * FRAME que el AOT (reconstruye RBP con frame_size) -> robusto ante los
     * frames C++ del runtime que a -O0 rompen la cadena RBP (@c lea
     * rbp,[rsp+N]), que es justo lo que hacia que el scan de frames JIT (cadena
     * RBP) marcara 0 young roots dentro de un loop JIT que dispara GC.  NO
     * invalida el boundary: la misma coleccion puede correr varias fases
     * (minor: este root-scan + @c scan_jit_forwards; major: otro root-scan)
     * sobre el mismo frame JIT llamador -- lo invalida el guard de la
     * runtime-entry al salir. */
    if (jit_boundary_valid_) {
        const jit::JitScanStats stats = jit::scan_aot_frames(
            &jit_precise_root_cb, &ctx, jit_boundary_pc_, jit_boundary_sp_);
        stats_.precise_roots_marked += ctx.roots_marked;
        stats_.precise_frames_scanned += stats.jit_frames;
        return;
    }

    /* INTERP/JIT: RBP del frame actual (major_gc).  Iniciamos la walk aqui;
     * el walker sigue la cadena hasta el bottom del stack. */
    const uint8_t *gc_rbp =
        static_cast<const uint8_t *>(__builtin_frame_address(0));

    /* Bounds del stack NATIVO del hilo: OBLIGATORIOS para la seguridad del
     * walk.  El interprete (y binarios -fomit-frame-pointer) NO mantienen una
     * cadena de frame-pointers valida, asi que seguir [rbp] sin acotar
     * deref-earia direcciones arbitrarias -> segfault dependiente del contenido
     * del stack.  Con los limites reales, cada lectura queda dentro del stack y
     * el walk termina de forma segura (no encuentra RIPs JIT en modo interp ->
     * ningun root, que es lo correcto).  El limite inferior efectivo es el
     * frame actual (la walk solo sube hacia la base). */
    const uint8_t *stk_low = nullptr;
    const uint8_t *stk_high = nullptr;
    if (!native_stack_bounds(stk_low, stk_high) || stk_low == nullptr ||
        stk_high == nullptr) {
        /* Sin limites fiables no es seguro caminar la cadena RBP: abortar el
         * scan JIT (aditivo -- el mark preciso/conservador + BFS ya cubre las
         * raices en interp).  Mejor perder este scan que arriesgar un deref
         * invalido. */
        return;
    }
    /* Clamp del limite inferior al frame actual: la walk nunca desciende por
     * debajo del frame de major_gc. */
    if (gc_rbp > stk_low) stk_low = gc_rbp;

    const jit::JitScanStats stats =
        jit::scan_jit_frames(&jit_precise_root_cb, &ctx, gc_rbp,
                             /*low=*/stk_low,
                             /*high=*/stk_high);

    stats_.precise_roots_marked += ctx.roots_marked;
    stats_.precise_frames_scanned += stats.jit_frames;
}

// -------------------------------------------------------------------------
//  Forward-update de host_ptrs en frames JIT tras evacuar (minor_gc).
// -------------------------------------------------------------------------

bool GcHeap::jit_forward_slot(uint64_t value, const uint8_t *slot_addr) {
    if (slot_addr == nullptr || value == 0 || value < 256) return false;
    const auto *p =
        reinterpret_cast<const uint8_t *>(static_cast<uintptr_t>(value));
    const uint8_t *const *fv = forward_table_.find(p);
    if (fv == nullptr) return false;
    const uint64_t new_v = reinterpret_cast<uint64_t>(*fv);
    // slot_addr apunta al slot de 8 bytes en la pila NATIVA del hilo actual
    // (escribible).  Sobrescribimos el host_ptr stale con el forwarded.
    std::memcpy(const_cast<uint8_t *>(slot_addr), &new_v, sizeof(new_v));
    return true;
}

namespace {
/**
 * @brief Contexto del walk de forward-update de frames JIT.
 */
struct JitForwardCtx {
    gc::GcHeap *heap;
    uint64_t updated;
};

/**
 * @brief Callback de @c scan_jit_frames para el forward-update: por cada slot
 *        HOSTPTR/STRING con un host_ptr evacuado, reescribe el slot con la
 * nueva direccion.  Los slots HANDLE no se tocan (el GcHandle es estable).
 */
void jit_forward_cb(void *ctx, uint64_t value, jit::StackmapGcKind kind,
                    const uint8_t *slot_addr) {
    auto *c = static_cast<JitForwardCtx *>(ctx);
    if (kind == jit::StackmapGcKind::HANDLE) return; // handle estable
    if (c->heap->jit_forward_slot(value, slot_addr)) ++c->updated;
}
} // namespace

void GcHeap::scan_jit_forwards() {
    if (forward_table_.empty()) return;
    if (jit::JitRegistry::instance().size() == 0) return;

    /* INTERP+JIT: si la runtime-entry capturo el frame JIT llamador, usar el
     * WALK POR TAMANO DE FRAME (mismo boundary que consumio el root-scan del
     * minor).  Sin esto, un slot HOSTPTR en un frame JIT que apunta a un young
     * evacuado quedaria stale (la cadena RBP se rompe en los frames C++ del
     * runtime) -> UAF con el GC movible. */
    if (jit_boundary_valid_) {
        JitForwardCtx ctx{this, 0};
        jit::scan_aot_frames(&jit_forward_cb, &ctx, jit_boundary_pc_,
                             jit_boundary_sp_);
        return;
    }

    const uint8_t *gc_rbp =
        static_cast<const uint8_t *>(__builtin_frame_address(0));
    const uint8_t *stk_low = nullptr;
    const uint8_t *stk_high = nullptr;
    if (!native_stack_bounds(stk_low, stk_high) || stk_low == nullptr ||
        stk_high == nullptr)
        return; // sin limites fiables no es seguro caminar la cadena RBP
    if (gc_rbp > stk_low) stk_low = gc_rbp;

    JitForwardCtx ctx{this, 0};
    jit::scan_jit_frames(&jit_forward_cb, &ctx, gc_rbp, stk_low, stk_high);
}

// -------------------------------------------------------------------------
//  Scan PRECISO del interprete (stackmaps VSMP) -- modo aditivo.
// -------------------------------------------------------------------------

namespace {
/**
 * @brief Contexto del callback de @c scan_interp_precise_roots.
 */
struct InterpPreciseCtx {
    gc::GcHeap *heap;
    std::vector<gc::GcHandle> *worklist;
    uint64_t roots_marked;
    uint64_t notified;
};

/**
 * @brief Callback C-style invocado por el provider para cada raiz precisa
 *        de un frame del interprete.
 *
 * HANDLE: el valor es directamente un GcHandle.
 * HOSTPTR/STRING: el valor es un host_ptr al payload -> handle_for_ptr.
 */
void interp_precise_root_cb(void *ctx, uint64_t value, uint8_t kind) {
    auto *c = static_cast<InterpPreciseCtx *>(ctx);
    ++c->notified;
    // kind reusa jit::StackmapGcKind (0=HANDLE 1=HOSTPTR 2=STRING).
    if (kind == static_cast<uint8_t>(jit::StackmapGcKind::HANDLE)) {
        const auto h = static_cast<gc::GcHandle>(value);
        if (c->heap->try_mark_precise_handle(h, *c->worklist))
            ++c->roots_marked;
    } else {
        if (value == 0) return;
        const auto *ptr = reinterpret_cast<const uint8_t *>(value);
        const gc::GcHandle h = c->heap->handle_for_ptr(ptr);
        if (h != gc::GC_NULL_HANDLE &&
            c->heap->try_mark_precise_handle(h, *c->worklist))
            ++c->roots_marked;
    }
}
} // namespace

namespace {
/**
 * @brief Callback C-style para el scan preciso del NURSERY (minor_gc).
 *
 * Identico a @c interp_precise_root_cb pero enruta a
 * @c try_mark_precise_young: solo marca objetos YOUNG (el minor_gc no toca
 * OLD).  Reusa @c InterpPreciseCtx.
 */
void interp_precise_young_root_cb(void *ctx, uint64_t value, uint8_t kind) {
    auto *c = static_cast<InterpPreciseCtx *>(ctx);
    ++c->notified;
    if (kind == static_cast<uint8_t>(jit::StackmapGcKind::HANDLE)) {
        const auto h = static_cast<gc::GcHandle>(value);
        if (c->heap->try_mark_precise_young(h, *c->worklist)) ++c->roots_marked;
    } else {
        if (value == 0) return;
        const auto *ptr = reinterpret_cast<const uint8_t *>(value);
        const gc::GcHandle h = c->heap->handle_for_ptr(ptr);
        if (h != gc::GC_NULL_HANDLE &&
            c->heap->try_mark_precise_young(h, *c->worklist))
            ++c->roots_marked;
    }
}
} // namespace

void GcHeap::scan_interp_young_roots_precise(std::vector<GcHandle> &worklist) {
    // Sin provider (p.ej. GC AOT standalone) o sin stackmaps -> no-op.  En AOT
    // el nursery queda vacio (vx_gc_alloc usa alloc_pinned -> OldGen), asi que
    // este scan no encuentra nada de todos modos.
    if (root_provider_ == nullptr) return;

    InterpPreciseCtx ctx{this, &worklist, 0, 0};
    root_provider_->scan_interp_precise_roots(&interp_precise_young_root_cb,
                                              &ctx);
    stats_.interp_precise_roots_marked += ctx.roots_marked;
    stats_.interp_precise_notified += ctx.notified;
}

void GcHeap::scan_interp_roots_precise(std::vector<GcHandle> &worklist) {
    // Sin provider (p.ej. GC AOT standalone) o sin stackmaps -> no-op.
    if (root_provider_ == nullptr) return;

    InterpPreciseCtx ctx{this, &worklist, 0, 0};
    root_provider_->scan_interp_precise_roots(&interp_precise_root_cb, &ctx);

    stats_.interp_precise_roots_marked += ctx.roots_marked;
    stats_.interp_precise_notified += ctx.notified;

    // Diagnostico temporal de desarrollo (verificador aditivo-vs-primario):
    // NO es un flag de producto.  Muestra la cobertura precisa-vs-conservador.
    // Gateado por FREESTANDING: el GC del AOT (libvesta_gc) no tiene libc/stdio
    // (arrastrar std::fprintf romperia el link con __mingw_fprintf sin
    // resolver) y ademas no hay pila de interprete que trazar en AOT.  Usa
    // gc_dbg_emit (write() syscall, freestanding-safe) en el build de la VM.
#if !defined(VESTA_GC_FREESTANDING)
    static const bool trace = [] {
        const char *v = std::getenv("VESTA_GC_INTERP_TRACE");
        return v && v[0] == '1';
    }();
    if (trace && ctx.notified > 0) {
        gc_dbg_emit("[gc-interp-precise] notified=%llu marked=%llu "
                    "(acc marked=%llu conservador=%llu)\n",
                    (unsigned long long)ctx.notified,
                    (unsigned long long)ctx.roots_marked,
                    (unsigned long long)stats_.interp_precise_roots_marked,
                    (unsigned long long)stats_.conservative_roots_marked);
        gc_debug_flush();
    }
#endif
}

// -------------------------------------------------------------------------
//  Verificador diferencial de COMPLETITUD (VESTA_GC_VERIFY=1, DEV-ONLY).
// -------------------------------------------------------------------------

#if !defined(VESTA_GC_FREESTANDING)
void GcHeap::verify_completeness(std::vector<GcHandle> &worklist) {
    stats_.verify_major_gc_checked++;

    // Paso 1: cerrar TRANSITIVAMENTE el conjunto preciso ya acumulado en
    // worklist (interp + JIT frames).  Tras esto, todo objeto OLD alcanzable
    // desde una raiz precisa esta BLACK.  Es idempotente con el BFS que el GC
    // corre despues (mark_reachable solo WHITE->BLACK) -> no cambia el
    // conjunto final de supervivientes.
    for (size_t i = 0; i < worklist.size(); ++i)
        mark_reachable(worklist[i], worklist);

    // Paso 2: recolectar CANDIDATOS a hueco via HOST_PTR (referencia genuina,
    // sin ambiguedad de coincidencia numerica).  Un valor en pila/regs que
    // resuelve a un objeto OLD vivo via handle_for_ptr (exacto o interior) es
    // un puntero real.  Si el cierre preciso NO lo alcanzo (sigue WHITE), es un
    // CANDIDATO a hueco.
    //
    // IMPORTANTE -- por que es CANDIDATO y no hueco confirmado: un host_ptr
    // puede ser RANCIO (memoria de pila reusada -- p.ej. un slot ALLOCA o un
    // registro scratch que contuvo el ptr de un objeto ya MUERTO cuyo handle
    // aun no fue barrido).  Ese objeto NO es raiz real (nadie lo usa), asi que
    // es CORRECTO que el preciso no lo marque -- es un falso positivo del
    // conservador, no un hueco.  El diferencial solo (aditivo) no puede
    // distinguirlos con certeza.
    //
    // La AUTORIDAD de completitud es el modo PRECISO-PURO (VESTA_GC_PRECISE_
    // ONLY=1 + STRESS): si el programa produce el MISMO resultado con el
    // conservador desactivado, el preciso captura TODAS las raices reales y
    // los candidatos que este diferencial reporta son ranciedades (confirmado
    // empiricamente sobre todo el corpus GC).  Este diferencial sirve para
    // LOCALIZAR los candidatos; el preciso-puro CONFIRMA si son reales.
    //
    // NO contamos coincidencias por handle-numerico bare (value == handle
    // pequeno): esas SI pueden ser un escalar del programa; falso positivo que
    // el preciso elimina legitimamente.
    uint64_t rsp = 0, high = 0, regs[16];
    if (!root_provider_->vm_stack_regs(rsp, high, regs)) return;
    auto *vmem = root_provider_->vm_mem();
    if (vmem == nullptr) return;

    // Limitar el rango de pila al REALMENTE ACTIVO (mismo watermark que el
    // conservador usa): por debajo del low-water los slots ya no son
    // alcanzables.  Reduce ranciedades sin perder cobertura de raices vivas.
    const uint64_t low = root_provider_->stack_low_water();
    if (low != 0 && low > rsp) rsp = low;

    // Conjunto de handles ya reportados este ciclo (evita doble-conteo del
    // mismo objeto referenciado desde varios slots).
    std::vector<GcHandle> gap_handles;

    auto check_hostptr = [&](uint64_t v) {
        // Igual criterio de rango que scan_stack_roots: descartar NULL y
        // escalares pequenos que nunca son host_ptrs canonicos.
        if (v < 65536) return;
        if ((v & 7) != 0) return; // host_ptr GC siempre alineado a 8
        const auto *ptr =
            reinterpret_cast<const uint8_t *>(static_cast<uintptr_t>(v));
        GcHandle h = handle_for_ptr(ptr);
        if (h == GC_NULL_HANDLE) {
            // Intento de interior scan en OldGen (STRRAW -> data[] a offset
            // 40).
            for (auto &block : old_blocks_) {
                uint8_t *bend = block.ptr + block.bump_offset;
                if (ptr < block.ptr || ptr >= bend) continue;
                GcHeader *hdr = find_containing_header(
                    block.ptr, block.bump_offset, const_cast<uint8_t *>(ptr));
                if (hdr == nullptr) return;
                uint8_t *payload =
                    reinterpret_cast<uint8_t *>(hdr) + sizeof(GcHeader);
                h = ptr_to_handle_.find(payload);
                break;
            }
            if (h == GC_NULL_HANDLE) return;
        }
        if (h >= handles_.size() || !handles_[h].live || !handles_[h].addr)
            return;
        auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
        if (hdr->gen != GcGen::OLD) return; // young lo cubre minor_gc
        // Objeto GC vivo referenciado por un host_ptr real.  Es raiz real.
        // Si el cierre preciso NO lo alcanzo (WHITE) -> HUECO de completitud.
        if (hdr->color == GcColor::WHITE) {
            for (GcHandle g : gap_handles)
                if (g == h) return; // ya reportado
            gap_handles.push_back(h);
        }
    };

    if (rsp < high && (high - rsp) < (16 * 1024 * 1024)) {
        for (uint64_t addr = rsp; addr + 8 <= high; addr += 8)
            check_hostptr(vmem->read_u64(addr));
    }
    for (int i = 0; i < 16; ++i)
        check_hostptr(regs[i]);

    if (!gap_handles.empty()) {
        stats_.verify_gap_roots += gap_handles.size();
        gc_dbg_emit(
            "[gc-verify] CANDIDATO: %zu obj(s) GC via host_ptr que el PRECISO "
            "no marco (major_gc #%llu) -- confirmar con PRECISE_ONLY. handles:",
            gap_handles.size(), (unsigned long long)stats_.major_gc_count);
        for (GcHandle h : gap_handles)
            gc_dbg_emit(" %u", (unsigned)h);
        gc_dbg_emit("\n");
        gc_debug_flush();
    }
}
#endif // !VESTA_GC_FREESTANDING

// -------------------------------------------------------------------------
// update_stack_forwards - actualiza host_ptrs en stack/regs tras evacuar
// -------------------------------------------------------------------------

void GcHeap::update_stack_forwards(uint64_t rsp_lo, uint64_t stack_high,
                                   uint64_t regs[16],
                                   vm::VirtualMemory &vm_mem) {
    // Si no hubo evacuaciones, no hay nada que actualizar.
    if (forward_table_.empty()) return;

    // 1. Walk stack: para cada slot 8-byte aligned, si el valor coincide
    //    con un forward source, reemplazar por el destino.
    if (rsp_lo < stack_high && (stack_high - rsp_lo) < (16 * 1024 * 1024)) {
        for (uint64_t addr = rsp_lo; addr + 8 <= stack_high; addr += 8) {
            const uint64_t v = vm_mem.read_u64(addr);
            if (v == 0 || v < 256) continue;
            auto *p =
                reinterpret_cast<const uint8_t *>(static_cast<uintptr_t>(v));
            const uint8_t *const *fv = forward_table_.find(p);
            if (fv != nullptr) {
                const uint64_t new_v = reinterpret_cast<uint64_t>(*fv);
                vm_mem.write_bytes(addr, &new_v, 8);
            }
        }
    }

    // 2. Walk GP regs R0..R15: misma logica.
    for (int i = 0; i < 16; ++i) {
        const uint64_t v = regs[i];
        if (v == 0 || v < 256) continue;
        auto *p = reinterpret_cast<const uint8_t *>(static_cast<uintptr_t>(v));
        const uint8_t *const *fv = forward_table_.find(p);
        if (fv != nullptr) {
            regs[i] = reinterpret_cast<uint64_t>(*fv);
        }
    }
}

GcHandle GcHeap::alloc_pinned(size_t size) {
    const size_t total = (sizeof(GcHeader) + size + 7) & ~7ULL;
    size_t actual_total = 0;
    uint8_t *raw = alloc_in_old_with_total(total, actual_total);
    if (!raw) return GC_NULL_HANDLE;
    // Inicializacion del header / contadores: equivalente al lambda
    // init_obj de @c alloc, pero inlineado porque la lambda es local
    // a aquel metodo.  Convencion OldGen: hdr->size = payload del
    // slot incluyendo padding hasta size class (necesario para que
    // free_in_old encuentre la free list correcta).
    auto *hdr = reinterpret_cast<GcHeader *>(raw);
    hdr->size = static_cast<uint32_t>(actual_total - sizeof(GcHeader));
    hdr->color = GcColor::WHITE;
    hdr->gen = GcGen::OLD;
    std::memset(raw + sizeof(GcHeader), 0, size);
    stats_.alloc_count++;
    stats_.alloc_bytes += size;
    if (old_used_ > stats_.peak_old) stats_.peak_old = old_used_;
    return new_handle(raw);
}

// -------------------------------------------------------------------------
// deref
// -------------------------------------------------------------------------

uint8_t *GcHeap::deref(GcHandle h) {
    //  Z.5/Z.6: bit 31 = SHARED_HANDLE_BIT.  Si esta set, el
    // handle apunta a un objeto del @c SharedHeap (cross-process,
    // accesible por todos los procesos de la misma VM); resolvemos
    // via la tabla global @c shared_handle_table.
    //
    // Branch predicted always-not-taken para objetos locales (caso
    // dominante).  Coste estimado en x86-64 moderno: ~0 ns para
    // handles locales (branch predicho), ~5 ns para handles shared
    // (2 atomic loads: chunk + slot).
    if (h & SHARED_HANDLE_BIT) {
        if (!root_provider_) return nullptr;
        return root_provider_->shared_lookup(h);
    }
    if (h >= handles_.size() || !handles_[h].live) return nullptr;
    return handles_[h].addr + sizeof(GcHeader);
}

// -------------------------------------------------------------------------
// Finalizadores GC
// -------------------------------------------------------------------------

void GcHeap::register_finalizer(uint8_t *payload, GcFinalizerKind kind,
                                uint64_t dtor_vaddr) {
    if (payload == nullptr || kind == GcFinalizerKind::NONE) return;
    // El GcHeader precede al payload en memoria (layout [GcHeader][payload]).
    auto *hdr = reinterpret_cast<GcHeader *>(payload - sizeof(GcHeader));
    hdr->has_finalizer = 1;
    hdr->finalizer_kind = static_cast<uint8_t>(kind) & 0x3;
    // CLASS_DTOR: guardar el vaddr del dtor concreto en la side-table (la
    // instancia de clase no lo lleva inline).  Keyed por el host_ptr del
    // payload, estable mientras el objeto no se evacue (los boxes gc<Clase>
    // usan alloc_pinned -> OldGen non-moving -> el ptr es estable).
    // Freestanding -safe (U64U64Map hash open-addressing): mismo camino en
    // interp/JIT/AOT, cierra la fuga de gc<Clase> con ~Clase() en AOT.  O(1)
    // amortizado.
    // Y UNIQUE igual: quien libera lo dice el TIPO del box, asi que quien lo
    // registra lo sabe al COMPILAR y lo pasa aqui.  Antes se leia del propio
    // box (la palabra de al lado del puntero), que es la unica razon por la
    // que un `unique<T>` media dos palabras en vez de una.
    if (kind == GcFinalizerKind::CLASS_DTOR ||
        kind == GcFinalizerKind::UNIQUE) {
        const uint64_t key = reinterpret_cast<uint64_t>(payload);
        // set() sobrescribe si ya existe (re-registro del mismo host_ptr).
        finalizer_target_.set(key, dtor_vaddr);
    }
}

void GcHeap::unregister_finalizer(uint8_t *payload) {
    if (payload == nullptr) return;
    auto *hdr = reinterpret_cast<GcHeader *>(payload - sizeof(GcHeader));
    hdr->has_finalizer = 0;
    hdr->finalizer_kind = 0;
    // Quitar la entrada de la tabla lateral (hash erase, O(1) amortizado).
    const uint64_t key = reinterpret_cast<uint64_t>(payload);
    finalizer_target_.erase(key);
}

void GcHeap::stage_finalizer(GcHeader *hdr, uint8_t *payload) {
    // Copia el CONTENIDO relevante del box (aun valido en el sweep) al pending,
    // para que el drenado posterior (fuera del GC) no dependa del box liberado.
    const GcFinalizerKind kind =
        static_cast<GcFinalizerKind>(hdr->finalizer_kind);
    GcPendingFinalizer f{};
    f.kind = kind;
    if (kind == GcFinalizerKind::CLASS_DTOR) {
        // CLASS_DTOR: a0 = dtor_vaddr (side-table), a1 = obj_host_ptr (el
        // payload = la instancia).  El runner invoca dtor_vaddr(obj_host_ptr).
        // take() = lookup + borrado en una sola pasada (hash, O(1) amortizado).
        const uint64_t key = reinterpret_cast<uint64_t>(payload);
        f.a0 = 0;
        finalizer_target_.take(key, f.a0);
        f.a1 = reinterpret_cast<uint64_t>(payload);
    } else {
        // El box guarda UNA palabra: el puntero al recurso (UNIQUE) o al
        // bloque de control (SHARED).
        std::memcpy(&f.a0, payload, sizeof(uint64_t));
        f.a1 = 0;
        // Y quien libera un UNIQUE sale de la tabla lateral, no del box: lo
        // dejo puesto quien registro el finalizador, que conocia el TIPO.
        // Leerlo del box obligaba a que el box llevara una palabra de mas.
        if (kind == GcFinalizerKind::UNIQUE) {
            const uint64_t key = reinterpret_cast<uint64_t>(payload);
            finalizer_target_.take(key, f.a1);
        }
    }
    pending_finalizers_.push_back(f);
    hdr->has_finalizer = 0;
}

void GcHeap::run_pending_finalizers() {
    // Guard de reentrada: si ya estamos drenando (un finalizador disparo un
    // GC que a su vez stageo mas finalizadores), NO re-drenar aqui -- el bucle
    // externo procesara la cola actualizada.  Sin esto, un finalizador que
    // aloca podria recursar indefinidamente.
    if (finalizing_) return;
    if (pending_finalizers_.empty()) return;
    if (finalizer_runner_ == nullptr) {
        // Sin ejecutor instalado (solo posible pre-init): descartar la cola
        // para no acumular trabajo colgante.  No hay crash; el recurso se fuga.
        pending_finalizers_.clear();
        return;
    }
    finalizing_ = true;
    // Procesar por indice: el runner puede (via un GC anidado) APPEND-ear mas
    // entradas; el guard impide un drenado anidado, pero este bucle SI las
    // recoge porque re-lee size() en cada vuelta.  Cada entrada se ejecuta
    // EXACTAMENTE una vez.
    for (size_t i = 0; i < pending_finalizers_.size(); ++i)
        finalizer_runner_(finalizer_owner_, pending_finalizers_[i]);
    pending_finalizers_.clear();
    finalizing_ = false;
}

void GcHeap::stage_all_live_finalizers() {
    // Recorrer la tabla de handles: cubre YOUNG (nursery) y OLD (promovidos)
    // porque todo objeto vivo tiene una entrada live con addr != nullptr.
    for (GcHandle h = 0; h < static_cast<GcHandle>(handles_.size()); ++h) {
        if (!handles_[h].live || !handles_[h].addr) continue;
        auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
        if (hdr->has_finalizer) {
            uint8_t *payload = handles_[h].addr + sizeof(GcHeader);
            stage_finalizer(hdr, payload);
        }
    }
}

void GcHeap::finalize_all_live() {
    stage_all_live_finalizers();
    run_pending_finalizers();
}

// -------------------------------------------------------------------------
// write_barrier  - O(1) con unordered_set
// -------------------------------------------------------------------------

void GcHeap::write_barrier(GcHandle old_handle) {
    // Filtro generacional: solo interesa old->young.  Si el contenedor NO es
    // OLD (YOUNG recien alocado, o handle invalido/muerto), no ensuciar el
    // remembered_set: un contenedor YOUNG con refs young ya se alcanza por el
    // BFS del nursery (o esta muerto), y al promoverse co-evacua sus refs en el
    // mismo minor.  El barrier SOLO importa cuando un objeto YA OLD recibe una
    // referencia young en un campo (store post-promocion).  Sound: sin el
    // filtro solo habria mas entradas (over-approx); con el filtro el set queda
    // minimo (old->young reales).  Barato: 1 lookup + 1 check de generacion.
    if (old_handle == GC_NULL_HANDLE ||
        old_handle >= static_cast<GcHandle>(handles_.size()))
        return;
    if (!handles_[old_handle].live || !handles_[old_handle].addr) return;
    const auto *hdr =
        reinterpret_cast<const GcHeader *>(handles_[old_handle].addr);
    if (hdr->gen != GcGen::OLD) return; // contenedor YOUNG -> no-op
    remembered_set_.insert(old_handle);
}

// -------------------------------------------------------------------------
// External refcount API.
//
// El GcHeap es per-process y NO multi-thread (uso exclusivo del thread
// owner del proceso, garantizado por el scheduler).  Por tanto, no hay
// necesidad de atomics ni locks en estas APIs: el plugin nativo se
// ejecuta en el mismo thread que esta procesando bytecode del proceso.
// Si futuro se introduce un GC concurrente o pre-emptive, deberian
// anadirse atomics y/o locks aqui.
// -------------------------------------------------------------------------

void GcHeap::gc_addref(GcHandle h) {
    if (h == GC_NULL_HANDLE) return;
    // Lookup-or-insert con valor inicial 0, despues incrementar.
    // operator[] inserta automaticamente si no existe.
    external_refs_[h] += 1;
}

void GcHeap::gc_release(GcHandle h) {
    if (h == GC_NULL_HANDLE) return;
    uint32_t *rc = external_refs_.find(h);
    if (rc == nullptr) return; // no estaba pinnado: no-op
    if (*rc > 1) {
        *rc -= 1;
    } else {
        // Al llegar a 0 eliminamos la entrada para que el bucket se libere
        // y el mark  no malgaste tiempo iterando handles ya liberados.
        external_refs_.erase(h);
    }
}

// -------------------------------------------------------------------------
// do_evacuate - nucleo de evacuacion sin comprobacion de liveness
// -------------------------------------------------------------------------

void GcHeap::do_evacuate(GcHandle h) {
    uint8_t *src_raw = handles_[h].addr;
    if (!src_raw) return;

    auto *hdr = reinterpret_cast<GcHeader *>(src_raw);
    // Bug fix 2026-05-23: NO skipear si color == BLACK.  El scan_stack_roots
    // (y mi BFS de minor_gc) marca BLACK ANTES de invocar do_evacuate; el
    // check anterior `color == BLACK` causaba que do_evacuate se saltara
    // los roots reciem marcados -> nunca movian a OldGen -> al resetear
    // nursery_bump_ sus addr quedaban dangling -> linked list corrupta.
    // Solo skipear si ya esta en OLD (donde no aplica evacuacion).
    if (hdr->gen == GcGen::OLD) return;

    const size_t total = (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;
    // (iv) alloc_in_old_with_total reporta el slot REAL en OldGen
    // (puede ser >= total por redondeo a size class).  Actualizamos
    // dst_hdr->size con el slot real para que al re-free el slot
    // encaje exactamente en su size class.
    size_t actual_total = 0;
    uint8_t *dst_raw = alloc_in_old_with_total(total, actual_total);
    if (!dst_raw) return;

    // Copiamos solo `total` bytes (el slot fuente); los bytes extras del
    // slot destino quedan inaccesibles para el usuario (padding interno).
    std::memcpy(dst_raw, src_raw, total);

    auto *dst_hdr = reinterpret_cast<GcHeader *>(dst_raw);
    dst_hdr->gen = GcGen::OLD;
    dst_hdr->color = GcColor::BLACK;
    // Actualizar size al payload real del slot OldGen (>= payload original).
    dst_hdr->size = static_cast<uint32_t>(actual_total - sizeof(GcHeader));

    handles_[h].addr = dst_raw;

    // Mover la entrada del mapa inverso payload_ptr -> handle.  El
    // payload anterior se marcara como forward pointer y dejara de
    // ser un puntero valido a un objeto vivo, asi que lo retiramos.
    uint8_t *src_payload = src_raw + sizeof(GcHeader);
    uint8_t *dst_payload = dst_raw + sizeof(GcHeader);
    ptr_to_handle_.erase(src_payload);
    ptr_to_handle_.insert_or_assign(dst_payload, h);

    // Forward pointer en payload original para detectar doble evacuacion.
    // Tambien registramos en forward_table_ para que update_stack_forwards
    // pueda actualizar host_ptrs en stack/regs tras la evacuacion completa.
    // El forward apunta al PAYLOAD destino (no al header) porque los
    // host_ptrs en bytecode siempre son ptrs a payload start (resultado
    // de gcderef tras NEWOBJ).
    std::memcpy(src_payload, &dst_payload, sizeof(void *));
    forward_table_[src_payload] = dst_payload;
    hdr->color = GcColor::BLACK;

    stats_.promoted_count++;
    stats_.promoted_bytes += hdr->size;
    if (old_used_ > stats_.peak_old) stats_.peak_old = old_used_;
}

void GcHeap::evacuate_object(GcHandle h) {
    if (h >= handles_.size() || !handles_[h].addr) return;
    do_evacuate(h);
}

// -------------------------------------------------------------------------
// scan_young_refs - escanea payload buscando handles VIVOS que apunten a YOUNG
// -------------------------------------------------------------------------

void GcHeap::scan_young_refs(GcHandle h, std::vector<GcHandle> &worklist) {
    if (!handles_[h].addr) return;

    auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
    uint8_t *payload = handles_[h].addr + sizeof(GcHeader);
    size_t sz = hdr->size;

    for (size_t off = 0; off + sizeof(GcHandle) <= sz;
         off += sizeof(GcHandle)) {
        GcHandle ref;
        std::memcpy(&ref, payload + off, sizeof(GcHandle));

        if (ref == GC_NULL_HANDLE ||
            ref >= static_cast<GcHandle>(handles_.size()))
            continue;
        // Solo seguir handles vivos para evitar falsos positivos con datos
        // numericos
        if (!handles_[ref].live || !handles_[ref].addr) continue;

        uint8_t *ref_raw = handles_[ref].addr;
        if (ref_raw < nursery_base_ || ref_raw >= nursery_end_) continue;

        auto *ref_hdr = reinterpret_cast<GcHeader *>(ref_raw);
        if (ref_hdr->color != GcColor::WHITE) continue;

        // MARK+PUSH (NO evacuar aqui): dejamos que el BFS transitivo del
        // minor_gc siga la cadena (old->young1->young2...) y que el bucle de
        // evacuacion unificado mueva TODO.  Si evacuaramos aqui, los hijos
        // transitivos del young directo-desde-old quedarian sin visitar.
        ref_hdr->color = GcColor::BLACK;
        worklist.push_back(ref);
    }
}

// -------------------------------------------------------------------------
// mark_reachable - BFS sobre handles VIVOS embebidos en payloads OLD
// -------------------------------------------------------------------------

void GcHeap::mark_reachable(GcHandle h, std::vector<GcHandle> &worklist) {
    if (!handles_[h].addr) return;

    auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
    uint8_t *payload = handles_[h].addr + sizeof(GcHeader);
    size_t sz = hdr->size;

    // Modo AOT (native_poo): los campos-referencia guardan host_ptrs CRUDOS,
    // no GcHandles -> el word-scan por indices de abajo no los seguiria.  Se
    // traza PRECISO via el field-map del descriptor de tipo (obj[0]): solo los
    // offsets de campos gc<Y>.  Esto hace el mark SOUND (sin ello, un objeto
    // alcanzable solo via un campo quedaria WHITE y se colectaria -> UAF).
    if (aot_precise_roots_) {
        for_each_gc_field(
            hdr, payload, sz, stats_, [&](uint32_t, uint64_t fptr) {
                const GcHandle ref =
                    handle_for_ptr(reinterpret_cast<const uint8_t *>(fptr));
                if (ref == GC_NULL_HANDLE ||
                    ref >= static_cast<GcHandle>(handles_.size()))
                    return;
                if (!handles_[ref].live || !handles_[ref].addr) return;
                auto *ref_hdr =
                    reinterpret_cast<GcHeader *>(handles_[ref].addr);
                if (ref_hdr->gen != GcGen::OLD ||
                    ref_hdr->color != GcColor::WHITE)
                    return;
                ref_hdr->color = GcColor::BLACK;
                worklist.push_back(ref);
            });
        return;
    }

    for (size_t off = 0; off + sizeof(GcHandle) <= sz;
         off += sizeof(GcHandle)) {
        GcHandle ref;
        std::memcpy(&ref, payload + off, sizeof(GcHandle));

        if (ref == GC_NULL_HANDLE ||
            ref >= static_cast<GcHandle>(handles_.size()))
            continue;
        // Solo seguir handles vivos: un handle soltado con drop() no mantiene
        // vivo al objeto aunque su valor este embebido en el payload
        if (!handles_[ref].live || !handles_[ref].addr) continue;

        auto *ref_hdr = reinterpret_cast<GcHeader *>(handles_[ref].addr);
        if (ref_hdr->gen != GcGen::OLD || ref_hdr->color != GcColor::WHITE)
            continue;

        ref_hdr->color = GcColor::BLACK;
        worklist.push_back(ref);
    }
}

// -------------------------------------------------------------------------
// Minor GC - Cheney-style
// -------------------------------------------------------------------------

void GcHeap::minor_gc() {
    stats_.minor_gc_count++;
    GC_LOGF("minor_gc start (count=%llu, nursery_used=%llu)",
            (unsigned long long)stats_.minor_gc_count,
            (unsigned long long)(nursery_bump_ - nursery_base_));

    // usar scan_stack_roots tambien en minor_gc para
    // evitar evacuar objetos YOUNG que NO son alcanzables desde stack
    // /regs/external_refs.  Sin esto, todos los handles live se
    // evacuaban a OldGen indiscriminadamente -> Old crecia rapido
    // -> major_gc se disparaba constantemente.
    //
    // Pre-mark: poner WHITE todos los YOUNG live (color por defecto
    // tras alloc).  Luego scan_stack_roots marca BLACK los alcanzables
    // (tanto YOUNG como OLD; OLD se ignora porque el sweep aqui solo
    // procesa young).  Solo evacuamos los BLACK.
    for (GcHandle h = 0; h < static_cast<GcHandle>(handles_.size()); ++h) {
        if (!handles_[h].live || !handles_[h].addr) continue;
        uint8_t *raw = handles_[h].addr;
        if (raw < nursery_base_ || raw >= nursery_end_) continue;
        auto *hdr = reinterpret_cast<GcHeader *>(raw);
        if (hdr->gen == GcGen::YOUNG) hdr->color = GcColor::WHITE;
    }

    // MIGRACION DEL NURSERY A RAICES PRECISAS
    // (scan_interp_young_roots_precise).
    //
    // El scan PRECISO (stackmaps VSMP) reporta TODAS las raices GC del
    // interprete independientemente de la generacion; el enrutado a
    // try_mark_precise_young marca los YOUNG DIRECTAMENTE alcanzables desde la
    // pila/regs.  Es el mismo mecanismo que el major_gc usa para OldGen.
    //
    // BLOQUEANTE ESTRUCTURAL (por eso el preciso young es OPT-IN, NO el
    // default): un minor_gc generacional preciso NECESITA un WRITE-BARRIER
    // old->young para encontrar los YOUNG alcanzables SOLO a traves de un campo
    // de un objeto OLD (p.ej. `l.head` cuando `l` ya se promovio).  El opcode
    // `gcwb` + remembered_set EXISTEN, pero el frontend Vesta NUNCA los emite
    // en stores de campo (los baja a STORE/movh de host_ptr, sin barrier) ->
    // remembered_set queda VACIO.  El scan CONSERVADOR enmascara este hueco al
    // retener esos young via slots rancios de la pila VM.  Sin el
    // write-barrier, hacer el young preciso PRIMARIO perderia los young
    // alcanzables solo via old (UAF con el GC moving).  Hasta que exista el
    // write-barrier, el conservador sigue siendo el PRIMARIO del nursery
    // (comportamiento previo, sound en la practica).  El preciso young se
    // activa para validacion/futuro con VESTA_GC_YOUNG_PRECISE=1 (aditivo con
    // el conservador salvo que ademas se pida VESTA_GC_PRECISE_ONLY=1).
    std::vector<GcHandle> worklist;

#if !defined(VESTA_GC_FREESTANDING)
    static const bool minor_precise_only_forced = [] {
        const char *v = std::getenv("VESTA_GC_PRECISE_ONLY");
        return v && v[0] == '1';
    }();
    // VESTA_GC_CONSERVATIVE=1 (DEV-ONLY): re-activa el conservador del nursery
    // como red de seguridad / diagnostico (espeja el major_gc).
    static const bool minor_conservative_forced = [] {
        const char *v = std::getenv("VESTA_GC_CONSERVATIVE");
        return v && v[0] == '1';
    }();
#else
    constexpr bool minor_precise_only_forced = false;
    constexpr bool minor_conservative_forced = false;
#endif

    // FLIP A PRECISO-PRIMARIO del nursery (espeja el major_gc; cierra la ultima
    // pieza del GC preciso).  El scan PRECISO del nursery (stackmaps VSMP ->
    // try_mark_precise_young) es ahora el mecanismo PRIMARIO de raices YOUNG.
    // El write-barrier old->young (gcwb, emitido por el frontend en cada store
    // de campo-CLASS y filtrado a old->young reales por write_barrier()) puebla
    // el remembered_set -> los young alcanzables SOLO via un campo de un objeto
    // OLD (p.ej. la cola young de una lista cuyo head ya es OLD) sobreviven. El
    // scan CONSERVADOR de la pila deja de ser primario: sus falsos positivos
    // (host_ptrs rancios) retenian young ya muertos -> no-determinismo.  Queda
    // como fallback GATEADO (igual que en major_gc):
    //   - VESTA_GC_CONSERVATIVE=1 -> conservador aditivo (diagnostico / dev).
    //   - VESTA_GC_PRECISE_ONLY=1 -> preciso-puro incluso con .velb legacy.
    // BACKWARD-COMPAT por-ejecutable: un .velb SIN seccion VSMP (legacy) no
    // lleva stackmaps -> all_interp_frames_have_stackmaps() == false ->
    // conservador primario para no perder raices de sus frames.
    scan_interp_young_roots_precise(worklist);

    // Frames JIT nativos: raices YOUNG precisas via stackmaps (mismo walk que
    // el major_gc pero enrutado a try_mark_precise_young).  Imprescindible al
    // flipear a preciso-primario: el scan de interp SOLO cubre frames del
    // interprete; un objeto young cuya unica raiz viva vive en un frame
    // JIT-compilado (p.ej. el `head`/`tail` de un build() JIT-eado) se perderia
    // sin esto.  En AOT (aot_precise_roots_) el nursery queda vacio -> se
    // omite.
    if (!aot_precise_roots_) scan_jit_roots_precise(worklist, /*young=*/true);

    // Decidir si corre el conservador de la pila del interprete (fallback).
    bool run_conservative_minor = false;
    if (!minor_precise_only_forced) {
        if (minor_conservative_forced) {
            run_conservative_minor = true; // forzado por env (aditivo)
        } else if (root_provider_ != nullptr &&
                   !root_provider_->all_interp_frames_have_stackmaps()) {
            run_conservative_minor = true; // algun ejecutable legacy sin VSMP
        }
    }

    uint64_t rsp = 0, stack_high = 0;
    uint64_t regs[16];
    if (run_conservative_minor && root_provider_ != nullptr &&
        root_provider_->vm_stack_regs(rsp, stack_high, regs) &&
        root_provider_->vm_mem() != nullptr) {
        scan_stack_roots(rsp, stack_high, regs, *root_provider_->vm_mem(),
                         worklist);
    } else if (root_provider_ == nullptr && !aot_precise_roots_) {
        // Fallback: modelo previo (todos los handles live = root).  Solo si no
        // hay provider NI modo AOT (defensivo para tests/setups especiales).
        // En modo AOT vx_gc_alloc usa alloc_pinned (OldGen) -> el nursery
        // queda vacio -> minor_gc no toca objetos gc<T>; solo major_gc.
        for (GcHandle h = 0; h < static_cast<GcHandle>(handles_.size()); ++h) {
            if (!handles_[h].live || !handles_[h].addr) continue;
            uint8_t *raw = handles_[h].addr;
            if (raw < nursery_base_ || raw >= nursery_end_) continue;
            auto *hdr = reinterpret_cast<GcHeader *>(raw);
            if (hdr->gen == GcGen::YOUNG && hdr->color == GcColor::WHITE) {
                hdr->color = GcColor::BLACK;
                worklist.push_back(h);
            }
        }
    }

    // external_refs: handles pinnados por plugins nativos.
    for (const auto &kv : external_refs_) {
        const GcHandle h = kv.first;
        if (kv.second == 0) continue;
        if (h >= handles_.size()) continue;
        if (!handles_[h].live || !handles_[h].addr) continue;
        uint8_t *raw = handles_[h].addr;
        if (raw < nursery_base_ || raw >= nursery_end_) continue;
        auto *hdr = reinterpret_cast<GcHeader *>(raw);
        if (hdr->color == GcColor::WHITE) {
            hdr->color = GcColor::BLACK;
            worklist.push_back(h);
        }
    }

    // pending_alloc_root_: handle en construccion.
    if (pending_alloc_root_ != GC_NULL_HANDLE &&
        pending_alloc_root_ < handles_.size() &&
        handles_[pending_alloc_root_].live &&
        handles_[pending_alloc_root_].addr) {
        uint8_t *raw = handles_[pending_alloc_root_].addr;
        if (raw >= nursery_base_ && raw < nursery_end_) {
            auto *hdr = reinterpret_cast<GcHeader *>(raw);
            if (hdr->color == GcColor::WHITE) {
                hdr->color = GcColor::BLACK;
                worklist.push_back(pending_alloc_root_);
            }
        }
    }

    // Raices del REMEMBERED SET (write-barrier old->young): objetos OLD que
    // recibieron una referencia YOUNG en un campo (store post-promocion).  Para
    // cada uno, scan_young_refs MARCA+PUSH los young DIRECTOS al worklist (NO
    // evacua).  DEBE correr ANTES del BFS de abajo: asi la cadena transitiva
    // (old->young1->young2...) se sigue por el mismo BFS y la evacuacion
    // unificada mueve TODO.  (Antes se escaneaba DESPUES de la evacuacion con
    // un worklist local que se descartaba -> los hijos transitivos del young
    // directo-desde-old se perdian.)
    for (GcHandle old_h : remembered_set_) {
        if (old_h >= static_cast<GcHandle>(handles_.size()) ||
            !handles_[old_h].live || !handles_[old_h].addr)
            continue;
        scan_young_refs(old_h, worklist);
    }

    // Bug fix 2026-05-23: BFS transitivo sobre YOUNG.  Sin esto, solo
    // los roots inmediatos (cur, head desde regs/stack) se marcaban,
    // pero la cadena interna `head.next.next.next...` quedaba WHITE
    // y el sweep la mataba.  Sintoma: linked list pierde ~87% de
    // nodos al cruzar el limite del nursery.
    //
    // Patron: por cada h en worklist (YOUNG BLACK), escanear su payload
    // buscando handles a otros YOUNG vivos.  Si esta WHITE, marcar
    // BLACK + push al worklist (que se procesa en el mismo loop).
    for (size_t wi = 0; wi < worklist.size(); ++wi) {
        const GcHandle h = worklist[wi];
        if (h >= handles_.size() || !handles_[h].live || !handles_[h].addr)
            continue;
        uint8_t *raw = handles_[h].addr;
        if (raw < nursery_base_ || raw >= nursery_end_) continue; // solo YOUNG
        auto *hdr = reinterpret_cast<GcHeader *>(raw);
        uint8_t *payload = raw + sizeof(GcHeader);
        const size_t sz = hdr->size;
        for (size_t off = 0; off + sizeof(GcHandle) <= sz;
             off += sizeof(GcHandle)) {
            GcHandle ref;
            std::memcpy(&ref, payload + off, sizeof(GcHandle));
            if (ref == GC_NULL_HANDLE ||
                ref >= static_cast<GcHandle>(handles_.size()))
                continue;
            if (!handles_[ref].live || !handles_[ref].addr) continue;
            uint8_t *ref_raw = handles_[ref].addr;
            if (ref_raw < nursery_base_ || ref_raw >= nursery_end_) continue;
            auto *ref_hdr = reinterpret_cast<GcHeader *>(ref_raw);
            if (ref_hdr->color != GcColor::WHITE) continue;
            ref_hdr->color = GcColor::BLACK;
            worklist.push_back(ref);
        }
    }

    // Evacuar SOLO los YOUNG marcados BLACK (alcanzables).  Los WHITE
    // se descartan al resetear nursery_bump_ abajo.
    for (GcHandle h : worklist) {
        if (h >= handles_.size() || !handles_[h].live || !handles_[h].addr)
            continue;
        uint8_t *raw = handles_[h].addr;
        if (raw < nursery_base_ || raw >= nursery_end_) continue;
        auto *hdr = reinterpret_cast<GcHeader *>(raw);
        if (hdr->gen == GcGen::YOUNG) {
            do_evacuate(h);
        }
    }

    // (El scan del remembered_set old->young corre ARRIBA, antes del BFS y de
    // la evacuacion, para que la cadena transitiva old->young1->young2 se
    // evacue completa.  Aqui ya no se re-escanea.)

    // los handles YOUNG no evacuados (color WHITE tras
    // scan) deben liberarse: handles_[h].live = false + payload_ptr
    // borrado del ptr_to_handle_.  Sin esto, los handles quedan live
    // pero su addr apunta al nursery que se va a resetear -> dangling.
    for (GcHandle h = 0; h < static_cast<GcHandle>(handles_.size()); ++h) {
        if (!handles_[h].live || !handles_[h].addr) continue;
        uint8_t *raw = handles_[h].addr;
        if (raw < nursery_base_ || raw >= nursery_end_) continue;
        auto *hdr = reinterpret_cast<GcHeader *>(raw);
        if (hdr->gen == GcGen::YOUNG && hdr->color == GcColor::WHITE) {
            // No evacuado: el objeto muere con el reset del nursery.
            GC_LOGF("minor_gc sweep killed YOUNG h=%u (size=%u)", (unsigned)h,
                    (unsigned)hdr->size);
            // FINALIZADOR: si el objeto muerto tiene un recurso interno,
            // STAGEAR su finalizador (copia el contenido del box AHORA, que
            // sigue valido; el drenado se hace FUERA del GC, en un safe point).
            if (hdr->has_finalizer)
                stage_finalizer(hdr, raw + sizeof(GcHeader));
            ptr_to_handle_.erase(raw + sizeof(GcHeader));
            handles_[h].addr = nullptr;
            handles_[h].live = false;
            free_handles_.push_back(h);
        }
    }

    // Stack write-back: actualizar host_ptrs en stack y GP regs cuyo
    // valor sea un payload de YoungGen evacuada.  Sin esto, los
    // locales del bytecode que mantenian host_ptrs a objetos CLASS
    // recien movidos a OldGen quedaban dangling -> SEGFAULT al field
    // access siguiente.  Ver `forward_table_` y comentario de la
    // declaracion en gc_heap.h.
    uint64_t fwd_rsp = 0, fwd_high = 0;
    uint64_t fwd_regs[16];
    if (root_provider_ != nullptr && !forward_table_.empty() &&
        root_provider_->vm_stack_regs(fwd_rsp, fwd_high, fwd_regs) &&
        root_provider_->vm_mem() != nullptr) {
        const uint64_t lo = root_provider_->stack_low_water();
        const uint64_t rsp_lo = lo != 0 ? lo : fwd_rsp;
        update_stack_forwards(rsp_lo, fwd_high, fwd_regs,
                              *root_provider_->vm_mem());
        // Escribir de vuelta los regs actualizados (el GC pudo moverlos).
        root_provider_->write_back_regs(fwd_regs);
    }
    // Forward-update de los host_ptrs GC guardados en frames JIT nativos (la
    // pila VM la cubre update_stack_forwards arriba; los frames JIT-compilados
    // tienen sus propios slots en la pila NATIVA).  Sin esto, un `gc<T>` vivo
    // en un frame JIT a traves de la alocacion que disparo el minor quedaria
    // stale
    // -> el siguiente store de campo escribiria en el nursery ya reseteado
    // (sintoma: la cola de una lista construida en un loop JIT se pierde tras
    // el primer minor).  En AOT el nursery esta vacio -> se omite.
    if (!aot_precise_roots_) scan_jit_forwards();
    forward_table_.clear();

    // Reset BLACK -> WHITE para los YOUNG no procesados (ninguno tras
    // el sweep arriba) y para mantener invariante post-minor.
    // (No necesario en realidad porque los WHITE ya murieron y los
    // evacuados ya estan en OLD con BLACK).
    remembered_set_.clear();

    // FINALIZADORES: NO se ejecutan aqui.  Estamos DENTRO de alloc() (que
    // disparo este minor_gc), a su vez dentro de una instruccion del mutator:
    // reentrar al interprete para correr un deleter aqui corromperia la
    // alocacion en curso (bug observado: hang/corrupcion).  El sweep ya STAGEo
    // (copio) los datos del box en pending_finalizers_; el drenado ocurre en un
    // safe point FUERA del GC (el runtime lo hace tras la instruccion de
    // alocacion que disparo el GC).
    nursery_bump_ = nursery_base_;

    if (old_used_ >= old_threshold_) major_gc();
}

// -------------------------------------------------------------------------
// Major GC - mark-and-sweep tri-color transitivo sobre OldGen
// -------------------------------------------------------------------------

void GcHeap::major_gc() {
    stats_.major_gc_count++;
    GC_LOGF("major_gc start (count=%llu, n_old_blocks=%zu)",
            (unsigned long long)stats_.major_gc_count, old_blocks_.size());

    // PRE-MARK: todos los objetos OldGen vivos (no DEAD) -> WHITE
    for (auto &block : old_blocks_) {
        uint8_t *cursor = block.ptr;
        uint8_t *end = block.ptr + block.size;
        while (cursor + sizeof(GcHeader) <= end) {
            auto *hdr = reinterpret_cast<GcHeader *>(cursor);
            if (hdr->size == 0) break;
            if (hdr->color != GcColor::DEAD) hdr->color = GcColor::WHITE;
            cursor += (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;
        }
    }

    std::vector<GcHandle> worklist;

    // MARK PRECISO del interprete (stackmaps VSMP) -- se ejecuta ANTES del
    // scan conservador.  Es un SUBCONJUNTO de lo que el conservador marca
    // (las mismas raices, sobre la misma region de pila VM), por lo que el
    // conjunto final de supervivientes es IDENTICO al orden inverso: puro
    // reordenamiento, cero cambio de comportamiento.  Ejecutarlo primero hace
    // VISIBLE su contribucion (interp_precise_roots_marked > 0) en lugar de
    // que el conservador marque todo antes y el preciso siempre vea BLACK.
    // No-op si el .velb no lleva VSMP.
    scan_interp_roots_precise(worklist);

    // -----------------------------------------------------------------------
    // VERIFICADOR DIFERENCIAL DE COMPLETITUD (VESTA_GC_VERIFY=1, DEV-ONLY).
    //
    // Comprueba que el conjunto PRECISO captura TODA raiz GC real.  Modelo:
    // "preciso ⊇ todas las raices reales".  Si es asi, cerrando el conjunto
    // preciso transitivamente se alcanza TODO objeto vivo alcanzable; el
    // conservador (que corre despues) no anadiria ninguna raiz directa nueva.
    // Cualquier raiz que el conservador SI anade -> el preciso la perdio.
    //
    // Es ADITIVO puro: cerramos el worklist preciso ANTES del conservador
    // (mark_reachable es idempotente WHITE->BLACK, asi que hacerlo ahora o
    // despues no cambia el conjunto final de supervivientes).  El conservador
    // sigue siendo primario -> cero cambio de comportamiento observable.
    //
    // Filtrado de falsos positivos del conservador: el conservador SOLO marca
    // objetos GC vivos de verdad (process_value valida handle/ptr_to_handle_/
    // interior, y salta host_ptr_only).  El unico falso positivo residual es
    // un escalar que coincide NUMERICAMENTE con un handle pequeno vivo; para
    // descartarlo, exigimos que el objeto reportado como hueco tenga ademas
    // un HOST_PTR real presente en pila/regs (una referencia real, no solo un
    // valor==handle).  Asi "raiz real perdida" (hueco) se distingue de
    // "coincidencia numerica" (correcto que el preciso no la marque).
    // -----------------------------------------------------------------------
#if !defined(VESTA_GC_FREESTANDING)
    static const bool verify_enabled = [] {
        const char *v = std::getenv("VESTA_GC_VERIFY");
        return v && v[0] == '1';
    }();
    if (verify_enabled && root_provider_ != nullptr &&
        root_provider_->vm_mem() != nullptr) {
        verify_completeness(worklist);
    }
#endif

    // MARK: raices de los frames del INTERPRETE.
    //
    // FLIP A PRECISO-PRIMARIO (jubilacion del scan conservador por defecto):
    // el scan PRECISO (stackmaps VSMP, ejecutado arriba en scan_interp_roots_
    // precise) es ahora el mecanismo PRIMARIO.  El scan CONSERVADOR de la pila
    // del interprete deja de correr por defecto -- sus FALSOS POSITIVOS
    // (host_ptrs rancios en memoria reusada) retenian objetos ya muertos, lo
    // que introducia no-determinismo en las colecciones.  El preciso solo toca
    // slots GC reales -> ademas es mas rapido que escanear toda la pila.
    //
    // El conservador NO se borra: queda como herramienta de verificacion /
    // fallback GATEADA:
    //   - VESTA_GC_CONSERVATIVE=1  -> re-activa el conservador (aditivo) para
    //                                 diagnostico / red de seguridad de dev.
    //   - VESTA_GC_PRECISE_ONLY=1  -> fuerza preciso-puro incluso con .velb
    //                                 viejos (verificador de completitud).
    //   - VESTA_GC_VERIFY=1        -> ya corrio arriba el diferencial.
    //
    // BACKWARD-COMPAT (por-ejecutable): un .velb SIN seccion VSMP (compilado
    // antes del scan preciso, format_v < 4) NO lleva stackmaps -> usar preciso
    // sobre sus frames perderia raices (UAF).  all_interp_frames_have_stackmaps
    // devuelve false si ALGUN ejecutable cargado es legacy -> mantenemos el
    // conservador como PRIMARIO en ese proceso.  Modelo: binario nuevo=preciso,
    // viejo=conservador.
    const size_t worklist_after_precise = worklist.size();
#if !defined(VESTA_GC_FREESTANDING)
    // VESTA_GC_PRECISE_ONLY=1 (DEV-ONLY): fuerza preciso-puro (sin conservador)
    // incluso para .velb viejos.  Herramienta de validacion, NO el flip.
    static const bool precise_only_forced = [] {
        const char *v = std::getenv("VESTA_GC_PRECISE_ONLY");
        return v && v[0] == '1';
    }();
    // VESTA_GC_CONSERVATIVE=1 (DEV-ONLY): re-activa el conservador aditivo como
    // red de seguridad / diagnostico.
    static const bool conservative_forced = [] {
        const char *v = std::getenv("VESTA_GC_CONSERVATIVE");
        return v && v[0] == '1';
    }();
#else
    constexpr bool precise_only_forced = false;
    constexpr bool conservative_forced = false;
#endif

    // Decidir si corre el conservador de la pila del interprete.  Preciso-
    // primario (DEFAULT): NO corre, salvo que un ejecutable legacy lo exija o
    // el usuario lo fuerce.  precise_only_forced lo desactiva pase lo que pase.
    bool run_conservative = false;
    if (!precise_only_forced) {
        if (conservative_forced) {
            run_conservative = true; // forzado por env (aditivo)
        } else if (root_provider_ != nullptr &&
                   !root_provider_->all_interp_frames_have_stackmaps()) {
            // Algun ejecutable sin VSMP (legacy) -> conservador primario para
            // no perder raices de sus frames.
            run_conservative = true;
        }
    }
#if !defined(VESTA_GC_FREESTANDING)
    // SOUNDNESS DEL MOVING con marcado PRECISO.  El scan preciso del interprete
    // es ahora COMPLETO: cada raiz GC viva (regs + slots de spill + slots de
    // Vesta ALLOCA materializados como spill del SSA value) queda cubierta por
    // el stackmap del PC del safepoint.  Cerrados los dos huecos que lo
    // rompian:
    //   (1) el offset del stackmap se registraba TRAS la instruccion (rip+size)
    //       en vez de en su INICIO -> el scan (match exacto con rip) nunca lo
    //       hallaba (ver helpers_emmit_parser_to_bytecode.cpp);
    //   (2) el resultado de un CALL a funcion libre que devuelve CLASS no se
    //       marcaba is_gc_object -> la raiz (p.ej. `Node k = build(...)`) no
    //       entraba en safepoint_gc_roots (ver lowering.cpp lower_call).
    // Verificado con el GC MOVING (detector infalible: un falso negativo libera
    // Y reusa el hueco -> corrupcion): corpus GC + repros de listas 30-40k con
    // huecos reales -> 0 stale de raiz viva, R0 correcto, movimientos reales.
    // Por eso la compactacion YA NO fuerza el conservador: usa el marcado
    // preciso primario.  El conservador queda como fallback de dev via
    // VESTA_GC_CONSERVATIVE=1 (aditivo) por si un patron aun no cubierto
    // (p.ej. una raiz GC en una ALLOCA address-taken invisible al SSA) lo
    // necesitara -- se activa explicitamente, no por la compactacion.
    (void)0;
#endif

    uint64_t mj_rsp = 0, mj_high = 0;
    uint64_t mj_regs[16];
    if (run_conservative && root_provider_ != nullptr &&
        root_provider_->vm_stack_regs(mj_rsp, mj_high, mj_regs) &&
        root_provider_->vm_mem() != nullptr) {
        scan_stack_roots(mj_rsp, mj_high, mj_regs, *root_provider_->vm_mem(),
                         worklist);
        // Reset low-water-mark al rsp actual: tras el GC, los slots
        // por debajo del rsp actual ya no son alcanzables; el watermark
        // debe limitar el rango del proximo scan al rango realmente
        // activo desde ahora.
        root_provider_->set_stack_low_water(mj_rsp);
    } else if (!aot_precise_roots_ && root_provider_ == nullptr) {
        // Fallback: modelo previo (todo handle live = root).  Solo se usa si no
        // hay root_provider_ NI modo AOT (defensivo para tests / setups
        // especiales).  En modo AOT (libvesta_gc) se OMITE -> las raices vienen
        // de external_refs + scan_jit_roots_precise (frames nativos) + pending
        // -> el GC colecta de verdad lo no alcanzable.
        for (GcHandle h = 0; h < static_cast<GcHandle>(handles_.size()); ++h) {
            if (!handles_[h].live || !handles_[h].addr) continue;
            auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
            if (hdr->gen == GcGen::OLD && hdr->color == GcColor::WHITE) {
                hdr->color = GcColor::BLACK;
                worklist.push_back(h);
            }
        }
    } else if (root_provider_ != nullptr &&
               root_provider_->vm_stack_regs(mj_rsp, mj_high, mj_regs)) {
        // Preciso-primario (sin conservador): mantener el watermark del stack
        // coherente para el proximo ciclo (el interp precise scan y el
        // forward-update lo usan).
        root_provider_->set_stack_low_water(mj_rsp);
    }

    // MARK roots externos: handles pinnados por estructuras nativas
    // (ArrayList<string> del plugin vesta_collections, etc.) se tratan
    // como roots vivos.  Iteramos external_refs_; si refcount > 0,
    // marcamos BLACK + agregamos al worklist para BFS transitivo.  Asi
    // un string almacenado solo en un slot del array nativo NO es
    // colectado durante el major_gc.
    for (const auto &kv : external_refs_) {
        const GcHandle h = kv.first;
        if (kv.second == 0) continue; // refcount 0: deberia haberse limpiado
        if (h >= handles_.size()) continue; // handle stale (objeto ya freed)
        if (!handles_[h].live || !handles_[h].addr) continue;
        auto *hdr = reinterpret_cast<GcHeader *>(handles_[h].addr);
        if (hdr->gen == GcGen::OLD && hdr->color == GcColor::WHITE) {
            hdr->color = GcColor::BLACK;
            worklist.push_back(h);
        }
        // Si esta en YOUNG, el minor_gc se encarga (no se evacua si esta
        // en external_refs_ tampoco -- ver minor_gc adaptado abajo).
    }

    // Metrica conservador: cuantas raices anadio el scan conservador (total
    // tras el conservador menos las que ya habia marcado el preciso interp).
    // El preciso del interprete ya corrio arriba (antes del conservador).
    const size_t worklist_after_conservative = worklist.size();
    if (worklist_after_conservative >= worklist_after_precise)
        stats_.conservative_roots_marked +=
            worklist_after_conservative - worklist_after_precise;

    // precise scan de JIT frames (additive con
    // conservativo).  (no hay JIT funcs) la funcion sale
    // de inmediato.  Cuando lance JIT real, añade roots que
    // el conservativo posiblemente cubrio por aproximacion.
    scan_jit_roots_precise(worklist);

    // BFS transitivo: seguir handles VIVOS embebidos en payloads
    for (size_t i = 0; i < worklist.size(); ++i)
        mark_reachable(worklist[i], worklist);

    // ---- COMPACTACION (mark-compact sliding) vs SWEEP no-moving ----
    //
    // GATE de seguridad: la compactacion MUEVE objetos del OldGen, lo que solo
    // es correcto en el camino INTERPRETE.  Alli los fields de referencia
    // guardan un GcHandle ESTABLE (mover el objeto solo actualiza
    // handles_[h].addr; las referencias-handle embebidas no cambian) y las
    // UNICAS referencias crudas (host_ptr) viven en la pila/regs del VM, que se
    // reescriben tras mover.  NO se compacta en AOT (native_poo guarda
    // host_ptrs crudos en los fields, sin tabla de handles -> haria falta un
    // field-map que no existe) ni con frames nativos JIT activos (host_ptrs en
    // la pila nativa sin reescritura implementada aun).  En esos modos se cae
    // al sweep no-moving de siempre -> comportamiento identico a hoy. AOT
    // (native_poo): compactar con reescritura de raices (stackmaps) + punteros
    // internos (field-maps del descriptor de tipo).  Es correcto porque el mark
    // AOT es preciso (raices via scan_aot_frames + interior via field-maps).
    // Sigue OPT-IN dentro de compact_old_gen_aot.  El path interp mantiene su
    // gate original (vm_mem + sin JIT frames nativos).
    const bool can_compact_now =
        aot_precise_roots_ ||
        (root_provider_ != nullptr && root_provider_->vm_mem() != nullptr &&
         jit::JitRegistry::instance().size() == 0);
    if (!(can_compact_now && compact_old_gen())) {
        // SWEEP: WHITE (sin raiz) -> DEAD, y reconstruir free lists.
        //
        // (iv) GC no-moving: tras el sweep, los slots DEAD se vuelven a
        // colocar en sus free lists segregadas para que el siguiente
        // alloc_in_old los reuse en O(1).  Limpiamos las free lists al
        // inicio del sweep y las repoblamos al recorrer cada slot DEAD.
        // De este modo el estado de las listas siempre refleja la realidad
        // post-sweep, sin entradas obsoletas.
        //
        // Solo se barren los bytes [block.ptr, block.ptr + block.bump_offset);
        // los bytes posteriores nunca se aloacron y no contienen GcHeaders
        // validos.
        freelist_clear();
        for (auto &block : old_blocks_) {
            uint8_t *cursor = block.ptr;
            uint8_t *end = block.ptr + block.bump_offset;

            while (cursor + sizeof(GcHeader) <= end) {
                auto *hdr = reinterpret_cast<GcHeader *>(cursor);
                if (hdr->size == 0) break;

                const size_t total = (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;

                if (hdr->color == GcColor::WHITE) {
                    GC_LOGF("major_gc sweep killed OLD obj cursor=%p size=%u",
                            (void *)cursor, (unsigned)hdr->size);
                    // FINALIZADOR: si el objeto colectado tiene un recurso
                    // interno (unique/shared con deleter), encolar su
                    // finalizador para correrlo en el safe point post-collect.
                    // NO se ejecuta aqui (dentro del sweep) para no reentrar al
                    // interprete en medio del mark/sweep; se drena tras
                    // completar el collect.  Se limpia el bit para no
                    // re-encolar si el slot se re-inspecciona.
                    if (hdr->has_finalizer)
                        stage_finalizer(hdr, cursor + sizeof(GcHeader));
                    stats_.freed_count++;
                    stats_.freed_bytes += total; // total slot, no payload
                    old_used_ -= total;
                    hdr->color = GcColor::DEAD;
                    // Modo AOT: LIBERAR el handle del objeto colectado
                    // (live=false + borrar de ptr_to_handle_ + reciclar).  En
                    // el path VM el handle colgante es benigno (el programa ya
                    // lo solto) y NO se libera en el sweep -> aqui solo lo
                    // hacemos en AOT para que la tabla de handles no crezca sin
                    // limite (new-and-forget) y para que el conteo de vivos sea
                    // exacto.  El slot se reusa abajo (freelist).
                    if (aot_precise_roots_) {
                        uint8_t *payload = cursor + sizeof(GcHeader);
                        const GcHandle dh = ptr_to_handle_.find(payload);
                        if (dh != GC_NULL_HANDLE) {
                            ptr_to_handle_.erase(payload);
                            if (dh < static_cast<GcHandle>(handles_.size())) {
                                handles_[dh].addr = nullptr;
                                handles_[dh].live = false;
                                free_handles_.push_back(dh);
                            }
                        }
                    }
                }

                if (hdr->color == GcColor::DEAD) {
                    // Re-insertar en su free list (sea exact match o large).
                    freelist_push(cursor, total);
                }

                cursor += total;
            }
        }
    } // fin del sweep no-moving (solo si NO se compacto arriba)

    // WEAK SWEEP: anular referencias debiles a objetos recolectados
    // Si el handle apuntado por una WeakEntry esta muerto, poner target =
    // GC_NULL_HANDLE
    for (auto &entry : weak_table_) {
        if (!entry.live) continue;                    // entrada ya liberada
        if (entry.target == GC_NULL_HANDLE) continue; // ya anulada

        // verificar si el objeto sigue vivo (color != DEAD) en la tabla de
        // handles
        bool alive = false;
        if (entry.target < handles_.size()) {
            const auto &he = handles_[entry.target];
            if (he.addr != nullptr && he.live) {
                // he.addr apunta al GcHeader del objeto; leer su color
                const auto *ghdr = reinterpret_cast<const GcHeader *>(he.addr);
                alive = (ghdr->color != GcColor::DEAD);
            }
        }
        if (!alive)
            entry.target = GC_NULL_HANDLE; // objeto muerto: anular referencia
    }

    // FINALIZADORES: el sweep ya STAGEo los datos de los objetos colectados en
    // pending_finalizers_.  NO se drenan aqui (major_gc corre dentro de alloc,
    // dentro de una instruccion del mutator -> reentrar al interp seria
    // inseguro).  El drenado ocurre en un safe point FUERA del GC (el runtime
    // lo dispara tras la instruccion que causo el GC, via has_pending +
    // run_pending_finalizers).
}

// -------------------------------------------------------------------------
// Compactacion mark-compact SLIDING in-place del OldGen (copia escalar).
// -------------------------------------------------------------------------
//
// Reemplaza al sweep cuando corre.  Desliza los objetos vivos (BLACK) hacia el
// inicio de SU bloque, eliminando los huecos (WHITE colectados + DEAD previos).
// Copia por objeto con @c memmove (escalar; SIMD = incremento posterior).  Cero
// memoria extra: se compacta EN EL MISMO espacio (sin segundo semispace).
//
// Correccion (por que no hace falta un field-map en el interprete): los handles
// son ESTABLES (indices en la HandleTable), asi que las referencias entre
// objetos -que en el interprete se guardan como GcHandle en el payload- NO
// cambian al mover.  Mover un objeto solo requiere: (1) actualizar
// handles_[h].addr; (2) reubicar su entrada en ptr_to_handle_; (3) reescribir
// las raices host_ptr crudas (pila+regs del VM) que apuntan a el (incluidos
// punteros interiores tipo STRRAW) via remap por rango de slot.
//
// Fases:
//   A. PLAN   : clasifica BLACK (mueve) vs WHITE/DEAD (colecta), calcula el
//               destino de cada BLACK, sin mutar memoria.  Aborta (return
//               false) si un BLACK no tiene handle valido (defensa
//               anti-corrupcion) o si la fragmentacion esta por debajo del
//               umbral (salvo forzado).
//   B. FIN    : stagea los finalizadores de los colectados (memoria aun
//   intacta). C. MOVE   : memmove de cada BLACK a su destino (orden creciente
//   -> solape
//               seguro: destino <= fuente siempre).
//   D. MAPS   : actualiza handles_ (moved: nueva addr; collected: release) y
//               ptr_to_handle_ (erase viejos, insert nuevos).
//   E. RECOUNT: old_used_, bump_offset por bloque, limpia free-lists.
//   F. ROOTS  : reescribe host_ptrs en pila+regs del VM (exacto + interior).
//   G. VERIFY : (VESTA_GC_VERIFY_MOVE=1) 0 punteros a la region hueco.
//
// El caller (major_gc) restringe su uso al camino interprete (ver GATE alli).

#if !defined(VESTA_GC_FREESTANDING)
namespace {
/// Lee un flag de entorno 0/1 una sola vez (static local en el caller).
inline bool env_flag_1(const char *name) noexcept {
    const char *v = std::getenv(name);
    return v && v[0] == '1';
}
} // namespace
#endif

bool GcHeap::compact_old_gen() {
    // AOT (native_poo): ruta dedicada con reescritura por field-maps + raices
    // de pila nativa (stackmaps).  aot_precise_roots_ solo es true en
    // libvesta_gc (set_aot_mode); en interp/JIT es false -> ruta de abajo.
    if (aot_precise_roots_) return compact_old_gen_aot();
#if defined(VESTA_GC_FREESTANDING)
    // GC freestanding NO-AOT (no deberia ocurrir: freestanding implica AOT).
    // Stub defensivo para no arrastrar getenv/atoi/std::sort al link.
    return false;
#else
    // ------------------------------------------------------------------
    // OPT-IN ESTRICTO (seguridad).  La compactacion (moving) es correcta SOLO
    // si el MARK que la precede es SOUND: marca BLACK toda raiz viva.  Hoy el
    // scan preciso del interprete tiene HUECOS de cobertura (una raiz host_ptr
    // en un registro no cubierto por el stackmap del PC de un safe point puede
    // quedar sin marcar).  Con el GC NO-MOVING eso es benigno (el objeto queda
    // DEAD pero su memoria intacta -> se lee "stale pero valido"; es justo lo
    // que documenta el ejemplo 249).  Con MOVING, ese mismo hueco libera Y
    // REUSA el espacio -> corrupcion.  Por eso la compactacion NO se activa por
    // umbral de fragmentacion en produccion: requiere OPT-IN explicito.
    //   - VESTA_GC_COMPACT_ALWAYS=1        -> compacta en cada major_gc.
    //   - VESTA_GC_COMPACT_THRESHOLD=NN    -> compacta si fragmentacion > NN%.
    // Sin ninguno de los dos, jamas compacta (impacto cero en el corpus/e2e).
    // Cerrar los huecos del mark (scan preciso completo) es prerequisito para
    // activarla por defecto -- ver el informe.
    // ------------------------------------------------------------------
    static const bool compact_always = env_flag_1("VESTA_GC_COMPACT_ALWAYS");
    static const bool verify_move = env_flag_1("VESTA_GC_VERIFY_MOVE");
    static const bool has_threshold =
        std::getenv("VESTA_GC_COMPACT_THRESHOLD") != nullptr;
    // Umbral de fragmentacion [0..1].  Sin la env var explicita: 1.0
    // (inalcanzable -> nunca compacta por fragmentacion).  Valor invalido
    // (<=0 o >=100) -> 0.5.
    static const double frag_threshold = [] {
        const char *v = std::getenv("VESTA_GC_COMPACT_THRESHOLD");
        if (!v) return 1.0;
        const int pct = std::atoi(v);
        if (pct <= 0 || pct >= 100) return 0.5;
        return static_cast<double>(pct) / 100.0;
    }();
    // Opt-in estricto: sin COMPACT_ALWAYS ni THRESHOLD explicito, no compactar.
    if (!compact_always && !has_threshold) return false;

    // vm_mem obligatorio para reescribir las raices (el caller ya lo verifico,
    // pero re-chequeamos por seguridad: sin el, mover corromperia).
    vm::VirtualMemory *mem =
        root_provider_ ? root_provider_->vm_mem() : nullptr;
    if (mem == nullptr) return false;

    // Objeto vivo a mover: handle + posiciones + tamano de slot.
    struct MovedObj {
        GcHandle h;
        uint8_t *old_hdr;
        uint8_t *new_hdr;
        size_t total;
    };
    // Objeto colectado (WHITE inalcanzable): posicion + tamano + finalizador.
    struct CollectedObj {
        uint8_t *hdr;
        size_t total;
        bool has_fin;
    };

    std::vector<MovedObj> moved;
    std::vector<CollectedObj> collected;
    std::vector<size_t> new_bump(old_blocks_.size(), 0);
    std::vector<size_t> old_bump(old_blocks_.size(), 0);

    size_t live_bytes = 0, dead_bytes = 0;

    // ----   PLAN (sin mutar memoria) ----
    for (size_t bi = 0; bi < old_blocks_.size(); ++bi) {
        auto &block = old_blocks_[bi];
        old_bump[bi] = block.bump_offset;
        uint8_t *cursor = block.ptr;
        uint8_t *end = block.ptr + block.bump_offset;
        uint8_t *dest = block.ptr; // objetivo del sliding
        while (cursor + sizeof(GcHeader) <= end) {
            auto *hdr = reinterpret_cast<GcHeader *>(cursor);
            if (hdr->size == 0) break;
            const size_t total = (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;

            if (hdr->color == GcColor::BLACK) {
                uint8_t *old_payload = cursor + sizeof(GcHeader);
                const GcHandle h = ptr_to_handle_.find(old_payload);
                // Un objeto vivo SIN handle valido apuntando exactamente a este
                // slot no se puede reubicar de forma segura (no sabriamos que
                // handle actualizar).  Abortamos TODA la compactacion sin haber
                // mutado nada -> el caller correra el sweep normal.  No deberia
                // ocurrir (cada alloc registra su payload en ptr_to_handle_).
                if (h == GC_NULL_HANDLE || h >= handles_.size() ||
                    !handles_[h].live || handles_[h].addr != cursor) {
                    gc_dbg_emit("[gc-compact] abort: BLACK sin handle valido "
                                "(cursor=%p)\n",
                                (void *)cursor);
                    return false;
                }
                moved.push_back({h, cursor, dest, total});
                dest += total;
                live_bytes += total;
            } else {
                // WHITE (inalcanzable, a colectar) o DEAD (ya colectado):
                // hueco.
                if (hdr->color == GcColor::WHITE) {
                    collected.push_back(
                        {cursor, total, hdr->has_finalizer != 0});
                }
                dead_bytes += total;
            }
            cursor += total;
        }
        new_bump[bi] = static_cast<size_t>(dest - block.ptr);
    }

    // Gate de fragmentacion: si no se fuerza y hay pocos huecos, no vale la
    // pena mover (el sweep no-moving es mas barato).
    const size_t total_bytes = live_bytes + dead_bytes;
    if (!compact_always) {
        if (total_bytes == 0) return false;
        const double frag =
            static_cast<double>(dead_bytes) / static_cast<double>(total_bytes);
        if (frag < frag_threshold) return false;
    }

    // Si nada se mueve fisicamente y no hay nada que colectar, no aporta;
    // dejamos el sweep normal (que ademas repuebla free-lists).  Con
    // compact_always seguimos para EJERCITAR el camino aunque sea no-op.
    bool any_physical_move = false;
    for (const auto &m : moved)
        if (m.new_hdr != m.old_hdr) {
            any_physical_move = true;
            break;
        }
    if (!compact_always && !any_physical_move && collected.empty())
        return false;

    // ----   FINALIZADORES de los colectados (box aun intacto) ----
    for (const auto &c : collected) {
        if (c.has_fin) {
            auto *hdr = reinterpret_cast<GcHeader *>(c.hdr);
            stage_finalizer(hdr, c.hdr + sizeof(GcHeader));
        }
    }

    // ----   MOVER (memmove sliding) ----
    // Orden creciente de old_hdr por bloque -> new_hdr <= old_hdr siempre y las
    // regiones destino nunca pisan una fuente aun no procesada.  memmove maneja
    // el solape del propio objeto.
    for (const auto &m : moved) {
        if (m.new_hdr != m.old_hdr) std::memmove(m.new_hdr, m.old_hdr, m.total);
        // El color BLACK se preserva; el PRE-MARK del proximo major_gc lo
        // blanqueara.  gen/size/finalizer se copian con el memmove.
    }

    // ----   FIX MAPS ----
    // 1. Erase de las claves viejas de los movidos + update handles_ (antes de
    //    insertar las nuevas para no colisionar claves).
    for (const auto &m : moved) {
        ptr_to_handle_.erase(m.old_hdr + sizeof(GcHeader));
        handles_[m.h].addr = m.new_hdr;
    }
    // 2. Colectados: erase de su clave del mapa inverso.  NO se libera el
    //    handle (handles_[h].live queda como estaba), IGUAL que el sweep
    //    no-moving del camino VM: "el handle colgante es benigno (el programa
    //    ya lo solto)".  Esto iguala la semantica del sweep no-moving y evita
    //    que la compactacion, ante un MARK con huecos (una raiz viva marcada
    //    WHITE por error), destruya handles que el programa sigue usando -- el
    //    no-moving los deja leer memoria "stale pero valida"; la compactacion,
    //    al no mover esos objetos WHITE (solo se mueven los BLACK), preserva su
    //    memoria intacta salvo que un objeto deslizado la reuse.  El caso de un
    //    handle libre reutilizado por un alloc futuro se comporta igual que en
    //    el no-moving (la memoria del slot DEAD se recicla).  Si el mark fuese
    //    completo, estos colectados serian realmente inalcanzables y el handle
    //    colgante nunca se usaria.
    for (const auto &c : collected) {
        uint8_t *payload = c.hdr + sizeof(GcHeader);
        ptr_to_handle_.erase(payload);
        stats_.freed_count++;
        stats_.freed_bytes += c.total;
    }
    // 3. Insert de las claves nuevas de los movidos.
    for (const auto &m : moved)
        ptr_to_handle_.insert_or_assign(m.new_hdr + sizeof(GcHeader), m.h);

    // ----   RECUENTO + free-lists ----
    freelist_clear();
    stats_.old_freelist_bytes = 0;
    for (size_t bi = 0; bi < old_blocks_.size(); ++bi)
        old_blocks_[bi].bump_offset = new_bump[bi];
    old_used_ = live_bytes;

    // ----   REESCRITURA DE RAICES (pila + regs del VM) ----
    // Construimos rangos [old_start, old_end) con su delta (new-old).  Un
    // host_ptr en pila/regs que caiga en un rango movido se remapea +delta
    // (cubre el inicio del payload y punteros interiores tipo STRRAW).  Las
    // referencias-handle NO se tocan (son indices pequenos, filtrados por
    // v < 65536).
    struct Range {
        uint64_t old_start;
        uint64_t old_end;
        int64_t delta;
    };
    std::vector<Range> ranges;
    ranges.reserve(moved.size());
    for (const auto &m : moved) {
        if (m.new_hdr == m.old_hdr) continue; // no se movio
        ranges.push_back(
            {reinterpret_cast<uint64_t>(m.old_hdr),
             reinterpret_cast<uint64_t>(m.old_hdr + m.total),
             static_cast<int64_t>(reinterpret_cast<intptr_t>(m.new_hdr) -
                                  reinterpret_cast<intptr_t>(m.old_hdr))});
    }
    std::sort(ranges.begin(), ranges.end(), [](const Range &a, const Range &b) {
        return a.old_start < b.old_start;
    });
    auto remap = [&](uint64_t v) -> uint64_t {
        if (ranges.empty()) return v;
        // Busqueda binaria: mayor old_start <= v.
        size_t lo = 0, hi = ranges.size();
        while (lo < hi) {
            const size_t mid = (lo + hi) / 2;
            if (ranges[mid].old_start <= v)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo == 0) return v;
        const Range &r = ranges[lo - 1];
        if (v >= r.old_start && v < r.old_end)
            return static_cast<uint64_t>(static_cast<int64_t>(v) + r.delta);
        return v;
    };

    if (!ranges.empty()) {
        uint64_t rsp = 0, high = 0;
        uint64_t regs[16];
        if (root_provider_->vm_stack_regs(rsp, high, regs)) {
            const uint64_t lo = root_provider_->stack_low_water();
            const uint64_t start = (lo != 0 && lo < rsp) ? lo : rsp;
            if (start < high && (high - start) < (16 * 1024 * 1024)) {
                for (uint64_t a = start; a + 8 <= high; a += 8) {
                    const uint64_t v = mem->read_u64(a);
                    if (v < 65536) continue;
                    const uint64_t nv = remap(v);
                    if (nv != v) mem->write_bytes(a, &nv, 8);
                }
            }
            bool regs_changed = false;
            for (int i = 0; i < 16; ++i) {
                const uint64_t v = regs[i];
                if (v < 65536) continue;
                const uint64_t nv = remap(v);
                if (nv != v) {
                    regs[i] = nv;
                    regs_changed = true;
                }
            }
            if (regs_changed) root_provider_->write_back_regs(regs);
        }
    }

    // ----   VERIFICADOR DE MOVING (VESTA_GC_VERIFY_MOVE=1, DEV-ONLY) ----
    // Comprueba que NINGUNA raiz (pila+regs) ni campo-puntero de ningun objeto
    // vivo apunta a la region HUECO liberada [ptr+new_bump, ptr+old_bump) de
    // cada bloque -> 0 punteros colgantes/stale.  Un puntero real no-reescrito
    // a un objeto movido cae justo ahi (los objetos deslizan hacia abajo, sus
    // posiciones viejas quedan en el hueco).  Freestanding-safe (gateado).
    if (verify_move) {
        // Rangos hueco [ptr+new_bump, ptr+old_bump) por bloque.
        std::vector<Range> holes;
        for (size_t bi = 0; bi < old_blocks_.size(); ++bi) {
            const uint64_t hs =
                reinterpret_cast<uint64_t>(old_blocks_[bi].ptr) + new_bump[bi];
            const uint64_t he =
                reinterpret_cast<uint64_t>(old_blocks_[bi].ptr) + old_bump[bi];
            if (he > hs) holes.push_back({hs, he, 0});
        }
        auto in_hole = [&](uint64_t v) -> bool {
            for (const auto &r : holes)
                if (v >= r.old_start && v < r.old_end) return true;
            return false;
        };
        uint64_t stale_roots = 0, stale_payload = 0;

        // Raices: pila + regs (tras la reescritura).
        uint64_t rsp = 0, high = 0;
        uint64_t regs[16];
        if (root_provider_->vm_stack_regs(rsp, high, regs)) {
            const uint64_t lo = root_provider_->stack_low_water();
            const uint64_t start = (lo != 0 && lo < rsp) ? lo : rsp;
            if (start < high && (high - start) < (16 * 1024 * 1024)) {
                for (uint64_t a = start; a + 8 <= high; a += 8) {
                    const uint64_t v = mem->read_u64(a);
                    if (v < 65536) continue;
                    if (in_hole(v)) {
                        ++stale_roots;
                        gc_dbg_emit("[gc-verify-move] STALE root @vm=%llu "
                                    "v=0x%llx\n",
                                    (unsigned long long)a,
                                    (unsigned long long)v);
                    }
                }
            }
            for (int i = 0; i < 16; ++i) {
                const uint64_t v = regs[i];
                if (v < 65536) continue;
                if (in_hole(v)) {
                    ++stale_roots;
                    gc_dbg_emit("[gc-verify-move] STALE reg r%d v=0x%llx\n", i,
                                (unsigned long long)v);
                }
            }
        }

        // Campos-puntero de cada objeto vivo (movido o no): recorrer los
        // payloads y buscar words que apunten al hueco.  En el interprete los
        // fields de referencia son HANDLES (indices, < 65536 casi siempre), no
        // host_ptrs -> stale_payload debe ser 0.  Si NO lo es, es evidencia de
        // que algun field guarda un host_ptr crudo (viola el modelo) y hay que
        // PARAR: un field-map seria necesario.
        for (auto &block : old_blocks_) {
            uint8_t *cursor = block.ptr;
            uint8_t *end = block.ptr + block.bump_offset;
            while (cursor + sizeof(GcHeader) <= end) {
                auto *hdr = reinterpret_cast<GcHeader *>(cursor);
                if (hdr->size == 0) break;
                const size_t total = (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;
                uint8_t *pl = cursor + sizeof(GcHeader);
                const size_t sz = hdr->size;
                for (size_t off = 0; off + 8 <= sz; off += 8) {
                    uint64_t v;
                    std::memcpy(&v, pl + off, 8);
                    if (v < 65536) continue;
                    if (in_hole(v)) {
                        ++stale_payload;
                        gc_dbg_emit("[gc-verify-move] STALE payload cursor=%p "
                                    "off=%zu v=0x%llx\n",
                                    (void *)cursor, off, (unsigned long long)v);
                    }
                }
                cursor += total;
            }
        }

        gc_dbg_emit("[gc-verify-move] compacted moved=%zu collected=%zu "
                    "live=%zu freed=%zu stale_roots=%llu stale_payload=%llu\n",
                    moved.size(), collected.size(), live_bytes, dead_bytes,
                    (unsigned long long)stale_roots,
                    (unsigned long long)stale_payload);
        gc_debug_flush();
    }

    return true;
#endif // VESTA_GC_FREESTANDING
}

// -------------------------------------------------------------------------
// Compactacion mark-compact del OldGen en AOT (libvesta_gc / native_poo).
// -------------------------------------------------------------------------
// Traza de la compactacion AOT: en el build FREESTANDING (libvesta_gc) NO se
// emite (evita arrastrar vsnprintf/__mingw_vsnprintf al link nativo, igual que
// el resto de gc_dbg_emit del path freestanding, todos gateados).  La
// correctness NO depende de la traza: el verificador cuenta stale igual y el
// resultado del programa (R0) delata cualquier corrupcion.
#if defined(VESTA_GC_FREESTANDING)
#define GC_AOT_DBG(...) ((void)0)
#define GC_AOT_FLUSH() ((void)0)
#else
#define GC_AOT_DBG(...) gc_dbg_emit(__VA_ARGS__)
#define GC_AOT_FLUSH() gc_debug_flush()
#endif
namespace {
// Emisor freestanding-safe (SIN vsnprintf) para el resumen de la compactacion
// AOT: formatea manualmente los contadores a decimal y los escribe al fd 2 via
// GC_DBG_WRITE (_write/::write).  Gateado en runtime por VESTA_GC_DEBUG.  Asi
// la compactacion AOT es OBSERVABLE (moved/collected/stale) sin arrastrar
// stdio.
inline void gc_aot_write_str(const char *s) noexcept {
    size_t n = 0;
    while (s[n])
        ++n;
    if (n) GC_DBG_WRITE(2, s, (unsigned)n);
}
inline void gc_aot_write_u64(uint64_t v) noexcept {
    char buf[24];
    int i = 24;
    buf[--i] = '\0';
    if (v == 0) buf[--i] = '0';
    while (v) {
        buf[--i] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    gc_aot_write_str(buf + i);
}
inline void gc_aot_summary(uint64_t moved, uint64_t collected, uint64_t live,
                           uint64_t freed, uint64_t stale_roots,
                           uint64_t stale_fields) noexcept {
    gc_aot_write_str("[gc-compact-aot] moved=");
    gc_aot_write_u64(moved);
    gc_aot_write_str(" collected=");
    gc_aot_write_u64(collected);
    gc_aot_write_str(" live=");
    gc_aot_write_u64(live);
    gc_aot_write_str(" freed=");
    gc_aot_write_u64(freed);
    gc_aot_write_str(" stale_roots=");
    gc_aot_write_u64(stale_roots);
    gc_aot_write_str(" stale_fields=");
    gc_aot_write_u64(stale_fields);
    gc_aot_write_str("\n");
}
/// Rango [old_start, old_end) de un objeto movido con su delta (new - old).
struct AotRange {
    uint64_t old_start;
    uint64_t old_end;
    int64_t delta;
};
/// Remapea un host_ptr @p v: si cae en un rango movido, +delta; si no, igual.
/// Cubre el inicio del objeto y punteros interiores (el payload al que apunta
/// un campo cae dentro de [old_hdr, old_hdr+total)).  Busqueda binaria.
inline uint64_t aot_remap(const std::vector<AotRange> &ranges,
                          uint64_t v) noexcept {
    if (ranges.empty()) return v;
    size_t lo = 0, hi = ranges.size();
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        if (ranges[mid].old_start <= v)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0) return v;
    const AotRange &r = ranges[lo - 1];
    if (v >= r.old_start && v < r.old_end)
        return static_cast<uint64_t>(static_cast<int64_t>(v) + r.delta);
    return v;
}
/// Contexto del callback de reescritura de raices de pila nativa (AOT).
struct AotRootCtx {
    const std::vector<AotRange> *ranges;
    uint64_t rewritten;
};
/// Callback de @c scan_aot_frames: reescribe IN SITU el slot de pila nativa
/// que aloja una raiz movida.  @p slot_addr es la direccion nativa del slot.
void aot_root_rewrite_cb(void *ctx, uint64_t value, jit::StackmapGcKind /*k*/,
                         const uint8_t *slot_addr) {
    auto *c = static_cast<AotRootCtx *>(ctx);
    if (value < 65536 || slot_addr == nullptr) return;
    const uint64_t nv = aot_remap(*c->ranges, value);
    if (nv != value) {
        std::memcpy(const_cast<uint8_t *>(slot_addr), &nv, 8);
        ++c->rewritten;
    }
}
/// Contexto del verificador: cuenta raices que aun apuntan a un hueco.
struct AotVerifyCtx {
    const std::vector<AotRange> *holes; // delta ignorado; solo el rango
    uint64_t stale;
};
void aot_root_verify_cb(void *ctx, uint64_t value, jit::StackmapGcKind /*k*/,
                        const uint8_t * /*slot_addr*/) {
    auto *c = static_cast<AotVerifyCtx *>(ctx);
    if (value < 65536) return;
    for (const auto &h : *c->holes)
        if (value >= h.old_start && value < h.old_end) {
            ++c->stale;
            GC_AOT_DBG("[gc-verify-move-aot] STALE root v=0x%llx\n",
                       (unsigned long long)value);
            break;
        }
}
} // namespace

bool GcHeap::compact_old_gen_aot() {
    // OPT-IN estricto (igual que el path interp): sin VESTA_GC_COMPACT_ALWAYS
    // ni VESTA_GC_COMPACT_THRESHOLD explicitos, jamas compacta.  getenv esta
    // disponible en el build freestanding (ya lo usa el init de debug).
    static const bool compact_always = [] {
        const char *v = std::getenv("VESTA_GC_COMPACT_ALWAYS");
        return v && v[0] == '1';
    }();
    static const bool verify_move = [] {
        const char *v = std::getenv("VESTA_GC_VERIFY_MOVE");
        return v && v[0] == '1';
    }();
    // VESTA_GC_DEBUG leido como static LOCAL (no via g_gc_debug, cuyo
    // inicializador namespace-scope no corre en un binario AOT bare sin
    // .init_array).  Habilita el resumen observable de la compactacion.
    static const bool aot_debug = [] {
        const char *v = std::getenv("VESTA_GC_DEBUG");
        return v && v[0] != '\0' && v[0] != '0';
    }();
    static const bool has_threshold =
        std::getenv("VESTA_GC_COMPACT_THRESHOLD") != nullptr;
    static const double frag_threshold = [] {
        const char *v = std::getenv("VESTA_GC_COMPACT_THRESHOLD");
        if (!v) return 1.0;
        const int pct = std::atoi(v);
        if (pct <= 0 || pct >= 100) return 0.5;
        return static_cast<double>(pct) / 100.0;
    }();
    if (!compact_always && !has_threshold) return false;

    // Sin frontera Vesta valida NO podemos reescribir las raices de la pila
    // nativa -> mover corromperia.  Abortamos ANTES de mutar nada (los valores
    // pc/sp persisten tras el mark; solo se limpio el flag valid_).
    const uint64_t bpc = aot_boundary_pc_;
    const uint64_t bsp = aot_boundary_sp_;
    if (bpc == 0 || bsp == 0) return false;

    struct MovedObj {
        GcHandle h;
        uint8_t *old_hdr;
        uint8_t *new_hdr;
        size_t total;
    };
    struct CollectedObj {
        uint8_t *hdr;
        size_t total;
        bool has_fin;
    };
    std::vector<MovedObj> moved;
    std::vector<CollectedObj> collected;
    std::vector<size_t> new_bump(old_blocks_.size(), 0);
    std::vector<size_t> old_bump(old_blocks_.size(), 0);
    size_t live_bytes = 0, dead_bytes = 0;

    // ----   PLAN (sin mutar) ----
    for (size_t bi = 0; bi < old_blocks_.size(); ++bi) {
        auto &block = old_blocks_[bi];
        old_bump[bi] = block.bump_offset;
        uint8_t *cursor = block.ptr;
        uint8_t *end = block.ptr + block.bump_offset;
        uint8_t *dest = block.ptr;
        while (cursor + sizeof(GcHeader) <= end) {
            auto *hdr = reinterpret_cast<GcHeader *>(cursor);
            if (hdr->size == 0) break;
            const size_t total = (sizeof(GcHeader) + hdr->size + 7) & ~7ULL;
            if (hdr->color == GcColor::BLACK) {
                uint8_t *old_payload = cursor + sizeof(GcHeader);
                const GcHandle h = ptr_to_handle_.find(old_payload);
                if (h == GC_NULL_HANDLE || h >= handles_.size() ||
                    !handles_[h].live || handles_[h].addr != cursor) {
                    GC_AOT_DBG("[gc-compact-aot] abort: BLACK sin handle "
                               "(cursor=%p)\n",
                               (void *)cursor);
                    return false;
                }
                moved.push_back({h, cursor, dest, total});
                dest += total;
                live_bytes += total;
            } else {
                if (hdr->color == GcColor::WHITE)
                    collected.push_back(
                        {cursor, total, hdr->has_finalizer != 0});
                dead_bytes += total;
            }
            cursor += total;
        }
        new_bump[bi] = static_cast<size_t>(dest - block.ptr);
    }

    const size_t total_bytes = live_bytes + dead_bytes;
    if (!compact_always) {
        if (total_bytes == 0) return false;
        const double frag =
            static_cast<double>(dead_bytes) / static_cast<double>(total_bytes);
        if (frag < frag_threshold) return false;
    }
    bool any_physical_move = false;
    for (const auto &m : moved)
        if (m.new_hdr != m.old_hdr) {
            any_physical_move = true;
            break;
        }
    if (!compact_always && !any_physical_move && collected.empty())
        return false;

    // ----   FINALIZADORES de colectados ----
    for (const auto &c : collected)
        if (c.has_fin) {
            auto *hdr = reinterpret_cast<GcHeader *>(c.hdr);
            stage_finalizer(hdr, c.hdr + sizeof(GcHeader));
        }

    // ----   MOVER (memmove sliding) ----
    for (const auto &m : moved)
        if (m.new_hdr != m.old_hdr) std::memmove(m.new_hdr, m.old_hdr, m.total);

    // ---- Rangos de reubicacion (para remapear punteros) ----
    std::vector<AotRange> ranges;
    ranges.reserve(moved.size());
    for (const auto &m : moved) {
        if (m.new_hdr == m.old_hdr) continue;
        ranges.push_back(
            {reinterpret_cast<uint64_t>(m.old_hdr),
             reinterpret_cast<uint64_t>(m.old_hdr + m.total),
             static_cast<int64_t>(reinterpret_cast<intptr_t>(m.new_hdr) -
                                  reinterpret_cast<intptr_t>(m.old_hdr))});
    }
    std::sort(ranges.begin(), ranges.end(),
              [](const AotRange &a, const AotRange &b) {
                  return a.old_start < b.old_start;
              });

    // ----   FIX MAPS (ptr_to_handle_ + handles_) ----
    for (const auto &m : moved) {
        ptr_to_handle_.erase(m.old_hdr + sizeof(GcHeader));
        handles_[m.h].addr = m.new_hdr;
    }
    for (const auto &c : collected) {
        uint8_t *payload = c.hdr + sizeof(GcHeader);
        const GcHandle dh = ptr_to_handle_.find(payload);
        ptr_to_handle_.erase(payload);
        // En AOT liberamos el handle del colectado (igual que el sweep AOT):
        // la tabla no debe crecer sin limite (new-and-forget).
        if (dh != GC_NULL_HANDLE && dh < handles_.size()) {
            handles_[dh].addr = nullptr;
            handles_[dh].live = false;
            free_handles_.push_back(dh);
        }
        stats_.freed_count++;
        stats_.freed_bytes += c.total;
    }
    for (const auto &m : moved)
        ptr_to_handle_.insert_or_assign(m.new_hdr + sizeof(GcHeader), m.h);

    // ----   RECUENTO + free-lists ----
    freelist_clear();
    stats_.old_freelist_bytes = 0;
    for (size_t bi = 0; bi < old_blocks_.size(); ++bi)
        old_blocks_[bi].bump_offset = new_bump[bi];
    old_used_ = live_bytes;

    // ---- Fase F1: REESCRITURA DE PUNTEROS INTERNOS (field-maps) ----
    // Recorre TODOS los objetos vivos (en su posicion nueva) y remapea cada
    // campo-referencia gc<Y> a la direccion de destino de su objeto.  Un objeto
    // que no se movio puede referir a uno que si -> hay que recorrerlos todos.
    if (!ranges.empty()) {
        for_each_old_object(old_blocks_, [&](GcHeader *hdr, uint8_t *payload,
                                             size_t sz) {
            for_each_gc_field(hdr, payload, sz, stats_,
                              [&](uint32_t fo, uint64_t fptr) {
                                  const uint64_t nptr = aot_remap(ranges, fptr);
                                  if (nptr != fptr)
                                      std::memcpy(payload + fo, &nptr, 8);
                              });
        });
    }

    // ---- Fase F2: REESCRITURA DE RAICES (pila nativa via stackmaps) ----
    if (!ranges.empty()) {
        AotRootCtx rctx{&ranges, 0};
        jit::scan_aot_frames(&aot_root_rewrite_cb, &rctx, bpc, bsp);
    }

    // ----   VERIFICADOR (VESTA_GC_VERIFY_MOVE=1) ----
    if (verify_move) {
        std::vector<AotRange> holes;
        for (size_t bi = 0; bi < old_blocks_.size(); ++bi) {
            const uint64_t hs =
                reinterpret_cast<uint64_t>(old_blocks_[bi].ptr) + new_bump[bi];
            const uint64_t he =
                reinterpret_cast<uint64_t>(old_blocks_[bi].ptr) + old_bump[bi];
            if (he > hs) holes.push_back({hs, he, 0});
        }
        auto in_hole = [&](uint64_t v) -> bool {
            for (const auto &r : holes)
                if (v >= r.old_start && v < r.old_end) return true;
            return false;
        };
        uint64_t stale_fields = 0;
        // Campos-referencia de cada objeto vivo (tras la reescritura): 0 deben
        // apuntar al hueco.  Si alguno lo hace, el mark tenia un hueco o falto
        // un offset en el field-map.
        for_each_old_object(
            old_blocks_, [&](GcHeader *hdr, uint8_t *payload, size_t sz) {
                for_each_gc_field(
                    hdr, payload, sz, stats_, [&](uint32_t fo, uint64_t v) {
                        if (!in_hole(v)) return;
                        ++stale_fields;
                        GC_AOT_DBG("[gc-verify-move-aot] STALE field "
                                   "payload=%p off=%u v=0x%llx\n",
                                   (void *)payload, fo, (unsigned long long)v);
                    });
            });
        // Raices de pila nativa (tras la reescritura).
        AotVerifyCtx vctx{&holes, 0};
        jit::scan_aot_frames(&aot_root_verify_cb, &vctx, bpc, bsp);
        // Resumen OBSERVABLE en AOT (freestanding-safe, sin vsnprintf).
        gc_aot_summary(moved.size(), collected.size(), live_bytes, dead_bytes,
                       vctx.stale, stale_fields);
        GC_AOT_FLUSH();
    } else if (aot_debug) {
        // Sin verificador pero con VESTA_GC_DEBUG: emitir el resumen para
        // confirmar que la compactacion realmente movio objetos.
        gc_aot_summary(moved.size(), collected.size(), live_bytes, dead_bytes,
                       0, 0);
    }

    return true;
}

// -------------------------------------------------------------------------
// (iv) GC no-moving en OldGen: free lists segregadas + bump per-block
// -------------------------------------------------------------------------
//
// Diseno de allocator:
//   - 16 size classes (16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
//     768, 1024, 1536, 2048, 4096) cubren la mayoria de objetos Vesta.
//   - Cada size class tiene una free list LIFO (singly-linked) de slots
//     DEAD reusables.  El next pointer reusa los primeros 8 bytes del
//     payload del slot (cero memoria extra).
//   - Slots con total > 4096 bytes van a una free list general
//     (large_free_list_) buscada con first-fit lineal.  Lista corta
//     en la practica.
//   - Al pop de free list: O(1) por size class.
//   - Al miss en todas las free lists: bump pointer en algun OldBlock
//     con espacio (probamos en orden, primer fit).
//   - Al miss tambien en bumps: crear nuevo OldBlock (arena_mgr).
//
// Garantia: los objetos OldGen NO se mueven nunca tras la asignacion
// inicial.  Sus host_ptrs son estables hasta que el sweep los marque
// DEAD (lo que ocurre solo cuando el handle se libera y no quedan
// referencias del programa al objeto).  Esto elimina el bug de
// host_ptr stale tras un GC para todos los objetos OldGen.
//
// Trade-off: fragmentacion interna por redondeo a size class
// (~10-20% tipico) a cambio de cero overhead per acceso a campo.
// -------------------------------------------------------------------------

size_t GcHeap::size_class_ceil(size_t total) noexcept {
    // Busqueda lineal sobre 16 entradas: la tabla cabe en 1 cache line
    // y el branch predictor aprende rapido.  Mas eficiente que std::lower_bound
    // por la baja cardinalidad y la simplicidad del codigo emitido.
    for (size_t i = 0; i < SMALL_CLASS_COUNT; ++i) {
        if (SMALL_CLASS_SIZES[i] >= total) return i;
    }
    return SMALL_CLASS_COUNT; // total > 4096: cae en la free list large
}

void GcHeap::freelist_clear() noexcept {
    // Solo limpiar los heads.  Los nodos viven embebidos en los slots
    // DEAD; al re-push sobreescribimos sus next pointers.  Los slots
    // que ya no son DEAD tras el sweep simplemente no se reinsertan.
    for (size_t i = 0; i < SMALL_CLASS_COUNT; ++i) {
        small_free_lists_[i] = nullptr;
    }
    large_free_list_.clear();
    stats_.old_freelist_bytes = 0;
}

void GcHeap::freelist_push(uint8_t *raw_header, size_t total) {
    // Pre-condicion: hdr->size del slot ya refleja el slot_total - header.
    // Calculamos size class basado en el total (que ya incluye
    // header+payload+pad).
    const size_t cls = size_class_ceil(total);
    if (cls < SMALL_CLASS_COUNT && total >= SMALL_CLASS_SIZES[cls]) {
        // Slot exactamente del tamano del class (porque alloc redondea
        // siempre al class).  Si por algun motivo el slot es mas grande
        // del esperado, lo dejamos en su clase: al re-allocar se
        // devolvera con el tamano real registrado en hdr->size.
        auto *node =
            reinterpret_cast<FreeNode *>(raw_header + sizeof(GcHeader));
        node->next = small_free_lists_[cls];
        small_free_lists_[cls] = node;
        stats_.old_freelist_bytes += total;
    } else {
        // Slot grande o que no encaja en ningun small class: free list general.
        large_free_list_.push_back({raw_header, total});
        stats_.old_freelist_bytes += total;
    }
}

uint8_t *GcHeap::alloc_in_old(size_t total_bytes) {
    size_t actual = 0;
    return alloc_in_old_with_total(total_bytes, actual);
}

uint8_t *GcHeap::alloc_in_old_with_total(size_t total_bytes,
                                         size_t &out_actual_total) {
    // 1. Free list segregada del size class apropiado.
    const size_t cls = size_class_ceil(total_bytes);
    if (cls < SMALL_CLASS_COUNT) {
        FreeNode *node = small_free_lists_[cls];
        if (node != nullptr) {
            small_free_lists_[cls] = node->next;
            // Recuperar el header del slot (el next pointer estaba en
            // payload[0..7], asi que el header esta justo antes).
            uint8_t *raw = reinterpret_cast<uint8_t *>(node) - sizeof(GcHeader);
            out_actual_total = SMALL_CLASS_SIZES[cls];
            old_used_ += out_actual_total;
            if (stats_.old_freelist_bytes >= out_actual_total) {
                stats_.old_freelist_bytes -= out_actual_total;
            }
            stats_.old_alloc_freelist++;
            return raw;
        }
        // Si el class exacto esta vacio, intentar el siguiente size class
        // (slot mas grande del estrictamente necesario).  Limitamos a 2
        // buckets adicionales para no hacer searches largos: si llegamos
        // aqui es porque el patron de alloc no encaja con free lists
        // pre-existentes y caera al bump pointer rapidamente.
        for (size_t off = 1; off <= 2 && cls + off < SMALL_CLASS_COUNT; ++off) {
            FreeNode *n = small_free_lists_[cls + off];
            if (n != nullptr) {
                small_free_lists_[cls + off] = n->next;
                uint8_t *raw =
                    reinterpret_cast<uint8_t *>(n) - sizeof(GcHeader);
                out_actual_total = SMALL_CLASS_SIZES[cls + off];
                old_used_ += out_actual_total;
                if (stats_.old_freelist_bytes >= out_actual_total) {
                    stats_.old_freelist_bytes -= out_actual_total;
                }
                stats_.old_alloc_freelist++;
                return raw;
            }
        }
    } else {
        // 2. Free list general para slots grandes (>4096): first-fit lineal.
        for (size_t i = 0; i < large_free_list_.size(); ++i) {
            if (large_free_list_[i].total >= total_bytes) {
                uint8_t *raw = large_free_list_[i].ptr;
                out_actual_total = large_free_list_[i].total;
                // Erase swap-and-pop O(1) (no nos importa el orden).
                large_free_list_[i] = large_free_list_.back();
                large_free_list_.pop_back();
                old_used_ += out_actual_total;
                if (stats_.old_freelist_bytes >= out_actual_total) {
                    stats_.old_freelist_bytes -= out_actual_total;
                }
                stats_.old_alloc_freelist++;
                return raw;
            }
        }
    }

    // 3. Sin slot reusable: bump pointer en algun OldBlock con espacio.
    // Redondeamos al size class para que el slot creado sea reciclable
    // exactamente en su class al ser liberado mas tarde.
    const size_t alloc_total = (cls < SMALL_CLASS_COUNT)
                                   ? SMALL_CLASS_SIZES[cls]
                                   : ((total_bytes + 7) & ~7ULL);
    for (auto &block : old_blocks_) {
        const size_t available = block.size - block.bump_offset;
        if (available >= alloc_total) {
            uint8_t *raw = block.ptr + block.bump_offset;
            block.bump_offset += alloc_total;
            out_actual_total = alloc_total;
            old_used_ += alloc_total;
            stats_.old_reserved_bytes += alloc_total;
            stats_.old_alloc_bump++;
            return raw;
        }
    }

    // 4. Crear bloque nuevo.  Tamano: max(64KB, alloc_total*2) para
    // amortizar el overhead de la syscall y dejar espacio para futuros
    // alocs sin syscall.
    const size_t block_size =
        alloc_total < 64 * 1024 ? 64 * 1024 : alloc_total * 2;
    uint64_t aid = arena_mgr_.create_arena(block_size, vm::MemPerm::READ |
                                                           vm::MemPerm::WRITE);
    const vm::Arena *a = arena_mgr_.get_arena(aid);
    if (!a || !a->ptr) {
        out_actual_total = 0;
        return nullptr;
    }
    old_blocks_.push_back({
        static_cast<uint8_t *>(a->ptr), block_size, aid,
        alloc_total // bump_offset arranca tras el primer slot
    });
    out_actual_total = alloc_total;
    old_used_ += alloc_total;
    stats_.old_reserved_bytes += alloc_total;
    stats_.old_alloc_newblock++;
    return static_cast<uint8_t *>(a->ptr);
}

// =========================================================================
//  Tabla de referencias debiles
// =========================================================================

/**
 * @brief Registra un GcHandle en la tabla de referencias debiles.
 *
 * Busca primero un slot libre (live==false) para reutilizarlo.  Si no hay
 * ninguno disponible, inserta una nueva entrada al final.
 *
 * @param target GcHandle del objeto a observar debilmente.
 * @return Indice opaco uint32_t de la entrada en la tabla.
 */
uint32_t GcHeap::alloc_weak(GcHandle target) {
    // reutilizar slots liberados antes de crecer la tabla
    for (uint32_t i = 0; i < static_cast<uint32_t>(weak_table_.size()); ++i) {
        if (!weak_table_[i].live) {
            weak_table_[i].target = target;
            weak_table_[i].live = true;
            return i;
        }
    }
    // ningun slot libre: anadir al final de la tabla
    uint32_t idx = static_cast<uint32_t>(weak_table_.size());
    weak_table_.push_back({target, true});
    return idx;
}

/**
 * @brief Resuelve un indice de weak ref al GcHandle subyacente.
 *
 * Si el objeto fue recolectado durante el ultimo major GC el campo target
 * habra sido puesto a GC_NULL_HANDLE por el barrido de weak refs.
 *
 * @param idx Indice opaco devuelto por alloc_weak().
 * @return GcHandle del objeto si sigue vivo; GC_NULL_HANDLE si fue recolectado
 *         o si el indice esta fuera de rango.
 */
GcHandle GcHeap::deref_weak(uint32_t idx) const {
    if (idx >= static_cast<uint32_t>(weak_table_.size())) return GC_NULL_HANDLE;
    const auto &entry = weak_table_[idx];
    if (!entry.live)
        return GC_NULL_HANDLE; // slot liberado: referencia invalida
    return entry.target; // GC_NULL_HANDLE si el objeto fue recolectado, handle
                         // valido si no
}

/**
 * @brief Libera una entrada de la tabla de referencias debiles.
 *
 * Marca el slot como libre (live=false) para que pueda ser reutilizado.
 * Si idx esta fuera de rango o el slot ya estaba libre, no hace nada.
 *
 * @param idx Indice opaco devuelto por alloc_weak().
 */
void GcHeap::free_weak(uint32_t idx) {
    if (idx >= static_cast<uint32_t>(weak_table_.size())) return;
    weak_table_[idx].live = false;            // marcar como slot libre
    weak_table_[idx].target = GC_NULL_HANDLE; // limpiar el handle por seguridad
}

// -------------------------------------------------------------------------
// Monitor / sincronizacion
// -------------------------------------------------------------------------

/**
 * @brief Intenta adquirir el monitor del objeto referenciado por @p h.
 *
 * Si owner_pid == 0 (libre): asigna el monitor a @p local_pid,
 * establece lock_depth = 1 y devuelve true.
 * Si owner_pid == local_pid (lock reentrante): incrementa lock_depth y
 * devuelve true.
 * Si lo posee otro proceso: devuelve false (el llamante debe bloquear).
 *
 * @param h         Handle del objeto cuyo monitor se quiere adquirir.
 * @param local_pid PID local del proceso solicitante.
 * @return true si el monitor fue adquirido o incrementado.
 */
bool GcHeap::monitor_try_acquire(GcHandle h, uint64_t owner_encoded) {
    uint8_t *ptr = deref(h);
    if (ptr == nullptr) return false; // handle invalido: no se puede adquirir

    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(ptr);

    // Z.2: CAS lock-free de 0 -> (owner_encoded, 1).  Fast path para monitor
    // libre. Memory order acquire: garantiza que las lecturas posteriores ven
    // el estado consistente publicado por el ultimo release del owner anterior.
    uint64_t expected = 0;
    uint64_t desired = loader::monitor_make(owner_encoded, 1);
    if (hdr->monitor_word.compare_exchange_strong(expected, desired,
                                                  std::memory_order_acquire,
                                                  std::memory_order_relaxed)) {
        return true; // FAST PATH: monitor libre, adquirido en 1 CAS (~5 ns)
    }

    // CAS fallo: alguien posee el monitor.  Si soy yo, reentrante.
    // El CAS poblo @c expected con el valor actual del word.
    // Z.11 ext: comparamos los 48 bits de owner_encoded (sched<<32|local)
    // para garantizar unicidad cross-scheduler (antes solo local_pid -> data
    // loss).
    if (loader::monitor_owner(expected) ==
        (owner_encoded & loader::MONITOR_OWNER_MASK)) {
        // Reentrante: solo nosotros tocamos esto.  No hace falta CAS
        // (no hay race posible: nadie mas puede tocar el monitor mientras
        // lo poseemos).  Store relaxed es suficiente: ya hay barrera
        // acquire del CAS inicial que adquirio el monitor.
        uint32_t d = loader::monitor_depth(expected);
        hdr->monitor_word.store(loader::monitor_make(owner_encoded, d + 1),
                                std::memory_order_relaxed);
        return true;
    }
    return false; // monitor ocupado por otro proceso
}

/**
 * @brief Libera el monitor del objeto referenciado por @p h.
 *
 * Decrementa lock_depth.  Cuando llega a 0 el monitor queda libre
 * (owner_pid = 0).  Extrae el primer proceso de la cola de espera
 * para despertarlo.
 *
 * @param h         Handle del objeto cuyo monitor se libera.
 * @param local_pid PID local del propietario actual (para validar).
 * @return PID codificado del siguiente proceso en cola
 *         (@c UINT64_MAX si vacia / no aplica).  Z.6: sentinel
 *         cambiado de 0 a UINT64_MAX porque encoded_pid=0 es valido
 *         (main process en scheduler 0).
 */
uint64_t GcHeap::monitor_release(GcHandle h, uint64_t owner_encoded) {
    uint8_t *ptr = deref(h);
    if (ptr == nullptr) return UINT64_MAX;

    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(ptr);

    // Load relaxed: el word solo es modificado por el owner (nosotros)
    // mientras estamos dentro del monitor; nadie puede haberlo cambiado
    // de un valor con owner==owner_encoded a otra cosa.
    uint64_t cur = hdr->monitor_word.load(std::memory_order_relaxed);
    if (loader::monitor_owner(cur) !=
        (owner_encoded & loader::MONITOR_OWNER_MASK)) {
        return UINT64_MAX; // no soy owner
    }

    uint32_t d = loader::monitor_depth(cur);
    if (d > 1) {
        // Reentrante: decrementar sin liberar.  Relaxed (no hay handoff).
        hdr->monitor_word.store(loader::monitor_make(owner_encoded, d - 1),
                                std::memory_order_relaxed);
        return UINT64_MAX;
    }

    // Ultima liberacion: store 0 con release semantics.  El release
    // sincroniza con el acquire del proximo monenter (capa CAS), de
    // modo que sus reads sobre el objeto ven los writes nuestros.
    hdr->monitor_word.store(0, std::memory_order_release);

    return monitor_pop_waiter(
        h); // siguiente proceso a despertar (o UINT64_MAX)
}

// ----------------------------------------------------------------------
// Wait queues ( Z.4 + Z.6): delegacion a WaitTable lock-free
//
// Antes (v1): @c std::unordered_map<GcHandle, std::vector<uint64_t>>
// separados (monitor_waiters_ + condvar_waiters_).  NO thread-safe,
// requerian mutex global implicito.
//
// Z.4: un solo @c WaitTable con spinlock per-bucket.  Thread-safe.
//
// Z.6: handles con bit 31 set (SHARED_HANDLE_BIT) dispatch al
// @c vm.shared_wait_table (compartido cross-process).  Sin esto,
// un @c wait en el padre y un @c notify en el hijo sobre el mismo
// objeto shared NO se ven (cada uno tendria su propia cola).
// ----------------------------------------------------------------------

/**
 * @brief Selecciona la WaitTable apropiada segun el bit 31 del handle.
 *
 * Inline en hot path; branch predicted always-not-taken para objetos
 * locales (caso dominante).
 */
inline WaitTable &GcHeap::wait_table_for(GcHandle h) noexcept {
    if ((h & SHARED_HANDLE_BIT) && root_provider_ != nullptr) {
        // Shared: usar la tabla per-VM (cross-process visible).
        if (WaitTable *swt = root_provider_->shared_wait_table()) return *swt;
    }
    // Local: tabla per-process.
    return wait_table_;
}

void GcHeap::monitor_add_waiter(GcHandle h, uint64_t encoded_pid) {
    wait_table_for(h).push(static_cast<uint32_t>(h), WaitKind::MONITOR,
                           encoded_pid);
}

uint64_t GcHeap::monitor_pop_waiter(GcHandle h) {
    return wait_table_for(h).pop_one(static_cast<uint32_t>(h),
                                     WaitKind::MONITOR);
}

std::vector<uint64_t> GcHeap::monitor_pop_all_waiters(GcHandle h) {
    return wait_table_for(h).pop_all(static_cast<uint32_t>(h),
                                     WaitKind::MONITOR);
}

void GcHeap::condvar_add_waiter(GcHandle h, uint64_t encoded_pid) {
    wait_table_for(h).push(static_cast<uint32_t>(h), WaitKind::CONDVAR,
                           encoded_pid);
}

uint64_t GcHeap::condvar_pop_waiter(GcHandle h) {
    return wait_table_for(h).pop_one(static_cast<uint32_t>(h),
                                     WaitKind::CONDVAR);
}

std::vector<uint64_t> GcHeap::condvar_pop_all_waiters(GcHandle h) {
    return wait_table_for(h).pop_all(static_cast<uint32_t>(h),
                                     WaitKind::CONDVAR);
}

// set_owner_process esta inlineada en el header (gc_heap.h).
} // namespace gc
