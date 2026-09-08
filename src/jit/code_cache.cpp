/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/code_cache.cpp
 * @brief Asignador de memoria ejecutable para el JIT.
 *
 * El @c CodeCache reserva regiones del sistema operativo con permisos
 * READ|WRITE|EXEC para que el JIT pueda escribir bytes-maquina y luego
 * saltar a ellos sin pasar por el cargador dinamico.  Caracteristicas:
 *
 *   - **Reserva por chunks** de tamano fijo (default 1 MiB).  El primer
 *     alloc crea el primer chunk; cuando un alloc no cabe, se reserva
 *     uno nuevo.  Asi evitamos pedir 64 MiB al SO de golpe (que muchos
 *     SOs commit-an realmente) cuando un programa pequeno solo necesita
 *     una funcion JIT.
 *
 *   - **Limite duro total** (default 64 MiB) para que un bug del JIT no
 *     agote la memoria del proceso.  Si se quiere mas, el caller lo
 *     pasa explicitamente en el constructor.
 *
 *   - **Bump allocator dentro de cada chunk**: la asignacion es un
 *     incremento del puntero `used` + alignment.  No hay free
 *     individual: la memoria solo se libera al destruir el CodeCache
 *     (cuando la VM termina) o via @c invalidate para deopt.
 *
 *   - **Modo RWX simple** en v1: cada pagina es escribible y ejecutable
 *     simultaneamente.   E migrara a W^X (write-XOR-exec) para
 *     hardening: durante emit las paginas son RW, durante exec son RX,
 *     transicion via @c mprotect / @c VirtualProtect.  Sin esto, en
 *     macOS moderno + Apple Silicon directamente no funciona (hardware
 *     enforcement).
 *
 *   - **Flush de icache** tras commit: en x86-64 es no-op (modelo
 *     coherente), pero en ARM/AArch64 es OBLIGATORIO para que el CPU
 *     no ejecute bytes viejos de su cache de instrucciones.
 *
 * Comparacion API por plataforma:
 *
 * | Operacion        | Windows (Win32)                              | POSIX
 * (Linux/macOS)               | | :--------------- |
 * :------------------------------------------- |
 * :-------------------------------- | | Reservar pagina  | VirtualAlloc(NULL,
 * n, RESERVE\|COMMIT, RWX)  | mmap(NULL, n, RWX, PRIV\|ANON)    | | Liberar
 * pagina   | VirtualFree(p, 0, MEM_RELEASE)               | munmap(p, n) | |
 * Flush icache     | FlushInstructionCache(GetCurrentProcess(),..)|
 * __builtin___clear_cache           | | Transicion perms | VirtualProtect
 * ( E, futuro)             | mprotect ( E, futuro)        |
 */

#include "jit/code_cache.h"

#include <cstring>
#include <cstdlib>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace jit {

namespace {
/**
 * @brief Round-up entero a multiplo de @p align (potencia de 2).
 *
 * Truco clasico: @c (value + align - 1) & ~(align - 1).  Coste 2
 * instrucciones; no requiere division.  PRESUPONE @c align es
 * potencia de 2 (el caller lo garantiza).
 */
inline size_t round_up(size_t value, size_t align) noexcept {
    return (value + align - 1) & ~(align - 1);
}
} // namespace

/**
 * @brief Constructor: solo valida y guarda los parametros.
 *
 * Por que NO reservamos el primer chunk aqui: si el programa nunca
 * llama a @c alloc (caso comun: programa Vesta puro sin JIT), nunca
 * pagamos las 1 MiB de memoria virtual.  Lazy allocation = mejor para
 * el caso "JIT instalado pero no usado".
 */
CodeCache::CodeCache(size_t chunk_bytes, size_t max_total_bytes)
    : chunk_bytes_(chunk_bytes), max_total_(max_total_bytes), used_(0) {
    // Minimo razonable: 1 page (4 KiB).  Pedir menos no aporta nada
    // (el SO redondea internamente) y complica la aritmetica.
    if (chunk_bytes_ < 4096u) chunk_bytes_ = 4096u;
    // Cordura: si el caller paso @c max_total < chunk, normalizar al
    // chunk size para que AL MENOS quepa un chunk completo.  Mejor
    // funcionar con un solo chunk que rechazar TODAS las asignaciones.
    if (max_total_ < chunk_bytes_) max_total_ = chunk_bytes_;
}

/**
 * @brief Destructor: suelta la lista de trozos.
 *
 * LA MEMORIA LA DEVUELVE LA ARENA, no esto.  Los trozos salen de ella, asi que
 * soltarlos aqui uno a uno seria liberar dos veces lo mismo -- y ademas cada
 * trozo no es una reserva del sistema: es un pedazo de un bloque suyo, del que
 * puede haber varios por bloque.  Lo que queda aqui es tirar la lista.
 *
 * Devolver la memoria SIGUE importando, porque las paginas ejecutables cuentan
 * en el presupuesto del proceso; lo que cambia es quien lo hace.
 */
CodeCache::~CodeCache() { chunks_.clear(); }

/**
 * @brief Reserva un nuevo chunk del SO y lo añade a la lista.
 *
 * @return true si el SO atendio la peticion y aun cabe en el budget.
 *
 * Se llama bajo demanda desde @c alloc cuando el chunk actual no
 * tiene espacio.  Fallar aqui significa OOM o limite excedido: el
 * caller (JIT compiler) debe abortar la compilacion y caer al
 * interprete para esta funcion.
 */
bool CodeCache::reserve_chunk() {
    // Budget check antes de tocar el SO: ahorra una syscall costosa
    // cuando estamos al limite.  total_reserved cuenta lo ya pedido,
    // no lo realmente usado (los chunks vacios tambien cuentan).
    const size_t total_reserved = chunks_.size() * chunk_bytes_;
    if (total_reserved + chunk_bytes_ > max_total_) {
        return false;
    }
    /* LA MEMORIA SE LA PIDE AL ASIGNADOR, con los permisos y la zona que hacen
     * falta.  No es un caso especial: el asignador es, por debajo, un repartidor
     * de arenas con permisos, y una arena de codigo es una de ellas.
     *
     * LA DIRECCION NO DA IGUAL, y por eso se le pasa el ancla.  El codigo que se
     * emite aqui referencia datos del anfitrion -- los globales del modulo,
     * sobre todo -- con desplazamientos RELATIVOS A RIP de 32 bits, que
     * alcanzan +-2 GB.  Mientras codigo y datos salian del mismo sitio caian
     * cerca por casualidad -- medido, a 18 MB --; al separarse, la distancia
     * paso a ser arbitraria y la compilacion nativa empezo a fallar con "rel32
     * fuera de rango", que no era un aviso: devolvia cero, y ese cero acababa
     * siendo el punto de entrada de un hilo.
     *
     * El barrido de regiones que habia aqui se fue a `os_alloc_near`, que es
     * donde le toca: preguntar al mapa de memoria donde hay hueco no es trabajo
     * de un generador de codigo, y ahi ademas se elige el hueco MAS CERCANO en
     * vez del primero -- esto se quedaba en el borde de la ventana, a 1.920 MiB,
     * y ahi no queda margen para los datos que no son el ancla exacta. */
    if (arena_ == nullptr) {
        /* Casi lo que alcanza un rel32, no la mitad: el desplazamiento se mide
         * entre el CODIGO y CADA dato, y el ancla es una direccion
         * representativa de la zona.  Los 128 MiB de margen dan de sobra para
         * los globales de un modulo. */
        constexpr size_t kWindow = (size_t(1) << 31) - (128u << 20);
        arena_storage_ = util::ScratchArena(
            util::kOsReadWriteExec,
            anchor_ != 0 ? reinterpret_cast<const void *>(anchor_) : nullptr,
            kWindow);
        arena_ = &arena_storage_;
    }
    void *p = arena_->allocate(chunk_bytes_, 4096);
    if (p == nullptr) return false;
    anchored_ = arena_->placed();
    // Registrar el chunk en la lista para tracking y cleanup posterior.
    Chunk c;
    c.base = static_cast<uint8_t *>(p);
    c.size = chunk_bytes_;
    c.used = 0; // bump pointer arranca en 0; lo incrementan los allocs
    chunks_.push_back(c);
    return true;
}

/**
 * @brief Aloca @c size bytes con alineamiento @c align dentro del cache.
 *
 * Estrategia: bump allocator sobre el ULTIMO chunk.  Si no cabe ahi,
 * reservar un nuevo chunk e intentar de nuevo (max 2 intentos -- si
 * tras reservar tampoco cabe, el bloque es mas grande que un chunk).
 *
 * @return Puntero al primer byte alocado, o nullptr en cualquier
 *         fallo (size=0, size>chunk_bytes, reserva del SO fallida).
 */
uint8_t *CodeCache::alloc(size_t size, size_t align) {
    // Validacion del input: size=0 es no-op.
    if (size == 0) return nullptr;
    // align=0 lo tratamos como 1 (sin alineamiento).
    if (align == 0) align = 1;
    // Forzar align a potencia de 2 (requisito de round_up).  Si el
    // caller paso un valor que no lo es, redondear arriba al siguiente
    // power-of-two: emula @c std::bit_ceil de C++20 sin requerirlo.
    if ((align & (align - 1)) != 0) {
        size_t a = 1;
        while (a < align)
            a <<= 1;
        align = a;
    }
    // Limitacion arquitectural: no soportamos asignaciones mayores
    // que un chunk completo.  Si una funcion JIT necesita >1 MiB de
    // codigo, el caller debe subir @c chunk_bytes al construir el
    // cache.  Cero overhead para el caso comun (funciones pequenas).
    if (size > chunk_bytes_) return nullptr;

    // Reclaim C2: intentar reusar una region del free-list ANTES de
    // hacer bump.  First-fit: la primera region cuyo inicio alineado
    // + size cabe dentro de ella.  El hueco por alineacion (head) se
    // descarta (pequeno); el remanente, si es util (>= 64 B), se
    // reinserta al free-list.  Las regiones del free-list ya son RWX
    // (fueron committed antes); el caller las re-escribe + commit.
    for (size_t i = 0; i < free_list_.size(); ++i) {
        uint8_t *fb = free_list_[i].ptr;
        const size_t cap = free_list_[i].size;
        const uintptr_t a = reinterpret_cast<uintptr_t>(fb);
        const uintptr_t aligned = round_up(a, align);
        const size_t head = static_cast<size_t>(aligned - a);
        if (head + size <= cap) {
            uint8_t *ret = reinterpret_cast<uint8_t *>(aligned);
            const size_t remainder = cap - head - size;
            free_list_.erase(free_list_.begin() +
                             static_cast<std::ptrdiff_t>(i));
            if (remainder >= 64u) {
                free_list_.push_back({ret + size, remainder});
            }
            return ret;
        }
    }

    // Maximo 2 intentos: primer try en el chunk actual; si no cabe,
    // reservar uno nuevo y reintentar.  No iteramos mas porque el
    // limite es chunk_bytes_, asi que tras reservar fresh DEBE caber
    // (excepto si reserve_chunk fallo, en cuyo caso devolvemos null).
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!chunks_.empty()) {
            Chunk &c = chunks_.back();
            // Calcular offset alineado: subir el bump pointer hasta el
            // siguiente multiplo de @c align.  Resta @c c.base para
            // trabajar en offsets relativos (overflow-safe).
            const size_t base =
                round_up(reinterpret_cast<uintptr_t>(c.base + c.used), align) -
                reinterpret_cast<uintptr_t>(c.base);
            // Cabe si el rango [base, base+size) esta dentro del chunk.
            if (base + size <= c.size) {
                uint8_t *ptr = c.base + base;
                const size_t prev = c.used;
                c.used = base + size;
                // used_ acumula los bytes REALMENTE usados (incluyendo
                // padding por alignment).  Usado para reportes de
                // memory usage al usuario.
                used_ += c.used - prev;
                return ptr;
            }
        }
        // No cabe (o no hay chunks aun); reservar uno fresco.
        if (!reserve_chunk()) return nullptr;
    }
    return nullptr;
}

/**
 * @brief Marca un bloque como listo para ejecutar (publicacion).
 *
 * Llamado por el JIT tras escribir todos los bytes maquina y
 * resolver las relocations.  Hace dos cosas:
 *   1. Transicion de permisos (no-op en modo RWX; lo prepara para
 *       E cuando vayamos a W^X).
 *   2. Flush de la icache para que el CPU descarte cualquier copia
 *      cacheada de los bytes anteriores en ese rango.  Esencial en
 *      ARM/AArch64; no-op en x86-64 (modelo de memoria coherente
 *      entre dcache e icache).
 */
void CodeCache::commit(const uint8_t *ptr, size_t size) {
    if (!ptr || size == 0) return;
    // En modo RWX la transicion es no-op.  Cuando llegue  E,
    // esta funcion hara @c mprotect(ptr, size, PROT_READ|PROT_EXEC)
    // para hacer la region read-only ejecutable.
    transition_to_executable(const_cast<uint8_t *>(ptr), size);
    flush_icache(ptr, size);
}

/**
 * @brief Rellena un bloque con INT3 (0xCC) para que cualquier salto
 *        a el dispare un breakpoint inmediato (uso: deopt).
 *
 * Tras invalidate, cualquier puntero al codigo viejo es trap-on-jump.
 * El JIT compiler puede entonces re-emit la funcion en otra parte
 * del cache (el espacio invalidado no se reusa: serviria solo si
 * implementamos compactacion del cache, no en v1).
 */
void CodeCache::invalidate(uint8_t *ptr, size_t size) {
    if (!ptr || size == 0) return;
    // Defensa: ignorar punteros que no son nuestros (e.g. el caller
    // paso un puntero ajeno por error).  Sin esto crashearia el SO.
    if (!contains(ptr)) return;
    // 0xCC = opcode INT3 en x86-64.  Genera SIGTRAP / EXCEPTION_BREAKPOINT
    // si se ejecuta.  En ARM cambiariamos a la instruccion BKPT.
    std::memset(ptr, 0xCC, size);
    // Tras escribir, flush icache: el CPU podria tener cacheados los
    // bytes viejos y ejecutarlos por mucho tiempo sin este flush.
    flush_icache(ptr, size);
}

/**
 * @brief Devuelve una region al free-list para reuso (reclaim C2 tier-up).
 *
 * Envenena la region con 0xCC (INT3) como defensa: si una referencia
 * perdida la ejecuta antes de reusarse, trapea en vez de correr basura.
 * No devuelve memoria al SO (las regiones son sub-alocaciones de chunks);
 * @c alloc la reciclara.  Serializacion responsabilidad del caller.
 */
void CodeCache::free_region(uint8_t *ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;
    if (!contains(ptr)) return; // defensa: solo regiones nuestras
    std::memset(ptr, 0xCC, size);
    flush_icache(ptr, size);
    free_list_.push_back({ptr, size});
}

/**
 * @brief Comprueba si @c ptr esta dentro de algun chunk del cache.
 *
 * Lineal en numero de chunks (~10 tipicamente).  Usado por
 * @c invalidate y por debugging tools para validar punteros antes
 * de operar sobre ellos.
 */
bool CodeCache::contains(const uint8_t *ptr) const noexcept {
    if (!ptr) return false;
    for (const auto &c : chunks_) {
        if (ptr >= c.base && ptr < c.base + c.size) return true;
    }
    return false;
}

/**
 * @brief Hook reservado para futura transicion RW -> RX (W^X).
 *
 * En modo RWX simple (v1) es no-op porque la region ya tiene los
 * tres permisos.  Cuando llegue  E, esta funcion hara
 * @c VirtualProtect / @c mprotect para retirar el bit de escritura
 * antes de ejecutar.  Asi un buffer overflow en el JIT compiler
 * no puede inyectar codigo en regiones ya commit-eadas.
 */
void CodeCache::transition_to_executable(uint8_t *ptr, size_t size) {
    (void)ptr;
    (void)size;
}

/**
 * @brief Garantiza que el CPU descarta sus caches de instrucciones
 *        para el rango [ptr, ptr+size).
 *
 * Sin este flush, en arquitecturas con icache no-coherente (ARM,
 * AArch64, MIPS) el CPU podria ejecutar bytes viejos despues de un
 * write reciente.  En x86-64 la coherencia es automatica via el
 * protocolo MESI pero llamar a la API correcta no cuesta nada y
 * mantiene el codigo portable.
 */
void CodeCache::flush_icache(const uint8_t *ptr, size_t size) {
#if defined(_WIN32)
    // FlushInstructionCache es la API documentada para esto.  En x86
    // no hace casi nada (el SO sabe que es coherente); en ARM emite
    // las instrucciones DSB+ISB necesarias.
    ::FlushInstructionCache(::GetCurrentProcess(), ptr, size);
#elif defined(__GNUC__) || defined(__clang__)
    // Builtin portable de GCC/Clang.  En x86 es no-op; en ARM emite
    // las invalidaciones necesarias.  Mas legible que llamar a APIs
    // OS-specific via syscalls intrinsicos.
    __builtin___clear_cache(
        const_cast<char *>(reinterpret_cast<const char *>(ptr)),
        const_cast<char *>(reinterpret_cast<const char *>(ptr + size)));
#else
    // Compilador sin builtin: dejar como no-op confiando en que la
    // arquitectura es coherente (x86-64 antiguo, p.ej. con MSVC pre-
    // VS2017 sin clang fallback).  Si llegamos a soportar ARM
    // explicitamente sin GCC/Clang, añadir aqui asm volatile con
    // las instrucciones de barrier apropiadas.
    (void)ptr;
    (void)size;
#endif
}

} // namespace jit
