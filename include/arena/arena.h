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
 * @file arena.h                                                               \
 * @brief Definicion de tipos y primitivas de memoria de arena de VestaVM.     \
 *                                                                             \
 * Define: MemPerm, round_to_page(), allocate_memory(), free_memory(),         \
 * MemBlock, vm_map_ptr, MappedPtr, RemotePtr y los niveles de la tabla        \
 * de paginas virtual.  Base del subsistema de memoria de la VM.               \
 */                                                                            \
#ifndef ARENA_H
#define ARENA_H

#include <cstddef>

#include "util/gc_diag.h" // VGC_CERR/COUT (neutralizable en freestanding)
#include "util/os_memory.h" // tamano de pagina, preguntado UNA vez

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

#include "net/net.h"

/**
 * @brief Redondea un valor al multiplo de pagina de 4 KiB mas cercano por
 * arriba.
 *
 * La mascara ~4095ULL elimina los 12 bits de offset para obtener la
 * direccion de inicio de pagina; sumando 4095 antes de enmascarar
 * garantiza el redondeo hacia arriba.
 */
#define ALIGN_4K(x) (((x) + 4095) & ~4095ULL)

namespace vm {

/**
 * @enum MemPerm
 * @brief Permisos de acceso a memoria para bloques de arena y mapeos virtuales.
 *
 * Cada constante ocupa un bit distinto del byte subyacente para permitir
 * combinaciones mediante OR de bits.  Usado en allocate_memory() y en
 * ArenaManager::create_arena().
 *
 * Tabla de valores:
 *   NONE  = 0x00  -- sin permisos
 *   READ  = 0x01  -- lectura
 *   WRITE = 0x02  -- escritura
 *   EXEC  = 0x04  -- ejecucion (necesario para JIT)
 *
 * @example
 *   MemPerm rw = MemPerm::READ | MemPerm::WRITE;
 *   MemPerm rwx = MemPerm::READ | MemPerm::WRITE | MemPerm::EXEC;
 */
enum class MemPerm : uint8_t {
    NONE = 0,       ///< Sin ningun permiso
    READ = 1 << 0,  ///< Permiso de lectura
    WRITE = 1 << 1, ///< Permiso de escritura
    EXEC = 1 << 2,  ///< Permiso de ejecucion (paginas JIT)
};

/**
 * @brief Combina dos valores MemPerm mediante OR de bits.
 *
 * Permite escribir expresiones como:
 *   MemPerm p = MemPerm::READ | MemPerm::WRITE;
 *
 * @param a Primer conjunto de permisos.
 * @param b Segundo conjunto de permisos.
 * @return  Union de los permisos indicados.
 */
constexpr MemPerm operator|(MemPerm a, MemPerm b) {
    return static_cast<MemPerm>(static_cast<uint8_t>(a) |
                                static_cast<uint8_t>(b));
}

/**
 * @brief Comprueba si un permiso especifico esta activo en un conjunto de
 * permisos.
 *
 * Realiza una comprobacion AND de bits entre el conjunto actual y el permiso
 * que se desea verificar.
 *
 * @param perms Conjunto de permisos a examinar (p.ej. READ | WRITE).
 * @param test  Permiso individual que se quiere verificar.
 * @return true  si el bit de @p test esta activo en @p perms.
 * @return false si el bit de @p test no esta presente.
 *
 * @example
 *   MemPerm p = MemPerm::READ | MemPerm::WRITE;
 *   has_perm(p, MemPerm::EXEC);  // false
 *   has_perm(p, MemPerm::WRITE); // true
 */
constexpr bool has_perm(MemPerm perms, MemPerm test) {
    // La operacion AND extrae el bit del permiso buscado; si es != 0 esta
    // presente
    return (static_cast<uint8_t>(perms) & static_cast<uint8_t>(test)) != 0;
}

/**
 * @brief Redondea @p n hacia arriba al multiplo de @p a.
 * @param a Tiene que ser potencia de dos (un tamano de pagina lo es).
 *
 * El nombre que prometia el encabezado de este fichero era `round_to_page`,
 * pero nunca existio: se redondeaba a mano en dos sitios con dos copias de la
 * misma cuenta.
 */
constexpr size_t round_up_to(size_t n, size_t a) {
    return (n + a - 1) & ~(a - 1);
}

/**
 * @brief Traduce permisos a la constante que entiende el sistema.
 *
 * Suelta y @c constexpr a proposito: en todos los sitios de llamada los
 * permisos son una constante escrita a mano (`READ | WRITE`), asi que la
 * cadena entera de comparaciones se PLIEGA a un numero al compilar y lo que
 * queda de @c allocate_memory es lo bastante pequeno como para meterse dentro
 * de quien la llama.  Con la traduccion metida en medio de la funcion, no.
 *
 * @note En Windows, EXEC+WRITE sin READ se traduce a PAGE_EXECUTE_READWRITE
 *       porque no existe una proteccion de solo escritura y ejecucion.
 */
#if defined(_WIN32) || defined(_WIN64)
constexpr DWORD os_protection_of(MemPerm perms) {
    return has_perm(perms, MemPerm::EXEC)
               ? (has_perm(perms, MemPerm::READ) &&
                          has_perm(perms, MemPerm::WRITE)
                      ? PAGE_EXECUTE_READWRITE
                      : has_perm(perms, MemPerm::READ)
                            ? PAGE_EXECUTE_READ
                            : has_perm(perms, MemPerm::WRITE)
                                  ? PAGE_EXECUTE_READWRITE
                                  : PAGE_EXECUTE)
               : (has_perm(perms, MemPerm::READ) &&
                          has_perm(perms, MemPerm::WRITE)
                      ? PAGE_READWRITE
                      : has_perm(perms, MemPerm::READ)
                            ? PAGE_READONLY
                            : has_perm(perms, MemPerm::WRITE) ? PAGE_READWRITE
                                                              : PAGE_NOACCESS);
}
#else
constexpr int os_protection_of(MemPerm perms) {
    return (has_perm(perms, MemPerm::READ) ? PROT_READ : 0) |
           (has_perm(perms, MemPerm::WRITE) ? PROT_WRITE : 0) |
           (has_perm(perms, MemPerm::EXEC) ? PROT_EXEC : 0);
}
#endif

/**
 * @brief Reserva memoria del sistema con los permisos indicados.
 *
 * El tamano se redondea automaticamente al multiplo de pagina del sistema
 * (4 KiB en x86/x64 tipicamente).  Internamente usa VirtualAlloc en Windows
 * y mmap(MAP_PRIVATE | MAP_ANONYMOUS) en POSIX.
 *
 * La memoria obtenida debe liberarse con free_memory() pasando el mismo
 * tamano original (antes del redondeo).
 *
 * @param size  Numero de bytes a reservar.
 * @param perms Combinacion de MemPerm que determina READ / WRITE / EXEC.
 * @return      Puntero al bloque reservado, o nullptr si la asignacion falla.
 *
 * @note En Windows, la combinacion EXEC+WRITE sin READ se traduce a
 *       PAGE_EXECUTE_READWRITE porque no existe PAGE_EXECUTE_WRITE.
 */
inline void *allocate_memory(size_t size, MemPerm perms) {
    if (size == 0) return nullptr; // tamanyo nulo: nada que reservar

    /* El tamano de pagina se PREGUNTA UNA VEZ en toda la vida del proceso, no
     * en cada reserva.  Antes habia aqui un `GetSystemInfo` (o un `sysconf`)
     * por llamada: cuarenta bytes de estructura en la pila mas una consulta al
     * sistema para averiguar un numero que no cambia nunca, y ademas bastaba
     * para que la funcion no cupiera dentro de quien la llama. */
    size = round_up_to(size, util::os_page_size());

#ifdef _WIN32
    // Se pliega a una constante cuando los permisos lo son, que es siempre.
    const DWORD flProtect = os_protection_of(perms);

    void *mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, flProtect);
    if (!mem) {
        /* CONTAR POR QUE FALLO SOLO EN DEBUG, y no por ahorrar: las dos cosas
         * que hacen falta para dar el mensaje -- los flujos de C++ y
         * `FormatMessageA` con `FORMAT_MESSAGE_ALLOCATE_BUFFER` -- PIDEN
         * MEMORIA.  Contar que no hay memoria pidiendo memoria es reentrar por
         * el mismo sitio, y en el peor momento: cuando el sistema acaba de
         * decir que no.  El que llama sigue enterandose por el nullptr, que es
         * un fallo ruidoso igual, solo que sin texto. */
#ifndef NDEBUG
        DWORD err = GetLastError();
        LPVOID msg;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                           FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       (LPSTR)&msg, 0, NULL);
        VGC_CERR << "VirtualAlloc fallo. Codigo: " << err << " - "
                 << (msg ? (char *)msg : "Error desconocido") << "\n";
        if (msg) LocalFree(msg); // liberar el buffer de mensaje
#endif
        return nullptr;
    }
    return mem;
#else
    // Se pliega a una constante cuando los permisos lo son, que es siempre.
    const int prot = os_protection_of(perms);

    void *mem = mmap(nullptr, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        // Mismo motivo que en la rama de Windows: los flujos reservan.
#ifndef NDEBUG
        VGC_CERR << "mmap fallo: " << std::strerror(errno)
                 << "\n"; // mostrar error de sistema
#endif
        return nullptr;
    }
    return mem;
#endif
}

/**
 * @brief Libera memoria previamente reservada con allocate_memory().
 *
 * El parametro @p size debe ser el mismo valor original pasado a
 * allocate_memory() antes del redondeo interno.  En Windows el tamanyo
 * no se usa (VirtualFree con MEM_RELEASE no lo requiere); en POSIX
 * munmap necesita el tamanyo alineado a pagina.
 *
 * @param mem  Puntero al bloque a liberar (devuelto por allocate_memory).
 * @param size Tamanyo original del bloque (antes del redondeo).
 */
inline void free_memory(void *mem, size_t size) {
#ifdef _WIN32
    (void)size; // con MEM_RELEASE el tamano no se usa
    VirtualFree(mem, 0, MEM_RELEASE); // libera todo el rango reservado
#else
    // Redondear IGUAL que en allocate, o `munmap` deja un trozo colgando.
    munmap(mem, round_up_to(size, util::os_page_size()));
#endif
}

/**
 * @brief Bloque de memoria contigua con permisos asociados.
 *
 * Una Arena representa la unidad minima de gestion de memoria dentro de
 * ArenaManager.  Cada arena tiene un identificador unico, un puntero al
 * bloque real del sistema y los permisos con los que fue reservado.
 */
typedef struct Arena {
    void *ptr =
        nullptr;     ///< Puntero al inicio del bloque de memoria del sistema
    size_t size = 0; ///< Tamanyo del bloque en bytes (multiplo de pagina)
    MemPerm perms = MemPerm::NONE; ///< Permisos de acceso (READ / WRITE / EXEC)
} Arena;

/**
 * @brief Alias para punteros reales del proceso anfitrio (host).
 *
 * Se usa para distinguir punteros del sistema operativo nativo
 * de los punteros virtuales de la VM (vm_map_ptr).
 */
typedef void *host_ptr;

/**
 * @enum PageLevel
 * @brief Niveles de la tabla de paginas virtual de la VM.
 *
 * La direccion virtual de 64 bits se descompone en cuatro campos:
 *
 *   Bits [11: 0] OFFSET (12 bits) -- desplazamiento dentro de la pagina
 *   Bits [23:12] PT     (12 bits) -- indice en la tabla de paginas nivel 1
 *   Bits [39:24] PT1    (16 bits) -- indice en la tabla de paginas nivel 2
 *   Bits [63:40] PT2    (24 bits) -- indice en la tabla de paginas nivel 3
 * (raiz)
 */
enum class PageLevel : uint8_t {
    OFFSET = 0, ///< Desplazamiento dentro de la pagina (bits 0-11)
    PT,         ///< Tabla de paginas nivel 1 (bits 12-23)
    PT1,        ///< Tabla de paginas nivel 2 (bits 24-39)
    PT2         ///< Tabla de paginas nivel 3 raiz (bits 40-63)
};

/**
 * @brief Direccion virtual interna de la maquina virtual.
 *
 * Empaqueta 64 bits en un valor bruto e implementa metodos de acceso
 * por nivel de tabla de paginas (OFFSET, PT, PT1, PT2).
 *
 * Estructura de bits:
 *   [63:40] PT2    24 bits
 *   [39:24] PT1    16 bits
 *   [23:12] PT     12 bits
 *   [11: 0] OFFSET 12 bits
 */
struct vm_map_ptr {
    uint64_t raw = 0; ///< Valor bruto de 64 bits de la direccion virtual

    /**
     * @brief Extrae el campo del nivel indicado de la direccion virtual.
     *
     * @param level Nivel de la tabla de paginas a extraer.
     * @return      Valor del campo correspondiente.
     */
    [[nodiscard]] uint64_t get(PageLevel level) const {
        switch (level) {
        case PageLevel::OFFSET: return raw & 0xFFF;         // bits 11-0
        case PageLevel::PT: return (raw >> 12) & 0xFFF;     // bits 23-12
        case PageLevel::PT1: return (raw >> 24) & 0xFFFF;   // bits 39-24
        case PageLevel::PT2: return (raw >> 40) & 0xFFFFFF; // bits 63-40
        }
        return 0; // nunca alcanzado; silencia advertencias del compilador
    }

    /**
     * @brief Escribe un campo del nivel indicado en la direccion virtual.
     *
     * Solo los bits del nivel seleccionado son modificados; el resto
     * de la direccion permanece intacto.
     *
     * @param level Nivel de la tabla de paginas a modificar.
     * @param value Nuevo valor para el campo (los bits extra son ignorados).
     */
    void set(PageLevel level, uint64_t value) {
        switch (level) {
        case PageLevel::OFFSET:
            raw =
                (raw & ~0xFFFULL) | (value & 0xFFFULL); // actualizar bits 11-0
            break;
        case PageLevel::PT:
            raw = (raw & ~(0xFFFULL << 12)) |
                  ((value & 0xFFFULL) << 12); // actualizar bits 23-12
            break;
        case PageLevel::PT1:
            raw = (raw & ~(0xFFFFULL << 24)) |
                  ((value & 0xFFFFULL) << 24); // actualizar bits 39-24
            break;
        case PageLevel::PT2:
            raw = (raw & ~(0xFFFFFFULL << 40)) |
                  ((value & 0xFFFFFFULL) << 40); // actualizar bits 63-40
            break;
        }
    }
};

/**
 * @brief Alias semantico para punteros remotos.
 *
 * Un puntero remoto es en la practica una direccion virtual (vm_map_ptr)
 * que pertenece a otra instancia de VestaVM accesible via red.
 */
typedef vm_map_ptr remote_ptr;

/**
 * @brief Union de los tres tipos de destino que puede referenciar un puntero
 * mapeado.
 *
 * Un puntero de la VM puede apuntar a:
 *   - Memoria virtual local  (ptr_vm)
 *   - Memoria real del host  (ptr_host)
 *   - Memoria de un nodo remoto (ptr_remote, identificado por IP)
 */
typedef union ptr_mapped {
    vm_map_ptr ptr_vm;     ///< Direccion virtual local de la VM
    host_ptr ptr_host;     ///< Puntero real en el proceso del host
    remote_ptr ptr_remote; ///< Direccion virtual en una VM remota
} ptr_mapped;

/**
 * @enum type_ptr_mapped
 * @brief Discriminante que identifica el tipo de puntero almacenado en
 * ptr_mapped.
 *
 * Usado junto con la union ptr_mapped para determinar que campo es valido
 * sin incurrir en comportamiento indefinido al acceder al campo incorrecto.
 */
typedef enum type_ptr_mapped {
    NONE = 0,             ///< Sin mapeo activo
    MAPPED_PTR_VM = 1,    ///< Apunta a memoria virtual local
    MAPPED_PTR_HOST = 2,  ///< Apunta a memoria real del proceso host
    MAPPED_PTR_REMOTE = 3 ///< Apunta a memoria en una VM remota
} type_ptr_mapped;

/**
 * @brief Par (direccion virtual, destino mapeado) que describe un mapeo de
 * memoria.
 *
 * Las arenas de la VM no son necesariamente contiguas en la memoria fisica del
 * host.  Esta estructura relaciona cada direccion virtual con su destino real,
 * ya sea memoria local del host, otra direccion virtual o un nodo remoto.
 *
 * La variante MappedPtrRemoteIpv4/6 extiende este concepto anadiendo la
 * direccion IP del nodo propietario de la memoria remota.
 */
typedef struct MappedPtr {
    vm_map_ptr ptr_vm{}; ///< Direccion virtual de la VM
    ptr_mapped mapped{}; ///< Destino real (host, VM local o remoto)

    /**
     * @brief Genera una representacion textual del mapeo.
     *
     * Muestra la direccion virtual, la direccion mapeada y el puntero
     * host en formato hexadecimal de 16 digitos.
     *
     * @return Cadena con el estado completo del mapeo.
     */
#if !defined(VESTA_GC_FREESTANDING)
    std::string to_string() const;

    /**
     * @brief Escribe la representacion textual en un flujo de salida.
     *
     * @param os Flujo destino (p.ej. std::cout).
     */
    void print(std::ostream &os) const;
#endif

    /**
     * @brief Avanza la direccion virtual y la mapeada en @p offset bytes.
     *
     * Modifica tanto ptr_vm.raw como mapped.ptr_vm.raw de manera consistente
     * para que el par siga siendo valido tras el desplazamiento.
     *
     * @param offset Numero de bytes a avanzar.
     * @return Referencia a este mismo objeto tras la modificacion.
     */
    MappedPtr &operator+=(uint64_t offset) {
        ptr_vm.raw += offset;        // avanzar la direccion virtual
        mapped.ptr_vm.raw += offset; // avanzar el destino mapeado en paralelo
        return *this;
    }

    /**
     * @brief Incrementa la direccion en 1 byte (prefijo).
     * @return Referencia a este mismo objeto.
     */
    MappedPtr &operator++() { return (*this += 1); }

    /**
     * @brief Decrementa la direccion en 1 byte (prefijo).
     * @return Referencia a este mismo objeto.
     */
    MappedPtr &operator--() {
        return (*this += static_cast<uint64_t>(
                    -1)); // equivale a -1 en aritmetica de 64 bits
    }

    /**
     * @brief Devuelve una copia del mapeo avanzado en @p offset bytes.
     *
     * No modifica el objeto original.
     *
     * @param offset Numero de bytes de desplazamiento.
     * @return Nueva instancia con la direccion desplazada.
     */
    MappedPtr operator+(uint64_t offset) const {
        MappedPtr tmp = *this; // copia del estado actual
        tmp += offset;         // aplicar desplazamiento
        return tmp;
    }
} MappedPtr;

/**
 * @brief Mapeo de una direccion virtual a un nodo remoto identificado por IPv4.
 *
 * Empaquetado sin relleno (__attribute__((packed))) para que el tamanyo
 * sea predecible al serializar/deserializar mensajes de red.
 */
typedef struct __attribute__((packed)) MappedPtrRemoteIpv4 {
    vm_map_ptr ptr_vm{};  ///< Direccion virtual en la maquina remota
    HostIpv4 host_ipv4{}; ///< Direccion IPv4 del nodo propietario
} MappedPtrRemoteIpv4;

/**
 * @brief Mapeo de una direccion virtual a un nodo remoto identificado por IPv6.
 *
 * Empaquetado sin relleno (__attribute__((packed))) para serialization de red.
 */
typedef struct __attribute__((packed)) MappedPtrRemoteIpv6 {
    vm_map_ptr ptr_vm{};  ///< Direccion virtual en la maquina remota
    HostIpv6 host_ipv6{}; ///< Direccion IPv6 del nodo propietario
} MappedPtrRemote6;

} // namespace vm

#endif // ARENA_H
