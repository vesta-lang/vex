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
 * @file VirtualMemory.h                                                       \
 * @brief Declaracion de la interfaz de memoria virtual de VestaVM.            \
 *                                                                             \
 * Declara @c VirtualMemory: mapeo de rangos de direcciones virtuales a        \
 * arenas del host, lectura/escritura a traves del TLB y relleno de            \
 * regiones con un valor de byte constante.                                    \
 */                                                                            \
#ifndef VIRTUALMEMORY_H
#define VIRTUALMEMORY_H

#include <cstdint>
#include <cstring>

#include "arena_manager.h"
#include "TLB.h"
#include "util/vesta_memcpy.h" // copia por bloques que SI despacha por CPU

namespace vm {

/**
 * @class VirtualMemory
 * @brief Interfaz de acceso a la memoria virtual de un proceso de la VM.
 *
 * VirtualMemory combina un ArenaManager (bloques de memoria real) y un
 * LazyHybridTLB (tabla de traduccion de direcciones) para ofrecer una
 * vista uniforme del espacio de direcciones virtual de la VM.
 *
 * Operaciones principales:
 *   - map()    / unmap()         -- gestionar regiones de memoria.
 *   - read_*() / write_*()       -- acceso tipado a memoria virtual.
 *   - read_bytes() / write_bytes() -- acceso por bloques con cruce de pagina.
 *   - read_any<T>() / write_any<T>() -- despacho en tiempo de compilacion por
 * tipo.
 *   - operator[]                 -- acceso byte a byte por direccion virtual.
 *
 * Todas las traducciones pasan por el TLB.  Si una pagina no esta
 * mapeada, read_bytes() y write_bytes() realizan una asignacion perezosa
 * (lazy allocation) usando permsDefault.
 */
class VirtualMemory {
  private:
    tlb::LazyHybridTLB &tlb; ///< TLB compartido con el proceso propietario
    ArenaManager &arena_mgr; ///< Gestor de bloques de memoria real
    MemPerm
        permsDefault; ///< Permisos usados en lazy allocation (RWX por defecto)

  public:
    /**
     * @brief Cache de pagina de 1 entrada para acelerar accesos secuenciales.
     *
     * El stack del proceso vive en una unica pagina (o pocas) y los accesos
     * de @c enter / @c leave / @c push / @c pop golpean la misma pagina
     * en sucesion.  Cachear la traduccion (vaddr_base -> host_ptr) salta
     * el TLB walk de 3 niveles para hits.
     *
     * **Publico para inline page cache hit del JIT** ( D.jit-mem-model
     * INLINE-CACHE): el codigo nativo emite cmp directo contra
     * cached_page_vaddr y carga cached_page_host sin call al runtime.
     * Los offsets se expone via @c vesta_rt/abi.h con @c static_assert
     * de drift.
     *
     * Invalidacion: el cache se invalida cuando se llama a @c map() o se
     * crea una arena nueva (lazy allocation).
     */
    mutable uint64_t cached_page_vaddr =
        UINT64_MAX; ///< Base de la pagina cacheada (vaddr alineado a 4096)
    mutable uint8_t *cached_page_host =
        nullptr; ///< Host pointer correspondiente

  public:
    /**
     * @brief Acceso al cached_page_vaddr (publico para uso del JIT).
     *
     * El codigo JIT-eated puede leer la pagina cacheada y emitir un
     * fast-path inline para accesos a memoria VM (~10 instrucciones)
     * que evita el call a write_u64_fast / read_u64_fast cuando hay
     * cache hit.  Los offsets de estos campos en ProcessVM se exponen
     * en @c vesta_rt/abi.h con @c static_assert.
     */
    inline uint64_t jit_cached_page_vaddr() const noexcept {
        return cached_page_vaddr;
    }
    inline uint8_t *jit_cached_page_host() const noexcept {
        return cached_page_host;
    }

  public:
    /**
     * @brief La cache de pagina de UN lector, en vez de la del objeto.
     *
     * POR QUE EXISTE
     * --------------
     * Leer memoria de la VM desde OTRO hilo era imposible, y no por la TLB --
     * consultarla no muta nada, es un recorrido de tres niveles y ya --: era por
     * `cached_page_vaddr` y `cached_page_host`, que se escriben en cada acceso.
     * Dos hilos leyendo se pisan esa pareja y uno acaba usando el puntero de una
     * pagina con la direccion de otra.  Y eso no falla: lee bytes equivocados.
     *
     * Ya mordio una vez.  El fusionador de paquetes se llevo a un hilo ayudante
     * y por dentro llamaba a `live_out_after`, que descodifica hasta ocho
     * instrucciones mas alla del paquete.  No hubo ningun error: fusionaba MAL,
     * y el programa devolvia 0 donde esperaba 19.
     *
     * Con la cache del LLAMANTE, la lectura deja de tener estado compartido y
     * cualquier hilo puede mirar el bytecode.
     */
    struct PageView {
        uint64_t vaddr = UINT64_MAX; ///< pagina cacheada, o ninguna
        uint8_t *host = nullptr;     ///< su puntero de anfitrion
    };

    /**
     * @brief Puntero de anfitrion de @p vaddr, SIN tocar nada compartido.
     *
     * No asigna paginas: si la direccion no esta mapeada devuelve null, y quien
     * llama decide.  Asignar es lo unico que muta de verdad en este camino
     * -- crea nodos en la TLB --, asi que dejarlo fuera es lo que hace segura la
     * lectura desde otro hilo.
     *
     * @param vaddr Direccion virtual de la VM.
     * @param view  Cache de pagina del llamante.  Se actualiza.
     * @return Puntero al byte, o null si esa pagina no existe todavia.
     */
    [[nodiscard]] inline uint8_t *host_ptr_readonly(uint64_t vaddr,
                                                    PageView &view) const {
        const uint64_t page = vaddr & ~0xFFFULL;
        if (__builtin_expect(page == view.vaddr, 1))
            return view.host + (vaddr & 0xFFFULL);

        const tlb::TLBEntryData *entry = tlb.get_entry(vaddr);
        /* Sin entrada, sin pagina, o mapeada de una forma que no es un puntero
         * del anfitrion: se dice que no.  Aqui NO se asigna nada -- eso muta la
         * TLB -- ni se aborta el proceso, que es lo que hace el camino normal
         * ante un modo raro: este es un camino de solo lectura y su respuesta a
         * "no se puede" es null. */
        if (entry == nullptr || entry->type_address != MAPPED_PTR_HOST)
            return nullptr;
        uint8_t *base = static_cast<uint8_t *>(entry->address.ptr_host);
        if (base == nullptr) return nullptr;
        view.vaddr = page;
        view.host = base;
        return base + (vaddr & 0xFFFULL);
    }

    /**
     * @brief Quedan tablas de traduccion anteriores por liberar?
     *
     * En linea porque quien lo pregunta lo hace en un punto que se recorre a
     * menudo y la respuesta es que no casi siempre.
     */
    [[nodiscard]] inline bool has_stale_translation_tables() const {
        return tlb.has_older();
    }

    /**
     * @brief Libera las tablas de traduccion anteriores.
     *
     * SOLO desde un punto en el que quien llama sepa que ningun otro hilo
     * esta consultando la traduccion.  La tabla crece duplicandose y guarda la
     * anterior viva para que un lector rezagado no se quede con memoria
     * liberada; esto es lo que la recupera cuando ya no hay rezagados.
     */
    inline void reclaim_translation_tables() { tlb.reclaim_older(); }

    /**
     * @brief Invalida la cache de pagina (usar tras @c map / lazy alloc).
     */
    inline void invalidate_page_cache() const {
        cached_page_vaddr = UINT64_MAX;
        cached_page_host = nullptr;
    }

    /**
     * @brief Escritura rapida de 8 bytes aprovechando la cache de pagina.
     *
     * Si @p vaddr y @p vaddr+8 caen en la pagina cacheada, hace una
     * escritura directa sin TLB walk.  En caso contrario delega en
     * write_bytes (que tambien actualiza la cache).
     */
    inline void write_u64_fast(uint64_t vaddr, uint64_t value) {
        const uint64_t page = vaddr & ~0xFFFULL;
        const uint64_t off = vaddr & 0xFFFULL;
        // Pagina cacheada Y la escritura no cruza el limite de pagina.
        if (__builtin_expect(page == cached_page_vaddr && off <= 4096 - 8, 1)) {
            std::memcpy(cached_page_host + off, &value, 8);
            return;
        }
        write_bytes(vaddr, &value, 8);
    }

    /**
     * @brief Lectura rapida de 8 bytes aprovechando la cache de pagina.
     */
    inline uint64_t read_u64_fast(uint64_t vaddr) {
        const uint64_t page = vaddr & ~0xFFFULL;
        const uint64_t off = vaddr & 0xFFFULL;
        uint64_t v;
        if (__builtin_expect(page == cached_page_vaddr && off <= 4096 - 8, 1)) {
            std::memcpy(&v, cached_page_host + off, 8);
            return v;
        }
        read_bytes(vaddr, &v, 8);
        return v;
    }

  public:
    /**
     * @brief Construye la interfaz de memoria virtual.
     *
     * Los permisos por defecto para la asignacion perezosa se establecen
     * a READ | WRITE | EXEC para que el codigo JIT y los datos funcionen
     * sin necesidad de especificar permisos en cada acceso.
     *
     * @param tlb_    Referencia al TLB del proceso.
     * @param arena   Referencia al ArenaManager del proceso.
     */
    VirtualMemory(tlb::LazyHybridTLB &tlb_, vm::ArenaManager &arena)
        : tlb(tlb_), arena_mgr(arena),
          permsDefault(MemPerm::EXEC | MemPerm::READ | MemPerm::WRITE) {}

    /**
     * @brief Mapea una region de memoria virtual a un bloque real del host.
     *
     * Crea una sola Arena de tamanyo @p size (redondeado a paginas) para
     * cubrir todo el rango [@p vaddr, @p vaddr + @p size).  Cada pagina
     * del rango queda registrada en el TLB apuntando a su offset dentro
     * de la arena.
     *
     * @param vaddr Direccion virtual de inicio del mapeo.
     * @param size  Tamanyo en bytes del rango a mapear.
     * @param perms Permisos de acceso para la arena creada.
     * @return      vm_map_ptr con la direccion de inicio alineada a pagina.
     */
    vm_map_ptr map(uint64_t vaddr, size_t size, MemPerm perms);

    /**
     * @brief Copia datos desde memoria del host a memoria virtual.
     *
     * Recorre las paginas de destino creandolas si no existen (auto-map RW)
     * y copia @p size bytes de @p src_host.
     *
     * @param dest_vaddr Direccion virtual destino.
     * @param src_host   Puntero en memoria del host con los datos a copiar.
     * @param size       Numero de bytes a copiar.
     */
    void vm_to_host_memcpy(uint64_t dest_vaddr, const void *src_host,
                           size_t size);

    /**
     * @brief Rellena una region de memoria virtual con un valor de byte.
     *
     * Equivalente a memset() sobre el espacio de direcciones virtual.
     * Crea las paginas que no existan antes de escribir.
     *
     * @param dest_vaddr Direccion virtual de inicio.
     * @param value      Valor de byte (0-255) a escribir en cada posicion.
     * @param size       Numero de bytes a rellenar.
     */
    void vm_to_host_memset(uint64_t dest_vaddr, int value, size_t size);

    /**
     * @brief Lee @p size bytes desde la memoria virtual a un buffer del host.
     *
     * Gestiona automaticamente la traduccion TLB y los cruces de pagina.
     * En caso de miss (pagina no mapeada) realiza una asignacion perezosa
     * con permsDefault.
     *
     * Optimizacion: cuando el puntero fisico resultante esta alineado a 16
     * bytes se activa un fast-path con __builtin_assume_aligned para que el
     * compilador pueda emitir instrucciones SIMD alineadas (movaps/vmovaps). De
     * lo contrario se usa memcpy() estandar.
     *
     * @param vaddr Direccion virtual de inicio de la lectura.
     * @param dst   Buffer del host donde se almacenan los bytes leidos.
     * @param size  Numero de bytes a leer.
     */
    void read_bytes_slow(uint64_t vaddr, void *dst, size_t size);

    /**
     * @brief Camino RAPIDO: la pagina esta cacheada y el bloque cabe en ella.
     *
     * El cuerpo de verdad -- cruce de pagina, asignacion perezosa, el
     * fast-path SIMD -- sigue fuera de linea en `read_bytes_slow`.  Aqui solo
     * queda la comprobacion y la copia, que es el caso comun con diferencia.
     *
     * Se parte asi y no inlinando el cuerpo entero: son sesenta y dos lineas
     * con reservas de memoria dentro, y meterlas en cada llamante hincharia el
     * icache del camino caliente para acelerar el frio.  Lo que se inlina es
     * SOLO la parte que casi siempre basta.
     *
     * MEDIDO: no da ganancia apreciable (+0,82% en el banco de 68, dentro del
     * +-7% de ruido).  Se deja porque la forma es la correcta -- el camino
     * caliente no debe pagar una llamada -- pero que conste que el numero no lo
     * respalda: lo que si la dio fue conectar la cache de pagina en
     * `operator[]` (-20,6%) e inlinar `get_entry` (-11,1%).
     */
    inline void read_bytes(uint64_t vaddr, void *dst, size_t size) {
        const uint64_t page = vaddr & ~0xFFFULL;
        const uint64_t off = vaddr & 0xFFFULL;
        if (__builtin_expect(page == cached_page_vaddr && off + size <= 4096,
                             1)) {
            /* `util::vesta_memcpy` y no `std::memcpy`: el de la CRT de Windows
             * no despacha por capacidad de la CPU y se queda en el camino
             * escalar.  El nuestro elige AVX2 o SSE2 segun lo que haya, y por
             * debajo de 16 bytes copia en linea con bloques solapados en vez
             * de llamar a la biblioteca. */
            util::vesta_memcpy(dst, cached_page_host + off, size);
            return;
        }
        read_bytes_slow(vaddr, dst, size);
    }

    /**
     * @brief Escribe @p size bytes desde un buffer del host a memoria virtual.
     *
     * Simetrico de read_bytes().  Gestiona cruces de pagina y asignacion
     * perezosa del mismo modo.
     *
     * @param vaddr Direccion virtual de inicio de la escritura.
     * @param src   Buffer del host con los datos a escribir.
     * @param size  Numero de bytes a escribir.
     */
    void write_bytes_slow(uint64_t vaddr, const void *src, size_t size);

    /// Camino RAPIDO de escritura, simetrico del de lectura.  Ver `read_bytes`.
    inline void write_bytes(uint64_t vaddr, const void *src, size_t size) {
        const uint64_t page = vaddr & ~0xFFFULL;
        const uint64_t off = vaddr & 0xFFFULL;
        if (__builtin_expect(page == cached_page_vaddr && off + size <= 4096,
                             1)) {
            util::vesta_memcpy(cached_page_host + off, src, size);
            return;
        }
        write_bytes_slow(vaddr, src, size);
    }

    /**
     * @brief Escribe un byte en la direccion virtual indicada.
     * @param vaddr Direccion virtual destino.
     * @param value Byte a escribir.
     */
    void write_u8(uint64_t vaddr, uint8_t value);

    /**
     * @brief Escribe dos bytes (little-endian) en la direccion virtual
     * indicada.
     * @param vaddr Direccion virtual destino.
     * @param value Valor de 16 bits a escribir.
     */
    void write_u16(uint64_t vaddr, uint16_t value);

    /**
     * @brief Escribe cuatro bytes (little-endian) en la direccion virtual
     * indicada.
     * @param vaddr Direccion virtual destino.
     * @param value Valor de 32 bits a escribir.
     */
    void write_u32(uint64_t vaddr, uint32_t value);

    /**
     * @brief Escribe ocho bytes (little-endian) en la direccion virtual
     * indicada.
     * @param vaddr Direccion virtual destino.
     * @param value Valor de 64 bits a escribir.
     */
    void write_u64(uint64_t vaddr, uint64_t value);

    /**
     * @brief Lee un byte desde la direccion virtual indicada.
     * @param vaddr Direccion virtual fuente.
     * @return      Byte leido.
     */
    uint8_t read_u8(uint64_t vaddr);

    /**
     * @brief Lee dos bytes (little-endian) desde la direccion virtual indicada.
     * @param vaddr Direccion virtual fuente.
     * @return      Valor de 16 bits leido.
     */
    uint16_t read_u16(uint64_t vaddr);

    /**
     * @brief Lee cuatro bytes (little-endian) desde la direccion virtual
     * indicada.
     *
     * Atajo sobre read_bytes() para acceso de 32 bits.  Gestiona
     * automaticamente la traduccion TLB y los cruces de pagina.
     *
     * @param vaddr Direccion virtual fuente.
     * @return      Valor de 32 bits leido.
     */
    uint32_t read_u32(uint64_t vaddr);

    /**
     * @brief Lee ocho bytes (little-endian) desde la direccion virtual
     * indicada.
     *
     * Atajo sobre read_bytes() para acceso de 64 bits.  Gestiona
     * automaticamente la traduccion TLB y los cruces de pagina.
     *
     * @param vaddr Direccion virtual fuente.
     * @return      Valor de 64 bits leido.
     */
    uint64_t read_u64(uint64_t vaddr);

    /**
     * @brief Desmapea la region de memoria virtual indicada.
     *
     * Libera las arenas asociadas a las paginas del rango e invalida
     * las entradas correspondientes en el TLB.
     *
     * @param vaddr Direccion virtual de inicio del rango.
     * @param size  Tamanyo en bytes del rango a desmapear.
     */
    void unmap(uint64_t vaddr, size_t size);

    /**
     * @brief Acceso por referencia a un byte de la memoria virtual.
     *
     * Traduce @p vaddr a un puntero de host y devuelve una referencia
     * al byte en el offset de pagina correspondiente.  Si la entrada
     * TLB no existe o no es de tipo HOST, fuerza una lectura de un byte
     * para crear la pagina antes de devolver la referencia.
     *
     * @param vaddr Direccion virtual del byte a acceder.
     * @return      Referencia mutable al byte en memoria del host.
     *
     * @warning El resultado es invalido tras cualquier llamada que
     *          desaloje la pagina del TLB (unmap, clear_tlb_entry).
     */
    uint8_t &operator[](uint64_t vaddr) {
        const uint64_t page = vaddr & ~0xFFFULL;
        /* La cache de pagina PRIMERO.
         *
         * Existia desde antes y este acceso no la usaba: iba directo al arbol
         * de la TLB, tres cargas dependientes y tres comprobaciones de rango,
         * en CADA byte.  `read_u64_fast` y `write_u64_fast` si la consultan, o
         * sea que aqui faltaba el mismo camino rapido que ya estaba escrito al
         * lado -- el mismo modo de fallo que el camino rapido del slab, que
         * tambien dejo consumidores atras.
         *
         * Y no es un acceso raro: `cursor_en` trae los bytes de cada
         * instruccion UNO A UNO por aqui, dieciseis por descodificacion.  Su
         * comentario dice que el coste es irrelevante porque descodificar solo
         * ocurre al fallar la icache "el 0,57% de las ejecuciones", pero medido
         * con VTune retira 6,17 veces mas instrucciones que `icache_lookup`,
         * que corre una vez por instruccion ejecutada: la tasa de fallo real
         * ronda el 6%, un orden de magnitud mas.
         *
         * La invalidacion no cambia: la cache la rellenan `read_bytes` y
         * `write_bytes`, y la limpia `invalidate_page_cache()` tras `map` o
         * una asignacion perezosa.  Aqui solo se LEE. */
        if (__builtin_expect(page == cached_page_vaddr, 1))
            return cached_page_host[vaddr & 0xFFF];

        tlb::TLBEntryData *entry =
            tlb.get_entry(vaddr); // buscar entrada en TLB

        // si no existe o no es host, forzar la asignacion perezosa
        if (!entry || entry->type_address != MAPPED_PTR_HOST) {
            uint8_t dummy;
            read_bytes(vaddr, &dummy, 1); // genera la pagina si no existe
            entry = tlb.get_entry(vaddr); // releer la entrada tras asignacion
        }

        uint8_t *base = static_cast<uint8_t *>(
            entry->address.ptr_host); // base de la pagina
        /* Y se DEJA cacheada, que es lo que hace que el siguiente byte de la
         * misma pagina no vuelva a recorrer el arbol.  Sin esto el camino
         * rapido de arriba solo acertaria por lo que dejaran otros. */
        cached_page_vaddr = page;
        cached_page_host = base;
        return base[vaddr & 0xFFF]; // offset dentro de la pagina (12 bits)
    }

    /**
     * @brief Lee un valor del tipo T desde la direccion virtual indicada.
     *
     * Despacha en tiempo de compilacion a read_u8/u16/u32/u64 segun sizeof(T).
     * Solo soporta uint8_t, uint16_t, uint32_t y uint64_t.
     *
     * @tparam T Tipo entero sin signo a leer (8, 16, 32 o 64 bits).
     * @param  addr Direccion virtual fuente.
     * @return Valor leido de tipo T.
     */
    template <typename T> inline T read_any(uint64_t addr) {
        if constexpr (std::is_same_v<T, uint8_t>)
            return read_u8(addr); // lectura de 8 bits
        else if constexpr (std::is_same_v<T, uint16_t>)
            return read_u16(addr); // lectura de 16 bits
        else if constexpr (std::is_same_v<T, uint32_t>)
            return read_u32(addr); // lectura de 32 bits
        else if constexpr (std::is_same_v<T, uint64_t>)
            return read_u64(addr); // lectura de 64 bits
        else
            static_assert(
                sizeof(T) == 0,
                "read_any: tipo no soportado"); // error en compilacion
    }

    /**
     * @brief Escribe un valor del tipo T en la direccion virtual indicada.
     *
     * Despacha en tiempo de compilacion a write_u8/u16/u32/u64 segun sizeof(T).
     * Solo soporta uint8_t, uint16_t, uint32_t y uint64_t.
     *
     * @tparam T     Tipo entero sin signo a escribir (8, 16, 32 o 64 bits).
     * @param  addr  Direccion virtual destino.
     * @param  value Valor a escribir.
     */
    template <typename T> inline void write_any(uint64_t addr, T value) {
        if constexpr (std::is_same_v<T, uint8_t>)
            write_u8(addr, value); // escritura de 8 bits
        else if constexpr (std::is_same_v<T, uint16_t>)
            write_u16(addr, value); // escritura de 16 bits
        else if constexpr (std::is_same_v<T, uint32_t>)
            write_u32(addr, value); // escritura de 32 bits
        else if constexpr (std::is_same_v<T, uint64_t>)
            write_u64(addr, value); // escritura de 64 bits
        else
            static_assert(
                sizeof(T) == 0,
                "write_any: tipo no soportado"); // error en compilacion
    }
};

} // namespace vm

#endif // VIRTUALMEMORY_H
