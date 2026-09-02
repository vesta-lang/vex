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
 * @file raw_allocator.cpp
 * @brief Implementacion del asignador de memoria contigua para FFI.
 *
 * @c RawAllocator es el backend de @c malloc / @c free / @c realloc del
 * bytecode VM cuando el codigo Vesta pide memoria que tiene que ser
 * accesible directamente desde funciones C nativas (FFI).
 *
 * Diferencias con el GC heap (@c gc_heap):
 *   - SIN tracking de referencias: el GC NO escanea esta memoria; el
 *     usuario es responsable de llamar a @c free explicitamente.  Util
 *     para buffers FFI donde el GC no debe interferir.
 *   - SIN compactacion: las direcciones permanecen estables durante toda
 *     la vida del bloque.  Critico para FFI: una funcion C que recibe un
 *     puntero NO se mueve durante una llamada larga.
 *   - SIN evacuacion: cada @c alloc devuelve un bloque distinto y
 *     contiguo via @c vm::allocate_memory (envoltorio sobre
 *     @c VirtualAlloc en Windows o @c mmap en POSIX).
 *
 * Decisiones de diseno:
 *   - @c allocations_ usa @c std::unordered_map<key, AllocRec>: necesitamos
 *     lookup O(1) por puntero en @c free / @c realloc para validar que el
 *     puntero efectivamente proviene de este allocator (evita double-free
 *     y free de punteros foraneos).
 *   - Toda la memoria se zero-initializa en @c alloc: comportamiento
 *     predecible (igual que @c calloc) a coste de un memset.  El usuario
 *     que necesite el ultimo nano-segundo puede usar @c vm::allocate_memory
 *     directamente, pero ese path no entra en el tracking.
 *   - El campo @c total_bytes_ y @c stats_ se mantienen sin atomicidad
 *     porque @c RawAllocator es per-proceso (cada @c ProcessVM tiene el
 *     suyo) y los procesos VM no comparten allocator entre threads.
 */

#include "util/env_flags.h"
#include "gc/raw_allocator.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <algorithm>

namespace gc {

/**
 * @brief Asigna @c size bytes contiguos y devuelve la direccion host.
 *
 * @param size Numero de bytes a reservar.  Si es 0, devuelve 0
 *             inmediatamente (convencion para "alocacion nula").
 * @return Direccion host como @c uint64_t (es el resultado de
 *         @c reinterpret_cast<uint64_t>(ptr)); 0 si el SO no pudo
 *         atender la peticion.
 *
 * El puntero devuelto es valido hasta que se llame a @c free, @c realloc
 * o @c free_all sobre el.  La zona se zero-initializa para que el
 * usuario no vea basura de memoria reusada.
 */
uint64_t RawAllocator::alloc(size_t size) {
    // Convencion: tama~no cero -> no alocar.  Asi el frontend puede
    // llamar @c alloc(0) sin manejar el caso especial y obtiene 0
    // (que @c free trata como no-op).  Coherente con la semantica
    // de malloc en C99 cuando size==0.
    if (size == 0) return 0;

    // ===== Slab fast path (Sprint mem-loop-fix 2026-06-02) =====
    // Para bloques pequenos (<= 1024 bytes), usar el slab allocator
    // para evitar el syscall VirtualAlloc/mmap por alloc.  Bench
    // mem_malloc_free (5M iter de malloc(96)+free) pasaba de 20s
    // a ~50-100ms con esto.
    // Env var @c VESTA_NO_SLAB=1 desactiva el slab (fallback a
    // VirtualAlloc/mmap por alloc).  Util para diagnosticar
    // regresiones del slab vs el path tradicional.
    // Sprint mem-perf (2026-06-02): cachear el env var VESTA_NO_SLAB
    // para evitar @c getenv en el hot path (es 100-300 ns por
    // llamada, mayor que el coste de un alloc del slab).
    if (slab_env_cache_ == 0) {
        slab_env_cache_ = (util::flag_on(util::FlagId::NoSlab)) ? 2u : 1u;
    }
    const size_t class_idx =
        (slab_env_cache_ == 2u) ? SIZE_MAX : slab_class_for(size);
    if (class_idx != SIZE_MAX) {
        // Asegurar que hay slots libres en este class; grow si no.
        if (slab_free_list_[class_idx] == nullptr) {
            if (!slab_grow_class(class_idx)) {
                // Slab grow fallo (OOM o size >SLAB_CHUNK_BYTES).
                // Caer al path tradicional como fallback.
                goto fallback_vm_alloc;
            }
        }
        // Pop del free list LIFO.
        SlabFreeNode *node = slab_free_list_[class_idx];
        slab_free_list_[class_idx] = node->next;
        // Zero-init del payload (consistente con alloc tradicional).
        std::memset(node, 0, SLAB_SIZES[class_idx]);
        const uint64_t payload_ptr = reinterpret_cast<uint64_t>(node);
        // Sprint mem-perf: NO map insert.  El class_idx se localiza
        // en @c free via binary search sobre @c slab_chunks_sorted_.
        // Stats.
        const size_t slab_size = SLAB_SIZES[class_idx];
        total_bytes_ += slab_size;
        ++slab_live_count_;
        slab_live_bytes_ += slab_size;
        stats_.alloc_count++;
        stats_.alloc_bytes += slab_size;
        if (total_bytes_ > stats_.peak_bytes) {
            stats_.peak_bytes = total_bytes_;
        }
        return payload_ptr;
    }

fallback_vm_alloc:
    /* Antes de pedirle nada al sistema: ¿hay uno de ese tamano guardado?
     *
     * Un bucle que pide y suelta un bloque grande pagaba dos llamadas al
     * sistema y el borrado del bloque entero en cada vuelta.  Reusar el que
     * acaba de soltarse cuesta un memset -- que se paga igual, porque el
     * contenido tiene que salir a cero -- y nada mas. */
    for (size_t i = grandes_libres_.size(); i-- > 0;) {
        if (grandes_libres_[i].size != size) continue;
        const uint64_t reusado = grandes_libres_[i].host_ptr;
        grandes_libres_bytes_ -= grandes_libres_[i].size;
        grandes_libres_.erase(grandes_libres_.begin() + (long)i);
        // Se entrega a cero, igual que uno recien pedido al sistema: quien
        // reserva no tiene por que saber si le toco uno reciclado.
        std::memset(reinterpret_cast<void *>(reusado), 0, size);
        allocations_.emplace(
            reusado, AllocRecord{reinterpret_cast<void *>(reusado), size});
        total_bytes_ += size;
        stats_.alloc_count++;
        stats_.alloc_bytes += size;
        if (total_bytes_ > stats_.peak_bytes) stats_.peak_bytes = total_bytes_;
        return reusado;
    }

    // ===== Slow path: VirtualAlloc/mmap para bloques grandes =====
    // Reservar memoria contigua con permisos READ|WRITE (sin EXEC: la
    // memoria raw es para datos, no para codigo).  La capa @c vm::
    // selecciona @c VirtualAlloc (Win32) o @c mmap (POSIX) segun
    // plataforma.  Una unica region contigua => el puntero es valido
    // para aritmetica de punteros C estandar.
    void *ptr =
        vm::allocate_memory(size, vm::MemPerm::READ | vm::MemPerm::WRITE);
    // Si el sistema operativo no pudo satisfacer la peticion (OOM,
    // limite de VAS, etc.), devolvemos 0.  El caller (FFI o codigo
    // Vesta) decide como manejarlo (panic, throw, retry...).
    if (!ptr) return 0;

    // Zero-init: garantiza comportamiento predecible (lectura sin
    // escribir devuelve 0, no contenido residual de otro proceso).
    // Coste lineal en @c size pero ya pagamos por la pagina al
    // tocarla con writes posteriores.  Skipearlo solo ahorraria
    // cuando el caller va a escribir TODO el bloque inmediatamente.
    std::memset(ptr, 0, size);

    // La clave de la tabla es la propia direccion host (cast a u64).
    // Usar el puntero como clave permite que @c free(ptr) sea un
    // lookup directo sin tener que mantener un mapeo handle->ptr
    // por separado.  El bytecode VM trata el u64 como un host_ptr
    // opaco y nunca lo deref directamente desde memoria VM.
    uint64_t key = reinterpret_cast<uint64_t>(ptr);
    allocations_[key] = {ptr, size};
    // Acumulador de bytes vivos: incrementa aqui, decrementa en free.
    // Usado para reportar al usuario / debugger y para el high-water.
    total_bytes_ += size;

    // Estadisticas: incrementadas sin checks defensivos porque los
    // campos del struct son @c uint64_t y los counts en programas
    // normales no se acercan al overflow (~10^19 allocs).
    stats_.alloc_count++;
    stats_.alloc_bytes += size;
    // High-water mark: rastrea el pico de uso para que el usuario
    // pueda dimensionar mejor el heap.  Solo se actualiza al crecer.
    if (total_bytes_ > stats_.peak_bytes) stats_.peak_bytes = total_bytes_;

    return key;
}

/**
 * @brief Libera un bloque previamente devuelto por @c alloc o @c realloc.
 *
 * @param ptr Direccion host (la misma que devolvio @c alloc).  Si NO
 *            esta registrada en la tabla (puntero foraneo, ya
 *            liberado, o 0), retorna @c false sin tocar nada.
 * @return @c true si efectivamente se libero el bloque; @c false si
 *         el puntero no era conocido.
 *
 * La validacion previa por lookup evita el doble-free silencioso: un
 * @c free duplicado del mismo puntero falla con @c false en lugar de
 * corromper el heap del sistema.  La semantica @c "free de ptr null
 * es no-op" se preserva.
 */
bool RawAllocator::free(uint64_t ptr) {
    // ===== Slab fast path (Sprint mem-perf 2026-06-02) =====
    // Si ptr cae en algun chunk del slab, push al free list.
    if (const SlabChunkInfo *chunk = slab_chunk_for(ptr)) {
        const uint8_t class_idx = chunk->class_idx;
        const size_t slab_size = SLAB_SIZES[class_idx];

        /* (1) Que el puntero sea el PRINCIPIO de un slot.
         *
         * Bastaba con que cayera dentro del chunk, asi que un `free(p + 8)`
         * -- de un bloque VIVO, ademas -- se aceptaba: el slot se encadenaba
         * desplazado y el `next` de la lista pasaba a ser lo que el programa
         * tuviera escrito ahi.  El `alloc` SIGUIENTE lo seguia y moria de
         * violacion de acceso, lejos del `free` culpable.
         *
         * Los tamanos son potencias de dos, asi que comprobarlo es un AND. */
        if (((ptr - chunk->base) & (slab_size - 1)) != 0) {
            ++stats_.invalid_free_count;
            return false;
        }

        SlabFreeNode *node = reinterpret_cast<SlabFreeNode *>(ptr);
        const uint64_t marca = SLAB_FREE_MARK ^ ptr;

        /* (2) Que el slot no estuviera YA libre.
         *
         * El camino tradicional lo comprobaba buscando el puntero en el
         * catalogo -- y la documentacion de esta funcion lo sigue prometiendo
         * --, pero el camino rapido no miraba nada: un doble free encadenaba
         * el nodo consigo mismo (`p->next = p`) y los DOS `alloc` siguientes
         * devolvian la MISMA direccion, dos objetos vivos sobre la misma
         * memoria y en silencio.  De paso se perdia la lista libre entera del
         * chunk, porque el `next` que se sobrescribia era el que la
         * enhebraba: 64 KiB fugados por cada doble free. */
        if (node->free_mark == marca) {
            ++stats_.double_free_count;
            return false;
        }

        // Push al free list: el slot mismo guarda el next ptr.
        node->next = slab_free_list_[class_idx];
        node->free_mark = marca;
        slab_free_list_[class_idx] = node;
        // Stats.
        stats_.free_count++;
        stats_.freed_bytes += slab_size;
        total_bytes_ -= slab_size;
        --slab_live_count_;
        slab_live_bytes_ -= slab_size;
        return true;
    }

    // ===== Slow path: bloques de allocations_ tradicional =====
    // Lookup en la tabla.  Si ptr no esta registrado (puede ser 0,
    // puntero foraneo, o doble-free), no hacemos nada y devolvemos
    // false para que el caller sepa.  Mas seguro que llamar a
    // @c vm::free_memory ciegamente con un puntero invalido.
    auto it = allocations_.find(ptr);
    if (it == allocations_.end()) return false;

    // Stats: contamos el free + acumulamos los bytes liberados para
    // que el reporte final indique cuanto se libero (vs total alocado).
    stats_.free_count++;
    stats_.freed_bytes += it->second.size;

    /* Guardarlo para el siguiente en vez de devolverlo, mientras quepa.
     *
     * El caso que lo justifica no es raro: un bucle que pide un bloque, lo
     * usa y lo suelta.  Devolviendolo, cada vuelta cuesta dos llamadas al
     * sistema y el borrado del bloque entero.  Pasado el tope se devuelve --
     * esto ahorra llamadas, no acapara memoria. */
    const size_t tam = it->second.size;
    const uint64_t dir = reinterpret_cast<uint64_t>(it->second.host_ptr);
    if (grandes_libres_.size() < kGrandesLibresMax &&
        grandes_libres_bytes_ + tam <= kGrandesLibresTope) {
        grandes_libres_.push_back({dir, tam});
        grandes_libres_bytes_ += tam;
    } else {
        // Tras esto la direccion puede reusarla el sistema para otra peticion,
        // asi que cualquier copia del puntero queda colgando.
        vm::free_memory(it->second.host_ptr, tam);
    }
    // Actualizar el contador de bytes vivos.  No actualizamos
    // @c peak_bytes (sigue siendo el max historico, no el actual).
    total_bytes_ -= it->second.size;
    allocations_.erase(it);
    return true;
}

/**
 * @brief Cambia el tamano de un bloque existente.
 *
 * @param ptr      Direccion previamente alocada (o 0 para comportarse
 *                 como @c alloc).
 * @param new_size Nuevo tamano deseado.  Si es 0, equivale a @c free.
 * @return Nueva direccion host (o 0 en OOM).  La direccion PUEDE haber
 *         cambiado: el caller debe actualizar cualquier puntero local.
 *
 * Semantica equivalente a @c realloc(3) de C: si el bloque crece, los
 * bytes adicionales se zero-initializan; si decrece, los bytes finales
 * se descartan.  Implementacion simple "alloc + memcpy + free" en
 * lugar de intentar extender en-sitio (que requeriria mas hooks con
 * el allocator del SO y rara vez funcionaria con bloques grandes).
 */
uint64_t RawAllocator::realloc(uint64_t ptr, size_t new_size) {
    // Stats: contamos siempre, incluso si el realloc degenera en free
    // o en alloc (el usuario puso realloc en su codigo, eso es lo
    // que importa para reportar).
    stats_.realloc_count++;

    // Caso especial 1: new_size == 0 -> equivalente a free.
    // Devolver 0 indica "ya no hay bloque" segun la convencion C.
    if (new_size == 0) {
        free(ptr);
        return 0;
    }

    /* Un bloque del SLAB no esta en el catalogo: el camino rapido no registra
     * nada.  Sin preguntar por el, el `find` de abajo fallaba y el bloque se
     * trataba como ajeno -- o sea `return alloc(new_size)`: un bloque nuevo
     * SIN copiar los datos y SIN soltar el viejo.  El contenido se perdia y el
     * viejo se fugaba, y ninguna de las dos cosas daba error.
     *
     * Su tamano no hay que guardarlo en ningun sitio: es el de su clase. */
    if (const SlabChunkInfo *chunk = slab_chunk_for(ptr)) {
        const size_t old_size = SLAB_SIZES[chunk->class_idx];
        const uint64_t nuevo = alloc(new_size);
        if (nuevo == 0) return 0; // sin memoria: el viejo sigue intacto
        std::memcpy(reinterpret_cast<void *>(nuevo),
                    reinterpret_cast<const void *>(ptr),
                    std::min(old_size, new_size));
        /* `alloc` ya zerifica el bloque entero, asi que la cola de un bloque
         * que crece queda a cero sin hacer nada mas. */
        free(ptr);
        return nuevo;
    }

    // Caso especial 2: ptr no registrado.  Tipico cuando el caller
    // pasa 0 ("este puntero aun no existe, dame uno nuevo") o un
    // puntero foraneo (que tratamos defensivamente como si fuera 0).
    // Equivale a @c alloc(new_size).
    auto it = allocations_.find(ptr);
    if (it == allocations_.end()) return alloc(new_size);

    size_t old_size = it->second.size;

    // Estrategia "alloc + memcpy + free" en lugar de extension en-sitio.
    // Razones: (a) la API del SO no garantiza poder extender pages ya
    // mapeadas sin mover; (b) la copia es lineal pero ya pagamos el
    // coste de las pages nuevas en cualquier estrategia.
    void *new_ptr =
        vm::allocate_memory(new_size, vm::MemPerm::READ | vm::MemPerm::WRITE);
    // Si el OS no puede dar la memoria nueva, mantenemos el bloque
    // original intacto y devolvemos 0.  El caller decide que hacer
    // (e.g. liberar el bloque viejo y reportar OOM, o seguir con el
    // tamano anterior).  NUNCA liberamos el bloque viejo en OOM:
    // mejor un bloque mas chico que ningun bloque.
    if (!new_ptr) return 0;

    // Copiar min(old, new) bytes: si decrece, copiamos solo lo que
    // cabe en el destino (truncacion al final); si crece, copiamos
    // todo lo viejo y dejamos los bytes nuevos sin tocar (los
    // inicializaremos a 0 a continuacion).
    std::memcpy(new_ptr, it->second.host_ptr, std::min(old_size, new_size));
    // Zero-init de la cola si el bloque creci`o, para mantener la
    // misma semantica que @c alloc (lectura sin escritura devuelve 0).
    if (new_size > old_size)
        std::memset(static_cast<uint8_t *>(new_ptr) + old_size, 0,
                    new_size - old_size);

    // Stats del free implicito del bloque viejo.
    stats_.free_count++;
    stats_.freed_bytes += old_size;

    // Liberar el bloque viejo y eliminar su entrada de la tabla.  Solo
    // despues añadiremos el nuevo (en orden para que @c total_bytes_
    // refleje la transicion correctamente y el peak se actualice
    // contra el nuevo total).
    vm::free_memory(it->second.host_ptr, old_size);
    total_bytes_ -= old_size;
    allocations_.erase(it);

    // Registrar el nuevo bloque + stats.
    uint64_t new_key = reinterpret_cast<uint64_t>(new_ptr);
    allocations_[new_key] = {new_ptr, new_size};
    total_bytes_ += new_size;

    stats_.alloc_count++;
    stats_.alloc_bytes += new_size;
    if (total_bytes_ > stats_.peak_bytes) stats_.peak_bytes = total_bytes_;

    return new_key;
}

/**
 * @brief Libera TODOS los bloques activos de una sola pasada.
 *
 * Llamado tipicamente desde el destructor del ProcessVM para limpiar
 * fugas si el codigo Vesta olvido alguna llamada a @c free.  Tras
 * @c free_all, cualquier puntero previamente devuelto queda dangling
 * y NO debe usarse.
 */
void RawAllocator::free_all() {
    // Iterar la tabla completa.  Como vamos a @c clear() al final, no
    // hace falta @c erase incremental durante el bucle (mas rapido).
    for (auto &[key, rec] : allocations_) {
        stats_.free_count++;
        stats_.freed_bytes += rec.size;
        vm::free_memory(rec.host_ptr, rec.size);
    }
    // Clear despues del free: liberar memoria primero, despues
    // descartar la tabla de tracking.  Si pasara al reves dejariamos
    // los bloques alocados sin tracking y serian un leak real.
    allocations_.clear();
    /* Los del slab tambien se sueltan aqui, y tambien CUENTAN.  Se liberan
     * desde siempre, pero no se sumaban a las estadisticas: un programa que
     * reservara mil bloques pequenos y los dejara vivos hasta el final
     * terminaba con `free_count` a cero, como si no hubiera soltado nada. */
    stats_.free_count += slab_live_count_;
    stats_.freed_bytes += slab_live_bytes_;
    slab_live_count_ = 0;
    slab_live_bytes_ = 0;
    // Sprint mem-loop-fix: tambien liberar todos los chunks del slab.
    slab_free_all();
    total_bytes_ = 0;
}

// =========================================================================
// Slab allocator (Sprint mem-loop-fix 2026-06-02)
// =========================================================================

/**
 * @brief Aloca un chunk del SO + trocea + thread al free list.
 *
 * Llamado por @c alloc cuando el free list del size class esta
 * vacio.  Pide un chunk grande (SLAB_CHUNK_BYTES = 64 KB) al SO
 * y lo divide en N slots del tamano del class.  Cada slot incluye
 * un @c SlabSlotHeader de 8 bytes con el class_idx, asi @c free
 * sabe a que free list devolverlo sin lookup en el mapa.
 *
 * Coste: 1 syscall VirtualAlloc/mmap amortizado sobre 64 KB / size
 * slots = N slots por chunk.  Para size=128, 64K/128 = 512 slots
 * por syscall.
 */
bool RawAllocator::slab_grow_class(size_t class_idx) {
    if (class_idx >= SLAB_CLASSES) return false;
    const size_t slot_size = SLAB_SIZES[class_idx];
    if (slot_size > SLAB_CHUNK_BYTES) return false;
    // Reservar un chunk del SO.  El chunk completo se contabiliza
    // en slab_chunks_ para liberarlo en @c slab_free_all.
    void *chunk = vm::allocate_memory(SLAB_CHUNK_BYTES,
                                      vm::MemPerm::READ | vm::MemPerm::WRITE);
    if (!chunk) return false;
    // Sprint mem-perf: insertar el chunk en @c slab_chunks_sorted_
    // manteniendo el orden por base (binary insert).  Inserts son
    // raros (~1 por cada N slots del mismo class consumidos), asi
    // que el O(N_chunks) memmove es despreciable.
    SlabChunkInfo info{};
    info.base = reinterpret_cast<uint64_t>(chunk);
    info.end = info.base + SLAB_CHUNK_BYTES;
    info.class_idx = static_cast<uint8_t>(class_idx);
    auto pos = std::upper_bound(
        slab_chunks_sorted_.begin(), slab_chunks_sorted_.end(), info.base,
        [](uint64_t b, const SlabChunkInfo &c) { return b < c.base; });
    slab_chunks_sorted_.insert(pos, info);
    // Trocear el chunk en N slots y push cada uno al free list.
    // Walk linear (los slots no necesitan estar en orden).
    uint8_t *base = static_cast<uint8_t *>(chunk);
    const size_t n_slots = SLAB_CHUNK_BYTES / slot_size;
    for (size_t i = 0; i < n_slots; ++i) {
        SlabFreeNode *node =
            reinterpret_cast<SlabFreeNode *>(base + i * slot_size);
        node->next = slab_free_list_[class_idx];
        slab_free_list_[class_idx] = node;
    }
    return true;
}

/**
 * @brief Libera todos los chunks del slab.  Llamado por @c free_all
 * (y por tanto por el destructor).  Tras esto, todos los punteros
 * del slab quedan invalidos.
 */
void RawAllocator::slab_free_all() {
    for (const auto &c : slab_chunks_sorted_) {
        vm::free_memory(reinterpret_cast<void *>(c.base),
                        static_cast<size_t>(c.end - c.base));
    }
    slab_chunks_sorted_.clear();
    for (size_t i = 0; i < SLAB_CLASSES; ++i) {
        slab_free_list_[i] = nullptr;
    }
}

} // namespace gc
