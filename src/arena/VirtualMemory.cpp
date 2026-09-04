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
 * @file VirtualMemory.cpp
 * @brief Implementacion de la interfaz de memoria virtual de VestaVM.
 *
 * Implementa @c VirtualMemory: mapeo de regiones virtuales a arenas del host,
 * lectura y escritura de bytes a traves del TLB, y relleno de regiones
 * con un valor constante.
 */
#include "arena/VirtualMemory.h"
#include <algorithm> // UCRT64: no transitivo

#include "util/gc_diag.h" // VGC_COUT (neutralizable en freestanding)

namespace vm {

/**
 * @brief Mapea una region de memoria virtual a un bloque real del host.
 *
 * Alinea el rango [@p vaddr, @p vaddr + @p size) a limites de pagina (4 KiB),
 * reserva una sola arena que cubre todo el rango y registra en el TLB una
 * entrada HOST por cada pagina del rango apuntando a su offset dentro de la
 * arena.
 *
 * @param vaddr Direccion virtual de inicio del mapeo (se redondea hacia abajo a
 * 4 KiB).
 * @param size  Tamanyo en bytes del rango a mapear.
 * @param perms Permisos de acceso para la arena creada (READ / WRITE / EXEC).
 * @return      vm_map_ptr con la direccion de inicio alineada a pagina.
 */
vm_map_ptr VirtualMemory::map(uint64_t vaddr, size_t size, vm::MemPerm perms) {
    // alinear inicio hacia abajo y fin hacia arriba al limite de pagina
    uint64_t start = vaddr & ~0xFFFULL;
    uint64_t end = (vaddr + size + 0xFFFULL) & ~0xFFFULL;
    size_t total_size = end - start; // tamanyo total alineado a paginas

    // reservar una sola arena contigua para toda la region
    uint64_t id = arena_mgr.create_arena(total_size, perms);
    const Arena *arena =
        arena_mgr.get_arena(id); // obtener el bloque recien creado
    if (arena == nullptr || arena->ptr == nullptr) {
        /* Sin memoria no hay region, y seguir era desreferenciar `arena` para
         * calcular la base de cada pagina: el fallo salia como una violacion
         * de acceso dentro del bucle de abajo, que no dice nada de que lo que
         * ocurrio fue que la reserva no cupo.  El gestor ya ha dicho cuanto se
         * pedia; aqui se dice PARA QUE era. */
        VGC_CERR << "[VirtualMemory] no se pudo mapear la region virtual ["
                 << start << ", " << end << ") de " << total_size
                 << " bytes: el gestor de arenas no dio memoria\n";
        return vm_map_ptr{}; // raw = 0: no hay region
    }

    // registrar una entrada TLB HOST por cada pagina del rango
    for (uint64_t page = start; page < end; page += 0x1000) {
        ptr_mapped pm{};
        pm.ptr_host =
            (uint8_t *)arena->ptr + (page - start); // offset dentro de la arena
        tlb.translate(page, MAPPED_PTR_HOST,
                      pm); // registrar traduccion pagina -> host
    }

    vm_map_ptr result{};
    result.raw = start; // devolver la direccion de inicio alineada
    return result;
}

/**
 * @brief Desmapea la region de memoria virtual indicada.
 *
 * Itera sobre las paginas del rango, libera la arena asociada a cada una
 * (usando una busqueda lineal por puntero de host) e invalida la entrada
 * del TLB para cada pagina liberada.
 *
 * @param vaddr Direccion virtual de inicio del rango a desmapear.
 * @param size  Tamanyo en bytes del rango a desmapear.
 */
void VirtualMemory::unmap(uint64_t vaddr, size_t size) {
    uint64_t end = vaddr + size; // limite superior del rango

    // iterar sobre cada pagina del rango
    for (uint64_t page = vaddr & ~0xFFFULL; page < end; page += 0x1000) {
        tlb::TLBEntryData *entry = tlb.get_entry(page); // buscar la entrada TLB
        if (!entry || entry->type_address != vm::MAPPED_PTR_HOST) {
            continue; // pagina no mapeada o no es HOST, ignorar
        }

        // localizar la arena a partir del puntero de host (O(N))
        int arena_id = arena_mgr.find_arena_id_for_ptr(entry->address.ptr_host);
        if (arena_id != -1) {
            arena_mgr.free_arena(arena_id); // liberar la arena del SO
        }

        tlb.clear_tlb_entry(page); // invalidar la entrada TLB de la pagina
    }
}

/**
 * @brief Copia datos desde memoria del host a memoria virtual.
 *
 * Recorre las paginas de destino creandolas si no existen (auto-map RW)
 * y copia @p size bytes de @p src_host byte a byte respetando los limites
 * de pagina.
 *
 * @param dest_vaddr Direccion virtual destino de la copia.
 * @param src_host   Puntero en memoria del host con los datos a copiar.
 * @param size       Numero de bytes a copiar.
 */
void VirtualMemory::vm_to_host_memcpy(uint64_t dest_vaddr, const void *src_host,
                                      size_t size) {
    const uint8_t *src =
        (const uint8_t *)src_host;           // cursor de lectura en el host
    uint64_t vaddr = dest_vaddr & ~0xFFFULL; // primera pagina del rango

    while (size > 0) {
        // resolver el puntero de host para la pagina actual
        void *host_dest = this->tlb.get_real_host_ptr_of_vptr(vaddr);
        if (!host_dest) {
            // pagina no existe: crearla con permisos RW
            this->map(vaddr, 4096, vm::MemPerm::READ | vm::MemPerm::WRITE);
            host_dest =
                this->tlb.get_real_host_ptr_of_vptr(vaddr); // releer tras mapeo
            /* Y comprobar que el remedio funciono.  El nulo estaba PREVISTO
             * -- por eso el `if` --, se intentaba arreglar y no se miraba si
             * se habia arreglado: el `memcpy` de abajo escribia entonces en
             * `nullptr + offset`. */
            if (!host_dest) {
                VGC_CERR << "[VirtualMemory] no se pudo mapear la pagina "
                         << vaddr << " para copiar en ella; se abandona la "
                         << "copia de " << size << " bytes\n";
                return;
            }
        }

        // calcular cuantos bytes caben en lo que resta de la pagina actual
        size_t offset =
            dest_vaddr & 0xFFF;            // desplazamiento dentro de la pagina
        size_t page_avail = 4096 - offset; // bytes disponibles en esta pagina
        size_t copy_size =
            std::min(size, page_avail); // bytes a copiar en esta iteracion

        memcpy((uint8_t *)host_dest + offset, src,
               copy_size); // copiar fragmento

        // avanzar cursores para la siguiente pagina
        src += copy_size;
        size -= copy_size;
        dest_vaddr += copy_size;
        vaddr = dest_vaddr & ~0xFFFULL; // recalcular la pagina actual
    }
}

/**
 * @brief Rellena una region de memoria virtual con un valor de byte.
 *
 * Equivalente a memset() sobre el espacio de direcciones virtual.
 * Crea las paginas que no existan antes de escribir.
 *
 * @param dest_vaddr Direccion virtual de inicio del relleno.
 * @param value      Valor de byte (0-255) a escribir en cada posicion.
 * @param size       Numero de bytes a rellenar.
 */
void VirtualMemory::vm_to_host_memset(uint64_t dest_vaddr, int value,
                                      size_t size) {
    uint64_t vaddr = dest_vaddr & ~0xFFFULL; // primera pagina del rango

    while (size > 0) {
        // resolver el puntero de host para la pagina actual
        void *host_dest = tlb.get_real_host_ptr_of_vptr(vaddr);
        if (!host_dest) {
            // pagina no existe: crearla con permisos RW
            map(vaddr, 4096, vm::MemPerm::READ | vm::MemPerm::WRITE);
            host_dest =
                tlb.get_real_host_ptr_of_vptr(vaddr); // releer tras mapeo
            /* Y comprobar que el remedio funciono.  El nulo estaba PREVISTO
             * -- por eso el `if` --, se intentaba arreglar y no se miraba si
             * se habia arreglado: el `memset` de abajo escribia entonces en
             * `nullptr + offset`. */
            if (!host_dest) {
                VGC_CERR << "[VirtualMemory] no se pudo mapear la pagina "
                         << vaddr << " para rellenarla; se abandona el "
                         << "relleno de " << size << " bytes\n";
                return;
            }
        }

        // calcular cuantos bytes rellenar en esta pagina
        size_t offset =
            dest_vaddr & 0xFFF;            // desplazamiento dentro de la pagina
        size_t page_avail = 4096 - offset; // bytes disponibles en esta pagina
        size_t fill_size =
            std::min(size, page_avail); // bytes a rellenar en esta iteracion

        memset((uint8_t *)host_dest + offset, value,
               fill_size); // rellenar fragmento

        // avanzar cursores para la siguiente pagina
        size -= fill_size;
        dest_vaddr += fill_size;
        vaddr = dest_vaddr & ~0xFFFULL; // recalcular la pagina actual
    }
}

/**
 * @brief Lee @p size bytes desde la memoria virtual a un buffer del host.
 *
 * Gestiona la traduccion TLB y los cruces de pagina automaticamente.
 * En caso de miss (pagina no mapeada) realiza una asignacion perezosa con
 * permsDefault.
 *
 * Optimizacion: cuando el offset dentro de la pagina esta alineado a 16 bytes
 * se activa un fast-path con __builtin_assume_aligned para que el compilador
 * pueda emitir instrucciones SIMD alineadas (movaps/vmovaps).
 *
 * @param vaddr Direccion virtual de inicio de la lectura.
 * @param dst   Buffer del host donde se almacenan los bytes leidos.
 * @param size  Numero de bytes a leer.
 */
void VirtualMemory::read_bytes_slow(uint64_t vaddr, void *dst, size_t size) {
    uint8_t *out =
        static_cast<uint8_t *>(dst); // cursor de escritura en el buffer destino

    while (size > 0) {
        uint64_t page_vaddr =
            vaddr & ~0xFFFULL;            // direccion base de la pagina actual
        size_t offset = vaddr & 0xFFFULL; // offset dentro de la pagina
        size_t chunk = std::min<size_t>(4096 - offset,
                                        size); // bytes a leer en esta iteracion

        uint8_t *base;
        if (__builtin_expect(page_vaddr == cached_page_vaddr, 1)) {
            base = cached_page_host;
        } else {
            tlb::TLBEntryData *entry = tlb.get_entry(vaddr); // consultar el TLB

            // MISS: pagina no mapeada -> asignar perezosamente con los permisos
            // por defecto
            if (!entry || entry->type_address == NONE) {
                void *host_mem = get_ptr_arena(
                    arena_mgr,
                    arena_mgr.create_arena(
                        4096, permsDefault)); // reservar pagina nueva

                ptr_mapped pm{};
                pm.ptr_host = host_mem; // apuntar al bloque recien reservado

                tlb.translate(page_vaddr, MAPPED_PTR_HOST,
                              pm); // registrar traduccion
                entry =
                    tlb.get_entry(vaddr); // releer la entrada tras el registro
            }

            if (entry->type_address != MAPPED_PTR_HOST) {
                VGC_COUT << "Modo de acceso no implementado: "
                         << entry->type_address << VGC_ENDL;
                exit(-1);
            }

            base = static_cast<uint8_t *>(entry->address.ptr_host);
            // Cachear para la proxima iteracion en la misma pagina.
            cached_page_vaddr = page_vaddr;
            cached_page_host = base;
        }

        // FAST-PATH: offset alineado a 16 bytes -> el compilador puede usar
        // SIMD
        if ((offset & 0xF) == 0) {
            uint8_t *aligned =
                (uint8_t *)__builtin_assume_aligned(base + offset, 16);
            memcpy(out, aligned, chunk); // copia potencialmente vectorizada
        } else {
            memcpy(out, base + offset, chunk); // copia estandar sin alineacion
        }

        // avanzar cursores para la siguiente pagina
        vaddr += chunk;
        out += chunk;
        size -= chunk;
    }
}

/**
 * @brief Escribe @p size bytes desde un buffer del host a memoria virtual.
 *
 * Simetrico de read_bytes().  Gestiona cruces de pagina y asignacion
 * perezosa del mismo modo.  El fast-path SIMD tambien se activa cuando
 * el offset esta alineado a 16 bytes.
 *
 * @param vaddr Direccion virtual de inicio de la escritura.
 * @param src   Buffer del host con los datos a escribir.
 * @param size  Numero de bytes a escribir.
 */
void VirtualMemory::write_bytes_slow(uint64_t vaddr, const void *src,
                                     size_t size) {
    const uint8_t *in = static_cast<const uint8_t *>(
        src); // cursor de lectura en el buffer fuente

    while (size > 0) {
        uint64_t page_vaddr =
            vaddr & ~0xFFFULL;            // direccion base de la pagina actual
        size_t offset = vaddr & 0xFFFULL; // offset dentro de la pagina
        size_t chunk = std::min<size_t>(
            4096 - offset, size); // bytes a escribir en esta iteracion

        uint8_t *base;
        if (__builtin_expect(page_vaddr == cached_page_vaddr, 1)) {
            base = cached_page_host;
        } else {
            tlb::TLBEntryData *entry = tlb.get_entry(vaddr); // consultar el TLB

            // MISS: pagina no mapeada -> asignar perezosamente con los permisos
            // por defecto
            if (!entry || entry->type_address == NONE) {
                void *host_mem = get_ptr_arena(
                    arena_mgr,
                    arena_mgr.create_arena(
                        4096, permsDefault)); // reservar pagina nueva

                ptr_mapped pm{};
                pm.ptr_host = host_mem; // apuntar al bloque recien reservado

                tlb.translate(page_vaddr, MAPPED_PTR_HOST,
                              pm); // registrar traduccion
                entry =
                    tlb.get_entry(vaddr); // releer la entrada tras el registro
            }

            if (entry->type_address != MAPPED_PTR_HOST) {
                VGC_COUT << "Modo de acceso no implementado: "
                         << entry->type_address << VGC_ENDL;
                exit(-1);
            }

            base = static_cast<uint8_t *>(entry->address.ptr_host);
            cached_page_vaddr = page_vaddr;
            cached_page_host = base;
        }

        // FAST-PATH: offset alineado a 16 bytes -> el compilador puede usar
        // SIMD
        if ((offset & 0xF) == 0) {
            uint8_t *aligned =
                (uint8_t *)__builtin_assume_aligned(base + offset, 16);
            memcpy(aligned, in, chunk); // escritura potencialmente vectorizada
        } else {
            memcpy(base + offset, in,
                   chunk); // escritura estandar sin alineacion
        }

        // avanzar cursores para la siguiente pagina
        vaddr += chunk;
        in += chunk;
        size -= chunk;
    }
}

/**
 * @brief Escribe un byte en la direccion virtual indicada.
 * @param vaddr Direccion virtual destino.
 * @param value Byte a escribir.
 */
void VirtualMemory::write_u8(uint64_t vaddr, uint8_t value) {
    write_bytes(
        vaddr, &value,
        sizeof(value)); // delegar en write_bytes para manejar TLB y paginas
}

/**
 * @brief Escribe dos bytes (little-endian) en la direccion virtual indicada.
 * @param vaddr Direccion virtual destino.
 * @param value Valor de 16 bits a escribir.
 */
void VirtualMemory::write_u16(uint64_t vaddr, uint16_t value) {
    write_bytes(
        vaddr, &value,
        sizeof(value)); // delegar en write_bytes para manejar TLB y paginas
}

/**
 * @brief Escribe cuatro bytes (little-endian) en la direccion virtual indicada.
 * @param vaddr Direccion virtual destino.
 * @param value Valor de 32 bits a escribir.
 */
void VirtualMemory::write_u32(uint64_t vaddr, uint32_t value) {
    write_bytes(
        vaddr, &value,
        sizeof(value)); // delegar en write_bytes para manejar TLB y paginas
}

/**
 * @brief Escribe ocho bytes (little-endian) en la direccion virtual indicada.
 * @param vaddr Direccion virtual destino.
 * @param value Valor de 64 bits a escribir.
 */
void VirtualMemory::write_u64(uint64_t vaddr, uint64_t value) {
    write_bytes(
        vaddr, &value,
        sizeof(value)); // delegar en write_bytes para manejar TLB y paginas
}

/**
 * @brief Lee un byte desde la direccion virtual indicada.
 * @param vaddr Direccion virtual fuente.
 * @return      Byte leido.
 */
uint8_t VirtualMemory::read_u8(uint64_t vaddr) {
    uint8_t x;
    read_bytes(vaddr, &x,
               sizeof(x)); // delegar en read_bytes para manejar TLB y paginas
    return x;
}

/**
 * @brief Lee dos bytes (little-endian) desde la direccion virtual indicada.
 * @param vaddr Direccion virtual fuente.
 * @return      Valor de 16 bits leido.
 */
uint16_t VirtualMemory::read_u16(uint64_t vaddr) {
    uint16_t x;
    read_bytes(vaddr, &x,
               sizeof(x)); // delegar en read_bytes para manejar TLB y paginas
    return x;
}

/**
 * @brief Lee cuatro bytes (little-endian) desde la direccion virtual indicada.
 * @param vaddr Direccion virtual fuente.
 * @return      Valor de 32 bits leido.
 */
uint32_t VirtualMemory::read_u32(uint64_t vaddr) {
    uint32_t x;
    read_bytes(vaddr, &x,
               sizeof(x)); // delegar en read_bytes para manejar TLB y paginas
    return x;
}

/**
 * @brief Lee ocho bytes (little-endian) desde la direccion virtual indicada.
 * @param vaddr Direccion virtual fuente.
 * @return      Valor de 64 bits leido.
 */
uint64_t VirtualMemory::read_u64(uint64_t vaddr) {
    uint64_t x;
    read_bytes(vaddr, &x,
               sizeof(x)); // delegar en read_bytes para manejar TLB y paginas
    return x;
}

} // namespace vm
