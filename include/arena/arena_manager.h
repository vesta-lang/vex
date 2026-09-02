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
 * @file arena_manager.h                                                       \
 * @brief Declaracion del gestor global de arenas de memoria de VestaVM.       \
 *                                                                             \
 * Declara @c ArenaManager: pool compartido de bloques de memoria mapeados,    \
 * asignacion con permisos READ/WRITE/EXEC y liberacion masiva mediante        \
 * @c free_all().  Hereda de TLB para traduccion de direcciones.               \
 */                                                                            \
#ifndef ARENA_MANAGER_H
#define ARENA_MANAGER_H

#include "arena.h"
#include "util/oa_u64_map.h"

namespace vm {

struct Arena; // declaracion adelantada para evitar dependencias circulares

/**
 * @class ArenaManager
 * @brief Gestor centralizado de bloques de memoria (arenas).
 *
 * ArenaManager mantiene un catalogo de bloques de memoria identificados
 * por IDs unicos de 64 bits.  Cada bloque es una Arena reservada mediante
 * allocate_memory() con permisos configurables (READ / WRITE / EXEC).
 *
 * Ciclo de vida tipico:
 *   1. create_arena()  -- reserva memoria y registra la arena.
 *   2. get_arena()     -- consulta el bloque sin transferir propiedad.
 *   3. free_arena()    -- libera un bloque concreto.
 *   4. free_all()      -- libera todos los bloques al destruir el manager.
 *
 * TLB hereda de esta clase para poder crear y liberar paginas directamente
 * desde el subsistema de traduccion de direcciones.
 */
class ArenaManager {
  public:
    /**
     * @brief Inicializa el manager con contadores a cero y mapa vacio.
     */
    ArenaManager();

    /**
     * @brief Destructor: libera todos los bloques pendientes llamando a
     * free_all().
     */
    ~ArenaManager();

    /**
     * @brief Reserva un nuevo bloque de memoria y lo registra en el catalogo.
     *
     * El tamanyo se redondea internamente al multiplo de pagina (4 KiB).
     * Las paginas no tienen que ser contiguas entre distintas arenas.
     *
     * @param size  Tamanyo deseado en bytes.
     * @param perms Permisos de acceso (READ / WRITE / EXEC o combinaciones).
     * @return      ID unico del bloque creado, o 0 si la asignacion falla.
     *
     * @note El ID 0 se usa como valor de error; la primera arena valida
     *       tiene ID 0 solo si el constructor no incremento el contador,
     *       por lo que create_arena() devuelve 0 unicamente ante fallo.
     */
    uint64_t create_arena(size_t size, MemPerm perms);

    /**
     * @brief Libera el bloque identificado por @p id.
     *
     * Resta su tamanyo de total_allocated_bytes_, llama a free_memory()
     * y elimina la entrada del mapa.
     *
     * @param id ID del bloque a liberar.
     * @return   true si el bloque existia y fue liberado; false si no existia.
     */
    bool free_arena(uint64_t id);

    /**
     * @brief Devuelve un puntero de solo lectura a la estructura Arena.
     *
     * No transfiere propiedad.  El puntero puede quedar invalidado
     * si se llama a free_arena() o free_all() posteriormente.
     *
     * @param id ID del bloque a consultar.
     * @return   Puntero constante a la Arena, o nullptr si el ID no existe.
     */
    const Arena *get_arena(uint64_t id) const;

    /**
     * @brief Libera todos los bloques registrados en el catalogo.
     *
     * Itera sobre una copia de las claves para evitar invalidar el iterador
     * mientras se libera.  Tras la llamada el mapa queda vacio y
     * total_allocated_bytes_ vale cero.
     */
    void free_all();

    /**
     * @brief Numero de bloques vivos en el catalogo.
     * @return Cuantas arenas hay reservadas ahora mismo.
     *
     * Observabilidad: el coste de la memoria no es solo cuantos BYTES se
     * reservan, sino en CUANTAS reservas -- cada una es una llamada al sistema
     * y, en Windows, consume 64 KiB de espacio de direcciones aunque pida 4.
     * Sin esta cifra, medio giga en 120.000 reservas y medio giga en 8 se ven
     * exactamente igual.
     */
    size_t arena_count() const noexcept { return arenas.size(); }

    /**
     * @brief Bytes totales reservados por las arenas vivas.
     */
    size_t total_allocated_bytes() const noexcept {
        return total_allocated_bytes_;
    }

    /**
     * @brief Busca el ID de la arena cuyo puntero de host coincide con @p
     * host_ptr.
     *
     * Busqueda lineal O(N) sobre el mapa.  Solo debe usarse en rutas no
     * criticas (p.ej. durante unmap); no es apta para el hot path de ejecucion.
     *
     * @param host_ptr Puntero real del proceso a localizar.
     * @return         ID de la arena si se encuentra, -1 en caso contrario.
     *
     * @todo Anadir cache o indice inverso para reducir la complejidad a O(1).
     */
    int find_arena_id_for_ptr(void *host_ptr);

    size_t total_allocated_bytes_; ///< Suma acumulada de bytes reservados por
                                   ///< todas las arenas activas

    util::OAU64Map<Arena>
        arenas; ///< Catalogo de arenas indexado por ID (open-addressing:
                ///< cache-friendly + freestanding, sin std::unordered_map)

  protected:
    // Accessible por clases derivadas (p.ej. TLB) para crear arenas internas
    uint64_t next_id; ///< Contador monotonico para generar IDs unicos
};

/**
 * @brief Devuelve el puntero de inicio de una arena a partir de su ID.
 *
 * Funcion de conveniencia que combina get_arena() y acceso al campo ptr.
 * No verifica si @p id_arena existe; un ID invalido causara comportamiento
 * indefinido al desreferenciar nullptr.
 *
 * @param arena_mgr Manager que gestiona la arena.
 * @param id_arena  ID de la arena a consultar.
 * @return          Puntero al primer byte del bloque.
 */
inline void *get_ptr_arena(const ArenaManager &arena_mgr,
                           const uint64_t id_arena) {
    const Arena *arena =
        arena_mgr.get_arena(id_arena); // buscar la arena por ID
    return arena->ptr;                 // devolver puntero al bloque
}

} // namespace vm

#endif // ARENA_MANAGER_H
