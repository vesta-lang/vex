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
 * @file debug_info.h
 * @brief Estructuras y clase de gestion de informacion de depuracion para
 * VestaVM.
 *
 * Define el formato binario de la seccion de depuracion del archivo VELB y la
 * clase DebugInfo que permite consultar la informacion durante la ejecucion.
 *
 * La seccion de depuracion soporta tres niveles de granularidad:
 *
 *   Nivel 1 (minimo) -- mapeo bytecode_offset -> (archivo_fuente, linea)
 *   Nivel 2 (medio)  -- nivel 1 + tabla de variables locales
 *                       (nombre, offset_en_pila, tipo, alcance)
 *   Nivel 3 (maximo) -- nivel 2 + columna de origen, scopes con nombre y
 *                       anidamiento, soporte para stack traces completos.
 *
 * Formato binario de la seccion de depuracion (en el archivo .velb):
 * @verbatim
 *   [DebugSectionHeader  (24 bytes)]
 *   [DebugLineEntry[]    (line_count * 12 bytes para nivel 1)]
 *          O
 *   [DebugLineEntry3[]   (line_count * 16 bytes para nivel 3)]
 *   [DebugVarEntry[]     (var_count  * 20 bytes, solo nivel >= 2)]
 *   [DebugScopeEntry[]   (scope_count * 16 bytes, solo nivel 3)]
 *   [cadenas de depuracion (blob de bytes terminados en 0)]
 * @endverbatim
 *
 * El magic DVBG (0x47425644 en LE) permite validar que la seccion es correcta
 * antes de intentar interpretarla.
 */

#ifndef DEBUG_INFO_H
#define DEBUG_INFO_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace debug {

// -------------------------------------------------------------------------
//  Constantes del formato
// -------------------------------------------------------------------------

/** @brief Magic number de la seccion de depuracion ("DVBG" en little-endian).
 */
static constexpr uint32_t DEBUG_SECTION_MAGIC = 0x47425644u;

/** @brief Version del formato de la seccion de depuracion. */
static constexpr uint8_t DEBUG_FORMAT_VERSION = 1u;

/** @brief Nivel minimo: solo mapeo bytecode -> (archivo, linea). */
static constexpr uint8_t DEBUG_LEVEL_LINES = 1u;

/** @brief Nivel medio: nivel 1 + variables locales. */
static constexpr uint8_t DEBUG_LEVEL_VARS = 2u;

/** @brief Nivel maximo: nivel 2 + columna, scopes, stack traces completos. */
static constexpr uint8_t DEBUG_LEVEL_FULL = 3u;

// -------------------------------------------------------------------------
//  Flags para DebugVarEntry::var_flags
// -------------------------------------------------------------------------
static constexpr uint8_t VAR_FLAG_LOCAL = 0u; ///< variable local
static constexpr uint8_t VAR_FLAG_PARAM = 1u; ///< parametro de funcion
static constexpr uint8_t VAR_FLAG_CAPTURE =
    2u; ///< variable capturada (closure)

// -------------------------------------------------------------------------
//  Tipos de variable para DebugVarEntry::type_kind
// -------------------------------------------------------------------------
static constexpr uint8_t VAR_TYPE_INT = 0u;    ///< entero (int64)
static constexpr uint8_t VAR_TYPE_FLOAT = 1u;  ///< flotante (double)
static constexpr uint8_t VAR_TYPE_OBJECT = 2u; ///< objeto GC (GcHandle)
static constexpr uint8_t VAR_TYPE_PTR = 3u;    ///< puntero raw

// -------------------------------------------------------------------------
//  DebugSectionHeader - encabezado de la seccion de depuracion (24 bytes)
// -------------------------------------------------------------------------

/* Clang con el ABI de MSVC no define `__GNUC__`, y sin esta rama `DEBUG_PACKED`
 * se quedaba VACIO: las structs de abajo dejaban de ir empaquetadas y el layout
 * binario de la seccion de depuracion cambiaba sin un solo aviso.  El atributo
 * lo acepta clang con cualquier ABI. */
#if defined(__clang__) || defined(__GNUC__)
#define DEBUG_PACKED __attribute__((packed))
#else
#define DEBUG_PACKED
#endif

/**
 * @brief Encabezado de la seccion de depuracion del archivo .velb.
 *
 * Precede a todas las tablas de entradas de depuracion.  El campo magic
 * permite detectar corrupcion o una seccion invalida antes de leer las tablas.
 */
struct DEBUG_PACKED DebugSectionHeader {
    uint32_t magic;       ///< debe ser DEBUG_SECTION_MAGIC (0x47425644)
    uint8_t version;      ///< version del formato (actualmente 1)
    uint8_t level;        ///< nivel de granularidad (1, 2 o 3)
    uint16_t _pad;        ///< relleno de alineacion (debe ser 0)
    uint32_t line_count;  ///< numero de entradas de linea
    uint32_t var_count;   ///< numero de entradas de variable (nivel >= 2)
    uint32_t scope_count; ///< numero de entradas de scope (nivel 3)
    uint32_t
        strings_size; ///< tamano del blob de cadenas de depuracion en bytes
};

// -------------------------------------------------------------------------
//  DebugLineEntry - mapeo bytecode -> archivo y linea (nivel 1, 12 bytes)
// -------------------------------------------------------------------------

/**
 * @brief Entrada de informacion de linea para el nivel 1.
 *
 * Mapea un offset de bytecode a un numero de linea en el archivo fuente.
 * El nombre del archivo se obtiene indexando el blob de cadenas con
 * file_offset.
 *
 * Para nivel 3 usar DebugLineEntry3 que incluye tambien la columna.
 */
struct DEBUG_PACKED DebugLineEntry {
    uint32_t bytecode_offset; ///< offset en el bytecode de la instruccion
    uint32_t line_number;     ///< numero de linea en el archivo fuente (base 1)
    uint32_t
        file_offset; ///< offset al nombre del archivo en el blob de strings
};

// -------------------------------------------------------------------------
//  DebugLineEntry3 - mapeo bytecode -> archivo, linea y columna (nivel 3, 16
//  bytes)
// -------------------------------------------------------------------------

/**
 * @brief Entrada de informacion de linea y columna para el nivel 3.
 *
 * Extension de DebugLineEntry que incluye la columna de origen.
 */
struct DEBUG_PACKED DebugLineEntry3 {
    uint32_t bytecode_offset; ///< offset en el bytecode de la instruccion
    uint32_t line_number;     ///< numero de linea en el archivo fuente (base 1)
    uint32_t
        file_offset; ///< offset al nombre del archivo en el blob de strings
    uint16_t column; ///< columna de origen (base 1; 0 = desconocida)
    uint16_t _pad;   ///< relleno de alineacion
};

// -------------------------------------------------------------------------
//  DebugVarEntry - variable local o parametro (nivel >= 2, 20 bytes)
// -------------------------------------------------------------------------

/**
 * @brief Entrada de informacion de variable local o parametro de funcion.
 *
 * Describe una variable dentro de un rango de bytecode (su alcance visible).
 * El nombre se obtiene indexando el blob de cadenas con name_offset.
 */
struct DEBUG_PACKED DebugVarEntry {
    uint32_t
        name_offset; ///< offset al nombre de la variable en el blob de strings
    uint32_t scope_start; ///< offset de bytecode donde la variable es visible
    uint32_t scope_end;   ///< offset de bytecode donde deja de ser visible
    int16_t stack_offset; ///< offset en pila desde RBP (puede ser negativo)
    uint8_t type_kind;    ///< tipo de la variable (VAR_TYPE_*)
    uint8_t var_flags;    ///< tipo de variable (VAR_FLAG_*)
    uint32_t scope_idx;   ///< indice del scope padre (nivel 3) o 0xFFFFFFFF
};

// -------------------------------------------------------------------------
//  DebugScopeEntry - scope de funcion o bloque (nivel 3, 16 bytes)
// -------------------------------------------------------------------------

/**
 * @brief Entrada de scope (funcion, bloque, lambda) para el nivel 3.
 *
 * Permite reconstruir el arbol de llamadas para stack traces con nombres
 * de funcion y anidamiento de bloques.
 */
struct DEBUG_PACKED DebugScopeEntry {
    uint32_t start_offset; ///< offset de bytecode donde comienza el scope
    uint32_t end_offset;   ///< offset de bytecode donde termina el scope
    uint32_t name_offset;  ///< offset al nombre del scope en el blob de strings
    uint32_t parent_idx;   ///< indice del scope padre (0xFFFFFFFF = raiz)
};

// -------------------------------------------------------------------------
//  DebugInfo - clase de consulta de informacion de depuracion en tiempo de
//  ejecucion
// -------------------------------------------------------------------------

/**
 * @brief Resultado de una consulta de informacion de linea.
 *
 * Devuelto por DebugInfo::lookup_line() para un offset de bytecode dado.
 */
struct LineInfo {
    const char
        *file;       ///< nombre del archivo fuente (puntero al blob de strings)
    uint32_t line;   ///< numero de linea (base 1)
    uint16_t column; ///< columna (base 1; 0 = no disponible en nivel 1/2)
    bool found;      ///< false si no hay informacion para ese offset
};

/**
 * @brief Resultado de consulta de variable local.
 *
 * Devuelto por DebugInfo::lookup_vars() para un offset de bytecode y un
 * offset de pila dados.
 */
struct VarInfo {
    const char *name;     ///< nombre de la variable
    int16_t stack_offset; ///< offset en pila desde RBP
    uint8_t type_kind;    ///< tipo (VAR_TYPE_*)
    uint8_t var_flags;    ///< rol (VAR_FLAG_*)
};

/**
 * @brief Clase de consulta de informacion de depuracion cargada de un .velb.
 *
 * Se construye con el blob de bytes de la seccion de depuracion.  Una vez
 * construida, permite consultas O(log n) de linea/archivo/variable por
 * offset de bytecode.
 *
 * Uso tipico (en el loader):
 * @code
 *   DebugInfo di(raw_bytes, size);
 *   auto info = di.lookup_line(current_pc - base_addr);
 *   if (info.found)
 *       print("en %s:%u", info.file, info.line);
 * @endcode
 */
class DebugInfo {
  public:
    /**
     * @brief Construye DebugInfo a partir del blob de la seccion de depuracion.
     *
     * @param data  Puntero al inicio de la seccion (comienza con
     * DebugSectionHeader).
     * @param size  Tamano en bytes de la seccion.
     */
    DebugInfo(const uint8_t *data, size_t size);

    /**
     * @brief Busca la informacion de linea para el offset de bytecode dado.
     *
     * Realiza busqueda binaria en la tabla de lineas para encontrar la entrada
     * cuyo bytecode_offset sea menor o igual al offset buscado.
     *
     * @param bytecode_offset Offset dentro del bytecode del ejecutable.
     * @return LineInfo con la informacion encontrada; found=false si no hay
     * datos.
     */
    LineInfo lookup_line(uint32_t bytecode_offset) const;

    /**
     * @brief Devuelve las variables visibles en el offset de bytecode dado.
     *
     * Solo disponible para nivel >= 2.  Devuelve todas las entradas de variable
     * cuyo rango [scope_start, scope_end) contiene el offset dado.
     *
     * @param bytecode_offset Offset dentro del bytecode del ejecutable.
     * @return Vector de VarInfo con las variables visibles.
     */
    std::vector<VarInfo> lookup_vars(uint32_t bytecode_offset) const;

    /**
     * @brief Traduce (file, line) -> bytecode_offset (busqueda inversa).
     *
     * Util para resolver breakpoints emitidos por el cliente como
     * "file.vx:42" a un offset concreto que el server pueda usar
     * con SET_BREAK.  El match del file es por sufijo: "foo.vx"
     * matchea cualquier path que termine en "foo.vx".  Si
     * @p line_target es 0 devuelve el primer offset del file.  Si
     * la linea exacta no esta en la tabla, devuelve el offset de
     * la siguiente linea conocida (>= target).  Devuelve UINT32_MAX
     * si no hay match.
     *
     * @param file_target Nombre o sufijo del archivo fuente.
     * @param line_target Numero de linea (1-based).  0 = primera linea.
     * @return bytecode_offset o UINT32_MAX si no se encuentra.
     */
    uint32_t lookup_offset_for_line(const std::string &file_target,
                                    uint32_t line_target) const;

    /**
     * @brief Devuelve el nombre del scope que contiene el offset de bytecode.
     *
     * Solo disponible para nivel 3.  Devuelve el nombre del scope mas interno
     * (funcion o bloque) que contiene el offset dado.
     *
     * @param bytecode_offset Offset dentro del bytecode del ejecutable.
     * @return Nombre del scope, o cadena vacia si no hay datos o nivel < 3.
     */
    std::string lookup_scope(uint32_t bytecode_offset) const;

    /** @brief Devuelve el nivel de granularidad de la informacion cargada. */
    uint8_t level() const { return level_; }

    /** @brief Devuelve true si la informacion de depuracion es valida. */
    bool valid() const { return valid_; }

  private:
    bool valid_ = false; ///< true si el magic y version son correctos
    uint8_t level_ = 0;  ///< nivel de granularidad cargado

    // Tablas en memoria (apuntan dentro de raw_)
    const DebugLineEntry *lines1_ = nullptr; ///< tabla de nivel 1 (12B/entrada)
    const DebugLineEntry3 *lines3_ =
        nullptr;                          ///< tabla de nivel 3 (16B/entrada)
    const DebugVarEntry *vars_ = nullptr; ///< tabla de variables (nivel >= 2)
    const DebugScopeEntry *scopes_ = nullptr; ///< tabla de scopes (nivel 3)
    const char *strings_ = nullptr;           ///< blob de cadenas de depuracion

    uint32_t line_count_ = 0;  ///< numero de entradas de linea
    uint32_t var_count_ = 0;   ///< numero de entradas de variable
    uint32_t scope_count_ = 0; ///< numero de entradas de scope

    std::vector<uint8_t> raw_; ///< copia del blob de la seccion (propietario)
};

} // namespace debug

#endif // DEBUG_INFO_H
