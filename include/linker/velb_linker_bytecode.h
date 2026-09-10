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
 * @file velb_linker_bytecode.h
 * @brief Definicion del formato binario VELB/VELA y la clase Linker de VestaVM.
 *
 * Contiene:
 *  - Tipos y estructuras del formato de archivo @b VELB (VestaLangBinary):
 *      Header, tabla de secciones, tabla de espacios de direcciones, tablas de
 *      labels e importaciones.
 *  - Tipos y estructuras del formato de libreria estatica @b VELA.
 *  - Clase @c Linker que combina multiples modulos objeto en un ejecutable
 * final.
 *  - Estructuras de reporte (@c LinkerReport, @c LinkerError, @c
 * LinkerWarning).
 *
 * Formato VELB (layout del header, 120 bytes):
 * @verbatim
 *   Offset  Size  Campo
 *   ------  ----  -----
 *      0      4   magic              ("VELB" en LE / "BLEV" en BE)
 *      4      4   format_v           (version del formato)
 *      8      4   max_v              (version maxima de VM compatible)
 *     12      4   min_v              (version minima de VM compatible)
 *     16      8   checksum           (checksum del ejecutable)
 *     24      8   flags              (meta-informacion del ejecutable)
 *     32      8   timestamp          (marca de tiempo de compilacion)
 *     40      4   arch               (arquitectura objetivo)
 *     44      4   count              (numero de secciones)
 *     48      8   table_offset       (offset a la tabla de secciones)
 *     56      8   n_spaces           (numero de espacios de direcciones)
 *     64      8   offset_section_strings
 *     72      8   start_pc           (PC inicial del programa)
 *     80      8   offset_import_table
 *     88      8   offset_label_table
 *     96      4   size_import_table
 *    100      4   size_label_table
 *    104      8   offset_debug_section (0 = sin info de depuracion)
 *    112      4   size_debug_section
 *    116      1   debug_level        (0=ninguno 1=lineas 2=+vars 3=+scopes)
 *    117      3   _debug_pad         (reservado, debe ser 0)
 * @endverbatim
 *
 * @note Todas las estructuras usan @c __attribute__((packed)) / @c pragma
 * pack(push,1) para garantizar un layout binario sin padding y seguro para
 * serializar.
 */

#ifndef VELB_LINKER_BYTECODE_H
#define VELB_LINKER_BYTECODE_H

/*
 * debemos usar "pack" para evitar el padding adicional de los compiladores
 * y que sea una estructura segura para serializar.
 */
/* Clang acepta `__attribute__((packed))` con CUALQUIER ABI, tambien con el de
 * MSVC, asi que va PRIMERO.  Importa que sea el atributo y no el `pragma pack`:
 * el atributo empaqueta POR ESTRUCTURA y el pragma por REGION, y en este
 * fichero conviven 11 structs que deben ir empaquetadas con 20 que NO -- un
 * pragma abierto arriba las empaquetaria todas, y ademas se filtraria a cada
 * cabecera incluida despues.
 *
 * La rama de `_MSC_VER` se deja para `cl.exe`, que no tiene atributo por
 * estructura.  No esta verificada: aqui se compila con GCC y con Clang. */
#if defined(__clang__) || defined(__GNUC__)
#define PACKED __attribute__((packed))
#elif defined(_MSC_VER)
#pragma pack(push, 1)
#define PACKED
#else
#define PACKED
#endif

#include <stdint.h>

#include "emmit/bytewriter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAGIC_NUMBER_VELB 0x424C4556
// bumped to 0x2 cuando se añadio la tabla de relocations al header.
// Loaders viejos (v1) no entenderan los campos nuevos; no es backward
// compatible.  Las .velb existentes deben recompilarse.
#define VERSION_VELB 0x4
#define VERSION_VELA 0x1

/**
 * A traves del numero magico, se puede conocer el endian de la maquina que
 * genero el bytecode. EN?n caso de ser little?endian (LE) en el ejecutable
 * pondra "VELB", pero en caso de ser big-endian (BE), pondra BLEV
 */
typedef union velb_magic {
    uint32_t firma; // 0x424C4556 == "VELB" en LE
    uint8_t firma_byte[4];
} velb_magic;

/**
 * ``4 bytes`` para la version del formato.
 */
typedef uint32_t velb_version_format;

/**
 * ``4 bytes`` con la maxima version compatible en la
 * que el codigo puede ser ejecutado en una VM.
 */
typedef uint32_t max_vm_version;

/**
 *  ``4 bytes`` con la minima version
 *  compatible en la que el codigo puede ser ejecutado en una VM.
 */
typedef uint32_t min_vm_version;

/**
 * ``8 bytes`` para indicar un checksum del codigo, sino
 * coincide, no se ejecuta.
 */
typedef uint64_t velb_checksum;

/**
 * para indicar caracteristicas del ejecutable
 * (meta-informacion adicional del ejecutable).
 */
typedef uint64_t velb_flags;

/**
 * ``8 bytes`` de marca de tiempo para indicar la fecha de compilacion.
 */
typedef uint64_t build_timestamp;

/**
 * ``4 bytes`` para indicar la
 * arquitectura en la que se realizo la compilacion del ejecutable.
 */
typedef uint32_t target_arch;

/**
 * ``4 bytes`` para el numero de secciones en la tabla de secciones.
 */
typedef uint32_t section_count;

/**
 * ``8 bytes`` de desplazamiento respecto a la
 * direccion base para indicar la tabla de secciones.
 */
typedef uint64_t section_table_offset;

/**
 * 8 bytes para indicar la cantidad de espacio de
 * direcciones de la tabla que viene a continuacion.
 */
typedef uint64_t number_spaces_address;

typedef struct PACKED range_memory {
    uint64_t address_init = 0;
    uint64_t address_final = 0;
} range_memory;

typedef struct PACKED table_spaces_address {
    range_memory address{}; // 16 bytes

    // contiene el offset a la tabla de strings,
    // en caso de estar el ejecutable cargado en la VM,
    // este campo contendra la direccion virtual con el offset
    // aplicado.
    uint64_t offset_section_strings = 0;

    /**
     * Offset al bytecode en el archivo. Al estar las secciones de forma lineal
     * y continua, se puede averiguar donde reside cada seccion en el bytecode
     * usando las direcciones virtuales de estas: space =
     * table_spaces_address[0] file_offset_section = space.offset_bytecode + (
     *           sec.address_init - space.range.address_init
     *      )
     * El computo para obtener el offset de la seccion es restar las direcciones
     * virtuales de inicio de la seccion y del espacio de direcciones, esto nos
     * dara el offset plano al que si sumamos donde esta el byte code(offset del
     * bytecode) nos dira donde inicia la seccion.
     */
    uint64_t offset_bytecode = 0;
} table_spaces_address;

typedef struct PACKED HeaderVELB {
    velb_magic magic = {MAGIC_NUMBER_VELB};      // 4, 4
    velb_version_format format_v = VERSION_VELB; // 4, 8

    max_vm_version max_v = 0; // 4, 12
    min_vm_version min_v = 0; // 4, 16

    velb_checksum checksum = 0; // 8, 24

    velb_flags flags = 0;          // 8, 32
    build_timestamp timestamp = 0; // 8, 40
    target_arch arch = 0;          // 4, 44

    // cantidad de secciones en la tabla de secciones.
    section_count count = 0; // 4, 48

    // offset a la tabla de secciones // 8, 56 vector<section_range_memory>
    section_table_offset table_offset = 0;

    // cantidad de espacios de direcciones
    number_spaces_address n_spaces = 0; // 8, 64

    // seccion con cadenas espaciales que pone el linker.
    // "code\0data\0stack\0main\0foo\0bar\0"
    uint64_t offset_section_strings = 0; // 8, 72
    uint64_t start_pc = 0;               // 8, 80

    // ofset a la tabla de importacion
    uint64_t offset_import_table = 0; // 8, 88 // vector<entry_import_table*>

    // ofset a la tabla de labels
    uint64_t offset_label_table = 0; // 8, 96 // vector<entry_label_table*>

    /**
     * Cantidad de entradas de la tabla de importacion
     */
    uint32_t size_import_table = 0;

    /**
     * cantidad de entradas en la tabla de etiquetas.
     */
    uint32_t size_label_table = 0;

    /**
     * Offset desde el inicio del archivo a la seccion de informacion de
     * depuracion. El valor 0 indica que el ejecutable no contiene informacion
     * de depuracion. La seccion comienza con el magic 0x47425644 ("DVBG") para
     * validacion.
     */
    uint64_t offset_debug_section = 0; // 8, offset 104

    /**
     * Tamano en bytes de la seccion de depuracion completa.
     * Incluye el encabezado DebugSectionHeader, todas las entradas y el blob de
     * cadenas.
     */
    uint32_t size_debug_section = 0; // 4, offset 112

    /**
     * Nivel de granularidad de la informacion de depuracion generada.
     *   0 = sin informacion (offset_debug_section debe ser 0)
     *   1 = solo mapeo bytecode -> (archivo, linea)
     *   2 = nivel 1 + tabla de variables locales con nombre y offset en pila
     *   3 = nivel 2 + columna, scopes con nombre y rango, soporte completo
     */
    uint8_t debug_level = 0; // 1, offset 116

    uint8_t _debug_pad[3] = {}; // 3, offset 117 (reservado, debe ser 0)

    /**
     * @brief Offset al inicio de la tabla de relocations dentro del .velb.
     *
     * Cada entry registra un slot de bytecode que contiene una direccion
     * absoluta (e.g. resultado de @c @Absolute("code.foo")).  Permite al
     * loader (`load_module_dynamic`) reescribir esos slots cuando un modulo
     * se carga en una VA distinta de la original (rebase transparente sin
     * heuristics ni flags de compilacion).  El valor 0 indica que el .velb
     * no contiene tabla de relocations (build viejo o sin relocations
     * resolubles).
     */
    uint64_t offset_reloc_table = 0; // 8, offset 120

    /**
     * @brief Numero de entries en la tabla de relocations.
     */
    uint32_t size_reloc_table = 0; // 4, offset 128

    /**
     * @brief Opcion W: offset al inicio de la seccion @c @ir dentro del
     *        .velb.  Esta seccion contiene SSA IR serializado de las
     *        funciones para JIT compile-time.
     *
     * Layout de la seccion:
     *   +0  [4]  magic "VEIR"
     *   +4  [2]  version u16
     *   +6  [2]  reserved u16
     *   +8  [4]  function_count
     *   +12 [..] IrFunctions serializadas (back-to-back)
     *
     * El valor 0 indica que el .velb no contiene IR (build sin JIT,
     * solo bytecode interpretado).  VERSION_VELB es 0x3 cuando se
     * introduce este campo; archivos 0x2 con _reloc_pad zero-init
     * continuan funcionando si se actualiza el version check (ya que
     * leen 0 en este campo = no IR).
     */
    uint64_t offset_ir_section = 0; // 8, offset 132

    /**
     * @brief Opcion W: tamano en bytes de la seccion @c @ir.
     */
    uint32_t size_ir_section = 0; // 4, offset 140

    /**
     * @brief  E.1: offset al inicio de la seccion @c VSMP dentro del
     *        .velb.  Contiene los stackmaps PRECISOS del interprete (por
     *        cada safepoint, las ubicaciones GC vivas) para el GC preciso.
     *
     * Layout de la seccion:
     *   +0  [4]  magic "VSMP"
     *   +4  [2]  version u16
     *   +6  [2]  reserved u16
     *   +8  [4]  entry_count
     *   +12 [..] entradas: pc_offset u32 + slot_count u16 +
     *            slot_count * { location u8, gc_kind u8 }
     *
     * El valor 0 indica que el .velb no lleva stackmaps precisos (build
     * sin --vx-emit-stackmaps o .vel sin safepoints).  En ese caso el GC
     * del interprete cae al scan conservador.  VERSION_VELB es 0x4 cuando
     * se introduce este campo.
     */
    uint64_t offset_stackmap_section = 0; // 8, offset 144

    /**
     * @brief  E.1: tamano en bytes de la seccion @c VSMP.
     */
    uint32_t size_stackmap_section = 0; // 4, offset 152

    /**
     * @brief Relleno para que el header serializado siga siendo multiplo de
     *        16 bytes (156 -> 160).  Necesario porque
     *        @c compute_sections_base_offset usa
     *        @c sizeof(HeaderVELB) - sizeof(ptr) sin re-alinear; si el header
     *        no fuera 16-aligned, la tabla de espacios quedaria desfasada 4
     *        bytes respecto a su posicion real en el archivo.
     */
    uint32_t _stackmap_pad = 0; // 4, offset 156 (reservado, debe ser 0)

    table_spaces_address *address_spaces =
        nullptr; // tabla de espacios de direcciones (NO se serializa)
} HeaderVELB;

/**
 * Datos de entrada
 */
typedef struct PACKED entry_label_table {
    /**
     * Offset a la tabla string
     */
    uint32_t offset_table_string;

    /**
     * offset del bytecode en el archivo.
     */
    uint32_t offset_bytecode;

    /**
     * Indice de la seccion a la que pertecene.
     */
    uint32_t index_section;

    /**
     * Tamano de la label en el bytecode
     */
    uint32_t size_label;
} entry_label_table;

/**
 * @brief entrada en la tabla de relocations.
 *
 * Cada entrada describe un slot DENTRO del bytecode (offset desde el inicio
 * de los bytes ejecutables, NO desde el inicio del archivo) que contiene
 * una direccion absoluta resuelta por el linker.  El loader puede usar
 * estos datos para reescribir los slots cuando un modulo se carga en una
 * VA distinta de la original (`load_module_dynamic` rebase transparente).
 *
 * Layout (24 bytes packed):
 *
 *   +0  bytecode_offset  (u64)  Offset desde el inicio de los bytes
 * ejecutables. Sumar @c offset_real_bytecode + section.file_offset para obtener
 * offset dentro del .velb completo. +8  target_value     (u64)  Valor original
 * escrito en el slot (la direccion absoluta resuelta por el linker).  El loader
 *                                puede comparar contra el rango VA del modulo
 *                                para decidir si patchear o no.
 *  +16  type             (u8)   Tipo de relocation: 1=Absolute64, 2=Relative32,
 *                                3=Relative64, 4=Absolute32.  El linker
 *                                emite tipicamente Absolute64 (lo que produce
 *                                @c @Absolute(...)) y Absolute32 para
 *                                instrucciones fusion @c cmpjmp / @c decjnz.
 *  +17  _pad             (u8x7) Relleno hasta 24 bytes.
 */
typedef struct PACKED entry_relocation_table {
    uint64_t bytecode_offset;
    uint64_t target_value;
    uint8_t type;
    uint8_t _pad[7];
} entry_relocation_table;

/**
 * @brief codigos compactos de tipo de relocation usados en
 * @c entry_relocation_table::type.  Mapeo desde el enum @c Type del
 * linker (que tiene mas variantes pero las relevantes para .velb son
 * absolute64 -- el resto se descarta o se transforma).
 */
enum class RelocTypeVELB : uint8_t {
    NONE = 0,
    ABSOLUTE64 = 1,
    RELATIVE32 = 2,
    RELATIVE64 = 3,
    ABSOLUTE32 = 4, ///< Direccion absoluta truncada a 32 bits (cmpjmp/decjnz).
};

/**
 * Entrada en la tabla de importaciones de funciones
 * nativas.
 */
typedef struct PACKED entry_import_table {
    /**
     * Offset al nombre del modulo, Ejemplo: kernel32.dll
     */
    uint32_t offset_module_string = 0;

    /**
     * offset al nombre del metodo, Ejemplo: GetTickCount()
     */
    uint32_t offset_function_string = 0;

    /**
     * La firma sirve para describir los tipos de argumentos y el tipo de
     * retorno de la funcion nativa.
     *      - (i32,i32)->i32
     *      - (f64)->f64
     *      - (str)->void
     *      - (ptr,i32)->i32
     */
    uint32_t offset_signature_string = 0;

    /**
     * offset de la instruccion a parchear.
     */
    uint32_t offset_bytecode = 0;
} entry_import_table;

typedef struct PACKED HeaderVELA {
    char magic[4] = {'V', 'E', 'L', 'A'}; // "VELA"
    uint32_t version = VERSION_VELA;      // version del formato
    uint32_t module_count = 0;            // numero de modulos
    uint64_t module_table_offset = 0;
} HeaderVELA;

typedef struct PACKED section_range_memory {
    range_memory address{}; // aqui deberia contener offsets a los
    // espacios de direcciones, al cargar el ejecutable,
    // se indica la direccion real,

    // nombre de la seccion, maximo 16 bytes.
    uint64_t offset_string =
        0; // donde empieza el bytecode o los datos dentro del archivo
} section_range_memory;

typedef struct PACKED VELA_ModuleEntry {
    uint64_t offset = 0; // offset al modulo
    uint64_t size = 0;   // tamano del modulo
    uint32_t symbol_count = 0;
    uint64_t symbol_table_offset = 0;
    uint32_t relocation_count = 0;
    uint64_t relocation_table_offset = 0;
} VELA_ModuleEntry;

typedef struct PACKED VELA_Symbol {
    uint64_t offset = 0; // offset dentro del modulo
    uint8_t type = 0;    // FUNC, DATA, GLOBAL, LOCAL
    char name[32] = {};
} VELA_Symbol;

typedef struct PACKED VELA_Relocation {
    uint64_t offset = 0;  // donde aplicar la relocacion
    uint8_t type = 0;     // ABS64, REL32, REL64
    char symbol[32] = {}; // simbolo a resolver
} VELA_Relocation;

/**
 * Nos permite comprobar si dos rangos de memoria se solapan ("se pisan")
 * @param a rango de memoria 1
 * @param b rango de memoria 2
 * @return si hay solapacion entonces devuelve true.
 */
static bool ranges_overlap(const range_memory *a, const range_memory *b) {
    return !(a->address_final <= b->address_init ||
             b->address_final <= a->address_init);
}

#ifdef __cplusplus
}
#endif

// #ifdef __cplusplus
//  Codigo exclusivo de C++ (clases, metodos, namespaces, etc.)

#include <unordered_map>
#include <vector>
#include <memory>
#include <inttypes.h>

#include "emmit/struct_context.h"
#include "optimizer/optimizer.h"
#include "emmit/annotations.h"

namespace Assembly::Bytecode::Linker {
/**
 * Opciones que controlan el comportamiento del linker.
 */
struct LinkerOptions {
    bool optimize_bytecode = true; // aplicar optimizaciones
    bool allow_undefined_symbols = false;
    bool generate_map_file = false; // archivo .map opcional
    bool verbose = false;           // logs detallados
    // Strip label names del .velb: una vez resueltas las relocations,
    // los nombres simbolicos de los labels NO los usa nadie en runtime
    // (el loader lee `offset_label_table`/`size_label_table` pero
    // nunca consulta la tabla, y ningun campo del binario referencia
    // strings_offsets[<label>]).  Por defecto los omitimos para
    // reducir el tamano del ejecutable ~9%.  Setear a false para
    // forzar la inclusion (util si debug tooling externo los necesita).
    bool strip_labels = true;

    std::string output_path;   // ruta del ejecutable final
    std::string map_file_path; // donde generar el map
};

/**
 * @brief Errores estructurados
 */
struct LinkerError {
    enum class Type {
        FileNotFound,
        InvalidFormat,
        DuplicateSymbol,
        UndefinedSymbol,
        RelocationError,
        IOError,
        InternalError
    };

    [[nodiscard]] const char *type_to_string() const {
        switch (type) {
        case LinkerError::Type::FileNotFound: return "FileNotFound";
        case LinkerError::Type::InvalidFormat: return "InvalidFormat";
        case LinkerError::Type::DuplicateSymbol: return "DuplicateSymbol";
        case LinkerError::Type::UndefinedSymbol: return "UndefinedSymbol";
        case LinkerError::Type::RelocationError: return "RelocationError";
        case LinkerError::Type::IOError: return "IOError";
        default: return "InternalError";
        }
    }

    Type type;
    std::string message;

    /**
     * @brief Representacion textual del error.
     * @return string con formato "[Type] message"
     */
    [[nodiscard]] std::string to_string() const {
        return std::string("[") + type_to_string() + "] " + message;
    }

    friend std::ostream &operator<<(std::ostream &os, const LinkerError &e) {
        os << e.to_string();
        return os;
    }
};

/**
 * @brief Tipos de warning del linker
 */
struct LinkerWarning {
    enum class Type {
        DeprecatedOption,
        UnusedSymbol,
        AlignmentAdjusted,
        ConfigWarning,
        IOWarning,
        PCDefault,
        Other
    };

    Type type;
    std::string message;

    [[nodiscard]] const char *type_to_string() const {
        switch (type) {
        case LinkerWarning::Type::DeprecatedOption: return "DeprecatedOption";
        case LinkerWarning::Type::UnusedSymbol: return "UnusedSymbol";
        case LinkerWarning::Type::AlignmentAdjusted: return "AlignmentAdjusted";
        case LinkerWarning::Type::ConfigWarning: return "ConfigWarning";
        case LinkerWarning::Type::IOWarning: return "IOWarning";
        case LinkerWarning::Type::PCDefault: return "PCDefault";
        default: return "Other";
        }
    }

    LinkerWarning(Type t, std::string m) : type(t), message(std::move(m)) {}

    /**
     * @brief Representacion textual del warning.
     * @return string con formato "[Type] message"
     */
    [[nodiscard]] std::string to_string() const {
        return std::string("[") + type_to_string() + "] " + message;
    }

    friend std::ostream &operator<<(std::ostream &os, const LinkerWarning &w) {
        os << w.to_string();
        return os;
    }
};

struct RelocReportEntry {
    std::string module;
    std::string symbol;
    uint64_t offset;
    uint64_t value_written;
    Type type;
};

static const char *reloc_type_to_string(Type t) {
    switch (t) {
    case Type::Relative64: return "REL64";
    case Type::Relative40: return "REL40";
    case Type::Relative32: return "REL32";
    case Type::Relative16: return "REL16";
    case Type::Relative8: return "REL8";
    case Type::Absolute64: return "ABS64";
    case Type::Absolute40: return "ABS40";
    case Type::Absolute32: return "ABS32";
    case Type::Absolute16: return "ABS16";
    case Type::Absolute8: return "ABS8";
    case Type::Native_Method: return "NATIVE_METHOD";
    case Type::NO_VALID: return "NO_VALID";

    default: return "UNKNOWN";
    }
}

/**
 * Un informe final con estadisticas del linking.
 */
struct LinkerReport {
    /**
     * numero de modulos usados para el linkado
     */
    size_t modules_linked = 0;

    /**
     * simbolos resueltos en el proceso de linkado
     */
    size_t symbols_resolved = 0;

    /**
     * relocalizaciones aplicadas en el proceso de linkado
     */
    size_t relocations_applied = 0;

    /**
     * optimizaciones aplicadas en el proceso de linkado.
     */
    size_t optimizations_applied = 0;

    /**
     * Relocalizaciones aplicadas:
     */
    std::vector<RelocReportEntry> relocations_log;

    /**
     * Tabla de warnings
     */
    std::vector<LinkerWarning> warnings;

    /**
     * Tabla de errores.
     */
    std::vector<LinkerError> errors;

    /**
     * indica si no ocurrio ningun error.
     * @return En caso de no haber errores devuelve true.
     */
    bool success() const { return errors.empty(); }

    /**
     * @brief Anade un error estructurado al reporte.
     * @param err datos del error
     */
    void add_error(LinkerError err) { errors.push_back(err); }

    /**
     * @brief Anade un error estructurado al reporte.
     * @param type Tipo del error (LinkerError::Type).
     * @param message Mensaje descriptivo.
     */
    void add_error(LinkerError::Type type, const std::string &message) {
        errors.push_back(LinkerError{type, message});
    }

    /**
     * @brief Anade un warning estructurado al reporte.
     * @param war datos del warning
     */
    void add_warning(LinkerWarning war) { warnings.push_back(war); }

    /**
     * @brief Anade un warning al reporte.
     * @param message Mensaje del warning.
     */
    void add_warning(LinkerWarning::Type type, const std::string &message) {
        warnings.emplace_back(type, message);
    }

    /**
     * @brief Version con contexto (archivo/clave/valor) para errores no ligados
     * al codigo.
     * @param type Tipo del error.
     * @param message Mensaje principal.
     * @param context Texto corto con contexto (p.ej.
     * "config:assembler.conf:line 12").
     */
    void add_error_with_context(LinkerError::Type type,
                                const std::string &message,
                                const std::string &context) {
        std::string full = message;
        if (!context.empty()) full += " (" + context + ")";
        add_error(type, full);
    }

    /**
     * @brief Anade un warning con contexto.
     */
    void add_warning_with_context(LinkerWarning::Type type,
                                  const std::string &message,
                                  const std::string &context) {
        std::string full = message;
        if (!context.empty()) full += " (" + context + ")";
        add_warning(type, full);
    }

    /**
     * @brief Merge sencillo de dos reportes (concatena warnings/errors y suma
     * contadores).
     */
    void merge_report(const LinkerReport &src) {
        modules_linked += src.modules_linked;
        symbols_resolved += src.symbols_resolved;
        relocations_applied += src.relocations_applied;
        optimizations_applied += src.optimizations_applied;
        warnings.insert(warnings.end(), src.warnings.begin(),
                        src.warnings.end());
        errors.insert(errors.end(), src.errors.begin(), src.errors.end());
    }

    /**
     * @brief Imprime un resumen legible del reporte en el stream dado.
     */
    void print_report(std::ostream &os = std::cout) {
        os << "* LinkerReport: \n"
           << "    - modules=" << modules_linked << "\n"
           << "    - symbols=" << symbols_resolved << "\n"
           << "    - relocations=" << relocations_applied << "\n"
           << "    - optimizations=" << optimizations_applied << "\n";

        os << "* Warnings (" << warnings.size() << "):\n";
        if (!warnings.empty()) {
            for (const auto &w : warnings)
                os << "  - " << w << "\n";
        }
        os << "* Errors (" << errors.size() << "):\n";
        if (!errors.empty()) {
            for (const auto &e : errors)
                os << "  - " << e << "\n";
        }
    }
};

/**
 * @brief Anade un error formateado (printf-like).
 * @note Implementacion simple usando snprintf.
 */
template <typename... Args>
static void add_errorf(LinkerReport &rpt, LinkerError::Type type,
                       const char *fmt, Args &&...args) {
    int size = std::snprintf(nullptr, 0, fmt, std::forward<Args>(args)...) + 1;
    if (size <= 0) {
        rpt.add_error(type, std::string(fmt));
        return;
    }
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(), size, fmt, std::forward<Args>(args)...);
    rpt.add_error(type, std::string(buf.get(), buf.get() + size - 1));
}

/**
 * @brief Anade un warning formateado (printf-like).
 * @param rpt reporte destino
 * @param type tipo de warning (LinkerWarning::Type)
 * @param fmt formato printf
 * @param args argumentos
 */
template <typename... Args>
static void add_warningf(LinkerReport &rpt, LinkerWarning::Type type,
                         const char *fmt, Args &&...args) {
    int size = std::snprintf(nullptr, 0, fmt, std::forward<Args>(args)...) + 1;
    if (size <= 0) {
        rpt.add_warning(type, std::string(fmt));
        return;
    }
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(), size, fmt, std::forward<Args>(args)...);
    rpt.add_warning(type, std::string(buf.get(), buf.get() + size - 1));
}

/**
 * Una libreria estatica es simplemente un contenedor de modulos.
 */
struct StaticLibrary {
    std::string path;
    std::vector<std::vector<uint8_t>> object_modules;
};

/**
 * Cada Module tiene su contexto, su bytecode, sys simbolos, sus
 * relocalizaciones.
 */
struct Module {
    std::string name;
    std::vector<uint8_t> bytecode;
    Context *ctx;
    bool is_object = false;
    std::vector<Relocation> relocations;
    std::unordered_map<std::string, uint64_t> local_symbols;
};

/**
 * Tabla para simbolos, los simbolos globales usan otra tabla aparte
 */
struct SymbolInfo {
    std::string space;
    std::string section;
    uint64_t relative;    // offset dentro de la seccion
    uint64_t absolute;    // direccion virtual absoluta
    uint64_t file_offset; // se rellena despues en build_section_table()
    std::string module;   // modulo donde se definio
    uint64_t size;        // tamano del label, algunas no tienen
};

typedef struct section_info_linker {
    section_range_memory memory;
    std::string name;
} section_info_linker;

/**
 * clase Linker va a cumplir dos roles muy distintos:
 *
 * - Linker tradicional
 *      Recibe varios ejecutables parciales (objetos, modulos, librerias) y
 *      resuelve simbolos, funciones externas, imports, etc.
 *
 * - Builder de ejecutables VELB
 *      Recibe un bytecode crudo + contexto generado por
 *      ensamblador y produce un ejecutable final VELB.
 *
 * Linker tiene 3 fases:
 *      1. Entrada
 *          - Cargar modulos objeto (.velo)
 *          - Cargar librerias estaticas (.vela)
 *          - Cargar ensamblados crudos (bytecode + contexto)
 *
 *      2. Proceso
 *          - Resolver simbolos
 *          - Seleccionar modulos necesarios
 *          - Aplicar relocaciones
 *          - Optimizar bytecode
 *          - Fusionar secciones y espacios de direcciones
 *
 *      3. Salida
 *          - Construir ejecutable VELB
 *          - Escribir archivo final
 *          - Escribir archivo .velb-map
 *
 */
class Linker {
  public:
    explicit Linker(const LinkerOptions &opts = {}) : options(opts) {
        this->result = new ByteWriter;
    }

    /**
     * Carga un archivo .velo o .velb parcial.
     *  Responsabilidades
     *      - Abrir archivo
     *      - Validar formato
     *      - Leer header
     *      - Leer secciones
     *      - Leer tabla de simbolos
     *      - Leer relocaciones
     *      - Convertirlo en un Module
     *      - Anadirlo a modules
     *
     *  Errores posibles
     *      - Archivo no encontrado
     *      - Formato invalido
     *      - Simbolos duplicados dentro del modulo
     *
     * @param path path donde se encuentra el archivo
     */
    void add_object_file(const std::string &path);

    /**
     * Igual que add_object_file pero desde memoria.
     *      Responsabilidades
     *          - Interpretar el buffer como un modulo objeto
     *          - Validar header
     *          - Extraer simbolos y relocaciones
     *          - Anadir a modules
     *
     * @param data buffer del archivo
     */
    void add_object_memory(const std::vector<uint8_t> &data);

    void merge_space_address(Space &dest, const Space &src);

    /**
     * @brief Registra una entrada de importacion en la tabla global del linker.
     *
     * Este metodo toma una entrada de importacion generada por un modulo
     * (compuesta por nombre de libreria y nombre de funcion) y la inserta
     * en la tabla global de importaciones del linker.
     *
     * Si la combinacion <lib:func> ya existe en la tabla global, no se crea
     * una nueva entrada y simplemente se devuelve el indice previamente
     * asignado.
     *
     * Si no existe, se anade una nueva entrada a `import_table`, se genera
     * un indice unico y se actualiza `import_lookup` para permitir busquedas
     * O(1) mediante la clave "lib:function".
     *
     * @param imp Entrada de importacion local del modulo, que contiene
     *            el nombre de la libreria y el nombre del metodo.
     *
     * @return uint64_t
     *         Indice global dentro de la tabla de importaciones del linker.
     *         Este indice es el que debe usarse en las relocaciones de tipo
     *         import (por ejemplo, para instrucciones CALLN).
     *
     * @note Este metodo garantiza que no existan duplicados en la tabla
     *       global de importaciones, incluso si varios modulos importan
     *       la misma funcion nativa.
     *
     * @see import_table
     * @see import_lookup
     */
    uint64_t register_import(const ImportEntry &imp);

    /**
     * Recibe el resultado del ensamblador.
     * Responsabilidades:
     *      Crear un Module con:
     *         - bytecode crudo
     *         - contexto (secciones, labels, espacios)
     *         - simbolos locales
     *         - relocaciones generadas por el ensamblador
     *     Marcarlo como is_object = false (es un ensamblado directo)
     * @param bytecode
     * @param ctx
     */
    void add_assembly_unit(const std::vector<uint8_t> &bytecode,
                           const Assembly::Bytecode::Context *ctx);

    /**
     * Carga un archivo .vela.
     * Responsabilidades
     *     - Leer header VELA
     *     - Leer tabla de modulos
     *     - NO cargar todos los modulos todavia
     *     - Guardar la libreria en libraries
     *     - Los modulos se cargaran solo si se necesitan para resolver simbolos
     *
     * Comportamiento tipo ar/ld
     *     - Si un simbolo requerido esta en la libreria -> se extrae ese modulo
     *     - Si no -> se ignora
     * @param path archivo vela a cargar
     */
    void add_static_library(const std::string &path);

    void merge_section(Section &dest, const Section &src);

    /**
     * Responsabilidades
     *     - Construir la tabla global de simbolos
     *     - Detectar simbolos duplicados
     *     - Detectar simbolos indefinidos
     *     - Extraer modulos necesarios de librerias .vela
     *     - Repetir hasta que no falten simbolos
     *
     * Algoritmo (como ld/LLD)
     *     - Insertar simbolos de modulos ya cargados
     *     - Mientras existan simbolos indefinidos:
     *         * Buscar en librerias .vela
     *         * Si un modulo contiene el simbolo -> cargarlo
     *         * Anadir sus simbolos
     *
     *     - Si al final quedan simbolos indefinidos:
     *         * Error (a menos que allow_undefined_symbols = true)
     */
    void resolve_symbols();

    /**
     * Aplica las relocaciones de cada modulo.
     *
     * Responsabilidades
     *     Para cada relocacion:
     *         - Buscar el simbolo en global_symbols
     *         - Calcular la direccion final
     *         - Escribir el valor en el bytecode
     *
     *     Tipos soportados:
     *         - ABS64
     *         - REL32
     *         - REL64
     *
     * Errores
     *     Simbolo no encontrado
     *     Offset fuera de rango
     */
    void apply_relocations();

    /**
     * Si options.optimize_bytecode == true.
     * Responsabilidades
     *     - Eliminar NOPs
     *     - Fusionar instrucciones triviales
     *     - Eliminar bloques muertos
     *     - Compactar saltos
     *     - Reordenar instrucciones si es seguro
     *
     * Resultado
     *     - Bytecode mas pequeno
     *     - Mejor rendimiento en la VM
     */
    void optimize_modules();

    /**
     * Orquesta todo el proceso.
     * Responsabilidades
     *     - resolve_symbols()
     *     - apply_relocations()
     *     - optimize_modules()
     *     - merge_address_spaces()
     *     - merge_sections()
     *     - build_header()
     *     - build_section_table()
     *     - concatenar bytecode final
     *
     * @return Devuelve un std::vector<uint8_t> con el ejecutable completo.
     */
    std::vector<uint8_t> build_executable();

    /**
     * Escribe el ejecutable final en disco.
     * @param path donde guardar el ejecutable
     */
    void write_to_file(const std::string &path);

    /**
     * Permite generar un archivo velb-map:
     * Y dentro:
     *   - listar modulos incluidos
     *   - listar simbolos globales
     *   - listar relocaciones aplicadas
     *   - listar secciones finales
     *   - listar espacios de direcciones
     *   - listar optimizaciones aplicadas
     *   - Escribir tamano final del ejecutable
     * @param path
     */
    void write_map_file(const std::string &path);

    const LinkerReport &get_report() const { return report; }

    LinkerOptions options;

    /**
     * @brief Permite realizar un reporte del linkado, guarda informacion del
     * proceso del linkado, errores y warnings.
     *
     * @code{.cpp}
     * LinkerReport rpt;
     *
     * // error con ruta (usar c_str() para std::string)
     * std::string path = "/tmp/module.velb";
     * add_errorf(rpt, LinkerError::Type::FileNotFound,
     *            "No se encontro el fichero '%s'", path.c_str());
     *
     * // error con entero (hex)
     * uint64_t addr = 0x1000;
     * add_errorf(rpt, LinkerError::Type::RelocationError,
     *            "Relocation failed at 0x%llx (section %s)", (unsigned long
     * long)addr, "text");
     *
     * // warning con tipo especifico
     * add_warningf(rpt, LinkerWarning::Type::DeprecatedOption,
     *              "La opcion %s esta obsoleta y sera removida en la proxima
     * version", "--fast-link");
     *
     * // imprimir resultado
     * rpt.print_report(std::cout);
     * @endcode
     */
    LinkerReport report;

    // para construir el binario final, buffer de salida
    ByteWriter *result;

    /**
     * @brief Opcion W: setea los bytes pre-serializados de la seccion
     *        @c @ir.  Llamado por el frontend Vesta (via assembler)
     *        antes de @c build_executable.
     *
     * Los bytes deben venir de @c ir::emit_ir_section(functions),
     * que produce el layout binario completo (magic + header +
     * funciones serializadas back-to-back).  El Linker simplemente
     * los appendea al .velb final tras la seccion de debug, y
     * patchea @c offset_ir_section + @c size_ir_section en el header.
     *
     * Vacio = no IR section -> @c offset_ir_section queda en 0.
     */
    void set_ir_section_bytes(std::vector<uint8_t> bytes) {
        ir_section_bytes = std::move(bytes);
    }

    /** @brief Acceso const para tests / inspeccion. */
    const std::vector<uint8_t> &get_ir_section_bytes() const noexcept {
        return ir_section_bytes;
    }

  private:
    /// Opcion W: bytes pre-serializados del @c @ir section.  Set via
    /// @c set_ir_section_bytes; usado en @c build_executable.
    std::vector<uint8_t> ir_section_bytes;

  private:
    // Interno: lista de modulos cargados
    struct Module {
        std::string name;
        std::vector<uint8_t> bytecode;
        Context ctx;
        bool is_object = false;

        std::vector<Relocation> relocations;
        std::unordered_map<std::string, uint64_t> local_symbols;
    };

    std::vector<Module> modules;
    std::vector<StaticLibrary> libraries;

    /**
     * Simbolos globales
     */
    std::unordered_map<std::string, uint64_t> global_symbols;

    /**
     * Tabla de importacion con nombres de los metodos y nombre de las
     * librerias usadas. Se recomienda usar la tabla `import_lookup` para
     * examinar si existe un simbolo dado de forma rapida, ya que esta via
     * tiene un coste O(1), en caso contrario usando otros metodos de buqyedas
     * perdera mas tiempo.
     */
    std::vector<ImportEntry> import_table;

    /**
     * Tabla de importacion de tipo clave: valor para acceso rapido,
     * ejemplo de clave:
     * "kernel32.dll:GetTickCount". el valor es el indice de la entrada
     * dentro de la tabla "import_table".
     */
    std::unordered_map<std::string, uint64_t> import_lookup;

    /**
     * Simbolos no globales
     */
    std::unordered_map<std::string, SymbolInfo> symbol_info;

    /**
     * bytecode final que plasmar, esto esta generado por una unidad de
     * ensamblado
     */
    std::vector<uint8_t> final_bytecode;

    /**
     * @brief tabla de relocations Absolute64 capturadas durante
     * @c apply_relocations.  Cada entry guarda el offset (relativo al
     * inicio del @c final_bytecode) y el target_value escrito en ese
     * slot.  Se serializa al .velb tras el bytecode y se actualiza
     * @c final_header.offset_reloc_table / size_reloc_table.  El loader
     * la usa en @c load_module_dynamic para rebase transparente.
     */
    std::vector<entry_relocation_table> applied_relocations_;

    /**
     * Header que escribir en el archivo final
     */
    HeaderVELB final_header{};

    /**
     * Tabla de metodos nativos a ejecutar. Esta tabla debe construirse en dos
     * dases distintas, la primera fase es en "apply_relocations" donde
     * detectamos el tipo de relocalizacion y creamos la entrada dentro de esta
     * tabla con el indice del metodo a la tabla import_lookup. Como aun no
     * tenemos la tabla strings construida, es necesario pos-poner la
     * construccion completa a la siguiente fase donde ya deberiamos tener la
     * tabla strings y podemos completar cada entrada de la tabla de importa
     * -cion
     */
    std::vector<entry_import_table> table_import_method;

    /**
     * Tabla de secciones finales
     */
    std::vector<section_info_linker> final_sections;

    /**
     * Pool de cadenas, estas son las que iran en la seccion "strings"
     */
    std::vector<std::string> string_pool;

    /**
     * Segun el nombre instroducido, devuelve un offset u otro, este offset
     * es donde esta la cadena si se suma la direccion base.
     */
    std::unordered_map<std::string, uint64_t> string_offsets;

    /**
     * contenido final de la seccion "strings"
     * "code\0data\0stack\0main\0foo\0bar\0"
     */
    std::vector<uint8_t> string_blob;

    /**
     * Vector de espacios de direcciones, cuando se junta varios modulos,
     * cada modulo puede contener los mismos espacios de direcciones o
     * tener mas o menos, en cualquiera de los casos, al generar un binario
     * final debe existir todos los espacios de direcciones descritos por
     * los modulos, en caso de que los espacios de direcciones ya existan
     * con un mismo nombre, se aplicara una relocalizacion a todo_ el codigo
     * de un modulo bajo ese espacio de direcciones, para que los
     * codigos de distintos modulos coexistan en el mismo espacio de direcciones
     */
    std::unordered_map<std::string, Space> spaces_address;

    /**
     * Fusiona los espacios de direcciones de todos los modulos.
     * Responsabilidades
     *     - Unir rangos de memoria
     *     - Detectar solapamientos
     *     - Reasignar offsets si es necesario
     *     - Preparar el layout final del ejecutable
     */
    void merge_address_spaces();

    /**
     * Fusiona secciones de todos los modulos.
     *
     * Responsabilidades
     *     - Concatenar .code
     *     - Concatenar .data
     *     - Alinear secciones segun reglas
     *     - Actualizar offsets de simbolos
     */
    void merge_sections();

    /**
     * Construye el header VELB final.
     * Responsabilidades
     *     Escribir:
     *         - magic "VELB"
     *         - version
     *         - checksum
     *         - timestamp
     *         - arquitectura
     *         - numero de secciones
     *         - tabla de espacios de direcciones
     *     Calcular checksum del ejecutable
     */
    void build_header();

    /**
     * Permite la construccion de la seccion especial "strings",
     * esta seccion contiene strings especiales que solo el linker usara,
     * normalmente son strings contantes con el nombre de los espacios de
     * direcciones, nombre de los labels y otros. Cada string debe tener un
     * terminador nulo.
     *
     * Es necesario conocer el offset en el que comienda dicha seccion para
     * poder calcular el offset a esta tabla
     *
     * @param offset_init offset donde inicial la seccion de cadena.
     */
    void build_section_strings(uint64_t offset_init);

    uint64_t compute_sections_base_offset() const;

    void compute_symbol_file_offsets();

    std::string get_string_from_offset(uint64_t offset) const;

    /**
     * Construye la tabla de secciones del ejecutable.
     * Responsabilidades
     *     Escribir:
     *         - nombre de seccion (16 bytes)
     *         - rango de memoria
     *         - offset en el archivo
     *         - tamano
     */
    void build_section_table();
};
} // namespace Assembly::Bytecode::Linker

// #endif

#endif // VELB_LINKER_BYTECODE_H
