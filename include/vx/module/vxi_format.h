/**
 * @file vxi_format.h
 * @brief Formato binario del fichero de interfaz `.vxi` ( M.2).
 *
 * El `.vxi` es la interfaz publica de un modulo Vesta.  Contiene SOLO los
 * simbolos exportados (marcados `public`) + sus firmas, sin
 * implementacion.  El TypeChecker de un modulo CONSUMIDOR carga los
 * `.vxi` de sus deps para resolver nombres cross-module sin reparsear
 * el source de cada dep.
 *
 * Caracteristicas hardware-aware:
 *   - Layout flat little-endian (cache-friendly, sin pointer chasing).
 *   - String pool al final (los nombres referencian offsets dentro del
 *     pool).  Permite hashing rapido O(1) por (offset+len) sin copiar.
 *   - Hash ABI FNV-1a 64 cubre TODOS los simbolos publicos en orden;
 *     dos modulos compilados con el mismo source + mismas deps producen
 *     el mismo ABI hash (detectable por el linker).
 *   - Reserva anticipada del buffer de salida en el emitter.
 *
 * El parser es zero-copy donde posible: los nombres se materializan como
 * `string_view` al pool sin alocar nuevos `std::string` hasta que el
 * caller lo necesite.  Para fields/methods se construyen colecciones
 * propias del TypeChecker.
 *
 * Multi-platform: bytes little-endian explicitos (no usa __PRAGMA pack
 * ni layout dependiente del compilador).  Compila identico en GCC,
 * Clang, MSVC, x86-64, ARM64, RISC-V.
 */

#ifndef VX_VXI_FORMAT_H
#define VX_VXI_FORMAT_H

#include <cstdint>
#include <string>
#include <vector>

namespace vx {

/// Magic del fichero `.vxi` (4 bytes ASCII "VXI").
inline constexpr uint32_t VXI_MAGIC = 0x49584556u;

/// Version del formato.  Incrementar al cambiar el layout binario.  El
/// loader rechaza versiones distintas (no se intenta forward-compat).
/// v2 ( M5.b): añade `extern_lib_len` explicito en el payload
/// FUNCTION (cierra L.5).
/// v3 (M4.ext): dep_table para invalidacion transitiva del cache.
/// v4 (.vxi-v4): **blob_pool** -- buffer contiguo para valores no
/// escalares (string, array, struct) de comptime const cross-module.
/// El Symbol GLOBAL_VAR ahora puede llevar @c blob_offset apuntando al
/// pool en lugar de @c init_value (que solo cabe 8 bytes).  Atributos
/// `@align`/`@hot`/`@cold`/`@section` viajan en el blob.
/// v6: seccion de plantillas genericas exportadas (texto fuente) para
/// monomorphizacion cross-module.
/// v9: ns_path en templates genericas (NS.2 cross-module).
/// v10: package_id en el header (NS.3, offsets 72/76 del pad v6).
/// v11: ext_methods (NS.6-ext) -- header crece a 88 (ext_off 80 + ext_count
/// 84).
/// v17: huella del mapa de diagnostico del modulo (cabecera 88 -> 104).  El
/// grafo de un modulo se emite al bajarlo, y bajar se salta cuando el modulo
/// viene de su cache; sin esto sus simbolos no llegaban al mapa del artefacto y
/// su grafo se quedaba sin nadie que lo sostuviera.  Se guarda la HUELLA y no
/// el mapa: el grafo ya esta en su almacen y es el mismo, porque la clave es el
/// contenido.  Y va en la cabecera, que ya se lee entera, para no anadir ni una
/// apertura por modulo -- con seis mil modulos eso serian seis mil.
inline constexpr uint16_t VXI_FORMAT_VERSION = 19; // v19: tipo base del enum
/* v19: el payload de un ENUM lleva su tipo base.  El lector ya lo leia y el
 * escritor no lo ponia, asi que ningun `.vxi` con un enum parseaba -- y eso
 * no se ve, porque un interfaz que no parsea se recompila desde el fuente:
 * el resultado sale bien y lo unico que se pierde, en silencio, es lo
 * incremental.  Se sube la version para que lo escrito por la anterior se
 * rechace limpiamente en vez de leerse corrido. */

/// Nombre del SO del HOST de compilacion, en el mismo vocabulario que usan los
/// atomos `os:` de @Target.  Es el valor por defecto del objetivo cuando no hay
/// override de cross-target.
const char *vxi_host_os_name() noexcept;

/// Nombre de la arquitectura del HOST, en el vocabulario de los atomos `arch:`
/// de @Target.  Mismo papel que @c vxi_host_os_name.
const char *vxi_host_arch_name() noexcept;

/// Kind del payload dentro de un BlobHeader (.vxi v4).  Asignaciones
/// estables (persisten en disco).  Cualquier kind desconocido = saltar.
enum class VxiBlobKind : uint32_t {
    NONE = 0,        ///< sentinel; no aplica.
    STRING = 1,      ///< bytes UTF-8 sin NUL terminator.
    ARRAY_PRIM = 2,  ///< array de primitivos (i8..u64, bool, char).
    STRUCT_PRIM = 3, ///< struct con campos primitivos.
    // Reservados v5+:
    STRUCT_NESTED =
        4, ///< struct con campos compuestos (referencias a otros blobs).
    ARRAY_REF = 5, ///< array de referencias (e.g. array de strings).
    TYPE_DESC = 6, ///< type-as-value descriptor.
};

/// BlobHeader: cabecera uniforme (24 bytes) de cada blob dentro del pool.
/// Permite que herramientas (desensamblador, dumper, port a C) recorran
/// el pool sin conocer las kinds futuras: para un kind desconocido,
/// saltan @c total_bytes.  Reads alineados a 8 bytes.
struct VxiBlobHeader {
    uint32_t kind = 0;         ///< VxiBlobKind
    uint32_t element_size = 0; ///< STRING:1; ARRAY_PRIM:sizeof(elem); STRUCT:0
    uint32_t count = 0; ///< STRING:byte_len; ARRAY_PRIM:N; STRUCT:field_count
    uint32_t total_bytes = 0;  ///< payload bytes que siguen (sin contar header)
    uint64_t content_hash = 0; ///< FNV-1a 64 sobre payload; permite dedup
    // payload[total_bytes] aligned a 8.
};

/// Categorias de simbolos exportados.  Asignaciones estables (no
/// reorderear; el byte se persiste en disco).
enum class VxiSymbolKind : uint8_t {
    TYPEDEF_ALIAS = 1, ///< typedef transparente (T = u32).
    TYPEDEF_NEW = 2,   ///< newtype (typedef T name new [@opaque] [@align(N)]).
    STRUCT = 3,        ///< struct value-type con su layout completo.
    CLASS = 4,         ///< class (incluye superclase, fields, metodos).
    ENUM = 5,          ///< enum (ADT) con variantes + payloads.
    GLOBAL_VAR = 6,    ///< global variable (typed).
    FUNCTION = 7,      ///< funcion top-level con firma.
};

/// Cabecera del fichero .vxi (48 bytes en v3).
///
/// Layout binario (offsets little-endian):
/// @verbatim
/// +0   u32  magic = 'VXI' (0x49584556)
/// +4   u16  format_version
/// +6   u16  _reserved
/// +8   u64  abi_hash      = FNV-1a 64 sobre simbolos publicos en orden
/// +16  u64  source_hash   = FNV-1a 64 sobre el .vx source crudo
/// +24  u64  compiler_version_hash  (M5.b L.27)
/// +32  u32  symbol_count
/// +36  u32  string_pool_offset (relativo al inicio del fichero)
/// +40  u32  dep_count   (M4.ext L.13: deps directos)
/// +44  u32  dep_table_offset  (relativo al inicio del fichero)
/// +48  ... entries (variable length) ...
/// +    ... dep table (16 bytes c/u: u64 name_off+name_len packed
///                                 + u64 abi_hash) ...
/// +    ... string pool al final ...
/// @endverbatim
struct VxiHeader {
    uint32_t magic = VXI_MAGIC;
    uint16_t format_version = VXI_FORMAT_VERSION;
    uint16_t _reserved = 0;
    uint64_t abi_hash = 0;
    uint64_t source_hash = 0;
    ///  M5.b L.27: hash de la version del compilador.  Si el .vxi
    /// fue generado por una version anterior cuyas reglas de mangling
    /// o layout difieren, el loader debe rechazar el cache y regenerar.
    /// El valor lo provee el compilador via @c vxi_compiler_version_hash().
    uint64_t compiler_version_hash = 0;
    uint32_t symbol_count = 0;
    uint32_t string_pool_offset = 0;
    ///  M4.ext L.13: cache transitivo.  El .vxi guarda los
    /// (module_name, abi_hash) de cada dep directo del modulo.  Al
    /// cache hit, el loader verifica que TODOS los deps siguen con el
    /// mismo abi_hash que cuando se compilo este modulo; si alguno
    /// cambio, invalida el cache y fuerza recompilar.
    uint32_t dep_count = 0;
    uint32_t dep_table_offset = 0;
    /// v4: blob_pool.  Buffer contiguo de bytes para los valores de
    /// `comptime` no escalares (string, array, struct).  Cada simbolo
    /// que use el pool lleva @c blob_offset apuntando a un @c BlobHeader
    /// dentro de este buffer.  Los blobs se alinean a
    /// @c blob_pool_alignment bytes para permitir reads alineados.
    uint32_t blob_pool_offset = 0;
    uint32_t blob_pool_size = 0;
    uint8_t blob_pool_alignment = 8; ///< default 8; reservado para AVX
    uint8_t _pad[3] = {0, 0, 0};
    /// v13: OBJETIVO con el que se genero este .vxi, como offset al string
    /// pool ("<os>|<arch>", p.ej. "windows|x86_64").  **0 = el modulo no usa
    /// @Target**, asi que su contenido no depende del objetivo y su artefacto
    /// vale para todos -- que es el caso de la inmensa mayoria de modulos.
    ///
    /// Solo los que SI usan @Target quedan atados a un objetivo, y al cargarlos
    /// un objetivo distinto es fallo de cache, no acierto.  Sin esto, un .vxi
    /// generado compilando para arm64 se seguia sirviendo en un build x86-64 y
    /// metia sus tipos en la resolucion: el mismo `uintptr` acababa con dos
    /// identidades (`arm64__uintptr` y `std__types__uintptr`) segun la ruta.
    ///
    /// Se guarda el NOMBRE y no un hash para poder decir en el diagnostico cual
    /// era el objetivo del artefacto y cual el actual; un hash obligaria a un
    /// mensaje vago justo donde hace falta precision.
    uint32_t target_offset = 0;
    /// v17 (88, 96): huella del mapa de diagnostico de ESTE modulo -- simbolo a
    /// entidad --, guardado como nodo en el almacen de vxdbg.  Cero = el modulo
    /// no aporta ninguno (no se emitio grafo, o el `.vxi` es anterior a v17).
    ///
    /// Quien sirva este modulo desde cache cita esta huella en el mapa del
    /// artefacto y con eso el grafo del modulo vuelve a estar sostenido, sin
    /// re-emitirlo y sin abrir nada mas: la cabecera ya se leyo.
    uint64_t vxdbg_map_lo = 0;
    uint64_t vxdbg_map_hi = 0;
};

/**
 * @brief Descriptor in-memory de un simbolo exportado en el .vxi.
 *
 * Representacion alta-nivel decodificada del binario.  El parser materializa
 * estos struct para que el TypeChecker los consuma sin tener que tocar
 * los bytes raw.
 *
 * El layout binario per-kind se documenta en la implementacion del
 * emitter (`vxi_format.cpp`).
 */
struct VxiSymbol {
    VxiSymbolKind kind = VxiSymbolKind::FUNCTION;
    std::string name; ///< Nombre publico del simbolo.

    /// NS.2 round-trip: namespace DECLARADO al que pertenece el simbolo
    /// (path punteado, e.g. "std.collections").  Vacio = simbolo a nivel de
    /// modulo (sin namespace).  El consumidor registra el namespace declarado
    /// al importar, para que `import "lib"` haga visible `mylib.helper()`.
    std::string ns_path;

    // Comun: el payload depende de @c kind.  Solo los campos relevantes
    // se llenan; el resto queda con su valor default.

    // === TYPEDEF_ALIAS / TYPEDEF_NEW ===
    /// Tipo subyacente en forma textual canonica (e.g. "u64", "i32*").
    /// El TypeChecker re-resuelve el TypeNode parseando este string.
    std::string underlying_type;
    /// (TYPEDEF_NEW) Bits ocultos al cliente (`@opaque`).
    bool is_opaque = false;
    /// (GLOBAL_VAR) marca `const` propagada al consumidor.  L.7.
    bool is_const = false;
    /// (GLOBAL_VAR) marca @c true si el .vxi contiene el valor literal
    /// inicial (solo aplicable a const numericas).  L.7.
    bool has_init_value = false;
    /// (GLOBAL_VAR) Valor inicial entero (raw u64, signo segun el tipo).
    /// Solo significativo si @c has_init_value es @c true.
    uint64_t init_value = 0;
    /// v4: si @c has_blob_ref es @c true, el valor inicial vive en el
    /// blob_pool del .vxi en @c blob_offset.  Este campo es excluyente
    /// con @c has_init_value (un simbolo es escalar inline O via blob).
    /// El consumer materializa el blob al @c static_data del modulo en
    /// el primer uso.
    bool has_blob_ref = false;
    uint32_t blob_offset = 0;
    /// v4: hint del kind del blob.  Copia del @c BlobHeader::kind para
    /// que el consumer pueda decidir sin chase del puntero.  0 = NONE.
    uint8_t blob_kind_hint = 0;
    /// v4: atributos de usuario (`@align`, `@hot`, `@cold`, `@section`).
    /// Solo se persisten para GLOBAL_VAR con blob ref; los atributos en
    /// runtime const numericas se aplican al lowering local del consumer.
    /// Bits: 0=hot, 1=cold; los demas reservados.  Alineacion en bytes.
    uint8_t attr_flags = 0;
    uint16_t attr_align = 0;  ///< 0 = default; sino multiplo de 8/16/32/64
    std::string attr_section; ///< vacio = default; sino nombre de seccion
    /// (TYPEDEF_NEW) Alineacion forzada (`@align(N)`).  0 = default.
    uint16_t align_override = 0;
    /// (TYPEDEF_NEW) IDs nominales se asignan localmente al re-importar.
    /// El que se persiste aqui es el ABI hash (FNV-1a del nombre).
    uint64_t nominal_abi = 0;

    ///  M.L8: bloque @c {explicit from/to T;} del typedef new.
    /// Cada entry es @c (typename_canonico, is_public).  El consumidor
    /// solo puede usar conversiones marcadas @c is_public.
    struct ExplicitConvEntry {
        std::string type_str;
        bool is_public = false;
    };
    std::vector<ExplicitConvEntry> from_conversions;
    std::vector<ExplicitConvEntry> to_conversions;
    /// Bloque @c {implicit from/to T;}: conversiones que no piden cast.  Viajan
    /// igual que las explicitas porque el consumidor necesita saberlas para
    /// aceptar la asignacion; sin ellas un `uintptr` importado volvia a exigir
    /// el cast que su propio modulo declara innecesario.
    std::vector<ExplicitConvEntry> implicit_from_conversions;
    std::vector<ExplicitConvEntry> implicit_to_conversions;

    // === STRUCT / CLASS ===
    struct FieldInfo {
        std::string name;
        std::string type_str; ///< typename canonico
        uint32_t offset = 0;
        uint32_t size = 0;
        uint8_t bit_offset = 0;
        uint8_t bit_width = 0;
    };
    std::vector<FieldInfo> fields;
    /// (CLASS) Nombre de la superclase o vacio.
    std::string super_class;
    /// (CLASS) Interfaces implementadas (nombres).
    std::vector<std::string> interfaces;
    /// (CLASS)  M6.b: firmas de metodos publicos para que el
    /// consumidor pueda emitir CALLVIRT correctamente cross-module.
    /// Cierra L.6.
    struct MethodInfo {
        std::string name;                     ///< nombre publico ("area")
        std::string return_type;              ///< typename canonico
        std::vector<std::string> param_types; ///< typenames canonicos
        uint32_t vtable_index = 0;
        uint8_t flags =
            0; ///< bit0=is_static, bit1=is_constructor, bit2=is_virtual
        std::string mangled_label; ///< label real en .vel para CALLVM directo
                                   ///< si !is_virtual
    };
    std::vector<MethodInfo> methods;
    /// (STRUCT / CLASS) Tamano total + alineacion.
    uint32_t size_bytes = 0;
    uint32_t align_bytes = 1;
    /// (STRUCT) @c true si el struct es un `@overlay struct` (vista tipada
    /// sobre memoria ajena).  Se propaga para que el consumidor reconozca la
    /// construccion `Tipo(ptr)` de un overlay importado (solo campos escalares
    /// con @offset fijo; los overlays con offset dinamico/array/resolver usan
    /// punteros al AST no serializables y no cruzan modulo).
    bool is_overlay = false;
    /// (STRUCT overlay) Extension real del overlay en bytes (no @c size_bytes,
    /// que para un overlay es el tamano del puntero).  0 si no aplica.
    uint32_t overlay_extent = 0;

    // === ENUM ===
    struct EnumVariant {
        std::string name;
        uint32_t tag = 0;
        std::vector<std::string> payload_types;
        /// Valor de la variante en un enum C-style (`Less = -1`).  Sin esto,
        /// un enum con valor importado llegaba con sus variantes SIN valor:
        /// `Ordering.Less` resolvia a basura y comparar dos de ellas fallaba.
        int64_t int_value = 0;
    };
    std::vector<EnumVariant> variants;

    // === FUNCTION ===
    std::string return_type;              ///< typename canonico del retorno
    std::vector<std::string> param_types; ///< typenames canonicos en orden
    std::vector<std::string> param_names; ///< paralelo a param_types
    /// ABI custom por-parametro (`register("rax")` en params): registro fisico
    /// canonico de cada param, paralelo a @c param_types.  Vacio = ABI
    /// estandar. Sin esto, un CALLIND cross-modulo a traves de un campo cuyo
    /// default es una funcion con ABI custom (p.ej. `invoke` de std.syscall) no
    /// conocia los registros y colocaba los args mal.  Se serializa como una
    /// lista de strings (idx u32 + reg) tras @c param_names.
    std::vector<std::string> param_abi_regs;
    bool is_extern = false; ///< extern "lib.dll"
    std::string extern_lib; ///< si is_extern
    ///  M.5: label internal usado en el .vel del modulo origen.
    /// Vacio = mismo que @c name.  Si distinto, el consumidor emite
    /// @c CALLVM al @c mangled_label en lugar de @c name (resuelve
    /// colisiones de nombres cross-module).  E.g. funcion "sumar" del
    /// modulo "lib" tiene @c name="sumar" pero @c mangled_label="lib__sumar".
    std::string mangled_label;
    /// (FUNCTION) LIM-A: marca @c \@Naked (cuerpo asm nativo puro).  Se
    /// serializa en el bit 0x08 del byte de flags del symbol header (no en
    /// el payload -- asi un .vxi previo con ese bit a 0 lee @c false y el
    /// comportamiento es el actual).  El consumidor propaga a
    /// @c FunctionSig::is_naked para enrutar la llamada cross-modulo al
    /// dispatcher @c vrt:naked_dispatch en interp/JIT.
    bool is_naked = false;
    ///  NS.3: @c "internal" (package-scoped).  Bit 0x10 del byte de flags.
    /// El simbolo se exporta pero el consumidor de OTRO package_id lo filtra.
    bool is_internal = false;
};

/**
 * @brief Modulo de interfaz decodificado.
 */
struct VxiModule {
    uint16_t format_version = 0;
    uint64_t abi_hash = 0;
    uint64_t source_hash = 0;
    uint64_t compiler_version_hash = 0; ///< M5.b L.27
    /// v17: huella del mapa de diagnostico de este modulo (ver @ref
    /// VxiHeader).  Cero = no aporta ninguno.
    uint64_t vxdbg_map_lo = 0;
    uint64_t vxdbg_map_hi = 0;
    std::vector<VxiSymbol> symbols;
    ///  M4.ext L.13: cache transitivo.  Cada DepRecord guarda el
    /// nombre del modulo dep + su abi_hash en el momento de compilar
    /// este .vxi.  El loader verifica los deps al cache hit.
    struct DepRecord {
        std::string name;
        uint64_t abi_hash = 0;
    };
    std::vector<DepRecord> deps;
    /// v4: blob_pool.  Bytes contiguos para los valores de simbolos
    /// con @c VxiSymbol::has_blob_ref=true.  Cada blob arranca en un
    /// multiplo de 8 (`blob_pool_alignment`) y tiene un @c VxiBlobHeader
    /// al inicio.  Vacio si ningun simbolo necesita blobs.
    std::vector<uint8_t> blob_pool;
    uint8_t blob_pool_alignment = 8;
    /// v6: plantillas genericas + conceptos exportados (texto fuente).  El
    /// importador las re-parsea e inyecta en su AST para monomorphizar
    /// `Caja<i64>` cross-module.  Ver @c GenericTemplateSource.
    struct GenericTemplateSource {
        std::string name;   ///< nombre del template
        uint8_t kind = 0;   ///< NodeKind del decl (Struct/Class/Function/...)
        std::string source; ///< texto fuente completo del decl
        std::string
            ns_path; ///< NS.2 (v9): namespace declarado (vacio = ninguno)
    };
    std::vector<GenericTemplateSource> generic_templates;

    /**
     * @brief v18: el conjunto comptime de este modulo, tal como se extrajo.
     *
     * Es el texto de las decls que se EJECUTAN al compilar (las `comptime fn`,
     * los `@Macro`, sus constantes y las funciones normales de las que
     * dependen), listo para compilarse aparte.
     *
     * Viaja en el `.vxi` porque extraerlo necesita el AST, y un modulo servido
     * del cache no se parsea: sin esto, el conjunto de un proyecto salia con un
     * modulo de siete -- el unico que se recompilo -- y no habia forma de saber
     * que faltaban los demas.  Guardarlo aqui lo hace disponible SIN parsear
     * nada, que es la unica forma de que no cueste tiempo de compilacion.
     *
     * Mismo criterio que @c generic_templates, que ya lleva texto fuente por
     * la misma razon.
     */
    std::string comptime_unit_source;
    /// @brief v18: huella del conjunto.  Cambia si y solo si cambia codigo
    /// comptime, asi que sirve de clave de cache de su artefacto.
    uint64_t comptime_unit_hash = 0;
    /// @brief v18: los NOMBRES que forman el conjunto.  Son el criterio de
    /// pertenencia al emitirlo; deducirlos del texto seria adivinar.
    std::vector<std::string> comptime_unit_names;
    /// @brief v18: lo que se vio y NO se llevo, para poder decirlo.  Sin esto,
    /// un modulo cacheado callaria lo que dejo fuera.
    std::vector<std::string> comptime_unit_not_collected;
    /// NS.6-ext (v11): metodos de @c extension / @c impl que este modulo
    /// anyade a un tipo (posiblemente IMPORTADO de otro modulo).  El
    /// consumidor los re-apendea al layout del tipo destino para que
    /// @c obj.metodo() resuelva cross-modulo (dispatch estatico al
    /// @c mangled_label, que vive en el .velb de ESTE modulo).
    struct ExtMethod {
        std::string
            target_key;   ///< clave del layout destino (p.ej. shapes__Punto)
        std::string name; ///< nombre del metodo
        std::string return_type;              ///< tipo de retorno canonico
        std::vector<std::string> param_types; ///< tipos de los params
        std::string mangled_label;            ///< label real (target_key__name)
        bool target_is_class = false;
    };
    std::vector<ExtMethod> ext_methods;
    ///  NS.3 (v10): identidad del PAQUETE que produjo este .vxi.
    /// Derivado de @c "vx.toml" ([package] name@version) o de @c "@id(...)"
    /// opt-in; vacio = paquete anonimo.  Usado para: (a) desambiguar
    /// namespaces homonimos de paquetes distintos, (b) frontera de la
    /// visibilidad @c internal (visible solo dentro del mismo package_id).
    std::string package_id;
    /// v13: objetivo con el que se genero/leyo el artefacto, como
    /// "<os>|<arch>". VACIO = el modulo no usa @Target, asi que su contenido no
    /// depende del objetivo y el `.vxi` sirve para todos.  Lo rellena el emisor
    /// a partir de
    /// @c ast::ModuleNode::uses_conditional_target.
    std::string target;
};

/// Helper: alocar un blob en el pool y devolver su offset.  El emitter
/// lo usa al construir el VxiModule antes de serializar.  Padding
/// automatico al multiplo de @c alignment.
///
/// @param pool       buffer destino (in-out)
/// @param kind       VxiBlobKind del blob a alocar
/// @param payload    bytes del payload (alineados internamente al elem_size)
/// @param element_size 1/2/4/8 para arrays primitivos; 1 para strings
/// @param count      elementos (o byte_len para strings)
/// @param alignment  alineamiento del header (default 8)
/// @return offset del header dentro del pool
uint32_t vxi_blob_append(std::vector<uint8_t> &pool, VxiBlobKind kind,
                         const uint8_t *payload, size_t payload_len,
                         uint32_t element_size, uint32_t count,
                         uint32_t alignment = 8);

/// Helper: leer un BlobHeader del pool en @c offset.  Devuelve nullptr
/// si @c offset esta fuera de rango o el header esta truncado.  No
/// valida la integridad del payload (caller debe respetar @c total_bytes).
const VxiBlobHeader *vxi_blob_read(const std::vector<uint8_t> &pool,
                                   uint32_t offset) noexcept;

/// Helper: devuelve puntero al payload del blob en @c offset (justo
/// despues del header).  Caller asume responsabilidad de respetar
/// @c total_bytes para no leer fuera de rango.
const uint8_t *vxi_blob_payload(const std::vector<uint8_t> &pool,
                                uint32_t offset) noexcept;

/**
 * @brief Hash constante del compilador en uso.  Definido por una macro
 * @c VXI_COMPILER_BUILD_ID (sobreescribible en CMake) o por defecto al
 * FNV-1a del string @c "vx-1.0.0" / fecha de build.  Si dos compiladores
 * tienen el mismo hash, sus .vxi son ABI-compatibles.  Si difieren, el
 * cache se invalida.
 */
uint64_t vxi_compiler_version_hash() noexcept;

/**
 * @brief Serializa un @c VxiModule a bytes listos para escribir a disco.
 *
 * @param mod Modulo con simbolos publicos a exportar.
 * @return Vector de bytes con el header + entries + string pool.  El
 *         abi_hash se RECALCULA durante la emision sobre los simbolos
 *         en orden.
 *
 * Optimizaciones:
 *   - Reserva del buffer estimada con base en el conteo de simbolos.
 *   - String pool con dedup (mismo nombre = un solo offset).
 *   - FNV-1a streaming durante el emit (no requiere segunda pasada).
 */
std::vector<uint8_t> vxi_emit(const VxiModule &mod);

/**
 * @brief Resultado del parsing de un .vxi.
 */
struct VxiParseResult {
    bool ok = false;
    std::string error_message;
    VxiModule module_;
};

/**
 * @brief Parsea bytes de un .vxi y devuelve un @c VxiModule decodificado.
 *
 * Validaciones:
 *   - magic == VXI_MAGIC
 *   - format_version == VXI_FORMAT_VERSION (rechaza otras)
 *   - offsets dentro del buffer (no OOB reads)
 *   - string_pool_offset coherente
 *
 * Si falla devuelve @c ok=false + mensaje detallado.
 */
VxiParseResult vxi_parse(const uint8_t *data, size_t size);

/**
 * @brief FNV-1a 64-bit publico (mismo helper que ModuleGraph).
 *
 * Expuesto aqui para que el TypeChecker pueda calcular el source_hash
 * sin importar el resolver.
 */
uint64_t vxi_fnv1a(const void *data, size_t len) noexcept;

/**
 * @brief Huella de UN SUBCONJUNTO de los simbolos de un modulo: lo que un
 *        consumidor concreto ve de el.
 *
 * El `abi_hash` describe la interfaz ENTERA, asi que anadirle a un modulo una
 * funcion publica que nadie usa invalidaba a todos sus consumidores.  Lo que
 * de verdad le importa a cada uno es lo que IMPORTA de el, y eso es lo que
 * mide esta huella.
 *
 * La huella de un simbolo se define como *lo que el escritor persiste de el*:
 * se serializa un modulo con ese unico simbolo y se hashean sus bytes.  Es
 * deliberado -- enumerar los campos a mano seria una lista que se queda corta
 * el dia que se anade uno, y quedarse corto aqui no recompila de mas: sirve un
 * artefacto que no corresponde al fuente.
 *
 * Independiente del ORDEN de @p nombres.  Un nombre que no existe en @p m
 * cuenta igualmente (se mezcla su nombre), para que quitar un simbolo tambien
 * cambie la huella de quien lo usaba.
 *
 * @param m       Modulo importado, ya parseado.
 * @param nombres Simbolos que el consumidor toma de el.
 * @return Huella FNV-1a de 64 bits.
 */
uint64_t vxi_hash_de_simbolos(const VxiModule &m,
                              const std::vector<std::string> &nombres);

inline uint64_t vxi_fnv1a(const std::string &s) noexcept {
    return vxi_fnv1a(s.data(), s.size());
}

} // namespace vx

#endif // VX_VXI_FORMAT_H
