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
 * @file type_checker.h
 * @brief Pase de comprobacion de tipos del frontend Vesta.
 *
 * Recorre el AST producido por el parser, resuelve nombres, infiere
 * el tipo de cada expresion (rellenando @c Expr::result_type) y verifica
 * la validez semantica de las operaciones para el subset:
 *
 *   - Funciones top-level y variables globales.
 *   - Variables locales con scope lexico.
 *   - Operaciones aritmeticas, logicas, bitwise y comparacion sobre
 *     tipos compatibles segun reglas estilo C.
 *   - Llamadas a funcion con verificacion de aridad y tipo de argumentos.
 *   - Asignaciones a lvalues
 *
 * Decisiones de hardware / rendimiento:
 *   - Tabla de simbolos como std::vector<unordered_map>: capa por scope.
 *     Lookup en orden inverso (scope mas interno primero) con early-exit.
 *   - Symbols pequenyos (24 bytes): kind + Type + indice de funcion en
 *     el modulo si aplica.  Almacenamiento contiguo en cada scope.
 *   - El check NO modifica la estructura del AST salvo el campo
 *     @c result_type en cada @c Expr; esto evita reasignaciones y mantiene
 *     ownership intacto.
 */

#ifndef VX_TYPE_CHECKER_H
#define VX_TYPE_CHECKER_H

#include "util/env_flags.h"
#include <algorithm>
#include <cstdint>
#include <functional> // std::function, en la firma de un parametro de abajo
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <memory>
#include "vx/ast.h"
#include "vx/borrow_checker.h"
#include "vx/comptime/comptime_vm.h"
#include "vx/diag/diag_catalog.h"
#include "vx/diagnostic.h"

namespace vx {

/// Sustitucion de type params de una instanciacion generica.  Se define en
/// `src/vx/generic_clone.h` (interno del frontend, no publico); aqui basta la
/// declaracion adelantada para pasarla por referencia.
namespace vxgen {
struct GenSubst;
}

/**
 * @brief ComptimeValue recursivo via shared_ptr.
 *
 * Necesario shared_ptr para break el cycle de "containers de self".
 * `std::unordered_map<K, ComptimeValue>` con T incompleto es UB en
 * C++17 (no soportado por libstdc++).  Con shared_ptr el container
 * almacena punteros + las copias son O(1) hasta que se necesita
 * deep copy (que se hace explicitamente cuando se necesita modificar
 * sin afectar al original).
 */
struct ComptimeValue {
    bool is_str = false;
    bool is_array = false;
    bool is_struct = false;
    bool is_type = false;
    int64_t value = 0;
    std::string str;
    std::vector<std::shared_ptr<ComptimeValue>> array_vals;
    std::unordered_map<std::string, std::shared_ptr<ComptimeValue>>
        struct_fields;
    Type type_val;
};
} // namespace vx

namespace vx {

/**
 * @enum SymbolKind
 * @brief Categoria del simbolo en la tabla.
 */
enum class SymbolKind : uint8_t {
    Variable,  ///< Variable local o global.
    Param,     ///< Parametro de funcion.
    Function,  ///< Funcion top-level.
    Constant,  ///<       identificador magico de string constante
               ///<       (ANSI codes RED/GREEN/BOLD/RESET/etc.).
               ///<       El lowering los convierte en STR_LIT_ADDR
               ///<       de un literal predefinido.
    Namespace, ///<  M.7: namespace de un modulo importado.
               ///< Sintaxis: @c "import \"lib_a\";" registra @c lib_a
               ///< como Symbol::Namespace.  El campo @c ns_index del
               ///< Symbol apunta al @c imported_namespaces_ del
               ///< TypeChecker para resolver @c lib_a.simbolo.
};

/**
 * @struct FunctionSig
 * @brief Firma de una funcion: tipo de retorno + tipos de parametros.
 */
struct FunctionSig {
    Type return_type;
    std::vector<Type> param_types;
    /// ABI custom por-parametro (`register("rXX") T name`): registro fisico de
    /// entrada por parametro, alineado con @c param_types.  Vacio = ABI
    /// estandar. Lo consume: (a) el codegen del CALL directo (via IrFunction),
    /// y (b) el tipado de `&funcion`, que construye un @c cfn cuyo @c
    /// fn_param_abi_regs hereda esta lista -> el tipo del puntero LLEVA la ABI.
    std::vector<std::string> param_abi_regs;
    ///  FFI extern: si no esta vacio, esta funcion es un import
    /// de una libreria nativa (ej. "user32.dll", "kernel32.dll" o
    /// "stdlib/native/io/vesta_io").  El lowering al ver una llamada a
    /// una funcion con @c extern_lib != "" emite directamente
    /// @c CALLN @Method("<extern_lib>:<name>") con args en R1..RN,
    /// registrando el import via @c register_native_import.  Sin entry
    /// para extern_lib se trata como funcion Vesta normal (CALLVM).
    std::string extern_lib;
    ///  M.5: nombre real del label generado para esta funcion.
    /// Vacio = el nombre visible coincide con el label (caso normal).
    /// No vacio = la funcion fue importada de otro modulo con
    /// mangling automatico (`lib__foo`); el lowering emite @c CALLVM
    /// al label mangled mientras que el resolver de nombres sigue
    /// usando el nombre publico (`foo`).  Cierra la limitacion L.4.
    std::string mangled_label;
    /// Variadicos: si @c true, el ULTIMO param es un rest `T... name`.  En
    /// @c param_types el ultimo entry es @c T* (puntero al elemento) y
    /// @c variadic_elem guarda el tipo del ELEMENTO T (para validar los args
    /// trailing).  La funcion acepta >= (N-1) args (N = param_types.size());
    /// los args extra se empacan en un array de pila y se pasan como (ptr,
    /// count); el count va en un param i64 OCULTO al final.
    bool is_variadic = false;
    Type variadic_elem;
    /// Variadico CRUDO: el ULTIMO param es un `...` pelado (sin tipo ni
    /// nombre). El caller NO empaqueta los args trailing -- los pasa crudos en
    /// los arg-regs del ABI segun el tipo de cada uno.  Solo para funciones
    /// @Naked.
    bool is_raw_variadic = false;
    /// Bug/feature 198: @Naked -- funcion cuyo cuerpo es asm nativo puro (sin
    /// prologo/epilogo VM).  El lowering, al ver una llamada a una @Naked,
    /// emite un CALLN al dispatcher @c vrt:naked_dispatch (que la compila al
    /// vuelo como nativa con sus simbolos propios resueltos) en vez de un
    /// CALLVM a bytecode VM que no existe.  Solo se activa en interp/JIT; en
    /// AOT todo es nativo y la llamada normal ya funciona.
    bool is_naked = false;
};

/**
 * @struct StructFieldInfo
 * @brief Informacion del layout de un campo dentro de un @c struct.
 *
 * @c offset es el desplazamiento en bytes desde el inicio del struct.
 * @c size es el tamano del campo en bytes (sizeof(field.type)).
 * @c type es el tipo semantico ya resuelto (incluye campos struct
 * anidados via Type{STRUCT, name}).
 */
struct StructFieldInfo {
    std::string name;
    Type type;
    uint32_t offset;
    uint32_t size;
    /// fase C - Bit field metadata.  bit_width=0 indica campo
    /// normal (byte-aligned, ocupa @c size bytes desde @c offset).
    /// bit_width>0 indica bit field: el storage word esta en
    /// @c [offset, offset+size); el bit field empieza en @c bit_offset
    /// (0..size*8-1) dentro de ese word y ocupa @c bit_width bits.
    /// Multiple bit fields del mismo storage word comparten @c offset
    /// y @c size pero con distintos @c bit_offset.
    uint8_t bit_offset = 0;
    uint8_t bit_width = 0;
    /// `comptime T campo`: campo solo-compile-time (en @c comptime_fields, no
    /// en
    /// @c fields).  @c offset/@c size no aplican (no vive en la instancia).
    bool is_comptime = false;
    /// Valor por defecto del campo (`u8 a = 0x10;`), no-owning al AST (vive
    /// durante toda la compilacion).  null = sin default (zero-init).  Lo usa
    /// el lowering para `= {}`, campos no listados en el init y `default()`.
    ast::Expr *default_init = nullptr;
    /// Offset DINAMICO de un campo de overlay dado por una expresion que puede
    /// referenciar campos hermanos (`@offset(prev_off + 0x10)`).  no-owning al
    /// AST.  null = offset estatico (usa @c offset).  Al resolver un acceso el
    /// lowering evalua esta expresion (los nombres desnudos de hermanos leen
    /// @c LOAD [base + hermano.offset]) y direcciona en @c base + resultado.
    ast::Expr *offset_expr = nullptr;
    /// Resolver de la DIRECCION del campo (F3): `@offset { ...; return <dir>;
    /// }`. no-owning al AST.  A diferencia de @c offset_expr (un offset
    /// relativo a base), el bloque DEVUELVE la DIRECCION absoluta donde vive el
    /// campo, con control de flujo completo; tiene `base` (el puntero de la
    /// vista) y los campos hermanos en scope.  null = usa expr/offset
    /// constante.
    ast::BlockStmt *offset_block = nullptr;
    /// Overlay ARRAY (F3b): `T Name[count] @offset(pos) stride(s)`.  Si
    /// @c array_stride != null, el campo es un array: @c offset/@c offset_expr
    /// da `pos` (base de la tabla), @c array_stride los bytes por elemento, y
    /// @c type es el tipo del ELEMENTO.  `v.Name[i]` = base + pos + i*stride.
    /// no-owning al AST.
    ast::Expr *array_count = nullptr;
    ast::Expr *array_stride = nullptr;
    /// Overlay array POR-ELEMENTO (`T Name[c] @element { ... }`): resolver que
    /// da la DIRECCION del elemento `index` (stride variable / TLV).  no-owning
    /// al AST.  null = array de stride fijo (usa @c array_stride).
    ast::BlockStmt *element_block = nullptr;
    /// Overlay endianness (F5): 0=nativo, 1=big-endian (`@be`), 2=little
    /// (`@le`). Un campo `@be` emite BYTESWAP en read/write (host x86-64 =
    /// little-endian).
    uint8_t endian = 0;
    /// Overlay endianness DINAMICA (F5): `@endian(expr)` -- expr (nonzero=BE)
    /// decide el orden en tiempo de acceso.  no-owning al AST.  null =
    /// estatico.
    ast::Expr *endian_expr = nullptr;
    /// Overlay array SIN count (`T Name[] @offset(...) stride(s)`): el usuario
    /// gestiona la terminacion (p.ej. bucle hasta entrada nula).  @c
    /// array_count null + @c is_array true = array no acotado.
    bool is_array = false;
    /// F4: el resolver `@offset { }` de este campo usa `parent<T>()`.  Entonces
    /// la funcion sintetizada recibe un param extra `root` (el puntero de la
    /// vista RAIZ) que el call site enhebra caminando la cadena de accesos.
    /// @c resolver_parent_type = nombre del tipo overlay raiz (T).
    bool resolver_uses_parent = false;
    std::string resolver_parent_type;
};

/**
 * @struct ClassMethodInfo
 * @brief Resumen de un metodo de clase para el type checker.
 *
 * @c vtable_index es el slot donde el lowering insertara el metodo
 * en la vtable del ClassRegistry (constructor en posicion 0 por
 * convencion, resto en orden de declaracion).  @c is_constructor
 * y @c is_static replican la info del AST.
 *
 * Tambien lo reutiliza @c StructLayout::methods: los structs son
 * value-types sin vtable, asi que @c vtable_index/@c is_constructor
 * no aplican; el lowering despacha sus metodos como funciones libres
 * @c <Struct>__<metodo> con dispatch estatico.
 */
struct ClassMethodInfo {
    std::string name;
    Type return_type;
    std::vector<Type> param_types;
    /**
     * @name El ultimo parametro recoge los que sobren
     *
     * `i64... xs` no es un parametro mas: quien llama puede pasar cuantos
     * quiera, los mete en un array y pasa su direccion y cuantos son.  Por eso
     * en @c param_types el ultimo aparece ya como `T*`, y el numero de
     * elementos viaja en un parametro que no se escribio.
     *
     * @c variadic_elem es la T con la que se comprueban los argumentos que
     * sobran; sin ella habria que deshacer el puntero cada vez.
     * @{
     */
    bool is_variadic = false;
    Type variadic_elem;

    /**
     * @brief Cuantos parametros ve el IR, contando el que no se escribio.
     *
     * Los declarados, mas UNO si el ultimo recoge los que sobren: ese lleva
     * detras cuantos son.  Quien construya la firma a nivel de IR -- el
     * ayudante que crea el objeto, por ejemplo -- tiene que contarlo, o
     * declarara un parametro menos de los que le van a llegar.
     */
    size_t ir_param_count() const {
        return param_types.size() + (is_variadic ? 1u : 0u);
    }
    /** @} */
    uint32_t vtable_index = 0;
    /// `@Virtual` (structs polimorficos): el metodo se despacha por vtable.
    /// En un struct polimorfico `vtable_index` es el slot dentro de la vtable
    /// estatica (blob en static_data); en los no-virtuales no aplica.
    bool is_virtual = false;
    bool is_constructor = false;
    /// F1b: constructor `comptime T(expr)` de un struct value-type.  Se ejecuta
    /// en compile-time (ComptimeVM) y materializa el struct como datos; no
    /// emite llamada en runtime.  Propagado desde @c
    /// ClassMethodDecl::is_comptime.
    bool is_comptime = false;
    /// destructor `~ClassName()`.  Sin params, void retorno.
    /// El lowering lo invoca via CALLVIRT al exit del scope para
    /// instancias locales que NO escapan
    bool is_destructor = false;
    bool is_static = false;
    bool is_final = false;
    /// NS.6-ext: metodo anyadido por una @c extension / @c impl.  Dispatch
    /// ESTATICO (CALL directo a @c defining_class__name con @c this como primer
    /// arg), no entra en la vtable.  Inline-able.
    bool is_extension = false;
    /// el lowering, si encuentra un metodo expression-bodied
    /// con esta marca, sustituye la llamada por el cuerpo en el call
    /// site (sin CALLVIRT).  No es heredable: cada override decide su
    /// propio @c is_inline.
    bool is_inline = false;
    /// ctor "trivial zero-init": cuerpo del constructor
    /// solo asigna campos a valores que coinciden con el zero-init
    /// que ya hace el GC (`gc_heap.alloc` memset el payload a 0).  En
    /// ese caso, generate_new_helpers omite el callvirt al ctor en
    /// `__new_<X>` -- ahorra ~9 instrucciones VM por `new` para clases
    /// triviales.  Detectado en el type checker analizando el body.
    bool is_zero_init_ctor = false;
    /// Nombre de la clase donde el metodo esta DEFINIDO realmente
    /// (importante para herencia: un metodo heredado por @c Y de
    /// @c X tiene @c defining_class == "X" aunque lay.methods de Y
    /// lo liste).  El lowering usa este nombre para construir el
    /// label del code_vaddr (@c <defining_class>__<name>).
    std::string defining_class;
    /// Nombre del SIMBOLO real de la funcion en el .velb para metodos
    /// IMPORTADOS cross-module (p.ej. "std__wideint__u128____div__").  El
    /// lowering emite el CALL a este simbolo en vez de reconstruir
    /// "<struct_local>__<metodo>" (que llevaria el mangling del consumidor y no
    /// resolveria en el linker).  Vacio para metodos del propio modulo.
    std::string link_name;
    /// Debug info para stack traces.  Llenado por el type
    /// checker al ver el ClassMethodDecl original.  El lowering lo
    /// emite en __module_init via @c setmethdbg.
    std::string source_file;
    uint32_t source_line = 0;
};

/**
 * @struct StructLayout
 * @brief Layout completo de un @c struct: nombre + campos + tamano total.
 *
 * @c size_bytes es el tamano total (con padding al alineamiento del
 * campo mas grande, estilo C).  @c align_bytes es el alineamiento
 * requerido del struct cuando se almacena dentro de otro struct o
 * como campo aislado.
 */
struct StructLayout {
    std::string name;
    std::vector<StructFieldInfo> fields;
    /// Campos `static`: NO viven en cada instancia; su storage es una global
    /// sintetica `<Struct>__<campo>` (una sola por tipo).  Se listan aparte
    /// para que `Struct.campo` los resuelva (lectura/escritura) sin inflar el
    /// layout.
    std::vector<StructFieldInfo> static_fields;
    /// Campos `comptime`: existen SOLO en tiempo de compilacion (los consume el
    /// codigo comptime, p.ej. un `comptime char* name` para un hash).  NO
    /// ocupan espacio en la instancia runtime; se listan aparte para que un
    /// constructor/metodo comptime pueda resolver `this.campo`.
    std::vector<StructFieldInfo> comptime_fields;
    /// Tamano del buffer usado por la ComptimeVM al evaluar un
    /// constructor/metodo comptime: incluye los campos runtime (@c size_bytes)
    /// MAS los campos
    /// @c comptime apilados al final (cada uno con su @c offset asignado dentro
    /// de @c comptime_fields).  La materializacion del struct solo copia los
    /// primeros @c size_bytes (descarta la cola comptime).  == @c size_bytes si
    /// el struct no tiene campos comptime.
    uint32_t comptime_size_bytes = 0;
    /// Metodos del struct (value-type, dispatch estatico).  Reusa
    /// @c ClassMethodInfo; @c vtable_index/@c is_constructor no se usan
    /// (los structs no tienen vtable ni constructores con this(...)).
    /// @c defining_class lleva el nombre del struct (para el label
    /// @c <Struct>__<metodo> que emite el lowering como funcion libre).
    std::vector<ClassMethodInfo> methods;
    uint32_t size_bytes = 0;
    uint32_t align_bytes = 1;
    /// Overlay F1: el struct es una VISTA sobre un puntero base ajeno.  Un
    /// valor de este tipo ES un puntero (host) de 8 bytes; no se aloca buffer
    /// ni se zero-inicializa.  Los @c fields usan sus @c offset EXPLICITOS
    /// (@offset).
    bool is_union = false;    ///< union C-style: campos en offset 0, size=max.
    bool is_abstract = false; ///< `@Abstract`: no instanciable, solo base.
    /// true si el struct tiene >=1 metodo `@Virtual` (propio o heredado): es
    /// "polimorfico" y lleva un vptr en offset 0 (los campos empiezan en 8).
    /// El dispatch de sus metodos virtuales va por vtable estatica.
    bool is_polymorphic = false;
    /// Nombre del struct base (herencia estatica), o vacio.  Preservado del AST
    /// aunque el flatten ya haya aplanado los campos/metodos; lo usa el upcast
    /// de puntero `Derivado* -> Base*`.  Si apunta a una interfaz (no struct),
    /// el recorrido de la cadena para al no hallarlo en struct_layouts_.
    std::string super_name;
    bool is_overlay = false;
    /// Overlay: HUELLA estatica de la vista = max(offset+size) sobre los campos
    /// de offset constante, redondeada al alineamiento.  Es lo que `sizeof(T)`
    /// devuelve para un overlay (no @c size_bytes=8, que es el puntero):
    /// permite reservar `u8[sizeof(PEB)] buf;` con el tamano exacto para CREAR
    /// la vista. Los campos de offset dinamico (@offset(expr)) no cuentan
    /// (data-dependent).
    uint32_t overlay_extent = 0;
    /// Fase 1 interop C: categoria INFERIDA de los campos (clasificador de
    /// Fase 0).  @c cat_c_representable: el struct cruza la frontera C por
    /// valor (todos sus campos C-representables y sin `~Struct()`).
    /// @c cat_managed: posee un recurso de lifetime no-C (algun campo
    /// gestionado o un `~Struct()`) -> carril move-only + RAII.  NO son
    /// complementarios (un struct con un campo VirtualPtr no es ninguno).
    /// Se computan en @c compute_struct_categories tras registrar todos los
    /// structs; los consumidores (move-checker, header-gen) deben preferir
    /// @c TypeChecker::type_is_managed / @c type_is_c_representable (siempre
    /// correctos, incl. structs monomorphizados tarde).  @c cat_computed
    /// marca si ya se calcularon (false hasta el pase final).
    bool cat_c_representable = false;
    bool cat_managed = false;
    bool cat_computed = false;
    /// Fase 2b ownership: @c true si el struct tiene algun campo struct que es
    /// destructible (tiene `~Struct()` o a su vez @c has_destructible_field).
    /// Dispara la sintesis de un dtor implicito + la augmentacion RAII
    /// recursiva (el dtor del contenedor llama al dtor de cada campo struct).
    bool has_destructible_field = false;
    /// Ownership ruta B (copy-hook): @c true si el struct declara un metodo
    /// reservado `__clone__(this) -> Self`.  Es el copy-constructor IMPLICITO
    /// (estilo C++): el compilador lo invoca en cada sitio de COPIA del struct
    /// (`S b = a`, `obj.f = a`, paso por valor) en vez de un memcpy bit a bit,
    /// para que la copia tenga efecto (p.ej. ++refcount de shared<T>).  Un
    /// `return`/`move` NO lo invoca (es transferencia).  Ver
    /// doc/VMdoc/Vesta/SmartPointers.md y proj_ownership_hooks.
    bool has_copy_hook = false;
    /// marca `@Introspect` -- el lowering emite
    /// IntrospectInfo POD en static_data para que `find_type("Name")`
    /// runtime lo encuentre.
    bool is_introspect = false;
    ///  M6.a L.3: visibilidad cross-module.  Solo se exporta a
    /// `.vxi` si es @c true.  Sin keyword `public`/`private` en el
    /// source: @c true (default permisivo).  Sin esto en false, otros
    /// modulos podrian importar el struct via @c only.
    bool is_public = true;
};

/**
 * @brief El campo que se llama @p name, o nada.
 *
 * Vale para las dos clases de layout -- un struct y una clase -- porque la
 * pregunta es la misma y sus campos son del mismo tipo.  Escribirla dos veces
 * seria empezar a que una se quede atras.
 *
 * Se busca recorriendo: un struct tiene pocos campos y el orden importa --
 * es el orden en que estan en memoria --, asi que la lista es lo natural.  Lo
 * que no era natural es que este recorrido estuviera escrito diecisiete veces;
 * el dia que a alguien le sobren campos, aqui hay UN sitio donde poner otra
 * cosa.
 *
 * @param lay  El layout donde mirar.
 * @param name El nombre del campo.
 * @return Puntero al campo, o @c nullptr si ese struct no lo tiene.
 */
template <typename Layout>
inline const StructFieldInfo *find_field(const Layout &lay,
                                         const std::string &name) noexcept {
    for (const StructFieldInfo &f : lay.fields)
        if (f.name == name) return &f;
    return nullptr;
}

/**
 * @brief El metodo que se llama @p name, o nada.
 *
 * Se queda con el PRIMERO.  Con sobrecarga habria varios con el mismo nombre y
 * habria que mirar ademas los argumentos, pero eso lo resuelve el type checker
 * antes de llegar aqui: al bajar ya se sabe cual es.
 *
 * OJO: los constructores estan en esta misma lista.  Si lo que se busca es un
 * METODO, no vale esto -- un constructor puede llamarse igual, y quedarse con
 * el deja sin encontrar al que se buscaba.  Para eso hay que recorrer saltando
 * los que tengan @c is_constructor.
 *
 * @param lay  El layout donde mirar.
 * @param name El nombre del metodo.
 * @return Puntero al metodo, o @c nullptr si ese struct no lo tiene.
 */
template <typename Layout>
inline const ClassMethodInfo *find_method(const Layout &lay,
                                          const std::string &name) noexcept {
    for (const ClassMethodInfo &m : lay.methods)
        if (m.name == name) return &m;
    return nullptr;
}

/**
 * @struct EnumVariantInfo
 * @brief Resumen de una variante de enum (ADT, tagged union).
 *
 * @c tag es el indice asignado por el orden de declaracion (0..N-1).
 * @c field_types lista los tipos de los payload fields en orden.
 * Variantes sin payload tienen @c field_types vacio.
 */
struct EnumVariantInfo {
    std::string name;
    uint32_t tag = 0;
    int64_t int_value = 0; ///< Valor (enums con tipo base ENTERO C-style).
    /// Enums con VALOR de tipo NO-entero (float/string/struct/clase): el
    /// lowering de @c E.A baja directamente esta expresion AST (reusa el
    /// lowering de literales float/string/init-list).  Para backing entero
    /// se usa @c int_value (soporta auto-incremento sin AST).
    const ast::Expr *value_ast = nullptr;
    std::vector<Type> field_types;
    /// Offset EXPLICITO (en bytes) de cada payload field dentro del buffer.
    /// Vacio = layout uniforme del enum (`8 + 8*i`).  Se usa para los
    /// pseudo-enums sinteticos de @c Optional / @c Result (ver
    /// @c EnumLayout::is_optlike), donde el payload de @c Err vive en +16
    /// (no en +8) porque Ok(V) y Err(E) NO se solapan en el buffer.
    std::vector<uint32_t> field_offsets;
};

/**
 * @struct EnumLayout
 * @brief Layout completo de un @c enum.
 *
 * Layout de un valor del enum (igual para todas las variantes,
 * para que cualquier variante quepa):
 *   `[+0 i64 tag][+8 payload[0]][+16 payload[1]] ...`
 * @c size_bytes = 8 + 8 * max_payload_fields donde max_payload_fields
 * es el maximo numero de payload fields entre las variantes.  Cada
 * payload se almacena padded a 8 bytes para alineacion uniforme y
 * acceso simple por offset (sin necesidad de calcular offsets por
 * variante).
 */
struct EnumLayout {
    std::string name;
    std::vector<EnumVariantInfo> variants;
    bool is_valued = false;                     ///< enum con VALOR (`: u8`).
    PrimitiveKind backing = PrimitiveKind::I64; ///< tipo base si is_valued.
    /// Nombre del tipo de USUARIO cuando @c backing es STRUCT/CLASS (`enum
    /// Color : Rgb {..}`).  Un valor del enum ES un valor de este tipo.
    std::string backing_type_name;
    uint32_t size_bytes = 8;         ///< Minimum: solo el tag.
    uint32_t max_payload_fields = 0; ///< 0 si todas son sin payload.
    /// marca `@Introspect`.
    bool is_introspect = false;
    ///  M6.a L.3: visibilidad cross-module.
    bool is_public = true;
    /// Pseudo-enum sintetico para @c match sobre @c Optional<T> / @c
    /// Result<V,E>.  Cuando es true: (a) los payloads se guardan/leen con
    /// su tipo NATIVO (no promovidos a i64 con BITCAST como los enums
    /// reales), y (b) el offset del payload sale de @c
    /// EnumVariantInfo::field_offsets (no del layout uniforme).  Coincide
    /// con como los construye @c Some/None/Ok/Err y los lee
    /// @c unwrap/value/error/isPresent/isOk.
    bool is_optlike = false;
    /// La palabra del desplazamiento cero NO es una marca aparte: ES el valor,
    /// y lo que dice si hay algo es que no sea cero.  Pasa cuando el payload no
    /// puede valer cero y por eso no necesita marca (ver @c OptionalLayout).
    /// Quien compare tiene que mirar "distinto de cero", no "igual a la marca
    /// de la variante": el valor no vale uno, vale lo que valga.
    bool tag_is_value = false;
};

/**
 * @brief Construye un @c EnumLayout sintetico para tratar @c Optional<T>
 * o @c Result<V,E> como un enum de dos variantes en @c match.
 *
 * Convenio de layout (identico al que emiten @c Some/None/Ok/Err):
 *   - @c Optional<T>: buffer de 16 bytes; `[+0 i64 flag]` (None=0, Some=1),
 *     Some.payload en +8 con tipo @p st.pointee.
 *   - @c Result<V,E>: buffer de 24 bytes; `[+0 i64 tag]` (Err=0, Ok=1),
 *     Ok.payload en +8 (@p st.pointee), Err.payload en +16 (@p st.pointee2).
 *
 * @param st Tipo del scrutinee (kind OPTIONAL o RESULT).
 * @return Layout con @c is_optlike=true, variantes ordenadas por tag.
 */
/**
 * @struct OptionalLayout
 * @brief Como esta puesto en memoria un `Optional<T>`.
 *
 * No solo cuanto ocupa: TAMBIEN donde esta el valor y si hace falta una marca
 * aparte.  Ese tercer dato es el que permite que ocupe menos: un `Optional` de
 * algo que ya tiene un valor imposible -- un puntero, que no puede ser nulo si
 * el valor esta presente -- no necesita marca, porque el propio valor la lleva,
 * y entonces mide ocho en vez de dieciseis.
 *
 * Vive con el TIPO y no con el bajado porque es una propiedad del tipo: la
 * preguntan el que emite codigo, el que resuelve un `match` y el que calcula el
 * tamano de un struct que lo lleva de campo.  Repartida, "aqui no hace falta
 * marca" habria que escribirlo en los tres.
 */
/**
 * @struct ResultLayout
 * @brief Como esta puesto en memoria un `Result<V,E>`.
 *
 * La marca en el cero, el valor detras y el error detras del valor.  Los dos
 * payloads se guardan uno al lado del otro aunque solo uno este vivo cada vez.
 *
 * Vive aqui, con el tipo, por lo mismo que @ref OptionalLayout: lo preguntan el
 * emisor, el `match` y el calculo del tamano de un struct que lo lleve de
 * campo, y ninguno de los tres puede permitirse una respuesta propia.
 */
struct ResultLayout {
    uint32_t bytes = 24;        ///< Lo que ocupa el conjunto.
    uint32_t value_offset = 8;  ///< Donde empieza el valor.
    uint32_t error_offset = 16; ///< Donde empieza el error.
};

struct OptionalLayout {
    uint32_t bytes = 16;       ///< Lo que ocupa el conjunto.
    uint32_t value_offset = 8; ///< Donde empieza el valor.
    bool has_tag = true;       ///< Si la marca va aparte, en el cero.
};

/**
 * @brief Presenta un `Optional`/`Result` como un enum de dos variantes, que es
 *        lo que el `match` sabe recorrer.
 *
 * @param st  El tipo.
 * @param opt Como esta puesto en memoria, cuando @p st es un `Optional`.  Lo
 *            decide @c TypeChecker::optional_layout y se pasa hecho: esta
 *            funcion vive en una cabecera y no alcanza los layouts de struct
 *            que hacen falta para calcularlo.  Antes lo llevaba clavado --
 *            tamano dieciseis, payload en el ocho --, que era el septimo sitio
 *            que describia la misma disposicion por su cuenta.
 */
inline EnumLayout build_optlike_enum_layout(const Type &st,
                                            const OptionalLayout &opt,
                                            const ResultLayout &res) {
    EnumLayout lay;
    lay.is_optlike = true;
    lay.max_payload_fields = 1;
    if (st.kind == PrimitiveKind::OPTIONAL) {
        lay.name = "Optional";
        lay.size_bytes = opt.bytes;
        lay.tag_is_value = !opt.has_tag;
        // None (tag 0, sin payload).
        EnumVariantInfo vn;
        vn.name = "None";
        vn.tag = 0;
        lay.variants.push_back(std::move(vn));
        // Some (tag 1, payload T en +8).
        EnumVariantInfo vs;
        vs.name = "Some";
        vs.tag = 1;
        vs.field_types.push_back(st.pointee ? *st.pointee
                                            : Type{PrimitiveKind::I64});
        vs.field_offsets.push_back(opt.value_offset);
        lay.variants.push_back(std::move(vs));
    } else {
        // Result<V,E>.
        lay.name = "Result";
        lay.size_bytes = res.bytes;
        // Err (tag 0, payload E).
        EnumVariantInfo ve;
        ve.name = "Err";
        ve.tag = 0;
        ve.field_types.push_back(st.pointee2 ? *st.pointee2
                                             : Type{PrimitiveKind::I64});
        ve.field_offsets.push_back(res.error_offset);
        lay.variants.push_back(std::move(ve));
        // Ok (tag 1, payload V).
        EnumVariantInfo vo;
        vo.name = "Ok";
        vo.tag = 1;
        vo.field_types.push_back(st.pointee ? *st.pointee
                                            : Type{PrimitiveKind::I64});
        vo.field_offsets.push_back(res.value_offset);
        lay.variants.push_back(std::move(vo));
    }
    return lay;
}

/**
 * @struct ClassLayout
 * @brief Layout completo de una clase Vesta.
 *
 * Reusa @c StructFieldInfo para los campos (offset, size, type).
 * @c size_bytes es el tamano total de la instancia (sin contar el
 * @c ObjectHeader: el ClassRegistry suma sizeof(ObjectHeader) al
 * registrar).  @c methods enumera todos los metodos en orden de
 * declaracion; el indice en el vector es el vtable_index.
 */
struct ClassLayout {
    std::string name;
    std::string super_name;
    std::vector<std::string> interface_names;
    std::vector<StructFieldInfo> fields; // solo campos de instancia
    std::vector<StructFieldInfo> static_fields;
    std::vector<ClassMethodInfo> methods;
    uint32_t size_bytes = 0;
    /// Para clases importadas cross-module via  M:
    ///   - @c name lleva el nombre mangled (e.g. "buffer__Buffer")
    ///     usado para identidad de tipo dentro del consumer.
    ///   - @c imported_helper_suffix lleva el nombre LOCAL en el modulo
    ///     dep (e.g. "Buffer") que es el sufijo del helper
    ///     `__new_<helper_suffix>` ya emitido en el .vel del dep.
    /// Para clases locales del consumer, este campo queda vacio y el
    /// lowering usa @c name como sufijo del helper (comportamiento
    /// historico).
    std::string imported_helper_suffix;
    /// Numero de fields heredados (los primeros @c inherited_field_count
    /// elementos de @c fields fueron copiados de la superclase y NO
    /// deben re-emitirse como deffield en __module_init).  El resto
    /// son los fields propios de esta clase.
    uint32_t inherited_field_count = 0;
    /// Idem para static_fields.
    uint32_t inherited_static_field_count = 0;
    /// Si esta declaracion proviene de @c interface (sin instancias,
    /// metodos abstractos).  El lowering omite la generacion de
    /// __new_<X> y de bodies de metodo, pero SI emite defclass para
    /// que sea localizable via reflexion.  El validador rechaza @c new
    /// X() para layouts con esta marca.
    bool is_interface = false;
    /**
     * @brief `final class C` (o `@Final`): nadie puede extenderla.
     *
     * El comprobador rechaza cualquier clase que la ponga como super.  Sirve
     * ademas para decidir por lo BARATO si sus metodos se despachan por tabla:
     * si nadie puede extenderla, no hay que recorrer el programa buscando quien
     * lo hace (ver @c Lowering::class_has_vtable).
     *
     * Ese atajo es SOLO valido mientras la prohibicion se cumpla de verdad:
     * marcar una clase como final y dejar que la extiendan igual daria llamada
     * directa donde hace falta tabla, y el metodo de la derivada no se
     * ejecutaria.  De ahi que el rechazo y este campo entraran a la vez.
     */
    bool is_final = false;
    /// true si la clase es @c @Aspect (contiene @Before/@After/@Around).
    /// Habilita el devirt monomorfico saber que CALLVIRTs no se pueden
    /// resolver estaticamente en este modulo (los advice chains corren
    /// al despachar dinamicamente; un CALL directo los saltaria).
    bool is_aspect = false;
    /// marca `@Introspect` -- el lowering emite
    /// IntrospectInfo POD en static_data para que `find_type("Name")`
    /// runtime lo encuentre.
    bool is_introspect = false;
    /// true si la clase declara `~ClassName()`.  Computado tras
    /// agregar todos los metodos.  El type checker usa este flag para
    /// rechazar escapes ilegales: una instancia con destructor NO puede
    /// asignarse a un FieldAccessExpr (objeto/struct field) ni a un
    /// IndexExpr (slot de array nativo) porque rompe el modelo RAII --
    /// el destructor solo se invoca al exit del scope local; sin
    /// scope owner el handle quedaria con destructor pendiente
    /// indefinido.  Returns siguen permitidos (el caller toma owner).
    bool has_destructor = false;
    /// true si la clase tiene al menos un campo (de instancia)
    /// cuyo tipo es CLASS y esa clase tiene su propio @c has_destructor
    /// (transitivamente).  En ese caso la regla de escape se RELAJA:
    /// asignar una instancia destructible a `obj.field` es legal porque
    /// el destructor del contenedor (auto-sintetizado si no existe)
    /// invocara recursivamente el destructor del field al destruirse.
    ///
    /// Para clases con @c has_destructible_field == true pero sin
    /// destructor declarado por el usuario, el lowering sintetiza un
    /// destructor implicito que solo recorre los fields destructibles.
    ///
    /// Importante: el computo de este flag requiere un punto-fijo
    /// porque las clases pueden ser mutuamente recursivas (e.g.
    /// LinkedList<T> { Node head; } y Node { Node next; T payload; }).
    /// El TypeChecker itera hasta estabilizarse antes de usar este flag.
    bool has_destructible_field = false;
    /// la clase ya esta registrada en runtime (e.g. FatalError
    /// pre-creada por @c init_exception_classes en cada VM).  El
    /// lowering NO debe emitir @c defclass / @c deffield / @c defmethod
    /// para esta clase; tampoco generar @c __new_<X> ni bodies de
    /// metodo.  El @c findclass(name) en runtime ya la encuentra.
    /// Acceso a campos via @c getfield con offsets fijos del ABI.
    bool is_runtime_predefined = false;
    ///  M6.a L.3: visibilidad cross-module.
    bool is_public = true;
};

/**
 * @struct Symbol
 * @brief Entrada de la tabla de simbolos.
 *
 * @c type sirve para Variable/Param.  Para Function se ignora y se
 * consulta @c sig_index en una tabla aparte (vector contiguo).
 */
struct Symbol {
    SymbolKind kind = SymbolKind::Variable;
    Type type{};
    uint32_t sig_index =
        0; ///< Indice en TypeChecker::function_sigs_, si kind==Function.
    bool is_const = false;
    /// Nombre del alias de tipo cuando el simbolo se declaro con un alias
    /// "magico" como `Class`, `Method`, `Field`, `Object`.  El tipo
    /// subyacente es i64 (para reflexion: handles del ClassRegistry).
    /// Permite que `Class cls = ...` registre cls -> "Class" y que
    /// `cls.getMethod("foo")` baje a `getMethod(cls, "foo")` sin que
    /// el usuario escriba la builtin standalone.  Vacio para variables
    /// normales.
    std::string reflection_alias;
    ///  M.7: indice en @c TypeChecker::imported_namespaces_
    /// cuando @c kind == SymbolKind::Namespace.  Sin uso para los
    /// demas kinds.
    uint32_t ns_index = 0;
    ///  AS inc.2: registro fisico canonico (rax/r8/v0...) si la
    /// variable se declaro con storage-class @c register("reg").  Vacio
    /// para variables normales.  Usado para detectar conflicto same-reg
    /// dentro del mismo scope.
    std::string reg_binding;
};

/**
 * @brief Registra las funciones virtuales del compilador (`vesta_comptime`).
 *
 * Idempotente y segura desde cualquier hilo.  La llama el TypeChecker al
 * construirse y tambien el arranque de la VM: un `.velb` puede llevar un
 * cuerpo comptime como codigo muerto, y su import debe RESOLVER aunque nadie
 * lo llame.
 */
void register_comptime_virtual_fns();

/**
 * @brief Registra como error de compilacion un fallo del codigo comptime.
 *
 * La llama quien ejecuta ese codigo cuando el proceso muere sin que nadie
 * capture el fallo.  Con un `try` que lo capture, el proceso no muere y esto
 * no se invoca.
 *
 * @param msg Mensaje del fallo, ya formado.
 */
void report_comptime_fatal(const std::string &msg);

/**
 * @brief Guarda el texto de un `static_assert` y devuelve su indice.
 *
 * El mensaje no viaja por la maquina virtual: por ella solo va el indice.  La
 * direccion de un literal pertenece al espacio de la VM y el proceso anfitrion
 * no puede dereferenciarla.
 *
 * @param text Mensaje de la asercion.
 * @return Indice estable con el que el helper lo recupera.
 */
uint64_t intern_static_assert_msg(const std::string &text);

/**
 * @class TypeChecker
 * @brief Pase de comprobacion sobre un ModuleNode.
 */
class TypeChecker {
  public:
    /**
     * @brief Construye el checker sobre un modulo y su sumidero de errores.
     *
     * @param mod   Modulo AST a verificar.  Sera modificado solo en
     *              los campos result_type de las expresiones internas.
     * @param diags Sumidero de diagnosticos.
     */
    TypeChecker(ast::ModuleNode &mod, Diagnostics &diags);

    /**
     * @brief Bytecode del conjunto comptime, ya compilado y en memoria.
     *
     * Se pone ANTES de @c check().  Es la via preferente: sin esto se cae a la
     * ruta que llega por variable de entorno, que obliga a releer el fichero en
     * cada modulo.  Los bytes son del llamante.
     *
     * @param bytes Bytecode, o @c nullptr para no usar esta via.
     */
    void set_comptime_artifact(const std::vector<uint8_t> *bytes) noexcept {
        comptime_artifact_ = bytes;
    }
    ~TypeChecker(); // limpia g_active_typechecker thread_local

    /**
     * @brief Ejecuta el checker.
     *
     * @return @c true si no hubo errores.  Si devuelve @c false, el
     *         lowering NO debe ejecutarse (hay nodos sin tipo).
     */
    bool run();

    /**
     * @brief Acceso de solo lectura a la tabla de layouts de struct.
     *
     * El lowering la consulta para calcular offsets de campos y
     * tamano total en bytes al reservar variables de tipo struct.
     */
    const std::unordered_map<std::string, StructLayout> &
    struct_layouts() const noexcept {
        return struct_layouts_;
    }

    /**
     * @brief Fase 1 interop C: clasifica un @c Type via el clasificador de
     *        Fase 0 con un resolver respaldado por @c struct_layouts_.
     *
     * Fuente de verdad (siempre correcta, incl. structs monomorphizados
     * tarde) -- los consumidores (move-checker, header-gen) deben preferir
     * estos metodos a los flags cacheados @c StructLayout::cat_*.
     *
     * @c type_is_c_representable: cruza la frontera C por valor (ABI C).
     * @c type_is_managed: posee un recurso de lifetime no-C (move-only+RAII).
     */
    bool type_is_c_representable(const Type &t) const;
    bool type_is_managed(const Type &t) const;

    /**
     * @brief Acceso de solo lectura a la tabla de layouts de clases.
     *
     * El lowering la consulta para emitir el bloque __module_init
     * (defclass + deffield + defmethod) y para resolver offsets de
     * campos al traducir GETFIELD / SETFIELD.
     */
    const std::unordered_map<std::string, ClassLayout> &
    class_layouts() const noexcept {
        return class_layouts_;
    }

    /**
     * @brief Upcast implicito clase concreta -> interfaz.
     *
     * Devuelve true si @p value es una CLASE concreta que implementa la
     * INTERFAZ @p target (directamente o via su cadena de super).  Habilita
     * el polimorfismo: `ISh s = new Sq();`, `s = new Sq();`, `use(new Sq())`
     * cuando `use(ISh)`.  Sin esto el type-checker rechazaba el upcast y el
     * polimorfismo con tipo concreto desconocido era inalcanzable.
     */
    bool value_assignable_to_interface(const Type &target,
                                       const Type &value) const noexcept;

    /**
     * @brief Acceso de solo lectura a la tabla de layouts de enums.
     *
     * El lowering la consulta para emitir el codigo de constructor de
     * variante (STORE de tag + payloads) y de match (jumptable +
     * extraccion de bindings via LOAD por offset).
     */
    const std::unordered_map<std::string, EnumLayout> &
    enum_layouts() const noexcept {
        return enum_layouts_;
    }

    /**
     * @brief Acceso de solo lectura al ModuleNode AST.   M.L7
     * lo usa @c export_typechecker_to_vxi para iterar
     * @c GlobalVarDecl y extraer sus tipos sin tener que mantener
     * un mapa paralelo en el TypeChecker.
     */
    const ast::ModuleNode &ast_module() const noexcept { return mod_; }

    /**
     * @brief Anyade una plantilla generica / comptime fn / @Macro re-exportada
     * a los exports de ESTE modulo (via `public import`).  El emitter del
     * `.vxi` la vuelca como fuente para que los consumidores del re-exportador
     * la vean.
     */
    void add_reexported_generic_template(ast::GenericTemplateExport tex) {
        mod_.generic_template_exports.push_back(std::move(tex));
    }

    /// #cross-module-generics: inyecta un decl (plantilla generica o
    /// concepto) re-parseado de un `.vxi` importado en este modulo, para
    /// que se pueda monomorphizar `Caja<i64>` cross-module.  Debe llamarse
    /// ANTES de run() (que registra los templates).  Idempotente por nombre.
    void inject_decl(std::unique_ptr<ast::Node> decl) {
        mod_.decls.push_back(std::move(decl));
    }
    bool has_injected_template(const std::string &name) const noexcept {
        return injected_templates_.count(name) > 0;
    }
    void mark_injected_template(const std::string &name) {
        injected_templates_.insert(name);
    }

    /**
     * @brief Resuelve un TypeNode AST a su Type semantico.
     *
     * Aplica resolucion de aliases (typedef/using) y reconocimiento
     * de structs.  Expuesto publico para que el lowering pueda
     * resolver el tipo declarado de variables locales sin duplicar
     * la logica de bilinkeo nombre->tipo.
     */
    Type resolve_type_node(const ast::TypeNode *tn) const {
        return type_from_node(tn);
    }

    /**
     * @brief Genera (o devuelve cacheado) el nombre concreto de un
     *        instanciado generico.  Public para que el pre-pase de
     *        monomorphizacion (helpers static en type_checker.cpp)
     *        pueda invocarlo.  Detalles en la docstring del impl.
     */
    std::string monomorphize_class(const std::string &template_name,
                                   const std::vector<Type> &args,
                                   const SourceLoc &loc);

    /**
     * @brief L2.3: monomorphizacion de enum generico.  Crea una copia
     * concreta del template (con type_params=[T,U,...]) sustituyendo
     * los parametros por args concretos.  Devuelve el nombre mangled
     * (e.g. "Maybe_i32") que se usa como struct_name del Type STRUCT.
     */
    std::string monomorphize_enum(const std::string &template_name,
                                  const std::vector<Type> &args,
                                  const SourceLoc &loc);

    /**
     * @brief Monomorphizacion de struct generico.  Crea una copia concreta
     * del template (`struct Box<T> { T v; }`) sustituyendo los type_params
     * por args concretos, la anyade a @c mod_.decls para que @c collect_globals
     * construya su @c StructLayout (size/offsets/destructibilidad/copy-hook) y
     * @c lower_struct_methods baje sus metodos.  Devuelve el nombre mangled
     * (e.g. "Box_i32") usado como @c struct_name del Type STRUCT.  Idempotente.
     */
    std::string monomorphize_struct(const std::string &template_name,
                                    const std::vector<Type> &args,
                                    const SourceLoc &loc);

    /**
     * @brief Aplana la herencia ESTATICA de structs y resuelve `Self`
     *
     * Corre en pre_mono (antes de @c collect_globals).  Por CADA struct
     * concreto S (base o derivado): (a) embebe los campos de su cadena de bases
     * al INICIO (raiz primero, layout-compatible); (b) hereda los metodos de la
     * cadena (el mas derivado gana por nombre); (c) sustituye el marcador
     * `Self` por el tipo concreto S en firmas y cuerpos, via @c
     * GenSubst{["Self"],[STRUCT S]} +
     * @c clone_type_with_subst / @c clone_stmt -- la misma maquinaria de los
     * genericos.  Tras esto el resto del compilador solo ve structs concretos
     * sin `Self`.  Aplica las prohibiciones: `Self` por VALOR en el layout,
     * `Self` en un metodo `@Virtual`.  Ver [[proj_struct_self_inheritance]].
     */
    void flatten_struct_inheritance();

    /**
     * @brief Verifica que cada struct que declara `: IConcepto` satisface ese
     *        concepto.  Coste cero: es una comprobacion comptime (misma via que
     *        `where T: C`), no genera codigo ni vtables.  Distinto de heredar
     * de un `@Abstract` (que aporta campos + implementacion): aqui la interfaz
     * solo OBLIGA la forma (contrato), no da codigo.
     */
    void verify_struct_interface_conformance();

    /**
     * @brief @Virtual: true si `value` es asignable a `target` por upcast de
     * puntero `Derivado* -> Base*` (herencia estatica de structs).  Recorre la
     * cadena super_name del pointee de @p value buscando el pointee de @p
     * target. Layout-compatible (el derivado embebe la base al inicio, vptr en
     * offset 0).
     */
    bool struct_ptr_upcast_ok(const Type &target, const Type &value) const;

    /// @brief Resuelve los @c @complexity que el parser dejo pendientes.
    ///
    /// Su `when:` habla del parametro de tipo (`is_float<T>()`), asi que solo
    /// tiene respuesta aqui, con T ya concreto: el coste de un metodo generico
    /// depende de T de verdad (`atomic<i64>::fetch_add` es un `lock xadd` y
    /// `atomic<f64>::fetch_add` un bucle CAS).  Vuelca el que casa a los campos
    /// resueltos de @p nm y vacia su lista de pendientes.
    /// @param nm el metodo CLONADO (la instanciacion).
    /// @param m  el metodo de la PLANTILLA (de donde salen los pendientes).
    void resolve_pending_complexity_(ast::ClassMethodDecl &nm,
                                     const ast::ClassMethodDecl &m,
                                     const vxgen::GenSubst &g,
                                     const SourceLoc &loc);

    /// Resuelve los @complexity de un metodo NO generico (todos sus atomos
    /// deben ser de target: aqui no hay T al que referirse).
    void resolve_complexity_no_generico_(ast::ClassMethodDecl &m);

    /// Recorre las decls resolviendo los @complexity pendientes.  Las
    /// instanciaciones ya vienen resueltas del clon; las plantillas se saltan
    /// (no producen IR y sus `when:` sobre T no tienen respuesta fuera de una
    /// instanciacion).
    void
    resolve_complexity_decls_(std::vector<std::unique_ptr<ast::Node>> &decls);

    /**
     * @brief Monomorphizacion de funcion generica.  Clona la FunctionDecl
     * template sustituyendo los type_params, la anyade a @c mod_.decls (para
     * que collect_globals registre su firma y el lowering la baje) y devuelve
     * el nombre mangled (e.g. "id_i64").  Idempotente.
     */
    std::string monomorphize_function(const std::string &template_name,
                                      const std::vector<Type> &args,
                                      const SourceLoc &loc);

    /**
     * @brief Monomorphizacion de un METODO generico `R metodo<U>(...)` (#4).
     *
     * Clona el @c ClassMethodDecl template del struct/clase @p container
     * sustituyendo sus @c method_type_params por @p targs concretos,
     * produciendo `metodo_<mangle(targs)>`.  El metodo concreto se anyade
     * AL LAYOUT inmediatamente (para que la resolucion de la llamada actual
     * lo encuentre) y se ENCOLA en @c pending_method_monos_ para anyadirlo
     * al AST del contenedor + chequear su body tras @c check_functions
     * (evita invalidar el iterador del bucle de metodos al estar dentro de
     * uno).  Dispatch SIEMPRE estatico; cero artefacto generico en runtime.
     * Idempotente por (container, mangled).  Devuelve el nombre mangled o
     * cadena vacia si error.  Implementado en generic_methods.cpp.
     */
    std::string monomorphize_method(const std::string &container,
                                    bool is_struct,
                                    const ast::ClassMethodDecl *tmpl,
                                    const std::vector<Type> &targs,
                                    const SourceLoc &loc);

    /**
     * @brief Drena @c pending_method_monos_: anyade cada metodo clonado al
     * AST de su struct/clase y chequea su body.  El chequeo puede encolar
     * mas (un metodo generico que llama a otro); se repite hasta punto fijo
     * (cota dura defensiva).  Lo invoca @c check_functions al final.
     * Implementado en generic_methods.cpp.
     */
    void drain_pending_method_monos();

    /**
     * @brief Busca el @c ClassMethodDecl template (con method_type_params
     * no vacios) de @p method_name en el struct/clase @p container.
     * Devuelve nullptr si no existe o no es generico.  Usado por el hook
     * de @c check_call.  Implementado en generic_methods.cpp.
     */
    const ast::ClassMethodDecl *
    find_generic_method_template(const std::string &container,
                                 const std::string &method_name) const;

    /**
     * @brief Hook de @c check_call para metodos genericos (#4).  Si
     * @p fa->field_name es un metodo generico de @p bt (struct/clase),
     * resuelve los type-args (explicitos en @c e->type_args o inferidos
     * de los argumentos), monomorphiza via @c monomorphize_method y
     * reescribe @c fa->field_name al nombre concreto (`metodo_<U>`),
     * dejando que la resolucion normal de la llamada lo encuentre.
     * Devuelve true si reescribio (era generico).  Si no es generico,
     * false (la resolucion sigue su curso).  En generic_methods.cpp.
     */
    bool try_monomorphize_method_call(ast::CallExpr *e,
                                      ast::FieldAccessExpr *fa, const Type &bt);

    /// L2.3: el nombre es un enum template generico?  Acepta el nombre CRUDO,
    /// el cualificado por namespace (`col.Maybe` -> `col__Maybe`) y el simple
    /// con un unico match `<ns>__<name>` (resolucion namespace-relativa).
    bool is_generic_enum_template(const std::string &name) const;

    /// El nombre es un struct template generico?  (misma resolucion que
    /// is_generic_enum_template.)
    bool is_generic_struct_template(const std::string &name) const;

    /// El nombre es una funcion generica (template)?
    bool is_generic_fn_template(const std::string &name) const noexcept {
        if (generic_fn_templates_.count(name) > 0) return true;
        // Por el nombre publico solo cuenta si de verdad lleva a una plantilla
        // REGISTRADA.  Decir que si sin comprobarlo es peor que decir que no:
        // quien pregunta lo siguiente que hace es buscarla en la tabla y usar
        // lo que encuentre, y ahi no habria nada que usar.
        auto it = generic_fn_public_names_.find(name);
        return it != generic_fn_public_names_.end() &&
               generic_fn_templates_.count(it->second) > 0;
    }

    /**
     * @brief Ata el nombre PUBLICO de una plantilla importada a su label real.
     *
     * Una funcion normal importada se registra con el nombre que el usuario
     * escribe y lleva su label real aparte (@c FunctionSig::mangled_label): el
     * resolutor de nombres ve `add`, y quien emite el codigo, `std__numeric__
     * add`.  Las plantillas genericas no tenian ese puente -- al inyectarlas se
     * las renombraba al label y el nombre corto dejaba de existir --, asi que
     * `add<i64>(...)` no se reconocia como generica: se trataba como una
     * llamada normal, no se instanciaba ninguna version concreta, y el fallo
     * aparecia mucho despues, al enlazar, como un simbolo que nadie define.
     *
     * @param public_name Nombre tal y como se escribe en el modulo de origen.
     * @param mangled Label con el que la plantilla quedo registrada.
     */
    void register_generic_fn_alias(const std::string &public_name,
                                   const std::string &mangled) {
        if (public_name.empty() || public_name == mangled) return;
        generic_fn_public_names_[public_name] = mangled;
    }

    /**
     * @brief Traduce un nombre de plantilla al que esta registrado.
     * @param name Nombre visto en la llamada.
     * @return El label real si @p name era un nombre publico; si no, @p name.
     */
    const std::string &
    resolve_generic_fn_name(const std::string &name) const noexcept {
        auto it = generic_fn_public_names_.find(name);
        return it == generic_fn_public_names_.end() ? name : it->second;
    }

    /// #6: registro de conceptos de usuario (consultado por concepts.cpp).
    const std::unordered_map<std::string, const ast::ConceptDecl *> &
    concepts() const noexcept {
        return concepts_;
    }

    /// Conformidades declaradas (`impl Concepto for Tipo`), por nombre de tipo.
    /// Se expone porque quien vuelca el conocimiento del programa la necesita:
    /// sin ella tendria que reevaluar los predicados que aqui ya se
    /// comprobaron, pagando dos veces por la misma respuesta.
    const std::unordered_map<std::string, std::unordered_set<std::string>> &
    impl_conformances() const noexcept {
        return impl_conformances_;
    }

    /**
     * @brief Verifica los constraints (#6) de un generico al monomorphizar.
     *
     * Para cada @c TypeBound, localiza el type-arg concreto correspondiente
     * (via @p params -> @p args) y evalua cada concepto exigido sobre el.
     * Si alguno no se satisface, emite un error claro citando el tipo, el
     * type-param y el concepto.  Cero codigo emitido: las constraints
     * desaparecen tras el check.  Implementado en src/vx/concepts.cpp.
     */
    void check_type_bounds(const std::vector<ast::TypeBound> &bounds,
                           const std::vector<std::string> &params,
                           const std::vector<Type> &args, const SourceLoc &loc);

    /**
     * @brief Evalua los bounds encolados por @c check_type_bounds (#6).
     *
     * @c check_type_bounds NO evalua en el acto: encola (concepto, tipo
     * concreto, param, loc).  La evaluacion se DIFIERE hasta que los layouts
     * de clases/structs existen (los conceptos estructurales y has_method/
     * sizeof de tipos de usuario los necesitan).  Se invoca tras
     * @c collect_globals y al final de @c check_functions.  Implementado en
     * src/vx/concepts.cpp.
     */
    void verify_pending_type_bounds();

    /**
     * @brief Disponibilidad condicional de un metodo por su clausula `where`
     * (#6).
     *
     * Modelo Rust `impl<T: Bound>` / Swift `extension where`.  Un metodo de un
     * struct/clase generico con `where T: Concepto` (sobre un type-param del
     * CONTENEDOR) SOLO existe en las instanciaciones cuyo type-arg satisface el
     * concepto.  Devuelve @c false si algun bound sobre un type-param del
     * contenedor no se cumple -> el metodo se OMITE (ni se clona ni se
     * type-checkea), como si no estuviera declarado para ese T.  Los bounds
     * sobre type-params del PROPIO metodo (`m<U: C>`) se copian a
     * @p method_only para verificarse al monomorphizar el metodo.
     *
     * Se evalua en pre_mono (antes de collect_globals), asi que solo son
     * fiables los conceptos evaluables SIN layouts: kind-based (Integer,
     * Numeric, Float, Signed, Unsigned, Bool, Char, Pointer, Scalar, ...) y
     * predicados is_x / sizeof sobre primitivos.  Un concepto estructural
     * (has_method) sobre un type-param del contenedor se veria como no
     * satisfecho aqui; no debe usarse para filtrar existencia.
     */
    bool
    method_available_for_subst(const ast::ClassMethodDecl *m,
                               const std::vector<std::string> &container_params,
                               const std::vector<Type> &container_args,
                               std::vector<ast::TypeBound> &method_only);

    /// Registra @p m como no-disponible en la instanciacion @p
    /// container_mangled (por su `where`), para dar un mensaje claro si se
    /// intenta llamar.
    void record_unavailable_method(const std::string &container_mangled,
                                   const ast::ClassMethodDecl *m);

    /**
     * @brief Elige la especializacion de struct mas especifica para @p args
     * (#7).
     *
     * Busca en @c struct_specializations_[base] la especializacion (total o
     * parcial) cuyo patron matchee @p args; entre varias, la MAS ESPECIFICA
     * (exacta > patron).  Si encuentra una, devuelve su @c StructDecl y
     * rellena @p out_params / @p out_args con los bindings de sus params
     * frescos (vacios para una especializacion total).  Si no hay match,
     * devuelve nullptr (el llamante usa el template primario).  Implementado
     * en src/vx/specialization.cpp.
     */
    const ast::StructDecl *select_struct_specialization(
        const std::string &base, const std::vector<Type> &args,
        std::vector<std::string> &out_params, std::vector<Type> &out_args);
    /// #7: idem para CLASES genericas.  En specialization.cpp.
    const ast::ClassDecl *select_class_specialization(
        const std::string &base, const std::vector<Type> &args,
        std::vector<std::string> &out_params, std::vector<Type> &out_args);
    /// #7: idem para FUNCIONES genericas.  En specialization.cpp.
    const ast::FunctionDecl *select_function_specialization(
        const std::string &base, const std::vector<Type> &args,
        std::vector<std::string> &out_params, std::vector<Type> &out_args);

    /// L2.3: stack de contexto.  Cuando check_var_decl o check_assign
    /// procesa `Maybe<i32> a = Maybe.Some(42)`, push ("Maybe","Maybe_i32")
    /// para que `Maybe.Some(42)` o `Maybe.None` resuelvan al mangled
    /// correcto.  Pop tras el check.
    void push_expected_enum(const std::string &templ, const std::string &mang) {
        expected_enum_stack_.push_back({templ, mang});
    }
    void pop_expected_enum() noexcept {
        if (!expected_enum_stack_.empty()) expected_enum_stack_.pop_back();
    }
    const std::string *
    expected_enum_mangled(const std::string &templ) const noexcept {
        for (auto it = expected_enum_stack_.rbegin();
             it != expected_enum_stack_.rend(); ++it) {
            if (it->first == templ) return &it->second;
        }
        return nullptr;
    }

    /**
     * @brief Accesor publico a la firma de una funcion top-level.
     *
     * El lowering lo usa en @c lower_call para detectar parametros de
     * tipo STRING y promover automaticamente literales pasados como
     * argumento (`helper("hola")`) a StringObject inline via STRMAKE.
     * Sin esta promocion, el callee recibiria la direccion VM del
     * literal en vez del GcHandle al StringObject -> crash en strraw.
     *
     * @param name Nombre de la funcion.
     * @return Puntero a su FunctionSig o nullptr si no es funcion conocida.
     */
    const FunctionSig *function_sig_by_name(const std::string &name) const;

    /**
     * @brief Accesor publico al mapa nombre -> indice de firma.
     *
     * El lowering lo recorre en su pase 1 para registrar el tipo de retorno
     * de las funciones IMPORTADAS de otro modulo.  Esas funciones NO estan en
     * @c mod_.decls (solo viven como @c FunctionSig inyectada desde el .vxi),
     * asi que sin este recorrido el caller no sabria que una fn cross-modulo
     * devuelve Optional/Result/enum/... y omitiria el retbuf hidden de la
     * convencion SRET (escritura a puntero basura -> SEGV).
     *
     * @return Mapa nombre publico -> indice en @c function_sigs_.
     */
    const std::unordered_map<std::string, uint32_t> &
    function_sigs_by_name() const noexcept {
        return sig_by_name_;
    }

    /**
     * @brief Si @p name es una funcion extern, devuelve "@extern:<lib>:<name>".
     *        En cualquier otro caso devuelve "".
     *
     * Usado por @c unique_with / @c shared_with en el lowering para
     * generar el literal_deleter de la CleanupAction con el formato
     * que @c emit_cleanups_all sabe interpretar como CALLN a libreria
     * nativa (en lugar de CALLVM a funcion Vesta).
     */
    std::string lookup_extern_qualified(const std::string &name) const;

  private:
    // -----------------------------------------------------------------
    // Pases globales.
    // -----------------------------------------------------------------

    /**
     * @brief Pase 1: registra funciones y variables globales en el scope
     * global.
     */
    void collect_globals();
    /// Fase 1 interop C: tras registrar todos los structs, cachea su
    /// categoria (@c StructLayout::cat_c_representable / @c cat_managed) via
    /// el clasificador de Fase 0.  Se llama al final de @c collect_globals.
    void compute_struct_categories();
    /// Resolver de structs (Fase 0) respaldado por @c struct_layouts_.
    const StructLayout *resolve_struct_layout(const std::string &name) const;

    /**
     * @brief Pase 2: chequea el cuerpo de cada funcion declarada.
     */
    void check_functions();

    /**
     * @brief Chequea los cuerpos de las funciones libres del modulo.
     *
     * Idempotente: se llama dos veces, antes y despues de los cuerpos de
     * metodos, porque una generica instanciada al chequear un metodo nace
     * cuando la primera pasada ya termino.  El set @c checked_fn_bodies_
     * evita repetir trabajo (y diagnosticos duplicados).
     */
    void check_free_function_bodies();

    /// @brief Tipo de un enum en la representacion que le corresponde:
    /// entero etiquetado si es CON VALOR, agregado si es de variantes.
    /// Punto UNICO de decision para que no diverjan las rutas.
    Type enum_type_of(const EnumLayout &lay,
                      const std::string &fallback_name) const;

    /// @brief true si el tipo (o un ancestro) declara `toString()`.
    bool type_declares_to_string(const Type &t) const;

    /**
     * @brief El @c Type de un enum, en la representacion que le corresponde.
     *
     * Un enum admite DOS representaciones, y cual toca lo decide su
     * declaracion, nunca el camino por el que se resuelva su nombre:
     *
     *   - enum con VALOR (`enum Ordering : i8 { Less = -1 }`) -> el entero que
     *     lo respalda, etiquetado con el nombre del enum.  Cabe en un registro
     *     y se compara como un numero.
     *   - enum de VARIANTES (con o sin payload) -> un agregado, que vive en
     *     memoria con su tag y sus campos.
     *
     * Toda ruta que necesite el tipo de un enum debe pasar por aqui.  Cuando
     * cada una lo construia por su cuenta, un mismo enum acababa siendo entero
     * por un lado y agregado por otro: declararlo reservaba un buffer y
     * guardaba el TAG en vez del valor, y compararlo comparaba las direcciones
     * de dos buffers en lugar de su contenido.
     *
     * @param name Nombre del enum tal y como aparece en @c enum_layouts_.
     * @param out Recibe el tipo si el enum existe.
     * @return false si no hay ningun enum con ese nombre (el caller sigue con
     *         su propia busqueda).
     */
    bool enum_type_of(const std::string &name, Type &out) const {
        auto it = enum_layouts_.find(name);
        if (it == enum_layouts_.end()) return false;
        /* Busca el enum y DELEGA: la decision de que representacion le toca
         * vive en un solo sitio.  Aqui habia una segunda copia, identica linea
         * por linea, y dos copias de un criterio son dos criterios en cuanto
         * una se toca -- que es precisamente como este enum acabo llegando
         * entero por un camino y agregado por otro. */
        out = enum_type_of(it->second, name);
        return true;
    }

    /// Cuerpos de funcion ya chequeados, para que la pasada sea idempotente.
    std::unordered_set<const ast::FunctionDecl *> checked_fn_bodies_;

    // -----------------------------------------------------------------
    // Visit de statements.
    // -----------------------------------------------------------------

    void check_stmt(ast::Stmt *s, const Type &fn_return_type);
    /**
     * @brief Expande los `inject(expr)` del cuerpo de un bloque `asm`.
     *
     * Sustituye cada `inject(expr)` por el texto que la expresion produce en
     * compilacion, dejando el cuerpo ya listo en el propio nodo.
     *
     * Se hace en el CHEQUEO y no en el lowering por dos motivos: la expresion
     * hay que chequearla antes de poder evaluarla -- si no, una llamada a una
     * funcion comptime no resuelve -- y el cuerpo pasa por el lowering mas de
     * una vez, con lo que expandirlo alli dejaba pasadas sin expandir.
     *
     * @param as Nodo del bloque asm; se modifica su cuerpo.
     */
    void expandir_inject_en_asm(ast::AsmStmt *as);
    void check_block(ast::BlockStmt *b, const Type &fn_return_type);
    void check_var_decl(ast::VarDeclStmt *vd);
    void check_if(ast::IfStmt *s, const Type &fn_return_type);
    void check_while(ast::WhileStmt *s, const Type &fn_return_type);
    void check_for(ast::ForStmt *s, const Type &fn_return_type);
    void check_return(ast::ReturnStmt *s, const Type &fn_return_type);

    // -----------------------------------------------------------------
    // Visit de expresiones (rellena result_type).
    //
    // Devuelven el tipo deducido y al mismo tiempo lo escriben en
    // @c e->result_type para que el lowering lo lea sin recomputar.
    // -----------------------------------------------------------------

    Type check_expr(ast::Expr *e);
    Type check_binary(ast::BinaryExpr *e);
    Type check_unary(ast::UnaryExpr *e);
    Type check_assign(ast::AssignExpr *e);
    /// Nucleo de check_assign; devuelve el tipo del LVALUE (campo/pointee/
    /// elemento/variable).  El wrapper usa ese @c is_const para el enforcement
    /// de const-correctness (escritura a lvalue const = error).
    Type check_assign_impl(ast::AssignExpr *e);

  public:
    /**
     * @brief Resuelve un compound assign (`c += v`) sobre un tipo que
     *        sobrecarga operadores, dejando @p e listo para el lowering.
     *
     * Dos vias, en este orden (el modelo de Python):
     *   1. `__iadd__(V)` -> marca @c e->overload_method: UNA sola operacion
     *      (lo que hace que `atomic<i64> g; g += 1;` sea indivisible).
     *   2. si no lo declara -> DESAZUCARA el AST a `c = c + v` via `__add__`.
     *
     * Publico porque el lowering tambien lo necesita: `c++` fabrica su
     * AssignExpr cuando el checker ya paso, y sin pasar por aqui caia al camino
     * entero (sumaba 1 a la direccion del objeto).  Una sola implementacion
     * para los dos.
     *
     * @param tt tipo del target; @p tv tipo del valor.
     * @param out_result tipo resultante de la expresion, si devuelve true.
     * @return true si @p e quedo resuelto como sobrecarga.
     */
    bool prepare_overloaded_compound_assign(ast::AssignExpr *e, const Type &tt,
                                            const Type &tv,
                                            Type &out_result) const;

    /**
     * @brief Fusiona `g = g OP x` en `g OP= x` (read-modify-write).
     *
     * Reescribe @p e in-place.  Es la INVERSA del desazucarado de
     * @ref prepare_overloaded_compound_assign, y existe por los tipos ATOMICOS:
     * reconocer que las dos `g` son la MISMA posicion permite fusionar los tres
     * pasos (leer, operar, escribir) en el RMW indivisible del tipo.
     *
     * Solo actua si el tipo declara el metodo in-place, asi que los primitivos
     * no se ven afectados.  Cubre los diez operadores con forma compuesta
     * (`+ - * / %` y `& | ^ << >>`).
     *
     * @return true si @p e quedo reescrito.
     */
    bool try_fuse_rmw_assign(ast::AssignExpr *e);

  private:
    /// @brief Busca el dunder de compound assign (`+=` -> @c __iadd__) en el
    ///        tipo @p tt (CLASS o STRUCT) que acepte un valor @p tv.
    /// @return el metodo, o nullptr si el tipo no sobrecarga ese operador
    ///         (entonces `a += b` sigue el camino clasico).
    const ClassMethodInfo *find_compound_assign_dunder(const Type &tt,
                                                       const Type &tv,
                                                       ast::AssignOp op) const;

    /// Metodos de un CLASS/STRUCT; nullptr si @p t no es uno o no esta
    /// registrado.
    const std::vector<ClassMethodInfo> *methods_of_type(const Type &t) const;

    /// ¿@p t sobrecarga la suma/resta, de modo que `x++` / `x--` tengan
    /// sentido?  (`__iadd__`/`__add__`/`__isub__`/`__sub__`.)
    bool type_overloads_step(const Type &t) const;

    /// @brief Busca un dunder UNARIO (sin parametros) por nombre en @p t.
    /// @return el metodo, o nullptr si no aplica.
    const ClassMethodInfo *find_unary_dunder(const Type &t,
                                             const char *nm) const;

    /// @brief Si @p t declara `__bool__`, envuelve @p slot en
    ///        `(*slot).__bool__()` (desazucarado en el AST).
    /// @return true si envolvio.
    bool wrap_in_bool_dunder(std::unique_ptr<ast::Expr> &slot, const Type &t);
    /// Safety net (item 1): true si @c e es un closure CAPTURADOR -- un
    /// LambdaExpr con capturas o un metodo ligado `&obj.m` (que captura el
    /// receptor).  Un closure asi guardado en un campo de struct deja el env
    /// en stack; ver @c struct_stack_closure_taint_.
    bool is_capturing_closure_expr(const ast::Expr *e) const;
    // Promocion de nombre desnudo de funcion a function value: si @c val es un
    // IdentExpr que nombra una funcion (is_func_ref) y @c target es FUNCTION,
    // le asigna el tipo cfn/fn (segun target.fn_is_raw) y devuelve ese tipo.
    // Si no aplica, devuelve @c fallback sin tocar el AST.
    Type maybe_promote_func_ref(ast::Expr *val, const Type &target,
                                const Type &fallback);
    // Bidireccional poor-man's: propaga la firma esperada @c fn_type (params +
    // return) a un lambda-literal sin anotaciones, para que infiera los tipos
    // de sus parametros y su retorno desde el contexto (var-decl/assign/field/
    // return).  No-op si la aridad no coincide o el lambda ya esta anotado.
    void propagate_fn_type_to_lambda(ast::LambdaExpr *lam, const Type &fn_type);
    /// Construye un @c TypeNode (Primitive o Named) que representa @c t, para
    /// sintetizar AST (params/return de un lambda desugarado).
    std::unique_ptr<ast::TypeNode> type_to_node(const Type &t, SourceLoc loc);
    /// Desugara `&base_var.metodo` (puntero a metodo LIGADO) a un lambda
    /// `(args) => base_var.metodo(args)` que captura el receptor.  Reusa toda
    /// la maquinaria de closures (Fase 1).  @c m es el metodo resuelto.
    std::unique_ptr<ast::Expr>
    build_bound_method_lambda(const std::string &base_var,
                              const ClassMethodInfo &m, SourceLoc loc);
    Type check_call(ast::CallExpr *e);
    Type check_ident(ast::IdentExpr *e);
    Type check_field_access(ast::FieldAccessExpr *e);
    /// Tipo de un campo de struct propagando la ABI custom cuando el campo es
    /// de tipo funcion con default = una funcion (ctx pattern): la ABI del
    /// CALLIND via el campo viene del DEFAULT.  El cast del campo la trunca.
    Type field_type_with_abi(const StructFieldInfo &f) const;
    Type check_index(ast::IndexExpr *e);
    Type check_this(ast::ThisExpr *e);
    Type check_new(ast::NewExpr *e);

    /**
     * @brief type-checking de una expresion lambda.
     *
     * Pasos:
     *   1. Construye el Type{FUNCTION, ...} a partir de la firma
     *      declarada (params con tipo) o, si los params no llevan
     *      tipo, los deja como VOID a la espera de inferencia desde
     *      el contexto.  El context-driven type narrowing se realiza
     *      en check_var_decl / check_assign cuando el destino es
     *      @c fn(T1, T2) -> R.
     *   2. Empuja un nuevo @c LambdaCtx con outer_depth = scopes_.size().
     *   3. Push de scope con los params como locales.
     *   4. Recursivamente type-checks @c body; cualquier IdentExpr a un
     *      scope @c < outer_depth se anade automaticamente a
     *      @c expr->captures via la rama de @c check_ident.
     *   5. Pop del scope y del LambdaCtx.
     *   6. Devuelve @c Type::make_function(params, return_type).
     *
     * El tipo del return se infiere del primer @c ReturnStmt visto
     * (los siguientes deben ser compatibles); si el body no tiene
     * @c return, el tipo es VOID.
     */
    Type check_lambda(ast::LambdaExpr *e);

    /**
     * @brief type-checking de un @c MatchExpr.
     *
     * Pasos:
     *   1. Type-check del scrutinee.  Debe ser un valor cuyo tipo
     *      sea un enum registrado (kind==STRUCT con struct_name en
     *      enum_layouts_).
     *   2. Para cada arm:
     *      - Validar que @c variant_name existe en el enum (o es @c _).
     *      - Validar que @c bindings.size() coincide con el numero
     *        de payload fields de la variante.
     *      - Push de scope local con los bindings tipados.
     *      - Lower del body (return_type del enclosing function lo
     *        propaga el caller).
     *   3. Validar exhaustividad: o (a) hay un arm @c _, o (b)
     *      todas las variantes del enum tienen al menos un arm.
     *      Si no se cumple, reportar error claro.
     *
     * Devuelve @c Type{VOID}: en MVP el match es statement-like, no
     * produce valor utilizable como expresion.  Para usar el match
     * como expresion, el usuario asigna dentro de cada arm a una
     * variable comun.
     */
    Type check_match(ast::MatchExpr *e);

    /**
     * @brief Recorre el cuerpo de un metodo de clase con el contexto
     *        adecuado: anade @c this como variable implicita y los
     *        parametros declarados.  El primer parametro del metodo
     *        (en bytecode) es @c this; los demas vienen detras.
     */
    void check_class_method(const ClassLayout &cls, ast::ClassMethodDecl *m);

    /**
     * @brief Chequea el cuerpo de un metodo de struct (value-type).
     *
     * Analogo a @c check_class_method pero @c this se tipa
     * @c Type{STRUCT, lay.name} (no CLASS) y no hay super ni vtable.
     * El reescrito implicit-this usa los nombres de campos del struct.
     * @param lay layout del struct contenedor.
     * @param m   declaracion del metodo (reusa @c ClassMethodDecl).
     */
    void check_struct_method(const StructLayout &lay, ast::ClassMethodDecl *m);

    /**
     * @brief Sprint lombok (2026-06-03): pre-pase de anotaciones Lombok.
     *
     * Recorre cada @c ClassDecl del modulo y, segun los flags
     * @c lombok_* a nivel de campo y de clase, genera
     * @c ClassMethodDecl sinteticos directamente en el AST.  Tras
     * este pre-pase el AST aparece como si el usuario hubiera
     * escrito los metodos a mano.  El resto del pipeline
     * (collect_classes, check_functions, lowering) no necesita
     * conocer Lombok.  Combos como @Data y @Value se descomponen
     * en sus partes.
     */
    void expand_lombok_annotations();

    /**
     * @brief Inyecta los valores por defecto de los campos de instancia de cada
     *        clase (`i32 a = 5;`) al INICIO de sus constructores como
     *        asignaciones `this.campo = default` (estilo Java/C++: los field
     *        initializers corren antes del cuerpo del ctor, tras un super()).
     *        Asi `new C()` aplica los defaults.  Si la clase con defaults no
     *        declara ningun constructor, se sintetiza uno vacio.  Debe correr
     *        tras @c expand_lombok_annotations (para cubrir ctors generados) y
     *        antes de @c collect_classes (para que @c is_zero_init_ctor vea las
     *        asignaciones inyectadas).
     */
    void apply_class_field_defaults_to_ctors();

    /**
     * @brief Pase 0 extendido: registra todas las clases del modulo
     *        con sus layouts (fields + methods) antes del checking
     *        de cuerpos.  Permite que un metodo refiera a otra clase
     *        sin importar el orden de declaracion.
     */
    /**
     * @brief Anota en @p mi los tipos de los parametros de @p m.
     *
     * Estaba escrito dos veces -- para el metodo que sobrescribe a otro y para
     * el que no --, que son el mismo trabajo con distinto destino.  Es ademas
     * el punto donde se ve un parametro que la declaracion admite y el resto
     * del compilador aun no sabe llevar hasta el final.
     *
     * @param m  El metodo declarado.
     * @param mi Donde anotar los tipos.
     */
    /**
     * @brief Comprueba los argumentos de una llamada a metodo contra su firma.
     *
     * Estaba escrito dos veces -- struct y clase -- y a las dos les faltaba lo
     * mismo: que el ultimo parametro puede recoger los que sobren.
     *
     * @param e    La llamada.
     * @param mi   El metodo al que se llama.
     * @param name Su nombre, para los mensajes.
     */
    /**
     * @brief Declara los parametros de @p params en el ambito actual.
     *
     * El `...` pelado no declara nada, y un variadico empaquetado se ve dentro
     * del cuerpo como `T*`.  Las dos cosas estaban mal en dos de las tres
     * copias que habia.
     *
     * @param params Los parametros declarados.
     */
    void declare_params_in_scope(
        const std::vector<std::unique_ptr<ast::ParamDecl>> &params);

    /**
     * @brief Comprueba UN argumento contra el parametro que le toca.
     *
     * Es la pregunta que mas veces se hace el comprobador y estaba escrita una
     * vez por clase de llamada -- funcion, closure, metodo, constructor,
     * variante de enum -- y las copias no coincidian.  Ademas de comparar,
     * convierte el nombre de una funcion en un valor-funcion y re-tipa una
     * constante que cabe en un newtype.
     *
     * @param arg  El argumento; su @c result_type puede quedar reescrito.
     * @param tp   El tipo del parametro.
     * @param idx  Su posicion desde cero, para el mensaje.
     * @param what Como nombrar lo que se llama ("" = generico).
     */
    /**
     * @brief Empaqueta los argumentos de una llamada para ejecutarla al
     *        COMPILAR, si TODOS son constantes que se sepan escribir.
     *
     * El ancho del registro por el que viaja cada constante es el del
     * TRANSPORTE, no el del tipo: un `i16` sigue siendo de dieciseis bits.
     *
     * Estaba escrito dos veces -- expansion de macro y comprobacion cruzada --
     * y la segunda no sabia empaquetar CADENAS, asi que se saltaba en silencio
     * toda llamada que pasara una.
     *
     * @param e   La llamada.
     * @param out Donde dejar las palabras; a medias si devuelve @c false.
     * @return @c true si TODOS se pudieron escribir.
     */
    bool marshal_const_args(const ast::CallExpr &e, std::vector<uint64_t> &out);

    /**
     * @brief La REGLA: si un argumento de tipo @p ta encaja con un parametro
     *        de tipo @p tp, aplicando de paso las dos conversiones que un
     *        argumento admite (nombre de funcion -> valor-funcion, constante
     *        -> newtype).
     *
     * Separada de @ref check_call_arg porque quien pregunta no siempre es
     * quien calculo el tipo: al elegir entre varios constructores hay que
     * calcularlo ANTES, y volver a comprobarlo repetiria sus avisos.
     *
     * @param arg El argumento; su @c result_type puede quedar reescrito.
     * @param tp  El tipo del parametro.
     * @param ta  Su tipo ya calculado; puede quedar reescrito.
     * @return @c true si encaja.
     */
    /**
     * @brief Comprueba la construccion de una variante de enum y da su tipo.
     *
     * `Color.Rojo(3)` no es una llamada, pero se comprueba igual que una --
     * misma cantidad, mismos tipos, mismas conversiones -- porque para quien
     * escribe el programa es lo mismo.  Estaba escrito dos veces, en las dos
     * ramas del despacho que llegan a una variante.
     *
     * @param e         La construccion.
     * @param fa        El acceso `Enum.Variante`, que queda marcado.
     * @param var       La variante y los tipos de su carga.
     * @param enum_name Nombre del enum, que es el tipo del resultado.
     * @return El tipo del valor construido.
     */
    /**
     * @brief Comprueba `Tipo.metodoEstatico(args)` y da su tipo de retorno.
     *
     * Estaba escrito dos veces -- clase y struct -- con la unica diferencia de
     * la MARCA que se deja para la bajada, que es distinta porque cada una
     * toma un camino distinto: la del struct atiende la factoria que devuelve
     * el propio struct por valor.
     *
     * @param e     La llamada.
     * @param fa    El acceso `Tipo.metodo`, que queda marcado.
     * @param smtd  El metodo encontrado.
     * @param donde `Tipo.metodo`, para los mensajes.
     * @param marca Que camino toma la bajada.
     * @return El tipo que devuelve el metodo.
     */
    /**
     * @brief Dice por que no hay tal metodo, y comprueba los argumentos igual.
     *
     * No siempre es que no exista: puede ser un CAMPO que guarda una funcion,
     * o un metodo que esta instanciacion dejo fuera por su condicion -- y ahi
     * "no tiene ese metodo" seria enganoso.  Estaba escrito dos veces, clase y
     * struct, con la unica diferencia de como se nombra el tipo.
     *
     * @param e      La llamada.
     * @param fa     El acceso `obj.metodo`.
     * @param campos Los campos del tipo.
     * @param tipo   Nombre del tipo, para el mensaje.
     * @param clase_o_struct Como llamarlo en el mensaje.
     * @param llamada_indirecta Que hacer si el nombre es un campo funcion.
     * @return El tipo del resultado, o ninguno.
     */
    Type report_method_missing(
        ast::CallExpr *e, ast::FieldAccessExpr *fa,
        const std::vector<StructFieldInfo> &campos, const std::string &tipo,
        const char *clase_o_struct,
        const std::function<Type(const Type &)> &llamada_indirecta);

    Type check_static_method_call(ast::CallExpr *e, ast::FieldAccessExpr *fa,
                                  const ClassMethodInfo &smtd,
                                  const std::string &donde, uint8_t marca);

    Type check_variant_ctor(ast::CallExpr *e, ast::FieldAccessExpr *fa,
                            const EnumVariantInfo &var,
                            const std::string &enum_name);

    bool arg_fits_param(ast::Expr *arg, const Type &tp, Type &ta);

    void check_call_arg(ast::Expr *arg, const Type &tp, size_t idx,
                        const std::string &what = std::string());

    void check_method_args(ast::CallExpr *e, const ClassMethodInfo &mi,
                           const std::string &name);

    /**
     * @brief Construye la ficha de un metodo a partir de su declaracion.
     *
     * Estaba escrito dos veces -- override y no-override -- y a la copia del
     * override le faltaban tres cosas: si es un DESTRUCTOR, y el fichero y la
     * linea.  Lo primero hacia que una clase derivada con destructor propio no
     * llamara a NINGUNO al salir de un ambito.
     *
     * @param m          El metodo declarado.
     * @param class_name La clase que lo define.
     * @return La ficha, sin el indice de tabla.
     */
    ClassMethodInfo make_method_info(const ast::ClassMethodDecl &m,
                                     const std::string &class_name);

    void record_method_params(const ast::ClassMethodDecl &m,
                              ClassMethodInfo &mi);

    void collect_classes();

    // -----------------------------------------------------------------
    // Tabla de simbolos: scopes apilados.
    // -----------------------------------------------------------------

    void push_scope();
    void pop_scope();

    /**
     * @brief Inserta @p sym con el nombre dado en el scope mas interno.
     * @return @c false si ya existia (redefinicion); el caller debe
     *         emitir el diagnostico correspondiente.
     */
    bool declare(const std::string &name, Symbol sym);

    /**
     * @brief Busca @p name desde el scope interno hacia el global.
     * @return Puntero al Symbol o nullptr si no existe.
     */
    const Symbol *lookup(const std::string &name) const;

    /**
     * @brief Variante de @c lookup que ademas devuelve el indice del
     *        scope donde se encontro (0 = global, scopes_.size() - 1 = top).
     *
     * Necesaria para el analisis de capturas de @c LambdaExpr: si el
     * indice del scope es @c < lambda_ctx.outer_depth, la variable
     * pertenece al entorno exterior y debe capturarse en el env block.
     *
     * @param name        Nombre a buscar.
     * @param depth_out   Si no es null y se encuentra, escribe el indice
     *                    del scope.  Sin tocar si no se encuentra.
     * @return Puntero al Symbol o nullptr.
     */
    const Symbol *lookup_with_depth(const std::string &name,
                                    size_t *depth_out) const;

  public:
    /**
     * @brief  M.L26: acceso de solo lectura al set de nombres que
     * @c lookup_with_depth ha resuelto exitosamente durante el check.
     * El @c compile_vx_project lo usa para detectar imports
     * declarados pero no usados y emitir warnings.
     */
    const std::unordered_set<std::string> &referenced_names() const noexcept {
        return referenced_names_;
    }

    ///  M.L23: marca un nombre como importado de otro modulo.
    /// El export del @c .vxi del modulo actual lo filtra por
    /// defecto (no se re-exporta).  Si @c is_reexport es @c true ,
    /// se anyade tambien al set de re-exportados y SE EXPORTA al
    /// @c .vxi (semantica @c public @c import @c "x"; ).
    void mark_imported(const std::string &name, bool is_reexport) {
        imported_names_.insert(name);
        if (is_reexport) reexported_imported_names_.insert(name);
    }
    bool is_imported(const std::string &name) const noexcept {
        return imported_names_.count(name) > 0;
    }
    bool is_reexported(const std::string &name) const noexcept {
        return reexported_imported_names_.count(name) > 0;
    }

  private:
    /**
     * @brief Convierte un TypeNode AST a Type semantico.  Wrapper que propaga
     * la const-correctness POR NIVEL: tras resolver la forma del tipo con
     * @c type_from_node_impl, marca @c Type::is_const con el @c is_const de
     * ESTE nodo (el nivel base o el nivel de puntero correspondiente; la const
     * del apuntado la aporta la recursion sobre el pointee).
     */
    Type type_from_node(const ast::TypeNode *tn) const;
    /// Nucleo de @c type_from_node (resuelve la FORMA del tipo).  No aplica el
    /// @c is_const del nodo raiz -- eso lo hace el wrapper.
    Type type_from_node_impl(const ast::TypeNode *tn) const;

    /**
     * @brief Devuelve el nombre de un tipo NO resuelto dentro de @p tn.
     *
     * Recorre punteros/arrays/optional hasta el @c NamedTypeNode base.  Si ese
     * nombre no corresponde a ningun tipo conocido (primitivo, alias, struct/
     * clase/enum, parametro de tipo comptime, ni un especial/generico que
     * @c type_from_node reconozca), devuelve el nombre; en otro caso, cadena
     * vacia.  Sirve para dar un error CLARO en vez de tratar el tipo como
     * @c void (tamano 0) en silencio (return types, @c sizeof<T>, ...).
     */
    std::string first_unresolved_type(const ast::TypeNode *tn) const;

    /**
     * @brief Verifica si una asignacion entre tipos CLASS es valida
     *        considerando la jerarquia de interfaces / superclases.
     *
     * Devuelve true cuando @p target.struct_name es una superclase o
     * interfaz (transitiva) implementada por @p value.struct_name.
     * Solo se aplica a CLASS<->CLASS; otras combinaciones se delegan
     * a @c types_assignable.
     */
    bool class_is_assignable(const Type &target,
                             const Type &value) const noexcept;

  public:
    /**
     * @brief Indica si @p sub es, subiendo por donde sea, un @p super.
     *
     * Sube por las DOS vias a la vez -- la superclase y las interfaces -- y
     * hasta arriba del todo, no un nivel.  Que sean las dos importa mas de lo
     * que parece: el padre de una INTERFAZ no se guarda en su lista de
     * interfaces sino en su superclase, porque la promocion a esa lista solo
     * ocurre cuando quien declara no es una interfaz.  Un recorrido que solo
     * mire la lista no encuentra nunca el padre de una interfaz, que es
     * exactamente lo que pasaba: con `interface Alta : Media : Base`, una clase
     * que cumple `Alta` no se podia asignar ni a `Media` ni a `Base`.
     *
     * Lo preguntan dos: la comprobacion de tipos y la introspeccion en tiempo
     * de compilacion.  Estaba escrito en los dos sitios -- el segundo lo decia
     * en su comentario, "reimplementado" -- y solo uno subia por las dos vias,
     * asi que a la misma pregunta respondian cosas distintas.
     *
     * @param sub   Nombre del tipo de partida.
     * @param super Nombre del tipo al que se quiere llegar.
     * @return true si se llega, o si son el mismo.
     */
    bool type_derives_from(const std::string &sub,
                           const std::string &super) const noexcept;

    /**
     * @brief Como esta puesto en memoria un `Optional<T>`.
     *
     * Unica respuesta a cuanto ocupa, donde tiene el valor y si lleva marca
     * aparte.  La preguntan el bajado, el `match` y quien calcula el tamano de
     * un struct que lo lleva de campo.
     *
     * @param t Tipo `OPTIONAL`.
     * @return Su disposicion.
     */
    OptionalLayout optional_layout(const Type &t) const;

    /**
     * @brief La disposicion en memoria de un `Result<V,E>`.
     *
     * Misma idea y mismo motivo que @ref optional_layout: el tamano y los
     * desplazamientos dependen de lo que envuelva, y estaban escritos a mano
     * -- veinticuatro, valor en el ocho, error en el dieciseis -- en seis
     * sitios.  Con eso, un `Result` cuyo valor fuera un struct de mas de una
     * palabra no cabia y lo que se sacaba eran ceros.
     *
     * @param t Tipo `RESULT`.
     * @return Su disposicion.
     */
    ResultLayout result_layout(const Type &t) const;

    /**
     * @brief Lo que ocupa un payload dentro de un `Optional` o un `Result`.
     *
     * Lo comparten los dos porque es la misma pregunta: una palabra para un
     * escalar, y el tamano real redondeado a palabra para un struct por valor.
     *
     * @param p Tipo del payload.
     * @return Su hueco, en bytes.
     */
    uint32_t payload_slot_bytes(const Type &p) const;

    /**
     * @brief tabla de constantes comptime declaradas con
     * `comptime const T NAME = expr;` a nivel modulo.
     *
     * Cada entrada `{name -> {type, value_bits}}` es poblada por el
     * type checker tras evaluar el init con @c comptime_eval_expr.
     * El lowering consulta esta tabla en @c lower_ident para
     * inlinear el valor como @c IrOp::CONST en cada uso (cero
     * overhead, sin storage runtime).  El evaluador comptime
     * (`comptime_eval_expr`) tambien la consulta para resolver
     * identifiers a su valor cacheado, permitiendo `comptime const`
     * en cualquier expresion comptime (incluida `comptime if`).
     */
    struct ComptimeConst {
        Type type;
        bool is_str = false;
        bool is_array = false;
        bool is_struct = false;
        bool is_type = false; ///< contiene un Type
        bool is_mutable = false;
        /// #2: valor placeholder diferido (init dependia de una comptime fn
        /// via ComptimeVM aun no cargada, pass 1 del two-phase).  Se resuelve
        /// en pass 2; los reads propagan `deferred` para que static_assert no
        /// se dispare sobre el placeholder.
        bool deferred = false;
        int64_t value = 0;
        std::string str_value;
        std::vector<std::shared_ptr<ComptimeValue>> array_vals;
        std::unordered_map<std::string, std::shared_ptr<ComptimeValue>>
            struct_fields;
        Type type_val;
        // v4: atributos del usuario (@align/@hot/@cold/@section).
        // Solo significativos para comptime constants TOP-LEVEL
        // (GlobalVarDecl con is_comptime=true).  El lowering los
        // propaga al @c static_data_meta tras intern.
        uint16_t attr_align = 0; ///< 0 = default; sino potencia de 2
        bool attr_hot = false;
        bool attr_cold = false;
        std::string attr_section;
    };
    const std::unordered_map<std::string, ComptimeConst> &
    comptime_const_values() const noexcept {
        return comptime_const_values_;
    }
    std::unordered_map<std::string, ComptimeConst> &
    comptime_const_values() noexcept {
        return comptime_const_values_;
    }

    /**
     * @brief stack de scopes locales de comptime const.
     *
     * Se push al entrar a una funcion, un bloque @c comptime { ... },
     * un body de @c comptime for o un cuerpo de @c comptime fn; se
     * pop al salir.  Los identifiers se resuelven buscando desde el
     * top (mas reciente) hacia abajo; finalmente caen en la tabla
     * global @c comptime_const_values_ .
     */
    const std::vector<std::unordered_map<std::string, ComptimeConst>> &
    comptime_const_locals() const noexcept {
        return comptime_const_locals_;
    }
    std::vector<std::unordered_map<std::string, ComptimeConst>> &
    comptime_const_locals() noexcept {
        return comptime_const_locals_;
    }
    void push_comptime_scope() { comptime_const_locals_.emplace_back(); }
    void pop_comptime_scope() {
        if (!comptime_const_locals_.empty()) {
            comptime_const_locals_.pop_back();
        }
    }
    void register_comptime_local(const std::string &name, ComptimeConst v) {
        if (comptime_const_locals_.empty()) push_comptime_scope();
        comptime_const_locals_.back()[name] = std::move(v);
    }

    /**
     * @brief registro de funciones declaradas como `comptime fn`.
     *
     * Cuando una llamada se resuelve a un nombre presente aqui, el
     * evaluador @c comptime_eval_expr la interpreta en compile-time
     * en lugar de generar codigo runtime.  Soporta recursion con un
     * limite de profundidad (defensivo contra loops infinitos).
     */
    const std::unordered_map<std::string, const ast::FunctionDecl *> &
    comptime_fns() const noexcept {
        return comptime_fns_;
    }
    void register_comptime_fn(const std::string &name,
                              const ast::FunctionDecl *fn) {
        comptime_fns_[name] = fn;
    }
    /// Contador de recursion para detectar loops infinitos en
    /// comptime fn (limite 256 niveles).
    int &comptime_recursion_depth() noexcept {
        return comptime_recursion_depth_;
    }

    /// stack de scopes de type-params bindeados para
    /// comptime fn genericos.  Cuando se llama `my_fn<T1, T2>(...)`,
    /// push scope con {"T1" -> resolved_t1, "T2" -> resolved_t2},
    /// eval body, pop.  @c resolve_type_node consulta este stack
    /// para sustituir IdentExpr de tipo (e.g. `T` en `sizeof<T>()`)
    /// por el tipo bindeado.
    std::vector<std::unordered_map<std::string, Type>> &
    comptime_type_locals() noexcept {
        return comptime_type_locals_;
    }
    const std::vector<std::unordered_map<std::string, Type>> &
    comptime_type_locals() const noexcept {
        return comptime_type_locals_;
    }
    void push_comptime_type_scope() { comptime_type_locals_.emplace_back(); }
    void pop_comptime_type_scope() {
        if (!comptime_type_locals_.empty()) {
            comptime_type_locals_.pop_back();
        }
    }
    void register_comptime_type(const std::string &name, Type t) {
        if (comptime_type_locals_.empty()) push_comptime_type_scope();
        comptime_type_locals_.back()[name] = std::move(t);
    }
    /// Lookup en el stack de type-params.  Devuelve true + setea
    /// @c out_t si encontro el nombre.
    /// accesor publico a diagnostics, requerido por
    /// @c comptime_compile para reportar errores de parsing de los
    /// fragmentos de fuente que recibe como input.  Mutable porque
    /// el evaluador comptime (`comptime_eval_expr`) recibe @c const
    /// @c TypeChecker& pero necesita anyadir errores cuando un
    /// fragmento es invalido.
    Diagnostics &diagnostics() const noexcept { return diags_; }
    bool lookup_comptime_type(const std::string &name, Type &out_t) const {
        for (auto it = comptime_type_locals_.rbegin();
             it != comptime_type_locals_.rend(); ++it) {
            auto hit = it->find(name);
            if (hit != it->end()) {
                out_t = hit->second;
                return true;
            }
        }
        return false;
    }

    /**
     * @struct ComptimeBlockSnapshot
     * @brief valor capturado de una variable local (o assert) de un
     *        bloque @c comptime { ... } tras evaluarlo.
     *
     * Solo se rellena cuando @c capture_comptime_block_locals esta
     * activo (lo activa el LSP via @c dump_comptime_values).  Cero
     * coste en builds normales.
     */
    struct ComptimeBlockSnapshot {
        std::string name;  ///< Nombre de la variable o "static_assert".
        std::string scope; ///< Ambito; e.g. "comptime@<linea>".
        std::string
            type_kind; ///< "int"|"string"|"array"|"struct"|"type"|"assert".
        std::string value_str; ///< Representacion legible del valor.
    };

    /// Activa/desactiva la captura de locales de bloques comptime.
    void set_capture_comptime_block_locals(bool on) noexcept {
        capture_comptime_block_locals_ = on;
    }
    /// Snapshots acumulados de los bloques @c comptime { ... }.
    const std::vector<ComptimeBlockSnapshot> &
    comptime_block_snapshots() const noexcept {
        return comptime_block_snapshots_;
    }

    /**
     * @struct ComptimeBuiltinHit
     * @brief valor que un builtin de introspeccion (@c sizeof<T>,
     *        @c alignof<T>, @c kind<T>, @c type_id<T>, @c typename<T>)
     *        resolvio en tiempo de compilacion, con la ubicacion de la
     *        expresion para que el LSP lo muestre en hover / inspector.
     *
     * Solo se rellena con @c capture_comptime_block_locals_ activo (lo
     * activa el LSP via @c dump_comptime_values).  Cero coste normal.
     */
    struct ComptimeBuiltinHit {
        SourceLoc loc;         ///< loc del nombre del builtin (para el hover).
        std::string name;      ///< Expresion legible: "sizeof<i32>".
        std::string type_kind; ///< "int"|"string".
        std::string value_str; ///< Valor: "4", "0 (Primitive)", "\"i32\"".
    };
    /// Valores de builtins comptime resueltos (sizeof/alignof/kind/...).
    const std::vector<ComptimeBuiltinHit> &
    comptime_builtin_hits() const noexcept {
        return comptime_builtin_hits_;
    }

  private:
    /// Serializa un @c ComptimeValue (elemento de array / campo de
    /// struct) a texto legible, recursivo y acotado.
    static std::string render_comptime_value(const ComptimeValue &v);

    bool capture_comptime_block_locals_ = false;
    std::vector<ComptimeBlockSnapshot> comptime_block_snapshots_;
    std::vector<ComptimeBuiltinHit> comptime_builtin_hits_;

    /// Valor comptime (int/bool) de variables locales cuyo init es
    /// comptime-evaluable, para evaluar despues la condicion de un `if`.
    /// Solo se llena con @c capture_comptime_block_locals_ activo (LSP).
    std::unordered_map<std::string, int64_t> lsp_var_values_;
    /// Mini-evaluador comptime de enteros/bools: literales, variables conocidas
    /// (@c lsp_var_values_), builtins escalares y operadores
    /// logicos/aritmeticos. Devuelve true y escribe @p out si la expresion es
    /// evaluable.
    bool lsp_eval_int(const ast::Expr *e, int64_t *out);
    /// Evalua un builtin de introspeccion que da un escalar/bool (sizeof,
    /// field_count, has_field, is_subtype, is_float, ...).  No cubre los que
    /// dan string.  Publico: ademas del LSP lo usa el lowering para resolver en
    /// comptime los predicados de tipo y emitirlos como constante.
  public:
    bool lsp_eval_builtin_scalar(const ast::CallExpr *e, int64_t *out);

  private:
    std::unordered_map<std::string, ComptimeConst> comptime_const_values_;
    std::vector<std::unordered_map<std::string, ComptimeConst>>
        comptime_const_locals_;
    std::unordered_map<std::string, const ast::FunctionDecl *> comptime_fns_;
    int comptime_recursion_depth_ = 0;
    std::vector<std::unordered_map<std::string, Type>> comptime_type_locals_;
    /// profundidad de scopes `synchronized` activos en el
    /// path actual.  Incrementa al entrar a un SynchronizedStmt y
    /// decrementa al salir.  Los builtins @c wait / @c notify /
    /// @c notifyAll lo consultan: si es 0 se emite error claro
    /// "debe llamarse dentro de un synchronized".
    int synchronized_depth_ = 0;
    /// contador para @c gensym -- emite identificadores
    /// frescos unicos por llamada, util para macros hygenic que
    /// quieren introducir nombres sin colision con el scope del
    /// caller.  El contador es per-TypeChecker (no global) asi
    /// cada compilacion empieza desde 0.
    uint64_t gensym_counter_ = 0;
    /// cache de memoizacion para fns @Pure.  Key =
    /// nombre+args serializados; value = ComptimeEvalResult cacheado
    /// via shared_ptr para evitar tener que conocer el size del tipo
    /// en este header (ComptimeEvalResult vive en comptime_introspect.h
    /// y depende de ComptimeValue de este header, asi que evitamos el
    /// ciclo via puntero).  Llamadas repetidas con mismos args
    /// retornan el resultado sin reejecutar el body.
    std::unordered_map<std::string, std::shared_ptr<struct ComptimeEvalResult>>
        pure_macro_cache_;
    /// runtime dedicado a ejecutar @Macros lowered al IR.
    /// Lazy: construido vacio aqui, la VM interna se inicializa al
    /// primer @c try_invoke.  Vida util = vida util del TypeChecker.
    /// Reusado cross-macro durante toda la compilacion.
    ComptimeRuntime comptime_runtime_;

    /// contadores de hits/misses del path VM-only en
    /// el call site del @Macro.  hits = invocacion VM exitosa
    /// (resultado usado, AST eval saltado); misses = VM no aplico
    /// (flag off, sin bytecode, args no codificables, o invoke
    /// fallo) y caimos al AST evaluator.  Reset al start de run().
    uint32_t macro_vmonly_hits_ = 0;
    uint32_t macro_vmonly_misses_ = 0;

    /// Un `inject(...)` de un bloque asm quedo sin resolver porque la maquina
    /// de compilacion aun no podia ejecutar la funcion que lo produce.  Marca
    /// esta pasada como PROVISIONAL: el cuerpo del asm salio vacio y hay que
    /// repetir la compilacion con esa maquina ya cargada.
    bool inject_diferido_ = false;

    /// @copydoc set_comptime_artifact
    const std::vector<uint8_t> *comptime_artifact_ = nullptr;

  public:
    uint64_t next_gensym_id() noexcept { return gensym_counter_++; }
    std::unordered_map<std::string,
                       std::shared_ptr<struct ComptimeEvalResult>> &
    pure_macro_cache() noexcept {
        return pure_macro_cache_;
    }
    ComptimeRuntime &comptime_runtime() noexcept { return comptime_runtime_; }
    const ComptimeRuntime &comptime_runtime() const noexcept {
        return comptime_runtime_;
    }

    ///  MC.9: snapshot publico de los contadores VM-only para
    /// diagnostico desde main.cpp (cuando VESTA_MC_VERBOSE esta on).
    uint32_t macro_vmonly_hits() const noexcept { return macro_vmonly_hits_; }
    uint32_t macro_vmonly_misses() const noexcept {
        return macro_vmonly_misses_;
    }

    /// @copydoc inject_diferido_
    bool inject_diferido() const noexcept { return inject_diferido_; }

  private:
    // -----------------------------------------------------------------
    // Datos.
    // -----------------------------------------------------------------

    ast::ModuleNode &mod_;
    Diagnostics &diags_;

    // Pila de scopes: scopes_[0] = global, scopes_.back() = mas interno.
    std::vector<std::unordered_map<std::string, Symbol>> scopes_;

    // Almacen de firmas de funciones (referenciadas por sig_index).
    std::vector<FunctionSig> function_sigs_;

    /// De donde salio cada trozo de codigo generado por una @Macro.  Vive
    /// aqui porque las posiciones lo apuntan sin poseerlo y tienen que
    /// seguir siendo validas mientras exista el arbol.  Se reusa por sitio
    /// de invocacion: la misma macro invocada dos veces son dos.
    std::unordered_map<std::string, std::unique_ptr<ExpansionInfo>>
        macro_expansions_;

    /// mapa nombre -> indice en function_sigs_ que sobrevive
    /// al @c pop_scope() final de @c run().  Necesario porque el lowering
    /// consulta firmas POST-check para auto-promover literales a STRING
    /// cuando el parametro espera STRING (sin esto, el lookup en scopes_
    /// devolveria nullptr porque el scope global ya fue cerrado).  Se
    /// rellena en cada @c function_sigs_.push_back y nunca se limpia.
    std::unordered_map<std::string, uint32_t> sig_by_name_;

    /// Funciones registradas SOLO para que resuelvan los cuerpos de plantillas
    /// importadas.  Ver @ref mark_template_only_fn.
    std::unordered_set<std::string> template_only_fns_;

    ///  M.2.e: simbolos de funcion importados via .vxi que
    /// deben declararse en el scope global al inicio de run().  El
    /// constructor del TypeChecker NO ha pusheado scope todavia,
    /// asi que las llamadas a register_imported_function durante
    /// la fase de inyeccion no pueden hacer declare() directamente.
    /// Esta cola se drena al inicio de run() tras push_scope().
    std::vector<std::pair<std::string, uint32_t>> pending_imported_fn_names_;

    ///  M.L7: cola paralela para variables globales importadas.
    struct PendingGlobal {
        std::string name;
        Type type;
        bool is_const = false;
        bool has_init_value = false;
        uint64_t init_value = 0;
        /// v4: si @c is_str es @c true, el valor del global es un
        /// string almacenado en @c str_value.  El lowering materializa
        /// via STRMAKE en @c lower_ident.
        bool is_str = false;
        std::string str_value;
        /// Nombre del slot en el modulo que lo DEFINE (`lib__counter`).  Es la
        /// clave con la que el merge cross-module unifica el storage, asi que
        /// el lowering la necesita para los globals que NO se inlinean (los
        /// mutables y los const sin valor de compile-time).
        std::string mangled_label;
    };
    std::vector<PendingGlobal> pending_imported_globals_;
    ///  M.L7: declaracion adelantada del struct + map.  El
    /// accesor publico @c imported_global_consts() en la seccion
    /// public devuelve este miembro.
  public:
    struct ImportedGlobalConst {
        Type type;
        uint64_t value = 0;
        /// v4: para comptime const string cross-module.
        bool is_str = false;
        std::string str_value;
    };

    /**
     * @brief Global importado que tiene STORAGE (no se inlinea): un mutable
     *        (`public i64 counter`) o un const cuyo valor no se conoce en
     *        compile time (`public const string S = "hola"` -> el StringObject
     *        lo construye el `__module_init` del dep).
     *
     * El consumidor no ve el AST del dep, asi que crea su propio slot con
     * @c mangled_label como `shared_key`: el merge cross-module unifica por esa
     * clave y ambos modulos acaban leyendo y escribiendo el MISMO storage.
     */
    struct ImportedGlobalStorage {
        Type type;                 ///< tipo declarado en el dep.
        std::string mangled_label; ///< nombre del slot en el dep.
    };

  private:
    std::unordered_map<std::string, ImportedGlobalConst>
        imported_global_consts_;
    std::unordered_map<std::string, ImportedGlobalStorage>
        imported_global_storage_;

    ///  M6.a L.3: visibilidad por simbolo top-level.
    /// El TypeChecker rellena estos sets al procesar cada decl segun
    /// @c FunctionDecl::is_public, @c GlobalVarDecl::is_public, etc.
    /// El emitter de .vxi consulta para filtrar simbolos privados.
    std::unordered_map<std::string, bool> function_is_public_;
    std::unordered_map<std::string, bool> global_is_public_;
    std::unordered_map<std::string, bool> typedef_is_public_;
    ///  NS.3: nombres marcados @c "internal" (package-scoped).  El emitter
    /// de .vxi los exporta con flag; el consumidor de OTRO paquete los filtra.
    std::unordered_set<std::string> function_is_internal_;
    std::unordered_set<std::string> global_is_internal_;

  public:
    /// @brief  NS.3: @c true si la funcion @p name es @c internal.
    bool function_is_internal(const std::string &name) const {
        return function_is_internal_.count(name) != 0;
    }
    /// @brief  NS.3: @c true si el global @p name es @c internal.
    bool global_is_internal(const std::string &name) const {
        return global_is_internal_.count(name) != 0;
    }

  private:
    ///  M.L26: set de nombres que @c lookup_with_depth resolvio
    /// exitosamente.  Mutable porque el lookup es @c const pero el
    /// tracking es metadata observacional, no afecta la semantica.
    /// Util para detectar imports declarados pero nunca usados +
    /// emitir warnings.
    mutable std::unordered_set<std::string> referenced_names_;

    ///  M.L23: set de nombres importados desde @c .vxi de otros
    /// modulos.  El export del @c .vxi del modulo actual los filtra
    /// por DEFAULT (no se re-exportan) salvo que esten tambien en
    /// @c reexported_imported_names_ (marcados con @c public import).
    std::unordered_set<std::string> imported_names_;
    std::unordered_set<std::string> reexported_imported_names_;

    /// LANG.fix-3: mapa persistente local_name -> ns_idx para que
    /// @c resolve_type_node pueda resolver namespaces tras el
    /// @c pop_scope final.  Sin esto, la lowering pierde los
    /// namespaces porque viven en @c scopes_ (popped).
    std::unordered_map<std::string, uint32_t> ns_idx_by_local_name_;

    /// NS short-form: alias del ULTIMO segmento de un namespace punteado
    /// (`org.geo.shapes` -> `shapes`) hacia su indice, cuando es UNICO. Permite
    /// acceder por el ultimo segmento (`shapes.area`) ademas del path completo.
    /// @c ns_short_ambiguous_ marca los segmentos que aparecen en 2+ namespaces
    /// (no se resuelve el short-form; hay que usar el path completo).
    std::unordered_map<std::string, uint32_t> ns_short_alias_;
    std::unordered_set<std::string> ns_short_ambiguous_;

    /// NS.2 round-trip: namespaces DECLARADOS por este modulo (via
    /// `namespace X;`), para que el export al .vxi sepa que la funcion
    /// mangled `mylib__helper` pertenece al namespace `mylib` con nombre
    /// publico `helper`.  Clave = mangled_label; valor = (ns_path,
    /// public_name).
    std::unordered_map<std::string, std::pair<std::string, std::string>>
        declared_ns_symbols_;

  public:
    const std::unordered_map<std::string, uint32_t> &
    ns_idx_by_local_name() const {
        return ns_idx_by_local_name_;
    }

    /// NS.2: registra un simbolo de un namespace DECLARADO localmente (para el
    /// export al .vxi).  Llamado por el compiler tras flatten_namespaces.
    void register_declared_ns_symbol(const std::string &mangled_label,
                                     const std::string &ns_path,
                                     const std::string &public_name) {
        declared_ns_symbols_[mangled_label] = {ns_path, public_name};
    }
    const std::unordered_map<std::string, std::pair<std::string, std::string>> &
    declared_ns_symbols() const {
        return declared_ns_symbols_;
    }

    /// Registra que @p nombre existe, pero solo bajo la condicion @Target
    /// @p spec, que no se cumple en esta compilacion.  Lo alimenta el driver
    /// con lo que el parser descarto en este modulo y en sus dependencias.
    /// Se consulta cuando una busqueda de nombre falla, para poder decir
    /// "declarado para otro objetivo" en vez del enganoso "no declarado".
    void register_target_skipped(const std::string &nombre,
                                 const std::string &spec) {
        auto &v = target_skipped_[nombre];
        if (std::find(v.begin(), v.end(), spec) == v.end()) v.push_back(spec);
    }

    /// Condiciones @Target bajo las que @p nombre si existe, o nullptr si el
    /// nombre no lo descarto ningun @Target.
    const std::vector<std::string> *
    target_skipped_for(const std::string &nombre) const {
        auto it = target_skipped_.find(nombre);
        return it == target_skipped_.end() ? nullptr : &it->second;
    }

  private:
    /// Nombre -> condicion(es) @Target que lo dejaron fuera de esta build.
    std::unordered_map<std::string, std::vector<std::string>> target_skipped_;

  public:
  private:
  public:
    ///  M.7: namespace de un modulo importado.  Cada entry
    /// contiene los simbolos publicos del @c .vxi indexados por
    /// nombre.  Cuando el TypeChecker ve @c "buf.Buffer" o
    /// @c "lib_a.valor_a", busca @c "buf"/@c "lib_a" en la pila de
    /// scopes (debe ser Symbol::Namespace con @c ns_index apuntando
    /// aqui) y resuelve el simbolo dentro del namespace.
    struct ImportedNamespace {
        /// Nombre del modulo original (e.g. "lib_a"); util para
        /// emitir el label mangled al hacer CALL.
        std::string module_name;
        /// Simbolos del namespace: nombre publico -> indice en
        /// @c symbols.  El lookup es O(1) en uso normal.
        std::unordered_map<std::string, uint32_t> by_name;
        struct Sym {
            std::string mangled_label; ///< label real en el .vel (e.g.
                                       ///< "lib_a__valor_a")
            FunctionSig sig;           ///< firma para validacion en check_call
            Type var_type;             ///< para Variable/Constant
            uint8_t kind = 0; ///< 0=Function, 1=Variable/Const, 2=TypeAlias
            /// Para kind=1 (Constant): valor literal si esta disponible.
            /// El lowering lo emite como CONST inline (cero overhead vs
            /// `const` runtime).  Solo valido cuando @c has_const_value.
            bool has_const_value = false;
            int64_t const_value = 0;
        };
        std::vector<Sym> symbols;
    };

  private:
    std::vector<ImportedNamespace> imported_namespaces_;

    /// Cola de namespaces pendientes a declarar en el scope global
    /// (mismo patron que @c pending_imported_fn_names_).
    std::vector<std::pair<std::string, uint32_t>> pending_imported_ns_names_;

  public:
    /// @brief Acceso al registro de namespaces (para el lowering).
    const std::vector<ImportedNamespace> &imported_namespaces() const noexcept {
        return imported_namespaces_;
    }

    /// @brief Registra un namespace importado.  Devuelve el indice
    /// asignado en @c imported_namespaces_.  El caller (compiler_project)
    /// llama esto tras parsear el .vxi del dep para registrar
    /// `import "lib_a";` o `import "lib_a" as foo;`.
    /// @param local_name Nombre con el que se accede en el modulo
    ///                   actual (e.g. "lib_a" o "foo" si hay alias).
    /// @param module_name Nombre del modulo origen (para mensajes).
    uint32_t register_imported_namespace(const std::string &local_name,
                                         const std::string &module_name);

    /// @brief anyade un simbolo al namespace registrado en @p ns_index.
    /// Llamado por el compiler_project durante la inyeccion de cada
    /// VxiSymbol cuyo modulo se importo plain (sin `only`).
    void register_namespace_symbol(uint32_t ns_index,
                                   const std::string &public_name,
                                   ImportedNamespace::Sym sym);

    /// @brief  NS.2-full: apunta un nombre local (alias del import) a un
    /// namespace ya registrado.  Usado para que @c "import a.b.c as x;" haga
    /// que @c x.Sym resuelva igual que @c a.b.c.Sym cuando el namespace
    /// declarado difiere del nombre del fichero/alias.
    /// @brief NS.6-ext: re-apendea un metodo de extension importado (desde el
    /// .vxi de otro modulo) al layout del tipo destino en este consumidor, para
    /// que @c obj.metodo() resuelva (dispatch estatico al @p mangled_label).
    void inject_imported_ext_method(const std::string &target_key,
                                    bool target_is_class,
                                    const std::string &name,
                                    const std::string &return_type_str,
                                    const std::vector<std::string> &param_strs,
                                    const std::string &mangled_label);

    void point_namespace_alias(const std::string &alias, uint32_t ns_index) {
        ns_idx_by_local_name_[alias] = ns_index;
        // El Symbol::Namespace de @p alias se crea desde la cola pendiente con
        // el ns_index capturado al registrarlo; corregirlo aqui para que
        // @c alias.Sym resuelva contra el namespace destino.
        for (auto &pn : pending_imported_ns_names_) {
            if (pn.first == alias) pn.second = ns_index;
        }
    }

  private:
    ///  NS.1b: resuelve un nombre qualified punteado `a.b.c.Symbol` a su
    /// namespace + simbolo, probando el PREFIJO de namespace mas LARGO (para
    /// paths multi-segmento: `ui.widgets.Button` -> ns=`ui.widgets`,
    /// sym=`Button`).  Cubre tambien el caso single-segment (`ui.Button`).
    /// @return true si resolvio; rellena @p out_ns_idx + @p out_sym.
    bool resolve_ns_qualified(const std::string &dotted, uint32_t &out_ns_idx,
                              std::string &out_sym) const;

    /// Borrow checker compile-time.  Mantiene estado de borrows
    /// activos durante el chequeo de una funcion.  Se resetea al
    /// entrar a cada funcion.
    BorrowChecker borrow_checker_{diags_};

    /// F1 NLL - contador de stmt durante el chequeo del cuerpo de
    /// una funcion.  Incrementado en cada stmt; el borrow checker
    /// consulta @c last_use_idx vs current_stmt_idx_ para dropear
    /// borrows tras su ultimo uso (Non-Lexical Lifetimes).
    uint32_t current_stmt_idx_ = 0;

    /// F1 NLL - pre-pase: walk del body de la funcion en DFS order,
    /// asignando stmt_idx a cada statement y registrando el stmt_idx
    /// maximo en que cada nombre aparece referenciado.  El resultado
    /// se entrega al @c borrow_checker_ via @c set_last_use antes
    /// de empezar el chequeo del body.
    void compute_borrow_last_uses(ast::Stmt *body);

    // Tabla de alias de tipo (introducidos por typedef / using).  Mapea
    // el nombre alias al Type ya resuelto al tipo subyacente; alias
    // anidados (a -> b -> u32) se aplanan en collect_globals.
    std::unordered_map<std::string, Type> type_aliases_;

    // Newtypes (typedef T name new) -- mapa nombre -> tipo underlying
    // (sin nominal_id ni is_opaque) para responder a la introspeccion
    // `X typedef is T` y al cast explicito `(T)x` que cruza la barrera
    // nominal.  Solo poblado para aliases con @c is_newtype = true.
    std::unordered_map<std::string, Type> newtype_underlying_;

  public:
    /// @brief Conversion declarada via @c "explicit from T;" o
    /// @c "explicit to T;" en el bloque del typedef.  @c is_public
    /// indica si la conversion es accesible desde otros ficheros
    /// (default: privado al fichero donde se declaro el typedef).
    struct ExplicitConv {
        Type type;
        bool is_public = false;
    };

    /// @brief Metadata por newtype: conversiones declaradas + fichero
    /// donde se declaro el typedef.  El fichero se usa para imponer
    /// module-privacy: una conversion sin @c public solo aplica en el
    /// mismo fichero.
    struct NewtypeInfo {
        std::vector<ExplicitConv> from_conversions;
        std::vector<ExplicitConv> to_conversions;
        /// Conversiones que NO necesitan cast (`implicit from/to T;`).  La
        /// barrera nominal sigue cerrada para el resto: el typedef declara las
        /// que forman parte de su contrato.
        std::vector<ExplicitConv> implicit_from_conversions;
        std::vector<ExplicitConv> implicit_to_conversions;
        std::string source_file;
    };

  public:
    /**
     * @brief Asignabilidad, incluyendo las conversiones @c implicit que un
     *        newtype declare en su bloque.
     *
     * SOMBREA a proposito la funcion libre @c vx::types_assignable: todos los
     * sitios del checker que preguntan "¿cabe este valor aqui?" resuelven a
     * este metodo sin tener que enumerarlos uno a uno, y la respuesta es la
     * misma en todos ellos (declaracion, retorno, argumento, asignacion).
     *
     * @param target Tipo de destino.
     * @param value  Tipo del valor que se quiere poner en el.
     * @return @c true si el valor se puede usar como @p target sin cast.
     */
    bool types_assignable(const Type &target, const Type &value) const {
        if (vx::types_assignable(target, value)) return true;
        // Un enum con VALOR es su tipo base: `enum Ordering : i8` ES un `i8`
        // etiquetado.  Asignarle un valor de ese mismo entero -- p.ej. el que
        // devuelve un metodo importado de otro modulo -- es legitimo, y sin
        // esto un `Ordering o = a.ucmp(b);` se rechazaba pese a que ambos
        // lados son el mismo tipo.  Se exige que coincida el ancho y el signo,
        // asi que no abre la puerta a mezclar enteros de cualquier tipo.
        if (target.is_valued_enum && target.kind == value.kind &&
            (value.struct_name.empty() ||
             value.struct_name == target.struct_name))
            return true;
        return newtype_implicit_conv_ok_(target, value);
    }

  private:
    /// ¿Hay una conversion `implicit` declarada que lleve @p value hasta
    /// @p target?  Se mira en los dos sentidos: las `implicit to` del newtype
    /// de origen y las `implicit from` del de destino.
    bool newtype_implicit_conv_ok_(const Type &target,
                                   const Type &value) const {
        if (value.nominal_id != 0 && !value.nominal_name.empty()) {
            auto it = newtype_info_.find(value.nominal_name);
            if (it != newtype_info_.end()) {
                for (const auto &c : it->second.implicit_to_conversions) {
                    if (vx::types_assignable(target, c.type)) return true;
                }
            }
        }
        if (target.nominal_id != 0 && !target.nominal_name.empty()) {
            auto it = newtype_info_.find(target.nominal_name);
            if (it != newtype_info_.end()) {
                for (const auto &c : it->second.implicit_from_conversions) {
                    if (vx::types_assignable(c.type, value)) return true;
                }
            }
        }
        return false;
    }

    // Mapa de metadata por nombre de newtype.  Vacio para newtypes
    // sin bloque @c {explicit from/to T;} declarado.
    std::unordered_map<std::string, NewtypeInfo> newtype_info_;

    // Counter global de IDs nominales asignados a newtypes.  Empieza
    // en 0; el ID 0 esta reservado para "no es newtype" (alias clasico).
    uint32_t newtype_counter_ = 0;

  public:
    /// @brief Acceso de solo lectura al underlying de un newtype.
    /// Usado por el lowering para emitir el cast explicito (T)x
    /// preservando bits.  Devuelve nullptr si @p name no es un newtype.
    const Type *newtype_underlying(const std::string &name) const noexcept {
        auto it = newtype_underlying_.find(name);
        return (it != newtype_underlying_.end()) ? &it->second : nullptr;
    }

    /**
     * @brief Nombre del layout REAL detras de un newtype (cadena vacia si no lo
     *        es, o si su underlying no es un tipo con layout).
     *
     * `typedef Caja Sesion new;` -> `underlying_layout_name("Sesion")` da
     * "Caja".  Un newtype comparte la representacion del underlying -- y por
     * tanto su layout, sus campos y sus metodos; lo unico que anade es ser
     * NOMINALMENTE distinto, y eso viaja en el @c Type (nominal_id), no en el
     * layout.  Sin esto, los lookups por NOMBRE (`class_layouts_`,
     * `enum_layouts_`) no encuentran nada y un newtype sobre una clase o un
     * enum no se podia usar.
     */
    /// @brief Tipo que vale `new X(...)` (ver la definicion en el .cpp).
    Type new_expr_result_type(const std::string &name) const;

    std::string underlying_layout_name(const std::string &name) const {
        auto it = newtype_underlying_.find(name);
        if (it == newtype_underlying_.end()) return std::string();
        return it->second.struct_name;
    }

    /// @brief Metadata de conversiones de un newtype (puede ser nullptr).
    const NewtypeInfo *newtype_info(const std::string &name) const noexcept {
        auto it = newtype_info_.find(name);
        return (it != newtype_info_.end()) ? &it->second : nullptr;
    }

  private:
    // Tabla de structs declarados con su layout pre-calculado (offsets
    // de campos y tamano total).  Acceso O(1) por nombre desde
    // type_from_node y desde el lowering (a traves de la API publica).
    std::unordered_map<std::string, StructLayout> struct_layouts_;

    // Tabla de clases declaradas con su layout pre-calculado.  Una
    // clase tiene los mismos fields que un struct mas una vtable y
    // una superclase opcional; el frontend baja a defclass +
    // deffield* + defmethod* en el __module_init.
    std::unordered_map<std::string, ClassLayout> class_layouts_;

    // tabla de enums declarados en el modulo.  El nombre
    // de la variante esta calificado por el nombre del enum (e.g.
    // un enum @c Color con variante @c Red se accede via
    // @c enum_layouts_["Color"].variants[0]).  Los nombres de variante
    // son unicos dentro de su enum pero pueden colisionar entre
    // enums distintos (no hay namespace global de variantes).
    std::unordered_map<std::string, EnumLayout> enum_layouts_;

    // Plantillas genericas (clases con type_params no vacios).  No se
    // procesan como clases concretas; cada instanciado las
    // monomorphiza.  Mapea nombre del template -> indice en
    // mod_.decls (para clonar el ClassDecl original).
    std::unordered_map<std::string, size_t> generic_templates_;
    /// L2.3: templates de enum genericos.  Mapea template_name (sin
    /// args) -> indice en mod_.decls.  Cada uso `Maybe<i32>` se
    /// monomorphiza on demand via monomorphize_enum().
    std::unordered_map<std::string, size_t> generic_enum_templates_;
    /// NS.6-ext: conformidades declaradas via @c "impl Concept for Tipo".
    /// Mapea nombre-de-tipo -> conjunto de concepts implementados.  Consultado
    /// por la verificacion de bounds (un tipo con impl explicito satisface el
    /// concept aunque el predicado estructural tambien lo confirme).
    std::unordered_map<std::string, std::unordered_set<std::string>>
        impl_conformances_;
    /// Templates de struct genericos (`struct Box<T> { ... }`).  Mapea
    /// template_name -> indice en mod_.decls.  Cada uso `Box<i32>` se
    /// monomorphiza on demand via monomorphize_struct() (mismo modelo que
    /// las clases y los enums).
    std::unordered_map<std::string, size_t> generic_struct_templates_;
    /// #7: especializaciones de struct (`struct Caja<i64>` total /
    /// `struct Caja<T*>` parcial).  Mapea nombre base -> indices en
    /// mod_.decls de las especializaciones.  Al instanciar `Caja<X>` se
    /// elige la mas especifica que matchee (ver select_struct_specialization).
    std::unordered_map<std::string, std::vector<size_t>>
        struct_specializations_;
    /// #7: especializaciones de CLASE (mismo modelo que structs).
    std::unordered_map<std::string, std::vector<size_t>> class_specializations_;
    /// #7: especializaciones de FUNCION generica (`R id<i64>(...)`).
    std::unordered_map<std::string, std::vector<size_t>>
        function_specializations_;
    /// Templates de FUNCIONES genericas (`T id<T>(T x)`).  Mapea template_name
    /// -> indice en mod_.decls.  Cada llamada `id<i64>(...)` (o con args
    /// inferidos) se monomorphiza via monomorphize_function().
    std::unordered_map<std::string, size_t> generic_fn_templates_;
    /// Nombre publico de una plantilla importada -> label con el que quedo
    /// registrada.  Ver @ref register_generic_fn_alias.
    std::unordered_map<std::string, std::string> generic_fn_public_names_;

    /// Idempotencia de monomorphize_method: clave = "Container#metodo_i32"
    /// (separador '#' interno; el lenguaje no usa sintaxis '::').
    std::unordered_set<std::string> monomorphized_methods_;

    /// #6: registro de conceptos de usuario (`concept Name<T> = ...`).
    /// Clave = nombre; valor = puntero al ConceptDecl (vive en mod_.decls).
    /// Poblado al registrar templates.  Consultado por la evaluacion de
    /// bounds y por la composicion de conceptos en predicados comptime.
    std::unordered_map<std::string, const ast::ConceptDecl *> concepts_;
    /// #cross-module-generics: nombres de plantillas/conceptos ya inyectados
    /// desde un `.vxi` importado (dedup de re-parse + evita doble inyeccion
    /// si varios imports los traen).
    std::unordered_set<std::string> injected_templates_;
    /// #6: bounds encolados por check_type_bounds, pendientes de evaluar
    /// cuando los layouts existan (ver verify_pending_type_bounds).
    struct PendingBoundCheck {
        std::string concept_name; ///< concepto exigido
        Type arg;                 ///< type-arg concreto
        std::string type_param;   ///< nombre del param (para el mensaje)
        SourceLoc loc;
    };
    std::vector<PendingBoundCheck> pending_bound_checks_;
    /// #6: metodos omitidos por su `where` en una instanciacion concreta.
    /// Clave = contenedor mangled (`atomic_f32`); valor = [(metodo,
    /// requisitos)] para dar un mensaje claro si se intenta llamar el metodo no
    /// disponible.
    std::unordered_map<std::string,
                       std::vector<std::pair<std::string, std::string>>>
        unavailable_methods_;
    /// Cola de metodos genericos monomorphizados pendientes de anyadir al
    /// AST del contenedor + chequear su body (drenada por
    /// drain_pending_method_monos tras check_functions).
    struct PendingMethodMono {
        std::string container;                        ///< struct/clase
        bool is_struct = false;                       ///< true si struct
        std::unique_ptr<ast::ClassMethodDecl> method; ///< clon sustituido
    };
    std::vector<PendingMethodMono> pending_method_monos_;
    /// L2.3: stack para inferir el mangled de variantes sin payload
    /// (e.g. `Maybe<i32> a = Maybe.None`).  Pair = (template_name,
    /// mangled_name).
    std::vector<std::pair<std::string, std::string>> expected_enum_stack_;

    // Cache de monomorphizaciones: clave = "Box<i32>" mangled como
    // "Box_i32"; valor = true si ya esta generada.  Evita regenerar
    // la misma instanciacion mas de una vez.
    std::unordered_map<std::string, bool> monomorphized_;

  public:
    /**
     * @brief Provenance de una clase monomorphizada.
     *        Conocer el template + los args concretos permite que
     *        el JIT/AOT identifique instanciaciones, deduplique
     *        especializaciones, y emita stack traces legibles
     *        ("Box<i32>" en vez de "Box_i32").
     */
    struct MonomorphInfo {
        std::string template_name;          ///< "Box"
        std::vector<std::string> type_args; ///< ["i32"] (legibles)
        /// #7: los type-args concretos como @c Type (no solo el string).
        /// Lo usa el matching de patrones genericos anidados
        /// (`Caja<Inner<T>>`) para recuperar el T concreto de un
        /// `Inner_i64` y ligar el param fresco.
        std::vector<Type> type_arg_types;
    };

    /**
     * @brief Devuelve el provenance de una clase monomorphizada,
     *        o @c nullptr si @p mangled no es una instanciacion.
     *
     * Lo consulta @c Lowering al generar IrFunction para los
     * metodos de la clase: rellena @c IrFunction::generic_template_name
     * y @c generic_type_args para que el IR lleve el contract.
     */
    const MonomorphInfo *
    monomorph_info(const std::string &mangled) const noexcept {
        auto it = monomorph_info_.find(mangled);
        return (it == monomorph_info_.end()) ? nullptr : &it->second;
    }

    // ----  M.2: interop con .vxi (interfaces compiladas) ----
    //
    // El TypeChecker puede exportar sus simbolos publicos a un
    // descriptor @c vx::VxiModule para que el emitter del .vxi
    // los serialize.  Tambien puede inyectar simbolos importados
    // desde un .vxi parseado.  Las firmas precisas viven en
    // @c module_interop.cpp para no forzar include de vxi_format.h
    // aqui (forward declaramos VxiModule mas abajo via traits).

    /// @brief Entry para la lista de simbolos en @c only.
    struct VxiOnlyEntry {
        std::string name;   // nombre original en el modulo
        std::string rename; // nombre local (vacio = mismo)
    };

    /// @brief Resolver de typenames canonicos -> @c Type.  Re-parsea
    /// strings tipo @c "i32", @c "u64*", @c "Optional<i32>",
    /// @c "fn(i32) -> i64".  Devuelve @c Type{} (kind=VOID) si el
    /// typename es desconocido en el contexto actual.  Usado por el
    /// cargador de .vxi para resolver firmas de funciones y tipos
    /// de fields cross-module.
    Type resolve_type_string(const std::string &type_str) const;

    /// @brief Acceso const al mapa de aliases (transparente + newtype).
    const std::unordered_map<std::string, Type> &type_aliases() const noexcept {
        return type_aliases_;
    }

    /// @brief Map de nombre -> sig_index (para iterar funciones top-level).
    /// Usado por el emitter del .vxi para enumerar funciones con
    /// sus firmas sin necesidad de mantener un getter por funcion.
    const std::unordered_map<std::string, uint32_t> &
    function_names() const noexcept {
        return sig_by_name_;
    }

    /// @brief Reserva un nominal_id univoco para un nuevo newtype
    /// (cuando se inyecta desde .vxi).  Cada llamada devuelve un id
    /// distinto.  No tiene efectos secundarios.
    uint32_t allocate_nominal_id() noexcept { return ++newtype_counter_; }

    /// @brief Devuelve un nominal_id ESTABLE y DETERMINISTA derivado del
    /// nombre canonico @p canonical (el nombre mangled del tipo, p.ej.
    /// "std__pool__fiber").  Dos importaciones del mismo tipo (una por el
    /// nombre corto via `only T`, otra por el mangled en las firmas de las
    /// funciones libres del mismo modulo) obtienen ASI el mismo id -> el
    /// type checker las unifica.  Rango alto (bit 30) para no chocar con los
    /// ids de contador de allocate_nominal_id (que empiezan bajos).  FNV-1a 32.
    uint32_t stable_nominal_id(const std::string &canonical) const noexcept {
        uint32_t h = 2166136261u;
        for (char c : canonical) {
            h ^= static_cast<uint8_t>(c);
            h *= 16777619u;
        }
        return 0x40000000u | (h & 0x3FFFFFFFu);
    }

    // -- Registradores usados solo por el cargador de .vxi (M2.d).
    // Insertan en las tablas internas SIN re-validar (asumen que el
    // .vxi de origen es valido).  Si el nombre ya existe, no se
    // sobreescribe (idempotente).

    void register_imported_type_alias(const std::string &name, Type t) {
        type_aliases_.emplace(name, std::move(t));
    }
    void register_imported_newtype(const std::string &name, Type underlying) {
        newtype_underlying_.emplace(name, std::move(underlying));
    }
    ///  M.L8: registra el bloque @c {explicit from/to T;} de un
    /// newtype importado.  Las conversiones se almacenan en
    /// @c newtype_info_ y participan en @c check_cast como
    /// allow-list para casts cross-module.
    void register_imported_newtype_info(const std::string &name,
                                        NewtypeInfo ni) {
        newtype_info_.emplace(name, std::move(ni));
    }
    void register_imported_struct(const std::string &name, StructLayout L) {
        //  M.fix-classfield: overwrite (no emplace) para soportar
        // pre-registro de skeleton seguido de fill cross-type within
        // mismo dep modulo.
        struct_layouts_[name] = std::move(L);
    }
    void register_imported_class(const std::string &name, ClassLayout L) {
        class_layouts_[name] = std::move(L);
    }
    /**
     * @brief True si ya hay un layout de enum con ese nombre y viene entero.
     *
     * Lo usa el pre-registro de la importacion, que solo reserva el nombre:
     * si el enum ya entro completo no debe sobrescribirlo, porque el esqueleto
     * no lleva ni el tipo de respaldo ni los payloads.
     *
     * @param name Nombre (canonico o local) bajo el que se busca.
     * @return true si existe y tiene variantes.
     */
    bool enum_layout_is_complete(const std::string &name) const {
        auto it = enum_layouts_.find(name);
        return it != enum_layouts_.end() && !it->second.variants.empty();
    }
    /**
     * @brief Busca el layout de un enum por cualquiera de sus nombres.
     *
     * Un enum se conoce por varios nombres a la vez: el local con el que se
     * escribe (`Ordering`), el canonico del modulo que lo define
     * (`std__wideint__Ordering`) y, si hay un newtype de por medio, el del
     * tipo de debajo.  Cada sitio que necesitaba el layout hacia su propia
     * busqueda y cubria unos nombres si y otros no, de modo que el mismo enum
     * se reconocia por un camino y no por otro -- y un enum CON VALOR que no
     * se reconoce se trata como agregado, con lo que sus variantes dejan de
     * ser numeros para volverse buffers en memoria.
     *
     * Este es el UNICO sitio donde se decide.  Al ser uno solo, tambien es el
     * unico que hay que mirar cuando algo no se reconoce.
     *
     * @param name Nombre tal y como aparece en el codigo.
     * @return El layout, o nullptr si no hay ningun enum con ese nombre.
     */
    const EnumLayout *find_enum_layout(const std::string &name) const {
        if (name.empty()) return nullptr;
        auto it = enum_layouts_.find(name);
        if (it != enum_layouts_.end()) return &it->second;
        // Newtype: `typedef Color Tinta new;` -- Tinta comparte las variantes
        // del enum de debajo.
        if (const std::string real = underlying_layout_name(name);
            !real.empty()) {
            it = enum_layouts_.find(real);
            if (it != enum_layouts_.end()) return &it->second;
        }
        // Importado: registrado solo bajo su nombre canonico.
        const std::string sufijo = "__" + name;
        for (const auto &kv : enum_layouts_) {
            const std::string &k = kv.first;
            if (k.size() > sufijo.size() &&
                k.compare(k.size() - sufijo.size(), sufijo.size(), sufijo) == 0)
                return &kv.second;
        }
        return nullptr;
    }

    void register_imported_enum(const std::string &name, EnumLayout L) {
        if (util::flag_on(util::FlagId::DbgReg)) {
            fprintf(stderr, "[REG] %s is_valued=%d nvars=%d:", name.c_str(),
                    (int)L.is_valued, (int)L.variants.size());
            for (const auto &v : L.variants)
                fprintf(stderr, " %s=%lld", v.name.c_str(),
                        (long long)v.int_value);
            fprintf(stderr, "\n");
        }
        enum_layouts_[name] = std::move(L);
    }
    /**
     * @brief Marca una funcion como visible SOLO para cuerpos de plantilla.
     *
     * El cuerpo de una plantilla generica importada se re-parsea en el modulo
     * que la usa, donde los helpers de su modulo de origen no estan en scope.
     * Se registran (bajo su label mangled) para que resuelva y enlace, pero el
     * consumidor no los pidio: marcarlos aqui los excluye del fallback por
     * sufijo de @c check_call, que si no dejaria que el nombre corto resolviera
     * y romperia la higiene del `only`.
     */
    void mark_template_only_fn(const std::string &mangled) {
        template_only_fns_.insert(mangled);
    }
    void register_imported_function(const std::string &name, FunctionSig sig) {
        /* Dos imports que traen el MISMO nombre.
         *
         * `emplace` no sobrescribe, asi que gana el primero -- y hasta aqui
         * eso pasaba en silencio: el mismo programa daba un resultado u otro
         * segun el orden de dos lineas que nadie mira.
         *
         * Que sea un conflicto o no lo dice la etiqueta manglada, que lleva el
         * modulo de origen.  Si coincide es la MISMA funcion llegando por dos
         * caminos -- una re-exportacion, que es un patron corriente en la
         * stdlib y tiene que seguir funcionando --; si difiere son dos
         * funciones distintas peleandose por un nombre. */
        const auto ya = sig_by_name_.find(name);
        if (ya != sig_by_name_.end() && ya->second < function_sigs_.size()) {
            const std::string &antes = function_sigs_[ya->second].mangled_label;
            if (!antes.empty() && !sig.mangled_label.empty() &&
                antes != sig.mangled_label)
                diags_.error(
                    {}, vx::diag::format("VXT003",
                                         {name, antes, sig.mangled_label}));
        }
        const uint32_t idx = static_cast<uint32_t>(function_sigs_.size());
        function_sigs_.push_back(std::move(sig));
        sig_by_name_.emplace(name, idx);
        // Encolar para que `run()` declare el Symbol en el scope global
        // tras el push_scope inicial.  Sin esto, el lookup en
        // `lookup_with_depth` no encuentra la funcion importada.
        pending_imported_fn_names_.push_back({name, idx});
    }
    ///  M.L7: registra una variable global importada de otro
    /// modulo via @c .vxi.  Igual que las funciones, se encola para
    /// que @c run() la declare en el scope global tras el
    /// @c push_scope inicial.  Si @c has_init_value es @c true y la
    /// global es @c const , el lowering del consumidor puede
    /// inline-ar el valor literal.
    void register_imported_global(const std::string &name, Type type,
                                  bool is_const, bool has_init_value = false,
                                  uint64_t init_value = 0,
                                  const std::string &mangled_label = "") {
        PendingGlobal pg;
        pg.name = name;
        pg.type = std::move(type);
        pg.is_const = is_const;
        pg.has_init_value = has_init_value;
        pg.init_value = init_value;
        pg.mangled_label = mangled_label;
        pending_imported_globals_.push_back(std::move(pg));
    }

    /// v4: registra un comptime const string importado cross-module.
    /// El lowering puede materializar el StringObject al primer uso via
    /// `STRMAKE` con los bytes guardados en @c imported_global_consts_.
    void register_imported_global_str(const std::string &name, Type type,
                                      std::string str_value) {
        PendingGlobal pg;
        pg.name = name;
        pg.type = std::move(type);
        pg.is_const = true;
        pg.is_str = true;
        pg.str_value = std::move(str_value);
        pending_imported_globals_.push_back(std::move(pg));
    }

    ///  M.L7: tabla de globals const importadas con valor
    /// literal embedded.  El lowering la consulta en @c lower_ident
    /// para inline-ar `CONST <value>` directamente cuando el ident
    /// resuelve a uno de estos nombres.  Poblada al final de run()
    /// drenando @c pending_imported_globals_.  El struct esta
    /// declarado arriba en la primera seccion public anidada.
    const std::unordered_map<std::string, ImportedGlobalConst> &
    imported_global_consts() const noexcept {
        return imported_global_consts_;
    }

    /// Globals importados que tienen storage propio (no inlinables).  El
    /// lowering la consulta para crear el slot compartido con el dep.  Poblada
    /// al final de run() drenando @c pending_imported_globals_.
    const std::unordered_map<std::string, ImportedGlobalStorage> &
    imported_global_storage() const noexcept {
        return imported_global_storage_;
    }

    ///  M6.a L.3: setea visibilidad de un simbolo top-level.
    /// El TypeChecker llama esto al procesar cada decl.
    void set_function_visibility(const std::string &name, bool is_pub) {
        function_is_public_[name] = is_pub;
    }
    void set_global_visibility(const std::string &name, bool is_pub) {
        global_is_public_[name] = is_pub;
    }
    void set_typedef_visibility(const std::string &name, bool is_pub) {
        typedef_is_public_[name] = is_pub;
    }
    /// Acceso de solo lectura.  @c true si el simbolo es publico (o
    /// no fue registrado; default permisivo).
    bool is_function_public(const std::string &name) const noexcept {
        auto it = function_is_public_.find(name);
        return (it == function_is_public_.end()) || it->second;
    }
    bool is_global_public(const std::string &name) const noexcept {
        auto it = global_is_public_.find(name);
        return (it == global_is_public_.end()) || it->second;
    }
    bool is_typedef_public(const std::string &name) const noexcept {
        auto it = typedef_is_public_.find(name);
        return (it == typedef_is_public_.end()) || it->second;
    }

  private:
    // Tabla paralela a @c monomorphized_ que ademas guarda el
    // template_name + lista legible de type_args.  Util para
    // pasar al IR y para tools.
    std::unordered_map<std::string, MonomorphInfo> monomorph_info_;

    // Nombre de la clase contenedora durante la verificacion de un
    // metodo de instancia (vacio fuera de un metodo).  Lo usa
    // check_this y la resolucion de nombres no calificados que
    // refieren a campos/metodos de la propia clase.
    std::string current_class_;

    // Nombre del struct contenedor durante la verificacion de un
    // metodo de struct (vacio fuera).  Los structs son value-types
    // sin vtable: @c this dentro de un metodo de struct se tipa como
    // @c Type{STRUCT, current_struct_} y @c this.campo resuelve via
    // la rama STRUCT de check_field_access.  Disjunto de
    // @c current_class_ (nunca ambos no-vacios a la vez).
    std::string current_struct_;

    // Flag activo cuando el metodo en chequeo es static.  Se usa para
    // rechazar @c this dentro de su body con un mensaje claro.
    bool current_method_is_static_ = false;

    // tipo de retorno de la funcion / metodo en chequeo.
    // Lo usa @c check_match para que los @c return dentro de las
    // arms del match validen contra el return type real (no contra
    // VOID).  Se settea al entrar en @c check_function /
    // @c check_class_method y se restaura al salir.
    Type current_fn_return_type_{PrimitiveKind::VOID};

    // F4: contexto de chequeo de un resolver `@offset { }` de overlay.  Cuando
    // @c overlay_resolver_active_ es true y el body llama a `parent<T>()`, se
    // marca @c overlay_resolver_used_parent_ y se guarda T; tras el check se
    // copia a @c StructFieldInfo::resolver_uses_parent del campo resolver.
    bool overlay_resolver_active_ = false;
    bool overlay_resolver_used_parent_ = false;
    std::string overlay_resolver_parent_type_;
    /// F4: resolvers `@offset { }` cuyo check se DIFIERE a un 2o pase (tras
    /// construir TODOS los layouts de overlay), para que un resolver pueda usar
    /// `parent<Otro>()` aunque Otro se defina despues (dependencia circular:
    /// PeImage.Imports usa ImportDesc; ImportDesc.name usa parent<PeImage>()).
    std::vector<
        std::pair<const ast::StructDecl *, const ast::StructFieldDecl *>>
        pending_overlay_resolvers_;
    void check_overlay_resolvers_deferred();

    // Safety net (item 1): variables LOCALES de tipo STRUCT a las que se les
    // asigno un closure CAPTURADOR en un campo.  El env de ese closure vive en
    // el STACK del scope actual (los structs son value-types sin destructor de
    // campos owned), asi que si el struct ESCAPA (return, o store a un destino
    // que sobrevive: campo/indice/deref) el env queda colgante (use-after-
    // scope).  Se taintea en @c check_assign y se rechaza el escape en
    // @c check_return / @c check_assign.  Se limpia al entrar en cada funcion.
    // Ver doc/VMdoc/Vesta/ClosuresEnCampos.md.
    std::unordered_set<std::string> struct_stack_closure_taint_;

    // Ruta B (H2 move-only): locales que han sido MOVIDOS -- `S b = a` de un
    // struct gestionado (con `~Struct()` o campo destructible) SIN copy-hook es
    // un move (estilo Rust): `a` queda invalidado.  Usar `a` despues es un
    // error (use-after-move).  Se inserta en @c check_var_decl tras procesar el
    // init; se chequea en @c check_ident; se limpia al reasignar el local
    // (`a = ...`) y al entrar en cada funcion.  Conservador para no dar falsos
    // positivos: solo el caso lineal claro.  Ver proj_ownership_hooks.
    std::unordered_set<std::string> moved_locals_;

    // Bug fix 2026-05-23 (audit optres infer): tipo Result<V,E> esperado
    // en el contexto actual (caller del check_expr).  Se setea en
    // check_return / check_var_decl antes de check_expr cuando el destino
    // es un Result<V,E>; @c check_call lo consulta al ver Ok(v) o Err(e)
    // y usa V/E del contexto en lugar de los placeholders (Result<V, i64>
    // / Result<i64, E>).  Resuelve `return Err("lit")` con string E y
    // `Ok(i32)` que se promocionaria a i64 sin contexto.
    Type expected_result_type_{};
    // Idem para Optional<T>: cuando el destino es Optional<T>, propagar
    // T al Some(v).
    Type expected_optional_type_{};

    /// BugFix R8: indica si estamos en el body de un @Macro.  Cuando
    /// es true, check_var_decl trata las var-decls como
    /// `comptime const` automaticamente para que los IdentExpr
    /// posteriores sean resoluble por el comptime evaluator.
    bool current_fn_is_macro_ = false;
    /// P1: true si la fn actual es una comptime fn ruteada a la ComptimeVM (NO
    /// un @Macro).  Se ejecuta SIEMPRE en la VM, asi que sus locales runtime NO
    /// deben registrarse como comptime_const_locals (evita que un builtin como
    /// comptime_concat pliegue el snapshot inicial en un loop de acumulacion).
    bool current_fn_is_vm_comptime_fn_ = false;
    /// @NoExcept/@NoExceptions: la funcion actual no admite excepciones.
    /// check_stmt rechaza throw/try/catch cuando es true.
    bool current_fn_is_noexcept_ = false;

    // Conteo de errores al inicio del run() para detectar exito.
    size_t initial_errors_ = 0;

    /**
     * @brief contexto activo por cada lambda anidada.
     *
     * Cuando se entra a chequear el body de una @c LambdaExpr,
     * empujamos un @c LambdaCtx que registra (a) el puntero al
     * @c LambdaExpr para acumular captures y (b) el numero de scopes
     * que existian ANTES de la lambda (su @c outer_depth).
     *
     * Cualquier @c IdentExpr resuelto en check_ident comprueba: si la
     * lambda esta activa y el indice del scope donde resolvio es
     * @c < outer_depth, entonces ese identificador es una variable
     * del entorno exterior y debe capturarse.  Lo registramos en
     * @c LambdaExpr::captures (sin duplicados) y guardamos su tipo
     * en @c LambdaExpr::capture_types para que el lowering decida el
     * ancho del LOAD/STORE en el env block.
     *
     * Anidamiento: dos lambdas anidadas producen dos entradas en el
     * stack.  La lambda interior captura del depth exterior a la
     * suya, no del global, asi que cada nivel mantiene su propio
     * outer_depth.  Captures transitivas (la lambda interior usa una
     * captura de la exterior) se manejan por composicion: cuando la
     * lambda interior captura, agrega el nombre a su lista; cuando
     * la lambda exterior se chequea, ese nombre tambien se resolvera
     * via captures de la exterior si era ajeno a su scope.
     */
    struct LambdaCtx {
        ast::LambdaExpr *expr; ///< Donde acumular captures.
        size_t outer_depth;    ///< scopes_.size() antes de push del scope de la
                               ///< lambda.
    };
    std::vector<LambdaCtx> lambda_stack_;
    /// Inferencia del tipo de retorno de un lambda block-body SIN tipo
    /// declarado ni contexto (p.ej. el lambda que emite un @Macro).  Mientras
    /// @c infer_lambda_void_return_ es true, un `return <valor>` en un cuerpo
    /// declarado VOID NO es error: su tipo se captura en
    /// @c inferred_lambda_return_type_ (el PRIMER return con valor manda) y se
    /// usa como tipo de retorno del lambda.  Se salva/restaura por nivel para
    /// soportar lambdas anidados.
    bool infer_lambda_void_return_ = false;
    Type inferred_lambda_return_type_{PrimitiveKind::VOID};
};

} // namespace vx

#endif // VX_TYPE_CHECKER_H
