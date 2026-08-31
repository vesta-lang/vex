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
 * @file types.h
 * @brief Representacion canonica del sistema de tipos del lenguaje Vesta.
 *
 * En Vesta se aceptan dos estilos sintacticos para los tipos primitivos
 * (estilo C++/stdint con sufijo _t y estilo corto sin sufijo); ambos
 * son tokens distintos pero designan exactamente el mismo tipo a
 * efectos semanticos.  Este modulo concentra la conversion canonica:
 *
 *   uint8_t  <->  u8   <->  PrimitiveKind::U8
 *   int32_t  <->  i32  <->  PrimitiveKind::I32
 *   double   <->  f64  <->  PrimitiveKind::F64
 *   ...
 *
 * La estructura @c Type
 * ya esta disenyada como union etiquetada por extension futura: el
 * miembro discriminador @c kind permite añadir variantes sin tocar
 * los call sites.
 *
 * Decision de hardware:
 *   - PrimitiveKind cabe en un byte; permite serializarlo en flat
 *     arrays y mantenerlo en cache cuando el type checker recorre
 *     muchos tipos (e.g. al validar parametros de una funcion).
 */

#ifndef VX_TYPES_H
#define VX_TYPES_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "vx/token.h"

namespace vx {

/**
 * @enum PrimitiveKind
 * @brief Tipos primitivos canonicos del lenguaje Vesta.
 *
 * Los valores ordinales son estables.  Si se añaden nuevos tipos,
 * hacerlo SIEMPRE al final del enum para que las tablas planas
 * indexadas por (uint8_t)kind permanezcan validas.
 */
enum class PrimitiveKind : uint8_t {
    VOID = 0,
    BOOL,
    CHAR,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    /// Puntero raw (8 bytes en x86-64). solo se usa como tipo
    /// del literal de string para FFI; en hitos posteriores aparece como
    /// T* generico
    PTR,
    /// Tipo agregado declarado por @c struct.  El nombre del struct se
    /// guarda en @c Type::struct_name; el TypeChecker mantiene el
    /// layout (offsets de campos + tamano total) en una tabla aparte.
    STRUCT,
    /// Tipo de instancia de clase Vesta (reference type).  El nombre de
    /// la clase se guarda en @c Type::struct_name (reusamos el campo
    /// para no duplicar storage).  A diferencia de STRUCT, las
    /// instancias viven en heap (NEWOBJ) y se acceden via puntero;
    /// igualdad estructural compara por nombre de clase.
    CLASS,
    /// Array nativo @c T[N] o @c T[].  El tipo de elemento se guarda en
    /// @c Type::pointee y el numero de elementos en @c Type::array_size
    /// (0 indica @c T[] sin size, usado como parametro de funcion para
    /// permitir el decay-to-pointer).  El layout es contiguo, sin
    /// header de longitud (no es @c Array<T> gestionado).
    ARRAY,
    /// `Optional<T>` builtin del compilador.  NO se modela como
    /// clase template: el lowering emite directamente un buffer en
    /// stack de 16 bytes (8 flag + 8 valor).  Tipo del payload en
    /// @c pointee.  Sin allocacion de heap, sin clase concreta por
    /// instanciado: el bytecode es identico para todos los Optional
    /// y solo varia el ancho del LOAD/STORE del payload.
    OPTIONAL,
    /// `Result<V, E>` builtin del compilador.  Stack value de
    /// 24 bytes: 8 tag (0=err, 1=ok) + 8 V + 8 E.  V en @c pointee y
    /// E en @c pointee2.
    RESULT,
    /// Tipo @c fn(T1, T2, ...) -> R: closure / function pointer.
    /// Layout en memoria: 16 bytes = `[+0 i64 fn_addr][+8 i64 env_addr]`.
    /// Cuando la lambda no captura nada, env_addr = 0 (sentinela "sin
    /// env") y la calling convention degenera a un callvmr puro sin
    /// pase de env.  Cuando captura N variables, env_addr apunta a un
    /// bloque contiguo en la pila del CALLER del cual el helper lee
    /// los captures por offset fijo.  Sin GC: el env vive en el stack
    /// frame del scope que crea la lambda; cuando ese scope sale, la
    /// lambda deja de ser valida (escape detection no implementado en
    /// MVP, vease README para extension a heap).
    ///
    /// Type carries the full signature in `fn_params` (parameter types)
    /// and `pointee` (return type); el call site las usa para validar
    /// aridad y compatibilidad de argumentos en compile time.
    FUNCTION,
    /// Tipo @c string de Vesta.  Reference-type al @c StringObject
    /// gestionado por GC.  Internamente es un GcHandle (i64) que el
    /// runtime dereferencia para acceder al header (encoding, length,
    /// byte_len, hash) y al buffer FLAT/ROPE/SLICE.  Cero overhead vs
    /// PTR; solo el type checker y el lowering distinguen entre
    /// @c string (managed) y @c cstring (alias de @c char* raw).
    ///
    /// Operaciones soportadas (todas via opcodes 0x46-0x54 del runtime):
    ///   s + t     -> STRCAT (rope concatenation O(1))
    ///   s == t    -> STRCMP (byte-level equality)
    ///   s.length()-> STRLEN (count code points)
    ///   s.bytes() -> STRGETBYTES (raw byte count)
    ///   s.cstr()  -> STRRAW (host_ptr al buffer NUL-terminated)
    ///   s.wstr()  -> STRCONV(UTF16) + STRRAW (host_ptr a wchar_t*)
    ///   s.slice(a,b) -> STRSLICE (vista O(1) sin copia)
    ///   s.intern()-> STRINTERN (canonical pool)
    ///   s.hash()  -> STRHASH (FNV-1a cacheado)
    ///   s.encoding() -> STRGETENC
    ///
    /// Literales `"hola"` siguen siendo PTR a static_data (cero coste);
    /// solo se promueven a StringObject via STRMAKE cuando se asignan
    /// a una variable @c string o se usan en operaciones que lo
    /// requieren (lazy promotion).
    STRING,
    /// Tipos primitivos de coleccion.  Cada uno modela un GcHandle
    /// opaco (i64, host pointer al descriptor del plugin nativo
    /// `vesta_collections.dll`).  El frontend trata estos tipos como
    /// primitivos, NO como clases: cero overhead vs llamar el plugin
    /// directo (sin vtable, sin CALLVIRT).  Las operaciones se despachan
    /// como builtins (CALLN directo) y la liberacion es AUTOMATICA al
    /// salir del scope (cleanup_stack_ del lowering).
    ///
    ///   ArrayList - array dinamico de uint64_t (vcol_alist_*)
    ///   HashMap   - tabla hash uint64->uint64 (vcol_map_*, swisstable+SSE2)
    ///   HashSet   - set hash uint64 (vcol_set_*)
    ///   Queue     - ring buffer FIFO uint64 (vcol_queue_*)
    ///   Deque     - ring buffer doble extremos (vcol_deque_*)
    ///   TreeMap   - mapa ordenado Red-Black uint64->uint64 (vcol_tmap_*)
    ///   TreeSet   - set ordenado Red-Black (vcol_tset_*)
    ///   Stack     - alias logico de ArrayList con LIFO (push/pop)
    ARRAYLIST,
    HASHMAP,
    HASHSET,
    QUEUE,
    DEQUE,
    TREEMAP,
    TREESET,
    STACK,
    /// `Future<T>` builtin del compilador (Mejora II).  Reference-type
    /// que envuelve el handle del FutureObject runtime (i64) preservando
    /// el tipo logico T del valor que el future resolvera.  El bytecode
    /// no cambia: FutureObject::result sigue siendo i64 opaco.  El
    /// frontend hace coercion T -> i64 al @c fulfill (zero/sign-extend
    /// para tipos < 8B) y i64 -> T al @c await (truncate/cast back).
    ///
    /// @c pointee = tipo T (payload del future).
    ///
    /// Limitaciones MVP:
    ///   - T debe tener tamano <= 8 bytes (i8..i64, u8..u64, f32, f64,
    ///     bool, char, ptr/handle).  Tipos compuestos (struct, array)
    ///     requeririan futures con buffer auxiliar (deferido).
    ///   - El handle queda en HandleTable hasta que el caller hace
    ///     await; tras await, el future muere salvo que algo lo
    ///     referencie (e.g., otra closure).
    FUTURE,
    /// `unique<T>` builtin del compilador (smart pointer move-only).
    /// Modelado como un slot de stack de 8 bytes (Tier 0: deleter
    /// conocido en compile-time, p.ej. @c free) o 16 bytes (Tier 1:
    /// deleter custom guardado al lado del ptr).
    ///
    /// Tier 0 (caso 95%): `[+0 u64 ptr]`.  El deleter se decide en
    /// compile-time por el builtin de construccion (@c unique_malloc
    /// usa @c free; @c unique_new usa @c ~T() virtual; @c unique_fopen
    /// usa @c fclose).  Cleanup al exit del scope emite un CALL
    /// directo al deleter, sin indireccion.
    ///
    /// Tier 1 (caso 4%): `[+0 u64 ptr][+8 u64 deleter_fn]`.  El
    /// deleter es variable runtime (capturado en construccion).
    /// Cleanup emite un CALL indirecto via reg.  Si el deleter es
    /// literal, el compilador colapsa a Tier 0.
    ///
    /// Move semantics: `unique<T> q = move(p)` emite UN solo opcode
    /// @c mvtake (0x72) que copia el ptr de p a q y zerifica p en
    /// 1 instr VM (3 instr host x86-64 tras JIT).
    ///
    /// @c pointee = tipo T del recurso apuntado.
    /// `borrow<T>` (shared) y `borrow_mut<T>` (exclusivo) builtins
    /// del compilador.  Modelan un puntero T* host pero con
    /// VERIFICACION DE ALIASING en compile-time (borrow checker).
    ///
    /// Runtime: ambos son 8 bytes (host_ptr, identico a `T*`).
    /// Toda la seguridad esta en el type checker:
    ///   R1: solo UN borrow_mut activo OR multiples borrow shared.
    ///   R2: prohibido leer/mutar/mover el owner mientras prestado.
    ///   R3: los borrows no pueden sobrevivir al owner (no escape).
    ///
    /// @c pointee = tipo T apuntado.
    BORROW,
    BORROW_MUT,
    UNIQUE_PTR,
    /// `shared<T>` builtin del compilador (smart pointer con refcount).
    /// Slot de stack de 8 bytes (host_ptr al control block).  El
    /// control block vive en el GcHeap y se aloca via @c gcallocp
    /// (alocacion unica con el payload contiguo, estilo
    /// @c std::make_shared):
    ///
    ///   `[+0 i64 refcount][+8 u64 deleter][+16 T payload]`
    ///
    /// La copia incrementa el refcount; la destruccion al exit lo
    /// decrementa y, si llega a 0, ejecuta el deleter.  No atomic
    /// por defecto (single-thread).  Con @c @ThreadSafe se usaria
    /// CAS, pero el MVP mantiene refcount simple.
    ///
    /// @c pointee = tipo T del payload.
    SHARED_PTR,
    /// `gc<T>` builtin opt-in (`import vx.gc`): referencia GC-managed.  El
    /// parser produce este kind; el type checker lo CONVIERTE a @c CLASS con
    /// @c gc_managed=true (reusa todo el acceso a miembros de clase).  Por eso
    /// GC_PTR no deberia sobrevivir al type checking en valores; es solo la
    /// forma parseada del tipo.  Slot de 8 bytes (host_ptr al payload, igual
    /// que una ref de clase native_poo, pero alocado por el GC y sin RAII).
    GC_PTR,
    /// Type-as-first-class-value.  Sentinela usado SOLO en
    /// declaraciones de @c comptime const Type T = comptime_type<X>().
    /// No tiene representacion runtime (cero bytes); el ComptimeConst
    /// asociado lleva el @c Type real en su campo @c type_val.  Al
    /// usar `T` en posicion de tipo, `type_from_node` lo resuelve via
    /// @c comptime_const_values_.
    TYPE_META,
    // Sentinela para construir tablas planas.
    COUNT
};

/**
 * @struct Type
 * @brief Representacion del tipo de una expresion o declaracion.
 *
 * El miembro @c kind es el discriminador principal; campos adicionales
 * (@c pointee para punteros, @c fn_params/fn_return para funciones,
 * @c element_type para arrays, @c struct_name para structs/clases/
 * enums, @c is_virtual para distinguir punteros VM vs host, etc.)
 * estan declarados pero solo son relevantes para el @c kind apropiado.
 *
 * Layout: 1 byte util + padding -> queda en 1 cache line incluso
 * cuando se almacenan miles de tipos juntos.
 */
struct Type {
    PrimitiveKind kind = PrimitiveKind::VOID;
    /// Nombre del struct (vacio para todo lo demas).  Se incluye aqui
    /// porque distinguir @c Punto de @c Color requiere el nombre, y
    /// porque el numero de structs por modulo es pequenyo (tipicamente
    /// decenas), por lo que el coste del std::string en cache es
    /// despreciable comparado con la simplicidad del modelo.  Si en
    /// el futuro la presion de cache importa, se puede sustituir por
    /// un indice a una pool de StructLayout en TypeChecker.
    std::string struct_name;
    /// @c true si esta referencia de clase (@c kind == CLASS) es GC-managed
    /// (declarada como @c gc<X>): se aloca con @c vx_gc_alloc en vez de
    /// @c calloc, no tiene cleanup RAII (el GC colecta, incl. ciclos), y su
    /// slot se marca @c is_gc_object para los stackmaps precisos del GC.  El
    /// resto (acceso a campos/metodos) es identico a una ref de clase normal.
    bool gc_managed = false;
    /// @c true si este tipo es un enum con VALOR entero (C-style,
    /// `enum Op : u8 { ... }`).  @c kind es el tipo base (U8/U16/...)
    /// y @c struct_name el nombre del enum, para resolver variantes y
    /// distinguirlo de un entero plano.  El lowering lo trata como su
    /// entero base en todos los sitios.
    bool is_valued_enum = false;
    /// Tipo apuntado cuando @c kind == PTR o tipo de elemento cuando
    /// @c kind == ARRAY; nulo para todo lo demas.  Se usa @c shared_ptr
    /// porque @c Type debe ser copiable (el AST Type vive como valor en
    /// cada Expr) y porque la cadena puede ser arbitraria (T**, T**[5]
    /// etc.).  El coste de heap por nivel es aceptable: pocos arrays /
    /// punteros por modulo y el campo solo se materializa cuando aplica.
    std::shared_ptr<Type> pointee;
    /// Segundo tipo para cuando @c kind == RESULT (V en @c pointee, E
    /// aqui).  No se usa para los demas kinds.
    std::shared_ptr<Type> pointee2;
    /// Tamano del array cuando @c kind == ARRAY; 0 si es @c T[] (decay).
    /// No se usa para los otros kinds.
    uint32_t array_size = 0;

    /// Naturaleza del puntero cuando @c kind == PTR o ARRAY.
    /// false = puntero HOST (default; los datos viven en memoria del
    ///         proceso real, accesibles via opcode @c movh).  Producido
    ///         por @c malloc, @c str_cstr, FFI, fields de objetos GC, etc.
    /// true  = puntero VIRTUAL (la direccion es offset dentro del
    ///         vm_mem del proceso VM, accesible via opcode @c mov).
    ///         Producido por @c &local, @c T[N] arrays nativos
    ///         locales, y por la sintaxis explicita @c VirtualPtr<T>.
    ///
    /// La naturaleza de la direccion (host/virtual) y el tipo del
    /// contenido (apuntado por @c pointee) son ortogonales: un
    /// @c VirtualPtr<u8*> es una direccion VM cuyo contenido es a su
    /// vez un puntero HOST (resultado de @c malloc por ejemplo).
    ///
    /// La aritmetica preserva el flag.  Mezclar host con virtual en
    /// asignacion / comparacion es error de tipo.
    bool is_virtual = false;

    /// const-correctness C-style, POR NIVEL.  @c is_const marca que ESTE nivel
    /// del tipo es inmutable: para un escalar/struct, el valor no se puede
    /// escribir; para un PTR, el PUNTERO no se puede reasignar (la const del
    /// APUNTADO vive en @c pointee->is_const).  Asi `const char *` =
    /// PTR{is_const=false, pointee=char{is_const=true}} y `char *const` =
    /// PTR{is_const=true, pointee=char{is_const=false}}.  El enforcement es
    /// uniforme: escribir a un lvalue es error si @c
    /// lvalue.result_type.is_const. Ortogonal a @c is_virtual y a la forma del
    /// tipo (NO entra en la igualdad estructural).
    bool is_const = false;

    /// Tipos de los parametros cuando @c kind == FUNCTION.  Vacio para
    /// los demas kinds.  La lista se materializa solo cuando se crea un
    /// tipo @c fn(...), por lo que el coste de cache para tipos no-fn
    /// es solo el de un std::vector vacio (3 punteros, 24 bytes en x64
    /// libstdc++) que se queda sin alocar nada en heap.  Para llamar a
    /// un function value, el call site recorre esta lista para validar
    /// aridad y tipos en compile time.
    std::vector<Type> fn_params;

    /// ABI custom por-parametro cuando @c kind == FUNCTION: registro fisico de
    /// entrada por parametro, alineado con @c fn_params.  Cadena vacia = ABI
    /// estandar.  Forma parte de la IDENTIDAD del tipo (ver operator==): dos
    /// @c cfn con abi_regs distintos son tipos DISTINTOS, asi una CALLIND
    /// conoce la ABI en compile-time desde el tipo del puntero.  Vacio cuando
    /// ningun parametro tiene ABI custom (caso comun; no aloca heap).
    std::vector<std::string> fn_param_abi_regs;

    /// Solo para @c kind == FUNCTION: distingue el LAMBDA/closure (false,
    /// @c fn(...) -> R, fat-pointer de 16 bytes {fn_addr, env}) del PUNTERO
    /// A FUNCION crudo estilo C (true, @c cfn(...) -> R, 8 bytes = solo la
    /// direccion, llamada directa via CALLIND, sin env).  lambda != cfn.
    bool fn_is_raw = false;

    /// Solo para @c kind == FUNCTION: el ultimo parametro recoge los que
    /// sobren.  En @c fn_params ese ultimo aparece ya como `T*` -- que es lo
    /// que el cuerpo ve --, asi que el tipo del ELEMENTO se saca de su
    /// @c pointee.  Forma parte del tipo: una funcion variadica y una que no lo
    /// es NO son intercambiables, porque la llamada se monta distinto.
    bool fn_is_variadic = false;

    /// Newtype nominal ID (typedef T name new).  0 = no es newtype
    /// (alias transparente clasico).  Cualquier valor > 0 identifica
    /// univocamente al newtype: dos Type con kinds/representacion
    /// identicos pero distinto @c nominal_id son tipos DIFERENTES.
    /// El ID se asigna en el type checker (counter global) cuando
    /// se procesa la TypeAliasDecl con marca @c is_newtype.
    /// Conservacion: cualquier copia de un Type preserva el ID;
    /// la representacion subyacente (kind, pointee, etc.) se mantiene
    /// para que el lowering y el ABI nativo no cambien.
    uint32_t nominal_id = 0;

    /// @c true si el newtype es @c @opaque: el usuario NO puede leer
    /// los bits subyacentes (no hay cast implicito ni inicializacion
    /// por literal).  Solo se puede construir/consumir via funciones
    /// que lo manejen explicitamente.  Sin efecto si @c nominal_id == 0.
    bool is_opaque = false;

    /// Nombre humano-legible del newtype (para mensajes de error e
    /// introspeccion).  Vacio si no es newtype.
    std::string nominal_name;

    /// Nombre de la funcion que libera el recurso, cuando @c kind es
    /// @c UNIQUE_PTR o @c SHARED_PTR.  Vacio = el de por defecto.
    ///
    /// Va en el TIPO, no guardado en la ranura, y por eso un puntero
    /// inteligente ocupa OCHO bytes y no dieciseis: quien limpia sabe al
    /// COMPILAR a quien llamar, asi que no hay nada que guardar.  Es lo mismo
    /// que hace C++ -- ahi el liberador es un parametro de plantilla y
    /// `default_delete` es una clase vacia --, salvo que aqui tambien sale
    /// gratis el liberador propio, que en C++ cuesta ocho bytes cuando es un
    /// puntero a funcion.
    ///
    /// Dos `unique<T>` con liberador distinto son tipos DISTINTOS: mezclarlos
    /// significaria liberar con el que no es.  Un `unique<T>` escrito sin
    /// liberador en una DECLARACION LOCAL adopta el de su inicializador; donde
    /// el tipo esta fijado de antemano -- un campo, una firma -- hay que
    /// escribirlo, porque quien limpie del otro lado tiene que saberlo.
    std::string deleter_name;

    /// Alineacion forzada en bytes (sintaxis @c "@align(N)").  0 = sin
    /// override (usar alineacion natural del kind).  Debe ser potencia
    /// de 2 en [1, 4096].  Aplica cuando el tipo se usa como campo de
    /// struct o como ALLOCA: el frontend padea hasta cumplir el
    /// requirement.  Util para SIMD (16/32/64), DMA, GPU descriptors,
    /// protocolos de wire format con padding fijo.
    uint16_t align_override = 0;

    Type() = default;
    explicit Type(PrimitiveKind k) : kind(k) {}
    Type(PrimitiveKind k, std::string sn)
        : kind(k), struct_name(std::move(sn)) {}

    /**
     * @brief Construye un PTR a otro tipo (host por defecto).
     * @param virt true para VirtualPtr<T> (direccion VM), false para
     *             T* convencional (host).
     */
    static Type make_ptr(Type pointee_ty, bool virt = false) {
        Type t;
        t.kind = PrimitiveKind::PTR;
        t.pointee = std::make_shared<Type>(std::move(pointee_ty));
        t.is_virtual = virt;
        return t;
    }

    /**
     * @brief Construye un ARRAY de tamano fijo (size > 0) o variable (size ==
     * 0).
     *
     * Los arrays nativos (@c T[N] declarados como local o miembro) son
     * SIEMPRE virtuales: el ALLOCA reserva en stack VM.  Por eso
     * @c is_virtual queda a true por defecto.  Los arrays cargados de
     * memoria host (rara vez) deben construirse con virt=false.
     */
    static Type make_array(Type element_ty, uint32_t size, bool virt = true) {
        Type t;
        t.kind = PrimitiveKind::ARRAY;
        t.pointee = std::make_shared<Type>(std::move(element_ty));
        t.array_size = size;
        t.is_virtual = virt;
        return t;
    }

    /**
     * @brief Compara dos tipos por igualdad estructural (sigue la cadena de
     * punteros).
     */
    bool operator==(const Type &o) const noexcept {
        // Newtypes con distinto nominal_id son tipos DIFERENTES aunque
        // la representacion subyacente coincida.  nominal_id == 0
        // significa "no es newtype" -> caen al check estructural.
        if (nominal_id != o.nominal_id) return false;
        // align_override forma parte de la identidad del tipo: dos
        // newtypes con misma representacion pero @align(N) distinto
        // son tipos distintos (al menos para evitar mezcla accidental).
        if (align_override != o.align_override) return false;
        if (kind != o.kind || struct_name != o.struct_name) return false;
        /* Para un puntero inteligente, QUIEN LIBERA es parte de la identidad:
         * mezclar dos con liberador distinto significaria liberar con el que
         * no es.  Es lo mismo que en C++, donde el liberador es un parametro
         * de la plantilla y `unique_ptr<T>` y `unique_ptr<T,D>` son tipos
         * distintos. */
        if ((kind == PrimitiveKind::UNIQUE_PTR ||
             kind == PrimitiveKind::SHARED_PTR) &&
            deleter_name != o.deleter_name)
            return false;
        // Para PTR/ARRAY la naturaleza host vs virtual ES parte de la
        // identidad de tipo: `T*` y `VirtualPtr<T>` son tipos distintos.
        if ((kind == PrimitiveKind::PTR || kind == PrimitiveKind::ARRAY) &&
            is_virtual != o.is_virtual)
            return false;
        // Para ARRAY el tamano es parte de la identidad (i32[3] != i32[5]).
        if (kind == PrimitiveKind::ARRAY && array_size != o.array_size)
            return false;
        // Para PTR/ARRAY/OPTIONAL/RESULT/FUNCTION comparamos pointee
        // (return type para FUNCTION) y, si aplica, pointee2 (E del
        // Result).
        const bool a_has = static_cast<bool>(pointee);
        const bool b_has = static_cast<bool>(o.pointee);
        if (a_has != b_has) return false;
        if (a_has && b_has && !(*pointee == *o.pointee)) return false;
        if (kind == PrimitiveKind::RESULT) {
            const bool a2 = static_cast<bool>(pointee2);
            const bool b2 = static_cast<bool>(o.pointee2);
            if (a2 != b2) return false;
            if (a2 && b2 && !(*pointee2 == *o.pointee2)) return false;
        }
        // Para FUNCTION la lista de parametros tambien forma parte de
        // la identidad estructural.  Dos `fn(i32) -> i32` con distinta
        // aridad o distinto tipo de parametro son tipos diferentes.
        if (kind == PrimitiveKind::FUNCTION) {
            // lambda (fn) != puntero a funcion crudo (cfn): tipos distintos
            // aunque compartan firma (representacion 16B vs 8B).
            if (fn_is_raw != o.fn_is_raw) return false;
            if (fn_is_variadic != o.fn_is_variadic) return false;
            if (fn_params.size() != o.fn_params.size()) return false;
            for (size_t i = 0; i < fn_params.size(); ++i) {
                if (!(fn_params[i] == o.fn_params[i])) return false;
            }
            // La ABI custom por-parametro forma parte de la identidad del tipo:
            // dos cfn con abi_regs distintos son tipos INCOMPATIBLES (asi una
            // CALLIND conoce la ABI en compile-time desde el tipo del puntero,
            // y asignar &f_abiA a un campo cfn-de-abiB es un error de tipos).
            // Se comparan posicionalmente, normalizando "vector vacio" == "todo
            // ABI estandar" para que un tipo sin ABI custom (vector vacio)
            // iguale a uno con la lista de "" explicita.
            for (size_t i = 0; i < fn_params.size(); ++i) {
                const std::string a = i < fn_param_abi_regs.size()
                                          ? fn_param_abi_regs[i]
                                          : std::string();
                const std::string b = i < o.fn_param_abi_regs.size()
                                          ? o.fn_param_abi_regs[i]
                                          : std::string();
                if (a != b) return false;
            }
        }
        return true;
    }

    /// @brief Construye un Optional<T> builtin.  Layout en memoria
    /// (compartido por todos los Optional, sin clase concreta):
    /// `[+0 i64 flag][+8 8-byte payload]`.  El pointee es el tipo
    /// del payload; el frontend usa este tipo para decidir el ancho
    /// del LOAD/STORE en Some/unwrap.
    static Type make_optional(Type inner) {
        Type t;
        t.kind = PrimitiveKind::OPTIONAL;
        t.pointee = std::make_shared<Type>(std::move(inner));
        return t;
    }
    /// @brief Construye un Result<V, E> builtin.  Layout 24 bytes:
    /// `[+0 i64 tag (0=err, 1=ok)][+8 V][+16 E]`.
    static Type make_result(Type ok_t, Type err_t) {
        Type t;
        t.kind = PrimitiveKind::RESULT;
        t.pointee = std::make_shared<Type>(std::move(ok_t));
        t.pointee2 = std::make_shared<Type>(std::move(err_t));
        return t;
    }

    /**
     * @brief Construye un tipo @c fn(P1, P2, ...) -> R (closure).
     *
     * Layout en memoria: 16 bytes = `[+0 i64 fn_addr][+8 i64 env_addr]`.
     * Dos function types son iguales si tienen el mismo numero de
     * parametros con tipos identicos en el mismo orden y el mismo
     * return type.  La firma se usa en compile time para validar la
     * llamada y deducir el tipo del resultado.
     *
     * @param params Tipos de los parametros (en orden).  Se mueve.
     * @param ret    Tipo de retorno.  Se mueve.
     * @return Type con kind = FUNCTION, pointee = ret, fn_params = params.
     */
    static Type make_function(std::vector<Type> params, Type ret) {
        Type t;
        t.kind = PrimitiveKind::FUNCTION;
        t.pointee = std::make_shared<Type>(std::move(ret));
        t.fn_params = std::move(params);
        return t;
    }

    /// @brief Construye un Future<T> builtin (Mejora II).  Layout en
    /// memoria: 8 bytes (handle del FutureObject runtime).  El @c pointee
    /// es el tipo T del payload que el future resolvera.  Dos
    /// @c Future<T> son iguales si los T son iguales.
    static Type make_future(Type inner) {
        Type t;
        t.kind = PrimitiveKind::FUTURE;
        t.pointee = std::make_shared<Type>(std::move(inner));
        return t;
    }

    /// @brief Construye un @c borrow<T> (shared) o @c borrow_mut<T>
    /// (exclusive).  Layout 8 bytes (host_ptr).  El borrow checker
    /// del type_checker valida las reglas de aliasing en compile-time.
    static Type make_borrow(Type inner, bool is_mut) {
        Type t;
        t.kind = is_mut ? PrimitiveKind::BORROW_MUT : PrimitiveKind::BORROW;
        t.pointee = std::make_shared<Type>(std::move(inner));
        return t;
    }

    /// @brief Construye un @c unique<T> builtin (smart pointer move-only).
    /// El campo @c is_virtual del Type result distingue HOST vs VM,
    /// heredado del Type apuntado segun lo decida el builtin de
    /// construccion (e.g. @c unique_malloc devuelve host, una
    /// hipotetica @c unique_local devolveria virtual).  Por
    /// defecto: host (la mayoria de usos: malloc/new/fopen).
    static Type make_unique(Type inner) {
        Type t;
        t.kind = PrimitiveKind::UNIQUE_PTR;
        t.pointee = std::make_shared<Type>(std::move(inner));
        return t;
    }

    /// @brief Construye un @c shared<T> builtin (smart pointer con refcount).
    /// El control block + payload viven en el GcHeap (heap GC); el
    /// slot stack contiene un host_ptr al control block.
    static Type make_shared(Type inner) {
        Type t;
        t.kind = PrimitiveKind::SHARED_PTR;
        t.pointee = std::make_shared<Type>(std::move(inner));
        return t;
    }

    bool operator!=(const Type &o) const noexcept { return !(*this == o); }
};

/**
 * @brief Convierte un TokenKind de palabra reservada de tipo a PrimitiveKind.
 *
 * Acepta tanto el estilo corto (i8, u32, f64) como el estilo C/stdint
 * (int8_t, uint32_t, double).  Ambos producen el mismo PrimitiveKind.
 *
 * @param k Token producido por el lexer.
 * @return PrimitiveKind canonico, o @c PrimitiveKind::COUNT si @p k no
 *         designa un tipo primitivo.  El caller debe chequear contra
 *         COUNT antes de usar el valor.
 */
constexpr PrimitiveKind primitive_kind_from_token(TokenKind k) noexcept {
    switch (k) {
    // Bloque "compartido" (sin alias).
    case TokenKind::KW_VOID: return PrimitiveKind::VOID;
    case TokenKind::KW_BOOL: return PrimitiveKind::BOOL;
    case TokenKind::KW_CHAR: return PrimitiveKind::CHAR;

    // Estilo corto.
    case TokenKind::KW_INT8: return PrimitiveKind::I8;
    case TokenKind::KW_INT16: return PrimitiveKind::I16;
    case TokenKind::KW_INT32: return PrimitiveKind::I32;
    case TokenKind::KW_INT64: return PrimitiveKind::I64;

    case TokenKind::KW_UINT8: return PrimitiveKind::U8;
    case TokenKind::KW_UINT16: return PrimitiveKind::U16;
    case TokenKind::KW_UINT32: return PrimitiveKind::U32;
    case TokenKind::KW_UINT64: return PrimitiveKind::U64;

    case TokenKind::KW_F32: return PrimitiveKind::F32;
    case TokenKind::KW_F64: return PrimitiveKind::F64;

    // Estilo C/stdint.
    case TokenKind::KW_INT8_T: return PrimitiveKind::I8;
    case TokenKind::KW_INT16_T: return PrimitiveKind::I16;
    case TokenKind::KW_INT32_T: return PrimitiveKind::I32;
    case TokenKind::KW_INT64_T: return PrimitiveKind::I64;

    case TokenKind::KW_UINT8_T: return PrimitiveKind::U8;
    case TokenKind::KW_UINT16_T: return PrimitiveKind::U16;
    case TokenKind::KW_UINT32_T: return PrimitiveKind::U32;
    case TokenKind::KW_UINT64_T: return PrimitiveKind::U64;

    case TokenKind::KW_FLOAT: return PrimitiveKind::F32;
    case TokenKind::KW_DOUBLE: return PrimitiveKind::F64;

    // Tipo string dedicado (referencia a StringObject GC-managed).
    case TokenKind::KW_STRING: return PrimitiveKind::STRING;

    // tipos primitivos de coleccion (handles del plugin
    // vesta_collections.dll, gestionados con auto-free al exit).
    case TokenKind::KW_ARRAYLIST: return PrimitiveKind::ARRAYLIST;
    case TokenKind::KW_HASHMAP: return PrimitiveKind::HASHMAP;
    case TokenKind::KW_HASHSET: return PrimitiveKind::HASHSET;
    case TokenKind::KW_QUEUE: return PrimitiveKind::QUEUE;
    case TokenKind::KW_DEQUE: return PrimitiveKind::DEQUE;
    case TokenKind::KW_TREEMAP: return PrimitiveKind::TREEMAP;
    case TokenKind::KW_TREESET: return PrimitiveKind::TREESET;
    case TokenKind::KW_STACK: return PrimitiveKind::STACK;

    // Smart pointers builtins (move-only + refcount).  El payload T
    // se completa en el parser via `unique<T>` / `shared<T>`.
    case TokenKind::KW_UNIQUE: return PrimitiveKind::UNIQUE_PTR;
    case TokenKind::KW_SHARED: return PrimitiveKind::SHARED_PTR;
    case TokenKind::KW_GC: return PrimitiveKind::GC_PTR;
    // Borrows (referencias compile-time-checkadas, runtime = host_ptr).
    case TokenKind::KW_BORROW: return PrimitiveKind::BORROW;
    case TokenKind::KW_BORROW_MUT: return PrimitiveKind::BORROW_MUT;

    // No es un tipo primitivo.
    default: return PrimitiveKind::COUNT;
    }
}

/**
 * @brief @c true si k designa un tipo entero (con o sin signo).
 */
constexpr bool is_integral(PrimitiveKind k) noexcept {
    // Rango contiguo en el enum: I8..U64.  Comparacion numerica
    // mas barata que un switch lineal.
    return (uint8_t)k >= (uint8_t)PrimitiveKind::I8 &&
           (uint8_t)k <= (uint8_t)PrimitiveKind::U64;
}

/**
 * @brief @c true si k designa un tipo entero con signo.
 */
constexpr bool is_signed_integral(PrimitiveKind k) noexcept {
    return (uint8_t)k >= (uint8_t)PrimitiveKind::I8 &&
           (uint8_t)k <= (uint8_t)PrimitiveKind::I64;
}

/**
 * @brief @c true si k designa un tipo flotante (f32 o f64).
 */
constexpr bool is_floating(PrimitiveKind k) noexcept {
    return k == PrimitiveKind::F32 || k == PrimitiveKind::F64;
}

/**
 * @brief @c true si k designa un tipo numerico (entero o flotante).
 */
constexpr bool is_numeric(PrimitiveKind k) noexcept {
    return is_integral(k) || is_floating(k);
}

/**
 * @brief Bytes que ocupa la RANURA de un envoltorio de puntero inteligente.
 *
 * Un `unique<T>` suelto guarda dos cosas -- el puntero y su liberador --, y un
 * `shared<T>` o un `borrow<T>` una sola: el puntero al bloque de control, que
 * ya lleva el liberador dentro.
 *
 * ESTE ES EL SITIO DONDE VA LA OPTIMIZACION.  El tamano de estos tipos NO es
 * fijo: siempre que se pueda ocupar menos, mejor, y cuanto se puede ocupar
 * depende del caso concreto -- un `Optional` de un puntero acaba midiendo lo
 * que el puntero, porque el nulo ya sirve de marca, y un `unique` cuyo
 * liberador se conoce al compilar no necesita guardarlo --.  Mientras eso no
 * este, esta funcion devuelve la cota de arriba, que es siempre correcta
 * aunque gaste.
 *
 * Estaba escrita a mano en cuatro sitios del bajado.  Con la decision
 * repartida, la optimizacion habria que meterla en los cuatro y el primero que
 * se olvidara daria una ranura de un tamano y una escritura de otro.
 *
 * @param k Clase del tipo.
 * @return Bytes de la ranura.
 */
constexpr size_t smart_ptr_slot_bytes(PrimitiveKind k) noexcept {
    /* OCHO, los dos: la ranura guarda SOLO el puntero al recurso.
     *
     * Quien libera va en el TIPO (@c Type::deleter_name), asi que quien limpia
     * sabe al COMPILAR a quien llamar y no hay nada que guardar.  Antes un
     * `unique<T>` media dos palabras porque llevaba el liberador al lado, y
     * hacia falta porque no habia forma de decirlo en una firma: cuando el
     * puntero venia de una funcion, el liberador se leia de la ranura EN
     * EJECUCION.
     *
     * Lo que se gana: con el liberador de por defecto esa segunda palabra era
     * SIEMPRE un cero -- ocho bytes por una constante, en el caso mas
     * frecuente --.  Y en un CAMPO no cabia, asi que obligaba a un bloque
     * aparte en el monton: treinta y dos bytes y DOS reservas para guardar un
     * entero, contra dieciseis y una.
     *
     * C++ llega a ocho por el mismo camino (el liberador es un parametro de
     * plantilla y `default_delete` es una clase vacia); alli un liberador
     * propio vuelve a costar ocho porque guarda el puntero a funcion, y aqui
     * es gratis tambien. */
    /* OCHO los dos: la ranura guarda SOLO el puntero al recurso.
     *
     * Quien libera va en el TIPO (@c Type::deleter_name), asi que quien limpia
     * sabe al COMPILAR a quien llamar y no hay nada que guardar.  Antes un
     * `unique<T>` media dos palabras porque llevaba el liberador al lado, y con
     * el de por defecto esa segunda palabra era SIEMPRE un cero: ocho bytes por
     * una constante, en el caso mas frecuente.  Peor en un CAMPO, donde no
     * cabia y obligaba a un bloque aparte en el monton -- treinta y dos bytes y
     * DOS reservas para guardar un entero, contra dieciseis y una --.
     *
     * C++ llega a ocho por el mismo camino (el liberador es un parametro de
     * plantilla y `default_delete` es una clase vacia); alli un liberador
     * propio vuelve a costar ocho porque guarda el puntero a funcion, y aqui es
     * gratis tambien. */
    (void)k;
    return 8u;
}

/**
 * @brief Tamano en bytes del tipo primitivo.
 *
 * @return Numero de bytes ocupados por una instancia, o 0 para VOID.
 */
constexpr size_t primitive_size_bytes(PrimitiveKind k) noexcept {
    switch (k) {
    case PrimitiveKind::VOID: return 0;
    case PrimitiveKind::BOOL: return 1;
    case PrimitiveKind::CHAR: return 1;
    case PrimitiveKind::I8: return 1;
    case PrimitiveKind::I16: return 2;
    case PrimitiveKind::I32: return 4;
    case PrimitiveKind::I64: return 8;
    case PrimitiveKind::U8: return 1;
    case PrimitiveKind::U16: return 2;
    case PrimitiveKind::U32: return 4;
    case PrimitiveKind::U64: return 8;
    case PrimitiveKind::F32: return 4;
    case PrimitiveKind::F64: return 8;
    case PrimitiveKind::PTR: return 8;
    // Para STRUCT y ARRAY el caller debe consultar metadata extra
    // (StructLayout, array_size + sizeof(element)).  Devolvemos 0
    // como sentinela y el callsite valida.
    case PrimitiveKind::STRUCT: return 0;
    // CLASS es un reference type: la "variable" guarda un puntero
    // al ObjectHeader, asi que ocupa 8 bytes.  El tamano de la
    // instancia (instance_size) lo gestiona el ClassRegistry.
    case PrimitiveKind::CLASS: return 8;
    case PrimitiveKind::ARRAY: return 0;
    // FUNCTION es siempre un par (fn_addr, env_addr) -> 16 bytes.
    // Cero overhead vs un puntero plano cuando no hay capturas
    // (env_addr = 0) y captura "first-class" cuando si las hay.
    case PrimitiveKind::OPTIONAL: return 16;
    case PrimitiveKind::RESULT: return 24;
    case PrimitiveKind::FUNCTION: return 16;
    // string es un GcHandle (i64) opaco al frontend; el StringObject
    // real vive en el heap del GC y se accede via instrucciones
    // dedicadas (STRRAW, STRGETBYTES, etc.).
    case PrimitiveKind::STRING: return 8;
    // Tipos primitivos de coleccion: cada uno es un handle (i64) que
    // el plugin nativo de colecciones traduce a la estructura real
    // en su propia heap.  El frontend solo conoce el handle opaco.
    case PrimitiveKind::ARRAYLIST: return 8;
    case PrimitiveKind::HASHMAP: return 8;
    case PrimitiveKind::HASHSET: return 8;
    case PrimitiveKind::QUEUE: return 8;
    case PrimitiveKind::DEQUE: return 8;
    case PrimitiveKind::TREEMAP: return 8;
    case PrimitiveKind::TREESET: return 8;
    case PrimitiveKind::STACK: return 8;
    // Future<T>: 8 bytes (handle del FutureObject runtime).  El T
    // logico no afecta al storage: el bytecode siempre opera sobre
    // el handle como i64.
    case PrimitiveKind::FUTURE: return 8;
    // Borrows: 8 bytes (host_ptr).  Verificacion compile-time.
    case PrimitiveKind::BORROW: return 8;
    case PrimitiveKind::BORROW_MUT: return 8;
    // Smart pointers: 8 bytes (slot stack con host_ptr al recurso).
    // Para Tier 1 con deleter custom seran 16 bytes; el frontend
    // todavia no usa esa variante (cuando llegue se diferenciara
    // via campo extra del Type).
    case PrimitiveKind::UNIQUE_PTR: return 8;
    case PrimitiveKind::SHARED_PTR: return 8;
    case PrimitiveKind::GC_PTR: return 8;
    // TYPE_META: marcador comptime sin storage runtime.
    case PrimitiveKind::TYPE_META: return 0;
    case PrimitiveKind::COUNT: return 0;
    }
    return 0;
}

/**
 * @brief A cuantos bytes se alinea un valor de este tipo.
 *
 * No es lo mismo que su tamano, y confundirlos sale caro.  Un `Result` mide
 * veinticuatro bytes -- tres palabras -- pero se alinea a ocho: alinearlo a su
 * tamano da un numero que ni siquiera es potencia de dos, y un struct con un
 * campo asi acaba midiendo setenta y dos bytes donde le bastan cuarenta.
 *
 * Esto lo decidian dos sitios: el calculo del layout de un struct, que tomaba
 * la alineacion IGUAL al tamano, y la introspeccion, que tenia esta tabla.  La
 * segunda estaba bien.
 *
 * @param k Clase del tipo.
 * @return Alineacion en bytes.
 */
constexpr size_t primitive_align_bytes(PrimitiveKind k) noexcept {
    const size_t sz = primitive_size_bytes(k);
    // Nada se alinea a mas de una palabra, y nada a cero.
    if (sz == 0) return 1;
    return sz > 8 ? 8 : sz;
}

/**
 * @brief Nombre canonico del tipo primitivo (estilo corto).
 *
 * Usar el estilo corto en mensajes de error es preferible porque es
 * mas legible y unifica los dos alias del usuario en una sola
 * representacion.
 *
 * @param k Tipo primitivo.
 * @return Cadena estatica (no liberar).
 */
/**
 * @brief Nombre legible de un Type completo (incluye chain de punteros).
 *
 * Crea una cadena nueva por cada llamada (tipico de mensajes de error),
 * por lo que no se debe usar en hot paths.  Para PTR escribe "T*", para
 * STRUCT usa el nombre concreto, para primitivos usa el estilo corto.
 *
 * @param t Tipo a formatear.
 * @return std::string nuevo con la representacion textual.
 */
inline std::string type_to_string(const Type &t) {
    // const-correctness: mostrar el qualifier en los mensajes de error para
    // que un discard de const (`i32* = const i32*`) sea legible ("const i32*
    // incompatible con i32*") en vez de "i32* incompatible con i32*".
    if (t.is_const) {
        Type nc = t;
        nc.is_const = false;
        return "const " + type_to_string(nc);
    }
    // Newtype: mostrar el nombre nominal (e.g. "fd" en vez de "u64").
    // Asi los mensajes de error son legibles ("incompatible con fd"
    // en lugar de "incompatible con u64").
    if (t.nominal_id != 0 && !t.nominal_name.empty()) {
        return t.nominal_name;
    }
    /* Un puntero inteligente ENSENA quien libera, porque forma parte de su
     * identidad: sin esto, decir que `unique<i64>` no es compatible con
     * `unique<i64>` era un mensaje que no decia nada -- los dos lados se
     * imprimian igual y la diferencia estaba justo en lo que no se veia. */
    if ((t.kind == PrimitiveKind::UNIQUE_PTR ||
         t.kind == PrimitiveKind::SHARED_PTR) &&
        !t.deleter_name.empty()) {
        const char *n =
            (t.kind == PrimitiveKind::UNIQUE_PTR) ? "unique<" : "shared<";
        /* El nombre CORTO, que es el que el usuario escribio: por dentro lleva
         * el del espacio de nombres pegado delante -- dos `cerrar` de sitios
         * distintos son liberadores distintos -- pero ensenarselo en un
         * mensaje solo estorba. */
        const std::string &d = t.deleter_name;
        const size_t sep = d.rfind("__");
        return n + (t.pointee ? type_to_string(*t.pointee) : "?") + ", " +
               (sep == std::string::npos ? d : d.substr(sep + 2)) + ">";
    }
    if (t.kind == PrimitiveKind::PTR) {
        // T* (host por defecto) vs VirtualPtr<T> (direccion VM).
        if (t.is_virtual) {
            return std::string("VirtualPtr<") +
                   (t.pointee ? type_to_string(*t.pointee) : "?") + ">";
        }
        if (t.pointee) return type_to_string(*t.pointee) + "*";
        return "ptr";
    }
    if (t.kind == PrimitiveKind::ARRAY) {
        // T[N] con tamano fijo o T[] (decay) cuando array_size == 0.
        std::string elem = t.pointee ? type_to_string(*t.pointee) : "?";
        std::string sfx = (t.array_size == 0)
                              ? "[]"
                              : ("[" + std::to_string(t.array_size) + "]");
        // Los arrays VM (locales) no anaden marcador; los raros host
        // se prefijan con `host` para no confundir.
        if (!t.is_virtual) return std::string("host ") + elem + sfx;
        return elem + sfx;
    }
    if (t.kind == PrimitiveKind::STRUCT)
        return t.struct_name.empty() ? std::string("struct") : t.struct_name;
    if (t.kind == PrimitiveKind::CLASS)
        return t.struct_name.empty() ? std::string("class") : t.struct_name;
    if (t.kind == PrimitiveKind::OPTIONAL) {
        return std::string("Optional<") +
               (t.pointee ? type_to_string(*t.pointee) : "?") + ">";
    }
    if (t.kind == PrimitiveKind::RESULT) {
        return std::string("Result<") +
               (t.pointee ? type_to_string(*t.pointee) : "?") + ", " +
               (t.pointee2 ? type_to_string(*t.pointee2) : "?") + ">";
    }
    if (t.kind == PrimitiveKind::FUTURE) {
        return std::string("Future<") +
               (t.pointee ? type_to_string(*t.pointee) : "?") + ">";
    }
    if (t.kind == PrimitiveKind::UNIQUE_PTR) {
        return std::string("unique<") +
               (t.pointee ? type_to_string(*t.pointee) : "?") + ">";
    }
    if (t.kind == PrimitiveKind::SHARED_PTR) {
        return std::string("shared<") +
               (t.pointee ? type_to_string(*t.pointee) : "?") + ">";
    }
    if (t.kind == PrimitiveKind::BORROW) {
        return std::string("borrow<") +
               (t.pointee ? type_to_string(*t.pointee) : "?") + ">";
    }
    if (t.kind == PrimitiveKind::BORROW_MUT) {
        return std::string("borrow_mut<") +
               (t.pointee ? type_to_string(*t.pointee) : "?") + ">";
    }
    if (t.kind == PrimitiveKind::FUNCTION) {
        // cfn/fn(P1, P2, ...) -> R con cada Pi formateado recursivamente.  Si
        // un parametro declara ABI custom (register("rXX")), se muestra delante
        // del tipo -> el mensaje de error distingue dos cfn con ABIs distintas
        // (que de otro modo se veian identicos: "fn(i64) -> i64" en ambos
        // lados).
        std::string s = t.fn_is_raw ? "cfn(" : "fn(";
        for (size_t i = 0; i < t.fn_params.size(); ++i) {
            if (i) s += ", ";
            if (i < t.fn_param_abi_regs.size() &&
                !t.fn_param_abi_regs[i].empty())
                s += "register(\"" + t.fn_param_abi_regs[i] + "\") ";
            s += type_to_string(t.fn_params[i]);
        }
        s += ") -> ";
        s += t.pointee ? type_to_string(*t.pointee) : "?";
        return s;
    }
    switch (t.kind) {
    case PrimitiveKind::VOID: return "void";
    case PrimitiveKind::BOOL: return "bool";
    case PrimitiveKind::CHAR: return "char";
    case PrimitiveKind::I8: return "i8";
    case PrimitiveKind::I16: return "i16";
    case PrimitiveKind::I32: return "i32";
    case PrimitiveKind::I64: return "i64";
    case PrimitiveKind::U8: return "u8";
    case PrimitiveKind::U16: return "u16";
    case PrimitiveKind::U32: return "u32";
    case PrimitiveKind::U64: return "u64";
    case PrimitiveKind::F32: return "f32";
    case PrimitiveKind::F64: return "f64";
    case PrimitiveKind::STRING: return "string";
    case PrimitiveKind::ARRAYLIST: return "ArrayList";
    case PrimitiveKind::HASHMAP: return "HashMap";
    case PrimitiveKind::HASHSET: return "HashSet";
    case PrimitiveKind::QUEUE: return "Queue";
    case PrimitiveKind::DEQUE: return "Deque";
    case PrimitiveKind::TREEMAP: return "TreeMap";
    case PrimitiveKind::TREESET: return "TreeSet";
    case PrimitiveKind::STACK: return "Stack";
    default: return "<unknown>";
    }
}

inline const char *primitive_name(PrimitiveKind k) noexcept {
    switch (k) {
    case PrimitiveKind::VOID: return "void";
    case PrimitiveKind::BOOL: return "bool";
    case PrimitiveKind::CHAR: return "char";
    case PrimitiveKind::I8: return "i8";
    case PrimitiveKind::I16: return "i16";
    case PrimitiveKind::I32: return "i32";
    case PrimitiveKind::I64: return "i64";
    case PrimitiveKind::U8: return "u8";
    case PrimitiveKind::U16: return "u16";
    case PrimitiveKind::U32: return "u32";
    case PrimitiveKind::U64: return "u64";
    case PrimitiveKind::F32: return "f32";
    case PrimitiveKind::F64: return "f64";
    case PrimitiveKind::PTR: return "ptr";
    case PrimitiveKind::STRUCT: return "struct";
    case PrimitiveKind::CLASS: return "class";
    case PrimitiveKind::ARRAY: return "array";
    case PrimitiveKind::OPTIONAL: return "Optional";
    case PrimitiveKind::RESULT: return "Result";
    case PrimitiveKind::FUNCTION: return "fn";
    case PrimitiveKind::STRING: return "string";
    case PrimitiveKind::ARRAYLIST: return "ArrayList";
    case PrimitiveKind::HASHMAP: return "HashMap";
    case PrimitiveKind::HASHSET: return "HashSet";
    case PrimitiveKind::QUEUE: return "Queue";
    case PrimitiveKind::DEQUE: return "Deque";
    case PrimitiveKind::TREEMAP: return "TreeMap";
    case PrimitiveKind::TREESET: return "TreeSet";
    case PrimitiveKind::STACK: return "Stack";
    case PrimitiveKind::FUTURE: return "Future";
    case PrimitiveKind::BORROW: return "borrow";
    case PrimitiveKind::BORROW_MUT: return "borrow_mut";
    case PrimitiveKind::UNIQUE_PTR: return "unique";
    case PrimitiveKind::SHARED_PTR: return "shared";
    case PrimitiveKind::GC_PTR: return "gc";
    case PrimitiveKind::TYPE_META: return "Type";
    case PrimitiveKind::COUNT: return "<count>";
    }
    return "<unknown>";
}

/**
 * @brief Inverso de @c primitive_name para los diez tipos numericos cortos.
 *
 * Recorre la propia @c primitive_name en vez de repetir la tabla, que en este
 * fichero ya esta escrita dos veces.  Asi un tipo nuevo se reconoce por los
 * dos lados en cuanto se anade a un solo sitio, y no hay forma de que las dos
 * direcciones discrepen.
 *
 * @param name Nombre canonico corto (`"i8"`, `"u32"`, `"f64"`).
 * @return La categoria, o @c PrimitiveKind::VOID si el nombre no es de ninguna.
 */
inline PrimitiveKind numeric_primitive_from_name(const std::string &name) {
    static const PrimitiveKind kNumeric[] = {
        PrimitiveKind::I8,  PrimitiveKind::I16, PrimitiveKind::I32,
        PrimitiveKind::I64, PrimitiveKind::U8,  PrimitiveKind::U16,
        PrimitiveKind::U32, PrimitiveKind::U64, PrimitiveKind::F32,
        PrimitiveKind::F64};
    for (const PrimitiveKind k : kNumeric)
        if (name == primitive_name(k)) return k;
    return PrimitiveKind::VOID;
}

/**
 * @struct NumericRange
 * @brief Valores que caben en un tipo entero.
 *
 * @c max se guarda sin signo para poder representar el de @c u64, que no cabe
 * en un @c int64_t.  Para los tipos con signo, @c max nunca pasa de
 * @c INT64_MAX, asi que la comparacion es segura por los dos lados.
 */
struct NumericRange {
    int64_t min = 0;        ///< Minimo representable (0 en los sin signo).
    uint64_t max = 0;       ///< Maximo representable.
    bool is_signed = false; ///< Cierto si el tipo admite negativos.
    bool valid = false;     ///< Falso si el tipo no es entero.
};

/**
 * @brief Rango de un tipo entero.
 *
 * Escrito UNA vez: lo consultan tanto el aviso de literal fuera de rango como
 * la comprobacion del sufijo de un literal (`300u8`).  Antes el rango vivia en
 * un switch dentro del comprobador que ademas se dejaba fuera @c i64 y @c u64.
 *
 * @param k Categoria del tipo.
 * @return El rango, con @c valid a falso si @p k no es un entero.
 */
inline NumericRange numeric_range_of(PrimitiveKind k) noexcept {
    switch (k) {
    case PrimitiveKind::I8: return {-128, 127, true, true};
    case PrimitiveKind::I16: return {-32768, 32767, true, true};
    case PrimitiveKind::I32: return {-2147483648LL, 2147483647ULL, true, true};
    case PrimitiveKind::I64:
        return {INT64_MIN, (uint64_t)INT64_MAX, true, true};
    case PrimitiveKind::U8: return {0, 255, false, true};
    case PrimitiveKind::U16: return {0, 65535, false, true};
    case PrimitiveKind::U32: return {0, 4294967295ULL, false, true};
    case PrimitiveKind::U64: return {0, UINT64_MAX, false, true};
    default: return {};
    }
}

/**
 * @brief Texto del rango para un diagnostico (`"u8 [0, 255]"`).
 * @param k Categoria del tipo.
 * @return El texto, o vacio si @p k no es un entero.
 */
inline std::string numeric_range_text(PrimitiveKind k) {
    const NumericRange r = numeric_range_of(k);
    if (!r.valid) return {};
    std::string s = primitive_name(k);
    s += " [";
    s += r.is_signed ? std::to_string(r.min) : "0";
    s += ", ";
    s += std::to_string(r.max);
    s += "]";
    return s;
}

/**
 * @brief Comprueba si un literal entero cabe en un tipo.
 *
 * Toma el signo y la MAGNITUD por separado en vez de un valor con signo: el
 * maximo de @c u64 no cabe en un @c int64_t, asi que leerlo como tal lo
 * convertiria en -1 y parecerian no caber justo los valores del borde.
 *
 * @param k Categoria del tipo destino.
 * @param negative Cierto si el literal lleva un `-` delante.
 * @param magnitude Valor absoluto tal como lo leyo el lexer.
 * @return Cierto si cabe, o si @p k no es un entero (nada que comprobar).
 */
inline bool literal_fits(PrimitiveKind k, bool negative,
                         uint64_t magnitude) noexcept {
    const NumericRange r = numeric_range_of(k);
    if (!r.valid) return true;
    if (!negative) return magnitude <= r.max;
    if (!r.is_signed) return false; // un negativo nunca cabe en un sin signo
    // El minimo con signo tiene una unidad mas de magnitud que el maximo
    // (-128 frente a 127), y se calcula asi para no desbordar al negarlo.
    return magnitude <= (uint64_t)r.max + 1u;
}

/**
 * @brief Texto de un literal entero para un diagnostico, con su signo.
 * @param negative Cierto si lleva un `-` delante.
 * @param magnitude Valor absoluto.
 */
inline std::string literal_text(bool negative, uint64_t magnitude) {
    return (negative ? "-" : "") + std::to_string(magnitude);
}

/**
 * @brief Calcula el tipo resultante de una promocion entre dos numericos.
 *
 * Reglas (estilo C, simplificadas):
 *   - Si alguno es flotante, el resultado es f64 si alguno es f64,
 *     en caso contrario f32.
 *   - Si ambos son enteros, se promociona al entero mas ancho;
 *     si uno es signed y otro unsigned y comparten anchura, gana
 *     el unsigned (cohesion con C).
 *
 * Si los tipos no son compatibles (uno no-numerico), devuelve
 * @c PrimitiveKind::COUNT como senyal de error; el caller debe
 * emitir el diagnostico oportuno.
 *
 * @param a Tipo del operando izquierdo.
 * @param b Tipo del operando derecho.
 * @return Tipo promovido, o COUNT si no son compatibles.
 */
/**
 * @brief Indica si un valor de tipo @p value puede asignarse a una
 *        ubicacion de tipo @p target sin diagnostico.
 *
 * Reglas:
 *   - Tipos identicos -> ok.
 *   - Ambos numericos (entero/flotante) -> ok (con conversion implicita).
 *   - Ambos PTR y alguno apunta a void -> ok (null o void* generico).
 *   - Ambos PTR con pointee identico -> ok (cubierto por igualdad).
 *
 * Para todo lo demas devuelve false; el caller debe emitir un
 * diagnostico claro indicando ambos tipos.
 */
inline bool types_assignable(const Type &target, const Type &value) noexcept {
    // const-correctness A: no DESCARTAR const al asignar punteros.  Se recorren
    // las cadenas de pointee en paralelo; si en algun nivel el VALUE es const y
    // el TARGET no, la asignacion "lavaria" el const (aliasing a traves de un
    // puntero mutable) -> se rechaza.  Al reves (target const, value no) SI se
    // permite (anadir const es seguro).  Va ANTES del `==` porque este ignora
    // @c is_const.  Para no-punteros el bucle no corre (no hay laundering:
    // copiar un valor const a uno mutable es una COPIA, no un alias).
    {
        const Type *tt = &target, *vv = &value;
        while (tt->kind == PrimitiveKind::PTR &&
               vv->kind == PrimitiveKind::PTR && tt->pointee && vv->pointee) {
            tt = tt->pointee.get();
            vv = vv->pointee.get();
            if (vv->is_const && !tt->is_const) return false; // discard const
        }
    }
    if (target == value) return true;
    // Smart pointer con pointee void: `unique<void*>` / `unique<void>` (y su
    // variante shared) es el resultado de adoptar un puntero crudo generico,
    // p.ej. `unique_with(malloc(n*8), free)` cuyo value es `void*`.  Se adopta
    // a cualquier `unique<T>`: como en C, `void*` es universal y el pointee
    // concreto lo fija el destino (`unique<u64>` gestiona el bloque como buffer
    // de u64).  Solo el pointee void generaliza; `unique<i64>` (handle opaco,
    // 105/106) NO -> conserva su tipo.
    if ((target.kind == PrimitiveKind::UNIQUE_PTR &&
         value.kind == PrimitiveKind::UNIQUE_PTR) ||
        (target.kind == PrimitiveKind::SHARED_PTR &&
         value.kind == PrimitiveKind::SHARED_PTR)) {
        if (value.pointee) {
            const Type &vp = *value.pointee;
            const bool vp_is_void =
                vp.kind == PrimitiveKind::VOID ||
                (vp.kind == PrimitiveKind::PTR && vp.pointee &&
                 vp.pointee->kind == PrimitiveKind::VOID);
            if (vp_is_void) return true;
        }
    }
    // Valued enum (`enum Op : u8 {..}`, `enum M : string {..}`): ES su tipo
    // base.  El @c struct_name solo distingue el enum para resolver variantes,
    // no para asignabilidad.  Assignable a/desde su tipo base y a otro valued
    // enum del mismo backing cuando el @c kind coincide (int<->int de distinto
    // ancho lo cubre @c is_numeric mas abajo).
    if ((target.is_valued_enum || value.is_valued_enum) &&
        target.kind == value.kind) {
        return true;
    }
    // Newtype barrier: si target O value es un newtype (nominal_id > 0)
    // y NO son el mismo newtype (operator== ya lo cubrio), el tipo
    // es nominalmente distinto y requiere cast explicito `(T)x`.
    // Sin este check, `typedef u64 port new; port p = 100;` permitiria
    // la coercion numerica u64 -> port silenciosamente, perdiendo la
    // garantia del newtype.  Salvo: newtype -> u64 (extraer bits) y
    // u64 -> newtype (envolver) requieren cast explicito (manejado en
    // lower_cast_expr + check_call).
    if (target.nominal_id != 0 || value.nominal_id != 0) return false;
    if (is_numeric(target.kind) && is_numeric(value.kind)) return true;
    /* CHAR (codepoint Unicode u32) acepta coercion a/de cualquier tipo
     * entero.  Permite `u8 b = 'H';` (caso C clasico: char literal a
     * byte) y `u32 cp = 'A';`.  El lowering hace truncate cuando el
     * destino es < 32 bits; sin warning porque el usuario escribio
     * un literal char (intencion clara).  Tambien permite el sentido
     * inverso `char c = 65;` para construir un codepoint desde int. */
    if (is_integral(target.kind) && value.kind == PrimitiveKind::CHAR)
        return true;
    if (target.kind == PrimitiveKind::CHAR && is_integral(value.kind))
        return true;
    if (target.kind == PrimitiveKind::PTR && value.kind == PrimitiveKind::PTR) {
        // Tratamos un PTR sin pointee como @c void* (caso de builtins
        // historicamente declarados con @c Type{PTR} a secas).  Esto
        // permite que free(p) acepte cualquier T* sin diagnosticar
        // type mismatch contra el tipo concreto del puntero.
        const bool t_void =
            !target.pointee || target.pointee->kind == PrimitiveKind::VOID;
        const bool v_void =
            !value.pointee || value.pointee->kind == PrimitiveKind::VOID;
        if (t_void || v_void) return true;
        // `T*` y `VirtualPtr<T>` son tipos DISTINTOS: no se coercen.
        //
        // Nombran espacios de direcciones distintos.  `T*` es siempre HOST;
        // `VirtualPtr<T>` es la memoria VM, que es paginada (4 KiB, mapeo
        // perezoso) y per-proceso.  Una direccion VM usada como host
        // segfaltea; una host leida como VM devuelve basura de vm_mem sin
        // avisar.  Lo que hace irreducible la distincion es que en el sitio
        // del DEREF el unico contrato disponible es el del tipo: en cuanto el
        // puntero pasa por memoria (un campo, un parametro), no queda rastro
        // de su origen que el compilador pueda seguir.
        //
        // (Hubo una regla de auto-promocion entre ambos, apoyada en deducir
        // la naturaleza del ALLOCA de origen.  Deja de funcionar justo cuando
        // el puntero viaja por memoria, y convertia el error en un SIGSEGV
        // silencioso.)
        //
        // Para mezclarlos a proposito, cast explicito.
        if (target.pointee && value.pointee &&
            *target.pointee == *value.pointee &&
            target.is_virtual == value.is_virtual) {
            return true;
        }
    }
    // Decay automatico de array: T[N] o T[] se convierten implicitamente
    // a T*.  Util para pasar arrays como argumentos `T*` o asignarlos a
    // variables puntero.  Tambien admitimos PTR -> ARRAY[] (sin tamano)
    // para simetria, util en el lowering al unificar parametros.
    if (target.kind == PrimitiveKind::PTR &&
        value.kind == PrimitiveKind::ARRAY) {
        if (target.pointee && value.pointee &&
            *target.pointee == *value.pointee)
            return true;
        // void* destino acepta cualquier array.
        if (!target.pointee || target.pointee->kind == PrimitiveKind::VOID)
            return true;
    }
    if (target.kind == PrimitiveKind::ARRAY &&
        value.kind == PrimitiveKind::PTR) {
        if (target.pointee && value.pointee &&
            *target.pointee == *value.pointee && target.array_size == 0)
            return true;
    }
    // Array a array: T[N] -> T[] (target array sin tamano).  Permite
    // pasar un array de tamano fijo como parametro `T[]` (decay).
    if (target.kind == PrimitiveKind::ARRAY &&
        value.kind == PrimitiveKind::ARRAY) {
        if (target.array_size == 0 && target.pointee && value.pointee &&
            *target.pointee == *value.pointee)
            return true;
    }
    // Lazy promotion: literal de string (PTR) -> string.  El
    // lowering del var-decl detecta el caso y emite STRMAKE para
    // producir un StringObject GC-managed.  Sin esto el type checker
    // rechazaria `string s = "hola"`.
    if (target.kind == PrimitiveKind::STRING &&
        value.kind == PrimitiveKind::PTR)
        return true;
    /* C-style: `u8[N] arr = "literal"` o `char[N] arr = "literal"`.
     * Target es ARRAY de byte-like (u8/i8/char); value es un literal
     * de string (modelado como PTR).  El lowering del var-decl
     * detecta el caso y emite STOREs byte-a-byte del contenido del
     * string (con zerificacion del resto si N > strlen).  Equivalente
     * directo a la inicializacion C de char arrays. */
    if (target.kind == PrimitiveKind::ARRAY &&
        value.kind == PrimitiveKind::PTR && target.pointee &&
        (target.pointee->kind == PrimitiveKind::U8 ||
         target.pointee->kind == PrimitiveKind::I8 ||
         target.pointee->kind == PrimitiveKind::CHAR)) {
        return true;
    }
    // null asignable a CLASS (Java-style nullability).  null se modela
    // como PTR void; CLASS es una referencia que admite null por
    // defecto.  Necesario para `return null` en metodos que devuelven
    // tipo CLASS (lookup/find que pueden no encontrar el item) y para
    // `class_field = null` en init de structures de datos opcionales.
    if (target.kind == PrimitiveKind::CLASS &&
        value.kind == PrimitiveKind::PTR) {
        const bool v_void =
            !value.pointee || value.pointee->kind == PrimitiveKind::VOID;
        if (v_void) return true;
    }
    // string -> i64: extraer el GcHandle como entero opaco para FFI o
    // comparaciones manuales.  La direccion es valida solo durante el
    // lifetime del proceso (no exportar a otros procesos).
    if (is_numeric(target.kind) && value.kind == PrimitiveKind::STRING) {
        return primitive_size_bytes(target.kind) >= 8;
    }
    // los handles de las colecciones primitivas son i64
    // opacos a runtime; la informacion del tipo de elemento solo vive
    // en el frontend para decidir el dispatch *_gc.  Una asignacion
    // entre `ArrayList<T>` y `ArrayList` (sin params) o entre dos
    // colecciones del mismo @c kind con elementos GC-equivalentes es
    // siempre legal: el handle es identico bit-a-bit.
    if (target.kind == value.kind && (target.kind == PrimitiveKind::ARRAYLIST ||
                                      target.kind == PrimitiveKind::HASHMAP ||
                                      target.kind == PrimitiveKind::HASHSET ||
                                      target.kind == PrimitiveKind::QUEUE ||
                                      target.kind == PrimitiveKind::DEQUE ||
                                      target.kind == PrimitiveKind::TREEMAP ||
                                      target.kind == PrimitiveKind::TREESET ||
                                      target.kind == PrimitiveKind::STACK)) {
        return true;
    }
    // Mejora II: Future<T1> -> Future<T2> con coercion numerica del
    // payload (mismo principio que Optional/Result).  Tambien permite
    // Future<T> -> Future<T> trivial (cubierto por target==value
    // anterior; redundante pero explicito para clarity).
    if (target.kind == PrimitiveKind::FUTURE &&
        value.kind == PrimitiveKind::FUTURE && target.pointee &&
        value.pointee) {
        // Compatibilidad estructural exacta o coercion numerica.
        if (*target.pointee == *value.pointee) return true;
        if (is_numeric(target.pointee->kind) && is_numeric(value.pointee->kind))
            return true;
    }
    // Mejora II compat: Future<T> -> i64/u64 (extraer el handle como
    // entero opaco).  Permite codigo legacy `i64 f = compute()` cuando
    // compute es @Async.  El handle es identico bit-a-bit en runtime.
    if (value.kind == PrimitiveKind::FUTURE &&
        (target.kind == PrimitiveKind::I64 ||
         target.kind == PrimitiveKind::U64)) {
        return true;
    }
    // Y la inversa: i64/u64 -> Future<T> (interpretar el handle).
    // Sin esto, codigo que aloca un future raw via `future_alloc()`
    // (devuelve i64) no podria asignarse a una variable Future<T>.
    if (target.kind == PrimitiveKind::FUTURE &&
        (value.kind == PrimitiveKind::I64 ||
         value.kind == PrimitiveKind::U64)) {
        return true;
    }
    // Smart pointers: unique<X> -> unique<Y> y shared<X> -> shared<Y>
    // son asignables si X == Y exacto (no admitimos coercion numerica
    // entre punteros porque cambiaria la semantica del sizeof + del
    // deleter; el usuario debe usar el tipo correcto).  La excepcion
    // es Y == VOID (placeholder devuelto por los builtins `unique_box`
    // / `shared_box` cuando no hay info de tipo - se unifica con el
    // tipo concreto del LHS).
    if (target.kind == PrimitiveKind::UNIQUE_PTR &&
        value.kind == PrimitiveKind::UNIQUE_PTR && target.pointee &&
        value.pointee) {
        if (*target.pointee == *value.pointee) return true;
        if (value.pointee->kind == PrimitiveKind::VOID) return true;
        // Coercion numerica para `unique_box(50)` que devuelve
        // unique<i64> y se asigna a unique<i32> - misma logica que
        // Some(50) con Optional.
        if (is_numeric(target.pointee->kind) && is_numeric(value.pointee->kind))
            return true;
    }
    if (target.kind == PrimitiveKind::SHARED_PTR &&
        value.kind == PrimitiveKind::SHARED_PTR && target.pointee &&
        value.pointee) {
        if (*target.pointee == *value.pointee) return true;
        if (value.pointee->kind == PrimitiveKind::VOID) return true;
        if (is_numeric(target.pointee->kind) && is_numeric(value.pointee->kind))
            return true;
    }
    return false;
}

inline PrimitiveKind promote_arith(PrimitiveKind a, PrimitiveKind b) noexcept {
    if (!is_numeric(a) || !is_numeric(b)) return PrimitiveKind::COUNT;

    // Si alguno es flotante, ganan los flotantes.
    if (is_floating(a) || is_floating(b)) {
        if (a == PrimitiveKind::F64 || b == PrimitiveKind::F64)
            return PrimitiveKind::F64;
        return PrimitiveKind::F32;
    }
    // Ambos enteros: el de mayor anchura; en empate, el unsigned.
    const size_t sa = primitive_size_bytes(a);
    const size_t sb = primitive_size_bytes(b);
    if (sa != sb) return sa > sb ? a : b;
    // Misma anchura: si alguno es unsigned, el resultado es unsigned.
    const bool a_signed = is_signed_integral(a);
    const bool b_signed = is_signed_integral(b);
    if (a_signed && !b_signed) return b;
    if (!a_signed && b_signed) return a;
    return a; // ambos signed o ambos unsigned: da igual cual devolvamos.
}

/**
 * @brief Mapea CHAR a U8 para las decisiones de aritmetica entera.
 *
 * En Vesta un @c char es un byte sin signo (0-255), estilo C.  El resto
 * del checker NO considera CHAR como numerico (is_numeric falso) para
 * evitar coerciones implicitas no deseadas, pero la aritmetica de char
 * (`'a' + 'b'`) debe tratarse como aritmetica u8.  Este helper traduce
 * CHAR a U8 y deja cualquier otro tipo intacto, de modo que se puede
 * reusar @c promote_arith y la maquinaria entera existente.
 *
 * @param k Tipo primitivo de entrada.
 * @return U8 si @p k es CHAR; @p k en cualquier otro caso.
 */
constexpr PrimitiveKind char_as_u8(PrimitiveKind k) noexcept {
    return k == PrimitiveKind::CHAR ? PrimitiveKind::U8 : k;
}

/**
 * @brief @c true si @p k es CHAR o un entero (apto para aritmetica).
 */
constexpr bool is_char_or_integral(PrimitiveKind k) noexcept {
    return k == PrimitiveKind::CHAR || is_integral(k);
}

} // namespace vx

#endif // VX_TYPES_H
