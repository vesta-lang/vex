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
 * @file type_checker.cpp
 * @brief Implementacion del pase de tipos de Vesta.
 *
 * Estructura:
 *   1. collect_globals() - pase superficial que llena el scope global
 *      con las funciones y variables top-level (permite forward refs).
 *   2. check_functions() - pase profundo que verifica cada cuerpo.
 *
 * Patrones de hardware aplicados:
 *   - lookup() recorre los scopes desde el mas interno al global con
 *     un loop cerrado; los scopes son std::unordered_map (los nombres
 *     son cadenas variables de tamanyo, std::vector ordenado seria
 *     peor para inserciones repetidas).
 *   - El AST se modifica solo en @c result_type; nada de allocaciones
 *     extra durante el checking.
 *   - La tabla de firmas de funciones es un vector contiguo con
 *     acceso por indice (cache-friendly al validar muchas llamadas).
 */

#include "util/env_flags.h"
#include "util/thread_slot.h" // buffer por hilo sin pasar por la TLS emulada
#include "vx/type_checker.h"

#include "vx/diag/diag_catalog.h"
#include "vx/ansi_names.h"      // los nombres de color que el lenguaje conoce
#include "vx/asm/asm_effects.h" // asm_canonical_reg ( AS inc.4)
#include "vx/type_classify.h"   // is_c_representable / is_managed (Fase 1)
#include "vx/collection_intrinsics.h"        // tabla de tipos coleccion
#include "vx/comptime/comptime_introspect.h" // comptime_field_type
#include "vx/generics/concepts.h" // conceptos como predicado comptime
#include "vx/lexer.h"             // parse de fragments en comptime_emit_expr
#include "vx/contract_when.h"
#include "vx/parser.h" // parse_one_expr para macros con splice
#include "loader/oop_types.h" // para sizeof(loader::ObjectHeader) en el layout de clases
#include "vx/generics/generic_clone.h" // GenSubst + clone_* + mangle_* (extraidos del monolito)

#include <algorithm>
#include <utility>
#include <cctype>   // tolower/isdigit para canonical_x86_reg ( AS)
#include <cstdlib>  // getenv para VESTA_MC_VMONLY/PREBUILT
#include <cstring>  // memcpy para bitcast f64 -> u64
#include <fstream>  // cargar prebuilt .velb desde disco
#include <iostream> // log VESTA_MC_VERBOSE
#include <mutex>    // std::call_once para registro one-shot
#include <functional>

#include "ffi/virtual_lib_registry.h" // registrar vx_static_assert

/* extern "C" decl global del thunk generator.  La impl esta
 * en src/runtime/native_callback.cpp.  La registramos como virtual_fn
 * "vesta_runtime:vx_get_native_thunk" para que el builtin Vesta
 * `as_native_callback(fn)` la invoque via CALLN. */
extern "C" uint64_t vx_get_native_thunk(uint64_t fn_pc, uint64_t argc);

namespace vx {

//  AS inc.4: la canonicalizacion de registros x86-64 vive ahora en
// @c asm_effects.{h,cpp} (compartida con la inferencia de clobbers).  El
// type checker la usa via @c asm_canonical_reg.

/* TypeChecker activo (thread_local) para los virtual
 * fns expuestos a macros via `extern "vesta_comptime"`.  Cuando un
 * macro llama @c static_assert (o futuros @c comptime_compile, etc.),
 * el virtual fn accede al TypeChecker del compile en curso via este
 * puntero.  Single-thread compile -> sin contencion. */
thread_local TypeChecker *g_active_typechecker = nullptr;

/**
 * @brief implementacion del virtual fn `static_assert`
 * exportado bajo `extern "vesta_comptime"`.  Cuando un macro lo
 * invoca via la FFI dispatch (camino A), esta funcion recibe el
 * @c cond evaluado y un @c msg como C-string (host_ptr a bytes).
 *
 * Si @c cond es 0/falso, emite un diagnostic error en el TypeChecker
 * activo (g_active_typechecker) y returns 1 (status fail).  El AST
 * eval del macro recibe el u64 returned y puede propagar; pero el
 * mecanismo standar es: el diagnostic emite el error -> el macro
 * sigue ejecutando pero el compile final fallara con ese error.
 *
 * @c msg puede ser @c nullptr; en ese caso se usa un mensaje generic.
 *
 * @note Marcada @c extern "C" para que su nombre no sea mangled
 *       (asi @c register_virtual_fn la registra con simbolo limpio
 *       y la FFI dispatch la encuentra via fn_ptr).
 */
/**
 * @brief virtual fn `comptime_compile(src) -> string`.
 *
 * Toma source Vesta como C-string, lo trata como una EXPRESION Vesta y
 * la devuelve TAL CUAL como string.  Sirve para componer codigo
 * desde macros sin que el AST evaluator se queje de "no es comptime
 * evaluable".  El AST resultante se parsea en el call site de la
 * macro como cualquier otro string de retorno @Macro.
 *
 * En v1 es esencialmente identity (devuelve src tal cual).  La
 * utilidad real esta en que el usuario puede pasar AST construido
 * via macros recursivos y obtener un string concreto sin
 * preocuparse de comptime_eval_expr.
 *
 * El buffer sobrevive al retorno para que el @c c_str() siga valido mientras el
 * caller lo necesite, y es POR HILO: los modulos se compilan en paralelo y cada
 * uno ejecuta su propio comptime, asi que uno solo compartido significaba dos
 * hilos asignando la misma @c std::string -- la misma carrera que mataba al
 * compilador con 0xC0000374 desde el conjunto comptime.
 *
 * Por ranura propia (@c util::ThreadSlot), no por @c thread_local: en MinGW
 * cada acceso a una variable de hilo es una llamada a `__emutls_get_address`
 * (12x mas lento que leer el TEB) y su variable de guarda ya provoco cuelgues
 * en este proyecto.  Mismo patron que `scratch_arena`: un array fijo, un
 * contador atomico que reparte uno por hilo, y la ranura guardando el puntero.
 */
constexpr uint32_t kMaxComptimeBufs = 64;
static std::string g_comptime_compile_bufs[kMaxComptimeBufs];
static std::atomic<uint32_t> g_next_comptime_buf{0};
static util::ThreadSlot g_comptime_buf_slot;

/// El buffer de ESTE hilo, reservandolo la primera vez.
static std::string &comptime_compile_buf() noexcept {
    g_comptime_buf_slot.ensure();
    if (void *p = g_comptime_buf_slot.get())
        return *static_cast<std::string *>(p);
    const uint32_t id =
        g_next_comptime_buf.fetch_add(1, std::memory_order_acq_rel);
    /* Mas hilos de los previstos: se reparten en circulo sobre el array.  Dos
     * hilos compartiendo buffer vuelve a ser una carrera, pero para llegar aqui
     * hacen falta mas de 64 hilos compilando comptime a la vez -- el reparto de
     * modulos tiene tope de ocho -- y la alternativa (reservar uno suelto por
     * hilo) es memoria que no se devuelve nunca. */
    std::string &b = g_comptime_compile_bufs[id % kMaxComptimeBufs];
    g_comptime_buf_slot.set(&b);
    return b;
}

extern "C" const char *vx_comptime_compile(const char *src) {
    if (!src) return "";
    std::string &buf = comptime_compile_buf();
    buf = src;
    return buf.c_str();
}

/**
 * @brief  MC.23: helpers virtual fn para queries de tipos por
 * NOMBRE (string).  Mucho mas simple que la version con hash: el
 * macro pasa "i32"/"u64"/"f32"/"<class_name>" y obtiene la metadata.
 *
 * Coverage: primitivos + clases + structs + enums.  Devuelve 0
 * si el nombre no se reconoce.
 */
static Type type_from_name_str(const char *name) {
    if (!name) return Type{};
    const std::string nm{name};
    /* Primitivos. */
    if (nm == "i8") return Type{PrimitiveKind::I8};
    if (nm == "i16") return Type{PrimitiveKind::I16};
    if (nm == "i32") return Type{PrimitiveKind::I32};
    if (nm == "i64") return Type{PrimitiveKind::I64};
    if (nm == "u8") return Type{PrimitiveKind::U8};
    if (nm == "u16") return Type{PrimitiveKind::U16};
    if (nm == "u32") return Type{PrimitiveKind::U32};
    if (nm == "u64") return Type{PrimitiveKind::U64};
    if (nm == "f32") return Type{PrimitiveKind::F32};
    if (nm == "f64") return Type{PrimitiveKind::F64};
    if (nm == "bool") return Type{PrimitiveKind::BOOL};
    if (nm == "char") return Type{PrimitiveKind::CHAR};
    if (nm == "string") return Type{PrimitiveKind::STRING};
    if (nm == "ptr") return Type{PrimitiveKind::PTR};
    /* Clase/struct/enum por nombre.  Buscamos en los layouts del
     * TypeChecker activo. */
    if (!g_active_typechecker) return Type{};
    const auto &cls = g_active_typechecker->class_layouts();
    if (cls.find(nm) != cls.end()) {
        Type t{PrimitiveKind::CLASS};
        t.struct_name = nm;
        return t;
    }
    const auto &str = g_active_typechecker->struct_layouts();
    if (str.find(nm) != str.end()) {
        Type t{PrimitiveKind::STRUCT};
        t.struct_name = nm;
        return t;
    }
    const auto &enm = g_active_typechecker->enum_layouts();
    if (enm.find(nm) != enm.end()) {
        Type t{PrimitiveKind::STRUCT}; // enum representado como STRUCT en Type
        t.struct_name = nm;
        return t;
    }
    return Type{};
}

extern "C" uint64_t vx_comptime_type_sizeof(const char *name) {
    if (!g_active_typechecker) return 0;
    const Type t = type_from_name_str(name);
    if (t.kind == PrimitiveKind::VOID) return 0;
    return comptime_type_size(*g_active_typechecker, t);
}

extern "C" uint64_t vx_comptime_type_alignof(const char *name) {
    if (!g_active_typechecker) return 0;
    const Type t = type_from_name_str(name);
    if (t.kind == PrimitiveKind::VOID) return 0;
    return comptime_type_align(*g_active_typechecker, t);
}

extern "C" uint64_t vx_comptime_type_kind(const char *name) {
    if (!g_active_typechecker) return 0;
    const Type t = type_from_name_str(name);
    return static_cast<uint64_t>(comptime_type_kind(t));
}

/**
 * @brief Registra como error de compilacion un fallo del codigo comptime.
 *
 * La llama quien ejecuta ese codigo cuando el proceso muere sin que nadie
 * capture el fallo.  Si el propio codigo comptime lo envuelve en un `try`, el
 * proceso NO muere y esto no se invoca: el programa sigue siendo valido.
 *
 * @param msg Mensaje del fallo, ya formado.
 */
void report_comptime_fatal(const std::string &msg) {
    if (g_active_typechecker) {
        SourceLoc loc;
        loc.file = "<comptime>";
        g_active_typechecker->diagnostics().error(loc, msg);
    } else {
        std::fprintf(stderr, "[vx] %s (sin TypeChecker activo)\n", msg.c_str());
    }
}

/**
 * @brief Helper de `static_assert` invocado desde codigo comptime.
 *
 * Recibe la direccion y la longitud del mensaje en el espacio de la MAQUINA
 * VIRTUAL, y lo lee con la API del proceso -- la misma convencion que el resto
 * de nativos.  Antes tomaba un `const char *` y se le pasaba la direccion tal
 * cual: un numero del espacio de la VM que el anfitrion no puede dereferenciar,
 * asi que leerlo mataba el proceso.  No se habia notado nunca porque la ruta no
 * llegaba a ejecutarse: la asercion se descartaba siempre al bajarla.
 *
 * @param proc_ptr Proceso que ejecuta el codigo comptime (via `getproc`).
 * @param cond     Resultado de la condicion; 0 = incumplida.
 * @param msg_addr Direccion del mensaje en la memoria de la VM.
 * @param msg_len  Longitud del mensaje en bytes.
 * @return 0 si se cumple, 1 si no.
 */
extern "C" uint64_t vx_static_assert(uint64_t proc_ptr, int64_t cond,
                                     uint64_t msg_addr, uint64_t msg_len) {
    if (cond) return 0; /* Se cumple: nada que hacer. */
    /* Solo el veredicto: NO se reporta nada aqui.
     *
     * Quien decide si la asercion rompe la compilacion es el `panic` que el
     * lowering emite justo detras.  Si el codigo comptime la envuelve en un
     * `try`, ese panic se captura y el programa sigue siendo valido -- y
     * reportar desde aqui lo habria tumbado igualmente, haciendo inutil el
     * `catch`.  Sin `try`, el proceso muere y quien lo recoge imprime el
     * mensaje y la traza. */
    (void)proc_ptr;
    (void)msg_addr;
    (void)msg_len;
    return 1; /* Incumplida. */
}

/**
 * @brief Registra las funciones virtuales del compilador (`vesta_comptime`).
 *
 * Viven en el propio ejecutable: `vesta_comptime` es una libreria VIRTUAL.
 * El registro estaba dentro del constructor del TypeChecker, asi que solo
 * existia al COMPILAR; un `.velb` que lleve un cuerpo comptime como codigo
 * muerto importa `vesta_comptime`, y al cargarlo el FFI no lo encontraba en
 * el registro, intentaba LoadLibrary y el programa moria antes de arrancar
 * por un simbolo que nadie iba a llamar.
 */
void register_comptime_virtual_fns() {
    static std::once_flag once_reg;
    std::call_once(once_reg, []() {
        ffi::register_virtual_fn("vesta_comptime", "static_assert",
                                 reinterpret_cast<void *>(&vx_static_assert));
        /* type queries via virtual fns.  Macros invocan
         * `comptime_type_sizeof("i32")` etc. y obtienen metadata. */
        ffi::register_virtual_fn(
            "vesta_comptime", "comptime_type_sizeof",
            reinterpret_cast<void *>(&vx_comptime_type_sizeof));
        ffi::register_virtual_fn(
            "vesta_comptime", "comptime_type_alignof",
            reinterpret_cast<void *>(&vx_comptime_type_alignof));
        ffi::register_virtual_fn(
            "vesta_comptime", "comptime_type_kind",
            reinterpret_cast<void *>(&vx_comptime_type_kind));
        /* comptime_compile: identity en v1 (devuelve src tal cual).
         * Util para que el AST evaluator no rechace el call cuando
         * el macro hace `return comptime_compile(complicated_str)`. */
        ffi::register_virtual_fn(
            "vesta_comptime", "comptime_compile",
            reinterpret_cast<void *>(&vx_comptime_compile));
        /* Sprint B.1: thunk generator para callbacks Vesta -> C nativos.
         * Builtin `as_native_callback(fn)` se baja a un CALLN a esta
         * fn que retorna el host_ptr al thunk callable con cc nativa.
         * El extern "C" decl global esta arriba del namespace. */
        ffi::register_virtual_fn(
            "vesta_runtime", "vx_get_native_thunk",
            reinterpret_cast<void *>(&::vx_get_native_thunk));
    });
}

TypeChecker::TypeChecker(ast::ModuleNode &mod, Diagnostics &diags)
    : mod_(mod), diags_(diags) {
    // Reservar espacio razonable para evitar realocaciones en programas
    // tipicos.
    scopes_.reserve(8);
    function_sigs_.reserve(16);
    /* marcar este TypeChecker como el activo + registrar
     * los virtual fns una vez por proceso (registration idempotent).
     * NOTA: g_active_typechecker se mantiene apuntando aqui hasta el
     * destructor.  Multi-instancia en paralelo no soportado todavia
     * (single-thread compile por diseno). */
    g_active_typechecker = this;
    register_comptime_virtual_fns();
}

TypeChecker::~TypeChecker() {
    /*  MC.20: limpiar el pointer thread_local SOLO si es esta
     * instancia (defensive: otro TypeChecker pudo haberse construido
     * y sobreescrito el slot). */
    if (g_active_typechecker == this) {
        g_active_typechecker = nullptr;
    }
}

// =====================================================================
//  Generics: AST cloning + type substitution
//
//  La monomorphizacion clona el AST de la clase generica sustituyendo
//  los type params (T, U, ...) por los args concretos en TODOS los
//  TypeNodes encontrados (firmas, bodies de metodo, etc).  Despues la
//  clase clonada se procesa por collect_classes / check_functions
//  como una clase normal.  El cloning se hace una vez por
//  (template, args) y se cachea en monomorphized_.
// =====================================================================

// Las utilidades de clonacion de AST con sustitucion de type-params
// (GenSubst, clone_*, mangle_*) viven ahora en generic_clone.{h,cpp}
// para mantener este fichero manejable (el include esta arriba, fuera
// del namespace).  Se traen al scope de `vx` con un using para no
// requalificar las decenas de usos existentes.
using namespace vxgen;

// #cross-module-generics: un template importado con namespace se inyecta con
// nombre cualificado `lib.Box` (con punto).  El punto es invalido en las
// etiquetas del IR/linker, asi que el nombre MANGLED de la instancia debe ser
// dot-free.  Reemplaza '.' por '_' (idempotente para nombres sin punto).
static std::string mangle_sanitize(const std::string &s) {
    if (s.find('.') == std::string::npos) return s;
    std::string out = s;
    for (char &c : out)
        if (c == '.') c = '_';
    return out;
}

// True si @p k es un tipo entero (con o sin signo).  Usado para validar el
// tipo base de un enum con valor y para el lowering de valued-enums.
static bool is_integer_kind(PrimitiveKind k) {
    switch (k) {
    case PrimitiveKind::I8:
    case PrimitiveKind::I16:
    case PrimitiveKind::I32:
    case PrimitiveKind::I64:
    case PrimitiveKind::U8:
    case PrimitiveKind::U16:
    case PrimitiveKind::U32:
    case PrimitiveKind::U64: return true;
    default: return false;
    }
}

// Mapea el nombre textual de un tipo base ("u8", "i32", "f64", "string", ...) a
// su PrimitiveKind.  Devuelve VOID si no es un tipo base reconocido para enums.
// Los nombres de USUARIO (struct/clase) no se mapean aqui: el checker los
// resuelve por separado y deja backing=STRUCT/CLASS con el nombre en otro
// campo.
static PrimitiveKind prim_kind_from_name(const std::string &n) {
    if (n == "u8") return PrimitiveKind::U8;
    if (n == "u16") return PrimitiveKind::U16;
    if (n == "u32") return PrimitiveKind::U32;
    if (n == "u64") return PrimitiveKind::U64;
    if (n == "i8") return PrimitiveKind::I8;
    if (n == "i16") return PrimitiveKind::I16;
    if (n == "i32") return PrimitiveKind::I32;
    if (n == "i64") return PrimitiveKind::I64;
    if (n == "f32") return PrimitiveKind::F32;
    if (n == "f64") return PrimitiveKind::F64;
    if (n == "string") return PrimitiveKind::STRING;
    return PrimitiveKind::VOID;
}

// Resuelve la CLAVE real de un template generico referido de forma
// CUALIFICADA.  El uso `col.Box<T>` llega como "col.Box" (dotted), pero segun
// el origen el template esta registrado como: "col.Box" (import cross-module
// con namespace), "col__Box" (MISMO fichero: el aplanador de namespaces
// manglea con "__"), o "Box" (sin namespace).  Devuelve la clave que exista en
// @p m, o "" si ninguna.  Reglas (mas especifica primero):
//   1. nombre tal cual;  2. dotted -> mangled con "__";  3. si el nombre es
//   SIMPLE (sin punto), unico key del mapa que termine en "__<name>".
template <class MapT>
static std::string resolve_generic_key(const std::string &name, const MapT &m) {
    if (m.count(name)) return name;
    if (name.find('.') != std::string::npos) {
        std::string dd = name;
        size_t p;
        while ((p = dd.find('.')) != std::string::npos)
            dd.replace(p, 1, "__");
        if (m.count(dd)) return dd;
    } else {
        // Nombre simple `Box`: buscar un unico `<ns>__Box`
        // (namespace-relativo).
        const std::string suf = "__" + name;
        std::string hit;
        int n = 0;
        for (const auto &kv : m) {
            const std::string &k = kv.first;
            if (k.size() > suf.size() &&
                k.compare(k.size() - suf.size(), suf.size(), suf) == 0) {
                hit = k;
                if (++n > 1) break;
            }
        }
        if (n == 1) return hit;
    }
    return {};
}

bool TypeChecker::is_generic_enum_template(const std::string &name) const {
    return !resolve_generic_key(name, generic_enum_templates_).empty();
}

bool TypeChecker::is_generic_struct_template(const std::string &name) const {
    return !resolve_generic_key(name, generic_struct_templates_).empty();
}

namespace {

/// Da valor a un atomo de un `when:` de contrato con los type params ligados.
///
/// Los de target los resuelve el evaluador de @Target -- el mismo que usa la
/// anotacion @Target, asi que no hay dos gramaticas ni dos verdades.  Los que
/// hablan del parametro de tipo se responden aqui, que es donde T es concreto:
/// es lo que permite declarar que `atomic<i64>::fetch_add` es un `lock xadd`
/// (O(1)) y `atomic<f64>::fetch_add` un bucle CAS (O(n)), del mismo fuente.
static bool when_atomo_(const std::string &at, const vxgen::GenSubst &g,
                        bool &ok) {
    if (cwhen::atom_kind(at) == cwhen::AtomKind::TARGET)
        return target_expr_matches(at);

    // `pred<PARAM>()` [OP N].  La forma ya la valido `atom_kind`.
    const size_t lt = at.find('<');
    const size_t gt = at.find('>', lt == std::string::npos ? 0 : lt);
    if (lt == std::string::npos || gt == std::string::npos || gt < lt) {
        ok = false;
        return false;
    }
    const std::string pred = at.substr(0, lt);
    const std::string param = at.substr(lt + 1, gt - lt - 1);

    const Type *concreto = nullptr;
    if (g.params && g.args) {
        for (size_t i = 0; i < g.params->size() && i < g.args->size(); ++i) {
            if ((*g.params)[i] == param) {
                concreto = &(*g.args)[i];
                break;
            }
        }
    }
    if (!concreto) {
        ok = false; // el `when:` nombra un param que este tipo no tiene
        return false;
    }
    const PrimitiveKind k = concreto->kind;
    const bool es_float = (k == PrimitiveKind::F32 || k == PrimitiveKind::F64);
    const bool es_int = (k == PrimitiveKind::I8 || k == PrimitiveKind::I16 ||
                         k == PrimitiveKind::I32 || k == PrimitiveKind::I64 ||
                         k == PrimitiveKind::U8 || k == PrimitiveKind::U16 ||
                         k == PrimitiveKind::U32 || k == PrimitiveKind::U64);

    if (pred == "is_float") return es_float;
    if (pred == "is_integer") return es_int;
    if (pred == "is_pointer") return k == PrimitiveKind::PTR;
    if (pred == "is_signed")
        return (k == PrimitiveKind::I8 || k == PrimitiveKind::I16 ||
                k == PrimitiveKind::I32 || k == PrimitiveKind::I64);
    if (pred == "sizeof") {
        size_t bytes = 0;
        switch (k) {
        case PrimitiveKind::I8:
        case PrimitiveKind::U8:
        case PrimitiveKind::BOOL: bytes = 1; break;
        case PrimitiveKind::I16:
        case PrimitiveKind::U16: bytes = 2; break;
        case PrimitiveKind::I32:
        case PrimitiveKind::U32:
        case PrimitiveKind::F32:
        case PrimitiveKind::CHAR: bytes = 4; break;
        case PrimitiveKind::I64:
        case PrimitiveKind::U64:
        case PrimitiveKind::F64:
        case PrimitiveKind::PTR: bytes = 8; break;
        default: ok = false; return false;
        }
        const size_t par = at.find(')', gt);
        if (par == std::string::npos) {
            ok = false;
            return false;
        }
        std::string resto = at.substr(par + 1);
        size_t a = resto.find_first_not_of(" 	");
        if (a == std::string::npos) {
            ok = false;
            return false;
        }
        resto = resto.substr(a);
        std::string op;
        while (!resto.empty() && (resto[0] == '=' || resto[0] == '!' ||
                                  resto[0] == '<' || resto[0] == '>')) {
            op.push_back(resto[0]);
            resto.erase(resto.begin());
        }
        a = resto.find_first_not_of(" 	");
        if (op.empty() || a == std::string::npos) {
            ok = false;
            return false;
        }
        const long n = std::strtol(resto.c_str() + a, nullptr, 10);
        const long b = static_cast<long>(bytes);
        if (op == "==" || op == "=") return b == n;
        if (op == "!=") return b != n;
        if (op == "<") return b < n;
        if (op == "<=") return b <= n;
        if (op == ">") return b > n;
        if (op == ">=") return b >= n;
        ok = false;
        return false;
    }
    ok = false;
    return false;
}

} // namespace

void TypeChecker::resolve_pending_complexity_(ast::ClassMethodDecl &nm,
                                              const ast::ClassMethodDecl &m,
                                              const vxgen::GenSubst &g,
                                              const SourceLoc &loc) {
    nm.complexity_pending.clear();
    nm.footprint_pending.clear();

    cwhen::AtomEval ev = [&](const std::string &at, bool &ok) {
        return when_atomo_(at, g, ok);
    };
    cwhen::ErrFn err = [&](const std::string &msg) { diags_.error(loc, msg); };

    // @complexity con `when:` sobre T: aqui T ya es concreto.
    if (!m.complexity_pending.empty()) {
        cwhen::Resolved r;
        cwhen::resolve(m.complexity_pending, ev, err, r);
        nm.complexity_expr = std::move(r.expr);
        nm.complexity_vars = std::move(r.vars);
        nm.complexity_partial_pre = std::move(r.partial_pre);
        nm.complexity_partial_post = std::move(r.partial_post);
        nm.complexity_total_pre = std::move(r.total_pre);
        nm.complexity_total_post = std::move(r.total_post);
    }

    // Contratos de HUELLA con `when:` sobre T (mismo motivo).  El default son
    // los campos directos que el clon ya copio.
    if (!m.footprint_pending.empty()) {
        cwhen::ResolvedFP base;
        base.pure = nm.contract_pure ? 1 : -1;
        base.nothrow_ = nm.contract_nothrow ? 1 : -1;
        base.nopanic = nm.contract_nopanic ? 1 : -1;
        base.alloc = nm.contract_alloc;
        base.alloc_partial = nm.contract_alloc_partial;
        base.stack = nm.contract_stack;
        base.stack_partial = nm.contract_stack_partial;
        cwhen::ResolvedFP r;
        cwhen::resolve_footprint(m.footprint_pending, base, ev, err, r);
        nm.contract_pure = (r.pure == 1);
        nm.contract_nothrow = (r.nothrow_ == 1);
        nm.contract_nopanic = (r.nopanic == 1);
        nm.contract_alloc = r.alloc;
        nm.contract_alloc_partial = r.alloc_partial;
        nm.contract_stack = r.stack;
        nm.contract_stack_partial = r.stack_partial;
    }
}

std::string TypeChecker::monomorphize_class(const std::string &template_name,
                                            const std::vector<Type> &args,
                                            const SourceLoc &loc) {
    // #cross-module-generics: usar el template lo marca como referenciado
    // (evita el falso "import no se usa" cuando se importa cross-module).
    referenced_names_.insert(template_name);
    if (template_name.find('.') != std::string::npos)
        referenced_names_.insert(
            template_name.substr(0, template_name.find('.')));
    const std::string mangled =
        mangle_sanitize(template_name) + "_" + mangle_args(args);
    if (monomorphized_.count(mangled)) return mangled;

    const std::string gkey =
        resolve_generic_key(template_name, generic_templates_);
    auto it =
        gkey.empty() ? generic_templates_.end() : generic_templates_.find(gkey);
    if (it == generic_templates_.end()) {
        diags_.error(loc, "tipo generico desconocido: '" + template_name + "'");
        return std::string();
    }
    auto *tmpl =
        static_cast<const ast::ClassDecl *>(mod_.decls[it->second].get());
    if (tmpl->type_params.size() != args.size()) {
        diags_.error(loc, "numero incorrecto de args de tipo para '" +
                              template_name + "': esperados " +
                              std::to_string(tmpl->type_params.size()) +
                              ", recibidos " + std::to_string(args.size()));
        return std::string();
    }

    // #6: verificar constraints de la clase generica sobre los type-args.
    check_type_bounds(tmpl->type_bounds, tmpl->type_params, args, loc);

    // #7: elegir la especializacion de CLASE mas especifica que matchee.
    std::vector<std::string> spec_params;
    std::vector<Type> spec_args;
    const ast::ClassDecl *spec = select_class_specialization(
        template_name, args, spec_params, spec_args);
    const ast::ClassDecl *src = spec ? spec : tmpl;
    GenSubst g = spec ? GenSubst{&spec_params, &spec_args}
                      : GenSubst{&tmpl->type_params, &args};

    auto cloned = std::make_unique<ast::ClassDecl>();
    cloned->loc = src->loc;
    cloned->name = mangled;
    cloned->super_name = src->super_name;
    cloned->interface_names = src->interface_names;
    cloned->is_final = src->is_final;
    cloned->is_aspect = src->is_aspect;
    cloned->is_interface = src->is_interface;
    cloned->is_introspect = src->is_introspect;
    // type_params vacio: ya es concreto.

    // Clonar fields.
    for (const auto &f : src->fields) {
        ast::ClassFieldDecl nf;
        nf.loc = f.loc;
        nf.name = f.name;
        nf.access = f.access;
        nf.is_static = f.is_static;
        nf.is_final = f.is_final;
        nf.type = clone_type_with_subst(f.type.get(), g);
        if (f.init) nf.init = clone_expr(f.init.get(), g);
        cloned->fields.push_back(std::move(nf));
    }
    // Clonar metodos.
    for (const auto &m : src->methods) {
        // #6: disponibilidad condicional por `where` sobre el T de la clase.
        std::vector<ast::TypeBound> method_only;
        if (!method_available_for_subst(m.get(), *g.params, *g.args,
                                        method_only)) {
            record_unavailable_method(mangled, m.get());
            continue;
        }
        auto nm = std::make_unique<ast::ClassMethodDecl>();
        nm->type_bounds = std::move(method_only); // solo bounds sobre `m<U>`
        nm->loc = m->loc;
        // Si el metodo es el constructor del template, su nombre
        // textualmente coincide con el template_name; en la version
        // monomorphizada debe coincidir con el mangled name.
        nm->name = m->is_constructor ? mangled : m->name;
        nm->access = m->access;
        nm->is_static = m->is_static;
        // Un constructor `comptime` que se hereda o se monomorphiza sigue
        // siendolo: sin copiar el flag, el clon dejaba de ser comptime y su
        // cuerpo se trataba como codigo normal.
        nm->is_comptime = m->is_comptime;
        nm->is_final = m->is_final;
        nm->is_override = m->is_override;
        nm->is_virtual = m->is_virtual;
        nm->is_inline = m->is_inline;
        nm->is_constructor = m->is_constructor;
        nm->advice_kind = m->advice_kind;
        nm->advice_target = m->advice_target;
        // Contratos de efectos y coste: son del METODO, asi que viajan a cada
        // instanciacion.  Sin copiarlos, un contrato declarado sobre la
        // plantilla se evaporaba al monomorphizar -- en silencio -- y no se
        // verificaba en ninguna instanciacion.
        nm->contract_pure = m->contract_pure;
        nm->contract_nothrow = m->contract_nothrow;
        nm->contract_nopanic = m->contract_nopanic;
        nm->contract_alloc = m->contract_alloc;
        nm->contract_alloc_partial = m->contract_alloc_partial;
        nm->contract_stack = m->contract_stack;
        nm->contract_stack_partial = m->contract_stack_partial;
        nm->complexity_expr = m->complexity_expr;
        nm->complexity_vars = m->complexity_vars;
        nm->complexity_partial_pre = m->complexity_partial_pre;
        nm->complexity_partial_post = m->complexity_partial_post;
        nm->complexity_total_pre = m->complexity_total_pre;
        nm->complexity_total_post = m->complexity_total_post;
        // Contratos de HUELLA con `when:` (sobre arch o sobre T): al clon.
        nm->footprint_pending = m->footprint_pending;
        // Los @complexity/huella cuyo `when:` habla de T: aqui T ya es
        // concreto.
        resolve_pending_complexity_(*nm, *m, g, loc);
        // #4: preservar los type-params del METODO (`metodo<U>`) tras
        // sustituir T; el metodo sigue siendo generico y se monomorphiza
        // por separado en cada llamada `obj.metodo<U>()`.
        nm->method_type_params = m->method_type_params;
        if (m->return_type) {
            nm->return_type = clone_type_with_subst(m->return_type.get(), g);
        }
        for (const auto &p : m->params) {
            auto np = std::make_unique<ast::ParamDecl>();
            np->loc = p->loc;
            np->name = p->name;
            np->type = clone_type_with_subst(p->type.get(), g);
            nm->params.push_back(std::move(np));
        }
        if (m->body) {
            auto cb = clone_stmt(m->body.get(), g);
            if (cb && cb->kind == ast::NodeKind::BlockStmt) {
                nm->body.reset(static_cast<ast::BlockStmt *>(cb.release()));
            }
        }
        cloned->methods.push_back(std::move(nm));
    }

    monomorphized_[mangled] = true;

    // B.3 contract: registrar provenance para que el lowering
    // marque cada IrFunction generada con template_name + type_args
    // legibles.  Los nombres legibles vienen de @c type_to_string
    // sobre cada arg (e.g., "i32", "string", "Box<i64>" para
    // generics anidados).
    MonomorphInfo info;
    info.template_name = template_name;
    info.type_args.reserve(args.size());
    info.type_arg_types = args; // #7: Types concretos para matching anidado
    for (const auto &t : args) {
        info.type_args.push_back(type_to_string(t));
    }
    monomorph_info_[mangled] = std::move(info);

    // BugFix P1-A4: pre-registrar la clase monomorphizada en
    // class_layouts_ con layout vacio.  Sin esto, type_from_node de
    // generics anidados (`Container<Pair<i32,i64>>`) devolvia Type{}
    // porque Pair_i32_i64 aun no estaba en class_layouts_ cuando el
    // outer se monomorphizaba.  El pre-pase de class_layouts (en
    // collect_globals) sobrescribe esta entrada con el layout real.
    if (!class_layouts_.count(mangled)) {
        ClassLayout empty;
        empty.name = mangled;
        class_layouts_[mangled] = std::move(empty);
    }

    mod_.decls.push_back(std::move(cloned));
    return mangled;
}

// L2.3: monomorphize_enum -- equivalente a monomorphize_class pero
// sobre EnumDecl.  Crea una copia concreta del template con los
// type_params sustituidos por args concretos, registra la entrada en
// generic_templates_-stylee y la anade a mod_.decls para que el pase
// 2 de collect_globals la procese como enum normal y genere su
// EnumLayout.  Idempotente: si la version (template, args) ya esta
// monomorphizada, retorna el mangled name sin clonar.
std::string TypeChecker::monomorphize_enum(const std::string &template_name,
                                           const std::vector<Type> &args,
                                           const SourceLoc &loc) {
    const std::string mangled =
        mangle_sanitize(template_name) + "_" + mangle_args(args);
    if (monomorphized_.count(mangled)) return mangled;

    const std::string gkey =
        resolve_generic_key(template_name, generic_enum_templates_);
    auto it = gkey.empty() ? generic_enum_templates_.end()
                           : generic_enum_templates_.find(gkey);
    if (it == generic_enum_templates_.end()) {
        diags_.error(loc, "enum generico desconocido: '" + template_name + "'");
        return std::string();
    }
    auto *tmpl =
        static_cast<const ast::EnumDecl *>(mod_.decls[it->second].get());
    if (tmpl->type_params.size() != args.size()) {
        diags_.error(loc, "numero incorrecto de args de tipo para enum '" +
                              template_name + "': esperados " +
                              std::to_string(tmpl->type_params.size()) +
                              ", recibidos " + std::to_string(args.size()));
        return std::string();
    }

    GenSubst g{&tmpl->type_params, &args};

    auto cloned = std::make_unique<ast::EnumDecl>();
    cloned->loc = tmpl->loc;
    cloned->name = mangled;
    cloned->is_introspect = tmpl->is_introspect;
    cloned->is_public = tmpl->is_public;
    // type_params vacio: ya es concreto.

    // Clonar variantes sustituyendo los payload types.
    for (const auto &v : tmpl->variants) {
        ast::EnumVariantDecl nv;
        nv.loc = v.loc;
        nv.name = v.name;
        nv.field_types.reserve(v.field_types.size());
        for (const auto &ft : v.field_types) {
            nv.field_types.push_back(clone_type_with_subst(ft.get(), g));
        }
        cloned->variants.push_back(std::move(nv));
    }

    monomorphized_[mangled] = true;

    // Construir el EnumLayout concreto INMEDIATAMENTE (no diferimos al
    // pase 2 porque el monomorphize_enum puede invocarse on-demand
    // durante check_call cuando ya estamos pasado el pase 2).
    EnumLayout elay;
    elay.name = mangled;
    elay.is_introspect = tmpl->is_introspect;
    elay.is_public = tmpl->is_public;
    uint32_t max_pl = 0;
    for (size_t vi = 0; vi < cloned->variants.size(); ++vi) {
        const auto &vd = cloned->variants[vi];
        EnumVariantInfo vi_info;
        vi_info.name = vd.name;
        vi_info.tag = static_cast<uint32_t>(vi);
        vi_info.field_types.reserve(vd.field_types.size());
        for (const auto &ft : vd.field_types) {
            vi_info.field_types.push_back(type_from_node(ft.get()));
        }
        if (vi_info.field_types.size() > max_pl) {
            max_pl = static_cast<uint32_t>(vi_info.field_types.size());
        }
        elay.variants.push_back(std::move(vi_info));
    }
    elay.max_payload_fields = max_pl;
    elay.size_bytes = 8 + 8 * max_pl;
    enum_layouts_[mangled] = std::move(elay);

    mod_.decls.push_back(std::move(cloned));
    return mangled;
}

// Monomorphizacion de struct generico.  Mismo modelo que monomorphize_class:
// clona el StructDecl template sustituyendo los type_params, pre-registra un
// StructLayout vacio (para resolver genericos anidados) y anyade el clon a
// mod_.decls; collect_globals construye el layout real (size/offsets/
// destructibilidad/copy-hook) y lower_struct_methods baja sus metodos.
std::string TypeChecker::monomorphize_struct(const std::string &template_name,
                                             const std::vector<Type> &args,
                                             const SourceLoc &loc) {
    referenced_names_.insert(template_name);          // #cross-module-generics
    if (template_name.find('.') != std::string::npos) // marca el namespace
        referenced_names_.insert(
            template_name.substr(0, template_name.find('.')));
    const std::string mangled =
        mangle_sanitize(template_name) + "_" + mangle_args(args);
    if (monomorphized_.count(mangled)) return mangled;

    const std::string gkey =
        resolve_generic_key(template_name, generic_struct_templates_);
    auto it = gkey.empty() ? generic_struct_templates_.end()
                           : generic_struct_templates_.find(gkey);
    if (it == generic_struct_templates_.end()) {
        diags_.error(loc,
                     "struct generico desconocido: '" + template_name + "'");
        return std::string();
    }
    auto *tmpl =
        static_cast<const ast::StructDecl *>(mod_.decls[it->second].get());
    if (tmpl->type_params.size() != args.size()) {
        diags_.error(loc, "numero incorrecto de args de tipo para struct '" +
                              template_name + "': esperados " +
                              std::to_string(tmpl->type_params.size()) +
                              ", recibidos " + std::to_string(args.size()));
        return std::string();
    }

    // #6: verificar constraints del struct generico sobre los type-args.
    check_type_bounds(tmpl->type_bounds, tmpl->type_params, args, loc);

    // #7: elegir la especializacion mas especifica que matchee los args
    // (total/parcial).  Si la hay, se clona ESA definicion con los bindings
    // de sus params frescos; si no, el template primario con T -> args.
    std::vector<std::string> spec_params;
    std::vector<Type> spec_args;
    const ast::StructDecl *spec = select_struct_specialization(
        template_name, args, spec_params, spec_args);
    const ast::StructDecl *src = spec ? spec : tmpl;
    GenSubst g = spec ? GenSubst{&spec_params, &spec_args}
                      : GenSubst{&tmpl->type_params, &args};

    auto cloned = std::make_unique<ast::StructDecl>();
    cloned->loc = src->loc;
    cloned->name = mangled;
    cloned->is_public = src->is_public;
    cloned->is_introspect = src->is_introspect;
    // type_params vacio: ya es concreto.

    // Clonar campos sustituyendo el tipo (T -> arg concreto).
    for (const auto &f : src->fields) {
        ast::StructFieldDecl nf;
        nf.loc = f.loc;
        nf.name = f.name;
        nf.bit_width = f.bit_width;
        nf.type = clone_type_with_subst(f.type.get(), g);
        // Clonar el valor por defecto del campo (`u8 tag = 0x7`) para que el
        // struct monomorphizado conserve sus defaults.
        if (f.default_init)
            nf.default_init = clone_expr(f.default_init.get(), g);
        cloned->fields.push_back(std::move(nf));
    }
    // Clonar metodos (dtor `__dtor`, copy-hook `__clone__`, y metodos normales;
    // los structs no tienen constructores nombrados como el tipo).
    for (const auto &m : src->methods) {
        // #6: disponibilidad condicional por `where` sobre el T del struct.  Si
        // el metodo exige `where T: Concepto` y el arg concreto no lo cumple,
        // el metodo NO existe en esta instanciacion (no se clona ni
        // type-checkea).
        std::vector<ast::TypeBound> method_only;
        if (!method_available_for_subst(m.get(), *g.params, *g.args,
                                        method_only)) {
            record_unavailable_method(mangled, m.get());
            continue;
        }
        auto nm = std::make_unique<ast::ClassMethodDecl>();
        nm->type_bounds = std::move(method_only); // solo bounds sobre `m<U>`
        nm->loc = m->loc;
        nm->name = m->name;
        nm->access = m->access;
        nm->is_static = m->is_static;
        // Un constructor `comptime` que se hereda o se monomorphiza sigue
        // siendolo: sin copiar el flag, el clon dejaba de ser comptime y su
        // cuerpo se trataba como codigo normal.
        nm->is_comptime = m->is_comptime;
        // Y sigue siendo un CONSTRUCTOR: el aplanado de la herencia tampoco
        // copiaba el flag, con lo que el clon dejaba de reconocerse como tal.
        nm->is_constructor = m->is_constructor;
        nm->is_final = m->is_final;
        nm->is_virtual = m->is_virtual;
        nm->is_inline = m->is_inline;
        nm->is_destructor = m->is_destructor;
        // Contratos de efectos y coste: son del METODO, asi que viajan a cada
        // instanciacion.  Sin copiarlos, un contrato declarado sobre la
        // plantilla se evaporaba al monomorphizar -- en silencio -- y no se
        // verificaba en ninguna instanciacion.
        nm->contract_pure = m->contract_pure;
        nm->contract_nothrow = m->contract_nothrow;
        nm->contract_nopanic = m->contract_nopanic;
        nm->contract_alloc = m->contract_alloc;
        nm->contract_alloc_partial = m->contract_alloc_partial;
        nm->contract_stack = m->contract_stack;
        nm->contract_stack_partial = m->contract_stack_partial;
        nm->complexity_expr = m->complexity_expr;
        nm->complexity_vars = m->complexity_vars;
        nm->complexity_partial_pre = m->complexity_partial_pre;
        nm->complexity_partial_post = m->complexity_partial_post;
        nm->complexity_total_pre = m->complexity_total_pre;
        nm->complexity_total_post = m->complexity_total_post;
        // Contratos de HUELLA con `when:` (sobre arch o sobre T): al clon.
        nm->footprint_pending = m->footprint_pending;
        // Los @complexity/huella cuyo `when:` habla de T: aqui T ya es
        // concreto.
        resolve_pending_complexity_(*nm, *m, g, loc);
        // #4: preservar los type-params del METODO (`mezcla<U>`).  El
        // substituto @c g solo sustituye T (el type-param del struct); U
        // queda intacto y el metodo sigue siendo template generico, que se
        // monomorphiza en cada `obj.mezcla<U>()` sobre el struct concreto.
        nm->method_type_params = m->method_type_params;
        if (m->return_type) {
            nm->return_type = clone_type_with_subst(m->return_type.get(), g);
        }
        for (const auto &p : m->params) {
            auto np = std::make_unique<ast::ParamDecl>();
            np->loc = p->loc;
            np->name = p->name;
            np->type = clone_type_with_subst(p->type.get(), g);
            nm->params.push_back(std::move(np));
        }
        if (m->body) {
            auto cb = clone_stmt(m->body.get(), g);
            if (cb && cb->kind == ast::NodeKind::BlockStmt) {
                nm->body.reset(static_cast<ast::BlockStmt *>(cb.release()));
            }
        }
        cloned->methods.push_back(std::move(nm));
    }

    monomorphized_[mangled] = true;

    // B.3 contract: provenance legible (template + args) para el lowering.
    MonomorphInfo info;
    info.template_name = template_name;
    info.type_args.reserve(args.size());
    info.type_arg_types = args; // #7: Types concretos para matching anidado
    for (const auto &t : args) {
        info.type_args.push_back(type_to_string(t));
    }
    monomorph_info_[mangled] = std::move(info);

    // Pre-registrar StructLayout vacio (mismo motivo que monomorphize_class):
    // un generico anidado (`Outer<Inner<i32>>`) resuelve Inner_i32 antes de que
    // collect_globals construya su layout real.  collect_globals lo
    // sobreescribe.
    if (!struct_layouts_.count(mangled)) {
        StructLayout empty;
        empty.name = mangled;
        empty.is_introspect = src->is_introspect;
        struct_layouts_[mangled] = std::move(empty);
    }

    mod_.decls.push_back(std::move(cloned));
    return mangled;
}

// ------------------------------------------------------------------
// Fase 2 de la herencia de structs: aplanado + resolucion de `Self`.
// Ver [[proj_struct_self_inheritance]].
// ------------------------------------------------------------------

/// ¿El TypeNode mete un `Self` POR VALOR en el layout? (prohibido como campo).
/// `Self`, `Optional<Self>`, `Array<Self>` por valor -> true; `Self*` -> false.
static bool type_has_self_by_value(const ast::TypeNode *t) {
    if (!t) return false;
    if (t->kind == ast::NodeKind::NamedTypeNode) {
        auto *nt = static_cast<const ast::NamedTypeNode *>(t);
        if (nt->name == "Self") return true;
        for (const auto &ta : nt->type_args)
            if (type_has_self_by_value(ta.get())) return true;
        return false;
    }
    if (t->kind == ast::NodeKind::PointerTypeNode)
        return false; // tras indireccion
    if (t->kind == ast::NodeKind::ArrayTypeNode) {
        auto *at = static_cast<const ast::ArrayTypeNode *>(t);
        return type_has_self_by_value(at->element_type.get());
    }
    return false;
}

/// ¿El TypeNode menciona `Self` en CUALQUIER posicion (incluida tras puntero)?
static bool type_mentions_self(const ast::TypeNode *t) {
    if (!t) return false;
    if (t->kind == ast::NodeKind::NamedTypeNode) {
        auto *nt = static_cast<const ast::NamedTypeNode *>(t);
        if (nt->name == "Self") return true;
        for (const auto &ta : nt->type_args)
            if (type_mentions_self(ta.get())) return true;
        return false;
    }
    if (t->kind == ast::NodeKind::PointerTypeNode)
        return type_mentions_self(
            static_cast<const ast::PointerTypeNode *>(t)->pointee.get());
    if (t->kind == ast::NodeKind::ArrayTypeNode)
        return type_mentions_self(
            static_cast<const ast::ArrayTypeNode *>(t)->element_type.get());
    if (t->kind == ast::NodeKind::FunctionTypeNode) {
        auto *ft = static_cast<const ast::FunctionTypeNode *>(t);
        for (const auto &pt : ft->param_types)
            if (type_mentions_self(pt.get())) return true;
        return type_mentions_self(ft->return_type.get());
    }
    return false;
}

/// ¿Un stmt menciona `Self` en el tipo de alguna var-decl local (`Self r`)?
/// Recorre los contenedores de stmts comunes; los casos raros (cast/new Self en
/// una expresion suelta) los cubre el uso de Self en firma, que es lo habitual.
static bool stmt_mentions_self(const ast::Stmt *s) {
    if (!s) return false;
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        auto *b = static_cast<const ast::BlockStmt *>(s);
        for (const auto &st : b->body)
            if (stmt_mentions_self(st.get())) return true;
        return false;
    }
    case ast::NodeKind::VarDeclStmt:
        return type_mentions_self(
            static_cast<const ast::VarDeclStmt *>(s)->type.get());
    case ast::NodeKind::IfStmt: {
        auto *i = static_cast<const ast::IfStmt *>(s);
        return stmt_mentions_self(i->then_branch.get()) ||
               stmt_mentions_self(i->else_branch.get());
    }
    case ast::NodeKind::WhileStmt:
        return stmt_mentions_self(
            static_cast<const ast::WhileStmt *>(s)->body.get());
    case ast::NodeKind::ForStmt: {
        auto *f = static_cast<const ast::ForStmt *>(s);
        return stmt_mentions_self(f->init.get()) ||
               stmt_mentions_self(f->body.get());
    }
    default: return false;
    }
}

/// ¿El struct usa `Self` en alguna firma (return/params) o en el body?
static bool struct_uses_self(const ast::StructDecl *s) {
    for (const auto &m : s->methods) {
        if (m->return_type && type_mentions_self(m->return_type.get()))
            return true;
        for (const auto &p : m->params)
            if (type_mentions_self(p->type.get())) return true;
        if (m->body && stmt_mentions_self(m->body.get())) return true;
    }
    return false;
}

/// Clona un ClassMethodDecl aplicando la sustitucion @p g (Self -> derivado).
/// Mismo conjunto de campos que el clon de monomorphize_struct (preserva
/// contratos de efectos/coste, type-params de metodo generico, etc.).
static std::unique_ptr<ast::ClassMethodDecl>
clone_method_subst(const ast::ClassMethodDecl *m, const GenSubst &g) {
    auto nm = std::make_unique<ast::ClassMethodDecl>();
    nm->loc = m->loc;
    nm->name = m->name;
    nm->access = m->access;
    nm->is_static = m->is_static;
    // Un constructor `comptime` que se hereda o se monomorphiza sigue
    // siendolo: sin copiar el flag, el clon dejaba de ser comptime y su
    // cuerpo se trataba como codigo normal.
    nm->is_comptime = m->is_comptime;
    // Y sigue siendo un CONSTRUCTOR: el aplanado de la herencia tampoco
    // copiaba el flag, con lo que el clon dejaba de reconocerse como tal.
    nm->is_constructor = m->is_constructor;
    nm->is_final = m->is_final;
    nm->is_virtual = m->is_virtual;
    nm->is_inline = m->is_inline;
    nm->is_destructor = m->is_destructor;
    nm->contract_pure = m->contract_pure;
    nm->contract_nothrow = m->contract_nothrow;
    nm->contract_nopanic = m->contract_nopanic;
    nm->contract_alloc = m->contract_alloc;
    nm->contract_alloc_partial = m->contract_alloc_partial;
    nm->contract_stack = m->contract_stack;
    nm->contract_stack_partial = m->contract_stack_partial;
    nm->complexity_expr = m->complexity_expr;
    nm->complexity_vars = m->complexity_vars;
    nm->complexity_partial_pre = m->complexity_partial_pre;
    nm->complexity_partial_post = m->complexity_partial_post;
    nm->complexity_total_pre = m->complexity_total_pre;
    nm->complexity_total_post = m->complexity_total_post;
    nm->footprint_pending = m->footprint_pending;
    nm->method_type_params = m->method_type_params;
    nm->type_bounds = m->type_bounds;
    if (m->return_type)
        nm->return_type = clone_type_with_subst(m->return_type.get(), g);
    for (const auto &p : m->params) {
        auto np = std::make_unique<ast::ParamDecl>();
        np->loc = p->loc;
        np->name = p->name;
        np->type = clone_type_with_subst(p->type.get(), g);
        nm->params.push_back(std::move(np));
    }
    if (m->body) {
        auto cb = clone_stmt(m->body.get(), g);
        if (cb && cb->kind == ast::NodeKind::BlockStmt)
            nm->body.reset(static_cast<ast::BlockStmt *>(cb.release()));
    }
    return nm;
}

bool TypeChecker::struct_ptr_upcast_ok(const Type &target,
                                       const Type &value) const {
    if (target.kind != PrimitiveKind::PTR || value.kind != PrimitiveKind::PTR ||
        !target.pointee || !value.pointee ||
        target.pointee->kind != PrimitiveKind::STRUCT ||
        value.pointee->kind != PrimitiveKind::STRUCT)
        return false;
    std::string cur = value.pointee->struct_name;
    int guard = 0;
    while (!cur.empty() && guard++ < 64) {
        if (cur == target.pointee->struct_name) return true;
        auto it = struct_layouts_.find(cur);
        if (it == struct_layouts_.end()) break;
        cur = it->second.super_name;
    }
    return false;
}

void TypeChecker::verify_struct_interface_conformance() {
    // Para cada struct que declara `: IConcepto`, exigir que satisfaga el
    // concepto.  Es coste cero: la misma via comptime que `where T: C`, sin
    // vtable ni codigo.  El `super_name` (herencia de un @Abstract) NO se toca
    // aqui -- eso aporta campos+impl; las `interface_names` solo son contratos.
    // Indice nombre -> StructDecl para recorrer cadenas de herencia (bases).
    std::unordered_map<std::string, ast::StructDecl *> smap;
    for (auto &d : mod_.decls)
        if (d && d->kind == ast::NodeKind::StructDecl) {
            auto *sd = static_cast<ast::StructDecl *>(d.get());
            smap[sd->name] = sd;
        }

    for (const auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::StructDecl) continue;
        auto *s = static_cast<ast::StructDecl *>(decl.get());
        // Los templates (`struct Caja<T> : C`) no se verifican sobre el molde;
        // cada instancia monomorphizada hereda las clausulas y se verifica.
        if (!s->type_params.empty()) continue;

        // Conceptos exigidos = interfaces declaradas por el struct MAS las de
        // toda su cadena de bases (@Abstract).  Un @Abstract puede declarar una
        // interfaz sin implementarla del todo (modelo Java): la obligacion se
        // TRANSFIERE al derivado concreto.  Recopilamos aqui esa herencia.
        // Un nombre en la posicion `super_name` que NO resuelve a struct es en
        // realidad una interfaz (`struct S : IConcepto` sin base concreta).
        std::vector<std::string> ifaces;
        std::unordered_set<std::string> seen_iface;
        auto add_ifaces_of = [&](ast::StructDecl *d) {
            for (const std::string &n : d->interface_names)
                if (seen_iface.insert(n).second) ifaces.push_back(n);
            if (!d->super_name.empty() &&
                smap.find(d->super_name) == smap.end())
                if (seen_iface.insert(d->super_name).second)
                    ifaces.push_back(d->super_name);
        };
        {
            std::unordered_set<std::string> seen_base;
            ast::StructDecl *cur = s;
            while (cur && seen_base.insert(cur->name).second) {
                add_ifaces_of(cur);
                if (cur->super_name.empty()) break;
                auto it = smap.find(cur->super_name);
                if (it == smap.end()) break; // super es interfaz, ya contada
                cur = it->second;            // subir a la base struct
            }
        }
        if (ifaces.empty()) continue;

        // El tipo concreto del struct (nombre ya mangled tras
        // flatten/namespace).
        Type st{PrimitiveKind::STRUCT};
        st.struct_name = s->name;
        for (const std::string &iname : ifaces) {
            const ConceptEval ev = comptime_eval_concept(*this, iname, st);
            if (!ev.found) {
                diags_.error(s->loc, "el struct '" + s->name + "' declara ': " +
                                         iname + "' pero '" + iname +
                                         "' no es un concepto conocido");
                continue;
            }
            // Un @Abstract NO se verifica estrictamente: puede diferir la
            // implementacion a sus derivados.  Solo se comprueba que el
            // concepto exista (diagnostico de nombres mal escritos).  El
            // derivado concreto que herede de este abstract SI sera verificado
            // (arriba acumulamos las interfaces heredadas).
            if (s->is_abstract) continue;
            if (!ev.satisfied) {
                diags_.error(s->loc,
                             "el struct '" + s->name +
                                 "' no satisface el concepto '" + iname +
                                 "' que declara implementar (directamente "
                                 "o heredado de una base @Abstract)");
            }
        }
    }
}

void TypeChecker::flatten_struct_inheritance() {
    // Indice nombre -> StructDecl.
    std::unordered_map<std::string, ast::StructDecl *> smap;
    for (auto &d : mod_.decls)
        if (d && d->kind == ast::NodeKind::StructDecl) {
            auto *sd = static_cast<ast::StructDecl *>(d.get());
            smap[sd->name] = sd;
        }
    if (smap.empty()) return;

    // FASE A: computar campos+metodos aplanados de cada struct leyendo los
    // decls ORIGINALES (sin mutar); FASE B: asignarlos de golpe (asi el
    // multinivel y la herencia leen siempre los propios sin ver mutaciones
    // intermedias).
    struct Flat {
        std::vector<ast::StructFieldDecl> fields;
        std::vector<std::unique_ptr<ast::ClassMethodDecl>> methods;
        bool changed = false;
    };
    std::unordered_map<std::string, Flat> result;

    for (auto &kv : smap) {
        ast::StructDecl *S = kv.second;
        // Cadena de bases de S (S -> ... -> raiz), siguiendo super_name que
        // solo apunta a otro STRUCT.  Si apunta a algo que no es struct
        // (interface), se para: la conformidad la valida la fase de interfaces.
        std::vector<ast::StructDecl *> chain;
        std::unordered_set<std::string> seen;
        ast::StructDecl *cur = S;
        while (cur) {
            if (seen.count(cur->name)) {
                diags_.error(cur->loc, "ciclo de herencia de struct en '" +
                                           cur->name + "'");
                break;
            }
            seen.insert(cur->name);
            chain.push_back(cur);
            if (cur->super_name.empty()) break;
            auto it = smap.find(cur->super_name);
            if (it == smap.end()) break; // super no es struct
            cur = it->second;
        }
        const bool has_base = chain.size() > 1;
        // Solo hay trabajo si hereda de otro struct o si usa `Self` (para
        // resolver Self=S).  Los demas structs se dejan intactos (sin
        // re-clonar).
        if (!has_base && !struct_uses_self(S)) continue;

        // Sustitucion Self -> S (tipo STRUCT del propio struct).
        Type sty;
        sty.kind = PrimitiveKind::STRUCT;
        sty.struct_name = S->name;
        std::vector<std::string> params = {"Self"};
        std::vector<Type> args = {sty};
        GenSubst g{&params, &args};

        Flat f;
        // Campos: raiz primero (chain va S->raiz, recorrer al reves).
        for (auto rit = chain.rbegin(); rit != chain.rend(); ++rit) {
            for (const auto &fld : (*rit)->fields) {
                if (type_has_self_by_value(fld.type.get()))
                    diags_.error(
                        fld.loc,
                        "'Self' por valor no puede ser un campo de '" +
                            S->name +
                            "' (produciria un layout de tamano infinito); usa "
                            "'Self*'");
                ast::StructFieldDecl nf;
                nf.loc = fld.loc;
                nf.name = fld.name;
                nf.type = clone_type_with_subst(fld.type.get(), g);
                // Preservar TODOS los atributos del campo (sin esto un miembro
                // ANONIMO -- union/struct sin nombre -- o un array/overlay
                // heredado se copiaba como campo escalar sin nombre y se
                // perdian sus subcampos, p.ej. la union lo64/hi64/bytes de un
                // wide-int).
                nf.is_anonymous = fld.is_anonymous;
                nf.bit_width = fld.bit_width;
                nf.explicit_offset = fld.explicit_offset;
                nf.is_array = fld.is_array;
                nf.endian = fld.endian;
                if (fld.offset_expr)
                    nf.offset_expr = clone_expr(fld.offset_expr.get(), g);
                if (fld.array_count)
                    nf.array_count = clone_expr(fld.array_count.get(), g);
                if (fld.array_stride)
                    nf.array_stride = clone_expr(fld.array_stride.get(), g);
                if (fld.endian_expr)
                    nf.endian_expr = clone_expr(fld.endian_expr.get(), g);
                if (fld.offset_block) {
                    auto cb = clone_stmt(fld.offset_block.get(), g);
                    if (cb && cb->kind == ast::NodeKind::BlockStmt)
                        nf.offset_block.reset(
                            static_cast<ast::BlockStmt *>(cb.release()));
                }
                if (fld.element_block) {
                    auto cb = clone_stmt(fld.element_block.get(), g);
                    if (cb && cb->kind == ast::NodeKind::BlockStmt)
                        nf.element_block.reset(
                            static_cast<ast::BlockStmt *>(cb.release()));
                }
                if (fld.default_init)
                    nf.default_init = clone_expr(fld.default_init.get(), g);
                f.fields.push_back(std::move(nf));
            }
        }
        // Metodos: raiz->S, el mas derivado gana por nombre.
        std::unordered_map<std::string, size_t> midx;
        for (auto rit = chain.rbegin(); rit != chain.rend(); ++rit) {
            for (const auto &m : (*rit)->methods) {
                // Regla 8: PROHIBIDO `Self` en un metodo `@Virtual`.  Son
                // mecanismos OPUESTOS: `Self` = clon-por-derivado estatico;
                // `@Virtual` = una sola firma con dispatch dinamico por vtable.
                if (m->is_virtual) {
                    bool self_in_sig =
                        (m->return_type &&
                         type_mentions_self(m->return_type.get()));
                    for (const auto &p : m->params)
                        self_in_sig =
                            self_in_sig || type_mentions_self(p->type.get());
                    const bool self_in_body =
                        m->body && stmt_mentions_self(m->body.get());
                    if (self_in_sig || self_in_body)
                        diags_.error(
                            m->loc,
                            "'Self' no puede usarse en un metodo @Virtual "
                            "('" +
                                m->name +
                                "'): Self solo existe durante la "
                                "monomorfizacion de "
                                "metodos heredados (dispatch estatico), "
                                "mientras que "
                                "@Virtual es dispatch dinamico por vtable");
                }
                auto clon = clone_method_subst(m.get(), g);
                auto mi = midx.find(m->name);
                if (mi != midx.end())
                    f.methods[mi->second] = std::move(clon);
                else {
                    midx[m->name] = f.methods.size();
                    f.methods.push_back(std::move(clon));
                }
            }
        }
        f.changed = true;
        result[S->name] = std::move(f);
    }

    // FASE B: aplicar los aplanados.
    for (auto &kv : result) {
        auto it = smap.find(kv.first);
        if (it == smap.end() || !kv.second.changed) continue;
        it->second->fields = std::move(kv.second.fields);
        it->second->methods = std::move(kv.second.methods);
    }
}

// Monomorphizacion de funcion generica.  Clona la FunctionDecl template
// sustituyendo los type_params en return_type, params y body; la anyade a
// mod_.decls para que collect_globals registre su firma y el lowering la baje.
std::string TypeChecker::monomorphize_function(const std::string &template_name,
                                               const std::vector<Type> &args,
                                               const SourceLoc &loc) {
    referenced_names_.insert(template_name);          // #cross-module-generics
    if (template_name.find('.') != std::string::npos) // marca el namespace
        referenced_names_.insert(
            template_name.substr(0, template_name.find('.')));
    const std::string mangled =
        mangle_sanitize(template_name) + "_" + mangle_args(args);
    if (monomorphized_.count(mangled)) return mangled;

    auto it = generic_fn_templates_.find(template_name);
    if (it == generic_fn_templates_.end()) {
        diags_.error(loc,
                     "funcion generica desconocida: '" + template_name + "'");
        return std::string();
    }
    auto *tmpl =
        static_cast<const ast::FunctionDecl *>(mod_.decls[it->second].get());
    if (tmpl->type_params.size() != args.size()) {
        diags_.error(loc, "numero incorrecto de args de tipo para funcion '" +
                              template_name + "': esperados " +
                              std::to_string(tmpl->type_params.size()) +
                              ", recibidos " + std::to_string(args.size()));
        return std::string();
    }

    // #6: verificar las constraints `<T: Concepto>` / `where` sobre los
    // type-args concretos (compile-time; cero codigo emitido).
    check_type_bounds(tmpl->type_bounds, tmpl->type_params, args, loc);

    // #7: elegir la especializacion de FUNCION mas especifica que matchee.
    std::vector<std::string> spec_params;
    std::vector<Type> spec_args;
    const ast::FunctionDecl *spec = select_function_specialization(
        template_name, args, spec_params, spec_args);
    const ast::FunctionDecl *src = spec ? spec : tmpl;
    GenSubst g = spec ? GenSubst{&spec_params, &spec_args}
                      : GenSubst{&tmpl->type_params, &args};

    auto cloned = std::make_unique<ast::FunctionDecl>();
    cloned->loc = src->loc;
    cloned->name = mangled;
    cloned->is_public = src->is_public;
    cloned->is_noexcept = src->is_noexcept;
    cloned->is_pure = src->is_pure;
    // Preservar el caracter comptime: una comptime fn generica monomorfizada
    // sigue siendo comptime (su instancia concreta se ejecuta en la ComptimeVM
    // como cualquier otra comptime fn; su introspeccion `sizeof<Vec3>` etc. se
    // pliega a constante al bajarla).  is_macro NO (los @Macro tienen su path).
    cloned->is_comptime = src->is_comptime;
    // type_params vacio: ya es concreta.
    if (src->return_type)
        cloned->return_type = clone_type_with_subst(src->return_type.get(), g);
    for (const auto &p : src->params) {
        auto np = std::make_unique<ast::ParamDecl>();
        np->loc = p->loc;
        np->name = p->name;
        np->is_expr_capture = p->is_expr_capture;
        np->type = clone_type_with_subst(p->type.get(), g);
        cloned->params.push_back(std::move(np));
    }
    if (src->body) {
        auto cb = clone_stmt(src->body.get(), g);
        if (cb && cb->kind == ast::NodeKind::BlockStmt) {
            cloned->body.reset(static_cast<ast::BlockStmt *>(cb.release()));
        }
    }

    monomorphized_[mangled] = true;

    MonomorphInfo info;
    info.template_name = template_name;
    info.type_args.reserve(args.size());
    info.type_arg_types = args; // #7: Types concretos para matching anidado
    for (const auto &t : args)
        info.type_args.push_back(type_to_string(t));
    monomorph_info_[mangled] = std::move(info);

    // Instancia de una comptime fn generica: registrarla como comptime fn
    // (collect_globals ya paso; sin esto el path VM no la encontraria y la
    // instancia caeria al tree-walker).  Ahora `vec_dim_Vec3` es una comptime
    // fn concreta que se rutea a la ComptimeVM como cualquier otra.
    if (cloned->is_comptime) {
        register_comptime_fn(mangled, cloned.get());
    }

    mod_.decls.push_back(std::move(cloned));
    return mangled;
}

bool TypeChecker::class_is_assignable(const Type &target,
                                      const Type &value) const noexcept {
    // Optional/Result: dos Optional<X> son asignables si X y Y
    // son ambos numericos (coercion implicita comun: Some(50) tipa
    // como Optional<i64> y se asigna a Optional<i32> sin error,
    // igual que la regla numerica para escalares).  Tambien para
    // Result<V1,E1> -> Result<V2,E2>.
    if (target.kind == PrimitiveKind::OPTIONAL &&
        value.kind == PrimitiveKind::OPTIONAL && target.pointee &&
        value.pointee && is_numeric(target.pointee->kind) &&
        is_numeric(value.pointee->kind)) {
        return true;
    }
    if (target.kind == PrimitiveKind::RESULT &&
        value.kind == PrimitiveKind::RESULT && target.pointee &&
        value.pointee && target.pointee2 && value.pointee2 &&
        is_numeric(target.pointee->kind) && is_numeric(value.pointee->kind) &&
        is_numeric(target.pointee2->kind) && is_numeric(value.pointee2->kind)) {
        return true;
    }
    if (target.kind != PrimitiveKind::CLASS) return false;
    if (value.kind != PrimitiveKind::CLASS) return false;
    return type_derives_from(value.struct_name, target.struct_name);
}

/**
 * @copydoc vx::TypeChecker::type_derives_from
 */
/**
 * @copydoc vx::TypeChecker::payload_slot_bytes
 */
uint32_t TypeChecker::payload_slot_bytes(const Type &p) const {
    /* Un escalar ocupa una palabra; un struct por valor, su tamano real
     * redondeado a palabra, para que quepa entero.  El redondeo importa porque
     * la copia va palabra a palabra: uno de doce que se cuente como doce
     * copiaria ocho y perderia el ultimo campo. */
    uint32_t bytes = 8;
    if (p.kind == PrimitiveKind::STRUCT && !p.struct_name.empty()) {
        const auto it = struct_layouts_.find(p.struct_name);
        if (it != struct_layouts_.end() && it->second.size_bytes > bytes)
            bytes = (it->second.size_bytes + 7u) & ~uint32_t(7);
    }
    return bytes;
}

/**
 * @copydoc vx::TypeChecker::result_layout
 */
ResultLayout TypeChecker::result_layout(const Type &t) const {
    ResultLayout lay;
    /* La marca en el cero, el valor detras y el error detras del valor.  Los
     * dos payloads se guardan UNO AL LADO DEL OTRO aunque solo uno este vivo
     * cada vez: son ocho mas lo que ocupe cada uno.
     *
     * Escrito a mano -- veinticuatro, valor en el ocho, error en el dieciseis
     * -- un `Result` cuyo valor fuera un struct de mas de una palabra no cabia,
     * y lo que se sacaba eran ceros.  Es el mismo fallo que tenia el `Optional`
     * y se arregla igual: preguntando. */
    lay.value_offset = 8;
    const uint32_t v = t.pointee ? payload_slot_bytes(*t.pointee) : 8u;
    const uint32_t e = t.pointee2 ? payload_slot_bytes(*t.pointee2) : 8u;
    lay.error_offset = lay.value_offset + v;
    lay.bytes = lay.error_offset + e;
    return lay;
}

/**
 * @copydoc vx::TypeChecker::optional_layout
 */
OptionalLayout TypeChecker::optional_layout(const Type &t) const {
    OptionalLayout lay;
    /* El payload de un escalar ocupa una palabra; el de un struct por valor,
     * su tamano real redondeado a palabra, para que quepa entero. */
    const uint32_t payload = t.pointee ? payload_slot_bytes(*t.pointee) : 8u;
    /* AQUI ES DONDE OCUPA MENOS.  Cuando el payload no puede valer cero, el
     * cero SOBRA como valor y sirve de marca: no hace falta una palabra aparte
     * para decir si esta o no esta, y el conjunto mide ocho en vez de
     * dieciseis.
     *
     * Solo donde el tipo lo PROMETE.  Un prestamo (`borrow<T>`) es la
     * direccion de algo que existe -- solo se obtiene prestando algo vivo --,
     * asi que no puede ser nulo.  Un `T*` crudo SI puede: ahi `Some(nulo)` y
     * "no hay nada" serian el mismo valor, y un programa que guarda un puntero
     * nulo a proposito dejaria de distinguirlos.  Por eso no entra.
     *
     * El resto del camino -- construir, leer, `match`, y el tamano de un struct
     * que lo lleve de campo -- no hay que tocarlo: pregunta. */
    const bool payload_no_puede_ser_nulo =
        t.pointee && (t.pointee->kind == PrimitiveKind::BORROW ||
                      t.pointee->kind == PrimitiveKind::BORROW_MUT);
    if (payload_no_puede_ser_nulo) {
        lay.has_tag = false;
        lay.value_offset = 0;
        lay.bytes = 8;
        return lay;
    }
    lay.has_tag = true;
    lay.value_offset = 8;
    lay.bytes = 8 + payload;
    return lay;
}

bool TypeChecker::type_derives_from(const std::string &sub,
                                    const std::string &super) const noexcept {
    if (sub.empty() || super.empty()) return false;
    if (sub == super) return true;

    /* Se sube en anchura por las DOS vias -- superclase e interfaces -- porque
     * el padre de una interfaz vive en la primera y el de una clase que cumple
     * interfaces en la segunda.  Antes se subia solo por la lista de
     * interfaces, con un nivel de transitividad escrito a mano que miraba
     * donde el dato no esta: la transitividad no funcionaba ni un nivel. */
    std::vector<std::string> nivel{sub};
    std::vector<std::string> siguiente;
    // Cota dura por si la jerarquia estuviera corrupta.
    for (int depth = 0; !nivel.empty() && depth < 256; ++depth) {
        siguiente.clear();
        for (const std::string &n : nivel) {
            const auto it = class_layouts_.find(n);
            if (it == class_layouts_.end()) continue;
            const ClassLayout &cl = it->second;
            if (cl.super_name == super) return true;
            if (!cl.super_name.empty()) siguiente.push_back(cl.super_name);
            for (const std::string &iname : cl.interface_names) {
                if (iname == super) return true;
                siguiente.push_back(iname);
            }
        }
        nivel.swap(siguiente);
    }
    return false;
}

// ----- Pre-pase de monomorphizacion generics) ---------------
//
// Recorre el AST detectando referencias a clases con type_args (en
// tipos de var-decl, params, returns, fields, news) y genera los
// ClassDecls concretos por monomorphizacion antes de que
// collect_globals los necesite.  Tambien identifica los templates y
// los registra en generic_templates_ para skip-check.
//
// El recorrido es tolerante: si encuentra un tipo cuyo template no
// existe (puede ser una clase concreta no-generica), simplemente lo
// ignora.  Errores se reportan despues por type_from_node.
// ----------------------------------------------------------------
static void pre_mono_collect_in_type(TypeChecker &tc, const ast::TypeNode *t,
                                     const SourceLoc &loc);
static void pre_mono_collect_in_expr(TypeChecker &tc, const ast::Expr *e);
static void pre_mono_collect_in_stmt(TypeChecker &tc, const ast::Stmt *s);

static void pre_mono_collect_in_type(TypeChecker &tc, const ast::TypeNode *t,
                                     const SourceLoc &loc) {
    if (!t) return;
    if (t->kind == ast::NodeKind::NamedTypeNode) {
        const auto *nt = static_cast<const ast::NamedTypeNode *>(t);
        // Optional<T> y Result<V,E> son builtins del compilador,
        // NO templates de usuario: no se monomorphizan.  Se ignoran
        // aqui; type_from_node los resuelve a Type{OPTIONAL/RESULT}.
        // Pero SI necesitamos recursar en los args para detectar
        // templates de usuario anidados (Optional<MyTpl<i32>>).
        if (nt->name == "Optional" || nt->name == "Result" ||
            nt->name == "Future") {
            // Mejora II: Future<T> es builtin igual que Optional/Result.
            for (auto &ta : nt->type_args) {
                pre_mono_collect_in_type(tc, ta.get(), loc);
            }
            return;
        }
        if (!nt->type_args.empty()) {
            // BugFix P1-A4: monomorphizar args ANIDADOS primero, para
            // que cuando resolvamos el outer (`Container<Pair<i32,i64>>`),
            // el Type::struct_name del inner ya sea "Pair_i32_i64".
            // Sin esto, resolve_type_node devolvia COUNT para Pair<...>
            // y la mangle quedaba mal.
            for (auto &ta : nt->type_args) {
                pre_mono_collect_in_type(tc, ta.get(), loc);
            }
            std::vector<Type> args;
            args.reserve(nt->type_args.size());
            for (auto &ta : nt->type_args) {
                args.push_back(tc.resolve_type_node(ta.get()));
            }
            // Despachar por categoria del template: enum, struct o clase.
            if (tc.is_generic_enum_template(nt->name)) {
                (void)tc.monomorphize_enum(nt->name, args, loc);
            } else if (tc.is_generic_struct_template(nt->name)) {
                (void)tc.monomorphize_struct(nt->name, args, loc);
            } else {
                (void)tc.monomorphize_class(nt->name, args, loc);
            }
        }
    } else if (t->kind == ast::NodeKind::PointerTypeNode) {
        const auto *pn = static_cast<const ast::PointerTypeNode *>(t);
        pre_mono_collect_in_type(tc, pn->pointee.get(), loc);
    } else if (t->kind == ast::NodeKind::ArrayTypeNode) {
        const auto *an = static_cast<const ast::ArrayTypeNode *>(t);
        pre_mono_collect_in_type(tc, an->element_type.get(), loc);
    }
}

static void pre_mono_collect_in_expr(TypeChecker &tc, const ast::Expr *e) {
    if (!e) return;
    switch (e->kind) {
    case ast::NodeKind::NewExpr: {
        auto *ne = static_cast<const ast::NewExpr *>(e);
        // BugFix R5: Optional/Result/Future son builtins NO
        // templates de usuario.  Skipear monomorphize_class para
        // ellos; check_new tiene su propio handling.  Recursamos
        // en type_args para detectar templates anidados.
        if (ne->class_name == "Optional" || ne->class_name == "Result" ||
            ne->class_name == "Future") {
            for (auto &ta : ne->type_args) {
                pre_mono_collect_in_type(tc, ta.get(), ne->loc);
            }
            for (auto &a : ne->args)
                pre_mono_collect_in_expr(tc, a.get());
            return;
        }
        if (!ne->type_args.empty()) {
            // BugFix P1-A4: monomorphizar args ANIDADOS primero,
            // identical fix que para NamedTypeNode.  Sin esto
            // `new Container<Pair<i32,i64>>(...)` no monomorphiza
            // Container_Pair_i32_i64 porque resolve_type_node de
            // Pair<...> devuelve COUNT.
            for (auto &ta : ne->type_args) {
                pre_mono_collect_in_type(tc, ta.get(), ne->loc);
            }
            std::vector<Type> args;
            args.reserve(ne->type_args.size());
            for (auto &ta : ne->type_args) {
                args.push_back(tc.resolve_type_node(ta.get()));
            }
            (void)tc.monomorphize_class(ne->class_name, args, ne->loc);
        }
        for (auto &a : ne->args)
            pre_mono_collect_in_expr(tc, a.get());
        return;
    }
    case ast::NodeKind::BinaryExpr: {
        auto *b = static_cast<const ast::BinaryExpr *>(e);
        pre_mono_collect_in_expr(tc, b->lhs.get());
        pre_mono_collect_in_expr(tc, b->rhs.get());
        return;
    }
    case ast::NodeKind::UnaryExpr: {
        auto *u = static_cast<const ast::UnaryExpr *>(e);
        pre_mono_collect_in_expr(tc, u->operand.get());
        return;
    }
    case ast::NodeKind::CastExpr: {
        auto *c = static_cast<const ast::CastExpr *>(e);
        if (c->target_type) {
            pre_mono_collect_in_type(tc, c->target_type.get(), c->loc);
        }
        pre_mono_collect_in_expr(tc, c->operand.get());
        return;
    }
    case ast::NodeKind::AssignExpr: {
        auto *a = static_cast<const ast::AssignExpr *>(e);
        pre_mono_collect_in_expr(tc, a->target.get());
        pre_mono_collect_in_expr(tc, a->value.get());
        return;
    }
    case ast::NodeKind::CallExpr: {
        auto *c = static_cast<const ast::CallExpr *>(e);
        pre_mono_collect_in_expr(tc, c->callee.get());
        // Type-args de la llamada (builtins de introspeccion comptime como
        // `sizeof<Box<i64>>()`, `field_name<Par<i32,i64>>(1)`, `offsetof<..>`):
        // disparan la monomorphizacion del tipo generico aunque no se declare
        // ninguna variable de ese tipo.  Sin esto la introspeccion resolveria
        // el tipo a void.
        for (auto &ta : c->type_args)
            pre_mono_collect_in_type(tc, ta.get(), c->loc);
        // Llamada a FUNCION generica con args de tipo explicitos
        // (`id<i64>(42)`): monomorphizar la funcion aqui (en pre_mono, antes de
        // collect_globals, para que su firma se registre).  La inferencia desde
        // los argumentos sin `<...>` se resuelve en check_call.
        if (!c->type_args.empty() && c->callee &&
            c->callee->kind == ast::NodeKind::IdentExpr) {
            auto *cid = static_cast<const ast::IdentExpr *>(c->callee.get());
            // Una plantilla importada se ve por su nombre corto; el registro
            // esta bajo su label.
            const std::string &tpl_name = tc.resolve_generic_fn_name(cid->name);
            if (tc.is_generic_fn_template(tpl_name)) {
                std::vector<Type> targs;
                targs.reserve(c->type_args.size());
                for (auto &ta : c->type_args)
                    targs.push_back(tc.resolve_type_node(ta.get()));
                (void)tc.monomorphize_function(tpl_name, targs, c->loc);
            }
        }
        for (auto &a : c->args)
            pre_mono_collect_in_expr(tc, a.get());
        return;
    }
    case ast::NodeKind::FieldAccessExpr: {
        auto *f = static_cast<const ast::FieldAccessExpr *>(e);
        pre_mono_collect_in_expr(tc, f->base.get());
        return;
    }
    case ast::NodeKind::IndexExpr: {
        auto *i = static_cast<const ast::IndexExpr *>(e);
        pre_mono_collect_in_expr(tc, i->base.get());
        pre_mono_collect_in_expr(tc, i->index.get());
        return;
    }
    default: return;
    }
}

static void pre_mono_collect_in_stmt(TypeChecker &tc, const ast::Stmt *s) {
    if (!s) return;
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        auto *b = static_cast<const ast::BlockStmt *>(s);
        for (auto &st : b->body)
            pre_mono_collect_in_stmt(tc, st.get());
        return;
    }
    case ast::NodeKind::VarDeclStmt: {
        auto *v = static_cast<const ast::VarDeclStmt *>(s);
        pre_mono_collect_in_type(tc, v->type.get(), v->loc);
        if (v->init) pre_mono_collect_in_expr(tc, v->init.get());
        return;
    }
    case ast::NodeKind::ExprStmt: {
        auto *e = static_cast<const ast::ExprStmt *>(s);
        pre_mono_collect_in_expr(tc, e->expr.get());
        return;
    }
    case ast::NodeKind::IfStmt: {
        auto *i = static_cast<const ast::IfStmt *>(s);
        pre_mono_collect_in_expr(tc, i->cond.get());
        pre_mono_collect_in_stmt(tc, i->then_branch.get());
        pre_mono_collect_in_stmt(tc, i->else_branch.get());
        return;
    }
    case ast::NodeKind::WhileStmt: {
        auto *w = static_cast<const ast::WhileStmt *>(s);
        pre_mono_collect_in_expr(tc, w->cond.get());
        pre_mono_collect_in_stmt(tc, w->body.get());
        return;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *r = static_cast<const ast::ReturnStmt *>(s);
        if (r->value) pre_mono_collect_in_expr(tc, r->value.get());
        return;
    }
    case ast::NodeKind::ForStmt: {
        auto *f = static_cast<const ast::ForStmt *>(s);
        pre_mono_collect_in_stmt(tc, f->init.get());
        pre_mono_collect_in_expr(tc, f->cond.get());
        pre_mono_collect_in_expr(tc, f->step.get());
        pre_mono_collect_in_stmt(tc, f->body.get());
        return;
    }
    case ast::NodeKind::ThrowStmt: {
        auto *t = static_cast<const ast::ThrowStmt *>(s);
        pre_mono_collect_in_expr(tc, t->value.get());
        return;
    }
    case ast::NodeKind::TryStmt: {
        auto *t = static_cast<const ast::TryStmt *>(s);
        pre_mono_collect_in_stmt(tc, t->body.get());
        for (auto &cc : t->catches)
            pre_mono_collect_in_stmt(tc, cc.body.get());
        pre_mono_collect_in_stmt(tc, t->finally_body.get());
        return;
    }
    case ast::NodeKind::SynchronizedStmt: {
        auto *ss = static_cast<const ast::SynchronizedStmt *>(s);
        pre_mono_collect_in_expr(tc, ss->target.get());
        pre_mono_collect_in_stmt(tc, ss->body.get());
        return;
    }
    default: return;
    }
}

void TypeChecker::apply_class_field_defaults_to_ctors() {
    // Construye un statement `this.<campo> = <default>;`.
    auto make_field_init_stmt =
        [](const std::string &fname, const ast::Expr *init,
           SourceLoc loc) -> std::unique_ptr<ast::Stmt> {
        GenSubst empty; // clon literal (sin sustitucion de tipos).
        auto this_e = std::make_unique<ast::ThisExpr>();
        this_e->loc = loc;
        auto fa = std::make_unique<ast::FieldAccessExpr>();
        fa->loc = loc;
        fa->base = std::move(this_e);
        fa->field_name = fname;
        auto assign = std::make_unique<ast::AssignExpr>();
        assign->loc = loc;
        assign->op = ast::AssignOp::Assign;
        assign->target = std::move(fa);
        assign->value = clone_expr(init, empty);
        auto stmt = std::make_unique<ast::ExprStmt>();
        stmt->loc = loc;
        stmt->expr = std::move(assign);
        return stmt;
    };

    // Procesa un vector de decls (recursivo para NamespaceDecl).
    std::function<void(std::vector<std::unique_ptr<ast::Node>> &)> visit =
        [&](std::vector<std::unique_ptr<ast::Node>> &decls) {
            for (auto &d : decls) {
                if (!d) continue;
                if (d->kind == ast::NodeKind::NamespaceDecl) {
                    visit(static_cast<ast::NamespaceDecl *>(d.get())->decls);
                    continue;
                }
                if (d->kind != ast::NodeKind::ClassDecl) continue;
                auto *cd = static_cast<ast::ClassDecl *>(d.get());
                if (cd->is_interface) continue;
                // Campos de instancia PROPIOS con default (en orden de decl).
                std::vector<const ast::ClassFieldDecl *> defs;
                for (const auto &f : cd->fields) {
                    if (f.is_static || !f.init) continue;
                    defs.push_back(&f);
                }
                if (defs.empty()) continue;

                // Localizar los constructores propios de la clase.
                std::vector<ast::ClassMethodDecl *> ctors;
                for (auto &m : cd->methods) {
                    if (m && m->is_constructor) ctors.push_back(m.get());
                }
                // Sin constructor declarado: sintetizar uno vacio para tener
                // donde aplicar los defaults (equivalente al ctor por defecto).
                if (ctors.empty()) {
                    auto ctor = std::make_unique<ast::ClassMethodDecl>();
                    ctor->loc = cd->loc;
                    ctor->name = cd->name;
                    ctor->is_constructor = true;
                    ctor->access = 0; // public
                    ctor->body = std::make_unique<ast::BlockStmt>();
                    ctor->body->loc = cd->loc;
                    ctors.push_back(ctor.get());
                    cd->methods.push_back(std::move(ctor));
                }

                for (auto *ctor : ctors) {
                    if (!ctor->body)
                        ctor->body = std::make_unique<ast::BlockStmt>();
                    auto &stmts = ctor->body->body;
                    // Los field-init corren tras un super()/this() inicial (que
                    // debe ir primero); si no lo hay, al inicio del cuerpo.
                    size_t pos = 0;
                    if (!stmts.empty() &&
                        stmts[0]->kind == ast::NodeKind::ExprStmt) {
                        auto *es = static_cast<ast::ExprStmt *>(stmts[0].get());
                        if (es->expr &&
                            es->expr->kind == ast::NodeKind::SuperCallExpr)
                            pos = 1; // super() debe ir primero.
                    }
                    std::vector<std::unique_ptr<ast::Stmt>> inits;
                    inits.reserve(defs.size());
                    for (const auto *f : defs)
                        inits.push_back(make_field_init_stmt(
                            f->name, f->init.get(), f->loc));
                    stmts.insert(stmts.begin() + pos,
                                 std::make_move_iterator(inits.begin()),
                                 std::make_move_iterator(inits.end()));
                }
            }
        };
    visit(mod_.decls);
}

/// Resuelve los @complexity de un metodo que NO es de una plantilla generica.
///
/// El parser los deja todos sin resolver a proposito: hay que verlos juntos
/// para aplicar la prioridad por especificidad.  Los de una instanciacion los
/// resuelve el clon (con T); estos no tienen T, asi que todos sus atomos deben
/// ser de target -- uno que hable de un parametro de tipo aqui no tiene a que
/// referirse, y se dice.
namespace {
/// Resuelve los @complexity pendientes de CUALQUIER declaracion sin type
/// params (funcion libre o metodo no generico): todos sus atomos deben ser de
/// target -- aqui no hay T al que referirse.  Template porque FunctionDecl y
/// ClassMethodDecl tienen los mismos campos de @complexity y no queria dos
/// copias de esto.  Aplica la REGLA DE PRIORIDAD (cwhen::resolve): sin ella
/// ganaba el ultimo textualmente, tambien en las funciones libres.
template <class Decl> void resolve_cx_sin_tipos(Decl &m, Diagnostics &diags) {
    if (m.complexity_pending.empty()) return;
    static const vxgen::GenSubst kSinTipos{};
    cwhen::AtomEval ev = [&](const std::string &at, bool &ok) {
        if (cwhen::atom_kind(at) == cwhen::AtomKind::TIPO) {
            ok = false;
            return false;
        }
        return when_atomo_(at, kSinTipos, ok);
    };
    cwhen::ErrFn err = [&](const std::string &msg) { diags.error(m.loc, msg); };
    cwhen::Resolved r;
    cwhen::resolve(m.complexity_pending, ev, err, r);
    m.complexity_expr = std::move(r.expr);
    m.complexity_vars = std::move(r.vars);
    m.complexity_partial_pre = std::move(r.partial_pre);
    m.complexity_partial_post = std::move(r.partial_post);
    m.complexity_total_pre = std::move(r.total_pre);
    m.complexity_total_post = std::move(r.total_post);
    m.complexity_pending.clear();
}

/// Igual, pero para los contratos de HUELLA con `when:`.  El default son los
/// campos directos (los declarados SIN when); un `when:` que casa gana sobre
/// ellos por ser mas especifico.
template <class Decl> void resolve_fp_sin_tipos(Decl &m, Diagnostics &diags) {
    if (m.footprint_pending.empty()) return;
    static const vxgen::GenSubst kSinTipos{};
    cwhen::AtomEval ev = [&](const std::string &at, bool &ok) {
        if (cwhen::atom_kind(at) == cwhen::AtomKind::TIPO) {
            ok = false;
            return false;
        }
        return when_atomo_(at, kSinTipos, ok);
    };
    cwhen::ErrFn err = [&](const std::string &msg) { diags.error(m.loc, msg); };
    cwhen::ResolvedFP base;
    base.pure = m.contract_pure ? 1 : -1;
    base.nothrow_ = m.contract_nothrow ? 1 : -1;
    base.nopanic = m.contract_nopanic ? 1 : -1;
    base.alloc = m.contract_alloc;
    base.alloc_partial = m.contract_alloc_partial;
    base.stack = m.contract_stack;
    base.stack_partial = m.contract_stack_partial;
    cwhen::ResolvedFP r;
    cwhen::resolve_footprint(m.footprint_pending, base, ev, err, r);
    m.contract_pure = (r.pure == 1);
    m.contract_nothrow = (r.nothrow_ == 1);
    m.contract_nopanic = (r.nopanic == 1);
    m.contract_alloc = r.alloc;
    m.contract_alloc_partial = r.alloc_partial;
    m.contract_stack = r.stack;
    m.contract_stack_partial = r.stack_partial;
    m.footprint_pending.clear();
}
} // namespace

void TypeChecker::resolve_complexity_no_generico_(ast::ClassMethodDecl &m) {
    resolve_cx_sin_tipos(m, diags_);
}

/// Recorre las decls resolviendo los @complexity que queden pendientes.
///
/// Las instanciaciones genericas ya vienen resueltas del clon (que es quien
/// tiene T) y llegan con la lista vacia; esto cubre el resto (funciones libres
/// incluidas: sin este pase, la regla de prioridad no las tocaba y ganaba el
/// ultimo textualmente).  Las PLANTILLAS se saltan: no producen IR, y sus
/// `when:` sobre T no tienen respuesta aqui.
void TypeChecker::resolve_complexity_decls_(
    std::vector<std::unique_ptr<ast::Node>> &decls) {
    for (auto &d : decls) {
        if (!d) continue;
        if (d->kind == ast::NodeKind::NamespaceDecl) {
            resolve_complexity_decls_(
                static_cast<ast::NamespaceDecl *>(d.get())->decls);
            continue;
        }
        if (d->kind == ast::NodeKind::FunctionDecl) {
            auto *fd = static_cast<ast::FunctionDecl *>(d.get());
            resolve_cx_sin_tipos(*fd, diags_);
            resolve_fp_sin_tipos(*fd, diags_);
        } else if (d->kind == ast::NodeKind::StructDecl) {
            auto *sd = static_cast<ast::StructDecl *>(d.get());
            if (!sd->type_params.empty() || sd->is_specialization) continue;
            for (auto &m : sd->methods)
                if (m) {
                    resolve_cx_sin_tipos(*m, diags_);
                    resolve_fp_sin_tipos(*m, diags_);
                }
        } else if (d->kind == ast::NodeKind::ClassDecl) {
            auto *cd = static_cast<ast::ClassDecl *>(d.get());
            if (!cd->type_params.empty()) continue;
            for (auto &m : cd->methods)
                if (m) {
                    resolve_cx_sin_tipos(*m, diags_);
                    resolve_fp_sin_tipos(*m, diags_);
                }
        }
    }
}

bool TypeChecker::run() {
    initial_errors_ = diags_.error_count();
    push_scope(); // global

    //  M.2.e: drenar la cola de funciones importadas via .vxi.
    // Cada entrada se declara en el scope global como Symbol::Function
    // con su sig_index ya asignado, igual que los builtins.
    for (const auto &pf : pending_imported_fn_names_) {
        Symbol s;
        s.kind = SymbolKind::Function;
        s.sig_index = pf.second;
        (void)declare(pf.first, s);
    }
    pending_imported_fn_names_.clear();

    //  M.L7: drenar la cola de globals importadas.  Cada entry
    // se declara en el scope global como Symbol::Variable con su
    // tipo resuelto + flag is_const propagado del .vxi.  Si la
    // global es const + trae init_value, ademas se guarda en la
    // tabla @c imported_global_consts_ que el lowering consulta
    // para inline-ar el literal en cada uso.
    for (auto &pg : pending_imported_globals_) {
        Symbol s;
        s.kind = SymbolKind::Variable;
        s.type = pg.type;
        s.is_const = pg.is_const;
        (void)declare(pg.name, s);
        if (pg.is_const && pg.has_init_value) {
            ImportedGlobalConst ic;
            ic.type = pg.type;
            ic.value = pg.init_value;
            imported_global_consts_.emplace(pg.name, std::move(ic));
        }
        // v4: comptime const string cross-module.  Guardamos los
        // bytes para que @c lower_ident pueda materializar el
        // StringObject via STRMAKE al primer uso.
        if (pg.is_str) {
            ImportedGlobalConst ic;
            ic.type = pg.type;
            ic.is_str = true;
            ic.str_value = std::move(pg.str_value);
            imported_global_consts_.emplace(pg.name, std::move(ic));
        }
        // El que no se inlinea (mutable, o const sin valor de compile time
        // como un `const string` que construye el `__module_init` del dep)
        // tiene STORAGE: se comparte por `shared_key` con el modulo que lo
        // define.  Sin esto el lowering no encontraba el nombre y el uso moria
        // con "nombre no resuelto", que ni siquiera senalaba al global.
        const bool inlinable = (pg.is_const && pg.has_init_value) || pg.is_str;
        if (!inlinable && !pg.mangled_label.empty()) {
            ImportedGlobalStorage gs;
            gs.type = pg.type;
            gs.mangled_label = pg.mangled_label;
            imported_global_storage_.emplace(pg.name, std::move(gs));
        }
    }
    pending_imported_globals_.clear();

    //  M.7: drenar la cola de namespaces.  Cada `import "x";`
    // o `import "x" as alias;` registro un namespace; aqui los
    // declaramos como Symbol::Namespace en el scope global para
    // que `lib_a.simbolo` se resuelva via check_field_access.
    for (const auto &pn : pending_imported_ns_names_) {
        // NS short-form: un ultimo segmento que resulto AMBIGUO (2+ namespaces)
        // no se declara como Symbol::Namespace -> forzar el path completo.
        if (ns_short_ambiguous_.count(pn.first) &&
            ns_idx_by_local_name_.find(pn.first) == ns_idx_by_local_name_.end())
            continue;
        Symbol s;
        s.kind = SymbolKind::Namespace;
        s.ns_index = pn.second;
        (void)declare(pn.first, s);
    }
    pending_imported_ns_names_.clear();

    //  M6.a L.3: pre-pase de visibilidad para fns/globals/typedefs.
    // Las layouts struct/class/enum se setean en su procesado main
    // (que sobreescribe la entry pre-registrada con un layout fresco).
    for (const auto &decl : mod_.decls) {
        if (!decl) continue;
        switch (decl->kind) {
        case ast::NodeKind::FunctionDecl: {
            auto *fd = static_cast<const ast::FunctionDecl *>(decl.get());
            function_is_public_[fd->name] = fd->is_public;
            if (fd->is_internal) function_is_internal_.insert(fd->name);
            break;
        }
        case ast::NodeKind::GlobalVarDecl: {
            auto *gd = static_cast<const ast::GlobalVarDecl *>(decl.get());
            global_is_public_[gd->name] = gd->is_public;
            if (gd->is_internal) global_is_internal_.insert(gd->name);
            break;
        }
        case ast::NodeKind::TypeAliasDecl: {
            auto *td = static_cast<const ast::TypeAliasDecl *>(decl.get());
            typedef_is_public_[td->name] = td->is_public;
            break;
        }
        default: break;
        }
    }

    /* si la flag de prebuilt esta seteada, intentamos
     * cargar el `.velb` cacheado en el @c comptime_runtime_ ANTES de
     * type-checar.  Esto permite que la rama @Macro VM-only (mas
     * abajo) tenga bytecode disponible al encontrar el primer call
     * site.  Cero impacto si la flag no esta o el archivo no existe
     * (la rama VM cae a AST eval). */
    {
        /* Primero, el que llega YA EN MEMORIA.  Se construye una vez, antes de
         * compilar ningun modulo, y lo comparten todos: ni se relee el fichero
         * por modulo ni hace falta que exista fichero.  La via por variable de
         * entorno se conserva detras, que es como entra cuando quien orquesta
         * es otro proceso. */
        bool en_memoria_sirvio = false;
        if (comptime_artifact_ != nullptr && !comptime_artifact_->empty()) {
            std::vector<uint8_t> copia = *comptime_artifact_;
            if (comptime_runtime_.load_macros_from_bytes(std::move(copia))) {
                /* Solo cuenta si trae ALGO.  Un artefacto que carga pero no
                 * registra ni un macro no sirve, y preferirlo tapaba al bueno
                 * que llega por la otra via: el modulo se compilaba sin poder
                 * ejecutar nada al compilar, y lo que dependia de eso salia con
                 * valores de relleno. */
                en_memoria_sirvio =
                    comptime_runtime_.registered_macro_count() > 0;
                if (en_memoria_sirvio &&
                    util::flag_on(util::FlagId::McVerbose)) {
                    std::cerr << "[mc-prebuilt] en memoria ("
                              << comptime_runtime_.registered_macro_count()
                              << " macros registrados)\n";
                }
            }
        }
        if (!en_memoria_sirvio) {
            const std::string &pre = util::flag_text(util::FlagId::McPrebuilt);
            if (!pre.empty()) {
                std::ifstream f(pre, std::ios::binary);
                if (f) {
                    std::vector<uint8_t> bytes(
                        (std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
                    if (!bytes.empty() &&
                        comptime_runtime_.load_macros_from_bytes(
                            std::move(bytes)) &&
                        util::flag_on(util::FlagId::McVerbose)) {
                        std::cerr << "[mc-prebuilt] cargado: " << pre << " ("
                                  << comptime_runtime_.registered_macro_count()
                                  << " macros registrados)\n";
                    }
                }
            }
        }
    }

    // -------- Sprint lombok (2026-06-03): expansion de anotaciones Lombok.
    // Antes de procesar templates / collect / check, recorremos cada
    // ClassDecl y generamos los ClassMethodDecls sinteticos que las
    // anotaciones Lombok piden.  Esto es un AST rewrite puro: tras el
    // pre-pase el AST se ve como si el usuario hubiera escrito los
    // metodos a mano, asi que el resto del pipeline funciona sin
    // cambios.  Implementa: @Getter, @Setter, @ToString,
    // @EqualsAndHashCode, @NoArgsConstructor, @AllArgsConstructor,
    // @RequiredArgsConstructor, @With (en field), @Data, @Value,
    // @Builder, @Synchronized, @Log.  @NonNull se traduce a la
    // sintaxis `nonnull T` del lenguaje (validacion compile-time).
    expand_lombok_annotations();

    // Inyectar los valores por defecto de campos de instancia en los
    // constructores (antes de monomorphizar: los templates los propagan a sus
    // instanciaciones al clonar los cuerpos).
    apply_class_field_defaults_to_ctors();

    // -------- registrar templates + monomorphizar.
    // Primero localizamos todas las clases con type_params y las
    // marcamos como templates (no se procesaran como concretas).
    for (size_t i = 0; i < mod_.decls.size(); ++i) {
        auto *d = mod_.decls[i].get();
        if (d && d->kind == ast::NodeKind::ClassDecl) {
            auto *cd = static_cast<ast::ClassDecl *>(d);
            if (cd->is_specialization) {
                // #7: especializacion (total/parcial) de una clase generica.
                class_specializations_[cd->name].push_back(i);
            } else if (!cd->type_params.empty()) {
                generic_templates_[cd->name] = i;
            }
        } else if (d && d->kind == ast::NodeKind::EnumDecl) {
            // L2.3: enums genericos como templates.
            auto *en = static_cast<ast::EnumDecl *>(d);
            if (!en->type_params.empty()) {
                generic_enum_templates_[en->name] = i;
            }
        } else if (d && d->kind == ast::NodeKind::StructDecl) {
            // structs genericos como templates.
            auto *sd = static_cast<ast::StructDecl *>(d);
            if (sd->is_specialization) {
                // #7: especializacion (total/parcial) de un struct generico.
                struct_specializations_[sd->name].push_back(i);
            } else if (!sd->type_params.empty()) {
                generic_struct_templates_[sd->name] = i;
            }
        } else if (d && d->kind == ast::NodeKind::FunctionDecl) {
            // funciones genericas RUNTIME como templates.  Las comptime fns
            // genericas (`comptime <T> ...`) y los @Macro tienen su propio
            // manejo (evaluacion comptime), no se monomorphizan a runtime.
            auto *fd = static_cast<ast::FunctionDecl *>(d);
            if (fd->is_specialization && !fd->is_macro) {
                // #7: especializacion (total/parcial) de una funcion generica.
                function_specializations_[fd->name].push_back(i);
            } else if (!fd->type_params.empty() && !fd->is_macro) {
                // Templates genericos RUNTIME y COMPTIME.  Las comptime fns
                // genericas se monomorfizan igual (la instancia concreta se
                // rutea a la ComptimeVM: su introspeccion `sizeof<Vec3>` se
                // pliega a constante al bajarla).  Los @Macro conservan su
                // propio path de invocacion.
                generic_fn_templates_[fd->name] = i;
            }
        } else if (d && d->kind == ast::NodeKind::ConceptDecl) {
            // #6: registrar conceptos de usuario para la evaluacion de
            // bounds + composicion en predicados comptime.
            auto *cn = static_cast<ast::ConceptDecl *>(d);
            concepts_[cn->name] = cn;
        }
    }
    // Pre-registro de NOMBRES de tipos de usuario (struct/clase/enum concretos)
    // como layouts vacios ANTES de la monomorphizacion.  Sin esto, un type-arg
    // de usuario (`Caja<Punto>`) se resuelve a void durante pre_mono porque su
    // layout aun no existe -> mangling roto (`Caja_x`) + campo invalido.  Con
    // el nombre registrado, resolve_type_node devuelve Type{STRUCT/CLASS,
    // "Punto"} correcto.  collect_globals construye el layout real luego
    // (sobreescribe).
    for (size_t i = 0; i < mod_.decls.size(); ++i) {
        auto *d = mod_.decls[i].get();
        if (!d) continue;
        if (d->kind == ast::NodeKind::StructDecl) {
            auto *sd = static_cast<ast::StructDecl *>(d);
            // Templates (type_params) y especializaciones (#7) NO son
            // structs concretos: se clonan on-demand en monomorphize_struct.
            if (!sd->type_params.empty() || sd->is_specialization) continue;
            if (!struct_layouts_.count(sd->name)) {
                StructLayout empty;
                empty.name = sd->name;
                empty.is_introspect = sd->is_introspect;
                struct_layouts_.emplace(sd->name, std::move(empty));
            }
        } else if (d->kind == ast::NodeKind::ClassDecl) {
            auto *cd = static_cast<ast::ClassDecl *>(d);
            // Templates (type_params) y especializaciones (#7) no son clases
            // concretas: se clonan on-demand en monomorphize_class.
            if (!cd->type_params.empty() || cd->is_specialization) continue;
            if (!class_layouts_.count(cd->name)) {
                ClassLayout empty;
                empty.name = cd->name;
                empty.is_interface = cd->is_interface;
                class_layouts_.emplace(cd->name, std::move(empty));
            }
        } else if (d->kind == ast::NodeKind::EnumDecl) {
            auto *en = static_cast<ast::EnumDecl *>(d);
            if (!en->type_params.empty()) continue; // template
            if (!enum_layouts_.count(en->name)) {
                EnumLayout empty;
                empty.name = en->name;
                empty.is_introspect = en->is_introspect;
                enum_layouts_.emplace(en->name, std::move(empty));
            }
        }
    }
    // Pre-registro de los typedef/using PLANOS (no-newtype) ANTES del walk de
    // pre_mono.  Sin esto, un type-arg que es un alias (`Caja<Edad>` con
    // `typedef i64 Edad`) se resuelve a void durante la monomorphizacion
    // (type_aliases_ se llena en collect_globals, DESPUES) -> mangling roto
    // (`Caja_x`).  Los newtypes (con nominal_id, conversiones) los maneja
    // collect_globals (mas complejo + raro como type-arg); aqui solo los
    // alias simples.  collect_globals tolera el re-registro (no re-emplaza).
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::TypeAliasDecl) continue;
        auto *a = static_cast<ast::TypeAliasDecl *>(decl.get());
        if (a->is_newtype) continue; // los maneja collect_globals
        if (type_aliases_.count(a->name)) continue;
        Type resolved = type_from_node(a->aliased.get());
        // Solo registrar si resolvio a algo concreto (primitivo o tipo de
        // usuario ya pre-registrado como nombre).  Si no, lo deja a
        // collect_globals (que emite el error si procede).
        if (resolved.kind != PrimitiveKind::COUNT &&
            !(resolved.kind == PrimitiveKind::VOID && a->aliased &&
              a->aliased->kind == ast::NodeKind::NamedTypeNode)) {
            type_aliases_.emplace(a->name, std::move(resolved));
        }
    }
    // Snapshot del numero de decls antes de monomorphizar (las
    // monomorphizaciones nuevas se anyaden al final).  Recorremos
    // SOLO los decls originales para evitar revisitar lo nuevo.
    const size_t orig_decls = mod_.decls.size();
    for (size_t i = 0; i < orig_decls; ++i) {
        auto *d = mod_.decls[i].get();
        if (!d) continue;
        if (d->kind == ast::NodeKind::ClassDecl) {
            auto *cd = static_cast<ast::ClassDecl *>(d);
            // Templates (type_params) y especializaciones (#7) no son clases
            // concretas: se clonan on-demand en monomorphize_class.
            if (!cd->type_params.empty() || cd->is_specialization) continue;
            for (const auto &f : cd->fields) {
                pre_mono_collect_in_type(*this, f.type.get(), f.loc);
            }
            for (const auto &m : cd->methods) {
                if (m->return_type)
                    pre_mono_collect_in_type(*this, m->return_type.get(),
                                             m->loc);
                for (const auto &p : m->params)
                    pre_mono_collect_in_type(*this, p->type.get(), p->loc);
                if (m->body) pre_mono_collect_in_stmt(*this, m->body.get());
            }
        } else if (d->kind == ast::NodeKind::FunctionDecl) {
            auto *fn = static_cast<ast::FunctionDecl *>(d);
            // Templates y especializaciones (#7) no son funciones concretas.
            if (!fn->type_params.empty() || fn->is_specialization)
                continue; // template generico
            if (fn->return_type)
                pre_mono_collect_in_type(*this, fn->return_type.get(), fn->loc);
            for (const auto &p : fn->params)
                pre_mono_collect_in_type(*this, p->type.get(), p->loc);
            if (fn->body) pre_mono_collect_in_stmt(*this, fn->body.get());
        } else if (d->kind == ast::NodeKind::GlobalVarDecl) {
            auto *gv = static_cast<ast::GlobalVarDecl *>(d);
            if (gv->type)
                pre_mono_collect_in_type(*this, gv->type.get(), gv->loc);
            if (gv->init) pre_mono_collect_in_expr(*this, gv->init.get());
        } else if (d->kind == ast::NodeKind::StructDecl) {
            // Un struct (no template) puede usar genericos en sus campos o
            // cuerpos de metodo (`Caja<i64>`); dispararlos aqui.
            auto *sd = static_cast<ast::StructDecl *>(d);
            // Templates (type_params) y especializaciones (#7) NO son
            // structs concretos: se clonan on-demand en monomorphize_struct.
            if (!sd->type_params.empty() || sd->is_specialization) continue;
            for (const auto &f : sd->fields) {
                pre_mono_collect_in_type(*this, f.type.get(), f.loc);
            }
            for (const auto &m : sd->methods) {
                if (m->return_type)
                    pre_mono_collect_in_type(*this, m->return_type.get(),
                                             m->loc);
                for (const auto &p : m->params)
                    pre_mono_collect_in_type(*this, p->type.get(), p->loc);
                if (m->body) pre_mono_collect_in_stmt(*this, m->body.get());
            }
        }
    }
    // Las monomorphizaciones recien anadidas pueden a su vez
    // referenciar otros generics: re-pasamos hasta punto fijo (cota
    // razonable para evitar bucles maliciosos).  Cubre clones de clase Y
    // de struct (un struct monomorphizado con un campo `Inner<T>` anidado).
    for (int round = 0; round < 8; ++round) {
        const size_t before = mod_.decls.size();
        for (size_t i = orig_decls; i < before; ++i) {
            auto *d = mod_.decls[i].get();
            if (!d) continue;
            if (d->kind == ast::NodeKind::ClassDecl) {
                auto *cd = static_cast<ast::ClassDecl *>(d);
                for (const auto &f : cd->fields) {
                    pre_mono_collect_in_type(*this, f.type.get(), f.loc);
                }
                for (const auto &m : cd->methods) {
                    if (m->return_type)
                        pre_mono_collect_in_type(*this, m->return_type.get(),
                                                 m->loc);
                    for (const auto &p : m->params)
                        pre_mono_collect_in_type(*this, p->type.get(), p->loc);
                    if (m->body) pre_mono_collect_in_stmt(*this, m->body.get());
                }
            } else if (d->kind == ast::NodeKind::StructDecl) {
                auto *sd = static_cast<ast::StructDecl *>(d);
                for (const auto &f : sd->fields) {
                    pre_mono_collect_in_type(*this, f.type.get(), f.loc);
                }
                for (const auto &m : sd->methods) {
                    if (m->return_type)
                        pre_mono_collect_in_type(*this, m->return_type.get(),
                                                 m->loc);
                    for (const auto &p : m->params)
                        pre_mono_collect_in_type(*this, p->type.get(), p->loc);
                    if (m->body) pre_mono_collect_in_stmt(*this, m->body.get());
                }
            } else if (d->kind == ast::NodeKind::FunctionDecl) {
                auto *fn = static_cast<ast::FunctionDecl *>(d);
                if (!fn->type_params.empty() || fn->is_specialization)
                    continue; // template / especializacion (#7)
                if (fn->return_type)
                    pre_mono_collect_in_type(*this, fn->return_type.get(),
                                             fn->loc);
                for (const auto &p : fn->params)
                    pre_mono_collect_in_type(*this, p->type.get(), p->loc);
                if (fn->body) pre_mono_collect_in_stmt(*this, fn->body.get());
            }
        }
        if (mod_.decls.size() == before) break;
    }

    // Fase 2 de la herencia de structs: aplanar campos+metodos del base en cada
    // derivado y resolver el marcador `Self` -> tipo concreto, ANTES de que
    // collect_globals construya los layouts.  Tras esto no queda ningun `Self`.
    flatten_struct_inheritance();

    collect_globals();

    // #6: ya existen los layouts -> verificar los bounds encolados durante
    // pre_mono (conceptos estructurales / has_method de tipos de usuario los
    // necesitan).  Los bounds de metodos genericos (monomorphizados en
    // check_functions) se verifican al final de check_functions.
    verify_pending_type_bounds();

    // Fase 4b: un struct `: IConcepto` debe satisfacer el concepto (coste cero,
    // comptime).  Se corre con los layouts ya completos (conceptos
    // estructurales inspeccionan struct_layouts_).
    verify_struct_interface_conformance();

    /* LANG.fix-2 pre-pase: inicializar los `comptime const|var`
     * globals con sus inits.  Sin esto, los top-level `comptime { }`
     * blocks no podrian leer ni mutar los globales (no estan en
     * comptime_const_values_ todavia).  El check_functions de mas
     * abajo skipea los globales ya inicializados aqui. */
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::GlobalVarDecl) continue;
        auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
        /* Toda CONSTANTE es comptime por definicion: los globales `const`
         * (ademas de los `comptime`) se evaluan aqui y entran en
         * comptime_const_values_ para que el evaluador comptime los pueda
         * LEER igual que un `comptime` (p.ej. `const N = 5;
         * comptime_to_str(N)`).  Si el init de un `const` NO es comptime-
         * evaluable (depende de runtime), comptime_eval_expr devuelve
         * r.ok=false y se skipea -> el const sigue su ruta runtime normal
         * (collect_globals + lowering).  Un const en comptime_const_values_
         * ademas se inlina en sus usos, asi que si solo se usa en comptime
         * queda muerto y la DCE elimina su slot runtime. */
        if ((!gv->is_comptime && !gv->is_const) || !gv->init) continue;
        const ComptimeEvalResult r = comptime_eval_expr(*this, gv->init.get());
        if (!r.ok) continue; /* check_functions emitira diagnostico */
        ComptimeConst c;
        if (gv->type)
            c.type = type_from_node(gv->type.get());
        else if (r.is_str)
            c.type = Type{PrimitiveKind::STRING};
        else if (r.is_type)
            c.type = Type{PrimitiveKind::TYPE_META};
        else
            c.type = Type{PrimitiveKind::I64};
        c.is_str = r.is_str;
        c.is_array = r.is_array;
        c.is_struct = r.is_struct;
        c.is_type = r.is_type;
        /* Todo global `const` o `comptime` es MUTABLE en compile-time (el
         * codigo comptime lo puede alterar); INMUTABLE en runtime (is_const).
         * Un global puede declararse con cualquiera de las dos palabras y
         * funciona igual: mutable durante la compilacion, congelado al final.
         */
        c.is_mutable = true;
        c.deferred = r.deferred; /* #2: propaga placeholder diferido */
        if (r.is_str)
            c.str_value = r.str;
        else if (r.is_array)
            c.array_vals = r.array_vals;
        else if (r.is_struct)
            c.struct_fields = r.struct_fields;
        else if (r.is_type)
            c.type_val = r.type_val;
        else
            c.value = r.value;
        c.attr_align = gv->attr_align;
        c.attr_hot = gv->attr_hot;
        c.attr_cold = gv->attr_cold;
        c.attr_section = gv->attr_section;
        comptime_const_values_[gv->name] = std::move(c);
    }

    /* LANG.fix-2: ejecutar bloques `comptime { ... }` a nivel modulo.
     * Tras el pre-pase los globales estan en comptime_const_values_;
     * ahora podemos evaluar/mutar via comptime_eval_stmt.  Util
     * para inicializar tablas via loops, validar invariantes con
     * static_assert sobre valores derivados, etc. */
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::ComptimeBlockStmt) continue;
        check_stmt(static_cast<ast::Stmt *>(decl.get()),
                   Type{PrimitiveKind::VOID});
    }

    check_functions();
    pop_scope();

    /* log resumen de hits/misses del path VM-only si el
     * usuario activo verbose.  Util para verificar que el opt-in
     * @c VESTA_MC_VMONLY=1 + @c VESTA_MC_PREBUILT=... efectivamente
     * desvio las invocaciones @Macro al VM. */
    if (macro_vmonly_hits_ > 0 || macro_vmonly_misses_ > 0) {
        if (util::flag_on(util::FlagId::McVerbose)) {
            {
                std::cerr << "[mc-vmonly] hits=" << macro_vmonly_hits_
                          << " misses=" << macro_vmonly_misses_
                          << "  memo_hits="
                          << comptime_runtime_.memo_hit_count()
                          << " memo_misses="
                          << comptime_runtime_.memo_miss_count() << "\n";
            }
        }
    }

    // Los @complexity que queden sin resolver: los de todo lo que no es una
    // instanciacion generica (esas ya las resolvio su clon, que es quien tiene
    // T).  Va al final porque hasta aqui pueden haber aparecido decls nuevas
    // (monomorphizaciones, expansiones de anotaciones...).
    resolve_complexity_decls_(mod_.decls);

    return diags_.error_count() == initial_errors_;
}

void TypeChecker::push_scope() {
    scopes_.emplace_back();
}
void TypeChecker::pop_scope() {
    scopes_.pop_back();
}

bool TypeChecker::declare(const std::string &name, Symbol sym) {
    auto &top = scopes_.back();
    // emplace devuelve {iterator, bool} donde bool=true si se inserto.
    // Si ya existia con ese nombre en el mismo scope, reportamos colision.
    return top.emplace(name, std::move(sym)).second;
}

const Symbol *TypeChecker::lookup(const std::string &name) const {
    // Recorrido inverso para shadowing: scope mas interno tiene prioridad.
    for (auto it = scopes_.rbegin(); it != scopes_.rend(); ++it) {
        auto found = it->find(name);
        if (found != it->end()) return &found->second;
    }
    return nullptr;
}

const FunctionSig *
TypeChecker::function_sig_by_name(const std::string &name) const {
    // fix - usar el mapa @c sig_by_name_ que sobrevive al
    // @c pop_scope() final de @c run().  El @c lookup tradicional
    // falla aqui porque el scope global esta cerrado al llegar el
    // lowering.  function_sigs_ solo crece, nunca se reduce, asi que
    // los indices son estables.
    auto it = sig_by_name_.find(name);
    if (it == sig_by_name_.end()) return nullptr;
    if (it->second >= function_sigs_.size()) return nullptr;
    return &function_sigs_[it->second];
}

std::string
TypeChecker::lookup_extern_qualified(const std::string &name) const {
    const FunctionSig *sig = function_sig_by_name(name);
    if (!sig) return std::string();
    if (sig->extern_lib.empty()) return std::string();
    // Formato: "@extern:<lib>:<fn>" - el cleanup distingue del nombre Vesta.
    return std::string("@extern:") + sig->extern_lib + ":" + name;
}

const Symbol *TypeChecker::lookup_with_depth(const std::string &name,
                                             size_t *depth_out) const {
    // Mismo algoritmo que @c lookup pero devolviendo tambien el indice
    // del scope en la pila para que el analisis de capturas pueda
    // discriminar variables locales (depth >= lambda outer_depth) de
    // variables del entorno exterior (depth < outer_depth).
    for (size_t i = scopes_.size(); i-- > 0;) {
        auto found = scopes_[i].find(name);
        if (found != scopes_[i].end()) {
            if (depth_out) *depth_out = i;
            //  M.L26: registrar el name como referenciado.  Solo
            // los lookups exitosos cuentan (los misses son errores y
            // no significan "uso valido").  El @c compile_vx_project
            // consulta este set tras run() para detectar imports sin
            // usar y emitir warnings.
            referenced_names_.insert(name);
            return &found->second;
        }
    }
    return nullptr;
}

Type TypeChecker::type_from_node(const ast::TypeNode *tn) const {
    Type t = type_from_node_impl(tn);
    // const-correctness A: propagar el const de ESTE nivel.  La recursion sobre
    // pointee/element ya marco los niveles interiores.
    if (tn && tn->is_const) t.is_const = true;
    return t;
}

/**
 * @brief Tipo de un enum registrado, en la representacion que le corresponde.
 *
 * Un `enum` puede ser dos cosas distintas, y cada una tiene la suya:
 *
 *   - CON VALOR (`enum Ordering : i8 { Less = -1 }`): es su entero base
 *     etiquetado con el nombre del enum.  Cabe en un registro y se compara
 *     como un numero.
 *   - DE VARIANTES (con payloads): es un agregado -- tag mas campos -- que
 *     vive en memoria, y por eso comparte @c PrimitiveKind::STRUCT con los
 *     structs.
 *
 * Cual de las dos se usa depende de la DECLARACION del enum, nunca del camino
 * por el que se llegue a resolverlo.  Antes cada ruta construia el tipo por su
 * cuenta y una devolvia siempre el agregado: el mismo enum acababa con dos
 * representaciones segun quien preguntara, y comparar dos de sus valores
 * comparaba las direcciones de dos buffers en lugar de su contenido.
 * Centralizarlo aqui es lo que impide que vuelvan a divergir.
 *
 * @param lay Layout del enum ya localizado.
 * @param fallback_name Nombre a usar si el layout no lo trae.
 * @return El tipo en la representacion que corresponde al enum.
 */
Type TypeChecker::enum_type_of(const EnumLayout &lay,
                               const std::string &fallback_name) const {
    const std::string en = lay.name.empty() ? fallback_name : lay.name;
    if (lay.is_valued) {
        // Respaldo de tipo de usuario (`enum Color : Rgb`): el enum ES ese
        // tipo.
        if (!lay.backing_type_name.empty()) {
            Type vt{lay.backing};
            vt.struct_name = lay.backing_type_name;
            return vt;
        }
        Type vt{lay.backing};
        vt.struct_name = en;
        vt.is_valued_enum = true;
        return vt;
    }
    return Type{PrimitiveKind::STRUCT, en};
}

// ---------------------------------------------------------------------------
// La direccion de un parametro contra su tipo.
//
// Dos comprobaciones, y las dos son sobre lo mismo: que la marca hable de algo
// que existe.
//
//   1. Decir `in`/`out` de algo que no apunta a nada no dice nada.  La marca es
//      sobre lo APUNTADO, y un `i32` por valor no apunta a nada -- el callee
//      recibe una copia y lo que le haga no se ve fuera.
//   2. `out`/`inout` prometen ESCRIBIR lo apuntado; si lo apuntado se declaro
//      `const`, la promesa y la declaracion se contradicen.
//
// La segunda merece cuidado porque es facil pasarse de celo.  `const` es un
// permiso POR NIVEL -- lo mismo que en C, donde `const T*` y `T* const` no son
// lo mismo -- y la direccion habla del nivel EXTERNO.  Asi que solo choca
// cuando la promesa de escribir cae JUSTO sobre el nivel declarado no
// escribible: `out T const*` si, `out T const**` no, porque ahi se escribe el
// puntero de fuera y lo de dentro sigue siendo const.  Colapsar los dos ejes
// haria de `out T const**` algo inexpresable sin ganar nada.
// ---------------------------------------------------------------------------
void TypeChecker::check_param_dir_(const std::string &name, ast::ParamDir dir,
                                   SourceLoc loc, Type &pt) {
    if (dir == ast::ParamDir::None) return;
    const char *marca = dir == ast::ParamDir::In    ? "in"
                        : dir == ast::ParamDir::Out ? "out"
                                                    : "inout";
    // Lo que apunta.  Un array nativo tambien apunta: lo que viaja es la
    // direccion del primer elemento, no una copia del bloque.
    const bool apunta =
        (pt.kind == PrimitiveKind::PTR || pt.kind == PrimitiveKind::ARRAY);

    if (!apunta) {
        // Sobre un VALOR la marca sigue significando algo, y cada palabra una
        // cosa distinta, porque el mecanismo tiene que expresar lo que dice.
        if (dir == ast::ParamDir::In) {
            // `in` = copia de solo lectura.  Se cumple con el `const` que ya
            // existe: escribir a un lvalue const ya es error, y es la MISMA
            // regla en todo el lenguaje.  Un segundo camino de enforcement
            // seria otra copia del criterio, con su forma de divergir.
            pt.is_const = true;
            return;
        }
        // `out`/`inout` sobre un valor es el parametro de SALIDA -- quien
        // llama cede un hueco y el llamado lo escribe --.  Baja a lo que ya
        // existe (un `T*` con `&` en el sitio de llamada), pero eso es
        // reescribir la llamada y todavia no esta hecho.  Se dice: aceptar la
        // marca sin cumplirla seria peor que rechazarla, porque el programa
        // pareceria decir algo que no ocurre.
        diags_.diag(loc, DiagLevel::ERR, "VXT009",
                    {name, marca, type_to_string(pt)});
        return;
    }

    if (dir == ast::ParamDir::In) {
        // `in T*` = por ahi solo se lee.  Misma via: se marca const lo
        // APUNTADO, no el puntero -- el puntero si se puede reasignar --.
        //
        // El pointee se COPIA antes de tocarlo: es un `shared_ptr` que puede
        // estar compartido con otros tipos, y marcarlo en sitio le pondria
        // const a quien no lo pidio.
        if (pt.pointee) {
            auto solo_lectura = std::make_shared<Type>(*pt.pointee);
            solo_lectura->is_const = true;
            pt.pointee = std::move(solo_lectura);
        }
        return; // leer nunca contradice a `const`
    }
    if (pt.pointee && pt.pointee->is_const)
        diags_.diag(loc, DiagLevel::ERR, "VXT006", {name, marca});
}

Type TypeChecker::type_from_node_impl(const ast::TypeNode *tn) const {
    if (!tn) return Type{};
    if (tn->kind == ast::NodeKind::PrimitiveTypeNode) {
        const auto *pt = static_cast<const ast::PrimitiveTypeNode *>(tn);
        Type t{pt->prim};
        // gc<X> (opt-in `import vx.gc`): referencia GC-managed.  Resolvemos X
        // y devolvemos su tipo de CLASE con @c gc_managed=true -> reusa TODO el
        // acceso a miembros de clase; el lowering decide el allocator (vx_gc_
        // alloc) y la ausencia de RAII por el flag.  GC_PTR no sobrevive al
        // type checking en valores; es solo la forma parseada del tipo.
        if (pt->prim == PrimitiveKind::GC_PTR) {
            if (pt->type_args.empty()) return t; // gc<> mal formado
            Type inner = type_from_node(pt->type_args[0].get());
            inner.gc_managed = true;
            return inner;
        }
        // si el tipo primitivo es una coleccion y se
        // declara con type args (ej. ArrayList<string>), guardamos
        // el tipo de elemento en pointee (key en pointee, value en
        // pointee2 para los map-like).  Esto permite que el lowering
        // dispatche a las variantes *_gc cuando el elemento es GC
        // (string, class) en lugar del *_no_gc de cero overhead.
        if (!pt->type_args.empty() && is_col_kind(pt->prim)) {
            const bool is_map = (pt->prim == PrimitiveKind::HASHMAP ||
                                 pt->prim == PrimitiveKind::TREEMAP);
            if (is_map) {
                if (pt->type_args.size() >= 1) {
                    t.pointee = std::make_shared<Type>(
                        type_from_node(pt->type_args[0].get()));
                }
                if (pt->type_args.size() >= 2) {
                    t.pointee2 = std::make_shared<Type>(
                        type_from_node(pt->type_args[1].get()));
                }
            } else {
                // ARRAYLIST/HASHSET/QUEUE/DEQUE/TREESET/STACK -> 1 arg.
                t.pointee = std::make_shared<Type>(
                    type_from_node(pt->type_args[0].get()));
            }
        }
        // Smart pointers: unique<T> / shared<T> almacenan el tipo del
        // recurso apuntado en @c pointee (analogo a Optional<T>).
        // Sin esto, `unique<i32>` quedaria como kind=UNIQUE_PTR sin
        // pointee, y la asignacion `unique<i32> p = unique_box(42)`
        // fallaria al unificar.
        if (!pt->type_args.empty() && (pt->prim == PrimitiveKind::UNIQUE_PTR ||
                                       pt->prim == PrimitiveKind::SHARED_PTR ||
                                       pt->prim == PrimitiveKind::BORROW ||
                                       pt->prim == PrimitiveKind::BORROW_MUT)) {
            t.pointee =
                std::make_shared<Type>(type_from_node(pt->type_args[0].get()));
            /* `unique<T, liberador>`: el segundo argumento NO es un tipo, es
             * el NOMBRE de la funcion que libera.  Va en el tipo y no en la
             * ranura -- ver @c Type::deleter_name --, que es lo que permite
             * que un puntero inteligente ocupe una sola palabra.
             *
             * Se escribe donde el tipo esta fijado de antemano: un campo o una
             * firma.  En una declaracion local se puede omitir, y la variable
             * adopta el del inicializador. */
            if (pt->type_args.size() >= 2 &&
                (pt->prim == PrimitiveKind::UNIQUE_PTR ||
                 pt->prim == PrimitiveKind::SHARED_PTR) &&
                pt->type_args[1] &&
                pt->type_args[1]->kind == ast::NodeKind::NamedTypeNode) {
                t.deleter_name = static_cast<const ast::NamedTypeNode *>(
                                     pt->type_args[1].get())
                                     ->name;
            }
        }
        return t;
    }
    if (tn->kind == ast::NodeKind::NamedTypeNode) {
        const auto *nt = static_cast<const ast::NamedTypeNode *>(tn);
        //  M.7.c: namespace qualified type (`ui.Button`).
        // El parser concatena los segmentos con `.`; lo separamos
        // y resolvemos buscando primero el namespace local, luego
        // el simbolo dentro.  Si encaja, traducimos a Type del
        // tipo apuntado (con el mangled label correspondiente).
        {
            //  NS.1b: resolver por el prefijo de namespace mas largo
            // (multi-segmento `ui.widgets.Button`).
            uint32_t ns_idx_resolved = UINT32_MAX;
            std::string sym_name;
            if (nt->name.find('.') != std::string::npos &&
                resolve_ns_qualified(nt->name, ns_idx_resolved, sym_name)) {
                if (ns_idx_resolved < imported_namespaces_.size()) {
                    const auto &ns = imported_namespaces_[ns_idx_resolved];
                    auto its = ns.by_name.find(sym_name);
                    if (its != ns.by_name.end()) {
                        const auto &sym = ns.symbols[its->second];
                        // El mangled_label es el nombre interno
                        // (e.g. `ui__Button`).  Buscamos el layout
                        // en struct/class/enum layouts.
                        // Bug M: identidad = nombre del LAYOUT, no la clave.
                        auto it_cls = class_layouts_.find(sym.mangled_label);
                        if (it_cls != class_layouts_.end()) {
                            return Type{PrimitiveKind::CLASS,
                                        it_cls->second.name.empty()
                                            ? sym.mangled_label
                                            : it_cls->second.name};
                        }
                        // El enum va ANTES que el struct: un enum tambien
                        // queda registrado entre los agregados (comparte el
                        // camino de los value-types), asi que preguntar por
                        // struct primero se lo lleva y un enum CON VALOR
                        // pierde su representacion -- sus variantes dejan de
                        // ser el entero que son para volverse buffers.
                        auto it_en = enum_layouts_.find(sym.mangled_label);
                        if (it_en != enum_layouts_.end()) {
                            return enum_type_of(it_en->second,
                                                sym.mangled_label);
                        }
                        auto it_st = struct_layouts_.find(sym.mangled_label);
                        if (it_st != struct_layouts_.end()) {
                            return Type{PrimitiveKind::STRUCT,
                                        it_st->second.name.empty()
                                            ? sym.mangled_label
                                            : it_st->second.name};
                        }
                        auto it_ta = type_aliases_.find(sym.mangled_label);
                        if (it_ta != type_aliases_.end()) {
                            return it_ta->second;
                        }
                    }
                }
            }
        }
        /* si el nombre esta bindeado como comptime type-param
         * (estamos dentro de un call a comptime fn generica), lo
         * sustituimos por el tipo concreto.  Esto permite que
         * `sizeof<T>()` dentro del body resuelva al tipo proveido en
         * el call site. */
        {
            Type bound;
            if (lookup_comptime_type(nt->name, bound)) {
                return bound;
            }
        }
        /* Type-as-first-class-value.  Si el nombre matchea un
         * `comptime const Type X = comptime_type<...>()` global, el
         * `type_val` cacheado contiene el Type real -> sustituir.
         * Permite usar `X` en cualquier posicion de tipo. */
        {
            auto it_ct = comptime_const_values_.find(nt->name);
            if (it_ct != comptime_const_values_.end() &&
                it_ct->second.is_type &&
                it_ct->second.type_val.kind != PrimitiveKind::TYPE_META) {
                return it_ct->second.type_val;
            }
        }
        /* identifier `Type` actua como sentinela TYPE_META.  El
         * caller (check_var_decl + lower_var_decl) se encarga del
         * binding real (sin storage runtime). */
        if (nt->name == "Type" && nt->type_args.empty()) {
            return Type{PrimitiveKind::TYPE_META};
        }
        // -1) Builtins genericos del compilador: Optional<T> y
        //     Result<V, E> NO se monomorphizan; el type checker los
        //     recoge como tipos especiales con layout fijo, y el
        //     lowering emite directamente el codigo optimizado.  Esto
        //     evita que cada uso genere una clase concreta nueva en
        //     el bytecode (ahorro masivo en proyectos grandes).
        if (nt->name == "Optional" && nt->type_args.size() == 1) {
            return Type::make_optional(type_from_node(nt->type_args[0].get()));
        }
        if (nt->name == "Result" && nt->type_args.size() == 2) {
            return Type::make_result(type_from_node(nt->type_args[0].get()),
                                     type_from_node(nt->type_args[1].get()));
        }
        // Mejora II: Future<T> es builtin igual que Optional/Result.
        // El frontend lo modela con kind=FUTURE + pointee=T.  El
        // bytecode no cambia: el handle sigue siendo i64 opaco.
        if (nt->name == "Future" && nt->type_args.size() == 1) {
            return Type::make_future(type_from_node(nt->type_args[0].get()));
        }
        // 0) Generics: si tiene type_args, mapeamos al mangled name
        //    (la monomorphizacion ya se hizo en el pre-pase).
        std::string lookup = nt->name;
        if (!nt->type_args.empty()) {
            std::vector<Type> args;
            args.reserve(nt->type_args.size());
            for (auto &ta : nt->type_args) {
                args.push_back(type_from_node(ta.get()));
            }
            // #cross-module-generics: un template importado con namespace se
            // registra con nombre cualificado `lib.Box` (con punto), pero su
            // instancia se mangla dot-free (`lib_Box_i64`) para etiquetas
            // validas.  Sanitizar aqui para que el lookup del layout coincida.
            lookup = mangle_sanitize(nt->name) + "_" + mangle_args(args);
        }
        // 1) Alias resolution.
        auto it_a = type_aliases_.find(lookup);
        if (it_a != type_aliases_.end()) {
            referenced_names_.insert(lookup); // L.26: type alias usado
            // Un enum importado se ve por su nombre local (`Ordering`) y por
            // el canonico (`std__wideint__Ordering`), y el local llega como
            // alias.  El tipo guardado en el alias se construyo sin consultar
            // el layout, asi que un enum CON VALOR volvia aqui convertido en
            // agregado: sus variantes dejaban de ser -1/0/1 para ser
            // direcciones de buffers, y compararlas comparaba direcciones.
            // Reconstruirlo desde el layout devuelve la representacion real.
            // Un newtype queda fuera: es un tipo NUEVO que solo comparte
            // representacion con el de origen, y devolver el de origen le
            // quitaria la identidad que es su razon de ser.
            if (!it_a->second.struct_name.empty() &&
                !newtype_underlying_.count(lookup)) {
                const EnumLayout *lay_al =
                    find_enum_layout(it_a->second.struct_name);
                if (lay_al != nullptr && lay_al->is_valued)
                    return enum_type_of(*lay_al, it_a->second.struct_name);
            }
            return it_a->second;
        }
        // 2) Struct registrado: devolvemos Type{STRUCT, name}.
        auto it_s = struct_layouts_.find(lookup);
        if (it_s != struct_layouts_.end()) {
            referenced_names_.insert(lookup); // L.26: struct usado
            // Bug M: la identidad es el NOMBRE DEL LAYOUT, no la clave por la
            // que se busco.  Un tipo importado esta registrado bajo su nombre
            // publico Y bajo el canonico (mangled); devolver la clave daba dos
            // identidades para un mismo tipo segun por donde se llegara.
            return Type{PrimitiveKind::STRUCT,
                        it_s->second.name.empty() ? lookup : it_s->second.name};
        }
        // enum registrado.  Reusamos PrimitiveKind::STRUCT
        // con struct_name = nombre del enum: el lowering distingue
        // mirando enum_layouts_ vs struct_layouts_.  Esto evita
        // anyadir un nuevo PrimitiveKind para no inflar el switch
        // ubicuo del IR / lowering, manteniendo la semantica
        // value-type igual que un struct (alocado en stack del scope
        // que lo crea, copia por valor).
        const EnumLayout *lay_ty = find_enum_layout(lookup);
        if (lay_ty != nullptr) {
            referenced_names_.insert(lookup); // L.26: enum usado
            // C-style: un enum con VALOR es su tipo base (U8/...) etiquetado
            // con el nombre del enum -> el lowering lo trata como entero.
            return enum_type_of(*lay_ty, lookup);
        }
        // 3) Clase registrada: devolvemos Type{CLASS, name}.  CLASS
        //    es reference type: variables del tipo son punteros al
        //    ObjectHeader, instances se crean con NEWOBJ.
        auto it_c = class_layouts_.find(lookup);
        if (it_c != class_layouts_.end()) {
            referenced_names_.insert(lookup); // L.26: class usada
            return Type{PrimitiveKind::CLASS,
                        it_c->second.name.empty() ? lookup : it_c->second.name};
        }
        // 4) Si el original (no mangled) ESTA en class_layouts, lo
        //    devolvemos: probablemente es uso de una clase concreta
        //    pasada como type arg.  Solo recurrimos a este fallback
        //    cuando habia type_args (sin args es uso normal).
        if (!nt->type_args.empty()) {
            auto it_cb = class_layouts_.find(nt->name);
            if (it_cb != class_layouts_.end()) {
                return Type{PrimitiveKind::CLASS, it_cb->second.name.empty()
                                                      ? nt->name
                                                      : it_cb->second.name};
            }
        }
        // 5) Tipo desconocido.
        return Type{};
    }
    if (tn->kind == ast::NodeKind::PointerTypeNode) {
        const auto *pn = static_cast<const ast::PointerTypeNode *>(tn);
        // Resolver recursivamente el tipo apuntado y envolverlo en PTR.
        Type pointee = type_from_node(pn->pointee.get());
        // No exigimos que pointee este resuelto aqui (un puntero a un
        // tipo desconocido produce VOID-pointee, que el callsite
        // detectara cuando intente desreferenciar).
        return Type::make_ptr(std::move(pointee), pn->is_virtual);
    }
    if (tn->kind == ast::NodeKind::ArrayTypeNode) {
        const auto *an = static_cast<const ast::ArrayTypeNode *>(tn);
        Type elem = type_from_node(an->element_type.get());
        uint32_t size = 0;
        if (an->size_expr) {
            // Solo aceptamos literal entero positivo en.  Ampliar
            // a expresiones constantes (con const-folding) requiere un
            // evaluador en el frontend; pendiente para hitos posteriores.
            if (an->size_expr->kind == ast::NodeKind::IntLitExpr) {
                auto *lit =
                    static_cast<const ast::IntLitExpr *>(an->size_expr.get());
                size = static_cast<uint32_t>(lit->value);
            } else {
                // El caller emite el diagnostico apropiado mas tarde
                // (typicamente en check_var_decl con loc preciso).
                size = 0;
            }
        }
        // Bug host-vs-VM (2026-07-15): un array nombrado en el codigo
        // (`T[N]` local o `T[]` como parametro) NO es virtual.  Los `T[N]`
        // locales viven en memoria host desde que @c
        // ir_pass_promote_local_allocas promueve con force_all, y los
        // dinamicos (`new T[N]`) siempre lo fueron, asi que ambos origenes
        // coinciden.  Marcarlos virtual hacia que `&arr[i]` produjese un
        // VirtualPtr que luego se asignaba/pasaba como `T*` (host) y se
        // deref-eaba con movh sobre una direccion VM -> SIGSEGV.
        // `VirtualPtr<T>` sigue siendo la unica forma de nombrar memoria VM.
        return Type::make_array(std::move(elem), size, /*virt=*/false);
    }
    // `fn(P1, P2) -> R` -> Type{FUNCTION, [P1,P2], R}.
    // El parser garantiza que return_type nunca es null (usa VOID por
    // defecto cuando el usuario omite la flecha @c ->), asi que no
    // necesitamos chequear nullptr aqui.
    if (tn->kind == ast::NodeKind::FunctionTypeNode) {
        const auto *fn = static_cast<const ast::FunctionTypeNode *>(tn);
        std::vector<Type> params;
        params.reserve(fn->param_types.size());
        for (size_t i = 0; i < fn->param_types.size(); ++i) {
            Type pt = type_from_node(fn->param_types[i].get());
            /* `fn(T...) -> R`: dentro del cuerpo el ultimo es la DIRECCION del
             * array, no un `T`.  Se guarda ya asi para que la firma diga lo
             * mismo aqui que en una declaracion de parametros. */
            if (fn->is_variadic && i + 1 == fn->param_types.size())
                pt = Type::make_ptr(pt);
            params.push_back(std::move(pt));
        }
        Type ret = type_from_node(fn->return_type.get());
        Type ft = Type::make_function(std::move(params), std::move(ret));
        ft.fn_is_raw = fn->is_raw; // cfn(...) -> puntero a funcion crudo (8B)
        ft.fn_is_variadic = fn->is_variadic;
        // ABI custom por-parametro: forma parte de la identidad del tipo (dos
        // cfn con abi_regs distintos son tipos incompatibles).  El operator==
        // de Type ya lo distingue; aqui se valida el nombre del registro y se
        // propaga.
        for (const auto &r : fn->param_abi_regs)
            if (!r.empty() && asm_canonical_reg(r).empty())
                diags_.error(fn->loc, "register(\"" + r +
                                          "\") en el tipo funcion: '" + r +
                                          "' no es un registro reconocido");
        ft.fn_param_abi_regs = fn->param_abi_regs;
        return ft;
    }
    return Type{};
}

std::string TypeChecker::first_unresolved_type(const ast::TypeNode *tn) const {
    if (!tn) return {};
    switch (tn->kind) {
    case ast::NodeKind::PointerTypeNode:
        return first_unresolved_type(
            static_cast<const ast::PointerTypeNode *>(tn)->pointee.get());
    case ast::NodeKind::ArrayTypeNode:
        return first_unresolved_type(
            static_cast<const ast::ArrayTypeNode *>(tn)->element_type.get());
    case ast::NodeKind::NamedTypeNode: {
        const auto *nt = static_cast<const ast::NamedTypeNode *>(tn);
        // Casos legitimos que producen VOID o que ya son conocidos: no son
        // "no resueltos".
        if (nt->name == "void" || nt->name == "never") return {};
        if (type_aliases_.count(nt->name)) // alias (incluido alias-a-void)
            return {};
        Type bound;
        if (lookup_comptime_type(nt->name, bound)) // parametro de tipo comptime
            return {};
        // type_from_node reconoce primitivos, struct/clase/enum, genericos y
        // especiales (Optional/Result/Array/VirtualPtr/...), namespaces, y
        // Type-as-value; todos ellos devuelven algo != VOID.  Solo un nombre
        // GENUINAMENTE desconocido cae a VOID aqui.
        if (type_from_node(tn).kind == PrimitiveKind::VOID) return nt->name;
        return {};
    }
    default: return {};
    }
}

// ---------------------------------------------------------------------
// Pase 1: declaraciones globales.
// ---------------------------------------------------------------------

void TypeChecker::collect_globals() {
    // ----- Builtins predefinidos -----
    //
    // Declarados con firmas que el type checker valida por unificacion
    // exacta (PTR == PTR, I64 == I64, ...).  El lowering intercepta
    // las llamadas a estos nombres en try_lower_builtin_call() y emite
    // la convencion FFI correspondiente a vesta_io.
    //
    // Restriccion: los argumentos de tipo PTR deben ser literales
    // de string directos (StringLitExpr), porque para los FFI
    // necesitamos la longitud en compile-time.  El type checker NO
    // exige esto (le basta con el tipo PTR); el lowering lo verifica
    // por su lado y reporta error claro si el arg no es literal.
    auto reg_builtin = [&](const std::string &name, Type ret,
                           std::initializer_list<PrimitiveKind> params) {
        FunctionSig sig;
        sig.return_type = ret;
        sig.param_types.reserve(params.size());
        for (auto p : params)
            sig.param_types.push_back(Type{p});
        Symbol s;
        s.kind = SymbolKind::Function;
        s.sig_index = (uint32_t)function_sigs_.size();
        sig_by_name_[name] = s.sig_index;
        function_sigs_.push_back(std::move(sig));
        (void)declare(name, s);
    };
    // Salida de texto (aceptan ANY tipo via dispatch en lowering).
    // El check_call hace bypass especial para estos nombres y permite
    // string interpolado (StringLitExpr con interp_exprs) o escalares.
    reg_builtin("print", Type{PrimitiveKind::VOID}, {PrimitiveKind::PTR});
    reg_builtin("println", Type{PrimitiveKind::VOID}, {PrimitiveKind::PTR});
    reg_builtin("echo", Type{PrimitiveKind::VOID}, {PrimitiveKind::PTR});
    // flush() sin argumentos (vacia el buffer de vesta_io).
    reg_builtin("flush", Type{PrimitiveKind::VOID}, {});
    // gc_collect() sin argumentos: fuerza un ciclo de GC + finalizadores.
    reg_builtin("gc_collect", Type{PrimitiveKind::VOID}, {});
    // gc_finalize_all() sin argumentos: finaliza TODO objeto GC vivo con
    // recurso interno (deleter/dtor).  Determinista (no depende de la colecta):
    // util para observar la finalizacion de objetos escapados sin polling.
    reg_builtin("gc_finalize_all", Type{PrimitiveKind::VOID}, {});
    // fiber_swapctx(from_ctx, to_ctx): context-switch cooperativo de fibra en
    // el path INTERPRETE (FN.1).  Baja al opcode VM `swapctx`: guarda el
    // contexto actual (152 bytes = 19 qwords {PC,SP,BP,R0..R15}) en @p from_ctx
    // y salta al de @p to_ctx.  Ambos son direcciones de memoria VM (arrays
    // globales).
    reg_builtin("fiber_swapctx", Type{PrimitiveKind::VOID},
                {PrimitiveKind::U64, PrimitiveKind::U64});
    // Salida de valores numericos (sin acceso a memoria VM).
    reg_builtin("print_int", Type{PrimitiveKind::VOID}, {PrimitiveKind::I64});
    reg_builtin("print_uint", Type{PrimitiveKind::VOID}, {PrimitiveKind::U64});
    reg_builtin("print_hex", Type{PrimitiveKind::VOID}, {PrimitiveKind::U64});
    reg_builtin("print_float", Type{PrimitiveKind::VOID}, {PrimitiveKind::F64});
    reg_builtin("print_bool", Type{PrimitiveKind::VOID}, {PrimitiveKind::BOOL});
    reg_builtin("print_char", Type{PrimitiveKind::VOID}, {PrimitiveKind::U32});
    reg_builtin("print_color", Type{PrimitiveKind::VOID}, {PrimitiveKind::U32});
    // print_cstr(host_ptr) imprime una cstring desde memoria host
    // (FatalError.message o .stack_trace).  Acepta cualquier PTR.
    reg_builtin("print_cstr", Type{PrimitiveKind::VOID}, {PrimitiveKind::PTR});
    // Formatos numericos alternativos: binario y octal con prefijo
    // "0b" / "0o".  Compactos (sin ceros lider).
    reg_builtin("print_bin", Type{PrimitiveKind::VOID}, {PrimitiveKind::U64});
    reg_builtin("print_oct", Type{PrimitiveKind::VOID}, {PrimitiveKind::U64});
    // print_ptr(addr) imprime "0x<hex>" compacto sin ceros lider.
    // Acepta cualquier PTR (host o virtual) o un i64 con la direccion.
    // print_gchandle(handle) imprime "<gc:N>" donde N es el handle
    // como entero decimal.  Para uso con CLASS objects el lowering
    // emite la instruccion @c gchandle antes de llamar.
    reg_builtin("print_ptr", Type{PrimitiveKind::VOID}, {PrimitiveKind::PTR});
    reg_builtin("print_gchandle", Type{PrimitiveKind::VOID},
                {PrimitiveKind::I64});
    // Padding/alineacion: emite @p width copias del codepoint
    // @p fill_cp.  El usuario calcula la diferencia entre el ancho
    // deseado y el ancho actual del texto y llama a este builtin.
    // Para alineacion manual de columnas en TUIs.
    reg_builtin("print_pad", Type{PrimitiveKind::VOID},
                {PrimitiveKind::U32, PrimitiveKind::U64});
    // I/O de fichero.  fopen recibe path y modo como literales de
    // string; devuelve un FILE* (uint64_t).  fwrite recibe el FILE*
    // y un buffer literal; devuelve el numero de bytes escritos.
    // fclose recibe el FILE* y devuelve un codigo i32.
    reg_builtin("fopen", Type{PrimitiveKind::I64},
                {PrimitiveKind::PTR, PrimitiveKind::PTR});
    reg_builtin("fwrite", Type{PrimitiveKind::I64},
                {PrimitiveKind::I64, PrimitiveKind::PTR});
    reg_builtin("fclose", Type{PrimitiveKind::I32}, {PrimitiveKind::I64});

    // Allocator manual: malloc devuelve void* (puntero host obtenido del
    // RawAllocator del proceso); free libera un puntero anteriormente
    // devuelto por malloc.  El usuario calcula los bytes manualmente
    // (sizeof aun no implementado): malloc(4 * 10) reserva 10 i32s.
    // El lowering marca el resultado de malloc como is_host_ptr=true
    // para que LOAD/STORE emitan `movh` (acceso a memoria host).
    // free admite cualquier T* (sin chequeo dinamico de tipo).
    reg_builtin("malloc", Type::make_ptr(Type{PrimitiveKind::VOID}),
                {PrimitiveKind::I64});
    reg_builtin("free", Type{PrimitiveKind::VOID}, {PrimitiveKind::PTR});

    // CPU dispatch (cimiento): cpu_features() -> u64 devuelve el bitmask de
    // features de la CPU detectadas via cpuid al arranque.  Base del despacho
    // de helpers por hardware + del override por el usuario.  Sin args.
    // Bits: bit0=SSE2 bit1=SSE4.2 bit2=POPCNT bit3=AVX bit4=AVX2 bit5=BMI1
    // bit6=BMI2 bit7=AVX512F bit8=ERMS.
    reg_builtin("cpu_features", Type{PrimitiveKind::U64}, {});

    // Alias predefinido `cstring` = `char*`.  Permite
    // declarar `cstring p` para FFI con char* sin tener que escribir
    // `char* p`.  Se registra como type alias (typedef) global; el
    // type checker resuelve `cstring` a `Type{PTR, pointee=CHAR}`.
    {
        Type t_char = Type{PrimitiveKind::CHAR};
        Type t_cstring = Type::make_ptr(t_char);
        type_aliases_["cstring"] = t_cstring;
    }

    // Alias predefinidos para reflexion: Class / Method / Field / Object.
    // Se resuelven a i64 (handle opaco del ClassRegistry / MethodInfo* /
    // FieldInfo* / host_ptr del objeto).  Cuando se declara una variable
    // con uno de estos tipos (e.g. `Class cls = forName("X")`), el type
    // checker registra el alias en el Symbol; las llamadas
    // `cls.getMethod("foo")` se desazucaran a `getMethod(cls, "foo")`.
    // Esto provee sintaxis OO ergonomica sin cambios en el runtime.
    {
        const Type t_i64 = Type{PrimitiveKind::I64};
        type_aliases_["Class"] = t_i64;
        type_aliases_["Method"] = t_i64;
        type_aliases_["Field"] = t_i64;
        type_aliases_["Object"] = t_i64;
    }

    // Builtins de string operando sobre StringObject (tipo
    // STRING).  Todos se bajan a un solo opcode bytecode (~5 ns).
    reg_builtin("str_length", Type{PrimitiveKind::I64},
                {PrimitiveKind::STRING});
    reg_builtin("str_bytes", Type{PrimitiveKind::I64}, {PrimitiveKind::STRING});
    reg_builtin("str_cstr", Type{PrimitiveKind::PTR}, {PrimitiveKind::STRING});
    reg_builtin("str_wstr", Type{PrimitiveKind::PTR}, {PrimitiveKind::STRING});
    reg_builtin("str_hash", Type{PrimitiveKind::U64}, {PrimitiveKind::STRING});
    reg_builtin("str_intern", Type{PrimitiveKind::STRING},
                {PrimitiveKind::STRING});
    reg_builtin("str_concat", Type{PrimitiveKind::STRING},
                {PrimitiveKind::STRING, PrimitiveKind::STRING});
    reg_builtin("str_equals", Type{PrimitiveKind::BOOL},
                {PrimitiveKind::STRING, PrimitiveKind::STRING});
    reg_builtin("str_make", Type{PrimitiveKind::STRING},
                {PrimitiveKind::PTR, PrimitiveKind::I64});
    // Encoding explicito.  str_convert(s, enc) usa
    // STRCONV bytecode.  Acepta cualquier int de las constantes
    // ENC_* (ASCII=0, ANSI=1, UTF8=2, UTF16=3, UTF32=4) declaradas
    // como Symbol::Constant abajo.  Util para preparar wstr (UTF16)
    // antes de pasar a Win32 *W APIs.
    reg_builtin("str_convert", Type{PrimitiveKind::STRING},
                {PrimitiveKind::STRING, PrimitiveKind::I32});

    // Constantes de encoding (idem ANSI codes: registradas como
    // Symbol::Constant con tipo i32).  El lowering las inlinea como
    // const literal sin lookup runtime.
    auto reg_const_int = [&](const std::string &name, int32_t value) {
        Symbol s;
        s.kind = SymbolKind::Constant;
        s.type = Type{PrimitiveKind::I32};
        // Reusamos campo type como contenedor + valor en sig_index
        // (truco: sig_index es uint32_t y vale como inmediato).
        s.sig_index = static_cast<uint32_t>(value);
        (void)declare(name, s);
    };
    reg_const_int("ENC_ASCII", 0);
    reg_const_int("ENC_ANSI", 1);
    reg_const_int("ENC_UTF8", 2);
    reg_const_int("ENC_UTF16", 3);
    reg_const_int("ENC_UTF32", 4);

    // panic("msg") lanza FatalError(USER_ABORT, msg).  Si hay
    // try/catch FatalError lo captura; si no, mata el proceso (no la VM).
    reg_builtin("panic", Type{PrimitiveKind::VOID}, {PrimitiveKind::PTR});

    // AOT 2c (dev OS): simbolos de seccion estilo linker (__start_/__stop_).
    // El arg es un string LITERAL con el nombre de la seccion (".boot", etc.);
    // el lowering extrae el literal y emite SECTION_REF.  En interp/JIT (sin
    // secciones nativas) devuelven 0.  section_start/end -> puntero a la
    // base/fin de la seccion; section_size -> tamano en bytes.
    reg_builtin("section_start", Type{PrimitiveKind::PTR},
                {PrimitiveKind::STRING});
    reg_builtin("section_end", Type{PrimitiveKind::PTR},
                {PrimitiveKind::STRING});
    reg_builtin("section_size", Type{PrimitiveKind::U64},
                {PrimitiveKind::STRING});

    // dispose(xs) libera explicitamente una coleccion antes
    // del exit del scope.  Tras la llamada, el local queda con handle=0
    // y el cleanup automatico llama free fn que es no-op con handle=0.
    // Aceptamos cualquier tipo coleccion (bypass relax en check_call).
    reg_builtin("dispose", Type{PrimitiveKind::VOID}, {PrimitiveKind::I64});

    // Constructores de tipos primitivos de coleccion.
    // Cada uno acepta una capacidad inicial opcional (i64, default 16);
    // por simplicidad, registramos la signature con el arg requerido.
    // El usuario llama @c arraylist(N) (N >= 16 internamente capado) o
    // @c arraylist() (caso 0-args sin registrar firma extra: usamos el
    // bypass relajado en check_call analogo a print).  Para esta primera
    // iteracion exigimos siempre 1 arg explicito o wrapper Vesta; suficiente
    // para validar la integracion.
    for (size_t i = 0; i < COL_TYPES_N; ++i) {
        const ColType &ct = COL_TYPES[i];
        // arraylist(i64) -> ArrayList     (constructor con capacidad)
        // tmap_new() / tset_new() son sin args; los tratamos igual:
        // el lowering ignora args extra cuando default_cap == 0.
        if (ct.default_cap == 0) {
            reg_builtin(ct.vx_ctor_name, Type{ct.kind}, {});
        } else {
            reg_builtin(ct.vx_ctor_name, Type{ct.kind}, {PrimitiveKind::I64});
        }
    }

    // FFI runtime dinamico estilo VSH.  Permite cargar DLLs y
    // resolver simbolos en runtime (vs el FFI declarativo extern, que
    // resuelve en compile-time).  Cero overhead de la ruta normal:
    // solo paga cuando el usuario decide usarlo.
    //   ffi_open(string path) -> i64 handle
    //   ffi_sym (i64 handle, string name) -> i64 fn_addr
    //   ffi_call(i64 fn_addr, ...args) -> i64 result   (variadic 0-12)
    // El check_call hace bypass para ffi_call (acepta argc variable).
    reg_builtin("ffi_open", Type{PrimitiveKind::I64}, {PrimitiveKind::PTR});
    reg_builtin("ffi_sym", Type{PrimitiveKind::I64},
                {PrimitiveKind::I64, PrimitiveKind::PTR});
    reg_builtin("ffi_call", Type{PrimitiveKind::I64}, {PrimitiveKind::I64});

    // Math builtins delegando a stdlib/native/math/vesta_math.dll.  El
    // ABI nativo es uint64_t -> uint64_t con bits IEEE 754; el lowering
    // emite CALLN directo a vmath_<name> (no pasa por IR ops float).
    // Cubrir todo lo expuesto por vmath_*: scalar y trig.
    reg_builtin("sqrt", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("pow", Type{PrimitiveKind::F64},
                {PrimitiveKind::F64, PrimitiveKind::F64});
    reg_builtin("fabs", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("floor", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("ceil", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("round", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("fmin", Type{PrimitiveKind::F64},
                {PrimitiveKind::F64, PrimitiveKind::F64});
    reg_builtin("fmax", Type{PrimitiveKind::F64},
                {PrimitiveKind::F64, PrimitiveKind::F64});
    reg_builtin("log", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("log2", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("log10", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("sin", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("cos", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("tan", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("abs", Type{PrimitiveKind::I64}, {PrimitiveKind::I64});
    reg_builtin("imin", Type{PrimitiveKind::I64},
                {PrimitiveKind::I64, PrimitiveKind::I64});
    reg_builtin("imax", Type{PrimitiveKind::I64},
                {PrimitiveKind::I64, PrimitiveKind::I64});
    reg_builtin("clamp", Type{PrimitiveKind::I64},
                {PrimitiveKind::I64, PrimitiveKind::I64, PrimitiveKind::I64});
    // Math-IR-promote v2.2a: float + bit ops nuevos.
    reg_builtin("trunc", Type{PrimitiveKind::F64}, {PrimitiveKind::F64});
    reg_builtin("iminu", Type{PrimitiveKind::U64},
                {PrimitiveKind::U64, PrimitiveKind::U64});
    reg_builtin("imaxu", Type{PrimitiveKind::U64},
                {PrimitiveKind::U64, PrimitiveKind::U64});
    reg_builtin("ilog2", Type{PrimitiveKind::U64}, {PrimitiveKind::U64});
    reg_builtin("popcount", Type{PrimitiveKind::U64}, {PrimitiveKind::U64});
    reg_builtin("clz", Type{PrimitiveKind::U64}, {PrimitiveKind::U64});
    reg_builtin("ctz", Type{PrimitiveKind::U64}, {PrimitiveKind::U64});
    reg_builtin("bswap", Type{PrimitiveKind::U64}, {PrimitiveKind::U64});
    reg_builtin("rotl", Type{PrimitiveKind::U64},
                {PrimitiveKind::U64, PrimitiveKind::U64});
    reg_builtin("rotr", Type{PrimitiveKind::U64},
                {PrimitiveKind::U64, PrimitiveKind::U64});

    /* Sprint B.1: callback Vesta -> C nativo.  Toma una fn Vesta como
     * argumento y devuelve un host_ptr (i64) a un thunk con cc C
     * estandar (Win64 o SysV).  El check_call hace bypass especial
     * para validar que el arg es una IdentExpr a una funcion
     * declarada (no a un lambda value).  Sintaxis:
     *
     *   i32 mi_cmp(u8* a, u8* b) { ... }
     *   u64 cb = as_native_callback(mi_cmp);
     *   qsort(arr, n, sz, cb);  // C llama a mi_cmp via cc nativa */
    reg_builtin("as_native_callback", Type{PrimitiveKind::I64},
                {PrimitiveKind::PTR});
    // fiber_entry(fn): VA de bytecode VM de una funcion (PC de arranque de
    // fibra, FN.1).  Registrado para que el simbolo exista; el bypass en
    // check_call lo resuelve (acepta un nombre de funcion como arg, no un valor
    // tipado).
    reg_builtin("fiber_entry", Type{PrimitiveKind::U64}, {PrimitiveKind::U64});

    // Identificadores magicos para colores y atributos ANSI.
    //
    // Registramos como Symbols globales tipo PTR (string).  El
    // lowering los detecta en lower_ident y emite la secuencia ANSI
    // correspondiente como string literal estatico (zero overhead).
    // Lista cubre los SGR mas comunes: 8 colores foreground + 8
    // brillantes + atributos de estilo + RESET + dos helpers de
    // pantalla (CLEAR_SCREEN, CURSOR_HOME).  Todos quedan en el
    // scope global y se ven desde cualquier funcion.
    auto reg_const_string = [&](const std::string &name) {
        Symbol s;
        s.kind = SymbolKind::Constant;
        s.type = Type{PrimitiveKind::PTR};
        (void)declare(name, s);
    };
    // La lista vive en un solo sitio (vx/ansi_names.h) porque tambien la
    // necesita el bajado, y una lista por sitio se desincroniza sin que nada
    // lo note: un color que existe como nombre pero no se baja, o al reves.
    for (const AnsiName &a : kAnsiNames)
        reg_const_string(a.name);

    // Builtins de color verdadero (truecolor, SGR 24-bit).  A
    // diferencia de los identificadores magicos anteriores (cadenas
    // constantes), estos toman r,g,b como parametros y se usan dentro
    // de la interpolacion de print/println: por ejemplo
    // @c println("${fg_rgb(255,128,0)}texto${RESET}").  El lowering de
    // la interpolacion los reconoce como caso especial y los expande a
    // la secuencia ANSI truecolor reusando la maquinaria de emision de
    // literales + enteros (funciona identico en interp/JIT/AOT y sin
    // construir un StringObject).  El tipo de retorno I32 solo sirve
    // para que pasen la validacion de la interpolacion (no puede ser
    // void); el valor nunca se imprime como entero.
    reg_builtin("fg_rgb", Type{PrimitiveKind::I32},
                {PrimitiveKind::I32, PrimitiveKind::I32, PrimitiveKind::I32});
    reg_builtin("bg_rgb", Type{PrimitiveKind::I32},
                {PrimitiveKind::I32, PrimitiveKind::I32, PrimitiveKind::I32});

    // registrar @c FatalError como clase pre-definida en
    // runtime.  El @c init_exception_classes del runtime ya la creo
    // en el ClassRegistry; aqui solo damos al type checker / lowering
    // la metadata para validar @c catch (FatalError e) y @c e.kind /
    // @c e.message / @c e.stack_trace.  Marcada con
    // @c is_runtime_predefined=true para que el lowering NO emita
    // defclass / __new_FatalError / etc.
    {
        ClassLayout fe;
        fe.name = "FatalError";
        fe.is_runtime_predefined = true;
        // ABI fija (matching exception_runtime.h):
        //   +24 i32 kind  (size 8 con padding)
        //   +32 u64 pc
        //   +40 ptr message
        //   +48 ptr stack_trace
        // Total 56 bytes (ObjectHeader 24 + 4*8).
        auto add_field = [&](const char *name, PrimitiveKind k, uint32_t off) {
            StructFieldInfo fi;
            fi.name = name;
            fi.type = Type{k};
            fi.offset = off;
            fi.size = 8;
            fe.fields.push_back(fi);
        };
        add_field("kind", PrimitiveKind::I32, 24);
        add_field("pc", PrimitiveKind::U64, 32);
        add_field("message", PrimitiveKind::PTR, 40);
        add_field("stack_trace", PrimitiveKind::PTR, 48);
        fe.size_bytes = 56;
        class_layouts_["FatalError"] = std::move(fe);
    }

    // BugFix R4: registrar clases excepcion estandar (sincronizado con
    // exception_runtime.cpp::init_exception_classes).  Cada una tiene
    // un solo field `message` (string ptr) en offset 24 (despues del
    // ObjectHeader).  El lowering del frontend detecta
    // `new <ExceptionClass>(msg)` y emite la secuencia inline
    // (newobj + store message at +24).  El catch puede leer
    // `e.message` via getfield estandar.
    {
        const char *std_exc_names[] = {
            "RuntimeException",         "ArithmeticException",
            "IllegalArgumentException", "IndexOutOfBoundsException",
            "NullPointerException",     "IOException",
            "ClassCastException",       "UnsupportedOperationException",
        };
        for (const char *n : std_exc_names) {
            ClassLayout cl;
            cl.name = n;
            cl.is_runtime_predefined = true;
            StructFieldInfo fi;
            fi.name = "message";
            fi.type = Type{PrimitiveKind::PTR};
            fi.offset = 24;
            fi.size = 8;
            cl.fields.push_back(fi);
            cl.size_bytes = 32;
            class_layouts_[n] = std::move(cl);
        }
    }

    // Pre-pasada (robustness): registrar nombres de TODOS
    // los structs / clases / enums con layouts mininos (vacio) ANTES
    // del procesamiento real de campos y metodos.  Esto permite:
    //   - Self-references: `class Node { Node next; }`
    //   - Forward refs: `class A { B b; }  class B { A a; }`
    //   - Mutual recursion entre clases en cualquier orden.
    // Sin esto, type_from_node falla al ver el primer uso del
    // nombre y devuelve VOID, propagando errores en cascada.
    for (auto &decl : mod_.decls) {
        if (!decl) continue;
        if (decl->kind == ast::NodeKind::StructDecl) {
            auto *s = static_cast<ast::StructDecl *>(decl.get());
            // Templates con type_params y especializaciones (#7) no son
            // structs concretos.
            if (!s->type_params.empty() || s->is_specialization) continue;
            if (!struct_layouts_.count(s->name)) {
                StructLayout empty;
                empty.name = s->name;
                empty.is_introspect = s->is_introspect;
                struct_layouts_.emplace(s->name, std::move(empty));
            }
        } else if (decl->kind == ast::NodeKind::ClassDecl) {
            auto *c = static_cast<ast::ClassDecl *>(decl.get());
            // Templates con type_params y especializaciones (#7) no son
            // clases concretas.
            if (!c->type_params.empty() || c->is_specialization) continue;
            if (!class_layouts_.count(c->name)) {
                ClassLayout empty;
                empty.name = c->name;
                empty.is_interface = c->is_interface;
                empty.is_aspect = c->is_aspect;
                empty.is_introspect = c->is_introspect;
                class_layouts_.emplace(c->name, std::move(empty));
            }
        } else if (decl->kind == ast::NodeKind::EnumDecl) {
            auto *en = static_cast<ast::EnumDecl *>(decl.get());
            // L2.3: enums template (con type_params) NO se registran
            // como concretos; se monomorphizan on demand.
            if (!en->type_params.empty()) continue;
            if (!enum_layouts_.count(en->name)) {
                EnumLayout empty;
                empty.name = en->name;
                empty.is_introspect = en->is_introspect;
                enum_layouts_.emplace(en->name, std::move(empty));
            }
        }
    }
    // Pase 0: registrar typedef/using y struct ANTES de funciones y
    // globales, para que cualquier referencia posterior a esos nombres
    // se resuelva correctamente.  Procesar typedef/using en orden
    // permite alias anidados (typedef A B; typedef B C;) si A esta
    // declarado antes que B; alias adelantados (B antes de A) no se
    // resuelven y emiten error.
    for (auto &decl : mod_.decls) {
        if (!decl) continue;
        if (decl->kind == ast::NodeKind::TypeAliasDecl) {
            auto *a = static_cast<ast::TypeAliasDecl *>(decl.get());
            Type resolved = type_from_node(a->aliased.get());
            if (resolved.kind == PrimitiveKind::COUNT ||
                (resolved.kind == PrimitiveKind::VOID && a->aliased &&
                 a->aliased->kind == ast::NodeKind::NamedTypeNode)) {
                // No se pudo resolver el tipo subyacente: nombre
                // desconocido o forward-reference.
                diags_.error(a->loc,
                             "tipo no resuelto en alias '" + a->name + "'");
                continue;
            }
            // Newtype: asignar nominal_id unico para que sea
            // nominalmente distinto del underlying y de otros newtypes
            // con misma representacion.  Sin esto, `typedef u64 fd new`
            // y `typedef u64 port new` serian tipos identicos (ambos
            // u64) -- exactamente lo que queremos EVITAR.
            if (a->is_newtype) {
                resolved.nominal_id = ++newtype_counter_;
                resolved.nominal_name = a->name;
                resolved.is_opaque = a->is_opaque;
                resolved.align_override = a->align_override;
                // Underlying preservado (para introspeccion + cast
                // explicito).  Conservamos COPIA del underlying en
                // newtype_underlying_ para que `typedef is T` y
                // `(T)x` puedan responder sin parsear el AST.
                Type underlying = resolved;
                underlying.nominal_id = 0;
                underlying.is_opaque = false;
                underlying.align_override = 0;
                underlying.nominal_name.clear();
                newtype_underlying_.emplace(a->name, std::move(underlying));
                // Registrar conversiones permitidas + fichero de
                // declaracion (para module-privacy de @opaque).
                NewtypeInfo info;
                info.source_file = a->loc.file;
                for (auto &ec : a->explicit_from) {
                    if (!ec.type) continue;
                    Type t = type_from_node(ec.type.get());
                    if (t.kind == PrimitiveKind::COUNT ||
                        t.kind == PrimitiveKind::VOID) {
                        diags_.error(
                            a->loc, "tipo no resuelto en 'explicit from' de '" +
                                        a->name + "'");
                        continue;
                    }
                    info.from_conversions.push_back(
                        {std::move(t), ec.is_public});
                }
                for (auto &ec : a->explicit_to) {
                    if (!ec.type) continue;
                    Type t = type_from_node(ec.type.get());
                    if (t.kind == PrimitiveKind::COUNT ||
                        t.kind == PrimitiveKind::VOID) {
                        diags_.error(a->loc,
                                     "tipo no resuelto en 'explicit to' de '" +
                                         a->name + "'");
                        continue;
                    }
                    info.to_conversions.push_back({std::move(t), ec.is_public});
                }
                // Las implicitas siguen el mismo camino; lo unico que cambia
                // es que no exigen cast en el punto de uso.
                for (auto &ec : a->implicit_from) {
                    if (!ec.type) continue;
                    Type t = type_from_node(ec.type.get());
                    if (t.kind == PrimitiveKind::COUNT ||
                        t.kind == PrimitiveKind::VOID) {
                        diags_.error(
                            a->loc, "tipo no resuelto en 'implicit from' de '" +
                                        a->name + "'");
                        continue;
                    }
                    info.implicit_from_conversions.push_back(
                        {std::move(t), ec.is_public});
                }
                for (auto &ec : a->implicit_to) {
                    if (!ec.type) continue;
                    Type t = type_from_node(ec.type.get());
                    if (t.kind == PrimitiveKind::COUNT ||
                        t.kind == PrimitiveKind::VOID) {
                        diags_.error(a->loc,
                                     "tipo no resuelto en 'implicit to' de '" +
                                         a->name + "'");
                        continue;
                    }
                    info.implicit_to_conversions.push_back(
                        {std::move(t), ec.is_public});
                }
                newtype_info_.emplace(a->name, std::move(info));
            }
            if (!type_aliases_.emplace(a->name, resolved).second) {
                // #typedef-generics: si el alias ya estaba registrado por el
                // pre-pase early (para que los type-args genericos lo
                // resuelvan), NO es una redefinicion real.  Solo es error si
                // hay DOS TypeAliasDecl con el mismo nombre.  Distinguimos
                // re-registrando el valor (idempotente) y contando decls.
                int count = 0;
                for (auto &d2 : mod_.decls)
                    if (d2 && d2->kind == ast::NodeKind::TypeAliasDecl &&
                        static_cast<ast::TypeAliasDecl *>(d2.get())->name ==
                            a->name)
                        ++count;
                if (count > 1) {
                    diags_.error(a->loc,
                                 "alias de tipo redefinido: '" + a->name + "'");
                } else {
                    type_aliases_[a->name] =
                        resolved; // refrescar (idempotente)
                }
            }
        } else if (decl->kind == ast::NodeKind::StructDecl) {
            auto *s = static_cast<ast::StructDecl *>(decl.get());
            // Templates con type_params no se procesan como concretos; cada
            // instanciado `Box<i32>` se monomorphiza y produce su propio
            // StructDecl concreto (sin type_params) que SI llega aqui.  Las
            // especializaciones (#7) tampoco se procesan como concretos.
            if (!s->type_params.empty() || s->is_specialization) continue;
            // Pre-pasada (mas arriba) ya creo una entrada vacia.  Si
            // size_bytes > 0 (ya completada) -> redeclaracion real.
            auto it_pre = struct_layouts_.find(s->name);
            if (it_pre != struct_layouts_.end() &&
                !it_pre->second.fields.empty()) {
                diags_.error(s->loc, "struct redeclarado: '" + s->name + "'");
                continue;
            }

            // Calcular layout con alineamiento natural por campo, igual
            // que C: cada campo arranca en el siguiente offset que sea
            // multiplo de su sizeof.  El struct entero tambien queda
            // alineado al campo mas grande, redondeando size_bytes
            // al final para que arrays de structs tengan offset
            // consistente entre elementos.
            StructLayout layout;
            layout.name = s->name;
            layout.is_union = s->is_union;
            layout.is_abstract = s->is_abstract;
            // @Virtual: un struct es POLIMORFICO si tiene >=1 metodo @Virtual
            // (propio o heredado -- tras el flatten los heredados ya estan en
            // s->methods con is_virtual preservado).  Un struct polimorfico
            // lleva un vptr (puntero a vtable estatica) en OFFSET 0; sus campos
            // empiezan en offset 8.  El upcast por Base* es layout-compatible.
            bool is_poly = false;
            for (const auto &m : s->methods)
                if (m->is_virtual) {
                    is_poly = true;
                    break;
                }
            layout.is_polymorphic = is_poly;
            layout.super_name =
                s->super_name; // para el upcast Derivado*->Base*
            // union: `offset` se reutiliza como MAXIMO tamano de campo (todos
            // los campos viven en offset 0); en struct es el offset secuencial.
            uint32_t offset = 0;
            uint32_t max_align = 1;
            if (is_poly && !s->is_union) {
                offset = 8;    // reservar [0..8) para el vptr
                max_align = 8; // el vptr fuerza alineamiento a 8
            }
            std::unordered_map<std::string, bool> seen_names;

            // Estado para packing de bit fields.
            //   bf_active=true mientras hay un storage word abierto.
            //   bf_offset: offset (bytes) del storage word actual.
            //   bf_size: tamano (bytes) del storage word.
            //   bf_used: bits ya usados dentro del word.
            bool bf_active = false;
            uint32_t bf_offset = 0, bf_size = 0;
            uint8_t bf_used = 0;
            auto close_bf = [&]() {
                if (bf_active) {
                    offset = bf_offset + bf_size;
                    bf_active = false;
                    bf_used = 0;
                }
            };

            for (const auto &f : s->fields) {
                // Campo `static`: su storage es la global sintetica
                // `<Struct>__<campo>` (creada en el parser).  Aqui solo lo
                // registramos para resolver `Struct.campo` y lo EXCLUIMOS del
                // layout de instancia (no ocupa espacio en cada valor).
                if (f.is_static) {
                    StructFieldInfo sfi;
                    sfi.name = f.name;
                    sfi.type = type_from_node(f.type.get());
                    layout.static_fields.push_back(std::move(sfi));
                    continue;
                }
                // Campo `comptime`: existe SOLO en compile-time (lo consume el
                // codigo comptime, p.ej. un `comptime char* name` para un
                // hash). EXCLUIDO del layout de instancia; se registra aparte
                // para que un constructor/metodo comptime resuelva
                // `this.campo`.
                if (f.is_comptime) {
                    StructFieldInfo cfi;
                    cfi.name = f.name;
                    cfi.type = type_from_node(f.type.get());
                    cfi.is_comptime = true;
                    if (f.default_init) cfi.default_init = f.default_init.get();
                    layout.comptime_fields.push_back(std::move(cfi));
                    continue;
                }
                // Miembro ANONIMO C11 (`union { ... };` sin nombre): aplanar
                // sus campos en ESTE struct (accesibles como `parent.inner`).
                // El agregado ocupa espacio como un campo normal; sus campos se
                // copian al offset base + su offset interno.
                if (f.is_anonymous) {
                    close_bf();
                    Type at = type_from_node(f.type.get());
                    auto ita = (at.kind == PrimitiveKind::STRUCT)
                                   ? struct_layouts_.find(at.struct_name)
                                   : struct_layouts_.end();
                    if (ita == struct_layouts_.end()) {
                        diags_.error(f.loc,
                                     "agregado anonimo no resuelto en '" +
                                         s->name + "'");
                        continue;
                    }
                    const StructLayout &inner = ita->second;
                    uint32_t abase = offset;
                    if (!s->is_union && inner.align_bytes > 1 &&
                        abase % inner.align_bytes != 0)
                        abase +=
                            inner.align_bytes - (abase % inner.align_bytes);
                    for (const auto &inf : inner.fields) {
                        if (!seen_names.emplace(inf.name, true).second) {
                            diags_.error(f.loc,
                                         "campo '" + inf.name +
                                             "' del agregado anonimo colisiona "
                                             "con otro campo de '" +
                                             s->name + "'");
                            continue;
                        }
                        StructFieldInfo fi =
                            inf; // copia (nombre + tipo + size)
                        fi.offset = (s->is_union ? 0 : abase) + inf.offset;
                        layout.fields.push_back(std::move(fi));
                    }
                    if (s->is_union) {
                        if (inner.size_bytes > offset)
                            offset = inner.size_bytes;
                    } else {
                        offset = abase + inner.size_bytes;
                    }
                    if (inner.align_bytes > max_align)
                        max_align = inner.align_bytes;
                    continue;
                }
                if (!seen_names.emplace(f.name, true).second) {
                    diags_.error(f.loc, "campo duplicado en struct '" +
                                            s->name + "': '" + f.name + "'");
                    continue;
                }
                Type ft = type_from_node(f.type.get());
                if (ft.kind == PrimitiveKind::COUNT ||
                    ft.kind == PrimitiveKind::VOID) {
                    diags_.error(f.loc, "tipo invalido en campo '" + f.name +
                                            "' del struct '" + s->name + "'");
                    continue;
                }
                // Tamano y alineamiento del campo.  Para STRUCT anidado
                // consultamos su propio layout previamente registrado;
                // si aun no se registro (forward ref dentro del mismo
                // pase) emitimos error de orden de declaracion.
                uint32_t fsize = (uint32_t)primitive_size_bytes(ft.kind);
                /* Un `Optional` no siempre mide lo mismo: depende de lo que
                 * lleve dentro.  `primitive_size_bytes` solo recibe la especie,
                 * asi que no puede saberlo; hay que preguntarlo. */
                if (ft.kind == PrimitiveKind::OPTIONAL)
                    fsize = optional_layout(ft).bytes;
                /* La alineacion NO es el tamano.  Un `Result` mide veinticuatro
                 * -- tres palabras -- y se alinea a ocho; tomarla igual al
                 * tamano daba veinticuatro, que ni siquiera es potencia de dos,
                 * y un struct con un campo asi acababa midiendo setenta y dos
                 * bytes donde le bastan cuarenta.  El caso de las funciones ya
                 * estaba corregido a mano aqui debajo con este mismo motivo
                 * escrito; le pasaba a mas de un tipo. */
                uint32_t falign = (uint32_t)primitive_align_bytes(ft.kind);
                // Tipos funcion en un campo: cfn (`fn_is_raw`) = 1 puntero (8
                // bytes); fn (lambda fat) = par (fn_addr, env) = 16 bytes.
                if (ft.kind == PrimitiveKind::FUNCTION) {
                    fsize = ft.fn_is_raw ? 8 : 16;
                    falign = 8;
                }
                if (ft.kind == PrimitiveKind::STRUCT) {
                    auto it = struct_layouts_.find(ft.struct_name);
                    if (it != struct_layouts_.end()) {
                        fsize = it->second.size_bytes;
                        falign = it->second.align_bytes;
                    } else if (const EnumLayout *ie =
                                   find_enum_layout(ft.struct_name);
                               ie != nullptr) {
                        // enum ADT como campo: usa su layout de tagged-union
                        // (tag i64, 8 bytes), alineado a 8.  Un enum con
                        // backing
                        // (`: u8`) NO llega aqui: resuelve a su primitivo antes
                        // (kind entero, no STRUCT).  Solo se permite el enum
                        // PAYLOADLESS: su valor es un unico qword (el tag), asi
                        // que la asignacion/lectura del campo es una copia
                        // escalar. Un enum con payload requeriria copiar N
                        // qwords en el store/load del campo (lowering
                        // pendiente).
                        if (ie->max_payload_fields > 0) {
                            diags_.error(
                                f.loc,
                                "un enum con payload ('" + ft.struct_name +
                                    "') no puede usarse como campo de struct "
                                    "todavia; usa un puntero o un enum con "
                                    "backing entero (': u32')");
                            continue;
                        }
                        fsize = ie->size_bytes;
                        falign = 8;
                    } else {
                        diags_.error(
                            f.loc,
                            "struct '" + ft.struct_name +
                                "' debe declararse antes de usarse como campo");
                        continue;
                    }
                } else if (ft.kind == PrimitiveKind::ARRAY) {
                    // Array inline `T campo[N]` / multidimensional `T c[N][M]`:
                    // tamano = element_size * count (recursivo); align = del
                    // elemento.  Un array vacio (`T[]`) cuenta como puntero.
                    std::function<void(const Type &, uint32_t &, uint32_t &)>
                        size_align_of = [&](const Type &t, uint32_t &sz,
                                            uint32_t &al) {
                            if (t.kind == PrimitiveKind::STRUCT) {
                                auto it2 = struct_layouts_.find(t.struct_name);
                                if (it2 != struct_layouts_.end()) {
                                    sz = it2->second.size_bytes;
                                    al = it2->second.align_bytes;
                                } else {
                                    sz = 1;
                                    al = 1;
                                }
                            } else if (t.kind == PrimitiveKind::ARRAY) {
                                uint32_t es = 1, ea = 1;
                                if (t.pointee)
                                    size_align_of(*t.pointee, es, ea);
                                sz = t.array_size > 0 ? es * t.array_size : 8;
                                al = ea;
                            } else {
                                sz = (uint32_t)primitive_size_bytes(t.kind);
                                /* La alineacion NO es el tamano: un `Result`
                                 * mide veinticuatro y se alinea a ocho.
                                 * Tomarla igual al tamano daba un numero que
                                 * ni es potencia de dos, y un struct con un
                                 * campo asi media setenta y dos bytes donde le
                                 * bastan cuarenta. */
                                al = (uint32_t)primitive_align_bytes(t.kind);
                            }
                            if (sz == 0) sz = 1;
                            if (al == 0) al = 1;
                        };
                    uint32_t es = 1, ea = 1;
                    if (ft.pointee) size_align_of(*ft.pointee, es, ea);
                    fsize = ft.array_size > 0 ? es * ft.array_size : 8;
                    falign = ea;
                }
                if (fsize == 0) {
                    // Defensa: deberia haber sido atrapado arriba.
                    fsize = 1;
                }
                if (falign == 0) falign = 1;
                // Newtype con @align(N): forzar alineacion del campo.
                // El tamano sigue siendo el del underlying (el align
                // solo afecta el padding antes del campo + el align
                // del struct contenedor).
                if (ft.align_override > 0 && ft.align_override > falign) {
                    falign = ft.align_override;
                }

                // Bit field handling.
                if (f.bit_width > 0) {
                    // Solo permitido sobre tipos integer.
                    if (!is_integral(ft.kind)) {
                        diags_.error(f.loc, "bit field '" + f.name +
                                                "' requiere tipo integer");
                        continue;
                    }
                    const uint8_t bw = f.bit_width;
                    const uint8_t cap = (uint8_t)(fsize * 8u);
                    if (bw > cap) {
                        diags_.error(f.loc,
                                     "bit_width (" + std::to_string((int)bw) +
                                         ") excede el tamano del tipo (" +
                                         std::to_string((int)cap) + ")");
                        continue;
                    }
                    // Si hay storage abierto del MISMO tamano y queda hueco,
                    // empaquetar.  Si no, abrir nuevo storage en posicion
                    // alineada.
                    if (!bf_active || bf_size != fsize ||
                        (bf_used + bw) > cap) {
                        close_bf();
                        // Padding hasta multiplo de falign.
                        if (offset % falign != 0) {
                            offset += falign - (offset % falign);
                        }
                        bf_active = true;
                        bf_offset = offset;
                        bf_size = fsize;
                        bf_used = 0;
                        if (falign > max_align) max_align = falign;
                    }
                    StructFieldInfo fi;
                    fi.name = f.name;
                    fi.type = ft;
                    fi.offset = bf_offset;
                    fi.size = bf_size;
                    fi.bit_offset = bf_used;
                    fi.bit_width = bw;
                    fi.default_init = f.default_init.get();
                    // Overlay: un bitfield puede llevar @offset dinamico
                    // (`u8 mod : 2 @offset { ... }`).  Sin copiar el resolver,
                    // la direccion del BYTE contenedor caeria al offset
                    // estatico (bf_offset), que solo coincide con el resolver
                    // por casualidad -> escrituras al byte equivocado.  El
                    // bit_offset (posicion DENTRO del byte) sigue siendo el que
                    // asigna el empaquetador secuencial (correcto para
                    // bitfields consecutivos que comparten byte, p.ej.
                    // mod/reg/rm).
                    if (s->is_overlay) {
                        fi.offset_block = f.offset_block.get();
                        fi.offset_expr = f.offset_expr.get();
                        fi.endian = f.endian;
                        fi.endian_expr = f.endian_expr.get();
                    }
                    layout.fields.push_back(std::move(fi));
                    bf_used += bw;
                    continue;
                }
                // Campo normal: cerrar bit field activo si lo hay.
                close_bf();

                // Padding hasta multiplo de falign (solo struct: en union todos
                // los campos van a offset 0, no hay layout secuencial).
                if (!s->is_union && offset % falign != 0) {
                    offset += falign - (offset % falign);
                }

                StructFieldInfo fi;
                fi.name = f.name;
                fi.type = ft;
                // Overlay: el offset lo da @offset(N) explicito (no el
                // auto-layout secuencial).  Si un campo de un overlay no lo
                // trae, es error (F1).
                if (s->is_overlay) {
                    // Array (F3b): copiar count/stride; el offset es `pos`.
                    fi.array_count = f.array_count.get();
                    fi.array_stride = f.array_stride.get();
                    fi.element_block = f.element_block.get();
                    fi.is_array = f.is_array;
                    fi.endian = f.endian;
                    fi.endian_expr = f.endian_expr.get();
                    if (f.element_block) {
                        // Array POR-ELEMENTO `@element { }`: la direccion de
                        // cada elemento la da el resolver; no hay offset/pos de
                        // tabla.
                        fi.offset = 0;
                    } else if (f.offset_block) {
                        // Resolver de BLOQUE (F3): `@offset { ... }`.  Devuelve
                        // la direccion final; se resuelve en tiempo de acceso.
                        fi.offset = 0;
                        fi.offset_block = f.offset_block.get();
                    } else if (f.offset_expr) {
                        // Offset DINAMICO: `@offset(hermano + N)`.  Se resuelve
                        // en tiempo de acceso; @c offset base queda a 0.
                        fi.offset = 0;
                        fi.offset_expr = f.offset_expr.get();
                    } else if (f.explicit_offset < 0) {
                        diags_.error(
                            f.loc,
                            "campo '" + f.name +
                                "' de un @overlay "
                                "struct requiere @offset(N), @offset(expr) "
                                "o @offset { ... }");
                        fi.offset = 0;
                    } else {
                        fi.offset = (uint32_t)f.explicit_offset;
                    }
                } else {
                    // union: todos los campos comparten offset 0.
                    fi.offset = s->is_union ? 0 : offset;
                }
                fi.size = fsize;
                fi.default_init = f.default_init.get();
                layout.fields.push_back(std::move(fi));

                if (s->is_union) {
                    // El "tamano" de la union es el del campo mayor.
                    if (fsize > offset) offset = fsize;
                } else {
                    offset += fsize;
                }
                if (falign > max_align) max_align = falign;
            }
            // Cerrar bit field activo al final del struct.
            close_bf();
            // Tamano total redondeado al max_align (compatible con
            // arrays de structs).
            if (max_align > 1 && offset % max_align != 0) {
                offset += max_align - (offset % max_align);
            }
            // Overlay: es una VISTA = un puntero (host) de 8 bytes; no un
            // buffer de @c offset bytes.  Los offsets de campo apuntan a
            // memoria ajena.
            if (s->is_overlay) {
                layout.is_overlay = true;
                layout.size_bytes = 8;
                layout.align_bytes = 8;
                // Huella estatica = max(offset+size) sobre los campos de offset
                // constante.  `sizeof(overlay)` la devuelve para reservar el
                // buffer de respaldo exacto al CREAR la vista.
                uint32_t extent = 0;
                for (auto &fi : layout.fields) {
                    if (fi.offset_expr || fi.offset_block) continue; // dinamico
                    uint32_t end = fi.offset + fi.size;
                    if (end > extent) extent = end;
                }
                if (extent % 8 != 0) extent += 8 - (extent % 8);
                layout.overlay_extent = extent;
                // F4: registrar el layout PROVISIONALMENTE (copia) ANTES de
                // chequear los resolvers, para que un resolver `@offset { }`
                // pueda acceder a arrays hermanos via `this.<array>[i].<campo>`
                // (la maquinaria overlay resuelve el array mirando el layout de
                // la vista, que debe estar registrado).  El registro definitivo
                // (con metodos) se hace mas abajo con std::move.
                struct_layouts_[s->name] = layout;
                // Chequeo de los resolvedores dinamicos (`@offset(hermano+N)` y
                // `@offset { ... }`): los nombres desnudos resuelven contra los
                // campos hermanos + el puntero `base` de la vista.  Metemos
                // cada campo (como entero) y `base` (u64) en un scope temporal.
                // La expr debe evaluar a un entero; el bloque devuelve una
                // direccion.
                bool any_dyn = false;
                for (auto &f : s->fields)
                    if (f.offset_expr || f.offset_block || f.array_stride ||
                        f.element_block || f.endian_expr) {
                        any_dyn = true;
                        break;
                    }
                if (any_dyn) {
                    push_scope();
                    for (auto &fi : layout.fields) {
                        Symbol sym;
                        sym.kind = SymbolKind::Variable;
                        sym.type = fi.type;
                        (void)declare(fi.name, sym);
                    }
                    auto is_int_kind = [](PrimitiveKind k) {
                        return k == PrimitiveKind::I8 ||
                               k == PrimitiveKind::I16 ||
                               k == PrimitiveKind::I32 ||
                               k == PrimitiveKind::I64 ||
                               k == PrimitiveKind::U8 ||
                               k == PrimitiveKind::U16 ||
                               k == PrimitiveKind::U32 ||
                               k == PrimitiveKind::U64;
                    };
                    for (auto &f : s->fields) {
                        if (f.offset_expr) {
                            // La expr es un OFFSET (base no esta en scope
                            // aqui).
                            Type ot = check_expr(f.offset_expr.get());
                            if (!is_int_kind(ot.kind))
                                diags_.error(f.loc,
                                             "el @offset(expr) del campo '" +
                                                 f.name +
                                                 "' debe evaluar a un entero");
                        } else if (f.offset_block) {
                            // F4: DIFERIR el check del resolver de bloque a un
                            // 2o pase (tras construir TODOS los layouts), para
                            // que pueda usar `parent<Otro>().campo` aunque Otro
                            // se defina despues (dependencia circular).  El
                            // check real (scope base/this/self + parent
                            // detection) lo hace
                            // check_overlay_resolvers_deferred().
                            pending_overlay_resolvers_.push_back({s, &f});
                        }
                        // Array (F3b): count y stride pueden referenciar
                        // hermanos; deben evaluar a enteros.
                        if (f.array_count) {
                            Type ct = check_expr(f.array_count.get());
                            if (!is_int_kind(ct.kind))
                                diags_.error(f.loc, "el count del array '" +
                                                        f.name +
                                                        "' debe ser entero");
                        }
                        if (f.array_stride) {
                            Type st2 = check_expr(f.array_stride.get());
                            if (!is_int_kind(st2.kind))
                                diags_.error(f.loc, "el stride del array '" +
                                                        f.name +
                                                        "' debe ser entero");
                        }
                        // F4/@element: resolver POR-ELEMENTO -> pase diferido
                        // (con `index` en scope, y puede usar parent<T>()).
                        if (f.element_block) {
                            pending_overlay_resolvers_.push_back({s, &f});
                        }
                        // F5 @endian(expr): la expr ve los hermanos + comptime
                        // consts; debe evaluar a entero/bool (nonzero = big).
                        if (f.endian_expr) {
                            Type et = check_expr(f.endian_expr.get());
                            if (!is_int_kind(et.kind) &&
                                et.kind != PrimitiveKind::BOOL)
                                diags_.error(
                                    f.loc, "el @endian(expr) del campo '" +
                                               f.name +
                                               "' debe evaluar a bool/entero");
                        }
                    }
                    pop_scope();
                }
            } else {
                layout.size_bytes = offset;
                layout.align_bytes = max_align;
            }
            // Campos `comptime`: se apilan DESPUES del tamano runtime para que
            // la ComptimeVM les de un slot temporal al evaluar el ctor/metodo
            // comptime (leer/escribir `this.<campo_comptime>`).  Cada uno
            // recibe un @c offset alineado a su tipo; @c comptime_size_bytes
            // cubre la instancia runtime + la cola comptime.  La
            // materializacion solo copia @c size_bytes (la cola comptime se
            // descarta).
            {
                uint32_t coff = layout.size_bytes;
                for (auto &cf : layout.comptime_fields) {
                    uint32_t csize = 8; // punteros/enteros anchos por defecto
                    uint32_t calign = 8;
                    if (cf.type.kind == PrimitiveKind::PTR ||
                        cf.type.kind == PrimitiveKind::ARRAY) {
                        csize = 8;
                        calign = 8;
                    } else if (cf.type.kind == PrimitiveKind::STRUCT) {
                        auto it2 = struct_layouts_.find(cf.type.struct_name);
                        if (it2 != struct_layouts_.end()) {
                            csize = it2->second.size_bytes;
                            calign = it2->second.align_bytes;
                        }
                    } else {
                        uint32_t ps =
                            (uint32_t)primitive_size_bytes(cf.type.kind);
                        if (ps > 0) {
                            csize = ps;
                            calign = ps;
                        }
                    }
                    if (calign > 1 && (coff % calign) != 0)
                        coff += calign - (coff % calign);
                    cf.offset = coff;
                    cf.size = csize;
                    coff += csize;
                }
                layout.comptime_size_bytes = coff;
            }
            // `@align(N)` a nivel de struct (C __declspec(align(N))/_Alignas):
            // fuerza la alineacion a max(natural, N) y padea el tamano a un
            // multiplo de esa alineacion.  No reduce nunca la alineacion
            // natural.
            if (s->attr_align > 0) {
                uint32_t a = s->attr_align;
                if (a > layout.align_bytes) layout.align_bytes = a;
                const uint32_t al = layout.align_bytes;
                if (al > 0 && (layout.size_bytes % al) != 0)
                    layout.size_bytes += al - (layout.size_bytes % al);
            }
            /* preservar la marca @Introspect que
             * la pre-pasada copio del AST.  Como aqui sobrescribimos
             * la entrada con un layout local fresco, hay que re-copiar
             * el flag desde el StructDecl. */
            layout.is_introspect = s->is_introspect;
            //  M6.a L.3.
            layout.is_public = s->is_public;

            // Registrar metodos del struct (value-type, dispatch
            // estatico).  Cada metodo baja a una funcion libre
            // <Struct>__<metodo>(this_ptr, args...).  No hay vtable
            // ni constructores; @c defining_class lleva el nombre del
            // struct para que el lowering construya el label correcto.
            std::unordered_map<std::string, bool> seen_methods;
            // Slot de vtable para los metodos @Virtual, asignado por orden de
            // aparicion.  Como el flatten deja los metodos raiz-primero y el
            // override reemplaza EN SU POSICION, el slot de un metodo virtual
            // coincide entre la base y el derivado -> dispatch por Base*
            // correcto.
            uint32_t vslot = 0;
            for (const auto &m_uptr : s->methods) {
                auto *m = m_uptr.get();
                if (!m) continue;
                // Metodo generico template (`R metodo<U>(...)`, #4): NO se
                // anyade al layout (es plantilla).  Cada `obj.metodo<U>()`
                // clona una version concreta via monomorphize_method.
                if (!m->method_type_params.empty()) continue;
                /* Un struct no sobrecarga: un nombre, un metodo.  Los
                 * constructores son la unica excepcion, y lo que los distingue
                 * es el NUMERO de argumentos -- literalmente su identidad,
                 * porque el simbolo que se emite es `<T>__ctor_<aridad>`.
                 *
                 * Por eso entran en la comprobacion con esa clave, y no con su
                 * nombre.  Antes quedaban FUERA por completo, asi que dos
                 * constructores de la misma aridad se emitian los dos con el
                 * mismo nombre -- dos etiquetas iguales que el enlazador se
                 * tragaba -- y la llamada se iba a uno cualquiera: con
                 * `V(f64,f64)` y `V(i64,i64)`, escribir `V(1.0, 2.0)` acababa
                 * en el de enteros.  Sin una sola queja.
                 *
                 * Distinguirlos ademas por tipos seria darle al struct una
                 * sobrecarga que no tiene en ningun otro sitio -- ni sus
                 * metodos ni las funciones libres la tienen -- , asi que lo que
                 * se hace es DECIRLO donde se escribe. */
                const std::string clave =
                    m->is_constructor
                        ? ("ctor/" + std::to_string(m->params.size()))
                        : m->name;
                if (!seen_methods.emplace(clave, true).second) {
                    if (m->is_constructor) {
                        diags_.error(
                            m->loc,
                            "el struct '" + s->name +
                                "' ya tiene un constructor de " +
                                std::to_string(m->params.size()) +
                                " argumentos; en un struct los constructores se"
                                " distinguen por el numero de argumentos, no"
                                " por sus tipos");
                    } else {
                        diags_.error(m->loc, "metodo duplicado en struct '" +
                                                 s->name + "': '" + m->name +
                                                 "'");
                    }
                    continue;
                }
                ClassMethodInfo mi = make_method_info(*m, s->name);
                /* El hueco en la tabla solo lo tienen los virtuales, y se
                 * reparten EN ORDEN de declaracion: eso es propio de montar el
                 * layout, no de la ficha del metodo. */
                if (m->is_virtual) mi.vtable_index = vslot++;
                // copy-hook (copy-constructor implicito).  El compilador lo
                // invoca en cada sitio de copia del struct.
                if (m->name == "__clone__") layout.has_copy_hook = true;
                layout.methods.push_back(std::move(mi));
            }

            // Sobrescribir la entrada vacia pre-registrada con el layout
            // ya completo.  Usar operator[] = porque la entrada existe.
            struct_layouts_[s->name] = std::move(layout);
        } else if (decl->kind == ast::NodeKind::EnumDecl) {
            // Registrar el enum (ADT) con su layout: max_payload determina
            // el tamano del slot (8 + 8*N_payload_fields_max) y los tags.
            auto *en = static_cast<ast::EnumDecl *>(decl.get());
            // L2.3: enums template (con type_params) NO se procesan como
            // concretos; se monomorphizan on demand.
            if (!en->type_params.empty()) continue;
            // Pre-pasada creo entradas vacias en enum_layouts_; un
            // enum es "ya registrado" si tiene variantes.  Para
            // colisiones cross-tipo, struct/class no deberian
            // existir con el mismo nombre.
            auto it_pre_e = enum_layouts_.find(en->name);
            const bool already_done = (it_pre_e != enum_layouts_.end() &&
                                       !it_pre_e->second.variants.empty());
            auto it_struct_done = struct_layouts_.find(en->name);
            auto it_class_done = class_layouts_.find(en->name);
            const bool struct_collision =
                (it_struct_done != struct_layouts_.end() &&
                 !it_struct_done->second.fields.empty());
            const bool class_collision =
                (it_class_done != class_layouts_.end() &&
                 !it_class_done->second.name.empty() &&
                 it_class_done->second.name == en->name &&
                 (!it_class_done->second.fields.empty() ||
                  !it_class_done->second.methods.empty()));
            // L2.3: enums monomorphizados ya tienen su layout completo
            // (lo construye monomorphize_enum); skip silente sin error.
            if (monomorphized_.count(en->name)) {
                continue;
            }
            if (already_done || struct_collision || class_collision) {
                diags_.error(en->loc, "tipo redeclarado: '" + en->name +
                                          "' (colision con struct/class/enum)");
                continue;
            }
            EnumLayout elay;
            elay.name = en->name;
            // C-style: enum con VALOR (`enum Op : u8 { ... }`, `enum M : f64
            // {..}`, `enum V : string {..}`).  El backing puede ser entero,
            // float o string; cada variante es una CONSTANTE de ese tipo.
            const bool valued =
                !en->backing_type.empty() || en->c_style_auto_backing;
            elay.is_valued = valued;
            bool backing_is_int = false;
            bool backing_is_float = false;
            bool backing_is_string = false;
            bool backing_is_user = false; // struct o clase
            // C-style `typedef enum { ... }` sin `: tipo`: se infiere el
            // backing del KIND de los valores.  Caso normal (C): todas las
            // variantes son constantes ENTERAS (o no llevan valor) -> se
            // pre-pliegan con auto-incremento y se elige el ancho minimo que
            // cubre el rango (i32 si todo cabe en int; si no u32; si no i64),
            // imitando C.  Si en cambio los valores son STRING, se infiere
            // backing `string`.  Los backings de struct/array/float requieren
            // la forma explicita `enum Name : Tipo { ... }` (un enum bare no
            // puede inferirlos).
            std::vector<int64_t> auto_vals;
            bool auto_have_vals = false;
            if (en->c_style_auto_backing) {
                // Detectar el kind mirando el primer valor explicito.
                bool any_str = false, any_bad = false;
                for (const auto &vd : en->variants) {
                    if (!vd.value_expr) continue;
                    const ComptimeEvalResult r =
                        comptime_eval_expr(*this, vd.value_expr.get());
                    if (r.is_str) {
                        any_str = true;
                    } else if (r.is_array || r.is_struct || !r.ok) {
                        any_bad = true;
                    }
                    break; // basta el primero para decidir el kind.
                }
                if (any_str) {
                    // Backing string: cada variante requiere valor explicito;
                    // el bucle principal baja value_ast (no hay
                    // auto-incremento).
                    en->backing_type = "string";
                } else if (any_bad) {
                    diags_.error(en->loc,
                                 "un enum C-style 'typedef enum { ... }' solo "
                                 "infiere backing entero o string; para struct/"
                                 "array/float usa la forma explicita "
                                 "'enum " +
                                     en->name + " : Tipo { ... }'");
                    en->backing_type = "i32"; // recuperacion.
                } else {
                    // Entero (o sin valores): pre-plegar con auto-incremento.
                    auto_vals.reserve(en->variants.size());
                    int64_t nv = 0;
                    for (const auto &vd : en->variants) {
                        if (vd.value_expr) {
                            const ComptimeEvalResult r =
                                comptime_eval_expr(*this, vd.value_expr.get());
                            if (r.ok && !r.is_str && !r.is_array &&
                                !r.is_struct) {
                                nv = r.value;
                            } else {
                                diags_.error(vd.loc,
                                             "el valor de la variante '" +
                                                 vd.name +
                                                 "' debe ser una "
                                                 "constante entera");
                            }
                        }
                        auto_vals.push_back(nv);
                        nv = nv + 1;
                    }
                    auto_have_vals = true;
                    // Elegir el ancho minimo que cubre el rango (C-style).
                    int64_t lo = 0, hi = 0;
                    for (int64_t v : auto_vals) {
                        if (v < lo) lo = v;
                        if (v > hi) hi = v;
                    }
                    std::string inferred;
                    if (lo < 0) {
                        // Con negativos hay que usar tipo con signo.
                        if (lo >= INT32_MIN && hi <= INT32_MAX)
                            inferred = "i32";
                        else
                            inferred = "i64";
                    } else {
                        // Todos no negativos.  C prefiere int; ensancha si no
                        // cabe.
                        if (hi <= INT32_MAX)
                            inferred = "i32";
                        else if (hi <= static_cast<int64_t>(UINT32_MAX))
                            inferred = "u32";
                        else
                            inferred = "i64";
                    }
                    en->backing_type =
                        inferred; // fijar para el resto del flujo.
                }
            }
            if (valued) {
                // Un alias vale como tipo base: `typedef u32 DWORD;` y luego
                // `enum Stream : DWORD` es lo natural al declarar las
                // constantes de un sistema.  Antes solo se aceptaba el nombre
                // primitivo, asi que el alias -- que ES ese primitivo, ya
                // aplanado en la tabla -- se rechazaba.  Se resuelve aqui, sin
                // tocar `backing_type`, que sigue siendo el nombre que escribio
                // el usuario para los mensajes.
                {
                    auto al = type_aliases_.find(en->backing_type);
                    if (al != type_aliases_.end() &&
                        al->second.nominal_id == 0 &&
                        (is_integer_kind(al->second.kind) ||
                         al->second.kind == PrimitiveKind::F32 ||
                         al->second.kind == PrimitiveKind::F64 ||
                         al->second.kind == PrimitiveKind::STRING)) {
                        en->backing_type = primitive_name(al->second.kind);
                    }
                }
                elay.backing = prim_kind_from_name(en->backing_type);
                backing_is_int = is_integer_kind(elay.backing);
                backing_is_float = (elay.backing == PrimitiveKind::F32 ||
                                    elay.backing == PrimitiveKind::F64);
                backing_is_string = (elay.backing == PrimitiveKind::STRING);
                if (!backing_is_int && !backing_is_float &&
                    !backing_is_string) {
                    // Tipo de USUARIO: struct o clase ya registrada.  Un valor
                    // del enum ES un valor de ese tipo.
                    if (struct_layouts_.count(en->backing_type)) {
                        elay.backing = PrimitiveKind::STRUCT;
                        elay.backing_type_name = en->backing_type;
                        backing_is_user = true;
                    } else if (class_layouts_.count(en->backing_type)) {
                        elay.backing = PrimitiveKind::CLASS;
                        elay.backing_type_name = en->backing_type;
                        backing_is_user = true;
                    } else {
                        diags_.error(
                            en->loc,
                            "el tipo base de un enum debe ser entero, "
                            "float, string o un struct/clase existente: '" +
                                en->backing_type + "'");
                        elay.backing = PrimitiveKind::I64;
                        backing_is_int = true;
                    }
                }
            }
            (void)backing_is_user;
            std::unordered_map<std::string, bool> seen_v;
            uint32_t max_pl = 0;
            int64_t next_val =
                0; // auto-incremento para enums con valor entero.
            for (size_t vi = 0; vi < en->variants.size(); ++vi) {
                const auto &vd = en->variants[vi];
                if (!seen_v.emplace(vd.name, true).second) {
                    diags_.error(vd.loc, "variante duplicada en enum '" +
                                             en->name + "': '" + vd.name + "'");
                    continue;
                }
                EnumVariantInfo vi_info;
                vi_info.name = vd.name;
                vi_info.tag = static_cast<uint32_t>(vi);
                // Valor de la variante (solo enums con tipo base).
                if (valued) {
                    if (!vd.field_types.empty()) {
                        diags_.error(vd.loc,
                                     "una variante de un enum con valor (tipo "
                                     "base) no puede llevar payload: '" +
                                         vd.name + "'");
                    }
                    if (backing_is_int) {
                        // Entero: se pliega a constante (soporta
                        // auto-incremento). Si el backing se infirio (C-style
                        // auto), reusamos los valores ya plegados en el
                        // pre-pase para no duplicar evaluacion ni diagnosticos.
                        if (auto_have_vals) {
                            vi_info.int_value = auto_vals[vi];
                        } else {
                            if (vd.value_expr) {
                                const ComptimeEvalResult r = comptime_eval_expr(
                                    *this, vd.value_expr.get());
                                if (!r.ok || r.is_str || r.is_array ||
                                    r.is_struct) {
                                    diags_.error(vd.loc,
                                                 "el valor de la variante '" +
                                                     vd.name +
                                                     "' debe ser una "
                                                     "constante entera");
                                } else {
                                    next_val = r.value;
                                }
                            }
                            vi_info.int_value = next_val;
                            next_val = next_val + 1;
                        }
                    } else {
                        // Float/string/...: el valor es OBLIGATORIO y
                        // explicito; el lowering baja la expresion AST tal cual
                        // (reusa el lowering de literales
                        // float/string/init-list).
                        if (!vd.value_expr) {
                            diags_.error(vd.loc,
                                         "la variante '" + vd.name +
                                             "' de un enum con tipo base '" +
                                             en->backing_type +
                                             "' requiere un valor explicito "
                                             "(= <valor>)");
                        } else {
                            vi_info.value_ast = vd.value_expr.get();
                        }
                    }
                }
                vi_info.field_types.reserve(vd.field_types.size());
                for (const auto &ft : vd.field_types) {
                    vi_info.field_types.push_back(type_from_node(ft.get()));
                }
                if (vi_info.field_types.size() > max_pl) {
                    max_pl = static_cast<uint32_t>(vi_info.field_types.size());
                }
                elay.variants.push_back(std::move(vi_info));
            }
            elay.max_payload_fields = max_pl;
            // Layout: 8 (tag) + 8 * max_payload_fields.  Cada payload
            // se padea a 8 bytes para uniformidad del offset acceso
            // (i*8 a partir de offset 8) sin tablas por variante.
            elay.size_bytes = 8 + 8 * max_pl;
            /* preservar marca @Introspect del AST. */
            elay.is_introspect = en->is_introspect;
            //  M6.a L.3.
            elay.is_public = en->is_public;
            // Sobrescribir entrada vacia pre-registrada.
            enum_layouts_[en->name] = std::move(elay);
        } else if (decl->kind == ast::NodeKind::ClassDecl) {
            auto *c = static_cast<ast::ClassDecl *>(decl.get());
            // generics: templates (con type_params) y especializaciones (#7)
            // no son clases concretas.  Solo se procesa la version
            // monomorphizada (que tiene type_params vacio y no es spec).
            if (!c->type_params.empty() || c->is_specialization) continue;
            // Pre-pasada creo entradas vacias en class_layouts_; un
            // class es "ya completada" si tiene fields o methods.
            auto it_pre_c = class_layouts_.find(c->name);
            if (it_pre_c != class_layouts_.end() &&
                (!it_pre_c->second.fields.empty() ||
                 !it_pre_c->second.methods.empty())) {
                diags_.error(c->loc, "clase redeclarada: '" + c->name + "'");
                continue;
            }

            // Layout de campos: cada slot ocupa 8 bytes (igual que el
            // ClassRegistry) por simplicidad y alineacion.  El offset
            // efectivo en el ObjectHeader lo recalcula el ClassRegistry
            // sumandole sizeof(ObjectHeader); aqui guardamos el offset
            // relativo al payload para que el lowering pueda emitir
            // GETFIELD <off>.
            ClassLayout layout;
            layout.name = c->name;
            layout.super_name = c->super_name;
            layout.interface_names = c->interface_names;
            layout.is_interface = c->is_interface;
            /* preservar la marca @Introspect del AST. */
            layout.is_introspect = c->is_introspect;
            layout.is_aspect = c->is_aspect;
            layout.is_final = c->is_final;
            //  M6.a L.3: visibilidad cross-module.
            layout.is_public = c->is_public;

            // Herencia: si hay super_name resuelto, copiamos sus fields
            // y metodos al inicio del layout actual.  Los offsets
            // continuan tras los heredados; los slots del vtable se
            // mantienen para que un metodo no override lo mantenga
            // como heredado.  Override por nombre se resuelve mas
            // abajo cuando procesamos los metodos propios.
            const ClassLayout *super_layout = nullptr;
            if (!c->super_name.empty()) {
                //  M.L30: detector de ciclos de herencia.
                // Recorrer la cadena super_name -> super_name de la
                // clase candidata.  Si llegamos al name de la clase
                // que estamos procesando, hay un ciclo (e.g. A:B y
                // B:A o A:B:C:A).  Limite defensivo de 256 niveles
                // para evitar loops espurios en layouts mal formados.
                {
                    const std::string &self_name = c->name;
                    std::string cur = c->super_name;
                    for (int depth = 0; depth < 256; ++depth) {
                        if (cur == self_name) {
                            diags_.error(
                                c->loc,
                                "ciclo de herencia detectado: la clase '" +
                                    self_name +
                                    "' aparece en su propia "
                                    "cadena de superclases");
                            break;
                        }
                        auto it_cycle = class_layouts_.find(cur);
                        if (it_cycle == class_layouts_.end()) break;
                        if (it_cycle->second.super_name.empty()) break;
                        cur = it_cycle->second.super_name;
                    }
                }
                auto it_super = class_layouts_.find(c->super_name);
                if (it_super == class_layouts_.end()) {
                    diags_.error(
                        c->loc,
                        "superclase '" + c->super_name +
                            "' no encontrada (debe declararse antes que '" +
                            c->name + "')");
                } else if (it_super->second.is_interface && !c->is_interface) {
                    // El identificador despues de `:` resulto ser una
                    // interfaz, no una clase.  Promocionamos a la lista
                    // de interfaces implementadas y vaciamos super_name
                    // (la clase queda sin super, equivalente a Object).
                    // Esto permite la sintaxis natural Vesta
                    // `class X : IFoo, IBar` sin requerir un super
                    // dummy en primera posicion.
                    layout.interface_names.insert(
                        layout.interface_names.begin(), c->super_name);
                    layout.super_name.clear();
                } else if (it_super->second.is_final) {
                    /* Una clase final no se extiende.  El rechazo no es solo
                     * por respetar lo que la declaracion promete: el bajado se
                     * FIA de esa promesa para despachar sus metodos con llamada
                     * directa en vez de por tabla.  Dejar pasar esto daria un
                     * programa en el que el metodo de la derivada no se ejecuta
                     * nunca, sin un solo aviso. */
                    diags_.error(c->loc,
                                 "'" + c->name + "' no puede heredar de '" +
                                     c->super_name +
                                     "': esta declarada final.\n"
                                     "  sugerencia: quita el `final` de '" +
                                     c->super_name +
                                     "', o usa composicion en vez de herencia");
                } else {
                    super_layout = &it_super->second;
                    // Copiar fields heredados (offsets ya incluyen header).
                    for (const auto &sf : super_layout->fields) {
                        layout.fields.push_back(sf);
                    }
                    for (const auto &ssf : super_layout->static_fields) {
                        layout.static_fields.push_back(ssf);
                    }
                    // Copiar metodos heredados con sus vtable_index.
                    for (const auto &sm : super_layout->methods) {
                        layout.methods.push_back(sm);
                    }
                    // Marcar cuantos elementos son heredados para que
                    // el lowering de __module_init los omita (los
                    // anyade ya define_class en el loader).
                    layout.inherited_field_count =
                        static_cast<uint32_t>(super_layout->fields.size());
                    layout.inherited_static_field_count = static_cast<uint32_t>(
                        super_layout->static_fields.size());
                }
            }

            std::unordered_map<std::string, bool> seen_field;
            for (const auto &fi : layout.fields)
                seen_field[fi.name] = true;
            // Los campos de instancia van DESPUES del ObjectHeader
            // (24 bytes) en el layout en memoria.  El frontend usa
            // estos offsets directamente con xchg cur0,r_obj +
            // addcur, asi que deben incluir el header para apuntar
            // al field real.  Los static_fields parten de 0
            // (offset relativo al bloque static_data).
            uint32_t off_inst =
                static_cast<uint32_t>(sizeof(loader::ObjectHeader));
            if (super_layout) {
                // Continuar tras los fields heredados.
                off_inst +=
                    static_cast<uint32_t>(super_layout->fields.size()) * 8;
            }
            uint32_t off_stat = 0;
            for (const auto &f : c->fields) {
                if (!seen_field.emplace(f.name, true).second) {
                    diags_.error(f.loc, "campo duplicado en clase '" + c->name +
                                            "': '" + f.name + "'");
                    continue;
                }
                Type ft = type_from_node(f.type.get());
                if (ft.kind == PrimitiveKind::COUNT) {
                    diags_.error(f.loc, "tipo invalido en campo '" + f.name +
                                            "' de la clase '" + c->name + "'");
                    continue;
                }
                StructFieldInfo fi;
                fi.name = f.name;
                fi.type = ft;
                fi.size = 8; // todos los slots de instancia ocupan 8 bytes
                if (f.is_static) {
                    fi.offset = off_stat;
                    off_stat += 8;
                    layout.static_fields.push_back(std::move(fi));
                } else {
                    fi.offset = off_inst;
                    off_inst += 8;
                    layout.fields.push_back(std::move(fi));
                }
            }
            layout.size_bytes = off_inst;

            // Resumen de metodos (incluyendo constructor).  Override:
            // si un metodo de la subclase tiene el mismo nombre que
            // uno heredado, REEMPLAZA el slot del super (mismo
            // vtable_index).  El AST lo marca con is_override pero
            // tambien aceptamos override implicito si el nombre coincide.
            std::unordered_map<std::string, bool> seen_method;
            for (const auto &m_inh : layout.methods)
                seen_method[m_inh.name] = true;
            for (size_t mi = 0; mi < c->methods.size(); ++mi) {
                const auto *m = c->methods[mi].get();
                const std::string &mname = m->name;

                // Metodo generico template (`R metodo<U>(...)`, #4): NO se
                // anyade al layout.  Es una plantilla; cada llamada
                // `obj.metodo<U>()` clona una version concreta
                // (`metodo_<U>`) que SI entra al layout via
                // monomorphize_method.  Mismo trato que structs/clases
                // template (que tampoco se procesan como concretos).
                if (!m->method_type_params.empty()) continue;

                // Detectar override: ya existe un metodo con ese nombre
                // (heredado del super).  Buscar su slot.
                int override_idx = -1;
                if (!m->is_constructor) {
                    for (size_t j = 0; j < layout.methods.size(); ++j) {
                        if (layout.methods[j].name == mname) {
                            override_idx = static_cast<int>(j);
                            break;
                        }
                    }
                }

                if (override_idx >= 0) {
                    // Override de metodo heredado.  Validar que el
                    // metodo del super NO es final.
                    if (layout.methods[override_idx].is_final) {
                        diags_.error(
                            m->loc,
                            "no se puede sobrescribir el metodo final '" +
                                mname + "' de la superclase");
                        continue;
                    }
                    // Reemplazar el slot manteniendo vtable_index.
                    ClassMethodInfo mi_info = make_method_info(*m, c->name);
                    mi_info.is_constructor = false; // un ctor no sobrescribe
                    mi_info.vtable_index =
                        layout.methods[override_idx].vtable_index;
                    layout.methods[override_idx] = std::move(mi_info);
                    continue;
                }

                // Metodo nuevo (no override).  Si is_override estaba
                // marcado pero no hay metodo con ese nombre en la
                // jerarquia, error.
                // Bug fix 2026-05-23: @Override tambien valido si
                // implementa un metodo de cualquier interface declarada
                // por la clase (interface_names).  Sin esto, el patron
                // estandar Java/C# `class X : IFoo { @Override foo() }`
                // se rechazaba con "metodo 'foo' no existe en la jerarquia"
                // forzando a quitar @Override del codigo.
                if (m->is_override) {
                    bool found_in_iface = false;
                    // Usar layout.interface_names (con promote `IFoo` desde
                    // super_name aplicada) en lugar de c->interface_names
                    // (que es el AST raw sin promote).
                    for (const auto &iname : layout.interface_names) {
                        auto it_if = class_layouts_.find(iname);
                        if (it_if == class_layouts_.end()) continue;
                        for (const auto &im : it_if->second.methods) {
                            if (im.name == mname) {
                                found_in_iface = true;
                                break;
                            }
                        }
                        if (found_in_iface) break;
                    }
                    if (!found_in_iface) {
                        diags_.error(
                            m->loc,
                            "@Override: el metodo '" + mname +
                                "' no existe en la jerarquia de la clase");
                    }
                }

                /* Los constructores tambien entran, con una clave propia.
                 *
                 * Hoy una clase solo puede tener UNO: su simbolo es
                 * `<Clase>__ctor`, sin nada que distinga a uno de otro -- ni
                 * siquiera el numero de argumentos, a diferencia del struct,
                 * cuyo simbolo si lo lleva.  Declarar dos emitia dos etiquetas
                 * con el MISMO nombre y la llamada se iba a una cualquiera:
                 * teniendo `K()` y `K(i64)`, `new K(9)` no ejecutaba el que se
                 * habia escrito.  Y en silencio.
                 *
                 * Se dice donde se escribe, en vez de dar un objeto mal
                 * construido.  Mientras tanto, varias formas de construir se
                 * escriben como metodos `static` que devuelven la clase, que si
                 * tienen nombre propio y funcionan hoy. */
                const std::string clave_m =
                    m->is_constructor ? std::string("\1ctor") : mname;
                if (!seen_method.emplace(clave_m, true).second) {
                    if (m->is_constructor) {
                        diags_.error(m->loc,
                                     "la clase '" + c->name +
                                         "' ya tiene un constructor; por ahora"
                                         " una clase solo admite uno.  Para"
                                         " varias formas de construirla, usa"
                                         " metodos 'static' que la devuelvan");
                    } else {
                        diags_.error(m->loc, "metodo duplicado en clase '" +
                                                 c->name + "': '" + mname +
                                                 "'");
                    }
                    continue;
                }
                ClassMethodInfo mi_info = make_method_info(*m, c->name);
                mi_info.vtable_index =
                    static_cast<uint32_t>(layout.methods.size());

                // fix12 - detectar ctores trivial zero-init.  Si el
                // body es solo `this.field = 0|0.0|null|false` para varios
                // fields, podemos saltar la callvirt al ctor en runtime
                // porque el GC ya hace memset a 0 del payload.  Solo aplica
                // si la clase NO tiene super custom (super == "Object" o
                // ausente): si hay super con ctor no-trivial, hay que llamarlo.
                if (m->is_constructor && m->body &&
                    (c->super_name.empty() || c->super_name == "Object")) {
                    bool zero_init_only = true;
                    for (const auto &stmt : m->body->body) {
                        if (!stmt) {
                            zero_init_only = false;
                            break;
                        }
                        // Aceptamos solo ExprStmt con AssignExpr de la forma
                        // <FieldAccess>.field = literal_zero
                        if (stmt->kind != ast::NodeKind::ExprStmt) {
                            zero_init_only = false;
                            break;
                        }
                        auto *es = static_cast<ast::ExprStmt *>(stmt.get());
                        if (!es->expr ||
                            es->expr->kind != ast::NodeKind::AssignExpr) {
                            zero_init_only = false;
                            break;
                        }
                        auto *ae =
                            static_cast<ast::AssignExpr *>(es->expr.get());
                        if (ae->op != ast::AssignOp::Assign) {
                            zero_init_only = false;
                            break;
                        }
                        // target: FieldAccessExpr cuyo base es ThisExpr.
                        if (!ae->target || ae->target->kind !=
                                               ast::NodeKind::FieldAccessExpr) {
                            zero_init_only = false;
                            break;
                        }
                        auto *fa = static_cast<ast::FieldAccessExpr *>(
                            ae->target.get());
                        if (!fa->base ||
                            fa->base->kind != ast::NodeKind::ThisExpr) {
                            zero_init_only = false;
                            break;
                        }
                        // value: literal cero/false/null.
                        if (!ae->value) {
                            zero_init_only = false;
                            break;
                        }
                        const ast::Expr *v = ae->value.get();
                        bool is_zero_lit = false;
                        if (v->kind == ast::NodeKind::IntLitExpr) {
                            is_zero_lit =
                                (static_cast<const ast::IntLitExpr *>(v)
                                     ->value == 0);
                        } else if (v->kind == ast::NodeKind::FloatLitExpr) {
                            is_zero_lit =
                                (static_cast<const ast::FloatLitExpr *>(v)
                                     ->value == 0.0);
                        } else if (v->kind == ast::NodeKind::BoolLitExpr) {
                            is_zero_lit =
                                (static_cast<const ast::BoolLitExpr *>(v)
                                     ->value == false);
                        } else if (v->kind == ast::NodeKind::NullLitExpr) {
                            is_zero_lit = true;
                        }
                        if (!is_zero_lit) {
                            zero_init_only = false;
                            break;
                        }
                    }
                    // Body vacio tambien cuenta como zero-init trivial.
                    mi_info.is_zero_init_ctor = zero_init_only;
                }

                layout.methods.push_back(std::move(mi_info));
            }

            // precomputar has_destructor para que las rules de
            // escape (check_assign) lo consulten en O(1) sin iterar
            // metodos.  Importante: heredamos del super, asi que si la
            // clase no declara su propio dtor pero el super si lo tiene,
            // se considera destructible (el dtor del super correra).
            for (const auto &mi : layout.methods) {
                if (mi.is_destructor) {
                    layout.has_destructor = true;
                    break;
                }
            }

            // Sobrescribir entrada vacia pre-registrada con el layout
            // ya completo.
            class_layouts_[c->name] = std::move(layout);
        }
    }

    // NS.6-ext: APENDEAR los metodos de `extension Tipo { ... }` e
    // `impl Concept for Tipo { ... }` al layout del tipo destino (struct o
    // clase, LOCAL o IMPORTADO -- ambos viven en
    // struct_layouts_/class_layouts_). Dispatch ESTATICO: los metodos son CALL
    // directos a `<clave>__metodo` (defining_class = la clave del layout,
    // mangled si es importado).  Cross- modulo: el tipo importado ya tiene su
    // layout via .vxi, y el metodo se emite como funcion libre en ESTE modulo.
    // Coherencia (Vesta): permisivo; error duro solo en la colision real (mismo
    // nombre+aridad ya presente).
    for (const auto &decl : mod_.decls) {
        if (!decl) continue;
        const bool is_ext = decl->kind == ast::NodeKind::ExtensionDecl;
        const bool is_impl = decl->kind == ast::NodeKind::ImplDecl;
        if (!is_ext && !is_impl) continue;
        std::string target_src, concept_name;
        const std::vector<std::unique_ptr<ast::ClassMethodDecl>> *methods =
            nullptr;
        if (is_ext) {
            auto *e = static_cast<const ast::ExtensionDecl *>(decl.get());
            target_src = e->target_type;
            methods = &e->methods;
        } else {
            auto *im = static_cast<const ast::ImplDecl *>(decl.get());
            target_src = im->target_type;
            concept_name = im->concept_name;
            methods = &im->methods;
        }
        // Resolver el nombre destino a la clave del layout (directo o via
        // resolve_type_string para tipos importados/cualificados).
        std::string key;
        std::vector<ClassMethodInfo> *dst = nullptr;
        bool is_class_target = false;
        auto try_key = [&](const std::string &k) -> bool {
            auto sit = struct_layouts_.find(k);
            if (sit != struct_layouts_.end()) {
                key = k;
                dst = &sit->second.methods;
                is_class_target = false;
                return true;
            }
            auto cit = class_layouts_.find(k);
            if (cit != class_layouts_.end()) {
                key = k;
                dst = &cit->second.methods;
                is_class_target = true;
                return true;
            }
            return false;
        };
        if (!try_key(target_src)) {
            // Nombre cualificado `mod.Tipo` -> clave mangled `mod__Tipo`.
            std::string mangled = target_src;
            for (size_t p = mangled.find('.'); p != std::string::npos;
                 p = mangled.find('.'))
                mangled.replace(p, 1, "__");
            if (mangled == target_src || !try_key(mangled)) {
                const Type rt = resolve_type_string(target_src);
                if (rt.kind == PrimitiveKind::STRUCT ||
                    rt.kind == PrimitiveKind::CLASS)
                    try_key(rt.struct_name);
            }
        }
        if (!dst) {
            diags_.error(decl->loc,
                         std::string(is_impl ? "impl" : "extension") +
                             " sobre un tipo desconocido: '" + target_src +
                             "'");
            continue;
        }
        for (const auto &m_uptr : *methods) {
            auto *m = m_uptr.get();
            if (!m) continue;
            if (!m->method_type_params.empty()) continue; // template: on-use
            bool collision = false;
            for (const auto &ex : *dst) {
                if (ex.name == m->name &&
                    ex.param_types.size() == m->params.size()) {
                    collision = true;
                    break;
                }
            }
            if (collision) {
                diags_.error(m->loc, "el metodo '" + m->name + "' (aridad " +
                                         std::to_string(m->params.size()) +
                                         ") ya existe en el tipo '" + key +
                                         "'; una extension/impl no puede "
                                         "redefinirlo");
                continue;
            }
            ClassMethodInfo mi = make_method_info(*m, key);
            mi.is_extension = true; // label = <key>__<name>, despacho estatico
            dst->push_back(std::move(mi));
        }
        if (is_impl && !concept_name.empty())
            impl_conformances_[key].insert(concept_name);
    }

    // Fase 2b ownership: destructibilidad de STRUCTS (value-types).  Se computa
    // ANTES que la de clases para que una clase con un campo struct
    // destructible lo vea (incluido el dtor SINTETIZADO de un struct con
    // composicion).  Un struct es destructible si tiene `~Struct()` propio O un
    // campo struct destructible.  @c struct_destructible se reusa abajo en el
    // fixpoint de clase.  Tras esto se sintetiza el dtor implicito de los
    // structs.
    auto struct_destructible = [&](const std::string &n) -> bool {
        auto it = struct_layouts_.find(n);
        if (it == struct_layouts_.end()) return false;
        if (it->second.has_destructible_field) return true;
        for (const auto &m : it->second.methods)
            if (m.is_destructor) return true;
        return false;
    };
    for (bool changed = true; changed;) {
        changed = false;
        for (auto &kv : struct_layouts_) {
            StructLayout &sl = kv.second;
            if (sl.has_destructible_field) continue;
            for (const auto &f : sl.fields) {
                // Campo unique<T>: posee un recurso -> struct destructible.
                if (f.type.kind == PrimitiveKind::UNIQUE_PTR) {
                    sl.has_destructible_field = true;
                    changed = true;
                    break;
                }
                // Campo shared<T> (H5): refcount no-GC -> struct destructible
                // (su dtor decrementa el bloque de control).
                if (f.type.kind == PrimitiveKind::SHARED_PTR) {
                    sl.has_destructible_field = true;
                    changed = true;
                    break;
                }
                if (f.type.kind != PrimitiveKind::STRUCT) continue;
                if (struct_destructible(f.type.struct_name)) {
                    sl.has_destructible_field = true;
                    changed = true;
                    break;
                }
            }
        }
    }
    // Sintesis del dtor implicito para structs con campo destructible y sin
    // `~Struct()` propio (mismo patron que las clases).  Tras esto, cualquier
    // struct destructible tiene un metodo is_destructor -> @c
    // struct_destructible y el fixpoint de clase lo detectan.
    for (auto &mod_node : mod_.decls) {
        if (!mod_node || mod_node->kind != ast::NodeKind::StructDecl) continue;
        auto *sd = static_cast<ast::StructDecl *>(mod_node.get());
        auto it_lay = struct_layouts_.find(sd->name);
        if (it_lay == struct_layouts_.end()) continue;
        StructLayout &lay = it_lay->second;
        if (!lay.has_destructible_field) continue;
        bool has_dtor = false;
        for (const auto &m : lay.methods)
            if (m.is_destructor) {
                has_dtor = true;
                break;
            }
        if (has_dtor) continue; // el user ya declaro uno
        auto dtor = std::make_unique<ast::ClassMethodDecl>();
        dtor->loc = sd->loc;
        dtor->name = "__dtor";
        dtor->is_destructor = true;
        dtor->access = 0;
        dtor->body = std::make_unique<ast::BlockStmt>();
        dtor->body->loc = sd->loc;
        sd->methods.push_back(std::move(dtor));
        ClassMethodInfo mi;
        mi.name = "__dtor";
        mi.is_destructor = true;
        mi.defining_class = sd->name;
        mi.return_type = Type{PrimitiveKind::VOID};
        mi.source_file = sd->loc.file;
        mi.source_line = sd->loc.line;
        lay.methods.push_back(std::move(mi));
    }

    // punto-fijo de @c has_destructible_field.  Una clase tiene
    // @c has_destructible_field si alguno de sus fields (incluidos los
    // heredados del super) es de tipo CLASS y esa clase tiene
    // @c has_destructor o @c has_destructible_field a su vez, O es un campo
    // FUNCTION (closure) o un campo STRUCT destructible (Fase 2b).
    //
    // Iteramos hasta estabilizar para soportar referencias mutuamente
    // recursivas (LinkedList { Node head; } / Node { Node next; }).
    // En cada iteracion, si una clase X gana @c has_destructible_field,
    // las clases que la contienen como field tambien lo ganan.  Como
    // efecto del cierre transitivo, cualquier ciclo se resuelve en N
    // iteraciones donde N es la profundidad maxima de la cadena.
    for (bool changed = true; changed;) {
        changed = false;
        for (auto &kv : class_layouts_) {
            ClassLayout &cl = kv.second;
            if (cl.is_interface || cl.is_runtime_predefined) continue;
            if (cl.has_destructible_field) continue; // ya maximo
            for (const auto &f : cl.fields) {
                // Un campo FUNCTION (lambda) guarda un closure cuyo slot+env
                // (RAW_ALLOC host owned) libera el destructor (RAII, sin GC).
                if (f.type.kind == PrimitiveKind::FUNCTION &&
                    !f.type.fn_is_raw) {
                    cl.has_destructible_field = true;
                    changed = true;
                    break;
                }
                // Fase 2b: un campo STRUCT destructible (con dtor propio o
                // sintetizado) -> la clase lo libera en su dtor augmentado.
                if (f.type.kind == PrimitiveKind::STRUCT) {
                    if (struct_destructible(f.type.struct_name)) {
                        cl.has_destructible_field = true;
                        changed = true;
                        break;
                    }
                    continue;
                }
                // Un campo unique<T> POSEE un recurso: el dtor del contenedor
                // lo libera (con el liberador de por defecto o con el suyo).
                if (f.type.kind == PrimitiveKind::UNIQUE_PTR) {
                    cl.has_destructible_field = true;
                    changed = true;
                    break;
                }
                // Un campo shared<T> (H5): el dtor del contenedor decrementa
                // el refcount del bloque de control (free-when-0).
                if (f.type.kind == PrimitiveKind::SHARED_PTR) {
                    cl.has_destructible_field = true;
                    changed = true;
                    break;
                }
                // Solo fields de tipo CLASS aportan destructibilidad.
                if (f.type.kind != PrimitiveKind::CLASS) continue;
                auto it_inner = class_layouts_.find(f.type.struct_name);
                if (it_inner == class_layouts_.end()) continue;
                const ClassLayout &inner = it_inner->second;
                if (inner.has_destructor || inner.has_destructible_field) {
                    cl.has_destructible_field = true;
                    changed = true;
                    break;
                }
            }
        }
    }

    // sintesis del destructor implicito.  Para cada clase con
    // @c has_destructible_field == true y SIN destructor declarado por
    // el usuario, anadimos un ClassMethodDecl sintetico con body vacio
    // y @c is_destructor = true.  El lowering augmenta el body de TODOS
    // los destructores (sintetizados o no) con CALLVIRT a los dtors de
    // los fields destructibles, asi que un cuerpo vacio basta para
    // disparar la cadena RAII recursiva.
    //
    // Tras la sintesis actualizamos @c has_destructor a true (el flag
    // representa la presencia EFECTIVA de un destructor invocable, sea
    // user o sintetico).  Esto unifica todas las consultas downstream.
    for (auto &mod_node : mod_.decls) {
        if (!mod_node || mod_node->kind != ast::NodeKind::ClassDecl) continue;
        auto *cd = static_cast<ast::ClassDecl *>(mod_node.get());
        auto it_lay = class_layouts_.find(cd->name);
        if (it_lay == class_layouts_.end()) continue;
        ClassLayout &lay = it_lay->second;
        if (lay.is_interface || lay.is_runtime_predefined) continue;
        if (!lay.has_destructible_field) continue;
        if (lay.has_destructor) continue; // user ya declaro uno

        // Anadir ClassMethodDecl sintetica al AST con body vacio.
        auto dtor = std::make_unique<ast::ClassMethodDecl>();
        dtor->loc = cd->loc;
        dtor->name = "__dtor";
        dtor->is_destructor = true;
        dtor->access = 0;
        dtor->body = std::make_unique<ast::BlockStmt>();
        dtor->body->loc = cd->loc;
        cd->methods.push_back(std::move(dtor));

        // Reflejarlo en el ClassLayout: anadir un ClassMethodInfo y
        // marcar @c has_destructor.  El @c vtable_index sigue al final
        // de los metodos existentes.
        ClassMethodInfo mi_info;
        mi_info.name = "__dtor";
        mi_info.is_destructor = true;
        mi_info.is_constructor = false;
        mi_info.is_static = false;
        mi_info.is_final = false;
        mi_info.is_inline = false;
        mi_info.defining_class = cd->name;
        mi_info.return_type = Type{PrimitiveKind::VOID};
        mi_info.vtable_index = static_cast<uint32_t>(lay.methods.size());
        mi_info.source_file = cd->loc.file;
        mi_info.source_line = cd->loc.line;
        lay.methods.push_back(std::move(mi_info));
        lay.has_destructor = true;
    }

    // -----------------------------------------------------------------
    // Validacion de implementacion de interfaces.
    //
    // Para cada clase NO-interface con `class X : Base, IFoo, IBar`,
    // verificar que todos los metodos abstractos de IFoo y IBar
    // (incluyendo los heredados por sus super-interfaces) estan
    // presentes en X (o en algun ancestro) con firma compatible.
    // Las interfaces que no encuentre se reportan como error claro.
    // -----------------------------------------------------------------
    for (auto &kv : class_layouts_) {
        const ClassLayout &cl = kv.second;
        if (cl.is_interface) continue; // las interfaces no implementan otras
        for (const std::string &iname : cl.interface_names) {
            auto it_iface = class_layouts_.find(iname);
            if (it_iface == class_layouts_.end()) {
                diags_.error(SourceLoc{}, "interfaz '" + iname +
                                              "' usada por '" + cl.name +
                                              "' no esta declarada");
                continue;
            }
            if (!it_iface->second.is_interface) {
                diags_.error(SourceLoc{},
                             "'" + iname + "' usada como interfaz por '" +
                                 cl.name + "' es una clase, no una interfaz");
                continue;
            }
            // Verificar que cada metodo abstracto de la interfaz esta
            // implementado en cl (mismo nombre + aridad + tipos).
            const ClassLayout &iface = it_iface->second;
            for (const ClassMethodInfo &im : iface.methods) {
                bool found = false;
                for (const ClassMethodInfo &cm : cl.methods) {
                    if (cm.name != im.name) continue;
                    if (cm.param_types.size() != im.param_types.size())
                        continue;
                    // Comparacion shallow de firmas: kinds primarios.
                    bool sigs_ok = (cm.return_type.kind == im.return_type.kind);
                    for (size_t i = 0; sigs_ok && i < cm.param_types.size();
                         ++i) {
                        if (cm.param_types[i].kind != im.param_types[i].kind) {
                            sigs_ok = false;
                        }
                    }
                    if (sigs_ok) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    diags_.error(SourceLoc{},
                                 "la clase '" + cl.name +
                                     "' no implementa el metodo '" + im.name +
                                     "' requerido por la interfaz '" + iname +
                                     "'");
                }
            }
        }
    }

    for (auto &decl : mod_.decls) {
        if (!decl) continue;
        if (decl->kind == ast::NodeKind::FunctionDecl) {
            auto *fn = static_cast<ast::FunctionDecl *>(decl.get());
            // #7: las especializaciones de funcion NO se registran como
            // simbolo global (comparten nombre con el primario): solo el
            // primario declara el nombre; las specs se eligen al
            // monomorphizar.  Sin esto -> "redefinicion de simbolo".
            if (fn->is_specialization) continue;
            /* comptime fn -- registrar para que las llamadas
             * desde contextos comptime puedan interpretar el body.
             * NO se registra como Symbol::Function regular porque
             * NO debe llamarse desde codigo runtime.  Pero sigue
             * declarando el nombre en el scope global para que el
             * type checker resuelva el ident en el callee de las
             * llamadas (comptime_eval_expr discrimina luego). */
            if (fn->is_comptime) {
                register_comptime_fn(fn->name, fn);
                /* Tambien registramos un Symbol::Function dummy para
                 * que `lookup(fn->name)` lo resuelva.  El sig real
                 * importa poco porque la llamada nunca sale a IR. */
                FunctionSig sig_ct;
                sig_ct.return_type = type_from_node(fn->return_type.get());
                sig_ct.param_types.reserve(fn->params.size());
                for (auto &p : fn->params) {
                    sig_ct.param_types.push_back(type_from_node(p->type.get()));
                }
                Symbol s;
                s.kind = SymbolKind::Function;
                s.sig_index = (uint32_t)function_sigs_.size();
                sig_by_name_[fn->name] = s.sig_index;
                function_sigs_.push_back(std::move(sig_ct));
                if (!declare(fn->name, s)) {
                    diags_.error(fn->loc, "comptime fn: redefinicion de '" +
                                              fn->name + "'");
                }
                continue;
            }

            FunctionSig sig;
            // Tipo de retorno no reconocido -> error CLARO (en vez de tratarlo
            // como void en silencio y disparar luego "return con valor en
            // void"). Se omite en funciones TEMPLATE (con parametros de tipo):
            // ahi el tipo de retorno puede ser un placeholder (`T`, `Caja<T>`)
            // que no resuelve hasta monomorphizar; las instancias concretas
            // (sin type_params) si se validan.
            if (fn->return_type && fn->type_params.empty()) {
                const std::string bad =
                    first_unresolved_type(fn->return_type.get());
                if (!bad.empty())
                    diags_.error(fn->loc, "tipo de retorno no reconocido: '" +
                                              bad + "'");
            }
            Type ret_t = type_from_node(fn->return_type.get());
            // Mejora II: si la funcion es @Async, el wrapper publico
            // visible al callsite devuelve Future<T> donde T es el tipo
            // declarado del @c return.  El bytecode del wrapper sigue
            // produciendo un i64 (handle), pero al frontend le
            // interesa preservar T para que `T r = await fn();` se
            // tipo-checkee correctamente.
            if (fn->is_async) {
                sig.return_type = Type::make_future(std::move(ret_t));
            } else {
                sig.return_type = std::move(ret_t);
            }
            sig.param_types.reserve(fn->params.size());
            for (size_t pi = 0; pi < fn->params.size(); ++pi) {
                auto &p = fn->params[pi];
                // Variadico CRUDO (`...` pelado): sin tipo ni nombre.  No es un
                // slot de param -- son N args extra crudos.  Solo valido como
                // ultimo param de una funcion @Naked.
                if (p->is_raw_variadic) {
                    if (pi + 1 != fn->params.size())
                        diags_.error(p->loc,
                                     "el variadico crudo '...' debe ser el "
                                     "ultimo parametro");
                    if (!fn->is_naked)
                        diags_.error(
                            p->loc,
                            "un variadico crudo '...' solo es valido en una "
                            "funcion @Naked (el cuerpo asm accede a los "
                            "registros de argumento del ABI directamente)");
                    sig.is_variadic = true;
                    sig.is_raw_variadic = true;
                    continue; // no anñade param_type.
                }
                Type pt = type_from_node(p->type.get());
                // ABI custom (register("rXX") en el param): validar que el
                // registro sea reconocido -> error temprano y claro.
                if (!p->abi_reg.empty() &&
                    asm_canonical_reg(p->abi_reg).empty())
                    diags_.error(
                        p->loc,
                        "register(\"" + p->abi_reg + "\") en el parametro '" +
                            p->name + "': '" + p->abi_reg +
                            "' no es un registro reconocido (x86-64: rax..r15;"
                            " x86-32: eax/ecx/edx/ebx/esi/edi; xmm/ymm/zmm)");
                // Guardar el registro del ABI custom en forma CANONICA de 64
                // bits (eax/ax/al -> rax): asi el .vxi y todos los consumidores
                // del codegen (canon_gp_to_mreg del CALLIND, del prologo del
                // callee) lo reconocen igual en x86-64 y x86-32.  Sin esto, un
                // `register("eax")` del `int 0x80` x86-32 quedaba como "eax",
                // canon_gp_to_mreg("eax")=-1 -> el ABI custom se ignoraba en el
                // CALLIND cross-modulo y los args iban a los registros/pila
                // equivocados.  Vacio (param sin register) queda vacio.
                const std::string p_abi = p->abi_reg.empty()
                                              ? std::string()
                                              : asm_canonical_reg(p->abi_reg);
                if (p->is_variadic) {
                    // Variadico (`T... name`, ultimo param): el callee lo
                    // recibe como `T*` (puntero al array empaquetado por el
                    // caller); el numero de elementos se lee con vacount().
                    if (pi + 1 != fn->params.size())
                        diags_.error(p->loc, "el parametro variadico '" +
                                                 p->name +
                                                 "' debe ser el ultimo");
                    sig.is_variadic = true;
                    sig.variadic_elem = pt;
                    sig.param_types.push_back(Type::make_ptr(pt));
                    sig.param_abi_regs.push_back(p_abi);
                } else {
                    sig.param_types.push_back(pt);
                    sig.param_abi_regs.push_back(p_abi);
                }
            }
            // Normalizar: si ningun param declaro ABI custom, dejar el vector
            // vacio (== ABI estandar; consistente con el operator== de Type).
            {
                bool any_abi = false;
                for (const auto &r : sig.param_abi_regs)
                    if (!r.empty()) {
                        any_abi = true;
                        break;
                    }
                if (!any_abi) sig.param_abi_regs.clear();
            }

            // Bug/feature 198: propagar @Naked a la firma para que el lowering
            // enrute las llamadas al dispatcher nativo (interp/JIT).
            sig.is_naked = fn->is_naked;

            Symbol s;
            s.kind = SymbolKind::Function;
            s.sig_index = (uint32_t)function_sigs_.size();
            sig_by_name_[fn->name] = s.sig_index;
            function_sigs_.push_back(std::move(sig));
            if (!declare(fn->name, s)) {
                // Bug fix 2026-05-23: forward declaration -- si el simbolo
                // ya existe Y este es un forward decl (sin body), OK.
                // Si la PREVIA era forward y esta tiene body, tambien OK
                // (es la definicion completando la forward).  Solo error
                // si AMBAS tienen body (redefinicion real).
                if (!fn->is_forward_decl) {
                    // Verificar si el simbolo existente era un forward decl.
                    const Symbol *prev = lookup(fn->name);
                    bool prev_is_forward = false;
                    if (prev && prev->kind == SymbolKind::Function) {
                        for (auto &d2 : mod_.decls) {
                            if (!d2 || d2->kind != ast::NodeKind::FunctionDecl)
                                continue;
                            auto *prev_fn =
                                static_cast<ast::FunctionDecl *>(d2.get());
                            if (prev_fn != fn && prev_fn->name == fn->name &&
                                prev_fn->is_forward_decl) {
                                prev_is_forward = true;
                                break;
                            }
                        }
                    }
                    if (!prev_is_forward) {
                        diags_.error(
                            fn->loc,
                            "redefinicion de simbolo a nivel global: '" +
                                fn->name + "'");
                    }
                }
            }
        } else if (decl->kind == ast::NodeKind::GlobalVarDecl) {
            auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
            Symbol s;
            s.kind = SymbolKind::Variable;
            s.type = type_from_node(gv->type.get());
            s.is_const = gv->is_const;
            if (!declare(gv->name, s)) {
                diags_.error(gv->loc,
                             "redefinicion de simbolo a nivel global: '" +
                                 gv->name + "'");
            }
        } else if (decl->kind == ast::NodeKind::ExternFnDecl) {
            // FFI declarativo: registrar como Symbol::Function con
            // FunctionSig::extern_lib != "" para que el lowering emita
            // CALLN @Method("<lib>:<name>") en vez de CALLVM al llamarla.
            auto *efd = static_cast<ast::ExternFnDecl *>(decl.get());
            FunctionSig sig;
            sig.return_type = type_from_node(efd->return_type.get());
            sig.param_types.reserve(efd->params.size());
            for (auto &p : efd->params) {
                Type pt = type_from_node(p->type.get());
                // Un extern no tiene cuerpo, asi que no pasa por
                // declare_params_in_scope y hay que preguntarlo aqui.  Y es
                // justo donde MAS importa: aqui la marca no es un contrato que
                // alguien vaya a comprobar contra el codigo, es lo unico que se
                // sabe de esa funcion.
                check_param_dir_(p->name, p->dir, p->loc, pt);
                sig.param_types.push_back(pt);
            }
            sig.extern_lib = efd->lib;
            Symbol s;
            s.kind = SymbolKind::Function;
            s.sig_index = (uint32_t)function_sigs_.size();
            sig_by_name_[efd->name] = s.sig_index;
            function_sigs_.push_back(std::move(sig));
            if (!declare(efd->name, s)) {
                diags_.error(efd->loc, "redefinicion de simbolo extern: '" +
                                           efd->name + "'");
            }
        }
    }
    // F4: 2o pase de resolvers de overlay `@offset { }`, ahora que TODOS los
    // layouts estan construidos (permite parent<Otro>() con dependencia
    // circular).
    check_overlay_resolvers_deferred();
    // Fase 1 interop C: con todos los structs ya registrados, cachear su
    // categoria (C-compat vs gestionado) inferida de los campos.
    compute_struct_categories();
}

// ---------------------------------------------------------------------
// F4: 2o pase -- chequea los resolvers `@offset { }` de overlay tras
// construir todos los layouts.  Reconstruye el scope (siblings + base +
// this/self) y detecta parent<T>() para marcar el campo resolver.
// ---------------------------------------------------------------------
void TypeChecker::check_overlay_resolvers_deferred() {
    for (auto &pr : pending_overlay_resolvers_) {
        const ast::StructDecl *s = pr.first;
        const ast::StructFieldDecl *f = pr.second;
        // Resolver de campo (@offset{}) o POR-ELEMENTO (@element{}).
        const bool is_element = (f->element_block != nullptr);
        ast::BlockStmt *block =
            is_element ? f->element_block.get() : f->offset_block.get();
        if (!block) continue;
        auto it = struct_layouts_.find(s->name);
        if (it == struct_layouts_.end()) continue;
        StructLayout &lay = it->second;
        push_scope();
        // Hermanos (como enteros / su tipo) para los nombres desnudos.
        for (auto &fi : lay.fields) {
            Symbol sym;
            sym.kind = SymbolKind::Variable;
            sym.type = fi.type;
            (void)declare(fi.name, sym);
        }
        const Type saved_ret = current_fn_return_type_;
        current_fn_return_type_ = Type{PrimitiveKind::U64};
        push_scope();
        Symbol bsym;
        bsym.kind = SymbolKind::Variable;
        bsym.type = Type{PrimitiveKind::U64};
        (void)declare("base", bsym);
        Symbol tsym;
        tsym.kind = SymbolKind::Variable;
        tsym.type = Type{};
        tsym.type.kind = PrimitiveKind::STRUCT;
        tsym.type.struct_name = s->name;
        (void)declare("this", tsym);
        // @element: `index` (i64) del elemento a resolver, en scope.
        if (is_element) {
            Symbol isym;
            isym.kind = SymbolKind::Variable;
            isym.type = Type{PrimitiveKind::I64};
            (void)declare("index", isym);
        }
        overlay_resolver_active_ = true;
        overlay_resolver_used_parent_ = false;
        overlay_resolver_parent_type_.clear();
        check_block(const_cast<ast::BlockStmt *>(block),
                    Type{PrimitiveKind::U64});
        if (overlay_resolver_used_parent_) {
            for (auto &lf : lay.fields)
                if (lf.name == f->name) {
                    lf.resolver_uses_parent = true;
                    lf.resolver_parent_type = overlay_resolver_parent_type_;
                    break;
                }
        }
        overlay_resolver_active_ = false;
        current_fn_return_type_ = saved_ret;
        pop_scope();
        pop_scope();
    }
    pending_overlay_resolvers_.clear();
}

// ---------------------------------------------------------------------
// Fase 1 interop C: clasificacion de tipos (C-representable / gestionado).
// ---------------------------------------------------------------------

const StructLayout *
TypeChecker::resolve_struct_layout(const std::string &name) const {
    auto it = struct_layouts_.find(name);
    return it == struct_layouts_.end() ? nullptr : &it->second;
}

bool TypeChecker::type_is_c_representable(const Type &t) const {
    StructResolver r = [this](const std::string &n) {
        return resolve_struct_layout(n);
    };
    return vx::is_c_representable(t, r);
}

bool TypeChecker::type_is_managed(const Type &t) const {
    StructResolver r = [this](const std::string &n) {
        return resolve_struct_layout(n);
    };
    return vx::is_managed(t, r);
}

void TypeChecker::compute_struct_categories() {
    // El clasificador recursa via el resolver (que ve el mapa COMPLETO), asi
    // que el orden de iteracion no importa; los structs no se contienen a si
    // mismos por valor (el type checker ya lo rechazaria).
    StructResolver r = [this](const std::string &n) {
        return resolve_struct_layout(n);
    };
    for (auto &kv : struct_layouts_) {
        StructLayout &lay = kv.second;
        const Type st{PrimitiveKind::STRUCT, kv.first};
        lay.cat_c_representable = vx::is_c_representable(st, r);
        lay.cat_managed = vx::is_managed(st, r);
        lay.cat_computed = true;
    }
}

// ---------------------------------------------------------------------
// Pase 2: cuerpos de funciones.
// ---------------------------------------------------------------------

/**
 * @brief Indica si un tipo compuesto declara `toString()`.
 *
 * Se busca tambien en la cadena de bases: un `toString()` escrito una sola vez
 * en la base sirve a toda la familia, que es como debe escribirse.
 *
 * @param t Tipo a consultar (STRUCT o CLASS).
 * @return true si el tipo, o alguno de sus ancestros, tiene el metodo.
 */
bool TypeChecker::type_declares_to_string(const Type &t) const {
    if (t.struct_name.empty()) return false;
    if (t.kind == PrimitiveKind::STRUCT) {
        std::string cur = t.struct_name;
        for (int depth = 0; depth < 64 && !cur.empty(); ++depth) {
            auto it = struct_layouts_.find(cur);
            if (it == struct_layouts_.end()) return false;
            for (const auto &m : it->second.methods)
                if (m.name == "toString") return true;
            cur = it->second.super_name;
        }
        return false;
    }
    std::string cur = t.struct_name;
    for (int depth = 0; depth < 64 && !cur.empty(); ++depth) {
        auto it = class_layouts_.find(cur);
        if (it == class_layouts_.end()) return false;
        for (const auto &m : it->second.methods)
            if (m.name == "toString") return true;
        cur = it->second.super_name;
    }
    return false;
}

/**
 * @brief Anota en @p mi los tipos de los parametros de @p m.
 *
 * Estaba escrito dos veces -- una para el metodo que sobrescribe a otro y otra
 * para el que no --, que son el mismo trabajo con distinto destino.
 *
 * Ademas es el punto donde se ve un parametro que la declaracion admite y el
 * resto del compilador todavia no sabe llevar hasta el final: un variadico en
 * un metodo se PARSEA y se DECLARA -- desde que la lista de parametros dejo de
 * tener una version pobre para los metodos --, pero la comprobacion de la
 * llamada y el empaquetado de los argumentos solo existen para las funciones
 * sueltas.  Decirlo aqui, una vez y con su motivo, es mejor que dejar que
 * reviente mas tarde contando los argumentos.
 *
 * @param m  El metodo declarado.
 * @param mi Donde anotar los tipos.
 */
void TypeChecker::record_method_params(const ast::ClassMethodDecl &m,
                                       ClassMethodInfo &mi) {
    mi.param_types.reserve(m.params.size());
    for (size_t pi = 0; pi < m.params.size(); ++pi) {
        const auto &p = m.params[pi];
        const Type pt = type_from_node(p->type.get());
        if (p->is_variadic) {
            /* El que recoge los que sobren tiene que ser el ULTIMO: si no, no
             * habria forma de saber donde acaban los suyos y empiezan los del
             * siguiente. */
            if (pi + 1 != m.params.size())
                diags_.error(p->loc, "el parametro variadico '" + p->name +
                                         "' debe ser el ultimo");
            mi.is_variadic = true;
            mi.variadic_elem = pt;
            /* Dentro del cuerpo `xs` es la direccion del array que monto quien
             * llamo, no un `T`. */
            mi.param_types.push_back(Type::make_ptr(pt));
            continue;
        }
        mi.param_types.push_back(pt);
    }
}

/**
 * @brief Construye la ficha de un metodo a partir de su declaracion.
 *
 * Estaba escrito dos veces -- para el metodo que sobrescribe a otro y para el
 * que no -- y a la copia del override le faltaban tres cosas: si es un
 * DESTRUCTOR, y el fichero y la linea donde se escribio.
 *
 * Lo del destructor no era cosmetico.  Una clase derivada que declara el suyo
 * reemplaza la ficha heredada por una que ya no dice que lo es, asi que al
 * salir de un ambito no se llamaba a NINGUNO -- ni al propio ni al de la base
 * --, sin un solo aviso.  Y lo del fichero y la linea deja a un metodo
 * sobrescrito sin sitio en una traza de llamadas.
 *
 * @param m          El metodo declarado.
 * @param class_name La clase donde se escribe (la que lo define).
 * @return La ficha, sin el indice de tabla, que lo pone quien llama porque
 *         depende de si sustituye a otro o se anade al final.
 */
ClassMethodInfo TypeChecker::make_method_info(const ast::ClassMethodDecl &m,
                                              const std::string &class_name) {
    ClassMethodInfo mi;
    mi.name = m.name;
    mi.is_constructor = m.is_constructor;
    mi.is_destructor = m.is_destructor;
    mi.is_static = m.is_static;
    mi.is_final = m.is_final;
    mi.is_inline = m.is_inline;
    /* Un struct puede declarar metodos VIRTUALES y constructores que se
     * ejecutan al compilar; sin copiarlos aqui, el layout del struct los perdia
     * y ni `Struct.zero()` ni el despacho por tabla los encontraban. */
    mi.is_virtual = m.is_virtual;
    mi.is_comptime = m.is_comptime;
    mi.defining_class = class_name;
    mi.source_file = m.loc.file;
    mi.source_line = m.loc.line;
    mi.return_type = m.return_type ? type_from_node(m.return_type.get())
                                   : Type{PrimitiveKind::VOID};
    record_method_params(m, mi);
    return mi;
}

/**
 * @brief Comprueba los argumentos de una llamada a metodo contra su firma.
 *
 * Estaba escrito dos veces -- para el metodo de un struct y para el de una
 * clase --, casi igual pero no del todo: una comprobaba ademas que un puntero a
 * struct se puede subir a su base y la otra no.
 *
 * Y de las dos faltaba lo mismo: que el ultimo parametro puede recoger los que
 * sobren.  Entonces la aridad se cuenta distinto -- hay un minimo, no un numero
 * exacto -- y los argumentos de mas se comprueban contra el tipo del ELEMENTO,
 * no contra el del array.
 *
 * @param e    La llamada.
 * @param mi   El metodo al que se llama.
 * @param name Su nombre, para los mensajes.
 */

void TypeChecker::check_method_args(ast::CallExpr *e, const ClassMethodInfo &mi,
                                    const std::string &name) {
    /* Con un variadico, los parametros FIJOS son todos menos el ultimo -- que
     * es el array -- y de ahi en adelante se admite cualquier cantidad. */
    const size_t fixed =
        mi.is_variadic ? mi.param_types.size() - 1 : mi.param_types.size();

    if (mi.is_variadic) {
        if (e->args.size() < fixed)
            diags_.error(e->loc, "numero de argumentos insuficiente en metodo "
                                 "variadico '" +
                                     name + "': minimo " +
                                     std::to_string(fixed) + ", recibidos " +
                                     std::to_string(e->args.size()));
    } else if (e->args.size() != mi.param_types.size()) {
        diags_.error(e->loc, "numero de argumentos incorrecto en metodo '" +
                                 name + "': esperados " +
                                 std::to_string(mi.param_types.size()) +
                                 ", recibidos " +
                                 std::to_string(e->args.size()));
    }

    for (size_t i = 0; i < e->args.size(); ++i) {
        /* Un argumento de mas se compara con el tipo del elemento; uno fijo,
         * con el suyo.  Si sobran y el metodo no es variadico, ya se dijo
         * arriba y aqui no hay con que compararlo -- pero se comprueba igual,
         * por sus efectos. */
        if (i >= fixed && !mi.is_variadic) {
            (void)check_expr(e->args[i].get());
            continue;
        }
        const Type &tp = (i >= fixed) ? mi.variadic_elem : mi.param_types[i];
        check_call_arg(e->args[i].get(), tp, i, "el metodo '" + name + "'");
    }
}

/**
 * @brief Declara los parametros de @p params en el ambito actual.
 *
 * Dos cosas no son obvias y por eso estaban mal en dos de las tres copias que
 * habia (funcion suelta, metodo de clase, metodo de struct):
 *
 *   - El `...` pelado NO declara nada: sus argumentos van crudos en los
 *     registros que diga la convencion y el cuerpo en ensamblador los lee de
 *     ahi.
 *   - Un variadico empaquetado se ve DENTRO del cuerpo como `T*`, la direccion
 *     del array que monto quien llamo -- se indexa `xs[i]` y se pregunta
 *     cuantos con `vacount()` --, no como un `T`.
 *
 * @param params Los parametros declarados.
 */
void TypeChecker::declare_params_in_scope(
    const std::vector<std::unique_ptr<ast::ParamDecl>> &params) {
    for (const auto &p : params) {
        if (p->is_raw_variadic) continue;
        Symbol sp;
        sp.kind = SymbolKind::Param;
        const Type pt = type_from_node(p->type.get());
        sp.type = p->is_variadic ? Type::make_ptr(pt) : pt;
        // La direccion se comprueba AQUI y no donde se construye cada firma:
        // por aqui pasan la funcion suelta, el metodo y el constructor, asi que
        // los tres reciben el mismo criterio sin repetirlo tres veces.  Se
        // mira el tipo YA envuelto: en un variadico `in T... xs` el callee
        // recibe el puntero al array, que si apunta a algo.
        check_param_dir_(p->name, p->dir, p->loc, sp.type);
        if (!declare(p->name, sp))
            diags_.error(p->loc, "parametro repetido: '" + p->name + "'");
    }
}
void TypeChecker::check_free_function_bodies() {
    for (size_t di_ = 0; di_ < mod_.decls.size(); ++di_) {
        ast::Node *decl = mod_.decls[di_].get();
        if (!decl || decl->kind != ast::NodeKind::FunctionDecl) {
            // Globales: si tienen init, chequear el tipo.
            if (decl && decl->kind == ast::NodeKind::GlobalVarDecl) {
                auto *gv = static_cast<ast::GlobalVarDecl *>(decl);
                if (gv->init) {
                    Type t = check_expr(gv->init.get());
                    const Type want = type_from_node(gv->type.get());
                    /* A.39: para comptime const NO aplicamos el check
                     * estricto -- el "tipo" del literal es flexible
                     * (string literal tiene type PTR pero comptime
                     * lo evalua como STRING).  La validez se chequea
                     * via comptime_eval_expr abajo. */
                    if (gv->is_comptime) {
                        /* skip */
                    } else if (t.kind != PrimitiveKind::COUNT &&
                               want.kind != PrimitiveKind::COUNT &&
                               !is_numeric(t.kind) == !is_numeric(want.kind) &&
                               t != want) {
                        // Si ambos son numericos pero no exactamente iguales,
                        // toleramos la promocion implicita (la decision final
                        // la toma el lowering).  Si no son ambos numericos,
                        // exigimos igualdad estricta.
                        // Bug fix 2026-05-23: tolerar `string g = "lit"` --
                        // el init es PTR (literal raw) y el destino STRING;
                        // el lowering hara la promotion via STRMAKE en
                        // __module_init (igual que vars locales).
                        const bool is_str_from_lit =
                            want.kind == PrimitiveKind::STRING &&
                            t.kind == PrimitiveKind::PTR && gv->init &&
                            gv->init->kind == ast::NodeKind::StringLitExpr;
                        if (!(is_numeric(t.kind) && is_numeric(want.kind)) &&
                            !is_str_from_lit) {
                            diags_.error(
                                gv->loc,
                                std::string("tipo del inicializador (") +
                                    primitive_name(t.kind) +
                                    ") incompatible con el tipo declarado (" +
                                    primitive_name(want.kind) + ")");
                        }
                    }
                }
                /* comptime const NAME = expr; evaluar init en
                 * compile-time y cachear el valor.  Errors si no es
                 * comptime-evaluable.  LANG.fix-2: si el global YA
                 * fue inicializado (por init_comptime_globals previo
                 * que llama el runtime de top-level comptime block),
                 * NO re-evaluar el init -- preservamos las mutaciones
                 * aplicadas por el bloque. */
                if (gv->is_comptime && comptime_const_values_.find(gv->name) ==
                                           comptime_const_values_.end()) {
                    if (!gv->init) {
                        diags_.error(gv->loc,
                                     "'comptime const " + gv->name +
                                         "' requiere un inicializador");
                    } else {
                        const ComptimeEvalResult r =
                            comptime_eval_expr(*this, gv->init.get());
                        if (!r.ok) {
                            diags_.error(gv->init->loc,
                                         "el init de 'comptime const " +
                                             gv->name +
                                             "' no es comptime-evaluable");
                        } else {
                            ComptimeConst c;
                            /* sugar: si gv->type es nullptr
                             * (sugar `comptime X = ...` sin tipo
                             * explicito), inferimos el tipo desde el
                             * ComptimeEvalResult: is_str->STRING,
                             * is_type->TYPE_META, else->I64. */
                            if (gv->type) {
                                c.type = type_from_node(gv->type.get());
                            } else if (r.is_str) {
                                c.type = Type{PrimitiveKind::STRING};
                            } else if (r.is_type) {
                                c.type = Type{PrimitiveKind::TYPE_META};
                            } else {
                                c.type = Type{PrimitiveKind::I64};
                            }
                            c.is_str = r.is_str;
                            c.is_array = r.is_array;
                            c.is_struct = r.is_struct;
                            c.is_type = r.is_type;
                            /* Todo global `const` o `comptime` es MUTABLE en
                             * compile-time (las @Macro y comptime fn lo
                             * modifican via apply_comptime_assign) e INMUTABLE
                             * en runtime.  Da igual con cual de las dos
                             * palabras se declare: funciona igual. */
                            c.is_mutable = true;
                            c.deferred =
                                r.deferred; /* #2: propaga placeholder */
                            if (r.is_str)
                                c.str_value = r.str;
                            else if (r.is_array)
                                c.array_vals = r.array_vals;
                            else if (r.is_struct)
                                c.struct_fields = r.struct_fields;
                            else if (r.is_type)
                                c.type_val = r.type_val;
                            else
                                c.value = r.value;
                            // v4: propagar atributos
                            // @align/@hot/@cold/@section.
                            c.attr_align = gv->attr_align;
                            c.attr_hot = gv->attr_hot;
                            c.attr_cold = gv->attr_cold;
                            c.attr_section = gv->attr_section;
                            comptime_const_values_[gv->name] = c;
                        }
                    }
                }
            }
            continue;
        }
        auto *fn = static_cast<ast::FunctionDecl *>(decl);
        // Idempotente: esta pasada corre dos veces (antes y despues de los
        // cuerpos de metodos), y un cuerpo no debe chequearse dos veces.
        if (!checked_fn_bodies_.insert(fn).second) continue;
        if (!fn->body) continue;
        // Templates genericos RUNTIME: NO se type-checkea el body del template
        // (su `T` no esta resuelto -> resolveria a void).  Solo se chequean sus
        // monomorphizaciones concretas (que aparecen como FunctionDecls sin
        // type_params en mod_.decls).  Las comptime genericas siguen su path.
        if (!fn->type_params.empty() && !fn->is_comptime && !fn->is_macro)
            continue;
        // #7: especializaciones de funcion no se chequean como concretas (su
        // body usa el patron); cada uso se monomorphiza eligiendo la spec.
        if (fn->is_specialization && !fn->is_comptime && !fn->is_macro)
            continue;
        /* comptime fn NO-macro -- el body solo se interpreta al
         * call site via comptime_eval_stmt.  No type-check estatico
         * aqui (los IdentExpr no necesitan annotation; el eval los
         * busca en tc.comptime_const_locals_).  Si hay errores de
         * sintaxis o expresiones invalidas, el eval fallara con
         * `ok=false` en el call y emitiremos error alli.
         *
         * Los @Macro SI se type-checkean (mas abajo, con
         * current_fn_is_macro_): su body se baja a IR (`__macro_`) y se
         * VM-evalua, asi que los exprs necesitan result_type correcto
         * (arrays, string concat, indexing...).  El check_block con
         * current_fn_is_macro_ trata los locals como comptime const y
         * es tolerante con los patrones de macro. */
        /* Las comptime fn que corren en la ComptimeVM (asm/@Naked O I/O) SI se
         * type-checkean: su body se baja a IR (`__macro_`) y se VM-evalua, asi
         * que los exprs necesitan result_type correcto (arrays, indexing,
         * string concat...) -- igual que los @Macro. */
        if (fn->is_comptime && !fn->is_macro &&
            !comptime_fn_needs_vm(*this, fn))
            continue;

        // Mejora II: validacion @Async extendida.  Antes solo permitia
        // funciones sin parametros y return type i64.  Ahora:
        //   - Cualquier numero de parametros, cada uno con tipo de
        //     tamano <= 8 bytes (primitivos numericos, bool, char,
        //     ptr, handle de string/objeto, futures).
        //   - Cualquier tipo de retorno T con tamano <= 8 bytes.
        //   - El wrapper publico visible al callsite devuelve
        //     Future<T> (envuelto automaticamente por el type checker).
        //     `i32 r = await compute(10, 20);` tipo-checkea correctamente.
        //
        // Tipos > 8 bytes (struct, array, optional, result) requeririan
        // serializacion en buffer auxiliar.  Deferido a  B.
        if (fn->is_async) {
            auto fits_in_qword = [](const Type &t) -> bool {
                if (t.kind == PrimitiveKind::COUNT)
                    return true; // tipo desconocido OK
                return primitive_size_bytes(t.kind) > 0 &&
                       primitive_size_bytes(t.kind) <= 8;
            };
            for (size_t pi = 0; pi < fn->params.size(); ++pi) {
                Type pt = type_from_node(fn->params[pi]->type.get());
                if (!fits_in_qword(pt)) {
                    diags_.error(fn->params[pi]->loc,
                                 "@Async: parametro '" + fn->params[pi]->name +
                                     "' de tipo '" + type_to_string(pt) +
                                     "' excede 8 bytes.  Tipos compuestos "
                                     "(struct, array, "
                                     "Optional, Result) no soportados aun.");
                }
            }
            const Type rt_chk = type_from_node(fn->return_type.get());
            if (rt_chk.kind != PrimitiveKind::COUNT &&
                rt_chk.kind != PrimitiveKind::VOID && !fits_in_qword(rt_chk)) {
                diags_.error(fn->loc, "@Async: tipo de retorno '" +
                                          type_to_string(rt_chk) +
                                          "' excede 8 bytes.  Tipos compuestos "
                                          "no soportados aun.");
            }
        }

        const Type fn_ret = type_from_node(fn->return_type.get());
        push_scope(); // scope de la funcion (parametros)
        declare_params_in_scope(fn->params);
        // Guardar y settear current_fn_return_type_ para que
        // check_match (que recibe expected_return_type via miembro
        // y no via param para no contaminar la signature) pueda
        // validar returns dentro del match con el tipo correcto.
        const Type saved_ret = current_fn_return_type_;
        current_fn_return_type_ = fn_ret;
        // Resetear el borrow checker al entrar a cada funcion.
        // Cada funcion tiene su propio scope de borrows; los borrows
        // de una funcion no afectan a otra.
        borrow_checker_.reset();
        // Safety net (item 1): el taint de structs-con-closure-en-stack es
        // por-funcion (los locals no cruzan fronteras de funcion).
        struct_stack_closure_taint_.clear();
        moved_locals_.clear();
        // F2: registrar parametros como owners con OwnerKind::Param.
        // Si el parametro ES un borrow (su tipo es BORROW/BORROW_MUT),
        // ademas lo registramos como borrower self-referencial: el
        // borrow checker lo reconoce como "borrow valido cuyo owner
        // es Param" -> escape via return permitido.
        for (auto &p : fn->params) {
            borrow_checker_.declare_owner(p->name, OwnerKind::Param);
            const Type pt = type_from_node(p->type.get());
            if (pt.kind == PrimitiveKind::BORROW ||
                pt.kind == PrimitiveKind::BORROW_MUT) {
                borrow_checker_.register_borrow(
                    p->name, p->name,
                    /*is_mut=*/(pt.kind == PrimitiveKind::BORROW_MUT));
            }
        }
        // F1 NLL: pre-pase de last-uses + reset del contador.
        current_stmt_idx_ = 0;
        compute_borrow_last_uses(fn->body.get());
        // BugFix R8: cuando estamos dentro de un @Macro body, todas
        // las var-decls se tratan automaticamente como comptime
        // const (incluso si no llevan `comptime` explicito).  Esto
        // permite que `string n = typename<T>(); comptime_concat(n, "/")`
        // funcione naturalmente sin que el usuario tenga que escribir
        // `comptime const string n = ...`.
        const bool saved_is_macro = current_fn_is_macro_;
        const bool saved_is_vm_ct = current_fn_is_vm_comptime_fn_;
        /* P1: fn-VM type-checkea en modo macro (builtins comptime args runtime
         * OK). */
        current_fn_is_vm_comptime_fn_ =
            fn->is_comptime && !fn->is_macro && comptime_fn_needs_vm(*this, fn);
        current_fn_is_macro_ = fn->is_macro || current_fn_is_vm_comptime_fn_;
        const bool saved_noexcept = current_fn_is_noexcept_;
        current_fn_is_noexcept_ = fn->is_noexcept || mod_.no_exceptions;
        // Tambien empujamos un scope comptime nuevo para los locals del
        // macro body (para que find_comptime_local_mut los encuentre).
        if (fn->is_macro) push_comptime_scope();
        /* Type-check del cuerpo de @Macro = SOLO-ANOTACION: rellena los
         * result_type (para que el lowering maneje arrays, string concat,
         * indexing...) pero SUPRIME los diagnosticos -- los patrones comptime
         * (macro-a-macro, comptime globals, introspect, code-injection) no son
         * errores reales aqui; se resuelven en el lowering (macro_body_
         * unsupported_reason gatea los no-lowereables a AST-eval) o al expandir
         * el macro en su call site. */
        const bool sup_prev =
            fn->is_macro ? diags_.set_suppressed(true) : false;
        check_block(fn->body.get(), fn_ret);
        if (fn->is_macro) diags_.set_suppressed(sup_prev);
        if (fn->is_macro) pop_comptime_scope();
        current_fn_is_macro_ = saved_is_macro;
        current_fn_is_vm_comptime_fn_ = saved_is_vm_ct;
        current_fn_is_noexcept_ = saved_noexcept;
        current_fn_return_type_ = saved_ret;
        pop_scope();
    }
}

void TypeChecker::check_functions() {
    // Defaults de campos de tipo funcion (`fnptr method = invoke;`): promover
    // AHORA que todas las firmas de funcion estan registradas (collect_globals
    // ya paso; al construir el layout aun no lo estaban -> "nombre no
    // declarado").  check_expr marca is_func_ref (via check_ident) y
    // maybe_promote_func_ref fija el result_type FUNCTION con la ABI de la
    // firma -> el lowering emite LABEL_ADDR (no "nombre no resuelto") y el cast
    // del campo hereda esa ABI (base de la devirtualizacion del ctx pattern).
    for (auto &kv : struct_layouts_) {
        for (auto &fi : kv.second.fields) {
            if (fi.default_init && fi.type.kind == PrimitiveKind::FUNCTION) {
                (void)check_expr(fi.default_init);
                (void)maybe_promote_func_ref(fi.default_init, fi.type, Type{});
            }
        }
    }

    // Fix (generic-fn inference): las monomorphizaciones por INFERENCIA
    // (`usa(p)` sin type-arg explicito) se crean DURANTE este check (en
    // check_call) y se anyaden al FINAL de mod_.decls.  Iteramos por INDICE
    // re-evaluando size() cada vuelta para que esos clones nuevos tambien se
    // chequeen (sin esto su body queda sin result_types -> el lowering falla
    // con "callee no es identificador" al bajar `v.metodo()`).  El puntero al
    // objeto es estable ante realloc del vector (los unique_ptr mueven de slot
    // pero el objeto apuntado no), asi que `fn`/`gv` siguen validos.
    check_free_function_bodies();

    // Chequeo de cuerpos de metodos de clase.  Para cada ClassDecl
    // recorremos sus metodos: el scope local incluye 'this' y los
    // parametros declarados.  El campo current_class_ guia
    // check_this para que sepa la clase contenedora.
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::ClassDecl) continue;
        auto *cd = static_cast<ast::ClassDecl *>(decl.get());
        auto it = class_layouts_.find(cd->name);
        if (it == class_layouts_.end()) continue;
        const ClassLayout &cls = it->second;

        const std::string saved_class = current_class_;
        current_class_ = cd->name;

        for (auto &m : cd->methods) {
            if (!m || !m->body) continue;
            // Metodo generico template (#4): su body tiene U sin resolver;
            // se chequea solo en sus monomorphizaciones concretas (drain).
            if (!m->method_type_params.empty()) continue;
            check_class_method(cls, m.get());
        }
        current_class_ = saved_class;
    }

    // Chequeo de cuerpos de metodos de struct (value-types).  Mismo
    // patron que clases pero @c this se tipa STRUCT y no hay vtable
    // ni super.  El campo @c current_struct_ guia check_this.
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::StructDecl) continue;
        auto *sd = static_cast<ast::StructDecl *>(decl.get());
        auto it = struct_layouts_.find(sd->name);
        if (it == struct_layouts_.end()) continue;
        const StructLayout &lay = it->second;

        const std::string saved_struct = current_struct_;
        current_struct_ = sd->name;
        for (auto &m : sd->methods) {
            if (!m || !m->body) continue;
            // Metodo generico template (#4): su body tiene U sin resolver;
            // se chequea solo en sus monomorphizaciones concretas (drain).
            if (!m->method_type_params.empty()) continue;
            check_struct_method(lay, m.get());
        }
        current_struct_ = saved_struct;
    }

    // NS.6-ext: chequear los cuerpos de los metodos de extension / impl.
    // Enrutar por check_struct_method / check_class_method con el
    // current_struct_/current_class_ = clave del layout destino (asi `this`
    // se tipa correcto y el rewrite implicit-this funciona).
    for (auto &decl : mod_.decls) {
        if (!decl) continue;
        const bool is_ext = decl->kind == ast::NodeKind::ExtensionDecl;
        const bool is_impl = decl->kind == ast::NodeKind::ImplDecl;
        if (!is_ext && !is_impl) continue;
        std::string target_src;
        std::vector<std::unique_ptr<ast::ClassMethodDecl>> *methods = nullptr;
        if (is_ext) {
            auto *e = static_cast<ast::ExtensionDecl *>(decl.get());
            target_src = e->target_type;
            methods = &e->methods;
        } else {
            auto *im = static_cast<ast::ImplDecl *>(decl.get());
            target_src = im->target_type;
            methods = &im->methods;
        }
        // Resolver la clave del layout (directo o via resolve_type_string).
        std::string key;
        bool is_class_target = false;
        auto find_key = [&](const std::string &k) -> bool {
            if (struct_layouts_.count(k)) {
                key = k;
                is_class_target = false;
                return true;
            }
            if (class_layouts_.count(k)) {
                key = k;
                is_class_target = true;
                return true;
            }
            return false;
        };
        if (!find_key(target_src)) {
            std::string mangled = target_src;
            for (size_t p = mangled.find('.'); p != std::string::npos;
                 p = mangled.find('.'))
                mangled.replace(p, 1, "__");
            if (mangled == target_src || !find_key(mangled)) {
                const Type rt = resolve_type_string(target_src);
                if (rt.kind == PrimitiveKind::STRUCT ||
                    rt.kind == PrimitiveKind::CLASS)
                    find_key(rt.struct_name);
            }
        }
        if (key.empty()) continue;
        if (!is_class_target) {
            auto it = struct_layouts_.find(key);
            const std::string saved = current_struct_;
            current_struct_ = key;
            for (auto &m : *methods) {
                if (!m || !m->body) continue;
                if (!m->method_type_params.empty()) continue;
                check_struct_method(it->second, m.get());
            }
            current_struct_ = saved;
        } else {
            auto it = class_layouts_.find(key);
            const std::string saved = current_class_;
            current_class_ = key;
            for (auto &m : *methods) {
                if (!m || !m->body) continue;
                if (!m->method_type_params.empty()) continue;
                check_class_method(it->second, m.get());
            }
            current_class_ = saved;
        }
    }

    // #4: drenar las monomorphizaciones de metodos genericos encoladas
    // durante el chequeo (anyadir cada `metodo_<U>` al AST de su
    // contenedor + chequear su body, a punto fijo).  Debe ir DESPUES de
    // los bucles de metodos para no invalidar sus iteradores.
    drain_pending_method_monos();

    // Instancias de funciones genericas creadas al chequear un CUERPO DE
    // METODO.  El bucle de funciones libres de mas arriba ya re-evalua
    // `size()` para recoger las que nacen mientras el mismo corre, pero los
    // metodos se chequean DESPUES de el: sus instancias llegaban a
    // `mod_.decls` con ese bucle terminado y nadie las chequeaba nunca.  Se
    // quedaban sin `result_type` en todo el cuerpo, y entonces el lowering
    // decidia a ciegas -- `(*out) = valor` con un struct guardaba la DIRECCION
    // en lugar de copiar los bytes, asi que una generica con `T` struct
    // llamada desde un metodo devolvia punteros como si fueran valores.
    // La pasada es idempotente, asi que basta con repetirla: salta lo ya
    // chequeado y recoge lo nuevo.
    check_free_function_bodies();

    // #6: verificar los bounds encolados durante check_functions (metodos
    // genericos con `<U: Concepto>`, y cualquier monomorphizacion on-demand).
    verify_pending_type_bounds();
}

/**
 * @brief Sprint edge-bugs (2026-06-02): rewrite implicit-this.
 *
 * En metodos de instancia, identifiers como @c v dentro del body que
 * matchean un field name de la clase contenedora se reescriben como
 * @c this.v (FieldAccessExpr).  Convencion Java/C#.  No reescribe si:
 *   - el ident matchea un parametro (params_set)
 *   - el ident matchea una local declarada en un scope previo (locals_stack)
 *   - es lhs de un VarDecl (la propia declaracion)
 *
 * El walker recibe @c unique_ptr<Expr>& para poder swap-ear el nodo
 * IdentExpr por FieldAccessExpr in-place.  Walkea TODAS las statements
 * y exprs hijas (recursivo).
 */
static void
rewrite_implicit_this(std::unique_ptr<ast::Stmt> &stmt,
                      const std::unordered_set<std::string> &field_names,
                      const std::unordered_set<std::string> &params_set);

static void rewrite_implicit_this_expr(
    std::unique_ptr<ast::Expr> &node,
    const std::unordered_set<std::string> &field_names,
    const std::unordered_set<std::string> &params_set,
    std::vector<std::unordered_set<std::string>> &locals_stack) {
    if (!node) return;
    // IdentExpr: si matches field y NO en params/locals, rewrite.
    if (node->kind == ast::NodeKind::IdentExpr) {
        auto *id = static_cast<ast::IdentExpr *>(node.get());
        if (field_names.count(id->name) && !params_set.count(id->name) &&
            id->name != "this" && id->name != "super") {
            bool shadowed = false;
            for (auto &s : locals_stack)
                if (s.count(id->name)) {
                    shadowed = true;
                    break;
                }
            if (!shadowed) {
                auto fa = std::make_unique<ast::FieldAccessExpr>();
                fa->loc = id->loc;
                auto base = std::make_unique<ast::IdentExpr>();
                base->loc = id->loc;
                base->name = "this";
                fa->base = std::move(base);
                fa->field_name = id->name;
                node = std::move(fa);
            }
        }
        return;
    }
    switch (node->kind) {
    case ast::NodeKind::BinaryExpr: {
        auto *b = static_cast<ast::BinaryExpr *>(node.get());
        rewrite_implicit_this_expr(b->lhs, field_names, params_set,
                                   locals_stack);
        rewrite_implicit_this_expr(b->rhs, field_names, params_set,
                                   locals_stack);
        return;
    }
    case ast::NodeKind::UnaryExpr: {
        auto *u = static_cast<ast::UnaryExpr *>(node.get());
        rewrite_implicit_this_expr(u->operand, field_names, params_set,
                                   locals_stack);
        return;
    }
    case ast::NodeKind::TernaryExpr: {
        auto *t = static_cast<ast::TernaryExpr *>(node.get());
        rewrite_implicit_this_expr(t->cond, field_names, params_set,
                                   locals_stack);
        rewrite_implicit_this_expr(t->then_expr, field_names, params_set,
                                   locals_stack);
        rewrite_implicit_this_expr(t->else_expr, field_names, params_set,
                                   locals_stack);
        return;
    }
    case ast::NodeKind::CallExpr: {
        auto *c = static_cast<ast::CallExpr *>(node.get());
        // Para el callee: si es IdentExpr (llamada simple `foo(x)`),
        // NO reescribimos a this.foo -- la llamada se resuelve por
        // simbolo global (clase methods se invocan con this. explicito
        // o se inlinean).  Si es FieldAccessExpr o algo mas, recurse.
        if (c->callee && c->callee->kind != ast::NodeKind::IdentExpr) {
            rewrite_implicit_this_expr(c->callee, field_names, params_set,
                                       locals_stack);
        }
        for (auto &a : c->args)
            rewrite_implicit_this_expr(a, field_names, params_set,
                                       locals_stack);
        return;
    }
    case ast::NodeKind::FieldAccessExpr: {
        auto *fa = static_cast<ast::FieldAccessExpr *>(node.get());
        rewrite_implicit_this_expr(fa->base, field_names, params_set,
                                   locals_stack);
        return;
    }
    case ast::NodeKind::IndexExpr: {
        auto *ix = static_cast<ast::IndexExpr *>(node.get());
        rewrite_implicit_this_expr(ix->base, field_names, params_set,
                                   locals_stack);
        rewrite_implicit_this_expr(ix->index, field_names, params_set,
                                   locals_stack);
        return;
    }
    case ast::NodeKind::AssignExpr: {
        auto *a = static_cast<ast::AssignExpr *>(node.get());
        rewrite_implicit_this_expr(a->target, field_names, params_set,
                                   locals_stack);
        rewrite_implicit_this_expr(a->value, field_names, params_set,
                                   locals_stack);
        return;
    }
    case ast::NodeKind::CastExpr: {
        auto *c = static_cast<ast::CastExpr *>(node.get());
        rewrite_implicit_this_expr(c->operand, field_names, params_set,
                                   locals_stack);
        return;
    }
    case ast::NodeKind::NewExpr: {
        auto *n = static_cast<ast::NewExpr *>(node.get());
        for (auto &a : n->args)
            rewrite_implicit_this_expr(a, field_names, params_set,
                                       locals_stack);
        return;
    }
    case ast::NodeKind::LambdaExpr: {
        auto *lam = static_cast<ast::LambdaExpr *>(node.get());
        std::unordered_set<std::string> lam_locals;
        for (auto &p : lam->params)
            lam_locals.insert(p->name);
        locals_stack.push_back(std::move(lam_locals));
        if (lam->body)
            for (auto &child : lam->body->body)
                rewrite_implicit_this(child, field_names, params_set);
        locals_stack.pop_back();
        return;
    }
    case ast::NodeKind::StringLitExpr: {
        auto *sl = static_cast<ast::StringLitExpr *>(node.get());
        for (auto &ie : sl->interp_exprs)
            rewrite_implicit_this_expr(ie, field_names, params_set,
                                       locals_stack);
        return;
    }
    case ast::NodeKind::MatchExpr: {
        auto *me = static_cast<ast::MatchExpr *>(node.get());
        rewrite_implicit_this_expr(me->scrutinee, field_names, params_set,
                                   locals_stack);
        for (auto &arm : me->arms) {
            std::unordered_set<std::string> arm_locals;
            for (auto &bn : arm.bindings)
                arm_locals.insert(bn);
            locals_stack.push_back(std::move(arm_locals));
            if (arm.body)
                rewrite_implicit_this(arm.body, field_names, params_set);
            locals_stack.pop_back();
        }
        return;
    }
    case ast::NodeKind::InitListExpr: {
        auto *il = static_cast<ast::InitListExpr *>(node.get());
        for (auto &e : il->elements)
            rewrite_implicit_this_expr(e, field_names, params_set,
                                       locals_stack);
        return;
    }
    default: return;
    }
}

static void
rewrite_implicit_this(std::unique_ptr<ast::Stmt> &stmt,
                      const std::unordered_set<std::string> &field_names,
                      const std::unordered_set<std::string> &params_set) {
    if (!stmt) return;
    /* Stack de scopes locales (a parte de los params).  Cada BlockStmt
     * push/pop su scope para soportar shadowing.  El VarDecl agrega el
     * nombre al scope ACTUAL antes de procesar las stmts siguientes. */
    std::vector<std::unordered_set<std::string>> locals_stack;
    std::function<void(std::unique_ptr<ast::Stmt> &)> visit;
    visit = [&](std::unique_ptr<ast::Stmt> &s) {
        if (!s) return;
        switch (s->kind) {
        case ast::NodeKind::BlockStmt: {
            auto *bs = static_cast<ast::BlockStmt *>(s.get());
            locals_stack.push_back({});
            for (auto &child : bs->body)
                visit(child);
            locals_stack.pop_back();
            return;
        }
        case ast::NodeKind::VarDeclStmt: {
            auto *vd = static_cast<ast::VarDeclStmt *>(s.get());
            /* Reescribir el init ANTES de declarar el local (el init
             * no puede referirse a si mismo). */
            if (vd->init)
                rewrite_implicit_this_expr(vd->init, field_names, params_set,
                                           locals_stack);
            /* Anadir el nombre al scope local actual.  Si stack vacio,
             * crear scope top-level. */
            if (locals_stack.empty()) locals_stack.push_back({});
            locals_stack.back().insert(vd->name);
            return;
        }
        case ast::NodeKind::ExprStmt: {
            auto *es = static_cast<ast::ExprStmt *>(s.get());
            rewrite_implicit_this_expr(es->expr, field_names, params_set,
                                       locals_stack);
            return;
        }
        case ast::NodeKind::ReturnStmt: {
            auto *rs = static_cast<ast::ReturnStmt *>(s.get());
            if (rs->value)
                rewrite_implicit_this_expr(rs->value, field_names, params_set,
                                           locals_stack);
            return;
        }
        case ast::NodeKind::IfStmt: {
            auto *is = static_cast<ast::IfStmt *>(s.get());
            rewrite_implicit_this_expr(is->cond, field_names, params_set,
                                       locals_stack);
            visit(is->then_branch);
            visit(is->else_branch);
            return;
        }
        case ast::NodeKind::WhileStmt: {
            auto *ws = static_cast<ast::WhileStmt *>(s.get());
            rewrite_implicit_this_expr(ws->cond, field_names, params_set,
                                       locals_stack);
            visit(ws->body);
            return;
        }
        case ast::NodeKind::DoWhileStmt: {
            auto *ds = static_cast<ast::DoWhileStmt *>(s.get());
            visit(ds->body);
            rewrite_implicit_this_expr(ds->cond, field_names, params_set,
                                       locals_stack);
            return;
        }
        case ast::NodeKind::ForStmt: {
            auto *fs = static_cast<ast::ForStmt *>(s.get());
            locals_stack.push_back({});
            visit(fs->init);
            if (fs->cond)
                rewrite_implicit_this_expr(fs->cond, field_names, params_set,
                                           locals_stack);
            if (fs->step)
                rewrite_implicit_this_expr(fs->step, field_names, params_set,
                                           locals_stack);
            visit(fs->body);
            locals_stack.pop_back();
            return;
        }
        case ast::NodeKind::TryStmt: {
            auto *ts = static_cast<ast::TryStmt *>(s.get());
            /* body es BlockStmt; iterar children. */
            if (ts->body)
                for (auto &child : ts->body->body)
                    visit(child);
            for (auto &c : ts->catches) {
                locals_stack.push_back({});
                if (!c.var_name.empty()) locals_stack.back().insert(c.var_name);
                if (c.body)
                    for (auto &child : c.body->body)
                        visit(child);
                locals_stack.pop_back();
            }
            if (ts->finally_body)
                for (auto &child : ts->finally_body->body)
                    visit(child);
            return;
        }
        case ast::NodeKind::ThrowStmt: {
            auto *th = static_cast<ast::ThrowStmt *>(s.get());
            if (th->value)
                rewrite_implicit_this_expr(th->value, field_names, params_set,
                                           locals_stack);
            return;
        }
        case ast::NodeKind::SynchronizedStmt: {
            auto *ss = static_cast<ast::SynchronizedStmt *>(s.get());
            rewrite_implicit_this_expr(ss->target, field_names, params_set,
                                       locals_stack);
            if (ss->body)
                for (auto &child : ss->body->body)
                    visit(child);
            return;
        }
        default: return;
        }
    };
    visit(stmt);
}

void TypeChecker::check_class_method(const ClassLayout &cls,
                                     ast::ClassMethodDecl *m) {
    // Semantica de modificadores:
    //  - constructor static: error (no tiene sentido).
    //  - metodo static que use 'this': error claro via check_this
    //    consultando current_method_is_static_.
    //  - final: aceptado, sera enforced en cuando haya override.
    if (m->is_static && m->is_constructor) {
        diags_.error(m->loc, "el constructor de '" + cls.name +
                                 "' no puede ser 'static'");
    }

    const bool saved_static = current_method_is_static_;
    current_method_is_static_ = m->is_static;

    push_scope();
    // 'this' implicito como Symbol solo en metodos de instancia.
    if (!m->is_static) {
        Symbol s_this;
        s_this.kind = SymbolKind::Param;
        s_this.type = Type{PrimitiveKind::CLASS, cls.name};
        (void)declare("this", s_this);
    }
    // Parametros declarados.
    declare_params_in_scope(m->params);
    // Sprint edge-bugs (2026-06-02): pre-pase de implicit-this.
    // Recolecta field names de la clase + sus supers transitivos.
    // Despues walkea el body y reescribe identifiers de fields a
    // FieldAccessExpr(this, field).  Solo para metodos de instancia
    // (en static methods no hay this, debe ser explicito error).
    if (!m->is_static && m->body) {
        std::unordered_set<std::string> field_names;
        const ClassLayout *cl_cur = &cls;
        int depth_guard = 256;
        while (cl_cur && depth_guard-- > 0) {
            for (const auto &f : cl_cur->fields)
                field_names.insert(f.name);
            if (cl_cur->super_name.empty()) break;
            auto sup_it = class_layouts_.find(cl_cur->super_name);
            if (sup_it == class_layouts_.end()) break;
            cl_cur = &sup_it->second;
        }
        std::unordered_set<std::string> params_set;
        params_set.insert("this");
        params_set.insert("super");
        for (auto &p : m->params)
            params_set.insert(p->name);
        /* Rewrite inline las stmts del body.  m->body es
         * unique_ptr<BlockStmt> con vector body de unique_ptr<Stmt>.
         *
         * BugFix (2026-06-04): antes iterabamos los children uno a uno
         * llamando @c rewrite_implicit_this(child, ...) , pero esa
         * funcion crea su PROPIO @c locals_stack vacio internamente, lo
         * que provocaba que las var locals declaradas en un statement
         * (e.g. `i64 fp = ffi_call(...)`) NO se vieran como shadowed en
         * el siguiente statement (e.g. `if (fp == 0)`).  Resultado: el
         * `fp` se reescribia a `this.fp` cuando el ident colisionaba
         * con un field, leyendo basura.  Caso real cerrado: file_io
         * `read_all` con variable local `fp` colisionando con field
         * `this.fp`.
         *
         * Fix: tratar el body como UN SOLO BlockStmt, lo que comparte
         * el @c locals_stack interno entre todos los statements del body.
         */
        std::unique_ptr<ast::Stmt> body_as_stmt(m->body.release());
        rewrite_implicit_this(body_as_stmt, field_names, params_set);
        // Re-inyectar el BlockStmt al field body (el rewrite no lo movio).
        m->body.reset(static_cast<ast::BlockStmt *>(body_as_stmt.release()));
    }
    // Tipo de retorno: VOID para constructores; el declarado para los demas.
    const Type fn_ret = m->is_constructor
                            ? Type{PrimitiveKind::VOID}
                            : type_from_node(m->return_type.get());
    const Type saved_ret = current_fn_return_type_;
    current_fn_return_type_ = fn_ret;
    struct_stack_closure_taint_.clear();
    moved_locals_.clear();
    check_block(m->body.get(), fn_ret);
    current_fn_return_type_ = saved_ret;
    pop_scope();
    current_method_is_static_ = saved_static;
}

void TypeChecker::check_struct_method(const StructLayout &lay,
                                      ast::ClassMethodDecl *m) {
    // Configura el scope con 'this' (STRUCT) + parametros y chequea el body.
    // Vale igual para metodos normales, factorias `static` y constructores
    // (`u128(args)`): un constructor es un metodo void cuyo `this` es el buffer
    // a inicializar; no requiere trato especial en el chequeo del cuerpo.
    const bool saved_static = current_method_is_static_;
    current_method_is_static_ = false;

    push_scope();
    // 'this' implicito como Symbol de tipo STRUCT.
    Symbol s_this;
    s_this.kind = SymbolKind::Param;
    s_this.type = Type{PrimitiveKind::STRUCT, lay.name};
    (void)declare("this", s_this);
    // Parametros declarados.
    declare_params_in_scope(m->params);
    // Pre-pase implicit-this: reescribe identifiers que matchean un
    // campo del struct a FieldAccessExpr(this, campo).  Mismo
    // mecanismo que metodos de clase (sin supers: los structs no
    // heredan).
    if (m->body) {
        std::unordered_set<std::string> field_names;
        for (const auto &f : lay.fields)
            field_names.insert(f.name);
        std::unordered_set<std::string> params_set;
        params_set.insert("this");
        for (auto &p : m->params)
            params_set.insert(p->name);
        std::unique_ptr<ast::Stmt> body_as_stmt(m->body.release());
        rewrite_implicit_this(body_as_stmt, field_names, params_set);
        m->body.reset(static_cast<ast::BlockStmt *>(body_as_stmt.release()));
    }
    const Type fn_ret = m->return_type ? type_from_node(m->return_type.get())
                                       : Type{PrimitiveKind::VOID};
    const Type saved_ret = current_fn_return_type_;
    current_fn_return_type_ = fn_ret;
    struct_stack_closure_taint_.clear();
    moved_locals_.clear();
    check_block(m->body.get(), fn_ret);
    current_fn_return_type_ = saved_ret;
    pop_scope();
    current_method_is_static_ = saved_static;
}

void TypeChecker::check_block(ast::BlockStmt *b, const Type &fn_return_type) {
    push_scope();
    for (auto &s : b->body) {
        check_stmt(s.get(), fn_return_type);
    }
    pop_scope();
}

// F1 NLL - pre-pase: numera stmts en DFS order y para cada IdentExpr
// registra el stmt_idx de su uso.  Calcula el max per nombre y se lo
// da al borrow checker.
void TypeChecker::compute_borrow_last_uses(ast::Stmt *body) {
    if (!body) return;
    std::unordered_map<std::string, uint32_t> last_use;
    uint32_t counter = 0;

    std::function<void(ast::Expr *)> visit_expr;
    std::function<void(ast::Stmt *)> visit_stmt;

    // Recorre la expr y registra el stmt_idx actual (counter) en
    // cualquier IdentExpr.  Para CallExpr, recurse en callee + args.
    // Para los demas, recurse en sub-exprs relevantes.
    visit_expr = [&](ast::Expr *e) {
        if (!e) return;
        switch (e->kind) {
        case ast::NodeKind::IdentExpr: {
            auto *id = static_cast<ast::IdentExpr *>(e);
            auto it = last_use.find(id->name);
            if (it == last_use.end() || it->second < counter) {
                last_use[id->name] = counter;
            }
            return;
        }
        case ast::NodeKind::BinaryExpr: {
            auto *b = static_cast<ast::BinaryExpr *>(e);
            visit_expr(b->lhs.get());
            visit_expr(b->rhs.get());
            return;
        }
        case ast::NodeKind::UnaryExpr: {
            auto *u = static_cast<ast::UnaryExpr *>(e);
            visit_expr(u->operand.get());
            return;
        }
        case ast::NodeKind::CallExpr: {
            auto *c = static_cast<ast::CallExpr *>(e);
            visit_expr(c->callee.get());
            for (auto &a : c->args)
                visit_expr(a.get());
            return;
        }
        case ast::NodeKind::FieldAccessExpr: {
            auto *f = static_cast<ast::FieldAccessExpr *>(e);
            visit_expr(f->base.get());
            return;
        }
        case ast::NodeKind::IndexExpr: {
            auto *ix = static_cast<ast::IndexExpr *>(e);
            visit_expr(ix->base.get());
            visit_expr(ix->index.get());
            return;
        }
        case ast::NodeKind::AssignExpr: {
            auto *as = static_cast<ast::AssignExpr *>(e);
            visit_expr(as->target.get());
            visit_expr(as->value.get());
            return;
        }
        default: return;
        }
    };

    visit_stmt = [&](ast::Stmt *s) {
        if (!s) return;
        // Para BlockStmt no incrementamos: solo es contenedor; check_stmt
        // tampoco lo cuenta como un stmt aparte (se procesa via check_block
        // que itera children).  Mantenemos la simetria con la fase
        // de checkeo.
        if (s->kind == ast::NodeKind::BlockStmt) {
            auto *b = static_cast<ast::BlockStmt *>(s);
            for (auto &sub : b->body)
                visit_stmt(sub.get());
            return;
        }
        ++counter;
        switch (s->kind) {
        case ast::NodeKind::BlockStmt: {
            auto *b = static_cast<ast::BlockStmt *>(s);
            for (auto &sub : b->body)
                visit_stmt(sub.get());
            return;
        }
        case ast::NodeKind::VarDeclStmt: {
            auto *vd = static_cast<ast::VarDeclStmt *>(s);
            if (vd->init) visit_expr(vd->init.get());
            return;
        }
        case ast::NodeKind::ExprStmt: {
            auto *es = static_cast<ast::ExprStmt *>(s);
            visit_expr(es->expr.get());
            return;
        }
        case ast::NodeKind::IfStmt: {
            auto *is = static_cast<ast::IfStmt *>(s);
            visit_expr(is->cond.get());
            if (is->then_branch) visit_stmt(is->then_branch.get());
            if (is->else_branch) visit_stmt(is->else_branch.get());
            return;
        }
        case ast::NodeKind::WhileStmt: {
            auto *ws = static_cast<ast::WhileStmt *>(s);
            visit_expr(ws->cond.get());
            if (ws->body) visit_stmt(ws->body.get());
            return;
        }
        case ast::NodeKind::ForStmt: {
            auto *fs = static_cast<ast::ForStmt *>(s);
            if (fs->init) visit_stmt(fs->init.get());
            if (fs->cond) visit_expr(fs->cond.get());
            if (fs->step) visit_expr(fs->step.get());
            if (fs->body) visit_stmt(fs->body.get());
            return;
        }
        case ast::NodeKind::ReturnStmt: {
            auto *r = static_cast<ast::ReturnStmt *>(s);
            if (r->value) visit_expr(r->value.get());
            return;
        }
        default: return;
        }
    };

    visit_stmt(body);

    // Entregar los last-uses al borrow checker.  El borrow checker
    // los aplica solo a entradas ya registradas en borrows_; las
    // de variables que no son borrows se ignoran silenciosamente.
    for (const auto &kv : last_use) {
        borrow_checker_.set_last_use(kv.first, kv.second);
    }
}

std::string TypeChecker::render_comptime_value(const ComptimeValue &v) {
    // Acota el numero de elementos/campos serializados para no generar
    // cadenas gigantes con tablas grandes.
    static constexpr size_t kMaxItems = 16;
    if (v.is_type) {
        return type_to_string(v.type_val);
    }
    if (v.is_str) {
        return "\"" + v.str + "\"";
    }
    if (v.is_array) {
        std::string out = "[";
        size_t n = v.array_vals.size();
        size_t shown = n < kMaxItems ? n : kMaxItems;
        for (size_t i = 0; i < shown; ++i) {
            if (i) out += ", ";
            out +=
                v.array_vals[i] ? render_comptime_value(*v.array_vals[i]) : "?";
        }
        if (n > shown) out += ", ...";
        out += "]";
        return out;
    }
    if (v.is_struct) {
        std::string out = "{";
        size_t i = 0;
        for (const auto &kv : v.struct_fields) {
            if (i >= kMaxItems) {
                out += ", ...";
                break;
            }
            if (i) out += ", ";
            out += kv.first + "=" +
                   (kv.second ? render_comptime_value(*kv.second) : "?");
            ++i;
        }
        out += "}";
        return out;
    }
    return std::to_string(v.value);
}

void TypeChecker::expandir_inject_en_asm(ast::AsmStmt *as) {
    if (as == nullptr || as->body.find("inject(") == std::string::npos) return;
    const std::string orig = as->body;
    std::string salida;
    salida.reserve(orig.size());
    size_t p = 0;
    while (p < orig.size()) {
        if (orig.compare(p, 7, "inject(") != 0) {
            salida.push_back(orig[p]);
            ++p;
            continue;
        }
        // Buscar el ')' que cierra, contando anidados: el argumento puede ser
        // una llamada con sus propios parentesis.
        size_t cierre = p + 7;
        int prof = 1;
        while (cierre < orig.size() && prof > 0) {
            if (orig[cierre] == '(')
                ++prof;
            else if (orig[cierre] == ')')
                --prof;
            if (prof > 0) ++cierre;
        }
        if (prof != 0) {
            diags_.error(as->loc, "asm: falta ')' al cerrar un inject(...)");
            salida += orig.substr(p);
            break;
        }
        const std::string texto = orig.substr(p + 7, cierre - (p + 7));
        Diagnostics d_tmp;
        Lexer lex_tmp(texto, "<asm-inject>", d_tmp);
        Parser par_tmp(lex_tmp, d_tmp);
        auto e_tmp = par_tmp.parse_one_expr();
        bool hecho = false;
        if (e_tmp && !d_tmp.has_errors()) {
            // CHEQUEAR antes de evaluar: sin esto una llamada a una funcion
            // comptime no resuelve y la evaluacion no da nada.
            (void)check_expr(e_tmp.get());
            const ComptimeEvalResult r = comptime_eval_expr(*this, e_tmp.get());
            /* Un resultado DIFERIDO no es un resultado: llega con la cadena
             * VACIA porque la maquina de compilacion aun no podia ejecutar la
             * funcion.  Empalmarlo dejaria el bloque asm vacio SIN decir nada
             * -- que es lo que hacia, y por eso una copia escrita con inject
             * no copiaba nada.  Se deja el texto tal cual para que lo expanda
             * quien si pueda; si no lo expanda nadie, el ensamblador se queja
             * del `inject(` que sigue ahi, y eso se ve. */
            if (r.ok && r.is_str && !r.deferred) {
                salida += r.str;
                hecho = true;
            } else if (r.ok && r.deferred) {
                /* Se anota que quedo pendiente para que el compilador sepa que
                 * esta pasada NO es la buena y tenga que repetirla con la
                 * maquina de compilacion ya cargada.  Mientras tanto se deja un
                 * comentario: la pasada intermedia tiene que poder ensamblar.
                 */
                inject_diferido_ = true;
                salida += "; inject pendiente\n";
                hecho = true;
            }
        }
        if (!hecho) {
            diags_.error(as->loc,
                         "asm: el inject(...) no dio texto en compilacion; "
                         "tiene que ser una expresion comptime de tipo string");
        }
        p = cierre + 1;
    }
    as->body = salida;
}

void TypeChecker::check_stmt(ast::Stmt *s, const Type &fn_return_type) {
    if (!s) return;
    // F1 NLL: BlockStmt no cuenta como un stmt independiente (delegamos
    // a check_block que itera children).  Para todos los demas, este
    // ES el stmt: incrementar el contador y avanzar el borrow checker
    // (drop NLL de borrows cuyo last_use < current_stmt_idx_).
    if (s->kind != ast::NodeKind::BlockStmt) {
        ++current_stmt_idx_;
        borrow_checker_.advance_stmt(current_stmt_idx_);
    }
    switch (s->kind) {
    case ast::NodeKind::BlockStmt:
        check_block(static_cast<ast::BlockStmt *>(s), fn_return_type);
        return;
    case ast::NodeKind::VarDeclStmt:
        check_var_decl(static_cast<ast::VarDeclStmt *>(s));
        return;
    case ast::NodeKind::AsmStmt: {
        //  AS inc.7: cada operando de la lista `( <clase> <nombre> [=
        // init] )` declara una variable register-bound en el scope actual
        // (modelo read-back: legible tras el bloque = su valor de salida).
        auto *as = static_cast<ast::AsmStmt *>(s);
        /* `inject(expr)` dentro del cuerpo: se expande AQUI, en el chequeo.
         *
         * Aqui es el sitio y no el lowering, por dos razones que se notaron
         * intentandolo alli: la expresion hay que CHEQUEARLA antes de poder
         * evaluarla -- si no, una llamada a una funcion comptime no resuelve y
         * se expandia a nada -- y el cuerpo pasa por el lowering mas de una
         * vez, con lo que un `inject` sin expandir en la primera pasada
         * ensuciaba con errores de ensamblado codigo que si funcionaba.
         *
         * Expandido una sola vez y guardado en el propio nodo, el lowering ya
         * recibe el cuerpo listo. */
        expandir_inject_en_asm(as);
        for (auto &op : as->operands) {
            // Tipo: inferido del inicializador; sin init (scratch) -> i64.
            Type ty{PrimitiveKind::I64};
            if (op.init) {
                Type it = check_expr(op.init.get());
                if (it.kind != PrimitiveKind::VOID) ty = it;
            }
            // Clase de registro: `reg` = el compilador elige; concreta =
            // canonica x86; `mem` diferido.
            std::string canon;
            if (op.reg_class == "reg" || op.reg_class == "xmm" ||
                op.reg_class == "ymm" || op.reg_class == "zmm") {
                // Clases sin numero: las asigna el compilador.  `reg` para
                // enteros y `xmm`/`ymm`/`zmm` para vectoriales -- nombrar el
                // registro fisico a mano le quita al asignador la posibilidad
                // de usar los que estan libres, y obliga a mover valores que
                // ya estaban donde tocaba.
                canon = op.reg_class;
            } else if (op.reg_class == "mem") {
                diags_.error(op.loc,
                             "asm: la clase 'mem' aun no esta soportada; usa "
                             "'reg' o un registro concreto");
            } else {
                canon = asm_canonical_reg(op.reg_class);
                if (canon.empty()) {
                    diags_.error(op.loc,
                                 "asm: '" + op.reg_class +
                                     "' no es una clase de registro valida "
                                     "(reg, rax..r15, xmm.., mem)");
                } else {
                    // Conflicto same-reg concreto con otro binding vivo.
                    for (auto it = scopes_.rbegin(); it != scopes_.rend();
                         ++it) {
                        for (const auto &kv : *it) {
                            if (kv.second.reg_binding == canon) {
                                diags_.error(op.loc,
                                             "asm: el registro '" +
                                                 op.reg_class +
                                                 "' ya esta ligado a '" +
                                                 kv.first + "'");
                            }
                        }
                    }
                }
            }
            Symbol sym;
            sym.kind = SymbolKind::Variable;
            sym.type = ty;
            sym.reg_binding = canon;
            (void)declare(op.name, sym);
        }
        return;
    }
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<ast::ExprStmt *>(s);
        if (es->expr) {
            Type t = check_expr(es->expr.get());
            // si la expresion es una llamada que retorna
            // Result<V,E>, el caller DEBE manejar el resultado
            // (asignar a una var, encadenar con isOk()/value(),
            // etc).  Descartar un Result en expression-statement
            // suele ser un bug (errores ignorados silenciosamente).
            // Mismo principio que Rust con #[must_use].
            if (t.kind == PrimitiveKind::RESULT &&
                es->expr->kind == ast::NodeKind::CallExpr) {
                diags_.error(es->loc,
                             "el valor de tipo Result<...> debe ser manejado: "
                             "asigna a una variable y comprueba con "
                             "isOk()/value()/error(), "
                             "o usa unwrap() para propagar el error");
            }
        }
        return;
    }
    case ast::NodeKind::IfStmt:
        check_if(static_cast<ast::IfStmt *>(s), fn_return_type);
        return;
    case ast::NodeKind::WhileStmt:
        check_while(static_cast<ast::WhileStmt *>(s), fn_return_type);
        return;
    case ast::NodeKind::ForStmt:
        check_for(static_cast<ast::ForStmt *>(s), fn_return_type);
        return;
    case ast::NodeKind::ForEachStmt: {
        auto *fe = static_cast<ast::ForEachStmt *>(s);
        push_scope();
        // Validar que iter_expr es array.
        Type tcol = fe->iter_expr ? check_expr(fe->iter_expr.get())
                                  : Type{PrimitiveKind::COUNT};
        if (tcol.kind != PrimitiveKind::ARRAY &&
            tcol.kind != PrimitiveKind::COUNT) {
            diags_.error(fe->loc,
                         "for-each: la coleccion debe ser un array (recibido " +
                             type_to_string(tcol) + ")");
        }
        Type elem_decl = type_from_node(fe->iter_type.get());
        Type elem_actual = (tcol.kind == PrimitiveKind::ARRAY && tcol.pointee)
                               ? *tcol.pointee
                               : Type{PrimitiveKind::COUNT};
        if (elem_actual.kind != PrimitiveKind::COUNT &&
            elem_actual != elem_decl) {
            diags_.error(fe->loc, "for-each: tipo del iterador (" +
                                      type_to_string(elem_decl) +
                                      ") incompatible con tipo de elemento (" +
                                      type_to_string(elem_actual) + ")");
        }
        Symbol sym;
        sym.kind = SymbolKind::Variable;
        sym.type = elem_decl;
        if (!declare(fe->iter_name, sym)) {
            diags_.error(fe->loc, "for-each: redefinicion de variable: '" +
                                      fe->iter_name + "'");
        }
        if (fe->body) check_stmt(fe->body.get(), fn_return_type);
        pop_scope();
        return;
    }
    case ast::NodeKind::ReturnStmt:
        check_return(static_cast<ast::ReturnStmt *>(s), fn_return_type);
        return;
    case ast::NodeKind::BreakStmt:
    case ast::NodeKind::ContinueStmt:
        // En no validamos que esten dentro de un loop;
        // ese check llega en el lowering (donde es trivial).
        return;
    case ast::NodeKind::TryStmt: {
        auto *ts = static_cast<ast::TryStmt *>(s);
        if (current_fn_is_noexcept_)
            diags_.error(ts->loc,
                         "try/catch no permitido: la funcion esta marcada "
                         "@NoExcept (o el modulo @NoExceptions).  Las "
                         "excepciones estan deshabilitadas en este scope");
        if (ts->body) check_stmt(ts->body.get(), fn_return_type);
        for (auto &cc : ts->catches) {
            // Validar que el tipo de la excepcion (si se da) es
            // una clase declarada.
            if (!cc.exc_class_name.empty() &&
                class_layouts_.find(cc.exc_class_name) ==
                    class_layouts_.end()) {
                diags_.error(cc.loc, "tipo de excepcion no encontrado: '" +
                                         cc.exc_class_name + "'");
            }
            // Bindear la variable del catch al scope del body.
            push_scope();
            if (!cc.var_name.empty() && !cc.exc_class_name.empty()) {
                Symbol sym;
                sym.kind = SymbolKind::Variable;
                sym.type = Type{PrimitiveKind::CLASS};
                sym.type.struct_name = cc.exc_class_name;
                if (!declare(cc.var_name, sym)) {
                    diags_.error(cc.loc,
                                 "redefinicion de variable en catch: '" +
                                     cc.var_name + "'");
                }
            }
            if (cc.body) check_stmt(cc.body.get(), fn_return_type);
            pop_scope();
        }
        if (ts->finally_body)
            check_stmt(ts->finally_body.get(), fn_return_type);
        return;
    }
    case ast::NodeKind::ThrowStmt: {
        auto *th = static_cast<ast::ThrowStmt *>(s);
        if (current_fn_is_noexcept_)
            diags_.error(th->loc,
                         "throw no permitido: la funcion esta marcada "
                         "@NoExcept (o el modulo @NoExceptions).  Usa "
                         "Result<T,E> o panic() para errores sin excepciones");
        if (th->value) {
            Type tv = check_expr(th->value.get());
            if (tv.kind != PrimitiveKind::CLASS &&
                tv.kind != PrimitiveKind::COUNT) {
                diags_.error(th->loc, "throw: el valor debe ser una instancia "
                                      "de clase, recibido " +
                                          type_to_string(tv));
            }
        }
        return;
    }
    case ast::NodeKind::SynchronizedStmt: {
        // validar que la expresion-target es CLASS
        // (los monitores solo aplican a objetos GC-managed; primitivos
        // no tienen header de monitor en el ObjectHeader).
        auto *ss = static_cast<ast::SynchronizedStmt *>(s);
        if (ss->target) {
            Type tv = check_expr(ss->target.get());
            if (tv.kind != PrimitiveKind::CLASS &&
                tv.kind != PrimitiveKind::COUNT) {
                diags_.error(ss->loc, "synchronized: el target debe ser una "
                                      "instancia de clase, recibido " +
                                          type_to_string(tv));
            }
        }
        /* incrementa el depth para que wait/notify/notifyAll
         * dentro del body se acepten.  Decrementa al salir aun si
         * el body tuvo errores (no bloquea diagnosticos sucesivos). */
        ++synchronized_depth_;
        if (ss->body) check_stmt(ss->body.get(), fn_return_type);
        --synchronized_depth_;
        return;
    }
    case ast::NodeKind::ComptimeBlockStmt: {
        /* bloque comptime { ... } -- scope con vars
         * mutables + control de flujo completo.  Se procesa con
         * UN solo pase interleaved: para cada stmt, primero
         * validamos via check_stmt (annota IdentExprs y registra
         * vars en comptime_const_locals_), luego ejecutamos via
         * comptime_eval_stmt (aplica asignaciones, evalua while
         * con counter mutable, etc).  Esto garantiza que un
         * static_assert posterior vea el estado actualizado por
         * las asignaciones anteriores. */
        auto *cb = static_cast<ast::ComptimeBlockStmt *>(s);
        push_comptime_scope();
        ComptimeControl ctrl;
        for (auto &inner : cb->stmts) {
            if (!inner) continue;
            /* Validar permisos del stmt.  Otros stmts emiten
             * error explicito. */
            bool valid = false;
            if (inner->kind == ast::NodeKind::VarDeclStmt) {
                auto *v = static_cast<ast::VarDeclStmt *>(inner.get());
                // Dentro de un comptime block TODA var local es comptime por
                // contexto: el usuario no necesita anotar `comptime` en cada
                // una (`i32 x = 5;` == `comptime i32 x = 5;` aqui).  El init
                // debe seguir siendo comptime-evaluable (si no, error claro
                // mas abajo al ejecutar).
                v->is_comptime = true;
                valid = true;
            } else if (inner->kind == ast::NodeKind::ExprStmt ||
                       inner->kind == ast::NodeKind::IfStmt ||
                       inner->kind == ast::NodeKind::WhileStmt ||
                       inner->kind == ast::NodeKind::DoWhileStmt ||
                       inner->kind == ast::NodeKind::ForStmt ||
                       inner->kind == ast::NodeKind::BlockStmt ||
                       inner->kind == ast::NodeKind::ComptimeBlockStmt ||
                       inner->kind == ast::NodeKind::ComptimeForStmt ||
                       inner->kind == ast::NodeKind::BreakStmt ||
                       inner->kind == ast::NodeKind::ContinueStmt) {
                valid = true;
            }
            if (!valid) {
                diags_.error(
                    inner->loc,
                    "comptime block: stmt no soportado en contexto comptime");
                continue;
            }
            /* PASS A: annotation pass.  Para VarDeclStmt
             * comptime, registramos el binding via check_var_decl
             * (eso lo agrega a comptime_const_locals_).  Para
             * todo lo demas NO llamamos check_stmt (porque
             * dispararia static_assert con estado obsoleto u
             * otras evaluaciones tempranas).  En su lugar
             * confiamos en que comptime_eval_stmt anota lo que
             * necesite via check_ident interno (comptime_eval_expr
             * busca directo en comptime_const_locals_, no necesita
             * annotation). */
            if (inner->kind == ast::NodeKind::VarDeclStmt) {
                auto *v = static_cast<ast::VarDeclStmt *>(inner.get());
                check_var_decl(v);
                continue; /* check_var_decl ya evaluo el init */
            }
            /* PASS B: execute comptime.  Para ExprStmt con
             * static_assert (o cualquier CallExpr con efecto
             * compile-time), llamamos check_expr DENTRO de la
             * llamada que invoca eval.  Para AssignExpr,
             * comptime_eval_stmt actualiza el binding.  Para
             * if/while/for, ejecuta el cuerpo iterativamente. */
            if (inner->kind == ast::NodeKind::ExprStmt) {
                auto *es = static_cast<ast::ExprStmt *>(inner.get());
                if (es->expr) {
                    /* Pre-annotate identifiers via check_expr.
                     * Esto tambien dispara static_assert si lo
                     * hay -- y como se hace AHORA (tras las
                     * asignaciones previas), ve el estado
                     * actualizado. */
                    (void)check_expr(es->expr.get());
                }
            }
            /* Ejecutar el stmt en compile-time. */
            if (!comptime_eval_stmt(*this, inner.get(), ctrl)) {
                diags_.error(
                    inner->loc,
                    "comptime block: stmt no evaluable en compile-time");
                break;
            }
            if (ctrl.returned || ctrl.break_seen || ctrl.continue_seen) {
                ctrl.returned = ctrl.break_seen = ctrl.continue_seen = false;
                break;
            }
        }
        // Captura LSP (gateada): justo antes del pop, los valores
        // finales de las variables comptime locales del bloque viven
        // en el scope top.  Los serializamos para vesta/comptimeValues.
        // Cero coste cuando capture_comptime_block_locals_ esta off.
        if (capture_comptime_block_locals_ && !comptime_const_locals_.empty()) {
            const std::string scope =
                "comptime@" + std::to_string(cb->loc.line);
            for (const auto &kv : comptime_const_locals_.back()) {
                const auto &c = kv.second;
                ComptimeBlockSnapshot snap;
                snap.name = kv.first;
                snap.scope = scope;
                if (c.is_type) {
                    snap.type_kind = "type";
                    snap.value_str = type_to_string(c.type_val);
                } else if (c.is_str) {
                    snap.type_kind = "string";
                    snap.value_str = "\"" + c.str_value + "\"";
                } else if (c.is_array) {
                    snap.type_kind = "array";
                    std::string out = "[";
                    static constexpr size_t kMaxItems = 16;
                    size_t n = c.array_vals.size();
                    size_t shown = n < kMaxItems ? n : kMaxItems;
                    for (size_t i = 0; i < shown; ++i) {
                        if (i) out += ", ";
                        out += c.array_vals[i]
                                   ? render_comptime_value(*c.array_vals[i])
                                   : "?";
                    }
                    if (n > shown) out += ", ...";
                    out += "]";
                    snap.value_str = std::move(out);
                } else if (c.is_struct) {
                    snap.type_kind = "struct";
                    std::string out = "{";
                    static constexpr size_t kMaxItems = 16;
                    size_t i = 0;
                    for (const auto &fkv : c.struct_fields) {
                        if (i >= kMaxItems) {
                            out += ", ...";
                            break;
                        }
                        if (i) out += ", ";
                        out += fkv.first + "=" +
                               (fkv.second ? render_comptime_value(*fkv.second)
                                           : "?");
                        ++i;
                    }
                    out += "}";
                    snap.value_str = std::move(out);
                } else {
                    snap.type_kind = "int";
                    snap.value_str = std::to_string(c.value);
                }
                comptime_block_snapshots_.push_back(std::move(snap));
            }
        }
        pop_comptime_scope();
        return;
    }
    case ast::NodeKind::ComptimeForStmt: {
        /* A.39: comptime for (i in lo..hi) { body } -- evaluamos
         * lo y hi en compile-time.  El body se chequea UNA vez
         * con i bindeado al valor de lo (suficiente para validar
         * tipos en la primera iteracion; el lowering hace el
         * unroll real clonando el body N veces). */
        auto *cf = static_cast<ast::ComptimeForStmt *>(s);
        if (!cf->lo_expr || !cf->hi_expr) {
            diags_.error(cf->loc, "comptime for: rango incompleto");
            return;
        }
        const ComptimeEvalResult lo =
            comptime_eval_expr(*this, cf->lo_expr.get());
        const ComptimeEvalResult hi =
            comptime_eval_expr(*this, cf->hi_expr.get());
        if (!lo.ok || !hi.ok || lo.is_str || hi.is_str) {
            diags_.error(cf->loc, "comptime for: lo y hi deben ser enteros "
                                  "comptime-evaluables");
            return;
        }
        /* Chequear el body con i bindeado a lo (representativo). */
        push_comptime_scope();
        ComptimeConst c;
        c.type = Type{PrimitiveKind::I64};
        c.value = lo.value;
        register_comptime_local(cf->var_name, std::move(c));
        if (cf->body) check_stmt(cf->body.get(), fn_return_type);
        pop_comptime_scope();
        return;
    }
    default: return;
    }
}

void TypeChecker::check_var_decl(ast::VarDeclStmt *vd) {
    // BugFix R8 mutation: si el var es `comptime var` (mutable) dentro
    // de un @Macro body, lo convertimos a runtime var (lowering emite
    // ALLOCA + STORE).  El bytecode del macro asi reflejara las
    // mutaciones correctamente.  El AST evaluator mantiene su propio
    // tracking via comptime_const_locals_ + apply_comptime_assign.
    // Para `comptime const` (inmutable) mantenemos el comportamiento
    // original (skip lowering, inline en lower_ident).
    if (current_fn_is_macro_ && vd->is_comptime && !vd->is_const && vd->init) {
        // Evaluar init y registrar para AST eval; pero convertir a
        // runtime var (clear is_comptime).
        const ComptimeEvalResult r = comptime_eval_expr(*this, vd->init.get());
        if (r.ok) {
            ComptimeConst c;
            if (vd->type) {
                c.type = type_from_node(vd->type.get());
            } else if (r.is_str) {
                c.type = Type{PrimitiveKind::STRING};
            } else {
                c.type = Type{PrimitiveKind::I64};
            }
            c.is_str = r.is_str;
            c.is_mutable = true;
            if (r.is_str)
                c.str_value = r.str;
            else
                c.value = r.value;
            register_comptime_local(vd->name, std::move(c));
        }
        vd->is_comptime = false; // convertir a runtime
        // FALLTHROUGH: el resto de check_var_decl emite runtime storage.
    }
    // BugFix R8 (read-only): dentro de un @Macro body, las var-decls
    // SIN modificador comptime registran su valor inicial en
    // @c comptime_const_locals_ para que el AST evaluator resuelva
    // IdentExprs cuando otros builtins comptime (comptime_concat,
    // etc.) los necesitan.  NO marcamos is_comptime en el AST.
    /* P1: en una comptime fn ruteada a la VM (no @Macro) NO registramos los
     * locales runtime como comptime_const_locals.  Si lo hicieramos, un builtin
     * como comptime_concat(buf, ...) dentro de un loop pliega el snapshot
     * INICIAL de buf ("") en vez de bajarse como STRCAT runtime que acumula ->
     * el loop devolveria solo el primer elemento (bug alphabet_up_to="A").  La
     * fn corre SIEMPRE en la VM, no necesita el snapshot para AST-eval. */
    if (current_fn_is_macro_ && !current_fn_is_vm_comptime_fn_ &&
        !vd->is_comptime && vd->init) {
        const ComptimeEvalResult r = comptime_eval_expr(*this, vd->init.get());
        if (r.ok) {
            ComptimeConst c;
            if (vd->type) {
                c.type = type_from_node(vd->type.get());
            } else if (r.is_str) {
                c.type = Type{PrimitiveKind::STRING};
            } else {
                c.type = Type{PrimitiveKind::I64};
            }
            c.is_str = r.is_str;
            c.is_array = r.is_array;
            c.is_struct = r.is_struct;
            c.is_mutable = !vd->is_const;
            if (r.is_str)
                c.str_value = r.str;
            else if (r.is_array)
                c.array_vals = r.array_vals;
            else if (r.is_struct)
                c.struct_fields = r.struct_fields;
            else
                c.value = r.value;
            register_comptime_local(vd->name, std::move(c));
        }
        // FALLTHROUGH: el resto de check_var_decl emite el var-decl
        // como runtime normal (ALLOCA + STORE).  El AST evaluator usa
        // el comptime local registrado arriba; el VM/bytecode usa la
        // variable runtime con sus mutaciones aplicadas en orden.
    }
    // Captura LSP: recordar el valor comptime de la variable cuando su init es
    // una EXPRESION evaluable (builtin como field_count<T>, o combinacion de
    // vars/builtins) -- no un literal puro, que podria reasignarse despues.
    // Sirve para evaluar luego la condicion de los `if` que la usen.
    if (capture_comptime_block_locals_ && vd->init) {
        const ast::NodeKind k = vd->init->kind;
        const bool is_literal = (k == ast::NodeKind::IntLitExpr ||
                                 k == ast::NodeKind::BoolLitExpr ||
                                 k == ast::NodeKind::CharLitExpr);
        int64_t v;
        const bool known = !is_literal && lsp_eval_int(vd->init.get(), &v);
        if (known) lsp_var_values_[vd->name] = v;
        const bool is_bool = vd->init->result_type.kind == PrimitiveKind::BOOL;
        auto val_str = [&]() -> std::string {
            return is_bool
                       ? (v != 0 ? std::string("true") : std::string("false"))
                       : std::to_string(v);
        };
        if (vd->infer_type) {
            // `auto`/`var`: mostrar el TIPO deducido (+ valor si se conoce).
            std::string ts = type_to_string(vd->init->result_type);
            if (!ts.empty() && ts != "void") {
                ComptimeBuiltinHit hit;
                hit.loc = vd->init->loc;
                hit.name = "type"; // builtin_kind="type" -> prefijo ": "
                hit.type_kind = "type";
                hit.value_str = known ? (ts + " = " + val_str()) : ts;
                comptime_builtin_hits_.push_back(std::move(hit));
            }
        } else if (known) {
            // Tipo explicito + init constante o COMPTIME (incluye llamadas a
            // `comptime fn`, que el evaluador real ejecuta de verdad): p.ej.
            // `i32 mask = 1 << 8` -> = 256, `comptime i64 F = fib(10)` -> = 55.
            // (Si el init es un builtin de introspeccion -- sizeof<T>, ... --
            // este "al final" coincide en la linea con el hit del builtin; el
            // cliente muestra uno: no se duplica visualmente.)
            ComptimeBuiltinHit hit;
            hit.loc = vd->init->loc;
            hit.name = "expr"; // builtin_kind="expr" -> el cliente lo pinta
            hit.type_kind = is_bool ? "bool" : "int";
            hit.value_str = val_str();
            comptime_builtin_hits_.push_back(std::move(hit));
        }
    }
    /* `comptime const NAME = expr;` local.  Evalua el init en
     * compile-time y registra en el scope local de comptime const.
     * El lowering lo trata como no-op (no genera ALLOCA ni STORE);
     * cualquier ident posterior queda anotado por check_ident. */
    if (vd->is_comptime) {
        if (!vd->init) {
            diags_.error(vd->loc, std::string("'comptime ") +
                                      (vd->is_const ? "const " : "") +
                                      vd->name + "' requiere un inicializador");
            return;
        }
        const ComptimeEvalResult r = comptime_eval_expr(*this, vd->init.get());
        if (!r.ok) {
            diags_.error(vd->init->loc, std::string("el init de 'comptime ") +
                                            (vd->is_const ? "const " : "") +
                                            vd->name +
                                            "' no es comptime-evaluable");
            return;
        }
        ComptimeConst c;
        /* sugar: si vd->type es nullptr (sugar `comptime X = ...`
         * local sin tipo explicito), inferimos el tipo desde el
         * ComptimeEvalResult.  Misma logica que en el handler global. */
        if (vd->type) {
            c.type = type_from_node(vd->type.get());
        } else if (r.is_str) {
            c.type = Type{PrimitiveKind::STRING};
        } else if (r.is_type) {
            c.type = Type{PrimitiveKind::TYPE_META};
        } else {
            c.type = Type{PrimitiveKind::I64};
        }
        c.is_str = r.is_str;
        c.is_array = r.is_array;
        c.is_struct = r.is_struct;
        c.is_type = r.is_type;
        c.is_mutable = !vd->is_const;
        /* P1: propagar DIFERIDO.  Un comptime local cuyo init depende de una
         * comptime fn ruteada a la ComptimeVM (sin bytecode en pass 1) es
         * diferido; sin esto, un static_assert posterior sobre el local
         * dispararia con el placeholder (0) en pass 1 en vez de resolverse en
         * pass 2.  Mismo fix que el pre-pase global (1547) y el block-local. */
        c.deferred = r.deferred;
        if (r.is_str)
            c.str_value = r.str;
        else if (r.is_array)
            c.array_vals = r.array_vals;
        else if (r.is_struct)
            c.struct_fields = r.struct_fields;
        else if (r.is_type)
            c.type_val = r.type_val;
        else
            c.value = r.value;
        register_comptime_local(vd->name, std::move(c));
        return;
    }
    Symbol s;
    s.kind = SymbolKind::Variable;
    /* `auto NAME = init;` o `var NAME = init;` -- inferencia
     * local.  El parser dejo @c vd->type=nullptr y marco infer_type.
     * Computamos el tipo del init aqui y lo aplicamos al binding sin
     * reconstruir el AST.  Falla con error si no hay init. */
    if (vd->infer_type) {
        if (!vd->init) {
            diags_.error(vd->loc, "'auto " + vd->name +
                                      "' requiere un inicializador (no se "
                                      "puede inferir sin valor)");
            return;
        }
        s.type = check_expr(vd->init.get());
        if (s.type.kind == PrimitiveKind::VOID) {
            diags_.error(vd->loc, "no se pudo inferir el tipo de '" + vd->name +
                                      "' (init devuelve void)");
            return;
        }
    } else {
        s.type = type_from_node(vd->type.get());
    }
    /* Y la direccion, si la lleva.  Por el MISMO sitio que la de un parametro:
     * en una variable la marca ya no dice que hace una funcion -- no hay
     * funcion --, pero el permiso es el mismo, y con dos criterios acabarian
     * siendo dos cosas con el mismo nombre. */
    check_param_dir_(vd->name, vd->dir, vd->loc, s.type);
    s.is_const = vd->is_const;
    // Captura del alias de reflexion (Class/Method/Field/Object) para
    // habilitar dispatch ergonomico `cls.getMethod(...)` etc.  El TypeNode
    // original era un NamedTypeNode con el nombre del alias; tras
    // type_from_node el tipo subyacente queda como i64.  Si el nombre
    // textual coincide con uno de los aliases magicos, registramos en
    // el Symbol para que `check_field_access` lo recupere despues.
    if (vd->type && vd->type->kind == ast::NodeKind::NamedTypeNode) {
        const auto *nt =
            static_cast<const ast::NamedTypeNode *>(vd->type.get());
        if (nt->name == "Class" || nt->name == "Method" ||
            nt->name == "Field" || nt->name == "Object") {
            s.reflection_alias = nt->name;
        }
    }
    // Restricciones para arrays nativos como variables locales:
    //  - El tamano debe ser conocido (T[]) solo se admite como tipo de
    //    parametro de funcion, no como variable.
    //  - El tamano debe ser > 0 (literal entero positivo).
    // El caso T[] como parametro se construye en otro punto (firma de
    // funcion, no aqui), por lo que aqui basta reportar.
    if (s.type.kind == PrimitiveKind::ARRAY && s.type.array_size == 0) {
        // bug4: arrays dinamicos `T[]` con init `new T[N]` o asignacion
        // desde otro array dinamico son legales: el slot guarda el
        // host_ptr al buffer alocado heap.  Solo rechazar si NO hay init
        // (variable sin tamano fijo ni alocacion runtime).
        const bool init_provides_size =
            vd->init && (vd->init->kind == ast::NodeKind::NewExpr ||
                         vd->init->kind == ast::NodeKind::CallExpr ||
                         vd->init->kind == ast::NodeKind::IdentExpr ||
                         vd->init->kind == ast::NodeKind::FieldAccessExpr);
        if (!init_provides_size) {
            diags_.error(vd->loc, "el array '" + vd->name +
                                      "' requiere un tamano fijo (T[N] con N > "
                                      "0) o init con `new T[N]`");
        }
    }
    //  AS inc.2: validacion del storage-class register("reg").
    //  (a) el nombre debe ser un registro x86-64 reconocido;
    //  (b) el tipo debe ser primitivo (int/float/bool/char/ptr);
    //  (c) no puede haber otra variable viva en el MISMO scope ligada
    //      al mismo registro fisico (canonico).  Liveness completo se
    //      difiere a inc.5; aqui basta deteccion same-scope.
    if (!vd->reg_binding.empty()) {
        const std::string canon = asm_canonical_reg(vd->reg_binding);
        if (canon.empty()) {
            diags_.error(vd->loc,
                         "register(\"" + vd->reg_binding + "\"): '" +
                             vd->reg_binding +
                             "' no es un registro reconocido (x86-64: rax..r15,"
                             " xmm/ymm/zmm; AArch64: x0..x30, w0..w30, sp, lr,"
                             " fp, xzr, v/b/h/s/d/q 0..31)");
        } else {
            const PrimitiveKind k = s.type.kind;
            const bool ok_prim = is_numeric(k) || k == PrimitiveKind::BOOL ||
                                 k == PrimitiveKind::CHAR ||
                                 k == PrimitiveKind::PTR;
            if (!ok_prim) {
                diags_.error(
                    vd->loc,
                    "register(\"" + vd->reg_binding +
                        "\") solo admite tipos "
                        "primitivos (entero/float/bool/char/ptr), no '" +
                        vd->name + "'");
            }
            // Conflicto same-reg en CUALQUIER scope activo (no solo el
            // mas interno): dos variables register-bound vivas a la vez
            // ligadas al mismo registro fisico colisionarian al listarse
            // ambas como operandos del mismo bloque asm.  Recorremos toda
            // la cadena de scopes.
            bool conflict_found = false;
            for (auto it = scopes_.rbegin();
                 it != scopes_.rend() && !conflict_found; ++it) {
                for (const auto &kv : *it) {
                    if (kv.second.reg_binding == canon) {
                        diags_.error(vd->loc,
                                     "conflicto de register: '" +
                                         vd->reg_binding +
                                         "' ya esta ligado a la variable '" +
                                         kv.first + "' viva en este ambito");
                        conflict_found = true;
                        break;
                    }
                }
            }
            s.reg_binding = canon; // canonico para el conflicto y el backend
        }
    }
    if (!declare(vd->name, s)) {
        diags_.error(vd->loc, "redefinicion de variable: '" + vd->name + "'");
    }
    // @Abstract: un struct abstracto no se puede instanciar por VALOR (solo
    // sirve de base); como tipo de un puntero (`Base*`) si es valido.  Se
    // chequea aqui (con o sin init) para cubrir tambien `Base b;` sin
    // inicializador.
    // @Abstract: un struct abstracto no se puede instanciar por VALOR (solo
    // sirve de base); como tipo de un puntero (`Base*`) si.  EXCEPCION: dentro
    // de un metodo del PROPIO abstracto, `Self` se resuelve a el mismo (`Base
    // r`) y eso es el mecanismo, no una instanciacion del usuario -> permitido.
    if (s.type.kind == PrimitiveKind::STRUCT &&
        current_struct_ != s.type.struct_name) {
        auto it_ab = struct_layouts_.find(s.type.struct_name);
        if (it_ab != struct_layouts_.end() && it_ab->second.is_abstract)
            diags_.error(vd->loc, "no se puede instanciar el struct '" +
                                      s.type.struct_name +
                                      "' porque es @Abstract; usa un derivado");
    }
    // Safety net (item 1): copia de un struct tainteado (`T s2 = s1;`)
    // propaga el taint -> `s2` tambien apunta al closure-en-stack y su escape
    // se rechaza igual.
    if (vd->init && vd->init->kind == ast::NodeKind::IdentExpr) {
        auto *iid = static_cast<ast::IdentExpr *>(vd->init.get());
        if (struct_stack_closure_taint_.count(iid->name))
            struct_stack_closure_taint_.insert(vd->name);
    }
    // Borrow checker: si la variable es @c unique<T>/shared<T>,
    // registrarla como owner (posible objeto de prestamos).  Si la
    // variable es @c borrow<T>/borrow_mut<T>, registrarla como
    // borrower del owner del que provino.  El registro real ocurre
    // tras chequear el init (que es donde sabemos el owner via
    // lend(owner)).
    if (s.type.kind == PrimitiveKind::UNIQUE_PTR ||
        s.type.kind == PrimitiveKind::SHARED_PTR) {
        borrow_checker_.declare_owner(vd->name);
    }
    if (vd->init) {
        // si la variable tiene tipo `fn(T1, T2) -> R` y
        // el inicializador es una @c LambdaExpr, propagamos los tipos
        // declarados a los parametros de la lambda que no llevan
        // anotacion explicita (poor-man's bidirectional type checking).
        // Tambien anotamos return_type para que check_lambda lo respete.
        // Esto permite la sintaxis natural sin escribir tipos dos veces:
        //   fn(i32) -> i32 sq = (x) => x * x;       // x deducido a i32
        // Si el numero de parametros no coincide, NO mutamos nada: el
        // check normal generara el diagnostico de aridad.
        if (s.type.kind == PrimitiveKind::FUNCTION &&
            vd->init->kind == ast::NodeKind::LambdaExpr) {
            propagate_fn_type_to_lambda(
                static_cast<ast::LambdaExpr *>(vd->init.get()), s.type);
        }
        // Opcion B: auto-envolver init list anonimo en unique_box/shared_box.
        //   unique<Punto> p = {.x=10, .y=20};  ===>
        //   unique<Punto> p = unique_box({.x=10, .y=20});
        // Anotamos target_type_name del init list para que el check
        // del init list valide campos contra el struct destino y
        // devuelva un Type STRUCT (en vez de COUNT).
        if ((s.type.kind == PrimitiveKind::UNIQUE_PTR ||
             s.type.kind == PrimitiveKind::SHARED_PTR) &&
            s.type.pointee && vd->init->kind == ast::NodeKind::InitListExpr &&
            s.type.pointee->kind == PrimitiveKind::STRUCT) {
            auto *il = static_cast<ast::InitListExpr *>(vd->init.get());
            il->target_type_name = s.type.pointee->struct_name;
            // Sintetizar CallExpr(unique_box/shared_box, [init_list]).
            auto wrap = std::make_unique<ast::CallExpr>();
            wrap->loc = vd->init->loc;
            auto callee = std::make_unique<ast::IdentExpr>();
            callee->loc = vd->init->loc;
            callee->name = (s.type.kind == PrimitiveKind::UNIQUE_PTR)
                               ? "unique_box"
                               : "shared_box";
            wrap->callee = std::move(callee);
            wrap->args.push_back(std::move(vd->init));
            vd->init = std::move(wrap);
        }
        // L2.3: si el tipo declarado es un enum generico monomorphizado
        // (e.g. Maybe_i32), push expected_enum_stack para que el RHS
        // `Maybe.Some(42)` o `Maybe.None` resuelva al mangled correcto.
        bool pushed_expected_enum = false;
        if (s.type.kind == PrimitiveKind::STRUCT &&
            !s.type.struct_name.empty()) {
            const std::string &mn = s.type.struct_name;
            size_t us = mn.find('_');
            if (us != std::string::npos) {
                std::string templ = mn.substr(0, us);
                if (is_generic_enum_template(templ)) {
                    push_expected_enum(templ, mn);
                    pushed_expected_enum = true;
                }
            }
        }
        // Sprint edge-bugs (2026-06-02): propagar expected_optional_type_
        // y expected_result_type_ al check_expr del init.  Sin esto
        // Optional<Optional<i32>> o = Some(Some(42)) NO infiere el
        // inner Some como Optional<i32> (queda como Optional<i64> por
        // el literal 42).  Mismo patron que check_return ya hacia.
        const Type saved_outer_opt = expected_optional_type_;
        const Type saved_outer_result = expected_result_type_;
        if (s.type.kind == PrimitiveKind::OPTIONAL) {
            expected_optional_type_ = s.type;
        } else if (s.type.kind == PrimitiveKind::RESULT) {
            expected_result_type_ = s.type;
        }
        Type t = check_expr(vd->init.get());
        expected_optional_type_ = saved_outer_opt;
        expected_result_type_ = saved_outer_result;
        if (pushed_expected_enum) pop_expected_enum();
        // Funciones de primera clase: `fn(...)->R f = nombre_funcion;`.  Si el
        // tipo declarado es FUNCTION y el init es un IdentExpr que resuelve a
        // una funcion top-level con firma compatible, lo PROMOCIONAMOS a un
        // function value {fn_addr, env=0}.  Mismo mecanismo que la promocion en
        // argumentos de HOF (check_call); el lowering de un IdentExpr con
        // result_type FUNCTION emite el slot via emit_topfn_value.
        if (s.type.kind == PrimitiveKind::FUNCTION &&
            t.kind == PrimitiveKind::VOID &&
            vd->init->kind == ast::NodeKind::IdentExpr) {
            auto *id_arg = static_cast<ast::IdentExpr *>(vd->init.get());
            const Symbol *s_arg = lookup(id_arg->name);
            if (s_arg && s_arg->kind == SymbolKind::Function) {
                const FunctionSig &arg_sig = function_sigs_[s_arg->sig_index];
                Type fnv = Type::make_function(arg_sig.param_types,
                                               arg_sig.return_type);
                if (types_assignable(s.type, fnv)) {
                    t = fnv;
                    id_arg->result_type = fnv;
                }
            }
        }
        /* `unique<T> p = unique_with(h, del);` -- la variable ADOPTA el
         * liberador de su inicializador.
         *
         * Quien libera es parte del tipo, asi que en rigor lo declarado y lo
         * asignado son tipos distintos.  Pero en una declaracion LOCAL el
         * tipo declarado se lee como "un unique de T, liberador el que traiga
         * el inicializador": es la unica lectura util, y ademas es la que
         * mantiene escribible lo que ya estaba escrito.  Donde el tipo esta
         * fijado de antemano -- un campo, una firma -- no se puede adoptar
         * nada y hay que escribirlo (`unique<T, del>`), porque quien limpie
         * del otro lado tiene que saber a quien llamar. */
        if ((s.type.kind == PrimitiveKind::UNIQUE_PTR ||
             s.type.kind == PrimitiveKind::SHARED_PTR) &&
            s.type.deleter_name.empty() && t.kind == s.type.kind &&
            !t.deleter_name.empty()) {
            s.type.deleter_name = t.deleter_name;
            if (vd->type) vd->declared_deleter = t.deleter_name;
            /* Y en el simbolo YA REGISTRADO: `declare()` lo metio en el ambito
             * antes de mirar el inicializador, asi que mutar la copia de aqui
             * no alcanza.  Sin esto, un `move(a)` posterior lee el tipo de `a`
             * SIN liberador y el recurso se libera con el que no es -- o no se
             * libera. */
            auto &top = scopes_.back();
            auto it_sym = top.find(vd->name);
            if (it_sym != top.end())
                it_sym->second.type.deleter_name = t.deleter_name;
        }
        // implicit Some: si el tipo declarado es Optional<T> y el
        // init es de tipo T (o asignable a T), envolvemos el init
        // automaticamente con `Some(...)`.  null literal -> None().
        // Esto permite la sintaxis natural:
        //   Optional<i32> a = 50;       -> Some(50)
        //   Optional<i32> a = null;     -> None()
        // sin obligar al usuario a escribir `Some(50)` cada vez.
        if (s.type.kind == PrimitiveKind::OPTIONAL && s.type.pointee &&
            t.kind != PrimitiveKind::OPTIONAL &&
            t.kind != PrimitiveKind::COUNT) {
            if (vd->init->kind == ast::NodeKind::NullLitExpr) {
                // Reemplazar init con None().
                auto none_call = std::make_unique<ast::CallExpr>();
                none_call->loc = vd->init->loc;
                auto callee = std::make_unique<ast::IdentExpr>();
                callee->loc = vd->init->loc;
                callee->name = "None";
                none_call->callee = std::move(callee);
                vd->init = std::move(none_call);
                t = check_expr(vd->init.get()); // re-tipar
            } else if (types_assignable(*s.type.pointee, t) ||
                       class_is_assignable(*s.type.pointee, t)) {
                // Reemplazar init con Some(init_original).
                auto some_call = std::make_unique<ast::CallExpr>();
                some_call->loc = vd->init->loc;
                auto callee = std::make_unique<ast::IdentExpr>();
                callee->loc = vd->init->loc;
                callee->name = "Some";
                some_call->callee = std::move(callee);
                some_call->args.push_back(std::move(vd->init));
                vd->init = std::move(some_call);
                t = check_expr(vd->init.get());
            }
        }
        // Coherencia laxa: numericos se promueven en lowering, void*
        // (literal null) es asignable a cualquier T*. si
        // ambos lados son CLASS, permitimos upcast desde clase a
        // interfaz (o supereinterfaz) implementada.  Optional:
        // null es asignable a cualquier referencia (CLASS), modelando
        // semantica nullable por defecto en reference types.
        const bool is_null_lit = vd->init->kind == ast::NodeKind::NullLitExpr;
        const bool null_to_class =
            is_null_lit && s.type.kind == PrimitiveKind::CLASS;
        // Promocion de nombre desnudo de funcion: `cfn(...) f = doblar` o
        // `fn(...) g = doblar` -> tratar el nombre como &doblar (cfn) o
        // como slot lambda {addr,0} segun el tipo declarado.
        t = maybe_promote_func_ref(vd->init.get(), s.type, t);
        // nonnull: si el tipo declarado lleva el modificador
        // nonnull, rechazar literal null como inicializador.
        /* El consejo que daba antes -- "use !!x para forzar unwrap" -- dejo de
         * valer.  Para empezar, sobre el literal `null` nunca valio: `!!null`
         * es lanzar SIEMPRE, asi que cambiaba un error de compilacion por un
         * fallo garantizado en ejecucion.  Y desde que asignar a un `nonnull`
         * comprueba por si mismo, escribir `!!` ahi no anade nada: la
         * comprobacion de mas la borra el optimizador (medido: dos antes de
         * optimizar, una despues).  Lo que hay que decir es que las dos mitades
         * -- el tipo y el valor -- no pueden ser las dos como estan. */
        if (vd->type && vd->type->is_nonnull && is_null_lit) {
            diags_.error(vd->loc,
                         "no se puede asignar null a una variable 'nonnull': "
                         "el tipo promete que nunca lo es.  Quite 'nonnull' "
                         "del tipo, o de un valor inicial que no sea null");
        }
        // Inferencia CTAD: `Caja c = expr;` con un nombre de template generico
        // SIN args de tipo y un init cuyo tipo es una monomorphizacion del
        // template (`Caja_i64`) -> deducir los args del init (como C++17 CTAD).
        // Equivalente a `auto c = expr;` pero con el nombre del template
        // escrito.
        if (vd->type && vd->type->kind == ast::NodeKind::NamedTypeNode) {
            auto *nt = static_cast<ast::NamedTypeNode *>(vd->type.get());
            const bool is_template = is_generic_struct_template(nt->name) ||
                                     is_generic_enum_template(nt->name) ||
                                     generic_templates_.count(nt->name) > 0;
            if (nt->type_args.empty() && is_template &&
                (t.kind == PrimitiveKind::STRUCT ||
                 t.kind == PrimitiveKind::CLASS) &&
                t.struct_name.rfind(nt->name + "_", 0) == 0) {
                s.type = t; // deducir el tipo concreto del init
                // Actualizar el simbolo ya declarado (declare() lo metio en el
                // scope antes de computar el init) para que `c.campo` resuelva.
                auto &top = scopes_.back();
                auto it_sym = top.find(vd->name);
                if (it_sym != top.end()) it_sym->second.type = t;
                // Reescribir el TypeNode al nombre concreto monomorphizado para
                // que el lowering (que re-resuelve vd->type) lo baje bien.
                nt->name = t.struct_name;
            }
        }
        // Un newtype NUMERICO (typedef-new sobre int/float, p.ej. `uintptr`)
        // ACEPTA una CONSTANTE numerica como inicializador sin cast (como C:
        // `uintptr x = 0;`): el newtype ES un tipo numerico y recibir un
        // literal/constante numerica es natural.  Un valor NO-constante (otra
        // variable) sigue requiriendo cast explicito para preservar la
        // seguridad del tipo nominal.  El literal toma el tipo del newtype.
        bool numeric_const_to_newtype = false;
        if (s.type.nominal_id != 0 && is_numeric(s.type.kind) && vd->init) {
            const ast::Expr *ie = vd->init.get();
            const bool is_num_const =
                ie->kind == ast::NodeKind::IntLitExpr ||
                ie->kind == ast::NodeKind::FloatLitExpr ||
                ie->kind == ast::NodeKind::CharLitExpr ||
                (ie->kind == ast::NodeKind::UnaryExpr &&
                 (static_cast<const ast::UnaryExpr *>(ie)->op ==
                      ast::UnOp::Neg ||
                  static_cast<const ast::UnaryExpr *>(ie)->op ==
                      ast::UnOp::BitNot) &&
                 static_cast<const ast::UnaryExpr *>(ie)->operand &&
                 (static_cast<const ast::UnaryExpr *>(ie)->operand->kind ==
                      ast::NodeKind::IntLitExpr ||
                  static_cast<const ast::UnaryExpr *>(ie)->operand->kind ==
                      ast::NodeKind::FloatLitExpr));
            if (is_num_const &&
                (is_numeric(t.kind) || t.kind == PrimitiveKind::CHAR)) {
                numeric_const_to_newtype = true;
                vd->init->result_type = s.type; // el literal es del newtype
            }
        }
        // @Virtual: upcast de puntero `Derivado* -> Base*` (herencia estatica).
        const bool ptr_upcast = struct_ptr_upcast_ok(s.type, t);
        if (!numeric_const_to_newtype && t.kind != PrimitiveKind::COUNT &&
            !types_assignable(s.type, t) && !class_is_assignable(s.type, t) &&
            !null_to_class && !ptr_upcast) {
            std::string msg = std::string("tipo del inicializador (") +
                              type_to_string(t) +
                              ") incompatible con tipo declarado (" +
                              type_to_string(s.type) + ")";
            // La conversion entero<->puntero NUNCA es implicita: si el mismatch
            // es exactamente ese, sugerir el cast explicito (el usuario debe
            // indicar la intencion con `(T)expr`).
            const bool decl_ptr = (s.type.kind == PrimitiveKind::PTR);
            const bool init_ptr = (t.kind == PrimitiveKind::PTR);
            const bool decl_int = is_integer_kind(s.type.kind);
            const bool init_int = is_integer_kind(t.kind);
            if ((decl_ptr && init_int) || (decl_int && init_ptr))
                msg +=
                    "; la conversion entero<->puntero no es implicita, usa un "
                    "cast explicito: (" +
                    type_to_string(s.type) + ")expr";
            diags_.error(vd->loc, msg);
        }
        // Bug fix 2026-05-23 (LR1): detectar overflow de literales
        // enteros al tipo declarado.  `i32 x = 2147483648;` ahora
        // emite warning.  Cubre IntLitExpr directo y UnaryExpr(Neg,
        // IntLitExpr) para literales negativos.
        bool has_int_lit_init = false;
        bool lit_negative = false;
        uint64_t lit_magnitude = 0;
        if (vd->init->kind == ast::NodeKind::IntLitExpr) {
            has_int_lit_init = true;
            lit_magnitude =
                static_cast<ast::IntLitExpr *>(vd->init.get())->value;
        } else if (vd->init->kind == ast::NodeKind::UnaryExpr) {
            auto *u = static_cast<ast::UnaryExpr *>(vd->init.get());
            if (u->op == ast::UnOp::Neg && u->operand &&
                u->operand->kind == ast::NodeKind::IntLitExpr) {
                has_int_lit_init = true;
                lit_negative = true;
                lit_magnitude =
                    static_cast<ast::IntLitExpr *>(u->operand.get())->value;
            }
        }
        // Un literal que no cabe en su destino es ERROR, no aviso: truncar es
        // una decision, y una decision se escribe.  Quien la quiera tiene el
        // cast (`(u8) 300`), que dice lo mismo pero a proposito.
        if (has_int_lit_init && is_integral(s.type.kind) &&
            !literal_fits(s.type.kind, lit_negative, lit_magnitude)) {
            diags_.error(
                vd->init ? vd->init->loc : vd->loc,
                vx::diag::format("VXT001",
                                 {literal_text(lit_negative, lit_magnitude),
                                  type_to_string(s.type),
                                  numeric_range_text(s.type.kind)}));
        }
        // Borrow checker: si el var-decl recibio un borrow, asociar
        // el nombre de la variable como borrower del owner correcto.
        // El owner puede venir de tres rutas:
        //   1. lend(owner_var) directo            -> owner = owner_var
        //   2. lend(borrow_var) (reborrow)        -> owner = root via
        //   root_owner_of
        //   3. factory(): borrow propagado via F4 -> owner =
        //   init->borrow_owner_source
        if ((s.type.kind == PrimitiveKind::BORROW ||
             s.type.kind == PrimitiveKind::BORROW_MUT)) {
            std::string owner = vd->init->borrow_owner_source;
            if (owner.empty() && vd->init->kind == ast::NodeKind::CallExpr) {
                auto *ce = static_cast<ast::CallExpr *>(vd->init.get());
                if (ce->callee &&
                    ce->callee->kind == ast::NodeKind::IdentExpr &&
                    ce->args.size() == 1 &&
                    ce->args[0]->kind == ast::NodeKind::IdentExpr) {
                    auto *cid = static_cast<ast::IdentExpr *>(ce->callee.get());
                    if (cid->name == "lend" || cid->name == "lend_mut") {
                        auto *o =
                            static_cast<ast::IdentExpr *>(ce->args[0].get());
                        owner = borrow_checker_.root_owner_of(o->name);
                        if (owner.empty()) owner = o->name;
                    }
                }
            }
            if (!owner.empty()) {
                const bool is_mut = (s.type.kind == PrimitiveKind::BORROW_MUT);
                borrow_checker_.register_borrow(vd->name, owner, is_mut);
                // F3 ext - si el init fue un lend()/lend_mut() cuya
                // fuente era un borrow_mut, marcamos este binding como
                // reborrow para que su drop restaure el estado
                // suspendido del owner.
                if (vd->init->borrow_reborrow_source_is_mut &&
                    !vd->init->borrow_reborrow_source_name.empty()) {
                    borrow_checker_.mark_as_reborrow(
                        vd->name, vd->init->borrow_reborrow_source_name);
                }
            }
        }
    }

    // Ruta B (H2 move-only): `S b = a` donde `a` es un local y `S` es un
    // struct GESTIONADO (con `~Struct()` o un campo destructible) SIN
    // copy-hook `__clone__` es un MOVE: la fuente `a` queda invalidada (su
    // dtor de scope-exit se suprime en el lowering para evitar doble-free).
    // Marcamos `a` como movido para que un uso posterior sea un error claro.
    if (vd->init && vd->init->kind == ast::NodeKind::IdentExpr &&
        s.type.kind == PrimitiveKind::STRUCT) {
        auto it_sl = struct_layouts_.find(s.type.struct_name);
        if (it_sl != struct_layouts_.end()) {
            const StructLayout &sl = it_sl->second;
            bool managed = sl.has_destructible_field;
            if (!managed) {
                for (const auto &mm : sl.methods)
                    if (mm.is_destructor) {
                        managed = true;
                        break;
                    }
            }
            if (managed && !sl.has_copy_hook) {
                auto *src = static_cast<ast::IdentExpr *>(vd->init.get());
                // Solo locales (no campos/params globales): el move solo
                // aplica a un binding que poseemos en este scope.
                moved_locals_.insert(src->name);
            }
        }
    }
}

bool TypeChecker::lsp_eval_builtin_scalar(const ast::CallExpr *e,
                                          int64_t *out) {
    auto *id = dynamic_cast<const ast::IdentExpr *>(e->callee.get());
    if (!id || e->type_args.empty()) return false;
    const std::string &nm = id->name;
    const Type t1 = type_from_node(e->type_args[0].get());
    std::string str_arg;
    if (!e->args.empty())
        if (auto *sl =
                dynamic_cast<const ast::StringLitExpr *>(e->args[0].get()))
            str_arg = sl->value;
    if (nm == "sizeof") {
        *out = (int64_t)comptime_type_size(*this, t1);
        return true;
    }
    if (nm == "alignof") {
        *out = (int64_t)comptime_type_align(*this, t1);
        return true;
    }
    if (nm == "type_id") {
        *out = (int64_t)comptime_type_id(*this, t1);
        return true;
    }
    if (nm == "kind") {
        *out = (int64_t)(int)comptime_type_kind(t1);
        return true;
    }
    if (nm == "field_count") {
        *out = (int64_t)comptime_field_count(*this, t1);
        return true;
    }
    if (nm == "method_count") {
        *out = (int64_t)comptime_method_count(*this, t1);
        return true;
    }
    if (nm == "offsetof") {
        *out = (int64_t)comptime_field_offset(*this, t1, str_arg);
        return true;
    }
    if (nm == "has_field") {
        *out = comptime_has_field(*this, t1, str_arg) ? 1 : 0;
        return true;
    }
    if (nm == "has_method") {
        *out = comptime_has_method(*this, t1, str_arg) ? 1 : 0;
        return true;
    }
    if (nm == "is_class") {
        *out = comptime_is_class(t1) ? 1 : 0;
        return true;
    }
    if (nm == "is_struct") {
        *out = comptime_is_struct(*this, t1) ? 1 : 0;
        return true;
    }
    if (nm == "is_primitive") {
        *out = comptime_is_primitive(t1) ? 1 : 0;
        return true;
    }
    if (nm == "is_enum") {
        *out = comptime_is_enum(*this, t1) ? 1 : 0;
        return true;
    }
    // Predicados numericos.  Estaban solo en el evaluador de CONCEPTOS, asi que
    // `is_float<T>()` valia dentro de un `concept` y daba "funcion no
    // declarada" en cualquier otro sitio -- mientras `sizeof<T>()` valia en los
    // dos.  Son el mismo tipo de pregunta sobre el mismo tipo: o valen en todas
    // partes o en ninguna.  Los necesita, por ejemplo, un metodo generico que
    // elige en comptime entre `lock xadd` (entero) y bucle CAS (float).
    if (nm == "is_float") {
        *out = (t1.kind == PrimitiveKind::F32 || t1.kind == PrimitiveKind::F64)
                   ? 1
                   : 0;
        return true;
    }
    if (nm == "is_integer") {
        *out = is_integral(t1.kind) ? 1 : 0;
        return true;
    }
    if (nm == "is_signed") {
        *out = is_signed_integral(t1.kind) ? 1 : 0;
        return true;
    }
    if (nm == "is_unsigned") {
        *out = (is_integral(t1.kind) && !is_signed_integral(t1.kind)) ? 1 : 0;
        return true;
    }
    if (nm == "is_numeric") {
        *out = is_numeric(t1.kind) ? 1 : 0;
        return true;
    }
    if (nm == "is_bool") {
        *out = (t1.kind == PrimitiveKind::BOOL) ? 1 : 0;
        return true;
    }
    if (nm == "is_char") {
        *out = (t1.kind == PrimitiveKind::CHAR) ? 1 : 0;
        return true;
    }
    if (nm == "is_pointer") {
        *out = (t1.kind == PrimitiveKind::PTR) ? 1 : 0;
        return true;
    }
    if (nm == "is_string") {
        *out = (t1.kind == PrimitiveKind::STRING) ? 1 : 0;
        return true;
    }
    if ((nm == "is_subtype" || nm == "is_same") && e->type_args.size() == 2) {
        const Type t2 = type_from_node(e->type_args[1].get());
        *out = (nm == "is_subtype" ? comptime_is_subtype(*this, t1, t2)
                                   : comptime_is_same(*this, t1, t2))
                   ? 1
                   : 0;
        return true;
    }
    return false;
}

bool TypeChecker::lsp_eval_int(const ast::Expr *e, int64_t *out) {
    if (!e) return false;
    // Delegar en el evaluador comptime REAL del frontend: ejecuta de verdad las
    // construcciones comptime (comptime fn con su body, comptime const con
    // llamadas, math constante, builtins sizeof<T>/kind<T>/...).  Devuelve
    // ok=false para lo que NO es comptime (valores runtime como ffi_call o una
    // variable mutable): eso se resuelve ejecutando el programa (notebook), no
    // aqui, para no mostrar un valor que en runtime seria otro.
    const ComptimeEvalResult r = comptime_eval_expr(*this, e);
    if (!r.ok || r.is_str || r.is_array || r.is_struct || r.is_type)
        return false;
    if (out) *out = r.value;
    return true;
}

void TypeChecker::check_if(ast::IfStmt *s, const Type &fn_return_type) {
    if (s->cond) {
        Type tc = check_expr(s->cond.get());
        // `if (obj)` sobre un tipo con `__bool__`: se lee su verdad con ESE
        // metodo (mismo camino que `!x`, `&&` y `||`).
        const bool via_bool = wrap_in_bool_dunder(s->cond, tc);
        if (!via_bool && tc.kind != PrimitiveKind::BOOL &&
            !is_numeric(tc.kind)) {
            diags_.error(s->cond->loc,
                         "condicion de 'if' debe ser numerica o bool");
        }
        // Captura LSP: si la condicion de un `if` normal es comptime-evaluable
        // (variables con valor comptime conocido + literales + builtins +
        // operadores), guardar true/false para mostrarlo inline en el IDE.
        if (capture_comptime_block_locals_ && !s->is_comptime) {
            int64_t v;
            if (lsp_eval_int(s->cond.get(), &v)) {
                ComptimeBuiltinHit hit;
                hit.loc = s->cond->loc;
                hit.name = "if"; // compiler.cpp deriva builtin_kind="if"
                hit.type_kind = "int";
                hit.value_str = (v != 0) ? "true" : "false";
                comptime_builtin_hits_.push_back(std::move(hit));
            }
        }
    }
    /* `comptime if (cond)` exige que cond sea evaluable
     * 100% en compile-time.  Si no lo es, error claro aqui (no se
     * espera al lowering).  Tambien valida solo la rama elegida --
     * la otra se descarta sin chequear (permite codigo que no compila
     * en la rama no tomada, p.ej. usando features no soportadas para
     * el tipo concreto). */
    if (s->is_comptime) {
        const ComptimeEvalResult r = comptime_eval_expr(*this, s->cond.get());
        if (!r.ok) {
            diags_.error(s->cond->loc,
                         "comptime if: la condicion debe ser evaluable en "
                         "compile-time (literales + builtins comptime + "
                         "operadores logicos/aritmeticos)");
            /* Como fallback, chequear ambas ramas para no perder
             * diagnosticos posteriores. */
            if (s->then_branch)
                check_stmt(s->then_branch.get(), fn_return_type);
            if (s->else_branch)
                check_stmt(s->else_branch.get(), fn_return_type);
            return;
        }
        /* Solo chequeamos la rama tomada.  La otra se descarta. */
        if (r.value != 0) {
            if (s->then_branch)
                check_stmt(s->then_branch.get(), fn_return_type);
        } else {
            if (s->else_branch)
                check_stmt(s->else_branch.get(), fn_return_type);
        }
        return;
    }
    if (s->then_branch) check_stmt(s->then_branch.get(), fn_return_type);
    if (s->else_branch) check_stmt(s->else_branch.get(), fn_return_type);
}

void TypeChecker::check_while(ast::WhileStmt *s, const Type &fn_return_type) {
    if (s->cond) {
        Type tc = check_expr(s->cond.get());
        const bool via_bool = wrap_in_bool_dunder(s->cond, tc);
        if (!via_bool && tc.kind != PrimitiveKind::BOOL &&
            !is_numeric(tc.kind)) {
            diags_.error(s->cond->loc,
                         "condicion de 'while' debe ser numerica o bool");
        }
    }
    if (s->body) check_stmt(s->body.get(), fn_return_type);
}

void TypeChecker::check_for(ast::ForStmt *s, const Type &fn_return_type) {
    // Scope adicional para el init del for (estilo C).
    push_scope();
    if (s->init) check_stmt(s->init.get(), fn_return_type);
    if (s->cond) {
        Type tc = check_expr(s->cond.get());
        if (tc.kind != PrimitiveKind::BOOL && !is_numeric(tc.kind)) {
            diags_.error(s->cond->loc,
                         "condicion de 'for' debe ser numerica o bool");
        }
    }
    if (s->step) (void)check_expr(s->step.get());
    if (s->body) check_stmt(s->body.get(), fn_return_type);
    pop_scope();
}

void TypeChecker::check_return(ast::ReturnStmt *s, const Type &fn_return_type) {
    if (s->value) {
        // BugFix P1-G1: cuando el caller declara return type FUNCTION
        // y el valor de retorno es una LambdaExpr sin return_type
        // declarado, propagar la firma esperada a la lambda ANTES de
        // check_expr.  Sin esto, check_lambda inferiria VOID como
        // return type y dispararia "return con valor en void" en el
        // body interno.  Mismo patron que check_var_decl ya hace para
        // `fn(...) -> R var = (x) => ...`.
        if (fn_return_type.kind == PrimitiveKind::FUNCTION &&
            s->value->kind == ast::NodeKind::LambdaExpr) {
            propagate_fn_type_to_lambda(
                static_cast<ast::LambdaExpr *>(s->value.get()), fn_return_type);
        }
        // Bug fix 2026-05-23: propagar el Result<V,E> / Optional<T>
        // declarado del return type al check_expr antes de bajar Ok/Err/Some.
        // Sin esto, `return Err("lit")` infiere E como i64 (ptr del literal)
        // y rechaza con "Result<i32, i64> incompatible con Result<i32,
        // string>".
        const Type saved_expected_result = expected_result_type_;
        const Type saved_expected_optional = expected_optional_type_;
        if (fn_return_type.kind == PrimitiveKind::RESULT) {
            expected_result_type_ = fn_return_type;
        } else if (fn_return_type.kind == PrimitiveKind::OPTIONAL) {
            expected_optional_type_ = fn_return_type;
        }
        Type t = check_expr(s->value.get());
        expected_result_type_ = saved_expected_result;
        expected_optional_type_ = saved_expected_optional;
        // Ownership escape-sensitive: retornar por valor un struct con un
        // closure capturador en un campo esta SOPORTADO (move-on-return).  El
        // lowering aloca el env en HEAP para ese struct escapante (en vez de
        // stack), lo mueve al caller con los bytes del struct (SRET), suprime
        // el cleanup del productor (escaping_locals_) y registra el free en el
        // consumidor (`T c = crear()` -> CLOSURE_ENV_FREE).  Un solo free, sin
        // GC.  El caso local-no-escapa sigue en stack (cero coste).  El taint
        // se conserva para rechazar el store-a-campo (aun no soportado).
        // Borrow checker R4: si el valor de retorno es un borrow,
        // validar via on_borrow_escape.  El owner_kind del borrow
        // (Local vs Param/Global) decide si el escape es valido.
        // - return borrow de local -> error (lifetime invalido).
        // - return borrow de param -> OK (param vive durante funcion).
        // - return borrow propagado via F4 -> OK si el source es Param.
        if ((t.kind == PrimitiveKind::BORROW ||
             t.kind == PrimitiveKind::BORROW_MUT) &&
            s->value->kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<ast::IdentExpr *>(s->value.get());
            (void)borrow_checker_.on_borrow_escape(id->name, s->loc, "return");
        }
        if (fn_return_type.kind == PrimitiveKind::VOID) {
            // Inferencia del retorno de un lambda block-body sin tipo
            // declarado: capturamos el tipo del primer `return <valor>` en vez
            // de emitir error.  check_lambda lee este tipo como el retorno del
            // lambda.  Fuera de ese contexto (funcion void real), es error.
            if (infer_lambda_void_return_ && t.kind != PrimitiveKind::COUNT &&
                t.kind != PrimitiveKind::VOID) {
                if (inferred_lambda_return_type_.kind == PrimitiveKind::VOID) {
                    inferred_lambda_return_type_ = t; // primer return manda
                }
            } else {
                diags_.error(s->loc,
                             "'return' con valor en funcion declarada void");
            }
        } else if (t.kind != PrimitiveKind::COUNT && t != fn_return_type) {
            // Aceptar conversiones numericas, asignabilidad de clases
            // (subtypes / interfaces) y compatibilidad de Optional/Result
            // builtins (igual que en check_var_decl).
            const bool numeric_ok =
                is_numeric(t.kind) && is_numeric(fn_return_type.kind);
            const bool class_ok = class_is_assignable(fn_return_type, t);
            // null asignable a CLASS / STRING / cualquier referencia.
            // El AST representa `null` como NullLitExpr cuyo tipo es PTR
            // void.  Lo aceptamos en return aunque @c class_is_assignable
            // no lo cubra explicitamente.
            const bool null_ok =
                (fn_return_type.kind == PrimitiveKind::CLASS ||
                 fn_return_type.kind == PrimitiveKind::STRING ||
                 fn_return_type.kind == PrimitiveKind::PTR) &&
                t.kind == PrimitiveKind::PTR &&
                (!t.pointee || t.pointee->kind == PrimitiveKind::VOID);
            // String literal puro promovible a STRING (mismo patron que
            // `var-decl: string s = "lit"`).  El lowering lo convierte
            // a StringObject via STRMAKE.
            const bool str_lit_ok =
                fn_return_type.kind == PrimitiveKind::STRING &&
                t.kind == PrimitiveKind::PTR && s->value &&
                s->value->kind == ast::NodeKind::StringLitExpr &&
                !static_cast<ast::StringLitExpr *>(s->value.get())
                     ->is_interpolated();
            if (!numeric_ok && !class_ok && !null_ok && !str_lit_ok) {
                diags_.error(s->loc,
                             std::string("tipo del valor de retorno (") +
                                 type_to_string(t) +
                                 ") incompatible con tipo declarado (" +
                                 type_to_string(fn_return_type) + ")");
            }
        }
    } else {
        if (fn_return_type.kind != PrimitiveKind::VOID) {
            diags_.error(s->loc, "'return' sin valor en funcion no-void");
        }
    }
}

// ---------------------------------------------------------------------
// Expresiones.
// ---------------------------------------------------------------------

Type TypeChecker::check_expr(ast::Expr *e) {
    if (!e) return Type{};
    Type t;
    switch (e->kind) {
    case ast::NodeKind::IntLitExpr: {
        // Por defecto los literales enteros son i64.  La promocion
        // / truncacion a la variable destino la decide el lowering.
        // Un sufijo (`42u8`) FIJA el tipo y desactiva esa inferencia.
        const auto *lit = static_cast<const ast::IntLitExpr *>(e);
        const PrimitiveKind sfx = lit->suffix;
        t = Type{sfx == PrimitiveKind::VOID ? PrimitiveKind::I64 : sfx};
        // Un literal que no cabe en SU PROPIO sufijo se contradice: no existe
        // ningun u8 que valga 300.  Se comprueba aqui, y no solo en el
        // var-decl, porque el sufijo tambien aparece donde no hay declaracion
        // (`f(300u8)`, `return 300u8;`) y porque puede no coincidir con el
        // tipo del destino (`i64 x = 300u8;` cabe en i64 pero no en u8).
        if (sfx != PrimitiveKind::VOID &&
            !literal_fits(sfx, lit->negated, lit->value)) {
            diags_.error(
                e->loc,
                vx::diag::format(
                    "VXT002", {literal_text(lit->negated, lit->value),
                               primitive_name(sfx), numeric_range_text(sfx)}));
        }
        break;
    }
    case ast::NodeKind::FloatLitExpr: {
        const PrimitiveKind sfx =
            static_cast<const ast::FloatLitExpr *>(e)->suffix;
        t = Type{sfx == PrimitiveKind::VOID ? PrimitiveKind::F64 : sfx};
        break;
    }
    case ast::NodeKind::BoolLitExpr: t = Type{PrimitiveKind::BOOL}; break;
    case ast::NodeKind::CharLitExpr: t = Type{PrimitiveKind::CHAR}; break;
    case ast::NodeKind::StringLitExpr: {
        // En el literal de string se modela como puntero a
        // los bytes en la seccion estatica del modulo (compatible
        // con la convencion FFI de vesta_io: vio_println recibe
        // (proc_ptr, vm_addr, len)).
        //
        // para strings interpolados, validar el tipo de
        // cada expresion ${expr}.  El lowering despachara cada
        // una al builtin nativo apropiado (vio_print_int / _uint
        // / _hex / _float / _bool / _char / _str).
        auto *sl = static_cast<ast::StringLitExpr *>(e);
        if (sl->is_interpolated()) {
            for (auto &ex : sl->interp_exprs) {
                Type tx = check_expr(ex.get());
                ex->result_type = tx;
                // `${obj}` sobre un tipo que declara `toString()` se reescribe
                // a `${obj.toString()}`.  Es lo que hace util tener el metodo:
                // sin esto habia que llamarlo a mano en cada sitio, y un tipo
                // compuesto se imprimia destripando sus campos uno a uno.
                if (tx.kind == PrimitiveKind::STRUCT ||
                    tx.kind == PrimitiveKind::CLASS) {
                    if (type_declares_to_string(tx)) {
                        auto fa = std::make_unique<ast::FieldAccessExpr>();
                        fa->loc = ex->loc;
                        fa->field_name = "toString";
                        fa->base = std::move(ex);
                        auto call = std::make_unique<ast::CallExpr>();
                        call->loc = fa->loc;
                        call->callee = std::move(fa);
                        ex = std::move(call);
                        tx = check_expr(ex.get());
                        ex->result_type = tx;
                    }
                }
                if (tx.kind == PrimitiveKind::VOID ||
                    tx.kind == PrimitiveKind::COUNT) {
                    diags_.error(ex->loc,
                                 "expresion ${...} no puede ser de tipo void");
                }
            }
        }
        t = Type{PrimitiveKind::PTR};
        break;
    }
    case ast::NodeKind::InitListExpr: {
        auto *il = static_cast<ast::InitListExpr *>(e);
        for (auto &el : il->elements) {
            Type tx = check_expr(el.get());
            el->result_type = tx;
        }
        // Si el desugar (Opcion B) anoto target_type_name desde el
        // contexto (`unique<Punto> p = {.x=10, .y=20}`), devolvemos
        // el Type STRUCT correspondiente para que unique_box/
        // shared_box vea un tipo concreto en lugar de COUNT.
        if (!il->target_type_name.empty() &&
            struct_layouts_.find(il->target_type_name) !=
                struct_layouts_.end()) {
            t = Type{PrimitiveKind::STRUCT};
            t.struct_name = il->target_type_name;
            break;
        }
        // Sin anotacion: tipo dependiente del contexto.  El caller
        // (check_var_decl, lower_var_decl para arrays, etc.) refina.
        t = Type{PrimitiveKind::COUNT};
        break;
    }
    case ast::NodeKind::NullLitExpr:
        // 'null' se modela como void*; el chequeo de asignacion
        // permite asignar void* a cualquier T* sin error.  Se
        // implementa en check_assign / check_var_decl.
        t = Type::make_ptr(Type{PrimitiveKind::VOID});
        break;
    case ast::NodeKind::IdentExpr:
        t = check_ident(static_cast<ast::IdentExpr *>(e));
        break;
    case ast::NodeKind::FieldAccessExpr:
        t = check_field_access(static_cast<ast::FieldAccessExpr *>(e));
        break;
    case ast::NodeKind::BinaryExpr:
        t = check_binary(static_cast<ast::BinaryExpr *>(e));
        break;
    case ast::NodeKind::UnaryExpr:
        t = check_unary(static_cast<ast::UnaryExpr *>(e));
        break;
    case ast::NodeKind::AssignExpr:
        t = check_assign(static_cast<ast::AssignExpr *>(e));
        break;
    case ast::NodeKind::TryExpr: {
        // P2: operador `?` postfix para Result -- early-return.
        // Validar:
        //   1. operand debe ser Result<V, E>
        //   2. la funcion actual debe retornar Result<_, E> con
        //      mismo E (o convertible).
        //   3. result type = V (el payload Ok del operand).
        auto *te = static_cast<ast::TryExpr *>(e);
        Type ot = te->operand ? check_expr(te->operand.get()) : Type{};
        if (ot.kind != PrimitiveKind::RESULT &&
            ot.kind != PrimitiveKind::COUNT) {
            diags_.error(te->loc, "operador '?' requiere un Result<V,E>, no '" +
                                      type_to_string(ot) + "'");
            t = Type{};
            break;
        }
        // Verificar que la funcion actual retorne Result<_, E>
        // compatible (mismo E o convertible).
        Type fn_ret = current_fn_return_type_;
        if (fn_ret.kind != PrimitiveKind::RESULT) {
            diags_.error(
                te->loc,
                "operador '?' solo es valido dentro de funciones "
                "que retornan Result<_, E>; tipo de retorno actual: '" +
                    type_to_string(fn_ret) + "'");
            t = Type{};
            break;
        }
        // Comparar tipos E (pointee2 en ambos).
        if (ot.pointee2 && fn_ret.pointee2) {
            if (!types_assignable(*fn_ret.pointee2, *ot.pointee2)) {
                diags_.error(te->loc,
                             "operador '?': tipo de error '" +
                                 type_to_string(*ot.pointee2) +
                                 "' incompatible con el del return type '" +
                                 type_to_string(*fn_ret.pointee2) + "'");
            }
        }
        // Tipo del resultado = V (pointee del operand).
        t = (ot.pointee ? *ot.pointee : Type{PrimitiveKind::I64});
        break;
    }
    case ast::NodeKind::TernaryExpr: {
        /*ternario cond ? then : else.  Tipo resultado =
         * tipo en comun entre then y else (preferimos el de then;
         * si else no es asignable a then se reporta error). */
        auto *te = static_cast<ast::TernaryExpr *>(e);
        if (te->cond) {
            Type ct = check_expr(te->cond.get());
            if (ct.kind != PrimitiveKind::BOOL && !is_numeric(ct.kind) &&
                ct.kind != PrimitiveKind::COUNT) {
                diags_.error(
                    te->cond->loc,
                    "condicion ternaria debe ser numerica o bool, no '" +
                        type_to_string(ct) + "'");
            }
        }
        Type tt = te->then_expr ? check_expr(te->then_expr.get()) : Type{};
        Type et = te->else_expr ? check_expr(te->else_expr.get()) : Type{};
        /* Si los dos son numericos, promovemos al mas ancho.
         * Si son tipos compatibles, usamos tt como resultado.
         * Si no, error. */
        if (tt.kind == PrimitiveKind::COUNT) tt = et;
        if (et.kind == PrimitiveKind::COUNT) et = tt;
        if (!types_assignable(tt, et) && !types_assignable(et, tt)) {
            diags_.error(te->loc, "ternario: ramas con tipos incompatibles '" +
                                      type_to_string(tt) + "' y '" +
                                      type_to_string(et) + "'");
        }
        t = tt;
        break;
    }
    case ast::NodeKind::CallExpr:
        t = check_call(static_cast<ast::CallExpr *>(e));
        break;
    case ast::NodeKind::IndexExpr:
        t = check_index(static_cast<ast::IndexExpr *>(e));
        break;
    case ast::NodeKind::ThisExpr:
        t = check_this(static_cast<ast::ThisExpr *>(e));
        break;
    case ast::NodeKind::NewExpr:
        t = check_new(static_cast<ast::NewExpr *>(e));
        break;
    case ast::NodeKind::SuperCallExpr: {
        // BugFix R1: super(args) -- valida que estamos en un ctor
        // con super_name no vacio.  No retorna nada util (es como
        // void); validamos args y propagamos.
        auto *sc = static_cast<ast::SuperCallExpr *>(e);
        for (auto &arg : sc->args)
            check_expr(arg.get());
        if (current_class_.empty()) {
            diags_.error(sc->loc, "super(...) fuera de cuerpo de clase");
        } else {
            auto it = class_layouts_.find(current_class_);
            if (it == class_layouts_.end() || it->second.super_name.empty()) {
                diags_.error(sc->loc, "super(...) en clase '" + current_class_ +
                                          "' que no tiene superclase");
            }
        }
        t = Type{PrimitiveKind::VOID};
        break;
    }
    case ast::NodeKind::SuperMethodCallExpr: {
        // BugFix R1: super.method(args) -- valida que estamos en
        // metodo de instancia + clase con super_name.  Resuelve
        // el metodo en la jerarquia super y retorna su tipo.
        auto *sm = static_cast<ast::SuperMethodCallExpr *>(e);
        for (auto &arg : sm->args)
            check_expr(arg.get());
        if (current_class_.empty()) {
            diags_.error(sm->loc,
                         "super.<metodo>(...) fuera de cuerpo de clase");
            t = Type{};
            break;
        }
        auto it = class_layouts_.find(current_class_);
        if (it == class_layouts_.end() || it->second.super_name.empty()) {
            diags_.error(sm->loc, "super.<metodo>(...) en clase '" +
                                      current_class_ +
                                      "' que no tiene superclase");
            t = Type{};
            break;
        }
        // Buscar el metodo en la jerarquia super (BFS).
        std::string cur = it->second.super_name;
        const ClassMethodInfo *found = nullptr;
        for (int depth = 0; depth < 32; ++depth) {
            auto it_s = class_layouts_.find(cur);
            if (it_s == class_layouts_.end()) break;
            for (const auto &m : it_s->second.methods) {
                if (!m.is_constructor && m.name == sm->method_name) {
                    found = &m;
                    break;
                }
            }
            if (found) break;
            if (it_s->second.super_name.empty()) break;
            cur = it_s->second.super_name;
        }
        if (!found) {
            diags_.error(sm->loc,
                         "super.<metodo>: '" + sm->method_name +
                             "' no encontrado en jerarquia super de '" +
                             current_class_ + "'");
            t = Type{};
        } else {
            t = found->return_type;
        }
        break;
    }
    case ast::NodeKind::SpawnExpr: {
        // spawn { body } - validar el body como un statement
        // ordinario y devolver i64 (PID encoded del proceso hijo).
        auto *se = static_cast<ast::SpawnExpr *>(e);
        // si la policy es Pinned, validar que la
        // expresion del scheduler sea integral (i32/i64/u32/u64).  El
        // lowering hara el modulo num_schedulers en runtime.
        if (se->policy == ast::SpawnExpr::Policy::Pinned && se->sched_idx) {
            const Type ti = check_expr(se->sched_idx.get());
            if (ti.kind != PrimitiveKind::I32 &&
                ti.kind != PrimitiveKind::I64 &&
                ti.kind != PrimitiveKind::U32 &&
                ti.kind != PrimitiveKind::U64 &&
                ti.kind != PrimitiveKind::COUNT) {
                diags_.error(
                    se->loc,
                    std::string("spawn on(expr): la expresion del scheduler "
                                "debe ser integral, recibido ") +
                        type_to_string(ti));
            }
            se->sched_idx->result_type = ti;
        }
        if (se->body) {
            // El body se valida en su propio contexto; cualquier
            // referencia a variables externas se permite (sin closure
            // lexica en MVP, son globals o errores).  Para evitar
            // falsos positivos por capturas que el lowering no soporta,
            // simplemente validamos sintaxis: no bloqueamos returns
            // ni reglas de funcion.  Falsa simetria con check_function.
            Type void_t{PrimitiveKind::VOID};
            push_scope();
            check_stmt(se->body.get(), void_t);
            pop_scope();
        }
        t = Type{PrimitiveKind::I64};
        break;
    }
    case ast::NodeKind::LambdaExpr:
        t = check_lambda(static_cast<ast::LambdaExpr *>(e));
        break;
    case ast::NodeKind::MatchExpr:
        t = check_match(static_cast<ast::MatchExpr *>(e));
        break;
    case ast::NodeKind::RSpawnExpr: {
        //  rspawn(node_idx) { body } - spawn distribuido cross-node.
        // Validar:
        //   - node_idx es expresion integral (i32/i64/u32/u64).
        //   - body es block valido; el `return X` se intercepta en
        //     lowering y se transforma en `mov r0, X; hlt` para que
        //     el runtime remoto capture X y lo envie como fulfill.
        // Tipo resultado: i64 (GcHandle del Future).
        auto *re = static_cast<ast::RSpawnExpr *>(e);
        if (re->node_idx) {
            const Type ti = check_expr(re->node_idx.get());
            if (ti.kind != PrimitiveKind::I32 &&
                ti.kind != PrimitiveKind::I64 &&
                ti.kind != PrimitiveKind::U32 &&
                ti.kind != PrimitiveKind::U64 &&
                ti.kind != PrimitiveKind::COUNT) {
                diags_.error(re->loc,
                             std::string("rspawn(node): la expresion del nodo "
                                         "debe ser integral, recibido ") +
                                 type_to_string(ti));
            }
            re->node_idx->result_type = ti;
        }
        if (re->body) {
            Type i64_t{PrimitiveKind::I64};
            push_scope();
            check_stmt(re->body.get(), i64_t); // permite return i64
            pop_scope();
        }
        t = Type{PrimitiveKind::I64};
        break;
    }
    case ast::NodeKind::CastExpr: {
        // Cast C-style `(T) expr`.  Validacion permisiva: el
        // tipo destino se evalua y se chequea el operando, pero
        // no se rechaza ninguna conversion concreta (la decision
        // sobre como bajar la conversion la toma el lowering
        // segun los tipos actual y destino).  Convertir entre
        // punteros (incl. virtual <-> host) es legal; convertir
        // de int a ptr o viceversa tambien.  Quien escriba el
        // cast asume las consecuencias.
        auto *ce = static_cast<ast::CastExpr *>(e);
        if (ce->target_type) {
            t = type_from_node(ce->target_type.get());
        } else {
            t = Type{};
        }
        // Compound literal `(Struct){...}`: el operando es un InitListExpr y el
        // target un struct.  No es una conversion sino la CONSTRUCCION inline
        // de un struct; anotamos el nombre del struct en el init-list y
        // devolvemos el tipo struct.  Funciona con templates (t ya esta
        // monomorphizado).
        if (t.kind == PrimitiveKind::STRUCT && ce->operand &&
            ce->operand->kind == ast::NodeKind::InitListExpr) {
            auto *il = static_cast<ast::InitListExpr *>(ce->operand.get());
            il->target_type_name = t.struct_name;
            for (auto &el : il->elements)
                (void)check_expr(el.get());
            il->result_type = t;
            e->result_type = t;
            return t;
        }
        if (ce->operand) {
            Type to = check_expr(ce->operand.get());
            ce->operand->result_type = to;
            // ABI custom via CALLIND: si el operando lleva una ABI a medida
            // (una funcion, o un campo-funcion cuyo default es una funcion con
            // register en params) y el target es un cfn, el cast HEREDA esa ABI
            // truncada a la aridad del target -- toma los N primeros registros.
            // El cast solo fija aridad/tipos/orden; los REGISTROS vienen de la
            // funcion apuntada (contrato del ctx pattern).  El lowering del
            // CALLIND consume t.fn_param_abi_regs (multi-ABI como un CALL).
            if (t.kind == PrimitiveKind::FUNCTION &&
                to.kind == PrimitiveKind::FUNCTION &&
                !to.fn_param_abi_regs.empty()) {
                std::vector<std::string> abi = to.fn_param_abi_regs;
                if (abi.size() > t.fn_params.size())
                    abi.resize(t.fn_params.size());
                t.fn_param_abi_regs = std::move(abi);
            }
            // Function pointer: `(u64) foo` / `(fn(...)->R) foo` -- foo es una
            // funcion (check_ident la marca is_func_ref y devuelve void).  El
            // cast es valido: el resultado es la direccion del codigo.
            bool op_is_func_ref =
                ce->operand->kind == ast::NodeKind::IdentExpr &&
                static_cast<ast::IdentExpr *>(ce->operand.get())->is_func_ref;
            if (to.kind == PrimitiveKind::VOID && !op_is_func_ref) {
                diags_.error(ce->loc,
                             "no se puede castear una expresion de tipo void");
            }
            // Helper local: validar cast contra el bloque
            // {explicit from/to T;} + module-privacy.
            // Devuelve true si la conversion esta declarada y
            // accesible desde el sitio del cast.
            auto is_declared_conv = [&](const Type &nt_type, const Type &other,
                                        bool from_dir) -> bool {
                if (nt_type.nominal_id == 0) return false;
                const auto *info = newtype_info(nt_type.nominal_name);
                if (!info) return false;
                const auto &lst =
                    from_dir ? info->from_conversions : info->to_conversions;
                const bool same_file = (ce->loc.file == info->source_file);
                for (const auto &ec : lst) {
                    // Match estricto: kind + nominal_id + (struct_name
                    // si aplica).  No usamos types_assignable porque
                    // permite coercion numerica (u32 -> u64), lo que
                    // hace que `explicit from u32` aceptaria u64.
                    // El usuario que declara `from u32` espera
                    // EXACTAMENTE u32, no cualquier integer.
                    if (ec.type.kind != other.kind) continue;
                    if (ec.type.nominal_id != other.nominal_id) continue;
                    if (ec.type.struct_name != other.struct_name) continue;
                    if (ec.is_public || same_file) return true;
                }
                return false;
            };
            // Newtype @opaque: prohibido cruzar la barrera salvo
            // que haya una conversion explicita declarada Y la
            // accesibilidad lo permita (mismo fichero o `public`).
            // Sin bloque {from/to}: opaque bloquea TODO cast en
            // cualquier direccion.
            const bool tgt_opaque = (t.nominal_id != 0 && t.is_opaque);
            const bool src_opaque = (to.nominal_id != 0 && to.is_opaque);
            if (tgt_opaque && t.nominal_id != to.nominal_id) {
                if (!is_declared_conv(t, to, /*from_dir=*/true)) {
                    diags_.error(ce->loc,
                                 "no se puede castear a newtype @opaque '" +
                                     t.nominal_name +
                                     "'; declara "
                                     "'explicit from " +
                                     type_to_string(to) +
                                     ";' en el bloque del typedef" +
                                     " (o anyade 'public' si se llama "
                                     "desde otro fichero)");
                }
            } else if (src_opaque && to.nominal_id != t.nominal_id) {
                if (!is_declared_conv(to, t, /*from_dir=*/false)) {
                    diags_.error(ce->loc,
                                 "no se puede castear desde newtype @opaque '" +
                                     to.nominal_name +
                                     "'; declara "
                                     "'explicit to " +
                                     type_to_string(t) +
                                     ";' en el bloque del typedef" +
                                     " (o anyade 'public' si se llama "
                                     "desde otro fichero)");
                }
            }
            // Newtypes NO-opacos con bloque {from/to} declarado:
            // restringen el cast a las conversiones listadas (mas
            // estricto que el default no-opaque que permite todo).
            // Sin bloque: comportamiento default (cast libre con
            // el underlying).
            if (!tgt_opaque && t.nominal_id != 0 &&
                t.nominal_id != to.nominal_id) {
                const auto *info = newtype_info(t.nominal_name);
                if (info && !info->from_conversions.empty() &&
                    !is_declared_conv(t, to, /*from_dir=*/true)) {
                    diags_.error(ce->loc, "cast a newtype '" + t.nominal_name +
                                              "': '" + type_to_string(to) +
                                              "' no esta en su bloque "
                                              "{explicit from ...;}");
                }
            }
            if (!src_opaque && to.nominal_id != 0 &&
                to.nominal_id != t.nominal_id) {
                const auto *info = newtype_info(to.nominal_name);
                if (info && !info->to_conversions.empty() &&
                    !is_declared_conv(to, t, /*from_dir=*/false)) {
                    diags_.error(ce->loc, "cast desde newtype '" +
                                              to.nominal_name + "': '" +
                                              type_to_string(t) +
                                              "' no esta en su bloque "
                                              "{explicit to ...;}");
                }
            }
        }
        break;
    }
    default: t = Type{}; break;
    }
    e->result_type = t;
    return t;
}

Type TypeChecker::check_this(ast::ThisExpr *e) {
    // Resolver de overlay (@offset/@element): `this` es la vista (STRUCT).
    // Se declara como variable `this`/`self` en scope; permitimos ademas la
    // forma con palabra clave `this.campo` como alias del acceso al hermano
    // por nombre.  Mismo tipo, misma bajada (lower_this ve el binding).
    if (overlay_resolver_active_) {
        if (const Symbol *s = lookup("this")) return s->type;
    }
    // Metodo de struct: @c this es un value-type (STRUCT).
    if (!current_struct_.empty()) {
        return Type{PrimitiveKind::STRUCT, current_struct_};
    }
    if (current_class_.empty()) {
        diags_.error(e->loc, "'this' solo es valido dentro del cuerpo de un "
                             "metodo de instancia");
        return Type{};
    }
    if (current_method_is_static_) {
        diags_.error(e->loc,
                     "'this' no es accesible dentro de un metodo 'static'");
        return Type{};
    }
    return Type{PrimitiveKind::CLASS, current_class_};
}

Type TypeChecker::check_new(ast::NewExpr *e) {
    //  M.7.c: namespace qualified `new ui.Button(...)`.
    // Si class_name contiene `.`, lo traducimos al mangled label
    // ANTES de que el resto del check_new procese.  Asi el resto
    // del codigo (lookup en class_layouts_, llamada al ctor, etc.)
    // ve el nombre interno (`ui__Button`) sin necesidad de cambios.
    {
        //  NS.1b: resolver por el prefijo de namespace mas largo
        // (multi-segmento `new ui.widgets.Button(...)`).
        uint32_t ns_idx = UINT32_MAX;
        std::string sym_name;
        if (e->class_name.find('.') != std::string::npos &&
            resolve_ns_qualified(e->class_name, ns_idx, sym_name) &&
            ns_idx < imported_namespaces_.size()) {
            const auto &ns = imported_namespaces_[ns_idx];
            auto its = ns.by_name.find(sym_name);
            if (its != ns.by_name.end()) {
                e->class_name = ns.symbols[its->second].mangled_label;
            }
        }
    }
    // bug4: array allocation `new T[N]`.  Validar count (debe ser int),
    // resolver el elem type, devolver T[] (array de host_ptr).
    if (e->array_size) {
        Type count_t = check_expr(e->array_size.get());
        if (count_t.kind != PrimitiveKind::I8 &&
            count_t.kind != PrimitiveKind::I16 &&
            count_t.kind != PrimitiveKind::I32 &&
            count_t.kind != PrimitiveKind::I64 &&
            count_t.kind != PrimitiveKind::U8 &&
            count_t.kind != PrimitiveKind::U16 &&
            count_t.kind != PrimitiveKind::U32 &&
            count_t.kind != PrimitiveKind::U64 &&
            count_t.kind != PrimitiveKind::COUNT) {
            diags_.error(e->array_size->loc,
                         "new T[N]: el tamano del array debe ser un tipo "
                         "entero, recibido '" +
                             type_to_string(count_t) + "'");
        }
        // Resolver elem_type desde class_name.  Puede ser:
        //   - Primitivo (i32, f64, string, etc.) -> PrimitiveKind
        //   correspondiente.
        //   - Clase user (PrimitiveKind::CLASS).
        //   - Struct value-type (PrimitiveKind::STRUCT).
        //   - Enum (PrimitiveKind::STRUCT con enum_layouts_ entry).
        Type elem_t;
        auto pk_from_name = [](const std::string &n) -> PrimitiveKind {
            if (n == "i8") return PrimitiveKind::I8;
            if (n == "i16") return PrimitiveKind::I16;
            if (n == "i32") return PrimitiveKind::I32;
            if (n == "i64") return PrimitiveKind::I64;
            if (n == "u8" || n == "char") return PrimitiveKind::U8;
            if (n == "u16") return PrimitiveKind::U16;
            if (n == "u32") return PrimitiveKind::U32;
            if (n == "u64") return PrimitiveKind::U64;
            if (n == "f32" || n == "float") return PrimitiveKind::F32;
            if (n == "f64" || n == "double") return PrimitiveKind::F64;
            if (n == "bool") return PrimitiveKind::BOOL;
            if (n == "string") return PrimitiveKind::STRING;
            return PrimitiveKind::COUNT;
        };
        PrimitiveKind pk = pk_from_name(e->class_name);
        // BugFix R5: builtins genericos Optional/Result/Future como
        // tipo elemento del array.
        bool elem_set = false;
        if (pk == PrimitiveKind::COUNT &&
            (e->class_name == "Optional" || e->class_name == "Result" ||
             e->class_name == "Future")) {
            if (e->type_args.empty()) {
                diags_.error(e->loc, "new " + e->class_name +
                                         "<T>[N]: falta argumento de tipo <T>");
                e->result_type = Type{};
                return Type{};
            }
            Type inner = type_from_node(e->type_args[0].get());
            if (e->class_name == "Optional") {
                elem_t = Type::make_optional(std::move(inner));
            } else if (e->class_name == "Future") {
                elem_t = Type::make_future(std::move(inner));
            } else {
                if (e->type_args.size() < 2) {
                    diags_.error(
                        e->loc,
                        "new Result<V,E>[N]: faltan 2 argumentos de tipo");
                    e->result_type = Type{};
                    return Type{};
                }
                Type err_t = type_from_node(e->type_args[1].get());
                elem_t = Type::make_result(std::move(inner), std::move(err_t));
            }
            e->type_args.clear();
            elem_set = true;
        }
        if (!elem_set) {
            if (pk != PrimitiveKind::COUNT) {
                elem_t = Type{pk};
            } else if (class_layouts_.find(e->class_name) !=
                       class_layouts_.end()) {
                elem_t = Type{PrimitiveKind::CLASS};
                elem_t.struct_name = e->class_name;
            } else if (struct_layouts_.find(e->class_name) !=
                       struct_layouts_.end()) {
                elem_t = Type{PrimitiveKind::STRUCT};
                elem_t.struct_name = e->class_name;
            } else if (find_enum_layout(e->class_name) != nullptr) {
                elem_t = Type{PrimitiveKind::STRUCT};
                elem_t.struct_name = e->class_name;
            } else {
                diags_.error(e->loc, "new T[N]: tipo desconocido '" +
                                         e->class_name + "'");
                e->result_type = Type{};
                return Type{};
            }
        }
        // Tipo resultado: ARRAY de elem_t (host, is_virtual=false).
        // size=0 = decay-to-pointer (dynamic size, no conocido en
        // compile-time).
        Type rt = Type::make_array(elem_t, /*size=*/0, /*virt=*/false);
        e->result_type = rt;
        return rt;
    }
    // Validar argumentos primero (siempre se chequean para reportar
    // errores en sus subexpresiones aunque la clase sea desconocida).
    std::vector<Type> arg_types;
    arg_types.reserve(e->args.size());
    for (auto &a : e->args)
        arg_types.push_back(check_expr(a.get()));

    // generics: si NewExpr trae type_args, redirigimos al nombre
    // mangled de la clase monomorphizada (la cual fue generada en el
    // pre-pase de run()).
    // Bug fix 2026-05-23: el flag is_mangled previene re-mutacion del
    // class_name cuando check_new se invoca multiples veces sobre el
    // mismo NewExpr (e.g. por compound assign que re-evalua RHS, o por
    // reuso del AST entre pases).  Sin esto, `Node` -> `Node_i32` en
    // la primera llamada y `Node_i32` -> `Node_i32_i32` en la segunda.
    if (!e->type_args.empty() && !e->is_mangled) {
        std::vector<Type> targs;
        targs.reserve(e->type_args.size());
        for (auto &ta : e->type_args)
            targs.push_back(type_from_node(ta.get()));
        // #cross-module-generics: sanitizar el punto del nombre cualificado
        // (`lib.Box`) para que el mangled (`lib_Box_i64`) coincida con el
        // layout y sea una etiqueta valida.
        e->class_name =
            mangle_sanitize(e->class_name) + "_" + mangle_args(targs);
        e->is_mangled = true;
    }

    auto it = class_layouts_.find(e->class_name);
    if (it == class_layouts_.end()) {
        // `typedef Caja Sesion new;` -> `new Sesion()` construye la clase de
        // debajo.  El newtype comparte la representacion (y por tanto el
        // layout, los campos y los metodos); lo unico que anade es que sea
        // NOMINALMENTE distinto, y eso lo lleva el Type, no el layout.
        if (const std::string real = underlying_layout_name(e->class_name);
            !real.empty()) {
            it = class_layouts_.find(real);
        }
    }
    if (it == class_layouts_.end()) {
        diags_.error(e->loc, "clase desconocida: '" + e->class_name + "'");
        return Type{};
    }
    const ClassLayout &cls = it->second;

    // BugFix R4: clases excepcion estandar (is_runtime_predefined=true)
    // no tienen constructor Vesta; aceptan 1 arg string (message).
    // Devolvemos directamente CLASS sin validar ctor.  El lowering
    // detecta el caso y emite newobj + store message inline.
    if (cls.is_runtime_predefined && cls.name != "FatalError") {
        if (arg_types.size() != 1) {
            diags_.error(e->loc, "constructor de '" + e->class_name +
                                     "' espera 1 argumento (message)");
        } else {
            const Type &ta = arg_types[0];
            if (ta.kind != PrimitiveKind::STRING &&
                ta.kind != PrimitiveKind::PTR &&
                ta.kind != PrimitiveKind::COUNT) {
                diags_.error(e->args[0]->loc, "constructor de '" +
                                                  e->class_name +
                                                  "': message debe ser string");
            }
        }
        return new_expr_result_type(e->class_name);
    }

    // Localizar el constructor: debe tener el mismo nombre que la
    // clase y is_constructor=true.  Si hay varios, elegimos el que
    // encaje con la lista de argumentos por aridad estricta (overload
    // resolution mejorada llegara).
    const ClassMethodInfo *ctor = nullptr;
    for (const auto &m : cls.methods) {
        if (!m.is_constructor) continue;
        /* Con un variadico la aridad no es exacta: los parametros de delante
         * son obligatorios y de ahi en adelante se admite cualquier cantidad,
         * incluida ninguna. */
        if (m.is_variadic) {
            if (arg_types.size() + 1 < m.param_types.size()) continue;
        } else if (m.param_types.size() != arg_types.size()) {
            continue;
        }
        ctor = &m;
        break;
    }
    if (!ctor) {
        // Si la clase no declara ningun constructor explicito,
        // permitimos new X() sin args (constructor implicito).
        const bool has_any_ctor = std::any_of(
            cls.methods.begin(), cls.methods.end(),
            [](const ClassMethodInfo &m) { return m.is_constructor; });
        if (has_any_ctor || !e->args.empty()) {
            diags_.error(e->loc, "no existe constructor de '" + e->class_name +
                                     "' con " +
                                     std::to_string(arg_types.size()) +
                                     " argumentos");
        }
    } else {
        // Verificar tipos de cada argumento contra el constructor.
        /* Los de delante del variadico van contra su parametro; los que sobran,
         * contra el tipo del ELEMENTO -- el parametro es ya el array. */
        const size_t fixed = ctor->is_variadic ? ctor->param_types.size() - 1
                                               : ctor->param_types.size();
        for (size_t i = 0; i < arg_types.size(); ++i) {
            const Type &ta = arg_types[i];
            const Type &tp =
                (i >= fixed) ? ctor->variadic_elem : ctor->param_types[i];
            /* Los tipos ya se calcularon arriba para elegir el constructor,
             * asi que aqui se aplica la REGLA sin volver a comprobar: hacerlo
             * dos veces repetiria los avisos del propio argumento. */
            Type targ = ta;
            if (!arg_fits_param(e->args[i].get(), tp, targ)) {
                diags_.error(e->args[i]->loc,
                             std::string("argumento ") + std::to_string(i + 1) +
                                 " del constructor '" + e->class_name +
                                 "': tipo (" + type_to_string(targ) +
                                 ") incompatible con parametro (" +
                                 type_to_string(tp) + ")");
            }
        }
    }
    return new_expr_result_type(e->class_name);
}

bool TypeChecker::value_assignable_to_interface(
    const Type &target, const Type &value) const noexcept {
    if (target.kind != PrimitiveKind::CLASS ||
        value.kind != PrimitiveKind::CLASS)
        return false;
    if (target.struct_name.empty() || value.struct_name.empty()) return false;
    if (target.struct_name == value.struct_name) return false; // ya cubierto
    auto it_t = class_layouts_.find(target.struct_name);
    if (it_t == class_layouts_.end() || !it_t->second.is_interface)
        return false;
    // Recorrer la clase concreta + su cadena de super buscando la interfaz.
    std::string cur = value.struct_name;
    for (int depth = 0; depth < 64 && !cur.empty(); ++depth) {
        auto it_c = class_layouts_.find(cur);
        if (it_c == class_layouts_.end()) break;
        for (const auto &in : it_c->second.interface_names)
            if (in == target.struct_name) return true;
        cur = it_c->second.super_name;
    }
    return false;
}

Type TypeChecker::check_index(ast::IndexExpr *e) {
    // p[i] requiere base PTR o ARRAY y index entero.  El resultado es
    // el tipo del elemento.  Subscript sobre cualquier otro tipo es
    // un error claro.
    if (!e->base) {
        diags_.error(e->loc, "subscript sin base");
        return Type{};
    }
    // Overlay F3b: `v.arr[i]` donde `arr` es un campo ARRAY de un overlay.
    // Se resuelve `base + pos + i*stride`; el resultado es el tipo del
    // elemento.
    if (e->base->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->base.get());
        if (fa->base) {
            Type ovt = check_expr(fa->base.get());
            fa->base->result_type = ovt;
            if (ovt.kind == PrimitiveKind::STRUCT) {
                auto it = struct_layouts_.find(ovt.struct_name);
                if (it != struct_layouts_.end() && it->second.is_overlay) {
                    for (const auto &fi : it->second.fields) {
                        if (fi.name == fa->field_name &&
                            (fi.array_stride || fi.element_block)) {
                            if (e->index) {
                                Type idt = check_expr(e->index.get());
                                e->index->result_type = idt;
                            }
                            e->is_overlay_array = true;
                            fa->result_type = fi.type; // tipo del elemento
                            e->result_type = fi.type;
                            return fi.type;
                        }
                    }
                }
            }
        }
    }
    const Type bt = check_expr(e->base.get());
    if (e->index) (void)check_expr(e->index.get());
    // Operator overloading C-2: `base[i]` (LECTURA) -> base.__index__(i)
    // cuando @c bt es CLASS o STRUCT y declara @c __index__ cuya firma
    // unaria acepta el tipo del indice.  El resultado es el return type
    // del metodo.  Sin el dunder cae al flujo clasico (subscript de
    // puntero/array).  Nota: solo LECTURA en C-2; @c base[i] = v
    // (index-set) no esta cubierto aqui.
    {
        const Type it = e->index ? e->index->result_type : Type{};
        const std::vector<ClassMethodInfo> *methods = nullptr;
        if (bt.kind == PrimitiveKind::CLASS && !bt.struct_name.empty()) {
            auto it_cls = class_layouts_.find(bt.struct_name);
            if (it_cls != class_layouts_.end())
                methods = &it_cls->second.methods;
        } else if (bt.kind == PrimitiveKind::STRUCT &&
                   !bt.struct_name.empty()) {
            auto it_s = struct_layouts_.find(bt.struct_name);
            if (it_s != struct_layouts_.end()) methods = &it_s->second.methods;
        }
        if (methods) {
            for (const auto &m : *methods) {
                if (m.is_constructor || m.is_static) continue;
                if (m.name != "__index__") continue;
                if (m.param_types.size() != 1) continue;
                if (!types_assignable(m.param_types[0], it)) continue;
                e->overload_method = "__index__";
                return m.return_type;
            }
        }
    }
    // String Inc 3: `s[i]` (indexado simple) y `s[a..b]` / `s[a..=b]`
    // (slice) sobre `string`.  El indexado devuelve el CHAR (byte) en la
    // posicion i; el slice devuelve un NUEVO `string` con la copia de los
    // bytes [a, b).  El lowering nativo (native_poo_) implementa ambos;
    // en Full/JIT el lowering aun no los soporta y emite un error claro.
    if (bt.kind == PrimitiveKind::STRING) {
        if (e->index) {
            const Type it = e->index->result_type;
            if (!is_integral(it.kind)) {
                diags_.error(e->loc,
                             std::string("indice de string debe ser entero, "
                                         "recibido ") +
                                 type_to_string(it));
            }
        }
        if (e->is_range) {
            if (e->range_hi) {
                const Type ht = check_expr(e->range_hi.get());
                if (!is_integral(ht.kind)) {
                    diags_.error(e->loc,
                                 std::string("limite superior del slice de "
                                             "string debe ser entero, "
                                             "recibido ") +
                                     type_to_string(ht));
                }
            }
            // `s[a..b]` -> nuevo string owned.
            return Type{PrimitiveKind::STRING};
        }
        // `s[i]` -> el char (byte) en la posicion i.
        return Type{PrimitiveKind::CHAR};
    }

    // Los smart pointers (unique/shared) y borrows transparentan la
    // indexacion al puntero gestionado: `u[i]` == `(gestionado)[i]` sin
    // extraer el raw a mano (ptr_of es redundante).  Todos son un host_ptr
    // de 8 bytes con `pointee` = el tipo apuntado, igual que un PTR normal.
    const bool is_ptr_like =
        (bt.kind == PrimitiveKind::PTR || bt.kind == PrimitiveKind::ARRAY ||
         bt.kind == PrimitiveKind::UNIQUE_PTR ||
         bt.kind == PrimitiveKind::SHARED_PTR ||
         bt.kind == PrimitiveKind::BORROW ||
         bt.kind == PrimitiveKind::BORROW_MUT) &&
        static_cast<bool>(bt.pointee);
    if (!is_ptr_like) {
        diags_.error(
            e->loc, std::string("'[]' requiere un puntero o array, recibido ") +
                        type_to_string(bt));
        return Type{};
    }
    if (bt.pointee->kind == PrimitiveKind::VOID) {
        diags_.error(e->loc, "'[]' no puede indexar void*");
        return Type{};
    }
    if (e->index) {
        const Type it = e->index->result_type;
        if (!is_integral(it.kind)) {
            diags_.error(
                e->loc,
                std::string("indice de '[]' debe ser entero, recibido ") +
                    type_to_string(it));
        }
    }
    return *bt.pointee;
}

// ---------------------------------------------------------------------
// closures: check_lambda.
//
// Diseno:
//   - Construye Type{FUNCTION, params, return_type} a partir de la
//     firma sintactica de la lambda.  Los parametros sin tipo
//     declarado quedan como VOID temporalmente; el contexto (assign /
//     var-decl con tipo fn(...)) puede resolverlos a posteriori en
//     una fase futura (MVP: exigimos tipos explicitos en parametros
//     o defaults a i64).
//   - El analisis de capturas usa @c lambda_stack_: empuja el ctx
//     antes de chequear el body y check_ident detecta las referencias
//     externas para anyadirlas a expr->captures sin duplicados.
//   - El return_type se infiere del tipo del primer ReturnStmt.  Para
//     simplificar la implementacion, MVP: si el body termina en
//     `return X;` con X de tipo T, usar T.  Si no hay return, asumir
//     VOID.  Validacion de coherencia entre multiples returns queda
//     para una fase posterior.
// ---------------------------------------------------------------------
Type TypeChecker::check_lambda(ast::LambdaExpr *e) {
    // Construir lista de tipos de parametros.  Los parametros sin
    // tipo declarado se asumen i64 (el tipo "todo cabe" de Vesta).
    // Inferencia desde contexto (asignacion a fn(T1, T2) -> R) queda
    // como mejora futura: aqui solo soportamos tipos explicitos o
    // i64 por defecto.
    std::vector<Type> param_types;
    param_types.reserve(e->params.size());
    bool lam_variadic = false;
    for (auto &p : e->params) {
        Type pt;
        if (p->type) {
            pt = type_from_node(p->type.get());
        } else {
            // Default i64 cuando no hay anotacion.  Suficiente para
            // MVP (la mayoria de lambdas cortas usan enteros); el
            // usuario puede anotar el tipo si quiere otro.
            pt = Type{PrimitiveKind::I64};
        }
        /* `(T... xs) => ...`: el ultimo recoge los que sobren, y dentro del
         * cuerpo se ve como la DIRECCION del array.  Igual que en cualquier
         * otra declaracion; la lambda no es una excepcion. */
        if (p->is_variadic) {
            lam_variadic = true;
            pt = Type::make_ptr(pt);
        }
        // El cuerpo de una lambda no pasa por declare_params_in_scope, asi que
        // sin esto seria el unico de los siete contextos donde la marca se
        // aceptaria sin mirarla.
        check_param_dir_(p->name, p->dir, p->loc, pt);
        param_types.push_back(pt);
    }

    // Tipo de retorno declarado, o VOID provisional para inferir del body.
    Type return_t;
    bool return_t_declared = false;
    if (e->return_type) {
        return_t = type_from_node(e->return_type.get());
        return_t_declared = true;
    } else {
        return_t = Type{PrimitiveKind::VOID};
    }

    // Empujar el contexto de lambda ANTES de abrir el scope local: el
    // outer_depth debe reflejar el numero de scopes existentes en el
    // momento previo a entrar a la lambda, no incluyendo el scope de
    // sus propios parametros.
    const size_t outer_depth = scopes_.size();
    lambda_stack_.push_back(LambdaCtx{e, outer_depth});

    // Scope local para los parametros.
    push_scope();
    for (size_t i = 0; i < e->params.size(); ++i) {
        Symbol sym;
        sym.kind = SymbolKind::Param;
        sym.type = param_types[i];
        (void)declare(e->params[i]->name, std::move(sym));
    }

    // Type-check del body.  Usamos return_t como expected_return en
    // check_stmt; cuando no hay anotacion explicita, pasamos VOID y
    // luego inferimos del primer return encontrado.
    if (e->body) {
        // Sin tipo declarado: activar la inferencia por `return`.  Asi un
        // `return <valor>` en el cuerpo (incluso anidado en if/while, o cuando
        // el lambda viene de un @Macro sin contexto de asignacion) NO dispara
        // "return con valor en funcion void" -- su tipo se captura en
        // @c inferred_lambda_return_type_.  Salvar/restaurar por nivel para
        // lambdas anidados.
        const bool saved_infer = infer_lambda_void_return_;
        const Type saved_inferred = inferred_lambda_return_type_;
        if (!return_t_declared) {
            infer_lambda_void_return_ = true;
            inferred_lambda_return_type_ = Type{PrimitiveKind::VOID};
        }
        check_stmt(e->body.get(), return_t);
        if (!return_t_declared &&
            inferred_lambda_return_type_.kind != PrimitiveKind::VOID) {
            return_t = inferred_lambda_return_type_;
        }
        infer_lambda_void_return_ = saved_infer;
        inferred_lambda_return_type_ = saved_inferred;
    }

    pop_scope();
    lambda_stack_.pop_back();

    Type lam_t =
        Type::make_function(std::move(param_types), std::move(return_t));
    lam_t.fn_is_variadic = lam_variadic;
    return lam_t;
}

// ---------------------------------------------------------------------
// ADTs: check_match.
//
// Validaciones:
//   1. Scrutinee debe ser de tipo enum (Type{STRUCT, name} con
//      enum_layouts_[name] presente).
//   2. Cada arm debe nombrar una variante existente (o '_').
//   3. bindings.size() == variant.field_types.size().
//   4. Bindings se introducen como variables locales tipadas en el
//      scope del body (push/pop scope por arm).
//   5. Exhaustividad: error si ninguna arm es '_' y faltan
//      variantes por cubrir.
// ---------------------------------------------------------------------
Type TypeChecker::check_match(ast::MatchExpr *e) {
    if (!e->scrutinee) {
        diags_.error(e->loc, "match: scrutinee nulo");
        return Type{};
    }
    const Type st = check_expr(e->scrutinee.get());
    e->scrutinee->result_type = st;

    // ---- match sobre ESCALARES (enteros/chars), estilo switch ----
    // El scrutinee es entero/char y las arms usan patrones de VALOR
    // (`case 1 =>`, `case 'a' =>`) + `case _ =>` default (obligatorio: no se
    // puede enumerar el rango).  Dispatch eficiente en el lowering (jumptable
    // denso / busqueda binaria dispersa).  Statement-like (VOID), como el
    // match de enums; el valor se produce con `return` dentro de cada arm.
    auto is_int_or_char = [](PrimitiveKind k) {
        return k == PrimitiveKind::I8 || k == PrimitiveKind::I16 ||
               k == PrimitiveKind::I32 || k == PrimitiveKind::I64 ||
               k == PrimitiveKind::U8 || k == PrimitiveKind::U16 ||
               k == PrimitiveKind::U32 || k == PrimitiveKind::U64 ||
               k == PrimitiveKind::CHAR;
    };
    bool any_value_arm = false;
    for (auto &a : e->arms)
        if (a.value_pattern) {
            any_value_arm = true;
            break;
        }
    const bool scrut_is_string = (st.kind == PrimitiveKind::STRING);
    if (any_value_arm || scrut_is_string ||
        (st.kind != PrimitiveKind::STRUCT && is_int_or_char(st.kind))) {
        if (!is_int_or_char(st.kind) && !scrut_is_string) {
            diags_.error(e->scrutinee->loc,
                         "match con patrones de valor requiere un scrutinee "
                         "entero, char o string, recibido " +
                             type_to_string(st));
            return Type{PrimitiveKind::VOID};
        }
        bool has_default = false;
        for (auto &arm : e->arms) {
            if (arm.value_pattern) {
                Type pt = check_expr(arm.value_pattern.get());
                if (scrut_is_string) {
                    if (arm.value_pattern->kind !=
                        ast::NodeKind::StringLitExpr) {
                        diags_.error(arm.loc,
                                     "el patron de un match sobre string debe "
                                     "ser un literal de cadena");
                    }
                    if (arm.value_pattern_hi)
                        diags_.error(arm.loc,
                                     "los rangos `a..b` no aplican a strings");
                } else if (!is_int_or_char(pt.kind)) {
                    diags_.error(arm.loc,
                                 "el patron de un match escalar debe ser un "
                                 "literal entero o char");
                }
                // Rango: el endpoint alto tambien debe ser entero/char.
                if (arm.value_pattern_hi) {
                    Type ph = check_expr(arm.value_pattern_hi.get());
                    if (!is_int_or_char(ph.kind))
                        diags_.error(arm.loc,
                                     "el fin del rango debe ser un literal "
                                     "entero o char");
                }
            } else if (arm.variant_name == "_") {
                has_default = true;
            } else {
                diags_.error(
                    arm.loc,
                    "en un match escalar/string los patrones deben ser "
                    "literales o '_' (default)");
            }
            if (arm.guard) {
                Type tg = check_expr(arm.guard.get());
                if (tg.kind != PrimitiveKind::BOOL && !is_numeric(tg.kind) &&
                    tg.kind != PrimitiveKind::COUNT)
                    diags_.error(arm.loc,
                                 "el guard del case debe ser booleano");
            }
            push_scope();
            if (arm.body) check_stmt(arm.body.get(), current_fn_return_type_);
            pop_scope();
        }
        if (!has_default) {
            diags_.error(e->loc,
                         "match no exhaustivo: anyade 'case _ =>' como default "
                         "(no se puede enumerar todos los valores)");
        }
        return Type{PrimitiveKind::VOID};
    }

    // ---- match sobre Optional<T> / Result<V,E> ----
    // Ambos son conceptualmente enums (None|Some, Err|Ok); se tratan como
    // un enum sintetico de dos variantes (ver build_optlike_enum_layout).
    // Toda la maquinaria de arms/bindings/scope/exhaustividad de abajo se
    // reutiliza sin cambios: solo cambia de donde sale el EnumLayout.
    EnumLayout syn_optlike;
    const EnumLayout *elayp = nullptr;
    if (st.kind == PrimitiveKind::OPTIONAL ||
        st.kind == PrimitiveKind::RESULT) {
        syn_optlike = build_optlike_enum_layout(st, optional_layout(st),
                                                result_layout(st));
        elayp = &syn_optlike;
    } else {
        if (st.kind != PrimitiveKind::STRUCT) {
            diags_.error(e->scrutinee->loc,
                         std::string("match: el scrutinee debe ser un valor de "
                                     "tipo enum, recibido ") +
                             type_to_string(st));
            return Type{};
        }
        const EnumLayout *lay_sc = find_enum_layout(st.struct_name);
        auto it = enum_layouts_.end();
        if (lay_sc != nullptr)
            for (auto i2 = enum_layouts_.begin(); i2 != enum_layouts_.end();
                 ++i2)
                if (&i2->second == lay_sc) {
                    it = i2;
                    break;
                }
        if (it == enum_layouts_.end()) {
            diags_.error(e->scrutinee->loc, std::string("match: '") +
                                                st.struct_name +
                                                "' no es un enum (es struct?)");
            return Type{};
        }
        elayp = &it->second;
    }
    const EnumLayout &elay = *elayp;

    bool has_default = false;
    std::unordered_map<std::string, bool> covered;
    for (auto &arm : e->arms) {
        if (arm.variant_name == "_") {
            has_default = true;
            // Default arm: no bindings, body en scope vacio adicional.
            // Usamos current_fn_return_type_ para que returns dentro
            // del body validen con el tipo correcto de la funcion
            // enclosing.
            push_scope();
            if (arm.body) {
                check_stmt(arm.body.get(), current_fn_return_type_);
            }
            pop_scope();
            continue;
        }
        // Buscar la variante por nombre.
        const EnumVariantInfo *var = nullptr;
        for (const auto &v : elay.variants) {
            if (v.name == arm.variant_name) {
                var = &v;
                break;
            }
        }
        if (!var) {
            diags_.error(arm.loc, std::string("variante desconocida '") +
                                      arm.variant_name + "' en enum '" +
                                      elay.name + "'");
            continue;
        }
        // Bug fix 2026-05-23: solo marcamos como cubierta totalmente
        // si NO tiene guard.  Arms con guard NO cuentan para
        // exhaustividad (el guard puede ser falso en runtime).
        if (!arm.guard) covered[var->name] = true;
        // Validar aridad de bindings.
        if (arm.bindings.size() != var->field_types.size()) {
            diags_.error(arm.loc, std::string("variante '") + var->name +
                                      "': esperados " +
                                      std::to_string(var->field_types.size()) +
                                      " bindings, recibidos " +
                                      std::to_string(arm.bindings.size()));
        }
        // Push scope, bind cada binding con su tipo, lower body.
        push_scope();
        const size_t n = std::min(arm.bindings.size(), var->field_types.size());
        for (size_t i = 0; i < n; ++i) {
            Symbol sym;
            sym.kind = SymbolKind::Variable;
            sym.type = var->field_types[i];
            if (!declare(arm.bindings[i], std::move(sym))) {
                diags_.error(arm.loc, "binding duplicado en patron: '" +
                                          arm.bindings[i] + "'");
            }
        }
        // Bug fix 2026-05-23: validar tipo del guard.
        if (arm.guard) {
            Type tg = check_expr(arm.guard.get());
            if (tg.kind != PrimitiveKind::BOOL && !is_numeric(tg.kind) &&
                tg.kind != PrimitiveKind::COUNT) {
                diags_.error(
                    arm.loc,
                    "el guard del case debe ser una expresion booleana, no '" +
                        type_to_string(tg) + "'");
            }
        }
        if (arm.body) {
            check_stmt(arm.body.get(), current_fn_return_type_);
        }
        pop_scope();
    }

    // Exhaustividad: si no hay default, todas las variantes deben
    // estar cubiertas (al menos una arm cada una).
    if (!has_default) {
        std::vector<std::string> missing;
        for (const auto &v : elay.variants) {
            if (!covered.count(v.name)) missing.push_back(v.name);
        }
        if (!missing.empty()) {
            std::string msg = "match no exhaustivo: faltan variantes:";
            for (const auto &m : missing)
                msg += " " + m;
            msg +=
                " (anyade una arm por cada una o usa 'case _ =>' como default)";
            diags_.error(e->loc, msg);
        }
    }

    // En MVP el match es statement-like, no produce valor utilizable
    // como expresion (cada arm puede tener su propio efecto).
    return Type{PrimitiveKind::VOID};
}

Type TypeChecker::check_ident(ast::IdentExpr *e) {
    // Ruta B (H2 move-only): usar un local tras un move (`S b = a; use(a)`)
    // es un error.  La fuente quedo invalidada por el move (su contenido se
    // transfirio a `b`); leerla seria un use-after-move.  Reasignar el local
    // lo rehabilita (se limpia en check_assign).
    if (!moved_locals_.empty() && moved_locals_.count(e->name)) {
        diags_.error(e->loc,
                     "uso de '" + e->name +
                         "' tras moverlo: el valor se transfirio a otro "
                         "binding (move); el tipo es gestionado sin copy-hook "
                         "'__clone__', por lo que la copia es un move. Define "
                         "'__clone__' si quieres copiar, o reasigna '" +
                         e->name + "' antes de usarlo.");
    }

    /* A.39: si el ident resuelve a un comptime const (local o
     * global), anotamos el valor en el AST.  El lowering lee la
     * marca y emite CONST directo sin volver a consultar la tabla
     * (que puede haber sido pop()-ada por scope locals).  Esto
     * preserva los comptime const locales a traves del boundary
     * type-check -> lowering. */
    {
        /* Buscar en stack de scopes locales primero. */
        for (auto sc = comptime_const_locals_.rbegin();
             sc != comptime_const_locals_.rend(); ++sc) {
            auto it = sc->find(e->name);
            if (it != sc->end()) {
                // BugFix R8 mutation: en @Macro body, NO anotar
                // comptime_const_resolved si el var es mutable (puede
                // tener escrituras runtime que el lowering debe leer
                // del stack slot).  El AST evaluator sigue accediendo
                // a comptime_const_locals_ directamente.  Solo para
                // vars con tipo declarado (not auto-register).
                if (current_fn_is_macro_ && it->second.is_mutable) {
                    e->result_type = it->second.type;
                    return e->result_type;
                }
                e->comptime_const_resolved = true;
                if (it->second.is_str) {
                    e->comptime_const_is_str = true;
                    e->comptime_const_str = it->second.str_value;
                } else {
                    e->comptime_const_int = it->second.value;
                }
                e->result_type = it->second.type;
                return e->result_type;
            }
        }
        /* Tabla global. */
        auto it = comptime_const_values_.find(e->name);
        if (it != comptime_const_values_.end()) {
            e->comptime_const_resolved = true;
            if (it->second.is_str) {
                e->comptime_const_is_str = true;
                e->comptime_const_str = it->second.str_value;
            } else {
                e->comptime_const_int = it->second.value;
            }
            e->result_type = it->second.type;
            return e->result_type;
        }
    }
    size_t depth = 0;
    const Symbol *s = lookup_with_depth(e->name, &depth);
    if (!s) {
        // Aliases magicos para reflexion estatica:
        // `Class`, `Method`, `Field`, `Object` pueden aparecer como
        // base de una llamada estatica `Class.forName(...)` SIN haber
        // sido declarados como variable.  En ese contexto NO son
        // identificadores resolubles; el dispatch los reconoce en
        // `check_call` con la forma estatica.  Aqui devolvemos un
        // tipo i64 silencioso para que `check_expr` no reporte error.
        // Si el ident "Class" aparece fuera de ese contexto (e.g.
        // como expresion suelta `i32 x = Class;`), el lowering no
        // sabra que hacer y eso si fallara.  En la practica el unico
        // uso valido es como base de un FieldAccessExpr.
        if (e->name == "Class" || e->name == "Method" || e->name == "Field" ||
            e->name == "Object") {
            Type t{PrimitiveKind::I64};
            e->result_type = t;
            return t;
        }
        diags_.error(e->loc, "nombre no declarado: '" + e->name + "'");
        return Type{};
    }
    // closures: si estamos dentro del body de una lambda y el
    // identificador resuelve a un scope que existia ANTES de entrar a
    // la lambda, hay que capturarlo en el env block.  Procesamos el
    // stack de lambdas desde el TOPE (la mas interna) hacia abajo:
    // cada lambda cuyo outer_depth excede el depth del lookup necesita
    // capturar el nombre.  Captures transitivas: si la lambda interna
    // captura un nombre que no esta en su outer scope pero si en uno
    // mas externo, registramos en TODAS las lambdas intermedias para
    // que el lowering construya la cadena correcta de envs.
    //
    // Solo capturamos variables (Variable / Param), no funciones top-
    // level ni clases ni metodos.  Una funcion global sigue siendo
    // accesible por nombre desde cualquier lambda sin pasar por env.
    if (s->kind != SymbolKind::Function && !lambda_stack_.empty()) {
        for (auto &ctx : lambda_stack_) {
            if (depth < ctx.outer_depth) {
                // No duplicar: si ya esta registrada como captura, saltar.
                bool already = false;
                for (auto &nm : ctx.expr->captures) {
                    if (nm == e->name) {
                        already = true;
                        break;
                    }
                }
                if (!already) {
                    ctx.expr->captures.push_back(e->name);
                    ctx.expr->capture_types.push_back(s->type);
                }
            }
        }
    }
    if (s->kind == SymbolKind::Function) {
        // Function pointers: marcamos el ident como referencia a funcion y
        // guardamos el nombre mangled, PERO devolvemos VOID (comportamiento
        // historico) para no romper:
        //   - HOF: pasar `foo` a un parametro fn(...) -> R lo promociona a
        //     closure en check_call.
        //   - closures/lambdas (modelo de 16 bytes fn+env).
        // La marca @c is_func_ref solo la consume el CAST explicito
        // (`(u64) foo` o `(fn(...)->R) foo`), que emite LABEL_ADDR (la
        // direccion cruda del codigo).  Asi el OS puede meter direcciones de
        // funciones del kernel en una tabla sin tocar el modelo de closures.
        const FunctionSig *sig = function_sig_by_name(e->name);
        if (sig) {
            e->is_func_ref = true;
            e->func_ref_mangled =
                sig->mangled_label.empty() ? e->name : sig->mangled_label;
        }
        return Type{};
    }
    return s->type;
}

//  NS.1b: colapsa una cadena de field-access de identificadores en un path
// punteado (ui.widgets.button -> "ui.widgets.button").  Devuelve false si algun
// eslabon no es IdentExpr/FieldAccessExpr simple.
static bool collect_dotted_path(const ast::Expr *e, std::string &out) {
    if (!e) return false;
    if (e->kind == ast::NodeKind::IdentExpr) {
        out = static_cast<const ast::IdentExpr *>(e)->name;
        return true;
    }
    if (e->kind == ast::NodeKind::FieldAccessExpr) {
        const auto *fa = static_cast<const ast::FieldAccessExpr *>(e);
        std::string base;
        if (!collect_dotted_path(fa->base.get(), base)) return false;
        out = base + "." + fa->field_name;
        return true;
    }
    return false;
}

Type TypeChecker::field_type_with_abi(const StructFieldInfo &f) const {
    Type t = f.type;
    // Campo de tipo funcion con default = una funcion (promovido en
    // check_functions con maybe_promote_func_ref): la ABI de una llamada
    // INDIRECTA (CALLIND) a traves de este campo viene del DEFAULT (p.ej.
    // `invoke`), no del tipo nominal del campo -- ese es el contrato del ctx
    // pattern (una reasignacion runtime debe respetar la MISMA ABI).  Se
    // propaga la ABI COMPLETA del default; el cast del campo la trunca a la
    // aridad real (toma los N primeros registros).  Asi el CALLIND via campo
    // usa multi-ABI igual que un CALL directo.
    if (t.kind == PrimitiveKind::FUNCTION && f.default_init &&
        f.default_init->result_type.kind == PrimitiveKind::FUNCTION &&
        !f.default_init->result_type.fn_param_abi_regs.empty()) {
        t.fn_param_abi_regs = f.default_init->result_type.fn_param_abi_regs;
    }
    return t;
}

Type TypeChecker::check_field_access(ast::FieldAccessExpr *e) {
    //  NS.1b: acceso qualified MULTI-segmento a namespace
    // (`ui.widgets.button`): la base es una CADENA de field-access de
    // identificadores.  Colapsamos la base en un path punteado, la resolvemos
    // como namespace (por su nombre completo registrado) y buscamos
    // @c field_name como simbolo suyo.  El caso single-segment (`ui.button`) lo
    // cubre el path M.7 de mas abajo (base = IdentExpr).
    if (e->base && e->base->kind == ast::NodeKind::FieldAccessExpr) {
        std::string base_ns_path;
        if (collect_dotted_path(e->base.get(), base_ns_path)) {
            uint32_t ns_idx = UINT32_MAX;
            auto it = ns_idx_by_local_name_.find(base_ns_path);
            if (it != ns_idx_by_local_name_.end()) {
                ns_idx = it->second;
            } else {
                const Symbol *s = lookup(base_ns_path);
                if (s && s->kind == SymbolKind::Namespace) ns_idx = s->ns_index;
            }
            if (ns_idx < imported_namespaces_.size()) {
                const auto &ns = imported_namespaces_[ns_idx];
                auto its = ns.by_name.find(e->field_name);
                if (its != ns.by_name.end()) {
                    referenced_names_.insert(base_ns_path);
                    const auto &sym = ns.symbols[its->second];
                    e->property_kind = 4;
                    e->ns_index = ns_idx;
                    if (sym.kind == 0) { // funcion
                        Type t = Type::make_function(sym.sig.param_types,
                                                     sym.sig.return_type);
                        e->result_type = t;
                        return t;
                    }
                    if (sym.kind == 2) { // tipo (struct/class/enum/alias)
                        if (enum_layouts_.find(sym.mangled_label) !=
                            enum_layouts_.end()) {
                            Type t{PrimitiveKind::STRUCT, sym.mangled_label};
                            e->result_type = t;
                            return t;
                        }
                        if (class_layouts_.find(sym.mangled_label) !=
                            class_layouts_.end()) {
                            Type t{PrimitiveKind::CLASS, sym.mangled_label};
                            e->result_type = t;
                            return t;
                        }
                        if (struct_layouts_.find(sym.mangled_label) !=
                            struct_layouts_.end()) {
                            Type t{PrimitiveKind::STRUCT, sym.mangled_label};
                            e->result_type = t;
                            return t;
                        }
                    }
                    /* Variables y constantes.  Faltaban: aqui solo se resolvia
                     * la funcion y el tipo, asi que leer una constante publica
                     * por su namespace -- `std.memory.x86_64.BIT_AVX2` -- caia
                     * al camino de un solo segmento, que no aplica, y acababa
                     * en "nombre no declarado: 'std'".  Con `only` funcionaba,
                     * y esa diferencia es la que empujaba a escribir el import
                     * de otra forma en vez de arreglar esto.
                     *
                     * Mismo tratamiento que en el acceso de un segmento: si es
                     * una constante compile-time, se anota su valor en el nodo
                     * para que el lowering emita un CONST y no una lectura. */
                    {
                        auto itcc =
                            comptime_const_values_.find(sym.mangled_label);
                        if (itcc != comptime_const_values_.end()) {
                            e->comptime_const_resolved = true;
                            if (itcc->second.is_str) {
                                e->comptime_const_is_str = true;
                                e->comptime_const_str = itcc->second.str_value;
                            } else {
                                e->comptime_const_int = itcc->second.value;
                            }
                            e->result_type = itcc->second.type;
                            return e->result_type;
                        }
                    }
                    if (sym.kind == 1) { // variable / constante
                        e->result_type = sym.var_type;
                        return sym.var_type;
                    }
                }
            }
        }
    }
    // ADTs: detectar variante sin payload `Color.Red` (sin
    // parens).  Si la base es un identificador que nombra un enum
    // y el field_name es una variante de aridad 0, lo tratamos como
    // CONSTRUCTOR sin argumentos y devolvemos Type{STRUCT, enum_name}.
    // Si la variante tiene payload no-vacio, reportamos error
    // sugiriendo invocar con argumentos.
    if (e->base && e->base->kind == ast::NodeKind::IdentExpr) {
        auto *base_id = static_cast<ast::IdentExpr *>(e->base.get());
        //  M.7: namespace qualified access (`lib_a.valor_a`).
        // Si el IdentExpr base resuelve a un Symbol::Namespace, el
        // field_name es un simbolo del namespace; devolvemos su tipo
        // (return type para FUNCTION, var_type para Variable).
        // Marcamos property_kind=4 para que el lowering reconozca
        // que debe emitir CALL al mangled_label.
        {
            const Symbol *ns_sym = lookup(base_id->name);
            uint32_t ns_idx_base = UINT32_MAX;
            if (ns_sym && ns_sym->kind == SymbolKind::Namespace) {
                ns_idx_base = ns_sym->ns_index;
            } else if (!ns_sym) {
                // NS short-form: la base NO es un simbolo (ni variable ni
                // funcion), pero SI un namespace registrado -- incluido el
                // alias del ultimo segmento (`shapes` -> `org.geo.shapes`).
                // Fallback guardado por `!ns_sym` para no robar un nombre que
                // ya sea una funcion/variable homonima.
                auto itns = ns_idx_by_local_name_.find(base_id->name);
                if (itns != ns_idx_by_local_name_.end())
                    ns_idx_base = itns->second;
            }
            if (ns_idx_base != UINT32_MAX) {
                // L.26: marcar el namespace como referenciado para
                // que el linter de "import no se usa" no genere
                // falsos positivos.  El `lookup` plano no toca
                // @c referenced_names_ ; aqui sabemos que el acceso
                // namespace.X tuvo exito, asi que marcamos manualmente.
                referenced_names_.insert(base_id->name);
                if (ns_idx_base < imported_namespaces_.size()) {
                    const auto &ns = imported_namespaces_[ns_idx_base];
                    auto its = ns.by_name.find(e->field_name);
                    if (its == ns.by_name.end()) {
                        diags_.error(e->loc,
                                     "el namespace '" + base_id->name +
                                         "' no tiene un simbolo llamado '" +
                                         e->field_name + "' (modulo '" +
                                         ns.module_name + "')");
                        return Type{};
                    }
                    const auto &sym = ns.symbols[its->second];
                    e->property_kind = 4;      // namespace member
                    e->ns_index = ns_idx_base; // M.7: para lowering
                    // Para functions, el "tipo" del FieldAccess es VOID
                    // (no es una expresion valor); el call site lo trata
                    // como una callable.  Pero retornamos un Type
                    // FUNCTION para que `check_call` lo detecte.
                    if (sym.kind == 0) {
                        // function
                        Type t = Type::make_function(sym.sig.param_types,
                                                     sym.sig.return_type);
                        e->result_type = t;
                        return t;
                    }
                    if (sym.kind == 2) {
                        // TypeAlias (struct/class/enum/typedef cross-module).
                        // Devolver un Type que apunte al layout mangled
                        // para que el outer FieldAccess (`ns.Type.Variant`)
                        // o constructor (`new ns.Class(...)`) pueda
                        // resolver el layout correcto en class_layouts_/
                        // struct_layouts_/enum_layouts_.
                        if (enum_layouts_.find(sym.mangled_label) !=
                            enum_layouts_.end()) {
                            // Enum types ref: convencion existente usa
                            // PrimitiveKind::STRUCT + struct_name (el name
                            // coincide con un layout en enum_layouts_).
                            Type t{PrimitiveKind::STRUCT, sym.mangled_label};
                            e->result_type = t;
                            return t;
                        }
                        if (class_layouts_.find(sym.mangled_label) !=
                            class_layouts_.end()) {
                            Type t{PrimitiveKind::CLASS, sym.mangled_label};
                            e->result_type = t;
                            return t;
                        }
                        if (struct_layouts_.find(sym.mangled_label) !=
                            struct_layouts_.end()) {
                            Type t{PrimitiveKind::STRUCT, sym.mangled_label};
                            e->result_type = t;
                            return t;
                        }
                        // typedef alias: resolver al subyacente.
                        auto it_alias = type_aliases_.find(sym.mangled_label);
                        if (it_alias != type_aliases_.end()) {
                            e->result_type = it_alias->second;
                            return it_alias->second;
                        }
                        // No resolvible -> void.
                        e->result_type = Type{};
                        return Type{};
                    }
                    // Variables / Constants.  NS.2: si es un comptime const
                    // del namespace (`mod.ANSWER`), su valor vive en
                    // comptime_const_values_ bajo el label mangled; lo
                    // resolvemos y anotamos en el nodo para que el lowering
                    // emita un CONST inline (cero overhead, compile-time).
                    {
                        auto itcc =
                            comptime_const_values_.find(sym.mangled_label);
                        if (itcc != comptime_const_values_.end()) {
                            e->comptime_const_resolved = true;
                            if (itcc->second.is_str) {
                                e->comptime_const_is_str = true;
                                e->comptime_const_str = itcc->second.str_value;
                            } else {
                                e->comptime_const_int = itcc->second.value;
                            }
                            e->result_type = itcc->second.type;
                            return e->result_type;
                        }
                    }
                    e->result_type = sym.var_type;
                    return sym.var_type;
                }
            }
        }
        // Limitacion G (cerrada): acceso a static field via nombre de
        // clase: @c Counter.count.  Si el base es IdentExpr cuyo nombre
        // resuelve a una clase declarada (no es una variable local),
        // tratamos como acceso a static field.  Marcamos
        // @c property_kind=3 para que el lowering emita
        // @c findclass + getstatic en vez del @c addr=obj+offset
        // habitual de instancia.
        auto it_cls_static = class_layouts_.find(base_id->name);
        if (it_cls_static != class_layouts_.end()) {
            const ClassLayout &lay = it_cls_static->second;
            for (const auto &f : lay.static_fields) {
                if (f.name == e->field_name) {
                    e->property_kind = 3; // marca para el lowering
                    e->result_type = f.type;
                    return f.type;
                }
            }
            // Nombre de clase pero el campo no es static: mensaje claro.
            diags_.error(e->loc, "la clase '" + base_id->name +
                                     "' no tiene un campo static llamado '" +
                                     e->field_name + "'");
            return Type{};
        }
        // Gemelo para STRUCT: `Struct.campo_static` (singletons/contadores por
        // tipo).  El storage es la global `<Struct>__<campo>`; property_kind=8
        // le dice al lowering que acceda a esa global en vez del offset de
        // instancia. Si el campo no es static, NO diagnosticamos aqui: podria
        // ser `Struct.staticMethod()` (un CallExpr, resuelto en check_call).
        {
            auto it_str_static = struct_layouts_.find(base_id->name);
            if (it_str_static != struct_layouts_.end()) {
                for (const auto &f : it_str_static->second.static_fields) {
                    if (f.name == e->field_name) {
                        e->property_kind = 8;
                        e->result_type = f.type;
                        return f.type;
                    }
                }
            }
        }
        // L2.3: enum generico template `Maybe.None` -> resolver via
        // expected stack (LHS var-decl/param).  Sin contexto:
        // diagnostic.
        if (is_generic_enum_template(base_id->name)) {
            const std::string *expected = expected_enum_mangled(base_id->name);
            if (expected) {
                auto it_mono = enum_layouts_.find(*expected);
                if (it_mono != enum_layouts_.end()) {
                    const EnumLayout &elay = it_mono->second;
                    for (const auto &v : elay.variants) {
                        if (v.name == e->field_name) {
                            if (!v.field_types.empty()) {
                                diags_.error(
                                    e->loc, std::string("variante '") + v.name +
                                                "' del enum '" + elay.name +
                                                "' tiene payload(s); usa '" +
                                                base_id->name + "." + v.name +
                                                "(...)' con argumentos");
                                return Type{PrimitiveKind::STRUCT, elay.name};
                            }
                            e->property_kind = 99;
                            Type rt{PrimitiveKind::STRUCT, elay.name};
                            e->result_type = rt;
                            // Reescribir base_id->name al mangled
                            // para que el lowering lo trate como enum
                            // concreto.
                            base_id->name = elay.name;
                            return rt;
                        }
                    }
                }
            }
            diags_.error(e->loc,
                         "no se puede inferir tipos para enum generico '" +
                             base_id->name +
                             "'; usa anotacion explicita en var-decl o param");
            return Type{};
        }
        // Un solo sitio decide que enum es este nombre (ver
        // find_enum_layout): antes se buscaba a mano aqui y en otros veinte
        // puntos, cada uno cubriendo unos nombres si y otros no.
        const EnumLayout *lay_p = find_enum_layout(base_id->name);
        auto it_en =
            lay_p ? enum_layouts_.find(lay_p->name.empty() ? base_id->name
                                                           : lay_p->name)
                  : enum_layouts_.end();
        if (it_en == enum_layouts_.end() && lay_p) {
            // El layout existe pero su clave no es su propio nombre: se busca
            // por identidad para quedarse con el iterador correcto.
            for (auto it2 = enum_layouts_.begin(); it2 != enum_layouts_.end();
                 ++it2)
                if (&it2->second == lay_p) {
                    it_en = it2;
                    break;
                }
        }
        if (it_en != enum_layouts_.end()) {
            const EnumLayout &elay = it_en->second;
            for (const auto &v : elay.variants) {
                if (v.name == e->field_name) {
                    // C-style: enum con valor -> la variante ES una constante
                    // del tipo base.  property_kind=98; el tipo es el base
                    // (etiquetado con el nombre del enum si es entero/float/
                    // string; el nombre del struct/clase si el backing es de
                    // usuario -- un Color.RED ES un Rgb).
                    if (elay.is_valued) {
                        e->property_kind = 98;
                        Type rt{elay.backing};
                        if (!elay.backing_type_name.empty()) {
                            rt.struct_name = elay.backing_type_name;
                        } else {
                            rt.struct_name = elay.name;
                            rt.is_valued_enum = true;
                        }
                        e->result_type = rt;
                        return rt;
                    }
                    if (!v.field_types.empty()) {
                        diags_.error(
                            e->loc, std::string("variante '") + v.name +
                                        "' del enum '" + elay.name +
                                        "' tiene " +
                                        std::to_string(v.field_types.size()) +
                                        " payload(s); usa '" + elay.name + "." +
                                        v.name + "(...)' con argumentos");
                        return Type{PrimitiveKind::STRUCT, elay.name};
                    }
                    // Variante sin payload: marcar property_kind=99
                    // para que el lowering la trate como constructor
                    // sin args.
                    e->property_kind = 99;
                    // Si se llego por un newtype (`Tinta.Verde`), el valor es
                    // del NEWTYPE, no del enum de debajo: devolver el Type
                    // declarado, que lleva su nominal_id.  Con `elay.name` a
                    // secas, `Tinta t = Tinta.Verde;` fallaba con "tipo (Color)
                    // incompatible con tipo declarado (Tinta)".
                    Type rt{PrimitiveKind::STRUCT, elay.name};
                    if (auto ait = type_aliases_.find(base_id->name);
                        ait != type_aliases_.end() &&
                        ait->second.nominal_id != 0)
                        rt = ait->second;
                    e->result_type = rt;
                    return rt;
                }
            }
            diags_.error(e->loc, "variante desconocida '" + e->field_name +
                                     "' en enum '" + elay.name + "'");
            return Type{};
        }
    }

    // Cross-module variant access: `lib.Op.Nop` o `lib.Op.Add(...)`.
    // El base (FieldAccessExpr `lib.Op`) ya resolvio a un enum type
    // (typedef alias cross-module marcado property_kind=4).  Aqui
    // detectamos que el outer FieldAccess es variant-lookup.
    if (e->base && e->base->kind == ast::NodeKind::FieldAccessExpr) {
        // Resolver el tipo del base primero.
        const Type bt_ns = check_expr(e->base.get());
        if (bt_ns.kind == PrimitiveKind::STRUCT) {
            const EnumLayout *lay_ns = find_enum_layout(bt_ns.struct_name);
            if (lay_ns != nullptr) {
                const EnumLayout &elay = *lay_ns;
                for (const auto &v : elay.variants) {
                    if (v.name == e->field_name) {
                        // Valued enum via namespace (`ns.Op.MOV`): la variante
                        // ES una constante del tipo base.  El lowering
                        // (property_kind=98) resuelve el enum por
                        // e->base->result_type.struct_name.
                        if (elay.is_valued) {
                            e->property_kind = 98;
                            Type rt{elay.backing};
                            if (!elay.backing_type_name.empty()) {
                                rt.struct_name = elay.backing_type_name;
                            } else {
                                rt.struct_name = elay.name;
                                rt.is_valued_enum = true;
                            }
                            e->result_type = rt;
                            return rt;
                        }
                        if (!v.field_types.empty()) {
                            diags_.error(
                                e->loc,
                                std::string("variante '") + v.name +
                                    "' del enum '" + elay.name + "' tiene " +
                                    std::to_string(v.field_types.size()) +
                                    " payload(s); usa '" + elay.name + "." +
                                    v.name + "(...)' con argumentos");
                            return Type{PrimitiveKind::STRUCT, elay.name};
                        }
                        e->property_kind = 99; // variante sin payload
                        Type rt{PrimitiveKind::STRUCT, elay.name};
                        e->result_type = rt;
                        return rt;
                    }
                }
                diags_.error(e->loc, "variante desconocida '" + e->field_name +
                                         "' en enum '" + elay.name + "'");
                return Type{};
            }
        }
        // No es enum cross-module: caer al path generico.
    }

    // Bajar el tipo del lado izquierdo: debe ser STRUCT o CLASS.
    Type bt = check_expr(e->base.get());
    /* Un PUNTERO a struct o clase se atraviesa solo: `q.x` es `(*q).x`.  En vez
     * de ensenar a cada sitio de aguas abajo -- leer, asignar, `++`, `&`,
     * llamar a un metodo -- lo que significa un punto sobre un puntero, se
     * REESCRIBE el arbol aqui, metiendo la desreferencia que el programador no
     * escribio.  A partir de este punto no hay ningun caso nuevo: es la forma
     * que ya funcionaba.
     *
     * Un solo nivel, como el `->` de C: para `Punto**` sigue haciendo falta
     * decirlo a mano, porque ahi la intencion ya no es evidente. */
    if (bt.kind == PrimitiveKind::PTR && bt.pointee &&
        (bt.pointee->kind == PrimitiveKind::STRUCT ||
         bt.pointee->kind == PrimitiveKind::CLASS)) {
        auto deref = std::make_unique<ast::UnaryExpr>();
        deref->op = ast::UnOp::Deref;
        deref->loc = e->base->loc;
        deref->operand = std::move(e->base);
        e->base = std::move(deref);
        bt = check_expr(e->base.get());
    }
    if (bt.kind == PrimitiveKind::STRUCT) {
        auto it = struct_layouts_.find(bt.struct_name);
        if (it == struct_layouts_.end()) {
            diags_.error(e->loc,
                         "struct desconocido: '" + bt.struct_name + "'");
            return Type{};
        }
        const StructLayout &lay = it->second;
        for (const auto &f : lay.fields) {
            if (f.name == e->field_name) return field_type_with_abi(f);
        }
        // Campo `comptime` (solo-compile-time, p.ej. `comptime char* name`
        // para calcular un hash): no vive en el layout de instancia pero SI
        // se resuelve para el codigo comptime (constructores/metodos comptime
        // que lo leen/escriben).  Marca el acceso con property_kind=97 para
        // que el lowering sepa que NO debe emitir un STORE/LOAD a un offset de
        // instancia (el campo lo consume la ComptimeVM, no el runtime).
        for (const auto &f : lay.comptime_fields) {
            if (f.name == e->field_name) {
                e->property_kind = 97; // campo comptime (sin storage runtime)
                return field_type_with_abi(f);
            }
        }
        diags_.error(e->loc, "el struct '" + bt.struct_name +
                                 "' no tiene un campo llamado '" +
                                 e->field_name + "'");
        return Type{};
    }
    if (bt.kind == PrimitiveKind::CLASS) {
        auto it = class_layouts_.find(bt.struct_name);
        if (it == class_layouts_.end()) {
            diags_.error(e->loc, "clase desconocida: '" + bt.struct_name + "'");
            return Type{};
        }
        const ClassLayout &lay = it->second;
        // Buscar el campo y aplicar enforcement de visibilidad.  Los
        // campos privados solo se pueden acceder desde la propia
        // clase; los protegidos desde la propia o subclases.
        // Aqui solo distinguimos private vs publico/protegido porque
        // sin herencia protected actua como public.
        // Enforcement de visibilidad: si el campo es privado y se
        // accede desde fuera de la clase contenedora, error.  Como
        // StructFieldInfo no lleva el flag access, lo localizamos en
        // el AST original via @c find_class_field_access_flag.
        uint8_t access_flag = 0; // 0 = public/default
        const ast::ClassDecl *cd_orig = nullptr;
        for (auto &d : mod_.decls) {
            if (!d || d->kind != ast::NodeKind::ClassDecl) continue;
            auto *cdp = static_cast<const ast::ClassDecl *>(d.get());
            if (cdp->name == bt.struct_name) {
                cd_orig = cdp;
                break;
            }
        }
        if (cd_orig) {
            for (const auto &fd : cd_orig->fields) {
                if (fd.name == e->field_name) {
                    access_flag = fd.access;
                    break;
                }
            }
        }
        const bool inside_same_class = (current_class_ == bt.struct_name);
        if (access_flag == 1 /*private*/ && !inside_same_class) {
            diags_.error(e->loc,
                         "campo privado '" + e->field_name + "' de la clase '" +
                             bt.struct_name +
                             "' no es accesible desde fuera de la clase");
        }
        for (const auto &f : lay.fields) {
            if (f.name == e->field_name) return f.type;
        }
        for (const auto &f : lay.static_fields) {
            if (f.name == e->field_name) return f.type;
        }
        // Si no hay campo con ese nombre, buscar getter de propiedad
        // `get_<field_name>`.  Si existe, marcar como acceso de
        // propiedad y devolver su tipo de retorno.  El lowering ve
        // @c property_kind=1 y emite la llamada al accesor.
        const std::string getter_name = std::string("get_") + e->field_name;
        for (const auto &m : lay.methods) {
            if (m.name == getter_name && !m.is_constructor) {
                e->property_kind = 1;
                return m.return_type;
            }
        }
        // Si solo hay setter (`set_<field_name>`), el campo es
        // write-only; leerlo es error.  Distinguimos del caso
        // "no existe nada" para mejor diagnostico.
        const std::string setter_name = std::string("set_") + e->field_name;
        for (const auto &m : lay.methods) {
            if (m.name == setter_name && !m.is_constructor) {
                diags_.error(e->loc, "la propiedad '" + e->field_name +
                                         "' de la clase '" + bt.struct_name +
                                         "' es solo de escritura (sin getter)");
                return Type{};
            }
        }
        diags_.error(e->loc, "la clase '" + bt.struct_name +
                                 "' no tiene un campo llamado '" +
                                 e->field_name + "'");
        return Type{};
    }
    /* Un PUNTERO a struct/clase merece respuesta propia.  El '.' no
     * desreferencia solo, asi que decir "debe ser un struct o clase" es cierto
     * pero no ayuda: lo que hace falta es como se escribe en su lugar, y va en
     * el mensaje.
     *
     * Y se devuelve "tipo desconocido" en vez de void: void se propaga y hace
     * que el resto de la expresion se queje tambien -- por un `q.x` salian
     * TRES errores, dos de ellos ruido derivado del primero. */
    if (bt.kind == PrimitiveKind::PTR && bt.pointee &&
        (bt.pointee->kind == PrimitiveKind::STRUCT ||
         bt.pointee->kind == PrimitiveKind::CLASS)) {
        std::string base_txt = "expr";
        if (e->base && e->base->kind == ast::NodeKind::IdentExpr)
            base_txt = static_cast<ast::IdentExpr *>(e->base.get())->name;
        diags_.diag(e->loc, DiagLevel::ERR, "VX2001",
                    {base_txt, type_to_string(bt), e->field_name});
        return Type{PrimitiveKind::COUNT};
    }
    diags_.error(
        e->loc,
        "el operando de '.' debe ser un struct o clase (tipo recibido: " +
            type_to_string(bt) + ")");
    return Type{};
}

// ¿el argumento/valor @p e es una CONSTANTE numerica que puede coercionarse a
// un newtype NUMERICO @p param sin cast?  Regla ergonomica (NO debilita el
// tipado fuerte entre newtypes distintos): un tipo numerico -- incluido un
// typedef-new como `uintptr` -- recibe constantes numericas directamente
// (`f(0)`, `uintptr p = 4096`).  Un valor NO-constante (otra variable) sigue
// requiriendo cast explicito.  Misma logica en check_var_decl / check_assign.
static bool numeric_const_fits_newtype(const Type &param, const Type &arg,
                                       const ast::Expr *e) {
    if (param.nominal_id == 0 || !is_numeric(param.kind)) return false;
    if (!(is_numeric(arg.kind) || arg.kind == PrimitiveKind::CHAR))
        return false;
    if (!e) return false;
    switch (e->kind) {
    case ast::NodeKind::IntLitExpr:
    case ast::NodeKind::FloatLitExpr:
    case ast::NodeKind::CharLitExpr: return true;
    case ast::NodeKind::UnaryExpr: {
        auto *u = static_cast<const ast::UnaryExpr *>(e);
        return (u->op == ast::UnOp::Neg || u->op == ast::UnOp::BitNot) &&
               u->operand &&
               (u->operand->kind == ast::NodeKind::IntLitExpr ||
                u->operand->kind == ast::NodeKind::FloatLitExpr);
    }
    default: return false;
    }
}

/**
 * @brief Comprueba UN argumento contra el parametro que le toca.
 *
 * Es la pregunta que mas veces se hace el comprobador -- por cada argumento de
 * cada llamada -- y estaba escrita varias veces, una por clase de llamada:
 * funcion suelta, closure, metodo, constructor, variante de enum.  Las copias
 * no coincidian: una admitia subir un puntero a struct a su base y otra no.
 *
 * Dos cosas ocurren aqui ademas de comparar, y por eso no es un simple
 * @c types_assignable:
 *
 *   - Si el parametro espera una FUNCION y el argumento es el NOMBRE de una
 *     declarada en el modulo, se convierte en un valor-funcion.  Sin esto,
 *     pasar `&doblar` seria lo unico que valdria, y escribir el nombre a secas
 *     daria un error raro sobre `void`.  Se respeta la naturaleza del
 *     parametro: un puntero a codigo crudo y un lambda no son lo mismo.
 *   - Una constante numerica que cabe en un newtype se re-tipa a el, para que
 *     `f(3)` valga cuando el parametro es un `Metros` y no obligue a escribir
 *     la conversion.
 *
 * @param arg  El argumento; su @c result_type puede quedar reescrito.
 * @param tp   El tipo del parametro.
 * @param idx  Su posicion, contando desde cero, para el mensaje.
 * @param what Como nombrar lo que se llama en el mensaje ("" = generico).
 */

/**
 * @brief Empaqueta los argumentos de una llamada para ejecutarla al COMPILAR,
 *        si TODOS son constantes que se sepan escribir.
 *
 * La maquina que ejecuta al compilar recibe los argumentos por sus registros,
 * asi que cada constante se escribe en uno.  Eso NO cambia el tipo de nada: el
 * ancho del registro es el del TRANSPORTE, y quien recibe el argumento lo lee
 * con el ancho que declaro -- un `i16` sigue siendo de dieciseis bits, y uno
 * negativo llega negativo --.  Confundir las dos cosas seria decir que el
 * lenguaje trabaja en palabras de sesenta y cuatro, y no es cierto ni aqui ni,
 * mucho menos, en otros procesadores.
 *
 * Un argumento que no sea constante -- o que lo sea de una forma que no sepamos
 * escribir -- impide la jugada entera, y por eso la respuesta es un si o un no
 * para todos y no una palabra por argumento.
 *
 * Estaba escrito dos veces, para las dos cosas que ejecutan al compilar: la
 * expansion de una macro y la comprobacion cruzada que valida el resultado del
 * arbol contra el de la maquina.  Y la segunda copia no sabia empaquetar
 * CADENAS -- su propio comentario lo dejaba como pendiente --, asi que se
 * saltaba en silencio toda llamada que pasara una, que son muchas.
 *
 * Lo que cabe: enteros, booleanos, caracteres, nulo, decimales (por sus bits) y
 * cadenas no interpoladas (por el manejador del objeto que se construye).  Y el
 * signo menos delante de un numero, que el arbol representa como una operacion
 * y aqui se resuelve al vuelo -- sin eso, `f(-42)` no se podria ejecutar al
 * compilar, que es un caso de lo mas normal.
 *
 * @param e   La llamada.
 * @param out Donde dejar las palabras; queda a medias si se devuelve @c false.
 * @return @c true si TODOS los argumentos se pudieron escribir.
 */
bool TypeChecker::marshal_const_args(const ast::CallExpr &e,
                                     std::vector<uint64_t> &out) {
    out.clear();
    out.reserve(e.args.size());
    for (const auto &a : e.args) {
        if (!a) return false;
        switch (a->kind) {
        case ast::NodeKind::IntLitExpr:
            out.push_back(static_cast<const ast::IntLitExpr *>(a.get())->value);
            break;
        case ast::NodeKind::BoolLitExpr:
            out.push_back(static_cast<const ast::BoolLitExpr *>(a.get())->value
                              ? 1u
                              : 0u);
            break;
        case ast::NodeKind::CharLitExpr:
            out.push_back(
                static_cast<const ast::CharLitExpr *>(a.get())->codepoint);
            break;
        case ast::NodeKind::NullLitExpr: out.push_back(0u); break;
        case ast::NodeKind::FloatLitExpr: {
            /* Un decimal viaja por sus BITS, no por su valor: los registros por
             * los que pasan los argumentos son de enteros, y quien lo recibe
             * vuelve a leerlos como numero. */
            const double v =
                static_cast<const ast::FloatLitExpr *>(a.get())->value;
            uint64_t bits = 0;
            std::memcpy(&bits, &v, sizeof(bits));
            out.push_back(bits);
            break;
        }
        case ast::NodeKind::StringLitExpr: {
            /* Una cadena viaja por el manejador del objeto que se construye con
             * la misma maquinaria que en ejecucion.  Una INTERPOLADA no: sus
             * huecos son expresiones que hay que evaluar, y eso es justo lo que
             * no se puede hacer todavia. */
            const auto *lit = static_cast<const ast::StringLitExpr *>(a.get());
            if (lit->is_interpolated()) return false;
            uint64_t handle = 0;
            if (!comptime_runtime_.marshal_string(lit->value, handle))
                return false;
            out.push_back(handle);
            break;
        }
        case ast::NodeKind::UnaryExpr: {
            /* El signo menos delante de un numero: el arbol lo representa como
             * una operacion, y aqui se resuelve al vuelo.  Sin esto, `f(-42)`
             * -- de lo mas normal -- no se podria ejecutar al compilar. */
            const auto *u = static_cast<const ast::UnaryExpr *>(a.get());
            if (u->op != ast::UnOp::Neg || !u->operand) return false;
            if (u->operand->kind == ast::NodeKind::IntLitExpr) {
                const auto *lit =
                    static_cast<const ast::IntLitExpr *>(u->operand.get());
                out.push_back(
                    static_cast<uint64_t>(-static_cast<int64_t>(lit->value)));
            } else if (u->operand->kind == ast::NodeKind::FloatLitExpr) {
                const double neg =
                    -static_cast<const ast::FloatLitExpr *>(u->operand.get())
                         ->value;
                uint64_t bits = 0;
                std::memcpy(&bits, &neg, sizeof(bits));
                out.push_back(bits);
            } else {
                return false;
            }
            break;
        }
        default: return false;
        }
    }
    return true;
}
bool TypeChecker::arg_fits_param(ast::Expr *arg, const Type &tp, Type &ta) {
    if (!arg) return true;

    /* Un literal con decimales es de sesenta y cuatro bits por omision.  Si el
     * parametro es de treinta y dos hay que re-tiparlo AQUI, despues de
     * comprobarlo -- comprobar vuelve a calcular su tipo y desharia la marca --
     * o la bajada guardaria en un hueco de cuatro bytes los bits de ocho, que
     * es guardar basura. */
    if ((tp.kind == PrimitiveKind::F32 || tp.kind == PrimitiveKind::F64) &&
        arg->kind == ast::NodeKind::FloatLitExpr && ta.kind != tp.kind) {
        arg->result_type = tp;
        ta = tp;
    }

    /* El NOMBRE de una funcion del modulo, donde se espera una funcion, se
     * convierte en un valor-funcion (direccion + entorno vacio).  El nodo se
     * marca con ese tipo para que la bajada emita el par de ocho mas ocho. */
    if (tp.kind == PrimitiveKind::FUNCTION && ta.kind == PrimitiveKind::VOID &&
        arg->kind == ast::NodeKind::IdentExpr) {
        auto *id_arg = static_cast<ast::IdentExpr *>(arg);
        const Symbol *s_arg = lookup(id_arg->name);
        if (s_arg && s_arg->kind == SymbolKind::Function) {
            const FunctionSig &arg_sig = function_sigs_[s_arg->sig_index];
            Type fnv =
                Type::make_function(arg_sig.param_types, arg_sig.return_type);
            /* Un puntero a codigo crudo (ocho bytes) y un lambda (direccion mas
             * entorno) NO son el mismo tipo: se respeta el del parametro. */
            fnv.fn_is_raw = tp.fn_is_raw;
            if (types_assignable(tp, fnv)) {
                ta = fnv;
                id_arg->result_type = fnv;
            }
        }
    }

    if (numeric_const_fits_newtype(tp, ta, arg)) {
        arg->result_type = tp; // una constante que cabe ES de ese tipo
        return true;
    }
    if (ta.kind == PrimitiveKind::COUNT) return true; // ya se dijo que fallaba
    // El ascenso de una subclase a su base, igual que el de punteros a struct
    // que ya estaba aqui al lado: pasar un `Perro` donde se pide un `Animal`.
    return types_assignable(tp, ta) || class_is_assignable(tp, ta) ||
           value_assignable_to_interface(tp, ta) ||
           struct_ptr_upcast_ok(tp, ta);
}

/**
 * @brief Dice por que no hay tal metodo, y comprueba los argumentos igual.
 *
 * No siempre es que el metodo no exista.  Puede que el nombre sea el de un
 * CAMPO que guarda una funcion -- y entonces `obj.cb(3)` es una llamada
 * indirecta perfectamente valida --, o puede que el metodo exista en la
 * plantilla y esta instanciacion lo haya DEJADO FUERA porque su condicion no se
 * cumple, que es un caso donde decir "no tiene ese metodo" seria enganoso: lo
 * tiene, pero no para este tipo.
 *
 * Los argumentos se comprueban aunque no haya a que llamar, para no callar un
 * error que este dentro de uno de ellos.
 *
 * @param e      La llamada.
 * @param fa     El acceso `obj.metodo`.
 * @param campos Los campos del tipo, por si el nombre es uno que guarda una
 *               funcion.
 * @param tipo   Nombre del tipo, para el mensaje.
 * @param clase_o_struct Como llamarlo ("la clase" / "el struct").
 * @param llamada_indirecta Que hacer si el nombre resulta ser un campo funcion.
 * @return El tipo del resultado: el de la llamada indirecta, o ninguno.
 */
Type TypeChecker::report_method_missing(
    ast::CallExpr *e, ast::FieldAccessExpr *fa,
    const std::vector<StructFieldInfo> &campos, const std::string &tipo,
    const char *clase_o_struct,
    const std::function<Type(const Type &)> &llamada_indirecta) {
    /* Antes de dar el nombre por inexistente: puede ser un CAMPO que guarda una
     * funcion, y entonces `obj.cb(3)` es una llamada indirecta valida. */
    for (const auto &fld : campos)
        if (fld.name == fa->field_name &&
            fld.type.kind == PrimitiveKind::FUNCTION)
            return llamada_indirecta(fld.type);

    /* Si la plantilla lo declara pero esta instanciacion lo dejo fuera, se dice
     * QUE condicion falta; "no tiene ese metodo" seria enganoso. */
    std::string requiere;
    auto uit = unavailable_methods_.find(tipo);
    if (uit != unavailable_methods_.end())
        for (const auto &pr : uit->second)
            if (pr.first == fa->field_name) {
                requiere = pr.second;
                break;
            }

    if (!requiere.empty())
        diags_.error(e->loc, "el metodo '" + fa->field_name +
                                 "' no esta disponible para '" + tipo +
                                 "' (requiere " + requiere + ")");
    else
        diags_.error(e->loc, std::string(clase_o_struct) + " '" + tipo +
                                 "' no tiene un metodo '" + fa->field_name +
                                 "'");

    for (auto &a : e->args)
        (void)check_expr(a.get());
    return Type{};
}

/**
 * @brief Busca un metodo de INSTANCIA por nombre.
 *
 * Se salta los constructores, y no es un detalle: viven en la misma lista que
 * los metodos, asi que buscar solo por nombre deja llamar al constructor como
 * si fuera un metodo -- `s.S(5)` --, que no es lo que nadie quiere decir.  La
 * copia de las clases ya lo hacia y la de los structs no, con lo que la misma
 * escritura se rechazaba en una y se colaba en la otra.
 *
 * @param metodos La lista del layout.
 * @param nombre  El que se busca.
 * @return El metodo, o nulo.
 */
static const ClassMethodInfo *
find_instance_method(const std::vector<ClassMethodInfo> &metodos,
                     const std::string &nombre) {
    for (const auto &m : metodos) {
        if (m.is_constructor) continue;
        if (m.name == nombre) return &m;
    }
    return nullptr;
}

/**
 * @brief Busca un metodo ESTATICO por nombre en una lista de metodos.
 *
 * Se salta los constructores a proposito: viven en la misma lista que los
 * metodos, asi que buscar solo por nombre encuentra el constructor de una clase
 * que se llame igual -- es la trampa clasica de esta estructura.
 *
 * @param metodos La lista del layout (de clase o de struct).
 * @param nombre  El que se busca.
 * @return El metodo, o nulo si no hay uno estatico con ese nombre.
 */
static const ClassMethodInfo *
find_static_method(const std::vector<ClassMethodInfo> &metodos,
                   const std::string &nombre) {
    for (const auto &m : metodos) {
        if (m.is_constructor) continue;
        if (m.is_static && m.name == nombre) return &m;
    }
    return nullptr;
}

/**
 * @copydoc vx::TypeChecker::check_static_method_call
 */
Type TypeChecker::check_static_method_call(ast::CallExpr *e,
                                           ast::FieldAccessExpr *fa,
                                           const ClassMethodInfo &smtd,
                                           const std::string &donde,
                                           uint8_t marca) {
    if (e->args.size() != smtd.param_types.size()) {
        diags_.error(e->loc,
                     donde + ": numero de argumentos incorrecto (esperado " +
                         std::to_string(smtd.param_types.size()) +
                         ", recibido " + std::to_string(e->args.size()) + ")");
    }
    for (size_t i = 0; i < e->args.size(); ++i)
        check_call_arg(e->args[i].get(),
                       i < smtd.param_types.size() ? smtd.param_types[i]
                                                   : Type{},
                       i, donde);
    fa->property_kind = marca;
    fa->base->result_type = Type{PrimitiveKind::VOID};
    e->result_type = smtd.return_type;
    return smtd.return_type;
}

/**
 * @brief Comprueba la construccion de una variante de enum y da su tipo.
 *
 * `Color.Rojo(3)` no es una llamada a nada: es fabricar un valor del enum con
 * la carga que la variante declara.  Aun asi se comprueba igual que una llamada
 * -- misma cantidad, mismos tipos, mismas conversiones -- porque para quien
 * escribe el programa es lo mismo, y que una constante valga como argumento y
 * no como carga seria una diferencia que nadie sabria explicar.
 *
 * Estaba escrito dos veces, en dos ramas distintas del mismo despacho: la que
 * llega por el nombre del enum y la que llega por un valor de ese tipo.
 *
 * @param e    La construccion.
 * @param fa   El acceso `Enum.Variante`, que queda marcado para la bajada.
 * @param var  La variante y los tipos de su carga.
 * @param enum_name Nombre del enum, que es el tipo del resultado.
 * @return El tipo del valor construido.
 */
Type TypeChecker::check_variant_ctor(ast::CallExpr *e, ast::FieldAccessExpr *fa,
                                     const EnumVariantInfo &var,
                                     const std::string &enum_name) {
    if (e->args.size() != var.field_types.size()) {
        diags_.error(e->loc, std::string("variante '") + var.name +
                                 "': esperados " +
                                 std::to_string(var.field_types.size()) +
                                 " argumentos, recibidos " +
                                 std::to_string(e->args.size()));
    }
    const size_t n = std::min(e->args.size(), var.field_types.size());
    for (size_t i = 0; i < n; ++i)
        check_call_arg(e->args[i].get(), var.field_types[i], i,
                       "la variante '" + var.name + "'");
    /* Los que sobran se comprueban igual, por sus efectos: un error dentro de
     * uno de ellos hay que decirlo aunque el argumento no pinte nada. */
    for (size_t i = n; i < e->args.size(); ++i)
        (void)check_expr(e->args[i].get());

    /* 99 marca "esto construye una variante": la bajada tiene un camino propio
     * para eso y lo reconoce por este valor. */
    fa->property_kind = 99;
    Type rt{PrimitiveKind::STRUCT, enum_name};
    fa->result_type = rt;
    return rt;
}

/**
 * @copydoc vx::TypeChecker::check_call_arg
 */
void TypeChecker::check_call_arg(ast::Expr *arg, const Type &tp, size_t idx,
                                 const std::string &what) {
    if (!arg) return;
    Type ta = check_expr(arg);
    if (arg_fits_param(arg, tp, ta)) return;
    diags_.error(arg->loc,
                 std::string("argumento ") + std::to_string(idx + 1) +
                     (what.empty() ? std::string() : (" de " + what)) +
                     ": tipo (" + type_to_string(ta) +
                     ") incompatible con parametro (" + type_to_string(tp) +
                     ")");
}
/**
 * @brief Tipo que vale `new X(...)`.
 *
 * Normalmente `CLASS X`.  Pero si @p name es un newtype sobre una clase
 * (`typedef Caja Sesion new;`), lo que vale es el Type DECLARADO -- que lleva
 * su `nominal_id`.  Fabricar uno nuevo aqui daria un `CLASS Sesion` sin id, y
 * asignarlo a un `Sesion` fallaba con el mensaje absurdo "tipo (Sesion)
 * incompatible con tipo declarado (Sesion)": mismo nombre, distinta identidad.
 */
Type TypeChecker::new_expr_result_type(const std::string &name) const {
    auto it = type_aliases_.find(name);
    if (it != type_aliases_.end() && it->second.nominal_id != 0)
        return it->second;
    return Type{PrimitiveKind::CLASS, name};
}

/**
 * @brief Mapea un operador binario a su metodo de sobrecarga canonico.
 * @return cadena vacia si el operador no tiene metodo asociado.
 *
 * `==`/`!=` se manejan aparte (`__ne__` se deriva negando `__eq__`).
 *
 * `&&` y `||` NO tienen metodo propio a proposito: sobrecargarlos (como deja
 * C++) mata el CORTOCIRCUITO -- `a && b` evaluaria `b` siempre.  Se sobrecarga
 * `__bool__` y ellos lo usan, igual que `!x` y que `if (x)`: el cortocircuito
 * se conserva y un solo metodo cubre los cuatro sitios.
 */
static const char *binop_dunder_name(ast::BinOp op) {
    switch (op) {
    case ast::BinOp::Add: return "__add__";
    case ast::BinOp::Sub: return "__sub__";
    case ast::BinOp::Mul: return "__mul__";
    case ast::BinOp::Div: return "__div__";
    case ast::BinOp::Mod: return "__mod__";
    case ast::BinOp::Lt: return "__lt__";
    case ast::BinOp::Gt: return "__gt__";
    case ast::BinOp::Le: return "__le__";
    case ast::BinOp::Ge: return "__ge__";
    // Bitwise y shifts (nombres de Python).
    case ast::BinOp::BitAnd: return "__and__";
    case ast::BinOp::BitOr: return "__or__";
    case ast::BinOp::BitXor: return "__xor__";
    case ast::BinOp::Shl: return "__lshift__";
    case ast::BinOp::Shr: return "__rshift__";
    default: return "";
    }
}

/**
 * @brief Texto del operador tal y como se escribe, para los diagnosticos.
 */
static const char *binop_spelling(ast::BinOp op) {
    switch (op) {
    case ast::BinOp::Add: return "+";
    case ast::BinOp::Sub: return "-";
    case ast::BinOp::Mul: return "*";
    case ast::BinOp::Div: return "/";
    case ast::BinOp::Mod: return "%";
    case ast::BinOp::Lt: return "<";
    case ast::BinOp::Gt: return ">";
    case ast::BinOp::Le: return "<=";
    case ast::BinOp::Ge: return ">=";
    case ast::BinOp::BitAnd: return "&";
    case ast::BinOp::BitOr: return "|";
    case ast::BinOp::BitXor: return "^";
    case ast::BinOp::Shl: return "<<";
    case ast::BinOp::Shr: return ">>";
    default: return "?";
    }
}

Type TypeChecker::check_binary(ast::BinaryExpr *e) {
    const Type tl = check_expr(e->lhs.get());
    const Type tr = check_expr(e->rhs.get());

    // Newtype entero CERRADO bajo aritmetica/bitwise/shift: un typedef-new
    // sobre un entero (nominal_id != 0), p.ej. `uintptr`/`usize`, conserva su
    // identidad al operar con el MISMO newtype o con un entero plano.  Asi
    // `uintptr p; p = p + 8;` o `p & ~15` (alinear) NO requieren un cast en
    // cada paso -> los tipos semanticos son usables en la stdlib.  Sin esto,
    // promote_arith devolveria el underlying (u64) y la reasignacion al
    // newtype fallaria.  @p fallback = tipo entero plano si no aplica.
    // @return el Type resultado (newtype preservado o @p fallback).
    auto preserve_int_newtype = [&](const Type &a, const Type &b,
                                    PrimitiveKind fallback) -> Type {
        const bool a_nt = a.nominal_id != 0 && is_integral(a.kind);
        const bool b_nt = b.nominal_id != 0 && is_integral(b.kind);
        // a es newtype y b es el mismo newtype o un entero plano -> a.
        if (a_nt && is_integral(b.kind) &&
            (!b_nt || b.nominal_id == a.nominal_id))
            return a;
        // b es newtype y a es un entero plano -> b.
        if (b_nt && is_integral(a.kind) && !a_nt) return b;
        return Type{fallback};
    };

    // Operator overloading via metodos dunder (C-1 + C-2).  Si @c tl es
    // de tipo CLASS o STRUCT y declara el dunder correspondiente al
    // operador cuya firma acepta @c tr, el operador DESPACHA a
    // @c tl.__op__(tr) y el resultado es el return type del metodo.
    // Mapeo C-1: `+` -> __add__, `==`/`!=` -> __eq__/__ne__.
    // Mapeo C-2 (aritmetica): `-` -> __sub__, `*` -> __mul__,
    //   `/` -> __div__, `%` -> __mod__.
    // Mapeo C-2 (comparacion): `<` -> __lt__, `>` -> __gt__,
    //   `<=` -> __le__, `>=` -> __ge__.
    // Sin el dunder, el flujo clasico de abajo queda intacto (cero cambio
    // para tipos que no sobrecargan).  El dispatch del lowering es
    // generico: CALLVIRT para CLASS, CALL directo para STRUCT.
    {
        const auto &binop_dunder = binop_dunder_name;
        // Localiza un metodo dunder por nombre en una lista de metodos
        // (CLASS o STRUCT): no-constructor, no-static, unario (1 param)
        // cuya firma acepte @c tr.  Devuelve nullptr si no hay match.
        auto find_dunder = [&](const std::vector<ClassMethodInfo> &methods,
                               const char *nm) -> const ClassMethodInfo * {
            for (const auto &m : methods) {
                if (m.is_constructor || m.is_static) continue;
                if (m.name != nm) continue;
                if (m.param_types.size() != 1) continue;
                if (types_assignable(m.param_types[0], tr)) return &m;
            }
            return nullptr;
        };
        // Obtiene el vector de metodos del tipo del lhs (CLASS o STRUCT).
        // nullptr si el tipo no es sobrecargable o no esta registrado.
        const std::vector<ClassMethodInfo> *methods = nullptr;
        if (tl.kind == PrimitiveKind::CLASS && !tl.struct_name.empty()) {
            auto it_cls = class_layouts_.find(tl.struct_name);
            if (it_cls != class_layouts_.end())
                methods = &it_cls->second.methods;
        } else if (tl.kind == PrimitiveKind::STRUCT &&
                   !tl.struct_name.empty()) {
            auto it_s = struct_layouts_.find(tl.struct_name);
            if (it_s != struct_layouts_.end()) methods = &it_s->second.methods;
        }
        if (methods) {
            if (e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq) {
                // `==` -> __eq__ ; `!=` -> __ne__ si existe, si no __eq__
                // negado.  El lowering niega el BOOL cuando overload_negate.
                if (e->op == ast::BinOp::Neq) {
                    if (const ClassMethodInfo *m =
                            find_dunder(*methods, "__ne__")) {
                        e->overload_method = "__ne__";
                        return m->return_type;
                    }
                }
                if (const ClassMethodInfo *m =
                        find_dunder(*methods, "__eq__")) {
                    e->overload_method = "__eq__";
                    e->overload_negate = (e->op == ast::BinOp::Neq);
                    (void)m;
                    return Type{PrimitiveKind::BOOL};
                }
            } else {
                // Aritmeticos + comparacion ordenada: dunder directo.  El
                // resultado es el return type del metodo (BOOL para los
                // comparadores normalmente).
                const char *nm = binop_dunder(e->op);
                if (nm[0] != '\0') {
                    if (const ClassMethodInfo *m = find_dunder(*methods, nm)) {
                        e->overload_method = nm;
                        return m->return_type;
                    }
                }
            }
        }
        // Sin dunder aplicable: cae al flujo clasico (aritmetica de
        // primitivos/punteros, igualdad struct campo-a-campo, etc.).
    }

    // Operadores nativos para STRING.
    // Auto-coerce: si un lado es STRING y el otro es un literal de string
    // (`"ASCII " + var`, o `base + "${n}"`), el lowering lo promovera a
    // StringObject / value-string (via STRMAKE o STRMAKE+STRCAT para los
    // interpolados).  Un literal INTERPOLADO tambien es un operando string
    // valido: produce una cadena en runtime -> cuenta como string para el
    // concat/comparacion (antes se excluia -> `base + "${n}"` fallaba).
    auto is_str_lit = [](ast::Expr *e) {
        return e && e->kind == ast::NodeKind::StringLitExpr;
    };
    const bool lhs_str =
        (tl.kind == PrimitiveKind::STRING) ||
        (tl.kind == PrimitiveKind::PTR && is_str_lit(e->lhs.get()));
    const bool rhs_str =
        (tr.kind == PrimitiveKind::STRING) ||
        (tr.kind == PrimitiveKind::PTR && is_str_lit(e->rhs.get()));
    // `"a" + "b"` (ambos literales de string) tambien es concat: aunque
    // ninguno sea STRING "real" (los literales se tipan PTR), dos literales
    // de string juntos solo pueden ser concatenacion (nunca aritmetica de
    // punteros, que requiere operandos PTR no-literales).
    const bool both_str_lit =
        is_str_lit(e->lhs.get()) && is_str_lit(e->rhs.get());
    const bool any_real_string = (tl.kind == PrimitiveKind::STRING) ||
                                 (tr.kind == PrimitiveKind::STRING) ||
                                 both_str_lit;
    if (lhs_str && rhs_str && any_real_string) {
        if (e->op == ast::BinOp::Add) {
            return Type{PrimitiveKind::STRING};
        }
        // Inc 4: comparacion (== != < > <= >=) -> BOOL.  La ordenacion es
        // lexicografica byte-a-byte (ver __vx_strcmp en el lowering native).
        if (e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq ||
            e->op == ast::BinOp::Lt || e->op == ast::BinOp::Gt ||
            e->op == ast::BinOp::Le || e->op == ast::BinOp::Ge) {
            return Type{PrimitiveKind::BOOL};
        }
        diags_.error(e->loc, "operador no soportado entre strings (solo + y "
                             "== != < > <= >=)");
        return Type{};
    }

    switch (e->op) {
    case ast::BinOp::Add:
    case ast::BinOp::Sub:
    case ast::BinOp::Mul:
    case ast::BinOp::Div:
    case ast::BinOp::Mod: {
        // Aritmetica puntero (estilo C). admitimos:
        //   PTR + integer  -> PTR (escalado por sizeof(*p))
        //   PTR - integer  -> PTR
        //   PTR - PTR      -> i64 (numero de elementos entre punteros)
        // No se admite integer + PTR para evitar ambiguedad y
        // simplificar el lowering; el usuario puede escribir p + n.
        if (e->op == ast::BinOp::Add || e->op == ast::BinOp::Sub) {
            // PTR/ARRAY + int -> PTR (decay implicito de array a ptr).
            const bool lhs_ptr_like = (tl.kind == PrimitiveKind::PTR ||
                                       tl.kind == PrimitiveKind::ARRAY);
            if (lhs_ptr_like && is_integral(tr.kind)) {
                if (!tl.pointee || tl.pointee->kind == PrimitiveKind::VOID) {
                    diags_.error(e->loc, "aritmetica de punteros no permitida "
                                         "sobre void* o ptr sin pointee");
                    return Type{};
                }
                // Resultado siempre es PTR (no ARRAY), porque la
                // aritmetica puede dejar el puntero fuera del rango
                // del array original; el decay esta resuelto.
                // is_virtual del resultado = is_virtual del puntero
                // base (la aritmetica preserva la naturaleza).
                return Type::make_ptr(*tl.pointee, tl.is_virtual);
            }
            // PTR - PTR -> i64 (numero de elementos entre punteros).
            // Tambien aceptamos ARRAY mediante decay.
            if (e->op == ast::BinOp::Sub) {
                const bool rhs_ptr_like = (tr.kind == PrimitiveKind::PTR ||
                                           tr.kind == PrimitiveKind::ARRAY);
                if (lhs_ptr_like && rhs_ptr_like) {
                    if (!tl.pointee || !tr.pointee ||
                        *tl.pointee != *tr.pointee) {
                        diags_.error(e->loc,
                                     "p - q requiere punteros al mismo tipo");
                        return Type{};
                    }
                    return Type{PrimitiveKind::I64};
                }
            }
        }
        // Aritmetica de char (estilo C): un char es un byte sin signo
        // (0-255).  `'a' + 'b'` SUMA los valores; el resultado es CHAR
        // si AMBOS operandos son CHAR (envuelve mod 256), o el tipo
        // entero del otro operando si solo uno es CHAR (el char se
        // promociona).  Para el calculo tratamos CHAR como U8 via
        // char_as_u8(), reusando promote_arith y la maquinaria entera.
        const bool lhs_char = (tl.kind == PrimitiveKind::CHAR);
        const bool rhs_char = (tr.kind == PrimitiveKind::CHAR);
        // Si el operando es un tipo que PODRIA sobrecargar el operador pero no
        // lo declara, decirlo nombrando el metodo que falta -- "operandos no
        // numericos" no orienta a nadie.  Caso tipico: un tipo atomico declara
        // `__iadd__` (un solo paso indivisible) y a proposito NO `__add__`, asi
        // que `g = g + 1` -- que en C++ compila y es una carrera -- aqui no
        // compila, y el mensaje dice por donde salir.
        const char *dn = binop_dunder_name(e->op);
        for (const Type *t : {&tl, &tr}) {
            if (t->kind != PrimitiveKind::CLASS &&
                t->kind != PrimitiveKind::STRUCT)
                continue;
            if (dn[0] == '\0') break;
            diags_.error(e->loc, "el tipo '" + type_to_string(*t) +
                                     "' no declara el operador '" +
                                     binop_spelling(e->op) +
                                     "' (le falta el metodo '" + dn + "')");
            return Type{};
        }
        if (!is_char_or_integral(tl.kind) && !is_floating(tl.kind)) {
            diags_.error(e->loc,
                         "operandos no numericos en operacion aritmetica");
            return Type{};
        }
        if (!is_char_or_integral(tr.kind) && !is_floating(tr.kind)) {
            diags_.error(e->loc,
                         "operandos no numericos en operacion aritmetica");
            return Type{};
        }
        if (e->op == ast::BinOp::Mod) {
            if (!is_char_or_integral(tl.kind) ||
                !is_char_or_integral(tr.kind)) {
                diags_.error(e->loc, "'%' requiere operandos enteros");
                return Type{};
            }
        }
        // char OP char -> char (un solo char, como pidio el usuario).
        if (lhs_char && rhs_char) {
            return Type{PrimitiveKind::CHAR};
        }
        // char OP integer (o al reves) -> el tipo entero (el char se
        // promociona como u8).
        if (lhs_char || rhs_char) {
            const PrimitiveKind a = char_as_u8(tl.kind);
            const PrimitiveKind b = char_as_u8(tr.kind);
            return Type{promote_arith(a, b)};
        }
        /* Narrowing de literales enteros 2026-05-16: si UN operando es
         * un IntLit (default i64) y el otro tiene un tipo entero
         * estrecho (i32/i16/i8/u32/u16/u8), y el literal CABE en ese
         * tipo, narrow el literal al tipo del otro.  Esto evita que
         * `i32 + 1` se baje como sext.i64 + add.i64 + trunc.i32
         * cuando puede ser add.i32 directo.
         *
         * Beneficio: el hot loop tipico (counter i32 += 1) baja a
         * `add.i32` puro en lugar de la cadena sext+add+trunc.  Cada
         * iteracion elimina 4 instrucciones IR (-> 4-7 instr maquina).
         */
        auto narrow_int_lit_to = [&](ast::Expr *operand,
                                     PrimitiveKind target) -> bool {
            if (!operand) return false;
            if (operand->kind != ast::NodeKind::IntLitExpr) return false;
            if (!is_integral(target)) return false;
            auto *il = static_cast<ast::IntLitExpr *>(operand);
            const int64_t v = static_cast<int64_t>(il->value);
            bool fits = false;
            switch (target) {
            case PrimitiveKind::I8:
                fits = v >= INT8_MIN && v <= INT8_MAX;
                break;
            case PrimitiveKind::I16:
                fits = v >= INT16_MIN && v <= INT16_MAX;
                break;
            case PrimitiveKind::I32:
                fits = v >= INT32_MIN && v <= INT32_MAX;
                break;
            case PrimitiveKind::I64: fits = true; break;
            case PrimitiveKind::U8: fits = v >= 0 && v <= 0xFF; break;
            case PrimitiveKind::U16: fits = v >= 0 && v <= 0xFFFF; break;
            case PrimitiveKind::U32:
                fits = v >= 0 && static_cast<uint64_t>(v) <= 0xFFFFFFFFULL;
                break;
            case PrimitiveKind::U64: fits = v >= 0; break;
            default: return false;
            }
            if (!fits) return false;
            /* Modificar el result_type del literal in-place. */
            il->result_type = Type{target};
            return true;
        };
        Type adj_l = tl;
        Type adj_r = tr;
        /* Si lhs es IntLit y rhs es entero estrecho que lo contiene. */
        if (is_integral(tl.kind) && is_integral(tr.kind) &&
            tl.kind != tr.kind) {
            if (narrow_int_lit_to(e->lhs.get(), tr.kind)) {
                adj_l = tr;
            } else if (narrow_int_lit_to(e->rhs.get(), tl.kind)) {
                adj_r = tl;
            }
        }
        return preserve_int_newtype(adj_l, adj_r,
                                    promote_arith(adj_l.kind, adj_r.kind));
    }
    case ast::BinOp::Eq:
    case ast::BinOp::Neq:
    case ast::BinOp::Lt:
    case ast::BinOp::Le:
    case ast::BinOp::Gt:
    case ast::BinOp::Ge: {
        // Comparaciones de punteros (PTR vs PTR) tratan los punteros
        // como uint64.  PTR vs null (void*) admitido tambien.
        if (tl.kind == PrimitiveKind::PTR && tr.kind == PrimitiveKind::PTR) {
            return Type{PrimitiveKind::BOOL};
        }
        // Comparacion de referencias CLASS contra null o entre si.
        // El lowering trata las refs CLASS como i64 (puntero al
        // ObjectHeader), asi que la comparacion se hace tambien
        // como entero.  Solo permitimos == y !=, no < <= > >=.
        const bool both_class_or_null =
            (tl.kind == PrimitiveKind::CLASS ||
             tl.kind == PrimitiveKind::PTR) &&
            (tr.kind == PrimitiveKind::CLASS || tr.kind == PrimitiveKind::PTR);
        if (both_class_or_null &&
            (e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq)) {
            return Type{PrimitiveKind::BOOL};
        }
        // Bug fix 2026-05-23 (LR2): struct value-type == struct
        // value-type via comparacion campo-a-campo.  Solo permitido
        // si ambos lados son del MISMO struct nombrado.  Los structs
        // con bit fields se comparan correctamente porque el lowering
        // hace una secuencia de loads + cmp_eq + and.  Solo == y !=.
        if (tl.kind == PrimitiveKind::STRUCT &&
            tr.kind == PrimitiveKind::STRUCT &&
            tl.struct_name == tr.struct_name && !tl.struct_name.empty() &&
            (e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq)) {
            return Type{PrimitiveKind::BOOL};
        }
        // Bug fix 2026-05-23: char es un codepoint entero (UTF-32);
        // se compara con int como integral (igual que C).  Tratar
        // char como numerico SOLO en este contexto de comparacion.
        auto is_cmp_compatible = [](PrimitiveKind k) {
            return is_numeric(k) || k == PrimitiveKind::CHAR;
        };
        if (!is_cmp_compatible(tl.kind) || !is_cmp_compatible(tr.kind)) {
            // Permitimos bool == bool; resto de combinaciones invalidas.
            if (!(tl.kind == PrimitiveKind::BOOL &&
                  tr.kind == PrimitiveKind::BOOL)) {
                // Igual que en la rama aritmetica: si el operando es un tipo
                // que PODRIA declarar el operador, decirlo y nombrar el metodo.
                const char *cdn = binop_dunder_name(e->op);
                bool named = false;
                for (const Type *t : {&tl, &tr}) {
                    if (t->kind != PrimitiveKind::CLASS &&
                        t->kind != PrimitiveKind::STRUCT)
                        continue;
                    if (cdn[0] == '\0') break;
                    diags_.error(e->loc, "el tipo '" + type_to_string(*t) +
                                             "' no declara el operador '" +
                                             binop_spelling(e->op) +
                                             "' (le falta el metodo '" + cdn +
                                             "')");
                    named = true;
                    break;
                }
                if (!named)
                    diags_.error(e->loc,
                                 "operandos no numericos en comparacion");
            }
        }
        return Type{PrimitiveKind::BOOL};
    }
    case ast::BinOp::LogicalAnd:
    case ast::BinOp::LogicalOr: {
        // Aceptamos bool y numericos (estilo C), y ademas cualquier tipo que
        // declare `__bool__`: el operando se convierte a bool con ESE metodo.
        // Se marca CADA lado por separado (`obj && flag` es legal) y el
        // CORTOCIRCUITO se conserva -- por eso no hay dunder de `&&`: el
        // lowering sigue emitiendo las dos ramas, y solo llama a `__bool__`
        // del lado que de verdad evalua.
        const bool l_bool = wrap_in_bool_dunder(e->lhs, tl);
        const bool r_bool = wrap_in_bool_dunder(e->rhs, tr);
        if (!l_bool && tl.kind != PrimitiveKind::BOOL && !is_numeric(tl.kind)) {
            diags_.error(e->loc,
                         "operando izquierdo no booleano en operador logico");
        }
        if (!r_bool && tr.kind != PrimitiveKind::BOOL && !is_numeric(tr.kind)) {
            diags_.error(e->loc,
                         "operando derecho no booleano en operador logico");
        }
        return Type{PrimitiveKind::BOOL};
    }
    case ast::BinOp::BitAnd:
    case ast::BinOp::BitOr:
    case ast::BinOp::BitXor:
    case ast::BinOp::Shl:
    case ast::BinOp::Shr: {
        // Promocion entera estilo C: un `char` es un entero (u8) en las
        // operaciones bitwise -- `(attr << 8) | ch` con ch:char no requiere
        // cast manual.  Reusa char_as_u8 + promote_arith como la aritmetica.
        if (!is_char_or_integral(tl.kind) || !is_char_or_integral(tr.kind)) {
            diags_.error(e->loc, "operandos no enteros en operacion bitwise");
            return Type{};
        }
        const PrimitiveKind a = char_as_u8(tl.kind);
        const PrimitiveKind b = char_as_u8(tr.kind);
        // Newtype cerrado bajo bitwise/shift: `p & ~15` (alinear una uintptr)
        // conserva el tipo uintptr.  Para shift, el newtype relevante es el
        // izquierdo (el valor desplazado); el contador (derecho) es un entero.
        return preserve_int_newtype(tl, tr, promote_arith(a, b));
    }
    }
    return Type{};
}

Type TypeChecker::check_unary(ast::UnaryExpr *e) {
    // Idempotencia: check_assign hace un "peek" del RHS antes del check real,
    // asi que check_unary puede invocarse DOS veces sobre el mismo nodo.  Si ya
    // desugaramos un metodo ligado (`&obj.m` / `&getObj().m`), devolvemos el
    // tipo ya calculado sin re-procesar -- critico para la base compuesta,
    // cuya expresion base ya fue MOVIDA a bound_recv_init (un segundo pase no
    // la encontraria y caeria al AddrOf generico -> VirtualPtr<void>).
    if (e->op == ast::UnOp::AddrOf && e->desugared_bound_method) {
        return e->result_type;
    }
    // &var.metodo -> PUNTERO A METODO LIGADO (Fase 2).  Cuando `var` es una
    // VARIABLE de tipo CLASE o STRUCT y `metodo` es un metodo (no un campo),
    // `&var.metodo` es un closure que CAPTURA el receptor.  Lo desugaramos a un
    // lambda `(args) => var.metodo(args)` (reusa toda la maquinaria de
    // closures: env owned para clase / captura del struct por valor) y lo
    // guardamos en @c desugared_bound_method.  Si la base NO es una variable
    // simple (e.g. `&getObj().metodo`) damos un error claro mas abajo.
    if (e->op == ast::UnOp::AddrOf && e->operand &&
        e->operand->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->operand.get());
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *bid = static_cast<ast::IdentExpr *>(fa->base.get());
            const Symbol *vs = lookup(bid->name);
            // Layout de la clase o struct de la variable receptora.
            const std::vector<StructFieldInfo> *rfields = nullptr;
            const std::vector<ClassMethodInfo> *rmethods = nullptr;
            if (vs && vs->kind == SymbolKind::Variable) {
                if (vs->type.kind == PrimitiveKind::CLASS) {
                    auto itc = class_layouts_.find(vs->type.struct_name);
                    if (itc != class_layouts_.end()) {
                        rfields = &itc->second.fields;
                        rmethods = &itc->second.methods;
                    }
                } else if (vs->type.kind == PrimitiveKind::STRUCT) {
                    auto its = struct_layouts_.find(vs->type.struct_name);
                    if (its != struct_layouts_.end()) {
                        rfields = &its->second.fields;
                        rmethods = &its->second.methods;
                    }
                }
            }
            if (rmethods) {
                {
                    // Buscar un METODO con ese nombre (no constructor/dtor/
                    // estatico); si es un campo, NO aplica (cae a &obj.campo).
                    const ClassMethodInfo *method = nullptr;
                    bool is_field = false;
                    for (const auto &f : *rfields)
                        if (f.name == fa->field_name) is_field = true;
                    if (!is_field) {
                        for (const auto &mm : *rmethods) {
                            if (mm.name == fa->field_name &&
                                !mm.is_constructor && !mm.is_destructor &&
                                !mm.is_static) {
                                method = &mm;
                                break;
                            }
                        }
                    }
                    if (method) {
                        // Tipo resultante = fn(...params) -> ret (lambda).
                        Type fnt = Type::make_function(method->param_types,
                                                       method->return_type);
                        // Construir y type-checkear el lambda desugarado.
                        e->desugared_bound_method = build_bound_method_lambda(
                            bid->name, *method, e->loc);
                        const Type lt =
                            check_expr(e->desugared_bound_method.get());
                        e->desugared_bound_method->result_type = lt;
                        e->result_type = fnt;
                        return fnt;
                    }
                }
            }
        }
    }
    // &expr.metodo con base COMPUESTA (no una variable simple, e.g.
    // `&getObj().metodo`): el metodo ligado necesita capturar el receptor UNA
    // vez.  Un lambda solo captura variables por nombre, asi que materializamos
    // un TEMPORAL oculto (`__bmrecv_<id>`), movemos la expresion base a
    // @c bound_recv_init (el lowering la evalua una vez y la liga al temporal)
    // y construimos el lambda capturando ese temporal -- exactamente como el
    // caso de variable simple, pero con un receptor sintetico.
    if (e->op == ast::UnOp::AddrOf && e->operand &&
        e->operand->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->operand.get());
        const bool base_is_simple_var =
            fa->base && fa->base->kind == ast::NodeKind::IdentExpr;
        if (fa->base && !base_is_simple_var) {
            const Type bt = check_expr(fa->base.get());
            fa->base->result_type = bt;
            const std::vector<StructFieldInfo> *bfields = nullptr;
            const std::vector<ClassMethodInfo> *bm = nullptr;
            if (bt.kind == PrimitiveKind::CLASS) {
                auto itc = class_layouts_.find(bt.struct_name);
                if (itc != class_layouts_.end()) {
                    bfields = &itc->second.fields;
                    bm = &itc->second.methods;
                }
            } else if (bt.kind == PrimitiveKind::STRUCT) {
                auto its = struct_layouts_.find(bt.struct_name);
                if (its != struct_layouts_.end()) {
                    bfields = &its->second.fields;
                    bm = &its->second.methods;
                }
            }
            if (bm) {
                // No aplicar si el nombre es un CAMPO (cae a &obj.campo).
                bool is_field = false;
                if (bfields)
                    for (const auto &f : *bfields)
                        if (f.name == fa->field_name) is_field = true;
                const ClassMethodInfo *method = nullptr;
                if (!is_field) {
                    for (const auto &mm : *bm) {
                        if (mm.name == fa->field_name && !mm.is_constructor &&
                            !mm.is_destructor && !mm.is_static) {
                            method = &mm;
                            break;
                        }
                    }
                }
                if (method) {
                    // Temporal oculto del receptor, registrado como Variable
                    // del tipo de la base para que el body del lambda
                    // (`__bmrecv.metodo(...)`) type-checkee igual que con una
                    // variable real.
                    const std::string recv_name =
                        "__bmrecv_" + std::to_string(next_gensym_id());
                    Symbol rs;
                    rs.kind = SymbolKind::Variable;
                    rs.type = bt;
                    (void)declare(recv_name, rs);
                    e->bound_recv_name = recv_name;
                    e->bound_recv_init = std::move(fa->base);
                    Type fnt = Type::make_function(method->param_types,
                                                   method->return_type);
                    e->desugared_bound_method =
                        build_bound_method_lambda(recv_name, *method, e->loc);
                    const Type lt = check_expr(e->desugared_bound_method.get());
                    e->desugared_bound_method->result_type = lt;
                    e->result_type = fnt;
                    return fnt;
                }
            }
        }
    }
    // &Tipo.metodo -> PUNTERO A METODO NO LIGADO (cfn).  Se detecta ANTES de
    // type-checkear el operando porque `Tipo.metodo` como FieldAccess fallaria
    // (el base nombra un TIPO, no un valor).  El metodo se desugara a la free
    // fn `Tipo__metodo(Tipo* this, ...params)`; el cfn lleva `Tipo*` como
    // primer parametro (this explicito).
    if (e->op == ast::UnOp::AddrOf && e->operand &&
        e->operand->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->operand.get());
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *bid = static_cast<ast::IdentExpr *>(fa->base.get());
            const Symbol *bsym = lookup(bid->name);
            const bool shadowed = bsym && bsym->kind == SymbolKind::Variable;
            const std::vector<ClassMethodInfo> *methods = nullptr;
            bool base_is_class = false;
            if (!shadowed) {
                auto itc = class_layouts_.find(bid->name);
                if (itc != class_layouts_.end()) {
                    methods = &itc->second.methods;
                    base_is_class = true;
                } else {
                    auto its = struct_layouts_.find(bid->name);
                    if (its != struct_layouts_.end())
                        methods = &its->second.methods;
                }
            }
            if (methods) {
                for (const auto &m : *methods) {
                    if (m.name != fa->field_name) continue;
                    if (m.is_constructor || m.is_destructor || m.is_static)
                        break;
                    std::vector<Type> params;
                    params.reserve(m.param_types.size() + 1);
                    // this: para CLASS es la referencia (ya es puntero) -> el
                    // primer parametro es el propio tipo CLASS; para STRUCT
                    // (value-type) es `Struct*`.
                    if (base_is_class) {
                        Type self_ty;
                        self_ty.kind = PrimitiveKind::CLASS;
                        self_ty.struct_name = bid->name;
                        params.push_back(self_ty);
                    } else {
                        Type self_ty;
                        self_ty.kind = PrimitiveKind::STRUCT;
                        self_ty.struct_name = bid->name;
                        params.push_back(Type::make_ptr(self_ty));
                    }
                    for (const auto &pt : m.param_types)
                        params.push_back(pt);
                    Type cfnt = Type::make_function(params, m.return_type);
                    cfnt.fn_is_raw = true;
                    fa->is_func_ref = true;
                    fa->func_ref_mangled = bid->name + "__" + m.name;
                    fa->result_type = cfnt;
                    e->result_type = cfnt;
                    return cfnt;
                }
            }
        }
    }
    const Type t = check_expr(e->operand.get());
    switch (e->op) {
    case ast::UnOp::Neg: {
        // Operator overloading C-2: `-x` -> x.__neg__() cuando @c t es
        // CLASS o STRUCT y declara @c __neg__ (metodo sin parametros).
        // El resultado es el return type del metodo.  Sin el dunder cae
        // al flujo clasico (negacion aritmetica de primitivos).
        const std::vector<ClassMethodInfo> *methods = nullptr;
        if (t.kind == PrimitiveKind::CLASS && !t.struct_name.empty()) {
            auto it_cls = class_layouts_.find(t.struct_name);
            if (it_cls != class_layouts_.end())
                methods = &it_cls->second.methods;
        } else if (t.kind == PrimitiveKind::STRUCT && !t.struct_name.empty()) {
            auto it_s = struct_layouts_.find(t.struct_name);
            if (it_s != struct_layouts_.end()) methods = &it_s->second.methods;
        }
        if (methods) {
            for (const auto &m : *methods) {
                if (m.is_constructor || m.is_static) continue;
                if (m.name != "__neg__") continue;
                if (!m.param_types.empty()) continue;
                e->overload_method = "__neg__";
                return m.return_type;
            }
        }
        if (!is_numeric(t.kind)) {
            diags_.error(e->loc,
                         "operador unario aritmetico requiere numerico");
        }
        return t;
    }
    case ast::UnOp::Pos:
        if (!is_numeric(t.kind)) {
            diags_.error(e->loc,
                         "operador unario aritmetico requiere numerico");
        }
        return t;
    case ast::UnOp::LogicalNot:
        // `!x` sobre un tipo con `__bool__`: se evalua la verdad del objeto y
        // se niega.  Mismo metodo que usan `&&`, `||` y `if (x)`.
        (void)wrap_in_bool_dunder(e->operand, t);
        return Type{PrimitiveKind::BOOL};
    case ast::UnOp::Unwrap:
        // !!x assert non-null: requiere referencia (CLASS o PTR).
        // Lowering identico a unwrap(x) pero sintactico-mas-corto.
        if (t.kind != PrimitiveKind::CLASS && t.kind != PrimitiveKind::PTR &&
            t.kind != PrimitiveKind::COUNT) {
            diags_.error(
                e->loc, std::string("'!!' requiere una referencia, recibido ") +
                            type_to_string(t));
        }
        return t;
    case ast::UnOp::Await: {
        // Mejora II: `await fut` extrae el tipo logico T de
        // Future<T>.  Casos aceptados:
        //   - Future<T>: devuelve T (el frontend hace cast/bitcast
        //     adecuado al lowering).
        //   - i64/i32/u64/u32 (legacy): devuelve I64 sin cast.
        //     Util para handles raw alocados via `future` directo.
        //   - COUNT (tipo desconocido): devuelve I64 default.
        if (t.kind == PrimitiveKind::FUTURE) {
            if (t.pointee) return *t.pointee;
            return Type{PrimitiveKind::I64};
        }
        if (t.kind != PrimitiveKind::I64 && t.kind != PrimitiveKind::I32 &&
            t.kind != PrimitiveKind::U64 && t.kind != PrimitiveKind::U32 &&
            t.kind != PrimitiveKind::COUNT) {
            diags_.error(
                e->loc,
                std::string(
                    "'await' requiere Future<T> o handle i64, recibido ") +
                    type_to_string(t));
        }
        return Type{PrimitiveKind::I64};
    }
    case ast::UnOp::BitNot: {
        // `~x` -> x.__invert__() (nombre de Python).
        if (const ClassMethodInfo *m = find_unary_dunder(t, "__invert__")) {
            e->overload_method = "__invert__";
            return m->return_type;
        }
        if (!is_integral(t.kind)) {
            diags_.error(e->loc, "'~' requiere operando entero, o un tipo que "
                                 "declare `__invert__`; recibido " +
                                     type_to_string(t));
        }
        return t;
    }
    case ast::UnOp::PreInc:
    case ast::UnOp::PreDec:
    case ast::UnOp::PostInc:
    case ast::UnOp::PostDec: {
        // `x++` es `x += 1`: si el tipo sobrecarga esa suma (via `__iadd__`
        // in-place o `__add__`), el incremento vale igual que el `+`.  Sin esto
        // la sobrecarga quedaba incoherente: `c + 1` compilaba y `c++` no,
        // significando lo mismo.
        const bool overloads_inc = (t.kind == PrimitiveKind::CLASS ||
                                    t.kind == PrimitiveKind::STRUCT) &&
                                   type_overloads_step(t);
        /* Si el tipo del operando quedo DESCONOCIDO, el porque ya se conto
         * donde ocurrio; quejarse aqui de "recibido <unknown>" solo anade una
         * segunda linea derivada de la primera. */
        if (t.kind != PrimitiveKind::COUNT && !is_integral(t.kind) &&
            !overloads_inc) {
            diags_.error(e->loc,
                         "++/-- requieren operando entero, o un tipo que "
                         "sobrecargue la suma (`__iadd__` o `__add__`); "
                         "recibido " +
                             type_to_string(t));
        }
        // const-correctness A: ++/-- MUTAN el lvalue -> prohibido si es const.
        // Cubre el const de TIPO (pointee/campo/elemento via t.is_const) Y el
        // binding const de una variable simple (`const i32 x; x++`).
        if (t.is_const) {
            diags_.error(e->loc,
                         "no se puede modificar (++/--) un lvalue 'const'");
        } else if (e->operand && e->operand->kind == ast::NodeKind::IdentExpr) {
            const auto *oid =
                static_cast<const ast::IdentExpr *>(e->operand.get());
            const Symbol *sv = lookup(oid->name);
            if (sv && sv->is_const) {
                diags_.error(e->loc, "no se puede modificar (++/--) la "
                                     "variable 'const' '" +
                                         oid->name + "'");
            }
        }
        // bug4: aceptar IdentExpr (var local), FieldAccessExpr
        // (this.x, obj.x), IndexExpr (arr[i]) y UnaryExpr Deref
        // (*p) como lvalues validos para ++/--.
        if (e->operand) {
            const auto k = e->operand->kind;
            const bool is_lvalue =
                k == ast::NodeKind::IdentExpr ||
                k == ast::NodeKind::FieldAccessExpr ||
                k == ast::NodeKind::IndexExpr ||
                (k == ast::NodeKind::UnaryExpr &&
                 static_cast<ast::UnaryExpr *>(e->operand.get())->op ==
                     ast::UnOp::Deref);
            if (!is_lvalue) {
                diags_.error(e->loc, "++/-- requieren un lvalue");
            }
        }
        return t;
    }
    case ast::UnOp::AddrOf: {
        // '&x' requiere un lvalue.  aceptamos:
        //  - IdentExpr (variable local; el lowering la promociona
        //    a ALLOCA si todavia no lo estaba).
        //  - FieldAccessExpr (campo de un struct; ya es address-taken).
        //  - UnaryExpr(Deref, p) -> equivalente al propio p.
        // Otros casos (e.g. literales, expresiones temporales) son
        // errores: no hay direccion estable.
        if (!e->operand) {
            diags_.error(e->loc, "'&' requiere un operando");
            return Type{};
        }
        // &funcion -> PUNTERO A FUNCION crudo (cfn).  La direccion de una
        // funcion top-level ES un puntero a funcion estilo C; lo tipamos como
        // cfn(sig) con fn_is_raw=true.  El lowering emite LABEL_ADDR (direccion
        // cruda del codigo), igual que el cast `(cfn(...)) nombre`.  Solo si el
        // nombre NO esta sombreado por una variable local (esa tendria address
        // normal).
        if (e->operand->kind == ast::NodeKind::IdentExpr) {
            auto *fid = static_cast<ast::IdentExpr *>(e->operand.get());
            const Symbol *vs = lookup(fid->name);
            const bool shadowed_var = vs && vs->kind == SymbolKind::Variable;
            if (!shadowed_var) {
                if (const FunctionSig *fsig = function_sig_by_name(fid->name)) {
                    fid->is_func_ref = true;
                    fid->func_ref_mangled = fsig->mangled_label.empty()
                                                ? fid->name
                                                : fsig->mangled_label;
                    Type cfnt = Type::make_function(fsig->param_types,
                                                    fsig->return_type);
                    cfnt.fn_is_raw = true; // cfn, no lambda
                    e->result_type = cfnt;
                    return cfnt;
                }
            }
        }
        const auto kind = e->operand->kind;
        const bool is_lvalue =
            kind == ast::NodeKind::IdentExpr ||
            kind == ast::NodeKind::FieldAccessExpr ||
            kind == ast::NodeKind::IndexExpr ||
            (kind == ast::NodeKind::UnaryExpr &&
             static_cast<ast::UnaryExpr *>(e->operand.get())->op ==
                 ast::UnOp::Deref);
        if (!is_lvalue) {
            diags_.error(e->loc,
                         "'&' requiere un lvalue (variable, campo, p[i] o *p)");
            return Type{};
        }
        //  AS inc.3: no se puede tomar la direccion de una
        // variable register("reg") -- vive en un registro fisico, no
        // tiene direccion estable (en C es un error de compilacion
        // `&register`).  Rechazar en compile-time con mensaje claro.
        if (kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<ast::IdentExpr *>(e->operand.get());
            const Symbol *sym = lookup(id->name);
            if (sym && !sym->reg_binding.empty()) {
                diags_.error(
                    e->loc,
                    "no se puede tomar la direccion de '" + id->name +
                        "': vive en el registro '" + sym->reg_binding +
                        "' (storage-class register), no tiene direccion");
                return Type{};
            }
        }
        // Bug host-vs-VM (2026-07-15): `&x` devuelve un `T*`, es decir una
        // direccion HOST -- sea `x` un local o un global.  Antes el default era
        // VirtualPtr<T> (memoria VM) porque el storage vivia en la memoria de
        // la VM, pero el resultado se asignaba/pasaba como `T*` sin queja del
        // checker y el consumidor lo deref-eaba con movh -> SIGSEGV.  Ahora el
        // storage esta en host en los tres modos: los locales address-taken
        // (ver @c lower_var_decl) y los globales (seccion `gdata`, que el
        // loader materializa en un bloque host; en AOT ya es `.data`).  Asi la
        // direccion ES host y ambos lados coinciden -- ademas de sobrevivir a
        // viajar por memoria (a un campo, a la FFI, a un `lock cmpxchg`).
        //
        // Consecuencia: NINGUN `&` produce memoria VM.  `VirtualPtr<T>` queda
        // como tipo de INTEROP para nombrar una direccion VM que ya se tiene
        // (via cast explicito); los casos de abajo solo la PRESERVAN cuando ya
        // se parte de una (deref de un VirtualPtr, subscript de un array
        // virtual).
        //
        // Caso 1: campo de un objeto CLASS o STRUCT.  Si el operando
        // es FieldAccessExpr cuya base es CLASS o STRUCT alocado
        // en host (e.g. via @c new), la direccion del campo es
        // HOST.  Lo distinguimos por el tipo del operando: si el
        // base.result_type es PTR is_virtual=false (host) o CLASS,
        // entonces la direccion del campo tambien es host.
        bool result_is_virtual = false;
        if (kind == ast::NodeKind::FieldAccessExpr) {
            auto *fa = static_cast<ast::FieldAccessExpr *>(e->operand.get());
            const Type bt = fa->base ? fa->base->result_type : Type{};
            if (bt.kind == PrimitiveKind::PTR && bt.is_virtual) {
                // Campo alcanzado a traves de un VirtualPtr<T>: sigue en
                // memoria VM.
                result_is_virtual = true;
            }
        }
        // Caso 2: subscript (p[i]).  La direccion del elemento
        // hereda la naturaleza del puntero/array base: solo es VM si la
        // base lo es (VirtualPtr<T> o array virtual).
        if (kind == ast::NodeKind::IndexExpr) {
            auto *ie = static_cast<ast::IndexExpr *>(e->operand.get());
            const Type bt = ie->base ? ie->base->result_type : Type{};
            if ((bt.kind == PrimitiveKind::PTR ||
                 bt.kind == PrimitiveKind::ARRAY) &&
                bt.is_virtual) {
                result_is_virtual = true;
            }
        }
        // Caso 3: deref (*p).  &*p == p; preserva exactamente la
        // naturaleza del puntero original.
        if (kind == ast::NodeKind::UnaryExpr) {
            auto *un = static_cast<ast::UnaryExpr *>(e->operand.get());
            if (un->operand) {
                const Type pt = un->operand->result_type;
                if (pt.kind == PrimitiveKind::PTR) {
                    result_is_virtual = pt.is_virtual;
                }
            }
        }
        // NOTA: `&global` NO entra aqui.  El storage de una variable global
        // vive en memoria HOST (seccion `gdata`, que el loader materializa en
        // un bloque host; en AOT ya es `.data`), asi que su direccion es un
        // `T*` normal.  Es lo que permite que sobreviva a viajar por memoria y
        // que la FFI o un `lock cmpxchg` la usen.
        return Type::make_ptr(t, result_is_virtual);
    }
    case ast::UnOp::Deref: {
        // bug6 - `*g` sobre un gc<T> (T CUALQUIERA): el operando es un
        // host_ptr a un box GC de sizeof(T) bytes; deref-earlo devuelve el
        // valor T (mismo tipo sin gc_managed).  Cubre gc<i64>, gc<f64>,
        // gc<unique<i64>>, gc<shared<unique<i64>>>, etc.  Para gc<Clase> el
        // acceso es via `.campo` (no `*`), asi que ese caso no llega aqui.
        if (t.gc_managed) {
            Type inner = t;
            inner.gc_managed = false;
            return inner;
        }
        // Sobrecarga: `*x` -> x.__deref__() cuando @c x es una CLASE o STRUCT
        // que lo declara (metodo sin parametros).  Habilita los smart pointers
        // escritos en el propio lenguaje.  Un tipo que no lo declara sigue
        // exigiendo un puntero de verdad (abajo).
        if (const ClassMethodInfo *dm = find_unary_dunder(t, "__deref__")) {
            e->overload_method = "__deref__";
            return dm->return_type;
        }
        // '*p' requiere que p sea un puntero; el tipo resultante
        // es el del tipo apuntado.  Desreferenciar void (resultado
        // de un pointee no resuelto) emite error.
        if (t.kind != PrimitiveKind::PTR || !t.pointee) {
            diags_.error(e->loc,
                         std::string("'*' requiere un puntero, recibido ") +
                             type_to_string(t));
            return Type{};
        }
        if (t.pointee->kind == PrimitiveKind::VOID) {
            diags_.error(e->loc,
                         "'*' no puede desreferenciar un puntero a void");
            return Type{};
        }
        return *t.pointee;
    }
    }
    return Type{};
}

std::unique_ptr<ast::TypeNode> TypeChecker::type_to_node(const Type &t,
                                                         SourceLoc loc) {
    if (t.kind == PrimitiveKind::CLASS || t.kind == PrimitiveKind::STRUCT) {
        auto nt = std::make_unique<ast::NamedTypeNode>();
        nt->loc = loc;
        nt->name = t.struct_name;
        return nt;
    }
    auto pn = std::make_unique<ast::PrimitiveTypeNode>();
    pn->loc = loc;
    pn->prim = t.kind;
    return pn;
}

std::unique_ptr<ast::Expr> TypeChecker::build_bound_method_lambda(
    const std::string &base_var, const ClassMethodInfo &m, SourceLoc loc) {
    // Sintetiza:  (__bm0, __bm1, ...) => base_var.metodo(__bm0, __bm1, ...)
    // El receptor base_var se referencia en el body -> el type check del
    // lambda lo detecta como CAPTURA (by-value: la referencia del objeto).
    auto lam = std::make_unique<ast::LambdaExpr>();
    lam->loc = loc;
    // Params: uno por cada parametro del metodo, con nombre sintetico.
    std::vector<std::unique_ptr<ast::Expr>> call_args;
    for (size_t i = 0; i < m.param_types.size(); ++i) {
        auto pd = std::make_unique<ast::ParamDecl>();
        pd->loc = loc;
        pd->name = "__bm" + std::to_string(i);
        pd->type = type_to_node(m.param_types[i], loc);
        lam->params.push_back(std::move(pd));
        // Arg correspondiente para la llamada.
        auto arg = std::make_unique<ast::IdentExpr>();
        arg->loc = loc;
        arg->name = "__bm" + std::to_string(i);
        call_args.push_back(std::move(arg));
    }
    // return_type del lambda = return type del metodo (null si void).
    const bool ret_void = (m.return_type.kind == PrimitiveKind::VOID ||
                           m.return_type.kind == PrimitiveKind::COUNT);
    if (!ret_void) lam->return_type = type_to_node(m.return_type, loc);
    // Cuerpo: CallExpr  base_var.metodo(args...)
    auto recv = std::make_unique<ast::IdentExpr>();
    recv->loc = loc;
    recv->name = base_var;
    auto fa = std::make_unique<ast::FieldAccessExpr>();
    fa->loc = loc;
    fa->base = std::move(recv);
    fa->field_name = m.name;
    auto call = std::make_unique<ast::CallExpr>();
    call->loc = loc;
    call->callee = std::move(fa);
    call->args = std::move(call_args);
    // BlockStmt: `return call;` (o `call;` si void).
    auto blk = std::make_unique<ast::BlockStmt>();
    blk->loc = loc;
    if (ret_void) {
        auto es = std::make_unique<ast::ExprStmt>();
        es->loc = loc;
        es->expr = std::move(call);
        blk->body.push_back(std::move(es));
    } else {
        auto ret = std::make_unique<ast::ReturnStmt>();
        ret->loc = loc;
        ret->value = std::move(call);
        blk->body.push_back(std::move(ret));
    }
    lam->body = std::move(blk);
    return lam;
}

void TypeChecker::propagate_fn_type_to_lambda(ast::LambdaExpr *lam,
                                              const Type &fn_type) {
    if (!lam || fn_type.kind != PrimitiveKind::FUNCTION) return;
    if (lam->params.size() != fn_type.fn_params.size()) return;
    for (size_t i = 0; i < lam->params.size(); ++i) {
        if (lam->params[i]->type) continue;
        const Type &pt = fn_type.fn_params[i];
        if (pt.kind == PrimitiveKind::CLASS ||
            pt.kind == PrimitiveKind::STRUCT) {
            auto nt = std::make_unique<ast::NamedTypeNode>();
            nt->loc = lam->params[i]->loc;
            nt->name = pt.struct_name;
            lam->params[i]->type = std::move(nt);
        } else {
            auto pn = std::make_unique<ast::PrimitiveTypeNode>();
            pn->loc = lam->params[i]->loc;
            pn->prim = pt.kind;
            lam->params[i]->type = std::move(pn);
        }
    }
    if (!lam->return_type && fn_type.pointee) {
        const Type &rt = *fn_type.pointee;
        if (rt.kind == PrimitiveKind::CLASS ||
            rt.kind == PrimitiveKind::STRUCT) {
            auto nt = std::make_unique<ast::NamedTypeNode>();
            nt->loc = lam->loc;
            nt->name = rt.struct_name;
            lam->return_type = std::move(nt);
        } else {
            auto pn = std::make_unique<ast::PrimitiveTypeNode>();
            pn->loc = lam->loc;
            pn->prim = rt.kind;
            lam->return_type = std::move(pn);
        }
    }
}

Type TypeChecker::maybe_promote_func_ref(ast::Expr *val, const Type &target,
                                         const Type &fallback) {
    // Solo aplica si el destino es un tipo funcion y el valor es un nombre
    // desnudo de funcion (sin `&`).  check_ident ya marco is_func_ref y
    // func_ref_mangled; aqui le damos un result_type concreto (cfn o lambda
    // segun el destino) para que types_assignable lo acepte y el lowering
    // emita LABEL_ADDR (+ slot si lambda) -- ver lower_ident.
    if (!val || target.kind != PrimitiveKind::FUNCTION) return fallback;
    if (val->kind != ast::NodeKind::IdentExpr) return fallback;
    auto *id = static_cast<ast::IdentExpr *>(val);
    if (!id->is_func_ref) return fallback;
    // No promocionar si el nombre esta sombreado por una variable local.
    const Symbol *vs = lookup(id->name);
    if (vs && vs->kind == SymbolKind::Variable) return fallback;
    const FunctionSig *fsig = function_sig_by_name(id->name);
    if (!fsig) return fallback;
    Type ft = Type::make_function(fsig->param_types, fsig->return_type);
    ft.fn_is_raw = target.fn_is_raw; // cfn o lambda segun el destino
    // La ABI custom viaja con el TIPO: `&funcion` hereda los abi_regs de la
    // firma de la funcion.  types_assignable (via operator==) exige que el tipo
    // destino declare la MISMA ABI -> asignar &f_abiA a un cfn-de-abiB (o a un
    // cfn sin ABI) es un error de tipos claro.
    ft.fn_param_abi_regs = fsig->param_abi_regs;
    val->result_type = ft;
    return ft;
}

bool TypeChecker::is_capturing_closure_expr(const ast::Expr *e) const {
    if (!e) return false;
    // Lambda literal con capturas: el env contiene esas variables.
    if (e->kind == ast::NodeKind::LambdaExpr) {
        auto *lam = static_cast<const ast::LambdaExpr *>(e);
        return !lam->captures.empty();
    }
    // Metodo ligado `&obj.m`: el lambda desugarado captura SIEMPRE el receptor.
    if (e->kind == ast::NodeKind::UnaryExpr) {
        auto *u = static_cast<const ast::UnaryExpr *>(e);
        if (u->op == ast::UnOp::AddrOf && u->desugared_bound_method)
            return true;
    }
    return false;
}

static const char *compound_assign_dunder(ast::AssignOp op);

/**
 * @brief Operador compuesto equivalente a un binario (`+` -> `+=`).
 * @return @c AssignOp::Assign si el binario no tiene forma compuesta.
 */
static ast::AssignOp binop_to_compound_assign(ast::BinOp op) {
    switch (op) {
    case ast::BinOp::Add: return ast::AssignOp::AddAssign;
    case ast::BinOp::Sub: return ast::AssignOp::SubAssign;
    case ast::BinOp::Mul: return ast::AssignOp::MulAssign;
    case ast::BinOp::Div: return ast::AssignOp::DivAssign;
    case ast::BinOp::Mod: return ast::AssignOp::ModAssign;
    case ast::BinOp::BitAnd: return ast::AssignOp::BitAndAssign;
    case ast::BinOp::BitOr: return ast::AssignOp::BitOrAssign;
    case ast::BinOp::BitXor: return ast::AssignOp::BitXorAssign;
    case ast::BinOp::Shl: return ast::AssignOp::ShlAssign;
    case ast::BinOp::Shr: return ast::AssignOp::ShrAssign;
    default: return ast::AssignOp::Assign;
    }
}

/**
 * @brief ¿Menciona @p e el identificador @p name en algun sitio?
 *
 * Conservador: ante un nodo que no sabe recorrer, responde @c true (asume que
 * si) para no fusionar de mas.
 */
static bool expr_mentions_ident(const ast::Expr *e, const std::string &name) {
    if (!e) return false;
    switch (e->kind) {
    case ast::NodeKind::IdentExpr:
        return static_cast<const ast::IdentExpr *>(e)->name == name;
    case ast::NodeKind::IntLitExpr:
    case ast::NodeKind::FloatLitExpr:
    case ast::NodeKind::BoolLitExpr:
    case ast::NodeKind::CharLitExpr:
    case ast::NodeKind::NullLitExpr: return false;
    case ast::NodeKind::BinaryExpr: {
        const auto *b = static_cast<const ast::BinaryExpr *>(e);
        return expr_mentions_ident(b->lhs.get(), name) ||
               expr_mentions_ident(b->rhs.get(), name);
    }
    case ast::NodeKind::UnaryExpr:
        return expr_mentions_ident(
            static_cast<const ast::UnaryExpr *>(e)->operand.get(), name);
    case ast::NodeKind::CastExpr:
        return expr_mentions_ident(
            static_cast<const ast::CastExpr *>(e)->operand.get(), name);
    default: return true; // no se recorrer -> asumir que lo menciona
    }
}

bool TypeChecker::try_fuse_rmw_assign(ast::AssignExpr *e) {
    // `g = g OP x`  ->  `g OP= x`  cuando el tipo de `g` declara el metodo
    // in-place (`__iadd__`, ...).  Es la INVERSA del desazucarado que ya hace
    // `prepare_overloaded_compound_assign` (un tipo con `__add__` y sin
    // `__iadd__` convierte `a += b` en `a = a + b`).
    //
    // Existe por los tipos ATOMICOS.  `g = g + 1` son tres pasos -- leer,
    // sumar, escribir -- y otro hilo cabe en medio: en C++ compila y es una
    // carrera silenciosa.  Aqui, reconocer que las dos `g` son la MISMA
    // posicion permite fusionarlo en el RMW indivisible del tipo (un solo `lock
    // xadd`, sin load suelto).  Asi el atomico se escribe en las tres formas --
    // `g++`, `g += 1` y `g = g + 1` -- y las tres son igual de correctas, en
    // vez de tener que prohibir la larga.
    //
    // Estricto a proposito (ante la duda, no fusionar):
    //   - el destino es un identificador simple: releerlo no tiene efectos
    //     (`arr[f()] = arr[f()] + 1` llamaria a `f()` dos veces);
    //   - el operando izquierdo del binario es ESE identificador, no otro;
    //   - el derecho NO lo menciona (`g = g + g` no se fusiona: son dos
    //     lecturas, y `g += g` solo seria una);
    //   - el tipo declara el metodo in-place.  Sin esto no se toca nada: los
    //     primitivos (`i64 g; g = g + 1`) siguen su camino de siempre.
    if (!e || e->op != ast::AssignOp::Assign) return false;
    if (!e->target || e->target->kind != ast::NodeKind::IdentExpr) return false;
    if (!e->value || e->value->kind != ast::NodeKind::BinaryExpr) return false;
    const std::string &nm =
        static_cast<ast::IdentExpr *>(e->target.get())->name;
    auto *bin = static_cast<ast::BinaryExpr *>(e->value.get());
    if (!bin->lhs || bin->lhs->kind != ast::NodeKind::IdentExpr) return false;
    if (static_cast<ast::IdentExpr *>(bin->lhs.get())->name != nm) return false;
    if (expr_mentions_ident(bin->rhs.get(), nm)) return false;
    const ast::AssignOp cop = binop_to_compound_assign(bin->op);
    if (cop == ast::AssignOp::Assign) return false;
    const Symbol *s = lookup(nm);
    if (!s || s->kind != SymbolKind::Variable) return false;
    if (s->type.kind != PrimitiveKind::CLASS &&
        s->type.kind != PrimitiveKind::STRUCT)
        return false;
    const char *nm_dunder = compound_assign_dunder(cop);
    if (nm_dunder[0] == '\0') return false;
    const std::vector<ClassMethodInfo> *ms = methods_of_type(s->type);
    if (!ms) return false;
    bool has_inplace = false;
    for (const auto &m : *ms) {
        if (m.is_constructor || m.is_static) continue;
        if (m.name == nm_dunder && m.param_types.size() == 1) {
            has_inplace = true;
            break;
        }
    }
    if (!has_inplace) return false;
    e->value = std::move(bin->rhs);
    e->op = cop;
    return true;
}

Type TypeChecker::check_assign(ast::AssignExpr *e) {
    // const-correctness A: check_assign_impl devuelve el tipo del LVALUE (el
    // nivel correcto: campo, pointee de `*p`, elemento de `a[i]`, o la var).
    // Si ESE nivel es const, escribir es error -- un solo check cubre todos los
    // kinds.  `const char *p; *p=x` -> impl devuelve char{is_const} -> error;
    // `char *const q; q=x` -> impl devuelve el PTR{is_const} -> error.
    Type t = check_assign_impl(e);
    if (t.is_const) {
        diags_.error(e->loc,
                     "no se puede escribir a un lvalue 'const' (el tipo de "
                     "destino es de solo lectura)");
    }
    return t;
}

/**
 * @brief Nombre del dunder de un compound assign (`+=` -> @c __iadd__).
 * @return cadena vacia para @c Assign (no es compound) o si no tiene dunder.
 *
 * Tiene dunder PROPIO, distinto del binario: `a += b` NO es `a = a + b`.  Para
 * un tipo que promete atomicidad la diferencia no es de estilo -- leer, sumar y
 * escribir son tres pasos, y otro hilo cabe en medio.
 */
static const char *compound_assign_dunder(ast::AssignOp op) {
    switch (op) {
    case ast::AssignOp::AddAssign: return "__iadd__";
    case ast::AssignOp::SubAssign: return "__isub__";
    case ast::AssignOp::MulAssign: return "__imul__";
    case ast::AssignOp::DivAssign: return "__idiv__";
    case ast::AssignOp::ModAssign: return "__imod__";
    case ast::AssignOp::BitAndAssign: return "__iand__";
    case ast::AssignOp::BitOrAssign: return "__ior__";
    case ast::AssignOp::BitXorAssign: return "__ixor__";
    case ast::AssignOp::ShlAssign: return "__ilshift__";
    case ast::AssignOp::ShrAssign: return "__irshift__";
    // `=` tiene su propio dunder (`__assign__`), no es un compound.
    case ast::AssignOp::Assign: return "";
    }
    return "";
}

/**
 * @brief Si @p slot es de un tipo con `__bool__`, lo envuelve en
 *        `(*slot).__bool__()`.
 *
 * Se DESAZUCARA en el AST en vez de marcar el nodo: el lowering ya sabe bajar
 * una llamada a metodo (CALL directo para struct, CALLVIRT para clase), asi que
 * no hay que tocarlo.  Se usa en los cuatro sitios donde un valor se lee como
 * verdad -- `!x`, `x && y`, `x || y`, `if (x)`/`while (x)` -- y por eso `&&` y
 * `||` NO tienen dunder propio: cada lado se convierte por separado y el
 * lowering sigue emitiendo sus dos ramas, asi que el CORTOCIRCUITO se conserva
 * (sobrecargar `&&`, como deja C++, lo perderia: evaluaria siempre el derecho).
 *
 * @return true si envolvio (el tipo del slot pasa a ser BOOL).
 */
bool TypeChecker::wrap_in_bool_dunder(std::unique_ptr<ast::Expr> &slot,
                                      const Type &t) {
    if (!slot) return false;
    const ClassMethodInfo *m = find_unary_dunder(t, "__bool__");
    if (!m) return false;
    auto fa = std::make_unique<ast::FieldAccessExpr>();
    fa->loc = slot->loc;
    fa->field_name = "__bool__";
    slot->result_type = t; // el lowering resuelve el layout por aqui
    fa->base = std::move(slot);
    auto call = std::make_unique<ast::CallExpr>();
    call->loc = fa->loc;
    call->callee = std::move(fa);
    call->result_type = m->return_type;
    slot = std::move(call);
    return true;
}

/**
 * @brief Busca un dunder UNARIO (sin parametros) llamado @p nm en @p t.
 * @return el metodo, o nullptr si @p t no es CLASS/STRUCT o no lo declara.
 */
const ClassMethodInfo *TypeChecker::find_unary_dunder(const Type &t,
                                                      const char *nm) const {
    const std::vector<ClassMethodInfo> *methods = methods_of_type(t);
    if (!methods) return nullptr;
    for (const auto &m : *methods) {
        if (m.is_constructor || m.is_static) continue;
        if (m.name != nm) continue;
        if (!m.param_types.empty()) continue;
        return &m;
    }
    return nullptr;
}

/// @brief Operador binario equivalente a un compound assign (`+=` -> `+`).
/// Para el desazucarado `a += b` -> `a = a + b` del fallback.
static ast::BinOp compound_assign_op_to_binop_tc(ast::AssignOp op) {
    switch (op) {
    case ast::AssignOp::SubAssign: return ast::BinOp::Sub;
    case ast::AssignOp::MulAssign: return ast::BinOp::Mul;
    case ast::AssignOp::DivAssign: return ast::BinOp::Div;
    case ast::AssignOp::ModAssign: return ast::BinOp::Mod;
    case ast::AssignOp::BitAndAssign: return ast::BinOp::BitAnd;
    case ast::AssignOp::BitOrAssign: return ast::BinOp::BitOr;
    case ast::AssignOp::BitXorAssign: return ast::BinOp::BitXor;
    case ast::AssignOp::ShlAssign: return ast::BinOp::Shl;
    case ast::AssignOp::ShrAssign: return ast::BinOp::Shr;
    default: return ast::BinOp::Add; // AddAssign (y Assign, que no llega aqui)
    }
}

/// @brief Dunder BINARIO equivalente a un compound assign (`+=` -> @c __add__).
///
/// Es el fallback cuando el tipo no declara el in-place: `a += b` pasa a ser
/// `a = a + b`.  Cadena vacia si el operador no tiene binario asociado.
static const char *compound_assign_binary_dunder(ast::AssignOp op) {
    switch (op) {
    case ast::AssignOp::AddAssign: return "__add__";
    case ast::AssignOp::SubAssign: return "__sub__";
    case ast::AssignOp::MulAssign: return "__mul__";
    case ast::AssignOp::DivAssign: return "__div__";
    case ast::AssignOp::ModAssign: return "__mod__";
    case ast::AssignOp::BitAndAssign: return "__and__";
    case ast::AssignOp::BitOrAssign: return "__or__";
    case ast::AssignOp::BitXorAssign: return "__xor__";
    case ast::AssignOp::ShlAssign: return "__lshift__";
    case ast::AssignOp::ShrAssign: return "__rshift__";
    default: return "";
    }
}

/// Lista de metodos de un CLASS/STRUCT, o nullptr si el tipo no los tiene.
const std::vector<ClassMethodInfo> *
TypeChecker::methods_of_type(const Type &t) const {
    if (t.struct_name.empty()) return nullptr;
    if (t.kind == PrimitiveKind::CLASS) {
        auto it = class_layouts_.find(t.struct_name);
        if (it != class_layouts_.end()) return &it->second.methods;
    } else if (t.kind == PrimitiveKind::STRUCT) {
        auto it = struct_layouts_.find(t.struct_name);
        if (it != struct_layouts_.end()) return &it->second.methods;
    }
    return nullptr;
}

bool TypeChecker::type_overloads_step(const Type &t) const {
    const auto *methods = methods_of_type(t);
    if (!methods) return false;
    for (const auto &m : *methods) {
        if (m.is_constructor || m.is_static) continue;
        if (m.param_types.size() != 1) continue;
        // `x++` es `x += 1`: sirve el in-place (`__iadd__`) o, cayendo al
        // clasico, `__add__`/`__isub__`/`__sub__` para `--`.
        if (m.name == "__iadd__" || m.name == "__add__" ||
            m.name == "__isub__" || m.name == "__sub__")
            return true;
    }
    return false;
}

bool TypeChecker::prepare_overloaded_compound_assign(ast::AssignExpr *e,
                                                     const Type &tt,
                                                     const Type &tv,
                                                     Type &out_result) const {
    if (!e) return false;
    if (tt.kind != PrimitiveKind::CLASS && tt.kind != PrimitiveKind::STRUCT)
        return false;
    // `g = v` sobre un tipo que declara `__assign__(V)`: la escritura la hace
    // ESE metodo, no la copia memberwise por defecto.  Es lo que permite que
    // `atomic<i64> g; g = 5;` sea un store atomico.  Un tipo que no lo declara
    // conserva la copia de siempre.  Ojo: `atomic<i64> g = 0;` es una
    // declaracion (construccion), no un AssignExpr -- no pasa por aqui.
    if (e->op == ast::AssignOp::Assign) {
        const std::vector<ClassMethodInfo> *ams = methods_of_type(tt);
        if (!ams) return false;
        for (const auto &m : *ams) {
            if (m.is_constructor || m.is_static) continue;
            if (m.name != "__assign__") continue;
            if (m.param_types.size() != 1) continue;
            if (!types_assignable(m.param_types[0], tv)) continue;
            e->overload_method = "__assign__";
            out_result = m.return_type;
            return true;
        }
        return false;
    }
    // Via 1 -- `__iadd__(V)`: in-place, UNA sola operacion.  Es lo que permite
    // que `atomic<i64> g; g += 1;` sea una unica instruccion atomica.
    if (const ClassMethodInfo *dm =
            find_compound_assign_dunder(tt, tv, e->op)) {
        e->overload_method = compound_assign_dunder(e->op);
        out_result = dm->return_type;
        return true;
    }
    // Via 2 -- fallback clasico: `c += v` pasa a ser `c = c + v`.  Se
    // DESAZUCARA en el AST (el value se sustituye por un BinaryExpr y el op por
    // `=`), asi que el resto del pipeline ve una asignacion normal cuyo valor
    // es un binario sobrecargado -- que ya funcionaba.  Cero codigo nuevo en el
    // lowering.  Asi un tipo normal (Vector, BigInt) define SOLO `__add__` y
    // obtiene `+=` y `++` gratis; el dunder in-place solo lo paga quien lo
    // necesita.
    //
    // Exige que el binario devuelva algo asignable al propio target
    // (`Cnt.__add__ -> Cnt`); si devuelve otra cosa no transforma, y el error
    // de tipos del caller lo dice -- que es lo correcto: `__add__ -> i64` no
    // define un `+=`.
    const char *bin_nm = compound_assign_binary_dunder(e->op);
    if (bin_nm[0] == '\0') return false;
    const std::vector<ClassMethodInfo> *ms = methods_of_type(tt);
    if (!ms) return false;
    for (const auto &m : *ms) {
        if (m.is_constructor || m.is_static) continue;
        if (m.name != bin_nm) continue;
        if (m.param_types.size() != 1) continue;
        if (!types_assignable(m.param_types[0], tv)) continue;
        if (!types_assignable(tt, m.return_type)) continue;
        auto bin = std::make_unique<ast::BinaryExpr>();
        bin->loc = e->loc;
        bin->op = compound_assign_op_to_binop_tc(e->op);
        // El target se LEE ademas de escribirse: hace falta una copia para el
        // lado izquierdo del binario.
        bin->lhs = vxgen::clone_expr(e->target.get());
        bin->lhs->result_type = tt;
        bin->rhs = std::move(e->value);
        bin->overload_method = bin_nm;
        bin->result_type = m.return_type;
        e->value = std::move(bin);
        e->op = ast::AssignOp::Assign;
        out_result = tt;
        return true;
    }
    return false;
}

const ClassMethodInfo *
TypeChecker::find_compound_assign_dunder(const Type &tt, const Type &tv,
                                         ast::AssignOp op) const {
    const char *nm = compound_assign_dunder(op);
    if (nm[0] == '\0') return nullptr;
    const std::vector<ClassMethodInfo> *methods = methods_of_type(tt);
    if (!methods) return nullptr;
    for (const auto &m : *methods) {
        if (m.is_constructor || m.is_static) continue;
        if (m.name != nm) continue;
        if (m.param_types.size() != 1) continue;
        if (types_assignable(m.param_types[0], tv)) return &m;
    }
    return nullptr;
}

Type TypeChecker::check_assign_impl(ast::AssignExpr *e) {
    // Target debe ser un lvalue.  admitimos:
    //  - IdentExpr        (variable simple).
    //  - FieldAccessExpr  (p.x = v).
    // Otros lvalues (deref de puntero, indexado de array) llegaran
    if (!e->target) {
        diags_.error(e->loc, "el lado izquierdo de '=' es nulo");
        (void)check_expr(e->value.get());
        return Type{};
    }

    // Fusion read-modify-write: `g = g OP x` -> `g OP= x`.  Antes de chequear
    // nada mas, porque `g + x` por si solo puede no existir.
    (void)try_fuse_rmw_assign(e);

    // Ruta B (H2 move-only): reasignar un local lo rehabilita tras un move.
    // `S b = a; a = make(); use(a)` es valido -- `a` vuelve a poseer un valor.
    if (e->target->kind == ast::NodeKind::IdentExpr && !moved_locals_.empty()) {
        moved_locals_.erase(
            static_cast<ast::IdentExpr *>(e->target.get())->name);
    }

    // validacion de escape ilegal para clases con destructor.
    // Si el value es una instancia de clase con `~Class()` y se asigna
    // a un field, slot de array o deref-store, el destructor RAII del
    // nunca llegara a ejecutarse (no hay scope owner).  Mejor
    // rechazar en compile time con error claro que dejar leaks
    // silenciosos del recurso wrapped.
    //
    // Casos legales (NO se rechazan aqui):
    //   - target IdentExpr (asignacion a var local): el cleanup_stack_
    //     ejecuta el destructor al exit del scope.
    //   - return res; (handled por escape detection -- caller
    //     toma owner via su propio cleanup_stack_).
    //   - dispose(res) explicito
    //
    // Caso ilegal:
    //   - this.field   = res;  (atributo de objeto: el dtor del objeto
    //                           no recursa a sus fields todavia)
    //   - obj.field    = res;  idem
    //   - arr[i]       = res;  (slot de array nativo, sin cleanup)
    //   - *p           = res;  (deref store, sin cleanup)
    if (e->target && e->value) {
        const bool target_is_field =
            (e->target->kind == ast::NodeKind::FieldAccessExpr);
        const bool target_is_index =
            (e->target->kind == ast::NodeKind::IndexExpr);
        bool target_is_deref = false;
        if (e->target->kind == ast::NodeKind::UnaryExpr) {
            auto *u = static_cast<ast::UnaryExpr *>(e->target.get());
            if (u->op == ast::UnOp::Deref) target_is_deref = true;
        }
        // Un lambda-literal nunca es una CLASS con destructor; saltamos el
        // peek para no type-checkear el lambda ANTES de propagarle la firma
        // esperada del campo (la propagacion va mas abajo).
        if ((target_is_field || target_is_index || target_is_deref) &&
            e->value->kind != ast::NodeKind::LambdaExpr) {
            // Resolver tipo del value sin reportar errores de check_expr
            // para no duplicar diagnosticos.  Si es CLASS con destructor,
            // emitir error claro.
            Type tv_peek = check_expr(e->value.get());
            e->value->result_type = tv_peek;
            if (tv_peek.kind == PrimitiveKind::CLASS) {
                auto it_cls = class_layouts_.find(tv_peek.struct_name);
                if (it_cls != class_layouts_.end() &&
                    it_cls->second.has_destructor) {
                    // relajacion: si el target es un FieldAccess y
                    // la CLASE CONTENEDORA tambien es destructible (tiene
                    // su propio destructor o has_destructible_field), la
                    // asignacion es legal.  El lowering augmenta el
                    // destructor del contenedor para que invoque el
                    // destructor del field automaticamente al ser
                    // destruido (RAII recursivo).
                    bool container_owns = false;
                    if (target_is_field) {
                        auto *fa = static_cast<ast::FieldAccessExpr *>(
                            e->target.get());
                        if (fa && fa->base) {
                            Type tb = check_expr(fa->base.get());
                            if (tb.kind == PrimitiveKind::CLASS) {
                                auto it_outer =
                                    class_layouts_.find(tb.struct_name);
                                if (it_outer != class_layouts_.end() &&
                                    (it_outer->second.has_destructor ||
                                     it_outer->second.has_destructible_field)) {
                                    container_owns = true;
                                }
                            }
                        }
                    }
                    if (!container_owns) {
                        const char *target_name =
                            target_is_field   ? "campo de objeto/struct"
                            : target_is_index ? "slot de array"
                                              : "deref de puntero";
                        diags_.error(
                            e->loc,
                            std::string("clase '") + tv_peek.struct_name +
                                "' tiene destructor `~" + tv_peek.struct_name +
                                "()` y no puede asignarse a " + target_name +
                                ": el destructor solo se ejecuta "
                                "automaticamente "
                                "para variables locales (RAII).  Usa `return`, "
                                "`dispose(...)` o vive en una variable local. "
                                "(O bien declara un destructor en la clase "
                                "contenedora para que herede la "
                                "responsabilidad RAII.)");
                        return Type{PrimitiveKind::VOID};
                    }
                }
            }
            // Fase 2a interop C / ownership: un STRUCT value-type con
            // `~Struct()` almacenado en un campo/slot/deref fugaria -- el
            // destructor del campo NO se ejecuta todavia (el dtor del
            // contenedor no recursa a campos struct; eso es Fase 2b).  El dtor
            // de struct SI corre para variables locales (RAII) y se transfiere
            // por `return` (move).  Rechazar el escape a campo para no dejar un
            // leak silencioso.
            if (tv_peek.kind == PrimitiveKind::STRUCT) {
                auto it_s = struct_layouts_.find(tv_peek.struct_name);
                if (it_s != struct_layouts_.end()) {
                    bool s_has_dtor = false;
                    for (const auto &m : it_s->second.methods)
                        if (m.is_destructor) {
                            s_has_dtor = true;
                            break;
                        }
                    if (s_has_dtor) {
                        // relajacion Fase 2b/3 (move-on-store): si el target es
                        // un FieldAccess y el CONTENEDOR (clase o struct) es
                        // destructible, copiar un struct-con-dtor entero a su
                        // campo es legal.  El lowering hace memcpy del struct y
                        // el local origen queda detectado como escaping
                        // (scan_escaping_locals) -> su dtor de scope-exit se
                        // suprime (MOVE); solo el dtor augmentado del
                        // contenedor libera el recurso -> un unico free, sin
                        // doble free.
                        bool container_owns = false;
                        if (target_is_field) {
                            auto *fa = static_cast<ast::FieldAccessExpr *>(
                                e->target.get());
                            if (fa && fa->base) {
                                Type tb = check_expr(fa->base.get());
                                if (tb.kind == PrimitiveKind::CLASS) {
                                    auto it_outer =
                                        class_layouts_.find(tb.struct_name);
                                    if (it_outer != class_layouts_.end() &&
                                        (it_outer->second.has_destructor ||
                                         it_outer->second
                                             .has_destructible_field))
                                        container_owns = true;
                                } else if (tb.kind == PrimitiveKind::STRUCT) {
                                    auto it_outer =
                                        struct_layouts_.find(tb.struct_name);
                                    if (it_outer != struct_layouts_.end() &&
                                        it_outer->second.has_destructible_field)
                                        container_owns = true;
                                }
                            }
                        }
                        if (!container_owns) {
                            const char *target_name =
                                target_is_field   ? "campo de objeto/struct"
                                : target_is_index ? "slot de array"
                                                  : "deref de puntero";
                            diags_.error(
                                e->loc,
                                std::string("struct '") + tv_peek.struct_name +
                                    "' tiene destructor `~" +
                                    tv_peek.struct_name +
                                    "()` y no puede asignarse a " +
                                    target_name +
                                    ": el destructor del recurso no se "
                                    "ejecutaria (fuga).  Usalo como variable "
                                    "local (RAII) o retornalo (move).  (O bien "
                                    "declara el contenedor con "
                                    "destructor/campo "
                                    "destructible para que herede la "
                                    "responsabilidad RAII.)");
                            return Type{PrimitiveKind::VOID};
                        }
                    }
                }
            }
            // Re-procesamos el target/value despues por el flujo normal.
            // Idempotente porque check_expr no muta el AST de forma no-op.
        }
    }
    // Caso FieldAccessExpr: validar como lvalue de struct/clase, o
    // detectar setter de propiedad si la clase tiene `set_<field>`.
    if (e->target->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->target.get());
        // Limitacion (cerrada): @c Counter.count = v.  Si el base
        // es IdentExpr cuyo nombre es una clase declarada, tratamos
        // como asignacion a static field y delegamos a
        // @c check_field_access (que marca property_kind=3 y resuelve
        // el tipo desde @c lay.static_fields).  Sin esto, el
        // @c check_expr(base) reportaria "nombre no declarado".
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *base_id = static_cast<ast::IdentExpr *>(fa->base.get());
            auto it_cls = class_layouts_.find(base_id->name);
            if (it_cls != class_layouts_.end()) {
                Type ft_static = check_field_access(fa);
                fa->result_type = ft_static;
                const Type tv = check_expr(e->value.get());
                if (ft_static.kind != PrimitiveKind::COUNT &&
                    tv.kind != PrimitiveKind::COUNT &&
                    !types_assignable(ft_static, tv)) {
                    diags_.error(
                        e->loc,
                        std::string("tipo del valor (") + type_to_string(tv) +
                            ") incompatible con tipo del static field '" +
                            fa->field_name + "' (" + type_to_string(ft_static) +
                            ")");
                }
                return ft_static;
            }
            // Gemelo para STRUCT: `Struct.campo_static = v` (singletons/
            // contadores).  Delegamos a check_field_access (property_kind=8)
            // para no resolver el base como variable (daria "nombre no
            // declarado").
            auto it_str_lhs = struct_layouts_.find(base_id->name);
            if (it_str_lhs != struct_layouts_.end()) {
                bool is_sf = false;
                for (const auto &f : it_str_lhs->second.static_fields)
                    if (f.name == fa->field_name) {
                        is_sf = true;
                        break;
                    }
                if (is_sf) {
                    Type ft_static = check_field_access(fa);
                    fa->result_type = ft_static;
                    const Type tv = check_expr(e->value.get());
                    if (ft_static.kind != PrimitiveKind::COUNT &&
                        tv.kind != PrimitiveKind::COUNT &&
                        !types_assignable(ft_static, tv)) {
                        diags_.error(
                            e->loc, std::string("tipo del valor (") +
                                        type_to_string(tv) +
                                        ") incompatible con el static field '" +
                                        fa->field_name + "' (" +
                                        type_to_string(ft_static) + ")");
                    }
                    return ft_static;
                }
            }
        }

        // chequeo previo de setter de propiedad.  Solo aplica
        // si el base resuelve a CLASS y la clase tiene un metodo
        // `set_<field_name>` (con parametro tipado).  En ese caso
        // marcamos @c property_kind=2 y devolvemos el tipo del
        // parametro como tipo del lvalue.
        const Type bt_pre = check_expr(fa->base.get());
        fa->base->result_type = bt_pre;
        if (bt_pre.kind == PrimitiveKind::CLASS) {
            auto itc = class_layouts_.find(bt_pre.struct_name);
            if (itc != class_layouts_.end()) {
                const ClassLayout &lay = itc->second;
                bool has_field = false;
                for (const auto &f : lay.fields) {
                    if (f.name == fa->field_name) {
                        has_field = true;
                        break;
                    }
                }
                for (const auto &f : lay.static_fields) {
                    if (f.name == fa->field_name) {
                        has_field = true;
                        break;
                    }
                }
                if (!has_field) {
                    const std::string setter_name =
                        std::string("set_") + fa->field_name;
                    const ClassMethodInfo *setter = nullptr;
                    for (const auto &m : lay.methods) {
                        if (m.name == setter_name && !m.is_constructor) {
                            setter = &m;
                            break;
                        }
                    }
                    if (setter) {
                        fa->property_kind = 2;
                        const Type pt = setter->param_types.empty()
                                            ? Type{}
                                            : setter->param_types.front();
                        fa->result_type = pt;
                        const Type tv = check_expr(e->value.get());
                        // Una subclase cabe en el parametro de un `set`,
                        // igual que en cualquier otro parametro.
                        if (tv.kind != PrimitiveKind::COUNT &&
                            pt.kind != PrimitiveKind::COUNT &&
                            !types_assignable(pt, tv) &&
                            !class_is_assignable(pt, tv) &&
                            !value_assignable_to_interface(pt, tv)) {
                            diags_.error(
                                e->loc,
                                std::string("tipo del valor (") +
                                    type_to_string(tv) +
                                    ") incompatible con tipo del setter (" +
                                    type_to_string(pt) + ")");
                        }
                        return pt;
                    }
                    // Si solo hay getter, el campo es read-only.
                    const std::string getter_name =
                        std::string("get_") + fa->field_name;
                    for (const auto &m : lay.methods) {
                        if (m.name == getter_name && !m.is_constructor) {
                            diags_.error(
                                e->loc,
                                "la propiedad '" + fa->field_name +
                                    "' de la clase '" + bt_pre.struct_name +
                                    "' es solo de lectura (sin setter)");
                            (void)check_expr(e->value.get());
                            return Type{};
                        }
                    }
                }
            }
        }
        // Camino normal: campo de struct/clase.  El check_field_access
        // re-evalua base() pero el lookup esta cacheado en su layout.
        Type ft = check_field_access(fa);
        fa->result_type = ft;
        // Lambda-literal a un campo fn: propagar la firma esperada al lambda
        // (params + return) ANTES de check_expr, igual que var-decl/assign.
        if (ft.kind == PrimitiveKind::FUNCTION && e->value &&
            e->value->kind == ast::NodeKind::LambdaExpr) {
            propagate_fn_type_to_lambda(
                static_cast<ast::LambdaExpr *>(e->value.get()), ft);
        }
        Type tv = check_expr(e->value.get());
        // Promocion de nombre desnudo de funcion: `o.f = doblar` cuando el
        // campo es cfn/fn -> tratar el nombre como &doblar.
        tv = maybe_promote_func_ref(e->value.get(), ft, tv);
        // null asignable a cualquier referencia CLASS (modelo
        // nullable por defecto, igual que en check_var_decl).
        const bool null_to_class_field =
            e->value && e->value->kind == ast::NodeKind::NullLitExpr &&
            ft.kind == PrimitiveKind::CLASS;
        // Tambien admitimos asignacion de instancia de subclase a
        // campo declarado como interfaz/superclase via class_is_assignable.
        // Constante numerica -> campo de tipo newtype numerico (p.ej.
        // `Fiber(f).next = 0` donde next es `fiber`): permitido sin cast, igual
        // que en var-decl/asignacion/args.
        if (numeric_const_fits_newtype(ft, tv, e->value.get())) {
            e->value->result_type = ft;
        } else if (tv.kind != PrimitiveKind::COUNT &&
                   /* Y tampoco si el desconocido es el CAMPO: que no se sepa su
                    * tipo ya se conto al mirar el acceso, y repetirlo aqui solo
                    * anade ruido derivado.  Antes esto era asimetrico -- se
                    * callaba por el valor pero no por el campo. */
                   ft.kind != PrimitiveKind::COUNT &&
                   !types_assignable(ft, tv) && !class_is_assignable(ft, tv) &&
                   !null_to_class_field) {
            diags_.error(e->loc, std::string("tipo del valor (") +
                                     type_to_string(tv) +
                                     ") incompatible con tipo del campo (" +
                                     type_to_string(ft) + ")");
        }
        // Mismatch host/VM: guardar un puntero VIRTUAL (VM, un `VirtualPtr<T>`)
        // en un campo `T*` (host) falla silenciosamente -- el campo se lee con
        // `movh` (host) pero contiene una direccion VM.  Lo rechazamos en
        // compile-time dirigiendo al tipo correcto.  (Un puntero host --
        // malloc, `&x`, etc. -- en un campo `T*` SI es valido.)
        if (ft.kind == PrimitiveKind::PTR && !ft.is_virtual &&
            tv.kind == PrimitiveKind::PTR && tv.is_virtual) {
            diags_.error(
                e->loc,
                "no se puede guardar un puntero virtual (memoria VM, un "
                "'VirtualPtr<T>') en un campo de tipo '" +
                    type_to_string(ft) +
                    "' (puntero host): el campo se leeria como host y la "
                    "direccion "
                    "es VM.  Declara el campo como 'VirtualPtr<...>' para "
                    "guardar "
                    "direcciones de memoria VM.");
        }
        // Ownership (H5): almacenar un shared<T> en un CAMPO incrementa el
        // refcount (inc-on-store en el lowering) y el destructor del contenedor
        // lo decrementa (dec-on-dtor, free-when-0).  Cada campo es un dueno mas
        // del bloque de control; el origen conserva su propia referencia.
        // Safety net (item 1): un closure CAPTURADOR asignado a un campo de un
        // STRUCT local deja el env en el STACK del scope actual.  Tainteamos el
        // struct para rechazar luego su escape (return/store).  Para CLASES el
        // env es heap-owned (lo libera el dtor), asi que no se taintea.
        if (ft.kind == PrimitiveKind::FUNCTION && !ft.fn_is_raw && fa->base &&
            fa->base->kind == ast::NodeKind::IdentExpr &&
            fa->base->result_type.kind == PrimitiveKind::STRUCT &&
            is_capturing_closure_expr(e->value.get())) {
            auto *bid = static_cast<ast::IdentExpr *>(fa->base.get());
            struct_stack_closure_taint_.insert(bid->name);
        }
        // Safety net (item 1): escape via store de un struct tainteado a un
        // campo (obj.f = s) -> la copia con el closure-en-stack sobrevive al
        // scope productor -> colgaria.  Rechazar.
        if (e->value && e->value->kind == ast::NodeKind::IdentExpr) {
            auto *vid = static_cast<ast::IdentExpr *>(e->value.get());
            if (struct_stack_closure_taint_.count(vid->name)) {
                diags_.error(
                    e->loc,
                    "el struct '" + vid->name +
                        "' tiene un closure capturador en un campo (su env "
                        "vive "
                        "en el stack) y se almacena en un campo que le "
                        "sobrevive: el env quedaria colgante.  Usa una CLASE "
                        "(env heap owned, liberado por el destructor) si el "
                        "closure debe sobrevivir al scope.");
            }
        }
        return ft;
    }
    // Caso IndexExpr: 'p[i] = v' equivale a *(p+i) = v; el tipo es
    // el del pointee y aplicamos las mismas reglas de compatibilidad
    // que para Deref.
    if (e->target->kind == ast::NodeKind::IndexExpr) {
        auto *ix = static_cast<ast::IndexExpr *>(e->target.get());
        // Operator overloading (escritura): `base[i] = v` ->
        // base.__index_set__(i, v) cuando @c base es CLASS o STRUCT que
        // declara @c __index_set__(index, value).  Lo detectamos ANTES de
        // check_index porque check_index marcaria @c __index__ (lectura) y
        // resolveria el tipo del elemento al return type del getter, no al
        // tipo del value.  Validamos los tipos de los 2 parametros y, si
        // matchea, marcamos @c ix->index_set_method y devolvemos el tipo
        // del value.  Si NO existe el dunder y @c base es CLASS/STRUCT
        // (no array/ptr/string nativo), emitimos un error claro.
        if (ix->base && !ix->is_range) {
            const Type bt = check_expr(ix->base.get());
            ix->base->result_type = bt;
            const std::vector<ClassMethodInfo> *methods = nullptr;
            bool base_is_class_or_struct = false;
            if (bt.kind == PrimitiveKind::CLASS && !bt.struct_name.empty()) {
                auto it_c = class_layouts_.find(bt.struct_name);
                if (it_c != class_layouts_.end()) {
                    methods = &it_c->second.methods;
                    base_is_class_or_struct = true;
                }
            } else if (bt.kind == PrimitiveKind::STRUCT &&
                       !bt.struct_name.empty()) {
                auto it_s = struct_layouts_.find(bt.struct_name);
                if (it_s != struct_layouts_.end()) {
                    methods = &it_s->second.methods;
                    base_is_class_or_struct = true;
                }
            }
            if (base_is_class_or_struct) {
                // Tipo del indice y del value para validar la firma.
                const Type it =
                    ix->index ? check_expr(ix->index.get()) : Type{};
                if (ix->index) ix->index->result_type = it;
                const Type vt = check_expr(e->value.get());
                e->value->result_type = vt;
                const ClassMethodInfo *setter = nullptr;
                if (methods) {
                    for (const auto &m : *methods) {
                        if (m.is_constructor || m.is_static) continue;
                        if (m.name != "__index_set__") continue;
                        if (m.param_types.size() != 2) continue;
                        if (!types_assignable(m.param_types[0], it)) continue;
                        if (!types_assignable(m.param_types[1], vt) &&
                            !class_is_assignable(m.param_types[1], vt))
                            continue;
                        setter = &m;
                        break;
                    }
                }
                if (setter) {
                    ix->index_set_method = "__index_set__";
                    ix->result_type = setter->param_types[1];
                    return setter->param_types[1];
                }
                // No hay __index_set__ aplicable: para CLASS/STRUCT no hay
                // forma clasica de escribir un slot subscript, asi que es
                // un error claro (a diferencia de array/ptr/string).
                diags_.error(
                    e->loc,
                    std::string("la clase/struct '") + bt.struct_name +
                        "' no declara `__index_set__(indice, valor)` para "
                        "soportar `base[i] = valor`");
                return Type{PrimitiveKind::VOID};
            }
        }
        const Type tt = check_index(ix);
        ix->result_type = tt;
        const Type tv = check_expr(e->value.get());
        // BugFix P1-B1: ademas de types_assignable (igualdad estricta o
        // coercion numerica), aceptar subtipado CLASS<->Interface via
        // class_is_assignable.  Tambien aceptar null literal asignable
        // a array de CLASS/STRING/PTR.
        const bool null_ok =
            (tt.kind == PrimitiveKind::CLASS ||
             tt.kind == PrimitiveKind::STRING ||
             tt.kind == PrimitiveKind::PTR) &&
            tv.kind == PrimitiveKind::PTR &&
            (!tv.pointee || tv.pointee->kind == PrimitiveKind::VOID);
        if (tt.kind != PrimitiveKind::COUNT &&
            tv.kind != PrimitiveKind::COUNT && !types_assignable(tt, tv) &&
            !class_is_assignable(tt, tv) && !null_ok) {
            diags_.error(e->loc, std::string("tipo del valor (") +
                                     type_to_string(tv) +
                                     ") incompatible con tipo del elemento (" +
                                     type_to_string(tt) + ")");
        }
        return tt;
    }
    // Caso UnaryExpr(Deref, p): '*p = v' escribe a traves del puntero.
    // Validamos que p sea un puntero a un tipo asignable y que el tipo
    // del valor encaje con el pointee.
    if (e->target->kind == ast::NodeKind::UnaryExpr) {
        auto *un = static_cast<ast::UnaryExpr *>(e->target.get());
        if (un->op == ast::UnOp::Deref) {
            const Type tt =
                check_unary(un); // valida el deref y devuelve pointee
            un->result_type = tt;
            const Type tv = check_expr(e->value.get());
            if (tt.kind != PrimitiveKind::COUNT &&
                tv.kind != PrimitiveKind::COUNT && !types_assignable(tt, tv)) {
                diags_.error(e->loc, std::string("tipo del valor (") +
                                         type_to_string(tv) +
                                         ") incompatible con tipo apuntado (" +
                                         type_to_string(tt) + ")");
            }
            return tt;
        }
    }
    if (e->target->kind != ast::NodeKind::IdentExpr) {
        diags_.error(e->loc, "el lado izquierdo de '=' debe ser un "
                             "identificador o un acceso a campo");
        (void)check_expr(e->value.get());
        return Type{};
    }
    const auto *id = static_cast<const ast::IdentExpr *>(e->target.get());
    /* asignacion a comptime var (mutable).  Si el nombre esta
     * en el stack de comptime const locales y is_mutable=true,
     * permitimos la asignacion: el comptime_eval_stmt (en bloques
     * comptime / fn bodies) la procesa.  No emitimos error aqui. */
    {
        const auto &stack = comptime_const_locals_;
        for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
            auto hit = it->find(id->name);
            if (hit != it->end()) {
                if (!hit->second.is_mutable) {
                    diags_.error(e->loc,
                                 "asignacion a 'comptime const' inmutable: '" +
                                     id->name + "'");
                    return Type{};
                }
                /* Chequear tipo del valor (compatible). */
                Type vt = check_expr(e->value.get());
                (void)vt;
                return hit->second.type;
            }
        }
    }
    size_t id_depth = 0;
    const Symbol *s = lookup_with_depth(id->name, &id_depth);
    if (!s) {
        diags_.error(e->loc, "nombre no declarado: '" + id->name + "'");
        (void)check_expr(e->value.get());
        return Type{};
    }
    if (s->kind == SymbolKind::Function) {
        diags_.error(e->loc, "no se puede asignar a una funcion");
        (void)check_expr(e->value.get());
        return Type{};
    }
    if (s->is_const) {
        diags_.error(e->loc,
                     "asignacion a variable 'const': '" + id->name + "'");
    }
    // closures: si la asignacion ocurre DENTRO de una lambda y
    // el target es una variable del scope EXTERIOR, marcar la
    // captura como mutable: el lowering la promovera a address-taken
    // (ALLOCA estable en el scope outer) y guardara su PUNTERO en
    // el env block, no su valor.  Asi reads/writes desde el body de
    // la lambda se ven correctamente fuera.  Sin esto, la asignacion
    // dentro del helper modifica solo el SSA value local y NO
    // propaga al outer.
    if (!lambda_stack_.empty()) {
        for (auto &ctx : lambda_stack_) {
            if (id_depth < ctx.outer_depth) {
                bool already = false;
                for (auto &nm : ctx.expr->captures) {
                    if (nm == id->name) {
                        already = true;
                        break;
                    }
                }
                if (!already) {
                    ctx.expr->captures.push_back(id->name);
                    ctx.expr->capture_types.push_back(s->type);
                }
                // Marcar la captura como mutable.  Si ya esta en
                // mutable_captures, no duplicamos.
                bool already_mut = false;
                for (auto &nm : ctx.expr->mutable_captures) {
                    if (nm == id->name) {
                        already_mut = true;
                        break;
                    }
                }
                if (!already_mut) {
                    ctx.expr->mutable_captures.push_back(id->name);
                }
            }
        }
    }
    // Marcar el tipo del target en el AST.
    e->target->result_type = s->type;

    // Sprint edge-bugs (2026-06-02): si el target tiene tipo FUNCTION y
    // el value es una LambdaExpr sin annotations de tipo, propagar la
    // firma esperada (params + return_type) a la lambda antes de
    // check_expr.  Sin esto, la lambda infiere VOID como return y
    // dispara 'return con valor en funcion declarada void' en su body.
    // Mismo patron que check_var_decl + check_return ya hacen.
    if (s->type.kind == PrimitiveKind::FUNCTION && e->value &&
        e->value->kind == ast::NodeKind::LambdaExpr) {
        propagate_fn_type_to_lambda(
            static_cast<ast::LambdaExpr *>(e->value.get()), s->type);
    }

    Type tv = check_expr(e->value.get());
    // Funciones de primera clase: `g_fp = nombre_funcion;` (asignacion a una
    // variable de tipo FUNCTION).  Promociona el nombre desnudo a cfn o lambda
    // segun el destino (fn_is_raw del target); el lowering emite LABEL_ADDR
    // (+ slot {fn_addr,env=0} si lambda) -- ver lower_ident.
    tv = maybe_promote_func_ref(e->value.get(), s->type, tv);
    // Compound assign sobre un tipo que sobrecarga operadores.
    if (Type tr; prepare_overloaded_compound_assign(e, s->type, tv, tr))
        return tr;
    // Vesta Embed Inc 2: `string += string` y `string += char` son legales
    // (append sugar).  El RHS char NO es assignable a string en general,
    // pero en compound `+=` sobre string lo aceptamos: el lowering native
    // appenda 1 byte (igual que str + char).  Aceptamos tambien string.
    const bool string_append_ok =
        (e->op == ast::AssignOp::AddAssign &&
         s->type.kind == PrimitiveKind::STRING &&
         (tv.kind == PrimitiveKind::STRING || tv.kind == PrimitiveKind::CHAR));
    // Newtype NUMERICO acepta una CONSTANTE numerica sin cast (como en
    // check_var_decl): `uintptr p; p = 100;` es natural (el newtype ES
    // numerico).  Solo para `=` directo y valor constante; un no-constante
    // sigue requiriendo cast explicito (seguridad del tipo nominal).
    bool num_const_to_newtype = false;
    if (s->type.nominal_id != 0 && is_numeric(s->type.kind) && e->value &&
        e->op == ast::AssignOp::Assign &&
        (is_numeric(tv.kind) || tv.kind == PrimitiveKind::CHAR)) {
        const ast::Expr *ie = e->value.get();
        const bool is_num_const =
            ie->kind == ast::NodeKind::IntLitExpr ||
            ie->kind == ast::NodeKind::FloatLitExpr ||
            ie->kind == ast::NodeKind::CharLitExpr ||
            (ie->kind == ast::NodeKind::UnaryExpr &&
             (static_cast<const ast::UnaryExpr *>(ie)->op == ast::UnOp::Neg ||
              static_cast<const ast::UnaryExpr *>(ie)->op ==
                  ast::UnOp::BitNot) &&
             static_cast<const ast::UnaryExpr *>(ie)->operand &&
             (static_cast<const ast::UnaryExpr *>(ie)->operand->kind ==
                  ast::NodeKind::IntLitExpr ||
              static_cast<const ast::UnaryExpr *>(ie)->operand->kind ==
                  ast::NodeKind::FloatLitExpr));
        if (is_num_const) {
            num_const_to_newtype = true;
            e->value->result_type = s->type; // el literal es del newtype
        }
    }
    // Newtype entero CERRADO bajo aritmetica tambien en el COMPUESTO: `a += 8`
    // es `a = a + 8`, y check_binary ya conserva el newtype en esa suma
    // (preserve_int_newtype).  Aqui el `tv` es el del OPERANDO DERECHO en
    // crudo (i64 para el literal), asi que sin esta regla `a = a + 8` compila
    // y `a += 8` no -- la misma operacion escrita de dos formas.  Se admite el
    // entero plano o el MISMO newtype, igual criterio que en el binario.
    const bool newtype_compound_ok =
        e->op != ast::AssignOp::Assign && s->type.nominal_id != 0 &&
        is_integral(s->type.kind) && is_integral(tv.kind) &&
        (tv.nominal_id == 0 || tv.nominal_id == s->type.nominal_id);
    // Una subclase cabe donde se espera la base: es el ascenso de toda la vida.
    // Aqui faltaba, y era el UNICO sitio del checker que preguntaba si un valor
    // cabe sin consultarlo -- la declaracion, el retorno, el argumento, el
    // campo y el parametro de un `set` si lo hacen.  Efecto: `A a = new B();`
    // se aceptaba y `a = new B();` no, la misma conversion resuelta de dos
    // formas segun estuviera escrita.  Pasaba desapercibido porque la
    // asignacion si miraba la mitad del criterio, la de las interfaces: con el
    // destino declarado como interfaz funcionaba, y solo fallaba con la
    // superclase.
    if (tv.kind != PrimitiveKind::COUNT && !string_append_ok &&
        !num_const_to_newtype && !newtype_compound_ok &&
        !types_assignable(s->type, tv) && !class_is_assignable(s->type, tv) &&
        !value_assignable_to_interface(s->type, tv)) {
        diags_.error(e->loc, std::string("tipo del valor (") +
                                 type_to_string(tv) +
                                 ") incompatible con tipo del destino (" +
                                 type_to_string(s->type) + ")");
    }
    return s->type;
}

/**
 * @brief Indica si @p t es un handle de overlay (una vista sobre memoria
 * ajena).
 *
 * El valor de una variable overlay son los 8 bytes de la direccion de la vista:
 * un overlay ES un puntero.  Por eso admite el mismo modelo nullable que
 * CLASS/PTR en los builtins @c isPresent / @c unwrap, en lugar de obligar al
 * usuario a comparar contra @c 0.  (No confundir con @c sizeof(T), que sobre un
 * overlay devuelve la huella de la vista para reservar su buffer de respaldo.)
 *
 * @param layouts Tabla de layouts de struct del modulo.
 * @param t       Tipo a examinar.
 * @return true si @p t es un struct marcado @c \@overlay.
 */
static bool type_is_overlay_handle(
    const std::unordered_map<std::string, StructLayout> &layouts,
    const Type &t) {
    if (t.kind != PrimitiveKind::STRUCT) return false;
    const auto it = layouts.find(t.struct_name);
    return it != layouts.end() && it->second.is_overlay;
}

Type TypeChecker::check_call(ast::CallExpr *e) {
    if (!e->callee) {
        diags_.error(e->loc, "callee nulo en llamada");
        for (auto &a : e->args)
            (void)check_expr(a.get());
        return Type{};
    }

    // Las operaciones de cadena son METODOS, no funciones libres: una sola
    // forma de escribir cada cosa.  Los nombres `str_*` siguen REGISTRADOS
    // porque el despacho de metodos los reescribe internamente
    // (`s.length()` -> `str_length(s)`), pero esa reescritura ocurre en el
    // lowering, despues del type check: aqui solo llega codigo del usuario.
    if (e->callee->kind == ast::NodeKind::IdentExpr) {
        static const char *RETIRADOS[][2] = {
            {"str_length", "length"}, {"str_bytes", "bytes"},
            {"str_cstr", "cstr"},     {"str_wstr", "wstr"},
            {"str_hash", "hash"},     {"str_intern", "intern"},
            {"str_concat", "concat"}, {"str_equals", "equals"},
        };
        const std::string &nlibre =
            static_cast<ast::IdentExpr *>(e->callee.get())->name;
        for (const auto &r : RETIRADOS) {
            if (nlibre != r[0]) continue;
            std::string sug = "s." + std::string(r[1]) + "(";
            if (!e->args.empty()) sug = "<cadena>." + std::string(r[1]) + "(";
            diags_.error(e->loc,
                         nlibre + " no existe como funcion libre: las " +
                             "operaciones de cadena son metodos.  Usa `" + sug +
                             "...)` sobre la propia cadena");
            for (auto &a : e->args)
                (void)check_expr(a.get());
            return Type{};
        }
    }

    // Overlay F1: construccion `PEB(ptr)` donde PEB es un `@overlay struct`. El
    // valor resultante ES un puntero (la vista sobre esa memoria base); el tipo
    // resultado es el propio overlay.  1 argumento: el puntero base.
    if (e->callee->kind == ast::NodeKind::IdentExpr) {
        const std::string &cn =
            static_cast<ast::IdentExpr *>(e->callee.get())->name;
        auto ito = struct_layouts_.find(cn);
        if (ito != struct_layouts_.end() && ito->second.is_overlay) {
            if (e->args.size() != 1) {
                diags_.error(e->loc, "construccion de overlay '" + cn +
                                         "' requiere 1 argumento (el puntero "
                                         "base)");
            } else {
                (void)check_expr(e->args[0].get()); // valida el puntero base.
            }
            Type rt;
            rt.kind = PrimitiveKind::STRUCT;
            rt.struct_name = cn;
            e->result_type = rt;
            return rt;
        }
    }

    // NS.2: llamada cualificada a un namespace (`mod.sq(3)` / `a.b.mk(21)`)
    // cuyo simbolo resuelto es una funcion COMPTIME o un MACRO.  Estas NO se
    // emiten como codigo runtime (se pliegan en compile-time via el
    // ComptimeRuntime), asi que reescribimos el callee al nombre mangled
    // desnudo (`mod__sq`) para que la maquinaria de bare-call comptime/macro lo
    // maneje uniformemente. `Tipo.default([{...}])` / `val.default([{...}])`:
    // crea o resetea un struct con sus valores por defecto (+ overrides
    // opcionales via un init-list).  El tipo resultado es el propio struct.
    // Funciona con templates: la forma de instancia usa el tipo ya
    // monomorphizado del receptor.
    if (e->callee->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa0 = static_cast<ast::FieldAccessExpr *>(e->callee.get());
        if (fa0->field_name == "default") {
            std::string sname;
            // Forma estatica: la base es el NOMBRE de un struct conocido.
            if (fa0->base && fa0->base->kind == ast::NodeKind::IdentExpr) {
                const std::string &bn =
                    static_cast<ast::IdentExpr *>(fa0->base.get())->name;
                if (struct_layouts_.count(bn)) sname = bn;
            }
            // Forma de instancia: la base es un valor struct (incl. templates).
            if (sname.empty()) {
                Type bt = check_expr(fa0->base.get());
                if (bt.kind == PrimitiveKind::STRUCT) sname = bt.struct_name;
            }
            if (!sname.empty()) {
                if (e->args.size() > 1) {
                    diags_.error(e->loc,
                                 "default() acepta a lo sumo un '{...}' de "
                                 "overrides");
                } else if (e->args.size() == 1 &&
                           e->args[0]->kind != ast::NodeKind::InitListExpr) {
                    diags_.error(e->loc,
                                 "el argumento de default() debe ser un "
                                 "init-list '{...}'");
                } else if (e->args.size() == 1) {
                    (void)check_expr(e->args[0].get()); // valida el init-list.
                }
                Type rt;
                rt.kind = PrimitiveKind::STRUCT;
                rt.struct_name = sname;
                e->result_type = rt;
                return rt;
            }
        }
    }

    if (e->callee->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
        std::string ns_path;
        bool got_ns = false;
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            ns_path = static_cast<ast::IdentExpr *>(fa->base.get())->name;
            got_ns = true;
        } else if (fa->base &&
                   fa->base->kind == ast::NodeKind::FieldAccessExpr) {
            got_ns = collect_dotted_path(fa->base.get(), ns_path);
        }
        if (got_ns) {
            uint32_t ns_idx = UINT32_MAX;
            auto itn = ns_idx_by_local_name_.find(ns_path);
            if (itn != ns_idx_by_local_name_.end()) {
                ns_idx = itn->second;
            } else {
                const Symbol *s = lookup(ns_path);
                if (s && s->kind == SymbolKind::Namespace) ns_idx = s->ns_index;
            }
            if (ns_idx < imported_namespaces_.size()) {
                const auto &ns = imported_namespaces_[ns_idx];
                auto its = ns.by_name.find(fa->field_name);
                if (its != ns.by_name.end()) {
                    const std::string mangled =
                        ns.symbols[its->second].mangled_label;
                    // Buscar la FunctionDecl mangled y comprobar
                    // comptime/macro.
                    const ast::FunctionDecl *fd = nullptr;
                    for (auto &d2 : mod_.decls) {
                        if (!d2 || d2->kind != ast::NodeKind::FunctionDecl)
                            continue;
                        auto *cand = static_cast<ast::FunctionDecl *>(d2.get());
                        if (cand->name == mangled) {
                            fd = cand;
                            break;
                        }
                    }
                    // Comptime/macro -> fold; generico -> monomorfizacion.  En
                    // los tres casos reescribimos el callee al nombre mangled
                    // desnudo para reusar la maquinaria de bare-call (fold /
                    // is_generic_fn_template + monomorphize_function).
                    if (fd && (fd->is_comptime || fd->is_macro ||
                               !fd->type_params.empty())) {
                        referenced_names_.insert(ns_path);
                        auto id = std::make_unique<ast::IdentExpr>();
                        id->name = mangled;
                        id->loc = fa->loc;
                        e->callee = std::move(id);
                        // fall-through: se procesa como bare `mangled(args)`.
                    }
                }
            }
        }
    }

    // Funcion generica (`id<i64>(42)` o `id(42)` con inferencia): reescribir el
    // nombre del callee al de la instancia monomorphizada (`id_i64`) para que
    // el resto de check_call y el lowering la resuelvan como una funcion
    // normal. La monomorphizacion ya ocurrio en pre_mono (caso explicito); aqui
    // solo reescribimos el nombre.  La inferencia desde los argumentos se
    // resuelve tambien aqui (los args ya tienen result_type).
    if (e->callee->kind == ast::NodeKind::IdentExpr) {
        auto *cid = static_cast<ast::IdentExpr *>(e->callee.get());
        // Nombre corto de una plantilla importada -> su label registrado.  Se
        // reescribe en el AST para que el resto de check_call y la bajada
        // trabajen con un solo nombre.
        {
            const std::string &tn = resolve_generic_fn_name(cid->name);
            if (&tn != &cid->name && generic_fn_templates_.count(tn) > 0)
                cid->name = tn;
        }
        if (is_generic_fn_template(cid->name)) {
            auto it_t = generic_fn_templates_.find(cid->name);
            auto *tmpl = static_cast<const ast::FunctionDecl *>(
                mod_.decls[it_t->second].get());
            std::vector<Type> targs;
            if (!e->type_args.empty()) {
                // Explicitos.
                for (auto &ta : e->type_args)
                    targs.push_back(resolve_type_node(ta.get()));
            } else {
                // Inferencia: por cada type_param, buscar el primer parametro
                // cuyo tipo declarado sea exactamente ese nombre (`T x`) y
                // tomar el tipo del argumento correspondiente.
                for (const auto &tp : tmpl->type_params) {
                    Type deduced{PrimitiveKind::COUNT};
                    for (size_t pi = 0;
                         pi < tmpl->params.size() && pi < e->args.size();
                         ++pi) {
                        auto *pt = tmpl->params[pi]->type.get();
                        if (pt && pt->kind == ast::NodeKind::NamedTypeNode &&
                            static_cast<ast::NamedTypeNode *>(pt)->name == tp) {
                            deduced = check_expr(e->args[pi].get());
                            break;
                        }
                    }
                    targs.push_back(deduced);
                }
            }
            bool ok = targs.size() == tmpl->type_params.size();
            for (const auto &t : targs)
                if (t.kind == PrimitiveKind::COUNT) ok = false;
            if (ok) {
                const std::string mangled =
                    monomorphize_function(cid->name, targs, e->loc);
                if (!mangled.empty()) {
                    // Si la monomorphizacion ocurrio AQUI (caso inferencia,
                    // tras collect_globals) su firma aun no esta registrada; la
                    // construimos on-demand para que la resolucion de la
                    // llamada (y el lowering) la encuentren.  En el caso
                    // explicito, pre_mono ya la monomorphizo y collect_globals
                    // la registro.
                    if (sig_by_name_.find(mangled) == sig_by_name_.end()) {
                        for (auto &d2 : mod_.decls) {
                            if (!d2 || d2->kind != ast::NodeKind::FunctionDecl)
                                continue;
                            auto *mfn =
                                static_cast<ast::FunctionDecl *>(d2.get());
                            if (mfn->name != mangled) continue;
                            FunctionSig sig;
                            sig.return_type =
                                mfn->return_type
                                    ? type_from_node(mfn->return_type.get())
                                    : Type{PrimitiveKind::VOID};
                            for (auto &p : mfn->params)
                                sig.param_types.push_back(
                                    type_from_node(p->type.get()));
                            Symbol s;
                            s.kind = SymbolKind::Function;
                            s.sig_index = (uint32_t)function_sigs_.size();
                            sig_by_name_[mangled] = s.sig_index;
                            function_sigs_.push_back(std::move(sig));
                            // La instancia es una funcion GLOBAL, asi que va al
                            // scope global y no al que este abierto ahora.  Con
                            // `declare` acababa en el scope de quien la llamo:
                            // desde `main` daba igual, pero desde el cuerpo de
                            // un metodo moria al cerrarse ese scope, y cuando
                            // el aplanado de la herencia vuelve a revisar el
                            // metodo
                            // -- ya con el nombre reescrito al de la instancia
                            // -- nadie la reconocia: "funcion no declarada:
                            // 'copia_u64'".  Una generica solo se podia llamar
                            // desde una funcion libre.
                            if (!scopes_.empty())
                                scopes_.front().emplace(mangled, s);
                            break;
                        }
                    }
                    cid->name = mangled;
                    e->type_args.clear(); // ya consumidos
                }
            } else {
                diags_.error(
                    e->loc,
                    "no se pudieron inferir los argumentos de tipo de la "
                    "funcion generica '" +
                        cid->name + "'; especificalos explicitamente: " +
                        cid->name + "<...>(...)");
            }
        }
    }

    // Function pointers: llamada INDIRECTA a traves de un valor de tipo
    // FUNCTION (una variable que guarda un puntero a funcion, el resultado
    // de un cast `(fn(...)->R) addr`, etc.).  Las llamadas DIRECTAS por
    // nombre (`foo(args)`) NO entran aqui: una IdentExpr que resuelve a una
    // funcion top-level se despacha por nombre mas abajo.
    {
        // Solo casts/index a tipo FUNCTION son punteros a funcion RAW (8
        // bytes) -> CALLIND.  Una VARIABLE de tipo FUNCTION puede ser un
        // closure (lambda con env de 16 bytes); esas se llaman por el path
        // de closure existente (CALLCLOSURE) mas abajo -- no las intercepta.
        bool indirect = false;
        Type ftype{};
        // Cualquier callee que sea una EXPRESION (no un nombre de funcion ni un
        // metodo) cuyo valor es de tipo FUNCTION es una llamada indirecta:
        //   - cast `(cfn/fn(...)) x`, index `tabla[i]`, &funcion (UnaryExpr),
        //     resultado de otra llamada `ptr_of(p)(x)`, etc.
        // Una IdentExpr (variable fn/cfn) y los nombres de funcion / metodos se
        // resuelven en sus paths dedicados mas abajo.
        if (e->callee->kind == ast::NodeKind::CastExpr ||
            e->callee->kind == ast::NodeKind::IndexExpr ||
            e->callee->kind == ast::NodeKind::UnaryExpr ||
            e->callee->kind == ast::NodeKind::CallExpr) {
            Type ct = check_expr(e->callee.get());
            if (ct.kind == PrimitiveKind::FUNCTION) {
                indirect = true;
                ftype = ct;
            }
        }
        if (indirect) {
            e->is_indirect_call = true;
            // Validar el numero de argumentos contra la firma.
            if (e->args.size() != ftype.fn_params.size()) {
                diags_.error(e->loc,
                             "llamada indirecta: numero de argumentos (" +
                                 std::to_string(e->args.size()) +
                                 ") distinto de la firma (" +
                                 std::to_string(ftype.fn_params.size()) + ")");
            }
            for (size_t i = 0; i < e->args.size(); ++i) {
                Type at = check_expr(e->args[i].get());
                if (i < ftype.fn_params.size() &&
                    !types_assignable(ftype.fn_params[i], at)) {
                    diags_.warning(e->loc,
                                   "llamada indirecta: argumento " +
                                       std::to_string(i + 1) +
                                       " de tipo distinto al de la firma");
                }
            }
            Type ret =
                ftype.pointee ? *ftype.pointee : Type{PrimitiveKind::VOID};
            e->result_type = ret;
            return ret;
        }
    }

    // Metodos OO sobre tipo string.  Si callee es
    // FieldAccess con base STRING (NO un enum identifier) y nombre
    // de metodo conocido, devolvemos el tipo del builtin equivalente.
    // CRITICO: el check enum constructor `Color.Red(...)` esta mas
    // abajo y necesita la base intacta.  Skip si la base es un
    // IdentExpr que nombra un enum.
    if (e->callee->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
        //  NS.1b: namespace MULTI-segmento `ui.widgets.button(args)` -- la
        // base es una cadena de field-access (`ui.widgets`).  Colapsar en path
        // punteado y resolver el namespace ANTES de check_expr(base) (que
        // trataria `ui` como variable indefinida).  El caso single-segment
        // (`ui.button()`) lo cubre el bloque IdentExpr de abajo.
        if (fa->base && fa->base->kind == ast::NodeKind::FieldAccessExpr) {
            std::string ns_path;
            if (collect_dotted_path(fa->base.get(), ns_path)) {
                uint32_t ns_idx_c = UINT32_MAX;
                auto itc = ns_idx_by_local_name_.find(ns_path);
                if (itc != ns_idx_by_local_name_.end()) {
                    ns_idx_c = itc->second;
                } else {
                    const Symbol *s = lookup(ns_path);
                    if (s && s->kind == SymbolKind::Namespace)
                        ns_idx_c = s->ns_index;
                }
                if (ns_idx_c < imported_namespaces_.size()) {
                    const auto &ns = imported_namespaces_[ns_idx_c];
                    auto its = ns.by_name.find(fa->field_name);
                    if (its != ns.by_name.end()) {
                        referenced_names_.insert(ns_path);
                        const auto &sym = ns.symbols[its->second];
                        const FunctionSig *real_sig =
                            sym.mangled_label.empty()
                                ? nullptr
                                : function_sig_by_name(sym.mangled_label);
                        const FunctionSig *use_sig =
                            real_sig ? real_sig : &sym.sig;
                        if (e->args.size() != use_sig->param_types.size()) {
                            diags_.error(e->loc,
                                         "llamada a '" + ns_path + "." +
                                             fa->field_name +
                                             "': se esperaban " +
                                             std::to_string(
                                                 use_sig->param_types.size()) +
                                             " args, recibidos " +
                                             std::to_string(e->args.size()));
                        }
                        for (auto &a : e->args)
                            (void)check_expr(a.get());
                        fa->property_kind = 4;
                        fa->ns_index = ns_idx_c;
                        fa->result_type = Type::make_function(
                            use_sig->param_types, use_sig->return_type);
                        e->result_type = use_sig->return_type;
                        return use_sig->return_type;
                    }
                }
            }
        }
        //  M.7: namespace.function(args) -- el base resuelve a
        // Symbol::Namespace y el field es una funcion del namespace.
        // Detectar ANTES de check_expr(base) para que no se trate
        // como variable indefinida.
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *idb = static_cast<ast::IdentExpr *>(fa->base.get());
            const Symbol *ns_sym = lookup(idb->name);
            uint32_t ns_idx_b = UINT32_MAX;
            if (ns_sym && ns_sym->kind == SymbolKind::Namespace) {
                ns_idx_b = ns_sym->ns_index;
            } else if (!ns_sym) {
                // NS short-form: la base no es un simbolo (ni funcion ni
                // variable) pero SI un namespace registrado (incluido el alias
                // del ultimo segmento `shapes` -> `org.geo.shapes`).  Guardado
                // por `!ns_sym` para no robar un nombre que ya sea funcion.
                auto itb = ns_idx_by_local_name_.find(idb->name);
                if (itb != ns_idx_by_local_name_.end()) ns_idx_b = itb->second;
            }
            if (ns_idx_b != UINT32_MAX) {
                // L.26 fix (2026-06-04): marcar el namespace como
                // referenciado para que el linter de "import no se
                // usa" no genere falsos positivos en namespace calls
                // (`ns.fn()`).  Sin esto, los warnings spurios
                // aparecen aunque el usuario claramente usa el
                // import via call.  Mismo patron que check_field_access
                // ya hacia para namespace field access.
                referenced_names_.insert(idb->name);
                if (ns_idx_b < imported_namespaces_.size()) {
                    const auto &ns = imported_namespaces_[ns_idx_b];
                    auto its = ns.by_name.find(fa->field_name);
                    if (its == ns.by_name.end()) {
                        diags_.error(e->loc,
                                     "el namespace '" + idb->name +
                                         "' no tiene un simbolo llamado '" +
                                         fa->field_name + "'");
                        for (auto &a : e->args)
                            (void)check_expr(a.get());
                        return Type{};
                    }
                    const auto &sym = ns.symbols[its->second];
                    //  M.7.c: si la sig esta vacia (namespace
                    // inline; las firmas se rellenan en check_function),
                    // buscamos la sig real via function_sig_by_name
                    // usando el mangled_label.  Para namespaces
                    // cross-module (M7.a), sym.sig ya esta lleno.
                    const FunctionSig *real_sig = nullptr;
                    if (!sym.mangled_label.empty()) {
                        real_sig = function_sig_by_name(sym.mangled_label);
                    }
                    const FunctionSig *use_sig = real_sig ? real_sig : &sym.sig;
                    // Validar aridad.
                    if (e->args.size() != use_sig->param_types.size()) {
                        diags_.error(
                            e->loc,
                            "llamada a '" + idb->name + "." + fa->field_name +
                                "': se esperaban " +
                                std::to_string(use_sig->param_types.size()) +
                                " args, recibidos " +
                                std::to_string(e->args.size()));
                    }
                    // Chequear cada arg (sin validacion estricta de
                    // tipo en MVP; M7.x anyadira coerce + cast checks).
                    for (auto &a : e->args)
                        (void)check_expr(a.get());
                    // Marcar el FieldAccess para que el lowering lo
                    // reconozca como namespace call y emita CALLVM al
                    // mangled_label.
                    fa->property_kind = 4;
                    fa->ns_index = ns_idx_b; // M.7
                    fa->result_type = Type::make_function(use_sig->param_types,
                                                          use_sig->return_type);
                    e->result_type = use_sig->return_type;
                    return use_sig->return_type;
                }
            }
            auto it_cls_s = class_layouts_.find(idb->name);
            if (it_cls_s != class_layouts_.end() &&
                lookup(idb->name) == nullptr) {
                const ClassMethodInfo *smtd = find_static_method(
                    it_cls_s->second.methods, fa->field_name);
                if (smtd)
                    return check_static_method_call(
                        e, fa, *smtd, idb->name + "." + fa->field_name,
                        /*marca=*/4);
            }
            // Gemelo para STRUCT: `StructName.staticMethod(...)` (factoria sin
            // this, p.ej. `u128.zero()`).  Mismo criterio que la clase (es un
            // nombre de tipo, no una variable: `lookup(...)==nullptr`) + busca
            // el metodo `is_static` en el StructLayout.  Comparte
            // property_kind=4; el lowering hace fallback a struct_layouts para
            // el CALL sin `this`.
            auto it_str_s = struct_layouts_.find(idb->name);
            if (it_str_s != struct_layouts_.end() &&
                lookup(idb->name) == nullptr) {
                /* La marca es 7 y no 4 porque al bajar toma otro camino: el
                 * del struct tiene que atender una factoria que devuelve el
                 * propio struct POR VALOR, que viaja por el hueco que presta
                 * quien llama. */
                const ClassMethodInfo *smtd = find_static_method(
                    it_str_s->second.methods, fa->field_name);
                if (smtd)
                    return check_static_method_call(
                        e, fa, *smtd, idb->name + "." + fa->field_name,
                        /*marca=*/7);
            }
        }
        bool base_is_enum_id = false;
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *id_b = static_cast<ast::IdentExpr *>(fa->base.get());
            if (find_enum_layout(id_b->name) != nullptr) {
                base_is_enum_id = true;
            }
            // L2.3: enums genericos templates.
            if (is_generic_enum_template(id_b->name)) {
                base_is_enum_id = true;
            }
        }
        if (!base_is_enum_id) {
            Type base_t = check_expr(fa->base.get());
            // Un literal en posicion de RECEPTOR es una cadena: `"x".length()`.
            // check_expr lo tipa PTR porque en la mayoria de contextos un
            // literal es el buffer crudo de static_data; el `.metodo()` obliga
            // a verlo como `string`, igual que la promocion que ya ocurre al
            // pasarlo a un parametro `string`.
            if (fa->base->kind == ast::NodeKind::StringLitExpr &&
                !static_cast<ast::StringLitExpr *>(fa->base.get())
                     ->is_interpolated())
                base_t = Type{PrimitiveKind::STRING};
            fa->base->result_type = base_t;
            if (base_t.kind == PrimitiveKind::STRING) {
                static const struct {
                    const char *m;
                    PrimitiveKind ret;
                } MAP[] = {
                    {"length", PrimitiveKind::I64},
                    {"bytes", PrimitiveKind::I64},
                    {"cstr", PrimitiveKind::PTR},
                    {"wstr", PrimitiveKind::PTR},
                    {"hash", PrimitiveKind::U64},
                    {"intern", PrimitiveKind::STRING},
                    {"equals", PrimitiveKind::BOOL},
                    {"concat", PrimitiveKind::STRING},
                };
                for (const auto &m : MAP) {
                    if (fa->field_name == m.m) {
                        for (auto &a : e->args)
                            (void)check_expr(a.get());
                        return Type{m.ret};
                    }
                }
            }
            // dispatch de metodos de coleccion primitiva.  Si el
            // base es uno de los tipos coleccion (ARRAYLIST/HASHMAP/etc),
            // buscamos el metodo en la tabla COL_METHODS y devolvemos
            // su tipo de retorno.  Validamos aridad simple; tipos de
            // arg los chequeamos via check_expr(a) sin cast (todos los
            // args nativos son uint64_t en la calling convention CALLN).
            if (is_col_kind(base_t.kind)) {
                const ColMethod *cm =
                    find_col_method(base_t.kind, fa->field_name);
                if (cm) {
                    if ((int)e->args.size() != cm->n_args) {
                        diags_.error(e->loc,
                                     std::string("'") +
                                         primitive_name(base_t.kind) + "." +
                                         cm->vx_name + "' espera " +
                                         std::to_string(cm->n_args) +
                                         " arg(s), recibidos " +
                                         std::to_string(e->args.size()));
                    }
                    for (auto &a : e->args)
                        (void)check_expr(a.get());
                    return Type{cm->ret};
                }
                diags_.error(e->loc, std::string("metodo desconocido '") +
                                         fa->field_name + "' sobre tipo " +
                                         primitive_name(base_t.kind));
                for (auto &a : e->args)
                    (void)check_expr(a.get());
                return Type{};
            }
        }
    }

    // ------------------------------------------------------------
    // Reflexion OO: dispatch para `cls.getMethod`, `m.invoke`, etc.
    // Se activa cuando el base es un IdentExpr resolviendo a un
    // Symbol con `reflection_alias` no vacio (declarado como
    // `Class cls`, `Method m`, `Field f`, `Object o`), o cuando el
    // base es el identifier literal "Class"/"Method"/"Field"
    // (forma estatica `Class.forName`).  Cada metodo se desazucara
    // a su builtin standalone equivalente (forName, getMethod, etc.)
    // sin cambios en el runtime: solo conveniencia sintactica.
    // ------------------------------------------------------------
    if (e->callee->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *idb = static_cast<ast::IdentExpr *>(fa->base.get());
            std::string
                alias_kind; // "Class" | "Method" | "Field" | "Object" o vacio
            bool is_static_form = false;
            // Forma estatica: literal "Class"/"Method"/etc. como base.
            if (idb->name == "Class" || idb->name == "Method" ||
                idb->name == "Field" || idb->name == "Object") {
                if (lookup(idb->name) == nullptr) {
                    // No es una variable real con ese nombre; es la
                    // forma estatica.  El base no se evaluara.
                    alias_kind = idb->name;
                    is_static_form = true;
                }
            }
            // Forma instancia: variable cuyo Symbol tiene reflection_alias.
            if (!is_static_form) {
                if (const Symbol *sym = lookup(idb->name)) {
                    if (!sym->reflection_alias.empty()) {
                        alias_kind = sym->reflection_alias;
                    }
                }
            }
            if (!alias_kind.empty()) {
                // Mapeo de metodo OO -> builtin standalone equivalente
                // y validacion de aridad.  El lowering hace la reescritura
                // efectiva (CallExpr al builtin con base prepended).
                struct DispatchEntry {
                    const char *alias;
                    const char *method;
                    const char *builtin;
                    int min_args;
                    int max_args; // -1 = variadico
                    PrimitiveKind ret;
                    bool needs_self; // true: prepend base como primer arg
                };
                // Tabla declarativa.  args contados sin contar self.
                static const DispatchEntry MAP[] = {
                    // Estatico: Class.forName(name)
                    {"Class", "forName", "forName", 1, 1, PrimitiveKind::I64,
                     false},
                    // Instancia: Class -> getMethod / getField / newInstance /
                    // getMethods
                    {"Class", "getMethod", "getMethod", 1, 1,
                     PrimitiveKind::I64, true},
                    {"Class", "getField", "getField", 1, 1, PrimitiveKind::I64,
                     true},
                    {"Class", "newInstance", "newInstance", 0, 0,
                     PrimitiveKind::I64, true},
                    {"Class", "getMethods", "getMethods", 0, 0,
                     PrimitiveKind::I64, true},
                    // Instancia: Method -> invoke
                    {"Method", "invoke", "invoke", 1, -1, PrimitiveKind::I64,
                     true},
                    // Instancia: Object -> getClass (alias del builtin)
                    {"Object", "getClass", "getClass", 0, 0, PrimitiveKind::I64,
                     true},
                };
                const DispatchEntry *match = nullptr;
                for (const auto &e0 : MAP) {
                    if (alias_kind == e0.alias && fa->field_name == e0.method) {
                        // Filtrar por static/instance segun forma.
                        if (is_static_form && !e0.needs_self) {
                            match = &e0;
                            break;
                        }
                        if (!is_static_form && e0.needs_self) {
                            match = &e0;
                            break;
                        }
                    }
                }
                if (match) {
                    const int n = static_cast<int>(e->args.size());
                    if (n < match->min_args ||
                        (match->max_args >= 0 && n > match->max_args)) {
                        diags_.error(e->loc, std::string(alias_kind) + "." +
                                                 match->method +
                                                 ": numero de argumentos "
                                                 "incorrecto (recibidos " +
                                                 std::to_string(n) + ")");
                    }
                    // Validacion de tipos minima: solo evaluamos los args
                    // para que tengan result_type asignado (el lowering
                    // hara la coercion final).
                    for (auto &a : e->args)
                        (void)check_expr(a.get());
                    // Marca al callee con dispatch_kind para que el
                    // lowering lo reconozca y emita la builtin.
                    // Usamos property_kind como vehiculo (ya existe en
                    // FieldAccessExpr para getter/setter de propiedad).
                    // Codigos:
                    //   100 = forName        (estatico)
                    //   101 = getMethod
                    //   102 = getField
                    //   103 = newInstance
                    //   104 = getMethods
                    //   105 = invoke
                    //   106 = getClass
                    if (match->method == std::string("forName"))
                        fa->property_kind = 100;
                    else if (match->method == std::string("getMethod"))
                        fa->property_kind = 101;
                    else if (match->method == std::string("getField"))
                        fa->property_kind = 102;
                    else if (match->method == std::string("newInstance"))
                        fa->property_kind = 103;
                    else if (match->method == std::string("getMethods"))
                        fa->property_kind = 104;
                    else if (match->method == std::string("invoke"))
                        fa->property_kind = 105;
                    else if (match->method == std::string("getClass"))
                        fa->property_kind = 106;
                    const Type rt{match->ret};
                    e->result_type = rt;
                    return rt;
                }
            }
        }
    }

    // -------------------------------------------------------------
    // ADTs: si el callee es un FieldAccessExpr con base que es
    // un IDENTIFIER nombrando un enum (e.g. `Color.Red(42)`), lo
    // tratamos como CONSTRUCTOR de variante en lugar de llamada a
    // metodo.  Validamos:
    //   - El identifier de la izquierda nombra un enum registrado.
    //   - El identifier de la derecha nombra una variante existente.
    //   - El numero de argumentos coincide con el payload de la
    //     variante.
    // El tipo resultado es @c Type{STRUCT, "Color"} (mismo trick
    // que para enums "estaticos": reusamos kind=STRUCT con el
    // struct_name del enum).
    // -------------------------------------------------------------
    if (e->callee->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
        // M.L7 ext: enum cross-module via namespace qualified.
        // `command.Command.InsertChar(65)` -- aqui `fa->base` es
        // FieldAccessExpr ("command.Command"), no IdentExpr.  Si su
        // result_type es STRUCT cuyo nombre coincide con un enum
        // registrado, lo tratamos como constructor de variante.
        if (fa->base && fa->base->kind == ast::NodeKind::FieldAccessExpr) {
            // Forzar el check del base para que poblee result_type.
            Type bt = check_expr(fa->base.get());
            if (bt.kind == PrimitiveKind::STRUCT && !bt.struct_name.empty()) {
                const EnumLayout *lay_bt = find_enum_layout(bt.struct_name);
                if (lay_bt != nullptr) {
                    const EnumLayout &elay = *lay_bt;
                    const EnumVariantInfo *var = nullptr;
                    for (const auto &v : elay.variants) {
                        if (v.name == fa->field_name) {
                            var = &v;
                            break;
                        }
                    }
                    if (!var) {
                        diags_.error(e->loc,
                                     "variante desconocida '" + fa->field_name +
                                         "' en enum '" + elay.name + "'");
                        for (auto &a : e->args)
                            (void)check_expr(a.get());
                        return Type{};
                    }
                    return check_variant_ctor(e, fa, *var, elay.name);
                }
            }
        }
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *base_id = static_cast<ast::IdentExpr *>(fa->base.get());
            // L2.3: enum generico template `Maybe.Some(42)` -- inferir
            // monomorph desde args si es posible, o usar expected_enum
            // stack desde el contexto.
            if (is_generic_enum_template(base_id->name)) {
                // Localizar template AST + variante.
                auto it_tmpl = generic_enum_templates_.find(base_id->name);
                const ast::EnumDecl *tmpl =
                    (it_tmpl != generic_enum_templates_.end())
                        ? static_cast<const ast::EnumDecl *>(
                              mod_.decls[it_tmpl->second].get())
                        : nullptr;
                const ast::EnumVariantDecl *tvar = nullptr;
                if (tmpl) {
                    for (const auto &v : tmpl->variants) {
                        if (v.name == fa->field_name) {
                            tvar = &v;
                            break;
                        }
                    }
                }
                // Inferir args concretos por type_param: para cada
                // type_param T, buscar la primera variante payload que
                // usa T como NamedTypeNode y leer el arg correspondiente
                // del call (su tipo concreto).
                std::vector<Type> infer_args(
                    tmpl ? tmpl->type_params.size() : 0, Type{});
                bool fully_inferred = (tmpl && !tmpl->type_params.empty());
                if (tmpl && tvar) {
                    const size_t n =
                        std::min(e->args.size(), tvar->field_types.size());
                    std::vector<Type> arg_types(n);
                    for (size_t i = 0; i < n; ++i)
                        arg_types[i] = check_expr(e->args[i].get());
                    for (size_t i = n; i < e->args.size(); ++i)
                        (void)check_expr(e->args[i].get());
                    for (size_t tpi = 0; tpi < tmpl->type_params.size();
                         ++tpi) {
                        const std::string &tp_name = tmpl->type_params[tpi];
                        for (size_t pi = 0;
                             pi < tvar->field_types.size() && pi < n; ++pi) {
                            const ast::TypeNode *ft =
                                tvar->field_types[pi].get();
                            if (ft &&
                                ft->kind == ast::NodeKind::NamedTypeNode) {
                                const auto *nt =
                                    static_cast<const ast::NamedTypeNode *>(ft);
                                if (nt->name == tp_name) {
                                    infer_args[tpi] = arg_types[pi];
                                    break;
                                }
                            }
                        }
                        if (infer_args[tpi].kind == PrimitiveKind::COUNT ||
                            infer_args[tpi].kind == PrimitiveKind::VOID) {
                            fully_inferred = false;
                        }
                    }
                } else {
                    for (auto &a : e->args)
                        (void)check_expr(a.get());
                }

                std::string mangled;
                // Prefer expected (LHS context) sobre inferencia desde
                // args, porque literales como `42` defaultean a i64
                // pero el LHS puede pedir i32.
                if (const std::string *expected =
                        expected_enum_mangled(base_id->name)) {
                    mangled = *expected;
                } else if (fully_inferred) {
                    mangled =
                        monomorphize_enum(base_id->name, infer_args, e->loc);
                }
                if (mangled.empty()) {
                    diags_.error(e->loc, "no se puede inferir args de tipo "
                                         "para enum generico '" +
                                             base_id->name + "'");
                    return Type{};
                }
                auto it_mono = enum_layouts_.find(mangled);
                if (it_mono == enum_layouts_.end()) {
                    // Trigger monomorphize y pase 2 re-run no es viable aqui;
                    // forzar el layout via run_pass2_for_decl no esta expuesto.
                    // Como fallback, reportar y salir.
                    diags_.error(e->loc, "enum generico '" + mangled +
                                             "' no esta registrado");
                    return Type{};
                }
                const EnumLayout &elay = it_mono->second;
                const EnumVariantInfo *var = nullptr;
                for (const auto &v : elay.variants) {
                    if (v.name == fa->field_name) {
                        var = &v;
                        break;
                    }
                }
                if (!var) {
                    diags_.error(e->loc, "variante desconocida '" +
                                             fa->field_name + "' en enum '" +
                                             elay.name + "'");
                    return Type{};
                }
                fa->property_kind = 99;
                Type rt{PrimitiveKind::STRUCT, elay.name};
                fa->result_type = rt;
                // Reescribir el base_id al mangled para que el lowering
                // dispatche al enum concreto.
                base_id->name = elay.name;
                return rt;
            }
            // Un solo sitio resuelve que enum es este nombre.
            const EnumLayout *lay_ce = find_enum_layout(base_id->name);
            if (lay_ce != nullptr) {
                const EnumLayout &elay = *lay_ce;
                const EnumVariantInfo *var = nullptr;
                for (const auto &v : elay.variants) {
                    if (v.name == fa->field_name) {
                        var = &v;
                        break;
                    }
                }
                if (!var) {
                    diags_.error(e->loc, "variante desconocida '" +
                                             fa->field_name + "' en enum '" +
                                             elay.name + "'");
                    for (auto &a : e->args)
                        (void)check_expr(a.get());
                    return Type{};
                }
                return check_variant_ctor(e, fa, *var, elay.name);
            }
        }
    }

    // Caso A: obj.method(args) - callee es FieldAccessExpr.  El base
    // debe ser de tipo CLASS (instancia con vtable) o STRUCT (value
    // type con dispatch estatico).  Los metodos de struct se desugaran
    // a funciones libres tomando @c Struct* como primer argumento; el
    // lowering emite CALL directo (sin vtable).
    if (e->callee->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
        Type bt = check_expr(fa->base.get());
        // @Virtual: `ptr.metodo()` sobre un `Struct*` -> auto-deref al struct
        // apuntado.  El metodo se despacha sobre el objeto (dispatch dinamico
        // por vtable si es @Virtual).  Habilita el polimorfismo `Base* p =
        // &derivado; p.metodo()`.
        if (bt.kind == PrimitiveKind::PTR && bt.pointee &&
            bt.pointee->kind == PrimitiveKind::STRUCT)
            bt = *bt.pointee;
        // Helper: `o.f(args)` donde f es un CAMPO de tipo funcion (cfn/fn) ->
        // llamada INDIRECTA a traves del puntero a funcion guardado en el campo
        // (CALLIND), NO un metodo.  Esto distingue un METODO de struct/clase
        // (dispatch directo, inline-able, eficiente) de un MIEMBRO puntero a
        // funcion estilo C.  Marca is_indirect_call y valida la firma; el
        // lowering bajara `o.f` al valor del campo y emitira CALLIND.
        auto funcptr_field_call = [&](const Type &ftype) -> Type {
            e->is_indirect_call = true;
            fa->result_type = ftype;
            if (e->args.size() != ftype.fn_params.size())
                diags_.error(e->loc,
                             "llamada a campo-funcion '" + fa->field_name +
                                 "': numero de argumentos (" +
                                 std::to_string(e->args.size()) +
                                 ") distinto de la firma (" +
                                 std::to_string(ftype.fn_params.size()) + ")");
            const size_t n = std::min(e->args.size(), ftype.fn_params.size());
            for (size_t i = 0; i < n; ++i) {
                const Type ta = check_expr(e->args[i].get());
                if (ta.kind != PrimitiveKind::COUNT &&
                    !types_assignable(ftype.fn_params[i], ta))
                    diags_.warning(e->args[i]->loc,
                                   "argumento " + std::to_string(i + 1) +
                                       " del campo-funcion '" + fa->field_name +
                                       "': tipo incompatible");
            }
            for (size_t i = n; i < e->args.size(); ++i)
                (void)check_expr(e->args[i].get());
            return ftype.pointee ? *ftype.pointee : Type{};
        };
        // Campo de tipo funcion (cfn O fn): `o.f(args)` baja a llamada
        // indirecta.  El lowering elige CALLIND (cfn raw, 8 bytes) o
        // CALLCLOSURE (fn lambda, fat-pointer de 16 bytes con env) segun
        // fn_is_raw.  NOTA: un campo lambda guarda el PUNTERO a un slot que
        // vive en stack -> el programador es responsable del lifetime.
        // #4 metodos genericos: `obj.metodo<U>(args)` (explicito) o
        // `obj.metodo(args)` con U inferido.  Si lo es, monomorphiza +
        // reescribe fa->field_name al concreto (`metodo_<U>`) y deja que
        // la resolucion normal de abajo lo encuentre ya en el layout.
        (void)try_monomorphize_method_call(e, fa, bt);

        // STRUCT: resolver el metodo en el layout del struct (dispatch
        // estatico).  Si no es un metodo del struct, error claro.
        if (bt.kind == PrimitiveKind::STRUCT) {
            auto it_s = struct_layouts_.find(bt.struct_name);
            if (it_s == struct_layouts_.end()) {
                diags_.error(e->loc,
                             "struct desconocido: '" + bt.struct_name + "'");
                for (auto &a : e->args)
                    (void)check_expr(a.get());
                return Type{};
            }
            const StructLayout &slay = it_s->second;
            const ClassMethodInfo *smtd =
                find_instance_method(slay.methods, fa->field_name);
            if (!smtd)
                return report_method_missing(e, fa, slay.fields, bt.struct_name,
                                             "el struct", funcptr_field_call);
            check_method_args(e, *smtd, fa->field_name);
            fa->result_type = smtd->return_type;
            return smtd->return_type;
        }
        if (bt.kind != PrimitiveKind::CLASS) {
            diags_.error(e->loc, "invocacion de metodo sobre tipo no-clase: " +
                                     type_to_string(bt));
            for (auto &a : e->args)
                (void)check_expr(a.get());
            return Type{};
        }
        auto it = class_layouts_.find(bt.struct_name);
        if (it == class_layouts_.end()) {
            diags_.error(e->loc, "clase desconocida: '" + bt.struct_name + "'");
            for (auto &a : e->args)
                (void)check_expr(a.get());
            return Type{};
        }
        const ClassLayout &cls = it->second;
        const ClassMethodInfo *mtd =
            find_instance_method(cls.methods, fa->field_name);
        if (!mtd)
            return report_method_missing(e, fa, cls.fields, bt.struct_name,
                                         "la clase", funcptr_field_call);
        // Enforcement de visibilidad en metodos (private = solo dentro
        // de la misma clase).  Buscamos el ClassMethodDecl original
        // en el AST para consultar el flag access.
        for (auto &d : mod_.decls) {
            if (!d || d->kind != ast::NodeKind::ClassDecl) continue;
            auto *cdp = static_cast<const ast::ClassDecl *>(d.get());
            if (cdp->name != bt.struct_name) continue;
            for (auto &mm : cdp->methods) {
                if (mm && !mm->is_constructor && mm->name == fa->field_name) {
                    if (mm->access == 1 /*private*/
                        && current_class_ != bt.struct_name) {
                        diags_.error(
                            e->loc,
                            "metodo privado '" + fa->field_name +
                                "' de la clase '" + bt.struct_name +
                                "' no es accesible desde fuera de la clase");
                    }
                    break;
                }
            }
            break;
        }
        check_method_args(e, *mtd, fa->field_name);
        // Anotar el tipo del FieldAccessExpr como el tipo de retorno
        // (util para que el lowering tenga el target_type listo).
        fa->result_type = mtd->return_type;
        return mtd->return_type;
    }

    // Caso B: llamada normal a funcion top-level.
    if (e->callee->kind != ast::NodeKind::IdentExpr) {
        diags_.error(e->loc, "se esperaba un nombre de funcion como callee");
        for (auto &a : e->args)
            (void)check_expr(a.get());
        return Type{};
    }
    /* A.43.13: aliases globales para builtins comptime.  Reduce
     * verbosidad permitiendo escribir `concat(a, b)` en vez de
     * `comptime_concat(a, b)`, `replace(s, n, v)` en vez de
     * `comptime_replace(...)`, etc.  Los aliases mutan el AST
     * in-place (renombran el IdentExpr a su nombre canonico) asi
     * todas las branches downstream que comparan @c id->name siguen
     * funcionando sin cambios.  Solo se aplica a CallExpr; no
     * afecta a IdentExpr en otras posiciones.
     *
     * Nota: NO aliasamos `print` (colisiona con runtime print) ni
     * nombres ya usados por la stdlib.  El usuario que quiera ser
     * explicito puede seguir escribiendo `comptime_*`. */
    {
        auto *id_mut = static_cast<ast::IdentExpr *>(e->callee.get());
        static const std::pair<const char *, const char *> ALIASES[] = {
            {"concat", "comptime_concat"},
            {"streq", "comptime_streq"},
            {"strlen", "comptime_strlen"},
            {"chr", "comptime_chr"},
            {"ord", "comptime_ord"},
            {"substr", "comptime_substr"},
            {"repeat", "comptime_repeat"},
            {"to_str", "comptime_to_str"},
            {"replace", "comptime_replace"},
            {"contains", "comptime_contains"},
            {"emit_expr", "comptime_emit_expr"},
            {"compile", "comptime_compile"},
            {"ct_print", "comptime_print"},
        };
        for (const auto &a : ALIASES) {
            if (id_mut->name == a.first) {
                id_mut->name = a.second;
                break;
            }
        }
    }
    const auto *id = static_cast<const ast::IdentExpr *>(e->callee.get());

    // -----------------------------------------------------------------
    // Overlay: `offsetof(v.campo)` / `in_bounds(v.campo, len)` -- forma
    // VALOR (runtime), distinta del `offsetof<T>("campo")` COMPTIME de
    // mas abajo (esa lleva type args).  Sin type args; el primer arg es
    // un acceso a un campo/elemento de una vista @overlay:
    //   offsetof(v.campo)      -> u64  (offset resuelto del campo dentro
    //                                    de la vista, sin leer memoria)
    //   in_bounds(v.campo,len) -> bool (offsetof(v.campo)+sizeof(campo)<=len)
    // Azucar legible para que el usuario componga sus propias
    // comprobaciones sin aritmetica de punteros a mano.  No son keywords
    // de la gramatica: se reconocen aqui por nombre + forma del arg.
    // -----------------------------------------------------------------
    // F4: `parent<T>()` dentro de un resolver `@offset { }` -> la vista RAIZ,
    // de tipo overlay T.  Marca que el resolver usa parent (para enhebrar
    // `root`).
    if (id->name == "parent" && e->type_args.size() == 1 && e->args.empty()) {
        const Type t = type_from_node(e->type_args[0].get());
        if (t.kind != PrimitiveKind::STRUCT) {
            diags_.error(e->loc, "parent<T>(): T debe ser un tipo @overlay");
        }
        if (overlay_resolver_active_) {
            overlay_resolver_used_parent_ = true;
            overlay_resolver_parent_type_ = t.struct_name;
        } else {
            diags_.error(e->loc, "parent<T>() solo es valido dentro de un "
                                 "resolver @offset { } de un overlay");
        }
        e->result_type = t;
        return t;
    }

    // Overlay: `extent(v)` -> u64.  Span TOTAL en runtime del layout declarado
    // de la vista v (max(fin de campo) - base), con los datos de la instancia
    // (counts dinamicos, resolvers).  Cubre escalares + arrays de stride con
    // count; NO cubre arrays sin count ni @element (documentado).
    if (id->name == "extent" && e->type_args.empty() && e->args.size() == 1) {
        const Type vt = check_expr(e->args[0].get());
        if (vt.kind == PrimitiveKind::STRUCT) {
            auto it = struct_layouts_.find(vt.struct_name);
            if (it != struct_layouts_.end() && it->second.is_overlay) {
                e->result_type = Type{PrimitiveKind::U64};
                return e->result_type;
            }
        }
        diags_.error(e->loc, "extent(v): v debe ser una vista @overlay");
        e->result_type = Type{PrimitiveKind::U64};
        return e->result_type;
    }

    if (e->type_args.empty() && !e->args.empty() &&
        (id->name == "offsetof" || id->name == "in_bounds")) {
        // Predicado: el arg accede a un campo/elemento de un overlay.
        auto is_overlay_access = [&](const ast::Expr *x) -> bool {
            while (x != nullptr) {
                if (x->kind == ast::NodeKind::FieldAccessExpr) {
                    const auto *fa =
                        static_cast<const ast::FieldAccessExpr *>(x);
                    const Type &bt = fa->base->result_type;
                    if (bt.kind == PrimitiveKind::STRUCT) {
                        auto it = struct_layouts_.find(bt.struct_name);
                        if (it != struct_layouts_.end() &&
                            it->second.is_overlay)
                            return true;
                    }
                    x = fa->base.get();
                    continue;
                }
                if (x->kind == ast::NodeKind::IndexExpr) {
                    const auto *ix = static_cast<const ast::IndexExpr *>(x);
                    if (ix->is_overlay_array) return true;
                    x = ix->base.get();
                    continue;
                }
                return false;
            }
            return false;
        };
        // Poblar result_type de toda la cadena del acceso.
        (void)check_expr(e->args[0].get());
        if (is_overlay_access(e->args[0].get())) {
            const bool is_ib = (id->name == "in_bounds");
            if (is_ib) {
                if (e->args.size() != 2) {
                    diags_.error(
                        e->loc,
                        "in_bounds(v.campo, len): se esperan 2 argumentos");
                } else {
                    const Type lt = check_expr(e->args[1].get());
                    const PrimitiveKind lk = lt.kind;
                    const bool int_len =
                        lk == PrimitiveKind::I8 || lk == PrimitiveKind::I16 ||
                        lk == PrimitiveKind::I32 || lk == PrimitiveKind::I64 ||
                        lk == PrimitiveKind::U8 || lk == PrimitiveKind::U16 ||
                        lk == PrimitiveKind::U32 || lk == PrimitiveKind::U64;
                    if (!int_len)
                        diags_.error(e->args[1]->loc,
                                     "in_bounds: 'len' debe ser un entero");
                }
                e->result_type = Type{PrimitiveKind::BOOL};
                return e->result_type;
            }
            if (e->args.size() != 1)
                diags_.error(e->loc,
                             "offsetof(v.campo): se espera 1 argumento");
            e->result_type = Type{PrimitiveKind::U64};
            return e->result_type;
        }
        // No es un overlay: dejar caer.  `offsetof<T>` comptime necesita
        // type args (se maneja abajo); `in_bounds` solo aplica a overlays
        // -> se reportara como funcion desconocida, con mensaje normal.
    }

    // -----------------------------------------------------------------
    // Builtins comptime de introspection (Sprint 1).
    // Toman <T> en e->type_args.  Resolvidos a CONSTANTES literales
    // por el lowering.  Cero overhead runtime.  Validamos:
    //   1. e->type_args.size() == aridad esperada.
    //   2. e->args.size() == 0 (los del sprint 1 son nullary).
    //   3. T es resoluble (type_from_node devuelve algo distinto a VOID).
    // El RETURN type lo fijamos aqui; el VALOR concreto lo computa
    // lowering invocando los helpers en comptime_introspect.h.
    // -----------------------------------------------------------------
    // `bitcast<T>(v)`: reinterpreta los BITS de @p v como un T del MISMO ancho.
    // Distinto del cast `(T) v`, que convierte el VALOR (`(i64) 1.5` da 1;
    // `bitcast<i64>(1.5)` da el patron IEEE 754).  Hace falta para leer un f64
    // que se guardo/leyo como bits, que es lo que hacen los atomicos.
    //
    // No es comptime: es una operacion runtime con type-arg.  Baja a
    // @c IrOp::BITCAST, que entre tipos del mismo ancho es un `mov` -> coste
    // cero.  Exigir anchos iguales es lo que lo hace seguro: sin eso, leeria o
    // escribiria fuera del valor.
    if (id->name == "bitcast" && !e->type_args.empty()) {
        if (e->type_args.size() != 1) {
            diags_.error(e->loc,
                         "bitcast: se esperaba 1 type arg <T>, recibidos " +
                             std::to_string(e->type_args.size()));
            return Type{};
        }
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         "bitcast<T>: se esperaba 1 argumento (el valor "
                         "cuyos bits reinterpretar)");
            return Type{};
        }
        const Type dst = type_from_node(e->type_args[0].get());
        const Type src = check_expr(e->args[0].get());
        const size_t sz_dst = comptime_type_size(*this, dst);
        const size_t sz_src = comptime_type_size(*this, src);
        if (sz_dst != sz_src) {
            diags_.error(e->loc, "bitcast<" + type_to_string(dst) +
                                     ">: el origen (" + type_to_string(src) +
                                     ", " + std::to_string(sz_src) +
                                     " bytes) y el destino (" +
                                     std::to_string(sz_dst) +
                                     " bytes) deben tener el MISMO ancho; para "
                                     "convertir el valor usa el cast '(" +
                                     type_to_string(dst) + ") x'");
            return dst;
        }
        return dst;
    }
    // Predicados de tipo: `is_float<T>()` y companeros.  Devuelven bool y su
    // valor lo computa el comptime-eval (que ya los conoce), asi que aqui solo
    // hay que fijar el tipo de retorno.
    if (e->type_args.size() == 1 && e->args.empty() &&
        (id->name == "is_float" || id->name == "is_integer" ||
         id->name == "is_signed" || id->name == "is_unsigned" ||
         id->name == "is_numeric" || id->name == "is_bool" ||
         id->name == "is_char" || id->name == "is_pointer" ||
         id->name == "is_string" || id->name == "is_class" ||
         id->name == "is_struct" || id->name == "is_primitive" ||
         id->name == "is_enum")) {
        (void)type_from_node(e->type_args[0].get());
        return Type{PrimitiveKind::BOOL};
    }
    if (e->type_args.size() >= 1 &&
        (id->name == "sizeof" || id->name == "alignof" ||
         id->name == "typename" || id->name == "type_id" ||
         id->name == "kind" || id->name == "comptime_type" ||
         id->name == "parent_class" || id->name == "element_type" ||
         id->name == "error_type")) {
        if (e->type_args.size() != 1) {
            diags_.error(e->loc,
                         id->name + ": se esperaba 1 type arg <T>, recibidos " +
                             std::to_string(e->type_args.size()));
        }
        if (!e->args.empty()) {
            diags_.error(
                e->loc, id->name + ": no acepta argumentos runtime (solo <T>)");
        }
        /* Validar que T sea resoluble.  type_from_node devuelve un
         * Type con kind=VOID si no logro resolver -- pero NO emite
         * diagnostico por si mismo; hay que detectarlo aqui para no
         * devolver 0 en silencio (p.ej. sizeof<uintptr>() con uintptr
         * indefinido).  sizeof<void>() explicito sigue permitido.  @c resolved
         * es el Type de T (usado por el size real + el hover LSP); @c rt es el
         * tipo de RETORNO del builtin (u64 para sizeof, etc.). */
        Type resolved = e->type_args.empty()
                            ? Type{}
                            : type_from_node(e->type_args[0].get());
        if (e->type_args.size() == 1) {
            const std::string bad =
                first_unresolved_type(e->type_args[0].get());
            if (!bad.empty())
                diags_.error(e->loc,
                             id->name + ": tipo no reconocido: '" + bad + "'");
        }
        /* Tipo de retorno segun el builtin. */
        Type rt{};
        if (id->name == "sizeof" || id->name == "alignof") {
            rt = Type{PrimitiveKind::U64};
        } else if (id->name == "typename") {
            rt = Type{PrimitiveKind::STRING};
        } else if (id->name == "type_id") {
            rt = Type{PrimitiveKind::U32};
        } else if (id->name == "kind") {
            rt = Type{PrimitiveKind::I32};
        } else if (id->name == "comptime_type" || id->name == "parent_class" ||
                   id->name == "element_type" || id->name == "error_type") {
            /* devuelven un Type como first-class value.  Solo
             * usable como init de `comptime const Type X = ...`. */
            rt = Type{PrimitiveKind::TYPE_META};
        }
        // Captura para el LSP: si esta activa, guardar el VALOR que el builtin
        // resuelve en compile-time (sizeof/alignof/kind/type_id/typename) con
        // su ubicacion, para mostrarlo en hover / inspector.  Cero coste cuando
        // el flag esta apagado (builds normales).
        if (capture_comptime_block_locals_ && e->type_args.size() == 1) {
            auto kind_name = [](ComptimeKind k) -> const char * {
                switch (k) {
                case ComptimeKind::Primitive: return "Primitive";
                case ComptimeKind::Class: return "Class";
                case ComptimeKind::Struct: return "Struct";
                case ComptimeKind::Enum: return "Enum";
                case ComptimeKind::Optional: return "Optional";
                case ComptimeKind::Result: return "Result";
                case ComptimeKind::Array: return "Array";
                case ComptimeKind::Ptr: return "Ptr";
                case ComptimeKind::Function: return "Function";
                case ComptimeKind::String: return "String";
                case ComptimeKind::Borrow: return "Borrow";
                case ComptimeKind::Future: return "Future";
                case ComptimeKind::Unique: return "Unique";
                case ComptimeKind::Shared: return "Shared";
                case ComptimeKind::Collection: return "Collection";
                default: return "Unknown";
                }
            };
            ComptimeBuiltinHit hit;
            hit.loc = id->loc;
            hit.loc.length = static_cast<uint32_t>(id->name.size());
            hit.name = id->name + "<" + type_to_string(resolved) + ">";
            hit.type_kind = "int";
            if (id->name == "sizeof") {
                hit.value_str =
                    std::to_string(comptime_type_size(*this, resolved));
            } else if (id->name == "alignof") {
                hit.value_str =
                    std::to_string(comptime_type_align(*this, resolved));
            } else if (id->name == "type_id") {
                hit.value_str =
                    std::to_string(comptime_type_id(*this, resolved));
            } else if (id->name == "kind") {
                const ComptimeKind k = comptime_type_kind(resolved);
                hit.value_str = std::to_string(static_cast<int>(k)) + " (" +
                                kind_name(k) + ")";
            } else if (id->name == "typename") {
                hit.type_kind = "string";
                hit.value_str =
                    "\"" + comptime_type_name(*this, resolved) + "\"";
            }
            if (!hit.value_str.empty())
                comptime_builtin_hits_.push_back(std::move(hit));
        }
        e->result_type = rt;
        return rt;
    }

    // -----------------------------------------------------------------
    // introspection: acceso directo a campos via offset
    // compile-time.  Bypass de getfield/setfield -- el offset se
    // resuelve via comptime_field_offset y el LOAD/STORE va directo.
    //
    //   field_get<T>(obj: T, "f")        -> typeof(T.f)
    //   field_set<T>(obj: T, "f", value) -> void
    //
    // Ventajas vs `obj.f` plano:
    //   - bypass del CALLVIRT a getter de propiedad
    //   - bypass del RMW de bit fields (acceso al storage word directo)
    //   - acceso "raw" util para serializadores / hashers genericos
    // -----------------------------------------------------------------
    if (!e->type_args.empty() &&
        (id->name == "field_get" || id->name == "field_set")) {
        const bool is_get = (id->name == "field_get");
        if (e->type_args.size() != 1) {
            diags_.error(e->loc,
                         id->name + ": se esperaba 1 type arg <T>, recibidos " +
                             std::to_string(e->type_args.size()));
        }
        const size_t expected_args = is_get ? 2 : 3;
        if (e->args.size() != expected_args) {
            diags_.error(
                e->loc,
                id->name + ": se esperaban " + std::to_string(expected_args) +
                    " argumentos (obj, \"field\"" + (is_get ? "" : ", value") +
                    "), recibidos " + std::to_string(e->args.size()));
        }
        const Type t = e->type_args.empty()
                           ? Type{}
                           : type_from_node(e->type_args[0].get());
        /* obj: debe ser STRUCT/CLASS compatible con T. */
        if (!e->args.empty()) {
            const Type ot = check_expr(e->args[0].get());
            if (ot.kind != PrimitiveKind::CLASS &&
                ot.kind != PrimitiveKind::STRUCT &&
                ot.kind != PrimitiveKind::COUNT) {
                diags_.error(e->args[0]->loc,
                             id->name +
                                 ": el primer argumento debe ser una "
                                 "instancia de tipo " +
                                 type_to_string(t) + ", recibido '" +
                                 type_to_string(ot) + "'");
            }
        }
        /* segundo arg: string literal compile-time con el nombre. */
        std::string fname;
        if (e->args.size() >= 2) {
            auto *slit = dynamic_cast<ast::StringLitExpr *>(e->args[1].get());
            if (!slit || slit->is_interpolated()) {
                diags_.error(
                    e->args[1]->loc,
                    id->name + ": el segundo argumento debe ser un "
                               "literal string compile-time (no interpolado)");
            } else {
                fname = slit->value;
            }
            (void)check_expr(e->args[1].get());
        }
        /* Resolver el tipo del campo en T. */
        Type ftype = comptime_field_type(*this, t, fname);
        if (ftype.kind == PrimitiveKind::COUNT && !fname.empty()) {
            diags_.error(e->loc, id->name + ": el tipo '" + type_to_string(t) +
                                     "' no tiene campo '" + fname + "'");
        }
        /* field_set: tercer arg debe ser asignable al tipo del campo. */
        if (!is_get && e->args.size() >= 3) {
            const Type vt = check_expr(e->args[2].get());
            if (ftype.kind != PrimitiveKind::COUNT &&
                !types_assignable(ftype, vt)) {
                diags_.error(e->args[2]->loc,
                             "field_set: el valor de tipo '" +
                                 type_to_string(vt) +
                                 "' no es asignable al campo '" + fname +
                                 "' de tipo '" + type_to_string(ftype) + "'");
            }
        }
        /* Tipo de retorno. */
        const Type rt =
            is_get ? (ftype.kind == PrimitiveKind::COUNT ? Type{} : ftype)
                   : Type{PrimitiveKind::VOID};
        e->result_type = rt;
        return rt;
    }

    // -----------------------------------------------------------------
    // Sprint 3-C introspection: for_each_field<T>(cb) / for_each_method.
    // El callback se invoca UNA vez por cada field/method de T en
    // compile-time (loop completamente unrolled).  La firma del
    // callback debe ser `fn(string) -> void` (o `fn(string) -> T`
    // ignorando el retorno).
    // -----------------------------------------------------------------
    if (!e->type_args.empty() &&
        (id->name == "for_each_field" || id->name == "for_each_method")) {
        if (e->type_args.size() != 1) {
            diags_.error(e->loc,
                         id->name + ": se esperaba 1 type arg <T>, recibidos " +
                             std::to_string(e->type_args.size()));
        }
        if (e->args.size() != 1) {
            diags_.error(
                e->loc, id->name +
                            ": se esperaba 1 argumento (callback), recibidos " +
                            std::to_string(e->args.size()));
        }
        (void)type_from_node(e->type_args[0].get());
        if (!e->args.empty()) {
            const Type cbt = check_expr(e->args[0].get());
            /* El callback debe ser FUNCTION tomando 1 string. */
            if (cbt.kind != PrimitiveKind::FUNCTION ||
                cbt.fn_params.size() != 1 ||
                cbt.fn_params[0].kind != PrimitiveKind::STRING) {
                diags_.error(
                    e->args[0]->loc,
                    id->name +
                        ": el callback debe tener firma "
                        "fn(string) -> _ (recibe el nombre del field/method)");
            }
        }
        const Type rt{PrimitiveKind::VOID};
        e->result_type = rt;
        return rt;
    }

    // -----------------------------------------------------------------
    // Concepto como PREDICADO directo: `Concepto<T>()` evalua a un bool
    // compile-time (0/1), igual que dentro de un predicado de concepto o de
    // un `where`.  Permite usar cualquier concepto (built-in o de usuario)
    // como una funcion booleana comptime: `if (Enum<T>()) {...}`,
    // `static_assert(Numeric<T>(), ...)`, `bool b = AnyEnum<Shape>();`.
    // Requiere 1 type-arg y 0 args runtime.  El lowering lo dobla a CONST.
    // -----------------------------------------------------------------
    if (!e->type_args.empty() &&
        (is_builtin_concept(id->name) ||
         concepts().find(id->name) != concepts().end())) {
        if (e->type_args.size() != 1) {
            diags_.error(e->loc,
                         "concepto '" + id->name +
                             "' como predicado: se esperaba 1 type arg, "
                             "recibidos " +
                             std::to_string(e->type_args.size()));
        }
        if (!e->args.empty()) {
            diags_.error(e->loc, "concepto '" + id->name +
                                     "' como predicado no toma argumentos "
                                     "runtime (solo el type-arg <T>)");
        }
        (void)type_from_node(e->type_args[0].get());
        const Type rt{PrimitiveKind::BOOL};
        e->result_type = rt;
        return rt;
    }

    // -----------------------------------------------------------------
    // Sprint 2 introspection: queries de fields/methods + queries de tipos.
    // Aridades:
    //   1 type_arg, 0 runtime args:  field_count, method_count,
    //                                 is_class, is_struct, is_primitive
    //   1 type_arg, 1 runtime arg:   offsetof, has_field, has_method,
    //                                 field_type (arg debe ser string lit)
    //                                 field_name (arg debe ser int lit)
    //   2 type_args, 0 runtime args: is_subtype, is_same
    // -----------------------------------------------------------------
    {
        const std::string &nm = id->name;
        const bool one_targ_no_args =
            nm == "field_count" || nm == "method_count" || nm == "is_class" ||
            nm == "is_struct" || nm == "is_primitive" || nm == "is_enum" ||
            nm == "is_newtype" || nm == "is_opaque" || nm == "underlying_of";
        const bool one_targ_str_arg = nm == "offsetof" || nm == "has_field" ||
                                      nm == "has_method" || nm == "field_type";
        const bool one_targ_int_arg =
            (nm == "field_name" || nm == "field_type_at" ||
             nm == "method_name" || nm == "method_return_type");
        const bool two_targ_no_args = nm == "is_subtype" || nm == "is_same";

        if ((one_targ_no_args || one_targ_str_arg || one_targ_int_arg ||
             two_targ_no_args) &&
            !e->type_args.empty()) {
            /* Aridad de type_args. */
            const size_t expected_targs = two_targ_no_args ? 2 : 1;
            if (e->type_args.size() != expected_targs) {
                diags_.error(e->loc, nm + ": se esperaban " +
                                         std::to_string(expected_targs) +
                                         " type args, recibidos " +
                                         std::to_string(e->type_args.size()));
            }
            /* Aridad de runtime args. */
            const size_t expected_args =
                (one_targ_str_arg || one_targ_int_arg) ? 1 : 0;
            if (e->args.size() != expected_args) {
                diags_.error(e->loc, nm + ": se esperaban " +
                                         std::to_string(expected_args) +
                                         " argumentos runtime, recibidos " +
                                         std::to_string(e->args.size()));
            }
            /* Validar que los type_args resuelvan. */
            for (auto &ta : e->type_args)
                (void)type_from_node(ta.get());
            /* Arg literal compile-time (string lit no interpolado, o
             * int lit).  El lowering lo asume garantizado. */
            if (one_targ_str_arg && !e->args.empty()) {
                auto *slit =
                    dynamic_cast<ast::StringLitExpr *>(e->args[0].get());
                if (!slit || slit->is_interpolated()) {
                    diags_.error(
                        e->args[0]->loc,
                        nm + ": el argumento debe ser un literal string "
                             "compile-time (no interpolado, no variable)");
                }
                (void)check_expr(e->args[0].get());
            }
            if (one_targ_int_arg && !e->args.empty()) {
                auto *ilit = dynamic_cast<ast::IntLitExpr *>(e->args[0].get());
                if (!ilit) {
                    diags_.error(
                        e->args[0]->loc,
                        nm + ": el argumento debe ser un literal entero "
                             "compile-time (no variable, no expresion)");
                }
                (void)check_expr(e->args[0].get());
            }
            /* Tipo de retorno segun el builtin. */
            Type rt{};
            if (nm == "offsetof") {
                rt = Type{PrimitiveKind::U64};
            } else if (nm == "field_count" || nm == "method_count") {
                rt = Type{PrimitiveKind::U32};
            } else if (nm == "field_name" || nm == "field_type" ||
                       nm == "underlying_of") {
                rt = Type{PrimitiveKind::STRING};
            } else if (nm == "field_type_at") {
                /* A.43: field_type_at<T>(idx) -> Type as first-class value. */
                rt = Type{PrimitiveKind::TYPE_META};
            } else if (nm == "method_name") {
                /* A.43: method_name<T>(idx) -> string. */
                rt = Type{PrimitiveKind::STRING};
            } else if (nm == "method_return_type") {
                /* A.43: method_return_type<T>(idx) -> Type. */
                rt = Type{PrimitiveKind::TYPE_META};
            } else {
                /* has_field/has_method/is_subtype/is_same/is_class/
                 * is_struct/is_primitive -> BOOL. */
                rt = Type{PrimitiveKind::BOOL};
            }
            // Captura para el LSP: guardar el VALOR que resuelve el builtin con
            // su ubicacion, para mostrarlo inline / en hover.  Cubre los que
            // dan un valor escalar/string (no los que devuelven Type).
            if (capture_comptime_block_locals_ && !e->type_args.empty()) {
                const Type t1 = type_from_node(e->type_args[0].get());
                std::string str_arg, arg_disp;
                uint32_t int_arg = 0;
                if (one_targ_str_arg && !e->args.empty()) {
                    auto *sl =
                        dynamic_cast<ast::StringLitExpr *>(e->args[0].get());
                    if (sl) {
                        str_arg = sl->value;
                        arg_disp = "\"" + str_arg + "\"";
                    }
                } else if (one_targ_int_arg && !e->args.empty()) {
                    auto *il =
                        dynamic_cast<ast::IntLitExpr *>(e->args[0].get());
                    if (il) {
                        int_arg = static_cast<uint32_t>(il->value);
                        arg_disp = std::to_string(int_arg);
                    }
                }
                auto yn = [](bool b) -> std::string {
                    return b ? "true" : "false";
                };
                ComptimeBuiltinHit hit;
                hit.loc = id->loc;
                hit.loc.length = static_cast<uint32_t>(nm.size());
                hit.type_kind = "int";
                if (nm == "field_count") {
                    hit.value_str =
                        std::to_string(comptime_field_count(*this, t1));
                } else if (nm == "method_count") {
                    hit.value_str =
                        std::to_string(comptime_method_count(*this, t1));
                } else if (nm == "offsetof") {
                    hit.value_str = std::to_string(
                        comptime_field_offset(*this, t1, str_arg));
                } else if (nm == "has_field") {
                    hit.value_str = yn(comptime_has_field(*this, t1, str_arg));
                } else if (nm == "has_method") {
                    hit.value_str = yn(comptime_has_method(*this, t1, str_arg));
                } else if (nm == "is_class") {
                    hit.value_str = yn(comptime_is_class(t1));
                } else if (nm == "is_struct") {
                    hit.value_str = yn(comptime_is_struct(*this, t1));
                } else if (nm == "is_primitive") {
                    hit.value_str = yn(comptime_is_primitive(t1));
                } else if (nm == "is_enum") {
                    hit.value_str = yn(comptime_is_enum(*this, t1));
                } else if (nm == "field_name") {
                    hit.type_kind = "string";
                    hit.value_str =
                        "\"" + comptime_field_name(*this, t1, int_arg) + "\"";
                } else if (nm == "field_type") {
                    hit.type_kind = "string";
                    hit.value_str =
                        "\"" + comptime_field_type_name(*this, t1, str_arg) +
                        "\"";
                } else if (two_targ_no_args && e->type_args.size() == 2) {
                    const Type t2 = type_from_node(e->type_args[1].get());
                    if (nm == "is_subtype")
                        hit.value_str = yn(comptime_is_subtype(*this, t1, t2));
                    else if (nm == "is_same")
                        hit.value_str = yn(comptime_is_same(*this, t1, t2));
                }
                if (!hit.value_str.empty()) {
                    if (two_targ_no_args && e->type_args.size() == 2) {
                        hit.name = nm + "<" + type_to_string(t1) + "," +
                                   type_to_string(
                                       type_from_node(e->type_args[1].get())) +
                                   ">";
                    } else {
                        hit.name = nm + "<" + type_to_string(t1) + ">";
                        if (!arg_disp.empty()) hit.name += "(" + arg_disp + ")";
                    }
                    comptime_builtin_hits_.push_back(std::move(hit));
                }
            }
            e->result_type = rt;
            return rt;
        }
    }

    // -----------------------------------------------------------------
    // A.39: builtins comptime sobre strings.
    //   comptime_concat(a, b) -> string  (concat de 2 strings comptime)
    //   comptime_streq(a, b)  -> bool    (igualdad de strings comptime)
    //   comptime_strlen(s)    -> u64     (longitud en bytes)
    //
    // Estos son SIEMPRE compile-time -- args deben ser comptime-
    // evaluables a string.  El lowering los inlinea como literal
    // (string -> STR_LIT_ADDR+STRMAKE; int -> CONST) sin runtime call.
    // -----------------------------------------------------------------
    /* A.43.12: comptime_replace(s, needle, replacement) y
     * comptime_contains(s, needle) -- patron declarativo de templates
     * para macros.  Combinados con `comptime_emit_expr` permiten
     * generar codigo a partir de templates con placeholders. */
    if (id->name == "comptime_replace") {
        if (e->args.size() != 3) {
            diags_.error(e->loc, "comptime_replace: se esperaban 3 args (str, "
                                 "needle, replacement), recibidos " +
                                     std::to_string(e->args.size()));
        } else {
            for (auto &a : e->args)
                (void)check_expr(a.get());
        }
        Type rt{PrimitiveKind::STRING};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "comptime_contains") {
        if (e->args.size() != 2) {
            diags_.error(e->loc, "comptime_contains: se esperaban 2 args (str, "
                                 "needle), recibidos " +
                                     std::to_string(e->args.size()));
        } else {
            for (auto &a : e->args)
                (void)check_expr(a.get());
        }
        Type rt{PrimitiveKind::BOOL};
        e->result_type = rt;
        return rt;
    }
    /* A.43.11: gensym(prefix) -> string.  Devuelve un identifier
     * fresco unico, util para macros hygenic (prevenir capture en
     * el scope del caller).  Validacion minima: 1 arg string. */
    if (id->name == "gensym") {
        if (e->args.size() != 1) {
            diags_.error(
                e->loc,
                "gensym: se esperaba 1 argumento (string prefix), recibidos " +
                    std::to_string(e->args.size()));
        } else {
            (void)check_expr(e->args[0].get());
        }
        Type rt{PrimitiveKind::STRING};
        e->result_type = rt;
        return rt;
    }
    /* comptime_emit_expr(str) -- macros Lisp con splice/emit.
     * El string se parsea como una EXPRESION Vesta, se type-checa en el
     * contexto actual y se SUSTITUYE en el AST runtime (no solo
     * comptime eval).  El lowering ve el AST sustituido y emite
     * codigo runtime real.  Equivalente al unquote/splice de Lisp.
     * Diferencia con comptime_compile: este SI emite codigo runtime;
     * comptime_compile solo evalua al compile-time y descarta el AST. */
    if (id->name == "comptime_emit_expr") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "comptime_emit_expr: se esperaba 1 argumento "
                                 "(string), recibidos " +
                                     std::to_string(e->args.size()));
            return Type{};
        }
        (void)check_expr(e->args[0].get());
        const ComptimeEvalResult sarg =
            comptime_eval_expr(*this, e->args[0].get());
        if (!sarg.ok || !sarg.is_str) {
            diags_.error(e->args[0]->loc,
                         "comptime_emit_expr: el argumento debe ser un string "
                         "comptime-evaluable");
            return Type{};
        }
        /* Parsear el fragmento como expresion Vesta. */
        Lexer fragment_lex(sarg.str, "<comptime_emit_expr>", diags_);
        Parser fragment_par(fragment_lex, diags_);
        std::unique_ptr<ast::Expr> parsed = fragment_par.parse_one_expr();
        if (!parsed) {
            diags_.error(e->loc, "comptime_emit_expr: el fragmento no se pudo "
                                 "parsear como expresion");
            return Type{};
        }
        parsed->loc = e->loc;
        /* Type-checar la expresion sustituida en el contexto actual. */
        const Type rt = check_expr(parsed.get());
        /* Guardar el AST sustituido para que el lowering lo recoja. */
        e->macro_expanded = std::move(parsed);
        e->result_type = rt;
        return rt;
    }
    /* comptime_compile(str) -> result.  MVP de macros estilo
     * Lisp: el string se parsea como una EXPRESION Vesta y se evalua
     * en compile-time.  Permite construir codigo a partir de datos
     * (typename<T>, comptime_concat, comptime_to_str, etc.) y
     * ejecutarlo sin runtime.  Limitaciones:
     *  - Solo expresion (no statements).
     *  - El tipo de retorno depende del contenido y se inferira
     *    desde el comptime const que reciba el valor; aqui en check
     *    devolvemos el tipo declarado del binding o un sentinela u64. */
    if (id->name == "comptime_compile") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "comptime_compile: se esperaba 1 argumento "
                                 "(string), recibidos " +
                                     std::to_string(e->args.size()));
        }
        if (!e->args.empty()) {
            (void)check_expr(e->args[0].get());
            /* Eval temprano para reportar errores de parsing aqui. */
            const ComptimeEvalResult r = comptime_eval_expr(*this, e);
            if (!r.ok) {
                diags_.error(
                    e->loc,
                    "comptime_compile: el fragmento no es comptime-evaluable");
            }
            /* Devolver el tipo segun el contenido inferido. */
            Type rt{};
            if (r.is_str)
                rt = Type{PrimitiveKind::STRING};
            else if (r.is_type)
                rt = Type{PrimitiveKind::TYPE_META};
            else
                rt = Type{PrimitiveKind::I64};
            e->result_type = rt;
            return rt;
        }
        Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    /* comptime_print(value) -> u64 (=0).  Emite a stderr en
     * compile-time.  Acepta string/int/Type.  Validacion minima: 1 arg
     * comptime-evaluable.  Retorna u64=0 para componer en static_assert. */
    if (id->name == "comptime_print") {
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         "comptime_print: se esperaba 1 argumento, recibidos " +
                             std::to_string(e->args.size()));
        }
        if (!e->args.empty()) {
            (void)check_expr(e->args[0].get());
            const ComptimeEvalResult r =
                comptime_eval_expr(*this, e->args[0].get());
            if (!r.ok) {
                diags_.error(
                    e->args[0]->loc,
                    "comptime_print: el argumento no es comptime-evaluable");
            }
        }
        Type rt{PrimitiveKind::U64};
        e->result_type = rt;
        return rt;
    }

    if (id->name == "comptime_concat" || id->name == "comptime_streq" ||
        id->name == "comptime_strlen" || id->name == "comptime_chr" ||
        id->name == "comptime_ord" || id->name == "comptime_substr" ||
        id->name == "comptime_repeat" || id->name == "comptime_to_str") {
        const std::string &nm = id->name;
        size_t expected;
        if (nm == "comptime_strlen" || nm == "comptime_chr" ||
            nm == "comptime_ord" || nm == "comptime_to_str") {
            expected = 1;
        } else if (nm == "comptime_substr") {
            expected = 3;
        } else {
            expected = 2;
        }
        if (e->args.size() != expected) {
            diags_.error(e->loc, nm + ": se esperaban " +
                                     std::to_string(expected) +
                                     " argumentos, recibidos " +
                                     std::to_string(e->args.size()));
        }
        /* Chequear que los args sean comptime-evaluables.
         * El tipo (string vs int) depende del builtin:
         *   chr/repeat: arg int (codepoint o count)
         *   to_str: arg int
         *   ord: arg string
         *   substr: arg0 string, arg1/arg2 ints
         *   concat/streq/strlen: arg(s) string */
        for (auto &a : e->args)
            (void)check_expr(a.get());
        for (size_t i = 0; i < e->args.size(); ++i) {
            const ComptimeEvalResult r =
                comptime_eval_expr(*this, e->args[i].get());
            bool need_str = false;
            if (nm == "comptime_concat" || nm == "comptime_streq" ||
                nm == "comptime_strlen" || nm == "comptime_ord") {
                need_str = true;
            } else if ((nm == "comptime_substr" || nm == "comptime_repeat") &&
                       i == 0) {
                need_str = true;
            }
            if (!r.ok) {
                /* si el arg es un IdentExpr que resuelve
                 * a un `comptime var` (mutable) o `comptime const`
                 * en cualquier scope, NO emitimos error.  Esto
                 * cubre el caso de comptime_strlen(s) dentro de un
                 * @Macro body donde `s` esta declarada como
                 * `comptime var string s = "";` -- en type-check
                 * time s tiene valor "" (inicial) pero el call
                 * SITE del macro la evaluara con el valor mutado
                 * tras el loop.  El AST evaluator en
                 * comptime_introspect.cpp ya resuelve correctamente
                 * al call site.  Aqui solo el chequeo estatico es
                 * demasiado estricto. */
                bool deferrable = false;
                if (e->args[i]->kind == ast::NodeKind::IdentExpr) {
                    const auto *id =
                        static_cast<const ast::IdentExpr *>(e->args[i].get());
                    /* Buscar en local stack del lowering (comptime
                     * for index / comptime var locales). */
                    for (auto it = comptime_const_locals_.rbegin();
                         it != comptime_const_locals_.rend(); ++it) {
                        if (it->find(id->name) != it->end()) {
                            deferrable = true;
                            break;
                        }
                    }
                    /* Buscar en globales comptime const. */
                    if (!deferrable && comptime_const_values_.count(id->name)) {
                        deferrable = true;
                    }
                }
                /* Estos builtins (concat/streq/strlen/chr/ord/substr/repeat/
                 * to_str/replace/contains) son las FUNCIONES ESTANDAR del
                 * lenguaje: bajan a ops runtime (STRLEN/STRCAT/STRCMP/...) que
                 * la ComptimeVM (interp/JIT) ejecuta.  Cuando el argumento NO
                 * es un comptime const (p.ej. `strlen(src)` donde `src` es un
                 * param de una fn -- comptime o no -- llamada desde un @Macro),
                 * NO se pliega en compile-time: se difiere a la CALL runtime y
                 * se VM-evalua al invocar.  Por eso NO es un error -- son las
                 * mismas funciones estandar, sin helper comptime-especifico.
                 * (El fold estatico sigue ocurriendo cuando el arg SI es const:
                 * r.ok=true, no se llega aqui.) */
                (void)current_fn_is_macro_;
                deferrable = true;
                if (!deferrable) {
                    diags_.error(e->args[i]->loc,
                                 nm + ": argumento " + std::to_string(i) +
                                     " no es comptime-evaluable");
                }
            } else if (!r.deferred && need_str && !r.is_str) {
                diags_.error(e->args[i]->loc, nm + ": argumento " +
                                                  std::to_string(i) +
                                                  " debe ser string comptime");
            } else if (!r.deferred && !need_str && r.is_str) {
                diags_.error(e->args[i]->loc, nm + ": argumento " +
                                                  std::to_string(i) +
                                                  " debe ser int comptime");
            }
        }
        Type rt{};
        if (nm == "comptime_concat" || nm == "comptime_chr" ||
            nm == "comptime_substr" || nm == "comptime_repeat" ||
            nm == "comptime_to_str") {
            rt = Type{PrimitiveKind::STRING};
        } else if (nm == "comptime_streq") {
            rt = Type{PrimitiveKind::BOOL};
        } else {
            rt = Type{PrimitiveKind::U64};
        }
        e->result_type = rt;
        return rt;
    }

    // -----------------------------------------------------------------
    // static_assert(cond, "msg")
    // Verifica una condicion comptime-evaluable.  Si la cond es false
    // (o no evaluable), emite error de compile-time con el msg.  No
    // genera codigo runtime: el lowering devuelve IR_NO_VALUE (void).
    // -----------------------------------------------------------------
    if (id->name == "static_assert") {
        if (e->args.size() != 2) {
            diags_.error(e->loc, "static_assert: se esperaban 2 argumentos "
                                 "(cond, \"msg\"), recibidos " +
                                     std::to_string(e->args.size()));
            return Type{PrimitiveKind::VOID};
        }
        /* Validar tipo de la cond y del msg.  No es bloqueante --
         * intentamos evaluar de todas formas. */
        for (auto &a : e->args)
            (void)check_expr(a.get());
        /* Extraer el msg.  Un literal directo es el caso comun, pero vale
         * CUALQUIER string comptime-evaluable: una `comptime string` con el
         * mensaje, o una concatenacion de varias.  Exigir un literal obligaba a
         * repetir el mismo texto en cada assert (o a meterlo todo en una linea
         * larguisima) cuando varios comparten mensaje -- que es justo lo que
         * pasa en un tipo generico con un guard por metodo. */
        std::string msg;
        auto *slit = dynamic_cast<ast::StringLitExpr *>(e->args[1].get());
        if (slit && !slit->is_interpolated()) {
            msg = slit->value;
        } else if (ComptimeEvalResult mv =
                       comptime_eval_expr(*this, e->args[1].get());
                   mv.ok && mv.is_str) {
            msg = mv.str;
        } else {
            diags_.error(e->args[1]->loc,
                         "static_assert: el segundo argumento debe ser un "
                         "string comptime-evaluable (un literal, una 'comptime "
                         "string' o una concatenacion de ambos)");
        }
        /* try comptime eval first.  Si la cond ES
         * comptime-evaluable: fire diagnostic si false (same as
         * before).  Si NO ES (e.g. depende de macro param), NO
         * emitimos error -- el lowering bajara a CALLN
         * "vesta_comptime:static_assert" que evalua en runtime VM
         * (que sigue siendo compile time porque la macro corre en
         * ComptimeRuntime). */
        const ComptimeEvalResult r =
            comptime_eval_expr(*this, e->args[0].get());
        /* #2: NO disparar sobre un valor DIFERIDO (placeholder de una comptime
         * fn via ComptimeVM aun no cargada, pass 1 del two-phase).  El pass 2
         * (bytecode cargado) re-evalua la cond con el valor real. */
        if (r.ok && !r.deferred && r.value == 0) {
            diags_.error(
                e->loc,
                std::string("static_assert FAILED: ") +
                    (msg.empty() ? std::string("condicion falsa") : msg));
        }
        // Captura LSP: indicar inline si el static_assert PASA (OK) o FALLA.
        // Usamos lsp_eval_int porque evalua los builtins (sizeof<T>, ...) que
        // comptime_eval_expr no cubre.
        if (capture_comptime_block_locals_) {
            int64_t sv;
            if (lsp_eval_int(e->args[0].get(), &sv)) {
                ComptimeBuiltinHit hit;
                hit.loc = e->loc;
                hit.name = "static_assert";
                hit.type_kind = "assert";
                hit.value_str = (sv != 0) ? "OK" : "FALLA";
                comptime_builtin_hits_.push_back(std::move(hit));
            }
        }
        /* Si !r.ok, no emitimos error -- el lowering despachara
         * via FFI al virtual fn que hace el check en runtime VM. */

        /* el tipo de retorno cambia segun el contexto.
         * Si la cond es comptime-evaluable (caso comun a nivel
         * modulo), devolvemos VOID -- el call site no usa el
         * resultado.  Si NO es (macros con runtime cond), devolvemos
         * I64 porque el lowering emitira CALLN a un fn que devuelve
         * i64 status (0=ok, 1=fail) y algunos sitios podrian leer
         * el valor. */
        const Type rt =
            r.ok ? Type{PrimitiveKind::VOID} : Type{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }

    // -----------------------------------------------------------------
    // Sprint 4 (A.37.s4): builtins runtime de introspection.
    //   find_type(name: string)              -> i64 (ptr a IntrospectInfo
    //                                            o 0 si no existe)
    //   type_info_kind(p)                    -> i32
    //   type_info_size(p)                    -> u32
    //   type_info_align(p)                   -> u32
    //   type_info_field_count(p)             -> u32
    //   type_info_name(p)                    -> string
    //   type_info_field_name(p, idx)         -> string
    //   type_info_field_offset(p, idx)       -> u32
    //   type_info_field_size(p, idx)         -> u32
    // -----------------------------------------------------------------
    {
        const std::string &nm = id->name;
        const bool is_find = (nm == "find_type");
        const bool is_simple =
            nm == "type_info_kind" || nm == "type_info_size" ||
            nm == "type_info_align" || nm == "type_info_field_count";
        const bool is_str_q = (nm == "type_info_name");
        const bool is_field_idx_str = (nm == "type_info_field_name");
        const bool is_field_idx_num =
            nm == "type_info_field_offset" || nm == "type_info_field_size";
        if (is_find || is_simple || is_str_q || is_field_idx_str ||
            is_field_idx_num) {
            const size_t expected = is_find     ? 1
                                    : is_simple ? 1
                                    : is_str_q  ? 1
                                                : 2;
            if (e->args.size() != expected) {
                diags_.error(e->loc, nm + ": se esperaban " +
                                         std::to_string(expected) +
                                         " argumentos, recibidos " +
                                         std::to_string(e->args.size()));
            }
            /* Validar tipo del primer arg (string para find_type / _name;
             * i64/ptr para type_info_*).  No imponemos restriccion
             * estricta: aceptamos COUNT (inferido) y dejamos al lowering
             * confiar en que el handle es un i64. */
            for (auto &a : e->args)
                (void)check_expr(a.get());
            if (is_find && !e->args.empty()) {
                const Type ta = e->args[0]->result_type;
                if (ta.kind != PrimitiveKind::STRING &&
                    ta.kind != PrimitiveKind::PTR &&
                    ta.kind != PrimitiveKind::COUNT) {
                    diags_.error(e->args[0]->loc,
                                 "find_type: el argumento debe ser un string");
                }
            }
            Type rt{};
            if (is_find)
                rt = Type{PrimitiveKind::I64};
            else if (nm == "type_info_kind")
                rt = Type{PrimitiveKind::I32};
            else if (nm == "type_info_name" || nm == "type_info_field_name")
                rt = Type{PrimitiveKind::STRING};
            else
                rt = Type{PrimitiveKind::U32};
            e->result_type = rt;
            return rt;
        }
    }

    // -----------------------------------------------------------------
    // Builtins de reflexion.  No se declaran como funciones
    // normales; el lowering los baja a secuencias de instrucciones
    // bytecode existentes (findclass, mov, etc).  El tipo de retorno
    // de los punteros opacos es i64 (ClassInfo*/FieldInfo*/MethodInfo*).
    //
    //   forName(string lit / char* / string)   -> i64 (ClassInfo*)
    //   getClass(class_instance)                -> i64 (ClassInfo*)
    // -----------------------------------------------------------------
    if (id->name == "forName") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "forName: se esperaba 1 argumento (nombre de "
                                 "clase), recibidos " +
                                     std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "getClass") {
        if (e->args.size() != 1) {
            diags_.error(
                e->loc,
                "getClass: se esperaba 1 argumento (instancia), recibidos " +
                    std::to_string(e->args.size()));
        }
        for (auto &a : e->args) {
            const Type at = check_expr(a.get());
            if (at.kind != PrimitiveKind::CLASS &&
                at.kind != PrimitiveKind::COUNT) {
                diags_.error(a->loc, "getClass: el argumento debe ser una "
                                     "instancia de clase, no '" +
                                         type_to_string(at) + "'");
            }
        }
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    // getField(cls, "field_name") -> i64 (FieldInfo*).  cls debe ser
    // un i64 (resultado de forName/getClass) y el nombre un string lit.
    if (id->name == "getField") {
        if (e->args.size() != 2) {
            diags_.error(
                e->loc,
                "getField: se esperaban 2 argumentos (cls, name), recibidos " +
                    std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    // Reflexion extendida.
    //
    //   getMethod(cls, "name")     -> i64 (MethodInfo*)
    //   newInstance(cls)           -> i64 (host_ptr a la nueva instancia,
    //                                  marcado is_host_ptr=true en lowering)
    //   invoke(method, this, ...)  -> i64 (resultado del dispatch via
    //                                  CALLM/advice_chain)
    //
    // Todos devuelven i64 generico (cast por el usuario al tipo logico).
    // El argumento variadico de invoke (this + args) se valida solo en
    // aridad >= 2.
    if (id->name == "getMethod") {
        if (e->args.size() != 2) {
            diags_.error(
                e->loc,
                "getMethod: se esperaban 2 argumentos (cls, name), recibidos " +
                    std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "newInstance") {
        if (e->args.size() != 1) {
            diags_.error(
                e->loc,
                "newInstance: se esperaba 1 argumento (cls), recibidos " +
                    std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "invoke") {
        if (e->args.size() < 2) {
            diags_.error(e->loc, "invoke: se esperan al menos 2 argumentos "
                                 "(method, this, ...args), recibidos " +
                                     std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    // proceed() -> i64.  Solo valido dentro de un advice @Around; el
    // type checker no fuerza el contexto (lo hace el runtime: si se
    // ejecuta fuera de un AROUND frame, dispara
    // THREAD_ILLEGAL_INSTRUCTION).  Acepta cualquier tipo de retorno
    // pero declaramos i64 generico para que pase types_assignable.
    if (id->name == "proceed") {
        if (!e->args.empty()) {
            diags_.error(e->loc, "proceed: no acepta argumentos (re-invoca el "
                                 "target con la calling convention actual)");
        }
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    // Optional via referencias nullable + instrucciones VM
    // isnull/unwrap (sin clase generica de wrapper).  Modelo:
    // cualquier referencia (CLASS) puede ser null; null literal
    // representa "ausente".  Builtins:
    //   isPresent(x) -> i32  (1 si x != null, 0 si x == null)
    //                    Lowering: isnull r_tmp, r_x; xor r_tmp, 1
    //   unwrap(x)    -> mismo tipo de x (host_ptr); throw si null.
    //                    Lowering: unwrap r_dst, r_x  (bytecode 0x26).
    // Pensados primariamente para reference types (CLASS); para
    // value types primitivos no hay null asi que el checker lo rechaza.
    // builtins de monitor para uso dentro de synchronized.
    //   wait(obj)      -> void   (libera monitor + suspende)
    //   notify(obj)    -> void   (despierta un waiter)
    //   notifyAll(obj) -> void   (despierta todos los waiters)
    // El argumento debe ser CLASS (referencia GC).  El llamador es
    // responsable de invocarlas dentro de synchronized(obj) {...},
    // si no, el bytecode subyacente fallara silenciosamente
    // (monwait sobre objeto sin lock = no-op + suspension indefinida).
    // builtins de procesos / IPC.
    //   pid()              -> i64    (PID encoded del proceso actual)
    //   msgsend(pid, val)  -> i32    (1 si enviado, 0 si error)
    //   msgrecv()          -> i64    (valor recibido del propio mailbox)
    if (id->name == "pid") {
        if (!e->args.empty()) {
            diags_.error(e->loc, "pid: no acepta argumentos");
        }
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    // argv del script: builtins args_count() y args_get(i).
    // El runtime guarda los args en VM::script_args (poblado desde
    // main.cpp con todo lo que viene tras `--run prog.velb`).  Los
    // opcodes bytecode getargc (0x6B) y getarg (0x6C) los consultan.
    if (id->name == "args_count") {
        if (!e->args.empty()) {
            diags_.error(e->loc, "args_count: no acepta argumentos");
        }
        const Type rt{PrimitiveKind::I32};
        e->result_type = rt;
        return rt;
    }
    // Builtins de terminal / VT100.  Sin args
    // (clear/save/restore/show/hide/reset) o con (row, col) para term_move.
    // Cada uno baja a una secuencia de vio_print con escapes ANSI hardcodeados.
    if (id->name == "term_clear" || id->name == "term_clear_line" ||
        id->name == "term_save_cursor" || id->name == "term_restore_cursor" ||
        id->name == "term_hide_cursor" || id->name == "term_show_cursor" ||
        id->name == "term_reset") {
        if (!e->args.empty()) {
            diags_.error(e->loc, id->name + ": no acepta argumentos");
        }
        const Type rt{PrimitiveKind::VOID};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "term_move") {
        if (e->args.size() != 2) {
            diags_.error(
                e->loc,
                "term_move: se esperan 2 argumentos (row, col), recibidos " +
                    std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::VOID};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "args_get") {
        if (e->args.size() != 1) {
            diags_.error(
                e->loc,
                "args_get: se espera 1 argumento (i32 indice), recibidos " +
                    std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::STRING};
        e->result_type = rt;
        return rt;
    }
    // unloadmodule(path_lit): descarga un modulo dinamico previamente
    // cargado via loadmodule.  Devuelve i32 (1 ok, 0 no encontrado).
    // path debe ser string literal por las mismas razones que loadmodule:
    // se interna en static_data en compile time.
    // Reflexion: enumeracion de miembros de una clase.
    //   getMethods(cls) -> i32        (numero de metodos)
    //   getMethodAt(cls, i) -> i64    (MethodInfo* del i-esimo)
    //   getFields(cls) -> i32         (numero de fields de instancia)
    //   getFieldAt(cls, i) -> i64     (FieldInfo* del i-esimo)
    // Permiten descubrimiento dinamico sin conocer los nombres.
    if (id->name == "getMethods" || id->name == "getFields") {
        if (e->args.size() != 1) {
            diags_.error(
                e->loc, id->name + ": se espera 1 argumento (cls), recibidos " +
                            std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I32};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "getMethodAt" || id->name == "getFieldAt") {
        if (e->args.size() != 2) {
            diags_.error(e->loc,
                         id->name +
                             ": se esperan 2 argumentos (cls, i), recibidos " +
                             std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "unloadmodule") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "unloadmodule: se espera 1 argumento (string "
                                 "literal con path), recibidos " +
                                     std::to_string(e->args.size()));
        } else if (e->args[0] &&
                   e->args[0]->kind != ast::NodeKind::StringLitExpr) {
            diags_.error(e->loc,
                         "unloadmodule: el path debe ser un string literal");
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I32};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "msgsend") {
        if (e->args.size() != 2) {
            diags_.error(e->loc, "msgsend: se esperan 2 argumentos (pid, valor "
                                 "i64), recibidos " +
                                     std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I32};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "vacount") {
        // Numero de argumentos variadicos recibidos por la funcion actual.
        // Solo valido dentro de una funcion con un param `T... name`.
        if (!e->args.empty()) {
            diags_.error(e->loc, "vacount: no acepta argumentos");
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "msgrecv") {
        if (!e->args.empty()) {
            diags_.error(e->loc, "msgrecv: no acepta argumentos");
        }
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    // builtins de futures.
    //   future_alloc()         -> i64   (GcHandle del nuevo FutureObject
    //   PENDING) fulfill(fut, value)    -> void  (resuelve y despierta al
    //   waiter)
    // El await NO es un builtin sino una expresion (KW_AWAIT) procesada
    // en lower_expr.  Vease check de UnaryExpr para AwaitExpr o el caso
    // dedicado mas abajo si se anyade un AST node.
    if (id->name == "future_alloc") {
        if (!e->args.empty()) {
            diags_.error(e->loc, "future_alloc: no acepta argumentos");
        }
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    // loadmodule(string_lit) -> i64 (init_pc del modulo cargado, 0 = error).
    // Auto-invoca el main del modulo cargado tras la carga (callvm-equivalente
    // en el opcode loadmod), por lo que el __module_init del nuevo modulo se
    // ejecuta y sus clases quedan disponibles via findclass / forName tras
    // que loadmodule retorne.
    if (id->name == "loadmodule") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "loadmodule: se esperaba 1 argumento (string "
                                 "literal con la ruta), recibidos " +
                                     std::to_string(e->args.size()));
        } else if (e->args[0] &&
                   e->args[0]->kind != ast::NodeKind::StringLitExpr) {
            diags_.error(e->loc, "loadmodule: el argumento debe ser un string "
                                 "literal con la ruta al .velb");
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "fulfill") {
        if (e->args.size() != 2) {
            diags_.error(e->loc, "fulfill: se esperan 2 argumentos (fut, valor "
                                 "i64), recibidos " +
                                     std::to_string(e->args.size()));
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        const Type rt{PrimitiveKind::VOID};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "wait" || id->name == "notify" || id->name == "notifyAll") {
        /* validacion estatica.  wait/notify/notifyAll requieren
         * mantener el monitor del target -- semanticamente solo tienen
         * sentido dentro de un bloque `synchronized (obj) { ... }`.
         * Llamarlas fuera produce IllegalMonitorState en runtime; el
         * check estatico evita el bug antes del primer arranque. */
        if (synchronized_depth_ == 0) {
            diags_.error(
                e->loc,
                id->name +
                    ": solo puede invocarse dentro de un bloque "
                    "'synchronized (obj) { ... }' (de lo contrario el proceso "
                    "no posee el monitor y se produce IllegalMonitorState en "
                    "runtime)");
        }
        if (e->args.size() != 1) {
            diags_.error(e->loc, id->name +
                                     ": se esperaba 1 argumento (target del "
                                     "monitor), recibidos " +
                                     std::to_string(e->args.size()));
        }
        for (auto &a : e->args) {
            Type at = check_expr(a.get());
            if (at.kind != PrimitiveKind::CLASS &&
                at.kind != PrimitiveKind::COUNT) {
                diags_.error(
                    a->loc,
                    id->name +
                        ": el argumento debe ser una referencia a clase, no '" +
                        type_to_string(at) + "'");
            }
        }
        const Type rt{PrimitiveKind::VOID};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "isPresent") {
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         "isPresent: se esperaba 1 argumento, recibidos " +
                             std::to_string(e->args.size()));
        }
        for (auto &a : e->args) {
            Type at = check_expr(a.get());
            if (at.kind != PrimitiveKind::CLASS &&
                at.kind != PrimitiveKind::PTR &&
                at.kind != PrimitiveKind::I64 &&
                at.kind != PrimitiveKind::OPTIONAL &&
                at.kind != PrimitiveKind::COUNT &&
                !type_is_overlay_handle(struct_layouts_, at)) {
                diags_.error(a->loc, "isPresent: el argumento debe ser "
                                     "Optional<T> o referencia, no '" +
                                         type_to_string(at) + "'");
            }
        }
        const Type rt{PrimitiveKind::I32};
        e->result_type = rt;
        return rt;
    }
    // unwrap(x)          : assert non-null, throw/panic si null.
    // unwrap_unchecked(x): MISMA semantica de TIPO, pero el lowering NO
    //                      emite chequeo (baja a identidad).  UB si x es
    //                      null -- es el opt-out per-sitio (estilo Rust
    //                      unwrap_unchecked); nombre greppable para audits.
    if (id->name == "unwrap" || id->name == "unwrap_unchecked") {
        const char *bn = id->name.c_str();
        if (e->args.size() != 1) {
            diags_.error(e->loc, std::string(bn) +
                                     ": se esperaba 1 argumento, recibidos " +
                                     std::to_string(e->args.size()));
        }
        Type at = e->args.empty() ? Type{} : check_expr(e->args[0].get());
        // Si el argumento es Optional<T>, devolvemos T (extrae el
        // payload).  Para CLASS/PTR seguimos el modelo nullable
        // legacy y devolvemos el mismo tipo.
        if (at.kind == PrimitiveKind::OPTIONAL && at.pointee) {
            Type rt = *at.pointee;
            e->result_type = rt;
            return rt;
        }
        if (at.kind != PrimitiveKind::CLASS && at.kind != PrimitiveKind::PTR &&
            at.kind != PrimitiveKind::I64 && at.kind != PrimitiveKind::COUNT &&
            !type_is_overlay_handle(struct_layouts_, at)) {
            diags_.error(e->loc, std::string(bn) +
                                     ": el argumento debe ser una referencia "
                                     "o Optional<T>, no '" +
                                     type_to_string(at) + "'");
        }
        e->result_type = at;
        return at;
    }
    /* unwrap_or(x, def) : el valor si esta, y si no, `def`.  NO afirma nada,
     *                     asi que no puede fallar y nunca mata el proceso.
     * expect(x, "msg")  : lo mismo que `unwrap`, con un mensaje propio.  Desde
     *                     que fallar es fatal, el mensaje es la unica pista que
     *                     queda de que se dio por hecho y donde.
     *
     * Los dos van AQUI, pegados a `unwrap`, porque son la misma familia: la
     * pregunta es siempre "puede que no haya nada", y lo que cambia es que se
     * hace al respecto.  Sin `unwrap_or` la unica salida recuperable era
     * escribir el `if` a mano, y eso empuja a afirmar por comodidad -- que es
     * justo lo que no queremos incentivar. */
    if (id->name == "unwrap_or" || id->name == "expect") {
        const bool is_expect = (id->name == "expect");
        const char *bn = id->name.c_str();
        if (e->args.size() != 2) {
            diags_.error(e->loc, std::string(bn) +
                                     ": se esperaban 2 argumentos, recibidos " +
                                     std::to_string(e->args.size()));
            e->result_type = Type{};
            return Type{};
        }
        Type at = check_expr(e->args[0].get());
        Type second = check_expr(e->args[1].get());
        // El tipo del valor: el payload si es un Optional, el propio tipo si
        // es una referencia nullable.
        Type rt = at;
        if (at.kind == PrimitiveKind::OPTIONAL && at.pointee)
            rt = *at.pointee;
        else if (at.kind != PrimitiveKind::CLASS &&
                 at.kind != PrimitiveKind::PTR &&
                 at.kind != PrimitiveKind::I64 &&
                 at.kind != PrimitiveKind::COUNT &&
                 !type_is_overlay_handle(struct_layouts_, at)) {
            diags_.error(e->args[0]->loc,
                         std::string(bn) +
                             ": el primer argumento debe ser una referencia "
                             "o Optional<T>, no '" +
                             type_to_string(at) + "'");
        }
        if (is_expect) {
            // El mensaje: una cadena, y del tiron -- tiene que estar en el
            // binario, no calcularse.
            if (e->args[1]->kind != ast::NodeKind::StringLitExpr) {
                diags_.error(e->args[1]->loc,
                             "expect: el segundo argumento debe ser una cadena "
                             "escrita en el sitio, no '" +
                                 type_to_string(second) + "'");
            }
        } else if (!types_assignable(rt, second)) {
            diags_.error(e->args[1]->loc,
                         "unwrap_or: el valor por defecto es '" +
                             type_to_string(second) + "' y deberia ser '" +
                             type_to_string(rt) + "'");
        }
        e->result_type = rt;
        return rt;
    }
    // Builtins de Optional<T> (builtin del compilador).
    // Some(x) -> Optional<typeof(x)>: construye un Optional presente
    //           con el payload x.  El lowering emite un ALLOCA de 16
    //           bytes en stack + STORE 1 en +0 + STORE x en +8.
    if (id->name == "Some") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "Some: se esperaba 1 argumento, recibidos " +
                                     std::to_string(e->args.size()));
            e->result_type = Type{};
            return Type{};
        }
        // Sprint edge-bugs (2026-06-02): propagar expected_optional_type_
        // al inner cuando esperamos Optional<Optional<T>>.  Sin esto el
        // inner Some infiere T por defecto del literal (i64) en vez de
        // del contexto outer (Optional<i32>).
        const Type saved_outer_opt = expected_optional_type_;
        if (expected_optional_type_.kind == PrimitiveKind::OPTIONAL &&
            expected_optional_type_.pointee &&
            expected_optional_type_.pointee->kind == PrimitiveKind::OPTIONAL) {
            expected_optional_type_ = *expected_optional_type_.pointee;
        } else {
            /* Si el inner no es Optional, deshabilitar la propagacion
             * para que el inner check_expr no la malinterprete. */
            expected_optional_type_ = Type{};
        }
        Type at = check_expr(e->args[0].get());
        expected_optional_type_ = saved_outer_opt;
        // Bug fix 2026-05-23: propagar el T esperado del Optional cuando
        // hay contexto.  Acepta el arg si es asignable al T esperado.
        Type final_t = at;
        if (expected_optional_type_.kind == PrimitiveKind::OPTIONAL &&
            expected_optional_type_.pointee) {
            const Type &want = *expected_optional_type_.pointee;
            if (at.kind == PrimitiveKind::COUNT || types_assignable(want, at)) {
                final_t = want;
            }
        }
        Type rt = Type::make_optional(final_t);
        e->result_type = rt;
        return rt;
    }
    // None() -> Optional<T> donde T es del contexto si existe; sino i64.
    if (id->name == "None") {
        if (!e->args.empty()) {
            diags_.error(e->loc, "None: no acepta argumentos");
        }
        Type t_inner{PrimitiveKind::I64};
        if (expected_optional_type_.kind == PrimitiveKind::OPTIONAL &&
            expected_optional_type_.pointee) {
            t_inner = *expected_optional_type_.pointee;
        }
        Type rt = Type::make_optional(t_inner);
        e->result_type = rt;
        return rt;
    }
    // Builtins de Result<V, E>.
    // Ok(v) y Err(e) construyen Result<V, ?>; el tipo de error o
    // valor faltante debe inferirse del contexto (asignacion,
    // return).  Para MVP devolvemos Result con un placeholder; la
    // unificacion con el tipo declarado se hace en check_var_decl.
    if (id->name == "Ok") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "Ok: se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        Type vt = check_expr(e->args[0].get());
        // Bug fix 2026-05-23: si hay contexto Result<V,E> esperado,
        // usar V y E del contexto en vez de placeholders.  V: si el arg
        // es asignable al V esperado (numerico permite coercion),
        // sobreescribir vt.  E: siempre tomar el E del contexto.
        Type final_v = vt;
        Type final_e{PrimitiveKind::I64};
        if (expected_result_type_.kind == PrimitiveKind::RESULT &&
            expected_result_type_.pointee && expected_result_type_.pointee2) {
            const Type &want_v = *expected_result_type_.pointee;
            const Type &want_e = *expected_result_type_.pointee2;
            if (vt.kind == PrimitiveKind::COUNT ||
                types_assignable(want_v, vt)) {
                final_v = want_v;
            }
            final_e = want_e;
        }
        Type rt = Type::make_result(final_v, final_e);
        e->result_type = rt;
        return rt;
    }
    if (id->name == "Err") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "Err: se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        // Bug fix 2026-05-23: propagar contexto Result<V,E> al Err.
        // Antes de check_expr del arg, si el contexto E es STRING,
        // permitimos que el arg sea StringLitExpr (que normalmente seria
        // PTR).  El lowering hace la promotion via STRMAKE.
        Type et = check_expr(e->args[0].get());
        Type final_e = et;
        Type final_v{PrimitiveKind::I64};
        if (expected_result_type_.kind == PrimitiveKind::RESULT &&
            expected_result_type_.pointee && expected_result_type_.pointee2) {
            const Type &want_v = *expected_result_type_.pointee;
            const Type &want_e = *expected_result_type_.pointee2;
            // Permitir coercion del arg al E esperado.
            if (et.kind == PrimitiveKind::COUNT ||
                types_assignable(want_e, et)
                // Caso especial: literal string (PTR) -> STRING.
                || (want_e.kind == PrimitiveKind::STRING &&
                    et.kind == PrimitiveKind::PTR && e->args[0] &&
                    e->args[0]->kind == ast::NodeKind::StringLitExpr)) {
                final_e = want_e;
            }
            final_v = want_v;
        }
        Type rt = Type::make_result(final_v, final_e);
        e->result_type = rt;
        return rt;
    }
    if (id->name == "isOk") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "isOk: se esperaba 1 argumento");
        } else {
            Type at = check_expr(e->args[0].get());
            if (at.kind != PrimitiveKind::RESULT &&
                at.kind != PrimitiveKind::COUNT) {
                diags_.error(e->loc,
                             "isOk: el argumento debe ser Result<V,E>, no '" +
                                 type_to_string(at) + "'");
            }
        }
        const Type rt{PrimitiveKind::I32};
        e->result_type = rt;
        return rt;
    }
    if (id->name == "value" || id->name == "error") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, id->name + ": se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        Type at = check_expr(e->args[0].get());
        if (at.kind != PrimitiveKind::RESULT) {
            diags_.error(
                e->loc, id->name + ": el argumento debe ser Result<V,E>, no '" +
                            type_to_string(at) + "'");
            e->result_type = Type{};
            return Type{};
        }
        Type rt = (id->name == "value") ? (at.pointee ? *at.pointee : Type{})
                                        : (at.pointee2 ? *at.pointee2 : Type{});
        e->result_type = rt;
        return rt;
    }

    // ===================================================================
    // Builtins de smart pointers: unique<T> y shared<T>.
    // ===================================================================
    //
    // Modelo de inferencia: estos builtins devuelven un tipo "generico"
    // con T = typeof(arg) (o U8 placeholder si el arg es count).  La
    // unificacion con el tipo declarado del LHS la hace check_var_decl
    // mediante types_assignable (que admite cualquier T compatible).
    //
    // `unique_box(value)` -> unique<typeof(value)>
    //   Aloca un slot host_ptr para `value` y lo guarda.  Deleter por
    //   defecto: `free` (Tier 0).  El lowering emite malloc(sizeof(T)) +
    //   STORE value + cleanup CALL free al exit del scope.
    if (id->name == "unique_box" || id->name == "shared_box") {
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         id->name +
                             ": se esperaba 1 argumento (valor a envolver)");
            e->result_type = Type{};
            return Type{};
        }
        // M7 / Opcion B: si el arg es un InitListExpr anonimo y el
        // contexto (return type de la funcion actual) es unique<T>/
        // shared<T> con T struct, anotar target_type_name antes del
        // check_expr para que el init list se resuelva contra T.
        // Cubre `return unique_box({.x=10, .y=20})` y similares fuera
        // de var-decl (donde check_var_decl ya anota).
        if (e->args[0]->kind == ast::NodeKind::InitListExpr) {
            auto *il = static_cast<ast::InitListExpr *>(e->args[0].get());
            if (il->target_type_name.empty() &&
                current_fn_return_type_.kind ==
                    (id->name == "unique_box" ? PrimitiveKind::UNIQUE_PTR
                                              : PrimitiveKind::SHARED_PTR) &&
                current_fn_return_type_.pointee &&
                current_fn_return_type_.pointee->kind ==
                    PrimitiveKind::STRUCT &&
                struct_layouts_.find(
                    current_fn_return_type_.pointee->struct_name) !=
                    struct_layouts_.end()) {
                il->target_type_name =
                    current_fn_return_type_.pointee->struct_name;
            }
        }
        Type vt = check_expr(e->args[0].get());
        if (vt.kind == PrimitiveKind::VOID || vt.kind == PrimitiveKind::COUNT) {
            diags_.error(e->loc, id->name + ": tipo del valor invalido ('" +
                                     type_to_string(vt) + "')");
        }
        Type rt = (id->name == "unique_box") ? Type::make_unique(vt)
                                             : Type::make_shared(vt);
        e->result_type = rt;
        return rt;
    }

    // ===================================================================
    // bug6 - `gc_box(value)` -> gc<typeof(value)>
    //   Aloja `value` en un bloque GC-managed (vx_gc_alloc_ptr) de
    //   sizeof(T) bytes y devuelve el host_ptr al box.  Generaliza el
    //   modelo gc<Clase> (que aloja la INSTANCIA de clase en el heap GC)
    //   a un T CUALQUIERA: primitivo (gc<i64>, gc<f64>), smart pointer
    //   (gc<unique<i64>>, gc<shared<i64>>) o anidamiento arbitrario de
    //   modelos de memoria (gc<shared<unique<i64>>>).  El valor interno se
    //   lee via `*g` (deref).  El GC recolecta la memoria del box.
    //
    //   CERO FUGA: si T posee un recurso con dtor (unique<T> -> deleter,
    //   shared<T> -> decref), el box arrastra el cleanup DETERMINISTA de T al
    //   salir de scope (mismo cleanup_stack_ + SMARTPTR_FREE/SHAREDPTR_REL que
    //   usa gc<Clase> con campo owned).  El dtor se invoca por CALL DIRECTO al
    //   deleter/decref concreto (dispatch estatico, sin vtable) -- portable en
    //   el interprete (bytecode arch-independiente) e identico en interp/JIT/
    //   AOT.  El payload del box tiene el MISMO layout que el slot del smart
    //   pointer (unique=16 / shared=8), asi que el cleanup opera sobre el box
    //   directamente.  Un T primitivo (gc<i64>, gc<f64>) no tiene dtor -> solo
    //   se recolecta la memoria del box, sin cleanup.
    // ===================================================================
    if (id->name == "gc_box") {
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         "gc_box: se esperaba 1 argumento (valor a envolver)");
            e->result_type = Type{};
            return Type{};
        }
        Type vt = check_expr(e->args[0].get());
        if (vt.kind == PrimitiveKind::VOID || vt.kind == PrimitiveKind::COUNT) {
            diags_.error(e->loc, "gc_box: tipo del valor invalido ('" +
                                     type_to_string(vt) + "')");
        }
        // El tipo resultante es el mismo T con gc_managed=true: unifica
        // contra el tipo declarado `gc<T>` (que type_from_node produce
        // como inner + gc_managed=true).
        Type rt = vt;
        rt.gc_managed = true;
        e->result_type = rt;
        return rt;
    }

    // ===================================================================
    // unique_with(value, deleter_fn) -> unique<typeof(value)>
    // shared_with(value, deleter_fn) -> shared<typeof(value)>
    //
    // Permite al programador especificar el alloc + dealloc para
    // cualquier recurso (memoria, archivos, sockets, handles OS, etc).
    // El primer argumento es el RESULTADO de la alocacion (ya hecho
    // por el usuario), y el segundo es el nombre de una funcion
    // (Vesta o extern) de aridad 1 que se invocara con el value al
    // exit del scope.
    //
    // Ejemplos:
    //   extern "kernel32" {
    //       fn VirtualAlloc(addr: u64, size: u64, t: u32, prot: u32) -> u64;
    //       fn VirtualFree(addr: u64, size: u64, type: u32) -> u32;
    //   }
    //   fn release_vmem(p: u64) { VirtualFree(p, 0, 0x8000); }
    //
    //   u64 mem = VirtualAlloc(0, 4096, 0x3000, 0x04);
    //   unique<i64> auto_mem = unique_with(mem, release_vmem);
    //   // ... usar auto_mem ... cleanup: release_vmem(mem) automatico
    // ===================================================================
    if (id->name == "unique_with" || id->name == "shared_with") {
        if (e->args.size() != 2) {
            diags_.error(e->loc,
                         id->name +
                             ": se esperaba 2 argumentos (value, deleter_fn)");
            e->result_type = Type{};
            return Type{};
        }
        Type vt = check_expr(e->args[0].get());
        if (vt.kind == PrimitiveKind::VOID || vt.kind == PrimitiveKind::COUNT) {
            diags_.error(e->loc, id->name + ": tipo del valor invalido ('" +
                                     type_to_string(vt) + "')");
        }
        // El segundo argumento debe ser IdentExpr de una funcion.
        if (e->args[1]->kind != ast::NodeKind::IdentExpr) {
            diags_.error(e->args[1]->loc,
                         id->name + ": el deleter debe ser un identificador de "
                                    "funcion (no una expresion)");
            e->result_type = Type{};
            return Type{};
        }
        auto *deleter_id = static_cast<ast::IdentExpr *>(e->args[1].get());
        const Symbol *del_sym = lookup(deleter_id->name);
        if (!del_sym) {
            diags_.error(e->args[1]->loc,
                         id->name + ": funcion deleter no declarada: '" +
                             deleter_id->name + "'");
            e->result_type = Type{};
            return Type{};
        }
        if (del_sym->kind != SymbolKind::Function) {
            diags_.error(e->args[1]->loc,
                         id->name + ": '" + deleter_id->name +
                             "' no es una funcion (es " +
                             (del_sym->kind == SymbolKind::Variable
                                  ? "variable"
                                  : "constante") +
                             ")");
            e->result_type = Type{};
            return Type{};
        }
        const FunctionSig &sig = function_sigs_[del_sym->sig_index];
        if (sig.param_types.size() != 1) {
            diags_.error(e->args[1]->loc,
                         id->name + ": el deleter '" + deleter_id->name +
                             "' debe tener aridad 1, tiene " +
                             std::to_string(sig.param_types.size()));
            e->result_type = Type{};
            return Type{};
        }
        // Validar que el tipo del parametro del deleter sea compatible
        // con el value (laxa: aceptamos tipos numericos o ptr equivalentes).
        const Type &pt = sig.param_types[0];
        if (!types_assignable(pt, vt) &&
            !(is_numeric(pt.kind) && is_numeric(vt.kind))) {
            diags_.error(e->args[1]->loc,
                         id->name + ": parametro del deleter '" +
                             type_to_string(pt) +
                             "' incompatible con tipo del value '" +
                             type_to_string(vt) + "'");
        }
        // Marcamos el deleter_id para que el lowering sepa que es
        // referencia a funcion (no llamada).  Usamos result_type
        // FUNCTION para distinguir.  El lowering NO debe bajar este
        // IdentExpr a un valor; en su lugar lee el nombre y emite
        // el cleanup apropiado.
        deleter_id->result_type =
            Type::make_function(sig.param_types, sig.return_type);
        Type rt = (id->name == "unique_with") ? Type::make_unique(vt)
                                              : Type::make_shared(vt);
        /* QUIEN LIBERA va en el TIPO.  Antes viajaba por un canal lateral del
         * bajado (`pending_smartptr_deleter_`), que solo alcanzaba a la
         * declaracion de al lado: en cuanto el puntero cruzaba una funcion
         * habia que leer el liberador de la ranura EN EJECUCION, y por eso la
         * ranura media dos palabras.  Dicho en el tipo, quien limpia lo sabe
         * al compilar en todos los casos. */
        rt.deleter_name = deleter_id->name;
        e->result_type = rt;
        return rt;
    }

    // `move(p)` -> typeof(p): transfiere ownership.  El compilador
    // marca p como "consumed" via flag en lowering; un uso posterior
    // de p sera comprobado por el cleanup (binding = 0, skip).
    // Borrow checker R3: prohibe mover si p tiene borrows activos.
    // Z.8 builtins: atomic primitives + raw shared malloc/free.
    // atomic_load_i64(host_ptr) -> i64                    (acquire)
    // atomic_store_i64(host_ptr, val: i64) -> void        (release)
    // atomic_cas_i64(host_ptr, exp: i64, des: i64) -> i64 (acq_rel, retorna
    // OLD) atomic_add_i64(host_ptr, delta: i64) -> i64         (acq_rel,
    // retorna OLD) shared_malloc(size: u64) -> i64* (host_ptr) -- aloca en
    // SharedHeap shared_free(ptr: i64*) -> void
    if (id->name == "atomic_load_i64") {
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         "atomic_load_i64: se esperaba 1 argumento (host_ptr)");
            e->result_type = Type{};
            return Type{};
        }
        (void)check_expr(e->args[0].get());
        e->result_type = Type{PrimitiveKind::I64};
        return e->result_type;
    }
    if (id->name == "atomic_store_i64") {
        if (e->args.size() != 2) {
            diags_.error(
                e->loc,
                "atomic_store_i64: se esperaba 2 argumentos (host_ptr, val)");
            e->result_type = Type{};
            return Type{};
        }
        (void)check_expr(e->args[0].get());
        (void)check_expr(e->args[1].get());
        e->result_type = Type{PrimitiveKind::VOID};
        return e->result_type;
    }
    if (id->name == "atomic_cas_i64") {
        if (e->args.size() != 3) {
            diags_.error(e->loc, "atomic_cas_i64: se esperaba 3 argumentos "
                                 "(host_ptr, exp, des)");
            e->result_type = Type{};
            return Type{};
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        e->result_type = Type{PrimitiveKind::I64};
        return e->result_type;
    }
    if (id->name == "atomic_add_i64") {
        if (e->args.size() != 2) {
            diags_.error(
                e->loc,
                "atomic_add_i64: se esperaba 2 argumentos (host_ptr, delta)");
            e->result_type = Type{};
            return Type{};
        }
        (void)check_expr(e->args[0].get());
        (void)check_expr(e->args[1].get());
        e->result_type = Type{PrimitiveKind::I64};
        return e->result_type;
    }
    // Atomicos GENERICOS width-aware: el resultado es el POINTEE del puntero
    // (arg 0).  atomic_load(T*)->T, atomic_store(T*,T)->void,
    // atomic_cas(T*,T,T)->T, atomic_add(T*,T)->T.  El ancho de la op lo saca el
    // lowering del mismo pointee.  Los usa atomic<T> para 1/2/4/8 bytes.
    if (id->name == "atomic_load" || id->name == "atomic_store" ||
        id->name == "atomic_cas" || id->name == "atomic_add") {
        const size_t need = (id->name == "atomic_load")  ? 1
                            : (id->name == "atomic_cas") ? 3
                                                         : 2;
        if (e->args.size() != need) {
            diags_.error(e->loc, id->name +
                                     ": aridad incorrecta para el atomico "
                                     "generico");
            e->result_type = Type{};
            return Type{};
        }
        Type ptrt{};
        for (size_t i = 0; i < e->args.size(); ++i) {
            Type at = check_expr(e->args[i].get());
            if (i == 0) ptrt = at;
        }
        if (id->name == "atomic_store") {
            e->result_type = Type{PrimitiveKind::VOID};
        } else {
            e->result_type =
                ptrt.pointee ? *ptrt.pointee : Type{PrimitiveKind::I64};
        }
        return e->result_type;
    }
    if (id->name == "shared_malloc") {
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         "shared_malloc: se esperaba 1 argumento (size)");
            e->result_type = Type{};
            return Type{};
        }
        (void)check_expr(e->args[0].get());
        // Tipo de retorno: i64* host (puntero raw a memoria shared).
        Type ret;
        ret.kind = PrimitiveKind::PTR;
        ret.pointee = std::make_shared<Type>(Type{PrimitiveKind::I64});
        e->result_type = ret;
        return e->result_type;
    }
    if (id->name == "shared_free") {
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         "shared_free: se esperaba 1 argumento (host_ptr)");
            e->result_type = Type{};
            return Type{};
        }
        (void)check_expr(e->args[0].get());
        e->result_type = Type{PrimitiveKind::VOID};
        return e->result_type;
    }

    // Z.10: introspeccion del SharedHeap.
    //   shared_heap_live_count() -> u32  (handles vivos en SharedHandleTable)
    //   shared_heap_bytes() -> u64       (total bytes alocados live)
    //   shared_gc_collect() -> void      (placeholder hasta Z.10-ext)
    if (id->name == "shared_heap_live_count") {
        if (!e->args.empty()) {
            diags_.error(e->loc,
                         "shared_heap_live_count: no acepta argumentos");
            e->result_type = Type{};
            return Type{};
        }
        e->result_type = Type{PrimitiveKind::U32};
        return e->result_type;
    }
    if (id->name == "shared_heap_bytes") {
        if (!e->args.empty()) {
            diags_.error(e->loc, "shared_heap_bytes: no acepta argumentos");
            e->result_type = Type{};
            return Type{};
        }
        e->result_type = Type{PrimitiveKind::U64};
        return e->result_type;
    }
    if (id->name == "shared_gc_collect") {
        if (!e->args.empty()) {
            diags_.error(e->loc, "shared_gc_collect: no acepta argumentos");
            e->result_type = Type{};
            return Type{};
        }
        e->result_type = Type{PrimitiveKind::VOID};
        return e->result_type;
    }

    // Z.6 builtins: is_shared(obj) / share(obj) / unshare(obj).
    // - is_shared(obj) -> bool: chequea bit 31 del handle subyacente.
    //   Acepta cualquier CLASS / STRING / ARRAY (todo objeto GC).
    // - share(obj): promueve in-place al SharedHeap.  No-op si ya shared.
    //   Devuelve la misma referencia (mismo tipo).
    // - unshare(obj): deep-copy al gc_heap local.  Devuelve nueva ref local.
    //   Hoy v1 NO copia campos profundos (TODO Z.7 ext).
    if (id->name == "is_shared") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "is_shared: se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        Type at = check_expr(e->args[0].get());
        (void)at; // acepta cualquier tipo referencia
        e->result_type = Type{PrimitiveKind::BOOL};
        return e->result_type;
    }
    if (id->name == "share") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "share: se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        Type at = check_expr(e->args[0].get());
        // share devuelve el mismo tipo (la referencia ahora apunta al
        // SharedHeap pero el tipo logico no cambia).
        e->result_type = at;
        return at;
    }
    if (id->name == "unshare") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "unshare: se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        Type at = check_expr(e->args[0].get());
        e->result_type = at;
        return at;
    }

    if (id->name == "move") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "move: se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        Type at = check_expr(e->args[0].get());
        if (at.kind != PrimitiveKind::UNIQUE_PTR &&
            at.kind != PrimitiveKind::SHARED_PTR &&
            at.kind != PrimitiveKind::COUNT) {
            diags_.error(
                e->loc,
                "move: el argumento debe ser unique<T> o shared<T>, no '" +
                    type_to_string(at) + "'");
            e->result_type = Type{};
            return Type{};
        }
        // Borrow checker R3: si el argumento es IdentExpr, validar
        // que no tenga borrows activos.
        if (e->args[0]->kind == ast::NodeKind::IdentExpr) {
            auto *idarg = static_cast<ast::IdentExpr *>(e->args[0].get());
            (void)borrow_checker_.on_owner_move(idarg->name, e->loc);
        }
        e->result_type = at;
        return at;
    }

    // `ptr_of(p)` -> T* host: extrae el puntero raw de un unique<T>
    // o shared<T> SIN consumir el smart pointer.  Para unique<T> es
    // p.ptr; para shared<T> es ctrl_block + 16 (offset del payload
    // inline).  El resultado es un T* host (movh).  Util para
    // operaciones que no deben extender la vida (e.g., pasar a una
    // funcion que no retiene el ptr).  Se llama `ptr_of` y no `get`
    // porque `get` ya es keyword reservada para properties (`get
    // name => expr`).
    if (id->name == "ptr_of") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "ptr_of: se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        Type at = check_expr(e->args[0].get());
        if (at.kind != PrimitiveKind::UNIQUE_PTR &&
            at.kind != PrimitiveKind::SHARED_PTR) {
            diags_.error(
                e->loc,
                "ptr_of: el argumento debe ser unique<T> o shared<T>, no '" +
                    type_to_string(at) + "'");
            e->result_type = Type{};
            return Type{};
        }
        // BugFix R2: para inner CLASS, devolver el tipo CLASS
        // directamente (no T*).  En Vesta una instancia CLASS ya es un
        // host_ptr al ObjectHeader; unique<Class> guarda el host_ptr
        // directo sin doble indireccion (M7 in-place).  Asi
        // `ptr_of(unique<Resource>).method()` funciona naturalmente.
        // Para primitivos (i32, f64, etc.) seguimos retornando T* porque
        // unique<i32> aloca un buffer host de 4 bytes.
        if (at.pointee && at.pointee->kind == PrimitiveKind::CLASS) {
            Type rt = *at.pointee;
            e->result_type = rt;
            return rt;
        }
        // T* host (is_virtual=false por defecto).
        Type rt = Type::make_ptr(at.pointee ? *at.pointee : Type{}, false);
        e->result_type = rt;
        return rt;
    }

    // ===================================================================
    // Builtins de borrow checker: lend / lend_mut / read_borrow / write_borrow
    // ===================================================================
    //
    //   lend(owner)        -> borrow<T> (shared)
    //   lend_mut(owner)    -> borrow_mut<T> (exclusive)
    //   read_borrow(b)     -> T (lee el contenido apuntado)
    //   write_borrow(m, v) -> void (escribe a traves del mut borrow)
    //
    // lend/lend_mut: valida R1/R2 via BorrowChecker.  El argumento
    // debe ser un IdentExpr (no se permite tomar borrow de una
    // expresion compleja porque no hay un "owner" estable).
    if (id->name == "lend" || id->name == "lend_mut") {
        const bool is_mut = (id->name == "lend_mut");
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         id->name +
                             ": se esperaba 1 argumento (el owner a prestar)");
            e->result_type = Type{};
            return Type{};
        }
        if (e->args[0]->kind != ast::NodeKind::IdentExpr) {
            diags_.error(e->args[0]->loc,
                         id->name + ": el argumento debe ser un identificador "
                                    "de variable (no una expresion)");
            e->result_type = Type{};
            return Type{};
        }
        auto *owner_id = static_cast<ast::IdentExpr *>(e->args[0].get());
        Type vt = check_expr(e->args[0].get());
        // bug3: rechazar lend(local_plain) en compile-time.
        // El modelo zero-cost del borrow checker requiere que el slot
        // del owner viva en HOST heap (host_ptr).  Para un local
        // primitivo declarado `i32 x = ...`, el slot vive en VM stack
        // (ALLOCA), no en host.  Si permitimos lend(local_plain), o
        // bien introducimos overhead runtime (RAW_ALLOC/RAW_FREE), o
        // bien rompemos la convencion uniforme borrow=host_ptr cuando
        // el borrow se pasa cross-funcion (la callee asumiria host
        // pero recibe VM addr -> corrupcion).
        //
        // Para mantener la promesa "borrow checker zero-cost", exigimos
        // que el owner sea unique<T>/shared<T> (host heap) o un borrow
        // anidado (reborrow).  Los locales primitivos plain deben
        // promocionarse explicitamente con `unique<T> x = unique_box(v)`.
        // Tipos cuyo "valor" YA es un host_ptr (lend zero-cost):
        //   UNIQUE_PTR     : slot 8B con host_ptr al payload.
        //   SHARED_PTR     : ctrl_block en GcHeap; lend devuelve payload@16.
        //   BORROW/_MUT    : reborrow; el inner ya es host_ptr.
        //   CLASS          : variable contiene host_ptr al objeto GC.
        //   PTR is_virtual=false: raw host pointer (T* via malloc o &heap).
        // Resto (i32, struct VM-stack, VirtualPtr<T>, etc.): error.
        const bool owner_is_host = vt.kind == PrimitiveKind::UNIQUE_PTR ||
                                   vt.kind == PrimitiveKind::SHARED_PTR ||
                                   vt.kind == PrimitiveKind::BORROW ||
                                   vt.kind == PrimitiveKind::BORROW_MUT ||
                                   vt.kind == PrimitiveKind::CLASS ||
                                   ((vt.kind == PrimitiveKind::PTR ||
                                     vt.kind == PrimitiveKind::ARRAY) &&
                                    !vt.is_virtual);
        if (!owner_is_host && vt.kind != PrimitiveKind::COUNT &&
            vt.kind != PrimitiveKind::VOID) {
            diags_.error(
                e->loc,
                id->name + ": el owner '" + owner_id->name +
                    "' es un local plain.  El borrow checker zero-cost" +
                    " requiere que el owner viva en host heap: declara" + " '" +
                    owner_id->name + "' como `unique<" + type_to_string(vt) +
                    "> " + owner_id->name + " = unique_box(...)`" +
                    " en lugar de un local primitivo.");
            e->result_type = Type{};
            return Type{};
        }
        // El tipo del borrow es borrow<T> donde T es el tipo
        // logico del owner.
        Type inner;
        if ((vt.kind == PrimitiveKind::UNIQUE_PTR ||
             vt.kind == PrimitiveKind::SHARED_PTR) &&
            vt.pointee) {
            inner = *vt.pointee;
        } else if ((vt.kind == PrimitiveKind::BORROW ||
                    vt.kind == PrimitiveKind::BORROW_MUT) &&
                   vt.pointee) {
            // F3 - reborrow: lend(borrow_var) -> shared borrow.
            // lend_mut(borrow_mut_var) -> mut reborrow.  Validamos
            // que el reborrow_mut solo se aplique a borrow_mut, no
            // a borrow (upgrade shared->mut prohibido).
            if (is_mut && vt.kind == PrimitiveKind::BORROW) {
                diags_.error(
                    e->loc,
                    "lend_mut: no se puede crear borrow_mut a partir de borrow "
                    "shared (no se puede 'subir' la mutabilidad)");
            }
            inner = *vt.pointee;
        } else if ((vt.kind == PrimitiveKind::PTR ||
                    vt.kind == PrimitiveKind::ARRAY) &&
                   !vt.is_virtual && vt.pointee) {
            // Raw host pointer (T* o T[N] host): el inner es el pointee
            // (T), no el ptr mismo.  Semantica: lend(host_ptr_T) crea
            // borrow<T> que apunta al objeto pointed-to.
            inner = *vt.pointee;
        } else {
            inner = vt;
        }
        Type rt = Type::make_borrow(inner, is_mut);
        // F4 - propagar borrow_owner_source para lifetime tracking.
        // Si lend de un IdentExpr que es borrow: heredamos el source
        // (transitivo via reborrow).  Sino: el id es el owner directo.
        // IMPORTANTE: usamos @c borrow_owner_source de la expresion
        // (campo dedicado para tracking), NO @c Type::struct_name
        // que es parte de la identidad del tipo y romperia equality.
        if (vt.kind == PrimitiveKind::BORROW ||
            vt.kind == PrimitiveKind::BORROW_MUT) {
            e->borrow_owner_source =
                borrow_checker_.root_owner_of(owner_id->name);
            if (e->borrow_owner_source.empty()) {
                e->borrow_owner_source = owner_id->name;
            }
        } else {
            e->borrow_owner_source = owner_id->name;
        }
        // Registrar borrow en el borrow checker.  Para reborrow
        // (lend de un borrow_var), trazamos al owner root.
        std::string root_owner = owner_id->name;
        if (vt.kind == PrimitiveKind::BORROW ||
            vt.kind == PrimitiveKind::BORROW_MUT) {
            // root_owner = lookup_root_owner(owner_id->name)
            // El borrow checker mantiene borrows_ con owner real.
            // Necesitamos exponer ese lookup.
            root_owner = borrow_checker_.root_owner_of(owner_id->name);
            if (root_owner.empty()) root_owner = owner_id->name;
        }
        // F3 ext - suspend semantics: si la fuente es un borrow_mut
        // activo, suspendemos su estado antes de @c on_lend para que
        // R1 (exclusividad mutable) no falle.  El estado se restaura
        // cuando el reborrow recien creado dropea (NLL o exit scope).
        //
        // Cubre dos casos:
        //   1) lend_mut(borrow_mut_var) = reborrow mut.
        //   2) lend(borrow_mut_var)     = shared reborrow (rebaja temporal).
        //
        // Si la fuente es un borrow shared (no mut) o el owner directo,
        // no necesitamos suspend: el reborrow shared simplemente
        // incrementa shared_count, y el lend de owner directo aplica
        // las reglas normales.
        const bool source_is_mut_borrow =
            (vt.kind == PrimitiveKind::BORROW_MUT);
        if (source_is_mut_borrow) {
            (void)borrow_checker_.suspend_for_reborrow(owner_id->name);
        }
        (void)borrow_checker_.on_lend(
            root_owner,
            /*borrower_name=*/"", // VarDecl lo registra correctamente
            e->loc, is_mut);
        // F3 ext - marcar el binding pendiente como reborrow.  El
        // nombre real del reborrower se establece en check_var_decl;
        // alli leemos @c borrow_owner_source y comparamos con la
        // fuente.  Aqui guardamos la info en el AST node para que
        // check_var_decl pueda recuperarla sin re-analizar.
        if (source_is_mut_borrow) {
            e->borrow_reborrow_source_is_mut = true;
            e->borrow_reborrow_source_name = owner_id->name;
        }
        e->result_type = rt;
        return rt;
    }

    // read_borrow(b) -> T: lee el valor a traves del borrow.
    // Equivalente conceptual a `*b` (deref).  No requiere que el
    // borrow sea mut.
    if (id->name == "read_borrow") {
        if (e->args.size() != 1) {
            diags_.error(e->loc,
                         "read_borrow: se esperaba 1 argumento (un borrow)");
            e->result_type = Type{};
            return Type{};
        }
        Type bt = check_expr(e->args[0].get());
        if (bt.kind != PrimitiveKind::BORROW &&
            bt.kind != PrimitiveKind::BORROW_MUT) {
            diags_.error(e->args[0]->loc, "read_borrow: el argumento debe ser "
                                          "borrow<T> o borrow_mut<T>, no '" +
                                              type_to_string(bt) + "'");
            e->result_type = Type{};
            return Type{};
        }
        Type rt = bt.pointee ? *bt.pointee : Type{};
        e->result_type = rt;
        return rt;
    }

    // write_borrow(m, v) -> void: escribe a traves del mut borrow.
    // Solo admite borrow_mut<T>.
    if (id->name == "write_borrow") {
        if (e->args.size() != 2) {
            diags_.error(
                e->loc,
                "write_borrow: se esperaba 2 argumentos (borrow_mut, value)");
            e->result_type = Type{PrimitiveKind::VOID};
            return Type{PrimitiveKind::VOID};
        }
        Type bt = check_expr(e->args[0].get());
        Type vt = check_expr(e->args[1].get());
        if (bt.kind != PrimitiveKind::BORROW_MUT) {
            diags_.error(e->args[0]->loc, "write_borrow: el primer argumento "
                                          "debe ser borrow_mut<T>, no '" +
                                              type_to_string(bt) + "'");
        }
        if (bt.pointee && !types_assignable(*bt.pointee, vt)) {
            diags_.error(e->args[1]->loc,
                         "write_borrow: tipo del valor (" + type_to_string(vt) +
                             ") incompatible con el tipo del borrow (" +
                             type_to_string(bt.pointee ? *bt.pointee : Type{}) +
                             ")");
        }
        const Type rt{PrimitiveKind::VOID};
        e->result_type = rt;
        return rt;
    }

    // `use_count(s)` -> i64: refcount actual del shared<T>.  Util
    // para diagnostico; cero si el shared esta moved.  En MVP la
    // operacion lee directamente el campo refcount del control block.
    if (id->name == "use_count") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "use_count: se esperaba 1 argumento");
            e->result_type = Type{};
            return Type{};
        }
        Type at = check_expr(e->args[0].get());
        if (at.kind != PrimitiveKind::SHARED_PTR) {
            diags_.error(e->loc,
                         "use_count: el argumento debe ser shared<T>, no '" +
                             type_to_string(at) + "'");
        }
        const Type rt{PrimitiveKind::I64};
        e->result_type = rt;
        return rt;
    }

    /* A.43.16: @Macro -- comptime fn cuyo string de retorno se
     * INYECTA como codigo Vesta en el call site (auto-emit).  El
     * call site evalua la fn al compile-time, parsea el resultado
     * como expresion y type-checa la expresion en el contexto
     * actual.  El tipo retornado por el call es el de la expresion
     * generada, NO `string` (el tipo declarado de la fn). */
    {
        auto fn_it = comptime_fns_.find(id->name);
        if (fn_it != comptime_fns_.end() && fn_it->second &&
            fn_it->second->is_macro && current_fn_is_macro_) {
            /* Macro invocado DENTRO del body de OTRO macro (composicion /
             * recursion): NO se expande aqui -- el body del macro externo se
             * baja a IR y la llamada al macro interno se lowerea como una CALL
             * runtime a `__macro_<interno>` (que devuelve un StringObject).  El
             * tipo del call es STRING (el retorno declarado del macro), no la
             * expansion.  Sin esto, el type-check intentaria expandir el macro
             * interno con args RUNTIME (params del externo) -> "debe ser
             * comptime-evaluable a string" + cascada de errores VOID. */
            for (auto &a : e->args)
                (void)check_expr(a.get());
            e->result_type = Type{PrimitiveKind::STRING};
            return e->result_type;
        }
        if (fn_it != comptime_fns_.end() && fn_it->second &&
            fn_it->second->is_macro) {
            /* Pass-1 del two-phase: si algun ARG del macro resuelve a un valor
             * comptime aun DEFERIDO (p.ej. `inject(CODE)` con
             * `comptime string CODE = gen(...)` cuyo `gen` se rutea a la
             * ComptimeVM sin bytecode todavia), no podemos expandir el macro:
             * el arg no tiene valor real en esta pasada.  DIFERIMOS -> COUNT
             * (tipo "desconocido" que suprime los chequeos en cascada del
             * inicializador/interpolacion); pass-2 (con el bytecode cargado)
             * evalua los args reales y expande el macro.  Un arg no
             * comptime-evaluable devuelve ok=false (no deferred) y no dispara
             * esto -- solo los DEFERIDOS genuinos. */
            for (const auto &a : e->args) {
                if (!a) continue;
                const ComptimeEvalResult ar =
                    comptime_eval_expr(*this, a.get());
                if (ar.deferred) {
                    e->result_type = Type{PrimitiveKind::COUNT};
                    return e->result_type;
                }
            }
            /*  MC.9/MC.10: VM eval es el camino DEFAULT cuando
             * el bytecode esta disponible.  Sin flags ni opt-in: si
             * @c comptime_runtime_ tiene el macro registrado y los
             * args son codificables como uint64, invocamos via VM.
             * Fallback transparente al AST evaluator si la VM falla
             * o si los args no son encodables.  El bytecode se
             * popula automaticamente via two- compile (main.cpp
             * orquestador) sin intervencion del usuario. */
            ComptimeEvalResult r;
            bool used_vm = false;
            if ((comptime_runtime_.registered_macro_count() > 0) &&
                e->args.size() <= 12) {
                std::vector<uint64_t> arg_words;
                if (marshal_const_args(*e, arg_words)) {
                    std::string vm_out;
                    /* si el macro es @Pure, usar la
                     * variante memoized (cache HOST-side @c
                     * (macro,args) -> result).  Hits del cache no
                     * tocan la VM.  Si el macro no es @Pure, no
                     * cache; cada call site invoca el VM fresco. */
                    const bool is_pure = fn_it->second->is_pure;
                    const bool vm_ok =
                        comptime_runtime_.invoke_string_macro_memoized(
                            "__macro_" + id->name, arg_words, vm_out, is_pure);
                    if (vm_ok) {
                        r.ok = true;
                        r.is_str = true;
                        r.str = std::move(vm_out);
                        used_vm = true;
                        ++macro_vmonly_hits_;
                    } else {
                        ++macro_vmonly_misses_;
                    }
                }
            }
            /* Fallback AST: corre solo si VM-only no aplico o fallo. */
            if (!used_vm) {
                r = comptime_eval_expr(*this, e);
            }
            /* Pass-1 del two-phase: si la expansion del macro es DEFERIDA (sus
             * args dependen de un valor comptime que aun no esta disponible
             * porque la ComptimeVM no esta cargada -- p.ej. `inject(CODE)` con
             * `comptime string CODE = gen(...)` ruteado a la VM), NO parseamos
             * el resultado (vacio) ni erramos.  Devolvemos el sentinel COUNT
             * (tipo "desconocido") que suprime los chequeos en cascada del
             * inicializador/interpolacion; pass-2 (con VESTA_MC_PREBUILT) tiene
             * el bytecode, regenera el cuerpo real y resuelve el tipo. */
            if (r.deferred) {
                e->result_type = Type{PrimitiveKind::COUNT};
                return e->result_type;
            }
            if (!r.ok || !r.is_str) {
                diags_.error(e->loc,
                             "@Macro '" + id->name +
                                 "' debe ser comptime-evaluable a string");
                return Type{};
            }
            /* Parsear el string como expresion Vesta. */
            /* El fragmento se parsea diciendo DE DONDE viene.  Sin esto, todo
             * lo que nace aqui lleva una posicion en un fichero que no existe
             * -- `<macro:X>` linea 3 -- y un fallo dentro del codigo generado
             * no se puede explicar: no hay fuente que enseñar ni sitio al que
             * mandar a mirar.  Con la procedencia se puede contar el camino:
             * esto lo genero tal macro, invocada aqui. */
            auto &exp =
                macro_expansions_[id->name + "@" + std::to_string(e->loc.line) +
                                  ":" + std::to_string(e->loc.column)];
            if (!exp) {
                exp = std::make_unique<ExpansionInfo>();
                exp->macro = id->name;
                exp->site = std::make_shared<SourceLoc>(e->loc);
            }
            Lexer fragment_lex(r.str, "<macro:" + id->name + ">", diags_,
                               exp.get());
            Parser fragment_par(fragment_lex, diags_);
            std::unique_ptr<ast::Expr> parsed = fragment_par.parse_one_expr();
            if (!parsed) {
                diags_.error(e->loc,
                             "@Macro '" + id->name +
                                 "' devolvio codigo no-parseable: " + r.str);
                return Type{};
            }
            parsed->loc = e->loc;
            /* Type-checar y guardar el AST para que el lowering lo recoja. */
            Type rt = check_expr(parsed.get());
            /* Si el macro se expandio a un literal string (`source(expr)` ->
             * `"texto"`), su tipo es STRING (no el char* raw que check_expr da
             * a un literal desnudo).  Asi la interpolacion `${macro()}` y las
             * asignaciones a `string` lo tratan como StringObject, no como
             * puntero crudo.  El lowering coacciona a StringObject. */
            if (parsed->kind == ast::NodeKind::StringLitExpr) {
                rt = Type{PrimitiveKind::STRING};
            }
            e->macro_expanded = std::move(parsed);
            e->result_type = rt;

            /* record SHADOW EXPECTATION para validacion
             * cruzada AST vs VM.  Solo registramos si:
             *   (a) Todos los args son literales codificables como
             *       uint64 (Int, Bool, Char, Null) -- el VM espera
             *       valores raw en R1..R12.  Otros tipos requeririan
             *       marshalling adicional que cae fuera del scope MC.8.
             *   (b) Hay <= 12 args (CALLVM convention).
             *
             * Si no encaja, simplemente no registramos -- la expansion
             * AST sigue siendo correcta y el shadow_validate solo
             * cubrira un subset de call sites en MC.8.  MC.9 ampliara
             * el marshalling para string args, structs, etc. */
            if (e->args.size() <= 12) {
                std::vector<uint64_t> arg_words;
                if (marshal_const_args(*e, arg_words)) {
                    const std::string src_loc =
                        e->loc.file + ":" + std::to_string(e->loc.line) + ":" +
                        std::to_string(e->loc.column);
                    comptime_runtime_.record_expectation(
                        id->name, std::move(arg_words), r.str, src_loc);
                }
            }
            return rt;
        }
    }

    size_t id_depth = 0;
    const Symbol *s = lookup_with_depth(id->name, &id_depth);
    if (!s) {
        // NS.1 fix: fallback de namespace para codigo emitido por comptime
        // (comptime_compile / comptime_emit_expr) cuyo string referencia un
        // hermano por su nombre PUBLICO (`doblar`), pero el simbolo real quedo
        // mangled por el namespace (`ejemplos__X__doblar`).  El string no lo
        // reescribe el flatten (es data), asi que aqui buscamos un match UNICO
        // que termine en `__<name>` y reescribimos la llamada.
        if (id->name.find("__") == std::string::npos) {
            const std::string suffix = "__" + id->name;
            std::string found;
            int matches = 0;
            for (const auto &kv : sig_by_name_) {
                const std::string &fn = kv.first;
                // Los helpers registrados para el cuerpo de una plantilla
                // importada NO participan: existen para que la plantilla
                // resuelva, no para que el consumidor los alcance por el
                // nombre corto que su `only` no pidio.
                if (template_only_fns_.count(fn)) continue;
                if (fn.size() > suffix.size() &&
                    fn.compare(fn.size() - suffix.size(), suffix.size(),
                               suffix) == 0) {
                    found = fn;
                    if (++matches > 1) break;
                }
            }
            if (matches == 1) {
                const_cast<ast::IdentExpr *>(id)->name = found;
                s = lookup_with_depth(found, &id_depth);
            }
        }
    }
    if (!s) {
        // Constructor de STRUCT: `u128(args)` donde el callee es el nombre de
        // un struct que declara uno o mas constructores.  Overload por aridad Y
        // tipos (types_assignable).  El resultado es un valor STRUCT; el
        // lowering baja a `<Struct>__ctor(this, args...)` con SRET.  (No
        // colisiona con `Struct.metodo()` / `Struct.default()` / `toString`,
        // que son FieldAccess, ni con `new` -- los structs no usan `new`.)
        auto it_sc = struct_layouts_.find(id->name);
        if (it_sc != struct_layouts_.end()) {
            const StructLayout &slay = it_sc->second;
            std::vector<Type> arg_types;
            arg_types.reserve(e->args.size());
            for (auto &a : e->args)
                arg_types.push_back(check_expr(a.get()));
            const ClassMethodInfo *ctor = nullptr;
            bool any_ctor = false;
            for (const auto &m : slay.methods) {
                if (!m.is_constructor) continue;
                any_ctor = true;
                if (m.param_types.size() != arg_types.size()) continue;
                bool ok = true;
                for (size_t i = 0; i < arg_types.size(); ++i) {
                    if (arg_types[i].kind == PrimitiveKind::COUNT) continue;
                    if (!types_assignable(m.param_types[i], arg_types[i])) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    ctor = &m;
                    break;
                }
            }
            if (any_ctor) {
                if (!ctor) {
                    // Antes de rendirse: un constructor `comptime T(expr)`
                    // recoge la llamada precisamente cuando ninguna sobrecarga
                    // encaja.  Recibe la expresion sin evaluar, asi que sirve
                    // para lo que el lenguaje no sabe construir por sus medios
                    // -- un numero mas ancho que la palabra, por ejemplo.
                    for (const auto &m : it_sc->second.methods) {
                        if (!m.is_constructor || !m.is_comptime) continue;
                        for (auto &a : e->args)
                            (void)check_expr(a.get());
                        // La identidad es el nombre del LAYOUT, no la clave
                        // por la que se busco: un tipo importado se conoce por
                        // su nombre local y por el canonico, y devolver el
                        // local da dos identidades para el mismo tipo.
                        const std::string &tn_ct = it_sc->second.name.empty()
                                                       ? id->name
                                                       : it_sc->second.name;
                        e->comptime_ctor_type = tn_ct;
                        Type rtc{PrimitiveKind::STRUCT, tn_ct};
                        e->result_type = rtc;
                        return rtc;
                    }
                    diags_.error(e->loc,
                                 "ningun constructor de '" + id->name +
                                     "' coincide con los argumentos dados");
                    return Type{};
                }
                // La identidad es el nombre del LAYOUT, no la clave por la
                // que se busco: un tipo importado se conoce por su nombre
                // local y por el canonico, y devolver el local da dos
                // identidades para el mismo tipo.
                Type rt{PrimitiveKind::STRUCT, it_sc->second.name.empty()
                                                   ? id->name
                                                   : it_sc->second.name};
                // Si el constructor elegido es comptime, se deja anotado: el
                // lowering lo EJECUTA al compilar en vez de emitir la llamada,
                // y necesita saberlo aqui porque un tipo importado no llega
                // por el mismo camino que uno declarado en el fichero.
                if (ctor != nullptr && ctor->is_comptime)
                    e->comptime_ctor_type = rt.struct_name;
                e->result_type = rt;
                return rt;
            }
            // Struct SIN constructores declarados + 0 args: `Struct()` es el
            // constructor por defecto (equivalente a `Struct{}`): cada campo
            // toma su valor por defecto (o cero).  El lowering lo trata como un
            // init con defaults.  Con args, cae al error (no hay ctor que los
            // acepte).
            if (arg_types.empty()) {
                Type rt{PrimitiveKind::STRUCT, id->name};
                e->result_type = rt;
                e->is_default_struct_ctor = true;
                return rt;
            }
        }
        // Antes de decir "no declarada", comprobar si el nombre existe pero
        // bajo una @Target que no se cumple aqui: es una situacion muy
        // distinta y merece un mensaje que lo diga.
        if (const auto *specs = target_skipped_for(id->name)) {
            std::string lista;
            for (size_t i = 0; i < specs->size(); ++i) {
                if (i) lista += ", ";
                lista += (*specs)[i];
            }
            diags_.diag(e->loc, DiagLevel::ERR,
                        specs->size() == 1 ? "VX4001" : "VX4002",
                        {id->name, lista});
            for (auto &a : e->args)
                (void)check_expr(a.get());
            // COUNT = "tipo desconocido": el problema es el simbolo, no lo que
            // se hace con su resultado, asi que no se encadenan quejas sobre
            // un tipo de retorno que nunca se llego a conocer.
            return Type{PrimitiveKind::COUNT};
        }
        // Constructor comptime: `T(expr)` donde ninguna sobrecarga encaja.
        //
        // Se llega aqui cuando la resolucion normal ya ha fallado, que es
        // justo lo que se pretende: el constructor comptime NO compite con las
        // sobrecargas ni las ensombrece, actua cuando el lenguaje no sabe
        // construir el valor por sus medios.  Recibe la expresion SIN evaluar
        // -- por eso su parametro se declara `expr` -- de modo que sirve para
        // un literal mas ancho que la palabra igual que para cualquier otra
        // cosa que el tipo quiera interpretar por su cuenta.
        {
            const StructLayout *sl_ct = nullptr;
            auto it_sl = struct_layouts_.find(id->name);
            if (it_sl != struct_layouts_.end()) sl_ct = &it_sl->second;
            if (sl_ct != nullptr) {
                for (const auto &m : sl_ct->methods) {
                    if (!m.is_constructor || !m.is_comptime) continue;
                    // El tipo del valor es el propio struct; el constructor
                    // rellena `this` en tiempo de compilacion y su resultado
                    // se materializa donde estaba la llamada.
                    for (auto &a : e->args)
                        (void)check_expr(a.get());
                    e->comptime_ctor_type = id->name;
                    return Type{PrimitiveKind::STRUCT, id->name};
                }
            }
        }
        diags_.error(e->loc, "funcion no declarada: '" + id->name + "'");
        for (auto &a : e->args)
            (void)check_expr(a.get());
        return Type{};
    }
    // closures: si el simbolo es una variable de tipo FUNCTION
    // (function pointer / closure), tratamos esto como llamada
    // indirecta y devolvemos el return type del tipo.  Si la lambda
    // esta en stack del scope actual, no necesitamos captura; si la
    // variable vive en un scope exterior y estamos dentro de otra
    // lambda, registramos la captura igual que para variables
    // ordinarias (la rama esta en check_ident, pero aqui no pasamos
    // por check_ident, asi que replicamos la logica).
    if (s->kind != SymbolKind::Function &&
        s->type.kind == PrimitiveKind::FUNCTION) {
        // Captura como variable normal si aplica.
        if (!lambda_stack_.empty()) {
            for (auto &ctx : lambda_stack_) {
                if (id_depth < ctx.outer_depth) {
                    bool already = false;
                    for (auto &nm : ctx.expr->captures) {
                        if (nm == id->name) {
                            already = true;
                            break;
                        }
                    }
                    if (!already) {
                        ctx.expr->captures.push_back(id->name);
                        ctx.expr->capture_types.push_back(s->type);
                    }
                }
            }
        }
        const Type fn_type = s->type;
        /* Con un variadico la aridad no es exacta: los de delante son
         * obligatorios y de ahi en adelante vale cualquier cantidad. */
        const size_t fn_fixed =
            (fn_type.fn_is_variadic && !fn_type.fn_params.empty())
                ? fn_type.fn_params.size() - 1
                : fn_type.fn_params.size();
        // Validar aridad y tipos de los argumentos contra fn_params.
        if (fn_type.fn_is_variadic) {
            if (e->args.size() < fn_fixed)
                diags_.error(e->loc,
                             std::string("numero de argumentos insuficiente en "
                                         "llamada al closure variadico '") +
                                 id->name + "': minimo " +
                                 std::to_string(fn_fixed) + ", recibidos " +
                                 std::to_string(e->args.size()));
        } else if (e->args.size() != fn_type.fn_params.size()) {
            diags_.error(
                e->loc,
                std::string(
                    "numero de argumentos incorrecto en llamada al closure '") +
                    id->name + "': esperados " +
                    std::to_string(fn_type.fn_params.size()) + ", recibidos " +
                    std::to_string(e->args.size()));
        }
        const size_t n =
            fn_type.fn_is_variadic
                ? e->args.size()
                : std::min(e->args.size(), fn_type.fn_params.size());
        /* El que sobra se compara con el tipo del ELEMENTO: el parametro
         * declarado es ya la direccion del array. */
        const Type var_elem =
            (fn_type.fn_is_variadic && !fn_type.fn_params.empty() &&
             fn_type.fn_params.back().pointee)
                ? *fn_type.fn_params.back().pointee
                : Type{};
        for (size_t i = 0; i < n; ++i)
            check_call_arg(e->args[i].get(),
                           (i >= fn_fixed) ? var_elem : fn_type.fn_params[i],
                           i);
        for (size_t i = n; i < e->args.size(); ++i)
            (void)check_expr(e->args[i].get());
        // Marcar el callee con el tipo function para que el lowering
        // sepa que es una llamada indirecta a closure.
        e->callee->result_type = fn_type;
        return fn_type.pointee ? *fn_type.pointee : Type{PrimitiveKind::VOID};
    }
    // Sobrecarga de `()` y de `{}`: `c(4,4,4)` / `c{3,4,5}` sobre una VARIABLE
    // de un tipo que declara `__call__` / `__braces__` se reescribe a
    // `c.__call__(4,4,4)` / `c.__braces__(3,4,5)` y se re-chequea.  Asi el
    // resto del pipeline (chequeo de args, marshalling, SRET, lowering) ve una
    // llamada a metodo normal, sin codigo nuevo.  Son operadores DISTINTOS: un
    // tipo puede definir uno, el otro o los dos.  Si no declara el que toca, el
    // error de abajo lo dice: la sintaxis solo existe si el tipo la define.
    if (s->kind == SymbolKind::Variable &&
        (s->type.kind == PrimitiveKind::CLASS ||
         s->type.kind == PrimitiveKind::STRUCT)) {
        const char *dn = e->is_braces_call ? "__braces__" : "__call__";
        if (const std::vector<ClassMethodInfo> *ms = methods_of_type(s->type)) {
            for (const auto &m : *ms) {
                if (m.is_constructor || m.is_static) continue;
                if (m.name != dn) continue;
                auto fa = std::make_unique<ast::FieldAccessExpr>();
                fa->loc = e->callee->loc;
                fa->field_name = dn;
                fa->base = std::move(e->callee);
                fa->base->result_type = s->type;
                e->callee = std::move(fa);
                return check_call(e);
            }
        }
    }
    if (e->is_braces_call) {
        diags_.error(e->loc, "'" + id->name +
                                 "' no soporta la sintaxis '{...}'"
                                 " (su tipo no declara "
                                 "'__braces__')");
        for (auto &a : e->args)
            (void)check_expr(a.get());
        return Type{};
    }
    if (s->kind != SymbolKind::Function) {
        diags_.error(e->loc, "'" + id->name + "' no es una funcion");
        for (auto &a : e->args)
            (void)check_expr(a.get());
        return Type{};
    }
    const FunctionSig &sig = function_sigs_[s->sig_index];

    // dispose(xs) acepta cualquier tipo coleccion (no solo I64).
    // Validamos que el arg es un IdentExpr (necesario en el lowering
    // para reescribir el local) y que su tipo es uno de los tipos
    // coleccion primitivos.
    if (id->name == "dispose") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "'dispose' espera exactamente 1 argumento");
        } else {
            Type ta = check_expr(e->args[0].get());
            if (!is_col_kind(ta.kind)) {
                diags_.error(
                    e->args[0]->loc,
                    std::string(
                        "'dispose' requiere un tipo coleccion, recibido ") +
                        type_to_string(ta));
            }
            if (e->args[0]->kind != ast::NodeKind::IdentExpr) {
                diags_.error(e->args[0]->loc,
                             "'dispose' requiere un identificador local (no "
                             "expresion compuesta)");
            }
        }
        return Type{PrimitiveKind::VOID};
    }

    // ffi_call(fn, ...) es variadic 1+0..12.  Bypass del strict
    // type-check de aridad.  El primer arg debe ser i64 (puntero a
    // funcion); los siguientes (0..12) son argumentos opacos i64 que
    // el lowering empaqueta en R01..R12 antes del callni.  Cada uno
    // se chequea con check_expr para detectar errores semanticos
    // basicos pero no se valida tipo (todos se tratan como i64 en
    // la calling convention nativa).
    if (id->name == "ffi_call") {
        if (e->args.empty()) {
            diags_.error(
                e->loc,
                "'ffi_call' requiere al menos 1 arg (puntero a funcion)");
        } else if (e->args.size() > 13) {
            diags_.error(
                e->loc,
                "'ffi_call' acepta como maximo 12 args ademas del puntero");
        }
        for (auto &a : e->args)
            (void)check_expr(a.get());
        return sig.return_type;
    }

    // print/println/echo aceptan cualquier tipo escalar como
    // arg[0] (despacha en lowering).  Bypass del strict type-check.
    // print_ptr/print_gchandle tambien son polimorficos: aceptan
    // CLASS, PTR, ARRAY, o entero arbitrario sin que el bypass del
    // type checker se queje del tipo.  El lowering despacha al
    // CALLN apropiado convirtiendo a uint64.
    /* Sprint B.1: as_native_callback(fn_name) bypass.  Acepta IdentExpr
     * que resuelve a Function (no a Variable).  Captura el nombre +
     * argc para que el lowering emita la secuencia correcta. */
    if (id->name == "as_native_callback") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "'as_native_callback' espera 1 argumento "
                                 "(nombre de funcion Vesta)");
            return Type{PrimitiveKind::I64};
        }
        auto *fn_id = dynamic_cast<ast::IdentExpr *>(e->args[0].get());
        if (fn_id == nullptr) {
            diags_.error(e->args[0]->loc,
                         "'as_native_callback' requiere un identificador de "
                         "funcion (no expresion)");
            return Type{PrimitiveKind::I64};
        }
        /* Lookup del simbolo via lookup_with_depth. */
        size_t depth = 0;
        const Symbol *sym = lookup_with_depth(fn_id->name, &depth);
        if (sym == nullptr || sym->kind != SymbolKind::Function) {
            diags_.error(fn_id->loc, "'as_native_callback': '" + fn_id->name +
                                         "' no es una funcion conocida");
            return Type{PrimitiveKind::I64};
        }
        /* Marcamos result_type del IdentExpr como I64 sentinela para
         * que el lowering reconozca el patron (sin pasar por lower_ident
         * normal que daria error de simbolo). */
        fn_id->result_type = Type{PrimitiveKind::I64};
        return Type{PrimitiveKind::I64};
    }

    // fiber_entry(fn): direccion de ENTRADA (VA de bytecode VM) de una funcion
    // plana, para instalar como PC en un contexto de fibra (FN.1).  A
    // diferencia del cast `(cfn) fn` (que en interp/JIT enruta a naked_fnaddr
    // -> direccion NATIVA, correcta para codigo host), fiber_entry devuelve la
    // VA de BYTECODE porque el cuerpo de fibra corre como bytecode NORMAL (lo
    // arranca `swapctx` fijando el PC).  Mismo patron de bypass que
    // as_native_callback: acepta un identificador de funcion y devuelve U64.
    if (id->name == "fiber_entry") {
        if (e->args.size() != 1) {
            diags_.error(e->loc, "'fiber_entry' espera 1 argumento (nombre de "
                                 "funcion cuerpo de fibra)");
            return Type{PrimitiveKind::U64};
        }
        auto *fn_id = dynamic_cast<ast::IdentExpr *>(e->args[0].get());
        if (fn_id == nullptr) {
            diags_.error(e->args[0]->loc,
                         "'fiber_entry' requiere un identificador de funcion");
            return Type{PrimitiveKind::U64};
        }
        size_t fe_depth = 0;
        const Symbol *sym = lookup_with_depth(fn_id->name, &fe_depth);
        if (sym == nullptr || sym->kind != SymbolKind::Function) {
            diags_.error(fn_id->loc, "'fiber_entry': '" + fn_id->name +
                                         "' no es una funcion conocida");
            return Type{PrimitiveKind::U64};
        }
        // Sentinela U64 para que el lowering reconozca el patron sin pasar por
        // lower_ident (que daria error de simbolo para un nombre de funcion).
        fn_id->result_type = Type{PrimitiveKind::U64};
        return Type{PrimitiveKind::U64};
    }

    const bool is_io_print_relaxed =
        (id->name == "print" || id->name == "println" || id->name == "echo" ||
         id->name == "print_ptr" || id->name == "print_gchandle");
    if (is_io_print_relaxed) {
        if (e->args.size() != 1) {
            diags_.error(e->loc, std::string("'") + id->name +
                                     "' espera exactamente 1 argumento");
        } else {
            Type ta = check_expr(e->args[0].get());
            if (ta.kind == PrimitiveKind::VOID ||
                ta.kind == PrimitiveKind::COUNT) {
                diags_.error(e->args[0]->loc,
                             std::string("'") + id->name +
                                 "' no acepta argumentos de tipo void");
            }
        }
        return sig.return_type;
    }

    // Variadicos (`fn foo(A a, T... rest)`): aridad >= numero de params FIJOS
    // (N-1).  Los args fijos se validan contra su tipo; los trailing (a partir
    // de N-1) contra el tipo del ELEMENTO T.  El lowering empaqueta los
    // trailing en un array de pila y pasa (ptr, count).
    if (sig.is_variadic) {
        // Variadico CRUDO (`...`): todos los param_types son FIJOS (el `...` no
        // aporta slot); los args trailing aceptan CUALQUIER tipo (no se
        // validan). Variadico EMPAQUETADO (`T... rest`): el ultimo param_type
        // es el T*, asi que hay N-1 fijos y los trailing se validan contra
        // variadic_elem.
        const bool raw = sig.is_raw_variadic;
        const size_t fixed =
            raw ? sig.param_types.size() : sig.param_types.size() - 1;
        if (e->args.size() < fixed) {
            diags_.error(e->loc,
                         std::string("numero de argumentos insuficiente en "
                                     "llamada variadica a '") +
                             id->name + "': minimo " + std::to_string(fixed) +
                             ", recibidos " + std::to_string(e->args.size()));
        }
        for (size_t i = 0; i < e->args.size(); ++i) {
            Type ta = check_expr(e->args[i].get());
            if (i >= fixed) {
                // Args del `...`: crudos = cualquier tipo (sin check);
                // empaquetados = contra variadic_elem.
                if (raw) continue;
                const Type tp = sig.variadic_elem;
                if (ta.kind != PrimitiveKind::COUNT &&
                    !types_assignable(tp, ta) &&
                    !value_assignable_to_interface(tp, ta)) {
                    diags_.error(e->args[i]->loc,
                                 std::string("argumento ") +
                                     std::to_string(i + 1) + ": tipo (" +
                                     type_to_string(ta) +
                                     ") incompatible con elemento variadico (" +
                                     type_to_string(tp) + ")");
                }
                continue;
            }
            const Type tp = sig.param_types[i];
            if (numeric_const_fits_newtype(tp, ta, e->args[i].get())) {
                e->args[i]->result_type = tp; // el literal es del newtype
            } else if (ta.kind != PrimitiveKind::COUNT &&
                       !types_assignable(tp, ta) &&
                       !class_is_assignable(tp, ta) &&
                       !value_assignable_to_interface(tp, ta) &&
                       !struct_ptr_upcast_ok(tp, ta)) {
                diags_.error(e->args[i]->loc,
                             std::string("argumento ") + std::to_string(i + 1) +
                                 ": tipo (" + type_to_string(ta) +
                                 ") incompatible con parametro (" +
                                 type_to_string(tp) + ")");
            }
        }
        e->result_type = sig.return_type;
        return sig.return_type;
    }

    // Aridad.
    if (e->args.size() != sig.param_types.size()) {
        diags_.error(
            e->loc,
            std::string("numero de argumentos incorrecto en llamada a '") +
                id->name + "': esperados " +
                std::to_string(sig.param_types.size()) + ", recibidos " +
                std::to_string(e->args.size()));
    }
    // Tipos de cada arg.  Usamos types_assignable para admitir las
    // mismas conversiones implicitas que en var-decl/asignacion
    // (numericos entre si, void* <-> T*).  Para builtins generic-like
    // como free(PTR), el parametro declarado es PTR sin pointee
    // (equivalente a void*) y types_assignable acepta cualquier T*.
    const size_t n = std::min(e->args.size(), sig.param_types.size());
    for (size_t i = 0; i < n; ++i)
        check_call_arg(e->args[i].get(), sig.param_types[i], i);
    // Chequear los argumentos extra para sus efectos (si la aridad fallo).
    for (size_t i = n; i < e->args.size(); ++i)
        (void)check_expr(e->args[i].get());

    // F4 - lifetime elision rule 1: si la funcion devuelve borrow<T>
    // o borrow_mut<T> y tiene EXACTAMENTE un parametro borrow (o un
    // self CLASS implicito), el lifetime del retorno = lifetime de
    // ese argumento.  Propagamos el borrow_owner_source del arg a
    // la expresion CallExpr para que el caller pueda registrar el
    // nuevo borrow con el owner correcto.
    const Type &rty = sig.return_type;
    const bool ret_is_borrow = (rty.kind == PrimitiveKind::BORROW ||
                                rty.kind == PrimitiveKind::BORROW_MUT);
    if (ret_is_borrow) {
        size_t borrow_param_idx = SIZE_MAX;
        size_t borrow_param_count = 0;
        for (size_t i = 0; i < sig.param_types.size(); ++i) {
            if (sig.param_types[i].kind == PrimitiveKind::BORROW ||
                sig.param_types[i].kind == PrimitiveKind::BORROW_MUT) {
                borrow_param_idx = i;
                borrow_param_count++;
            }
        }
        if (borrow_param_count == 1 && borrow_param_idx < e->args.size()) {
            // Heredamos el source del arg correspondiente.
            const std::string &src =
                e->args[borrow_param_idx]->borrow_owner_source;
            if (!src.empty()) {
                e->borrow_owner_source = src;
            }
        } else if (borrow_param_count > 1) {
            diags_.warning(e->loc, "lifetime elision ambigua: la funcion '" +
                                       id->name +
                                       "' tiene multiples parametros borrow; "
                                       "la elision rule 1 no aplica.\n"
                                       "  El borrow retornado podria tener "
                                       "cualquiera de los lifetimes.\n"
                                       "  (Anotaciones explicitas no "
                                       "soportadas; considera reescribir.)");
        }
    }

    return sig.return_type;
}

} // namespace vx
