/**
 * @file module_interop.cpp
 * @brief Interop entre TypeChecker y formato @c .vxi ( M.2.d).
 *
 * Funciones libres en namespace @c vx que conectan el estado del
 * @c TypeChecker con un @c VxiModule:
 *
 *   - @c export_typechecker_to_vxi: extrae los simbolos publicos del
 *     TypeChecker a un @c VxiModule listo para serializar.  En el MVP
 *     todos los simbolos top-level son publicos; @c public/private
 *     explicito llega en M6.
 *
 *   - @c import_vxi_into_typechecker: inyecta los simbolos listados en
 *     @c only_symbols en las tablas del TypeChecker (type_aliases_,
 *     struct_layouts_, class_layouts_, enum_layouts_, function_sigs_).
 *
 * Las firmas viven en este TU (no en type_checker.h) para no forzar el
 * include de vxi_format.h en todos los consumidores del TypeChecker.
 * El compiler.cpp (en M2.e) las invoca explicitamente.
 */

#include "util/env_flags.h"
#include "vx/module/module_interop.h"

#include <algorithm>
#include <cassert>
#include <cstring>

#include "vx/comptime/comptime_introspect.h" // evaluar el init de una const publica
#include "vx/type_checker.h"
#include "vx/types.h"
#include "vx/module/vxi_format.h"
#include "vx/diagnostic.h" // #cross-module-generics: re-parse de templates
#include "vx/lexer.h"
#include "vx/generics/generic_clone.h" // rename_idents: helpers del modulo de la plantilla
#include "vx/parser.h"

namespace vx {

/// Cualifica @p name con @p ns_path (`a.b` + `T` -> `a__b__T`), pero SOLO si
/// no lo estaba ya.
///
/// La cualificacion tiene que ser IDEMPOTENTE: por una cadena de re-exports el
/// mismo nombre pasa por varios modulos, y prefijarlo en cada salto produce
/// `std__syscall__std__syscall__windows__std__ntwindows__std__types__uintptr`
/// -- un prefijo por eslabon -- con lo que el tipo deja de unificar consigo
/// mismo.
///
/// El criterio es el propio invariante del formato: un nombre PUBLICO corto
/// nunca lleva `__`, porque el exportador siempre lo parte en (ns_path, nombre
/// corto).  Asi que si ya lo lleva, es que viene cualificado y se respeta.
static std::string qualify_once_(const std::string &ns_path,
                                 const std::string &name) {
    if (name.find("__") != std::string::npos) return name; // ya cualificado
    std::string out;
    out.reserve(ns_path.size() + name.size() + 4);
    for (const char c : ns_path) {
        if (c == 0x2E)
            out += "__";
        else
            out.push_back(c);
    }
    out += "__";
    out += name;
    return out;
}

// ---------------------------------------------------------------------------
// Convertir un @c Type del checker a un typename canonico.  Usado para
// serializar tipos de fields, returns, params, etc.
// ---------------------------------------------------------------------------
static std::string canonical_typename_of(const Type &t) {
    // Newtype (typedef-new, p.ej. `uintptr`): enriquecer con su tipo SUBYACENTE
    // en la forma `nombre#underlying` (p.ej. `uintptr#u64`).  Asi un modulo que
    // importa una firma que USA el newtype PERO no importa su definicion puede
    // RECONSTRUIRLO (kind + nominal) sin tener el typedef local -- sin esto el
    // param resolvia a `void`.  type_to_string (usado en errores) NO cambia.
    if (t.nominal_id != 0 && !t.nominal_name.empty() && is_integral(t.kind)) {
        return t.nominal_name + "#" + type_to_string(Type{t.kind});
    }
    // Enum con valor: su `kind` es el del entero que lo respalda, asi que sin
    // el nombre viajaba como ese entero a secas.  Un metodo que devolvia
    // `Ordering` llegaba al consumidor devolviendo `i8`, y comparar el
    // resultado con `Ordering.Less` no compilaba: el enum perdia su identidad
    // al cruzar el modulo.  El marcador `enum:` lo distingue de un newtype, que
    // se reconstruye de otra forma.
    if (t.is_valued_enum && !t.struct_name.empty()) {
        return t.struct_name + "#enum:" + type_to_string(Type{t.kind});
    }
    // Tipos COMPUESTOS: recursar en cada sub-tipo con canonical_typename_of (no
    // con type_to_string) para que los newtypes ANIDADOS -- Optional<fiber>,
    // fiber*, Result<fiber, i32>, fn(fiber) -> ... -- tambien lleven su
    // `#underlying` y sean reconstruibles cross-modulo.  Sin esto solo el
    // newtype de TOP-LEVEL se enriquecia y `Optional<fiber>` se importaba como
    // `Optional<void>` (el payload `fiber` no resolvia -> match/unwrap/value
    // leian el payload con tipo void).  El formato coincide con type_to_string
    // y resolve_type_string.
    switch (t.kind) {
    case PrimitiveKind::PTR:
        if (t.pointee) {
            const std::string inner = canonical_typename_of(*t.pointee);
            return t.is_virtual ? ("VirtualPtr<" + inner + ">") : (inner + "*");
        }
        break;
    case PrimitiveKind::OPTIONAL:
        if (t.pointee)
            return "Optional<" + canonical_typename_of(*t.pointee) + ">";
        break;
    case PrimitiveKind::RESULT:
        if (t.pointee && t.pointee2)
            return "Result<" + canonical_typename_of(*t.pointee) + ", " +
                   canonical_typename_of(*t.pointee2) + ">";
        break;
    case PrimitiveKind::FUTURE:
        if (t.pointee)
            return "Future<" + canonical_typename_of(*t.pointee) + ">";
        break;
    case PrimitiveKind::UNIQUE_PTR:
        if (t.pointee)
            return "unique<" + canonical_typename_of(*t.pointee) + ">";
        break;
    case PrimitiveKind::SHARED_PTR:
        if (t.pointee)
            return "shared<" + canonical_typename_of(*t.pointee) + ">";
        break;
    case PrimitiveKind::FUNCTION: {
        // cfn (puntero a funcion crudo, 8 bytes) vs fn (lambda/fat pointer, 16
        // bytes) SOLO difieren en `fn_is_raw`.  Sin serializarlo, un typedef
        // `cfn(...)` importado de otro modulo se leia como `fn(...)` -> el
        // campo que lo usa se dimensionaba a 16 bytes y su default se promovia
        // a lambda -> el CALLIND llamaba al slot en vez de a la funcion
        // (crash).
        std::string s = t.fn_is_raw ? "cfn(" : "fn(";
        for (size_t i = 0; i < t.fn_params.size(); ++i) {
            if (i) s += ", ";
            s += canonical_typename_of(t.fn_params[i]);
        }
        s += ") -> ";
        s += t.pointee ? canonical_typename_of(*t.pointee) : "void";
        return s;
    }
    default: break;
    }
    // type_to_string ya produce un nombre canonico legible.  Por ejemplo:
    //   i32, u64*, Optional<i32>, Result<i32, string>, fn(i32) -> i64,
    //   VirtualPtr<T>, struct_name (para STRUCT), nominal_name (newtype).
    return type_to_string(t);
}

} // namespace vx

// ---------------------------------------------------------------------------
// resolve_type_string: re-parsea un typename canonico al Type del checker.
// Coverage v1 (M2 MVP):
//   - Primitivos: i8/i16/i32/i64, u8/u16/u32/u64, f32/f64, bool, char, void.
//   - string.
//   - Tipos nombrados ya conocidos en el checker (struct/class/enum/alias).
//   - Punteros `T*` (parsea recursivamente).
//   - Arrays `T[]` (decay, size=0).
//
// No cubre (deferred): fn(...), Optional<T>, Result<V,E>, VirtualPtr<T>,
// arrays con tamano explicito, generics anidados.  Estos casos requieren
// un mini-parser de tipos que llega en M5.
// ---------------------------------------------------------------------------
namespace vx {

// Helper: encuentra el ultimo `>` que coincide con el primer `<` en
// `prefix<contents>`.  Devuelve std::string::npos si no es la forma
// generica esperada.  Util para Optional<T>, Result<V,E>, fn(...), etc.
static size_t find_matching_close_(const std::string &s, size_t open_idx,
                                   char open_ch, char close_ch) noexcept {
    int depth = 1;
    for (size_t i = open_idx + 1; i < s.size(); ++i) {
        if (s[i] == open_ch)
            ++depth;
        else if (s[i] == close_ch) {
            if (--depth == 0) return i;
        }
    }
    return std::string::npos;
}

// Helper: separa una lista de tipos por comas a top-level (respetando
// anidamiento de < > / ( ) ).  Trimea espacios.
static std::vector<std::string> split_type_list_(const std::string &s) {
    std::vector<std::string> out;
    int depth_angle = 0, depth_paren = 0;
    std::string cur;
    cur.reserve(s.size());
    for (char c : s) {
        if (c == '<')
            ++depth_angle;
        else if (c == '>')
            --depth_angle;
        else if (c == '(')
            ++depth_paren;
        else if (c == ')')
            --depth_paren;
        if (c == ',' && depth_angle == 0 && depth_paren == 0) {
            // Trim
            size_t a = 0, b = cur.size();
            while (a < b && (cur[a] == ' ' || cur[a] == '\t'))
                ++a;
            while (b > a && (cur[b - 1] == ' ' || cur[b - 1] == '\t'))
                --b;
            out.push_back(cur.substr(a, b - a));
            cur.clear();
            continue;
        }
        cur.push_back(c);
    }
    if (!cur.empty()) {
        size_t a = 0, b = cur.size();
        while (a < b && (cur[a] == ' ' || cur[a] == '\t'))
            ++a;
        while (b > a && (cur[b - 1] == ' ' || cur[b - 1] == '\t'))
            --b;
        out.push_back(cur.substr(a, b - a));
    }
    return out;
}

Type TypeChecker::resolve_type_string(const std::string &type_str) const {
    if (type_str.empty()) return Type{};

    // Newtype enriquecido `nombre#underlying` (ver canonical_typename_of): un
    // typedef-new importado en una firma cuyo modulo NO define el newtype.  Si
    // el newtype SI esta definido localmente (mismo nombre en type_aliases_),
    // se prefiere esa definicion (id nominal consistente).  Si no, se
    // reconstruye: kind del underlying + nombre nominal + un id derivado
    // DETERMINISTICAMENTE del nombre (asi todas las referencias al mismo
    // newtype -- de cualquier modulo -- son == entre si sin importar el
    // typedef).  El `#` no aparece en ningun otro typename canonico.
    if (type_str.find('#') != std::string::npos &&
        type_str.substr(0, type_str.find('#')).find_first_of("<([*") ==
            std::string::npos &&
        type_str.substr(type_str.find('#') + 1).find_first_of("<>([*], \t") ==
            std::string::npos) {
        // Solo un newtype de TOP-LEVEL, y con AMBOS lados del '#' simples:
        //   - Antes del '#': un identificador.  Si lleva '<'/'('/'*'/'[' el
        //     newtype esta ANIDADO en un compuesto (`Optional<fiber#u64>`) y
        //     se maneja al recursar en el sub-tipo mas abajo.
        //   - Despues del '#': el underlying, que canonical_typename_of emite
        //     SIEMPRE como un primitivo integral pelado (`u64`).  Si lleva un
        //     sufijo/compuesto (`u64*`, `u64[4]`) ese sufijo es del TOP-LEVEL
        //     (`fiber#u64*` = puntero a `fiber`), no del underlying: dejamos
        //     que las ramas de puntero/array de abajo lo stripeen y recursen
        //     sobre `fiber#u64`.  Sin esta segunda condicion, `fiber#u64*` se
        //     reconstruia como "PTR a u64 llamado fiber" -- un escalar con
        //     nominal a ojos de type_to_string/types_assignable -> un param
        //     `T* p` importado de otro modulo se veia como `T` y toda llamada
        //     que le pasara un puntero fallaba el chequeo de tipos.
        const size_t hp = type_str.find('#');
        const std::string name = type_str.substr(0, hp);
        const std::string under = type_str.substr(hp + 1);
        // Enum con valor: se reconstruye COMO ENUM (entero de respaldo + marca
        // + nombre), no como newtype, para que unifique con el mismo enum del
        // consumidor.
        if (under.rfind("enum:", 0) == 0) {
            Type ev = resolve_type_string(under.substr(5));
            ev.is_valued_enum = true;
            ev.struct_name = name;
            return ev;
        }
        auto it_local = type_aliases_.find(name);
        if (it_local != type_aliases_.end()) return it_local->second;
        Type u = resolve_type_string(under); // primitivo subyacente
        u.nominal_name = name;
        // id determinista != 0, en rango alto para no chocar con los ids de
        // contador (que empiezan bajos).  FNV-1a 32 del nombre.
        uint32_t h = 2166136261u;
        for (char c : name) {
            h ^= static_cast<uint8_t>(c);
            h *= 16777619u;
        }
        u.nominal_id = 0x40000000u | (h & 0x3FFFFFFFu);
        return u;
    }

    // Tipo funcion (`cfn(...) -> T` / `fn(...) -> T`): NO stripear el '*'
    // final. Si el retorno es un puntero (`cfn(i64) -> u8*`), ese '*' pertenece
    // al RETORNO, no al tipo entero: tratarlo como sufijo daba "puntero a
    // cfn(i64) -> u8", el typedef importado quedaba en void y el campo que lo
    // usaba dejaba de ser invocable cross-module.
    const bool is_fn_typename =
        (type_str.size() >= 3 && type_str.rfind("fn(", 0) == 0) ||
        (type_str.size() >= 4 && type_str.rfind("cfn(", 0) == 0);

    // Punteros: stripear sufijo '*' antes del resto.
    if (!is_fn_typename && type_str.back() == '*') {
        std::string inner = type_str.substr(0, type_str.size() - 1);
        Type pt = resolve_type_string(inner);
        if (pt.kind == PrimitiveKind::VOID && inner != "void") {
            // No se pudo resolver inner: devolver void* generico.
            return Type::make_ptr(Type{PrimitiveKind::VOID});
        }
        return Type::make_ptr(std::move(pt));
    }

    //  M5.b L.10: ARRAY con tamano explicito `T[N]` o decay `T[]`.
    if (type_str.size() >= 2 && type_str.back() == ']') {
        size_t lb = type_str.find_last_of('[');
        if (lb != std::string::npos) {
            std::string inner = type_str.substr(0, lb);
            std::string size_str =
                type_str.substr(lb + 1, type_str.size() - lb - 2);
            Type elt = resolve_type_string(inner);
            uint32_t sz = 0;
            if (!size_str.empty()) {
                try {
                    sz = static_cast<uint32_t>(std::stoul(size_str));
                } catch (...) {
                    sz = 0;
                }
            }
            return Type::make_array(std::move(elt), sz, /*virt=*/true);
        }
    }

    //  M5.b L.10: VirtualPtr<T> (PTR is_virtual=true).
    {
        const std::string prefix = "VirtualPtr<";
        if (type_str.size() > prefix.size() &&
            type_str.compare(0, prefix.size(), prefix) == 0 &&
            type_str.back() == '>') {
            std::string inner = type_str.substr(
                prefix.size(), type_str.size() - prefix.size() - 1);
            Type elt = resolve_type_string(inner);
            return Type::make_ptr(std::move(elt), /*virt=*/true);
        }
    }

    //  M5.b L.10: Optional<T>.
    {
        const std::string prefix = "Optional<";
        if (type_str.size() > prefix.size() &&
            type_str.compare(0, prefix.size(), prefix) == 0 &&
            type_str.back() == '>') {
            std::string inner = type_str.substr(
                prefix.size(), type_str.size() - prefix.size() - 1);
            Type elt = resolve_type_string(inner);
            return Type::make_optional(std::move(elt));
        }
    }

    //  M5.b L.10: Result<V, E>.
    {
        const std::string prefix = "Result<";
        if (type_str.size() > prefix.size() &&
            type_str.compare(0, prefix.size(), prefix) == 0 &&
            type_str.back() == '>') {
            std::string inner = type_str.substr(
                prefix.size(), type_str.size() - prefix.size() - 1);
            auto parts = split_type_list_(inner);
            if (parts.size() == 2) {
                Type ok_t = resolve_type_string(parts[0]);
                Type err_t = resolve_type_string(parts[1]);
                return Type::make_result(std::move(ok_t), std::move(err_t));
            }
        }
    }

    //  M5.b L.10: Future<T>.
    {
        const std::string prefix = "Future<";
        if (type_str.size() > prefix.size() &&
            type_str.compare(0, prefix.size(), prefix) == 0 &&
            type_str.back() == '>') {
            std::string inner = type_str.substr(
                prefix.size(), type_str.size() - prefix.size() - 1);
            Type elt = resolve_type_string(inner);
            return Type::make_future(std::move(elt));
        }
    }

    //  M5.b L.10: smart pointers `unique<T>` y `shared<T>`.
    {
        const std::string p_uniq = "unique<";
        if (type_str.size() > p_uniq.size() &&
            type_str.compare(0, p_uniq.size(), p_uniq) == 0 &&
            type_str.back() == '>') {
            std::string inner = type_str.substr(
                p_uniq.size(), type_str.size() - p_uniq.size() - 1);
            return Type::make_unique(resolve_type_string(inner));
        }
        const std::string p_shr = "shared<";
        if (type_str.size() > p_shr.size() &&
            type_str.compare(0, p_shr.size(), p_shr) == 0 &&
            type_str.back() == '>') {
            std::string inner = type_str.substr(
                p_shr.size(), type_str.size() - p_shr.size() - 1);
            return Type::make_shared(resolve_type_string(inner));
        }
    }

    //  M5.b L.10: function types `fn(T1, T2) -> R`.
    // El typename canonico de type_to_string para FUNCTION es
    // `fn(p1, p2) -> ret`.  Detectamos el patron y parseamos.
    {
        // `cfn(...)` = puntero a funcion crudo (fn_is_raw); `fn(...)` = lambda.
        // Ambos comparten el patron; distinguirlos preserva el ancho (8 vs 16
        // bytes) del campo/typedef importado.
        bool is_raw = false;
        std::string prefix = "fn(";
        if (type_str.size() >= 4 && type_str.rfind("cfn(", 0) == 0) {
            prefix = "cfn(";
            is_raw = true;
        }
        if (type_str.size() > prefix.size() &&
            type_str.compare(0, prefix.size(), prefix) == 0) {
            // Buscar el matching ')'.
            size_t close =
                find_matching_close_(type_str, prefix.size() - 1, '(', ')');
            if (close != std::string::npos) {
                std::string params_str =
                    type_str.substr(prefix.size(), close - prefix.size());
                // Tras el `)`, esperamos ` -> RET`.
                std::string after = type_str.substr(close + 1);
                // Trim leading spaces.
                size_t i = 0;
                while (i < after.size() &&
                       (after[i] == ' ' || after[i] == '\t'))
                    ++i;
                after = after.substr(i);
                if (after.size() >= 3 && after[0] == '-' && after[1] == '>' &&
                    after[2] == ' ') {
                    std::string ret_str = after.substr(3);
                    auto pp = split_type_list_(params_str);
                    std::vector<Type> params;
                    params.reserve(pp.size());
                    for (auto &p : pp) {
                        if (!p.empty())
                            params.push_back(resolve_type_string(p));
                    }
                    Type ret = resolve_type_string(ret_str);
                    Type fn =
                        Type::make_function(std::move(params), std::move(ret));
                    fn.fn_is_raw = is_raw; // cfn -> raw (8 bytes)
                    return fn;
                }
            }
        }
    }

    // Primitivos.
    static const std::unordered_map<std::string, PrimitiveKind> primitives = {
        {"void", PrimitiveKind::VOID}, {"bool", PrimitiveKind::BOOL},
        {"char", PrimitiveKind::CHAR}, {"i8", PrimitiveKind::I8},
        {"i16", PrimitiveKind::I16},   {"i32", PrimitiveKind::I32},
        {"i64", PrimitiveKind::I64},   {"u8", PrimitiveKind::U8},
        {"u16", PrimitiveKind::U16},   {"u32", PrimitiveKind::U32},
        {"u64", PrimitiveKind::U64},   {"f32", PrimitiveKind::F32},
        {"f64", PrimitiveKind::F64},   {"string", PrimitiveKind::STRING},
    };
    auto itp = primitives.find(type_str);
    if (itp != primitives.end()) {
        return Type{itp->second};
    }

    // Alias / newtype ya registrado en el checker.
    {
        auto it = type_aliases_.find(type_str);
        if (it != type_aliases_.end()) return it->second;
    }
    // Struct/class/enum conocido.  Bug M: la identidad es el nombre del LAYOUT,
    // no la clave por la que se busco -- un tipo importado esta registrado bajo
    // su nombre publico Y bajo el canonico, y devolver la clave daba dos
    // identidades para un mismo tipo segun por donde se llegara.
    {
        auto it = struct_layouts_.find(type_str);
        if (it != struct_layouts_.end()) {
            return Type{PrimitiveKind::STRUCT,
                        it->second.name.empty() ? type_str : it->second.name};
        }
    }
    {
        auto it = class_layouts_.find(type_str);
        if (it != class_layouts_.end()) {
            return Type{PrimitiveKind::CLASS,
                        it->second.name.empty() ? type_str : it->second.name};
        }
    }
    {
        auto it = enum_layouts_.find(type_str);
        if (it != enum_layouts_.end()) {
            return Type{PrimitiveKind::STRUCT,
                        it->second.name.empty() ? type_str : it->second.name};
        }
    }
    // NS.1 fix: fallback de namespace para tipos referenciados por su nombre
    // PUBLICO simple dentro de codigo emitido por comptime (`sizeof<Vec3>()`
    // via comptime_compile).  El tipo real quedo mangled (`ejemplos__X__Vec3`);
    // el string no lo reescribe el flatten.  Buscar un match UNICO que termine
    // en `__<type_str>` en los layouts.  Solo para identificadores simples.
    if (type_str.find("__") == std::string::npos &&
        type_str.find('<') == std::string::npos &&
        type_str.find('.') == std::string::npos) {
        const std::string suffix = "__" + type_str;
        auto ends_with = [&](const std::string &n) {
            return n.size() > suffix.size() &&
                   n.compare(n.size() - suffix.size(), suffix.size(), suffix) ==
                       0;
        };
        std::string found;
        PrimitiveKind kind = PrimitiveKind::VOID;
        int matches = 0;
        for (const auto &kv : struct_layouts_)
            if (ends_with(kv.first)) {
                found = kv.first;
                kind = PrimitiveKind::STRUCT;
                ++matches;
            }
        for (const auto &kv : class_layouts_)
            if (ends_with(kv.first)) {
                found = kv.first;
                kind = PrimitiveKind::CLASS;
                ++matches;
            }
        for (const auto &kv : enum_layouts_)
            if (ends_with(kv.first)) {
                found = kv.first;
                kind = PrimitiveKind::STRUCT;
                ++matches;
            }
        if (matches == 1) return Type{kind, found};
    }
    // No se pudo resolver: devolver VOID (sentinel).  El caller decide
    // si emitir error o intentar resolver mas adelante (round-trip
    // cross-modulo cuando se inyectan tipos en orden equivocado).
    return Type{};
}

//  M.7: registrar un namespace importado.  Devuelve el indice
// asignado.  El namespace se declara como Symbol::Namespace al inicio
// de run() (via la cola pending_imported_ns_names_).
void TypeChecker::inject_imported_ext_method(
    const std::string &target_key, bool target_is_class,
    const std::string &name, const std::string &return_type_str,
    const std::vector<std::string> &param_strs,
    const std::string &mangled_label) {
    std::vector<ClassMethodInfo> *dst = nullptr;
    if (target_is_class) {
        auto it = class_layouts_.find(target_key);
        if (it != class_layouts_.end()) dst = &it->second.methods;
    } else {
        auto it = struct_layouts_.find(target_key);
        if (it != struct_layouts_.end()) dst = &it->second.methods;
    }
    if (!dst) return; // el tipo destino no esta cargado -> silencioso
    // Dedup: si ya existe (mismo nombre+aridad), no re-apendear.
    for (const auto &ex : *dst)
        if (ex.name == name && ex.param_types.size() == param_strs.size())
            return;
    ClassMethodInfo mi;
    mi.name = name;
    mi.defining_class = target_key; // label = target_key__name
    mi.is_extension = true;
    mi.return_type = resolve_type_string(return_type_str);
    for (const auto &ps : param_strs)
        mi.param_types.push_back(resolve_type_string(ps));
    if (target_is_class) mi.vtable_index = static_cast<uint32_t>(dst->size());
    (void)mangled_label; // el label se deriva de defining_class + name
    dst->push_back(std::move(mi));
}

uint32_t
TypeChecker::register_imported_namespace(const std::string &local_name,
                                         const std::string &module_name) {
    // LANG.fix-3: si ya hay un namespace registrado con este local_name,
    // devolver su idx para evitar duplicados (el caller puede llamar dos
    // veces al pre-importar transit + import explicito del mismo dep).
    auto existing = ns_idx_by_local_name_.find(local_name);
    if (existing != ns_idx_by_local_name_.end()) {
        return existing->second;
    }
    const uint32_t idx = static_cast<uint32_t>(imported_namespaces_.size());
    ImportedNamespace ns;
    ns.module_name = module_name;
    imported_namespaces_.push_back(std::move(ns));
    pending_imported_ns_names_.push_back({local_name, idx});
    ns_idx_by_local_name_[local_name] = idx;

    // NS short-form: si el nombre es multi-segmento (`org.geo.shapes`),
    // registrar tambien su ULTIMO segmento (`shapes`) como alias, para poder
    // acceder por el
    // (`shapes.area()`) ademas del path completo -- SOLO cuando sea UNICO.
    const size_t dot = local_name.rfind('.');
    if (dot != std::string::npos) {
        const std::string last = local_name.substr(dot + 1);
        // No pisar un namespace REAL llamado igual que el ultimo segmento, ni
        // reprocesar un segmento ya marcado ambiguo.
        const bool is_real_full =
            ns_idx_by_local_name_.count(last) && !ns_short_alias_.count(last);
        if (is_real_full || ns_short_ambiguous_.count(last)) {
            // colision con nombre real o ya ambiguo -> no crear alias corto.
        } else {
            auto ex = ns_short_alias_.find(last);
            if (ex != ns_short_alias_.end() && ex->second != idx) {
                // Segundo namespace con el mismo ultimo segmento -> AMBIGUO:
                // retirar el alias; ambos deberan usar el path completo.
                ns_short_alias_.erase(last);
                ns_idx_by_local_name_.erase(last);
                ns_short_ambiguous_.insert(last);
            } else if (ex == ns_short_alias_.end()) {
                // NO declaramos un Symbol::Namespace global para el alias corto
                // (eso sombrearia una funcion/variable homonima -- p.ej. un
                // namespace `x.fiber_swapctx` cuyo ultimo segmento coincide con
                // la funcion `fiber_swapctx`).  El alias vive solo en los
                // mapas; la base de un `alias.Symbol` lo resuelve como FALLBACK
                // cuando el nombre no es ya otro simbolo.
                ns_short_alias_[last] = idx;
                ns_idx_by_local_name_[last] = idx;
            }
        }
    }
    return idx;
}

void TypeChecker::register_namespace_symbol(uint32_t ns_index,
                                            const std::string &public_name,
                                            ImportedNamespace::Sym sym) {
    if (ns_index >= imported_namespaces_.size()) return;
    auto &ns = imported_namespaces_[ns_index];
    const uint32_t sym_idx = static_cast<uint32_t>(ns.symbols.size());
    ns.symbols.push_back(std::move(sym));
    ns.by_name.emplace(public_name, sym_idx);
}

//  NS.1b: resuelve `a.b.c.Symbol` probando el prefijo de namespace mas
// LARGO.  Itera desde el ultimo punto hacia el primero: el namespace es el
// prefijo mas largo registrado (por su nombre punteado completo) que contiene
// el simbolo restante.  Cubre single-segment (`ui.Button`) y multi-segment
// (`ui.widgets.Button` -> ns=`ui.widgets`, sym=`Button`).
bool TypeChecker::resolve_ns_qualified(const std::string &dotted,
                                       uint32_t &out_ns_idx,
                                       std::string &out_sym) const {
    size_t pos = dotted.rfind('.');
    while (pos != std::string::npos) {
        const std::string ns_name = dotted.substr(0, pos);
        const std::string sym_name = dotted.substr(pos + 1);
        // Resolver ns_name como namespace: primero el mapa persistente (que
        // sobrevive al pop_scope), luego el lookup tradicional.
        uint32_t idx = UINT32_MAX;
        auto it = ns_idx_by_local_name_.find(ns_name);
        if (it != ns_idx_by_local_name_.end()) {
            idx = it->second;
        } else {
            const Symbol *s = lookup(ns_name);
            if (s && s->kind == SymbolKind::Namespace) idx = s->ns_index;
        }
        if (idx < imported_namespaces_.size()) {
            const auto &ns = imported_namespaces_[idx];
            if (ns.by_name.find(sym_name) != ns.by_name.end()) {
                out_ns_idx = idx;
                out_sym = sym_name;
                return true;
            }
        }
        // Probar un prefijo de namespace mas corto (punto anterior).
        if (pos == 0) break;
        pos = dotted.rfind('.', pos - 1);
    }
    return false;
}

} // namespace vx

namespace vx {

// ---------------------------------------------------------------------------
// export: TypeChecker -> VxiModule.
// ---------------------------------------------------------------------------
void export_typechecker_to_vxi(const TypeChecker &tc, uint64_t source_hash,
                               VxiModule &out,
                               const std::string &strip_prefix) {
    out.source_hash = source_hash;
    out.symbols.clear();
    // Reserva pesimista: cubrir todos los simbolos conocidos en una sola
    // alocacion sin reallocs durante el push_back.
    const size_t cap = tc.type_aliases().size() + tc.struct_layouts().size() +
                       tc.class_layouts().size() + tc.enum_layouts().size() +
                       32;
    out.symbols.reserve(cap);

    // Namespace de ESTE modulo, si declara todo bajo uno solo.  Se deduce de
    // los simbolos que declara, que ya lo llevan anotado.  Hace falta para las
    // RE-EXPORTACIONES: un `public import` dentro de un namespace mete el
    // simbolo en la superficie de ese namespace, pero como el simbolo no se
    // declara aqui no estaba en la tabla y salia sin namespace.  El efecto era
    // que `import ns only sym;` lo encontraba y `ns.sym` no -- la misma cosa
    // visible por un camino y no por el otro.
    std::string module_ns;
    {
        bool uno_solo = true;
        for (const auto &kv : tc.declared_ns_symbols()) {
            const std::string &p = kv.second.first;
            if (p.empty()) continue;
            if (module_ns.empty()) {
                module_ns = p;
            } else if (module_ns != p) {
                uno_solo = false; // varios namespaces: no se puede deducir.
                break;
            }
        }
        if (!uno_solo) module_ns.clear();
    }

    // #cross-module-generics: nombres de plantillas genericas + conceptos de
    // ESTE modulo.  NO se exportan como simbolos regulares (function/struct/
    // class/enum): se exportan aparte como texto fuente (out.generic_templates)
    // y el importador los re-parsea.  Sin este filtro, un `triple<T>` se
    // exportaria a la vez como FUNCTION symbol Y como template -> el importador
    // declararia el nombre dos veces ("redefinicion a nivel global").
    std::unordered_set<std::string> template_names;
    for (const auto &tex : tc.ast_module().generic_template_exports)
        template_names.insert(tex.name);

    // --- Type aliases + newtypes ---
    for (const auto &kv : tc.type_aliases()) {
        //  M6.a L.3: solo exportar si es publico.
        if (!tc.is_typedef_public(kv.first)) continue;
        //  M.L23: filtrar imports NO re-exportados.  Solo lo que
        // venga de otro .vxi vive en imported_names_; los locales no.
        if (tc.is_imported(kv.first) && !tc.is_reexported(kv.first)) continue;
        VxiSymbol s;
        const Type &t = kv.second;
        s.name = kv.first;
        // NS.2: si el typedef/newtype se declaro en un `namespace X;`,
        // exportarlo con su nombre publico (sin manglar) + ns_path, igual que
        // struct/class/enum.  Sin esto, el import recalculaba un mangled
        // distinto (module__name en vez de X__name) y `type_aliases_[mangled]`
        // no coincidia -> `sizeof<X.Tipo>` / `X.Tipo var` daban VOID.
        {
            auto itns = tc.declared_ns_symbols().find(kv.first);
            if (itns != tc.declared_ns_symbols().end()) {
                s.ns_path = itns->second.first;
                s.name = itns->second.second;
            } else if (tc.is_reexported(kv.first)) {
                // RE-EXPORTADO: el simbolo NO se declaro aqui, asi que no esta
                // en declared_ns_symbols y se exportaria con el nombre ya
                // cualificado (`ch__base__handle`) y sin ns_path.  El siguiente
                // eslabon de la cadena lo re-cualifica con SU namespace y el
                // tipo acaba con dos identidades: `ch__base__handle` por el
                // retorno de la funcion (que si conserva el nombre original) y
                // `ch__top__handle` al declarar una variable.
                //
                // Se recupera la identidad ORIGINAL partiendo por el ultimo
                // separador: `ch__base__handle` -> ns `ch.base` + `handle`.
                // Asi el tipo es el MISMO da igual cuantos saltos tenga la
                // cadena, porque ya no hay nada que recalcular en cada uno.
                const size_t sep = kv.first.rfind("__");
                if (sep != std::string::npos && sep > 0) {
                    std::string flat = kv.first.substr(0, sep);
                    std::string dotted;
                    dotted.reserve(flat.size());
                    for (size_t i = 0; i < flat.size();) {
                        if (i + 1 < flat.size() && flat[i] == '_' &&
                            flat[i + 1] == '_') {
                            dotted.push_back('.');
                            i += 2;
                        } else {
                            dotted.push_back(flat[i]);
                            ++i;
                        }
                    }
                    s.ns_path = dotted;
                    s.name = kv.first.substr(sep + 2);
                }
            }
        }
        // Un typedef es NEWTYPE si se declaro con `new`, no si su tipo lleva
        // identidad nominal: un alias PLANO de un newtype la hereda -- porque
        // es transparente, que es justo lo que un alias significa -- y con el
        // criterio antiguo se exportaba como si fuera un tipo fuerte propio.
        // Al importarlo se le fabricaba identidad, y `typedef uintptr HANDLE;`
        // dejaba de unificar con `uintptr` en cuanto cruzaba de modulo.
        //
        // `newtype_underlying` solo tiene entrada para los declarados con
        // `new`, asi que responde exactamente a la pregunta correcta.
        if (t.nominal_id != 0 && tc.newtype_underlying(kv.first) != nullptr) {
            s.kind = VxiSymbolKind::TYPEDEF_NEW;
            s.is_opaque = t.is_opaque;
            s.align_override = t.align_override;
            // Los registros de newtype (underlying/info) estan keyeados por el
            // nombre LOCAL (kv.first), no por el public renombrado arriba.
            s.nominal_abi = vxi_fnv1a(kv.first);
            // El underlying canonico se obtiene del registro de newtypes.
            const Type *u = tc.newtype_underlying(kv.first);
            if (u != nullptr) {
                s.underlying_type = canonical_typename_of(*u);
            } else {
                // Fallback defensivo: representar el propio Type sin la
                // marca nominal.
                Type tmp = t;
                tmp.nominal_id = 0;
                tmp.is_opaque = false;
                tmp.align_override = 0;
                tmp.nominal_name.clear();
                s.underlying_type = canonical_typename_of(tmp);
            }
            //  M.L8: serializar bloque {explicit from/to T;}.
            // Solo se exportan las conversiones marcadas @c is_public ;
            // las privadas (module-scope del fichero origen) NO viajan
            // cross-module porque su semantica solo aplica intra-modulo.
            const TypeChecker::NewtypeInfo *ni = tc.newtype_info(kv.first);
            if (ni != nullptr) {
                for (const auto &conv : ni->from_conversions) {
                    if (!conv.is_public) continue;
                    VxiSymbol::ExplicitConvEntry e;
                    e.type_str = canonical_typename_of(conv.type);
                    e.is_public = true;
                    s.from_conversions.push_back(std::move(e));
                }
                for (const auto &conv : ni->to_conversions) {
                    if (!conv.is_public) continue;
                    VxiSymbol::ExplicitConvEntry e;
                    e.type_str = canonical_typename_of(conv.type);
                    e.is_public = true;
                    s.to_conversions.push_back(std::move(e));
                }
                for (const auto &conv : ni->implicit_from_conversions) {
                    if (!conv.is_public) continue;
                    VxiSymbol::ExplicitConvEntry e;
                    e.type_str = canonical_typename_of(conv.type);
                    e.is_public = true;
                    s.implicit_from_conversions.push_back(std::move(e));
                }
                for (const auto &conv : ni->implicit_to_conversions) {
                    if (!conv.is_public) continue;
                    VxiSymbol::ExplicitConvEntry e;
                    e.type_str = canonical_typename_of(conv.type);
                    e.is_public = true;
                    s.implicit_to_conversions.push_back(std::move(e));
                }
            }
        } else {
            s.kind = VxiSymbolKind::TYPEDEF_ALIAS;
            s.underlying_type = canonical_typename_of(t);
        }
        out.symbols.push_back(std::move(s));
    }

    // --- Structs ---
    for (const auto &kv : tc.struct_layouts()) {
        const auto &name = kv.first;
        const auto &layout = kv.second;
        //  M6.a L.3: solo exportar publicos.
        if (!layout.is_public) continue;
        //  M.L23: filtrar imports NO re-exportados.
        if (tc.is_imported(name) && !tc.is_reexported(name)) continue;
        VxiSymbol s;
        s.kind = VxiSymbolKind::STRUCT;
        s.name = name;
        // NS.2: si el tipo se declaro en un `namespace X;`, exportarlo con su
        // nombre publico (sin manglar) + ns_path para que el consumidor lo vea
        // como `X.Tipo` cross-modulo.
        {
            auto itns = tc.declared_ns_symbols().find(name);
            if (itns != tc.declared_ns_symbols().end()) {
                s.ns_path = itns->second.first;
                s.name = itns->second.second;
            }
        }
        s.size_bytes = layout.size_bytes;
        s.align_bytes = layout.align_bytes;
        s.is_overlay = layout.is_overlay;
        s.overlay_extent = layout.overlay_extent;
        s.fields.reserve(layout.fields.size());
        for (const auto &f : layout.fields) {
            VxiSymbol::FieldInfo fi;
            fi.name = f.name;
            fi.type_str = canonical_typename_of(f.type);
            fi.offset = f.offset;
            fi.size = f.size;
            fi.bit_offset = f.bit_offset;
            fi.bit_width = f.bit_width;
            s.fields.push_back(std::move(fi));
        }
        s.super_class = layout.super_name;
        // Metodos del struct: incluye los HEREDADOS ya aplanados por el flatten
        // de la herencia (con Self resuelto al derivado) y los operadores.  Sin
        // esto, un `struct` con metodos importado cross-module no exponia
        // NINGUN metodo (ni propios, ni heredados, ni __op__).  El dispatch de
        // metodos de struct es ESTATICO (value-type) -> el mangled_label lleva
        // el nombre real de la free-function en el .velb
        // (`<mangled_struct>__<metodo>`).
        s.methods.reserve(layout.methods.size());
        for (const auto &m : layout.methods) {
            VxiSymbol::MethodInfo mi;
            mi.name = m.name;
            mi.return_type = canonical_typename_of(m.return_type);
            mi.vtable_index = m.vtable_index;
            mi.flags = 0;
            if (m.is_static) mi.flags |= 0x01;
            if (m.is_constructor) mi.flags |= 0x02;
            // Un constructor `comptime` se resuelve de otra manera que uno
            // normal: si la marca no cruza el modulo, al importarlo parece un
            // constructor corriente y la llamada se rechaza con "ninguna
            // sobrecarga coincide".
            if (m.is_comptime) mi.flags |= 0x08;
            mi.mangled_label = name + "__" + m.name;
            mi.param_types.reserve(m.param_types.size());
            for (const auto &pt : m.param_types)
                mi.param_types.push_back(canonical_typename_of(pt));
            s.methods.push_back(std::move(mi));
        }
        out.symbols.push_back(std::move(s));
    }

    // --- Classes ---
    for (const auto &kv : tc.class_layouts()) {
        const auto &name = kv.first;
        const auto &layout = kv.second;
        //  M6.a L.3: solo exportar publicos.  Tambien skipear las
        // clases runtime-predefined (FatalError etc.) que vienen con la
        // VM y no son parte del modulo del usuario.
        if (!layout.is_public) continue;
        //  M.L23: filtrar imports NO re-exportados.
        if (tc.is_imported(name) && !tc.is_reexported(name)) continue;
        if (layout.is_runtime_predefined) continue;
        VxiSymbol s;
        s.kind = VxiSymbolKind::CLASS;
        s.name = name;
        // NS.2: export namespaced (nombre publico + ns_path).  `name` (mangled)
        // se conserva para construir los mangled_label de los metodos.
        {
            auto itns = tc.declared_ns_symbols().find(name);
            if (itns != tc.declared_ns_symbols().end()) {
                s.ns_path = itns->second.first;
                s.name = itns->second.second;
            }
        }
        s.super_class = layout.super_name;
        s.size_bytes = layout.size_bytes;
        s.align_bytes = 8; // las instancias se alinean a 8 (ObjectHeader)
        s.interfaces = layout.interface_names;
        s.fields.reserve(layout.fields.size());
        for (const auto &f : layout.fields) {
            VxiSymbol::FieldInfo fi;
            fi.name = f.name;
            fi.type_str = canonical_typename_of(f.type);
            fi.offset = f.offset;
            fi.size = f.size;
            fi.bit_offset = f.bit_offset;
            fi.bit_width = f.bit_width;
            s.fields.push_back(std::move(fi));
        }
        //  M6.b L.6: emitir methods con firmas + vtable_index +
        // mangled_label para que el consumer pueda emitir CALLVIRT
        // correcto cross-module.
        s.methods.reserve(layout.methods.size());
        for (const auto &m : layout.methods) {
            VxiSymbol::MethodInfo mi;
            mi.name = m.name;
            mi.return_type = canonical_typename_of(m.return_type);
            mi.vtable_index = m.vtable_index;
            mi.flags = 0;
            if (m.is_static) mi.flags |= 0x01;
            if (m.is_constructor) mi.flags |= 0x02;
            // Un constructor `comptime` se resuelve de otra manera que uno
            // normal: si la marca no cruza el modulo, al importarlo parece un
            // constructor corriente y la llamada se rechaza con "ninguna
            // sobrecarga coincide".
            if (m.is_comptime) mi.flags |= 0x08;
            // Todos los metodos de instancia son virtuales por defecto
            // en Vesta (mismo despacho que Java).
            if (!m.is_static) mi.flags |= 0x04;
            // El label real en el .vel: si la clase fue mangled (deps en
            // compile_vx_project), el method label tiene el mismo
            // prefix.  Aqui usamos `<ClassName>__<MethodName>` que es
            // como el lowering lo emite.
            mi.mangled_label = name + "__" + m.name;
            mi.param_types.reserve(m.param_types.size());
            for (const auto &pt : m.param_types) {
                mi.param_types.push_back(canonical_typename_of(pt));
            }
            s.methods.push_back(std::move(mi));
        }
        out.symbols.push_back(std::move(s));
    }

    // --- Enums ---
    for (const auto &kv : tc.enum_layouts()) {
        const auto &name = kv.first;
        const auto &layout = kv.second;
        //  M6.a L.3: solo exportar publicos.
        if (!layout.is_public) continue;
        //  M.L23: filtrar imports NO re-exportados.
        if (tc.is_imported(name) && !tc.is_reexported(name)) continue;
        VxiSymbol s;
        s.kind = VxiSymbolKind::ENUM;
        s.name = name;
        // NS.2: export namespaced (nombre publico + ns_path).
        {
            auto itns = tc.declared_ns_symbols().find(name);
            if (itns != tc.declared_ns_symbols().end()) {
                s.ns_path = itns->second.first;
                s.name = itns->second.second;
            }
        }
        // Preservar size_bytes para que el consumidor pueda allocar
        // slots del enum (8 + 8*max_payload_fields).  Sin esto, el
        // consumer ve size_bytes=0 -> ALLOCA cero -> corrupcion de
        // memoria adjacente.
        s.size_bytes = layout.size_bytes;
        s.align_bytes = 8;
        // Enum con VALOR (`enum Ordering : i8 { Less = -1, ... }`): hay que
        // llevarse tambien el tipo que lo respalda y el valor de cada
        // variante.  Sin ellos, el consumidor recibia un enum "a secas": sus
        // variantes no valian -1/0/1 sino basura, y comparar dos de ellas
        // daba falso.
        if (layout.is_valued) {
            s.underlying_type = type_to_string(Type{layout.backing});
        }
        s.variants.reserve(layout.variants.size());
        for (const auto &v : layout.variants) {
            VxiSymbol::EnumVariant ev;
            ev.name = v.name;
            ev.tag = v.tag;
            ev.int_value = v.int_value;
            ev.payload_types.reserve(v.field_types.size());
            for (const auto &ft : v.field_types) {
                ev.payload_types.push_back(canonical_typename_of(ft));
            }
            s.variants.push_back(std::move(ev));
        }
        out.symbols.push_back(std::move(s));
    }

    // --- Funciones ---
    // Si @c strip_prefix esta seteado (e.g. "lib__"), SOLO exportamos las
    // funciones cuyo nombre empieza con ese prefijo (las que pertenecen
    // a este modulo).  El nombre publico se obtiene quitando el prefijo;
    // el mangled_label conserva el nombre interno completo.  Asi el
    // consumidor importa "sumar" pero el lowering emite CALLVM al label
    // "lib__sumar" -- cierra L.4 (colisiones cross-module).
    //
    // Si @c strip_prefix esta vacio, exportamos todas las funciones
    // sin filtrar (caso del root o tests directos).
    for (const auto &kv : tc.function_names()) {
        const std::string &fname = kv.first;
        const FunctionSig *sig = tc.function_sig_by_name(fname);
        if (util::flag_on(util::FlagId::DbgVxi) &&
            fname.find("invoke") != std::string::npos)
            fprintf(stderr,
                    "[vxi-fn] fname=%s sig=%p strip='%s' in_ns=%d "
                    "pub=%d\n",
                    fname.c_str(), (void *)sig, strip_prefix.c_str(),
                    (int)(tc.declared_ns_symbols().count(fname)),
                    (int)tc.is_function_public(fname));
        if (sig == nullptr) continue;
        // Filtro: si hay prefix, ignorar simbolos que no lo lleven (son
        // builtins como print, malloc, sqrt -- no parte de este modulo).
        // Excepcion (L.23): imports re-exportados (`public import "X" only
        // A, B;`) llegan SIN el prefix del modulo actual pero deben
        // exportarse igual con su nombre publico original.
        std::string public_name;
        std::string mangled_label;
        std::string ns_path_for_sym;
        // NS.2: funcion de un namespace DECLARADO (`namespace mylib;`).  El
        // mangled es `mylib__helper`; exportamos con nombre publico `helper` +
        // ns_path `mylib` para que el consumidor la registre bajo ese namespace
        // al importar el modulo.  Independiente del strip_prefix del modulo (el
        // prefijo fisico es el del NAMESPACE, no el del modulo).
        auto itns = tc.declared_ns_symbols().find(fname);
        if (itns != tc.declared_ns_symbols().end()) {
            ns_path_for_sym = itns->second.first;
            public_name = itns->second.second;
            mangled_label = fname;
        } else if (!strip_prefix.empty()) {
            const bool has_prefix =
                fname.size() > strip_prefix.size() &&
                fname.compare(0, strip_prefix.size(), strip_prefix) == 0;
            if (has_prefix) {
                public_name = fname.substr(strip_prefix.size());
                mangled_label = fname;
            } else if (tc.is_reexported(fname)) {
                // L.23: re-export.  Conservamos el mangled_label original
                // (e.g. `base__base_value`) para que el linker del consumer
                // resuelva al codigo real en el .velb mergeado.
                public_name = fname;
                const FunctionSig *si = tc.function_sig_by_name(fname);
                if (si && !si->mangled_label.empty()) {
                    mangled_label = si->mangled_label;
                }
                // Lo re-exportado pertenece al namespace de quien re-exporta:
                // es parte de su superficie igual que lo que declara.
                ns_path_for_sym = module_ns;
            } else {
                continue;
            }
        } else {
            public_name = fname;
            // mangled_label = "" (mismo que name).
            // Mismo caso que arriba cuando no hay prefijo que quitar.
            if (tc.is_reexported(fname)) ns_path_for_sym = module_ns;
        }
        //  M6.a L.3: filtrar privadas.  La fn esta registrada con su
        // nombre mangled (post pre-pase de mangling cross-module).  Si el
        // mapa la marca explicitamente como privada, omitir; en cualquier
        // otro caso (entrada con true o no registrada) se exporta.  Esto
        // arregla la fallback al public_name que daba false-positive porque
        // el unmangled name nunca esta en el mapa (default true).
        if (!tc.is_function_public(fname)) {
            continue;
        }
        // #cross-module-generics: las plantillas se exportan como fuente, no
        // como simbolo regular.
        if (template_names.count(public_name) || template_names.count(fname)) {
            continue;
        }
        //  M.L23: filtrar imports NO re-exportados.  El check
        // contra public_name (no mangled) porque los imports se
        // registran con su nombre publico al consumer.
        if (tc.is_imported(public_name) && !tc.is_reexported(public_name)) {
            continue;
        }
        VxiSymbol s;
        s.kind = VxiSymbolKind::FUNCTION;
        s.name = public_name;
        s.mangled_label = mangled_label;
        s.ns_path =
            ns_path_for_sym; // NS.2: namespace declarado (vacio si none)
        s.return_type = canonical_typename_of(sig->return_type);
        s.is_extern = !sig->extern_lib.empty();
        s.extern_lib = sig->extern_lib;
        // LIM-A: propagar @Naked al .vxi para que la importacion cross-modulo
        // en interp/JIT enrute al dispatcher naked (y no ejecute el asm como
        // bytecode).
        s.is_naked = sig->is_naked;
        s.is_internal = tc.function_is_internal(fname); // NS.3: package-scoped
        s.param_types.reserve(sig->param_types.size());
        for (const auto &pt : sig->param_types) {
            s.param_types.push_back(canonical_typename_of(pt));
        }
        s.param_names.assign(sig->param_types.size(), std::string());
        // ABI custom por-param (`register("rax")`): imprescindible para que un
        // CALLIND cross-modulo a traves de un campo cuyo default es esta
        // funcion coloque los args en los registros correctos.
        s.param_abi_regs = sig->param_abi_regs;
        out.symbols.push_back(std::move(s));
    }

    // --- Globals ( M.L7) ---
    // Iteramos el AST del modulo en busca de GlobalVarDecl publicas (las
    // privadas + `static_assert` sinteticas se filtran).  El TypeChecker
    // ya valido el tipo y la visibilidad; aqui solo lo serializamos.
    // Comptime const tambien se exportan: el valor se materializa via
    // @c comptime_const_values_ y se inlinea como CONST en el consumer
    // (mismo path que `const` runtime, cero overhead).
    for (const auto &decl : tc.ast_module().decls) {
        if (!decl || decl->kind != ast::NodeKind::GlobalVarDecl) continue;
        const auto *gv = static_cast<const ast::GlobalVarDecl *>(decl.get());
        if (!gv->is_public) continue;
        // El name post-pre-pase puede estar mangled (`lib__MAX_USERS`).
        // Aplicar strip_prefix para obtener el nombre publico tal como
        // el consumidor lo importa.  Igual que funciones.
        std::string public_name = gv->name;
        std::string mangled_label;
        std::string ns_path_for_gv;
        // NS.2: global de un namespace DECLARADO (`namespace mylib; public
        // comptime string CLEAR = ...`).  El mangled es `mylib__CLEAR`;
        // exportamos con nombre publico `CLEAR` + ns_path `mylib`.
        auto itnsg = tc.declared_ns_symbols().find(gv->name);
        if (itnsg != tc.declared_ns_symbols().end()) {
            ns_path_for_gv = itnsg->second.first;
            public_name = itnsg->second.second;
            mangled_label = gv->name;
        } else if (!strip_prefix.empty()) {
            if (gv->name.size() > strip_prefix.size() &&
                gv->name.compare(0, strip_prefix.size(), strip_prefix) == 0) {
                public_name = gv->name.substr(strip_prefix.size());
                mangled_label = gv->name;
            } else {
                // No empieza con el prefix -> probablemente builtin o
                // sintetico de otro modulo; saltar.
                continue;
            }
        }
        // Filtrar los globales sinteticos / reservados del compilador: todo lo
        // que empieza con `__` (doble subrayado) -- `__static_assert_N`,
        // builtins, etc.  El doble subrayado queda RESERVADO al compilador;
        // los simbolos publicos del usuario usan a lo sumo UN subrayado inicial
        // (p.ej. `_NR_write`), que SI se exporta.
        if (public_name.size() >= 2 && public_name[0] == '_' &&
            public_name[1] == '_') {
            continue;
        }
        VxiSymbol s;
        s.kind = VxiSymbolKind::GLOBAL_VAR;
        s.name = public_name;
        s.mangled_label = mangled_label;
        s.ns_path = ns_path_for_gv; // NS.2: namespace declarado (vacio si none)
        s.is_internal = gv->is_internal; // NS.3: package-scoped
        Type gv_type =
            const_cast<TypeChecker &>(tc).resolve_type_node(gv->type.get());
        s.underlying_type = canonical_typename_of(gv_type);
        // Para los comptime const, marcamos @c is_const=true en el .vxi
        // porque el consumer los va a inlinear como CONST (mismo flujo que
        // los const runtime).  El bit @c is_comptime no se persiste; es
        // detalle interno del modulo emisor.
        s.is_const = gv->is_const || gv->is_comptime;
        // v4: propagar atributos al .vxi para que el consumer/AOT/JIT
        // los respeten al materializar el simbolo.
        if (gv->attr_hot) s.attr_flags |= 0x01;
        if (gv->attr_cold) s.attr_flags |= 0x02;
        s.attr_align = gv->attr_align;
        s.attr_section = gv->attr_section;
        // L.7: extraer valor inicial.  Tres caminos:
        //   1) `comptime const X = <expr>` -> consultar el valor ya
        //      evaluado en @c comptime_const_values_ (cubre expresiones
        //      arbitrarias resueltas en compile time).
        //   2) `const X = <int literal>` -> leer literal directo.
        //   3) `const X = -<int literal>` -> leer literal del UnaryExpr Neg.
        if (gv->is_comptime) {
            const auto &cv_map = tc.comptime_const_values();
            auto it = cv_map.find(gv->name);
            if (it != cv_map.end() && !it->second.is_str &&
                !it->second.is_array && !it->second.is_struct &&
                !it->second.is_type) {
                s.has_init_value = true;
                s.init_value = static_cast<uint64_t>(it->second.value);
            } else if (it != cv_map.end() && it->second.is_str) {
                // v4: materializar como blob STRING en el pool.
                const std::string &sv = it->second.str_value;
                const uint32_t blob_off = vxi_blob_append(
                    out.blob_pool, VxiBlobKind::STRING,
                    reinterpret_cast<const uint8_t *>(sv.data()), sv.size(),
                    /*element_size=*/1u,
                    /*count=*/static_cast<uint32_t>(sv.size()),
                    /*alignment=*/8u);
                s.has_blob_ref = true;
                s.blob_offset = blob_off;
                s.blob_kind_hint = static_cast<uint8_t>(VxiBlobKind::STRING);
            } else if (it != cv_map.end() && it->second.is_array) {
                // v4: materializar como blob ARRAY_PRIM.  Solo i64 elements
                // soportados en v4 (el evaluador comptime guarda los array
                // values como int64_t aunque el tipo declarado sea i32/u32).
                // El consumer puede truncar al tipo declarado al materializar.
                const auto &av = it->second.array_vals;
                std::vector<uint8_t> bytes;
                bytes.resize(av.size() * sizeof(int64_t));
                for (size_t i = 0; i < av.size(); ++i) {
                    int64_t v = av[i] ? av[i]->value : 0;
                    std::memcpy(bytes.data() + i * sizeof(int64_t), &v,
                                sizeof(int64_t));
                }
                const uint32_t blob_off = vxi_blob_append(
                    out.blob_pool, VxiBlobKind::ARRAY_PRIM, bytes.data(),
                    bytes.size(),
                    /*element_size=*/static_cast<uint32_t>(sizeof(int64_t)),
                    /*count=*/static_cast<uint32_t>(av.size()),
                    /*alignment=*/8u);
                s.has_blob_ref = true;
                s.blob_offset = blob_off;
                s.blob_kind_hint =
                    static_cast<uint8_t>(VxiBlobKind::ARRAY_PRIM);
            } else if (it != cv_map.end() && it->second.is_struct) {
                // v4: materializar como blob STRUCT_PRIM (campos primitivos
                // i64).  El consumer reconstruye el struct accediendo a los
                // campos por nombre via lookup.
                const auto &fields = it->second.struct_fields;
                std::vector<uint8_t> bytes;
                // Layout: (u32 name_off + u32 name_len + u64 value) por field.
                // El name_off apunta al string pool del .vxi (que sigue al
                // blob_pool).  Lo resolvemos via el StringPoolBuilder NO
                // accesible aqui directamente.  Para v4 inicial, almacenamos
                // el nombre EN EL BLOB mismo via inline u32 len + bytes.
                // Layout per field: u32 name_len + u32 _pad + u64 value
                //                 + name_bytes (padded a 8).
                for (const auto &kv : fields) {
                    const std::string &name = kv.first;
                    int64_t v = kv.second ? kv.second->value : 0;
                    uint32_t nl = static_cast<uint32_t>(name.size());
                    bytes.insert(bytes.end(), reinterpret_cast<uint8_t *>(&nl),
                                 reinterpret_cast<uint8_t *>(&nl) + 4);
                    uint32_t pad = 0;
                    bytes.insert(bytes.end(), reinterpret_cast<uint8_t *>(&pad),
                                 reinterpret_cast<uint8_t *>(&pad) + 4);
                    bytes.insert(bytes.end(), reinterpret_cast<uint8_t *>(&v),
                                 reinterpret_cast<uint8_t *>(&v) + 8);
                    bytes.insert(bytes.end(), name.begin(), name.end());
                    while (bytes.size() % 8 != 0)
                        bytes.push_back(0);
                }
                const uint32_t blob_off = vxi_blob_append(
                    out.blob_pool, VxiBlobKind::STRUCT_PRIM, bytes.data(),
                    bytes.size(),
                    /*element_size=*/0u,
                    /*count=*/static_cast<uint32_t>(fields.size()),
                    /*alignment=*/8u);
                s.has_blob_ref = true;
                s.blob_offset = blob_off;
                s.blob_kind_hint =
                    static_cast<uint8_t>(VxiBlobKind::STRUCT_PRIM);
            } else {
                // is_type u otros casos no soportados en v4: saltar.
                continue;
            }
        } else if (gv->is_const && gv->init) {
            if (gv->init->kind == ast::NodeKind::StringLitExpr) {
                // `public const string S = "lit"`.  Un const string NO tiene
                // storage ni en su propio modulo: cada uso materializa el
                // StringObject desde el literal.  Cross-module vale lo mismo,
                // asi que exportamos los bytes como blob STRING y el consumidor
                // los materializa igual -- el mismo camino que un comptime
                // string.  Sin esto el simbolo viajaba sin valor y el uso moria
                // con "nombre no resuelto", que ni senalaba al global.
                auto *sl = static_cast<ast::StringLitExpr *>(gv->init.get());
                // Interpolado (`"a=${b}"`): el valor no es un literal, se
                // construye en cada uso -> no exportable como blob.
                if (sl->interp_exprs.empty()) {
                    const std::string &sv = sl->value;
                    const uint32_t blob_off = vxi_blob_append(
                        out.blob_pool, VxiBlobKind::STRING,
                        reinterpret_cast<const uint8_t *>(sv.data()), sv.size(),
                        /*element_size=*/1u,
                        /*count=*/static_cast<uint32_t>(sv.size()),
                        /*alignment=*/8u);
                    s.has_blob_ref = true;
                    s.blob_offset = blob_off;
                    s.blob_kind_hint =
                        static_cast<uint8_t>(VxiBlobKind::STRING);
                }
            } else {
                // El valor se EVALUA, no se reconoce por la forma que tenga
                // escrita.  Antes solo se admitian dos: un literal entero y un
                // literal con signo delante; cualquier otra cosa se exportaba
                // SIN valor y en silencio, asi que el consumidor leia 0.  Un
                // `const i32 STD_OUTPUT_HANDLE = ((DWORD)-11);` -- un cast, que
                // es lo normal al declarar constantes del sistema -- llegaba
                // como 0 al otro modulo y todo lo que dependiera de el fallaba
                // sin decir por que.
                const ComptimeEvalResult ev =
                    comptime_eval_expr(tc, gv->init.get());
                if (ev.ok && !ev.is_str && !ev.is_array && !ev.is_struct &&
                    !ev.is_type) {
                    s.has_init_value = true;
                    s.init_value = static_cast<uint64_t>(ev.value);
                } else if (!ev.deferred) {
                    // No se pudo evaluar: NO se exporta el simbolo.  Aqui no
                    // hay por donde emitir un diagnostico, y de las dos formas
                    // de fallar -- que el uso no resuelva el nombre, o que lea
                    // un 0 que nadie escribio -- la primera al menos se ve.
                    continue;
                }
            }
        }
        out.symbols.push_back(std::move(s));
    }

    //  M.L23: re-export de globals const importadas.  Los globals
    // importados via `public import "lib" only X;` NO viven en el AST
    // del modulo actual (estan en @c imported_global_consts_ del
    // TypeChecker).  Iteramos ese mapa y exportamos los que esten
    // marcados como re-exportados.
    for (const auto &kv : tc.imported_global_consts()) {
        const std::string &name = kv.first;
        if (!tc.is_reexported(name)) continue;
        VxiSymbol s;
        s.kind = VxiSymbolKind::GLOBAL_VAR;
        s.name = name;
        s.underlying_type = canonical_typename_of(kv.second.type);
        s.is_const = true; // imported_global_consts solo guarda const
        s.has_init_value = true;
        s.init_value = kv.second.value;
        out.symbols.push_back(std::move(s));
    }

    // --- #cross-module-generics: plantillas genericas + conceptos ---
    // Exportar el TEXTO FUENTE de cada plantilla generica/concepto publico
    // para que los importadores la re-parseen e inyecten en su AST y puedan
    // monomorphizar `Caja<i64>` cross-module.  No re-exportar las que vienen
    // de otro modulo (salvo re-export explicito).
    for (const auto &tex : tc.ast_module().generic_template_exports) {
        if (!tex.is_public) continue;
        if (tc.is_imported(tex.name) && !tc.is_reexported(tex.name)) continue;
        VxiModule::GenericTemplateSource g;
        g.name = tex.name;
        g.kind = tex.kind;
        g.source = tex.source;
        // NS.2: si la plantilla/concepto se declaro en un namespace, propagar
        // su ns_path.  El tex.name es el nombre publico (sin manglar); lo
        // buscamos en declared_ns_symbols (keyed por mangled -> (ns, public)).
        for (const auto &dns : tc.declared_ns_symbols()) {
            if (dns.second.second == tex.name) {
                g.ns_path = dns.second.first;
                break;
            }
        }
        out.generic_templates.push_back(std::move(g));
    }

    // NS.6-ext: exportar los metodos de `extension`/`impl` de ESTE modulo para
    // que un consumidor los re-apendee al layout del tipo destino (dispatch
    // estatico al mangled_label, que vive en el .velb de este modulo).
    for (const auto &decl : tc.ast_module().decls) {
        if (!decl) continue;
        const bool is_ext = decl->kind == ast::NodeKind::ExtensionDecl;
        const bool is_impl = decl->kind == ast::NodeKind::ImplDecl;
        if (!is_ext && !is_impl) continue;
        std::string target_src;
        if (is_ext)
            target_src = static_cast<const ast::ExtensionDecl *>(decl.get())
                             ->target_type;
        else
            target_src =
                static_cast<const ast::ImplDecl *>(decl.get())->target_type;
        // Resolver la clave del layout (directo / mangled /
        // resolve_type_string).
        std::string key;
        bool is_class = false;
        const std::vector<ClassMethodInfo> *layout_methods = nullptr;
        auto set_key = [&](const std::string &k) -> bool {
            auto sit = tc.struct_layouts().find(k);
            if (sit != tc.struct_layouts().end()) {
                key = k;
                is_class = false;
                layout_methods = &sit->second.methods;
                return true;
            }
            auto cit = tc.class_layouts().find(k);
            if (cit != tc.class_layouts().end()) {
                key = k;
                is_class = true;
                layout_methods = &cit->second.methods;
                return true;
            }
            return false;
        };
        if (!set_key(target_src)) {
            std::string mangled = target_src;
            for (size_t p = mangled.find('.'); p != std::string::npos;
                 p = mangled.find('.'))
                mangled.replace(p, 1, "__");
            if (mangled == target_src || !set_key(mangled)) {
                const Type rt = tc.resolve_type_string(target_src);
                if (rt.kind == PrimitiveKind::STRUCT ||
                    rt.kind == PrimitiveKind::CLASS)
                    set_key(rt.struct_name);
            }
        }
        if (!layout_methods) continue;
        for (const auto &mi : *layout_methods) {
            if (!mi.is_extension) continue;
            if (mi.defining_class != key) continue;
            VxiModule::ExtMethod em;
            em.target_key = key;
            em.name = mi.name;
            em.return_type = canonical_typename_of(mi.return_type);
            em.mangled_label = key + "__" + mi.name;
            em.target_is_class = is_class;
            for (const auto &pt : mi.param_types)
                em.param_types.push_back(canonical_typename_of(pt));
            out.ext_methods.push_back(std::move(em));
        }
    }
}

/**
 * @brief Registra en el comprobador un typedef que viene de un `.vxi`.
 *
 * Un alias es transparente y un newtype tiene identidad propia, y esa identidad
 * tiene que ser LA MISMA que ve el modulo donde se declaro: el id sale del
 * nombre canonico, y lo que se guarda como tipo de debajo va SIN esa identidad
 * -- si la llevara, preguntar de que esta hecho `usize` respondaria `usize`, y
 * resolverlo se llamaria a si mismo hasta desbordar la pila.
 *
 * Esto vivia dentro del bucle que importa los simbolos de un `.vxi`.  Hace
 * falta tambien al inyectar plantillas genericas, que se re-parsean y necesitan
 * resolver los tipos que su modulo trajo de un tercero; escribirlo alli otra
 * vez habria sido una segunda version de las mismas reglas, y la copia que se
 * quedara corta seria la que fallara -- que es exactamente lo que paso al
 * intentarlo: una version reducida se dejo lo de la identidad y el compilador
 * se caia.
 *
 * @param tc Comprobador de tipos destino.
 * @param s Simbolo del `.vxi` (debe ser TYPEDEF_ALIAS o TYPEDEF_NEW).
 * @param canon Nombre canonico (cualificado) del tipo.
 * @param local_name Nombre con el que se ve desde el modulo que importa.
 */
static void register_vxi_typedef_(TypeChecker &tc, const VxiSymbol &s,
                                  const std::string &canon,
                                  const std::string &local_name) {
    Type underlying = tc.resolve_type_string(s.underlying_type);
    if (underlying.kind == PrimitiveKind::VOID && s.underlying_type != "void") {
        // No se pudo resolver el underlying (e.g. apunta a un
        // tipo no importado todavia).  Skip silente; M5
        // añadira un round adicional de resolucion.
        return;
    }
    if (s.kind == VxiSymbolKind::TYPEDEF_NEW) {
        // Id ESTABLE por identidad mangled (la clave canonica de
        // arriba).  Sin esto un `only T` recibia un id de contador !=
        // al de las firmas de las funciones libres del mismo modulo
        // (`f(T)`) -> no unificaban.
        underlying.nominal_id = tc.stable_nominal_id(canon);
        // nominal_name CANONICO (no el local), igual que la ruta
        // namespaced.  canonical_typename_of lo serializa como
        // `<nombre>#<underlying>` en las firmas del .vxi, y el decoder
        // deriva el id de ESE nombre: si aqui fuera el local, un modulo
        // que importa la firma antes que el typedef obtendria
        // id(FNV"usize") mientras que quien importa el typedef
        // obtendria id(FNV"std__types__usize") -> dos identidades para
        // un tipo.
        underlying.nominal_name = canon;
        underlying.is_opaque = s.is_opaque;
        underlying.align_override = s.align_override;
        Type clean = underlying;
        clean.nominal_id = 0;
        clean.nominal_name.clear();
        clean.is_opaque = false;
        clean.align_override = 0;
        tc.register_imported_newtype(local_name, clean);
        //  M.L8: registrar el bloque {explicit from/to T;}
        // si el .vxi lo trae.  Las entries no-public ya fueron
        // filtradas por el lado emit.  Las que llegan aqui son
        // siempre is_public=true.
        if (!s.from_conversions.empty() || !s.to_conversions.empty() ||
            !s.implicit_from_conversions.empty() ||
            !s.implicit_to_conversions.empty()) {
            TypeChecker::NewtypeInfo ni;
            ni.from_conversions.reserve(s.from_conversions.size());
            for (const auto &c : s.from_conversions) {
                TypeChecker::ExplicitConv ec;
                ec.type = tc.resolve_type_string(c.type_str);
                ec.is_public = c.is_public;
                ni.from_conversions.push_back(std::move(ec));
            }
            ni.to_conversions.reserve(s.to_conversions.size());
            for (const auto &c : s.to_conversions) {
                TypeChecker::ExplicitConv ec;
                ec.type = tc.resolve_type_string(c.type_str);
                ec.is_public = c.is_public;
                ni.to_conversions.push_back(std::move(ec));
            }
            ni.implicit_from_conversions.reserve(
                s.implicit_from_conversions.size());
            for (const auto &c : s.implicit_from_conversions) {
                TypeChecker::ExplicitConv ec;
                ec.type = tc.resolve_type_string(c.type_str);
                ec.is_public = c.is_public;
                ni.implicit_from_conversions.push_back(std::move(ec));
            }
            ni.implicit_to_conversions.reserve(
                s.implicit_to_conversions.size());
            for (const auto &c : s.implicit_to_conversions) {
                TypeChecker::ExplicitConv ec;
                ec.type = tc.resolve_type_string(c.type_str);
                ec.is_public = c.is_public;
                ni.implicit_to_conversions.push_back(std::move(ec));
            }
            // El newtype importado responde a su nombre local Y al
            // canonico (mangled): las firmas de otros .vxi lo
            // referencian por el segundo, y si solo estuviera el
            // primero la conversion no se encontraria desde ahi.
            if (canon != local_name) {
                TypeChecker::NewtypeInfo copia = ni;
                tc.register_imported_newtype_info(canon, std::move(copia));
            }
            tc.register_imported_newtype_info(local_name, std::move(ni));
        }
    }
    // Igual que con struct/class/enum: atar el tipo TAMBIEN a su clave
    // canonica.  Las firmas serializadas en los .vxi referencian el
    // nombre mangled (`std__types__usize`); si solo estuviera el
    // publico, esa referencia no resolveria al MISMO tipo y un newtype
    // acabaria con dos identidades ("(usize) incompatible con
    // (usize)").
    tc.register_imported_type_alias(local_name, underlying);
    if (canon != local_name)
        tc.register_imported_type_alias(canon, std::move(underlying));
}
// ---------------------------------------------------------------------------
// #cross-module-generics: inyectar plantillas genericas + conceptos.
// ---------------------------------------------------------------------------
void inject_generic_templates_from_vxi(
    TypeChecker &tc, const VxiModule &mod,
    const std::unordered_set<std::string> &wanted, const std::string &ns_prefix,
    const std::unordered_set<std::string> &alias_unqualified,
    const std::vector<const VxiModule *> &alias_sources) {
    if (mod.generic_templates.empty()) return;

    // Dedup a nivel de (modulo + namespace): un modulo importado dos veces
    // bajo el mismo prefijo no se re-inyecta.  La clave usa el nombre del
    // primer template + ns para identificar el conjunto.
    const std::string dedup_key = "__modtpl__" + ns_prefix + "|" +
                                  mod.generic_templates.front().name + "@" +
                                  std::to_string(mod.generic_templates.size());
    if (tc.has_injected_template(dedup_key)) return;
    tc.mark_injected_template(dedup_key);

    // CONCATENAR todas las fuentes de plantillas del modulo y parsearlas
    // JUNTAS, en orden.  Critico para #7: la deteccion de especializacion
    // (`la PRIMERA Caja<...> es el primario, las siguientes son specs`) usa
    // estado del parser (generic_struct_names_seen_) que se perderia si se
    // re-parsea cada fuente por separado -> una spec aislada se trataria
    // como primario.
    std::string combined;
    for (const auto &g : mod.generic_templates) {
        combined += g.source;
        combined += "\n";
    }
    Diagnostics tmp_diags;
    Lexer lex(combined, "<vxi-templates:" + ns_prefix + ">", tmp_diags);
    Parser parser(lex, tmp_diags);
    // Sembrar los nombres de TIPO del modulo (typedefs, structs, enums, clases)
    // como aliases conocidos ANTES de parsear.  Sin esto, una fn comptime cuya
    // firma referencia un typedef del modulo (p.ej. `comptime WORD MK(...)`) se
    // re-parsea con el parser sin conocer `WORD` -> lo interpreta como retorno
    // void y falla ("return con valor en funcion void").
    for (const auto &sym : mod.symbols) {
        if (sym.kind == VxiSymbolKind::TYPEDEF_ALIAS ||
            sym.kind == VxiSymbolKind::TYPEDEF_NEW ||
            sym.kind == VxiSymbolKind::STRUCT ||
            sym.kind == VxiSymbolKind::CLASS ||
            sym.kind == VxiSymbolKind::ENUM) {
            parser.add_known_alias(sym.name);
        }
    }
    // Y los de los modulos de los que ESTE importa: la firma de una plantilla
    // puede nombrar un tipo que su modulo trajo de un tercero (`usize`, de
    // `std.types`).  Sin sembrarlos, el re-parseo no reconoce el nombre y el
    // parametro se queda en `void`.
    for (const VxiModule *src : alias_sources) {
        if (!src) continue;
        for (const auto &sym : src->symbols) {
            if (sym.kind == VxiSymbolKind::TYPEDEF_ALIAS ||
                sym.kind == VxiSymbolKind::TYPEDEF_NEW ||
                sym.kind == VxiSymbolKind::STRUCT ||
                sym.kind == VxiSymbolKind::CLASS ||
                sym.kind == VxiSymbolKind::ENUM) {
                parser.add_known_alias(sym.name);
            }
        }
    }
    // Las plantillas comptime/macro se inyectan TODAS (wanted vacio) y se
    // type-checkean; si su firma referencia un typedef transparente del modulo
    // (WORD -> u16) que NO fue importado por `only`, el checker no lo
    // resolveria
    // (-> void).  Registrar aqui los alias transparentes del modulo
    // (idempotente) para que esas firmas resuelvan.  Son alias a primitivos:
    // inocuos.
    for (const auto &sym : mod.symbols) {
        if (sym.kind != VxiSymbolKind::TYPEDEF_ALIAS) continue;
        Type u = tc.resolve_type_string(sym.underlying_type);
        if (u.kind == PrimitiveKind::VOID && sym.underlying_type != "void")
            continue; // underlying no resoluble aun; skip.
        // emplace es idempotente: no pisa un alias ya registrado (local o
        // import).
        tc.register_imported_type_alias(sym.name, std::move(u));
    }
    // Y los tipos de los modulos de los que ESTE importa: la firma de una
    // plantilla puede nombrar uno que su modulo trajo de un tercero (`usize`,
    // de `std.types`).  Se registran con la MISMA rutina que usa el import
    // normal -- ver @ref register_vxi_typedef_ --, porque una version reducida
    // aqui volveria a equivocarse en lo mismo.
    for (const VxiModule *src : alias_sources) {
        if (!src) continue;
        for (const auto &sym : src->symbols) {
            if (sym.kind != VxiSymbolKind::TYPEDEF_ALIAS &&
                sym.kind != VxiSymbolKind::TYPEDEF_NEW)
                continue;
            if (sym.ns_path.empty()) continue; // sin canonica no se puede atar
            // Solo los que se apoyan DIRECTAMENTE en un tipo del lenguaje.
            //
            // Estos tipos son de un modulo que no es el nuestro y se recorren
            // en el orden en que estan, que no es el de dependencia: en cuanto
            // uno se apoya en otro del mismo sitio, registrarlo puede pasar por
            // uno a medio hacer y volver sobre si mismo.  `usize`, que es un
            // `u64`, no tiene esa vuelta -- y es lo que hace falta para que las
            // firmas de las plantillas resuelvan.  Lo demas lo trae el import
            // normal cuando alguien lo pida de verdad.
            if (!comptime_is_primitive(
                    tc.resolve_type_string(sym.underlying_type)))
                continue;
            register_vxi_typedef_(tc, sym, qualify_once_(sym.ns_path, sym.name),
                                  sym.name);
        }
    }
    auto parsed = parser.parse_program();
    if (!parsed || tmp_diags.has_errors()) return; // best-effort

    // El cuerpo de una plantilla puede llamar a funciones de SU PROPIO modulo
    // (`struct atomic<T>` usando un helper de `atomic`).  Como se re-parsea
    // aqui, esos nombres no estan en el scope del consumidor -- y no deben
    // estarlo: el consumidor puso `only atomic`, no pidio los helpers.
    //
    // Se reescriben en el AST de la plantilla al label REAL que el `.vxi` ya
    // trae (`atomic__atomic_load64`) y se registra ESE label como funcion
    // importada.  Asi la plantilla resuelve y enlaza, y el consumidor sigue sin
    // ver los helpers: el label mangled no es un nombre que nadie escriba.
    {
        std::unordered_map<std::string, std::string> fn_renames;
        for (const auto &sym : mod.symbols) {
            if (sym.kind != VxiSymbolKind::FUNCTION) continue;
            if (sym.mangled_label.empty() || sym.mangled_label == sym.name)
                continue;
            fn_renames.emplace(sym.name, sym.mangled_label);
        }
        if (!fn_renames.empty()) {
            for (auto &decl : parsed->decls)
                if (decl) vxgen::rename_idents(decl.get(), fn_renames);
            // Registrar la firma de cada helper bajo su label.  Idempotente: si
            // ya estaba (otro import), `register_imported_function` lo repite
            // sin dano.
            for (const auto &sym : mod.symbols) {
                if (sym.kind != VxiSymbolKind::FUNCTION) continue;
                auto it = fn_renames.find(sym.name);
                if (it == fn_renames.end()) continue;
                if (tc.function_sigs_by_name().count(it->second)) continue;
                FunctionSig sig;
                sig.return_type = tc.resolve_type_string(sym.return_type);
                sig.param_types.reserve(sym.param_types.size());
                for (const auto &pt : sym.param_types)
                    sig.param_types.push_back(tc.resolve_type_string(pt));
                sig.extern_lib = sym.is_extern ? sym.extern_lib : std::string();
                sig.mangled_label = sym.mangled_label;
                sig.is_naked = sym.is_naked;
                sig.param_abi_regs = sym.param_abi_regs; // ABI custom
                tc.register_imported_function(it->second, std::move(sig));
                tc.mark_template_only_fn(it->second);
            }
        }
    }

    // Lo mismo con las `comptime const` del modulo: una plantilla que use la de
    // su propia libreria (p.ej. el mensaje que comparten sus static_assert) no
    // la resolveria aqui.  Se registra su VALOR bajo un nombre que nadie
    // escribe (`<mod>__<NOMBRE>`) y se reescriben las referencias en el AST de
    // la plantilla -- misma jugada que con las funciones, misma higiene: el
    // consumidor no ve el nombre corto si su `only` no lo pidio.
    {
        std::unordered_map<std::string, std::string> const_renames;
        for (const auto &sym : mod.symbols) {
            if (sym.kind != VxiSymbolKind::GLOBAL_VAR) continue;
            if (!sym.is_const) continue;
            // El nombre solo tiene que ser unico y que nadie lo escriba: una
            // `comptime const` se inlinea en el uso, no enlaza contra nada, asi
            // que no hace falta que coincida con el mangling real del modulo.
            const std::string mangled = "__tpl__" + ns_prefix + "__" + sym.name;
            TypeChecker::ComptimeConst c;
            c.type = tc.resolve_type_string(sym.underlying_type);
            if (sym.has_blob_ref) {
                const VxiBlobHeader *bh =
                    vxi_blob_read(mod.blob_pool, sym.blob_offset);
                const uint8_t *payload =
                    vxi_blob_payload(mod.blob_pool, sym.blob_offset);
                if (!bh || !payload ||
                    bh->kind != static_cast<uint32_t>(VxiBlobKind::STRING))
                    continue; // solo strings por ahora
                c.is_str = true;
                c.str_value.assign(reinterpret_cast<const char *>(payload),
                                   bh->count);
            } else if (sym.has_init_value) {
                c.value = static_cast<int64_t>(sym.init_value);
            } else {
                continue; // sin valor conocido: nada que inyectar
            }
            tc.comptime_const_values().emplace(mangled, std::move(c));
            const_renames.emplace(sym.name, mangled);
        }
        if (!const_renames.empty())
            for (auto &decl : parsed->decls)
                if (decl) vxgen::rename_idents(decl.get(), const_renames);
    }

    // Helper: nombre del decl (para el filtro `only` + rename namespace).
    auto decl_name = [](ast::Node *d) -> std::string {
        switch (d->kind) {
        case ast::NodeKind::StructDecl:
            return static_cast<ast::StructDecl *>(d)->name;
        case ast::NodeKind::ClassDecl:
            return static_cast<ast::ClassDecl *>(d)->name;
        case ast::NodeKind::FunctionDecl:
            return static_cast<ast::FunctionDecl *>(d)->name;
        case ast::NodeKind::EnumDecl:
            return static_cast<ast::EnumDecl *>(d)->name;
        case ast::NodeKind::ConceptDecl:
            return static_cast<ast::ConceptDecl *>(d)->name;
        default: return std::string();
        }
    };
    auto set_decl_name = [](ast::Node *d, const std::string &nm) {
        switch (d->kind) {
        case ast::NodeKind::StructDecl:
            static_cast<ast::StructDecl *>(d)->name = nm;
            break;
        case ast::NodeKind::ClassDecl:
            static_cast<ast::ClassDecl *>(d)->name = nm;
            break;
        case ast::NodeKind::FunctionDecl:
            static_cast<ast::FunctionDecl *>(d)->name = nm;
            break;
        case ast::NodeKind::EnumDecl:
            static_cast<ast::EnumDecl *>(d)->name = nm;
            break;
        case ast::NodeKind::ConceptDecl:
            static_cast<ast::ConceptDecl *>(d)->name = nm;
            break;
        default: break;
        }
    };
    // Los conceptos inyectados se registran con su nombre cualificado
    // (`std__numeric__PackedSum`), pero las plantillas viajan como TEXTO
    // FUENTE y su restriccion sigue diciendo el nombre corto que se
    // escribio en el modulo de origen (`<T: PackedSum>`).  Sin traducir
    // una a la otra, importar una funcion generica restringida fallaba
    // con "concepto desconocido" -- y el concepto estaba, solo que
    // guardado bajo otro nombre.
    //
    // El mapa se construye ANTES del bucle porque una plantilla puede
    // inyectarse antes que el concepto que exige; el orden de las decls
    // en la interfaz no es el de dependencia.
    std::unordered_map<std::string, std::string> concept_rename;
    for (const auto &d : parsed->decls) {
        if (!d || d->kind != ast::NodeKind::ConceptDecl) continue;
        const std::string cnm = decl_name(d.get());
        std::string cns;
        for (const auto &g : mod.generic_templates)
            if (g.name == cnm) {
                cns = g.ns_path;
                break;
            }
        if (cns.empty()) continue;
        std::string ns_m;
        for (char c : cns)
            ns_m += (c == 0x2E) ? std::string("__") : std::string(1, c);
        concept_rename[cnm] = ns_m + "__" + cnm;
    }
    // Aplica el mapa a las restricciones de una decl ya inyectada.
    auto rename_bounds = [&](std::vector<ast::TypeBound> &bounds) {
        for (auto &b : bounds)
            for (auto &c : b.concepts) {
                auto it = concept_rename.find(c);
                if (it != concept_rename.end()) c = it->second;
            }
    };
    /* Y lo mismo DENTRO del predicado de un concepto, que puede llamar a otro
     * del mismo modulo (`concept A<T> = B<T>() && ...`).  Ese cuerpo tambien
     * viaja como texto y tambien nombra al otro por su nombre corto, asi que
     * sin traducirlo el predicado no encontraba nada y el tipo no satisfacia
     * una condicion que si cumplia.  Solo hace falta mirar a quien se LLAMA:
     * un concepto se usa como `Otro<T>()`. */
    std::function<void(ast::Expr *)> rename_in_expr = [&](ast::Expr *e) {
        if (!e) return;
        switch (e->kind) {
        case ast::NodeKind::CallExpr: {
            auto *c = static_cast<ast::CallExpr *>(e);
            if (c->callee && c->callee->kind == ast::NodeKind::IdentExpr) {
                auto *id = static_cast<ast::IdentExpr *>(c->callee.get());
                auto it = concept_rename.find(id->name);
                if (it != concept_rename.end()) id->name = it->second;
            }
            rename_in_expr(c->callee.get());
            for (auto &a : c->args)
                rename_in_expr(a.get());
            break;
        }
        case ast::NodeKind::BinaryExpr: {
            auto *b = static_cast<ast::BinaryExpr *>(e);
            rename_in_expr(b->lhs.get());
            rename_in_expr(b->rhs.get());
            break;
        }
        case ast::NodeKind::UnaryExpr:
            rename_in_expr(static_cast<ast::UnaryExpr *>(e)->operand.get());
            break;
        default: break;
        }
    };

    for (auto &decl : parsed->decls) {
        if (!decl) continue;
        // Cross-module comptime/macro: marcar las fns comptime/macro
        // re-parseadas como IMPORTADAS para que el importer NO las re-baje a IR
        // (el dep ya baja `__macro_<X>` + helpers force-lowered, que el
        // importer mergea).  Re-bajar aqui produce un `code.<helper>` colgante
        // por el mangling incoherente del cuerpo re-parseado.  El importer solo
        // las AST-evalua al invocarlas.  Ver
        // ast::FunctionDecl::is_imported_comptime.
        if (decl->kind == ast::NodeKind::FunctionDecl) {
            auto *ifd = static_cast<ast::FunctionDecl *>(decl.get());
            if (ifd->is_comptime || ifd->is_macro)
                ifd->is_imported_comptime = true;
        }
        const std::string nm = decl_name(decl.get());
        // Filtro `only` (si wanted no esta vacio).  Las specs comparten el
        // nombre del primario, asi que el filtro por nombre las incluye.
        if (!wanted.empty() && wanted.find(nm) == wanted.end()) continue;
        // NS.2: si la plantilla/concepto declaraba un namespace en el dep,
        // registrarla bajo el nombre ns-mangled (`mat__X`) para que el acceso
        // cualificado `mat.X` resuelva (misma convencion `.`->`__`).  Si no,
        // usar el prefijo del modulo con punto (comportamiento previo).
        std::string tpl_ns;
        for (const auto &g : mod.generic_templates)
            if (g.name == nm) {
                tpl_ns = g.ns_path;
                break;
            }
        if (!tpl_ns.empty()) {
            std::string ns_m;
            for (char c : tpl_ns)
                ns_m += (c == '.') ? std::string("__") : std::string(1, c);
            const std::string mangled_full = ns_m + "__" + nm;
            set_decl_name(decl.get(), mangled_full);
            // El nombre corto tiene que seguir llevando a la plantilla: un
            // `import std.numeric;` mete `add` en el scope, y sin este puente
            // `add<i64>(...)` no se reconocia como generica.
            if (decl->kind == ast::NodeKind::FunctionDecl)
                tc.register_generic_fn_alias(nm, mangled_full);
            // NS.2: registrar el template bajo su namespace DECLARADO para que
            // el acceso cualificado resuelva (`geo.doble<i64>()` / `geo.Caja`).
            // El concepto usa la ruta comptime_eval_concept (`.`->`__`), pero
            // registrarlo aqui tambien es inocuo.  Para fn el kind=0, tipos=2.
            const uint32_t tns_idx =
                tc.register_imported_namespace(tpl_ns, tpl_ns);
            TypeChecker::ImportedNamespace::Sym nsym;
            nsym.mangled_label = mangled_full;
            nsym.kind = (decl->kind == ast::NodeKind::FunctionDecl) ? 0 : 2;
            tc.register_namespace_symbol(tns_idx, nm, std::move(nsym));
        } else if (!ns_prefix.empty() && !nm.empty()) {
            set_decl_name(decl.get(), ns_prefix + "." + nm);
        }
        /* only-import de una comptime/macro fn: registrar tambien el nombre SIN
         * cualificar (`nm`) apuntando al decl, para que la invocacion suelta
         * (`emit_val(...)`) la resuelva -- consistente con una fn regular via
         * `only`.  El acceso cualificado ya quedo cubierto por
         * register_namespace_symbol.  El decl ya tiene su nombre MANGLED; el
         * alias es una segunda clave en comptime_fns_ hacia el mismo decl.
         * Solo para los nombres listados en `only` (alias_unqualified): un
         * import plano NO expone el nombre suelto (higiene de namespace, igual
         * que las fns regulares). */
        if (alias_unqualified.count(nm) &&
            decl->kind == ast::NodeKind::FunctionDecl) {
            auto *cfd = static_cast<ast::FunctionDecl *>(decl.get());
            if (cfd->is_comptime || cfd->is_macro)
                tc.register_comptime_fn(nm, cfd);
        }
        // Traducir las restricciones al nombre con el que el concepto
        // acaba de quedar registrado.
        if (!concept_rename.empty()) {
            switch (decl->kind) {
            case ast::NodeKind::FunctionDecl:
                rename_bounds(
                    static_cast<ast::FunctionDecl *>(decl.get())->type_bounds);
                break;
            case ast::NodeKind::StructDecl:
                rename_bounds(
                    static_cast<ast::StructDecl *>(decl.get())->type_bounds);
                break;
            case ast::NodeKind::ClassDecl:
                rename_bounds(
                    static_cast<ast::ClassDecl *>(decl.get())->type_bounds);
                break;
            case ast::NodeKind::EnumDecl:
                rename_bounds(
                    static_cast<ast::EnumDecl *>(decl.get())->type_bounds);
                break;
            case ast::NodeKind::ConceptDecl:
                rename_in_expr(static_cast<ast::ConceptDecl *>(decl.get())
                                   ->predicate.get());
                break;
            default: break;
            }
        }
        tc.inject_decl(std::move(decl));
    }
}
/**
 * @brief Reconstruye el layout de un enum a partir de su simbolo de interfaz.
 *
 * Un enum puede ser dos cosas y cada una tiene su representacion: uno de
 * VARIANTES es un agregado -- tag mas campos, en memoria --, mientras que uno
 * CON VALOR (`enum Ordering : i8 { Less = -1 }`) es su entero base etiquetado,
 * que cabe en un registro y se compara como un numero.  Perder esa distincion
 * al cruzar el modulo convierte las variantes en direcciones de buffers, y
 * comparar dos de ellas pasa a comparar direcciones.
 *
 * Esta funcion es el UNICO sitio donde se toma esa decision al importar.  Habia
 * cuatro copias de esta logica repartidas por las distintas rutas de
 * importacion, y cada una se equivocaba a su manera: el bug reaparecia por un
 * camino distinto cada vez que se cerraba por otro.
 *
 * @param tc TypeChecker destino (resuelve los nombres de tipo del .vxi).
 * @param s Simbolo de la interfaz, con su tipo de respaldo y sus variantes.
 * @param name Nombre con el que registrar el layout.
 * @param with_payloads Si false, omite los tipos de payload (pre-registro de
 *        esqueleto, cuando los tipos referidos aun no estan todos resueltos).
 * @return El layout listo para registrar.
 */
static EnumLayout enum_layout_from_vxi_(TypeChecker &tc, const VxiSymbol &s,
                                        const std::string &name,
                                        bool with_payloads) {
    EnumLayout L;
    L.name = name;
    // Sin el tamano, el consumidor reserva slots de cero bytes y al construir
    // una variante pisa la memoria de al lado.
    L.size_bytes = static_cast<uint32_t>(s.size_bytes);
    // Enum CON VALOR: hay que llevarse el tipo que lo respalda; sin el, sus
    // variantes no valen -1/0/1 sino basura.
    if (!s.underlying_type.empty()) {
        const Type bt = tc.resolve_type_string(s.underlying_type);
        if (bt.kind != PrimitiveKind::VOID) {
            L.is_valued = true;
            L.backing = bt.kind;
        } else {
            // La interfaz dice que el enum tiene tipo base, pero ese nombre no
            // resuelve en el consumidor.  Callarse aqui es lo que convertia un
            // enum CON VALOR en un agregado: sus variantes dejaban de ser
            // numeros para volverse buffers, y compararlas comparaba
            // direcciones.  Se avisa en vez de seguir con un tipo por defecto
            // que no es el suyo.
            std::fprintf(stderr,
                         "[vxi] aviso: el enum '%s' declara el tipo base '%s' "
                         "y no se ha podido resolver; sus valores no se "
                         "conservaran\n",
                         name.c_str(), s.underlying_type.c_str());
        }
    }
    L.variants.reserve(s.variants.size());
    for (const auto &v : s.variants) {
        EnumVariantInfo ev;
        ev.name = v.name;
        ev.tag = v.tag;
        ev.int_value = v.int_value;
        if (with_payloads) {
            ev.field_types.reserve(v.payload_types.size());
            for (const auto &pt : v.payload_types)
                ev.field_types.push_back(tc.resolve_type_string(pt));
        }
        L.variants.push_back(std::move(ev));
    }
    return L;
}

// ---------------------------------------------------------------------------
// import: VxiModule -> TypeChecker (inyeccion selectiva via only_symbols).
//
//  M.2 MVP: solo procesamos los simbolos LISTADOS en only_symbols.
// Para cada uno, buscamos el VxiSymbol con ese nombre en el modulo y
// lo inyectamos en la tabla del TypeChecker que corresponda a su kind.
//
// Si only_symbols esta vacio, no se inyecta nada (los imports plain
// `import "x";` o `import "x" as alias;` requieren namespace support,
// pendiente en M2.x).
// ---------------------------------------------------------------------------
void import_vxi_into_typechecker(
    TypeChecker &tc, const VxiModule &mod,
    const std::vector<TypeChecker::VxiOnlyEntry> &only_symbols,
    const std::string &module_name) {
    if (only_symbols.empty()) return;

    // Mapa name -> indice en mod.symbols para lookup O(1).
    std::unordered_map<std::string, size_t> by_name;
    by_name.reserve(mod.symbols.size() * 2);
    for (size_t i = 0; i < mod.symbols.size(); ++i) {
        by_name.emplace(mod.symbols[i].name, i);
    }

    // Orden de inyeccion: primero los TIPOS, luego lo que los USA (funciones
    // y globales).  Las firmas se reconstruyen con resolve_type_string, que
    // para un newtype prefiere la definicion ya registrada en type_aliases_ y
    // solo si falta sintetiza un id determinista.  Si una funcion se inyectara
    // antes que el typedef que usa (`only take_ptr, handle` -- el orden lo
    // elige el usuario), su firma se quedaria con el id sintetizado mientras
    // que el typedef recibiria despues un id del contador local: el MISMO
    // newtype con dos ids -> `handle* p` dejaria de aceptar un `handle*`.
    // Ordenando por kind, las firmas siempre ven los tipos ya registrados.
    // Se conserva el orden relativo dentro de cada grupo (estable).
    auto is_type_sym = [&](const TypeChecker::VxiOnlyEntry &os) noexcept {
        auto it = by_name.find(os.name);
        if (it == by_name.end()) return false;
        switch (mod.symbols[it->second].kind) {
        case VxiSymbolKind::TYPEDEF_ALIAS:
        case VxiSymbolKind::TYPEDEF_NEW:
        case VxiSymbolKind::STRUCT:
        case VxiSymbolKind::CLASS:
        case VxiSymbolKind::ENUM: return true;
        default: return false;
        }
    };
    std::vector<const TypeChecker::VxiOnlyEntry *> ordered;
    ordered.reserve(only_symbols.size());
    for (const auto &os : only_symbols)
        if (is_type_sym(os)) ordered.push_back(&os);
    for (const auto &os : only_symbols)
        if (!is_type_sym(os)) ordered.push_back(&os);

    // Mapa nombre-de-tipo-en-el-ORIGEN -> local_name.  El .vxi serializa los
    // param_types/return_type de los metodos con el nombre CANONICO (mangled
    // con su namespace, p.ej. "std__wideint__u128") del modulo origen, pero el
    // consumidor registra cada tipo con su local_name (p.ej. "u128").  Sin
    // traducir, `types_assignable` compararia "std__wideint__u128" contra
    // "u128" y fallaria -> un metodo u operador con parametros del propio
    // modulo no resolveria cross-module (`a / b` con a,b:u128 daba "u128 no
    // declara /").
    std::unordered_map<std::string, Type> origin_to_local;
    for (const auto *os_ptr : ordered) {
        auto it = by_name.find(os_ptr->name);
        if (it == by_name.end()) continue;
        const VxiSymbol &s = mod.symbols[it->second];
        switch (s.kind) {
        case VxiSymbolKind::STRUCT:
        case VxiSymbolKind::CLASS: break;
        default: continue;
        }
        const std::string local =
            os_ptr->rename.empty() ? os_ptr->name : os_ptr->rename;
        // MISMA regla canonica que el registro de layouts de abajo: sin
        // `namespace` declarado la clave es `<modulo>__<nombre>`.
        std::string mangled;
        {
            mangled = s.ns_path.empty() ? qualify_once_(module_name, s.name)
                                        : qualify_once_(s.ns_path, s.name);
        }
        // Type base local ya construido: se usa DIRECTO (sin
        // resolve_type_string) porque el struct que porta el metodo todavia no
        // esta registrado cuando se resuelven sus propios param_types
        // (self-reference: `a / b` con a,b:u128 -> __div__(u128)).  Solo
        // STRUCT/CLASS por valor (los tipos por los que se cruzan los
        // operadores); ENUM/typedef caen a resolve_type_string. Bug M: el Type
        // base lleva la identidad CANONICA (la misma que `L.name` del layout),
        // no el nombre local: si no, el tipo de retorno de un metodo importado
        // (`u128.from_u64() -> u128`) quedaba con una identidad distinta a la
        // del tipo declarado por el consumer.
        Type base;
        if (s.kind == VxiSymbolKind::STRUCT)
            base = Type{PrimitiveKind::STRUCT, mangled};
        else if (s.kind == VxiSymbolKind::CLASS)
            base = Type{PrimitiveKind::CLASS, mangled};
        origin_to_local[mangled] = base;
        origin_to_local[s.name] = base; // por si la firma usa el nombre simple
        origin_to_local[local] = base;  // ... o el nombre local/renombrado
    }
    // Resuelve un type_string del origen a un Type local.  Para un tipo del
    // propio modulo importado usado POR VALOR devuelve el Type base ya
    // construido (sin depender de que este registrado); en cualquier otro caso
    // (primitivos, punteros, tipos externos) delega en resolve_type_string.
    auto resolve_imported = [&](const std::string &ts_in) -> Type {
        // Strip de sufijos de puntero: `std__chan__Chan*` -> resolver el base
        // `std__chan__Chan` via origin_to_local (al Type LOCAL `Chan`) y
        // re-aplicar el puntero.  Sin esto, un param `f(Chan* c)` de una
        // funcion libre importada no unificaba con un `Chan*` del consumidor
        // (el base quedaba como el struct MANGLED std__chan__Chan).
        std::string ts = ts_in;
        int nptr = 0;
        while (!ts.empty() && ts.back() == '*') {
            ts.pop_back();
            ++nptr;
        }
        Type base;
        auto direct = origin_to_local.find(ts);
        if (direct != origin_to_local.end() &&
            direct->second.kind != PrimitiveKind::VOID)
            base = direct->second;
        else
            base = tc.resolve_type_string(nptr ? ts : ts_in);
        for (int i = 0; i < nptr; ++i)
            base = Type::make_ptr(base);
        return base;
    };

    for (const auto *os_ptr : ordered) {
        const auto &os = *os_ptr;
        auto it = by_name.find(os.name);
        if (it == by_name.end()) {
            // El simbolo solicitado no existe en el modulo importado.
            // El caller (compiler.cpp) emitira un diagnostico claro.
            // Aqui solo skipeamos para no abortar las demas inyecciones.
            continue;
        }
        const VxiSymbol &s = mod.symbols[it->second];
        const std::string local_name = os.rename.empty() ? os.name : os.rename;

        // Clave CANONICA del simbolo (ns_path -> "std__ntwindows__T").  Es la
        // MISMA que usa la ruta namespaced al registrar tipos y la que aparece
        // en las firmas serializadas de los .vxi.
        //
        // Bug M: registrar los tipos bajo `local_name` creaba un SEGUNDO layout
        // para el mismo tipo (uno por `only T`, otro por el re-export
        // namespaced).  Dos claves = dos identidades: un valor construido por
        // el llamante no unificaba con el parametro de una funcion importada de
        // otro modulo ("tipo (T*) incompatible con parametro (mod__T*)").
        // Se registra bajo la canonica y se ata `local_name` como ALIAS, que es
        // justo lo que TYPEDEF_NEW ya hace via stable_nominal_id.
        std::string canon;
        {
            // MISMA regla que la ruta namespaced (PASE 1b): sin `namespace`
            // declarado, la clave es `<modulo>__<nombre>`.  Si aqui se usara el
            // nombre pelado, un newtype importado con `only` obtendria un
            // stable_nominal_id distinto al de las firmas -> dos identidades.
            canon = s.ns_path.empty() ? qualify_once_(module_name, s.name)
                                      : qualify_once_(s.ns_path, s.name);
        }

        // Recordar el ORIGEN del simbolo importado (namespace donde se declara
        // + nombre publico).  Sin esto, un modulo que lo RE-EXPORTA lo escribe
        // en su .vxi con el nombre local y sin ns_path, y el siguiente eslabon
        // de la cadena lo re-cualifica con SU namespace: el tipo termina con
        // una identidad por cada salto (`ch__base__handle` en la firma de la
        // funcion, `ch__top__handle` al declarar una variable) y deja de
        // unificar consigo mismo.  Guardandolo aqui, la identidad ORIGINAL
        // viaja intacta por toda la cadena y no hay nada que recalcular.
        //
        // SOLO tipos: una funcion re-exportada ya conserva su identidad por
        // otra via (`mangled_label`), y registrarla aqui la haria pasar por
        // "declarada localmente" en el export -- esa rama fija la etiqueta al
        // nombre local y perderia el `ch__base__mk` real, dejando al enlazador
        // sin resolver la llamada.
        const bool es_tipo = s.kind == VxiSymbolKind::TYPEDEF_ALIAS ||
                             s.kind == VxiSymbolKind::TYPEDEF_NEW ||
                             s.kind == VxiSymbolKind::STRUCT ||
                             s.kind == VxiSymbolKind::CLASS ||
                             s.kind == VxiSymbolKind::ENUM;
        if (es_tipo && !s.ns_path.empty()) {
            tc.register_declared_ns_symbol(local_name, s.ns_path, s.name);
        }

        switch (s.kind) {
        case VxiSymbolKind::TYPEDEF_ALIAS:
        case VxiSymbolKind::TYPEDEF_NEW: {
            register_vxi_typedef_(tc, s, canon, local_name);
            break;
        }
        case VxiSymbolKind::STRUCT: {
            StructLayout L;
            L.name = canon;
            L.size_bytes = s.size_bytes;
            L.align_bytes = s.align_bytes;
            // LIM-11: restaurar la condicion de overlay para que el consumidor
            // reconozca la construccion `Tipo(ptr)` del overlay importado.
            L.is_overlay = s.is_overlay;
            L.overlay_extent = s.overlay_extent;
            L.fields.reserve(s.fields.size());
            for (const auto &fi : s.fields) {
                StructFieldInfo sfi;
                sfi.name = fi.name;
                sfi.type = tc.resolve_type_string(fi.type_str);
                sfi.offset = fi.offset;
                sfi.size = fi.size;
                sfi.bit_offset = fi.bit_offset;
                sfi.bit_width = fi.bit_width;
                L.fields.push_back(std::move(sfi));
            }
            L.super_name = s.super_class;
            // Metodos del struct importado (propios + heredados aplanados +
            // operadores).  El lowering del consumidor los usa para resolver
            // `a.metodo(...)` y los operadores (`a / b` -> __div__)
            // cross-module.
            L.methods.reserve(s.methods.size());
            for (const auto &mi : s.methods) {
                ClassMethodInfo cmi;
                cmi.name = mi.name;
                cmi.return_type = resolve_imported(mi.return_type);
                cmi.vtable_index = mi.vtable_index;
                cmi.is_static = (mi.flags & 0x01) != 0;
                cmi.is_constructor = (mi.flags & 0x02) != 0;
                cmi.is_comptime = (mi.flags & 0x08) != 0;
                cmi.defining_class = canon;
                cmi.link_name = mi.mangled_label;
                cmi.param_types.reserve(mi.param_types.size());
                for (const auto &pt : mi.param_types)
                    cmi.param_types.push_back(resolve_imported(pt));
                L.methods.push_back(std::move(cmi));
            }
            // Bug M: UNA identidad (`L.name` = canonica) accesible por DOS
            // claves.  Las firmas de los .vxi referencian el tipo por su nombre
            // mangled (`std__ntwindows__PROCESSOR_NUMBER`) y el codigo del
            // consumer por el publico (`PROCESSOR_NUMBER`); con una sola clave,
            // cual de las dos identidades acababa en la firma dependia del
            // ORDEN de los imports -> "tipo (T*) incompatible con parametro
            // (mod__T*)" siendo el mismo tipo.  La resolucion nombre->Type
            // devuelve `L.name`, no la clave, asi que ambas rutas dan el mismo
            // tipo.
            if (canon != local_name) tc.register_imported_struct(local_name, L);
            tc.register_imported_struct(canon, std::move(L));
            break;
        }
        case VxiSymbolKind::CLASS: {
            // M2 MVP: las clases inyectadas son layouts solo de
            // estructura (sin vtable funcional, sin metodos
            // dispatcheables).  Util para que el TypeChecker conozca
            // el TIPO de un identificador importado.  La llamada real
            // a sus metodos requiere M5 (link de los .velb).
            // ClassLayout reusa StructFieldInfo para sus fields.
            ClassLayout L;
            L.name = canon;
            L.super_name = s.super_class;
            L.size_bytes = s.size_bytes;
            L.fields.reserve(s.fields.size());
            for (const auto &fi : s.fields) {
                StructFieldInfo cfi;
                cfi.name = fi.name;
                cfi.type = tc.resolve_type_string(fi.type_str);
                cfi.offset = fi.offset;
                cfi.size = fi.size;
                cfi.bit_offset = fi.bit_offset;
                cfi.bit_width = fi.bit_width;
                L.fields.push_back(std::move(cfi));
            }
            L.interface_names = s.interfaces;
            //  M6.b L.6: inyectar methods con sus firmas.  El
            // lowering de `obj.method(args)` en el consumidor podra
            // usar `vtable_index` para emitir CALLVIRT correcto.
            L.methods.reserve(s.methods.size());
            for (const auto &mi : s.methods) {
                ClassMethodInfo cmi;
                cmi.name = mi.name;
                cmi.return_type = resolve_imported(mi.return_type);
                cmi.vtable_index = mi.vtable_index;
                cmi.is_static = (mi.flags & 0x01) != 0;
                cmi.is_constructor = (mi.flags & 0x02) != 0;
                cmi.is_comptime = (mi.flags & 0x08) != 0;
                cmi.defining_class = canon;
                cmi.link_name = mi.mangled_label;
                cmi.param_types.reserve(mi.param_types.size());
                for (const auto &pt : mi.param_types) {
                    cmi.param_types.push_back(resolve_imported(pt));
                }
                L.methods.push_back(std::move(cmi));
            }
            if (canon != local_name) tc.register_imported_class(local_name, L);
            tc.register_imported_class(canon, std::move(L));
            break;
        }
        case VxiSymbolKind::ENUM: {
            EnumLayout L =
                enum_layout_from_vxi_(tc, s, canon, /*with_payloads=*/true);
            if (canon != local_name) tc.register_imported_enum(local_name, L);
            tc.register_imported_enum(canon, std::move(L));
            break;
        }
        case VxiSymbolKind::FUNCTION: {
            FunctionSig sig;
            // Las firmas del .vxi traen los tipos del propio modulo por su
            // nombre CANONICO mangled (std__ns__T).  resolve_imported (igual
            // que los metodos, L1716+) los traduce al Type local ya importado
            // -> `f(T)` unifica con el `T` que el consumidor puso en `only T`.
            // Con resolve_type_string a secas quedaban como std__ns__T y NO
            // unificaban (struct Chan y newtype fiber cross-modulo).
            sig.return_type = resolve_imported(s.return_type);
            sig.param_types.reserve(s.param_types.size());
            for (const auto &pt : s.param_types) {
                sig.param_types.push_back(resolve_imported(pt));
            }
            sig.extern_lib = s.is_extern ? s.extern_lib : std::string();
            //  M.5: si el .vxi declara un mangled_label, el
            // lowering del consumidor emitira @c CALLVM a ese label
            // en lugar del nombre publico.  Cierra L.4.
            sig.mangled_label = s.mangled_label;
            // LIM-A: preservar @Naked para enrutar la llamada al dispatcher.
            sig.is_naked = s.is_naked;
            sig.param_abi_regs = s.param_abi_regs; // ABI custom por-param
            tc.register_imported_function(local_name, std::move(sig));
            break;
        }
        case VxiSymbolKind::GLOBAL_VAR: {
            //  M.L7: registrar global importada.  El TypeChecker
            // la declarara como Symbol::Variable en el scope global
            // tras el push_scope inicial de run().  Si trae
            // has_init_value, ademas se inline-a en el lowering como
            // CONST literal -- cierra el caso `public const i32 X = N;`.
            Type t = tc.resolve_type_string(s.underlying_type);
            if (t.kind == PrimitiveKind::VOID && s.underlying_type != "void") {
                continue; // tipo no resoluble (skip silente)
            }
            // Const string/array/struct: el valor viaja como blob del .vxi.  Un
            // const string no tiene storage (cada uso materializa el
            // StringObject desde el literal), asi que el consumidor necesita
            // los bytes, no una direccion.  Mismo trato que por namespace.
            if (s.is_const && s.has_blob_ref) {
                const VxiBlobHeader *bh =
                    vxi_blob_read(mod.blob_pool, s.blob_offset);
                const uint8_t *payload =
                    vxi_blob_payload(mod.blob_pool, s.blob_offset);
                if (bh && payload &&
                    bh->kind == static_cast<uint32_t>(VxiBlobKind::STRING)) {
                    std::string str_val(reinterpret_cast<const char *>(payload),
                                        bh->count);
                    tc.register_imported_global_str(local_name, t,
                                                    std::move(str_val));
                    break;
                }
            }
            // El mangled_label identifica el slot en el modulo que lo define:
            // los globals que no se inlinean comparten storage por esa clave.
            // Vacio (global del root, sin mangle) => no exportable: se queda
            // sin storage compartido y el uso falla al resolver, como antes.
            tc.register_imported_global(local_name, std::move(t), s.is_const,
                                        s.has_init_value, s.init_value,
                                        s.mangled_label);
            break;
        }
        }
    }
}

// =========================================================================
// Variante que devuelve la lista de simbolos solicitados pero NO encontrados
// (o no publicos) en el .vxi.  El caller (compile_vx_project) la usa para
// emitir diagnosticos cross-module precisos ( M6.a L.3).
//
// Tras llamar a esta funcion, el TypeChecker queda con las inyecciones de
// los simbolos que SI existian (igual que la variante simple); los faltantes
// solo se devuelven para que el caller decida si emitir error o warning.
// =========================================================================
std::vector<std::string> import_vxi_into_typechecker_with_missing(
    TypeChecker &tc, const VxiModule &mod,
    const std::vector<TypeChecker::VxiOnlyEntry> &only_symbols,
    const std::string &module_name) {
    std::vector<std::string> missing;
    if (only_symbols.empty()) return missing;

    // Mapa name -> indice en mod.symbols para lookup O(1).
    std::unordered_map<std::string, size_t> by_name;
    by_name.reserve(mod.symbols.size() * 2);
    for (size_t i = 0; i < mod.symbols.size(); ++i) {
        by_name.emplace(mod.symbols[i].name, i);
    }

    // Primera pasada: identificar simbolos faltantes.  Solo se serializan al
    // .vxi los simbolos PUBLICOS, asi que un `not found` significa "no
    // existe" O "existe pero es privado".  Para el usuario el mensaje es el
    // mismo en ambos casos (privado == no exportado).
    for (const auto &os : only_symbols) {
        if (by_name.find(os.name) == by_name.end()) {
            missing.push_back(os.name);
        }
    }

    // Delegar la inyeccion real a la variante simple (ya skipea los missing
    // silenciosamente).  De esta manera no duplicamos la logica de switch
    // sobre VxiSymbolKind.
    import_vxi_into_typechecker(tc, mod, only_symbols, module_name);

    return missing;
}

// =========================================================================
//  M.7: namespace qualified imports.
//
// Cuando `import "lib_a";` (sin `only`) o `import "lib_a" as foo;` se
// procesa, el compiler_project llama @c register_namespace_for_import
// para registrar el modulo como @c Symbol::Namespace en el scope global
// del consumidor.  El consumidor accede a @c lib_a.valor_a / @c foo.valor_a
// como FieldAccessExpr donde la base es un IdentExpr que resuelve a
// Namespace.  El check_field_access del type checker detecta el caso
// y resuelve el simbolo del namespace.
// =========================================================================

void register_namespace_for_import(TypeChecker &tc,
                                   const std::string &local_name,
                                   const std::string &module_name,
                                   const VxiModule &mod) {
    const uint32_t ns_idx =
        tc.register_imported_namespace(local_name, module_name);
    //  M7.b: para que `lib.MyClass` funcione como tipo qualified
    // (clase, struct, enum o typedef), necesitamos:
    //   1. Inyectar el layout en class_layouts_ / struct_layouts_ /
    //      enum_layouts_ / type_aliases_ del consumer, pero usando
    //      NOMBRE MANGLED (`<module>__<TypeName>`) para evitar colision
    //      con tipos locales del consumer del mismo nombre.
    //   2. Registrar Sym en el namespace con mangled_label apuntando a
    //      ese mismo mangled name, kind=2 (TypeAlias).
    // El type_checker ya tiene la resolucion (M7.c lineas 1471+):
    // detecta `lib.MyClass`, busca Sym en namespace, usa mangled_label
    // para lookup en layouts.  Solo faltaban estos dos pasos.
    // Helper local para resolver typenames con fallback a la version
    // mangled del modulo.  Si el .vxi exporta `return_type = "Point"` pero
    // el consumer registro el tipo como `lib__Point` (M7.b), debemos probar
    // ambos.  Cubre el bug 2 (struct value return cross-module).
    auto resolve_with_mangled_fallback = [&](const std::string &name) -> Type {
        Type t = tc.resolve_type_string(name);
        if (t.kind != PrimitiveKind::VOID || name == "void") return t;
        // Si la resolucion plana fallo, intentar con mangling.
        const std::string mangled = module_name + "__" + name;
        return tc.resolve_type_string(mangled);
    };

    // PASE 1a: pre-registrar el SKELETON de cada tipo (solo nombre + size,
    // sin fields/methods/variants) para que los tipos del mismo modulo
    // dep se vean entre si al resolver fields en el sub-pase 1b.  Ej:
    // `Workspace.active : EditorTab` resuelve correctamente aunque
    // Workspace aparezca antes que EditorTab en mod.symbols.
    //
    // LANG.fix-3: ademas de registrar el layout, marcar el NOMBRE MANGLED
    // como imported (sin re-export) para que cuando el modulo consumer
    // se exporte a su propia .vxi, NO incluya estos tipos importados
    // como simbolos exportados.  Sin esto, una cadena main -> outer ->
    // inner re-exportaba `inner__Bar` desde outer.vxi (double-mangling
    // y type mismatches).
    for (const auto &s : mod.symbols) {
        if (s.kind == VxiSymbolKind::FUNCTION) continue;
        if (s.kind == VxiSymbolKind::GLOBAL_VAR) continue;
        // La identidad de un tipo sale del namespace donde se DECLARA, no del
        // modulo por el que entra.  Es la MISMA regla que usa la ruta `only`
        // (`canon`), y tenerlas distintas creaba DOS registros del mismo tipo:
        // `ch__base__handle` por una y `ch__top__handle` por la otra.
        //
        // Depende de que `ns_path` sobreviva a los re-exports (lo garantiza el
        // registro del origen al importar): sin eso, los nombres ya venian
        // cualificados y volver a prefijarlos daba `ch__top__ch__base__handle`.
        const std::string mangled_pre = s.ns_path.empty()
                                            ? qualify_once_(module_name, s.name)
                                            : qualify_once_(s.ns_path, s.name);
        switch (s.kind) {
        case VxiSymbolKind::STRUCT: {
            StructLayout L;
            L.name = mangled_pre;
            L.size_bytes = s.size_bytes;
            L.align_bytes = s.align_bytes;
            tc.register_imported_struct(mangled_pre, std::move(L));
            tc.mark_imported(mangled_pre, /*is_reexport=*/false);
            break;
        }
        case VxiSymbolKind::CLASS: {
            ClassLayout L;
            L.name = mangled_pre;
            L.imported_helper_suffix = s.name;
            L.size_bytes = s.size_bytes;
            tc.register_imported_class(mangled_pre, std::move(L));
            tc.mark_imported(mangled_pre, /*is_reexport=*/false);
            break;
        }
        case VxiSymbolKind::ENUM: {
            // Esqueleto: reserva el nombre para que los tipos que se resuelvan
            // entre medias lo encuentren.  Lleva ya el tipo de respaldo, o
            // entre este registro y el definitivo cualquier uso tomaria el
            // enum por uno de variantes.
            EnumLayout L = enum_layout_from_vxi_(tc, s, mangled_pre,
                                                 /*with_payloads=*/false);
            // Si el enum ya entro COMPLETO por la inyeccion selectiva, este
            // esqueleto no debe pisarlo: es mas pobre, y sobrescribirlo le
            // quita al enum con valor su tipo base -- sus variantes dejan de
            // ser el entero que son para volverse direcciones de buffers.
            tc.register_imported_enum(mangled_pre, std::move(L));
            tc.mark_imported(mangled_pre, /*is_reexport=*/false);
            break;
        }
        default: break;
        }
    }

    // PASE 1b: rellenar fields/methods/variants ahora que TODOS los
    // tipos del modulo dep tienen skeleton registrado.  Las referencias
    // cross-type dentro del mismo dep ya resuelven via mangled fallback.
    for (const auto &s : mod.symbols) {
        if (s.kind == VxiSymbolKind::FUNCTION) continue;
        if (s.kind == VxiSymbolKind::GLOBAL_VAR) continue;
        // M7.b: tipos cross-module via namespace qualified.
        // Compute mangled name = module_name + "__" + s.name.  Asi el
        // tipo no colisiona con un tipo del mismo nombre en el consumer.
        // NS.2: si el tipo pertenece a un `namespace X;` DECLARADO por el dep,
        // su label real en el dep es `X__Tipo` (ns-mangled por flatten); usamos
        // ESE como clave local para que fields/fns que lo referencian por
        // `X__Tipo` resuelvan directo, y para que `__new_X__Tipo` coincida.
        std::string ns_mangled_prefix;
        for (char c : s.ns_path)
            ns_mangled_prefix +=
                (c == '.') ? std::string("__") : std::string(1, c);
        const std::string mangled = s.ns_path.empty()
                                        ? (module_name + "__" + s.name)
                                        : (ns_mangled_prefix + "__" + s.name);
        switch (s.kind) {
        case VxiSymbolKind::TYPEDEF_ALIAS:
        case VxiSymbolKind::TYPEDEF_NEW: {
            Type underlying = tc.resolve_type_string(s.underlying_type);
            if (underlying.kind == PrimitiveKind::VOID &&
                s.underlying_type != "void") {
                continue; // forward-ref no resolvible -> skip
            }
            if (s.kind == VxiSymbolKind::TYPEDEF_NEW) {
                // Id ESTABLE por identidad mangled: la ruta del `only T`
                // (que registra el newtype bajo el nombre corto) usa el MISMO
                // id derivado de este mismo mangled -> `f(T)` (firma libre) y
                // `T` (tipo importado) unifican.
                underlying.nominal_id = tc.stable_nominal_id(mangled);
                underlying.nominal_name = mangled;
                underlying.is_opaque = s.is_opaque;
                underlying.align_override = s.align_override;
                Type clean = underlying;
                clean.nominal_id = 0;
                clean.nominal_name.clear();
                clean.is_opaque = false;
                clean.align_override = 0;
                tc.register_imported_newtype(mangled, clean);
            }
            tc.register_imported_type_alias(mangled, std::move(underlying));
            // LANG.fix-3: marcar typedef importado para que NO se
            // re-exporte cuando el consumer mismo emita su .vxi.
            tc.mark_imported(mangled, /*is_reexport=*/false);
            break;
        }
        case VxiSymbolKind::STRUCT: {
            StructLayout L;
            L.name = mangled;
            L.size_bytes = s.size_bytes;
            L.align_bytes = s.align_bytes;
            L.fields.reserve(s.fields.size());
            for (const auto &fi : s.fields) {
                StructFieldInfo sfi;
                sfi.name = fi.name;
                //  M.fix-classfield: fallback al mangled del dep
                // para campos con tipo CLASS/STRUCT/ENUM del mismo
                // modulo dep.  El .vxi guarda type_str unmangled
                // ("EditorTab") pero el consumer registra mangled
                // ("tabs__EditorTab"); el fallback lo encuentra.
                sfi.type = resolve_with_mangled_fallback(fi.type_str);
                sfi.offset = fi.offset;
                sfi.size = fi.size;
                sfi.bit_offset = fi.bit_offset;
                sfi.bit_width = fi.bit_width;
                L.fields.push_back(std::move(sfi));
            }
            tc.register_imported_struct(mangled, std::move(L));
            break;
        }
        case VxiSymbolKind::CLASS: {
            ClassLayout L;
            L.name = mangled;
            // dep emitio __new_<label real>.  Para clase namespaced el label
            // real es el ns-mangled (mylib__MyClass); si no, el nombre publico.
            L.imported_helper_suffix = s.ns_path.empty() ? s.name : mangled;
            L.super_name = s.super_class;
            L.size_bytes = s.size_bytes;
            L.fields.reserve(s.fields.size());
            for (const auto &fi : s.fields) {
                StructFieldInfo cfi;
                cfi.name = fi.name;
                cfi.type = resolve_with_mangled_fallback(fi.type_str);
                cfi.offset = fi.offset;
                cfi.size = fi.size;
                cfi.bit_offset = fi.bit_offset;
                cfi.bit_width = fi.bit_width;
                L.fields.push_back(std::move(cfi));
            }
            L.interface_names = s.interfaces;
            L.methods.reserve(s.methods.size());
            for (const auto &mi : s.methods) {
                ClassMethodInfo cmi;
                cmi.name = mi.name;
                cmi.return_type = resolve_with_mangled_fallback(mi.return_type);
                cmi.vtable_index = mi.vtable_index;
                cmi.is_static = (mi.flags & 0x01) != 0;
                cmi.is_constructor = (mi.flags & 0x02) != 0;
                cmi.is_comptime = (mi.flags & 0x08) != 0;
                cmi.defining_class = mangled;
                cmi.param_types.reserve(mi.param_types.size());
                for (const auto &pt : mi.param_types) {
                    cmi.param_types.push_back(
                        resolve_with_mangled_fallback(pt));
                }
                L.methods.push_back(std::move(cmi));
            }
            tc.register_imported_class(mangled, std::move(L));
            break;
        }
        case VxiSymbolKind::ENUM: {
            EnumLayout L;
            L.name = mangled;
            L.variants.reserve(s.variants.size());
            L.size_bytes = static_cast<uint32_t>(s.size_bytes);
            // Enum con valor: recuperar el tipo de respaldo y los valores.
            if (!s.underlying_type.empty()) {
                const Type bt = tc.resolve_type_string(s.underlying_type);
                if (bt.kind != PrimitiveKind::VOID) {
                    L.is_valued = true;
                    L.backing = bt.kind;
                }
            }
            for (const auto &v : s.variants) {
                EnumVariantInfo ev;
                ev.name = v.name;
                ev.tag = v.tag;
                ev.int_value = v.int_value;
                ev.field_types.reserve(v.payload_types.size());
                for (const auto &pt : v.payload_types) {
                    ev.field_types.push_back(resolve_with_mangled_fallback(pt));
                }
                L.variants.push_back(std::move(ev));
            }
            tc.register_imported_enum(mangled, std::move(L));
            break;
        }
        case VxiSymbolKind::GLOBAL_VAR: {
            // M.L7 ext: globals const cross-module via namespace plain.
            // v4: si el simbolo tiene blob ref (string/array/struct),
            // leemos el blob del pool del .vxi y lo registramos como
            // comptime const string/array/struct importado.
            Type t = tc.resolve_type_string(s.underlying_type);
            if (t.kind == PrimitiveKind::VOID && s.underlying_type != "void") {
                continue; // tipo no resolvible -> skip silente
            }
            if (s.is_const && s.has_init_value) {
                tc.register_imported_global(s.name, t,
                                            /*is_const=*/true,
                                            /*has_init_value=*/true,
                                            s.init_value);
            }
            if (s.is_const && s.has_blob_ref) {
                // Leer el blob desde el pool del .vxi.
                const VxiBlobHeader *bh =
                    vxi_blob_read(mod.blob_pool, s.blob_offset);
                const uint8_t *payload =
                    vxi_blob_payload(mod.blob_pool, s.blob_offset);
                if (bh && payload &&
                    bh->kind == static_cast<uint32_t>(VxiBlobKind::STRING)) {
                    std::string str_val(reinterpret_cast<const char *>(payload),
                                        bh->count);
                    tc.register_imported_global_str(s.name, t,
                                                    std::move(str_val));
                }
                // Otros kinds (array/struct) requeriran extender
                // imported_global_consts_ con esos tipos -- pendiente
                // en proxima sub-fase.  Por ahora, registrar solo el
                // Sym sin valor para que la resolucion de nombre no
                // falle silenciosamente.
            }
            TypeChecker::ImportedNamespace::Sym sym;
            sym.kind = 1; // Variable / Constant
            sym.mangled_label = s.mangled_label.empty()
                                    ? (module_name + "__" + s.name)
                                    : s.mangled_label;
            sym.var_type = t;
            sym.has_const_value = s.is_const && s.has_init_value;
            sym.const_value = static_cast<int64_t>(s.init_value);
            tc.register_namespace_symbol(ns_idx, s.name, std::move(sym));
            continue; // ya registrado, saltar el push generico
        }
        default: continue;
        }
        // Registrar Sym en el namespace con mangled_label apuntando
        // al layout recien inyectado.  El type_checker resuelve
        // `lib.MyClass` via `sym.mangled_label` lookup en layouts.
        TypeChecker::ImportedNamespace::Sym sym;
        sym.kind = 2; // TypeAlias
        sym.mangled_label = mangled;
        // NS.2: si el tipo pertenece a un namespace DECLARADO por el dep,
        // registrarlo bajo ESE namespace (mylib.MyClass), no bajo el del
        // modulo.
        const uint32_t type_target_ns =
            s.ns_path.empty()
                ? ns_idx
                : tc.register_imported_namespace(s.ns_path, module_name);
        tc.register_namespace_symbol(type_target_ns, s.name, std::move(sym));
    }

    // PASE 2: registrar FUNCTIONS y GLOBAL_VAR (que tambien podrian usar
    // structs como tipo).  Ahora los layouts ya estan en el TypeChecker;
    // el resolver con fallback encontrara "lib__Point" si "Point" no esta.
    for (const auto &s : mod.symbols) {
        if (s.kind == VxiSymbolKind::FUNCTION) {
            TypeChecker::ImportedNamespace::Sym sym;
            sym.kind = 0;
            sym.mangled_label =
                s.mangled_label.empty() ? s.name : s.mangled_label;
            sym.sig.return_type = resolve_with_mangled_fallback(s.return_type);
            sym.sig.param_types.reserve(s.param_types.size());
            for (const auto &pt : s.param_types) {
                sym.sig.param_types.push_back(
                    resolve_with_mangled_fallback(pt));
            }
            sym.sig.extern_lib = s.is_extern ? s.extern_lib : std::string();
            sym.sig.mangled_label = sym.mangled_label;
            // LIM-A: preservar @Naked para enrutar la llamada cross-modulo
            // via namespace (`lib.fn(...)`) al dispatcher naked en interp/JIT.
            sym.sig.is_naked = s.is_naked;
            // NS.2: si la funcion pertenece a un namespace DECLARADO por el dep
            // (`namespace mylib;`), la registramos bajo ESE namespace (mylib)
            // para que el consumidor la vea como `mylib.helper()` (desacoplado
            // del nombre del modulo).  register_imported_namespace dedupea por
            // nombre, asi que varios simbolos del mismo namespace comparten
            // idx.
            const uint32_t target_ns =
                s.ns_path.empty()
                    ? ns_idx
                    : tc.register_imported_namespace(s.ns_path, module_name);
            tc.register_namespace_symbol(target_ns, s.name, std::move(sym));
        } else if (s.kind == VxiSymbolKind::GLOBAL_VAR) {
            // M.L7 ext: globals const cross-module via namespace plain.
            // v4: si tiene blob_ref, leemos el blob string del pool.
            Type t = resolve_with_mangled_fallback(s.underlying_type);
            if (t.kind == PrimitiveKind::VOID && s.underlying_type != "void") {
                continue;
            }
            if (s.is_const && s.has_init_value) {
                tc.register_imported_global(s.name, t,
                                            /*is_const=*/true,
                                            /*has_init_value=*/true,
                                            s.init_value);
            }
            if (s.is_const && s.has_blob_ref) {
                const VxiBlobHeader *bh =
                    vxi_blob_read(mod.blob_pool, s.blob_offset);
                const uint8_t *payload =
                    vxi_blob_payload(mod.blob_pool, s.blob_offset);
                if (bh && payload &&
                    bh->kind == static_cast<uint32_t>(VxiBlobKind::STRING)) {
                    std::string str_val(reinterpret_cast<const char *>(payload),
                                        bh->count);
                    tc.register_imported_global_str(s.name, t,
                                                    std::move(str_val));
                }
            }
            TypeChecker::ImportedNamespace::Sym sym;
            sym.kind = 1;
            sym.mangled_label = s.mangled_label.empty()
                                    ? (module_name + "__" + s.name)
                                    : s.mangled_label;
            sym.var_type = t;
            sym.has_const_value = s.is_const && s.has_init_value;
            sym.const_value = static_cast<int64_t>(s.init_value);
            // NS.2: global de un namespace DECLARADO -> registrar bajo ese
            // namespace (mylib.CLEAR), no bajo el namespace del modulo.
            const uint32_t target_ns_g =
                s.ns_path.empty()
                    ? ns_idx
                    : tc.register_imported_namespace(s.ns_path, module_name);
            tc.register_namespace_symbol(target_ns_g, s.name, std::move(sym));
        }
    }

    // NS.2-full: si el modulo declara UN namespace (ns_path) y el local_name
    // (alias del import o el module_name por defecto) difiere de el, apuntar
    // el alias a ese namespace para que `alias.Sym` resuelva igual que
    // `ns_path.Sym`.  Arregla `import a.b.c as x;` (y el alias por-path con
    // namespace declarado, que estaba roto pre-existente).
    {
        std::string primary_ns;
        bool multiple = false;
        for (const auto &s : mod.symbols) {
            if (s.ns_path.empty()) continue;
            if (primary_ns.empty()) {
                primary_ns = s.ns_path;
            } else if (primary_ns != s.ns_path) {
                multiple = true;
                break;
            }
        }
        if (!multiple && !primary_ns.empty() && primary_ns != local_name) {
            const uint32_t target =
                tc.register_imported_namespace(primary_ns, module_name);
            tc.point_namespace_alias(local_name, target);
        }
    }
}

} // namespace vx
