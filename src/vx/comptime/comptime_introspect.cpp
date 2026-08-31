/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file comptime_introspect.cpp
 * @brief Implementacion de los helpers de la rama A (compile-time) de
 *        introspection.  Resuelve metadata por valor literal sin tocar
 *        runtime.  Llamado tanto desde el type checker (validacion) como
 *        desde el lowering (emision de CONST IR).
 *
 * @note LEGACY -- el tree-walker `comptime_eval_expr` / `comptime_eval_stmt`
 *       de este fichero NO es el mecanismo de EJECUCION de codigo comptime del
 *       lenguaje.  El mecanismo real es el ComptimeRuntime (MC): todo cuerpo
 *       comptime (`comptime fn`, `comptime { }`, `@Macro`) se baja a IR y se
 *       ejecuta en la ComptimeVM por INTERPRETE o JIT (JIT preferido; el
 *       interprete es solo el fallback cuando el JIT no puede compilar la fn).
 *       Este evaluador de AST queda como resto legacy (resolucion de metadata
 *       literal simple) y NO debe usarse como base para features nuevas de
 *       ejecucion comptime -- esas van por IR -> ComptimeVM (interp/JIT).
 */

#include "vx/comptime/comptime_introspect.h"
#include <algorithm> // UCRT64: no transitivo
#include "vx/lexer.h"
#include "vx/parser.h"
#include "vx/generics/concepts.h" // #6: composicion de conceptos en predicados comptime
#include "ffi/virtual_lib_registry.h" //   : virtual libs

#include <cstdio>
#include <cstring>
#include <unordered_map>

/*   (Camino A): includes para FFI dinamico en compile time.
 * El AST evaluator gana capacidad de invocar funciones declaradas
 * `extern "lib" fn ...` durante la evaluacion comptime, exactamente
 * como lo hace la VM en runtime.  Asi `static_assert`, `comptime_compile`,
 * etc. se vuelven implementables como `extern "vesta_comptime" fn ...`
 * y se eliminan como casos especiales del COMPTIME_ONLY set. */
#if defined(_WIN32)
/* Aislar windows.h: sin esto contamina con macros como min/max,
 * IN/OUT (PARAM_INFO), interface (struct), y la mas peligrosa --
 * static_assert (que como macro toma 2 args sin coma; quema el
 * comptime_introspect.h donde lo usa el static_assert). */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
/* Defensas adicionales contra symbols Windows que colisionan con
 * identifiers del codigo Vesta.  Estos #undef solo afectan a este TU. */
#ifdef interface
#undef interface
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef VOID
#undef VOID
#endif
#ifdef CONST
#undef CONST
#endif
#ifdef IN
#undef IN
#endif
#ifdef OUT
#undef OUT
#endif
#ifdef OPTIONAL
#undef OPTIONAL
#endif
#else
#include <dlfcn.h>
#endif

namespace vx {

/* A.40: forward decls del mini-interprete usadas en este TU. */
static bool comptime_eval_stmt_3arg(TypeChecker &tc, const ast::Stmt *s,
                                    ComptimeEvalResult &return_value,
                                    bool &returned);
static ComptimeEvalResult comptime_call_fn(TypeChecker &tc,
                                           const ast::FunctionDecl *fn,
                                           std::vector<ComptimeEvalResult> args,
                                           std::vector<Type> type_args);

uint64_t comptime_type_size(const TypeChecker &tc, const Type &t) {
    switch (t.kind) {
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
    case PrimitiveKind::CLASS: return 8;
    case PrimitiveKind::STRING: return 8;
    case PrimitiveKind::FUNCTION: return 16;
    /* Un `Optional` NO mide siempre lo mismo: depende de lo que envuelva, y
     * cuando el valor no puede ser cero no lleva marca aparte y son ocho en
     * vez de dieciseis.  Lo decide `TypeChecker::optional_layout`, que es el
     * unico sitio que sabe como esta puesto en memoria.
     *
     * Escrito aqui aparte -- un 16 clavado -- `sizeof<Optional<borrow<i64>>>()`
     * decia dieciseis mientras el bajado reservaba ocho.  Es exactamente lo que
     * avisa la nota de los punteros inteligentes tres lineas mas abajo, escrita
     * antes y por lo mismo. */
    case PrimitiveKind::OPTIONAL: return tc.optional_layout(t).bytes;
    case PrimitiveKind::RESULT: return tc.result_layout(t).bytes;
    /* La ranura de un puntero inteligente la decide un solo sitio
     * (smart_ptr_slot_bytes), que es donde ira la optimizacion de ocupar menos
     * cuando se pueda.  Escrito aqui aparte, `sizeof<T>` empezaria a decir un
     * numero y el bajado a reservar otro en cuanto uno de los dos cambiara. */
    case PrimitiveKind::UNIQUE_PTR:
    case PrimitiveKind::SHARED_PTR: return smart_ptr_slot_bytes(t.kind);
    case PrimitiveKind::BORROW: return 8;
    case PrimitiveKind::BORROW_MUT: return 8;
    case PrimitiveKind::FUTURE: return 8;
    case PrimitiveKind::STRUCT: {
        auto it = tc.struct_layouts().find(t.struct_name);
        if (it != tc.struct_layouts().end()) {
            // Overlay: `sizeof(T)` = HUELLA de la vista (para reservar el
            // buffer de respaldo), no @c size_bytes=8 (el puntero).
            if (it->second.is_overlay) return it->second.overlay_extent;
            return it->second.size_bytes;
        }
        auto en = tc.enum_layouts().find(t.struct_name);
        if (en != tc.enum_layouts().end()) {
            return en->second.size_bytes;
        }
        auto cl = tc.class_layouts().find(t.struct_name);
        if (cl != tc.class_layouts().end()) {
            return 8;
        }
        return 0;
    }
    case PrimitiveKind::ARRAY: {
        if (t.array_size == 0) return 8; /* decay-to-ptr o T[] sin tamano */
        if (!t.pointee) return 0;
        const uint64_t elem = comptime_type_size(tc, *t.pointee);
        return elem * static_cast<uint64_t>(t.array_size);
    }
    default: return 0;
    }
}

uint64_t comptime_type_align(const TypeChecker &tc, const Type &t) {
    switch (t.kind) {
    case PrimitiveKind::STRUCT: {
        auto it = tc.struct_layouts().find(t.struct_name);
        if (it != tc.struct_layouts().end()) return it->second.align_bytes;
        /* Enum y Class siempre 8 (puntero o tagged union qword). */
        return 8;
    }
    case PrimitiveKind::ARRAY: {
        if (t.array_size == 0) return 8;
        if (!t.pointee) return 1;
        return comptime_type_align(tc, *t.pointee);
    }
    default:
        /* Lo que no lleva layout propio lo decide la tabla comun, que es la
         * misma que usa el calculo del layout de un struct.  Estaba escrito
         * aqui aparte, y de las dos versiones la que acertaba era esta: el
         * layout tomaba la alineacion IGUAL al tamano, y para un `Result` eso
         * daba veinticuatro. */
        return primitive_align_bytes(t.kind);
    }
}

// NS.1: los tipos declarados en un namespace tienen nombre FISICO mangled
// (`a__b__Vec3`); la introspeccion (typename<T> etc.) debe devolver el nombre
// PUBLICO simple (`Vec3`), no el interno.  El separador de namespace es `__`;
// el nombre publico es el ultimo segmento.
static std::string ns_public_name_(const std::string &n) {
    size_t p = n.rfind("__");
    return (p == std::string::npos) ? n : n.substr(p + 2);
}

std::string comptime_type_name(const TypeChecker &tc, const Type &t) {
    // Newtype (typedef T name new): es NOMINALMENTE distinto del underlying.
    // Devolver su nombre propio para que is_same<user_id, group_id> sea false
    // aunque ambos compartan representacion u64 (bug 168/169).  nominal_id>0
    // identifica univocamente al newtype.
    if (t.nominal_id != 0 && !t.nominal_name.empty())
        return ns_public_name_(t.nominal_name);
    /* Aqui SOLO estan los tipos cuyo nombre depende de lo que llevan dentro --
     * un puntero, un array, un `Optional<T>` -- y por eso hace falta bajar
     * recursivamente.  Los demas los nombra `primitive_name` en el `default`
     * de abajo, que es la tabla de siempre.
     *
     * Los catorce escalares estaban ademas escritos aqui, diciendo lo mismo.
     * Coincidian, pero eran dos tablas: un tipo nuevo se nombraba en una y en
     * la otra salia el nombre por defecto -- que es como las ocho colecciones
     * primitivas acabaron devolviendo "?" en `typename<T>`. */
    switch (t.kind) {
    case PrimitiveKind::PTR: {
        if (!t.pointee) return "void*";
        return comptime_type_name(tc, *t.pointee) +
               (t.is_virtual ? "*virtual" : "*");
    }
    case PrimitiveKind::CLASS:
    case PrimitiveKind::STRUCT:
        return t.struct_name.empty() ? "?" : ns_public_name_(t.struct_name);
    case PrimitiveKind::FUNCTION: {
        std::string r = "fn(";
        /* FunctionSig opcional almacenado en t.fn_sig si Vesta lo expone.
         * Si no, devolvemos "fn(...)->?".  Mantener simple para Sprint 1. */
        r += "...)";
        return r;
    }
    case PrimitiveKind::ARRAY: {
        const std::string elem =
            t.pointee ? comptime_type_name(tc, *t.pointee) : "?";
        if (t.array_size != 0) {
            return elem + "[" + std::to_string(t.array_size) + "]";
        }
        return elem + "[]";
    }
    case PrimitiveKind::OPTIONAL: {
        const std::string inner =
            t.pointee ? comptime_type_name(tc, *t.pointee) : "?";
        return "Optional<" + inner + ">";
    }
    case PrimitiveKind::RESULT: {
        const std::string v =
            t.pointee ? comptime_type_name(tc, *t.pointee) : "?";
        const std::string e =
            t.pointee2 ? comptime_type_name(tc, *t.pointee2) : "?";
        return "Result<" + v + "," + e + ">";
    }
    case PrimitiveKind::UNIQUE_PTR: {
        const std::string inner =
            t.pointee ? comptime_type_name(tc, *t.pointee) : "?";
        return "unique<" + inner + ">";
    }
    case PrimitiveKind::SHARED_PTR: {
        const std::string inner =
            t.pointee ? comptime_type_name(tc, *t.pointee) : "?";
        return "shared<" + inner + ">";
    }
    case PrimitiveKind::BORROW: {
        const std::string inner =
            t.pointee ? comptime_type_name(tc, *t.pointee) : "?";
        return "borrow<" + inner + ">";
    }
    case PrimitiveKind::BORROW_MUT: {
        const std::string inner =
            t.pointee ? comptime_type_name(tc, *t.pointee) : "?";
        return "borrow_mut<" + inner + ">";
    }
    case PrimitiveKind::FUTURE: {
        const std::string inner =
            t.pointee ? comptime_type_name(tc, *t.pointee) : "?";
        return "Future<" + inner + ">";
    }
    default:
        /* Lo que no tenga forma propia lo nombra la tabla de types.h, que es
         * la misma que usan los diagnosticos.  Antes salia "?": las ocho
         * colecciones primitivas del lenguaje -- ArrayList, HashMap, HashSet,
         * Queue, Deque, Stack, TreeMap, TreeSet -- no tienen caso aqui y caian
         * a este default, asi que `typename<HashMap>()` no devolvia su nombre
         * pese a que el compilador lo sabe y lo escribe en cualquier mensaje de
         * error.  Preguntando, una clase de tipo nueva tampoco se queda sin
         * nombre por olvido. */
        return primitive_name(t.kind);
    }
}

uint32_t comptime_type_id(const TypeChecker &tc, const Type &t) {
    /* FNV-1a 32-bit del nombre canonico.  Estable cross-build. */
    const std::string n = comptime_type_name(tc, t);
    uint32_t h = 2166136261u;
    for (unsigned char c : n) {
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

ComptimeKind comptime_type_kind(const Type &t) {
    switch (t.kind) {
    case PrimitiveKind::VOID:
    case PrimitiveKind::BOOL:
    case PrimitiveKind::CHAR:
    case PrimitiveKind::I8:
    case PrimitiveKind::I16:
    case PrimitiveKind::I32:
    case PrimitiveKind::I64:
    case PrimitiveKind::U8:
    case PrimitiveKind::U16:
    case PrimitiveKind::U32:
    case PrimitiveKind::U64:
    case PrimitiveKind::F32:
    case PrimitiveKind::F64: return ComptimeKind::Primitive;
    case PrimitiveKind::CLASS: return ComptimeKind::Class;
    case PrimitiveKind::STRUCT: return ComptimeKind::Struct;
    case PrimitiveKind::PTR: return ComptimeKind::Ptr;
    case PrimitiveKind::ARRAY: return ComptimeKind::Array;
    case PrimitiveKind::FUNCTION: return ComptimeKind::Function;
    case PrimitiveKind::STRING: return ComptimeKind::String;
    case PrimitiveKind::OPTIONAL: return ComptimeKind::Optional;
    case PrimitiveKind::RESULT: return ComptimeKind::Result;
    case PrimitiveKind::UNIQUE_PTR: return ComptimeKind::Unique;
    case PrimitiveKind::SHARED_PTR: return ComptimeKind::Shared;
    case PrimitiveKind::BORROW:
    case PrimitiveKind::BORROW_MUT: return ComptimeKind::Borrow;
    case PrimitiveKind::FUTURE: return ComptimeKind::Future;
    default: return ComptimeKind::Unknown;
    }
}

// -------------------------------------------------------------------
// Sprint 2: queries de fields y methods.
// -------------------------------------------------------------------

/**
 * @brief Devuelve un puntero a los fields de @c t (struct o class).
 *
 * Para STRUCT real busca en `struct_layouts`; para CLASS busca en
 * `class_layouts`.  El name esta en `t.struct_name` (overloaded para
 * struct/class/enum -- los enums devuelven nullptr porque no tienen
 * fields en sentido tradicional, tienen variantes).
 */
static const std::vector<StructFieldInfo> *fields_of(const TypeChecker &tc,
                                                     const Type &t) {
    if (t.kind == PrimitiveKind::STRUCT) {
        auto it = tc.struct_layouts().find(t.struct_name);
        if (it != tc.struct_layouts().end()) return &it->second.fields;
        auto cl = tc.class_layouts().find(t.struct_name);
        if (cl != tc.class_layouts().end()) return &cl->second.fields;
    }
    if (t.kind == PrimitiveKind::CLASS) {
        auto cl = tc.class_layouts().find(t.struct_name);
        if (cl != tc.class_layouts().end()) return &cl->second.fields;
    }
    return nullptr;
}

static const std::vector<ClassMethodInfo> *methods_of(const TypeChecker &tc,
                                                      const Type &t) {
    if (t.kind == PrimitiveKind::STRUCT || t.kind == PrimitiveKind::CLASS) {
        auto cl = tc.class_layouts().find(t.struct_name);
        if (cl != tc.class_layouts().end()) return &cl->second.methods;
    }
    return nullptr;
}

int64_t comptime_field_offset(const TypeChecker &tc, const Type &t,
                              const std::string &field_name) {
    const auto *fs = fields_of(tc, t);
    if (!fs) return -1;
    for (const auto &f : *fs) {
        if (f.name == field_name) return static_cast<int64_t>(f.offset);
    }
    return -1;
}

bool comptime_has_field(const TypeChecker &tc, const Type &t,
                        const std::string &name) {
    const auto *fs = fields_of(tc, t);
    if (!fs) return false;
    for (const auto &f : *fs) {
        if (f.name == name) return true;
    }
    return false;
}

bool comptime_has_method(const TypeChecker &tc, const Type &t,
                         const std::string &name) {
    const auto *ms = methods_of(tc, t);
    if (!ms) return false;
    for (const auto &m : *ms) {
        if (m.name == name) return true;
    }
    return false;
}

uint32_t comptime_field_count(const TypeChecker &tc, const Type &t) {
    const auto *fs = fields_of(tc, t);
    if (fs) return static_cast<uint32_t>(fs->size());
    /* ENUM: variant count.  Distinguible de struct/class porque
     * fields_of devolvio nullptr y t.struct_name esta en enum_layouts. */
    if (t.kind == PrimitiveKind::STRUCT) {
        auto en = tc.enum_layouts().find(t.struct_name);
        if (en != tc.enum_layouts().end()) {
            return static_cast<uint32_t>(en->second.variants.size());
        }
    }
    return 0;
}

uint32_t comptime_method_count(const TypeChecker &tc, const Type &t) {
    const auto *ms = methods_of(tc, t);
    if (ms) return static_cast<uint32_t>(ms->size());
    return 0;
}

std::string comptime_field_name(const TypeChecker &tc, const Type &t,
                                uint32_t idx) {
    const auto *fs = fields_of(tc, t);
    if (fs) {
        if (idx < fs->size()) return (*fs)[idx].name;
        return std::string();
    }
    if (t.kind == PrimitiveKind::STRUCT) {
        auto en = tc.enum_layouts().find(t.struct_name);
        if (en != tc.enum_layouts().end()) {
            if (idx < en->second.variants.size()) {
                return en->second.variants[idx].name;
            }
        }
    }
    return std::string();
}

std::string comptime_field_type_name(const TypeChecker &tc, const Type &t,
                                     const std::string &field_name) {
    const auto *fs = fields_of(tc, t);
    if (!fs) return std::string();
    for (const auto &f : *fs) {
        if (f.name == field_name) return comptime_type_name(tc, f.type);
    }
    return std::string();
}

Type comptime_field_type(const TypeChecker &tc, const Type &t,
                         const std::string &field_name) {
    const auto *fs = fields_of(tc, t);
    if (!fs) return Type{PrimitiveKind::COUNT};
    for (const auto &f : *fs) {
        if (f.name == field_name) return f.type;
    }
    return Type{PrimitiveKind::COUNT};
}

// -------------------------------------------------------------------
// Sprint 2: queries de tipos.
// -------------------------------------------------------------------

bool comptime_is_same(const TypeChecker &tc, const Type &a, const Type &b) {
    return comptime_type_name(tc, a) == comptime_type_name(tc, b);
}

bool comptime_is_subtype(const TypeChecker &tc, const Type &sub,
                         const Type &super) {
    if (comptime_is_same(tc, sub, super)) return true;
    /* El recorrido de la jerarquia lo hace el comprobador de tipos, que es
     * quien la construyo: `type_derives_from`.  Aqui habia una segunda copia
     * -- el comentario lo decia, "reimplementado sobre la API publica" -- y las
     * dos no respondian igual: esta subia por la superclase Y por las
     * interfaces, y la del comprobador solo por las interfaces, con lo que a la
     * misma pregunta contestaban cosas distintas. */
    return tc.type_derives_from(sub.struct_name, super.struct_name);
}

bool comptime_is_class(const Type &t) {
    return t.kind == PrimitiveKind::CLASS;
}

bool comptime_is_struct(const TypeChecker &tc, const Type &t) {
    if (t.kind != PrimitiveKind::STRUCT) return false;
    /* Filtramos enums y classes: solo true para layouts en struct_layouts. */
    auto it = tc.struct_layouts().find(t.struct_name);
    return it != tc.struct_layouts().end();
}

bool comptime_is_enum(const TypeChecker &tc, const Type &t) {
    /* Enum con valor de backing entero/float/string: flag explicito. */
    if (t.is_valued_enum) return true;
    /* Enum ADT (o nombre de enum sin valor usado como tipo): llega como
       STRUCT cuyo struct_name esta en enum_layouts_ (no en struct_layouts_). */
    if (t.struct_name.empty()) return false;
    return tc.enum_layouts().find(t.struct_name) != tc.enum_layouts().end();
}

/* F1: ¿el body contiene inline asm directo (AsmStmt) en cualquier container? */
static bool stmt_contains_asm_ci(const ast::Stmt *s) {
    if (!s) return false;
    switch (s->kind) {
    case ast::NodeKind::AsmStmt: return true;
    case ast::NodeKind::BlockStmt: {
        const auto *bs = static_cast<const ast::BlockStmt *>(s);
        for (const auto &st : bs->body)
            if (stmt_contains_asm_ci(st.get())) return true;
        return false;
    }
    case ast::NodeKind::IfStmt: {
        const auto *is = static_cast<const ast::IfStmt *>(s);
        return stmt_contains_asm_ci(is->then_branch.get()) ||
               stmt_contains_asm_ci(is->else_branch.get());
    }
    case ast::NodeKind::WhileStmt:
        return stmt_contains_asm_ci(
            static_cast<const ast::WhileStmt *>(s)->body.get());
    case ast::NodeKind::DoWhileStmt:
        return stmt_contains_asm_ci(
            static_cast<const ast::DoWhileStmt *>(s)->body.get());
    case ast::NodeKind::ForStmt: {
        const auto *fs = static_cast<const ast::ForStmt *>(s);
        return stmt_contains_asm_ci(fs->init.get()) ||
               stmt_contains_asm_ci(fs->body.get());
    }
    default: return false;
    }
}

/* #3: ¿la expresion llama (directamente) a una fn @Naked (cuerpo asm)? */
static bool expr_calls_naked_ci(const TypeChecker &tc, const ast::Expr *e) {
    if (!e) return false;
    switch (e->kind) {
    case ast::NodeKind::CallExpr: {
        const auto *ce = static_cast<const ast::CallExpr *>(e);
        if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr) {
            const auto *cid =
                static_cast<const ast::IdentExpr *>(ce->callee.get());
            const FunctionSig *sig = tc.function_sig_by_name(cid->name);
            if (sig && sig->is_naked) return true;
        }
        for (const auto &a : ce->args)
            if (expr_calls_naked_ci(tc, a.get())) return true;
        return expr_calls_naked_ci(tc, ce->callee.get());
    }
    case ast::NodeKind::BinaryExpr: {
        const auto *bn = static_cast<const ast::BinaryExpr *>(e);
        return expr_calls_naked_ci(tc, bn->lhs.get()) ||
               expr_calls_naked_ci(tc, bn->rhs.get());
    }
    case ast::NodeKind::UnaryExpr:
        return expr_calls_naked_ci(
            tc, static_cast<const ast::UnaryExpr *>(e)->operand.get());
    case ast::NodeKind::CastExpr:
        return expr_calls_naked_ci(
            tc, static_cast<const ast::CastExpr *>(e)->operand.get());
    default: return false;
    }
}

static bool stmt_calls_naked_ci(const TypeChecker &tc, const ast::Stmt *s) {
    if (!s) return false;
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        const auto *bs = static_cast<const ast::BlockStmt *>(s);
        for (const auto &st : bs->body)
            if (stmt_calls_naked_ci(tc, st.get())) return true;
        return false;
    }
    case ast::NodeKind::ExprStmt:
        return expr_calls_naked_ci(
            tc, static_cast<const ast::ExprStmt *>(s)->expr.get());
    case ast::NodeKind::ReturnStmt:
        return expr_calls_naked_ci(
            tc, static_cast<const ast::ReturnStmt *>(s)->value.get());
    case ast::NodeKind::VarDeclStmt:
        return expr_calls_naked_ci(
            tc, static_cast<const ast::VarDeclStmt *>(s)->init.get());
    case ast::NodeKind::IfStmt: {
        const auto *is = static_cast<const ast::IfStmt *>(s);
        return expr_calls_naked_ci(tc, is->cond.get()) ||
               stmt_calls_naked_ci(tc, is->then_branch.get()) ||
               stmt_calls_naked_ci(tc, is->else_branch.get());
    }
    case ast::NodeKind::WhileStmt: {
        const auto *ws = static_cast<const ast::WhileStmt *>(s);
        return expr_calls_naked_ci(tc, ws->cond.get()) ||
               stmt_calls_naked_ci(tc, ws->body.get());
    }
    case ast::NodeKind::DoWhileStmt: {
        const auto *ds = static_cast<const ast::DoWhileStmt *>(s);
        return expr_calls_naked_ci(tc, ds->cond.get()) ||
               stmt_calls_naked_ci(tc, ds->body.get());
    }
    case ast::NodeKind::ForStmt: {
        const auto *fs = static_cast<const ast::ForStmt *>(s);
        return stmt_calls_naked_ci(tc, fs->init.get()) ||
               expr_calls_naked_ci(tc, fs->cond.get()) ||
               expr_calls_naked_ci(tc, fs->step.get()) ||
               stmt_calls_naked_ci(tc, fs->body.get());
    }
    default: return false;
    }
}

bool comptime_fn_uses_asm(const TypeChecker &tc, const ast::FunctionDecl *fd) {
    if (!fd) return false;
    if (fd->is_naked) return true;
    if (stmt_contains_asm_ci(fd->body.get())) return true;
    return stmt_calls_naked_ci(tc, fd->body.get());
}

// -------------------------------------------------------------------
// Deteccion de I/O (println/print/...) en el cuerpo de una comptime fn.
// El tree-walker AST NO ejecuta I/O; esas fns deben correr en la ComptimeVM
// (motor real) para que el `println` salga EN compile-time.  Es un paso de la
// migracion "todo comptime corre en la VM": cada construccion que ruteamos a
// la VM es una menos que hace el tree-walker (que se elimina al final).
// -------------------------------------------------------------------
static bool expr_is_io_call_ci(const ast::Expr *e) {
    if (!e) return false;
    if (e->kind == ast::NodeKind::CallExpr) {
        const auto *ce = static_cast<const ast::CallExpr *>(e);
        if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr) {
            const std::string &nm =
                static_cast<const ast::IdentExpr *>(ce->callee.get())->name;
            // builtins de I/O que solo tienen efecto ejecutandose de verdad.
            if (nm == "println" || nm == "print" || nm == "ct_print" ||
                nm == "comptime_print" || nm == "flush")
                return true;
        }
        for (const auto &a : ce->args)
            if (expr_is_io_call_ci(a.get())) return true;
    }
    return false;
}

static bool stmt_uses_io_ci(const ast::Stmt *s) {
    if (!s) return false;
    switch (s->kind) {
    case ast::NodeKind::ExprStmt:
        return expr_is_io_call_ci(
            static_cast<const ast::ExprStmt *>(s)->expr.get());
    case ast::NodeKind::VarDeclStmt:
        return expr_is_io_call_ci(
            static_cast<const ast::VarDeclStmt *>(s)->init.get());
    case ast::NodeKind::ReturnStmt:
        return expr_is_io_call_ci(
            static_cast<const ast::ReturnStmt *>(s)->value.get());
    case ast::NodeKind::BlockStmt: {
        const auto *bs = static_cast<const ast::BlockStmt *>(s);
        for (const auto &st : bs->body)
            if (stmt_uses_io_ci(st.get())) return true;
        return false;
    }
    case ast::NodeKind::IfStmt: {
        const auto *is = static_cast<const ast::IfStmt *>(s);
        return stmt_uses_io_ci(is->then_branch.get()) ||
               stmt_uses_io_ci(is->else_branch.get());
    }
    case ast::NodeKind::WhileStmt:
        return stmt_uses_io_ci(
            static_cast<const ast::WhileStmt *>(s)->body.get());
    case ast::NodeKind::DoWhileStmt:
        return stmt_uses_io_ci(
            static_cast<const ast::DoWhileStmt *>(s)->body.get());
    case ast::NodeKind::ForStmt: {
        const auto *fs = static_cast<const ast::ForStmt *>(s);
        return stmt_uses_io_ci(fs->init.get()) ||
               stmt_uses_io_ci(fs->body.get());
    }
    default: return false;
    }
}

bool comptime_fn_needs_vm(const TypeChecker &tc, const ast::FunctionDecl *fd) {
    if (!fd) return false;
    /* Los @Macro tienen su PROPIO path de invocacion en la VM (check_call:
     * marshalling de args incl. string, memoizacion @Pure, splice del codigo).
     * needs_vm controla el path de las comptime FN normales (2430); no debe
     * incluir @Macros o los rutearia por el path equivocado (codigo vacio). */
    if (fd->is_macro) return false;
    /* P1 rewrite: TODA comptime fn corre en la ComptimeVM.  Las GENERICAS se
     * monomorfizan antes (la instancia concreta llega aqui sin type_params); el
     * template en si nunca se invoca directo.  Las que devuelven `Type` no se
     * "ejecutan" para producir un valor VM: su resultado (un tipo) se pliega en
     * el consumidor (typename/sizeof) al bajarlo, asi que caen al tree-walker.
     */
    if (!fd->type_params.empty()) return false;
    if (fd->return_type) {
        const Type rt = tc.resolve_type_node(fd->return_type.get());
        if (rt.kind == PrimitiveKind::TYPE_META) return false;
    }
    return true;
}

// -------------------------------------------------------------------
// A.39: mini-interprete para `comptime fn`.
//
// Ejecuta el body de una funcion comptime con los args bindeados.
// Soporta:
//   - BlockStmt
//   - VarDeclStmt (treats como comptime const local)
//   - IfStmt (cond comptime, ejecuta rama elegida)
//   - ReturnStmt
//   - ExprStmt (descartado salvo static_assert que ya se chequeo)
// Las expresiones se reutilizan via comptime_eval_expr.
// -------------------------------------------------------------------

/**
 * @brief Busca en el stack de scopes locales una entrada por nombre.
 * Devuelve nullptr si no esta.
 */
/**
 * @brief A.43.21 fast path multi-chunk -- detecta cadenas
 * `s = s + X1 + X2 + ... + Xn` y appendea cada Xi a la variable s.
 * Recursivo: baja por lhs descubriendo s; cada rhs encontrado se
 * evalua y se appendea en sitio (cero allocs de vector temporal).
 * Transaccional via snapshot del caller (binding.str_value.resize).
 */
static bool walk_and_append_chunks(TypeChecker &tc,
                                   TypeChecker::ComptimeConst &binding,
                                   const ast::Expr *expr,
                                   const std::string &target_name) {
    if (!expr) return false;
    if (expr->kind == ast::NodeKind::IdentExpr) {
        const auto *id = static_cast<const ast::IdentExpr *>(expr);
        return id->name == target_name;
    }
    if (expr->kind == ast::NodeKind::BinaryExpr) {
        const auto *bn = static_cast<const ast::BinaryExpr *>(expr);
        if (bn->op == ast::BinOp::Add) {
            if (walk_and_append_chunks(tc, binding, bn->lhs.get(),
                                       target_name)) {
                ComptimeEvalResult ev = comptime_eval_expr(tc, bn->rhs.get());
                if (!ev.ok || !ev.is_str) return false;
                binding.str_value += ev.str;
                return true;
            }
        }
    }
    return false;
}

/**
 * @brief A.43.19/.21 fast path -- detecta el patron `s = s + X` o
 * `s = s + X1 + X2 + ...` y lo trata como N appends sobre s.  Evita
 * el O(N) de copiar `s` durante la evaluacion del RHS y reduce
 * el coste de loops tipicos de string builder de O(N^2) a O(N).
 *
 * Tambien soporta `s = X + s` (commutativo, prepend simple).
 */
static bool try_self_concat_fast_path(TypeChecker &tc,
                                      TypeChecker::ComptimeConst &binding,
                                      const std::string &lhs_name,
                                      const ast::Expr *rhs_expr,
                                      ast::AssignOp op) {
    if (op != ast::AssignOp::Assign) return false;
    if (!binding.is_mutable || !binding.is_str) return false;
    if (!rhs_expr || rhs_expr->kind != ast::NodeKind::BinaryExpr) return false;
    const auto *bn_root = static_cast<const ast::BinaryExpr *>(rhs_expr);
    if (bn_root->op != ast::BinOp::Add) return false;
    /* A.43.21 fast path simple `s = s + X`: caso comun (~90%).
     * Sin alocacion de vector temporal. */
    if (bn_root->lhs && bn_root->lhs->kind == ast::NodeKind::IdentExpr) {
        const auto *id =
            static_cast<const ast::IdentExpr *>(bn_root->lhs.get());
        if (id->name == lhs_name) {
            ComptimeEvalResult tail =
                comptime_eval_expr(tc, bn_root->rhs.get());
            if (!tail.ok || !tail.is_str) return false;
            binding.str_value += tail.str;
            return true;
        }
    }
    /* A.43.21 multi-chunk path `s = s + X1 + X2 + ... + Xn`: cadena
     * de Adds asociada por izquierda.  Recursion via funcion static
     * (no std::function) para zero overhead.  Transaccional via
     * snapshot: si la cadena falla a mitad, restauramos el binding. */
    const size_t snapshot_size = binding.str_value.size();
    if (walk_and_append_chunks(tc, binding, rhs_expr, lhs_name)) {
        return true;
    }
    binding.str_value.resize(snapshot_size);
    /* Caso simetrico `s = X + s`: simple prepend, O(|s| + |X|).
     * Solo lo aplicamos cuando NO matcheo el chain anterior. */
    if (bn_root->rhs && bn_root->rhs->kind == ast::NodeKind::IdentExpr) {
        const auto *id =
            static_cast<const ast::IdentExpr *>(bn_root->rhs.get());
        if (id->name == lhs_name) {
            ComptimeEvalResult head =
                comptime_eval_expr(tc, bn_root->lhs.get());
            if (!head.ok || !head.is_str) return false;
            binding.str_value.insert(0, head.str);
            return true;
        }
    }
    return false;
}

static TypeChecker::ComptimeConst *
find_comptime_local_mut(TypeChecker &tc, const std::string &name) {
    auto &stack = tc.comptime_const_locals();
    for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
        auto hit = it->find(name);
        if (hit != it->end()) return &hit->second;
    }
    /* A.43.17: tambien buscamos en el mapa GLOBAL de comptime
     * constants/vars.  Esto permite que @Macro y comptime fn
     * lean/escriban estado compartido a nivel modulo, util para
     * generadores acumulativos (id counters, tablas de simbolos,
     * etc.).  La mutabilidad la valida el caller via @c is_mutable. */
    auto &g = tc.comptime_const_values();
    auto git = g.find(name);
    if (git != g.end()) return &git->second;
    return nullptr;
}

/**
 * @brief Aplica una asignacion compuesta sobre un ComptimeConst
 * mutable.  Devuelve true si exito.
 */
static bool apply_comptime_assign(TypeChecker::ComptimeConst &dst,
                                  ComptimeEvalResult &rhs, ast::AssignOp op) {
    if (rhs.is_str && dst.is_str) {
        /* A.43.20: Strings con move.  rhs es local del caller (vive
         * solo hasta el return), asi que podemos mover su buffer en
         * Assign sin riesgo.  Para AddAssign + grandes rhs, mover
         * tambien evita el copy del rhs en operator+=. */
        switch (op) {
        case ast::AssignOp::Assign:
            dst.str_value = std::move(rhs.str);
            return true;
        case ast::AssignOp::AddAssign: dst.str_value += rhs.str; return true;
        default: return false;
        }
    }
    if (rhs.is_str || dst.is_str) return false;
    switch (op) {
    case ast::AssignOp::Assign: dst.value = rhs.value; return true;
    case ast::AssignOp::AddAssign: dst.value += rhs.value; return true;
    case ast::AssignOp::SubAssign: dst.value -= rhs.value; return true;
    case ast::AssignOp::MulAssign: dst.value *= rhs.value; return true;
    case ast::AssignOp::DivAssign:
        if (rhs.value == 0) return false;
        dst.value /= rhs.value;
        return true;
    case ast::AssignOp::ModAssign:
        if (rhs.value == 0) return false;
        dst.value %= rhs.value;
        return true;
    case ast::AssignOp::BitAndAssign: dst.value &= rhs.value; return true;
    case ast::AssignOp::BitOrAssign: dst.value |= rhs.value; return true;
    case ast::AssignOp::BitXorAssign: dst.value ^= rhs.value; return true;
    case ast::AssignOp::ShlAssign: dst.value <<= (rhs.value & 63); return true;
    case ast::AssignOp::ShrAssign: dst.value >>= (rhs.value & 63); return true;
    default: return false;
    }
}

/**
 * @brief Evalua un Stmt en compile-time.  Maneja control de flujo
 * completo (return/break/continue) via @c ComptimeControl.
 */
bool comptime_eval_stmt(TypeChecker &tc, const ast::Stmt *s,
                        ComptimeControl &ctrl) {
    if (!s) return true;
    if (ctrl.returned || ctrl.break_seen || ctrl.continue_seen) return true;
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        auto *b = static_cast<const ast::BlockStmt *>(s);
        tc.push_comptime_scope();
        for (const auto &inner : b->body) {
            if (!comptime_eval_stmt(tc, inner.get(), ctrl)) {
                tc.pop_comptime_scope();
                return false;
            }
            if (ctrl.returned || ctrl.break_seen || ctrl.continue_seen) break;
        }
        tc.pop_comptime_scope();
        return true;
    }
    case ast::NodeKind::VarDeclStmt: {
        auto *vd = static_cast<const ast::VarDeclStmt *>(s);
        if (!vd->init) return false;
        ComptimeEvalResult v = comptime_eval_expr(tc, vd->init.get());
        if (!v.ok) return false;
        TypeChecker::ComptimeConst c;
        c.type = tc.resolve_type_node(vd->type.get());
        c.is_str = v.is_str;
        c.is_array = v.is_array;
        c.is_struct = v.is_struct;
        c.is_mutable = !vd->is_const;
        /* #2 (P1): propagar el flag DIFERIDO.  Si el init depende de una
         * comptime fn ruteada a la VM (que en pass 1 aun no tiene bytecode),
         * v.deferred=true; sin copiarlo, un `static_assert` posterior sobre
         * este local dispararia con el valor placeholder (0) en pass 1 en vez
         * de esperar a pass 2.  Es el bloqueador central para que un block
         * consuma valores calculados en la ComptimeVM. */
        c.deferred = v.deferred;
        if (v.is_str)
            c.str_value = v.str;
        else if (v.is_array)
            c.array_vals = v.array_vals;
        else if (v.is_struct)
            c.struct_fields = v.struct_fields;
        else
            c.value = v.value;
        tc.register_comptime_local(vd->name, std::move(c));
        return true;
    }
    case ast::NodeKind::IfStmt: {
        auto *ifs = static_cast<const ast::IfStmt *>(s);
        ComptimeEvalResult c = comptime_eval_expr(tc, ifs->cond.get());
        if (!c.ok) return false;
        if (c.value != 0) {
            return comptime_eval_stmt(tc, ifs->then_branch.get(), ctrl);
        }
        if (ifs->else_branch) {
            return comptime_eval_stmt(tc, ifs->else_branch.get(), ctrl);
        }
        return true;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *rs = static_cast<const ast::ReturnStmt *>(s);
        if (rs->value) {
            ctrl.return_value = comptime_eval_expr(tc, rs->value.get());
            if (!ctrl.return_value.ok) return false;
        } else {
            ctrl.return_value.ok = true;
            ctrl.return_value.value = 0;
        }
        ctrl.returned = true;
        return true;
    }
    case ast::NodeKind::BreakStmt: ctrl.break_seen = true; return true;
    case ast::NodeKind::ContinueStmt: ctrl.continue_seen = true; return true;
    case ast::NodeKind::WhileStmt: {
        /* A.40: while loop comptime con limite defensivo de
         * iteraciones (1M) para evitar loops infinitos en
         * compile-time. */
        auto *ws = static_cast<const ast::WhileStmt *>(s);
        int iter = 0;
        const int MAX_ITER = 1000000;
        while (iter++ < MAX_ITER) {
            ComptimeEvalResult c = comptime_eval_expr(tc, ws->cond.get());
            if (!c.ok) return false;
            if (c.value == 0) break;
            if (!comptime_eval_stmt(tc, ws->body.get(), ctrl)) return false;
            if (ctrl.returned) break;
            if (ctrl.break_seen) {
                ctrl.break_seen = false;
                break;
            }
            if (ctrl.continue_seen) {
                ctrl.continue_seen = false; /* siguiente iter */
            }
        }
        if (iter >= MAX_ITER) {
            /* No tenemos diags aqui directamente; el caller
             * detectara el problema porque ctrl.returned=false
             * y el resultado quedara incompleto. */
            return false;
        }
        return true;
    }
    case ast::NodeKind::DoWhileStmt: {
        auto *ws = static_cast<const ast::DoWhileStmt *>(s);
        int iter = 0;
        const int MAX_ITER = 1000000;
        while (iter++ < MAX_ITER) {
            if (!comptime_eval_stmt(tc, ws->body.get(), ctrl)) return false;
            if (ctrl.returned) break;
            if (ctrl.break_seen) {
                ctrl.break_seen = false;
                break;
            }
            if (ctrl.continue_seen) {
                ctrl.continue_seen = false;
            }
            ComptimeEvalResult c = comptime_eval_expr(tc, ws->cond.get());
            if (!c.ok) return false;
            if (c.value == 0) break;
        }
        return iter < MAX_ITER;
    }
    case ast::NodeKind::ForStmt: {
        /* C-style for: init + cond + step + body. */
        auto *fs = static_cast<const ast::ForStmt *>(s);
        tc.push_comptime_scope();
        if (fs->init && !comptime_eval_stmt(tc, fs->init.get(), ctrl)) {
            tc.pop_comptime_scope();
            return false;
        }
        int iter = 0;
        const int MAX_ITER = 1000000;
        while (iter++ < MAX_ITER) {
            if (fs->cond) {
                ComptimeEvalResult c = comptime_eval_expr(tc, fs->cond.get());
                if (!c.ok) {
                    tc.pop_comptime_scope();
                    return false;
                }
                if (c.value == 0) break;
            }
            if (!comptime_eval_stmt(tc, fs->body.get(), ctrl)) {
                tc.pop_comptime_scope();
                return false;
            }
            if (ctrl.returned) break;
            if (ctrl.break_seen) {
                ctrl.break_seen = false;
                break;
            }
            if (ctrl.continue_seen) {
                ctrl.continue_seen = false;
            }
            /* A.41: el step es una expresion que puede ser un
             * AssignExpr (e.g. `i = i + 1`).  Lo procesamos como
             * ExprStmt sintetico via comptime_eval_stmt para que
             * la asignacion actualice el binding correctamente. */
            if (fs->step) {
                if (fs->step->kind == ast::NodeKind::AssignExpr) {
                    /* Aplicar asignacion directamente. */
                    auto *ae =
                        static_cast<const ast::AssignExpr *>(fs->step.get());
                    if (ae->target &&
                        ae->target->kind == ast::NodeKind::IdentExpr) {
                        auto *id = static_cast<const ast::IdentExpr *>(
                            ae->target.get());
                        auto *binding = find_comptime_local_mut(tc, id->name);
                        if (binding && binding->is_mutable) {
                            /* A.43.19 fast path: `s = s + X`. */
                            if (try_self_concat_fast_path(
                                    tc, *binding, id->name, ae->value.get(),
                                    ae->op)) {
                                /* OK -- continuar. */
                            } else {
                                ComptimeEvalResult rhs =
                                    comptime_eval_expr(tc, ae->value.get());
                                if (!rhs.ok) {
                                    tc.pop_comptime_scope();
                                    return false;
                                }
                                if (!apply_comptime_assign(*binding, rhs,
                                                           ae->op)) {
                                    tc.pop_comptime_scope();
                                    return false;
                                }
                            }
                        } else {
                            /* No es comptime var -- error. */
                            tc.pop_comptime_scope();
                            return false;
                        }
                    } else {
                        tc.pop_comptime_scope();
                        return false;
                    }
                } else {
                    /* Otra expresion: evaluamos por side effects. */
                    (void)comptime_eval_expr(tc, fs->step.get());
                }
            }
        }
        tc.pop_comptime_scope();
        return iter < MAX_ITER;
    }
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<const ast::ExprStmt *>(s);
        if (!es->expr) return true;
        /* A.40/A.41: asignacion a comptime var (mutable). */
        if (es->expr->kind == ast::NodeKind::AssignExpr) {
            auto *ae = static_cast<const ast::AssignExpr *>(es->expr.get());
            if (ae->target && ae->target->kind == ast::NodeKind::IdentExpr) {
                auto *id =
                    static_cast<const ast::IdentExpr *>(ae->target.get());
                auto *binding = find_comptime_local_mut(tc, id->name);
                if (binding && binding->is_mutable) {
                    /* A.43.19 fast path: `s = s + X` -> `s += X`
                     * para evitar el O(N) de copiar s durante la
                     * evaluacion del RHS.  Convierte el loop
                     * tipico de string builder de O(N^2) a O(N). */
                    if (try_self_concat_fast_path(tc, *binding, id->name,
                                                  ae->value.get(), ae->op)) {
                        return true;
                    }
                    ComptimeEvalResult rhs =
                        comptime_eval_expr(tc, ae->value.get());
                    if (!rhs.ok) return false;
                    if (!apply_comptime_assign(*binding, rhs, ae->op))
                        return false;
                    return true;
                }
                if (binding && !binding->is_mutable) {
                    /* Asignacion a comptime const -- error. */
                    return false;
                }
            }
            /* A.41: obj.field = v -- asignacion a field de
             * comptime struct mutable. */
            if (ae->target &&
                ae->target->kind == ast::NodeKind::FieldAccessExpr) {
                auto *fa =
                    static_cast<const ast::FieldAccessExpr *>(ae->target.get());
                if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
                    auto *id =
                        static_cast<const ast::IdentExpr *>(fa->base.get());
                    auto *binding = find_comptime_local_mut(tc, id->name);
                    if (binding && binding->is_mutable && binding->is_struct) {
                        ComptimeEvalResult rhs =
                            comptime_eval_expr(tc, ae->value.get());
                        if (!rhs.ok) return false;
                        auto &slot_ptr = binding->struct_fields[fa->field_name];
                        if (!slot_ptr)
                            slot_ptr = std::make_shared<ComptimeValue>();
                        ComptimeValue &slot = *slot_ptr;
                        if (ae->op == ast::AssignOp::Assign) {
                            slot = value_from_result(rhs);
                            return true;
                        }
                        if (rhs.is_str || rhs.is_array || rhs.is_struct ||
                            slot.is_str || slot.is_array || slot.is_struct) {
                            return false;
                        }
                        switch (ae->op) {
                        case ast::AssignOp::AddAssign:
                            slot.value += rhs.value;
                            break;
                        case ast::AssignOp::SubAssign:
                            slot.value -= rhs.value;
                            break;
                        case ast::AssignOp::MulAssign:
                            slot.value *= rhs.value;
                            break;
                        case ast::AssignOp::DivAssign:
                            if (rhs.value == 0) return false;
                            slot.value /= rhs.value;
                            break;
                        case ast::AssignOp::ModAssign:
                            if (rhs.value == 0) return false;
                            slot.value %= rhs.value;
                            break;
                        case ast::AssignOp::BitAndAssign:
                            slot.value &= rhs.value;
                            break;
                        case ast::AssignOp::BitOrAssign:
                            slot.value |= rhs.value;
                            break;
                        case ast::AssignOp::BitXorAssign:
                            slot.value ^= rhs.value;
                            break;
                        case ast::AssignOp::ShlAssign:
                            slot.value <<= (rhs.value & 63);
                            break;
                        case ast::AssignOp::ShrAssign:
                            slot.value >>= (rhs.value & 63);
                            break;
                        default: return false;
                        }
                        return true;
                    }
                }
            }
            /* A.41: arr[i] = v -- asignacion a elemento de
             * comptime array mutable. */
            if (ae->target && ae->target->kind == ast::NodeKind::IndexExpr) {
                auto *ix =
                    static_cast<const ast::IndexExpr *>(ae->target.get());
                if (ix->base && ix->base->kind == ast::NodeKind::IdentExpr) {
                    auto *id =
                        static_cast<const ast::IdentExpr *>(ix->base.get());
                    auto *binding = find_comptime_local_mut(tc, id->name);
                    if (binding && binding->is_mutable && binding->is_array) {
                        ComptimeEvalResult idx =
                            comptime_eval_expr(tc, ix->index.get());
                        if (!idx.ok || idx.is_str || idx.is_array ||
                            idx.is_struct)
                            return false;
                        if (idx.value < 0 ||
                            (size_t)idx.value >= binding->array_vals.size()) {
                            return false;
                        }
                        ComptimeEvalResult rhs =
                            comptime_eval_expr(tc, ae->value.get());
                        if (!rhs.ok) return false;
                        auto &slot_ptr = binding->array_vals[(size_t)idx.value];
                        if (!slot_ptr)
                            slot_ptr = std::make_shared<ComptimeValue>();
                        ComptimeValue &slot = *slot_ptr;
                        if (ae->op == ast::AssignOp::Assign) {
                            slot = value_from_result(rhs);
                            return true;
                        }
                        if (rhs.is_str || rhs.is_array || rhs.is_struct ||
                            slot.is_str || slot.is_array || slot.is_struct) {
                            return false;
                        }
                        switch (ae->op) {
                        case ast::AssignOp::AddAssign:
                            slot.value += rhs.value;
                            break;
                        case ast::AssignOp::SubAssign:
                            slot.value -= rhs.value;
                            break;
                        case ast::AssignOp::MulAssign:
                            slot.value *= rhs.value;
                            break;
                        case ast::AssignOp::DivAssign:
                            if (rhs.value == 0) return false;
                            slot.value /= rhs.value;
                            break;
                        case ast::AssignOp::ModAssign:
                            if (rhs.value == 0) return false;
                            slot.value %= rhs.value;
                            break;
                        case ast::AssignOp::BitAndAssign:
                            slot.value &= rhs.value;
                            break;
                        case ast::AssignOp::BitOrAssign:
                            slot.value |= rhs.value;
                            break;
                        case ast::AssignOp::BitXorAssign:
                            slot.value ^= rhs.value;
                            break;
                        case ast::AssignOp::ShlAssign:
                            slot.value <<= (rhs.value & 63);
                            break;
                        case ast::AssignOp::ShrAssign:
                            slot.value >>= (rhs.value & 63);
                            break;
                        default: return false;
                        }
                        return true;
                    }
                }
            }
        }
        /* Caso general: evaluar por side effects comptime
         * (e.g. static_assert que emite errores en check_call). */
        ComptimeEvalResult v = comptime_eval_expr(tc, es->expr.get());
        (void)v;
        return true;
    }
    default: return false;
    }
}

/**
 * @brief Ejecuta una @c comptime fn con args bindeados a sus params.
 *
 * Push scope con params; ejecuta el body; pop scope.  Devuelve el
 * valor de retorno o @c ok=false si el body no produjo return o
 * sobrepaso el limite de recursion.
 */
static ComptimeEvalResult comptime_call_fn(TypeChecker &tc,
                                           const ast::FunctionDecl *fn,
                                           std::vector<ComptimeEvalResult> args,
                                           std::vector<Type> type_args) {
    ComptimeEvalResult r{};
    if (!fn || !fn->body) return r;
    if (args.size() != fn->params.size()) return r;
    /* A.41: validar aridad de type-args si la fn es generica. */
    if (!fn->type_params.empty() &&
        type_args.size() != fn->type_params.size()) {
        return r;
    }
    /* A.43.20: memoizacion para fns @Pure.  Cache key = nombre +
     * args serializados + type_args serializados.  Hit -> retorno
     * directo sin reejecutar el body.  Coste cache miss = 1 hash
     * + 1 lookup + insert; coste cache hit = 1 hash + 1 lookup. */
    std::string cache_key;
    const bool memoizable = fn->is_pure;
    if (memoizable) {
        cache_key.reserve(64);
        cache_key.append(fn->name);
        cache_key.push_back('|');
        for (const auto &a : args) {
            if (a.is_str) {
                cache_key.push_back('S');
                cache_key.append(std::to_string(a.str.size()));
                cache_key.push_back(':');
                cache_key.append(a.str);
            } else {
                cache_key.push_back('I');
                cache_key.append(std::to_string(a.value));
            }
            cache_key.push_back(',');
        }
        cache_key.push_back('|');
        for (const auto &t : type_args) {
            cache_key.append(comptime_type_name(tc, t));
            cache_key.push_back(',');
        }
        auto &cache = tc.pure_macro_cache();
        auto it = cache.find(cache_key);
        if (it != cache.end() && it->second) {
            return *it->second; /* hit: reusa resultado */
        }
    }
    int &depth = tc.comptime_recursion_depth();
    if (depth >= 256) return r;
    ++depth;
    /* A.41: push type-scope con los bindings T_i -> type_args[i]. */
    tc.push_comptime_type_scope();
    for (size_t i = 0; i < fn->type_params.size() && i < type_args.size();
         ++i) {
        tc.register_comptime_type(fn->type_params[i], type_args[i]);
    }
    tc.push_comptime_scope();
    for (size_t i = 0; i < fn->params.size(); ++i) {
        TypeChecker::ComptimeConst c;
        c.type = tc.resolve_type_node(fn->params[i]->type.get());
        c.is_str = args[i].is_str;
        c.is_array = args[i].is_array;
        c.is_struct = args[i].is_struct;
        if (args[i].is_str)
            c.str_value = args[i].str;
        else if (args[i].is_array)
            c.array_vals = args[i].array_vals;
        else if (args[i].is_struct)
            c.struct_fields = args[i].struct_fields;
        else
            c.value = args[i].value;
        tc.register_comptime_local(fn->params[i]->name, std::move(c));
    }
    bool returned = false;
    ComptimeEvalResult ret{};
    (void)comptime_eval_stmt_3arg(tc, fn->body.get(), ret, returned);
    tc.pop_comptime_scope();
    tc.pop_comptime_type_scope();
    --depth;
    if (!returned) return r;
    /* A.43.20: cachear resultado si la fn es @Pure. */
    if (memoizable && ret.ok) {
        tc.pure_macro_cache()[cache_key] =
            std::make_shared<ComptimeEvalResult>(ret);
    }
    return ret;
}

bool comptime_is_primitive(const Type &t) {
    switch (t.kind) {
    case PrimitiveKind::VOID:
    case PrimitiveKind::BOOL:
    case PrimitiveKind::CHAR:
    case PrimitiveKind::I8:
    case PrimitiveKind::I16:
    case PrimitiveKind::I32:
    case PrimitiveKind::I64:
    case PrimitiveKind::U8:
    case PrimitiveKind::U16:
    case PrimitiveKind::U32:
    case PrimitiveKind::U64:
    case PrimitiveKind::F32:
    case PrimitiveKind::F64: return true;
    default: return false;
    }
}

// -------------------------------------------------------------------
// Sprint 3-B: evaluador comptime de expresiones AST.
//
// Soporta literales, builtins comptime y operadores aritmeticos/
// logicos sobre constantes.  Devuelve `ok=false` si la expresion
// depende de valores runtime.  Los booleanos se codifican como 0/1.
// -------------------------------------------------------------------

/**
 * @brief Helper interno para evaluar una llamada a builtin comptime.
 *
 * Reconoce los mismos builtins que `try_lower_builtin_call` resuelve a
 * CONST IR, pero evaluados aqui en el type checker.  Para los que
 * devuelven string (typename/field_name/field_type) devuelve `ok=false`
 * porque comptime if solo necesita ints/bools; permitirlo en un
 * `comptime if` no tiene sentido semantico (string != entero).
 */
static ComptimeEvalResult eval_builtin_call(const TypeChecker &tc,
                                            const ast::CallExpr *ce) {
    ComptimeEvalResult r{};
    auto *id = dynamic_cast<const ast::IdentExpr *>(ce->callee.get());
    if (!id) return r;
    const std::string &nm = id->name;
    if (ce->type_args.empty()) return r;
    const Type t1 = tc.resolve_type_node(ce->type_args[0].get());

    if (nm == "sizeof") {
        r.ok = true;
        r.value = (int64_t)comptime_type_size(tc, t1);
        return r;
    }
    if (nm == "alignof") {
        r.ok = true;
        r.value = (int64_t)comptime_type_align(tc, t1);
        return r;
    }
    if (nm == "type_id") {
        r.ok = true;
        r.value = (int64_t)comptime_type_id(tc, t1);
        return r;
    }
    if (nm == "kind") {
        r.ok = true;
        r.value = (int64_t)static_cast<int32_t>(comptime_type_kind(t1));
        return r;
    }
    if (nm == "field_count") {
        r.ok = true;
        r.value = (int64_t)comptime_field_count(tc, t1);
        return r;
    }
    if (nm == "method_count") {
        r.ok = true;
        r.value = (int64_t)comptime_method_count(tc, t1);
        return r;
    }
    if (nm == "is_class") {
        r.ok = true;
        r.value = comptime_is_class(t1) ? 1 : 0;
        return r;
    }
    if (nm == "is_struct") {
        r.ok = true;
        r.value = comptime_is_struct(tc, t1) ? 1 : 0;
        return r;
    }
    if (nm == "is_primitive") {
        r.ok = true;
        r.value = comptime_is_primitive(t1) ? 1 : 0;
        return r;
    }
    if (nm == "is_enum") {
        r.ok = true;
        r.value = comptime_is_enum(tc, t1) ? 1 : 0;
        return r;
    }
    /* #6: predicados de tipo adicionales, base de los conceptos built-in
     * (Numeric/Integer/Float/...).  Todos derivan de t1.kind. */
    {
        const PrimitiveKind k = t1.kind;
        /* Que es entero, que lleva signo y que es de coma flotante lo dice
         * types.h, que es donde vive el enum.  Escrito aqui aparte -- ocho
         * comparaciones a mano frente a la comprobacion de rango de alla --
         * coincidia hoy, pero el dia que se meta una clase de tipo dentro de
         * ese rango las dos respuestas se separan sin que nada avise, y de
         * estos predicados cuelgan los conceptos de la libreria numerica. */
        const bool is_int = is_integral(k);
        const bool is_signed = is_signed_integral(k);
        const bool is_flt = is_floating(k);
        if (nm == "is_integer") {
            r.ok = true;
            r.value = is_int ? 1 : 0;
            return r;
        }
        if (nm == "is_signed") {
            r.ok = true;
            r.value = is_signed ? 1 : 0;
            return r;
        }
        if (nm == "is_unsigned") {
            r.ok = true;
            r.value = (is_int && !is_signed) ? 1 : 0;
            return r;
        }
        if (nm == "is_float") {
            r.ok = true;
            r.value = is_flt ? 1 : 0;
            return r;
        }
        if (nm == "is_numeric") {
            r.ok = true;
            r.value = (is_int || is_flt) ? 1 : 0;
            return r;
        }
        if (nm == "is_bool") {
            r.ok = true;
            r.value = (k == PrimitiveKind::BOOL) ? 1 : 0;
            return r;
        }
        if (nm == "is_char") {
            r.ok = true;
            r.value = (k == PrimitiveKind::CHAR) ? 1 : 0;
            return r;
        }
        if (nm == "is_pointer") {
            r.ok = true;
            r.value = (k == PrimitiveKind::PTR) ? 1 : 0;
            return r;
        }
        if (nm == "is_string") {
            r.ok = true;
            r.value = (k == PrimitiveKind::STRING) ? 1 : 0;
            return r;
        }
    }

    /* Builtins con 1 string literal arg. */
    if (nm == "offsetof" || nm == "has_field" || nm == "has_method") {
        if (ce->args.size() < 1) return r;
        auto *slit =
            dynamic_cast<const ast::StringLitExpr *>(ce->args[0].get());
        if (!slit || slit->is_interpolated()) return r;
        const std::string &fname = slit->value;
        if (nm == "offsetof") {
            const int64_t off = comptime_field_offset(tc, t1, fname);
            if (off < 0) return r;
            r.ok = true;
            r.value = off;
            return r;
        }
        if (nm == "has_field") {
            r.ok = true;
            r.value = comptime_has_field(tc, t1, fname) ? 1 : 0;
            return r;
        }
        if (nm == "has_method") {
            r.ok = true;
            r.value = comptime_has_method(tc, t1, fname) ? 1 : 0;
            return r;
        }
    }

    /* Builtins con 2 type args. */
    if (nm == "is_subtype" || nm == "is_same") {
        if (ce->type_args.size() < 2) return r;
        const Type t2 = tc.resolve_type_node(ce->type_args[1].get());
        if (nm == "is_subtype") {
            r.ok = true;
            r.value = comptime_is_subtype(tc, t1, t2) ? 1 : 0;
            return r;
        }
        if (nm == "is_same") {
            r.ok = true;
            r.value = comptime_is_same(tc, t1, t2) ? 1 : 0;
            return r;
        }
    }

    /* #6: composicion de conceptos en predicados comptime.  Si `nm` es un
     * concepto (built-in o de usuario), `Concepto<T>()` evalua a 0/1.  Esto
     * permite `concept Ordenable<T> = Comparable<T>() && Sized<T>();`. */
    {
        const ConceptEval ce = comptime_eval_concept(tc, nm, t1);
        if (ce.found) {
            r.ok = true;
            r.value = ce.satisfied ? 1 : 0;
            return r;
        }
    }
    return r;
}

/* Forward declarations: las definiciones publicas no-static
 * (comptime_eval_stmt 2-args y ComptimeControl) ya se declararon
 * en comptime_introspect.h.  Aqui solo necesitamos forward para el
 * mini-interprete interno y el wrapper de back-compat. */
static bool comptime_eval_stmt_3arg(TypeChecker &tc, const ast::Stmt *s,
                                    ComptimeEvalResult &return_value,
                                    bool &returned) {
    ComptimeControl ctrl;
    bool ok = comptime_eval_stmt(tc, s, ctrl);
    return_value = ctrl.return_value;
    returned = ctrl.returned;
    return ok;
}
static ComptimeEvalResult
comptime_call_fn(TypeChecker &tc, const ast::FunctionDecl *fn,
                 std::vector<ComptimeEvalResult> args);

/**
 * @brief construye el valor de compile-time de un struct a partir de sus bytes.
 *
 * Recorre el layout del struct y, por cada campo, lee sus bytes del buffer
 * @c bytes (con @c base como desplazamiento del struct dentro del buffer) y los
 * guarda en @c out.struct_fields.  Los campos de tipo struct se resuelven
 * recursivamente.  Hoy se soportan campos enteros, @c bool y @c char, y structs
 * anidados; los campos de otros tipos (coma flotante, punteros) se omiten y
 * quedan a cero al materializar el struct.
 *
 * @param tc    Type checker (para localizar el layout de structs anidados).
 * @param lay   Layout del struct a reconstruir.
 * @param bytes Buffer con la representacion en memoria del struct.
 * @param base  Desplazamiento del struct dentro de @c bytes.
 * @param out   Resultado a rellenar (@c is_struct queda a @c true).
 */
/**
 * @brief Vuelca un valor de struct a sus BYTES, con la disposicion real.
 *
 * Espejo de @ref fill_struct_fields_from_bytes.  Hace falta para pasar un
 * agregado como ARGUMENTO: no cabe en un registro, asi que viaja por direccion
 * y alguien tiene que escribir sus bytes.
 *
 * Un campo que no se sepa volcar se deja como este (a cero): es lo mismo que
 * hace la lectura al reves, que omite los que no sabe leer.
 *
 * @param tc     Para resolver los layouts de los campos anidados.
 * @param lay    Disposicion del struct.
 * @param v      El valor, con sus campos por nombre.
 * @param base   Desplazamiento donde empieza este struct dentro de @p bytes.
 * @param bytes  Destino, ya dimensionado.
 */
void dump_struct_fields_to_bytes(const TypeChecker &tc, const StructLayout &lay,
                                 const ComptimeValue &v, uint32_t base,
                                 std::vector<uint8_t> &bytes) {
    for (const auto &f : lay.fields) {
        const uint32_t off = base + f.offset;
        if (static_cast<size_t>(off) + f.size > bytes.size()) continue;
        auto it = v.struct_fields.find(f.name);
        if (it == v.struct_fields.end() || !it->second) continue;
        const ComptimeValue &fv = *it->second;
        if (f.type.kind == PrimitiveKind::STRUCT) {
            const auto &slays = tc.struct_layouts();
            auto its = slays.find(f.type.struct_name);
            if (its == slays.end() || its->second.is_overlay) continue;
            dump_struct_fields_to_bytes(tc, its->second, fv, off, bytes);
            continue;
        }
        const uint64_t raw = static_cast<uint64_t>(fv.value);
        const uint32_t n = f.size < 8u ? f.size : 8u;
        std::memcpy(bytes.data() + off, &raw, n);
    }
}

void fill_struct_fields_from_bytes(const TypeChecker &tc,
                                   const StructLayout &lay,
                                   const std::vector<uint8_t> &bytes,
                                   uint32_t base, ComptimeEvalResult &out) {
    out.ok = true;
    out.is_struct = true;
    for (const auto &f : lay.fields) {
        const uint32_t off = base + f.offset;
        // Defensa: no leer fuera del buffer del struct.
        if (static_cast<size_t>(off) + f.size > bytes.size()) continue;
        ComptimeValue cv;
        if (f.type.kind == PrimitiveKind::STRUCT) {
            // Campo struct anidado: reconstruir recursivamente.
            const auto &slays = tc.struct_layouts();
            auto it = slays.find(f.type.struct_name);
            if (it == slays.end() || it->second.is_overlay) continue;
            ComptimeEvalResult sub;
            fill_struct_fields_from_bytes(tc, it->second, bytes, off, sub);
            cv = value_from_result(sub);
        } else {
            const PrimitiveKind k = f.type.kind;
            const bool int_like =
                k == PrimitiveKind::BOOL || k == PrimitiveKind::CHAR ||
                k == PrimitiveKind::I8 || k == PrimitiveKind::I16 ||
                k == PrimitiveKind::I32 || k == PrimitiveKind::I64 ||
                k == PrimitiveKind::U8 || k == PrimitiveKind::U16 ||
                k == PrimitiveKind::U32 || k == PrimitiveKind::U64;
            // Campos aun no soportados (coma flotante, puntero): se omiten.
            if (!int_like) continue;
            uint64_t raw = 0;
            const uint32_t n = f.size < 8u ? f.size : 8u;
            std::memcpy(&raw, bytes.data() + off, n);
            cv.value = static_cast<int64_t>(raw);
        }
        out.struct_fields[f.name] =
            std::make_shared<ComptimeValue>(std::move(cv));
    }
}

ComptimeEvalResult comptime_eval_expr(const TypeChecker &tc,
                                      const ast::Expr *expr) {
    ComptimeEvalResult r{};
    if (!expr) return r;
    switch (expr->kind) {
    case ast::NodeKind::IntLitExpr: {
        auto *il = static_cast<const ast::IntLitExpr *>(expr);
        r.ok = true;
        r.value = static_cast<int64_t>(il->value);
        return r;
    }
    /* Un caracter es su punto de codigo, igual que un entero: no habia caso
     * para el, asi que `'a'` caia al final del switch y se declaraba "no
     * comptime-evaluable".  Y el fallo no se quedaba en el literal -- se
     * llevaba por delante cualquier funcion comptime que tomara un `char`,
     * porque su ARGUMENTO no se podia evaluar: por eso el compilador Brainfuck
     * (`bf_classify(src[i])`) daba codigo vacio, y por eso parecia que el
     * problema era el `match` o el retorno enum, que es donde se veia. */
    case ast::NodeKind::CharLitExpr: {
        auto *cl = static_cast<const ast::CharLitExpr *>(expr);
        r.ok = true;
        r.value = static_cast<int64_t>(cl->codepoint);
        return r;
    }
    case ast::NodeKind::BoolLitExpr: {
        auto *bl = static_cast<const ast::BoolLitExpr *>(expr);
        r.ok = true;
        r.value = bl->value ? 1 : 0;
        return r;
    }
    case ast::NodeKind::StringLitExpr: {
        /* String literal compile-time.  Los NO interpolados devuelven su texto.
         * Los INTERPOLADOS (`"a ${e} b"`, tambien triple-quoted) se construyen
         * iterando parts/exprs: cada expr de interpolacion se comptime-evalua
         * (string -> tal cual, int/char -> ASCII decimal) y se concatena.
         *
         * Esto es el BOOTSTRAP del pass-1 del two-phase: un @Macro que emite
         * codigo via interpolacion (`"() => { ${bf_compile_body(src)} }"`)
         * necesita expandirse en pass-1 para conocer el tipo de la expansion;
         * la EJECUCION final (pass-2) corre en la ComptimeVM (interp/JIT) sobre
         * el `__macro_<X>` ya compilado.  Sin esto, un macro interpolado no era
         * evaluable (solo funcionaba con concat `+`). */
        auto *sl = static_cast<const ast::StringLitExpr *>(expr);
        if (!sl->is_interpolated()) {
            r.ok = true;
            r.is_str = true;
            r.str = sl->value;
            return r;
        }
        std::string out;
        bool any_deferred = false;
        const auto &parts = sl->interp_parts;
        const auto &exprs = sl->interp_exprs;
        for (size_t k = 0; k < parts.size(); ++k) {
            out.append(parts[k]);
            if (k < exprs.size()) {
                ComptimeEvalResult er = comptime_eval_expr(tc, exprs[k].get());
                /* Deferido (pass-1 del two-phase: la ComptimeVM aun no tiene el
                 * bytecode del helper): usamos un placeholder VACIO y marcamos
                 * el resultado como deferido.  Asi la interpolacion produce la
                 * ESTRUCTURA (`"() => { ... }"` con cuerpo vacio) -> el type-
                 * check de pass-1 ve un lambda valido y resuelve su tipo;
                 * pass-2 (VM cargada) reconstruye el texto completo.  Sin esto,
                 * un solo expr deferido tumbaria toda la interpolacion (bf_gen
                 * -> ""). */
                if (er.deferred) {
                    any_deferred = true;
                    continue;
                }
                if (!er.ok) return r; /* r.ok sigue false -> no evaluable */
                if (er.is_str) {
                    out.append(er.str);
                } else if (!er.is_array && !er.is_struct) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "%lld",
                                  static_cast<long long>(er.value));
                    out.append(buf);
                } else {
                    return r; /* array/struct en interpolacion: no soportado */
                }
            }
        }
        r.ok = true;
        r.is_str = true;
        r.deferred = any_deferred;
        r.str = std::move(out);
        return r;
    }
    case ast::NodeKind::IdentExpr: {
        /* A.38/A.39: resuelve identifier a su valor comptime const.
         * Buscamos primero en el stack de scopes locales (A.39 --
         * comptime const locales declarados con `comptime const`
         * dentro de funciones o `comptime { }` blocks); luego en
         * la tabla global (A.38).  Devuelve ok=false si no esta. */
        auto *id = static_cast<const ast::IdentExpr *>(expr);
        /* Stack local: scopes apilados; topmost prioridad. */
        const auto &local_scopes = tc.comptime_const_locals();
        for (auto it = local_scopes.rbegin(); it != local_scopes.rend(); ++it) {
            auto hit = it->find(id->name);
            if (hit != it->end()) {
                r.ok = true;
                if (hit->second.is_str) {
                    r.is_str = true;
                    r.str = hit->second.str_value;
                } else if (hit->second.is_array) {
                    r.is_array = true;
                    r.array_vals = hit->second.array_vals;
                } else if (hit->second.is_struct) {
                    r.is_struct = true;
                    r.struct_fields = hit->second.struct_fields;
                } else {
                    r.value = hit->second.value;
                }
                r.deferred = hit->second.deferred; /* #2: propaga diferido */
                return r;
            }
        }
        const auto &tbl = tc.comptime_const_values();
        auto it = tbl.find(id->name);
        if (it == tbl.end()) {
            /* Una `const` corriente tambien es legible al compilar: su valor
             * esta fijado en el fuente.  Antes solo se miraban las tablas de
             * `comptime const`, asi que `const i32 K = 5; enum E { a = K }` se
             * rechazaba con "debe ser una constante entera" -- siendolo.  Se
             * mira primero la importada (ya viene con el valor resuelto del
             * .vxi) y si no, se evalua el inicializador del global local. */
            const auto &imp = tc.imported_global_consts();
            auto ii = imp.find(id->name);
            if (ii != imp.end()) {
                r.ok = true;
                if (ii->second.is_str) {
                    r.is_str = true;
                    r.str = ii->second.str_value;
                } else {
                    r.value = static_cast<int64_t>(ii->second.value);
                }
                return r;
            }
            for (const auto &d : tc.ast_module().decls) {
                if (!d || d->kind != ast::NodeKind::GlobalVarDecl) continue;
                auto *gv = static_cast<const ast::GlobalVarDecl *>(d.get());
                if (!gv->is_const || !gv->init || gv->name != id->name)
                    continue;
                /* Recursivo: el inicializador puede ser a su vez una
                 * expresion sobre otras constantes.  Un ciclo no es posible
                 * porque una const no puede referirse a si misma. */
                return comptime_eval_expr(tc, gv->init.get());
            }
            return r;
        }
        r.ok = true;
        if (it->second.is_str) {
            r.is_str = true;
            r.str = it->second.str_value;
        } else if (it->second.is_array) {
            r.is_array = true;
            r.array_vals = it->second.array_vals;
        } else if (it->second.is_struct) {
            r.is_struct = true;
            r.struct_fields = it->second.struct_fields;
        } else {
            r.value = it->second.value;
        }
        r.deferred = it->second.deferred; /* #2: propaga diferido */
        return r;
    }
    case ast::NodeKind::CallExpr: {
        auto *ce = static_cast<const ast::CallExpr *>(expr);
        /* A.39: builtins comptime sobre strings. */
        auto *cid = dynamic_cast<const ast::IdentExpr *>(ce->callee.get());
        /* A.43.13: alias resolution -- mismo set que check_call.
         * Mutamos el AST in-place (const_cast) para que TODOS los
         * checks de `cid->name` posteriores vean el nombre canonico
         * sin necesidad de comprobar el alias en cada branch. */
        if (cid) {
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
                if (cid->name == a.first) {
                    const_cast<ast::IdentExpr *>(cid)->name = a.second;
                    break;
                }
            }
        }
        if (cid) {
            if (cid->name == "comptime_concat" && ce->args.size() == 2) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                ComptimeEvalResult b =
                    comptime_eval_expr(tc, ce->args[1].get());
                /* P1: si algun arg es DIFERIDO (const de fn-VM sin valor en
                 * pass 1) el resultado tambien es diferido -> pass 2 lo
                 * resuelve; NO computar con el placeholder vacio. */
                if ((a.ok && a.deferred) || (b.ok && b.deferred)) {
                    r.ok = true;
                    r.is_str = true;
                    r.deferred = true;
                    return r;
                }
                if (a.ok && b.ok && a.is_str && b.is_str) {
                    r.ok = true;
                    r.is_str = true;
                    r.str = a.str + b.str;
                    return r;
                }
                return r;
            }
            if (cid->name == "comptime_streq" && ce->args.size() == 2) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                ComptimeEvalResult b =
                    comptime_eval_expr(tc, ce->args[1].get());
                if ((a.ok && a.deferred) || (b.ok && b.deferred)) {
                    r.ok = true;
                    r.deferred = true;
                    return r;
                }
                if (a.ok && b.ok && a.is_str && b.is_str) {
                    r.ok = true;
                    r.value = (a.str == b.str) ? 1 : 0;
                    return r;
                }
                return r;
            }
            if (cid->name == "comptime_strlen" && ce->args.size() == 1) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (a.ok && a.deferred) {
                    r.ok = true;
                    r.deferred = true;
                    return r;
                }
                if (a.ok && a.is_str) {
                    r.ok = true;
                    r.value = (int64_t)a.str.size();
                    return r;
                }
                return r;
            }
            /* A.42: comptime_chr(cp) -> string de 1 char (ASCII;
             * codepoints >127 se encodean como UTF-8 1-4 bytes). */
            if (cid->name == "comptime_chr" && ce->args.size() == 1) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!a.ok || a.is_str || a.is_array || a.is_struct) return r;
                const uint32_t cp = (uint32_t)a.value;
                std::string out;
                if (cp < 0x80) {
                    out += (char)cp;
                } else if (cp < 0x800) {
                    out += (char)(0xC0 | (cp >> 6));
                    out += (char)(0x80 | (cp & 0x3F));
                } else if (cp < 0x10000) {
                    out += (char)(0xE0 | (cp >> 12));
                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                    out += (char)(0x80 | (cp & 0x3F));
                } else {
                    out += (char)(0xF0 | (cp >> 18));
                    out += (char)(0x80 | ((cp >> 12) & 0x3F));
                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                    out += (char)(0x80 | (cp & 0x3F));
                }
                r.ok = true;
                r.is_str = true;
                r.str = out;
                return r;
            }
            /* A.42: comptime_ord(s) -> primer byte (u64). */
            if (cid->name == "comptime_ord" && ce->args.size() == 1) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!a.ok || !a.is_str || a.str.empty()) return r;
                r.ok = true;
                r.value = (int64_t)(uint8_t)a.str[0];
                return r;
            }
            /* A.42: comptime_substr(s, start, len) -> string. */
            if (cid->name == "comptime_substr" && ce->args.size() == 3) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                ComptimeEvalResult b =
                    comptime_eval_expr(tc, ce->args[1].get());
                ComptimeEvalResult c =
                    comptime_eval_expr(tc, ce->args[2].get());
                if (!a.ok || !a.is_str) return r;
                if (!b.ok || b.is_str || b.is_array || b.is_struct) return r;
                if (!c.ok || c.is_str || c.is_array || c.is_struct) return r;
                size_t start = (size_t)std::max((int64_t)0, b.value);
                size_t len = (size_t)std::max((int64_t)0, c.value);
                if (start > a.str.size()) start = a.str.size();
                if (start + len > a.str.size()) len = a.str.size() - start;
                r.ok = true;
                r.is_str = true;
                r.str = a.str.substr(start, len);
                return r;
            }
            /* A.42: comptime_repeat(s, n) -> s repetido n veces. */
            if (cid->name == "comptime_repeat" && ce->args.size() == 2) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                ComptimeEvalResult b =
                    comptime_eval_expr(tc, ce->args[1].get());
                if (!a.ok || !a.is_str) return r;
                if (!b.ok || b.is_str || b.is_array || b.is_struct) return r;
                std::string out;
                const int64_t n = b.value > 0 ? b.value : 0;
                if (n > 0 && a.str.size() * (size_t)n > (1u << 22)) {
                    return r; /* limite 4 MB defensivo */
                }
                out.reserve(a.str.size() * (size_t)n);
                for (int64_t i = 0; i < n; ++i)
                    out += a.str;
                r.ok = true;
                r.is_str = true;
                r.str = std::move(out);
                return r;
            }
            /* A.43.12: comptime_replace(s, needle, replacement) -> string.
             * Substituye TODAS las ocurrencias de `needle` en `s` por
             * `replacement`.  Base para macros con patrones declarativos
             * (templates con placeholders `{x}`, `{name}`, etc.).
             * Combinable con `comptime_emit_expr` para code-gen real. */
            if (cid->name == "comptime_replace" && ce->args.size() == 3) {
                ComptimeEvalResult s =
                    comptime_eval_expr(tc, ce->args[0].get());
                ComptimeEvalResult n =
                    comptime_eval_expr(tc, ce->args[1].get());
                ComptimeEvalResult v =
                    comptime_eval_expr(tc, ce->args[2].get());
                if (!s.ok || !s.is_str) return r;
                if (!n.ok || !n.is_str || n.str.empty()) return r;
                if (!v.ok || !v.is_str) return r;
                std::string out;
                out.reserve(s.str.size());
                size_t i = 0;
                const size_t SAFETY = (1u << 22); /* 4 MB defensivo */
                while (i < s.str.size()) {
                    if (s.str.compare(i, n.str.size(), n.str) == 0) {
                        out.append(v.str);
                        i += n.str.size();
                        if (out.size() > SAFETY) return r;
                    } else {
                        out += s.str[i++];
                    }
                }
                r.ok = true;
                r.is_str = true;
                r.str = std::move(out);
                return r;
            }
            /* A.43.12: comptime_contains(s, needle) -> bool.
             * Util para validar templates antes de aplicar replace. */
            if (cid->name == "comptime_contains" && ce->args.size() == 2) {
                ComptimeEvalResult s =
                    comptime_eval_expr(tc, ce->args[0].get());
                ComptimeEvalResult n =
                    comptime_eval_expr(tc, ce->args[1].get());
                if (!s.ok || !s.is_str) return r;
                if (!n.ok || !n.is_str) return r;
                r.ok = true;
                r.value =
                    (n.str.empty() || s.str.find(n.str) != std::string::npos)
                        ? 1
                        : 0;
                return r;
            }
            /* A.43.11: gensym(prefix) -> string.  Devuelve un
             * identificador fresco unico por llamada, util para
             * macros hygenic: prevenir capture accidental de
             * nombres del scope del caller.  El counter es per-
             * TypeChecker (no global), asi cada compilacion
             * empieza desde 0.  Formato: "<prefix>_<counter>". */
            if (cid->name == "gensym" && ce->args.size() == 1) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!a.ok || !a.is_str) return r;
                auto &mut_tc = const_cast<TypeChecker &>(tc);
                const uint64_t n = mut_tc.next_gensym_id();
                r.ok = true;
                r.is_str = true;
                r.str = a.str + "_" + std::to_string(n);
                return r;
            }
            /* A.43.9: comptime_compile(s) -> result.  Macro MVP
             * estilo Lisp eval: el string se parsea como una
             * EXPRESION Vesta y se evalua comptime recursivamente.
             * Permite construir codigo a partir de datos (concat
             * de strings comptime) y evaluarlo en compile-time.
             * Limitacion: solo expresion (no stmt); el AST
             * resultante se descarta tras eval (no se emite codigo
             * runtime). */
            if (cid->name == "comptime_compile" && ce->args.size() == 1) {
                ComptimeEvalResult sarg =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!sarg.ok || !sarg.is_str) return r;
                /* Construir lexer + parser locales sobre la cadena.
                 * Usamos un filename sintetico para que los
                 * diagnostics de parsing tengan ubicacion. */
                auto &mut_tc = const_cast<TypeChecker &>(tc);
                Lexer fragment_lex(sarg.str, "<comptime_compile>",
                                   mut_tc.diagnostics());
                Parser fragment_par(fragment_lex, mut_tc.diagnostics());
                std::unique_ptr<ast::Expr> parsed =
                    fragment_par.parse_one_expr();
                if (!parsed) return r;
                /* Evaluar el AST recursivamente con el mismo TC.
                 * Asi los `comptime const` del modulo siguen
                 * visibles dentro del fragmento. */
                return comptime_eval_expr(tc, parsed.get());
            }
            /* A.42: comptime_to_str(int) -> "<decimal>". */
            if (cid->name == "comptime_to_str" && ce->args.size() == 1) {
                ComptimeEvalResult a =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!a.ok || a.is_str || a.is_array || a.is_struct) return r;
                r.ok = true;
                r.is_str = true;
                r.str = std::to_string(a.value);
                return r;
            }
            /* A.43: comptime_type<T>() devuelve un Type como
             * ComptimeValue.  Permite type-as-first-class-value:
             * el resultado se guarda en un `comptime const Type T`
             * y puede usarse en cualquier posicion de tipo. */
            if (cid->name == "comptime_type" && !ce->type_args.empty()) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                if (t1.kind == PrimitiveKind::VOID ||
                    t1.kind == PrimitiveKind::COUNT) {
                    return r; /* no resoluble -> ok=false */
                }
                r.ok = true;
                r.is_type = true;
                r.type_val = t1;
                return r;
            }
            /* A.43: parent_class<T>() -> Type.  Devuelve el tipo del
             * super de una CLASS; si no tiene super (o T no es CLASS),
             * devuelve TYPE_META vacio (sentinela "no parent"). */
            if (cid->name == "parent_class" && !ce->type_args.empty()) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                Type parent{PrimitiveKind::TYPE_META};
                if (t1.kind == PrimitiveKind::CLASS) {
                    auto it = tc.class_layouts().find(t1.struct_name);
                    if (it != tc.class_layouts().end() &&
                        !it->second.super_name.empty()) {
                        parent = Type{PrimitiveKind::CLASS};
                        parent.struct_name = it->second.super_name;
                    }
                }
                r.ok = true;
                r.is_type = true;
                r.type_val = parent;
                return r;
            }
            /* A.43: element_type<T>() -> Type.  Extrae el tipo
             * "interior" de wrappers: T* -> T, T[N] -> T, Optional<T> -> T,
             * Future<T> -> T, borrow<T> -> T, unique<T> -> T, shared<T> -> T.
             * Para tipos sin pointee, devuelve TYPE_META vacio. */
            if (cid->name == "element_type" && !ce->type_args.empty()) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                Type inner{PrimitiveKind::TYPE_META};
                if (t1.pointee) {
                    inner = *t1.pointee;
                }
                r.ok = true;
                r.is_type = true;
                r.type_val = inner;
                return r;
            }
            /* A.43: error_type<T>() -> Type.  Para Result<V,E> devuelve E.
             * Para no-Result devuelve TYPE_META vacio. */
            if (cid->name == "error_type" && !ce->type_args.empty()) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                Type inner{PrimitiveKind::TYPE_META};
                if (t1.kind == PrimitiveKind::RESULT && t1.pointee2) {
                    inner = *t1.pointee2;
                }
                r.ok = true;
                r.is_type = true;
                r.type_val = inner;
                return r;
            }
            /* A.43: method_name<T>(idx) -> string.  Sister de
             * field_name pero para metodos de una CLASS.  Incluye
             * heredados.  Cadena vacia si idx out-of-range. */
            if (cid->name == "method_name" && !ce->type_args.empty() &&
                ce->args.size() == 1) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                ComptimeEvalResult idx =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!idx.ok || idx.is_str) return r;
                const auto *ms = methods_of(tc, t1);
                std::string nm;
                if (ms && (size_t)idx.value < ms->size()) {
                    nm = (*ms)[(size_t)idx.value].name;
                }
                r.ok = true;
                r.is_str = true;
                r.str = std::move(nm);
                return r;
            }
            /* A.43: method_return_type<T>(idx) -> Type.  Tipo de
             * retorno del metodo idx-esimo.  TYPE_META vacio si
             * out-of-range o T no es CLASS. */
            if (cid->name == "method_return_type" && !ce->type_args.empty() &&
                ce->args.size() == 1) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                ComptimeEvalResult idx =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!idx.ok || idx.is_str) return r;
                const auto *ms = methods_of(tc, t1);
                Type rt_v{PrimitiveKind::TYPE_META};
                if (ms && (size_t)idx.value < ms->size()) {
                    rt_v = (*ms)[(size_t)idx.value].return_type;
                }
                r.ok = true;
                r.is_type = true;
                r.type_val = rt_v;
                return r;
            }
            /* A.43: comptime_print(val) -> u64 = 0.  Emite el valor
             * a stderr al COMPILE-TIME (no runtime).  Util para
             * debug de metaprogramas.  Acepta int, string, o type.
             * Retorna 0 (u64) para componer con static_assert
             * (`static_assert(comptime_print("hi") == 0, "ok")`). */
            if (cid->name == "comptime_print" && ce->args.size() == 1) {
                ComptimeEvalResult arg =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!arg.ok) return r;
                if (arg.is_str) {
                    std::fprintf(stderr, "[comptime] %s\n", arg.str.c_str());
                } else if (arg.is_type) {
                    std::fprintf(stderr, "[comptime] Type=%s\n",
                                 comptime_type_name(tc, arg.type_val).c_str());
                } else if (arg.is_array) {
                    std::fprintf(stderr, "[comptime] array (n=%zu)\n",
                                 arg.array_vals.size());
                } else if (arg.is_struct) {
                    std::fprintf(stderr, "[comptime] struct (fields=%zu)\n",
                                 arg.struct_fields.size());
                } else {
                    std::fprintf(stderr, "[comptime] %lld\n",
                                 static_cast<long long>(arg.value));
                }
                r.ok = true;
                r.value = 0;
                return r;
            }
            /* A.43: field_type_at<T>(idx) -> Type.  Hermana de
             * field_type pero devuelve el Type del campo idx-esimo
             * en orden de declaracion (struct/class). */
            if (cid->name == "field_type_at" && !ce->type_args.empty() &&
                ce->args.size() == 1) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                ComptimeEvalResult idx =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (!idx.ok || idx.is_str) return r;
                const std::string fname =
                    comptime_field_name(tc, t1, (uint32_t)idx.value);
                Type ft{PrimitiveKind::TYPE_META};
                if (!fname.empty()) {
                    ft = comptime_field_type(tc, t1, fname);
                    if (ft.kind == PrimitiveKind::COUNT) {
                        ft = Type{PrimitiveKind::TYPE_META};
                    }
                }
                r.ok = true;
                r.is_type = true;
                r.type_val = ft;
                return r;
            }
            /* typename<T>() devuelve un string comptime-evaluable.
             * Lo redirigimos via comptime_type_name. */
            if (cid->name == "typename" && !ce->type_args.empty()) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                r.ok = true;
                r.is_str = true;
                r.str = comptime_type_name(tc, t1);
                return r;
            }
            /* field_name<T>(idx) tambien devuelve string. */
            if (cid->name == "field_name" && !ce->type_args.empty() &&
                ce->args.size() == 1) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                ComptimeEvalResult idx =
                    comptime_eval_expr(tc, ce->args[0].get());
                if (idx.ok && !idx.is_str) {
                    r.ok = true;
                    r.is_str = true;
                    r.str = comptime_field_name(tc, t1, (uint32_t)idx.value);
                    return r;
                }
                return r;
            }
            /* field_type<T>("f") tambien. */
            if (cid->name == "field_type" && !ce->type_args.empty() &&
                ce->args.size() == 1) {
                const Type t1 = tc.resolve_type_node(ce->type_args[0].get());
                auto *slit =
                    dynamic_cast<const ast::StringLitExpr *>(ce->args[0].get());
                if (slit && !slit->is_interpolated()) {
                    r.ok = true;
                    r.is_str = true;
                    r.str = comptime_field_type_name(tc, t1, slit->value);
                    return r;
                }
                return r;
            }
            /*   (Camino A): llamada a `extern fn` declarada
             * con `extern "lib" { fn ... }`.  El AST evaluator gana
             * la capacidad de dispatchear FFI nativa en compile time
             * via LoadLibrary/dlopen + GetProcAddress/dlsym +
             * invoke con marshalling de uint64.
             *
             * Cobertura v1:
             *  - Args int/bool/char/null/float (literales o
             *    comptime-evaluables) -> u64 directo / bitcast f64.
             *  - Args string literal -> host_ptr (cstr) via duplicacion
             *    en heap del proceso compile (auto-libre al exit).
             *  - Return: u64.  El caller interpreta segun la firma.
             *
             * Limitaciones documentadas:
             *  - No marshalla structs/arrays todavia (~caso raro).
             *  - Cache de modulos por nombre (no recarga DLLs entre
             *    invocaciones del mismo compile). */
            {
                const FunctionSig *sig = tc.function_sig_by_name(cid->name);
                /*   : ademas de externs declarados,
                 * tambien aceptamos "implicit externs" -- nombres
                 * que NO estan declarados como `extern "..."` en
                 * el .vx pero estan registrados como virtual fns
                 * bajo `vesta_comptime`.  Esto cubre builtins
                 * como `static_assert` que el usuario no necesita
                 * declarar explicitamente. */
                std::string implicit_lib_name;
                if ((!sig || sig->extern_lib.empty()) &&
                    ffi::lookup_virtual_fn("vesta_comptime", cid->name)) {
                    implicit_lib_name = "vesta_comptime";
                }
                /* #2: static_assert cuya CONDICION es un placeholder DIFERIDO
                 * (depende de una comptime fn con asm via ComptimeVM aun no
                 * cargada, pass 1 del two-phase) NO debe dispararse aqui -- el
                 * FFI `vesta_comptime:static_assert` no distingue deferred de
                 * false y daria un error espurio.  Se resuelve en pass 2 (con
                 * el bytecode comptime cargado, la cond da su valor real).
                 * Cubre el static_assert DENTRO de un `comptime {}` block, que
                 * pasa por esta ruta (el top-level pasa por check_call, ya
                 * arreglado). */
                if (cid->name == "static_assert" && !ce->args.empty()) {
                    ComptimeEvalResult cond =
                        comptime_eval_expr(tc, ce->args[0].get());
                    if (cond.ok && cond.deferred) {
                        ComptimeEvalResult skip{};
                        skip.ok = true;
                        skip.value = 0;
                        skip.deferred = true;
                        return skip;
                    }
                }
                if ((sig && !sig->extern_lib.empty()) ||
                    !implicit_lib_name.empty()) {
                    ComptimeEvalResult err{};
                    const std::string &lib_name = !implicit_lib_name.empty()
                                                      ? implicit_lib_name
                                                      : sig->extern_lib;
                    const std::string &fn_name = cid->name;

                    /*   : PRIMERO consultamos el registry
                     * de virtual libs.  Si el (lib, fn) esta
                     * registrado in-process (e.g. vesta_comptime
                     * services), usamos ese fn_ptr directamente
                     * y skipeamos el LoadLibrary path. */
                    void *fn_ptr = ffi::lookup_virtual_fn(lib_name, fn_name);
                    if (!fn_ptr) {
                        /* Cache estatico de modulos cargados.  Vive
                         * durante todo el compile -- no se libera
                         * porque las funciones obtenidas via
                         * GetProcAddress pueden seguir invocandose
                         * en macros posteriores. */
                        static std::unordered_map<std::string, void *>
                            g_comptime_native_modules;
                        void *mod_handle = nullptr;
                        auto mit = g_comptime_native_modules.find(lib_name);
                        if (mit != g_comptime_native_modules.end()) {
                            mod_handle = mit->second;
                        } else {
#if defined(_WIN32)
                            mod_handle =
                                (void *)::LoadLibraryA(lib_name.c_str());
#else
                            mod_handle = ::dlopen(lib_name.c_str(),
                                                  RTLD_LAZY | RTLD_LOCAL);
#endif
                            g_comptime_native_modules[lib_name] = mod_handle;
                        }
                        if (!mod_handle) {
                            /* Lib no cargo; falla limpia y el caller
                             * reporta "no es comptime-evaluable". */
                            return err;
                        }
#if defined(_WIN32)
                        fn_ptr = (void *)::GetProcAddress((HMODULE)mod_handle,
                                                          fn_name.c_str());
#else
                        fn_ptr = ::dlsym(mod_handle, fn_name.c_str());
#endif
                    }
                    if (!fn_ptr) return err;

                    /* Marshalling: evaluar cada arg en compile time
                     * y promoverlo a u64 segun su tipo.    :
                     * extendido a 12 args (vs antes 8) + soporte
                     * para string interpolados (construyendo el
                     * string final) + soporte para args generales
                     * via comptime_eval_expr recursivo (no solo
                     * literales). */
                    if (ce->args.size() > 12) return err;
                    uint64_t arg_words[12] = {0};
                    /* Buffer estable para string args; persiste
                     * durante el compile completo.  Limpieza al
                     * destruir el TypeChecker. */
                    static std::vector<std::string> g_str_buf_holder;
                    for (size_t i = 0; i < ce->args.size(); ++i) {
                        const ast::Expr *arg_e = ce->args[i].get();
                        /* String literal (incluido interpolado).
                         * Para interpolados, evaluamos
                         * comptime_eval_expr que arma el string
                         * final con todas las parts/exprs ya
                         * resueltos.  Asi `static_assert(c, "n=${n}")`
                         * pasa al callee el msg con n sustituido. */
                        if (arg_e->kind == ast::NodeKind::StringLitExpr) {
                            const auto *slit =
                                static_cast<const ast::StringLitExpr *>(arg_e);
                            std::string final_str;
                            if (!slit->is_interpolated()) {
                                final_str = slit->value;
                            } else {
                                /*   : construir string
                                 * interpolado inline iterando
                                 * parts/exprs.  Cada expr se
                                 * evalua comptime (int -> ASCII,
                                 * string -> tal cual) y se
                                 * concatena con las partes literales. */
                                const auto &parts = slit->interp_parts;
                                const auto &exprs = slit->interp_exprs;
                                for (size_t k = 0; k < parts.size(); ++k) {
                                    final_str.append(parts[k]);
                                    if (k < exprs.size()) {
                                        ComptimeEvalResult er =
                                            comptime_eval_expr(tc,
                                                               exprs[k].get());
                                        if (!er.ok) return err;
                                        if (er.is_str) {
                                            final_str.append(er.str);
                                        } else {
                                            /* Int -> decimal ASCII. */
                                            char buf[32];
                                            std::snprintf(
                                                buf, sizeof(buf), "%lld",
                                                static_cast<long long>(
                                                    er.value));
                                            final_str.append(buf);
                                        }
                                    }
                                }
                            }
                            g_str_buf_holder.push_back(std::move(final_str));
                            arg_words[i] = reinterpret_cast<uint64_t>(
                                g_str_buf_holder.back().c_str());
                            continue;
                        }
                        /* Float literal: bitcast a u64. */
                        if (arg_e->kind == ast::NodeKind::FloatLitExpr) {
                            const auto *flit =
                                static_cast<const ast::FloatLitExpr *>(arg_e);
                            double v = flit->value;
                            std::memcpy(&arg_words[i], &v, sizeof(double));
                            continue;
                        }
                        /* Otros: evaluar como comptime expr.  Si
                         * el resultado es string (e.g. de un
                         * comptime_concat), copiamos al buffer
                         * estable y pasamos c_str(). */
                        ComptimeEvalResult ar = comptime_eval_expr(tc, arg_e);
                        if (!ar.ok) return err;
                        if (ar.is_str) {
                            g_str_buf_holder.push_back(ar.str);
                            arg_words[i] = reinterpret_cast<uint64_t>(
                                g_str_buf_holder.back().c_str());
                        } else {
                            arg_words[i] = static_cast<uint64_t>(ar.value);
                        }
                    }

                    /* Invocacion FFI directa via switch sobre argc.
                     *   : extendido a 12 args (matchea
                     * @c runtime::invoke_native_unchecked). */
                    using F0 = uint64_t (*)();
                    using F1 = uint64_t (*)(uint64_t);
                    using F2 = uint64_t (*)(uint64_t, uint64_t);
                    using F3 = uint64_t (*)(uint64_t, uint64_t, uint64_t);
                    using F4 =
                        uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t);
                    using F5 = uint64_t (*)(uint64_t, uint64_t, uint64_t,
                                            uint64_t, uint64_t);
                    using F6 = uint64_t (*)(uint64_t, uint64_t, uint64_t,
                                            uint64_t, uint64_t, uint64_t);
                    using F7 =
                        uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t);
                    using F8 =
                        uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);
                    using F9 = uint64_t (*)(uint64_t, uint64_t, uint64_t,
                                            uint64_t, uint64_t, uint64_t,
                                            uint64_t, uint64_t, uint64_t);
                    using F10 = uint64_t (*)(
                        uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                    using F11 =
                        uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t);
                    using F12 =
                        uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);
                    uint64_t ret = 0;
                    const size_t nargs_call = ce->args.size();
                    try {
                        switch (nargs_call) {
                        case 0: ret = ((F0)fn_ptr)(); break;
                        case 1: ret = ((F1)fn_ptr)(arg_words[0]); break;
                        case 2:
                            ret = ((F2)fn_ptr)(arg_words[0], arg_words[1]);
                            break;
                        case 3:
                            ret = ((F3)fn_ptr)(arg_words[0], arg_words[1],
                                               arg_words[2]);
                            break;
                        case 4:
                            ret = ((F4)fn_ptr)(arg_words[0], arg_words[1],
                                               arg_words[2], arg_words[3]);
                            break;
                        case 5:
                            ret = ((F5)fn_ptr)(arg_words[0], arg_words[1],
                                               arg_words[2], arg_words[3],
                                               arg_words[4]);
                            break;
                        case 6:
                            ret = ((F6)fn_ptr)(arg_words[0], arg_words[1],
                                               arg_words[2], arg_words[3],
                                               arg_words[4], arg_words[5]);
                            break;
                        case 7:
                            ret = ((F7)fn_ptr)(arg_words[0], arg_words[1],
                                               arg_words[2], arg_words[3],
                                               arg_words[4], arg_words[5],
                                               arg_words[6]);
                            break;
                        case 8:
                            ret = ((F8)fn_ptr)(arg_words[0], arg_words[1],
                                               arg_words[2], arg_words[3],
                                               arg_words[4], arg_words[5],
                                               arg_words[6], arg_words[7]);
                            break;
                        case 9:
                            ret = ((F9)fn_ptr)(
                                arg_words[0], arg_words[1], arg_words[2],
                                arg_words[3], arg_words[4], arg_words[5],
                                arg_words[6], arg_words[7], arg_words[8]);
                            break;
                        case 10:
                            ret = ((F10)fn_ptr)(arg_words[0], arg_words[1],
                                                arg_words[2], arg_words[3],
                                                arg_words[4], arg_words[5],
                                                arg_words[6], arg_words[7],
                                                arg_words[8], arg_words[9]);
                            break;
                        case 11:
                            ret = ((F11)fn_ptr)(
                                arg_words[0], arg_words[1], arg_words[2],
                                arg_words[3], arg_words[4], arg_words[5],
                                arg_words[6], arg_words[7], arg_words[8],
                                arg_words[9], arg_words[10]);
                            break;
                        case 12:
                            ret = ((F12)fn_ptr)(
                                arg_words[0], arg_words[1], arg_words[2],
                                arg_words[3], arg_words[4], arg_words[5],
                                arg_words[6], arg_words[7], arg_words[8],
                                arg_words[9], arg_words[10], arg_words[11]);
                            break;
                        default: return err;
                        }
                    } catch (...) {
                        return err;
                    }

                    /*   : interpretar el return segun la
                     * firma declarada (cuando hay sig).  Cubre:
                     *   F32/F64: bitcast u64 -> float -> int (truncado)
                     *     o devolver como is_str (representacion ASCII).
                     *   STRING: tratar u64 como host_ptr a c_str
                     *     y copiar a r.str (asi r.is_str es true y el
                     *     macro recibe el string para usar/parsear).
                     *   Int/uint/bool/char (incluso ancho variable): u64
                     * directo. PTR: u64 directo (host_ptr opaco).
                     *
                     * Si no hay sig (implicit extern), retorno como int. */
                    r.ok = true;
                    if (sig) {
                        const PrimitiveKind rk = sig->return_type.kind;
                        if (rk == PrimitiveKind::STRING) {
                            const char *cstr =
                                reinterpret_cast<const char *>(ret);
                            if (cstr) {
                                r.is_str = true;
                                r.str.assign(cstr);
                            } else {
                                r.is_str = true;
                                r.str.clear();
                            }
                        } else if (rk == PrimitiveKind::F64 ||
                                   rk == PrimitiveKind::F32) {
                            /* Devolver como int truncado.  Si el
                             * usuario quiere el bit pattern exacto,
                             * puede usar la variante con bitcast. */
                            double dv;
                            std::memcpy(&dv, &ret, sizeof(double));
                            r.value = static_cast<int64_t>(dv);
                        } else {
                            r.value = static_cast<int64_t>(ret);
                        }
                    } else {
                        r.value = static_cast<int64_t>(ret);
                    }
                    return r;
                }
            }

            /* A.39/A.41: llamada a comptime fn (generica o no). */
            const auto &cfns = tc.comptime_fns();
            auto fn_it = cfns.find(cid->name);
            if (fn_it != cfns.end()) {
                /* Evaluar todos los args en compile-time. */
                std::vector<ComptimeEvalResult> args;
                args.reserve(ce->args.size());
                bool algun_arg_diferido = false;
                for (const auto &a : ce->args) {
                    args.push_back(comptime_eval_expr(tc, a.get()));
                    if (!args.back().ok) return r;
                    if (args.back().deferred) algun_arg_diferido = true;
                }
                /* Un argumento DIFERIDO no es un valor: es un marcador de la
                 * primera pasada, a la espera de que la segunda lo resuelva con
                 * el bytecode ya cargado.  Llamar con el da un resultado que
                 * parece bueno y no lo es -- calculado sobre un relleno -- y
                 * como no se marcaba, la segunda pasada ya no lo rehacia.
                 *
                 * Se difiere la llamada entera.  Se ve, por ejemplo, en
                 * `emitir(clasificar(c))`: si la de dentro esta diferida, la de
                 * fuera trabajaba sobre la etiqueta cero y devolvia la variante
                 * equivocada. */
                if (algun_arg_diferido) {
                    r.ok = true;
                    r.deferred = true;
                    if (fn_it->second->return_type) {
                        const Type rtd = tc.resolve_type_node(
                            fn_it->second->return_type.get());
                        if (rtd.kind == PrimitiveKind::STRING) r.is_str = true;
                    }
                    return r;
                }
                /* F1/#2: comptime fn con inline asm -> NO es tree-walkeable;
                 * se ejecuta en el ComptimeVM (JIT + interp fallback).  En
                 * pass 2 (bytecode comptime cargado via prebuilt) devuelve el
                 * valor real; en pass 1 (sin bytecode) devuelve un placeholder
                 * DIFERIDO (ok=true para que consts/exprs no den error, pero
                 * static_assert no debe dispararse -- se resuelve en pass 2).
                 *
                 * Las comptime fns IMPORTADAS de otro modulo TAMBIEN van por la
                 * VM: su IR (`__macro_<fn>`) se mergea al .velb del importer
                 * (compiler_project.cpp) y la ComptimeVM lo carga
                 * (load_macros_from_bytes filtra `code.__macro_` de TODO el
                 * symbol_table, sin distinguir local/importado).  Asi cualquier
                 * funcion es invocable en comptime venga de donde venga
                 * (malloc, bucles, etc.), no solo las locales.  Antes se
                 * forzaban al TREE-WALKER legacy (que no ejecuta builtins
                 * nativos como malloc), asumiendo -- falsamente ya -- que no
                 * habia `__macro_` que invocar.  El unico caso que sigue en el
                 * tree-walker es el expr-capture forwardeado (abajo), que el
                 * path VM no marshaliza. */
                /* Forwarding de expr-capture anidado: si la fn tiene un param
                 * `expr` cuyo argumento NO es un StringLit crudo (es un
                 * IdentExpr forwardeado desde un `expr` param del
                 * macro/comptime fn llamante), el path VM (`__macro_<fn>`) no
                 * maneja el texto forwardeado (devuelve vacio).  Se rutea al
                 * TREE-WALKER, que evalua `return code` con `code` = el texto
                 * ya capturado. */
                bool forwarded_expr_arg = false;
                {
                    const auto &prms = fn_it->second->params;
                    for (size_t pi = 0;
                         pi < prms.size() && pi < ce->args.size(); ++pi) {
                        if (prms[pi] && prms[pi]->is_expr_capture &&
                            ce->args[pi] &&
                            ce->args[pi]->kind !=
                                ast::NodeKind::StringLitExpr) {
                            forwarded_expr_arg = true;
                            break;
                        }
                    }
                }
                /* Una comptime fn IMPORTADA con un param `expr` (expr-capture)
                 * NO baja a un `__macro_<fn>` propio: el importer la expande
                 * INLINE (fast-path del lowering) porque su valor es el TEXTO
                 * capturado del call site.  No hay simbolo que invocar en la
                 * ComptimeVM -> debe evaluarse por el tree-walker (que devuelve
                 * `code`).  El `forwarded_expr_arg` de arriba no la captura
                 * cuando el arg ya llega como StringLit (p.ej. `source( p++;
                 * )`).  Sin expr-capture (p.ej. `parse_int_lit(string)`), la
                 * importada SI tiene `__macro_` mergeado y va por la VM. */
                bool imported_expr_capture = false;
                if (fn_it->second->is_imported_comptime) {
                    for (const auto &p : fn_it->second->params)
                        if (p && p->is_expr_capture) {
                            imported_expr_capture = true;
                            break;
                        }
                }
                if (comptime_fn_needs_vm(tc, fn_it->second) &&
                    !forwarded_expr_arg && !imported_expr_capture) {
                    bool ret_is_str = false;
                    bool ret_is_struct = false;
                    bool ret_is_enum = false;
                    uint32_t ret_enum_bytes = 0;
                    const StructLayout *ret_slay = nullptr;
                    if (fn_it->second->return_type) {
                        const Type rt = tc.resolve_type_node(
                            fn_it->second->return_type.get());
                        ret_is_str = (rt.kind == PrimitiveKind::STRING);
                        /* Un ENUM tambien se devuelve por BUFER, igual que un
                         * struct -- comparten el kind y comparten convencion
                         * --, y aqui se le trataba como si cupiera en un
                         * registro.
                         *
                         * Eso no era una simplificacion inofensiva: el llamado
                         * esta compilado esperando el puntero al bufer, asi que
                         * al no pasarselo tomaba como puntero lo que hubiera en
                         * la ranura del primer argumento y escribia la etiqueta
                         * AHi.  Se veia clavado en la direccion del fallo:
                         * `0x0` sin parametros, `0x1` llamando con `1`, `0x2b`
                         * llamando con `'+'` -- que no es una direccion, es una
                         * letra.
                         *
                         * A diferencia de un struct no hay que reconstruir
                         * campo a campo: el valor de un enum es su ETIQUETA,
                         * ocho bytes al principio del bufer. */
                        if (rt.kind == PrimitiveKind::STRUCT) {
                            const auto &elays = tc.enum_layouts();
                            auto ite = elays.find(rt.struct_name);
                            if (ite != elays.end()) {
                                ret_is_enum = true;
                                ret_enum_bytes = ite->second.size_bytes;
                            }
                        }
                        /* Retorno struct por valor: se recupera por su buffer
                         * de retorno (SRET) y se reconstruye campo a campo.  Se
                         * excluyen los enums (que van por la rama de arriba) y
                         * los overlay, cuyo valor es un puntero y no un buffer.
                         */
                        if (rt.kind == PrimitiveKind::STRUCT && !ret_is_enum) {
                            const auto &slays = tc.struct_layouts();
                            const auto &elays = tc.enum_layouts();
                            auto its = slays.find(rt.struct_name);
                            if (its != slays.end() && !its->second.is_overlay &&
                                elays.find(rt.struct_name) == elays.end()) {
                                ret_is_struct = true;
                                ret_slay = &its->second;
                            }
                        }
                    }
                    std::vector<uint64_t> vm_args;
                    vm_args.reserve(args.size());
                    /* Marshalling de args a la ComptimeVM: los STRING (p.ej.
                     * un `expr code` capturado como texto crudo del call site)
                     * se convierten a un GcHandle de un StringObject via
                     * @c marshal_string -- misma maquinaria que el path @Macro
                     * en check_call.  Sin esto, un `comptime string f(expr c)`
                     * recibiria 0 en vez del texto y devolveria vacio. */
                    bool marshal_ok = true;
                    const auto &pars = fn_it->second->params;
                    for (size_t ai = 0; ai < args.size(); ++ai) {
                        const auto &a = args[ai];
                        if (a.is_str) {
                            uint64_t handle = 0;
                            if (!const_cast<TypeChecker &>(tc)
                                     .comptime_runtime()
                                     .marshal_string(a.str, handle)) {
                                marshal_ok = false;
                                break;
                            }
                            vm_args.push_back(handle);
                            continue;
                        }
                        /* Un AGREGADO no cabe en un registro: viaja por
                         * direccion, y el llamado lo lee con un acceso a
                         * memoria de la maquina.  Antes se empujaba `a.value`
                         * tal cual -- para un struct, cero; para un enum, su
                         * etiqueta -- y el llamado lo tomaba como puntero: de
                         * ahi los fallos en la direccion 0x0 y 0x2b (que no es
                         * una direccion, es la letra que se paso). */
                        Type pt;
                        bool pt_ok = false;
                        if (ai < pars.size() && pars[ai] && pars[ai]->type) {
                            pt = tc.resolve_type_node(pars[ai]->type.get());
                            pt_ok = true;
                        }
                        if (pt_ok && pt.kind == PrimitiveKind::STRUCT) {
                            const auto &elays = tc.enum_layouts();
                            const auto &slays = tc.struct_layouts();
                            auto ite = elays.find(pt.struct_name);
                            std::vector<uint8_t> buf;
                            if (ite != elays.end()) {
                                /* El valor de un enum es su ETIQUETA, ocho
                                 * bytes al principio. */
                                buf.assign(ite->second.size_bytes, 0);
                                const uint64_t tag =
                                    static_cast<uint64_t>(a.value);
                                std::memcpy(buf.data(), &tag, 8);
                            } else {
                                auto its = slays.find(pt.struct_name);
                                if (its == slays.end() ||
                                    its->second.is_overlay || !a.is_struct) {
                                    marshal_ok = false;
                                    break;
                                }
                                buf.assign(its->second.size_bytes, 0);
                                dump_struct_fields_to_bytes(
                                    tc, its->second, value_from_result(a), 0,
                                    buf);
                            }
                            uint64_t dir = 0;
                            if (!const_cast<TypeChecker &>(tc)
                                     .comptime_runtime()
                                     .marshal_aggregate(buf, dir)) {
                                marshal_ok = false;
                                break;
                            }
                            vm_args.push_back(dir);
                            continue;
                        }
                        vm_args.push_back(static_cast<uint64_t>(a.value));
                    }
                    ComptimeEvalResult vr;
                    vr.ok = true;
                    if (!marshal_ok) {
                        /* No pudimos marshalizar (VM no lista en pass 1):
                         * diferir; pass 2 lo resuelve con el bytecode cargado.
                         */
                        if (ret_is_str) vr.is_str = true;
                        vr.deferred = true;
                        return vr;
                    }
                    /* Nombre del macro: para las LOCALES el call site
                     * (`cid->name`) es la clave correcta (comportamiento
                     * previo; puede diferir del decl en casos como
                     * lambdas/monomorfiza- cion).  Para las IMPORTADAS el call
                     * usa el nombre desnudo
                     * (`buf_sum`) pero el `__macro_` mergeado del dep lleva el
                     * nombre mangled del namespace
                     * (`std__comptime__literal__buf_sum`), que es justamente el
                     * `decl->name` fijado por module_interop; solo ese coincide
                     * con el simbolo cargado en la ComptimeVM. */
                    const std::string macro_nm =
                        "__macro_" + (fn_it->second->is_imported_comptime
                                          ? fn_it->second->name
                                          : cid->name);
                    /* El otro nombre posible.  Una funcion comptime declarada
                     * en un fichero CON `namespace` compila a un simbolo con el
                     * prefijo del namespace (`__macro_mimod__gen`), pero desde
                     * su propio fichero se la llama por el nombre desnudo
                     * (`gen`) -- y con la clave desnuda no se encontraba, se
                     * daba por no ejecutable y el resultado salia VACiO sin
                     * decir nada.  Se prueba tambien la otra forma. */
                    const std::string macro_alt =
                        "__macro_" + (fn_it->second->is_imported_comptime
                                          ? cid->name
                                          : fn_it->second->name);
                    if (ret_is_str) {
                        std::string out;
                        bool inv =
                            const_cast<TypeChecker &>(tc)
                                .comptime_runtime()
                                .invoke_string_macro(macro_nm, vm_args, out);
                        if (!inv && macro_alt != macro_nm)
                            inv = const_cast<TypeChecker &>(tc)
                                      .comptime_runtime()
                                      .invoke_string_macro(macro_alt, vm_args,
                                                           out);
                        vr.is_str = true;
                        if (inv)
                            vr.str = std::move(out);
                        else
                            vr.deferred = true;
                    } else if (ret_is_enum) {
                        /* Mismo camino que un struct -- la funcion escribe en
                         * un bufer de retorno --, pero el valor de un enum es
                         * su ETIQUETA, y esa esta al principio del bufer.  No
                         * hay campos que reconstruir. */
                        std::vector<uint8_t> ebytes;
                        bool inv =
                            const_cast<TypeChecker &>(tc)
                                .comptime_runtime()
                                .invoke_struct_macro(macro_nm, vm_args,
                                                     ret_enum_bytes, ebytes);
                        if (!inv && macro_alt != macro_nm)
                            inv = const_cast<TypeChecker &>(tc)
                                      .comptime_runtime()
                                      .invoke_struct_macro(macro_alt, vm_args,
                                                           ret_enum_bytes,
                                                           ebytes);
                        if (inv && ebytes.size() >= 8) {
                            uint64_t tag = 0;
                            std::memcpy(&tag, ebytes.data(), 8);
                            vr.value = static_cast<int64_t>(tag);
                        } else {
                            vr.value = 0;
                            vr.deferred = true;
                        }
                    } else if (ret_is_struct) {
                        /* La funcion escribe el struct en un buffer de retorno
                         * (SRET); recuperamos sus bytes y reconstruimos cada
                         * campo como valor de compile-time. */
                        std::vector<uint8_t> sbytes;
                        bool inv = const_cast<TypeChecker &>(tc)
                                       .comptime_runtime()
                                       .invoke_struct_macro(
                                           macro_nm, vm_args,
                                           ret_slay->size_bytes, sbytes);
                        if (!inv && macro_alt != macro_nm)
                            inv = const_cast<TypeChecker &>(tc)
                                      .comptime_runtime()
                                      .invoke_struct_macro(macro_alt, vm_args,
                                                           ret_slay->size_bytes,
                                                           sbytes);
                        if (inv)
                            fill_struct_fields_from_bytes(tc, *ret_slay, sbytes,
                                                          0, vr);
                        else
                            vr.deferred = true;
                    } else {
                        uint64_t r0 = 0;
                        bool inv =
                            const_cast<TypeChecker &>(tc)
                                .comptime_runtime()
                                .invoke_simple_macro(macro_nm, vm_args, r0);
                        if (!inv && macro_alt != macro_nm)
                            inv = const_cast<TypeChecker &>(tc)
                                      .comptime_runtime()
                                      .invoke_simple_macro(macro_alt, vm_args,
                                                           r0);
                        if (inv)
                            vr.value = static_cast<int64_t>(r0);
                        else {
                            vr.value = 0;
                            vr.deferred = true;
                        }
                    }
                    return vr;
                }
                /* A.41: resolver type-args del call site. */
                std::vector<Type> type_args;
                type_args.reserve(ce->type_args.size());
                for (const auto &ta : ce->type_args) {
                    type_args.push_back(tc.resolve_type_node(ta.get()));
                }
                /* Necesitamos mutar tc (push/pop scope, contador
                 * de recursion).  Casting es seguro: la mutacion
                 * es local a la llamada y se revierte en la pop. */
                auto &mut_tc = const_cast<TypeChecker &>(tc);
                return comptime_call_fn(mut_tc, fn_it->second, std::move(args),
                                        std::move(type_args));
            }
        }
        return eval_builtin_call(tc, ce);
    }
    case ast::NodeKind::InitListExpr: {
        /* A.41/A.42: literal de array o struct, recursivo. */
        auto *il = static_cast<const ast::InitListExpr *>(expr);
        if (il->is_designated) {
            r.is_struct = true;
            for (size_t i = 0; i < il->elements.size(); ++i) {
                ComptimeEvalResult ev =
                    comptime_eval_expr(tc, il->elements[i].get());
                if (!ev.ok) {
                    r.ok = false;
                    return r;
                }
                const std::string &fname = (i < il->field_names.size())
                                               ? il->field_names[i]
                                               : std::to_string(i);
                r.struct_fields[fname] =
                    std::make_shared<ComptimeValue>(value_from_result(ev));
            }
            r.ok = true;
            return r;
        }
        r.is_array = true;
        r.array_vals.reserve(il->elements.size());
        for (const auto &el : il->elements) {
            ComptimeEvalResult ev = comptime_eval_expr(tc, el.get());
            if (!ev.ok) {
                r.ok = false;
                return r;
            }
            r.array_vals.push_back(
                std::make_shared<ComptimeValue>(value_from_result(ev)));
        }
        r.ok = true;
        return r;
    }
    case ast::NodeKind::FieldAccessExpr: {
        /* A.41/A.42: `obj.field` -- field puede ser cualquier kind. */
        auto *fa = static_cast<const ast::FieldAccessExpr *>(expr);
        if (!fa->base) return r;
        /* Valued enum: `Op.MOV` -> valor comptime de la variante.  Entero
         * directo (int_value); float/string se evaluan de su value_ast. */
        if (fa->base->kind == ast::NodeKind::IdentExpr) {
            const auto *bid =
                static_cast<const ast::IdentExpr *>(fa->base.get());
            const auto &elays = tc.enum_layouts();
            auto ite = elays.find(bid->name);
            if (ite != elays.end() && ite->second.is_valued) {
                const PrimitiveKind bk = ite->second.backing;
                const bool is_int =
                    (bk == PrimitiveKind::I8 || bk == PrimitiveKind::I16 ||
                     bk == PrimitiveKind::I32 || bk == PrimitiveKind::I64 ||
                     bk == PrimitiveKind::U8 || bk == PrimitiveKind::U16 ||
                     bk == PrimitiveKind::U32 || bk == PrimitiveKind::U64);
                for (const auto &v : ite->second.variants) {
                    if (v.name == fa->field_name) {
                        if (is_int) {
                            r.ok = true;
                            r.value = v.int_value;
                            return r;
                        }
                        if (v.value_ast)
                            return comptime_eval_expr(tc, v.value_ast);
                        return r;
                    }
                }
            }
            /* Un enum SIN valor -- el corriente, `enum Tok { A, B, C }` -- vale
             * su ETIQUETA, que es el orden en que se declaro.  Solo se trataban
             * los enums con valor (`: u8`), asi que `Tok.C` no era
             * comptime-evaluable y se llevaba por delante toda expresion que lo
             * mencionara: una llamada comptime con un enum por argumento no se
             * podia evaluar, y lo que dependiera de ella salia vacio. */
            if (ite != elays.end() && !ite->second.is_valued) {
                for (const auto &v : ite->second.variants) {
                    if (v.name != fa->field_name) continue;
                    /* Con carga util no basta la etiqueta: el valor son ademas
                     * sus campos, y eso no cabe en un entero.  Se dice que no
                     * en vez de devolver media verdad. */
                    if (!v.field_types.empty()) return r;
                    r.ok = true;
                    r.value = static_cast<int64_t>(v.tag);
                    return r;
                }
            }
        }
        ComptimeEvalResult obj = comptime_eval_expr(tc, fa->base.get());
        if (!obj.ok || !obj.is_struct) return r;
        auto it = obj.struct_fields.find(fa->field_name);
        if (it == obj.struct_fields.end() || !it->second) return r;
        return result_from_value(*it->second);
    }
    case ast::NodeKind::IndexExpr: {
        /* A.41/A.42: `arr[i]` -- element puede ser cualquier kind. */
        auto *ie = static_cast<const ast::IndexExpr *>(expr);
        if (!ie->base || !ie->index) return r;
        ComptimeEvalResult arr = comptime_eval_expr(tc, ie->base.get());
        if (!arr.ok || !arr.is_array) return r;
        ComptimeEvalResult idx = comptime_eval_expr(tc, ie->index.get());
        if (!idx.ok || idx.is_str || idx.is_array || idx.is_struct) return r;
        if (idx.value < 0 || (size_t)idx.value >= arr.array_vals.size()) {
            return r;
        }
        const auto &slot = arr.array_vals[(size_t)idx.value];
        if (!slot) return r;
        return result_from_value(*slot);
    }
    case ast::NodeKind::CastExpr: {
        /* A.41: cast `(T) expr` en contexto comptime: evaluamos
         * el operando y, si es entero, lo enmascaramos al ancho
         * del tipo destino (truncate).  No soportamos casts a
         * struct/array/string en comptime. */
        auto *ce = static_cast<const ast::CastExpr *>(expr);
        if (!ce->operand) return r;
        ComptimeEvalResult v = comptime_eval_expr(tc, ce->operand.get());
        if (!v.ok || v.is_str || v.is_array || v.is_struct) return r;
        /* Aplicar mascara segun el tipo destino (cast a entero
         * narrower).  Para float / bool / ptr lo dejamos pasar. */
        if (ce->target_type) {
            Type tt = tc.resolve_type_node(ce->target_type.get());
            int64_t val = v.value;
            switch (tt.kind) {
            case PrimitiveKind::I8: val = (int8_t)val; break;
            case PrimitiveKind::I16: val = (int16_t)val; break;
            case PrimitiveKind::I32: val = (int32_t)val; break;
            case PrimitiveKind::U8: val = (uint8_t)val; break;
            case PrimitiveKind::U16: val = (uint16_t)val; break;
            case PrimitiveKind::U32: val = (uint32_t)val; break;
            default: break;
            }
            r.ok = true;
            r.value = val;
            return r;
        }
        r.ok = true;
        r.value = v.value;
        return r;
    }
    case ast::NodeKind::TernaryExpr: {
        /* A.38/A.39: ternario comptime-evaluable.  Soporta
         * cortocircuito: solo se evalua la rama elegida. */
        auto *te = static_cast<const ast::TernaryExpr *>(expr);
        ComptimeEvalResult c = comptime_eval_expr(tc, te->cond.get());
        if (!c.ok) return r;
        if (c.value != 0) {
            return comptime_eval_expr(tc, te->then_expr.get());
        }
        return comptime_eval_expr(tc, te->else_expr.get());
    }
    case ast::NodeKind::UnaryExpr: {
        auto *un = static_cast<const ast::UnaryExpr *>(expr);
        ComptimeEvalResult v = comptime_eval_expr(tc, un->operand.get());
        if (!v.ok) return r;
        switch (un->op) {
        case ast::UnOp::LogicalNot:
            r.ok = true;
            r.value = (v.value == 0) ? 1 : 0;
            return r;
        case ast::UnOp::Neg:
            r.ok = true;
            r.value = -v.value;
            return r;
        case ast::UnOp::Pos:
            r.ok = true;
            r.value = v.value;
            return r;
        case ast::UnOp::BitNot:
            r.ok = true;
            r.value = ~v.value;
            return r;
        case ast::UnOp::PreInc:
        case ast::UnOp::PostInc:
        case ast::UnOp::PreDec:
        case ast::UnOp::PostDec: {
            /* Incremento/decremento sobre un identificador comptime mutable:
             * actualiza el binding EN SITIO y devuelve el valor viejo (post-)
             * o nuevo (pre-).  Necesario para `for (...; i++)` en comptime
             * (el step cae aqui como UnaryExpr, no como AssignExpr). */
            if (un->operand->kind != ast::NodeKind::IdentExpr) return r;
            const auto *id =
                static_cast<const ast::IdentExpr *>(un->operand.get());
            auto *binding = find_comptime_local_mut(
                const_cast<TypeChecker &>(tc), id->name);
            if (!binding || !binding->is_mutable || binding->is_str ||
                binding->is_array || binding->is_struct)
                return r;
            const int64_t old_v = binding->value;
            const int64_t delta =
                (un->op == ast::UnOp::PreInc || un->op == ast::UnOp::PostInc)
                    ? 1
                    : -1;
            binding->value = old_v + delta;
            r.ok = true;
            r.value =
                (un->op == ast::UnOp::PostInc || un->op == ast::UnOp::PostDec)
                    ? old_v
                    : binding->value;
            return r;
        }
        default: return r;
        }
    }
    case ast::NodeKind::BinaryExpr: {
        auto *bn = static_cast<const ast::BinaryExpr *>(expr);
        /* Cortocircuito para && y ||: evaluamos rhs solo si hace falta. */
        if (bn->op == ast::BinOp::LogicalAnd) {
            ComptimeEvalResult a = comptime_eval_expr(tc, bn->lhs.get());
            if (!a.ok) return r;
            if (a.value == 0) {
                r.ok = true;
                r.value = 0;
                r.deferred = a.deferred;
                return r;
            }
            ComptimeEvalResult b = comptime_eval_expr(tc, bn->rhs.get());
            if (!b.ok) return r;
            r.ok = true;
            r.value = (b.value != 0) ? 1 : 0;
            r.deferred = a.deferred || b.deferred;
            return r;
        }
        if (bn->op == ast::BinOp::LogicalOr) {
            ComptimeEvalResult a = comptime_eval_expr(tc, bn->lhs.get());
            if (!a.ok) return r;
            if (a.value != 0) {
                r.ok = true;
                r.value = 1;
                r.deferred = a.deferred;
                return r;
            }
            ComptimeEvalResult b = comptime_eval_expr(tc, bn->rhs.get());
            if (!b.ok) return r;
            r.ok = true;
            r.value = (b.value != 0) ? 1 : 0;
            r.deferred = a.deferred || b.deferred;
            return r;
        }
        ComptimeEvalResult a = comptime_eval_expr(tc, bn->lhs.get());
        if (!a.ok) return r;
        ComptimeEvalResult b = comptime_eval_expr(tc, bn->rhs.get());
        if (!b.ok) return r;
        /* #2: si algun operando es un placeholder diferido (valor de una
         * comptime fn via ComptimeVM aun no cargada), el resultado tambien
         * lo es -> static_assert no debe dispararse (se resuelve en pass 2). */
        r.deferred = a.deferred || b.deferred;
        /* A.43.14: operadores sobre strings comptime.
         *   `s1 + s2`  -> concat
         *   `s1 == s2` -> streq
         *   `s1 != s2` -> !streq
         * Reduce verbosidad en cadenas largas de macros donde
         * antes habia que escribir `comptime_concat(a, b)` o
         * `comptime_streq(a, b)` explicitamente. */
        if (a.is_str && b.is_str) {
            if (bn->op == ast::BinOp::Add) {
                /* A.43.20: move + reserve para evitar 1 alocacion
                 * del temporal `a.str + b.str`.  Reusamos el
                 * buffer de `a` (que es local de esta funcion)
                 * y appendamos b.  Coste: 1 alocacion en lugar
                 * de 2 (~30-50% menos memoria traffic). */
                r.ok = true;
                r.is_str = true;
                r.str.reserve(a.str.size() + b.str.size());
                r.str = std::move(a.str);
                r.str += b.str;
                return r;
            }
            if (bn->op == ast::BinOp::Eq) {
                r.ok = true;
                r.value = (a.str == b.str) ? 1 : 0;
                return r;
            }
            if (bn->op == ast::BinOp::Neq) {
                r.ok = true;
                r.value = (a.str != b.str) ? 1 : 0;
                return r;
            }
            /* Otros operadores sobre strings: no soportados.
             * Caemos al default (return r con ok=false). */
            return r;
        }
        /* Mismo soporte para string + int (concat con stringify
         * automatico del int) -- azucar adicional muy comun en
         * builders de codigo: `"doblar(" + n + ")"`. */
        if (a.is_str && !b.is_str && !b.is_array && !b.is_struct &&
            !b.is_type && bn->op == ast::BinOp::Add) {
            /* A.43.20: move a.str + append.  Mismo ahorro. */
            r.ok = true;
            r.is_str = true;
            const std::string b_str = std::to_string(b.value);
            r.str.reserve(a.str.size() + b_str.size());
            r.str = std::move(a.str);
            r.str += b_str;
            return r;
        }
        if (!a.is_str && !a.is_array && !a.is_struct && !a.is_type &&
            b.is_str && bn->op == ast::BinOp::Add) {
            /* A.43.20: aqui no podemos mover b porque el prepend
             * requiere a-stringified ANTES de b.  Reserve para
             * 1 sola alocacion. */
            r.ok = true;
            r.is_str = true;
            const std::string a_str = std::to_string(a.value);
            r.str.reserve(a_str.size() + b.str.size());
            r.str = a_str;
            r.str += b.str;
            return r;
        }
        switch (bn->op) {
        case ast::BinOp::Add:
            r.ok = true;
            r.value = a.value + b.value;
            return r;
        case ast::BinOp::Sub:
            r.ok = true;
            r.value = a.value - b.value;
            return r;
        case ast::BinOp::Mul:
            r.ok = true;
            r.value = a.value * b.value;
            return r;
        case ast::BinOp::Div:
            if (b.value == 0) return r;
            r.ok = true;
            r.value = a.value / b.value;
            return r;
        case ast::BinOp::Mod:
            if (b.value == 0) return r;
            r.ok = true;
            r.value = a.value % b.value;
            return r;
        case ast::BinOp::BitAnd:
            r.ok = true;
            r.value = a.value & b.value;
            return r;
        case ast::BinOp::BitOr:
            r.ok = true;
            r.value = a.value | b.value;
            return r;
        case ast::BinOp::BitXor:
            r.ok = true;
            r.value = a.value ^ b.value;
            return r;
        case ast::BinOp::Shl:
            r.ok = true;
            r.value = a.value << (b.value & 63);
            return r;
        case ast::BinOp::Shr:
            r.ok = true;
            r.value = a.value >> (b.value & 63);
            return r;
        case ast::BinOp::Eq:
            r.ok = true;
            r.value = (a.value == b.value) ? 1 : 0;
            return r;
        case ast::BinOp::Neq:
            r.ok = true;
            r.value = (a.value != b.value) ? 1 : 0;
            return r;
        case ast::BinOp::Lt:
            r.ok = true;
            r.value = (a.value < b.value) ? 1 : 0;
            return r;
        case ast::BinOp::Gt:
            r.ok = true;
            r.value = (a.value > b.value) ? 1 : 0;
            return r;
        case ast::BinOp::Le:
            r.ok = true;
            r.value = (a.value <= b.value) ? 1 : 0;
            return r;
        case ast::BinOp::Ge:
            r.ok = true;
            r.value = (a.value >= b.value) ? 1 : 0;
            return r;
        default: return r;
        }
    }
    default: return r;
    }
}

// -------------------------------------------------------------------------
// Helpers de introspeccion sobre newtypes (typedef T name new).
// -------------------------------------------------------------------------
// Un newtype es un alias nominal: dos Type con la misma representacion
// pero distinto @c nominal_id son tipos DIFERENTES.  El campo se setea
// en el TypeChecker al procesar la TypeAliasDecl con @c is_newtype.
// @opaque es un sub-flag que prohibe al usuario observar el underlying.

bool comptime_is_newtype(const Type &t) {
    return t.nominal_id != 0;
}

bool comptime_is_opaque(const Type &t) {
    return t.nominal_id != 0 && t.is_opaque;
}

std::string comptime_underlying_name(const TypeChecker &tc, const Type &t) {
    // Para un newtype, el typename canonico ya esconde el nominal_id.
    // El "underlying" es el mismo tipo con @c nominal_id=0, lo que se
    // consigue creando una copia sin la marca nominal.  Para no-newtype
    // devolvemos el name habitual sin indireccion.
    if (t.nominal_id == 0) return comptime_type_name(tc, t);
    Type u = t;
    u.nominal_id = 0;
    u.is_opaque = false;
    u.nominal_name.clear();
    return comptime_type_name(tc, u);
}

} // namespace vx
