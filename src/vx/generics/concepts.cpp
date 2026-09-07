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
 * @file concepts.cpp
 * @brief Evaluacion de conceptos / constraints de genericos (#6).
 *
 * Conceptos built-in (Numeric, Comparable, Sized, ...) evaluados sobre el
 * @c Type concreto, y conceptos de usuario (`concept N<T> = ...;`) evaluados
 * por el interprete comptime (predicado / bloque / estructural).  La
 * verificacion de bounds al monomorphizar vive en @c TypeChecker::
 * check_type_bounds.  Todo es compile-time: cero codigo emitido.
 */

#include "vx/generics/concepts.h"

#include "vx/comptime/comptime_introspect.h"
#include "vx/type_checker.h"

#include "vx/generics/generic_clone.h"

#include "util/os/thread_slot.h" // el contador de recursion, sin `thread_local`

namespace vx {

// ------------------------------------------------------------------
// Conceptos built-in: predicados sobre el Type concreto.
// ------------------------------------------------------------------

bool is_builtin_concept(const std::string &name) {
    static const std::unordered_set<std::string> set = {
        "Numeric",   "Number",     "Integer",    "Int",          "Float",
        "Signed",    "Unsigned",   "Bool",       "Char",         "Pointer",
        "String",    "Comparable", "Ordered",    "Eq",           "Sized",
        "Copyable",  "Hashable",   "Stringable", "Default",      "Primitive",
        "Class",     "Struct",     "Callable",   "Destructible", "Iterable",
        "Shareable", "Enum",       "ValuedEnum", "Scalar",
    };
    return set.count(name) > 0;
}

/// Evalua un concepto BUILT-IN.  @p found queda true si el nombre es
/// built-in.  Todos derivan de @c t.kind + la introspeccion comptime.
static bool eval_builtin_concept(const TypeChecker &tc, const std::string &name,
                                 const Type &t, bool &found) {
    found = true;
    const PrimitiveKind k = t.kind;
    const bool is_int = k == PrimitiveKind::I8 || k == PrimitiveKind::I16 ||
                        k == PrimitiveKind::I32 || k == PrimitiveKind::I64 ||
                        k == PrimitiveKind::U8 || k == PrimitiveKind::U16 ||
                        k == PrimitiveKind::U32 || k == PrimitiveKind::U64;
    const bool is_signed = k == PrimitiveKind::I8 || k == PrimitiveKind::I16 ||
                           k == PrimitiveKind::I32 || k == PrimitiveKind::I64;
    const bool is_flt = k == PrimitiveKind::F32 || k == PrimitiveKind::F64;
    const bool is_num = is_int || is_flt;
    const bool is_prim = comptime_is_primitive(t);

    if (name == "Numeric" || name == "Number") return is_num;
    // Scalar: valor escalar de maquina (int|float|bool|puntero).  Base de los
    // tipos atomizables / bitcasteables; NO incluye string/struct/clase/enum.
    if (name == "Scalar")
        return is_int || is_flt || k == PrimitiveKind::BOOL ||
               k == PrimitiveKind::PTR;
    if (name == "Integer" || name == "Int") return is_int;
    if (name == "Float") return is_flt;
    if (name == "Signed") return is_signed;
    if (name == "Unsigned") return is_int && !is_signed;
    if (name == "Bool") return k == PrimitiveKind::BOOL;
    if (name == "Char") return k == PrimitiveKind::CHAR;
    if (name == "Pointer") return k == PrimitiveKind::PTR;
    if (name == "String") return k == PrimitiveKind::STRING;
    if (name == "Primitive") return is_prim;
    if (name == "Class") return comptime_is_class(t);
    if (name == "Struct") return comptime_is_struct(tc, t);
    // Enum: cualquier enum (ADT tagged-union o C-style con valor).
    if (name == "Enum") return comptime_is_enum(tc, t);
    // ValuedEnum: solo los C-style con backing entero/float/string
    // (los ADT no tienen valor).  Backing struct/clase son su tipo base.
    if (name == "ValuedEnum") return t.is_valued_enum;
    if (name == "Callable") return k == PrimitiveKind::FUNCTION;
    // Comparable / Ordered: soportan `<` / `>` -> numericos, char, bool.
    if (name == "Comparable" || name == "Ordered")
        return is_num || k == PrimitiveKind::CHAR || k == PrimitiveKind::BOOL;
    // Eq: soportan `==` -> primitivos, string, punteros.
    if (name == "Eq")
        return is_prim || k == PrimitiveKind::STRING || k == PrimitiveKind::PTR;
    // Sized: tiene tamano conocido (> 0) -> todo tipo concreto salvo void.
    if (name == "Sized") return comptime_type_size(tc, t) > 0;
    // Copyable: value-types copiables (primitivos, structs, punteros).
    if (name == "Copyable")
        return is_prim || comptime_is_struct(tc, t) || k == PrimitiveKind::PTR;
    // Hashable: primitivos + string (tienen hash canonico).
    if (name == "Hashable") return is_prim || k == PrimitiveKind::STRING;
    // Stringable: string, primitivos, o tiene metodo toString().
    if (name == "Stringable")
        return k == PrimitiveKind::STRING || is_prim ||
               comptime_has_method(tc, t, "toString");
    // Default: tiene valor por defecto (primitivos + punteros = 0/null).
    if (name == "Default") return is_prim || k == PrimitiveKind::PTR;
    // Destructible: clases/structs (pueden tener ~T()).
    if (name == "Destructible")
        return comptime_is_class(t) || comptime_is_struct(tc, t);
    // Iterable: arrays, strings, o tiene iter()/next().
    if (name == "Iterable")
        return k == PrimitiveKind::ARRAY || k == PrimitiveKind::STRING ||
               comptime_has_method(tc, t, "iter") ||
               comptime_has_method(tc, t, "next");
    // Shareable ( Z): objetos GC + value-types compartibles.
    if (name == "Shareable")
        return comptime_is_class(t) || comptime_is_struct(tc, t) || is_prim;

    found = false;
    return false;
}

// ------------------------------------------------------------------
// Evaluacion unificada (built-in + usuario) con cota de recursion.
// ------------------------------------------------------------------

ConceptEval comptime_eval_concept(const TypeChecker &tc,
                                  const std::string &name, const Type &t) {
    ConceptEval r;

    /* Cota dura contra conceptos ciclicos (A definido via B definido via A).
     *
     * En una RANURA y no en `thread_local`: en MinGW la TLS es emulada y cada
     * acceso es una llamada.  Un contador cabe en el propio puntero, asi que
     * no hay nada que reservar.  Ver `util/os/thread_slot.h`. */
    static util::ThreadSlot depth_slot;
    depth_slot.ensure();
    const auto read_depth = [&]() -> uintptr_t {
        return reinterpret_cast<uintptr_t>(depth_slot.get());
    };
    const auto write_depth = [&](uintptr_t d) {
        depth_slot.set(reinterpret_cast<void *>(d));
    };
    if (read_depth() > 64) {
        r.found = true;
        r.satisfied = false;
        return r;
    }

    if (is_builtin_concept(name)) {
        bool found = false;
        const bool v = eval_builtin_concept(tc, name, t, found);
        r.found = found;
        r.satisfied = v;
        return r;
    }

    auto it = tc.concepts().find(name);
    if (it == tc.concepts().end() && name.find('.') != std::string::npos) {
        // NS.2: concepto cualificado por namespace (`mat.Numerico`).  El
        // flatten lo registro como `mat__Numerico`; mapear `.`->`__` y
        // reintentar.
        std::string mangled;
        for (char c : name)
            mangled += (c == '.') ? std::string("__") : std::string(1, c);
        it = tc.concepts().find(mangled);
    }
    if (it == tc.concepts().end()) {
        r.found = false; // ni built-in ni de usuario
        return r;
    }
    r.found = true;
    const ast::ConceptDecl *cd = it->second;

    // Sustituir el (primer) type-param del concepto por el tipo concreto.
    std::vector<std::string> params = cd->type_params;
    std::vector<Type> args;
    args.push_back(t);
    vxgen::GenSubst g;
    g.params = &params;
    g.args = &args;

    write_depth(read_depth() + 1);
    struct DepthGuard {
        util::ThreadSlot &s;
        ~DepthGuard() {
            s.set(reinterpret_cast<void *>(
                reinterpret_cast<uintptr_t>(s.get()) - 1));
        }
    } guard{depth_slot};

    switch (cd->ckind) {
    case ast::ConceptKind::Predicate: {
        if (!cd->predicate) {
            r.satisfied = false;
            return r;
        }
        auto cloned = vxgen::clone_expr(cd->predicate.get(), g);
        const ComptimeEvalResult er = comptime_eval_expr(tc, cloned.get());
        r.satisfied = er.ok && er.value != 0;
        return r;
    }
    case ast::ConceptKind::Block: {
        if (!cd->body) {
            r.satisfied = false;
            return r;
        }
        auto cloned = vxgen::clone_stmt(cd->body.get(), g);
        // comptime_eval_stmt muta el estado comptime (scopes); el cast es
        // seguro porque la mutacion es local y se revierte.  Mismo patron
        // que comptime_eval_expr al invocar comptime_call_fn.
        auto &mut_tc = const_cast<TypeChecker &>(tc);
        ComptimeControl ctrl;
        const bool ok = comptime_eval_stmt(mut_tc, cloned.get(), ctrl);
        r.satisfied = ok && ctrl.returned && ctrl.return_value.ok &&
                      ctrl.return_value.value != 0;
        return r;
    }
    case ast::ConceptKind::Structural: {
        // El tipo debe tener TODOS los metodos exigidos, con FIRMA
        // compatible: mismo nombre, misma aridad, mismo tipo de retorno y
        // mismos tipos de parametros.  Localiza el ClassMethodInfo del tipo
        // (clase o struct) y lo compara contra la firma del concepto.
        const std::vector<ClassMethodInfo> *methods = nullptr;
        if (t.kind == PrimitiveKind::CLASS) {
            auto itc = tc.class_layouts().find(t.struct_name);
            if (itc != tc.class_layouts().end()) methods = &itc->second.methods;
        } else if (t.kind == PrimitiveKind::STRUCT) {
            auto its = tc.struct_layouts().find(t.struct_name);
            if (its != tc.struct_layouts().end())
                methods = &its->second.methods;
        }
        bool all = (methods != nullptr);
        if (methods) {
            for (const auto &sm : cd->structural_methods) {
                const ClassMethodInfo *found = nullptr;
                for (const auto &m : *methods) {
                    if (m.is_constructor || m.is_destructor) continue;
                    if (m.name == sm.name) {
                        found = &m;
                        break;
                    }
                }
                if (!found) {
                    all = false;
                    break;
                }
                // Aridad.
                if (found->param_types.size() != sm.param_types.size()) {
                    all = false;
                    break;
                }
                // Tipo de retorno (null en la firma = void).
                const Type want_ret =
                    sm.return_type ? tc.resolve_type_node(sm.return_type.get())
                                   : Type{PrimitiveKind::VOID};
                if (!(found->return_type == want_ret)) {
                    all = false;
                    break;
                }
                // Tipos de parametros.
                bool params_ok = true;
                for (size_t i = 0; i < sm.param_types.size(); ++i) {
                    const Type want_p =
                        tc.resolve_type_node(sm.param_types[i].get());
                    if (!(found->param_types[i] == want_p)) {
                        params_ok = false;
                        break;
                    }
                }
                if (!params_ok) {
                    all = false;
                    break;
                }
            }
        }
        r.satisfied = all;
        return r;
    }
    }
    return r;
}

// ------------------------------------------------------------------
// Verificacion de bounds al monomorphizar (TypeChecker method).
// ------------------------------------------------------------------

void TypeChecker::check_type_bounds(const std::vector<ast::TypeBound> &bounds,
                                    const std::vector<std::string> &params,
                                    const std::vector<Type> &args,
                                    const SourceLoc &loc) {
    if (bounds.empty()) return;
    // NO se evalua aqui: se ENCOLA.  La evaluacion se difiere hasta que los
    // layouts de clases/structs existen (los conceptos estructurales y
    // has_method/sizeof de tipos de usuario los necesitan); la monomorphizacion
    // de structs/clases/funciones corre en pre_mono, ANTES de collect_globals.
    for (const auto &b : bounds) {
        size_t idx = params.size();
        for (size_t i = 0; i < params.size(); ++i) {
            if (params[i] == b.type_param) {
                idx = i;
                break;
            }
        }
        if (idx >= args.size()) continue; // param no encontrado: ignorar
        for (const auto &cname : b.concepts) {
            PendingBoundCheck pc;
            pc.concept_name = cname;
            pc.arg = args[idx];
            pc.type_param = b.type_param;
            pc.loc = loc;
            pending_bound_checks_.push_back(std::move(pc));
        }
    }
}

bool TypeChecker::method_available_for_subst(
    const ast::ClassMethodDecl *m,
    const std::vector<std::string> &container_params,
    const std::vector<Type> &container_args,
    std::vector<ast::TypeBound> &method_only) {
    bool available = true;
    for (const auto &b : m->type_bounds) {
        // ¿El bound habla de un type-param del PROPIO metodo (`m<U: C>`)?  Esos
        // se verifican al monomorphizar el metodo, no filtran su existencia.
        bool is_method_param = false;
        for (const auto &mp : m->method_type_params)
            if (mp == b.type_param) {
                is_method_param = true;
                break;
            }
        if (is_method_param) {
            method_only.push_back(b);
            continue;
        }
        // Bound sobre un type-param del CONTENEDOR: localizar su arg concreto.
        size_t idx = container_params.size();
        for (size_t i = 0; i < container_params.size(); ++i)
            if (container_params[i] == b.type_param) {
                idx = i;
                break;
            }
        if (idx >= container_args.size()) {
            // Ni del metodo ni del contenedor: bound anomalo; preservarlo sin
            // filtrar (podria referirse a un alias externo).
            method_only.push_back(b);
            continue;
        }
        const Type &arg = container_args[idx];
        for (const auto &cname : b.concepts) {
            const ConceptEval ev = comptime_eval_concept(*this, cname, arg);
            if (!ev.found) {
                diags_.error(b.loc, "concepto desconocido '" + cname +
                                        "' en la clausula where del metodo '" +
                                        m->name + "'");
                continue; // no filtrar por un concepto invalido
            }
            if (!ev.satisfied) available = false;
        }
    }
    return available;
}

void TypeChecker::record_unavailable_method(
    const std::string &container_mangled, const ast::ClassMethodDecl *m) {
    std::string reqs;
    for (const auto &b : m->type_bounds) {
        for (const auto &c : b.concepts) {
            if (!reqs.empty()) reqs += ", ";
            reqs += b.type_param + ": " + c;
        }
    }
    unavailable_methods_[container_mangled].push_back({m->name, reqs});
}

void TypeChecker::verify_pending_type_bounds() {
    if (pending_bound_checks_.empty()) return;
    // Tomar el lote actual (la evaluacion de un concepto podria, en teoria,
    // disparar monomorphizaciones que encolen mas bounds; procesamos a punto
    // fijo con cota dura defensiva).
    for (int round = 0; round < 64 && !pending_bound_checks_.empty(); ++round) {
        std::vector<PendingBoundCheck> batch;
        batch.swap(pending_bound_checks_);
        for (const auto &pc : batch) {
            const ConceptEval ev =
                comptime_eval_concept(*this, pc.concept_name, pc.arg);
            if (!ev.found) {
                diags_.error(pc.loc,
                             "concepto desconocido '" + pc.concept_name +
                                 "' en el bound de '" + pc.type_param + "'");
                continue;
            }
            if (!ev.satisfied) {
                diags_.error(pc.loc, "el tipo '" + type_to_string(pc.arg) +
                                         "' no satisface el concepto '" +
                                         pc.concept_name +
                                         "' exigido por el parametro '" +
                                         pc.type_param + "'");
            }
        }
    }
}

} // namespace vx
