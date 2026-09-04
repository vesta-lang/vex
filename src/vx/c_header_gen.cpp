/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file c_header_gen.cpp
 * @brief Implementacion del generador de header C publico (Fase 4 interop C).
 */

#include "vx/c_header_gen.h"

#include "port/snippet_loader.h" // boilerplate C en stdlib/port/c, no hardcode
#include "vx/ast.h"
#include "vx/type_checker.h"
#include "vx/types.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <unordered_set>
#include <vector>

namespace vx {

namespace {

/// Mapea un primitivo escalar Vesta a su tipo C (stdint).  Devuelve nullptr si
/// no es un escalar simple (struct/ptr/fn/etc. se manejan aparte).
const char *c_scalar(PrimitiveKind k) {
    switch (k) {
    case PrimitiveKind::VOID: return "void";
    case PrimitiveKind::BOOL: return "uint8_t"; // 1 byte
    case PrimitiveKind::CHAR: return "uint8_t"; // 1 byte (layout)
    case PrimitiveKind::I8: return "int8_t";
    case PrimitiveKind::I16: return "int16_t";
    case PrimitiveKind::I32: return "int32_t";
    case PrimitiveKind::I64: return "int64_t";
    case PrimitiveKind::U8: return "uint8_t";
    case PrimitiveKind::U16: return "uint16_t";
    case PrimitiveKind::U32: return "uint32_t";
    case PrimitiveKind::U64: return "uint64_t";
    case PrimitiveKind::F32: return "float";
    case PrimitiveKind::F64: return "double";
    default: return nullptr;
    }
}

/// Nombre base de un tipo PTR: el pointee mapeado + "*" (recursivo para T**).
/// void* para punteros opacos.
std::string c_ptr_base(const Type &t);

std::string c_base_type(const Type &t) {
    if (const char *s = c_scalar(t.kind)) return s;
    if (t.kind == PrimitiveKind::STRUCT) return t.struct_name;
    if (t.kind == PrimitiveKind::PTR) return c_ptr_base(t);
    // Fallback opaco (no deberia llegar para tipos C-representables).
    return "void";
}

std::string c_ptr_base(const Type &t) {
    if (!t.pointee) return "void*";
    // void* explicito para puntero a void.
    if (t.pointee->kind == PrimitiveKind::VOID) return "void*";
    return c_base_type(*t.pointee) + "*";
}

/// Declara un identificador con su tipo C, embebiendo el nombre donde C lo
/// exige (punteros a funcion `cfn`, arrays).
/// @param as_field true para un campo de struct (agregados INLINE: struct por
///        valor, array dimensionado); false para un parametro (agregados por
///        PUNTERO: la ABI de agregados del port-C).
std::string c_decl(const Type &t, const std::string &name, bool as_field) {
    // Puntero a funcion crudo `cfn(params) -> R`: `R (*name)(p1, p2, ...)`.
    if (t.kind == PrimitiveKind::FUNCTION && t.fn_is_raw) {
        std::ostringstream os;
        const Type ret = t.pointee ? *t.pointee : Type{PrimitiveKind::VOID};
        os << c_base_type(ret) << " (*" << name << ")(";
        if (t.fn_params().empty()) {
            os << "void";
        } else {
            for (size_t i = 0; i < t.fn_params().size(); ++i) {
                if (i) os << ", ";
                os << c_decl(t.fn_params()[i], "", /*as_field=*/false);
            }
        }
        os << ")";
        return os.str();
    }
    // Array nativo.
    if (t.kind == PrimitiveKind::ARRAY && t.pointee) {
        const std::string elem = c_base_type(*t.pointee);
        if (as_field && t.array_size > 0)
            return elem + " " + name + "[" + std::to_string(t.array_size) + "]";
        // Como parametro (o T[] sin tamano) decae a puntero.
        return elem + "* " + name;
    }
    // Struct: campo -> por valor (inline); parametro/retorno -> por puntero.
    if (t.kind == PrimitiveKind::STRUCT) {
        if (as_field) return t.struct_name + " " + name;
        return t.struct_name + "* " + name;
    }
    // Puntero / escalar.
    std::string base = c_base_type(t);
    if (name.empty()) return base;
    return base + " " + name;
}

/// Sanitiza un nombre para el include guard (mayusculas, no-alfanumerico->'_').
std::string guard_of(const std::string &base) {
    std::string g;
    for (char c : base) {
        if (std::isalnum(static_cast<unsigned char>(c)))
            g += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        else
            g += '_';
    }
    if (g.empty() || std::isdigit(static_cast<unsigned char>(g[0])))
        g = "_" + g;
    return g + "_H";
}

/// Orden topologico de structs por dependencia de campo INLINE (un struct con
/// un campo struct-por-valor debe declararse despues del contenido).  Los
/// campos puntero/cfn no crean dependencia (forward typedef basta).
void topo_visit(const std::string &name,
                const std::unordered_map<std::string, StructLayout> &layouts,
                const std::set<std::string> &c_compat,
                std::unordered_set<std::string> &done,
                std::vector<std::string> &order) {
    if (done.count(name)) return;
    done.insert(name);
    auto it = layouts.find(name);
    if (it != layouts.end()) {
        for (const auto &f : it->second.fields) {
            if (f.type.kind == PrimitiveKind::STRUCT &&
                c_compat.count(f.type.struct_name)) {
                topo_visit(f.type.struct_name, layouts, c_compat, done, order);
            }
        }
    }
    order.push_back(name);
}

} // namespace

std::string generate_c_header(const ast::ModuleNode &mod, const TypeChecker &tc,
                              const std::string &guard_base) {
    std::ostringstream os;
    const std::string guard = guard_of(guard_base);

    os << "/* Header C generado por VestaVM (vx --emit-header).\n"
       << " * Interfaz publica del modulo Vesta: structs C-compat + funciones\n"
       << " * con firma C-representable.  Los structs cruzan POR PUNTERO\n"
       << " * (ABI de agregados; un T* == void* a nivel ABI).  Editar a mano\n"
       << " * bajo tu propio riesgo; regenera con vx --emit-header. */\n";
    os << "#ifndef " << guard << "\n#define " << guard << "\n\n";
    // Prelude estatico desde stdlib/port/c (includes + apertura extern "C").
    // Minimo C/C++ hardcodeado: la boilerplate vive en el snippet.
    bool pre_ok = false;
    const std::string prelude =
        port::load_snippet_text("vx_header_prelude", "", pre_ok);
    if (pre_ok) {
        os << prelude << "\n";
    } else {
        // Fallback minimo si no se encuentra stdlib/port/c.
        os << "#include <stdint.h>\n#ifdef __cplusplus\nextern \"C\" "
              "{\n#endif\n\n";
    }

    // --- 1. Structs C-representables, en orden topologico ---
    const auto &layouts = tc.struct_layouts();
    std::set<std::string> c_compat;
    for (const auto &kv : layouts) {
        if (kv.second.cat_c_representable && kv.second.is_public)
            c_compat.insert(kv.first);
    }
    std::vector<std::string> order;
    std::unordered_set<std::string> done;
    for (const auto &name : c_compat)
        topo_visit(name, layouts, c_compat, done, order);

    if (!order.empty()) {
        os << "/* Structs (layout C). */\n";
        for (const auto &name : order) {
            const StructLayout &lay = layouts.at(name);
            os << "typedef struct {\n";
            for (const auto &f : lay.fields) {
                os << "    " << c_decl(f.type, f.name, /*as_field=*/true)
                   << ";\n";
            }
            os << "} " << name << ";\n\n";
        }
    }

    // --- 2. Prototipos de funciones con firma C-representable ---
    std::ostringstream protos;
    int skipped = 0;
    for (const auto &decl : mod.decls) {
        if (!decl || decl->kind != ast::NodeKind::FunctionDecl) continue;
        const auto *fd = static_cast<const ast::FunctionDecl *>(decl.get());
        // Saltar: entry point, comptime/macro, async, no-publicas.
        if (fd->name == "main" || fd->is_comptime || fd->is_macro ||
            fd->is_async || !fd->is_public)
            continue;
        const FunctionSig *sig = tc.function_sig_by_name(fd->name);
        if (!sig || !sig->extern_lib.empty()) continue; // extern = import
        // Toda la firma debe ser C-representable.
        bool c_ok = tc.type_is_c_representable(sig->return_type);
        for (const auto &pt : sig->param_types)
            c_ok = c_ok && tc.type_is_c_representable(pt);
        if (sig->is_variadic) c_ok = false; // variadicos Vesta != C (v1)
        if (!c_ok) {
            ++skipped;
            continue;
        }
        // Retorno: struct -> puntero; escalar/ptr -> tipo C; void -> void.
        std::string ret;
        if (sig->return_type.kind == PrimitiveKind::STRUCT)
            ret = sig->return_type.struct_name + "*";
        else
            ret = c_base_type(sig->return_type);
        protos << ret << " " << fd->name << "(";
        if (sig->param_types.empty()) {
            protos << "void";
        } else {
            for (size_t i = 0; i < sig->param_types.size(); ++i) {
                if (i) protos << ", ";
                // Nombre del parametro desde el AST (si esta disponible).
                std::string pname =
                    (i < fd->params.size()) ? fd->params[i]->name : "";
                protos << c_decl(sig->param_types[i], pname,
                                 /*as_field=*/false);
            }
        }
        protos << ");\n";
    }
    const std::string protos_s = protos.str();
    if (!protos_s.empty()) {
        os << "/* Funciones. */\n" << protos_s << "\n";
    }
    if (skipped > 0) {
        os << "/* (" << skipped
           << " funcion(es) con tipos gestionados en la firma omitidas: son\n"
           << " * internas, no cruzan la frontera C por valor.) */\n\n";
    }

    // Postlude estatico desde stdlib/port/c (cierre de extern "C").
    bool post_ok = false;
    const std::string postlude =
        port::load_snippet_text("vx_header_postlude", "", post_ok);
    if (post_ok) {
        os << postlude << "\n";
    } else {
        os << "#ifdef __cplusplus\n}\n#endif\n\n";
    }
    os << "#endif /* " << guard << " */\n";
    return os.str();
}

} // namespace vx
