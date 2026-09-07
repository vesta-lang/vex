/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file c_backend.cpp
 * @brief Backend C del transpiler.  Genera codigo C99/C11 portable y compacto.
 *
 * = Estrategia de generacion =
 *
 * El backend se apoya en TRES tecnicas para producir C de calidad humana:
 *
 *   1. **Single-use inlining**: cualquier SSA value con @c use_count == 1 y
 *      definicion pura (CONST, ADD, CMP, CAST, ...) NO se declara como
 *      variable.  Su expresion se construye en el sitio del uso via
 *      @c value_expr recursivo.  Ejemplo:
 *        IR:  v1 = const 1; v2 = v0 - v1; v3 = factorial(v2);
 *        out: v3 = factorial(v0 - 1);
 *
 *   2. **PHI parallel-move via lookup**: las copias PHI emiten al evaluar
 *      la expresion (no la variable intermedia), permitiendo que el
 *      "incremento de loop" se exprese inline en la propia copy:
 *        bb_body: v3 = v_acc + v_i;
 *                 v_acc = v3;  // phi copy
 *      se vuelve:
 *        bb_body: v_acc = v_acc + v_i;
 *
 *   3. **Skip de labels y gotos triviales**: bloques sin predecesores
 *      (entry) no llevan label.  BR a bloque inmediatamente siguiente se
 *      omite (fall-through natural).
 *
 * = Por que stdint.h =
 *
 * Cada SSA value lleva su tipo concreto (int8_t/int16_t/int32_t/...).
 * GCC -O3 usa la informacion para regalloc + vectorizar.  Sin tipo concreto,
 * el compilador trata todo como int/long y pierde oportunidades SIMD.
 *
 * = Comprobacion del binario =
 *
 * Output verificado con:
 *   - @c gcc -O3 -std=c11 -Wall -Wextra -Wpedantic produce 0 errores.
 *   - El asm generado es identico a C hecho a mano (4 instrucciones por iter
 *     en hot loops; ver tests/port_c/).
 */

#include "port/c/c_backend.h"
#include "util/fs_utils.h" // fs::get_executable_path()

#include <cctype>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <unordered_set>

namespace port {

// =========================================================================
//  Mapeo de tipos
// =========================================================================

std::string CBackend::type_for(ir::IrType t, bool is_host_ptr) const {
    if (opts_.types == TypeStyle::Builtin) {
        switch (t) {
        case ir::IrType::VOID: return "void";
        case ir::IrType::I8: return "signed char";
        case ir::IrType::I16: return "short";
        case ir::IrType::I32: return "int";
        case ir::IrType::I64: return "long long";
        case ir::IrType::U8: return "unsigned char";
        case ir::IrType::U16: return "unsigned short";
        case ir::IrType::U32: return "unsigned int";
        case ir::IrType::U64: return "unsigned long long";
        case ir::IrType::F32: return "float";
        case ir::IrType::F64: return "double";
        case ir::IrType::PTR: return is_host_ptr ? "void*" : "uintptr_t";
        case ir::IrType::HANDLE: return "unsigned int";
        case ir::IrType::BOOL: return "_Bool";
        }
    }
    switch (t) {
    case ir::IrType::VOID: return "void";
    case ir::IrType::I8: return "int8_t";
    case ir::IrType::I16: return "int16_t";
    case ir::IrType::I32: return "int32_t";
    case ir::IrType::I64: return "int64_t";
    case ir::IrType::U8: return "uint8_t";
    case ir::IrType::U16: return "uint16_t";
    case ir::IrType::U32: return "uint32_t";
    case ir::IrType::U64: return "uint64_t";
    case ir::IrType::F32: return "float";
    case ir::IrType::F64: return "double";
    case ir::IrType::PTR: return "void*";
    case ir::IrType::HANDLE: return "uint32_t";
    case ir::IrType::BOOL: return "_Bool";
    }
    return "int64_t";
}

std::string CBackend::cast_for(ir::IrType t, bool is_host_ptr) const {
    return "(" + type_for(t, is_host_ptr) + ")";
}

// =========================================================================
//  Sanitizacion de nombres
// =========================================================================

std::string CBackend::sanitize_name(const std::string &n) const {
    std::string out;
    out.reserve(n.size() + 8);
    if (n.empty() || std::isdigit(static_cast<unsigned char>(n[0]))) {
        out = "vx_";
    }
    for (char c : n) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            out += c;
        } else {
            out += '_';
        }
    }
    if (out == "main") return "vx_main";
    return out;
}

// =========================================================================
//  Formateo de constantes
// =========================================================================

std::string CBackend::format_const_literal(uint64_t imm, ir::IrType t) const {
    std::ostringstream oss;
    switch (t) {
    case ir::IrType::F64: {
        double d;
        std::memcpy(&d, &imm, 8);
        oss << "(double)" << d;
        return oss.str();
    }
    case ir::IrType::F32: {
        uint32_t bits = static_cast<uint32_t>(imm);
        float f;
        std::memcpy(&f, &bits, 4);
        oss << "(float)" << f << "f";
        return oss.str();
    }
    case ir::IrType::I8:
    case ir::IrType::I16:
    case ir::IrType::I32:
    case ir::IrType::I64: {
        int64_t s = static_cast<int64_t>(imm);
        // Optimizacion: si el valor cabe en int (32 bits con signo),
        // no le ponemos sufijo @c LL ni cast -- C lo promociona
        // automaticamente.  Resultado mas legible.
        if (s >= -0x80000000LL && s <= 0x7FFFFFFFLL && t == ir::IrType::I32) {
            oss << s;
        } else {
            oss << "(" << type_for(t, false) << ")" << s << "LL";
        }
        return oss.str();
    }
    case ir::IrType::U8:
    case ir::IrType::U16:
    case ir::IrType::U32:
    case ir::IrType::U64:
    case ir::IrType::HANDLE: {
        if (imm <= 0xFFFFFFFFu && t == ir::IrType::U32) {
            oss << imm << "u";
        } else {
            oss << "(" << type_for(t, false) << ")" << imm << "ULL";
        }
        return oss.str();
    }
    case ir::IrType::PTR:
        oss << "(void*)(uintptr_t)" << imm << "ULL";
        return oss.str();
    case ir::IrType::BOOL: return (imm != 0 ? "1" : "0");
    default: oss << imm << "ULL"; return oss.str();
    }
}

// =========================================================================
//  Inlining de expresiones (nivel A)
// =========================================================================

/**
 * @brief Sufijo binario C para un IrOp.
 */
static const char *binop_symbol_for(ir::IrOp op) {
    switch (op) {
    case ir::IrOp::ADD:
    case ir::IrOp::FADD: return "+";
    case ir::IrOp::SUB:
    case ir::IrOp::FSUB: return "-";
    case ir::IrOp::MUL:
    case ir::IrOp::FMUL: return "*";
    case ir::IrOp::DIV:
    case ir::IrOp::FDIV: return "/";
    case ir::IrOp::MOD: return "%";
    case ir::IrOp::AND: return "&";
    case ir::IrOp::OR: return "|";
    case ir::IrOp::XOR: return "^";
    case ir::IrOp::SHL: return "<<";
    default: return "?";
    }
}

static const char *cmp_symbol_for(ir::IrOp op, bool &is_unsigned) {
    is_unsigned = false;
    switch (op) {
    case ir::IrOp::CMP_EQ:
    case ir::IrOp::FCMP_EQ: return "==";
    case ir::IrOp::CMP_NE:
    case ir::IrOp::FCMP_NE: return "!=";
    case ir::IrOp::CMP_LT:
    case ir::IrOp::FCMP_LT: return "<";
    case ir::IrOp::CMP_GT:
    case ir::IrOp::FCMP_GT: return ">";
    case ir::IrOp::CMP_LE:
    case ir::IrOp::FCMP_LE: return "<=";
    case ir::IrOp::CMP_GE:
    case ir::IrOp::FCMP_GE: return ">=";
    case ir::IrOp::CMP_ULT: is_unsigned = true; return "<";
    case ir::IrOp::CMP_UGT: is_unsigned = true; return ">";
    case ir::IrOp::CMP_ULE: is_unsigned = true; return "<=";
    case ir::IrOp::CMP_UGE: is_unsigned = true; return ">=";
    default: return "==";
    }
}

std::string CBackend::value_expr(EmitContext &ctx, ir::IrValueId v) const {
    if (v == ir::IR_NO_VALUE) return "/*nil*/0";
    if (!ctx.tx || !ctx.tx->is_inline_candidate(v)) {
        return "v" + std::to_string(v);
    }
    const ir::IrInstr *def = ctx.tx->def_of(v);
    if (!def) return "v" + std::to_string(v);
    return build_inline_expr(ctx, *def);
}

std::string CBackend::build_inline_expr(EmitContext &ctx,
                                        const ir::IrInstr &ins) const {
    using ir::IrOp;
    switch (ins.op) {
    case IrOp::CONST: return format_const_literal(ins.imm, ins.type);

    // Un prestamo ES su puntero: se traduce a la misma expresion.
    case IrOp::BORROW:
    case IrOp::MOV: return value_expr(ctx, ins.operands[0]);

    case IrOp::ADD:
    case IrOp::SUB: {
        // Aritmetica de PTR en el IR es POR BYTES.  En C, el
        // operador @c "ptr + int" hace aritmetica por sizeof(elem),
        // lo cual es INCORRECTO cuando el ptr esta tipado como
        // @c Counter* y queremos sumar bytes.  Cast a @c char* para
        // forzar byte arithmetic; cast final a @c void* para
        // compatibilidad con el load/store siguiente.
        std::string lhs = value_expr(ctx, ins.operands[0]);
        std::string rhs = value_expr(ctx, ins.operands[1]);
        if (ins.type == ir::IrType::PTR) {
            const char *sym = (ins.op == ir::IrOp::ADD) ? "+" : "-";
            return "(void*)((char*)" + lhs + " " + sym + " " + rhs + ")";
        }
        return "(" + lhs + " " + binop_symbol_for(ins.op) + " " + rhs + ")";
    }
    case IrOp::MUL:
    case IrOp::AND:
    case IrOp::OR:
    case IrOp::XOR:
    case IrOp::SHL:
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV: {
        std::string lhs = value_expr(ctx, ins.operands[0]);
        std::string rhs = value_expr(ctx, ins.operands[1]);
        return "(" + lhs + " " + binop_symbol_for(ins.op) + " " + rhs + ")";
    }

    case IrOp::FMA: {
        // round(a*b+c) con UN redondeo -> fma()/fmaf() de C99 (mismo std::fma
        // que el interp).  Consistente con los demas backends.
        std::string a = value_expr(ctx, ins.operands[0]);
        std::string b = value_expr(ctx, ins.operands[1]);
        std::string c = value_expr(ctx, ins.operands[2]);
        const char *fn = (ins.type == ir::IrType::F32) ? "fmaf" : "fma";
        return std::string(fn) + "(" + a + ", " + b + ", " + c + ")";
    }

    case IrOp::SHR: {
        // logical shift -> cast a unsigned
        std::string utype;
        switch (ins.type) {
        case ir::IrType::I8: utype = "uint8_t"; break;
        case ir::IrType::I16: utype = "uint16_t"; break;
        case ir::IrType::I32: utype = "uint32_t"; break;
        case ir::IrType::I64: utype = "uint64_t"; break;
        default: utype = type_for(ins.type, false); break;
        }
        std::string lhs = value_expr(ctx, ins.operands[0]);
        std::string rhs = value_expr(ctx, ins.operands[1]);
        return "((" + type_for(ins.type, false) + ")((" + utype + ")" + lhs +
               " >> " + rhs + "))";
    }
    case IrOp::SAR: {
        std::string stype;
        switch (ins.type) {
        case ir::IrType::U8: stype = "int8_t"; break;
        case ir::IrType::U16: stype = "int16_t"; break;
        case ir::IrType::U32: stype = "int32_t"; break;
        case ir::IrType::U64: stype = "int64_t"; break;
        default: stype = type_for(ins.type, false); break;
        }
        std::string lhs = value_expr(ctx, ins.operands[0]);
        std::string rhs = value_expr(ctx, ins.operands[1]);
        return "((" + type_for(ins.type, false) + ")((" + stype + ")" + lhs +
               " >> " + rhs + "))";
    }

    case IrOp::FMIN:
    case IrOp::FMAX: {
        const char *cmp = (ins.op == IrOp::FMIN) ? "<" : ">";
        std::string lhs = value_expr(ctx, ins.operands[0]);
        std::string rhs = value_expr(ctx, ins.operands[1]);
        return "(" + lhs + " " + cmp + " " + rhs + " ? " + lhs + " : " + rhs +
               ")";
    }

    case IrOp::NEG:
    case IrOp::FNEG: return "(-" + value_expr(ctx, ins.operands[0]) + ")";

    case IrOp::NOT: return "(~" + value_expr(ctx, ins.operands[0]) + ")";

    case IrOp::FABS: {
        std::string e = value_expr(ctx, ins.operands[0]);
        if (ins.type == ir::IrType::F32) {
            return "((float)__builtin_fabsf(" + e + "))";
        }
        return "((double)__builtin_fabs(" + e + "))";
    }
    case IrOp::FSQRT: {
        std::string e = value_expr(ctx, ins.operands[0]);
        if (ins.type == ir::IrType::F32) {
            return "((float)__builtin_sqrtf(" + e + "))";
        }
        return "((double)__builtin_sqrt(" + e + "))";
    }

    case IrOp::CMP_EQ:
    case IrOp::CMP_NE:
    case IrOp::CMP_LT:
    case IrOp::CMP_GT:
    case IrOp::CMP_LE:
    case IrOp::CMP_GE:
    case IrOp::CMP_ULT:
    case IrOp::CMP_UGT:
    case IrOp::CMP_ULE:
    case IrOp::CMP_UGE:
    case IrOp::FCMP_EQ:
    case IrOp::FCMP_NE:
    case IrOp::FCMP_LT:
    case IrOp::FCMP_GT:
    case IrOp::FCMP_LE:
    case IrOp::FCMP_GE: {
        bool is_unsigned = false;
        const char *cmp = cmp_symbol_for(ins.op, is_unsigned);
        std::string lhs = value_expr(ctx, ins.operands[0]);
        std::string rhs = value_expr(ctx, ins.operands[1]);
        if (is_unsigned && ctx.fn) {
            // Determinar tipo de operandos para cast a unsigned.
            ir::IrType ot = ir::IrType::I64;
            if (ins.operands[0] < ctx.fn->values.size()) {
                ot = ctx.fn->values[ins.operands[0]].type;
            }
            std::string utype;
            switch (ot) {
            case ir::IrType::I8: utype = "uint8_t"; break;
            case ir::IrType::I16: utype = "uint16_t"; break;
            case ir::IrType::I32: utype = "uint32_t"; break;
            case ir::IrType::I64: utype = "uint64_t"; break;
            default: utype = type_for(ot, false); break;
            }
            return "((" + utype + ")" + lhs + " " + cmp + " (" + utype + ")" +
                   rhs + ")";
        }
        return "(" + lhs + " " + cmp + " " + rhs + ")";
    }

    case IrOp::CAST:
    case IrOp::TRUNC:
    case IrOp::ITOF:
    case IrOp::UITOF:
    case IrOp::FTOI:
    case IrOp::FTOUI:
    case IrOp::F32TOF64:
    case IrOp::F64TOF32: {
        return cast_for(ins.type, false) + value_expr(ctx, ins.operands[0]);
    }

    case IrOp::ZEXT: {
        if (ctx.fn && ins.operands[0] < ctx.fn->values.size()) {
            ir::IrType st = ctx.fn->values[ins.operands[0]].type;
            std::string utype;
            switch (st) {
            case ir::IrType::I8: utype = "uint8_t"; break;
            case ir::IrType::I16: utype = "uint16_t"; break;
            case ir::IrType::I32: utype = "uint32_t"; break;
            case ir::IrType::I64: utype = "uint64_t"; break;
            default: utype = type_for(st, false); break;
            }
            return cast_for(ins.type, false) + "(" + utype + ")" +
                   value_expr(ctx, ins.operands[0]);
        }
        return cast_for(ins.type, false) + value_expr(ctx, ins.operands[0]);
    }
    case IrOp::SEXT: {
        if (ctx.fn && ins.operands[0] < ctx.fn->values.size()) {
            ir::IrType st = ctx.fn->values[ins.operands[0]].type;
            std::string stype;
            switch (st) {
            case ir::IrType::U8: stype = "int8_t"; break;
            case ir::IrType::U16: stype = "int16_t"; break;
            case ir::IrType::U32: stype = "int32_t"; break;
            case ir::IrType::U64: stype = "int64_t"; break;
            default: stype = type_for(st, false); break;
            }
            return cast_for(ins.type, false) + "(" + stype + ")" +
                   value_expr(ctx, ins.operands[0]);
        }
        return cast_for(ins.type, false) + value_expr(ctx, ins.operands[0]);
    }

    case IrOp::BITCAST: {
        ir::IrType st = ir::IrType::I64;
        if (ctx.fn && ins.operands[0] < ctx.fn->values.size()) {
            st = ctx.fn->values[ins.operands[0]].type;
        }
        // Preferir el tipo del SSA value destino al de la instr.
        // Fallback al tipo source si destino tambien queda VOID
        // (caso comun en bitcasts identity sin tipo explicito).
        ir::IrType dt = ins.type;
        if (dt == ir::IrType::VOID && ctx.fn &&
            ins.dst < ctx.fn->values.size()) {
            dt = ctx.fn->values[ins.dst].type;
        }
        if (dt == ir::IrType::VOID) dt = st; /* identity */
        bool src_is_int = (st != ir::IrType::F32 && st != ir::IrType::F64);
        bool dst_is_int = (dt != ir::IrType::F32 && dt != ir::IrType::F64);
        std::string e = value_expr(ctx, ins.operands[0]);
        if (src_is_int && dst_is_int) {
            return cast_for(dt, false) + e;
        }
        // Cross-domain bitcast: usar gcc statement expr.
        return "({ " + type_for(dt, false) + " __tmp; " +
               "__builtin_memcpy(&__tmp, &(" + e +
               "), sizeof(__tmp)); __tmp; })";
    }

    default: return "v" + std::to_string(ins.dst); // fallback
    }
}

// =========================================================================
//  Prelude / postamble
// =========================================================================

// =========================================================================
//  Soporte POO (clases, herencia, devirt)
// =========================================================================

const ir::IrClass *CBackend::lookup_class(const std::string &name) const {
    auto it = class_by_name_.find(name);
    return it == class_by_name_.end() ? nullptr : it->second;
}

std::string CBackend::field_name_at_offset(const ir::IrClass &cls,
                                           uint32_t offset,
                                           ir::IrType type) const {
    // Lookup lineal por offset.  Como las clases tipicas tienen pocos
    // campos (<10), O(N) es perfecto.  Si hay mas, podemos cachear un
    // mapa (offset, type) -> name.  El tipo se valida tambien para
    // evitar matches falsos en bit fields o casos raros.
    for (const auto &f : cls.fields) {
        if (f.offset == offset && f.type == type) {
            return f.name;
        }
        // Heurica: si el tipo coincide en tamano (e.g. todos i32/u32 son
        // 4 bytes pero distintos signos), aceptarlo igualmente.  GCC
        // emitira el cast correcto en el use site.
        if (f.offset == offset && f.size_bytes > 0) {
            return f.name;
        }
    }
    return "";
}

void CBackend::analyze_escapes(const ir::IrFunction &fn) {
    stack_alloc_candidates_.clear();

    // Identificar candidates: SSA values producidos por @c CALL a
    // @c __new_<X> donde X esta en class_by_name_.
    std::vector<ir::IrValueId> candidates;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.op != ir::IrOp::CALL) continue;
            if (ins.dst == ir::IR_NO_VALUE) continue;
            if (ins.func_name.rfind("__new_", 0) != 0) continue;
            std::string cls_name = ins.func_name.substr(6);
            if (lookup_class(cls_name)) {
                candidates.push_back(ins.dst);
            }
        }
    }
    if (candidates.empty()) return;

    // Para cada candidate, walk de usos y comprobar si escapa.
    // Conservativo: si CUALQUIER uso "raro" (RET / STORE como valor /
    // arg distinto del primero), NO stack-alloc.
    std::unordered_set<ir::IrValueId> cand_set(candidates.begin(),
                                               candidates.end());

    // Walk usos.
    std::unordered_set<ir::IrValueId> escaped;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            using ir::IrOp;
            switch (ins.op) {
            case IrOp::RET:
                // Si el value retornado es candidate, escapa.
                if (!ins.operands.empty() && cand_set.count(ins.operands[0])) {
                    escaped.insert(ins.operands[0]);
                }
                break;
            case IrOp::STORE:
                // operands[0] = val (escapa si candidate), operands[1] = addr.
                if (ins.operands.size() >= 1 &&
                    cand_set.count(ins.operands[0])) {
                    escaped.insert(ins.operands[0]);
                }
                break;
            case IrOp::CALL:
            case IrOp::CALLVIRT:
            case IrOp::CALLM:
            case IrOp::CALLN: {
                // Permitido: candidate como PRIMER operando (this) en
                // CALLVIRT/CALLM, o como arg en CALL a Class__ctor/dtor.
                // No permitido: candidate como arg posterior (asume
                // que la funcion puede guardarlo).
                // Conservativo: si aparece en operands[1..], escapa.
                // EXCEPCION: CALL a Class__ctor (es nuestro propio
                // helper que no escapa this).
                for (size_t i = 1; i < ins.operands.size(); ++i) {
                    if (cand_set.count(ins.operands[i])) {
                        escaped.insert(ins.operands[i]);
                    }
                }
                // operands[0] (el this o el func ptr) -- skip OK.
                break;
            }
            case IrOp::PHI:
                // Si el dst de un PHI recibe un candidate, el flow
                // es ambiguo -> conservativo: escapa.
                for (const auto &arg : ins.phi_args) {
                    if (cand_set.count(arg.value)) {
                        escaped.insert(arg.value);
                    }
                }
                break;
            case IrOp::BORROW:
            case IrOp::MOV:
                // MOV y el prestamo son alias; el dst hereda.  Si dst
                // aparece despues en un escape, lo perdimos ->
                // conservativo: escapa.
                if (!ins.operands.empty() && cand_set.count(ins.operands[0])) {
                    escaped.insert(ins.operands[0]);
                }
                break;
            default: break;
            }
        }
    }

    for (auto v : candidates) {
        if (!escaped.count(v)) stack_alloc_candidates_.insert(v);
    }
}

void CBackend::infer_concrete_types(const ir::IrFunction &fn) {
    concrete_type_.clear();

    // 1. Si la funcion es metodo (nombre @c "<Class>__<method>"),
    //    marcar el primer parametro (@c this) con tipo @c Class.
    const std::string &fn_name = fn.name;
    auto sep = fn_name.find("__");
    if (sep != std::string::npos && !fn.params.empty()) {
        std::string class_name = fn_name.substr(0, sep);
        if (lookup_class(class_name)) {
            concrete_type_[fn.params[0]] = class_name;
        }
    }

    // 2. Propagation iterativa: hasta punto fijo (raro mas de 2 pasadas).
    bool changed = true;
    size_t iter = 0;
    while (changed && iter < 4) {
        changed = false;
        iter++;
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.dst == ir::IR_NO_VALUE) continue;

                std::string new_type;

                if (ins.op == ir::IrOp::CALL && !ins.func_name.empty()) {
                    // Si la funcion es @c __new_<X>, el resultado es X*.
                    if (ins.func_name.rfind("__new_", 0) == 0) {
                        new_type = ins.func_name.substr(6);
                    } else {
                        // Si la funcion es @c <Class>__<method> y el
                        // return type es PTR, no podemos inferir con
                        // certeza sin firma.  Skip por ahora.
                    }
                } else if (ins.op == ir::IrOp::MOV ||
                           ins.op == ir::IrOp::BORROW) {
                    // MOV y el prestamo propagan el tipo.
                    if (!ins.operands.empty()) {
                        auto it = concrete_type_.find(ins.operands[0]);
                        if (it != concrete_type_.end()) new_type = it->second;
                    }
                } else if (ins.op == ir::IrOp::PHI) {
                    // PHI: si TODOS los args tienen el mismo tipo concreto,
                    // propagar; si no, vacio.
                    bool all_same = !ins.phi_args.empty();
                    std::string first_t;
                    for (const auto &arg : ins.phi_args) {
                        auto it = concrete_type_.find(arg.value);
                        std::string t =
                            (it == concrete_type_.end()) ? "" : it->second;
                        if (first_t.empty()) {
                            first_t = t;
                        } else if (first_t != t) {
                            all_same = false;
                            break;
                        }
                    }
                    if (all_same && !first_t.empty()) new_type = first_t;
                } else if (ins.op == ir::IrOp::NEWOBJ) {
                    // NEWOBJ: el operando[0] es un class_ptr; sin info
                    // estatica no podemos resolver el nombre aqui.  Vesta
                    // emite NEWOBJ desde __new_<X> que es donde lo
                    // detectamos via la rama CALL.
                }
                // BITCAST y otras conversiones a PTR no preservan tipo
                // concreto -- el usuario expreso un cast.

                if (!new_type.empty()) {
                    auto it = concrete_type_.find(ins.dst);
                    if (it == concrete_type_.end() || it->second != new_type) {
                        concrete_type_[ins.dst] = new_type;
                        changed = true;
                    }
                }
            }
        }
    }
}

void CBackend::emit_class_decls(EmitContext &ctx, const ir::IrModule &mod) {
    if (mod.classes.empty()) return;

    // 1. Indexar clases por nombre para lookup O(1).  Llenamos
    //    class_by_name_ aqui porque infer_concrete_types lo necesita.
    class_by_name_.clear();
    for (const auto &cls : mod.classes) {
        class_by_name_[cls.name] = &cls;
    }

    // 2. Topological sort: emit super-clases antes que sub-clases.
    //    Algoritmo: Kahn's (BFS sobre dependencias).
    std::vector<std::string> emit_order;
    std::unordered_set<std::string> emitted;
    std::function<void(const std::string &)> emit_recur =
        [&](const std::string &name) {
            if (emitted.count(name)) return;
            const ir::IrClass *cls = lookup_class(name);
            if (!cls) {
                emitted.insert(name);
                return;
            }
            if (!cls->super_name.empty() && cls->super_name != "Object") {
                emit_recur(cls->super_name);
            }
            emitted.insert(name);
            emit_order.push_back(name);
        };
    for (const auto &cls : mod.classes) {
        emit_recur(cls.name);
    }

    // 3. Forward typedef de todas las clases (permite punteros cruzados).
    if (opts_.emit_comments) {
        ctx.out << "/* Forward declarations de clases */\n";
    }
    for (const auto &name : emit_order) {
        const ir::IrClass *cls = lookup_class(name);
        if (!cls || cls->is_interface) continue;
        ctx.out << "typedef struct " << name << " " << name << ";\n";
    }
    ctx.out << "\n";

    // 4. Definiciones de struct (en orden topologico).
    if (opts_.emit_comments) {
        ctx.out << "/* Definiciones de struct */\n";
    }
    for (const auto &name : emit_order) {
        const ir::IrClass *cls = lookup_class(name);
        if (!cls || cls->is_interface) continue;

        ctx.out << "struct " << name << " {\n";
        // Herencia: el campo @c __base es el struct de la super
        // (struct embedding C-style).  Permite acceso transparente
        // a fields heredados via @c obj->__base.parent_field.
        if (!cls->super_name.empty() && cls->super_name != "Object" &&
            lookup_class(cls->super_name)) {
            ctx.out << "    " << cls->super_name << " __base;\n";
        }
        // Fields propios (skip los heredados que ya estan en __base).
        // ClassLayout incluye los heredados en lay.fields; el offset es
        // continuo (heredados primero, propios al final).  Heredados:
        // los primeros @c inherited_field_count.  Como IrClass no
        // expone inherited_field_count, los detectamos por offset:
        // si super.size_bytes > 0 y field.offset < super.size_bytes,
        // es heredado.  Skip en ese caso.
        const ir::IrClass *super =
            (cls->super_name.empty() || cls->super_name == "Object")
                ? nullptr
                : lookup_class(cls->super_name);
        const uint32_t inherited_bound = super ? super->size_bytes : 0;

        size_t emitted_fields = 0;
        for (const auto &f : cls->fields) {
            if (f.offset < inherited_bound) continue; // heredado, en __base
            ctx.out << "    " << type_for(f.type, false) << " " << f.name
                    << ";\n";
            ++emitted_fields;
        }
        // Si la clase es empty (sin fields propios ni heredados), emit
        // un placeholder para que el struct sea valido en C99.  GCC con
        // -pedantic rechaza empty structs.
        if (emitted_fields == 0 && inherited_bound == 0) {
            ctx.out << "    char __reserved;\n";
        }
        ctx.out << "};\n\n";
    }

    // 5. Forward decls de metodos (incluyendo Class__new y Class__delete).
    if (opts_.emit_comments) {
        ctx.out << "/* Forward decls de metodos */\n";
    }
    for (const auto &name : emit_order) {
        const ir::IrClass *cls = lookup_class(name);
        if (!cls || cls->is_interface) continue;
        // Buscar el ctor para extraer su firma -- la forward decl de
        // @c Class__new debe coincidir con la definicion emitida en
        // @c emit_class_bodies.
        const ir::IrMethod *ctor = nullptr;
        for (const auto &m : cls->methods) {
            if (m.is_constructor) {
                ctor = &m;
                break;
            }
        }
        ctx.out << "static " << name << " *" << name << "__new(";
        if (ctor && !ctor->param_types.empty()) {
            for (size_t i = 0; i < ctor->param_types.size(); ++i) {
                if (i) ctx.out << ", ";
                ctx.out << type_for(ctor->param_types[i], false);
            }
        } else {
            ctx.out << "void";
        }
        ctx.out << ");\n";
        ctx.out << "static void " << name << "__delete(" << name
                << " *self);\n";
        for (const auto &m : cls->methods) {
            if (m.is_static) continue;
            // Solo emitir si el metodo esta DEFINIDO en esta clase.
            // (Metodos heredados sin override apuntan a la implementacion
            // de la super; no se redefinen aqui.)
            if (!m.defining_class.empty() && m.defining_class != cls->name) {
                continue;
            }
            ctx.out << "static " << type_for(m.return_type, false) << " "
                    << cls->name << "__" << (m.is_constructor ? "ctor" : m.name)
                    << "(" << cls->name << " *self";
            for (size_t pi = 0; pi < m.param_types.size(); ++pi) {
                ctx.out << ", " << type_for(m.param_types[pi], false) << " p"
                        << pi;
            }
            ctx.out << ");\n";
        }
    }
    ctx.out << "\n";
}

void CBackend::emit_class_bodies(EmitContext &ctx, const ir::IrModule &mod) {
    if (mod.classes.empty()) return;

    // Emite @c Class__new(args) (calloc + ctor) y @c Class__delete(self) (dtor
    // + free).
    for (const auto &cls : mod.classes) {
        if (cls.is_interface) continue;

        // Localizar el constructor para extraer su firma.
        const ir::IrMethod *ctor = nullptr;
        for (const auto &m : cls.methods) {
            if (m.is_constructor) {
                ctor = &m;
                break;
            }
        }

        // @c Class__new(args...) : calloc + Class__ctor(self, args...).
        //  calloc da zero-init de un golpe (mas eficiente que malloc+memset).
        //  Si la clase tiene multiples ctors, solo el primero se invoca
        //  desde new -- el frontend Vesta elige cual via overload resolution.
        ctx.out << "static VX_UNUSED " << cls.name << " *" << cls.name
                << "__new(";
        if (ctor && !ctor->param_types.empty()) {
            for (size_t i = 0; i < ctor->param_types.size(); ++i) {
                if (i) ctx.out << ", ";
                ctx.out << type_for(ctor->param_types[i], false) << " p" << i;
            }
        } else {
            ctx.out << "void";
        }
        ctx.out << ") {\n";
        ctx.out << "    " << cls.name << " *o = (" << cls.name
                << "*)calloc(1, sizeof(" << cls.name << "));\n";
        ctx.out << "    if (!o) return (" << cls.name << "*)0;\n";
        // Invocar el constructor del usuario (si existe).
        if (ctor) {
            ctx.out << "    " << cls.name << "__ctor(o";
            for (size_t i = 0; i < ctor->param_types.size(); ++i) {
                ctx.out << ", p" << i;
            }
            ctx.out << ");\n";
        }
        ctx.out << "    return o;\n";
        ctx.out << "}\n\n";

        // @c Class__delete(self) : dtor (si existe) + free.
        ctx.out << "static VX_UNUSED void " << cls.name << "__delete("
                << cls.name << " *self) {\n";
        ctx.out << "    if (!self) return;\n";
        if (cls.has_destructor) {
            ctx.out << "    " << cls.name << "____dtor(self);\n";
        }
        ctx.out << "    free(self);\n";
        ctx.out << "}\n\n";
    }
}

// =========================================================================
//  Snippet loader (stdlib/port/c/<name>.v.c)
// =========================================================================

std::string CBackend::resolve_stdlib_dir() const {
    // Si el usuario especifico un dir explicito, usarlo tal cual.
    if (!opts_.stdlib_port_c_dir.empty()) return opts_.stdlib_port_c_dir;
    // Autodetect: probar varios paths comunes desde cwd.  El executable
    // path no es trivial de obtener cross-platform sin extra deps; los
    // proyectos Vesta normalmente ejecutan desde el root del repo.
    static const char *candidates[] = {
        "stdlib/port/c",
        "../stdlib/port/c",
        "../../stdlib/port/c",
    };
    for (const char *c : candidates) {
        std::string path = std::string(c) + "/vx_macros.v.c";
        std::ifstream test(path.c_str());
        if (test.good()) {
            return std::string(c);
        }
    }
    // Fallback relativo al EJECUTABLE (instalacion: vesta.exe junto a
    // stdlib/port/c/; build-tree: vm.exe en cmake-build-X/).  Hace que el
    // backend C funcione desde cualquier directorio de trabajo.
    {
        std::string exe = fs::get_executable_path();
        if (!exe.empty()) {
            std::filesystem::path ed = std::filesystem::path(exe).parent_path();
            const std::filesystem::path exe_cands[] = {
                ed / "stdlib" / "port" / "c",
                ed.parent_path() / "stdlib" / "port" / "c"};
            for (const auto &c : exe_cands) {
                std::ifstream test((c / "vx_macros.v.c").string());
                if (test.good()) return c.string();
            }
        }
    }
    return "stdlib/port/c"; // fallback razonable
}

bool CBackend::emit_snippet(EmitContext &ctx, const std::string &name) {
    std::string dir = resolve_stdlib_dir();
    std::string path = dir + "/" + name + ".v.c";
    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in.is_open()) {
        ctx.out << "/* ERROR: snippet " << name << " no encontrado en " << path
                << " -- ejecuta desde el root del proyecto o usa "
                << "--port-stdlib-dir=PATH */\n";
        fprintf(stderr, "[port C] snippet '%s' no encontrado en '%s'\n",
                name.c_str(), path.c_str());
        return false;
    }

    // Parsear cabecera @c "// @vx-freestanding-skip: yes" para decidir
    // si omitir en modo freestanding.  La cabecera esta en las primeras
    // ~10 lineas.
    std::string line;
    bool freestanding_skip = false;
    std::ostringstream content;
    int header_lines = 0;
    bool in_header = true;
    while (std::getline(in, line)) {
        if (in_header && line.size() > 3 && line[0] == '/' && line[1] == '/' &&
            line[2] == ' ' && line[3] == '@') {
            // Cabecera de metadata.  Parse "@vx-freestanding-skip:".
            auto pos = line.find("@vx-freestanding-skip:");
            if (pos != std::string::npos) {
                auto val = line.substr(pos + 23);
                while (!val.empty() && (val[0] == ' ' || val[0] == '\t')) {
                    val.erase(0, 1);
                }
                if (val.substr(0, 3) == "yes") freestanding_skip = true;
            }
            header_lines++;
            continue;
        }
        // Primera linea no-header: salimos del modo header.
        in_header = false;
        content << line << "\n";
    }

    if (opts_.freestanding && freestanding_skip) {
        ctx.out << "/* snippet '" << name
                << "' omitido en --port-freestanding */\n";
        return true;
    }

    ctx.out << "/* === BEGIN snippet: " << name << " === */\n";
    ctx.out << content.str();
    ctx.out << "/* === END snippet: " << name << " === */\n\n";
    return true;
}

// =========================================================================
//  Static data + string runtime
// =========================================================================

/**
 * @brief Detecta si el modulo usa instrumentacion (vx_trace:*).
 */
static bool module_uses_instrument(const ir::IrModule &mod) {
    for (const auto &fn : mod.functions) {
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op != ir::IrOp::CALLN) continue;
                if (ins.func_name.find("vx_trace:enter") != std::string::npos ||
                    ins.func_name.find("vx_trace:leave") != std::string::npos)
                    return true;
            }
        }
    }
    return false;
}

/**
 * @brief Detecta si el modulo usa async (future/await/fulfillhlt/spawn).
 */
static bool module_uses_async(const ir::IrModule &mod) {
    for (const auto &fn : mod.functions) {
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op == ir::IrOp::SPAWN_ARGS) return true;
                if (ins.op != ir::IrOp::RAW_ASM) continue;
                const std::string &t = ins.func_name;
                if (t.find("future\n") != std::string::npos ||
                    t.find("await {src0}") != std::string::npos ||
                    t.find("fulfillhlt {src0}") != std::string::npos) {
                    return true;
                }
            }
        }
    }
    return false;
}

/**
 * @brief Detecta si el modulo usa try/catch (via raw_asm patterns
 * tryenter/panic/tryleave del frontend Vesta).
 */
static bool module_uses_exceptions(const ir::IrModule &mod) {
    for (const auto &fn : mod.functions) {
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op != ir::IrOp::RAW_ASM) continue;
                const std::string &t = ins.func_name;
                if (t == "tryenter {src0}, {src1}\n" || t == "tryleave\n" ||
                    t.find("panic r12") != std::string::npos) {
                    return true;
                }
            }
        }
    }
    return false;
}

/**
 * @brief Detecta si el modulo usa strings (literales o ops).
 */
static bool module_uses_strings(const ir::IrModule &mod) {
    if (!mod.static_data.empty()) return true;
    for (const auto &fn : mod.functions) {
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op == ir::IrOp::STR_LIT_ADDR) return true;
                if (ins.op == ir::IrOp::RAW_ASM &&
                    ins.func_name.rfind("str", 0) == 0)
                    return true;
            }
        }
    }
    return false;
}

void CBackend::emit_static_data(EmitContext &ctx, const ir::IrModule &mod) {
    if (mod.static_data.empty()) return;
    if (opts_.emit_comments) {
        ctx.out << "/* Literales estaticos del modulo (interned por el "
                   "frontend Vesta).\n"
                   " * Layout pool unificado (M.staticdata-pool):\n"
                   " *   - __vx_static_pool[]: todos los bytes contiguos.\n"
                   " *   - __str_<i>: macro que retorna ptr al inicio de la "
                   "entry i.\n"
                   " * Beneficios cache-locality + un solo simbolo expuesto al "
                   "linker.\n"
                   " */\n";
    }
    const size_t N = mod.static_data.size();
    // 1) Pool unico con TODOS los bytes contiguos, alineado a 8.  Si
    //    alguna entry tiene meta.alignment > 8, el pool no garantiza
    //    el alineamiento absoluto del array C (el linker C puede
    //    relocarlo); pero el offset relativo entre entries es estable.
    //    Para alineamientos mayores (AVX2/AVX-512), usar atributos C
    //    `_Alignas` o `__attribute__((aligned(N)))` en el array.
    uint16_t max_align = 8;
    for (size_t i = 0; i < N; ++i) {
        const uint16_t a = mod.static_data.meta_at(i).alignment;
        if (a > max_align) max_align = a;
    }
    ctx.out << "static VX_UNUSED";
    if (max_align > 1) {
        // Atributo C estandar (C11) para alineamiento garantizado.
        ctx.out << " _Alignas(" << max_align << ")";
    }
    ctx.out << " const unsigned char __vx_static_pool[] = {";
    // 2) Emit pool byte por byte, respetando alineamiento de cada entry
    //    via padding NUL intermedio.  Indices [offset] dentro del pool.
    size_t cursor = 0;
    std::vector<size_t> entry_offsets(N);
    for (size_t i = 0; i < N; ++i) {
        auto [bp, bn] = mod.static_data.bytes_at(i);
        const uint16_t a = mod.static_data.meta_at(i).alignment;
        const uint16_t needed = (a > 0) ? a : 1;
        // Padding hasta multiplo de needed.
        while (cursor % needed != 0) {
            ctx.out << (cursor ? ", " : "") << "0";
            cursor++;
        }
        entry_offsets[i] = cursor;
        for (size_t b = 0; b < bn; ++b) {
            ctx.out << ((cursor || b) ? ", " : "")
                    << static_cast<unsigned>(bp[b]);
            cursor++;
        }
        // Sufijo NUL: separa entries Y permite uso como cstr para FFI.
        ctx.out << ", 0";
        cursor++;
    }
    ctx.out << " };\n\n";
    // 3) Macros legibles por entry.  El consumer existente del C
    //    backend referencia `__str_<i>` como puntero a unsigned char.
    //    Generamos un alias macro -> &__vx_static_pool[offset] con
    //    coste cero en runtime (resuelto en compile time del C).
    for (size_t i = 0; i < N; ++i) {
        ctx.out << "#define __str_" << i << " (&__vx_static_pool["
                << entry_offsets[i] << "])\n";
    }
    ctx.out << "\n";
}

void CBackend::emit_string_runtime(EmitContext &ctx) {
    // Runtime VxString embebido inline al inicio del .c.  Cuando el
    // modulo no usa strings, este bloque NO se emite (cero overhead).
    // Tracking de leaks: linked list per-thread + warning a stderr al
    // exit del proceso (registrado via atexit).
    ctx.out
        << "/* "
           "==================================================================="
           "======\n"
           " * Runtime mini VxString embebido (mode=managed).\n"
           " * Layout: header 16 bytes + buffer flexible.  Operaciones de "
           "strings\n"
           " * (concat/equals/length/raw/bytes) usan estos helpers.  El "
           "usuario debe\n"
           " * llamar vx_str_free(s) cuando termine con un VxString* "
           "heap-alloc'd\n"
           " * (los marcados is_owned=1).  Al exit del programa, los unfreed "
           "se\n"
           " * reportan a stderr.\n"
           " * "
           "==================================================================="
           "======\n"
           " */\n"
           "typedef struct VxString {\n"
           "    struct VxString *__prev;\n"
           "    struct VxString *__next;\n"
           "    uint32_t byte_len;\n"
           "    uint32_t code_points;\n"
           "    uint8_t  is_owned;       /* 1=heap (free at vx_str_free), "
           "0=literal */\n"
           "    uint8_t  __pad[3];\n"
           "    char    *data;\n"
           "} VxString;\n"
           "\n"
           "#ifndef VX_TLS\n"
           "#  if defined(__GNUC__) || defined(__clang__)\n"
           "#    define VX_TLS __thread\n"
           "#  elif defined(_MSC_VER)\n"
           "#    define VX_TLS __declspec(thread)\n"
           "#  else\n"
           "#    define VX_TLS\n"
           "#  endif\n"
           "#endif\n"
           "\n"
           "/* @c __thread + self-reference no funciona en algunos "
           "toolchains;\n"
           " * lazy-init en la primera inserccion al list. */\n"
           "static VX_TLS VxString  vx_str_head_;\n"
           "static VX_TLS int        vx_str_head_init_ = 0;\n"
           "static VX_TLS int        vx_str_live_count_ = 0;\n"
           "static int                vx_str_atexit_registered_ = 0;\n"
           "\n"
           "static void vx_str_head_ensure_(void) {\n"
           "    if (!vx_str_head_init_) {\n"
           "        vx_str_head_.__prev = &vx_str_head_;\n"
           "        vx_str_head_.__next = &vx_str_head_;\n"
           "        vx_str_head_init_ = 1;\n"
           "    }\n"
           "}\n"
           "\n"
           "static void vx_str_track_(VxString *s) {\n"
           "    vx_str_head_ensure_();\n"
           "    s->__next = vx_str_head_.__next;\n"
           "    s->__prev = &vx_str_head_;\n"
           "    vx_str_head_.__next->__prev = s;\n"
           "    vx_str_head_.__next = s;\n"
           "    vx_str_live_count_++;\n"
           "}\n"
           "\n"
           "static void vx_str_untrack_(VxString *s) {\n"
           "    s->__prev->__next = s->__next;\n"
           "    s->__next->__prev = s->__prev;\n"
           "    s->__prev = s->__next = 0;\n"
           "    vx_str_live_count_--;\n"
           "}\n"
           "\n"
           "static void vx_str_atexit_warn_(void) {\n"
           "    if (vx_str_live_count_ > 0) {\n"
           "        fprintf(stderr,\n"
           "          \"[vx] warning: %d VxString blocks leaked at thread "
           "exit\\n\",\n"
           "          vx_str_live_count_);\n"
           "    }\n"
           "}\n"
           "\n"
           "static void vx_str_register_atexit_(void) {\n"
           "    if (!vx_str_atexit_registered_) {\n"
           "        vx_str_atexit_registered_ = 1;\n"
           "        atexit(vx_str_atexit_warn_);\n"
           "    }\n"
           "}\n"
           "\n"
           "/* Cuenta code points UTF-8 en un buffer (1 byte por cp ASCII, "
           "varios para multi-byte). */\n"
           "static uint32_t vx_str_count_cp_(const char *buf, uint32_t "
           "byte_len) {\n"
           "    uint32_t n = 0;\n"
           "    for (uint32_t i = 0; i < byte_len; ) {\n"
           "        unsigned char c = (unsigned char)buf[i];\n"
           "        uint32_t adv = 1;\n"
           "        if      ((c & 0x80) == 0x00) adv = 1;\n"
           "        else if ((c & 0xE0) == 0xC0) adv = 2;\n"
           "        else if ((c & 0xF0) == 0xE0) adv = 3;\n"
           "        else if ((c & 0xF8) == 0xF0) adv = 4;\n"
           "        i += adv;\n"
           "        n++;\n"
           "    }\n"
           "    return n;\n"
           "}\n"
           "\n"
           "/* Crea un VxString desde un literal de @c .rodata. NO trackeado, "
           "NO owned. */\n"
           "static VX_UNUSED VxString *vx_str_from_lit(const char *lit, "
           "uint32_t byte_len) {\n"
           "    VxString *s = (VxString*)malloc(sizeof(VxString));\n"
           "    if (!s) return 0;\n"
           "    s->byte_len = byte_len;\n"
           "    s->code_points = vx_str_count_cp_(lit, byte_len);\n"
           "    s->is_owned = 0;\n"
           "    s->data = (char*)lit;\n"
           "    vx_str_track_(s);\n"
           "    vx_str_register_atexit_();\n"
           "    return s;\n"
           "}\n"
           "\n"
           "/* Crea un VxString desde un buffer de bytes (copia los datos). "
           "*/\n"
           "static VX_UNUSED VxString *vx_str_make(const char *buf, "
           "uint32_t byte_len) {\n"
           "    VxString *s = (VxString*)malloc(sizeof(VxString));\n"
           "    if (!s) return 0;\n"
           "    s->byte_len = byte_len;\n"
           "    s->code_points = vx_str_count_cp_(buf, byte_len);\n"
           "    s->is_owned = 1;\n"
           "    s->data = (char*)malloc(byte_len + 1);\n"
           "    if (!s->data) { free(s); return 0; }\n"
           "    memcpy(s->data, buf, byte_len);\n"
           "    s->data[byte_len] = 0;\n"
           "    vx_str_track_(s);\n"
           "    vx_str_register_atexit_();\n"
           "    return s;\n"
           "}\n"
           "\n"
           "/* Concatena dos strings. Devuelve nuevo VxString owned. */\n"
           "static VX_UNUSED VxString *vx_str_concat(VxString *a, "
           "VxString *b) {\n"
           "    if (!a || !b) return 0;\n"
           "    uint32_t na = a->byte_len, nb = b->byte_len;\n"
           "    char *buf = (char*)malloc(na + nb + 1);\n"
           "    if (!buf) return 0;\n"
           "    memcpy(buf, a->data, na);\n"
           "    memcpy(buf + na, b->data, nb);\n"
           "    buf[na + nb] = 0;\n"
           "    VxString *r = (VxString*)malloc(sizeof(VxString));\n"
           "    if (!r) { free(buf); return 0; }\n"
           "    r->byte_len = na + nb;\n"
           "    r->code_points = a->code_points + b->code_points;\n"
           "    r->is_owned = 1;\n"
           "    r->data = buf;\n"
           "    vx_str_track_(r);\n"
           "    return r;\n"
           "}\n"
           "\n"
           "static VX_UNUSED int vx_str_eq(VxString *a, VxString *b) {\n"
           "    if (a == b) return 1;\n"
           "    if (!a || !b) return 0;\n"
           "    if (a->byte_len != b->byte_len) return 0;\n"
           "    return memcmp(a->data, b->data, a->byte_len) == 0;\n"
           "}\n"
           "static VX_UNUSED uint32_t vx_str_len(VxString *s)      { return "
           "s ? s->code_points : 0; }\n"
           "static VX_UNUSED uint32_t vx_str_byte_len(VxString *s) { return "
           "s ? s->byte_len    : 0; }\n"
           "static VX_UNUSED const char *vx_str_raw(VxString *s)   { return "
           "s ? s->data : (const char*)\"\"; }\n"
           "\n"
           "/* Libera explicitamente un VxString.  No-op si NULL.  Si es "
           "literal\n"
           "   (is_owned=0) solo libera el header (data esta en .rodata).  Si "
           "es\n"
           "   owned, libera tambien data. */\n"
           "static VX_UNUSED void vx_str_free(VxString *s) {\n"
           "    if (!s) return;\n"
           "    vx_str_untrack_(s);\n"
           "    if (s->is_owned) free(s->data);\n"
           "    free(s);\n"
           "}\n"
           "\n";
}

void CBackend::emit_str_lit_addr(EmitContext &ctx, ir::IrValueId dst,
                                 uint64_t imm, ir::IrType t) {
    (void)t;
    emit_assign_lhs(ctx, dst);
    ctx.out << "(void*)__str_" << imm << ";\n";
}

// -------- Tabla compartida de reconocimiento raw_asm --------
//
// Mantenemos las firmas exactas que emite el frontend Vesta.  Cualquier
// cambio en el lowering (ej. añadir un atributo de instr) requiere
// actualizar esta tabla.  Compartido conceptualmente con el JIT
// selector (D.3-G) -- la diferencia es el destino: aqui emit C,
// alla emit MachineIR.

void CBackend::emit_raw_asm(EmitContext &ctx, ir::IrValueId dst,
                            const std::string &asm_text,
                            ir::IrValueList operands,
                            ir::IrType t) {
    // El tipo del dst determina como castear el resultado: PTR para
    // strraw (host buffer) vs I64 para los handles internos.
    const char *result_cast =
        (t == ir::IrType::PTR) ? "(void*)" : "(int64_t)(intptr_t)";
    // Helper para leer un VxString * desde una direccion VM (cuando
    // el src es un puntero a memoria VM con buffer raw).  Aqui los
    // strings se construyen siempre desde memoria VM (alloca + store
    // de literales).  La direccion del buffer apunta al inicio de los
    // bytes; le pasamos a vx_str_make directamente para que copie.

    auto src = [&](size_t i) -> std::string {
        if (i >= operands.size()) return "0";
        return value_expr(ctx, operands[i]);
    };
    auto dst_lhs = [&]() {
        if (dst != ir::IR_NO_VALUE)
            emit_assign_lhs(ctx, dst);
        else
            ctx.indent();
    };

    // strmake {dst}, {src0 buffer_addr}, {src1 byte_len}
    // El dst en el IR es i64 (handle); en C lo representamos como un
    // puntero VxString* pero almacenado en int64_t -> cast inline.
    if (asm_text == "strmake {dst}, {src0}, {src1}\n") {
        dst_lhs();
        ctx.out << "(int64_t)(intptr_t)vx_str_make((const char*)(intptr_t)"
                << src(0) << ", (uint32_t)" << src(1) << ");\n";
        return;
    }
    if (asm_text == "strcat {dst}, {src0}, {src1}\n") {
        dst_lhs();
        ctx.out << "(int64_t)(intptr_t)vx_str_concat((VxString*)(intptr_t)"
                << src(0) << ", (VxString*)(intptr_t)" << src(1) << ");\n";
        return;
    }
    if (asm_text == "strraw {dst}, {src0}\n") {
        dst_lhs();
        ctx.out << result_cast << "vx_str_raw((VxString*)(intptr_t)" << src(0)
                << ");\n";
        return;
    }
    // strgetbytes {dst}, {src0 str} -> uint32 byte count
    if (asm_text == "strgetbytes {dst}, {src0}\n") {
        dst_lhs();
        ctx.out << "(int64_t)vx_str_byte_len((VxString*)(intptr_t)" << src(0)
                << ");\n";
        return;
    }
    if (asm_text == "strlen {dst}, {src0}\n") {
        dst_lhs();
        ctx.out << "(int64_t)vx_str_len((VxString*)(intptr_t)" << src(0)
                << ");\n";
        return;
    }
    if (asm_text == "strcmp {dst}, {src0}, {src1}\n") {
        dst_lhs();
        ctx.out << "(int64_t)(vx_str_eq((VxString*)(intptr_t)" << src(0)
                << ", (VxString*)(intptr_t)" << src(1) << ") ? 0 : "
                << "memcmp(vx_str_raw((VxString*)(intptr_t)" << src(0)
                << "), vx_str_raw((VxString*)(intptr_t)" << src(1)
                << "), vx_str_byte_len((VxString*)(intptr_t)" << src(0)
                << ")));\n";
        return;
    }
    // gchandle {dst}, {src0 host_ptr} -> handle (GC handle; en port C
    // sin GC, devolvemos el ptr crudo como handle - no requiere lookup
    // porque no hay HandleTable).
    if (asm_text == "gchandle {dst}, {src0}\n") {
        dst_lhs();
        ctx.out << "(int64_t)(intptr_t)" << src(0) << ";\n";
        return;
    }
    // gcderef cur0, {src0 handle}  +  xchg cur0, {dst}  ->  host_ptr
    if (asm_text == "gcderef cur0, {src0}\nxchg cur0, {dst}\n") {
        dst_lhs();
        ctx.out << result_cast << "(intptr_t)" << src(0) << ";\n";
        return;
    }
    // setmethdbg {src0}, {src1}  -> debug info para stack trace (no-op en C).
    if (asm_text == "setmethdbg {src0}, {src1}\n") {
        if (opts_.emit_comments) {
            ctx.indent();
            ctx.out << "/* setmethdbg no-op en port C */\n";
        }
        return;
    }

    // -------- Try/catch (substring patterns) --------
    //
    // El frontend Vesta baja try/catch a SECUENCIAS de raw_asm que
    // emulan la maquinaria de tryenter/throw/tryleave del bytecode.
    // Pattern-match para reemitirlos en C con setjmp/longjmp +
    // GCC labels-as-values (&&label + goto *ptr).
    //
    // Secuencia esperada por bloque try:
    //   1. findclass FatalError              -> sentinel @c (void*)1
    //   2. mov {dst}, @Absolute("code.<fn>_<handler_bb>") -> &&bb_id
    //   3. tryenter {src0}, {src1}           -> setjmp + push frame
    //   4. (body) panic                      -> longjmp
    //   5. (handler) mov {dst}, r0           -> v_dst = vx_exc_value
    //   6. tryleave                          -> pop frame

    // (1) findclass FatalError.  Devolvemos un sentinel (no usado en C,
    // pero debe ser non-null para que el codigo posterior siga la rama
    // de "tipo encontrado").
    if (asm_text.find("findclass") != std::string::npos &&
        asm_text.find("mov {dst}, r12") != std::string::npos) {
        dst_lhs();
        ctx.out << "(void*)1; /* findclass FatalError -> sentinel */\n";
        return;
    }

    // (2) Cargar direccion de label de handler:
    //   mov {dst}, @Absolute("code.<funcname>_<bbname>")
    // En C: extraer <bbname>, buscar el block_id en la funcion actual,
    // y emitir &&bb_<id> (labels-as-values GCC).
    {
        const std::string MOV_ABS = "mov {dst}, @Absolute(\"";
        // Encontrar el patron incluso si hay lineas de comentario @c "// ..."
        // antes -- el frontend Vesta prepende a veces un comentario
        // descriptivo a sus raw_asm.
        size_t mov_pos = asm_text.find(MOV_ABS);
        if (mov_pos != std::string::npos) {
            auto open_q = mov_pos + MOV_ABS.size();
            auto close_q = asm_text.find('"', open_q);
            if (close_q != std::string::npos) {
                std::string full_label =
                    asm_text.substr(open_q, close_q - open_q);
                // Quitar prefix "code." si presente.
                const std::string CODE_PFX = "code.";
                if (full_label.compare(0, CODE_PFX.size(), CODE_PFX) == 0) {
                    full_label = full_label.substr(CODE_PFX.size());
                }
                // Si el resto tiene "<fn>_<bbname>", separamos por el
                // nombre de la funcion actual.
                std::string bb_target;
                if (ctx.fn) {
                    const std::string &fnname = ctx.fn->name;
                    if (full_label.compare(0, fnname.size(), fnname) == 0 &&
                        full_label.size() > fnname.size() &&
                        full_label[fnname.size()] == '_') {
                        bb_target = full_label.substr(fnname.size() + 1);
                    }
                }
                if (!bb_target.empty() && ctx.fn) {
                    // Buscar el block con ese nombre.
                    for (const auto &bb : ctx.fn->blocks) {
                        if (bb.name == bb_target) {
                            dst_lhs();
                            ctx.out << "(void*)&&bb_" << bb.id << ";\n";
                            return;
                        }
                    }
                }
                // Fallback: literal string -> static data lookup.
                // El @Absolute apunta a una etiqueta de @c static_data
                // (e.g. code.s_0 para un literal).  En C, los literales
                // se exponen como @c __str_<i>.
                if (full_label.rfind("s_", 0) == 0) {
                    std::string idx = full_label.substr(2);
                    dst_lhs();
                    ctx.out << "(void*)__str_" << idx << ";\n";
                    return;
                }
                // Funcion (lambda o user): @Absolute("code.<fn_name>")
                // Cast al tipo del dst (i64 o ptr).  Lambdas se nombran
                // @c __lambda_<N> y son funciones libres globales.
                if (!full_label.empty()) {
                    dst_lhs();
                    if (t == ir::IrType::PTR) {
                        ctx.out << "(void*)&" << sanitize_name(full_label)
                                << ";\n";
                    } else {
                        ctx.out << "(int64_t)(intptr_t)&"
                                << sanitize_name(full_label) << ";\n";
                    }
                    return;
                }
            }
        }
    }

    // (3) tryenter {src0=handler_ptr}, {src1=type_ptr}.  En C emitimos
    // setjmp + push frame + on != 0 do goto handler.
    if (asm_text == "tryenter {src0}, {src1}\n") {
        ctx.indent();
        ctx.out << "{\n";
        ctx.indent_level++;
        // Inicializacion explicita por campos para evitar
        // -Wmissing-braces.  El jmp_buf se inicializa via setjmp; aqui
        // basta con declarar la variable.
        ctx.indent();
        ctx.out << "vx_exc_frame __vx_f;\n";
        ctx.indent();
        ctx.out << "__vx_f.type_tag = (int64_t)(intptr_t)" << src(1) << ";\n";
        ctx.indent();
        ctx.out << "__vx_f.prev = vx_exc_top;\n";
        ctx.indent();
        ctx.out << "vx_exc_top = &__vx_f;\n";
        ctx.indent();
        ctx.out << "if (setjmp(__vx_f.buf) != 0) {\n";
        ctx.indent_level++;
        ctx.indent();
        ctx.out << "vx_exc_top = __vx_f.prev;\n";
        ctx.indent();
        ctx.out << "goto *((void*)(intptr_t)" << src(0) << ");\n";
        ctx.indent_level--;
        ctx.indent();
        ctx.out << "}\n";
        ctx.indent_level--;
        ctx.indent();
        ctx.out << "}\n";
        return;
    }

    // (4) catch handler bind:  // catch: bind r0 -> var\nmov {dst}, r0\n
    // Lee @c vx_exc_value (set por panic).
    if (asm_text.find("// catch:") != std::string::npos &&
        asm_text.find("mov {dst}, r0") != std::string::npos) {
        if (dst != ir::IR_NO_VALUE && ctx.tx != nullptr &&
            ctx.tx->use_count(dst) > 0) {
            emit_assign_lhs(ctx, dst);
            ctx.out << "(int64_t)vx_exc_value;\n";
        } else if (opts_.emit_comments) {
            ctx.indent();
            ctx.out << "/* catch bind: dst no usado, asignacion suprimida */\n";
        }
        return;
    }

    // (5) panic r12, r11   -> set vx_exc_value + longjmp.  src0=msg_ptr,
    // src1=len; en port C ignoramos len y guardamos msg como exc_value.
    if (asm_text.find("panic r12, r11") != std::string::npos) {
        // panic con mov hardcoded r12/r11 -- no tenemos los SSA values.
        // El frontend pone los regs directamente.  Recuperamos r12 (msg)
        // del bloque anterior si esta inmediato; sino emit longjmp con
        // un mensaje generico.  Detalle: el patron full es:
        //   mov r12, @Absolute("code.s_N")
        //   mov r11, <len>
        //   panic r12, r11
        // El N del string lo podemos extraer del propio texto.
        auto pos = asm_text.find("@Absolute(\"code.s_");
        std::string msg_idx = "0";
        if (pos != std::string::npos) {
            pos += std::string("@Absolute(\"code.s_").size();
            auto end = asm_text.find('"', pos);
            if (end != std::string::npos) {
                msg_idx = asm_text.substr(pos, end - pos);
            }
        }
        ctx.indent();
        ctx.out << "vx_panic_with_str(__str_" << msg_idx << ");\n";
        return;
    }

    // (6) tryleave -> pop frame.
    if (asm_text == "tryleave\n") {
        ctx.indent();
        ctx.out << "if (vx_exc_top) vx_exc_top = vx_exc_top->prev;\n";
        return;
    }

    // -------- Optional/Result unwrap (chequeo tag != 0) --------
    // Si tag == 0 (None), llamamos a vx_throw(1).  Marcamos la rama
    // como @c __builtin_expect(cond, 0) para que GCC la prediga como
    // NO tomada -> branch prediction agresiva al fast path.
    if (asm_text == "unwrap {dst}, {src0}\n") {
        ctx.indent();
        if (opts_.aggressive_opt) {
            ctx.out << "if (__builtin_expect((int64_t)" << src(0)
                    << " == 0, 0)) {\n";
        } else {
            ctx.out << "if ((int64_t)" << src(0) << " == 0) {\n";
        }
        ctx.indent_level++;
        if (!opts_.freestanding) {
            ctx.indent();
            ctx.out << "fputs(\"[vx] unwrap of None\\n\", stderr);\n";
        }
        ctx.indent();
        ctx.out << "vx_throw(1);\n";
        ctx.indent_level--;
        ctx.indent();
        ctx.out << "}\n";
        dst_lhs();
        ctx.out << "(int64_t)" << src(0) << ";\n";
        return;
    }
    // isnull para referencias nullable (PrimitiveKind class? / unwrap).
    if (asm_text == "isnull {dst}, {src0}\n") {
        dst_lhs();
        ctx.out << "(int64_t)((int64_t)(intptr_t)" << src(0) << " == 0);\n";
        return;
    }

    // -------- Async: future / await / fulfillhlt --------
    // future\nmov {dst}, r0\n  -> vx_future_alloc()
    if (asm_text.find("future\n") != std::string::npos &&
        asm_text.find("mov {dst}, r0") != std::string::npos) {
        dst_lhs();
        ctx.out << "vx_future_alloc();\n";
        return;
    }
    // await {src0}\nmov {dst}, r0\n  -> vx_future_await(src0)
    if (asm_text.find("await {src0}") != std::string::npos &&
        asm_text.find("mov {dst}, r0") != std::string::npos) {
        dst_lhs();
        ctx.out << "vx_future_await(" << src(0) << ");\n";
        return;
    }
    // fulfillhlt {src0}, {src1}  -> fulfill + return (helper async exit)
    if (asm_text.find("fulfillhlt {src0}, {src1}") != std::string::npos) {
        ctx.indent();
        ctx.out << "vx_future_fulfill(" << src(0) << ", " << src(1) << ");\n";
        ctx.indent();
        ctx.out << "return;\n";
        return;
    }

    // -------- Closures con captura: leer env de R14 --------
    // El frontend Vesta emite "mov {dst}, r14" en el prologue de cada
    // lambda que captura, para acceder al env_ptr (que llega en R14
    // segun la calling convention bytecode).  En port C, la firma de
    // la lambda es @c (void* __vx_env, ...) -> ret asi que basta
    // exponer @c __vx_env como i64.
    if (asm_text.find("leer env_ptr de R14") != std::string::npos ||
        asm_text == "mov {dst}, r14\n") {
        dst_lhs();
        if (t == ir::IrType::PTR) {
            ctx.out << "(void*)__vx_env;\n";
        } else {
            ctx.out << "(int64_t)(intptr_t)__vx_env;\n";
        }
        return;
    }

    // Fallback: pattern desconocido.  Imprimimos truncado en el
    // comentario para diagnostico + warning a stderr.
    std::string preview = asm_text.substr(0, 60);
    for (auto &c : preview)
        if (c == '\n') c = ' ';
    ctx.indent();
    ctx.out << "/* TODO unsupported raw_asm: \"" << preview;
    if (asm_text.size() > 60) ctx.out << "...";
    ctx.out << "\" */\n";
    if (dst != ir::IR_NO_VALUE) {
        emit_assign_lhs(ctx, dst);
        ctx.out << "0;\n";
    }
    fprintf(stderr, "[port C] raw_asm no reconocido: \"%s\"\n",
            preview.c_str());
}

// =========================================================================
//  Native call dispatch (CALLN)
// =========================================================================

void CBackend::emit_native_call(EmitContext &ctx, ir::IrValueId dst,
                                const std::string &lib, const std::string &sym,
                                ir::IrValueList args,
                                ir::IrType ret_type) {
    (void)lib;
    (void)ret_type;
    auto src = [&](size_t i) -> std::string {
        if (i >= args.size()) return "0";
        return value_expr(ctx, args[i]);
    };

    // ---- bridge a stdio.h C estandar para los vio_print_* ----
    // (Asi el .c es standalone sin requerir vesta_io.dll/.so).
    // vesta_io firma: la mayoria toma (proc_ptr, vm_addr, len) que en
    // port C se ignora el proc_ptr (no hay ProcessVM).  Para los
    // print_* simples: vio_print_int(proc, n) ignora proc, imprime n.
    // Para los print_buf: vio_print_buf(host_ptr, len) -> fwrite stdout.

    // -------- Instrumentacion: vx_trace:enter / vx_trace:exit --------
    // El frontend emite estas calls con --instrument trace.  Default
    // bridge: imprime a stderr con indentacion por depth (TLS counter).
    // El usuario puede override declarando sus propias funciones
    // @c "void vx_trace_enter(const char*)" y reemplazando este snippet.
    // Detectar vx_trace por basename del lib path
    // (puede venir como "vx_trace" o "stdlib/native/runtime/vx_trace").
    auto basename_eq = [](const std::string &s, const char *base) {
        size_t pos = s.rfind('/');
        std::string b = (pos == std::string::npos) ? s : s.substr(pos + 1);
        return b == base;
    };
    if (sym == "enter" && basename_eq(lib, "vx_trace")) {
        // args: (proc_ptr, name_ptr).  Ignoramos proc_ptr en port C
        // (no hay VM-proc; el nombre es ya un host_ptr a .rodata).
        ctx.indent();
        ctx.out << "vx_trace_enter((const char*)(intptr_t)" << src(1) << ");\n";
        return;
    }
    if (sym == "leave" && basename_eq(lib, "vx_trace")) {
        // args: (proc_ptr, name_ptr, return_value)
        ctx.indent();
        ctx.out << "vx_trace_leave((const char*)(intptr_t)" << src(1)
                << ", (int64_t)" << src(2) << ");\n";
        return;
    }

    // Helpers de impresion: bridge a fputs/fwrite/printf de stdio.
    if (sym == "vio_print_newline") {
        ctx.indent();
        ctx.out << "fputc('\\n', stdout);\n";
        return;
    }
    if (sym == "vio_println_newline") {
        ctx.indent();
        ctx.out << "fputc('\\n', stdout);\n";
        return;
    }
    if (sym == "vio_flush") {
        ctx.indent();
        ctx.out << "fflush(stdout);\n";
        return;
    }
    if (sym == "vio_print_buf") {
        // (host_ptr, byte_len)
        ctx.indent();
        ctx.out << "fwrite(" << src(0) << ", 1, (size_t)" << src(1)
                << ", stdout);\n";
        return;
    }
    if (sym == "vio_print_cstr") {
        ctx.indent();
        ctx.out << "fputs((const char*)" << src(0) << ", stdout);\n";
        return;
    }
    if (sym == "vio_print" || sym == "vio_println") {
        // (host_ptr) NUL-terminated
        ctx.indent();
        ctx.out << "fputs((const char*)" << src(0) << ", stdout);\n";
        if (sym == "vio_println") {
            ctx.indent();
            ctx.out << "fputc('\\n', stdout);\n";
        }
        return;
    }
    if (sym == "vio_print_int") {
        ctx.indent();
        ctx.out << "fprintf(stdout, \"%lld\", (long long)" << src(0) << ");\n";
        return;
    }
    if (sym == "vio_println_int") {
        ctx.indent();
        ctx.out << "fprintf(stdout, \"%lld\\n\", (long long)" << src(0)
                << ");\n";
        return;
    }
    if (sym == "vio_print_uint") {
        ctx.indent();
        ctx.out << "fprintf(stdout, \"%llu\", (unsigned long long)" << src(0)
                << ");\n";
        return;
    }
    if (sym == "vio_println_uint") {
        ctx.indent();
        ctx.out << "fprintf(stdout, \"%llu\\n\", (unsigned long long)" << src(0)
                << ");\n";
        return;
    }
    if (sym == "vio_print_hex") {
        ctx.indent();
        ctx.out << "fprintf(stdout, \"0x%llx\", (unsigned long long)" << src(0)
                << ");\n";
        return;
    }
    if (sym == "vio_print_bin" || sym == "vio_print_oct") {
        ctx.indent();
        ctx.out << "fprintf(stdout, \""
                << (sym == "vio_print_bin" ? "0b%llb" : "0o%llo")
                << "\", (unsigned long long)" << src(0) << ");\n";
        return;
    }
    if (sym == "vio_print_ptr") {
        ctx.indent();
        ctx.out << "fprintf(stdout, \"%p\", (void*)(intptr_t)" << src(0)
                << ");\n";
        return;
    }
    if (sym == "vio_print_bool") {
        ctx.indent();
        ctx.out << "fputs(((" << src(0)
                << ") ? \"true\" : \"false\"), stdout);\n";
        return;
    }
    if (sym == "vio_print_float") {
        // bits IEEE 754 como uint64; bitcast a double inline.
        ctx.indent();
        ctx.out << "{ union { uint64_t u; double d; } __u_; __u_.u = (uint64_t)"
                << src(0) << "; fprintf(stdout, \"%g\", __u_.d); }\n";
        return;
    }
    // vio_print_color(code) -> escape ANSI \x1b[<code>m
    if (sym == "vio_print_color") {
        ctx.indent();
        ctx.out << "fprintf(stdout, \"\\x1b[%lldm\", (long long)" << src(0)
                << ");\n";
        return;
    }

    // ---- vio_*_to_vmbuf (interpolacion: rellena buffer VM, devuelve len) ----
    // Bridge: usamos snprintf en host memory.  El "buffer VM" es solo un
    // host_ptr en port C (sin ProcessVM).  Args: (proc, vm_addr, value).
    // Devolvemos la longitud escrita (sin nul).
    if (sym == "vio_int_to_vmbuf" || sym == "vio_uint_to_vmbuf" ||
        sym == "vio_hex_to_vmbuf" || sym == "vio_bool_to_vmbuf" ||
        sym == "vio_char_to_vmbuf" || sym == "vio_ptr_to_vmbuf") {
        if (dst != ir::IR_NO_VALUE)
            emit_assign_lhs(ctx, dst);
        else
            ctx.indent();
        const char *fmt = "%lld";
        const char *cast = "(long long)";
        if (sym == "vio_uint_to_vmbuf") {
            fmt = "%llu";
            cast = "(unsigned long long)";
        } else if (sym == "vio_hex_to_vmbuf") {
            fmt = "0x%llx";
            cast = "(unsigned long long)";
        } else if (sym == "vio_bool_to_vmbuf") {
            // Special: imprime "true"/"false".
            ctx.out << "(int64_t)snprintf((char*)" << src(1) << ", 32, \"%s\", "
                    << src(2) << " ? \"true\" : \"false\");\n";
            return;
        } else if (sym == "vio_char_to_vmbuf") {
            fmt = "%c";
            cast = "(int)";
        } else if (sym == "vio_ptr_to_vmbuf") {
            fmt = "%p";
            cast = "(void*)(intptr_t)";
        }
        ctx.out << "(int64_t)snprintf((char*)" << src(1) << ", 32, \"" << fmt
                << "\", " << cast << src(2) << ");\n";
        return;
    }

    // ---- vmath_* -> math.h C estandar ----
    if (sym.rfind("vmath_", 0) == 0) {
        // Cada vmath_* toma bits IEEE 754 como uint64 y devuelve idem.
        // Mapping a libm:
        // sqrt/pow/floor/ceil/round/fmin/fmax/log/log2/log10/sin/cos/tan/fabs.
        std::string name = sym.substr(6);
        if (dst != ir::IR_NO_VALUE)
            emit_assign_lhs(ctx, dst);
        else
            ctx.indent();
        if (name == "abs" || name == "imin" || name == "imax" ||
            name == "clamp") {
            // Variantes int.
            if (name == "abs")
                ctx.out << "(int64_t)((" << src(0) << " < 0) ? -(" << src(0)
                        << ") : (" << src(0) << "));\n";
            else if (name == "imin")
                ctx.out << "(int64_t)((" << src(0) << " < " << src(1) << ") ? ("
                        << src(0) << ") : (" << src(1) << "));\n";
            else if (name == "imax")
                ctx.out << "(int64_t)((" << src(0) << " > " << src(1) << ") ? ("
                        << src(0) << ") : (" << src(1) << "));\n";
            else /* clamp */
                ctx.out << "(int64_t)((" << src(0) << " < " << src(1) << ") ? ("
                        << src(1) << ") : ((" << src(0) << " > " << src(2)
                        << ") ? (" << src(2) << ") : (" << src(0) << ")));\n";
            return;
        }
        // Float math: bitcast u64 -> double, call libm, bitcast back.
        std::string fn = name;
        // Renombrar fmin/fmax (igual nombre en libm).
        ctx.out << "({ union { uint64_t u; double d; } __a_, __r_; __a_.u = "
                   "(uint64_t)"
                << src(0) << "; ";
        if (args.size() >= 2) {
            ctx.out
                << "union { uint64_t u; double d; } __b_; __b_.u = (uint64_t)"
                << src(1) << "; ";
            ctx.out << "__r_.d = " << fn << "(__a_.d, __b_.d); ";
        } else {
            ctx.out << "__r_.d = " << fn << "(__a_.d); ";
        }
        ctx.out << "(int64_t)__r_.u; });\n";
        return;
    }

    // ---- Fallback: extern declaration + direct call ----
    // El IR conoce la firma del callee (params + return) -- emit el
    // tipo de funcion y hace cast inline al pointer.  Lo declaramos
    // como extern; el usuario debe enlazar @c lib.  Si la lib es una
    // DLL Windows / .so POSIX, el linker la resuelve via @c -l<lib>
    // o equivalente.
    if (dst != ir::IR_NO_VALUE)
        emit_assign_lhs(ctx, dst);
    else
        ctx.indent();
    ctx.out << "/* native call " << lib << ":" << sym << " */ ";
    ctx.out << sym << "(";
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) ctx.out << ", ";
        ctx.out << value_expr(ctx, args[i]);
    }
    ctx.out << ");\n";
}

// =========================================================================
//  Prelude / postamble
// =========================================================================

void CBackend::emit_prelude(EmitContext &ctx, const ir::IrModule &mod) {
    if (!opts_.source_path.empty()) {
        ctx.out << "/*\n";
        ctx.out << " * Generated from: " << opts_.source_path << "\n";
        ctx.out << " * by VestaVM port-C transpiler\n";
        ctx.out << " * Edit at your own risk - regenerate with:\n";
        ctx.out << " *   vm --port=c <source.vx> -o " << opts_.source_path
                << ".c\n";
        ctx.out << " */\n\n";
    }

    // Detectar features usadas por el modulo para decidir que
    // snippets cargar y que @c #include emitir.
    bool uses_strings = module_uses_strings(mod);
    bool uses_io = false;
    bool uses_math = false;
    for (const auto &fn : mod.functions) {
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op == ir::IrOp::FMA) {
                    uses_math = true; // fma()/fmaf() de <math.h>
                    continue;
                }
                if (ins.op != ir::IrOp::CALLN && ins.op != ir::IrOp::CALL)
                    continue;
                auto colon = ins.func_name.find(':');
                if (colon == std::string::npos) continue;
                std::string sym = ins.func_name.substr(colon + 1);
                if (sym.rfind("vio_", 0) == 0) uses_io = true;
                if (sym.rfind("vmath_", 0) == 0) uses_math = true;
            }
        }
    }
    bool uses_exc_inc = module_uses_exceptions(mod);
    bool uses_inst = module_uses_instrument(mod);
    bool uses_unwrap = false;
    for (const auto &fn : mod.functions) {
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op != ir::IrOp::RAW_ASM) continue;
                const std::string &t = ins.func_name;
                if (t == "unwrap {dst}, {src0}\n" ||
                    t == "isnull {dst}, {src0}\n") {
                    uses_unwrap = true;
                    break;
                }
            }
            if (uses_unwrap) break;
        }
        if (uses_unwrap) break;
    }

    // CPU target pragmas: habilitar instrucciones extendidas (AVX2/FMA/
    // BMI2/etc) que GCC use al vectorizar/folding.  Solo emit si el
    // usuario opto explicitamente via @c --port-arch.  El default es
    // portable (sin pragmas, GCC infiere por @c -march en CLI).
    if (!opts_.arch_target.empty()) {
        const std::string &t = opts_.arch_target;
        ctx.out << "#if defined(__GNUC__) || defined(__clang__)\n";
        if (t == "native") {
            ctx.out << "#  pragma GCC target(\"arch=native\")\n";
            ctx.out << "#  pragma GCC "
                       "optimize(\"O3\",\"unroll-loops\",\"tree-vectorize\")\n";
        } else if (t == "x86-64-v2") {
            ctx.out << "#  pragma GCC target(\"sse4.2,popcnt\")\n";
        } else if (t == "x86-64-v3") {
            ctx.out << "#  pragma GCC target(\"avx2,fma,bmi,bmi2,lzcnt\")\n";
            ctx.out << "#  pragma GCC "
                       "optimize(\"O3\",\"unroll-loops\",\"tree-vectorize\")\n";
        } else if (t == "x86-64-v4") {
            ctx.out << "#  pragma GCC "
                       "target(\"avx512f,avx512dq,avx512cd,avx512bw,avx512vl,"
                       "bmi2,fma\")\n";
            ctx.out << "#  pragma GCC "
                       "optimize(\"O3\",\"unroll-loops\",\"tree-vectorize\")\n";
        } else {
            ctx.out << "/* WARNING: --port-arch valor desconocido '" << t
                    << "', usando portable */\n";
        }
        ctx.out << "#endif\n\n";
    }

    // Emit los @c #include necesarios.  Modo freestanding: nada
    // automatico.  El usuario los pondra en su propio codigo si los
    // necesita.
    bool uses_async = module_uses_async(mod);
    if (!opts_.freestanding) {
        // _WIN32_WINNT debe definirse ANTES de cualquier header de
        // Windows para habilitar APIs Vista+ (ConditionVariable, etc.)
        // que async usa.  Definirlo siempre es inofensivo.
        if (uses_async) {
            ctx.out << "#if defined(_WIN32) && !defined(_WIN32_WINNT)\n";
            ctx.out << "#  define _WIN32_WINNT 0x0600\n";
            ctx.out << "#endif\n";
        }
        ctx.out << "#include <stdint.h>\n";
        ctx.out << "#include <stdlib.h>\n";
        ctx.out << "#include <string.h>\n";
        if (opts_.exc == ExcMode::SetJmp || uses_exc_inc) {
            ctx.out << "#include <setjmp.h>\n";
        }
        if (uses_strings || uses_io || uses_exc_inc || uses_unwrap ||
            uses_inst) {
            ctx.out << "#include <stdio.h>\n";
        }
        if (uses_math) ctx.out << "#include <math.h>\n";
        if (opts_.gc == GcMode::Boehm) {
            ctx.out << "#include <gc.h>\n";
            // Redefinir malloc/free a Boehm GC.  Esto cubre todas las
            // alocaciones del runtime VxString y RAW_ALLOC del IR.
            ctx.out << "#define malloc(n)  GC_MALLOC(n)\n";
            ctx.out << "#define free(p)    ((void)(p))  /* boehm gestiona */\n";
            ctx.out << "#define calloc(n,s) GC_MALLOC((n)*(s))\n";
        }
    } else {
        // En freestanding solo @c stdint.h (header puramente de tipos,
        // siempre disponible incluso sin libc).  Setjmp si try/catch
        // se usa.
        ctx.out << "#include <stdint.h>\n";
        if (uses_exc_inc) ctx.out << "#include <setjmp.h>\n";
        ctx.out << "/* --port-freestanding: sin stdio/stdlib/string/math.\n"
                << " * El usuario debe proveer en su codigo:\n"
                << " *   - VX_NORETURN void vx_throw(int code);\n"
                << " *   - void *memcpy/memset (si se usan strings/structs)\n"
                << " */\n";
    }
    // El @c gc.h y @c vesta_rt/*.h ya se emitieron arriba dentro del
    // bloque de includes.  No duplicar.
    if (opts_.gc == GcMode::Vesta) {
        ctx.out << "#include \"vesta_rt/public.h\"\n";
        ctx.out << "#include \"vesta_rt/abi.h\"\n";
    }
    ctx.out << "\n";

    ctx.out << "\n";
    // Snippets siempre presentes: macros + pragma silence.
    emit_snippet(ctx, "vx_macros");
    emit_snippet(ctx, "vx_pragma_silence");

    // vx_throw: hosted (setjmp) o freestanding (extern stub).
    if (opts_.freestanding) {
        emit_snippet(ctx, "vx_throw_freestanding");
    } else if (opts_.exc == ExcMode::SetJmp) {
        emit_snippet(ctx, "vx_throw_hosted");
    } else if (opts_.exc == ExcMode::None) {
        ctx.out << "static VX_UNUSED VX_NORETURN void vx_throw(int code) {\n";
        ctx.out << "    (void)code; abort();\n";
        ctx.out << "}\n\n";
    }

    // Runtime de excepciones de usuario (try/catch + panic).  Se emite
    // solo si el modulo usa estos patrones para evitar simbolos muertos.
    bool uses_exc = module_uses_exceptions(mod);
    if (uses_exc) {
        if (opts_.freestanding) {
            emit_snippet(ctx, "vx_exception_freestanding");
        } else {
            emit_snippet(ctx, "vx_exception");
        }
    }
    // FFI extern declarations: scan el modulo y emite @c extern firma
    // para cada simbolo nativo unico.  Sin esto, GCC tira warnings de
    // implicit-function-declaration y el linker tiene que inferir la
    // firma.  Con esto, full type checking del compilador host.
    {
        std::unordered_set<std::string> declared;
        for (const auto &fn : mod.functions) {
            for (const auto &bb : fn.blocks) {
                for (const auto &ins : bb.instrs) {
                    if (ins.op != ir::IrOp::CALL && ins.op != ir::IrOp::CALLN)
                        continue;
                    auto colon = ins.func_name.find(':');
                    if (colon == std::string::npos) continue;
                    const std::string lib = ins.func_name.substr(0, colon);
                    const std::string sym = ins.func_name.substr(colon + 1);
                    // Skip los builtins de vesta_io/vesta_math que
                    // tienen bridges manuales (vio_*, vmath_*).
                    if (sym.rfind("vio_", 0) == 0) continue;
                    if (sym.rfind("vmath_", 0) == 0) continue;
                    // Por prefijo: tambien las tandas en que se parte
                    // (`__module_init_partN`) y las de las dependencias.
                    if (sym.rfind("__module_init", 0) == 0) continue;
                    if (sym.rfind("__new_", 0) == 0) continue;
                    // Skip vx_trace:* (provistos por snippet inline).
                    // Match por basename para tolerar tanto "vx_trace"
                    // como "stdlib/native/runtime/vx_trace".
                    {
                        size_t pos = lib.rfind('/');
                        std::string base = (pos == std::string::npos)
                                               ? lib
                                               : lib.substr(pos + 1);
                        if (base == "vx_trace") continue;
                    }
                    if (declared.count(sym)) continue;
                    declared.insert(sym);

                    // Emit extern <ret> <sym>(<args>...).
                    ctx.out << "extern " << type_for(ins.type, false) << " "
                            << sanitize_name(sym) << "(";
                    if (ins.operands.empty()) {
                        ctx.out << "void";
                    } else {
                        for (size_t i = 0; i < ins.operands.size(); ++i) {
                            if (i) ctx.out << ", ";
                            ir::IrType at = ir::IrType::I64;
                            if (ins.operands[i] < fn.values.size()) {
                                at = fn.values[ins.operands[i]].type;
                            }
                            ctx.out << type_for(at, false);
                        }
                    }
                    ctx.out << ");\n";
                }
            }
        }
        if (!declared.empty()) ctx.out << "\n";
    }

    // Static data (literales de string interned por el frontend Vesta).
    // Se emite ANTES del runtime + clases para que las referencias
    // @c __str_<i> esten visibles a todo lo que sigue.
    emit_static_data(ctx, mod);

    // Runtime VxString si aplica.  Cero overhead si el modulo no
    // usa strings (no se emite el bloque).  En freestanding, el
    // snippet tiene @c freestanding-skip:yes y se omite -- error si
    // el programa usa strings + freestanding.
    if (uses_strings && opts_.strings == StringMode::Managed) {
        emit_snippet(ctx, "vx_string");
    }

    // Runtime de instrumentacion si --instrument trace/profile fue activo.
    // Detectamos el modo por presencia de CALLNs vx_trace:* (siempre
    // trace por defecto; el usuario controla profile via env var o el
    // backend puede emitir @c #define VX_INSTRUMENT_MODE).
    if (module_uses_instrument(mod)) {
        /* Permitimos al usuario forzar el modo via @c VX_INSTRUMENT_MODE
         * al compilar el .c con @c gcc.  Default = 1 (solo trace). */
        ctx.out << "#ifndef VX_INSTRUMENT_MODE\n";
        ctx.out << "/* 1=trace, 2=profile, 3=trace+profile.  Override con\n"
                   "   gcc -DVEX_INSTRUMENT_MODE=N. */\n";
        ctx.out << "#define VX_INSTRUMENT_MODE 3\n";
        ctx.out << "#endif\n\n";
        emit_snippet(ctx, "vx_instrument");
    }

    // Async runtime (futures + spawn + monitors) si se usa.
    if (module_uses_async(mod)) {
        emit_snippet(ctx, "vx_async");

        // Scan SPAWN_ARGS para recolectar las aridades necesarias y
        // forward-declarar sus trampolines (el cuerpo se emite en
        // @c emit_postamble).
        std::unordered_set<size_t> arities;
        for (const auto &fn : mod.functions) {
            for (const auto &bb : fn.blocks) {
                for (const auto &ins : bb.instrs) {
                    if (ins.op != ir::IrOp::SPAWN_ARGS) continue;
                    if (ins.operands.size() > 2) {
                        size_t n_total = ins.operands.size() - 1;
                        arities.insert(n_total);
                    }
                }
            }
        }
        if (!arities.empty()) {
            ctx.out << "/* Forward decls de spawn trampolines (bodies en "
                       "postamble) */\n";
            for (size_t N : arities) {
                ctx.out << "static void __vx_trampoline_" << N
                        << "(int64_t packed);\n";
                spawn_trampoline_arities_.insert(N);
            }
            ctx.out << "\n";
        }
    }

    // Emitir clases (structs + forward decls de metodos) ANTES de los
    // forward decls de funciones libres, asi los typedefs estan listos.
    emit_class_decls(ctx, mod);

    if (opts_.emit_comments) {
        ctx.out << "/* Forward declarations de funciones libres */\n";
    }
    for (const auto &fn : mod.functions) {
        if (fn.is_native) continue;
        // Skip funciones POO que ya se declararon en emit_class_decls.
        // Patron: @c "<Class>__<method>" o @c "<Class>____dtor".
        const std::string &n = fn.name;
        auto sep = n.find("__");
        if (sep != std::string::npos && lookup_class(n.substr(0, sep))) {
            continue; // ya forward-decl en emit_class_decls
        }
        // Skip @c __module_init: el transpiler emite la inicializacion
        // de clases via @c Class__new y constructores estaticos cuando
        // sea necesario.  El runtime de VestaVM lo necesita; C no.
        // Por prefijo: cubre las tandas (`__module_init_partN`) y las de las
        // dependencias, que son la misma maquinaria.
        if (n.rfind("__module_init", 0) == 0) continue;
        // Skip @c __new_<X>: emitido por @c emit_class_bodies.
        if (n.rfind("__new_", 0) == 0 && lookup_class(n.substr(6))) {
            continue;
        }
        bool is_lambda = (fn.name.rfind("__lambda_", 0) == 0);
        ctx.out << type_for(fn.ret_type, false) << " " << sanitize_name(fn.name)
                << "(";
        if (is_lambda) ctx.out << "void*";
        if (fn.params.empty()) {
            if (!is_lambda) ctx.out << "void";
        } else {
            for (size_t i = 0; i < fn.params.size(); ++i) {
                if (i || is_lambda) ctx.out << ", ";
                ir::IrValueId vid = fn.params[i];
                if (vid < fn.values.size()) {
                    const auto &v = fn.values[vid];
                    ctx.out << type_for(v.type, v.is_host_ptr);
                } else {
                    ctx.out << "int64_t";
                }
            }
        }
        ctx.out << ");\n";
    }
    ctx.out << "\n";

    // Cuerpos de @c Class__new y @c Class__delete (helpers de POO).
    // Las funciones de usuario (Class__method) son IrFunctions normales
    // que emit_function se encarga de procesar.
    emit_class_bodies(ctx, mod);
}

bool CBackend::should_skip_function(const ir::IrFunction &fn,
                                    const ir::IrModule &mod) const {
    (void)mod;
    const std::string &n = fn.name;
    // 1. @c __module_init: el runtime VestaVM lo usa para registrar
    //    clases dinamicamente.  En C standalone con structs estaticos
    //    no se necesita -- las clases son literales.  Skip.
    if (n.rfind("__module_init", 0) == 0) return true;
    // 2. @c __new_<X>: reemplazado por @c X__new del backend (definido
    //    en emit_class_bodies).  El user code que llamaba a __new_<X>
    //    se redirige a X__new en emit_call.
    if (n.rfind("__new_", 0) == 0) {
        std::string class_name = n.substr(6);
        if (lookup_class(class_name)) return true;
    }
    return false;
}

void CBackend::emit_postamble(EmitContext &ctx, const ir::IrModule &mod) {
    // Emitir trampolines de SPAWN_ARGS para cada aridad usada.  El
    // layout del payload es: @c args[0]=fn_ptr, @c args[1..N]=args.
    // El trampoline castea @c fn_ptr al puntero de funcion correcto
    // y llama con los args desempaquetados.  Free del payload tras
    // la llamada para evitar leak.
    if (!spawn_trampoline_arities_.empty()) {
        ctx.out << "\n";
        // Orden estable: emitir aridades ascendentes para legibilidad.
        std::vector<size_t> arities(spawn_trampoline_arities_.begin(),
                                    spawn_trampoline_arities_.end());
        std::sort(arities.begin(), arities.end());
        for (size_t N : arities) {
            ctx.out << "static void __vx_trampoline_" << N
                    << "(int64_t packed) {\n";
            ctx.out << "    int64_t *a = (int64_t*)(intptr_t)packed;\n";
            ctx.out << "    void (*fn)(";
            for (size_t i = 0; i < N; ++i) {
                if (i) ctx.out << ", ";
                ctx.out << "int64_t";
            }
            ctx.out << ") = (void (*)(";
            for (size_t i = 0; i < N; ++i) {
                if (i) ctx.out << ", ";
                ctx.out << "int64_t";
            }
            ctx.out << "))(intptr_t)a[0];\n";
            /* Capturar args antes de free para no leerlos tras liberar. */
            for (size_t i = 0; i < N; ++i) {
                ctx.out << "    int64_t a" << i << " = a[" << (i + 1) << "];\n";
            }
            ctx.out << "    free(a);\n";
            ctx.out << "    fn(";
            for (size_t i = 0; i < N; ++i) {
                if (i) ctx.out << ", ";
                ctx.out << "a" << i;
            }
            ctx.out << ");\n";
            ctx.out << "}\n";
        }
    }

    bool has_main = false;
    ir::IrType main_ret = ir::IrType::VOID;
    for (const auto &fn : mod.functions) {
        if (fn.name == "main") {
            has_main = true;
            main_ret = fn.ret_type;
            break;
        }
    }
    if (!has_main) return;
    if (opts_.freestanding) {
        // En freestanding NO emitimos un wrapper @c "int main()" --
        // el usuario decide el entry point (e.g. _start del kernel,
        // BootMain del bootloader).  Emitimos solo un comentario
        // guia.  La funcion @c vx_main esta disponible para
        // llamarse desde codigo del usuario.
        ctx.out << "\n/* --port-freestanding: sin wrapper int main(). */\n";
        ctx.out << "/* Llama a @c vx_main desde tu entry point custom. */\n";
        return;
    }
    ctx.out << "\n/* Entry point wrapper */\n";
    ctx.out << "int main(int argc, char **argv) {\n";
    ctx.out << "    (void)argc; (void)argv;\n";
    if (opts_.exc == ExcMode::SetJmp) {
        ctx.out << "    if (setjmp(vx_exc_buf) != 0) return vx_exc_code;\n";
    }
    if (main_ret == ir::IrType::VOID) {
        ctx.out << "    vx_main();\n";
        ctx.out << "    return 0;\n";
    } else {
        ctx.out << "    return (int)vx_main();\n";
    }
    ctx.out << "}\n";
}

// =========================================================================
//  Firma + locales
// =========================================================================

void CBackend::emit_fn_signature(EmitContext &ctx, const ir::IrFunction &fn) {
    // Pre-pasada de inferencia de tipos concretos para esta funcion.
    // Llenamos @c concrete_type_ con el class_name de cada SSA value
    // que conocemos.  Lo usaremos para devirtualizar CALLVIRT y para
    // emitir field access tipados.
    infer_concrete_types(fn);
    // Pre-pasada de escape analysis: identifica @c __new_<X> que NO
    // escapan -> safe para stack alloc.  Big perf win vs heap.
    analyze_escapes(fn);
    // Reset RAII tracking: cada funcion empieza con su propia lista
    // de stack allocs.  Se llena durante @c emit_call y se drena en
    // @c emit_return (LIFO).
    stack_alloc_in_fn_.clear();

    // Analizar atributos: pure (const), cold, always_inline.
    // Esta info informa al compilador host para mejor optimizacion.
    struct FnAttrs {
        bool is_const_pure = false;  /* solo CONST/ALU/SEXT/etc + RET */
        bool is_cold = false;        /* contiene panic/throw exclusivo */
        bool is_tiny_inline = false; /* <= 5 ops triviales */
    } attrs;
    if (opts_.aggressive_opt) {
        size_t alu_only_count = 0;
        bool has_call = false;
        bool has_store = false;
        bool has_load = false;
        bool has_throw = false;
        bool has_return = false;
        size_t total_real_instrs = 0;
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                using ir::IrOp;
                if (ins.op == IrOp::NOP || ins.op == IrOp::PHI) continue;
                total_real_instrs++;
                switch (ins.op) {
                case IrOp::CONST:
                case IrOp::MOV:
                case IrOp::ADD:
                case IrOp::SUB:
                case IrOp::MUL:
                case IrOp::DIV:
                case IrOp::MOD:
                case IrOp::AND:
                case IrOp::OR:
                case IrOp::XOR:
                case IrOp::NEG:
                case IrOp::NOT:
                case IrOp::SHL:
                case IrOp::SHR:
                case IrOp::SAR:
                case IrOp::FADD:
                case IrOp::FSUB:
                case IrOp::FMUL:
                case IrOp::FDIV:
                case IrOp::FNEG:
                case IrOp::FABS:
                case IrOp::FSQRT:
                case IrOp::CMP_EQ:
                case IrOp::CMP_NE:
                case IrOp::CMP_LT:
                case IrOp::CMP_GT:
                case IrOp::CMP_LE:
                case IrOp::CMP_GE:
                case IrOp::CMP_ULT:
                case IrOp::CMP_UGT:
                case IrOp::CMP_ULE:
                case IrOp::CMP_UGE:
                case IrOp::CAST:
                case IrOp::ZEXT:
                case IrOp::SEXT:
                case IrOp::TRUNC:
                case IrOp::ITOF:
                case IrOp::UITOF:
                case IrOp::FTOI:
                case IrOp::FTOUI:
                case IrOp::F32TOF64:
                case IrOp::F64TOF32:
                case IrOp::BITCAST: alu_only_count++; break;
                case IrOp::RET: has_return = true; break;
                case IrOp::CALL:
                case IrOp::CALLN:
                case IrOp::CALLIND:
                case IrOp::CALLVIRT:
                case IrOp::CALLCLOSURE:
                case IrOp::CALLM:
                case IrOp::TAILCALL:
                    has_call = true;
                    // Detectar si el unico call es a vx_throw/panic
                    // (heuristica para @c cold).
                    if (ins.func_name.find("panic") != std::string::npos ||
                        ins.func_name == "vx_throw") {
                        has_throw = true;
                    }
                    break;
                case IrOp::STORE: has_store = true; break;
                case IrOp::LOAD: has_load = true; break;
                case IrOp::RAW_ASM:
                    if (ins.func_name.find("panic") != std::string::npos)
                        has_throw = true;
                    break;
                default: break;
                }
            }
        }
        // Funcion pura: solo CONST/ALU + RET, sin call/load/store.
        attrs.is_const_pure =
            (has_return && !has_call && !has_store && !has_load &&
             alu_only_count > 0 && fn.ret_type != ir::IrType::VOID);
        // Funcion cold: termina con throw/panic exclusivamente.
        attrs.is_cold = has_throw && !has_return;
        // Funcion tiny inline: <= 5 instrucciones reales, sin loops.
        // Detectar loops: bloques con back-edge (preds en multiple bloques
        // del orden).  Aproximacion: si el numero de bloques == 1, no loops.
        attrs.is_tiny_inline =
            (total_real_instrs <= 5 && fn.blocks.size() == 1 && has_return);
    }

    // Si la funcion es un metodo @c Class__name, el primer parametro
    // es @c Class *self (no void*).  Tambien arriva el ctor (Class__ctor).
    bool is_method = false;
    std::string method_class;
    {
        auto sep = fn.name.find("__");
        if (sep != std::string::npos && !fn.params.empty()) {
            std::string class_name = fn.name.substr(0, sep);
            if (lookup_class(class_name)) {
                is_method = true;
                method_class = class_name;
            }
        }
    }

    // Lambdas (__lambda_<N>): emit con @c void* @c env como primer param
    // para que la convencion coincida con CALLCLOSURE.  Si la lambda no
    // captura, el env_addr sera @c NULL y el callee lo ignora.
    bool is_lambda = (fn.name.rfind("__lambda_", 0) == 0);

    // Atributos agresivos: const para puras, cold para throw-only,
    // always_inline para accesors triviales.  Estos atributos vienen
    // ANTES de @c "static" para que GCC los aplique a la definicion.
    if (opts_.aggressive_opt && opts_.emit_compiler_hints) {
        if (attrs.is_tiny_inline) {
            ctx.out << "__attribute__((always_inline)) inline ";
        }
        if (attrs.is_const_pure) {
            // @c __attribute__((const)) significa: el resultado depende
            // SOLO de los argumentos; no lee memoria ni tiene side effects.
            // Habilita CSE agresivo y elision de calls redundantes.
            ctx.out << "__attribute__((const)) ";
        }
        if (attrs.is_cold) {
            ctx.out << "VX_COLD ";
        }
    }

    // Detectar "static" para metodos (para mantener simbolos privados al
    // archivo, evitando colisiones cross-modulo en builds futuros).
    if (is_method) ctx.out << "static ";

    ctx.out << type_for(fn.ret_type, false) << " " << sanitize_name(fn.name)
            << "(";
    if (is_lambda) {
        ctx.out << "void *VX_UNUSED __vx_env";
    }
    if (fn.params.empty()) {
        if (!is_lambda) ctx.out << "void";
    } else {
        for (size_t i = 0; i < fn.params.size(); ++i) {
            if (i || is_lambda) ctx.out << ", ";
            ir::IrValueId vid = fn.params[i];
            if (vid < fn.values.size()) {
                const auto &v = fn.values[vid];
                // Si es metodo Y este es el primer param (this) -> tipo
                // concreto.
                if (is_method && i == 0) {
                    ctx.out << method_class << " *";
                    if (opts_.emit_compiler_hints) {
                        ctx.out << "VX_RESTRICT ";
                    }
                    ctx.out << "v" << vid;
                    continue;
                }
                std::string t = type_for(v.type, v.is_host_ptr);
                ctx.out << t << " ";
                // @c __restrict__ en TODOS los pointer params: en Vesta
                // los parametros no aliasing por convencion del lenguaje
                // (sin & address-of cross-param), asi habilitamos
                // vectorizacion automatica de GCC.
                if (opts_.emit_compiler_hints &&
                    (v.is_host_ptr || v.type == ir::IrType::PTR)) {
                    ctx.out << "VX_RESTRICT ";
                }
                ctx.out << "v" << vid;
            } else {
                ctx.out << "int64_t v" << vid;
            }
        }
    }
    ctx.out << ")";
}

const ir::AsmRegBinding *CBackend::reg_binding_for(const EmitContext &ctx,
                                                   ir::IrValueId id) const {
    if (!ctx.fn) return nullptr;
    for (const auto &b : ctx.fn->asm_reg_bindings) {
        if (b.alloca_value == id) return &b;
    }
    return nullptr;
}

void CBackend::emit_local_decl(EmitContext &ctx, ir::IrValueId id,
                               const ir::IrValue &value) {
    //  AS inc.3: si este value es el slot ALLOCA de una variable
    // register("reg"), declararlo como variable C ESCALAR con el
    // register-pin de GCC (no como void* a un slot de memoria).  Sus
    // LOAD/STORE se traducen a accesos directos (emit_load/emit_store) y
    // el bloque asm la lista como operando "+r"/"+x".  No se puede tomar
    // su direccion en C (limitacion documentada: nada de &reg_var).
    if (const ir::AsmRegBinding *rb = reg_binding_for(ctx, id)) {
        ctx.indent();
        ctx.out << "register " << type_for(rb->type, false) << " v" << id
                << " __asm__(\"" << rb->reg << "\")";
        if (opts_.emit_comments && !value.name.empty()) {
            ctx.out << ";  /* " << value.name << " @reg(" << rb->reg
                    << ") */\n";
        } else {
            ctx.out << ";\n";
        }
        return;
    }
    ctx.indent();
    // Si conocemos el tipo concreto del value (por SSA propagation),
    // emitir @c "ClassX *" en lugar de @c "void *".  Permite al
    // compilador host devirtualizar las llamadas de metodo y al lector
    // humano ver de un vistazo el flujo de tipos.
    auto it = concrete_type_.find(id);
    if (it != concrete_type_.end() && lookup_class(it->second)) {
        ctx.out << it->second << " *v" << id << ";";
    } else {
        ctx.out << type_for(value.type, value.is_host_ptr) << " v" << id << ";";
    }
    if (opts_.emit_comments && !value.name.empty()) {
        ctx.out << "  /* " << value.name << " */";
    }
    ctx.out << "\n";
}

// =========================================================================
//  Helpers
// =========================================================================

void CBackend::emit_assign_lhs(EmitContext &ctx, ir::IrValueId dst) const {
    ctx.indent();
    ctx.out << "v" << dst << " = ";
}

// =========================================================================
//  Control flow
// =========================================================================

void CBackend::emit_return(EmitContext &ctx, ir::IrValueId val) {
    // NOTA: NO emitimos cleanups RAII aqui porque el frontend Vesta YA
    // inserta @c callvirt %obj, vtbl_idx_dtor() en el IR antes del
    // RET para cada objeto con destructor en scope (modelo "destructor
    // virtual" del propio Vesta).  @c emit_callvirt los devirtualiza a
    // @c Class____dtor(obj) directos.  Si emitieramos aqui ademas, el
    // objeto se destruiria dos veces.
    ctx.indent();
    if (val == ir::IR_NO_VALUE) {
        ctx.out << "return;\n";
    } else {
        // Usar value_expr para que constantes y expresiones simples se
        // inlinean directamente en el @c return.
        ctx.out << "return " << value_expr(ctx, val) << ";\n";
    }
}

void CBackend::emit_cond_branch(EmitContext &ctx, ir::IrValueId cond,
                                ir::IrBlockId true_id, ir::IrBlockId false_id) {
    // Override del default para usar value_expr (que puede inlinear
    // un CMP single-use en la propia condicion del if).
    ctx.indent();
    ctx.out << "if (" << value_expr(ctx, cond) << ") goto "
            << label_for(true_id) << ";\n";
    ctx.indent();
    ctx.out << "goto " << label_for(false_id) << ";\n";
}

void CBackend::emit_phi_copy(EmitContext &ctx, ir::IrValueId dst,
                             ir::IrValueId src, ir::IrType t) {
    (void)t;
    // Emite la copia PHI con la expresion del src (que puede ser un
    // inline candidate -- entonces se substituye por la expresion
    // completa en lugar de @c v<id>).  El destino siempre es una
    // variable declarada (los PHIs nunca son inline candidates porque
    // su uso esta en el bloque del PHI y la def en los predecesores).
    ctx.indent();
    ctx.out << "v" << dst << " = " << value_expr(ctx, src) << ";\n";
}

// =========================================================================
//  Constantes / Mov
// =========================================================================

void CBackend::emit_const(EmitContext &ctx, ir::IrValueId dst, uint64_t imm,
                          ir::IrType t) {
    // Skip si el value es inline candidate -- su expresion se construye
    // perezosamente en el use site via @c value_expr.
    if (ctx.tx && ctx.tx->is_inline_candidate(dst)) return;
    emit_assign_lhs(ctx, dst);
    ctx.out << format_const_literal(imm, t) << ";\n";
}

void CBackend::emit_mov(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId src,
                        ir::IrType t) {
    (void)t;
    if (ctx.tx && ctx.tx->is_inline_candidate(dst)) return;
    emit_assign_lhs(ctx, dst);
    ctx.out << value_expr(ctx, src) << ";\n";
}

// =========================================================================
//  Binarias + unarias
// =========================================================================

void CBackend::emit_binop(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                          ir::IrValueId lhs, ir::IrValueId rhs, ir::IrType t) {
    if (ctx.tx && ctx.tx->is_inline_candidate(dst)) return;
    emit_assign_lhs(ctx, dst);
    // Pointer arithmetic: byte-wise, cast lhs a char* (ver build_inline_expr).
    if (t == ir::IrType::PTR && (op == ir::IrOp::ADD || op == ir::IrOp::SUB)) {
        const char *sym = (op == ir::IrOp::ADD) ? "+" : "-";
        ctx.out << "(void*)((char*)" << value_expr(ctx, lhs) << " " << sym
                << " " << value_expr(ctx, rhs) << ");\n";
        return;
    }
    if (op == ir::IrOp::FMIN || op == ir::IrOp::FMAX) {
        const char *cmp = (op == ir::IrOp::FMIN) ? "<" : ">";
        std::string l = value_expr(ctx, lhs);
        std::string r = value_expr(ctx, rhs);
        ctx.out << "(" << l << " " << cmp << " " << r << " ? " << l << " : "
                << r << ");\n";
        return;
    }
    if (op == ir::IrOp::SHR) {
        std::string utype;
        switch (t) {
        case ir::IrType::I8: utype = "uint8_t"; break;
        case ir::IrType::I16: utype = "uint16_t"; break;
        case ir::IrType::I32: utype = "uint32_t"; break;
        case ir::IrType::I64: utype = "uint64_t"; break;
        default: utype = type_for(t, false); break;
        }
        ctx.out << "(" << type_for(t, false) << ")((" << utype << ")"
                << value_expr(ctx, lhs) << " >> " << value_expr(ctx, rhs)
                << ");\n";
        return;
    }
    if (op == ir::IrOp::SAR) {
        std::string stype;
        switch (t) {
        case ir::IrType::U8: stype = "int8_t"; break;
        case ir::IrType::U16: stype = "int16_t"; break;
        case ir::IrType::U32: stype = "int32_t"; break;
        case ir::IrType::U64: stype = "int64_t"; break;
        default: stype = type_for(t, false); break;
        }
        ctx.out << "(" << type_for(t, false) << ")((" << stype << ")"
                << value_expr(ctx, lhs) << " >> " << value_expr(ctx, rhs)
                << ");\n";
        return;
    }
    ctx.out << value_expr(ctx, lhs) << " " << binop_symbol_for(op) << " "
            << value_expr(ctx, rhs) << ";\n";
}

void CBackend::emit_fma(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId a,
                        ir::IrValueId b, ir::IrValueId c, ir::IrType t) {
    if (ctx.tx && ctx.tx->is_inline_candidate(dst)) return;
    emit_assign_lhs(ctx, dst);
    // round(a*b+c) con 1 redondeo -> fma()/fmaf() de C99 (mismo std::fma que el
    // interp).  El consumidor gcc usa la misma semantica de contraccion.
    const char *fn = (t == ir::IrType::F32) ? "fmaf" : "fma";
    ctx.out << fn << "(" << value_expr(ctx, a) << ", " << value_expr(ctx, b)
            << ", " << value_expr(ctx, c) << ");\n";
}

void CBackend::emit_unop(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                         ir::IrValueId src, ir::IrType t) {
    if (ctx.tx && ctx.tx->is_inline_candidate(dst)) return;
    emit_assign_lhs(ctx, dst);
    switch (op) {
    case ir::IrOp::NEG:
    case ir::IrOp::FNEG: ctx.out << "-" << value_expr(ctx, src) << ";\n"; break;
    case ir::IrOp::NOT: ctx.out << "~" << value_expr(ctx, src) << ";\n"; break;
    case ir::IrOp::FABS:
        if (t == ir::IrType::F32) {
            ctx.out << "__builtin_fabsf(" << value_expr(ctx, src) << ");\n";
        } else {
            ctx.out << "__builtin_fabs(" << value_expr(ctx, src) << ");\n";
        }
        break;
    case ir::IrOp::FSQRT:
        if (t == ir::IrType::F32) {
            ctx.out << "__builtin_sqrtf(" << value_expr(ctx, src) << ");\n";
        } else {
            ctx.out << "__builtin_sqrt(" << value_expr(ctx, src) << ");\n";
        }
        break;
    default: ctx.out << value_expr(ctx, src) << "; /* unknown unop */\n"; break;
    }
}

void CBackend::emit_cmp(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                        ir::IrValueId lhs, ir::IrValueId rhs,
                        ir::IrType operand_type) {
    if (ctx.tx && ctx.tx->is_inline_candidate(dst)) return;
    emit_assign_lhs(ctx, dst);
    bool is_unsigned = false;
    const char *cmp = cmp_symbol_for(op, is_unsigned);
    if (is_unsigned) {
        std::string utype;
        switch (operand_type) {
        case ir::IrType::I8: utype = "uint8_t"; break;
        case ir::IrType::I16: utype = "uint16_t"; break;
        case ir::IrType::I32: utype = "uint32_t"; break;
        case ir::IrType::I64: utype = "uint64_t"; break;
        default: utype = type_for(operand_type, false); break;
        }
        ctx.out << "((" << utype << ")" << value_expr(ctx, lhs) << " " << cmp
                << " (" << utype << ")" << value_expr(ctx, rhs) << ");\n";
    } else {
        ctx.out << "(" << value_expr(ctx, lhs) << " " << cmp << " "
                << value_expr(ctx, rhs) << ");\n";
    }
}

void CBackend::emit_convert(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                            ir::IrValueId src, ir::IrType dst_type,
                            ir::IrType src_type) {
    if (ctx.tx && ctx.tx->is_inline_candidate(dst)) return;
    emit_assign_lhs(ctx, dst);
    switch (op) {
    case ir::IrOp::BITCAST: {
        bool src_is_int =
            (src_type != ir::IrType::F32 && src_type != ir::IrType::F64);
        bool dst_is_int =
            (dst_type != ir::IrType::F32 && dst_type != ir::IrType::F64);
        if (src_is_int && dst_is_int) {
            ctx.out << cast_for(dst_type, false) << value_expr(ctx, src)
                    << ";\n";
        } else {
            std::string e = value_expr(ctx, src);
            ctx.out << "({ " << type_for(dst_type, false) << " __tmp; "
                    << "__builtin_memcpy(&__tmp, &(" << e << "), "
                    << "sizeof(__tmp)); __tmp; });\n";
        }
        return;
    }
    case ir::IrOp::ITOF:
    case ir::IrOp::UITOF:
    case ir::IrOp::FTOI:
    case ir::IrOp::FTOUI:
    case ir::IrOp::F32TOF64:
    case ir::IrOp::F64TOF32:
    case ir::IrOp::CAST:
    case ir::IrOp::TRUNC: {
        ctx.out << cast_for(dst_type, false) << value_expr(ctx, src) << ";\n";
        return;
    }
    case ir::IrOp::ZEXT: {
        std::string utype;
        switch (src_type) {
        case ir::IrType::I8: utype = "uint8_t"; break;
        case ir::IrType::I16: utype = "uint16_t"; break;
        case ir::IrType::I32: utype = "uint32_t"; break;
        case ir::IrType::I64: utype = "uint64_t"; break;
        default: utype = type_for(src_type, false); break;
        }
        ctx.out << cast_for(dst_type, false) << "(" << utype << ")"
                << value_expr(ctx, src) << ";\n";
        return;
    }
    case ir::IrOp::SEXT: {
        std::string stype;
        switch (src_type) {
        case ir::IrType::U8: stype = "int8_t"; break;
        case ir::IrType::U16: stype = "int16_t"; break;
        case ir::IrType::U32: stype = "int32_t"; break;
        case ir::IrType::U64: stype = "int64_t"; break;
        default: stype = type_for(src_type, false); break;
        }
        ctx.out << cast_for(dst_type, false) << "(" << stype << ")"
                << value_expr(ctx, src) << ";\n";
        return;
    }
    default:
        ctx.out << cast_for(dst_type, false) << value_expr(ctx, src) << ";\n";
        return;
    }
}

// =========================================================================
//  Memoria
// =========================================================================

void CBackend::emit_alloca(EmitContext &ctx, ir::IrValueId dst,
                           uint64_t size_bytes) {
    //  AS inc.3: un ALLOCA register-bound NO reserva storage; su
    // variable C ya se declaro con register-pin en emit_local_decl.
    if (reg_binding_for(ctx, dst)) {
        return;
    }
    ctx.indent();
    ctx.out << "{\n";
    ctx.indent_level++;
    ctx.indent();
    ctx.out << "static uint8_t __alloca_storage_" << dst << "[" << size_bytes
            << "];\n";
    ctx.indent();
    ctx.out << "v" << dst << " = (void*)__alloca_storage_" << dst << ";\n";
    ctx.indent_level--;
    ctx.indent();
    ctx.out << "}\n";
}

/**
 * @brief Intenta reconocer el patron @c "ADD base + const_offset" como
 *        acceso a un field de una clase con tipo concreto conocido.
 * @return Cadena C @c "base->fieldname" si aplica, vacio en caso contrario.
 *
 * Esta optimizacion convierte aritmetica byte-wise generica:
 *   @c *(int32_t*)((char*)v0 + 24)
 * en acceso tipado:
 *   @c v0->count
 *
 * Ventajas:
 *   - Codigo C legible (igual a lo escrito a mano).
 *   - GCC hace mejor alias analysis (sabe el tipo del field).
 *   - Habilita devirtualizacion downstream.
 *   - Compatible con @c -Wstrict-aliasing (no rompe TBAA).
 */
std::string CBackend::try_match_field_access(EmitContext &ctx,
                                             ir::IrValueId addr,
                                             ir::IrType type) const {
    (void)type;
    if (!ctx.tx) return "";
    const ir::IrInstr *def = ctx.tx->def_of(addr);
    if (!def) return "";
    if (def->op != ir::IrOp::ADD) return "";
    if (def->operands.size() < 2) return "";
    if (def->type != ir::IrType::PTR) return "";

    ir::IrValueId base = def->operands[0];
    ir::IrValueId off = def->operands[1];

    const ir::IrInstr *off_def = ctx.tx->def_of(off);
    if (!off_def || off_def->op != ir::IrOp::CONST) return "";
    uint64_t offset = off_def->imm;

    auto it = concrete_type_.find(base);
    if (it == concrete_type_.end()) return "";
    const ir::IrClass *cls = lookup_class(it->second);
    if (!cls) return "";

    // Buscar field por offset en coordenadas del IR (que incluyen el
    // ObjectHeader de 24 bytes que NO emitimos en Mode TRIVIAL).
    // Walking inheritance chain: si @c f.offset < super.size_bytes,
    // el field vive en @c __base; iterar recursivamente con la super
    // para construir @c "base->__base.field" o @c "base->__base.__base.field".
    std::string base_expr = value_expr(ctx, base);
    std::string suffix;
    const ir::IrClass *cur = cls;
    while (cur != nullptr) {
        // Si super existe y el offset cae dentro de su layout,
        // bajar un nivel.
        const ir::IrClass *super =
            (cur->super_name.empty() || cur->super_name == "Object")
                ? nullptr
                : lookup_class(cur->super_name);
        if (super != nullptr && offset < super->size_bytes) {
            suffix += "->__base";
            cur = super;
            continue;
        }
        // No baja mas; buscar field directamente en @c cur.
        for (const auto &f : cur->fields) {
            if (f.offset == offset) {
                return base_expr + suffix + (suffix.empty() ? "->" : ".") +
                       f.name;
            }
        }
        break;
    }
    return "";
}

void CBackend::emit_load(EmitContext &ctx, ir::IrValueId dst,
                         ir::IrValueId addr, ir::IrType t, bool is_host_ptr) {
    (void)is_host_ptr;
    emit_assign_lhs(ctx, dst);
    //  AS inc.3: LOAD desde un slot register-bound = leer la variable
    // C register directamente (no deref de un puntero).
    if (reg_binding_for(ctx, addr)) {
        ctx.out << "v" << addr << ";\n";
        return;
    }
    // Pattern-match field access: @c "ADD base + const_N" donde base
    // tiene tipo concreto -> emitir @c "base->fieldname" tipado.
    // Si el patron no aplica, emit el load generico con cast.
    std::string field_expr = try_match_field_access(ctx, addr, t);
    if (!field_expr.empty()) {
        ctx.out << field_expr << ";\n";
        return;
    }
    ctx.out << "*(" << type_for(t, false) << "*)" << value_expr(ctx, addr)
            << ";\n";
}

void CBackend::emit_store(EmitContext &ctx, ir::IrValueId val,
                          ir::IrValueId addr, ir::IrType t, bool is_host_ptr) {
    (void)is_host_ptr;
    ctx.indent();
    //  AS inc.3: STORE a un slot register-bound = asignar la variable
    // C register directamente.
    if (reg_binding_for(ctx, addr)) {
        ctx.out << "v" << addr << " = " << cast_for(t, false)
                << value_expr(ctx, val) << ";\n";
        return;
    }
    std::string field_expr = try_match_field_access(ctx, addr, t);
    if (!field_expr.empty()) {
        ctx.out << field_expr << " = " << cast_for(t, false)
                << value_expr(ctx, val) << ";\n";
        return;
    }
    ctx.out << "*(" << type_for(t, false) << "*)" << value_expr(ctx, addr)
            << " = " << cast_for(t, false) << value_expr(ctx, val) << ";\n";
}

void CBackend::emit_inline_asm(EmitContext &ctx, const ir::IrInstr &ins) {
    //  AS inc.3: materializar IrOp::INLINE_ASM como GCC extended asm.
    //   imm bits 0..5 = quals/efectos (volatile/nomem/preserves_flags/
    //   pure/clobbers_memory/clobbers_flags); bits 8..31 = asm-id (indice
    //   en fn->asm_clobber_lists).  func_name = cuerpo NASM Intel verbatim.
    //   operands = slots ALLOCA de las vars register() (listadas como
    //   inout "+r"/"+x"; el register-pin lo da la declaracion en C).
    const uint64_t q = ins.imm;
    const bool clob_mem = (q >> 4) & 1u;
    const bool clob_flags = (q >> 5) & 1u;
    const uint64_t asm_id = (q >> 8) & 0xFFFFFFull;

    ctx.indent();
    // volatile SIEMPRE: el asm nunca debe ser movido/eliminado por GCC.
    ctx.out << "__asm__ __volatile__(\n";
    ctx.indent_level++;
    // Cambiar a sintaxis Intel sin prefijo '%' (el cuerpo es NASM Intel).
    ctx.indent();
    ctx.out << "\".intel_syntax noprefix\\n\\t\"\n";
    // Cuerpo: una linea fuente por string literal, trim + escape.
    {
        std::string line;
        auto flush_line = [&]() {
            size_t b = line.find_first_not_of(" \t\r");
            if (b == std::string::npos) {
                line.clear();
                return;
            }
            size_t e = line.find_last_not_of(" \t\r");
            std::string body = line.substr(b, e - b + 1);
            std::string esc;
            for (char c : body) {
                if (c == '\\' || c == '"') esc.push_back('\\');
                esc.push_back(c);
            }
            ctx.indent();
            ctx.out << "\"" << esc << "\\n\\t\"\n";
            line.clear();
        };
        for (char c : ins.func_name) {
            if (c == '\n')
                flush_line();
            else
                line.push_back(c);
        }
        flush_line();
    }
    // Volver a AT&T (estado por defecto que GCC asume tras el bloque).
    ctx.indent();
    ctx.out << "\".att_syntax prefix\"\n";
    // Operandos de salida (inout): las vars register() ligadas.  El pin
    // al registro fisico lo da la declaracion `register T v asm("reg")`,
    // por eso basta el constraint generico "+r" (GP) / "+x" (vector).
    ctx.indent();
    ctx.out << ": ";
    bool first_op = true;
    for (ir::IrValueId opv : ins.operands) {
        const ir::AsmRegBinding *rb = reg_binding_for(ctx, opv);
        if (!rb) continue;
        if (!first_op) ctx.out << ", ";
        first_op = false;
        ctx.out << (rb->is_vector ? "\"+x\"(v" : "\"+r\"(v") << opv << ")";
    }
    ctx.out << "\n";
    // Sin operandos de entrada puros (todo va por la lista inout).
    ctx.indent();
    ctx.out << ":\n";
    // Clobbers: explicitos del usuario + memory/flags si se marcaron.
    ctx.indent();
    ctx.out << ": ";
    bool first_cl = true;
    if (ctx.fn && asm_id < ctx.fn->asm_clobber_lists.size()) {
        for (const auto &c : ctx.fn->asm_clobber_lists[asm_id]) {
            if (!first_cl) ctx.out << ", ";
            first_cl = false;
            ctx.out << "\"" << c << "\"";
        }
    }
    if (clob_mem) {
        if (!first_cl) ctx.out << ", ";
        first_cl = false;
        ctx.out << "\"memory\"";
    }
    if (clob_flags) {
        if (!first_cl) ctx.out << ", ";
        first_cl = false;
        ctx.out << "\"cc\"";
    }
    ctx.out << ");\n";
    ctx.indent_level--;
}

void CBackend::emit_raw_alloc(EmitContext &ctx, ir::IrValueId dst,
                              ir::IrValueId size) {
    emit_assign_lhs(ctx, dst);
    if (opts_.gc == GcMode::Boehm) {
        ctx.out << "GC_malloc((size_t)" << value_expr(ctx, size) << ");\n";
    } else {
        ctx.out << "malloc((size_t)" << value_expr(ctx, size) << ");\n";
    }
}

void CBackend::emit_raw_free(EmitContext &ctx, ir::IrValueId ptr) {
    ctx.indent();
    if (opts_.gc == GcMode::Boehm) {
        ctx.out << "(void)" << value_expr(ctx, ptr) << "; /* Boehm: no-op */\n";
    } else {
        ctx.out << "free(" << value_expr(ctx, ptr) << ");\n";
    }
}

// =========================================================================
//  Llamadas
// =========================================================================

void CBackend::emit_call(EmitContext &ctx, ir::IrValueId dst,
                         const std::string &func_name,
                         ir::IrValueList args,
                         ir::IrType ret_type) {
    // Skip llamadas a @c __module_init: la funcion no se emite (es para
    // VestaVM runtime).  Las clases en C son literales con structs
    // estaticos -- nada que inicializar dinamicamente.
    if (func_name.rfind("__module_init", 0) == 0) {
        if (opts_.emit_comments) {
            ctx.indent();
            ctx.out
                << "/* __module_init() omitido: clases son literales en C */\n";
        }
        return;
    }

    // CALLN nativa: el func_name tiene forma "lib_path:sym".  Lo
    // tratamos como un call C normal al simbolo @c sym, asumiendo
    // que el usuario enlazara con la libreria correspondiente.
    // Mapping especial para los builtins de @c vesta_io (vio_*) que
    // exponen una API estandar de print -> bridge a stdio C, para que
    // el .c sea standalone (sin necesitar @c vesta_io.dll).
    auto colon = func_name.find(':');
    if (colon != std::string::npos) {
        std::string lib = func_name.substr(0, colon);
        std::string sym = func_name.substr(colon + 1);
        emit_native_call(ctx, dst, lib, sym, args, ret_type);
        return;
    }

    // Detect early: es esta llamada a @c __new_<X> con escape-free dst?
    // Si si, emitir STACK ALLOC en lugar de heap.  Tiene que decidirse
    // ANTES de emit_assign_lhs para evitar @c "v0 = Counter __stk..." rota.
    std::string new_class_name;
    if (func_name.rfind("__new_", 0) == 0) {
        std::string class_name = func_name.substr(6);
        if (lookup_class(class_name)) {
            new_class_name = class_name;
            if (dst != ir::IR_NO_VALUE) {
                concrete_type_[dst] = class_name;
            }
        }
    }

    if (!new_class_name.empty() && dst != ir::IR_NO_VALUE &&
        stack_alloc_candidates_.count(dst)) {
        // === STACK ALLOC PATH ===
        //   Class __stk_<dst> = {0};
        //   Class__ctor(&__stk_<dst>, args...);
        //   Class *v<dst> = &__stk_<dst>;
        // GCC -O3 hace SROA y elimina __stk_<dst> -- equivalente o
        // mejor que C++ stack alloc.
        const ir::IrClass *cls = lookup_class(new_class_name);
        ctx.indent();
        // Inicializacion: empty struct + @c {0} da warning de
        // "excess elements"; chequear si la clase tiene fields
        // declarados o solo metodos.
        bool has_any_field = (cls && !cls->fields.empty());
        ctx.out << new_class_name << " __stk_" << dst;
        if (has_any_field) ctx.out << " = {0}";
        ctx.out << ";\n";
        bool has_ctor = false;
        if (cls) {
            for (const auto &m : cls->methods) {
                if (m.is_constructor) {
                    has_ctor = true;
                    break;
                }
            }
        }
        if (has_ctor) {
            ctx.indent();
            ctx.out << new_class_name << "__ctor(&__stk_" << dst;
            for (auto a : args) {
                ctx.out << ", " << value_expr(ctx, a);
            }
            ctx.out << ");\n";
        }
        emit_assign_lhs(ctx, dst);
        ctx.out << "&__stk_" << dst << ";\n";
        // Si la clase tiene destructor, registrar para LIFO cleanup
        // al exit del scope (RAII).  Si no, omitir (no-op evita
        // ruido en el output C).
        if (cls && cls->has_destructor) {
            stack_alloc_in_fn_.emplace_back(dst, new_class_name);
        }
        return;
    }

    // === HEAP ALLOC / NORMAL CALL PATH ===
    if (ret_type != ir::IrType::VOID && dst != ir::IR_NO_VALUE) {
        emit_assign_lhs(ctx, dst);
    } else {
        ctx.indent();
    }
    std::string callee =
        new_class_name.empty() ? func_name : new_class_name + "__new";
    ctx.out << sanitize_name(callee) << "(";
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) ctx.out << ", ";
        ctx.out << value_expr(ctx, args[i]);
    }
    ctx.out << ");\n";
}

void CBackend::emit_callvirt(EmitContext &ctx, ir::IrValueId dst,
                             ir::IrValueId obj, uint32_t vtable_idx,
                             ir::IrValueList args,
                             ir::IrType ret_type) {
    // Estrategia: SIEMPRE intentar devirtualizar.  Si el tipo concreto
    // del receiver es conocido (via @c concrete_type_), buscar el
    // metodo en @c cls.methods por vtable_index y emitir DIRECT CALL.
    // Si no se puede determinar, caer a vtable lookup (Mode VIRTUAL).
    //
    // En Mode TRIVIAL (sin vtable), si no podemos devirtualizar,
    // emitimos error -- el modulo no clasifica como TRIVIAL en tal caso.
    std::string class_name;
    auto it = concrete_type_.find(obj);
    if (it != concrete_type_.end()) {
        class_name = it->second;
    }

    const ir::IrClass *cls = lookup_class(class_name);
    if (cls != nullptr) {
        // Buscar metodo con @c vtable_index = vtable_idx.
        const ir::IrMethod *method = nullptr;
        for (const auto &m : cls->methods) {
            if (m.vtable_index == static_cast<int32_t>(vtable_idx)) {
                method = &m;
                break;
            }
        }
        if (method) {
            // DEVIRTUALIZED: emit direct call.
            if (ret_type != ir::IrType::VOID && dst != ir::IR_NO_VALUE) {
                emit_assign_lhs(ctx, dst);
            } else {
                ctx.indent();
            }
            // Si el metodo esta definido en una super-clase (heredado
            // puro, no override), el simbolo @c ir_fn_name pertenece
            // a esa super.  El receiver @c obj es de tipo @c cls;
            // necesitamos pasar @c &obj->__base[->__base...] para que
            // el tipo del puntero coincida con el del parametro de la
            // super.  Construimos la cadena caminando @c super_name
            // hasta @c defining_class.
            std::string this_expr = value_expr(ctx, obj);
            if (!method->defining_class.empty() &&
                method->defining_class != cls->name) {
                std::string chain = "&" + this_expr;
                const ir::IrClass *cur = cls;
                while (cur != nullptr && cur->name != method->defining_class) {
                    chain += "->__base";
                    if (cur->super_name.empty() || cur->super_name == "Object")
                        break;
                    cur = lookup_class(cur->super_name);
                }
                this_expr = chain;
            }
            ctx.out << method->ir_fn_name << "(" << this_expr;
            for (size_t i = 0; i < args.size(); ++i) {
                ctx.out << ", " << value_expr(ctx, args[i]);
            }
            ctx.out << ");\n";
            // Trackear tipo concreto del resultado si es un metodo que
            // devuelve PTR (devolvera *otra* clase o la misma; sin
            // metadata adicional no podemos saber, pero podemos
            // propagar conservadoramente vacio).
            return;
        }
    }

    // FALLBACK: no podemos devirtualizar.  En Mode VIRTUAL emitiriamos
    // vtable lookup, pero todavia no tenemos infraestructura.  Por
    // ahora emit un comentario indicando que se requiere Mode VIRTUAL.
    ctx.indent();
    ctx.out << "/* CALLVIRT no devirtualizable (idx=" << vtable_idx << ", obj=v"
            << obj << "): se requiere Mode VIRTUAL con vtable */\n";
    if (dst != ir::IR_NO_VALUE) {
        emit_assign_lhs(ctx, dst);
        ctx.out << "0;\n";
    }
}

void CBackend::emit_call_closure(EmitContext &ctx, ir::IrValueId dst,
                                 ir::IrValueId fn_addr,
                                 ir::IrValueList args,
                                 ir::IrType ret_type, const ir::IrInstr &ins) {
    (void)ins;
    // Layout IR: @c callclosure func_ptr=%fn_addr, operands=[%env, args...]
    // donde @c fn_addr y @c env ya estan cargados como @c i64.  El
    // primer argumento del callee es siempre @c env (void*).
    if (args.empty()) {
        ctx.indent();
        ctx.out << "/* CALLCLOSURE sin env -- skip */\n";
        return;
    }
    ir::IrValueId env = args[0];
    std::vector<ir::IrValueId> real_args(args.begin() + 1, args.end());

    if (ret_type != ir::IrType::VOID && dst != ir::IR_NO_VALUE) {
        emit_assign_lhs(ctx, dst);
    } else {
        ctx.indent();
    }
    std::string ret_t = type_for(ret_type, false);
    // Construir el tipo del function pointer: T (*)(void*, T_arg0, ...)
    std::string fn_t = ret_t + "(*)(void*";
    for (size_t i = 0; i < real_args.size(); ++i) {
        fn_t += ", ";
        ir::IrType at = ir::IrType::I64;
        if (ctx.fn && real_args[i] < ctx.fn->values.size()) {
            at = ctx.fn->values[real_args[i]].type;
        }
        fn_t += type_for(at, false);
    }
    fn_t += ")";

    ctx.out << "((" << fn_t << ")(intptr_t)" << value_expr(ctx, fn_addr) << ")"
            << "((void*)(intptr_t)" << value_expr(ctx, env);
    for (auto a : real_args) {
        ctx.out << ", " << value_expr(ctx, a);
    }
    ctx.out << ");\n";
}

void CBackend::emit_spawn_trampoline_call(EmitContext &ctx,
                                          ir::IrValueId fn_ptr, size_t argc,
                                          const std::string &args_var) {
    (void)fn_ptr;
    spawn_trampoline_arities_.insert(argc);
    ctx.indent();
    ctx.out << "vx_spawn(__vx_trampoline_" << argc << ", (int64_t)(intptr_t)"
            << args_var << ");\n";
}

void CBackend::emit_callm(EmitContext &ctx, ir::IrValueId dst,
                          ir::IrValueId obj, ir::IrValueId method_ptr,
                          ir::IrValueList args,
                          ir::IrType ret_type) {
    // En port C el dispatch dinamico via @c MethodInfo* no es viable
    // sin ClassRegistry runtime.  La devirtualizacion compile-time
    // (en lowering Vesta) reescribe el patron a CALLVIRT cuando el tipo
    // concreto del receiver es conocido.  Si llegamos aqui con CALLM,
    // es que el receptor es genuinamente abstracto sin info -- emit
    // stub que el usuario puede completar manualmente.
    (void)method_ptr;
    if (opts_.emit_comments) {
        ctx.indent();
        ctx.out << "/* CALLM no devirtualizable en compile time (receptor "
                   "abstracto) */\n";
    }
    if (ret_type != ir::IrType::VOID && dst != ir::IR_NO_VALUE) {
        emit_assign_lhs(ctx, dst);
        ctx.out << "0;\n";
    }
    (void)obj;
    (void)args;
    fprintf(stderr,
            "[port C] CALLM sin tipo concreto resuelto (receptor abstracto)\n");
}

void CBackend::emit_call_indirect(EmitContext &ctx, ir::IrValueId dst,
                                  ir::IrValueId fn_ptr,
                                  ir::IrValueList args,
                                  ir::IrType ret_type) {
    if (ret_type != ir::IrType::VOID && dst != ir::IR_NO_VALUE) {
        emit_assign_lhs(ctx, dst);
    } else {
        ctx.indent();
    }
    ctx.out << "((" << type_for(ret_type, false) << "(*)(";
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) ctx.out << ", ";
        ctx.out << "uintptr_t";
    }
    ctx.out << "))" << value_expr(ctx, fn_ptr) << ")(";
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) ctx.out << ", ";
        ctx.out << "(uintptr_t)" << value_expr(ctx, args[i]);
    }
    ctx.out << ");\n";
}

} // namespace port
