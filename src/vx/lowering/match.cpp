/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/match.cpp
 * @brief Bajada de `match`: despachar por la FORMA de un valor.
 *
 * `match` no es solo para tipos suma: tambien despacha por un entero, un
 * caracter, un rango o una cadena, y cada uno se baja distinto porque lo que
 * los distingue es distinto -- una tabla densa de saltos cuando los valores
 * estan juntos, una cadena de comparaciones cuando no, y una comparacion de
 * bytes cuando lo que se mira son cadenas.  Elegir esa forma es todo el trabajo
 * de este fichero.
 */
#include "vx/lowering.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {

namespace {
// Evalua un patron de valor de un match escalar (IntLit / CharLit / -IntLit)
// a int64.  Los patrones estan validados por el type checker.
static int64_t eval_scalar_pattern(const ast::Expr *p) {
    if (!p) return 0;
    if (p->kind == ast::NodeKind::IntLitExpr)
        return (int64_t)static_cast<const ast::IntLitExpr *>(p)->value;
    if (p->kind == ast::NodeKind::CharLitExpr)
        return (int64_t)static_cast<const ast::CharLitExpr *>(p)->codepoint;
    if (p->kind == ast::NodeKind::UnaryExpr) {
        const auto *u = static_cast<const ast::UnaryExpr *>(p);
        if (u->op == ast::UnOp::Neg)
            return -eval_scalar_pattern(u->operand.get());
    }
    return 0;
}
} // namespace
/**
 * @copydoc vx::Lowering::emit_case_bst
 */
void Lowering::emit_case_bst(
    ir::IrValueId value,
    const std::vector<std::pair<int64_t, ir::IrBlockId>> &cases, size_t lo,
    size_t hi, ir::IrBlockId cur, ir::IrBlockId default_bb, const char *prefix,
    uint32_t source_line) {
    current_block_ = cur;
    // Con dos o menos, comparar uno a uno sale mas barato que seguir
    // partiendo: el arbol ahorra comparaciones, pero cada nodo cuesta un
    // bloque y un salto.
    if (hi - lo <= 2) {
        for (size_t k = lo; k < hi; ++k) {
            const ir::IrValueId tc =
                emit_const(ir::IrType::I64,
                           static_cast<uint64_t>(cases[k].first), source_line);
            const ir::IrValueId eq = emit_ir_binop(
                ir::IrOp::CMP_EQ, value, tc, ir::IrType::BOOL, source_line);
            const ir::IrBlockId nb =
                fn_->new_block(std::string(prefix) + "_next");
            emit_br_cond(eq, cases[k].second, nb, source_line);
            current_block_ = nb;
        }
        emit_br(default_bb, source_line);
        return;
    }
    const size_t mid = lo + (hi - lo) / 2;
    const ir::IrValueId tc = emit_const(
        ir::IrType::I64, static_cast<uint64_t>(cases[mid].first), source_line);
    // Con signo: los casos vienen ordenados como numeros, no como bits.
    const ir::IrValueId lt = emit_ir_binop(ir::IrOp::CMP_LT, value, tc,
                                           ir::IrType::BOOL, source_line);
    const ir::IrBlockId lb = fn_->new_block(std::string(prefix) + "_lt");
    const ir::IrBlockId rb = fn_->new_block(std::string(prefix) + "_ge");
    emit_br_cond(lt, lb, rb, source_line);
    emit_case_bst(value, cases, lo, mid, lb, default_bb, prefix, source_line);
    emit_case_bst(value, cases, mid, hi, rb, default_bb, prefix, source_line);
}

ir::IrValueId Lowering::lower_match_scalar(ast::MatchExpr *e) {
    // 1. Valor del scrutinee (entero/char).  Se compara como i64.
    ir::IrValueId tag_v = lower_expr(e->scrutinee.get());
    if (tag_v == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    const ir::IrBlockId merge_bb = fn_->new_block("smatch_end");
    ssize_t default_arm_idx = -1;
    for (size_t i = 0; i < e->arms.size(); ++i)
        if (!e->arms[i].value_pattern && e->arms[i].variant_name == "_") {
            default_arm_idx = (ssize_t)i;
            break;
        }
    ir::IrBlockId default_bb =
        (default_arm_idx >= 0) ? fn_->new_block("smatch_default") : merge_bb;

    std::vector<ir::IrBlockId> arm_blocks(e->arms.size(), ir::IR_NO_BLOCK);
    std::vector<ir::IrBlockId> arm_fall_bbs(e->arms.size(), ir::IR_NO_BLOCK);
    for (size_t i = 0; i < e->arms.size(); ++i)
        if ((ssize_t)i != default_arm_idx && e->arms[i].value_pattern)
            arm_blocks[i] = fn_->new_block("smatch_arm");

    bool any_guard = false;
    for (const auto &a : e->arms)
        if (a.guard) {
            any_guard = true;
            break;
        }
    // Rangos `case a..b =>`: si hay alguno, forzamos dispatch LINEAL en orden
    // de arm (preserva la prioridad first-match y permite el check
    // `lo<=v<(=)hi`).
    bool any_range = false;
    for (const auto &a : e->arms)
        if (a.value_pattern_hi) {
            any_range = true;
            break;
        }

    std::vector<std::pair<int64_t, ir::IrBlockId>> sw_cases;
    for (size_t i = 0; i < e->arms.size(); ++i) {
        if ((ssize_t)i == default_arm_idx || !e->arms[i].value_pattern)
            continue;
        if (e->arms[i].value_pattern_hi) continue; // rango: no es caso puntual
        sw_cases.push_back({eval_scalar_pattern(e->arms[i].value_pattern.get()),
                            arm_blocks[i]});
    }
    std::sort(sw_cases.begin(), sw_cases.end());

    // Dispatch DENSO O(1): marker SWITCH_DENSE (island nativo en JIT).
    if (!any_guard && !any_range && sw_cases.size() >= 4) {
        const int64_t lo = sw_cases.front().first, hi = sw_cases.back().first;
        const int64_t range = hi - lo + 1, n = (int64_t)sw_cases.size();
        if (lo >= 0 && range >= n && range <= 2 * n && range <= 256) {
            std::vector<uint32_t> table((size_t)range, (uint32_t)default_bb);
            for (const auto &c : sw_cases)
                table[(size_t)(c.first - lo)] = (uint32_t)c.second;
            ir::IrInstr sd{};
            sd.op = ir::IrOp::SWITCH_DENSE;
            sd.type = ir::IrType::VOID;
            sd.dst = ir::IR_NO_VALUE;
            sd.operands = {tag_v};
            sd.imm = (uint64_t)lo;
            sd.target_block = default_bb;
            sd.jump_targets = std::move(table);
            sd.source_line = e->loc.line;
            emit(current_block_, std::move(sd));
        }
    }

    const bool use_bst = !any_guard && !any_range && sw_cases.size() >= 5;
    if (use_bst) {
        // BST balanceado O(log N): cmp_lt en nodos, cmp_eq en hojas.
        emit_case_bst(tag_v, sw_cases, 0, sw_cases.size(), current_block_,
                      default_bb, "s", e->loc.line);
    } else {
        // Cadena lineal en orden de arm (pocos casos, guards, o rangos).
        // Helper: emite BR_COND cmp -> target, else fall.
        auto emit_cmp_br = [&](ir::IrOp op, ir::IrValueId a, int64_t b,
                               ir::IrBlockId target, ir::IrBlockId fall,
                               uint32_t line) {
            ir::IrValueId cmp = fn_->new_value(ir::IrType::BOOL);
            ir::IrValueId tc = emit_const(ir::IrType::I64, (uint64_t)b, line);
            ir::IrInstr cm{};
            cm.op = op;
            cm.type = ir::IrType::BOOL;
            cm.dst = cmp;
            cm.operands = {a, tc};
            cm.source_line = line;
            emit(current_block_, std::move(cm));
            emit_br_cond(cmp, target, fall, line);
        };
        for (size_t i = 0; i < e->arms.size(); ++i) {
            if ((ssize_t)i == default_arm_idx || !e->arms[i].value_pattern)
                continue;
            const uint32_t ln = e->arms[i].loc.line;
            const int64_t lo =
                eval_scalar_pattern(e->arms[i].value_pattern.get());
            ir::IrBlockId fall = fn_->new_block("smatch_next");
            arm_fall_bbs[i] = fall;
            if (e->arms[i].value_pattern_hi) {
                // Rango `lo <= v <(=) hi`: dos comparaciones.
                const int64_t hi =
                    eval_scalar_pattern(e->arms[i].value_pattern_hi.get());
                ir::IrBlockId mid = fn_->new_block("smatch_rmid");
                emit_cmp_br(ir::IrOp::CMP_GE, tag_v, lo, mid, fall, ln);
                current_block_ = mid;
                block_terminated_ = false;
                const ir::IrOp hi_op = e->arms[i].range_inclusive
                                           ? ir::IrOp::CMP_LE
                                           : ir::IrOp::CMP_LT;
                emit_cmp_br(hi_op, tag_v, hi, arm_blocks[i], fall, ln);
            } else {
                emit_cmp_br(ir::IrOp::CMP_EQ, tag_v, lo, arm_blocks[i], fall,
                            ln);
            }
            current_block_ = fall;
            block_terminated_ = false;
        }
        emit_br(default_bb, e->loc.line);
    }

    // 4. Bodies (con guard opcional).  SSA N-vias: snapshot del scope de entry,
    // cada arm parte de ese entry, y en el merge se insertan PHIs para las
    // variables mutadas (sin esto, una var ASIGNADA en un arm se quedaba con el
    // valor del ultimo arm bajado).
    std::vector<std::unordered_map<std::string, ir::IrValueId>> entry_scopes =
        scopes_;
    std::vector<std::vector<std::unordered_map<std::string, ir::IrValueId>>>
        arm_scopes(e->arms.size());
    std::vector<ir::IrBlockId> arm_preds(e->arms.size(), ir::IR_NO_BLOCK);
    std::vector<char> arm_reaches(e->arms.size(), 0);
    for (size_t i = 0; i < e->arms.size(); ++i) {
        const auto &arm = e->arms[i];
        const ir::IrBlockId target =
            ((ssize_t)i == default_arm_idx) ? default_bb : arm_blocks[i];
        if (target == ir::IR_NO_BLOCK) continue;
        current_block_ = target;
        block_terminated_ = false;
        scopes_ = entry_scopes; // cada arm parte del mismo entry
        push_scope();
        if (arm.guard) {
            ir::IrValueId g = lower_expr(arm.guard.get());
            ir::IrBlockId body_bb = fn_->new_block("smatch_body");
            ir::IrBlockId gfall = (arm_fall_bbs[i] != ir::IR_NO_BLOCK)
                                      ? arm_fall_bbs[i]
                                      : default_bb;
            emit_br_cond(g, body_bb, gfall, arm.loc.line);
            current_block_ = body_bb;
            block_terminated_ = false;
        }
        if (arm.body) lower_stmt(arm.body.get());
        if (!block_terminated_) {
            arm_reaches[i] = 1;
            arm_preds[i] = current_block_;
            arm_scopes[i] = scopes_; // snapshot ANTES del pop
            emit_br(merge_bb, arm.loc.line);
        }
        pop_scope();
    }

    current_block_ = merge_bb;
    block_terminated_ = false;
    emit_match_arm_phis(entry_scopes, arm_scopes, arm_preds, arm_reaches,
                        merge_bb, e->loc.line);
    return ir::IR_NO_VALUE; // statement-like (VOID)
}

ir::IrValueId Lowering::lower_match_string(ast::MatchExpr *e) {
    ir::IrValueId s_h = lower_expr(e->scrutinee.get());
    if (s_h == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    // FAST PATH: la longitud en bytes es el discriminador MAS BARATO (O(1), sin
    // iterar bytes).  Despachamos por longitud primero; la mayoria de inputs
    // que no coinciden con ningun case se descartan aqui sin una sola
    // comparacion. Dentro de un bucket (misma longitud) verificamos byte-a-byte
    // (longitud igual).  Tipico: 1 comparacion de tamano + 1 comparacion de
    // bytes.
    //
    // Dos modos, mismo algoritmo:
    //   * native_poo_ (AOT / Embed, SIN GC): value-string {ptr,len,cap}.  La
    //     longitud es un campo (emit_native_str_len) y la verificacion es
    //     emit_strcmp_dispatched(ptr,len,...) -- todo AOT-nativo.
    //   * GC (interp / JIT): StringObject via STRGETBYTES + STRCMP.
    ir::IrValueId s_ptr = ir::IR_NO_VALUE; // solo native
    ir::IrValueId L_v;
    if (native_poo_) {
        s_ptr = emit_native_str_data_ptr(s_h, e->loc.line);
        L_v = emit_native_str_len(s_h, e->loc.line);
    } else {
        L_v = fn_->new_value(ir::IrType::I64);
        ir::IrInstr gb{};
        gb.op = ir::IrOp::STRGETBYTES;
        gb.type = ir::IrType::I64;
        gb.dst = L_v;
        gb.operands = {s_h};
        gb.source_line = e->loc.line;
        emit(current_block_, std::move(gb));
    }

    ssize_t default_arm_idx = -1;
    for (size_t i = 0; i < e->arms.size(); ++i)
        if (!e->arms[i].value_pattern && e->arms[i].variant_name == "_") {
            default_arm_idx = (ssize_t)i;
            break;
        }

    // Agrupar arms por LONGITUD en bytes del literal (orden estable).  La
    // longitud del StringLitExpr::value = bytes UTF-8, igual que STRGETBYTES.
    std::vector<int64_t> distinct_lens;
    std::map<int64_t, std::vector<size_t>> by_len;
    for (size_t i = 0; i < e->arms.size(); ++i) {
        if ((ssize_t)i == default_arm_idx || !e->arms[i].value_pattern)
            continue;
        auto *sl =
            static_cast<ast::StringLitExpr *>(e->arms[i].value_pattern.get());
        const int64_t L = (int64_t)sl->value.size();
        if (!by_len.count(L)) distinct_lens.push_back(L);
        by_len[L].push_back(i);
    }

    const ir::IrBlockId merge_bb = fn_->new_block("strmatch_end");
    ir::IrBlockId default_bb =
        (default_arm_idx >= 0) ? fn_->new_block("strmatch_default") : merge_bb;
    std::map<int64_t, ir::IrBlockId> verify_bb;
    for (int64_t L : distinct_lens)
        verify_bb[L] = fn_->new_block("strmatch_verify");
    std::vector<ir::IrBlockId> arm_blocks(e->arms.size(), ir::IR_NO_BLOCK);
    for (size_t i = 0; i < e->arms.size(); ++i)
        if ((ssize_t)i != default_arm_idx && e->arms[i].value_pattern)
            arm_blocks[i] = fn_->new_block("strmatch_arm");

    // Dispatch por LONGITUD (entero): SWITCH_DENSE si las longitudes son densas
    // (comun: 3,4,5,6...), BST O(log N) si dispersas y muchas, else lineal.
    std::vector<std::pair<int64_t, ir::IrBlockId>> sw_cases;
    for (int64_t L : distinct_lens)
        sw_cases.push_back({L, verify_bb[L]});
    std::sort(sw_cases.begin(), sw_cases.end());
    ir::IrValueId h_v = L_v; // el dispatch de abajo compara contra L_v
    if (!sw_cases.empty()) {
        const int64_t lo = sw_cases.front().first, hi = sw_cases.back().first;
        const int64_t range = hi - lo + 1, n = (int64_t)sw_cases.size();
        if (lo >= 0 && n >= 4 && range >= n && range <= 2 * n && range <= 256) {
            std::vector<uint32_t> table((size_t)range, (uint32_t)default_bb);
            for (const auto &c : sw_cases)
                table[(size_t)(c.first - lo)] = (uint32_t)c.second;
            ir::IrInstr sd{};
            sd.op = ir::IrOp::SWITCH_DENSE;
            sd.type = ir::IrType::VOID;
            sd.dst = ir::IR_NO_VALUE;
            sd.operands = {L_v};
            sd.imm = (uint64_t)lo;
            sd.target_block = default_bb;
            sd.jump_targets = std::move(table);
            sd.source_line = e->loc.line;
            emit(current_block_, std::move(sd));
        }
    }
    const bool use_bst = sw_cases.size() >= 5;
    if (use_bst) {
        emit_case_bst(h_v, sw_cases, 0, sw_cases.size(), current_block_,
                      default_bb, "h", e->loc.line);
    } else {
        for (const auto &c : sw_cases) {
            ir::IrValueId cmp = fn_->new_value(ir::IrType::BOOL);
            ir::IrValueId tc =
                emit_const(ir::IrType::I64, (uint64_t)c.first, e->loc.line);
            ir::IrInstr cm{};
            cm.op = ir::IrOp::CMP_EQ;
            cm.type = ir::IrType::BOOL;
            cm.dst = cmp;
            cm.operands = {h_v, tc};
            cm.source_line = e->loc.line;
            emit(current_block_, std::move(cm));
            ir::IrBlockId nb = fn_->new_block("h_next");
            emit_br_cond(cmp, c.second, nb, e->loc.line);
            current_block_ = nb;
        }
        emit_br(default_bb, e->loc.line);
    }

    // Verify: en cada verify block, STRCMP del scrutinee contra cada case
    // string del grupo (normalmente 1); ==0 -> arm body; ninguno -> default.
    for (int64_t L : distinct_lens) {
        current_block_ = verify_bb[L];
        block_terminated_ = false;
        for (size_t idx : by_len[L]) {
            auto *sl = static_cast<ast::StringLitExpr *>(
                e->arms[idx].value_pattern.get());
            const uint32_t aln = e->arms[idx].loc.line;
            ir::IrValueId scmp; // -1/0/1
            if (native_poo_) {
                // AOT: literal -> .rodata (STR_LIT_ADDR) + len const; compara
                // via el strcmp CPU-dispatched (mismo que el `==` nativo).
                std::vector<uint8_t> data(sl->value.begin(), sl->value.end());
                data.push_back(0);
                const uint64_t li =
                    out_mod_->intern_static_data(std::move(data));
                ir::IrValueId lit_ptr = emit_str_lit_addr(li, aln, true);
                ir::IrValueId lit_len = emit_const(
                    ir::IrType::I64, (uint64_t)sl->value.size(), aln);
                scmp =
                    emit_strcmp_dispatched(s_ptr, L_v, lit_ptr, lit_len, aln);
            } else {
                ir::IrValueId case_h =
                    lower_string_literal_to_string_object(sl);
                scmp = fn_->new_value(ir::IrType::I64);
                ir::IrInstr sc{};
                sc.op = ir::IrOp::STRCMP;
                sc.type = ir::IrType::I64;
                sc.dst = scmp;
                sc.operands = {s_h, case_h};
                sc.source_line = aln;
                emit(current_block_, std::move(sc));
            }
            ir::IrValueId zero =
                emit_const(ir::IrType::I64, 0, e->arms[idx].loc.line);
            ir::IrValueId eqb =
                emit_ir_binop(ir::IrOp::CMP_EQ, scmp, zero, ir::IrType::BOOL,
                              e->arms[idx].loc.line);
            ir::IrBlockId vnext = fn_->new_block("strmatch_vnext");
            emit_br_cond(eqb, arm_blocks[idx], vnext, e->arms[idx].loc.line);
            current_block_ = vnext;
            block_terminated_ = false;
        }
        emit_br(default_bb, e->loc.line);
    }

    // Bodies (con guard opcional: fallo del guard -> default) + merge N-vias.
    std::vector<std::unordered_map<std::string, ir::IrValueId>> entry_scopes =
        scopes_;
    std::vector<std::vector<std::unordered_map<std::string, ir::IrValueId>>>
        arm_scopes(e->arms.size());
    std::vector<ir::IrBlockId> arm_preds(e->arms.size(), ir::IR_NO_BLOCK);
    std::vector<char> arm_reaches(e->arms.size(), 0);
    for (size_t i = 0; i < e->arms.size(); ++i) {
        const auto &arm = e->arms[i];
        const ir::IrBlockId target =
            ((ssize_t)i == default_arm_idx) ? default_bb : arm_blocks[i];
        if (target == ir::IR_NO_BLOCK) continue;
        current_block_ = target;
        block_terminated_ = false;
        scopes_ = entry_scopes;
        push_scope();
        if (arm.guard) {
            ir::IrValueId g = lower_expr(arm.guard.get());
            ir::IrBlockId body_bb = fn_->new_block("strmatch_body");
            emit_br_cond(g, body_bb, default_bb, arm.loc.line);
            current_block_ = body_bb;
            block_terminated_ = false;
        }
        if (arm.body) lower_stmt(arm.body.get());
        if (!block_terminated_) {
            arm_reaches[i] = 1;
            arm_preds[i] = current_block_;
            arm_scopes[i] = scopes_;
            emit_br(merge_bb, arm.loc.line);
        }
        pop_scope();
    }

    current_block_ = merge_bb;
    block_terminated_ = false;
    emit_match_arm_phis(entry_scopes, arm_scopes, arm_preds, arm_reaches,
                        merge_bb, e->loc.line);
    return ir::IR_NO_VALUE;
}

ir::IrValueId Lowering::lower_match_expr(ast::MatchExpr *e) {
    if (!e || !e->scrutinee) {
        error_at(e ? e->loc : SourceLoc{}, "lowering: match sin scrutinee");
        return ir::IR_NO_VALUE;
    }
    // match ESCALAR (int/char) o STRING: scrutinee no-enum + arms
    // value_pattern.
    const Type st = e->scrutinee->result_type;
    // Optional<T> / Result<V,E>: pseudo-enums de dos variantes (ver
    // build_optlike_enum_layout).  El dispatch + bindings reusan la misma
    // maquinaria del enum; el layout sale sintetico.
    const bool st_optlike = (st.kind == PrimitiveKind::OPTIONAL ||
                             st.kind == PrimitiveKind::RESULT);
    if (st.kind != PrimitiveKind::STRUCT && !st_optlike) {
        bool any_value_arm = false;
        for (const auto &a : e->arms)
            if (a.value_pattern) {
                any_value_arm = true;
                break;
            }
        if (st.kind == PrimitiveKind::STRING) return lower_match_string(e);
        if (any_value_arm) return lower_match_scalar(e);
        // Si no encaja en ningun path, el type checker ya reporto error;
        // devolvemos NO_VALUE silenciosamente para no inundar.
        return ir::IR_NO_VALUE;
    }
    // Tipo del scrutinee: STRUCT (enum real) u Optional/Result (sintetico).
    const auto &elays = tc_.enum_layouts();
    EnumLayout syn_optlike;
    const EnumLayout *elayp = nullptr;
    if (st_optlike) {
        syn_optlike = build_optlike_enum_layout(st, optional_layout(st),
                                                tc_.result_layout(st));
        elayp = &syn_optlike;
    } else {
        auto it = elays.find(st.struct_name);
        if (it == elays.end()) return ir::IR_NO_VALUE;
        elayp = &it->second;
    }
    const EnumLayout &elay = *elayp;

    // 1. Lower del scrutinee -> SSA PTR al slot.
    ir::IrValueId scrut_addr = lower_expr(e->scrutinee.get());
    if (scrut_addr == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    // marker: MATCH_VARIANT identifica el inicio del match.  Emitido
    // ANTES del LOAD del tag + cadena cmp+br para que el C2 JIT
    // reconozca el patron y emita dispatch eficiente
    // (jumptable si tags densos, switch tree balanceado si dispersos).
    // No produce SSA value; el emitter actual lo trata como no-op.
    {
        size_t n_concrete = 0;
        for (const auto &arm : e->arms) {
            if (arm.variant_name != "_") n_concrete++;
        }
        ir::IrInstr mt{};
        mt.op = ir::IrOp::MATCH_VARIANT;
        mt.type = ir::IrType::VOID;
        mt.dst = ir::IR_NO_VALUE;
        mt.operands = {scrut_addr};
        mt.func_name = elay.name; // nombre del enum (o Optional/Result)
        mt.imm = static_cast<uint64_t>(n_concrete);
        mt.source_line = e->loc.line;
        emit(current_block_, std::move(mt));
    }

    // 2. LOAD i64 del tag en offset 0.
    ir::IrValueId tag_v =
        emit_load_typed(scrut_addr, ir::IrType::I64, e->loc.line);
    /* Cuando el payload no puede valer cero, no hay marca aparte: lo que hay
     * en el cero ES el valor, y lo que dice si hay algo es que no sea cero.
     * Se normaliza aqui a cero-o-uno y todo el reparto de abajo -- lineal,
     * arbol, tabla -- sigue comparando marcas como siempre, sin enterarse.
     * La alternativa era ensenarle a cada una de las tres a comparar "distinto
     * de cero", que es la misma cosa escrita tres veces. */
    if (elay.tag_is_value) {
        const ir::IrValueId v_es_cero =
            emit_ir_unop(ir::IrOp::ISNULL, tag_v, ir::IrType::I64, e->loc.line);
        const ir::IrValueId v_uno = emit_const(ir::IrType::I64, 1, e->loc.line);
        tag_v = emit_ir_binop(ir::IrOp::XOR, v_es_cero, v_uno, ir::IrType::I64,
                              e->loc.line);
    }

    // 3. Construir bloques: uno por arm + uno default + uno merge.
    // Estrategia simple O(N): para cada arm con variant concreto,
    // emitimos un cmp_eq + br_cond a su body block.  Si ninguno
    // matchea, caemos en default_block (= arm "_") o merge_block
    // (continuacion del programa) si no hay default.
    const ir::IrBlockId merge_bb = fn_->new_block("match_end");
    // Localizar arm default (si existe).
    ssize_t default_arm_idx = -1;
    for (size_t i = 0; i < e->arms.size(); ++i) {
        if (e->arms[i].variant_name == "_") {
            default_arm_idx = static_cast<ssize_t>(i);
            break;
        }
    }
    ir::IrBlockId default_bb =
        (default_arm_idx >= 0) ? fn_->new_block("match_default") : merge_bb;

    // Pre-crear un bloque por cada arm concreto (no-default).
    std::vector<ir::IrBlockId> arm_blocks(e->arms.size(), ir::IR_NO_BLOCK);
    // Bug fix 2026-05-23: arm_fall_bbs[i] = fall_bb del cmp del arm i.
    // Si el arm tiene guard y falla en runtime, saltamos a este bloque
    // (que reanuda con el cmp del arm siguiente).
    std::vector<ir::IrBlockId> arm_fall_bbs(e->arms.size(), ir::IR_NO_BLOCK);
    for (size_t i = 0; i < e->arms.size(); ++i) {
        if (static_cast<ssize_t>(i) == default_arm_idx) continue;
        arm_blocks[i] =
            fn_->new_block(std::string("match_arm_") + e->arms[i].variant_name);
    }

    // ---- Dispatch del match: estrategia segun el caso (hiperoptimizado) ----
    // - Con guards: cadena lineal O(N) (los guards necesitan el "siguiente
    //   arm" via arm_fall_bbs).
    // - Sin guards y N>=5: BST balanceado O(log N) (cmp_lt en los nodos +
    //   cmp_eq en las hojas).  Beneficia interp Y JIT (ops existentes).
    // - (jumptable denso O(1): se anade despues sobre este mismo dispatch.)
    bool match_any_guard = false;
    for (const auto &a : e->arms)
        if (a.guard) {
            match_any_guard = true;
            break;
        }
    // Recolectar los casos concretos (tag, bloque) ordenados por tag.
    std::vector<std::pair<int64_t, ir::IrBlockId>> sw_cases;
    sw_cases.reserve(e->arms.size());
    for (size_t i = 0; i < e->arms.size(); ++i) {
        if (static_cast<ssize_t>(i) == default_arm_idx) continue;
        const EnumVariantInfo *var = nullptr;
        for (const auto &v : elay.variants)
            if (v.name == e->arms[i].variant_name) {
                var = &v;
                break;
            }
        if (!var) continue;
        sw_cases.push_back({static_cast<int64_t>(var->tag), arm_blocks[i]});
    }
    std::sort(sw_cases.begin(), sw_cases.end());
    const bool use_bst = !match_any_guard && sw_cases.size() >= 5;

    // Jump table DENSO (computed-goto O(1) en JIT): rango ~= N, sin guards,
    // tags no-negativos.  Emite un marker SWITCH_DENSE (no-op en interp/
    // optimizer) que el backend JIT baja a un island nativo; el dispatch
    // BST/lineal de abajo sigue siendo el path del interp + fallback.
    if (!match_any_guard && sw_cases.size() >= 4) {
        const int64_t lo_tag = sw_cases.front().first;
        const int64_t hi_tag = sw_cases.back().first;
        const int64_t range = hi_tag - lo_tag + 1;
        const int64_t n = static_cast<int64_t>(sw_cases.size());
        // Densidad: rango no mucho mayor que N (evita tablas con muchos
        // huecos) + cap a 256 entradas (island compacto) + base no-negativa.
        if (lo_tag >= 0 && range >= n && range <= 2 * n && range <= 256) {
            std::vector<uint32_t> table(static_cast<size_t>(range),
                                        static_cast<uint32_t>(default_bb));
            for (const auto &c : sw_cases)
                table[static_cast<size_t>(c.first - lo_tag)] =
                    static_cast<uint32_t>(c.second);
            ir::IrInstr sd{};
            sd.op = ir::IrOp::SWITCH_DENSE;
            sd.type = ir::IrType::VOID;
            sd.dst = ir::IR_NO_VALUE;
            sd.operands = {tag_v};
            // imm: bits 0-31 = min; bit 32 = no_bounds.  no_bounds cuando la
            // tabla cubre TODO el rango de tags del enum (min==0 y
            // range==n_variantes): el tag de un enum SIEMPRE es valido, asi
            // que idx in [0,range) -> el cmp/jae de bounds es redundante (el
            // backend lo elide).  Los huecos van por table[idx]=default.
            const bool sw_no_bounds =
                (lo_tag == 0 &&
                 range == static_cast<int64_t>(elay.variants.size()));
            sd.imm = static_cast<uint64_t>(lo_tag) |
                     (sw_no_bounds ? (UINT64_C(1) << 32) : 0);
            sd.target_block = default_bb;
            sd.jump_targets = std::move(table);
            sd.source_line = e->loc.line;
            emit(current_block_, std::move(sd));
        }
    }

    // Helper local: anade una arista CFG (succ + pred).
    if (use_bst) {
        // BST balanceado sobre sw_cases [lo,hi).  En cada nodo interno:
        // cmp_lt tag < cases[mid] -> izquierda [lo,mid); else derecha
        // [mid,hi).  En hojas (<=2 casos): cmp_eq lineal -> arm; al final
        // br a default_bb.  O(log N) comparaciones.
        emit_case_bst(tag_v, sw_cases, 0, sw_cases.size(), current_block_,
                      default_bb, "sw", e->loc.line);
    } else {
        // Cadena lineal O(N) (con guards, o pocos casos).
        for (size_t i = 0; i < e->arms.size(); ++i) {
            if (static_cast<ssize_t>(i) == default_arm_idx) continue;
            const EnumVariantInfo *var = nullptr;
            for (const auto &v : elay.variants) {
                if (v.name == e->arms[i].variant_name) {
                    var = &v;
                    break;
                }
            }
            if (!var) continue;

            ir::IrValueId cmp_v = fn_->new_value(ir::IrType::BOOL);
            ir::IrValueId tag_const =
                emit_const(ir::IrType::I64, static_cast<uint64_t>(var->tag),
                           e->arms[i].loc.line);
            {
                ir::IrInstr cm{};
                cm.op = ir::IrOp::CMP_EQ;
                cm.type = ir::IrType::BOOL;
                cm.dst = cmp_v;
                cm.operands = {tag_v, tag_const};
                cm.source_line = e->arms[i].loc.line;
                emit(current_block_, std::move(cm));
            }

            const ir::IrBlockId fall_bb = fn_->new_block("match_next");
            arm_fall_bbs[i] = fall_bb; // para uso si la arm tiene guard
            emit_br_cond(cmp_v, arm_blocks[i], fall_bb, e->arms[i].loc.line);

            current_block_ = fall_bb;
            block_terminated_ = false;
        }
        // Ultima rama: ninguna variante matcheada -> default (o merge).
        {
            emit_br(default_bb, e->loc.line);
        }
    }

    // Snapshot bindings ANTES de las arms para PHI en merge.
    // Mismo patron que lower_try: cada arm asigna en el scope enclosing,
    // y al merge llegan multiples binding distintos.  Sin PHI el
    // binding final es el de la ultima arm lowered (no determinista).
    //
    // BUG FIX 2026-05-26: guardar TODOS los scopes enclosing, no solo
    // el inmediato.  Antes solo se restauraba scopes_.back() entre
    // arms; pero un arm puede modificar vars en cualquier nivel deeper
    // (e.g. `n` declarada en la funcion, dentro de un match dentro
    // de un while).  Esas mutaciones leakean al siguiente arm si
    // no restauramos toda la stack de scopes.
    const auto entry_all_scopes_match = scopes_;
    // Mantener compat con codigo que referencia entry_bindings_match
    // (solo el outer del match) para el PHI de merge.
    const auto entry_bindings_match = scopes_.back();

    struct ArmSnapshot {
        // Cada arm captura TODOS los niveles de scope post-body para
        // poder hacer PHI merge a multiples niveles.
        std::vector<std::unordered_map<std::string, ir::IrValueId>> all_scopes;
        std::unordered_map<std::string, ir::IrValueId> bindings;
        ir::IrBlockId pred;
        bool reaches_merge;
    };
    std::vector<ArmSnapshot> arm_snaps;
    arm_snaps.reserve(e->arms.size());

    // 4. Emitir el body de cada arm (incluido el default).
    for (size_t i = 0; i < e->arms.size(); ++i) {
        const auto &arm = e->arms[i];
        const ir::IrBlockId target =
            (static_cast<ssize_t>(i) == default_arm_idx) ? default_bb
                                                         : arm_blocks[i];
        current_block_ = target;
        block_terminated_ = false;
        // Restaurar TODOS los scopes enclosing al estado de entry
        // antes de cada arm.  Sin esto, mutaciones de outer-outer
        // scopes en arm_A se ven en arm_B (-> SSA values cruzados).
        scopes_ = entry_all_scopes_match;
        push_scope();

        // Bind de los payload bindings (si la variante tiene
        // payload).  Para cada binding i, emit LOAD i64 de
        // [scrut_addr + 8 + 8*i] y bind con el nombre del binding.
        //
        // Para tipos float, el slot guarda BITS IEEE como i64
        // (escrito por el constructor via BITCAST).  Aqui bitcasteamos
        // de vuelta a F64 antes del bind para que las operaciones
        // posteriores (multiplicacion, comparacion) usen FMUL/FCMP en
        // vez de IMUL/CMP int.  Para F32 originalmente guardado:
        // BITCAST i64 -> f64 + F64TOF32 narrow (recupera el valor).
        if (arm.variant_name != "_") {
            // Localizar la EnumVariantInfo para conocer field_types.
            const EnumVariantInfo *arm_var = nullptr;
            for (const auto &vinfo : elay.variants) {
                if (vinfo.name == arm.variant_name) {
                    arm_var = &vinfo;
                    break;
                }
            }
            for (size_t bi = 0; bi < arm.bindings.size(); ++bi) {
                // Offset del payload dentro del buffer.  Para Optional/Result
                // (optlike) sale de field_offsets (Err vive en +16, no en +8);
                // para enums reales es el layout uniforme 8 + 8*bi.
                uint64_t off = 8ULL + 8ULL * static_cast<uint64_t>(bi);
                if (elay.is_optlike && arm_var &&
                    bi < arm_var->field_offsets.size()) {
                    off = static_cast<uint64_t>(arm_var->field_offsets[bi]);
                }
                // Tipo del LOAD.  optlike: el payload se guardo con su tipo
                // NATIVO (Some/Ok/Err no promueven a i64), asi que se lee
                // directo -- igual que unwrap/value/error.  Enum real: i64
                // (el constructor promueve todo payload a i64, floats via
                // BITCAST) y se recupera abajo.
                ir::IrType load_t = ir::IrType::I64;
                if (elay.is_optlike && arm_var &&
                    bi < arm_var->field_types.size()) {
                    load_t =
                        ir_type_from_primitive(arm_var->field_types[bi].kind);
                }
                ir::IrValueId addr_i = fn_->new_value(ir::IrType::PTR);
                ir::IrValueId off_v =
                    emit_const(ir::IrType::I64, off, arm.loc.line);
                {
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::I64;
                    ad.dst = addr_i;
                    ad.operands = {scrut_addr, off_v};
                    ad.source_line = arm.loc.line;
                    emit(current_block_, std::move(ad));
                }
                // Propagar is_host_ptr del scrutinee al puntero scrut+off
                // (patron is_host_ptr-en-add: el LOAD del payload debe usar la
                // misma naturaleza -- host o VM -- que el buffer del enum). Los
                // enum reales viven en VM stack (no-op), pero Optional/Result
                // viven en HOST alloca -> aqui el LOAD emite `movh`/`loadzh`
                // correctamente.
                fn_->values[addr_i].is_host_ptr =
                    fn_->values[scrut_addr].is_host_ptr;
                // Payload STRUCT por valor: no se carga en un registro -- el
                // valor de un agregado ES su direccion.  Se liga `scrut+off`
                // directamente, igual que hace `unwrap`.  Con el LOAD escalar
                // de abajo, `case Some(p)` sobre un struct ligaba sus primeros
                // 8 bytes interpretados como un entero, y el codigo del brazo
                // leia campos en direcciones inventadas.
                /* Salvo que sea un `@overlay`, que NO esta en linea: su valor
                 * ES un puntero de 8 bytes, y lo que el hueco guarda es ese
                 * puntero, no los campos.  Ligar aqui la direccion del hueco
                 * hacia que el brazo leyera sus campos como si el objeto
                 * empezara ahi -- `v.b` iba a `hueco+8` en vez de a
                 * `(*hueco)+8` --, o sea memoria que el productor nunca
                 * escribio y fuera del buffer del Optional.
                 *
                 * Lo encontro el analisis de regiones: `__vxch_wq_pop` escribe
                 * 16 bytes (tag + handle) y el llamador leia en +16 y +24.
                 * Repro: un `Optional<Vista>` con tres campos daba
                 * 2451845201647 en vez de 666.  Con el LOAD de abajo se liga el
                 * HANDLE, que es lo que un overlay es. */
                if (elay.is_optlike && arm_var &&
                    bi < arm_var->field_types.size() &&
                    arm_var->field_types[bi].kind == PrimitiveKind::STRUCT &&
                    !arm_var->field_types[bi].struct_name.empty() &&
                    !type_is_overlay(arm_var->field_types[bi])) {
                    bind(arm.bindings[bi], addr_i);
                    continue;
                }
                /* Un overlay se carga como lo que es: un PUNTERO de 8 bytes.
                 * No basta con dejarlo caer en la carga de abajo, porque esa se
                 * tipa por el campo declarado -- que aqui es STRUCT -- y una
                 * vista no tiene tipo escalar.  Y hereda la naturaleza (host o
                 * VM) del buffer, porque la vista puede apuntar a cualquiera de
                 * las dos memorias y de eso depende como se lea despues. */
                if (elay.is_optlike && arm_var &&
                    bi < arm_var->field_types.size() &&
                    arm_var->field_types[bi].kind == PrimitiveKind::STRUCT &&
                    type_is_overlay(arm_var->field_types[bi])) {
                    const ir::IrValueId vh = fn_->new_value(ir::IrType::PTR);
                    fn_->values[vh].is_host_ptr =
                        fn_->values[scrut_addr].is_host_ptr;
                    ir::IrInstr ld{};
                    ld.op = ir::IrOp::LOAD;
                    ld.type = ir::IrType::PTR;
                    ld.dst = vh;
                    ld.operands = {addr_i};
                    ld.source_line = arm.loc.line;
                    emit(current_block_, std::move(ld));
                    bind(arm.bindings[bi], vh);
                    continue;
                }
                ir::IrValueId v = emit_load_typed(addr_i, load_t, arm.loc.line);
                // optlike: el valor cargado ya es del tipo nativo del payload;
                // sin recuperacion de bits (Some/Ok/Err guardan native).
                if (elay.is_optlike) {
                    bind(arm.bindings[bi], v);
                    continue;
                }
                // Si el field declarado es float, bitcastear i64 -> f64
                // (recupera los bits IEEE escritos por el constructor).
                if (arm_var && bi < arm_var->field_types.size()) {
                    const Type &ft = arm_var->field_types[bi];
                    if (ft.kind == PrimitiveKind::F64) {
                        ir::IrValueId v2 =
                            emit_ir_unop(ir::IrOp::BITCAST, v, ir::IrType::F64,
                                         arm.loc.line);
                        v = v2;
                    } else if (ft.kind == PrimitiveKind::F32) {
                        // Recuperar f32: el slot guardo BITCAST(F32TOF64(x))
                        // como i64.  Invertimos: BITCAST i64->f64 +
                        // F64TOF32 narrow para volver al f32 original.
                        ir::IrValueId vd =
                            emit_ir_unop(ir::IrOp::BITCAST, v, ir::IrType::F64,
                                         arm.loc.line);
                        ir::IrValueId v2 =
                            emit_ir_unop(ir::IrOp::F64TOF32, vd,
                                         ir::IrType::F32, arm.loc.line);
                        v = v2;
                    }
                    // Para tipos enteros mas estrechos, dejar v como i64;
                    // el codigo de uso aplicara cast_if_needed cuando
                    // sea necesario (sign-extend / truncate).
                }
                bind(arm.bindings[bi], v);
            }
        }

        // Bug fix 2026-05-23: si la arm tiene guard, evaluarlo ANTES
        // del body.  Si falso, saltar al fall_bb (siguiente cmp).
        if (arm.guard && arm.variant_name != "_") {
            const ir::IrValueId guard_v = lower_expr(arm.guard.get());
            if (guard_v != ir::IR_NO_VALUE &&
                arm_fall_bbs[i] != ir::IR_NO_BLOCK) {
                const ir::IrBlockId body_bb = fn_->new_block("match_arm_body");
                // Guarda incumplida -> se sigue probando la siguiente rama.
                emit_br_cond(guard_v, body_bb, arm_fall_bbs[i], arm.loc.line);
                current_block_ = body_bb;
                block_terminated_ = false;
            }
        }

        if (arm.body) lower_stmt(arm.body.get());
        // Capturar snapshot ANTES de pop_scope.  Guardamos TANTO
        // el scope outer inmediato (size-2) PARA compatibilidad con
        // el PHI merge existente, COMO la stack completa (size-2 y
        // todos los inferiores) para PHI multi-nivel.
        ArmSnapshot snap;
        snap.reaches_merge = !block_terminated_;
        if (snap.reaches_merge) {
            if (scopes_.size() >= 2) {
                snap.bindings = scopes_[scopes_.size() - 2];
                // Capturar todos los niveles enclosing (excluyendo
                // el scope local del arm, size-1).  Necesario para
                // que el PHI insert al merge atrape mutaciones de
                // vars declaradas en funcion/loop body/etc.
                snap.all_scopes.assign(scopes_.begin(),
                                       scopes_.begin() + (scopes_.size() - 1));
            }
            snap.pred = current_block_;
        } else {
            snap.pred = ir::IR_NO_BLOCK;
        }
        arm_snaps.push_back(std::move(snap));

        if (!block_terminated_) {
            // br merge_bb
            emit_br(merge_bb, arm.loc.line);
            block_terminated_ = true;
        }
        pop_scope();
    }

    // Si NO hubo arm default y el merge_bb es el destino del
    // fall-through "ninguna variante matcheo", aseguramos que
    // continuamos en merge_bb.  Si hubo default, el fall_block ya
    // saltaba a default_bb que a su vez hace br a merge_bb.
    current_block_ = merge_bb;
    block_terminated_ = false;

    // PHI insertion en merge_bb para variables modificadas
    // en multiples arms.  Mismo algoritmo que lower_try.
    // Reset TODOS los scopes al estado de entry; el PHI insert
    // multi-nivel sobreescribe las vars que difieren.
    scopes_ = entry_all_scopes_match;
    struct MergeContrib2 {
        ir::IrBlockId pred;
        const std::vector<std::unordered_map<std::string, ir::IrValueId>>
            *all_scopes;
    };
    std::vector<MergeContrib2> contribs;
    contribs.reserve(arm_snaps.size());
    for (auto &as : arm_snaps) {
        if (as.reaches_merge) {
            contribs.push_back({as.pred, &as.all_scopes});
        }
    }
    // PHI insertion multi-nivel: por cada scope-level enclosing del
    // match, para cada var, si los arms producen valores distintos,
    // insertar PHI en merge_bb y actualizar el scope correspondiente.
    // Esto cierra el bug del match-en-loop donde mutaciones a vars
    // declaradas en niveles outer-outer (e.g. funcion) no eran
    // PHI-merged y la back-edge tomaba el valor del ULTIMO arm.
    if (contribs.size() >= 2) {
        const size_t n_levels = entry_all_scopes_match.size();
        for (size_t lvl = 0; lvl < n_levels; ++lvl) {
            for (const auto &kv : entry_all_scopes_match[lvl]) {
                const std::string &name = kv.first;
                const ir::IrValueId entry_val = kv.second;
                bool any_diff = false;
                for (const auto &c : contribs) {
                    if (lvl >= c.all_scopes->size()) continue;
                    auto it_b = (*c.all_scopes)[lvl].find(name);
                    if (it_b == (*c.all_scopes)[lvl].end()) continue;
                    if (it_b->second != entry_val) {
                        any_diff = true;
                        break;
                    }
                }
                if (!any_diff) continue;

                ir::IrType ity = ir::IrType::I64;
                if (entry_val != ir::IR_NO_VALUE &&
                    entry_val < fn_->values.size()) {
                    ity = fn_->values[entry_val].type;
                }
                ir::IrValueId v_phi = fn_->new_value(ity);
                ir::IrInstr phi{};
                phi.op = ir::IrOp::PHI;
                phi.type = ity;
                phi.dst = v_phi;
                phi.source_line = e->loc.line;
                for (const auto &c : contribs) {
                    ir::IrValueId in_val = entry_val;
                    if (lvl < c.all_scopes->size()) {
                        auto it_b = (*c.all_scopes)[lvl].find(name);
                        if (it_b != (*c.all_scopes)[lvl].end()) {
                            in_val = it_b->second;
                        }
                    }
                    ir::IrPhiArg arg{};
                    arg.value = in_val;
                    arg.block = c.pred;
                    phi.phi_args.push_back(arg);
                }
                fn_->blocks[merge_bb].instrs.insert(
                    fn_->blocks[merge_bb].instrs.begin(), std::move(phi));
                scopes_[lvl][name] = v_phi;
            }
        }
    } else if (contribs.size() == 1) {
        // Solo un arm reach merge: copiar sus all_scopes directos.
        const auto &as = *contribs[0].all_scopes;
        const size_t n_min = std::min(as.size(), scopes_.size());
        for (size_t lvl = 0; lvl < n_min; ++lvl) {
            for (const auto &kv : as[lvl]) {
                scopes_[lvl][kv.first] = kv.second;
            }
        }
    }
    return ir::IR_NO_VALUE; // statement-like
}

} // namespace vx
