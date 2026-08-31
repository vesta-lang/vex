/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/strings.cpp
 * @brief Bajada de las cadenas nativas: como se representan y como se
 *        construyen.
 *
 * Una cadena de Vesta no es un puntero.  Es una estructura que guarda las
 * cortas DENTRO de si misma y solo pide memoria para las largas, asi que casi
 * ninguna operacion es directa: para saber su longitud, para llegar a sus
 * bytes, o para liberarla, hay que mirar antes en cual de las dos formas esta.
 * Ese "mirar antes" es lo que se repite por todo el fichero, y es tambien la
 * razon de que la mayoria de estas funciones existan en pareja -- una version
 * en linea para el caso frecuente y una llamada a un ayudante compartido para
 * el resto --.
 *
 * Lo demas es construirlas: a partir de un caracter, de un trozo, de otras dos,
 * de un numero, o de una interpolacion; y transcodificarlas cuando salen del
 * lenguaje hacia una biblioteca que espera otra codificacion.
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

std::string Lowering::ensure_strcmp_helper() {
    // Vesta Embed Inc 4: helper de comparacion lexicografica de strings
    // value-type nativos.  Firma:
    //   i64 __vx_strcmp(u8* pa, i64 la, u8* pb, i64 lb)
    // Devuelve -1/0/1 (memcmp + tie-break por longitud):
    //   1. min = (la < lb) ? la : lb.
    //   2. for (i = 0; i < min; i++): comparar pa[i] vs pb[i] como bytes
    //      unsigned (0..255).  El primer byte que difiere decide:
    //      pa[i] < pb[i] -> -1 ; pa[i] > pb[i] -> 1.
    //   3. Si los min bytes coinciden, el mas CORTO es menor:
    //      la < lb -> -1 ; la > lb -> 1 ; la == lb -> 0.
    // Vive en una funcion APARTE con loop -> el optimizer NO foldea la
    // comparacion byte-a-byte mid-expression con operandos constantes y
    // el inliner no la re-inlinea (is_inlineable exige 1 bloque).  Usa
    // slots ALLOCA para el indice (mem2reg los promueve en O2) y evita
    // PHIs manuales.  Todas las ops son PURE_NATIVE.
    //
    // CPU dispatch Inc 5a: este es el BASELINE escalar (`__vx_strcmp_base`)
    // al que apunta __vx_strcmp_fp por defecto.  Es llamable por nombre desde
    // Vesta (un override puede delegar a el).
    const std::string name = "__vx_strcmp_base";
    if (strcmp_helper_emitted_) return name;
    strcmp_helper_emitted_ = true;

    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction hf;
    hf.name = name;
    hf.ret_type = ir::IrType::I64;
    const ir::IrValueId p_pa = hf.new_value(ir::IrType::PTR, "%pa");
    hf.values[p_pa].is_param = true;
    hf.values[p_pa].is_host_ptr = true;
    hf.params.push_back(p_pa);
    const ir::IrValueId p_la = hf.new_value(ir::IrType::I64, "%la");
    hf.values[p_la].is_param = true;
    hf.params.push_back(p_la);
    const ir::IrValueId p_pb = hf.new_value(ir::IrType::PTR, "%pb");
    hf.values[p_pb].is_param = true;
    hf.values[p_pb].is_host_ptr = true;
    hf.params.push_back(p_pb);
    const ir::IrValueId p_lb = hf.new_value(ir::IrType::I64, "%lb");
    hf.values[p_lb].is_param = true;
    hf.params.push_back(p_lb);
    const ir::IrBlockId e = hf.new_block("entry");

    fn_ = &hf;
    current_block_ = e;

    const uint32_t ln = 0;

    // Helpers locales (mismo patron que emit_native_itoa_to_buf).
    auto new_slot = [&]() { return stack_alloc_buf(8, ln, true); };
    auto load_i64 = [&](ir::IrValueId addr) { return emit_load_i64(addr, ln); };
    auto store_i64 = [&](ir::IrValueId addr, ir::IrValueId val) {
        emit_store_i64(addr, val, ln);
    };
    auto load_byte = [&](ir::IrValueId addr) {
        return emit_load_byte(addr, ln);
    };
    auto bin = [&](ir::IrOp op, ir::IrValueId a, ir::IrValueId b) {
        return emit_ir_binop(op, a, b, ir::IrType::U64, ln);
    };
    auto cmp = [&](ir::IrOp op, ir::IrValueId a,
                   ir::IrValueId b) -> ir::IrValueId {
        ir::IrValueId v = fn_->new_value(ir::IrType::I64);
        ir::IrInstr in{};
        in.op = op;
        in.type = ir::IrType::I64;
        in.dst = v;
        in.operands = {a, b};
        in.source_line = ln;
        emit(current_block_, std::move(in));
        return v;
    };
    auto new_block = [&]() -> ir::IrBlockId { return fn_->new_block(); };
    auto ret = [&](ir::IrValueId v) {
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::I64;
        rt.dst = ir::IR_NO_VALUE;
        rt.operands = {v};
        rt.source_line = ln;
        emit(current_block_, std::move(rt));
    };

    ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, ln);
    ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, ln);
    ir::IrValueId v_neg1 = emit_const(ir::IrType::I64, (uint64_t)(-1), ln);

    // min = (la < lb) ? la : lb.  Bloques: bb_minA / bb_minB / join.
    ir::IrValueId s_min = new_slot();
    {
        ir::IrValueId la_lt_lb = cmp(ir::IrOp::CMP_LT, p_la, p_lb); // signed
        ir::IrBlockId bb_minA = new_block();
        ir::IrBlockId bb_minB = new_block();
        ir::IrBlockId bb_minJ = new_block();
        emit_br_cond(la_lt_lb, bb_minA, bb_minB, ln);
        current_block_ = bb_minA;
        store_i64(s_min, p_la);
        emit_br(bb_minJ, ln);
        current_block_ = bb_minB;
        store_i64(s_min, p_lb);
        emit_br(bb_minJ, ln);
        current_block_ = bb_minJ;
    }

    // i = 0.
    ir::IrValueId s_i = new_slot();
    store_i64(s_i, v_zero);

    // Loop: while (i < min) { ca=pa[i]; cb=pb[i]; if(ca!=cb) ret cmp; i++; }
    ir::IrBlockId bb_hdr = new_block();
    emit_br(bb_hdr, ln);
    current_block_ = bb_hdr;
    {
        ir::IrValueId v_i = load_i64(s_i);
        ir::IrValueId v_min = load_i64(s_min);
        ir::IrValueId i_lt = cmp(ir::IrOp::CMP_LT, v_i, v_min); // signed
        ir::IrBlockId bb_body = new_block();
        ir::IrBlockId bb_tail = new_block();
        emit_br_cond(i_lt, bb_body, bb_tail, ln);

        // bb_body: comparar bytes.
        current_block_ = bb_body;
        {
            ir::IrValueId v_i2 = load_i64(s_i);
            ir::IrValueId v_a_at = emit_ptr_add(p_pa, v_i2, ln);
            ir::IrValueId v_b_at = emit_ptr_add(p_pb, v_i2, ln);
            ir::IrValueId v_ca = load_byte(v_a_at);
            ir::IrValueId v_cb = load_byte(v_b_at);
            ir::IrValueId ne = cmp(ir::IrOp::CMP_NE, v_ca, v_cb);
            ir::IrBlockId bb_diff = new_block();
            ir::IrBlockId bb_cont = new_block();
            emit_br_cond(ne, bb_diff, bb_cont, ln);

            // bb_diff: ret (ca < cb) ? -1 : 1.  Bytes 0..255 -> CMP_LT
            //          unsigned == signed (ambos positivos en i64).
            current_block_ = bb_diff;
            {
                ir::IrValueId lt = cmp(ir::IrOp::CMP_LT, v_ca, v_cb);
                ir::IrBlockId bb_lt = new_block();
                ir::IrBlockId bb_gt = new_block();
                emit_br_cond(lt, bb_lt, bb_gt, ln);
                current_block_ = bb_lt;
                ret(v_neg1);
                current_block_ = bb_gt;
                ret(v_one);
            }

            // bb_cont: i++ ; volver al header.
            current_block_ = bb_cont;
            {
                ir::IrValueId v_i3 = load_i64(s_i);
                ir::IrValueId v_i4 = bin(ir::IrOp::ADD, v_i3, v_one);
                store_i64(s_i, v_i4);
            }
            emit_br(bb_hdr, ln);
        }

        // bb_tail: prefijos iguales -> el mas corto es menor.
        current_block_ = bb_tail;
        {
            ir::IrValueId la_lt = cmp(ir::IrOp::CMP_LT, p_la, p_lb);
            ir::IrBlockId bb_short = new_block();
            ir::IrBlockId bb_chk_gt = new_block();
            emit_br_cond(la_lt, bb_short, bb_chk_gt, ln);
            current_block_ = bb_short;
            ret(v_neg1);
            current_block_ = bb_chk_gt;
            {
                ir::IrValueId la_gt = cmp(ir::IrOp::CMP_GT, p_la, p_lb);
                ir::IrBlockId bb_long = new_block();
                ir::IrBlockId bb_eq = new_block();
                emit_br_cond(la_gt, bb_long, bb_eq, ln);
                current_block_ = bb_long;
                ret(v_one);
                current_block_ = bb_eq;
                ret(v_zero);
            }
        }
    }

    out_mod_->add_function(std::move(hf));
    return name;
}

ir::IrValueId Lowering::build_native_string_interp(ast::StringLitExpr *slit) {
    // Vesta Embed Inc 2: interpolacion native.  Construimos un value-string
    // owned partiendo de un buffer vacio + appendeando cada parte (literal
    // o ${expr}).  El resultado es un slot {ptr,len,cap} de 24 bytes; el
    // caller registra su STRING_FREE.  Layout del literal: parts[0] +
    // exprs[0] + parts[1] + ... + parts[N] (N+1 parts para N exprs).
    const int line = slit->loc.line;
    const uint32_t ln = static_cast<uint32_t>(line);

    // Helper: addr = base + off (host).
    // 1. Slot resultado vacio.  String Inc 5 (SSO): arrancamos como SSO
    //    vacio (len=0) -> CERO malloc inicial.  Los appends posteriores
    //    crecen inline (SSO) o transicionan a HEAP via
    //    build_native_string_append_inplace.  El slot vive en host stack.
    const ir::IrValueId v_slot = fn_->new_value(ir::IrType::PTR);
    if (native_poo_) fn_->values[v_slot].is_host_ptr = true;
    {
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = v_slot;
        al.imm = 24;
        al.host_alloca = native_poo_;
        al.source_line = ln;
        emit(current_block_, std::move(al));
    }
    // String Inc 5 (SSO): zero-init qword0/1 + qword2 = (0 << 56) -> SSO
    // vacio (len 0, flag bit alto 0, data inline definida).  Los appends
    // crecen desde aqui.  Cubre los 24 bytes (sin uninitialised reads).
    emit_zero_native_str_slot(v_slot, ln);
    emit_str_meta_sso(v_slot, emit_const(ir::IrType::I64, 0, ln), ln);

    // Helper: appendear un literal de compile-time conocido.  Escribimos
    // sus bytes a un buffer scratch en stack (ALLOCA) y appendeamos via
    // build_native_string_append_inplace.  Para literales pequenos esto
    // es directo (bytes a STORE inline).
    auto append_literal = [&](const std::string &part) {
        if (part.empty()) return;
        const uint64_t plen = static_cast<uint64_t>(part.size());
        // Buffer scratch de plen bytes (sin nul; append no lo necesita).
        ir::IrValueId v_scratch = stack_alloc_buf(plen, ln, native_poo_);
        if (native_poo_) fn_->values[v_scratch].is_host_ptr = true;
        // STOREs empaquetados (qword/dword/word/byte) de los bytes.
        std::vector<uint8_t> data(part.begin(), part.end());
        auto store_chunk = [&](uint64_t off, uint64_t val, ir::IrType ty) {
            ir::IrValueId v_dst =
                (off == 0)
                    ? v_scratch
                    : emit_ptr_add(v_scratch,
                                   emit_const(ir::IrType::I64, off, ln), ln);
            ir::IrValueId v_val = emit_const(ty, val, ln);
            emit_store_typed(v_dst, v_val, ty, ln);
        };
        auto pack = [&](uint64_t pos, int n) { return pack_le(data, pos, n); };
        uint64_t pos = 0;
        for (; pos + 8 <= plen; pos += 8)
            store_chunk(pos, pack(pos, 8), ir::IrType::I64);
        if (pos + 4 <= plen) {
            store_chunk(pos, pack(pos, 4), ir::IrType::I32);
            pos += 4;
        }
        if (pos + 2 <= plen) {
            store_chunk(pos, pack(pos, 2), ir::IrType::I16);
            pos += 2;
        }
        if (pos + 1 <= plen) {
            store_chunk(pos, pack(pos, 1), ir::IrType::U8);
            pos += 1;
        }
        ir::IrValueId v_plen = emit_const(ir::IrType::I64, plen, ln);
        build_native_string_append_inplace(v_slot, v_scratch, v_plen, ln);
    };

    // Helper: appendear un ${expr}.  Segun el tipo del expr:
    //   string -> append de sus bytes (ptr/len del slot del expr).
    //   char   -> 1 byte (el char ya es un valor 0-255).
    //   int    -> itoa inline a un buffer scratch de 24 bytes.
    //   bool   -> "true"/"false" via branch + append literal.
    // BUG-3: extractor del KIND del format spec (ignora alineacion).
    auto fmt_kind_of = [](const std::string &fmt) -> std::string {
        size_t i = 0;
        while (i < fmt.size()) {
            while (i < fmt.size() && (fmt[i] == ' ' || fmt[i] == '\t'))
                ++i;
            if (i >= fmt.size()) break;
            if (fmt[i] == '<' || fmt[i] == '>') {
                ++i;
                while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9')
                    ++i;
                if (i < fmt.size() && fmt[i] != ':') ++i;
            } else {
                size_t start = i;
                while (i < fmt.size() && fmt[i] != ':' && fmt[i] != ' ' &&
                       fmt[i] != '\t')
                    ++i;
                std::string kw = fmt.substr(start, i - start);
                if (kw == "char" || kw == "hex" || kw == "bin" || kw == "oct" ||
                    kw == "dec" || kw == "ptr" || kw == "bool" || kw == "gc")
                    return kw;
            }
            while (i < fmt.size() && (fmt[i] == ' ' || fmt[i] == '\t'))
                ++i;
            if (i < fmt.size() && fmt[i] == ':') ++i;
        }
        return std::string();
    };
    auto append_expr = [&](ast::Expr *ex, const std::string &fmt) -> bool {
        if (!ex) return false;
        // String literal anidado (no interpolado) -> tratamos su texto
        // como literal directo.
        if (ex->kind == ast::NodeKind::StringLitExpr) {
            auto *sl = static_cast<ast::StringLitExpr *>(ex);
            if (!sl->is_interpolated()) {
                append_literal(sl->value);
                return true;
            }
        }
        const PrimitiveKind ek = ex->result_type.kind;
        // BUG-3: `${int:char}` -> codificar el valor como codepoint UTF-8 via
        // __vx_ctoa (paridad con interp/JIT), no como decimal.
        if (!fmt.empty() && fmt_kind_of(fmt) == "char" &&
            (is_integral(ek) || ek == PrimitiveKind::CHAR)) {
            ir::IrValueId v_cp = lower_expr(ex);
            if (v_cp == ir::IR_NO_VALUE) return false;
            // Promover a i64 para el helper (cp puede ser hasta 0x10FFFF).
            if (ek != PrimitiveKind::I64 && ek != PrimitiveKind::U64) {
                ir::IrValueId v64 = fn_->new_value(ir::IrType::I64);
                ir::IrInstr ext{};
                ext.op =
                    is_signed_integral(ek) ? ir::IrOp::SEXT : ir::IrOp::ZEXT;
                ext.type = ir::IrType::I64;
                ext.dst = v64;
                ext.operands = {v_cp};
                ext.source_line = ln;
                emit(current_block_, std::move(ext));
                v_cp = v64;
            }
            // scratch de 4 bytes (max UTF-8).
            ir::IrValueId v_scr = stack_alloc_buf(4, ln, native_poo_);
            if (native_poo_) fn_->values[v_scr].is_host_ptr = true;
            const std::string ctoa_fn = ensure_ctoa_helper();
            ir::IrValueId v_len =
                emit_call(ctoa_fn, {v_scr, v_cp}, ir::IrType::I64, ln);
            build_native_string_append_inplace(v_slot, v_scr, v_len, ln);
            return true;
        }
        if (ek == PrimitiveKind::STRING) {
            // El expr produce un value-string (PTR a slot).  Inc 5 (SSO):
            // (ptr, len) via accesores flag-aware.  Append de sus bytes.
            ir::IrValueId v_src = lower_expr(ex);
            if (v_src == ir::IR_NO_VALUE) return false;
            ir::IrValueId v_sptr = emit_native_str_data_ptr(v_src, ln);
            ir::IrValueId v_slen = emit_native_str_len(v_src, ln);
            build_native_string_append_inplace(v_slot, v_sptr, v_slen, ln);
            return true;
        }
        if (ek == PrimitiveKind::CHAR) {
            ir::IrValueId v_ch = lower_expr(ex);
            if (v_ch == ir::IR_NO_VALUE) return false;
            // Buffer scratch de 1 byte con el char.
            ir::IrValueId v_scr = stack_alloc_buf(1, ln, native_poo_);
            if (native_poo_) fn_->values[v_scr].is_host_ptr = true;
            emit_store_typed(v_scr, v_ch, ir::IrType::U8, ln);
            build_native_string_append_inplace(
                v_slot, v_scr, emit_const(ir::IrType::I64, 1, ln), ln);
            return true;
        }
        // Enteros (i8..i64/u8..u64): itoa decimal inline a un scratch de
        // 24 bytes, luego append de los `len` bytes escritos.
        if (is_integral(ek)) {
            ir::IrValueId v_int = lower_expr(ex);
            if (v_int == ir::IR_NO_VALUE) return false;
            // El itoa trabaja en i64: promover si es mas estrecho.
            if (ek != PrimitiveKind::I64 && ek != PrimitiveKind::U64) {
                ir::IrValueId v64 = fn_->new_value(ir::IrType::I64);
                ir::IrInstr ext{};
                ext.op =
                    is_signed_integral(ek) ? ir::IrOp::SEXT : ir::IrOp::ZEXT;
                ext.type = ir::IrType::I64;
                ext.dst = v64;
                ext.operands = {v_int};
                ext.source_line = ln;
                emit(current_block_, std::move(ext));
                v_int = v64;
            }
            // scratch de 24 bytes (suficiente para i64 con signo).
            ir::IrValueId v_scr = stack_alloc_buf(24, ln, native_poo_);
            if (native_poo_) fn_->values[v_scr].is_host_ptr = true;
            // CALL al helper itoa (no inline): evita el const-fold
            // mid-expression que daba longitudes erroneas con argumento
            // constante (el itoa vive en una funcion aparte con loops).
            const std::string itoa_fn =
                ensure_itoa_helper(is_signed_integral(ek));
            ir::IrValueId v_len =
                emit_call(itoa_fn, {v_scr, v_int}, ir::IrType::I64, ln);
            build_native_string_append_inplace(v_slot, v_scr, v_len, ln);
            return true;
        }
        // bool: "true" (4) / "false" (5) via helper btoa (no inline,
        // branch -> fold-safe con argumento constante).
        if (ek == PrimitiveKind::BOOL) {
            ir::IrValueId v_b = lower_expr(ex);
            if (v_b == ir::IR_NO_VALUE) return false;
            // Promover el bool a i64 para el helper (cmp != 0).
            ir::IrValueId v_b64 =
                emit_ir_unop(ir::IrOp::ZEXT, v_b, ir::IrType::I64, ln);
            // scratch de 8 bytes (cabe "false" + margen).
            ir::IrValueId v_scr = stack_alloc_buf(8, ln, native_poo_);
            if (native_poo_) fn_->values[v_scr].is_host_ptr = true;
            const std::string btoa_fn = ensure_btoa_helper();
            ir::IrValueId v_len =
                emit_call(btoa_fn, {v_scr, v_b64}, ir::IrType::I64, ln);
            build_native_string_append_inplace(v_slot, v_scr, v_len, ln);
            return true;
        }
        // Tipo no soportado en interpolacion native (float/struct/class/
        // enum) -- Inc 2b futuro.  Diagnostico claro.
        error_at(ex->loc,
                 "interpolacion `${expr}` native (AOT): solo se soportan "
                 "todavia string, char, int y bool.  float (y struct/class/"
                 "enum) quedan para un follow-up (requieren codegen de "
                 "bloques anidados en la construccion del string).");
        return false;
    };

    const size_t ne = slit->interp_exprs.size();
    const size_t np = slit->interp_parts.size();
    // parts[0].
    if (np > 0) append_literal(slit->interp_parts[0]);
    for (size_t i = 0; i < ne; ++i) {
        const std::string fmt_i = (i < slit->interp_formats.size())
                                      ? slit->interp_formats[i]
                                      : std::string();
        if (!append_expr(slit->interp_exprs[i].get(), fmt_i))
            return ir::IR_NO_VALUE;
        if (i + 1 < np) append_literal(slit->interp_parts[i + 1]);
    }
    return v_slot;
}

ir::IrValueId Lowering::load_native_string_field(ir::IrValueId v_slot,
                                                 uint64_t byte_off,
                                                 bool as_host,
                                                 uint32_t source_line) {
    ir::IrValueId v_addr = v_slot;
    if (byte_off > 0) {
        ir::IrValueId v_off =
            emit_const(ir::IrType::I64, byte_off, source_line);
        v_addr = emit_ptr_add(v_slot, v_off, source_line);
    }
    const ir::IrType rt = as_host ? ir::IrType::PTR : ir::IrType::I64;
    ir::IrValueId v_val = fn_->new_value(rt);
    if (as_host) fn_->values[v_val].is_host_ptr = true;
    ir::IrInstr ld{};
    ld.op = ir::IrOp::LOAD;
    ld.type = ir::IrType::I64;
    ld.dst = v_val;
    ld.operands = {v_addr};
    ld.source_line = source_line;
    emit(current_block_, std::move(ld));
    return v_val;
}

// -----------------------------------------------------------------------
// String Inc 5 (SSO): accesores flag-aware del value-string nativo.
//
// Layout union de 24 bytes con flag en el bit alto del byte [23]:
//   HEAP (byte[23]&0x80 != 0): ptr@0, len@8, cap en bytes[16..22] (56b).
//   SSO  (byte[23]&0x80 == 0): data inline en bytes[0..21], len en
//                              byte[23]&0x7F, nul en byte[len].
// Los accesores son BRANCHLESS (mascara aritmetica) -> sin CFG, barato y
// robusto en el regalloc (sin PHIs).
// -----------------------------------------------------------------------

ir::IrValueId Lowering::emit_native_str_is_heap(ir::IrValueId v_slot,
                                                uint32_t source_line) {
    // is_heap = (byte[23] >> 7) & 1.  Cargamos el byte [23] (u8
    // zero-extended) y lo desplazamos 7 bits.  Resultado I64 0 o 1.
    ir::IrValueId v_off = emit_const(ir::IrType::I64, 23, source_line);
    ir::IrValueId v_addr = emit_ptr_add(v_slot, v_off, source_line);
    ir::IrValueId v_b23 = emit_load_typed(v_addr, ir::IrType::U8, source_line);
    // is_heap = b23 >> 7  (logico; b23 es 0..255 zero-extended).
    ir::IrValueId v_seven = emit_const(ir::IrType::I64, 7, source_line);
    ir::IrValueId v_is_heap = emit_ir_binop(ir::IrOp::SHR, v_b23, v_seven,
                                            ir::IrType::I64, source_line);
    return v_is_heap;
}

ir::IrValueId Lowering::emit_native_str_is_owned(ir::IrValueId v_slot,
                                                 uint32_t source_line) {
    // owned = (byte[23] >> 7) & ~(byte[23] >> 6) & 1, sin ramas:
    //   b23 >> 6 da 0b11 para un prestado (bits 7 y 6) y 0b10 para uno
    //   propio, asi que basta comparar con 2.  Se hace con aritmetica para no
    //   introducir un salto en el camino de salida de cada scope.
    //
    //   propio    -> (b23 >> 6) == 0b10 = 2 -> owned = 1
    //   prestado  -> (b23 >> 6) == 0b11 = 3 -> owned = 0
    //   SSO       -> (b23 >> 6) == 0b00 = 0 -> owned = 0 (no hay buffer)
    ir::IrValueId v_off = emit_const(ir::IrType::I64, 23, source_line);
    ir::IrValueId v_addr = emit_ptr_add(v_slot, v_off, source_line);
    ir::IrValueId v_b23 = emit_load_typed(v_addr, ir::IrType::U8, source_line);
    ir::IrValueId v_six = emit_const(ir::IrType::I64, 6, source_line);
    ir::IrValueId v_top2 = emit_ir_binop(ir::IrOp::SHR, v_b23, v_six,
                                         ir::IrType::I64, source_line);
    ir::IrValueId v_dos = emit_const(ir::IrType::I64, 2, source_line);
    ir::IrValueId v_owned = emit_ir_binop(ir::IrOp::CMP_EQ, v_top2, v_dos,
                                          ir::IrType::I64, source_line);
    return v_owned;
}

ir::IrValueId Lowering::emit_native_str_data_ptr_inline(ir::IrValueId v_slot,
                                                        uint32_t source_line) {
    // data_ptr = is_heap ? LOAD ptr@0 : &slot.
    // Branchless: slot + is_heap*(ptr0 - slot).
    //   - SSO  (is_heap=0): slot + 0 = slot           (data inline @0).
    //   - HEAP (is_heap=1): slot + (ptr0 - slot) = ptr0.
    ir::IrValueId v_is_heap = emit_native_str_is_heap(v_slot, source_line);
    // ptr0 cargado SIEMPRE (slot+0 es memoria valida en ambos modos; en
    // SSO son bytes de data, pero solo los usamos si is_heap=1).  Lo
    // tratamos como I64 para la aritmetica de mascara.
    ir::IrValueId v_ptr0 =
        emit_load_typed(v_slot, ir::IrType::I64, source_line);
    // slot como I64 (la direccion del slot).  BITCAST PTR->I64.
    ir::IrValueId v_slot_i =
        emit_ir_unop(ir::IrOp::BITCAST, v_slot, ir::IrType::I64, source_line);
    // diff = ptr0 - slot.
    ir::IrValueId v_diff = emit_ir_binop(ir::IrOp::SUB, v_ptr0, v_slot_i,
                                         ir::IrType::I64, source_line);
    // masked = diff & (-is_heap)  (AND, no MUL: valgrind sabe x&0=0 es
    // definido aunque diff use ptr0 con bits de data inline SSO).
    ir::IrValueId v_mask =
        emit_ir_unop(ir::IrOp::NEG, v_is_heap, ir::IrType::I64, source_line);
    ir::IrValueId v_masked = emit_ir_binop(ir::IrOp::AND, v_diff, v_mask,
                                           ir::IrType::I64, source_line);
    // data = slot + masked.  La base es el slot pasado a ENTERO -- asi se
    // elige entre las dos direcciones sin bifurcar --, y un entero no lleva la
    // marca de ser del anfitrion: hay que devolversela.
    ir::IrValueId v_data = emit_host_ptr_add(v_slot_i, v_masked, source_line);
    return v_data;
}

ir::IrValueId Lowering::emit_native_str_len_inline(ir::IrValueId v_slot,
                                                   uint32_t source_line) {
    // len = is_heap ? LOAD len@8 : (byte[23] & 0x7F).
    // Branchless: sso_len + (diff & -is_heap), donde diff = heap_len -
    // sso_len.
    ir::IrValueId v_is_heap = emit_native_str_is_heap(v_slot, source_line);
    // sso_len = byte[23] & 0x7F.
    ir::IrValueId v_off23 = emit_const(ir::IrType::I64, 23, source_line);
    ir::IrValueId v_addr23 = emit_ptr_add(v_slot, v_off23, source_line);
    ir::IrValueId v_b23 =
        emit_load_typed(v_addr23, ir::IrType::U8, source_line);
    ir::IrValueId v_mask7f = emit_const(ir::IrType::I64, 0x7F, source_line);
    ir::IrValueId v_sso_len = emit_ir_binop(ir::IrOp::AND, v_b23, v_mask7f,
                                            ir::IrType::I64, source_line);
    // heap_len = LOAD len@8.
    ir::IrValueId v_heap_len =
        load_native_string_field(v_slot, 8, /*as_host=*/false, source_line);
    // diff = heap_len - sso_len.
    ir::IrValueId v_diff = emit_ir_binop(ir::IrOp::SUB, v_heap_len, v_sso_len,
                                         ir::IrType::I64, source_line);
    // masked = diff & (-is_heap)  (AND, no MUL: heap_len puede ser un
    // LOAD de bytes no inicializados en modo SSO; x&0=0 es definido).
    ir::IrValueId v_mask =
        emit_ir_unop(ir::IrOp::NEG, v_is_heap, ir::IrType::I64, source_line);
    ir::IrValueId v_masked = emit_ir_binop(ir::IrOp::AND, v_diff, v_mask,
                                           ir::IrType::I64, source_line);
    // len = sso_len + masked.
    ir::IrValueId v_len = emit_ir_binop(ir::IrOp::ADD, v_sso_len, v_masked,
                                        ir::IrType::I64, source_line);
    return v_len;
}

ir::IrValueId Lowering::emit_native_str_data_ptr(ir::IrValueId v_slot,
                                                 uint32_t source_line) {
    // CALL __vx_strdata(s) -> u8* (la logica branchless vive en el helper;
    // ver ensure_strdata_helper / el comentario del blacklist del inliner).
    const std::string name = ensure_strdata_helper();
    ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true;
    ir::IrInstr ca{};
    ca.op = ir::IrOp::CALL;
    ca.type = ir::IrType::PTR;
    ca.dst = v;
    ca.func_name = name;
    ca.operands = {v_slot};
    ca.source_line = source_line;
    emit(current_block_, std::move(ca));
    return v;
}

ir::IrValueId Lowering::emit_native_str_len(ir::IrValueId v_slot,
                                            uint32_t source_line) {
    // Fuera de native_poo_ (no deberia ocurrir: el value-string solo existe
    // en AOT native) -> CALL directo al baseline, sin dispatch (el init NO se
    // prepone en main no-native, asi que el fp quedaria a null).
    if (!native_poo_) {
        const std::string name = ensure_strlen_helper();
        ir::IrValueId v =
            emit_call(name, {v_slot}, ir::IrType::I64, source_line);
        return v;
    }
    // CPU dispatch Inc 5a: strlen(s) -> i64 DESPACHADO por tabla de punteros:
    // `call [__vx_strlen_fp]`.  El fp apunta al baseline (__vx_strlen_base)
    // o al @HelperOverride(strlen) del usuario.  ensure_strdisp() es
    // idempotente y marca cpu_dispatch_used_ para wirear el init en main.
    ensure_strdisp();
    const uint64_t fp_slot = strlen_fp_slot_;
    // v_fpaddr = &__vx_strlen_fp ; v_fp = LOAD i64 [v_fpaddr].
    ir::IrValueId v_fpaddr = emit_str_lit_addr(fp_slot, source_line, true);
    ir::IrValueId v_fp = emit_load_host_ptr(v_fpaddr, source_line);
    // CALLIND v_fp(s) -> i64.
    ir::IrValueId v = fn_->new_value(ir::IrType::I64);
    ir::IrInstr ci{};
    ci.op = ir::IrOp::CALLIND;
    ci.type = ir::IrType::I64;
    ci.dst = v;
    ci.func_ptr = v_fp;
    ci.operands = {v_slot};
    ci.source_line = source_line;
    emit(current_block_, std::move(ci));
    return v;
}

// -------------------------------------------------------------------------
// Vesta Embed Inc 6 (encoding UTF-8): conteo de code-points + conversion a
// UTF-16 (.length() / .wstr()).  Ambos como helpers IR aparte (loop) ->
// fuera del const-fold y del inliner (prefijo __vx_str), self-contained
// (solo malloc en utf16, overridable) -> funciona freestanding.
// -------------------------------------------------------------------------
std::string Lowering::ensure_str_cplen_helper() {
    // i64 __vx_str_cplen(u8* p, i64 byte_len):
    //   count = 0;
    //   for (i = 0; i < byte_len; i++)
    //     if ((p[i] & 0xC0) != 0x80) count++;   // no es byte de continuacion
    //   ret count;
    // Para ASCII puro coincide con byte_len (cada byte < 0x80).
    const std::string name = "__vx_str_cplen";
    if (str_cplen_helper_emitted_) return name;
    str_cplen_helper_emitted_ = true;

    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction hf;
    hf.name = name;
    hf.ret_type = ir::IrType::I64;
    const ir::IrValueId p_p = hf.new_value(ir::IrType::PTR, "%p");
    hf.values[p_p].is_param = true;
    hf.values[p_p].is_host_ptr = true;
    hf.params.push_back(p_p);
    const ir::IrValueId p_blen = hf.new_value(ir::IrType::I64, "%blen");
    hf.values[p_blen].is_param = true;
    hf.params.push_back(p_blen);
    const ir::IrBlockId entry = hf.new_block("entry");

    fn_ = &hf;
    current_block_ = entry;
    block_terminated_ = false;
    const uint32_t ln = 0;

    // Toolkit local (mismo patron que ensure_strcmp_helper).
    auto new_slot = [&]() { return stack_alloc_buf(8, ln, true); };
    auto load_i64 = [&](ir::IrValueId addr) { return emit_load_i64(addr, ln); };
    auto store_i64 = [&](ir::IrValueId addr, ir::IrValueId val) {
        emit_store_i64(addr, val, ln);
    };
    auto load_byte = [&](ir::IrValueId addr) {
        return emit_load_byte(addr, ln);
    };
    auto bin = [&](ir::IrOp op, ir::IrValueId a, ir::IrValueId b) {
        return emit_ir_binop(op, a, b, ir::IrType::U64, ln);
    };
    ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, ln);
    ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, ln);
    ir::IrValueId v_c0 = emit_const(ir::IrType::I64, 0xC0, ln);
    ir::IrValueId v_80 = emit_const(ir::IrType::I64, 0x80, ln);

    // i = 0 ; count = 0.
    ir::IrValueId s_i = new_slot();
    ir::IrValueId s_cnt = new_slot();
    store_i64(s_i, v_zero);
    store_i64(s_cnt, v_zero);

    // header: while (i < byte_len)
    ir::IrBlockId bb_hdr = fn_->new_block();
    emit_br(bb_hdr, ln);
    current_block_ = bb_hdr;
    ir::IrValueId v_i = load_i64(s_i);
    ir::IrValueId i_lt = bin(ir::IrOp::CMP_LT, v_i, p_blen);
    ir::IrBlockId bb_body = fn_->new_block();
    ir::IrBlockId bb_exit = fn_->new_block();
    emit_br_cond(i_lt, bb_body, bb_exit, ln);

    // body: b = p[i]; if ((b & 0xC0) != 0x80) count++; i++.
    current_block_ = bb_body;
    ir::IrValueId v_i2 = load_i64(s_i);
    ir::IrValueId v_at = emit_ptr_add(p_p, v_i2, ln);
    ir::IrValueId v_b = load_byte(v_at);
    ir::IrValueId v_hi = bin(ir::IrOp::AND, v_b, v_c0);
    ir::IrValueId is_cont = bin(ir::IrOp::CMP_EQ, v_hi, v_80);
    ir::IrBlockId bb_inc = fn_->new_block(); // no-continuacion -> count++
    ir::IrBlockId bb_adv = fn_->new_block(); // avanza i
    // si is_cont (==0x80) saltar el count++; si no, contarlo.
    emit_br_cond(is_cont, bb_adv, bb_inc, ln);
    current_block_ = bb_inc;
    {
        ir::IrValueId v_c = load_i64(s_cnt);
        store_i64(s_cnt, bin(ir::IrOp::ADD, v_c, v_one));
    }
    emit_br(bb_adv, ln);
    current_block_ = bb_adv;
    {
        ir::IrValueId v_i3 = load_i64(s_i);
        store_i64(s_i, bin(ir::IrOp::ADD, v_i3, v_one));
    }
    emit_br(bb_hdr, ln);

    // exit: ret count.
    current_block_ = bb_exit;
    {
        ir::IrValueId v_cnt = load_i64(s_cnt);
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::I64;
        rt.dst = ir::IR_NO_VALUE;
        rt.operands = {v_cnt};
        rt.source_line = ln;
        emit(current_block_, std::move(rt));
    }
    block_terminated_ = true;

    out_mod_->add_function(std::move(hf));
    return name;
}

ir::IrValueId Lowering::emit_native_str_cplen(ir::IrValueId v_ptr,
                                              ir::IrValueId v_blen,
                                              uint32_t source_line) {
    const std::string name = ensure_str_cplen_helper();
    ir::IrValueId v =
        emit_call(name, {v_ptr, v_blen}, ir::IrType::I64, source_line);
    return v;
}

std::string Lowering::ensure_str_to_utf16_helper() {
    // u16* __vx_str_to_utf16(u8* p, i64 byte_len):
    //   out = malloc((byte_len + 1) * 2)   // cota superior: ASCII = 1
    //   unit/byte i = 0; ob = 0;                       // i=byte idx, ob=output
    //   byte off while (i < byte_len):
    //     b0 = p[i]
    //     if      b0 < 0x80: cp = b0;                                     i+=1
    //     elif    b0 < 0xE0: cp = ((b0&0x1F)<<6)|c(1);                    i+=2
    //     elif    b0 < 0xF0: cp = ((b0&0x0F)<<12)|(c(1)<<6)|c(2);         i+=3
    //     else:              cp = ((b0&0x07)<<18)|(c(1)<<12)|(c(2)<<6)|c(3);
    //     i+=4
    //       (c(k) = p[i+k] & 0x3F)
    //     if cp < 0x10000: out[ob]=cp; ob+=2
    //     else: cp-=0x10000; out[ob]=0xD800|(cp>>10);
    //     out[ob+2]=0xDC00|(cp&0x3FF); ob+=4
    //   out[ob] = 0   // NUL u16
    //   ret out
    // Asume UTF-8 bien formado (el value-string se construye de literales/
    // concat validos).  El CALLER es dueno del buffer (transitorio para FFI).
    const std::string name = "__vx_str_to_utf16";
    if (str_to_utf16_helper_emitted_) return name;
    str_to_utf16_helper_emitted_ = true;

    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction hf;
    hf.name = name;
    hf.ret_type = ir::IrType::PTR;
    const ir::IrValueId p_p = hf.new_value(ir::IrType::PTR, "%p");
    hf.values[p_p].is_param = true;
    hf.values[p_p].is_host_ptr = true;
    hf.params.push_back(p_p);
    const ir::IrValueId p_blen = hf.new_value(ir::IrType::I64, "%blen");
    hf.values[p_blen].is_param = true;
    hf.params.push_back(p_blen);
    const ir::IrBlockId entry = hf.new_block("entry");

    fn_ = &hf;
    current_block_ = entry;
    block_terminated_ = false;
    const uint32_t ln = 0;

    // Toolkit local.
    auto new_slot = [&]() { return stack_alloc_buf(8, ln, true); };
    auto load_i64 = [&](ir::IrValueId addr) { return emit_load_i64(addr, ln); };
    auto store_i64 = [&](ir::IrValueId addr, ir::IrValueId val) {
        emit_store_i64(addr, val, ln);
    };
    auto load_byte_at = [&](ir::IrValueId base, ir::IrValueId off) {
        return emit_load_byte(emit_ptr_add(base, off, ln), ln);
    };
    auto store_u16 = [&](ir::IrValueId addr, ir::IrValueId val) {
        emit_store_typed(addr, val, ir::IrType::I16, ln);
    };
    auto bin = [&](ir::IrOp op, ir::IrValueId a, ir::IrValueId b) {
        return emit_ir_binop(op, a, b, ir::IrType::U64, ln);
    };
    auto cst = [&](uint64_t k) -> ir::IrValueId {
        return emit_const(ir::IrType::I64, k, ln);
    };
    // out = malloc((byte_len + 1) * 2).
    ir::IrValueId v_units = bin(ir::IrOp::ADD, p_blen, cst(1));
    ir::IrValueId v_bytes = bin(ir::IrOp::SHL, v_units, cst(1)); // *2
    ir::IrValueId v_out = fn_->new_value(ir::IrType::PTR);
    fn_->values[v_out].is_host_ptr = true;
    {
        ir::IrInstr al{};
        al.op = ir::IrOp::RAW_ALLOC;
        al.type = ir::IrType::PTR;
        al.dst = v_out;
        al.operands = {v_bytes};
        al.source_line = ln;
        emit(current_block_, std::move(al));
    }

    // i = 0 ; ob = 0 ; cp slot.
    ir::IrValueId s_i = new_slot();
    ir::IrValueId s_ob = new_slot();
    ir::IrValueId s_cp = new_slot();
    store_i64(s_i, cst(0));
    store_i64(s_ob, cst(0));

    // header: while (i < byte_len).
    ir::IrBlockId bb_hdr = fn_->new_block();
    emit_br(bb_hdr, ln);
    current_block_ = bb_hdr;
    ir::IrValueId v_i = load_i64(s_i);
    ir::IrValueId i_lt = bin(ir::IrOp::CMP_LT, v_i, p_blen);
    ir::IrBlockId bb_dec = fn_->new_block();
    ir::IrBlockId bb_end = fn_->new_block();
    emit_br_cond(i_lt, bb_dec, bb_end, ln);

    // bb_dec: b0 = p[i] ; 4-way segun rango.
    current_block_ = bb_dec;
    ir::IrValueId v_i0 = load_i64(s_i);
    ir::IrValueId v_b0 = load_byte_at(p_p, v_i0);
    ir::IrBlockId bb_emit = fn_->new_block(); // tras decodificar cp + avanzar i
    auto cont = [&](uint64_t k) -> ir::IrValueId {
        // (p[i + k] & 0x3F)
        ir::IrValueId off = bin(ir::IrOp::ADD, load_i64(s_i), cst(k));
        return bin(ir::IrOp::AND, load_byte_at(p_p, off), cst(0x3F));
    };
    // if b0 < 0x80
    {
        ir::IrValueId lt80 = bin(ir::IrOp::CMP_LT, v_b0, cst(0x80));
        ir::IrBlockId bb_1 = fn_->new_block();
        ir::IrBlockId bb_n1 = fn_->new_block();
        emit_br_cond(lt80, bb_1, bb_n1, ln);
        // 1 byte.
        current_block_ = bb_1;
        store_i64(s_cp, v_b0);
        store_i64(s_i, bin(ir::IrOp::ADD, load_i64(s_i), cst(1)));
        emit_br(bb_emit, ln);
        // else.
        current_block_ = bb_n1;
        ir::IrValueId ltE0 = bin(ir::IrOp::CMP_LT, v_b0, cst(0xE0));
        ir::IrBlockId bb_2 = fn_->new_block();
        ir::IrBlockId bb_n2 = fn_->new_block();
        emit_br_cond(ltE0, bb_2, bb_n2, ln);
        // 2 bytes: cp = ((b0&0x1F)<<6) | c(1).
        current_block_ = bb_2;
        {
            ir::IrValueId hi =
                bin(ir::IrOp::SHL, bin(ir::IrOp::AND, v_b0, cst(0x1F)), cst(6));
            store_i64(s_cp, bin(ir::IrOp::OR, hi, cont(1)));
            store_i64(s_i, bin(ir::IrOp::ADD, load_i64(s_i), cst(2)));
        }
        emit_br(bb_emit, ln);
        // else.
        current_block_ = bb_n2;
        ir::IrValueId ltF0 = bin(ir::IrOp::CMP_LT, v_b0, cst(0xF0));
        ir::IrBlockId bb_3 = fn_->new_block();
        ir::IrBlockId bb_4 = fn_->new_block();
        emit_br_cond(ltF0, bb_3, bb_4, ln);
        // 3 bytes: cp = ((b0&0x0F)<<12) | (c(1)<<6) | c(2).
        current_block_ = bb_3;
        {
            ir::IrValueId hi = bin(
                ir::IrOp::SHL, bin(ir::IrOp::AND, v_b0, cst(0x0F)), cst(12));
            ir::IrValueId mid = bin(ir::IrOp::SHL, cont(1), cst(6));
            store_i64(s_cp,
                      bin(ir::IrOp::OR, bin(ir::IrOp::OR, hi, mid), cont(2)));
            store_i64(s_i, bin(ir::IrOp::ADD, load_i64(s_i), cst(3)));
        }
        emit_br(bb_emit, ln);
        // 4 bytes: cp = ((b0&0x07)<<18)|(c(1)<<12)|(c(2)<<6)|c(3).
        current_block_ = bb_4;
        {
            ir::IrValueId hi = bin(
                ir::IrOp::SHL, bin(ir::IrOp::AND, v_b0, cst(0x07)), cst(18));
            ir::IrValueId m1 = bin(ir::IrOp::SHL, cont(1), cst(12));
            ir::IrValueId m2 = bin(ir::IrOp::SHL, cont(2), cst(6));
            ir::IrValueId acc = bin(ir::IrOp::OR, bin(ir::IrOp::OR, hi, m1),
                                    bin(ir::IrOp::OR, m2, cont(3)));
            store_i64(s_cp, acc);
            store_i64(s_i, bin(ir::IrOp::ADD, load_i64(s_i), cst(4)));
        }
        emit_br(bb_emit, ln);
    }

    // bb_emit: codificar cp a UTF-16 (BMP o par suplente) + ob += unidades.
    current_block_ = bb_emit;
    ir::IrValueId v_cp = load_i64(s_cp);
    ir::IrValueId is_bmp = bin(ir::IrOp::CMP_LT, v_cp, cst(0x10000));
    ir::IrBlockId bb_bmp = fn_->new_block();
    ir::IrBlockId bb_ast = fn_->new_block();
    emit_br_cond(is_bmp, bb_bmp, bb_ast, ln);
    // BMP: out[ob] = cp ; ob += 2.
    current_block_ = bb_bmp;
    {
        ir::IrValueId v_ob = load_i64(s_ob);
        store_u16(emit_ptr_add(v_out, v_ob, ln), v_cp);
        store_i64(s_ob, bin(ir::IrOp::ADD, v_ob, cst(2)));
    }
    emit_br(bb_hdr, ln);
    // Astral: cp2 = cp - 0x10000 ; hi/lo surrogates.
    current_block_ = bb_ast;
    {
        ir::IrValueId cp2 = bin(ir::IrOp::SUB, v_cp, cst(0x10000));
        ir::IrValueId hi =
            bin(ir::IrOp::OR, cst(0xD800), bin(ir::IrOp::SHR, cp2, cst(10)));
        ir::IrValueId lo =
            bin(ir::IrOp::OR, cst(0xDC00), bin(ir::IrOp::AND, cp2, cst(0x3FF)));
        ir::IrValueId v_ob = load_i64(s_ob);
        store_u16(emit_ptr_add(v_out, v_ob, ln), hi);
        ir::IrValueId v_ob2 = bin(ir::IrOp::ADD, v_ob, cst(2));
        store_u16(emit_ptr_add(v_out, v_ob2, ln), lo);
        store_i64(s_ob, bin(ir::IrOp::ADD, v_ob, cst(4)));
    }
    emit_br(bb_hdr, ln);

    // bb_end: out[ob] = 0 (NUL u16) ; ret out.
    current_block_ = bb_end;
    {
        ir::IrValueId v_ob = load_i64(s_ob);
        store_u16(emit_ptr_add(v_out, v_ob, ln), cst(0));
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::PTR;
        rt.dst = ir::IR_NO_VALUE;
        rt.operands = {v_out};
        rt.source_line = ln;
        emit(current_block_, std::move(rt));
    }
    block_terminated_ = true;

    out_mod_->add_function(std::move(hf));
    return name;
}

ir::IrValueId Lowering::emit_native_str_to_utf16(ir::IrValueId v_ptr,
                                                 ir::IrValueId v_blen,
                                                 uint32_t source_line) {
    const std::string name = ensure_str_to_utf16_helper();
    ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true;
    ir::IrInstr ca{};
    ca.op = ir::IrOp::CALL;
    ca.type = ir::IrType::PTR;
    ca.dst = v;
    ca.func_name = name;
    ca.operands = {v_ptr, v_blen};
    ca.source_line = source_line;
    emit(current_block_, std::move(ca));
    return v;
}

ir::IrValueId Lowering::emit_strcmp_dispatched(ir::IrValueId pa,
                                               ir::IrValueId la,
                                               ir::IrValueId pb,
                                               ir::IrValueId lb,
                                               uint32_t source_line) {
    // CPU dispatch Inc 5a: strcmp(pa, la, pb, lb) -> i64 (-1/0/1) DESPACHADO
    // por tabla de punteros: `call [__vx_strcmp_fp]`.  El fp apunta al
    // baseline (__vx_strcmp_base) o al @HelperOverride(strcmp) del usuario.
    // Solo se llama desde el path native_poo_ de lower_binary.  Idempotente +
    // marca cpu_dispatch_used_ para wirear el init en main.
    ensure_strdisp();
    const uint64_t fp_slot = strcmp_fp_slot_;
    // v_fpaddr = &__vx_strcmp_fp ; v_fp = LOAD i64 [v_fpaddr].
    ir::IrValueId v_fpaddr = emit_str_lit_addr(fp_slot, source_line, true);
    ir::IrValueId v_fp = emit_load_host_ptr(v_fpaddr, source_line);
    // CALLIND v_fp(pa, la, pb, lb) -> i64.
    ir::IrValueId v = fn_->new_value(ir::IrType::I64);
    ir::IrInstr ci{};
    ci.op = ir::IrOp::CALLIND;
    ci.type = ir::IrType::I64;
    ci.dst = v;
    ci.func_ptr = v_fp;
    ci.operands = {pa, la, pb, lb};
    ci.source_line = source_line;
    emit(current_block_, std::move(ci));
    return v;
}

std::string Lowering::ensure_strdata_helper() {
    // u8* __vx_strdata(u8* s): data_ptr branchless (is_heap ? ptr@0 : &s).
    // Funcion APARTE (no inline) -> una sola CALL por uso; el blacklist del
    // inliner (prefijo __vx_str) impide re-inlinearla.
    const std::string name = "__vx_strdata";
    if (strdata_helper_emitted_) return name;
    strdata_helper_emitted_ = true;

    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction hf;
    hf.name = name;
    hf.ret_type = ir::IrType::PTR;
    const ir::IrValueId p_s = hf.new_value(ir::IrType::PTR, "%s");
    hf.values[p_s].is_param = true;
    hf.values[p_s].is_host_ptr = true;
    hf.params.push_back(p_s);
    const ir::IrBlockId e = hf.new_block("entry");

    fn_ = &hf;
    current_block_ = e;

    ir::IrValueId v_data = emit_native_str_data_ptr_inline(p_s, 0);
    {
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::PTR;
        rt.operands.push_back(v_data);
        rt.source_line = 0;
        emit(current_block_, std::move(rt));
    }

    out_mod_->add_function(std::move(hf));
    return name;
}

std::string Lowering::ensure_strlen_helper() {
    // i64 __vx_strlen_base(u8* s): len branchless (is_heap ? len@8 :
    // byte[23]&0x7F).
    //
    // CPU dispatch Inc 5a: BASELINE escalar al que apunta __vx_strlen_fp por
    // defecto.  Llamable por nombre desde Vesta (un override puede delegar a
    // el).
    const std::string name = "__vx_strlen_base";
    if (strlen_helper_emitted_) return name;
    strlen_helper_emitted_ = true;

    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction hf;
    hf.name = name;
    hf.ret_type = ir::IrType::I64;
    const ir::IrValueId p_s = hf.new_value(ir::IrType::PTR, "%s");
    hf.values[p_s].is_param = true;
    hf.values[p_s].is_host_ptr = true;
    hf.params.push_back(p_s);
    const ir::IrBlockId e = hf.new_block("entry");

    fn_ = &hf;
    current_block_ = e;

    ir::IrValueId v_len = emit_native_str_len_inline(p_s, 0);
    {
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::I64;
        rt.operands.push_back(v_len);
        rt.source_line = 0;
        emit(current_block_, std::move(rt));
    }

    out_mod_->add_function(std::move(hf));
    return name;
}

void Lowering::emit_native_str_free_if_heap(ir::IrValueId v_slot,
                                            uint32_t source_line) {
    // free(is_heap ? ptr@0 : 0).  Branchless via AND-mask:
    //   mask = -is_heap   (SSO: 0 ; HEAP: ~0)
    //   to_free = ptr0 & mask  (SSO: ptr0 & 0 = 0 ; HEAP: ptr0).
    // Usamos AND (no MUL) porque valgrind sabe que `x & 0 = 0` es definido
    // aunque x tenga bits no inicializados (en SSO ptr0 = data inline);
    // MUL propagaba la indefinicion a free() -> "Conditional jump depends
    // on uninitialised value".  free(0) es no-op -> seguro para SSO y
    // move-out.
    // Se pregunta por PROPIO, no por "tiene puntero": una vista sobre
    // .rodata tambien tiene puntero, y liberarlo seria pasarle al asignador
    // una direccion que nunca le pidio.
    ir::IrValueId v_is_heap = emit_native_str_is_owned(v_slot, source_line);
    ir::IrValueId v_ptr0 =
        emit_load_typed(v_slot, ir::IrType::I64, source_line);
    // mask = -is_heap  (0 - is_heap): 0 -> 0 ; 1 -> ~0.
    ir::IrValueId v_mask =
        emit_ir_unop(ir::IrOp::NEG, v_is_heap, ir::IrType::I64, source_line);
    ir::IrValueId v_to_free_i = emit_ir_binop(ir::IrOp::AND, v_ptr0, v_mask,
                                              ir::IrType::I64, source_line);
    ir::IrValueId v_to_free = fn_->new_value(ir::IrType::PTR);
    fn_->values[v_to_free].is_host_ptr = true;
    {
        ir::IrInstr bc{};
        bc.op = ir::IrOp::BITCAST;
        bc.type = ir::IrType::PTR;
        bc.dst = v_to_free;
        bc.operands = {v_to_free_i};
        bc.source_line = source_line;
        emit(current_block_, std::move(bc));
    }
    ir::IrInstr rf{};
    rf.op = ir::IrOp::RAW_FREE;
    rf.type = ir::IrType::VOID;
    rf.dst = ir::IR_NO_VALUE;
    rf.operands = {v_to_free};
    rf.source_line = source_line;
    emit(current_block_, std::move(rf));
}

/**
 * @brief Reserva el hueco de una cadena y lo deja VACIO.
 *
 * Una cadena de las que no pasan por el recolector son veinticuatro bytes:
 * donde estan sus caracteres, cuantos hay y cuantos caben.  Reservar ese hueco
 * y dejarlo en el estado de "cadena vacia" van SIEMPRE juntos -- un hueco
 * recien reservado tiene lo que hubiera antes en la pila, y leerlo como cadena
 * da una longitud absurda y un puntero a cualquier sitio --, y por eso son un
 * solo metodo y no dos que haya que acordarse de encadenar.
 *
 * Estaba escrito cuatro veces, una por cada funcion que fabrica una cadena.
 *
 * @param source_line Linea fuente, para la depuracion.
 * @return El valor SSA con la direccion del hueco.
 */
ir::IrValueId Lowering::emit_new_native_str_slot(uint32_t source_line) {
    const ir::IrValueId v_slot = stack_alloc_buf(24, source_line, native_poo_);
    emit_zero_native_str_slot(v_slot, source_line);
    return v_slot;
}

void Lowering::emit_zero_native_str_slot(ir::IrValueId v_slot,
                                         uint32_t source_line) {
    // Zerar los bytes 0..22 del slot DEJANDO byte[23] para el caller.
    // Cubre todo lo que el move (copia de los 3 qwords) y los accesores
    // flag-aware podrian leer no inicializado en modo SSO:
    //   - qword0 (ptr@0 / data[0..7])  via STORE i64=0.
    //   - qword1 (len@8 / data[8..15]) via STORE i64=0.
    //   - bytes 16..22 (cap-low en HEAP / padding SSO) via I32+I16+U8.
    // byte[23] (flag/len SSO) NO se toca aqui: lo escribe el caller con un
    // STORE U8.  CRITICO: nunca usamos un STORE i64 a offset 16 porque el
    // patch U8 posterior a byte[23] crearia un solape parcial que el
    // store-forwarding del optimizer mal-resuelve (un LOAD i64 de offset
    // 16 forwarda el i64=0 e ignora el U8) -- rompia el MOVE de SSO.  Con
    // I32+I16+U8 (sin i64 que cubra byte[23]) el move lee bytes 16..22=0 +
    // byte[23]=len -> definido y correcto.
    auto store0 = [&](uint64_t off, ir::IrType ty) {
        ir::IrValueId v_z = emit_const(ty, 0, source_line);
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ty;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {v_z, emit_ptr_add(v_slot, (uint64_t)(off), source_line)};
        st.source_line = source_line;
        emit(current_block_, std::move(st));
    };
    store0(0, ir::IrType::I64);  // bytes 0..7   (ptr@0 / data)
    store0(8, ir::IrType::I64);  // bytes 8..15  (len@8 / data)
    store0(16, ir::IrType::I32); // bytes 16..19 (cap-lo HEAP / data SSO)
    store0(20, ir::IrType::I16); // bytes 20..21
    store0(22, ir::IrType::U8);  // byte  22  (byte[23] lo pone el caller)
    // byte[23] (flag/len) lo escribe el caller con un STORE U8.  El move
    // usa MEMCPY (emit_native_str_move_copy), no i64 LOADs, asi que el
    // solape parcial de los stores no afecta la copia (lee la memoria).
}

void Lowering::emit_str_meta_sso(ir::IrValueId v_slot, ir::IrValueId v_len,
                                 uint32_t source_line) {
    // SSO: byte[23] = len (flag bit alto 0).  STORE U8 -- NO toca bytes
    // 16..22 (que pueden contener DATA inline para len > 16).  El
    // store-forwarding del move se resuelve via MEMCPY (no i64 LOADs),
    // ver emit_native_str_move_copy.
    ir::IrValueId v_addr23 = fn_->new_value(ir::IrType::PTR);
    fn_->values[v_addr23].is_host_ptr = fn_->values[v_slot].is_host_ptr;
    {
        ir::IrValueId v_off = emit_const(ir::IrType::I64, 23, source_line);
        ir::IrInstr ad{};
        ad.op = ir::IrOp::ADD;
        ad.type = ir::IrType::I64;
        ad.dst = v_addr23;
        ad.operands = {v_slot, v_off};
        ad.source_line = source_line;
        emit(current_block_, std::move(ad));
    }
    emit_store_typed(v_addr23, v_len, ir::IrType::U8, source_line);
}

void Lowering::emit_str_meta_heap(ir::IrValueId v_slot, ir::IrValueId v_cap,
                                  uint32_t source_line) {
    // HEAP: cap en bytes 16..22, byte[23] = 0x80 (flag HEAP).  En HEAP
    // qword2 no contiene data -> escribimos cap como i64 a offset 16 (que
    // toca byte[23]=0 si cap < 2^56) y luego byte[23]=0x80 (U8).  El move
    // de un HEAP usa MEMCPY (no i64 LOADs) -> sin solape de forwarding.
    auto store = [&](ir::IrValueId addr, ir::IrValueId val, ir::IrType ty) {
        emit_store_typed(addr, val, ty, source_line);
    };
    store(emit_ptr_add(v_slot, (uint64_t)(16), source_line), v_cap,
          ir::IrType::I64);
    store(emit_ptr_add(v_slot, (uint64_t)(23), source_line),
          emit_const(ir::IrType::U8, 0x80, source_line), ir::IrType::U8);
}

void Lowering::emit_native_str_move_copy(ir::IrValueId v_dst_slot,
                                         ir::IrValueId v_src_slot,
                                         uint32_t source_line) {
    // Copia los 24 bytes del value-string @p v_src_slot a @p v_dst_slot
    // via MEMCPY (rep movsb), NO via 3 LOAD/STORE i64.  Asi evita el
    // store-forwarding del optimizer sobre qword2 (que mezcla data inline
    // + byte[23] via stores parciales) -- los i64 LOADs lo mal-resolvian
    // (perdian la longitud SSO).  MEMCPY lee la MEMORIA directamente.
    ir::IrValueId v_24 = emit_const(ir::IrType::I64, 24, source_line);
    ir::IrInstr mc{};
    mc.op = ir::IrOp::MEMCPY;
    mc.type = ir::IrType::I8;
    mc.dst = ir::IR_NO_VALUE;
    mc.operands = {v_dst_slot, v_src_slot, v_24};
    mc.source_line = source_line;
    emit(current_block_, std::move(mc));
}

void Lowering::emit_native_str_invalidate_moved(ir::IrValueId v_slot,
                                                uint32_t source_line) {
    // ptr@0 = old_ptr0 & (is_heap - 1).
    //   HEAP (is_heap=1): mask = 0     -> ptr@0 = 0  (free posterior no-op).
    //   SSO  (is_heap=0): mask = ~0    -> ptr@0 sin cambio (data inline).
    ir::IrValueId v_is_heap = emit_native_str_is_heap(v_slot, source_line);
    ir::IrValueId v_old_ptr0 =
        emit_load_typed(v_slot, ir::IrType::I64, source_line);
    // mask = is_heap - 1.
    ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, source_line);
    ir::IrValueId v_mask = emit_ir_binop(ir::IrOp::SUB, v_is_heap, v_one,
                                         ir::IrType::I64, source_line);
    // new_ptr0 = old_ptr0 & mask.
    ir::IrValueId v_new = emit_ir_binop(ir::IrOp::AND, v_old_ptr0, v_mask,
                                        ir::IrType::I64, source_line);
    emit_store_typed(v_slot, v_new, ir::IrType::I64, source_line);
}

ir::IrValueId Lowering::emit_folded_string_blob(const std::string &utf8,
                                                int enc, uint32_t line) {
    std::vector<uint8_t> bytes;
    if (!transcode_literal(utf8, enc, bytes)) return ir::IR_NO_VALUE;

    const auto key = std::make_pair(utf8, enc);
    auto it = folded_str_blobs_.find(key);
    uint64_t slot;
    if (it != folded_str_blobs_.end()) {
        slot = it->second;
    } else {
        // push_back directo (no intern): el intern deduplica POR CONTENIDO y
        // podria devolver un slot ya existente de la seccion `data` (memoria
        // VM), que al marcarlo host romperia a quien lo use como direccion VM.
        slot = static_cast<uint64_t>(
            out_mod_->static_data.push_back(bytes.data(), bytes.size()));
        auto &m = out_mod_->static_data.meta_at(slot);
        m.flags |= ir::IrModule::SD_FLAG_NON_DEDUP;
        // `.data` es lo que enruta el slot a la seccion `gdata` (memoria HOST):
        // el blob tiene que ser direccionable por una API nativa.
        m.section_name = ".data";
        // UTF-16 y UTF-32 exigen alineacion propia para leerse como u16/u32.
        m.alignment = (enc == 3) ? 2 : ((enc == 4) ? 4 : 1);
        folded_str_blobs_[key] = slot;
    }

    const ir::IrValueId v = emit_str_lit_addr(slot, line);
    fn_->values[v].is_host_ptr = true; // gdata vive en memoria host
    return v;
}

ir::IrValueId Lowering::lower_string_lit(ast::StringLitExpr *e) {
    if (!out_mod_) {
        error_at(e->loc, "lowering: out_mod_ nulo al bajar StringLitExpr");
        return ir::IR_NO_VALUE;
    }
    // Vesta Embed Inc 2: en native_poo_ un literal INTERPOLADO se baja a un
    // value-string {ptr,len,cap} construido inline (sin StringObject GC ni
    // STRMAKE/STRCAT).  Devuelve el PTR al slot owned; el caller registra
    // su STRING_FREE (var-decl caso (c) ya lo hace).  El path Full/JIT/
    // interp (sin native_poo_) NO entra aqui: cae al STR_LIT_ADDR / a la
    // promocion StringObject de los callers superiores.
    if (native_poo_ && e->is_interpolated()) {
        return build_native_string_interp(e);
    }
    // Convertir el contenido resuelto a vector<uint8_t> y registrarlo
    // (deduplicado) en static_data.  Los duplicados retornan el mismo
    // indice, ahorrando bytes en el .vel emitido.
    //
    // NUL terminator: el STR_LIT_ADDR se usa como `char*` (C string) -- p.ej.
    // pasado a una funcion que itera hasta el 0.  Sin el nul, dos literales
    // contiguos en .rodata se leen como uno solo (un `dputs("A")` seguia
    // hasta el siguiente literal).  En PE/exe "funcionaba" por relleno de
    // alineacion casual; en el .bin empaquetado no.  El +1 byte es inocuo
    // para los consumidores que usan longitud explicita (STRMAKE lee
    // value.size() bytes e ignora el nul).
    std::vector<uint8_t> bytes(e->value.begin(), e->value.end());
    bytes.push_back(0);
    const uint64_t idx = out_mod_->intern_static_data(std::move(bytes));

    // Emitir IrOp::STR_LIT_ADDR -> el emisor genera "mov rDst,
    // @Absolute(\"code.s_<idx>\")".
    const ir::IrValueId dst = emit_str_lit_addr(idx, e->loc.line);
    return dst;
}

ir::IrValueId Lowering::emit_strmake(ir::IrValueId v_buf, ir::IrValueId v_len,
                                     uint32_t source_line) {
    // STRMAKE retorna el GcHandle uint32 zero-extended a i64.  El
    // handle es indice estable en la HandleTable (no se mueve con GC),
    // asi que NO se marca is_gc_object (esa flag indica "host_ptr a
    // payload" que SI se mueve y necesita gcderef en reloads).
    const ir::IrValueId v_str = fn_->new_value(ir::IrType::I64);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::STRMAKE;
    ins.type = ir::IrType::I64;
    ins.dst = v_str;
    ins.operands = {v_buf, v_len};
    ins.is_call_site = true;
    ins.source_line = source_line;
    emit(current_block_, std::move(ins));
    return v_str;
}

ir::IrValueId Lowering::emit_string_literal_repr(ir::IrValueId v_addr,
                                                 ir::IrValueId v_len,
                                                 int64_t known_len,
                                                 uint32_t source_line) {
    // native_poo (AOT): value-string nativo (PURE_NATIVE, SSO) en vez de
    // STRMAKE (RUNTIME_DEPENDENT).  Resto de tiers: GcHandle via STRMAKE.
    if (native_poo_)
        return build_native_string_from_buffer(v_addr, v_len, source_line,
                                               known_len);
    return emit_strmake(v_addr, v_len, source_line);
}

ir::IrValueId Lowering::emit_strcat(ir::IrValueId v_a, ir::IrValueId v_b,
                                    uint32_t source_line) {
    const ir::IrValueId v_str = fn_->new_value(ir::IrType::I64);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::STRCAT;
    ins.type = ir::IrType::I64;
    ins.dst = v_str;
    ins.operands = {v_a, v_b};
    ins.is_call_site = true;
    ins.source_line = source_line;
    emit(current_block_, std::move(ins));
    return v_str;
}

ir::IrValueId Lowering::emit_strraw(ir::IrValueId v_str, uint32_t source_line) {
    // STRRAW devuelve host_ptr al buffer data[] del StringObject.
    // Es PTR-typed con is_host_ptr=true para que LOAD/STORE posteriores
    // emitan movh (memoria host) en vez de mov (memoria VM).
    const ir::IrValueId v_ptr = fn_->new_value(ir::IrType::PTR);
    fn_->values[v_ptr].is_host_ptr = true;
    ir::IrInstr ins{};
    ins.op = ir::IrOp::STRRAW;
    ins.type = ir::IrType::PTR;
    ins.dst = v_ptr;
    ins.operands = {v_str};
    ins.source_line = source_line;
    emit(current_block_, std::move(ins));
    return v_ptr;
}

ir::IrValueId Lowering::emit_strconv(ir::IrValueId v_str, uint64_t enc_imm,
                                     uint32_t source_line) {
    // AOT (native_poo): el value-string es canonicamente UTF-8 -> un `string`
    // ES una secuencia de code-points (no de bytes con un tag de encoding).
    // str_convert preserva los code-points: deep-copy del value-string (los
    // mismos bytes UTF-8).  str_length(resultado) = cplen (code-points) ->
    // correcto.  El encoding concreto solo importa en la frontera FFI, donde se
    // usa str_wstr (UTF-16) / str_raw (bytes) sobre el resultado.  El enc_imm
    // es advisory en este modelo.
    if (native_poo_) {
        (void)enc_imm;
        const ir::IrValueId v_ptr =
            emit_native_str_data_ptr(v_str, source_line);
        const ir::IrValueId v_blen = emit_native_str_len(v_str, source_line);
        return build_native_string_from_buffer(v_ptr, v_blen, source_line);
    }
    // VM/JIT: STRCONV retorna GcHandle del nuevo StringObject re-encoded.
    const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I64);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::STRCONV;
    ins.type = ir::IrType::I64;
    ins.dst = v_dst;
    ins.operands = {v_str};
    ins.imm = enc_imm;
    ins.is_call_site = true;
    ins.source_line = source_line;
    emit(current_block_, std::move(ins));
    return v_dst;
}

ir::IrValueId Lowering::emit_strgetbytes(ir::IrValueId v_str,
                                         uint32_t source_line) {
    const ir::IrValueId v_n = emit_ir_unop(ir::IrOp::STRGETBYTES, v_str,
                                           ir::IrType::U64, source_line);
    return v_n;
}

std::string Lowering::ensure_ctoa_helper() {
    // BUG-3: helper codepoint -> UTF-8 nativo (una vez por modulo).
    //   i64 __vx_ctoa(u8* buf, i64 cp)
    //     cp < 0x80    -> 1 byte;  cp < 0x800   -> 2 bytes;
    //     cp < 0x10000 -> 3 bytes; else         -> 4 bytes.
    // Paridad byte-exacta con vio_char_to_vmbuf (interp/JIT).  Vive en una
    // funcion APARTE con branches -> evita const-fold mid-expression.
    const std::string name = "__vx_ctoa";
    if (ctoa_helper_emitted_) return name;
    ctoa_helper_emitted_ = true;

    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction hf;
    hf.name = name;
    hf.ret_type = ir::IrType::I64;
    const ir::IrValueId p_buf = hf.new_value(ir::IrType::PTR, "%buf");
    hf.values[p_buf].is_param = true;
    hf.values[p_buf].is_host_ptr = true;
    hf.params.push_back(p_buf);
    const ir::IrValueId p_cp = hf.new_value(ir::IrType::I64, "%cp");
    hf.values[p_cp].is_param = true;
    hf.params.push_back(p_cp);
    const ir::IrBlockId e = hf.new_block("entry");

    fn_ = &hf;
    current_block_ = e;

    // Helpers locales de emision de instrucciones aritmeticas/bit.
    auto emit_bin = [&](ir::IrOp op, ir::IrValueId a,
                        ir::IrValueId b) -> ir::IrValueId {
        ir::IrValueId v = fn_->new_value(ir::IrType::I64);
        ir::IrInstr in{};
        in.op = op;
        in.type = ir::IrType::I64;
        in.dst = v;
        in.operands = {a, b};
        in.source_line = 0;
        emit(current_block_, std::move(in));
        return v;
    };
    auto shr = [&](ir::IrValueId a, uint64_t k) -> ir::IrValueId {
        return emit_bin(ir::IrOp::SHR, a, emit_const(ir::IrType::I64, k, 0));
    };
    auto andc = [&](ir::IrValueId a, uint64_t k) -> ir::IrValueId {
        return emit_bin(ir::IrOp::AND, a, emit_const(ir::IrType::I64, k, 0));
    };
    auto orc = [&](ir::IrValueId a, uint64_t k) -> ir::IrValueId {
        return emit_bin(ir::IrOp::OR, a, emit_const(ir::IrType::I64, k, 0));
    };
    auto store_u8_at = [&](uint64_t off, ir::IrValueId v_val) {
        ir::IrValueId v_dst = p_buf;
        if (off != 0) {
            v_dst = fn_->new_value(ir::IrType::PTR);
            fn_->values[v_dst].is_host_ptr = true;
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = v_dst;
            ad.operands = {p_buf, emit_const(ir::IrType::I64, off, 0)};
            ad.source_line = 0;
            emit(current_block_, std::move(ad));
        }
        emit_store_typed(v_dst, v_val, ir::IrType::U8, 0);
    };
    auto ret_len = [&](uint64_t len) {
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::I64;
        rt.dst = ir::IR_NO_VALUE;
        rt.operands = {emit_const(ir::IrType::I64, len, 0)};
        rt.source_line = 0;
        emit(current_block_, std::move(rt));
    };
    // cond = (cp u< limit) -> branch a bb_then, si no a bb_else.
    auto branch_ult = [&](uint64_t limit, ir::IrBlockId bb_then,
                          ir::IrBlockId bb_else) {
        ir::IrValueId v_cond = fn_->new_value(ir::IrType::I64);
        {
            ir::IrInstr in{};
            in.op = ir::IrOp::CMP_ULT;
            in.type = ir::IrType::I64;
            in.dst = v_cond;
            in.operands = {p_cp, emit_const(ir::IrType::I64, limit, 0)};
            in.source_line = 0;
            emit(current_block_, std::move(in));
        }
        emit_br_cond(v_cond, bb_then, bb_else, 0);
    };

    ir::IrBlockId bb1 = fn_->new_block("ctoa_1");
    ir::IrBlockId bb_ge1 = fn_->new_block("ctoa_ge1");
    ir::IrBlockId bb2 = fn_->new_block("ctoa_2");
    ir::IrBlockId bb_ge2 = fn_->new_block("ctoa_ge2");
    ir::IrBlockId bb3 = fn_->new_block("ctoa_3");
    ir::IrBlockId bb4 = fn_->new_block("ctoa_4");

    // if (cp < 0x80) -> 1 byte, else -> ge1.
    branch_ult(0x80, bb1, bb_ge1);
    // 1 byte: buf[0]=cp; ret 1.
    current_block_ = bb1;
    store_u8_at(0, p_cp);
    ret_len(1);
    // ge1: if (cp < 0x800) -> 2 bytes, else -> ge2.
    current_block_ = bb_ge1;
    branch_ult(0x800, bb2, bb_ge2);
    // 2 bytes: buf[0]=0xC0|(cp>>6); buf[1]=0x80|(cp&0x3F); ret 2.
    current_block_ = bb2;
    store_u8_at(0, orc(shr(p_cp, 6), 0xC0));
    store_u8_at(1, orc(andc(p_cp, 0x3F), 0x80));
    ret_len(2);
    // ge2: if (cp < 0x10000) -> 3 bytes, else -> 4 bytes.
    current_block_ = bb_ge2;
    branch_ult(0x10000, bb3, bb4);
    // 3 bytes.
    current_block_ = bb3;
    store_u8_at(0, orc(shr(p_cp, 12), 0xE0));
    store_u8_at(1, orc(andc(shr(p_cp, 6), 0x3F), 0x80));
    store_u8_at(2, orc(andc(p_cp, 0x3F), 0x80));
    ret_len(3);
    // 4 bytes.
    current_block_ = bb4;
    store_u8_at(0, orc(shr(p_cp, 18), 0xF0));
    store_u8_at(1, orc(andc(shr(p_cp, 12), 0x3F), 0x80));
    store_u8_at(2, orc(andc(shr(p_cp, 6), 0x3F), 0x80));
    store_u8_at(3, orc(andc(p_cp, 0x3F), 0x80));
    ret_len(4);

    out_mod_->add_function(std::move(hf));
    return name;
}

ir::IrValueId Lowering::stringify_primitive_via_native(ir::IrValueId v_val,
                                                       const char *native_fn,
                                                       uint32_t source_line) {
    const int ln = static_cast<int>(source_line);
    /* 1. ALLOCA 32 bytes -- buffer en stack VM.  Suficiente para
     *    todos los tipos: i64=20+signo, hex=18, "false"=5, UTF-8 4 B. */
    ir::IrValueId v_buf = stack_alloc_buf(32, ln);
    /* 2. proc_ptr via getproc. */
    const ir::IrValueId v_proc = emit_getproc(ln);
    /* 3. CALLN al native: devuelve length escrita en buf. */
    /* Se dice lo que hace, porque aqui se sabe: la familia `*_to_vmbuf`
     * formatea `value` y deja los bytes en el buffer del SEGUNDO argumento.
     * Nada mas -- ni lee otra memoria, ni hace E/S pese al prefijo `vio_`, ni
     * puede lanzar, y dos llamadas iguales dan lo mismo.
     *
     * Sin decirlo, cada `${n}` de una interpolacion era una barrera total para
     * cuanto la rodeara (52 sitios solo en std.memory), que es lo unico honesto
     * ante una funcion nativa de la que no se sabe nada. */
    ir::IrNativeEffects fx;
    fx.declared = true;
    fx.writes_pointee = 1u << 1; // el buffer destino
    ir::IrValueId v_len =
        emit_native_call(kVestaIoLib, native_fn, {v_proc, v_buf, v_val},
                         ir::IrType::I64, ln, &fx);
    /* 4. STRMAKE desde buf vm_mem. */
    ir::IrValueId v_h = emit_strmake(v_buf, v_len, ln);
    return v_h;
}

bool Lowering::transcode_literal(const std::string &utf8, int enc,
                                 std::vector<uint8_t> &out) {
    out.clear();
    // ENC_ANSI (1) NO se pliega: la codepage es del sistema donde se EJECUTA,
    // no donde se compila.  Plegarlo produciria bytes correctos solo en las
    // maquinas que compartan codepage con la de compilacion.
    if (enc == 1) return false;

    // Decodificar la forma canonica (UTF-8) a code points.
    std::vector<uint32_t> cps;
    cps.reserve(utf8.size());
    for (size_t i = 0; i < utf8.size();) {
        const uint8_t b = static_cast<uint8_t>(utf8[i]);
        uint32_t cp = 0;
        size_t n = 1;
        if ((b & 0x80) == 0) {
            cp = b;
        } else if ((b & 0xE0) == 0xC0) {
            cp = b & 0x1Fu;
            n = 2;
        } else if ((b & 0xF0) == 0xE0) {
            cp = b & 0x0Fu;
            n = 3;
        } else if ((b & 0xF8) == 0xF0) {
            cp = b & 0x07u;
            n = 4;
        } else {
            return false; // byte inicial invalido
        }
        if (i + n > utf8.size()) return false;
        for (size_t k = 1; k < n; ++k) {
            const uint8_t c = static_cast<uint8_t>(utf8[i + k]);
            if ((c & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3Fu);
        }
        cps.push_back(cp);
        i += n;
    }

    switch (enc) {
    case 0: // ENC_ASCII: solo representable si TODO cae por debajo de 0x80.
        for (uint32_t cp : cps) {
            if (cp >= 0x80) return false;
            out.push_back(static_cast<uint8_t>(cp));
        }
        out.push_back(0);
        return true;
    case 2: // ENC_UTF8: la forma canonica ya lo es.
        out.assign(utf8.begin(), utf8.end());
        out.push_back(0);
        return true;
    case 3: {
        // ENC_UTF16 (LE), con pares sustitutos.
        auto put16 = [&out](uint16_t u) {
            out.push_back(static_cast<uint8_t>(u & 0xFFu));
            out.push_back(static_cast<uint8_t>((u >> 8) & 0xFFu));
        };
        for (uint32_t cp : cps) {
            if (cp < 0x10000u) {
                put16(static_cast<uint16_t>(cp));
            } else {
                const uint32_t v = cp - 0x10000u;
                put16(static_cast<uint16_t>(0xD800u + (v >> 10)));
                put16(static_cast<uint16_t>(0xDC00u + (v & 0x3FFu)));
            }
        }
        put16(0);
        return true;
    }
    case 4: // ENC_UTF32 (LE).
        for (uint32_t cp : cps) {
            out.push_back(static_cast<uint8_t>(cp & 0xFFu));
            out.push_back(static_cast<uint8_t>((cp >> 8) & 0xFFu));
            out.push_back(static_cast<uint8_t>((cp >> 16) & 0xFFu));
            out.push_back(static_cast<uint8_t>((cp >> 24) & 0xFFu));
        }
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
        return true;
    default: return false;
    }
}

std::string Lowering::ensure_btoa_helper() {
    // Vesta Embed Inc 2: helper bool->string nativo (una vez por modulo).
    //   i64 __vx_btoa(u8* buf, i64 b)
    //     if (b != 0) { buf <- "true";  ret 4; }
    //     else        { buf <- "false"; ret 5; }
    // Vive en una funcion APARTE con branch -> el optimizer no foldea el
    // append condicional mid-expression con argumento constante.
    const std::string name = "__vx_btoa";
    if (btoa_helper_emitted_) return name;
    btoa_helper_emitted_ = true;

    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction hf;
    hf.name = name;
    hf.ret_type = ir::IrType::I64;
    const ir::IrValueId p_buf = hf.new_value(ir::IrType::PTR, "%buf");
    hf.values[p_buf].is_param = true;
    hf.values[p_buf].is_host_ptr = true;
    hf.params.push_back(p_buf);
    const ir::IrValueId p_b = hf.new_value(ir::IrType::I64, "%b");
    hf.values[p_b].is_param = true;
    hf.params.push_back(p_b);
    const ir::IrBlockId e = hf.new_block("entry");

    fn_ = &hf;
    current_block_ = e;

    // Helper: STORE empaquetado de los bytes de `s` en buf[off..].
    auto write_bytes = [&](const std::string &s) {
        std::vector<uint8_t> data(s.begin(), s.end());
        auto store_chunk = [&](uint64_t off, uint64_t val, ir::IrType ty) {
            ir::IrValueId v_dst = emit_ptr_add(p_buf, off, 0);
            ir::IrInstr st{};
            st.op = ir::IrOp::STORE;
            st.type = ty;
            st.dst = ir::IR_NO_VALUE;
            st.operands = {emit_const(ty, val, 0), v_dst};
            st.source_line = 0;
            emit(current_block_, std::move(st));
        };
        auto pack = [&](uint64_t pos, int n) { return pack_le(data, pos, n); };
        const uint64_t plen = data.size();
        uint64_t pos = 0;
        for (; pos + 4 <= plen; pos += 4)
            store_chunk(pos, pack(pos, 4), ir::IrType::I32);
        if (pos + 2 <= plen) {
            store_chunk(pos, pack(pos, 2), ir::IrType::I16);
            pos += 2;
        }
        if (pos + 1 <= plen) {
            store_chunk(pos, pack(pos, 1), ir::IrType::U8);
            pos += 1;
        }
    };
    auto ret_len = [&](uint64_t len) {
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::I64;
        rt.dst = ir::IR_NO_VALUE;
        rt.operands = {emit_const(ir::IrType::I64, len, 0)};
        rt.source_line = 0;
        emit(current_block_, std::move(rt));
    };

    // if (b != 0) -> bb_true ; else -> bb_false.
    ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, 0);
    ir::IrValueId v_cond =
        emit_ir_binop(ir::IrOp::CMP_NE, p_b, v_zero, ir::IrType::I64, 0);
    ir::IrBlockId bb_true = fn_->new_block("btoa_true");
    ir::IrBlockId bb_false = fn_->new_block("btoa_false");
    {
        emit_br_cond(v_cond, bb_true, bb_false, 0);
    }
    current_block_ = bb_true;
    write_bytes("true");
    ret_len(4);
    current_block_ = bb_false;
    write_bytes("false");
    ret_len(5);

    out_mod_->add_function(std::move(hf));
    return name;
}

} // namespace vx
