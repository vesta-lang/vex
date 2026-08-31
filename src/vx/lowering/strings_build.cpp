/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/strings_build.cpp
 * @brief Construir una cadena nativa: a partir de un caracter, de un trozo, de
 *        otras dos, de un numero.
 *
 * Separado de la representacion (@c strings.cpp) porque el problema es otro:
 * ahi se trata de LEER una cadena que ya existe -- y por eso todo empieza
 * mirando si es corta o larga --, y aqui de fabricarla, que es decidir cuanto
 * ocupa, si cabe dentro de la propia estructura o hay que pedir memoria, y
 * dejar sus metadatos coherentes con esa eleccion.
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
ir::IrValueId Lowering::build_native_string_from_char(ir::IrValueId v_char,
                                                      uint32_t source_line) {
    // Vesta Embed: cast (string)<char> -> value-string de UN caracter.
    // String Inc 5 (SSO): un solo char (len=1 <= 22) SIEMPRE es SSO ->
    // CERO malloc.  La data inline en bytes[0..1]: byte[0]=char, byte[1]=
    // nul, byte[23]=1 (flag SSO=0).

    // 1. Slot de 24 bytes en stack.
    const ir::IrValueId v_slot = emit_new_native_str_slot(source_line);

    auto store_u8 = [&](ir::IrValueId v_addr, ir::IrValueId v_val) {
        emit_store_typed(v_addr, v_val, ir::IrType::U8, source_line);
    };

    // byte[0] = char.
    store_u8(v_slot, v_char);
    // byte[1] = nul.
    store_u8(emit_ptr_add(v_slot, (uint64_t)(1), source_line),
             emit_const(ir::IrType::U8, 0, source_line));
    // qword2 = (1 << 56): byte[23]=1 (SSO len 1), bytes 16..22=0.
    emit_str_meta_sso(v_slot, emit_const(ir::IrType::I64, 1, source_line),
                      source_line);

    return v_slot;
}

ir::IrValueId Lowering::build_native_string_concat(ir::IrValueId v_a,
                                                   ir::IrValueId v_b,
                                                   uint32_t source_line) {
    // Vesta Embed Inc 1: a + b -> nuevo string owned.  String Inc 5 (SSO):
    // si el total cabe inline (<= 22) construye SSO (cero malloc); si no,
    // HEAP.  v_a / v_b son PTR a slots value-string (no se consumen);
    // leemos su (ptr, len) via los accesores flag-aware.  Branch real
    // porque el malloc debe ser condicional.

    auto emit_memcpy = [&](ir::IrValueId dst, ir::IrValueId src,
                           ir::IrValueId len) {
        this->emit_memcpy(dst, src, len, source_line);
    };
    auto store_at = [&](ir::IrValueId addr, ir::IrValueId val, ir::IrType ty) {
        emit_store_typed(addr, val, ty, source_line);
    };

    // 1. (ptr, len) de ambos operandos via accesores flag-aware.
    ir::IrValueId v_a_ptr = emit_native_str_data_ptr(v_a, source_line);
    ir::IrValueId v_a_len = emit_native_str_len(v_a, source_line);
    ir::IrValueId v_b_ptr = emit_native_str_data_ptr(v_b, source_line);
    ir::IrValueId v_b_len = emit_native_str_len(v_b, source_line);

    // 2. total = la + lb.
    ir::IrValueId v_total = emit_ir_binop(ir::IrOp::ADD, v_a_len, v_b_len,
                                          ir::IrType::I64, source_line);

    // 3. Slot de 24 bytes del resultado.
    const ir::IrValueId v_slot = emit_new_native_str_slot(source_line);

    // 4. cond = (total > 22) -> HEAP.
    ir::IrValueId v_22 = emit_const(ir::IrType::I64, 22, source_line);
    ir::IrValueId v_cond = fn_->new_value(ir::IrType::BOOL);
    {
        ir::IrInstr c{};
        c.op = ir::IrOp::CMP_GT;
        c.type = ir::IrType::I64;
        c.dst = v_cond;
        c.operands = {v_total, v_22};
        c.source_line = source_line;
        emit(current_block_, std::move(c));
    }
    const ir::IrBlockId heap_bb = fn_->new_block("concat_heap");
    const ir::IrBlockId sso_bb = fn_->new_block("concat_sso");
    const ir::IrBlockId merge_bb = fn_->new_block("concat_merge");
    {
        emit_br_cond(v_cond, heap_bb, sso_bb, source_line);
    }

    // --- HEAP: total > 22 ---
    current_block_ = heap_bb;
    {
        ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, source_line);
        ir::IrValueId v_cap = emit_ir_binop(ir::IrOp::ADD, v_total, v_one,
                                            ir::IrType::I64, source_line);
        ir::IrValueId v_buf = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_buf].is_host_ptr = true;
        {
            ir::IrInstr ra{};
            ra.op = ir::IrOp::RAW_ALLOC;
            ra.type = ir::IrType::PTR;
            ra.dst = v_buf;
            ra.operands = {v_cap};
            ra.source_line = source_line;
            emit(current_block_, std::move(ra));
        }
        emit_memcpy(v_buf, v_a_ptr, v_a_len);
        emit_memcpy(emit_ptr_add(v_buf, v_a_len, source_line), v_b_ptr,
                    v_b_len);
        store_at(emit_ptr_add(v_buf, v_total, source_line),
                 emit_const(ir::IrType::U8, 0, source_line), ir::IrType::U8);
        store_at(v_slot, v_buf, ir::IrType::I64);
        store_at(emit_ptr_add(v_slot,
                              emit_const(ir::IrType::I64, 8, source_line),
                              source_line),
                 v_total, ir::IrType::I64);
        // qword2 = cap | flag HEAP (un solo i64).
        emit_str_meta_heap(v_slot, v_cap, source_line);
        emit_br(merge_bb, source_line);
    }

    // --- SSO: total <= 22 ---
    current_block_ = sso_bb;
    {
        emit_memcpy(v_slot, v_a_ptr, v_a_len);
        emit_memcpy(emit_ptr_add(v_slot, v_a_len, source_line), v_b_ptr,
                    v_b_len);
        store_at(emit_ptr_add(v_slot, v_total, source_line),
                 emit_const(ir::IrType::U8, 0, source_line), ir::IrType::U8);
        // qword2 = (total << 56): byte[23]=total (SSO).
        emit_str_meta_sso(v_slot, v_total, source_line);
        emit_br(merge_bb, source_line);
    }

    current_block_ = merge_bb;
    return v_slot;
}

ir::IrValueId Lowering::build_native_string_slice(ir::IrValueId v_src,
                                                  ir::IrValueId v_lo,
                                                  ir::IrValueId v_hi,
                                                  bool inclusive,
                                                  uint32_t source_line) {
    // String Inc 3: `s[a..b]` (exclusivo) o `s[a..=b]` (inclusivo) ->
    // NUEVO string owned con la copia de los bytes [a, b) (o [a, b]).
    // Repr value-string {ptr@0,len@8,cap@16} en stack + buffer fresco en
    // heap.  La copia usa MEMCPY (rep movsb).  Todas las ops son
    // PURE_NATIVE/LIBC (RAW_ALLOC=malloc, MEMCPY=rep movsb).  v1 asume
    // indices validos (a <= b <= src.len); indices negativos / OOB no
    // soportados (mismo contrato que el resto del AOT bare).
    auto emit_sub = [&](ir::IrValueId a, ir::IrValueId b) -> ir::IrValueId {
        ir::IrValueId v =
            emit_ir_binop(ir::IrOp::SUB, a, b, ir::IrType::I64, source_line);
        return v;
    };
    auto emit_add = [&](ir::IrValueId a, ir::IrValueId b) -> ir::IrValueId {
        ir::IrValueId v =
            emit_ir_binop(ir::IrOp::ADD, a, b, ir::IrType::I64, source_line);
        return v;
    };

    // 1. Cargar el data_ptr del slot fuente via accesor flag-aware (SSO
    //    o HEAP).  Los limites a/b ya estan en regs.
    ir::IrValueId v_src_ptr = emit_native_str_data_ptr(v_src, source_line);

    // 2. len = b - a  (o  b - a + 1  si es `..=` inclusivo).
    ir::IrValueId v_len = emit_sub(v_hi, v_lo);
    if (inclusive) {
        ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, source_line);
        v_len = emit_add(v_len, v_one);
    }

    // 3. Slot de 24 bytes del resultado.
    const ir::IrValueId v_slot = emit_new_native_str_slot(source_line);

    // 4. src_off = src.data + a.  String Inc 5 (SSO): finalize decide
    //    SSO vs HEAP runtime (cero malloc si el slice cabe inline).
    ir::IrValueId v_src_off = emit_ptr_add(v_src_ptr, v_lo, source_line);
    build_native_string_finalize(v_slot, v_src_off, v_len, source_line);

    return v_slot;
}

ir::IrValueId Lowering::build_native_string_index_char(ir::IrValueId v_src,
                                                       ir::IrValueId v_idx,
                                                       uint32_t source_line) {
    // String Inc 3: `s[i]` -> el byte en la posicion i del value-string.
    // String Inc 5 (SSO): data_ptr via accesor flag-aware + LOAD u8 de
    // [data+i].  El resultado es un U8 zero-extended (0-255) que el type
    // checker marca como char.  v1 asume i valido (0 <= i < src.len).
    ir::IrValueId v_ptr = emit_native_str_data_ptr(v_src, source_line);
    // addr = ptr + i (host_ptr).
    ir::IrValueId v_addr = emit_ptr_add(v_ptr, v_idx, source_line);
    // LOAD u8: el codegen zero-extiende el byte a un registro completo.
    ir::IrValueId v_byte = emit_load_typed(v_addr, ir::IrType::U8, source_line);
    return v_byte;
}

void Lowering::build_native_string_finalize(ir::IrValueId v_slot,
                                            ir::IrValueId v_src_ptr,
                                            ir::IrValueId v_len,
                                            uint32_t source_line,
                                            int64_t known_len) {
    // String Inc 5 (SSO): rellena el slot value-string ya alocado (24
    // bytes) decidiendo SSO vs HEAP segun la longitud.  Si len <= 22 -> SSO
    // (data inline, cero malloc); si len > 22 -> HEAP (RAW_ALLOC + MEMCPY +
    // ptr@0/len@8/cap@16 + flag).  Cada rama finaliza COMPLETAMENTE el slot
    // -> no necesita PHI.  Si @p known_len >= 0 (Tier B str_make) la decision
    // es COMPILE-TIME -> se emite solo el cuerpo aplicable, SIN rama runtime.
    auto emit_memcpy = [&](ir::IrValueId dst, ir::IrValueId src,
                           ir::IrValueId len) {
        this->emit_memcpy(dst, src, len, source_line);
    };
    auto store_at = [&](ir::IrValueId addr, ir::IrValueId val, ir::IrType ty) {
        emit_store_typed(addr, val, ty, source_line);
    };

    // Cuerpos SSO/HEAP como lambdas (emiten en current_block_, SIN el BR final
    // -> el caller decide si hay rama o no).  Reusados por la rama runtime y
    // por el fast-path const (Tier B).
    auto fill_heap = [&]() {
        // cap = len + 1.
        ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, source_line);
        ir::IrValueId v_cap = emit_ir_binop(ir::IrOp::ADD, v_len, v_one,
                                            ir::IrType::I64, source_line);
        // buf = RAW_ALLOC(cap).
        ir::IrValueId v_buf = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_buf].is_host_ptr = true;
        {
            ir::IrInstr ra{};
            ra.op = ir::IrOp::RAW_ALLOC;
            ra.type = ir::IrType::PTR;
            ra.dst = v_buf;
            ra.operands = {v_cap};
            ra.source_line = source_line;
            emit(current_block_, std::move(ra));
        }
        // MEMCPY buf <- src (len bytes).
        emit_memcpy(v_buf, v_src_ptr, v_len);
        // nul en buf[len].
        store_at(emit_ptr_add(v_buf, v_len, source_line),
                 emit_const(ir::IrType::U8, 0, source_line), ir::IrType::U8);
        // Campos: ptr@0 = buf, len@8 = len, qword2 = cap | flag HEAP.
        store_at(v_slot, v_buf, ir::IrType::I64);
        store_at(emit_ptr_add(v_slot,
                              emit_const(ir::IrType::I64, 8, source_line),
                              source_line),
                 v_len, ir::IrType::I64);
        emit_str_meta_heap(v_slot, v_cap, source_line);
    };
    auto fill_sso = [&]() {
        // MEMCPY slot <- src (len bytes; data inline en bytes[0..len)).
        // v_slot es PTR al inicio del struct; lo usamos como dst directo.
        emit_memcpy(v_slot, v_src_ptr, v_len);
        // nul en slot[len].
        store_at(emit_ptr_add(v_slot, v_len, source_line),
                 emit_const(ir::IrType::U8, 0, source_line), ir::IrType::U8);
        // qword2 = (len << 56): byte[23]=len (SSO).
        emit_str_meta_sso(v_slot, v_len, source_line);
    };

    // Tier B (str_make con len constante): decision compile-time, SIN rama.
    if (known_len >= 0) {
        if (known_len <= 22)
            fill_sso();
        else
            fill_heap();
        return;
    }

    // Tier C (len runtime): rama CMP_GT(len, 22) -> heap_bb / sso_bb -> merge.
    ir::IrValueId v_22 = emit_const(ir::IrType::I64, 22, source_line);
    ir::IrValueId v_cond = fn_->new_value(ir::IrType::BOOL);
    {
        ir::IrInstr c{};
        c.op = ir::IrOp::CMP_GT;
        c.type = ir::IrType::I64;
        c.dst = v_cond;
        c.operands = {v_len, v_22};
        c.source_line = source_line;
        emit(current_block_, std::move(c));
    }

    const ir::IrBlockId heap_bb = fn_->new_block("strfin_heap");
    const ir::IrBlockId sso_bb = fn_->new_block("strfin_sso");
    const ir::IrBlockId merge_bb = fn_->new_block("strfin_merge");
    {
        emit_br_cond(v_cond, heap_bb, sso_bb, source_line);
    }
    auto close_to_merge = [&]() { emit_br(merge_bb, source_line); };
    current_block_ = heap_bb;
    fill_heap();
    close_to_merge();
    current_block_ = sso_bb;
    fill_sso();
    close_to_merge();
    current_block_ = merge_bb;
}

ir::IrValueId Lowering::build_native_string_from_buffer(ir::IrValueId v_ptr,
                                                        ir::IrValueId v_len,
                                                        uint32_t source_line,
                                                        int64_t known_len) {
    // str_make: COPIA known/runtime len bytes de v_ptr a un value-string
    // PROPIO (sin GC, RAII).  Slot 24B + finalize (SSO/HEAP; copia dispatched).
    const ir::IrValueId v_slot = emit_new_native_str_slot(source_line);
    build_native_string_finalize(v_slot, v_ptr, v_len, source_line, known_len);
    return v_slot;
}

void Lowering::build_native_string_append_inplace(ir::IrValueId v_dst_slot,
                                                  ir::IrValueId v_app_ptr,
                                                  ir::IrValueId v_app_len,
                                                  uint32_t source_line) {
    // Vesta Embed Inc 2: `s += t` (y append de interpolacion).  Muta el
    // value-string apuntado por @p v_dst_slot in place.  String Inc 5
    // (SSO): branch en new_len > 22.  Como un HEAP nunca decrece
    // (new_len >= old_len), HEAP solo transiciona a HEAP; SSO puede
    // crecer SSO->SSO (cero malloc, data inline) o SSO->HEAP (alocar +
    // copiar la data inline al heap).  El free del buffer viejo solo se
    // hace si el slot estaba en HEAP (la data SSO es inline, no se libera).
    // Todas las ops son PURE_NATIVE/LIBC.
    auto emit_memcpy = [&](ir::IrValueId dst, ir::IrValueId src,
                           ir::IrValueId len) {
        this->emit_memcpy(dst, src, len, source_line);
    };
    auto store_at = [&](ir::IrValueId addr, ir::IrValueId val, ir::IrType ty) {
        emit_store_typed(addr, val, ty, source_line);
    };

    // 1. Estado actual del slot via accesores flag-aware.  v_old_data es
    //    el host_ptr a los bytes (SSO -> &slot; HEAP -> ptr@0).
    ir::IrValueId v_old_data =
        emit_native_str_data_ptr(v_dst_slot, source_line);
    ir::IrValueId v_old_len = emit_native_str_len(v_dst_slot, source_line);
    // 2. new_len = old_len + app_len ; new_cap = new_len + 1.
    ir::IrValueId v_new_len = emit_ir_binop(ir::IrOp::ADD, v_old_len, v_app_len,
                                            ir::IrType::I64, source_line);
    ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, source_line);
    ir::IrValueId v_new_cap = emit_ir_binop(ir::IrOp::ADD, v_new_len, v_one,
                                            ir::IrType::I64, source_line);

    // 3. Branch new_len > 22.  HEAP nunca decrece (new_len >= old_len) ->
    //    HEAP solo transiciona a HEAP; SSO crece SSO->SSO (cero malloc,
    //    data inline) o SSO->HEAP.  El free del buffer viejo se hace en la
    //    rama HEAP (solo si era HEAP).
    ir::IrValueId v_22 = emit_const(ir::IrType::I64, 22, source_line);
    ir::IrValueId v_cond = fn_->new_value(ir::IrType::BOOL);
    {
        ir::IrInstr c{};
        c.op = ir::IrOp::CMP_GT;
        c.type = ir::IrType::I64;
        c.dst = v_cond;
        c.operands = {v_new_len, v_22};
        c.source_line = source_line;
        emit(current_block_, std::move(c));
    }
    const ir::IrBlockId heap_bb = fn_->new_block("append_heap");
    const ir::IrBlockId sso_bb = fn_->new_block("append_sso");
    const ir::IrBlockId merge_bb = fn_->new_block("append_merge");
    {
        emit_br_cond(v_cond, heap_bb, sso_bb, source_line);
    }

    // --- HEAP: new_len > 22 (SSO->HEAP o HEAP->HEAP) ---
    current_block_ = heap_bb;
    {
        ir::IrValueId v_new_buf = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_new_buf].is_host_ptr = true;
        {
            ir::IrInstr ra{};
            ra.op = ir::IrOp::RAW_ALLOC;
            ra.type = ir::IrType::PTR;
            ra.dst = v_new_buf;
            ra.operands = {v_new_cap};
            ra.source_line = source_line;
            emit(current_block_, std::move(ra));
        }
        // Copiar lo viejo (old_data: inline o heap) + lo nuevo ANTES de
        // liberar y de tocar los campos.
        emit_memcpy(v_new_buf, v_old_data, v_old_len);
        emit_memcpy(emit_ptr_add(v_new_buf, v_old_len, source_line), v_app_ptr,
                    v_app_len);
        store_at(emit_ptr_add(v_new_buf, v_new_len, source_line),
                 emit_const(ir::IrType::U8, 0, source_line), ir::IrType::U8);
        // Liberar el buffer viejo SOLO si era HEAP (lee el flag/ptr0 del
        // slot AQUI, antes de los stores).  new_buf es malloc fresco que
        // nunca aliasa el viejo -> sin doble-free.
        emit_native_str_free_if_heap(v_dst_slot, source_line);
        store_at(v_dst_slot, v_new_buf, ir::IrType::I64);
        store_at(emit_ptr_add(v_dst_slot,
                              emit_const(ir::IrType::I64, 8, source_line),
                              source_line),
                 v_new_len, ir::IrType::I64);
        // qword2 = cap | flag HEAP (un solo i64).
        emit_str_meta_heap(v_dst_slot, v_new_cap, source_line);
        emit_br(merge_bb, source_line);
    }

    // --- SSO: new_len <= 22 (siempre SSO->SSO; la data vieja ya esta
    //     inline en slot[0..old_len), solo appendeamos lo nuevo) ---
    current_block_ = sso_bb;
    {
        // app -> slot[old_len..old_len+app_len).  old_data == &slot, asi
        // que la data vieja ya esta en su sitio; solo copiamos lo nuevo.
        emit_memcpy(emit_ptr_add(v_dst_slot, v_old_len, source_line), v_app_ptr,
                    v_app_len);
        store_at(emit_ptr_add(v_dst_slot, v_new_len, source_line),
                 emit_const(ir::IrType::U8, 0, source_line), ir::IrType::U8);
        // qword2 = (new_len << 56): byte[23]=new_len (SSO).
        emit_str_meta_sso(v_dst_slot, v_new_len, source_line);
        emit_br(merge_bb, source_line);
    }

    current_block_ = merge_bb;
}

ir::IrValueId Lowering::emit_native_itoa_to_buf(ir::IrValueId v_buf,
                                                ir::IrValueId v_val,
                                                bool is_signed,
                                                uint32_t source_line) {
    // Vesta Embed Inc 2: itoa decimal INLINE (sin helper nativo, AOT bare no
    // tiene plugin).  Escribe la representacion ASCII de v_val (I64) en
    // v_buf (host, >= 24 bytes garantizados por el caller) y devuelve la
    // longitud escrita (sin nul).
    //
    // Algoritmo:
    //   1. Si is_signed y val < 0: emitir '-', negar val (abs).  Trabajamos
    //      con un magnitude unsigned a partir de aqui.
    //   2. Caso val==0: escribir '0', len=1.
    //   3. Loop: extraer digitos por mod 10 (val % 10 + '0') a un buffer
    //      temporal en orden inverso, val /= 10, hasta val==0.
    //   4. Loop de inversion: copiar los digitos del temporal al v_buf en
    //      el orden correcto.
    // Para evitar PHIs complejos, usamos slots ALLOCA (mem2reg los promueve
    // en O2) para val, write index, y el buffer temporal de digitos.
    // Todas las ops PURE_NATIVE (ALLOCA/LOAD/STORE/DIV/MOD/ADD/SUB/CMP/BR).

    auto new_slot = [&](uint64_t bytes) {
        return stack_alloc_buf(bytes, source_line, native_poo_);
    };
    auto load_i64 = [&](ir::IrValueId addr) {
        return emit_load_i64(addr, source_line);
    };
    auto store_i64 = [&](ir::IrValueId addr, ir::IrValueId val) {
        emit_store_i64(addr, val, source_line);
    };
    auto store_byte = [&](ir::IrValueId addr, ir::IrValueId val) {
        emit_store_typed(addr, val, ir::IrType::U8, source_line);
    };
    auto bin = [&](ir::IrOp op, ir::IrValueId a, ir::IrValueId b) {
        return emit_ir_binop(op, a, b, ir::IrType::U64, source_line);
    };
    auto new_block = [&]() -> ir::IrBlockId { return fn_->new_block(); };
    auto v_one_helper = [&](uint32_t) -> ir::IrValueId {
        return emit_const(ir::IrType::I64, 1, source_line);
    };
    auto cmp = [&](ir::IrOp op, ir::IrValueId a,
                   ir::IrValueId b) -> ir::IrValueId {
        ir::IrValueId v = fn_->new_value(ir::IrType::I64);
        ir::IrInstr in{};
        in.op = op;
        in.type = ir::IrType::I64;
        in.dst = v;
        in.operands = {a, b};
        in.source_line = source_line;
        emit(current_block_, std::move(in));
        return v;
    };

    // Slots: mag (magnitud unsigned), tmp_buf (digitos inversos, 24B),
    //        di (indice de escritura en tmp), out_len (longitud final),
    //        out_pos (indice de escritura en v_buf).
    ir::IrValueId s_mag = new_slot(8);
    ir::IrValueId s_tmp = new_slot(24);
    ir::IrValueId s_di = new_slot(8);
    ir::IrValueId s_pos = new_slot(8);

    ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, source_line);
    ir::IrValueId v_ten = emit_const(ir::IrType::I64, 10, source_line);
    ir::IrValueId v_z48 = emit_const(ir::IrType::I64, 48, source_line); // '0'

    store_i64(s_pos, v_zero); // out_pos = 0
    store_i64(s_di, v_zero);  // di = 0

    // --- Manejo del signo ---
    // Bloques: bb_neg (val<0), bb_setmag (mag = val o -val), join.
    if (is_signed) {
        ir::IrValueId is_neg = cmp(ir::IrOp::CMP_LT, v_val, v_zero); // signed <
        uint32_t bb_neg = new_block();
        uint32_t bb_pos = new_block();
        uint32_t bb_after_sign = new_block();
        emit_br_cond(is_neg, bb_neg, bb_pos, source_line);
        // bb_neg: escribir '-' en v_buf[0], pos=1, mag = 0 - val.
        current_block_ = bb_neg;
        {
            ir::IrValueId v_minus =
                emit_const(ir::IrType::I64, 45, source_line);
            store_byte(v_buf, v_minus);
            store_i64(s_pos, v_one_helper(source_line));
            ir::IrValueId v_negmag = bin(ir::IrOp::SUB, v_zero, v_val);
            store_i64(s_mag, v_negmag);
        }
        emit_br(bb_after_sign, source_line);
        // bb_pos: mag = val.
        current_block_ = bb_pos;
        store_i64(s_mag, v_val);
        emit_br(bb_after_sign, source_line);
        current_block_ = bb_after_sign;
    } else {
        store_i64(s_mag, v_val);
    }

    // --- Caso especial mag == 0 ---
    // Bloques: bb_zero ('0', di=1), bb_digits (loop de extraccion), bb_inv.
    ir::IrValueId v_mag0 = load_i64(s_mag);
    ir::IrValueId is_zero = cmp(ir::IrOp::CMP_EQ, v_mag0, v_zero);
    uint32_t bb_zero = new_block();
    uint32_t bb_loop_hdr = new_block();
    uint32_t bb_after_digits = new_block();
    emit_br_cond(is_zero, bb_zero, bb_loop_hdr, source_line);

    // bb_zero: tmp[0]='0', di=1.
    current_block_ = bb_zero;
    {
        store_byte(s_tmp, v_z48);
        store_i64(s_di, v_one_helper(source_line));
    }
    emit_br(bb_after_digits, source_line);

    // bb_loop_hdr: while (mag != 0) { tmp[di++] = mag%10+'0'; mag/=10; }
    current_block_ = bb_loop_hdr;
    {
        ir::IrValueId v_mag = load_i64(s_mag);
        ir::IrValueId cont = cmp(ir::IrOp::CMP_NE, v_mag, v_zero);
        uint32_t bb_body = new_block();
        emit_br_cond(cont, bb_body, bb_after_digits, source_line);
        // bb_body.
        current_block_ = bb_body;
        {
            ir::IrValueId v_m = load_i64(s_mag);
            // DIV/MOD: el signo lo determina el tipo IR del resultado.
            // Para signed ya trabajamos con magnitud positiva (cabe en
            // i64 salvo INT64_MIN); usamos I64.  Para unsigned usamos U64
            // para cubrir todo el rango u64 (valores con bit 63 alto).
            const ir::IrType dm_ty =
                is_signed ? ir::IrType::I64 : ir::IrType::U64;
            ir::IrValueId v_rem = fn_->new_value(dm_ty);
            {
                ir::IrInstr in{};
                in.op = ir::IrOp::MOD;
                in.type = dm_ty;
                in.dst = v_rem;
                in.operands = {v_m, v_ten};
                in.source_line = source_line;
                emit(current_block_, std::move(in));
            }
            ir::IrValueId v_digit = bin(ir::IrOp::ADD, v_rem, v_z48);
            ir::IrValueId v_di = load_i64(s_di);
            ir::IrValueId v_tmp_at = emit_ptr_add(s_tmp, v_di, source_line);
            store_byte(v_tmp_at, v_digit);
            ir::IrValueId v_di1 =
                bin(ir::IrOp::ADD, v_di, v_one_helper(source_line));
            store_i64(s_di, v_di1);
            ir::IrValueId v_div = fn_->new_value(dm_ty);
            {
                ir::IrInstr in{};
                in.op = ir::IrOp::DIV;
                in.type = dm_ty;
                in.dst = v_div;
                in.operands = {v_m, v_ten};
                in.source_line = source_line;
                emit(current_block_, std::move(in));
            }
            store_i64(s_mag, v_div);
        }
        emit_br(bb_loop_hdr, source_line);
    }

    // bb_after_digits: invertir tmp[0..di) -> v_buf[pos..pos+di).
    current_block_ = bb_after_digits;
    {
        // out_pos ya tiene 0 (positivo) o 1 (signo) escrito; los digitos
        // en tmp estan en orden inverso (menos significativo primero).
        // Copiar tmp[di-1], tmp[di-2], ..., tmp[0] a v_buf[pos], pos+1, ...
        // Usamos un indice src que decrece desde di-1 hasta 0.
        ir::IrValueId v_di_final = load_i64(s_di);
        // src = di - 1.
        ir::IrValueId s_src = new_slot(8);
        ir::IrValueId v_src0 =
            bin(ir::IrOp::SUB, v_di_final, v_one_helper(source_line));
        store_i64(s_src, v_src0);
        uint32_t bb_inv_hdr = new_block();
        emit_br(bb_inv_hdr, source_line);
        // bb_inv_hdr: while (src >= 0) { v_buf[pos++] = tmp[src]; src--; }
        current_block_ = bb_inv_hdr;
        {
            ir::IrValueId v_src = load_i64(s_src);
            ir::IrValueId cont = cmp(ir::IrOp::CMP_GE, v_src, v_zero); // signed
            uint32_t bb_inv_body = new_block();
            uint32_t bb_done = new_block();
            emit_br_cond(cont, bb_inv_body, bb_done, source_line);
            // body.
            current_block_ = bb_inv_body;
            {
                ir::IrValueId v_src_b = load_i64(s_src);
                ir::IrValueId v_tmp_at =
                    emit_ptr_add(s_tmp, v_src_b, source_line);
                ir::IrValueId v_d = emit_load_byte(v_tmp_at, source_line);
                ir::IrValueId v_pos = load_i64(s_pos);
                ir::IrValueId v_dst_at =
                    emit_ptr_add(v_buf, v_pos, source_line);
                store_byte(v_dst_at, v_d);
                ir::IrValueId v_pos1 =
                    bin(ir::IrOp::ADD, v_pos, v_one_helper(source_line));
                store_i64(s_pos, v_pos1);
                ir::IrValueId v_src1 =
                    bin(ir::IrOp::SUB, v_src_b, v_one_helper(source_line));
                store_i64(s_src, v_src1);
            }
            emit_br(bb_inv_hdr, source_line);
            current_block_ = bb_done;
        }
    }

    // len final = out_pos.
    return load_i64(s_pos);
}

std::string Lowering::ensure_itoa_helper(bool is_signed) {
    // Vesta Embed Inc 2: emite (una vez por modulo + signedness) el helper
    // itoa como funcion IR independiente.  Firma:
    //   i64 __vx_itoa_{s|u}(u8* buf, i64 val)
    // El cuerpo reutiliza emit_native_itoa_to_buf, que construye los loops
    // de extraccion/inversion sobre fn_/current_block_.  Al vivir en una
    // funcion APARTE con varios bloques:
    //   (a) el const-fold del optimizer NO foldea el itoa mid-expression
    //       (el bug de length erronea con argumento constante);
    //   (b) el inliner NO lo re-inlinea (is_inlineable exige 1 bloque).
    const int idx = is_signed ? 1 : 0;
    const std::string name = is_signed ? "__vx_itoa_s" : "__vx_itoa_u";
    if (itoa_helper_emitted_[idx]) return name;
    itoa_helper_emitted_[idx] = true;

    // Guardar el contexto del lowering en curso.
    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    // Construir el helper.  Params: buf (host_ptr), val (i64).
    ir::IrFunction hf;
    hf.name = name;
    hf.ret_type = ir::IrType::I64;
    const ir::IrValueId p_buf = hf.new_value(ir::IrType::PTR, "%buf");
    hf.values[p_buf].is_param = true;
    hf.values[p_buf].is_host_ptr = true;
    hf.params.push_back(p_buf);
    const ir::IrValueId p_val = hf.new_value(ir::IrType::I64, "%val");
    hf.values[p_val].is_param = true;
    hf.params.push_back(p_val);
    const ir::IrBlockId e = hf.new_block("entry");

    fn_ = &hf;
    current_block_ = e;

    // El itoa escribe en buf y devuelve la longitud.
    ir::IrValueId v_len =
        emit_native_itoa_to_buf(p_buf, p_val, is_signed, /*source_line=*/0);

    // ret len.
    {
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::I64;
        rt.dst = ir::IR_NO_VALUE;
        rt.operands = {v_len};
        rt.source_line = 0;
        emit(current_block_, std::move(rt));
    }

    // Restaurar el contexto del padre antes de mover el helper al modulo.
    out_mod_->add_function(std::move(hf));
    return name;
}

} // namespace vx
