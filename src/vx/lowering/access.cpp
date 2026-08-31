/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/access.cpp
 * @brief Bajada de las expresiones que NOMBRAN algo: una variable, un elemento
 *        de un array, el campo de una estructura.
 *
 * Separadas de las que calculan porque su trabajo es otro: no producen un valor
 * a partir de otros, resuelven DONDE esta un valor.  Y esa respuesta no es una
 * sola: segun quien pregunte hace falta la direccion -- para escribir en ella,
 * para prestarla, para tomar su direccion -- o el contenido, y buena parte del
 * fichero es decidir cual de las dos se debe entregar.
 */
#include "vx/lowering.h"
#include "vx/ansi_names.h"   // los nombres de color que el lenguaje conoce
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {
ir::IrValueId Lowering::lower_index_addr(ast::IndexExpr *e) {
    // Calcula base + index * sizeof(*base) y devuelve el puntero al
    // elemento.  Si sizeof == 1 omitimos la multiplicacion para
    // mantener el .vel mas claro en el caso comun de char/i8.
    if (!e->base || !e->index) {
        error_at(e->loc, "lowering: subscript con base o indice nulo");
        return ir::IR_NO_VALUE;
    }
    // Overlay F3b: `v.arr[i]` (campo array de un overlay).  Direccion del
    // elemento = base_overlay + pos + index*stride (escala por STRIDE, no por
    // sizeof).  pos/stride pueden referenciar campos hermanos.
    if (e->is_overlay_array &&
        e->base->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->base.get());
        const ir::IrValueId ov_base = lower_expr(fa->base.get());
        if (ov_base == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        const Type ovt = fa->base->result_type;
        const auto &lays = tc_.struct_layouts();
        auto it = lays.find(ovt.struct_name);
        if (it == lays.end()) {
            error_at(e->loc, "lowering: overlay array sin layout");
            return ir::IR_NO_VALUE;
        }
        const StructLayout &lay = it->second;
        const StructFieldInfo *afi = find_field(lay, fa->field_name);
        if (!afi || (!afi->array_stride && !afi->element_block)) {
            error_at(e->loc, "lowering: campo array de overlay no encontrado");
            return ir::IR_NO_VALUE;
        }
        // @element: la direccion del elemento la da un resolver POR-ELEMENTO
        // `__ovl_element_<S>_<f>(self, index, [root])` (stride variable / TLV).
        // Devuelve directamente la direccion del elemento `index`.
        if (afi->element_block) {
            const std::string rname =
                generate_overlay_resolver(lay, *afi, /*is_element=*/true);
            ir::IrValueId idx_v = lower_expr(e->index.get());
            if (idx_v == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            idx_v = cast_if_needed(idx_v, fn_->values[idx_v].type,
                                   ir::IrType::I64, e->loc.line);
            ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
            fn_->values[addr].is_host_ptr = fn_->values[ov_base].is_host_ptr;
            ir::IrInstr ins{};
            ins.op = ir::IrOp::CALL;
            ins.func_name = rname;
            ins.type = ir::IrType::PTR;
            ins.dst = addr;
            ins.operands = {ov_base, idx_v};
            if (afi->resolver_uses_parent) {
                const ir::IrValueId root_v = lower_overlay_root(e->base.get());
                if (root_v != ir::IR_NO_VALUE) ins.operands.push_back(root_v);
            }
            ins.is_call_site = true;
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
            return addr;
        }
        // Ligar `base` + hermanos para las exprs de pos/stride.  Helper: LOAD
        // en `addr` con el ancho del hermano y bind por nombre.
        push_scope();
        bind("base", ov_base);
        auto bind_sib_at = [&](const StructFieldInfo &sib, ir::IrValueId addr) {
            const ir::IrType stt = ir_type_from_primitive(sib.type.kind);
            ir::IrValueId sv = emit_load_typed(addr, stt, e->loc.line);
            bind(sib.name, sv);
        };
        auto add_off = [&](ir::IrValueId off_v) -> ir::IrValueId {
            ir::IrValueId a = fn_->new_value(ir::IrType::PTR);
            fn_->values[a].is_host_ptr = fn_->values[ov_base].is_host_ptr;
            ir::IrInstr ins{};
            ins.op = ir::IrOp::ADD;
            ins.type = ir::IrType::PTR;
            ins.dst = a;
            ins.operands = {ov_base, off_v};
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
            return a;
        };
        // Pass 1: hermanos de offset CONSTANTE.
        for (const auto &sib : lay.fields) {
            if (sib.offset_expr || sib.offset_block || sib.array_stride)
                continue;
            ir::IrValueId saddr = ov_base;
            if (sib.offset != 0)
                saddr = add_off(emit_const(ir::IrType::I64,
                                           (uint64_t)sib.offset, e->loc.line));
            bind_sib_at(sib, saddr);
        }
        // Pass 2: hermanos de offset DINAMICO (@offset(expr)) REFERENCIADOS por
        // la pos/stride del array (transitivamente).  Solo los usados: bindear
        // los no-usados es innecesario y ademas corrompe (un LOAD u64 de un
        // hermano dinamico no referenciado clobbereaba la direccion del array).
        // Recolector recursivo de nombres de IdentExpr en una expr.
        std::function<void(const ast::Expr *, std::set<std::string> &)>
            collect_idents = [&](const ast::Expr *ex,
                                 std::set<std::string> &out) {
                if (!ex) return;
                switch (ex->kind) {
                case ast::NodeKind::IdentExpr:
                    out.insert(static_cast<const ast::IdentExpr *>(ex)->name);
                    break;
                case ast::NodeKind::BinaryExpr: {
                    auto *b = static_cast<const ast::BinaryExpr *>(ex);
                    collect_idents(b->lhs.get(), out);
                    collect_idents(b->rhs.get(), out);
                    break;
                }
                case ast::NodeKind::UnaryExpr:
                    collect_idents(
                        static_cast<const ast::UnaryExpr *>(ex)->operand.get(),
                        out);
                    break;
                case ast::NodeKind::CastExpr:
                    collect_idents(
                        static_cast<const ast::CastExpr *>(ex)->operand.get(),
                        out);
                    break;
                default: break;
                }
            };
        std::set<std::string> referenced;
        collect_idents(afi->offset_expr, referenced);
        collect_idents(afi->array_stride, referenced);
        // Fixpoint: un hermano dinamico referenciado puede referenciar otros.
        for (bool changed = true; changed;) {
            changed = false;
            for (const auto &sib : lay.fields) {
                if (!sib.offset_expr || sib.array_stride) continue;
                if (!referenced.count(sib.name)) continue;
                size_t before = referenced.size();
                collect_idents(sib.offset_expr, referenced);
                if (referenced.size() != before) changed = true;
            }
        }
        for (const auto &sib : lay.fields) {
            if (!sib.offset_expr || sib.array_stride) continue;
            if (!referenced.count(sib.name)) continue; // solo los usados
            ir::IrValueId off_v = lower_expr(sib.offset_expr);
            if (off_v == ir::IR_NO_VALUE) continue;
            bind_sib_at(sib, add_off(off_v));
        }
        // Base de la tabla.  Dos formas:
        //  (a) `@offset { block }`: un RESOLVER devuelve la DIRECCION ABSOLUTA
        //  de
        //      la tabla (p.ej. traducir un RVA).  table_base = resolver(self).
        //  (b) `@offset(pos)`/const: table_base = ov_base + pos.
        ir::IrValueId stride_v = lower_expr(afi->array_stride);
        ir::IrValueId table_base = ir::IR_NO_VALUE;
        bool base_absolute = false;
        if (afi->offset_block) {
            base_absolute = true;
        } else {
            table_base = afi->offset_expr
                             ? lower_expr(afi->offset_expr)
                             : emit_const(ir::IrType::I64,
                                          (uint64_t)afi->offset, e->loc.line);
        }
        pop_scope();
        if (stride_v == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        if (base_absolute) {
            // F4/pieza2: la direccion base la da el resolver de bloque.  Se
            // enhebra `root` si el resolver usa parent<T>() (F4).
            const std::string rname = generate_overlay_resolver(lay, *afi);
            table_base = fn_->new_value(ir::IrType::PTR);
            fn_->values[table_base].is_host_ptr =
                fn_->values[ov_base].is_host_ptr;
            ir::IrInstr ins{};
            ins.op = ir::IrOp::CALL;
            ins.func_name = rname;
            ins.type = ir::IrType::PTR;
            ins.dst = table_base;
            ins.operands = {ov_base};
            if (afi->resolver_uses_parent) {
                const ir::IrValueId root_v = lower_overlay_root(e->base.get());
                if (root_v != ir::IR_NO_VALUE) ins.operands.push_back(root_v);
            }
            ins.is_call_site = true;
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
        } else if (table_base == ir::IR_NO_VALUE) {
            return ir::IR_NO_VALUE;
        }
        ir::IrValueId i_v = lower_expr(e->index.get());
        if (i_v == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        i_v = cast_if_needed(i_v, fn_->values[i_v].type, ir::IrType::I64,
                             e->loc.line);
        // scaled = i * stride
        ir::IrValueId scaled = emit_ir_binop(ir::IrOp::MUL, i_v, stride_v,
                                             ir::IrType::I64, e->loc.line);
        // addr = (base_absolute ? table_base : ov_base + pos) + scaled
        ir::IrValueId t1;
        if (base_absolute) {
            t1 = table_base; // ya es una direccion absoluta
        } else {
            t1 = emit_ptr_add(ov_base, table_base, e->loc.line);
        }
        /* Hereda de `t1`, que es su base, y no de `ov_base` como hacia antes.
         * En el caso normal da lo mismo -- `t1` ya heredo de `ov_base` --, pero
         * cuando la base es ABSOLUTA `t1` es `table_base` y `ov_base` ya no
         * tiene nada que ver con esta direccion. */
        return emit_ptr_add(t1, scaled, e->loc.line);
    }
    const Type bt = e->base->result_type;
    // unique/shared/borrow permiten indexar sin ptr_of.  OJO: el valor SSA de
    // un unique<T>/shared<T> es la DIRECCION DE SU RANURA, no el puntero de
    // datos -> mas abajo se extrae el recurso con un LOAD (+16 para shared,
    // que ahi lo que hay es el bloque de cuentas).  Un borrow SI es ya el
    // puntero de datos.
    const bool is_ptr_like =
        (bt.kind == PrimitiveKind::PTR || bt.kind == PrimitiveKind::ARRAY ||
         bt.kind == PrimitiveKind::UNIQUE_PTR ||
         bt.kind == PrimitiveKind::SHARED_PTR ||
         bt.kind == PrimitiveKind::BORROW ||
         bt.kind == PrimitiveKind::BORROW_MUT) &&
        static_cast<bool>(bt.pointee);
    if (!is_ptr_like) {
        error_at(e->loc, "lowering: '[]' sobre tipo no-PTR ni array");
        return ir::IR_NO_VALUE;
    }
    const size_t esz = size_of_type(*bt.pointee);
    if (esz == 0) {
        error_at(e->loc, "lowering: sizeof del tipo apuntado es 0 (void* u "
                         "struct desconocido)");
        return ir::IR_NO_VALUE;
    }
    const ir::IrValueId base_v = lower_expr(e->base.get());
    ir::IrValueId idx_v = lower_expr(e->index.get());
    if (base_v == ir::IR_NO_VALUE || idx_v == ir::IR_NO_VALUE)
        return ir::IR_NO_VALUE;
    // Promover index a I64 para sumarlo al puntero (que el emisor
    // trata como i64 en aritmetica).
    idx_v = cast_if_needed(idx_v, fn_->values[idx_v].type, ir::IrType::I64,
                           e->loc.line);
    // Escalar por sizeof(pointee) si != 1.
    ir::IrValueId offset = idx_v;
    if (esz != 1) {
        const ir::IrValueId sz_v =
            emit_const(ir::IrType::I64, (uint64_t)esz, e->loc.line);
        const ir::IrValueId scaled = emit_ir_binop(
            ir::IrOp::MUL, idx_v, sz_v, ir::IrType::I64, e->loc.line);
        offset = scaled;
    }
    // unique<T>/shared<T>: el valor SSA de `base` es la DIRECCION del slot
    // Tier 1 [data_ptr][deleter] (host), NO el puntero de datos.  Antes de
    // indexar hay que extraer el puntero gestionado: `LOAD [slot+0]` (unique)
    // o `LOAD [slot+0] + 16` (shared, payload tras el control block).  Misma
    // logica que ptr_of().  Los borrows YA son el puntero de datos -> sin
    // extraccion.
    ir::IrValueId base_eff = base_v;
    if (bt.kind == PrimitiveKind::UNIQUE_PTR ||
        bt.kind == PrimitiveKind::SHARED_PTR) {
        const ir::IrValueId v_data = emit_load_host_ptr(base_v, e->loc.line);
        base_eff = v_data;
        if (bt.kind == PrimitiveKind::SHARED_PTR) {
            const ir::IrValueId v16 =
                emit_const(ir::IrType::I64, 16, e->loc.line);
            base_eff = emit_ptr_add(v_data, v16, e->loc.line);
        }
    }
    const ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
    // Propagar is_host_ptr: p[i] vive en el mismo espacio que el puntero
    // gestionado (host para unique/shared; hereda de base para PTR/ARRAY).
    fn_->values[addr].is_host_ptr = fn_->values[base_eff].is_host_ptr;
    ir::IrInstr add{};
    add.op = ir::IrOp::ADD;
    add.type = ir::IrType::PTR;
    add.dst = addr;
    add.operands = {base_eff, offset};
    add.source_line = e->loc.line;
    emit(current_block_, std::move(add));
    return addr;
}

ir::IrValueId Lowering::lower_index(ast::IndexExpr *e) {
    // String Inc 3: `s[i]` (char) y `s[a..b]` / `s[a..=b]` (slice copia
    // owned) sobre el value-string nativo.  Solo en native_poo_; en
    // Full/JIT el string es GC-managed y este path no se implementa aun.
    if (e->base && e->base->result_type.kind == PrimitiveKind::STRING) {
        if (!native_poo_) {
            // VM/JIT/interp: el string es un StringObject GC-managed.  `s[i]`
            // (char) = el BYTE i-esimo del buffer: strraw (host_ptr a data) +
            // LOAD u8 en [data + i].  Mismo patron que el builtin `ord`.  Para
            // ASCII / UTF-8 de 1 byte el byte coincide con el codepoint.  El
            // slice `s[a..b]` sigue solo en AOT (requiere copiar un substring).
            if (e->is_range) {
                error_at(
                    e->loc,
                    "slice de string s[a..b] solo soportado en compilacion "
                    "nativa (AOT) por ahora; usa substr(s, a, len)");
                return ir::IR_NO_VALUE;
            }
            if (!e->index) {
                error_at(e->loc, "indexado de string sin indice");
                return ir::IR_NO_VALUE;
            }
            const ir::IrValueId v_src = lower_expr(e->base.get());
            if (v_src == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            ir::IrValueId v_idx = lower_expr(e->index.get());
            if (v_idx == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            v_idx = cast_if_needed(v_idx, fn_->values[v_idx].type,
                                   ir::IrType::I64, e->loc.line);
            // host_ptr al buffer de datos.
            const ir::IrValueId v_raw = emit_strraw(v_src, e->loc.line);
            // addr = raw + idx (hereda naturaleza host de strraw).
            const ir::IrValueId v_at = emit_ptr_add(v_raw, v_idx, e->loc.line);
            // LOAD u8 (host) -> byte, zero-extendido al ancho del char.
            const ir::IrType rt =
                (e->result_type.kind == PrimitiveKind::COUNT)
                    ? ir::IrType::I64
                    : ir_type_from_primitive(e->result_type.kind);
            return emit_load_byte(v_at, e->loc.line, rt);
        }
        const ir::IrValueId v_src = lower_expr(e->base.get());
        if (v_src == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        if (e->is_range) {
            // `s[a..b]`: lo = index, hi = range_hi.
            if (!e->index || !e->range_hi) {
                error_at(e->loc, "slice de string con limite nulo");
                return ir::IR_NO_VALUE;
            }
            ir::IrValueId v_lo = lower_expr(e->index.get());
            ir::IrValueId v_hi = lower_expr(e->range_hi.get());
            if (v_lo == ir::IR_NO_VALUE || v_hi == ir::IR_NO_VALUE)
                return ir::IR_NO_VALUE;
            // Promover ambos limites a I64.
            v_lo = cast_if_needed(v_lo, fn_->values[v_lo].type, ir::IrType::I64,
                                  e->loc.line);
            v_hi = cast_if_needed(v_hi, fn_->values[v_hi].type, ir::IrType::I64,
                                  e->loc.line);
            return build_native_string_slice(v_src, v_lo, v_hi,
                                             e->range_inclusive, e->loc.line);
        }
        // `s[i]`: el char en la posicion i.
        if (!e->index) {
            error_at(e->loc, "indexado de string sin indice");
            return ir::IR_NO_VALUE;
        }
        ir::IrValueId v_idx = lower_expr(e->index.get());
        if (v_idx == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        v_idx = cast_if_needed(v_idx, fn_->values[v_idx].type, ir::IrType::I64,
                               e->loc.line);
        return build_native_string_index_char(v_src, v_idx, e->loc.line);
    }

    // Operator overloading C-2: `base[i]` (LECTURA) -> base.__index__(i)
    // cuando el type checker marco @c e->overload_method.  El receptor
    // puede ser CLASS (CALLVIRT) o STRUCT (CALL directo).  Construimos un
    // CallExpr sintetico `base.__index__(index)` y delegamos en la
    // maquinaria de metodos.  Robamos los hijos @c base/@c index y los
    // restauramos despues para no danar el AST.
    if (!e->overload_method.empty() && e->base && e->index) {
        const bool recv_is_struct =
            (e->base->result_type.kind == PrimitiveKind::STRUCT);
        ast::CallExpr synth;
        synth.loc = e->loc;
        auto fa = std::make_unique<ast::FieldAccessExpr>();
        fa->loc = e->loc;
        fa->field_name = e->overload_method;
        fa->base = std::move(e->base); // receptor (CLASS o STRUCT)
        synth.callee = std::move(fa);
        synth.args.push_back(std::move(e->index)); // unico argumento (indice)
        ir::IrValueId v_call = recv_is_struct ? lower_struct_method_call(&synth)
                                              : lower_class_method_call(&synth);
        // Restaurar los hijos al IndexExpr original.
        auto *fa_back = static_cast<ast::FieldAccessExpr *>(synth.callee.get());
        e->base = std::move(fa_back->base);
        e->index = std::move(synth.args[0]);
        return v_call;
    }

    const ir::IrValueId addr = lower_index_addr(e);
    if (addr == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    // Bug fix 2026-05-23: para arrays multi-dim `m[i]` donde m es
    // `T[N][M]`, el "valor" de la sub-array NO es un puntero cargado
    // desde la memoria del array, sino la DIRECCION BASE de la fila.
    // Sin esto, `lower_index(m[i])` emitia LOAD ptr [m+i*sizeof(row)]
    // que leia bytes del primer elemento como si fueran un host_ptr ->
    // aliasing entre filas distintas, valores incorrectos.
    // Array de HANDLES overlay (`Foo[N] hs;` / `Foo* hs`): el elemento GUARDA
    // un puntero de 8 bytes -> su valor se obtiene CARGANDO ese puntero (cae al
    // LOAD de abajo), no devolviendo la direccion del slot.  Sin esto, `hs[i]`
    // daba `&hs[i]` -> todos los elementos aliaseaban el propio array.
    //
    // NO confundir con `v.arr[i]` (@c is_overlay_array = campo array DENTRO de
    // una vista, `Sec secs[n] @offset(p) stride(s)`): ahi el elemento vive
    // INLINE en la memoria ajena, asi que su direccion (la que ya calculo
    // @c lower_index_addr escalando por STRIDE) ES el valor de la vista.
    if ((e->result_type.kind == PrimitiveKind::ARRAY ||
         e->result_type.kind == PrimitiveKind::STRUCT) &&
        (e->is_overlay_array || !type_is_overlay(e->result_type))) {
        // Resultado es un sub-array o struct value-type; addr ya es la
        // direccion correcta del elemento.  Sin esto, `arr[i].field` con
        // `arr: Struct[N]` cargaba el primer qword del struct como un
        // ptr y luego sumaba el offset -> aliasing entre elementos.
        return addr;
    }
    const ir::IrType ft = ir_type_from_primitive(e->result_type.kind);
    const ir::IrValueId dst = fn_->new_value(ft);
    // El puntero cargado de un elemento overlay apunta a memoria HOST ajena:
    // marcarlo para que los accesos `hs[i].campo` emitan movh/loadzh (host) y
    // no mov/loadz (memoria VM).
    if (type_is_overlay(e->result_type)) fn_->values[dst].is_host_ptr = true;
    // Bug host-vs-VM (2026-07-15): mismo criterio que el campo de struct/clase
    // en @c lower_field_access -- un elemento de tipo `T*` (puntero HOST crudo,
    // no `VirtualPtr<T>`) guarda por convencion una direccion host, asi que su
    // deref posterior debe emitir movh/loadzh.  Sin esto, `hs[i][0]` sobre un
    // `i64*[N]` emitia `mov` (VM) sobre una direccion host y leia basura,
    // mientras que el MISMO puntero guardado en un campo de struct si usaba
    // movh -> las dos rutas discrepaban.  `VirtualPtr<T>` (is_virtual) queda
    // fuera: esa SI es una direccion de la memoria VM.
    if (e->result_type.kind == PrimitiveKind::PTR &&
        !e->result_type.is_virtual) {
        fn_->values[dst].is_host_ptr = true;
    }
    ir::IrInstr ld{};
    ld.op = ir::IrOp::LOAD;
    ld.type = ft;
    ld.dst = dst;
    ld.operands = {addr};
    ld.source_line = e->loc.line;
    emit(current_block_, std::move(ld));
    return dst;
}

ir::IrValueId Lowering::lower_ident(ast::IdentExpr *e) {
    // Promocion de NOMBRE DESNUDO de funcion a function value.  Cuando el
    // type checker detecta `campo_fn = nombre` / `cfn x = nombre` (sin `&`),
    // marca el IdentExpr is_func_ref y le asigna un result_type FUNCTION
    // (cfn si fn_is_raw, lambda si no).  Aqui emitimos la direccion cruda
    // (LABEL_ADDR) y, si el destino es un lambda, la envolvemos en el slot
    // fat-pointer de 16 bytes {fn_addr, env=0}.  Misma logica que el cast
    // explicito `(cfn/fn) nombre` en lower_cast_expr.
    if (e->is_func_ref && e->result_type.kind == PrimitiveKind::FUNCTION) {
        const ir::IrValueId code = fn_->new_value(ir::IrType::PTR);
        {
            ir::IrInstr ins{};
            ins.op = ir::IrOp::LABEL_ADDR;
            ins.type = ir::IrType::PTR;
            ins.dst = code;
            ins.func_name = func_ref_label(e->name, e->func_ref_mangled);
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
        }
        if (e->result_type.fn_is_raw) return code; // cfn: 8 bytes crudos
        // Lambda: fat-pointer de 16 bytes {fn_addr, env=0}.
        const ir::IrValueId fv = stack_alloc_buf(16, e->loc.line, native_poo_);
        if (native_poo_) fn_->values[fv].is_host_ptr = true;
        {
            // [fv+0] = fn_addr
            emit_store_typed(fv, code, ir::IrType::I64, e->loc.line);
        }
        {
            // [fv+8] = 0 (env vacio)
            const ir::IrValueId fv8 = fn_->new_value(ir::IrType::PTR);
            const ir::IrValueId o8 =
                emit_const(ir::IrType::I64, 8, e->loc.line);
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = fv8;
            ad.operands = {fv, o8};
            ad.source_line = e->loc.line;
            emit(current_block_, std::move(ad));
            if (native_poo_) fn_->values[fv8].is_host_ptr = true;
            const ir::IrValueId z = emit_const(ir::IrType::I64, 0, e->loc.line);
            emit_store_typed(fv8, z, ir::IrType::I64, e->loc.line);
        }
        return fv;
    }

    // `static T x` local: la variable vive en gdata (slot mangleado por
    // funcion).  Cada lectura emite STR_LIT_ADDR(slot) + LOAD (o solo la
    // direccion si es agregado).  Va ANTES del scope: un `static` sombrea
    // cualquier binding local del mismo nombre por diseno.
    {
        auto sit = static_local_slots_.find(e->name);
        if (sit != static_local_slots_.end()) {
            const int ln = e->loc.line;
            ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
            {
                ir::IrInstr is{};
                is.op = ir::IrOp::STR_LIT_ADDR;
                is.type = ir::IrType::PTR;
                is.dst = addr;
                is.imm = sit->second.slot;
                is.source_line = ln;
                emit(current_block_, std::move(is));
                fn_->values[addr].is_host_ptr = true;
            }
            if (sit->second.aggregate) return addr; // el valor ES la direccion
            ir::IrValueId v = emit_load_typed(addr, sit->second.ld_type, ln);
            return v;
        }
    }

    /* si estamos dentro de un @Macro body Y el name
     * resuelve a un comptime global int, emit LOAD desde el slot
     * @c static_data correspondiente.  Asi el macro ve el VALOR
     * ACTUAL (mutado por invocaciones previas), no el inicial. */
    if (current_fn_is_macro_) {
        auto cit = tc_.comptime_const_values().find(e->name);
        if (cit != tc_.comptime_const_values().end() && !cit->second.is_str) {
            /* Pero PRIORIDAD a comptime_const_locals_ del lowering
             * (sobreescrito por comptime for body): si la var esta
             * en el stack dinamico, hicimos override -- usar ese
             * valor inline en lugar del slot global. */
            bool overridden = false;
            for (auto it = lowering_comptime_scopes_.rbegin();
                 it != lowering_comptime_scopes_.rend(); ++it) {
                if (it->find(e->name) != it->end()) {
                    overridden = true;
                    break;
                }
            }
            if (!overridden) {
                const uint64_t slot_idx =
                    get_or_create_comptime_global_slot(e->name);
                if (slot_idx != UINT64_MAX) {
                    const int ln = e->loc.line;
                    ir::IrValueId v_addr = emit_str_lit_addr(slot_idx, ln);
                    ir::IrValueId v_val =
                        emit_load_typed(v_addr, ir::IrType::I64, ln);
                    return v_val;
                }
            }
        }
    }

    // A.39: primero consultamos el stack dinamico de comptime const
    // del lowering -- usado por `comptime for` para override del
    // index por iteracion sin re-correr el type checker.
    for (auto it = lowering_comptime_scopes_.rbegin();
         it != lowering_comptime_scopes_.rend(); ++it) {
        auto hit = it->find(e->name);
        if (hit != it->end()) {
            if (hit->second.is_str) {
                /* String comptime override (raro pero soportado). */
                std::vector<uint8_t> bytes(hit->second.str_value.begin(),
                                           hit->second.str_value.end());
                const uint64_t idx =
                    out_mod_->intern_static_data(std::move(bytes));
                ir::IrValueId v_addr = emit_str_lit_addr(idx, e->loc.line);
                ir::IrValueId v_len = emit_const(
                    ir::IrType::I64,
                    static_cast<uint64_t>(hit->second.str_value.size()),
                    e->loc.line);
                ir::IrValueId v_str =
                    emit_string_literal_repr(v_addr, v_len, -1, e->loc.line);
                return v_str;
            }
            return emit_const(hit->second.ir_t,
                              static_cast<uint64_t>(hit->second.value),
                              e->loc.line);
        }
    }

    // A.38/A.39: si el type checker ya resolvio este ident a un
    // comptime const (annotacion en el AST), inline-amos el valor
    // como CONST directo.  Cubre locales (que ya no estan en la
    // tabla del type checker) y globales.  Strings comptime se
    // materializan via STR_LIT_ADDR + STRMAKE.
    if (e->comptime_const_resolved) {
        if (e->comptime_const_is_str) {
            /* Construir StringObject inline desde los bytes del
             * comptime string -- mismo patron que typename<T>(). */
            std::vector<uint8_t> bytes(e->comptime_const_str.begin(),
                                       e->comptime_const_str.end());
            const uint64_t idx = out_mod_->intern_static_data(std::move(bytes));
            // v4: propagar atributos (@align/@hot/@cold/@section)
            // al static_data_meta del idx recien interno.  Lookup
            // en comptime_const_values_ por nombre para extraer
            // los atributos guardados durante el type check.
            {
                const auto &ccv = tc_.comptime_const_values();
                auto cit = ccv.find(e->name);
                if (cit != ccv.end() && idx < out_mod_->static_data.size()) {
                    auto &m = out_mod_->static_data.meta_at(idx);
                    if (cit->second.attr_align > 0) {
                        m.alignment = cit->second.attr_align;
                    }
                    m.flags |= ir::IrModule::SD_FLAG_IMMUTABLE;
                    if (cit->second.attr_hot)
                        m.flags |= ir::IrModule::SD_FLAG_HOT;
                    if (cit->second.attr_cold)
                        m.flags |= ir::IrModule::SD_FLAG_COLD;
                    if (!cit->second.attr_section.empty())
                        m.section_name = cit->second.attr_section;
                }
            }
            ir::IrValueId v_addr = emit_str_lit_addr(idx, e->loc.line);
            ir::IrValueId v_len =
                emit_const(ir::IrType::I64,
                           static_cast<uint64_t>(e->comptime_const_str.size()),
                           e->loc.line);
            ir::IrValueId v_str =
                emit_string_literal_repr(v_addr, v_len, -1, e->loc.line);
            return v_str;
        }
        ir::IrType t = ir_type_from_primitive(e->result_type.kind);
        return emit_const(t, static_cast<uint64_t>(e->comptime_const_int),
                          e->loc.line);
    }

    //  M.L7: globals const IMPORTADAS de otro modulo via .vxi.
    // El TypeChecker las registro con su valor literal embedded en
    // @c imported_global_consts_; emitimos CONST inline igual que
    // las locales (cero overhead).
    // v4: tambien soporta strings importados via STRMAKE.
    {
        auto it = tc_.imported_global_consts().find(e->name);
        if (it != tc_.imported_global_consts().end()) {
            if (it->second.is_str) {
                // Materializar StringObject inline.
                const std::string &sv = it->second.str_value;
                std::vector<uint8_t> pbytes(sv.begin(), sv.end());
                const uint64_t p_idx =
                    out_mod_->intern_static_data(std::move(pbytes));
                ir::IrValueId v_addr = emit_str_lit_addr(p_idx, e->loc.line);
                ir::IrValueId v_len =
                    emit_const(ir::IrType::I64,
                               static_cast<uint64_t>(sv.size()), e->loc.line);
                return emit_string_literal_repr(v_addr, v_len, -1, e->loc.line);
            }
            ir::IrType t = ir_type_from_primitive(it->second.type.kind);
            return emit_const(t, it->second.value, e->loc.line);
        }
    }

    // L2.2: globales runtime no-const con storage en static_data.
    // Antes del const-globals scan para preferir el storage real cuando
    // existe.  Cero overhead vs constantes (un LOAD adicional, ~2 ns).
    {
        // Un global IMPORTADO de otro modulo no tiene decl en este AST: se le
        // registra aqui su slot compartido para que el resto de la ruta lo
        // trate igual que a uno propio.
        (void)ensure_imported_global_slot(e->name);
        auto sit = runtime_global_slots_.find(e->name);
        if (sit != runtime_global_slots_.end()) {
            // Detectar el tipo declarado del global para emitir LOAD
            // con el ancho correcto.  Default i64.
            ir::IrType t = ir::IrType::I64;
            bool is_string = false;
            bool is_array = false;
            bool found_decl = false;
            for (auto &decl : mod_.decls) {
                if (!decl || decl->kind != ast::NodeKind::GlobalVarDecl)
                    continue;
                auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
                if (gv->name != e->name) continue;
                found_decl = true;
                if (gv->type &&
                    gv->type->kind == ast::NodeKind::PrimitiveTypeNode) {
                    auto *pt =
                        static_cast<ast::PrimitiveTypeNode *>(gv->type.get());
                    t = ir_type_from_primitive(pt->prim);
                    is_string = (pt->prim == PrimitiveKind::STRING);
                } else if (gv->type &&
                           gv->type->kind == ast::NodeKind::ArrayTypeNode) {
                    is_array = true;
                } else if (gv->type &&
                           gv->type->kind == ast::NodeKind::NamedTypeNode) {
                    // Un STRUCT global decae a su DIRECCION, igual que un
                    // array: el valor SSA de un agregado ES su direccion.
                    // Cargar 8 bytes de el daria su primer campo.
                    const Type gt = tc_.resolve_type_node(gv->type.get());
                    if (gt.kind == PrimitiveKind::STRUCT &&
                        !gt.struct_name.empty()) {
                        auto sl = tc_.struct_layouts().find(gt.struct_name);
                        if (sl != tc_.struct_layouts().end() &&
                            !sl->second.is_overlay)
                            is_array =
                                true; // mismo trato: devolver la direccion
                    }
                }
                break;
            }
            if (!found_decl) {
                // Importado: el tipo lo da el .vxi del dep.  Sin esto el LOAD
                // caeria al default i64 y un `i32` negativo del dep se leeria
                // con los bytes altos del slot.
                const auto &igs = tc_.imported_global_storage();
                auto igt = igs.find(e->name);
                if (igt != igs.end()) {
                    const Type &gt = igt->second.type;
                    is_string = (gt.kind == PrimitiveKind::STRING);
                    is_array = (gt.kind == PrimitiveKind::ARRAY);
                    if (!is_array) t = ir_type_from_primitive(gt.kind);
                }
            }
            const uint64_t slot_idx = sit->second;
            // Array global: decae a su DIRECCION (host_ptr), no se carga
            // el contenido.  g_heap[i] indexa sobre esta direccion.
            if (is_array) {
                const int ln_a = e->loc.line;
                ir::IrValueId v_a = fn_->new_value(ir::IrType::PTR);
                // El storage de un global vive en memoria HOST en los 3 modos:
                // en AOT en `.data`, y en interp/JIT en el bloque host al que
                // el loader mapea la seccion `gdata`.  Su direccion es un `T*`
                // y el indexado usa movh.
                fn_->values[v_a].is_host_ptr = true;
                ir::IrInstr is{};
                is.op = ir::IrOp::STR_LIT_ADDR;
                is.type = ir::IrType::PTR;
                is.dst = v_a;
                is.imm = slot_idx;
                is.source_line = ln_a;
                emit(current_block_, std::move(is));
                return v_a;
            }
            const int ln = e->loc.line;
            // El slot vive en memoria host (seccion `gdata`) -> el LOAD de
            // abajo es un acceso host directo, sin traducir.
            const ir::IrValueId v_addr =
                emit_str_lit_addr(slot_idx, ln, /*host_ptr=*/true);
            // Para STRING, LOAD i64 (GcHandle); para otros, LOAD con
            // ancho declarado.
            const ir::IrType load_t = is_string ? ir::IrType::I64 : t;
            ir::IrValueId v_val = emit_load_typed(v_addr, load_t, ln);
            return v_val;
        }
    }

    // const-globals - inlining de constantes globales `const T NAME = lit;`.
    // Vesta aun no genera storage para variables globales (solo warning),
    // pero para const con inicializador literal podemos emitir un CONST
    // inline en el call site.  Cero overhead, util para nombrar codigos
    // de tecla (KEY_*), VK constants, magic numbers.
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::GlobalVarDecl) continue;
        auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
        if (gv->name != e->name) continue;
        if (!gv->is_const || !gv->init) break;
        // Tipo destino: del declarado (i32, i64, ...).  Default i64.
        ir::IrType t = ir::IrType::I64;
        if (gv->type && gv->type->kind == ast::NodeKind::PrimitiveTypeNode) {
            auto *pt = static_cast<ast::PrimitiveTypeNode *>(gv->type.get());
            t = ir_type_from_primitive(pt->prim);
        }
        // Constante entera positiva: directamente IntLitExpr.
        if (gv->init->kind == ast::NodeKind::IntLitExpr) {
            auto *lit = static_cast<ast::IntLitExpr *>(gv->init.get());
            return emit_const(t, static_cast<uint64_t>(lit->value),
                              e->loc.line);
        }
        // Constante entera negativa: UnaryExpr Neg sobre IntLitExpr.
        if (gv->init->kind == ast::NodeKind::UnaryExpr) {
            auto *u = static_cast<ast::UnaryExpr *>(gv->init.get());
            if (u->op == ast::UnOp::Neg && u->operand &&
                u->operand->kind == ast::NodeKind::IntLitExpr) {
                auto *lit = static_cast<ast::IntLitExpr *>(u->operand.get());
                int64_t v = -static_cast<int64_t>(lit->value);
                return emit_const(t, static_cast<uint64_t>(v), e->loc.line);
            }
        }
        // Bug fix 2026-05-23: const string GLOBAL = "literal"; cada uso
        // inlinea un STRMAKE del literal a StringObject (mismo patron que
        // var-decl local).  Sin esto, `const string g = "x"` daba error
        // de tipo o un global sin storage.
        // NOTA: cada uso aloca un StringObject nuevo (no se cachea).  Si
        // el codigo invoca el global N veces dentro de un loop, hay N
        // allocaciones GC.  Aceptable para constantes string usadas una
        // vez; el usuario que necesite single-alloc puede hacer
        // `const string g = ...; string cached = g;` al inicio.
        if (gv->is_const && gv->init->kind == ast::NodeKind::StringLitExpr &&
            gv->type && gv->type->kind == ast::NodeKind::PrimitiveTypeNode &&
            static_cast<ast::PrimitiveTypeNode *>(gv->type.get())->prim ==
                PrimitiveKind::STRING) {
            auto *slit = static_cast<ast::StringLitExpr *>(gv->init.get());
            return lower_string_literal_to_string_object(slit);
        }
        // Otros tipos de inicializador (FloatLit, BinaryExpr)
        // -- a implementar cuando los necesite.
        break;
    }
    // Constantes ENC_* (encoding numerico para builtins de string como
    // @c str_convert(s, ENC_UTF16)).  Cero overhead: emit const i32
    // inline en el call site -- no necesitan storage como simbolos.
    {
        static const struct {
            const char *name;
            int32_t v;
        } ENC_LU[] = {
            {"ENC_ASCII", 0}, {"ENC_ANSI", 1},  {"ENC_UTF8", 2},
            {"ENC_UTF16", 3}, {"ENC_UTF32", 4},
        };
        for (const auto &m : ENC_LU) {
            if (e->name == m.name) {
                return emit_const(ir::IrType::I32, static_cast<uint64_t>(m.v),
                                  e->loc.line);
            }
        }
    }
    // Identificadores ANSI magicos.  Si el nombre es una constante
    // predefinida (RED, GREEN, BOLD, RESET, etc.), emitir un
    // STR_LIT_ADDR a la cadena ANSI correspondiente.  Cero overhead
    // vs un string literal explicito; la deteccion es un lookup O(1)
    // en una tabla estatica.  Permite que el usuario escriba
    // @c println("Error: ${RED}..${RESET}") sin necesidad de
    // memorizar los codigos ANSI ni de declararlos como constantes.
    if (const char *ansi = ansi_sequence_for(e->name)) {
        const std::string seq = ansi;
        std::vector<uint8_t> bytes(seq.begin(), seq.end());
        const uint64_t lit_idx = out_mod_->intern_static_data(std::move(bytes));
        return emit_str_lit_addr(lit_idx, e->loc.line);
    }
    // Gap N: coercion de funcion top-level a function value.
    // Si el ident esta tipado como FUNCTION pero NO existe en
    // ningun scope local, asumimos que el type checker resolvio el
    // nombre a una funcion top-level (Symbol::Function) y patcheo
    // el result_type para forzar esta promocion.  Emitimos un slot
    // de 16 bytes en stack: fn_addr = @Absolute("code.<name>"),
    // env_addr = 0.  El callee (helper sintetico de lambda o el
    // CALLCLOSURE) ignora env_addr cuando es 0 (no toca r14).
    if (e->result_type.kind == PrimitiveKind::FUNCTION &&
        lookup(e->name) == ir::IR_NO_VALUE) {
        return emit_topfn_value(e->name, e->loc.line);
    }
    // Para variables address-taken devolvemos el valor cargado (LOAD)
    // en lugar de la direccion guardada en scope.  Para STRUCT y
    // ARRAY, en cambio, el "valor" en uso es la propia direccion (no
    // son SSA-rvalues), por lo que lookup() es lo correcto: cualquier
    // uso posterior (subscript, decay-to-pointer al pasar a funcion,
    // arr + n) opera sobre la addr base.
    if (e->result_type.kind == PrimitiveKind::STRUCT ||
        e->result_type.kind == PrimitiveKind::ARRAY ||
        e->result_type.kind == PrimitiveKind::OPTIONAL ||
        e->result_type.kind == PrimitiveKind::RESULT ||
        // Vesta Embed Inc 0: en native_poo_ el `string` es value-type
        // (struct {ptr,len,cap}); su "valor" es el PTR al slot de 24
        // bytes, igual que un struct.  El path Full (sin native_poo_)
        // mantiene `string` como handle GC (cae a read_local mas abajo).
        (native_poo_ && e->result_type.kind == PrimitiveKind::STRING)) {
        // Para STRUCT/ARRAY/OPTIONAL/RESULT la variable guarda
        // directamente la direccion del buffer (heap o stack); el
        // ident se resuelve via lookup, sin LOAD adicional.
        const ir::IrValueId v = lookup(e->name);
        if (v == ir::IR_NO_VALUE)
            error_at(e->loc, "lowering: nombre no resuelto: '" + e->name + "'");
        return v;
    }
    const ir::IrType ir_ty = ir_type_from_primitive(e->result_type.kind);
    const ir::IrValueId v = read_local(e->name, ir_ty, e->loc.line);
    if (v == ir::IR_NO_VALUE)
        error_at(e->loc, "lowering: nombre no resuelto: '" + e->name + "'");
    return v;
}

ir::IrValueId Lowering::lower_field_access(ast::FieldAccessExpr *e) {
    // NS.2: comptime const de un namespace (`mod.ANSWER`).  El type checker
    // anoto el valor (resuelto en compile-time); emitimos CONST inline igual
    // que un comptime const desnudo -- cero overhead runtime.
    if (e->comptime_const_resolved) {
        if (e->comptime_const_is_str) {
            std::vector<uint8_t> bytes(e->comptime_const_str.begin(),
                                       e->comptime_const_str.end());
            const uint64_t idx = out_mod_->intern_static_data(std::move(bytes));
            ir::IrValueId v_addr = emit_str_lit_addr(idx, e->loc.line);
            ir::IrValueId v_len =
                emit_const(ir::IrType::I64,
                           static_cast<uint64_t>(e->comptime_const_str.size()),
                           e->loc.line);
            return emit_string_literal_repr(v_addr, v_len, -1, e->loc.line);
        }
        ir::IrType t = ir_type_from_primitive(e->result_type.kind);
        return emit_const(t, static_cast<uint64_t>(e->comptime_const_int),
                          e->loc.line);
    }
    // ADTs: variante sin payload `Color.Red` (sin parens).  El
    // type checker la marco con property_kind=99.  Despachar al
    // constructor de variante con args vacio en lugar del manejo
    // generico de field-access (struct/clase) que fallaria al no
    // encontrar un campo llamado "Red" en un struct.
    // C-style: enum con VALOR (property_kind=98).  La variante ES una constante
    // del tipo base -> emitir un CONST del ancho base.  Base puede ser el
    // nombre del enum (`Op.MOV`) o un acceso cualificado (`ns.Op.MOV`, cuyo
    // result_type.struct_name es el nombre del enum).
    if (e->property_kind == 98 && e->base) {
        std::string enum_name;
        if (e->base->kind == ast::NodeKind::IdentExpr) {
            enum_name = static_cast<ast::IdentExpr *>(e->base.get())->name;
        } else if (e->base->kind == ast::NodeKind::FieldAccessExpr) {
            enum_name = e->base->result_type.struct_name;
        }
        const auto &elays = tc_.enum_layouts();
        auto it = elays.find(enum_name);
        if (it != elays.end() && it->second.is_valued) {
            const PrimitiveKind bk = it->second.backing;
            const bool backing_int =
                (bk == PrimitiveKind::I8 || bk == PrimitiveKind::I16 ||
                 bk == PrimitiveKind::I32 || bk == PrimitiveKind::I64 ||
                 bk == PrimitiveKind::U8 || bk == PrimitiveKind::U16 ||
                 bk == PrimitiveKind::U32 || bk == PrimitiveKind::U64);
            for (const auto &v : it->second.variants) {
                if (v.name == e->field_name) {
                    if (backing_int) {
                        // Entero: CONST del ancho base (soporta
                        // auto-incremento).
                        const ir::IrType t = ir_type_from_primitive(bk);
                        return emit_const(t, static_cast<uint64_t>(v.int_value),
                                          e->loc.line);
                    }
                    // String: construir un StringObject real (no el puntero
                    // crudo a los bytes que produce lower_string_lit).
                    if (bk == PrimitiveKind::STRING && v.value_ast &&
                        v.value_ast->kind == ast::NodeKind::StringLitExpr) {
                        return lower_string_literal_to_string_object(
                            const_cast<ast::StringLitExpr *>(
                                static_cast<const ast::StringLitExpr *>(
                                    v.value_ast)));
                    }
                    // Float/...: bajar la expresion AST de la variante (reusa
                    // el lowering de literales float/init-list).
                    if (v.value_ast) {
                        return lower_expr(const_cast<ast::Expr *>(v.value_ast));
                    }
                    break;
                }
            }
        }
        error_at(e->loc, "lowering: variante de enum con valor '" +
                             e->field_name + "' no resuelta");
        return ir::IR_NO_VALUE;
    }
    if (e->property_kind == 99 && e->base &&
        e->base->kind == ast::NodeKind::IdentExpr) {
        auto *base_id = static_cast<ast::IdentExpr *>(e->base.get());
        static const std::vector<std::unique_ptr<ast::Expr>> empty_args;
        return lower_enum_constructor(base_id->name, e->field_name, empty_args,
                                      e->loc);
    }
    // Cross-module variante sin payload `lib.Op.Nop`.  La base es
    // FieldAccessExpr(lib, "Op") cuyo result_type es el enum type
    // (STRUCT con struct_name = mangled enum name).
    if (e->property_kind == 99 && e->base &&
        e->base->kind == ast::NodeKind::FieldAccessExpr) {
        const Type &bt = e->base->result_type;
        if (bt.kind == PrimitiveKind::STRUCT) {
            static const std::vector<std::unique_ptr<ast::Expr>> empty_args;
            return lower_enum_constructor(bt.struct_name, e->field_name,
                                          empty_args, e->loc);
        }
    }
    // Si el receptor es CLASS, ruta especifica via GETFIELD (offset
    // relativo al payload, sin header) en lugar del esquema struct
    // (LOAD desde direccion calculada).
    if (e->base && e->base->result_type.kind == PrimitiveKind::CLASS) {
        return lower_class_field_load(e);
    }
    // Limitacion G (cerrada): @c property_kind == 3 marca acceso a
    // static field via @c ClassName.field.  El base es IdentExpr cuyo
    // nombre NO es una variable (es un nombre de clase) asi que su
    // result_type es VOID/COUNT y no entra en la rama anterior.
    // Despachamos directamente a @c lower_class_field_load que sabe
    // emitir findclass + getstatic sin tocar @c base.
    if (e->property_kind == 3) {
        return lower_class_field_load(e);
    }
    // property_kind == 8: static field de struct.  Su storage es la global
    // sintetica `<Struct>__<campo>` (creada en el parser); la LECTURA es un
    // acceso a esa global.  base->name ya viene manglado con el namespace
    // (mismo prefix que recibio la global en el pase de mangling).
    if (e->property_kind == 8 && e->base &&
        e->base->kind == ast::NodeKind::IdentExpr) {
        auto *base_id = static_cast<ast::IdentExpr *>(e->base.get());
        ast::IdentExpr gid;
        gid.loc = e->loc;
        gid.name = base_id->name + "__" + e->field_name;
        gid.result_type = e->result_type;
        return lower_ident(&gid);
    }
    // M.L7 ext: @c namespace.CONSTANT.  El type checker marca con
    // @c property_kind=4 y rellena @c ns_index para que aqui podamos
    // consultar el Sym y -- si es kind=1 (Variable/Const) con literal
    // disponible -- inlinear el valor como CONST (cero overhead vs
    // const local).
    if (e->property_kind == 4 && e->ns_index != 0xFFFFFFFFu) {
        const auto &nss = tc_.imported_namespaces();
        if (e->ns_index < nss.size()) {
            const auto &ns = nss[e->ns_index];
            auto it_sym = ns.by_name.find(e->field_name);
            if (it_sym != ns.by_name.end()) {
                const auto &sym = ns.symbols[it_sym->second];
                if (sym.kind == 1 && sym.has_const_value) {
                    ir::IrType ft = ir_type_from_primitive(e->result_type.kind);
                    return emit_const(ft,
                                      static_cast<uint64_t>(sym.const_value),
                                      e->loc.line);
                }
                // v4: comptime const string cross-module.  El blob
                // se materializo en imported_global_consts_ con
                // is_str=true.  Aqui lo emitimos como STRMAKE para
                // obtener un StringObject usable.
                if (sym.kind == 1 &&
                    sym.var_type.kind == PrimitiveKind::STRING) {
                    const auto &ics = tc_.imported_global_consts();
                    auto it_ic = ics.find(e->field_name);
                    if (it_ic != ics.end() && it_ic->second.is_str) {
                        const std::string &sv = it_ic->second.str_value;
                        std::vector<uint8_t> pbytes(sv.begin(), sv.end());
                        const uint64_t p_idx =
                            out_mod_->intern_static_data(std::move(pbytes));
                        // v4: marcar el meta como immutable + imported.
                        // El JIT puede inlinear el ptr directo (no es
                        // realocable) y el AOT lo segrega a .rodata.
                        if (p_idx < out_mod_->static_data.size()) {
                            auto &m = out_mod_->static_data.meta_at(p_idx);
                            m.flags |= ir::IrModule::SD_FLAG_IMMUTABLE;
                            m.flags |= ir::IrModule::SD_FLAG_IMPORTED;
                        }
                        ir::IrValueId v_addr =
                            emit_str_lit_addr(p_idx, e->loc.line);
                        ir::IrValueId v_len = emit_const(
                            ir::IrType::I64, static_cast<uint64_t>(sv.size()),
                            e->loc.line);
                        return emit_string_literal_repr(v_addr, v_len, -1,
                                                        e->loc.line);
                    }
                }
            }
        }
    }
    const ir::IrValueId addr = lower_field_addr(e);
    if (addr == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    // Campo de tipo AGREGADO inline (struct/array/optional/result anidado):
    // su "valor" SSA ES su direccion (pass-through), NO se carga.  Sin esto,
    // `r.a.x` (a = sub-struct inline) emitia un LOAD que deref-eaba los
    // primeros 8 bytes de `a` como un puntero -> direccion basura -> segfault
    // en AOT (host) o valor erroneo en VM.  Mismo patron que los fixes B1/B3
    // de ptr_of/read_borrow sobre agregados.
    //
    // EXCEPCION: un campo cuyo TIPO es un `@overlay struct` NO es un agregado
    // inline: guarda el HANDLE de la vista (un puntero host de 8 bytes, igual
    // que una variable/parametro/elemento de array overlay).  Su valor se
    // obtiene CARGANDO ese puntero del slot -> cae al LOAD de abajo.  Sin esto
    // el campo se interpretaba como una vista EMBEBIDA en ese offset y leerlo
    // devolvia `base+offset` (la direccion del propio slot) en vez del handle.
    // Mismo patron que el array de handles overlay en lower_index.
    if ((e->result_type.kind == PrimitiveKind::STRUCT &&
         !type_is_overlay(e->result_type)) ||
        e->result_type.kind == PrimitiveKind::ARRAY ||
        e->result_type.kind == PrimitiveKind::OPTIONAL ||
        e->result_type.kind == PrimitiveKind::RESULT ||
        /* Un campo `shared<T>` o `unique<T>` ES la ranura: guarda el bloque de
         * cuentas en uno y el recurso en el otro, y su valor COMO puntero
         * inteligente es la DIRECCION del campo -- de ahi leen `ptr_of`,
         * `use_count` y quien lo suelta --.  Se deja pasar con la anfitrionia
         * que traiga @c lower_field_addr, que es la del contenedor. */
        e->result_type.kind == PrimitiveKind::SHARED_PTR ||
        e->result_type.kind == PrimitiveKind::UNIQUE_PTR) {
        return addr;
    }

    const ir::IrType ft = ir_type_from_primitive(e->result_type.kind);
    ir::IrValueId dst = fn_->new_value(ft);
    // El handle cargado de un campo overlay apunta a memoria HOST ajena:
    // marcarlo para que los accesos `h.ch.campo` emitan movh/loadzh (host) y no
    // mov/loadz (memoria VM).  Mismo criterio que lower_index sobre arrays de
    // handles overlay.
    if (type_is_overlay(e->result_type)) fn_->values[dst].is_host_ptr = true;
    ir::IrInstr ins{};
    ins.op = ir::IrOp::LOAD;
    ins.type = ft;
    ins.dst = dst;
    ins.operands = {addr};
    ins.source_line = e->loc.line;
    emit(current_block_, std::move(ins));

    // F5: campo `@endian(expr)` -> swap CONDICIONAL segun la expr (nonzero =
    // big-endian).  Comptime -> se pliega (cero coste); runtime -> select sin
    // ramas.  Solo enteros multi-byte; el resto opera en orden nativo.
    {
        const Type bt_e = e->base ? e->base->result_type : Type{};
        if (bt_e.kind == PrimitiveKind::STRUCT) {
            auto it_e = tc_.struct_layouts().find(bt_e.struct_name);
            if (it_e != tc_.struct_layouts().end()) {
                // Los nombres de campo son unicos en un layout, asi que
                // buscarlo y luego mirar si cumple es lo mismo que recorrer
                // comprobando las dos cosas a la vez.
                const StructFieldInfo *f =
                    find_field(it_e->second, e->field_name);
                if (f && f->endian_expr && f->bit_width == 0 &&
                    (f->size == 2 || f->size == 4 || f->size == 8)) {
                    dst = emit_overlay_endian_swap(e->base.get(), it_e->second,
                                                   *f, dst, e->loc.line);
                }
            }
        }
    }

    // Propagar is_host_ptr cuando el campo es un puntero/array host.
    // Critico para casos como `(*virtual_ptr).buf` donde el struct
    // tiene field `u8* buf` -- el LOAD lee desde VM mem (porque la
    // direccion del struct es VM addr), pero el VALOR cargado ES un
    // host_ptr (resultado de malloc) y los accesos byte-level posteriores
    // necesitan emitir movh.  Sin esto, `(*vp).buf[i] = x` emite mov
    // (VM mem) en lugar de movh (host mem) -> escribe al lugar erroneo.
    if (e->result_type.kind == PrimitiveKind::PTR ||
        e->result_type.kind == PrimitiveKind::ARRAY) {
        if (!e->result_type.is_virtual) {
            fn_->values[dst].is_host_ptr = true;
        }
    }
    // Si el campo es de tipo CLASS, el LOAD devuelve un host_ptr a
    // un objeto GC.  Marcar para gc-aware save/restore alrededor de
    // CALLs subsiguientes.
    if (e->result_type.kind == PrimitiveKind::CLASS) {
        fn_->values[dst].is_host_ptr = true;
        fn_->values[dst].is_gc_object = true;
    }

    // Bit field: aplicar SHR + AND para extraer.
    // Buscamos el StructFieldInfo del campo accedido para conocer
    // bit_offset/bit_width.  Si bit_width=0, es campo normal y
    // saltamos.
    const Type bt = e->base ? e->base->result_type : Type{};
    if (bt.kind == PrimitiveKind::STRUCT) {
        const auto &layouts = tc_.struct_layouts();
        auto it_l = layouts.find(bt.struct_name);
        if (it_l != layouts.end()) {
            const StructFieldInfo *f = find_field(it_l->second, e->field_name);
            if (f && f->bit_width > 0) {
                // shifted = dst >> bit_offset; masked = shifted & mask.
                ir::IrValueId v_shifted = dst;
                if (f->bit_offset > 0) {
                    ir::IrValueId v_shamt =
                        emit_const(ft, (uint64_t)f->bit_offset, e->loc.line);
                    v_shifted = fn_->new_value(ft);
                    ir::IrInstr sh{};
                    sh.op = ir::IrOp::SHR;
                    sh.type = ft;
                    sh.dst = v_shifted;
                    sh.operands = {dst, v_shamt};
                    sh.source_line = e->loc.line;
                    emit(current_block_, std::move(sh));
                }
                // mask = (1 << bit_width) - 1.
                const uint64_t mask = (f->bit_width == 64)
                                          ? UINT64_MAX
                                          : ((uint64_t(1) << f->bit_width) - 1);
                ir::IrValueId v_mask = emit_const(ft, mask, e->loc.line);
                ir::IrValueId v_masked = fn_->new_value(ft);
                ir::IrInstr an{};
                an.op = ir::IrOp::AND;
                an.type = ft;
                an.dst = v_masked;
                an.operands = {v_shifted, v_mask};
                an.source_line = e->loc.line;
                emit(current_block_, std::move(an));
                return v_masked;
            }
        }
    }
    return dst;
}

} // namespace vx
