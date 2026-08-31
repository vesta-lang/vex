/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_introspect.cpp
 * @brief Bajada de lo que se responde MIRANDO LOS TIPOS al compilar.
 *
 * Cincuenta y un builtins que preguntan por la forma de un tipo: cuanto mide,
 * como se alinea, cuantos campos tiene y como se llama el tercero, si es una
 * clase o un struct, si uno hereda del otro.  Todos comparten algo que los
 * separa del resto del lenguaje: **su respuesta no se calcula, se sabe**.
 *
 * Y eso se ve en lo que emiten.  `sizeof<Punto>()` no baja a una llamada ni a
 * una lectura: baja a la constante 16, la misma que si el programador la
 * hubiera escrito.  `field_name<Punto>(1)` baja a la cadena "y", ya montada.
 * Recorrer los campos de un tipo -- `for_each_field` -- no monta ningun bucle:
 * el bucle lo da el compilador, y lo que llega al programa es el cuerpo
 * repetido una vez por campo.  De ahi que esta familia sea, junto con los
 * conceptos, la unica cuyo coste en ejecucion es exactamente cero.
 *
 * La contrapartida es que todo tiene que saberse AQUI.  Un tipo que no se
 * resuelve, un indice de campo que no es una constante, un nombre que no es un
 * literal: no hay a donde bajarlo, y el error se da al compilar en vez de
 * producir codigo que falle luego.  Preguntar por un tipo EN MARCHA es otra
 * cosa y vive aparte, en la familia de reflexion.
 *
 * `bitcast` esta aqui aunque no pregunte nada: lo que hace -- leer los mismos
 * bits como otro tipo -- lo decide por completo el tipo destino, asi que sin
 * mirar tipos al compilar no hay operacion que emitir.
 *
 * Se separo de la funcion que despacha todos los builtins.  Entra por su
 * propio punto: si el nombre no es de esta familia, contesta que no y quien
 * pregunta sigue con las demas.
 */
#include "vx/lowering.h"
#include "vx/comptime/comptime_introspect.h"
#include "vx/generics/generic_clone.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering (no es su interfaz)

namespace vx {

/**
 * @brief Intenta bajar @p e como uno de los builtins que miran los tipos.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado; sin valor si el builtin no lo da.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_introspect_builtins(ast::CallExpr *e, Builtin b,
                                             ir::IrValueId &out_value) {
    /* El nombre solo para los DIAGNOSTICOS: quien lee un error quiere leer
     * `sizeof`, no un numero.  Para decidir se usa el enum, que es lo que
     * llega ya resuelto -- volver al texto para compararlo seria deshacer el
     * trabajo que hizo quien reparte. */
    const std::string_view name = builtin_name(b);

    /* Salida rapida: si no es de esta familia no se mira nada de lo de abajo.
     */
    if (!(b == Builtin::Alignof || b == Builtin::Bitcast ||
          b == Builtin::ComptimeTypeAlignof || b == Builtin::ComptimeTypeKind ||
          b == Builtin::ComptimeTypeSizeof || b == Builtin::Extent ||
          b == Builtin::FieldCount || b == Builtin::FieldGet ||
          b == Builtin::FieldName || b == Builtin::FieldSet ||
          b == Builtin::FieldType || b == Builtin::FindType ||
          b == Builtin::ForEachField || b == Builtin::ForEachMethod ||
          b == Builtin::HasField || b == Builtin::HasMethod ||
          b == Builtin::InBounds || b == Builtin::IsBool ||
          b == Builtin::IsChar || b == Builtin::IsClass ||
          b == Builtin::IsEnum || b == Builtin::IsFloat ||
          b == Builtin::IsInteger || b == Builtin::IsNewtype ||
          b == Builtin::IsNumeric || b == Builtin::IsOpaque ||
          b == Builtin::IsPointer || b == Builtin::IsPrimitive ||
          b == Builtin::IsSame || b == Builtin::IsSigned ||
          b == Builtin::IsString || b == Builtin::IsStruct ||
          b == Builtin::IsSubtype || b == Builtin::IsUnsigned ||
          b == Builtin::Kind || b == Builtin::MethodCount ||
          b == Builtin::Offsetof || b == Builtin::Parent ||
          b == Builtin::Sizeof || b == Builtin::StaticAssert ||
          b == Builtin::TypeId || b == Builtin::TypeInfoAlign ||
          b == Builtin::TypeInfoFieldCount || b == Builtin::TypeInfoFieldName ||
          b == Builtin::TypeInfoFieldOffset ||
          b == Builtin::TypeInfoFieldSize || b == Builtin::TypeInfoKind ||
          b == Builtin::TypeInfoName || b == Builtin::TypeInfoSize ||
          b == Builtin::Typename || b == Builtin::UnderlyingOf))
        return false;

    // Overlay: `extent(v)` -> span total en runtime del layout de la vista.
    // Baja a un CALL a `__ovl_extent_<S>(base)`.
    if (b == Builtin::Extent && e->type_args.empty() && e->args.size() == 1) {
        ast::Expr *arg = e->args[0].get();
        const Type vt = arg->result_type;
        if (vt.kind != PrimitiveKind::STRUCT) {
            return builtin_error(
                e->loc, "extent(v): v debe ser una vista @overlay", out_value);
        }
        const auto &lays = tc_.struct_layouts();
        auto it = lays.find(vt.struct_name);
        if (it == lays.end() || !it->second.is_overlay) {
            return builtin_error(e->loc,
                                 "extent(v): '" + vt.struct_name +
                                     "' no es una vista @overlay",
                                 out_value);
        }
        const ir::IrValueId base = lower_expr(arg);
        if (base == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const std::string rname = generate_overlay_extent(it->second);
        ir::IrValueId d = fn_->new_value(ir::IrType::U64);
        ir::IrInstr in{};
        in.op = ir::IrOp::CALL;
        in.func_name = rname;
        in.type = ir::IrType::U64;
        in.dst = d;
        in.operands = {base};
        in.is_call_site = true;
        in.source_line = e->loc.line;
        emit(current_block_, std::move(in));
        out_value = d;
        return true;
    }

    // F4: `parent<T>()` dentro de un resolver `@offset { }` = el puntero de la
    // vista RAIZ, enhebrado como 2o param `root` (bind "__ovl_root").  Devuelve
    // ese puntero tipado como la vista T (el CallExpr ya tiene result_type=T).
    if (b == Builtin::Parent && !e->type_args.empty() && e->args.empty()) {
        const ir::IrValueId rv = lookup("__ovl_root");
        if (rv == ir::IR_NO_VALUE) {
            return builtin_error(
                e->loc,
                "parent<T>() solo es valido dentro de un resolver "
                "@offset { } (de un overlay accedido como sub-vista)",
                out_value);
        }
        out_value = rv;
        return true;
    }

    // Overlay: forma-VALOR de offsetof / in_bounds (runtime).  Sin type
    // args; el 1er arg es un acceso a campo/elemento de una vista @overlay
    // (el type checker ya lo valido y fijo result_type a U64/BOOL).
    //   offsetof(v.campo)       = (u64) &campo - base_de_la_vista
    //   in_bounds(v.campo, len) = offsetof(v.campo) + sizeof(campo) <= len
    // Reusa la resolucion de direccion de lower_field_addr/lower_index_addr
    // (que ya resuelve @offset(expr) dinamico + stride de arrays); la raiz
    // de la cadena de accesos ES el puntero base construido con `T(buf)`.
    if (e->type_args.empty() && !e->args.empty() &&
        (b == Builtin::Offsetof || b == Builtin::InBounds) &&
        (e->result_type.kind == PrimitiveKind::U64 ||
         e->result_type.kind == PrimitiveKind::BOOL)) {
        const uint32_t ln = e->loc.line;
        ast::Expr *arg = e->args[0].get();
        // Direccion (host) del campo/elemento accedido.
        ir::IrValueId field_addr = ir::IR_NO_VALUE;
        if (arg->kind == ast::NodeKind::FieldAccessExpr) {
            field_addr =
                lower_field_addr(static_cast<ast::FieldAccessExpr *>(arg));
        } else if (arg->kind == ast::NodeKind::IndexExpr) {
            field_addr = lower_index_addr(static_cast<ast::IndexExpr *>(arg));
        }
        if (field_addr == ir::IR_NO_VALUE) {
            return builtin_error(e->loc,
                                 std::string(name) +
                                     ": el argumento debe ser un acceso a "
                                     "campo/elemento de un overlay",
                                 out_value);
        }
        // Puntero base de la vista: raiz de la cadena de accesos.
        ast::Expr *root = arg;
        for (;;) {
            if (root->kind == ast::NodeKind::FieldAccessExpr) {
                root = static_cast<ast::FieldAccessExpr *>(root)->base.get();
                continue;
            }
            if (root->kind == ast::NodeKind::IndexExpr) {
                root = static_cast<ast::IndexExpr *>(root)->base.get();
                continue;
            }
            break;
        }
        const ir::IrValueId base_ptr = lower_expr(root);
        if (base_ptr == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // off = field_addr - base_ptr   (u64)
        ir::IrValueId off = emit_ir_binop(ir::IrOp::SUB, field_addr, base_ptr,
                                          ir::IrType::U64, ln);
        if (b == Builtin::Offsetof) {
            out_value = off;
            return true;
        }
        // in_bounds: (off + sizeof(campo)) <= len   (sin signo).
        const uint64_t fsize = comptime_type_size(tc_, arg->result_type);
        ir::IrValueId endv = off;
        if (fsize != 0) {
            ir::IrValueId fc = emit_const(ir::IrType::U64, fsize, ln);
            endv = fn_->new_value(ir::IrType::U64);
            ir::IrInstr a{};
            a.op = ir::IrOp::ADD;
            a.type = ir::IrType::U64;
            a.dst = endv;
            a.operands = {off, fc};
            a.source_line = ln;
            emit(current_block_, std::move(a));
        }
        ir::IrValueId lenv = lower_expr(e->args[1].get());
        if (lenv == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // Coaccionar len a u64 para una comparacion sin signo de 64 bits.
        const ir::IrType lfrom =
            ir_type_from_primitive(e->args[1]->result_type.kind);
        lenv = cast_if_needed(lenv, lfrom, ir::IrType::U64, ln);
        ir::IrValueId res =
            emit_ir_binop(ir::IrOp::CMP_ULE, endv, lenv, ir::IrType::BOOL, ln);
        out_value = res;
        return true;
    }

    /* Type-metadata con arg LITERAL string: comptime_type_sizeof/alignof/kind
     * ("u64").  Son CONSTANTES compile-time -- se pliegan a un CONST para que
     * un @Macro que las use se baje a IR y corra por VM/JIT (no AST-eval).
     * El nombre del tipo se resuelve via resolve_type_string (misma ruta que
     * los typenames canonicos importados). */
    if (e->args.size() == 1 && e->args[0] &&
        e->args[0]->kind == ast::NodeKind::StringLitExpr &&
        (b == Builtin::ComptimeTypeSizeof ||
         b == Builtin::ComptimeTypeAlignof || b == Builtin::ComptimeTypeKind)) {
        const std::string tn =
            static_cast<ast::StringLitExpr *>(e->args[0].get())->value;
        const Type t = tc_.resolve_type_string(tn);
        const uint32_t src_line = e->loc.line;
        if (b == Builtin::ComptimeTypeSizeof) {
            out_value = emit_const(ir::IrType::U64, comptime_type_size(tc_, t),
                                   src_line);
            return true;
        }
        if (b == Builtin::ComptimeTypeAlignof) {
            out_value = emit_const(ir::IrType::U64, comptime_type_align(tc_, t),
                                   src_line);
            return true;
        }
        /* comptime_type_kind */
        const ComptimeKind k = comptime_type_kind(t);
        out_value = emit_const(ir::IrType::I32,
                               static_cast<uint64_t>(static_cast<int32_t>(k)),
                               src_line);
        return true;
    }

    // `bitcast<T>(v)`: reinterpretar los BITS.  El type checker ya exigio que
    // origen y destino midan lo mismo, asi que aqui es un BITCAST del IR -- que
    // entre tipos del mismo ancho baja a un `mov`: coste cero.
    if (b == Builtin::Bitcast && !e->type_args.empty() && e->args.size() == 1) {
        const Type dst_t = tc_.resolve_type_node(e->type_args[0].get());
        const ir::IrValueId v_src = lower_expr(e->args[0].get());
        if (v_src == ir::IR_NO_VALUE) return true;
        const ir::IrType dst_ir = ir_type_from_primitive(dst_t.kind);
        const ir::IrValueId v_dst = fn_->new_value(dst_ir);
        // Reinterpretar bits no cambia a que memoria apunta un puntero.
        fn_->values[v_dst].is_host_ptr = fn_->values[v_src].is_host_ptr;
        ir::IrInstr bc{};
        bc.op = ir::IrOp::BITCAST;
        bc.type = dst_ir;
        bc.dst = v_dst;
        bc.operands = {v_src};
        bc.source_line = e->loc.line;
        emit(current_block_, std::move(bc));
        out_value = v_dst;
        return true;
    }
    // Predicados de tipo: se responden en comptime -> una constante.  El `if`
    // que los use lo pliega el optimizer y la rama muerta desaparece: en el
    // binario solo queda el camino que corresponde a T.
    if (e->type_args.size() == 1 && e->args.empty() &&
        (b == Builtin::IsFloat || b == Builtin::IsInteger ||
         b == Builtin::IsSigned || b == Builtin::IsUnsigned ||
         b == Builtin::IsNumeric || b == Builtin::IsBool ||
         b == Builtin::IsChar || b == Builtin::IsPointer ||
         b == Builtin::IsString || b == Builtin::IsClass ||
         b == Builtin::IsStruct || b == Builtin::IsPrimitive ||
         b == Builtin::IsEnum)) {
        int64_t v = 0;
        if (!const_cast<TypeChecker &>(tc_).lsp_eval_builtin_scalar(e, &v)) {
            error_at(e->loc, "lowering: '" + std::string(name) +
                                 "' no se pudo resolver en comptime");
            return true;
        }
        out_value =
            emit_const(ir::IrType::I8, (uint64_t)(v != 0 ? 1 : 0), e->loc.line);
        return true;
    }
    if (!e->type_args.empty() &&
        (b == Builtin::Sizeof || b == Builtin::Alignof ||
         b == Builtin::Typename || b == Builtin::TypeId ||
         b == Builtin::Kind)) {
        const Type t = tc_.resolve_type_node(e->type_args[0].get());
        const uint32_t src_line = e->loc.line;
        if (b == Builtin::Sizeof) {
            const uint64_t v = comptime_type_size(tc_, t);
            out_value = emit_const(ir::IrType::U64, v, src_line);
            return true;
        }
        if (b == Builtin::Alignof) {
            const uint64_t v = comptime_type_align(tc_, t);
            out_value = emit_const(ir::IrType::U64, v, src_line);
            return true;
        }
        if (b == Builtin::TypeId) {
            const uint32_t v = comptime_type_id(tc_, t);
            out_value =
                emit_const(ir::IrType::U32, static_cast<uint64_t>(v), src_line);
            return true;
        }
        if (b == Builtin::Kind) {
            const ComptimeKind k = comptime_type_kind(t);
            out_value = emit_const(
                ir::IrType::I32, static_cast<uint64_t>(static_cast<int32_t>(k)),
                src_line);
            return true;
        }
        /* typename<T>() -> StringObject construido inline desde el
         * nombre canonico.  Reusa el mismo patron que el path no-
         * interpolado de @c lower_string_literal_to_string_object:
         * STR_LIT_ADDR a static_data + RAW_ASM strmake. */
        if (b == Builtin::Typename) {
            const std::string nm = comptime_type_name(tc_, t);
            std::vector<uint8_t> bytes(nm.begin(), nm.end());
            const uint64_t idx = out_mod_->intern_static_data(std::move(bytes));
            ir::IrValueId v_addr = emit_str_lit_addr(idx, src_line);
            ir::IrValueId v_len = emit_const(
                ir::IrType::I64, static_cast<uint64_t>(nm.size()), src_line);
            /* typename es un literal compile-time: value-string nativo en AOT
             * (PURE_NATIVE) o GcHandle en el resto de tiers. */
            ir::IrValueId v_str = emit_string_literal_repr(
                v_addr, v_len, (int64_t)nm.size(), src_line);
            out_value = v_str;
            return true;
        }
    }

    // -----------------------------------------------------------------
    // static_assert(cond, "msg").
    //
    // Con la condicion comptime-constante la resuelve el type checker y aqui
    // no se emite nada, como siempre.  Cuando NO lo es -- porque depende de un
    // parametro de la propia comptime fn, que es el caso interesante -- el
    // type checker calla a proposito y cuenta con que se baje a
    // `vesta_comptime:static_assert`, para que la evalue la ComptimeVM al
    // ejecutar el cuerpo (que sigue siendo tiempo de compilacion).  Esa
    // segunda ruta ya estaba escrita mas abajo pero un descarte incondicional
    // se la comia, dejando a una comptime fn sin forma de rechazar su entrada.
    //
    // Fuera de un cuerpo comptime se sigue descartando: emitir la llamada solo
    // meteria trabajo en el programa final (la stdlib declara decenas de
    // guards por tipo generico, y cada uno se volvia un CALLN de verdad).
    // -----------------------------------------------------------------
    /* `static_assert` se atiende en DOS sitios a proposito, y la condicion de
     * arriba es la que reparte: aqui se resuelve al compilar, que es lo suyo.
     * Pero dentro del cuerpo de una macro la condicion todavia no se conoce
     * -- depende de con que se invoque la macro --, asi que ahi esta familia no
     * lo captura, devuelve que no, y lo atiende el despacho general emitiendo
     * una comprobacion que corre cuando la macro corra.  Quitar el
     * `!current_fn_is_macro_` dejaria el otro bloque inalcanzable. */
    if (b == Builtin::StaticAssert && !current_fn_is_macro_) {
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    // -----------------------------------------------------------------
    // Sprint 4 (A.37.s4): builtins runtime de introspection.
    //   find_type("Lit")                   -> direct mov al chunk
    //   find_type(s)                       -> CALL al resolver runtime (TODO)
    //   type_info_kind/size/align/field_count -> LOAD u32 con offset fijo
    //   type_info_name(p) / _field_name(p, i) -> construye StringObject
    //   type_info_field_offset / _field_size  -> LOAD u32 con stride 16
    // -----------------------------------------------------------------
    {
        const bool is_find = (b == Builtin::FindType);
        const bool is_simple_u32 = b == Builtin::TypeInfoSize ||
                                   b == Builtin::TypeInfoAlign ||
                                   b == Builtin::TypeInfoFieldCount;
        const bool is_kind_i32 = (b == Builtin::TypeInfoKind);
        const bool is_name_q = (b == Builtin::TypeInfoName);
        const bool is_field_name = (b == Builtin::TypeInfoFieldName);
        const bool is_field_u32 = b == Builtin::TypeInfoFieldOffset ||
                                  b == Builtin::TypeInfoFieldSize;
        if (is_find || is_simple_u32 || is_kind_i32 || is_name_q ||
            is_field_name || is_field_u32) {
            const uint32_t src_line = e->loc.line;
            if (is_find) {
                /* Resolver literal -> chunk idx en compile-time.
                 * Caso runtime string deferido a Sprint 5. */
                auto *slit =
                    e->args.empty()
                        ? nullptr
                        : dynamic_cast<ast::StringLitExpr *>(e->args[0].get());
                if (slit && !slit->is_interpolated()) {
                    auto it = introspect_idx_by_name_.find(slit->value);
                    if (it == introspect_idx_by_name_.end()) {
                        /* Tipo no registrado con @Introspect -> 0. */
                        out_value = emit_const(ir::IrType::I64, 0, src_line);
                        return true;
                    }
                    // raw_asm-elim wave 2: usar IrOp::STR_LIT_ADDR
                    // que ya emite `mov {dst}, @Absolute("code.s_N")`.
                    ir::IrValueId dst = fn_->new_value(ir::IrType::I64);
                    ir::IrInstr sl{};
                    sl.op = ir::IrOp::STR_LIT_ADDR;
                    sl.type = ir::IrType::PTR;
                    sl.dst = dst;
                    sl.imm = static_cast<uint64_t>(it->second);
                    sl.source_line = src_line;
                    emit(current_block_, std::move(sl));
                    out_value = dst;
                    return true;
                }
                /* Runtime string: para MVP devolvemos 0 (no soportado).
                 * Sprint 5 añade resolver sintetico. */
                error_at(e->loc,
                         "find_type: en MVP solo se soporta literal string "
                         "(runtime resolver pendiente en Sprint 5)");
                out_value = emit_const(ir::IrType::I64, 0, src_line);
                return true;
            }
            /* Resto: el primer arg es el handle del IntrospectInfo. */
            if (e->args.empty()) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            ir::IrValueId info_ptr = lower_expr(e->args[0].get());
            if (info_ptr == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            /* Helper: emite ADD ptr + offset_const + LOAD U32. */
            auto emit_load_u32_at = [&](uint32_t offset) -> ir::IrValueId {
                ir::IrValueId addr;
                if (offset == 0) {
                    addr = info_ptr;
                } else {
                    ir::IrValueId off_val =
                        emit_const(ir::IrType::I64, offset, src_line);
                    addr = emit_ptr_add(info_ptr, off_val, src_line);
                }
                ir::IrValueId dst =
                    emit_load_typed(addr, ir::IrType::U32, src_line);
                return dst;
            };
            if (is_kind_i32) {
                /* kind vive en offset 0 como u32; el tipo de retorno
                 * declarado es i32 asi que el caller ve un i32 (mismos
                 * bits). */
                ir::IrValueId v = emit_load_u32_at(0);
                out_value = v;
                return true;
            }
            if (is_simple_u32) {
                uint32_t off = 0;
                if (b == Builtin::TypeInfoSize)
                    off = 4;
                else if (b == Builtin::TypeInfoAlign)
                    off = 8;
                else if (b == Builtin::TypeInfoFieldCount)
                    off = 12;
                out_value = emit_load_u32_at(off);
                return true;
            }
            if (is_name_q) {
                /* type_info_name(p): name_off = LOAD u32 [p+16],
                 * name_len = LOAD u32 [p+20], addr = p + name_off,
                 * STRMAKE(addr, name_len). */
                ir::IrValueId name_off = emit_load_u32_at(16);
                ir::IrValueId name_len = emit_load_u32_at(20);
                /* Promote name_off a i64 antes del ADD. */
                ir::IrValueId addr = emit_ptr_add(info_ptr, name_off, src_line);
                /* STRMAKE necesita addr y len.  Para name_len que es u32
                 * lo usamos como i64 directamente; en la VM ambos caben
                 * en qword. */
                ir::IrValueId v_str =
                    emit_string_literal_repr(addr, name_len, -1, src_line);
                out_value = v_str;
                return true;
            }
            /* type_info_field_*: segundo arg es idx (u32). */
            if (e->args.size() < 2) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            ir::IrValueId idx_val = lower_expr(e->args[1].get());
            /* field_addr = info_ptr + 24 + idx * 16 */
            ir::IrValueId v16 = emit_const(ir::IrType::I64, 16, src_line);
            ir::IrValueId idx_x16 = emit_ir_binop(ir::IrOp::MUL, idx_val, v16,
                                                  ir::IrType::I64, src_line);
            ir::IrValueId v24 = emit_const(ir::IrType::I64, 24, src_line);
            ir::IrValueId field_off = emit_ir_binop(ir::IrOp::ADD, idx_x16, v24,
                                                    ir::IrType::I64, src_line);
            ir::IrValueId field_addr =
                emit_ptr_add(info_ptr, field_off, src_line);
            /* Helper interno LOAD u32 at field_addr + offset. */
            auto load_u32_field = [&](uint32_t off) -> ir::IrValueId {
                ir::IrValueId off_val =
                    emit_const(ir::IrType::I64, off, src_line);
                ir::IrValueId addr =
                    emit_ptr_add(field_addr, off_val, src_line);
                ir::IrValueId dst =
                    emit_load_typed(addr, ir::IrType::U32, src_line);
                return dst;
            };
            if (b == Builtin::TypeInfoFieldOffset) {
                out_value = load_u32_field(0);
                return true;
            }
            if (b == Builtin::TypeInfoFieldSize) {
                out_value = load_u32_field(4);
                return true;
            }
            if (is_field_name) {
                /* field_addr+8 = name_off; field_addr+12 = name_len */
                ir::IrValueId fname_off = load_u32_field(8);
                ir::IrValueId fname_len = load_u32_field(12);
                ir::IrValueId addr =
                    emit_ptr_add(info_ptr, fname_off, src_line);
                ir::IrValueId v_str =
                    emit_string_literal_repr(addr, fname_len, -1, src_line);
                out_value = v_str;
                return true;
            }
        }
    }

    // -----------------------------------------------------------------
    // Sprint 3-C introspection: for_each_field<T>(cb) / for_each_method.
    // Loop completamente unrolled en compile-time: por cada field/
    // method de T emitimos UNA invocacion CALLCLOSURE al callback
    // con el nombre como string.  Cero overhead de loop runtime
    // (vs map dinamico), pero N llamadas reales al callback.
    // -----------------------------------------------------------------
    if (try_lower_for_each_member(e, b, out_value)) return true;

    // -----------------------------------------------------------------
    // Sprint 3-A introspection: field_get<T>(obj, "f") / field_set.
    // Bypass de getfield/setfield: usa offset compile-time via
    // comptime_field_offset.  El type checker ya valido tipos y
    // que el segundo arg sea string literal.
    // -----------------------------------------------------------------
    if (try_lower_field_access_by_name(e, b, out_value)) return true;

    // -----------------------------------------------------------------
    // Sprint 2 introspection: 12 builtins de fields/methods/types.
    // Mismas garantias que Sprint 1: cada llamada baja a UN solo
    // IrOp::CONST (o STR_LIT_ADDR + STRMAKE para los que devuelven
    // string).  El type checker ya valido aridad + que los args
    // runtime sean literales compile-time.
    // -----------------------------------------------------------------
    {
        const bool one_targ_no_args =
            b == Builtin::FieldCount || b == Builtin::MethodCount ||
            b == Builtin::IsClass || b == Builtin::IsStruct ||
            b == Builtin::IsPrimitive || b == Builtin::IsEnum ||
            b == Builtin::IsNewtype || b == Builtin::IsOpaque ||
            b == Builtin::UnderlyingOf;
        const bool one_targ_str_arg =
            b == Builtin::Offsetof || b == Builtin::HasField ||
            b == Builtin::HasMethod || b == Builtin::FieldType;
        const bool one_targ_int_arg = (b == Builtin::FieldName);
        const bool two_targ_no_args =
            b == Builtin::IsSubtype || b == Builtin::IsSame;

        if ((one_targ_no_args || one_targ_str_arg || one_targ_int_arg ||
             two_targ_no_args) &&
            !e->type_args.empty()) {
            const uint32_t src_line = e->loc.line;
            const Type t1 = tc_.resolve_type_node(e->type_args[0].get());
            /* Helper local: emite STRMAKE con el nombre canonico recibido. */
            auto emit_strmake_for =
                [&](const std::string &nm) -> ir::IrValueId {
                std::vector<uint8_t> bytes(nm.begin(), nm.end());
                const uint64_t idx =
                    out_mod_->intern_static_data(std::move(bytes));
                ir::IrValueId v_addr = emit_str_lit_addr(idx, src_line);
                ir::IrValueId v_len =
                    emit_const(ir::IrType::I64,
                               static_cast<uint64_t>(nm.size()), src_line);
                ir::IrValueId v_str =
                    emit_string_literal_repr(v_addr, v_len, -1, src_line);
                return v_str;
            };

            /* Extraer el arg literal compile-time si lo hay. */
            std::string slit_arg;
            uint64_t ilit_arg = 0;
            if (one_targ_str_arg) {
                auto *slit =
                    dynamic_cast<ast::StringLitExpr *>(e->args[0].get());
                if (slit) slit_arg = slit->value;
            }
            if (one_targ_int_arg) {
                auto *ilit = dynamic_cast<ast::IntLitExpr *>(e->args[0].get());
                if (ilit) ilit_arg = ilit->value;
            }

            if (b == Builtin::FieldCount) {
                const uint32_t v = comptime_field_count(tc_, t1);
                out_value = emit_const(ir::IrType::U32, v, src_line);
                return true;
            }
            if (b == Builtin::MethodCount) {
                const uint32_t v = comptime_method_count(tc_, t1);
                out_value = emit_const(ir::IrType::U32, v, src_line);
                return true;
            }
            if (b == Builtin::IsClass) {
                const bool v = comptime_is_class(t1);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::IsStruct) {
                const bool v = comptime_is_struct(tc_, t1);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::IsEnum) {
                const bool v = comptime_is_enum(tc_, t1);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::IsPrimitive) {
                const bool v = comptime_is_primitive(t1);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::IsNewtype) {
                const bool v = comptime_is_newtype(t1);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::IsOpaque) {
                const bool v = comptime_is_opaque(t1);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::UnderlyingOf) {
                const std::string un = comptime_underlying_name(tc_, t1);
                out_value = emit_strmake_for(un);
                return true;
            }
            if (b == Builtin::Offsetof) {
                const int64_t off = comptime_field_offset(tc_, t1, slit_arg);
                /* off==-1 (campo no existe): emitir error claro y
                 * usar 0 como fallback para no romper el flujo. */
                if (off < 0) {
                    diags_.error(e->loc, "offsetof: el tipo '" +
                                             comptime_type_name(tc_, t1) +
                                             "' no tiene campo '" + slit_arg +
                                             "'");
                }
                out_value = emit_const(
                    ir::IrType::U64,
                    off < 0 ? 0ULL : static_cast<uint64_t>(off), src_line);
                return true;
            }
            if (b == Builtin::HasField) {
                const bool v = comptime_has_field(tc_, t1, slit_arg);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::HasMethod) {
                const bool v = comptime_has_method(tc_, t1, slit_arg);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::FieldType) {
                const std::string tn =
                    comptime_field_type_name(tc_, t1, slit_arg);
                if (tn.empty()) {
                    diags_.error(e->loc, "field_type: el tipo '" +
                                             comptime_type_name(tc_, t1) +
                                             "' no tiene campo '" + slit_arg +
                                             "'");
                }
                out_value = emit_strmake_for(tn);
                return true;
            }
            if (b == Builtin::FieldName) {
                const std::string nm_v = comptime_field_name(
                    tc_, t1, static_cast<uint32_t>(ilit_arg));
                if (nm_v.empty()) {
                    diags_.error(e->loc, "field_name: el tipo '" +
                                             comptime_type_name(tc_, t1) +
                                             "' no tiene campo en indice " +
                                             std::to_string(ilit_arg));
                }
                out_value = emit_strmake_for(nm_v);
                return true;
            }
            if (b == Builtin::IsSame) {
                const Type t2 = tc_.resolve_type_node(e->type_args[1].get());
                const bool v = comptime_is_same(tc_, t1, t2);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
            if (b == Builtin::IsSubtype) {
                const Type t2 = tc_.resolve_type_node(e->type_args[1].get());
                const bool v = comptime_is_subtype(tc_, t1, t2);
                out_value =
                    emit_const(ir::IrType::BOOL, v ? 1ULL : 0ULL, src_line);
                return true;
            }
        }
    }

    return false;
}

/**
 * @brief Lee o escribe un campo nombrandolo con una CADENA.
 *
 * `field_get<T>(obj, "x")` parece reflexion y no lo es: el nombre es un
 * literal, asi que el desplazamiento se resuelve AL COMPILAR y lo que se emite
 * es el mismo acceso que habria escrito `obj.x`.  No queda ni busqueda ni
 * tabla en el programa.
 *
 * @param e         La llamada.
 * @param b         Cual de los dos es.
 * @param out_value Donde dejar lo leido; sin valor al escribir.
 * @return @c true si era uno de los dos y quedo bajado.
 */
bool Lowering::try_lower_field_access_by_name(ast::CallExpr *e, Builtin b,
                                              ir::IrValueId &out_value) {
    if (e->type_args.empty() ||
        (b != Builtin::FieldGet && b != Builtin::FieldSet))
        return false;
    {
        const bool is_get = (b == Builtin::FieldGet);
        const Type t = tc_.resolve_type_node(e->type_args[0].get());
        std::string fname;
        if (e->args.size() >= 2) {
            if (auto *slit =
                    dynamic_cast<ast::StringLitExpr *>(e->args[1].get())) {
                fname = slit->value;
            }
        }
        const int64_t off = comptime_field_offset(tc_, t, fname);
        if (off < 0) {
            return builtin_error(e->loc,
                                 std::string(builtin_name(b)) + ": el tipo '" +
                                     comptime_type_name(tc_, t) +
                                     "' no tiene campo '" + fname + "'",
                                 out_value);
        }
        const Type ftype = comptime_field_type(tc_, t, fname);
        const ir::IrType ir_t = ir_type_from_primitive(ftype.kind);
        /* Lower obj: el primer arg.  Para CLASS el SSA value es un
         * host_ptr al ObjectHeader; para STRUCT inline es la direccion
         * VM del slot (resultado de la ALLOCA o del campo padre).
         * Detectamos por el TIPO declarado en T (no por el resultado de
         * check_expr del arg, que podria ser COUNT/inferido). */
        const ir::IrValueId obj = lower_expr(e->args[0].get());
        if (obj == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        /* Para CLASS la convencion del codegen es is_host_ptr=true sobre
         * el resultado de NEWOBJ/__new_<X> (host_ptr al ObjectHeader).
         * Para STRUCT la convencion es is_host_ptr=false (slot VM).
         * NO usamos emit_field_addr aqui porque su shortcut offset==0
         * MUTA el flag is_host_ptr del base SSA value (rompe init-lists
         * anteriores que comparten el binding).  En su lugar emitimos
         * un ADD i64 explicito que produce un nuevo SSA value distinto
         * del base, y propagamos is_host_ptr/pointee_is_host_ptr segun
         * la naturaleza de T. */
        const bool t_is_class = (t.kind == PrimitiveKind::CLASS);
        ir::IrValueId addr;
        if (off == 0) {
            addr = obj;
        } else {
            ir::IrValueId off_val = fn_->new_value(ir::IrType::I64);
            fn_->values[off_val].is_const = true;
            fn_->values[off_val].const_val = static_cast<uint64_t>(off);
            {
                ir::IrInstr c{};
                c.op = ir::IrOp::CONST;
                c.type = ir::IrType::I64;
                c.dst = off_val;
                c.imm = static_cast<uint64_t>(off);
                c.source_line = e->loc.line;
                emit(current_block_, std::move(c));
            }
            addr = fn_->new_value(ir::IrType::PTR);
            fn_->values[addr].is_host_ptr = t_is_class;
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = addr;
            ad.operands = {obj, off_val};
            ad.source_line = e->loc.line;
            emit(current_block_, std::move(ad));
        }
        /* Si offset==0 y T es CLASS, el obj YA debe tener is_host_ptr.
         * Si T es STRUCT con offset==0, el slot VM se mantiene sin
         * tocar el flag (heredamos el state del obj, que ya es lo
         * correcto). */
        if (is_get) {
            const ir::IrValueId dst = emit_load_typed(addr, ir_t, e->loc.line);
            /* Propagar is_host_ptr para campos PTR no virtuales (mismo
             * tratamiento que lower_class_field_load). */
            if (ftype.kind == PrimitiveKind::PTR && !ftype.is_virtual) {
                fn_->values[dst].is_host_ptr = true;
            }
            /* Campo CLASS: el slot guarda un GcHandle, no un host_ptr.
             * Hacemos gcderef para obtener host_ptr fresco post-GC. */
            if (ftype.kind == PrimitiveKind::CLASS) {
                // raw_asm-elim 2026-05-28: gcderef + xchg ->
                // IrOp::GC_DEREF_HOST.
                ir::IrValueId v_host = fn_->new_value(ir::IrType::I64);
                fn_->values[v_host].is_host_ptr = true;
                fn_->values[v_host].is_gc_object = true;
                ir::IrInstr deref{};
                deref.op = ir::IrOp::GC_DEREF_HOST;
                deref.type = ir::IrType::PTR;
                deref.dst = v_host;
                deref.operands = {dst};
                deref.source_line = e->loc.line;
                emit(current_block_, std::move(deref));
                out_value = v_host;
                return true;
            }
            out_value = dst;
            return true;
        }
        /* field_set: lower value y emit STORE. */
        if (e->args.size() < 3) {
            /* Type checker ya emitio error; salir limpio. */
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        ir::IrValueId val = lower_expr(e->args[2].get());
        if (val == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        /* Coerce el valor al tipo del campo si difiere.  El SSA value
         * de val ya tiene su tipo en fn_->values[val].type; el cast
         * inserta truncate/sext/zext segun signos y anchos. */
        const ir::IrType val_t = fn_->values[val].type;
        val = cast_if_needed(val, val_t, ir_t, e->loc.line);
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ir_t;
        st.dst = ir::IR_NO_VALUE;
        /* Convencion IR: operands = {value, addr} (no al reves). */
        st.operands = {val, addr};
        st.source_line = e->loc.line;
        emit(current_block_, std::move(st));
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    return true;
}

/**
 * @brief Recorre los campos o los metodos de un tipo, AL COMPILAR.
 *
 * `for_each_field<T>(...)` no es un bucle: el compilador conoce los campos del
 * tipo, asi que repite el cuerpo una vez por cada uno con su nombre y su
 * desplazamiento ya puestos.  Lo que llega al programa son N copias, sin
 * contador ni condicion.
 *
 * @param e         La llamada.
 * @param b         Cual de los dos es.
 * @param out_value Donde dejar el resultado, si lo hay.
 * @return @c true si era uno de los dos y quedo bajado.
 */
bool Lowering::try_lower_for_each_member(ast::CallExpr *e, Builtin b,
                                         ir::IrValueId &out_value) {
    if (e->type_args.empty() ||
        (b != Builtin::ForEachField && b != Builtin::ForEachMethod))
        return false;
    {
        const bool is_fields = (b == Builtin::ForEachField);
        const Type t = tc_.resolve_type_node(e->type_args[0].get());
        if (e->args.empty()) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        /* Lower el callback una sola vez -> fv_addr (16 bytes en stack). */
        const ir::IrValueId fv_addr = lower_expr(e->args[0].get());
        if (fv_addr == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        /* LOAD fn_addr = [fv_addr]; LOAD env_addr = [fv_addr + 8]. */
        ir::IrValueId fn_addr =
            emit_load_typed(fv_addr, ir::IrType::I64, e->loc.line);
        ir::IrValueId env_addr = fn_->new_value(ir::IrType::I64);
        {
            ir::IrValueId fv_plus_8 = fn_->new_value(ir::IrType::PTR);
            ir::IrValueId off8 = emit_const(ir::IrType::I64, 8, e->loc.line);
            {
                ir::IrInstr ad{};
                ad.op = ir::IrOp::ADD;
                ad.type = ir::IrType::I64;
                ad.dst = fv_plus_8;
                ad.operands = {fv_addr, off8};
                ad.source_line = e->loc.line;
                emit(current_block_, std::move(ad));
            }
            ir::IrInstr ld{};
            ld.op = ir::IrOp::LOAD;
            ld.type = ir::IrType::I64;
            ld.dst = env_addr;
            ld.operands = {fv_plus_8};
            ld.source_line = e->loc.line;
            emit(current_block_, std::move(ld));
        }
        /* Iterar fields/methods y emitir una CALLCLOSURE por cada uno. */
        const uint32_t n = is_fields ? comptime_field_count(tc_, t)
                                     : comptime_method_count(tc_, t);
        for (uint32_t i = 0; i < n; ++i) {
            const std::string nm =
                is_fields
                    ? comptime_field_name(tc_, t, i)
                    : (i < comptime_method_count(tc_, t) ? [&]() {
                          /* Buscar el i-esimo method name. */
                          if (t.kind == PrimitiveKind::STRUCT ||
                              t.kind == PrimitiveKind::CLASS) {
                              auto it = tc_.class_layouts().find(t.struct_name);
                              if (it != tc_.class_layouts().end() &&
                                  i < it->second.methods.size()) {
                                  return it->second.methods[i].name;
                              }
                          }
                          return std::string();
                      }()
                                                         : std::string());
            if (nm.empty()) continue;
            /* Build StringObject para el nombre. */
            std::vector<uint8_t> bytes(nm.begin(), nm.end());
            const uint64_t idx = out_mod_->intern_static_data(std::move(bytes));
            ir::IrValueId v_addr = emit_str_lit_addr(idx, e->loc.line);
            ir::IrValueId v_len = emit_const(
                ir::IrType::I64, static_cast<uint64_t>(nm.size()), e->loc.line);
            ir::IrValueId v_str =
                emit_string_literal_repr(v_addr, v_len, -1, e->loc.line);
            /* CALLCLOSURE(env_addr, v_str) -- void return. */
            ir::IrInstr cl{};
            cl.op = ir::IrOp::CALLCLOSURE;
            cl.type = ir::IrType::VOID;
            cl.dst = ir::IR_NO_VALUE;
            cl.func_ptr = fn_addr;
            cl.operands = {env_addr, v_str};
            cl.source_line = e->loc.line;
            emit(current_block_, std::move(cl));
        }
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    return true;
}

} // namespace vx
