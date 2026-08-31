/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/expressions.cpp
 * @brief Bajada de las expresiones que CALCULAN: operadores, conversiones y el
 *        condicional.
 *
 * Lo que tienen en comun, y lo que ocupa casi todo el fichero, es que en Vesta
 * un operador no dice por si solo que instruccion sale.  Un `+` entre enteros
 * con signo, entre enteros sin signo, entre flotantes, entre cadenas o entre
 * dos tipos distintos son cinco cosas distintas, y ademas hay que convertir los
 * operandos antes -- con el ancho y el signo correctos -- para que el resultado
 * sea el que el lenguaje promete y no el que la maquina daria por accidente.
 */
#include "util/fnv.h" // la semilla y el primo, en UN sitio
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
ir::IrValueId Lowering::lower_cast_expr(ast::CastExpr *e) {
    if (!e || !e->operand) return ir::IR_NO_VALUE;

    // Compound literal `(Struct){...}`: construir un struct anonimo inline.
    // Aloca + zero-fill + defaults + init-list, y devuelve su direccion (un
    // valor struct como cualquier otro).  Funciona en interp/JIT/AOT.
    if (e->target_type && e->operand->kind == ast::NodeKind::InitListExpr) {
        Type tt = tc_.resolve_type_node(e->target_type.get());
        if (tt.kind == PrimitiveKind::STRUCT) {
            auto it = tc_.struct_layouts().find(tt.struct_name);
            if (it != tc_.struct_layouts().end()) {
                const StructLayout &lay = it->second;
                ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
                ir::IrInstr al{};
                al.op = ir::IrOp::ALLOCA;
                al.type = ir::IrType::I8;
                al.dst = addr;
                al.imm = (uint64_t)lay.size_bytes;
                al.source_line = e->loc.line;
                // El buffer de un compound literal `(T){...}` es un agregado
                // como cualquier otro -> host en los tres modos (ver
                // lower_var_decl), no solo en AOT.
                al.host_alloca = true;
                emit(current_block_, std::move(al));
                fn_->values[addr].is_host_ptr = true;
                emit_zero_fill(addr, (uint64_t)lay.size_bytes, e->loc.line);
                emit_struct_init_fields(
                    addr, lay,
                    static_cast<ast::InitListExpr *>(e->operand.get()),
                    e->loc.line);
                return addr;
            }
        }
    }

    // Function pointer: `(u64) foo` / `(fn(...)->R) foo` donde foo es una
    // funcion top-level -> emitir LABEL_ADDR (direccion cruda del codigo).
    // El resultado es un puntero de 8 bytes valido para meter en una tabla
    // o para una llamada indirecta posterior (cast u64->fn -> CALLIND).
    if (e->operand->kind == ast::NodeKind::IdentExpr) {
        auto *id = static_cast<ast::IdentExpr *>(e->operand.get());
        if (id->is_func_ref) {
            const std::string label =
                id->func_ref_mangled.empty() ? id->name : id->func_ref_mangled;
            // Bug/feature 198: en interp/JIT (no AOT), un puntero a funcion de
            // una funcion PLANA del modulo puede fluir a codigo NATIVO (asm
            // @Naked que hace `call [g_fp]`, o un callvmr que detecta la
            // direccion nativa).  Para que ese codigo pueda saltar al fp, la
            // direccion debe ser la NATIVA (no la VA de bytecode VM).  Emitimos
            // una CALLN a vrt:naked_fnaddr que compila la funcion al vuelo y
            // devuelve su direccion nativa.  El interp/JIT callvmr detecta que
            // la direccion cae en el code cache naked y la invoca con ABI del
            // host.  Solo funciones planas (no lambdas ni externs): las lambdas
            // van por otro path (LABEL_ADDR de bytecode) y los externs por su
            // thunk cfn.
            //
            // LIM-5: el sig se busca por el nombre LOCAL @c id->name (NO por
            // @c label), igual que el path de CALL a @Naked (mismo fichero,
            // ~L14986).  Para un simbolo IMPORTADO via `only`, la FunctionSig
            // se registra bajo su nombre LOCAL y su @c mangled_label lleva el
            // nombre del modulo (`racelib__race_task`); buscar por @c label (ya
            // mangled) devolveria nullptr -> se caeria al LABEL_ADDR de
            // bytecode VM (direccion equivocada) y el fiber_switch saltaria a
            // basura.  El @c label (para el hash del dispatcher) sigue siendo
            // el mangled, que es como se llama el IrFunction en el modulo
            // final.
            const FunctionSig *fs = tc_.function_sig_by_name(id->name);
            if (!native_poo_ && fs != nullptr && fs->extern_lib.empty() &&
                !extern_lib_by_fn_name_.count(id->name)) {
                out_mod_->register_native_import("vrt", "naked_fnaddr");
                uint64_t name_hash = util::kFnvOffset;
                for (unsigned char c : label) {
                    name_hash ^= static_cast<uint64_t>(c);
                    name_hash *= util::kFnvPrime;
                }
                std::vector<ir::IrValueId> args;
                args.push_back(emit_getproc(e->loc.line));
                args.push_back(
                    emit_const(ir::IrType::I64, name_hash, e->loc.line));
                const ir::IrValueId dst =
                    emit_calln("vrt:naked_fnaddr", std::move(args),
                               ir::IrType::PTR, e->loc.line);
                return dst;
            }
            const ir::IrValueId code = fn_->new_value(ir::IrType::PTR);
            ir::IrInstr ins{};
            ins.op = ir::IrOp::LABEL_ADDR;
            ins.type = ir::IrType::PTR;
            ins.dst = code;
            ins.func_name = func_ref_label(id->name, id->func_ref_mangled);
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
            // `(fn(...)) nombre` (LAMBDA): SIEMPRE un fat-pointer de 16 bytes
            // {fn_addr, env=0}, como TODO valor lambda -> el call lo trata por
            // CALLCLOSURE uniforme y se puede guardar en variables/campos fn.
            // `(cfn(...)) nombre`, `(u64) nombre`, `&nombre` (raw, 8 bytes)
            // devuelven la direccion cruda tal cual.
            const bool dst_is_lambda =
                (e->result_type.kind == PrimitiveKind::FUNCTION &&
                 !e->result_type.fn_is_raw);
            if (!dst_is_lambda) return code;
            const ir::IrValueId fv =
                stack_alloc_buf(16, e->loc.line, native_poo_);
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
                const ir::IrValueId z =
                    emit_const(ir::IrType::I64, 0, e->loc.line);
                emit_store_typed(fv8, z, ir::IrType::I64, e->loc.line);
            }
            return fv;
        }
    }

    const ir::IrValueId v_op = lower_expr(e->operand.get());
    if (v_op == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    const Type &dst_type = e->result_type;          // tipo destino del cast
    const Type &src_type = e->operand->result_type; // tipo del operando

    // Vesta Embed: cast (string)<char> -> value-string de un caracter.
    // En native_poo_ el `string` es value-type {ptr,len,cap}; el cast
    // construye un slot owned de 1 char (buffer malloc de 2 bytes).
    // El resultado es TEMPORAL (sin RAII) salvo que el caller lo ligue
    // a una variable -- lower_var_decl / build_native_operand del concat
    // lo registran como STRING_FREE / lo liberan tras copiar.
    if (dst_type.kind == PrimitiveKind::STRING &&
        src_type.kind == PrimitiveKind::CHAR) {
        if (native_poo_) {
            // v_op es el valor del char (u8).  Construir el slot.
            return build_native_string_from_char(v_op, e->loc.line);
        }
        // Path Full/JIT (StringObject GC): construir un StringObject de
        // 1 byte via STRMAKE no esta implementado aun; reportamos el
        // hueco sin romper Full.
        error_at(e->loc, "(string)<char> solo soportado en compilacion nativa "
                         "(-m aot); pendiente en el path Full");
        return ir::IR_NO_VALUE;
    }

    // Cast a tipo FUNCTION desde una direccion cruda ENTERA (i64/u64/...):
    // `(fn(...)->R) addr`.  Un function value es un PUNTERO a un slot de 16
    // bytes {fn_addr, env}; el cast debe CONSTRUIR ese slot (env=0, sin
    // captures) en lugar de reinterpretar la direccion como puntero al slot (lo
    // que deref-eaba el codigo de la funcion como si fuera el fn_addr ->
    // crash). Asi `((fn(...)->R) addr_i64)(args)` baja a una llamada indirecta
    // correcta (CALLCLOSURE) con los args en la convencion natural. RESTRINGIDO
    // a origen ENTERO: un origen PTR (e.g. `&slot[0]`) YA es el puntero al slot
    // y debe pasar tal cual (no envolverse de nuevo).
    auto is_int_kind = [](PrimitiveKind k) {
        return k == PrimitiveKind::I8 || k == PrimitiveKind::I16 ||
               k == PrimitiveKind::I32 || k == PrimitiveKind::I64 ||
               k == PrimitiveKind::U8 || k == PrimitiveKind::U16 ||
               k == PrimitiveKind::U32 || k == PrimitiveKind::U64;
    };
    // cfn (PUNTERO A FUNCION crudo estilo C): el cast NO envuelve en un slot
    // de 16 bytes; la direccion ENTERA ES el valor (8 bytes), y la llamada
    // baja a CALLIND directo.  lambda (fn) != cfn.  Esto cubre las tablas de
    // punteros a funcion y los saltos a direcciones fijas (kernels, FFI).
    if (dst_type.kind == PrimitiveKind::FUNCTION && dst_type.fn_is_raw &&
        is_int_kind(src_type.kind)) {
        return v_op; // la direccion cruda tal cual
    }
    if (dst_type.kind == PrimitiveKind::FUNCTION &&
        is_int_kind(src_type.kind)) {
        // v_op es la direccion de la funcion (i64).  Construir el slot.
        const ir::IrValueId fv_addr =
            stack_alloc_buf(16, e->loc.line, native_poo_);
        if (native_poo_) fn_->values[fv_addr].is_host_ptr = true;
        // [fv_addr + 0] = fn_addr (la direccion cruda).
        emit_store_typed(fv_addr, v_op, ir::IrType::I64, e->loc.line);
        // [fv_addr + 8] = 0 (env vacio).
        {
            const ir::IrValueId fv8 = fn_->new_value(ir::IrType::PTR);
            const ir::IrValueId off8 =
                emit_const(ir::IrType::I64, 8, e->loc.line);
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = fv8;
            ad.operands = {fv_addr, off8};
            ad.source_line = e->loc.line;
            emit(current_block_, std::move(ad));
            if (native_poo_) fn_->values[fv8].is_host_ptr = true;
            const ir::IrValueId z = emit_const(ir::IrType::I64, 0, e->loc.line);
            emit_store_typed(fv8, z, ir::IrType::I64, e->loc.line);
        }
        return fv_addr;
    }

    // Categorias.  PTR/ARRAY se tratan como pointer-like.
    auto is_ptr_like = [](const Type &t) {
        return t.kind == PrimitiveKind::PTR || t.kind == PrimitiveKind::ARRAY;
    };
    const bool dst_ptr = is_ptr_like(dst_type);
    const bool src_ptr = is_ptr_like(src_type);

    // Cast desde un tipo FUNCTION a entero/puntero.  Distinguimos:
    //   - cfn (fn_is_raw): el VALOR ya ES la direccion del codigo (8 bytes) ->
    //     identidad (`(u64) cfn` / `(i64) &funcion` = la direccion tal cual).
    //   - fn (lambda): un fat-pointer de 16 bytes {fn_addr, env}.  NO cabe en
    //   un
    //     entero de 8 bytes -> ERROR (usa cfn(...) o &funcion para el puntero
    //     crudo; o castea a un struct de dos i64 para deconstruir
    //     {fn_addr,env}).
    if (src_type.kind == PrimitiveKind::FUNCTION && src_type.fn_is_raw &&
        (is_int_kind(dst_type.kind) || dst_ptr)) {
        if (dst_ptr && native_poo_) fn_->values[v_op].is_host_ptr = true;
        return v_op; // identidad: el cfn ES la direccion
    }
    if (src_type.kind == PrimitiveKind::FUNCTION && !src_type.fn_is_raw &&
        is_int_kind(dst_type.kind)) {
        error_at(
            e->loc,
            "no se puede castear un lambda (fn(...), 16 bytes) a un entero "
            "de 8 bytes: se perderia el entorno.  Usa 'cfn(...)' o "
            "'&funcion' para el puntero a funcion crudo (8 bytes), o castea "
            "a un struct de dos i64 {fn_addr, env} para deconstruirlo.");
        return ir::IR_NO_VALUE;
    }
    // (void*) lambda: extraer el fn_addr (primeros 8 bytes del slot) para APIs
    // nativas que esperan un puntero de funcion crudo.  Solo para VARIABLE.
    if (src_type.kind == PrimitiveKind::FUNCTION &&
        e->operand->kind == ast::NodeKind::IdentExpr && dst_ptr) {
        const ir::IrValueId fa =
            emit_load_typed(v_op, ir::IrType::I64, e->loc.line);
        if (native_poo_) fn_->values[fa].is_host_ptr = true;
        return fa;
    }

    // ptr <-> ptr: el bit-pattern es identico, solo cambia la
    // interpretacion (host vs virtual, pointee).  No emitimos
    // ninguna instruccion IR; reusamos el SSA value tras propagar
    // los flags is_host_ptr/pointee_is_host_ptr al destino.
    if (dst_ptr && src_ptr) {
        // El SSA value sigue siendo el mismo bit-pattern.  Para
        // que LOAD/STORE posteriores emitan mov vs movh segun el
        // tipo DESTINO, marcamos el bit en el value resultante.
        // Convencion: VirtualPtr<T> -> is_host_ptr=false (memoria VM).
        //             T* (sin is_virtual) -> is_host_ptr=true (host).
        // Si el bit-pattern original era host_ptr=true y el destino
        // es VirtualPtr (is_virtual=true), el cast cambia la
        // interpretacion: el lowering ahora emitira mov en lugar
        // de movh.  El usuario asume las consecuencias.
        //
        // No clonamos el SSA value (eso obligaria a un MOV inutil);
        // creamos un nuevo SSA value vacio que comparte el reg con
        // el original via copy-prop natural del IR optimizer.  Para
        // ello emitimos un BITCAST de PTR a PTR (no-op a nivel
        // bytecode: se baja a `mov rd, rs` y la siguiente fase de
        // copy-prop suele eliminarlo).
        const ir::IrValueId dst =
            emit_ir_unop(ir::IrOp::BITCAST, v_op, ir::IrType::PTR, e->loc.line);
        // Propagar flags segun el tipo destino.
        fn_->values[dst].is_host_ptr = !dst_type.is_virtual;
        // pointee_is_host_ptr: si el destino apunta a otro puntero
        // host (e.g. T**), el slot apuntado lleva un host_ptr.  Sin
        // tipo pointee accesible aqui, replicamos el flag del
        // operando original como aproximacion conservadora.
        fn_->values[dst].pointee_is_host_ptr =
            fn_->values[v_op].pointee_is_host_ptr;
        return dst;
    }

    // ptr <-> int: BITCAST.  El IR_OP::BITCAST esta diseñado para
    // exactamente este caso (preserva bits sin conversion numerica).
    if (dst_ptr || src_ptr) {
        const ir::IrType ir_dst = ir_type_from_primitive(dst_type.kind);
        const ir::IrType ir_use =
            (ir_dst == ir::IrType::VOID)
                ? (dst_ptr ? ir::IrType::PTR : ir::IrType::I64)
                : ir_dst;
        const ir::IrValueId dst =
            emit_ir_unop(ir::IrOp::BITCAST, v_op, ir_use, e->loc.line);
        if (dst_ptr) {
            fn_->values[dst].is_host_ptr = !dst_type.is_virtual;
        } else if (dst_type.kind == PrimitiveKind::FUNCTION && src_ptr) {
            // Puntero -> cfn: un cfn ES un puntero a codigo, asi que hereda la
            // naturaleza host/VM de su origen.  Sin esto, castear una direccion
            // NATIVA (`(cfn(...)) ptr_host`) perdia el bit y la llamada se
            // emitia como indirecta de la VM, que interpreta la direccion como
            // codigo VM -> los argumentos no llegan y el fallo es silencioso.
            fn_->values[dst].is_host_ptr = fn_->values[v_op].is_host_ptr;
        }
        return dst;
    }

    // num <-> num: delegar al helper existente.  Maneja int<->int
    // (TRUNC/ZEXT/SEXT/CAST), int<->float (ITOF/UITOF/FTOI/FTOUI) y
    // float<->float (F32TOF64/F64TOF32).  Pasamos @c is_explicit=true
    // para silenciar el warning de cast implicito (el usuario opto
    // por el cast explicitamente).
    const ir::IrType ir_from = ir_type_from_primitive(src_type.kind);
    const ir::IrType ir_to = ir_type_from_primitive(dst_type.kind);
    if (ir_from == ir::IrType::VOID || ir_to == ir::IrType::VOID) {
        // Sin tipos validos en alguno de los lados, devolvemos el
        // operando sin convertir.  El type checker ya emitio el
        // error correspondiente.
        return v_op;
    }
    return cast_if_needed(v_op, ir_from, ir_to, e->loc.line,
                          /*is_explicit=*/true);
}

ir::IrValueId Lowering::lower_binary(ast::BinaryExpr *e) {
    // Tipos canonicos del checker.
    const PrimitiveKind ltk =
        e->lhs ? e->lhs->result_type.kind : PrimitiveKind::COUNT;
    const PrimitiveKind rtk =
        e->rhs ? e->rhs->result_type.kind : PrimitiveKind::COUNT;

    // Operator overloading via metodos dunder (C-1).  El type checker
    // dejo en @c e->overload_method el nombre del metodo (@c __add__ /
    // @c __eq__ / @c __ne__) cuando @c lhs es CLASS y declara el dunder.
    // Desugaramos @c `a OP b` a la llamada de metodo @c `a.__op__(b)`
    // construyendo un CallExpr sintetico y delegando en
    // @c lower_class_method_call (reusa CALLVIRT, marshalling y SRET).
    // Si el operador era @c `!=` sin @c __ne__ propio, negamos el BOOL
    // que devuelve @c __eq__.  Robamos los hijos @c lhs/@c rhs para el
    // call sintetico y los restauramos despues para no danar el AST.
    if (!e->overload_method.empty() && e->lhs && e->rhs) {
        // El receptor puede ser CLASS (dispatch via CALLVIRT) o STRUCT
        // (dispatch estatico via CALL directo).  Capturamos el kind
        // ANTES de mover @c e->lhs para elegir la ruta correcta.
        const bool recv_is_struct =
            (e->lhs->result_type.kind == PrimitiveKind::STRUCT);
        ast::CallExpr synth;
        synth.loc = e->loc;
        auto fa = std::make_unique<ast::FieldAccessExpr>();
        fa->loc = e->loc;
        fa->field_name = e->overload_method;
        // Propagar el result_type del receptor al FieldAccessExpr base
        // para que @c lower_struct_method_call lo use (resuelve el
        // struct layout via @c fa->base->result_type.struct_name).
        fa->base = std::move(e->lhs); // receptor (CLASS o STRUCT)
        synth.callee = std::move(fa);
        synth.args.push_back(std::move(e->rhs)); // unico argumento
        const bool negate = e->overload_negate;
        ir::IrValueId v_call = recv_is_struct ? lower_struct_method_call(&synth)
                                              : lower_class_method_call(&synth);
        // Restaurar los hijos al BinaryExpr original.
        auto *fa_back = static_cast<ast::FieldAccessExpr *>(synth.callee.get());
        e->lhs = std::move(fa_back->base);
        e->rhs = std::move(synth.args[0]);
        if (v_call == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        if (!negate) return v_call;
        // `a != b` sin __ne__ propio: niega el BOOL de __eq__ con
        // `cmp.eq result, 0` (= NOT logico).
        const ir::IrValueId zero = emit_const(ir::IrType::I64, 0, e->loc.line);
        const ir::IrValueId v_neg = emit_ir_binop(
            ir::IrOp::CMP_EQ, v_call, zero, ir::IrType::BOOL, e->loc.line);
        return v_neg;
    }

    // Bug fix 2026-05-23 (LR2): struct == struct via comparacion
    // field-a-field.  El type checker valida que ambos lados sean el
    // mismo struct nombrado.  Lowering emite: para cada campo, LOAD
    // del field en cada lado, CMP_EQ, AND acumulado.  Resultado BOOL.
    // Solo == y != (los otros operadores no aplican).
    /* Igualdad entre ENUMS: se comparan sus ETIQUETAS.
     *
     * Un enum comparte el kind con un struct, pero no esta en
     * `struct_layouts`, asi que caia por debajo de la comparacion campo a
     * campo y acababa en la generica -- que compara los PUNTEROS a sus
     * bufers y por tanto es SIEMPRE falsa.  El sintoma es feo porque el
     * `match` sobre el mismo valor SI acierta: `if (t == Tok.C)` daba falso
     * mientras `match t { case C => ... }` entraba.
     *
     * La etiqueta son ocho bytes al principio del bufer, igual que lee el
     * `match`. */
    if ((e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq) &&
        ltk == PrimitiveKind::STRUCT && rtk == PrimitiveKind::STRUCT &&
        e->lhs && e->rhs &&
        e->lhs->result_type.struct_name == e->rhs->result_type.struct_name &&
        !e->lhs->result_type.struct_name.empty() &&
        tc_.enum_layouts().count(e->lhs->result_type.struct_name) != 0) {
        const ir::IrValueId lhs_addr = lower_expr(e->lhs.get());
        const ir::IrValueId rhs_addr = lower_expr(e->rhs.get());
        if (lhs_addr == ir::IR_NO_VALUE || rhs_addr == ir::IR_NO_VALUE)
            return ir::IR_NO_VALUE;
        auto leer_tag = [&](ir::IrValueId dir) {
            ir::IrValueId t =
                emit_load_typed(dir, ir::IrType::I64, e->loc.line);
            return t;
        };
        const ir::IrValueId tl = leer_tag(lhs_addr);
        const ir::IrValueId tr = leer_tag(rhs_addr);
        const ir::IrValueId res = fn_->new_value(ir::IrType::BOOL);
        ir::IrInstr c{};
        c.op = (e->op == ast::BinOp::Eq) ? ir::IrOp::CMP_EQ : ir::IrOp::CMP_NE;
        c.type = ir::IrType::BOOL;
        c.dst = res;
        c.operands = {tl, tr};
        c.source_line = e->loc.line;
        emit(current_block_, std::move(c));
        return res;
    }
    if ((e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq) &&
        ltk == PrimitiveKind::STRUCT && rtk == PrimitiveKind::STRUCT &&
        e->lhs && e->rhs &&
        e->lhs->result_type.struct_name == e->rhs->result_type.struct_name &&
        !e->lhs->result_type.struct_name.empty()) {
        const auto &name = e->lhs->result_type.struct_name;
        auto it_sl = tc_.struct_layouts().find(name);
        if (it_sl != tc_.struct_layouts().end()) {
            const StructLayout &lay = it_sl->second;
            const ir::IrValueId lhs_addr = lower_expr(e->lhs.get());
            const ir::IrValueId rhs_addr = lower_expr(e->rhs.get());
            if (lhs_addr == ir::IR_NO_VALUE || rhs_addr == ir::IR_NO_VALUE)
                return ir::IR_NO_VALUE;
            // Comparar field por field.  Acumular result en v_acc (BOOL).
            ir::IrValueId v_acc = emit_const(ir::IrType::I64, 1, e->loc.line);
            // Set de offsets ya comparados (evita re-comparar bit field
            // packed words).
            std::set<uint32_t> compared_offsets;
            for (const auto &f : lay.fields) {
                if (f.bit_width > 0) {
                    // Bit field: comparamos el storage word completo
                    // (size_bytes en el offset) una sola vez por offset.
                    if (compared_offsets.count(f.offset)) continue;
                    compared_offsets.insert(f.offset);
                }
                const ir::IrType field_ir = ir_type_from_primitive(f.type.kind);
                // addr_lhs = lhs + offset
                ir::IrValueId v_off = emit_const(
                    ir::IrType::I64, (uint64_t)f.offset, e->loc.line);
                ir::IrValueId v_lhs_at =
                    emit_ptr_add(lhs_addr, v_off, e->loc.line);
                ir::IrValueId v_off2 = emit_const(
                    ir::IrType::I64, (uint64_t)f.offset, e->loc.line);
                ir::IrValueId v_rhs_at =
                    emit_ptr_add(rhs_addr, v_off2, e->loc.line);
                // LOAD a y b
                ir::IrValueId v_a =
                    emit_load_typed(v_lhs_at, field_ir, e->loc.line);
                ir::IrValueId v_b =
                    emit_load_typed(v_rhs_at, field_ir, e->loc.line);
                // cmp_eq a, b -> v_field_eq
                ir::IrValueId v_field_eq = emit_ir_binop(
                    ir::IrOp::CMP_EQ, v_a, v_b, ir::IrType::BOOL, e->loc.line);
                // v_acc = v_acc & v_field_eq
                ir::IrValueId v_new_acc =
                    emit_ir_binop(ir::IrOp::AND, v_acc, v_field_eq,
                                  ir::IrType::I64, e->loc.line);
                v_acc = v_new_acc;
            }
            // Para !=, negamos via XOR con 1.
            if (e->op == ast::BinOp::Neq) {
                ir::IrValueId v_one =
                    emit_const(ir::IrType::I64, 1, e->loc.line);
                ir::IrValueId v_neg = emit_ir_binop(
                    ir::IrOp::XOR, v_acc, v_one, ir::IrType::I64, e->loc.line);
                v_acc = v_neg;
            }
            return v_acc;
        }
    }

    // Short-circuit evaluation para `&&` y `||`.  Sin esto, ambos
    // operandos se evaluan siempre, lo que es incorrecto para patrones
    // como `i > 0 && this.data[i - 1] != 10` (con i==0, el rhs leeria
    // data[-1] y crashearia).  Ademas se evita evaluar efectos
    // colaterales innecesarios (CALLs en el rhs, dereferencias etc).
    //
    // Estrategia: usar PHI en el merge.  El predecesor del lhs aporta
    // el valor por defecto (false para &&, true para ||); el predecesor
    // del rhs aporta el valor del rhs.  Sin ALLOCA -- importante en
    // bucles, donde un ALLOCA en la condicion del while crearia un
    // ALLOCA por iteracion (stack growth ilimitado).
    if (e->op == ast::BinOp::LogicalAnd || e->op == ast::BinOp::LogicalOr) {
        const bool is_and = (e->op == ast::BinOp::LogicalAnd);
        // 1) Bajar lhs.  Si la propia lhs lleva un short-circuit anidado
        //    @c current_block_ ya no es el original; lo capturamos tras
        //    el lower_expr para anclar correctamente las aristas CFG.
        const ir::IrValueId v_lhs = lower_expr(e->lhs.get());
        if (v_lhs == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        const ir::IrBlockId lhs_end_bb = current_block_;
        const ir::IrBlockId rhs_bb =
            fn_->new_block(is_and ? "andsc_rhs" : "orsc_rhs");
        const ir::IrBlockId default_bb =
            fn_->new_block(is_and ? "andsc_def" : "orsc_def");
        const ir::IrBlockId merge_bb =
            fn_->new_block(is_and ? "andsc_merge" : "orsc_merge");
        // 2) BR_COND lhs:
        //   && : true -> rhs_bb (evaluar rhs); false -> default_bb (false)
        //   || : true -> default_bb (true);    false -> rhs_bb (evaluar rhs)
        // El salto sale de donde ACABO el lado izquierdo, que puede no ser el
        // bloque actual: bajarlo pudo abrir bloques por su cuenta.
        emit_br_cond_from(lhs_end_bb, v_lhs, is_and ? rhs_bb : default_bb,
                          is_and ? default_bb : rhs_bb, e->loc.line);
        // 3) Bloque default: emitir const por defecto y BR merge.
        current_block_ = default_bb;
        block_terminated_ = false;
        const ir::IrValueId v_default =
            emit_const(ir::IrType::BOOL, is_and ? 0u : 1u, e->loc.line);
        /* La arista se anotaba desde `default_bb`, que es el bloque actual aqui
         * -- entre la asignacion y este salto solo hay una constante --.  Que
         * salga del actual la hace inmune a que eso cambie: unas lineas mas
         * abajo, el propio codigo avisa de que bajar el rhs SI puede abrir
         * bloques intermedios. */
        emit_br(merge_bb, e->loc.line);
        const ir::IrBlockId default_pred = default_bb;
        // 4) Bloque rhs: bajar rhs (puede crear bloques intermedios si
        //    el rhs tiene su propio short-circuit), capturar el bloque
        //    final donde queda el resultado, y BR al merge desde ahi.
        current_block_ = rhs_bb;
        block_terminated_ = false;
        const ir::IrValueId v_rhs = lower_expr(e->rhs.get());
        if (v_rhs == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        const ir::IrValueId v_rhs_b = cast_if_needed(
            v_rhs, fn_->values[v_rhs].type, ir::IrType::BOOL, e->loc.line);
        const ir::IrBlockId rhs_pred = current_block_;
        if (!block_terminated_) {
            emit_br(merge_bb, e->loc.line);
        }
        // 5) Bloque merge: PHI(default desde default_pred, rhs desde rhs_pred).
        current_block_ = merge_bb;
        block_terminated_ = false;
        const ir::IrValueId v_res = fn_->new_value(ir::IrType::BOOL);
        ir::IrInstr phi{};
        phi.op = ir::IrOp::PHI;
        phi.type = ir::IrType::BOOL;
        phi.dst = v_res;
        phi.phi_args.push_back({v_default, default_pred});
        phi.phi_args.push_back({v_rhs_b, rhs_pred});
        phi.source_line = e->loc.line;
        emit(current_block_, std::move(phi));
        return v_res;
    }

    // Operadores nativos para STRING.
    //   s + t   -> strcat (ROPE O(1)).  Resultado tipo STRING.
    //   s == t  -> strcmp + cmp_eq con 0.  Resultado tipo BOOL.
    //   s != t  -> strcmp + cmp_ne con 0.  Resultado tipo BOOL.
    // Auto-coerce de literales: si un operando es un literal de string
    // (no interpolado, tipo PTR) y el otro es STRING, se promueve el
    // literal a StringObject via STRMAKE para no romper la regla de
    // "ambos operandos STRING" en el bytecode.
    auto coerce_string_operand = [&](ast::Expr *ex) -> ir::IrValueId {
        if (ex && ex->kind == ast::NodeKind::StringLitExpr) {
            // Literal de string (interpolado o no): construir el StringObject.
            // lower_string_literal_to_string_object maneja AMBOS casos (fast
            // path 1 STRMAKE para simples, STRMAKE+STRCAT para interpolados).
            // OJO: NO usar lower_expr aqui -- en modo GC, lower_string_lit de
            // un literal INTERPOLADO cae a STR_LIT_ADDR (bytes estaticos vacios
            // para `"${n}"`) en vez de construir la interpolacion.
            return lower_string_literal_to_string_object(
                static_cast<ast::StringLitExpr *>(ex));
        }
        return lower_expr(ex);
    };
    /* En el body de @Macro los StringLitExpr pueden no haber pasado
     * por check_string (que setea result_type=PTR).  Aceptamos
     * cualquier StringLitExpr como string -- solo importa el kind.
     * Los INTERPOLADOS tambien cuentan (`base + "${n}"`): coerce_string_operand
     * los baja via lower_expr (STRMAKE+STRCAT) a un handle STRING. */
    auto is_string_lit_node = [](const ast::Expr *ex) -> bool {
        return ex && ex->kind == ast::NodeKind::StringLitExpr;
    };
    /* Plegado de `"a" + "b"`: si TODO el arbol de `+` son literales, el valor
     * se conoce al compilar -> se emite UN literal, no una cadena de STRCAT.
     * Ninguno de los dos aporta nada en runtime, y el STRCAT ademas aloca.
     *
     * Recursivo para que `"a" + "b" + "c"` -- que es `((a+b)+c)` -- colapse
     * entero y no a medias.  Un literal INTERPOLADO no entra: su valor depende
     * de las expresiones de dentro. */
    {
        std::function<bool(const ast::Expr *, std::string &)> fold_str;
        fold_str = [&](const ast::Expr *ex, std::string &out) -> bool {
            if (!ex) return false;
            if (ex->kind == ast::NodeKind::StringLitExpr) {
                const auto *sl = static_cast<const ast::StringLitExpr *>(ex);
                if (sl->is_interpolated()) return false;
                out += sl->value;
                return true;
            }
            if (ex->kind != ast::NodeKind::BinaryExpr) return false;
            const auto *b = static_cast<const ast::BinaryExpr *>(ex);
            if (b->op != ast::BinOp::Add) return false;
            return fold_str(b->lhs.get(), out) && fold_str(b->rhs.get(), out);
        };
        if (e->op == ast::BinOp::Add) {
            std::string folded;
            if (fold_str(e, folded)) {
                ast::StringLitExpr lit;
                lit.loc = e->loc;
                lit.value = std::move(folded);
                return lower_string_literal_to_string_object(&lit);
            }
        }
    }
    /* En un cuerpo de @Macro los exprs tienen result_type=VOID (el macro no
     * pasa por check_functions), asi que una llamada a un builtin que DEVUELVE
     * string (`to_str`, `chr`, `substr`, `concat`, ...) no se reconoce como
     * STRING -> `s + to_str(n)` caia a suma ENTERA en vez de STRCAT.  Este
     * helper detecta esas llamadas por nombre para que el concat se lowere
     * correctamente tambien dentro de macros (necesario para VM-evaluarlos). */
    auto is_string_returning_builtin_call = [](const ast::Expr *ex) -> bool {
        if (!ex || ex->kind != ast::NodeKind::CallExpr) return false;
        const auto *ce = static_cast<const ast::CallExpr *>(ex);
        if (!ce->callee || ce->callee->kind != ast::NodeKind::IdentExpr)
            return false;
        const std::string &n =
            static_cast<const ast::IdentExpr *>(ce->callee.get())->name;
        static const std::unordered_set<std::string> STR_RET_BUILTINS = {
            "to_str",           "chr",
            "substr",           "concat",
            "repeat",           "replace",
            "str_concat",       "str_intern",
            "gensym",           "comptime_to_str",
            "comptime_concat",  "comptime_chr",
            "comptime_substr",  "comptime_repeat",
            "comptime_replace",
        };
        return STR_RET_BUILTINS.count(n) != 0;
    };
    const bool lhs_is_str =
        (ltk == PrimitiveKind::STRING) ||
        (is_string_lit_node(e->lhs.get()) &&
         (ltk == PrimitiveKind::PTR || ltk == PrimitiveKind::VOID)) ||
        is_string_returning_builtin_call(e->lhs.get());
    const bool rhs_is_str =
        (rtk == PrimitiveKind::STRING) ||
        (is_string_lit_node(e->rhs.get()) &&
         (rtk == PrimitiveKind::PTR || rtk == PrimitiveKind::VOID)) ||
        is_string_returning_builtin_call(e->rhs.get());
    // `"a" + "b"` (ambos literales): concat tambien (espejo del checker).
    const bool both_str_lit =
        is_string_lit_node(e->lhs.get()) && is_string_lit_node(e->rhs.get());
    const bool any_real_str = (ltk == PrimitiveKind::STRING) ||
                              (rtk == PrimitiveKind::STRING) || both_str_lit ||
                              is_string_returning_builtin_call(e->lhs.get()) ||
                              is_string_returning_builtin_call(e->rhs.get());
    if (lhs_is_str && rhs_is_str && any_real_str) {
        // C-3: si el usuario marco una fn libre @StringConcat / @StringEq,
        // rutear el operador a una CALL a esa fn (mecanismo override).
        // Aplica en native_poo_ y Full por igual.
        if (e->op == ast::BinOp::Add && !string_concat_override_.empty()) {
            return emit_string_override_call(
                string_concat_override_, e->lhs.get(), e->rhs.get(),
                ir::IrType::I64, /*negate=*/false, e->loc.line);
        }
        if ((e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq) &&
            !string_eq_override_.empty()) {
            return emit_string_override_call(
                string_eq_override_, e->lhs.get(), e->rhs.get(),
                ir::IrType::BOOL, /*negate=*/(e->op == ast::BinOp::Neq),
                e->loc.line);
        }
        // Vesta Embed Inc 1: en native_poo_ el `string` es value-type
        // {ptr,len,cap}; `a + b` produce un NUEVO string owned (buffer
        // fresco malloc + ambos contenidos copiados).  Los operandos
        // literales se materializan como slots value-string temporales;
        // como el concat copia los bytes, sus buffers son descartables y
        // se liberan inmediatamente (sin leak, sin doble-free porque no
        // se vuelven a usar).  El path Full/JIT (sin native_poo_) cae a
        // emit_strcat (StringObject GC) mas abajo.
        if (native_poo_ && e->op == ast::BinOp::Add) {
            // Construir slots nativos de ambos operandos.  Para
            // literales NO interpolados se construye un temporal; para
            // expresiones (var / concat anidado) lower_expr ya devuelve
            // un slot value-string.
            auto build_native_operand = [&](ast::Expr *ex,
                                            bool &is_temp) -> ir::IrValueId {
                if (ex && ex->kind == ast::NodeKind::StringLitExpr &&
                    !static_cast<ast::StringLitExpr *>(ex)->is_interpolated()) {
                    is_temp = true;
                    return build_native_string_from_literal(
                        static_cast<ast::StringLitExpr *>(ex), e->loc.line);
                }
                // Concat anidado (`a + b + c`): un operando que es a su vez un
                // `+` de strings produjo un buffer owned SIN RAII (resultado de
                // expresion, no ligado a variable) -> es TEMPORAL: hay que
                // liberarlo tras copiar sus bytes.  Sin esto, el intermedio
                // (a+b) fuga.  Los IdentExpr (variables) NO se marcan temp: su
                // RAII los libera al exit del scope dueno (no doble-free).
                if (ex && ex->kind == ast::NodeKind::BinaryExpr &&
                    static_cast<ast::BinaryExpr *>(ex)->op == ast::BinOp::Add &&
                    ex->result_type.kind == PrimitiveKind::STRING) {
                    is_temp = true;
                    return lower_expr(ex);
                }
                // Cast (string)<char>: produce un slot value-string owned
                // SIN RAII (resultado de expresion).  Es TEMPORAL: hay que
                // liberar su buffer tras copiar los bytes.  Sin esto el
                // buffer del cast fuga.
                if (ex && ex->kind == ast::NodeKind::CastExpr &&
                    ex->result_type.kind == PrimitiveKind::STRING) {
                    is_temp = true;
                    return lower_expr(ex);
                }
                is_temp = false;
                return lower_expr(ex);
            };
            bool a_temp = false, b_temp = false;
            ir::IrValueId v_na = build_native_operand(e->lhs.get(), a_temp);
            ir::IrValueId v_nb = build_native_operand(e->rhs.get(), b_temp);
            if (v_na == ir::IR_NO_VALUE || v_nb == ir::IR_NO_VALUE)
                return ir::IR_NO_VALUE;
            ir::IrValueId v_res =
                build_native_string_concat(v_na, v_nb, e->loc.line);
            // Liberar los buffers de los operandos temporales (sus bytes
            // ya estan copiados en el resultado).  Inc 5 (SSO): solo
            // libera si el operando estaba en HEAP.  Los operandos que son
            // slots de variables NO se liberan aqui (su RAII manda).
            if (a_temp) emit_native_str_free_if_heap(v_na, e->loc.line);
            if (b_temp) emit_native_str_free_if_heap(v_nb, e->loc.line);
            return v_res;
        }
        // Vesta Embed Inc 4: comparacion native de strings value-type via
        // helper __vx_strcmp (lexicografica, -1/0/1).  Cubre == != < > <= >=.
        // El resultado del strcmp se mapea a BOOL con la comparacion entera
        // correspondiente.
        if (native_poo_ &&
            (e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq ||
             e->op == ast::BinOp::Lt || e->op == ast::BinOp::Gt ||
             e->op == ast::BinOp::Le || e->op == ast::BinOp::Ge)) {
            // Obtener (ptr, len) de cada operando SIN materializar el literal
            // en heap.  Para un literal no interpolado: el contenido es
            // conocido en compile-time -> lo internamos en .rodata
            // (static_data) y emitimos STR_LIT_ADDR (host_ptr a .rodata) +
            // CONST len.  Cero malloc / free / STOREs (mucho mas barato que
            // un value-string temporal y, ademas, evita acumular varios
            // RAW_ALLOC/RAW_FREE en un mismo bloque cuando AMBOS operandos
            // son literales).  Para var / concat / cast: lower al slot
            // value-string y cargar ptr@0 / len@8; concat y cast son
            // resultados de expresion (temporales) cuyo buffer se libera
            // tras comparar.  Las variables NO se liberan (su RAII las
            // libera al exit del scope).  Devuelve true si el operando
            // produjo un slot value-string temporal a liberar.
            struct OperandRef {
                ir::IrValueId ptr = ir::IR_NO_VALUE;
                ir::IrValueId len = ir::IR_NO_VALUE;
                ir::IrValueId temp_slot = ir::IR_NO_VALUE; // !=NO_VALUE -> free
            };
            auto get_operand = [&](ast::Expr *ex) -> OperandRef {
                OperandRef r;
                // Literal no interpolado -> .rodata + CONST len.
                if (ex && ex->kind == ast::NodeKind::StringLitExpr &&
                    !static_cast<ast::StringLitExpr *>(ex)->is_interpolated()) {
                    auto *slit = static_cast<ast::StringLitExpr *>(ex);
                    const std::string &lit = slit->value;
                    std::vector<uint8_t> data(lit.begin(), lit.end());
                    // Nul final por seguridad (el strcmp usa solo len bytes,
                    // pero deja el literal NUL-terminated por si otro uso lo
                    // toma).
                    data.push_back(0);
                    const uint64_t idx =
                        out_mod_->intern_static_data(std::move(data));
                    r.ptr = fn_->new_value(ir::IrType::PTR);
                    fn_->values[r.ptr].is_host_ptr = true;
                    ir::IrInstr sa{};
                    sa.op = ir::IrOp::STR_LIT_ADDR;
                    sa.type = ir::IrType::PTR;
                    sa.dst = r.ptr;
                    sa.imm = idx;
                    sa.source_line = e->loc.line;
                    emit(current_block_, std::move(sa));
                    r.len = emit_const(ir::IrType::I64,
                                       static_cast<uint64_t>(lit.size()),
                                       e->loc.line);
                    return r;
                }
                // concat / cast -> resultado temporal (buffer a liberar).
                bool is_temp = false;
                if (ex && ex->kind == ast::NodeKind::BinaryExpr &&
                    static_cast<ast::BinaryExpr *>(ex)->op == ast::BinOp::Add &&
                    ex->result_type.kind == PrimitiveKind::STRING)
                    is_temp = true;
                else if (ex && ex->kind == ast::NodeKind::CastExpr &&
                         ex->result_type.kind == PrimitiveKind::STRING)
                    is_temp = true;
                ir::IrValueId v_slot = lower_expr(ex);
                if (v_slot == ir::IR_NO_VALUE) return r; // error -> r vacio
                // Inc 5 (SSO): (ptr, len) via accesores flag-aware.
                r.ptr = emit_native_str_data_ptr(v_slot, e->loc.line);
                r.len = emit_native_str_len(v_slot, e->loc.line);
                if (is_temp) r.temp_slot = v_slot;
                return r;
            };
            OperandRef ra = get_operand(e->lhs.get());
            OperandRef rb = get_operand(e->rhs.get());
            if (ra.ptr == ir::IR_NO_VALUE || rb.ptr == ir::IR_NO_VALUE)
                return ir::IR_NO_VALUE;
            // CPU dispatch Inc 5a: strcmp(pa, la, pb, lb) -> i64 (-1/0/1)
            // DESPACHADO por tabla de punteros: `call [__vx_strcmp_fp]`.  El
            // fp apunta al baseline o al @HelperOverride(strcmp) del usuario.
            const ir::IrValueId v_cmp = emit_strcmp_dispatched(
                ra.ptr, ra.len, rb.ptr, rb.len, e->loc.line);
            // Liberar buffers de operandos temporales (concat / cast).  El
            // CALL ya leyo sus bytes -> sin uso posterior, sin leak.  Inc 5
            // (SSO): solo libera si estaba en HEAP.  Los literales (.rodata)
            // NO se liberan; las variables tampoco (su RAII manda).
            auto free_temp = [&](ir::IrValueId v_slot) {
                if (v_slot == ir::IR_NO_VALUE) return;
                emit_native_str_free_if_heap(v_slot, e->loc.line);
            };
            free_temp(ra.temp_slot);
            free_temp(rb.temp_slot);
            // Mapear strcmp(-1/0/1) a BOOL:
            //   ==  -> cmp == 0    !=  -> cmp != 0
            //   <   -> cmp < 0     >   -> cmp > 0
            //   <=  -> cmp <= 0    >=  -> cmp >= 0
            ir::IrOp map_op;
            switch (e->op) {
            case ast::BinOp::Eq: map_op = ir::IrOp::CMP_EQ; break;
            case ast::BinOp::Neq: map_op = ir::IrOp::CMP_NE; break;
            case ast::BinOp::Lt: map_op = ir::IrOp::CMP_LT; break;
            case ast::BinOp::Gt: map_op = ir::IrOp::CMP_GT; break;
            case ast::BinOp::Le: map_op = ir::IrOp::CMP_LE; break;
            default: map_op = ir::IrOp::CMP_GE; break; // Ge
            }
            ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, e->loc.line);
            ir::IrValueId v_bool = fn_->new_value(ir::IrType::BOOL);
            ir::IrInstr cm{};
            cm.op = map_op;
            cm.type = ir::IrType::BOOL;
            cm.dst = v_bool;
            cm.operands = {v_cmp, v_zero};
            cm.source_line = e->loc.line;
            emit(current_block_, std::move(cm));
            return v_bool;
        }
        ir::IrValueId v_a = coerce_string_operand(e->lhs.get());
        ir::IrValueId v_b = coerce_string_operand(e->rhs.get());
        if (v_a == ir::IR_NO_VALUE || v_b == ir::IR_NO_VALUE)
            return ir::IR_NO_VALUE;
        if (e->op == ast::BinOp::Add) {
            // strcat -> rope handle (i64 STRING).
            return emit_strcat(v_a, v_b, e->loc.line);
        }
        // Full/JIT: == != < > <= >= via STRCMP (-1/0/1, lexicografico).
        if (e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq ||
            e->op == ast::BinOp::Lt || e->op == ast::BinOp::Gt ||
            e->op == ast::BinOp::Le || e->op == ast::BinOp::Ge) {
            ir::IrValueId v_cmp = emit_ir_binop(ir::IrOp::STRCMP, v_a, v_b,
                                                ir::IrType::I64, e->loc.line);
            ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, e->loc.line);
            ir::IrValueId v_bool = fn_->new_value(ir::IrType::BOOL);
            ir::IrOp map_op;
            switch (e->op) {
            case ast::BinOp::Eq: map_op = ir::IrOp::CMP_EQ; break;
            case ast::BinOp::Neq: map_op = ir::IrOp::CMP_NE; break;
            case ast::BinOp::Lt: map_op = ir::IrOp::CMP_LT; break;
            case ast::BinOp::Gt: map_op = ir::IrOp::CMP_GT; break;
            case ast::BinOp::Le: map_op = ir::IrOp::CMP_LE; break;
            default: map_op = ir::IrOp::CMP_GE; break; // Ge
            }
            ir::IrInstr cmp{};
            cmp.op = map_op;
            cmp.type = ir::IrType::BOOL;
            cmp.dst = v_bool;
            cmp.operands = {v_cmp, v_zero};
            cmp.source_line = e->loc.line;
            emit(current_block_, std::move(cmp));
            return v_bool;
        }
        error_at(e->loc, "operador no soportado entre strings");
        return ir::IR_NO_VALUE;
    }

    // Aritmetica puntero (PTR + int, PTR - int, PTR - PTR).  El type
    // checker ya valido las combinaciones; aqui escalamos el offset
    // por sizeof(*ptr) y emitimos ADD/SUB.  Aceptamos tambien ARRAY
    // como base para soportar `arr + n` (decay implicito).
    if ((e->op == ast::BinOp::Add || e->op == ast::BinOp::Sub) &&
        (ltk == PrimitiveKind::PTR || ltk == PrimitiveKind::ARRAY) &&
        is_integral(rtk)) {
        const Type pty = e->lhs->result_type;
        if (!pty.pointee) {
            error_at(e->loc, "lowering: aritmetica de puntero sin pointee");
            return ir::IR_NO_VALUE;
        }
        const size_t esz = size_of_type(*pty.pointee);
        if (esz == 0) {
            error_at(e->loc,
                     "lowering: aritmetica sobre void* o pointee con sizeof 0");
            return ir::IR_NO_VALUE;
        }
        ir::IrValueId base_v = lower_expr(e->lhs.get());
        ir::IrValueId idx_v = lower_expr(e->rhs.get());
        if (base_v == ir::IR_NO_VALUE || idx_v == ir::IR_NO_VALUE)
            return ir::IR_NO_VALUE;
        idx_v = cast_if_needed(idx_v, fn_->values[idx_v].type, ir::IrType::I64,
                               e->loc.line);
        ir::IrValueId offset = idx_v;
        if (esz != 1) {
            const ir::IrValueId sz_v =
                emit_const(ir::IrType::I64, (uint64_t)esz, e->loc.line);
            const ir::IrValueId scaled = emit_ir_binop(
                ir::IrOp::MUL, idx_v, sz_v, ir::IrType::I64, e->loc.line);
            offset = scaled;
        }
        const ir::IrValueId dst = fn_->new_value(ir::IrType::PTR);
        // Propagar el flag is_host_ptr desde el puntero base.  El
        // resultado de la aritmetica sigue apuntando al mismo espacio
        // (host o VM) que el operando original.
        fn_->values[dst].is_host_ptr = fn_->values[base_v].is_host_ptr;
        ir::IrInstr ins{};
        ins.op = (e->op == ast::BinOp::Add) ? ir::IrOp::ADD : ir::IrOp::SUB;
        ins.type = ir::IrType::PTR;
        ins.dst = dst;
        ins.operands = {base_v, offset};
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        return dst;
    }

    // PTR - PTR -> i64 (numero de elementos).  Calcula (a - b) / sizeof(*p).
    if (e->op == ast::BinOp::Sub && ltk == PrimitiveKind::PTR &&
        rtk == PrimitiveKind::PTR) {
        const Type pty = e->lhs->result_type;
        const size_t esz = (pty.pointee ? size_of_type(*pty.pointee) : 0);
        if (esz == 0) {
            error_at(e->loc, "lowering: p - q requiere pointee con sizeof > 0");
            return ir::IR_NO_VALUE;
        }
        const ir::IrValueId la = lower_expr(e->lhs.get());
        const ir::IrValueId lb = lower_expr(e->rhs.get());
        if (la == ir::IR_NO_VALUE || lb == ir::IR_NO_VALUE)
            return ir::IR_NO_VALUE;
        const ir::IrValueId diff =
            emit_ir_binop(ir::IrOp::SUB, la, lb, ir::IrType::I64, e->loc.line);
        if (esz == 1) return diff;
        const ir::IrValueId sz_v =
            emit_const(ir::IrType::I64, (uint64_t)esz, e->loc.line);
        const ir::IrValueId q = emit_ir_binop(ir::IrOp::DIV, diff, sz_v,
                                              ir::IrType::I64, e->loc.line);
        return q;
    }

    // Comparaciones de PTR vs PTR: tratamos como uint64 sin promocion.
    const bool is_ptr_cmp =
        (ltk == PrimitiveKind::PTR && rtk == PrimitiveKind::PTR) &&
        (e->op == ast::BinOp::Eq || e->op == ast::BinOp::Neq ||
         e->op == ast::BinOp::Lt || e->op == ast::BinOp::Le ||
         e->op == ast::BinOp::Gt || e->op == ast::BinOp::Ge);

    ir::IrValueId l = lower_expr(e->lhs.get());
    ir::IrValueId r = lower_expr(e->rhs.get());
    if (l == ir::IR_NO_VALUE || r == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    if (is_ptr_cmp) {
        // Saltar la promocion numerica y emitir directamente CMP_*
        // (variantes unsigned para comparaciones de orden).
        ir::IrOp op = ir::IrOp::CMP_EQ;
        switch (e->op) {
        case ast::BinOp::Eq: op = ir::IrOp::CMP_EQ; break;
        case ast::BinOp::Neq: op = ir::IrOp::CMP_NE; break;
        case ast::BinOp::Lt: op = ir::IrOp::CMP_ULT; break;
        case ast::BinOp::Le: op = ir::IrOp::CMP_ULE; break;
        case ast::BinOp::Gt: op = ir::IrOp::CMP_UGT; break;
        case ast::BinOp::Ge: op = ir::IrOp::CMP_UGE; break;
        default: break;
        }
        const ir::IrValueId dst = fn_->new_value(ir::IrType::BOOL);
        ir::IrInstr ins{};
        ins.op = op;
        ins.type = ir::IrType::BOOL;
        ins.dst = dst;
        ins.operands = {l, r};
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        return dst;
    }

    // Para operadores aritmeticos / bitwise / comparacion: promovemos
    // ambos operandos al tipo comun.  CHAR se trata como U8 (byte sin
    // signo) para la aritmetica estilo C: `'a' + 'b'` baja como suma
    // u8 (mismo ancho IR, zero-extend al castear a tipos mas anchos).
    const PrimitiveKind ltk_a = char_as_u8(ltk);
    const PrimitiveKind rtk_a = char_as_u8(rtk);
    const PrimitiveKind common =
        (ltk == PrimitiveKind::BOOL && rtk == PrimitiveKind::BOOL)
            ? PrimitiveKind::BOOL
            : promote_arith(ltk_a, rtk_a);
    const ir::IrType common_ir = ir_type_from_primitive(common);
    const bool is_float = is_floating(common);
    const bool is_unsign = is_integral(common) && !is_signed_integral(common);

    l = cast_if_needed(l, ir_type_from_primitive(ltk), common_ir, e->loc.line);
    r = cast_if_needed(r, ir_type_from_primitive(rtk), common_ir, e->loc.line);

    // Seleccionar opcode segun categoria.
    ir::IrOp op = ir::IrOp::ADD;
    ir::IrType result_ir = common_ir;
    switch (e->op) {
    case ast::BinOp::Add: op = is_float ? ir::IrOp::FADD : ir::IrOp::ADD; break;
    case ast::BinOp::Sub: op = is_float ? ir::IrOp::FSUB : ir::IrOp::SUB; break;
    case ast::BinOp::Mul: op = is_float ? ir::IrOp::FMUL : ir::IrOp::MUL; break;
    case ast::BinOp::Div: op = is_float ? ir::IrOp::FDIV : ir::IrOp::DIV; break;
    case ast::BinOp::Mod: op = ir::IrOp::MOD; break;

    case ast::BinOp::Eq:
        op = is_float ? ir::IrOp::FCMP_EQ : ir::IrOp::CMP_EQ;
        result_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Neq:
        op = is_float ? ir::IrOp::FCMP_NE : ir::IrOp::CMP_NE;
        result_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Lt:
        op = is_float ? ir::IrOp::FCMP_LT
                      : (is_unsign ? ir::IrOp::CMP_ULT : ir::IrOp::CMP_LT);
        result_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Le:
        op = is_float ? ir::IrOp::FCMP_LE
                      : (is_unsign ? ir::IrOp::CMP_ULE : ir::IrOp::CMP_LE);
        result_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Gt:
        op = is_float ? ir::IrOp::FCMP_GT
                      : (is_unsign ? ir::IrOp::CMP_UGT : ir::IrOp::CMP_GT);
        result_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Ge:
        op = is_float ? ir::IrOp::FCMP_GE
                      : (is_unsign ? ir::IrOp::CMP_UGE : ir::IrOp::CMP_GE);
        result_ir = ir::IrType::BOOL;
        break;

    case ast::BinOp::LogicalAnd:
        op = ir::IrOp::AND;
        result_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::LogicalOr:
        op = ir::IrOp::OR;
        result_ir = ir::IrType::BOOL;
        break;

    case ast::BinOp::BitAnd: op = ir::IrOp::AND; break;
    case ast::BinOp::BitOr: op = ir::IrOp::OR; break;
    case ast::BinOp::BitXor: op = ir::IrOp::XOR; break;
    case ast::BinOp::Shl: op = ir::IrOp::SHL; break;
    case ast::BinOp::Shr: {
        // El shift a la derecha es aritmetico (SAR) sii el LHS (el valor
        // desplazado) es SIGNED -- NO el tipo comun.  El RHS es solo el
        // contador de bits y no debe influir en la signedness (semantica C).
        // Sin esto, `i64 >> u64` promocionaba a u64 y hacia shift logico (bug:
        // perdia el signo).
        const bool lhs_unsign = is_integral(ltk) && !is_signed_integral(ltk);
        op = lhs_unsign ? ir::IrOp::SHR : ir::IrOp::SAR;
        break;
    }
    }

    const ir::IrValueId dst = fn_->new_value(result_ir);
    ir::IrInstr ins{};
    ins.op = op;
    ins.type = result_ir;
    ins.dst = dst;
    ins.operands = {l, r};
    ins.source_line = e->loc.line;
    emit(current_block_, std::move(ins));
    return dst;
}

ir::IrValueId Lowering::lower_unary(ast::UnaryExpr *e) {
    // Operator overloading C-2: `-x` -> x.__neg__() cuando el type
    // checker marco @c e->overload_method.  El receptor puede ser CLASS
    // (CALLVIRT) o STRUCT (CALL directo).  Construimos un CallExpr
    // sintetico `operand.__neg__()` (sin args) y delegamos en la
    // maquinaria de metodos.  Robamos el hijo @c operand para el call y
    // lo restauramos despues para no danar el AST.
    if (!e->overload_method.empty() && e->operand) {
        const bool recv_is_struct =
            (e->operand->result_type.kind == PrimitiveKind::STRUCT);
        ast::CallExpr synth;
        synth.loc = e->loc;
        auto fa = std::make_unique<ast::FieldAccessExpr>();
        fa->loc = e->loc;
        fa->field_name = e->overload_method;
        fa->base = std::move(e->operand); // receptor (CLASS o STRUCT)
        synth.callee = std::move(fa);
        // Sin argumentos: __neg__ es unario sobre el receptor.
        ir::IrValueId v_call = recv_is_struct ? lower_struct_method_call(&synth)
                                              : lower_class_method_call(&synth);
        // Restaurar el hijo al UnaryExpr original.
        auto *fa_back = static_cast<ast::FieldAccessExpr *>(synth.callee.get());
        e->operand = std::move(fa_back->base);
        return v_call;
    }

    // Caso especial: ++/-- requieren leer la variable, sumar/restar 1
    // y reescribir el valor.  Para variables address-taken pasamos por
    // LOAD/STORE; para SSA puro hacemos update_scope (Braun on-the-fly).
    if (e->op == ast::UnOp::PreInc || e->op == ast::UnOp::PreDec ||
        e->op == ast::UnOp::PostInc || e->op == ast::UnOp::PostDec) {
        if (!e->operand) {
            error_at(e->loc, "lowering: ++/-- sin operando");
            return ir::IR_NO_VALUE;
        }
        const ir::IrType vt =
            ir_type_from_primitive(e->operand->result_type.kind);
        const bool is_inc =
            (e->op == ast::UnOp::PreInc || e->op == ast::UnOp::PostInc);
        const bool is_pre =
            (e->op == ast::UnOp::PreInc || e->op == ast::UnOp::PreDec);
        // Tipo que SOBRECARGA la suma (`c++` es `c += 1`): tiene que salir por
        // aqui, ANTES de las rutas enteras.  El valor SSA de un struct es su
        // DIRECCION, asi que la ruta entera le sumaba 1 a la direccion del
        // objeto (medido: `addu r3, r2`) y luego leia basura.
        const PrimitiveKind opk = e->operand->result_type.kind;
        if (opk == PrimitiveKind::CLASS || opk == PrimitiveKind::STRUCT) {
            return lower_overloaded_step(e, is_inc, is_pre);
        }
        auto compute_new = [&](ir::IrValueId old_val) -> ir::IrValueId {
            const ir::IrValueId one = emit_const(vt, 1, e->loc.line);
            const ir::IrValueId nv = fn_->new_value(vt);
            ir::IrInstr o{};
            o.op = is_inc ? ir::IrOp::ADD : ir::IrOp::SUB;
            o.type = vt;
            o.dst = nv;
            o.operands = {old_val, one};
            o.source_line = e->loc.line;
            emit(current_block_, std::move(o));
            return nv;
        };
        // IdentExpr: si es un LOCAL del scope, ruta SSA original via
        // read_local/write_local (Braun on-the-fly, sin ALLOCA).
        if (e->operand->kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<ast::IdentExpr *>(e->operand.get());
            const ir::IrValueId old_val = read_local(id->name, vt, e->loc.line);
            if (old_val != ir::IR_NO_VALUE) {
                const ir::IrValueId new_val = compute_new(old_val);
                write_local(id->name, new_val, vt, e->loc.line);
                return is_pre ? new_val : old_val;
            }
            // No es un local del scope (p.ej. una variable GLOBAL runtime o
            // un comptime global dentro de un @Macro): delegamos en
            // lower_assign con un compound sintetico (`x += 1` / `x -= 1`)
            // para REUTILIZAR exactamente la misma resolucion de lvalue que
            // la asignacion compuesta (que resuelve runtime_global_slots_ y
            // comptime globals via STR_LIT_ADDR + LOAD + combine + STORE).
            // Para el postfijo capturamos el valor previo ANTES del store
            // via lower_ident, que tambien sabe resolver globales.
            ir::IrValueId prev = ir::IR_NO_VALUE;
            if (!is_pre) prev = lower_ident(id);
            auto tgt = std::make_unique<ast::IdentExpr>();
            tgt->name = id->name;
            tgt->result_type = id->result_type;
            tgt->loc = id->loc;
            auto one = std::make_unique<ast::IntLitExpr>();
            one->value = 1;
            one->result_type = e->operand->result_type;
            one->loc = e->loc;
            ast::AssignExpr asn;
            asn.op =
                is_inc ? ast::AssignOp::AddAssign : ast::AssignOp::SubAssign;
            asn.loc = e->loc;
            asn.result_type = id->result_type;
            asn.target = std::move(tgt);
            asn.value = std::move(one);
            const ir::IrValueId new_val = lower_assign(&asn);
            if (new_val == ir::IR_NO_VALUE) {
                error_at(e->loc,
                         "lowering: nombre no resuelto: '" + id->name + "'");
                return ir::IR_NO_VALUE;
            }
            return is_pre ? new_val : prev;
        }
        // bug4: FieldAccessExpr (this.x++, obj.x++) sobre struct field.
        // Class fields se manejan separadamente (CLASS property o getfield).
        if (e->operand->kind == ast::NodeKind::FieldAccessExpr) {
            auto *fa = static_cast<ast::FieldAccessExpr *>(e->operand.get());
            // LOAD valor actual via lower_field_access (genera ADD off + LOAD).
            const ir::IrValueId old_val = lower_field_access(fa);
            if (old_val == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            const ir::IrValueId new_val = compute_new(old_val);
            // STORE new_val a la misma direccion via assign synthetic.
            // Construir un AssignExpr ad-hoc para reusar lower_assign.
            ast::AssignExpr asn;
            asn.op = ast::AssignOp::Assign;
            asn.loc = e->loc;
            // No podemos mover el operand; pero podemos usar el ptr
            // directamente.  Mejor: emit STORE manual al field addr.
            if (fa->base &&
                fa->base->result_type.kind == PrimitiveKind::STRUCT) {
                const ir::IrValueId addr = lower_field_addr(fa);
                if (addr == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
                emit_store_typed(addr, new_val, vt, e->loc.line);
                return is_pre ? new_val : old_val;
            }
            /* Campo ESTATICO (`Clase.campo++`): la base no es una instancia
             * sino el NOMBRE de la clase, asi que no tiene tipo struct ni
             * clase y caia al error.  Escribirlo ya se sabia hacer -- es el
             * mismo camino que `Clase.campo = v`, que mira @c property_kind. */
            if (fa->property_kind == 3) {
                lower_class_field_store(fa, new_val, e->loc);
                return is_pre ? new_val : old_val;
            }
            // CLASS field: usar setfield via lower_class_field_store.
            if (fa->base &&
                fa->base->result_type.kind == PrimitiveKind::CLASS) {
                lower_class_field_store(fa, new_val, e->loc);
                return is_pre ? new_val : old_val;
            }
            error_at(
                e->loc,
                "lowering: ++/-- sobre field no soportado en este contexto");
            return ir::IR_NO_VALUE;
        }
        // IndexExpr (arr[i]++).
        if (e->operand->kind == ast::NodeKind::IndexExpr) {
            auto *ix = static_cast<ast::IndexExpr *>(e->operand.get());
            const ir::IrValueId addr = lower_index_addr(ix);
            if (addr == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            // LOAD valor actual.
            const ir::IrValueId old_val =
                emit_load_typed(addr, vt, e->loc.line);
            const ir::IrValueId new_val = compute_new(old_val);
            emit_store_typed(addr, new_val, vt, e->loc.line);
            return is_pre ? new_val : old_val;
        }
        // UnaryExpr Deref (*p++).
        if (e->operand->kind == ast::NodeKind::UnaryExpr) {
            auto *un = static_cast<ast::UnaryExpr *>(e->operand.get());
            if (un->op == ast::UnOp::Deref) {
                const ir::IrValueId addr = lower_expr(un->operand.get());
                if (addr == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
                const ir::IrValueId old_val =
                    emit_load_typed(addr, vt, e->loc.line);
                const ir::IrValueId new_val = compute_new(old_val);
                emit_store_typed(addr, new_val, vt, e->loc.line);
                return is_pre ? new_val : old_val;
            }
        }
        error_at(e->loc, "lowering: ++/-- requieren un lvalue");
        return ir::IR_NO_VALUE;
    }

    // AddrOf: devolver la direccion del lvalue.
    if (e->op == ast::UnOp::AddrOf) {
        if (!e->operand) {
            error_at(e->loc, "lowering: '&' sin operando");
            return ir::IR_NO_VALUE;
        }
        // &var.metodo (puntero a metodo LIGADO, Fase 2): el type checker lo
        // desugaro a un lambda `(args) => var.metodo(args)` que captura el
        // receptor.  Bajamos ESE lambda (reusa env owned + CALLCLOSURE).
        if (e->desugared_bound_method) {
            // Base COMPUESTA (`&getObj().m`): evaluar el receptor UNA vez y
            // ligarlo al temporal oculto que el lambda captura por nombre.
            // Asi getObj() no se re-evalua en cada llamada y se captura el
            // objeto/struct correcto.
            if (e->bound_recv_init && !e->bound_recv_name.empty()) {
                const ir::IrValueId rv = lower_expr(e->bound_recv_init.get());
                if (rv == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
                bind(e->bound_recv_name, rv);
            }
            return lower_expr(e->desugared_bound_method.get());
        }
        // &Tipo.metodo -> LABEL_ADDR del label de la free fn `Tipo__metodo`
        // (puntero a metodo no ligado, cfn).  El checker dejo el label en
        // FieldAccessExpr::func_ref_mangled.
        if (e->operand->kind == ast::NodeKind::FieldAccessExpr) {
            auto *fa = static_cast<ast::FieldAccessExpr *>(e->operand.get());
            if (fa->is_func_ref && !fa->func_ref_mangled.empty()) {
                const ir::IrValueId dst = fn_->new_value(ir::IrType::PTR);
                ir::IrInstr ins{};
                ins.op = ir::IrOp::LABEL_ADDR;
                ins.type = ir::IrType::PTR;
                ins.dst = dst;
                ins.func_name = fa->func_ref_mangled;
                ins.source_line = e->loc.line;
                emit(current_block_, std::move(ins));
                return dst;
            }
        }
        // & sobre IdentExpr local address-taken: scope guarda la addr.
        if (e->operand->kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<ast::IdentExpr *>(e->operand.get());
            // &funcion -> LABEL_ADDR (direccion cruda del codigo) = un cfn.
            // El type checker tipo el resultado como cfn(sig); aqui producimos
            // la direccion (8 bytes), igual que el cast `(cfn(...)) nombre`.
            if (id->is_func_ref) {
                const ir::IrValueId dst = fn_->new_value(ir::IrType::PTR);
                ir::IrInstr ins{};
                ins.op = ir::IrOp::LABEL_ADDR;
                ins.type = ir::IrType::PTR;
                ins.dst = dst;
                ins.func_name = func_ref_label(id->name, id->func_ref_mangled);
                ins.source_line = e->loc.line;
                emit(current_block_, std::move(ins));
                return dst;
            }
            // & sobre un `static` local: su storage vive en gdata (slot
            // mangleado por funcion, memoria host).  La direccion es
            // STR_LIT_ADDR del slot -- identica a la que emite la lectura, que
            // solo le anñade el LOAD.  Va ANTES del global runtime y del scope
            // local: un `static` sombrea cualquier binding del mismo nombre,
            // igual que en el path de lectura.  Sin esto, `&s` sobre un static
            // caia a `lookup` (que no lo conoce) y moria con "nombre no
            // resuelto".
            {
                auto sit = static_local_slots_.find(id->name);
                if (sit != static_local_slots_.end()) {
                    const ir::IrValueId va =
                        emit_str_lit_addr(sit->second.slot, e->loc.line);
                    // El slot vive en memoria host (gdata en interp/JIT,
                    // `.data` en AOT): la direccion sobrevive a viajar por
                    // memoria.
                    fn_->values[va].is_host_ptr = true;
                    return va;
                }
            }
            // & sobre un GLOBAL runtime (incluido un thread_local): su
            // direccion es STR_LIT_ADDR del slot static_data.  El driver AOT
            // deriva la TLS-ness desde SD_FLAG_TLS y emite el acceso por thread
            // pointer; para un global normal es la direccion lineal.
            auto git = runtime_global_slots_.find(id->name);
            if (git != runtime_global_slots_.end()) {
                const ir::IrValueId va =
                    emit_str_lit_addr(git->second, e->loc.line);
                // `&global` es un `T*`: el storage vive en memoria host (en
                // `.data` en AOT; en el bloque host de la seccion `gdata` en
                // interp/JIT).  Asi la direccion sobrevive a viajar por memoria
                // -- a un campo, a un parametro, a la FFI, a un `lock cmpxchg`.
                fn_->values[va].is_host_ptr = true;
                return va;
            }
            const ir::IrValueId addr = lookup(id->name);
            if (addr == ir::IR_NO_VALUE) {
                error_at(e->loc,
                         "lowering: nombre no resuelto: '" + id->name + "'");
                return ir::IR_NO_VALUE;
            }
            if (!address_taken_locals_.count(id->name) &&
                e->operand->result_type.kind != PrimitiveKind::STRUCT) {
                // Defensa: el pre-pase deberia haber marcado esta var,
                // pero si por alguna razon no lo hizo, emitir error
                // claro en lugar de devolver una SSA value como addr.
                error_at(e->loc, "lowering: '&" + id->name +
                                     "' sobre variable no promocionada");
                return ir::IR_NO_VALUE;
            }
            return addr;
        }
        // & sobre p.x: la direccion del campo es lower_field_addr.
        if (e->operand->kind == ast::NodeKind::FieldAccessExpr) {
            return lower_field_addr(
                static_cast<ast::FieldAccessExpr *>(e->operand.get()));
        }
        // & sobre p[i]: la direccion del elemento es lower_index_addr.
        if (e->operand->kind == ast::NodeKind::IndexExpr) {
            return lower_index_addr(
                static_cast<ast::IndexExpr *>(e->operand.get()));
        }
        // & sobre *p (idempotente): devolvemos el propio puntero.
        if (e->operand->kind == ast::NodeKind::UnaryExpr) {
            auto *un = static_cast<ast::UnaryExpr *>(e->operand.get());
            if (un->op == ast::UnOp::Deref) {
                return lower_expr(un->operand.get());
            }
        }
        error_at(e->loc, "lowering: '&' aplicado a un no-lvalue");
        return ir::IR_NO_VALUE;
    }

    // Deref: emit LOAD desde el puntero.
    if (e->op == ast::UnOp::Deref) {
        const ir::IrValueId p = lower_expr(e->operand.get());
        if (p == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        // B1 fix: para STRUCT/ARRAY/OPTIONAL/RESULT, el "valor"
        // semantico es el propio PTR al buffer; un `LOAD ptr` cargaria
        // erroneamente los primeros 8 bytes del struct como si fueran
        // otro puntero (bug observado en `(*ptr_of(unique_struct)).x`
        // que emitia 2 LOADs encadenados).  Pass-through: devolvemos
        // el ptr tal cual y deja que el field-access posterior haga
        // ADD offset + LOAD i32 correctamente.
        //
        // Para CLASS aplicamos el mismo pass-through: el `*obj` con
        // obj=Class no tiene sentido como "leer el header"; el campo
        // access posterior (.field) lee i32 del offset apropiado.
        if (e->result_type.kind == PrimitiveKind::STRUCT ||
            e->result_type.kind == PrimitiveKind::ARRAY ||
            e->result_type.kind == PrimitiveKind::OPTIONAL ||
            e->result_type.kind == PrimitiveKind::RESULT ||
            e->result_type.kind == PrimitiveKind::CLASS) {
            // Limpiar is_virtual del ptr origen (si aplicable) antes
            // de devolverlo, igual que en el path LOAD normal.
            if (e->operand && e->operand->result_type.is_virtual) {
                fn_->values[p].is_host_ptr = false;
                fn_->values[p].pointee_is_host_ptr = false;
            }
            return p;
        }
        // Fix defensivo VirtualPtr: un VirtualPtr<T> es por definicion una
        // direccion en el espacio de memoria virtual de la VM.  Si por
        // propagacion de is_host_ptr (emit_field_addr, copy-prop del IR
        // optimizer, etc.) el flag quedo marcado en el SSA value del
        // puntero, limpiarlo aqui antes de emitir el LOAD.  Sin esto,
        // el emitter IR elige 'movh' (acceso a memoria host) en lugar
        // de 'mov' (acceso VM) y causa SIGSEGV al intentar desreferenciar
        // una direccion virtual de la VM como si fuera puntero del host.
        if (e->operand && e->operand->result_type.is_virtual) {
            fn_->values[p].is_host_ptr = false;
            fn_->values[p].pointee_is_host_ptr = false;
        }
        const ir::IrType ft = ir_type_from_primitive(e->result_type.kind);
        const ir::IrValueId dst = emit_load_typed(p, ft, e->loc.line);
        // Limitacion A (cerrada) parte 2: si el puntero p apunta a un
        // slot VM cuyo CONTENIDO es un host_ptr (caso indirecto via
        // address-of: @c i32** pp = &p; *pp), propagar @c is_host_ptr
        // al destino del LOAD.  Sin esto, un STORE posterior usando
        // dst como puntero (e.g. @c **pp = v) emitiria mov en lugar
        // de movh y corromperia memoria VM.  El bit lo marco
        // @c write_local en el SSA value del slot.
        if (fn_->values[p].pointee_is_host_ptr) {
            fn_->values[dst].is_host_ptr = true;
        }
        // Multi-nivel de punteros host (i64****, etc.): cada deref
        // devuelve un valor que ES OTRO puntero host (apunta a una
        // celda en memoria del host malloc'eado).  Sin propagar el
        // bit, el siguiente deref emitiria mov (memoria VM) en
        // lugar de movh (memoria host) y leeria garbage.
        //
        // Heuristica: si el operando es un puntero host (is_host_ptr)
        // Y el tipo de resultado del deref es OTRO puntero (PTR no
        // virtual), entonces el valor cargado tambien es host_ptr.
        // Lo mismo simetricamente para VirtualPtr<VirtualPtr<...>>:
        // si el operando es VirtualPtr y el resultado es OTRO
        // VirtualPtr, el valor cargado es una direccion VM (NO
        // host_ptr).
        if (e->result_type.kind == PrimitiveKind::PTR ||
            e->result_type.kind == PrimitiveKind::ARRAY) {
            if (e->result_type.is_virtual) {
                fn_->values[dst].is_host_ptr = false;
            } else if (fn_->values[p].is_host_ptr) {
                // El resultado del deref de un host_ptr es OTRO
                // host_ptr.  Asi p4=host_ptr -> *p4 = i64*** que
                // apunta a celda host -> tambien host_ptr.
                fn_->values[dst].is_host_ptr = true;
            }
        }
        return dst;
    }

    /* `-128` es la constante -128, no un `128` que se niega en ejecucion.
     *
     * Plegarlo aqui ahorra la instruccion, pero sobre todo deja el valor
     * marcado como CONSTANTE, y de eso depende el aviso de estrechamiento:
     * solo se calla cuando la constante CABE en el destino.  Sin plegar,
     * `i8 x = -128;` avisaba de una perdida que no existe -- -128 es justo el
     * minimo de i8 --, mientras que `i8 x = 127;` no decia nada.  El mismo
     * codigo, dos respuestas, y la equivocada era la del borde. */
    if (e->op == ast::UnOp::Neg && e->operand &&
        e->operand->kind == ast::NodeKind::IntLitExpr) {
        const auto *lit =
            static_cast<const ast::IntLitExpr *>(e->operand.get());
        const ir::IrType t = ir_type_from_primitive(e->result_type.kind);
        return emit_const(t == ir::IrType::VOID ? ir::IrType::I64 : t,
                          (uint64_t)(-(int64_t)lit->value), e->loc.line);
    }

    const ir::IrValueId v = lower_expr(e->operand.get());
    if (v == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    const ir::IrType vt = fn_->values[v].type;
    const bool is_float = is_floating(e->operand->result_type.kind);
    ir::IrValueId dst = fn_->new_value(vt);
    ir::IrInstr ins{};
    ins.dst = dst;
    ins.type = vt;
    ins.source_line = e->loc.line;
    ins.operands = {v};

    switch (e->op) {
    case ast::UnOp::Neg:
        ins.op = is_float ? ir::IrOp::FNEG : ir::IrOp::NEG;
        break;
    case ast::UnOp::Pos:
        // Unario + es identidad; emitir un MOV es la opcion mas barata.
        ins.op = ir::IrOp::MOV;
        break;
    case ast::UnOp::LogicalNot:
        // !x  <=>  cmp.eq x, 0
        {
            const ir::IrValueId zero = emit_const(vt, 0, e->loc.line);
            ins.op = is_float ? ir::IrOp::FCMP_EQ : ir::IrOp::CMP_EQ;
            ins.type = ir::IrType::BOOL;
            ins.operands = {v, zero};
            fn_->values[dst].type = ir::IrType::BOOL;
        }
        break;
    case ast::UnOp::BitNot: ins.op = ir::IrOp::NOT; break;
    case ast::UnOp::Unwrap:
        /* `!!x` es exactamente hacer cumplir un no-nulo: devuelve el mismo
         * valor y lanza si es cero.  Lo hace el MISMO sitio que lo hace al
         * asignar a un `nonnull` -- eran dos escrituras de la operacion, y esta
         * se dejaba dos cosas: que lo devuelto siga siendo un objeto del
         * recolector, y que un `T**` conserve que lo de dentro tambien es del
         * anfitrion. */
        return enforce_nonnull(v, e->loc.line);
    case ast::UnOp::Await: {
        // `await fut` bloquea hasta que el future este resuelto.
        // El bytecode `await r_fut` (0x2A) suspende el proceso si el
        // future esta PENDING (state -> WAIT_IO, blocking=true).  Al
        // ser resuelto via fulfill desde otro proceso, el waiter se
        // re-planifica y await re-ejecuta, devolviendo r0 = result.
        // Capturamos r0 a {dst} como i64 (el bytecode siempre devuelve
        // i64 raw; el frontend hace cast/bitcast al tipo logico T).
        const ir::IrValueId v_raw = fn_->new_value(ir::IrType::I64);
        {
            // AOT (native_poo_): CALL nativo __vx_await(fut) -> i64 raw.  En
            // el scheduler cooperativo, si el future esta PENDING y estamos en
            // main, bombea la cola hasta que se resuelva (run-to-completion);
            // dentro de una tarea, suspende (fibra, fase 3).
            ir::IrInstr aw{};
            aw.op = native_poo_ ? ir::IrOp::CALL : ir::IrOp::AWAIT;
            if (native_poo_) aw.func_name = "__vx_await";
            aw.type = ir::IrType::I64;
            aw.dst = v_raw;
            aw.operands = {v};
            aw.is_call_site = true; // bloquea -> save/restore live regs
            aw.source_line = e->loc.line;
            emit(current_block_, std::move(aw));
        }
        // Mejora II: si el operando del await es Future<T>, el frontend
        // sabe el tipo T y puede convertir el i64 raw al tipo logico
        // adecuado.  Para tipos < 8 bytes hace TRUNC; para floats hace
        // BITCAST (no FTOI que cambia el valor).  Si el operando NO
        // es Future<T> (legacy: i64/i32/u64/u32 directos), devolvemos
        // el v_raw sin cast.
        const Type op_type = e->operand ? e->operand->result_type : Type{};
        if (op_type.kind == PrimitiveKind::FUTURE && op_type.pointee) {
            const PrimitiveKind tk = op_type.pointee->kind;
            if (tk == PrimitiveKind::F64) {
                ir::IrValueId v_dst = emit_ir_unop(
                    ir::IrOp::BITCAST, v_raw, ir::IrType::F64, e->loc.line);
                return v_dst;
            }
            if (tk == PrimitiveKind::F32) {
                // i64 -> trunc i32 -> bitcast f32.
                ir::IrValueId v_i32 = emit_ir_unop(
                    ir::IrOp::TRUNC, v_raw, ir::IrType::I32, e->loc.line);
                ir::IrValueId v_dst = emit_ir_unop(
                    ir::IrOp::BITCAST, v_i32, ir::IrType::F32, e->loc.line);
                return v_dst;
            }
            // Tipos enteros mas estrechos (i8..i32, u8..u32, bool, char):
            // cast_if_needed selecciona TRUNC con la mascara correcta.
            const ir::IrType pt_ir = ir_type_from_primitive(tk);
            if (pt_ir != ir::IrType::I64) {
                return cast_if_needed(v_raw, ir::IrType::I64, pt_ir,
                                      e->loc.line);
            }
        }
        return v_raw;
    }
    default:
        // PreInc/PostInc/PreDec/PostDec ya filtrados arriba.
        unsupported(e->loc, "operador unario no soportado");
        return ir::IR_NO_VALUE;
    }

    emit(current_block_, std::move(ins));
    return dst;
}

ir::IrValueId
Lowering::emit_branching_select(ir::IrValueId cond,
                                const std::function<ir::IrValueId()> &on_true,
                                const std::function<ir::IrValueId()> &on_false,
                                const char *tag, uint32_t line) {
    if (cond == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    const std::string n = std::to_string(ternary_counter_++);
    const ir::IrBlockId then_bb =
        fn_->new_block(std::string(tag) + "_then_" + n);
    const ir::IrBlockId else_bb =
        fn_->new_block(std::string(tag) + "_else_" + n);
    const ir::IrBlockId merge_bb =
        fn_->new_block(std::string(tag) + "_merge_" + n);
    emit_br_cond(cond, then_bb, else_bb, line);

    current_block_ = then_bb;
    const ir::IrValueId then_val = on_true();
    const ir::IrBlockId then_end = current_block_;
    const ir::IrType then_t = (then_val != ir::IR_NO_VALUE)
                                  ? fn_->values[then_val].type
                                  : ir::IrType::I64;
    emit_br_from(then_end, merge_bb, line);

    current_block_ = else_bb;
    ir::IrValueId else_val = on_false();
    const ir::IrBlockId else_end = current_block_;
    // Los dos lados tienen que llegar al PHI con el mismo tipo.
    if (else_val != ir::IR_NO_VALUE) {
        const ir::IrType else_t = fn_->values[else_val].type;
        if (else_t != then_t)
            else_val = cast_if_needed(else_val, else_t, then_t, line);
    }
    emit_br_from(else_end, merge_bb, line);

    current_block_ = merge_bb;
    if (then_val == ir::IR_NO_VALUE || else_val == ir::IR_NO_VALUE)
        return ir::IR_NO_VALUE;
    const ir::IrValueId result = fn_->new_value(then_t);
    ir::IrInstr phi{};
    phi.op = ir::IrOp::PHI;
    phi.type = then_t;
    phi.dst = result;
    phi.phi_args.push_back({then_val, then_end});
    phi.phi_args.push_back({else_val, else_end});
    phi.source_line = line;
    emit(merge_bb, std::move(phi));
    return result;
}

ir::IrValueId Lowering::lower_ternary(ast::TernaryExpr *e) {
    if (!e->cond || !e->then_expr || !e->else_expr) {
        error_at(e->loc, "lowering: ternario incompleto");
        return ir::IR_NO_VALUE;
    }
    /* La forma -- dos ramas y un punto donde se juntan -- la monta
     * `emit_branching_select`, que es la misma que necesita `unwrap_or`.  Aqui
     * solo se dice QUE va en cada lado. */
    const ir::IrValueId cond = lower_expr(e->cond.get());
    if (cond == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    const ir::IrValueId r = emit_branching_select(
        cond, [&] { return lower_expr(e->then_expr.get()); },
        [&] { return lower_expr(e->else_expr.get()); }, "ter", e->loc.line);
    if (r == ir::IR_NO_VALUE)
        error_at(e->loc, "ternario: una de las ramas no produjo valor");
    return r;
}

} // namespace vx
