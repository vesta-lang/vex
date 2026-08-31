/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/assignment.cpp
 * @brief Bajada de la asignacion.
 *
 * Asignar no es un almacenamiento y por eso ocupa un fichero: el destino puede
 * ser una variable, el campo de una estructura o de una clase, un elemento de
 * un array, lo apuntado por un puntero, un campo de bits o una propiedad con
 * `set` -- y cada uno se escribe distinto --.  Ademas, si lo que se asigna
 * POSEE algo, hay que soltar antes lo que habia en el destino, o se queda sin
 * duenno.  Y una asignacion compuesta (`x += v`) es leer, operar y escribir,
 * con el detalle de que el destino se evalua UNA sola vez.
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
// Mapea AssignOp compuesto al BinOp aritmetico/bitwise correspondiente.
// Se usa por todas las rutas de lower_assign que necesitan implementar
// x op= v (struct field, class field, p[i], *p y la ya existente para
// identifier).  Devuelve BinOp::Add para Assign (no deberia llamarse
// con ese caso; el caller filtra antes).
static ast::BinOp compound_assign_op_to_binop(ast::AssignOp op) {
    switch (op) {
    case ast::AssignOp::AddAssign: return ast::BinOp::Add;
    case ast::AssignOp::SubAssign: return ast::BinOp::Sub;
    case ast::AssignOp::MulAssign: return ast::BinOp::Mul;
    case ast::AssignOp::DivAssign: return ast::BinOp::Div;
    case ast::AssignOp::ModAssign: return ast::BinOp::Mod;
    case ast::AssignOp::BitAndAssign: return ast::BinOp::BitAnd;
    case ast::AssignOp::BitOrAssign: return ast::BinOp::BitOr;
    case ast::AssignOp::BitXorAssign: return ast::BinOp::BitXor;
    case ast::AssignOp::ShlAssign: return ast::BinOp::Shl;
    case ast::AssignOp::ShrAssign: return ast::BinOp::Shr;
    case ast::AssignOp::Assign: return ast::BinOp::Add;
    }
    return ast::BinOp::Add;
}
} // namespace

ir::IrValueId Lowering::lower_assign(ast::AssignExpr *e) {
    // admitimos como lvalue: IdentExpr (variable simple) o
    // FieldAccessExpr (p.x = v).  Otros lvalues (deref de puntero,
    // indexado de array)
    if (!e->target) {
        error_at(e->loc, "lowering: target de '=' nulo");
        return ir::IR_NO_VALUE;
    }
    // static field de struct como LHS (`Struct.campo = v`): su storage es la
    // global sintetica `<Struct>__<campo>`.  Reescribimos el target al
    // IdentExpr de esa global y dejamos que el flujo normal de
    // asignacion-a-global lo maneje (incluye compound assign).
    if (e->target->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->target.get());
        if (fa->property_kind == 8 && fa->base &&
            fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *bid = static_cast<ast::IdentExpr *>(fa->base.get());
            auto gid = std::make_unique<ast::IdentExpr>();
            gid->loc = fa->loc;
            gid->name = bid->name + "__" + fa->field_name;
            gid->result_type = fa->result_type;
            e->target = std::move(gid);
        }
    }
    // Asignacion sobrecargada: el type checker dejo en @c overload_method el
    // dunder (`__assign__` para `=`, `__iadd__` para `+=`, ...).  Se desugara a
    // UNA llamada `target.__op__(value)` -- ni copia memberwise ni
    // load-op-store.  Esa es toda la diferencia: para `atomic<T>` la operacion
    // tiene que ser indivisible.
    // Mismo patron que el binario sobrecargado (ver lower_binary): se roban los
    // hijos para el call sintetico y se devuelven despues.
    if (!e->overload_method.empty() && e->target && e->value) {
        const bool recv_is_struct =
            (e->target->result_type.kind == PrimitiveKind::STRUCT);
        ast::CallExpr synth;
        synth.loc = e->loc;
        auto fa = std::make_unique<ast::FieldAccessExpr>();
        fa->loc = e->loc;
        fa->field_name = e->overload_method;
        fa->base = std::move(e->target);
        synth.callee = std::move(fa);
        synth.args.push_back(std::move(e->value));
        const ir::IrValueId v_call = recv_is_struct
                                         ? lower_struct_method_call(&synth)
                                         : lower_class_method_call(&synth);
        auto *fa_back = static_cast<ast::FieldAccessExpr *>(synth.callee.get());
        e->target = std::move(fa_back->base);
        e->value = std::move(synth.args[0]);
        return v_call;
    }
    // Si el valor es un lambda-literal que se almacena en un campo / slot /
    // deref, su env ESCAPA del scope actual (el objeto contenedor puede
    // sobrevivir al frame) -> debe alocarse en heap (GC).  Activamos el flag
    // mientras se baja el valor; un guard RAII lo restaura en cualquier
    // return de esta funcion.  lower_lambda_expr lo consulta.
    struct EscapeFlagGuard {
        bool &flag;
        bool prev;

        EscapeFlagGuard(bool &f, bool v) : flag(f), prev(f) { flag = v; }

        ~EscapeFlagGuard() { flag = prev; }
    };
    // El modelo de env owned-by-holder (RAW_ALLOC liberado por el destructor)
    // requiere que el contenedor tenga un punto de destruccion determinista.
    // En v1 solo lo aplicamos a campos de CLASE (su destructor aumentado
    // libera el env; ver emit_free_closure_env_field).  Para holders struct
    // (value-type, sin destructor de campos) el env se queda en STACK -- es
    // correcto y zero-cost para el caso no-escapante (el comun); un struct
    // con closure que se copia fuera de scope comparte el env de stack (misma
    // limitacion que cualquier struct con puntero crudo).  Ver
    // doc/VMdoc/Vesta/ClosuresEnCampos.md.
    // El RHS es "una lambda" tanto si es un LambdaExpr directo como si es un
    // metodo ligado `&obj.metodo` (UnaryExpr AddrOf con desugared_bound_method,
    // que el lowering baja como un lambda que captura el receptor).  Sin
    // detectar el segundo caso, current_lambda_store_escapes_ no se activa ->
    // el lambda del bound-method usa slot STACK (ALLOCA) en vez de heap owned
    // -> el reassign-free/dtor harian `free` de una direccion de stack ->
    // crash.
    bool _val_is_lambda =
        e->value && e->value->kind == ast::NodeKind::LambdaExpr;
    if (!_val_is_lambda && e->value &&
        e->value->kind == ast::NodeKind::UnaryExpr) {
        auto *uv = static_cast<ast::UnaryExpr *>(e->value.get());
        if (uv->desugared_bound_method) _val_is_lambda = true;
    }
    bool _tgt_is_class_field = false;
    bool _tgt_is_escaping_struct_field = false;
    if (e->target->kind == ast::NodeKind::FieldAccessExpr) {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e->target.get());
        if (fa->base && fa->base->result_type.kind == PrimitiveKind::CLASS) {
            _tgt_is_class_field = true;
        }
        // Ownership escape-sensitive: un lambda almacenado en un campo de un
        // STRUCT local que ESCAPA (return/store -> escaping_locals_) necesita
        // env en HEAP (como el caso clase), porque el struct se mueve por valor
        // fuera del scope productor y el env de stack colgaria.  El consumidor
        // (init-from-call) lo libera (CLOSURE_ENV_FREE).  Si el struct NO
        // escapa, el env se queda en stack (cero coste).
        else if (fa->base &&
                 fa->base->result_type.kind == PrimitiveKind::STRUCT &&
                 fa->base->kind == ast::NodeKind::IdentExpr) {
            auto *bid = static_cast<ast::IdentExpr *>(fa->base.get());
            if (escaping_locals_.find(bid->name) != escaping_locals_.end())
                _tgt_is_escaping_struct_field = true;
        }
    }
    EscapeFlagGuard _esc_guard(
        current_lambda_store_escapes_,
        _val_is_lambda &&
            (_tgt_is_class_field || _tgt_is_escaping_struct_field));
    /* Aqui se decidia si la ranura de un `unique` que va a parar a un CAMPO
     * debia reservarse en el monton, mirando a la vez la forma del destino y el
     * nombre de la funcion del lado derecho.  Ya no hay nada que decidir: un
     * campo ES su propia ranura, asi que quien guarda en el traspasa el recurso
     * y no hay ninguna reserva que tenga que sobrevivir a nadie. */
    // El destino manda: cada forma de lvalue tiene su camino.
    {
        ir::IrValueId v_lv = ir::IR_NO_VALUE;
        if (try_lower_assign_to_field(e, v_lv)) return v_lv;
        if (try_lower_assign_to_index(e, v_lv)) return v_lv;
        if (try_lower_assign_to_deref(e, v_lv)) return v_lv;
    }
    if (e->target->kind != ast::NodeKind::IdentExpr) {
        error_at(e->loc, "lowering: el lado izquierdo de '=' debe ser un "
                         "identificador o un acceso a campo");
        (void)lower_expr(e->value.get());
        return ir::IR_NO_VALUE;
    }
    auto *id = static_cast<ast::IdentExpr *>(e->target.get());

    // Vesta Embed Inc 2: `s += t` / `s += 'c'` / `s += "lit"` en native_poo_.
    // El target `s` es un value-string (PTR al slot {ptr,len,cap}); el
    // append muta el slot in-place (grow del buffer si hace falta) sin
    // crear slot nuevo.  Soportamos RHS string (otra var/concat/literal) y
    // char.  El path Full (sin native_poo_) NO entra aqui: `string += x`
    // sobre StringObject cae al manejo generico de abajo (que para STRING
    // no es comun; el frontend Full usa STRCAT).
    if (native_poo_ && id->result_type.kind == PrimitiveKind::STRING &&
        e->op == ast::AssignOp::AddAssign && e->value) {
        const ir::IrValueId v_slot = lookup(id->name);
        if (v_slot == ir::IR_NO_VALUE) {
            error_at(e->loc, "lowering: nombre no resuelto en '+=': '" +
                                 id->name + "'");
            return ir::IR_NO_VALUE;
        }
        const uint32_t ln = static_cast<uint32_t>(e->loc.line);
        // Caso RHS char: append de 1 byte.
        if (e->value->result_type.kind == PrimitiveKind::CHAR) {
            const ir::IrValueId v_ch = lower_expr(e->value.get());
            if (v_ch == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            // Buffer scratch de 1 byte con el char.
            ir::IrValueId v_scr = stack_alloc_buf(1, ln, native_poo_);
            if (native_poo_) fn_->values[v_scr].is_host_ptr = true;
            emit_store_typed(v_scr, v_ch, ir::IrType::U8, ln);
            build_native_string_append_inplace(
                v_slot, v_scr, emit_const(ir::IrType::I64, 1, ln), ln);
            return v_slot;
        }
        // Caso RHS string (var, concat, literal): cargar ptr/len de la
        // fuente y appendear.  Para un literal lo materializamos via el
        // helper de literal native (slot temporal con buffer en heap,
        // liberado tras leer sus bytes -- pero como ALLOCA del slot y el
        // buffer del literal NO se registran STRING_FREE, hay que
        // liberarlo aqui para no leakear).  Para una expr string owned
        // (concat) liberamos su buffer tras copiarlo.
        ir::IrValueId v_src = ir::IR_NO_VALUE;
        bool free_src_buf = false; // liberar el buffer fuente tras copiar
        if (e->value->kind == ast::NodeKind::StringLitExpr &&
            !static_cast<ast::StringLitExpr *>(e->value.get())
                 ->is_interpolated()) {
            auto *slit = static_cast<ast::StringLitExpr *>(e->value.get());
            v_src = build_native_string_from_literal(slit, ln);
            free_src_buf = true; // buffer temporal owned -> liberar
        } else {
            v_src = lower_expr(e->value.get());
            // Un concat `a + b` produce un slot owned con buffer fresco;
            // tras copiar sus bytes hay que liberarlo (no se registro
            // STRING_FREE porque no es un var-decl).  Una var simple
            // (IdentExpr) NO se libera (su buffer lo posee la var).
            if (e->value->kind != ast::NodeKind::IdentExpr) free_src_buf = true;
        }
        if (v_src == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        // Inc 5 (SSO): (ptr, len) de la fuente via accesores flag-aware.
        // Calcularlos ANTES del append (que muta current_block_ con su
        // branch SSO/HEAP).
        ir::IrValueId v_sptr = emit_native_str_data_ptr(v_src, ln);
        ir::IrValueId v_slen = emit_native_str_len(v_src, ln);
        build_native_string_append_inplace(v_slot, v_sptr, v_slen, ln);
        if (free_src_buf) {
            // Liberar el buffer fuente temporal SOLO si estaba en HEAP
            // (SSO no tiene buffer que liberar).  El append ya copio los
            // bytes a un buffer/inline propio del destino.
            emit_native_str_free_if_heap(v_src, ln);
        }
        return v_slot;
    }

    // Bajar el lado derecho.
    // Bug fix 2026-05-23 (Audit 48): auto-promotion del string literal a
    // StringObject cuando el target es una var local de tipo string.  Sin
    // esto, `s = "lit"` (post var-decl) almacenaba el host_ptr al literal
    // como GcHandle invalido.
    ir::IrValueId rhs;
    if (id->result_type.kind == PrimitiveKind::STRING && e->value &&
        e->value->kind == ast::NodeKind::StringLitExpr) {
        auto *slit = static_cast<ast::StringLitExpr *>(e->value.get());
        rhs = lower_string_literal_to_string_object(slit);
    } else {
        rhs = lower_expr(e->value.get());
    }
    if (rhs == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    /* Value-type ENUM: `t = <enum>` COPIA los bytes del enum al slot ESTABLE
     * de `t` (no repunta el puntero).  Igual modelo que un struct; sin esto,
     * una asignacion (condicional o no) repuntaria `t` al slot del constructor
     * (naturaleza VM/host distinta al slot del var-decl) y un PHI mezclaria
     * punteros de naturaleza mixta -> el `match t` posterior leeria el tag con
     * el load de la naturaleza equivocada (movh sobre direccion VM) -> SIGSEGV.
     */
    if (e->op == ast::AssignOp::Assign &&
        id->result_type.kind == PrimitiveKind::STRUCT) {
        const auto &elays_e = tc_.enum_layouts();
        auto ite_e = elays_e.find(id->result_type.struct_name);
        if (ite_e != elays_e.end()) {
            const ir::IrValueId slot = lookup(id->name);
            if (slot != ir::IR_NO_VALUE) {
                emit_enum_copy(slot, rhs, fn_->values[rhs].is_host_ptr,
                               ite_e->second.size_bytes, e->loc.line);
                return slot;
            }
        }
    }

    /* L2.2: target es global runtime con storage en static_data.
     * Emit STORE al slot.  Soporta `=` directo y compound assigns
     * via load-modify-store. */
    {
        auto rit = runtime_global_slots_.find(id->name);
        if (rit != runtime_global_slots_.end()) {
            const uint64_t slot_idx = rit->second;
            const int ln = e->loc.line;
            // El slot vive en memoria host (seccion `gdata`) -> el
            // load-modify-store de abajo es acceso host directo.
            const ir::IrValueId v_addr =
                emit_str_lit_addr(slot_idx, ln, /*host_ptr=*/true);
            // Tipo declarado del global.  El compound assign tiene que operar
            // con EL del global, no con i64: sobre un `f64 g`, un `g += x` con
            // aritmetica entera sumaria los BITS IEEE (basura: 1.5+1.5+1.5 daba
            // -0.75).  `g = g + x` no sufria porque va por el camino normal,
            // con el tipo real.  Para STRING el valor es el GcHandle -> i64.
            PrimitiveKind gprim = PrimitiveKind::I64;
            for (auto &decl : mod_.decls) {
                if (!decl || decl->kind != ast::NodeKind::GlobalVarDecl)
                    continue;
                auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
                if (gv->name != id->name) continue;
                if (gv->type &&
                    gv->type->kind == ast::NodeKind::PrimitiveTypeNode)
                    gprim =
                        static_cast<ast::PrimitiveTypeNode *>(gv->type.get())
                            ->prim;
                break;
            }
            const bool gfloat =
                (gprim == PrimitiveKind::F32 || gprim == PrimitiveKind::F64);
            const ir::IrType gty =
                gfloat ? ir_type_from_primitive(gprim) : ir::IrType::I64;
            // El valor a guardar tiene que llegar en el ancho del global: los
            // literales float se parsean como double, asi que `f32 g = 1.25`
            // trae un f64 y guardarlo como F32 sin convertir escribe basura.
            if (gfloat && e->value) {
                const ir::IrType from =
                    (e->value->result_type.kind == PrimitiveKind::F32)
                        ? ir::IrType::F32
                        : ir::IrType::F64;
                rhs = cast_if_needed(rhs, from, gty, e->loc);
            }

            // Compound assign: load cur + combine.
            if (e->op != ast::AssignOp::Assign) {
                ir::IrValueId v_cur = emit_load_typed(v_addr, gty, ln);
                const ast::BinOp bop = compound_assign_op_to_binop(e->op);
                rhs =
                    emit_binop_ir(bop, v_cur, rhs,
                                  gfloat ? gprim : PrimitiveKind::I64, e->loc);
            }
            emit_store_typed(v_addr, rhs, gty, ln);
            return rhs;
        }
    }

    /*  MC.17.2: si estamos dentro de un @Macro Y el target es
     * un comptime global int, emit STORE al slot @c static_data
     * correspondiente.  Soporta `=` directo y compound `+=`/`-=`
     * (el caller computa cur op rhs en `rhs` antes de llegar aqui). */
    if (current_fn_is_macro_) {
        auto cit = tc_.comptime_const_values().find(id->name);
        if (cit != tc_.comptime_const_values().end() && !cit->second.is_str) {
            const uint64_t slot_idx =
                get_or_create_comptime_global_slot(id->name);
            if (slot_idx != UINT64_MAX) {
                const int ln = e->loc.line;
                /* Si compound assign, leer valor actual y combinar
                 * con rhs ANTES del store.  Esto es paralelo al
                 * camino general que sigue mas abajo, pero como
                 * salimos antes de llegar a ese punto, lo
                 * replicamos aqui inline para compound. */
                if (e->op != ast::AssignOp::Assign) {
                    /* Compound assign sobre global: load cur from
                     * slot + combine + store back. */
                    ir::IrValueId v_addr_load = emit_str_lit_addr(slot_idx, ln);
                    ir::IrValueId v_cur =
                        emit_load_typed(v_addr_load, ir::IrType::I64, ln);
                    /* Combine via emit_binop equivalent.  Mapeamos
                     * AssignOp -> BinOp y emitimos.  Para simplicidad
                     * solo cubrimos los compound mas comunes; otros
                     * caen al camino general (que falla porque
                     * write_local no encontrara el name). */
                    ast::BinOp bop = ast::BinOp::Add;
                    bool supported = true;
                    switch (e->op) {
                    case ast::AssignOp::AddAssign: bop = ast::BinOp::Add; break;
                    case ast::AssignOp::SubAssign: bop = ast::BinOp::Sub; break;
                    case ast::AssignOp::MulAssign: bop = ast::BinOp::Mul; break;
                    case ast::AssignOp::DivAssign: bop = ast::BinOp::Div; break;
                    case ast::AssignOp::ModAssign: bop = ast::BinOp::Mod; break;
                    case ast::AssignOp::BitAndAssign:
                        bop = ast::BinOp::BitAnd;
                        break;
                    case ast::AssignOp::BitOrAssign:
                        bop = ast::BinOp::BitOr;
                        break;
                    case ast::AssignOp::BitXorAssign:
                        bop = ast::BinOp::BitXor;
                        break;
                    case ast::AssignOp::ShlAssign: bop = ast::BinOp::Shl; break;
                    case ast::AssignOp::ShrAssign: bop = ast::BinOp::Shr; break;
                    default: supported = false; break;
                    }
                    if (supported) {
                        /* Use emit_binop_ir (mismo helper que el
                         * camino normal de compound assign).  Common
                         * = I64 (los globals son int de 64-bit). */
                        rhs = emit_binop_ir(bop, v_cur, rhs, PrimitiveKind::I64,
                                            e->loc);
                    }
                }
                /* STORE rhs al slot. */
                ir::IrValueId v_addr = emit_str_lit_addr(slot_idx, ln);
                emit_store_typed(v_addr, rhs, ir::IrType::I64, ln);
                return rhs;
            }
        }
    }

    // Tipo destino: el del simbolo en el scope (o el result_type del
    // target que el type checker dejo).
    const ir::IrType dst_ir =
        ir_type_from_primitive(e->target->result_type.kind);

    // Para asignaciones compuestas (+=, -=, etc.) cargamos el valor
    // actual y combinamos.  El operador ASCII '=' simplemente se
    // ignora aqui y va directo al write_local con rhs.
    if (e->op != ast::AssignOp::Assign) {
        // Lectura previa respeta promocion address-taken.
        const ir::IrValueId cur = read_local(id->name, dst_ir, e->loc.line);
        if (cur == ir::IR_NO_VALUE) {
            error_at(e->loc,
                     "lowering: nombre no resuelto: '" + id->name + "'");
            return ir::IR_NO_VALUE;
        }
        /* P1: `string += X` en el path Full/VM (no native_poo_).  El path arith
         * generico de abajo (promote_arith + emit_binop) NO hace STRCAT sobre
         * StringObject -> daba string vacio.  Emitimos STRCAT como `s = s + X`.
         * (Antes funcionaba solo porque la comptime fn se AST-evaluaba; con el
         * rewrite corre en la VM y necesita el lowering correcto.) */
        if (!native_poo_ &&
            e->target->result_type.kind == PrimitiveKind::STRING &&
            e->op == ast::AssignOp::AddAssign && e->value) {
            /* El lado derecho YA esta bajado arriba, con la misma coercion que
             * hace falta aqui: un literal se promueve a StringObject (STRMAKE)
             * en vez de quedarse como STR_LIT_ADDR crudo, que es lo que STRCAT
             * espera, y vale igual para el literal de una pieza y para el
             * interpolado (la cadena de trozos la arma el mismo constructor).
             *
             * Volver a bajarlo aqui -- que es lo que se hacia -- emitia la
             * expresion DOS veces y tiraba la primera.  Con un literal sale
             * gratis, pero con `s += "${x}"` la conversion es una llamada
             * nativa que escribe en un buffer de pila: dos reservas y dos
             * llamadas por interpolacion, una de ellas muerta y que ningun
             * DCE puede quitar porque la llamada tiene efectos. */
            const ir::IrValueId v_cat =
                emit_strcat(cur, rhs, static_cast<uint32_t>(e->loc.line));
            write_local(id->name, v_cat, dst_ir, e->loc.line);
            return v_cat;
        }
        // Promocion al tipo comun entre cur y rhs (igual que en
        // lower_binary).  En la mayoria de casos ambos tienen el
        // tipo de la variable; el cast es trivial.
        const PrimitiveKind ltk = e->target->result_type.kind;
        const PrimitiveKind rtk = e->value->result_type.kind;
        const PrimitiveKind common =
            (ltk == PrimitiveKind::BOOL && rtk == PrimitiveKind::BOOL)
                ? PrimitiveKind::BOOL
                : promote_arith(ltk, rtk);
        const ir::IrType common_ir = ir_type_from_primitive(common);

        ir::IrValueId l = cast_if_needed(cur, ir_type_from_primitive(ltk),
                                         common_ir, e->loc.line);
        ir::IrValueId r = cast_if_needed(rhs, ir_type_from_primitive(rtk),
                                         common_ir, e->loc.line);

        // Mapear AssignOp a su BinOp equivalente.
        ast::BinOp bop = ast::BinOp::Add;
        switch (e->op) {
        case ast::AssignOp::AddAssign: bop = ast::BinOp::Add; break;
        case ast::AssignOp::SubAssign: bop = ast::BinOp::Sub; break;
        case ast::AssignOp::MulAssign: bop = ast::BinOp::Mul; break;
        case ast::AssignOp::DivAssign: bop = ast::BinOp::Div; break;
        case ast::AssignOp::ModAssign: bop = ast::BinOp::Mod; break;
        case ast::AssignOp::BitAndAssign: bop = ast::BinOp::BitAnd; break;
        case ast::AssignOp::BitOrAssign: bop = ast::BinOp::BitOr; break;
        case ast::AssignOp::BitXorAssign: bop = ast::BinOp::BitXor; break;
        case ast::AssignOp::ShlAssign: bop = ast::BinOp::Shl; break;
        case ast::AssignOp::ShrAssign: bop = ast::BinOp::Shr; break;
        case ast::AssignOp::Assign: break; // ya filtrado arriba
        }
        rhs = emit_binop_ir(bop, l, r, common, e->loc);
    }

    // Self-assign via metodo: `x = x.metodo(...)` (el receptor del metodo ES el
    // target).  El metodo SRET escribe su retbuf y luego se rebindearia x a ese
    // retbuf; pero si esto esta en un LOOP, el ALLOCA del retbuf se hoista al
    // prologo (un solo buffer) y en la 2a+ iteracion `this` (=x, ya rebindeado
    // al retbuf) y el retbuf ALIASAN -> el metodo lee y escribe el mismo buffer
    // = corrupcion (el JIT lo sufre; el interp re-aloca por iteracion y lo
    // enmascara). Tratarlo como el caso address-taken: COPIAR el retbuf al
    // buffer ESTABLE de x (sin rebind) -> `this` y el retbuf quedan SIEMPRE
    // distintos.
    bool is_self_method_assign = false;
    if (e->op == ast::AssignOp::Assign && e->value &&
        e->value->kind == ast::NodeKind::CallExpr) {
        auto *cv = static_cast<ast::CallExpr *>(e->value.get());
        if (cv->callee && cv->callee->kind == ast::NodeKind::FieldAccessExpr) {
            auto *fa = static_cast<ast::FieldAccessExpr *>(cv->callee.get());
            if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr &&
                static_cast<ast::IdentExpr *>(fa->base.get())->name == id->name)
                is_self_method_assign = true;
        }
    }
    // @Virtual/struct: si el target es un STRUCT ADDRESS-TAKEN (o un
    // self-assign via metodo, ver arriba), @c rhs es el PTR a un buffer origen
    // (el retbuf de un metodo SRET, u otro struct).  Hay que COPIAR sus bytes
    // al buffer del target, NO rebindear el slot al ptr origen: con `&x` tomado
    // el buffer del target es fijo, y write_local guardaria el PUNTERO en el
    // slot en vez del contenido.
    if (rhs != ir::IR_NO_VALUE && e->op == ast::AssignOp::Assign &&
        e->target->result_type.kind == PrimitiveKind::STRUCT &&
        (address_taken_locals_.count(id->name) || is_self_method_assign) &&
        !type_is_overlay(e->target->result_type)) {
        const std::string &sn = e->target->result_type.struct_name;
        auto it_sl = tc_.struct_layouts().find(sn);
        if (it_sl != tc_.struct_layouts().end()) {
            // Para un struct address-taken el ALLOCA ES el buffer; lookup() da
            // su direccion (read_local haria un LOAD, devolviendo el
            // contenido).
            const ir::IrValueId dst_addr = lookup(id->name);
            if (dst_addr != ir::IR_NO_VALUE && dst_addr != rhs) {
                const uint64_t sz =
                    static_cast<uint64_t>(it_sl->second.size_bytes);
                const bool dst_host = fn_->values[dst_addr].is_host_ptr;
                const bool src_host = fn_->values[rhs].is_host_ptr;
                const uint64_t qwords = (sz + 7) / 8;
                for (uint64_t qi = 0; qi < qwords; ++qi) {
                    const ir::IrValueId v_off =
                        emit_const(ir::IrType::I64,
                                   static_cast<int64_t>(qi * 8), e->loc.line);
                    const ir::IrValueId s_at = fn_->new_value(ir::IrType::PTR);
                    fn_->values[s_at].is_host_ptr = src_host;
                    {
                        ir::IrInstr ad{};
                        ad.op = ir::IrOp::ADD;
                        ad.type = ir::IrType::I64;
                        ad.dst = s_at;
                        ad.operands = {rhs, v_off};
                        ad.source_line = e->loc.line;
                        emit(current_block_, std::move(ad));
                    }
                    const ir::IrValueId w =
                        emit_load_typed(s_at, ir::IrType::I64, e->loc.line);
                    const ir::IrValueId d_at = fn_->new_value(ir::IrType::PTR);
                    fn_->values[d_at].is_host_ptr = dst_host;
                    {
                        ir::IrInstr ad{};
                        ad.op = ir::IrOp::ADD;
                        ad.type = ir::IrType::I64;
                        ad.dst = d_at;
                        ad.operands = {dst_addr, v_off};
                        ad.source_line = e->loc.line;
                        emit(current_block_, std::move(ad));
                    }
                    emit_store_typed(d_at, w, ir::IrType::I64, e->loc.line);
                }
                return dst_addr;
            }
        }
    }

    // Cast final al tipo declarado de la variable y actualizar el scope.
    const ir::IrType rhs_ir =
        (rhs != ir::IR_NO_VALUE) ? fn_->values[rhs].type : dst_ir;
    rhs = cast_if_needed(rhs, rhs_ir, dst_ir, e->loc.line);
    write_local(id->name, rhs, dst_ir, e->loc.line);
    return rhs;
}

/**
 * @brief Asigna a un campo: `obj.campo = v`.
 *
 * Dos receptores muy distintos comparten sintaxis.  Si es una clase, el campo
 * puede ser de instancia o estatico -- y entonces no hay objeto que mirar --,
 * puede haber una propiedad con su metodo de escritura en vez de un campo, y
 * puede haber herencia de por medio, asi que el desplazamiento sale de la
 * clase que de verdad lo declara.  Si es un struct, es base mas desplazamiento
 * y ya, sin nada que resolver en ejecucion.
 *
 * @param e   La asignacion.
 * @param out Donde dejar el valor asignado (una asignacion es una expresion).
 * @return @c true si el destino era un campo y quedo bajado.
 */
bool Lowering::try_lower_assign_to_field(ast::AssignExpr *e,
                                         ir::IrValueId &out) {
    if (e->target->kind != ast::NodeKind::FieldAccessExpr) return false;
    auto *fa = static_cast<ast::FieldAccessExpr *>(e->target.get());
    // CLASS o static field (limitacion G cerrada, property_kind=3):
    // ruta SETFIELD con offset (lower_class_field_store), que
    // detecta property_kind=3 y emite findclass + setstatic.
    if ((fa->base && fa->base->result_type.kind == PrimitiveKind::CLASS) ||
        fa->property_kind == 3) {
        // fix.lazy-string - si el field es de tipo STRING y el
        // rhs es un string literal no interpolado, promovemos el
        // literal a StringObject (STRMAKE) ANTES del store.  Sin
        // esto, escribiriamos el host_ptr al literal en static_data
        // dentro del slot del field, que luego se interpretaria como
        // GcHandle invalido y crashearia al primer acceso.  La
        // promocion ya se hace para var-decl (`string s = "lit"`)
        // pero faltaba esta ruta para `this.field = "lit"` y
        // `obj.field = "lit"`.
        ir::IrValueId rhs = ir::IR_NO_VALUE;
        bool promoted = false;
        if (e->value && e->value->kind == ast::NodeKind::StringLitExpr &&
            fa->base &&
            fa->base->result_type.kind == PrimitiveKind::CLASS) {
            auto *slit = static_cast<ast::StringLitExpr *>(e->value.get());
            // Promovemos tanto literales puros como interpolados:
            // el helper detecta el caso y emite STRMAKE simple
            // (puro) o cadena STRMAKE+STRCAT (interpolado).
            auto it_cls =
                tc_.class_layouts().find(fa->base->result_type.struct_name);
            if (it_cls != tc_.class_layouts().end()) {
                const StructFieldInfo *f =
                    find_field(it_cls->second, fa->field_name);
                if (f && f->type.kind == PrimitiveKind::STRING) {
                    rhs = lower_string_literal_to_string_object(slit);
                    promoted = true;
                }
            }
        }
        if (!promoted) {
            rhs = lower_expr(e->value.get());
        }
        if (rhs == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        if (e->op != ast::AssignOp::Assign) {
            // Compound: leer valor actual via getter o GETFIELD,
            // aplicar el op, escribir via setter o SETFIELD.  Reusa
            // lower_class_field_load (maneja getters de propiedades
            // y GETFIELD por offset) para cero duplicacion logica.
            ir::IrValueId cur = lower_class_field_load(fa);
            if (cur == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            const ast::BinOp bop = compound_assign_op_to_binop(e->op);
            rhs =
                emit_binop_ir(bop, cur, rhs, fa->result_type.kind, e->loc);
        }
        out = lower_class_field_store(fa, rhs, e->loc);
        return true;
    }
    // STRUCT: ruta original via lower_field_addr + STORE.
    const ir::IrValueId addr = lower_field_addr(fa);
    if (addr == ir::IR_NO_VALUE) {
        (void)lower_expr(e->value.get());
        out = ir::IR_NO_VALUE;
        return true;
    }
    // Bug fix 2026-05-23 (Audit 45): auto-promotion del string literal
    // a StringObject cuando el field STRUCT es de tipo string.  Misma
    // motivacion que CLASS arriba: sin esto el host_ptr al literal
    // se guarda como GcHandle invalido en el slot.
    ir::IrValueId rhs;
    if (fa->result_type.kind == PrimitiveKind::STRING && e->value &&
        e->value->kind == ast::NodeKind::StringLitExpr) {
        auto *slit = static_cast<ast::StringLitExpr *>(e->value.get());
        rhs = lower_string_literal_to_string_object(slit);
    } else {
        rhs = lower_expr(e->value.get());
    }
    if (rhs == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    /* Campo `unique<T>` de un STRUCT: el campo ES la ranura, igual que en una
     * clase, asi que lo que se guarda es el RECURSO y no la direccion de otra
     * ranura.  Los mismos tres pasos que en la clase, y en el mismo orden:
     * soltar lo que hubiera, traspasar, y VACIAR el origen -- si no, al salir
     * del ambito su limpieza soltaria el mismo recurso que ahora tiene el
     * campo --.
     *
     * Esta ruta se quedo sin cambiar cuando el campo dejo de guardar una
     * direccion: entonces el struct seguia guardando una ranura mientras el
     * lector ya esperaba el recurso, y leerlo devolvia una direccion en vez de
     * un valor.  Se vio en `std.comptime.literal`, que tiene un `unique<u64>`
     * dentro de un struct y lo indexa. */
    if (fa->result_type.kind == PrimitiveKind::UNIQUE_PTR) {
        emit_free_unique_slot(addr, fa->result_type.deleter_name, e->loc.line,
                              /*slot_is_owned=*/false);
        const ir::IrValueId v_res = emit_load_host_ptr(rhs, e->loc.line);
        emit_store_typed(addr, v_res, ir::IrType::I64, e->loc.line);
        const ir::IrValueId cero = emit_const(ir::IrType::I64, 0, e->loc.line);
        emit_store_typed(rhs, cero, ir::IrType::I64, e->loc.line);
        out = rhs;
        return true;
    }

    const ir::IrType ft = ir_type_from_primitive(fa->result_type.kind);
    // Compound assign: leer el valor actual del campo (con
    // extraccion de bit field si aplica), aplicar el operador,
    // y luego seguir con la ruta de store normal (que tambien
    // maneja bit field RMW).
    if (e->op != ast::AssignOp::Assign) {
        ir::IrValueId cur = lower_field_access(fa);
        if (cur == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        const ast::BinOp bop = compound_assign_op_to_binop(e->op);
        rhs = emit_binop_ir(bop, cur, rhs, fa->result_type.kind, e->loc);
    }
    rhs = cast_if_needed(rhs, fn_->values[rhs].type, ft,
                         e->value ? e->value->loc : e->loc);

    // F5: campo `@endian(expr)` -> swap CONDICIONAL del valor a escribir
    // (simetrico con el read): el store LE deja los bytes en el orden que
    // dicta la expr.  Comptime se pliega; runtime = select sin ramas.
    {
        const Type bt_w = fa->base ? fa->base->result_type : Type{};
        if (bt_w.kind == PrimitiveKind::STRUCT) {
            auto it_w = tc_.struct_layouts().find(bt_w.struct_name);
            if (it_w != tc_.struct_layouts().end()) {
                const StructFieldInfo *f =
                    find_field(it_w->second, fa->field_name);
                if (f && f->endian_expr && f->bit_width == 0 &&
                    (f->size == 2 || f->size == 4 || f->size == 8)) {
                    rhs = emit_overlay_endian_swap(fa->base.get(),
                                                   it_w->second, *f, rhs,
                                                   e->loc.line);
                }
            }
        }
    }

    // WRITE de bit field: read-modify-write.  Si el campo es bit
    // field, leemos el storage word completo, le limpiamos los
    // bits del rango con AND inverse_mask, le metemos el valor
    // con OR ((rhs & mask) << bit_offset), y hacemos STORE de
    // vuelta.  Para campo normal (no-bitfield): STORE directo
    // del rhs sin lectura previa.
    const Type bt = fa->base ? fa->base->result_type : Type{};
    if (bt.kind == PrimitiveKind::STRUCT) {
        const auto &layouts = tc_.struct_layouts();
        auto it_l = layouts.find(bt.struct_name);
        if (it_l != layouts.end()) {
            const StructFieldInfo *f = find_field(it_l->second, fa->field_name);
            if (f && f->bit_width > 0) {
                // 1. LOAD storage word completo.
                ir::IrValueId v_old =
                    emit_load_typed(addr, ft, e->loc.line);
                // 2. mask = (1 << bit_width) - 1 (en el tipo
                //    del storage; truncar a tamano del LOAD).
                const uint64_t mask =
                    (f->bit_width == 64)
                        ? UINT64_MAX
                        : ((uint64_t(1) << f->bit_width) - 1);
                const uint64_t inv_mask = ~(mask << f->bit_offset);
                // 3. cleared = old & inv_mask
                ir::IrValueId v_inv =
                    emit_const(ft, inv_mask, e->loc.line);
                ir::IrValueId v_clr = fn_->new_value(ft);
                {
                    ir::IrInstr an{};
                    an.op = ir::IrOp::AND;
                    an.type = ft;
                    an.dst = v_clr;
                    an.operands = {v_old, v_inv};
                    an.source_line = e->loc.line;
                    emit(current_block_, std::move(an));
                }
                // 4. trimmed = rhs & mask  (clamp a rango).
                ir::IrValueId v_msk = emit_const(ft, mask, e->loc.line);
                ir::IrValueId v_tr = fn_->new_value(ft);
                {
                    ir::IrInstr an{};
                    an.op = ir::IrOp::AND;
                    an.type = ft;
                    an.dst = v_tr;
                    an.operands = {rhs, v_msk};
                    an.source_line = e->loc.line;
                    emit(current_block_, std::move(an));
                }
                // 5. shifted = trimmed << bit_offset
                ir::IrValueId v_sh = v_tr;
                if (f->bit_offset > 0) {
                    ir::IrValueId v_amt = emit_const(
                        ft, (uint64_t)f->bit_offset, e->loc.line);
                    v_sh = fn_->new_value(ft);
                    ir::IrInstr sh{};
                    sh.op = ir::IrOp::SHL;
                    sh.type = ft;
                    sh.dst = v_sh;
                    sh.operands = {v_tr, v_amt};
                    sh.source_line = e->loc.line;
                    emit(current_block_, std::move(sh));
                }
                // 6. new = cleared | shifted
                ir::IrValueId v_new = fn_->new_value(ft);
                {
                    ir::IrInstr or_{};
                    or_.op = ir::IrOp::OR;
                    or_.type = ft;
                    or_.dst = v_new;
                    or_.operands = {v_clr, v_sh};
                    or_.source_line = e->loc.line;
                    emit(current_block_, std::move(or_));
                }
                // 7. STORE new -> addr
                emit_store_typed(addr, v_new, ft, e->loc.line);
                out = rhs;
                return true;
            }
        }
    }
    // Campo de tipo STRUCT (value-type): @c rhs es la DIRECCION del struct
    // origen -> copia memberwise (qword-by-qword) sus bytes al campo, NO un
    // STORE escalar (que guardaria la direccion origen).  Si el struct
    // declara `__clone__` (copy-hook), tras la copia aplica el efecto sobre
    // la copia del campo (p.ej. ++refcount).  Mismo modelo que el path
    // CLASS (lower_class_field_store).
    //
    // EXCEPCION: si el campo es de tipo `@overlay struct`, el slot guarda
    // el HANDLE de la vista (8 bytes), no un agregado embebido -> STORE
    // directo del puntero (cae al camino generico de abajo).  Sin esto la
    // copia memberwise volcaba el PAYLOAD apuntado por el handle en el
    // campo.
    if (fa->result_type.kind == PrimitiveKind::STRUCT &&
        !type_is_overlay(fa->result_type)) {
        uint64_t sz = 8;
        auto it_sl = tc_.struct_layouts().find(fa->result_type.struct_name);
        if (it_sl != tc_.struct_layouts().end())
            sz = static_cast<uint64_t>(it_sl->second.size_bytes);
        const bool dst_host = fn_->values[addr].is_host_ptr;
        const bool src_host = fn_->values[rhs].is_host_ptr;
        const uint64_t qwords = (sz + 7) / 8;
        for (uint64_t qi = 0; qi < qwords; ++qi) {
            const ir::IrValueId v_off = emit_const(
                ir::IrType::I64, static_cast<int64_t>(qi * 8), e->loc.line);
            const ir::IrValueId s_at = fn_->new_value(ir::IrType::PTR);
            fn_->values[s_at].is_host_ptr = src_host;
            {
                ir::IrInstr ad{};
                ad.op = ir::IrOp::ADD;
                ad.type = ir::IrType::I64;
                ad.dst = s_at;
                ad.operands = {rhs, v_off};
                ad.source_line = e->loc.line;
                emit(current_block_, std::move(ad));
            }
            const ir::IrValueId w =
                emit_load_typed(s_at, ir::IrType::I64, e->loc.line);
            const ir::IrValueId d_at = fn_->new_value(ir::IrType::PTR);
            fn_->values[d_at].is_host_ptr = dst_host;
            {
                ir::IrInstr ad{};
                ad.op = ir::IrOp::ADD;
                ad.type = ir::IrType::I64;
                ad.dst = d_at;
                ad.operands = {addr, v_off};
                ad.source_line = e->loc.line;
                emit(current_block_, std::move(ad));
            }
            emit_store_typed(d_at, w, ir::IrType::I64, e->loc.line);
        }
        if (it_sl != tc_.struct_layouts().end() &&
            it_sl->second.has_copy_hook) {
            emit_struct_method_on_host_field(
                addr, fa->result_type.struct_name,
                fa->result_type.struct_name + "__" + "__clone__",
                e->loc.line);
        }
        out = rhs;
        return true;
    }
    // Campo shared<T> (H5) en contenedor struct: igual que en clase --
    // dec del shared anterior del campo (free-when-0), LOAD ctrl desde el
    // slot origen (rhs), STORE ctrl al campo, inc del refcount.
    if (fa->result_type.kind == PrimitiveKind::SHARED_PTR) {
        emit_shared_refcount_dec(addr, e->loc.line);
        const ir::IrValueId v_ctrl = emit_load_host_ptr(rhs, e->loc.line);
        emit_store_typed(addr, v_ctrl, ir::IrType::I64, e->loc.line);
        emit_shared_refcount_inc(addr, e->loc.line);
        out = rhs;
        return true;
    }
    // Campo normal: STORE directo.
    emit_store_typed(addr, rhs, ft, e->loc.line);
    out = rhs;
    return true;
}

/**
 * @brief Asigna a un elemento: `arr[i] = v`.
 *
 * Es escribir en la direccion del elemento, que sale del mismo calculo que
 * leerlo.  Con dos formas que no lo son: una clase o struct puede definir su
 * propio metodo de escritura por indice, y entonces esto es una llamada; y una
 * coleccion primitiva escribe por su funcion nativa, no por direccion.
 *
 * @param e   La asignacion.
 * @param out Donde dejar el valor asignado.
 * @return @c true si el destino era un indice y quedo bajado.
 */
bool Lowering::try_lower_assign_to_index(ast::AssignExpr *e,
                                         ir::IrValueId &out) {
    if (e->target->kind != ast::NodeKind::IndexExpr) return false;
    auto *ix = static_cast<ast::IndexExpr *>(e->target.get());
    // Operator overloading (escritura): el type checker marco
    // @c ix->index_set_method cuando @c base es CLASS o STRUCT con
    // @c __index_set__(index, value).  Construimos un CallExpr
    // sintetico @c `base.__index_set__(index, value)` y delegamos en
    // la maquinaria de metodos (CALLVIRT para CLASS, CALL para
    // STRUCT).  Robamos los hijos del AST y los restauramos despues.
    if (!ix->index_set_method.empty() && ix->base && ix->index &&
        e->value && e->op == ast::AssignOp::Assign) {
        const bool recv_is_struct =
            (ix->base->result_type.kind == PrimitiveKind::STRUCT);
        ast::CallExpr synth;
        synth.loc = e->loc;
        auto fa = std::make_unique<ast::FieldAccessExpr>();
        fa->loc = e->loc;
        fa->field_name = ix->index_set_method;
        fa->base = std::move(ix->base); // receptor (CLASS o STRUCT)
        synth.callee = std::move(fa);
        synth.args.push_back(std::move(ix->index)); // arg 0: indice
        synth.args.push_back(std::move(e->value));  // arg 1: valor
        ir::IrValueId v_call = recv_is_struct
                                   ? lower_struct_method_call(&synth)
                                   : lower_class_method_call(&synth);
        // Restaurar los hijos a sus nodos originales.
        auto *fa_back =
            static_cast<ast::FieldAccessExpr *>(synth.callee.get());
        ix->base = std::move(fa_back->base);
        ix->index = std::move(synth.args[0]);
        e->value = std::move(synth.args[1]);
        out = v_call;
        return true;
    }
    // String Inc (native_poo_): `s[i] = c` muta el byte i del
    // value-string in-place.  Calculamos data_ptr via el accesor
    // flag-aware (SSO vs HEAP, ya cubre ambos layouts) + STORE u8
    // del char (truncado a byte) en [data + i].  Sin bounds-check
    // (C-style, coherente con `s[i]` lectura).  No altera len.
    if (ix->base && ix->base->result_type.kind == PrimitiveKind::STRING &&
        !ix->is_range) {
        if (!native_poo_) {
            error_at(e->loc,
                     "escritura indexada de string (s[i]=c) solo "
                     "soportada en compilacion nativa (AOT Embed/Bare) "
                     "por ahora");
            out = ir::IR_NO_VALUE;
            return true;
        }
        if (!ix->index) {
            error_at(e->loc, "escritura indexada de string sin indice");
            out = ir::IR_NO_VALUE;
            return true;
        }
        const ir::IrValueId v_src = lower_expr(ix->base.get());
        if (v_src == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        ir::IrValueId v_idx = lower_expr(ix->index.get());
        if (v_idx == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        v_idx = cast_if_needed(v_idx, fn_->values[v_idx].type,
                               ir::IrType::I64, e->loc.line);
        ir::IrValueId v_val = lower_expr(e->value.get());
        if (v_val == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        // Compound `s[i] += c`: leer el byte actual, aplicar el op.
        if (e->op != ast::AssignOp::Assign) {
            const ir::IrValueId v_old =
                build_native_string_index_char(v_src, v_idx, e->loc.line);
            if (v_old == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            const ast::BinOp bop = compound_assign_op_to_binop(e->op);
            v_val =
                emit_binop_ir(bop, v_old, v_val, PrimitiveKind::U8, e->loc);
        }
        // data_ptr (flag-aware) + i -> direccion del byte.
        ir::IrValueId v_ptr = emit_native_str_data_ptr(v_src, e->loc.line);
        ir::IrValueId v_addr = emit_ptr_add(v_ptr, v_idx, e->loc.line);
        // STORE u8: el char rhs se guarda truncado a 1 byte.
        v_val = cast_if_needed(v_val, fn_->values[v_val].type,
                               ir::IrType::U8, e->loc.line);
        emit_store_typed(v_addr, v_val, ir::IrType::U8, e->loc.line);
        out = v_val;
        return true;
    }
    const ir::IrValueId addr = lower_index_addr(ix);
    if (addr == ir::IR_NO_VALUE) {
        (void)lower_expr(e->value.get());
        out = ir::IR_NO_VALUE;
        return true;
    }
    // Caso struct-value en slot de array: `arr[i] = struct_expr`
    // necesita memcpy de sizeof(Struct) bytes desde el RHS PTR al
    // slot (igual que `*ptr = struct_value`).  Sin esto, solo se
    // copia el primer qword.
    // Array de HANDLES overlay: el RHS ya ES el puntero de la vista (8
    // bytes), no la direccion de un payload que copiar.  Excluirlo del
    // memcpy: cae al STORE generico de abajo (pt = PTR) que guarda el
    // puntero tal cual.  Sin esto, `hs[i] = Foo(p)` emitia LOAD [p] +
    // STORE -> guardaba el CONTENIDO apuntado en vez del puntero.
    // `v.arr[i] = ...` (@c is_overlay_array, elemento INLINE en la vista)
    // conserva la copia de bytes: ahi no hay puntero que guardar.
    if ((ix->result_type.kind == PrimitiveKind::STRUCT ||
         ix->result_type.kind == PrimitiveKind::ARRAY) &&
        (ix->is_overlay_array || !type_is_overlay(ix->result_type)) &&
        e->op == ast::AssignOp::Assign) {
        uint64_t struct_size = 0;
        if (ix->result_type.kind == PrimitiveKind::STRUCT) {
            const auto &layouts = tc_.struct_layouts();
            auto it = layouts.find(ix->result_type.struct_name);
            if (it != layouts.end()) {
                struct_size = static_cast<uint64_t>(it->second.size_bytes);
            }
            if (struct_size == 0) {
                const auto &elays = tc_.enum_layouts();
                auto ite = elays.find(ix->result_type.struct_name);
                if (ite != elays.end()) {
                    struct_size =
                        static_cast<uint64_t>(ite->second.size_bytes);
                }
            }
        }
        if (struct_size > 0 && (struct_size % 8) == 0) {
            const ir::IrValueId src = lower_expr(e->value.get());
            if (src == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            const bool src_host = fn_->values[src].is_host_ptr;
            const bool dst_host = fn_->values[addr].is_host_ptr;
            const uint64_t qwords = struct_size / 8;
            for (uint64_t q = 0; q < qwords; ++q) {
                ir::IrValueId off_src = src;
                ir::IrValueId off_dst = addr;
                if (q > 0) {
                    const uint64_t byte_off = q * 8;
                    ir::IrValueId v_off =
                        emit_const(ir::IrType::I64, byte_off, e->loc.line);
                    {
                        ir::IrValueId v_new =
                            fn_->new_value(ir::IrType::PTR);
                        if (src_host) fn_->values[v_new].is_host_ptr = true;
                        ir::IrInstr ad{};
                        ad.op = ir::IrOp::ADD;
                        ad.type = ir::IrType::I64;
                        ad.dst = v_new;
                        ad.operands = {src, v_off};
                        ad.source_line = e->loc.line;
                        emit(current_block_, std::move(ad));
                        off_src = v_new;
                    }
                    {
                        ir::IrValueId v_new =
                            fn_->new_value(ir::IrType::PTR);
                        if (dst_host) fn_->values[v_new].is_host_ptr = true;
                        ir::IrInstr ad{};
                        ad.op = ir::IrOp::ADD;
                        ad.type = ir::IrType::I64;
                        ad.dst = v_new;
                        ad.operands = {addr, v_off};
                        ad.source_line = e->loc.line;
                        emit(current_block_, std::move(ad));
                        off_dst = v_new;
                    }
                }
                ir::IrValueId v_qw =
                    emit_load_typed(off_src, ir::IrType::I64, e->loc.line);
                emit_store_typed(off_dst, v_qw,
                                 ir::IrType::I64, e->loc.line);
            }
            out = addr;
            return true;
        }
    }
    // Bug fix 2026-05-23 (Audit 44): auto-promotion de string literal
    // a StringObject cuando el slot del array es de tipo string.
    // Sin esto, `arr[i] = "lit"` almacenaba la direccion raw del
    // literal y `str_length(arr[i])` daba 0 / garbage.
    ir::IrValueId rhs;
    if (ix->result_type.kind == PrimitiveKind::STRING && e->value &&
        e->value->kind == ast::NodeKind::StringLitExpr) {
        auto *slit = static_cast<ast::StringLitExpr *>(e->value.get());
        rhs = lower_string_literal_to_string_object(slit);
    } else {
        rhs = lower_expr(e->value.get());
    }
    if (rhs == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    const ir::IrType pt = ir_type_from_primitive(ix->result_type.kind);
    // Compound assign: LOAD elemento, op, STORE de vuelta a la
    // misma direccion (calculada una sola vez).  Cubre +=, -= y
    // todos los compound enteros/float sobre arrays e indexados.
    if (e->op != ast::AssignOp::Assign) {
        ir::IrValueId v_old = emit_load_typed(addr, pt, e->loc.line);
        const ast::BinOp bop = compound_assign_op_to_binop(e->op);
        rhs = emit_binop_ir(bop, v_old, rhs, ix->result_type.kind, e->loc);
    }
    rhs = cast_if_needed(rhs, fn_->values[rhs].type, pt,
                         e->value ? e->value->loc : e->loc);
    emit_store_typed(addr, rhs, pt, e->loc.line);
    out = rhs;
    return true;
}

/**
 * @brief Asigna a traves de un puntero: `*p = v`.
 *
 * El destino es el valor del puntero, no una variable, asi que lo unico que
 * hay que decidir es de que ancho es la escritura -- lo dice el tipo apuntado
 * -- y si va a memoria del anfitrion o de la maquina, que lo dice el propio
 * puntero.  Un `*` sobre algo que no es un puntero no llega aqui: no es un
 * lvalue y se rechaza fuera.
 *
 * @param e   La asignacion.
 * @param out Donde dejar el valor asignado.
 * @return @c true si el destino era un desreferenciado y quedo bajado.
 */
bool Lowering::try_lower_assign_to_deref(ast::AssignExpr *e,
                                         ir::IrValueId &out) {
    if (e->target->kind != ast::NodeKind::UnaryExpr) return false;
    auto *un = static_cast<ast::UnaryExpr *>(e->target.get());
    if (un->op == ast::UnOp::Deref) {
        // Bajar el puntero (operando del Deref) y el valor.
        const ir::IrValueId addr = lower_expr(un->operand.get());
        if (addr == ir::IR_NO_VALUE) {
            (void)lower_expr(e->value.get());
            out = ir::IR_NO_VALUE;
            return true;
        }
        // Caso struct-value assign `*ptr = struct_expr`: el lowering
        // generico emite un solo STORE de 8 bytes (ptr value), lo
        // que SOLO copia el primer qword del struct.  Para structs
        // reales necesitamos memcpy del payload completo.
        // El tipo que manda es el de lo que se ASIGNA.  Mirar solo el del
        // deref se queda corto en una instancia monomorfizada: alli el
        // parametro llega como puntero generico y el deref no dice STRUCT,
        // asi que `(*out) = valor` guardaba LA DIRECCION del struct en vez
        // de sus bytes -- una generica con `T` struct devolvia punteros
        // como si fueran valores.  Si cualquiera de los dos lados es un
        // agregado, se copia.
        const Type &deref_t = un->result_type;
        const Type &value_t = e->value->result_type;
        const bool deref_agg = (deref_t.kind == PrimitiveKind::STRUCT ||
                                deref_t.kind == PrimitiveKind::ARRAY);
        const bool value_agg = (value_t.kind == PrimitiveKind::STRUCT ||
                                value_t.kind == PrimitiveKind::ARRAY);
        if ((deref_agg || value_agg) && e->op == ast::AssignOp::Assign) {
            // Calcular sizeof.  STRUCT: lookup en struct_layouts_;
            // ARRAY: type.array_size * sizeof(elt) si conocido.
            uint64_t struct_size = 0;
            const Type &agg_t = deref_agg ? deref_t : value_t;
            if (agg_t.kind == PrimitiveKind::STRUCT) {
                const auto &layouts = tc_.struct_layouts();
                auto it = layouts.find(agg_t.struct_name);
                if (it != layouts.end()) {
                    struct_size =
                        static_cast<uint64_t>(it->second.size_bytes);
                }
                // Tambien enum (encoded como STRUCT con struct_name).
                if (struct_size == 0) {
                    const auto &elays = tc_.enum_layouts();
                    auto ite = elays.find(agg_t.struct_name);
                    if (ite != elays.end()) {
                        struct_size =
                            static_cast<uint64_t>(ite->second.size_bytes);
                    }
                }
            }
            if (struct_size > 0 && (struct_size % 8) == 0) {
                // Bajar RHS para obtener el PTR fuente.
                const ir::IrValueId src = lower_expr(e->value.get());
                if (src == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
                // Copia qword a qword.  Para size_bytes no multiplo
                // de 8 usariamos byte-loops; los structs Vesta tienen
                // padding a 8-bytes por field-alignment, asi que
                // size_bytes siempre es multiplo de 8 para Vesta
                // structs.  Defensa por bytes <8: fall-through.
                // Propagamos is_host_ptr de src/addr a los LOAD/STORE
                // para emitir movh cuando corresponda.
                const bool src_host = fn_->values[src].is_host_ptr;
                const bool dst_host = fn_->values[addr].is_host_ptr;
                const uint64_t qwords = struct_size / 8;
                for (uint64_t q = 0; q < qwords; ++q) {
                    // src + q*8
                    ir::IrValueId off_src = src;
                    ir::IrValueId off_dst = addr;
                    if (q > 0) {
                        const uint64_t byte_off = q * 8;
                        ir::IrValueId v_off = emit_const(
                            ir::IrType::I64, byte_off, e->loc.line);
                        // src + off
                        {
                            ir::IrValueId v_new =
                                fn_->new_value(ir::IrType::PTR);
                            if (src_host)
                                fn_->values[v_new].is_host_ptr = true;
                            ir::IrInstr ad{};
                            ad.op = ir::IrOp::ADD;
                            ad.type = ir::IrType::I64;
                            ad.dst = v_new;
                            ad.operands = {src, v_off};
                            ad.source_line = e->loc.line;
                            emit(current_block_, std::move(ad));
                            off_src = v_new;
                        }
                        {
                            ir::IrValueId v_new =
                                fn_->new_value(ir::IrType::PTR);
                            if (dst_host)
                                fn_->values[v_new].is_host_ptr = true;
                            ir::IrInstr ad{};
                            ad.op = ir::IrOp::ADD;
                            ad.type = ir::IrType::I64;
                            ad.dst = v_new;
                            ad.operands = {addr, v_off};
                            ad.source_line = e->loc.line;
                            emit(current_block_, std::move(ad));
                            off_dst = v_new;
                        }
                    }
                    // LOAD i64 del src + q*8
                    ir::IrValueId v_qw =
                        emit_load_typed(off_src, ir::IrType::I64, e->loc.line);
                    // STORE al dst + q*8
                    emit_store_typed(off_dst, v_qw,
                                     ir::IrType::I64, e->loc.line);
                }
                out = addr;
                return true;
            }
            // Si no se pudo calcular el size, cae al path generico
            // (que solo copia 8 bytes -- bug documentado).
        }
        // Bug fix 2026-05-23 (Audit 45): auto-promotion para `*p = "lit"`
        // cuando p es string* (deref produce STRING).
        ir::IrValueId rhs;
        if (un->result_type.kind == PrimitiveKind::STRING && e->value &&
            e->value->kind == ast::NodeKind::StringLitExpr) {
            auto *slit = static_cast<ast::StringLitExpr *>(e->value.get());
            rhs = lower_string_literal_to_string_object(slit);
        } else {
            rhs = lower_expr(e->value.get());
        }
        if (rhs == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

        const ir::IrType pt = ir_type_from_primitive(un->result_type.kind);
        // Compound assign sobre '*p': LOAD valor actual, op, STORE.
        if (e->op != ast::AssignOp::Assign) {
            ir::IrValueId v_old = emit_load_typed(addr, pt, e->loc.line);
            const ast::BinOp bop = compound_assign_op_to_binop(e->op);
            rhs = emit_binop_ir(bop, v_old, rhs, un->result_type.kind,
                                e->loc);
        }
        rhs = cast_if_needed(rhs, fn_->values[rhs].type, pt, e->loc.line);
        emit_store_typed(addr, rhs, pt, e->loc.line);
        out = rhs;
        return true;
    }
    return false;
}

} // namespace vx
