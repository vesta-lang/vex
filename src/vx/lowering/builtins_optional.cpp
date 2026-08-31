/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_optional.cpp
 * @brief Bajada de lo que puede NO estar: `Optional<T>` y `Result<T, E>`.
 *
 * Un `Optional` no es un puntero que a veces vale nulo y un `Result` no es un
 * codigo de error devuelto por convenio: los dos son un valor que lleva
 * consigo si esta o no esta, y el lenguaje no deja mirar dentro sin haber
 * preguntado antes.  Eso es todo lo que hacen estos diez builtins --
 * construirlos (`Some`, `None`, `Ok`, `Err`), preguntar (`isPresent`, `isOk`)
 * y sacar lo de dentro (`value`, `error`, `unwrap`) --.
 *
 * Lo importante de como bajan: NO tocan el monton.  Un Optional vive en la
 * pila como un par {hay, valor} y se devuelve por la direccion que da el
 * llamante, asi que envolver un valor no cuesta una reserva de memoria.  Por
 * eso construirlos y consultarlos esta aqui y no en una libreria: son forma
 * del codigo generado, no llamadas.
 *
 * Y hay dos maneras de sacar el valor, a proposito: `unwrap` comprueba y lanza
 * si no estaba, y `unwrap_unchecked` no comprueba nada -- baja a leer el
 * campo, sin mas --.  El segundo existe para quien YA comprobo y no quiere
 * pagarlo dos veces; si se equivoca, lee basura.  Ninguno de los dos es el
 * predeterminado del otro.
 *
 * Se separo de la funcion que despacha todos los builtins.  Entra por su
 * propio punto: si el nombre no es de esta familia, contesta que no y quien
 * pregunta sigue con las demas.
 */
#include "vx/lowering.h"
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
 * @copydoc vx::Lowering::emit_optional_present
 */
ir::IrValueId Lowering::emit_optional_present(ir::IrValueId v_arg,
                                              const Type &at, int line) {
    /* Como se responde depende de como este puesto en memoria.  Con marca
     * aparte se lee la marca; sin ella, la lleva el propio valor -- si no puede
     * ser cero, que no sea cero ES la marca -- y la pregunta pasa a ser la
     * misma que para un puntero crudo.  Preguntandolo aqui, el dia que la
     * disposicion cambie no hay que tocar a quien la use. */
    if (at.kind == PrimitiveKind::OPTIONAL) {
        const OptionalLayout lay = optional_layout(at);
        if (lay.has_tag) return emit_load_typed(v_arg, ir::IrType::I32, line);
        v_arg = emit_load_typed(v_arg, ir::IrType::I64, line);
    }
    /* Referencia (o valor sin marca): hay algo si no es nulo.  Dos operaciones
     * de IR en vez de ensamblador escrito a mano, para que el eliminador de
     * codigo muerto pueda quitar la cadena entera si nadie mira la respuesta y
     * el JIT trate cada paso de forma nativa. */
    const ir::IrValueId v_es_nulo =
        emit_ir_unop(ir::IrOp::ISNULL, v_arg, ir::IrType::I32, line);
    const ir::IrValueId v_uno = emit_const(ir::IrType::I32, 1, line);
    return emit_ir_binop(ir::IrOp::XOR, v_es_nulo, v_uno, ir::IrType::I32,
                         line);
}

/**
 * @copydoc vx::Lowering::emit_optional_value
 */
ir::IrValueId Lowering::emit_optional_value(ir::IrValueId v_arg, const Type &at,
                                            bool checked, int line) {
    if (at.kind == PrimitiveKind::OPTIONAL) {
        const Type payload_st =
            at.pointee ? *at.pointee : Type{PrimitiveKind::I64};
        const ir::IrType payload_t = ir_type_from_primitive(payload_st.kind);
        const OptionalLayout lay = optional_layout(at);
        if (checked) {
            /* Lo que hay en el desplazamiento cero es lo que decide si el valor
             * esta: la marca cuando va aparte, y el valor mismo cuando no.  En
             * los dos casos la comprobacion es la misma: fallar si es cero. */
            const ir::IrValueId v_marca =
                emit_load_typed(v_arg, ir::IrType::I64, line);
            (void)enforce_nonnull(v_marca, line);
        }
        // Y el valor, donde la disposicion diga.
        const ir::IrValueId v_off = emit_const(
            ir::IrType::I64, static_cast<uint64_t>(lay.value_offset), line);
        const ir::IrValueId v_at = emit_ptr_add(v_arg, v_off, line);
        // BugFix sret-cross-mem: el puntero al valor es de la misma memoria que
        // el buffer.  Sin esto, un Optional en un buffer del anfitrion -- el
        // que devuelve una funcion -- se leia con la instruccion de la maquina
        // virtual y daba cero.
        fn_->values[v_at].is_host_ptr = fn_->values[v_arg].is_host_ptr;
        // Un agregado no se carga en un registro: su valor ES su direccion.  Se
        // devuelve el puntero y quien lo consuma copia los bytes que necesite.
        if (payload_st.kind == PrimitiveKind::STRUCT &&
            !payload_st.struct_name.empty())
            return v_at;
        const ir::IrValueId v_dst = emit_load_typed(v_at, payload_t, line);
        /* Y se dice de que memoria es lo que sale, que es la misma regla que
         * para el resultado de cualquier llamada: sin la marca, sacar un
         * `Optional<T*>` daba un puntero que luego se dereferenciaba con la
         * instruccion equivocada y valia cero. */
        mark_value_from_type(v_dst, payload_st);
        return v_dst;
    }
    /* Referencia nullable: el valor ES el puntero.  Sin comprobar es la
     * identidad -- cero IR, cero coste --; comprobando, lo unico que se anade
     * es la afirmacion. */
    if (!checked) return v_arg;
    return enforce_nonnull(v_arg, line);
}

/**
 * @brief Intenta bajar @p e como uno de los builtins de Optional / Result.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado; sin valor si el builtin no lo da.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_optional_builtins(ast::CallExpr *e, Builtin b,
                                           ir::IrValueId &out_value) {
    // Optional sobre referencias, que baja a las instrucciones isnull/unwrap
    // de la maquina en vez de al par {hay, valor}.
    const bool is_isPresent = (b == Builtin::IsPresent);
    const bool is_unwrap = (b == Builtin::Unwrap);
    // unwrap_unchecked: renunciar a la comprobacion en UN sitio.  Misma forma
    // que unwrap pero sin el chequeo (baja a leer el payload directo); si el
    // valor no estaba, lee basura.
    const bool is_unwrap_unchecked = (b == Builtin::UnwrapUnchecked);
    // Los que NO afirman nada: preguntan y eligen.  Son la salida recuperable,
    // y estan aqui para que sea la comoda: sin ellos, lo unico que quedaba era
    // escribir el `if` a mano, y eso empuja a afirmar por pereza.
    const bool is_unwrap_or = (b == Builtin::UnwrapOr);
    const bool is_expect = (b == Builtin::Expect);
    // Construir y consultar los que viven en la PILA.
    const bool is_Some = (b == Builtin::Some);
    const bool is_None = (b == Builtin::None);
    const bool is_Ok = (b == Builtin::Ok);
    const bool is_Err = (b == Builtin::Err);
    const bool is_isOk = (b == Builtin::IsOk);
    const bool is_value = (b == Builtin::Value);
    const bool is_error = (b == Builtin::Error);

    /* Salida rapida: si no es de esta familia no se mira nada de lo de abajo.
     */
    if (!(is_isPresent || is_unwrap || is_unwrap_unchecked || is_unwrap_or ||
          is_expect || is_Some || is_None || is_Ok || is_Err || is_isOk ||
          is_value || is_error))
        return false;

    if (is_Some) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "Some: requiere 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_payload = lower_expr(e->args[0].get());
        if (v_payload == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // Un payload STRUCT viaja por DIRECCION, no por valor: hay que copiar
        // sus bytes al buffer y dimensionarlo para que quepan.  Guardando el
        // puntero (lo que se hacia antes) el `Some` sobrevivia al ALLOCA que
        // apuntaba y `unwrap` leia memoria muerta -> devolvia 0 en silencio.
        const Type &arg_t = e->args[0]->result_type;
        /* Un `@overlay` NO es un struct por valor: no reserva nada, es una
         * VISTA TIPADA sobre un puntero, y su valor ES ese puntero (8 bytes).
         * Copiar "sus bytes" copiaba los primeros 8 bytes del OBJETO VISTO, con
         * lo que el `Some` guardaba `*base` en vez de `base` y el consumidor
         * leia campos en direcciones inventadas.  Se guarda el handle, como
         * cualquier otro valor de 8 bytes; el objeto sigue viviendo donde
         * vivia. */
        const bool payload_is_struct = (arg_t.kind == PrimitiveKind::STRUCT) &&
                                       !arg_t.struct_name.empty() &&
                                       !type_is_overlay(arg_t);
        const size_t payload_sz = payload_is_struct ? size_of_type(arg_t) : 8u;
        /* Cuanto ocupa y donde va cada cosa lo decide `optional_layout`, no
         * este sitio: aqui habia una sexta copia del calculo del tamano, y la
         * marca y el valor iban clavados en el cero y el ocho.  Con eso, hacer
         * que un `Optional` ocupe menos habria que escribirlo tambien aqui. */
        const OptionalLayout lay = optional_layout(e->result_type);
        const ir::IrValueId v_buf =
            stack_alloc_buf(lay.bytes, e->loc.line, /*host_memory=*/true);
        // La marca, si la disposicion dice que va aparte.
        if (lay.has_tag) {
            const ir::IrValueId v_one =
                emit_const(ir::IrType::I64, 1, e->loc.line);
            emit_store_typed(v_buf, v_one, ir::IrType::I64, e->loc.line);
        }
        // Y el valor, donde la disposicion diga.
        const ir::IrValueId v_off =
            emit_const(ir::IrType::I64, static_cast<uint64_t>(lay.value_offset),
                       e->loc.line);
        const ir::IrValueId v_buf8 = emit_ptr_add(v_buf, v_off, e->loc.line);
        // BugFix sret-cross-mem: propagar is_host_ptr del buffer al puntero
        // buf+8.  Sin esto, el STORE del payload usa acceso VM (`mov`) sobre un
        // buffer HOST (stack_alloc_buf con host_alloca) -> el valor se escribe
        // a memoria VM en una direccion host (fuera de rango) y se pierde
        // (unwrap devuelve 0).  Funcionaba por SUERTE cuando la direccion del
        // alloc caia en rango VM.  Ok/Err ya tenian esta propagacion; Some no.
        fn_->values[v_buf8].is_host_ptr = fn_->values[v_buf].is_host_ptr;
        if (payload_is_struct) {
            // Copia de los bytes del struct al payload.  `v_payload` es la
            // direccion del agregado (asi viajan los structs por valor aqui).
            const ir::IrValueId v_len =
                emit_const(ir::IrType::I64, static_cast<uint64_t>(payload_sz),
                           e->loc.line);
            ir::IrInstr mc{};
            mc.op = ir::IrOp::MEMCPY;
            mc.type = ir::IrType::I8;
            mc.dst = ir::IR_NO_VALUE;
            mc.operands = {v_buf8, v_payload, v_len};
            mc.source_line = e->loc.line;
            emit(current_block_, std::move(mc));
        } else {
            const ir::IrType payload_t = fn_->values[v_payload].type;
            emit_store_typed(v_buf8, v_payload, payload_t, e->loc.line);
        }
        out_value = v_buf;
        return true;
    }
    // ----- None() -----  Optional vacio (flag=0) en stack.
    if (is_None) {
        /* El buffer se dimensiona por el Optional QUE SE ESPERA, no a 16 fijo.
         *
         * Un `Optional<u128>` mide 24 (tag + los 16 del struct), y quien
         * devuelve copia al retbuf tantos qwords como diga el TIPO DE RETORNO:
         * con 16 reservados, esa copia leia el tercer qword fuera del buffer --
         * memoria de pila sin inicializar.  No se notaba porque en un `None`
         * nadie mira el payload, pero el acceso era real: lo señalo el
         * comprobador de limites de `--analyze` (`region [0,16) ; acceso
         * [16,24)`) en `checked_div` y en 17 programas mas del corpus.
         *
         * Con el tipo a mano se usa el mismo calculo que el resto del camino
         * (`optional_buf_bytes`); si el contexto no lo da, se queda en 16 como
         * antes. */
        size_t none_sz = 16;
        if (e->result_type.kind == PrimitiveKind::OPTIONAL)
            none_sz = optional_buf_bytes(e->result_type);
        else if (sret_active_ && sret_buf_size_ >= 16)
            none_sz = static_cast<size_t>(sret_buf_size_);
        const ir::IrValueId v_buf =
            stack_alloc_buf(none_sz, e->loc.line, /*host_memory=*/true);
        const ir::IrValueId v_zero =
            emit_const(ir::IrType::I64, 0, e->loc.line);
        emit_store_typed(v_buf, v_zero, ir::IrType::I64, e->loc.line);
        out_value = v_buf;
        return true;
    }
    // ----- Ok(v) ----- / ----- Err(e) -----  Result<V,E> en heap.
    //   Layout: [+0 i64 tag (1=ok, 0=err)][+8 V][+16 E]. 24 bytes.
    if (is_Ok || is_Err) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc,
                                 (is_Ok ? "Ok" : "Err") +
                                     std::string(": requiere 1 argumento"),
                                 out_value);
        }
        // Bug fix 2026-05-23: si el payload esperado del Result es STRING
        // y el arg es StringLitExpr no interpolado, promover a StringObject
        // ANTES del STORE.  Sin esto, el handle guardado seria el ptr
        // raw del literal -> garbage en isOk/value/error.  El expected_type
        // viene de e->result_type que ya fue calculado en check_call.
        ir::IrValueId v_payload;
        bool need_str_promo = false;
        if (e->args[0] && e->args[0]->kind == ast::NodeKind::StringLitExpr &&
            e->result_type.kind == PrimitiveKind::RESULT) {
            const Type *target = is_Ok ? e->result_type.pointee.get()
                                       : e->result_type.pointee2.get();
            if (target && target->kind == PrimitiveKind::STRING) {
                need_str_promo = true;
            }
        }
        if (need_str_promo) {
            auto *slit = static_cast<ast::StringLitExpr *>(e->args[0].get());
            v_payload = lower_string_literal_to_string_object(slit);
        } else {
            v_payload = lower_expr(e->args[0].get());
        }
        if (v_payload == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        /* Cuanto ocupa y donde va cada cosa lo dice `result_layout`, no este
         * sitio: aqui estaban clavados el veinticuatro y los desplazamientos
         * ocho y dieciseis, asi que un `Result` cuyo valor fuera un struct de
         * mas de una palabra no cabia. */
        const ResultLayout lay = tc_.result_layout(e->result_type);
        const ir::IrValueId v_buf =
            stack_alloc_buf(lay.bytes, e->loc.line, /*host_memory=*/true);
        // La marca.
        const ir::IrValueId v_tag =
            emit_const(ir::IrType::I64, is_Ok ? 1 : 0, e->loc.line);
        emit_store_typed(v_buf, v_tag, ir::IrType::I64, e->loc.line);
        // Y el payload, donde la disposicion diga.
        const ir::IrValueId v_off = emit_const(
            ir::IrType::I64,
            static_cast<uint64_t>(is_Ok ? lay.value_offset : lay.error_offset),
            e->loc.line);
        const ir::IrValueId v_at = emit_ptr_add(v_buf, v_off, e->loc.line);
        // BugFix sret-cross-mem (2026-06-04): propagar is_host_ptr.
        fn_->values[v_at].is_host_ptr = fn_->values[v_buf].is_host_ptr;
        /* Un agregado no viaja en un registro: su valor ES su direccion, asi
         * que hay que COPIAR sus bytes.  Guardandolo como una palabra se
         * guardaba la direccion de algo que muere, y lo que se sacaba eran
         * ceros -- el mismo fallo que tenia `Some` y se arreglo igual. */
        const Type *pt = is_Ok ? e->result_type.pointee.get()
                               : e->result_type.pointee2.get();
        if (pt && pt->kind == PrimitiveKind::STRUCT &&
            !pt->struct_name.empty() && !type_is_overlay(*pt)) {
            const ir::IrValueId v_len =
                emit_const(ir::IrType::I64,
                           static_cast<uint64_t>(tc_.payload_slot_bytes(*pt)),
                           e->loc.line);
            ir::IrInstr mc{};
            mc.op = ir::IrOp::MEMCPY;
            mc.type = ir::IrType::I8;
            mc.dst = ir::IR_NO_VALUE;
            mc.operands = {v_at, v_payload, v_len};
            mc.source_line = e->loc.line;
            emit(current_block_, std::move(mc));
        } else {
            const ir::IrType payload_t = fn_->values[v_payload].type;
            emit_store_typed(v_at, v_payload, payload_t, e->loc.line);
        }
        out_value = v_buf;
        return true;
    }
    // ----- isOk(r) -----  LOAD i64 at +0; returns 1/0 as i32.
    if (is_isOk) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "isOk: requiere 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_buf = lower_expr(e->args[0].get());
        if (v_buf == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const ir::IrValueId v_dst =
            emit_load_typed(v_buf, ir::IrType::I32, e->loc.line);
        out_value = v_dst;
        return true;
    }
    // ----- value(r) -----  LOAD V from r+8 (sin tag check en MVP).
    // ----- error(r) -----  LOAD E from r+16 (sin tag check en MVP).
    if (is_value || is_error) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "value/error: requiere 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_buf = lower_expr(e->args[0].get());
        if (v_buf == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const Type at = e->args[0]->result_type;
        Type payload_st =
            (is_value
                 ? (at.pointee ? *at.pointee : Type{PrimitiveKind::I64})
                 : (at.pointee2 ? *at.pointee2 : Type{PrimitiveKind::I64}));
        const ir::IrType payload_t = ir_type_from_primitive(payload_st.kind);
        // Donde esta cada cosa lo dice la disposicion, no este sitio.
        const ResultLayout lay = tc_.result_layout(at);
        const ir::IrValueId v_off =
            emit_const(ir::IrType::I64,
                       static_cast<uint64_t>(is_value ? lay.value_offset
                                                      : lay.error_offset),
                       e->loc.line);
        const ir::IrValueId v_at = emit_ptr_add(v_buf, v_off, e->loc.line);
        // BugFix sret-cross-mem (2026-06-04): propagar is_host_ptr de
        // v_buf al v_at para que el LOAD downstream emita `movh`/`loadzh`.
        fn_->values[v_at].is_host_ptr = fn_->values[v_buf].is_host_ptr;
        /* Un agregado no se carga en un registro: su valor ES su direccion.
         * Se devuelve el puntero y quien lo consuma copia lo que necesite --
         * igual que hace `unwrap` sobre un `Optional<struct>`. */
        if (payload_st.kind == PrimitiveKind::STRUCT &&
            !payload_st.struct_name.empty()) {
            out_value = v_at;
            return true;
        }
        const ir::IrValueId v_dst =
            emit_load_typed(v_at, payload_t, e->loc.line);
        mark_value_from_type(v_dst, payload_st);
        out_value = v_dst;
        return true;
    }

    // ----- isPresent(x) -----
    // La pregunta la contesta `emit_optional_present`, que es la misma que se
    // hace `unwrap_or` para elegir rama.
    if (is_isPresent) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc,
                                 "isPresent: requiere exactamente 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_arg = lower_expr(e->args[0].get());
        if (v_arg == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        out_value =
            emit_optional_present(v_arg, e->args[0]->result_type, e->loc.line);
        return true;
    }

    // ----- unwrap_or(x, def) -----  y  ----- expect(x, "msg") -----
    //
    // Los dos se montan con las MISMAS dos piezas que `isPresent` y `unwrap`:
    // preguntar si hay, y sacar el valor.  Ninguno vuelve a escribir como se
    // lee un Optional.
    if (is_unwrap_or || is_expect) {
        if (e->args.size() != 2) {
            out_value = ir::IR_NO_VALUE;
            return true; // el comprobador de tipos ya lo dijo
        }
        const ir::IrValueId v_arg = lower_expr(e->args[0].get());
        if (v_arg == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const Type at = e->args[0]->result_type;
        if (is_expect) {
            /* `expect` es `unwrap` con una pista.  Desde que fallar es fatal,
             * el mensaje del sitio es lo unico que dice QUE se dio por hecho;
             * el mensaje generico del catalogo y la traza los sigue poniendo el
             * runtime detras.
             *
             * Solo se escribe cuando NO hay nada, asi que el camino bueno no
             * paga: la rama esta y no se toma.  Y el texto es conocido al
             * compilar -- por eso el comprobador exige una cadena escrita en el
             * sitio --, asi que no hay que construir nada en ejecucion. */
            std::string msg;
            if (e->args[1]->kind == ast::NodeKind::StringLitExpr)
                msg =
                    static_cast<ast::StringLitExpr *>(e->args[1].get())->value;
            const ir::IrValueId v_hay =
                emit_optional_present(v_arg, at, e->loc.line);
            const ir::IrValueId v_cero =
                emit_const(ir::IrType::I64, 0, e->loc.line);
            (void)emit_branching_select(
                v_hay, [&] { return v_cero; },
                [&] {
                    emit_print_string_literal("expect: " + msg + "\n",
                                              e->loc.line);
                    return v_cero;
                },
                "expect", e->loc.line);
            out_value =
                emit_optional_value(v_arg, at, /*checked=*/true, e->loc.line);
            return true;
        }
        /* `unwrap_or` NO afirma nada, asi que no puede fallar: se pregunta y se
         * elige.  El valor solo se lee en la rama donde lo hay, que es lo que
         * lo hace seguro. */
        const ir::IrValueId v_hay =
            emit_optional_present(v_arg, at, e->loc.line);
        out_value = emit_branching_select(
            v_hay,
            [&] {
                return emit_optional_value(v_arg, at, /*checked=*/false,
                                           e->loc.line);
            },
            [&] { return lower_expr(e->args[1].get()); }, "unwrap_or",
            e->loc.line);
        return true;
    }

    // ----- unwrap(x) / unwrap_unchecked(x) -----
    // Sacar el valor lo hace `emit_optional_value`; lo unico que cambia entre
    // los dos es si ademas se afirma que hay algo.
    if (is_unwrap || is_unwrap_unchecked) {
        const char *bn = is_unwrap_unchecked ? "unwrap_unchecked" : "unwrap";
        if (e->args.size() != 1) {
            return builtin_error(
                e->loc, std::string(bn) + ": requiere exactamente 1 argumento",
                out_value);
        }
        const ir::IrValueId v_arg = lower_expr(e->args[0].get());
        if (v_arg == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        out_value = emit_optional_value(v_arg, e->args[0]->result_type,
                                        /*checked=*/is_unwrap, e->loc.line);
        return true;
    }

    return false;
}

} // namespace vx
