/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_string.cpp
 * @brief Bajada de lo que se hace CON una cadena: medirla, cortarla, unirla,
 *        compararla y sacarla al exterior.
 *
 * Una cadena de Vesta no es un vector de bytes: es una secuencia de puntos de
 * codigo, y por dentro sabe en que codificacion los guarda.  Eso hace que
 * `length` no sea `bytes` -- una tilde ocupa uno y mide uno, pero no son la
 * misma pregunta -- y que unir dos cadenas de codificaciones distintas tenga
 * respuesta en vez de dar basura.
 *
 * Lo que se paga y lo que no: cada uno de estos baja a UNA instruccion de la
 * maquina, no a una llamada.  Medir es leer un campo que ya esta calculado;
 * el resumen se calcula la primera vez que se pide y se guarda; cortar no
 * copia -- da una vista sobre la original --, y solo al necesitar los bytes
 * seguidos se materializa.  Por eso partir una cadena en un bucle no reserva
 * memoria en cada vuelta.
 *
 * Y la frontera: `cstr` y `wstr` son lo unico que devuelve bytes crudos, y
 * existen para hablar con codigo que no es Vesta -- las dos formas de las APIs
 * de Windows, una por codificacion --.  `convert` es el unico que reescribe de
 * verdad: decodifica a puntos de codigo y vuelve a codificar en el destino,
 * que es lo que hace que cualquier par de codificaciones funcione y no solo
 * las dos habituales.
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
 * @brief Intenta bajar @p e como uno de los builtins de cadena.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado; sin valor si el builtin no lo da.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_string_builtins(ast::CallExpr *e, Builtin b,
                                         ir::IrValueId &out_value) {
    /* Cada uno baja a UNA instruccion de la maquina, no a una llamada.
     *
     * Los nombres `comptime_*` son los mismos builtins vistos desde el cuerpo
     * de una macro: alli el comprobador de tipos ya los evaluo, y lo que queda
     * es emitir el mismo codigo que emitiria la version normal.  Por eso
     * comparten bandera en vez de tener bloque propio. */
    const bool is_str_length =
        (b == Builtin::StrLength || b == Builtin::ComptimeStrlen);
    const bool is_str_bytes = (b == Builtin::StrBytes);
    // Sacar los bytes crudos: la unica frontera con lo que no es Vesta.
    const bool is_str_cstr = (b == Builtin::StrCstr);
    const bool is_str_wstr = (b == Builtin::StrWstr);
    // Resumirla y quedarse con una sola copia de las iguales.
    const bool is_str_hash = (b == Builtin::StrHash);
    const bool is_str_intern = (b == Builtin::StrIntern);
    const bool is_str_concat =
        (b == Builtin::StrConcat || b == Builtin::ComptimeConcat);
    const bool is_str_equals =
        (b == Builtin::StrEquals || b == Builtin::ComptimeStreq);
    // Fabricar una desde bytes, y reescribirla en otra codificacion.
    const bool is_str_make = (b == Builtin::StrMake);
    const bool is_str_convert = (b == Builtin::StrConvert);
    // Convertir a texto, entre caracter y su codigo, y cortar.
    const bool is_to_str = (b == Builtin::ToStr || b == Builtin::ComptimeToStr);
    const bool is_chr_b = (b == Builtin::Chr || b == Builtin::ComptimeChr);
    const bool is_ord_b = (b == Builtin::Ord || b == Builtin::ComptimeOrd);
    const bool is_substr_b =
        (b == Builtin::Substr || b == Builtin::ComptimeSubstr);
    // Repetir, reemplazar y buscar dentro.
    const bool is_repeat_b =
        (b == Builtin::Repeat || b == Builtin::ComptimeRepeat);
    const bool is_replace_b =
        (b == Builtin::Replace || b == Builtin::ComptimeReplace);
    const bool is_contains_b =
        (b == Builtin::Contains || b == Builtin::ComptimeContains);

    /* Salida rapida: si no es de esta familia no se mira nada de lo de abajo.
     */
    if (!(is_str_length || is_str_bytes || is_str_cstr || is_str_wstr ||
          is_str_hash || is_str_intern || is_str_concat || is_str_equals ||
          is_str_make || is_str_convert || is_to_str || is_chr_b || is_ord_b ||
          is_substr_b || is_repeat_b || is_replace_b || is_contains_b))
        return false;

    if (is_to_str) {
        /* to_str(int) -> string.  Reusa el helper
         * stringify_primitive_via_native con vio_int_to_vmbuf. */
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "to_str: se esperaba 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_val = lower_expr(e->args[0].get());
        if (v_val == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        out_value = stringify_primitive_via_native(v_val, "vio_int_to_vmbuf",
                                                   e->loc.line);
        return true;
    }

    if (is_chr_b) {
        /* chr(codepoint) -> string.  Reusa vio_char_to_vmbuf
         * (codepoint -> UTF-8 bytes -> STRMAKE). */
        if (e->args.size() != 1) {
            return builtin_error(
                e->loc, "chr: se esperaba 1 argumento (codepoint)", out_value);
        }
        const ir::IrValueId v_cp = lower_expr(e->args[0].get());
        if (v_cp == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        out_value = stringify_primitive_via_native(v_cp, "vio_char_to_vmbuf",
                                                   e->loc.line);
        return true;
    }

    if (is_ord_b) {
        /* ord(s) -> u64.  Devuelve el primer codepoint del string.
         * Fast path ASCII: emit strraw + LOAD u8 (host).  Para
         * multi-byte UTF-8 retorna solo el primer byte (lead byte);
         * el caller puede decodear si necesita el codepoint real. */
        if (e->args.size() != 1) {
            return builtin_error(
                e->loc, "ord: se esperaba 1 argumento (string)", out_value);
        }
        const ir::IrValueId v_str = lower_expr(e->args[0].get());
        if (v_str == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        /* strraw r_raw, r_str  -> host_ptr a bytes */
        ir::IrValueId v_raw = emit_strraw(v_str, e->loc.line);
        /* LOAD.u8 al primer byte (host).  El IR LOAD con is_host_ptr
         * en la fuente emite `movh` automaticamente. */
        ir::IrValueId v_byte =
            emit_load_byte(v_raw, e->loc.line, ir::IrType::U64);
        out_value = v_byte;
        return true;
    }

    if (is_substr_b) {
        /* substr(s, start, len) -> string.  Empaqueta start+len en
         * un u64 (hi<<32 | lo) y emite strslice. */
        if (e->args.size() != 3) {
            return builtin_error(
                e->loc, "substr: se esperaba 3 argumentos (string, start, len)",
                out_value);
        }
        const ir::IrValueId v_str = lower_expr(e->args[0].get());
        const ir::IrValueId v_start = lower_expr(e->args[1].get());
        const ir::IrValueId v_len = lower_expr(e->args[2].get());
        if (v_str == ir::IR_NO_VALUE || v_start == ir::IR_NO_VALUE ||
            v_len == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        /* Pack: r_range = (start << 32) | len */
        ir::IrValueId v_shifted = fn_->new_value(ir::IrType::U64);
        {
            ir::IrInstr sh{};
            sh.op = ir::IrOp::SHL;
            sh.type = ir::IrType::U64;
            sh.dst = v_shifted;
            sh.operands = {v_start,
                           emit_const(ir::IrType::U64, 32, e->loc.line)};
            sh.source_line = e->loc.line;
            emit(current_block_, std::move(sh));
        }
        ir::IrValueId v_range = emit_ir_binop(ir::IrOp::OR, v_shifted, v_len,
                                              ir::IrType::U64, e->loc.line);
        ir::IrValueId v_dst = fn_->new_value(ir::IrType::I64);
        {
            ir::IrInstr sl{};
            sl.op = ir::IrOp::STRSLICE;
            sl.type = ir::IrType::I64;
            sl.dst = v_dst;
            sl.operands = {v_str, v_range};
            sl.source_line = e->loc.line;
            sl.is_call_site = true;
            emit(current_block_, std::move(sl));
        }
        out_value = v_dst;
        return true;
    }

    if (is_repeat_b || is_replace_b || is_contains_b) {
        /*  MC.15D: builtins de string que requieren acceso a
         * los bytes RAW de StringObjects (via STRRAW) y un buffer
         * destino en vm_mem.  Layout comun:
         *   1. Resolver SSA values de cada arg (string -> handle).
         *      AUTO-PROMOCION: literals string como `"{a}"` no son
         *      StringObjects; los promovemos via STRMAKE antes de
         *      hacer STRRAW.  Sin esto, STRRAW recibe un raw ptr a
         *      static_data y devuelve garbage.  Mismo patron que
         *      str_concat / str_equals.
         *   2. Para cada string arg: emitir STRRAW + STRGETBYTES
         *      para obtener host_ptr + length.  Pasar host_ptr como
         *      vm_addr al native (que internamente lo trata como
         *      direccion VM via vm_read_bytes).
         *
         * NOTA: STRRAW devuelve host_ptr, no vm_addr.  Pero los
         * helpers usan `vm_read_bytes` que toma direcciones VM.
         * Para evitar confusion, copiamos cada string a un buffer
         * VM via ALLOCA + copia byte-por-byte... mucho overhead.
         *
         * Alternativa: el helper acepta DIRECTAMENTE el host_ptr
         * (uint64) y lo dereferencea como tal.  Re-disenamos los
         * natives para tomar host_ptr en lugar de vm_addr.  Para
         * mantener consistencia con vio_*_to_vmbuf, los repeat/
         * replace todavia usan vm_addr para el DESTINO; el caller
         * debe pasar un buffer ALLOCA fresco.
         *
         * Plan v1 simplificado: TODOS los args string se materializan
         * a buffer VM via ALLOCA + write.  Costoso para strings
         * grandes pero correcto.  Optimizable despues. */

        // Helper para auto-promote string literals a StringObjects
        // antes de aplicar strraw.  Mismo patron que en str_concat/equals.
        auto coerce_str_arg = [&](ast::Expr *ex) -> ir::IrValueId {
            if (ex && ex->kind == ast::NodeKind::StringLitExpr) {
                auto *sl = static_cast<ast::StringLitExpr *>(ex);
                return lower_string_literal_to_string_object(sl);
            }
            return lower_expr(ex);
        };

        auto materialize_str_to_vmbuf =
            [&](ir::IrValueId v_str,
                int ln) -> std::pair<ir::IrValueId, ir::IrValueId> {
            /* Returns (vm_addr, byte_len).  Aloca buffer VM,
             * llama STRRAW + STRGETBYTES, copia bytes a buffer VM. */
            ir::IrValueId v_raw = emit_strraw(v_str, ln);
            ir::IrValueId v_byte_len = emit_strgetbytes(v_str, ln);
            /* v_raw es host_ptr -- los helpers nativos lo aceptan
             * directamente via `(void *)(uint64_t)host_ptr` y
             * leen con memcpy.  Pero g_api->vm_read_bytes toma
             * VM address, no host_ptr.  Para usar vm_read_bytes
             * necesitamos un VM address.
             *
             * Workaround: ya que los helpers necesitan VM address,
             * vamos a alocar un buffer en VM (ALLOCA) y copiar via
             * un nuevo intrinsic 'memcpyh_to_v' que copia desde
             * host_ptr a vm_mem.  PERO ese intrinsic no existe.
             *
             * Solucion simple: cambiar los helpers nativos para
             * que tomen host_ptr.  Asi pasamos v_raw directo. */
            return {v_raw, v_byte_len};
        };

        if (is_repeat_b) {
            if (e->args.size() != 2) {
                return builtin_error(
                    e->loc, "repeat: se esperaba 2 argumentos (string, n)",
                    out_value);
            }
            const ir::IrValueId v_str = coerce_str_arg(e->args[0].get());
            const ir::IrValueId v_n = lower_expr(e->args[1].get());
            if (v_str == ir::IR_NO_VALUE || v_n == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            auto [v_src_addr, v_src_len] =
                materialize_str_to_vmbuf(v_str, e->loc.line);
            /* Aloca buffer destino (max 16 MB).  Tamano runtime no
             * conocido en compile-time; reservamos ALLOCA grande
             * (64 KB) como cap razonable.  El helper devuelve la
             * longitud escrita y abortara con 0 si excede 16 MB. */
            ir::IrValueId v_dst_buf = stack_alloc_buf(65536, e->loc.line);
            const ir::IrValueId v_proc = emit_getproc(e->loc.line);
            ir::IrValueId v_len = emit_native_call(
                kVestaIoLib, "vstr_repeat_to_vmbuf",
                {v_proc, v_dst_buf, v_src_addr, v_src_len, v_n},
                ir::IrType::U64, e->loc.line);
            /* STRMAKE desde el buffer dst. */
            ir::IrValueId v_h = emit_strmake(v_dst_buf, v_len, e->loc.line);
            out_value = v_h;
            return true;
        }

        if (is_contains_b) {
            if (e->args.size() != 2) {
                return builtin_error(
                    e->loc,
                    "contains: se esperaba 2 argumentos (string, substring)",
                    out_value);
            }
            const ir::IrValueId v_hay = coerce_str_arg(e->args[0].get());
            const ir::IrValueId v_needle = coerce_str_arg(e->args[1].get());
            if (v_hay == ir::IR_NO_VALUE || v_needle == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            auto [v_h_addr, v_h_len] =
                materialize_str_to_vmbuf(v_hay, e->loc.line);
            auto [v_n_addr, v_n_len] =
                materialize_str_to_vmbuf(v_needle, e->loc.line);
            const ir::IrValueId v_proc = emit_getproc(e->loc.line);
            ir::IrValueId v_dst =
                emit_native_call(kVestaIoLib, "vstr_contains",
                                 {v_proc, v_h_addr, v_h_len, v_n_addr, v_n_len},
                                 ir::IrType::BOOL, e->loc.line);
            out_value = v_dst;
            return true;
        }

        if (is_replace_b) {
            if (e->args.size() != 3) {
                return builtin_error(
                    e->loc,
                    "replace: se esperaba 3 argumentos (string, from, to)",
                    out_value);
            }
            // Auto-promote string literals a StringObjects.  Sin esto,
            // un literal como `"{a}"` se pasa como raw static_data ptr
            // a STRRAW que lo trata como GcHandle invalido -> garbage.
            const ir::IrValueId v_src = coerce_str_arg(e->args[0].get());
            const ir::IrValueId v_from = coerce_str_arg(e->args[1].get());
            const ir::IrValueId v_to = coerce_str_arg(e->args[2].get());
            if (v_src == ir::IR_NO_VALUE || v_from == ir::IR_NO_VALUE ||
                v_to == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            auto [v_src_addr, v_src_len] =
                materialize_str_to_vmbuf(v_src, e->loc.line);
            auto [v_from_addr, v_from_len] =
                materialize_str_to_vmbuf(v_from, e->loc.line);
            auto [v_to_addr, v_to_len] =
                materialize_str_to_vmbuf(v_to, e->loc.line);
            /* Buffer destino (64 KB ALLOCA). */
            ir::IrValueId v_dst_buf = stack_alloc_buf(65536, e->loc.line);
            const ir::IrValueId v_proc = emit_getproc(e->loc.line);
            ir::IrValueId v_len =
                emit_native_call(kVestaIoLib, "vstr_replace_to_vmbuf",
                                 {v_proc, v_dst_buf, v_src_addr, v_src_len,
                                  v_from_addr, v_from_len, v_to_addr, v_to_len},
                                 ir::IrType::U64, e->loc.line);
            ir::IrValueId v_h = emit_strmake(v_dst_buf, v_len, e->loc.line);
            out_value = v_h;
            return true;
        }
    }

    // ----- builtins de string -----
    // Cada uno se baja a un solo opcode bytecode mediante RAW_ASM
    // con substitucion {dst}/{src0}/{src1}.  Cero overhead vs .vel
    // crudo; el regalloc decide los registros.
    // Vesta Embed Inc 0: en native_poo_ el `string` es value-type
    // {ptr,len,cap}.  s.length() -> LOAD len@[slot+8]; s.cstr() ->
    // LOAD ptr@[slot+0] (ya nul-terminado).  No emitimos STRLEN/STRRAW
    // (RUNTIME_DEPENDENT en AOT).  Solo length/cstr en Inc 0; el resto
    // (bytes/hash/intern/wstr) sigue su path normal (no se prueba en AOT).
    // Vesta Embed Inc 0/5/6: en native_poo_ el value-string {ptr,len,cap}
    // resuelve length/bytes/cstr/wstr SIN STRMAKE/STRLEN/STRRAW
    // (RUNTIME_DEPENDENT en AOT).  Inc 6 (encoding UTF-8):
    //   .length() -> conteo de CODE-POINTS (UTF-8).
    //   .bytes()  -> conteo de BYTES (el len crudo del repr).
    //   .cstr()   -> u8* UTF-8 NUL-terminado (Win32 *A / FFI).
    //   .wstr()   -> u16* UTF-16LE NUL-terminado (Win32 *W).
    // Plegado en compile-time: `str_cstr("lit")` / `str_wstr("lit")` sobre un
    // literal no interpolado se resuelve AQUI.  Se transcodifica el texto, se
    // interna como blob en memoria host y se devuelve su direccion: sin
    // STRMAKE, sin STRCONV y sin objeto GC.  Vale en interp, JIT y AOT porque
    // el resultado es una direccion host, igual que la que devolvian esos
    // builtins.  Si el texto no es plegable, se sigue por el camino normal.
    if ((is_str_cstr || is_str_wstr) && e->args.size() == 1 && e->args[0]) {
        const std::string *txt = nullptr;
        ast::Expr *ae = e->args[0].get();
        if (ae->kind == ast::NodeKind::StringLitExpr &&
            !static_cast<ast::StringLitExpr *>(ae)->is_interpolated()) {
            txt = &static_cast<ast::StringLitExpr *>(ae)->value;
        } else if (ae->kind == ast::NodeKind::IdentExpr) {
            // Literal alcanzable por nombre (`const string p = "x"`).
            auto it =
                const_str_locals_.find(static_cast<ast::IdentExpr *>(ae)->name);
            if (it != const_str_locals_.end()) txt = &it->second;
        }
        if (txt) {
            const ir::IrValueId v_blob =
                emit_folded_string_blob(*txt, is_str_wstr ? 3 : 2, e->loc.line);
            if (v_blob != ir::IR_NO_VALUE) {
                out_value = v_blob;
                return true;
            }
        }
    }

    // La longitud de un LITERAL se sabe al compilar, asi que se pliega: es una
    // constante, no algo que haya que averiguar.  Sin esto se construia un
    // StringObject en ejecucion solo para leerle la longitud y tirarlo -- una
    // alocacion por cada `"lit".bytes()`, y en un modulo freestanding (vx_io)
    // eso no se puede pagar, de modo que la unica salida era contar los bytes a
    // mano al escribir el codigo.  Contarlos a mano ya habia fallado: el
    // mensaje de unwrap-null pasaba 54 donde el literal mide 56.
    //
    // Vale para los tres modos: el numero es el mismo se ejecute donde se
    // ejecute.
    if ((is_str_length || is_str_bytes) && e->args.size() == 1) {
        const ast::Expr *ae0 = e->args[0].get();
        if (ae0 && ae0->kind == ast::NodeKind::StringLitExpr &&
            !static_cast<const ast::StringLitExpr *>(ae0)->is_interpolated()) {
            const std::string &lit =
                static_cast<const ast::StringLitExpr *>(ae0)->value;
            uint64_t n = 0;
            if (is_str_bytes) {
                n = static_cast<uint64_t>(lit.size());
            } else {
                // Puntos de codigo: los bytes de continuacion de UTF-8
                // (10xxxxxx) no cuentan, son la cola del anterior.
                for (unsigned char b : lit)
                    if ((b & 0xC0) != 0x80) ++n;
            }
            out_value = emit_const(ir::IrType::I64, n, e->loc.line);
            return true;
        }
    }

    if (native_poo_ &&
        (is_str_length || is_str_bytes || is_str_cstr || is_str_wstr) &&
        e->args.size() == 1) {
        ast::Expr *ae = e->args[0].get();
        // Literal directo `str_length("x")`: raro en native; resolver con
        // el repr construido (correcto pero aloca un buffer descartable).
        ir::IrValueId v_slot;
        if (ae && ae->kind == ast::NodeKind::StringLitExpr &&
            !static_cast<ast::StringLitExpr *>(ae)->is_interpolated()) {
            v_slot = build_native_string_from_literal(
                static_cast<ast::StringLitExpr *>(ae), e->loc.line);
        } else {
            v_slot = lower_expr(ae);
        }
        if (v_slot == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        if (is_str_bytes) {
            // String Inc 5 (SSO): len de BYTES via accesor flag-aware.
            out_value = emit_native_str_len(v_slot, e->loc.line);
        } else if (is_str_length) {
            // Inc 6: code-points (UTF-8).  data_ptr + byte_len -> cplen.
            // Para ASCII == byte_len (sin regresion en los tests ASCII).
            ir::IrValueId v_ptr = emit_native_str_data_ptr(v_slot, e->loc.line);
            ir::IrValueId v_blen = emit_native_str_len(v_slot, e->loc.line);
            out_value = emit_native_str_cplen(v_ptr, v_blen, e->loc.line);
        } else if (is_str_cstr) {
            // String Inc 5 (SSO): data_ptr flag-aware (SSO -> &slot ya
            // nul-terminado; HEAP -> ptr@0).
            out_value = emit_native_str_data_ptr(v_slot, e->loc.line);
        } else {
            // is_str_wstr -- Inc 6: UTF-16LE para Win32 *W.
            ir::IrValueId v_ptr = emit_native_str_data_ptr(v_slot, e->loc.line);
            ir::IrValueId v_blen = emit_native_str_len(v_slot, e->loc.line);
            out_value = emit_native_str_to_utf16(v_ptr, v_blen, e->loc.line);
        }
        return true;
    }
    if (is_str_length || is_str_bytes || is_str_cstr || is_str_wstr ||
        is_str_hash || is_str_intern) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc,
                                 std::string("'") +
                                     std::string(builtin_name(b)) + "': 1 arg",
                                 out_value);
        }
        // coerce string literal (PTR) a StringObject (STRING
        // handle) inline via STRMAKE.  Sin esto pasar un literal directo
        // a str_cstr("wb") emitia STRRAW sobre el ptr raw del literal en
        // static_data, retornando garbage.  Mismo patron que fix3
        // hace en lower_call para args de funciones top-level.
        ast::Expr *ae = e->args[0].get();
        ir::IrValueId v_str;
        if (ae && ae->kind == ast::NodeKind::StringLitExpr) {
            auto *sl = static_cast<ast::StringLitExpr *>(ae);
            // Tanto literales puros como interpolados: el helper
            // construye el StringObject correcto.
            v_str = lower_string_literal_to_string_object(sl);
        } else {
            v_str = lower_expr(ae);
        }
        if (v_str == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // wstr requiere strconv UTF16 + strraw (2 ops).
        if (is_str_wstr) {
            // strconv(s, ENC_UTF16=3) + strraw -> host_ptr a wchar_t* para
            // Win32 *W.
            ir::IrValueId v_conv =
                emit_strconv(v_str, /*enc=UTF16*/ 3, e->loc.line);
            ir::IrValueId v_raw = emit_strraw(v_conv, e->loc.line);
            out_value = v_raw;
            return true;
        }
        // Resto: 1 sola instruccion bytecode mediante IR ops dedicados.
        if (is_str_length) {
            ir::IrValueId v_dst = emit_ir_unop(ir::IrOp::STRLEN, v_str,
                                               ir::IrType::I64, e->loc.line);
            out_value = v_dst;
        } else if (is_str_bytes) {
            out_value = emit_strgetbytes(v_str, e->loc.line);
        } else if (is_str_cstr) {
            out_value = emit_strraw(v_str, e->loc.line);
        } else if (is_str_hash) {
            ir::IrValueId v_dst = emit_ir_unop(ir::IrOp::STRHASH, v_str,
                                               ir::IrType::I64, e->loc.line);
            out_value = v_dst;
        } else {
            // str_intern: aloca nuevo StringObject canonical o reusa pool.
            // Retorna GcHandle (no host_ptr), por eso no is_gc_object.
            ir::IrValueId v_dst = fn_->new_value(ir::IrType::I64);
            ir::IrInstr ins{};
            ins.op = ir::IrOp::STRINTERN;
            ins.type = ir::IrType::I64;
            ins.dst = v_dst;
            ins.operands = {v_str};
            ins.is_call_site = true;
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
            out_value = v_dst;
        }
        return true;
    }

    if (is_str_concat || is_str_equals) {
        if (e->args.size() != 2) {
            return builtin_error(e->loc,
                                 std::string("'") +
                                     std::string(builtin_name(b)) + "': 2 args",
                                 out_value);
        }
        // C-3: ruteo del builtin str_concat/str_equals al override del
        // usuario (@StringConcat / @StringEq).  Solo el builtin runtime
        // real, NO el alias comptime_concat (que vive en compile-time).
        if (b == Builtin::StrConcat && !string_concat_override_.empty()) {
            out_value = emit_string_override_call(
                string_concat_override_, e->args[0].get(), e->args[1].get(),
                ir::IrType::I64, /*negate=*/false, e->loc.line);
            return true;
        }
        if (b == Builtin::StrEquals && !string_eq_override_.empty()) {
            out_value = emit_string_override_call(
                string_eq_override_, e->args[0].get(), e->args[1].get(),
                ir::IrType::BOOL, /*negate=*/false, e->loc.line);
            return true;
        }
        // Vesta Embed Inc 1: en native_poo_ str_concat(a, b) == `a + b`
        // (value-string).  Mismo lowering: buffer nuevo owned + copia de
        // ambos.  str_equals (cmp) es Inc 4 -> sigue su path normal.
        if (native_poo_ && is_str_concat) {
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
            ir::IrValueId v_na = build_native_operand(e->args[0].get(), a_temp);
            ir::IrValueId v_nb = build_native_operand(e->args[1].get(), b_temp);
            if (v_na == ir::IR_NO_VALUE || v_nb == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            ir::IrValueId v_res =
                build_native_string_concat(v_na, v_nb, e->loc.line);
            // Inc 5 (SSO): liberar operandos temporales SOLO si HEAP.
            if (a_temp) emit_native_str_free_if_heap(v_na, e->loc.line);
            if (b_temp) emit_native_str_free_if_heap(v_nb, e->loc.line);
            out_value = v_res;
            return true;
        }
        // Vesta Embed Inc 4 (builtin): en native_poo_ str_equals(a, b) usa el
        // mismo helper native __vx_strcmp que el operador `==` (value-string,
        // CERO GC), en vez de STRCMP (StringObject GC).  Devuelve bool (==0).
        if (native_poo_ && is_str_equals) {
            // Extrae (ptr, len) de cada operando como el operador == (literal
            // -> .rodata + CONST len; var/concat/cast -> slot value-string +
            // accesores; temporales se liberan tras comparar).
            struct OpRef {
                ir::IrValueId ptr = ir::IR_NO_VALUE;
                ir::IrValueId len = ir::IR_NO_VALUE;
                ir::IrValueId temp =
                    ir::IR_NO_VALUE; // !=NO_VALUE -> free si heap
            };
            auto op_ref = [&](ast::Expr *ex) -> OpRef {
                OpRef r;
                if (ex && ex->kind == ast::NodeKind::StringLitExpr &&
                    !static_cast<ast::StringLitExpr *>(ex)->is_interpolated()) {
                    auto *slit = static_cast<ast::StringLitExpr *>(ex);
                    const std::string &lit = slit->value;
                    std::vector<uint8_t> data(lit.begin(), lit.end());
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
                bool is_temp = false;
                if (ex && ex->kind == ast::NodeKind::BinaryExpr &&
                    static_cast<ast::BinaryExpr *>(ex)->op == ast::BinOp::Add &&
                    ex->result_type.kind == PrimitiveKind::STRING)
                    is_temp = true;
                else if (ex && ex->kind == ast::NodeKind::CastExpr &&
                         ex->result_type.kind == PrimitiveKind::STRING)
                    is_temp = true;
                ir::IrValueId v_slot = lower_expr(ex);
                if (v_slot == ir::IR_NO_VALUE) return r;
                r.ptr = emit_native_str_data_ptr(v_slot, e->loc.line);
                r.len = emit_native_str_len(v_slot, e->loc.line);
                if (is_temp) r.temp = v_slot;
                return r;
            };
            OpRef ra = op_ref(e->args[0].get());
            OpRef rb = op_ref(e->args[1].get());
            if (ra.ptr == ir::IR_NO_VALUE || rb.ptr == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            ir::IrValueId v_cmp = emit_strcmp_dispatched(ra.ptr, ra.len, rb.ptr,
                                                         rb.len, e->loc.line);
            if (ra.temp != ir::IR_NO_VALUE)
                emit_native_str_free_if_heap(ra.temp, e->loc.line);
            if (rb.temp != ir::IR_NO_VALUE)
                emit_native_str_free_if_heap(rb.temp, e->loc.line);
            // str_equals: bool = (strcmp == 0).
            ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, e->loc.line);
            ir::IrValueId v_eq = emit_ir_binop(ir::IrOp::CMP_EQ, v_cmp, v_zero,
                                               ir::IrType::BOOL, e->loc.line);
            out_value = v_eq;
            return true;
        }
        // Coerce string literals (PTR) a StringObject
        // (STRING handle) inline via STRMAKE.  Sin esto pasar un
        // literal directamente a str_concat/str_equals enviaria un
        // puntero raw como handle (UB).
        auto coerce_to_string_handle = [&](ast::Expr *ex) -> ir::IrValueId {
            if (ex && ex->kind == ast::NodeKind::StringLitExpr) {
                auto *sl = static_cast<ast::StringLitExpr *>(ex);
                // Tanto literales puros como interpolados.
                return lower_string_literal_to_string_object(sl);
            }
            return lower_expr(ex);
        };
        ir::IrValueId v_a = coerce_to_string_handle(e->args[0].get());
        ir::IrValueId v_b = coerce_to_string_handle(e->args[1].get());
        if (v_a == ir::IR_NO_VALUE || v_b == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // Sprint 6.D: usar STRCAT/STRCMP IR ops directos.  El helper
        // emit_strcat ya emite IR op puro con is_call_site=true.
        ir::IrValueId v_dst;
        if (is_str_concat) {
            v_dst = emit_strcat(v_a, v_b, e->loc.line);
        } else {
            v_dst = fn_->new_value(ir::IrType::I64);
            ir::IrInstr cmp{};
            cmp.op = ir::IrOp::STRCMP;
            cmp.type = ir::IrType::I64;
            cmp.dst = v_dst;
            cmp.operands = {v_a, v_b};
            cmp.source_line = e->loc.line;
            emit(current_block_, std::move(cmp));
        }
        // str_equals returns -1/0/1 (strcmp).  Convertir a bool: 0 == equal.
        if (is_str_equals) {
            ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, e->loc.line);
            ir::IrValueId v_eq = emit_ir_binop(ir::IrOp::CMP_EQ, v_dst, v_zero,
                                               ir::IrType::BOOL, e->loc.line);
            out_value = v_eq;
        } else {
            out_value = v_dst;
        }
        return true;
    }

    if (is_str_make) {
        if (e->args.size() != 2) {
            return builtin_error(e->loc, "str_make: 2 args (ptr, len)",
                                 out_value);
        }
        // Vesta Embed (native_poo_): str_make(ptr, len) COPIA len bytes a un
        // value-string PROPIO (sin GC), NO un StringObject GC.  Si len es un
        // literal entero -> Tier B (decision SSO/HEAP compile-time, sin rama).
        if (native_poo_) {
            int64_t known_len = -1;
            if (e->args[1] && e->args[1]->kind == ast::NodeKind::IntLitExpr) {
                int64_t lv =
                    (int64_t)static_cast<ast::IntLitExpr *>(e->args[1].get())
                        ->value;
                if (lv >= 0) known_len = lv;
            }
            ir::IrValueId v_ptr = lower_expr(e->args[0].get());
            ir::IrValueId v_len = lower_expr(e->args[1].get());
            if (v_ptr == ir::IR_NO_VALUE || v_len == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            out_value = build_native_string_from_buffer(v_ptr, v_len,
                                                        e->loc.line, known_len);
            return true;
        }
        ir::IrValueId v_ptr = lower_expr(e->args[0].get());
        ir::IrValueId v_len = lower_expr(e->args[1].get());
        if (v_ptr == ir::IR_NO_VALUE || v_len == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // Auto-detect: si el puntero proviene de memoria HOST (malloc,
        // str_cstr, gcallocp, etc.) emitimos `strmake_h` que lee bytes
        // del host.  Si es VM (subsp+&local, STR_LIT_ADDR, etc.) usamos
        // `strmake` original que lee de vm_mem.  Esto cierra el bug
        // historico en el que `str_make(buffer.data, len)` con `data`
        // mallocado retornaba zeros
        // Sprint 6.D: STRMAKE IR op.  El emitter elige strmake vs
        // strmake_h segun el flag is_host_ptr del SSA value v_ptr,
        // lo que reemplaza el if-else explicito anterior.
        out_value = emit_strmake(v_ptr, v_len, e->loc.line);
        return true;
    }

    // str_convert(s, enc) -> nuevo string con encoding
    // seleccionado.  El opcode strconv requiere encoding como inmediato
    // en el bytecode (no via registro), asi que el segundo arg debe
    // ser una constante numerica resuelta en compile time (literal int
    // o constante ENC_*).  Si no lo es, error claro.
    if (is_str_convert) {
        // Modelo de cadenas: un `string` es SIEMPRE una secuencia de code
        // points (UTF-8 por dentro), sin etiqueta de codificacion.  "Una
        // cadena en UTF-16" no es un valor del lenguaje, asi que convertir de
        // `string` a `string` no significa nada.
        //
        // La codificacion vive en la FRONTERA con codigo nativo: se pide el
        // buffer en la codificacion que espera esa API.  Ademas asi el mismo
        // codigo se comporta igual en interprete, JIT y AOT -- antes AOT
        // trataba la codificacion como advisory y divergia en silencio.
        return builtin_error(
            e->loc,
            "str_convert no existe: un `string` es siempre una secuencia "
            "de code points.  La codificacion se elige al cruzar a codigo "
            "nativo: usa `s.cstr()` para UTF-8 o `s.wstr()` para UTF-16",
            out_value);
    }

    return false;
}

} // namespace vx
