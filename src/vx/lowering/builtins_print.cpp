/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_print.cpp
 * @brief Bajada de imprimir: el builtin mas usado del lenguaje y el que mas
 *        trabajo da.
 *
 * `print("hola")` parece una llamada y no lo es.  Lo que se escribe puede ser
 * un literal, una interpolacion con expresiones dentro, un valor de cualquier
 * tipo -- y cada tipo se escribe distinto: un entero con signo no es uno sin
 * signo, un flotante no es un puntero, una cadena no es un caracter --.  Ademas
 * el usuario puede pedir COMO quiere verlo: en hexadecimal, en binario,
 * alineado a un ancho, relleno con un caracter suyo.
 *
 * Asi que el grueso del fichero no es imprimir: es AVERIGUAR QUE hay que
 * imprimir y elegir la primitiva que corresponde, con sus conversiones.  Lo de
 * verdad escribir son cuatro lineas, y viven en `io.cpp` porque tambien las
 * necesita quien no esta imprimiendo.
 *
 * Se separo de la funcion que despacha todos los builtins, donde era mil lineas
 * de siete mil.  Entra por su propio punto: si el nombre no es de esta familia,
 * contesta que no y quien pregunta sigue con las demas.
 */
#include "vx/lowering.h"
#include "vx/ansi_names.h" // los nombres de color que el lenguaje conoce
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
namespace {

/**
 * @brief Un builtin que escribe UN escalar, y como se llama en cada camino.
 *
 * Los doce -- `print_int`, `print_hex`, `print_ptr`... -- hacen exactamente lo
 * mismo: bajar el argumento, llevarlo a 64 bits y llamar a una primitiva.  Solo
 * cambia CUAL.  Ese unico dato estaba repartido en cinco listas paralelas: una
 * bandera por builtin, la cadena que decide si la familia es esta, la que
 * decide si el builtin lleva un argumento, la de los nombres nativos y la de
 * los de la maquina virtual.  Cinco sitios donde olvidarse de uno, y el
 * olvido no se nota: la ultima cadena acababa en un @c else que mandaba el
 * huerfano a imprimirse como cadena de C.
 */
struct ScalarPrinter {
    Builtin b;        ///< Que builtin es.
    const char *vm;   ///< La primitiva del runtime de la maquina virtual.
    const char *bare; ///< La del binario nativo; nulo si ahi todavia no hay.
    /**
     * @brief Si callar cuando el argumento no es lo que el nombre promete.
     *
     * Pasar un flotante a algo que escribe enteros trunca.  Once de los doce
     * lo hacen en silencio y `print_int` avisa.  Esto NO es una decision de
     * diseno: es lo que quedo de escribirlo en dos sitios distintos, y se
     * conserva tal cual porque cambiarlo es cosa de quien disena el lenguaje,
     * no de quien junta dos listas.
     */
    bool silent_on_lossy;
};

/// Los doce.  Un nulo en @c bare significa que ese camino aun no sabe hacerlo.
constexpr ScalarPrinter kScalarPrinters[] = {
    {Builtin::PrintInt, "vio_print_int", "__vx_print_i64", false},
    {Builtin::PrintUint, "vio_print_uint", "__vx_print_u64", true},
    {Builtin::PrintHex, "vio_print_hex", "__vx_print_hex", true},
    {Builtin::PrintBin, "vio_print_bin", "__vx_print_bin", true},
    {Builtin::PrintOct, "vio_print_oct", "__vx_print_oct", true},
    {Builtin::PrintBool, "vio_print_bool", "__vx_print_bool", true},
    {Builtin::PrintChar, "vio_print_char", "__vx_print_char", true},
    {Builtin::PrintPtr, "vio_print_ptr", "__vx_print_ptr", true},
    {Builtin::PrintCstr, "vio_print_cstr", "__vx_print_cstr", true},
    {Builtin::PrintFloat, "vio_print_float", nullptr, true},
    {Builtin::PrintColor, "vio_print_color", nullptr, true},
    {Builtin::PrintGchandle, "vio_print_gchandle", nullptr, true},
};

/// @return La entrada de @p b, o nulo si @p b no escribe un escalar suelto.
constexpr const ScalarPrinter *scalar_printer_for(Builtin b) {
    for (const ScalarPrinter &sp : kScalarPrinters)
        if (sp.b == b) return &sp;
    return nullptr;
}

} // namespace

/**
 * @brief Como se quiere ver un valor interpolado.
 *
 * Lo que sigue a los dos puntos en `${valor:fmt}`: en que base escribirlo, a
 * que ancho alinearlo y con que caracter rellenar.  Todo tiene omision, y la
 * omision de la base es "segun el tipo".
 */
struct FmtSpec {
    enum class Kind {
        AUTO, // dispatch por tipo (comportamiento default)
        DEC,  // entero decimal con signo correcto
        HEX,  // 0x + 16 hex fixed
        BIN,  // 0b + bits compactos
        OCT,  // 0o + dig compactos
        PTR,  // 0x + hex compacto
        GC,   // <gc:N>
        CHAR, // codepoint -> UTF-8
        BOOL  // "true"/"false"
    };

    enum class Align { NONE, LEFT, RIGHT };

    Kind kind = Kind::AUTO;
    Align align = Align::NONE;
    uint32_t width = 0;
    uint32_t fill_cp = 32; // espacio por defecto
};
/**
 * @brief Lee el formato de un `${expr:fmt}`.
 *
 * Lo que se escribe tras los dos puntos dice COMO se quiere ver el valor: en
 * que base, alineado a que ancho, con que caracter de relleno.  Sin formato
 * -- o con uno que no se entiende -- el valor sale como corresponda a su tipo,
 * que es lo que el programador espera por omision.
 *
 * @param s     El texto del formato, sin las llaves ni la expresion.
 * @param loc   Donde estaba escrito, para poder avisar.
 * @param diags A donde va el aviso si el formato no se entiende.
 * @return Lo leido; con los valores por omision en lo que no se dijo.
 */
static FmtSpec parse_fmt_spec(const std::string &s, const SourceLoc &loc,
                              Diagnostics &diags) {
    FmtSpec out;
    size_t i = 0;
    while (i < s.size()) {
        // Saltar espacios.
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
            ++i;
        if (i >= s.size()) break;
        // Detectar alineacion: primer caracter '<' / '>' = left/right,
        // seguido de digitos para el width, y opcionalmente un char
        // de fill.
        if (s[i] == '<' || s[i] == '>') {
            out.align =
                (s[i] == '<') ? FmtSpec::Align::LEFT : FmtSpec::Align::RIGHT;
            ++i;
            uint32_t w = 0;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
                w = w * 10 + (uint32_t)(s[i] - '0');
                ++i;
            }
            out.width = w;
            // Optional fill char (cualquier caracter no `:` ni final).
            if (i < s.size() && s[i] != ':') {
                // tomar UN char (asumimos ASCII; multibyte no
                // soportado en este parser simple).
                out.fill_cp = (uint32_t)(uint8_t)s[i];
                ++i;
            }
        } else {
            // Detectar keyword.
            size_t start = i;
            while (i < s.size() && s[i] != ':' && s[i] != ' ' && s[i] != '\t')
                ++i;
            std::string kw = s.substr(start, i - start);
            if (kw == "hex")
                out.kind = FmtSpec::Kind::HEX;
            else if (kw == "bin")
                out.kind = FmtSpec::Kind::BIN;
            else if (kw == "oct")
                out.kind = FmtSpec::Kind::OCT;
            else if (kw == "dec")
                out.kind = FmtSpec::Kind::DEC;
            else if (kw == "ptr")
                out.kind = FmtSpec::Kind::PTR;
            else if (kw == "gc")
                out.kind = FmtSpec::Kind::GC;
            else if (kw == "char")
                out.kind = FmtSpec::Kind::CHAR;
            else if (kw == "bool")
                out.kind = FmtSpec::Kind::BOOL;
            else {
                diags.warning(
                    loc, std::string("formato '") + kw +
                             "' desconocido en ${...:fmt}; usando default");
            }
        }
        // Saltar separador `:`.
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
            ++i;
        if (i < s.size() && s[i] == ':') ++i;
    }
    return out;
}

/**
 * @brief Intenta bajar @p e como uno de los builtins de impresion.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado; sin valor si el builtin no lo da.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_print_builtins(ast::CallExpr *e, Builtin b,
                                        ir::IrValueId &out_value) {
    const bool is_print = (b == Builtin::Print);
    /*  MC.18: `comptime_print` / `ct_print` se aliasan a
     * `println` -- en el path VM-lowered es exactamente eso (print
     * a stderr).  El macro corre en compile time (porque la
     * ComptimeRuntime ejecuta el body al type-checkear el call
     * site), asi que el output aparece durante la compilacion
     * igual que el AST eval. */
    const bool is_println =
        (b == Builtin::Println || b == Builtin::ComptimePrint ||
         b == Builtin::CtPrint);
    const bool is_echo = (b == Builtin::Echo);   // alias de print
    const bool is_flush = (b == Builtin::Flush); // vio_flush() sin args
    const bool is_gc_collect =
        (b == Builtin::GcCollect); // fuerza GC + finalizadores
    const bool is_gc_finalize_all =
        (b == Builtin::GcFinalizeAll); // finaliza todo objeto GC con recurso
    /* Los que escriben UN escalar -- `print_int`, `print_hex`, `print_ptr`...
     * -- se preguntan de una vez: la tabla dice si @p b es de esos y, si lo es,
     * como se llama la primitiva en cada camino.  Nulo es "no es de esos". */
    const ScalarPrinter *const scalar = scalar_printer_for(b);
    const bool is_print_pad = (b == Builtin::PrintPad);
    // Secuencias de control del terminal (escapes VT100 fijos): sin valor que
    // formatear, pero salen por la misma primitiva que todo lo de arriba.
    const bool is_term_clear = (b == Builtin::TermClear);
    const bool is_term_clear_line = (b == Builtin::TermClearLine);
    const bool is_term_move = (b == Builtin::TermMove);
    const bool is_term_save_cursor = (b == Builtin::TermSaveCursor);
    const bool is_term_restore_cursor = (b == Builtin::TermRestoreCursor);
    const bool is_term_hide_cursor = (b == Builtin::TermHideCursor);
    const bool is_term_show_cursor = (b == Builtin::TermShowCursor);
    const bool is_term_reset = (b == Builtin::TermReset);

    /* Salida rapida: si no es de esta familia no se monta nada de lo de abajo.
     * Antes esto no hacia falta porque todo vivia en la misma funcion; ahora
     * evita construir los ayudantes para una llamada que no va a usarlos. */
    if (!(is_print || is_println || is_echo || is_flush || is_gc_collect ||
          is_gc_finalize_all || scalar || is_print_pad || is_term_clear ||
          is_term_clear_line || is_term_move || is_term_save_cursor ||
          is_term_restore_cursor || is_term_hide_cursor ||
          is_term_show_cursor || is_term_reset))
        return false;

    auto emit_print_newline = [&](uint32_t line) {
        if (native_poo_) {
            emit_print_string_literal("\n", line); // via __vx_write
            return;
        }
        emit_native_call(kVestaIoLib, "vio_print_newline", {}, ir::IrType::VOID,
                         line);
    };

    auto emit_print_arg = [&](ast::Expr *ex) {
        if (!ex) return;
        if (ex->kind == ast::NodeKind::StringLitExpr) {
            auto *sl = static_cast<ast::StringLitExpr *>(ex);
            if (sl->is_interpolated()) {
                // Iteracion: parts[0] + exprs[0] + parts[1] + exprs[1]
                // + ... + parts[N].  Cada fragmento -> 1 CALLN.  Si
                // hay format spec por interpolacion (interp_formats[i]
                // no vacio), se pasa al typed_value para dispatch a
                // vio_print_fmt.
                const size_t ne = sl->interp_exprs.size();
                const size_t np = sl->interp_parts.size();
                const size_t nf = sl->interp_formats.size();
                for (size_t i = 0; i < ne; ++i) {
                    if (i < np && !sl->interp_parts[i].empty()) {
                        emit_print_string_literal(sl->interp_parts[i],
                                                  ex->loc.line);
                    }
                    const std::string &fmt =
                        (i < nf) ? sl->interp_formats[i] : std::string();
                    emit_print_typed_value(sl->interp_exprs[i].get(), fmt);
                }
                if (np > ne) {
                    const auto &last = sl->interp_parts.back();
                    if (!last.empty()) {
                        emit_print_string_literal(last, ex->loc.line);
                    }
                }
                return;
            }
            emit_print_string_literal(sl->value, ex->loc.line);
            return;
        }
        emit_print_typed_value(ex, std::string());
    };

    // ----- print(arg) / echo(arg) / println(arg) -----
    // Los tres aceptan UN argumento que puede ser:
    //   - String literal (con o sin interpolacion ${expr}).
    //   - Cualquier expresion escalar (i32/i64/f64/bool/char).
    // print y echo son sinonimos; println anade '\n' al final.
    if (is_print || is_println || is_echo) {
        if (e->args.size() != 1 || !e->args[0]) {
            return builtin_error(e->loc,
                                 std::string("'") +
                                     std::string(builtin_name(b)) +
                                     "' requiere exactamente un argumento",
                                 out_value);
        }
        emit_print_arg(e->args[0].get());
        if (is_println) emit_print_newline(e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    // ----- flush() -----
    // Vacia el buffer global de vesta_io ahora mismo.  Util para TUIs.
    if (is_gc_collect) {
        if (!e->args.empty()) {
            return builtin_error(e->loc, "'gc_collect' no acepta argumentos",
                                 out_value);
        }
        if (native_poo_) {
            // AOT: CALL al recolector nativo (libvesta_gc).
            ir::IrInstr ins{};
            ins.op = ir::IrOp::CALL;
            ins.type = ir::IrType::VOID;
            ins.dst = ir::IR_NO_VALUE;
            ins.func_name = "vx_gc_collect";
            ins.is_call_site = true;
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        ir::IrInstr ins{};
        ins.op = ir::IrOp::GC_COLLECT;
        ins.type = ir::IrType::VOID;
        ins.dst = ir::IR_NO_VALUE;
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    // gc_finalize_all(): finaliza TODO objeto GC vivo con recurso interno
    // (deleter/dtor).  Determinista, no depende de la colecta -> util para
    // observar la finalizacion de escapados sin polling ni residuos de scan.
    if (is_gc_finalize_all) {
        if (!e->args.empty()) {
            return builtin_error(
                e->loc, "'gc_finalize_all' no acepta argumentos", out_value);
        }
        module_has_gc_finalizers_ = true;
        if (native_poo_) {
            // AOT: CALL vx_gc_finalize_all de libvesta_gc.
            ir::IrInstr ins{};
            ins.op = ir::IrOp::CALL;
            ins.type = ir::IrType::VOID;
            ins.dst = ir::IR_NO_VALUE;
            ins.func_name = "vx_gc_finalize_all";
            ins.is_call_site = true;
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // interp/JIT: opcode gcfinall (ZERO) que llama finalize_all_live.
        ir::IrInstr ins{};
        ins.op = ir::IrOp::GC_FINALIZE_ALL;
        ins.type = ir::IrType::VOID;
        ins.dst = ir::IR_NO_VALUE;
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    if (is_flush) {
        if (!e->args.empty()) {
            return builtin_error(e->loc, "'flush' no acepta argumentos",
                                 out_value);
        }
        if (native_poo_) {
            emit_io_prim("__vx_flush", {}, e->loc.line);
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        emit_native_call(kVestaIoLib, "vio_flush", {}, ir::IrType::VOID,
                         e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    /* ----- Los doce que escriben un escalar suelto -----
     *
     * `print_uint(n)`, `print_hex(n)`, `print_ptr(p)`, `print_int(n)`...  El
     * nombre elige el formato; el trabajo es el mismo para todos, y por eso es
     * UN camino y no doce.  `print_int` tenia el suyo aparte, identico salvo en
     * si avisa cuando el argumento no es un entero -- eso se conserva, lo lleva
     * la tabla -- y en el texto de un error, que era menos exacto que el comun:
     * hoy ninguno de los doce exige un entero, todos convierten. */
    if (scalar) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc,
                                 std::string("'") +
                                     std::string(builtin_name(b)) +
                                     "' requiere exactamente un argumento",
                                 out_value);
        }
        ir::IrValueId v = lower_expr(e->args[0].get());
        if (v == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // Caso especial: print_gchandle recibe un objeto CLASS y debe
        // emitir la instruccion @c gchandle r_dst, r_src para
        // convertir el host_ptr al GcHandle (uint32) antes de
        // pasarlo al native como uint64 zero-extended.
        if (b == Builtin::PrintGchandle &&
            e->args[0]->result_type.kind == PrimitiveKind::CLASS) {
            v = emit_gc_handle_for_ptr(v, e->loc.line);
        }
        v = cast_if_needed(v, fn_->values[v].type, ir::IrType::I64, e->loc.line,
                           /*is_explicit=*/scalar->silent_on_lossy);
        if (native_poo_) {
            // Binario nativo: no hay proceso al que pasarle nada, se llama al
            // formateador suelto.  Los que la tabla deja a nulo todavia no
            // existen ahi, y eso se DICE en vez de escribir basura.
            if (!scalar->bare) {
                diags_.warning(e->loc, std::string("'") +
                                           std::string(builtin_name(b)) +
                                           "' en AOT nativo aun no soportado; "
                                           "se omite");
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            emit_io_prim(scalar->bare, {v}, e->loc.line);
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        emit_native_call(kVestaIoLib, scalar->vm, {v}, ir::IrType::VOID,
                         e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    // ----- print_pad(fill_cp, width) -----
    // Emite @p width copias del codepoint @p fill_cp al buffer.  Util
    // para construir alineacion manual de columnas (TUI / tablas).
    if (is_print_pad) {
        if (e->args.size() != 2) {
            return builtin_error(
                e->loc, "'print_pad' requiere (fill_cp, width)", out_value);
        }
        ir::IrValueId v_fill = lower_expr(e->args[0].get());
        ir::IrValueId v_w = lower_expr(e->args[1].get());
        if (v_fill == ir::IR_NO_VALUE || v_w == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        v_fill = cast_if_needed(v_fill, fn_->values[v_fill].type,
                                ir::IrType::I64, e->loc.line, true);
        v_w = cast_if_needed(v_w, fn_->values[v_w].type, ir::IrType::I64,
                             e->loc.line, true);
        emit_native_call(kVestaIoLib, "vio_print_pad", {v_fill, v_w},
                         ir::IrType::VOID, e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    /* Y las secuencias de control del terminal: mover el cursor, limpiar,
     * ocultarlo.  No se parecen a imprimir un valor -- no hay valor que
     * formatear -- pero salen por la misma primitiva, asi que separarlas
     * seria partir la familia por la mitad. */
    if (is_term_clear) {
        if (!e->args.empty()) {
            return builtin_error(e->loc, "term_clear: no acepta argumentos",
                                 out_value);
        }
        emit_print_string_literal("\x1b[2J\x1b[H", e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    if (is_term_clear_line) {
        if (!e->args.empty()) {
            return builtin_error(
                e->loc, "term_clear_line: no acepta argumentos", out_value);
        }
        emit_print_string_literal("\x1b[2K", e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    if (is_term_save_cursor) {
        emit_print_string_literal("\x1b[s", e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    if (is_term_restore_cursor) {
        emit_print_string_literal("\x1b[u", e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    if (is_term_hide_cursor) {
        emit_print_string_literal("\x1b[?25l", e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    if (is_term_show_cursor) {
        emit_print_string_literal("\x1b[?25h", e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    if (is_term_reset) {
        // Reset all attributes (color, style, bg, fg).
        emit_print_string_literal("\x1b[0m", e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    if (is_term_move) {
        if (e->args.size() != 2 || !e->args[0] || !e->args[1]) {
            return builtin_error(e->loc,
                                 "term_move: requiere 2 argumentos (row, col)",
                                 out_value);
        }
        // Emite "\x1b[" + row + ";" + col + "H" usando print + print_int.
        emit_print_string_literal("\x1b[", e->loc.line);
        // Sintetizar print_int(row) y print_int(col) reusando
        // try_lower_builtin_call con args sintetizados.
        for (int i = 0; i < 2; ++i) {
            const ir::IrValueId v = lower_expr(e->args[i].get());
            if (v == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            emit_native_call(kVestaIoLib, "vio_print_int", {v},
                             ir::IrType::VOID, e->loc.line);
            if (i == 0) {
                emit_print_string_literal(";", e->loc.line);
            }
        }
        emit_print_string_literal("H", e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    return false;
}

/**
 * @copydoc vx::Lowering::emit_print_typed_value
 */
void Lowering::emit_print_typed_value(ast::Expr *ex,
                                      const std::string &fmt_str) {
    if (!ex) return;
    // Impresion PERSONALIZADA (patron Display / __str__): si `ex` es un
    // struct/overlay que declara `to_string() -> string`, imprimimos
    // `ex.to_string()`.  Se sintetiza el call clonando `ex` como receptor.
    if (ex->result_type.kind == PrimitiveKind::STRUCT &&
        ex->kind != ast::NodeKind::CallExpr) {
        // evita recursion infinita
        auto itl = tc_.struct_layouts().find(ex->result_type.struct_name);
        if (itl != tc_.struct_layouts().end()) {
            const ClassMethodInfo *mth = find_method(itl->second, "to_string");
            if (mth && mth->return_type.kind == PrimitiveKind::STRING) {
                auto synth = std::make_unique<ast::CallExpr>();
                synth->loc = ex->loc;
                auto fa = std::make_unique<ast::FieldAccessExpr>();
                fa->loc = ex->loc;
                fa->field_name = "to_string";
                fa->base = vxgen::clone_expr(ex);
                if (fa->base) fa->base->result_type = ex->result_type;
                synth->callee = std::move(fa);
                synth->result_type = Type{PrimitiveKind::STRING};
                emit_print_typed_value(synth.get(), fmt_str);
                return;
            }
        }
    }
    // Caso especial: builtins de truecolor fg_rgb(r,g,b) /
    // bg_rgb(r,g,b) dentro de la interpolacion.  Se expanden a la
    // secuencia SGR 24-bit: fg -> "\x1b[38;2;R;G;Bm", bg ->
    // "\x1b[48;2;R;G;Bm".  Reusamos emit_print_string_literal para
    // los fragmentos ANSI y la propia emit_print_typed_value para
    // R,G,B (que se imprimen como enteros decimales).  Asi funciona
    // en interp/JIT/AOT sin construir StringObject ni helper nativo
    // nuevo, y r,g,b pueden ser literales o expresiones runtime.
    if (ex->kind == ast::NodeKind::CallExpr) {
        auto *ce = static_cast<ast::CallExpr *>(ex);
        if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr) {
            const std::string &cn =
                static_cast<ast::IdentExpr *>(ce->callee.get())->name;
            const bool is_fg = (cn == "fg_rgb");
            const bool is_bg = (cn == "bg_rgb");
            if (is_fg || is_bg) {
                if (ce->args.size() != 3) {
                    error_at(ex->loc, cn + ": requiere 3 argumentos (r, g, b)");
                    return;
                }
                emit_print_string_literal(is_fg ? "\x1b[38;2;" : "\x1b[48;2;",
                                          ex->loc.line);
                emit_print_typed_value(ce->args[0].get(), std::string());
                emit_print_string_literal(";", ex->loc.line);
                emit_print_typed_value(ce->args[1].get(), std::string());
                emit_print_string_literal(";", ex->loc.line);
                emit_print_typed_value(ce->args[2].get(), std::string());
                emit_print_string_literal("m", ex->loc.line);
                return;
            }
        }
    }
    const Type t = ex->result_type;
    // Parsear formato y, si hay alineacion right, calcular y emitir
    // padding ANTES del valor (para left-align se emite DESPUES).
    // Como no medimos el ancho exacto del valor a emitir (eso
    // requeriria itoa+len al vuelo), aceptamos un sub-set: el
    // usuario pasa un ancho que va a quedar como margen superior
    // al ancho real.  Para alineacion exacta de columnas con
    // valores variables, usar print_pad explicito.
    FmtSpec fs = parse_fmt_spec(fmt_str, ex->loc, diags_);
    // Caso especial: identificador ANSI magico -> emit la cadena
    // directamente como string literal (sin pasar por print_int).
    if (ex->kind == ast::NodeKind::IdentExpr) {
        auto *id_ex = static_cast<ast::IdentExpr *>(ex);
        if (const char *ansi = ansi_sequence_for(id_ex->name)) {
            emit_print_string_literal(ansi, ex->loc.line);
            return;
        }
    }
    // Caso especial: string literal directo (PTR a static_data).
    // NO recursamos en interpolacion anidada (raro y requeriria
    // std::function para auto-call).  Si llega un string
    // interpolado dentro de ${...}, error claro.
    if (ex->kind == ast::NodeKind::StringLitExpr) {
        auto *sl = static_cast<ast::StringLitExpr *>(ex);
        if (sl->is_interpolated()) {
            error_at(ex->loc,
                     "interpolacion anidada dentro de ${...} no soportada "
                     "(asignar a variable y usar la variable)");
            return;
        }
        emit_print_string_literal(sl->value, ex->loc.line);
        return;
    }
    // Lower la expr a un SSA value y despachar por tipo.
    ir::IrValueId v = lower_expr(ex);
    if (v == ir::IR_NO_VALUE) return;
    const ir::IrType vt = fn_->values[v].type;

    // -------------------------------------------------------------
    // AOT/bare (native_poo_): formateo de un valor de runtime SIN proc.
    // Despacha a los helpers __vx_print_* (libc, ABI plana).  El usuario
    // puede redefinir cualquiera.  Cubre escalares (dec/uint/hex/bin/oct/
    // ptr/bool/char) + char* (cstr).  Float y string value-type se
    // difieren con un warning claro.  El format-spec ${x:kind} elige el
    // helper; padding/alineacion se difiere (warning una vez).
    // -------------------------------------------------------------
    if (native_poo_) {
        if (t.kind == PrimitiveKind::F32 || t.kind == PrimitiveKind::F64) {
            // AOT: __vx_print_float(f64) del runtime de I/O (formateo %g
            // aproximado en Vesta puro).  F32 se promociona a F64 antes.
            ir::IrValueId vf = v;
            if (t.kind == PrimitiveKind::F32) {
                ir::IrValueId vp = emit_ir_unop(ir::IrOp::F32TOF64, v,
                                                ir::IrType::F64, ex->loc.line);
                vf = vp;
            }
            emit_io_prim("__vx_print_float", {vf}, ex->loc.line);
            return;
        }
        if (t.kind == PrimitiveKind::STRING) {
            // string value-type (Embed/AOT): (ptr,len) flag-aware (SSO) y
            // escritura via __vx_write (PURE_NATIVE).  El format-spec
            // ${s:>W} aplica padding via __vx_pad (fill_cp, count).
            ir::IrValueId sptr = emit_native_str_data_ptr(v, ex->loc.line);
            ir::IrValueId slen = emit_native_str_len(v, ex->loc.line);
            const bool need_pad =
                (fs.align != FmtSpec::Align::NONE) && (fs.width > 0);
            // pad = max(0, width - len); via SUB + clamp (CMP_GT*MUL).
            auto compute_pad = [&]() -> ir::IrValueId {
                ir::IrValueId v_width = emit_const(
                    ir::IrType::I64, (uint64_t)fs.width, ex->loc.line);
                ir::IrValueId v_sub =
                    emit_ir_binop(ir::IrOp::SUB, v_width, slen, ir::IrType::I64,
                                  ex->loc.line);
                ir::IrValueId v_zero =
                    emit_const(ir::IrType::I64, 0, ex->loc.line);
                ir::IrValueId v_pos =
                    emit_ir_binop(ir::IrOp::CMP_GT, v_sub, v_zero,
                                  ir::IrType::BOOL, ex->loc.line);
                ir::IrValueId v_mask = cast_if_needed(
                    v_pos, ir::IrType::BOOL, ir::IrType::I64, ex->loc.line,
                    /*is_explicit=*/true);
                ir::IrValueId v_cl =
                    emit_ir_binop(ir::IrOp::MUL, v_sub, v_mask, ir::IrType::I64,
                                  ex->loc.line);
                return v_cl;
            };
            auto emit_pad = [&](ir::IrValueId v_count) {
                ir::IrValueId v_fill = emit_const(
                    ir::IrType::I64, (uint64_t)fs.fill_cp, ex->loc.line);
                emit_io_prim("__vx_pad", {v_fill, v_count}, ex->loc.line);
            };
            ir::IrValueId v_pad = ir::IR_NO_VALUE;
            if (need_pad) v_pad = compute_pad();
            if (need_pad && fs.align == FmtSpec::Align::RIGHT) emit_pad(v_pad);
            emit_io_prim("__vx_write", {sptr, slen}, ex->loc.line);
            if (need_pad && fs.align == FmtSpec::Align::LEFT) emit_pad(v_pad);
            return;
        }
        if (fs.align != FmtSpec::Align::NONE && fs.width > 0) {
            diags_.warning(ex->loc, "padding/alineacion en print AOT nativo "
                                    "aun no soportado; se ignora el ancho");
        }
        const bool is_unsigned_t =
            (t.kind == PrimitiveKind::CHAR || t.kind == PrimitiveKind::U8 ||
             t.kind == PrimitiveKind::U16 || t.kind == PrimitiveKind::U32 ||
             t.kind == PrimitiveKind::U64);
        // Elegir el helper (kind explicito del format-spec o AUTO->tipo).
        std::string sym;
        bool as_signed_dec = false;
        if (fs.kind == FmtSpec::Kind::HEX)
            sym = "__vx_print_hex";
        else if (fs.kind == FmtSpec::Kind::BIN)
            sym = "__vx_print_bin";
        else if (fs.kind == FmtSpec::Kind::OCT)
            sym = "__vx_print_oct";
        else if (fs.kind == FmtSpec::Kind::PTR)
            sym = "__vx_print_ptr";
        else if (fs.kind == FmtSpec::Kind::BOOL)
            sym = "__vx_print_bool";
        else if (fs.kind == FmtSpec::Kind::CHAR)
            sym = "__vx_print_char";
        else if (fs.kind == FmtSpec::Kind::DEC) {
            sym = is_unsigned_t ? "__vx_print_u64" : "__vx_print_i64";
            as_signed_dec = !is_unsigned_t;
        } else {
            // AUTO: por tipo (mismo criterio que el path VM).
            switch (t.kind) {
            case PrimitiveKind::BOOL: sym = "__vx_print_bool"; break;
            case PrimitiveKind::PTR:
            case PrimitiveKind::ARRAY:
            case PrimitiveKind::CLASS: sym = "__vx_print_ptr"; break;
            // Un caracter se imprime como CARACTER.  Faltaba el caso, asi
            // que caia en el de por defecto y salia su punto de codigo:
            // `print("${c}")` con c='D' escribia 68.
            case PrimitiveKind::CHAR: sym = "__vx_print_char"; break;
            default:
                if (is_unsigned_t)
                    sym = "__vx_print_u64";
                else {
                    sym = "__vx_print_i64";
                    as_signed_dec = true;
                }
                break;
            }
        }
        // Extender el valor a 64 bits (los helpers toman u64/i64).  Para
        // decimal con signo, SEXT; en cualquier otro caso, ZEXT (bits).
        ir::IrValueId arg = v;
        if (vt != ir::IrType::I64 && vt != ir::IrType::PTR) {
            arg = fn_->new_value(ir::IrType::I64);
            ir::IrInstr ext{};
            ext.op = as_signed_dec ? ir::IrOp::SEXT : ir::IrOp::ZEXT;
            ext.type = ir::IrType::I64;
            ext.dst = arg;
            ext.operands = {v};
            ext.source_line = ex->loc.line;
            emit(current_block_, std::move(ext));
        }
        emit_io_prim(sym, {arg}, ex->loc.line);
        return;
    }

    // Format spec ${expr:fmt}: si el formato pide un kind concreto
    // (hex/bin/oct/dec/ptr/gc/char/bool) o alineacion, usamos el
    // helper unificado @c vio_print_fmt(value, kind, width,
    // fill, align) que combina formateo + padding en un solo
    // CALLN.  Sin formato (default), caemos al dispatch normal
    // por tipo abajo.
    const bool has_fmt =
        fs.kind != FmtSpec::Kind::AUTO || fs.align != FmtSpec::Align::NONE;
    if (has_fmt && t.kind != PrimitiveKind::STRING) {
        // Determinar el kind code para vio_print_fmt.  Si AUTO,
        // derivar del tipo de la expresion.  La logica es la
        // misma del switch de abajo.
        int kind_code = -1;
        if (fs.kind == FmtSpec::Kind::HEX)
            kind_code = 2;
        else if (fs.kind == FmtSpec::Kind::BIN)
            kind_code = 3;
        else if (fs.kind == FmtSpec::Kind::OCT)
            kind_code = 4;
        else if (fs.kind == FmtSpec::Kind::PTR)
            kind_code = 5;
        else if (fs.kind == FmtSpec::Kind::GC)
            kind_code = 6;
        else if (fs.kind == FmtSpec::Kind::BOOL)
            kind_code = 7;
        else if (fs.kind == FmtSpec::Kind::CHAR)
            kind_code = 8;
        else if (fs.kind == FmtSpec::Kind::DEC) {
            const bool unsigned_t =
                (t.kind == PrimitiveKind::CHAR || t.kind == PrimitiveKind::U8 ||
                 t.kind == PrimitiveKind::U16 || t.kind == PrimitiveKind::U32 ||
                 t.kind == PrimitiveKind::U64);
            kind_code = unsigned_t ? 1 : 0;
        } else {
            // AUTO: dispatch por tipo del operando.
            switch (t.kind) {
            case PrimitiveKind::BOOL: kind_code = 7; break;
            case PrimitiveKind::CHAR:
            case PrimitiveKind::U8:
            case PrimitiveKind::U16:
            case PrimitiveKind::U32:
            case PrimitiveKind::U64: kind_code = 1; break;
            case PrimitiveKind::I8:
            case PrimitiveKind::I16:
            case PrimitiveKind::I32:
            case PrimitiveKind::I64: kind_code = 0; break;
            case PrimitiveKind::F32:
            case PrimitiveKind::F64: kind_code = 9; break;
            case PrimitiveKind::PTR:
            case PrimitiveKind::ARRAY: kind_code = 5; break;
            case PrimitiveKind::CLASS: kind_code = 6; break;
            default: kind_code = 1; break;
            }
        }
        // Convertir el valor al uint64 que espera vio_print_fmt.
        ir::IrValueId v_arg = v;
        if (t.kind == PrimitiveKind::F32) {
            // F32 -> F64 (re-encoding) -> i64 bits.
            ir::IrValueId f64v = emit_ir_unop(ir::IrOp::F32TOF64, v_arg,
                                              ir::IrType::F64, ex->loc.line);
            ir::IrValueId bits = emit_ir_unop(ir::IrOp::BITCAST, f64v,
                                              ir::IrType::I64, ex->loc.line);
            v_arg = bits;
        } else if (t.kind == PrimitiveKind::F64 && vt != ir::IrType::I64) {
            ir::IrValueId bits = emit_ir_unop(ir::IrOp::BITCAST, v_arg,
                                              ir::IrType::I64, ex->loc.line);
            v_arg = bits;
        } else if (t.kind == PrimitiveKind::CLASS) {
            // CLASS -> GcHandle via instruccion `gchandle`.
            v_arg = emit_gc_handle_for_ptr(v_arg, ex->loc.line);
        } else {
            // Numeros enteros y punteros: cast (silencioso) a I64.
            v_arg = cast_if_needed(v_arg, vt, ir::IrType::I64, ex->loc.line,
                                   /*is_explicit=*/true);
        }
        // Constantes para kind, width, fill, align.
        ir::IrValueId v_kind = emit_const(
            ir::IrType::I64, (uint64_t)(uint32_t)kind_code, ex->loc.line);
        ir::IrValueId v_width =
            emit_const(ir::IrType::I64, (uint64_t)fs.width, ex->loc.line);
        ir::IrValueId v_fill =
            emit_const(ir::IrType::I64, (uint64_t)fs.fill_cp, ex->loc.line);
        int align_code = (fs.align == FmtSpec::Align::LEFT)    ? 1
                         : (fs.align == FmtSpec::Align::RIGHT) ? 2
                                                               : 0;
        ir::IrValueId v_align =
            emit_const(ir::IrType::I64, (uint64_t)align_code, ex->loc.line);
        emit_native_call(kVestaIoLib, "vio_print_fmt",
                         {v_arg, v_kind, v_width, v_fill, v_align},
                         ir::IrType::VOID, ex->loc.line);
        return;
    }

    // Caso STRING: el valor es GcHandle a un StringObject.  Emitir
    // STRRAW para obtener host_ptr al buffer + STRGETBYTES para la
    // longitud en bytes, y usar vio_print_buf para emitir el bloque
    // sin cortar en NUL (binary-safe; preserva multi-byte UTF-8).
    if (t.kind == PrimitiveKind::STRING) {
        // native_poo (AOT): `string` es value-string {ptr,len,cap} con SSO;
        // (ptr,len) via accesores flag-aware + escritura por __vx_write
        // (PURE_NATIVE).  Full/JIT/interp: GcHandle via strraw/strgetbytes
        // + vio_print_buf (VM).
        ir::IrValueId v_ptr = native_poo_
                                  ? emit_native_str_data_ptr(v, ex->loc.line)
                                  : emit_strraw(v, ex->loc.line);
        ir::IrValueId v_len = native_poo_ ? emit_native_str_len(v, ex->loc.line)
                                          : emit_strgetbytes(v, ex->loc.line);
        // Item 17: format spec en STRING.  Si align != NONE Y
        // width > 0, calcular padding = max(0, width - len) y
        // emitirlo antes (RIGHT) o despues (LEFT) del print_buf.
        // No support para kind=HEX/BIN/etc en strings (no aplica).
        const bool need_pad =
            (fs.align != FmtSpec::Align::NONE) && (fs.width > 0);
        ir::IrValueId v_pad = ir::IR_NO_VALUE;
        if (need_pad) {
            // pad_count = (width > len) ? (width - len) : 0
            // Implementado via SUB + CMOV.  Como no tengo CMOV en
            // el IR, uso: pad = width - len; if (pad < 0) pad = 0.
            // Cmps signed: si len > width, sub queda negativo.
            ir::IrValueId v_width =
                emit_const(ir::IrType::I64, (uint64_t)fs.width, ex->loc.line);
            ir::IrValueId v_sub = emit_ir_binop(ir::IrOp::SUB, v_width, v_len,
                                                ir::IrType::I64, ex->loc.line);
            // Clamp a 0: si v_sub < 0, usar 0.  Patron:
            // cmps v_sub, 0 -> SF; setcc gt -> 1 si positivo;
            // mul v_sub * mask = clamp.  Mas simple: usar
            // CMP_GT v_sub, 0 -> bool; cast a i64 (0 o 1);
            // mul v_sub * bool.
            ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, ex->loc.line);
            ir::IrValueId v_pos = emit_ir_binop(ir::IrOp::CMP_GT, v_sub, v_zero,
                                                ir::IrType::BOOL, ex->loc.line);
            ir::IrValueId v_mask =
                cast_if_needed(v_pos, ir::IrType::BOOL, ir::IrType::I64,
                               ex->loc.line, /*is_explicit=*/true);
            ir::IrValueId v_clamped = emit_ir_binop(
                ir::IrOp::MUL, v_sub, v_mask, ir::IrType::I64, ex->loc.line);
            v_pad = v_clamped;
        }
        // Emit padding LEADING si align==RIGHT.
        auto emit_pad_call = [&](ir::IrValueId v_count) {
            ir::IrValueId v_fill =
                emit_const(ir::IrType::I64, (uint64_t)fs.fill_cp, ex->loc.line);
            if (native_poo_) {
                // AOT: padding via __vx_pad (fill_cp, count) del runtime
                // de I/O (PURE_NATIVE); no hay vio_print_pad (VM).
                emit_io_prim("__vx_pad", {v_fill, v_count}, ex->loc.line);
                return;
            }
            emit_native_call(kVestaIoLib, "vio_print_pad", {v_fill, v_count},
                             ir::IrType::VOID, ex->loc.line);
        };
        if (need_pad && fs.align == FmtSpec::Align::RIGHT) {
            emit_pad_call(v_pad);
        }
        if (native_poo_) {
            // AOT: escribir los bytes via __vx_write (PURE_NATIVE).
            emit_io_prim("__vx_write", {v_ptr, v_len}, ex->loc.line);
        } else {
            emit_native_call(kVestaIoLib, "vio_print_buf", {v_ptr, v_len},
                             ir::IrType::VOID, ex->loc.line);
        }
        if (need_pad && fs.align == FmtSpec::Align::LEFT) {
            emit_pad_call(v_pad);
        }
        return;
    }
    std::string func;
    ir::IrType promote = ir::IrType::I64;
    switch (t.kind) {
    case PrimitiveKind::BOOL: func = "vio_print_bool"; break;
    case PrimitiveKind::CHAR:
    case PrimitiveKind::U8:
    case PrimitiveKind::U16:
    case PrimitiveKind::U32:
    case PrimitiveKind::U64: func = "vio_print_uint"; break;
    case PrimitiveKind::I8:
    case PrimitiveKind::I16:
    case PrimitiveKind::I32:
    case PrimitiveKind::I64: func = "vio_print_int"; break;
    case PrimitiveKind::F32:
    case PrimitiveKind::F64: func = "vio_print_float"; break;
    case PrimitiveKind::PTR:
    case PrimitiveKind::ARRAY:
        // Imprime "0x<hex>" compacto sin ceros lider.  El
        // mismo formato funciona tanto para punteros host
        // como virtuales: el numero es la direccion bruta.
        func = "vio_print_ptr";
        break;
    case PrimitiveKind::CLASS:
        // Para CLASS imprimimos el GcHandle como "<gc:N>".
        // Antes del CALLN debemos convertir el host_ptr al
        // handle via la instruccion @c gchandle.  Esto se
        // hace abajo en el bloque de F32/F64; aqui solo
        // marcamos el func.
        func = "vio_print_gchandle";
        break;
    default:
        // Fallback: trata como puntero a cstring (no len).
        // Por ahora no soportado; reportar error claro.
        error_at(ex->loc, "tipo de la expresion ${...} no es imprimible");
        return;
    }
    // Para floats el ABI de vio_print_float es "uint64_t bits"
    // (IEEE 754 raw f64).  Para F32 hay que extender primero a
    // F64 (cambia el patron de bits) antes del bitcast a I64.
    // Para F64 basta el bitcast (mismo ancho).  Para enteros
    // pequenos hace SEXT/ZEXT/TRUNC normal via cast_if_needed.
    if (t.kind == PrimitiveKind::F32) {
        ir::IrValueId f64v =
            emit_ir_unop(ir::IrOp::F32TOF64, v, ir::IrType::F64, ex->loc.line);
        ir::IrValueId bits = emit_ir_unop(ir::IrOp::BITCAST, f64v,
                                          ir::IrType::I64, ex->loc.line);
        v = bits;
    } else if (t.kind == PrimitiveKind::F64) {
        if (vt != ir::IrType::I64) {
            ir::IrValueId bits = emit_ir_unop(ir::IrOp::BITCAST, v,
                                              ir::IrType::I64, ex->loc.line);
            v = bits;
        }
    } else if (t.kind == PrimitiveKind::CLASS) {
        // El SSA value `v` es un host_ptr al objeto.  Convertir
        // a GcHandle (uint32) via la instruccion @c gchandle
        // antes de pasar al native.  vio_print_gchandle espera
        // el handle como uint64 zero-extended.
        v = emit_gc_handle_for_ptr(v, ex->loc.line);
    } else if (t.kind == PrimitiveKind::PTR || t.kind == PrimitiveKind::ARRAY) {
        // Punteros pasan tal cual; el ABI uint64 de
        // vio_print_ptr ya espera la direccion bruta.  Sin
        // cast_if_needed para no emitir un mov espureo.
    } else {
        v = cast_if_needed(v, vt, promote, ex->loc.line,
                           /*is_explicit=*/true);
    }
    emit_native_call(kVestaIoLib, func, {v}, ir::IrType::VOID, ex->loc.line);
}

} // namespace vx
