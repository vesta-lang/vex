/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_math.cpp
 * @brief Bajada de las operaciones matematicas.
 *
 * Veintiocho, y no son una sola cosa aunque lo parezcan: unas trabajan con
 * numeros reales -- raiz, potencia, seno --, otras con enteros -- el mayor de
 * dos, acotar entre dos limites -- y otras con los BITS del numero -- contar
 * los que estan a uno, cuantos ceros hay delante, dar la vuelta al orden de
 * los bytes --.  Las tres se escriben igual en Vesta y de ahi que se atiendan
 * juntas, pero bajan distinto y por eso el bloque distingue.
 *
 * Lo que las une de verdad es como viajan los numeros con decimales.  La
 * maquina virtual pasa los argumentos en registros de proposito general, asi
 * que un `f64` no viaja como numero sino como sus BITS metidos en un entero de
 * sesenta y cuatro; la funcion nativa los recibe asi y devuelve otros bits que
 * hay que volver a leer como numero.  Ese ida y vuelta es invisible en el
 * fuente -- `sqrt(2.0)` no lo menciona -- y es la razon de que estas no se
 * puedan tratar como una llamada normal.
 *
 * Las que devuelven un entero (el mayor de dos, acotar, contar bits) NO hacen
 * esa conversion: su resultado es un numero, no unos bits que representen uno.
 * Confundir los dos casos da valores absurdos que parecen aleatorios, y es el
 * error clasico de esta zona.
 *
 * Se separo de la funcion que despacha todos los builtins.  Entra por su
 * propio punto: si el nombre no es de esta familia, contesta que no y quien
 * pregunta sigue con las demas.
 */
#include "vx/lowering.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include "lowering_internal.h" // la cocina compartida (no es la interfaz)
#include <string>
#include <utility>

namespace vx {
namespace {

/**
 * @brief Una operacion matematica y como se baja.
 *
 * Las veintiocho estaban descritas en cuatro listas paralelas: una bandera por
 * operacion, la suma de las veintiocho para saber si la familia es esta, y
 * luego tres cadenas de @c if que elegian -- una por camino de bajada --.  Con
 * cuatro sitios que mantener a la vez pasaron dos cosas: tres operaciones
 * quedaron descritas DOS veces (con la segunda descripcion inalcanzable, detras
 * de un @c return), y una operacion que se anadiera sin tocar la tercera cadena
 * habria acabado llamando a una funcion nativa SIN NOMBRE.
 *
 * Aqui cada operacion se describe una vez.  Estar en la tabla es lo que la hace
 * de la familia, asi que no se puede pertenecer sin decir como se baja.
 */
struct MathBuiltin {
    Builtin b;     ///< Que operacion es.
    uint8_t nargs; ///< Cuantos argumentos exige.
    /**
     * @brief La funcion de la biblioteca, si se baja llamandola.
     *
     * Nulo significa que se baja a una instruccion del IR.  Se llama para lo
     * que libm hace mejor que cualquier cosa que sepamos emitir -- las
     * trascendentes -- y se emite instruccion para lo que el procesador tiene
     * en el juego de instrucciones.
     */
    const char *native;
    ir::IrOp op; ///< La instruccion, si @c native es nulo.
    /**
     * @brief En que trabaja: enteros (cierto) o numeros reales (falso).
     *
     * Decide las dos cosas que distinguen a un camino del otro: como entran los
     * argumentos y de que tipo sale el resultado.  Un real viaja como sus BITS
     * dentro de un entero, un entero viaja como el numero que es; confundirlos
     * da valores absurdos, y es el error clasico de esta zona.
     */
    bool integral;
};

/// Las veintiocho.  El orden no significa nada: cada una aparece una vez.
constexpr MathBuiltin kMathBuiltins[] = {
    // Reales, con instruccion propia en el procesador.
    {Builtin::Sqrt, 1, nullptr, ir::IrOp::FSQRT, false},
    {Builtin::Fabs, 1, nullptr, ir::IrOp::FABS, false},
    {Builtin::Fmin, 2, nullptr, ir::IrOp::FMIN, false},
    {Builtin::Fmax, 2, nullptr, ir::IrOp::FMAX, false},
    {Builtin::Floor, 1, nullptr, ir::IrOp::FFLOOR, false},
    {Builtin::Ceil, 1, nullptr, ir::IrOp::FCEIL, false},
    {Builtin::Round, 1, nullptr, ir::IrOp::FROUND, false},
    {Builtin::Trunc, 1, nullptr, ir::IrOp::FTRUNC, false},
    // Enteros y bits, tambien con instruccion propia.
    {Builtin::Abs, 1, nullptr, ir::IrOp::IABS, true},
    {Builtin::Imin, 2, nullptr, ir::IrOp::IMIN, true},
    {Builtin::Imax, 2, nullptr, ir::IrOp::IMAX, true},
    {Builtin::Iminu, 2, nullptr, ir::IrOp::IMINU, true},
    {Builtin::Imaxu, 2, nullptr, ir::IrOp::IMAXU, true},
    {Builtin::Ilog2, 1, nullptr, ir::IrOp::ILOG2, true},
    {Builtin::Popcount, 1, nullptr, ir::IrOp::POPCNT, true},
    {Builtin::Clz, 1, nullptr, ir::IrOp::CLZ, true},
    {Builtin::Ctz, 1, nullptr, ir::IrOp::CTZ, true},
    {Builtin::Bswap, 1, nullptr, ir::IrOp::BYTESWAP, true},
    {Builtin::Rotl, 2, nullptr, ir::IrOp::ROTL, true},
    {Builtin::Rotr, 2, nullptr, ir::IrOp::ROTR, true},
    // Las trascendentes: a la biblioteca, que las hace mejor.
    {Builtin::Pow, 2, "vmath_pow", ir::IrOp::NOP, false},
    {Builtin::Log, 1, "vmath_log", ir::IrOp::NOP, false},
    {Builtin::Log2, 1, "vmath_log2", ir::IrOp::NOP, false},
    {Builtin::Log10, 1, "vmath_log10", ir::IrOp::NOP, false},
    {Builtin::Sin, 1, "vmath_sin", ir::IrOp::NOP, false},
    {Builtin::Cos, 1, "vmath_cos", ir::IrOp::NOP, false},
    {Builtin::Tan, 1, "vmath_tan", ir::IrOp::NOP, false},
    // Y acotar, que aun no tiene instruccion.
    {Builtin::Clamp, 3, "vmath_clamp", ir::IrOp::NOP, true},
};

/// @return La entrada de @p b, o nulo si @p b no es una operacion matematica.
constexpr const MathBuiltin *math_builtin_for(Builtin b) {
    for (const MathBuiltin &m : kMathBuiltins)
        if (m.b == b) return &m;
    return nullptr;
}

} // namespace

/**
 * @brief Intenta bajar @p e como una de las operaciones matematicas.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_math_builtins(ast::CallExpr *e, Builtin b,
                                       ir::IrValueId &out_value) {
    /* Estar en la tabla es lo que hace que @p b sea de esta familia: no hay una
     * lista de miembros aparte de la que dice como se baja cada uno, asi que no
     * se puede pertenecer sin decir como. */
    const MathBuiltin *const m = math_builtin_for(b);
    if (!m) return false;

    /* El ABI de la biblioteca: los argumentos van en r1..rN y el resultado en
     * r0.  Un real viaja como sus BITS metidos en un entero de sesenta y
     * cuatro, asi que quien llama tiene que ponerlos ahi y quien recibe tiene
     * que volver a leerlos como numero.  Los que devuelven un entero no hacen
     * ese viaje: su resultado es el numero. */
    {
        const std::string lib_math = "stdlib/native/math/vesta_math";

        /* Lo que el procesador sabe hacer con UNA instruccion.  Emitirla en vez
         * de llamar a la biblioteca gana tres cosas: se puede plegar al
         * compilar (`sqrt(2.0)` acaba siendo el numero), el generador de codigo
         * nativo pone la instruccion de la maquina donde habria una llamada, y
         * el dia que haya otro procesador detras no hay que tocar nada de aqui.
         *
         * Era DOS ayudantes, uno para enteros y otro para reales, y las mismas
         * treinta lineas en los dos.  Lo unico que los separaba es como entra
         * el argumento y de que tipo sale, y las dos cosas las dice la tabla.
         */
        auto emit_irop = [&](ir::IrOp op, size_t nargs, bool integral) -> bool {
            if (e->args.size() != nargs) {
                return builtin_error(
                    e->loc,
                    std::string("'") + std::string(builtin_name(b)) +
                        "': " + std::to_string(nargs) + " arg(s)",
                    out_value);
            }
            const ir::IrType want =
                integral ? ir::IrType::I64 : ir::IrType::F64;
            std::vector<ir::IrValueId> ops;
            ops.reserve(nargs);
            for (auto &a : e->args) {
                ir::IrValueId v = lower_expr(a.get());
                if (v == ir::IR_NO_VALUE) {
                    out_value = ir::IR_NO_VALUE;
                    return true;
                }
                const ir::IrType vt = fn_->values[v].type;
                if (integral) {
                    v = cast_if_needed(v, vt, ir::IrType::I64, e->loc.line);
                } else if (vt == ir::IrType::F32) {
                    // Las de reales trabajan en f64.  Lo que no sea un real se
                    // deja como esta: ya son los bits, o quien llama los puso.
                    v = emit_ir_unop(ir::IrOp::F32TOF64, v, ir::IrType::F64,
                                     e->loc.line);
                }
                ops.push_back(v);
            }
            const ir::IrValueId v_dst = fn_->new_value(want);
            ir::IrInstr in{};
            in.op = op;
            in.type = want;
            in.dst = v_dst;
            in.operands = std::move(ops);
            in.source_line = e->loc.line;
            emit(current_block_, std::move(in));
            out_value = v_dst;
            return true;
        };
        if (!m->native) return emit_irop(m->op, m->nargs, m->integral);

        /* Y lo que se baja llamando a la biblioteca: las trascendentes -- que
         * libm hace mejor que cualquier cosa que sepamos emitir -- y acotar,
         * que aun no tiene instruccion propia.
         *
         * Aqui habia tambien tres ramas para el valor absoluto y el mayor y
         * menor de dos enteros, con sus nombres `vmath_abs` / `vmath_min` /
         * `vmath_max`.  Eran inalcanzables: los tres se bajan a instruccion
         * unas lineas mas arriba, detras de un @c return.  Se caen con la
         * cadena que los escondia. */
        const std::string func_name = m->native;
        const size_t expected_args = m->nargs;
        const ir::IrType ret_ir =
            m->integral ? ir::IrType::I64 : ir::IrType::F64;
        if (e->args.size() != expected_args) {
            return builtin_error(
                e->loc,
                std::string("'") + std::string(builtin_name(b)) +
                    "': " + std::to_string(expected_args) + " arg(s)",
                out_value);
        }
        std::vector<ir::IrValueId> ops;
        ops.reserve(expected_args);
        for (auto &a : e->args) {
            ir::IrValueId v = lower_expr(a.get());
            if (v == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            /* Un real entra como sus BITS, no como su valor: se reinterpreta
             * sin tocarlos (un @c BITCAST, NO una conversion, que cambiaria el
             * numero).  Un entero entra como el numero que es, con la
             * ampliacion normal a sesenta y cuatro bits. */
            const ir::IrType vt = fn_->values[v].type;
            if (vt == ir::IrType::F64 || vt == ir::IrType::F32) {
                if (vt == ir::IrType::F32) {
                    ir::IrValueId f64v = emit_ir_unop(
                        ir::IrOp::F32TOF64, v, ir::IrType::F64, e->loc.line);
                    v = f64v;
                }
                ir::IrValueId bits = emit_ir_unop(ir::IrOp::BITCAST, v,
                                                  ir::IrType::I64, e->loc.line);
                v = bits;
            } else {
                v = cast_if_needed(v, vt, ir::IrType::I64, e->loc.line);
            }
            ops.push_back(v);
        }
        const ir::IrValueId dst = emit_native_call(
            lib_math, func_name, std::move(ops), ret_ir, e->loc.line);
        out_value = dst;
        return true;
    }

    return false;
}

} // namespace vx
