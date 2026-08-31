/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/io.cpp
 * @brief Escribir al exterior, y los literales que se escriben.
 *
 * Escribir tiene DOS caminos, y de ahi que no sea una linea: con el runtime de
 * la maquina virtual delante se llama a su primitiva de salida, pasandole el
 * proceso; en un binario nativo no hay tal cosa, asi que se emiten los bytes
 * por un simbolo que el programador PUEDE REDEFINIR en Vesta.  Ese segundo
 * camino es lo que permite que un programa sin sistema operativo detras siga
 * pudiendo imprimir: quien sabe como se escribe ahi es el, no el compilador.
 *
 * Estas cuatro vivian como lambdas dentro de la bajada de los builtins, y de
 * ahi no podian salir aunque media docena de sitios las necesitara.  No
 * capturaban nada -- solo usan el estado del propio bajador --, asi que pasar a
 * metodos no cambio ninguna llamada.
 */
#include "vx/lowering.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <cstring>           // strlen, para comparar prefijos
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering (no es su interfaz)

namespace vx {

/// La biblioteca nativa de entrada y salida de la maquina virtual.
const std::string kVestaIoLib = "stdlib/native/io/vesta_io";

/**
 * @brief @c true si @p fn_name es una funcion que se invento el compilador.
 *
 * Sirve para no ponerles traza: quien la pide quiere ver SU programa, y un
 * recorrido lleno de nombres que no ha escrito no dice nada -- ademas de
 * meterse por medio en sitios donde no se le espera, como el resolutor de un
 * campo de una vista, que corre en cada acceso.
 *
 * La lista estaba escrita en TRES sitios y en ninguno completa: faltaban los
 * ayudantes de las vistas, los de las macros, los de copiar y los del spawn
 * remoto, que quedaban tratados como codigo del usuario.
 *
 * @param fn_name El nombre de la funcion, ya manglado.
 * @return @c true si la genero el compilador.
 */
bool is_compiler_generated_fn(const std::string &fn_name) {
    if (fn_name == "__module_init") return true;
    // Todas empiezan por dos guiones bajos, que un nombre de Vesta no puede
    // llevar: es lo que hace el prefijo seguro como marca.
    static const char *const kPrefixes[] = {
        "__new_",    // constructor sintetico de una clase
        "__async_",  // cuerpo de una funcion asincrona
        "__lambda_", // cuerpo de una lambda
        "__spawn_",  // cuerpo de un spawn
        "__rspawn_", // cuerpo de un spawn remoto
        "__ovl_",    // resolutores de una vista sobre bytes
        "__macro_",  // cuerpo de una macro bajado a funcion
        "__clone_",  // copia profunda generada para un tipo
        "__vx_",     // todo lo que aporta el runtime
    };
    for (const char *p : kPrefixes)
        if (fn_name.compare(0, std::strlen(p), p) == 0) return true;
    return false;
}

/// La que instrumenta la entrada y la salida de cada funcion.
const std::string kVestaTraceLib = "stdlib/native/runtime/vx_trace";

std::pair<ir::IrValueId, ir::IrValueId>
Lowering::emit_string_lit(ast::StringLitExpr *slit) {
    std::vector<uint8_t> bytes(slit->value.begin(), slit->value.end());
    const uint64_t lit_idx = out_mod_->intern_static_data(std::move(bytes));
    const uint64_t lit_len = (uint64_t)slit->value.size();
    const ir::IrValueId v_str = emit_str_lit_addr(lit_idx, slit->loc.line);
    const ir::IrValueId v_len =
        emit_const(ir::IrType::I64, lit_len, slit->loc.line);
    return {v_str, v_len};
}

// Helper que emite getproc en el bloque actual.

// -----------------------------------------------------------------
// Helpers para emitir un fragmento de salida.
//
// emit_print_string_literal(text):  CALLN vio_print(proc, addr, len)
//   con text registrado en static_data.  Si text vacio, no-op.
//
// emit_print_typed_value(expr):  segun el tipo de expr, despacha a
//   vio_print_int / _uint / _hex / _float / _bool / _char / o
//   vio_print(proc, addr, len) si el tipo es PTR (string).  Solo
//   un CALLN por valor; cero overhead intermedio.
//
// emit_print_arg(expr): si expr es StringLitExpr interpolado,
//   itera parts/exprs y emite UN CALLN por fragmento.  Si es un
//   string simple emite UN solo CALLN.  Si es escalar despacha
//   por tipo via emit_print_typed_value.
//
// emit_print_newline():  CALLN vio_print_newline (cero args).
// -----------------------------------------------------------------

// emit_io_prim(prim, args):  emite la llamada a una primitiva de I/O
// nativa (solo native_poo_).  Si el usuario DEFINIO una funcion Vesta con
// ese nombre (p.ej. `void __vx_write(u8* b, u64 n) {...}`) se llama a la
// SUYA (CALL interno, resuelto en el mismo objeto -> override en Vesta);
// si no, se usa el simbolo C por defecto (CALLN vx_bare_io:<prim>, lo
// aporta stdlib/native/io/vesta_io_bare.c).  Asi las primitivas son
// programables en el propio lenguaje sin import ni libreria std.
void Lowering::emit_io_prim(const std::string &prim,
                            const std::vector<ir::IrValueId> &args,
                            uint32_t line) {
    const bool user_defined = (tc_.function_sig_by_name(prim) != nullptr);
    ir::IrInstr ins{};
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = args;
    ins.source_line = line;
    if (user_defined) {
        ins.op = ir::IrOp::CALL;
        ins.func_name = prim;
    } else {
        out_mod_->register_native_import("vx_bare_io", prim);
        ins.op = ir::IrOp::CALLN;
        ins.func_name = "vx_bare_io:" + prim;
    }
    emit(current_block_, std::move(ins));
}

void Lowering::emit_print_string_literal(const std::string &text,
                                         uint32_t line) {
    if (text.empty()) return;
    std::vector<uint8_t> bytes(text.begin(), text.end());
    const uint64_t lit_idx = out_mod_->intern_static_data(std::move(bytes));
    const uint64_t lit_len = (uint64_t)text.size();
    const ir::IrValueId v_str = emit_str_lit_addr(lit_idx, line);
    const ir::IrValueId v_len = emit_const(ir::IrType::I64, lit_len, line);
    if (native_poo_) {
        // AOT/bare: sin proc -> escribir los bytes via __vx_write (el
        // usuario puede redefinirlo en Vesta).  v_str es host_ptr.
        fn_->values[v_str].is_host_ptr = true;
        emit_io_prim("__vx_write", {v_str, v_len}, line);
        return;
    }
    const ir::IrValueId v_proc = emit_getproc(line);
    emit_native_call(kVestaIoLib, "vio_print", {v_proc, v_str, v_len},
                     ir::IrType::VOID, line);
}

} // namespace vx
