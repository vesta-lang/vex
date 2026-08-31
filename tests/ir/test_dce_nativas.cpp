/**
 * @file test_dce_nativas.cpp
 * @brief El DCE consulta lo DECLARADO sobre las funciones nativas.
 *
 * Una llamada nativa es codigo que no esta en el programa, asi que sin mas
 * informacion lo unico honesto es conservarla.  Pero el modulo puede DECIR lo
 * que hace, y entonces deja de ser una caja negra: si lo unico que hacia era
 * llenar un buffer de pila que nadie lee, no queda nada que observar y sobra.
 *
 * Se comprueban las cuatro esquinas del criterio, porque las tres ultimas son
 * las que impiden que el arreglo se convierta en un miscompilado:
 *
 *   1. declarada, escribe un hueco de pila que nadie lee  -> se quita;
 *   2. declarada, pero alguien LEE ese hueco              -> se conserva;
 *   3. SIN declarar (el caso de siempre)                  -> se conserva;
 *   4. declarada como que hace E/S                        -> se conserva.
 *
 * El caso 1 no aparece hoy en el corpus -- el frontend dejo de emitir la
 * conversion por duplicado --, y justo por eso hace falta este test: sin el, la
 * regla se puede romper sin que nada lo note.
 */

#include "ir/ir_optimizer.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <string>

using namespace ir;

static int g_checks = 0;
static int g_fails = 0;

static void check(bool cond, const std::string &msg) {
    ++g_checks;
    if (!cond) {
        ++g_fails;
        std::printf("  FALLO: %s\n", msg.c_str());
    }
}

namespace {

const char *kLib = "stdlib/native/io/vesta_io";
const char *kFn = "escribe_buf";

/// Nombre con el que el IR referencia a la nativa ("lib:fn").
std::string nombre_llamada() {
    return std::string(kLib) + ":" + kFn;
}

/// Cuenta las llamadas nativas de @p fn.
int cuenta_calln(const IrFunction &fn) {
    int n = 0;
    for (const IrBlock &b : fn.blocks)
        for (const IrInstr &in : b.instrs)
            if (in.op == IrOp::CALLN) ++n;
    return n;
}

IrInstr &emitir(IrFunction &fn, uint32_t b, IrOp op, IrValueId dst,
                std::vector<IrValueId> ops) {
    IrInstr in{};
    in.op = op;
    in.dst = dst;
    in.type = IrType::I64;
    in.operands = std::move(ops);
    fn.blocks[b].instrs.push_back(std::move(in));
    return fn.blocks[b].instrs.back();
}

/**
 * @brief Modulo con una funcion que reserva 32 bytes y llama a la nativa.
 *
 * @param declarar  si el modulo dice lo que hace la nativa.
 * @param con_io    si lo declarado incluye E/S observable.
 * @param leer      si la funcion lee el buffer despues de la llamada.
 */
IrModule construir(bool declarar, bool con_io, bool leer) {
    IrModule mod;
    if (declarar) {
        IrNativeImport ni;
        ni.lib = kLib;
        ni.name = kFn;
        ni.effects.declared = true;
        ni.effects.writes_pointee = 1u << 0; // el buffer es el primer arg
        ni.effects.io = con_io;
        mod.native_imports.push_back(std::move(ni));
    }

    IrFunction fn;
    fn.name = "f";
    fn.ret_type = IrType::I64;
    const uint32_t b0 = fn.new_block("entry");

    const IrValueId buf = fn.new_value(IrType::PTR);
    emitir(fn, b0, IrOp::ALLOCA, buf, {}).imm = 32;
    fn.blocks[b0].instrs.back().type = IrType::I8;

    // El valor que se le pasa: una constante, para no depender de parametros.
    const IrValueId v = fn.new_value(IrType::I64);
    emitir(fn, b0, IrOp::CONST, v, {}).imm = 7;

    const IrValueId len = fn.new_value(IrType::I64);
    emitir(fn, b0, IrOp::CALLN, len, {buf, v}).func_name = nombre_llamada();

    IrValueId ret = v;
    if (leer) {
        // Alguien SI mira lo que la nativa dejo: la llamada pasa a importar.
        ret = fn.new_value(IrType::I64);
        emitir(fn, b0, IrOp::LOAD, ret, {buf});
    }
    emitir(fn, b0, IrOp::RET, IR_NO_VALUE, {ret});

    mod.functions.push_back(std::move(fn));
    return mod;
}

} // namespace

int main() {
    {
        IrModule mod = construir(/*declarar=*/true, /*con_io=*/false,
                                 /*leer=*/false);
        ir_optimize(mod, OptLevel::O2, /*allow_inline=*/false);
        check(cuenta_calln(mod.functions[0]) == 0,
              "declarada y nadie lee lo que escribe: la llamada sobra");
    }
    {
        IrModule mod = construir(/*declarar=*/true, /*con_io=*/false,
                                 /*leer=*/true);
        ir_optimize(mod, OptLevel::O2, /*allow_inline=*/false);
        check(cuenta_calln(mod.functions[0]) == 1,
              "declarada pero alguien lee el buffer: se conserva");
    }
    {
        IrModule mod = construir(/*declarar=*/false, /*con_io=*/false,
                                 /*leer=*/false);
        ir_optimize(mod, OptLevel::O2, /*allow_inline=*/false);
        check(cuenta_calln(mod.functions[0]) == 1,
              "sin declarar sigue siendo opaca: se conserva");
    }
    {
        IrModule mod = construir(/*declarar=*/true, /*con_io=*/true,
                                 /*leer=*/false);
        ir_optimize(mod, OptLevel::O2, /*allow_inline=*/false);
        check(cuenta_calln(mod.functions[0]) == 1,
              "declarada con E/S: el efecto es observable, se conserva");
    }

    std::printf("=== DCE de nativas declaradas: %d checks, %d fallos ===\n",
                g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
