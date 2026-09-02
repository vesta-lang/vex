/**
 * @file int_wraparound.cpp
 * @brief Implementacion del buscador de cuentas que se salen de su tipo.
 */
#include "analyze/int_wraparound.h"

#include <unordered_map>

namespace analyze {

bool int_type_bounds(ir::IrType t, int64_t &lo, int64_t &hi) {
    int bits = 0;
    bool with_sign = true;
    switch (t) {
    case ir::IrType::I8: bits = 8; break;
    case ir::IrType::I16: bits = 16; break;
    case ir::IrType::I32: bits = 32; break;
    case ir::IrType::U8: bits = 8; with_sign = false; break;
    case ir::IrType::U16: bits = 16; with_sign = false; break;
    case ir::IrType::U32: bits = 32; with_sign = false; break;
    /* Los de 64 quedan fuera: para saber si su cuenta se sale haria falta
     * aritmetica mas ancha que la que hay aqui, y afirmar de menos es el lado
     * seguro cuando lo que se emite es un ERROR. */
    default: return false;
    }
    if (with_sign) {
        lo = -(int64_t{1} << (bits - 1));
        hi = (int64_t{1} << (bits - 1)) - 1;
    } else {
        lo = 0;
        hi = (int64_t{1} << bits) - 1;
    }
    return true;
}

std::vector<IntWrap> find_int_wraparounds(const ir::IrFunction &fn) {
    std::vector<IntWrap> out;
    if (fn.is_native || fn.blocks.empty()) return out;

    /* Que valor lleva cada constante.  Se llena sobre la marcha y se lee en la
     * misma pasada: en forma SSA una definicion va siempre antes que sus usos,
     * asi que no hace falta punto fijo ni una segunda vuelta.
     *
     * Los CONST llevan su valor en `imm` con los BITS del tipo, asi que un
     * `const.i8 -1` viene como 0xFF...FF: se lee tal cual como i64 con signo,
     * que es como el resto del intermedio lo trata. */
    std::unordered_map<ir::IrValueId, int64_t> known;

    for (const ir::IrBlock &b : fn.blocks) {
        for (const ir::IrInstr &ins : b.instrs) {
            if (ins.dst == ir::IR_NO_VALUE) continue;
            if (ins.op == ir::IrOp::CONST) {
                known[ins.dst] = static_cast<int64_t>(ins.imm);
                continue;
            }
            // Una copia no cambia el valor: seguirla es gratis y evita que un
            // `mov` en medio esconda la cuenta.
            if (ins.op == ir::IrOp::MOV && ins.operands.size() == 1) {
                auto it = known.find(ins.operands[0]);
                if (it != known.end()) known[ins.dst] = it->second;
                continue;
            }
            if (ins.op != ir::IrOp::ADD && ins.op != ir::IrOp::SUB &&
                ins.op != ir::IrOp::MUL)
                continue;
            if (ins.operands.size() != 2) continue;
            int64_t lo = 0, hi = 0;
            if (!int_type_bounds(ins.type, lo, hi)) continue;
            auto ia = known.find(ins.operands[0]);
            auto ib = known.find(ins.operands[1]);
            if (ia == known.end() || ib == known.end()) continue;

            const int64_t x = ia->second, y = ib->second;
            int64_t r = 0;
            bool fits_in_64 = true;
            if (ins.op == ir::IrOp::ADD)
                fits_in_64 = !__builtin_add_overflow(x, y, &r);
            else if (ins.op == ir::IrOp::SUB)
                fits_in_64 = !__builtin_sub_overflow(x, y, &r);
            else
                fits_in_64 = !__builtin_mul_overflow(x, y, &r);
            // Ni en 64 bits cabe: no se puede afirmar el valor exacto, y sin
            // el no se dice nada.
            if (!fits_in_64) continue;
            // El resultado se propaga aunque se salga: lo que sigue opera
            // sobre lo que de verdad quedo, envuelto al tipo.
            known[ins.dst] = r;
            if (r >= lo && r <= hi) continue; // cabe: nada que decir
            // Y el programador puede haberlo dicho con un cast.
            if (ins.wrap_ok) continue;

            IntWrap w;
            w.line = ins.source_line;
            w.exact = r;
            w.lo = lo;
            w.hi = hi;
            w.type = ins.type;
            out.push_back(w);
        }
    }
    return out;
}

} // namespace analyze
