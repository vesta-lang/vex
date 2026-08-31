/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_trip_count.cpp
 * @brief Implementacion del hecho trip-count (ver loop_trip_count.h).
 */

#include "analysis/facts/loop_trip_count.h"

namespace analysis {

using ir::IR_NO_VALUE;
using ir::IrInstr;
using ir::IrOp;
using ir::IrValueId;

namespace {

// Resuelve el valor CONSTANTE de @p v (la CONST que lo define en su bloque).
bool const_of(const ir::IrFunction &fn, const std::vector<int> &def_block,
              IrValueId v, int64_t &out) {
    if (v == IR_NO_VALUE || v >= fn.values.size()) return false;
    const int db = (v < def_block.size()) ? def_block[v] : -1;
    if (db < 0 || (size_t)db >= fn.blocks.size()) return false;
    for (const IrInstr &in : fn.blocks[db].instrs)
        if (in.dst == v && in.op == IrOp::CONST) {
            out = (int64_t)in.imm;
            return true;
        }
    return false;
}

} // namespace

LoopTripInfo compute_trip_count(const ir::IrFunction &fn,
                                const std::vector<int> &def_block,
                                const LoopIV &iv) {
    LoopTripInfo info;
    int64_t init_v = 0, bound_v = 0;
    /* Cada renuncia con SU motivo.  No es documentacion: es lo que decide que
     * puede hacer el consumidor.  Un limite que solo existe al ejecutar admite
     * una guarda; una forma que este analisis no cubre, no -- ahi lo que hay
     * que hacer es ampliar el analisis, y por eso se distinguen. */
    if (iv.stride <= 0) {
        /* Decreciente o sin avance: la formula de abajo da por hecho que se
         * sube.  El bucle puede estar perfectamente acotado; es el analisis el
         * que no llega, y decirlo asi es lo honesto. */
        info.reason = asa::UnknownReason::ShapeNotRecognized;
        info.code = "loop.non_increasing_iv";
        return info;
    }
    if (!const_of(fn, def_block, iv.init, init_v)) {
        info.reason = asa::UnknownReason::RuntimeDependent;
        info.code = "loop.non_constant_init";
        return info;
    }
    if (!const_of(fn, def_block, iv.bound, bound_v)) {
        info.reason = asa::UnknownReason::RuntimeDependent;
        info.code = "loop.non_constant_bound";
        return info;
    }

    // room = cuanto queda desde el primer iv (mas el offset de la guarda) hasta
    // N.
    const int64_t room = bound_v - iv.cmp_offset - init_v;
    if (room <= 0) {
        info.trip = 0; // no itera (guarda falsa de entrada).
        return info;
    }
    if (iv.cmp_op == IrOp::CMP_LT || iv.cmp_op == IrOp::CMP_ULT) {
        info.trip = (room + iv.stride - 1) / iv.stride; // ceil
    } else if (iv.cmp_op == IrOp::CMP_LE || iv.cmp_op == IrOp::CMP_ULE) {
        info.trip = room / iv.stride + 1; // floor + 1
    } else {
        /* La guarda no es `<` ni `<=`.  Otra FORMA que no se cubre, y no un
         * limite que dependa de la ejecucion: el bucle puede ser perfectamente
         * contado con `!=` y este analisis no sabe leerlo. */
        info.reason = asa::UnknownReason::ShapeNotRecognized;
        info.code = "loop.unsupported_guard";
    }
    return info;
}

} // namespace analysis
