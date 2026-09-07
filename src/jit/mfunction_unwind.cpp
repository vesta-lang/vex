/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/mfunction_unwind.cpp
 * @brief Implementacion de @ref jit/mfunction_unwind.h.
 */

#include "jit/mfunction_unwind.h"

#include "jit/machine_ir.h"

namespace jit {

codegen::FrameUnwind frame_unwind_of(const MFunction &fn) {
    using codegen::FrameOp;

    codegen::FrameUnwind out;
    const MFunction::UnwindDesc &u = fn.unwind;

    out.owns_stack = u.naked;
    /* Los dos contadores tienen que estar: `prologue_instrs` lo pone quien
     * emite y `prologue_bytes` quien codifica, asi que uno a cero significa que
     * nadie midio.  Se colapsan en un solo cero porque la descripcion no tiene
     * por que saber que habia dos formas de no medir. */
    out.prologue_bytes = (fn.prologue_instrs == 0) ? 0u : fn.prologue_bytes;

    /* En el orden en que el generador las emitio.  El emisor guarda RBP y
     * establece el marco antes que nada -- para que un desenrollador pueda
     * apoyarse en el cuanto antes --, y la reserva de pila va al final, cuando
     * ya se sabe cuanto hace falta. */
    if (u.push_rbp)
        out.ops.push_back(
            {FrameOp::Kind::SaveReg, static_cast<uint32_t>(MReg::RBP), 0});
    if (u.frame_ptr)
        out.ops.push_back({FrameOp::Kind::SetFramePointer,
                           static_cast<uint32_t>(MReg::RBP), 0});
    if (u.push_rbx)
        out.ops.push_back(
            {FrameOp::Kind::SaveReg, static_cast<uint32_t>(MReg::RBX), 0});
    for (const uint8_t r : u.callee_saved)
        out.ops.push_back({FrameOp::Kind::SaveReg, r, 0});
    if (u.spill_bytes > 0)
        out.ops.push_back({FrameOp::Kind::AllocStack, 0, u.spill_bytes});

    return out;
}

} // namespace jit
