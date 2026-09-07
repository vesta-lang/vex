/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/jit/test_mfunction_unwind.cpp
 * @brief La traduccion de @c MFunction::UnwindDesc a la descripcion neutral.
 *
 * LO QUE SE VIGILA AQUI ES EL ORDEN, y merece decirse por que.  Un prologo mal
 * ORDENADO no produce una descripcion invalida: produce una VALIDA que dice
 * otra cosa.  El desenrollador no la comprueba -- no puede --, asi que la
 * aplica, deshace el marco al reves y sigue por una direccion de retorno que no
 * lo es.  Es el mismo fallo que el desenrollado del JIT vino a cerrar, y lo
 * unico que lo separa de volver son estas veinte lineas.
 *
 * Por eso el test compara la SECUENCIA entera y no campo a campo: cualquier
 * comprobacion que mire las operaciones sueltas pasaria con el orden invertido.
 */

#include "jit/machine_ir.h"
#include "jit/mfunction_unwind.h"

#include <cstdio>
#include <vector>

using codegen::FrameOp;
using codegen::FrameUnwind;
using jit::MFunction;
using jit::MReg;

static int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                               \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(c)) {                                                            \
            ++g_fails;                                                         \
            std::printf("  FALLO L%d: %s\n", __LINE__, #c);                    \
        }                                                                      \
    } while (0)

namespace {

/// Una operacion esperada, para poder comparar la secuencia de un vistazo.
struct Expected {
    FrameOp::Kind kind;
    uint32_t reg;
    uint32_t bytes;
};

/// Compara la secuencia ENTERA, que es lo unico que detecta un orden invertido.
bool same_ops(const FrameUnwind &got, const std::vector<Expected> &want) {
    if (got.ops.size() != want.size()) return false;
    for (size_t i = 0; i < want.size(); ++i) {
        if (got.ops[i].kind != want[i].kind) return false;
        if (got.ops[i].reg != want[i].reg) return false;
        if (got.ops[i].bytes != want[i].bytes) return false;
    }
    return true;
}

/// Imprime lo que salio, para no tener que adivinar cuando un CHECK falla.
void dump(const FrameUnwind &f) {
    std::printf("    ops:");
    for (const FrameOp &o : f.ops) {
        switch (o.kind) {
        case FrameOp::Kind::SaveReg: std::printf(" save(r%u)", o.reg); break;
        case FrameOp::Kind::SetFramePointer:
            std::printf(" fp(r%u)", o.reg);
            break;
        case FrameOp::Kind::AllocStack:
            std::printf(" alloc(%u)", o.bytes);
            break;
        }
    }
    std::printf("\n");
}

/// Una funcion con el prologo completo que emite el generador.
MFunction full_prologue() {
    MFunction fn;
    fn.unwind.push_rbp = true;
    fn.unwind.frame_ptr = true;
    fn.unwind.push_rbx = true;
    fn.unwind.callee_saved = {static_cast<uint8_t>(MReg::R12),
                              static_cast<uint8_t>(MReg::R13)};
    fn.unwind.spill_bytes = 32;
    fn.prologue_instrs = 6;
    fn.prologue_bytes = 18;
    return fn;
}

} // namespace

int main() {
    std::printf("== MFunction::UnwindDesc -> FrameUnwind ==\n");

    // --- El orden, que es lo que importa --------------------------------
    {
        const FrameUnwind f = jit::frame_unwind_of(full_prologue());
        const std::vector<Expected> want = {
            {FrameOp::Kind::SaveReg, static_cast<uint32_t>(MReg::RBP), 0},
            {FrameOp::Kind::SetFramePointer, static_cast<uint32_t>(MReg::RBP),
             0},
            {FrameOp::Kind::SaveReg, static_cast<uint32_t>(MReg::RBX), 0},
            {FrameOp::Kind::SaveReg, static_cast<uint32_t>(MReg::R12), 0},
            {FrameOp::Kind::SaveReg, static_cast<uint32_t>(MReg::R13), 0},
            {FrameOp::Kind::AllocStack, 0, 32},
        };
        if (!same_ops(f, want)) dump(f);
        CHECK(same_ops(f, want));
        CHECK(f.prologue_bytes == 18);
        CHECK(!f.owns_stack);

        /* Los callee-saved conservan SU orden, que es el de los push.  Si se
         * invirtieran aqui, el codificador -- que ya invierte -- los dejaria
         * en el orden original y la descripcion seria plausible y falsa. */
        CHECK(f.ops[3].reg == static_cast<uint32_t>(MReg::R12));
        CHECK(f.ops[4].reg == static_cast<uint32_t>(MReg::R13));
    }

    // --- Lo que se omite, se omite --------------------------------------
    {
        /* Un prologo minimo no debe arrastrar operaciones que nadie emitio:
         * describir un push que no ocurrio desplaza toda la pila. */
        MFunction fn;
        fn.unwind.push_rbp = true;
        fn.prologue_instrs = 1;
        fn.prologue_bytes = 1;

        const FrameUnwind f = jit::frame_unwind_of(fn);
        const std::vector<Expected> want = {
            {FrameOp::Kind::SaveReg, static_cast<uint32_t>(MReg::RBP), 0},
        };
        if (!same_ops(f, want)) dump(f);
        CHECK(same_ops(f, want));

        // Una reserva de cero no es una operacion.
        MFunction sin_pila = full_prologue();
        sin_pila.unwind.spill_bytes = 0;
        const FrameUnwind g = jit::frame_unwind_of(sin_pila);
        CHECK(g.ops.size() == 5);
        for (const FrameOp &o : g.ops)
            CHECK(o.kind != FrameOp::Kind::AllocStack);
    }

    // --- Las dos formas de "no se midio" colapsan en una ----------------
    {
        /* `prologue_instrs` lo pone quien emite y `prologue_bytes` quien
         * codifica.  Cualquiera de los dos a cero significa que no hay medida,
         * y la descripcion solo tiene una forma de decirlo. */
        MFunction sin_instrs = full_prologue();
        sin_instrs.prologue_instrs = 0;
        CHECK(jit::frame_unwind_of(sin_instrs).prologue_bytes == 0);

        MFunction sin_bytes = full_prologue();
        sin_bytes.prologue_bytes = 0;
        CHECK(jit::frame_unwind_of(sin_bytes).prologue_bytes == 0);

        /* Y no se pierden las operaciones al hacerlo: quien decide callarse es
         * el codificador, mirando `prologue_bytes`.  Que el adaptador vaciara
         * la lista esconderia el motivo. */
        CHECK(!jit::frame_unwind_of(sin_instrs).ops.empty());
    }

    // --- Una funcion duena de su pila -----------------------------------
    {
        MFunction naked = full_prologue();
        naked.unwind.naked = true;
        const FrameUnwind f = jit::frame_unwind_of(naked);
        CHECK(f.owns_stack);
        /* La marca viaja sola: el adaptador no decide, traduce.  Quien se
         * niega a describir es el codificador, y asi el motivo queda en un solo
         * sitio. */
        CHECK(!f.ops.empty());
    }

    std::printf("--- %d checks, %d fallos ---\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
