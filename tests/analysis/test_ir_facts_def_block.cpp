/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_ir_facts_def_block.cpp
 * @brief Test de @c IrFacts::def_block -- en QUE bloque se define cada valor.
 *
 * Es la otra mitad de @c def_of, que dice QUE instruccion lo define.  Antes lo
 * construia CADA consumidor por su cuenta con el mismo doble bucle (el
 * desenrollador, el resolvedor de punteros y el reconocedor de memoria por
 * lotes), asi que lo que se comprueba aqui no es solo que el hecho sea
 * correcto: es que las dos mitades CONCUERDAN, que es lo que permite tirar los
 * recorridos propios sin cambiar ninguna decision.
 */

#include "analysis/facts/ir_facts.h"
#include "ir/ssa_ir.h"

#include <cstdio>

using namespace analysis;
using ir::IrBlock;
using ir::IrBlockId;
using ir::IrFunction;
using ir::IrInstr;
using ir::IrOp;
using ir::IrType;
using ir::IrValueId;

static int g_checks = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  [FAIL] %s (linea %d)\n", (msg), __LINE__);          \
        }                                                                      \
    } while (0)

/// Una instruccion que DEFINE @p dst (un CONST cualquiera sirve: lo que se
/// mide es donde queda anotada, no que calcula).
static IrInstr make_def(IrValueId dst, int64_t v) {
    IrInstr i;
    i.op = IrOp::CONST;
    i.type = IrType::I64;
    i.dst = dst;
    i.imm = v;
    return i;
}
static IrInstr make_br(IrBlockId t) {
    IrInstr i;
    i.op = IrOp::BR;
    i.type = IrType::VOID;
    i.dst = ir::IR_NO_VALUE;
    i.target_block = t;
    return i;
}
static IrInstr make_ret() {
    IrInstr i;
    i.op = IrOp::RET;
    i.type = IrType::VOID;
    i.dst = ir::IR_NO_VALUE;
    return i;
}

/// Reserva @p n valores en la funcion para que los ids sean validos.
static void with_values(IrFunction &fn, size_t n) {
    fn.values.resize(n);
}

int main() {
    std::printf("=== IrFacts::def_block ===\n");

    // ---------------------------------------------------------------------
    // Tres bloques, un valor definido en cada uno.
    // ---------------------------------------------------------------------
    {
        IrFunction fn;
        fn.name = "three_blocks";
        with_values(fn, 3);

        IrBlock entry, middle, exit_b;
        entry.name = "entry";
        entry.instrs.push_back(make_def(0, 10));
        entry.instrs.push_back(make_br(1));
        middle.name = "middle";
        middle.instrs.push_back(make_def(1, 20));
        middle.instrs.push_back(make_br(2));
        exit_b.name = "exit";
        exit_b.instrs.push_back(make_def(2, 30));
        exit_b.instrs.push_back(make_ret());
        fn.blocks = {entry, middle, exit_b};

        const IrFacts f = build_ir_facts(fn);

        CHECK(f.def_block.size() == fn.values.size(),
              "def_block no cubre todos los valores");
        CHECK(f.def_block[0] == 0, "%0 no se define en el bloque 0");
        CHECK(f.def_block[1] == 1, "%1 no se define en el bloque 1");
        CHECK(f.def_block[2] == 2, "%2 no se define en el bloque 2");

        /* Las dos mitades tienen que hablar del MISMO sitio: si `def_of` dice
         * que existe una instruccion definidora, `def_block` tiene que decir
         * en que bloque esta, y al reves.  Discrepar aqui es exactamente el
         * fallo que un consumidor con su propio recorrido no podia detectar. */
        for (IrValueId v = 0; v < fn.values.size(); ++v) {
            const bool has_instr = f.def(v) != nullptr;
            const bool has_block = f.def_block[v] >= 0;
            CHECK(has_instr == has_block,
                  "def_of y def_block no concuerdan sobre si hay definicion");
            if (!has_instr) continue;
            const int32_t b = f.def_block[v];
            CHECK(b >= 0 && (size_t)b < fn.blocks.size(),
                  "def_block fuera de rango");
            bool inside = false;
            for (const IrInstr &in : fn.blocks[b].instrs)
                if (&in == f.def(v)) inside = true;
            CHECK(inside, "la instruccion definidora no esta en ese bloque");
        }
    }

    // ---------------------------------------------------------------------
    // Un valor que NADIE define (un parametro) queda en -1.  Vale la
    // distincion: "no lo define nadie" no es "lo define el bloque 0".
    // ---------------------------------------------------------------------
    {
        IrFunction fn;
        fn.name = "undefined_value";
        with_values(fn, 2);
        fn.params = {0}; // %0 es parametro: no lo define ninguna instruccion.

        IrBlock entry;
        entry.name = "entry";
        entry.instrs.push_back(make_def(1, 7));
        entry.instrs.push_back(make_ret());
        fn.blocks = {entry};

        const IrFacts f = build_ir_facts(fn);
        CHECK(f.def_block[0] == -1, "un parametro no puede tener bloque de def");
        CHECK(f.def(0) == nullptr, "un parametro no puede tener instr de def");
        CHECK(f.param_index(0) == 0, "%0 deberia ser el parametro 0");
        CHECK(f.def_block[1] == 0, "%1 no se define en el bloque 0");
    }

    // ---------------------------------------------------------------------
    // Sin bloques: nada que decir, pero la tabla existe y esta dimensionada.
    // Un consumidor que indexe sin comprobar no debe leer fuera.
    // ---------------------------------------------------------------------
    {
        IrFunction fn;
        fn.name = "empty";
        with_values(fn, 4);

        const IrFacts f = build_ir_facts(fn);
        CHECK(f.def_block.size() == 4, "def_block sin dimensionar");
        for (IrValueId v = 0; v < 4; ++v)
            CHECK(f.def_block[v] == -1, "valor sin definicion no vale -1");
    }

    std::printf("\n=== def_block: %d checks, %d fallos ===\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
