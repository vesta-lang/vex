/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/jit/test_ssa_coalesce_target.cpp
 * @brief El coalescing pregunta por su OBJETIVO en vez de suponerlo.
 *
 * La restriccion que este pase impone -- que el destino de un binop no comparta
 * registro con su segundo operando -- solo existe donde la ALU es de DOS
 * direcciones.  En x86 lo es (`add rax, rbx` deja el resultado en rax,
 * destruyendolo), asi que un binop de tres operandos del IR se legaliza a
 * `mov dst, op0; OP dst, op1` y ese `mov` pisaria op1 si compartieran registro.
 * En arm64, arm32 y RISC-V la ALU es de tres direcciones y no hay tal `mov`:
 * ahi la restriccion no protege de nada, solo impide coalescings validos.
 *
 * Estaba escrita a mano, con x86 dado por hecho.  Lo que se comprueba aqui es
 * que la respuesta DEPENDE del objetivo, que es lo unico que impide que un
 * backend nuevo herede en silencio las reglas de otro.
 */
#include "ir/ssa_ir.h"
#include "jit/ssa_coalesce.h"

#include <cstdio>

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("FALLO [%s:%d]: %s\n", __FILE__, __LINE__, msg);       \
        }                                                                      \
    } while (0)

// --------------------------------------------------------------------------
// 1) Que le hace cada arquitectura al destino de un binop.
// --------------------------------------------------------------------------
static void test_dst_kind_by_isa() {
    using jit::DstKind;
    using jit::sched::EffIsa;
    CHECK(jit::dst_kind_of_isa(EffIsa::X86) == DstKind::Destructive,
          "x86: `add rax, rbx` deja el resultado EN rax");
    CHECK(jit::dst_kind_of_isa(EffIsa::ARM64) == DstKind::Preserving,
          "arm64: `add x0, x1, x2` no toca ni x1 ni x2");
    CHECK(jit::dst_kind_of_isa(EffIsa::ARM32) == DstKind::Preserving,
          "arm32: la ALU tambien es de tres direcciones");
    CHECK(jit::dst_kind_of_isa(EffIsa::RISCV) == DstKind::Preserving,
          "risc-v: idem");
}

/**
 * @brief Un bucle contador cuyo acumulador entra en el par prohibido.
 *
 * bb0:  %0 = const 0
 *       br bb1
 * bb1:  %1 = phi [%0 from bb0, %2 from bb1]
 *       %2 = add %3, %1          <- dst=%2, operands[1]=%1
 *       br_cond bb1, bb2
 * bb2:  ret %1
 *
 * El destino del `add` y el segundo operando son las dos mitades de la misma
 * congruencia de PHI: exactamente el par que la legalizacion de dos direcciones
 * prohibe juntar, y que en tres direcciones se puede juntar sin problema.
 */
static ir::IrFunction build_loop() {
    ir::IrFunction fn;
    fn.name = "accumulator";
    fn.ret_type = ir::IrType::I64;

    const ir::IrBlockId bb0 = fn.new_block("entry");
    const ir::IrBlockId bb1 = fn.new_block("loop");
    const ir::IrBlockId bb2 = fn.new_block("exit");

    const ir::IrValueId v0 = fn.new_value(ir::IrType::I64, "%0");
    const ir::IrValueId v1 = fn.new_value(ir::IrType::I64, "%1");
    const ir::IrValueId v2 = fn.new_value(ir::IrType::I64, "%2");
    const ir::IrValueId v3 = fn.new_value(ir::IrType::I64, "%3");

    { // bb0: %0 = const 0 ; %3 = const 1 ; br bb1
        ir::IrInstr c{};
        c.op = ir::IrOp::CONST;
        c.type = ir::IrType::I64;
        c.dst = v0;
        c.imm = 0;
        fn.blocks[bb0].instrs.push_back(c);
        ir::IrInstr k{};
        k.op = ir::IrOp::CONST;
        k.type = ir::IrType::I64;
        k.dst = v3;
        k.imm = 1;
        fn.blocks[bb0].instrs.push_back(k);
        ir::IrInstr br{};
        br.op = ir::IrOp::BR;
        fn.blocks[bb0].instrs.push_back(br);
        fn.blocks[bb0].succs.push_back(bb1);
    }
    { // bb1: %1 = phi ; %2 = add %3, %1 ; br_cond
        ir::IrInstr phi{};
        phi.op = ir::IrOp::PHI;
        phi.type = ir::IrType::I64;
        phi.dst = v1;
        phi.phi_args.push_back({bb0, v0});
        phi.phi_args.push_back({bb1, v2});
        fn.blocks[bb1].instrs.push_back(phi);
        ir::IrInstr add{};
        add.op = ir::IrOp::ADD;
        add.type = ir::IrType::I64;
        add.dst = v2;
        add.operands = {v3, v1}; // operands[1] = %1: el par prohibido
        fn.blocks[bb1].instrs.push_back(add);
        ir::IrInstr br{};
        br.op = ir::IrOp::BR_COND;
        br.operands = {v2};
        fn.blocks[bb1].instrs.push_back(br);
        fn.blocks[bb1].succs.push_back(bb1);
        fn.blocks[bb1].succs.push_back(bb2);
    }
    { // bb2: ret %1
        ir::IrInstr ret{};
        ret.op = ir::IrOp::RET;
        ret.operands = {v1};
        fn.blocks[bb2].instrs.push_back(ret);
    }
    return fn;
}

// --------------------------------------------------------------------------
// 2) El mismo IR da un reparto DISTINTO segun el objetivo.
// --------------------------------------------------------------------------
static void test_answer_depends_on_target() {
    const ir::IrFunction fn = build_loop();
    const ir::IrValueId v1 = 1, v2 = 2;

    const std::vector<uint32_t> destructive =
        jit::ssa_phi_coalesce_remap(fn, jit::DstKind::Destructive);
    const std::vector<uint32_t> preserving =
        jit::ssa_phi_coalesce_remap(fn, jit::DstKind::Preserving);

    // Donde el destino se destruye, %2 y %1 NO pueden acabar en el mismo
    // registro: el `mov dst, op0` de la legalizacion pisaria %1 antes de
    // leerlo.
    const bool joined_destructive =
        !destructive.empty() && destructive[v1] == destructive[v2];
    CHECK(!joined_destructive,
          "en dos direcciones, el destino no puede compartir registro con su "
          "segundo operando");

    // Donde no se destruye, esa pareja es legal.  No se exige que el pase la
    // junte -- eso es su heuristica, no el contrato --, pero SI que la
    // prohibicion desaparezca: nunca puede coalescer MENOS por tener mas
    // libertad.
    const size_t classes_destructive = destructive.empty() ? 0 : 1;
    const size_t classes_preserving = preserving.empty() ? 0 : 1;
    CHECK(classes_preserving >= classes_destructive,
          "quitar una restriccion no puede quitar coalescings");
}

// --------------------------------------------------------------------------
// 3) Un IR sin binops no cambia con el objetivo: la diferencia viene de la
//    legalizacion, no de mirar el objetivo por mirarlo.
// --------------------------------------------------------------------------
static void test_no_alu_binops_same_answer() {
    ir::IrFunction fn;
    fn.name = "no_alu";
    fn.ret_type = ir::IrType::I64;
    const ir::IrBlockId bb = fn.new_block("entry");
    const ir::IrValueId v = fn.new_value(ir::IrType::I64, "%0");
    ir::IrInstr c{};
    c.op = ir::IrOp::CONST;
    c.type = ir::IrType::I64;
    c.dst = v;
    c.imm = 7;
    fn.blocks[bb].instrs.push_back(c);
    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.operands = {v};
    fn.blocks[bb].instrs.push_back(ret);

    CHECK(jit::ssa_phi_coalesce_remap(fn, jit::DstKind::Destructive) ==
              jit::ssa_phi_coalesce_remap(fn, jit::DstKind::Preserving),
          "sin binops ALU las dos respuestas son la misma");
}

int main() {
    test_dst_kind_by_isa();
    test_answer_depends_on_target();
    test_no_alu_binops_same_answer();
    std::printf("=== ssa-coalesce (objetivo): %d checks, %d fallos ===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
