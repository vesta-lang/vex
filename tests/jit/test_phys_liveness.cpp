/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/jit/test_phys_liveness.cpp
 * @brief Que registros estan vivos en cada punto del MachineIR ya repartido.
 *
 * Lo que se comprueba no es el algoritmo -- gen/kill y punto fijo son de
 * manual -- sino que la respuesta incluya lo que NO se ve mirando los
 * operandos, que es donde se equivoca quien lo deduce por su cuenta:
 *
 *   - lo que una instruccion lee IMPLICITAMENTE (el RDX:RAX de una division);
 *   - las bases de una direccion, que se leen aunque el operando sea destino;
 *   - los registros de un bloque de `asm volatile`;
 *   - lo que cruza de un bloque a otro;
 *   - y lo que lee la CONVENCION de llamada, que no es de la instruccion.
 *
 * Cada caso construye la funcion a mano, pregunta, y compara contra lo que
 * tiene que salir.  Sin la suite completa detras: este fichero se compila y se
 * ejecuta solo.
 */

#include "analysis/facts/phys_liveness.h"

#include "jit/target_reginfo.h" // la convencion: cuales son, por ISA
#include "vx/asm/asm_effects.h" // isa_host()

#include <cstdio>

using namespace jit;
using analysis::facts::compute_phys_liveness;
using analysis::facts::PhysLivenessFacts;

namespace {

int failures = 0;

/// @brief El descriptor de registros del objetivo en el que corre el test.
///
/// Los casos que hablan de la CONVENCION no pueden nombrar registros: cuales
/// son cambia con la ISA, y clavar los de x86 haria que el test dijese lo
/// contrario de lo que comprueba al construirlo para arm64.  Se le pregunta al
/// mismo sitio al que se lo pregunta el codigo probado.
const TargetRegInfo &target_info() {
    return (vx::isa_host() == vx::instr_db::Isa::ARM64)
               ? target_arm64()
               : target_x86_64_vm_abi(/*vec_acc=*/false, /*fp_scratch=*/false);
}

/// @brief El registro por el que viaja el valor de retorno, en esta ISA.
uint8_t ret_reg_of_target() {
    return target_info().ret_reg[static_cast<size_t>(RegClass::GP)];
}

/// @brief El registro del primer argumento entero, en esta ISA.
uint8_t first_arg_reg() {
    const auto &v = target_info().arg_regs[static_cast<size_t>(RegClass::GP)];
    return v.empty() ? ret_reg_of_target() : v[0];
}

/// @brief Comprueba que @p r este (o no) vivo tras la instruccion @p i de @p b.
void expect(const PhysLivenessFacts &F, uint32_t b, uint32_t i, uint8_t r,
            bool vivo, const char *que) {
    const bool real = F.is_live_after(b, i, r);
    if (real == vivo) {
        std::printf("  ok    %s\n", que);
        return;
    }
    std::printf("  FALLO %s: salio %s, se esperaba %s\n", que,
                real ? "vivo" : "muerto", vivo ? "vivo" : "muerto");
    ++failures;
}

MOperand reg(MReg r, uint8_t w = 8) {
    return MOperand::make_reg(r, w);
}
MOperand reg(uint8_t r, uint8_t w = 8) {
    return MOperand::make_reg(static_cast<MReg>(r), w);
}
MOperand imm(int32_t v) {
    return MOperand::make_imm32(v);
}

/// @brief Una funcion de un solo bloque con las instrucciones dadas.
MFunction one_block(std::vector<MInstr> is) {
    MFunction f;
    f.target =
        &target_info(); // para QUE se compila: sin esto no hay convencion
    f.blocks.emplace_back();
    f.blocks[0].instrs = std::move(is);
    return f;
}

/* --- 1.  Lo basico: escribir y no leer. --------------------------------- */
void case_overwritten() {
    std::printf("pisar un registro sin leerlo\n");
    // mov rax, 1 ; mov rax, 2 ; mov rcx, rax
    MFunction f = one_block({
        MInstr::make_unary(MOp::MOV, reg(MReg::RAX), imm(1)),
        MInstr::make_unary(MOp::MOV, reg(MReg::RAX), imm(2)),
        MInstr::make_unary(MOp::MOV, reg(MReg::RCX), reg(MReg::RAX)),
    });
    const PhysLivenessFacts F = compute_phys_liveness(f);
    // Tras la PRIMERA, rax no esta vivo: la segunda lo pisa entero sin leerlo.
    expect(F, 0, 0, static_cast<uint8_t>(MReg::RAX), false,
           "tras el primer mov, rax muerto");
    // Tras la SEGUNDA si: la tercera lo lee.
    expect(F, 0, 1, static_cast<uint8_t>(MReg::RAX), true,
           "tras el segundo mov, rax vivo");
}

/* --- 2.  Lecturas IMPLICITAS: la division. ------------------------------ */
void case_division() {
    std::printf("una division lee RDX:RAX sin nombrarlos\n");
    // mov rdx, 0 ; idiv rsi
    MFunction f = one_block({
        MInstr::make_unary(MOp::MOV, reg(MReg::RDX), imm(0)),
        MInstr::make_unary(MOp::IDIV, reg(MReg::RSI), reg(MReg::RSI)),
    });
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Es EL caso que rompe a quien mira solo los operandos: `idiv rsi` no
     * nombra rdx en ninguna parte, asi que el `mov rdx, 0` de delante parece
     * una escritura muerta.  Borrarlo cambia el resultado de la division. */
    expect(F, 0, 0, static_cast<uint8_t>(MReg::RDX), true,
           "tras poner rdx a 0, rdx sigue vivo");
}

/* --- 3.  Una direccion LEE su base. ------------------------------------- */
void case_address() {
    std::printf("escribir en [rax] no escribe rax: lo lee\n");
    // mov rax, 8 ; mov [rax], rcx
    MFunction f = one_block({
        MInstr::make_unary(MOp::MOV, reg(MReg::RAX), imm(8)),
        MInstr::make_unary(MOp::MOV, MOperand::make_mem(MReg::RAX, 0),
                           reg(MReg::RCX)),
    });
    const PhysLivenessFacts F = compute_phys_liveness(f);
    expect(F, 0, 0, static_cast<uint8_t>(MReg::RAX), true,
           "rax vivo: es la base de la direccion");
}

/* --- 4.  Lo que cruza de un bloque a otro. ------------------------------ */
void case_across_blocks() {
    std::printf("un valor que se usa en el bloque siguiente\n");
    MFunction f;
    f.target = &target_info();
    f.blocks.emplace_back();
    f.blocks.emplace_back();
    f.blocks[0].instrs = {MInstr::make_unary(MOp::MOV, reg(MReg::RBX), imm(7))};
    f.blocks[0].succ_a = 1;
    f.blocks[1].instrs = {
        MInstr::make_unary(MOp::MOV, reg(MReg::RCX), reg(MReg::RBX))};
    const PhysLivenessFacts F = compute_phys_liveness(f);
    expect(F, 0, 0, static_cast<uint8_t>(MReg::RBX), true,
           "rbx vivo al salir del primer bloque");
    expect(F, 1, 0, static_cast<uint8_t>(MReg::RBX), false,
           "y muerto tras su ultima lectura");
}

/* --- 5.  Un bloque de `asm volatile` dice lo que lee. -------------------- */
void case_asm() {
    std::printf(
        "un asm volatile lee registros que no estan en los operandos\n");
    MFunction f;
    f.target = &target_info();
    f.blocks.emplace_back();
    AsmBlob b;
    b.bytes = {0x90};                              // nop: da igual lo que sea
    b.in_phys = {static_cast<uint8_t>(MReg::RSI)}; // lee rsi
    b.out_phys = {static_cast<uint8_t>(MReg::RAX)};
    b.clobbers_conocidos = true;
    f.asm_blobs.push_back(std::move(b));
    MInstr a = MInstr::make_unary(MOp::INLINE_ASM_RAW, MOperand(), imm(0));
    f.blocks[0].instrs = {
        MInstr::make_unary(MOp::MOV, reg(MReg::RSI), imm(3)),
        a,
    };
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Sin mirar el bloque, ese `mov rsi, 3` parece muerto: el asm no nombra
     * rsi en ningun operando.  Es el fallo que se vio de verdad. */
    expect(F, 0, 0, static_cast<uint8_t>(MReg::RSI), true,
           "rsi vivo: lo lee el asm");
}

/* --- 6.  Lo que lee la CONVENCION, no la instruccion. ------------------- */
void case_call_convention() {
    std::printf("un ret lee el registro del valor de retorno\n");
    // mov <ret>, 42 ; ret
    MFunction f = one_block({
        MInstr::make_unary(MOp::MOV, reg(ret_reg_of_target()), imm(42)),
        MInstr::make_ret(),
    });
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Este es el caso mas fino de todos, porque la base de instrucciones NO se
     * equivoca: un `ret` de x86 no lee rax, lee rsp y salta.  Que el resultado
     * viaje en rax es un ACUERDO entre el que llama y el llamado, y esa capa va
     * encima de la instruccion.
     *
     * Se vio asi: mientras la base no conocia `ret`, la respuesta la daba el
     * pseudo y la convencion estaba dentro de el.  En cuanto la base lo
     * aprendio empezo a contestar primero, la convencion dejo de aplicarse sin
     * que nada fallara al compilar, y todo programa devolvia 0 -- el `mov rax,
     * <resultado>` lo borraba quien busca escrituras muertas. */
    expect(F, 0, 0, ret_reg_of_target(), true,
           "el de retorno, vivo al llegar al ret");
}

/* --- 7.  Y una llamada lee sus argumentos. ------------------------------ */
void case_call() {
    std::printf("una llamada lee los registros de argumento\n");
    MFunction f;
    f.target = &target_info();
    f.blocks.emplace_back();
    MInstr c{};
    c.op = MOp::CALL;
    c.dst = MOperand::make_label(0);
    f.blocks[0].instrs = {
        MInstr::make_unary(MOp::MOV, reg(first_arg_reg()), imm(5)),
        c,
        MInstr::make_ret(),
    };
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Los argumentos tampoco aparecen en los operandos del `call`: los coloca
     * un pseudo-ARG antes.  Sin esta capa, la escritura que pone el argumento
     * en su registro no la lee nadie. */
    expect(F, 0, 0, first_arg_reg(), true,
           "el del primer argumento, vivo en la llamada");
}

/* --- 8.  Un salto a traves de un registro lee ese registro. ------------- */
void case_indirect_jump() {
    std::printf("un jmp por registro lee el registro, y pasa argumentos\n");
    MFunction f;
    f.target = &target_info();
    f.blocks.emplace_back();
    MInstr j{};
    j.op = MOp::JMP;
    j.src1 = reg(MReg::R10);
    j.flags |= MI_FLAG_TAILCALL; // lo dice quien la emite, no su forma
    f.blocks[0].instrs = {
        MInstr::make_unary(MOp::MOV, reg(MReg::R10), imm(0x1234)),
        MInstr::make_unary(MOp::MOV, reg(first_arg_reg()), imm(7)),
        j,
    };
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* A la base se le pregunta por MNEMONICO, asi que para `jmp` contesta lo
     * del salto RELATIVO, que no lee ningun registro.  Con un registro delante
     * es otra cosa: es a donde se va, y en este backend es ademas una llamada
     * de cola.  Sin esto el `mov` que pone la direccion salia muerto y con el
     * se iba el salto entero (visto en `19_tco_basico`). */
    expect(F, 0, 0, static_cast<uint8_t>(MReg::R10), true,
           "r10 vivo: es a donde salta");
    expect(F, 0, 1, first_arg_reg(), true,
           "y el argumento tambien: una llamada de cola los pasa");
}

/* --- 9.  Un salto por TABLA lee los registros de la direccion. ---------- */
void case_jump_table() {
    std::printf("un jmp [base + indice*8] lee la base y el indice\n");
    MFunction f;
    f.target = &target_info();
    f.blocks.emplace_back();
    MInstr j{};
    j.op = MOp::JMP;
    j.src1 = MOperand::make_mem(MReg::R11, 0, MReg::R10, 8);
    f.blocks[0].instrs = {
        MInstr::make_unary(MOp::MOV, reg(MReg::R10), imm(2)), // el indice
        MInstr::make_unary(MOp::MOV, reg(MReg::R11), imm(0)), // la base
        j,
    };
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Lo que lee un despacho por tabla son los registros de la DIRECCION, no
     * lo que hay en ella, y no los nombra como operandos de registro.  Sin
     * esto, el `mov` que calcula el indice sale muerto y el despacho salta a
     * donde sea (visto en `std.memory`). */
    expect(F, 0, 0, static_cast<uint8_t>(MReg::R10), true,
           "r10 vivo: es el indice de la tabla");
    expect(F, 0, 1, static_cast<uint8_t>(MReg::R11), true,
           "r11 vivo: es la base de la tabla");
}

/* --- 10.  Una escritura ESTRECHA no pisa el registro entero. ------------ */
void case_narrow_write() {
    std::printf("un setcc escribe un byte: lo de arriba sobrevive\n");
    MInstr sc{};
    sc.op = MOp::SETCC;
    sc.dst = reg(MReg::RAX); // el destino se nombra entero; escribe un byte
    MFunction f = one_block({
        MInstr::make_unary(MOp::MOV, reg(MReg::RAX), imm(0)),
        sc,
        MInstr::make_binary(MOp::TEST, reg(MReg::RAX), reg(MReg::RAX),
                            reg(MReg::RAX)),
    });
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Es el patron mas comun que existe para convertir una comparacion en un
     * cero o un uno, y el `mov` de arriba no sobra: es quien limpia los bytes
     * que el `setcc` no toca, y que el `test` de abajo SI mira.  Darlo por
     * pisado hacia que `81_math_builtins` devolviera 2 en vez de 42. */
    expect(F, 0, 0, static_cast<uint8_t>(MReg::RAX), true,
           "rax vivo: el setcc solo escribe su byte bajo");
}

/* --- 11.  Un bloque con una ISLA dentro no se recorre en linea recta. --- */
void case_island_in_block() {
    std::printf("un bloque con un salto y una etiqueta dentro: no se sabe\n");
    MFunction f;
    f.target = &target_info();
    f.blocks.emplace_back();
    MInstr jc = MInstr::make_jcc(MCond::NE, 7);
    f.blocks[0].instrs = {
        MInstr::make_unary(MOp::MOV, reg(MReg::R14), imm(5)),
        jc, // se salta lo de abajo
        MInstr::make_unary(MOp::POP, reg(MReg::R14), MOperand()), // lo pisa
        MInstr::make_label_def(7), // ...y aqui aterriza el salto
        MInstr::make_unary(MOp::MOV, reg(MReg::RAX), reg(MReg::R14)), // lo lee
        MInstr::make_ret(),
    };
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Yendo en linea recta, el `pop` pisa r14 y el `mov` de arriba parece
     * muerto.  Pero el salto se salta el `pop` y llega a un uso, asi que r14 SI
     * hace falta.  Como el control interno no se modela, la respuesta tiene que
     * ser "no se sabe" -- y no saber es vivo --.  Es lo que pasaba en
     * `346_optional_struct`. */
    expect(F, 0, 0, static_cast<uint8_t>(MReg::R14), true,
           "r14 vivo: hay un salto que se salta quien lo pisa");
    if (F.unknown_points == 0) {
        std::printf("  FALLO el bloque tenia una isla y no se conto\n");
        ++failures;
    } else {
        std::printf("  ok    y queda contado como punto sin saber\n");
    }
}

/* --- 12.  Un memset nativo lee tres registros que no nombra. ------------ */
void case_rep_stosb() {
    std::printf("un rep stosb lee donde, cuantos y que, sin nombrarlos\n");
    MInstr rep{};
    rep.op = MOp::REP_STOSB;
    MFunction f = one_block({
        MInstr::make_unary(MOp::MOV, reg(MReg::RDI), imm(0x100)), // donde
        MInstr::make_unary(MOp::MOV, reg(MReg::RCX), imm(16)),    // cuantos
        MInstr::make_unary(MOp::MOV, reg(MReg::RAX), imm(0)),     // que
        rep,
    });
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Su hermano `rep movsb` SI declaraba los suyos; este no, y ese es el modo
     * de fallar de una lista escrita a mano.  Sin esto las tres instrucciones
     * que preparan el memset salen muertas y `183_memcpy_idiom` devolvia 0. */
    expect(F, 0, 0, static_cast<uint8_t>(MReg::RDI), true,
           "rdi vivo: es a donde escribe");
    expect(F, 0, 1, static_cast<uint8_t>(MReg::RCX), true,
           "rcx vivo: es cuantos");
    expect(F, 0, 2, static_cast<uint8_t>(MReg::RAX), true,
           "rax vivo: es el byte que escribe");
}

/* --- 13.  Una llamada lee los registros que el DESTINO fija. ------------ */
void case_pinned_call_args() {
    std::printf("una llamada a algo que fija sus parametros los lee ahi\n");
    MFunction f;
    f.target = &target_info();
    /* r10 no es registro de argumento en ninguna convencion normal, pero la
     * llamada al sistema de Linux pone ahi su cuarto argumento, y la funcion
     * que la envuelve lo declara asi: `register("r10") size_t a4`. */
    f.pinned_regs = 1ull << static_cast<unsigned>(MReg::R10);
    f.blocks.emplace_back();
    MInstr c{};
    c.op = MOp::CALL;
    c.dst = MOperand::make_label(0);
    f.blocks[0].instrs = {
        MInstr::make_unary(MOp::MOV, reg(MReg::R10), imm(7)),
        c,
        MInstr::make_ret(),
    };
    const PhysLivenessFacts F = compute_phys_liveness(f);
    /* Sin esto la llamada dice leer solo los registros de la convencion, ese
     * `mov` sale muerto, y el binario se cae con violacion de segmento en
     * cuanto alguien lo borra -- visto en `342_syscalls_os` bajo WSL. */
    expect(F, 0, 0, static_cast<uint8_t>(MReg::R10), true,
           "r10 vivo: el destino fija ahi un parametro");
}

} // namespace

int main() {
    std::printf("== liveness por registro fisico ==\n");
    case_overwritten();
    case_division();
    case_address();
    case_across_blocks();
    case_asm();
    case_call_convention();
    case_call();
    case_indirect_jump();
    case_jump_table();
    case_narrow_write();
    case_island_in_block();
    case_rep_stosb();
    case_pinned_call_args();
    if (failures == 0) {
        std::printf("\nTODO OK\n");
        return 0;
    }
    std::printf("\n%d FALLO(S)\n", failures);
    return 1;
}
