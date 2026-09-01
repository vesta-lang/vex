/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia VMProject
 */

/**
 * @file test_ir_emitter.cpp
 * @brief Test del emisor SSA IR -> .vel: liveness, regalloc, optimizer y
 * emitter.
 *
 * Verifica:
 *   - compute_liveness: intervalos de vida correctos
 *   - allocate_regs:    asignacion de registros sin conflictos
 *   - ir_optimize:      DCE, copia, plegado, inalcanzables
 *   - ir_emit_module:   texto .vel bien formado para casos representativos
 */

#include "ir/ssa_ir.h"
#include "ir/liveness.h"
#include "codegen/vm_allocate.h"
#include "ir/regalloc.h"
#include "ir/ir_optimizer.h"
#include "ir/ir_emitter.h"

#include "emmit/parser_to_bytecode.h"
#include "lexer/lexer.h"
#include "parser/parser.h"
#include "linker/velb_linker_bytecode.h"
#include "runtime/manager_runtime.h"

/* manager_runtime.h arrastra <windows.h>, que define CONST/VOID/IN/OUT como
 * macros y contaminarian ir::IrOp::CONST / ir::IrType::VOID.  Se deshacen aqui,
 * despues del ultimo include del sistema. */
#ifdef CONST
#undef CONST
#endif
#ifdef VOID
#undef VOID
#endif
#ifdef IN
#undef IN
#endif
#ifdef OUT
#undef OUT
#endif

#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

static int g_pass = 0;
static int g_fail = 0;

static void check(bool cond, const char *msg) {
    if (cond) {
        ++g_pass;
        std::cout << "  [PASS] " << msg << "\n";
    } else {
        ++g_fail;
        std::cout << "  [FAIL] " << msg << "\n";
    }
}

// Verifica que la cadena haystack contiene needle
static bool contains(const std::string &haystack, const std::string &needle) {
    return haystack.find(needle) != std::string::npos;
}

/**
 * @brief Emite un modulo, lo lleva por el pipeline COMPLETO (lex -> parse ->
 *        assemble -> link -> load) y lo EJECUTA en el interprete; devuelve R0.
 *
 * Es la unica prueba que no se puede enganyar: comprueba lo que el programa
 * CALCULA, no como se ve su `.vel`.  Un test de forma ("contiene enter") se
 * rompe cuando el emisor mejora y da un falso fallo; este solo se rompe si el
 * resultado cambia.  El proceso arranca en la funcion @c main (convencion del
 * loader), asi que @p mod debe tener una.
 */
static std::optional<uint64_t> emit_assemble_run(const ir::IrModule &mod) {
    ir::EmitOptions eo;
    eo.opt_level = ir::OptLevel::O0;
    eo.emit_comments = false;
    eo.export_all = true;
    const ir::EmitResult er = ir::ir_emit_module(mod, eo);
    if (!er.ok || er.vel_text.empty()) return std::nullopt;

    vm::Lexer lexer(er.vel_text);
    vm::Parser parser(lexer);
    std::vector<std::unique_ptr<vm::ASTNode>> program;
    try {
        program = parser.parse();
    } catch (const std::exception &) {
        return std::nullopt;
    }

    Assembly::Bytecode::Assembler asmblr;
    const std::vector<uint8_t> bytecode = asmblr.assemble(program);

    Assembly::Bytecode::Linker::LinkerOptions lo;
    lo.output_path = "test_ir_emitter_run.velb";
    lo.generate_map_file = false;
    Assembly::Bytecode::Linker::Linker linker(lo);
    linker.add_assembly_unit(bytecode, &asmblr.ctx);
    linker.write_to_file(lo.output_path);

    runtime::ManageVM manager(nullptr, 0);
    runtime::VM *vm = manager.loader.create_vm_instance(1);
    runtime::ProcessVM *proc =
        manager.loader.load_executable(*vm, lo.output_path);
    if (!proc) return std::nullopt;
    vm->make_ready(proc->pid);
    vm->start();
    const uint64_t r0 = proc->registers.regs[0].qword();
    vm->stop();
    return r0;
}

// =========================================================================
//  Modulos de prueba reutilizables
// =========================================================================

// Funcion add(a: i64, b: i64) -> i64  { ret a + b }
static ir::IrModule build_add() {
    ir::IrModule mod;
    mod.name = "test";

    ir::IrFunction fn;
    fn.name = "add";
    fn.ret_type = ir::IrType::I64;

    ir::IrValueId va = fn.new_value(ir::IrType::I64, "a");
    ir::IrValueId vb = fn.new_value(ir::IrType::I64, "b");
    fn.params = {va, vb};
    fn.values[va].is_param = true;
    fn.values[vb].is_param = true;

    ir::IrBlockId entry = fn.new_block("entry");

    ir::IrValueId vr = fn.new_value(ir::IrType::I64, "r");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ADD;
        i.type = ir::IrType::I64;
        i.dst = vr;
        i.operands = {va, vb};
        fn.append(entry, i);
    }
    {
        ir::IrInstr i;
        i.op = ir::IrOp::RET;
        i.type = ir::IrType::I64;
        i.operands = {vr};
        fn.append(entry, i);
    }

    mod.add_function(std::move(fn));
    return mod;
}

// Funcion abs(x: i64) -> i64  con PHI y BR_COND
static ir::IrModule build_abs() {
    ir::IrModule mod;
    mod.name = "test";

    ir::IrFunction fn;
    fn.name = "abs_val";
    fn.ret_type = ir::IrType::I64;

    ir::IrValueId vx = fn.new_value(ir::IrType::I64, "x");
    fn.params = {vx};
    fn.values[vx].is_param = true;

    ir::IrBlockId entry = fn.new_block("entry");
    ir::IrBlockId bb_neg = fn.new_block("negate");
    ir::IrBlockId bb_end = fn.new_block("end");
    fn.blocks[bb_neg].preds = {entry};
    fn.blocks[bb_end].preds = {entry, bb_neg};

    ir::IrValueId vzero = fn.new_value(ir::IrType::I64, "zero");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::CONST;
        i.type = ir::IrType::I64;
        i.dst = vzero;
        i.imm = 0;
        fn.append(entry, i);
    }
    ir::IrValueId vcond = fn.new_value(ir::IrType::BOOL, "cond");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::CMP_LT;
        i.type = ir::IrType::I64;
        i.dst = vcond;
        i.operands = {vx, vzero};
        fn.append(entry, i);
    }
    {
        ir::IrInstr i;
        i.op = ir::IrOp::BR_COND;
        i.type = ir::IrType::VOID;
        i.operands = {vcond};
        i.target_block = bb_neg;
        i.false_block = bb_end;
        fn.append(entry, i);
    }

    ir::IrValueId vneg = fn.new_value(ir::IrType::I64, "negx");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::NEG;
        i.type = ir::IrType::I64;
        i.dst = vneg;
        i.operands = {vx};
        fn.append(bb_neg, i);
    }
    {
        ir::IrInstr i;
        i.op = ir::IrOp::BR;
        i.type = ir::IrType::VOID;
        i.target_block = bb_end;
        fn.append(bb_neg, i);
    }

    ir::IrValueId vres = fn.new_value(ir::IrType::I64, "result");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::PHI;
        i.type = ir::IrType::I64;
        i.dst = vres;
        i.phi_args = {{vx, entry}, {vneg, bb_neg}};
        fn.append(bb_end, i);
    }
    {
        ir::IrInstr i;
        i.op = ir::IrOp::RET;
        i.type = ir::IrType::I64;
        i.operands = {vres};
        fn.append(bb_end, i);
    }

    mod.add_function(std::move(fn));
    return mod;
}

// =========================================================================
//  Test 1: liveness analysis
// =========================================================================
static void test_liveness() {
    std::cout << "\n[Test 1] compute_liveness\n";

    ir::IrModule mod = build_add();
    const ir::IrFunction &fn = mod.functions[0];
    ir::LivenessResult lv = ir::compute_liveness(fn);

    check(lv.num_instrs == 2, "add: 2 instrucciones linealizadas");
    check(lv.intervals.size() == 3, "add: 3 intervalos (a, b, r)");

    // El parametro 'a' debe tener def=0
    bool found_a = false;
    for (const auto &li : lv.intervals) {
        if (fn.values[li.id].name == "a") {
            check(li.def == 0, "param 'a' tiene def=0");
            found_a = true;
        }
    }
    check(found_a, "intervalo para 'a' encontrado");

    // La funcion abs tiene 3 bloques; verificar block_start/block_end
    ir::IrModule mabs = build_abs();
    ir::LivenessResult lv2 = ir::compute_liveness(mabs.functions[0]);
    check(lv2.block_start.size() == 3, "abs: 3 entradas en block_start");
    check(lv2.block_start[0] == 0, "abs: bloque 0 comienza en posicion 0");
    check(lv2.block_start[1] > 0, "abs: bloque 1 comienza despues del 0");
    check(lv2.block_start[2] > lv2.block_start[1], "abs: bloque 2 > bloque 1");
}

// =========================================================================
//  Test 2: register allocator
// =========================================================================
static void test_regalloc() {
    std::cout << "\n[Test 2] allocate_regs\n";

    ir::IrModule mod = build_add();
    const ir::IrFunction &fn = mod.functions[0];
    ir::LivenessResult lv = ir::compute_liveness(fn);
    // El interprete asigna con el modelo (codegen::rbank), igual que JIT y AOT.
    codegen::RegAlloc alloc = codegen::vm_allocate(fn, lv, nullptr);

    // Parametros deben estar en r1 y r2 (convencion de llamada).
    ir::IrValueId va = fn.params[0];
    ir::IrValueId vb = fn.params[1];
    check(alloc.in_reg(va) && alloc.reg_of(va) == 1, "param a -> r1");
    check(alloc.in_reg(vb) && alloc.reg_of(vb) == 2, "param b -> r2");

    // El resultado 'r' debe estar asignado a algun registro (no r14/r15)
    // Encontrar el id del valor 'r'
    ir::IrValueId vr = ir::IR_NO_VALUE;
    for (const auto &v : fn.values) {
        if (v.name == "r") {
            vr = v.id;
            break;
        }
    }
    check(vr != ir::IR_NO_VALUE, "valor 'r' encontrado");
    if (vr != ir::IR_NO_VALUE) {
        check(alloc.in_reg(vr), "valor 'r' asignado a registro");
        if (alloc.in_reg(vr))
            check(alloc.reg_of(vr) < ir::ALLOC_REGS,
                  "registro de 'r' < ALLOC_REGS");
    }

    // Sin spills para una funcion tan simple.
    check(alloc.num_spill_slots == 0, "sin spills en add");

    // Funcion con muchos parametros: verificar que no se exceden registros
    ir::IrModule mod2;
    mod2.name = "test";
    ir::IrFunction fn2;
    fn2.name = "many_params";
    fn2.ret_type = ir::IrType::I64;
    // Crear 13 parametros (mas del limite de 12 en registros)
    for (int i = 0; i < 13; ++i) {
        ir::IrValueId vid =
            fn2.new_value(ir::IrType::I64, "p" + std::to_string(i));
        fn2.params.push_back(vid);
        fn2.values[vid].is_param = true;
    }
    ir::IrBlockId e2 = fn2.new_block("entry");
    {
        ir::IrInstr ins;
        ins.op = ir::IrOp::RET;
        ins.type = ir::IrType::VOID;
        fn2.append(e2, ins);
    }
    mod2.add_function(std::move(fn2));

    ir::LivenessResult lv2 = ir::compute_liveness(mod2.functions[0]);
    codegen::RegAlloc alloc2 =
        codegen::vm_allocate(mod2.functions[0], lv2, nullptr);
    // El parametro 13 (indice 12) no cabe en r1-r12; debe estar derramado.
    check(alloc2.num_spill_slots >= 1, "many_params: al menos 1 spill");
}

// =========================================================================
//  Test 3: optimizer DCE
// =========================================================================
static void test_optimizer_dce() {
    std::cout << "\n[Test 3] ir_pass_dce\n";

    ir::IrModule mod;
    mod.name = "test";
    ir::IrFunction fn;
    fn.name = "dead_code";
    fn.ret_type = ir::IrType::I64;

    ir::IrValueId va = fn.new_value(ir::IrType::I64, "a");
    fn.params = {va};
    fn.values[va].is_param = true;

    ir::IrBlockId entry = fn.new_block("entry");

    // Instruccion muerta: %dead = add %a, %a  (nunca usada)
    ir::IrValueId vdead = fn.new_value(ir::IrType::I64, "dead");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ADD;
        i.type = ir::IrType::I64;
        i.dst = vdead;
        i.operands = {va, va};
        fn.append(entry, i);
    }

    // Ret vivo
    {
        ir::IrInstr i;
        i.op = ir::IrOp::RET;
        i.type = ir::IrType::I64;
        i.operands = {va};
        fn.append(entry, i);
    }

    size_t before = fn.blocks[0].instrs.size();
    bool changed = ir::ir_pass_dce(fn);

    check(changed, "DCE: detecto instruccion muerta");
    check(fn.blocks[0].instrs.size() < before,
          "DCE: reducio el numero de instrucciones");
    check(fn.blocks[0].instrs.size() == 1, "DCE: solo queda el ret");

    mod.add_function(std::move(fn));
}

// =========================================================================
//  Test 4: optimizer constant folding
// =========================================================================
static void test_optimizer_const_fold() {
    std::cout << "\n[Test 4] ir_pass_const_fold\n";

    ir::IrModule mod;
    mod.name = "test";
    ir::IrFunction fn;
    fn.name = "const_fold";
    fn.ret_type = ir::IrType::I64;

    ir::IrBlockId entry = fn.new_block("entry");

    // %a = const 10
    ir::IrValueId va = fn.new_value(ir::IrType::I64, "a");
    fn.values[va].is_const = true;
    fn.values[va].const_val = 10;
    {
        ir::IrInstr i;
        i.op = ir::IrOp::CONST;
        i.type = ir::IrType::I64;
        i.dst = va;
        i.imm = 10;
        fn.append(entry, i);
    }

    // %b = const 20
    ir::IrValueId vb = fn.new_value(ir::IrType::I64, "b");
    fn.values[vb].is_const = true;
    fn.values[vb].const_val = 20;
    {
        ir::IrInstr i;
        i.op = ir::IrOp::CONST;
        i.type = ir::IrType::I64;
        i.dst = vb;
        i.imm = 20;
        fn.append(entry, i);
    }

    // %r = add %a, %b  -> debe plegarse a const 30
    ir::IrValueId vr = fn.new_value(ir::IrType::I64, "r");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ADD;
        i.type = ir::IrType::I64;
        i.dst = vr;
        i.operands = {va, vb};
        fn.append(entry, i);
    }

    {
        ir::IrInstr i;
        i.op = ir::IrOp::RET;
        i.type = ir::IrType::I64;
        i.operands = {vr};
        fn.append(entry, i);
    }

    mod.add_function(std::move(fn));
    bool changed = ir::ir_pass_const_fold(mod.functions[0]);

    check(changed, "const_fold: detecto expresion plegable");
    // La instruccion add debe haberse convertido en const
    const auto &instrs = mod.functions[0].blocks[0].instrs;
    bool found_const_30 = false;
    for (const auto &ins : instrs) {
        if (ins.op == ir::IrOp::CONST && ins.imm == 30) found_const_30 = true;
    }
    check(found_const_30, "const_fold: resultado es CONST 30");
}

// =========================================================================
//  Test 5: emisor - funcion add simple
// =========================================================================
static void test_emit_add() {
    std::cout << "\n[Test 5] ir_emit_module (add)\n";

    ir::IrModule mod = build_add();
    ir::EmitOptions opts;
    opts.opt_level =
        ir::OptLevel::O0; // sin optimizacion para ver la salida cruda
    opts.emit_comments = false;
    opts.export_all = true;

    ir::EmitResult r = ir::ir_emit_module(mod, opts);
    check(r.ok, "emit add: ok=true");
    check(!r.vel_text.empty(), "emit add: texto no vacio");
    check(contains(r.vel_text, "add:"), "emit add: etiqueta 'add' presente");

    /* La prueba que importa: EJECUTAR.  Un `main` que suma 20 + 22 y retorna
     * debe dar 42 -- si el emisor produce una suma ejecutable, sale; si no,
     * falla, sin depender de como se escriba el `.vel`.  Esto sustituye a los
     * checks de forma ("enter presente", "adds presente"): aquellos daban
     * falsos fallos cuando el emisor mejoraba (add es una hoja sin spills, no
     * lleva frame) y no probaban que el resultado fuera correcto. */
    ir::IrModule prog;
    prog.name = "test_add_run";
    {
        ir::IrFunction fn;
        fn.name = "main";
        fn.ret_type = ir::IrType::I64;
        const ir::IrBlockId e = fn.new_block("entry");
        const ir::IrValueId a = fn.new_value(ir::IrType::I64, "a");
        const ir::IrValueId b = fn.new_value(ir::IrType::I64, "b");
        const ir::IrValueId s = fn.new_value(ir::IrType::I64, "s");
        auto konst = [&](ir::IrValueId d, int64_t k) {
            ir::IrInstr i;
            i.op = ir::IrOp::CONST;
            i.type = ir::IrType::I64;
            i.dst = d;
            i.imm = k;
            fn.append(e, i);
        };
        konst(a, 20);
        konst(b, 22);
        {
            ir::IrInstr i;
            i.op = ir::IrOp::ADD;
            i.type = ir::IrType::I64;
            i.dst = s;
            i.operands = {a, b};
            fn.append(e, i);
        }
        {
            ir::IrInstr i;
            i.op = ir::IrOp::RET;
            i.type = ir::IrType::I64;
            i.operands = {s};
            fn.append(e, i);
        }
        prog.add_function(std::move(fn));
    }
    const std::optional<uint64_t> r0 = emit_assemble_run(prog);
    check(r0.has_value(), "emit add: main compila, ensambla, carga y ejecuta");
    check(r0.has_value() && *r0 == 42, "emit add: 20 + 22 == 42 (ejecutado)");
}

// =========================================================================
//  Test 6: emisor - abs con PHI y CMP fused
// =========================================================================
static void test_emit_abs() {
    std::cout << "\n[Test 6] ir_emit_module (abs con PHI+BR_COND fusionado)\n";

    ir::IrModule mod = build_abs();
    ir::EmitOptions opts;
    opts.opt_level = ir::OptLevel::O1;
    opts.emit_comments = false;
    opts.export_all = true;

    ir::EmitResult r = ir::ir_emit_module(mod, opts);
    check(r.ok, "emit abs: ok=true");
    check(contains(r.vel_text, "abs_val:"), "emit abs: etiqueta abs_val");
    /* La comparacion CON SIGNO y el salto, en la forma que el emisor elija.
     *
     * Este test exigia un `cmps` suelto, y el emisor FUSIONA la comparacion
     * con el salto en una sola instruccion (`cmpjmp.cc`) cuando entre las dos
     * no hay copias de phi.  Fijar la forma separada era fijar un detalle de
     * la emision, asi que en cuanto llego la fusion el test empezo a fallar
     * sobre codigo MEJOR -- y ademas la comprobacion de abajo seguia pasando
     * de casualidad, porque "cmpjmp.jge" contiene "jmp.jge".
     *
     * Se comprueba lo que importa: que compara con signo y que salta segun el
     * resultado, venga en una instruccion o en dos. */
    const bool fusionado = contains(r.vel_text, "cmpjmp.");
    check(fusionado || contains(r.vel_text, "cmps"),
          "emit abs: comparacion con signo para CMP_LT (fusionada o suelta)");
    // Debe haber una instruccion de salto condicional
    bool has_cond_jmp = contains(r.vel_text, "jmp.jge") ||
                        contains(r.vel_text, "jmp.jlt") ||
                        contains(r.vel_text, "jmp.je");
    check(has_cond_jmp, "emit abs: salto condicional presente");

    std::cout << "    --- .vel generado ---\n"
              << r.vel_text << "    --------------------\n";
}

// =========================================================================
//  Test 7: emisor - CALLN + GETPROC
// =========================================================================
static void test_emit_calln() {
    std::cout << "\n[Test 7] ir_emit_module (CALLN + GETPROC)\n";

    ir::IrModule mod;
    mod.name = "test";
    mod.native_libs.push_back("stdlib/native/io/vesta_io");

    ir::IrFunction fn;
    fn.name = "print_hello";
    fn.ret_type = ir::IrType::VOID;

    ir::IrBlockId entry = fn.new_block("entry");

    ir::IrValueId v_proc = fn.new_value(ir::IrType::PTR, "proc");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::GETPROC;
        i.type = ir::IrType::PTR;
        i.dst = v_proc;
        fn.append(entry, i);
    }

    ir::IrValueId v_addr = fn.new_value(ir::IrType::I64, "addr");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::CONST;
        i.type = ir::IrType::I64;
        i.dst = v_addr;
        i.imm = 0x1000;
        fn.append(entry, i);
    }

    ir::IrValueId v_len = fn.new_value(ir::IrType::I64, "len");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::CONST;
        i.type = ir::IrType::I64;
        i.dst = v_len;
        i.imm = 5;
        fn.append(entry, i);
    }

    {
        ir::IrInstr i;
        i.op = ir::IrOp::CALLN;
        i.type = ir::IrType::VOID;
        i.dst = ir::IR_NO_VALUE;
        i.func_name = "stdlib/native/io/vesta_io:vio_println";
        i.operands = {v_proc, v_addr, v_len};
        fn.append(entry, i);
    }

    {
        ir::IrInstr i;
        i.op = ir::IrOp::RET;
        i.type = ir::IrType::VOID;
        fn.append(entry, i);
    }

    mod.add_function(std::move(fn));

    ir::EmitOptions opts;
    opts.opt_level = ir::OptLevel::O1;
    opts.emit_comments = false;
    opts.export_all = true;

    ir::EmitResult r = ir::ir_emit_module(mod, opts);
    check(r.ok, "emit calln: ok=true");
    check(contains(r.vel_text, "getproc"), "emit calln: getproc presente");
    check(contains(r.vel_text, "calln"), "emit calln: calln presente");
    check(contains(r.vel_text, "vio_println"),
          "emit calln: nombre de funcion nativa");

    std::cout << "    --- .vel generado ---\n"
              << r.vel_text << "    --------------------\n";
}

// =========================================================================
//  Test 8: optimizer O2 sobre modulo con bloques inalcanzables
// =========================================================================
static void test_optimizer_unreachable() {
    std::cout << "\n[Test 8] ir_pass_unreachable\n";

    ir::IrModule mod;
    mod.name = "test";
    ir::IrFunction fn;
    fn.name = "dead_block";
    fn.ret_type = ir::IrType::I64;

    ir::IrValueId va = fn.new_value(ir::IrType::I64, "a");
    fn.params = {va};
    fn.values[va].is_param = true;

    ir::IrBlockId entry = fn.new_block("entry");
    ir::IrBlockId dead = fn.new_block("dead"); // nunca alcanzado
    ir::IrBlockId end = fn.new_block("end");
    fn.blocks[end].preds = {entry};
    (void)dead; // para evitar warning

    // entry: br end  (salta directamente a end, nunca va a dead)
    {
        ir::IrInstr i;
        i.op = ir::IrOp::BR;
        i.type = ir::IrType::VOID;
        i.target_block = end;
        fn.append(entry, i);
    }

    // dead: ret (inalcanzable)
    {
        ir::IrInstr i;
        i.op = ir::IrOp::RET;
        i.type = ir::IrType::I64;
        i.operands = {va};
        fn.append(dead, i);
    }

    // end: ret a
    {
        ir::IrInstr i;
        i.op = ir::IrOp::RET;
        i.type = ir::IrType::I64;
        i.operands = {va};
        fn.append(end, i);
    }

    size_t before = fn.blocks.size();
    mod.add_function(std::move(fn));
    bool changed = ir::ir_pass_unreachable(mod.functions[0]);

    check(changed, "unreachable: elimino bloque inalcanzable");
    check(mod.functions[0].blocks.size() < before,
          "unreachable: numero de bloques reducido");
    check(mod.functions[0].blocks.size() == 2,
          "unreachable: quedan 2 bloques (entry y end)");
}

// =========================================================================
//  Test 9: round-trip completo .ir -> emit -> texto .vel
// =========================================================================
static void test_emit_from_ir_text() {
    std::cout << "\n[Test 9] ir_emit_text (round-trip desde texto .ir)\n";

    // Modulo IR minimo en texto
    const std::string ir_src = R"ir(
; modulo de prueba
@module round_trip

@function multiply(x: i64, y: i64) -> i64 {
entry:
    result = mul.i64 x, y
    ret.i64 result
}
)ir";

    ir::EmitOptions opts;
    opts.opt_level = ir::OptLevel::O2;
    opts.emit_comments = false;
    opts.export_all = true;

    ir::EmitResult r = ir::ir_emit_text(ir_src, opts);
    check(r.ok, "ir_emit_text: ok=true");
    check(contains(r.vel_text, "multiply:"), "ir_emit_text: etiqueta multiply");
    check(contains(r.vel_text, "muls") || contains(r.vel_text, "mulu"),
          "ir_emit_text: instruccion mul presente");
    check(contains(r.vel_text, "ret"), "ir_emit_text: ret presente");

    std::cout << "    --- .vel generado ---\n"
              << r.vel_text << "    --------------------\n";
}

// =========================================================================
//  Test 10: optimizer O3 CSE (subexpresiones comunes)
// =========================================================================
static void test_optimizer_cse() {
    std::cout << "\n[Test 10] ir_pass_cse\n";

    ir::IrModule mod;
    mod.name = "test";
    ir::IrFunction fn;
    fn.name = "cse_test";
    fn.ret_type = ir::IrType::I64;

    ir::IrValueId va = fn.new_value(ir::IrType::I64, "a");
    ir::IrValueId vb = fn.new_value(ir::IrType::I64, "b");
    fn.params = {va, vb};
    fn.values[va].is_param = true;
    fn.values[vb].is_param = true;

    ir::IrBlockId entry = fn.new_block("entry");

    // %r1 = add a, b
    ir::IrValueId vr1 = fn.new_value(ir::IrType::I64, "r1");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ADD;
        i.type = ir::IrType::I64;
        i.dst = vr1;
        i.operands = {va, vb};
        fn.append(entry, i);
    }

    // %r2 = add a, b  (subexpresion comun: mismo op, mismo tipo, mismos
    // operandos)
    ir::IrValueId vr2 = fn.new_value(ir::IrType::I64, "r2");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ADD;
        i.type = ir::IrType::I64;
        i.dst = vr2;
        i.operands = {va, vb};
        fn.append(entry, i);
    }

    // %res = add r1, r2
    ir::IrValueId vres = fn.new_value(ir::IrType::I64, "res");
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ADD;
        i.type = ir::IrType::I64;
        i.dst = vres;
        i.operands = {vr1, vr2};
        fn.append(entry, i);
    }

    {
        ir::IrInstr i;
        i.op = ir::IrOp::RET;
        i.type = ir::IrType::I64;
        i.operands = {vres};
        fn.append(entry, i);
    }

    size_t before = fn.blocks[0].instrs.size();
    mod.add_function(std::move(fn));
    ir::ir_optimize(mod, ir::OptLevel::O3);

    // Despues de O3, la segunda "add a,b" debe eliminarse (reemplazada por r1)
    size_t after = mod.functions[0].blocks[0].instrs.size();
    check(after < before, "CSE: instrucciones reducidas tras O3");
}

// =========================================================================
//  Test 11: raw_asm — codigo ensamblador incrustado verbatim
// =========================================================================

static void test_raw_asm() {
    using namespace ir;
    std::cout
        << "\n[Test 11] raw_asm: emision verbatim y no eliminacion por DCE\n";

    // --- subtest A: round-trip parse/print ---
    const char *src = R"(
@module test_raw
@function swap() -> void {
entry:
    raw_asm "mov r14, r1\nmov r1, r2\nmov r2, r14"
    ret.void
}
)";
    IrModule mod;
    std::string err;
    bool ok = ir_parse(src, mod, err);
    check(ok, "raw_asm parse sin error");
    check(err.empty(), "raw_asm sin mensaje de error");

    // verificar que la instruccion quedo como RAW_ASM
    bool found_raw = false;
    if (ok && !mod.functions.empty()) {
        for (const auto &bb : mod.functions[0].blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op == IrOp::RAW_ASM) {
                    found_raw = true;
                    break;
                }
            }
        }
    }
    check(found_raw, "raw_asm: IrOp::RAW_ASM en el bloque parseado");

    // verificar que func_name contiene el texto expandido (sin escapes)
    if (ok && found_raw) {
        const IrInstr *raw_ins = nullptr;
        for (const auto &bb : mod.functions[0].blocks) {
            for (const auto &ins : bb.instrs)
                if (ins.op == IrOp::RAW_ASM) {
                    raw_ins = &ins;
                    break;
                }
        }
        check(raw_ins != nullptr &&
                  raw_ins->func_name.find("mov r14, r1") != std::string::npos,
              "raw_asm: func_name contiene la primera instruccion");
        check(raw_ins != nullptr &&
                  raw_ins->func_name.find('\n') != std::string::npos,
              "raw_asm: \\n expandido a newline real");
    }

    // --- subtest B: emision verbatim ---
    if (ok) {
        EmitResult er = ir_emit_module(mod);
        check(er.ok, "raw_asm emit: EmitResult ok");
        check(er.vel_text.find("mov r14, r1") != std::string::npos,
              "raw_asm emit: primera linea en salida .vel");
        check(er.vel_text.find("mov r1, r2") != std::string::npos,
              "raw_asm emit: segunda linea en salida .vel");
        check(er.vel_text.find("mov r2, r14") != std::string::npos,
              "raw_asm emit: tercera linea en salida .vel");
    }

    // --- subtest C: DCE no elimina raw_asm ---
    const char *src_dce = R"(
@module test_raw_dce
@function nodce() -> i64 {
entry:
    raw_asm "nop1"
    %r = const.i64 42
    ret.i64 %r
}
)";
    IrModule mod2;
    bool ok2 = ir_parse(src_dce, mod2, err);
    check(ok2, "raw_asm DCE: parse ok");
    if (ok2) {
        ir_optimize(mod2, OptLevel::O3);
        bool still_raw = false;
        for (const auto &bb : mod2.functions[0].blocks)
            for (const auto &ins : bb.instrs)
                if (ins.op == IrOp::RAW_ASM) still_raw = true;
        check(still_raw, "raw_asm DCE: instruccion sobrevive a O3");
    }
}

// =========================================================================
//  Test 12: GETFIELD / SETFIELD lowering correcto
// =========================================================================
static void test_getfield_setfield() {
    using namespace ir;
    std::cout
        << "\n[Test 12] GETFIELD/SETFIELD -> gcderef+addcur+readcur/writecur\n";

    // getfield.i64 %obj, 32  (campo en byte 32 del objeto GC)
    const char *src = R"(
@module test_fields
@function read_field(obj: handle) -> i64 {
entry:
    %v = getfield.i64 %obj, 32
    ret.i64 %v
}
@function write_field(obj: handle, val: i64) -> void {
entry:
    setfield.i64 %obj, 32, %val
    ret.void
}
@function write_handle_field(obj: handle, h: handle) -> void {
entry:
    setfield.handle %obj, 24, %h
    ret.void
}
)";
    IrModule mod;
    std::string err;
    bool ok = ir_parse(src, mod, err);
    check(ok, "getfield/setfield parse ok");
    if (!ok) {
        std::cout << "    error: " << err << "\n";
        return;
    }

    // Verificar que el parse creo los opcodes correctos
    bool found_getfield = false, found_setfield = false;
    for (const auto &fn : mod.functions) {
        for (const auto &bb : fn.blocks) {
            for (const auto &ins : bb.instrs) {
                if (ins.op == IrOp::GETFIELD) found_getfield = true;
                if (ins.op == IrOp::SETFIELD) found_setfield = true;
            }
        }
    }
    check(found_getfield, "getfield: IrOp::GETFIELD parseado");
    check(found_setfield, "setfield: IrOp::SETFIELD parseado");

    // Emitir y verificar que NO se emite getfield/setfield nativo (instruccion
    // VM incorrecta)
    EmitOptions opts;
    opts.opt_level = OptLevel::O0;
    EmitResult er = ir_emit_module(mod, opts);
    check(er.ok, "getfield/setfield emit ok");

    // Debe emitir gcderef + addcur + readcur en vez de getfield
    check(contains(er.vel_text, "gcderef"), "getfield emit: usa gcderef");
    check(contains(er.vel_text, "readcur"), "getfield emit: usa readcur");
    check(contains(er.vel_text, "writecur"), "setfield emit: usa writecur");
    check(contains(er.vel_text, "addcur"), "field emit: usa addcur con offset");

    // NO debe emitir las instrucciones incorrectas
    check(!contains(er.vel_text, "    getfield "),
          "getfield emit: no emite opcode VM 'getfield'");
    check(!contains(er.vel_text, "    setfield "),
          "setfield emit: no emite opcode VM 'setfield'");

    // El setfield con tipo HANDLE debe emitir gcwb (write barrier)
    check(contains(er.vel_text, "gcwb"),
          "setfield.handle emit: gcwb write barrier");
}

// =========================================================================
//  Test 13: String IR opcodes
// =========================================================================
static void test_string_ops() {
    using namespace ir;
    std::cout << "\n[Test 13] String IR opcodes -> instrucciones VM str*\n";

    const char *src = R"(
@module test_str
@function str_ops(a: handle, b: handle) -> handle {
entry:
    %cat = strcat.handle %a, %b
    %len = strlen.i64 %cat
    %cmp = strcmp.i64 %a, %b
    %flt = strflat.handle %cat
    %hsh = strhash.u64 %a
    %itn = strintern.handle %a
    %raw = strraw.ptr %a
    ret.handle %cat
}
@function str_reserve(cap: i64) -> handle {
entry:
    %buf = strreserve.handle %cap
    ret.handle %buf
}
)";
    IrModule mod;
    std::string err;
    bool ok = ir_parse(src, mod, err);
    check(ok, "string ops parse ok");
    if (!ok) {
        std::cout << "    error: " << err << "\n";
        return;
    }

    // Verificar presencia de opcodes
    bool has_strcat = false, has_strlen = false, has_strcmp = false;
    bool has_strflat = false, has_strhash = false, has_strintern = false;
    bool has_strraw = false, has_strreserve = false;
    for (const auto &fn : mod.functions)
        for (const auto &bb : fn.blocks)
            for (const auto &ins : bb.instrs) {
                if (ins.op == IrOp::STRCAT) has_strcat = true;
                if (ins.op == IrOp::STRLEN) has_strlen = true;
                if (ins.op == IrOp::STRCMP) has_strcmp = true;
                if (ins.op == IrOp::STRFLAT) has_strflat = true;
                if (ins.op == IrOp::STRHASH) has_strhash = true;
                if (ins.op == IrOp::STRINTERN) has_strintern = true;
                if (ins.op == IrOp::STRRAW) has_strraw = true;
                if (ins.op == IrOp::STRRESERVE) has_strreserve = true;
            }
    check(has_strcat, "strcat: IrOp parseado");
    check(has_strlen, "strlen: IrOp parseado");
    check(has_strcmp, "strcmp: IrOp parseado");
    check(has_strflat, "strflat: IrOp parseado");
    check(has_strhash, "strhash: IrOp parseado");
    check(has_strintern, "strintern: IrOp parseado");
    check(has_strraw, "strraw: IrOp parseado");
    check(has_strreserve, "strreserve: IrOp parseado");

    // Emitir y verificar instrucciones .vel
    EmitOptions opts;
    opts.opt_level = OptLevel::O0;
    EmitResult er = ir_emit_module(mod, opts);
    check(er.ok, "string ops emit ok");
    check(contains(er.vel_text, "strcat"), "strcat emit: mnemonic en .vel");
    check(contains(er.vel_text, "strlen"), "strlen emit: mnemonic en .vel");
    check(contains(er.vel_text, "strcmp"), "strcmp emit: mnemonic en .vel");
    check(contains(er.vel_text, "strflat"), "strflat emit: mnemonic en .vel");
    check(contains(er.vel_text, "strhash"), "strhash emit: mnemonic en .vel");
    check(contains(er.vel_text, "strintern"),
          "strintern emit: mnemonic en .vel");
    check(contains(er.vel_text, "strraw"), "strraw emit: mnemonic en .vel");
    check(contains(er.vel_text, "strreserve"),
          "strreserve emit: mnemonic en .vel");

    // Round-trip print
    std::ostringstream printed;
    ir_print(mod, printed);
    std::string txt = printed.str();
    check(contains(txt, "strcat"), "strcat round-trip en ir_print");
    check(contains(txt, "strlen"), "strlen round-trip en ir_print");
}

// =========================================================================
//  Test 14: TCO optimizer pass
// =========================================================================
static void test_tco() {
    using namespace ir;
    std::cout << "\n[Test 14] TCO pass: call + ret -> tailcall\n";

    // Funcion con tail call explicita (call seguido de ret del resultado)
    const char *src = R"(
@module test_tco
@function fact(n: i64) -> i64 {
entry:
    %r = call.i64 @fact(%n)
    ret.i64 %r
}
@function void_tail() -> void {
entry:
    call.void @void_tail()
    ret.void
}
@function no_tail(n: i64) -> i64 {
entry:
    %r = call.i64 @fact(%n)
    %r2 = add.i64 %r, %n
    ret.i64 %r2
}
)";
    IrModule mod;
    std::string err;
    bool ok = ir_parse(src, mod, err);
    check(ok, "TCO parse ok");
    if (!ok) {
        std::cout << "    error: " << err << "\n";
        return;
    }

    // Aplicar el pase TCO directamente
    bool changed1 = ir_pass_tailcall(mod.functions[0]); // fact
    bool changed2 = ir_pass_tailcall(mod.functions[1]); // void_tail
    bool changed3 =
        ir_pass_tailcall(mod.functions[2]); // no_tail (no debe cambiar)

    check(changed1, "TCO: fact tail call convertida");
    check(changed2, "TCO: void_tail convertida");
    check(!changed3, "TCO: no_tail NO convertida (no es tail position)");

    // Verificar que fact ahora tiene TAILCALL en lugar de CALL + RET
    bool has_tailcall = false, has_call = false;
    for (const auto &bb : mod.functions[0].blocks)
        for (const auto &ins : bb.instrs) {
            if (ins.op == IrOp::TAILCALL) has_tailcall = true;
            if (ins.op == IrOp::CALL) has_call = true;
        }
    check(has_tailcall, "TCO: fact contiene TAILCALL despues del pase");
    check(!has_call, "TCO: fact NO contiene CALL normal despues del pase");

    // Emitir y verificar mnemonic tailcall en .vel
    EmitOptions opts;
    opts.opt_level = OptLevel::O0;
    EmitResult er = ir_emit_module(mod, opts);
    check(er.ok, "TCO emit ok");
    check(contains(er.vel_text, "tailcall"),
          "TCO emit: mnemonic tailcall en .vel");

    // TCO debe activarse automaticamente en O2
    IrModule mod2;
    bool ok2 = ir_parse(src, mod2, err);
    check(ok2, "TCO O2: parse ok");
    if (ok2) {
        ir_optimize(mod2, OptLevel::O2);
        bool found_tc = false;
        for (const auto &fn : mod2.functions)
            for (const auto &bb : fn.blocks)
                for (const auto &ins : bb.instrs)
                    if (ins.op == IrOp::TAILCALL) found_tc = true;
        check(found_tc, "TCO O2: tailcall generada por ir_optimize");
    }
}

// =========================================================================
//  Test 15: Array IR opcodes (parse + emit)
// =========================================================================
static void test_array_ops() {
    using namespace ir;
    std::cout << "\n[Test 15] Array IR opcodes: parse y emit\n";

    const char *src = R"(
@module test_arrays
@function array_ops(arr: i64, idx: i64, val: i64) -> i64 {
entry:
    %n   = array_len.i64 %arr
    %v   = array_load.i64 %arr, %idx
    array_store.i64 %arr, %idx, %val
    ret.i64 %v
}
@function array_handle(arr: handle, idx: i64, h: handle) -> void {
entry:
    array_store.handle %arr, %idx, %h
    ret.void
}
)";
    IrModule mod;
    std::string err;
    bool ok = ir_parse(src, mod, err);
    check(ok, "array ops parse ok");
    if (!ok) {
        std::cout << "    error: " << err << "\n";
        return;
    }

    bool has_array_len = false, has_array_load = false, has_array_store = false;
    for (const auto &fn : mod.functions)
        for (const auto &bb : fn.blocks)
            for (const auto &ins : bb.instrs) {
                if (ins.op == IrOp::ARRAY_LEN) has_array_len = true;
                if (ins.op == IrOp::ARRAY_LOAD) has_array_load = true;
                if (ins.op == IrOp::ARRAY_STORE) has_array_store = true;
            }
    check(has_array_len, "array_len: IrOp parseado");
    check(has_array_load, "array_load: IrOp parseado");
    check(has_array_store, "array_store: IrOp parseado");

    // Emitir y verificar MOVC SIB generado
    EmitOptions opts;
    opts.opt_level = OptLevel::O0;
    EmitResult er = ir_emit_module(mod, opts);
    check(er.ok, "array ops emit ok");
    /* ARRAY_LOAD/STORE bajan al calculo de la direccion indexada: el offset del
     * elemento es idx * stride + cabecera.  El emisor lo hace con `mulu ..., 8`
     * (stride de i64) seguido de la carga/almacen.  Antes este check buscaba
     * `movc`; el emisor dejo de usarlo hace tiempo (fusiona la direccion con
     * mulu+addu), asi que fallaba sin que fuera un bug.  Se verifica la
     * INTENCION -- que exista el escalado por el stride del elemento -- no el
     * mnemonico exacto. */
    check(contains(er.vel_text, "mulu") && contains(er.vel_text, ", 8"),
          "array ops emit: escala el indice por el stride (mulu * 8)");
    // ARRAY_STORE con handle debe emitir el write barrier del GC.
    check(contains(er.vel_text, "gcwb"),
          "array_store.handle emit: gcwb write barrier");
    // La longitud vive en la cabecera del array: un load, sin escalar el
    // indice.
    check(contains(er.vel_text, "array_ops:"),
          "array_len emit: funcion emitida");
}

// =========================================================================
//  Test 16: GEP + GCWB_IR opcodes
// =========================================================================
static void test_gep_gcwb() {
    using namespace ir;
    std::cout << "\n[Test 16] GEP y GCWB_IR\n";

    const char *src = R"(
@module test_gep
@function gep_test(obj: handle) -> void {
entry:
    gep.ptr %obj, 48
    gcwb_ir %obj
    gcderef_ir %obj
    ret.void
}
)";
    IrModule mod;
    std::string err;
    bool ok = ir_parse(src, mod, err);
    check(ok, "gep/gcwb_ir/gcderef_ir parse ok");
    if (!ok) {
        std::cout << "    error: " << err << "\n";
        return;
    }

    bool has_gep = false, has_gcwb_ir = false, has_gcderef_ir = false;
    for (const auto &fn : mod.functions)
        for (const auto &bb : fn.blocks)
            for (const auto &ins : bb.instrs) {
                if (ins.op == IrOp::GEP) has_gep = true;
                if (ins.op == IrOp::GCWB_IR) has_gcwb_ir = true;
                if (ins.op == IrOp::GCDEREF_IR) has_gcderef_ir = true;
            }
    check(has_gep, "gep: IrOp::GEP parseado");
    check(has_gcwb_ir, "gcwb_ir: IrOp::GCWB_IR parseado");
    check(has_gcderef_ir, "gcderef_ir: IrOp::GCDEREF_IR parseado");

    // gep debe emitir gcderef + addcur
    EmitOptions opts;
    opts.opt_level = OptLevel::O0;
    EmitResult er = ir_emit_module(mod, opts);
    check(er.ok, "gep/gcwb_ir emit ok");
    check(contains(er.vel_text, "gcderef"), "gep emit: gcderef");
    check(contains(er.vel_text, "addcur"), "gep emit: addcur con offset");
    check(contains(er.vel_text, "gcwb"), "gcwb_ir emit: gcwb VM instruction");

    // DCE no debe eliminar gcwb_ir ni gep (son side-effecting)
    IrModule mod2;
    bool ok2 = ir_parse(src, mod2, err);
    check(ok2, "gep DCE test parse ok");
    if (ok2) {
        ir_optimize(mod2, OptLevel::O3);
        bool still_gcwb = false;
        for (const auto &fn : mod2.functions)
            for (const auto &bb : fn.blocks)
                for (const auto &ins : bb.instrs)
                    if (ins.op == IrOp::GCWB_IR) still_gcwb = true;
        check(still_gcwb, "gcwb_ir: no eliminado por DCE O3");
    }
}

// =========================================================================
//  Test 17: emit_debug emite comentarios @line
// =========================================================================
static void test_emit_debug() {
    using namespace ir;
    std::cout << "\n[Test 17] emit_debug: comentarios @line N\n";

    const char *src = R"(
@module test_debug
@function dbg(x: i64) -> i64 {
entry:
    %r = add.i64 %x, %x
    ret.i64 %r
}
)";
    IrModule mod;
    std::string err;
    bool ok = ir_parse(src, mod, err);
    check(ok, "emit_debug parse ok");
    if (!ok) return;

    // Sin emit_debug: no deben aparecer @line
    EmitOptions opts_no;
    opts_no.opt_level = OptLevel::O0;
    opts_no.emit_debug = false;
    opts_no.emit_comments = false;
    EmitResult er_no = ir_emit_module(mod, opts_no);
    check(er_no.ok, "emit_debug=false: emit ok");
    check(!contains(er_no.vel_text, "@line"),
          "emit_debug=false: sin comentarios @line");

    // Con emit_debug: deben aparecer @line
    EmitOptions opts_yes;
    opts_yes.opt_level = OptLevel::O0;
    opts_yes.emit_debug = true;
    opts_yes.emit_comments = false;
    EmitResult er_yes = ir_emit_module(mod, opts_yes);
    check(er_yes.ok, "emit_debug=true: emit ok");
    check(contains(er_yes.vel_text, "@line"),
          "emit_debug=true: comentarios @line presentes");
}

// =========================================================================
//  Test 18: Round-trip parse/print de los nuevos opcodes
// =========================================================================
static void test_new_opcodes_roundtrip() {
    using namespace ir;
    std::cout
        << "\n[Test 18] Round-trip parse/print de todos los nuevos opcodes\n";

    const char *src = R"(
@module test_roundtrip
@function rt_test(a: handle, b: handle, arr: i64, idx: i64) -> i64 {
entry:
    %cat  = strcat.handle %a, %b
    %len  = strlen.i64 %a
    %cmp  = strcmp.i64 %a, %b
    %flt  = strflat.handle %a
    %hsh  = strhash.u64 %a
    %itn  = strintern.handle %a
    %raw  = strraw.ptr %a
    %res  = strreserve.handle %len
    %v    = array_load.i64 %arr, %idx
    array_store.i64 %arr, %idx, %v
    %n    = array_len.i64 %arr
    gcwb_ir %a
    gep.ptr %a, 32
    gcderef_ir %b
    ret.i64 %len
}
)";
    IrModule mod;
    std::string err;
    bool ok = ir_parse(src, mod, err);
    check(ok, "new opcodes round-trip: parse ok");
    if (!ok) {
        std::cout << "    error: " << err << "\n";
        return;
    }

    // Imprimir y re-parsear
    std::ostringstream printed;
    ir_print(mod, printed);
    std::string ir_text = printed.str();

    IrModule mod2;
    bool ok2 = ir_parse(ir_text, mod2, err);
    check(ok2, "new opcodes round-trip: re-parse despues de print ok");

    // Verificar que los conteos de instrucciones son iguales
    if (ok && ok2) {
        size_t cnt1 = 0, cnt2 = 0;
        for (const auto &fn : mod.functions)
            for (const auto &bb : fn.blocks)
                cnt1 += bb.instrs.size();
        for (const auto &fn : mod2.functions)
            for (const auto &bb : fn.blocks)
                cnt2 += bb.instrs.size();
        check(cnt1 == cnt2,
              "new opcodes round-trip: mismo numero de instrucciones");
    }
}

// =========================================================================
//  main
// =========================================================================
int main() {
    std::cout << "=== IR Emitter Test Suite ===\n";

    test_liveness();
    test_regalloc();
    test_optimizer_dce();
    test_optimizer_const_fold();
    test_emit_add();
    test_emit_abs();
    test_emit_calln();
    test_optimizer_unreachable();
    test_emit_from_ir_text();
    test_optimizer_cse();
    test_raw_asm();
    test_getfield_setfield();
    test_string_ops();
    test_tco();
    test_array_ops();
    test_gep_gcwb();
    test_emit_debug();
    test_new_opcodes_roundtrip();

    std::cout << "\n=== Resultado: " << g_pass << " PASS, " << g_fail
              << " FAIL ===\n";
    return g_fail == 0 ? 0 : 1;
}
