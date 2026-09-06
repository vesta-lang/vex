/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_effects.cpp
 * @brief Tests unitarios del modelo de efectos (Fase 0): reticulo de
 * AbstractLoc (TOP/BOTTOM, may_alias), LocSet (union, gen/kill, absorbente),
 *        combinadores seq/join (leyes: neutro, absorbente, conmutatividad de
 *        join, gen/kill de memoria y registros), y contratos declarativos.
 */
#include "analysis/facts/ir_facts.h"
#include "analysis/manager/analysis_manager.h"
#include "analysis/effects/effect_analysis.h"
#include "analysis/effects/effects.h"
#include "analysis/effects/ir_effects.h"
#include "analysis/effects/summary.h"

#include "ir/ssa_ir.h"

#include <cstdio>
#include <string>

using namespace analysis::effects;

static int g_checks = 0;
static int g_fails = 0;
static void check(bool ok, const char *what) {
    ++g_checks;
    if (!ok) {
        ++g_fails;
        std::printf("  FALLO: %s\n", what);
    }
}

static AbstractLoc L(AbstractLoc::Kind k, uint32_t id = 0) {
    return {k, id};
}

int main() {
    using K = AbstractLoc::Kind;

    // ---- may_alias: reticulo TOP/BOTTOM ----
    check(!may_alias(L(K::None), L(K::Unknown)), "bottom no aliasa nada");
    check(!may_alias(L(K::None), L(K::Heap, 1)), "bottom no aliasa heap");
    check(may_alias(L(K::Unknown), L(K::Stack)), "top aliasa stack");
    check(may_alias(L(K::Unknown), L(K::Heap, 7)), "top aliasa heap");
    check(!may_alias(L(K::Stack), L(K::Heap, 1)), "clases distintas disjuntas");
    check(may_alias(L(K::Heap, 3), L(K::Heap, 3)), "mismo heap id aliasa");
    check(!may_alias(L(K::Heap, 3), L(K::Heap, 4)),
          "heap ids distintos no aliasan");
    check(!may_alias(L(K::Heap, 0), L(K::Heap, 4)),
          "heap id 0 es sitio concreto (no aliasa 4)");
    check(may_alias(L(K::Heap, LOC_GENERIC), L(K::Heap, 4)),
          "heap generico aliasa cualquiera");
    check(may_alias(L(K::Global, 9), L(K::Global, 9)), "mismo global aliasa");

    // ---- LocSet: union, absorbente, gen/kill ----
    {
        LocSet s;
        check(s.empty(), "locset vacio");
        s.add(L(K::None)); // bottom no aporta
        check(s.empty(), "add bottom no aporta");
        s.add(L(K::Heap, 1));
        s.add(L(K::Heap, 1)); // dup
        check(!s.empty() && !s.is_top && s.locs.size() == 1, "add dedup");
        s.add(L(K::Unknown)); // top absorbente
        check(s.is_top && s.locs.empty(), "unknown colapsa a top");
        check(s.may_alias_any(L(K::Stack)), "top aliasa cualquiera");
    }
    {
        LocSet a, b;
        a.add(L(K::Heap, 1));
        b.add(L(K::Heap, 2));
        a.unite(b);
        check(a.locs.size() == 2, "union de dos heaps distintos");
        // gen/kill: quitar solo el loc concreto exacto.
        LocSet reads, writes;
        reads.add(L(K::Heap, 1));
        reads.add(L(K::Heap, 2));
        writes.add(L(K::Heap, 1));
        reads.subtract_concrete(writes);
        check(reads.locs.size() == 1 && reads.locs[0] == L(K::Heap, 2),
              "gen/kill quita el loc escrito exacto");
        // si writes es top, no mata nada (sound).
        LocSet reads2, wtop;
        reads2.add(L(K::Heap, 1));
        wtop.add(L(K::Unknown));
        reads2.subtract_concrete(wtop);
        check(reads2.locs.size() == 1, "writes top no mata lecturas (sound)");
    }

    // ---- seq: gen/kill de memoria + control terminador ----
    {
        SemanticEffects a; // escribe heap(1)
        a.mem.writes.add(L(K::Heap, 1));
        SemanticEffects b; // lee heap(1) (interno) y heap(2) (externo)
        b.mem.reads.add(L(K::Heap, 1));
        b.mem.reads.add(L(K::Heap, 2));
        SemanticEffects r = seq(a, b);
        check(r.mem.reads.locs.size() == 1 &&
                  r.mem.reads.locs[0] == L(K::Heap, 2),
              "seq mem: la lectura interna (heap1) se mata, la externa (heap2) "
              "queda");
        check(r.mem.writes.locs.size() == 1, "seq mem: writes se acumulan");
    }
    {
        // control: si 'a' termina (Return), el control del par es el de 'a'.
        SemanticEffects a, b;
        a.control.kind = ControlKind::Return;
        b.control.kind = ControlKind::Call;
        check(seq(a, b).control.kind == ControlKind::Return,
              "seq control: 'a' Return domina");
        SemanticEffects a2, b2;
        a2.control.kind = ControlKind::FallThrough;
        b2.control.kind = ControlKind::Call;
        check(seq(a2, b2).control.kind == ControlKind::Call,
              "seq control: 'a' FallThrough -> control de 'b'");
    }
    {
        // neutro: seq(none, x) == seq(x, none) en las may-props.
        SemanticEffects x;
        x.may_throw = true;
        x.mem.writes.add(L(K::Global, 5));
        SemanticEffects n = SemanticEffects::none();
        check(seq(n, x).may_throw && seq(x, n).may_throw,
              "neutro preserva may_throw");
    }

    // ---- join: conmutativo + union may-effects ----
    {
        SemanticEffects a, b;
        a.may_allocate = true;
        a.mem.reads.add(L(K::Stack));
        b.may_io = true;
        b.mem.reads.add(L(K::Global, 2));
        SemanticEffects ab = join(a, b);
        SemanticEffects ba = join(b, a);
        check(ab == ba, "join conmutativo");
        check(ab.may_allocate && ab.may_io, "join une may-effects");
        check(ab.mem.reads.locs.size() == 2, "join une read-sets");
    }
    {
        // idempotencia: join(x,x) == x.
        SemanticEffects x;
        x.may_block = true;
        x.tags.add(CapabilityTag::PortIO);
        check(join(x, x) == x, "join idempotente");
    }

    // ---- MachineEffects: gen/kill de registros + stack peak ----
    {
        MachineEffects a; // escribe reg0
        a.regs_written = 0x1;
        a.stack_net = 8;
        a.stack_peak = 8;
        MachineEffects b;  // lee reg0 (interno) y reg1 (externo)
        b.regs_read = 0x3; // reg0|reg1
        b.stack_net = 16;
        b.stack_peak = 16;
        MachineEffects r = seq(a, b);
        check(r.regs_read == 0x2, "seq regs: reg0 interno se mata, reg1 queda");
        check(r.regs_written == 0x1, "seq regs: writes se acumulan");
        check(r.stack_net == 24, "seq stack net = 8+16");
        check(r.stack_peak == 24, "seq stack peak = max(8, 8+16)");
    }

    // ---- CapabilityClass ----
    check(class_of(CapabilityTag::PortIO) == CapabilityClass::Observable,
          "PortIO es Observable");
    check(class_of(CapabilityTag::CPUID) == CapabilityClass::Machine,
          "CPUID es Machine");
    check(class_of(CapabilityTag::SecretDependent) == CapabilityClass::Security,
          "SecretDependent es Security");

    // ---- Contratos declarativos ----
    {
        // Funcion pura: sin efectos observables.
        FunctionSummary s;
        s.completeness = AnalysisCompleteness::Complete;
        auto cs = derive_contracts(s);
        bool pure = false, det = false, heapfree = false;
        for (const auto &c : cs) {
            if (std::string(c.name) == "pure") pure = c.holds;
            if (std::string(c.name) == "deterministic") det = c.holds;
            if (std::string(c.name) == "heap_free") heapfree = c.holds;
        }
        check(pure, "funcion vacia es pure");
        check(det, "funcion vacia es deterministic");
        check(heapfree, "funcion vacia es heap_free");
    }
    {
        /* mem_free es MAS fuerte que pure: pure admite lecturas, mem_free no.
         * La distincion importa porque es lo que decide si una LLAMADA sigue
         * siendo una barrera de memoria para lo que hay a su alrededor. */
        FunctionSummary s;
        s.completeness = AnalysisCompleteness::Complete;
        s.semantic.closure.mem.reads.add(L(K::Global, 1)); // solo LEE
        auto cs = derive_contracts(s);
        bool pure = false, memfree = true, readonly = false;
        for (const auto &c : cs) {
            if (std::string(c.name) == "pure") pure = c.holds;
            if (std::string(c.name) == "mem_free") memfree = c.holds;
            if (std::string(c.name) == "readonly") readonly = c.holds;
        }
        check(pure, "una funcion que solo LEE sigue siendo pure");
        check(readonly, "una funcion que solo LEE es readonly");
        check(!memfree, "pero NO es mem_free: toca memoria");
    }
    {
        // Sin tocar memoria de ninguna forma: mem_free.
        FunctionSummary s;
        s.completeness = AnalysisCompleteness::Complete;
        bool memfree = false;
        for (const auto &c : derive_contracts(s))
            if (std::string(c.name) == "mem_free") memfree = c.holds;
        check(memfree, "funcion vacia es mem_free");
    }
    {
        // Analisis INCOMPLETO: no se puede afirmar que no toca memoria.
        FunctionSummary s;
        s.completeness = AnalysisCompleteness::Conservative;
        bool memfree = true;
        for (const auto &c : derive_contracts(s))
            if (std::string(c.name) == "mem_free") memfree = c.holds;
        check(!memfree, "analisis incompleto: mem_free NO se afirma");
    }
    {
        // Funcion que escribe memoria y aloca: NO pura, NO heap_free.
        FunctionSummary s;
        s.completeness = AnalysisCompleteness::Complete;
        s.semantic.closure.mem.writes.add(L(K::Global, 1));
        s.semantic.closure.may_allocate = true;
        auto cs = derive_contracts(s);
        bool pure = true, heapfree = true, readonly = true;
        for (const auto &c : cs) {
            if (std::string(c.name) == "pure") pure = c.holds;
            if (std::string(c.name) == "heap_free") heapfree = c.holds;
            if (std::string(c.name) == "readonly") readonly = c.holds;
        }
        check(!pure, "funcion que escribe/aloca NO es pure");
        check(!heapfree, "funcion que aloca NO es heap_free");
        check(!readonly, "funcion que escribe NO es readonly");
    }
    {
        // Unknown -> ningun contrato positivo (conservador).
        FunctionSummary s;
        s.completeness = AnalysisCompleteness::Unknown;
        auto cs = derive_contracts(s);
        bool any = false;
        for (const auto &c : cs)
            if (std::string(c.name) == "pure" && c.holds) any = true;
        check(!any, "completeness Unknown -> no pure");
    }

    // =====================================================================
    //   motor IR -> SemanticEffects (construimos IrFunctions a mano).
    // =====================================================================
    auto add_instr = [](ir::IrFunction &fn, uint32_t blk, ir::IrOp op,
                        ir::IrValueId dst,
                        std::vector<ir::IrValueId> ops) -> ir::IrInstr & {
        ir::IrInstr in{};
        in.op = op;
        in.dst = dst;
        in.operands = std::move(ops);
        fn.append(blk, std::move(in));
        return fn.blocks[blk].instrs.back();
    };

    {
        // Funcion PURA: const + add + ret.
        ir::IrFunction fn;
        fn.name = "puro";
        uint32_t b0 = fn.new_block("entry");
        ir::IrValueId a = fn.new_value(ir::IrType::I64);
        ir::IrValueId c = fn.new_value(ir::IrType::I64);
        add_instr(fn, b0, ir::IrOp::CONST, a, {});
        add_instr(fn, b0, ir::IrOp::ADD, c, {a, a});
        add_instr(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {c});
        EffectAnalysisResult r = function_local_effects(fn);
        check(!r.effects.mem.writes_memory() && !r.effects.may_throw &&
                  !r.effects.may_allocate &&
                  r.completeness == AnalysisCompleteness::Complete,
              "IR: const+add+ret es puro");
        check(r.effects.control.kind == ControlKind::Return,
              "IR: control Return");
    }
    {
        // STORE a un ALLOCA -> escribe Stack.
        ir::IrFunction fn;
        fn.name = "st";
        uint32_t b0 = fn.new_block("entry");
        ir::IrValueId slot = fn.new_value(ir::IrType::I64);
        ir::IrValueId v = fn.new_value(ir::IrType::I64);
        add_instr(fn, b0, ir::IrOp::ALLOCA, slot, {});
        add_instr(fn, b0, ir::IrOp::CONST, v, {});
        add_instr(fn, b0, ir::IrOp::STORE, ir::IR_NO_VALUE, {v, slot});
        analysis::IrFacts defs = analysis::build_ir_facts(fn);
        analysis::PointsTo defs_pt = analysis::compute_points_to(fn, defs);
        // efecto de la STORE aislada.
        SemanticEffects st =
            effects_of_instr(fn, defs, defs_pt, fn.blocks[b0].instrs.back())
                .effects;
        check(st.mem.writes.locs.size() == 1 &&
                  st.mem.writes.locs[0].kind == AbstractLoc::Kind::Stack,
              "IR: STORE a ALLOCA escribe Stack");
        // La funcion NO escribe memoria OBSERVABLE fuera del marco: el Stack es
        // local, pero el modelo lo reporta como write de Stack (correcto: el
        // filtrado 'stack local no escapa' es tarea de un contrato/opt
        // superior).
    }
    {
        // GC_ALLOC -> may_allocate; THROW -> may_throw; CALLN -> conservative.
        ir::IrFunction fn;
        fn.name = "alloc";
        uint32_t b0 = fn.new_block("entry");
        ir::IrValueId o = fn.new_value(ir::IrType::I64);
        add_instr(fn, b0, ir::IrOp::GC_ALLOC, o, {});
        EffectAnalysisResult r = function_local_effects(fn);
        check(r.effects.may_allocate, "IR: GC_ALLOC -> may_allocate");

        ir::IrFunction ft;
        ft.name = "thr";
        uint32_t bt = ft.new_block("entry");
        add_instr(ft, bt, ir::IrOp::THROW, ir::IR_NO_VALUE, {});
        check(function_local_effects(ft).effects.may_throw,
              "IR: THROW -> may_throw");

        ir::IrFunction fc;
        fc.name = "ffi";
        uint32_t bc = fc.new_block("entry");
        add_instr(fc, bc, ir::IrOp::CALLN, ir::IR_NO_VALUE, {});
        EffectAnalysisResult rc = function_local_effects(fc);
        check(rc.effects.may_io &&
                  rc.completeness == AnalysisCompleteness::Conservative,
              "IR: CALLN -> may_io + Conservative");
    }
    {
        /* `panic` no baja igual en cada backend, y el efecto lo refleja: en la
         * maquina virtual lanza un FatalError capturable con `try`; en nativo
         * llama al hook de panico y no vuelve.  Un solo `may_throw` no podia
         * decir las dos cosas -- en nativo daba a entender que un `catch` de
         * mas arriba lo recogeria --, de ahi que abortar sea senal aparte. */
        ir::IrFunction fp;
        fp.name = "revienta";
        uint32_t bp = fp.new_block("entry");
        add_instr(fp, bp, ir::IrOp::PANIC, ir::IR_NO_VALUE, {});

        EffectEnv vm;
        const SemanticEffects e_vm =
            function_local_effects(fp, nullptr, vm).effects;
        check(e_vm.may_throw && e_vm.may_panic &&
                  e_vm.control.kind == ControlKind::Throw,
              "IR: panic en la VM -> lanza (capturable) y aborta");

        EffectEnv nat;
        nat.backend = Backend::Aot;
        const SemanticEffects e_nat =
            function_local_effects(fp, nullptr, nat).effects;
        check(!e_nat.may_throw && e_nat.may_panic &&
                  e_nat.control.kind == ControlKind::NoReturn,
              "IR: panic en nativo -> aborta sin lanzar y no vuelve");
    }
    {
        /* Liberar invalida LO QUE LIBERA, no toda la memoria.  Antes un `free`
         * se anotaba como escritura en "cualquier sitio", asi que hacia de
         * barrera para todo lo que hubiera alrededor. */
        ir::IrFunction ff;
        ff.name = "libera";
        uint32_t bf = ff.new_block("entry");
        ir::IrValueId h = ff.new_value(ir::IrType::PTR);
        add_instr(ff, bf, ir::IrOp::RAW_ALLOC, h, {});
        add_instr(ff, bf, ir::IrOp::RAW_FREE, ir::IR_NO_VALUE, {h});
        const SemanticEffects e = function_local_effects(ff).effects;
        bool preciso = !e.mem.writes.is_top;
        for (const AbstractLoc &l : e.mem.writes.locs)
            if (l.kind == AbstractLoc::Kind::Unknown) preciso = false;
        check(preciso && e.mem.writes_memory(),
              "IR: free invalida su bloque, no toda la memoria");
    }
    {
        // Dos ALLOCAs distintos NO aliasan (sites distintos).
        ir::IrFunction fn;
        fn.name = "twoslots";
        uint32_t b0 = fn.new_block("entry");
        ir::IrValueId s1 = fn.new_value(ir::IrType::I64);
        ir::IrValueId s2 = fn.new_value(ir::IrType::I64);
        add_instr(fn, b0, ir::IrOp::ALLOCA, s1, {});
        add_instr(fn, b0, ir::IrOp::ALLOCA, s2, {});
        analysis::IrFacts defs = analysis::build_ir_facts(fn);
        AbstractLoc l1 = classify_ptr(fn, defs, s1);
        AbstractLoc l2 = classify_ptr(fn, defs, s2);
        check(l1.kind == AbstractLoc::Kind::Stack &&
                  l2.kind == AbstractLoc::Kind::Stack && !may_alias(l1, l2),
              "IR: dos ALLOCA distintos no aliasan");
    }
    {
        // Parametro puntero -> ArgDerived.
        ir::IrFunction fn;
        fn.name = "argptr";
        ir::IrValueId p = fn.new_value(ir::IrType::I64);
        fn.params.push_back(p);
        uint32_t b0 = fn.new_block("entry");
        ir::IrValueId v = fn.new_value(ir::IrType::I64);
        add_instr(fn, b0, ir::IrOp::LOAD, v, {p});
        analysis::IrFacts defs = analysis::build_ir_facts(fn);
        AbstractLoc lp = classify_ptr(fn, defs, p);
        check(lp.kind == AbstractLoc::Kind::ArgDerived && lp.id == 0,
              "IR: parametro puntero -> ArgDerived(0)");
    }

    // =====================================================================
    //   punto-fijo del callgraph (cierre interprocedural) + contratos.
    // =====================================================================
    {
        // callee aloca; caller llama a callee -> el cierre de caller
        // may_allocate.
        ir::IrModule mod;
        {
            ir::IrFunction callee;
            callee.name = "callee";
            uint32_t b = callee.new_block("entry");
            ir::IrValueId o = callee.new_value(ir::IrType::I64);
            add_instr(callee, b, ir::IrOp::GC_ALLOC, o, {});
            add_instr(callee, b, ir::IrOp::RET, ir::IR_NO_VALUE, {});
            mod.functions.push_back(std::move(callee));
        }
        {
            ir::IrFunction caller;
            caller.name = "caller";
            uint32_t b = caller.new_block("entry");
            ir::IrInstr call{};
            call.op = ir::IrOp::CALL;
            call.func_name = "callee";
            call.dst = ir::IR_NO_VALUE;
            caller.append(b, std::move(call));
            add_instr(caller, b, ir::IrOp::RET, ir::IR_NO_VALUE, {});
            mod.functions.push_back(std::move(caller));
        }
        EffectAnalysis ea;
        const ModuleSummary &ms = ea.module_summary(mod);
        const FunctionSummary &caller = ms.fns.at("caller");
        const FunctionSummary &callee = ms.fns.at("callee");
        check(callee.semantic.local.may_allocate,
              "fixpoint: callee local aloca");
        check(!caller.semantic.local.may_allocate,
              "fixpoint: caller local NO aloca");
        check(caller.semantic.closure.may_allocate,
              "fixpoint: caller closure aloca (via callee)");
        // Contratos derivados del cierre.
        auto cc = derive_contracts(caller);
        bool heapfree = true, leaf = false;
        for (const auto &c : cc) {
            if (std::string(c.name) == "heap_free") heapfree = c.holds;
            if (std::string(c.name) == "leaf") leaf = c.holds;
        }
        check(!heapfree, "fixpoint: caller NO es heap_free (aloca transitivo)");
        check(!leaf, "fixpoint: caller NO es leaf (llama)");
        // callee es leaf (no llama).
        bool callee_leaf = false;
        for (const auto &c : derive_contracts(callee))
            if (std::string(c.name) == "leaf") callee_leaf = c.holds;
        check(callee_leaf, "fixpoint: callee es leaf");
    }
    {
        // Cadena A->B->C con C que lanza -> A closure may_throw.
        ir::IrModule mod;
        const char *names[3] = {"A", "B", "C"};
        for (int i = 0; i < 3; ++i) {
            ir::IrFunction f;
            f.name = names[i];
            uint32_t b = f.new_block("entry");
            if (i < 2) {
                ir::IrInstr call{};
                call.op = ir::IrOp::CALL;
                call.func_name = names[i + 1];
                call.dst = ir::IR_NO_VALUE;
                f.append(b, std::move(call));
            } else {
                add_instr(f, b, ir::IrOp::THROW, ir::IR_NO_VALUE, {});
            }
            add_instr(f, b, ir::IrOp::RET, ir::IR_NO_VALUE, {});
            mod.functions.push_back(std::move(f));
        }
        EffectAnalysis ea;
        const ModuleSummary &ms = ea.module_summary(mod);
        check(ms.fns.at("A").semantic.closure.may_throw,
              "fixpoint transitivo: A->B->C(throw) -> A closure may_throw");
        bool a_nothrow = true;
        for (const auto &c : derive_contracts(ms.fns.at("A")))
            if (std::string(c.name) == "nothrow") a_nothrow = c.holds;
        check(!a_nothrow, "fixpoint: A NO es nothrow (throw transitivo)");
    }

    {
        // Observabilidad de lagunas: un CALLN registra una laguna FUNDAMENTAL
        // (FFI), no una de cobertura.
        ir::IrModule mod;
        ir::IrFunction f;
        f.name = "ffi_caller";
        uint32_t b = f.new_block("entry");
        add_instr(f, b, ir::IrOp::CALLN, ir::IR_NO_VALUE, {});
        add_instr(f, b, ir::IrOp::RET, ir::IR_NO_VALUE, {});
        mod.functions.push_back(std::move(f));
        EffectAnalysis ea;
        ea.module_summary(mod);
        const EffectGaps &g = ea.gaps();
        check(!g.empty(), "gaps: CALLN genera una laguna");
        check(g.by_reason.count(UnknownReason::UnknownFFI) == 1,
              "gaps: la laguna del CALLN es UnknownFFI (fundamental)");
        check(g.unmodeled_ops.empty(),
              "gaps: FFI NO es laguna de cobertura (no unmodeled_op)");
        check(!reason_is_gap(UnknownReason::UnknownFFI) &&
                  reason_is_gap(UnknownReason::UnmodeledOp),
              "gaps: FFI es fundamental, UnmodeledOp es cobertura");
    }

    {
        // Interprocedural A NIVEL DE MoDULOS (program_summary): modulo A define
        // 'allocA' (aloca); modulo B define 'callB' que llama a 'allocA'.  Con
        // module_summary(B) solo, 'allocA' es EXTERNA -> callB closure = top
        // (may_throw/io/... conservador).  Con program_summary({A,B}) el callee
        // cruza el modulo y se resuelve -> callB closure aloca pero NO es top.
        ir::IrModule modA;
        {
            ir::IrFunction f;
            f.name = "allocA";
            uint32_t b = f.new_block("entry");
            ir::IrValueId o = f.new_value(ir::IrType::I64);
            add_instr(f, b, ir::IrOp::GC_ALLOC, o, {});
            add_instr(f, b, ir::IrOp::RET, ir::IR_NO_VALUE, {});
            modA.functions.push_back(std::move(f));
        }
        ir::IrModule modB;
        {
            ir::IrFunction f;
            f.name = "callB";
            uint32_t b = f.new_block("entry");
            ir::IrInstr call{};
            call.op = ir::IrOp::CALL;
            call.func_name = "allocA";
            call.dst = ir::IR_NO_VALUE;
            f.append(b, std::move(call));
            add_instr(f, b, ir::IrOp::RET, ir::IR_NO_VALUE, {});
            modB.functions.push_back(std::move(f));
        }
        // Solo B: allocA es externa -> callB closure conservador (top: may_io).
        {
            EffectAnalysis ea;
            const ModuleSummary &ms = ea.module_summary(modB);
            check(ms.fns.at("callB").semantic.closure.may_io,
                  "cross-mod: solo B, allocA externa -> callB closure top "
                  "(may_io)");
        }
        // A+B: el callgraph cruza el modulo -> allocA resuelto.
        {
            EffectAnalysis ea;
            const ModuleSummary &ps = ea.program_summary({&modA, &modB});
            const FunctionSummary &cb = ps.fns.at("callB");
            check(ps.fns.count("allocA") == 1,
                  "cross-mod: program_summary ve allocA de otro modulo");
            check(cb.semantic.closure.may_allocate,
                  "cross-mod: callB closure aloca (via allocA de otro modulo)");
            check(!cb.semantic.closure.may_io,
                  "cross-mod: callB closure NO es top (allocA resuelto, no "
                  "externa)");
        }
    }

    // =====================================================================
    // IRFacts: hechos objetivos + integracion con el AnalysisManager.
    // =====================================================================
    {
        ir::IrFunction fn;
        fn.name = "facts_fn";
        ir::IrValueId p = fn.new_value(ir::IrType::I64);
        fn.params.push_back(p);
        uint32_t b0 = fn.new_block("entry");
        ir::IrValueId v = fn.new_value(ir::IrType::I64);
        add_instr(fn, b0, ir::IrOp::LOAD, v, {p});
        ir::IrInstr call{};
        call.op = ir::IrOp::CALL;
        call.func_name = "otra";
        call.dst = ir::IR_NO_VALUE;
        fn.append(b0, std::move(call));
        add_instr(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {v});

        analysis::IrFacts f = analysis::build_ir_facts(fn);
        check(f.param_index(p) == 0, "IRFacts: param 0");
        check(f.def(v) != nullptr && f.def(v)->op == ir::IrOp::LOAD,
              "IRFacts: def-use del LOAD");
        check(f.static_callees.size() == 1 && f.static_callees[0] == "otra",
              "IRFacts: call-site estatico");
        check(!f.has_dynamic_call, "IRFacts: sin llamada dinamica");
        check(f.block_count == 1, "IRFacts: 1 bloque");

        // Integracion con el manager: IRFacts como analisis registrado.
        analysis::AnalysisManager am;
        int builds = 0;
        auto factory = [&]() {
            ++builds;
            return analysis::build_ir_facts(fn);
        };
        /* La unidad se nombra con el puntero internado, no con la cadena: es
         * lo que hace el optimizador de verdad. */
        const analysis::IrFacts &f1 =
            am.get_or_compute<analysis::IRFactsAnalysis, analysis::IrFacts>(
                fn.name_key(), factory);
        am.get_or_compute<analysis::IRFactsAnalysis, analysis::IrFacts>(
            fn.name_key(), factory);
        check(builds == 1 && f1.block_count == 1,
              "IRFacts: manager computa una vez (lazy + cache)");
        am.invalidate<analysis::IRFactsAnalysis>(fn.name_key());
        check(!am.cached<analysis::IRFactsAnalysis>(fn.name_key()),
              "IRFacts: invalidado del manager");
    }

    // =====================================================================
    // Perfiles de contratos: mismos hechos, distinta opinion.
    // =====================================================================
    {
        // Funcion sin escrituras/throw/alloc/io PERO no-determinista (lee
        // reloj).
        FunctionSummary s;
        s.completeness = AnalysisCompleteness::Complete;
        s.semantic.closure.determinism.add(DeterminismTag::ReadsClock);
        auto pure_of = [&](ContractProfile p) {
            for (const auto &c : derive_contracts(s, p))
                if (std::string(c.name) == "pure") return c.holds;
            return false;
        };
        check(pure_of(ContractProfile::Default),
              "perfil Default: no-determinista sigue siendo pure");
        check(!pure_of(ContractProfile::Strict),
              "perfil Strict: no-determinista NO es pure");
        check(pure_of(ContractProfile::Relaxed),
              "perfil Relaxed: no-determinista es pure");
    }

    std::printf("=== effects+facts+perfiles: %d checks, %d fallos ===\n",
                g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
