/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_loop_facts.cpp
 * @brief Test de compute_loop_facts: deteccion unificada de bucles (profundidad
 *        + header + in_loop + id) sobre CFGs sinteticos (sin loop, un loop,
 *        loops anidados).
 */

#include "analysis/asa/observed.h" // el hecho de bucle, para darselo al coste
#include "analysis/facts/ir_facts.h"
#include "analysis/facts/loop_facts.h"
#include "analyze/bigo.h" // el CONSUMIDOR: deja de contar por anidamiento
#include "analysis/facts/loop_iv.h"
#include "analysis/facts/loop_structure.h"
#include "analysis/facts/loop_trip_count.h"
#include "ir/ssa_ir.h"

#include <cstdio>

using namespace analysis;
using ir::IrBlock;
using ir::IrBlockId;
using ir::IrInstr;
using ir::IrOp;
using ir::IrType;

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

static IrInstr br(IrBlockId t) {
    IrInstr i;
    i.op = IrOp::BR;
    i.type = IrType::VOID;
    i.dst = ir::IR_NO_VALUE;
    i.target_block = t;
    return i;
}
static IrInstr brcond(IrBlockId tt, IrBlockId ff) {
    IrInstr i;
    i.op = IrOp::BR_COND;
    i.type = IrType::VOID;
    i.dst = ir::IR_NO_VALUE;
    i.operands = {0};
    i.target_block = tt;
    i.false_block = ff;
    return i;
}
static IrInstr ret() {
    IrInstr i;
    i.op = IrOp::RET;
    i.type = IrType::VOID;
    i.dst = ir::IR_NO_VALUE;
    return i;
}
static IrBlock block(IrBlockId id, const char *name, IrInstr term) {
    IrBlock b;
    b.id = id;
    b.name = name;
    b.instrs.push_back(term);
    return b;
}

/**
 * @brief Un bucle contado tal y como sale ANTES de optimizar.
 *
 * No es un CFG inventado para pasar el test: es exactamente la forma que deja
 * la construccion de SSA -- el limite materializado DENTRO de la cabecera
 * (`const`) y una COPIA del PHI (`mov`) que el `cmp` usa en su lugar --, y que
 * la propagacion de copias limpia mas tarde.
 *
 * Lo que se fija aqui es que el analisis mida el PROGRAMA y no al optimizador:
 * el mismo bucle no puede estar contado despues de optimizar y no estarlo
 * antes.  Los dos estorbos son puras copias, sin efectos laterales, y
 * rechazarlos hacia que el conocimiento solo existiera cuando ya era tarde --
 * el desenrollador reescribe el bucle, y para cuando alguien preguntaba ya no
 * habia bucle que contar.
 */
static void counted_loop_before_optimizing() {
    std::printf("\n[bucle contado ANTES de optimizar: con copias en la "
                "cabecera]\n");

    ir::IrFunction fn;
    fn.name = "counted";
    // %0 init(0)  %1 phi  %2 mov(%1)  %3 const(64)  %4 cmp  %5 add(%2,1)
    for (int i = 0; i < 7; ++i) fn.values.push_back({});

    auto val = [](IrOp op, ir::IrValueId dst, IrType t) {
        IrInstr in;
        in.op = op;
        in.dst = dst;
        in.type = t;
        return in;
    };

    IrBlock entry;
    entry.id = 0;
    entry.name = "entry";
    {
        IrInstr c = val(IrOp::CONST, 0, IrType::I64);
        c.imm = 0;
        entry.instrs.push_back(c);
    }
    entry.instrs.push_back(br(1));

    IrBlock header;
    header.id = 1;
    header.name = "header";
    {
        IrInstr phi = val(IrOp::PHI, 1, IrType::I64);
        phi.phi_args.push_back({/*value=*/0, /*block=*/0}); // init, preheader
        phi.phi_args.push_back({/*value=*/5, /*block=*/2}); // iv+1, latch
        header.instrs.push_back(phi);
        // La COPIA que deja la construccion de SSA.
        IrInstr mv = val(IrOp::MOV, 2, IrType::I64);
        mv.operands.push_back(1);
        header.instrs.push_back(mv);
        // El limite, materializado DENTRO de la cabecera.
        IrInstr lim = val(IrOp::CONST, 3, IrType::I64);
        lim.imm = 64;
        header.instrs.push_back(lim);
        IrInstr cmp = val(IrOp::CMP_LT, 4, IrType::BOOL);
        cmp.operands.push_back(2); // compara la COPIA, no el PHI
        cmp.operands.push_back(3);
        header.instrs.push_back(cmp);
        IrInstr t = brcond(2, 3);
        t.operands[0] = 4;
        header.instrs.push_back(t);
    }

    IrBlock body;
    body.id = 2;
    body.name = "body";
    {
        IrInstr one = val(IrOp::CONST, 6, IrType::I64);
        one.imm = 1;
        body.instrs.push_back(one);
        IrInstr add = val(IrOp::ADD, 5, IrType::I64);
        add.operands.push_back(2); // sobre la COPIA
        add.operands.push_back(6);
        body.instrs.push_back(add);
        body.instrs.push_back(br(1)); // back-edge
    }

    fn.blocks = {entry, header, body, block(3, "exit", ret())};

    const analysis::IrFacts facts = analysis::build_ir_facts(fn);
    const LoopFacts lf = compute_loop_facts(fn);
    CHECK(lf.loop_count == 1, "no se detecto el bucle");

    const analysis::LoopStructure st = analysis::detect_loop_structure(fn, lf, 0);
    CHECK(st.valid,
          "una copia y una constante en la cabecera NO descalifican el bucle");
    if (!st.valid) return;

    analysis::LoopIV iv;
    const bool hay = analysis::detect_loop_iv(fn, facts.def_block, st.header,
                                              st.preheader, st.latch, iv);
    CHECK(hay, "la variable de induccion se ve A TRAVES de la copia");
    if (!hay) return;
    CHECK(iv.phi == 1, "el IV es el PHI, no su copia");
    CHECK(iv.stride == 1, "paso 1");

    const analysis::LoopTripInfo tc =
        analysis::compute_trip_count(fn, facts.def_block, iv);
    CHECK(tc.known(), "y con eso el bucle esta CONTADO antes de optimizar");
    CHECK(tc.trip == 64, "sesenta y cuatro vueltas");
}

/**
 * @brief El COSTE deja de llamar lineal a un bucle de vueltas constantes.
 *
 * Un `for (i = 0; i < 64; i++)` da 64 vueltas den lo que den las entradas: es
 * un factor constante, no `n`.  El analisis lo deducia del ANIDAMIENTO a
 * secas, asi que lo declaraba O(n) -- y con el bucle de resto que deja el
 * desenrollador, O(n^2), llegando a acusar al optimizador de haber empeorado
 * el coste de una funcion cuyo coste es constante.
 *
 * No era un error, era una RESPUESTA equivocada, que es peor.  Ahora lo
 * pregunta: quien cuenta vueltas es el dominio de bucles, y el coste es un
 * consumidor mas.
 *
 * Se comprueba con y SIN hechos: sin ellos tiene que comportarse como antes,
 * o el cambio seria una regresion para todo el que llame sin ASA.
 */
static void constant_trip_loop_is_not_linear() {
    std::printf("\n[coste: un bucle de vueltas constantes NO es lineal]\n");

    ir::IrFunction fn;
    fn.name = "counted";
    for (int i = 0; i < 7; ++i) fn.values.push_back({});

    auto val = [](IrOp op, ir::IrValueId dst, IrType t) {
        IrInstr in;
        in.op = op;
        in.dst = dst;
        in.type = t;
        return in;
    };
    IrBlock entry;
    entry.id = 0;
    entry.name = "entry";
    {
        IrInstr c = val(IrOp::CONST, 0, IrType::I64);
        c.imm = 0;
        entry.instrs.push_back(c);
    }
    entry.instrs.push_back(br(1));

    IrBlock header;
    header.id = 1;
    header.name = "header";
    {
        IrInstr phi = val(IrOp::PHI, 1, IrType::I64);
        phi.phi_args.push_back({/*value=*/0, /*block=*/0});
        phi.phi_args.push_back({/*value=*/5, /*block=*/2});
        header.instrs.push_back(phi);
        IrInstr lim = val(IrOp::CONST, 3, IrType::I64);
        lim.imm = 64;
        header.instrs.push_back(lim);
        IrInstr cmp = val(IrOp::CMP_LT, 4, IrType::BOOL);
        cmp.operands.push_back(1);
        cmp.operands.push_back(3);
        header.instrs.push_back(cmp);
        IrInstr t = brcond(2, 3);
        t.operands[0] = 4;
        header.instrs.push_back(t);
    }
    IrBlock body;
    body.id = 2;
    body.name = "body";
    {
        IrInstr one = val(IrOp::CONST, 6, IrType::I64);
        one.imm = 1;
        body.instrs.push_back(one);
        IrInstr add = val(IrOp::ADD, 5, IrType::I64);
        add.operands.push_back(1);
        add.operands.push_back(6);
        body.instrs.push_back(add);
        body.instrs.push_back(br(1));
    }
    fn.blocks = {entry, header, body, block(3, "exit", ret())};
    /* El coste recorre `succs`, no los terminadores: sin esto no ve el
     * back-edge y no hay bucle que contar -- el test pasaria sin probar
     * nada. */
    fn.blocks[0].succs = {1};
    fn.blocks[1].succs = {2, 3};
    fn.blocks[2].succs = {1};
    fn.blocks[1].preds = {0, 2};
    fn.blocks[2].preds = {1};
    fn.blocks[3].preds = {1};

    /* SIN hechos: el anidamiento manda, como siempre.  Se compara con el otro
     * caso en vez de fijar un numero: lo que se prueba es que el hecho CAMBIA
     * la respuesta, no cuanto vale la cuenta estructural -- eso es cosa del
     * detector de bucles, y clavarlo aqui ataria este test a el. */
    const analyze::CostResult sin_hechos = analyze::analyze_function(fn);
    CHECK(sin_hechos.max_loop_depth >= 1,
          "sin hechos, el bucle cuenta como profundidad");

    /* CON el hecho de que da 64 vueltas, demostradas.  Se sella en el mismo
     * momento por el que se pregunta: un hecho de bucle nombra su cabecera por
     * ID DE BLOQUE, y preguntarlo desde otro momento seria leer otro bloque. */
    analysis::asa::FactStore store;
    analysis::LoopTripInfo trip;
    trip.trip = 64;
    analysis::asa::Fact f;
    CHECK(analysis::asa::loop_trip_fact(store, fn, /*header=*/1, trip,
                                        analysis::asa::kStagePreOpt,
                                        analysis::asa::Source::Static, f),
          "hay hecho que publicar");
    store.add(std::move(f));

    const analyze::CostResult con_hechos = analyze::analyze_function(
        fn, &store, analysis::asa::kStagePreOpt);
    CHECK(con_hechos.max_loop_depth == 0,
          "con las vueltas demostradas constantes, NO cuenta como profundidad");

    /* Y preguntando por OTRO momento no se ve: el hecho habla de los ids de su
     * codigo, no de los de este.  Que no case es lo correcto -- lo peligroso
     * seria que casara. */
    const analyze::CostResult otro_momento = analyze::analyze_function(
        fn, &store, analysis::asa::kStagePostOpt);
    CHECK(otro_momento.max_loop_depth == sin_hechos.max_loop_depth,
          "un hecho de otro momento no se aplica a este codigo");
}

/**
 * @brief Un ACUMULADOR en el bucle no esconde la variable de induccion.
 *
 * `for (i = 0; i < 64; i++) { t = t + 1; }` tiene DOS phis que avanzan igual:
 * el contador y el acumulador.  El detector probaba el primero, veia que la
 * guarda no lo compara, y se RENDIA -- devolvia "no se encontro una variable
 * de induccion" sobre un `for` de manual --.
 *
 * No daba error: hacia que el analisis de coste declarara O(?) una funcion que
 * es O(n), y que el desenrollador dejara pasar bucles perfectamente contados.
 * Y un acumulador es lo mas corriente que hay en un bucle.
 */
static void an_accumulator_does_not_hide_the_iv() {
    std::printf("\n[un acumulador no esconde la variable de induccion]\n");

    ir::IrFunction fn;
    fn.name = "with_acc";
    for (int i = 0; i < 10; ++i) fn.values.push_back({});

    auto val = [](IrOp op, ir::IrValueId dst, IrType t) {
        IrInstr in;
        in.op = op;
        in.dst = dst;
        in.type = t;
        return in;
    };
    IrBlock entry;
    entry.id = 0;
    entry.name = "entry";
    {
        IrInstr c0 = val(IrOp::CONST, 0, IrType::I64); // i = 0
        c0.imm = 0;
        entry.instrs.push_back(c0);
        IrInstr c1 = val(IrOp::CONST, 7, IrType::I64); // t = 0
        c1.imm = 0;
        entry.instrs.push_back(c1);
    }
    entry.instrs.push_back(br(1));

    IrBlock header;
    header.id = 1;
    header.name = "header";
    {
        /* El ACUMULADOR va PRIMERO, que es lo que destapaba el fallo: se
         * probaba antes que el contador. */
        IrInstr acc = val(IrOp::PHI, 8, IrType::I64);
        acc.phi_args.push_back({/*value=*/7, /*block=*/0});
        acc.phi_args.push_back({/*value=*/9, /*block=*/2});
        header.instrs.push_back(acc);
        IrInstr phi = val(IrOp::PHI, 1, IrType::I64);
        phi.phi_args.push_back({/*value=*/0, /*block=*/0});
        phi.phi_args.push_back({/*value=*/5, /*block=*/2});
        header.instrs.push_back(phi);
        IrInstr lim = val(IrOp::CONST, 3, IrType::I64);
        lim.imm = 64;
        header.instrs.push_back(lim);
        IrInstr cmp = val(IrOp::CMP_LT, 4, IrType::BOOL);
        cmp.operands.push_back(1); // compara el CONTADOR, no el acumulador
        cmp.operands.push_back(3);
        header.instrs.push_back(cmp);
        IrInstr t = brcond(2, 3);
        t.operands[0] = 4;
        header.instrs.push_back(t);
    }
    IrBlock body;
    body.id = 2;
    body.name = "body";
    {
        IrInstr one = val(IrOp::CONST, 6, IrType::I64);
        one.imm = 1;
        body.instrs.push_back(one);
        IrInstr inc = val(IrOp::ADD, 5, IrType::I64); // i + 1
        inc.operands.push_back(1);
        inc.operands.push_back(6);
        body.instrs.push_back(inc);
        IrInstr acc_add = val(IrOp::ADD, 9, IrType::I64); // t + 1
        acc_add.operands.push_back(8);
        acc_add.operands.push_back(6);
        body.instrs.push_back(acc_add);
        body.instrs.push_back(br(1));
    }
    fn.blocks = {entry, header, body, block(3, "exit", ret())};

    const analysis::IrFacts facts = analysis::build_ir_facts(fn);
    const LoopFacts lf = compute_loop_facts(fn);
    const analysis::LoopStructure st = analysis::detect_loop_structure(fn, lf, 0);
    CHECK(st.valid, "la forma se reconoce con dos phis");
    if (!st.valid) return;

    analysis::LoopIV iv;
    const bool hay = analysis::detect_loop_iv(fn, facts.def_block, st.header,
                                              st.preheader, st.latch, iv);
    CHECK(hay, "y la induccion se encuentra aunque el acumulador vaya primero");
    if (!hay) return;
    CHECK(iv.phi == 1, "el IV es el CONTADOR, no el acumulador");

    const analysis::LoopTripInfo tc =
        analysis::compute_trip_count(fn, facts.def_block, iv);
    CHECK(tc.known() && tc.trip == 64, "y salen las 64 vueltas");
}

int main() {
    std::printf("=== test_loop_facts (Fase 0.25: LoopFacts) ===\n");

    // --- CFG sin bucles: entry -> exit ---
    std::printf("\n[sin bucles]\n");
    {
        ir::IrFunction fn;
        fn.name = "noloop";
        fn.blocks.push_back(block(0, "entry", br(1)));
        fn.blocks.push_back(block(1, "exit", ret()));
        LoopFacts f = compute_loop_facts(fn);
        CHECK(f.loop_count == 0, "loop_count != 0");
        CHECK(!f.inside(0) && !f.inside(1),
              "bloques marcados in_loop sin bucle");
        CHECK(f.depth_of(0) == 0 && f.depth_of(1) == 0, "profundidad != 0");
    }

    // --- Un bucle: entry -> header <-> body, header -> exit ---
    std::printf("\n[un bucle]\n");
    {
        ir::IrFunction fn;
        fn.name = "oneloop";
        fn.blocks.push_back(block(0, "entry", br(1)));
        fn.blocks.push_back(block(1, "header", brcond(2, 3)));
        fn.blocks.push_back(block(2, "body", br(1))); // back-edge 2->1
        fn.blocks.push_back(block(3, "exit", ret()));
        LoopFacts f = compute_loop_facts(fn);
        CHECK(f.loop_count == 1, "loop_count != 1");
        CHECK(f.header_of(1), "header no detectado");
        CHECK(f.depth_of(1) == 1 && f.depth_of(2) == 1, "cuerpo no depth 1");
        CHECK(f.inside(1) && f.inside(2), "header/body no in_loop");
        CHECK(f.depth_of(0) == 0 && f.depth_of(3) == 0,
              "entry/exit no depth 0");
        CHECK(!f.header_of(2), "body marcado header");
    }

    // --- Bucles anidados ---
    std::printf("\n[bucles anidados]\n");
    {
        // 0 entry -> 1 outer_h
        // 1 outer_h -> 2 inner_h | 5 exit
        // 2 inner_h -> 3 inner_b | 4 outer_latch
        // 3 inner_b -> 2 (back inner)
        // 4 outer_latch -> 1 (back outer)
        // 5 exit ret
        ir::IrFunction fn;
        fn.name = "nested";
        fn.blocks.push_back(block(0, "entry", br(1)));
        fn.blocks.push_back(block(1, "outer_h", brcond(2, 5)));
        fn.blocks.push_back(block(2, "inner_h", brcond(3, 4)));
        fn.blocks.push_back(block(3, "inner_b", br(2)));
        fn.blocks.push_back(block(4, "outer_latch", br(1)));
        fn.blocks.push_back(block(5, "exit", ret()));
        LoopFacts f = compute_loop_facts(fn);
        CHECK(f.loop_count == 2, "loop_count != 2");
        CHECK(f.depth_of(0) == 0, "entry no depth 0");
        CHECK(f.depth_of(1) == 1, "outer_h no depth 1");
        CHECK(f.depth_of(2) == 2, "inner_h no depth 2");
        CHECK(f.depth_of(3) == 2, "inner_b no depth 2");
        CHECK(f.depth_of(4) == 1, "outer_latch no depth 1");
        CHECK(f.depth_of(5) == 0, "exit no depth 0");
        CHECK(f.header_of(1) && f.header_of(2), "headers no detectados");
        // loop_id: el bloque mas interno apunta al bucle mas pequeno.
        CHECK(f.innermost(3) == f.innermost(2),
              "inner_b/inner_h distinto bucle interno");
        CHECK(f.innermost(3) != f.innermost(4),
              "inner y outer comparten id interno");
        // parent_loop: el bucle interno tiene como padre al externo; el externo
        // no.
        const uint32_t inner_id = f.innermost(3);
        const uint32_t outer_id = f.innermost(1);
        CHECK(f.parent_of(inner_id) == outer_id,
              "padre del bucle interno no es el externo");
        CHECK(f.parent_of(outer_id) == LoopFacts::NO_LOOP,
              "el bucle externo tiene padre");
        CHECK(f.header_block_of(inner_id) == 2 &&
                  f.header_block_of(outer_id) == 1,
              "header_block_of incorrecto");
    }

    counted_loop_before_optimizing();
    constant_trip_loop_is_not_linear();
    an_accumulator_does_not_hide_the_iv();

    std::printf("\n=== %d checks, %d fallos ===\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
