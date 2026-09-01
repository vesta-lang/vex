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
#include "analysis/facts/loop_iv_bounds.h"
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

/**
 * @brief Un bucle DENTRO de otro tambien se reconoce, y el de fuera se
 *        descuenta si sus vueltas estan acotadas.
 *
 * `for (i = 0; i < 32; i++) { for (j = 0; j < 16; j++) {} }` recorre 512
 * veces: es CONSTANTE.  Salia O(n), y por dos fallos encadenados que no se
 * veian por separado:
 *
 *   1. la membresia de un bucle se calculaba como "los bloques cuyo bucle MAS
 *      INTERNO es este", asi que el bloque que entra al de dentro parecia
 *      saltar fuera y el de fuera se rechazaba con "sale del cuerpo".  Ningun
 *      bucle externo podia ser reconocido JAMAS;
 *   2. el coste deducia el anidamiento por contencion de INDICES de bloque,
 *      que es una suposicion sobre como numera el frontend y deja de valer en
 *      cuanto el optimizador reordena.
 *
 * El test los separa: primero que la FORMA se reconozca (1), despues que el
 * coste descuente (2).
 */
static void an_outer_loop_is_recognized_too() {
    std::printf("\n[un bucle externo tambien se reconoce, y se descuenta]\n");

    /* Valores: 0=cte 0 (init i) | 1=phi i | 2=cte 32 | 3=cmp i<32 | 4=i+1
     * 5=cte 1 | 6=cte 0 (init j) | 7=phi j | 8=cte 16 | 9=cmp j<16 | 10=j+1 */
    ir::IrFunction fn;
    fn.name = "anidado";
    for (int i = 0; i < 11; ++i) fn.values.push_back({});

    auto val = [](IrOp op, ir::IrValueId dst, IrType t) {
        IrInstr in;
        in.op = op;
        in.dst = dst;
        in.type = t;
        return in;
    };
    auto cte = [&](ir::IrValueId dst, uint64_t v) {
        IrInstr c = val(IrOp::CONST, dst, IrType::I64);
        c.imm = v;
        return c;
    };

    IrBlock entry; // b0
    entry.id = 0;
    entry.name = "entry";
    entry.instrs.push_back(cte(0, 0));
    /* El arranque de `j` y el paso viven en el preheader del de fuera, que es
     * donde los deja el frontend. */
    entry.instrs.push_back(cte(6, 0));
    entry.instrs.push_back(cte(5, 1));
    entry.instrs.push_back(br(1));

    IrBlock outer; // b1: for (i = 0; i < 32; i++)
    outer.id = 1;
    outer.name = "outer";
    {
        IrInstr phi = val(IrOp::PHI, 1, IrType::I64);
        phi.phi_args.push_back({/*value=*/0, /*block=*/0});
        phi.phi_args.push_back({/*value=*/4, /*block=*/4});
        outer.instrs.push_back(phi);
        outer.instrs.push_back(cte(2, 32));
        IrInstr cmp = val(IrOp::CMP_LT, 3, IrType::BOOL);
        cmp.operands.push_back(1);
        cmp.operands.push_back(2);
        outer.instrs.push_back(cmp);
        IrInstr t = brcond(2, 5);
        t.operands[0] = 3;
        outer.instrs.push_back(t);
    }

    IrBlock inner; // b2: for (j = 0; j < 16; j++)
    inner.id = 2;
    inner.name = "inner";
    {
        IrInstr phi = val(IrOp::PHI, 7, IrType::I64);
        phi.phi_args.push_back({/*value=*/6, /*block=*/1});
        phi.phi_args.push_back({/*value=*/10, /*block=*/3});
        inner.instrs.push_back(phi);
        inner.instrs.push_back(cte(8, 16));
        IrInstr cmp = val(IrOp::CMP_LT, 9, IrType::BOOL);
        cmp.operands.push_back(7);
        cmp.operands.push_back(8);
        inner.instrs.push_back(cmp);
        IrInstr t = brcond(3, 4);
        t.operands[0] = 9;
        inner.instrs.push_back(t);
    }

    IrBlock inner_body; // b3: j++
    inner_body.id = 3;
    inner_body.name = "inner_body";
    {
        IrInstr add = val(IrOp::ADD, 10, IrType::I64);
        add.operands.push_back(7);
        add.operands.push_back(5);
        inner_body.instrs.push_back(add);
        inner_body.instrs.push_back(br(2));
    }

    IrBlock outer_latch; // b4: i++
    outer_latch.id = 4;
    outer_latch.name = "outer_latch";
    {
        IrInstr add = val(IrOp::ADD, 4, IrType::I64);
        add.operands.push_back(1);
        add.operands.push_back(5);
        outer_latch.instrs.push_back(add);
        outer_latch.instrs.push_back(br(1));
    }

    fn.blocks = {entry, outer, inner, inner_body, outer_latch,
                 block(5, "exit", ret())};
    fn.blocks[0].succs = {1};
    fn.blocks[1].succs = {2, 5};
    fn.blocks[2].succs = {3, 4};
    fn.blocks[3].succs = {2};
    fn.blocks[4].succs = {1};
    fn.blocks[1].preds = {0, 4};
    fn.blocks[2].preds = {1, 3};
    fn.blocks[3].preds = {2};
    fn.blocks[4].preds = {2};
    fn.blocks[5].preds = {1};

    const LoopFacts lf = compute_loop_facts(fn);
    CHECK(lf.loop_count == 2, "hay dos bucles");

    const uint32_t outer_id = lf.innermost(1);
    const uint32_t inner_id = lf.innermost(2);
    CHECK(lf.parent_of(inner_id) == outer_id,
          "el de dentro cuelga del de fuera");

    // (1) La FORMA del bucle EXTERNO se reconoce.
    const LoopStructure so = detect_loop_structure(fn, lf, outer_id);
    CHECK(so.valid, "el bucle externo tiene forma de bucle contado");
    CHECK(so.inner_loops == 1 && !so.flat(),
          "y se dice que lleva otro dentro: quien clone tiene que mirarlo");
    CHECK(so.contains(3),
          "un bloque del bucle de DENTRO esta dentro del de fuera");

    const LoopStructure si = detect_loop_structure(fn, lf, inner_id);
    CHECK(si.valid && si.flat(), "el de dentro sigue siendo plano");

    // Y sus vueltas se cuentan: 32 el de fuera, 16 el de dentro.
    const IrFacts hechos = build_ir_facts(fn);
    LoopIV ivo, ivi;
    CHECK(detect_loop_iv(fn, hechos.def_block, so.header, so.preheader,
                         so.latch, ivo),
          "el externo tiene variable de induccion");
    CHECK(compute_trip_count(fn, hechos.def_block, ivo).trip == 32,
          "y da 32 vueltas");
    CHECK(detect_loop_iv(fn, hechos.def_block, si.header, si.preheader,
                         si.latch, ivi),
          "el interno tambien");
    CHECK(compute_trip_count(fn, hechos.def_block, ivi).trip == 16, "y da 16");

    // Y sus variables quedan acotadas SIN preguntar a los rangos.
    const LoopIvBounds cotas = compute_loop_iv_bounds(fn, hechos, lf);
    CHECK(cotas.bounds.size() == 2, "las dos variables quedan acotadas");
    int64_t lo = 0, hi = 0;
    bool vista = false;
    for (const IvBound &c : cotas.bounds)
        if (c.value == ivo.phi) vista = c.range.vista_con_signo(lo, hi);
    CHECK(vista && lo == 0 && hi == 32,
          "la del externo va de 0 a 32 -- el 32 es el valor con el que SALE");

    // (2) El coste: con las vueltas demostradas, ninguno cuenta.
    const analyze::CostResult sin_hechos = analyze::analyze_function(fn);
    CHECK(sin_hechos.max_loop_depth == 2,
          "sin hechos, dos bucles anidados son profundidad dos");

    analysis::asa::FactStore store;
    const ir::IrBlockId cabeceras[2] = {so.header, si.header};
    const int64_t vueltas[2] = {32, 16};
    for (int k = 0; k < 2; ++k) {
        analysis::LoopTripInfo trip;
        trip.trip = vueltas[k];
        analysis::asa::Fact f;
        CHECK(analysis::asa::loop_trip_fact(store, fn, cabeceras[k], trip,
                                            analysis::asa::kStagePreOpt,
                                            analysis::asa::Source::Static, f),
              "hay hecho que publicar");
        store.add(std::move(f));
    }
    const analyze::CostResult con_hechos =
        analyze::analyze_function(fn, &store, analysis::asa::kStagePreOpt);
    CHECK(con_hechos.max_loop_depth == 0,
          "con las dos cuentas demostradas, el coste es constante");
}

/**
 * @brief Un bucle de vueltas fijas POR FUERA de uno variable no lo hace
 *        cuadratico.
 *
 * `for (i = 0; i < 64; i++) { for (j = 0; j < n; j++) {} }` recorre 64*n, que
 * es LINEAL.  El coste sumaba el anidamiento a secas y decia O(n^2): la clase
 * equivocada, que es peor que una duda.
 */
static void a_constant_outer_loop_does_not_square_the_cost() {
    std::printf("\n[un bucle fijo por fuera no eleva el grado]\n");

    /* Igual que el de arriba pero el limite de dentro es un PARAMETRO, asi que
     * ese bucle no se puede contar.  Valores: 0=cte 0 | 1=phi i | 2=cte 64 |
     * 3=cmp | 4=i+1 | 5=cte 1 | 6=cte 0 | 7=phi j | 8=PARAM n | 9=cmp |
     * 10=j+1 */
    ir::IrFunction fn;
    fn.name = "mixto";
    for (int i = 0; i < 11; ++i) fn.values.push_back({});
    fn.params.push_back(8);

    auto val = [](IrOp op, ir::IrValueId dst, IrType t) {
        IrInstr in;
        in.op = op;
        in.dst = dst;
        in.type = t;
        return in;
    };
    auto cte = [&](ir::IrValueId dst, uint64_t v) {
        IrInstr c = val(IrOp::CONST, dst, IrType::I64);
        c.imm = v;
        return c;
    };

    IrBlock entry;
    entry.id = 0;
    entry.name = "entry";
    entry.instrs.push_back(cte(0, 0));
    entry.instrs.push_back(cte(6, 0));
    entry.instrs.push_back(cte(5, 1));
    entry.instrs.push_back(br(1));

    IrBlock outer;
    outer.id = 1;
    outer.name = "outer";
    {
        IrInstr phi = val(IrOp::PHI, 1, IrType::I64);
        phi.phi_args.push_back({0, 0});
        phi.phi_args.push_back({4, 4});
        outer.instrs.push_back(phi);
        outer.instrs.push_back(cte(2, 64));
        IrInstr cmp = val(IrOp::CMP_LT, 3, IrType::BOOL);
        cmp.operands.push_back(1);
        cmp.operands.push_back(2);
        outer.instrs.push_back(cmp);
        IrInstr t = brcond(2, 5);
        t.operands[0] = 3;
        outer.instrs.push_back(t);
    }

    IrBlock inner;
    inner.id = 2;
    inner.name = "inner";
    {
        IrInstr phi = val(IrOp::PHI, 7, IrType::I64);
        phi.phi_args.push_back({6, 1});
        phi.phi_args.push_back({10, 3});
        inner.instrs.push_back(phi);
        IrInstr cmp = val(IrOp::CMP_LT, 9, IrType::BOOL);
        cmp.operands.push_back(7);
        cmp.operands.push_back(8); // el PARAMETRO: no se sabe cuanto vale
        inner.instrs.push_back(cmp);
        IrInstr t = brcond(3, 4);
        t.operands[0] = 9;
        inner.instrs.push_back(t);
    }

    IrBlock inner_body;
    inner_body.id = 3;
    inner_body.name = "inner_body";
    {
        IrInstr add = val(IrOp::ADD, 10, IrType::I64);
        add.operands.push_back(7);
        add.operands.push_back(5);
        inner_body.instrs.push_back(add);
        inner_body.instrs.push_back(br(2));
    }

    IrBlock outer_latch;
    outer_latch.id = 4;
    outer_latch.name = "outer_latch";
    {
        IrInstr add = val(IrOp::ADD, 4, IrType::I64);
        add.operands.push_back(1);
        add.operands.push_back(5);
        outer_latch.instrs.push_back(add);
        outer_latch.instrs.push_back(br(1));
    }

    fn.blocks = {entry, outer, inner, inner_body, outer_latch,
                 block(5, "exit", ret())};
    fn.blocks[0].succs = {1};
    fn.blocks[1].succs = {2, 5};
    fn.blocks[2].succs = {3, 4};
    fn.blocks[3].succs = {2};
    fn.blocks[4].succs = {1};
    fn.blocks[1].preds = {0, 4};
    fn.blocks[2].preds = {1, 3};
    fn.blocks[3].preds = {2};
    fn.blocks[4].preds = {2};
    fn.blocks[5].preds = {1};

    const LoopFacts lf = compute_loop_facts(fn);
    const analyze::CostResult sin_hechos = analyze::analyze_function(fn);
    CHECK(sin_hechos.max_loop_depth == 2, "sin hechos, el anidamiento manda");

    /* Solo el de FUERA esta contado.  El de dentro depende de `n` y sigue
     * aportando: la respuesta es lineal, ni constante ni cuadratica. */
    analysis::asa::FactStore store;
    analysis::LoopTripInfo trip;
    trip.trip = 64;
    analysis::asa::Fact f;
    CHECK(analysis::asa::loop_trip_fact(
              store, fn, (ir::IrBlockId)lf.header_block_of(lf.innermost(1)),
              trip, analysis::asa::kStagePreOpt, analysis::asa::Source::Static,
              f),
          "hay hecho que publicar");
    store.add(std::move(f));

    const analyze::CostResult con_hechos =
        analyze::analyze_function(fn, &store, analysis::asa::kStagePreOpt);
    CHECK(con_hechos.max_loop_depth == 1,
          "el de fuera no cuenta y el de dentro si: LINEAL, no cuadratico");
}

/**
 * @brief Un bucle que MULTIPLICA es logaritmico, no lineal.
 *
 * `for (i = 1; i < n; i = i * 2)` da del orden de `log n` vueltas.  El
 * descriptor de induccion solo modelaba `phi + S`, asi que este bucle no tenia
 * variable de induccion, contaba como uno cualquiera y el coste contestaba
 * O(n).  No es imprecision: es otra CLASE -- y anidado dentro de uno lineal,
 * la diferencia entre O(n log n) y O(n^2), que es la que separa un algoritmo
 * de ordenacion de uno malo.
 *
 * Se prueban las DOS formas, `* 2` y `<< 1`, porque son la misma cosa: el
 * propio compilador convierte una en la otra, y reconocer solo una haria que
 * el mismo bucle fuera logaritmico antes de optimizar y lineal despues.
 */
static void a_multiplying_loop_is_logarithmic() {
    std::printf("\n[un bucle que multiplica es logaritmico]\n");

    /* `for (i = 1; i < n; i = i OP k)` con `n` PARAMETRO -- si fuera constante
     * el bucle estaria contado y no se veria lo que se quiere ver.
     * Valores: 0=cte 1 (init) | 1=phi i | 2=PARAM n | 3=cmp | 4=i OP k |
     * 5=cte k */
    auto construir = [](IrOp op, uint64_t k) {
        ir::IrFunction fn;
        fn.name = "geo";
        for (int i = 0; i < 6; ++i) fn.values.push_back({});
        fn.params.push_back(2);

        auto val = [](IrOp o, ir::IrValueId dst, IrType t) {
            IrInstr in;
            in.op = o;
            in.dst = dst;
            in.type = t;
            return in;
        };
        auto cte = [&](ir::IrValueId dst, uint64_t v) {
            IrInstr c = val(IrOp::CONST, dst, IrType::I64);
            c.imm = v;
            return c;
        };

        IrBlock entry;
        entry.id = 0;
        entry.name = "entry";
        entry.instrs.push_back(cte(0, 1));
        entry.instrs.push_back(cte(5, k));
        entry.instrs.push_back(br(1));

        IrBlock header;
        header.id = 1;
        header.name = "header";
        {
            IrInstr phi = val(IrOp::PHI, 1, IrType::I64);
            phi.phi_args.push_back({/*value=*/0, /*block=*/0});
            phi.phi_args.push_back({/*value=*/4, /*block=*/2});
            header.instrs.push_back(phi);
            IrInstr cmp = val(IrOp::CMP_LT, 3, IrType::BOOL);
            cmp.operands.push_back(1);
            cmp.operands.push_back(2);
            header.instrs.push_back(cmp);
            IrInstr t = brcond(2, 3);
            t.operands[0] = 3;
            header.instrs.push_back(t);
        }

        IrBlock body;
        body.id = 2;
        body.name = "body";
        {
            IrInstr adv = val(op, 4, IrType::I64);
            adv.operands.push_back(1);
            adv.operands.push_back(5);
            body.instrs.push_back(adv);
            body.instrs.push_back(br(1));
        }

        fn.blocks = {entry, header, body, block(3, "exit", ret())};
        fn.blocks[0].succs = {1};
        fn.blocks[1].succs = {2, 3};
        fn.blocks[2].succs = {1};
        fn.blocks[1].preds = {0, 2};
        fn.blocks[2].preds = {1};
        fn.blocks[3].preds = {1};
        return fn;
    };

    /* `i * 2` y `i << 1` son la MISMA progresion.  El segundo es en lo que el
     * compilador convierte el primero, asi que los dos tienen que dar igual. */
    const ir::IrFunction por_mul = construir(IrOp::MUL, 2);
    const ir::IrFunction por_shl = construir(IrOp::SHL, 1);

    for (const ir::IrFunction *fnp : {&por_mul, &por_shl}) {
        const ir::IrFunction &fn = *fnp;
        const LoopFacts lf = compute_loop_facts(fn);
        const IrFacts hechos = build_ir_facts(fn);
        const LoopStructure st = detect_loop_structure(fn, lf, 0);
        CHECK(st.valid, "la forma es la de un bucle contado");

        /* La induccion ARITMETICA no esta, y eso es correcto: quien
         * desenrolla o vectoriza da por hecho un paso fijo, y aqui no lo hay.
         * Confundirlas haria calcular direcciones que el bucle no toca. */
        LoopIV iv;
        CHECK(!detect_loop_iv(fn, hechos.def_block, st.header, st.preheader,
                              st.latch, iv),
              "no hay induccion aritmetica -- y no debe haberla");

        GeoIV g;
        CHECK(detect_geometric_iv(fn, hechos.def_block, st.header, st.preheader,
                                  st.latch, g),
              "pero si geometrica");
        CHECK(g.ratio == 2, "y el factor es 2, venga de `* 2` o de `<< 1`");
        CHECK(g.phi == 1 && g.bound == 2,
              "sobre la variable del bucle, contra el limite");
    }

    /* Y con eso el coste deja de decir O(n).  Se publica el hecho a mano: lo
     * que se prueba aqui es que el CONSUMIDOR cambia de clase, no el camino
     * del productor -- ese lo cubre la e2e. */
    const LoopFacts lf = compute_loop_facts(por_mul);
    analysis::asa::FactStore store;
    analysis::asa::Fact f;
    f.what.domain = analysis::asa::kProducerLoops;
    f.what.code = "loop.geometric";
    f.what.a = 2;
    f.about.kind = analysis::asa::Subject::Kind::Block;
    f.about.function = store.intern(por_mul.name);
    f.about.id = lf.header_block_of(0);
    f.seal.certainty = analysis::asa::Certainty::Proven;
    f.scope.stage = analysis::asa::kStagePreOpt;
    store.add(std::move(f));

    const analyze::CostResult sin_hechos = analyze::analyze_function(por_mul);
    CHECK(sin_hechos.big_o == analyze::CostClass::O_N,
          "sin el hecho, un bucle es un bucle: lineal");
    const analyze::CostResult con_hechos = analyze::analyze_function(
        por_mul, &store, analysis::asa::kStagePreOpt);
    CHECK(con_hechos.big_o == analyze::CostClass::O_LOGN,
          "con el hecho, LOGARITMICO -- otra clase, no otra constante");
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
    an_outer_loop_is_recognized_too();
    a_constant_outer_loop_does_not_square_the_cost();
    a_multiplying_loop_is_logarithmic();

    std::printf("\n=== %d checks, %d fallos ===\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
