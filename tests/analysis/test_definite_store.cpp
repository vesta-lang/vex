/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file test_definite_store.cpp
 * @brief Que un puntero se escriba en TODOS los caminos, y que preguntarlo
 *        cueste una vez.
 *
 * Dos cosas distintas y las dos hacen falta:
 *
 *   1. **El veredicto.**  Y sobre todo los casos en los que NO debe acusar: un
 *      analisis de "para todos los caminos" que se equivoque hacia el lado malo
 *      rechaza codigo correcto, y entonces se aprende a rodearlo.
 *   2. **Que sea perezoso y cacheado.**  Eso no se ve mirando el resultado --
 *      sale igual calculandolo mil veces --, asi que se comprueba con los
 *      contadores del gestor: la segunda pregunta tiene que ser un ACIERTO, y
 *      tras cambiar la funcion tiene que volver a calcularse.  Sin esta parte,
 *      "esta cacheado" seria una afirmacion sin comprobar.
 */

#include "analysis/facts/definite_store.h"
#include "analysis/manager/analysis_manager.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <string>

static int g_checks = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  [FALLO] %s (linea %d)\n", (msg), __LINE__);         \
        }                                                                      \
    } while (0)

using analysis::DefiniteStoreFacts;

namespace {

/// Una funcion con un solo parametro puntero y un solo bloque.
ir::IrFunction one_block(bool con_store) {
    ir::IrFunction fn;
    fn.name = "f";
    const ir::IrValueId p = fn.new_value(ir::IrType::PTR, "%p");
    fn.values[p].is_param = true;
    fn.params.push_back(p);
    const uint32_t b = fn.new_block("entry");
    if (con_store) {
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.dst = ir::IR_NO_VALUE;
        const ir::IrValueId v = fn.new_value(ir::IrType::I64);
        st.operands = {v, p};
        fn.append(b, std::move(st));
    }
    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.dst = ir::IR_NO_VALUE;
    ret.source_line = 42;
    fn.append(b, std::move(ret));
    return fn;
}

} // namespace

/**
 * @brief Lo basico: con escritura y sin ella.
 */
static void the_simple_verdicts() {
    std::printf("-- un camino: escribe o no escribe\n");
    {
        const ir::IrFunction fn = one_block(true);
        const DefiniteStoreFacts d =
            analysis::compute_definite_store(fn, fn.params[0]);
        CHECK(d.verdict == DefiniteStoreFacts::Verdict::Always,
              "con la escritura delante, esta demostrado que si");
        CHECK(!d.proven_missing(), "y no se acusa de nada");
    }
    {
        const ir::IrFunction fn = one_block(false);
        const DefiniteStoreFacts d =
            analysis::compute_definite_store(fn, fn.params[0]);
        CHECK(d.proven_missing(), "sin escritura, esta demostrado que falta");
        CHECK(d.witness_line == 42,
              "y se dice POR QUE retorno se sale sin escribir: es la prueba");
    }
}

/**
 * @brief Una rama escribe y la otra no.
 *
 * Es el caso que separa este analisis del anterior, que solo miraba si se
 * escribia ALGUNA vez: con una rama que escribe, aquel daba por bueno esto.
 */
static void one_branch_is_not_enough() {
    std::printf("-- escribir en UNA rama no basta\n");
    ir::IrFunction fn;
    fn.name = "f";
    const ir::IrValueId p = fn.new_value(ir::IrType::PTR, "%p");
    fn.values[p].is_param = true;
    fn.params.push_back(p);
    const uint32_t entry = fn.new_block("entry");
    const uint32_t then_ = fn.new_block("then");
    const uint32_t merge = fn.new_block("merge");

    ir::IrInstr br{};
    br.op = ir::IrOp::BR_COND;
    br.dst = ir::IR_NO_VALUE;
    fn.append(entry, std::move(br));
    fn.blocks[entry].succs = {then_, merge};
    fn.blocks[then_].preds = {entry};
    fn.blocks[merge].preds = {entry, then_};

    ir::IrInstr st{};
    st.op = ir::IrOp::STORE;
    st.dst = ir::IR_NO_VALUE;
    st.operands = {fn.new_value(ir::IrType::I64), p};
    fn.append(then_, std::move(st));
    ir::IrInstr jmp{};
    jmp.op = ir::IrOp::BR;
    jmp.dst = ir::IR_NO_VALUE;
    fn.append(then_, std::move(jmp));
    fn.blocks[then_].succs = {merge};

    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.dst = ir::IR_NO_VALUE;
    ret.source_line = 7;
    fn.append(merge, std::move(ret));

    const DefiniteStoreFacts d =
        analysis::compute_definite_store(fn, fn.params[0]);
    CHECK(d.proven_missing(),
          "hay un camino que llega al retorno sin escribir");
    CHECK(d.witness_line == 7, "y se senala ese retorno");
}

/**
 * @brief Si el puntero SALE, no se afirma que falte.
 *
 * Es la mitad que evita que el analisis sea inutilizable: delegar el relleno en
 * otra funcion es una forma legitima de cumplir un `out`, y acusarla seria el
 * peor fallo posible -- rechazar codigo correcto ensena a desactivar la regla.
 */
static void an_escape_means_unknown_not_missing() {
    std::printf("-- si el puntero sale, no se acusa: se dice que no se sabe\n");
    ir::IrFunction fn;
    fn.name = "f";
    const ir::IrValueId p = fn.new_value(ir::IrType::PTR, "%p");
    fn.values[p].is_param = true;
    fn.params.push_back(p);
    const uint32_t b = fn.new_block("entry");
    ir::IrInstr call{};
    call.op = ir::IrOp::CALL;
    call.dst = ir::IR_NO_VALUE;
    call.func_name = "relleno";
    call.operands = {p};
    fn.append(b, std::move(call));
    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.dst = ir::IR_NO_VALUE;
    fn.append(b, std::move(ret));

    const DefiniteStoreFacts d =
        analysis::compute_definite_store(fn, fn.params[0]);
    CHECK(d.verdict == DefiniteStoreFacts::Verdict::Unknown,
          "no se afirma ni que si ni que no");
    CHECK(!d.proven_missing(), "y sobre todo NO se acusa");
    CHECK(d.reason == analysis::asa::UnknownReason::OpaqueBoundary,
          "el motivo es una frontera opaca, del vocabulario del ASA");
    CHECK(std::string(d.reason_code) == "definite_store.escapes",
          "con su codigo estable, para el informe y el linter");
}

/**
 * @brief Perezoso y CACHEADO, comprobado con los contadores.
 *
 * Que el resultado sea el mismo no demuestra que no se recalcule.  Lo que lo
 * demuestra es que la segunda pregunta sea un acierto de cache, y que tras
 * cambiar la funcion vuelva a computarse.
 */
static void asking_twice_costs_once() {
    std::printf("-- preguntar dos veces cuesta una\n");
    analysis::AnalysisManager am;
    ir::IrFunction fn = one_block(true);
    fn.version = 1;

    int computed = 0;
    const auto pedir = [&]() -> const analysis::DefiniteStoreMap & {
        return am.get_or_compute_v<analysis::DefiniteStoreAnalysis,
                                   analysis::DefiniteStoreMap>(
            fn.name, fn.version, [&]() {
                ++computed;
                return analysis::compute_definite_stores(fn);
            });
    };

    const analysis::DefiniteStoreMap &a = pedir();
    CHECK(computed == 1, "la primera vez se calcula");
    CHECK(a.of(fn.params[0]) != nullptr, "y contesta por el parametro");

    (void)pedir();
    CHECK(computed == 1, "la segunda NO: se reutiliza lo cacheado");

    // Cambiar la funcion avanza su version, y eso basta para que el resultado
    // caduque: nadie tiene que acordarse de invalidarlo a mano.
    fn.version = 2;
    (void)pedir();
    CHECK(computed == 2,
          "tras cambiar la funcion se recalcula, sin invalidar a mano");
}

int main() {
    std::printf("=== test_definite_store ===\n");
    the_simple_verdicts();
    one_branch_is_not_enough();
    an_escape_means_unknown_not_missing();
    asking_twice_costs_once();
    std::printf("=== test_definite_store: %d comprobaciones, %d fallidas ===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
