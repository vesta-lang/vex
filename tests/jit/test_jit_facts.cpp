/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/jit/test_jit_facts.cpp
 * @brief La base de hechos del JIT (@c jit/jit_facts.h): que el conocimiento se
 *        calcule UNA vez y se reparta, que caduque cuando el IR cambia, y que
 * la pregunta que hace el especializador de llamadas conteste lo que dice.
 *
 * El test EXIGE que el reparto ocurra de verdad: no basta con que las
 * respuestas sean correctas -- eso tambien pasaria recomputando cada vez, que
 * es justo lo que se venia a quitar.  Por eso se mira el contador de analisis
 * ejecutados, y la identidad del objeto devuelto.
 */

#include "ir/ssa_ir.h"
#include "jit/jit_facts.h"

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

// ---------------------------------------------------------------------------
// Helpers de construccion.
// ---------------------------------------------------------------------------
static ir::IrInstr &emitir(ir::IrFunction &fn, uint32_t blk, ir::IrOp op,
                           ir::IrValueId dst, std::vector<ir::IrValueId> ops) {
    ir::IrInstr in{};
    in.op = op;
    in.dst = dst;
    in.operands = std::move(ops);
    fn.append(blk, std::move(in));
    return fn.blocks[blk].instrs.back();
}

static ir::IrValueId cte(ir::IrFunction &fn, uint32_t blk, int64_t v) {
    const ir::IrValueId id = fn.new_value(ir::IrType::I64);
    fn.values[id].is_const = true;
    fn.values[id].const_val = static_cast<uint64_t>(v);
    emitir(fn, blk, ir::IrOp::CONST, id, {}).imm = static_cast<uint64_t>(v);
    return id;
}

/// `i64 con_cota() { return copiar(64); }` -- el argumento de la llamada es una
/// constante, asi que de el se sabe algo.
static ir::IrFunction hacer_con_cota(const std::string &nombre) {
    ir::IrFunction fn;
    fn.name = nombre;
    const uint32_t b0 = fn.new_block("entry");
    const ir::IrValueId n = cte(fn, b0, 64);
    const ir::IrValueId r = fn.new_value(ir::IrType::I64);
    emitir(fn, b0, ir::IrOp::CALL, r, {n}).func_name = "copiar";
    emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {r});
    return fn;
}

/// `i64 sin_cota(i64 p) { return copiar(p); }` -- del argumento no se sabe mas
/// que su tipo, que es lo mismo que no saber nada util.
static ir::IrFunction hacer_sin_cota(const std::string &nombre) {
    ir::IrFunction fn;
    fn.name = nombre;
    const uint32_t b0 = fn.new_block("entry");
    const ir::IrValueId p = fn.new_value(ir::IrType::I64);
    fn.params.push_back(p);
    const ir::IrValueId r = fn.new_value(ir::IrType::I64);
    emitir(fn, b0, ir::IrOp::CALL, r, {p}).func_name = "copiar";
    emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {r});
    return fn;
}

// ===========================================================================
// 1. La pregunta del especializador contesta lo que dice
// ===========================================================================
static void probar_pregunta() {
    jit::JitFactBase base;

    const ir::IrFunction con = hacer_con_cota("con_cota");
    CHECK(jit::hay_argumento_acotado(con, base.ranges(con)),
          "un argumento constante esta acotado -- de el se sabe algo");

    const ir::IrFunction sin = hacer_sin_cota("sin_cota");
    CHECK(!jit::hay_argumento_acotado(sin, base.ranges(sin)),
          "un argumento que vale todo su tipo no acota nada");

    // Sin llamadas ni reservas no hay sitio donde aprovechar nada.
    ir::IrFunction pelada;
    pelada.name = "pelada";
    const uint32_t b0 = pelada.new_block("entry");
    const ir::IrValueId k = cte(pelada, b0, 7);
    emitir(pelada, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {k});
    CHECK(!jit::hay_argumento_acotado(pelada, base.ranges(pelada)),
          "sin llamada ni reserva no hay sitio donde aprovechar la cota");
}

// ===========================================================================
// 2. El conocimiento se calcula UNA vez y se reparte
// ===========================================================================
static void probar_reparto() {
    jit::JitFactBase base;
    const ir::IrFunction fn = hacer_con_cota("reparto");

    const analysis::RangeFacts &r1 = base.ranges(fn);
    const size_t tras_la_primera = base.computations();
    CHECK(tras_la_primera == 2, "la primera consulta ejecuta los rangos y la "
                                "estructura de la que dependen");

    const analysis::RangeFacts &r2 = base.ranges(fn);
    CHECK(&r1 == &r2,
          "la segunda consulta devuelve EL MISMO hecho, no una copia");
    CHECK(base.computations() == tras_la_primera,
          "la segunda consulta no ejecuta ningun analisis -- sale de la cache");

    // La estructura ya la pidieron los rangos: preguntarla no cuesta nada.
    base.structure(fn);
    CHECK(base.computations() == tras_la_primera,
          "la estructura que pidieron los rangos ya esta: no se recalcula");
    CHECK(base.queries() > base.computations(),
          "hay mas preguntas que analisis: eso ES el reparto");

    // Otra funcion es otro conocimiento: la cache no las confunde.
    const ir::IrFunction otra = hacer_sin_cota("otra");
    base.ranges(otra);
    CHECK(base.computations() == tras_la_primera + 2,
          "otra funcion se analiza aparte -- la cache va por funcion");
}

// ===========================================================================
// 3. Mutar el IR caduca los hechos (y arrastra a lo que se derivo de ellos)
// ===========================================================================
static void probar_caducidad() {
    jit::JitFactBase base;
    ir::IrFunction fn = hacer_con_cota("caducidad");

    base.ranges(fn);
    const size_t antes = base.computations();

    base.invalidate(fn);
    base.ranges(fn);
    CHECK(base.computations() == antes + 2,
          "tras invalidar se recalculan los rangos Y la estructura (cascada)");

    /* Y el hecho nuevo refleja el IR nuevo: la llamada pasa a recibir un valor
     * del que no se sabe nada, asi que la respuesta cambia. */
    const ir::IrValueId p = fn.new_value(ir::IrType::I64);
    fn.params.push_back(p);
    fn.blocks[0].instrs[1].operands[0] = p; // la CALL ahora recibe el parametro
    base.invalidate(fn);
    CHECK(!jit::hay_argumento_acotado(fn, base.ranges(fn)),
          "tras cambiar el IR la respuesta es la del IR NUEVO, no la cacheada");
}

// ===========================================================================
// 4. Todo hecho dice de donde sale y cuanto se puede uno fiar de el
// ===========================================================================
static void probar_sello_y_volcado() {
    jit::JitFactBase base;
    const ir::IrFunction fn = hacer_con_cota("sellada");
    base.ranges(fn);

    const analysis::asa::Seal s = base.seal(jit::kProducerRanges, fn);
    CHECK(s.certainty == analysis::asa::Certainty::Proven,
          "un analisis que llega a punto fijo da un hecho demostrado");
    CHECK(s.origin.producer == jit::kProducerRanges,
          "el hecho dice QUIEN lo descubrio");
    CHECK(std::string(s.origin.function) == "sellada", "y mirando que funcion");
    CHECK(
        s.support.depends_on(jit::kProducerStructure),
        "y sobre que otro hecho se dedujo -- sin eso no hay a quien invalidar");

    // De una funcion que nadie miro no se sabe nada, que NO es saber que no
    // hay.
    const ir::IrFunction ajena = hacer_sin_cota("ajena");
    CHECK(base.seal(jit::kProducerRanges, ajena).certainty ==
              analysis::asa::Certainty::Unknown,
          "sin preguntar no hay hecho, y eso se dice: desconocida");

    const std::vector<jit::RecordedFact> v = base.dump();
    CHECK(v.size() == 2,
          "el volcado saca los dos hechos vivos: los rangos y su estructura");
    CHECK(v[0].function == "sellada" && v[1].function == "sellada",
          "y solo los de la funcion consultada");
    CHECK(std::string(v[0].domain) == jit::kProducerStructure &&
              std::string(v[1].domain) == jit::kProducerRanges,
          "en orden estable, para que dos volcados se puedan comparar");

    base.invalidate(fn);
    CHECK(
        base.dump().empty(),
        "lo invalidado desaparece del volcado -- no queda afirmando lo que ya "
        "no se sabe");
}

int main() {
    std::printf("=== test_jit_facts (base de hechos del JIT) ===\n");
    probar_pregunta();
    probar_reparto();
    probar_caducidad();
    probar_sello_y_volcado();
    std::printf("%s: %d comprobaciones, %d fallos\n",
                g_fail == 0 ? "OK" : "FALLO", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
