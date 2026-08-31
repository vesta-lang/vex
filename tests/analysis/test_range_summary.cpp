/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_range_summary.cpp
 * @brief Pruebas de los rangos que cruzan la frontera de una funcion.
 *
 * Cada prueba EXIGE que el resumen haga algo.  Un test que pasa igual con el
 * analisis apagado no prueba el analisis: prueba que no estorba, y con el
 * tiempo se pudre sin que nadie se entere.  Por eso casi todas comparan contra
 * el mismo programa analizado SIN resumenes, y piden que la respuesta sea
 * estrictamente mejor.
 *
 * Y el reves tambien se prueba: cuando de verdad falta informacion -- la
 * direccion de la funcion se pierde de vista, es un punto de entrada -- el
 * resumen NO debe estrechar nada.  Afirmar de mas ahi puede costar un programa
 * valido rechazado.
 */
#include "analysis/facts/ir_facts.h"
#include "analysis/facts/range_summary.h"
#include "analysis/memory/fn_targets.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace analysis;

static int fallos = 0;
static int total = 0;

static void check(bool cond, const std::string &que) {
    ++total;
    if (!cond) {
        ++fallos;
        std::printf("  FALLO: %s\n", que.c_str());
    }
}

static const RangeType kI32 = RangeType::i(32);

static bool es(const ValueRange &r, RangeType t, int64_t lo, int64_t hi) {
    return r.acotada() && r.t == t && r.lo_c == t.desde_signo(lo) &&
           r.hi_c == t.desde_signo(hi);
}

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
    const ir::IrValueId id = fn.new_value(ir::IrType::I32);
    fn.values[id].is_const = true;
    fn.values[id].const_val = static_cast<uint64_t>(v);
    emitir(fn, blk, ir::IrOp::CONST, id, {}).imm = static_cast<uint64_t>(v);
    return id;
}

/// `i32 destino(i32 p) { return p; }` -- devuelve su parametro, para que el
/// resumen de retorno dependa del de entrada y se vea si se propaga.
static ir::IrFunction hacer_destino(const std::string &nombre) {
    ir::IrFunction fn;
    fn.name = nombre;
    const uint32_t b0 = fn.new_block("entry");
    const ir::IrValueId p = fn.new_value(ir::IrType::I32);
    fn.params.push_back(p);
    emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {p});
    return fn;
}

/// Rango del parametro @p idx de @p nombre segun los resumenes.
static ValueRange param_de(const RangeSummaries &s, const std::string &nombre,
                           size_t idx) {
    const FnRangeSummary *f = s.buscar(nombre);
    if (f == nullptr || idx >= f->params.size()) return ValueRange::top();
    return f->params[idx];
}

// ===========================================================================
// 1. Llamadas directas: el parametro vale lo que le pasan
// ===========================================================================
static void probar_llamadas_directas() {
    ir::IrModule mod;
    mod.functions.push_back(hacer_destino("destino"));
    {
        ir::IrFunction fn;
        fn.name = "main";
        const uint32_t b0 = fn.new_block("entry");
        const ir::IrValueId tres = cte(fn, b0, 3);
        const ir::IrValueId siete = cte(fn, b0, 7);
        const ir::IrValueId r1 = fn.new_value(ir::IrType::I32);
        emitir(fn, b0, ir::IrOp::CALL, r1, {tres}).func_name = "destino";
        const ir::IrValueId r2 = fn.new_value(ir::IrType::I32);
        emitir(fn, b0, ir::IrOp::CALL, r2, {siete}).func_name = "destino";
        emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {r1});
        mod.functions.push_back(std::move(fn));
    }

    const RangeSummaries s = compute_range_summaries(mod);
    check(s.convergio,
          "directas: el punto fijo del grafo de llamadas converge");
    check(s.buscar("destino") != nullptr && s.buscar("destino")->cerrada,
          "directas: 'destino' es cerrada -- se ven todos sus llamantes");
    check(es(param_de(s, "destino", 0), kI32, 3, 7),
          "directas: el parametro es la union de lo que pasa cada llamada");
    check(es(s.buscar("destino")->ret, kI32, 3, 7),
          "directas: y lo que devuelve se sigue de lo que entra");

    // Control: sin resumenes, ese parametro vale lo que su tipo.
    const ir::IrFunction &d = mod.functions[0];
    const IrFacts h = build_ir_facts(d);
    const RangeFacts sin = compute_ranges(d, h);
    check(es(sin.at(d.params[0]), kI32, INT32_MIN, INT32_MAX),
          "directas: SIN resumen el parametro es todo el tipo (el analisis "
          "hace falta)");
    const RangeFacts con = compute_ranges(d, h, RangeOptions{}, &s);
    check(es(con.at(d.params[0]), kI32, 3, 7),
          "directas: CON resumen el motor ya lo ve acotado");
}

// ===========================================================================
// 2. Mundo abierto: si falta un llamante, no se afirma nada
// ===========================================================================
static void probar_mundo_abierto() {
    // La direccion se toma y se GUARDA en memoria: se pierde de vista.
    ir::IrModule mod;
    mod.functions.push_back(hacer_destino("destino"));
    {
        ir::IrFunction fn;
        fn.name = "main";
        const uint32_t b0 = fn.new_block("entry");
        const ir::IrValueId dir = fn.new_value(ir::IrType::PTR);
        emitir(fn, b0, ir::IrOp::LABEL_ADDR, dir, {}).func_name = "destino";
        const ir::IrValueId hueco = fn.new_value(ir::IrType::PTR);
        emitir(fn, b0, ir::IrOp::ALLOCA, hueco, {}).imm = 8;
        emitir(fn, b0, ir::IrOp::STORE, ir::IR_NO_VALUE, {dir, hueco});
        const ir::IrValueId tres = cte(fn, b0, 3);
        const ir::IrValueId r1 = fn.new_value(ir::IrType::I32);
        emitir(fn, b0, ir::IrOp::CALL, r1, {tres}).func_name = "destino";
        emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {r1});
        mod.functions.push_back(std::move(fn));
    }

    const RangeSummaries s = compute_range_summaries(mod);
    check(s.buscar("destino") != nullptr && !s.buscar("destino")->cerrada,
          "abierto: guardar la direccion en memoria abre la funcion");
    check(es(param_de(s, "destino", 0), kI32, INT32_MIN, INT32_MAX),
          "abierto: su parametro vale lo que su tipo, aunque la unica llamada "
          "VISIBLE pase 3");

    // Un punto de entrada tampoco se estrecha: le llaman desde fuera.
    check(s.buscar("main") != nullptr && !s.buscar("main")->cerrada,
          "abierto: el punto de entrada nunca es cerrado");
}

// ===========================================================================
// 3. Direccion tomada Y llamada aqui mismo: la informacion ESTA, se busca
// ===========================================================================
static void probar_indirecta_resuelta() {
    ir::IrModule mod;
    mod.functions.push_back(hacer_destino("destino"));
    {
        ir::IrFunction fn;
        fn.name = "main";
        const uint32_t b0 = fn.new_block("entry");
        const ir::IrValueId dir = fn.new_value(ir::IrType::PTR);
        emitir(fn, b0, ir::IrOp::LABEL_ADDR, dir, {}).func_name = "destino";
        const ir::IrValueId cinco = cte(fn, b0, 5);
        const ir::IrValueId r = fn.new_value(ir::IrType::I32);
        {
            ir::IrInstr &ci = emitir(fn, b0, ir::IrOp::CALLIND, r, {cinco});
            ci.func_ptr = dir;
        }
        emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {r});
        mod.functions.push_back(std::move(fn));
    }

    const ir::IrFunction &main_fn = mod.functions[1];
    const IrFacts hm = build_ir_facts(main_fn);
    const ir::IrInstr *callind = nullptr;
    for (const ir::IrInstr &in : main_fn.blocks[0].instrs)
        if (in.op == ir::IrOp::CALLIND) callind = &in;
    check(callind != nullptr &&
              pointed_function(main_fn, hm, callind->func_ptr) == "destino",
          "indirecta: se resuelve a que funcion apunta el puntero");

    const AddressTaken d = follow_address(mod, "destino");
    check(d.taken && d.all_visible && d.indirect.size() == 1,
          "indirecta: la direccion se toma, pero TODOS sus usos son llamadas "
          "visibles");

    const RangeSummaries s = compute_range_summaries(mod);
    check(s.buscar("destino") != nullptr && s.buscar("destino")->cerrada,
          "indirecta: tomar la direccion NO abre la funcion si se ve donde se "
          "llama");
    check(
        es(param_de(s, "destino", 0), kI32, 5, 5),
        "indirecta: y el argumento de la llamada indirecta llega al parametro");
    check(es(s.buscar("destino")->ret, kI32, 5, 5),
          "indirecta: el retorno se sigue igual");
}

// ===========================================================================
// 4. Recursion: tiene que TERMINAR y no afirmar de mas
// ===========================================================================
static void probar_recursion() {
    /* i32 baja(i32 n) { if (n <= 0) return 0; return baja(n - 1); }
     * Llamada desde main con 10.  El punto fijo del grafo de llamadas es lo
     * mismo que el de un bucle: sin ensanchamiento no pararia. */
    ir::IrModule mod;
    {
        ir::IrFunction fn;
        fn.name = "baja";
        const uint32_t b0 = fn.new_block("entry");
        const uint32_t bfin = fn.new_block("fin");
        const uint32_t bsig = fn.new_block("sigue");
        const ir::IrValueId n = fn.new_value(ir::IrType::I32);
        fn.params.push_back(n);
        const ir::IrValueId cero = cte(fn, b0, 0);
        const ir::IrValueId c = fn.new_value(ir::IrType::BOOL);
        emitir(fn, b0, ir::IrOp::CMP_LE, c, {n, cero});
        {
            ir::IrInstr &br =
                emitir(fn, b0, ir::IrOp::BR_COND, ir::IR_NO_VALUE, {c});
            br.target_block = bfin;
            br.false_block = bsig;
        }
        const ir::IrValueId z = cte(fn, bfin, 0);
        emitir(fn, bfin, ir::IrOp::RET, ir::IR_NO_VALUE, {z});
        const ir::IrValueId uno = cte(fn, bsig, 1);
        const ir::IrValueId m = fn.new_value(ir::IrType::I32);
        emitir(fn, bsig, ir::IrOp::SUB, m, {n, uno});
        const ir::IrValueId r = fn.new_value(ir::IrType::I32);
        emitir(fn, bsig, ir::IrOp::CALL, r, {m}).func_name = "baja";
        emitir(fn, bsig, ir::IrOp::RET, ir::IR_NO_VALUE, {r});
        mod.functions.push_back(std::move(fn));
    }
    {
        ir::IrFunction fn;
        fn.name = "main";
        const uint32_t b0 = fn.new_block("entry");
        const ir::IrValueId diez = cte(fn, b0, 10);
        const ir::IrValueId r = fn.new_value(ir::IrType::I32);
        emitir(fn, b0, ir::IrOp::CALL, r, {diez}).func_name = "baja";
        emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {r});
        mod.functions.push_back(std::move(fn));
    }

    const RangeSummaries s = compute_range_summaries(mod);
    check(s.convergio, "recursion: el punto fijo TERMINA");
    const FnRangeSummary *f = s.buscar("baja");
    check(f != nullptr && f->cerrada,
          "recursion: llamarse a si misma no la abre");
    /* Lo que se exige no es un intervalo concreto -- el ensanchamiento puede
     * soltar la cota inferior -- sino que el resultado siga siendo CIERTO: el
     * 10 de la llamada de fuera esta dentro, y el retorno contiene al 0. */
    const ValueRange p = param_de(s, "baja", 0);
    check(p.acotada() && p.lo() <= 10 && p.hi() >= 10,
          "recursion: el parametro contiene el valor con el que se llama de "
          "fuera");
    check(f->ret.acotada() && f->ret.lo() <= 0 && f->ret.hi() >= 0,
          "recursion: el retorno contiene el 0 del caso base");
}

// ===========================================================================
// 5. El retorno vale para CUALQUIER llamante, se conozcan o no los demas
// ===========================================================================
static void probar_retorno_en_abierta() {
    ir::IrModule mod;
    {
        // i32 fija() { return 5; }  -- con la direccion tomada y perdida.
        ir::IrFunction fn;
        fn.name = "fija";
        const uint32_t b0 = fn.new_block("entry");
        const ir::IrValueId cinco = cte(fn, b0, 5);
        emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {cinco});
        mod.functions.push_back(std::move(fn));
    }
    {
        ir::IrFunction fn;
        fn.name = "main";
        const uint32_t b0 = fn.new_block("entry");
        const ir::IrValueId dir = fn.new_value(ir::IrType::PTR);
        emitir(fn, b0, ir::IrOp::LABEL_ADDR, dir, {}).func_name = "fija";
        const ir::IrValueId hueco = fn.new_value(ir::IrType::PTR);
        emitir(fn, b0, ir::IrOp::ALLOCA, hueco, {}).imm = 8;
        emitir(fn, b0, ir::IrOp::STORE, ir::IR_NO_VALUE, {dir, hueco});
        const ir::IrValueId r = fn.new_value(ir::IrType::I32);
        emitir(fn, b0, ir::IrOp::CALL, r, {}).func_name = "fija";
        emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {r});
        mod.functions.push_back(std::move(fn));
    }

    const RangeSummaries s = compute_range_summaries(mod);
    check(s.buscar("fija") != nullptr && !s.buscar("fija")->cerrada,
          "retorno: la funcion esta ABIERTA (su direccion se perdio de vista)");
    check(es(s.buscar("fija")->ret, kI32, 5, 5),
          "retorno: aun asi se sabe lo que devuelve -- eso sale de SU cuerpo");

    // Y el llamante lo aprovecha: el resultado de la llamada no es desconocido.
    const ir::IrFunction &main_fn = mod.functions[1];
    const IrFacts h = build_ir_facts(main_fn);
    ir::IrValueId res = ir::IR_NO_VALUE;
    for (const ir::IrInstr &in : main_fn.blocks[0].instrs)
        if (in.op == ir::IrOp::CALL) res = in.dst;
    const RangeFacts sin = compute_ranges(main_fn, h);
    check(es(sin.at(res), kI32, INT32_MIN, INT32_MAX),
          "retorno: SIN resumen, el resultado de la llamada es todo el tipo");
    const RangeFacts con = compute_ranges(main_fn, h, RangeOptions{}, &s);
    check(es(con.at(res), kI32, 5, 5),
          "retorno: CON resumen, el resultado de la llamada vale 5");
}

int main() {
    probar_llamadas_directas();
    probar_mundo_abierto();
    probar_indirecta_resuelta();
    probar_recursion();
    probar_retorno_en_abierta();
    std::printf("=== resumenes de frontera: %d checks, %d fallos ===\n", total,
                fallos);
    return fallos == 0 ? 0 : 1;
}
