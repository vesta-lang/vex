/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_aggregate_facts.cpp
 * @brief Bateria de FORMAS DE USO del dominio de forma de valor.
 *
 * Los casos se montan sobre el IR a mano, no desde `.vx`, y es deliberado: lo
 * que se prueba es que el conocimiento depende de COMO SE USA un valor y no de
 * que tipo tenia en el fuente.  Construyendo el IR directamente, el tipo
 * literalmente no existe -- solo hay una reserva, desplazamientos y llamadas
 * --, asi que si dos casos con el mismo esqueleto dieran respuestas distintas
 * seria imposible echarle la culpa al tipo.
 *
 * Y no se comprueba solo la forma.  El producto de ASA ya no es `Compuesto`: es
 * "compuesto, demostrado en tal ambito, por estas observaciones, limitado por
 * esta frontera, no elevable a este otro".  Por eso cada caso mira tambien el
 * universo, la causa y el efecto: una forma correcta con una explicacion falsa
 * es peor que no tener nada, porque parece auditable y no lo es.
 */
#include "analysis/asa/aggregate_facts.h"
#include "analysis/facts/ir_facts.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace analysis;
using namespace analysis::asa;

static int fallos = 0;
static int total = 0;

static void check(bool cond, const std::string &que) {
    ++total;
    if (!cond) {
        ++fallos;
        std::printf("  FALLO: %s\n", que.c_str());
    }
}

// ---------------------------------------------------------------------------
// Construccion del IR
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

/// Direccion de un componente: `base + off`.  Es como el IR habla de campos.
static ir::IrValueId componente(ir::IrFunction &fn, uint32_t blk,
                                ir::IrValueId base, int64_t off) {
    if (off == 0) return base;
    const ir::IrValueId k = cte(fn, blk, off);
    const ir::IrValueId p = fn.new_value(ir::IrType::PTR);
    emitir(fn, blk, ir::IrOp::ADD, p, {base, k});
    return p;
}

static void leer(ir::IrFunction &fn, uint32_t blk, ir::IrValueId base,
                 int64_t off) {
    const ir::IrValueId d = fn.new_value(ir::IrType::I64);
    emitir(fn, blk, ir::IrOp::LOAD, d, {componente(fn, blk, base, off)});
}

static void escribir(ir::IrFunction &fn, uint32_t blk, ir::IrValueId base,
                     int64_t off, int64_t valor) {
    const ir::IrValueId v = cte(fn, blk, valor);
    emitir(fn, blk, ir::IrOp::STORE, ir::IR_NO_VALUE,
           {v, componente(fn, blk, base, off)});
}

/// Una operacion sobre el valor: recibe el puntero entero y toca los
/// desplazamientos que se le digan.
static ir::IrFunction operacion(const std::string &nombre,
                                const std::vector<int64_t> &escribe_offs,
                                const std::vector<int64_t> &lee_offs) {
    ir::IrFunction fn;
    fn.name = nombre;
    const uint32_t b0 = fn.new_block("entry");
    const ir::IrValueId p = fn.new_value(ir::IrType::PTR);
    fn.params.push_back(p);
    for (int64_t o : lee_offs)
        leer(fn, b0, p, o);
    for (int64_t o : escribe_offs)
        escribir(fn, b0, p, o, 7);
    emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {});
    return fn;
}

/// El caso: un valor de 16 bytes en `main`, con el esqueleto de uso que toque.
struct Caso {
    ir::IrModule mod;
    ir::IrValueId ancla = 0;

    AggregateFacts hechos() {
        const ir::IrFunction &fn = mod.functions.back();
        const IrFacts h = build_ir_facts(fn);
        const AggregateFactsMap m = observar_agregados(mod, fn, h);
        return m.agregados.empty() ? AggregateFacts{} : m.agregados.front();
    }
};

/// @param toca_en_main desplazamientos que `main` lee por su cuenta.
/// @param op nombre de la operacion a la que se pasa el valor entero (o vacio).
static Caso montar(const std::vector<int64_t> &toca_en_main,
                   const std::string &op,
                   const std::vector<int64_t> &op_escribe,
                   const std::vector<int64_t> &op_lee) {
    Caso c;
    if (!op.empty())
        c.mod.functions.push_back(operacion(op, op_escribe, op_lee));
    ir::IrFunction fn;
    fn.name = "main";
    const uint32_t b0 = fn.new_block("entry");
    const ir::IrValueId a = fn.new_value(ir::IrType::PTR);
    emitir(fn, b0, ir::IrOp::ALLOCA, a, {}).imm = 16;
    c.ancla = a;
    if (!op.empty())
        emitir(fn, b0, ir::IrOp::CALL, ir::IR_NO_VALUE, {a}).func_name = op;
    for (int64_t o : toca_en_main)
        leer(fn, b0, a, o);
    emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {});
    c.mod.functions.push_back(std::move(fn));
    return c;
}

// ===========================================================================
//  A -- saco puro: se tocan las partes y nada consume el valor entero
// ===========================================================================
static void caso_a() {
    Caso c = montar({0, 8}, "", {}, {});
    const AggregateFacts f = c.hechos();
    check(f.forma() == FormaDeValor::Agregado,
          "A saco: sin nada que lo consuma entero, tocar partes es un saco");
    check(f.seal.certainty == Certainty::Proven,
          "A saco: con el universo cerrado, la conclusion esta demostrada");
    check(f.offsets_tocados() == 2, "A saco: se ven los dos desplazamientos");
    check(f.participaciones.empty(),
          "A saco: no hay participacion como unidad");
}

// ===========================================================================
//  B -- unidad pura: se pasa entero y el propietario no lo destripa
// ===========================================================================
static void caso_b() {
    Caso c = montar({}, "op", {}, {0});
    const AggregateFacts f = c.hechos();
    check(f.forma() == FormaDeValor::Compuesto,
          "B unidad: entra entero en una operacion vista entera");
    check(f.participaciones.size() == 1, "B unidad: una participacion");
    check(f.participaciones.front().operacion == "op",
          "B unidad: la procedencia dice en QUE operacion");
    check(f.seal.certainty == Certainty::Proven,
          "B unidad: universo cerrado -> demostrada");
}

// ===========================================================================
//  C -- unidad IMPLEMENTADA por partes: la operacion toca sus componentes
// ===========================================================================
static void caso_c() {
    Caso c = montar({}, "op", {0, 8}, {});
    const AggregateFacts f = c.hechos();
    check(f.forma() == FormaDeValor::Compuesto,
          "C implementacion: tocar partes DENTRO de la operacion no desmiente "
          "la unidad");
    check(f.accesos_con(RelacionAcceso::EnOperacion) == 2,
          "C implementacion: los accesos quedan con su relacion, no en un "
          "contador");
    check(f.accesos_con(RelacionAcceso::EnPropietario) == 0,
          "C implementacion: el propietario no toca nada");
}

// ===========================================================================
//  D -- unidad + acceso INDEPENDIENTE: la contradiccion de verdad
// ===========================================================================
static void caso_d() {
    // La operacion toca el 0; `main` lee el 8, que ninguna operacion produce.
    Caso c = montar({8}, "op", {0}, {});
    const AggregateFacts f = c.hechos();
    check(f.forma() == FormaDeValor::Desconocida,
          "D conflicto: unidad + una parte que ninguna operacion produce -> se "
          "calla");
    bool motivo_ok = false;
    for (MotivoForma m : f.motivos_forma())
        if (m == MotivoForma::AccesoIndependienteDeOperacion) motivo_ok = true;
    check(motivo_ok, "D conflicto: y DICE por que -- acceso independiente");
    check(f.seal.certainty == Certainty::Unknown,
          "D conflicto: sin forma que sostener, la certeza tampoco afirma");
}

// ===========================================================================
//  D' -- el mismo esqueleto, pero la parte que se lee SI la produce la
//  operacion
// ===========================================================================
static void caso_d_ligado() {
    Caso c = montar({8}, "op", {0, 8}, {});
    const AggregateFacts f = c.hechos();
    check(f.forma() == FormaDeValor::Compuesto,
          "D' consumo: leer lo que la operacion escribio es consumir, no "
          "destripar");
    check(f.accesos_con(RelacionAcceso::EnPropietario) == 1,
          "D' consumo: el acceso sigue observandose, solo cambia su lectura");
}

// ===========================================================================
//  Universo y efecto: una verdad local bajo una frontera abierta
// ===========================================================================
static void caso_universo() {
    /* `main` pasa el valor a `op`, que se lleva la direccion de un componente a
     * `otra`.  Dentro de `op` la frontera abre su ambito, pero lo que se
     * demuestre en un ambito cerrado tiene que sobrevivir. */
    Caso c;
    c.mod.functions.push_back(operacion("otra", {}, {0}));
    {
        ir::IrFunction fn;
        fn.name = "op";
        const uint32_t b0 = fn.new_block("entry");
        const ir::IrValueId p = fn.new_value(ir::IrType::PTR);
        fn.params.push_back(p);
        // Se lleva la direccion del componente 8: frontera hacia `otra`.
        emitir(fn, b0, ir::IrOp::CALL, ir::IR_NO_VALUE,
               {componente(fn, b0, p, 8)})
            .func_name = "otra";
        emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {});
        c.mod.functions.push_back(std::move(fn));
    }
    {
        ir::IrFunction fn;
        fn.name = "main";
        const uint32_t b0 = fn.new_block("entry");
        const ir::IrValueId a = fn.new_value(ir::IrType::PTR);
        emitir(fn, b0, ir::IrOp::ALLOCA, a, {}).imm = 16;
        emitir(fn, b0, ir::IrOp::CALL, ir::IR_NO_VALUE, {a}).func_name = "op";
        emitir(fn, b0, ir::IrOp::RET, ir::IR_NO_VALUE, {});
        c.mod.functions.push_back(std::move(fn));
    }
    const AggregateFacts f = c.hechos();

    check(!f.fronteras.empty(), "universo: la frontera se observa");
    if (!f.fronteras.empty()) {
        const Frontera &fr = f.fronteras.front();
        check(fr.codigo == CodigoFrontera::ComponenteSeLleva,
              "universo: la causa es que se llevan un componente");
        check(fr.hacia != kUniversoDesconocido,
              "universo: el destino se puede NOMBRAR aunque no se haya mirado");
        check(fr.hacia < f.universos.size() &&
                  f.universos[fr.hacia].observacion ==
                      EstadoObservacion::NoObservado,
              "universo: y se marca como no observado, que es otro eje");
        check(fr.desde != fr.hacia,
              "universo: la frontera va de un ambito a otro");
    }
    // Toda causa emitida tiene que estar localizada: ni silencio ni invento.
    for (const AggregateFacts::EfectoAlcance &e : f.efectos())
        check(e.causa_localizada,
              "universo: el efecto dice DONDE esta la causa que lo bloquea");
}

int main() {
    caso_a();
    caso_b();
    caso_c();
    caso_d();
    caso_d_ligado();
    caso_universo();
    std::printf("=== forma de valor: %d checks, %d fallos ===\n", total,
                fallos);
    return fallos == 0 ? 0 : 1;
}
