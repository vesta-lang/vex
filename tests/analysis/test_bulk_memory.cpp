/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_bulk_memory.cpp
 * @brief El dominio `asa.bulk_memory`: que un bucle que mueve un tramo se
 *        reconozca, y -- sobre todo -- que cuando NO se reconoce se diga por
 *        que.
 *
 * Lo segundo es lo que faltaba y es la mitad importante.  El reconocedor se
 * rendia quince veces en silencio, asi que "en este programa no hay ninguna
 * copia" y "habia una y me falto un byte para verla" salian exactamente igual
 * -- y un analisis que calla al renunciar parece que funciona.
 *
 * El test EXIGE ademas que el numero publicado sea el numero: la cota de un
 * bucle suele ser un valor del programa, y publicar su identificador como si
 * fuera la cuenta imprimia "1 elementos" para un tramo de longitud
 * desconocida.  No un error: un numero equivocado.
 */

#include "analysis/asa/observed.h"
#include "analysis/facts/bulk_memory.h"
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

using ir::IrBlock;
using ir::IrInstr;
using ir::IrOp;
using ir::IrType;
using ir::IrValueId;

namespace {

IrInstr br(ir::IrBlockId t) {
    IrInstr in{};
    in.op = IrOp::BR;
    in.target_block = t;
    return in;
}

IrInstr brcond(ir::IrBlockId tt, ir::IrBlockId ff) {
    IrInstr in{};
    in.op = IrOp::BR_COND;
    in.target_block = tt;
    in.false_block = ff;
    in.operands.push_back(ir::IR_NO_VALUE);
    return in;
}

IrInstr val(IrOp op, IrValueId dst, IrType t) {
    IrInstr in{};
    in.op = op;
    in.dst = dst;
    in.type = t;
    return in;
}

/**
 * @brief `for (i = 0; i < n; i += paso) { p[i] = 0; }` en SSA ya construido.
 *
 * @param paso        avance del indice.  Con 1 el tramo es contiguo.
 * @param n_constante longitud escrita en el programa, o 0 para que sea un
 *                    PARAMETRO -- que es lo normal y donde se veia el numero
 *                    equivocado.
 */
ir::IrFunction hacer_relleno(int64_t paso, int64_t n_constante) {
    /* Valores: 0=cte 0 (init) | 1=phi i | 2=n | 3=cmp | 4=i+paso | 5=cte paso
     * 6=p (puntero base) | 7=direccion | 8=cte 0 (el valor escrito) */
    ir::IrFunction fn;
    fn.name = "relleno";
    for (int i = 0; i < 9; ++i) fn.values.push_back({});
    /* El puntero es del HOST -- lo que devuelve `malloc` --, y la marca va en
     * el VALOR, no en la instruccion: de que memoria es un puntero es una
     * propiedad suya, no de quien lo usa. */
    fn.values[6].type = IrType::PTR;
    fn.values[6].is_host_ptr = true;
    fn.values[7].type = IrType::PTR;
    fn.values[7].is_host_ptr = true;
    fn.params.push_back(6);
    if (n_constante == 0) {
        fn.params.push_back(2);
    } else {
        fn.values[2].is_const = true;
        fn.values[2].const_val = static_cast<uint64_t>(n_constante);
    }

    /* La constante se marca en el VALOR ademas de emitir la instruccion: hay
     * analisis que preguntan por una cosa y analisis que preguntan por la
     * otra, y con solo la instruccion el reconocedor decia que el indice no
     * arranca en cero -- que es exactamente lo que su motivo contesto, y por
     * lo que se tarda diez segundos en verlo en vez de media hora. */
    auto cte = [&](IrValueId dst, uint64_t v) {
        fn.values[dst].is_const = true;
        fn.values[dst].const_val = v;
        IrInstr c = val(IrOp::CONST, dst, IrType::I64);
        c.imm = v;
        return c;
    };

    IrBlock entry;
    entry.id = 0;
    entry.name = "entry";
    entry.instrs.push_back(cte(0, 0));
    entry.instrs.push_back(cte(5, static_cast<uint64_t>(paso)));
    entry.instrs.push_back(cte(8, 0));
    if (n_constante != 0)
        entry.instrs.push_back(cte(2, static_cast<uint64_t>(n_constante)));
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
        // La direccion: base + indice, que es lo que el reconocedor despeja.
        IrInstr adr = val(IrOp::ADD, 7, IrType::PTR);
        adr.operands.push_back(6);
        adr.operands.push_back(1);
        body.instrs.push_back(adr);
        IrInstr st{};
        st.op = IrOp::STORE;
        st.type = IrType::I8;
        st.operands.push_back(8); // el valor
        st.operands.push_back(7); // la direccion
        body.instrs.push_back(st);
        IrInstr add = val(IrOp::ADD, 4, IrType::I64);
        add.operands.push_back(1);
        add.operands.push_back(5);
        body.instrs.push_back(add);
        body.instrs.push_back(br(1));
    }

    IrBlock exit;
    exit.id = 3;
    exit.name = "exit";
    {
        IrInstr r{};
        r.op = IrOp::RET;
        exit.instrs.push_back(r);
    }

    fn.blocks = {entry, header, body, exit};
    fn.blocks[0].succs = {1};
    fn.blocks[1].succs = {2, 3};
    fn.blocks[2].succs = {1};
    fn.blocks[1].preds = {0, 2};
    fn.blocks[2].preds = {1};
    fn.blocks[3].preds = {1};
    return fn;
}

/// El primer motivo de renuncia, o cadena vacia si no hubo ninguna.
std::string primer_motivo(const analysis::BulkMemoryReport &r) {
    if (r.declines.empty()) return "";
    return r.declines.front().code;
}

} // namespace

int main() {
    std::printf("=== test_bulk_memory (asa.bulk_memory) ===\n");

    // -----------------------------------------------------------------
    // 1. Un relleno se reconoce, y con sus numeros
    // -----------------------------------------------------------------
    std::printf("\n[un relleno de longitud FIJA]\n");
    {
        const ir::IrFunction fn = hacer_relleno(/*paso=*/1, /*n=*/32);
        const analysis::BulkMemoryReport r = analysis::analyze_bulk_memory(fn);
        if (r.facts.empty() && !r.declines.empty())
            std::printf("  (motivo: %s)\n", r.declines.front().code);
        CHECK(r.facts.size() == 1, "se reconoce el bucle");
        CHECK(r.declines.empty(), "y no se renuncia a nada");
        if (!r.facts.empty()) {
            CHECK(r.facts[0].clase ==
                      analysis::BulkMemoryFact::Clase::Relleno,
                  "es un RELLENO, no una copia");
            CHECK(r.facts[0].ancho == 1, "de un byte por elemento");

            /* Y el hecho publicado lleva el NUMERO, no el identificador del
             * valor.  Publicar el id como si fuera la cuenta imprimia "1
             * elementos" para un tramo de 32: un numero equivocado, que es
             * peor que no darlo. */
            analysis::asa::FactStore store;
            analysis::asa::Fact f;
            CHECK(analysis::asa::bulk_memory_fact(
                      store, fn, r.facts[0], analysis::asa::kStagePreOpt,
                      analysis::asa::Source::Static, f),
                  "hay hecho que publicar");
            CHECK(std::string(f.what.code) == "bulk.fill",
                  "con la longitud sabida, el codigo es el de siempre");
            CHECK(f.what.a == 32, "y el numero es 32, no el id del valor");
            CHECK(f.what.b == 1, "con el ancho aparte, sin multiplicar");
        }
    }

    // -----------------------------------------------------------------
    // 2. La longitud que solo se sabe al ejecutar se DICE como tal
    // -----------------------------------------------------------------
    std::printf("\n[un relleno de longitud que depende de la ejecucion]\n");
    {
        const ir::IrFunction fn = hacer_relleno(/*paso=*/1, /*n=*/0);
        const analysis::BulkMemoryReport r = analysis::analyze_bulk_memory(fn);
        CHECK(r.facts.size() == 1,
              "se reconoce igual: que la longitud sea un parametro no lo hace "
              "menos un relleno");
        if (!r.facts.empty()) {
            analysis::asa::FactStore store;
            analysis::asa::Fact f;
            CHECK(analysis::asa::bulk_memory_fact(
                      store, fn, r.facts[0], analysis::asa::kStagePreOpt,
                      analysis::asa::Source::Static, f),
                  "hay hecho que publicar");
            CHECK(std::string(f.what.code) == "bulk.fill_runtime",
                  "y sale con OTRO codigo: la longitud no se sabe");
            CHECK(f.what.b == 1, "el ancho si se sabe siempre");
        }
    }

    // -----------------------------------------------------------------
    // 3. Lo que NO se reconoce dice POR QUE
    // -----------------------------------------------------------------
    std::printf("\n[la renuncia lleva su motivo]\n");
    {
        const ir::IrFunction fn = hacer_relleno(/*paso=*/2, /*n=*/32);
        const analysis::BulkMemoryReport r = analysis::analyze_bulk_memory(fn);
        CHECK(r.facts.empty(),
              "de dos en dos el tramo tiene huecos: no es un bloque");
        CHECK(r.declines.size() == 1, "y se cuenta la renuncia");
        CHECK(primer_motivo(r) == "bulk.stride_not_one",
              "diciendo CUAL de las quince condiciones fallo");
    }

    // -----------------------------------------------------------------
    // 4. Una funcion sin bucles no es un silencio
    // -----------------------------------------------------------------
    std::printf("\n[sin bucles no hay ni hecho ni renuncia]\n");
    {
        ir::IrFunction fn;
        fn.name = "pelada";
        IrBlock b0;
        b0.id = 0;
        b0.name = "entry";
        IrInstr r{};
        r.op = IrOp::RET;
        b0.instrs.push_back(r);
        fn.blocks = {b0};
        const analysis::BulkMemoryReport rep = analysis::analyze_bulk_memory(fn);
        CHECK(rep.facts.empty() && rep.declines.empty(),
              "nada que decir, y se distingue de haber mirado y descartado");
    }

    std::printf("\n%s: %d comprobaciones, %d fallos\n",
                g_fail == 0 ? "OK" : "FALLO", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
