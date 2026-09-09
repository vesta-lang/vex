/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_mem_loc.cpp
 * @brief Tests del modelo de memoria UNICO: alias por rangos de bytes sobre
 *        AbstractLoc (may/must/no) + resolvedor points-to compartido
 *        (raiz + offset const, sound: nunca afirma un offset no probado).
 */
#include "analysis/effects/effects.h"
#include "analysis/effects/ir_effects.h" // traer un efecto al sitio de llamada
#include "analysis/facts/ir_facts.h"
#include "analysis/memory/memory_access.h"
#include "analysis/memory/points_to.h"
#include "ir/ssa_ir.h"

#include <cstdio>

using namespace analysis;
using namespace analysis::effects;
using K = AbstractLoc::Kind;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("FALLO [%s:%d]: %s\n", __FILE__, __LINE__, msg);       \
        }                                                                      \
    } while (0)

static AbstractLoc L(K k, uint32_t id, int64_t off, int32_t w) {
    return AbstractLoc{k, id, off, w};
}

// --------------------------------------------------------------------------
// 1) Alias por rangos: misma raiz, rangos disjuntos = no-alias.
// --------------------------------------------------------------------------
static void test_range_alias() {
    // Mismo slot Stack#5, off 0 w4 vs off 8 w4 -> DISJUNTOS.
    CHECK(no_alias(L(K::Stack, 5, 0, 4), L(K::Stack, 5, 8, 4)),
          "stack#5[0..4) y [8..12) deben ser disjuntos");
    // off 0 w8 vs off 4 w4 -> SOLAPAN.
    CHECK(may_alias(L(K::Stack, 5, 0, 8), L(K::Stack, 5, 4, 4)),
          "stack#5[0..8) y [4..8) deben solapar");
    // Adyacentes exactos [0..4) y [4..8) -> disjuntos.
    CHECK(no_alias(L(K::Stack, 5, 0, 4), L(K::Stack, 5, 4, 4)),
          "adyacentes [0..4) [4..8) disjuntos");
    // width 0 (objeto entero) siempre puede solapar en la misma raiz.
    CHECK(may_alias(L(K::Stack, 5, 0, 0), L(K::Stack, 5, 100, 4)),
          "width 0 = objeto entero -> conservador (solapa)");
}

// --------------------------------------------------------------------------
// 2) Raices/clases distintas = disjuntas; Unknown aliasa todo; None nada.
// --------------------------------------------------------------------------
static void test_class_alias() {
    CHECK(no_alias(L(K::Stack, 5, 0, 4), L(K::Stack, 7, 0, 4)),
          "dos ALLOCA distintos no aliasan");
    CHECK(no_alias(L(K::Stack, 5, 0, 4), L(K::Heap, 5, 0, 4)),
          "stack vs heap disjuntos aunque coincida el id");
    CHECK(may_alias(L(K::Unknown, LOC_GENERIC, 0, 0), L(K::Stack, 5, 0, 4)),
          "Unknown aliasa cualquier cosa");
    CHECK(!may_alias(L(K::None, 0, 0, 0), L(K::Stack, 5, 0, 4)),
          "None (bottom) no aliasa nada");
    // Generico aliasa cualquier sitio de su clase.
    CHECK(may_alias(L(K::Heap, LOC_GENERIC, 0, 0), L(K::Heap, 9, 0, 8)),
          "heap generico aliasa cualquier heap");
}

// --------------------------------------------------------------------------
// 3) must_alias: mismos bytes exactos (raiz+off+width>0).
// --------------------------------------------------------------------------
static void test_must_alias() {
    CHECK(must_alias(L(K::Stack, 5, 8, 4), L(K::Stack, 5, 8, 4)),
          "mismos bytes exactos = must-alias");
    CHECK(!must_alias(L(K::Stack, 5, 8, 4), L(K::Stack, 5, 8, 8)),
          "distinto width no es must-alias");
    CHECK(!must_alias(L(K::Stack, 5, 0, 0), L(K::Stack, 5, 0, 0)),
          "width 0 (objeto entero) no afirma 'mismos bytes'");
    CHECK(!must_alias(L(K::Unknown, LOC_GENERIC, 0, 0),
                      L(K::Unknown, LOC_GENERIC, 0, 0)),
          "Unknown nunca es must-alias");
}

// --------------------------------------------------------------------------
// 3b) Solape DEMOSTRADO: lo que hace falta para ACUSAR, que no es !no_alias.
//
// `may_alias` contesta "no se pudo demostrar que sean disjuntas", y esa
// respuesta esta bien para no optimizar y INVERTIDA para acusar.  Con ella un
// `f(m + 8, m)` sobre una reserva comun -- dos regiones que no se tocan --
// salia como solape probado y tumbaba un programa correcto.
// --------------------------------------------------------------------------
static void test_must_overlap() {
    // Rangos conocidos que se cortan de verdad.
    CHECK(must_overlap(L(K::Heap, 7, 0, 8), L(K::Heap, 7, 4, 8)),
          "[0..8) y [4..12) de la misma reserva se cortan");
    // Rangos conocidos que NO se cortan.
    CHECK(!must_overlap(L(K::Heap, 7, 0, 8), L(K::Heap, 7, 8, 8)),
          "adyacentes no se cortan");
    // El caso que rechazaba un programa correcto: misma raiz, anchos sin
    // conocer, desplazamientos distintos.  may_alias dice que si; demostrado,
    // no hay nada.
    CHECK(may_alias(L(K::Heap, 7, 64, 0), L(K::Heap, 7, 0, 0)),
          "sin anchos, may_alias es conservador y dice que puede");
    CHECK(!must_overlap(L(K::Heap, 7, 64, 0), L(K::Heap, 7, 0, 0)),
          "pero eso NO demuestra el solape: 64 bytes de distancia");
    // Sin anchos, lo unico demostrable es el mismo byte de arranque.
    CHECK(must_overlap(L(K::Heap, 7, 16, 0), L(K::Heap, 7, 16, 0)),
          "misma raiz y mismo desplazamiento: ese byte lo tocan los dos");
    // Uno de cada: el arranque del que no se conoce cae DENTRO del otro.  Es lo
    // que habilita la extension declarada (`i64 p[3]` -> 24 bytes): con ella
    // `f(m + 1, m)` si se ve, y sin ella no.
    CHECK(must_overlap(L(K::Heap, 7, 0, 24), L(K::Heap, 7, 8, 0)),
          "un arranque dentro de un rango conocido: solape demostrado");
    CHECK(must_overlap(L(K::Heap, 7, 8, 0), L(K::Heap, 7, 0, 24)),
          "y da igual el orden de los dos");
    // Pero fuera del rango conocido no se demuestra nada: el desconocido puede
    // acabar antes de llegar.
    CHECK(!must_overlap(L(K::Heap, 7, 0, 24), L(K::Heap, 7, 64, 0)),
          "un arranque FUERA del rango conocido no demuestra solape");
    // Raices y clases distintas no demuestran solape en ningun caso.
    CHECK(!must_overlap(L(K::Heap, 7, 0, 8), L(K::Heap, 9, 0, 8)),
          "dos reservas distintas no se solapan");
    CHECK(!must_overlap(L(K::Heap, 7, 0, 8), L(K::Stack, 7, 0, 8)),
          "clases distintas tampoco");
    // Un parametro: su raiz es un NOMBRE, asi que dos indices distintos no
    // demuestran ni lo uno ni lo otro.
    CHECK(!must_overlap(L(K::ArgDerived, 0, 0, 8), L(K::ArgDerived, 1, 0, 8)),
          "dos posiciones de parametro no demuestran solape");
    // Y TOP, que aliasa todo, no demuestra nada.
    CHECK(!must_overlap(L(K::Unknown, LOC_GENERIC, 0, 0), L(K::Heap, 7, 0, 8)),
          "Unknown puede aliasar todo, y por eso no demuestra nada");
    CHECK(!must_overlap(L(K::None, 0, 0, 0), L(K::None, 0, 0, 0)),
          "bottom no toca ningun byte");
}

// --------------------------------------------------------------------------
// 4) Resolvedor points-to: ALLOCA raiz, ADD const acumula, ADD var = Unknown.
// --------------------------------------------------------------------------
static void test_points_to() {
    ir::IrFunction fn;
    fn.name = "t";
    // valores: 0=alloca, 1=const 8, 2=add(0,1), 3=const var(no-const via load),
    //          4=bitcast(0)
    auto add_val = [&](bool is_const, uint64_t cv) -> ir::IrValueId {
        ir::IrValue v;
        v.is_const = is_const;
        v.const_val = cv;
        fn.values.push_back(v);
        return static_cast<ir::IrValueId>(fn.values.size() - 1);
    };
    ir::IrValueId a = add_val(false, 0); // 0: alloca dst
    ir::IrValueId c8 = add_val(true, 8); // 1: const 8
    ir::IrValueId g = add_val(false, 0); // 2: add dst
    ir::IrValueId b = add_val(false, 0); // 3: bitcast dst

    ir::IrBlock bb;
    bb.id = 0;
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ALLOCA;
        i.dst = a;
        bb.instrs.push_back(i);
    }
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ADD;
        i.dst = g;
        i.operands = {a, c8};
        bb.instrs.push_back(i);
    }
    {
        ir::IrInstr i;
        i.op = ir::IrOp::BITCAST;
        i.dst = b;
        i.operands = {a};
        bb.instrs.push_back(i);
    }
    fn.blocks.push_back(bb);

    IrFacts facts = build_ir_facts(fn);
    PointsTo pt = compute_points_to(fn, facts);

    // alloca -> Stack raiz=a off 0.
    AbstractLoc la = loc_of(pt, a, 4);
    CHECK(la.kind == K::Stack && la.id == a && la.off == 0,
          "alloca resuelve a Stack raiz=self off 0");
    // add(alloca, 8) -> Stack raiz=a off 8.
    AbstractLoc lg = loc_of(pt, g, 4);
    CHECK(lg.kind == K::Stack && lg.id == a && lg.off == 8,
          "add(alloca, const 8) resuelve a Stack raiz=a off 8");
    // bitcast(alloca) -> misma direccion (off 0).
    AbstractLoc lb = loc_of(pt, b, 4);
    CHECK(lb.kind == K::Stack && lb.id == a && lb.off == 0,
          "bitcast(alloca) hereda raiz y off 0");
    // El slot base [0..4) y el offset+8 [8..12) NO aliasan (misma raiz).
    CHECK(no_alias(la, lg), "alloca[0..4) y alloca+8[8..12) disjuntos");
    // bitcast y alloca SI aliasan (misma direccion).
    CHECK(must_alias(la, lb),
          "bitcast(alloca) es la misma direccion (must-alias)");
}

// --------------------------------------------------------------------------
// 5) El efecto de una funcion, traido al sitio donde se la llama.
//
// Una funcion describe lo que toca en terminos de SUS parametros ("escribo
// desde el primero, sesenta y cuatro bytes"), y eso dentro de ella no se puede
// juzgar: el tamano de la region lo sabe quien llama.  Traducirlo al llamante
// es lo que convierte un conocimiento abstracto en memoria concreta -- y lo que
// permite que la misma informacion sirva para comprobar limites, para alias y
// para el optimizador.
// --------------------------------------------------------------------------
static void test_instanciar_en_llamada() {
    // El llamante: reserva un objeto y se lo pasa a alguien.
    ir::IrFunction fn;
    fn.name = "caller";
    const ir::IrBlockId bb = fn.new_block("entry");
    const ir::IrValueId obj = fn.new_value(ir::IrType::PTR);
    {
        ir::IrInstr a{};
        a.op = ir::IrOp::ALLOCA;
        a.type = ir::IrType::I8;
        a.dst = obj;
        a.imm = 64;
        fn.append(bb, std::move(a));
    }
    const IrFacts facts = build_ir_facts(fn);
    const PointsTo pt = compute_points_to(fn, facts);

    // El efecto del llamado: escribe ocho bytes a dieciseis de su parametro 0.
    effects::SemanticEffects callee;
    callee.mem.writes.add(L(K::ArgDerived, 0, 16, 8));
    // Y lee algo global, que sigue siendo global se mire desde donde se mire.
    callee.mem.reads.add(L(K::Global, 7, 0, 4));
    // Y toca su propia pila, que aqui no nombra nada.
    callee.mem.writes.add(L(K::Stack, 3, 0, 8));

    const effects::EfectoEnLlamada inst =
        effects::instanciar_en_llamada(callee, {obj}, pt);

    bool visto_arg = false;
    for (const AbstractLoc &l : inst.escribe.locs) {
        if (l.kind == K::Stack && l.id == obj) {
            visto_arg = true;
            CHECK(l.off == 16,
                  "el desplazamiento del callee se suma al del arg");
            CHECK(l.width == 8, "y el ancho se conserva");
        }
    }
    CHECK(visto_arg, "arg#0 pasa a ser el objeto que se le paso");
    CHECK(!inst.completo,
          "y se dice que la lista NO es completa: la pila del callee no se "
          "puede nombrar aqui");
    CHECK(inst.escribe.locs.size() == 1,
          "lo que no se puede nombrar se deja fuera en vez de absorber el "
          "conjunto entero -- si absorbiera, se perderia lo de arg#0");
    bool visto_global = false;
    for (const AbstractLoc &l : inst.lee.locs)
        if (l.kind == K::Global && l.id == 7) visto_global = true;
    CHECK(visto_global, "lo global no cambia al cruzar la llamada");
}

// --------------------------------------------------------------------------
// Un relleno masivo ESCRIBE memoria, y hay que decirlo.
//
// MEMSET no estaba en el switch y caia en el default, que contesta "no toca
// memoria".  Como el modelo de efectos enruta MEMSET aqui dando por hecho que
// esta modelado, una funcion cuyo unico trabajo era rellenar un buffer del
// llamante -- el bucle `p[i] = 0` que el pase de memoria masiva sube a MEMSET
// -- salia con los contratos `pure` y `readonly`, y con el analisis marcado
// como COMPLETO: no decia "no lo se", afirmaba que no escribe nada.
// --------------------------------------------------------------------------
static void test_memset_escribe() {
    ir::IrFunction fn;
    fn.name = "t_memset";
    auto add_val = [&](bool is_const, uint64_t cv) -> ir::IrValueId {
        ir::IrValue v;
        v.is_const = is_const;
        v.const_val = cv;
        fn.values.push_back(v);
        return static_cast<ir::IrValueId>(fn.values.size() - 1);
    };
    const ir::IrValueId dst = add_val(false, 0);  // destino (un alloca)
    const ir::IrValueId val = add_val(true, 0);   // valor con el que rellena
    const ir::IrValueId len = add_val(true, 256); // bytes

    ir::IrBlock bb;
    bb.id = 0;
    {
        ir::IrInstr i;
        i.op = ir::IrOp::ALLOCA;
        i.dst = dst;
        bb.instrs.push_back(i);
    }
    ir::IrInstr ms{};
    ms.op = ir::IrOp::MEMSET;
    ms.dst = ir::IR_NO_VALUE;
    ms.operands = {dst, val, len};
    bb.instrs.push_back(ms);
    fn.blocks.push_back(bb);

    IrFacts facts = build_ir_facts(fn);
    PointsTo pt = compute_points_to(fn, facts);
    const MemoryAccess a = memory_access(bb.instrs.back(), pt);

    CHECK(a.touches, "un memset TOCA memoria");
    CHECK(a.is_store, "y lo que hace es ESCRIBIR");
    CHECK(!a.is_load, "el valor con el que rellena es un escalar, no una "
                      "lectura de memoria");
    CHECK(a.writes.size() == 1, "escribe en un solo sitio: su destino");
    if (!a.writes.empty())
        CHECK(a.writes[0].kind == K::Stack && a.writes[0].id == dst,
              "y ese sitio es la raiz del destino");

    // Un memset con la forma rota no puede quedarse callado: si no se sabe
    // donde escribe, se dice que escribe en cualquier parte, no que no escribe.
    ir::IrInstr roto{};
    roto.op = ir::IrOp::MEMSET;
    roto.dst = ir::IR_NO_VALUE;
    roto.operands = {dst};
    const MemoryAccess r = memory_access(roto, pt);
    CHECK(r.touches && r.is_store && r.opaque,
          "un memset sin sus tres operandos es opaco, nunca inocuo");
}

int main() {
    test_instanciar_en_llamada();
    test_memset_escribe();
    test_range_alias();
    test_class_alias();
    test_must_alias();
    test_must_overlap();
    test_points_to();
    std::printf("=== mem-loc (modelo unico): %d checks, %d fallos ===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
