/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/jit/test_rbank_crosscall.cpp
 * @brief Paso 1 del cross-call: crosses_call como CONSTRAINT DURA
 * (AllowedLaneSet), NO como preferencia del Objective.  Un valor vivo a traves
 * de un CALL solo puede colorear en lanes PRESERVED (callee-saved); el coloreo
 * lo consume via lane_admissible SIN saber que significa.  Property: ningun
 * cross-call queda jamas en caller-saved + el coloreo sigue siendo PROPIO.
 */

#include "codegen/rbank/allowed_lanes.h"
#include "codegen/rbank/coloring.h"
#include "codegen/rbank/optimization_context.h"
#include "codegen/rbank/physical_bank.h"
#include "codegen/rbank/smart_spill.h"

#include <cstdio>
#include <random>
#include <vector>

using namespace jit;            // BackendCaps.
using namespace codegen::rbank; // el modelo.

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

static AbstractValue mkval(uint32_t id, uint32_t start, uint32_t end,
                           ResourceClass cls, ViewWidth w,
                           bool crosses_call = false, int fixed = -1,
                           bool must_memory = false) {
    AbstractValue v;
    v.value_id = id;
    v.start = start;
    v.end = end;
    v.req.value_id = id;
    v.req.cls = cls;
    v.req.width = w;
    v.req.crosses_call = crosses_call;
    /* Y `needs_preserved`, que es el campo que de verdad DECIDE.
     *
     * Eran uno solo y se separaron: "cruza una llamada" y "necesita una lane
     * preservada" valen lo mismo salvo en un caso -- el operando de un asm
     * cuyo intervalo es un punto --, y el que mira `lane_admissible` es el
     * segundo.  Este ayudante se quedo poniendo el primero, asi que sus
     * valores decian cruzar una llamada y no pedian nada: siete
     * comprobaciones de seguridad pasaban a no comprobar NADA, y en silencio.
     *
     * Se pone aqui la misma equivalencia que pone el puente de produccion
     * (@c backend_bridge), que es lo que impide que se vuelvan a separar sin
     * que nadie lo note. */
    v.req.needs_preserved = crosses_call;
    v.req.fixed_reg = static_cast<int16_t>(fixed);
    // "debe-memoria": mecanismo unificado (GC root cross-call, force_spill,
    // addr-taken).
    if (must_memory) v.req.residency = Residency::MEMORY;
    return v;
}

/** @brief La lane fisica @p id es callee-saved (PRESERVED) para el ancho @p w?
 */
static bool is_callee_saved(const PhysicalRegisterBank &bank, int id,
                            ViewWidth w) {
    return id != kSpilled && bank.preservation(static_cast<uint8_t>(id), w) ==
                                 SavePolicy::PRESERVED;
}

int main() {
    std::printf("=== test_rbank_crosscall (Paso 1: crosses_call como "
                "Constraint dura) ===\n");

    const BackendCaps caps = [] {
        BackendCaps c{};
        c.sse2 = true;
        return c;
    }();
    PhysicalRegisterBank bank = physical_bank_x86_64(true, caps); // SysV.
    ConstraintSet cs;
    OptimizationContext ctx = make_context(bank, cs);

    // --- lane_admissible: un cross-call solo admite lanes PRESERVED ---
    std::printf("\n[lane_admissible: cross-call -> solo callee-saved]\n");
    {
        // Un GP normal admite MAS lanes que el mismo GP cross-call.
        const ValueRequirements normal =
            mkval(1, 0, 10, ResourceClass::GP, ViewWidth::W8, false).req;
        const ValueRequirements xcall =
            mkval(2, 0, 10, ResourceClass::GP, ViewWidth::W8, true).req;
        size_t n_normal = 0, n_xcall = 0, n_xcall_caller = 0;
        for (const Lane &l : bank.lanes) {
            if (lane_admissible(normal, l, false)) ++n_normal; // version pura.
            if (lane_admissible(xcall, l, false)) {
                ++n_xcall;
                if (l.preservation_of(ViewWidth::W8) != SavePolicy::PRESERVED)
                    ++n_xcall_caller;
            }
        }
        CHECK(n_xcall > 0,
              "cross-call no admite NINGUNA lane (banco sin callee-saved?)");
        CHECK(n_xcall < n_normal,
              "cross-call deberia admitir MENOS lanes que normal");
        CHECK(n_xcall_caller == 0,
              "lane_admissible dejo un cross-call en caller-saved");
        std::printf("  GP normal admite %zu lanes | GP cross-call admite %zu "
                    "(todas callee-saved)\n",
                    n_normal, n_xcall);
    }

    // --- build_allowed_lanes: el AllowedLaneSet materializado ---
    std::printf("\n[build_allowed_lanes: conjunto por valor]\n");
    {
        AbstractProblem p;
        p.values = {mkval(1, 0, 10, ResourceClass::GP, ViewWidth::W8, false),
                    mkval(2, 0, 10, ResourceClass::GP, ViewWidth::W8, true)};
        AllowedLanes al = build_allowed_lanes(p, bank, false);
        const std::vector<uint8_t> &normal = al.lanes_of(1);
        const std::vector<uint8_t> &xcall = al.lanes_of(2);
        CHECK(!xcall.empty(), "AllowedLaneSet de cross-call vacio");
        CHECK(xcall.size() < normal.size(),
              "cross-call deberia tener menos lanes");
        bool all_callee = true;
        for (uint8_t id : xcall)
            if (bank.preservation(id, ViewWidth::W8) != SavePolicy::PRESERVED)
                all_callee = false;
        CHECK(all_callee, "AllowedLaneSet de cross-call incluye caller-saved");
    }

    // --- coloreo: ningun cross-call en caller-saved ---
    std::printf("\n[color_smart_spill / color_linear_scan: cross-call en "
                "callee-saved]\n");
    {
        AbstractProblem p;
        // 3 cross-call GP solapando -> deben ir a callee-saved (o spill), nunca
        // caller.
        p.values = {mkval(1, 0, 30, ResourceClass::GP, ViewWidth::W8, true),
                    mkval(2, 0, 30, ResourceClass::GP, ViewWidth::W8, true),
                    mkval(3, 0, 30, ResourceClass::GP, ViewWidth::W8, true)};
        for (bool smart : {false, true}) {
            LaneAssignment s = smart ? color_smart_spill(p, ctx, false)
                                     : color_linear_scan(p, bank, false);
            CHECK(is_proper_coloring(p, s, bank, false),
                  smart ? "smart: coloreo invalido"
                        : "linear: coloreo invalido");
            uint32_t in_caller = 0;
            for (const AbstractValue &v : p.values) {
                const int lane = s.lane_of(v.value_id);
                if (lane != kSpilled &&
                    !is_callee_saved(bank, lane, ViewWidth::W8))
                    ++in_caller;
            }
            CHECK(in_caller == 0,
                  smart ? "smart puso un cross-call en caller-saved"
                        : "linear puso un cross-call en caller-saved");
        }
    }

    // --- GC root cross-call: DEBE ir a memoria (slot), nunca a registro ---
    std::printf("\n[GC root cross-call -> slot (stackmap), nunca registro]\n");
    {
        // Un handle GC vivo a traves de un CALL no admite NINGUNA lane.
        const ValueRequirements gc_x = mkval(1, 0, 10, ResourceClass::GP,
                                             ViewWidth::W8, /*xcall=*/true, -1,
                                             /*is_gc=*/true)
                                           .req;
        size_t admissible = 0;
        for (const Lane &l : bank.lanes)
            if (lane_admissible(gc_x, l, false)) ++admissible;
        CHECK(admissible == 0,
              "un GC cross-call admitio una lane (deberia spillear)");

        // El coloreo lo derrama aunque haya callee-saved libres.
        AbstractProblem p;
        p.values = {
            mkval(1, 0, 30, ResourceClass::GP, ViewWidth::W8, true, -1, true)};
        for (bool smart : {false, true}) {
            LaneAssignment s = smart ? color_smart_spill(p, ctx, false)
                                     : color_linear_scan(p, bank, false);
            CHECK(s.lane_of(1) == kSpilled,
                  smart ? "smart no derramo el GC cross-call"
                        : "linear no derramo el GC cross-call");
            CHECK(is_proper_coloring(p, s, bank, false), "coloreo GC invalido");
        }
    }

    // --- PROPERTY-BASED: 1000 problemas mixtos, cross-call NUNCA en
    // caller-saved ---
    std::printf("\n[property-based: 1000 problemas, cross-call jamas en "
                "caller-saved]\n");
    {
        std::mt19937 rng(0xC7A11u);
        int proper = 0, xcall_ok = 0, had_xcall = 0;
        const int TRIALS = 1000;
        for (int t = 0; t < TRIALS; ++t) {
            std::uniform_int_distribution<uint32_t> nvals(2, 20);
            std::uniform_int_distribution<uint32_t> pos(0, 20);
            std::uniform_int_distribution<uint32_t> dur(0, 30);
            std::bernoulli_distribution xc(0.5);

            AbstractProblem p;
            const uint32_t n = nvals(rng);
            bool any_xcall = false;
            for (uint32_t i = 0; i < n; ++i) {
                const uint32_t s = pos(rng);
                const bool cc = xc(rng);
                any_xcall |= cc;
                p.values.push_back(mkval(i + 1, s, s + dur(rng),
                                         ResourceClass::GP, ViewWidth::W8, cc));
            }
            if (any_xcall) ++had_xcall;

            LaneAssignment s = color_smart_spill(p, ctx, false);
            if (is_proper_coloring(p, s, bank, false)) ++proper;

            bool ok = true;
            for (const AbstractValue &v : p.values) {
                if (!v.req.crosses_call) continue;
                const int lane = s.lane_of(v.value_id);
                if (lane != kSpilled &&
                    !is_callee_saved(bank, lane, ViewWidth::W8))
                    ok = false;
            }
            if (ok) ++xcall_ok;
        }
        CHECK(proper == TRIALS, "algun coloreo con cross-call fue invalido");
        CHECK(xcall_ok == TRIALS, "algun cross-call quedo en caller-saved");
        CHECK(had_xcall > 0,
              "el generador no produjo cross-calls (test vacio)");
        std::printf("  propio=%d/%d  cross-call-seguro=%d/%d  (con_xcall=%d)\n",
                    proper, TRIALS, xcall_ok, TRIALS, had_xcall);
    }

    std::printf("\n=== %d checks, %d fallos ===\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
