/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_manager.cpp
 * @brief Tests del AnalysisManager: computo perezoso + caché, dependencias
 *        auto (invalidacion en cascada, ambos ejes), y PreservedAnalyses via el
 *        gancho `survives` del type-erasure.
 */
#include "analysis/manager/analysis_manager.h"

#include "util/name_pool.h"

#include <cstdio>

using namespace analysis;

static int g_checks = 0, g_fails = 0;
static void check(bool ok, const char *what) {
    ++g_checks;
    if (!ok) {
        ++g_fails;
        std::printf("  FALLO: %s\n", what);
    }
}

// --- Analisis A (hecho base): resultado ResultA.  Sin gancho survives. ---
struct AnalysisA {
    static char ID;
};
char AnalysisA::ID = 0;
struct ResultA {
    int v;
};

// --- Analisis B: depende de A.  ResultB SOBREVIVE si B esta preservado. ---
struct AnalysisB {
    static char ID;
};
char AnalysisB::ID = 0;
struct ResultB {
    int v;
    bool survives(const PreservedAnalyses &p) const {
        return p.preserves_id(&AnalysisB::ID);
    }
};

static int g_a_calls = 0, g_b_calls = 0;

int main() {
    /* La unidad se nombra con el puntero INTERNADO, no con la cadena.
     *
     * El gestor guarda ese puntero como clave: comparar e indexar cuesta lo
     * que un entero, en vez de hashear el nombre manglado de la funcion en
     * cada una de las cuatro consultas por funcion y pasada.  Quien lo llama
     * de verdad usa `IrFunction::name_key()`, que interna una sola vez. */
    const std::string *const f = util::intern_name(std::string("f"));
    const std::string *const g = util::intern_name(std::string("g"));
    {
        AnalysisManager am;
        auto compute_a = [&]() -> ResultA {
            ++g_a_calls;
            return {7};
        };
        auto compute_b = [&]() -> ResultB {
            ++g_b_calls;
            // B lee A -> registra dependencia B->A.
            const ResultA &a =
                am.get_or_compute<AnalysisA, ResultA>(f, compute_a);
            return {a.v + 1};
        };

        // (1) get B computa A y B una vez.
        const ResultB &b = am.get_or_compute<AnalysisB, ResultB>(f, compute_b);
        check(b.v == 8, "B = A+1 = 8");
        check(g_a_calls == 1 && g_b_calls == 1,
              "computo perezoso: A y B una vez");
        check(am.size() == 2, "caché con 2 resultados");

        // (2) segundo get: cache hit, no recomputa.
        am.get_or_compute<AnalysisB, ResultB>(f, compute_b);
        check(g_a_calls == 1 && g_b_calls == 1, "cache hit: no recomputa");

        // (3) invalidar A -> B tambien (dependencia en cascada).
        am.invalidate<AnalysisA>(f);
        check(am.size() == 0, "invalidar A cascada a B (ambos fuera)");

        // (4) recomputar: A y B otra vez.
        am.get_or_compute<AnalysisB, ResultB>(f, compute_b);
        check(g_a_calls == 2 && g_b_calls == 2, "recomputo tras invalidar");
    }

    {
        // PreservedAnalyses: un pase que preserva B mantiene ResultB; A (sin
        // gancho) no sobrevive -> se recomputa.
        AnalysisManager am;
        g_a_calls = g_b_calls = 0;
        auto compute_a = [&]() -> ResultA {
            ++g_a_calls;
            return {1};
        };
        auto compute_b = [&]() -> ResultB {
            ++g_b_calls;
            am.get_or_compute<AnalysisA, ResultA>(g, compute_a);
            return {2};
        };
        am.get_or_compute<AnalysisB, ResultB>(g, compute_b);
        check(am.size() == 2, "2 resultados antes del pase");

        PreservedAnalyses pres;
        pres.preserve<AnalysisB>(); // el pase preservo B, no A
        am.invalidate(g, pres);
        // A no sobrevive -> se quita.  B depende de A -> al invalidar A por
        // cascada, B tambien cae (aunque 'sobreviviera'): la dependencia manda.
        check(!am.cached<AnalysisA>(g), "A no preservado -> invalidado");
        check(!am.cached<AnalysisB>(g),
              "B cae por dependencia de A (aunque survives=true)");

        // Un pase que preserva TODO no invalida nada.
        g_a_calls = g_b_calls = 0;
        am.get_or_compute<AnalysisB, ResultB>(g, compute_b);
        const size_t before = am.size();
        am.invalidate(g, PreservedAnalyses::all());
        check(am.size() == before, "preserve-all no invalida nada");
    }

    std::printf("=== analysis manager: %d checks, %d fallos ===\n", g_checks,
                g_fails);
    return g_fails == 0 ? 0 : 1;
}
