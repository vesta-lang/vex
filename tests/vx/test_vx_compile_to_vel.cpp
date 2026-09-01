/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia VMProject
 *
 * USO LIBRE NO COMERCIAL con atribucion obligatoria.
 * PROHIBIDO lucro sin permiso escrito.
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file test_vx_compile_to_vel.cpp
 * @brief Test del pipeline completo Vesta-lang -> texto .vel (sin tocar la VM).
 *
 * Valida la cadena facade:
 *
 *   .vx source -> Lexer -> Parser -> TypeChecker -> Lowering -> IR emit ->
 * .vel text
 *
 * Las aserciones inspeccionan el texto .vel resultante para confirmar
 * que contiene los anclajes esperados (directivas @Module, @Function,
 * literales numericos, mnemonicos basicos como add/ret/mov/cmp, etc.).
 *
 * No ejecuta el .vel en la VM (eso lo hace test_vx_e2e.cpp via la CLI).
 */

#include "vx/compiler.h"

#include <cassert>
#include <cstdio>
#include <string>

using vx::compile_vx_source;
using vx::CompileOptions;
using vx::CompileResult;

static int g_passed = 0;
static int g_failed = 0;

#define VX_ASSERT(cond, msg)                                                   \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__,      \
                         msg);                                                 \
            ++g_failed;                                                        \
        } else {                                                               \
            ++g_passed;                                                        \
        }                                                                      \
    } while (0)

// Helper: chequear que un string aparece dentro del .vel emitido.
static bool contains(const std::string &haystack, const std::string &needle) {
    return haystack.find(needle) != std::string::npos;
}

static void test_minimal_main_emits_vel() {
    CompileOptions opts;
    opts.module_name = "min";
    opts.opt_level = 1;
    CompileResult r =
        compile_vx_source("i32 main() { return 42; }", "<min>", opts);
    if (!r.ok) {
        std::fprintf(stderr, "Diagnosticos:\n");
        for (auto &d : r.diagnostics.all()) {
            std::fprintf(stderr, "  %s:%u: %s\n", d.loc.file.c_str(),
                         d.loc.line, d.message.c_str());
        }
    }
    VX_ASSERT(r.ok, "compilacion ok");
    VX_ASSERT(!r.vel_text.empty(), ".vel no vacio");
    /* Anclajes minimos del formato .vel emitido por ir_emitter: etiquetas
     * tipo "name:"; NO usa @Function (eso es del .vsh / parser de .vel).
     *
     * NO se exige el prologo `enter` ni el epilogo `leave`, y antes si.  Solo
     * se emiten cuando la funcion tiene derrames que alojar (`spill_count >
     * 0`); una hoja sin marco no los necesita, y este `main` se reduce a
     * `mov r0, 42`.  El test fijaba un DETALLE de la emision -- que el
     * prologo saliera siempre -- en vez de lo que importa, asi que en cuanto
     * el emisor dejo de gastarlo empezo a fallar sobre codigo mejor.
     *
     * Lo que si tiene que estar es que sea una funcion emitida ENTERA: su
     * modulo, su etiqueta, el valor y un terminador. */
    VX_ASSERT(contains(r.vel_text, "@Module"), ".vel contiene @Module");
    VX_ASSERT(contains(r.vel_text, "main:"), ".vel contiene etiqueta main:");
    VX_ASSERT(contains(r.vel_text, "42"), ".vel contiene literal 42");
    VX_ASSERT(contains(r.vel_text, "hlt") || contains(r.vel_text, "ret"),
              ".vel termina la funcion");
}

static void test_factorial_recursive_emits_vel() {
    CompileOptions opts;
    opts.module_name = "fact";
    opts.opt_level = 1;
    const std::string src = R"(
        i64 fact(i64 n) {
            if (n <= 1) return 1;
            return n * fact(n - 1);
        }
        i64 main() { return fact(5); }
    )";
    CompileResult r = compile_vx_source(src, "<fact>", opts);
    if (!r.ok) {
        for (auto &d : r.diagnostics.all()) {
            std::fprintf(stderr, "  %s:%u: %s\n", d.loc.file.c_str(),
                         d.loc.line, d.message.c_str());
        }
    }
    VX_ASSERT(r.ok, "factorial recursivo compila");
    VX_ASSERT(contains(r.vel_text, "fact"), "fact aparece en el .vel");
    VX_ASSERT(contains(r.vel_text, "main"), "main aparece en el .vel");
    // El call a fact desde main debe traducirse en una instruccion call.
    // Aceptamos cualquiera de los mnemonicos posibles del emisor (.vel suele
    // emitir 'callvm' o similar; no fijamos el mnemonico exacto).
    VX_ASSERT(contains(r.vel_text, "call"), ".vel contiene 'call'");
}

static void test_error_propagates() {
    // Programa con error sintactico: el facade debe devolver !ok y cero
    // .vel.  El test verifica que NO se aborta y que los diagnosticos
    // estan disponibles para que el caller los imprima.
    CompileResult r = compile_vx_source("i32 main() { return ; }", "<bad>", {});
    VX_ASSERT(!r.ok, "error sintactico => no ok");
    VX_ASSERT(r.diagnostics.has_errors(), "diagnosticos contienen error");
}

int main() {
    test_minimal_main_emits_vel();
    test_factorial_recursive_emits_vel();
    test_error_propagates();

    std::printf("\n=== test_vx_compile_to_vel: %d pasos OK, %d fallidos ===\n",
                g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
