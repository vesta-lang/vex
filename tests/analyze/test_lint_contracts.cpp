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
 * @file test_lint_contracts.cpp
 * @brief Que ningun veredicto de contrato se descarte en silencio.
 *
 * El verificador tiene TRES veredictos y durante mucho tiempo los tres sitios
 * que lo consumian escribian lo mismo:
 *
 *     if (ck.status != VIOLATED) continue;
 *
 * O sea que el tercero -- "no se puede decidir" -- se tiraba sin decir nada.  Y
 * su forma de fallar es la peor: no da un error, da un contrato que PARECE
 * comprobado porque nadie protesto.  Alguien lee `@nothrow` y construye encima.
 *
 * Esto lo fija.  No comprueba texto -- eso vive en el catalogo y cambia de
 * idioma --: comprueba que cada veredicto produce un diagnostico con SU codigo
 * y SU severidad, que es lo unico que un consumidor decide.
 */

#include "analyze/fingerprint.h"
#include "analyze/linter.h"
#include "vx/diag/diag_catalog.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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

/// Un veredicto suelto, para no repetir la construccion en cada caso.
static analyze::ContractCheck check(const char *fn, const char *contract,
                                    analyze::ContractCheck::Status st) {
    analyze::ContractCheck c;
    c.function = fn;
    c.contract = contract;
    c.status = st;
    c.detail = "efectos desconocidos";
    return c;
}

/// Cuantos diagnosticos con ese codigo hay.
static int count_code(const vx::Diagnostics &d, const char *code) {
    int n = 0;
    for (const auto &x : d.all())
        if (x.code == code) ++n;
    return n;
}

/**
 * @brief Un contrato incumplido es un ERROR, y ademas lleva su codigo.
 */
static void violated_is_an_error() {
    std::printf("-- un contrato incumplido es un error con su codigo\n");
    std::vector<analyze::ContractCheck> checks = {
        check("f", "@nothrow", analyze::ContractCheck::VIOLATED)};
    vx::Diagnostics d;
    const analyze::ContractReport r =
        analyze::report_contract_checks(checks, "a.vx", d);
    CHECK(r.violated == 1, "se cuenta el incumplimiento");
    CHECK(r.unverified == 0, "y no se confunde con lo indecidible");
    CHECK(count_code(d, "VXT004") == 1, "sale por el catalogo, no como prosa");
    bool es_error = false;
    for (const auto &x : d.all())
        if (x.code == "VXT004" && x.level == vx::DiagLevel::ERR)
            es_error = true;
    CHECK(es_error, "y con severidad de error: aborta la construccion");
}

/**
 * @brief EL CASO QUE SE PERDIA: indecidible se dice, y no es un error.
 *
 * Las dos mitades importan.  Que se DIGA, porque callarlo deja un contrato
 * decorativo; y que NO sea un error, porque el programa puede estar perfecto y
 * ser el analisis el que no llega -- convertirlo en error rechazaria programas
 * correctos por una limitacion nuestra.
 */
static void unverifiable_is_not_silent() {
    std::printf("-- un contrato que nadie puede comprobar NO se calla\n");
    std::vector<analyze::ContractCheck> checks = {
        check("f", "@nothrow", analyze::ContractCheck::UNVERIFIABLE)};
    vx::Diagnostics d;
    const analyze::ContractReport r =
        analyze::report_contract_checks(checks, "a.vx", d);
    CHECK(r.unverified == 1, "se cuenta");
    CHECK(r.violated == 0, "y no se cuenta como incumplido");
    CHECK(count_code(d, "VXW001") == 1, "y se DICE: un aviso con su codigo");
    bool es_aviso = false;
    for (const auto &x : d.all())
        if (x.code == "VXW001" && x.level == vx::DiagLevel::WARN)
            es_aviso = true;
    CHECK(es_aviso, "aviso, no error: el programa puede estar bien");
    CHECK(d.error_count() == 0, "y no rompe la construccion");
}

/**
 * @brief Un contrato cumplido no dice nada.
 *
 * No es un descuido: decirlo seria una linea por contrato en cada compilacion,
 * y el sitio donde SI se ensena lo verde es el volcado del ASA.
 */
static void ok_says_nothing() {
    std::printf("-- un contrato cumplido no genera ruido\n");
    std::vector<analyze::ContractCheck> checks = {
        check("f", "@nothrow", analyze::ContractCheck::OK)};
    vx::Diagnostics d;
    const analyze::ContractReport r =
        analyze::report_contract_checks(checks, "a.vx", d);
    CHECK(r.violated == 0 && r.unverified == 0, "no se cuenta en ninguna");
    CHECK(d.all().empty(), "y no emite nada");
}

/**
 * @brief Los tres veredictos a la vez, que es el caso real.
 */
static void the_three_verdicts_together() {
    std::printf("-- los tres veredictos conviven sin pisarse\n");
    std::vector<analyze::ContractCheck> checks = {
        check("a", "@pure", analyze::ContractCheck::OK),
        check("b", "@nothrow", analyze::ContractCheck::VIOLATED),
        check("c", "@alloc", analyze::ContractCheck::UNVERIFIABLE),
        check("d", "@stack", analyze::ContractCheck::UNVERIFIABLE)};
    vx::Diagnostics d;
    const analyze::ContractReport r =
        analyze::report_contract_checks(checks, "a.vx", d);
    CHECK(r.violated == 1, "un incumplido");
    CHECK(r.unverified == 2, "dos sin comprobar");
    CHECK(count_code(d, "VXT004") == 1 && count_code(d, "VXW001") == 2,
          "y cada uno con su codigo");
}

/**
 * @brief El multi-idioma: los codigos existen en los dos idiomas.
 *
 * Un hallazgo es un CODIGO mas sus argumentos, nunca una frase.  Si un codigo
 * no esta en el catalogo, lo que sale por pantalla es el codigo pelado -- que
 * es exactamente lo que pasaba con los contratos, cuyo texto iba incrustado en
 * el compilador y solo existia en espanol.
 */
static void codes_are_in_the_catalog() {
    std::printf("-- los codigos estan en el catalogo, en los dos idiomas\n");
    const char *codigos[] = {"VXT004", "VXW001", "VXW002", "VXW003"};
    const int i_en = vx::diag::language_index("en");
    const int i_es = vx::diag::language_index("es");
    CHECK(i_en >= 0 && i_es >= 0, "el catalogo trae los dos idiomas");
    for (const char *c : codigos) {
        CHECK(vx::diag::has_code(c), "el codigo esta en el catalogo");
        for (int l : {i_en, i_es}) {
            vx::diag::set_language(l);
            const std::string s = vx::diag::format(c, {"f", "@nothrow", "x"});
            CHECK(!s.empty() && s != c, "y tiene texto en ese idioma");
        }
    }
    /* Y que NO son el mismo texto: si el catalogo cayera al idioma por defecto
     * los dos saldrian iguales y la comprobacion de arriba pasaria igual. */
    vx::diag::set_language(i_en);
    const std::string en = vx::diag::format("VXW001", {"f", "@nothrow", "x"});
    vx::diag::set_language(i_es);
    const std::string es = vx::diag::format("VXW001", {"f", "@nothrow", "x"});
    CHECK(en != es, "y cada idioma dice lo suyo, no el mismo texto dos veces");
}

/**
 * @brief Las familias del linter estan dadas de alta.
 */
static void families_are_registered() {
    std::printf("-- las familias del linter se registran\n");
    const std::vector<const analyze::LintFamily *> fams =
        analyze::registered_lint_families();
    CHECK(!fams.empty(), "hay al menos una familia");
    bool has_contracts = false;
    for (const analyze::LintFamily *f : fams) {
        if (std::strcmp(f->name, "contracts.loose") == 0) has_contracts = true;
        /* Y CADA UNA con su descripcion en el catalogo.  El nombre no se
         * traduce -- es lo que se escribe en `vx.toml` --, pero lo que hace si,
         * y una familia sin descripcion sale en la ayuda como un nombre pelado
         * que no dice nada. */
        CHECK(f->doc != nullptr && f->doc[0] != '\0',
              "cada familia dice donde esta su descripcion");
        CHECK(vx::diag::has_code(f->doc),
              "y esa descripcion existe en el catalogo");
    }
    CHECK(has_contracts, "y esta la de contratos mas debiles de lo demostrado");
}

int main() {
    std::printf("=== test_lint_contracts ===\n");
    violated_is_an_error();
    unverifiable_is_not_silent();
    ok_says_nothing();
    the_three_verdicts_together();
    codes_are_in_the_catalog();
    families_are_registered();
    std::printf("=== test_lint_contracts: %d comprobaciones, %d fallidas ===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
