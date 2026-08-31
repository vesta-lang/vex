/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analyze/lint_cli.cpp
 * @brief La orden `vesta lint`.
 *
 * Subcomando y no opcion de compilacion, por lo mismo que `fmt`, `pkg` y
 * `vxdbg`: pasar el linter no modifica lo que se compila.  Es una herramienta
 * aparte, con sus argumentos, y mezclarla con las opciones del compilador haria
 * que `--lint` conviviera con `-o`, `--format` o `--emit`, que no significan
 * nada aqui.
 *
 * TODO lo que sale por pantalla viene del catalogo multi-idioma, incluidos los
 * errores del propio subcomando.  Uno que diera los hallazgos traducidos y sus
 * propios errores en espanol seria un subcomando a medias, y la mitad que falta
 * es justo la que se ve cuando algo va mal.
 */

#include "analyze/lint_cli.h"

#include "analysis/asa/producers.h"
#include "analyze/asm_report.h"
#include "analyze/linter.h"
#include "vx/diag/diag_catalog.h"
#include "ir/ssa_ir.h"
#include "ir/ssa_ir_serialize.h"
#include "vx/compiler.h"
#include "vx/source_text.h"

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace analyze {
namespace lint_cli {

namespace {

/// Un mensaje del propio subcomando, en el idioma activo.
void say(std::ostream &os, const char *code,
         const std::vector<std::string> &args = {}) {
    os << vx::diag::format(code, args) << "\n";
}

void usage(std::ostream &os) {
    /* El uso tambien por el catalogo: un subcomando que traduce sus hallazgos y
     * deja su propia ayuda en un solo idioma esta a medias, y la mitad que
     * falta es la que uno lee ANTES de saber usarlo. */
    os << vx::diag::format("VXW903", {}) << "\n\n";
    os << vx::diag::format("VXW904", {}) << "\n";
    for (const LintFamily *f : registered_lint_families()) {
        os << "  " << f->name;
        /* El NOMBRE no se traduce -- es lo que se escribe en `vx.toml` -- pero
         * lo que hace, si. */
        if (f->doc != nullptr && f->doc[0] != '\0')
            os << "\n      " << vx::diag::format(f->doc, {});
        os << "\n";
    }
}

} // namespace

int run(int argc, char **argv) {
    std::string path;
    std::vector<std::string> wanted;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            usage(std::cout);
            return 0;
        }
        if (a == "--only" && i + 1 < argc) {
            wanted.push_back(argv[++i]);
            continue;
        }
        if (!a.empty() && a[0] == '-') {
            usage(std::cerr);
            return 2;
        }
        path = a;
    }
    if (path.empty()) {
        usage(std::cerr);
        return 2;
    }

    std::string source;
    if (!vx::leer_fuente(path, source)) {
        say(std::cerr, "VXW900", {path});
        return 1;
    }

    /* Sobre el codigo que de VERDAD va a existir (post-optimizador), no sobre
     * el escrito: un hallazgo acerca de codigo que el optimizador borra no le
     * sirve a nadie, y una cota que solo se cumple antes de optimizar no es la
     * que el programa tiene. */
    vx::CompileOptions copts;
    copts.module_name = "main";
    copts.opt_level = 2;
    copts.ir_only = true;
    copts.report_bounds = false;
    const bool as_project = vx::vx_source_has_imports(source) ||
                            vx::vx_source_declara_namespace(source);
    vx::CompileResult cr = as_project
                               ? vx::compile_vx_project(path, copts)
                               : vx::compile_vx_source(source, path, copts);
    for (const auto &d : cr.diagnostics.all())
        vx::print_diagnostic(std::cerr, d);
    if (!cr.ok || cr.ir_module_cache_bytes.empty()) {
        say(std::cerr, "VXW901", {path});
        return 1;
    }
    ir::IrModule mod;
    if (!ir::parse_ir_module_cache(cr.ir_module_cache_bytes, mod)) {
        say(std::cerr, "VXW901", {path});
        return 1;
    }

    /* Los dos dominios que viven fuera del nucleo se dan de alta desde aqui,
     * que es quien tiene su maquinaria.  Para eso existe el registro. */
    register_asm_producer();
    register_fingerprint_producer();

    analysis::asa::FactStore facts;
    /* SOLO lo que las familias ENCENDIDAS vayan a consultar.  Producirlo todo
     * se iba a ~544 us por modulo y el 80% eran los rangos, que aqui no los
     * mira nadie.  Ademas la produccion es idempotente y se apoya en la cache
     * en disco, asi que una segunda pasada sobre el mismo modulo no vuelve a
     * calcularlo.
     *
     * La lista la dicen las FAMILIAS, no esto.  Estaba escrita aqui a mano, y
     * en cuanto entro una familia que consultaba otro dominio se quedo sin sus
     * hechos -- y calladamente: una familia sin hechos no falla, no dice nada,
     * que es indistinguible de "aqui no hay nada que decir" --. */
    analysis::asa::produce(mod, facts, analyze::lint_required_domains(wanted));

    /* El alcance va vacio -- universal -- porque los hallazgos de hoy salen de
     * propiedades del codigo y no del objetivo.  El dia que una familia mire
     * algo que dependa del backend, se rellena aqui y los hechos de otro
     * objetivo dejan de verse solos, sin tocar ninguna familia. */
    LintInput in{mod, facts, cr.contracts, {}, path};
    vx::Diagnostics findings;
    const uint32_t n = run_lint(in, findings, wanted);
    for (const auto &d : findings.all())
        vx::print_diagnostic(std::cout, d);
    if (n == 0) say(std::cout, "VXW902");
    /* Cero aunque haya hallazgos: son decisiones para una persona, no fallos.
     * Devolver error haria que un `vesta lint` en un guion de integracion
     * rompiera la construccion por una sugerencia, y entonces lo primero que
     * hace todo el mundo es quitarlo. */
    return 0;
}

} // namespace lint_cli
} // namespace analyze
