/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analyze/linter.cpp
 * @brief El motor del linter y las familias que hoy saben decir algo.
 *
 * El motor NO conoce ninguna familia: recorre las registradas.  Cada familia es
 * una funcion corta que PREGUNTA al almacen y emite hallazgos; ninguna calcula
 * nada.  Es el mismo reparto que en los productores del ASA, y por el mismo
 * motivo: anadir la siguiente no toca el motor.
 */

#include "analyze/linter.h"

#include "ir/ssa_ir.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <sstream>

namespace analyze {

namespace {

/// Vector plano: son pocas y se recorren enteras.  Function-local para no
/// depender del orden de inicializacion estatica entre unidades de traduccion.
std::vector<LintFamily> &registry() {
    static std::vector<LintFamily> r;
    return r;
}

void register_builtin_families();

void ensure_registry() {
    static const bool done = [] {
        register_builtin_families();
        return true;
    }();
    (void)done;
}

/// Donde ensenar un hallazgo de una funcion.
///
/// El IR arrastra la linea de la que salio cada instruccion, asi que la primera
/// que la tenga sirve: un hallazgo sin sitio no se puede pinchar en el editor,
/// y el usuario tendria que buscar a mano la funcion de la que se habla.
vx::SourceLoc where_is(const LintInput &in, const std::string &function) {
    vx::SourceLoc loc;
    /* El fichero, sin el cual la posicion no se puede pinchar en el editor y el
     * hallazgo sale con un `:4:1` que no dice de que fichero habla. */
    loc.file = in.file;
    const ir::IrModule &mod = in.mod;
    for (const ir::IrFunction &fn : mod.functions) {
        if (fn.name != function) continue;
        for (const ir::IrBlock &b : fn.blocks)
            for (const ir::IrInstr &in : b.instrs)
                if (in.source_line > 0) {
                    loc.line = in.source_line;
                    return loc;
                }
        break;
    }
    return loc;
}

/// El nombre tal y como lo escribio el usuario (`Tipo__metodo` ->
/// `Tipo.metodo`).
///
/// Un hallazgo que nombra el simbolo mangled obliga a traducirlo mentalmente, y
/// el usuario no escribio eso en ninguna parte.
std::string readable(const std::string &mangled) {
    const size_t i = mangled.find("__");
    if (i == std::string::npos || i == 0) return mangled;
    return mangled.substr(0, i) + "." + mangled.substr(i + 2);
}

// ===========================================================================
// FAMILIA: contratos MAS DEBILES que lo demostrado
// ===========================================================================
/**
 * @brief Declaraste una cota y el analisis demostro una mejor.
 *
 * Solo se habla de funciones que YA declaran algun contrato: quien escribio uno
 * ha decidido que esta funcion tiene una promesa que mantener, y ahi una cota
 * floja es una promesa mas debil de lo necesario.  Ofrecerselo a TODA funcion
 * que no lance seria ruido -- casi ninguna lanza --, y un linter ruidoso se
 * apaga entero.
 *
 * Es "sugerencia con el valor puesto": no se dice "podrias apretar esto", se
 * dice el numero que el analisis demostro.  El arreglo lo firma el humano
 * porque una cota es una PROMESA hacia fuera, y prometer menos de lo que hoy
 * cumples puede ser deliberado.
 */
void family_loose_contracts(const LintInput &in, vx::Diagnostics &diags) {
    for (const auto &kv : in.contracts) {
        const std::string &fn = kv.first;
        const FunctionContracts &c = kv.second;
        if (!c.any()) continue;
        /* Si ni siquiera se pudo mirar, de esto se encarga la otra familia.  Un
         * hallazgo por funcion: dos avisos sobre lo mismo es ruido. */
        if (in.facts.find("fingerprint.effects_not_visible", fn.c_str(),
                          in.here))
            continue;

        if (c.alloc_total >= 0) {
            const auto q =
                in.facts.find("fingerprint.allocations", fn.c_str(), in.here);
            if (q && q.fact->what.a < c.alloc_total)
                diags.diag(where_is(in, fn), vx::DiagLevel::WARN, "VXW002",
                           {readable(fn), "@alloc",
                            std::to_string(c.alloc_total),
                            std::to_string(q.fact->what.a)});
        }
        if (c.stack_total >= 0) {
            const auto q =
                in.facts.find("fingerprint.stack", fn.c_str(), in.here);
            if (q && q.fact->what.a < c.stack_total)
                diags.diag(where_is(in, fn), vx::DiagLevel::WARN, "VXW002",
                           {readable(fn), "@stack",
                            std::to_string(c.stack_total),
                            std::to_string(q.fact->what.a)});
        }

        /* Y las propiedades que se demostraron y no estan declaradas.  Solo en
         * funciones que ya contratan algo, por lo dicho arriba. */
        if (!c.nothrow &&
            in.facts.find("fingerprint.does_not_throw", fn.c_str(), in.here))
            diags.diag(where_is(in, fn), vx::DiagLevel::WARN, "VXW003",
                       {readable(fn), "@nothrow"});
        if (!c.nopanic &&
            in.facts.find("fingerprint.does_not_panic", fn.c_str(), in.here))
            diags.diag(where_is(in, fn), vx::DiagLevel::WARN, "VXW003",
                       {readable(fn), "@nopanic"});
        if (!c.pure && in.facts.find("fingerprint.pure", fn.c_str(), in.here))
            diags.diag(where_is(in, fn), vx::DiagLevel::WARN, "VXW003",
                       {readable(fn), "@pure"});
    }
}

// ===========================================================================
// FAMILIA: lo que cuesta no declarar
// ===========================================================================
/**
 * @brief Una frontera opaca, y CUANTAS propiedades se quedan sin demostrar.
 *
 * Es la unica familia que puede CUANTIFICAR lo que pierdes, y por eso vale la
 * pena: no dice "declara los efectos" -- eso es un consejo que nadie sigue --,
 * dice que por UNA funcion sin declarar se caen las CINCO propiedades de
 * efectos de esta, y da el nombre de esa funcion.
 *
 * El nombre es lo que lo hace accionable.  Sin el, el usuario sabe que algo no
 * se puede probar y no tiene por donde empezar; el compilador si lo sabe --
 * acaba de decidirlo al componer el cierre de llamadas -- y callarselo seria
 * quedarse la mitad util de la respuesta.
 *
 * Se habla SOLO de funciones que no declaran contratos: si los declaran, el
 * compilador ya avisa de que nadie los comprueba (VXW001), y decir las dos
 * cosas del mismo sitio es ruido.
 */
void family_opaque_boundary_cost(const LintInput &in, vx::Diagnostics &diags) {
    /* UNO POR FRONTERA, NO POR FUNCION AFECTADA.
     *
     * La primera version avisaba en cada funcion con el cierre opaco, y MEDIDO
     * sobre 80 ejemplos salieron 403 avisos en 43 ficheros: la opacidad es la
     * NORMA -- casi todo acaba llamando a la I/O --, no la excepcion.  Un
     * linter asi se apaga entero, y apagado no protege de nada.
     *
     * Agrupado por la CAUSA, la misma informacion se vuelve util y ademas dice
     * mas: no "esta funcion no se puede probar" repetido treinta veces, sino
     * "declara los efectos de ESTA y treinta funciones pasan a poder probar los
     * suyos".  Es la unica familia que puede poner un numero a lo que cuesta no
     * declarar algo, y ese numero solo aparece al agrupar. */
    struct Blocked {
        uint32_t count = 0; ///< funciones que se quedan sin demostrar.
        std::string first;  ///< la primera, para situar el aviso.
    };
    std::map<std::string, Blocked> by_boundary;

    for (const ir::IrFunction &fn : in.mod.functions) {
        if (fn.is_native || fn.blocks.empty()) continue;
        /* Con contrato declarado se encarga el compilador (VXW001): una
         * implementacion, y ese si hace falta en cada construccion. */
        auto c = in.contracts.find(fn.name);
        if (c != in.contracts.end() && c->second.any()) continue;

        const auto q = in.facts.find("fingerprint.effects_not_visible",
                                     fn.name.c_str(), in.here);
        if (!q) continue;
        const std::string why =
            q.fact->what.detail != nullptr ? q.fact->what.detail : "";
        Blocked &b = by_boundary[why];
        if (b.count == 0) b.first = fn.name;
        ++b.count;
    }

    /* NO se filtra ninguna frontera, ni siquiera las de la stdlib.  Estuve a
     * punto de callar esas -- "el usuario no las arregla" -- y era el error de
     * siempre con otra cara: un hecho cierto que no se cuenta porque quien lo
     * lee no puede actuar.  Que la frontera este en nuestra I/O y no en su
     * codigo es INFORMACION, y ademas la mas util de todas: dice que declarar
     * los efectos de la stdlib desbloquea a todo el mundo a la vez. */
    for (const auto &kv : by_boundary) {
        /* Dos codigos, porque se arreglan de forma distinta.  Con nombre, el
         * destino se sabe y esta fuera del programa: no hay nada que leer, y
         * poder declararlo es algo que todavia no existe.  Sin nombre, el
         * destino ni se resuelve, y eso SI puede mejorar con el analisis.
         * Meterlos en un solo mensaje diria a medias las dos cosas. */
        const bool named = !kv.first.empty();
        diags.diag(where_is(in, kv.second.first), vx::DiagLevel::WARN,
                   named ? "VXW004" : "VXW005",
                   {std::to_string(kv.second.count), kv.first,
                    readable(kv.second.first)});
    }
}

void register_builtin_families() {
    /* El NOMBRE es vocabulario estable: es lo que se escribe en `vx.toml` para
     * apagar una familia, asi que va en ingles y no se traduce nunca -- igual
     * que los codigos de los hechos.  Lo que SI se traduce es su descripcion, y
     * por eso viaja como codigo del catalogo y no como frase. */
    register_lint_family("contracts.loose", "VXW910", &family_loose_contracts);
    register_lint_family("effects.opaque_boundary", "VXW911",
                         &family_opaque_boundary_cost);
}

/* NO hay familia "contrato que nadie comprueba", y no es un olvido: eso lo dice
 * el COMPILADOR en cada construccion (VXW001, desde
 * @c analyze::report_contract_checks).  Un contrato decorativo no es una
 * sugerencia que uno pase a pedir de vez en cuando -- es algo que hay que saber
 * siempre --, y ademas repetirlo aqui serian dos implementaciones del mismo
 * criterio, que es justo lo que el ASA existe para impedir.  Una
 * implementacion, tres caras: terminal, LSP y MCP. */

} // namespace

void register_lint_family(const char *name, const char *doc,
                          void (*run)(const LintInput &, vx::Diagnostics &)) {
    if (name == nullptr || run == nullptr) return;
    for (const LintFamily &f : registry())
        if (std::strcmp(f.name, name) == 0) return; // ya esta
    registry().push_back({name, doc != nullptr ? doc : "", run});
}

std::vector<const LintFamily *> registered_lint_families() {
    ensure_registry();
    std::vector<const LintFamily *> v;
    v.reserve(registry().size());
    for (const LintFamily &f : registry())
        v.push_back(&f);
    return v;
}

uint32_t run_lint(const LintInput &in, vx::Diagnostics &diags,
                  const std::vector<std::string> &wanted) {
    ensure_registry();
    const size_t before = diags.all().size();
    /* Una familia no pedida NI SE CORRE.  Con la lista vacia corren todas -- lo
     * que quiere quien pasa el linter entero --; con nombres, solo esas, que es
     * lo que permite apagar una desde `vx.toml` sin tocar codigo. */
    for (const LintFamily &f : registry()) {
        if (!wanted.empty() && std::find(wanted.begin(), wanted.end(),
                                         std::string(f.name)) == wanted.end())
            continue;
        f.run(in, diags);
    }
    return static_cast<uint32_t>(diags.all().size() - before);
}

} // namespace analyze
