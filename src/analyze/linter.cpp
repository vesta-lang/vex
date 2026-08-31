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

/**
 * @brief Un parametro que la funcion no mira.
 *
 * Sale entero del dominio `asa.use_def` -- que dice cuantas veces se usa cada
 * valor -- cruzado con quien de esos valores es un parametro.  El linter no
 * cuenta usos: pregunta.
 *
 * Por que un PARAMETRO y no cualquier valor sin usar: un valor SSA sin usos es
 * lo normal a mitad de una optimizacion y avisarlo seria ruido puro.  Un
 * parametro es otra cosa -- alguien lo escribio y alguien lo pasa en cada
 * llamada --, y que nadie lo lea suele ser una de tres: sobra, se olvido
 * usarlo, o la firma quedo de una version anterior.  Las tres se arreglan, que
 * es la condicion para que un hallazgo valga la pena.
 *
 * NO se avisa de un parametro de SALIDA sin leer: para eso estan y leerlos
 * seria lo raro.
 */
void family_unused_params(const LintInput &in, vx::Diagnostics &diags) {
    for (const ir::IrFunction &fn : in.mod.functions) {
        if (fn.is_native || fn.blocks.empty()) continue;
        /* TODOS los valores sin usar de esta funcion, de una vez.  Con la
         * puerta que devuelve uno solo, tres parametros sin usar en la misma
         * funcion habrian dado un unico aviso. */
        const std::vector<const analysis::asa::Fact *> sin_usar =
            in.facts.find_all("use_def.unused", fn.name.c_str(), in.here);
        if (sin_usar.empty()) continue;
        /* Un parametro que un bloque de `asm` lee ENTRA por una atadura de
         * registro, no por un uso del IR, asi que la cuenta de usos no lo ve.
         * Sin mirar las ataduras, esta familia acusaba a `memset_small_sse2`
         * de no usar su destino -- que es literalmente lo unico que hace --:
         * 34 de 36 hallazgos en un solo fichero.
         *
         * Aqui el asm no es opaco -- se lee y se entiende --, y el dominio
         * `asa.asm` publica ahora por que registro entra y sale cada valor.
         * Pero eso todavia no contesta ESTA pregunta, y conviene decir por que
         * en vez de forzarlo: la atadura habla del HUECO y del valor que el
         * bloque lee, y entre el parametro y ese hueco hay un almacen.  Para
         * unir los dos extremos hace falta seguir la cadena
         * parametro -> almacen -> hueco, que es conocimiento de otro dominio
         * (`asa.memory`, el points-to).
         *
         * Asi que se pregunta lo que SI se puede -- si esta funcion tiene
         * valores atados a un asm -- y con eso se dice que aqui la cuenta de
         * usos no decide.  Es menos de lo que se querria y es lo que se sabe;
         * inventar el enlace daria una respuesta que no se sostiene. */
        const std::vector<const analysis::asa::Fact *> atados =
            in.facts.find_all("asm.binding", fn.name.c_str(), in.here);
        if (!atados.empty()) {
            diags.diag(where_is(in, fn.name), vx::DiagLevel::NOTE, "VXW008",
                       {readable(fn.name)});
            continue;
        }
        for (const ir::IrValueId v : fn.params) {
            if (v >= fn.values.size()) continue;
            const std::string &nombre = fn.values[v].name;
            /* Los sinteticos no son del usuario y no puede quitarlos: el
             * contador oculto de un variadico, el buffer de retorno, el `this`.
             * Avisar de ellos seria pedirle que arregle algo que no escribio.
             */
            if (nombre.empty() || nombre.rfind("%__", 0) == 0 ||
                nombre == "%this")
                continue;
            /* Un guion bajo delante dice "ya lo se, es a proposito".
             *
             * Hace falta porque hay parametros que NO se pueden quitar aunque
             * no se lean: el de una devolucion de llamada cuya firma impone
             * quien la llama.  Sin una forma de decirlo, el hallazgo es cierto
             * y no accionable -- y un aviso que no se puede atender es el que
             * consigue que se apague la familia entera --.
             *
             * Es la convencion de todo el mundo, y por eso no se inventa otra:
             * lo que el usuario ya sabe escribir no hay que ensenarselo. */
            if (nombre.size() > 1 && nombre[0] == '%' && nombre[1] == '_')
                continue;
            bool lo_dice = false;
            for (const analysis::asa::Fact *f : sin_usar)
                if (f->about.id == v) {
                    lo_dice = true;
                    break;
                }
            if (!lo_dice) continue;
            /* Sin el `%`, que es como el IR nombra sus valores y no como el
             * usuario escribio el parametro.  Ensenarselo le pide que busque
             * en su fuente algo que ahi no pone. */
            diags.diag(
                where_is(in, fn.name), vx::DiagLevel::WARN, "VXW006",
                {nombre.substr(nombre[0] == '%' ? 1 : 0), readable(fn.name)});
        }
    }
}

/**
 * @brief Cuanta memoria toca la funcion sin que se pueda saber DoNDE.
 *
 * Del dominio `asa.memory_access`, que apunta con su motivo cada instruccion
 * que toca memoria y no se puede localizar.  Aqui solo se cuenta y se dice.
 *
 * Se agrupa POR FUNCION y no por instruccion, por lo mismo que la frontera
 * opaca: un aviso por instruccion en un programa que manosea punteros son
 * cientos, y un linter asi se apaga entero.  Agrupado dice ademas lo que
 * importa -- cuanto de esta funcion es opaco --, que es el numero con el que se
 * decide si vale la pena mirarla.
 *
 * Y NO es un error: que el compilador no sepa nombrar a donde apunta algo es
 * legitimo -- un puntero que llega de fuera, uno que sale de una cuenta que no
 * se puede seguir --.  Lo que dice el hallazgo es que ahi se pierde
 * conocimiento, y con el las optimizaciones que dependen de saber que no se
 * pisa nada.
 *
 * Un bloque `asm` NO entra en esta lista, y conviene decirlo porque es lo que
 * se esperaria de cualquier otro compilador: aqui el asm se LEE -- la base de
 * instrucciones dice que toca cada una y las ataduras dicen por donde entran y
 * salen los valores --, asi que de la mayoria se sabe perfectamente que memoria
 * mueve.  Si un asm aparece aqui es que falta modelar ESA instruccion, que es
 * un hueco que se cierra, no un limite que se acepta.
 */
void family_opaque_memory(const LintInput &in, vx::Diagnostics &diags) {
    for (const ir::IrFunction &fn : in.mod.functions) {
        if (fn.is_native || fn.blocks.empty()) continue;
        /* Cuantas, no si hay una: el numero es lo que se quiere decir, y es con
         * lo que se decide si merece la pena mirar esta funcion. */
        const size_t opacas = in.facts
                                  .find_all("memory_access.not_localizable",
                                            fn.name.c_str(), in.here)
                                  .size();
        if (opacas == 0) continue;
        diags.diag(where_is(in, fn.name), vx::DiagLevel::WARN, "VXW007",
                   {std::to_string(opacas), readable(fn.name)});
    }
}

/* Lo que consulta cada familia.  Listas nombradas y no literales sueltos para
 * que se lean al lado de su familia y no haya que buscarlas. */
const char *const kNeedsFingerprint[] = {"asa.fingerprint", nullptr};
/* `params.unused` consulta DOS: cuantas veces se usa cada valor, y por que
 * registro lo toma un bloque de asm.  Sin el segundo acusaba a 34 funciones de
 * no usar un parametro que el asm lee -- y la familia declara los dos, asi que
 * pedirla produce los dos y no hay forma de que se quede sin la mitad. */
const char *const kNeedsUseDef[] = {"asa.use_def", "asa.asm", nullptr};
const char *const kNeedsMemoryAccess[] = {"asa.memory_access", nullptr};

void register_builtin_families() {
    /* El NOMBRE es vocabulario estable: es lo que se escribe en `vx.toml` para
     * apagar una familia, asi que va en ingles y no se traduce nunca -- igual
     * que los codigos de los hechos.  Lo que SI se traduce es su descripcion, y
     * por eso viaja como codigo del catalogo y no como frase. */
    register_lint_family("contracts.loose", "VXW910", &family_loose_contracts,
                         kNeedsFingerprint);
    register_lint_family("effects.opaque_boundary", "VXW911",
                         &family_opaque_boundary_cost, kNeedsFingerprint);
    /* Las dos que consumen los dominios de valores y de memoria.  Son la prueba
     * de que el ASA sirve para lo que dice: ninguna de las dos cuenta nada por
     * su cuenta -- preguntan --, y por eso anadirlas no ha costado un
     * analisis. */
    register_lint_family("params.unused", "VXW912", &family_unused_params,
                         kNeedsUseDef);
    register_lint_family("memory.not_localizable", "VXW913",
                         &family_opaque_memory, kNeedsMemoryAccess);
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
                          void (*run)(const LintInput &, vx::Diagnostics &),
                          const char *const *needs) {
    if (name == nullptr || run == nullptr) return;
    for (const LintFamily &f : registry())
        if (std::strcmp(f.name, name) == 0) return; // ya esta
    registry().push_back({name, doc != nullptr ? doc : "", run, needs});
}

std::vector<const char *>
lint_required_domains(const std::vector<std::string> &wanted) {
    ensure_registry();
    std::vector<const char *> r;
    for (const LintFamily &f : registry()) {
        if (!wanted.empty() && std::find(wanted.begin(), wanted.end(),
                                         std::string(f.name)) == wanted.end())
            continue;
        if (f.needs == nullptr) continue;
        for (const char *const *d = f.needs; *d != nullptr; ++d) {
            bool ya = false;
            for (const char *v : r)
                if (v == *d || std::strcmp(v, *d) == 0) {
                    ya = true;
                    break;
                }
            if (!ya) r.push_back(*d);
        }
    }
    return r;
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
