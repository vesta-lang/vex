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
#include <fstream>
#include <set>
#include <map>
#include <sstream>

namespace analyze {

namespace {

/**
 * @brief Cuantas lineas tiene el fichero que se esta mirando, o 0 si no se
 *        pudo leer.
 *
 * Se lee UNA vez y se recuerda: el linter pregunta por cada hallazgo.
 */
size_t lineas_del_fichero(const std::string &ruta) {
    static std::map<std::string, size_t> memo;
    auto it = memo.find(ruta);
    if (it != memo.end()) return it->second;
    size_t n = 0;
    std::ifstream f(ruta);
    if (f.is_open()) {
        std::string l;
        while (std::getline(f, l))
            ++n;
    }
    memo.emplace(ruta, n);
    return n;
}

/**
 * @brief Puede @p linea ser de verdad del fichero que se esta linteando?
 *
 * El modulo que recibe el linter esta FUSIONADO: dentro viene la stdlib y todo
 * lo que se importe.  El intermedio guarda la linea de cada instruccion pero no
 * de QUE FICHERO salio -- lo dice el propio @ref LintInput --, asi que un
 * hallazgo en una funcion de la stdlib se atribuia al fichero del usuario, en
 * una linea de otro sitio.
 *
 * Esto no lo adivina: lo COMPRUEBA.  Si el fichero tiene diez lineas y el
 * hallazgo dice 138, ese hallazgo no es de aqui, y punto.  No cubre el caso de
 * dos ficheros de tamano parecido -- para eso hace falta que el intermedio
 * lleve el fichero de origen --, pero quita el grueso: medido sobre un programa
 * de diez lineas que importa `std.memory`, los 45 avisos que salian apuntaban a
 * las lineas 138 a 1177.  Ni uno existia.
 *
 * @return true si la linea cabe en el fichero, o si no se pudo leer (en la
 *         duda, se dice: callar por no poder comprobarlo seria perder avisos
 *         buenos).
 */
bool cabe_en_el_fichero(const LintInput &in, uint32_t linea) {
    if (linea == 0) return true; // sin linea: se atribuye al fichero entero
    const size_t total = lineas_del_fichero(in.file);
    if (total == 0) return true; // no se pudo leer: no se descarta nada
    return static_cast<size_t>(linea) <= total;
}

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

/**
 * @brief Un bucle cuyo cuerpo NO se ejecuta nunca, o como mucho una vez.
 *
 * Lo dice el dominio de bucles: si las vueltas estan CONTADAS y salen cero, el
 * cuerpo es codigo muerto -- y casi siempre es un error de quien lo escribio,
 * no una intencion: un limite mal puesto, un `<` donde iba `<=`, una constante
 * que quedo por debajo del inicio.  Con una sola vuelta, lo que hay no es un
 * bucle: se lee como si repitiera y no repite.
 *
 * La familia no cuenta NADA por su cuenta: pregunta.  Quien decidio que el
 * bucle esta contado es el analisis de induccion, con los rangos de segunda
 * fuente, y la certeza viene sellada en el hecho -- por eso aqui solo se
 * miran los DEMOSTRADOS: avisar de codigo muerto a partir de una inferencia
 * que pudo pararse por presupuesto seria acusar sin prueba.
 */
void family_dead_loop(const LintInput &in, vx::Diagnostics &diags) {
    /* Se pregunta por ANTES de optimizar, que es lo que el usuario escribio.
     *
     * Mirado despues, el desenrollado convierte `for (i = 0; i < 5; i++)` en
     * una cabecera que da UNA vuelta mas el cuerpo replicado -- cierto del
     * codigo final, y una acusacion falsa contra el codigo fuente --.  El
     * aviso es sobre lo que se escribio; el momento tiene que ser ese. */
    analysis::asa::Scope escrito = in.here;
    escrito.stage = analysis::asa::kStagePreOpt;

    /* Una vez por LINEA.  El inline copia el cuerpo en sus llamantes, asi que
     * un bucle escrito UNA vez se reconoce en dos o tres funciones: avisar por
     * funcion lo repite, y ademas lo senala en `main`, donde el usuario no
     * puso ese bucle y no puede arreglarlo.  La linea viene dentro del hecho.
     */
    std::set<uint32_t> ya_dicho;
    auto donde = [&](const ir::IrFunction &fn, const analysis::asa::Fact *f) {
        vx::SourceLoc loc = where_is(in, fn.name);
        if (f->seal.origin.site > 0) loc.line = f->seal.origin.site;
        return loc;
    };
    for (const ir::IrFunction &fn : in.mod.functions) {
        if (fn.is_native || fn.blocks.empty()) continue;
        for (const analysis::asa::Fact *f :
             in.facts.find_all("loop.trip_count", fn.name.c_str(), escrito)) {
            if (f->seal.certainty != analysis::asa::Certainty::Proven) continue;
            if (f->what.a != 0 && f->what.a != 1) continue;
            const vx::SourceLoc loc = donde(fn, f);
            if (loc.line > 0 && !ya_dicho.insert(loc.line).second) continue;
            if (f->what.a == 0)
                diags.diag(loc, vx::DiagLevel::WARN, "VXW916", {});
            else
                diags.diag(loc, vx::DiagLevel::NOTE, "VXW917", {});
        }
        /* Y el bucle cuya guarda `!=` NO CAE nunca en el limite.
         *
         * `for (i = 0; i != 10; i += 3)` pasa por 0, 3, 6, 9, 12... y nunca
         * vale 10.  El dominio de bucles lo sabe con su propio codigo -- no lo
         * mete en el saco de "forma que no se cubre" justamente para que se
         * pueda avisar --, asi que aqui solo hay que preguntarlo.
         *
         * Cero falsos positivos por construccion: es una forma DEMOSTRADA, no
         * una sospecha.  Lo unico que hay que cuidar es el mensaje, y por eso
         * dice "o no termina, o solo termina tras dar la vuelta al tipo": con
         * un paso impar acaba pasando por el limite despues de 2^64 vueltas.
         * Decir "no termina" a secas seria mas comodo y falso, y quien lo
         * comprobara dejaria de fiarse del resto de los avisos. */
        for (const analysis::asa::Fact *f : in.facts.find_all(
                 "loop.ne_guard_never_lands", fn.name.c_str(), escrito)) {
            const vx::SourceLoc loc = donde(fn, f);
            if (loc.line > 0 && !ya_dicho.insert(loc.line).second) continue;
            diags.diag(loc, vx::DiagLevel::WARN, "VXW920", {});
        }
    }
}

/**
 * @brief Un bucle que es EXACTAMENTE una operacion de bloque escrita larga.
 *
 * El compilador ya lo reduce a `memcpy`/`memset`, asi que esto no es un aviso
 * de rendimiento: es de INTENCION.  `std.memory.fill(p, 0, n)` dice en una
 * linea lo que el bucle dice en cinco, y sobre todo se lo dice a quien lo lea
 * despues -- y a los analisis, que no tienen que redescubrirlo cada vez.  Por
 * eso es una NOTA y no una advertencia: el codigo no esta mal.
 *
 * Solo sobre lo DEMOSTRADO, y no se avisa de los que CASI lo son.  Es
 * tentador -- "esto seria una copia si la base no cambiara dentro" es un
 * consejo util --, pero elegir cuales de los veinticinco motivos son "casi"
 * pide una lista escrita a mano, y ya se vio lo que pasa con esas: el coste
 * llevaba una de dos codigos, el dominio paso a dar veinticuatro, y desde
 * entonces creia entender lo que no entendia.  El motivo ESTA publicado en el
 * almacen para quien lo quiera; lo que no se hace es tapiar aqui una eleccion
 * que envejece sola.
 */
void family_bulk_by_hand(const LintInput &in, vx::Diagnostics &diags) {
    /* Las cuatro formas, que son dos hechos por dos maneras de saber la
     * longitud.  Que la longitud se sepa al compilar o al ejecutar no cambia
     * el consejo: lo que cambia es lo que el compilador puede hacer con el. */
    struct Forma {
        const char *code;
        const char *diag;
    };
    static const Forma kFormas[] = {
        {"bulk.fill", "VXW918"},
        {"bulk.fill_runtime", "VXW918"},
        {"bulk.copy", "VXW919"},
        {"bulk.copy_runtime", "VXW919"},
    };
    /* Se pregunta por el momento de EN MEDIO, y no es un capricho.
     *
     * Que un bucle sea una copia solo se sabe MIENTRAS EL BUCLE EXISTE: el
     * dominio, mirando el codigo ya optimizado, encuentra una instruccion de
     * bloque y ningun bucle que reconocer.  Quien lo afirma es el pase, justo
     * antes de deshacerlo.
     *
     * El consejo, en cambio, no es de una etapa: es sobre lo que el usuario
     * ESCRIBIo.  Que el compilador ya lo reduzca no quita que decirlo en una
     * linea se lo diga tambien a quien lo lea despues. */
    analysis::asa::Scope mientras = in.here;
    mientras.stage = analysis::asa::kStageDuringOpt;

    /* Una vez por LINEA de fuente, no por sitio donde aparezca el bucle.
     *
     * El inline copia el cuerpo de una funcion dentro de sus llamantes, asi
     * que un unico `for` escrito una vez sale reconocido en dos o tres
     * funciones distintas.  El usuario solo puede arreglarlo donde lo
     * escribio; avisarle en `main` de un bucle que el no puso ahi es ruido
     * -- y ruido que crece con lo agresivo que sea el inline, o sea que
     * empeora justo cuando el compilador mejora. */
    std::set<uint32_t> ya_dicho;
    for (const ir::IrFunction &fn : in.mod.functions) {
        if (fn.is_native || fn.blocks.empty()) continue;
        for (const Forma &f : kFormas) {
            for (const analysis::asa::Fact *h :
                 in.facts.find_all(f.code, fn.name.c_str(), mientras)) {
                /* Solo lo demostrado.  Aqui no hay inferencia que valga: se
                 * recorrio el bucle entero y todo lo que hace es mover. */
                if (h->seal.certainty != analysis::asa::Certainty::Proven)
                    continue;
                /* La linea viene DENTRO del hecho, no se busca por el numero
                 * de bloque.
                 *
                 * Un identificador de bloque solo vale dentro de su momento:
                 * este hecho es de mitad de la optimizacion y aqui se tiene el
                 * codigo de despues, ya renumerado.  Mirarlo daba posiciones
                 * de otros sitios -- el aviso apuntaba a lineas donde no hay
                 * ningun bucle --, que es peor que no dar posicion. */
                vx::SourceLoc loc = where_is(in, fn.name);
                if (h->seal.origin.site > 0) loc.line = h->seal.origin.site;
                if (loc.line > 0 && !ya_dicho.insert(loc.line).second) continue;
                /* Sin el nombre de la funcion, por lo mismo que la dedup: tras
                 * el inline, el bucle esta en varias y decir en cual es decir
                 * una al azar.  La posicion no miente. */
                diags.diag(loc, vx::DiagLevel::NOTE, f.diag, {});
            }
        }
    }
}

/**
 * @brief Lo que no cabe en un binario nativo sin runtime, y por que.
 *
 * No calcula nada: el dominio `asa.backend` ya publica, por cada operacion que
 * el objetivo `bare` no puede compilar, la funcion, la linea y el MOTIVO en
 * texto.  Esto solo lo lee y lo dice.
 *
 * El hecho se pregunta con el ambito del NATIVO a proposito.  Es lo que hace
 * que no sea ruido: un consumidor que preguntara desde el interprete no debe
 * encontrarlo, porque ahi la operacion vale.  El eje `backend` del ambito
 * llevaba tiempo en el vocabulario sin que casi nadie lo usara.
 */
void family_native_gap(const LintInput &in, vx::Diagnostics &diags) {
    analysis::asa::Scope en_nativo = in.here;
    en_nativo.backend = analysis::asa::kBackendAot;

    /* Una vez por MOTIVO en todo el fichero, con la primera linea donde
     * aparece.
     *
     * Ni por operacion ni por linea: la decision que el usuario toma es UNA
     * por motivo -- "me importa que esto no vaya a nativo sin runtime?" --, y
     * no cambia porque el motivo aparezca en veinte sitios.  Medido sobre
     * `107_unique_lifo_move_chain.vx`: 40 avisos en 21 lineas, y solo TRES
     * motivos distintos.  Repetirlo veinte veces no anade nada y tapa los
     * otros dos.
     *
     * Tampoco por funcion, porque tras el inline la misma operacion aparece en
     * varias: decir en cual es decir una de las copias. */
    std::set<std::string> ya_dicho;
    for (const ir::IrFunction &fn : in.mod.functions) {
        if (fn.is_native || fn.blocks.empty()) continue;
        for (const analysis::asa::Fact *h : in.facts.find_all(
                 "backend.unsupported_op", fn.name.c_str(), en_nativo)) {
            if (h->seal.certainty != analysis::asa::Certainty::Proven) continue;
            const char *motivo = h->what.detail;
            if (motivo == nullptr || *motivo == '\0') continue;
            /* Que el hallazgo sea de ESTE fichero.
             *
             * El modulo viene fusionado con la stdlib, y el intermedio no
             * guarda de que fichero salio cada funcion -- lo dice el propio
             * `LintInput` --, asi que un hallazgo en `std.memory` se atribuia
             * al fichero del usuario en una linea de otro sitio.  Medido sobre
             * un programa de DIEZ lineas que importa `std.memory`: los avisos
             * apuntaban a las lineas 138 a 1177.  Ni uno existia. */
            if (!cabe_en_el_fichero(in, h->seal.origin.site)) continue;
            vx::SourceLoc loc = where_is(in, fn.name);
            if (h->seal.origin.site > 0) loc.line = h->seal.origin.site;
            if (!ya_dicho.insert(motivo).second) continue;
            diags.diag(loc, vx::DiagLevel::WARN, "VXW924", {motivo});
        }
    }
}

/**
 * @brief Los bytes de una vista `@overlay` que no describe ningun campo.
 *
 * Un hueco NO es un fallo: `261_overlay_basics` declara `e_magic @0x00` y
 * `e_lfanew @0x3C` y se salta los 58 bytes de en medio A PROPOSITO -- describir
 * la cabecera entera no hace falta para leer los dos campos que importan --.
 * Por eso no es un aviso del compilador sino una familia del linter, que se
 * pide cuando uno quiere saberlo: al escribir una vista de una cabecera de
 * tamano fijo que SI se quiere cubrir del todo, o al revisar una que crecio a
 * trozos.
 *
 * No cuenta nada por su cuenta: el tramo de cada campo lo resolvio el frontend
 * -- que es el unico con la expresion del offset delante -- y lo publica el
 * dominio `asa.overlays`.  Aqui solo se restan del extent los tramos cubiertos.
 *
 * Solo entran los tramos del marco CONSTANTE (`overlay.covers`).  Uno que
 * cuelga de un simbolo cae donde digan los datos, asi que no tapa un hueco
 * concreto: contarlo como cobertura convertiria el hallazgo en una suposicion,
 * que es lo contrario de para lo que existe.
 */
void family_overlay_gaps(const LintInput &in, vx::Diagnostics &diags) {
    /* QUE vistas hay se pregunta, no se recorre el modulo.  Escrito al reves
     * -- iterando `in.mod.overlays` y consultando los hechos por cada una -- la
     * familia se quedaba MUDA en cuanto el modulo que el linter recibe no
     * llevara las vistas dentro, aunque los hechos estuvieran todos ahi: el
     * volcado del ASA los listaba y la familia no decia nada.  Una familia que
     * no encuentra nada no falla, y eso es indistinguible de "aqui no hay nada
     * que decir", que es la forma en que esto se queda roto en silencio. */
    for (const analysis::asa::Fact *huella :
         in.facts.find_all("overlay.extent", nullptr, in.here)) {
        const std::string vista =
            huella->about.function ? huella->about.function : "";
        if (vista.empty()) continue;
        /* Como el usuario la escribio.  El nombre viaja aplanado con el
         * namespace delante (`ejemplos__formato__Thunk`), y eso no lo escribio
         * nadie: `readable` no sirve porque solo deshace el PRIMER `__` -- vale
         * para `Tipo__metodo`, no para una ruta de namespace de tres tramos. */
        std::string nombre = vista;
        for (size_t k = nombre.find("__"); k != std::string::npos;
             k = nombre.find("__", k + 1))
            nombre.replace(k, 2, ".");
        const int64_t extent = huella->what.a;
        if (extent <= 0) continue;
        /* La posicion sale del hecho: una vista no es una funcion y no se puede
         * localizar recorriendo el codigo. */
        vx::SourceLoc loc;
        loc.file = in.file;
        loc.line = huella->seal.origin.site;
        if (!cabe_en_el_fichero(in, loc.line)) continue;

        /* Los bytes cubiertos, marcados uno a uno.  La huella de una vista son
         * decenas o pocos cientos de bytes -- una cabecera --, asi que un mapa
         * de bits plano es mas simple y mas rapido que ordenar tramos, y no hay
         * que tratar el solape como un caso aparte. */
        std::vector<bool> cubierto(static_cast<size_t>(extent), false);
        for (const analysis::asa::Fact *f :
             in.facts.find_all("overlay.covers", vista.c_str(), in.here)) {
            for (int64_t b = f->what.a; b < f->what.b && b < extent; ++b)
                if (b >= 0) cubierto[static_cast<size_t>(b)] = true;
        }

        /* Un hallazgo por TRAMO seguido y no por byte: lo que el usuario mira
         * es "de aqui a aqui no hay nada", y 58 avisos de un byte serian
         * exactamente el ruido que hace que se apague la familia. */
        size_t i = 0;
        while (i < cubierto.size()) {
            if (cubierto[i]) {
                ++i;
                continue;
            }
            const size_t ini = i;
            while (i < cubierto.size() && !cubierto[i]) ++i;
            char desde[24], hasta[24];
            std::snprintf(desde, sizeof(desde), "0x%02llX",
                          static_cast<unsigned long long>(ini));
            std::snprintf(hasta, sizeof(hasta), "0x%02llX",
                          static_cast<unsigned long long>(i - 1));
            diags.diag(loc, vx::DiagLevel::NOTE, "VXW926",
                       {nombre, std::to_string(i - ini), desde, hasta});
        }
    }
}

/* Lo que consulta cada familia.  Listas nombradas y no literales sueltos para
 * que se lean al lado de su familia y no haya que buscarlas. */
const char *const kNeedsFingerprint[] = {"asa.fingerprint", nullptr};
/* `loops.dead` consulta el dominio de bucles, que es quien sabe cuantas
 * vueltas da cada uno.  Uno solo: no pide los rangos aparte porque el
 * productor de bucles ya los consulta al armar su hecho. */
const char *const kNeedsLoops[] = {"asa.loops", nullptr};
/* `params.unused` consulta DOS: cuantas veces se usa cada valor, y por que
 * registro lo toma un bloque de asm.  Sin el segundo acusaba a 34 funciones de
 * no usar un parametro que el asm lee -- y la familia declara los dos, asi que
 * pedirla produce los dos y no hay forma de que se quede sin la mitad. */
const char *const kNeedsUseDef[] = {"asa.use_def", "asa.asm", nullptr};
const char *const kNeedsMemoryAccess[] = {"asa.memory_access", nullptr};

/* `memory.bulk_by_hand` consulta el dominio que reconoce las operaciones de
 * bloque.  Uno solo: ese productor ya pide por su cuenta la forma del bucle y
 * los efectos de memoria al armar su hecho. */
const char *const kNeedsBulkMemory[] = {"asa.bulk_memory", nullptr};
const char *const kNeedsBackend[] = {"asa.backend", nullptr};
/* `overlays.gaps` consulta el dominio de las vistas.  Uno solo: el tramo de
 * cada campo ya viene resuelto del frontend, asi que ese productor no depende
 * de ningun otro. */
const char *const kNeedsOverlays[] = {"asa.overlays", nullptr};

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
    /* Y la del dominio de bucles.  Igual que las dos de arriba: no cuenta
     * vueltas -- las pregunta --, asi que anadirla no ha costado un analisis
     * nuevo, que es exactamente lo que el ASA promete. */
    register_lint_family("loops.dead", "VXW914", &family_dead_loop,
                         kNeedsLoops);
    /* Y la del dominio que reconoce las operaciones de bloque, que hasta ahora
     * no llegaba al almacen: lo sabia solo el pase que las reduce, asi que ni
     * se veia ni se podia preguntar.  Registrar el dominio ha bastado para que
     * esta familia sea seis lineas. */
    register_lint_family("memory.bulk_by_hand", "VXW918", &family_bulk_by_hand,
                         kNeedsBulkMemory);
    /* Lo que no cabe en un binario nativo.  El analisis existia y lo leia un
     * solo consumidor, el editor: el mismo codigo tenia respuesta en el IDE y
     * ninguna al pasar el linter. */
    register_lint_family("modes.native_gap", "VXW924", &family_native_gap,
                         kNeedsBackend);
    /* Y los bytes que una vista `@overlay` no describe.  No es un aviso del
     * compilador porque el hueco es legitimo -- describir solo los dos campos
     * que importan es el uso normal de la feature --, pero es justo lo que uno
     * quiere preguntar al cubrir una cabecera entera. */
    register_lint_family("overlays.gaps", "VXW926", &family_overlay_gaps,
                         kNeedsOverlays, /*on_demand=*/true);
}

/* NO hay familia "contrato que nadie comprueba", y no es un olvido: eso lo dice
 * el COMPILADOR en cada construccion (VXW001, desde
 * @c analyze::report_contract_checks).  Un contrato decorativo no es una
 * sugerencia que uno pase a pedir de vez en cuando -- es algo que hay que saber
 * siempre --, y ademas repetirlo aqui serian dos implementaciones del mismo
 * criterio, que es justo lo que el ASA existe para impedir.  Una
 * implementacion, tres caras: terminal, LSP y MCP. */

/* Tampoco hay familia "la cuenta se sale del tipo", por la MISMA razon: eso lo
 * dice el COMPILADOR y es un ERROR (VX2050, desde
 * @c analyze::find_int_wraparounds sobre el intermedio de antes de optimizar).
 * Envolver sin querer no da un fallo, da otro numero, asi que no es una
 * sugerencia que uno pase a pedir de vez en cuando: para que no sea error se
 * escribe un cast al tipo, igual que para cualquier otra conversion que pierde
 * informacion.  Hubo aqui una familia haciendolo, y estuvo mal: eran dos
 * implementaciones del mismo criterio. */

} // namespace

void register_lint_family(const char *name, const char *doc,
                          void (*run)(const LintInput &, vx::Diagnostics &),
                          const char *const *needs, bool on_demand) {
    if (name == nullptr || run == nullptr) return;
    for (const LintFamily &f : registry())
        if (std::strcmp(f.name, name) == 0) return; // ya esta
    registry().push_back(
        {name, doc != nullptr ? doc : "", run, needs, on_demand});
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
        const bool pedida =
            !wanted.empty() && std::find(wanted.begin(), wanted.end(),
                                         std::string(f.name)) != wanted.end();
        if (!wanted.empty() && !pedida) continue;
        /* Y la que solo habla cuando se le pregunta no entra en la pasada
         * entera: lo que dice es legitimo, asi que decirlo siempre seria ruido
         * en el caso comun. */
        if (f.on_demand && !pedida) continue;
        f.run(in, diags);
    }
    return static_cast<uint32_t>(diags.all().size() - before);
}

} // namespace analyze
