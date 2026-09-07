/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file analysis/asa/param_contracts_producer.cpp
 * @brief Lo que cada parametro PROMETE de la region a la que apunta -- y, sobre
 *        todo, lo que NO promete.
 *
 * Lo que se afirma es util; lo que FALTA lo es mas.  Sin la marca, dos
 * parametros no se pueden dar por regiones distintas, y de eso depende que una
 * lectura pueda adelantar a una escritura o que una copia campo a campo se
 * reduzca a una operacion de bloque.  Callarlo dejaba al programador sin saber
 * que una palabra suya -- `out`, `in`, `borrow_mut` -- cambia el codigo que
 * sale de su funcion.
 *
 * Por eso este productor dice las dos cosas: la promesa cuando la hay, y cuando
 * no, QUE se pierde y QUE escribir para recuperarlo.  Un consumidor de cara al
 * usuario -- el linter, el editor -- no necesita nada mas.
 */

#include "analysis/asa/fact_base.h"
#include "analysis/asa/producers.h"
#include "ir/ssa_ir.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace analysis {
namespace asa {

namespace {

/**
 * @brief Huella de las ENTRADAS del dominio, sin producir nada.
 *
 * Cubre EXACTAMENTE lo que se mira: el contrato de cada parametro de cada
 * funcion, y cuantos parametros tiene.  Nada mas -- ni el cuerpo, ni los
 * nombres --: cambiar una instruccion no puede cambiar lo que un parametro
 * declara, y meterlo en la huella seria tirar los hechos guardados por algo que
 * no los afecta.
 *
 * @param mod Modulo que se compila.
 * @return La huella; nunca cero, que significa "no se decirlo".
 */
uint64_t param_contracts_inputs(const ir::IrModule &mod) {
    uint64_t h = 0xCBF29CE484222325ull; // FNV-1a de 64
    auto mix = [&h](uint64_t v) {
        h ^= v;
        h *= 0x100000001B3ull;
    };
    for (const ir::IrFunction &fn : mod.functions) {
        for (unsigned char ch : fn.name)
            mix(ch);
        mix(fn.params.size());
        mix(fn.param_contracts.size());
        for (const ir::IrParamContract &c : fn.param_contracts) {
            /* La CUENTA de niveles entra en la huella.  Sin ella, `T*` y
             * `T**` con las mismas promesas en el primer nivel darian la misma
             * huella, y lo cacheado de uno valdria para el otro. */
            mix(c.levels.size());
            for (const ir::IrParamLevel &l : c.levels) {
                mix(l.holds);
                mix(l.denied);
                mix(l.proven);
                mix(l.declared);
                mix(static_cast<uint64_t>(l.extent_bytes));
                mix(l.extent_from_param);
                mix(l.align_bytes);
            }
        }
    }
    return h == 0 ? 1ull : h;
}

/// Nombre estable de cada promesa, el mismo que sale en el volcado del IR.
/// Una sola tabla: dos listas de nombres para el mismo enum acaban diciendo
/// cosas distintas del mismo bit.
const char *claim_code(ir::IrParamClaim c) {
    switch (c) {
    case ir::IrParamClaim::MayRead: return "param.may_read";
    case ir::IrParamClaim::MayWrite: return "param.may_write";
    case ir::IrParamClaim::ExclusiveCall: return "param.exclusive_call";
    case ir::IrParamClaim::ExclusiveRun: return "param.exclusive_run";
    case ir::IrParamClaim::NonNull: return "param.nonnull";
    case ir::IrParamClaim::NoEscape: return "param.no_escape";
    case ir::IrParamClaim::Observable: return "param.observable";
    case ir::IrParamClaim::ImmutableDuringCall: return "param.immutable";
    default: return "param.unknown_claim";
    }
}

/**
 * @brief El NIVEL de indireccion del que habla una promesa cuando nadie dice
 *        otra cosa.
 *
 * No todas hablan de lo mismo: que un puntero no sea nulo o no se escape es del
 * PUNTERO, y que se lea o se escriba es de lo APUNTADO.  El eje estaba ahi
 * antes de nombrarlo -- las frases del catalogo ya decian "no es nula" para una
 * y "lo que apunta" para otra --, solo que sin poder decirse.
 */
uint32_t natural_level(ir::IrParamClaim c) {
    switch (c) {
    case ir::IrParamClaim::NonNull:
    case ir::IrParamClaim::NoEscape: return 0; // del puntero
    default: return 1;                         // de lo apuntado
    }
}

/**
 * @brief El codigo con el que se publica una promesa, segun nivel y polaridad.
 *
 * Va por una sola funcion para que ningun sitio pueda publicar la misma promesa
 * con dos codigos distintos.  Devuelve @c nullptr cuando no hay frase propia
 * para esa combinacion, y entonces el llamante usa la generica -- que dice el
 * nivel y el nombre de la promesa -- en vez de callarse el hecho.
 *
 * @param c      La promesa.
 * @param level  Nivel de indireccion del que habla.
 * @param denied @c true si lo que se afirma es su CONTRARIO.
 * @return El codigo del catalogo, o @c nullptr si no tiene uno propio.
 */
const char *level_claim_code(ir::IrParamClaim c, uint32_t level, bool denied) {
    if (level == natural_level(c)) {
        if (!denied) return claim_code(c);
        switch (c) {
        case ir::IrParamClaim::MayRead: return "param.not_may_read";
        case ir::IrParamClaim::MayWrite: return "param.not_may_write";
        case ir::IrParamClaim::ExclusiveCall:
            return "param.not_exclusive_call";
        case ir::IrParamClaim::ExclusiveRun: return "param.not_exclusive_run";
        case ir::IrParamClaim::NonNull: return "param.ptr.not_nonnull";
        case ir::IrParamClaim::NoEscape: return "param.ptr.not_no_escape";
        case ir::IrParamClaim::Observable: return "param.not_observable";
        case ir::IrParamClaim::ImmutableDuringCall:
            return "param.not_immutable";
        default: return nullptr;
        }
    }
    /* Fuera de su nivel natural solo hay frase para lo que de verdad se escribe
     * en el fuente: `T* const`, que es no reasignar el PUNTERO. */
    if (level == 0 && c == ir::IrParamClaim::MayWrite)
        return denied ? "param.ptr.not_may_write" : "param.ptr.may_write";
    return nullptr;
}

/// Que se sabe de un par de parametros mirando TODOS los sitios de llamada.
enum class PairVerdict {
    Disjoint, ///< en todas las llamadas visibles se demuestra que no coinciden.
    Overlaps, ///< en alguna se demuestra que SI, y esa se puede senyalar.
    Unknown,  ///< en alguna no se pudo decidir, o hay llamadas que no se ven.
};

/**
 * @brief Que se sabe del par de parametros (@p pa, @p pb) mirando las llamadas.
 *
 * La pregunta "estas dos regiones coinciden?" no se responde dentro de la
 * funcion -- ahi sus parametros son dos NOMBRES --, pero en la llamada se ven
 * los ARGUMENTOS, y ahi casi siempre se sabe: dos posiciones de la misma
 * reserva con desplazamientos conocidos, o dos reservas distintas.
 *
 * Pedirle al programador que lo declare sin haber mirado esto es derrotista: se
 * le pide una palabra para algo que el compilador tiene delante.
 *
 * Se miran SIEMPRE, sea la funcion publica o no.  Son dos preguntas distintas y
 * confundirlas tira conocimiento:
 *
 *   "se pisan estos dos ARGUMENTOS en esta llamada?" -> se responde en casi
 *      cualquier funcion, porque el llamante esta delante;
 *   "puedo suponerlo dentro del CUERPO?"             -> eso si exige TODAS las
 *      llamadas, y de una publica no se tienen.
 *
 * Aqui se contesta la primera.  Quien use el veredicto para el cuerpo mira
 * ademas @c is_public; quien lo use para avisar no lo necesita: una llamada que
 * se solapa es un dato del programa, no una limitacion.
 *
 * @param p     Produccion, para pedir el points-to de cada llamante.
 * @param sites Llamadas a esa funcion, del indice.
 * @param pa    Indice del primer parametro.
 * @param pb    Indice del segundo.
 * @param sitio Sale con la linea de la llamada que decide, si la hay.
 * @return El veredicto.
 */
PairVerdict pair_from_call_sites(Production &p,
                                 const std::vector<ModuleWalk::Site> &sites, size_t pa,
                                 size_t pb, uint32_t &sitio) {
    sitio = 0;
    if (sites.empty()) {
        /* Nadie la llama.  No se afirma nada: un hecho sobre codigo que no se
         * usa no ayuda y ensucia el recuento. */
        return PairVerdict::Unknown;
    }
    for (const ModuleWalk::Site &cs : sites) {
        const ir::IrInstr &in = *cs.instr;
        if (pa >= in.operands.size() || pb >= in.operands.size())
            return PairVerdict::Unknown;
        /* El points-to del LLAMANTE.  La base lo cachea por funcion, asi que
         * pedirlo por llamada no lo recalcula. */
        const PointsTo &pt = p.base.memory(*cs.fn);
        const effects::AbstractLoc la = loc_of(pt, in.operands[pa], 0);
        const effects::AbstractLoc lb = loc_of(pt, in.operands[pb], 0);
        /* Una posicion sin raiz concreta no demuestra nada en ninguno de los
         * dos sentidos. */
        if (!la.concrete() || !lb.concrete()) {
            sitio = in.source_line;
            return PairVerdict::Unknown;
        }
        if (effects::may_alias(la, lb)) {
            /* Se solapan de verdad: NO es una limitacion del analisis, es un
             * dato del programa, y es lo que hay que decir en vez de pedir una
             * declaracion. */
            sitio = in.source_line;
            return PairVerdict::Overlaps;
        }
    }
    return PairVerdict::Disjoint;
}

/**
 * @brief Cuenta los parametros que son punteros y no prometen exclusividad.
 * @param fn Funcion.
 * @return Cuantos hay.
 */
size_t undeclared_pointer_params(const ir::IrFunction &fn) {
    size_t n = 0;
    for (size_t i = 0; i < fn.params.size(); ++i) {
        const ir::IrValueId v = fn.params[i];
        if (v >= fn.values.size()) continue;
        if (fn.values[v].type != ir::IrType::PTR) continue;
        /* Habla lo APUNTADO: la exclusividad es sobre la region, no sobre la
         * variable que la senala. */
        if (i < fn.param_contracts.size() &&
            fn.param_contracts[i].pointee().has(ir::IrParamClaim::ExclusiveCall))
            continue;
        ++n;
    }
    return n;
}

/**
 * @brief Publica los parametros que NO se escapan de su funcion.
 *
 * Es la unica promesa del contrato que el compilador puede DEMOSTRAR hoy sin
 * que nadie escriba nada: si un puntero no sobrevive a la llamada, lo dice el
 * punto fijo del escape sobre el grafo de llamadas.
 *
 * Va aqui y no en el IR a proposito.  El contrato del IR es lo que el FUENTE
 * declara; esto es conocimiento DERIVADO, y mezclarlos haria que un hecho
 * demostrado por el compilador quedara indistinguible de una palabra del
 * programador -- que es justo la diferencia que decide si hay que comprobar
 * algo en el sitio de llamada.
 *
 * @param p Produccion en curso.
 */
void say_non_escaping_params(Production &p) {
    const auto &escape_by_fn = p.base.escape(p.mod);
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        auto it = escape_by_fn.find(fn.name);
        if (it == escape_by_fn.end()) continue;
        const auto &escaping = it->second.escaping_params;
        for (size_t i = 0; i < fn.params.size(); ++i) {
            const ir::IrValueId v = fn.params[i];
            if (v >= fn.values.size()) continue;
            if (fn.values[v].type != ir::IrType::PTR) continue;
            Subject about = value_subject(p, fn, v);
            about.id = static_cast<uint32_t>(i);
            if (escaping.count(static_cast<int32_t>(i)) != 0) {
                /* Escapa, y se DICE.  No poder afirmar que no escapa no es lo
                 * mismo que no haber mirado, y el que lee necesita saber cual
                 * de las dos es: aqui hay una respuesta, y es que si.
                 *
                 * Ademas es accionable: un puntero que sobrevive a la llamada
                 * es lo que impide que su reserva viva en la pila y lo que
                 * obliga a mantener viva la region despues de volver. */
                p.say_unknown(about, UnknownReason::NothingToSay,
                              "param.escapes", kProducerParamContracts,
                              p.store.intern(std::to_string(i)),
                              Scope::everywhere());
                continue;
            }
            Fact f;
            f.what.domain = kProducerParamContracts;
            f.what.code = claim_code(ir::IrParamClaim::NoEscape);
            f.what.a = static_cast<int64_t>(i);
            f.about = about;
            /* DEMOSTRADO: el punto fijo se cierra sobre el grafo de llamadas y
             * un callee que no se ve captura TODO, asi que lo que sale como "no
             * escapa" lo ha visto entero. */
            f.seal.certainty = Certainty::Proven;
            f.seal.origin.source = Source::Static;
            f.seal.origin.producer = kProducerParamContracts;
            f.seal.support.add(kProducerEscape);
            f.proof.rule = "param.checked_by_compiler";
            p.assert_fact(f);
        }
    }
}

void produce_param_contracts(Production &p) {
    say_non_escaping_params(p);
    /* Quien llama a quien SALE de la pasada comun, no de una propia: recorrer
     * el modulo aqui otra vez es exactamente lo que se vino a quitar. */
    const auto &calls = p.walk.calls;
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        ++p.summary.looked_at;

        for (size_t i = 0; i < fn.param_contracts.size(); ++i) {
            const ir::IrParamContract &c = fn.param_contracts[i];
            if (c.empty()) continue;
            Subject about = value_subject(p, fn, fn.params[i]);
            about.id = static_cast<uint32_t>(i);

            for (uint32_t lvl = 0; lvl < c.levels.size(); ++lvl) {
                const ir::IrParamLevel &l = c.levels[lvl];
                for (uint32_t k = 0;
                     k < static_cast<uint32_t>(ir::IrParamClaim::COUNT); ++k) {
                    const ir::IrParamClaim cl =
                        static_cast<ir::IrParamClaim>(k);
                    const bool holds = l.has(cl);
                    const bool denied = l.denies(cl);
                    /* Las dos caras se publican, y la que no se sabe NO se
                     * publica.  Callar la negacion la hacia indistinguible de
                     * no haber mirado, que es justo lo que un consumidor
                     * necesita separar para saber si puede quitar una
                     * comprobacion o solo especular. */
                    if (!holds && !denied) continue;
                    /* Los DOS ejes, por separado.  Cuanto me fio y quien lo
                     * dice no son la misma pregunta: el tipo puede derivar algo
                     * que aun no esta demostrado, y el programador puede
                     * declarar algo que si lo esta. */
                    const bool proven =
                        denied ? l.denies_proven(cl) : l.has_proven(cl);
                    const bool by_author = l.is_declared(cl);
                    Fact f;
                    f.what.domain = kProducerParamContracts;
                    const char *code = level_claim_code(cl, lvl, denied);
                    if (code != nullptr) {
                        f.what.code = code;
                        f.what.a = static_cast<int64_t>(lvl);
                        f.what.b = static_cast<int64_t>(i);
                    } else {
                        /* Sin frase propia para esa combinacion se dice el
                         * nivel y el nombre de la promesa.  Se prefiere una
                         * frase generica a no publicar el hecho: lo segundo
                         * seria callar algo que el fuente SI dice. */
                        f.what.code = denied ? "param.denied_at_level"
                                             : "param.claim_at_level";
                        f.what.a = static_cast<int64_t>(lvl);
                        f.what.b = static_cast<int64_t>(i);
                        f.what.detail = p.store.intern(claim_code(cl));
                    }
                    f.about = about;
                    /* La certeza sale del hecho, no de quien lo mire.  Un
                     * `borrow_mut<T>` lo hace cumplir el comprobador de
                     * prestamos: no hay nada que comprobar en ningun sitio de
                     * llamada.  Un `out T*` es un CONTRATO del que llama, asi
                     * que hay que comprobarlo donde se vea la llamada -- y
                     * avisar cuando se incumpla, que es lo que a `restrict` de
                     * C le falta. */
                    f.seal.certainty =
                        proven ? Certainty::Proven : Certainty::Inferred;
                    /* De DONDE sale, que es el eje que separa los dos casos.
                     * Lo declarado lo afirma el programador y se VERIFICA, no
                     * se cree; lo demostrado sale de leer el programa.  Sin
                     * esta distincion, quien tenga que comprobar contratos no
                     * sabria cuales le tocan.
                     *
                     * Sale de SU PROPIO eje, no del de la certeza.  Sacar los
                     * dos del mismo bit publicaba como "declarada por quien
                     * llama" lo que el compilador habia DERIVADO del tipo, y
                     * con eso el verificador de contratos se iba a comprobar en
                     * cada llamada una declaracion que nadie escribio. */
                    f.seal.origin.source =
                        by_author ? Source::Declared : Source::Static;
                    f.seal.origin.producer = kProducerParamContracts;
                    /* Y la REGLA separa los TRES casos, que piden cosas
                     * distintas de quien la lea: comprobarsela al que llama,
                     * fiarse porque la hace cumplir el compilador, o saber que
                     * sale del tipo pero que todavia no la exige nadie. */
                    f.proof.rule = by_author ? "param.declared_by_caller"
                                   : proven  ? "param.checked_by_compiler"
                                             : "param.implied_by_type";
                    p.assert_fact(f);
                }
                /* Y los que son un NUMERO.  Van aparte porque no son promesas
                 * de si/no: un bit no puede llevar un tamano. */
                if (l.extent_bytes >= 0 ||
                    l.extent_from_param != ir::IrParamLevel::kNoParam) {
                    Fact f;
                    f.what.domain = kProducerParamContracts;
                    f.what.code = "param.extent";
                    f.what.a = l.extent_bytes;
                    f.what.b = static_cast<int64_t>(l.extent_from_param);
                    f.about = about;
                    f.seal.certainty = Certainty::Inferred;
                    f.seal.origin.source = Source::Declared;
                    f.seal.origin.producer = kProducerParamContracts;
                    f.proof.rule = "param.declared_by_caller";
                    p.assert_fact(f);
                }
                if (l.align_bytes != 0) {
                    Fact f;
                    f.what.domain = kProducerParamContracts;
                    f.what.code = "param.align";
                    f.what.a = static_cast<int64_t>(l.align_bytes);
                    f.about = about;
                    f.seal.certainty = Certainty::Inferred;
                    f.seal.origin.source = Source::Declared;
                    f.seal.origin.producer = kProducerParamContracts;
                    f.proof.rule = "param.declared_by_caller";
                    p.assert_fact(f);
                }
            }
        }

        /* Y lo que NO se prometio, que es lo que de verdad ayuda a mejorar el
         * codigo.  Con dos o mas punteros sin declarar, el modelo de memoria no
         * puede dar sus regiones por distintas: dentro de esa funcion ninguna
         * lectura adelanta a ninguna escritura, y una copia campo a campo no se
         * reduce a una operacion de bloque.
         *
         * Se dice con UNO tambien: basta que dos parametros no lo declaren los
         * dos para perderlo, asi que el consejo -- "declara la direccion" -- es
         * el mismo y vale igual.  Lo que no se hace es callarlo, que es como
         * estaba: el programador no tenia forma de saber que una palabra suya
         * cambia el codigo que sale. */
        if (undeclared_pointer_params(fn) < 2) continue;

        /* Y ahora se MIRAN LAS LLAMADAS, en vez de pedir una declaracion sin
         * haberlo hecho.  Para cada par de punteros sin declarar hay tres
         * respuestas distintas, y las tres son mas utiles que "declaralo". */
        Subject s;
        s.kind = Subject::Kind::Function;
        s.function = p.store.intern(fn.name);
        /* Sus llamadas, del indice que se armo de una pasada.  Si no la llama
         * nadie, no hay nada que mirar y no se afirma nada. */
        const auto it_sites = calls.find(fn.name);
        if (it_sites == calls.end()) continue;
        const std::vector<ModuleWalk::Site> &sites = it_sites->second;
        for (size_t a = 0; a < fn.params.size(); ++a) {
            for (size_t b = a + 1; b < fn.params.size(); ++b) {
                const ir::IrValueId va = fn.params[a], vb = fn.params[b];
                if (va >= fn.values.size() || vb >= fn.values.size()) continue;
                if (fn.values[va].type != ir::IrType::PTR ||
                    fn.values[vb].type != ir::IrType::PTR)
                    continue;
                uint32_t sitio = 0;
                const PairVerdict v =
                    pair_from_call_sites(p, sites, a, b, sitio);

                if (v == PairVerdict::Overlaps) {
                    /* Un DATO del programa, no una limitacion del analisis: hay
                     * una llamada donde esas dos regiones son la misma.  Se
                     * dice con su linea, que es lo unico accionable -- y ahi
                     * declarar la direccion no arreglaria nada, la haria
                     * MENTIR. */
                    Fact f;
                    f.what.domain = kProducerParamContracts;
                    f.what.code = "param.call_site_overlaps";
                    f.what.a = static_cast<int64_t>(a);
                    f.what.b = static_cast<int64_t>(b);
                    f.about = s;
                    f.seal.origin.site = sitio;
                    f.seal.certainty = Certainty::Proven;
                    f.seal.origin.source = Source::Static;
                    f.seal.origin.producer = kProducerParamContracts;
                    f.proof.rule = "param.seen_at_call_site";
                    p.assert_fact(f);
                    continue;
                }
                if (v == PairVerdict::Disjoint) {
                    /* Todas las llamadas VISIBLES lo demuestran.  Si ademas no
                     * hay otras -- funcion privada --, vale para el cuerpo y no
                     * hace falta que nadie declare nada.  Si es publica, sigue
                     * siendo cierto de lo que se ve, y se dice con ese ambito
                     * en vez de tirarlo. */
                    Fact f;
                    f.what.domain = kProducerParamContracts;
                    f.what.code = fn.is_public
                                      ? "param.disjoint_in_seen_calls"
                                      : "param.disjoint_in_all_calls";
                    f.what.a = static_cast<int64_t>(a);
                    f.what.b = static_cast<int64_t>(b);
                    f.about = s;
                    f.seal.certainty = Certainty::Proven;
                    f.seal.origin.source = Source::Static;
                    f.seal.origin.producer = kProducerParamContracts;
                    f.seal.support.add(kProducerMemory);
                    f.proof.rule = "param.seen_at_call_site";
                    p.assert_fact(f);
                    continue;
                }
                /* No se pudo decidir, y se dice DONDE: sin la linea, "declara
                 * la direccion" es un consejo sobre una funcion entera cuando
                 * el problema esta en una llamada concreta. */
                p.say_unknown(s, UnknownReason::MissingDependency,
                              "param.call_site_undecidable",
                              kProducerParamContracts,
                              p.store.intern(std::to_string(a) + "," +
                                             std::to_string(b)),
                              Scope::everywhere());
            }
        }
    }
}

} // namespace

void register_param_contracts_producer() {
    register_producer(kProducerParamContracts, &produce_param_contracts,
                      &param_contracts_inputs);
}

} // namespace asa
} // namespace analysis
