/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/producers.cpp
 * @brief El motor de produccion y los dominios que hoy saben afirmar.
 *
 * El motor NO conoce ningun dominio: recorre los registrados.  Cada dominio es
 * una funcion corta que traduce SU analisis a hechos, y ahi -- no en quien
 * luego los mire -- vive el criterio de que merece afirmarse.
 */

#include "util/env_flags.h"
#include "util/fnv.h" // la mezcla del proyecto, no otra escrita aqui
#include "analysis/asa/producers.h"

#include "ir/ssa_ir.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>
#include "analysis/asa/observed.h" // el hecho de bucle, armado en UN sitio
#include "aot/aot_analyze.h" // que operaciones existen en el objetivo nativo
#include "analysis/facts/alignment.h"
/* La forma de un bucle, su variable de induccion y cuantas vueltas da: lo que
 * hace falta para que el dominio de bucles diga algo mas que "aqui hay uno". */
#include "analysis/facts/loop_iv.h"
#include "analysis/facts/loop_structure.h"
#include "analysis/facts/loop_trip_count.h"
#include "vx/diag/diag_catalog.h" // el texto del aviso, en todos los idiomas
#include "vx/asm/asm_cfg.h"
#include "vx/asm/asm_effects.h" // isa_actual

namespace analysis {
namespace asa {

// ===========================================================================
// Contexto de produccion
// ===========================================================================

bool Production::is_interesting(const ir::IrFunction &fn) const {
    /* Un stub de funcion nativa no tiene cuerpo del que sacar nada.  No hay mas
     * criterio: el volcado es entero, sin variantes que combinar. */
    if (fn.is_native) {
        /* Y se CUENTA.  Descartar en silencio deja un resumen que no cuadra:
         * quien lo lea no puede saber si el dominio vio el modulo entero o se
         * salto media docena de funciones.  Ningun sitio se calla. */
        ++summary.skipped;
        return false;
    }
    /* Y lo que YA vino del disco para ESTA funcion, en ESTE dominio y ESTE
     * momento, tampoco hay que mirarlo: producirlo otra vez daria las mismas
     * afirmaciones por duplicado.
     *
     * Aqui es donde se cobra la granularidad por funcion.  El fichero de hechos
     * valida funcion a funcion y trae lo que sigue valiendo sin marcar el
     * dominio; el productor recorre el modulo entero como siempre -- no se
     * entera de nada -- y este unico punto le salta lo que ya esta.  Sin esto
     * la cache era todo-o-nada: o se tiraba el dominio entero porque una
     * funcion cambio, o se duplicaba lo cargado.
     *
     * Cuando no hubo carga parcial -- el caso normal -- esto se responde sin
     * tocar ninguna tabla: el almacen no tiene nada marcado. */
    if (store.has_function(summary.domain, stage, fn.name.c_str())) {
        ++summary.reused;
        return false;
    }
    return true;
}

FactId Production::assert_fact(Fact f) {
    ++summary.looked_at;
    ++summary.facts;
    /* El MOMENTO se sella aqui, no en cada productor.  Un productor habla del
     * codigo que le dan y no tiene por que saber en que punto del pipeline se
     * lo dieron; y si tuviera que ponerlo el, bastaria que uno se olvidara
     * para que su hecho valiera en TODOS los momentos, incluido aquel en el
     * que es falso.  Se respeta el que ya venga puesto: un productor puede
     * saber que lo suyo no cambia al optimizar. */
    if (f.scope.stage == nullptr || f.scope.stage[0] == '\0')
        f.scope.stage = stage;
    return store.add(std::move(f));
}

void Production::say_unknown(Subject about, UnknownReason reason,
                             const char *code, const char *domain,
                             const char *detail, Scope scope, Anchor site) {
    ++summary.looked_at;
    ++summary.silent;
    /* El motivo SIEMPRE, aunque no se pidan los hechos uno a uno: un dominio
     * que no supo algo tiene que decir por que, o su silencio no se puede
     * arreglar. Son pocos codigos por dominio -- un vector plano se recorre
     * antes de lo que un mapa calcula el hash. */
    bool counted = false;
    for (UnknownEntry &m : summary.reasons) {
        if (m.code == code || std::strcmp(m.code, code) == 0) {
            ++m.times;
            counted = true;
            break;
        }
    }
    if (!counted) summary.reasons.push_back({code, reason, 1});
    /* "De esto no se sabe nada" ES un hecho -- con certeza Unknown --, no la
     * ausencia de uno: distingue lo que se miro y no dio nada de lo que ni
     * siquiera se miro, y esa diferencia es la que dice donde ampliar. */
    Fact f;
    f.what.domain = domain;
    f.what.code = code;
    f.what.detail = store.intern(detail);
    f.about = about;
    f.seal.certainty = Certainty::Unknown;
    f.seal.unknown_reason = reason;
    f.seal.origin.producer = domain;
    f.seal.origin.function = about.function;
    f.seal.origin.site = site;
    /* DONDE vale el no-saber, tal y como lo dijo quien no supo.  Un hueco puede
     * existir solo en un modo -- no modelar el puntero al proceso no le dice
     * nada a quien compila a nativo, donde ese puntero no existe --, y hasta
     * ahora todos salian universales. */
    f.scope = scope;
    /* Y el momento, que lo pone el motor: un productor habla del codigo que le
     * dan y no tiene por que saber en que punto del pipeline se lo dieron.
     * Se respeta el que venga puesto, igual que en `assert_fact`. */
    if (f.scope.stage == nullptr || f.scope.stage[0] == '\0')
        f.scope.stage = stage;
    store.add(std::move(f));
}

// ===========================================================================
// Registro
// ===========================================================================
namespace {

struct RegisteredDomain {
    const char *name;
    Producer producer;
    /// De que depende, para poder validar lo guardado SIN producir.  Nulo = no
    /// sabe decirlo, y entonces lo suyo no se puede comprobar.
    DomainFingerprint fingerprint = nullptr;
    /// Lo que MIRA, declarado.  @c None con @c fingerprint nulo es el estado
    /// que hay que erradicar: ni sabe decirlo ni se puede comprobar.
    DomainInput inputs = DomainInput::None;
};

/**
 * @brief Las huellas de las entradas del modulo, calculadas UNA vez.
 *
 * Se calculan todas de golpe y cada dominio pliega las suyas.  Al reves --
 * que cada uno calcule lo que mira -- serian tantos recorridos del modulo como
 * dominios, que es justo lo que @c ModuleWalk existe para no hacer.
 */
struct ModuleInputs {
    /// Plegado de las de TODAS las funciones.  Sirve mientras la validacion sea
    /// por dominio; con granularidad por funcion se usa la de cada una.
    uint64_t function_code = 0;
    uint64_t param_contracts = 0;
    uint64_t static_data = 0;
    uint64_t globals = 0;
    /**
     * @brief El codigo de las funciones SIN NOMBRE, plegado.
     *
     * Va con las entradas del MoDULO y no con las de cada funcion porque no hay
     * forma de referenciarlas: la tabla del fichero indexa por hash del nombre,
     * asi que una funcion anonima no puede tener su propia entrada.  Sin esto
     * quedaria fuera de TODAS las claves por funcion -- y como la validacion
     * granular se salta la huella de dominio cuando hay tabla, un cambio
     * encerrado en una anonima no lo veria nadie.
     *
     * Es la misma solucion que para los datos estaticos: lo que no se puede
     * repartir se le cobra a todos.
     */
    uint64_t unnamed_code = 0;
};

/// @brief Las entradas de UNA funcion.  Lo mismo, sin plegar.
struct FunctionInputs {
    uint64_t function_code = 0;
    uint64_t param_contracts = 0;
};

/**
 * @brief Dice, UNA vez, que llego una funcion del intermedio sin nombre.
 *
 * Una vez por proceso y no por funcion: el aviso es sobre una via de
 * construccion que se salta el nombre, no sobre cada caso, y repetirlo por
 * funcion en un modulo grande taparia lo que si dice algo.
 *
 * Aviso y no aborto a proposito: la compilacion es correcta -- el codigo de esa
 * funcion se le cobra a todas --, lo que se pierde es granularidad de cache.
 * Matar el compilador por eso seria desproporcionado; callarlo, lo de siempre.
 */
void warn_unnamed_function() {
    static bool said = false;
    if (said) return;
    said = true;
    const std::string msg =
        vx::diag::format("VXA072", vx::diag::current_language(), {});
    std::fprintf(stderr, "%s\n", msg.c_str());
}

/// @brief La huella de los CONTRATOS de una funcion.
///
/// Aparte de @c function_code_key a proposito: aquella no los cubre -- hashea
/// instrucciones, valores y parametros, no lo que los parametros PROMETEN --,
/// asi que cambiar un `in` por un `out` no la movería.  Meterlos dentro habria
/// invalidado la cache de rangos, que hoy es correcta, por un cambio que a los
/// rangos no les afecta.
uint64_t param_contracts_key(const ir::IrFunction &fn) {
    uint64_t h = util::kFnvOffset;
    for (const ir::IrParamContract &pc : fn.param_contracts) {
        for (const ir::IrParamLevel &lv : pc.levels) {
            h = util::fnv_mix(h, lv.holds);
            h = util::fnv_mix(h, lv.denied);
            h = util::fnv_mix(h, lv.proven);
            h = util::fnv_mix(h, lv.declared);
            h = util::fnv_mix(h, static_cast<uint64_t>(lv.extent_bytes));
            h = util::fnv_mix(h, lv.extent_from_param);
            h = util::fnv_mix(h, lv.align_bytes);
        }
    }
    return h;
}

FunctionInputs compute_function_inputs(const ir::IrFunction &fn) {
    FunctionInputs in;
    in.function_code = function_code_key(fn);
    in.param_contracts = param_contracts_key(fn);
    return in;
}

/**
 * @brief Las entradas de CADA funcion y su plegado del modulo, en UNA pasada.
 *
 * Las dos cifras salen del mismo recorrido a proposito: el plegado del modulo
 * ES la suma de las de las funciones, asi que calcularlas por separado seria
 * recorrer el modulo dos veces para obtener lo mismo.  Y lo que de verdad
 * importa es que se calcule una vez para TODOS los dominios: son las mismas
 * cifras para los dieciseis, lo unico que cambia por dominio es que parte se
 * pliega -- una operacion, no una pasada --.  Pedirlas por dominio serian
 * dieciseis recorridos completos del modulo antes de producir nada.
 */
struct AllInputs {
    ModuleInputs module;
    /// (hash del nombre, sus entradas).  Solo las funciones con nombre: una
    /// sin el no se puede referenciar desde el fichero de la proxima
    /// compilacion, que es donde esta tabla se compara.
    std::vector<std::pair<uint64_t, FunctionInputs>> by_function;
};

AllInputs compute_all_inputs(const ir::IrModule &mod) {
    AllInputs all;
    ModuleInputs &in = all.module;
    in.function_code = util::kFnvOffset;
    in.param_contracts = util::kFnvOffset;
    in.unnamed_code = util::kFnvOffset;
    all.by_function.reserve(mod.functions.size());
    for (const ir::IrFunction &fn : mod.functions) {
        /* Cada funcion aporta las suyas, y se pliegan.  Las de una funcion
         * suelta salen de @ref compute_function_inputs, que es lo que usa la
         * validacion por funcion. */
        const FunctionInputs f = compute_function_inputs(fn);
        in.function_code = util::fnv_mix(in.function_code, f.function_code);
        in.param_contracts =
            util::fnv_mix(in.param_contracts, f.param_contracts);
        if (!fn.name.empty()) {
            all.by_function.emplace_back(function_name_hash(fn.name), f);
        } else {
            /* Sin nombre no hay entrada posible en la tabla del fichero, asi
             * que su codigo se le cobra a TODAS: es la unica forma de que un
             * cambio encerrado en una anonima siga moviendo alguna clave.
             *
             * Y NO se calla.  Que sea correcto no lo hace inocuo: degrada la
             * granularidad del modulo ENTERO, y sin decirlo la cache se iria
             * volviendo gruesa sola sin que nadie supiera por que.  Hoy no
             * deberia sonar -- todos los sitios que construyen una funcion le
             * ponen nombre --, asi que si suena es que hay una via nueva. */
            in.unnamed_code = util::fnv_mix(in.unnamed_code, f.function_code);
            in.unnamed_code =
                util::fnv_mix(in.unnamed_code, f.param_contracts);
            warn_unnamed_function();
        }
    }
    in.static_data = util::kFnvOffset;
    for (size_t i = 0; i < mod.static_data.size(); ++i) {
        const std::string &name = mod.static_data.meta_at(i).section_name;
        in.static_data =
            util::fnv_bytes(in.static_data, name.data(), name.size());
    }
    in.globals = util::kFnvOffset;
    for (const auto &g : mod.globals) {
        in.globals = util::fnv_bytes(in.globals, g.first.data(), g.first.size());
        in.globals = util::fnv_mix(in.globals, g.second);
    }
    return all;
}

/// Solo el plegado del modulo, para quien no necesite el desglose.
ModuleInputs compute_module_inputs(const ir::IrModule &mod) {
    return compute_all_inputs(mod).module;
}

/// @brief Pliega las entradas que un dominio DECLARA mirar.
///
/// Cero cuando no declara nada: es "no se decirlo", que se acepta sin
/// comprobar.  Distinto de declarar @c DomainInput::None, que es "no miro nada
/// del programa" y da una huella constante -- comprobable y siempre valida.
/**
 * @brief La clave de un dominio PARA UNA FUNCIoN.
 *
 * Lo mismo que @ref fold_declared_inputs pero tomando del modulo solo lo que es
 * del modulo -- datos estaticos, globales -- y de la funcion lo que es suyo.
 * Es lo que hace que tocar una funcion no invalide los hechos de las demas.
 *
 * Un dominio que NO mire codigo ni contratos da la misma clave para todas: sus
 * hechos no dependen de en que funcion esten, y eso es correcto -- `layout`
 * habla del modulo aunque sus hechos se atribuyan a algo.
 */
uint64_t fold_declared_inputs_for_function(DomainInput set,
                                           const ModuleInputs &mod_in,
                                           const FunctionInputs &fn_in) {
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    if (has_input(set, DomainInput::FunctionCode)) {
        h = util::fnv_mix(h, fn_in.function_code);
        /* Y el de las anonimas, que no puede ir en la clave de ninguna: ver
         * @c ModuleInputs::unnamed_code.  Quien mira codigo lo mira TODO.
         *
         * Lo que NO entra es DONDE esta escrita.  Un hecho no guarda su linea:
         * guarda a que entidad se refiere, y la linea se resuelve al consultar
         * (@ref AnchorLines).  Meterla aqui hacia que reindentar caducara
         * analisis que seguian siendo validos -- la vida corta de la posicion
         * gobernando la larga de la afirmacion --, que es justo lo que
         * `hash_de_tokens` evita ignorando comentarios y espaciado. */
        h = util::fnv_mix(h, mod_in.unnamed_code);
    }
    if (has_input(set, DomainInput::ParamContracts))
        h = util::fnv_mix(h, fn_in.param_contracts);
    if (has_input(set, DomainInput::StaticData))
        h = util::fnv_mix(h, mod_in.static_data);
    if (has_input(set, DomainInput::Globals))
        h = util::fnv_mix(h, mod_in.globals);
    return h;
}

uint64_t fold_declared_inputs(DomainInput set, const ModuleInputs &in) {
    uint64_t h = 0x9E3779B97F4A7C15ULL; // semilla != 0: declarar None es un dato
    if (has_input(set, DomainInput::FunctionCode))
        h = util::fnv_mix(h, in.function_code);
    if (has_input(set, DomainInput::ParamContracts))
        h = util::fnv_mix(h, in.param_contracts);
    if (has_input(set, DomainInput::StaticData))
        h = util::fnv_mix(h, in.static_data);
    if (has_input(set, DomainInput::Globals))
        h = util::fnv_mix(h, in.globals);
    return h;
}

/// Vector plano: son unos pocos y se recorren enteros; un mapa aqui seria
/// indireccion para nada.  Function-local para no depender del orden de
/// inicializacion estatica entre unidades de traduccion.
std::vector<RegisteredDomain> &registry() {
    static std::vector<RegisteredDomain> r;
    return r;
}

void register_builtin_producers();

/// Da de alta los dominios de casa una sola vez.  Explicito y no por
/// inicializacion estatica: asi el orden es el que se lee aqui, y no el que
/// decida el enlazador.  Importa: la estructura va primero para que los demas
/// puedan apoyar SUS hechos en el suyo.
void ensure_registry() {
    static const bool done = [] {
        register_builtin_producers();
        return true;
    }();
    (void)done;
}

/// El intervalo, con sus numeros: un hecho que no ensena su valor obliga a
/// mirar el codigo para saber que dice.
std::string range_text(const ValueRange &r) {
    std::ostringstream o;
    int64_t lo = 0, hi = 0;
    if (r.vista_con_signo(lo, hi)) {
        if (lo == hi)
            o << "= " << lo;
        else
            o << "[" << lo << "," << hi << "]";
    } else {
        o << "[" << r.lo_c << "," << r.hi_c
          << "]u"; // `u`: sin signo, y no se traduce
    }
    o << " " << (r.t.sin_signo ? "u" : "i") << static_cast<int>(r.t.bits);
    return o.str();
}

// ===========================================================================
// DOMINIOS
// ===========================================================================

/// Estructura: la forma de la funcion.  Un recorrido, sin reticulo: lo que sale
/// de aqui es lo que el IR dice, no una aproximacion.
void produce_structure(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const IrFacts &h = p.base.structure(fn);
        Fact f;
        f.what.domain = kProducerStructure;
        f.what.code = "structure.shape";
        f.what.a = h.block_count;
        f.what.b = h.loop_count;
        std::ostringstream o;
        /* Clave=valor con claves en INGLES, que son identificadores y no se
         * traducen.  Cinco numeros no caben en los dos del hecho, y meterlos
         * como frase los volveria intraducibles; asi el dato sigue siendo dato
         * y quien lo pinte puede componer la frase que quiera. */
        o << "blocks=" << h.block_count << " loops=" << h.loop_count
          << " calls=" << h.static_callees.size()
          << (h.has_dynamic_call ? " +dynamic" : "")
          << (h.recursive ? " recursive" : "") << " params=" << fn.params.size()
          << " values=" << fn.values.size();
        f.what.detail = p.store.intern(o.str());
        f.about = function_subject(p, fn);
        f.seal = p.base.seal(kProducerStructure, fn);
        f.proof.rule = "cfg-walk";
        p.structure_of[fn.name] = p.assert_fact(std::move(f));
    }
}

/// Rangos: entre que dos numeros esta cada valor.
///
/// CRITERIO DEL DOMINIO: se afirma lo que dice MAS que el tipo.  Repetir "un
/// u64 cabe en un u64" no es conocimiento, es la definicion del tipo.
void produce_ranges(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const RangeFacts &rf = p.base.ranges(fn);
        const Seal s = p.base.seal(kProducerRanges, fn);
        for (ir::IrValueId v = 0; v < fn.values.size(); ++v) {
            const ValueRange &r = rf.at(v);
            if (r.es_bottom()) {
                Fact f;
                f.what.domain = kProducerRanges;
                f.what.code = "range.unreachable";
                /* Sin detalle: el texto lo pone el catalogo desde el CODIGO. */
                f.about = value_subject(p, fn, v);
                f.seal = s;
                support_with_structure(p, fn, f, "data-flow");
                p.assert_fact(std::move(f));
                continue;
            }
            if (!r.acotada() || r.es_todo()) {
                /* POR QUE no se supo, y son TRES casos distintos que antes
                 * salian todos como "depende de la ejecucion".  La diferencia
                 * decide que hacer, asi que colapsarlos dejaba al consumidor
                 * sin la mitad de la respuesta:
                 *
                 *   - el analisis se paro por PRESUPUESTO: el rango podria
                 *     saberse y no se ha llegado.  NO es culpa del programa --
                 *     es del limite --, y se arregla subiendolo o simplificando
                 *     la funcion.  Decirlo como "depende de la ejecucion" era
                 *     ademas FALSO: le echaba la culpa al codigo del usuario;
                 *   - `top` es que ese valor no tiene dominio: no se miro nada
                 *     de el;
                 *   - y acotado a TODO su tipo si es de verdad "puede valer
                 *     cualquier cosa de las que caben ahi". */
                UnknownReason why = UnknownReason::RuntimeDependent;
                const char *detail = "vale todo su tipo";
                if (!rf.convergio) {
                    why = UnknownReason::BudgetExceeded;
                    detail = "el analisis de rangos paro por presupuesto "
                             "antes de llegar a punto fijo";
                } else if (r.es_top()) {
                    why = UnknownReason::NotAsked;
                    detail = "sin dominio: no se miro este valor";
                }
                p.say_unknown(value_subject(p, fn, v), why, "range.unbounded",
                              kProducerRanges, detail, Scope::everywhere());
                continue;
            }
            Fact f;
            f.what.domain = kProducerRanges;
            f.what.code = r.es_constante() ? "range.constant" : "range.bounded";
            int64_t lo = 0, hi = 0;
            if (r.vista_con_signo(lo, hi)) {
                f.what.a = lo;
                f.what.b = hi;
            } else {
                f.what.a = static_cast<int64_t>(r.lo_c);
                f.what.b = static_cast<int64_t>(r.hi_c);
            }
            f.what.detail = p.store.intern(range_text(r));
            f.about = value_subject(p, fn, v);
            f.seal = s;
            support_with_structure(p, fn, f, "data-flow");
            p.assert_fact(std::move(f));
        }

    /* Y las operaciones que DAN LA VUELTA, que el dominio apunto al plegar.
     *
     * Van aparte de los rangos porque no son un rango: son una operacion.  Y
     * tienen que salir de aqui porque despues NO se pueden reconstruir -- el
     * plegado ya sustituyo `127 + 1` por un `-128` indistinguible de uno
     * escrito --.  El consumidor que avisa (la familia `types.int_wraparound`
     * del linter) mira el modulo ya optimizado, donde esa suma no existe. */
    for (const RangeFacts::Wrap &w : rf.wraps) {
        Fact f;
        f.what.domain = kProducerRanges;
        f.what.code = "range.wraps";
        f.what.a = w.exacto;
        f.what.b = static_cast<int64_t>(w.t);
        /* Neutro respecto al idioma: el detalle acaba en el volcado y en el
         * mensaje, y una frase escrita aqui no la puede traducir el catalogo. */
        f.what.detail = p.store.intern(std::to_string(w.exacto) + " -> [" +
                                       std::to_string(w.lo) + ", " +
                                       std::to_string(w.hi) + "]");
        f.about = value_subject(p, fn, w.dst);
        f.seal = s;
        /* Se ancla al VALOR, no a su linea.  El consumidor tiene otro codigo
         * delante, si -- pero lo que necesita es a que se refiere, no donde
         * estaba escrito cuando se produjo: la linea la saca del intermedio que
         * tenga en la mano (@ref resolve_anchor_line).  Guardarla aqui la
         * convertia en un dato que caduca al reindentar. */
        f.seal.origin.site = Anchor{Anchor::Kind::Value, w.dst};
        support_with_structure(p, fn, f, "data-flow");
        p.assert_fact(std::move(f));
    }
    }
}

/// Frontera: lo que entra y sale de cada funcion.  Conocimiento del MODULO: lo
/// que le llega a un parametro solo se sabe mirando a todos los que llaman.
void produce_boundary(Production &p) {
    const RangeSummaries &rs = p.base.boundary(p.mod);
    const Seal s = p.base.module_seal(kProducerBoundary);
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const FnRangeSummary *r = rs.lookup(fn.name);
        if (r == nullptr) {
            /* Y aqui la misma distincion: si el punto fijo del grafo de
             * llamadas no llego a converger, que falte un resumen NO es una
             * frontera opaca del programa -- es que el analisis paro --, y se
             * arregla subiendo el limite, no declarando nada. */
            p.say_unknown(function_subject(p, fn),
                          rs.convergio ? UnknownReason::OpaqueBoundary
                                       : UnknownReason::BudgetExceeded,
                          "boundary.no_summary", kProducerBoundary,
                          rs.convergio
                              ? "no aparece en el grafo de llamadas"
                              : "el punto fijo del grafo de llamadas paro por "
                                "presupuesto antes de resumirla",
                          Scope::everywhere());
            continue;
        }
        Fact f;
        f.what.domain = kProducerBoundary;
        f.what.code = r->cerrada ? "boundary.closed" : "boundary.open";
        f.what.a = static_cast<int64_t>(r->params.size());
        std::ostringstream o;
        o << (r->cerrada ? "se ven todos los llamantes"
                         : "llamantes sin ver -- los parametros valen su tipo");
        for (size_t i = 0; i < r->params.size(); ++i) {
            if (!r->params[i].acotada() || r->params[i].es_todo()) continue;
            int64_t lo = 0, hi = 0;
            if (!r->params[i].vista_con_signo(lo, hi)) continue;
            o << " | param" << i << " en [" << lo << "," << hi << "]";
            ++f.what.b;
        }
        if (r->ret.acotada() && !r->ret.es_todo()) {
            int64_t lo = 0, hi = 0;
            if (r->ret.vista_con_signo(lo, hi))
                o << " | devuelve [" << lo << "," << hi << "]";
        }
        f.what.detail = p.store.intern(o.str());
        f.about = function_subject(p, fn);
        f.seal = s;
        support_with_structure(p, fn, f, "callgraph-fixpoint");
        p.assert_fact(std::move(f));
    }
}

/// Nombre de la ISA con el vocabulario de @c Scope::isa.
///
/// La traduccion vive AQUI y no en la base porque aqui se ven las dos cosas: el
/// enum de la base de instrucciones y el vocabulario del alcance.  Meter el
/// primero en `fact.h` ataria el nucleo del ASA a la base de instrucciones, que
/// no tiene por que conocer.  Lo que si esta centralizado son los NOMBRES: sin
/// ellos, este helper los inventaba, y su propio comentario lo decia.
const char *scope_isa_name(vx::instr_db::Isa isa) {
    switch (isa) {
    case vx::instr_db::Isa::X86: return kIsaX8664;
    case vx::instr_db::Isa::ARM64: return kIsaArm64;
    case vx::instr_db::Isa::ARM32: return kIsaArm32;
    case vx::instr_db::Isa::RISCV: return kIsaRiscv;
    }
    return "";
}

/**
 * @brief El FLUJO DE CONTROL de cada bloque `asm`, como hecho.
 *
 * Antes esto se calculaba dentro del elevado y moria ahi: si un bloque tenia un
 * salto, se marcaba opaco y nadie mas se enteraba de la FORMA que tiene --
 * cuantos bloques basicos hay, que arista sale de cada uno, si algun destino no
 * se resuelve.  Y esa forma ya se sabia: `build_asm_cfg` la construye, y la
 * consumen el informe de efectos, `--analyze` y el calculo de coste, cada uno
 * volviendola a pedir por su cuenta.
 *
 * Puesta aqui, se calcula una vez y la lee quien quiera -- que es lo que hace
 * que el elevado del flujo (E1) no tenga que llevar su propio analisis.
 *
 * El terminador va en el hecho como NUMERO (`AsmTerm`) y no como frase: quien
 * decida algo compara el codigo, y el texto es solo para que lo lea una
 * persona.
 */
void produce_asm_flow(Production &p) {
    const vx::instr_db::Isa isa = vx::isa_actual();
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        /* Cuantos bloques `asm` se miraron de verdad.  Sin esta cuenta, una
         * funcion sin asm no producia NI hecho NI motivo, y el dominio salia
         * con "0 hechos de 0 miradas" aunque hubiera recorrido el modulo
         * entero: era imposible distinguir "no hay asm en ninguna parte" de
         * "este dominio no llego a correr". */
        uint32_t seen = 0;
        uint32_t idx = 0; // posicion lineal de la instruccion dentro de la fn
        for (const ir::IrBlock &b : fn.blocks) {
            for (const ir::IrInstr &in : b.instrs) {
                ++idx;
                /* El cuerpo esta en `func_name` cuando el bloque quedo opaco, y
                 * en la ficha del micro cuando se elevo.  Los dos casos
                 * interesan: la forma del flujo no depende de si se elevo. */
                std::string body;
                if (in.op == ir::IrOp::INLINE_ASM) {
                    body = in.func_name;
                } else if (in.op == ir::IrOp::ASM_MICRO &&
                           in.imm < fn.asm_micros.size()) {
                    body = fn.asm_micros[in.imm].tmpl;
                } else {
                    continue;
                }
                if (body.empty()) continue;
                ++seen; // hay asm aqui: el dominio SI tenia algo que mirar
                /* TAPoN PROVISIONAL, y conviene saber por que.
                 *
                 * Un `INLINE_ASM` no siempre lleva ensamblador: aqui llega
                 * `; __vxf_inject pendiente`, que es el MARCADOR de un bloque
                 * cuyo cuerpo lo genera `inject(...)` al compilar.  Saltarlos
                 * evita analizar un comentario, pero se lleva por delante justo
                 * los bloques CON FLUJO DE CONTROL: los `jb` del corpus salen
                 * todos de un `inject`, asi que lo que queda son los rectos.
                 *
                 * O sea que esto no esta bien: esta callado.  Lo correcto es
                 * que el flujo se analice DESPUES de la inyeccion, donde el
                 * cuerpo ya existe.  Hoy hay dos vistas y ninguna sirve sola --
                 * el lowering ve el asm expandido y avisa (VXA018), y aqui
                 * llega un marcador --, y por eso los dos recuentos nunca
                 * cuadraron. */
                if (body.find(ir::kAsmBodyPendingMark) != std::string::npos)
                    continue;
                const vx::AsmCfg cfg = vx::build_asm_cfg(isa, body);
                if (util::flag_on(util::FlagId::AsmFlujoDebug))
                    std::fprintf(stderr,
                                 "[asm-flujo] %s#%u: %zu bloques, %zu instr, "
                                 "cuerpo=<%.60s>\n",
                                 fn.name.c_str(), idx, cfg.blocks.size(),
                                 cfg.insns.size(), body.c_str());
                if (cfg.blocks.size() <= 1 && !cfg.has_indirect &&
                    cfg.unknown_terminators.empty())
                    continue; // recto y sin sorpresas: no hay nada que decir

                Subject s;
                s.kind = Subject::Kind::Instruction;
                s.function = p.store.intern(fn.name);
                s.id = idx;

                Fact f;
                f.what.domain = kProducerAsmFlow;
                f.what.code = "asm_flow.shape";
                f.what.a = (int64_t)cfg.blocks.size();
                f.what.b = (int64_t)cfg.insns.size();
                std::ostringstream o;
                o << cfg.blocks.size() << " bloques basicos";
                if (cfg.has_indirect) o << ", con salto indirecto";
                if (cfg.has_unresolved_target)
                    o << ", con destino sin resolver";
                if (cfg.has_external_target)
                    o << ", con salida a un simbolo del modulo";
                if (!cfg.unknown_terminators.empty())
                    o << ", " << cfg.unknown_terminators.size()
                      << " terminador(es) sin clasificar";
                f.what.detail = p.store.intern(o.str());
                f.about = s;
                /* La forma del grafo no depende del backend, pero SI de la ISA:
                 * el mismo texto no se trocea igual en dos juegos de
                 * instrucciones. */
                f.scope.isa = p.store.intern(scope_isa_name(isa));
                f.scope.why = "asm_flow.splitting_is_isa_specific";
                f.seal.certainty = Certainty::Proven;
                f.seal.origin.source = Source::Static;
                f.seal.origin.producer = kProducerAsmFlow;
                f.seal.origin.function = s.function;
                /* Aqui el ancla es una INSTRUCCIoN, no una linea -- y que el
                 * mismo campo significara una cosa aqui y otra 700 lineas mas
                 * abajo es justo lo que se vino a quitar. */
                f.seal.origin.site = Anchor{Anchor::Kind::Instruction, idx};
                f.proof.rule = "asm_flow.block_graph";
                p.assert_fact(f);

                /* Y lo que NO se supo, con su motivo: un terminador sin
                 * clasificar es una laguna concreta -- el mnemonico -- y
                 * callarla la vuelve indistinguible de no haber mirado. */
                for (const std::string &mn : cfg.unknown_terminators)
                    p.say_unknown(s, UnknownReason::ShapeNotRecognized,
                                  "asm_flow.unknown_terminator",
                                  kProducerAsmFlow, p.store.intern(mn),
                                  Scope::everywhere());
            }
        }
        /* Y si no habia ni un bloque `asm`, se DICE.  No es ignorancia: se sabe
         * perfectamente que no hay nada cuyo flujo analizar, y esa es la
         * diferencia entre "no hay" y "no se miro". */
        if (seen == 0)
            p.say_unknown(function_subject(p, fn), UnknownReason::NothingToSay,
                          "asm_flow.no_asm", kProducerAsmFlow, "",
                          Scope::everywhere());
    }
}

/**
 * @brief Con que alineacion se COLOCA cada seccion de datos.
 *
 * Es el hecho que un compilador con enlazador ajeno no puede producir: la
 * direccion final de un dato la decide otro, asi que lo unico afirmable es la
 * garantia generica del formato y cualquier exigencia mayor queda en "no puedo
 * probarlo".  Aqui la colocacion es nuestra.
 *
 * Y por eso mismo el hecho NACE CON AMBITO, en vez de ser un numero del
 * programa: la misma seccion no se coloca igual segun donde acabe corriendo.
 * En la maquina virtual el bloque lo reserva el cargador y el numero es firme.
 * En el nativo las secciones caen en pagina por defecto, PERO un guion de
 * enlazado puede ponerlas donde quiera (`place_section`), y esa direccion no
 * tiene por que cumplir nada.
 *
 * Afirmar el numero bueno sin decir para donde vale seria cometer justo el
 * fallo que este conocimiento existe para evitar: prometer una alineacion que
 * la memoria no da.  Y eso no falla ruidosamente -- lee mal.
 */
/**
 * @brief De que depende `asa.layout`: SOLO de si hay datos estaticos.
 *
 * Es el primer dominio que sabe decirlo, y se ve bien por que importa: lo que
 * afirma -- con que alineacion reserva el cargador la seccion `.data` -- no
 * depende ni una pizca del cuerpo de las funciones.  Con la huella del modulo
 * entero, tocar una linea de codigo tiraba este hecho y habia que rehacerlo;
 * con esta, sobrevive a cualquier cambio que no anada ni quite datos.
 *
 * Y es BARATA a proposito: se llama antes de producir nada, para decidir si lo
 * guardado vale.  Una huella cara aqui costaria mas que rehacer el dominio.
 */
uint64_t layout_inputs(const ir::IrModule &mod) {
    bool has_data = false;
    for (size_t i = 0; i < mod.static_data.size(); ++i) {
        if (mod.static_data.meta_at(i).section_name == ".data") {
            has_data = true;
            break;
        }
    }
    /* Dos valores distintos y NINGUNO cero: cero significa "no se decirlo", y
     * confundir "no hay datos" con "no lo se" haria que lo guardado se aceptara
     * sin comprobar. */
    return has_data ? 0x1A70D47Aull : 0x1A70E3C0ull;
}

void produce_layout(Production &p) {
    /* Un hecho por SECCION, no por dato: la garantia es de la seccion, y el
     * desplazamiento de cada dato dentro de ella ya lo sabe quien pregunta. */
    bool has_data = false;
    for (size_t i = 0; i < p.mod.static_data.size(); ++i) {
        if (p.mod.static_data.meta_at(i).section_name == ".data") {
            has_data = true;
            break;
        }
    }
    Subject subject;
    subject.kind = Subject::Kind::Module;

    /* Sin datos estaticos no hay nada que colocar, y eso se DICE.
     *
     * Antes esto era un `return` a secas, y tenia dos consecuencias que no se
     * ven hasta que se buscan.  La primera es la de siempre: irse callando deja
     * "no hay nada que colocar" indistinguible de "no lo mire", que son cosas
     * distintas y se arreglan distinto.  La segunda la destapo la cache: un
     * dominio que no deposita nada no tiene que guardar, asi que volvia a
     * correr en CADA compilacion para llegar otra vez a la misma nada.  La
     * conclusion "aqui no hay datos" es conocimiento y se cachea como el
     * resto. */
    if (!has_data) {
        p.say_unknown(subject, UnknownReason::NothingToSay,
                      "layout.no_static_data", kProducerLayout, "",
                      Scope::everywhere());
        return;
    }

    /* Corriendo en la maquina -- interprete o JIT -- el bloque de globales lo
     * reserva el cargador, y lo hace con una alineacion que elegimos nosotros.
     * Ahi el numero no se estima: se sabe.
     *
     * El alcance es la ISA, no el backend.  Este numero vale porque el bloque
     * lo coloco el CARGADOR DE LA MAQUINA, y eso pasa siempre que lo cargado es
     * bytecode -- interpretandolo o con el JIT, que parte del mismo --.  En
     * nativo no hay tal cargador.
     *
     * Sellado como `backend = "vm"`, el hecho era CIERTO PERO INVISIBLE desde
     * el JIT: `holds_in` exige que el campo coincida, y quien preguntara por
     * `jit` no lo encontraba.  Dicho como `isa = velb` es UN solo hecho, vale
     * en los dos, y ademas dice POR QUE vale en vez de enumerar donde. */
    {
        Fact f;
        f.what.domain = kProducerLayout;
        f.what.code = "layout.section_alignment";
        f.what.a = static_cast<int64_t>(alineacion_seccion_datos(kBackendVm));
        f.what.detail = p.store.intern(".data");
        f.about = subject;
        f.scope.isa = kIsaVelb;
        f.scope.why = "layout.placed_by_the_loader";
        f.seal.certainty = Certainty::Proven;
        f.seal.origin.source = Source::Static;
        f.seal.origin.producer = kProducerLayout;
        f.proof.rule = "layout.loader_reservation";
        p.assert_fact(f);
    }

    /* Y compilando a nativo NO se afirma, porque la colocacion la puede fijar
     * el usuario y aqui no se ve su guion de enlazado.  No decir nada seria
     * indistinguible de no haberlo mirado, asi que se deja constancia del
     * motivo: cuando el guion llegue hasta aqui, este silencio se convierte en
     * el numero que toque. */
    /* Este hueco es SOLO del nativo: el que coloca ahi es un guion de enlazado
     * que aqui no se ve, y con bytecode no existe tal cosa -- lo coloca el
     * cargador de la maquina, que es lo que el hecho de arriba afirma --. */
    p.say_unknown(subject, UnknownReason::OpaqueBoundary,
                  "layout.placement_is_configurable", kProducerLayout, "",
                  Scope::only_in_backend(kBackendAot,
                                         "layout.script_is_the_users"));
}

/**
 * @brief DONDE vale un hueco de este dominio, segun la operacion que lo causo.
 *
 * Un no-saber puede ser de UN SOLO modo.  "No modelo el puntero al proceso" no
 * le dice nada a quien compila a nativo: ahi ese puntero no existe, asi que
 * anunciarle el hueco es describirle un agujero que no esta.  La maquina es una
 * ISA mas -- `velb` --, asi que restringir a ella es lo mismo que restringir a
 * x86, no un caso aparte.
 *
 * QUE operaciones son NO se enumera aqui: lo dice el analisis que sabe que
 * subsistema necesita cada una para ir a nativo.  Con una lista escrita en este
 * fichero, la siguiente operacion que solo valga en un modo entraria anunciada
 * para los tres y nadie se enteraria.
 *
 * @param op    Operacion que CAUSO el hueco.
 * @param valid false si no lo causo ninguna operacion concreta.
 *
 * Se pide la que lo causo y no la que define el valor reportado, que es donde
 * se me fue la primera vez: el motivo se PROPAGA por las derivaciones, asi que
 * el valor del que se habla suele venir de un `bitcast` -- que existe en todos
 * los modos -- aunque el hueco lo causara un `getproc`, que no.  Preguntando
 * por el valor, el alcance salia universal siempre y el mecanismo no restringia
 * nada.
 *
 * @return El alcance del hueco; universal cuando la operacion existe en todos.
 */
Scope gap_scope_for(ir::IrOp op, bool valid) {
    if (!valid) return Scope::everywhere();
    aot::AotTarget bare;
    bare.tier = aot::Tier::BARE;
    const char *needs = aot::aot_op_requirement(op, bare);
    if (needs == nullptr || needs[0] == 0) return Scope::everywhere();
    return Scope::only_in_isa(kIsaVelb, "memory.op_needs_the_machine");
}

/// Memoria: a que se puede referir cada puntero.
///
/// CRITERIO DEL DOMINIO: un puntero que puede apuntar a cualquier cosa no es un
/// hecho, es la ausencia de uno.
void produce_memory(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const PointsTo &pt = p.base.memory(fn);
        /* Los def-use POR LA BASE, que es de donde salen los de todos: sirven
         * para llegar de un valor a la operacion que lo produjo, y esa
         * operacion es la que decide en que modos vale lo que se afirma. */
        const IrFacts &facts_of_fn = p.base.structure(fn);
        const Seal s = p.base.seal(kProducerMemory, fn);
        for (ir::IrValueId v = 0; v < fn.values.size(); ++v) {
            const effects::AbstractLoc l = loc_of(pt, v, 0);
            if (l.kind == effects::AbstractLoc::Kind::None ||
                l.kind == effects::AbstractLoc::Kind::Unknown) {
                /* EL MOTIVO LO DICE EL RESOLVEDOR, no este productor.
                 *
                 * Aqui habia una clasificacion propia -- `Unknown` es
                 * ejecucion, `None` no tiene nada que decir -- que adivinaba
                 * desde fuera lo que el resolvedor SABE desde dentro: si fue
                 * una operacion que no modela, si la raiz varia segun el
                 * camino, si viene de fuera o si se paso de saltos.  Dos sitios
                 * contestando a la misma pregunta, que es lo que el primer
                 * invariante existe para impedir: el de fuera solo podia
                 * acertar en el caso facil, y en los demas mentia con una clase
                 * plausible.
                 *
                 * Ahora se lee de la entrada.  Si el resolvedor no dijo nada
                 * -- un valor que nadie miro --, queda `NotAsked`, que es la
                 * verdad y no una suposicion. */
                const PointsToEntry &e = pt.at(v);
                const bool none = l.kind == effects::AbstractLoc::Kind::None;
                p.say_unknown(value_subject(p, fn, v),
                              none ? UnknownReason::NothingToSay : e.reason,
                              e.reason_code != nullptr &&
                                      e.reason_code[0] != '\0' && !none
                                  ? e.reason_code
                                  : "memory.not_located",
                              kProducerMemory,
                              /* Y QUE operacion o QUE valor, cuando se sabe: un
                               * motivo sin el dato no dice donde ampliar el
                               * analisis.
                               *
                               * Aqui iban dos frases escritas a mano, y eso es
                               * lo que el catalogo existe para que no pase: el
                               * hecho lleva DATOS y el texto sale del codigo,
                               * en el idioma de quien lo lea.  Escritas aqui,
                               * el volcado y el editor las ensenaban en
                               * castellano a todo el mundo. */
                              (e.reason_detail != nullptr &&
                               e.reason_detail[0] != '\0' && !none)
                                  ? e.reason_detail
                                  : "",
                              /* DONDE falta este conocimiento.  Un hueco puede
                               * ser de UN SOLO modo: "no modelo el puntero al
                               * proceso" no le dice nada a quien compila a
                               * nativo, porque ahi ese puntero no existe.  Lo
                               * decide el analisis que sabe que necesita cada
                               * operacion, no una lista escrita aqui. */
                              gap_scope_for(e.reason_op, e.has_reason_op));
                continue;
            }
            const PointsToEntry &pe = pt.at(v);
            const bool is_global =
                l.kind == effects::AbstractLoc::Kind::Global;
            Fact f;
            f.what.domain = kProducerMemory;
            /* Dos codigos, porque son dos propiedades distintas y la segunda es
             * la que decide lo que se puede hacer.
             *
             * Un global identificado por su SIMBOLO es una direccion concreta:
             * dos accesos al mismo global son la misma, y dos globales
             * distintos no se pisan.  Uno identificado solo por el valor que
             * dio su direccion no sostiene ninguna de las dos cosas -- el mismo
             * global tomado dos veces daria dos raices --.
             *
             * Va en el CODIGO y no en el texto porque quien decide mira el
             * codigo y los numeros; el texto es para que lo lea una persona.
             * Metido en el detalle, cada consumidor tendria que parsearlo, que
             * es la forma de que dos acaben interpretandolo distinto. */
            f.what.code = (is_global && pe.root_is_symbol)
                              ? "memory.points_to_symbol"
                              : "memory.points_to";
            f.what.a = static_cast<int64_t>(l.id);
            f.what.b = l.off;
            const char *kind_name = "";
            switch (l.kind) {
            case effects::AbstractLoc::Kind::Stack: kind_name = "pila"; break;
            case effects::AbstractLoc::Kind::Heap: kind_name = "monton"; break;
            case effects::AbstractLoc::Kind::Global:
                kind_name = "global";
                break;
            default: kind_name = "desde-parametro"; break;
            }
            std::ostringstream o;
            o << kind_name;
            if (l.id != effects::LOC_GENERIC) o << "#" << l.id;
            if (l.off != 0) o << (l.off > 0 ? "+" : "") << l.off;
            f.what.detail = p.store.intern(o.str());
            f.about = value_subject(p, fn, v);
            f.seal = s;
            /* DONDE vale.  Casi todo lo de este dominio es propiedad del
             * intermedio y vale en los tres modos, pero hay operaciones que
             * solo existen EJECUTANDO -- el puntero al proceso, los accesos a
             * la memoria de la maquina --, y un hecho sobre ellas leido desde
             * el nativo no describe nada que exista alli.
             *
             * Que operaciones son NO se enumera aqui: lo sabe el analisis que
             * clasifica cada op contra un objetivo nativo, y se le pregunta por
             * op -- barato, sin recorrer el modulo --.  Con una lista escrita
             * en este fichero, la siguiente operacion que solo valga en un modo
             * entraria sellada como universal y nadie se enteraria.
             *
             * El resto sigue sin restringir, y eso tambien es una afirmacion:
             * vale en todos.  Por eso el motivo se escribe solo cuando se
             * restringe -- restringir sin decir por que fue lo que costo meses
             * de silencio en el dominio de disposicion --. */
            if (const ir::IrInstr *def = facts_of_fn.def(v)) {
                /* La pregunta es si la operacion SIGNIFICA lo mismo fuera de la
                 * maquina, no si el backend sabe emitirla.  Son distintas, y
                 * confundirlas deja el mecanismo mudo: `aot_op_allowed` dice
                 * que si a `getproc` -- el nativo lo compila plegandolo a
                 * cero --, asi que preguntando por ahi no se restringia ni un
                 * hecho.  Lo que hace falta es su CLASE: una op que necesita el
                 * runtime de la maquina describe memoria que fuera de ella no
                 * existe. */
                if (aot::aot_classify_op(def->op) ==
                    aot::AotOpClass::RUNTIME_DEPENDENT) {
                    f.scope.isa = kIsaVelb;
                    f.scope.why = "memory.op_exists_only_at_runtime";
                }
            }
            support_with_structure(p, fn, f, "pointer-propagation");
            p.assert_fact(std::move(f));

            /* Y cuando es global pero NO se sabe de cual: se DICE.
             *
             * Es una respuesta parcial -- se sabe que apunta a memoria
             * estatica, no a cual --, y esa mitad que falta es justo la que
             * impide reusar una lectura o matar una escritura.  Sin dejarla
             * escrita, quien pregunte por que el optimizador no toco ese acceso
             * -- el editor, el linter, quien mire el volcado -- solo ve que no
             * lo toco; y el siguiente analisis que necesite lo mismo volveria a
             * descubrirlo por su cuenta.
             *
             * QUE operacion, ademas: es lo que dice donde ampliar (hoy solo
             * `str_lit_addr` demuestra su simbolo; `getstatic` lo lleva en un
             * operando y `label_addr`/`section_ref` en su nombre). */
            if (is_global && !pe.root_is_symbol) {
                const ir::IrInstr *d = nullptr;
                for (const ir::IrBlock &bb : fn.blocks)
                    for (const ir::IrInstr &in : bb.instrs)
                        if (in.dst == v) d = &in;
                p.say_unknown(value_subject(p, fn, v),
                              UnknownReason::ShapeNotRecognized,
                              "memory.global_without_symbol", kProducerMemory,
                              d != nullptr ? ir::ir_op_name(d->op) : "",
                              gap_scope_for(d != nullptr ? d->op : ir::IrOp{},
                                            d != nullptr));
            }
        }
    }
}

/// Bucles: donde estan, como de anidados, y CUANTAS VUELTAS dan.
void produce_loops(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const LoopFacts &lf = p.base.loops(fn);
        const Seal s = p.base.seal(kProducerLoops, fn);
        uint32_t seen = 0;
        for (ir::IrBlockId b = 0; b < fn.blocks.size(); ++b) {
            if (!lf.header_of(b)) continue;
            ++seen;
            Fact f;
            f.what.domain = kProducerLoops;
            f.what.code = "loop.header";
            f.what.a = lf.depth_of(b);
            /* Y CUAL lo contiene, que no es lo mismo que a que profundidad
             * esta.  Con la profundidad sola, quien la consume no puede
             * descontar los bucles de fuera que resulten constantes -- y ese
             * descuento es lo que separa `for(64) { for(n) }`, que es lineal,
             * de uno cuadratico de verdad.
             *
             * El dominio ya tiene el arbol de anidamiento; lo que faltaba era
             * publicarlo.  Sin el, el consumidor se lo inventaba por indices
             * de bloque, que es una suposicion sobre como numera el frontend y
             * deja de valer en cuanto el optimizador reordena. */
            const uint32_t li = lf.innermost(b);
            const uint32_t padre = li == LoopFacts::NO_LOOP ? LoopFacts::NO_LOOP
                                                            : lf.parent_of(li);
            f.what.b = padre == LoopFacts::NO_LOOP
                           ? -1
                           : static_cast<int64_t>(lf.header_block_of(padre));
            /* El detalle lleva DATOS, no una frase: el texto sale del catalogo
             * multi-idioma como el de cualquier otro diagnostico.  Aqui habia
             * espanol escrito a mano, que es justo lo que un usuario en otro
             * idioma no puede leer. */
            f.about.kind = Subject::Kind::Block;
            f.about.function = p.store.intern(fn.name);
            f.about.id = b;
            f.seal = s;
            support_with_structure(p, fn, f, "back-edges");
            p.assert_fact(std::move(f));
        }
        if (seen == 0) {
            p.say_unknown(function_subject(p, fn), UnknownReason::NothingToSay,
                          "loop.none", kProducerLoops, "",
                          Scope::everywhere());
            continue;
        }

        /* Y lo que de verdad se pregunta de un bucle: cuantas vueltas da.
         *
         * El analisis YA hablaba el vocabulario del ASA -- `LoopTripInfo`
         * lleva dentro un `asa::UnknownReason` --, pero nadie lo publicaba:
         * el conocimiento se calculaba, se usaba en el sitio y se tiraba.  Sin
         * esto, ni `--asa` lo ensena, ni viaja al fichero de hechos, ni el
         * linter puede preguntarlo.
         *
         * El `def_block` sale de la estructura, que la base ya tiene cacheada:
         * no se recorre la funcion otra vez. */
        const IrFacts &st = p.base.structure(fn);
        for (uint32_t L = 0; L < lf.loop_count; ++L) {
            Subject about;
            about.kind = Subject::Kind::Block;
            about.function = p.store.intern(fn.name);
            about.id = lf.header_block_of(L);
            /* DONDE esta el bucle, para todo lo que se diga de el.
             *
             * Sin esto un consumidor solo puede senalar la funcion -- y tras el
             * inline el mismo bucle esta en varias, asi que el aviso sale
             * repetido y en sitios donde el usuario no escribio nada.
             *
             * Se ancla al BLOQUE cabecera y NO a su linea, aunque la linea es
             * lo que acabara pintando el consumidor: es el mismo indice que ya
             * lleva `about`, asi que no se guarda nada nuevo, y la linea la
             * saca `resolve_anchor_line` del intermedio que tenga delante.  Con
             * la linea guardada aqui, reindentar el fichero la dejaba mintiendo
             * -- y para no mentir habia que tirar el analisis entero, que sigue
             * siendo bueno. */
            const Anchor at{Anchor::Kind::Block, about.id};

            const LoopStructure ls = detect_loop_structure(fn, lf, L);
            /* CONTABLE basta, que es mas debil que elegible para transformar.
             *
             * Un `for (i = 0; i < 32; i++)` con un `break` o un `return`
             * dentro no se contaba en absoluto -- se rechazaba entero por
             * tener mas de una salida --, y el coste declaraba O(n) una
             * funcion que da como mucho 32 vueltas.  Y esas dos formas son de
             * las mas corrientes que hay.
             *
             * Lo que sale de ahi es una COTA, no el numero: se degrada mas
             * abajo, donde ya se ha contado. */
            if (!ls.countable) {
                /* No es un bucle contado, y se dice CUAL de las condiciones
                 * fallo: son varias, se arreglan de formas distintas -- unas
                 * son huecos de este analisis y otras del programa -- y con un
                 * solo codigo para todas no habia forma de saber cual mirar. */
                p.say_unknown(about, UnknownReason::ShapeNotRecognized,
                              (ls.why != nullptr && ls.why[0] != '\0')
                                  ? ls.why
                                  : "loop.shape_unsupported",
                              kProducerLoops, "", Scope::everywhere(), at);
                continue;
            }
            /* Los DOS sentidos: aqui solo se CUENTA, y un bucle que baja
             * esta tan contado como uno que sube.  El que pide solo los que
             * suben es quien va a clonar o a calcular direcciones. */
            LoopIV iv;
            if (!detect_counted_iv(fn, st.def_block, ls.header, ls.preheader,
                                   ls.latch, iv)) {
                /* Antes de rendirse: puede que la induccion MULTIPLIQUE.
                 *
                 * `for (i = 1; i < n; i *= 2)` no da `n` vueltas sino del
                 * orden de `log n`, y eso no es una constante distinta: es
                 * otra CLASE.  Sin decirlo, el coste contestaba O(n) donde la
                 * respuesta es O(log n), y O(n^2) donde es O(n log n) -- la
                 * diferencia entre una busqueda y un barrido.
                 *
                 * Se publica como hecho propio y no como un trip count: no se
                 * sabe cuantas vueltas da (depende de `n`), se sabe COMO
                 * crece, que es justo lo que el coste necesita. */
                GeoIV g;
                if (detect_geometric_iv(fn, st.def_block, ls.header,
                                        ls.preheader, ls.latch, g)) {
                    Fact f;
                    f.what.domain = kProducerLoops;
                    f.what.code = "loop.geometric";
                    f.what.a = g.ratio;
                    f.about = about;
                    f.seal.certainty = Certainty::Proven;
                    f.seal.origin.source = Source::Static;
                    f.seal.origin.producer = kProducerLoops;
                    f.seal.origin.function = about.function;
                    f.scope.stage = p.stage;
                    support_with_structure(p, fn, f, "geometric-induction");
                    p.assert_fact(std::move(f));
                    continue;
                }
                p.say_unknown(about, UnknownReason::ShapeNotRecognized,
                              "loop.no_induction", kProducerLoops, "",
                              Scope::everywhere(), at);
                continue;
            }
            /* Con los RANGOS: son una segunda fuente para lo mismo.  Un
             * limite que no es una constante escrita puede seguir estando
             * acotado, y eso es un bucle acotado.  La base ya los tiene
             * cacheados, asi que preguntarlos no cuesta un analisis mas. */
            LoopTripInfo tc =
                compute_trip_count(fn, st.def_block, iv, &p.base.ranges(fn));
            /* Y si se puede salir antes, lo que se sabe es una COTA.
             *
             * La guarda dice que no pasa de N; un `break` puede cortarlo
             * antes, asi que N no es cuantas vueltas da sino cuantas da como
             * mucho.  Publicarlo como exacto seria dar un numero que el
             * programa puede no cumplir -- y hay quien lo usaria para quitar
             * una comprobacion. */
            if (!ls.single_exit()) tc.demote_to_bound("loop.early_exit");
            if (!tc.bounded()) {
                /* La razon Y EL CASO los da el ANALISIS, no quien pregunta: el
                 * ya sabe en cual de sus pasos se quedo, y lo dejo escrito.
                 *
                 * Publicar `loop.trip_unknown` para los cuatro tiraba justo lo
                 * que se acababa de calcular.  La CLASE (`ShapeNotRecognized`
                 * vs `RuntimeDependent`) es lo que puede leer quien no conoce
                 * este analisis; el codigo es cual de ellos fue, que es lo que
                 * dice DONDE mirar -- un inicio que no es constante y una
                 * guarda que no se cubre no se arreglan en el mismo sitio ni
                 * por la misma persona.  Justo encima, el rechazo de forma ya
                 * publica su `ls.why`; este se habia quedado atras. */
                p.say_unknown(about, tc.reason,
                              (tc.code != nullptr && tc.code[0] != '\0')
                                  ? tc.code
                                  : "loop.trip_unknown",
                              kProducerLoops, "", Scope::everywhere(), at);
                continue;
            }
            /* El hecho lo arma UN solo sitio (@c loop_trip_fact), el mismo que
             * usa el pase que lo descubre antes de deshacer el bucle.  Con dos
             * constructores bastaria que uno se quedara atras para que el mismo
             * bucle se contara distinto segun quien lo mirara. */
            Fact f;
            if (!loop_trip_fact(p.store, fn, about.id, tc, p.stage,
                                Source::Static, f))
                continue; // no habia nada que afirmar (ya se dijo por que)
            /* El apoyo CONCRETO -- no solo el nombre del productor -- para que
             * la derivacion se pueda recorrer.  Eso solo lo sabe quien produce
             * el dominio, que es quien tiene el hecho de estructura a mano. */
            f.seal.origin.site = at;
            support_with_structure(p, fn, f, f.proof.rule);
            p.assert_fact(std::move(f));
        }
    }
}

void register_builtin_producers() {
    /* CADA UNO DECLARA QUE MIRA.  Sin esto, el lector los aceptaba sin
     * comprobar -- y peor: en el lector, un dominio con huella cero ni siquiera
     * PUEDE caducar --, asi que la unica proteccion era que la puerta del
     * modulo fuese gruesa.  Quince de dieciseis estaban asi.
     *
     * Declarar de mas no da un error, da trabajo rehecho sin motivo; declarar
     * de menos SI da error, y del mudo.  En la duda, de mas. */
    register_producer(kProducerStructure, &produce_structure,
                      DomainInput::FunctionCode);
    register_producer(kProducerRanges, &produce_ranges,
                      DomainInput::FunctionCode);
    /* Los resumenes de frontera cierran sobre el grafo de llamadas, que sale
     * del propio codigo: con el codigo del modulo basta.
     *
     * Y por eso lleva ademas @c CallGraph: lo que dice de una funcion depende
     * de QUIEN LA LLAMA, asi que no puede validarse por funcion.  Con clave por
     * funcion, cambiar el llamante dejaba en pie una frontera que ya no era la
     * suya -- hechos falsos, no trabajo de mas --. */
    register_producer(kProducerBoundary, &produce_boundary,
                      DomainInput::FunctionCode | DomainInput::CallGraph);
    /* El points-to mira el codigo, y ademas la marca de direccion de los
     * parametros -- de ahi sale `AbstractLoc::exclusive` --, que vive en el
     * CONTRATO y no en las instrucciones. */
    register_producer(kProducerMemory, &produce_memory,
                      DomainInput::FunctionCode | DomainInput::ParamContracts);
    register_producer(kProducerLoops, &produce_loops,
                      DomainInput::FunctionCode);
    /* El unico que ya sabia decirlo, y con precision que las entradas no
     * alcanzan: distingue "hay .data" de "no hay".  Se le respeta la suya. */
    register_producer(kProducerLayout, &produce_layout, &layout_inputs);
    register_producer(kProducerAsmFlow, &produce_asm_flow,
                      DomainInput::FunctionCode);
    /* La forma de un valor vive en otra unidad de traduccion y se da de alta
     * ella misma.  Llevaba SIN registrar: calculaba sus hechos, los sellaba
     * con procedencia y certeza, y no llegaban al almacen -- o sea que nadie
     * podia consultarlos aunque quisiera. */
    register_value_shape_producer();
    register_definite_store_producer();
    /* Estos dos ya se CALCULABAN y los consumia uno solo: el acceso a memoria
     * lo preguntaban los pases sensibles a memoria, y uso-definicion el
     * asignador de registros.  Al almacen llegan para que ademas se puedan
     * CONSULTAR -- el editor, el linter --, que es la diferencia entre un
     * analisis y conocimiento compartido. */
    register_memory_access_producer();
    register_use_def_producer();
    /* Y el que dice que un bucle es en realidad una operacion de bloque.  Lo
     * calculaba solo el pase que lo baja a `memcpy`, asi que si ese no
     * disparaba no habia forma de saber si es que no lo vio o es que decidio
     * no tocarlo -- y las quince razones para no verlo no las contaba nadie. */
    register_bulk_memory_producer();
    /* Y el de las vistas `@overlay`: lo que el frontend SABE de como esta
     * puesto un formato, que se quedaba dentro del comprobador de tipos.  Sin
     * el, "que bytes cubre este campo" no se le podia preguntar a nadie -- ni
     * desde el linter ni desde el optimizador --, aunque el compilador acabara
     * de calcularlo para comprobar que dos campos no se pisan. */
    register_overlays_producer();
    /* Y la pregunta DUAL de los rangos: cuantos bits de cada valor llega a
     * mirar alguien.  Los KnownBits contestan que garantiza quien PRODUCE, y
     * con eso solo no se puede quitar una normalizacion: de un parametro no se
     * prueba nada por delante, y sin embargo si lo unico que se hace con la
     * cuenta es escribirla en un campo de cuatro bytes, los bits de arriba no
     * los mira nadie. */
    register_demanded_bits_producer();
    register_param_contracts_producer();
    /* Y el que dice que NO cabe en cada modo de ejecucion.  El analisis existia
     * desde hace tiempo y lo consumia un solo sitio, el editor: la misma
     * pregunta tenia dos respuestas segun quien la hiciera. */
    register_backend_producer();
}

} // namespace

/* Las tres de abajo son PUBLICAS (declaradas en producers.h).  Estuvieron en
 * el namespace anonimo de este fichero, y el resultado fue que cada dominio
 * nuevo se copio `value_subject`: habia tres identicas. */
Subject function_subject(Production &p, const ir::IrFunction &fn) {
    Subject s;
    s.kind = Subject::Kind::Function;
    s.function = p.store.intern(fn.name);
    return s;
}

Subject value_subject(Production &p, const ir::IrFunction &fn,
                      ir::IrValueId v) {
    Subject s;
    s.kind = Subject::Kind::Value;
    s.function = p.store.intern(fn.name);
    s.id = v;
    /* El MOMENTO forma parte de a quien se senyala.  `main:v3` antes de
     * optimizar y `main:v3` despues no son el mismo valor: el optimizador
     * renumera, funde y borra, asi que sin esto dos afirmaciones sobre
     * programas distintos caen sobre el mismo sujeto. */
    s.stage = p.stage;
    return s;
}

/// El hecho de estructura de @p fn si ya se produjo, para apoyarse en EL y no
/// solo en el nombre de su productor.
void support_with_structure(Production &p, const ir::IrFunction &fn, Fact &f,
                            const char *rule) {
    f.proof.rule = rule;
    auto it = p.structure_of.find(fn.name);
    if (it != p.structure_of.end()) f.proof.from.push_back(it->second);
    f.seal.support.add(kProducerStructure);
}


// ===========================================================================
// Motor
// ===========================================================================

ModuleWalk ModuleWalk::of(const ir::IrModule &mod) {
    ModuleWalk w;
    /* Solo se guarda lo que ALGUIEN lee.  Una travesia que materialice todo lo
     * que se podria querer no ahorra una pasada: la cambia por memoria, y de la
     * que se toca entera. */
    for (const ir::IrFunction &fn : mod.functions) {
        if (fn.is_native) continue;
        for (const ir::IrBlock &bb : fn.blocks)
            for (const ir::IrInstr &in : bb.instrs)
                if (in.op == ir::IrOp::CALL && !in.func_name.empty())
                    w.calls[in.func_name].push_back(Site{&fn, &in});
    }
    return w;
}

void register_producer(const char *domain, Producer p, DomainFingerprint fp) {
    for (const RegisteredDomain &d : registry())
        if (std::strcmp(d.name, domain) == 0) return; // ya esta
    registry().push_back({domain, p, fp, DomainInput::None});
}

void register_producer(const char *domain, Producer p, DomainInput inputs) {
    for (const RegisteredDomain &d : registry())
        if (std::strcmp(d.name, domain) == 0) return; // ya esta
    registry().push_back({domain, p, nullptr, inputs});
}

std::vector<std::pair<uint64_t, uint64_t>>
current_inputs_per_function(const ir::IrModule &mod, const char *domain) {
    ensure_registry();
    std::vector<std::pair<uint64_t, uint64_t>> out;
    if (domain == nullptr) return out;
    const RegisteredDomain *d = nullptr;
    for (const RegisteredDomain &r : registry())
        if (std::strcmp(r.name, domain) == 0) {
            d = &r;
            break;
        }
    /* Sin declaracion no hay clave por funcion.  Los que traen su propia huella
     * de dominio (`fingerprint`) tampoco entran: la suya habla del modulo y
     * partirla por funcion seria inventarle una precision que no tiene.
     *
     * Y el que avisa de que mira OTRAS funciones tampoco: su clave por funcion
     * invalidaria de menos.  @see DomainInput::CallGraph */
    if (d == nullptr || d->inputs == DomainInput::None ||
        has_input(d->inputs, DomainInput::CallGraph))
        return out;

    const AllInputs all = compute_all_inputs(mod);
    out.reserve(all.by_function.size());
    for (const auto &f : all.by_function)
        out.emplace_back(f.first, fold_declared_inputs_for_function(
                                      d->inputs, all.module, f.second));
    return out;
}

std::vector<DomainCost> current_inputs(const ir::IrModule &mod) {
    ensure_registry();
    std::vector<DomainCost> r;
    r.reserve(registry().size());
    /* Las entradas del modulo Y las de cada funcion, UNA vez para todos.  Si
     * cada dominio calculara las suyas serian tantos recorridos como dominios;
     * asi el recorrido es uno y por dominio solo queda plegar. */
    const AllInputs all = compute_all_inputs(mod);
    const ModuleInputs &in = all.module;
    for (const RegisteredDomain &d : registry()) {
        /* Un dominio que no sabe decir de que depende NO sale en la lista, y
         * eso no es lo mismo que salir con huella cero: la lista dice "esto es
         * lo que hoy se puede comprobar", y meter en ella a quien no sabe
         * responder solo sirve para que parezca comprobado. */
        DomainCost c;
        c.domain = d.name;
        if (d.fingerprint != nullptr) {
            /* Trae la suya hecha, y habla del MODULO.  No se reparte por
             * funcion: partirla seria inventarle una precision que no tiene, y
             * una clave por funcion falsa invalida menos de lo que debe -- que
             * es el unico error de esta cache que da un resultado equivocado en
             * vez de trabajo de mas. */
            c.fingerprint = d.fingerprint(mod);
        } else if (d.inputs != DomainInput::None) {
            c.fingerprint = fold_declared_inputs(d.inputs, in);
            /* Y la misma cuenta funcion a funcion, que es la que de verdad
             * ahorra: la de arriba se pliega sobre TODAS, asi que tocar una
             * linea la mueve y caduca el dominio entero.
             *
             * MENOS si el dominio avisa de que mira mas alla de la funcion.
             * Ahi una clave por funcion invalidaria de MENOS -- lo que dice de
             * `f` cambia cuando cambia `g`, y su clave no se movería --, que es
             * el unico error de esta cache que sirve hechos falsos en vez de
             * rehacer trabajo.  Sin tabla, se valida entero por la huella de
             * dominio: mas grueso y correcto.  @see DomainInput::CallGraph */
            if (!has_input(d.inputs, DomainInput::CallGraph)) {
                c.by_function.reserve(all.by_function.size());
                for (const auto &f : all.by_function)
                    c.by_function.emplace_back(
                        f.first, fold_declared_inputs_for_function(
                                     d.inputs, in, f.second));
            }
        } else {
            /* Declara `None`: no mira NADA del programa, asi que sus hechos no
             * pueden caducar por tocar el codigo.  Sale con una huella
             * constante -- comprobable y siempre valida -- en vez de quedarse
             * fuera de la lista.
             *
             * La diferencia importa: quedarse fuera es "no se puede comprobar",
             * y eso, con la puerta del modulo abierta, seria aceptar lo que
             * haya.  Una constante dice lo que de verdad pasa: no depende de
             * nada, luego siempre vale.  Y ya no existe la tercera opcion --
             * no declarar es error de compilacion. */
            c.fingerprint = fold_declared_inputs(d.inputs, in);
        }
        r.push_back(c);
    }
    return r;
}

std::vector<const char *> registered_producers() {
    ensure_registry();
    std::vector<const char *> v;
    v.reserve(registry().size());
    for (const RegisteredDomain &d : registry())
        v.push_back(d.name);
    return v;
}

std::vector<ProductionSummary> produce(const ir::IrModule &mod,
                                       FactStore &store,
                                       const std::vector<const char *> &wanted,
                                       const char *stage,
                                       AnalysisStore *analyses) {
    /* Antes de producir nada: los nombres de los productores tienen que ser
     * canonicos para que un hecho leido de disco se reconozca como suyo. */
    register_asa_canonical_names();
    ensure_registry();
    std::vector<ProductionSummary> summaries;
    /* UNA base para todos los dominios: si tres piden la estructura, se calcula
     * una vez.  Es la Regla 1 aplicada a la propia produccion. */
    /* Con el MOMENTO del que se esta produciendo.  Sin el, un analisis hecho
     * para los hechos de antes de optimizar se serviria tal cual para los de
     * despues, que hablan de otro codigo. */
    FactBase base(stage);
    /* Y el almacen ENTRE compilaciones, si lo hay: es lo que hace que el
     * RAZONAMIENTO tampoco se rehaga.  Sin el la base computa todo, que es el
     * comportamiento de siempre. */
    base.set_analysis_store(analyses);
    std::unordered_map<std::string, FactId> structure_of;

    /* Reservar de golpe: un modulo grande produce cientos de miles de hechos y
     * dejarlos crecer de uno en uno copia el vector entero una y otra vez.  La
     * cota se estima de lo unico que la determina -- valores por dominio -- y
     * no hace falta que sea exacta. */
    size_t values = 0;
    for (const ir::IrFunction &fn : mod.functions)
        if (!fn.is_native) values += fn.values.size();
    store.reserve(values * 2u + 64u);

    /* El modulo, recorrido UNA vez.  Antes lo recorria cada productor por su
     * cuenta y cada huella otra vez -- trece pasadas donde hace falta una --,
     * y no solo por el tiempo: cada pasada se trae el modulo a la cache y lo
     * tira, asi que se pisan entre ellas. */
    /* Y se pide a la BASE, que es quien lo cachea.  Construirlo aqui dejaba dos
     * recorridos vivos en cuanto un analisis de la base necesitara el mismo
     * indice -- exactamente la pasada de mas que esto vino a quitar. */
    const ModuleWalk &walk = base.walk(mod);

    /* Se reserva de golpe: los resumenes se referencian desde el contexto de
     * cada productor y un realloc a mitad dejaria la referencia colgando. */
    summaries.reserve(registry().size());
    /* Un dominio no pedido NI SE CORRE.  Comparado por texto y no por puntero:
     * quien pide los dominios suele tener el literal a mano, no el que guardo
     * el registro, y exigir la misma direccion convertiria un filtro correcto
     * en un "no produce nada" mudo. */
    const auto is_wanted = [&wanted](const char *domain) {
        if (wanted.empty()) return true; // sin lista: todos
        for (const char *w : wanted)
            if (w == domain || std::strcmp(w, domain) == 0) return true;
        return false;
    };
    /* Las entradas del modulo, compartidas por todos los dominios que declaren
     * mirar algo.  Perezosas: ver abajo. */
    ModuleInputs inputs;
    bool inputs_ready = false;
    for (const RegisteredDomain &d : registry()) {
        if (!is_wanted(d.name)) continue;
        /* Y no se repite: si ese dominio ya corrio sobre este almacen, su
         * conocimiento ya esta ahi.  Es lo que permite que cada consumidor pida
         * lo suyo sin coordinarse con los demas y el trabajo se haga UNA vez,
         * sea cual sea el orden en que pregunten. */
        if (store.has_domain(d.name, stage)) continue;
        summaries.push_back(ProductionSummary{});
        ProductionSummary &r = summaries.back();
        r.domain = d.name;
        const auto t0 = std::chrono::steady_clock::now();
        /* De que depende, apuntado ANTES de producir: es lo que se guardara con
         * sus hechos para que la proxima compilacion pueda validarlos sin
         * volver a producirlos. */
        if (d.fingerprint != nullptr) {
            r.fingerprint = d.fingerprint(mod);
        } else if (d.inputs != DomainInput::None) {
            /* Perezoso: las entradas del modulo se calculan la PRIMERA vez que
             * un dominio declarado las necesita, no al entrar.  Un `produce`
             * donde ninguno declare nada no paga el recorrido. */
            if (!inputs_ready) {
                inputs = compute_module_inputs(mod);
                inputs_ready = true;
            }
            r.fingerprint = fold_declared_inputs(d.inputs, inputs);
        }
        Production p{mod, walk, base, store, r, structure_of, stage};
        d.producer(p);
        r.micros = static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t0)
                .count());
        /* Corrio: queda dicho.  Se marca aunque no haya afirmado nada -- "ya se
         * miro" y "no dio nada" son cosas distintas, y confundirlas haria
         * correrlo otra vez cada vez que alguien pregunte. */
        store.mark_domain(d.name, stage);
    }
    return summaries;
}

} // namespace asa
} // namespace analysis
