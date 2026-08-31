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
#include "analysis/asa/producers.h"

#include "ir/ssa_ir.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>
#include "analysis/facts/alignment.h"
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
    return true;
}

FactId Production::assert_fact(Fact f) {
    ++summary.looked_at;
    ++summary.facts;
    return store.add(std::move(f));
}

void Production::say_unknown(Subject about, UnknownReason reason,
                             const char *code, const char *domain,
                             const char *detail) {
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
};

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
                UnknownReason por_que = UnknownReason::RuntimeDependent;
                const char *detalle = "vale todo su tipo";
                if (!rf.convergio) {
                    por_que = UnknownReason::BudgetExceeded;
                    detalle = "el analisis de rangos paro por presupuesto "
                              "antes de llegar a punto fijo";
                } else if (r.es_top()) {
                    por_que = UnknownReason::NotAsked;
                    detalle = "sin dominio: no se miro este valor";
                }
                p.say_unknown(value_subject(p, fn, v), por_que,
                              "range.unbounded", kProducerRanges, detalle);
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
    }
}

/// Frontera: lo que entra y sale de cada funcion.  Conocimiento del MODULO: lo
/// que le llega a un parametro solo se sabe mirando a todos los que llaman.
void produce_boundary(Production &p) {
    const RangeSummaries &rs = p.base.boundary(p.mod);
    const Seal s = p.base.module_seal(kProducerBoundary);
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const FnRangeSummary *r = rs.buscar(fn.name);
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
                                "presupuesto antes de resumirla");
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
                if (body.find("__vxf_inject") != std::string::npos) continue;
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
                f.seal.origin.site = idx;
                f.proof.rule = "asm_flow.block_graph";
                p.assert_fact(f);

                /* Y lo que NO se supo, con su motivo: un terminador sin
                 * clasificar es una laguna concreta -- el mnemonico -- y
                 * callarla la vuelve indistinguible de no haber mirado. */
                for (const std::string &mn : cfg.unknown_terminators)
                    p.say_unknown(s, UnknownReason::ShapeNotRecognized,
                                  "asm_flow.unknown_terminator",
                                  kProducerAsmFlow, p.store.intern(mn));
            }
        }
        /* Y si no habia ni un bloque `asm`, se DICE.  No es ignorancia: se sabe
         * perfectamente que no hay nada cuyo flujo analizar, y esa es la
         * diferencia entre "no hay" y "no se miro". */
        if (seen == 0)
            p.say_unknown(function_subject(p, fn), UnknownReason::NothingToSay,
                          "asm_flow.no_asm", kProducerAsmFlow, "");
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
                      "layout.no_static_data", kProducerLayout, "");
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
    p.say_unknown(subject, UnknownReason::OpaqueBoundary,
                  "layout.placement_is_configurable", kProducerLayout, "");
}

/// Memoria: a que se puede referir cada puntero.
///
/// CRITERIO DEL DOMINIO: un puntero que puede apuntar a cualquier cosa no es un
/// hecho, es la ausencia de uno.
void produce_memory(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const PointsTo &pt = p.base.memory(fn);
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
                              none ? "no es un puntero localizable"
                                   : "no se pudo localizar a que apunta");
                continue;
            }
            Fact f;
            f.what.domain = kProducerMemory;
            f.what.code = "memory.points_to";
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
            support_with_structure(p, fn, f, "pointer-propagation");
            p.assert_fact(std::move(f));
        }
    }
}

/// Bucles: donde estan y como de anidados.
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
            std::ostringstream o;
            o << "cabecera de bucle, profundidad " << lf.depth_of(b);
            f.what.detail = p.store.intern(o.str());
            f.about.kind = Subject::Kind::Block;
            f.about.function = p.store.intern(fn.name);
            f.about.id = b;
            f.seal = s;
            support_with_structure(p, fn, f, "back-edges");
            p.assert_fact(std::move(f));
        }
        if (seen == 0)
            p.say_unknown(function_subject(p, fn), UnknownReason::NothingToSay,
                          "loop.none", kProducerLoops, "");
    }
}

void register_builtin_producers() {
    register_producer(kProducerStructure, &produce_structure);
    register_producer(kProducerRanges, &produce_ranges);
    register_producer(kProducerBoundary, &produce_boundary);
    register_producer(kProducerMemory, &produce_memory);
    register_producer(kProducerLoops, &produce_loops);
    /* El primero que sabe decir de que depende.  Los demas se registran sin
     * huella -- "no se decirlo" --, que es lo que habia y no es peor; segun
     * vayan sabiendolo, la cache se vuelve granular sin tocar el motor. */
    register_producer(kProducerLayout, &produce_layout, &layout_inputs);
    register_producer(kProducerAsmFlow, &produce_asm_flow);
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
}

} // namespace

// ===========================================================================
// Motor
// ===========================================================================

void register_producer(const char *domain, Producer p) {
    register_producer(domain, p, nullptr);
}

void register_producer(const char *domain, Producer p, DomainFingerprint fp) {
    for (const RegisteredDomain &d : registry())
        if (std::strcmp(d.name, domain) == 0) return; // ya esta
    registry().push_back({domain, p, fp});
}

std::vector<DomainCost> current_inputs(const ir::IrModule &mod) {
    ensure_registry();
    std::vector<DomainCost> r;
    r.reserve(registry().size());
    for (const RegisteredDomain &d : registry()) {
        /* Un dominio que no sabe decir de que depende NO sale en la lista, y
         * eso no es lo mismo que salir con huella cero: la lista dice "esto es
         * lo que hoy se puede comprobar", y meter en ella a quien no sabe
         * responder solo sirve para que parezca comprobado. */
        if (d.fingerprint == nullptr) continue;
        DomainCost c;
        c.domain = d.name;
        c.fingerprint = d.fingerprint(mod);
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

std::vector<ProductionSummary>
produce(const ir::IrModule &mod, FactStore &store,
        const std::vector<const char *> &wanted) {
    /* Antes de producir nada: los nombres de los productores tienen que ser
     * canonicos para que un hecho leido de disco se reconozca como suyo. */
    register_asa_canonical_names();
    ensure_registry();
    std::vector<ProductionSummary> summaries;
    /* UNA base para todos los dominios: si tres piden la estructura, se calcula
     * una vez.  Es la Regla 1 aplicada a la propia produccion. */
    FactBase base;
    std::unordered_map<std::string, FactId> structure_of;

    /* Reservar de golpe: un modulo grande produce cientos de miles de hechos y
     * dejarlos crecer de uno en uno copia el vector entero una y otra vez.  La
     * cota se estima de lo unico que la determina -- valores por dominio -- y
     * no hace falta que sea exacta. */
    size_t values = 0;
    for (const ir::IrFunction &fn : mod.functions)
        if (!fn.is_native) values += fn.values.size();
    store.reserve(values * 2u + 64u);

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
    for (const RegisteredDomain &d : registry()) {
        if (!is_wanted(d.name)) continue;
        /* Y no se repite: si ese dominio ya corrio sobre este almacen, su
         * conocimiento ya esta ahi.  Es lo que permite que cada consumidor pida
         * lo suyo sin coordinarse con los demas y el trabajo se haga UNA vez,
         * sea cual sea el orden en que pregunten. */
        if (store.has_domain(d.name)) continue;
        summaries.push_back(ProductionSummary{});
        ProductionSummary &r = summaries.back();
        r.domain = d.name;
        const auto t0 = std::chrono::steady_clock::now();
        /* De que depende, apuntado ANTES de producir: es lo que se guardara con
         * sus hechos para que la proxima compilacion pueda validarlos sin
         * volver a producirlos. */
        if (d.fingerprint != nullptr) r.fingerprint = d.fingerprint(mod);
        Production p{mod, base, store, r, structure_of};
        d.producer(p);
        r.micros = static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t0)
                .count());
        /* Corrio: queda dicho.  Se marca aunque no haya afirmado nada -- "ya se
         * miro" y "no dio nada" son cosas distintas, y confundirlas haria
         * correrlo otra vez cada vez que alguien pregunte. */
        store.mark_domain(d.name);
    }
    return summaries;
}

} // namespace asa
} // namespace analysis
