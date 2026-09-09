/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact_base.cpp
 * @brief Implementacion de la base de hechos (ver @c
 * analysis/asa/fact_base.h).
 */

#include "util/env_flags.h"
#include "analysis/asa/fact_base.h"

#include "analysis/asa/fact_store.h"
#include "analysis/asa/producers.h" // ModuleWalk: el recorrido, una sola vez
#include "ir/ssa_ir.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace analysis {
namespace asa {

/* El VOCABULARIO va en ingles, como los identificadores: estos nombres viajan
 * al fichero de hechos, al volcado y al MCP, y ahi los lee gente y herramientas
 * que no tienen por que saber espanol.  La PROSA -- comentarios, y el texto que
 * ve el usuario, que sale del catalogo multi-idioma -- es lo unico que no. */
const char *const kProducerStructure = "asa.structure";
const char *const kProducerRanges = "asa.ranges";
const char *const kProducerMemory = "asa.memory";
const char *const kProducerEffects = "asa.effects";
const char *const kProducerEscape = "asa.escape";
const char *const kProducerLayout = "asa.layout";
const char *const kProducerAsmFlow = "asa.asm_flow";
const char *const kProducerBoundary = "asa.boundary";
const char *const kProducerLoops = "asa.loops";
const char *const kProducerBulkMemory = "asa.bulk_memory";
const char *const kProducerBackend = "asa.backend";
const char *const kProducerOverlays = "asa.overlays";
const char *const kProducerDemandedBits = "asa.demanded_bits";
const char *const kProducerParamContracts = "asa.param_contracts";
const char *const kModuleUnit = "<module>";

AnchorLines::AnchorLines(const ir::IrFunction &fn) {
    /* UNA pasada, y las tres tablas a la vez: son la misma informacion mirada
     * por tres claves distintas, asi que recorrer tres veces solo cambiaria el
     * numero de veces que el modulo entra y sale de la cache. */
    by_value_.assign(fn.values.size(), 0);
    by_block_.assign(fn.blocks.size(), 0);
    size_t total = 0;
    for (const ir::IrBlock &b : fn.blocks)
        total += b.instrs.size();
    by_instr_.assign(total, 0);

    uint32_t idx = 0;
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        for (const ir::IrInstr &in : fn.blocks[bi].instrs) {
            by_instr_[idx++] = in.source_line;
            /* La linea del bloque es la de su primera instruccion QUE TENGA
             * una.  No la primera a secas: el intermedio mete operaciones
             * sinteticas -- copias de phi, saltos de relleno -- que no salen de
             * ninguna linea del usuario, y empezar por ellas daria cero. */
            if (by_block_[bi] == 0 && in.source_line > 0)
                by_block_[bi] = in.source_line;
            /* Y la de un valor es la de la instruccion que lo DEFINE. */
            if (in.dst != ir::IR_NO_VALUE && in.dst < by_value_.size())
                by_value_[in.dst] = in.source_line;
        }
    }
}

uint32_t AnchorLines::of(const Anchor &a) const {
    switch (a.kind) {
    case Anchor::Kind::Line:
        /* Ya es una linea: no cuelga de ninguna entidad del intermedio -- una
         * vista `@overlay` se declara en el fuente y no la produce ninguna
         * instruccion --, asi que no hay nada contra lo que resolverla.  Es la
         * unica clase que puede quedarse rancia, y por eso es el ultimo
         * recurso. */
        return a.id;
    case Anchor::Kind::Value:
        return a.id < by_value_.size() ? by_value_[a.id] : 0;
    case Anchor::Kind::Block:
        return a.id < by_block_.size() ? by_block_[a.id] : 0;
    case Anchor::Kind::Instruction:
        return a.id < by_instr_.size() ? by_instr_[a.id] : 0;
    default:
        /* `None`: el productor no dijo donde miro.  Cero, y que decida quien
         * pregunta -- inventar la linea 1 seria senalar un sitio que nadie ha
         * mirado, que es peor que no senalar ninguno. */
        return 0;
    }
}

void register_asa_canonical_names() {
    /* Perezoso y una sola vez, NO un objeto global.  Un inicializador estatico
     * reservaria memoria antes de main aunque nadie fuera a leer hechos de
     * disco, y eso corre las direcciones de todo lo que se reserve despues --
     * en un programa que dependa de la alineacion de lo suyo, algo asi cambia
     * si funciona o no.  Ademas evita el orden de inicializacion entre ficheros
     * objeto, que aqui importa porque la tabla vive en otro. */
    static const bool done = [] {
        register_canonical_name(kProducerStructure);
        register_canonical_name(kProducerRanges);
        register_canonical_name(kProducerMemory);
        register_canonical_name(kProducerLayout);
        register_canonical_name(kProducerAsmFlow);
        register_canonical_name(kProducerBoundary);
        register_canonical_name(kProducerLoops);
        register_canonical_name(kProducerBulkMemory);
        register_canonical_name(kProducerBackend);
        register_canonical_name(kProducerOverlays);
        register_canonical_name(kProducerDemandedBits);
        register_canonical_name(kProducerParamContracts);
        register_canonical_name(kProducerEffects);
        register_canonical_name(kProducerEscape);
        register_canonical_name(kModuleUnit);
        return true;
    }();
    (void)done;
}

/// Marcadores de identidad para el gestor.  Uno por dominio: la cache va por
/// (analisis, unidad), asi que dos dominios distintos no se pisan.
namespace {
struct MemoryAnalysis {
    static char ID;
};
struct LoopsAnalysis {
    static char ID;
};
struct IvBoundsAnalysis {
    static char ID;
};
struct BoundaryAnalysis {
    static char ID;
};
struct EffectsSummaryAnalysis {
    static char ID;
};
struct ParamAliasingAnalysis {
    static char ID;
};
struct ModuleWalkAnalysis {
    static char ID;
};
struct EscapeAnalysisId {
    static char ID;
};
char MemoryAnalysis::ID = 0;
char LoopsAnalysis::ID = 0;
char IvBoundsAnalysis::ID = 0;
char BoundaryAnalysis::ID = 0;
char EffectsSummaryAnalysis::ID = 0;
char ParamAliasingAnalysis::ID = 0;
char ModuleWalkAnalysis::ID = 0;
char EscapeAnalysisId::ID = 0;
} // namespace

FactBase::FactBase() {
    register_asa_canonical_names();
}

FactBase::FactBase(const char *stage) {
    register_asa_canonical_names();
    /* Nulo o vacio se queda con el de por defecto: una base sin momento
     * declarado habla de lo que el compilador tiene delante antes de
     * optimizar, que es de donde parte todo. */
    if (stage != nullptr && stage[0] != '\0') default_stage_ = stage;
}

FactBase::~FactBase() {
    static const bool log_it = util::flag_on(util::FlagId::AsaFactsDebug);
    if (!log_it || queries_ == 0) return;
    dump_facts(dump(), stderr);
    std::fprintf(stderr,
                 "[hechos] %zu preguntas atendidas, %zu analisis ejecutados\n",
                 queries_, computations_);
}

const std::string *FactBase::key_of(const ir::IrFunction &fn,
                                    const char *stage) {
    /* El MOMENTO va en la clave, siempre.  Sin el, lo que se analizo antes de
     * optimizar se sirve despues, y entonces se contesta sobre un codigo que ya
     * no existe: valores que el optimizador borro, bloques que fusiono.  Eso no
     * da un error, da respuestas equivocadas -- que es la forma cara de
     * fallar --, y es lo que ya llevaba `effects` desde el principio mientras
     * el resto se quedo fuera. */
    const char *st = (stage != nullptr) ? stage : "";
    if (!fn.name.empty()) return util::intern_name(fn.name + "@" + st);
    /* Anonima: la direccion la identifica sin ambiguedad mientras viva, y una
     * base no sobrevive al modulo cuyas funciones consulta. */
    char buf[40];
    std::snprintf(buf, sizeof buf, "<anonima:%p>",
                  static_cast<const void *>(&fn));
    /* Internado tambien: asi la clave es un puntero venga de donde venga, y
     * dos consultas sobre la misma funcion anonima dan el mismo. */
    return util::intern_name(std::string(buf) + "@" + st);
}

uint64_t FactBase::module_version(const ir::IrModule &mod) noexcept {
    /* Plegado, no suma: dos funciones que se intercambian versiones -- una sube
     * y otra baja -- darian la misma suma y el resultado se serviria rancio.
     * Con la posicion dentro de la mezcla, no. */
    uint64_t h = 0xcbf29ce484222325ULL;
    for (const ir::IrFunction &fn : mod.functions) {
        h ^= fn.version;
        h *= 0x100000001b3ULL;
    }
    return h;
}

const std::string *FactBase::module_key(const char *stage) {
    return util::intern_name(std::string(kModuleUnit) + "@" +
                             (stage != nullptr ? stage : ""));
}

void FactBase::mark(const char *producer, const std::string &key, Certainty c,
                    const char *support) {
    Seal s;
    s.certainty = c;
    s.origin.producer = producer;
    if (support != nullptr) s.support.add(support);
    auto &table = seals_[producer];
    auto &stored = table[key];
    stored = s;
    /* La procedencia apunta a la CLAVE, no al nombre de la funcion: la clave
     * vive en el mapa tanto como el sello, y el nodo no se mueve al crecer.
     * Apuntar al nombre de la funcion dejaria un puntero colgando en cuanto la
     * funcion consultada muriera antes que la base. */
    stored.origin.function = table.find(key)->first.c_str();
}

const IrFacts &FactBase::structure(const ir::IrFunction &fn,
                                   const char *stage) {
    ++queries_;
    const std::string *key = key_of(fn, stage_or_default(stage));
    /* Con la VERSION: `cached` a secas dice "hay algo guardado", que no es lo
     * mismo que "se va a reutilizar".  Preguntarlo sin ella contaba de menos los
     * recomputos y, peor, se saltaba el sello -- lo destapo el test de reuso. */
    if (!manager_.cached_v<IRFactsAnalysis>(key, fn.version)) {
        ++computations_;
        /* Un recorrido, sin reticulo ni punto fijo: lo que sale de aqui esta
         * DEMOSTRADO, no inferido.  Los def-use y el CFG son lo que el IR dice,
         * no una aproximacion de lo que podria pasar. */
        mark(kProducerStructure, *key, Certainty::Proven);
    }
    /* Por la puerta VERSIONADA.  Estos hechos guardan punteros a instrucciones,
     * asi que servir uno de antes de una mutacion no es imprecision: es leer
     * memoria liberada.  La version la sube el optimizador en un solo sitio, y
     * el gestor recalcula si no coincide -- lo que sustituye a "acordarse de
     * invalidar", que es una obligacion que no se puede comprobar. */
    return manager_.get_or_compute_v<IRFactsAnalysis, IrFacts>(
        key, fn.version, [&fn]() { return build_ir_facts(fn); });
}

const DemandedBits &FactBase::demanded(const ir::IrFunction &fn,
                                       const char *stage) {
    ++queries_;
    const std::string *key = key_of(fn, stage_or_default(stage));
    const bool fresh = !manager_.cached_v<DemandedBitsAnalysis>(key, fn.version);
    if (fresh) ++computations_;
    /* Por el gestor, como los rangos: los tres que preguntan -- el pase que
     * quita normalizaciones, el productor del dominio y quien venga -- acaban
     * en la MISMA instancia en vez de recalcularla cada uno.  Esa es la unica
     * forma de que anadir un consumidor no cueste otro analisis. */
    const DemandedBits &db =
        *manager_.get_or_compute_v<DemandedBitsAnalysis,
                                   std::shared_ptr<const DemandedBits>>(
            key, fn.version, [&fn]() {
                return std::make_shared<const DemandedBits>(
                    compute_demanded_bits(fn));
            });
    if (fresh) {
        /* La certeza sale del analisis: llegar a punto fijo es haber visto
         * todo lo que podia contradecirlo; cortar por la cota deja una cota
         * valida pero no demostrada al maximo. */
        mark(kProducerDemandedBits, *key,
             db.converged ? Certainty::Proven : Certainty::Inferred, nullptr);
    }
    return db;
}

const RangeFacts &FactBase::ranges(const ir::IrFunction &fn,
                                   const char *stage) {
    ++queries_;
    const std::string *key = key_of(fn, stage_or_default(stage));
    const bool fresh = !manager_.cached_v<RangeAnalysis>(key, fn.version);
    if (fresh) ++computations_;
    /* La factoria pide la estructura POR LA BASE, no por su cuenta: asi el
     * gestor anota que los rangos dependen de ella y una invalidacion arrastra
     * a los dos.  Pedirla aparte dejaria rangos vivos sobre hechos muertos. */
    /* El gestor guarda el PUNTERO, no una copia.  `RangeFacts` lleva dentro el
     * estado de entrada de cada bloque, asi que copiarlo es duplicar el
     * analisis entero, y debajo ya existe UNA instancia en la cache por
     * dependencias.  Los otros dos gestores que piden rangos -- el del
     * optimizador y el de efectos -- apuntan a la MISMA. */
    const RangeFacts &rf =
        *manager_
             .get_or_compute_v<RangeAnalysis,
                               std::shared_ptr<const RangeFacts>>(
                 key, fn.version, [this, &fn]() {
                     /* Con las cotas de induccion, que las saca el PROPIO
                      * motor de rangos.  Es conocimiento que los rangos no
                      * pueden deducir solos -- la guarda de un bucle
                      * desenrollado compara `i + 7`, y despejar la `i` con
                      * aritmetica que envuelve es incorrecto --, y sin ellas
                      * la variable del bucle vale TODO SU TIPO.
                      *
                      * Antes se pasaban desde aqui, y eso las dejaba en su
                      * version pobre: `compute_loop_iv_bounds` solo despeja
                      * limites CONSTANTES ESCRITOS, y en un programa real eso
                      * dejaba sin cota al 89 % de los bucles contados.  El
                      * motor las saca ESCALONADAS -- rangos sin cotas, cotas
                      * con esos rangos, rangos con las cotas --, que recupera
                      * los limites que no son un literal sin cerrar el
                      * circulo.  Pasarlas desde aqui SALTABA ese escalon. */
                     const RangeRequester mark(RangeAsker::FactBase);
                     return compute_ranges_ptr(fn, structure(fn),
                                               RangeOptions{}, nullptr,
                                               nullptr);
                 });
    if (fresh) {
        /* La certeza sale del propio analisis, no de quien pregunta: llegar a
         * punto fijo es haber visto todo lo que podia contradecirlo; pararse
         * por presupuesto es "hasta aqui he llegado", que sostiene una decision
         * con red pero no permite quitar una comprobacion. */
        mark(kProducerRanges, *key,
             rf.convergio ? Certainty::Proven : Certainty::Inferred,
             kProducerStructure);
    }
    return rf;
}

const PointsTo &FactBase::memory(const ir::IrFunction &fn,
                                 const char *stage) {
    ++queries_;
    const std::string *key = key_of(fn, stage_or_default(stage));
    if (!manager_.cached_v<MemoryAnalysis>(key, fn.version)) {
        ++computations_;
        /* El conjunto de sitios a los que un puntero PUEDE referirse es una
         * sobre-aproximacion COMPLETA: nada que no este dentro puede ocurrir.
         * Que un puntero concreto quede en "cualquier cosa" no rebaja el hecho
         * -- eso lo dice la propia entrada, no su certeza. */
        mark(kProducerMemory, *key, Certainty::Proven, kProducerStructure);
    }
    /* Versionado, y aqui es donde mas importa: `PointsTo` se apoya en los
     * hechos de estructura, que guardan punteros a instrucciones. */
    return manager_.get_or_compute_v<MemoryAnalysis, PointsTo>(
        key, fn.version,
        [this, &fn, stage]() { return compute_points_to(fn, structure(fn, stage)); });
}

const LoopFacts &FactBase::loops(const ir::IrFunction &fn,
                                 const char *stage) {
    ++queries_;
    const std::string *key = key_of(fn, stage_or_default(stage));
    if (!manager_.cached_v<LoopsAnalysis>(key, fn.version)) {
        ++computations_;
        mark(kProducerLoops, *key, Certainty::Proven);
    }
    return manager_.get_or_compute_v<LoopsAnalysis, LoopFacts>(
        key, fn.version, [&fn]() { return compute_loop_facts(fn); });
}

const LoopIvBounds &FactBase::iv_bounds(const ir::IrFunction &fn,
                                        const char *stage) {
    ++queries_;
    const std::string *key = key_of(fn, stage_or_default(stage));
    if (!manager_.cached_v<IvBoundsAnalysis>(key, fn.version)) {
        ++computations_;
        /* Demostrado: sale de la FORMA del bucle y de constantes escritas, sin
         * punto fijo que pueda pararse por presupuesto ni aproximacion que
         * pueda quedarse corta.  Por eso puede alimentar a los rangos y no al
         * reves -- si preguntara, se morderian la cola. */
        mark(kProducerLoops, *key, Certainty::Proven, kProducerStructure);
    }
    return manager_.get_or_compute_v<IvBoundsAnalysis, LoopIvBounds>(
        key, fn.version, [this, &fn, stage]() {
            return compute_loop_iv_bounds(fn, structure(fn, stage),
                                          loops(fn, stage));
        });
}

const RangeSummaries &FactBase::boundary(const ir::IrModule &mod,
                                         const char *stage) {
    ++queries_;
    // Internada tambien: la clave es un puntero, hable de una funcion o del
    // modulo entero.  Y con el momento, como todas.
    const std::string *key = module_key(stage_or_default(stage));
    const bool fresh =
        !manager_.cached_v<BoundaryAnalysis>(key, module_version(mod));
    if (fresh) ++computations_;
    const RangeSummaries &rs =
        manager_.get_or_compute_v<BoundaryAnalysis, RangeSummaries>(
            key, module_version(mod), [&mod]() { return compute_range_summaries(mod); });
    if (fresh) {
        /* Sin punto fijo del grafo de llamadas los resumenes se abren solos, y
         * entonces lo que se sabe es nada -- no algo menos preciso. */
        mark(kProducerBoundary, *key,
             rs.convergio ? Certainty::Proven : Certainty::Unknown,
             kProducerStructure);
    }
    return rs;
}

const ModuleWalk &FactBase::walk(const ir::IrModule &mod, const char *stage) {
    ++queries_;
    const std::string *key = module_key(stage_or_default(stage));
    const bool fresh =
        !manager_.cached_v<ModuleWalkAnalysis>(key, module_version(mod));
    if (fresh) ++computations_;
    /* Y con la version del MoDULO plegada: el recorrido dice quien llama a
     * quien, asi que cambiar cualquier funcion puede cambiarlo. */
    return manager_.get_or_compute_v<ModuleWalkAnalysis, ModuleWalk>(
        key, module_version(mod), [&mod]() { return ModuleWalk::of(mod); });
}

const effects::ParamAliasing &FactBase::param_aliasing(const ir::IrModule &mod,
                                                       const char *stage) {
    ++queries_;
    /* La clave lleva el MOMENTO, por lo mismo que la de los efectos: esto se
     * apoya en ellos, asi que compartirlo entre momentos le daria a uno el
     * resumen de un codigo que ya no existe. */
    const std::string *key = module_key(stage_or_default(stage));
    const bool fresh =
        !manager_.cached_v<ParamAliasingAnalysis>(key, module_version(mod));
    if (fresh) ++computations_;
    /* Fuera de la lambda: pedir el recorrido tambien es una consulta a la base,
     * y meterla dentro la ataria a que la lambda se ejecute -- que es justo lo
     * que no pasa cuando ya esta cacheado. */
    const ModuleWalk &w = walk(mod);
    const effects::ParamAliasing &pa =
        manager_.get_or_compute_v<ParamAliasingAnalysis, effects::ParamAliasing>(
            key, module_version(mod), [&mod, &w, stage, this]() {
                return effects::ParamAliasing(mod, w, *this, stage);
            });
    if (fresh) {
        /* Lo que se sella aqui es el ANALISIS, no cada respuesta: esta montado
         * sobre el resolutor de punteros y no anade suposiciones propias.  Que
         * un par concreto salga "no se" viaja en la respuesta de esa consulta,
         * que es donde tiene que ir. */
        mark(kProducerParamContracts, *key, Certainty::Proven, kProducerMemory);
    }
    return pa;
}

effects::EffectAnalysis &FactBase::effects(const ir::IrModule &mod,
                                           const char *stage) {
    ++queries_;
    /* La clave lleva el MOMENTO.  Sin el, el resumen que tomo el optimizador al
     * empezar se le entregaria al comprobador de regiones despues de que el
     * modulo haya cambiado: un resumen de codigo que ya no existe.  No falla --
     * avisa de accesos que ya no estan, o deja de avisar de uno real. */
    const std::string *key = module_key(stage_or_default(stage));
    const bool fresh =
        !manager_.cached_v<EffectsSummaryAnalysis>(key, module_version(mod));
    if (fresh) ++computations_;
    /* Se guarda por PUNTERO: el motor lleva dentro sus tablas y el resumen
     * guarda referencias a ellas, asi que copiarlo al meterlo en la cache
     * dejaria el resumen apuntando a las tablas de la copia vieja. */
    const std::shared_ptr<effects::EffectAnalysis> &engine =
        manager_.get_or_compute_v<EffectsSummaryAnalysis,
                                  std::shared_ptr<effects::EffectAnalysis>>(
            key, module_version(mod), [&mod]() {
                auto e = std::make_shared<effects::EffectAnalysis>();
                e->module_summary(mod); // deja el motor con sus tablas listas
                return e;
            });
    if (fresh) {
        /* Lo que sale de recorrer el grafo de llamadas entero es demostrado; lo
         * que se queda a medias -- una nativa sin declarar, un puntero a
         * funcion sin resolver -- lo dice el propio resumen en sus lagunas, y
         * el sello no puede afirmar mas que el. */
        mark(kProducerEffects, *key, Certainty::Proven, kProducerStructure);
    }
    return *engine;
}

const std::unordered_map<std::string, EscapeInfo> &
FactBase::escape(const ir::IrModule &mod) {
    ++queries_;
    // Internada tambien: la clave es un puntero, hable de una funcion o del
    // modulo entero.
    const std::string *key = util::intern_name(kModuleUnit);
    const bool fresh =
        !manager_.cached_v<EscapeAnalysisId>(key, module_version(mod));
    if (fresh) ++computations_;
    /* La estructura y la memoria de cada funcion se piden POR LA BASE, no
     * aparte: asi el punto fijo del escape reusa lo que ya haya y una
     * invalidacion arrastra a los dos. */
    const auto &res =
        manager_.get_or_compute_v<EscapeAnalysisId,
                                  std::unordered_map<std::string, EscapeInfo>>(
            key, module_version(mod), [this, &mod]() {
                auto facts_of =
                    [this](const ir::IrFunction &f) -> const IrFacts & {
                    return structure(f);
                };
                auto pt_of =
                    [this](const ir::IrFunction &f) -> const PointsTo & {
                    return memory(f);
                };
                return compute_escape_module(mod, facts_of, pt_of);
            });
    if (fresh) {
        /* El punto fijo se cierra sobre el grafo de llamadas: un callee que no
         * se ve captura TODO, que es la respuesta correcta sin su cuerpo.  Lo
         * que sale de ahi esta demostrado. */
        mark(kProducerEscape, *key, Certainty::Proven, kProducerMemory);
    }
    return res;
}

void FactBase::invalidate(const ir::IrFunction &fn) {
    /* Con el momento POR DEFECTO de la base.  Invalidar es "esta funcion ha
     * cambiado", y quien la cambia esta trabajando en un momento concreto: lo
     * de los OTROS momentos habla de otro codigo y no le afecta -- lo pre-opt
     * sigue siendo cierto de lo pre-opt aunque el optimizador ya haya pasado. */
    const std::string *key = key_of(fn, default_stage_);
    /* La estructura arrastra en cascada a todo lo que se derivo de ella; los
     * demas se descartan tambien de forma explicita por si alguien los pidio
     * antes de que existiera esa dependencia. */
    manager_.invalidate<IRFactsAnalysis>(key);
    manager_.invalidate<RangeAnalysis>(key);
    manager_.invalidate<MemoryAnalysis>(key);
    manager_.invalidate<LoopsAnalysis>(key);
    /* Y su sello con ellos: un hecho muerto que deja su procedencia atras hace
     * que el volcado afirme lo que ya no se sabe. */
    for (auto &domain : seals_)
        domain.second.erase(*key);
}

Seal FactBase::seal(const char *producer, const ir::IrFunction &fn) const {
    auto d = seals_.find(producer);
    if (d == seals_.end()) return Seal{};
    auto it = d->second.find(*key_of(fn, default_stage_));
    /* Nadie ha preguntado todavia: no se sabe nada, que no es lo mismo que
     * saber que no hay nada. */
    if (it == d->second.end()) return Seal{};
    return it->second;
}

Seal FactBase::module_seal(const char *producer) const {
    auto d = seals_.find(producer);
    if (d == seals_.end()) return Seal{};
    auto it = d->second.find(kModuleUnit);
    if (it == d->second.end()) return Seal{};
    return it->second;
}

std::vector<RecordedFact> FactBase::dump() const {
    std::vector<RecordedFact> out;
    for (const auto &domain : seals_)
        for (const auto &pair : domain.second)
            out.push_back({domain.first, pair.first, pair.second});
    /* Orden estable: dos volcados del mismo programa deben poder compararse. */
    std::sort(out.begin(), out.end(),
              [](const RecordedFact &a, const RecordedFact &b) {
                  if (a.function != b.function) return a.function < b.function;
                  return std::strcmp(a.domain, b.domain) < 0;
              });
    return out;
}

void dump_facts(const std::vector<RecordedFact> &entries, FILE *out) {
    for (const RecordedFact &h : entries) {
        std::fprintf(out, "[hechos] %-16s %-32s certeza=%s", h.domain,
                     h.function.c_str(), certainty_name(h.seal.certainty));
        for (int i = 0; i < Support::kMax; ++i)
            if (h.seal.support.on[i] != nullptr)
                std::fprintf(out, " sobre=%s", h.seal.support.on[i]);
        std::fprintf(out, "\n");
    }
}

} // namespace asa
} // namespace analysis
