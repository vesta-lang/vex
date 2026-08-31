/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/manager/analysis_manager.h
 * @brief Infraestructura de analisis del compilador (estilo PassManager nuevo
 * de LLVM / MLIR).  Los HECHOS son unicos (IRFacts), los ANaLISIS son
 *        independientes (cada uno su retículo/punto-fijo), y los PRODUCTOS
 *        (contratos, complejidad, --analyze) son proyecciones puras FUERA de
 *        aqui.  Este header es el nucleo: identidad de analisis, resultados por
 *        TYPE-ERASURE con concepto (sin herencia forzada), PreservedAnalyses y
 *        el gestor con dependencias explicitas + invalidacion.
 *
 * Es TRANSVERSAL (no pertenece al IR): IR es un consumidor, MachineIR sera
 * otro. Por eso vive en @c analysis/, no en @c ir/.
 *
 * ===========================================================================
 *  VISTA GLOBAL -- EL MOTOR DE CONOCIMIENTO (un motor, capas modulares)
 * ===========================================================================
 *
 * Vesta no es una cadena de pases: es un MOTOR DE CONOCIMIENTO (Programa ->
 * Hechos -> Decisiones).  El motor es UNO SOLO, hecho de capas modulares que
 * se montaron a la vez y cada una se encarga de una cosa distinta.  ESTE
 * header (@c AnalysisManager) NO es un motor separado del @c FunctionSnapshot
 * (codegen/rbank): son DOS CAPAS del MISMO motor con responsabilidades
 * distintas -- GESTION del ciclo de vida vs VISTA de consulta.  Colaboran; no
 * compiten ni se duplican.  (Leer una como "otro motor" es el error a evitar.)
 *
 * El motor no produce hechos sueltos: produce CONOCIMIENTO derivado del
 * programa, y los Facts son su REPRESENTACION ESTABLE.  La cadena es siempre la
 * misma -- los productores (los Analysis) generan hechos; los consumidores los
 * consultan; nadie recomputa el IR:
 *
 *   IR --> Analysis (productor) --> Facts --> query<T>() --> consumidores
 *          recorrido / reticulo    dato       demand-        allocator /
 *                                  estable    driven         scheduler / ...
 *
 *   IR  (una representacion del programa)
 *    |     cada analisis DERIVA su hecho de un recorrido/reticulo; ningun
 *    |     consumidor re-recorre el IR -- el hecho se computa UNA vez.
 *    v
 *  +---------------------------------------------------------------------+
 *  | CAPA DE HECHOS (Facts) -- cada hecho un modulo independiente         |
 *  |                                                                      |
 *  |  STRUCTURAL  un recorrido, sin reticulo (analysis/facts, ir/):       |
 *  |     IrFacts (def-use, call-sites, back-edges)     Liveness           |
 *  |  SEMANTIC    reticulo / punto-fijo / interproc (analysis..):         |
 *  |     PointsTo + alias    EscapeInfo    SemanticEffects + summaries    |
 *  |  HARDWARE    Tipo C, por microarquitectura (analysis/hw):            |
 *  |     MachineCostFacts (latencias reload / store / move)               |
 *  |  DERIVED     compuestos de los anteriores (analysis/derived, facts): |
 *  |     LoopFacts    ProfileFacts    RematFacts                          |
 *  +---------------------------------------------------------------------+
 *      |                                          |
 *      | GESTION (ciclo de vida)                  | CONSULTA (demand-driven)
 *      v                                          v
 *  +------------------------------+   +---------------------------------+
 *  | AnalysisManager (ESTE file)  |   | FunctionSnapshot (codegen/rbank)|
 *  | transversal: IR + MachineIR  |   | vista para allocator/scheduler  |
 *  |  - cache por (AnalysisID,unit)|  |  - query<T>() lazy + LazyFact   |
 *  |  - deps explicitas (rev_deps) |  |  - QueryProducer<T> = algoritmo |
 *  |  - invalidacion en cascada    |  |  - deps se resuelven SOLAS      |
 *  |    (PreservedAnalyses)        |  |    (produce llama a query<U>)   |
 *  |  - dos ejes: cross-analisis   |  |  - DATO puro -> serializable    |
 *  |    e interprocedural          |  |    (core dump del conocimiento) |
 *  +------------------------------+   +---------------------------------+
 *          \                                    /
 *           \  El DISENO es UN unico ciclo de vida de los analisis (el del
 *            \ AnalysisManager); el snapshot mantiene HOY una cache propia
 *             \ (LazyFact) que se migrara a ese ciclo para heredar su
 *              \ invalidacion (los HUECOS estan en optimization_context.h).
 *               v El modelo mental ya es uno solo.
 *  +---------------------------------------------------------------------+
 *  | CONSUMIDORES: interp / JIT / AOT / allocator (rbank) / scheduler /   |
 *  |   vectorizer / --analyze / contratos de coste / LSP                  |
 *  +---------------------------------------------------------------------+
 *
 * POR QUE DOS CAPAS Y NO UNA: el @c AnalysisManager resuelve el CICLO DE VIDA
 * (computar perezoso, cachear por unidad, e INVALIDAR en cascada cuando un
 * pase muta el IR -- mecanismo @c PreservedAnalyses).  El @c FunctionSnapshot
 * resuelve la CONSULTA ergonomica de codegen (@c query<T>() que arrastra sus
 * dependencias solo).  Son ortogonales: uno gestiona QUE sobrevive a un
 * cambio; el otro ofrece COMO se pide un hecho.  El plan es que el segundo se
 * apoye en el primero (heredar invalidacion), no que uno sustituya al otro.
 *
 * POR QUE MODULAR: anadir conocimiento = anadir un MODULO (un Fact nuevo con
 * su productor), NO tocar el motor.  El @c AnalysisManager no cambia cuando
 * aparece un Fact; el @c query<T>() del snapshot tampoco.  Un hecho STRUCTURAL
 * y uno SEMANTIC nunca se mezclan (criterio en @c ir_facts.h: si necesita
 * reticulo o punto-fijo es ANALISIS, no hecho).  Y cada capa tiene informacion
 * que las otras NO tienen -- el IR sabe def-use y forma del CFG; el ASM sabe
 * latencias y puertos; el perfil sabe frecuencia real de ejecucion -- el motor
 * las mantiene juntas y consultables sin colapsarlas en una sola.
 *
 * ===========================================================================
 *  LOS TRES EJES DEL CONOCIMIENTO (que / cuanto / cuando-fisico)
 * ===========================================================================
 * El conocimiento que consume una decision (allocator, scheduler, ...) se
 * reparte en tres ejes ortogonales, cada uno en su nivel:
 *
 *   - IR  -> el QUE y el CUANDO SEMANTICO.  Que operacion, que tipo; cuando se
 *     vuelve a usar un valor EN EL PROGRAMA (UseDefFacts), profundidad de loop
 *     (LoopFacts), frecuencia (ProfileFacts), si es recomputable (RematFacts).
 *   - MachineKnowledge -> el CUANTO.  Coste real de una operacion en la
 *     microarquitectura (MachineCostFacts: latencia/puertos/uops;
 * SpillCostCard: reload/store/move).  OJO: es conocimiento de la ARQUITECTURA,
 * NO del MachineIR -- por eso vive en @c analysis/hw/, no en @c jit/.  Se puede
 *     preguntar "cuanto cuesta este ADD i64" SIN emitir una sola instruccion.
 *   - MachineIR -> el CUANDO FISICO.  El orden real tras la seleccion, use/def
 * a 2 posiciones por instruccion, folds (LEA), immediates, movimientos extra,
 *     presion de registros.  Solo aqui se conoce el coste OBSERVADO.
 *
 * COSTE ESTIMADO vs OBSERVADO.  De esos ejes salen dos costes:
 *   - ESTIMADO: IR (que op) + MachineKnowledge (cuanto) -> ANTES de bajar a
 *     MachineIR.  Ej: coste de recomputar una @c RematRecipe = latencia de su
 * op.
 *   - OBSERVADO: tras la seleccion de instrucciones (MachineIR) -> incluye
 * folds, immediates, MOVs extra, puertos ocupados. El IR NUNCA conoce su coste
 * maquina (no hay @c IrInstr::machine_cost()); es la MAQUINA quien lo estima
 * (@c MachineCostFacts::estimate(recipe)).  El punto donde los ejes se fusionan
 * es el @c OptimizationContext (Facts-programa x Facts-hardware ->
 * ObjectiveTerms -> decision).
 *
 * ===========================================================================
 *  UN FACT PERTENECE A UN DOMINIO (posiciones tipadas por nivel)
 * ===========================================================================
 * Un mismo concepto puede existir en VARIOS niveles sin ser duplicacion, porque
 * responde a dominios distintos.  Ejemplo canonico: el NEXT-USE ("cuando se
 * vuelve a usar cada valor") existe en dos, y no son intercambiables:
 *   - Belady IR      = @c UseDefFacts         (IrValueId + @c ir::LinearPos) ->
 * remat / sched IR
 *   - Belady Machine = @c MachineNextUseFacts  (vreg + @c codegen::LinearPos)
 * -> allocator Sus POSICIONES viven en dominios distintos (1 vs 2 por
 * instruccion); el tipo fuerte @c ir::LinearPos / @c codegen::LinearPos lo
 * impide cruzar en compilacion (ver @c ir/linear_pos.h, @c
 * codegen/linear_pos.h).  REGLA GENERAL: cada dominio tiene sus Facts y sus
 * posiciones.  Que un Fact nuevo aparezca "por nivel" (no como parche de un
 * consumidor) es indicio de que la regla es correcta.  Cuando lleguen @c CFGPos
 * / @c ProfilePos / ... seran "posiciones" pero ninguna intercambiable -- justo
 * el error que merece atrapar el compilador.
 */
#ifndef VESTA_ANALYSIS_MANAGER_H
#define VESTA_ANALYSIS_MANAGER_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace analysis {

// ===========================================================================
// AnalysisID -- identidad ESTABLE de un analisis (ortogonal a la interfaz de
// resultado).  Cada analisis expone un `static char ID;`; su direccion es el
// id.
// ===========================================================================
using AnalysisID = const void *;

/// Deriva el AnalysisID de un tipo de analisis @c A (que define `static char
/// ID`).
template <class A> AnalysisID analysis_id() {
    return &A::ID;
}

// ===========================================================================
// PreservedAnalyses -- que sobrevive a un pase.  Un pase declara lo que
// preserva; el manager conserva esos resultados y recomputa el resto
// perezosamente.
// ===========================================================================
class PreservedAnalyses {
  public:
    static PreservedAnalyses all() {
        PreservedAnalyses p;
        p.all_ = true;
        return p;
    }
    static PreservedAnalyses none() { return PreservedAnalyses{}; }

    /// Marca un analisis @c A como preservado.
    template <class A> void preserve() { ids_.insert(analysis_id<A>()); }
    void preserve_id(AnalysisID id) { ids_.insert(id); }

    bool preserves_all() const { return all_; }
    bool preserves_id(AnalysisID id) const {
        return all_ || ids_.count(id) != 0;
    }
    template <class A> bool preserves() const {
        return preserves_id(analysis_id<A>());
    }

  private:
    bool all_ = false;
    std::unordered_set<AnalysisID> ids_;
};

// ===========================================================================
// Type-erasure con CONCEPTO.  Los resultados NO heredan nada: pueden ser
// value-types puros (EffectSummary, IRFacts...).  El unico gancho que importa
// es `survives(PreservedAnalyses)`: se detecta por duck-typing (si el resultado
// lo define, se usa; si no, default conservador = no sobrevive -> se
// recomputa).
// ===========================================================================
namespace detail {
template <class T, class = void> struct has_survives : std::false_type {};
template <class T>
struct has_survives<T, decltype((void)std::declval<const T &>().survives(
                           std::declval<const PreservedAnalyses &>()))>
    : std::true_type {};

template <class T> bool call_survives(const T &r, const PreservedAnalyses &p) {
    // preserve-all no invalida NADA (el pase no cambio nada relevante).
    if (p.preserves_all()) return true;
    if constexpr (has_survives<T>::value)
        return r.survives(p);
    else
        return false; // sin gancho ante un pase que cambio algo: recomputar
}
} // namespace detail

/// Interfaz interna de un resultado type-erased.
struct AnalysisResultConcept {
    virtual ~AnalysisResultConcept() = default;
    virtual bool survives(const PreservedAnalyses &p) const = 0;
    /**
     * @brief Version de la unidad con la que se calculo este resultado.
     *
     * Es lo que hace que la caducidad sea IMPOSIBLE en vez de responsabilidad
     * de quien invalida.  Un resultado no describe "una funcion": describe una
     * funcion EN UN ESTADO.  Si el estado avanzo, lo que se guardo aqui habla
     * de codigo que ya no existe -- y en el caso de @c IrFacts eso no es solo
     * impreciso: guarda PUNTEROS a instrucciones, asi que leerlo tras una
     * mutacion es leer memoria ajena.  Medido: un 50 % de las ejecuciones
     * terminaba en fallo de segmentacion al confiar en la invalidacion manual.
     *
     * Cero = "sin versionar", para las unidades que no son funciones IR.
     */
    uint64_t version = 0;
};

/// Modelo templado: guarda un @c T por VALOR y reenvia el gancho.
template <class T> struct AnalysisResultModel final : AnalysisResultConcept {
    T result;
    explicit AnalysisResultModel(T r) : result(std::move(r)) {}
    bool survives(const PreservedAnalyses &p) const override {
        return detail::call_survives(result, p);
    }
};

// ===========================================================================
// AnalysisManager -- lazy + caché + dependencias explicitas + invalidacion.
//
// Clave = (AnalysisID, unit).  `unit` es un string (nombre de funcion, o
// "<module>" para el nivel modulo).  El grafo de DEPENDENCIAS se construye
// SOLO: cuando el computo de A pide getResult<B>, se registra "A depende de B";
// asi invalidar B invalida A -- y esto captura los DOS ejes de invalidacion
// (cross- analisis e interprocedural: si el cierre de un caller lee el summary
// del callee, la dependencia lo refleja automaticamente).
// ===========================================================================
class AnalysisManager {
  public:
    struct Key {
        AnalysisID id;
        std::string unit;
        bool operator==(const Key &o) const {
            return id == o.id && unit == o.unit;
        }
    };
    struct KeyHash {
        size_t operator()(const Key &k) const {
            return std::hash<const void *>()(k.id) ^
                   (std::hash<std::string>()(k.unit) << 1);
        }
    };

    /// Devuelve el resultado de @c A para @p unit, computandolo perezosamente
    /// con
    /// @p factory si no esta cacheado.  Registra la dependencia con el computo
    /// en curso (si lo hay) para la invalidacion.  @p factory: `() -> T`.
    /**
     * @brief Igual, pero comprobando que lo cacheado siga hablando del MISMO
     *        estado de la unidad.
     *
     * @param version Version actual de la unidad (p.ej. @c IrFunction::version,
     *        que avanza en cuanto un pase la modifica).  Si no coincide con la
     *        del resultado guardado, se recalcula: un resultado viejo no se
     *        entrega jamas, se haya invalidado o no.
     *
     * Esto sustituye a "acordarse de invalidar", que es una obligacion que no
     * se puede comprobar y que ya fallaba: hay caminos donde el IR se modifica
     * sin que nadie avise, y ahi el cache servia punteros a instrucciones
     * borradas.
     */
    template <class A, class T, class Factory>
    const T &get_or_compute_v(const std::string &unit, uint64_t version,
                              Factory &&factory) {
        const Key k{analysis_id<A>(), unit};
        /* El cerrojo protege las TABLAS, y solo eso.  La fabrica corre FUERA
         * -- ver abajo --: calcular un analisis es lo caro, y hacerlo con el
         * cerrojo puesto serializaria exactamente lo que se quiere repartir.
         *
         * Que dos hilos calculen a la vez el mismo analisis es posible y no es
         * un fallo: se guarda el ultimo y el otro conserva el suyo vivo por el
         * respaldo.  Se paga trabajo repetido en un caso raro a cambio de no
         * pagar serializacion en el caso normal. */
        std::unique_lock<std::mutex> lk(m_);
        if (!stack().empty()) rev_deps_[k].insert(stack().back());
        auto it = results_.find(k);
        if (it != results_.end()) {
            if (it->second->version == version) {
                ++aciertos_;
                // Respaldar antes de entregar: si otro hilo invalida esta
                // unidad -- o una de la que depende --, el mapa suelta su
                // referencia pero el objeto sigue vivo mientras el llamante lo
                // use.  Sin esto, la referencia devuelta puede colgar.
                retained().push_back(it->second);
                return static_cast<AnalysisResultModel<T> *>(it->second.get())
                    ->result;
            }
            ++caducados_;
            invalidate_key(k); // caduco: fuera, y con el lo que dependia de el
        } else {
            ++nuevos_;
        }
        stack().push_back(k);
        lk.unlock(); // la fabrica, sin el cerrojo puesto
        T value = factory();
        lk.lock();
        stack().pop_back();
        auto model = std::make_shared<AnalysisResultModel<T>>(std::move(value));
        model->version = version;
        T &ref = model->result;
        retained().push_back(model); // ver el caso de acierto
        results_[k] = std::move(model);
        index_add(k);
        return ref;
    }

    template <class A, class T, class Factory>
    const T &get_or_compute(const std::string &unit, Factory &&factory) {
        const Key k{analysis_id<A>(), unit};
        // Dependencia: el computo en curso (tope de la pila) depende de k.
        std::unique_lock<std::mutex> lk(m_);
        if (!stack().empty()) rev_deps_[k].insert(stack().back());
        auto it = results_.find(k);
        if (it != results_.end())
            return static_cast<AnalysisResultModel<T> *>(it->second.get())
                ->result;
        stack().push_back(k);
        /* Soltar el cerrojo ANTES de la fabrica es obligatorio, no una mejora:
         * la fabrica pide otros `get_or_compute` -- eso es lo que crea las
         * dependencias -- y volver a entrar con el cerrojo puesto se
         * autobloquea sobre un mutex no reentrante.  Aqui faltaba, y colgaba.
         */
        lk.unlock();
        T value = factory(); // puede pedir otros get_or_compute -> mas deps
        lk.lock();
        stack().pop_back();
        auto model = std::make_shared<AnalysisResultModel<T>>(std::move(value));
        T &ref = model->result;
        retained().push_back(model); // ver el caso de acierto
        results_[k] = std::move(model);
        index_add(k);
        return ref;
    }

    /// ¿Hay resultado cacheado de @c A para @p unit?
    template <class A> bool cached(const std::string &unit) const {
        std::lock_guard<std::mutex> lk(m_);
        return results_.count(Key{analysis_id<A>(), unit}) != 0;
    }

    /// Invalida el resultado @c A de @p unit y, transitivamente, todo lo que
    /// dependia de el (ambos ejes).
    template <class A> void invalidate(const std::string &unit) {
        std::lock_guard<std::mutex> lk(m_);
        invalidate_key(Key{analysis_id<A>(), unit});
    }

    /// Invalida los resultados de @p unit que NO sobreviven a @p preserved
    /// (mecanismo PreservedAnalyses tras un pase).  Cascada por dependencias.
    void invalidate(const std::string &unit,
                    const PreservedAnalyses &preserved) {
        /* Por el indice, no barriendo `results_` entero.
         *
         * Antes esto recorria TODAS las entradas del gestor para quedarse con
         * las de UNA unidad, y lo llama cualquier pase que cambie algo -- o
         * sea, muchas veces por vuelta del punto fijo.  Con el corpus de hoy no
         * se nota (0,06 s en el perfil), pero el coste crece con el producto de
         * unidades por invalidaciones: es de orden equivocado, y eso se
         * descubre tarde y caro cuando alguien compila un modulo grande. */
        std::lock_guard<std::mutex> lk(m_);
        auto u = keys_by_unit_.find(unit);
        if (u == keys_by_unit_.end()) return;
        std::vector<Key> dead;
        for (const Key &k : u->second) {
            auto it = results_.find(k);
            if (it != results_.end() && !it->second->survives(preserved))
                dead.push_back(k);
        }
        for (const Key &k : dead)
            invalidate_key(k);
    }

    /**
     * @brief Suelta lo que este hilo tenia cogido.
     *
     * Hay que llamarlo en un punto SEGURO: cuando el llamante ha terminado con
     * la unidad y ya no va a usar ninguna referencia que el gestor le diera.
     * En el bucle de pases, al cerrar cada funcion.
     *
     * Sin esto el respaldo crece sin fin -- cada resultado entregado quedaria
     * vivo hasta el final del proceso --, y con esto la memoria vuelve al
     * comportamiento de antes: solo sobrevive lo que el mapa siga guardando.
     */
    void release_retained() { retained().clear(); }

    /// Borra TODO (reconstruccion completa).
    void clear() {
        std::lock_guard<std::mutex> lk(m_);
        results_.clear();
        rev_deps_.clear();
        keys_by_unit_.clear();
        stack().clear();
    }

    size_t size() const { return results_.size(); }

    /**
     * @brief Cuantas consultas se sirvieron del cache, cuantas encontraron el
     *        resultado caducado, y cuantas no tenian nada guardado.
     *
     * Es lo que dice si cachear aqui puede servir de algo: si casi todo sale
     * CADUCADO, la unidad cambia entre consultas y no hay reuso posible por
     * mucho que se afine el mecanismo.  Sin este dato, "vamos a cachearlo" es
     * una apuesta.
     */
    struct Cuentas {
        long long aciertos = 0;
        long long caducados = 0;
        long long nuevos = 0;
    };
    Cuentas cuentas() const { return Cuentas{aciertos_, caducados_, nuevos_}; }

  private:
    long long aciertos_ = 0, caducados_ = 0, nuevos_ = 0;

    /// OJO: NO bloquea.  Se la llama desde dentro del cerrojo -- tanto desde
    /// `get_or_compute_v` cuando encuentra un resultado caduco como desde los
    /// `invalidate` publicos --, y volver a pedirlo aqui se autobloquearia.
    void invalidate_key(const Key &k) {
        auto it = results_.find(k);
        if (it == results_.end()) return;
        results_.erase(it);
        index_remove(k);
        auto d = rev_deps_.find(k);
        if (d == rev_deps_.end()) return;
        std::vector<Key> deps(d->second.begin(), d->second.end());
        rev_deps_.erase(d);
        for (const Key &dep : deps)
            invalidate_key(dep); // cascada
    }

    /// Protege las tablas de abajo.  NO se tiene puesto mientras corre una
    /// fabrica: ver `get_or_compute_v`.
    ///
    /// `mutable` porque hay consultas de solo lectura declaradas `const` que
    /// tambien tienen que tomarlo: mirar una tabla mientras otro hilo la muta
    /// no es seguro aunque no se escriba nada.
    mutable std::mutex m_;

    /// Que claves tiene cada unidad.  Existe para que invalidar una unidad no
    /// obligue a recorrer el gestor entero: sin esto, invalidar es O(todo) y se
    /// hace muchas veces por vuelta del punto fijo.
    std::unordered_map<std::string, std::vector<Key>> keys_by_unit_;

    /// Apunta @p k en el indice de su unidad, si no estaba.
    void index_add(const Key &k) {
        auto &v = keys_by_unit_[k.unit];
        for (const Key &x : v)
            if (x.id == k.id) return;
        v.push_back(k);
    }

    /// Quita @p k del indice.  La lista de una unidad son unas pocas entradas
    /// -- un analisis por tipo --, asi que buscar linealmente es mas rapido
    /// que cualquier estructura con indireccion.
    void index_remove(const Key &k) {
        auto u = keys_by_unit_.find(k.unit);
        if (u == keys_by_unit_.end()) return;
        auto &v = u->second;
        for (size_t i = 0; i < v.size(); ++i)
            if (v[i].id == k.id) {
                v[i] = v.back();
                v.pop_back();
                break;
            }
        if (v.empty()) keys_by_unit_.erase(u);
    }

    /* `shared_ptr` y no `unique_ptr`, y no es un detalle: el gestor entrega
     * REFERENCIAS a lo que guarda, y la invalidacion cascadea por dependencias
     * que CRUZAN funciones -- calcular points-to de `f` pide rangos de `g`, asi
     * que invalidar `g` puede borrar entradas de `f`.  Con varios hilos, uno
     * puede borrar justo lo que otro esta leyendo.
     *
     * Con `shared_ptr`, borrar del mapa solo suelta LA referencia del mapa: el
     * objeto sigue vivo mientras alguien lo tenga cogido (ver `retained_`).  Es
     * el mismo remedio que ya usa `rangos_de` en el motor de rangos. */
    std::unordered_map<Key, std::shared_ptr<AnalysisResultConcept>, KeyHash>
        results_;

    /* Lo que ESTE hilo tiene cogido.  Cada referencia entregada se respalda
     * aqui para que una cascada de otro hilo no pueda destruirla debajo.  Se
     * suelta en un punto seguro -- cuando el llamante termina con la unidad --
     * via `release_retained()`. */
    static std::vector<std::shared_ptr<AnalysisResultConcept>> &retained() {
        // Estatico LOCAL de funcion, no miembro `static inline thread_local`:
        // con MinGW, este ultimo duplica la funcion de inicializacion del TLS
        // en cada unidad de traduccion y el enlace falla.
        static thread_local std::vector<std::shared_ptr<AnalysisResultConcept>>
            v;
        return v;
    }
    std::unordered_map<Key, std::unordered_set<Key, KeyHash>, KeyHash>
        rev_deps_;
    /* Por hilo: una pila de computos en curso describe lo que ESTE hilo esta
     * calculando.  Compartida, dos hilos registrarian sus dependencias contra
     * el computo del otro. */
    static std::vector<Key> &stack() {
        static thread_local std::vector<Key> v; // ver retained()
        return v;
    }
};

} // namespace analysis

#endif // VESTA_ANALYSIS_MANAGER_H
