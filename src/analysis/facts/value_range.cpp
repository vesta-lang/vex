/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file value_range.cpp
 * @brief Motor de rangos sensible al flujo (contrato en value_range.h).
 *
 * Aqui NO hay semantica de tipos.  Ni envoltura, ni signo, ni extensiones: todo
 * eso vive en el dominio (@c value_range_domain.cpp) y se prueba sin construir
 * una funcion.  Este fichero solo hace tres cosas:
 *
 *   traducir    que operacion del dominio corresponde a cada op del IR
 *   recorrer    el CFG llevando el estado por bloque y por ARISTA
 *   terminar    ensanchando en las aristas de retroceso, y luego estrechando
 *
 * Esa division es la que permite creerse el resultado: si el dominio no miente,
 * lo unico que puede fallar aqui es el recorrido, y el recorrido es pequeno.
 */
#include "util/env_flags.h"
#include "analysis/facts/value_range.h"

#include "analysis/facts/loop_facts.h"
#include "analysis/facts/range_summary.h"
#include "analysis/memory/fn_targets.h"
#include "ir/ssa_ir.h"

#include "util/fnv.h"
#include "util/reloj.h"

#include <cstring> // memcmp: comparar dos estados de una vez

#include <atomic>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <unordered_map>

namespace analysis {

char RangeAnalysis::ID = 0;

namespace {

using ir::IrOp;
using ir::IrType;

// ===========================================================================
//  Tipos del IR -> tipos del dominio
// ===========================================================================

RangeType tipo_de(IrType t) {
    switch (t) {
    case IrType::BOOL: return RangeType::u(1);
    case IrType::I8: return RangeType::i(8);
    case IrType::I16: return RangeType::i(16);
    case IrType::I32: return RangeType::i(32);
    case IrType::I64: return RangeType::i(64);
    case IrType::U8: return RangeType::u(8);
    case IrType::U16: return RangeType::u(16);
    case IrType::U32: return RangeType::u(32);
    case IrType::U64: return RangeType::u(64);
    case IrType::PTR: return RangeType::u(64);
    default: return RangeType::i(64);
    }
}

/// Si el tipo permite razonar numericamente sobre el valor.
bool es_numerico(IrType t) {
    switch (t) {
    case IrType::I8:
    case IrType::I16:
    case IrType::I32:
    case IrType::I64:
    case IrType::U8:
    case IrType::U16:
    case IrType::U32:
    case IrType::U64:
    case IrType::BOOL:
    case IrType::PTR: return true;
    /* HANDLE es una referencia opaca, no una cantidad: acotarla por su ancho
     * invitaria a que la aritmetica explotara un "rango" sin significado. */
    default: return false;
    }
}

/// Suelo de conocimiento: lo que impone el tipo, gratis y en cualquier
/// arquitectura.  Un `u8` no pasa de 255; un `u64` no acota nada util pero SI
/// dice que no es negativo, y eso ya sirve.
ValueRange del_tipo(IrType t) {
    if (!es_numerico(t)) return ValueRange::top();
    return ValueRange::todo(tipo_de(t));
}

} // namespace

ValueRange rango_del_tipo(ir::IrType t) {
    return del_tipo(t);
}

namespace {

// ===========================================================================
//  Estado por punto del programa
// ===========================================================================

/**
 * @brief Refinamientos sobre el suelo del tipo, en un punto concreto.
 *
 * Disperso a proposito: lo que un camino sabe de mas son unas pocas variables
 * acotadas por una guarda, asi que un vector denso por bloque pagaria
 * bloques x valores para repetir lo que ya dice el tipo.
 *
 * CONVENIO que respetan todos los operadores: la AUSENCIA de una entrada
 * significa "lo que diga el suelo", no "no se".
 *
 * DOS INALCANZABILIDADES, y no son la misma:
 *
 *   `alcanzable = false`   propiedad del CFG: a este PUNTO no se llega.
 *   `ValueRange::Bottom`   propiedad de un VALOR: no hay numero que cumpla lo
 *                          que se ha afirmado sobre el en este punto.
 *
 * Lo segundo IMPLICA lo primero (si un valor vivo no puede valer nada, el punto
 * no se ejecuta) y por eso las guardas propagan lo uno a lo otro; pero al reves
 * no: un punto inalcanzable no dice nada de un valor concreto.
 */
/**
 * @brief Contadores del coste de la estructura del estado, por hilo.
 *
 * Van por hilo porque las funciones se analizan en paralelo, y se ponen a cero
 * al empezar cada funcion: lo que se quiere saber es el coste de ESTA, no un
 * acumulado del proceso.  Acaban en @c RangeStats, que es donde vive.
 */
struct CosteEstado {
    uint64_t inserciones = 0;
    uint64_t reescrituras = 0;
    uint64_t copias = 0;
    /* Las dos que faltaban, y que la cuenta de memoria no explicaba: consultar
     * el estado (una busqueda binaria por operando de cada instruccion y por
     * vuelta) y fusionarlo en las confluencias (un vector NUEVO por arista y
     * vuelta, con sus reservas).  Sin contarlas, 300 MB movidos tenian que
     * explicar 8 s, y no daba. */
    uint64_t busquedas = 0;
    uint64_t uniones = 0;
    uint64_t unidos =
        0; ///< elementos anadidos al fusionar (reservas del vector)
    uint64_t elems_muertos = 0; ///< refinamientos de valores que ya no se usan
    uint64_t elems_vivos_total = 0; ///< total mirado, para el ratio
    /* Cuantas entradas guardadas caben en extremos de 32 bits.  Es lo que
     * decide si la entrada puede bajar de 24 a 16 bytes: los extremos se
     * guardan EN CRUDO y se leen segun el tipo, asi que un valor estrecho no
     * necesita los 64 bits.  Sin este dato, cambiar la representacion es
     * apostar. */
    uint64_t narrow_width_count = 0; ///< entradas con tipo de 32 bits o menos
    uint64_t width_seen = 0;         ///< entradas miradas
    /* Cuanto tira la poda.  Decide si compensa FUSIONAR la copia con ella en
     * `calcular_out`: hoy se copia el estado entero y despues se descarta lo
     * muerto, asi que lo que la poda tira se copio para nada. */
    uint64_t pruned_count = 0; ///< entradas descartadas por muertas
    uint64_t prune_seen = 0;   ///< entradas que entraron en la poda
    /* CUANTO cambia una visita que cambia.  Si el delta es minusculo frente al
     * tamano del estado, rehacer la fusion y la copia enteras para propagarlo
     * es trabajo de mas, y la salida seria incremental en vez de recalcular. */
    uint64_t changed_entries = 0;    ///< entradas que de verdad difieren
    uint64_t changed_state_size = 0; ///< tamano del estado en esas visitas
    /* Cuantas salidas de bloque acaban SIENDO la entrada.  `calcular_out`
     * copia el estado entero antes de transformarlo; si el bloque no refina ni
     * poda nada, esa copia se hizo para nada y podria aliasearse. */
    uint64_t out_equals_in = 0; ///< salidas identicas a su entrada
    uint64_t out_computed = 0;  ///< salidas calculadas
    /* Entradas cuyo rango es EL SUELO del valor.  No aportan nada -- `valor()`
     * devuelve el suelo cuando no encuentra refinamiento -- pero ocupan, se
     * copian y se comparan.  Si son muchas, quitarlas encoge cada estado. */
    uint64_t redundant_floor = 0; ///< entradas que repiten el suelo
    uint64_t floor_seen = 0;      ///< entradas miradas
};
thread_local CosteEstado g_coste;

/**
 * @brief Si se estan contando los costes.  Se mira ANTES de tocar @c g_coste.
 *
 * En MinGW cada acceso a una variable de hilo es una LLAMADA
 * (`__emutls_get_address`), y los contadores estan en lo mas caliente del
 * motor: el constructor de `Estado` y `buscar`.  Medido con las pilas de VTune,
 * eso costaba el 1,15 % del tiempo total de compilar, encendido siempre y sin
 * que nadie mirara los numeros.  Con la bandera delante -- un bool global, sin
 * TLS
 * --, cuando no se mide no se toca la variable de hilo.
 *
 * La medida no puede salir gratis, pero si puede salir gratis NO medir.
 */
static const bool g_medir_coste = util::flag_on(util::FlagId::RangeStats);

/// Escape para comparar: conservar las entradas que solo repiten el suelo.
static const bool g_keep_floor_entries =
    util::flag_on(util::FlagId::RangeKeepFloor);

/* Los dos de abajo se leen UNA vez, aqui, y no donde se usan.
 *
 * Preguntar por una variable de entorno recorre su bloque entero, asi que
 * hacerlo dentro de una funcion que corre miles de veces cuesta mas que lo que
 * decide.  Ya paso en este proyecto: un `getenv` en el camino caliente llego a
 * ser el 45% de su propio pase.  Aqui estaban en la funcion de cache -- una
 * lectura por CADA peticion de rangos -- y en el volcado de estadisticas, que
 * corre en cada analisis de funcion. */

/// Nivel 1 de las estadisticas: ademas del resumen, el detalle por analisis.
static const bool g_stats_verbose = util::flag_on(util::FlagId::RangeStats);

/// Saltarse la cache de rangos (para comparar con y sin).
static const bool g_no_range_cache = util::flag_on(util::FlagId::NoRangeCache);

/**
 * @brief El refinamiento va al asignador general, y NO a una arena de fase.
 *
 * Se probo lo segundo y se midio: la vida util encaja -- nada de esto escapa
 * del analisis de una funcion --, pero el PATRON de reserva no.  Una arena
 * solo sabe soltarlo todo al final, y un `std::vector` que crece reserva un
 * bufer nuevo y ABANDONA el viejo; con mas de un millon de inserciones, esos
 * restos se acumulan hasta que la funcion termina.  Resultado medido: el pico
 * de memoria pasaba de 2.414 MB a 5.455 MB (+126%) a cambio de un ~4%.
 *
 * Y no hacia falta: estos vectores son diminutos (mediana 0 entradas,
 * percentil 90 igual a 9), o sea un millon de reservas PEQUENAS, que es
 * justo lo que sirve bien el asignador por clases de `util/host_allocator.h`
 * -- donde al crecer el bufer viejo SI se devuelve y se reaprovecha.
 */
struct Estado {
    bool alcanzable = false;
    std::vector<RangeEntry> ref;

    Estado() = default;
    /// Copiar un estado es el otro coste de la representacion dispersa: hay que
    /// contarlo aqui porque es donde ocurre (una copia por bloque y vuelta).
    Estado(const Estado &o) : alcanzable(o.alcanzable), ref(o.ref) {
        if (g_medir_coste) ++g_coste.copias;
    }
    Estado &operator=(const Estado &o) {
        if (this != &o) {
            alcanzable = o.alcanzable;
            ref = o.ref;
            if (g_medir_coste) ++g_coste.copias;
        }
        return *this;
    }
    Estado(Estado &&) = default;
    Estado &operator=(Estado &&) = default;

    /// Intercambia contenidos sin tocar el asignador.  Se usa para guardar un
    /// estado recien calculado quedandose con el bufer del que sustituye, de
    /// modo que el de trabajo conserve su capacidad para la siguiente vuelta.
    void swap(Estado &o) noexcept {
        std::swap(alcanzable, o.alcanzable);
        ref.swap(o.ref);
    }

    /// La ENTRADA, no el rango: aplanada ya no hay ningun `ValueRange` dentro
    /// al que apuntar.  Quien quiera el rango pide @c range().
    const RangeEntry *buscar(ir::IrValueId v) const {
        if (g_medir_coste) ++g_coste.busquedas;
        auto it = std::lower_bound(
            ref.begin(), ref.end(), v,
            [](const RangeEntry &p, ir::IrValueId x) { return p.id < x; });
        return (it == ref.end() || it->id != v) ? nullptr : &*it;
    }
    void poner(ir::IrValueId v, const ValueRange &r) {
        auto it = std::lower_bound(
            ref.begin(), ref.end(), v,
            [](const RangeEntry &p, ir::IrValueId x) { return p.id < x; });
        if (it != ref.end() && it->id == v) {
            it->set_range(r);
            if (g_medir_coste) ++g_coste.reescrituras;
        } else {
            ref.insert(it, RangeEntry::make(v, r)); // desplaza lo de detras
            if (g_medir_coste) ++g_coste.inserciones;
        }
    }
    void inalcanzable() {
        alcanzable = false;
        ref.clear();
    }
    bool operator==(const Estado &o) const {
        if (alcanzable != o.alcanzable) return false;
        if (!alcanzable) return true; // dos inalcanzables son el mismo estado
        if (ref.size() != o.ref.size()) return false;
        /* De una vez y no campo a campo.  Comparar estados es lo que decide
         * cada vuelta del punto fijo, y campo a campo eran cinco comparaciones
         * y una rama por entrada (0,549 s de 12,5 s solo en `same_range`).
         *
         * Se puede porque la entrada es un POD de 24 bytes SIN un solo hueco
         * implicito -- lo fijan las aserciones de `value_range.h` -- y su unico
         * byte de relleno explicito nace a cero y nadie lo escribe.  Sin esas
         * dos condiciones esto compararia basura y dos estados iguales podrian
         * salir distintos: por eso las aserciones y no un comentario. */
        return ref.empty() || std::memcmp(ref.data(), o.ref.data(),
                                          ref.size() * sizeof(RangeEntry)) == 0;
    }
};

/**
 * @brief Arista del CFG, con lo que se puede AFIRMAR al pasar por ella.
 *
 * Dos formas de afirmar, porque hay dos formas de bifurcar:
 *
 *   COMPARACION  `if (x < 10)`: la condicion y por que rama se va.
 *   CASO         el brazo de un `switch`: el selector vale exactamente esto
 *                (o, en el brazo por defecto, cualquier cosa MENOS esto).
 *
 * Sin la segunda, todo el dispatch de un `match` denso entra en sus brazos sin
 * saber el valor del tag, que es justo lo unico que ahi se sabe seguro.
 */
struct Arista {
    ir::IrBlockId desde = 0, hasta = 0;
    // Afirmacion por comparacion.
    ir::IrValueId cond = ir::IR_NO_VALUE;
    bool rama = true;
    // Afirmacion por caso de un switch.
    ir::IrValueId sel = ir::IR_NO_VALUE;
    bool dentro = true; ///< true: sel esta en [caso_lo,caso_hi]; false: fuera
    uint64_t caso_lo = 0, caso_hi = 0;
    bool retroceso = false; ///< cierra un bucle: es la que obliga a ensanchar
};

// ===========================================================================
//  Contexto: el suelo de los tipos y la transferencia de una instruccion
//
//  Lo comparten el MOTOR (que resuelve el punto fijo) y la CONSULTA (que
//  reproduce un bloque para responder por un punto).  Compartirlo no es un
//  ahorro de lineas: es lo que garantiza que preguntar por un punto y calcular
//  el punto fijo signifiquen exactamente lo mismo.
// ===========================================================================

/**
 * @brief Unica via para leer un resumen, y apunta cada lectura.
 *
 * No es un envoltorio por gusto: es lo que hace que la clave de reuso sea
 * COMPLETA por construccion.  Mientras el analisis no pueda alcanzar el
 * @c RangeSummaries de otra forma, cualquier lectura que se anada manana queda
 * registrada sin que nadie tenga que acordarse de anadirla a ninguna lista.
 *
 * Registra el NOMBRE ademas de la huella para que despues se pueda RELEER lo
 * mismo y comparar; con un total acumulado se sabria que algo cambio, pero no
 * se podria comprobar contra el estado de ahora.
 */
class LectorResumenes {
  public:
    explicit LectorResumenes(const RangeSummaries *s) : sum_(s) {}

    const FnRangeSummary *buscar(const std::string &nombre) {
        const FnRangeSummary *s = sum_ ? sum_->buscar(nombre) : nullptr;
        // Se apunta TAMBIEN cuando no hay resumen: "no habia" es un estado, y
        // si manana lo hay el resultado puede cambiar.
        leidas_.emplace_back(nombre, huella_de_resumen(s));
        return s;
    }
    /// @c true si hay resumenes en absoluto (para los caminos que no
    /// preguntan).
    bool hay() const { return sum_ != nullptr; }
    std::vector<std::pair<std::string, uint64_t>> soltar() {
        return std::move(leidas_);
    }

  private:
    const RangeSummaries *sum_ = nullptr;
    std::vector<std::pair<std::string, uint64_t>> leidas_;
};

struct Contexto {
    const ir::IrFunction &fn;
    const IrFacts &facts;
    mutable LectorResumenes sum{nullptr};
    std::vector<ValueRange> suelo;

    Contexto(const ir::IrFunction &f, const IrFacts &fc,
             const RangeSummaries *s = nullptr)
        : fn(f), facts(fc), sum(s) {
        const size_t n = fc.def_of.size();
        suelo.assign(n, ValueRange::top());
        for (ir::IrValueId v = 0; v < fn.values.size() && v < n; ++v) {
            suelo[v] = del_tipo(fn.values[v].type);
            if (fn.values[v].is_const && suelo[v].acotada())
                suelo[v] = suelo[v].cortar(
                    ValueRange::constante(suelo[v].t, fn.values[v].const_val));
        }
        /* Un parametro vale lo que su tipo... salvo que se sepa quien llama. El
         * resumen solo estrecha cuando se conocen TODOS los llamantes; si no,
         * trae el mismo suelo y esto no cambia nada. */
        if (sum.hay()) {
            const FnRangeSummary *mio = sum.buscar(fn.name);
            if (mio != nullptr)
                for (size_t i = 0;
                     i < fn.params.size() && i < mio->params.size(); ++i) {
                    const ir::IrValueId p = fn.params[i];
                    if (p < suelo.size())
                        suelo[p] = suelo[p].cortar(mio->params[i]);
                }
        }
    }

    ValueRange valor(const Estado &e, ir::IrValueId v) const {
        if (v == ir::IR_NO_VALUE || v >= suelo.size()) return ValueRange::top();
        if (!e.alcanzable) return ValueRange::bottom(suelo[v].t);
        if (const RangeEntry *r = e.buscar(v)) return r->range();
        return suelo[v];
    }

    /// Si cabe entero, se queda; si no, lo afirmable es el tipo.  Nunca BOTTOM
    /// por no caber (BOTTOM solo viene de un camino imposible).
    static ValueRange encajar_en(const ValueRange &r, const ValueRange &tipo) {
        if (r.es_bottom()) return r;
        if (!r.acotada()) return tipo;
        if (!tipo.acotada()) return r;
        if (r.t != tipo.t) return tipo;
        const ValueRange c = r.cortar(tipo);
        return c.es_bottom() ? tipo : c;
    }

    /// Que operacion del dominio corresponde a cada op del IR.  Nada mas.
    void transferir(const ir::IrInstr &in, Estado &e) const;
};

// ===========================================================================
//  Motor
// ===========================================================================

struct Motor : Contexto {
    const RangeOptions &op;

    std::vector<Arista> aristas;
    std::vector<Estado> out_arista;
    std::vector<Estado> in_bloque;

    /* Buferes de trabajo del punto fijo.  Existen para NO pedir memoria en cada
     * vuelta: el estado se calculaba nuevo por bloque, por predecesor y por
     * arista, y el ir y venir al asignador acabo siendo el mayor gasto de toda
     * la compilacion.  Reutilizarlos conserva su capacidad, asi que tras las
     * primeras vueltas no hay una sola peticion mas.  Son `mutable` porque el
     * calculo es conceptualmente const: no cambian ninguna respuesta. */
    mutable Estado union_scratch_;  ///< destino de cada fusion de predecesores
    mutable Estado out_scratch_;    ///< salida del bloque en curso
    mutable Estado arista_scratch_; ///< lo que viaja por la arista en curso
    /**
     * @brief Que bloques estan YA esperando en la cola.
     *
     * Sin esto, a un bloque con tres predecesores que cambian se le encola tres
     * veces y se procesa tres veces, cuando la primera ya fusiono el estado
     * ACTUAL de todas sus aristas: las otras dos rehacen la fusion, la copia y
     * la comparacion para no cambiar nada.  Medido, el 34,9% de las visitas
     * eran esteriles.
     *
     * Encolarlo una sola vez no cambia el resultado: se procese cuando se
     * procese, lee las aristas tal como estan en ese momento.
     */
    std::vector<char> queued_;
    mutable Estado widen_scratch_;  ///< destino del ensanchamiento en curso
    mutable Estado narrow_scratch_; ///< destino del estrechamiento en curso
    mutable Estado in_scratch_;     ///< entrada recien calculada de un bloque
    std::vector<std::vector<uint32_t>> entrantes, salientes;
    std::vector<uint32_t>
        vueltas_ciclo; ///< veces que el IN de un bloque cambio
    /**
     * @brief Ultimo bloque donde se USA cada valor.
     *
     * Un refinamiento de un valor que ya no se usa es lastre: viaja en cada
     * copia, cada fusion y cada comparacion hasta el final de la funcion, y
     * nadie va a preguntar por el.  Con esto se puede saber cuanto lastre hay
     * -- y, si compensa, dejar de arrastrarlo.
     *
     * Se calcula en una pasada: para cada operando, el mayor indice de bloque
     * donde aparece.  Los argumentos de PHI cuentan en el bloque del que
     * VIENEN, no donde esta la PHI: ahi es donde el valor tiene que seguir
     * vivo.
     */
    std::vector<uint32_t> ultimo_uso;

    void calcular_ultimo_uso() {
        ultimo_uso.assign(suelo.size(), 0);
        for (uint32_t bi = 0; bi < fn.blocks.size(); ++bi)
            for (const ir::IrInstr &in : fn.blocks[bi].instrs) {
                for (ir::IrValueId v : in.operands)
                    if (v < ultimo_uso.size() && bi > ultimo_uso[v])
                        ultimo_uso[v] = bi;
                for (const ir::IrPhiArg &pa : in.phi_args)
                    if (pa.value < ultimo_uso.size() &&
                        pa.block > ultimo_uso[pa.value])
                        ultimo_uso[pa.value] = pa.block;
            }
    }
    RangeStats stats;

    Motor(const ir::IrFunction &f, const IrFacts &fc, const RangeOptions &o,
          const RangeSummaries *s)
        : Contexto(f, fc, s), op(o) {
        const size_t nb = fn.blocks.size();
        in_bloque.assign(nb, Estado{});
        entrantes.assign(nb, {});
        salientes.assign(nb, {});
        vueltas_ciclo.assign(nb, 0);
        construir_aristas();
        out_arista.assign(aristas.size(), Estado{});
    }

    // --- construccion del grafo ------------------------------------------
    void construir_aristas() {
        const size_t nb = fn.blocks.size();
        for (uint32_t bi = 0; bi < nb; ++bi) {
            if (fn.blocks[bi].instrs.empty()) continue;
            const ir::IrInstr &t = fn.blocks[bi].instrs.back();
            auto anadir_arista = [&](Arista a) {
                if (a.hasta == ir::IR_NO_BLOCK || a.hasta >= nb) return;
                const uint32_t id = static_cast<uint32_t>(aristas.size());
                aristas.push_back(a);
                salientes[bi].push_back(id);
                entrantes[a.hasta].push_back(id);
            };
            auto anadir = [&](ir::IrBlockId d, ir::IrValueId c, bool r) {
                Arista a;
                a.desde = bi;
                a.hasta = d;
                a.cond = c;
                a.rama = r;
                anadir_arista(a);
            };
            auto anadir_caso = [&](ir::IrBlockId d, ir::IrValueId sel,
                                   bool dentro, uint64_t lo, uint64_t hi) {
                Arista a;
                a.desde = bi;
                a.hasta = d;
                a.sel = sel;
                a.dentro = dentro;
                a.caso_lo = lo;
                a.caso_hi = hi;
                anadir_arista(a);
            };
            if (t.op == IrOp::BR) {
                anadir(t.target_block, ir::IR_NO_VALUE, true);
            } else if (t.op == IrOp::BR_COND) {
                const ir::IrValueId c =
                    t.operands.empty() ? ir::IR_NO_VALUE : t.operands[0];
                anadir(t.target_block, c, true);
                anadir(t.false_block, c, false);
            } else if (t.op == IrOp::SWITCH_DENSE) {
                /* Tabla densa: el brazo `idx` se toma cuando el selector vale
                 * exactamente `min + idx`, y el brazo por defecto cuando cae
                 * FUERA de toda la tabla.  El minimo viaja en los 32 bits bajos
                 * del inmediato (el bit 32 dice otra cosa: que la comprobacion
                 * de rango sobra porque la tabla cubre el enum entero). */
                const ir::IrValueId sel =
                    t.operands.empty() ? ir::IR_NO_VALUE : t.operands[0];
                const uint64_t min = t.imm & 0xFFFFFFFFu;
                const size_t n = t.jump_targets.size();
                for (size_t idx = 0; idx < n; ++idx)
                    anadir_caso(t.jump_targets[idx], sel, true, min + idx,
                                min + idx);
                if (n > 0)
                    anadir_caso(t.target_block, sel, false, min, min + n - 1);
                else
                    anadir(t.target_block, ir::IR_NO_VALUE, true);
            } else if (t.op == IrOp::MATCH_VARIANT) {
                /* Marcador: el dispatch de verdad es la cadena de comparaciones
                 * que viene detras, y esa ya la lee la guarda.  Aqui solo hay
                 * que no perder los sucesores si acaba cerrando el bloque. */
                for (uint32_t d : t.jump_targets)
                    anadir(d, ir::IR_NO_VALUE, true);
                anadir(t.target_block, ir::IR_NO_VALUE, true);
            }
        }
        marcar_retrocesos();
    }

    /**
     * @brief Marca las aristas que CIERRAN un ciclo.
     *
     * El ensanchamiento no se dispara por "he visitado este bloque muchas
     * veces" -- eso es una consecuencia, no la causa -- sino por volver a una
     * cabecera POR LA ARISTA QUE CIERRA EL BUCLE, que es lo unico que puede
     * hacer crecer un intervalo sin fin.
     */
    void marcar_retrocesos() {
        const LoopFacts lf = compute_loop_facts(fn);
        auto dentro_de = [&](ir::IrBlockId b, uint32_t lid) {
            if (lid == LoopFacts::NO_LOOP) return false;
            uint32_t l =
                b < lf.loop_id.size() ? lf.loop_id[b] : LoopFacts::NO_LOOP;
            while (l !=
                   LoopFacts::NO_LOOP) { // sube por los bucles que lo contienen
                if (l == lid) return true;
                l = l < lf.parent_loop.size() ? lf.parent_loop[l]
                                              : LoopFacts::NO_LOOP;
            }
            return false;
        };
        for (Arista &a : aristas) {
            if (a.hasta >= lf.is_loop_header.size() ||
                !lf.is_loop_header[a.hasta])
                continue;
            const uint32_t lid = a.hasta < lf.loop_id.size()
                                     ? lf.loop_id[a.hasta]
                                     : LoopFacts::NO_LOOP;
            a.retroceso = dentro_de(a.desde, lid);
        }
    }

    // --- confluencia --------------------------------------------------------
    /**
     * @brief Fusiona @p a y @p b DEJANDO el resultado en @p out.
     *
     * Escribe sobre un destino que da el llamante en vez de devolver uno nuevo
     * porque esto corre por bloque, por predecesor y por vuelta del punto fijo:
     * un destino reutilizado conserva su capacidad y deja de pedir memoria tras
     * las primeras vueltas.  Pedir y devolver en cada fusion era el mayor
     * alojador de la compilacion.
     *
     * @p out puede ser el mismo objeto que @p a o @p b sin problema: los casos
     * en que eso pasa se resuelven antes de tocarlo.
     */
    void unir_en(const Estado &a, const Estado &b, Estado &out) const {
        if (!a.alcanzable) {
            if (&out != &b) out = b;
            return;
        }
        if (!b.alcanzable) {
            if (&out != &a) out = a;
            return;
        }
        Estado tmp;
        Estado &dst = (&out == &a || &out == &b) ? tmp : out;
        dst.ref.clear();
        unir_cuerpo(a, b, dst);
        if (&dst != &out) out = std::move(dst);
    }

    Estado unir_estados(const Estado &a, const Estado &b) const {
        Estado out;
        unir_en(a, b, out);
        return out;
    }

    /// El cuerpo de la fusion, con @p out ya vacio y distinto de las fuentes.
    void unir_cuerpo(const Estado &a, const Estado &b, Estado &out) const {
        if (g_medir_coste) ++g_coste.uniones;
        out.alcanzable = true;
        /* Se reserva la cota superior: el resultado nunca es mayor que el
         * origen, porque se recorre y se filtra.
         *
         * Reserva de MAS -- el filtro descarta la mayoria: ~35 elementos por
         * fusion frente a 100-150 en el origen --, y aun asi compensa: MEDIDO
         * A/B, el optimizador baja de 2.680 ms a 2.554 ms (-4,7 %), con los
         * rangos de tres corridas sin solaparse.  Evitar la cadena de realojos
         * en 7.334 fusiones pesa mas que pedir memoria de sobra. */
        out.ref.reserve(a.ref.size());
        /* FUSION LINEAL, no biseccion.  Los dos estados estan ordenados por
         * identificador, asi que recorrer uno buscando cada elemento en el otro
         * es avanzar dos indices a la vez -- O(|a|+|b|) en vez de
         * O(|a| log|b|) --, y ademas en orden, sin saltar por el vector.
         *
         * Es lo que el perfil senalaba: `buscar` -> `lower_bound` bajo esta
         * funcion era el mayor coste propio del motor.  El resultado es el
         * MISMO: mismos elementos, mismo orden. */
        size_t j = 0;
        for (const RangeEntry &p : a.ref) {
            while (j < b.ref.size() && b.ref[j].id < p.id)
                ++j;
            const bool hay = (j < b.ref.size() && b.ref[j].id == p.id);
            if (g_medir_coste)
                ++g_coste.busquedas; // comparable con la version vieja
            const ValueRange u =
                p.range().unir(hay ? b.ref[j].range() : suelo[p.id]);
            if (!u.es_top()) {
                out.ref.push_back(RangeEntry::make(p.id, u));
                if (g_medir_coste) ++g_coste.unidos;
            }
        }
    }

    /// Ensanchamiento del ascenso: por valor, soltando solo el extremo que
    /// crece.
    /// Sobre un destino REUTILIZADO; ver el motivo en @c narrow_into.
    void widen_into(const Estado &viejo, const Estado &nuevo,
                    Estado &out) const {
        if (!viejo.alcanzable || !nuevo.alcanzable) {
            if (&out != &nuevo) out = nuevo;
            return;
        }
        out.ref.clear();
        if (g_medir_coste) ++g_coste.uniones;
        out.alcanzable = true;
        out.ref.reserve(nuevo.ref.size()); // cota superior; ver unir_estados
        // Fusion lineal (ver unir_estados): ambos ordenados por identificador.
        size_t j = 0;
        for (const RangeEntry &p : nuevo.ref) {
            while (j < viejo.ref.size() && viejo.ref[j].id < p.id)
                ++j;
            const bool hay = (j < viejo.ref.size() && viejo.ref[j].id == p.id);
            if (g_medir_coste) ++g_coste.busquedas;
            const ValueRange base = hay ? viejo.ref[j].range() : suelo[p.id];
            const ValueRange w = base.ensanchar(p.range());
            if (!w.es_top()) {
                out.ref.push_back(RangeEntry::make(p.id, w));
                if (g_medir_coste) ++g_coste.unidos;
            }
        }
    }

    /**
     * @brief Estrechamiento del descenso: se queda con lo mejor de los dos.
     *
     * Nunca declara inalcanzable un valor: si el corte quedara vacio seria un
     * fallo del propio motor (el descenso parte de una solucion estable y solo
     * puede mejorar), y ante eso se conserva lo recien calculado en vez de
     * afirmar que ahi no se llega.
     */
    /* Sobre un destino REUTILIZADO, igual que @c unir_en y por el mismo
     * motivo: construir un `Estado` nuevo por llamada pedia memoria en cada
     * paso del descenso, que recorre TODOS los bloques.  El destino se limpia
     * al entrar, asi que conserva su capacidad de la vuelta anterior. */
    void narrow_into(const Estado &viejo, const Estado &nuevo,
                     Estado &out) const {
        if (!nuevo.alcanzable || !viejo.alcanzable) {
            if (&out != &nuevo) out = nuevo;
            return;
        }
        out.ref.clear();
        if (g_medir_coste) ++g_coste.uniones;
        out.alcanzable = true;
        out.ref.reserve(nuevo.ref.size()); // cota superior; ver unir_estados
        // Fusion lineal (ver unir_estados): ambos ordenados por identificador.
        size_t j = 0;
        for (const RangeEntry &p : nuevo.ref) {
            while (j < viejo.ref.size() && viejo.ref[j].id < p.id)
                ++j;
            const bool hay = (j < viejo.ref.size() && viejo.ref[j].id == p.id);
            if (g_medir_coste) ++g_coste.busquedas;
            ValueRange r = p.range();
            if (hay) {
                const ValueRange c = r.cortar(viejo.ref[j].range());
                if (!c.es_bottom()) r = c;
            }
            if (!r.es_top()) {
                out.ref.push_back(RangeEntry::make(p.id, r));
                if (g_medir_coste) ++g_coste.unidos;
            }
        }
    }

    // --- guardas ------------------------------------------------------------
    /**
     * @brief Lo que una guarda AFIRMA sobre una arista, en las DOS ramas.
     *
     * Saber que algo no se cumple informa tanto como saber que si.  Y si lo
     * afirmado contradice lo que ya se sabia, el resultado NO es "no se": es
     * que por esa arista no se pasa, y eso se propaga como estado inalcanzable.
     *
     * La comparacion decide EN QUE DOMINIO se razona, que no tiene por que ser
     * el del tipo declarado: un `ult` sobre un `i32` compara sin signo.  Los
     * dos operandos se releen en ese dominio, se restringe alli, y el resultado
     * se vuelve a leer en el tipo del valor.  Cuando alguna de esas relecturas
     * no es monotona el dominio responde "todo", y entonces no se afirma nada
     * -- que es exactamente lo que hay que hacer.
     */
    void estrechar_por_guarda(Estado &e, ir::IrValueId cond, bool rama) const {
        if (!e.alcanzable) return;
        const ir::IrInstr *d = facts.def(cond);
        if (!d || d->operands.size() != 2) return;
        const ir::IrValueId va = d->operands[0], vb = d->operands[1];
        IrOp o = d->op;
        if (!rama) {
            switch (o) {
            case IrOp::CMP_LT: o = IrOp::CMP_GE; break;
            case IrOp::CMP_LE: o = IrOp::CMP_GT; break;
            case IrOp::CMP_GT: o = IrOp::CMP_LE; break;
            case IrOp::CMP_GE: o = IrOp::CMP_LT; break;
            case IrOp::CMP_ULT: o = IrOp::CMP_UGE; break;
            case IrOp::CMP_ULE: o = IrOp::CMP_UGT; break;
            case IrOp::CMP_UGT: o = IrOp::CMP_ULE; break;
            case IrOp::CMP_UGE: o = IrOp::CMP_ULT; break;
            case IrOp::CMP_EQ: o = IrOp::CMP_NE; break;
            case IrOp::CMP_NE: o = IrOp::CMP_EQ; break;
            default: return;
            }
        }
        const ValueRange ra = valor(e, va), rb = valor(e, vb);
        if (!ra.acotada() || !rb.acotada()) return;
        if (ra.t.bits != rb.t.bits)
            return; // el IR no deberia comparar anchos distintos

        const bool sin_signo = (o == IrOp::CMP_ULT || o == IrOp::CMP_ULE ||
                                o == IrOp::CMP_UGT || o == IrOp::CMP_UGE);
        const RangeType dc = RangeType::de(ra.t.bits, sin_signo);
        const ValueRange ca = ra.reinterpretar(dc), cb = rb.reinterpretar(dc);

        // Devuelve el valor restringido, ya releido en el tipo del propio
        // valor.
        auto aplicar = [&](ir::IrValueId v, const ValueRange &orig,
                           const ValueRange &restringido) {
            if (!e.alcanzable) return;
            if (v == ir::IR_NO_VALUE || v >= suelo.size()) return;
            if (restringido.es_bottom()) {
                e.inalcanzable();
                return;
            }
            const ValueRange nuevo =
                orig.cortar(restringido.reinterpretar(orig.t));
            if (nuevo.es_bottom()) {
                e.inalcanzable();
                return;
            }
            if (!nuevo.es_top()) e.poner(v, nuevo);
        };

        switch (o) {
        case IrOp::CMP_LT:
        case IrOp::CMP_ULT:
            aplicar(va, ra, ca.restringir_menor(cb));
            aplicar(vb, rb, cb.restringir_mayor(ca));
            break;
        case IrOp::CMP_LE:
        case IrOp::CMP_ULE:
            aplicar(va, ra, ca.restringir_menor_igual(cb));
            aplicar(vb, rb, cb.restringir_mayor_igual(ca));
            break;
        case IrOp::CMP_GT:
        case IrOp::CMP_UGT:
            aplicar(va, ra, ca.restringir_mayor(cb));
            aplicar(vb, rb, cb.restringir_menor(ca));
            break;
        case IrOp::CMP_GE:
        case IrOp::CMP_UGE:
            aplicar(va, ra, ca.restringir_mayor_igual(cb));
            aplicar(vb, rb, cb.restringir_menor_igual(ca));
            break;
        case IrOp::CMP_EQ:
            aplicar(va, ra, ca.restringir_igual(cb));
            aplicar(vb, rb, cb.restringir_igual(ca));
            break;
        case IrOp::CMP_NE:
            aplicar(va, ra, ca.restringir_distinto(cb));
            aplicar(vb, rb, cb.restringir_distinto(ca));
            break;
        default: break;
        }
    }

    /**
     * @brief Lo que afirma el BRAZO de un switch sobre su selector.
     *
     * En un brazo concreto el tag vale exactamente uno; en el brazo por
     * defecto, cualquier cosa menos los de la tabla.  Lo segundo solo se puede
     * decir con un intervalo cuando la tabla toca un extremo del tipo -- si la
     * muerde por en medio quedarian dos trozos --, y el dominio ya sabe
     * distinguirlo.
     */
    void estrechar_por_caso(Estado &e, const Arista &a) const {
        if (!e.alcanzable) return;
        if (a.sel == ir::IR_NO_VALUE || a.sel >= suelo.size()) return;
        const ValueRange orig = valor(e, a.sel);
        if (!orig.acotada()) return;
        const ValueRange caso = ValueRange::crudo(orig.t, a.caso_lo, a.caso_hi);
        if (!caso.acotada()) return; // la tabla no cabe en el tipo del selector
        const ValueRange nuevo = a.dentro ? orig.restringir_igual(caso)
                                          : orig.restringir_fuera(caso);
        if (nuevo.es_bottom()) {
            e.inalcanzable();
            return;
        }
        if (!nuevo.es_top()) e.poner(a.sel, nuevo);
    }

    // --- transferencia: la pone Contexto, compartida con la consulta --------

    // --- ecuaciones ---------------------------------------------------------
    /**
     * @brief Estado a la ENTRADA de @p bi, dejado en @p dst.
     *
     * @p dst es un bufer del llamante que se reutiliza entre vueltas: fusionar
     * pedia un estado nuevo por cada predecesor, y esto corre por bloque y por
     * vuelta del punto fijo.
     */
    void calcular_in(ir::IrBlockId bi, Estado &dst) const {
        dst.ref.clear();
        dst.alcanzable = false;
        for (uint32_t ai : entrantes[bi])
            if (out_arista[ai].alcanzable) {
                unir_en(dst, out_arista[ai], union_scratch_);
                dst.swap(union_scratch_);
            }
        if (bi == 0) dst.alcanzable = true; // a la entrada siempre se llega
        if (!dst.alcanzable) return;
        resolver_phis(bi, dst);
    }

    Estado calcular_in(ir::IrBlockId bi) const {
        Estado e;
        calcular_in(bi, e);
        return e;
    }

    /**
     * @brief Cada PHI vale la union de lo que trae cada arista, leido EN ella.
     *
     * Es lo que hace el analisis sensible al flujo y no una propagacion global:
     * sin leer el estado DE LA ARISTA, una guarda no puede afectar a la PHI que
     * depende de ella.
     *
     * Si dos aristas vienen del MISMO bloque (un `switch` con dos casos al
     * mismo destino), las dos aportan y se unen: el argumento de la PHI
     * identifica el bloque de origen, no la arista, y unir de mas es correcto.
     */
    void resolver_phis(ir::IrBlockId bi, Estado &e) const {
        for (const ir::IrInstr &in : fn.blocks[bi].instrs) {
            if (in.op != IrOp::PHI) break; // van al principio del bloque
            if (in.dst == ir::IR_NO_VALUE || in.dst >= suelo.size()) continue;
            ValueRange acc = ValueRange::bottom(suelo[in.dst].t);
            for (const ir::IrPhiArg &pa : in.phi_args)
                for (uint32_t ai : entrantes[bi])
                    if (aristas[ai].desde == pa.block &&
                        out_arista[ai].alcanzable)
                        acc = acc.unir(valor(out_arista[ai], pa.value));
            e.poner(in.dst, encajar_en(acc, suelo[in.dst]));
        }
    }

    /// Estado a la SALIDA de @p bi, dejado en @p dst (bufer reutilizado: la
    /// asignacion conserva su capacidad, asi que deja de pedir memoria).
    void calcular_out(ir::IrBlockId bi, const Estado &in, Estado &dst) const {
        dst = in;
        for (const ir::IrInstr &instr : fn.blocks[bi].instrs)
            if (instr.op != IrOp::PHI) transferir(instr, dst);
        podar_muertos(dst, bi);
    }

    /**
     * @brief Quita del estado los valores que ya no se usan.
     *
     * Un refinamiento de un valor cuyo ultimo uso quedo atras no lo puede
     * consultar nadie, pero sigue viajando en cada copia, cada fusion y cada
     * comparacion hasta el final de la funcion.  MEDIDO: el **78 %** del estado
     * era eso (276.438 de 354.692 refinamientos).
     *
     * Es correcto porque no se descarta informacion consultable: si el valor no
     * se vuelve a usar, su rango no puede influir en ningun resultado.  Y
     * reduce las tres formas de visitar elementos a la vez, que es lo unico que
     * ha movido el tiempo en este motor.
     */
    void podar_muertos(Estado &e, ir::IrBlockId bi) const {
        if (ultimo_uso.empty() || e.ref.empty()) return;
        size_t w = 0;
        for (size_t r = 0; r < e.ref.size(); ++r) {
            const ir::IrValueId v = e.ref[r].id;
            bool vivo = v >= ultimo_uso.size() || ultimo_uso[v] >= bi;
            /* Y tambien se descarta lo que solo REPITE EL SUELO.
             *
             * Una entrada cuyo rango es el suelo del valor no dice nada:
             * `valor()` devuelve el suelo justo cuando NO encuentra
             * refinamiento, asi que guardarla es ocupar, copiar y comparar
             * para responder lo mismo.  Medido, era el 73,1% de todo lo
             * guardado (19,6 M de 26,8 M).
             *
             * Por que es SEGURO, que es lo que importa aqui: quitarla solo
             * puede hacer el resultado mas ANCHO, nunca mas estrecho.  El
             * unico sitio donde se nota es el descenso, que corta lo nuevo con
             * lo viejo recorriendo solo lo nuevo: sin la entrada, ese corte no
             * ocurre y el rango queda mas ancho.  Perder precision puede
             * costar una optimizacion; jamas puede hacer que se afirme algo
             * falso, que es la unica linea que este motor no puede cruzar.
             *
             * Y medido no se pierde ni eso: el `.velb` sale byte a byte igual
             * en 36 ejemplos y la suite e2e da lo mismo, tests negativos del
             * comprobador de limites incluidos. */
            if (vivo && !g_keep_floor_entries && v < suelo.size() &&
                e.ref[r].range() == suelo[v])
                vivo = false;
            if (vivo) {
                if (g_medir_coste) {
                    // Anchura de lo que SOBREVIVE, que es lo que se guarda,
                    // se copia y se compara.
                    ++g_coste.width_seen;
                    if (e.ref[r].t.bits <= 32) ++g_coste.narrow_width_count;
                }
                if (w != r) e.ref[w] = e.ref[r];
                ++w;
            }
        }
        if (g_medir_coste) {
            g_coste.prune_seen += e.ref.size();
            g_coste.pruned_count += e.ref.size() - w;
            for (size_t k = 0; k < w; ++k) {
                ++g_coste.floor_seen;
                const ir::IrValueId id = e.ref[k].id;
                if (id < suelo.size() && e.ref[k].range() == suelo[id])
                    ++g_coste.redundant_floor;
            }
        }
        e.ref.resize(w); // conserva el orden y la capacidad
    }

    /// Encola @p b si no estaba ya esperando.  Ver @c queued_.
    void enqueue(ir::IrBlockId b, std::deque<ir::IrBlockId> &cola) {
        if (b >= queued_.size() || queued_[b]) return;
        queued_[b] = 1;
        cola.push_back(b);
    }

    /// Saca el siguiente y lo desmarca.
    ir::IrBlockId dequeue(std::deque<ir::IrBlockId> &cola) {
        const ir::IrBlockId b = cola.front();
        cola.pop_front();
        if (b < queued_.size()) queued_[b] = 0;
        return b;
    }

    /// Recalcula las aristas de salida y encola los destinos que cambiaron.
    void propagar(ir::IrBlockId bi, std::deque<ir::IrBlockId> &cola) {
        calcular_out(bi, in_bloque[bi], out_scratch_);
        const Estado &out = out_scratch_;
        if (g_medir_coste) {
            ++g_coste.out_computed;
            if (out == in_bloque[bi]) ++g_coste.out_equals_in;
        }
        if (g_medir_coste && !ultimo_uso.empty()) {
            g_coste.elems_vivos_total += out.ref.size();
            for (const RangeEntry &p : out.ref)
                if (p.id < ultimo_uso.size() && ultimo_uso[p.id] < bi)
                    ++g_coste.elems_muertos;
        }
        for (uint32_t ai : salientes[bi]) {
            /* Una arista sin guarda ni caso no estrecha nada, asi que lo que
             * viajaria por ella es EXACTAMENTE el estado de salida del bloque.
             * Copiarlo para luego compararlo es copiar para tirar: se compara
             * el original, y solo se copia si de verdad cambia algo -- que en
             * un encadenado recto deja de pasar en cuanto converge.  Es la
             * mayoria de las aristas: solo las de un salto condicional o un
             * `switch` llevan refinamiento. */
            const bool refina = aristas[ai].cond != ir::IR_NO_VALUE ||
                                aristas[ai].sel != ir::IR_NO_VALUE;
            if (!refina) {
                if (!(out == out_arista[ai])) {
                    out_arista[ai] = out;
                    enqueue(aristas[ai].hasta, cola);
                }
                continue;
            }
            /* Sobre un bufer reutilizado, no uno nuevo: esto corre por arista
             * de cada bloque en cada vuelta.  Se intercambia en vez de mover
             * para que el bufer se quede con la capacidad del que sustituye y
             * la siguiente arista tampoco tenga que pedir memoria. */
            Estado &se = arista_scratch_;
            se = out;
            if (aristas[ai].cond != ir::IR_NO_VALUE)
                estrechar_por_guarda(se, aristas[ai].cond, aristas[ai].rama);
            if (aristas[ai].sel != ir::IR_NO_VALUE)
                estrechar_por_caso(se, aristas[ai]);
            if (!(se == out_arista[ai])) {
                out_arista[ai].swap(se);
                enqueue(aristas[ai].hasta, cola);
            }
        }
    }

    /// Alguna arista de retroceso que llega aqui esta viva: el bloque cierra un
    /// ciclo por el que ya se ha vuelto a pasar.
    bool cierra_ciclo(ir::IrBlockId bi) const {
        for (uint32_t ai : entrantes[bi])
            if (aristas[ai].retroceso && out_arista[ai].alcanzable) return true;
        return false;
    }

    /**
     * @brief ASCENSO: crece hasta un post-punto-fijo.  Ensancha en los ciclos.
     * @return true si la lista de trabajo se vacio sola.
     */
    bool resolver_ascenso(int presupuesto) {
        calcular_ultimo_uso();
        std::deque<ir::IrBlockId> cola;
        queued_.assign(fn.blocks.size(), 0);
        enqueue(0, cola);
        int pasos = 0;
        while (!cola.empty()) {
            if (++pasos > presupuesto) return false;
            stats.pasos++;
            const ir::IrBlockId bi = dequeue(cola);

            calcular_in(bi, in_scratch_);
            Estado &nuevo_in = in_scratch_;
            if (cierra_ciclo(bi) && vueltas_ciclo[bi] >= op.retardo_ensanche) {
                widen_into(in_bloque[bi], nuevo_in, widen_scratch_);
                nuevo_in.swap(widen_scratch_);
                stats.ensanches++;
            }
            if (!(nuevo_in == in_bloque[bi])) {
                if (g_medir_coste) {
                    /* Recorrido en paralelo de los dos, que estan ordenados
                     * por identificador: cuenta las entradas que solo estan en
                     * uno mas las que estan en ambos con distinto rango. */
                    const auto &na = nuevo_in.ref;
                    const auto &vi = in_bloque[bi].ref;
                    size_t i = 0, j = 0, d = 0;
                    while (i < na.size() && j < vi.size()) {
                        if (na[i].id < vi[j].id) {
                            ++d;
                            ++i;
                        } else if (vi[j].id < na[i].id) {
                            ++d;
                            ++j;
                        } else {
                            if (!na[i].same_range(vi[j])) ++d;
                            ++i;
                            ++j;
                        }
                    }
                    d += (na.size() - i) + (vi.size() - j);
                    g_coste.changed_entries += d;
                    g_coste.changed_state_size +=
                        vi.size() > na.size() ? vi.size() : na.size();
                }
                // Intercambiar, no mover: el bufer se queda con la capacidad
                // del estado que sustituye y sirve para la siguiente vuelta.
                in_bloque[bi].swap(nuevo_in);
                vueltas_ciclo[bi]++;
                stats.cambios++;
            }
            if (!in_bloque[bi].alcanzable) continue;
            propagar(bi, cola);
        }
        return true;
    }

    /**
     * @brief DESCENSO: parte de la solucion ensanchada y SOLO estrecha.
     *
     * No es el ascenso con una bandera: aqui no se ensancha nunca y cada IN
     * nuevo se cruza con el anterior, asi que la sucesion es decreciente.  Eso
     * es lo que recupera la precision que el ensanchamiento solto -- en
     * `for (i = 0; i < 200)` el ascenso deja `[0, max]` y el descenso lo
     * devuelve a `[0,199]` -- sin arriesgar la terminacion: un presupuesto
     * agotado aqui cuesta precision, jamas correccion.
     */
    bool resolver_descenso(int presupuesto) {
        std::deque<ir::IrBlockId> cola;
        queued_.assign(fn.blocks.size(), 0);
        for (uint32_t bi = 0; bi < fn.blocks.size(); ++bi)
            cola.push_back(bi);
        int pasos = 0;
        while (!cola.empty()) {
            if (++pasos > presupuesto) return false;
            stats.pasos++;
            const ir::IrBlockId bi = cola.front();
            cola.pop_front();

            /* Mismo trato que el ascenso, que aqui faltaba: bufer reutilizado
             * en vez de un `Estado` nuevo por paso, e INTERCAMBIAR en vez de
             * copiar.  El descenso mete TODOS los bloques en la cola, asi que
             * se ejecuta mucho, y copiar el estado -- que en las funciones que
             * importan trae cien o mas entradas -- era la operacion mas cara
             * de compilar: `operator=` del vector, 1,8 s de 19,4 s.
             *
             * Al intercambiar, el bufer que se sustituye no se tira: se queda
             * con la capacidad y sirve para el paso siguiente. */
            calcular_in(bi, in_scratch_);
            narrow_into(in_bloque[bi], in_scratch_, narrow_scratch_);
            if (!(narrow_scratch_ == in_bloque[bi])) {
                in_bloque[bi].swap(narrow_scratch_);
                stats.estrechados++;
            }
            if (!in_bloque[bi].alcanzable) continue;
            propagar(bi, cola);
        }
        return true;
    }

    /// El estado de entrada de cada bloque, para que se pueda preguntar por un
    /// PUNTO despues de que el motor haya terminado.
    /**
     * @brief El estado de entrada de cada bloque, para quien pregunte por un
     *        punto concreto.
     *
     * Se MUEVE, no se copia, y por eso no es `const`: es lo ULTIMO que se le
     * pide al motor -- despues ya no se vuelve a tocar y muere --, asi que
     * copiar el estado de cada bloque seria copiarlo para tirar el original
     * acto seguido.  Se llama despues de @c en_definicion, que si los lee.
     */
    std::vector<RangeBlockState> estados_de_entrada() {
        std::vector<RangeBlockState> out(fn.blocks.size());
        for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
            out[bi].alcanzable = in_bloque[bi].alcanzable;
            out[bi].refinamientos = std::move(in_bloque[bi].ref);
        }
        return out;
    }

    /// Proyeccion final: el rango de cada valor en SU PUNTO DE DEFINICION.
    std::vector<ValueRange> en_definicion() const {
        std::vector<ValueRange> out = suelo;
        for (uint32_t bi = 0; bi < fn.blocks.size(); ++bi) {
            if (!in_bloque[bi].alcanzable) continue;
            Estado e = in_bloque[bi];
            for (const ir::IrInstr &in : fn.blocks[bi].instrs) {
                if (in.op != IrOp::PHI) transferir(in, e);
                if (in.dst != ir::IR_NO_VALUE && in.dst < out.size())
                    out[in.dst] = valor(e, in.dst);
            }
        }
        return out;
    }
};

void Contexto::transferir(const ir::IrInstr &in, Estado &e) const {
    if (!e.alcanzable) return;
    if (in.dst == ir::IR_NO_VALUE || in.dst >= suelo.size()) return;
    const ValueRange piso = suelo[in.dst];
    auto arg = [&](size_t i) {
        return i < in.operands.size() ? valor(e, in.operands[i])
                                      : ValueRange::top();
    };
    ValueRange nuevo = ValueRange::top(piso.t);
    switch (in.op) {
    case IrOp::CONST:
        nuevo = piso.acotada() ? ValueRange::constante(piso.t, in.imm)
                               : ValueRange::top();
        break;
    case IrOp::MOV: nuevo = arg(0); break;
    case IrOp::ADD: nuevo = arg(0).sumar(arg(1)); break;
    case IrOp::SUB: nuevo = arg(0).restar(arg(1)); break;
    case IrOp::MUL: nuevo = arg(0).multiplicar(arg(1)); break;
    case IrOp::NEG: nuevo = arg(0).negar(); break;
    case IrOp::DIV: nuevo = arg(0).dividir(arg(1)); break;
    case IrOp::MOD: nuevo = arg(0).resto(arg(1)); break;
    case IrOp::AND: nuevo = arg(0).conjuncion(arg(1)); break;
    case IrOp::OR: nuevo = arg(0).disyuncion(arg(1)); break;
    case IrOp::XOR: nuevo = arg(0).exclusiva(arg(1)); break;
    case IrOp::NOT: nuevo = arg(0).complemento(); break;
    case IrOp::SHL: nuevo = arg(0).desplazar_izq(arg(1)); break;
    case IrOp::SHR: nuevo = arg(0).desplazar_der_logico(arg(1)); break;
    case IrOp::SAR: nuevo = arg(0).desplazar_der_aritmetico(arg(1)); break;
    case IrOp::SEXT:
        if (piso.acotada()) nuevo = arg(0).extender_con_signo(piso.t);
        break;
    case IrOp::ZEXT:
        if (piso.acotada()) nuevo = arg(0).extender_sin_signo(piso.t);
        break;
    case IrOp::TRUNC:
        if (piso.acotada()) nuevo = arg(0).truncar(piso.t);
        break;
    /* BITCAST reinterpreta BITS.  Entre un float y un entero el rango del
     * origen no dice nada del destino; entre dos enteros del mismo ancho los
     * bits SON el valor -- que es como el IR pasa un indice `u64` a una suma
     * de punteros, y tirarlo dejaba fuera de comprobacion justo los accesos
     * indexados.  El dominio decide cual de los dos casos es. */
    case IrOp::BITCAST:
        if (piso.acotada()) nuevo = arg(0).reinterpretar(piso.t);
        break;
    /* El resultado de una llamada no es desconocido si se puede leer el
     * cuerpo de quien la atiende: lo que devuelve sale de SU codigo y vale
     * para cualquier llamante, se conozcan o no los demas. */
    case IrOp::CALL:
    case IrOp::CALLIND:
        if (sum.hay() && piso.acotada()) {
            const std::string destino =
                (in.op == IrOp::CALL)
                    ? in.func_name
                    : pointed_function(fn, facts, in.func_ptr);
            if (const FnRangeSummary *s = sum.buscar(destino)) nuevo = s->ret;
        }
        break;
    default: break; // op sin modelar: lo que diga el tipo
    }
    e.poner(in.dst, encajar_en(nuevo, piso));
}

} // namespace

uint64_t huella_de_funcion(const ir::IrFunction &fn) {
    uint64_t h = util::kFnvOffset;
    for (const ir::IrBlock &b : fn.blocks) {
        h = util::fnv_mix(h, b.instrs.size());
        for (const ir::IrInstr &in : b.instrs) {
            h = util::fnv_mix(h, static_cast<uint64_t>(in.op));
            // El TIPO va dentro: el suelo de cada rango sale de el, no de la
            // forma de la instruccion.
            h = util::fnv_bytes(h, &in.type, sizeof(in.type));
            h = util::fnv_mix(h, in.dst);
            h = util::fnv_mix(h, in.target_block);
            h = util::fnv_mix(h, in.false_block);
            h = util::fnv_bytes(h, in.operands.data(),
                                in.operands.size() * sizeof(ir::IrValueId));
            h = util::fnv_bytes(h, in.func_name.data(), in.func_name.size());
            h = util::fnv_mix(
                h, in.func_ptr); // el destino de una llamada INDIRECTA
            for (const ir::IrPhiArg &pa : in.phi_args) {
                h = util::fnv_mix(h, pa.value);
                h = util::fnv_mix(h, pa.block);
            }
        }
    }
    // Los valores constantes y sus tipos son el suelo de todo el analisis.
    for (const auto &v : fn.values) {
        h = util::fnv_bytes(h, &v.type, sizeof(v.type));
        h = util::fnv_mix(h, v.is_const ? v.const_val : 0);
        h = util::fnv_mix(h, v.is_const ? 1u : 0u);
    }
    for (const ir::IrValueId p : fn.params)
        h = util::fnv_mix(h, p);
    return h;
}

/**
 * @brief Mezcla un rango en una huella, CAMPO A CAMPO.
 *
 * Nunca por bytes: `ValueRange` tiene 5 bytes de relleno de alineacion entre
 * `sin_signo` y `lo_c` que nadie inicializa, asi que dos rangos identicos
 * pueden dar huellas distintas segun lo que hubiera antes en esa memoria.  Una
 * huella que depende de basura no sirve para decidir si algo se puede reusar.
 */
static uint64_t mezcla_rango(uint64_t h, const ValueRange &r) {
    h = util::fnv_mix(h, static_cast<uint64_t>(r.kind));
    h = util::fnv_mix(h, r.t.bits);
    h = util::fnv_mix(h, r.t.sin_signo ? 1u : 0u);
    h = util::fnv_mix(h, r.lo_c);
    h = util::fnv_mix(h, r.hi_c);
    return h;
}

uint64_t huella_de_resumen(const FnRangeSummary *s) {
    // "No hay resumen" es un estado propio: si manana lo hay, el resultado
    // puede cambiar, asi que no puede colisionar con un resumen vacio.
    if (s == nullptr)
        return util::fnv_mix(util::kFnvOffset, 0xFFFFFFFFFFFFFFFFull);
    uint64_t h = util::fnv_mix(util::kFnvOffset, s->cerrada ? 1u : 0u);
    for (const ValueRange &p : s->params)
        h = mezcla_rango(h, p);
    return mezcla_rango(h, s->ret);
}

bool dependencias_vigentes(const DependenciasRango &d, const ir::IrFunction &fn,
                           const RangeOptions &op, const RangeSummaries *sum) {
    // Sin registro no se afirma nada: se recalcula.  Es la misma regla que rige
    // el resto del analisis -- no haber mirado no es haber comprobado.
    if (!d.registrada) return false;
    if (d.huella_opciones != util::fnv_bytes(util::kFnvOffset, &op, sizeof(op)))
        return false;
    if (d.huella_ir != huella_de_funcion(fn)) return false;
    /* HABIA resumenes entonces y los hay ahora?  Esta comprobacion no la puede
     * hacer la lista de abajo: un calculo SIN resumenes no consulta ninguno, y
     * su lista vacia pasa el bucle sin mirar nada.  Es el guardia lo que
     * cambia, no lo que se leyo detras de el. */
    if (d.had_summaries != (sum != nullptr)) return false;
    // Se RELEE cada resumen que se consulto, contra el estado de ahora.
    for (const auto &leida : d.resumenes) {
        const FnRangeSummary *s = sum ? sum->buscar(leida.first) : nullptr;
        if (huella_de_resumen(s) != leida.second) return false;
    }
    return true;
}

/// Tiempo total dentro del motor, para contrastarlo con lo que diga un perfil:
/// una lista de puntos calientes dice DONDE, no CUANTO, y confundirlo ya ha
/// costado varias hipotesis en falso.
static std::atomic<long long> g_ns_motor{0};
static std::atomic<long long> g_n_motor{0};

static RangeFacts calcular_rangos_impl(const ir::IrFunction &fn,
                                       const IrFacts &facts,
                                       const RangeOptions &op,
                                       const RangeSummaries *sum);

static RangeFacts calcular_rangos(const ir::IrFunction &fn,
                                  const IrFacts &facts, const RangeOptions &op,
                                  const RangeSummaries *sum) {
    const uint64_t t = util::reloj::ahora();
    RangeFacts r = calcular_rangos_impl(fn, facts, op, sum);
    g_ns_motor += util::reloj::a_ns(util::reloj::ahora() - t);
    if (g_medir_coste && (++g_n_motor % 100) == 0)
        std::fprintf(stderr, "[motor-rangos] %lld analisis | %lld ms\n",
                     g_n_motor.load(), g_ns_motor.load() / 1000000);
    return r;
}

static RangeFacts calcular_rangos_impl(const ir::IrFunction &fn,
                                       const IrFacts &facts,
                                       const RangeOptions &op,
                                       const RangeSummaries *sum) {
    /* --------------------------------------------------------------- reuso
     *
     * Siete sitios distintos piden rangos de la misma funcion, y medido sobre
     * un programa real el 75 % de las peticiones son REPETICIONES exactas:
     * misma funcion, mismas opciones, mismos resumenes.  Recalcularlas no
     * cambia nada.
     *
     * El indice va por la parte de la clave que se puede calcular SIN correr el
     * analisis (funcion + opciones); lo que solo se sabe despues -- que
     * resumenes se consultaron -- se comprueba releyendolos, que es justo lo
     * que hace @c dependencias_vigentes.  Por eso un cajon puede tener mas de
     * una entrada: mismo codigo, distinto entorno.
     *
     * Es una cache, no un buffer reaprovechado: se indexa por la entrada, no se
     * pisa mientras vale, y varios hilos pueden leer la misma. */
    RangeFacts out;
    g_coste = CosteEstado{}; // el coste que se mide es el de ESTA funcion
    Motor m(fn, facts, op, sum);
    if (fn.blocks.empty()) {
        out.r = m.suelo;
        return out;
    }
    const int presupuesto = static_cast<int>(
        op.pasos_por_bloque * fn.blocks.size() + op.pasos_extra);

    const bool ok = m.resolver_ascenso(presupuesto);
    if (ok) {
        const int tope_descenso = static_cast<int>(
            op.pasos_descenso * fn.blocks.size() + op.pasos_extra);
        /* Un descenso a medias sigue siendo correcto: toda la cadena
         * descendente arranca de un post-punto-fijo y solo estrecha, asi que
         * cualquier parada intermedia sigue conteniendo al punto fijo real.
         * Por eso no tumba la convergencia; solo se anota. */
        m.stats.descenso_completo = m.resolver_descenso(tope_descenso);
    }

    out.stats = m.stats;
    out.convergio = ok;
    if (!out.convergio) {
        // Sin punto fijo no hay hecho que sostener: no se afirma nada.
        out.r.assign(facts.def_of.size(), ValueRange::top());
        return out;
    }
    out.r = m.en_definicion();
    out.entrada = m.estados_de_entrada();

    /* Lo que se leyo para llegar aqui.  No se enumera: se recoge de lo que el
     * lector fue apuntando, asi que incluye lo que se consulto de verdad --
     * incluidas las llamadas indirectas, que no llevan el nombre escrito. */
    out.deps.huella_ir = huella_de_funcion(fn);
    /* Los HECHOS (def-use) NO entran aqui, y no por descuido: se derivan de la
     * funcion, asi que la huella de la funcion ya los cubre.  Mezclarlos
     * ademas rompia el invariante que sostiene todo esto -- que
     * `dependencias_vigentes` pueda RECALCULAR esta misma huella para
     * comprobarla --, porque alli solo se tiene la funcion.  El resultado era
     * una comparacion que no coincidia nunca: la cache no acertaba jamas.
     * Medido en su momento: anadirlos no quitaba ni un caso incoherente. */
    out.deps.huella_opciones =
        util::fnv_bytes(util::kFnvOffset, &op, sizeof(op));
    out.deps.resumenes = m.sum.soltar();
    /* Y si HABIA resumenes, que es lo que el guardia de arriba mira y la lista
     * de lecturas no puede contar: sin resumenes no se consulta ninguno, y una
     * lista vacia valdria para cualquier peticion futura. */
    out.deps.had_summaries = sum != nullptr;
    out.deps.registrada = true;

    // Densidad: cuantos de los valores de la funcion acaban teniendo rango en
    // un estado.  Es lo que decide si conviene guardar el estado DISPERSO (como
    // ahora) o DENSO indexado por valor; suponerlo seria elegir a ciegas.
    out.stats.valores = static_cast<uint32_t>(m.suelo.size());
    for (const RangeBlockState &e : out.entrada) {
        if (!e.alcanzable) continue;
        const uint32_t n = static_cast<uint32_t>(e.refinamientos.size());
        if (n > out.stats.ref_max) out.stats.ref_max = n;
        out.stats.ref_suma += n;
        ++out.stats.ref_muestras;
    }
    out.stats.inserciones = g_coste.inserciones;
    out.stats.reescrituras = g_coste.reescrituras;
    out.stats.copias = g_coste.copias;
    out.stats.busquedas = g_coste.busquedas;
    out.stats.uniones = g_coste.uniones;
    out.stats.unidos = g_coste.unidos;

    if (g_medir_coste) {
        if (g_stats_verbose) {
            /* Rehacer un analisis no es lo mismo que hacer trabajo: si el
             * resultado sale IGUAL que la vez anterior, la vuelta entera sobro
             * y lo que hay que arreglar es la invalidacion, no la estructura.
             * Se compara por huella del resultado, no por tiempo. */
            uint64_t h = util::kFnvOffset;
            for (const ValueRange &r : out.r)
                h = mezcla_rango(h, r);
            for (const RangeBlockState &e : out.entrada) {
                h = util::fnv_mix(h, e.alcanzable ? 1u : 0u);
                for (const RangeEntry &p : e.refinamientos) {
                    h = util::fnv_mix(h, p.id);
                    h = mezcla_rango(h, p.range());
                }
            }
            /* Y la otra mitad de la pregunta: si sale igual porque la ENTRADA
             * no habia cambiado, entonces lo que sobra es recalcular, no la
             * estructura.  Se usa el registro que dejo el propio analisis -- no
             * una huella calculada aparte: dos criterios acaban discrepando. */
            uint64_t hir =
                util::fnv_mix(out.deps.huella_ir, out.deps.huella_opciones);
            for (const auto &leida : out.deps.resumenes) {
                hir = util::fnv_bytes(hir, leida.first.data(),
                                      leida.first.size());
                hir = util::fnv_mix(hir, leida.second);
            }
            /* La comprobacion va por CLAVE, no "contra la vez anterior": el
             * orden de las llamadas cambia entre corridas (se compila en
             * paralelo), y comparar contra la anterior daba numeros distintos
             * cada vez.  Asi la pregunta es la correcta y no depende del orden:
             * la MISMA clave, ha dado alguna vez DOS resultados distintos?  Si
             * ocurre una sola vez, la clave esta incompleta y reusar serviria
             * un valor viejo. */
            static std::mutex mx;
            static std::unordered_map<uint64_t, uint64_t> por_clave;
            bool visto, incoherente;
            {
                std::lock_guard<std::mutex> g(mx);
                auto it = por_clave.find(hir);
                visto = (it != por_clave.end());
                incoherente = (visto && it->second != h);
                if (!visto) por_clave.emplace(hir, h);
            }
            std::fprintf(stderr, "[rangos] visto=%d incoherente=%d ",
                         visto ? 1 : 0, incoherente ? 1 : 0);
            std::fprintf(
                stderr,
                "%s valores=%u bloques=%zu ref_max=%u "
                "ref_media=%.1f altas=%llu reescrituras=%llu copias=%llu "
                "busquedas=%llu uniones=%llu unidos=%llu "
                "pasos=%u cambios=%u ensanches=%u estrechados=%u "
                "muertos=%llu detot=%llu\n",
                fn.name.c_str(), out.stats.valores, fn.blocks.size(),
                out.stats.ref_max,
                out.stats.ref_muestras
                    ? double(out.stats.ref_suma) / out.stats.ref_muestras
                    : 0.0,
                (unsigned long long)out.stats.inserciones,
                (unsigned long long)out.stats.reescrituras,
                (unsigned long long)out.stats.copias,
                (unsigned long long)out.stats.busquedas,
                (unsigned long long)out.stats.uniones,
                (unsigned long long)out.stats.unidos, out.stats.pasos,
                out.stats.cambios, out.stats.ensanches, out.stats.estrechados,
                (unsigned long long)g_coste.elems_muertos,
                (unsigned long long)g_coste.elems_vivos_total);
            std::fprintf(
                stderr,
                "[anchura] estrechas=%llu de %llu | pruned_count=%llu de "
                "%llu\n",
                (unsigned long long)g_coste.narrow_width_count,
                (unsigned long long)g_coste.width_seen,
                (unsigned long long)g_coste.pruned_count,
                (unsigned long long)g_coste.prune_seen);
            std::fprintf(stderr,
                         "[delta] difieren=%llu de %llu | salida=entrada %llu "
                         "de %llu\n",
                         (unsigned long long)g_coste.changed_entries,
                         (unsigned long long)g_coste.changed_state_size,
                         (unsigned long long)g_coste.out_equals_in,
                         (unsigned long long)g_coste.out_computed);
            std::fprintf(stderr, "[suelo] redundantes=%llu de %llu\n",
                         (unsigned long long)g_coste.redundant_floor,
                         (unsigned long long)g_coste.floor_seen);
        }
    }
    return out;
}

// ===========================================================================
//  Reuso
// ===========================================================================

/**
 * @brief Los rangos de una funcion, calculados o reusados, SIN copiarlos.
 *
 * Devolver por valor era el problema: `RangeFacts` lleva dentro el estado de
 * entrada de CADA bloque, asi que un acierto de cache copiaba todo eso.  Medido
 * en el camino del asm -- que pide los rangos de la funcion entera una vez por
 * bloque de asm --, esa copia costaba 16 s de una compilacion de 26.
 *
 * Se devuelve un puntero COMPARTIDO, no una referencia al cajon: asi la entrada
 * puede desalojarse sin dejar colgado a quien la estaba mirando.
 */
static std::shared_ptr<const RangeFacts> rangos_de(const ir::IrFunction &fn,
                                                   const IrFacts &facts,
                                                   const RangeOptions &op,
                                                   const RangeSummaries *sum) {
    struct EntradaCache {
        DependenciasRango deps;
        std::shared_ptr<const RangeFacts> hechos;
    };
    static std::mutex mx_cache;
    static std::unordered_map<uint64_t, std::vector<EntradaCache>> cache;

    if (g_no_range_cache)
        return std::make_shared<const RangeFacts>(
            calcular_rangos(fn, facts, op, sum));

    /* El indice va por la parte de la clave que se puede calcular SIN correr el
     * analisis (funcion + opciones); lo que solo se sabe despues -- que
     * resumenes se consultaron -- se comprueba releyendolos.  Por eso un cajon
     * puede tener varias entradas: mismo codigo, distinto entorno. */
    const uint64_t clave =
        util::fnv_mix(huella_de_funcion(fn),
                      util::fnv_bytes(util::kFnvOffset, &op, sizeof(op)));
    {
        std::lock_guard<std::mutex> g(mx_cache);
        auto it = cache.find(clave);
        if (it != cache.end())
            for (const EntradaCache &e : it->second)
                if (dependencias_vigentes(e.deps, fn, op, sum)) return e.hechos;
    }

    auto nuevos =
        std::make_shared<const RangeFacts>(calcular_rangos(fn, facts, op, sum));
    {
        std::lock_guard<std::mutex> g(mx_cache);
        std::vector<EntradaCache> &cajon = cache[clave];
        // Tope por cajon: mismo codigo con muchos entornos no puede crecer sin
        // fin.
        if (cajon.size() >= 8) cajon.erase(cajon.begin());
        cajon.push_back(EntradaCache{nuevos->deps, nuevos});
    }
    return nuevos;
}

std::shared_ptr<const RangeFacts>
compute_ranges_ptr(const ir::IrFunction &fn, const IrFacts &facts,
                   const RangeOptions &op, const RangeSummaries *sum) {
    return rangos_de(fn, facts, op, sum);
}

RangeFacts compute_ranges(const ir::IrFunction &fn, const IrFacts &facts,
                          const RangeOptions &op, const RangeSummaries *sum) {
    // Quien solo va a LEERLOS deberia usar `compute_ranges_ptr` y ahorrarse
    // esta copia; esta forma se mantiene para quien necesite los suyos propios.
    return *rangos_de(fn, facts, op, sum);
}

// ===========================================================================
//  Consulta por punto
// ===========================================================================

struct RangeWalk::Impl {
    Contexto ctx;
    const RangeFacts &rf;
    const ir::IrBlock *bloque = nullptr;
    Estado estado;
    size_t idx = 0;

    Impl(const ir::IrFunction &fn, const IrFacts &facts, const RangeFacts &r,
         ir::IrBlockId b)
        : ctx(fn, facts, nullptr), rf(r) {
        situar(b);
    }

    /* Lo UNICO que depende del bloque.  El contexto -- el suelo de cada valor,
     * que sale de su tipo y de si es constante -- es de la funcion, y por eso
     * se queda fuera de aqui: rehacerlo por bloque era recorrer todos los
     * valores de la funcion tantas veces como bloques tuviera. */
    void situar(ir::IrBlockId b) {
        idx = 0;
        estado = Estado{};
        bloque = nullptr;
        if (b >= ctx.fn.blocks.size()) return;
        bloque = &ctx.fn.blocks[b];
        if (b < rf.entrada.size()) {
            estado.alcanzable = rf.entrada[b].alcanzable;
            estado.ref = rf.entrada[b].refinamientos;
        } else {
            /* Sin estado guardado -- rangos que no convergieron, o un bloque
             * anadido despues -- no se puede afirmar por punto, pero tampoco
             * hay que mentir: se responde lo que diga la definicion. */
            estado.alcanzable = true;
        }
    }
};

RangeWalk::RangeWalk(const ir::IrFunction &fn, const IrFacts &facts,
                     const RangeFacts &rf, ir::IrBlockId b)
    : impl_(new Impl(fn, facts, rf, b)) {}

RangeWalk::RangeWalk(RangeWalk &&o) noexcept : impl_(o.impl_) {
    o.impl_ = nullptr;
}

RangeWalk::~RangeWalk() {
    delete impl_;
}

void RangeWalk::situar(ir::IrBlockId b) {
    if (impl_ != nullptr) impl_->situar(b);
}

bool RangeWalk::alcanzable() const {
    return impl_ != nullptr && impl_->estado.alcanzable;
}

ValueRange RangeWalk::rango(ir::IrValueId v) const {
    if (impl_ == nullptr) return ValueRange::top();
    const ValueRange en_def = impl_->rf.at(v);
    const ValueRange en_punto = impl_->ctx.valor(impl_->estado, v);
    /* Los dos son ciertos aqui: la definicion domina al uso, y el estado del
     * punto lleva lo que las guardas afirmaron por el camino.  Si el corte
     * quedara vacio seria una incoherencia del propio motor, y ante eso se
     * responde lo conocido en vez de declarar el punto imposible. */
    const ValueRange c = en_punto.cortar(en_def);
    return c.es_bottom() ? en_def : c;
}

void RangeWalk::avanzar() {
    if (impl_ == nullptr || impl_->bloque == nullptr) return;
    if (impl_->idx >= impl_->bloque->instrs.size()) return;
    const ir::IrInstr &in = impl_->bloque->instrs[impl_->idx++];
    /* Las PHI no se reproducen: su valor lo fijo el motor leyendo el estado de
     * cada ARISTA entrante, y eso ya viene resuelto en el estado de entrada. */
    if (in.op != ir::IrOp::PHI) impl_->ctx.transferir(in, impl_->estado);
}

} // namespace analysis
