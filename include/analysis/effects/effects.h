/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/effects/effects.h
 * @brief Modelo UNICO de efectos de Vesta.  Un solo tipo de efecto para TODO el
 *        compilador (IR, asm lifteado, asm opaco, builtins, intrinsics, FFI,
 *        syscalls, runtime).  ASM nunca es un caso especial: cuando liftea, se
 *        DISUELVE en IR y hereda este mismo modelo; solo el residuo opaco lo
 *        produce directamente.  Fuente de verdad del diseno: memoria del agente
 *        `proj_effects_system` (secciones 2 y 10b).
 *
 * Capas:
 *   - @c SemanticEffects : efecto SEMANTICO puro, independiente de maquina (lo
 *     que importa para legalidad de optimizacion y contratos).  NO contiene
 *     `unknown` (eso es estado del analisis, ver @c EffectAnalysisResult).
 *   - @c MachineEffects  : footprint fisico (regs/flags/stack/latencia), SOLO
 * lo rellenan MachineIR (post-seleccion) y el asm OPACO (clobbers).  Los nodos
 *     IR lo dejan vacio.
 *   - Combinadores @c seq / @c join / @c callsite : el RETICULO (agregar
 *     instr->bloque->funcion NO es OR campo-a-campo).
 */
#ifndef ANALYSIS_EFFECTS_EFFECTS_H
#define ANALYSIS_EFFECTS_EFFECTS_H

#include <cstdint>

#include "ir/native_effect_vocab.h" // de quien es lo que sale, y que puede fallar
#include <string>
#include <unordered_map>
#include <vector>

namespace analysis {
namespace effects {

// ===========================================================================
// AbstractLoc -- dominio de localizaciones de memoria.  Reticulo con TOP y
// BOTTOM explicitos: Bottom <= {Stack,Heap,Global,ArgDerived}
// <= Unknown.  Bottom = neutro del join; Unknown = absorbente.
// ===========================================================================
/// Id que representa "toda la clase" (generico): aliasa cualquier id de su
/// clase.  Reservado para poder usar el id 0 como un sitio concreto legitimo.
static constexpr uint32_t LOC_GENERIC = 0xFFFFFFFFu;

// ===========================================================================
// AbstractLoc -- localizacion abstracta de memoria UNICA para todo el
// compilador y el tooling (efectos, DSE/alias, diagramas).  Es PRECISA:
// clase (kind) + sitio concreto (id = raiz: ALLOCA/alloc-site/global/param) +
// OFFSET constante desde la raiz + ANCHO en bytes del acceso.  El alias es por
// RANGO de bytes: dos accesos al mismo sitio con rangos disjuntos NO aliasan.
//
// width == 0 significa "ancho desconocido / objeto entero": no permite probar
// disyuncion -> se comporta como el modelo base-only (conservador).  Asi el
// upgrade es un REFINAMIENTO: con off/width por defecto (0) el comportamiento
// es identico al anterior; poblarlos afina la precision sin regresar nada.
// ===========================================================================
struct AbstractLoc {
    enum class Kind : uint8_t {
        None,       ///< BOTTOM: no localizacion (neutro del join).
        Stack,      ///< marco de pila local (slots ALLOCA).
        Heap,       ///< heap; @c id = alloc-site (LOC_GENERIC = heap generico).
        Global,     ///< dato estatico/global; @c id = symbol/slot id.
        ArgDerived, ///< memoria alcanzable desde el parametro @c id (points-to
                    ///< grueso).
        Unknown     ///< TOP: puede aliasar cualquier cosa.
    };
    Kind kind = Kind::None;
    uint32_t id =
        0; ///< raiz concreta dentro de la clase; LOC_GENERIC = toda la clase.
    int64_t off = 0;   ///< offset const desde la raiz (solo si id concreto).
    int32_t width = 0; ///< bytes accedidos; 0 = desconocido/objeto entero.

    bool operator==(const AbstractLoc &o) const {
        return kind == o.kind && id == o.id && off == o.off && width == o.width;
    }
    /// ¿Es un sitio CONCRETO (raiz conocida, no la clase generica ni TOP)?
    bool concrete() const {
        return kind != Kind::None && kind != Kind::Unknown && id != LOC_GENERIC;
    }
};

/// ¿Pueden @p a y @p b referirse a la MISMA memoria?  Unknown aliasa todo;
/// None (bottom) no aliasa nada; clases distintas son disjuntas; misma clase +
/// misma raiz: solo aliasan si sus rangos de bytes [off,off+width) se solapan
/// (con width==0 = objeto entero = siempre puede solapar -> conservador).
bool may_alias(const AbstractLoc &a, const AbstractLoc &b);

/// ¿Se refieren SIEMPRE a EXACTAMENTE los mismos bytes?  (misma raiz concreta,
/// mismo off, mismo width > 0).  Requerido por el DSE para "sobreescritura".
bool must_alias(const AbstractLoc &a, const AbstractLoc &b);

/// ¿Se refieren SIEMPRE a memoria DISJUNTA?  (== !may_alias, pero explicito).
bool no_alias(const AbstractLoc &a, const AbstractLoc &b);

// ===========================================================================
// LocSet -- conjunto de AbstractLoc con TOP absorbente (is_top).  Cuando entra
// Unknown, colapsa a top y vacia el vector (comparaciones O(1)).
// ===========================================================================
struct LocSet {
    bool is_top = false;
    std::vector<AbstractLoc>
        locs; ///< vacio si is_top; sin duplicados; sin None.

    bool empty() const { return !is_top && locs.empty(); }
    void clear() {
        is_top = false;
        locs.clear();
        idx_listo_ = false;
    }

    /// Anade @p l.  Unknown -> top; None -> no-op; resto -> insertar sin dup.
    void add(const AbstractLoc &l);
    /// Union en sitio (this |= other).
    void unite(const LocSet &other);

    /**
     * @brief Avisa de que @c locs se ha tocado por fuera.
     *
     * @c locs es publico y hay codigo que lo manipula directamente; el indice
     * no puede enterarse solo.  Quien lo toque llama a esto -- o mejor, usa
     * @ref add / @ref unite / @ref clear, que ya lo hacen.
     */
    void indice_obsoleto() const { idx_listo_ = false; }
    /**
     * @brief ¿algun elemento puede aliasar @p l?
     *
     * Consulta INDEXADA por raiz.  Recorrer el vector entero por consulta
     * costaba O(posiciones), y quien pregunta lo hace una vez por instruccion:
     * con las dos cosas creciendo con el tamaño de la funcion, eso es
     * cuadratico.  Medido en el barrido del DCE sobre una funcion de 1740
     * instrucciones: 21 s de los 32 que tardaba compilar el programa entero.
     *
     * El indice sale de la propia regla de aliasing: dos posiciones solo pueden
     * aliasar si comparten clase Y raiz -- salvo el TOP, que aliasa todo, y la
     * raiz generica, que aliasa toda su clase.  Asi que basta mirar el cubo de
     * la raiz preguntada mas los dos casos que abarcan mas.
     */
    bool may_alias_any(const AbstractLoc &l) const;
    /// this \ other, quitando SOLO locs concretos de other (sound gen/kill: si
    /// other es top NO mata nada -- no sabemos que escribio exactamente).
    void subtract_concrete(const LocSet &other);
    bool operator==(const LocSet &o) const;

  private:
    /* Indice para @ref may_alias_any.  Perezoso y mutable: se construye en la
     * primera consulta y se tira en cuanto el conjunto cambia, asi que anadir
     * sigue costando lo mismo que antes y solo paga quien pregunta.
     *
     * `mutable` porque la consulta es const y el indice es cache, no estado:
     * dos LocSet con el mismo contenido responden lo mismo, se haya construido
     * el indice o no. */
    mutable bool idx_listo_ = false;
    mutable bool idx_top_ = false;
    mutable uint32_t idx_kinds_ = 0;
    mutable uint32_t idx_kinds_gen_ = 0;
    mutable std::unordered_map<uint64_t, std::vector<uint32_t>> idx_raiz_;

    /// Construye el indice si hace falta.
    void asegurar_indice_() const;
};

/// Efecto de memoria: read-set + write-set sobre localizaciones abstractas.
struct MemEffect {
    LocSet reads;
    LocSet writes;
    bool reads_memory() const { return !reads.empty(); }   ///< DERIVADO
    bool writes_memory() const { return !writes.empty(); } ///< DERIVADO
    bool operator==(const MemEffect &o) const {
        return reads == o.reads && writes == o.writes;
    }
};

// ===========================================================================
// ControlEffect -- tipo de transferencia de control (prepara
// Suspend/Resume para await/yield/coroutines/fibers).  Los TARGETS de
// Branch/Throw son aristas del CFG, NO se aplanan aqui.
// ===========================================================================
enum class ControlKind : uint8_t {
    FallThrough, ///< sigue a la siguiente instr.
    Return,      ///< ret.
    Branch,      ///< salto cond/incond (targets en el CFG).
    Call,        ///< llamada (callee ref o desconocido).
    Throw,       ///< lanza (aristas a handlers en el CFG).
    Suspend,     ///< await/yield: cede control (semantica futura).
    Resume,      ///< reanuda una suspension (semantica futura).
    Indirect,    ///< salto/llamada indirecta.
    NoReturn     ///< no retorna (panic/exit/loop infinito).
};

struct ControlEffect {
    ControlKind kind = ControlKind::FallThrough;
    int32_t callee_ref =
        -1; ///< symbol/summary id si Call conocido; -1 = desconocido.
    bool operator==(const ControlEffect &o) const {
        return kind == o.kind && callee_ref == o.callee_ref;
    }
};

/// ¿Este control TERMINA el flujo lineal (nada despues se ejecuta en
/// secuencia)?
bool control_is_terminator(ControlKind k);

// ===========================================================================
// Atomicity -- orden de memoria de una operacion atomica / barrera.
// ===========================================================================
enum class MemOrder : uint8_t {
    None,
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst
};
struct Atomicity {
    MemOrder order = MemOrder::None;
    bool is_fence = false;
    bool operator==(const Atomicity &o) const {
        return order == o.order && is_fence == o.is_fence;
    }
};

// ===========================================================================
// CapabilityTag -- escotilla EXTENSIBLE para efectos fuera del set cerrado
// (estado de maquina, I/O privilegiado, seguridad...).  Enum, no strings
// (type-safe + eficiente).  Cada tag tiene una CLASE de efecto.
// ===========================================================================
enum class CapabilityTag : uint16_t {
    MachineState, ///< toca estado global de la maquina (no modelable como mem).
    InterruptState,  ///< cli/sti (interrupt flag).
    PortIO,          ///< in/out.
    MSR,             ///< rdmsr/wrmsr.
    CPUID,           ///< cpuid (serializante + lee estado CPU).
    Privileged,      ///< ring-0 / instr privilegiada.
    SecretDependent, ///< control/acceso dependiente de dato secreto
                     ///< (constant-time).
    SelfModifying,   ///< codigo automodificante.
    UserBarrier,     ///< barrera declarada por el usuario (asm volatile).
    TLBFlush,        ///< invlpg / mov cr3.
    SegmentChange,   ///< cambio de registro de segmento.
    COUNT_           ///< centinela (numero de tags).
};

/// Clase de un tag: unos afectan LEGALIDAD de optimizacion, otros son solo
/// info.
enum class CapabilityClass : uint8_t {
    Observable,      ///< efecto observable (I/O) -> limita reordenacion.
    Synchronization, ///< barrera/sync.
    Machine,         ///< estado de maquina (CPUID, MSR...).
    Security,        ///< seguridad (SecretDependent).
    Runtime          ///< runtime/misc.
};
CapabilityClass class_of(CapabilityTag t);

/// Conjunto de tags como bitset (COUNT_ <= 64).
struct TagSet {
    uint64_t bits = 0;
    void add(CapabilityTag t) { bits |= (uint64_t(1) << uint16_t(t)); }
    bool has(CapabilityTag t) const {
        return bits & (uint64_t(1) << uint16_t(t));
    }
    bool empty() const { return bits == 0; }
    void unite(const TagSet &o) { bits |= o.bits; }
    bool operator==(const TagSet &o) const { return bits == o.bits; }
};

// ===========================================================================
// DeterminismSet -- determinismo como EFECTO (no un bool).
// Vacio = PureDeterministic.  El contrato `deterministic` sale de empty().
// ===========================================================================
enum class DeterminismTag : uint8_t {
    ReadsClock,
    ReadsRandom,
    ReadsPID,
    ReadsEnvironment,
    ExternalObservable,
    COUNT_
};
struct DeterminismSet {
    uint8_t bits = 0;
    void add(DeterminismTag t) { bits |= (uint8_t(1) << uint8_t(t)); }
    bool has(DeterminismTag t) const {
        return bits & (uint8_t(1) << uint8_t(t));
    }
    bool empty() const { return bits == 0; }
    void unite(const DeterminismSet &o) { bits |= o.bits; }
    bool operator==(const DeterminismSet &o) const { return bits == o.bits; }
};

// ===========================================================================
// SemanticEffects -- el modelo UNIVERSAL, independiente de maquina.  SIN
// `unknown` (eso es estado del analisis, no un efecto): ver
// EffectAnalysisResult.
// ===========================================================================
struct SemanticEffects {
    MemEffect mem;
    ControlEffect control;
    Atomicity atomic;
    bool may_trap = false;  ///< fallo hw (div0, deref invalido).
    bool may_throw = false; ///< lanza excepcion Vesta (capturable).
    /// Aborta por `panic`.  NO es lo mismo que lanzar, y por eso va aparte: en
    /// la maquina virtual un panic es un FatalError que un `catch` recoge, y en
    /// nativo llama al hook de panico y no vuelve.  Con una sola senal, decir
    /// "no lanza" en nativo se leia como "no aborta".
    bool may_panic = false;
    bool may_allocate = false;  ///< aloca heap (GC/raw/newobj/closure-GC).
    bool may_block = false;     ///< puede bloquear (await/monenter/msgrecv).
    /**
     * @brief De QUIEN es lo que sale, cuando sale por lanzar o por abortar.
     *
     * `may_throw`/`may_panic` dicen QUE puede pasar; esto, de quien es el
     * mecanismo.  Importa porque no se recogen igual: lo nuestro lo captura un
     * `catch` y lo de fuera -- una excepcion de C++, un SEH, un `abort()` de
     * la libreria -- no, y desenrollar a traves de nuestros marcos ni siquiera
     * esta garantizado.
     *
     * Modelar solo el lenguaje dejaba fuera justo la frontera donde el
     * lenguaje se acaba, que es donde vive el FFI.
     */
    ir::UnwindOrigin throw_origin = ir::UnwindOrigin::Any;
    ir::UnwindOrigin panic_origin = ir::UnwindOrigin::Any;
    /// Que fallos del PROCESADOR, si se acotaron.  Cero = cualquiera.
    ir::TrapKinds trap_kinds = ir::TRAP_NONE;
    bool may_io = false;        ///< I/O observable.
    DeterminismSet determinism; ///< vacio = puro-determinista.
    TagSet tags;                ///< capabilities.

    bool operator==(const SemanticEffects &o) const;
    /// El efecto NEUTRO (bottom): no hace nada observable.
    static SemanticEffects none();
    /// El efecto MAXIMO (top): puede hacer CUALQUIER cosa.  Es la respuesta
    /// ROBUSTA y COMPLETA ante lo desconocido (callee dinamico/externo/opaco):
    /// enciende TODOS los efectos posibles, asi ningun consumidor puede asumir
    /// de menos.  Nunca causa una optimizacion incorrecta (solo puede impedir
    /// una valida).  Debe cubrir CADA campo -- olvidar uno seria un error
    /// latente.
    static SemanticEffects top();
};

// ===========================================================================
// MachineEffects -- footprint fisico.  SOLO MachineIR y asm OPACO.  Incluye
// latencia/throughput (asi el modelo del scheduler es uno solo).
// ===========================================================================
using RegMask =
    uint64_t; ///< bit por registro fisico (GP 0..15, XMM 16..31, ...).

struct MachineEffects {
    RegMask regs_read = 0;
    RegMask regs_written = 0;
    uint8_t flags_read = 0; ///< bits CF/ZF/SF/OF/PF/AF/DF.
    uint8_t flags_written = 0;
    int64_t stack_net = 0;  ///< delta neto de pila (bytes).
    int64_t stack_peak = 0; ///< profundidad maxima alcanzada (bytes).
    uint16_t latency = 0;   ///< ciclos (prioridad del scheduler).
    uint16_t reciprocal_throughput =
        0;                    ///< 1/throughput * 100 (culo de botella).
    bool serializing = false; ///< barrera de ejecucion (cpuid/mfence/...).

    bool operator==(const MachineEffects &o) const;
};

// ===========================================================================
// AnalysisCompleteness -- estado del ANALISIS, separado del
// efecto.  El motor devuelve EffectAnalysisResult; el SemanticEffects viaja
// limpio por el resto del sistema.
// ===========================================================================
enum class AnalysisCompleteness : uint8_t {
    Complete,     ///< el efecto es exacto.
    Conservative, ///< sobre-aproximado pero acotado.
    Unknown       ///< no se pudo inferir (caja negra).
};
/// Por que el analisis no es Complete.  Distingue imprecision FUNDAMENTAL (no
/// se puede saber mas: FFI, dispatch dinamico, indirecto) de LAGUNA DEL MOTOR
/// (@c UnmodeledOp/@c UnknownMnemonic: deberiamos modelarlo para ganar
/// precision). Esta distincion es lo que permite reportar "que falta por
/// modelar" (cobertura) vs "donde perdemos optimizacion por opacidad real".
enum class UnknownReason : uint8_t {
    None,
    UnmodeledOp, ///< LAGUNA: IrOp que el motor aun no clasifica (mejorable).
    UnknownMnemonic,  ///< LAGUNA: mnemonico de asm opaco no tabulado
                      ///< (mejorable).
    UnknownIntrinsic, ///< LAGUNA: intrinsic no modelado (mejorable).
    UnknownEncoding,  ///< LAGUNA: forma no reconocida (mejorable).
    UserBarrier,      ///< FUNDAMENTAL: barrera declarada por el usuario.
    DynamicDispatch,  ///< FUNDAMENTAL: CALLVIRT/CALLM/CALLITF/CALLCLOSURE.
    Indirect,         ///< FUNDAMENTAL: llamada/salto indirecto.
    UnknownFFI,       ///< FUNDAMENTAL: CALLN a nativo (caja negra).
    ExternalCallee,   ///< FUNDAMENTAL: callee fuera del modulo analizado.
    UnknownRuntime    ///< FUNDAMENTAL: helper de runtime opaco.
};

/// ¿El motivo es una LAGUNA del motor (mejorable modelandolo) o imprecision
/// FUNDAMENTAL?  Lo usa el reporte de cobertura para separar ambos.
inline bool reason_is_gap(UnknownReason r) {
    return r == UnknownReason::UnmodeledOp ||
           r == UnknownReason::UnknownMnemonic ||
           r == UnknownReason::UnknownIntrinsic ||
           r == UnknownReason::UnknownEncoding;
}

struct EffectAnalysisResult {
    SemanticEffects effects;
    AnalysisCompleteness completeness = AnalysisCompleteness::Complete;
    UnknownReason unknown_reason = UnknownReason::None;
    /// Mnemonicos de asm que la tabla no supo explicar, si el motivo fue ese.
    /// Viajan hasta el informe porque una laguna sin nombre no se puede cerrar.
    std::vector<std::string> mnemonicos_desconocidos;
    /// Nombre de la funcion nativa sin efectos declarados, si el motivo fue
    /// ese.
    std::string nativa_sin_declarar;
};

// ===========================================================================
// Combinadores (el RETICULO).  Agregar NO es OR campo-a-campo.
// ===========================================================================
/// Composicion SECUENCIAL a-luego-b (dentro de un bloque, linea a linea).
/// mem: union con gen/kill (loc escrito por 'a' y leido por 'b' es interno);
/// stack: net += , peak = max(a.peak, a.net + b.peak); control: el de 'a' si
/// 'a' termina el flujo, si no el de 'b'; may_*/tags/determinism: union;
/// atomic: el orden mas fuerte.
SemanticEffects seq(const SemanticEffects &a, const SemanticEffects &b);
MachineEffects seq(const MachineEffects &a, const MachineEffects &b);

/// JOIN de control (merge de dos ramas).  may-effects: UNION.  stack peak: max.
/// Es el meet del reticulo para las propiedades may-.
SemanticEffects join(const SemanticEffects &a, const SemanticEffects &b);
MachineEffects join(const MachineEffects &a, const MachineEffects &b);

} // namespace effects
} // namespace analysis

#endif // ANALYSIS_EFFECTS_EFFECTS_H
