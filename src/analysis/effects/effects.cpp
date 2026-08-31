/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file effects.cpp
 * @brief Implementacion del modelo de efectos: reticulo de AbstractLoc/LocSet,
 *        may_alias, y los combinadores seq/join a nivel semantico y de maquina.
 */
#include "analysis/effects/effects.h"

#include <algorithm>

namespace analysis {
namespace effects {

// --------------------------------------------------------------------------
// AbstractLoc / may_alias
// --------------------------------------------------------------------------
bool may_alias(const AbstractLoc &a, const AbstractLoc &b) {
    using K = AbstractLoc::Kind;
    // BOTTOM no aliasa nada.
    if (a.kind == K::None || b.kind == K::None) return false;
    // TOP aliasa todo.
    if (a.kind == K::Unknown || b.kind == K::Unknown) return true;
    // Clases distintas son disjuntas (stack != heap != global != arg).
    if (a.kind != b.kind) return false;
    // Misma clase: el id GENERICO aliasa cualquier sitio de la clase.
    if (a.id == LOC_GENERIC || b.id == LOC_GENERIC) return true;
    // Raices concretas distintas -> disjuntas (dos ALLOCAs, dos
    // alloc-sites...).
    if (a.id != b.id) return false;
    // MISMA raiz concreta: aliasan solo si sus rangos de bytes se SOLAPAN.  Con
    // width==0 (ancho desconocido = objeto entero) no se puede probar
    // disyuncion
    // -> conservador (solapan).  Refinamiento sobre el modelo base-only.
    if (a.width <= 0 || b.width <= 0) return true;
    // Solapamiento de [off, off+width): a.off < b.off+b.width && b.off <
    // a.off+a.width.
    return a.off < b.off + b.width && b.off < a.off + a.width;
}

bool must_alias(const AbstractLoc &a, const AbstractLoc &b) {
    // Mismos bytes EXACTOS: ambas raices concretas iguales, mismo off, mismo
    // width > 0.  (width==0 = objeto entero -> no se puede afirmar "exactamente
    // los mismos bytes").
    if (!a.concrete() || !b.concrete()) return false;
    return a.kind == b.kind && a.id == b.id && a.off == b.off && a.width > 0 &&
           a.width == b.width;
}

bool no_alias(const AbstractLoc &a, const AbstractLoc &b) {
    return !may_alias(a, b);
}

// --------------------------------------------------------------------------
// LocSet
// --------------------------------------------------------------------------
void LocSet::add(const AbstractLoc &l) {
    idx_listo_ = false; // el conjunto cambia: el indice deja de valer.
    if (is_top) return;
    if (l.kind == AbstractLoc::Kind::None) return; // bottom: no aporta
    if (l.kind == AbstractLoc::Kind::Unknown) {    // top absorbente
        is_top = true;
        locs.clear();
        return;
    }
    for (const AbstractLoc &e : locs)
        if (e == l) return; // sin duplicados
    locs.push_back(l);
}

void LocSet::unite(const LocSet &other) {
    idx_listo_ = false; // el conjunto cambia: el indice deja de valer.
    if (is_top) return;
    if (other.is_top) {
        is_top = true;
        locs.clear();
        return;
    }
    for (const AbstractLoc &l : other.locs)
        add(l);
}

/// Clave del cubo: clase y raiz juntas en un entero.
static inline uint64_t clave_raiz_(AbstractLoc::Kind k, uint32_t id) {
    return (static_cast<uint64_t>(static_cast<uint8_t>(k)) << 32) | id;
}

void LocSet::asegurar_indice_() const {
    if (idx_listo_) return;
    idx_listo_ = true;
    idx_top_ = false;
    idx_kinds_ = 0;
    idx_kinds_gen_ = 0;
    idx_raiz_.clear();
    idx_raiz_.reserve(locs.size());
    for (uint32_t i = 0; i < locs.size(); ++i) {
        const AbstractLoc &e = locs[i];
        if (e.kind == AbstractLoc::Kind::None) continue;
        if (e.kind == AbstractLoc::Kind::Unknown) {
            idx_top_ = true; // hay un TOP dentro: aliasa con cualquier cosa.
            continue;
        }
        const uint32_t bit = 1u << static_cast<uint8_t>(e.kind);
        idx_kinds_ |= bit;
        if (e.id == LOC_GENERIC) {
            idx_kinds_gen_ |= bit; // la clase entera, sin raiz concreta.
            continue;
        }
        idx_raiz_[clave_raiz_(e.kind, e.id)].push_back(i);
    }
}

bool LocSet::may_alias_any(const AbstractLoc &l) const {
    if (l.kind == AbstractLoc::Kind::None) return false;
    if (is_top) return true; // el conjunto es TOP: aliasa cualquier cosa.
    /* La misma regla que @ref may_alias, respondida sin recorrer el conjunto:
     *   - un TOP dentro aliasa todo;
     *   - si lo preguntado es TOP, aliasa con cualquier elemento que haya;
     *   - la raiz generica de una clase aliasa toda su clase;
     *   - y si no, solo pueden aliasar los de SU misma raiz, que es el cubo. */
    asegurar_indice_();
    if (idx_top_) return true;
    if (l.kind == AbstractLoc::Kind::Unknown)
        return idx_kinds_ != 0; // (los None no entran en el indice)
    const uint32_t bit = 1u << static_cast<uint8_t>(l.kind);
    if ((idx_kinds_gen_ & bit) != 0) return true;
    if (l.id == LOC_GENERIC) return (idx_kinds_ & bit) != 0;
    auto it = idx_raiz_.find(clave_raiz_(l.kind, l.id));
    if (it == idx_raiz_.end()) return false;
    for (uint32_t i : it->second)
        if (may_alias(locs[i], l)) return true;
    return false;
}

void LocSet::subtract_concrete(const LocSet &other) {
    idx_listo_ = false; // el conjunto cambia: el indice deja de valer.
    // Si el otro es top, NO sabemos que escribio exactamente -> no matamos nada
    // (sound: mantener las lecturas).
    if (is_top || other.is_top) return;
    std::vector<AbstractLoc> keep;
    keep.reserve(locs.size());
    for (const AbstractLoc &l : locs) {
        bool killed = false;
        for (const AbstractLoc &w : other.locs)
            if (w == l) {
                killed = true;
                break;
            } // solo mata el loc EXACTO
        if (!killed) keep.push_back(l);
    }
    locs.swap(keep);
}

bool LocSet::operator==(const LocSet &o) const {
    if (is_top != o.is_top) return false;
    if (is_top) return true;
    if (locs.size() != o.locs.size()) return false;
    // Orden-independiente.
    for (const AbstractLoc &l : locs) {
        bool found = false;
        for (const AbstractLoc &r : o.locs)
            if (l == r) {
                found = true;
                break;
            }
        if (!found) return false;
    }
    return true;
}

// --------------------------------------------------------------------------
// ControlEffect / Capabilities
// --------------------------------------------------------------------------
bool control_is_terminator(ControlKind k) {
    switch (k) {
    case ControlKind::Return:
    case ControlKind::Throw:
    case ControlKind::NoReturn:
    case ControlKind::Indirect: return true;
    default:
        return false; // FallThrough/Branch/Call/Suspend/Resume no terminan la
                      // seq
    }
}

CapabilityClass class_of(CapabilityTag t) {
    switch (t) {
    case CapabilityTag::PortIO: return CapabilityClass::Observable;
    case CapabilityTag::UserBarrier: return CapabilityClass::Synchronization;
    case CapabilityTag::MachineState:
    case CapabilityTag::InterruptState:
    case CapabilityTag::MSR:
    case CapabilityTag::CPUID:
    case CapabilityTag::Privileged:
    case CapabilityTag::TLBFlush:
    case CapabilityTag::SegmentChange:
    case CapabilityTag::SelfModifying: return CapabilityClass::Machine;
    case CapabilityTag::SecretDependent: return CapabilityClass::Security;
    default: return CapabilityClass::Runtime;
    }
}

// --------------------------------------------------------------------------
// SemanticEffects / MachineEffects: igualdad y neutro
// --------------------------------------------------------------------------
bool SemanticEffects::operator==(const SemanticEffects &o) const {
    return mem == o.mem && control == o.control && atomic == o.atomic &&
           may_trap == o.may_trap && may_throw == o.may_throw &&
           may_panic == o.may_panic && may_allocate == o.may_allocate &&
           may_block == o.may_block && may_io == o.may_io &&
           throw_origin == o.throw_origin &&
           panic_origin == o.panic_origin &&
           trap_kinds == o.trap_kinds &&
           determinism == o.determinism && tags == o.tags;
}

SemanticEffects SemanticEffects::none() {
    return SemanticEffects{};
}

SemanticEffects SemanticEffects::top() {
    SemanticEffects e;
    // Memoria: puede leer y escribir cualquier cosa.
    e.mem.reads.add({AbstractLoc::Kind::Unknown, LOC_GENERIC});
    e.mem.writes.add({AbstractLoc::Kind::Unknown, LOC_GENERIC});
    // Control: transferencia desconocida (una llamada opaca).
    e.control.kind = ControlKind::Call;
    e.control.callee_ref = -1;
    // Barrera de memoria maxima (puede sincronizar de cualquier forma).
    e.atomic.order = MemOrder::SeqCst;
    e.atomic.is_fence = true;
    // TODOS los efectos posibles (cubrir cada campo -- robusto).
    e.may_trap = true;
    e.may_throw = true;
    e.may_panic = true;
    e.may_allocate = true;
    e.may_block = true;
    e.may_io = true;
    /* Y los refinamientos, en su valor CONSERVADOR: `Any` es "puede ser
     * cualquiera de los dos" y el conjunto vacio de fallos vale por todos.
     * Van explicitos aunque coincidan con el default por lo que dice el
     * comentario de arriba -- cubrir CADA campo --: si manana el default
     * cambia, el maximo no puede quedarse corto en silencio. */
    e.throw_origin = ir::UnwindOrigin::Any;
    e.panic_origin = ir::UnwindOrigin::Any;
    e.trap_kinds = ir::TRAP_NONE;
    // No-determinismo total.
    e.determinism.add(DeterminismTag::ReadsClock);
    e.determinism.add(DeterminismTag::ReadsRandom);
    e.determinism.add(DeterminismTag::ReadsPID);
    e.determinism.add(DeterminismTag::ReadsEnvironment);
    e.determinism.add(DeterminismTag::ExternalObservable);
    // Cualquier capacidad de maquina.
    e.tags.add(CapabilityTag::MachineState);
    return e;
}

bool MachineEffects::operator==(const MachineEffects &o) const {
    return regs_read == o.regs_read && regs_written == o.regs_written &&
           flags_read == o.flags_read && flags_written == o.flags_written &&
           stack_net == o.stack_net && stack_peak == o.stack_peak &&
           latency == o.latency &&
           reciprocal_throughput == o.reciprocal_throughput &&
           serializing == o.serializing;
}

// --------------------------------------------------------------------------
// Combinadores semanticos
// --------------------------------------------------------------------------
static MemOrder stronger(MemOrder a, MemOrder b) {
    return (uint8_t(a) >= uint8_t(b)) ? a : b;
}

SemanticEffects seq(const SemanticEffects &a, const SemanticEffects &b) {
    SemanticEffects r;
    // Memoria: reads(a;b) = a.reads U (b.reads \ a.writes-concretos); writes =
    // union.
    r.mem.reads = a.mem.reads;
    LocSet bkr = b.mem.reads;
    bkr.subtract_concrete(a.mem.writes); // gen/kill sound
    r.mem.reads.unite(bkr);
    r.mem.writes = a.mem.writes;
    r.mem.writes.unite(b.mem.writes);
    // Control: si 'a' termina el flujo, 'b' no se alcanza en secuencia -> el de
    // 'a'.
    r.control = control_is_terminator(a.control.kind) ? a.control : b.control;
    // Atomic: el orden mas fuerte; fence si alguno.
    r.atomic.order = stronger(a.atomic.order, b.atomic.order);
    r.atomic.is_fence = a.atomic.is_fence || b.atomic.is_fence;
    // may_*: OR.
    r.may_trap = a.may_trap || b.may_trap;
    r.may_throw = a.may_throw || b.may_throw;
    r.may_panic = a.may_panic || b.may_panic;
    r.may_allocate = a.may_allocate || b.may_allocate;
    r.may_block = a.may_block || b.may_block;
    /* El origen se ENSANCHA al juntar: si uno lanza lo nuestro y el otro lo
     * ajeno, lo que sale de los dos puede ser cualquiera de los dos, y eso es
     * `Any`.  Estrecharlo aqui seria quedarse con una mitad. */
    r.throw_origin = (a.throw_origin == b.throw_origin) ? a.throw_origin
                                                        : ir::UnwindOrigin::Any;
    r.panic_origin = (a.panic_origin == b.panic_origin) ? a.panic_origin
                                                        : ir::UnwindOrigin::Any;
    /* Y los fallos se SUMAN, salvo que alguno no acote: un conjunto vacio vale
     * por todos, asi que absorbe. */
    r.trap_kinds = (a.trap_kinds == ir::TRAP_NONE || b.trap_kinds == ir::TRAP_NONE)
                       ? ir::TRAP_NONE
                       : static_cast<ir::TrapKinds>(a.trap_kinds | b.trap_kinds);
    r.may_io = a.may_io || b.may_io;
    r.determinism = a.determinism;
    r.determinism.unite(b.determinism);
    r.tags = a.tags;
    r.tags.unite(b.tags);
    return r;
}

SemanticEffects join(const SemanticEffects &a, const SemanticEffects &b) {
    SemanticEffects r;
    // may-effects: UNION en ambas ramas.
    r.mem.reads = a.mem.reads;
    r.mem.reads.unite(b.mem.reads);
    r.mem.writes = a.mem.writes;
    r.mem.writes.unite(b.mem.writes);
    // Control en un merge: si coinciden, ese; si no, Branch (ambas salidas
    // vivas).
    r.control = (a.control == b.control)
                    ? a.control
                    : ControlEffect{ControlKind::Branch, -1};
    r.atomic.order = stronger(a.atomic.order, b.atomic.order);
    r.atomic.is_fence = a.atomic.is_fence || b.atomic.is_fence;
    r.may_trap = a.may_trap || b.may_trap;
    r.may_throw = a.may_throw || b.may_throw;
    r.may_panic = a.may_panic || b.may_panic;
    r.may_allocate = a.may_allocate || b.may_allocate;
    r.may_block = a.may_block || b.may_block;
    /* El origen se ENSANCHA al juntar: si uno lanza lo nuestro y el otro lo
     * ajeno, lo que sale de los dos puede ser cualquiera de los dos, y eso es
     * `Any`.  Estrecharlo aqui seria quedarse con una mitad. */
    r.throw_origin = (a.throw_origin == b.throw_origin) ? a.throw_origin
                                                        : ir::UnwindOrigin::Any;
    r.panic_origin = (a.panic_origin == b.panic_origin) ? a.panic_origin
                                                        : ir::UnwindOrigin::Any;
    /* Y los fallos se SUMAN, salvo que alguno no acote: un conjunto vacio vale
     * por todos, asi que absorbe. */
    r.trap_kinds = (a.trap_kinds == ir::TRAP_NONE || b.trap_kinds == ir::TRAP_NONE)
                       ? ir::TRAP_NONE
                       : static_cast<ir::TrapKinds>(a.trap_kinds | b.trap_kinds);
    r.may_io = a.may_io || b.may_io;
    r.determinism = a.determinism;
    r.determinism.unite(b.determinism);
    r.tags = a.tags;
    r.tags.unite(b.tags);
    return r;
}

// --------------------------------------------------------------------------
// Combinadores de maquina
// --------------------------------------------------------------------------
MachineEffects seq(const MachineEffects &a, const MachineEffects &b) {
    MachineEffects r;
    // Registros: reads = a.reads U (b.reads \ a.writes); writes = union
    // (clobber).
    r.regs_read = a.regs_read | (b.regs_read & ~a.regs_written);
    r.regs_written = a.regs_written | b.regs_written;
    r.flags_read = a.flags_read | (b.flags_read & ~a.flags_written);
    r.flags_written = a.flags_written | b.flags_written;
    r.stack_net = a.stack_net + b.stack_net;
    r.stack_peak = std::max(a.stack_peak, a.stack_net + b.stack_peak);
    r.latency = a.latency + b.latency; // camino secuencial (aprox)
    r.reciprocal_throughput = a.reciprocal_throughput + b.reciprocal_throughput;
    r.serializing = a.serializing || b.serializing;
    return r;
}

MachineEffects join(const MachineEffects &a, const MachineEffects &b) {
    MachineEffects r;
    r.regs_read = a.regs_read | b.regs_read;          // may-read
    r.regs_written = a.regs_written | b.regs_written; // may-clobber
    r.flags_read = a.flags_read | b.flags_read;
    r.flags_written = a.flags_written | b.flags_written;
    r.stack_net = std::max(a.stack_net, b.stack_net);
    r.stack_peak = std::max(a.stack_peak, b.stack_peak);
    r.latency = std::max(a.latency, b.latency);
    r.reciprocal_throughput =
        std::max(a.reciprocal_throughput, b.reciprocal_throughput);
    r.serializing = a.serializing || b.serializing;
    return r;
}

} // namespace effects
} // namespace analysis
