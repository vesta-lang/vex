/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/rbank/physical_bank.h
 * @brief Nivel FISICO del modelo de asignacion de recursos: el objeto UNICO
 *        donde convergen TargetRegInfo, BackendCaps, arch-data, ABI, scheduler,
 *        allocator, vectorizador e interprete.
 *
 * MOTIVACION (consolidacion de arquitectura, no optimizacion).  Hoy el banco
 * fisico de una arquitectura se mira de formas HETEROGENEAS y dispersas:
 *
 *     allocator   ---> TargetRegInfo   (clases, allocatable, scratch, ABI)
 *     scheduler   ---> BackendCaps     (features, puertos)
 *     vectorizer  ---> arch-data       (anchos SIMD, latencias)
 *     interp      ---> banco ancho f0..f15 (numeracion propia)
 *     AOT/JIT     ---> linear_scan sobre TargetRegInfo
 *
 * Cada uno reconstruye a su manera "que registros hay, que anchos presentan,
 * cuales se preservan, cuales aliasan".  El @c PhysicalRegisterBank es la
 * abstraccion donde TODOS miran el MISMO objeto.  Direccion de dependencia:
 *
 *                         PhysicalRegisterBank
 *                          ^                ^
 *                    BackendCaps      TargetTraits
 *                                          ^
 *                                  TargetRegInfo (adaptador legacy)
 *
 * TargetTraits es la fuente NEUTRAL (ISA+ABI en datos); @c TargetRegInfo se
 * consume via @c target_traits_from_reginfo (adaptador), no al reves -> el
 * modelo no depende del tipo legacy.  En Fase 0.25 los consumidores dejan de
 * preguntar a TargetRegInfo/BackendCaps/arch-data y consultan el banco.  Eso
 * prepara SVE, RVV, mask-regs AVX-512, GPU y recursos no-registro.
 *
 * SEPARACION DE EJES (aprendizaje de diseno, memoria proj_wide_bank_regalloc):
 *   - GEOMETRIA (ISA, independiente del ABI): que anchos presenta una lane
 *     (@c ViewGeom: width + spill_align) y que lanes aliasa (@c AliasSet).
 *   - ABI (depende de ISA + ABI + View): la PRESERVACION.  La misma lane XMM6
 *     es 128-preserved / 256-volatile en Win64 y todo-volatile en SysV -> la
 *     preservacion es de (Lane, ABI, View), NO de la vista.  Vive en
 *     @c Lane::preservation (por-vista); un banco es siempre ABI-especifico.
 *   - RESERVAS: su MOTIVO se clasifica por categoria (@c ReserveReason) porque
 *     el allocator razona distinto: OPTIMIZATION (VEC_ACC) es NEGOCIABLE; ABI
 *     (frame) es INAMOVIBLE.
 *
 * ============================ INVARIANTES ==================================
 * Reglas fuertes que TODO consumidor puede asumir (y que NADIE debe romper):
 *   I1. El orden de @c lanes es INMUTABLE tras construir el banco.  Nunca se
 *       reordena (p.ej. @c sort): @c AliasSet indexa por POSICION-de-lane, no
 *       por id -> reordenar romperia todos los alias.
 *   I2. @c id_to_index nunca cambia tras la construccion.
 *   I3. @c AliasSet siempre referencia INDICES de lane (posicion en @c lanes),
 *       nunca ids fisicos.
 *   I4. @c ViewGeom es geometria INMUTABLE (ISA); no depende del ABI ni cambia.
 *   I5. Un @c PhysicalRegisterBank es ABI-ESPECIFICO y de SOLO LECTURA tras
 *       construirse (sysv y win64 son bancos distintos).
 *
 * ============================ API PUBLICA =================================
 * Los consumidores usan las CONSULTAS del banco (@c supports, @c preservation,
 * @c is_allocatable, @c allocatable_count, @c aliases_of, @c spill_align,
 * @c views, @c lane_count, @c by_id), NO el acceso directo a @c lanes /
 * @c Lane::views / @c Lane::preservation.  Los miembros son publicos por
 * simplicidad del builder/test, pero se consideran REPRESENTACION INTERNA: las
 * consultas permiten cambiarla sin romper clientes.
 *
 * ============================ SERIALIZACION ===============================
 * El modelo describe DATOS, no comportamiento oculto: @c TargetDescriptor (name
 * + @c TargetTraits + specs por clase) es serializable tal cual, y
 * @c build_physical_bank es una funcion pura (descriptor -> banco).  Es decir,
 * @c TargetDescriptor -> JSON/YAML -> @c PhysicalRegisterBank saldria natural.
 * No se implementa aqui; es una comprobacion de que el nivel es datos puros.
 */

#ifndef VESTA_CODEGEN_RBANK_PHYSICAL_BANK_H
#define VESTA_CODEGEN_RBANK_PHYSICAL_BANK_H

#include "codegen/rbank/fnv.h"
#include "jit/backend_caps.h"
#include "jit/machine_ir.h"
#include "jit/target_reginfo.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib> // getenv, para la valvula de la memoizacion del banco
#include <string>
#include <vector>

namespace codegen {
namespace rbank {

// Tipos + factorias de las FUENTES (modulo jit) que el banco CONSUME para
// construirse.  El banco es de codegen (3 modos); sus insumos
// (caps/reginfo/ISA) son de jit.  target_traits_from_reginfo es del PROPIO
// rbank (adaptador, mas abajo), no de jit -> no se importa.
using jit::BackendCaps;
using jit::build_arm64_target;
using jit::MReg;
using jit::RegClass;
using jit::target_x86_32;
using jit::target_x86_64_abi;
using jit::TargetRegInfo;

// ===========================================================================
//  Clases de recurso.
// ===========================================================================

/**
 * @enum ResourceClass
 * @brief Clase logica de un recurso, superset de @c jit::RegClass.
 *
 * GP=0 y FP_VECTOR=1 COINCIDEN en valor con @c jit::RegClass para indexar las
 * tablas del target sin traduccion.  MASK/PREDICATE son extensiones futuras.
 *
 * @note DIRECCION FUTURA (P14): esto todavia "piensa en registros".  Cuando
 *       entren recursos que NO son registros (cache-line, scratchpad, tensor,
 *       DMA-channel), este enum evolucionara a un @c ResourceKind mas amplio
 *       (p.ej. GP / FP_VECTOR / PREDICATE / MASK / SPECIAL / CUSTOM).  No se
 *       toca ahora; solo se deja la senal de hacia donde crece.
 */
enum class ResourceClass : uint8_t {
    GP = 0,        ///< registros enteros de proposito general.
    FP_VECTOR = 1, ///< banco escalar-float + vector (XMM/YMM/ZMM, NEON, ...).
    MASK = 2,      ///< mascaras de prediccion (k0..k7 AVX-512).
    PREDICATE = 3, ///< predicados escalables (p0..p15 SVE).
    COUNT
};

static constexpr size_t kResourceClassCount =
    static_cast<size_t>(ResourceClass::COUNT);

/** @brief @c jit::RegClass -> @c ResourceClass (identidad GP/FP). */
constexpr ResourceClass to_resource_class(RegClass c) noexcept {
    return static_cast<ResourceClass>(static_cast<uint8_t>(c));
}

// ===========================================================================
//  Geometria de vistas (ISA, ABI-independiente).
// ===========================================================================

/**
 * @enum ViewWidth
 * @brief Ancho en BYTES con el que una lane puede nombrarse (potencia de 2).
 */
enum class ViewWidth : uint16_t {
    W1 = 1,
    W2 = 2,
    W4 = 4,
    W8 = 8,
    W16 = 16,
    W32 = 32,
    W64 = 64,
};

/** @brief log2 del ancho en bytes (1..64 -> 0..6). */
constexpr uint32_t view_log(ViewWidth w) noexcept {
    uint32_t bytes = static_cast<uint32_t>(w), b = 0;
    while (bytes > 1) {
        bytes >>= 1;
        ++b;
    }
    return b;
}
/** @brief Bit de mascara de un ancho (= 1 << view_log). */
constexpr uint32_t view_bit(ViewWidth w) noexcept {
    return 1u << view_log(w);
}

/**
 * @enum ViewIndex
 * @brief Slot SEMANTICO para las tablas indexadas por-vista (@c preservation).
 *
 * En vez de indexar con un entero crudo (donde "5" significaria "32 bytes" --
 * fragil), se indexa con este enum: @c preservation[ViewIndex::W32] se lee
 * solo.  Los nombres COINCIDEN 1:1 con @c ViewWidth (W32 = 32 bytes) para dejar
 * la correspondencia explicita.  Internamente sigue siendo un array plano.
 */
enum class ViewIndex : uint8_t { W1 = 0, W2, W4, W8, W16, W32, W64, COUNT };
static constexpr size_t kMaxViews = static_cast<size_t>(ViewIndex::COUNT);

/** @brief @c ViewWidth -> @c ViewIndex (slot de las tablas por-vista). */
constexpr ViewIndex view_index(ViewWidth w) noexcept {
    return static_cast<ViewIndex>(view_log(w));
}

/** @brief Alineamiento (bytes) de un slot de pila que aloja la vista @p w. */
constexpr uint16_t view_spill_align(ViewWidth w) noexcept {
    uint16_t bytes = static_cast<uint16_t>(w);
    return bytes < 8 ? 8 : bytes; // nunca menor que un qword.
}

/**
 * @struct ViewGeom
 * @brief GEOMETRIA de una vista (INMUTABLE, invariante I4): ancho +
 *        alineamiento de spill.  Propiedad de la ISA, NO del ABI.
 */
struct ViewGeom {
    ViewWidth width;      ///< ancho de la vista.
    uint16_t spill_align; ///< alineamiento del slot de pila (bytes).
};

// ===========================================================================
//  AliasSet: abstraccion sobre el conjunto de lanes que un recurso ocupa.
//  INVARIANTE I3: indexa POSICIONES-de-lane, nunca ids.  Hoy uint64; manana
//  puede crecer a bitset dinamico (SVE/RVV/GPU) sin tocar los call sites.
// ===========================================================================

/**
 * @struct AliasSet
 * @brief Conjunto de INDICES-de-lane (posicion en @c
 * PhysicalRegisterBank::lanes) que un recurso ocupa al usarse.  Abstrae la
 * representacion (hoy uint64).
 */
struct AliasSet {
    uint64_t bits = 0;

    void add(size_t lane_index) noexcept {
        bits |= (uint64_t{1} << lane_index);
    }
    bool test(size_t lane_index) const noexcept {
        return (bits & (uint64_t{1} << lane_index)) != 0;
    }
    /** @brief True si comparte alguna lane con @p o (interferencia). */
    bool overlaps(const AliasSet &o) const noexcept {
        return (bits & o.bits) != 0;
    }
    void merge(const AliasSet &o) noexcept { bits |= o.bits; }
    bool empty() const noexcept { return bits == 0; }
};

// ===========================================================================
//  Reservas: categoria (POR QUE) + provenance (QUE) + si es negociable.
// ===========================================================================

/**
 * @enum ReserveReason
 * @brief CATEGORIA de una reserva.  El allocator razona distinto sobre cada
 *        una: ABI/PLATFORM/SCRATCH inamovibles; OPTIMIZATION negociable; DEBUG
 *        opcional.
 */
enum class ReserveReason : uint8_t {
    NONE = 0,     ///< no reservada: asignable por el allocator general.
    ABI,          ///< impuesta por el ABI (frame, puntero fijo del ABI).
    PLATFORM,     ///< portabilidad de plataforma, o reserva IMPLICITA
                  ///< superficiada por el round-trip (ver @c implicit).
    OPTIMIZATION, ///< por una optimizacion (VEC_ACC).  NEGOCIABLE.
    SCRATCH,      ///< temporal del rewrite (spills / two-address).
    DEBUG,        ///< reservada para depuracion/instrumentacion.
};

/** @enum ReserveKind @brief PROVENANCE especifica (dentro de su categoria). */
enum class ReserveKind : uint8_t {
    NONE = 0,
    FRAME,    ///< [ABI] RSP/RBP / x29/x30/sp: marco y enlace.
    ABI_PTR,  ///< [ABI] RBX = ProcessVM* (VM_ABI) u otro puntero fijo.
    PLATFORM, ///< [PLATFORM] x18 AArch64 Win/Darwin, o implicita sin nombre.
    VEC_ACC,  ///< [OPTIMIZATION] acumulador de reduccion/FMA vectorial.
    SCRATCH,  ///< [SCRATCH] temporal del rewrite.
};

/**
 * @struct Reservation
 * @brief Reserva de una lane: por que (categoria), que (provenance) y si es
 *        demand-driven (negociable) o implicita.
 */
struct Reservation {
    ReserveReason reason = ReserveReason::NONE;
    ReserveKind kind = ReserveKind::NONE;
    bool demand_driven = false; ///< liberable si su path no se usa.
    bool implicit = false;      ///< descubierta como ausencia.

    bool is_free() const noexcept { return reason == ReserveReason::NONE; }
    bool is_scratch() const noexcept {
        return reason == ReserveReason::SCRATCH;
    }
};

/**
 * @enum SavePolicy
 * @brief Preservacion de una lane/vista a traves de un CALL.  Propiedad de
 *        (Lane, ABI, View), NO de la geometria de la vista.
 */
enum class SavePolicy : uint8_t {
    VOLATILE = 0,  ///< caller-saved: se pierde al cruzar un CALL.
    PRESERVED = 1, ///< callee-saved: el callee debe salvarlo.
    RESERVED = 2,  ///< no participa como valor (frame/ABI-ptr/scratch).
};

/** @brief Roles ABI de una lane (bitset). */
enum RoleBits : uint8_t {
    ROLE_NONE = 0,
    ROLE_ARG = 1u << 0, ///< pasa argumentos.
    ROLE_RET = 1u << 1, ///< recibe el valor de retorno.
};

// ===========================================================================
//  Lane: unidad fisica asignable (caso particular de Resource, ver P14).
// ===========================================================================

/**
 * @struct Lane
 * @brief Unidad fisica asignable del banco (un "registro").
 *
 * Separa GEOMETRIA (@c views + @c aliases) de ABI (@c preservation por-vista).
 * Miembros publicos por simplicidad del builder, pero REPRESENTACION INTERNA:
 * los consumidores usan las consultas del @c PhysicalRegisterBank.
 */
struct Lane {
    uint8_t id = 0;                        ///< id fisico del target.
    ResourceClass cls = ResourceClass::GP; ///< clase de recurso.

    // --- Geometria (ISA) ---
    std::vector<ViewGeom> views; ///< vistas soportadas (I4: inmutables).
    uint32_t view_mask = 0;      ///< OR de view_bit (fast supports).
    AliasSet aliases;            ///< lanes que ocupa (I3: indices).

    // --- ABI ---
    /// Preservacion POR-VISTA (indexada por @c ViewIndex).  Modela el matiz
    /// Win64 (128 preserved / 256+ volatile).  Poblada segun el ABI del banco.
    std::array<SavePolicy, kMaxViews> preservation{};

    // --- Reserva / roles ---
    Reservation reserve;       ///< por que no esta libre (o NONE).
    uint8_t roles = ROLE_NONE; ///< OR de RoleBits.

    Lane() { preservation.fill(SavePolicy::VOLATILE); }

    bool supports(ViewWidth w) const noexcept {
        return (view_mask & view_bit(w)) != 0;
    }
    SavePolicy preservation_of(ViewWidth w) const noexcept {
        return preservation[static_cast<size_t>(view_index(w))];
    }
    bool allocatable(bool vec_reduction_active) const noexcept {
        if (reserve.is_free()) return true;
        return reserve.demand_driven && !vec_reduction_active;
    }
};

/**
 * @struct BankFingerprint
 * @brief Identidad observable de un banco (tipo FUERTE, no un @c uint64 crudo:
 *        no se mezcla accidentalmente con la huella del problema o de una
 * policy).
 */
struct BankFingerprint {
    uint64_t value = 0;
    bool operator==(const BankFingerprint &o) const noexcept {
        return value == o.value;
    }
};

/**
 * @struct PhysicalRegisterBank
 * @brief Banco fisico de un backend/target (nivel 3).  ABI-especifico y de
 *        SOLO LECTURA tras construirse (invariante I5).  Usar las CONSULTAS,
 *        no el acceso directo a @c lanes.
 */
struct PhysicalRegisterBank {
    std::string name;      ///< identidad ABI-especifica ("x86-64-sysv"...).
    std::string microarch; ///< uarch de arch-data alineada (o vacio).
    uint8_t pointer_size = 8;
    bool is_two_address = true;

    std::vector<Lane> lanes;               ///< I1: orden INMUTABLE tras build.
    std::array<int16_t, 64> id_to_index{}; ///< I2: id fisico -> indice (o -1).

    PhysicalRegisterBank() { id_to_index.fill(-1); }

    // --- Consultas (API PUBLICA estable) ---

    /** @brief Lane de id @p id, o @c nullptr. */
    const Lane *by_id(uint8_t id) const noexcept {
        if (id >= 64 || id_to_index[id] < 0) return nullptr;
        return &lanes[static_cast<size_t>(id_to_index[id])];
    }
    /** @brief Numero de lanes de la clase @p cls. */
    size_t lane_count(ResourceClass cls) const noexcept {
        size_t n = 0;
        for (const auto &l : lanes)
            if (l.cls == cls) ++n;
        return n;
    }
    /**
     * @brief Lanes ASIGNABLES de @p cls.
     * @param vec_reduction_active  si la funcion usa el path de reduccion
     *        vectorial: con @c false, los VEC_ACC demand-driven cuentan.
     */
    size_t allocatable_count(ResourceClass cls,
                             bool vec_reduction_active) const noexcept {
        size_t n = 0;
        for (const auto &l : lanes)
            if (l.cls == cls && l.allocatable(vec_reduction_active)) ++n;
        return n;
    }
    /** @brief True si la lane @p id es asignable dado el path de reduccion. */
    bool is_allocatable(uint8_t id, bool vec_reduction_active) const noexcept {
        const Lane *l = by_id(id);
        return l && l->allocatable(vec_reduction_active);
    }
    /**
     * @brief True si existe ALGUNA lane asignable de clase @p cls que soporte
     *        la vista @p w (el banco puede alojar un valor de ese tipo).
     * @param vec_reduction_active  cuenta o no los VEC_ACC demand-driven.
     */
    bool can_hold(ResourceClass cls, ViewWidth w,
                  bool vec_reduction_active) const noexcept {
        for (const auto &l : lanes)
            if (l.cls == cls && l.allocatable(vec_reduction_active) &&
                l.supports(w))
                return true;
        return false;
    }
    /** @brief True si la lane @p id soporta la vista @p w. */
    bool supports(uint8_t id, ViewWidth w) const noexcept {
        const Lane *l = by_id(id);
        return l && l->supports(w);
    }
    /** @brief Preservacion de la lane @p id en la vista @p w (o RESERVED). */
    SavePolicy preservation(uint8_t id, ViewWidth w) const noexcept {
        const Lane *l = by_id(id);
        return l ? l->preservation_of(w) : SavePolicy::RESERVED;
    }
    /** @brief Alineamiento de spill de la lane @p id en la vista @p w (0 si no
     * soporta). */
    uint16_t spill_align(uint8_t id, ViewWidth w) const noexcept {
        const Lane *l = by_id(id);
        if (!l) return 0;
        for (const ViewGeom &g : l->views)
            if (g.width == w) return g.spill_align;
        return 0;
    }
    /** @brief Vistas soportadas por la lane @p id (o @c nullptr). */
    const std::vector<ViewGeom> *views(uint8_t id) const noexcept {
        const Lane *l = by_id(id);
        return l ? &l->views : nullptr;
    }
    /** @brief AliasSet de la lane @p id (o @c nullptr). */
    const AliasSet *aliases_of(uint8_t id) const noexcept {
        const Lane *l = by_id(id);
        return l ? &l->aliases : nullptr;
    }
    /** @brief Reserva de la lane @p id (o una NONE si no existe). */
    Reservation reservation_of(uint8_t id) const noexcept {
        const Lane *l = by_id(id);
        return l ? l->reserve : Reservation{};
    }

    /**
     * @brief IDENTIDAD OBSERVABLE del banco para un algoritmo de asignacion:
     * dos bancos que colorearian distinto dan huellas distintas.  Es una
     *        pregunta sobre el BANCO (por eso vive aqui), que la cache de
     *        soluciones consume para su key.  Incluye el nombre (ABI) + las
     * lanes asignables por clase relevante (que cambian con @p vec_active por
     * los VEC_ACC demand-driven).
     */
    BankFingerprint fingerprint(bool vec_active) const {
        uint64_t h = kFnvOffset;
        for (char c : name)
            h = fnv_mix(h, static_cast<uint64_t>(c));
        for (ResourceClass cls :
             {ResourceClass::GP, ResourceClass::FP_VECTOR, ResourceClass::MASK,
              ResourceClass::PREDICATE})
            h = fnv_mix(h, allocatable_count(cls, vec_active));
        h = fnv_mix(h, vec_active ? 1u : 0u);
        return BankFingerprint{h};
    }
};

// ===========================================================================
//  TargetTraits: fuente NEUTRAL (ISA+ABI en datos).  TargetRegInfo se adapta a
//  esto (no al reves): el modelo no depende del tipo legacy.
// ===========================================================================

/**
 * @struct TargetTraits
 * @brief Descripcion ISA+ABI NEUTRAL de un target (datos puros).  Fuente de la
 *        que se construye el banco.  @c TargetRegInfo es una de sus fuentes
 *        (via @c target_traits_from_reginfo); en el futuro un descriptor nativo
 *        (o deserializado de JSON/YAML) puede producir @c TargetTraits sin
 * pasar por el tipo legacy.
 */
struct TargetTraits {
    uint8_t pointer_size = 8;
    bool is_two_address = true;
    std::vector<uint8_t> reserved; ///< frame / punteros fijos del ABI (ids).

    /** @brief Roles ABI de una clase (listas de ids). */
    struct ClassAbi {
        std::vector<uint8_t> allocatable;  ///< asignables.
        std::vector<uint8_t> scratch;      ///< temporales del rewrite.
        std::vector<uint8_t> caller_saved; ///< volatiles.
        std::vector<uint8_t> callee_saved; ///< preservados.
        std::vector<uint8_t> arg_regs;     ///< paso de argumentos.
        uint8_t ret_reg = 0;               ///< registro de retorno.
    };
    std::array<ClassAbi, kResourceClassCount> classes;
};

/** @brief Adaptador legacy: @c TargetRegInfo -> @c TargetTraits (neutral). */
inline TargetTraits target_traits_from_reginfo(const TargetRegInfo &t) {
    TargetTraits tr;
    tr.pointer_size = t.pointer_size;
    tr.is_two_address = t.is_two_address;
    tr.reserved = t.reserved;
    for (size_t ci = 0; ci < TargetRegInfo::NCLASS; ++ci) {
        TargetTraits::ClassAbi &c = tr.classes[ci];
        c.allocatable = t.allocatable[ci];
        c.scratch = t.scratch[ci];
        c.caller_saved = t.caller_saved[ci];
        c.callee_saved = t.callee_saved[ci];
        c.arg_regs = t.arg_regs[ci];
        c.ret_reg = t.ret_reg[ci];
    }
    // MASK/PREDICATE quedan vacias (ningun target legacy las produce).
    return tr;
}

// ===========================================================================
//  Descriptor de target (DATA) + builder generico.
// ===========================================================================

/**
 * @struct ClassSpec
 * @brief Especificacion GEOMETRICA declarativa de una clase: rango de ids +
 *        vistas + ids reservados por optimizacion (VEC_ACC).
 */
struct ClassSpec {
    uint8_t first_id = 1;          ///< primer id (first>last = vacia).
    uint8_t last_id = 0;           ///< ultimo id inclusivo.
    std::vector<ViewWidth> widths; ///< vistas de la clase (resueltas por caps).
    std::vector<uint8_t> vec_acc;  ///< ids VEC_ACC (demand-driven).
};

/**
 * @struct TargetDescriptor
 * @brief Descripcion declarativa COMPLETA de un target (DATA pura,
 * serializable): identidad + @c TargetTraits (ABI neutral) + geometria por
 * clase.
 */
struct TargetDescriptor {
    std::string name;    ///< identidad del banco.
    TargetTraits traits; ///< ISA+ABI neutral.
    std::array<ClassSpec, kResourceClassCount>
        classes; ///< geometria por clase.
};

/** @brief Vistas de la clase FP x86 segun capacidades (SSE2 baseline). */
inline std::vector<ViewWidth> x86_fp_widths(const BackendCaps &caps) {
    std::vector<ViewWidth> w = {ViewWidth::W4, ViewWidth::W8, ViewWidth::W16};
    if (caps.avx) w.push_back(ViewWidth::W32);
    if (caps.avx512f) w.push_back(ViewWidth::W64);
    return w;
}
/** @brief Vistas de la clase GP segun el ancho de puntero. */
inline std::vector<ViewWidth> gp_widths(uint8_t pointer_size) {
    std::vector<ViewWidth> w = {ViewWidth::W1, ViewWidth::W2, ViewWidth::W4};
    if (pointer_size >= 8) w.push_back(ViewWidth::W8);
    return w;
}

/**
 * @brief Construye el @c PhysicalRegisterBank desde un @c TargetDescriptor.
 *        Funcion PURA (descriptor -> banco): sin estado ni efectos ocultos.
 *
 * Clasifica cada id del rango de una clase en NONE (allocatable), SCRATCH, ABI
 * (reserved), OPTIMIZATION/VEC_ACC (declarado) o PLATFORM implicita (ausente de
 * toda lista).  La preservacion por-vista se deriva del ABI (caller/callee)
 * uniformemente (el matiz Win64 upper-volatile se refinara al cerrar cross-call
 * FP; el modelo ya lo admite).  Alias = self (x86/AArch64/interp comparten id).
 */
inline PhysicalRegisterBank build_physical_bank(const TargetDescriptor &d) {
    const TargetTraits &tr = d.traits;
    PhysicalRegisterBank b;
    b.name = d.name;
    b.pointer_size = tr.pointer_size;
    b.is_two_address = tr.is_two_address;

    auto contains = [](const std::vector<uint8_t> &v, uint8_t x) {
        for (uint8_t e : v)
            if (e == x) return true;
        return false;
    };

    for (size_t ci = 0; ci < kResourceClassCount; ++ci) {
        const ClassSpec &spec = d.classes[ci];
        if (spec.first_id > spec.last_id) continue; // clase vacia.
        const ResourceClass rcls = static_cast<ResourceClass>(ci);
        const TargetTraits::ClassAbi &abi = tr.classes[ci];

        for (uint32_t idw = spec.first_id; idw <= spec.last_id; ++idw) {
            const uint8_t id = static_cast<uint8_t>(idw);
            Lane l;
            l.id = id;
            l.cls = rcls;

            const bool caller = contains(abi.caller_saved, id);
            const bool callee = contains(abi.callee_saved, id);
            if (contains(abi.arg_regs, id)) l.roles |= ROLE_ARG;
            if (abi.ret_reg == id && (caller || callee)) l.roles |= ROLE_RET;

            // Clasificacion de la reserva (categoria + provenance).
            if (contains(abi.allocatable, id)) {
                l.reserve = {ReserveReason::NONE, ReserveKind::NONE, false,
                             false};
            } else if (contains(abi.scratch, id)) {
                l.reserve = {ReserveReason::SCRATCH, ReserveKind::SCRATCH,
                             false, false};
            } else if (contains(tr.reserved, id)) {
                l.reserve = {ReserveReason::ABI, ReserveKind::FRAME, false,
                             false};
            } else if (contains(spec.vec_acc, id)) {
                l.reserve = {ReserveReason::OPTIMIZATION, ReserveKind::VEC_ACC,
                             true, false};
            } else {
                l.reserve = {ReserveReason::PLATFORM, ReserveKind::PLATFORM,
                             false, true};
            }

            // Preservacion por-vista (ABI, uniforme hoy).
            const SavePolicy sp =
                l.reserve.is_free()
                    ? (callee ? SavePolicy::PRESERVED : SavePolicy::VOLATILE)
                    : SavePolicy::RESERVED;
            l.preservation.fill(sp);

            // Geometria: vistas + alineamiento.
            for (ViewWidth w : spec.widths) {
                l.views.push_back(ViewGeom{w, view_spill_align(w)});
                l.view_mask |= view_bit(w);
            }

            b.id_to_index[id] = static_cast<int16_t>(b.lanes.size());
            b.lanes.push_back(std::move(l));
        }
    }

    // Alias sets (I3: indices).  Self-alias; mecanismo listo para pares/SVE.
    for (size_t i = 0; i < b.lanes.size(); ++i)
        b.lanes[i].aliases.add(i);

    return b;
}

/** @brief Ensambla un @c classes[] de COUNT clases desde GP/FP. */
inline std::array<ClassSpec, kResourceClassCount>
make_class_specs(ClassSpec gp, ClassSpec fp) {
    std::array<ClassSpec, kResourceClassCount> s{};
    s[static_cast<size_t>(ResourceClass::GP)] = std::move(gp);
    s[static_cast<size_t>(ResourceClass::FP_VECTOR)] = std::move(fp);
    s[static_cast<size_t>(ResourceClass::MASK)] = ClassSpec{1, 0, {}, {}};
    s[static_cast<size_t>(ResourceClass::PREDICATE)] = ClassSpec{1, 0, {}, {}};
    return s;
}

// --- Descriptores por-arquitectura (DATA; usan el adaptador legacy) ---

/** @brief Descriptor x86-64 (SysV/Win64) con vistas FP de @p caps. */
inline TargetDescriptor descriptor_x86_64(bool sysv, const BackendCaps &caps) {
    TargetDescriptor d;
    d.name = sysv ? "x86-64-sysv" : "x86-64-win64";
    d.traits = target_traits_from_reginfo(target_x86_64_abi(sysv));
    d.classes = make_class_specs(
        ClassSpec{0, 15, gp_widths(8), {}},
        ClassSpec{16, 31, x86_fp_widths(caps), {26, 27, 28, 29}}); // XMM10-13.
    return d;
}
/** @brief Descriptor x86-32 (regparm3).  GP 0-7; FP vacia. */
inline TargetDescriptor descriptor_x86_32() {
    TargetDescriptor d;
    d.name = "x86-32";
    d.traits = target_traits_from_reginfo(target_x86_32());
    d.classes = make_class_specs(ClassSpec{0, 7, gp_widths(4), {}},
                                 ClassSpec{1, 0, {}, {}});
    return d;
}
/** @brief Descriptor AArch64.  GP 0-30, FP/SIMD 32-63 (sin VEC_ACC). */
inline TargetDescriptor descriptor_arm64(const BackendCaps & /*caps*/) {
    TargetDescriptor d;
    d.name = "arm64";
    d.traits = target_traits_from_reginfo(build_arm64_target());
    d.classes = make_class_specs(
        ClassSpec{0, 30, gp_widths(8), {}},
        ClassSpec{32, 63, {ViewWidth::W4, ViewWidth::W8, ViewWidth::W16}, {}});
    return d;
}
/** @brief Descriptor del INTERPRETE (banco ancho de la VM, TargetTraits
 * sintetico). */
inline TargetDescriptor descriptor_interp() {
    TargetDescriptor d;
    d.name = "interp";
    TargetTraits tr;
    tr.pointer_size = 8;
    tr.is_two_address = false;
    const size_t GP = static_cast<size_t>(ResourceClass::GP);
    const size_t FP = static_cast<size_t>(ResourceClass::FP_VECTOR);
    for (uint8_t r = 0; r <= 15; ++r)
        tr.classes[GP].allocatable.push_back(r);
    for (uint8_t r = 16; r <= 31; ++r)
        tr.classes[FP].allocatable.push_back(r);
    tr.classes[GP].ret_reg = 0;
    tr.classes[FP].ret_reg = 16;
    d.traits = std::move(tr);
    d.classes = make_class_specs(
        ClassSpec{0, 15, gp_widths(8), {}},
        ClassSpec{16,
                  31,
                  {ViewWidth::W4, ViewWidth::W8, ViewWidth::W16, ViewWidth::W32,
                   ViewWidth::W64},
                  {}});
    return d;
}

/**
 * @brief Descriptor x86-64 desde un @c TargetRegInfo YA construido (el del PATH
 * real:
 *        @c target_x86_64_vm_abi del JIT, @c target.reg_info() del AOT...).  El
 *        ClassSpec x86-64 es fijo (GP 0-15, XMM 16-31 con VEC_ACC 26-29); solo
 * las traits (allocatable / reservas / preservation) vienen del @p tri -> el
 * banco describe EXACTAMENTE el mismo problema que ve el backend (rewrite) de
 * ese path.
 */
inline TargetDescriptor
descriptor_x86_64_from_reginfo(const TargetRegInfo &tri,
                               const BackendCaps &caps) {
    TargetDescriptor d;
    d.name = "x86-64";
    d.traits = target_traits_from_reginfo(tri);
    /* El tope de la clase ancha sale del OBJETIVO, no de un numero fijo: con
     * AVX-512 y una funcion que no emite coma flotante propia son 32 ranuras
     * (ids 16..47) en vez de 16.  Se toma del ultimo asignable que declare. */
    uint8_t fp_top = 31;
    for (uint8_t r : tri.allocatable[static_cast<size_t>(jit::RegClass::FP)])
        if (r > fp_top) fp_top = r;
    d.classes = make_class_specs(
        ClassSpec{0, 15, gp_widths(8), {}},
        ClassSpec{
            16, fp_top, x86_fp_widths(caps), {26, 27, 28, 29}}); // XMM10-13.
    return d;
}

// --- Wrappers de conveniencia (descriptor + banco) ---
inline PhysicalRegisterBank physical_bank_x86_64(bool sysv,
                                                 const BackendCaps &caps) {
    return build_physical_bank(descriptor_x86_64(sysv, caps));
}
/** @brief Banco x86-64 desde el @c TargetRegInfo del path real (JIT VM_ABI o
 * AOT). */
inline PhysicalRegisterBank
physical_bank_x86_64_from_reginfo(const TargetRegInfo &tri,
                                  const BackendCaps &caps) {
    return build_physical_bank(descriptor_x86_64_from_reginfo(tri, caps));
}
/**
 * @brief Igualdad POR VALOR de dos descriptores de registros.
 *
 * `TargetRegInfo` no define `operator==` y no se le anade desde aqui: es un
 * tipo de `jit/`, y darle igualdad seria decidir por otro modulo cuando dos de
 * sus objetos son el mismo.  Esta comparacion existe solo para la memoizacion
 * de abajo, y por eso vive con ella.
 */
inline bool same_target_reginfo(const TargetRegInfo &a,
                                const TargetRegInfo &b) noexcept {
    if (a.pointer_size != b.pointer_size ||
        a.is_two_address != b.is_two_address ||
        a.can_jump_to_abs_addr != b.can_jump_to_abs_addr ||
        a.stack_reg != b.stack_reg || a.reserved != b.reserved)
        return false;
    for (size_t c = 0; c < TargetRegInfo::NCLASS; ++c) {
        if (a.ret_reg[c] != b.ret_reg[c] ||
            a.allocatable[c] != b.allocatable[c] ||
            a.caller_saved[c] != b.caller_saved[c] ||
            a.callee_saved[c] != b.callee_saved[c] ||
            a.scratch[c] != b.scratch[c] || a.arg_regs[c] != b.arg_regs[c])
            return false;
    }
    return true;
}

/** @brief ¿Esta apagada la memoizacion del banco?  Ver la nota de la cache. */
inline bool rbank_cache_valve_off() noexcept {
    const char *v = std::getenv("VESTA_NO_RBANK_CACHE");
    return v != nullptr && v[0] != '\0' && v[0] != '0';
}

/**
 * @brief El mismo banco que @c physical_bank_x86_64_from_reginfo, memoizado.
 *
 * POR QUE EXISTE, con la medida que lo motivo.  El banco se construia una vez
 * POR FUNCION, desde `rbank_allocate`, y la cabecera de este mismo fichero
 * declara en su invariante I4 que la geometria es INMUTABLE: depende de la ISA,
 * no del ABI, y no cambia.  Se estaba rehaciendo algo constante una vez por
 * funcion compilada.
 *
 * Medido sobre el proyecto de 21 modulos del banco de compilacion (144k lineas,
 * `VESTA_HOST_ALLOC_SITES=1`), construirlo era:
 *
 *     4.608.096 reservas   41,0 MiB   crecer `std::vector<ViewGeom>`
 *       288.006 reservas  184,6 MiB   el resto de `build_physical_bank`
 *
 * 4,6 millones de reservas de 9,33 bytes de media -- tres viajes al monticulo
 * por lane para guardar 12 bytes.
 *
 * LA CLAVE ES POR VALOR, no la direccion de @p tri.  Los accesores del arbol
 * (`target_x86_64_abi`, `target_arm64`...) devuelven referencias a estaticos,
 * asi que comparar punteros funcionaria hoy; pero `build_x86_64_target` es
 * publico y devuelve POR VALOR, y un temporal puede reutilizar la direccion de
 * otro ya muerto.  Eso daria un banco equivocado sin fallar, que es el peor
 * modo de fallo.  Comparar los campos cuesta unos pocos memcmp de vectores de
 * bytes, dos ordenes de magnitud menos que construir el banco.
 *
 * Y la clave lleva los caps ENTEROS (`to_bits`) aunque hoy solo se miren `avx`
 * y `avx512f` en `x86_fp_widths`: si manana el banco pasa a depender de otro,
 * la clave ya lo cubre en vez de devolver algo caducado en silencio.
 *
 * MEMORIA POR HILO, sin cerrojos.  El compilador reparte los modulos de un
 * nivel topologico en hasta 8 hilos; un `static` compartido necesitaria
 * sincronizacion en un camino que se recorre una vez por funcion.  Una entrada
 * por hilo basta porque una tanda de compilacion procesa muchas funciones
 * seguidas para el MISMO objetivo: el fallo de cache ocurre al cambiar de
 * objetivo, no por funcion.
 *
 * @warning La referencia devuelta vive hasta la siguiente llamada EN ESTE HILO
 *          con una clave distinta.  Hoy es seguro tenerla durante toda una
 *          asignacion de registros porque nada aguas abajo vuelve a pedir un
 *          banco -- `rbank_solve` y `build_fragmentation_plan` lo reciben como
 *          parametro --, y son los dos unicos consumidores del arbol.  Quien
 *          anada un tercero que construya bancos dentro de esa ventana tiene
 *          que copiarlo en vez de guardar la referencia.
 */
inline const PhysicalRegisterBank &
physical_bank_x86_64_from_reginfo_cached(const TargetRegInfo &tri,
                                         const BackendCaps &caps) {
    /* Valvula de diagnostico: `VESTA_NO_RBANK_CACHE=1` la apaga.
     *
     * No es cortesia. Sin poder apagarla no hay contra que comparar, y
     * entonces "la cache suma" es una creencia y no una medida -- que es
     * justamente el error que este cambio vino a corregir.
     *
     * Se lee UNA vez, y con `std::getenv` en vez del registro de banderas de
     * `util/env_flags.h`: `flag_present` se define en un `.cpp`, y esta
     * cabecera la incluyen pruebas que hoy no enlazan esa biblioteca.  Anadir
     * una dependencia de enlace a ocho objetivos por una valvula de medida
     * saldria mas caro que la valvula. */
    static const bool disabled = rbank_cache_valve_off();
    if (disabled) {
        static thread_local PhysicalRegisterBank fresh;
        fresh = physical_bank_x86_64_from_reginfo(tri, caps);
        return fresh;
    }

    struct Memo {
        bool valid = false;
        TargetRegInfo key_tri;
        uint64_t key_caps = 0;
        PhysicalRegisterBank bank;
    };
    static thread_local Memo memo;

    const uint64_t bits = caps.to_bits();
    if (memo.valid && memo.key_caps == bits &&
        same_target_reginfo(memo.key_tri, tri))
        return memo.bank;

    memo.bank = physical_bank_x86_64_from_reginfo(tri, caps);
    memo.key_tri = tri;
    memo.key_caps = bits;
    memo.valid = true;
    return memo.bank;
}

inline PhysicalRegisterBank physical_bank_x86_32() {
    return build_physical_bank(descriptor_x86_32());
}
inline PhysicalRegisterBank physical_bank_arm64(const BackendCaps &caps) {
    return build_physical_bank(descriptor_arm64(caps));
}
inline PhysicalRegisterBank physical_bank_interp() {
    return build_physical_bank(descriptor_interp());
}

// ===========================================================================
//  Round-trip / validacion (Fase 0): el banco re-deriva exactamente el
//  allocatable/scratch del TargetRegInfo legacy -> valida toda la cadena
//  (TargetRegInfo -> TargetTraits -> TargetDescriptor -> banco).
// ===========================================================================

/** @struct RoundTripReport @brief Resultado de validar un banco vs su target.
 */
struct RoundTripReport {
    bool ok = true; ///< true si allocatable/scratch re-derivados coinciden.
    std::string mismatch; ///< primer desajuste (si @c !ok).
    /// Ids con reserva PLATFORM implicita (reservas que el target ocultaba).
    std::vector<uint8_t> unnamed_reserved;
};

/** @brief Valida que @p b re-deriva exactamente el allocatable/scratch de @p t.
 */
inline RoundTripReport
physical_bank_roundtrip_check(const PhysicalRegisterBank &b,
                              const TargetRegInfo &t) {
    RoundTripReport rep;
    auto sorted = [](std::vector<uint8_t> v) {
        std::sort(v.begin(), v.end());
        return v;
    };
    for (size_t ci = 0; ci < TargetRegInfo::NCLASS; ++ci) {
        const ResourceClass rcls = static_cast<ResourceClass>(ci);
        std::vector<uint8_t> alloc, scratch;
        for (const auto &l : b.lanes) {
            if (l.cls != rcls) continue;
            if (l.reserve.is_free()) alloc.push_back(l.id);
            if (l.reserve.is_scratch()) scratch.push_back(l.id);
            if (l.reserve.implicit) rep.unnamed_reserved.push_back(l.id);
        }
        if (sorted(alloc) != sorted(t.allocatable[ci])) {
            rep.ok = false;
            rep.mismatch = "allocatable de la clase " + std::to_string(ci) +
                           " no coincide con el TargetRegInfo";
            return rep;
        }
        if (sorted(scratch) != sorted(t.scratch[ci])) {
            rep.ok = false;
            rep.mismatch = "scratch de la clase " + std::to_string(ci) +
                           " no coincide con el TargetRegInfo";
            return rep;
        }
    }
    return rep;
}

} // namespace rbank
} // namespace codegen

#endif // VESTA_CODEGEN_RBANK_PHYSICAL_BANK_H
