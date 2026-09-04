/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/interval.cpp
 * @brief Implementacion del constructor de live intervals ( D.7).
 *
 * Ver interval.h y doc/REGALLOC.md.  Algoritmo: gen/kill por bloque ->
 * liveness por dataflow iterativo a punto fijo -> construccion de rangos en
 * una pasada backward por bloque.  Optimizado: liveness con bitsets
 * word-packed (uniones/diferencias por palabra de 64 bits), rangos en
 * vectores planos.
 */

#include "util/env_flags.h"
#include "jit/interval.h"

#include <algorithm>

namespace jit {

/* ===================================================================== */
/* operand_roles                                                          */
/* ===================================================================== */

InstrRoles operand_roles(MOp op) noexcept {
    using R = OperandRole;
    InstrRoles r;
    switch (op) {
    /* ALU binarios (forma 3-op pre-legalization): dst def, srcs use. */
    case MOp::ADD:
    case MOp::SUB:
    case MOp::IMUL:
    case MOp::AND:
    case MOp::OR:
    case MOp::XOR:
    case MOp::SHL:
    case MOp::SHR:
    case MOp::SAR:
    case MOp::ROL:
    case MOp::ROR:
    case MOp::DIVMOD_V: /* dst = src1 / src2 (variant: 0 DIV, 1 MOD) */
    case MOp::SHIFT_V:  /* dst = src1 <shift> src2 (cuenta variable en RCX) */
    /* arm64 3-op: division y select condicional (dst def, srcs use). */
    case MOp::A64_UDIV:
    case MOp::A64_SDIV:
    case MOp::A64_CSEL:
    /* arm64 float 3-op (dst def, srcs use). */
    case MOp::A64_FADD:
    case MOp::A64_FSUB:
    case MOp::A64_FMUL:
    case MOp::A64_FDIV:
        r.dst = R::DEF;
        r.src1 = R::USE;
        r.src2 = R::USE;
        break;
    /* Atomicas: CAS dst es IN/OUT (expected -> old); ADD dst solo salida. */
    case MOp::ATOMICCAS_V:
        r.dst = R::USEDEF; /* entra expected, sale old */
        r.src1 = R::USE;   /* addr */
        r.src2 = R::USE;   /* desired */
        break;
    case MOp::ATOMICADD_V:
        r.dst = R::USEDEF; /* entra delta, sale old (xadd 2-address) */
        r.src1 = R::USE;   /* addr */
        break;

    /* Unarios: dst def, src1 use. */
    case MOp::MOV:
    case MOp::MOVZX:
    case MOp::MOVSX:
    case MOp::NEG:
    case MOp::NOT:
    case MOp::INC:
    case MOp::DEC:
    case MOp::BSWAP:
    case MOp::POPCNT:
    case MOp::LZCNT:
    case MOp::TZCNT:
        r.dst = R::DEF;
        r.src1 = R::USE;
        break;

    /* LEA dst, base, disp: dst def, base(src1) use, disp(src2) imm. */
    case MOp::LEA:
        r.dst = R::DEF;
        r.src1 = R::USE;
        break;

    /* SETcc dst: solo def (lee flags, no regs). */
    case MOp::SETCC: r.dst = R::DEF; break;

    /* arm64: CSET dst (lee flags); extensiones/mvn/fmov/fneg/... unarios;
     * conversiones int<->float; CBNZ/CBZ leen el reg testeado (dst = label);
     * FCMP setea flags (solo lee). */
    case MOp::A64_CSET: r.dst = R::DEF; break;
    case MOp::A64_MVN:
    case MOp::A64_SXTB:
    case MOp::A64_UXTB:
    case MOp::A64_FMOV:
    case MOp::A64_FNEG:
    case MOp::A64_FABS:
    case MOp::A64_FSQRT:
    case MOp::A64_SCVTF:
    case MOp::A64_UCVTF:
    case MOp::A64_FCVTZS:
    case MOp::A64_FCVTZU:
    case MOp::A64_FCVT:
        r.dst = R::DEF;
        r.src1 = R::USE;
        break;
    case MOp::A64_CBNZ:
    case MOp::A64_CBZ: r.src1 = R::USE; break;
    case MOp::A64_FCMP:
        r.src1 = R::USE;
        r.src2 = R::USE;
        break;

    /* CMOVcc dst, src: dst es use+def (condicional preserva), src use. */
    case MOp::CMOVCC:
        r.dst = R::USEDEF;
        r.src1 = R::USE;
        break;

    /* Comparaciones: solo leen (setean flags). */
    case MOp::CMP:
    case MOp::TEST:
        r.src1 = R::USE;
        r.src2 = R::USE;
        break;

    /* UCOMISD/UCOMISS: compare FP (setea flags, NO escribe).  Se emiten con
     * @c make_unary(ucmp, a, b) -> el operando @c a ocupa el slot DST pero se
     * LEE (no se define).  Marcarlo como USE: si quedara en NONE (default) la
     * liveness no veria @c a vivo en el ucomisd -> su XMM se reusaria para
     * @c b -> @c ucomisd xmm0, xmm0 (compara un valor consigo mismo).  CMP/TEST
     * enteros no sufren esto porque usan src1/src2 (mk_cmp), no el slot dst. */
    case MOp::UCOMISD:
    case MOp::UCOMISS:
        r.dst = R::USE;
        r.src1 = R::USE;
        break;

    /* IDIV src: divisor use; dividendo/resultado en RAX/RDX (fijos,
     * constraints del allocator).  CQO no toca vregs. */
    case MOp::IDIV: r.src1 = R::USE; break;

    /* PUSH src / POP dst (prologue de callee-saved; raramente vregs). */
    case MOp::PUSH: r.src1 = R::USE; break;
    case MOp::POP: r.dst = R::DEF; break;

    /* ARG: marca un argumento de CALL; su vreg (src1) es un USE
     * (vivo hasta justo antes de la llamada). */
    case MOp::ARG: r.src1 = R::USE; break;

    /* LOAD: dst = [addr].  STORE: [addr] = val (commit 7). */
    /* El hueco libre de cada forma puede llevar el INDICE de la direccion
     * fusionada, y entonces es un USO como cualquier otro: si no se declara, su
     * intervalo muere antes de tiempo y el registro se reparte a otro.
     *
     * Declararlo cuando lleva el desplazamiento no molesta: un IMM32 no es un
     * vreg y el constructor lo ignora via `is_vreg()`, igual que ya hacia con
     * el indice de imm64 de LOAD_VM/STORE_VM. */
    case MOp::LOAD:
        r.dst = R::DEF;
        r.src1 = R::USE;
        r.src2 = R::USE;
        break;
    case MOp::STORE:
        r.dst = R::USE;
        r.src1 = R::USE;
        r.src2 = R::USE;
        break;
    /* LOAD_VM/STORE_VM (vm_mem, 2026-06-09): igual rol que LOAD/STORE.
     * Los operandos imm64_idx (src2 en LOAD_VM, dst en STORE_VM) no son
     * vregs -> el interval builder los ignora via is_vreg(). */
    case MOp::LOAD_VM:
        r.dst = R::DEF;
        r.src1 = R::USE;
        break;
    case MOp::STORE_VM:
        r.src1 = R::USE;
        r.src2 = R::USE;
        break;
    /* ALLOCA: dst = host_ptr al frame (src1 = size imm, no es vreg). */
    case MOp::ALLOCA: r.dst = R::DEF; break;
    /* ALLOCA_VM: dst = vaddr al VM stack (src1 = size imm).  Solo
     * mueve proc->stack_pointer (mov/sub/mov), NO hace CALL -> NO es
     * call-position. */
    case MOp::ALLOCA_VM: r.dst = R::DEF; break;

    /* FP scalar (XMM).  Forma 3-op pre-legalization (dst def, srcs use):
     * el rewrite legaliza a 2-address (mov dst,src1 + OP dst,src2).  XORPS
     * comparte el patron (lo usa el selector para neg/clear). */
    case MOp::ADDSD:
    case MOp::SUBSD:
    case MOp::MULSD:
    case MOp::DIVSD:
    case MOp::MINSD:
    case MOp::MAXSD:
    case MOp::MINSS:
    case MOp::MAXSS:
    case MOp::ADDSS:
    case MOp::SUBSS:
    case MOp::MULSS:
    case MOp::DIVSS:
    case MOp::XORPS:
    case MOp::ANDPS:
    /* AVX escalar 3-op no-destructivo: mismas roles (dst def, 2 srcs use) pero
     * el rewrite NO las legaliza a 2-address (son VX nativo -> sin el mov). */
    case MOp::VADDSD:
    case MOp::VSUBSD:
    case MOp::VMULSD:
    case MOp::VDIVSD:
    case MOp::VADDSS:
    case MOp::VSUBSS:
    case MOp::VMULSS:
    case MOp::VDIVSS:
    case MOp::VXORPS:
    case MOp::VANDPS:
        r.dst = R::DEF;
        r.src1 = R::USE;
        r.src2 = R::USE;
        break;
    /* FMA escalar: dst = src1*src2 + dst.  El dst es ACUMULADOR (lee el sumando
     * c y escribe el resultado) -> USEDEF, como XADD.  El vreg copia c->dst
     * antes (MOVSD) y NO legaliza a 2-address (dst != src1). */
    case MOp::VFMADD231SD:
    case MOp::VFMADD231SS:
        r.dst = R::USEDEF;
        r.src1 = R::USE;
        r.src2 = R::USE;
        break;
    /* Unarios FP (dst def, src1 use): conversiones, sqrt, MOVSD/MOVSS
     * (movimiento de datos, incluido el spill/load FP). */
    case MOp::SQRTSD:
    case MOp::ROUNDSD:
    case MOp::ROUNDSS:
    case MOp::CVTSI2SD:
    case MOp::CVTTSD2SI:
    case MOp::CVTSS2SD:
    case MOp::CVTSD2SS:
    case MOp::MOVQ_GP_XMM:
    case MOp::MOVQ_XMM_GP:
    case MOp::MOVSD:
    case MOp::MOVSS:
    case MOp::SQRTSS:
    case MOp::CVTSI2SS:
    case MOp::CVTTSS2SI:
        r.dst = R::DEF;
        r.src1 = R::USE;
        break;

    /* AOT MOV_SYM / LEA_RIP_SYM / TLS_LE_ADDR: dst = &simbolo (def); src1 es
     * el IMM32(sym_idx), no un vreg.  TLS_LE_ADDR usa dst como base del lea
     * pero lo ESCRIBE primero (mov %fs:0) -> def puro, sin use externo. */
    case MOp::MOV_SYM:
    case MOp::LEA_RIP_SYM:
    case MOp::TLS_LE_ADDR:
    case MOp::TLS_PE_ADDR:
    case MOp::LEA_LABEL: r.dst = R::DEF; break;

    /* CALL indirecta (CALLIND / dispatch por puntero): src1 es el vreg con
     * la DIRECCION de la funcion -- un USE que debe seguir vivo hasta el
     * call (si no, el regalloc reusa su registro para un argumento y el
     * call salta a basura).  El role solo aplica si src1.is_vreg(); el
     * CALL_SYM directo lleva un IMM (sym_idx), no un vreg -> no le afecta. */
    case MOp::CALL: r.src1 = R::USE; break;

    /* Control de flujo / pseudo: sin operandos de registro vreg.
     * CALL_SYM (AOT) cae aqui: sus args ya se marshalaron via ARG; su
     * src1 es el IMM32(sym_idx). */
    default: break;
    }
    return r;
}

/* ===================================================================== */
/* LiveInterval::add_range  (insert + coalesce)                           */
/* ===================================================================== */

void LiveInterval::add_range(uint32_t from, uint32_t to) {
    if (from >= to) return; // rango vacio: nada que añadir
    /* Caso comun (construccion backward): el nuevo rango toca o precede
     * al primer rango existente.  Coalesce con el front si solapan o son
     * adyacentes; si no, insercion ordenada general. */
    if (ranges.empty()) {
        ranges.push_back(LiveRange{from, to});
        return;
    }
    /* Fast path: extiende el primer rango si [from,to) lo toca por la
     * izquierda (lo mas frecuente en la pasada backward). */
    LiveRange &f = ranges.front();
    if (to >= f.from && from <= f.to) {
        f.from = std::min(f.from, from);
        f.to = std::max(f.to, to);
        return;
    }
    if (to < f.from) {
        ranges.insert(ranges.begin(), LiveRange{from, to});
        return;
    }
    /* Camino general: insertar ordenado por @c from y coalescer. */
    size_t i = 0;
    while (i < ranges.size() && ranges[i].from < from)
        ++i;
    ranges.insert(ranges.begin() + i, LiveRange{from, to});
    /* Coalesce hacia adelante desde i-1. */
    size_t j = (i > 0) ? i - 1 : 0;
    while (j + 1 < ranges.size()) {
        if (ranges[j].to >= ranges[j + 1].from) {
            ranges[j].to = std::max(ranges[j].to, ranges[j + 1].to);
            ranges[j].from = std::min(ranges[j].from, ranges[j + 1].from);
            ranges.erase(ranges.begin() + j + 1);
        } else {
            ++j;
        }
    }
}

/* ===================================================================== */
/* LiveInterval::first_overlap_from                                       */
/* ===================================================================== */

uint32_t LiveInterval::first_overlap_from(const LiveInterval &o,
                                          uint32_t pos) const noexcept {
    /* Dos pasadas sincronizadas sobre rangos ordenados (merge-like). */
    size_t i = 0, j = 0;
    while (i < ranges.size() && j < o.ranges.size()) {
        const LiveRange &a = ranges[i];
        const LiveRange &b = o.ranges[j];
        const uint32_t lo = std::max(std::max(a.from, b.from), pos);
        const uint32_t hi = std::min(a.to, b.to);
        if (lo < hi) return lo; // solapan a partir de lo
        if (a.to <= b.to)
            ++i;
        else
            ++j; // avanzar el que termina antes
    }
    return UINT32_MAX;
}

/* ===================================================================== */
/* build_intervals                                                        */
/* ===================================================================== */

namespace {

/**
 * @brief ¿Se sabe EXACTAMENTE que registros destruye este bloque de inline-asm?
 *
 * Un @c INLINE_ASM_RAW se trataba SIEMPRE como posicion de llamada ("clobbea
 * cualquiera"), y ADEMAS sus clobbers reales se registran aparte en
 * @c asm_clobbers, que alimenta @c forbidden_lanes y dice con PRECISION que
 * lanes destruye.  Eran dos mecanismos midiendo el mismo hecho, y el burdo no
 * anadia nada: solo exigia, encima, una lane PRESERVADA.
 *
 * En el banco vectorial de x86-64 eso es insatisfacible -- NINGUNA xmm es
 * callee-saved en SysV --, asi que un operando vectorial vivo a traves de otro
 * bloque asm se quedaba con 0 lanes admisibles.  Con residencia REGISTER (el
 * uso lo nombra como registro) no hay salida: el bloque se queda sin bytes y
 * una funcion cuyo cuerpo ENTERO es ese asm sale VACIA, devolviendo el residuo
 * del registro de retorno.  Eso rompia `std.memory.x86_64.memset_*_avx2`.
 *
 * Cuando la lista de clobbers esta VACIA no se sabe nada del asm y hay que
 * seguir siendo conservador: entonces si cuenta como posicion de llamada.
 *
 * @return true si el blob tiene lista de clobbers (el mecanismo preciso
 * aplica).
 */
inline bool asm_clobbers_conocidos(const MFunction &mf, const MInstr &in) {
    const uint32_t idx = static_cast<uint32_t>(in.src1.value);
    /* Lo que decide es que la lista sea AUTORITATIVA, no que tenga elementos:
     * una lista vacia con inferencia hecha significa "no destruye nada mas que
     * sus operandos", y es justo el caso de los memset AVX2 (`xmm sem`, `ymm
     * v0` son OPERANDOS declarados, no clobbers).  Confundir "vacia" con "no se
     * sabe" era lo que dejaba el trato conservador puesto. */
    return idx < mf.asm_blobs.size() && mf.asm_blobs[idx].clobbers_conocidos;
}

/**
 * @brief Bitset word-packed minimo (vector<uint64_t>) para liveness.
 *        Operaciones por palabra de 64 bits para cache locality.
 */
struct Bitset {
    std::vector<uint64_t> w;
    explicit Bitset(size_t nbits = 0) { resize(nbits); }
    void resize(size_t nbits) { w.assign((nbits + 63) / 64, 0); }
    void set(uint32_t i) noexcept { w[i >> 6] |= (1ull << (i & 63)); }
    void clear(uint32_t i) noexcept { w[i >> 6] &= ~(1ull << (i & 63)); }
    bool test(uint32_t i) const noexcept {
        return (w[i >> 6] >> (i & 63)) & 1ull;
    }
    /** @brief this |= o.  Devuelve true si cambio algun bit. */
    bool union_with(const Bitset &o) noexcept {
        bool changed = false;
        for (size_t k = 0; k < w.size(); ++k) {
            const uint64_t before = w[k];
            w[k] |= o.w[k];
            changed |= (w[k] != before);
        }
        return changed;
    }
    /** @brief Copia o y resta kill: this = src & ~kill. */
    void assign_sub(const Bitset &src, const Bitset &kill) noexcept {
        for (size_t k = 0; k < w.size(); ++k)
            w[k] = src.w[k] & ~kill.w[k];
    }
    void union_inplace(const Bitset &o) noexcept {
        for (size_t k = 0; k < w.size(); ++k)
            w[k] |= o.w[k];
    }
    bool equals(const Bitset &o) const noexcept { return w == o.w; }
    void copy_from(const Bitset &o) noexcept { w = o.w; }
};

} // namespace

IntervalResult build_intervals(const MFunction &mf, const TargetRegInfo &tri) {
    (void)tri; // commit 2: el target se usara para constraints en commit 4
    IntervalResult out;
    const uint32_t NV = mf.vreg_count;
    const size_t NB = mf.blocks.size();

    out.intervals.resize(NV);
    for (uint32_t v = 0; v < NV; ++v) {
        out.intervals[v].vreg = v;
        out.intervals[v].cls =
            (v < mf.vreg_class.size()) ? mf.vreg_class[v] : RegClass::GP;
        /*  D.7 commit 6: propagar la categoria GC (kind+1). */
        out.intervals[v].gc_kind =
            (v < mf.vreg_is_gc.size()) ? mf.vreg_is_gc[v] : 0;
        /*  AS inc.5: propagar el precoloreo (register-bound de un
         * inline-asm).  -1 si el vreg no esta pineado. */
        out.intervals[v].fixed_reg = mf.fixed_of(v);
        /* propagar el nivel intermedio register-required (el RA elige
         * el fisico pero no lo derrama).  Solo relevante si NO esta pineado. */
        out.intervals[v].reg_required = mf.reg_required_of(v);
    }
    if (NV == 0 || NB == 0) return out;

    /* ---- 1) Posiciones lineales por instruccion (use=par, def=impar) ----
     * @c first_gi[b] = indice global de la primera instr del bloque b.
     * @c block_start/@c block_end en espacio de posiciones (2 por instr). */
    std::vector<uint32_t> first_gi(NB, 0);
    std::vector<uint32_t> block_start(NB, 0), block_end(NB, 0);
    {
        uint32_t gi = 0;
        for (size_t b = 0; b < NB; ++b) {
            first_gi[b] = gi;
            block_start[b] = 2u * gi;
            gi += static_cast<uint32_t>(mf.blocks[b].instrs.size());
            block_end[b] = 2u * gi;
        }
        out.max_pos = 2u * gi;
        out.block_starts =
            block_start; // Fact de estructura (tramos rectilineos).
    }

    /* Helper: invoca @p fn(vreg_id, role) por cada operando VREG de la
     * instr, segun los roles del opcode. */
    auto each_vreg = [&mf](const MInstr &in, auto &&fn) {
        /*  AS inc.5: INLINE_ASM_RAW no usa los slots dst/src1/src2 para
         * vregs (src1 es el IMM32 del indice del blob).  Sus inputs/outputs
         * register-bound viven en el AsmBlob: in_vregs son USE, out_vregs
         * son DEF en esta posicion (asi sus intervalos cubren el asm y el
         * regalloc respeta el pin sin reusar sus registros fisicos). */
        if (in.op == MOp::INLINE_ASM_RAW) {
            const uint32_t idx = static_cast<uint32_t>(in.src1.value);
            if (idx < mf.asm_blobs.size()) {
                const AsmBlob &b = mf.asm_blobs[idx];
                for (uint32_t v : b.in_vregs)
                    fn(v, OperandRole::USE);
                for (uint32_t v : b.out_vregs)
                    fn(v, OperandRole::DEF);
            }
            return;
        }
        const InstrRoles roles = operand_roles(in.op);
        if (in.dst.is_vreg() && roles.dst != OperandRole::NONE)
            fn(in.dst.vreg_id(), roles.dst);
        if (in.src1.is_vreg() && roles.src1 != OperandRole::NONE)
            fn(in.src1.vreg_id(), roles.src1);
        if (in.src2.is_vreg() && roles.src2 != OperandRole::NONE)
            fn(in.src2.vreg_id(), roles.src2);
    };

    /* ---- 2) gen/kill por bloque ---- */
    std::vector<Bitset> gen(NB, Bitset(NV)), kill(NB, Bitset(NV));
    for (size_t b = 0; b < NB; ++b) {
        const auto &blk = mf.blocks[b];
        for (const MInstr &in : blk.instrs) {
            if (in.op == MOp::CALL || in.op == MOp::CALL_ABS) {
                /* posiciones de call: relleno mas abajo (necesito gi). */
            }
            /* USOS antes que DEFS: un uso es upward-exposed (gen) si NO lo mato
             * una instruccion PREVIA del bloque -- NUNCA el def de la MISMA
             * instruccion (semanticamente el op lee sus srcs y LUEGO escribe el
             * dst).  each_vreg entrega el dst (DEF) antes que los src (USE),
             * asi que un solo pase pondria kill[v] antes de chequear el gen del
             * uso
             * -> para `op v, v, ..` (dst==src1, tipico TRAS ssa_coalesce que
             * coalescio el phi loop-carried con su `v+1`) el gen del uso se
             * suprimiria y el vreg perderia su liveness backward (rango
             * fragmentado -> otro valor reusa su reg -> corrupcion).  DOS
             * pases: primero todos los USOS (contra el kill de instrs previas),
             * luego todos los DEFS. */
            each_vreg(in, [&](uint32_t v, OperandRole role) {
                if ((role == OperandRole::USE || role == OperandRole::USEDEF) &&
                    !kill[b].test(v))
                    gen[b].set(v);
            });
            each_vreg(in, [&](uint32_t v, OperandRole role) {
                if (role == OperandRole::DEF || role == OperandRole::USEDEF)
                    kill[b].set(v);
            });
        }
    }

    /* Posiciones de CALL (para clobbers del allocator, commit 4). */
    for (size_t b = 0; b < NB; ++b) {
        uint32_t gi = first_gi[b];
        /* ABI custom en un CALL/CALLIND: los pseudo-ARG con destino FIJO
         * (register() del cfn callee, p.ej. ebx=arg1 de un syscall) colocan su
         * operando en un registro fisico concreto.  El caller los sobreescribe
         * con el parallel-move ANTES del call -> esos regs son clobbers para
         * los vregs vivos A TRAVES del call.  crosses_call solo cubre los
         * caller-saved; un arg-dst CALLEE-SAVED (ebx/esi/edi en x86-32) NO lo
         * cubre -> un valor vivo (p.ej. la direccion de un buffer reusado en
         * dos syscalls) se colocaba en ebx y el mov ebx,arg1 lo destruia.  Se
         * acumulan los arg-dst hasta el CALL y se registran como clobbers de
         * esa posicion (mismo mecanismo que asm_clobbers -> forbidden_lanes).
         */
        std::vector<uint8_t> pending_arg_regs;
        for (const MInstr &in : mf.blocks[b].instrs) {
            if (in.op == MOp::ARG && in.dst.is_reg())
                pending_arg_regs.push_back(in.dst.reg);
            if (in.op == MOp::INLINE_ASM_RAW &&
                util::flag_on(util::FlagId::RbankAsmDebug)) {
                const uint32_t bi = static_cast<uint32_t>(in.src1.value);
                std::fprintf(stderr,
                             "[rbank]   asm en pos %u: blob %u, "
                             "clobbers_conocidos=%d, n_clobbers=%zu\n",
                             2u * gi, bi,
                             bi < mf.asm_blobs.size()
                                 ? (int)mf.asm_blobs[bi].clobbers_conocidos
                                 : -1,
                             bi < mf.asm_blobs.size()
                                 ? mf.asm_blobs[bi].clobbers.size()
                                 : 0);
            }
            /* DIVMOD_V clobbea RAX/RDX (idiv) -> tratarlo como call-position
             * para que los vregs vivos a traves vayan a callee-saved.
             * LOAD_VM/STORE_VM: su page-miss hace CALL a vrt_vm_read/write
             * -> clobbea caller-saved -> tambien call-position. */
            if (in.op == MOp::CALL || in.op == MOp::CALL_ABS ||
                in.op == MOp::CALL_SYM /* AOT: clobbea caller-saved */
                || in.op == MOp::DIVMOD_V || in.op == MOp::LOAD_VM ||
                in.op == MOp::STORE_VM
                /* Atomicas: el rewrite usa RAX + scratch fijo -> call-position
                 * para que los vregs vivos vayan a callee-saved. */
                || in.op == MOp::ATOMICCAS_V ||
                in.op == MOp::ATOMICADD_V
                /*  AS inc.5: el inline-asm clobbea caller-saved (en v1
                 * conservador: cualquiera) -> los vregs vivos a traves van a
                 * callee-saved/spill.  Los binding precoloreados son EXENTOS:
                 * el linear_scan les asigna su fixed_reg incondicionalmente. */
                || (in.op == MOp::INLINE_ASM_RAW &&
                    !asm_clobbers_conocidos(mf, in))) {
                out.call_positions.push_back(2u * gi);
                if (util::flag_on(util::FlagId::RbankAsmDebug)) {
                    /* QUE op impone cada posicion: sin esto, "cruza-llamada=1"
                     * no dice si es una llamada de verdad o una pseudo-op que
                     * clobbea (divmod / memoria VM / atomica / asm). */
                    std::fprintf(stderr,
                                 "[rbank]   pos %u impuesta por op %d\n",
                                 2u * gi, static_cast<int>(in.op));
                }
                /* Los arg-dst custom de este CALL son clobbers de su posicion
                 * (incluye callee-saved que crosses_call no protege). */
                if (!pending_arg_regs.empty()) {
                    out.asm_clobbers.push_back({2u * gi, pending_arg_regs});
                    pending_arg_regs.clear();
                }
            }
            /*  AS inc.5e: registrar los clobbers EXPLICITOS del asm
             * (callee-saved que el call-position no cubre) por posicion. */
            if (in.op == MOp::INLINE_ASM_RAW) {
                const uint32_t idx = static_cast<uint32_t>(in.src1.value);
                if (idx < mf.asm_blobs.size() &&
                    !mf.asm_blobs[idx].clobbers.empty()) {
                    out.asm_clobbers.push_back(
                        {2u * gi, mf.asm_blobs[idx].clobbers});
                }
            }
            ++gi;
        }
    }

    /* ---- 3) Liveness por dataflow iterativo a punto fijo ----
     * live_out[b] = U live_in[succ];  live_in[b] = gen[b] U (live_out − kill).
     * Iterar en orden REVERSO de layout converge rapido para CFGs
     * reducibles (lo normal en codigo Vesta). */
    std::vector<Bitset> live_in(NB, Bitset(NV)), live_out(NB, Bitset(NV));
    bool changed = true;
    /* Scratch reusado entre iteraciones (cero alocaciones en el loop). */
    Bitset tmp_out(NV), new_in(NV);
    while (changed) {
        changed = false;
        for (size_t bi = NB; bi-- > 0;) {
            const auto &blk = mf.blocks[bi];
            /* new_out = union de live_in de sucesores. */
            std::fill(tmp_out.w.begin(), tmp_out.w.end(), 0ull);
            if (blk.succ_a != MBLOCK_INVALID)
                tmp_out.union_inplace(live_in[blk.succ_a]);
            if (blk.succ_b != MBLOCK_INVALID && blk.succ_b != blk.succ_a)
                tmp_out.union_inplace(live_in[blk.succ_b]);
            /* Sucesores extra / abnormales (handlers de excepcion, futuros
             * targets de jumptable): unirlos mantiene vivos los valores
             * live-in al sucesor a traves del edge anormal (el catch usa
             * valores definidos antes del try; sin esta union el regalloc los
             * consideraria muertos y el throw los perderia). */
            for (const MBlockId es : blk.extra_succs)
                if (es != MBLOCK_INVALID && es != blk.succ_a &&
                    es != blk.succ_b)
                    tmp_out.union_inplace(live_in[es]);
            if (!tmp_out.equals(live_out[bi])) {
                live_out[bi].copy_from(tmp_out);
                changed = true;
            }
            /* new_in = gen U (out & ~kill). */
            new_in.assign_sub(live_out[bi], kill[bi]);
            new_in.union_inplace(gen[bi]);
            if (!new_in.equals(live_in[bi])) {
                live_in[bi].copy_from(new_in);
                changed = true;
            }
        }
    }

    /* ---- 3b) force_spill: vregs live-in a un sucesor EXTRA/abnormal ----
     * Deben ser memory-resident para sobrevivir al edge anormal (el throw
     * llega al handler por runtime, no por un branch; clobberea regs pero no
     * la memoria; el catch recarga del slot).  Solo recorre extra_succs (vacio
     * en el caso comun -> coste cero). */
    {
        bool any_extra = false;
        for (size_t b = 0; b < NB; ++b)
            if (!mf.blocks[b].extra_succs.empty()) {
                any_extra = true;
                break;
            }
        if (any_extra) {
            out.force_spill.assign(NV, 0u);
            for (size_t b = 0; b < NB; ++b) {
                for (const MBlockId es : mf.blocks[b].extra_succs) {
                    if (es == MBLOCK_INVALID || es >= NB) continue;
                    for (uint32_t v = 0; v < NV; ++v)
                        if (live_in[es].test(v)) out.force_spill[v] = 1u;
                }
            }
        }
    }

    /* ---- 3c) coalesce_hint: para ops 2-address (dst = src1 OP src2) ----
     * Registrar hint[dst] = src1 para que el linear_scan prefiera el fisico de
     * src1 al asignar dst (si libre = src1 murio -> coalescing seguro), de modo
     * que el legalizado elida el `mov dst, src1`.  Cubre ALU (ADD/SUB/AND/OR/
     * XOR/IMUL) y shifts/rotates (mov dst,src1 + sh dst,imm). */
    {
        out.coalesce_hint.assign(NV, -1);
        auto is_two_addr = [](MOp op) -> bool {
            switch (op) {
            case MOp::ADD:
            case MOp::SUB:
            case MOp::AND:
            case MOp::OR:
            case MOp::XOR:
            case MOp::IMUL:
            case MOp::SHL:
            case MOp::SHR:
            case MOp::SAR:
            case MOp::ROL:
            case MOp::ROR: return true;
            default: return false;
            }
        };
        for (size_t b = 0; b < NB; ++b) {
            for (const MInstr &mi : mf.blocks[b].instrs) {
                if (!mi.dst.is_vreg() || !mi.src1.is_vreg()) continue;
                /* Copia pura reg->reg (`mov d, s`, incluidas las copias de PHI
                 * ya materializadas): tambien es candidata a coalescing.  El
                 * hint es SOUND por construccion -- el linear_scan solo reusa
                 * el reg de `s` si `s` muere EXACTO en el def de `d`
                 * (partner.end()+1 == dst.start()), asi que nunca fusiona dos
                 * valores que interfieren.  A diferencia de un rewrite FORZADO
                 * de vregs, esto no puede miscompilar. */
                const bool is_copy =
                    (mi.op == MOp::MOV && mi.src2.kind == MOperandKind::NONE);
                if (!is_two_addr(mi.op) && !is_copy) continue;
                const uint32_t d = mi.dst.vreg_id();
                const uint32_t s = mi.src1.vreg_id();
                if (d == s || d >= NV || s >= NV) continue;
                /* No pisar un hint 2-address ya puesto (prioridad al ALU). */
                if (out.coalesce_hint[d] < 0)
                    out.coalesce_hint[d] = static_cast<int32_t>(s);
            }
        }
    }

    /* ---- 4) Construccion de rangos POR BLOQUE via live-in/out ----
     * Para cada bloque y cada vreg, se calcula su rango EN ese bloque a
     * partir de @c live_in/@c live_out (ya computados) + su primera
     * aparicion (def/use) y ultimo uso dentro del bloque.  Esto maneja
     * correctamente el MULTI-DEF que produce la eliminacion de PHI (un
     * vreg PHI se define en cada predecesor): el rango de un valor
     * loop-carried cubre TODO el loop (live-in && live-out -> bloque
     * completo) sin que un def en un bloque corte el rango de otro -- a
     * diferencia del set_from ingenuo, que asumia SSA single-def. */
    std::vector<uint32_t> b_first(NV, UINT32_MAX), b_first_def(NV, UINT32_MAX),
        b_last_use(NV, 0), b_last_def(NV, 0);
    std::vector<uint8_t> b_used(NV, 0), b_def(NV, 0);
    std::vector<uint32_t> touched;
    touched.reserve(64);
    for (size_t b = 0; b < NB; ++b) {
        const auto &blk = mf.blocks[b];
        const uint32_t bstart = block_start[b];
        const uint32_t bend = block_end[b];

        /* Reset de los temporales tocados en el bloque anterior. */
        for (uint32_t v : touched) {
            b_first[v] = UINT32_MAX;
            b_first_def[v] = UINT32_MAX;
            b_last_use[v] = 0;
            b_last_def[v] = 0;
            b_used[v] = 0;
            b_def[v] = 0;
        }
        touched.clear();

        /* Escaneo forward: primera aparicion, primer def, ultimo uso +
         * acumular posiciones de uso (ascendente). */
        const uint32_t base_gi = first_gi[b];
        for (size_t j = 0; j < blk.instrs.size(); ++j) {
            const MInstr &in = blk.instrs[j];
            const uint32_t gi = base_gi + static_cast<uint32_t>(j);
            const uint32_t use_pos = 2u * gi;
            const uint32_t def_pos = 2u * gi + 1u;
            each_vreg(in, [&](uint32_t v, OperandRole role) {
                if (b_first[v] == UINT32_MAX) touched.push_back(v);
                if (role == OperandRole::USE || role == OperandRole::USEDEF) {
                    b_used[v] = 1;
                    b_last_use[v] = use_pos;
                    if (use_pos < b_first[v]) b_first[v] = use_pos;
                    out.intervals[v].uses.push_back(use_pos);
                }
                if (role == OperandRole::DEF || role == OperandRole::USEDEF) {
                    b_def[v] = 1;
                    if (def_pos < b_first_def[v]) b_first_def[v] = def_pos;
                    if (def_pos > b_last_def[v]) b_last_def[v] = def_pos;
                    if (def_pos < b_first[v]) b_first[v] = def_pos;
                }
            });
        }

        /* Construir el rango de cada vreg relevante en este bloque. */
        for (uint32_t v = 0; v < NV; ++v) {
            const bool in = live_in[b].test(v);
            const bool out_ = live_out[b].test(v);
            const bool appears = (b_first[v] != UINT32_MAX);
            if (!in && !out_ && !appears) continue;
            const uint32_t start =
                in ? bstart : (appears ? b_first[v] : bstart);
            /* El intervalo debe cubrir TODO punto donde el valor se toca -- lo
             * lean o lo escriban.  Ultimo uso y ultima definicion son MAXIMOS,
             * no ramas excluyentes: un operando @c USEDEF (xadd, CMOVcc,
             * atomicas) hace las dos cosas en la MISMA instruccion, y la
             * escritura cae DESPUES de la lectura (@c def_pos = use_pos+1).
             *
             * Quedarse con el ultimo uso dejaba fuera esa escritura cuando el
             * resultado moria en el acto.  Un valor que muere no deja de
             * necesitar un SITIO donde escribirse: preguntar por su ubicacion
             * en su propia definicion devolvia "en ningun sitio", y esa
             * respuesta viajaba hasta el codigo emitido.  Solo se veia en el
             * AOT (el unico que construye el timeline con rangos); sobre una
             * base plana el fallo era invisible. */
            uint32_t end;
            if (out_) {
                end = bend; // vivo al salir
            } else if (b_used[v] || b_def[v]) {
                end = bstart;
                if (b_used[v] && b_last_use[v] + 1u > end)
                    end = b_last_use[v] + 1u;
                if (b_def[v] && b_last_def[v] + 1u > end)
                    end = b_last_def[v] + 1u;
            } else {
                end = bend; // live-in raro: conservador
            }
            out.intervals[v].add_range(start, end);
        }
    }
    return out;
}

/*
 * @brief Produce MachineNextUseFacts: por cada vreg, las posiciones de sus USOS
 *        (uso en 2*gi) en la MISMA numeracion que build_intervals.  Replica el
 *        criterio de operandos de build_intervals::each_vreg (roles USE/USEDEF
 * + INLINE_ASM_RAW) pero recolecta SOLO los usos (el def no es uso).  Dos
 *        pasadas -> CSR contiguo.  No mira el IR: solo el MachineIR asignado.
 */
MachineNextUseFacts compute_next_use(const MFunction &mf) {
    MachineNextUseFacts f;
    const uint32_t NV = mf.vreg_count;
    const size_t NB = mf.blocks.size();

    uint32_t total = 0;
    for (size_t b = 0; b < NB; ++b)
        total += static_cast<uint32_t>(mf.blocks[b].instrs.size());
    f.max_pos = 2u * total;

    if (NV == 0) {
        f.off.assign(1, 0);
        return f;
    }

    /* Vregs USADOS de una instr -- mismo criterio que
     * build_intervals::each_vreg, pero solo USE/USEDEF (para next-use el def no
     * cuenta como uso). */
    auto each_use = [&mf](const MInstr &in, auto &&fn) {
        if (in.op == MOp::INLINE_ASM_RAW) {
            const uint32_t idx = static_cast<uint32_t>(in.src1.value);
            if (idx < mf.asm_blobs.size())
                for (uint32_t v : mf.asm_blobs[idx].in_vregs)
                    fn(v);
            return;
        }
        const InstrRoles roles = operand_roles(in.op);
        auto is_use = [](OperandRole r) {
            return r == OperandRole::USE || r == OperandRole::USEDEF;
        };
        if (in.dst.is_vreg() && is_use(roles.dst)) fn(in.dst.vreg_id());
        if (in.src1.is_vreg() && is_use(roles.src1)) fn(in.src1.vreg_id());
        if (in.src2.is_vreg() && is_use(roles.src2)) fn(in.src2.vreg_id());
    };

    /* Pasada 1: contar usos por vreg (para dimensionar el CSR). */
    std::vector<uint32_t> count(NV, 0);
    for (size_t b = 0; b < NB; ++b)
        for (const MInstr &in : mf.blocks[b].instrs)
            each_use(in, [&](uint32_t v) {
                if (v < NV) ++count[v];
            });

    f.off.resize(NV + 1, 0);
    for (uint32_t v = 0; v < NV; ++v)
        f.off[v + 1] = f.off[v] + count[v];
    f.use_pos.resize(f.off[NV]);

    /* Pasada 2: llenar (gi global -> pos de uso 2*gi).  El recorrido lineal es
     * monotono (2*gi creciente) y el MachineIR ya no tiene PHI (resueltos a
     * copies), asi que los usos de cada vreg quedan ORDENADOS sin sort. */
    std::vector<uint32_t> cur(f.off.begin(), f.off.end() - 1);
    uint32_t gi = 0;
    for (size_t b = 0; b < NB; ++b)
        for (const MInstr &in : mf.blocks[b].instrs) {
            const uint32_t pos = 2u * gi;
            each_use(in, [&](uint32_t v) {
                if (v < NV) f.use_pos[cur[v]++] = pos;
            });
            ++gi;
        }
    return f;
}

} // namespace jit
