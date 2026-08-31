/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/x86_encoder.cpp
 * @brief Implementacion del encoder hand-rolled x86-64.
 *
 * Reference primaria: Intel SDM Vol 2 (Instruction Set Reference) y
 * AMD APM Vol 3.  Convenciones de notacion: "REX.W" = bit W del prefix
 * REX (0x48 base); "/r" = ModR/M con reg field; "/N" = ModR/M con
 * subop N en reg field; "rel32" = displacement 32-bit signed.
 */

#include "jit/x86_encoder.h"

#include <cstring>

namespace jit {

namespace {
/* Opcodes de ALU (reg/reg, REX.W + opcode + ModR/M) y subops
 * para variantes reg/imm32 (REX.W + 0x81 /subop + imm32).
 *
 * Indice por enum MOp - MOp::ADD (0..5):
 *   0 = ADD, 1 = SUB, 2 = AND, 3 = OR, 4 = XOR, 5 = CMP
 * Pero usamos la enum MOp tal cual para mantenerlo simple. */

struct AluEnc {
    uint8_t op_rr; ///< opcode reg/reg (direccion 0: dst=r/m, src=reg)
    uint8_t subop; ///< subop para variantes imm32 con opcode 0x81
};

/// Funcion helper que devuelve el AluEnc para un MOp dado.
/// Mantiene el mapping ALU op -> (opcode reg/reg, alu_subop) sin
/// usar designated initializers (no soportados en non-trivial
/// init en gcc/mingw modo C++).
inline AluEnc alu_enc_for(MOp op) noexcept {
    switch (op) {
    case MOp::ADD: return AluEnc{0x01, 0};
    case MOp::OR: return AluEnc{0x09, 1};
    case MOp::AND: return AluEnc{0x21, 4};
    case MOp::SUB: return AluEnc{0x29, 5};
    case MOp::XOR: return AluEnc{0x31, 6};
    case MOp::CMP: return AluEnc{0x39, 7};
    default: return AluEnc{0, 0};
    }
}

/// Opcode de Jcc para una condicion dada (corto: 0x70+cc, largo: 0x0F 0x80+cc).
/// Devuelve byte de la variante larga.
inline uint8_t jcc_long_opcode(MCond cc) {
    return static_cast<uint8_t>(0x80 + static_cast<uint8_t>(cc));
}
} // namespace

/* ===================================================================== */
/* encode (pasada principal + resolve)                                    */
/* ===================================================================== */

size_t X86Encoder::encode(MFunction &fn, std::vector<uint8_t> &out) {
    instr_count_ = 0;
    const size_t base = out.size();
    /* AOT: las MReloc que emitan los MOp CALL_SYM/MOV_SYM se registran con
     * patch_at en offset absoluto de @c out; tras el emit las reubicamos a
     * relativo-a-la-funcion (restando base).  Recordamos cuantas habia ya. */
    const size_t reloc_base = fn.relocs.size();

    /* Reservar capacidad estimada: ~6 bytes promedio por instr. */
    size_t total_instrs = 0;
    for (const auto &b : fn.blocks)
        total_instrs += b.instrs.size();
    out.reserve(out.size() + total_instrs * 6);

    for (auto &block : fn.blocks) {
        block.byte_offset = static_cast<uint32_t>(out.size() - base);
        /* Si el bloque tiene label_id, registrarlo. */
        if (block.label_id != MLABEL_INVALID &&
            block.label_id < fn.label_offsets.size()) {
            fn.label_offsets[block.label_id] =
                static_cast<uint32_t>(out.size() - base);
        }
        for (const auto &mi : block.instrs) {
            ++instr_count_;
            /* Solo-LSP (vista "Godbolt"): registrar el offset del primer
             * byte de esta instr y su source_line ANTES de emitirla.  Solo
             * cuando @c fn.emit_line_map esta activo (inspector del LSP);
             * en produccion el flag es OFF y no se construye la tabla -> los
             * bytes generados son identicos y el coste es 1 rama predicha. */
            const uint32_t pre_rel = static_cast<uint32_t>(out.size() - base);
            if (fn.emit_line_map) {
                fn.line_map.push_back({pre_rel, mi.source_pc, mi.ir_id});
            }
            /* Donde acaba el prologo, en bytes.  Quien lo emitio conto sus
             * instrucciones; cuanto ocupan solo se sabe aqui.  Lo necesita la
             * descripcion del marco que se le da al sistema para poder
             * desenrollar esta funcion (@c MFunction::UnwindDesc). */
            if (fn.prologue_instrs != 0 &&
                instr_count_ == fn.prologue_instrs + 1)
                fn.prologue_bytes = pre_rel;
            if (!emit_instr(fn, mi, out)) {
                /* fail-fast: opcode no soportado.  El INT3 hace que la
                 * ejecucion crasheee con SIGTRAP en lugar de seguir
                 * con basura. */
                put8(out, 0xCC);
                return 0;
            }
            /* Solo-LSP: para un bloque inline-asm, refinar el line_map con una
             * entrada POR INSTRUCCION del asm (su linea real) y reubicar sus
             * etiquetas internas a offset absoluto de la funcion. */
            if (fn.emit_line_map && mi.op == MOp::INLINE_ASM_RAW &&
                mi.src1.kind == MOperandKind::IMM32) {
                const uint32_t idx = static_cast<uint32_t>(mi.src1.value);
                if (idx < fn.asm_blobs.size()) {
                    const AsmBlob &bl = fn.asm_blobs[idx];
                    for (const auto &il : bl.insn_lines)
                        fn.line_map.push_back(
                            {pre_rel + il.first, il.second, mi.ir_id});
                    for (const auto &lb : bl.labels)
                        fn.asm_labels.push_back(
                            {pre_rel + lb.first, lb.second});
                }
            }
        }
    }

    resolve_fixups(fn, out, base);

    /* AOT: reubicar las MReloc emitidas en esta pasada a offset relativo
     * al inicio de la funcion (el driver les sumara la base de la funcion
     * en .text al hacer el layout). */
    for (size_t i = reloc_base; i < fn.relocs.size(); ++i)
        fn.relocs[i].patch_at -= static_cast<uint32_t>(base);

    return out.size() - base;
}

/* ===================================================================== */
/* Dispatcher                                                             */
/* ===================================================================== */

bool X86Encoder::emit_instr(MFunction &fn, const MInstr &mi,
                            std::vector<uint8_t> &out) {
    switch (mi.op) {
    case MOp::NOP: put8(out, 0x90); return true;
    case MOp::INT3: put8(out, 0xCC); return true;
    case MOp::RET: emit_ret(out); return true;
    case MOp::MOV: emit_mov(fn, mi, out); return true;
    case MOp::LEA: emit_lea(fn, mi, out); return true;
    case MOp::PUSH: emit_push(mi, out); return true;
    case MOp::POP: emit_pop(mi, out); return true;
    case MOp::ADD:
    case MOp::SUB:
    case MOp::AND:
    case MOp::OR:
    case MOp::XOR: {
        const AluEnc enc = alu_enc_for(mi.op);
        emit_alu(fn, mi, out, enc.op_rr, enc.subop);
        return true;
    }
    case MOp::CMP: emit_cmp(fn, mi, out); return true;
    case MOp::TEST: emit_test(fn, mi, out); return true;
    case MOp::IMUL: emit_imul(fn, mi, out); return true;
    case MOp::SHL: emit_shift(fn, mi, out, 4); return true;
    case MOp::SHR: emit_shift(fn, mi, out, 5); return true;
    case MOp::SAR: emit_shift(fn, mi, out, 7); return true;
    /* Math-IR-promote v2.2a: bit ops nativos.
     * ROL/ROR reusan emit_shift con subop 0/1; POPCNT/LZCNT/TZCNT
     * comparten encoding F3 0F <op> /r; BSWAP es 0F C8+rd. */
    case MOp::ROL: emit_shift(fn, mi, out, 0); return true;
    case MOp::ROR: emit_shift(fn, mi, out, 1); return true;
    case MOp::POPCNT:
    case MOp::LZCNT:
    case MOp::TZCNT: {
        /* F3 + REX.W + 0F + <op_byte> + ModR/M(11 dst src).
         * Todas reg-reg 64-bit; cae a INT3 si operandos invalidos. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        put8(out, 0xF3); /* prefix obligatorio */
        const uint8_t rex = rex_byte(true, static_cast<uint8_t>(mi.dst.reg),
                                     static_cast<uint8_t>(mi.src1.reg));
        if (rex) put8(out, rex);
        put8(out, 0x0F); /* escape */
        const uint8_t opcode = (mi.op == MOp::POPCNT)  ? 0xB8
                               : (mi.op == MOp::LZCNT) ? 0xBD
                                                       : 0xBC; /* TZCNT */
        put8(out, opcode);
        put8(out, modrm(3, mi.dst.reg & 7, mi.src1.reg & 7));
        return true;
    }
    case MOp::BSWAP: {
        /* BSWAP r64: REX.W + 0F C8+rd. */
        if (mi.dst.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t rex = rex_byte(true, 0, static_cast<uint8_t>(mi.dst.reg));
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, static_cast<uint8_t>(0xC8 + (mi.dst.reg & 7)));
        return true;
    }

    /* Math-IR-promote v2.2b: FP ops nativas con XMM.
     *
     * Convencion: dst.reg y src1.reg son indices MReg.  Los XMM
     * regs estan en 32..47 (XMM0..XMM15) y el encoding x86 usa
     * los low 3 bits + REX.R/B para el bit 3.  Para distinguir
     * GP de XMM en MOVQ, el encoder usa el reg id (32+ = XMM).
     *
     * Helper local: extraer el indice fisico (0..15) del MReg y
     * el bit alto para REX. */
    case MOp::MOVQ_GP_XMM: {
        /* MOVQ xmm, r64: 66 + REX.W + 0F 6E /r
         * dst es XMM, src1 es GP.  ModR/M: mod=11, reg=xmm&7, rm=gp&7. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xmm = static_cast<uint8_t>(mi.dst.reg) - 16; /* XMM0=16 */
        const uint8_t gp = static_cast<uint8_t>(mi.src1.reg);
        if (vx_scalar_) {
            /* VMOVQ xmm, r64: VX.128.66.0F.W1 6E, vvvv=1111. */
            emit_vx3(xmm, gp, VX_NO_VVVV, /*w=*/1, /*l256=*/false, 0, false,
                     out, /*map=*/1, /*pp=*/1);
            put8(out, 0x6E);
            put8(out, modrm(3, xmm & 7, gp & 7));
            return true;
        }
        put8(out, 0x66);
        /* REX.W=1, REX.R=xmm>=8, REX.B=gp>=8.  rex_byte(W, R_reg, B_reg). */
        const uint8_t rex = rex_byte(true, xmm, gp);
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, 0x6E);
        put8(out, modrm(3, xmm & 7, gp & 7));
        return true;
    }
    case MOp::MOVQ_XMM_GP: {
        /* MOVQ r64, xmm: 66 + REX.W + 0F 7E /r
         * dst es GP, src1 es XMM.  ModR/M: mod=11, reg=xmm&7, rm=gp&7. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t gp = static_cast<uint8_t>(mi.dst.reg);
        const uint8_t xmm = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (vx_scalar_) {
            /* VMOVQ r64, xmm: VX.128.66.0F.W1 7E, vvvv=1111. */
            emit_vx3(xmm, gp, VX_NO_VVVV, /*w=*/1, /*l256=*/false, 0, false,
                     out, /*map=*/1, /*pp=*/1);
            put8(out, 0x7E);
            put8(out, modrm(3, xmm & 7, gp & 7));
            return true;
        }
        put8(out, 0x66);
        const uint8_t rex = rex_byte(true, xmm, gp);
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, 0x7E);
        put8(out, modrm(3, xmm & 7, gp & 7));
        return true;
    }
    case MOp::SQRTSD:
    case MOp::MINSD:
    case MOp::MAXSD:
    case MOp::MINSS:
    case MOp::MAXSS: {
        /* SQRTSD/MINSD/MAXSD (F2, f64) + MINSS/MAXSS (F3, f32) xmm_dst,
         * xmm_src: pref + (REX si hay xmm>=8) + 0F + <op> + ModR/M(11, dst&7,
         * src&7). MIN opcode = 0x5D, MAX = 0x5F, SQRTSD = 0x51.  El prefijo
         * distingue f64 (F2) de f32 (F3). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const bool is_ss = (mi.op == MOp::MINSS || mi.op == MOp::MAXSS);
        const uint8_t opcode = (mi.op == MOp::SQRTSD) ? 0x51
                               : (mi.op == MOp::MINSD || mi.op == MOp::MINSS)
                                   ? 0x5D
                                   : 0x5F;
        const uint8_t pp = is_ss ? 2u : 3u; // VX pp: F3=2, F2=3
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* V{MIN,MAX}S{S,D}/VSQRTSD xmm, xmm(vvvv=dst), xmm: VX.LIG.<pp>.0F.
             */
            emit_vx3(xd, xs, xd, /*w=*/0, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/pp);
            put8(out, opcode);
            put8(out, modrm(3, xd & 7, xs & 7));
            return true;
        }
        put8(out, is_ss ? 0xF3 : 0xF2);
        /* REX solo si alguno >= 8.  REX.W no necesario para SSE. */
        const uint8_t rex_R = (xd >= 8) ? 1 : 0;
        const uint8_t rex_B = (xs >= 8) ? 1 : 0;
        if (rex_R || rex_B) {
            put8(out, 0x40 | (rex_R << 2) | rex_B);
        }
        put8(out, 0x0F);
        put8(out, opcode);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }
    case MOp::ROUNDSD:
    case MOp::ROUNDSS: {
        /* ROUNDSD (f64) / ROUNDSS (f32) xmm_dst, xmm_src, imm8:
         *   66 + (REX) + 0F 3A <0B|0A> + ModR/M + imm8(mode)
         *   variant tiene el rounding mode (0=nearest, 1=floor, 2=ceil,
         * 3=trunc). SSE4.1 required (todo x86-64 moderno lo tiene).
         * ROUNDSD = 0x0B, ROUNDSS = 0x0A. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t mode = static_cast<uint8_t>(mi.variant) & 0x3;
        put8(out, 0x66);
        const uint8_t rex_R = (xd >= 8) ? 1 : 0;
        const uint8_t rex_B = (xs >= 8) ? 1 : 0;
        if (rex_R || rex_B) {
            put8(out, 0x40 | (rex_R << 2) | rex_B);
        }
        put8(out, 0x0F);
        put8(out, 0x3A);
        put8(out, mi.op == MOp::ROUNDSS ? 0x0A : 0x0B);
        put8(out, modrm(3, xd & 7, xs & 7));
        put8(out, mode);
        return true;
    }
    case MOp::ADDSD:
    case MOp::SUBSD:
    case MOp::MULSD:
    case MOp::DIVSD: {
        /* ADDSD/SUBSD/MULSD/DIVSD xmm_dst, xmm_src:
         *   F2 + (REX) + 0F + <op_byte> + ModR/M.
         *   ADDSD=0x58, SUBSD=0x5C, MULSD=0x59, DIVSD=0x5E.  */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        put8(out, 0xF2);
        const uint8_t rex_R = (xd >= 8) ? 1 : 0;
        const uint8_t rex_B = (xs >= 8) ? 1 : 0;
        if (rex_R || rex_B) {
            put8(out, 0x40 | (rex_R << 2) | rex_B);
        }
        put8(out, 0x0F);
        const uint8_t opcode = (mi.op == MOp::ADDSD)   ? 0x58
                               : (mi.op == MOp::SUBSD) ? 0x5C
                               : (mi.op == MOp::MULSD) ? 0x59
                                                       : 0x5E; /* DIVSD */
        put8(out, opcode);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }
    case MOp::VADDSD:
    case MOp::VSUBSD:
    case MOp::VMULSD:
    case MOp::VDIVSD:
    case MOp::VADDSS:
    case MOp::VSUBSS:
    case MOp::VMULSS:
    case MOp::VDIVSS: {
        /* AVX escalar 3-operandos: VX.LIG.{F2|F3}.0F <op> dst, src1(vvvv),
         * src2(rm reg|mem).  dst = src1 OP src2 (no-destructivo).  pp: F2=3
         * (double), F3=2 (single).  opcode = 58/5C/59/5E como las legacy. */
        const bool ss = (mi.op == MOp::VADDSS || mi.op == MOp::VSUBSS ||
                         mi.op == MOp::VMULSS || mi.op == MOp::VDIVSS);
        const uint8_t pp = ss ? 2u : 3u; // F3 / F2
        const uint8_t opcode =
            (mi.op == MOp::VADDSD || mi.op == MOp::VADDSS)   ? 0x58
            : (mi.op == MOp::VSUBSD || mi.op == MOp::VSUBSS) ? 0x5C
            : (mi.op == MOp::VMULSD || mi.op == MOp::VMULSS) ? 0x59
                                                             : 0x5E; /* DIV */
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xv = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (mi.src2.kind == MOperandKind::REG) {
            const uint8_t xs = static_cast<uint8_t>(mi.src2.reg) - 16;
            emit_vx3(xd, xs, xv, /*w=*/0, /*l256=*/false, 0, false, out,
                     /*map=*/1, pp);
            put8(out, opcode);
            put8(out, modrm(3, xd & 7, xs & 7));
        } else if (mi.src2.kind == MOperandKind::MEM) {
            const MReg base = mi.src2.mem_base();
            const MReg idx = mi.src2.mem_index();
            const bool has_index = (idx != MReg::NONE);
            const uint8_t bid = reg_id(base);
            const uint8_t iid = has_index ? reg_id(idx) : 0;
            emit_vx3(xd, bid, xv, /*w=*/0, /*l256=*/false, iid, has_index, out,
                     /*map=*/1, pp);
            put8(out, opcode);
            emit_modrm_mem(mi.src2, xd & 7, out);
        } else {
            put8(out, 0xCC);
        }
        return true;
    }
    case MOp::ADDPD:
    case MOp::SUBPD:
    case MOp::MULPD:
    case MOp::DIVPD:
    case MOp::PADDD:
    case MOp::PSUBD:
    case MOp::PADDQ:
    case MOp::PSUBQ:
    case MOp::PADDW:
    case MOp::PSUBW:
    case MOp::PMULLW:
    case MOp::PADDB:
    case MOp::PSUBB:
    case MOp::SQRTPD:
    case MOp::XORPD:
    case MOp::ANDPD:
    case MOp::UNPCKLPD:
    case MOp::ADDPS:
    case MOp::SUBPS:
    case MOp::MULPS:
    case MOp::DIVPS: {
        /* Packed SSE2: 66? + (REX) + 0F + <op> + ModR/M.  Los packed-DOUBLE
         * (PD) y enteros llevan prefijo 66; los packed-SINGLE (PS) NO (pp=00).
         * Opcodes float 58/5C/59/5E (add/sub/mul/div) compartidos PD/PS;
         * enteros FE/FA/D4/FB; unarios/logicos 51/57/54; UNPCKLPD=14.  Reg-reg
         * only; los loads/stores van por MOVUPD (mover bytes crudos vale). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t opcode =
            (mi.op == MOp::ADDPD || mi.op == MOp::ADDPS)   ? 0x58
            : (mi.op == MOp::SUBPD || mi.op == MOp::SUBPS) ? 0x5C
            : (mi.op == MOp::MULPD || mi.op == MOp::MULPS) ? 0x59
            : (mi.op == MOp::DIVPD || mi.op == MOp::DIVPS) ? 0x5E
            : (mi.op == MOp::PADDD)                        ? 0xFE
            : (mi.op == MOp::PSUBD)                        ? 0xFA
            : (mi.op == MOp::PADDQ)                        ? 0xD4
            : (mi.op == MOp::PSUBQ)                        ? 0xFB
            : (mi.op == MOp::PADDW)                        ? 0xFD
            : (mi.op == MOp::PSUBW)                        ? 0xF9
            : (mi.op == MOp::PMULLW)                       ? 0xD5
            : (mi.op == MOp::PADDB)                        ? 0xFC
            : (mi.op == MOp::PSUBB)                        ? 0xF8
            : (mi.op == MOp::SQRTPD)                       ? 0x51
            : (mi.op == MOp::XORPD)                        ? 0x57
            : (mi.op == MOp::ANDPD)                        ? 0x54
                                    : 0x14; /* UNPCKLPD */
        /* packed-single (PS): pp=00 (sin 66), EVEX W0.  packed-double/qword:
         * pp=01 (66), EVEX W1.  PADDD/PSUBD (dword) y word/byte (WIG): pp=01
         * pero W0. */
        const bool is_ps = (mi.op == MOp::ADDPS || mi.op == MOp::SUBPS ||
                            mi.op == MOp::MULPS || mi.op == MOp::DIVPS);
        const bool is_w0 = (is_ps || mi.op == MOp::PADDD ||
                            mi.op == MOp::PSUBD || mi.op == MOp::PADDW ||
                            mi.op == MOp::PSUBW || mi.op == MOp::PMULLW ||
                            mi.op == MOp::PADDB || mi.op == MOp::PSUBB);
        const uint8_t pp = is_ps ? 0 : 1;
        const uint8_t wbit = is_w0 ? 0 : 1;
        /* SQRTPD es UNARIO (dst, src): vvvv no se usa (1111). */
        const bool unary = (mi.op == MOp::SQRTPD);
        const uint8_t vec_w = mi.dst.width ? mi.dst.width : 16;
        if (vec_w >= 64) {
            emit_evex(xd, xs, unary ? VX_NO_VVVV : xd, wbit, /*ll=*/2, 0, false,
                      out, /*map=*/1, pp);
            put8(out, opcode);
            put8(out, modrm(3, xd & 7, xs & 7));
        } else if (vec_w == 32) {
            emit_vx3(xd, xs, unary ? VX_NO_VVVV : xd, /*w=*/0, /*l256=*/true, 0,
                     false, out, /*map=*/1, pp);
            put8(out, opcode);
            put8(out, modrm(3, xd & 7, xs & 7));
        } else {
            /* SSE (128b): [66] [REX] 0F <op> modrm. */
            if (!is_ps) put8(out, 0x66);
            const uint8_t rex_R = (xd >= 8) ? 1 : 0;
            const uint8_t rex_B = (xs >= 8) ? 1 : 0;
            if (rex_R || rex_B) put8(out, 0x40 | (rex_R << 2) | rex_B);
            put8(out, 0x0F);
            put8(out, opcode);
            put8(out, modrm(3, xd & 7, xs & 7));
        }
        return true;
    }
    case MOp::PMULLD: {
        /* PMULLD xmm,xmm: 66 0F38 40 (SSE4.1) -- 4x i32 mul (low 32b).  Mapa
         * 0F38 (no 0F).  AVX2: VX.256.66.0F38.W0 40; AVX512: EVEX.512 W0. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t vec_w = mi.dst.width ? mi.dst.width : 16;
        if (vec_w >= 64) {
            emit_evex(xd, xs, xd, /*w=*/0, /*ll=*/2, 0, false, out, /*map=*/2,
                      /*pp=*/1);
            put8(out, 0x40);
            put8(out, modrm(3, xd & 7, xs & 7));
        } else if (vec_w == 32) {
            emit_vx3(xd, xs, xd, /*w=*/0, /*l256=*/true, 0, false, out,
                     /*map=*/2, /*pp=*/1);
            put8(out, 0x40);
            put8(out, modrm(3, xd & 7, xs & 7));
        } else {
            put8(out, 0x66);
            const uint8_t rex_R = (xd >= 8) ? 1 : 0;
            const uint8_t rex_B = (xs >= 8) ? 1 : 0;
            if (rex_R || rex_B) put8(out, 0x40 | (rex_R << 2) | rex_B);
            put8(out, 0x0F);
            put8(out, 0x38);
            put8(out, 0x40);
            put8(out, modrm(3, xd & 7, xs & 7));
        }
        return true;
    }
    case MOp::CVTSI2SD: {
        /* CVTSI2SD xmm, r64: F2 + REX.W + 0F + 2A + ModR/M(11, xmm&7, gp&7).
         * Convierte int64 signed a f64. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t gp = static_cast<uint8_t>(mi.src1.reg);
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VCVTSI2SD xmm, xmm(vvvv=dst), r64: VX.LIG.F2.0F.W1 2A.  El vvvv
             * (merge de bits altos) = dst; solo usamos el f64 bajo. */
            emit_vx3(xd, gp, xd, /*w=*/1, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/3);
            put8(out, 0x2A);
            put8(out, modrm(3, xd & 7, gp & 7));
            return true;
        }
        put8(out, 0xF2);
        put_rex(out, true, xd, gp);
        put8(out, 0x0F);
        put8(out, 0x2A);
        put8(out, modrm(3, xd & 7, gp & 7));
        return true;
    }
    case MOp::CVTTSD2SI: {
        /* CVTTSD2SI r64, xmm: F2 + REX.W + 0F + 2C + ModR/M.
         * Convierte f64 a int64 signed con truncacion hacia cero. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t gp = static_cast<uint8_t>(mi.dst.reg);
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VCVTTSD2SI r64, xmm: VX.LIG.F2.0F.W1 2C, vvvv=1111 (sin merge).
             */
            emit_vx3(gp, xs, VX_NO_VVVV, /*w=*/1, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/3);
            put8(out, 0x2C);
            put8(out, modrm(3, gp & 7, xs & 7));
            return true;
        }
        put8(out, 0xF2);
        put_rex(out, true, gp, xs);
        put8(out, 0x0F);
        put8(out, 0x2C);
        put8(out, modrm(3, gp & 7, xs & 7));
        return true;
    }
    case MOp::CVTSS2SD: {
        /* CVTSS2SD xmm, xmm: F3 + (REX) + 0F + 5A + ModR/M.
         * Convierte f32 a f64 (widening). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VCVTSS2SD xmm, xmm(vvvv=dst), xmm: VX.LIG.F3.0F 5A. */
            emit_vx3(xd, xs, xd, /*w=*/0, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/2);
            put8(out, 0x5A);
            put8(out, modrm(3, xd & 7, xs & 7));
            return true;
        }
        put8(out, 0xF3);
        const uint8_t rex_R = (xd >= 8) ? 1 : 0;
        const uint8_t rex_B = (xs >= 8) ? 1 : 0;
        if (rex_R || rex_B) {
            put8(out, 0x40 | (rex_R << 2) | rex_B);
        }
        put8(out, 0x0F);
        put8(out, 0x5A);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }
    case MOp::CVTSD2SS: {
        /* CVTSD2SS xmm, xmm: F2 + (REX) + 0F + 5A + ModR/M.
         * Convierte f64 a f32 (narrowing, truncacion). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VCVTSD2SS xmm, xmm(vvvv=dst), xmm: VX.LIG.F2.0F 5A. */
            emit_vx3(xd, xs, xd, /*w=*/0, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/3);
            put8(out, 0x5A);
            put8(out, modrm(3, xd & 7, xs & 7));
            return true;
        }
        put8(out, 0xF2);
        const uint8_t rex_R = (xd >= 8) ? 1 : 0;
        const uint8_t rex_B = (xs >= 8) ? 1 : 0;
        if (rex_R || rex_B) {
            put8(out, 0x40 | (rex_R << 2) | rex_B);
        }
        put8(out, 0x0F);
        put8(out, 0x5A);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }
    case MOp::UCOMISD: {
        /* UCOMISD xmm_a, xmm_b: 66 + (REX) + 0F + 2E + ModR/M.
         * Compara dos f64; setea ZF/PF/CF para SETCC/JCC. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xa = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xb = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VUCOMISD xmm, xmm: VX.LIG.66.0F 2E, vvvv=1111 (sin merge). */
            emit_vx3(xa, xb, VX_NO_VVVV, /*w=*/0, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/1);
            put8(out, 0x2E);
            put8(out, modrm(3, xa & 7, xb & 7));
            return true;
        }
        put8(out, 0x66);
        const uint8_t rex_R = (xa >= 8) ? 1 : 0;
        const uint8_t rex_B = (xb >= 8) ? 1 : 0;
        if (rex_R || rex_B) {
            put8(out, 0x40 | (rex_R << 2) | rex_B);
        }
        put8(out, 0x0F);
        put8(out, 0x2E);
        put8(out, modrm(3, xa & 7, xb & 7));
        return true;
    }

    /* ---- FP-regalloc ( AOT C1 float): MOVSD/MOVSS con memoria ---- */
    case MOp::MOVSD:
    case MOp::MOVSS: {
        /* MOVSD/MOVSS mueve un escalar f64/f32 entre XMM<->XMM o XMM<->mem.
         *   prefijo: F2 (MOVSD) / F3 (MOVSS).
         *   xmm <- xmm/mem : 0F 10  (reg = dst xmm, r/m = src)
         *   mem <- xmm     : 0F 11  (reg = src xmm, r/m = dst mem)
         * El reg-reg se codifica con 0F 10 (dst=reg field, src=r/m). */
        const uint8_t pfx = (mi.op == MOp::MOVSD) ? 0xF2 : 0xF3;
        const uint8_t pp = (mi.op == MOp::MOVSD) ? 3u : 2u; // VX: F2 / F3
        const bool dst_xmm = (mi.dst.kind == MOperandKind::REG);
        const bool src_xmm = (mi.src1.kind == MOperandKind::REG);
        if (dst_xmm && src_xmm) {
            /* xmm <- xmm : 0F 10, reg=dst, rm=src. */
            const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
            const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
            if (vx_scalar_) {
                /* VMOVSD/VMOVSS xmm, xmm(vvvv=src), xmm: VX.LIG.{F2|F3}.0F 10.
                 * vvvv=src -> copia el low-128 de src (el escalar). */
                emit_vx3(xd, xs, xs, /*w=*/0, /*l256=*/false, 0, false, out,
                         /*map=*/1, pp);
                put8(out, 0x10);
                put8(out, modrm(3, xd & 7, xs & 7));
                return true;
            }
            put8(out, pfx);
            const uint8_t rex = rex_byte(false, xd, xs);
            if (rex) put8(out, rex);
            put8(out, 0x0F);
            put8(out, 0x10);
            put8(out, modrm(3, xd & 7, xs & 7));
            return true;
        }
        if (dst_xmm && mi.src1.kind == MOperandKind::MEM) {
            /* xmm <- [mem] : 0F 10, reg=dst xmm, r/m = mem. */
            const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
            const MReg base = mi.src1.mem_base();
            const MReg idx = mi.src1.mem_index();
            const bool has_index = (idx != MReg::NONE);
            if (vx_scalar_) {
                /* VMOVSD/VMOVSS xmm, m64: VX.LIG.{F2|F3}.0F 10, vvvv=1111. */
                emit_vx3(xd, reg_id(base), VX_NO_VVVV, /*w=*/0, /*l256=*/false,
                         has_index ? reg_id(idx) : 0, has_index, out, /*map=*/1,
                         pp);
                put8(out, 0x10);
                emit_modrm_mem(mi.src1, xd & 7, out);
                return true;
            }
            put8(out, pfx);
            const uint8_t rex =
                rex_byte(false, xd, reg_id(base), has_index ? reg_id(idx) : 0);
            if (rex) put8(out, rex);
            put8(out, 0x0F);
            put8(out, 0x10);
            emit_modrm_mem(mi.src1, xd & 7, out);
            return true;
        }
        if (mi.dst.kind == MOperandKind::MEM && src_xmm) {
            /* [mem] <- xmm : 0F 11, reg=src xmm, r/m = mem. */
            const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
            const MReg base = mi.dst.mem_base();
            const MReg idx = mi.dst.mem_index();
            const bool has_index = (idx != MReg::NONE);
            if (vx_scalar_) {
                /* VMOVSD/VMOVSS m64, xmm: VX.LIG.{F2|F3}.0F 11, vvvv=1111. */
                emit_vx3(xs, reg_id(base), VX_NO_VVVV, /*w=*/0, /*l256=*/false,
                         has_index ? reg_id(idx) : 0, has_index, out, /*map=*/1,
                         pp);
                put8(out, 0x11);
                emit_modrm_mem(mi.dst, xs & 7, out);
                return true;
            }
            put8(out, pfx);
            const uint8_t rex =
                rex_byte(false, xs, reg_id(base), has_index ? reg_id(idx) : 0);
            if (rex) put8(out, rex);
            put8(out, 0x0F);
            put8(out, 0x11);
            emit_modrm_mem(mi.dst, xs & 7, out);
            return true;
        }
        put8(out, 0xCC); /* combinacion no soportada (mem<-mem, imm, ...) */
        return true;
    }

    case MOp::VFMADD231PD:
    case MOp::VFMADD231PS:
    case MOp::VFMSUB231PD:
    case MOp::VFMSUB231PS: {
        /* VFMADD231P{D,S} dst = src1*src2 + dst;  VFMSUB231P{D,S} dst =
         * src1*src2 - dst (1 redondeo).  66 0F38; ADD=B8, SUB=BA; W1 para PD,
         * W0 para PS.  Solo AVX/512 (vec_w 32/64). */
        const bool ps =
            (mi.op == MOp::VFMADD231PS || mi.op == MOp::VFMSUB231PS);
        const bool sub =
            (mi.op == MOp::VFMSUB231PD || mi.op == MOp::VFMSUB231PS);
        const uint8_t opbyte = sub ? 0xBA : 0xB8;
        const uint8_t wbit = ps ? 0 : 1;
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xv = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t vec_w = mi.dst.width ? mi.dst.width : 32;
        const bool evex = (vec_w >= 64);
        const bool l256 = (vec_w == 32); // 16->VX.128, 32->VX.256, 64->EVEX.512
        if (mi.src2.kind == MOperandKind::REG) {
            const uint8_t xs = static_cast<uint8_t>(mi.src2.reg) - 16;
            if (evex)
                emit_evex(xd, xs, xv, wbit, /*ll=*/2, 0, false, out, /*map=*/2,
                          /*pp=*/1);
            else
                emit_vx3(xd, xs, xv, wbit, l256, 0, false, out, /*map=*/2,
                         /*pp=*/1);
            put8(out, opbyte);
            put8(out, modrm(3, xd & 7, xs & 7));
        } else if (mi.src2.kind == MOperandKind::MEM) {
            const MReg base = mi.src2.mem_base();
            const MReg idx = mi.src2.mem_index();
            const bool has_index = (idx != MReg::NONE);
            const uint8_t bid = reg_id(base);
            const uint8_t iid = has_index ? reg_id(idx) : 0;
            if (evex)
                emit_evex(xd, bid, xv, wbit, /*ll=*/2, iid, has_index, out,
                          /*map=*/2, /*pp=*/1);
            else
                emit_vx3(xd, bid, xv, wbit, l256, iid, has_index, out,
                         /*map=*/2, /*pp=*/1);
            put8(out, opbyte);
            emit_modrm_mem(mi.src2, xd & 7, out);
        } else {
            put8(out, 0xCC);
        }
        return true;
    }

    case MOp::VFMADD231SD:
    case MOp::VFMADD231SS: {
        /* FMA ESCALAR: dst = src1*src2 + dst (1 redondeo).  66 0F38 B9; W1=SD,
         * W0=SS.  VEX.LIG -> L=0 (128b, opera sobre la lane baja).  src2 = REG.
         * Requiere FMA3 (el vreg lo comprueba con caps.fma antes de emitirlo).
         */
        const bool ss = (mi.op == MOp::VFMADD231SS);
        const uint8_t wbit = ss ? 0 : 1;
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xv = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (mi.src2.kind == MOperandKind::REG) {
            const uint8_t xs = static_cast<uint8_t>(mi.src2.reg) - 16;
            emit_vx3(xd, xs, xv, wbit, /*l256=*/false, 0, false, out, /*map=*/2,
                     /*pp=*/1);
            put8(out, 0xB9);
            put8(out, modrm(3, xd & 7, xs & 7));
        } else {
            put8(out, 0xCC); // solo REG
        }
        return true;
    }

    case MOp::VBROADCASTSD: {
        /* VBROADCASTSD ymm/zmm, xmm: difunde el f64 bajo a todos los lanes.
         * VX.256.66.0F38.W0 19 /r ; EVEX.512.66.0F38.W1 19 /r.  Op de 2
         * operandos (vvvv no usado).  Solo AVX (no hay forma 128b util aqui).
         */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t vec_w = mi.dst.width ? mi.dst.width : 32;
        if (vec_w >= 64)
            emit_evex(xd, xs, VX_NO_VVVV, /*w=*/1, /*ll=*/2, 0, false, out,
                      /*map=*/2);
        else
            emit_vx3(xd, xs, VX_NO_VVVV, /*w=*/0, /*l256=*/true, 0, false, out,
                     /*map=*/2);
        put8(out, 0x19);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }

    case MOp::SHUFPS: {
        /* SHUFPS dst, src, imm8: NP 0F C6 /r ib.  imm8=0 con dst==src difunde
         * el lane 0 (f32) a los 4 lanes de un XMM (128b, SSE, sin AVX).  El
         * imm8 viaja en mi.variant (como ROUNDSS). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t rex_R = (xd >= 8) ? 1 : 0;
        const uint8_t rex_B = (xs >= 8) ? 1 : 0;
        if (rex_R || rex_B) put8(out, 0x40 | (rex_R << 2) | rex_B);
        put8(out, 0x0F);
        put8(out, 0xC6);
        put8(out, modrm(3, xd & 7, xs & 7));
        put8(out, static_cast<uint8_t>(mi.variant)); // imm8
        return true;
    }

    case MOp::VBROADCASTSS: {
        /* VBROADCASTSS xmm/ymm/zmm, xmm: difunde el f32 bajo a todos los lanes.
         * VX.128/256.66.0F38.W0 18 /r ; EVEX.512.66.0F38.W0 18 /r.  W0 SIEMPRE
         * (f32), a diferencia de VBROADCASTSD (W0 VEX / W1 EVEX).  Op de 2
         * operandos (vvvv no usado).  Valido tambien a 128b (util para f32). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t vec_w = mi.dst.width ? mi.dst.width : 32;
        if (vec_w >= 64)
            emit_evex(xd, xs, VX_NO_VVVV, /*w=*/0, /*ll=*/2, 0, false, out,
                      /*map=*/2);
        else
            emit_vx3(xd, xs, VX_NO_VVVV, /*w=*/0, /*l256=*/(vec_w == 32), 0,
                     false, out, /*map=*/2);
        put8(out, 0x18);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }

    case MOp::MOVUPD:
    case MOp::MOVAPD: {
        /* Move packed 2x f64 (16 bytes) XMM<->XMM o XMM<->mem.  Prefijo 66.
         *   MOVUPD: 0F 10 (load) / 0F 11 (store)  -- unaligned.
         *   MOVAPD: 0F 28 (load) / 0F 29 (store)  -- aligned (#GP si !16B).
         * Misma estructura que MOVSD pero packed-double. */
        const bool apd = (mi.op == MOp::MOVAPD);
        const uint8_t op_load = apd ? 0x28 : 0x10;
        const uint8_t op_store = apd ? 0x29 : 0x11;
        const bool dst_xmm = (mi.dst.kind == MOperandKind::REG);
        const bool src_xmm = (mi.src1.kind == MOperandKind::REG);
        /* ancho del vector: del operando XMM (16=XMM/SSE2, 32=YMM/VX,
         * 64=ZMM/EVEX).  VMOVUPD/VMOVAPD: VX WIG (w=0); EVEX W1. */
        const uint8_t vec_w = dst_xmm ? (mi.dst.width ? mi.dst.width : 16)
                                      : (mi.src1.width ? mi.src1.width : 16);
        /* Emite el prefijo SSE2/VX/EVEX + opcode para un reg XMM @p xreg con
         * rm @p rm_id (reg o base de mem) e indice opcional. */
        auto emit_pfx_op = [&](uint8_t xreg, uint8_t rm_id, uint8_t idx_id,
                               bool has_idx, uint8_t opcode) {
            if (vec_w >= 64) {
                emit_evex(xreg, rm_id, VX_NO_VVVV, /*w=*/1, /*ll=*/2, idx_id,
                          has_idx, out);
                put8(out, opcode);
            } else if (vec_w == 32) {
                emit_vx3(xreg, rm_id, VX_NO_VVVV, /*w=*/0, /*l256=*/true,
                         idx_id, has_idx, out);
                put8(out, opcode);
            } else {
                put8(out, 0x66);
                const uint8_t rex =
                    rex_byte(false, xreg, rm_id, has_idx ? idx_id : 0);
                if (rex) put8(out, rex);
                put8(out, 0x0F);
                put8(out, opcode);
            }
        };
        if (dst_xmm && src_xmm) {
            const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
            const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
            emit_pfx_op(xd, xs, 0, false, op_load);
            put8(out, modrm(3, xd & 7, xs & 7));
            return true;
        }
        if (dst_xmm && mi.src1.kind == MOperandKind::MEM) {
            const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
            const MReg base = mi.src1.mem_base();
            const MReg idx = mi.src1.mem_index();
            const bool has_index = (idx != MReg::NONE);
            emit_pfx_op(xd, reg_id(base), has_index ? reg_id(idx) : 0,
                        has_index, op_load);
            emit_modrm_mem(mi.src1, xd & 7, out);
            return true;
        }
        if (mi.dst.kind == MOperandKind::MEM && src_xmm) {
            const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
            const MReg base = mi.dst.mem_base();
            const MReg idx = mi.dst.mem_index();
            const bool has_index = (idx != MReg::NONE);
            emit_pfx_op(xs, reg_id(base), has_index ? reg_id(idx) : 0,
                        has_index, op_store);
            emit_modrm_mem(mi.dst, xs & 7, out);
            return true;
        }
        put8(out, 0xCC);
        return true;
    }

    case MOp::ADDSS:
    case MOp::SUBSS:
    case MOp::MULSS:
    case MOp::DIVSS:
    case MOp::SQRTSS: {
        /* f32 arith/sqrt: F3 + (REX) + 0F + <op> + ModR/M(11, dst, src).
         *   ADDSS=0x58, SUBSS=0x5C, MULSS=0x59, DIVSS=0x5E, SQRTSS=0x51. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t opcode = (mi.op == MOp::ADDSS)   ? 0x58
                               : (mi.op == MOp::SUBSS) ? 0x5C
                               : (mi.op == MOp::MULSS) ? 0x59
                               : (mi.op == MOp::DIVSS) ? 0x5E
                                                       : 0x51; /* SQRTSS */
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VSQRTSS xmm, xmm(vvvv=dst), xmm: VX.LIG.F3.0F op. */
            emit_vx3(xd, xs, xd, /*w=*/0, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/2);
            put8(out, opcode);
            put8(out, modrm(3, xd & 7, xs & 7));
            return true;
        }
        put8(out, 0xF3);
        const uint8_t rex = rex_byte(false, xd, xs);
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, opcode);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }
    case MOp::UCOMISS: {
        /* UCOMISS xmm_a, xmm_b: (REX) + 0F + 2E + ModR/M.  SIN prefijo
         * 66 (esa es UCOMISD); compara dos f32 y setea ZF/PF/CF. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xa = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xb = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VUCOMISS xmm, xmm: VX.LIG.NP.0F 2E, vvvv=1111, pp=0 (sin
             * prefijo). */
            emit_vx3(xa, xb, VX_NO_VVVV, /*w=*/0, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/0);
            put8(out, 0x2E);
            put8(out, modrm(3, xa & 7, xb & 7));
            return true;
        }
        const uint8_t rex = rex_byte(false, xa, xb);
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, 0x2E);
        put8(out, modrm(3, xa & 7, xb & 7));
        return true;
    }
    case MOp::CVTSI2SS: {
        /* CVTSI2SS xmm, r64: F3 + REX.W + 0F + 2A + ModR/M(11, xmm, gp). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t gp = static_cast<uint8_t>(mi.src1.reg);
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VCVTSI2SS xmm, xmm(vvvv=dst), r64: VX.LIG.F3.0F.W1 2A. */
            emit_vx3(xd, gp, xd, /*w=*/1, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/2);
            put8(out, 0x2A);
            put8(out, modrm(3, xd & 7, gp & 7));
            return true;
        }
        put8(out, 0xF3);
        put_rex(out, true, xd, gp);
        put8(out, 0x0F);
        put8(out, 0x2A);
        put8(out, modrm(3, xd & 7, gp & 7));
        return true;
    }
    case MOp::CVTTSS2SI: {
        /* CVTTSS2SI r64, xmm: F3 + REX.W + 0F + 2C + ModR/M.  f32 -> int
         * truncado hacia cero. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t gp = static_cast<uint8_t>(mi.dst.reg);
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        if (mi.flags & MI_FLAG_VX_SCALAR) {
            /* VCVTTSS2SI r64, xmm: VX.LIG.F3.0F.W1 2C, vvvv=1111. */
            emit_vx3(gp, xs, VX_NO_VVVV, /*w=*/1, /*l256=*/false, 0, false, out,
                     /*map=*/1, /*pp=*/2);
            put8(out, 0x2C);
            put8(out, modrm(3, gp & 7, xs & 7));
            return true;
        }
        put8(out, 0xF3);
        put_rex(out, true, gp, xs);
        put8(out, 0x0F);
        put8(out, 0x2C);
        put8(out, modrm(3, gp & 7, xs & 7));
        return true;
    }
    case MOp::VXORPS:
    case MOp::VANDPS: {
        /* VXORPS/VANDPS dst, src1(vvvv), src2: VX.LIG.NP.0F {57|54}.  FNEG/
         * FABS escalar en avx (3-operandos no-destructivo). */
        const uint8_t opc = (mi.op == MOp::VXORPS) ? 0x57 : 0x54;
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xv = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src2.reg) - 16;
        emit_vx3(xd, xs, xv, /*w=*/0, /*l256=*/false, 0, false, out,
                 /*map=*/1, /*pp=*/0);
        put8(out, opc);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }
    case MOp::XORPS: {
        /* XORPS xmm_dst, xmm_src: (REX) + 0F + 57 + ModR/M.  Sin prefijo
         * (paquete f32).  Lo usa el selector para clear (xorps x,x -> 0.0)
         * y para construir la mascara de neg/abs. */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t rex = rex_byte(false, xd, xs);
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, 0x57);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }
    case MOp::ANDPS: {
        /* ANDPS xmm_dst, xmm_src: (REX) + 0F + 54 + ModR/M.  Sin prefijo
         * (paquete f32).  Lo usa el selector para FABS (AND con ~signbit). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t xd = static_cast<uint8_t>(mi.dst.reg) - 16;
        const uint8_t xs = static_cast<uint8_t>(mi.src1.reg) - 16;
        const uint8_t rex = rex_byte(false, xd, xs);
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, 0x54);
        put8(out, modrm(3, xd & 7, xs & 7));
        return true;
    }

    case MOp::IDIV:
    case MOp::DIV_U: {
        /* IDIV r/m64 (signed): REX.W + F7 /7.  DIV r/m64 (unsigned): F7 /6.
         * Divisor en src1.reg. */
        if (mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t ext = (mi.op == MOp::IDIV) ? 7 : 6;
        const uint8_t rex = rex_byte(true, 0, mi.src1.reg);
        if (rex) put8(out, rex);
        put8(out, 0xF7);
        put8(out, modrm(3, ext, mi.src1.reg & 7));
        return true;
    }
    case MOp::CQO: {
        /* CQO: REX.W + 99 -- sign-extend RAX -> RDX:RAX. */
        put8(out, 0x48);
        put8(out, 0x99);
        return true;
    }
    case MOp::LOCK_CMPXCHG:
    case MOp::LOCK_XADD: {
        /* lock cmpxchg/xadd [mem], reg.  dst = mem [addr], src1 = reg fuente.
         *   F0 (LOCK) + REX.W + 0F B1/C1 /r.  ModRM.reg = src1, r/m = mem. */
        if (mi.dst.kind != MOperandKind::MEM ||
            mi.src1.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        put8(out, 0xF0); /* prefijo LOCK */
        const uint8_t srcreg = static_cast<uint8_t>(mi.src1.reg);
        const MReg idx = mi.dst.mem_index();
        const uint8_t rex =
            rex_byte(true, srcreg, mi.dst.reg,
                     idx == MReg::NONE ? 0 : static_cast<uint8_t>(idx));
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, mi.op == MOp::LOCK_CMPXCHG ? 0xB1 : 0xC1);
        emit_modrm_mem(mi.dst, srcreg & 7, out);
        return true;
    }
    case MOp::MOVZX:
    case MOp::MOVSX: {
        /* MOVZX/MOVSX dst64, src_mem<width>.  Encoding:
         *   MOVZX r64, r/m8:  REX.W + 0F B6 /r
         *   MOVZX r64, r/m16: REX.W + 0F B7 /r
         *   MOVSX r64, r/m8:  REX.W + 0F BE /r
         *   MOVSX r64, r/m16: REX.W + 0F BF /r
         *   MOVSX r64, r/m32: REX.W + 63 /r    (MOVSXD)
         *
         * src.flags determina el ancho del operando fuente
         * (1/2/4 bytes).  Para src REG, usa src.width.
         * dst es siempre 64-bit. */
        if (mi.dst.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t src_width =
            (mi.src1.kind == MOperandKind::MEM) ? mi.src1.flags : mi.src1.width;
        /* Determine opcode bytes. */
        uint8_t op_byte1 = 0x0F;
        uint8_t op_byte2 = 0;
        bool single_byte = false; /* true para MOVSXD (sin 0F) */
        if (mi.op == MOp::MOVZX) {
            if (src_width == 1)
                op_byte2 = 0xB6;
            else if (src_width == 2)
                op_byte2 = 0xB7;
            else {
                put8(out, 0xCC);
                return true;
            }
        } else { /* MOVSX */
            if (src_width == 1)
                op_byte2 = 0xBE;
            else if (src_width == 2)
                op_byte2 = 0xBF;
            else if (src_width == 4) {
                single_byte = true;
            } else {
                put8(out, 0xCC);
                return true;
            }
        }
        if (mi.src1.kind == MOperandKind::REG) {
            const uint8_t rex = rex_byte(true, mi.dst.reg, mi.src1.reg);
            if (rex) put8(out, rex);
            if (single_byte) {
                /* x86-32: MOVSXD (0x63) no existe (es ARPL); un 32->64
                 * sign-extend no aplica sin reg de 64-bit -> mov r32 plano
                 * (8B /r), el valor YA es de 32-bit. */
                put8(out, mode32_ ? 0x8B : 0x63);
            } else {
                put8(out, op_byte1);
                put8(out, op_byte2);
            }
            put8(out, modrm(3, mi.dst.reg & 7, mi.src1.reg & 7));
        } else if (mi.src1.kind == MOperandKind::MEM) {
            const uint8_t base = mi.src1.reg;
            const uint8_t index = static_cast<uint8_t>(mi.src1.mem_index());
            const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
            const uint8_t rex =
                rex_byte(true, mi.dst.reg, base, has_index ? index : 0);
            if (rex) put8(out, rex);
            if (single_byte) {
                /* x86-32: MOVSXD -> mov r32, r/m32 (8B /r); ver arriba. */
                put8(out, mode32_ ? 0x8B : 0x63);
            } else {
                put8(out, op_byte1);
                put8(out, op_byte2);
            }
            emit_modrm_mem(mi.src1, mi.dst.reg & 7, out);
        } else {
            put8(out, 0xCC);
        }
        return true;
    }
    case MOp::NEG: emit_unary_alu(fn, mi, out, 3); return true;
    case MOp::NOT: emit_unary_alu(fn, mi, out, 2); return true;
    case MOp::INC: {
        const MOperand &dst = mi.dst;
        if (dst.kind == MOperandKind::MEM) {
            /* INC dword [mem]: 0xFF /0 (32-bit, sin REX.W).  Lo usa el auto-PGO
             * para incrementar un contador de branch (uint32) en memoria.  REX
             * solo si base/index es r8-r15. */
            const uint8_t base = dst.reg;
            const uint8_t index = static_cast<uint8_t>(dst.mem_index());
            const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
            const uint8_t rex = rex_byte(false, 0, base, has_index ? index : 0);
            if (rex) put8(out, rex);
            put8(out, 0xFF);
            emit_modrm_mem(dst, 0, out); // campo reg = 0 (/0)
            return true;
        }
        /* INC r64: REX.W + 0xFF /0.  3 bytes total. */
        if (dst.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t rex = rex_byte(true, 0, dst.reg);
        if (rex) put8(out, rex);
        put8(out, 0xFF);
        put8(out, modrm(3, 0, dst.reg & 7));
        return true;
    }
    case MOp::DEC: {
        /* DEC r64: REX.W + 0xFF /1.  3 bytes total. */
        const MOperand &dst = mi.dst;
        if (dst.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t rex = rex_byte(true, 0, dst.reg);
        if (rex) put8(out, rex);
        put8(out, 0xFF);
        put8(out, modrm(3, 1, dst.reg & 7));
        return true;
    }
    case MOp::SETCC: emit_setcc(fn, mi, out); return true;
    case MOp::CMOVCC: emit_cmovcc(fn, mi, out); return true;
    case MOp::JMP: emit_jmp(fn, mi, out); return true;
    case MOp::JCC: emit_jcc(fn, mi, out); return true;
    case MOp::CALL_SYM: {
        /* AOT: CALL rel32 a una funcion del modulo por nombre.  Se
         * emite E8 + rel32=0 (placeholder) y se registra una MReloc
         * CALL_REL32 que el driver parchea tras el layout de .text.
         * patch_at se deja en offset ABSOLUTO de @c out; encode() le
         * resta @c base para dejarlo relativo a la funcion. */
        /*  AOT-GC (Inc 1): si el call lleva stackmap (gc<T>), fijar su
         * pc_offset al inicio del call (mismo criterio que MOp::CALL) para que
         * el GC walker lo localice por la direccion de retorno. */
        if (mi.flags != UINT16_MAX && mi.flags < fn.stackmaps.size()) {
            fn.stackmaps[mi.flags].pc_offset =
                static_cast<uint32_t>(out.size());
        }
        put8(out, 0xE8);
        MReloc r;
        r.kind = MRelocKind::CALL_REL32;
        r.patch_at = static_cast<uint32_t>(out.size());
        r.sym_idx = static_cast<uint32_t>(mi.src1.value);
        r.addend = 0;
        fn.relocs.push_back(r);
        put32(out, 0); /* placeholder rel32 */
        return true;
    }
    case MOp::JMP_SYM: {
        /* AOT: JMP rel32 a una funcion del modulo (cola del tail-call).
         * E9 + rel32=0 (placeholder) + MReloc CALL_REL32 (misma
         * matematica rel32 que el CALL E8). */
        put8(out, 0xE9);
        MReloc r;
        r.kind = MRelocKind::CALL_REL32;
        r.patch_at = static_cast<uint32_t>(out.size());
        r.sym_idx = static_cast<uint32_t>(mi.src1.value);
        r.addend = 0;
        fn.relocs.push_back(r);
        put32(out, 0); /* placeholder rel32 */
        return true;
    }
    case MOp::DATA_PTR_LABEL: {
        /* Entrada de 8 bytes de la jump table densa: 8 zeros placeholder +
         * un AddrTableFixup {offset, label}.  El pipeline lo parchea
         * POST-memcpy con la direccion absoluta (base + label_offsets[label]).
         * No es codigo ejecutable (se salta); el dispatch lo lee con un mov. */
        if (mi.src1.kind != MOperandKind::LABEL) {
            put8(out, 0xCC);
            return true;
        }
        MFunction::AddrTableFixup f;
        f.patch_at = static_cast<uint32_t>(out.size());
        f.label = static_cast<MLabelId>(mi.src1.value);
        fn.addr_table_fixups.push_back(f);
        for (int k = 0; k < 8; ++k)
            put8(out, 0); /* placeholder qword */
        return true;
    }
    case MOp::DATA_REL32_LABEL: {
        /* Entrada self-relative de 4 bytes de la jump table AOT (PIC-safe, sin
         * reloc): valor = offset[block] - offset[table].  El table label_def
         * PRECEDE a las entradas -> offset[table] ya esta resuelto; lo usamos
         * como instr_end (base del MFixup) y label=block -> resolve_fixups
         * escribe offset[block]-offset[table].  El dispatch suma la base
         * runtime de la tabla. */
        if (mi.src1.kind != MOperandKind::LABEL ||
            mi.src2.kind != MOperandKind::LABEL) {
            for (int k = 0; k < 4; ++k)
                put8(out, 0xCC);
            return true;
        }
        const MLabelId block = static_cast<MLabelId>(mi.src1.value);
        const MLabelId table = static_cast<MLabelId>(mi.src2.value);
        const uint32_t table_off = (table < fn.label_offsets.size())
                                       ? fn.label_offsets[table]
                                       : UINT32_MAX;
        fn.fixups.push_back(
            MFixup{block, static_cast<uint32_t>(out.size()), table_off, 4});
        for (int k = 0; k < 4; ++k)
            put8(out, 0); /* placeholder dword */
        return true;
    }
    case MOp::LEA_LABEL: {
        /* lea r64, [rip+disp32] -> direccion NATIVA de un LABEL local
         * (intra-funcion).  Mismo encoding que LEA_RIP_SYM pero el disp32 lo
         * resuelve un MFixup (label local) en lugar de un MReloc (simbolo).
         * disp = label_off - instr_end (rip-relativo, igual que jmp/jcc). */
        if (mi.dst.kind != MOperandKind::REG ||
            mi.src1.kind != MOperandKind::LABEL) {
            put8(out, 0xCC);
            return true;
        }
        put_rex(out, true, mi.dst.reg, 0); /* REX.W + REX.R si dst>=R8 */
        put8(out, 0x8D);
        put8(out, modrm(0, mi.dst.reg & 7, 5)); /* mod=00 rm=101 -> [rip+d32] */
        const uint32_t patch_at = static_cast<uint32_t>(out.size());
        put32(out, 0); /* placeholder disp32 */
        const uint32_t instr_end = static_cast<uint32_t>(out.size());
        fn.fixups.push_back(MFixup{static_cast<MLabelId>(mi.src1.value),
                                   patch_at, instr_end, 4});
        return true;
    }
    case MOp::LEA_RIP_SYM: {
        /* AOT: lea r64, [rip+disp32] -> direccion de un dato (.rodata)
         * position-independent.  REX.W + 8D + ModRM(mod=00,reg=dst,rm=101
         * = RIP) + disp32=0 (placeholder) + MReloc{DATA_REL32}.  El writer
         * resuelve disp32 = target_VA - (site_VA + 4) tras el layout. */
        if (mi.dst.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        put_rex(out, true, mi.dst.reg, 0); /* REX.W + REX.R si dst>=R8 */
        put8(out, 0x8D);
        put8(out,
             modrm(0, mi.dst.reg & 7, 5)); /* mod=00 rm=101 -> [rip+disp32] */
        MReloc r;
        r.kind = MRelocKind::DATA_REL32;
        r.patch_at = static_cast<uint32_t>(out.size());
        r.sym_idx = static_cast<uint32_t>(mi.src1.value);
        r.addend = 0;
        fn.relocs.push_back(r);
        put32(out, 0); /* placeholder disp32 */
        return true;
    }
    case MOp::TLS_LE_ADDR: {
        /* AOT TLS local-exec (ELF): dst = direccion por-hilo de un
         * `thread_local`.  Dos instrucciones:
         *   mov dst, %fs:0            ; thread pointer (TP)
         *   lea dst, [dst + sym@tpoff]; &var = TP + tpoff (TPOFF32 reloc)
         * El reloc TPOFF32 va sobre el disp32 del lea; el driver lo traduce a
         * R_X86_64_TPOFF32 + STT_TLS y el --link resuelve el offset (negativo,
         * variante II).  El resultado es un host_ptr. */
        if (mi.dst.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t d = mi.dst.reg;
        /* mov dst, %fs:0 : 64 | REX.W(+R) | 8B | modrm(00,dst,100=SIB) | 25 |
         * disp32=0 */
        put8(out, 0x64);               /* prefijo de segmento FS */
        put_rex(out, true, d, 0);      /* REX.W + REX.R si dst>=R8 */
        put8(out, 0x8B);               /* mov r64, r/m64 */
        put8(out, modrm(0, d & 7, 4)); /* mod=00 rm=100 -> sigue SIB */
        put8(out, 0x25); /* SIB: base=101(none)+disp32, idx=none */
        put32(out, 0);   /* disp32 = 0 */
        /* lea dst, [dst + disp32] : REX.W(+R+B) | 8D | modrm + (SIB si rsp/r12)
         * | disp32 (TPOFF32 reloc) */
        put_rex(out, true, d, d); /* REX.R (reg=dst) + REX.B (base=dst) */
        put8(out, 0x8D);          /* lea r64, m */
        if ((d & 7) == 4) {       /* rsp/r12: requiere SIB */
            put8(out, modrm(2, d & 7, 4)); /* mod=10 rm=100 -> SIB */
            put8(out, 0x24); /* SIB: base=100(dst&7=4), idx=none */
        } else {
            put8(out, modrm(2, d & 7, d & 7)); /* mod=10 -> [dst + disp32] */
        }
        MReloc r;
        r.kind = MRelocKind::TPOFF32;
        r.patch_at = static_cast<uint32_t>(out.size());
        r.sym_idx = static_cast<uint32_t>(mi.src1.value);
        r.addend = 0;
        fn.relocs.push_back(r);
        put32(out, 0); /* placeholder disp32 (tpoff) */
        return true;
    }
    case MOp::TLS_PE_ADDR: {
        /* AOT TLS PE/Windows: dst = direccion por-hilo de un `thread_local`.
         *   mov r10, gs:[0x58]          ; TEB->ThreadLocalStoragePointer
         *   mov r11d, [rip+_tls_index]  ; indice del slot (DATA_REL32)
         *   mov r10, [r10 + r11*8]      ; base del bloque TLS del modulo
         *   lea dst, [r10 + var@secrel] ; &var (SECREL32)
         * Usa r10/r11 (scratch reservados por el regalloc) -> dst libre.  El
         * resultado es un host_ptr. */
        if (mi.dst.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        const uint8_t d = mi.dst.reg;
        /* mov r10, gs:[0x58] : 65 | REX.W+R | 8B | modrm(00,r10,SIB) | 25 | d32
         */
        put8(out, 0x65);           /* prefijo de segmento GS */
        put_rex(out, true, 10, 0); /* REX.W + REX.R (reg=r10) */
        put8(out, 0x8B);
        put8(out, modrm(0, 10, 4)); /* mod=00 reg=r10 rm=100(SIB) */
        put8(out, 0x25);            /* SIB base=101(none)+disp32 idx=none */
        put32(out, 0x58);           /* TEB->ThreadLocalStoragePointer */
        /* mov r11d, [rip+_tls_index] : REX.R | 8B | modrm(00,r11,101=rip) | d32
         */
        put_rex(out, false, 11, 0); /* REX.R (reg=r11), 32-bit (sin W) */
        put8(out, 0x8B);
        put8(out, modrm(0, 11, 5)); /* mod=00 reg=r11 rm=101(rip) */
        {
            MReloc r1;
            r1.kind = MRelocKind::DATA_REL32; /* &_tls_index (rip-relativo) */
            r1.patch_at = static_cast<uint32_t>(out.size());
            r1.sym_idx = static_cast<uint32_t>(mi.src2.value);
            r1.addend = 0;
            fn.relocs.push_back(r1);
        }
        put32(out, 0);
        /* mov r10, [r10 + r11*8] : REX.W+R+X+B | 8B | modrm(00,r10,SIB) | SIB
         */
        put_rex(out, true, 10, 10, 11); /* W + R(r10) + B(r10 base) + X(r11) */
        put8(out, 0x8B);
        put8(out, modrm(0, 10, 4)); /* mod=00 reg=r10 rm=100(SIB) */
        put8(out, sib(3, 11, 10));  /* scale=8 index=r11 base=r10 */
        /* lea dst, [r10 + var@secrel] : REX.W+R(dst)+B(r10) | 8D | modrm | d32
         */
        put_rex(out, true, d, 10); /* REX.R (reg=dst) + REX.B (base=r10) */
        put8(out, 0x8D);
        put8(out, modrm(2, d, 10)); /* mod=10 reg=dst rm=r10(=2) -> [r10+d32] */
        {
            MReloc r2;
            r2.kind = MRelocKind::SECREL32; /* offset del var en .tls */
            r2.patch_at = static_cast<uint32_t>(out.size());
            r2.sym_idx = static_cast<uint32_t>(mi.src1.value);
            r2.addend = 0;
            fn.relocs.push_back(r2);
        }
        put32(out, 0);
        return true;
    }
    case MOp::MOV_SYM: {
        /* AOT: mov r64, &simbolo (.rodata).  REX.W + B8+rd + imm64=0
         * (placeholder) + MReloc ABS64.  El driver escribe la VA
         * absoluta del dato tras conocer el layout de .rodata. */
        if (mi.dst.kind != MOperandKind::REG) {
            put8(out, 0xCC);
            return true;
        }
        if (mode32_) {
            /* x86-32: mov r32, imm32 (B8+rd + imm32) + MReloc{ABS32}.  x86-32
             * no tiene REX ni imm64; la VA de un no-PIE cabe en 32 bits.  El
             * emisor ELF32 lo traduce a R_386_32. */
            if (mi.dst.reg >= 8)
                put8(out, 0x41); /* REX.B para r8d..r15d (raro) */
            put8(out, 0xB8 + (mi.dst.reg & 7));
            MReloc r;
            r.kind = MRelocKind::ABS32;
            r.patch_at = static_cast<uint32_t>(out.size());
            r.sym_idx = static_cast<uint32_t>(mi.src1.value);
            r.addend = 0;
            fn.relocs.push_back(r);
            put32(out, 0); /* placeholder imm32 */
            return true;
        }
        put_rex(out, true, 0, mi.dst.reg);
        put8(out, 0xB8 + (mi.dst.reg & 7));
        MReloc r;
        r.kind = MRelocKind::ABS64;
        r.patch_at = static_cast<uint32_t>(out.size());
        r.sym_idx = static_cast<uint32_t>(mi.src1.value);
        r.addend = 0;
        fn.relocs.push_back(r);
        put64(out, 0); /* placeholder imm64 */
        return true;
    }
    case MOp::CALL: {
        /* si el CALL tiene stackmap asociado (flags
         * != UINT16_MAX), rellenar su pc_offset.  Esto permite
         * que el GC walker encuentre el stackmap correcto
         * cuando el callee triggera GC. */
        if (mi.flags != UINT16_MAX && mi.flags < fn.stackmaps.size()) {
            fn.stackmaps[mi.flags].pc_offset =
                static_cast<uint32_t>(out.size());
        }
        emit_call(fn, mi, out);
        return true;
    }
    case MOp::LABEL_DEF:
        /* No emite bytes; label_offset ya se setea en encode().
         * Sin embargo, si el LABEL_DEF aparece A MITAD del bloque
         * (insertado por el selector dentro de un BB grande)
         * necesitamos registrar el offset aqui tambien. */
        if (mi.src1.kind == MOperandKind::LABEL) {
            const uint32_t id = static_cast<uint32_t>(mi.src1.value);
            if (id < fn.label_offsets.size()) {
                /* Solo si no esta seteado por encode().  Calcular
                 * el offset relativo al base de la funcion. */
                if (fn.label_offsets[id] == UINT32_MAX) {
                    fn.label_offsets[id] = static_cast<uint32_t>(out.size());
                }
            }
        }
        return true;
    case MOp::COMMENT:
        /* skip en release */
        return true;
    case MOp::INLINE_ASM_RAW: {
        /*  AS inc.5: apendea los bytes del bloque inline-asm ya
         * ensamblado (via vx::g_asm_backend) verbatim al code cache.
         * El indice del blob viaja como IMM32 en src1.  Los inputs/
         * outputs register-bound ya estan en sus registros fisicos
         * (pineados por el regalloc); el asm opera sobre ellos. */
        if (mi.src1.kind == MOperandKind::IMM32) {
            const uint32_t idx = static_cast<uint32_t>(mi.src1.value);
            if (idx < fn.asm_blobs.size()) {
                const AsmBlob &ab = fn.asm_blobs[idx];
                const uint32_t blob_base = static_cast<uint32_t>(out.size());
                out.insert(out.end(), ab.bytes.begin(), ab.bytes.end());
                //  AS inc.6: emitir un MReloc por cada simbolo propio
                // referenciado en el asm.  rip-relativo (`jmp [sym]`, `lea
                // reg,[rip+sym]`) -> DATA_REL32; imm absoluto (`mov rax,sym`)
                // -> ABS64.  @c patch_at absoluto en @c out; encode() lo
                // reubica relativo a la funcion (igual que CALL_SYM).  El
                // driver resuelve el nombre del simbolo (funcion o dato).
                for (const auto &sr : ab.sym_refs) {
                    // Decodificar el nombre CANONICO que dejo lower_asm:
                    //   __vxf_<label>  -> FUNCION del modulo
                    //   __vxg_<slot>   -> GLOBAL (static_data slot)
                    // y combinarlo con la FORMA (kind) para fijar el reloc:
                    //   funcion + branch  -> CALL_REL32, nombre bare
                    //   (fn_by_name) funcion + abs/data-> fnsym:<label> global
                    //   + abs     -> ABS64,      rodata.<slot> global  + data
                    //   -> DATA_REL32, rodata.<slot>
                    std::string reloc_sym;
                    MRelocKind kind = MRelocKind::DATA_REL32;
                    const std::string &cn = sr.symbol;
                    const bool is_fn = cn.rfind("__vxf_", 0) == 0;
                    const bool is_g = cn.rfind("__vxg_", 0) == 0;
                    if (is_fn) {
                        const std::string label = cn.substr(6);
                        if (sr.kind == AsmBlob::AsmSymRefKind::BranchRel32) {
                            reloc_sym = label; // CALL_REL32 usa el bare label
                            kind = MRelocKind::CALL_REL32;
                        } else {
                            reloc_sym = "fnsym:" + label;
                            kind = (sr.kind == AsmBlob::AsmSymRefKind::Abs64)
                                       ? MRelocKind::ABS64
                                       : MRelocKind::DATA_REL32;
                        }
                    } else if (is_g) {
                        reloc_sym = "rodata." + cn.substr(6);
                        kind = (sr.kind == AsmBlob::AsmSymRefKind::Abs64)
                                   ? MRelocKind::ABS64
                                   : MRelocKind::DATA_REL32;
                    } else {
                        // Simbolo no decorado (no resuelto por lower_asm): se
                        // emite tal cual (best-effort segun la forma).
                        reloc_sym = cn;
                        kind = (sr.kind == AsmBlob::AsmSymRefKind::BranchRel32)
                                   ? MRelocKind::CALL_REL32
                               : (sr.kind == AsmBlob::AsmSymRefKind::Abs64)
                                   ? MRelocKind::ABS64
                                   : MRelocKind::DATA_REL32;
                    }
                    uint32_t sidx = UINT32_MAX;
                    for (uint32_t i = 0; i < fn.reloc_symbols.size(); ++i)
                        if (fn.reloc_symbols[i] == reloc_sym) {
                            sidx = i;
                            break;
                        }
                    if (sidx == UINT32_MAX) {
                        sidx = static_cast<uint32_t>(fn.reloc_symbols.size());
                        fn.reloc_symbols.push_back(reloc_sym);
                    }
                    MReloc r;
                    r.kind = kind;
                    r.patch_at = blob_base + sr.offset;
                    r.sym_idx = sidx;
                    r.addend = 0;
                    // DATA_REL32: el disp rip-rel se mide desde el FIN de
                    // instruccion.  Si hay bytes tras el disp (imm de
                    // `mov [rip+disp32], imm32`), el reloc `sym - (site+4)`
                    // apuntaria disp_trailing bytes de mas -> restamos.
                    if (kind == MRelocKind::DATA_REL32 && sr.pcrel_trailing)
                        r.addend = -static_cast<int64_t>(sr.pcrel_trailing);
                    fn.relocs.push_back(r);
                }
            }
        }
        return true;
    }
    case MOp::ARG:
        /* pseudo: el rewrite ya lo expandio a moves a arg_regs antes
         * del CALL.  No deberia llegar aqui; si llega, no emite. */
        return true;
    case MOp::SAFEPOINT: {
        /* poll expansion: lee safepoint_flag desde [rbx+0],
         * si != 0 salta al slow path que llama al handler.
         *
         * Layout:
         *
         *     80 7B 00 00          cmp byte [rbx+0], 0
         *     74 0F                je  skip                ; rel8
         *     48 89 DF             mov rdi, rbx            ; SysV: proc en rdi
         *     48 B8 <imm64>        mov rax, handler_addr
         *     FF D0                call rax
         *   skip:
         *
         * Total: 4 + 2 + 3 + 10 + 2 = 21 bytes.
         * En Win64 cambia: mov rcx, rbx (3 bytes).
         */
        /* rellenar pc_offset del stackmap asociado.
         * MInstr::flags lleva el indice del stackmap en mf.stackmaps.
         * El pc_offset que escribimos es la direccion DEL POLL, no
         * la del handler -- asi el GC encuentra el stackmap correcto
         * cuando captura RIP dentro o despues del poll. */
        if (mi.flags != UINT16_MAX && mi.flags < fn.stackmaps.size()) {
            fn.stackmaps[mi.flags].pc_offset =
                static_cast<uint32_t>(out.size());
        }
        /* cmp byte [rbx+0], 0  -- usamos disp8=0 explicito */
        put8(out, 0x80); /* cmp r/m8, imm8 */
        put8(out,
             modrm(1, 7, 3)); /* mod=01 (disp8), reg=7 (subop), r/m=3 (rbx) */
        put8(out, 0x00);      /* disp8 = 0 (safepoint_flag offset) */
        put8(out, 0x00);      /* imm8 = 0 */
        /* je rel8 = 0x74, salto al final de la secuencia (skip).
         * El slow path mide: mov rdi/rcx, rbx (3) + mov rax, imm64 (10) + call
         * rax (2) = 15. rel8 = 15. */
#if defined(_WIN32)
        put8(out, 0x74); /* je rel8 */
        put8(out, 15);
        /* mov rcx, rbx (Win64 ABI: proc en rcx) */
        put8(out, 0x48); /* REX.W */
        put8(out, 0x89);
        put8(out, modrm(3, 3, 1)); /* rcx <- rbx */
#else
        put8(out, 0x74); /* je rel8 */
        put8(out, 15);
        /* mov rdi, rbx (SysV: proc en rdi) */
        put8(out, 0x48); /* REX.W */
        put8(out, 0x89);
        put8(out, modrm(3, 3, 7)); /* rdi <- rbx */
#endif
        /* mov rax, imm64 = handler addr */
        {
            const uint32_t pool_idx = static_cast<uint32_t>(mi.src1.value);
            const uint64_t handler = (pool_idx < fn.imm64_pool.size())
                                         ? fn.imm64_pool[pool_idx]
                                         : 0ULL;
            put8(out, 0x48); /* REX.W */
            put8(out, 0xB8); /* MOV RAX, imm64 */
            put64(out, handler);
        }
        /* call rax */
        put8(out, 0xFF);
        put8(out, modrm(3, 2, 0)); /* /2 reg=rax */
        return true;
    }
    case MOp::LOAD_PROC: {
        /* Carga ProcessVM* en dst (RBX por convencion del callback).
         *
         * TLS-direct (src1.value != -1, Win64):
         *   65 48 8B <modrm> 25 <disp32>   mov dst, gs:[disp32]
         *   modrm = mod=00, reg=dst, r/m=100 (SIB);  SIB=0x25 (disp32 abs).
         *
         * Fallback (src1.value == -1):
         *   48 B8 <imm64>   mov rax, get_current_executing_process
         *   FF D0           call rax
         *   48 89 C0|dst    mov dst, rax
         */
        const uint8_t dst = mi.dst.reg; /* reg id completo (RBX=3) */
        if (mi.src1.value != -1) {
            put8(out, 0x65);               /* gs: prefix */
            put_rex(out, true, dst, 0, 0); /* REX.W (+R si dst>=8) */
            put8(out, 0x8B);               /* mov r64, r/m64 */
            put8(out, modrm(0, dst, 4));   /* mod=00 reg=dst rm=SIB */
            put8(out, 0x25);               /* SIB: disp32 absoluto */
            put32(out, static_cast<uint32_t>(mi.src1.value));
        } else {
            const uint32_t pool_idx = static_cast<uint32_t>(mi.src2.value);
            const uint64_t getproc = (pool_idx < fn.imm64_pool.size())
                                         ? fn.imm64_pool[pool_idx]
                                         : 0ULL;
            put8(out, 0x48);
            put8(out, 0xB8);
            put64(out, getproc); /* mov rax, imm64 */
            put8(out, 0xFF);
            put8(out, modrm(3, 2, 0)); /* call rax */
            /* mov dst, rax: REX.W (+B si dst>=8) + 0x89 + modrm(3, rax, dst) */
            put_rex(out, true, 0, dst, 0);
            put8(out, 0x89);
            put8(out, modrm(3, 0, dst));
        }
        return true;
    }
    case MOp::REP_MOVSB:
        /* REP MOVSB: copia RCX bytes desde [RSI] a [RDI], incrementando
         * ambos (DF=0 por la ABI host).  Encoding: F3 (prefijo REP) + A4
         * (MOVSB).  Sin REX (movsb opera sobre los punteros completos
         * RSI/RDI de 64 bits en modo long).  La instruccion x86 de
         * copia mas rapida (fast-string-ops / ERMSB). */
        put8(out, 0xF3); /* prefijo REP */
        put8(out, 0xA4); /* MOVSB */
        return true;
    case MOp::REP_STOSB:
        /* REP STOSB: escribe AL en [RDI] RCX veces (DF=0 por la ABI host).
         * Encoding: F3 (prefijo REP) + AA (STOSB).  Sin REX: stosb usa el
         * puntero completo RDI de 64 bits en modo long y el operando es el
         * byte AL.  Es la via rapida del hardware (fast-string-ops/ERMSB)
         * para rellenar una region -- lo que IrOp::MEMSET describe. */
        put8(out, 0xF3); /* prefijo REP */
        put8(out, 0xAA); /* STOSB */
        return true;
    default:
        /* Opcode no implementado en este encoder. */
        return false;
    }
}

/* ===================================================================== */
/* MOV (formas: r/r, r/imm32, r/imm64, r/m, m/r)                          */
/* ===================================================================== */

void X86Encoder::emit_mov(MFunction &fn, const MInstr &mi,
                          std::vector<uint8_t> &out) {
    const MOperand &dst = mi.dst;
    const MOperand &src = mi.src1;

    /* Caso 1: MOV reg, reg.  Ancho via dst.width (commit 9):
     *   8 -> REX.W + 0x89 (mov r64,r64)
     *   4 -> 0x89 sin REX.W (mov r32,r32 -> zero-extiende a 64)
     *   2 -> 66 + 0x89; 1 -> 0x88. */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::REG) {
        const uint8_t w = dst.width;
        if (w == 2) put8(out, 0x66);
        const bool need_rex_w = (w == 8);
        uint8_t rex = rex_byte(need_rex_w, src.reg, dst.reg);
        /* Byte op con SIL/DIL/BPL/SPL: forzar REX (sino seria AH/CH/etc). */
        if (w == 1 && rex == 0 &&
            (needs_rex_for_byte_reg(src.reg) ||
             needs_rex_for_byte_reg(dst.reg)))
            rex = 0x40;
        if (rex) put8(out, rex);
        put8(out, (w == 1) ? 0x88 : 0x89);
        put8(out, modrm(3, src.reg & 7, dst.reg & 7));
        return;
    }

    /* Caso 2: MOV reg, imm32 (sign-extended -> reg64) */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::IMM32) {
        /* Optimizacion: si valor cabe en 32-bit y no necesitamos
         * sign-ext especifico, usar MOV r32, imm32 (no REX.W).
         * Pero como la mayoria del codigo VM usa i64, emitimos REX.W
         * + 0xC7 /0 + imm32 (sign-extended a 64). */
        const uint8_t rex = rex_byte(true, 0, dst.reg);
        if (rex) put8(out, rex);
        put8(out, 0xC7);
        put8(out, modrm(3, 0, dst.reg & 7));
        put32(out, static_cast<uint32_t>(src.value));
        return;
    }

    /* Caso 3: MOV reg, imm64 (via pool) */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::IMM64_IDX) {
        const uint32_t idx = static_cast<uint32_t>(src.value);
        const uint64_t v64 =
            (idx < fn.imm64_pool.size()) ? fn.imm64_pool[idx] : 0;
        /* x86-32 NO tiene esta forma: no hay REX ni inmediatos de 64 bits en un
         * registro que solo tiene 32.  Se emitia igualmente `B8+r` con OCHO
         * bytes detras, asi que el desensamblado se descarrilaba a mitad -- el
         * procesador leia los 4 bytes sobrantes COMO CODIGO.  Sintoma tipico:
         * cargar un literal de texto acababa ejecutando el propio texto.
         * Aqui solo cabe la mitad baja; el emisor que necesite los 64 bits
         * completos debe partirlos en dos mitades ANTES de llegar a este punto
         * (en 32 bits un valor de 64 vive en un PAR de registros). */
        if (mode32_) {
            put8(out, 0xB8 + (dst.reg & 7));
            put32(out, static_cast<uint32_t>(v64));
            return;
        }
        /* MOV r64, imm64: REX.W + B8+r + imm64 */
        put_rex(out, true, 0, dst.reg);
        put8(out, 0xB8 + (dst.reg & 7));
        const size_t imm64_pos = out.size();
        put64(out, v64);
        /* Sprint fib-recursion: si este idx esta en self_ref_imm64_indices,
         * registrar la posicion del imm64 emitido para que el JitCompiler
         * pueda parchearlo con code_start tras la asignacion final. */
        for (uint32_t sref_idx : fn.self_ref_imm64_indices) {
            if (sref_idx == idx) {
                fn.self_ref_byte_offsets.push_back(imm64_pos);
                break;
            }
        }
        return;
    }

    /* Caso 4: MOV reg, [mem].  Ancho controlado por dst.width:
     *   8 -> mov r64, [mem]  (REX.W + 0x8B)  -- qword load
     *   4 -> mov r32, [mem]  (sin REX.W + 0x8B) -- dword load, zero-extend
     *   2 -> mov r16, [mem]  (66 prefix + 0x8B)
     *   1 -> mov r8,  [mem]  (0x8A) */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::MEM) {
        const uint8_t base = src.reg;
        const uint8_t index = static_cast<uint8_t>(src.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t w = dst.width;
        if (w == 2) put8(out, 0x66); /* 16-bit override */
        const bool need_rex_w = (w == 8);
        uint8_t rex =
            rex_byte(need_rex_w, dst.reg, base, has_index ? index : 0);
        /* Byte load a SIL/DIL/BPL/SPL: forzar REX. */
        if (w == 1 && rex == 0 && needs_rex_for_byte_reg(dst.reg)) rex = 0x40;
        if (rex) put8(out, rex);
        put8(out, (w == 1) ? 0x8A : 0x8B);
        emit_modrm_mem(src, dst.reg & 7, out);
        return;
    }

    /* Caso 5: MOV [mem], reg.  Ancho via src.width. */
    if (dst.kind == MOperandKind::MEM && src.kind == MOperandKind::REG) {
        const uint8_t base = dst.reg;
        const uint8_t index = static_cast<uint8_t>(dst.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t w = src.width;
        if (w == 2) put8(out, 0x66);
        const bool need_rex_w = (w == 8);
        uint8_t rex =
            rex_byte(need_rex_w, src.reg, base, has_index ? index : 0);
        /* Byte store desde SIL/DIL/BPL/SPL: forzar REX (sino seria
         * AH/CH/DH/BH -> escribe el byte equivocado del registro). */
        if (w == 1 && rex == 0 && needs_rex_for_byte_reg(src.reg)) rex = 0x40;
        if (rex) put8(out, rex);
        put8(out, (w == 1) ? 0x88 : 0x89);
        emit_modrm_mem(dst, src.reg & 7, out);
        return;
    }

    /* Caso 6: MOV [mem], imm32 (sign-extended) */
    if (dst.kind == MOperandKind::MEM && src.kind == MOperandKind::IMM32) {
        const uint8_t base = dst.reg;
        const uint8_t index = static_cast<uint8_t>(dst.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex = rex_byte(true, 0, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        put8(out, 0xC7); /* MOV r/m64, imm32 (sign-ext) */
        emit_modrm_mem(dst, 0, out);
        put32(out, static_cast<uint32_t>(src.value));
        return;
    }

    /* Cualquier otra combinacion no soportada -> INT3 para fail-fast. */
    put8(out, 0xCC);
}

/* ===================================================================== */
/* LEA reg, [mem]                                                         */
/* ===================================================================== */

void X86Encoder::emit_lea(MFunction & /*fn*/, const MInstr &mi,
                          std::vector<uint8_t> &out) {
    const MOperand &dst = mi.dst;
    const MOperand &src = mi.src1;
    if (dst.kind != MOperandKind::REG || src.kind != MOperandKind::MEM) {
        put8(out, 0xCC);
        return;
    }
    const uint8_t base = src.reg;
    const uint8_t index = static_cast<uint8_t>(src.mem_index());
    const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
    const uint8_t rex = rex_byte(true, dst.reg, base, has_index ? index : 0);
    if (rex) put8(out, rex);
    put8(out, 0x8D); /* LEA r64, m */
    emit_modrm_mem(src, dst.reg & 7, out);
}

/* ===================================================================== */
/* ALU binarias (ADD/SUB/AND/OR/XOR/CMP)                                  */
/* ===================================================================== */

void X86Encoder::emit_alu(MFunction & /*fn*/, const MInstr &mi,
                          std::vector<uint8_t> &out, uint8_t op_byte,
                          uint8_t alu_subop) {
    const MOperand &dst = mi.dst;
    const MOperand &src = mi.src1;

    /* ALU reg/reg: REX.W + op_byte + ModR/M(3, src, dst) */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::REG) {
        const uint8_t rex = rex_byte(true, src.reg, dst.reg);
        if (rex) put8(out, rex);
        put8(out, op_byte);
        put8(out, modrm(3, src.reg & 7, dst.reg & 7));
        return;
    }
    /* ALU reg/imm32: REX.W + 0x81 /subop + imm32 (sign-ext) */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::IMM32) {
        const uint8_t rex = rex_byte(true, 0, dst.reg);
        if (rex) put8(out, rex);
        /* Optimizacion: si imm32 cabe en imm8 sign-ext, usar 0x83
         * que reduce 3 bytes.  Encoding: REX.W + 0x83 /subop + imm8. */
        if (src.value >= -128 && src.value <= 127) {
            put8(out, 0x83);
            put8(out, modrm(3, alu_subop, dst.reg & 7));
            put8(out, static_cast<uint8_t>(src.value & 0xFF));
        } else {
            put8(out, 0x81);
            put8(out, modrm(3, alu_subop, dst.reg & 7));
            put32(out, static_cast<uint32_t>(src.value));
        }
        return;
    }
    /* ALU reg/mem: REX.W + (op_byte+2) + ModR/M */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::MEM) {
        const uint8_t base = src.reg;
        const uint8_t index = static_cast<uint8_t>(src.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex =
            rex_byte(true, dst.reg, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        put8(out, op_byte + 2); /* dir bit flipped */
        emit_modrm_mem(src, dst.reg & 7, out);
        return;
    }
    /* ALU mem/reg: REX.W + op_byte + ModR/M */
    if (dst.kind == MOperandKind::MEM && src.kind == MOperandKind::REG) {
        const uint8_t base = dst.reg;
        const uint8_t index = static_cast<uint8_t>(dst.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex =
            rex_byte(true, src.reg, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        put8(out, op_byte);
        emit_modrm_mem(dst, src.reg & 7, out);
        return;
    }
    /* ALU mem/imm32: REX.W + 0x81 /subop + ModR/M + imm32.
     * Forma optimizada con imm8 sign-ext: REX.W + 0x83 /subop + ModR/M + imm8.
     * Usado por @c add qword [&counter], N en el JIT MIPS profiler. */
    if (dst.kind == MOperandKind::MEM && src.kind == MOperandKind::IMM32) {
        const uint8_t base = dst.reg;
        const uint8_t index = static_cast<uint8_t>(dst.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex = rex_byte(true, 0, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        if (src.value >= -128 && src.value <= 127) {
            put8(out, 0x83);
            emit_modrm_mem(dst, alu_subop, out);
            put8(out, static_cast<uint8_t>(src.value & 0xFF));
        } else {
            put8(out, 0x81);
            emit_modrm_mem(dst, alu_subop, out);
            put32(out, static_cast<uint32_t>(src.value));
        }
        return;
    }
    put8(out, 0xCC);
}

/* ===================================================================== */
/* IMUL reg, reg / reg, reg, imm32                                        */
/* ===================================================================== */

void X86Encoder::emit_imul(MFunction & /*fn*/, const MInstr &mi,
                           std::vector<uint8_t> &out) {
    const MOperand &dst = mi.dst;
    const MOperand &src = mi.src1;
    const MOperand &src2 = mi.src2;
    /* Forma 1: IMUL reg, reg -> REX.W + 0x0F 0xAF /r */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::REG &&
        src2.kind == MOperandKind::NONE) {
        const uint8_t rex = rex_byte(true, dst.reg, src.reg);
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, 0xAF);
        put8(out, modrm(3, dst.reg & 7, src.reg & 7));
        return;
    }
    /* Forma 2: IMUL reg, reg, imm32 -> REX.W + 0x69 /r + imm32 */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::REG &&
        src2.kind == MOperandKind::IMM32) {
        const uint8_t rex = rex_byte(true, dst.reg, src.reg);
        if (rex) put8(out, rex);
        /* imm8 si cabe (0x6B), imm32 si no (0x69) */
        if (src2.value >= -128 && src2.value <= 127) {
            put8(out, 0x6B);
            put8(out, modrm(3, dst.reg & 7, src.reg & 7));
            put8(out, static_cast<uint8_t>(src2.value & 0xFF));
        } else {
            put8(out, 0x69);
            put8(out, modrm(3, dst.reg & 7, src.reg & 7));
            put32(out, static_cast<uint32_t>(src2.value));
        }
        return;
    }
    put8(out, 0xCC);
}

/* ===================================================================== */
/* SHL/SHR/SAR reg, imm8                                                  */
/* ===================================================================== */

void X86Encoder::emit_shift(MFunction & /*fn*/, const MInstr &mi,
                            std::vector<uint8_t> &out, uint8_t shift_subop) {
    const MOperand &dst = mi.dst;
    const MOperand &src = mi.src1;
    if (dst.kind != MOperandKind::REG) {
        put8(out, 0xCC);
        return;
    }
    const uint8_t rex = rex_byte(true, 0, dst.reg);
    if (src.kind == MOperandKind::REG) {
        /* Variante por CL: REX.W + 0xD3 /subop -- el caller debe
         * garantizar que la cuenta vive en CL (RCX low byte).  Solo
         * aceptamos src == RCX explicito para que el caller sepa que
         * debe coordinar el reg destino. */
        if (src.reg != static_cast<uint8_t>(MReg::RCX)) {
            put8(out, 0xCC);
            return;
        }
        if (rex) put8(out, rex);
        put8(out, 0xD3);
        put8(out, modrm(3, shift_subop, dst.reg & 7));
        return;
    }
    if (src.kind != MOperandKind::IMM32) {
        put8(out, 0xCC);
        return;
    }
    if (rex) put8(out, rex);
    if ((src.value & 0xFF) == 1) {
        /* Variante por 1: REX.W + 0xD1 /subop -- mas compacta */
        put8(out, 0xD1);
        put8(out, modrm(3, shift_subop, dst.reg & 7));
    } else {
        /* Variante imm8: REX.W + 0xC1 /subop + imm8 */
        put8(out, 0xC1);
        put8(out, modrm(3, shift_subop, dst.reg & 7));
        put8(out, static_cast<uint8_t>(src.value & 0xFF));
    }
}

/* ===================================================================== */
/* NEG/NOT reg                                                            */
/* ===================================================================== */

void X86Encoder::emit_unary_alu(MFunction & /*fn*/, const MInstr &mi,
                                std::vector<uint8_t> &out, uint8_t subop) {
    const MOperand &dst = mi.dst;
    if (dst.kind != MOperandKind::REG) {
        put8(out, 0xCC);
        return;
    }
    const uint8_t rex = rex_byte(true, 0, dst.reg);
    if (rex) put8(out, rex);
    put8(out, 0xF7);
    put8(out, modrm(3, subop, dst.reg & 7));
}

/* ===================================================================== */
/* CMP / TEST                                                             */
/* ===================================================================== */

void X86Encoder::emit_cmp(MFunction &fn, const MInstr &mi,
                          std::vector<uint8_t> &out) {
    /* CMP usa la misma tabla que ADD/SUB/etc.  El alu_subop=7 y
     * op_byte=0x39 estan en la tabla bajo MOp::CMP. */
    emit_alu(fn, mi, out, 0x39, 7);
}

void X86Encoder::emit_test(MFunction & /*fn*/, const MInstr &mi,
                           std::vector<uint8_t> &out) {
    const MOperand &dst = mi.dst;
    const MOperand &src = mi.src1;
    /* TEST reg, reg: REX.W + 0x85 /r */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::REG) {
        const uint8_t rex = rex_byte(true, src.reg, dst.reg);
        if (rex) put8(out, rex);
        put8(out, 0x85);
        put8(out, modrm(3, src.reg & 7, dst.reg & 7));
        return;
    }
    /* TEST reg, imm32: REX.W + 0xF7 /0 + imm32 */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::IMM32) {
        const uint8_t rex = rex_byte(true, 0, dst.reg);
        if (rex) put8(out, rex);
        put8(out, 0xF7);
        put8(out, modrm(3, 0, dst.reg & 7));
        put32(out, static_cast<uint32_t>(src.value));
        return;
    }
    /* TEST reg, [mem]: REX.W + 0x85 /r con el mem como r/m.  TEST es
     * simetrico (a AND b sin escribir resultado), asi que `TEST reg, mem`
     * se codifica con el reg en el campo reg y el mem en r/m.  Necesario
     * cuando el regalloc spillea el operando (p.ej. el cond de un BR_COND
     * spilled: `TEST scrN, [slot]`).  Sin esto el rewrite producia un
     * TEST reg,mem que caia al INT3 de abajo. */
    if (dst.kind == MOperandKind::REG && src.kind == MOperandKind::MEM) {
        const uint8_t base = src.reg;
        const uint8_t index = static_cast<uint8_t>(src.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex =
            rex_byte(true, dst.reg, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        put8(out, 0x85);
        emit_modrm_mem(src, dst.reg & 7, out);
        return;
    }
    /* TEST [mem], reg: misma simetria; reg en campo reg, mem en r/m. */
    if (dst.kind == MOperandKind::MEM && src.kind == MOperandKind::REG) {
        const uint8_t base = dst.reg;
        const uint8_t index = static_cast<uint8_t>(dst.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex =
            rex_byte(true, src.reg, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        put8(out, 0x85);
        emit_modrm_mem(dst, src.reg & 7, out);
        return;
    }
    put8(out, 0xCC);
}

/* ===================================================================== */
/* SETcc / CMOVcc                                                          */
/* ===================================================================== */

void X86Encoder::emit_setcc(MFunction & /*fn*/, const MInstr &mi,
                            std::vector<uint8_t> &out) {
    const MOperand &dst = mi.dst;
    const MCond cc = static_cast<MCond>(mi.variant);
    /* SETcc m8 (destino en memoria: el bool vive en un slot de derrame).
     * 0x0F 0x90+cc /0.  Sin REX.W (byte).  REX solo si base/index es r8-r15.
     * Escribe SOLO el byte bajo del slot; el caller (regalloc_rewrite) zerifica
     * el slot antes para que el valor de 8 bytes sea un 0/1 limpio. */
    if (dst.kind == MOperandKind::MEM) {
        const uint8_t base = dst.reg;
        const uint8_t index = static_cast<uint8_t>(dst.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex = rex_byte(false, 0, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        put8(out, 0x0F);
        put8(out, 0x90 + static_cast<uint8_t>(cc));
        emit_modrm_mem(dst, 0, out); // campo reg = 0 (/0)
        return;
    }
    if (dst.kind != MOperandKind::REG) {
        put8(out, 0xCC);
        return;
    }
    /* SETcc r/m8: 0x0F 0x90+cc /0 -- NO REX.W (es 8-bit).  Pero si el
     * destino es SPL/BPL/SIL/DIL (4-7) hay que forzar REX, sino el
     * ensamblado escribe AH/CH/DH/BH en su lugar. */
    uint8_t rex = rex_byte(false, 0, dst.reg);
    if (rex == 0 && needs_rex_for_byte_reg(dst.reg)) rex = 0x40;
    if (rex) put8(out, rex);
    put8(out, 0x0F);
    put8(out, 0x90 + static_cast<uint8_t>(cc));
    put8(out, modrm(3, 0, dst.reg & 7));
}

void X86Encoder::emit_cmovcc(MFunction & /*fn*/, const MInstr &mi,
                             std::vector<uint8_t> &out) {
    const MOperand &dst = mi.dst;
    const MOperand &src = mi.src1;
    const MCond cc = static_cast<MCond>(mi.variant);
    if (dst.kind != MOperandKind::REG || src.kind != MOperandKind::REG) {
        put8(out, 0xCC);
        return;
    }
    /* CMOVcc r64, r/m64: REX.W + 0x0F 0x40+cc /r */
    const uint8_t rex = rex_byte(true, dst.reg, src.reg);
    if (rex) put8(out, rex);
    put8(out, 0x0F);
    put8(out, 0x40 + static_cast<uint8_t>(cc));
    put8(out, modrm(3, dst.reg & 7, src.reg & 7));
}

/* ===================================================================== */
/* JMP / Jcc / CALL (rel32)                                                */
/* ===================================================================== */

void X86Encoder::emit_jmp(MFunction &fn, const MInstr &mi,
                          std::vector<uint8_t> &out) {
    if (mi.src1.kind == MOperandKind::LABEL) {
        put8(out, 0xE9);
        const uint32_t patch_at = static_cast<uint32_t>(out.size());
        put32(out, 0); /* placeholder rel32 */
        const uint32_t instr_end = static_cast<uint32_t>(out.size());
        fn.fixups.push_back(MFixup{static_cast<MLabelId>(mi.src1.value),
                                   patch_at, instr_end, 4});
        return;
    }
    /* JMP a una direccion ABSOLUTA que se conoce: E9 + relativo de 32 bits,
     * cinco bytes, sin gastar un registro y con el destino a la vista del
     * predictor de saltos.  La distancia no se sabe aqui -- se codifica antes
     * de pedir sitio en la cima de codigo --, asi que se deja el hueco y lo
     * rellena quien ya tiene la direccion.  Ver @c MFunction::rel_jump_fixups,
     * que explica tambien que pasa si no cabe. */
    if (mi.src1.kind == MOperandKind::IMM64_IDX) {
        const uint32_t idx = static_cast<uint32_t>(mi.src1.value);
        if (idx < fn.imm64_pool.size()) {
            put8(out, 0xE9);
            const uint32_t patch_at = static_cast<uint32_t>(out.size());
            put32(out, 0); /* hueco para el relativo */
            const uint32_t instr_end = static_cast<uint32_t>(out.size());
            fn.rel_jump_fixups.push_back(
                MFunction::RelJumpFixup{patch_at, instr_end,
                                        fn.imm64_pool[idx]});
            return;
        }
    }
    /* JMP reg INDIRECTO: FF /4 (mod=11).  Usado por el frame-swap del OSR
     * (salto C1->C2 a una direccion absoluta en un registro).  Mismo patron
     * que CALL reg (FF /2) pero con el campo reg del ModRM = 4. */
    if (mi.src1.kind == MOperandKind::REG) {
        const uint8_t rex = rex_byte(false, 0, mi.src1.reg);
        if (rex) put8(out, rex);
        put8(out, 0xFF);
        put8(out, modrm(3, 4, mi.src1.reg & 7));
        return;
    }
    /* JMP mem INDIRECTO: FF /4 con un operando de memoria. */
    if (mi.src1.kind == MOperandKind::MEM) {
        const uint8_t base = mi.src1.reg;
        const uint8_t index = static_cast<uint8_t>(mi.src1.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex = rex_byte(false, 0, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        put8(out, 0xFF);
        emit_modrm_mem(mi.src1, 4, out);
        return;
    }
    put8(out, 0xCC);
}

void X86Encoder::emit_jcc(MFunction &fn, const MInstr &mi,
                          std::vector<uint8_t> &out) {
    if (mi.src1.kind != MOperandKind::LABEL) {
        put8(out, 0xCC);
        return;
    }
    const MCond cc = static_cast<MCond>(mi.variant);
    put8(out, 0x0F);
    put8(out, jcc_long_opcode(cc));
    const uint32_t patch_at = static_cast<uint32_t>(out.size());
    put32(out, 0);
    const uint32_t instr_end = static_cast<uint32_t>(out.size());
    fn.fixups.push_back(
        MFixup{static_cast<MLabelId>(mi.src1.value), patch_at, instr_end, 4});
}

void X86Encoder::emit_call(MFunction &fn, const MInstr &mi,
                           std::vector<uint8_t> &out) {
    if (mi.src1.kind == MOperandKind::LABEL) {
        put8(out, 0xE8);
        const uint32_t patch_at = static_cast<uint32_t>(out.size());
        put32(out, 0);
        const uint32_t instr_end = static_cast<uint32_t>(out.size());
        fn.fixups.push_back(MFixup{static_cast<MLabelId>(mi.src1.value),
                                   patch_at, instr_end, 4});
        return;
    }
    /* CALL reg/mem: FF /2 */
    if (mi.src1.kind == MOperandKind::REG) {
        const uint8_t rex = rex_byte(false, 0, mi.src1.reg);
        if (rex) put8(out, rex);
        put8(out, 0xFF);
        put8(out, modrm(3, 2, mi.src1.reg & 7));
        return;
    }
    if (mi.src1.kind == MOperandKind::MEM) {
        const uint8_t base = mi.src1.reg;
        const uint8_t index = static_cast<uint8_t>(mi.src1.mem_index());
        const bool has_index = (index != static_cast<uint8_t>(MReg::NONE));
        const uint8_t rex = rex_byte(false, 0, base, has_index ? index : 0);
        if (rex) put8(out, rex);
        put8(out, 0xFF);
        emit_modrm_mem(mi.src1, 2, out);
        return;
    }
    put8(out, 0xCC);
}

/* ===================================================================== */
/* RET / PUSH / POP                                                       */
/* ===================================================================== */

void X86Encoder::emit_ret(std::vector<uint8_t> &out) {
    put8(out, 0xC3);
}

void X86Encoder::emit_push(const MInstr &mi, std::vector<uint8_t> &out) {
    if (mi.src1.kind == MOperandKind::REG) {
        const uint8_t r = mi.src1.reg;
        if (r & 0x8) put8(out, 0x41); /* REX.B para R8..R15 */
        put8(out, 0x50 + (r & 7));
        return;
    }
    /* PUSH imm32: 0x68 + imm32 (sign-ext a 64) */
    if (mi.src1.kind == MOperandKind::IMM32) {
        if (mi.src1.value >= -128 && mi.src1.value <= 127) {
            put8(out, 0x6A);
            put8(out, static_cast<uint8_t>(mi.src1.value & 0xFF));
        } else {
            put8(out, 0x68);
            put32(out, static_cast<uint32_t>(mi.src1.value));
        }
        return;
    }
    put8(out, 0xCC);
}

void X86Encoder::emit_pop(const MInstr &mi, std::vector<uint8_t> &out) {
    if (mi.dst.kind == MOperandKind::REG) {
        const uint8_t r = mi.dst.reg;
        if (r & 0x8) put8(out, 0x41);
        put8(out, 0x58 + (r & 7));
        return;
    }
    put8(out, 0xCC);
}

/* ===================================================================== */
/* emit_modrm_mem (ModR/M + SIB? + disp para operandos MEM)                */
/* ===================================================================== */

void X86Encoder::emit_modrm_mem(const MOperand &mem, uint8_t reg_field,
                                std::vector<uint8_t> &out) {
    const uint8_t base = mem.reg;
    const MReg idx = mem.mem_index();
    const uint8_t scale = mem.mem_scale();
    const int32_t disp = mem.mem_disp();
    const bool has_index = (idx != MReg::NONE);

    /* scale_bits: 1->0, 2->1, 4->2, 8->3 */
    uint8_t scale_bits = 0;
    switch (scale) {
    case 1: scale_bits = 0; break;
    case 2: scale_bits = 1; break;
    case 4: scale_bits = 2; break;
    case 8: scale_bits = 3; break;
    }

    const uint8_t base_3 = base & 7;
    const uint8_t reg_3 = reg_field & 7;

    /* Decidir mod segun disp + casos especiales:
     *   mod=00 si disp==0 y base != RBP (5) y base != R13 (13)
     *   mod=01 si disp cabe en int8
     *   mod=10 si disp es int32 */
    uint8_t mod = 0;
    bool emit_disp8 = false;
    bool emit_disp32 = false;
    if (disp == 0 && base_3 != 5) {
        mod = 0;
    } else if (disp >= -128 && disp <= 127) {
        mod = 1;
        emit_disp8 = true;
    } else {
        mod = 2;
        emit_disp32 = true;
    }

    /* Si hay index O si base es RSP (4) o R12 (12 & 7 == 4), debemos
     * usar SIB. */
    const bool needs_sib = has_index || base_3 == 4;

    if (needs_sib) {
        put8(out, modrm(mod, reg_3, 4)); /* r/m = 4 -> SIB sigue */
        const uint8_t idx_3 = has_index ? (static_cast<uint8_t>(idx) & 7) : 4;
        /* SIB con index=4 = no-index */
        put8(out, sib(scale_bits, idx_3, base_3));
    } else {
        put8(out, modrm(mod, reg_3, base_3));
    }

    if (emit_disp8) {
        put8(out, static_cast<uint8_t>(disp & 0xFF));
    } else if (emit_disp32) {
        put32(out, static_cast<uint32_t>(disp));
    } else if (mod == 0 && base_3 == 5) {
        /* base = RBP / R13 -> disp32 forzado por encoding */
        put32(out, 0);
    }
}

/* ===================================================================== */
/* resolve_fixups                                                          */
/* ===================================================================== */

void X86Encoder::resolve_fixups(MFunction &fn, std::vector<uint8_t> &out,
                                size_t base) {
    for (const auto &fx : fn.fixups) {
        if (fx.label_id >= fn.label_offsets.size()) continue;
        const uint32_t target_off = fn.label_offsets[fx.label_id];
        if (target_off == UINT32_MAX) continue; /* unresolved (bug) */
        const int64_t rel = static_cast<int64_t>(target_off) -
                            static_cast<int64_t>(fx.instr_end);
        /* Comprobar rango int32. */
        if (rel < INT32_MIN || rel > INT32_MAX) continue;
        const uint32_t rel32 = static_cast<uint32_t>(static_cast<int32_t>(rel));
        const size_t at = base + fx.patch_at;
        out[at] = static_cast<uint8_t>(rel32);
        out[at + 1] = static_cast<uint8_t>(rel32 >> 8);
        out[at + 2] = static_cast<uint8_t>(rel32 >> 16);
        out[at + 3] = static_cast<uint8_t>(rel32 >> 24);
    }
}

} // namespace jit
