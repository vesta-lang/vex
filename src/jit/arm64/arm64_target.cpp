/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file jit/arm64/arm64_target.cpp
 * @brief @ref Arm64Target: backend AArch64 por el pipeline vreg.  Subset entero
 *        (const/mov/ALU/cmp/branches/ret/params/call).  select emite MachineIR
 *        de vregs (AAPCS64); rewrite baja a fisico con prologo/epilogo/spills;
 *        encode produce AArch64 (Keystone) + relocs CALL26 (via Capstone).
 */

#include "util/env_flags.h"
#include "jit/arm64/arm64_target.h"

#include "ir/ssa_ir.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include "vx/asm/asm_backend.h"

#include <capstone/capstone.h>

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>

namespace jit {

namespace {

/* Ids arm64 (mismos que build_arm64_target): x0-x30 = 0-30, sp = 31. */
constexpr uint8_t A64_SP_ID = 31;

/// MOperand de un registro FISICO arm64 (id 0-30 GP / 32-63 FP).
MOperand a64_reg(uint8_t id, uint8_t w = 8) {
    MOperand o;
    o.kind = MOperandKind::REG;
    o.reg = id;
    o.width = w;
    return o;
}

/// Nombre AArch64 de un registro fisico segun ancho.
std::string a64_name(uint8_t id, uint8_t w) {
    if (id == A64_SP_ID) return w == 4 ? "wsp" : "sp";
    if (id <= 30) return (w == 4 ? "w" : "x") + std::to_string(id);
    // FP/SIMD v0-v31 (id 32-63).
    const int n = id - 32;
    if (w == 4) return "s" + std::to_string(n);
    if (w == 16) return "q" + std::to_string(n);
    return "d" + std::to_string(n);
}

/// ¿El tipo IR es float?
bool ir_is_float(ir::IrType t) {
    return t == ir::IrType::F32 || t == ir::IrType::F64;
}

/// ¿El tipo IR entero es con signo? (I8..I64).
/* El signo y el ancho en bytes los contesta el vocabulario unico
 * (ir/ir_type_info.h).  El signo se decidia aqui comparando el VALOR numerico
 * del enum (`t >= I8 && t <= I64`), que ademas de repetir la tabla se rompia
 * en silencio si alguien reordenaba IrType o metia un tipo entre medias. */
bool ir_signed(ir::IrType t) {
    return ir::type_is_signed(t);
}

/// IrOp ALU entero -> MOp (3-operandos; el encoder arm64 lo traduce).
bool alu_mop(ir::IrOp op, MOp &out) {
    switch (op) {
    case ir::IrOp::ADD: out = MOp::ADD; return true;
    case ir::IrOp::SUB: out = MOp::SUB; return true;
    case ir::IrOp::MUL: out = MOp::IMUL; return true; // -> mul
    case ir::IrOp::AND: out = MOp::AND; return true;
    case ir::IrOp::OR: out = MOp::OR; return true;   // -> orr
    case ir::IrOp::XOR: out = MOp::XOR; return true; // -> eor
    case ir::IrOp::SHL: out = MOp::SHL; return true; // -> lsl
    case ir::IrOp::SHR: out = MOp::SHR; return true; // -> lsr
    case ir::IrOp::SAR: out = MOp::SAR; return true; // -> asr
    default: return false;
    }
}

/// IrOp de comparacion -> condicion AArch64 (para cset / b.cond).
const char *cmp_cc(ir::IrOp op) {
    switch (op) {
    case ir::IrOp::CMP_EQ: return "eq";
    case ir::IrOp::CMP_NE: return "ne";
    case ir::IrOp::CMP_LT: return "lt";
    case ir::IrOp::CMP_GT: return "gt";
    case ir::IrOp::CMP_LE: return "le";
    case ir::IrOp::CMP_GE: return "ge";
    case ir::IrOp::CMP_ULT: return "lo";
    case ir::IrOp::CMP_UGT: return "hi";
    case ir::IrOp::CMP_ULE: return "ls";
    case ir::IrOp::CMP_UGE: return "hs";
    default: return "al";
    }
}

/// Guarda la condicion de un CMP/CSET/BR_COND en MInstr::flags (indice de cc).
uint8_t cc_index(ir::IrOp op) {
    switch (op) {
    case ir::IrOp::CMP_EQ: return 0;
    case ir::IrOp::CMP_NE: return 1;
    case ir::IrOp::CMP_LT: return 2;
    case ir::IrOp::CMP_GT: return 3;
    case ir::IrOp::CMP_LE: return 4;
    case ir::IrOp::CMP_GE: return 5;
    case ir::IrOp::CMP_ULT: return 6;
    case ir::IrOp::CMP_UGT: return 7;
    case ir::IrOp::CMP_ULE: return 8;
    case ir::IrOp::CMP_UGE: return 9;
    default: return 0;
    }
}
const char *cc_by_index(uint8_t i) {
    // 0-9: enteros.  10-15: float (fcmp ordered): eq/ne/mi(lt)/gt/ls(le)/ge.
    static const char *t[] = {"eq", "ne", "lt", "gt", "le", "ge", "lo", "hi",
                              "ls", "hs", "eq", "ne", "mi", "gt", "ls", "ge"};
    return i < 16 ? t[i] : "al";
}

/// Indice de condicion float (fcmp ordered) para el cset (10..15).
uint8_t fcc_index(ir::IrOp op) {
    switch (op) {
    case ir::IrOp::FCMP_EQ: return 10;
    case ir::IrOp::FCMP_NE: return 11;
    case ir::IrOp::FCMP_LT: return 12;
    case ir::IrOp::FCMP_GT: return 13;
    case ir::IrOp::FCMP_LE: return 14;
    case ir::IrOp::FCMP_GE: return 15;
    default: return 10;
    }
}

/// vreg de un IrValueId con la clase (FP para floats) y ancho de su tipo.
MOperand vr(const ir::IrFunction &fn, ir::IrValueId v) {
    const bool isf = v < fn.values.size() && ir_is_float(fn.values[v].type);
    const uint8_t w =
        v < fn.values.size()
            ? static_cast<uint8_t>(ir::type_access_bytes(fn.values[v].type))
            : 8;
    return MOperand::make_vreg(static_cast<uint32_t>(v),
                               isf ? RegClass::FP : RegClass::GP, w);
}

/// Copias de PHI en la arista bb -> target (una MOV por phi-arg).
void emit_phi_copies(std::vector<MInstr> &out, const ir::IrFunction &fn,
                     ir::IrBlockId from, ir::IrBlockId to) {
    if (to >= fn.blocks.size()) return;
    for (const ir::IrInstr &in : fn.blocks[to].instrs) {
        if (in.op != ir::IrOp::PHI) continue;
        for (const ir::IrPhiArg &pa : in.phi_args)
            if (pa.block == from)
                out.push_back(MInstr::make_unary(MOp::MOV, vr(fn, in.dst),
                                                 vr(fn, pa.value)));
    }
}

} // namespace

// ---------------------------------------------------------------------------
// SELECT: IR (SSA) -> MachineIR de vregs (AAPCS64)
// ---------------------------------------------------------------------------
bool Arm64Target::select(const ir::IrFunction &fn, MFunction &out) const {
    if (fn.blocks.empty()) return false;

    out = MFunction();
    out.vreg_count = static_cast<uint32_t>(fn.values.size());
    out.blocks.resize(fn.blocks.size());
    uint32_t syn_lbl = 0; // labels sinteticos de BR_COND (.Ls<n>)

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const ir::IrBlock &bb = fn.blocks[bi];
        std::vector<MInstr> &O = out.blocks[bi].instrs;

        // Bloque 0: cargar params desde los arg-regs AAPCS64 (x0-x7).
        if (bi == 0) {
            for (size_t i = 0; i < fn.params.size() && i < 8; ++i)
                O.push_back(
                    MInstr::make_unary(MOp::MOV, vr(fn, fn.params[i]),
                                       a64_reg(static_cast<uint8_t>(i))));
        }

        for (const ir::IrInstr &in : bb.instrs) {
            switch (in.op) {
            case ir::IrOp::PHI:
                break; // resuelto por copias en los predecesores.
            case ir::IrOp::CONST: {
                // MOV vreg, imm64 (el encoder materializa movz/movk).  El
                // inmediato viaja por el imm64_pool.
                MOperand imm;
                imm.kind = MOperandKind::IMM64_IDX;
                imm.value = static_cast<int32_t>(out.imm64_pool.size());
                out.imm64_pool.push_back(in.imm);
                O.push_back(MInstr::make_unary(MOp::MOV, vr(fn, in.dst), imm));
                break;
            }
            case ir::IrOp::MOV:
                if (in.operands.size() != 1) return false;
                O.push_back(MInstr::make_unary(MOp::MOV, vr(fn, in.dst),
                                               vr(fn, in.operands[0])));
                break;
            case ir::IrOp::NEG:
                if (in.operands.size() != 1) return false;
                O.push_back(MInstr::make_unary(MOp::NEG, vr(fn, in.dst),
                                               vr(fn, in.operands[0])));
                break;
            case ir::IrOp::NOT:
                if (in.operands.size() != 1) return false;
                O.push_back(MInstr::make_unary(MOp::NOT, vr(fn, in.dst),
                                               vr(fn, in.operands[0])));
                break;
            case ir::IrOp::ADD:
            case ir::IrOp::SUB:
            case ir::IrOp::MUL:
            case ir::IrOp::AND:
            case ir::IrOp::OR:
            case ir::IrOp::XOR:
            case ir::IrOp::SHL:
            case ir::IrOp::SHR:
            case ir::IrOp::SAR: {
                MOp mop;
                if (in.operands.size() != 2 || !alu_mop(in.op, mop))
                    return false;
                O.push_back(MInstr::make_binary(mop, vr(fn, in.dst),
                                                vr(fn, in.operands[0]),
                                                vr(fn, in.operands[1])));
                break;
            }
            case ir::IrOp::DIV: {
                if (in.operands.size() != 2) return false;
                const MOp d =
                    ir_signed(in.type) ? MOp::A64_SDIV : MOp::A64_UDIV;
                O.push_back(MInstr::make_binary(d, vr(fn, in.dst),
                                                vr(fn, in.operands[0]),
                                                vr(fn, in.operands[1])));
                break;
            }
            case ir::IrOp::MOD: {
                // mod = a - (a/b)*b (sin A64_MSUB, que necesitaria 4
                // operandos).
                if (in.operands.size() != 2) return false;
                const MOp d =
                    ir_signed(in.type) ? MOp::A64_SDIV : MOp::A64_UDIV;
                // Ancho de los temporales = ancho de la operacion (AArch64
                // exige que todos los operandos de sdiv/mul/sub sean w o x, no
                // mezclados).
                const uint8_t mw =
                    static_cast<uint8_t>(ir::type_access_bytes(in.type));
                const uint32_t q = out.vreg_count++; // cociente
                const uint32_t p = out.vreg_count++; // producto q*b
                MOperand qv = MOperand::make_vreg(q, RegClass::GP, mw);
                MOperand pv = MOperand::make_vreg(p, RegClass::GP, mw);
                O.push_back(MInstr::make_binary(d, qv, vr(fn, in.operands[0]),
                                                vr(fn, in.operands[1])));
                O.push_back(MInstr::make_binary(MOp::IMUL, pv, qv,
                                                vr(fn, in.operands[1])));
                O.push_back(MInstr::make_binary(MOp::SUB, vr(fn, in.dst),
                                                vr(fn, in.operands[0]), pv));
                break;
            }
            case ir::IrOp::SEXT:
            case ir::IrOp::ZEXT:
            case ir::IrOp::TRUNC:
            case ir::IrOp::CAST: {
                if (in.operands.size() != 1) return false;
                const ir::IrType st = fn.values[in.operands[0]].type;
                if (ir_is_float(st) || ir_is_float(in.type)) return false;
                // Extension/truncacion entera -> MOVSX/MOVZX con anchos (el
                // encoder emite sxt/uxt/mov segun src/dst).  El signo: SEXT o
                // CAST desde un tipo con signo (extension); TRUNC toma el signo
                // del tipo destino.
                const int sb = ir::type_access_bytes(st),
                          db = ir::type_access_bytes(in.type);
                bool sign;
                if (in.op == ir::IrOp::TRUNC || db < sb)
                    sign = ir_signed(in.type);
                else
                    sign = (in.op == ir::IrOp::SEXT) ||
                           (in.op == ir::IrOp::CAST && ir_signed(st));
                MInstr m =
                    MInstr::make_unary(sign ? MOp::MOVSX : MOp::MOVZX,
                                       vr(fn, in.dst), vr(fn, in.operands[0]));
                m.dst.width = static_cast<uint8_t>(db);
                m.src1.width = static_cast<uint8_t>(sb);
                O.push_back(m);
                break;
            }
            case ir::IrOp::ALLOCA:
                // Reserva de espacio en el frame; dst = puntero (host).  El
                // rewrite le asigna el offset y emite `add dst, sp, #off`.
                O.push_back(MInstr::make_alloca(vr(fn, in.dst),
                                                static_cast<uint32_t>(in.imm)));
                break;
            case ir::IrOp::LOAD: {
                // %dst = load %addr  (memoria host; ancho segun el tipo).
                if (in.operands.size() != 1) return false;
                const uint8_t w =
                    static_cast<uint8_t>(ir::type_access_bytes(in.type));
                O.push_back(MInstr::make_load(vr(fn, in.dst),
                                              vr(fn, in.operands[0]), w,
                                              ir_signed(in.type)));
                break;
            }
            case ir::IrOp::STORE: {
                // store %val, %addr  (operands[0]=val, operands[1]=addr).
                if (in.operands.size() != 2) return false;
                const ir::IrType vt = fn.values[in.operands[0]].type;
                const uint8_t w =
                    static_cast<uint8_t>(ir::type_access_bytes(vt));
                O.push_back(MInstr::make_store(vr(fn, in.operands[1]),
                                               vr(fn, in.operands[0]), w));
                break;
            }
            /* --- Float / SIMD escalar --- */
            case ir::IrOp::FADD:
            case ir::IrOp::FSUB:
            case ir::IrOp::FMUL:
            case ir::IrOp::FDIV: {
                if (in.operands.size() != 2) return false;
                const MOp m = in.op == ir::IrOp::FADD   ? MOp::A64_FADD
                              : in.op == ir::IrOp::FSUB ? MOp::A64_FSUB
                              : in.op == ir::IrOp::FMUL ? MOp::A64_FMUL
                                                        : MOp::A64_FDIV;
                O.push_back(MInstr::make_binary(m, vr(fn, in.dst),
                                                vr(fn, in.operands[0]),
                                                vr(fn, in.operands[1])));
                break;
            }
            case ir::IrOp::FNEG:
            case ir::IrOp::FABS:
            case ir::IrOp::FSQRT: {
                if (in.operands.size() != 1) return false;
                const MOp m = in.op == ir::IrOp::FNEG   ? MOp::A64_FNEG
                              : in.op == ir::IrOp::FABS ? MOp::A64_FABS
                                                        : MOp::A64_FSQRT;
                O.push_back(MInstr::make_unary(m, vr(fn, in.dst),
                                               vr(fn, in.operands[0])));
                break;
            }
            case ir::IrOp::FCMP_EQ:
            case ir::IrOp::FCMP_NE:
            case ir::IrOp::FCMP_LT:
            case ir::IrOp::FCMP_GT:
            case ir::IrOp::FCMP_LE:
            case ir::IrOp::FCMP_GE: {
                if (in.operands.size() != 2) return false;
                O.push_back(MInstr::make_binary(MOp::A64_FCMP, MOperand::none(),
                                                vr(fn, in.operands[0]),
                                                vr(fn, in.operands[1])));
                MInstr cset = MInstr::make_unary(MOp::A64_CSET, vr(fn, in.dst),
                                                 MOperand::none());
                cset.flags = fcc_index(in.op);
                O.push_back(cset);
                break;
            }
            case ir::IrOp::ITOF:
            case ir::IrOp::UITOF: {
                if (in.operands.size() != 1) return false;
                const MOp m =
                    in.op == ir::IrOp::ITOF ? MOp::A64_SCVTF : MOp::A64_UCVTF;
                O.push_back(MInstr::make_unary(m, vr(fn, in.dst),
                                               vr(fn, in.operands[0])));
                break;
            }
            case ir::IrOp::FTOI:
            case ir::IrOp::FTOUI: {
                if (in.operands.size() != 1) return false;
                const MOp m =
                    in.op == ir::IrOp::FTOI ? MOp::A64_FCVTZS : MOp::A64_FCVTZU;
                O.push_back(MInstr::make_unary(m, vr(fn, in.dst),
                                               vr(fn, in.operands[0])));
                break;
            }
            case ir::IrOp::F32TOF64:
            case ir::IrOp::F64TOF32:
                if (in.operands.size() != 1) return false;
                O.push_back(MInstr::make_unary(MOp::A64_FCVT, vr(fn, in.dst),
                                               vr(fn, in.operands[0])));
                break;
            case ir::IrOp::CMP_EQ:
            case ir::IrOp::CMP_NE:
            case ir::IrOp::CMP_LT:
            case ir::IrOp::CMP_GT:
            case ir::IrOp::CMP_LE:
            case ir::IrOp::CMP_GE:
            case ir::IrOp::CMP_ULT:
            case ir::IrOp::CMP_UGT:
            case ir::IrOp::CMP_ULE:
            case ir::IrOp::CMP_UGE: {
                if (in.operands.size() != 2) return false;
                // cmp a, b (sin dst) + cset dst, cc.
                MInstr cmp = MInstr::make_binary(MOp::CMP, MOperand::none(),
                                                 vr(fn, in.operands[0]),
                                                 vr(fn, in.operands[1]));
                O.push_back(cmp);
                MInstr cset = MInstr::make_unary(MOp::A64_CSET, vr(fn, in.dst),
                                                 MOperand::none());
                cset.flags = cc_index(in.op);
                O.push_back(cset);
                break;
            }
            case ir::IrOp::BR:
                emit_phi_copies(O, fn, static_cast<ir::IrBlockId>(bi),
                                in.target_block);
                O.push_back(MInstr::make_jmp(in.target_block));
                break;
            case ir::IrOp::BR_COND: {
                if (in.operands.size() != 1) return false;
                // Cada arista lleva SUS copias de PHI (correcto con o sin PHI):
                //   cbnz cond, .Ls_true
                //   <copias PHI del false> ; b false_block
                // .Ls_true:
                //   <copias PHI del true> ; b true_block
                const uint32_t ls = syn_lbl++;
                MInstr cbnz =
                    MInstr::make_unary(MOp::A64_CBNZ, MOperand::make_label(ls),
                                       vr(fn, in.operands[0]));
                O.push_back(cbnz);
                emit_phi_copies(O, fn, static_cast<ir::IrBlockId>(bi),
                                in.false_block);
                O.push_back(MInstr::make_jmp(in.false_block));
                O.push_back(MInstr::make_label_def(ls));
                emit_phi_copies(O, fn, static_cast<ir::IrBlockId>(bi),
                                in.target_block);
                O.push_back(MInstr::make_jmp(in.target_block));
                break;
            }
            case ir::IrOp::RET: {
                if (!in.operands.empty())
                    O.push_back(MInstr::make_unary(MOp::MOV, a64_reg(0),
                                                   vr(fn, in.operands[0])));
                O.push_back(MInstr::make_ret());
                break;
            }
            case ir::IrOp::CALL: {
                // Args -> x0..x7 ; bl <sym> ; dst <- x0.
                if (in.operands.size() > 8) return false;
                for (size_t i = 0; i < in.operands.size(); ++i)
                    O.push_back(MInstr::make_unary(
                        MOp::MOV, a64_reg(static_cast<uint8_t>(i)),
                        vr(fn, in.operands[i])));
                uint32_t sym = static_cast<uint32_t>(out.reloc_symbols.size());
                out.reloc_symbols.push_back(in.func_name);
                O.push_back(MInstr::make_call_sym(sym));
                if (in.dst != ir::IR_NO_VALUE)
                    O.push_back(MInstr::make_unary(MOp::MOV, vr(fn, in.dst),
                                                   a64_reg(0)));
                break;
            }
            default:
                if (util::flag_on(util::FlagId::Arm64Dump))
                    std::fprintf(stderr, "[arm64-vreg] op no soportado: %d\n",
                                 static_cast<int>(in.op));
                return false; // op fuera del subset entero -> fallback.
            }
        }
    }
    // Clase de cada vreg (FP para floats) -> el regalloc generico usa el pool
    // correcto.  Los temporales (>= fn.values.size()) son GP.
    out.vreg_class.assign(out.vreg_count, RegClass::GP);
    for (size_t v = 0; v < fn.values.size() && v < out.vreg_class.size(); ++v)
        if (ir_is_float(fn.values[v].type)) out.vreg_class[v] = RegClass::FP;

    // CFG de los MBlock (succ_a/succ_b): imprescindible para que el regalloc
    // generico calcule la liveness cross-block (loops).  MBlock index = IR
    // block id.
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        out.blocks[bi].label_id = static_cast<MLabelId>(bi);
        const std::vector<ir::IrBlockId> &succs = fn.blocks[bi].succs;
        if (succs.size() >= 1)
            out.blocks[bi].succ_a = static_cast<MBlockId>(succs[0]);
        if (succs.size() >= 2)
            out.blocks[bi].succ_b = static_cast<MBlockId>(succs[1]);
    }
    if (util::flag_on(util::FlagId::Arm64Dump))
        std::fprintf(stderr, "[arm64-vreg] select OK %s\n", fn.name.c_str());
    return true;
}

// ---------------------------------------------------------------------------
// REWRITE: vreg -> fisico + prologo/epilogo AAPCS64 + spills
// ---------------------------------------------------------------------------
namespace {

/// Sustituye un operando VREG por su registro fisico (o UINT8_MAX si spill).
MOperand phys_of(const MOperand &o, const codegen::RegAlloc &ra, bool &is_spill,
                 uint32_t &slot) {
    is_spill = false;
    if (o.kind != MOperandKind::VREG) return o;
    const uint32_t v = o.vreg_id();
    if (ra.in_reg(v)) return a64_reg(ra.reg_of(v), o.width);
    if (ra.spilled(v)) {
        is_spill = true;
        slot = ra.slot_of(v);
    }
    return o; // el llamador materializa el spill via scratch.
}

/// ldr/str de un spill slot: MInstr LOAD/STORE con MEM [sp, #off].
MOperand spill_mem(uint32_t slot, int32_t spill_base) {
    return MOperand::make_mem(static_cast<MReg>(A64_SP_ID),
                              spill_base + static_cast<int32_t>(slot) * 8);
}

} // namespace

MFunction Arm64Target::rewrite(const MFunction &vf, const codegen::RegAlloc &ra,
                               const IntervalResult &ivs) const {
    (void)ivs;
    MFunction pf = vf; // copia estructura (imm64_pool, reloc_symbols)
    for (MBlock &b : pf.blocks)
        b.instrs.clear();

    // ¿Hay CALL? -> hay que salvar x30 (LR).  Registros callee-saved usados.
    bool has_call = false;
    for (const MBlock &b : vf.blocks)
        for (const MInstr &mi : b.instrs)
            if (mi.op == MOp::CALL_SYM) has_call = true;

    // Layout del marco: [callee-saved... | x30 | spills].  Todo en 8B,
    // marco 16.
    std::vector<uint8_t> saved = ra.callee_saved_used;
    if (has_call) saved.push_back(30); // x30 = LR
    const int32_t saved_bytes = static_cast<int32_t>(saved.size()) * 8;
    // Area de ALLOCAs: asigna a cada ALLOCA un offset (8-aligned) en el frame.
    std::unordered_map<uint32_t, int32_t> alloca_off; // vreg dst -> offset
    int32_t alloca_bytes = 0;
    for (const MBlock &b : vf.blocks)
        for (const MInstr &mi : b.instrs)
            if (mi.op == MOp::ALLOCA && mi.dst.kind == MOperandKind::VREG) {
                int32_t sz = mi.src1.value > 0 ? mi.src1.value : 8;
                sz = (sz + 7) & ~7;
                alloca_off[mi.dst.vreg_id()] = saved_bytes + alloca_bytes;
                alloca_bytes += sz;
            }
    const int32_t spill_bytes = static_cast<int32_t>(ra.num_spill_slots) * 8;
    const int32_t spill_base = saved_bytes + alloca_bytes; // spills al final
    int32_t frame = saved_bytes + alloca_bytes + spill_bytes;
    frame = (frame + 15) & ~15; // alineado a 16

    // Prologo (bloque 0): sub sp + str de cada callee-saved/x30.
    std::vector<MInstr> &B0 = pf.blocks[0].instrs;
    auto emit_frame_save = [&](std::vector<MInstr> &O) {
        if (frame == 0) return;
        MOperand fimm;
        fimm.kind = MOperandKind::IMM32;
        fimm.value = frame;
        O.push_back(MInstr::make_binary(MOp::SUB, a64_reg(A64_SP_ID),
                                        a64_reg(A64_SP_ID), fimm));
        for (size_t i = 0; i < saved.size(); ++i)
            O.push_back(MInstr::make_store(
                MOperand::make_mem(static_cast<MReg>(A64_SP_ID),
                                   static_cast<int32_t>(i) * 8),
                a64_reg(saved[i]), 8));
    };
    auto emit_frame_restore = [&](std::vector<MInstr> &O) {
        if (frame == 0) return;
        for (size_t i = 0; i < saved.size(); ++i)
            O.push_back(MInstr::make_load(
                a64_reg(saved[i]),
                MOperand::make_mem(static_cast<MReg>(A64_SP_ID),
                                   static_cast<int32_t>(i) * 8),
                8, false));
        MOperand fimm;
        fimm.kind = MOperandKind::IMM32;
        fimm.value = frame;
        O.push_back(MInstr::make_binary(MOp::ADD, a64_reg(A64_SP_ID),
                                        a64_reg(A64_SP_ID), fimm));
    };

    for (size_t bi = 0; bi < vf.blocks.size(); ++bi) {
        std::vector<MInstr> &O = pf.blocks[bi].instrs;
        if (bi == 0) emit_frame_save(O);

        for (const MInstr &mi : vf.blocks[bi].instrs) {
            // El RET lleva epilogo delante.
            if (mi.op == MOp::RET) {
                emit_frame_restore(O);
                O.push_back(mi);
                continue;
            }
            // ALLOCA -> add dst, sp, #off (dst = puntero al slot del frame).
            if (mi.op == MOp::ALLOCA && mi.dst.kind == MOperandKind::VREG) {
                bool sd0 = false;
                uint32_t ds0 = 0;
                const MOperand d = phys_of(mi.dst, ra, sd0, ds0);
                const int32_t off = alloca_off[mi.dst.vreg_id()];
                MOperand imm;
                imm.kind = MOperandKind::IMM32;
                imm.value = off;
                MOperand dreg = sd0 ? a64_reg(A64_X16) : d;
                O.push_back(MInstr::make_binary(MOp::ADD, dreg,
                                                a64_reg(A64_SP_ID), imm));
                if (sd0)
                    O.push_back(MInstr::make_store(spill_mem(ds0, spill_base),
                                                   a64_reg(A64_X16), 8));
                continue;
            }
            MInstr m = mi;
            // Sustituye dst/src1/src2; los spills se resuelven con x16/x17.
            bool sd = false, s1 = false, s2 = false;
            uint32_t dslot = 0, slot1 = 0, slot2 = 0;
            const MOperand nd = phys_of(mi.dst, ra, sd, dslot);
            const MOperand n1 = phys_of(mi.src1, ra, s1, slot1);
            const MOperand n2 = phys_of(mi.src2, ra, s2, slot2);
            // Cargar sources spilled a scratch ANTES.
            MOperand rs1 = n1, rs2 = n2, rd = nd;
            if (s1) {
                O.push_back(MInstr::make_load(
                    a64_reg(A64_X16), spill_mem(slot1, spill_base), 8, false));
                rs1 = a64_reg(A64_X16, mi.src1.width);
            }
            if (s2) {
                O.push_back(MInstr::make_load(
                    a64_reg(A64_X17), spill_mem(slot2, spill_base), 8, false));
                rs2 = a64_reg(A64_X17, mi.src2.width);
            }
            if (sd) rd = a64_reg(A64_X16, mi.dst.width);
            m.dst = rd;
            m.src1 = rs1;
            m.src2 = rs2;
            O.push_back(m);
            // Guardar dst spilled DESPUES.
            if (sd)
                O.push_back(MInstr::make_store(spill_mem(dslot, spill_base),
                                               a64_reg(A64_X16, mi.dst.width),
                                               8));
        }
    }
    (void)B0;
    return pf;
}

// ---------------------------------------------------------------------------
// ENCODE: MachineIR fisico -> AArch64 (Keystone) + relocs CALL26 (Capstone)
// ---------------------------------------------------------------------------
int Arm64Target::encode(MFunction &pf, std::vector<uint8_t> &out) const {
    std::ostringstream os;
    std::vector<uint32_t>
        call_syms; // sym_idx por cada `bl` en orden de emision

    auto rn = [](const MOperand &o) { return a64_name(o.reg, o.width); };

    for (size_t bi = 0; bi < pf.blocks.size(); ++bi) {
        os << ".Lb" << bi << ":\n";
        for (const MInstr &mi : pf.blocks[bi].instrs) {
            switch (mi.op) {
            case MOp::MOV: {
                const bool dst_fp = mi.dst.reg >= 32 && mi.dst.reg <= 63;
                if (mi.src1.kind == MOperandKind::IMM64_IDX) {
                    const uint64_t imm =
                        pf.imm64_pool[static_cast<size_t>(mi.src1.value)];
                    // Materializa los 64 bits en un GP; si el dst es FP, mueve
                    // los bits al registro d/s con fmov.
                    const std::string g =
                        dst_fp ? a64_name(A64_X16, 8) : rn(mi.dst);
                    os << "    movz " << g << ", #" << (imm & 0xffff) << "\n";
                    if ((imm >> 16) & 0xffff)
                        os << "    movk " << g << ", #"
                           << ((imm >> 16) & 0xffff) << ", lsl #16\n";
                    if ((imm >> 32) & 0xffff)
                        os << "    movk " << g << ", #"
                           << ((imm >> 32) & 0xffff) << ", lsl #32\n";
                    if ((imm >> 48) & 0xffff)
                        os << "    movk " << g << ", #"
                           << ((imm >> 48) & 0xffff) << ", lsl #48\n";
                    if (dst_fp)
                        os << "    fmov " << rn(mi.dst) << ", " << g << "\n";
                } else if (mi.src1.kind == MOperandKind::IMM32) {
                    os << "    mov " << rn(mi.dst) << ", #" << mi.src1.value
                       << "\n";
                } else {
                    const bool src_fp = mi.src1.reg >= 32 && mi.src1.reg <= 63;
                    os << "    " << ((dst_fp || src_fp) ? "fmov " : "mov ")
                       << rn(mi.dst) << ", " << rn(mi.src1) << "\n";
                }
                break;
            }
            case MOp::A64_FADD:
            case MOp::A64_FSUB:
            case MOp::A64_FMUL:
            case MOp::A64_FDIV: {
                const char *m = mi.op == MOp::A64_FADD   ? "fadd"
                                : mi.op == MOp::A64_FSUB ? "fsub"
                                : mi.op == MOp::A64_FMUL ? "fmul"
                                                         : "fdiv";
                os << "    " << m << " " << rn(mi.dst) << ", " << rn(mi.src1)
                   << ", " << rn(mi.src2) << "\n";
                break;
            }
            case MOp::A64_FNEG:
            case MOp::A64_FABS:
            case MOp::A64_FSQRT: {
                const char *m = mi.op == MOp::A64_FNEG   ? "fneg"
                                : mi.op == MOp::A64_FABS ? "fabs"
                                                         : "fsqrt";
                os << "    " << m << " " << rn(mi.dst) << ", " << rn(mi.src1)
                   << "\n";
                break;
            }
            case MOp::A64_FCMP:
                os << "    fcmp " << rn(mi.src1) << ", " << rn(mi.src2) << "\n";
                break;
            case MOp::A64_SCVTF:
            case MOp::A64_UCVTF:
                // int (GP) -> float (FP).  dst FP, src GP.
                os << "    " << (mi.op == MOp::A64_SCVTF ? "scvtf" : "ucvtf")
                   << " " << rn(mi.dst) << ", " << a64_name(mi.src1.reg, 8)
                   << "\n";
                break;
            case MOp::A64_FCVTZS:
            case MOp::A64_FCVTZU:
                // float (FP) -> int (GP), truncando.  dst GP, src FP.
                os << "    " << (mi.op == MOp::A64_FCVTZS ? "fcvtzs" : "fcvtzu")
                   << " " << a64_name(mi.dst.reg, 8) << ", " << rn(mi.src1)
                   << "\n";
                break;
            case MOp::A64_FCVT:
                // Conversion de precision f32<->f64 (dst/src distinta anchura).
                os << "    fcvt " << rn(mi.dst) << ", " << rn(mi.src1) << "\n";
                break;
            case MOp::ADD:
            case MOp::SUB:
            case MOp::IMUL:
            case MOp::AND:
            case MOp::OR:
            case MOp::XOR:
            case MOp::SHL:
            case MOp::SHR:
            case MOp::SAR:
            case MOp::A64_UDIV:
            case MOp::A64_SDIV: {
                const char *mn = mi.op == MOp::ADD        ? "add"
                                 : mi.op == MOp::SUB      ? "sub"
                                 : mi.op == MOp::IMUL     ? "mul"
                                 : mi.op == MOp::AND      ? "and"
                                 : mi.op == MOp::OR       ? "orr"
                                 : mi.op == MOp::XOR      ? "eor"
                                 : mi.op == MOp::SHL      ? "lsl"
                                 : mi.op == MOp::SHR      ? "lsr"
                                 : mi.op == MOp::SAR      ? "asr"
                                 : mi.op == MOp::A64_UDIV ? "udiv"
                                                          : "sdiv";
                os << "    " << mn << " " << rn(mi.dst) << ", " << rn(mi.src1)
                   << ", ";
                if (mi.src2.kind == MOperandKind::IMM32)
                    os << "#" << mi.src2.value << "\n";
                else
                    os << rn(mi.src2) << "\n";
                break;
            }
            case MOp::NEG:
                os << "    neg " << rn(mi.dst) << ", " << rn(mi.src1) << "\n";
                break;
            case MOp::NOT:
                os << "    mvn " << rn(mi.dst) << ", " << rn(mi.src1) << "\n";
                break;
            case MOp::MOVSX:
            case MOp::MOVZX: {
                // Extension entera: sxt/uxt segun signo + ancho de la fuente.
                // El destino ancho es siempre x (64b); w para truncar a 32.
                const bool sign = mi.op == MOp::MOVSX;
                const int sb = mi.src1.width, db = mi.dst.width;
                const std::string d = a64_name(mi.dst.reg, db <= 4 ? 4 : 8);
                const std::string s = a64_name(mi.src1.reg, 4);
                if (db < sb) {
                    // Truncacion: quedarse con los db bytes bajos.
                    if (db == 4)
                        os << "    mov " << a64_name(mi.dst.reg, 4) << ", "
                           << a64_name(mi.src1.reg, 4) << "\n";
                    else if (db == 2)
                        os << "    " << (sign ? "sxth " : "uxth ") << d << ", "
                           << s << "\n";
                    else
                        os << "    " << (sign ? "sxtb " : "uxtb ") << d << ", "
                           << s << "\n";
                } else if (db > sb) {
                    if (sb == 1)
                        os << "    " << (sign ? "sxtb " : "uxtb ") << d << ", "
                           << s << "\n";
                    else if (sb == 2)
                        os << "    " << (sign ? "sxth " : "uxth ") << d << ", "
                           << s << "\n";
                    else // sb == 4
                        os << "    "
                           << (sign ? "sxtw " + a64_name(mi.dst.reg, 8) + ", " +
                                          s
                                    : "mov " + a64_name(mi.dst.reg, 4) + ", " +
                                          s)
                           << "\n";
                } else {
                    os << "    mov " << rn(mi.dst) << ", " << rn(mi.src1)
                       << "\n";
                }
                break;
            }
            case MOp::CMP:
                os << "    cmp " << rn(mi.src1) << ", " << rn(mi.src2) << "\n";
                break;
            case MOp::A64_CSET:
                os << "    cset " << rn(mi.dst) << ", "
                   << cc_by_index(static_cast<uint8_t>(mi.flags)) << "\n";
                break;
            case MOp::A64_CBNZ:
                os << "    cbnz " << rn(mi.src1) << ", .Ls" << mi.dst.value
                   << "\n";
                break;
            case MOp::A64_CBZ:
                os << "    cbz " << rn(mi.src1) << ", .Ls" << mi.dst.value
                   << "\n";
                break;
            case MOp::LABEL_DEF: os << ".Ls" << mi.src1.value << ":\n"; break;
            case MOp::JMP: os << "    b .Lb" << mi.src1.value << "\n"; break;
            case MOp::JCC:
                os << "    b." << cc_by_index(static_cast<uint8_t>(mi.variant))
                   << " .Lb" << mi.src1.value << "\n";
                break;
            case MOp::LOAD: {
                // dst = [addr].  addr en MEM [base,#disp] (spill) o en un REG.
                const int w = mi.flags >> 1; // (width<<1)|sgn
                const char *ld = w == 1 ? "ldrb" : w == 2 ? "ldrh" : "ldr";
                const std::string dst = a64_name(mi.dst.reg, w >= 8 ? 8 : 4);
                if (mi.src1.kind == MOperandKind::MEM)
                    os << "    " << ld << " " << dst << ", ["
                       << a64_name(mi.src1.reg, 8) << ", #" << mi.src1.value
                       << "]\n";
                else
                    os << "    " << ld << " " << dst << ", ["
                       << a64_name(mi.src1.reg, 8) << "]\n";
                break;
            }
            case MOp::STORE: {
                // [addr] = val.  src1 = addr (MEM o REG), src2 = val.
                const int w = mi.flags;
                const char *st = w == 1 ? "strb" : w == 2 ? "strh" : "str";
                const std::string val = a64_name(mi.src2.reg, w >= 8 ? 8 : 4);
                if (mi.src1.kind == MOperandKind::MEM)
                    os << "    " << st << " " << val << ", ["
                       << a64_name(mi.src1.reg, 8) << ", #" << mi.src1.value
                       << "]\n";
                else
                    os << "    " << st << " " << val << ", ["
                       << a64_name(mi.src1.reg, 8) << "]\n";
                break;
            }
            case MOp::CALL_SYM:
                call_syms.push_back(static_cast<uint32_t>(mi.src1.value));
                os << "    bl 0\n";
                break;
            case MOp::RET: os << "    ret\n"; break;
            default:
                if (util::flag_on(util::FlagId::Arm64Dump))
                    std::fprintf(stderr, "[arm64-vreg] ENCODE MOp no sop: %d\n",
                                 static_cast<int>(mi.op));
                return 0; // op no soportada por el encoder arm64
            }
        }
    }

    // Ensamblar el texto AArch64 con Keystone.
    if (util::flag_on(util::FlagId::Arm64Dump))
        std::fprintf(stderr, "---- asm arm64 ----\n%s-------------------\n",
                     os.str().c_str());
    if (!vx::g_asm_backend) return 0;
    const vx::AsmAssembleResult ar =
        vx::g_asm_backend->assemble(os.str(), vx::AsmArch::ARM64);
    if (!ar.ok || ar.bytes.empty()) return 0;
    out = ar.bytes;

    // Relocs CALL26: localizar cada `bl` con Capstone y emparejarlo, en orden,
    // con el sym_idx registrado en el select.
    if (!call_syms.empty()) {
        csh h;
        if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &h) == CS_ERR_OK) {
            cs_insn *insn = nullptr;
            const size_t n = cs_disasm(h, out.data(), out.size(), 0, 0, &insn);
            size_t ci = 0;
            for (size_t i = 0; i < n && ci < call_syms.size(); ++i) {
                if (insn[i].id != ARM64_INS_BL) continue;
                MReloc r;
                r.kind = MRelocKind::ARM64_CALL26;
                r.patch_at = static_cast<uint32_t>(insn[i].address);
                r.sym_idx = call_syms[ci++];
                pf.relocs.push_back(r);
            }
            if (insn) cs_free(insn, n);
            cs_close(&h);
        }
    }
    return static_cast<int>(out.size());
}

} // namespace jit
