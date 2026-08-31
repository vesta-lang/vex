/* * VestaVM -- core NEUTRO del lift de asm a IR-CFG (compartido por ISAs).
 * Copyright (C) 2026 David Lopez.T (DesmonHak).  GPLv2 + excepcion de runtime.
 */

/** @file vx/asm/asm_lift_core.h
 *  @brief Capa NEUTRA (independiente del ISA) del lift de asm a IR: emisores de
 *  IR genericos, utilidades de texto, el register-file + driver del CFG del asm
 *  a IR-CFG.  Cada frontend por-ISA (lift_x86, futuro lift_arm64) la reusa; el
 *  IR resultante es el mismo para todas las arquitecturas.  Header-only
 * (inline) para compartir sin dependencia de enlace. */
#ifndef VESTA_VX_ASM_ASM_LIFT_CORE_H
#define VESTA_VX_ASM_ASM_LIFT_CORE_H

#include "ir/ssa_ir.h"
#include "vx/asm/asm_cfg.h"
#include "vx/asm/asm_lift_general.h" // AsmBoundReg
#include "util/env_flags.h"          // el mando que hace hablar al elevado
#include <cstdio>

#include <cctype>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace vx {
namespace asmlift {

inline std::string trim(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a]))
        ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1]))
        --b;
    return s.substr(a, b - a);
}

/// Trocea una linea de asm en mnemonico + operandos (por comas).
inline void split_insn(const std::string &line, std::string &mnem,
                       std::vector<std::string> &ops) {
    mnem.clear();
    ops.clear();
    const std::string s = trim(line);
    size_t i = 0;
    while (i < s.size() && !std::isspace((unsigned char)s[i]))
        ++i;
    mnem = s.substr(0, i);
    for (char &c : mnem)
        c = (char)std::tolower((unsigned char)c);
    std::string rest = trim(s.substr(i));
    if (rest.empty()) return;
    size_t start = 0;
    for (size_t j = 0; j <= rest.size(); ++j)
        if (j == rest.size() || rest[j] == ',') {
            ops.push_back(trim(rest.substr(start, j - start)));
            start = j + 1;
        }
}

/// Divide el cuerpo en instrucciones, descartando comentarios (// ;) y labels.
inline std::vector<std::string> instructions(const std::string &body) {
    std::vector<std::string> out;
    std::string line;
    for (size_t i = 0; i <= body.size(); ++i) {
        if (i == body.size() || body[i] == '\n') {
            std::string l = line;
            line.clear();
            // Quitar comentario.
            size_t c = l.find("//");
            if (c != std::string::npos) l = l.substr(0, c);
            c = l.find(';');
            if (c != std::string::npos) l = l.substr(0, c);
            l = trim(l);
            if (l.empty()) continue;
            if (l.back() == ':') continue; // label
            out.push_back(l);
        } else {
            line += body[i];
        }
    }
    return out;
}

/// Intenta parsear un inmediato entero (dec/hex/negativo).  Los positivos usan
/// @c strtoull para cubrir el rango COMPLETO de 64 bits sin signo (p.ej. el
/// idioma @c mov @c rax,0xFFFFFFFFFFFFFFFF); @c strtoll lo saturaria a
/// @c INT64_MAX y produciria un valor equivocado.
inline bool parse_imm(const std::string &op, int64_t &out) {
    if (op.empty()) return false;
    char c0 = op[0];
    if (!(std::isdigit((unsigned char)c0) || c0 == '-' || c0 == '+'))
        return false;
    char *end = nullptr;
    if (c0 == '-') {
        const long long v = std::strtoll(op.c_str(), &end, 0);
        if (end == op.c_str() || (end && *end != '\0')) return false;
        out = (int64_t)v;
    } else {
        const unsigned long long v = std::strtoull(op.c_str(), &end, 0);
        if (end == op.c_str() || (end && *end != '\0')) return false;
        out = (int64_t)v; // reinterpretacion de bits (los backends usan u64)
    }
    return true;
}

/// Emisores IR minimos.
inline ir::IrValueId emit_const(ir::IrFunction &fn, uint32_t blk, int64_t v,
                                uint32_t line) {
    const ir::IrValueId d = fn.new_value(ir::IrType::I64);
    ir::IrInstr in{};
    in.op = ir::IrOp::CONST;
    in.type = ir::IrType::I64;
    in.dst = d;
    in.imm = (uint64_t)v;
    in.source_line = line;
    fn.append(blk, std::move(in));
    return d;
}

inline ir::IrValueId emit_bin(ir::IrFunction &fn, uint32_t blk, ir::IrOp op,
                              ir::IrValueId a, ir::IrValueId b, uint32_t line) {
    const ir::IrValueId d = fn.new_value(ir::IrType::I64);
    ir::IrInstr in{};
    in.op = op;
    in.type = ir::IrType::I64;
    in.dst = d;
    in.operands = {a, b};
    in.source_line = line;
    fn.append(blk, std::move(in));
    return d;
}

/** @brief Como @ref emit_bin pero con TIPO explicito (para DIV/MOD, donde el
 *  tipo -- I64 vs U64 -- decide con signo / sin signo). */
inline ir::IrValueId emit_bin_ty(ir::IrFunction &fn, uint32_t blk, ir::IrOp op,
                                 ir::IrValueId a, ir::IrValueId b,
                                 ir::IrType ty, uint32_t line) {
    const ir::IrValueId d = fn.new_value(ty);
    ir::IrInstr in{};
    in.op = op;
    in.type = ty;
    in.dst = d;
    in.operands = {a, b};
    in.source_line = line;
    fn.append(blk, std::move(in));
    return d;
}

inline ir::IrValueId emit_un(ir::IrFunction &fn, uint32_t blk, ir::IrOp op,
                             ir::IrValueId a, uint32_t line) {
    const ir::IrValueId d = fn.new_value(ir::IrType::I64);
    ir::IrInstr in{};
    in.op = op;
    in.type = ir::IrType::I64;
    in.dst = d;
    in.operands = {a};
    in.source_line = line;
    fn.append(blk, std::move(in));
    return d;
}

/// Tipo IR para un acceso a memoria de @p w bits.  Los LOAD usan el tipo SIN
/// signo (zero-extend, la semantica de un @c mov de x86 a un registro parcial);
/// los STORE solo miran el ANCHO.
inline ir::IrType mem_ty(int w, bool is_load) {
    switch (w) {
    case 8: return is_load ? ir::IrType::U8 : ir::IrType::I8;
    case 16: return is_load ? ir::IrType::U16 : ir::IrType::I16;
    case 32: return is_load ? ir::IrType::U32 : ir::IrType::I32;
    default: return ir::IrType::I64;
    }
}

/// LOAD de @p w bits desde @p addr, zero-extendido a I64.  @p host: si la
/// direccion apunta a memoria HOST (el IR emite @c movh/loadzh); un operando de
/// memoria de un asm inline es SIEMPRE host, un slot de variable (ALLOCA) es
/// VM.
inline ir::IrValueId emit_load(ir::IrFunction &fn, uint32_t blk,
                               ir::IrValueId addr, int w, bool host,
                               uint32_t line) {
    if (host) fn.values[addr].is_host_ptr = true; // el emitter mira el operando
    const ir::IrValueId d = fn.new_value(ir::IrType::I64);
    ir::IrInstr in{};
    in.op = ir::IrOp::LOAD;
    in.type = mem_ty(w, /*is_load=*/true);
    in.dst = d;
    in.operands = {addr};
    in.source_line = line;
    fn.append(blk, std::move(in));
    fn.values[d].is_host_ptr =
        false; // el valor cargado es un entero, no un ptr
    return d;
}

/// STORE de los @p w bits bajos de @p val en @p addr.  @p host: ver @c
/// emit_load.
inline void emit_store(ir::IrFunction &fn, uint32_t blk, ir::IrValueId val,
                       ir::IrValueId addr, int w, bool host, uint32_t line) {
    if (host) fn.values[addr].is_host_ptr = true;
    ir::IrInstr in{};
    in.op = ir::IrOp::STORE;
    in.type = mem_ty(w, /*is_load=*/false);
    in.operands = {val, addr};
    in.source_line = line;
    fn.append(blk, std::move(in));
}

/// Mascara de @p w bits bajos como u64 (w>=64 -> todos los bits).
inline uint64_t width_mask(int w) {
    return w >= 64 ? ~0ull : ((1ull << w) - 1ull);
}

/** @brief Estado NEUTRO del register-file durante el lift.  @c cur mapea el
 *  registro canonico a su valor SSA ACTUAL en el bloque; se vacia en cada
 *  frontera de bloque.  @c wrote son los registros LIGADOS escritos en el
 *  bloque actual (para volcarlos a su slot).  @c block es el bloque IR actual
 *  (mutable: cambia por bloque basico). */
struct LiftCtx {
    ir::IrFunction &fn;
    uint32_t &block; ///< alias al bloque IR actual del lifter (mutable)
    uint32_t line;
    const std::unordered_map<std::string, AsmBoundReg> &bound;
    std::unordered_map<std::string, ir::IrValueId> &cur;
    std::vector<std::string> &wrote;
};

/** @brief NEUTRO.  Vuelca a su slot cada registro LIGADO escrito en el bloque
 *  actual (flush del register-file en la frontera).  mem2reg lo promueve a
 *  SSA + PHI en los merges. */
inline void cfg_flush_block(LiftCtx &c) {
    for (const std::string &r : c.wrote) {
        auto b = c.bound.find(r);
        auto v = c.cur.find(r);
        if (b != c.bound.end() && v != c.cur.end()) {
            const bool host = c.fn.values[b->second.slot].is_host_ptr;
            emit_store(c.fn, c.block, v->second, b->second.slot,
                       b->second.width_bits, host, c.line);
        }
    }
}

/** @brief NEUTRO.  BR incondicional a @p target. */
inline void cfg_emit_br(LiftCtx &c, uint32_t target) {
    ir::IrInstr br{};
    br.op = ir::IrOp::BR;
    br.target_block = target;
    br.source_line = c.line;
    c.fn.append(c.block, std::move(br));
}

/** @brief NEUTRO.  BR_COND(@p cond) -> @p taken (cond!=0) / @p fallthrough. */
inline void cfg_emit_br_cond(LiftCtx &c, ir::IrValueId cond, uint32_t taken,
                             uint32_t fallthrough) {
    ir::IrInstr br{};
    br.op = ir::IrOp::BR_COND;
    br.operands = {cond};
    br.target_block = taken;
    br.false_block = fallthrough;
    br.source_line = c.line;
    c.fn.append(c.block, std::move(br));
}

/** @brief Hooks POR-ISA que el driver neutro del CFG invoca. */
struct CfgHooks {
    /// Lifta las instrucciones [from, to) (sin el terminador) en @c c.block.
    /// false = alguna no encaja -> se aborta el lift del bloque entero.
    std::function<bool(size_t from, size_t to)> lift_range;
    /// Para un bloque @c CondBranch: calcula la SSA de la condicion (0/1) a
    /// partir de su comparador + el sufijo del salto.  @c IR_NO_VALUE = bail.
    std::function<ir::IrValueId(const vx::AsmBasicBlock &)> branch_cond;
    /// indice de la primera instruccion del TERMINADOR del bloque (lo que NO
    /// se lifta como cuerpo).  Ej x86: CondBranch -> el cmp; Uncond -> el jmp;
    /// Fallthrough -> last+1 (no hay terminador, se lifta todo).
    std::function<uint32_t(const vx::AsmBasicBlock &)> term_start;
};

/** @brief NEUTRO.  Baja el CFG del asm a IR-CFG: un bloque IR por bloque
 * basico, register-file en slots (flush por bloque -> mem2reg hace el SSA+PHI),
 * y los terminadores como BR/BR_COND.  @p out_exit = bloque de continuacion
 * (donde sigue el codigo tras el asm).  @return false si algun bloque no lifta.
 */
inline bool cfg_give_up(const vx::AsmBasicBlock *bb, const char *why) {
    static const bool on = util::flag_on(util::FlagId::AsmLiftDebug);
    if (on) {
        std::fprintf(stderr, "[asm-lift] el grafo no se eleva: %s", why);
        if (bb != nullptr)
            std::fprintf(stderr, " (bloque %u..%u, %zu salidas)", bb->first,
                         bb->last, bb->succs.size());
        std::fprintf(stderr, "\n");
    }
    return false;
}

inline bool lift_cfg_neutral(LiftCtx &c, const vx::AsmCfg &cfg,
                             const CfgHooks &hooks, uint32_t &out_exit) {
    const size_t nb = cfg.blocks.size();
    if (nb == 0) return cfg_give_up(nullptr, "el asm no tiene ni un bloque");
    // Un bloque IR NUEVO por bloque basico.  El bloque de entrada actual NO se
    // reusa como BB0: si el asm tiene un back-edge al inicio (loop), reusar la
    // entrada re-ejecutaria el codigo previo (p.ej. la init de las variables)
    // en cada iteracion -> bucle infinito.  La entrada solo SALTA al primer BB.
    std::vector<uint32_t> irb(nb);
    for (size_t i = 0; i < nb; ++i)
        irb[i] = c.fn.new_block("asmbb" + std::to_string(i));
    const uint32_t cont = c.fn.new_block("asmcont");
    cfg_emit_br(c, irb[0]); // c.block (entrada) -> primer BB del asm

    for (size_t i = 0; i < nb; ++i) {
        const vx::AsmBasicBlock &bb = cfg.blocks[i];
        c.block = irb[i];
        c.cur.clear(); // register-file por bloque: cada uno recarga de su slot
        c.wrote.clear();
        if (!hooks.lift_range(bb.first, hooks.term_start(bb)))
            return cfg_give_up(&bb, "una instruccion del cuerpo no se pudo "
                                    "elevar");
        switch (bb.term) {
        case vx::AsmTerm::Fallthrough:
            cfg_flush_block(c);
            cfg_emit_br(c, (i + 1 < nb) ? irb[i + 1] : cont);
            break;
        case vx::AsmTerm::UncondJump:
            if (bb.succs.size() != 1)
                return cfg_give_up(&bb, "un salto incondicional que no lleva "
                                        "a UN solo sitio");
            cfg_flush_block(c);
            cfg_emit_br(c, irb[bb.succs[0]]);
            break;
        case vx::AsmTerm::CondBranch: {
            // succs[0] = si se toma, succs[1] = si se cae.
            if (bb.succs.size() != 2)
                return cfg_give_up(&bb, "un salto condicional que no tiene "
                                        "DOS salidas");
            const ir::IrValueId cond = hooks.branch_cond(bb);
            if (cond == ir::IR_NO_VALUE)
                return cfg_give_up(&bb, "no se supo que condicion mira el "
                                        "salto");
            cfg_flush_block(c); // tras calcular cond (usa cur) y antes de ramar
            cfg_emit_br_cond(c, cond, irb[bb.succs[0]], irb[bb.succs[1]]);
            break;
        }
        default:
            // Ret/Call/Indirect/Unknown: aun no se sabe elevarlos.
            return cfg_give_up(&bb, "el bloque acaba en algo que no es caer, "
                                    "saltar ni ramificar");
        }
    }
    c.block = cont;
    out_exit = cont;
    /* Y las ARISTAS, que hasta ahora no se ponian.
     *
     * Aqui se acaba de construir control de flujo: bloques nuevos con sus
     * saltos.  El terminador lo dice todo, pero `succs`/`preds` son lo que
     * camina cualquier analisis del grafo, y sin ellas el bucle que se acaba de
     * elevar queda INVISIBLE: el coste de una funcion cuyo cuerpo entero es ese
     * bucle salia O(1), sin un error, sin un aviso, solo una respuesta
     * tranquila y equivocada.  Se derivan de los terminadores en un solo sitio
     * en vez de escribirlas a mano aqui. */
    c.fn.recompute_edges();
    return true;
}

} // namespace asmlift
} // namespace vx

#endif // VESTA_VX_ASM_ASM_LIFT_CORE_H
