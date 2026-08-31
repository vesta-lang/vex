/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/peephole.cpp
 * @brief Implementacion del peephole sobre MachineIR fisico (ver peephole.h).
 */

#include "util/env_flags.h"
#include "jit/peephole.h"
#include "analysis/facts/phys_liveness.h" // diagnostico: ver el hecho en accion

#include <cstdio>
#include <string>

#include <cstdlib>
#include <cstring>
#include <vector>

namespace jit {

namespace {

bool peephole_disabled() noexcept {
    static const bool off = util::flag_on(util::FlagId::NoPeephole);
    return off;
}

/// Solo DICE que escrituras borraria la regla que no esta puesta, sin borrar
/// nada.  Es el instrumento para cerrarla: cada linea que imprime sobre un
/// programa que funciona es una escritura que el hecho da por muerta, y basta
/// con mirar UNA que no lo este para saber que fuente de liveness falta.
///
/// Filtra por NOMBRE de funcion, como @c VESTA_VREG_DUMP: sin filtro esto
/// imprime miles de lineas y no se lee.
bool deaddef_report(const std::string &fn) noexcept {
    const std::string &want = util::flag_text(util::FlagId::DeadDefReport);
    return !want.empty() && fn.find(want) != std::string::npos;
}

/// Desactiva SOLO el borrado de escrituras que nadie lee, dejando el resto
/// activo.  Sirve para separar en dos si algo sale mal: con esto puesto, lo que
/// siga fallando no es de esta regla.
bool deaddef_disabled() noexcept {
    static const bool off = util::flag_on(util::FlagId::NoDeadDef);
    return off;
}

/// Aplica la regla SOLO en las funciones cuyo nombre contenga esto.
///
/// Es el segundo instrumento, y el que cierra el circulo.  El informe dice que
/// SE BORRARIA; con esto se borra solo en una parte del programa y se bisecta
/// por NOMBRE hasta dar con la funcion en la que borrar cambia el resultado.
///
/// Se bisecta por nombre y no por un contador de borrados porque el JIT compila
/// desde varios hilos: un contador global sale distinto en cada ejecucion, asi
/// que el numero al que se llega bisecando no vuelve a senalar lo mismo.  El
/// nombre si es estable.
/// Se escribe `<parte del nombre>` o `<parte del nombre>#<bloque>`, y con el
/// bloque se llega hasta UN borrado concreto.
bool deaddef_only(const std::string &fn, size_t block) noexcept {
    const std::string &want = util::flag_text(util::FlagId::DeadDefOnly);
    if (want.empty()) return true;
    const size_t sep = want.find('#');
    const std::string name = want.substr(0, sep);
    if (!name.empty() && fn.find(name) == std::string::npos) return false;
    if (sep == std::string::npos) return true;
    return std::strtoul(want.c_str() + sep + 1, nullptr, 10) == block;
}

/// @brief Si @p in es una escritura que se puede borrar cuando nadie la lee.
///
/// El filtro es deliberadamente estrecho.  Solo un `mov` a un registro entero
/// de 64 bits desde algo que no es memoria:
///
///   - de MEMORIA no, porque leer una direccion puede fallar, y una lectura que
///     falla no es lo mismo que una que no hace falta;
///   - de menos de 64 bits no, porque escribir la parte baja deja el resto del
///     registro como estaba, asi que la escritura no es la unica duena de lo
///     que hay dentro;
///   - a memoria no (eso es un store, y quien lo lee no es un registro);
///   - y nada que toque las banderas, que se miran aparte y este predicado no
///     las mira.
///
/// Todo lo demas se queda.  Una regla que borra codigo tiene que equivocarse
/// hacia el lado de no borrar.
inline bool is_removable_def(const MInstr &in) noexcept {
    if (in.op != MOp::MOV) return false;
    if (in.dst.kind != MOperandKind::REG || in.dst.width != 8) return false;
    if (in.src2.kind != MOperandKind::NONE) return false;
    if (in.src1.kind == MOperandKind::MEM) return false;
    return in.src1.kind == MOperandKind::REG ||
           in.src1.kind == MOperandKind::IMM32 ||
           in.src1.kind == MOperandKind::IMM64_IDX;
}

/// Desactiva SOLO el idiom xor-zeroing (bisection), dejando el resto activo.
bool xorzero_disabled() noexcept {
    static const bool off = util::flag_on(util::FlagId::NoXorZero);
    return off;
}

/// True si @p op LEE los flags (su resultado depende de RFLAGS).  Solo
/// Jcc/SETcc/CMOVcc en el set actual (ADC/SBB/RCL/RCR no existen todavia).
bool mop_reads_flags(MOp op) noexcept {
    switch (op) {
    case MOp::JCC:
    case MOp::SETCC:
    case MOp::CMOVCC: return true;
    default: return false;
    }
}

/// True si @p op sobrescribe el conjunto COMPLETO de flags (CF/ZF/SF/OF/PF)
/// de forma incondicional -> mata cualquier valor previo.  Conservador: solo
/// las que garantizan escribir todos.  INC/DEC (no tocan CF), NOT (no toca
/// flags), ROL/ROR (solo CF/OF), IMUL/POPCNT/LZCNT/TZCNT (ZF parcial/undef) y
/// UCOMISD se tratan como NEUTRALES (se sigue escaneando) -> solo hace el
/// analisis MAS conservador, nunca menos, asi que es seguro.
bool mop_kills_all_flags(MOp op) noexcept {
    switch (op) {
    case MOp::ADD:
    case MOp::SUB:
    case MOp::CMP:
    case MOp::TEST:
    case MOp::AND:
    case MOp::OR:
    case MOp::XOR:
    case MOp::NEG:
    case MOp::SHL:
    case MOp::SHR:
    case MOp::SAR:
    case MOp::CALL:
    case MOp::CALL_ABS:
    case MOp::SAFEPOINT: /* expande a cmp byte[rbx],0 + jne -> clobbea flags */
        return true;
    default: return false;
    }
}

/// True si @p in es un `cmp reg, 0`.  `test reg, reg` pone EXACTAMENTE los
/// mismos 5 flags (CF=OF=0, ZF/SF/PF de reg) y es mas corto -> sustitucion
/// siempre segura para cualquier Jcc/SETcc posterior.  El encoder fuerza REX.W
/// en ambos, asi que la comparacion es de 64-bit en los dos casos.
bool is_cmp_zero(const MInstr &in) noexcept {
    return in.op == MOp::CMP && in.dst.kind == MOperandKind::REG &&
           in.src1.kind == MOperandKind::IMM32 && in.src1.value == 0;
}

/// True si @p in es un `mov reg, 0` (materializacion de cero en un GP).  Un
/// MOV con fuente inmediata siempre destina a un GP (no existe `mov xmm,imm`),
/// asi que no hay riesgo de tocar el banco flotante.
bool is_zero_mov(const MInstr &in) noexcept {
    return in.op == MOp::MOV && in.dst.kind == MOperandKind::REG &&
           in.src1.kind == MOperandKind::IMM32 && in.src1.value == 0 &&
           in.src2.kind == MOperandKind::NONE;
}

/// True si los flags estan MUERTOS justo despues del indice @p i del bloque
/// @p b: el primer uso relevante hacia adelante es un ESCRITOR completo (o se
/// alcanza el fin del bloque sin lectores, en cuyo caso -conservador- se
/// considera VIVO).  Habilita sustituir `mov reg,0` por `xor reg,reg` (que SI
/// escribe flags) sin corromper a un consumidor de flags posterior.
bool flags_dead_after(const MBlock &b, size_t i) noexcept {
    for (size_t j = i + 1; j < b.instrs.size(); ++j) {
        const MOp op = b.instrs[j].op;
        if (mop_reads_flags(op)) return false;    // lector primero -> VIVO
        if (mop_kills_all_flags(op)) return true; // escritor total -> MUERTO
        /* neutral -> seguir escaneando */
    }
    return false; // fin de bloque sin resolver -> conservador: VIVO
}

/// Desactiva SOLO la eliminacion de JMP-a-fallthrough (bisection).
bool jmpfall_disabled() noexcept {
    static const bool off = util::flag_on(util::FlagId::NoJmpFall);
    return off;
}

/// Si @p in es un `jmp LABEL` INCONDICIONAL (no jmp-reg ni jmp-sym), devuelve
/// true y escribe el label_id en @p out.  Solo los JMP con operando LABEL son
/// candidatos a eliminacion por fallthrough.
bool is_label_jmp(const MInstr &in, uint32_t &out) noexcept {
    if (in.op != MOp::JMP) return false;
    if (in.src1.kind != MOperandKind::LABEL) return false; // jmp-reg / jmp-sym
    out = static_cast<uint32_t>(in.src1.value);
    return true;
}

/// Label que DEFINE el bloque @p b en su primera instruccion real (saltando
/// COMMENT/NOP).  Devuelve true + label_id si esa primera instruccion es un
/// LABEL_DEF; el resto de instrucciones intermedias no cuenta (un JMP solo
/// cae en fallthrough si el destino es la etiqueta de ENTRADA del bloque
/// siguiente).
bool block_entry_label(const MBlock &b, uint32_t &out) noexcept {
    for (const MInstr &in : b.instrs) {
        if (in.op == MOp::COMMENT || in.op == MOp::NOP) continue;
        if (in.op == MOp::LABEL_DEF) {
            out = static_cast<uint32_t>(in.src1.value);
            return true;
        }
        return false; // primera instruccion real no es un label
    }
    return false; // bloque vacio
}

/// True si @p in es un SELF-MOVE redundante y eliminable: copia reg->reg
/// del MISMO registro fisico, en un ancho que no tiene efecto observable.
///   - MOV de 64-bit (`mov rX, rX`): nop puro.
///   - MOVSD/MOVSS (`movsd xX, xX`): nop (no toca bits altos relevantes).
/// Un `mov eX, eX` (32-bit) zero-extiende -> NO eliminable; se conserva.
bool is_redundant_self_move(const MInstr &in) noexcept {
    if (in.src2.kind != MOperandKind::NONE) return false;
    if (in.dst.kind != MOperandKind::REG || in.src1.kind != MOperandKind::REG)
        return false;
    if (in.dst.reg != in.src1.reg) return false;
    if (in.op == MOp::MOV) return in.dst.width == 8;
    if (in.op == MOp::MOVSD || in.op == MOp::MOVSS) return true;
    return false;
}

} // namespace

uint32_t peephole_physical(MFunction &pf) {
    if (peephole_disabled()) return 0;
    const bool no_xz = xorzero_disabled();
    uint32_t removed = 0;
    /* La regla que borra ESCRITURAS QUE NADIE LEE se apoya entera en el hecho
     * @c analysis::facts::compute_phys_liveness, que dice que sigue vivo tras
     * cada instruccion leyendolo de la base de instrucciones.
     *
     * Y el modelo de "que hace VIVO a un registro" en este backend tiene mas
     * fuentes de las que se ven mirando los operandos.  Cada una que faltaba
     * hacia que la regla borrase algo que hacia falta, y ninguna avisaba: el
     * codigo salia mas corto y con otro resultado.  Estan cerradas, una a una,
     * y cada una tiene su caso en @c tests/jit/test_phys_liveness.cpp:
     *
     *   1. Lo que lee un `ret` por convencion (el registro del retorno y los
     *      que hay que devolver intactos).  Estaba solo como "barrera", que
     *      basta para no reordenar y NO para liveness: una funcion que devolvia
     *      42 empezaba a devolver 0.
     *   2. Lo que lee una llamada por convencion (sus argumentos, que no
     *      aparecen en sus operandos).  Sin esto un bucle se comia toda la
     *      memoria de la maquina.
     *   3. Sus PROPIOS operandos cuando la llamada es indirecta.
     *   4. Que esas tres se apliquen ENCIMA de la base de instrucciones y no en
     *      lugar de ella: viven en @c abi_overlay porque la base contesta
     *      primero desde que aprendio `ret` y `call`, y mientras estuvieron
     *      dentro del pseudo dejaron de aplicarse sin que nada fallara al
     *      compilar.
     *   5. Que un salto a traves de un REGISTRO lee ese registro y ademas es
     *      una llamada de cola.  A la base se le pregunta por mnemonico, asi
     *      que para `jmp` contesta lo del salto relativo.
     *
     *   6. Que un bloque de `asm` diga los registros que lee su CUERPO, no solo
     *      los que nombran sus operandos.
     *
     * COMO SE BUSCA UNA QUE FALTE, que es lo util:
     * `VESTA_DEAD_DEF_REPORT=<parte del nombre de una funcion>` imprime que
     * escrituras borraria SIN borrar ninguna.  Cada linea sobre un programa que
     * funciona es una escritura que el hecho da por muerta; basta con mirar UNA
     * que no lo este para saber que fuente falta.  Asi salieron todas: en
     * `252_gc_ref_field` el informe paso de diez lineas a una, y en
     * `19_tco_basico` la unica que quedaba era el salto de la llamada de cola.
     *
     * Y se mide con la SUITE ENTERA: un subconjunto engana -- el grupo del
     * recolector solo pasa 22 de 23 aun cuando faltaban tres fuentes --. */
    if (deaddef_report(pf.name)) {
        const analysis::facts::PhysLivenessFacts live =
            analysis::facts::compute_phys_liveness(pf);
        for (size_t bi = 0; bi < pf.blocks.size(); ++bi) {
            const MBlock &b = pf.blocks[bi];
            for (size_t i = 0; i < b.instrs.size(); ++i) {
                const MInstr &in = b.instrs[i];
                if (in.op != MOp::MOV) continue;
                if (in.dst.kind != MOperandKind::REG || in.dst.width != 8)
                    continue;
                if (in.src2.kind != MOperandKind::NONE) continue;
                if (live.is_live_after(static_cast<uint32_t>(bi),
                                        static_cast<uint32_t>(i), in.dst.reg))
                    continue;
                /* Y con QUE sigue el bloque, que es lo que identifica el
                 * hueco: si lo de after usa el registro, el que se equivoca
                 * es el hecho, y el `op` de esa instruccion dice cual es la
                 * fuente de liveness que falta. */
                std::string after;
                for (size_t k = i + 1; k < b.instrs.size() && k <= i + 3; ++k) {
                    char buf[80];
                    std::snprintf(buf, sizeof buf, " op%d(d%d:r%d,s%d:r%d)",
                                  static_cast<int>(b.instrs[k].op),
                                  static_cast<int>(b.instrs[k].dst.kind),
                                  static_cast<int>(b.instrs[k].dst.reg),
                                  static_cast<int>(b.instrs[k].src1.kind),
                                  static_cast<int>(b.instrs[k].src1.reg));
                    after += buf;
                }
                std::fprintf(stderr,
                             "[deaddef] %s bloque %zu/%zu (succ %d,%d, "
                             "termina en op%d) instr %zu: "
                             "mov r%u <- (kind %d) MUERTA; after:%s%s\n",
                             pf.name.c_str(), bi, pf.blocks.size(),
                             static_cast<int>(b.succ_a),
                             static_cast<int>(b.succ_b),
                             static_cast<int>(b.instrs.back().op), i,
                             static_cast<unsigned>(in.dst.reg),
                             static_cast<int>(in.src1.kind), after.c_str(),
                             live.unknown_points ? " [hay puntos sin saber]" : "");
            }
        }
    }
    /* El hecho de liveness, UNA vez para toda la funcion: la regla de abajo lo
     * consulta por indice.  Se calcula solo si esa regla esta encendida, que es
     * lo unico que lo paga. */
    const bool drop_dead_defs = !deaddef_disabled();
    analysis::facts::PhysLivenessFacts live_regs;
    if (drop_dead_defs) live_regs = analysis::facts::compute_phys_liveness(pf);

    for (size_t bi = 0; bi < pf.blocks.size(); ++bi) {
        MBlock &b = pf.blocks[bi];
        std::vector<MInstr> kept;
        kept.reserve(b.instrs.size());
        bool changed = false;
        for (size_t i = 0; i < b.instrs.size(); ++i) {
            const MInstr &in = b.instrs[i];
            /* Una escritura que NADIE lee.
             *
             * Lo que hace que esto sea correcto no es la regla, es el hecho:
             * quien decide si el registro se lee despues mira lo que lee CADA
             * instruccion segun la base -- incluidos los registros que no
             * nombra --, lo que leen un `ret`, una llamada y un salto indirecto
             * por convencion, y lo que lee el cuerpo de un bloque de `asm`. */
            if (drop_dead_defs && is_removable_def(in) &&
                !live_regs.is_live_after(static_cast<uint32_t>(bi),
                                         static_cast<uint32_t>(i),
                                         in.dst.reg)) {
                if (deaddef_only(pf.name, bi)) {
                    if (deaddef_report(pf.name)) {
                        /* Y QUIEN MENCIONA ese registro en el resto de la
                         * funcion, en cualquier operando.  Es un barrido tonto
                         * -- sin flujo, sin orden --, y por eso vale: si el
                         * hecho dice que nadie lo lee y esto encuentra a
                         * alguien, el que se equivoca es el hecho, y esa linea
                         * dice exactamente donde mirar. */
                        std::string mentioned_by;
                        const uint8_t r = in.dst.reg;
                        const auto mentions = [r](const MOperand &o) {
                            if (o.kind == MOperandKind::REG) return o.reg == r;
                            if (o.kind == MOperandKind::MEM)
                                return o.reg == r ||
                                       ((o.width >> 2) & 0x3F) == r;
                            return false;
                        };
                        for (size_t cb = 0;
                             cb < pf.blocks.size() && mentioned_by.size() < 200; ++cb)
                            for (size_t ci = 0; ci < pf.blocks[cb].instrs.size();
                                 ++ci) {
                                if (cb == bi && ci <= i) continue;
                                const MInstr &c = pf.blocks[cb].instrs[ci];
                                if (!mentions(c.dst) && !mentions(c.src1) &&
                                    !mentions(c.src2))
                                    continue;
                                char buf[56];
                                std::snprintf(
                                    buf, sizeof buf, " b%zu:i%zu(op%d%s%s%s)",
                                    cb, ci, static_cast<int>(c.op),
                                    mentions(c.dst) ? ",d" : "",
                                    mentions(c.src1) ? ",s1" : "",
                                    mentions(c.src2) ? ",s2" : "");
                                mentioned_by += buf;
                            }
                        /* Y con QUE sigue el bloque, para ver la forma que
                         * tiene alrededor sin tener que volcarlo entero. */
                        std::string around;
                        for (size_t k = i; k < b.instrs.size() && k <= i + 8;
                             ++k) {
                            char bb[32];
                            std::snprintf(bb, sizeof bb, " %zu:op%d", k,
                                          static_cast<int>(b.instrs[k].op));
                            around += bb;
                        }
                        std::fprintf(stderr,
                                     "[deaddef] BORRA: %s bloque %zu "
                                     "instr %zu, r%u; sigue:%s; lo menciona:%s\n",
                                     pf.name.c_str(), bi, i,
                                     static_cast<unsigned>(in.dst.reg),
                                     around.c_str(),
                                     mentioned_by.empty() ? " nadie" : mentioned_by.c_str());
                    }
                    ++removed;
                    changed = true;
                    continue;
                }
            }
            if (is_redundant_self_move(in)) {
                ++removed;
                changed = true;
                continue;
            }
            /* xor-zeroing: `mov reg,0` -> `xor reg,reg` (2-3 bytes vs 5-7,
             * dependency-breaking idiom reconocido por la CPU) SOLO cuando los
             * flags esten muertos en ese punto (xor los escribe, mov no). */
            if (!no_xz && is_zero_mov(in) && flags_dead_after(b, i)) {
                const MOperand r =
                    MOperand::make_reg(static_cast<MReg>(in.dst.reg), 8);
                kept.push_back(MInstr::make_unary(MOp::XOR, r, r));
                changed = true;
                continue;
            }
            /* cmp reg,0 -> test reg,reg (mismos flags, mas corto). */
            if (is_cmp_zero(in)) {
                const MOperand r = MOperand::make_reg(
                    static_cast<MReg>(in.dst.reg), in.dst.width);
                kept.push_back(MInstr::make_unary(MOp::TEST, r, r));
                changed = true;
                continue;
            }
            kept.push_back(in);
        }
        if (changed) b.instrs = std::move(kept);
    }

    /* Eliminacion de JMP-a-fallthrough.  Los bridge-blocks del critical-edge
     * split suelen terminar con `jmp .L` cuando .L es justo el bloque
     * siguiente -> el salto es muerto (la caida natural va al mismo sitio). */
    if (!jmpfall_disabled()) {
        for (size_t bi = 0; bi < pf.blocks.size(); ++bi) {
            MBlock &b = pf.blocks[bi];
            /* (1) intra-bloque: `jmp L` seguido inmediatamente de `L:`. */
            std::vector<MInstr> kept;
            kept.reserve(b.instrs.size());
            bool changed = false;
            for (size_t i = 0; i < b.instrs.size(); ++i) {
                uint32_t tgt = 0;
                if (i + 1 < b.instrs.size() && is_label_jmp(b.instrs[i], tgt) &&
                    b.instrs[i + 1].op == MOp::LABEL_DEF &&
                    static_cast<uint32_t>(b.instrs[i + 1].src1.value) == tgt) {
                    ++removed;
                    changed = true;
                    continue; // el `L:` siguiente lo hace redundante
                }
                /* intra-bloque: `jcc X ; jmp Y ; X:` -> `j!cc Y ; X:`.  El
                 * `je X; jmp Y` que emiten los null/bool-checks con X contiguo:
                 * invertir la condicion (XOR 1 sobre el codigo x86) + soltar el
                 * jmp.  Semantica identica; seguro (no toca registros). */
                uint32_t jmp_tgt = 0;
                if (i + 2 < b.instrs.size() && b.instrs[i].op == MOp::JCC &&
                    b.instrs[i].src1.kind == MOperandKind::LABEL &&
                    b.instrs[i].variant != static_cast<uint8_t>(MCond::NONE) &&
                    is_label_jmp(b.instrs[i + 1], jmp_tgt) &&
                    b.instrs[i + 2].op == MOp::LABEL_DEF) {
                    const uint32_t jcc_tgt =
                        static_cast<uint32_t>(b.instrs[i].src1.value);
                    const uint32_t lbl =
                        static_cast<uint32_t>(b.instrs[i + 2].src1.value);
                    if (jcc_tgt == lbl && jmp_tgt != lbl) {
                        MInstr inv = b.instrs[i];
                        inv.variant ^= 1u;
                        inv.src1 = MOperand::make_label(jmp_tgt);
                        kept.push_back(inv); // j!cc Y
                        ++removed;
                        changed = true;
                        ++i; // saltar el jmp (i+1); el X: (i+2) se procesa
                             // normal
                        continue;
                    }
                }
                kept.push_back(b.instrs[i]);
            }
            if (changed) b.instrs = std::move(kept);

            /* (2) inter-bloque: ultima instr `jmp L` y el bloque SIGUIENTE
             * entra por `L:` -> fallthrough natural. */
            if (b.instrs.empty() || bi + 1 >= pf.blocks.size()) continue;
            uint32_t tgt = 0, next_lbl = 0;
            if (is_label_jmp(b.instrs.back(), tgt) &&
                block_entry_label(pf.blocks[bi + 1], next_lbl) &&
                next_lbl == tgt) {
                b.instrs.pop_back();
                ++removed;
                continue;
            }

            /* (3) `jcc X ; jmp Y` con X = entrada del bloque SIGUIENTE
             * (fallthrough) -> `j!cc Y` (cae natural a X, elimina el jmp).
             * El selector emite BR_COND como `jcc taken; jmp not-taken`; cuando
             * el bloque taken queda contiguo, la mitad es redundante.  Aparece
             * en CADA null-check / bool-test / comparacion-a-branch.  Invertir
             * la condicion es XOR 1 sobre el codigo x86 (E<->NE, L<->GE, ...).
             * Semantica identica: `if cc goto X(fallthrough) else goto Y`  ==
             * `if !cc goto Y else fall-through a X`.  Seguro (no toca regs). */
            if (b.instrs.size() >= 2) {
                MInstr &last = b.instrs.back();
                MInstr &prev = b.instrs[b.instrs.size() - 2];
                uint32_t jmp_tgt = 0, nl = 0;
                if (is_label_jmp(last, jmp_tgt) && prev.op == MOp::JCC &&
                    prev.src1.kind == MOperandKind::LABEL &&
                    prev.variant != static_cast<uint8_t>(MCond::NONE) &&
                    block_entry_label(pf.blocks[bi + 1], nl)) {
                    const uint32_t jcc_tgt =
                        static_cast<uint32_t>(prev.src1.value);
                    if (jcc_tgt == nl && jmp_tgt != nl) {
                        prev.variant ^= 1u; /* invertir condicion x86 */
                        prev.src1 = MOperand::make_label(jmp_tgt);
                        b.instrs.pop_back();
                        ++removed;
                    }
                }
            }
        }
    }
    return removed;
}

} // namespace jit
