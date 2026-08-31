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
 * @file jit/sched/machine_effects.cpp
 * @brief Efectos de una MInstr LEIDOS DE LAS DBs generadas (no re-derivados a
 *        mano).  Para una instruccion real de la ISA, la forma de @c instr_db
 *        (rmask/wmask/memflags + flags r/w de cada operando) es la fuente de
 *        verdad; los registros implicitos (rax:rdx de div...) salen del regset
 * de la DB. Solo los PSEUDOS propios de VestaVM (que no existen en ninguna ISA)
 * se modelan aqui explicitamente.
 */

#include "jit/sched/machine_effects.h"
#include "jit/sched/isa_effects.h" // lo que depende de la arquitectura
#include "vx/asm/instr_db.h"       // isa_name: como se llama cada una
#include "vx/diag/diag_catalog.h"  // el texto vive en el catalogo, no aqui
#include "jit/target_reginfo.h" // los registros del ABI: se PREGUNTAN, por ISA

#include <cstdio>
#include <cstdlib>
#include <string>

namespace jit {
namespace sched {

namespace {

using vx::instr_db::DbForm;
using vx::instr_db::DbOperand;
using vx::instr_db::Isa;
using vx::instr_db::ParsedOp;

/// Clave de registro uniforme de un operando REG/VREG (o UINT32_MAX si no lo
/// es).
uint32_t reg_key(const MOperand &o) {
    if (o.kind == MOperandKind::REG) return o.reg;
    if (o.kind == MOperandKind::VREG)
        return MEffects::VREG_BASE + static_cast<uint32_t>(o.value);
    return UINT32_MAX;
}

void add(std::vector<uint32_t> &v, uint32_t k) {
    if (k == UINT32_MAX) return;
    for (uint32_t x : v)
        if (x == k) return;
    v.push_back(k);
}

/// @brief Un pseudo llego a una ISA que no lo define.  Eso es un FALLO DEL
///        COMPILADOR, y se dice.
///
/// No es una duda que se pueda resolver poniendo una barrera y siguiendo.  Una
/// barrera dice "no se reordena por si acaso", y eso es exactamente lo que este
/// modulo existe para no hacer: aqui se SABE lo que toca cada instruccion, y si
/// una llega sin que nadie sepa contestar por ella, lo que hay es un objetivo
/// al que se le olvido declarar algo suyo.  Seguir con una respuesta inventada
/// significa que el codigo que salga sera correcto por casualidad o no lo sera,
/// y en ninguno de los dos casos se enteraria nadie.
///
/// @param code Cual de los tres fallos es.  Son TRES codigos y no uno con una
///             frase dentro: meter prosa como argumento de una plantilla la
///             parte en dos idiomas -- el texto traducido y el trozo que no lo
///             esta --, y ademas cada uno se arregla en otro sitio.
/// @param mi   La instruccion que nadie supo contestar.
/// @param isa  Para quien se preguntaba.
/// @param fn   QUE se estaba compilando.  Es el "donde" util de este fallo:
///             una traza de C++ diria por que camino se llego, y lo que hace
///             falta para arreglarlo es la funcion y la instruccion.
[[noreturn]] void isa_effects_bug(const char *code, const MInstr &mi,
                                  EffIsa isa, const std::string &fn) {
    /* Por el CATALOGO, como cualquier otro diagnostico: el texto vive alli en
     * todos los idiomas y aqui solo se dan los DATOS.  Que sea un fallo del
     * compilador y no del programa no lo saca de esa regla -- quien lo lea
     * merece leerlo en su idioma igual --. */
    const std::string msg =
        vx::diag::format(code, vx::diag::current_language(),
                         {std::to_string(static_cast<int>(mi.op)),
                          vx::instr_db::isa_name(isa), fn.empty() ? "?" : fn});
    std::fprintf(stderr, "\n%s\n\n", msg.c_str());
    std::fflush(stderr);
    std::abort();
}

/// Registros de DIRECCION de un operando MEM (base + index) -> siempre LEIDOS.
void add_mem_addr_reads(MEffects &e, const MOperand &o) {
    if (o.kind != MOperandKind::MEM) return;
    add(e.reads, o.reg); // base
    const uint8_t index = (o.width >> 2) & 0x3F;
    if (index != static_cast<uint8_t>(MReg::NONE)) add(e.reads, index);
}

/// El MInstr referencia N operandos explicitos (dst + src1 + src2 no-vacios).
const MOperand &minstr_slot(const MInstr &mi, int slot) {
    return slot == 0 ? mi.dst : (slot == 1 ? mi.src1 : mi.src2);
}

/// Traduce un operando del MInstr a su @c ParsedOp (kind + ancho en bits) para
/// el matcher de la DB.
bool to_parsed(const MOperand &o, ParsedOp &out) {
    switch (o.kind) {
    case MOperandKind::REG:
    case MOperandKind::VREG:
        out.kind = vx::instr_db::OP_REG;
        out.width = static_cast<uint16_t>(o.width) * 8;
        return true;
    case MOperandKind::IMM32:
    case MOperandKind::IMM64_IDX:
        out.kind = vx::instr_db::OP_IMM;
        out.width = 0;
        return true;
    case MOperandKind::MEM:
        out.kind = vx::instr_db::OP_MEM;
        out.width = 0;
        return true;
    case MOperandKind::LABEL:
    case MOperandKind::REL_RT:
        out.kind = vx::instr_db::OP_RELBR;
        out.width = 0;
        return true;
    default: return false; // NONE
    }
}

/// Cuenta de operandos explicitos del MInstr (dst/src1/src2 no vacios).
int explicit_operand_count(const MInstr &mi) {
    int n = 0;
    for (int s = 0; s < 3; ++s)
        if (minstr_slot(mi, s).kind != MOperandKind::NONE) ++n;
    return n;
}

/**
 * @brief Rol de los operandos de un MOp REAL.  Es la DEFINICION del MOp (que
 *        hace la operacion), NO un dato de ISA a extraer -> inequivoco.  Los
 *        registros IMPLICITOS con nombre (rax:rdx de div) SI son ISA y salen de
 *        la DB (@c div_family), no de aqui.
 */
struct OpRoles {
    bool dst_written = false; ///< el slot dst se ESCRIBE
    bool dst_read = false;    ///< el slot dst se LEE (two-address / compare)
    bool writes_flags = false;
    bool reads_flags = false;
    bool div_family = false; ///< consultar la DB por el implicito rax:rdx
};

/// Clasifica los roles de un MOp real (los mismos que enumera @ref
/// mop_mnemonic).
OpRoles mop_roles(MOp op) {
    OpRoles r;
    switch (op) {
    /* Movimientos / cargas / conversiones / direcciones: dst SOLO escrito. */
    case MOp::MOV:
    case MOp::LEA:
    case MOp::MOVZX:
    case MOp::MOVSX:
    case MOp::MOVQ_GP_XMM:
    case MOp::MOVQ_XMM_GP:
    case MOp::CVTSI2SD:
    case MOp::CVTTSD2SI:
    case MOp::CVTSS2SD:
    case MOp::CVTSD2SS:
    case MOp::CVTSI2SS:
    case MOp::CVTTSS2SI:
    case MOp::MOVSD:
    case MOp::MOVSS:
    case MOp::MOVUPD:
    case MOp::MOVAPD: r.dst_written = true; break;
    /* SETcc: escribe dst, LEE flags. */
    case MOp::SETCC:
        r.dst_written = true;
        r.reads_flags = true;
        break;
    /* CMOVcc: dst read+written (condicional), LEE flags. */
    case MOp::CMOVCC:
        r.dst_written = true;
        r.dst_read = true;
        r.reads_flags = true;
        break;

    /* ALU entera 2-address: dst read+written + escribe flags. */
    case MOp::ADD:
    case MOp::SUB:
    case MOp::IMUL:
    case MOp::AND:
    case MOp::OR:
    case MOp::XOR:
    case MOp::SHL:
    case MOp::SHR:
    case MOp::SAR:
    case MOp::NEG:
    case MOp::INC:
    case MOp::DEC:
    case MOp::ROL:
    case MOp::ROR:
        r.dst_written = true;
        r.dst_read = true;
        r.writes_flags = true;
        break;
    /* NOT / BSWAP: dst read+written, SIN flags. */
    case MOp::NOT:
    case MOp::BSWAP:
        r.dst_written = true;
        r.dst_read = true;
        break;
    /* POPCNT/LZCNT/TZCNT: dst SOLO escrito, escribe flags. */
    case MOp::POPCNT:
    case MOp::LZCNT:
    case MOp::TZCNT:
        r.dst_written = true;
        r.writes_flags = true;
        break;

    /* CMP / TEST / UCOMIS*: leen ambos (dst LEIDO), escriben flags, sin
     * destino. */
    case MOp::CMP:
    case MOp::TEST:
    case MOp::UCOMISD:
    case MOp::UCOMISS:
        r.dst_read = true;
        r.writes_flags = true;
        break;

    /* FP/SIMD 2-address (arith): dst read+written, sin flags de enteros. */
    case MOp::ADDSD:
    case MOp::SUBSD:
    case MOp::MULSD:
    case MOp::DIVSD:
    case MOp::MINSD:
    case MOp::MAXSD:
    case MOp::SQRTSD:
    case MOp::ROUNDSD:
    case MOp::ADDSS:
    case MOp::SUBSS:
    case MOp::MULSS:
    case MOp::DIVSS:
    case MOp::SQRTSS:
    case MOp::XORPS:
    case MOp::ANDPS:
    case MOp::ADDPD:
    case MOp::SUBPD:
    case MOp::MULPD:
    case MOp::DIVPD:
    case MOp::SQRTPD:
    case MOp::XORPD:
    case MOp::ANDPD:
    case MOp::UNPCKLPD:
    case MOp::SHUFPS: // dst,src,imm -> lanes 0,1 vienen de dst (read+written)
    case MOp::ADDPS:
    case MOp::SUBPS:
    case MOp::MULPS:
    case MOp::DIVPS:
    case MOp::PADDD:
    case MOp::PSUBD:
    case MOp::PADDQ:
    case MOp::PSUBQ:
    case MOp::PADDW:
    case MOp::PSUBW:
    case MOp::PMULLW:
    case MOp::PADDB:
    case MOp::PSUBB:
    case MOp::PMULLD:
    case MOp::VFMADD231PD: // FMA: dst es acumulador (read+written)
    case MOp::VFMADD231PS:
    case MOp::VFMSUB231PD: // FMSUB: dst = a*b - dst (tambien read+written)
    case MOp::VFMSUB231PS:
    /* Y las ESCALARES, que son lo mismo sobre un solo carril.  Estaban sin
     * declarar aqui igual que sin nombrar en la tabla de x86: las dos listas se
     * escribieron a la vez y a las dos les falto la misma mitad. */
    case MOp::VFMADD231SD:
    case MOp::VFMADD231SS:
        r.dst_written = true;
        r.dst_read = true;
        break;
    /* AVX 3-operandos NO destructivo: dst SOLO escrito. */
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
    case MOp::VBROADCASTSD:
    case MOp::VBROADCASTSS: r.dst_written = true; break;

    /* Division entera: el operando explicito es el divisor (LEIDO); el
     * resultado va a rax:rdx (implicito de la DB); escribe flags. */
    case MOp::IDIV:
    case MOp::DIV_U:
        r.dst_read = true;
        r.writes_flags = true;
        r.div_family = true;
        break;
    case MOp::CQO:
        r.div_family = true; // rax -> rdx, implicito de la DB
        break;

    default:
        // Todo MOp real esta arriba; si aparece uno nuevo sin clasificar, se
        // trata como read+write de dst + flags (seguro, no optimista de menos).
        r.dst_written = true;
        r.dst_read = true;
        r.writes_flags = true;
        break;
    }
    return r;
}

/**
 * @brief Anade los registros IMPLICITOS con nombre (rax:rdx) de una instruccion
 *        de la familia div, leidos de la DB (regset).  El mnemonico de div
 *        (idiv/div/cqo) NO es ambiguo -> el match es fiable.
 */
void add_div_implicit_from_db(const MInstr &mi, const char *mnem, Isa isa,
                              const IsaEffects &t, MEffects &e) {
    std::vector<ParsedOp> ops;
    const int nexp = explicit_operand_count(mi);
    for (int s = 0; s < nexp; ++s) {
        ParsedOp p;
        if (to_parsed(minstr_slot(mi, s), p)) ops.push_back(p);
    }
    const int32_t fid = vx::instr_db::match(isa, mnem, ops);
    if (fid < 0) return;
    const vx::instr_db::IsaData &db =
        (isa == Isa::X86) ? vx::instr_db::db_x86() : vx::instr_db::db_arm64();
    if (fid >= static_cast<int32_t>(db.form_count)) return;
    const DbForm &f = db.forms[static_cast<uint32_t>(fid)];
    for (uint8_t i = 0; i < f.ops_count; ++i) {
        const DbOperand &o = db.ops[f.ops_off + i];
        if ((o.flags & 0x4) == 0) continue;           // solo implicitos
        if (o.kind != vx::instr_db::OP_REG) continue; // solo registros
        if (o.regset >= db.str_count) continue;
        const uint32_t k = t.regset_key(db.str[o.regset], o.regset);
        if (k == UINT32_MAX) continue;
        if (o.flags & 0x1) add(e.reads, k);
        if (o.flags & 0x2) add(e.writes, k);
    }
}

/**
 * @brief Efectos de una instruccion REAL: roles explicitos (definicion del MOp)
 *        + flags + los implicitos con nombre de la DB (familia div).
 */
void real_effects(const MInstr &mi, const char *mnem, Isa isa,
                  const IsaEffects &t, MEffects &e) {
    // CQO/CDQ: sign-extienden RAX en RDX:RAX (semantica FIJA, sin operandos):
    // LEEN RAX y ESCRIBEN RDX, SIN tocar flags.  Es IMPRESCINDIBLE modelar el
    // RDX escrito -- si no, un `mov rdx, imm` puede colarse entre el CQO y el
    // IDIV/DIV que lee RDX:RAX como dividendo, corrompiendo la division (#DE o
    // resultado erroneo).  La familia div de la DB no siempre expone este RDX
    // implicito para CQO, asi que se modela aqui explicito (semantica exacta).
    if (mi.op == MOp::CQO) {
        add(e.reads, static_cast<uint8_t>(MReg::RAX));
        add(e.writes, static_cast<uint8_t>(MReg::RDX));
        return;
    }
    const OpRoles r = mop_roles(mi.op);
    e.writes_flags = r.writes_flags;
    e.reads_flags = r.reads_flags;

    // dst: escrito y/o leido segun el rol; si es MEM, define store/load.
    if (mi.dst.kind == MOperandKind::MEM) {
        add_mem_addr_reads(e, mi.dst);
        if (r.dst_written) e.writes_mem = true;
        if (r.dst_read) e.reads_mem = true;
    } else if (mi.dst.kind != MOperandKind::NONE) {
        if (r.dst_written) add(e.writes, reg_key(mi.dst));
        if (r.dst_read) add(e.reads, reg_key(mi.dst));
    }
    // src1/src2: siempre LEIDOS; MEM -> lee memoria + regs de direccion.
    for (const MOperand *s : {&mi.src1, &mi.src2}) {
        if (s->kind == MOperandKind::MEM) {
            add_mem_addr_reads(e, *s);
            e.reads_mem = true;
        } else if (s->kind != MOperandKind::NONE) {
            add(e.reads, reg_key(*s));
        }
    }
    // Familia div (IDIV/DIV): el dividendo es RDX:RAX -- LEE ambos -- y deja el
    // cociente en RAX y el resto en RDX -- ESCRIBE ambos.  Es semantica FIJA de
    // x86 (no depende de la microarq), asi que se modela EXPLICITO: la
    // extraccion de implicitos de la DB no siempre expone el RDX LEIDO, y sin
    // el, un `mov rdx, imm` puede colarse ANTES del div (WAR idiv/mov-rdx
    // perdida) y corromper el dividendo -> #DE o resultado erroneo.
    if (r.div_family) {
        if (isa == Isa::X86) {
            add(e.reads, static_cast<uint8_t>(MReg::RAX));
            add(e.reads, static_cast<uint8_t>(MReg::RDX));
            add(e.writes, static_cast<uint8_t>(MReg::RAX));
            add(e.writes, static_cast<uint8_t>(MReg::RDX));
        } else {
            add_div_implicit_from_db(mi, mnem, isa, t, e);
        }
    }
}

/**
 * @brief Modela los efectos de un PSEUDO de VestaVM (no existe en la ISA).
 *        Cada pseudo tiene una semantica fija y conocida por construccion.
 */
/**
 * @brief Anade a @p e lo que el ABI de @p isa hace VIVO en un `ret` o en una
 *        llamada.
 *
 * @param isa     ISA del objetivo: de ella depende QUE registros son.
 * @param is_return true = un `ret` (el registro del valor de retorno + los que
 *                  hay que devolver intactos); false = una llamada (los de
 *                  argumentos).
 * @param e       Se le anaden las lecturas.
 *
 * Los registros se PREGUNTAN al descriptor del objetivo, que es quien los sabe
 * por ISA.  Escribirlos aqui a mano daria los de x86 tambien en arm64, que es
 * justo el fallo que este modulo existe para evitar.
 */
void abi_reads(const TargetRegInfo &t, bool is_return, MEffects &e) {
    const auto anade = [&e](uint8_t r) {
        add(e.reads, static_cast<uint32_t>(r));
    };
    for (size_t c = 0; c < TargetRegInfo::NCLASS; ++c) {
        if (is_return) {
            anade(t.ret_reg[c]);
            for (const uint8_t r : t.callee_saved[c])
                anade(r);
        } else {
            for (const uint8_t r : t.arg_regs[c])
                anade(r);
        }
    }
    /* Y la pila, que la leen los dos en cualquier arquitectura.  Tambien se
     * PREGUNTA: no esta en las listas de asignables porque no lo es, pero el
     * descriptor la declara aparte justo para esto. */
    anade(t.stack_reg);
}

/**
 * @brief Los pseudos de VestaVM cuya respuesta NO depende de la arquitectura.
 *
 * Marcar un argumento, definir una etiqueta, una carga generica, una barrera:
 * todo eso se contesta mirando los operandos, que son los mismos en cualquier
 * objetivo.  Lo que nombra un registro concreto -- la pila, el par de la
 * division, las instrucciones de cadena -- NO esta aqui: lo contesta la tabla
 * de la arquitectura.
 *
 * @return @c false si este pseudo no es de los genericos.  Entonces le toca a
 *         la arquitectura, y si tampoco lo sabe es un fallo del compilador.
 */
bool generic_pseudo(const MInstr &mi, MEffects &e) {
    switch (mi.op) {
    /* Sin efecto de datos y movibles libremente. */
    case MOp::NOP:
    case MOp::COMMENT: break;

    /* Posiciones FIJAS: un LABEL_DEF es destino de salto y las entradas de
     * jump-table son datos inline referenciados por su offset -> barrera (nada
     * se reordena a traves de ellas). */
    case MOp::LABEL_DEF:
    case MOp::DATA_PTR_LABEL:
    case MOp::DATA_REL32_LABEL: e.is_barrier = true; break;

    /* ARG: marca un argumento -> LEE su src1 (para no adelantar al productor).
     */
    case MOp::ARG: add(e.reads, reg_key(mi.src1)); break;

    /* PUSH src: lee src + rsp, escribe rsp + memoria. */
    case MOp::LOAD:    // dst, src1=addr
    case MOp::LOAD_VM: // dst, src1=addr, src2=imm64_idx (fallback)
        add(e.writes, reg_key(mi.dst));
        add(e.reads, reg_key(mi.src1));
        e.reads_mem = true;
        break;
    /* Stores pseudo: [addr] = val. */
    case MOp::STORE:    // src1=addr, src2=val
    case MOp::STORE_VM: // src1=addr, src2=val, dst=imm64_idx
        add(e.reads, reg_key(mi.src1));
        add(e.reads, reg_key(mi.src2));
        e.writes_mem = true;
        break;

        /* ALLOCA: dst = puntero a espacio reservado del frame. */
        add(e.writes, reg_key(mi.dst));
        add(e.reads, reg_key(mi.src1));
        add(e.reads, reg_key(mi.src2));
        e.reads_mem = true;
        e.writes_mem = true;
        e.writes_flags = true;
        break;
        /* Atomicos fisicos (post-rewrite): dst=mem[addr], src1=reg. */
        add(e.reads, reg_key(mi.src1));
        add(e.writes, reg_key(mi.src1)); // xadd deja el valor viejo en el reg
        add_mem_addr_reads(e, mi.dst);
        e.reads_mem = true;
        e.writes_mem = true;
        e.writes_flags = true;
        break;

    /* Las instrucciones de CADENA de x86 (`rep movsb`, `rep stosb`): copiar y

    /* Direcciones de simbolo/label/TLS: dst = &X (sin flags, sin memoria). */
    case MOp::MOV_SYM:
    case MOp::LEA_RIP_SYM:
    case MOp::LEA_LABEL:
    case MOp::TLS_LE_ADDR:
    case MOp::TLS_PE_ADDR: add(e.writes, reg_key(mi.dst)); break;

    /* Salva/restaura proc->registers en la work-area del frame (usa R11). */

    /* Barreras: control de flujo / puntos de sincronizacion / asm opaco. */
    case MOp::JMP: e.is_barrier = true; break;
    case MOp::JCC:
        e.reads_flags = true;
        e.is_barrier = true;
        break;
    /* RET y la familia del CALL: lo que leen POR CONVENCION lo pone
     * @c abi_overlay, que corre despues de esto y tambien despues de la base de
     * instrucciones -- son dos capas distintas y la de arriba se aplica siempre
     * (ver el comentario alli). */
    case MOp::RET:
    case MOp::CALL:
    case MOp::CALL_ABS:
    case MOp::CALL_SYM:
    case MOp::JMP_SYM:
    case MOp::TAILCALL:
    case MOp::SAFEPOINT:
    case MOp::INT3:
    case MOp::INLINE_ASM_RAW: e.is_barrier = true; break;

    /* Cualquier otro pseudo no listado: barrera dura (nunca miscompilar). */
    /* Reservar sitio en el marco: escribe el destino y nada mas. */
    case MOp::ALLOCA:
    case MOp::ALLOCA_VM: add(e.writes, reg_key(mi.dst)); break;

    /* El puntero al proceso: lo lee de su sitio y lo deja en el destino. */
    case MOp::LOAD_PROC:
        add(e.writes, reg_key(mi.dst));
        e.reads_mem = true; // esta en el area por hilo
        break;

    /* Sumar de forma atomica: todo lo que toca esta en sus operandos, asi que
     * la respuesta no depende de la arquitectura.  Su primo el intercambio
     * condicional SI depende -- baja a algo que compara contra un registro
     * concreto -- y por eso vive en la tabla de x86. */
    case MOp::ATOMICADD_V: // dst = lo que habia, src1 = donde, src2 = cuanto
        add(e.writes, reg_key(mi.dst));
        add(e.reads, reg_key(mi.src1));
        add(e.reads, reg_key(mi.src2));
        e.reads_mem = true;
        e.writes_mem = true;
        e.writes_flags = true;
        break;
    case MOp::LOCK_XADD:
        add(e.reads, reg_key(mi.src1));
        add(e.writes, reg_key(mi.src1)); // deja el valor viejo en el registro
        add_mem_addr_reads(e, mi.dst);
        e.reads_mem = true;
        e.writes_mem = true;
        e.writes_flags = true;
        break;

    /* Cualquier otro pseudo lo tiene que contestar la arquitectura, porque su
     * respuesta nombra registros suyos.  Aqui NO hay caso por defecto a
     * proposito: el que habia daba por leidos y escritos todos los operandos,
     * la memoria y las banderas, mas barrera -- o sea, "no se sabe" con otro
     * nombre --, y eso tapa exactamente lo que este modulo existe para saber.
     */
    default: return false;
    }
    return true;
}

} // namespace

/// @brief Una escritura ESTRECHA no se lleva por delante el registro entero.
///
/// Cuando la escritura deja intactos bits que ya estaban, lo que hubiera antes
/// sigue ahi y sigue importando: para la liveness eso es una lectura ademas de
/// una escritura.  Sin decirlo, el registro parece pisado y lo de antes muerto.
///
/// CUANDO es estrecha lo sabe cada arquitectura y se le PREGUNTA -- en x86
/// escribir `al` conserva los demas bytes y un `setcc` escribe uno solo aunque
/// nombre el registro entero; en arm64 no pasa ninguna de las dos cosas --.
static void narrow_write_overlay(const MInstr &mi, const IsaEffects &t,
                                 MEffects &e) {
    const auto check = [&](const MOperand &o) {
        if (!t.is_narrow_write(mi, o)) return;
        const uint32_t k = reg_key(o);
        for (const uint32_t w : e.writes)
            if (w == k) {
                add(e.reads, k);
                return;
            }
    };
    check(mi.dst);
    check(mi.src1);
    check(mi.src2);
}

static void abi_overlay(const MInstr &mi, const TargetRegInfo &abi,
                        uint64_t pinned, MEffects &e) {
    /* Los registros que la funcion FIJA los lee cualquier llamada suya: puede
     * estar llamando a algo que pega sus parametros ahi.  Ver
     * @c MFunction::pinned_regs. */
    const auto reads_pinned = [&] {
        for (uint8_t r = 0; r < 64; ++r)
            if (pinned & (1ull << r)) add(e.reads, r);
    };
    /* Sus PROPIOS operandos: en una llamada o un salto INDIRECTOS son a donde
     * se va.  Una direccion de 64 bits no cabe como inmediato, asi que se
     * materializa en un registro de apoyo y se salta a traves de el; sin
     * contarlo como lectura, esa materializacion parece muerta.  @c reg_key
     * ignora solo lo que no es un registro, asi que un salto relativo no suma
     * nada por pasar por aqui. */
    const auto reads_its_target = [&] {
        add(e.reads, reg_key(mi.dst));
        add(e.reads, reg_key(mi.src1));
        add(e.reads, reg_key(mi.src2));
    };
    switch (mi.op) {
    case MOp::RET:
        abi_reads(abi, /*is_return=*/true, e);
        e.is_barrier = true;
        break;
    case MOp::CALL:
    case MOp::CALL_ABS:
    case MOp::CALL_SYM:
    case MOp::JMP_SYM:
    case MOp::TAILCALL:
        abi_reads(abi, /*is_return=*/false, e);
        reads_pinned();
        reads_its_target();
        e.is_barrier = true;
        break;
    case MOp::JMP:
    case MOp::JCC:
        /* Un salto a un LABEL no lee ningun registro y se queda como esta, que
         * es el caso normal.  Los otros dos si leen, y por razones distintas:
         *
         *   - Si es la COLA DE UNA LLAMADA, pasa argumentos igual que un
         *     `call`, y ademas lee su destino si va por registro.  Eso NO se
         *     deduce de la forma del operando -- una cola puede ir a un label,
         *     a una direccion o por registro, y las tres formas las usa tambien
         *     un salto normal --: lo dice quien la emite, con
         *     @c MI_FLAG_TAILCALL.  Visto en `19_tco_basico` y en
         *     `210_unique_en_campo`: las instrucciones que colocaban los
         *     argumentos salian muertas.
         *
         *   - A traves de MEMORIA es el despacho de una tabla de saltos, y lo
         *     que lee son los registros de la DIRECCION -- la base y el indice
         *     --, no lo que hay en ella.  No pasa argumentos: los brazos estan
         *     en la misma funcion y su entrada llega por el grafo.  Visto en
         *     `std.memory`: el `mov` que calculaba el indice salia muerto
         *     porque `jmp [base + indice*8]` no lo nombra como registro. */
        if ((mi.flags & MI_FLAG_TAILCALL) != 0) {
            abi_reads(abi, /*is_return=*/false, e);
            reads_pinned();
            reads_its_target();
        }
        if (mi.dst.kind == MOperandKind::MEM ||
            mi.src1.kind == MOperandKind::MEM ||
            mi.src2.kind == MOperandKind::MEM) {
            add_mem_addr_reads(e, mi.dst);
            add_mem_addr_reads(e, mi.src1);
            add_mem_addr_reads(e, mi.src2);
            e.reads_mem = true;
        } else if (mi.dst.kind == MOperandKind::REG ||
                   mi.src1.kind == MOperandKind::REG ||
                   mi.src2.kind == MOperandKind::REG) {
            /* Un salto indirecto que no viene marcado: al menos, su destino. */
            reads_its_target();
        }
        e.is_barrier = true;
        break;
    default: break;
    }
}

const char *mop_mnemonic(MOp op, EffIsa isa) {
    const IsaEffects *t = isa_effects(isa);
    return t ? t->mnemonic(op) : nullptr;
}

/// @brief El cuerpo comun: los efectos de @p mi para @p isa con la convencion
///        @p abi.
///
/// Las DOS cosas hacen falta y son distintas.  La ISA dice QUE hace cada
/// instruccion; la convencion, que registros importan al entrar y al salir de
/// una funcion.  Un mismo binario de x86 compilado para Windows o para Linux
/// tiene la MISMA ISA y OTRA convencion -- los dos primeros argumentos van en
/// registros distintos --, y confundirlas da que esos dos estan muertos justo
/// antes de la llamada que los usa.
static MEffects effects_for(const MInstr &mi, EffIsa isa,
                            const TargetRegInfo &abi, uint64_t pinned,
                            const std::string &fn) {
    /* Lo primero: la tabla de esta arquitectura.  Sin ella no hay respuesta que
     * dar, y dar una inventada es peor que no dar ninguna. */
    const IsaEffects *t = isa_effects(isa);
    if (t == nullptr) isa_effects_bug("VXA069", mi, isa, fn);

    MEffects e;
    if (const char *mnem = t->mnemonic(mi.op)) {
        /* Es una instruccion de verdad: la base de instrucciones es la fuente
         * de verdad, con sus registros implicitos incluidos. */
        real_effects(mi, mnem, isa, *t, e);
    } else if (!generic_pseudo(mi, e) && !t->pseudo(mi, e)) {
        /* Ni el comun ni la arquitectura saben que hace este pseudo.  Eso no es
         * una duda: es que falta declararlo. */
        isa_effects_bug("VXA068", mi, isa, fn);
    }
    /* Y encima, lo que la base no puede saber: la convencion de llamada y
     * cuanto escribe de verdad una escritura estrecha.  SIEMPRE, sin depender
     * de quien haya contestado antes. */
    abi_overlay(mi, abi, pinned, e);
    narrow_write_overlay(mi, *t, e);
    return e;
}

MEffects machine_effects(const MInstr &mi, EffIsa isa,
                         const TargetRegInfo &abi) {
    return effects_for(mi, isa, abi, /*pinned=*/0, std::string());
}

MEffects machine_effects(const MFunction &mf, const MInstr &mi, EffIsa isa) {
    /* La convencion sale de la FUNCION, que es quien sabe para donde va.  Si
     * nadie la puso, no se coge una cualquiera: se dice.  Coger la del
     * anfitrion es lo que hacia que un ELF de Linux generado desde Windows
     * creyera muertos sus dos primeros argumentos. */
    if (mf.target == nullptr) isa_effects_bug("VXA070", mi, isa, mf.name);
    MEffects e = effects_for(mi, isa, *mf.target, mf.pinned_regs, mf.name);
    if (mi.op != MOp::INLINE_ASM_RAW) return e;
    /* Un `asm` no es opaco: sus registros estan en su bloque, no en los
     * operandos.  Con la funcion delante ya se pueden leer, asi que se dicen en
     * vez de degradar a "barrera y no se sabe mas".
     *
     * Se dan los FISICOS si estan (despues de repartir) y si no los virtuales,
     * en el mismo espacio de ids uniforme que usa el resto de la estructura. */
    const uint32_t idx = static_cast<uint32_t>(mi.src1.value);
    if (idx >= mf.asm_blobs.size()) return e;
    const AsmBlob &b = mf.asm_blobs[idx];
    const auto anade = [](std::vector<uint32_t> &v, uint32_t id) {
        for (const uint32_t x : v)
            if (x == id) return;
        v.push_back(id);
    };
    if (!b.in_phys.empty() || !b.out_phys.empty()) {
        for (const uint8_t r : b.in_phys)
            anade(e.reads, r);
        for (const uint8_t r : b.out_phys)
            anade(e.writes, r);
    } else {
        for (const uint32_t v : b.in_vregs)
            anade(e.reads, MEffects::VREG_BASE + v);
        for (const uint32_t v : b.out_vregs)
            anade(e.writes, MEffects::VREG_BASE + v);
    }
    for (const uint8_t r : b.clobbers)
        anade(e.writes, r);
    e.reads_flags = e.reads_flags || b.clobbers_flags;
    e.writes_flags = e.writes_flags || b.clobbers_flags;
    e.reads_mem = e.reads_mem || b.clobbers_mem;
    e.writes_mem = e.writes_mem || b.clobbers_mem;
    /* Sigue siendo barrera para REORDENAR -- eso no cambia --, pero ahora
     * ademas se sabe que toca.  Lo unico que queda sin detalle es un bloque al
     * que no se le infirieron los clobbers. */
    return e;
}

} // namespace sched
} // namespace jit
