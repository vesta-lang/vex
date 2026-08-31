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
 * @file jit/sched/isa_effects_x86.cpp
 * @brief Lo que de los efectos de una instruccion sabe SOLO x86-64.
 *
 * Ver @ref jit/sched/isa_effects.h para por que esto vive aparte del modulo
 * comun.  Aqui se nombran registros de x86 y nada mas.
 */

#include "jit/sched/isa_effects.h"
#include "jit/sched/machine_effects.h"

#include <string>

namespace jit {
namespace sched {
namespace {

/// Base del espacio de claves para registros que NO estan en @c MReg
/// (mascaras K, MMX/x87, segmento, control/debug, MSR/MXCSR, zmm16-31): se
/// rastrean por su indice en el pool de cadenas, asi que el mismo nombre da
/// siempre la misma clave.
constexpr uint32_t SPECIAL_BASE = 1u << 21;

/// @brief Sufijo numerico tras un prefijo de N letras ("XMM12" -> 12).
int suffix_num(const std::string &s, size_t pref) {
    if (s.size() <= pref) return -1;
    int n = 0;
    for (size_t i = pref; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return -1;
        n = n * 10 + (s[i] - '0');
    }
    return n;
}

/**
 * @brief Decodifica un register_set de la base a la clave de dependencia,
 *        cubriendo TODAS las clases de registro de x86.
 *
 *   - GP (A/C/D/B/SP/BP/SI/DI/R8..R15, cualquier ancho) -> id de MReg 0-15,
 *     que es el mismo espacio que usan los operandos explicitos;
 *   - vector XMM/YMM/ZMM 0-15 -> MReg XMM (16+n); YMMn y ZMMn coinciden con
 *     XMMn, que es lo correcto: son el mismo registro visto mas ancho;
 *   - lo demas con nombre fijo (mascaras K, MMX, x87, segmento, CR/DR, MSR,
 *     MXCSR, ZMM16-31) -> por su indice en el pool de cadenas.
 *
 * @return La clave, o @c UINT32_MAX si es una CLASE (varios registros) o esta
 *         vacio -> no es un registro implicito concreto.
 */
uint32_t regset_key(const char *rs, uint16_t regset_idx) {
    if (rs == nullptr || rs[0] == '\0' || rs[0] == '-') return UINT32_MAX;
    for (const char *p = rs; *p; ++p)
        if (*p == '/') return UINT32_MAX; // una CLASE, no un registro concreto
    const std::string s(rs);
    // --- GP (familia de una letra o Rn, cualquier ancho) ---
    struct Fam {
        const char *k;
        int reg;
    };
    static const Fam fam[] = {
        {"AX", 0},  {"EAX", 0}, {"RAX", 0}, {"AL", 0},  {"AH", 0},  {"CX", 1},
        {"ECX", 1}, {"RCX", 1}, {"CL", 1},  {"CH", 1},  {"DX", 2},  {"EDX", 2},
        {"RDX", 2}, {"DL", 2},  {"DH", 2},  {"BX", 3},  {"EBX", 3}, {"RBX", 3},
        {"BL", 3},  {"BH", 3},  {"SP", 4},  {"ESP", 4}, {"RSP", 4}, {"SPL", 4},
        {"BP", 5},  {"EBP", 5}, {"RBP", 5}, {"BPL", 5}, {"SI", 6},  {"ESI", 6},
        {"RSI", 6}, {"SIL", 6}, {"DI", 7},  {"EDI", 7}, {"RDI", 7}, {"DIL", 7},
    };
    for (const Fam &f : fam)
        if (s == f.k) return static_cast<uint32_t>(f.reg);
    if ((s[0] == 'R') && s.size() >= 2 && s[1] >= '8' && s[1] <= '9') {
        // R8..R15 con sufijos D/W/B opcionales.
        int n = s[1] - '0';
        if (s.size() >= 3 && s[2] >= '0' && s[2] <= '5') n = 10 + (s[2] - '0');
        if (n >= 8 && n <= 15) return static_cast<uint32_t>(n);
    }

    // --- vector XMM/YMM/ZMM (SSE/AVX/AVX512): 0-15 aliasan MReg XMM ---
    if (s.size() >= 4 &&
        (s.rfind("XMM", 0) == 0 || s.rfind("YMM", 0) == 0 ||
         s.rfind("ZMM", 0) == 0)) {
        const int n = suffix_num(s, 3);
        if (n >= 0 && n <= 15)
            return static_cast<uint32_t>(static_cast<int>(MReg::XMM0) + n);
        // ZMM16..31 (AVX512): no estan en MReg -> clave especial por nombre.
    }

    // --- resto de clases con nombre fijo (K/MM/ST/seg/CR/DR/MSR/MXCSR/...) ---
    // No estan en MReg; se rastrean por su indice de register_set (estable).
    return SPECIAL_BASE + regset_idx;

}

/// @brief Como se llama @p op en el ensamblador de x86.
///
/// Los saltos y las llamadas NO se mapean a proposito: sus efectos no son de la
/// instruccion sino de la CONVENCION, y de eso se encarga el modulo comun
/// leyendo el descriptor del objetivo.  PUSH/POP tampoco: tocan la pila y la
/// memoria de forma implicita, y eso lo contesta @c pseudo.
const char *mnemonic(MOp op) {

    switch (op) {
    /* Movimiento / ALU entera. */
    case MOp::MOV: return "mov";
    case MOp::LEA: return "lea";
    /* PUSH/POP: NO reales aqui -> pseudo (tocan rsp + memoria implicitos). */
    case MOp::ADD: return "add";
    case MOp::SUB: return "sub";
    case MOp::IMUL: return "imul";
    case MOp::AND: return "and";
    case MOp::OR: return "or";
    case MOp::XOR: return "xor";
    case MOp::SHL: return "shl";
    case MOp::SHR: return "shr";
    case MOp::SAR: return "sar";
    case MOp::NEG: return "neg";
    case MOp::NOT: return "not";
    case MOp::IDIV: return "idiv";
    case MOp::CQO: return "cqo";
    case MOp::DIV_U: return "div";
    case MOp::MOVZX: return "movzx";
    case MOp::MOVSX: return "movsx";
    case MOp::INC: return "inc";
    case MOp::DEC: return "dec";
    case MOp::POPCNT: return "popcnt";
    case MOp::LZCNT: return "lzcnt";
    case MOp::TZCNT: return "tzcnt";
    case MOp::CMP: return "cmp";
    case MOp::TEST: return "test";
    case MOp::SETCC:
        return "setne"; // representante (mismos efectos: wr dst, rd flags)
    case MOp::CMOVCC: return "cmovne"; // representante (r+w dst, rd flags)
    case MOp::BSWAP: return "bswap";
    case MOp::ROL: return "rol";
    case MOp::ROR: return "ror";

    /* FP escalar f64 / f32. */
    case MOp::MOVQ_GP_XMM:
    case MOp::MOVQ_XMM_GP: return "movq";
    case MOp::SQRTSD: return "sqrtsd";
    case MOp::MINSD: return "minsd";
    case MOp::MAXSD: return "maxsd";
    case MOp::ROUNDSD: return "roundsd";
    case MOp::ADDSD: return "addsd";
    case MOp::SUBSD: return "subsd";
    case MOp::MULSD: return "mulsd";
    case MOp::DIVSD: return "divsd";
    case MOp::CVTSI2SD: return "cvtsi2sd";
    case MOp::CVTTSD2SI: return "cvttsd2si";
    case MOp::UCOMISD: return "ucomisd";
    case MOp::CVTSS2SD: return "cvtss2sd";
    case MOp::CVTSD2SS: return "cvtsd2ss";
    case MOp::MOVSD: return "movsd";
    case MOp::MOVSS: return "movss";
    case MOp::ADDSS: return "addss";
    case MOp::SUBSS: return "subss";
    case MOp::MULSS: return "mulss";
    case MOp::DIVSS: return "divss";
    case MOp::SQRTSS: return "sqrtss";
    case MOp::UCOMISS: return "ucomiss";
    case MOp::CVTSI2SS: return "cvtsi2ss";
    case MOp::CVTTSS2SI: return "cvttss2si";
    case MOp::XORPS: return "xorps";
    case MOp::ANDPS: return "andps";

    /* Packed SSE2 (f64/f32/int). */
    case MOp::ADDPD: return "addpd";
    case MOp::SUBPD: return "subpd";
    case MOp::MULPD: return "mulpd";
    case MOp::DIVPD: return "divpd";
    case MOp::MOVUPD: return "movupd";
    case MOp::MOVAPD: return "movapd";
    case MOp::SQRTPD: return "sqrtpd";
    case MOp::XORPD: return "xorpd";
    case MOp::ANDPD: return "andpd";
    case MOp::UNPCKLPD: return "unpcklpd";
    case MOp::ADDPS: return "addps";
    case MOp::SUBPS: return "subps";
    case MOp::MULPS: return "mulps";
    case MOp::DIVPS: return "divps";
    case MOp::PADDD: return "paddd";
    case MOp::PSUBD: return "psubd";
    case MOp::PADDQ: return "paddq";
    case MOp::PSUBQ: return "psubq";
    case MOp::PADDW: return "paddw";
    case MOp::PSUBW: return "psubw";
    case MOp::PMULLW: return "pmullw";
    case MOp::PADDB: return "paddb";
    case MOp::PSUBB: return "psubb";
    case MOp::PMULLD: return "pmulld";

    /* AVX 3-operandos no destructivos. */
    case MOp::VADDSD: return "vaddsd";
    case MOp::VSUBSD: return "vsubsd";
    case MOp::VMULSD: return "vmulsd";
    case MOp::VDIVSD: return "vdivsd";
    case MOp::VADDSS: return "vaddss";
    case MOp::VSUBSS: return "vsubss";
    case MOp::VMULSS: return "vmulss";
    case MOp::VDIVSS: return "vdivss";
    case MOp::VXORPS: return "vxorps";
    case MOp::VANDPS: return "vandps";
    case MOp::VFMADD231PD: return "vfmadd231pd";
    case MOp::VFMADD231PS: return "vfmadd231ps";
    case MOp::VFMSUB231PD: return "vfmsub231pd";
    case MOp::VFMSUB231PS: return "vfmsub231ps";
    /* Y sus versiones ESCALARES, que estaban sin nombrar: las cuatro de arriba
     * si estaban y estas cuatro no.  Nadie se entero porque el caso por defecto
     * las recogia dando por leido y escrito todo, o sea "no se sabe" con otro
     * nombre; en cuanto ese caso desaparecio, saltaron. */
    case MOp::VFMADD231SD: return "vfmadd231sd";
    case MOp::VFMADD231SS: return "vfmadd231ss";
    case MOp::VBROADCASTSD: return "vbroadcastsd";
    case MOp::VBROADCASTSS: return "vbroadcastss";
    case MOp::SHUFPS: return "shufps";

    default: return nullptr; // pseudo de VestaVM
    }
}


/// @brief Clave uniforme de un operando REG/VREG, o @c UINT32_MAX si no lo es.
uint32_t reg_key(const MOperand &o) {
    if (o.kind == MOperandKind::REG) return o.reg;
    if (o.kind == MOperandKind::VREG)
        return MEffects::VREG_BASE + static_cast<uint32_t>(o.value);
    return UINT32_MAX;
}

/// @brief Los registros de DIRECCION de un operando de memoria: siempre leidos.
void add_mem_addr_reads(MEffects &e, const MOperand &o) {
    if (o.kind != MOperandKind::MEM) return;
    add_reg(e.reads, o.reg); // la base
    const uint8_t index = (o.width >> 2) & 0x3F;
    if (index != static_cast<uint8_t>(MReg::NONE)) add_reg(e.reads, index);
}

/**
 * @brief Los registros que un PSEUDO de VestaVM toca en x86 sin nombrarlos.
 *
 * Aqui SOLO estan los pseudos cuya respuesta nombra un registro concreto de
 * x86.  Los que no dependen de la arquitectura -- marcar un argumento, definir
 * una etiqueta, una barrera, una carga generica -- los contesta el modulo comun
 * antes de llegar aqui, y por eso no aparecen.
 *
 * @return @c false si x86 no define ese pseudo.
 */
bool pseudo(const MInstr &mi, MEffects &e) {
    switch (mi.op) {
    /* PUSH src: lee src y rsp, escribe rsp y memoria. */
    case MOp::PUSH:
        add_reg(e.reads, reg_key(mi.dst));  // el operando viaja en dst
        add_reg(e.reads, reg_key(mi.src1)); // (o en src1, segun el selector)
        add_reg(e.reads, static_cast<uint8_t>(MReg::RSP));
        add_reg(e.writes, static_cast<uint8_t>(MReg::RSP));
        e.writes_mem = true;
        return true;
    /* POP dst: escribe dst y rsp, lee rsp y memoria. */
    case MOp::POP:
        add_reg(e.writes, reg_key(mi.dst));
        add_reg(e.reads, static_cast<uint8_t>(MReg::RSP));
        add_reg(e.writes, static_cast<uint8_t>(MReg::RSP));
        e.reads_mem = true;
        return true;

    /* La division baja a `idiv`, que usa RDX:RAX como dividendo y deja ahi el
     * cociente y el resto.  Se declara para que un uso posterior de esos dos
     * dependa de esta operacion en vez de leer lo que hubiera antes. */
    case MOp::DIVMOD_V:
        add_reg(e.writes, reg_key(mi.dst));
        add_reg(e.reads, reg_key(mi.src1));
        add_reg(e.reads, reg_key(mi.src2));
        add_reg(e.writes, static_cast<uint8_t>(MReg::RAX));
        add_reg(e.writes, static_cast<uint8_t>(MReg::RDX));
        e.writes_flags = true;
        return true;

    /* El intercambio condicional baja a `cmpxchg`, que compara contra RAX y
     * deja ahi el valor anterior. */
    case MOp::ATOMICCAS_V: // dst entra con lo esperado y sale con lo que habia
        add_reg(e.reads, reg_key(mi.dst));
        add_reg(e.writes, reg_key(mi.dst));
        add_reg(e.reads, reg_key(mi.src1));
        add_reg(e.reads, reg_key(mi.src2));
        add_reg(e.writes, static_cast<uint8_t>(MReg::RAX));
        e.reads_mem = true;
        e.writes_mem = true;
        e.writes_flags = true;
        return true;
    case MOp::LOCK_CMPXCHG:
        add_reg(e.reads, reg_key(mi.src1));
        add_reg(e.reads, static_cast<uint8_t>(MReg::RAX));
        add_reg(e.writes, static_cast<uint8_t>(MReg::RAX));
        add_mem_addr_reads(e, mi.dst);
        e.reads_mem = true;
        e.writes_mem = true;
        e.writes_flags = true;
        return true;

    /* Las instrucciones de CADENA: copiar y rellenar memoria en una sola
     * instruccion, con TODOS sus operandos implicitos.
     *
     *   - `rep movsb` copia de RSI a RDI, RCX veces;
     *   - `rep stosb` rellena desde RDI, RCX veces, con lo que hay en AL.
     *
     * Ninguno los nombra, asi que quien mire solo los operandos ve una
     * instruccion que no lee nada y da por muertas las tres que la preparan.
     * `183_memcpy_idiom` devolvia 0 en vez de 597 por eso -- y por una sola de
     * las dos: `rep movsb` ya estaba declarado y `rep stosb` no, que es como
     * falla una lista escrita a mano. */
    case MOp::REP_MOVSB:
    case MOp::REP_STOSB:
        add_reg(e.reads, static_cast<uint8_t>(MReg::RDI));  // a donde
        add_reg(e.reads, static_cast<uint8_t>(MReg::RCX));  // cuantos
        add_reg(e.writes, static_cast<uint8_t>(MReg::RDI));
        add_reg(e.writes, static_cast<uint8_t>(MReg::RCX));
        if (mi.op == MOp::REP_MOVSB) {
            add_reg(e.reads, static_cast<uint8_t>(MReg::RSI)); // de donde
            add_reg(e.writes, static_cast<uint8_t>(MReg::RSI));
            e.reads_mem = true;
        } else {
            add_reg(e.reads, static_cast<uint8_t>(MReg::RAX)); // el byte
        }
        e.writes_mem = true;
        return true;

    /* Salvar y restaurar los registros de la maquina virtual en la zona de
     * trabajo del marco: se apoyan en R11, que el reparto tiene reservado. */
    case MOp::CB_SAVE_REGS:
    case MOp::CB_RESTORE_REGS:
        add_reg(e.writes, static_cast<uint8_t>(MReg::R11));
        e.reads_mem = true;
        e.writes_mem = true;
        return true;

    default: return false; // que lo diga quien pregunta
    }
}

/**
 * @brief Si escribir en @p o deja intacto el RESTO del registro.
 *
 * Dos cosas distintas lo hacen estrecho, y hacen falta las dos:
 *
 *   - el ANCHO del operando: escribir `al` o `ax` conserva los demas bytes.
 *     De cuatro NO, que ahi el procesador pone a cero la mitad alta y por tanto
 *     es dueno del registro entero;
 *   - el OPCODE, cuando la instruccion escribe menos de lo que su operando
 *     mide.  `setcc` es el caso: su destino se nombra como el registro entero
 *     -- el ancho ahi describe el VALOR, un booleano de ocho bytes -- pero solo
 *     toca el byte bajo, y quien limpia el resto es el `mov` de delante.  Sin
 *     esto, `81_math_builtins` devolvia 2 en vez de 42.
 */
bool is_narrow_write(const MInstr &mi, const MOperand &o) {
    if (o.kind != MOperandKind::REG) return false;
    return mi.op == MOp::SETCC || o.width < 4;
}

/// El descriptor del objetivo.  Se pide sin reservar el banco ancho porque de
/// el solo se consulta la CONVENCION de llamada, que no depende de eso.
const TargetRegInfo &reg_info() {
    return target_x86_64_vm_abi(/*vec_acc=*/false, /*fp_scratch=*/false);
}

const IsaEffects kX86 = {
    "x86", mnemonic, regset_key, reg_info, pseudo, is_narrow_write,
};

} // namespace

const IsaEffects &isa_effects_x86() { return kX86; }

} // namespace sched
} // namespace jit
