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
 * @file jit/sched/isa_effects_arm64.cpp
 * @brief Lo que de los efectos de una instruccion sabe SOLO arm64.
 *
 * Ver @ref jit/sched/isa_effects.h para por que esto vive aparte del modulo
 * comun.  Aqui se nombran registros de AArch64 y nada mas; quien quiera los de
 * x86 va a su fichero.
 */

#include "jit/sched/isa_effects.h"
#include "jit/sched/machine_effects.h"

#include <string>

namespace jit {
namespace sched {
namespace {

/// Base del espacio de claves para lo que NO tiene hueco propio en el banco
/// (NZCV, FPCR/FPSR, sp/zr, sistema): se rastrea por su indice en el pool de
/// cadenas, asi que el mismo nombre da siempre la misma clave.
constexpr uint32_t SPECIAL_BASE = 1u << 21;

/// @brief Sufijo numerico de un nombre de registro tras un prefijo de N letras
///        ("X12" -> 12).  -1 si no hay digitos validos.
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
 *        USANDO LA MISMA NUMERACION que el objetivo arm64 del pipeline vreg
 *        (@c build_arm64_target).
 *
 * GP x/w n -> n (0-30); FP/SIMD v/q/d/s/h/b n -> 32+n (32-63).  Asi un registro
 * implicito de la base coincide con el operando explicito que nombra el mismo
 * registro.  sp/zr/PC y el resto de lo del sistema, por nombre.
 */
uint32_t regset_key(const char *rs, uint16_t regset_idx) {
    if (rs == nullptr || rs[0] == '\0' || rs[0] == '-') return UINT32_MAX;
    for (const char *p = rs; *p; ++p)
        if (*p == '/') return UINT32_MAX; // una CLASE, no un registro concreto
    const std::string s(rs);
    if (s == "SP" || s == "WSP" || s == "XZR" || s == "WZR" || s == "PC")
        return SPECIAL_BASE + regset_idx;
    const char c = s[0];
    const bool gp = (c == 'X' || c == 'W');
    const bool fp =
        (c == 'V' || c == 'Q' || c == 'D' || c == 'S' || c == 'H' || c == 'B');
    if (gp || fp) {
        const int n = suffix_num(s, 1);
        if (gp && n >= 0 && n <= 30) return static_cast<uint32_t>(n);
        if (fp && n >= 0 && n <= 31) return static_cast<uint32_t>(32 + n);
    }
    return SPECIAL_BASE + regset_idx; // NZCV/FPCR/FPSR/sistema/...
}

/**
 * @brief Como se llama @p op en el ensamblador de arm64.
 *
 * Los MOp enteros genericos se comparten; los @c A64_* son propios.  Los saltos
 * y las llamadas (b/bl/ret/cbz) NO se mapean a proposito: sus efectos no son de
 * la instruccion sino de la CONVENCION, y de eso se encarga el modulo comun
 * leyendo el descriptor del objetivo.
 */
const char *mnemonic(MOp op) {
    switch (op) {
    case MOp::MOV: return "mov";
    case MOp::ADD: return "add";
    case MOp::SUB: return "sub";
    case MOp::AND: return "and";
    case MOp::OR: return "orr";
    case MOp::XOR: return "eor";
    case MOp::SHL: return "lsl";
    case MOp::SHR: return "lsr";
    case MOp::SAR: return "asr";
    case MOp::NEG: return "neg";
    case MOp::NOT: return "mvn";
    case MOp::CMP: return "cmp";
    case MOp::LOAD: return "ldr";
    case MOp::STORE: return "str";
    case MOp::A64_UDIV: return "udiv";
    case MOp::A64_SDIV: return "sdiv";
    case MOp::A64_MADD: return "madd";
    case MOp::A64_MSUB: return "msub";
    case MOp::A64_CSEL: return "csel";
    case MOp::A64_CSET: return "cset";
    case MOp::A64_MVN: return "mvn";
    case MOp::A64_MOVZ: return "movz";
    case MOp::A64_MOVK: return "movk";
    case MOp::A64_SXTB: return "sxtb";
    case MOp::A64_UXTB: return "uxtb";
    case MOp::A64_FADD: return "fadd";
    case MOp::A64_FSUB: return "fsub";
    case MOp::A64_FMUL: return "fmul";
    case MOp::A64_FDIV: return "fdiv";
    case MOp::A64_FCMP: return "fcmp";
    case MOp::A64_FMOV: return "fmov";
    case MOp::A64_FNEG: return "fneg";
    case MOp::A64_FABS: return "fabs";
    case MOp::A64_FSQRT: return "fsqrt";
    case MOp::A64_SCVTF: return "scvtf";
    case MOp::A64_UCVTF: return "ucvtf";
    case MOp::A64_FCVTZS: return "fcvtzs";
    case MOp::A64_FCVTZU: return "fcvtzu";
    case MOp::A64_FCVT: return "fcvt";
    default: return nullptr; // un pseudo: lo contesta @c pseudo
    }
}

/**
 * @brief Los registros que un PSEUDO de VestaVM toca en arm64 sin nombrarlos.
 *
 * Aqui solo estan los pseudos cuya respuesta depende de la arquitectura.  Los
 * que no dependen -- marcar un argumento, definir una etiqueta, una barrera --
 * los contesta el modulo comun antes de llegar aqui.
 *
 * @return @c false si arm64 no define ese pseudo.  Eso NO es una duda que se
 *         pueda tapar con una barrera: es que falta declararlo, y quien
 *         pregunta lo hara saltar.
 */
bool pseudo(const MInstr &mi, MEffects &e) {
    switch (mi.op) {
    /* La pila: `str`/`ldr` con post/pre-indice sobre sp.  sp no es un registro
     * asignable y por eso va por su nombre, igual que en la base. */
    case MOp::PUSH:
    case MOp::POP:
        add_reg(e.reads, static_cast<uint32_t>(A64_SP));
        add_reg(e.writes, static_cast<uint32_t>(A64_SP));
        e.reads_mem = (mi.op == MOp::POP);
        e.writes_mem = (mi.op == MOp::PUSH);
        return true;
    default: return false; // que lo diga quien pregunta
    }
}

/**
 * @brief Si escribir en @p o deja intacto el resto del registro.
 *
 * En arm64 NUNCA: no hay escrituras de uno o dos bytes a un registro, y una
 * `w` de cuatro pone a cero la mitad alta, que es lo mismo que escribirlo
 * entero.  Se dice explicitamente en vez de dejarlo sin implementar para que se
 * lea como una AFIRMACION sobre la arquitectura y no como un hueco.
 */
bool is_narrow_write(const MInstr & /*mi*/, const MOperand & /*o*/) {
    return false;
}

/// El descriptor del objetivo, de donde sale la convencion de llamada.
const TargetRegInfo &reg_info() {
    return target_arm64();
}

const IsaEffects kArm64 = {
    "arm64", mnemonic, regset_key, reg_info, pseudo, is_narrow_write,
};

} // namespace

const IsaEffects &isa_effects_arm64() {
    return kArm64;
}

} // namespace sched
} // namespace jit
