/* * VestaVM -- frontend x86 del lift de asm a IR.
 * Copyright (C) 2026 David Lopez.T (DesmonHak).  GPLv2 + excepcion de runtime.
 */

/** @file vx/asm/asm_lift_x86.cpp
 *  @brief Frontend x86/x86-64 del lift de asm inline a IR neutro.  Reconoce el
 *  subset (mnemonicos + registros + direccionamiento x86) y lo baja al IR via
 * el core NEUTRO (@ref asm_lift_core.h: emisores, register-file, driver del
 * CFG). Ver asm_lift_x86.h. */
#include "util/env_flags.h"
#include "vx/asm/asm_lift_x86.h"

#include <cstdio>
#include <cstdlib>

#include "vx/asm/asm_cfg.h"       // build_asm_cfg
#include "vx/asm/asm_effects.h"   // asm_canonical_reg
#include "vx/asm/asm_lift_core.h" // core neutro
#include "vx/asm/asm_phys_reg.h"  // asm_x86_gp_index

#include <cctype>
#include <cstdlib>
#include <string>
#include <vector>

namespace vx {

// Traer al ambito los helpers NEUTROS del core (emisores, utilidades de texto,
// LiftCtx / CfgHooks / lift_cfg_neutral).  El frontend x86 los usa por nombre.
using namespace vx::asmlift;

namespace {

/// Un termino del modo de direccionamiento x86 @c [base + index*scale + disp].
struct MemAddr {
    std::string base;  ///< registro base canonico ("" si no hay)
    std::string index; ///< registro index canonico ("" si no hay)
    int64_t scale = 1; ///< 1/2/4/8
    int64_t disp = 0;  ///< desplazamiento constante
    bool ok = false;   ///< true si @p op es una memoria [ ... ] valida
};

/// Parsea CUALQUIER modo de direccionamiento x86 @c [base + index*scale + disp]
/// (base, index*scale, disp opcionales; el prefijo @c "qword ptr" se ignora).
/**
 * @brief Renunciar a elevar diciendo DONDE.
 *
 * El lift tenia noventa y seis salidas por renuncia y ninguna decia nada: la
 * instruccion se quedaba sin representar en el IR y el unico rastro era que
 * aparecia como micro asm.  Con la linea se llega al sitio en un paso.
 *
 * @param que Instruccion o fragmento que no se pudo elevar.
 * @param linea Linea del lift donde se renuncio.
 * @return Siempre @c false, para escribirlo como @c return lift_no(...).
 */
inline bool lift_no(const std::string &que, int linea) {
    static const bool on = util::flag_on(util::FlagId::AsmLiftDebug);
    if (on)
        std::fprintf(stderr, "[asm-lift] no se eleva %s (x86:%d)\n",
                     que.c_str(), linea);
    return false;
}

MemAddr parse_mem(const std::string &opr) {
    MemAddr a;
    std::string op = trim(opr);
    // Ignorar el size-hint tipo "qword ptr [..]".
    const size_t br = op.find('[');
    if (br == std::string::npos || op.back() != ']') return a;
    std::string in = trim(op.substr(br + 1, op.size() - br - 2));
    // Trocear por + / - conservando el signo del termino.
    std::vector<std::pair<int, std::string>> terms; // (signo, token)
    int sign = 1;
    std::string tok;
    auto flush = [&]() {
        std::string t = trim(tok);
        if (!t.empty()) terms.push_back({sign, t});
        tok.clear();
    };
    for (char c : in) {
        if (c == '+') {
            flush();
            sign = 1;
        } else if (c == '-') {
            flush();
            sign = -1;
        } else
            tok += c;
    }
    flush();
    for (auto &pr : terms) {
        const std::string &t = pr.second;
        const size_t star = t.find('*');
        if (star != std::string::npos) { // index*scale
            const std::string ir = asm_canonical_reg(trim(t.substr(0, star)));
            int64_t sc = 0;
            if (ir.empty() || !parse_imm(trim(t.substr(star + 1)), sc))
                return a;
            a.index = ir;
            a.scale = sc;
            continue;
        }
        int64_t d = 0;
        if (parse_imm(t, d)) {
            a.disp += pr.first * d;
            continue;
        }
        /* Un marcador de ligadura automatica tambien puede ser la base: es la
         * forma normal de escribir una direccion a partir de una variable. */
        std::string r;
        if (t.size() >= 2 && t[0] == '$' &&
            t.find_first_not_of("0123456789", 1) == std::string::npos)
            r = t;
        else
            r = asm_canonical_reg(t);
        if (r.empty()) return a;
        if (a.base.empty())
            a.base = r;
        else if (a.index.empty()) {
            a.index = r;
            a.scale = 1;
        } else
            return a; // >2 registros: no soportado
    }
    a.ok = true;
    return a;
}

/// ¿Es @p op un operando de memoria @c [ ... ]?
bool is_mem(const std::string &op) {
    return op.find('[') != std::string::npos && trim(op).back() == ']';
}

/// Ancho en bits de un size-hint de memoria (@c byte/word/dword/qword @c ptr).
/// 0 si no hay hint explicito (el ancho lo aporta el registro del otro
/// operando).
int mem_hint_width(const std::string &op) {
    const size_t br = op.find('[');
    if (br == std::string::npos) return 0;
    std::string pre;
    for (char c : op.substr(0, br))
        pre.push_back((char)std::tolower((unsigned char)c));
    pre = trim(pre);
    const std::string hint = pre.substr(0, pre.find(' '));
    if (hint == "byte") return 8;
    if (hint == "word") return 16;
    if (hint == "dword") return 32;
    if (hint == "qword") return 64;
    return 0;
}

/// Mapea el sufijo de un @c setCC (lo que sigue a "set") al IrOp de comparacion
/// y su signedness (para leer los operandos del cmp con signo/sin signo).  Para
/// eq/ne el signo es irrelevante (se usa sin signo).  @c false si no se conoce.
bool setcc_to_cmp(const std::string &cc, ir::IrOp &op, bool &sgn) {
    sgn = false;
    if (cc == "e" || cc == "z") {
        op = ir::IrOp::CMP_EQ;
        return true;
    }
    if (cc == "ne" || cc == "nz") {
        op = ir::IrOp::CMP_NE;
        return true;
    }
    sgn = true;
    if (cc == "l" || cc == "nge") {
        op = ir::IrOp::CMP_LT;
        return true;
    }
    if (cc == "g" || cc == "nle") {
        op = ir::IrOp::CMP_GT;
        return true;
    }
    if (cc == "le" || cc == "ng") {
        op = ir::IrOp::CMP_LE;
        return true;
    }
    if (cc == "ge" || cc == "nl") {
        op = ir::IrOp::CMP_GE;
        return true;
    }
    sgn = false;
    if (cc == "b" || cc == "c" || cc == "nae") {
        op = ir::IrOp::CMP_ULT;
        return true;
    }
    if (cc == "a" || cc == "nbe") {
        op = ir::IrOp::CMP_UGT;
        return true;
    }
    if (cc == "be" || cc == "na") {
        op = ir::IrOp::CMP_ULE;
        return true;
    }
    if (cc == "ae" || cc == "nb" || cc == "nc") {
        op = ir::IrOp::CMP_UGE;
        return true;
    }
    return false; // cc no soportado (o/no/s/ns/p/np...) -> el par no encaja
}

/// IrOp binario (2-address: dst = dst OP src) para un mnemonico ALU x86.
bool binop_of(const std::string &m, ir::IrOp &op) {
    if (m == "add") {
        op = ir::IrOp::ADD;
        return true;
    }
    if (m == "sub") {
        op = ir::IrOp::SUB;
        return true;
    }
    if (m == "imul") {
        op = ir::IrOp::MUL;
        return true;
    }
    if (m == "and") {
        op = ir::IrOp::AND;
        return true;
    }
    if (m == "or") {
        op = ir::IrOp::OR;
        return true;
    }
    if (m == "xor") {
        op = ir::IrOp::XOR;
        return true;
    }
    if (m == "shl" || m == "sal") {
        op = ir::IrOp::SHL;
        return true;
    }
    if (m == "shr") {
        op = ir::IrOp::SHR;
        return true;
    }
    if (m == "sar") {
        op = ir::IrOp::SAR;
        return true;
    }
    return false;
}

/// (canon, ancho, byte-alto).  Devuelve el ancho en bits (8/16/32/64) del
/// registro GP @p tok, 0 si no es un GP entero nombrable (vector/desconocido).
int reg_info(const std::string &tok, std::string &canon, bool &is_high) {
    is_high = false;
    std::string s;
    s.reserve(tok.size());
    for (char c : tok)
        s.push_back((char)std::tolower((unsigned char)c));
    // trim
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a]))
        ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1]))
        --b;
    s = s.substr(a, b - a);
    /* Un marcador de ligadura automatica ("$0") es un registro: solo que lo
     * elige el compilador en vez de nombrarlo el programador.  Sin esto, la
     * forma normal de escribir -- `reg d = p` -- no se reconoce y la
     * instruccion se queda sin representar aunque el IR la tenga. */
    if (s.size() >= 2 && s[0] == '$' &&
        s.find_first_not_of("0123456789", 1) == std::string::npos) {
        canon = s;
        return 64; // el ancho real lo dice su ligadura
    }
    canon = asm_canonical_reg(s);
    if (canon.empty()) return 0;   // no es registro (o arch no x86)
    if (canon[0] == 'v') return 0; // vector (xmm/ymm/zmm) -> no GP entero
    if (s == "ah" || s == "bh" || s == "ch" || s == "dh") {
        is_high = true;
        return 8;
    }
    uint16_t w = 0;
    const int idx = vx::asm_x86_gp_index(s, &w);
    if (idx >= 0) return (int)w;
    return 0; // canon no vacio pero ancho desconocido -> conservador
}

} // namespace

/** @brief Lifter x86/x86-64: reconoce el subset entero y lo baja a IR neutro.
 *  Straight-line (1 bloque) o con RAMAS: construye el CFG del asm y lo baja a
 *  IR-CFG via el driver NEUTRO (@ref lift_cfg_neutral), aportando los hooks x86
 *  (lift de instrucciones + condicion de rama).  reg_info/binop_of/parse_mem/
 *  mem_hint_width/setcc_to_cmp son la parte x86.  @p out_exit (si != null)
 * queda con el bloque de continuacion (donde sigue el codigo tras el asm). */
bool lift_x86(ir::IrFunction &fn, uint32_t block, const std::string &body,
              const std::unordered_map<std::string, AsmBoundReg> &bound,
              uint32_t line, uint32_t *out_exit) {
    // El CFG (por-ISA) trocea el body en bloques basicos + aristas.  Usamos su
    // lista de instrucciones (mismo troceo que instructions()) para indexar los
    // bloques de forma consistente.  Anadimos un `nop` centinela al final: una
    // etiqueta de SALIDA colocada al final (idioma comun `... jCC end; ...;
    // end:`) la ancla `build_asm_cfg` a un `nop` sintetico (bloque real que cae
    // a la continuacion) -> el salto a esa etiqueta resuelve.
    const vx::AsmCfg cfg = vx::build_asm_cfg(vx::instr_db::Isa::X86, body);
    std::vector<std::string> insns;
    insns.reserve(cfg.insns.size());
    for (const auto &in : cfg.insns)
        insns.push_back(in.text);
    if (insns.empty()) return lift_no("<bloque>", __LINE__);
    /* Ramas no resueltas / terminadores desconocidos -> no liftamos (opaco).
     *
     * Un salto que SALE del bloque hacia una funcion del modulo tampoco se
     * eleva: el grafo local es correcto, pero el IR tendria que representar un
     * salto a algo que no esta aqui.  Va aparte de `has_unresolved_target`
     * porque no es un error del usuario -- solo un limite de esto. */
    if (cfg.has_unresolved_target || cfg.has_external_target ||
        !cfg.unknown_terminators.empty())
        return lift_no("<bloque>", __LINE__);

    // Estado SSA por registro: cur[canon] = valor ARQUITECToNICO COMPLETO de
    // 64 bits del registro fisico (rax), con los bits altos correctos segun las
    // reglas de x86.  wrote = registros LIGADOS escritos (para el flush).
    std::unordered_map<std::string, ir::IrValueId> cur;
    std::vector<std::string> wrote;
    auto mark_write = [&](const std::string &r) {
        if (bound.find(r) == bound.end()) return; // temporal -> sin write-back
        for (const std::string &w : wrote)
            if (w == r) return;
        wrote.push_back(r);
    };

    // Emisores cortos.
    auto K = [&](int64_t v) { return emit_const(fn, block, v, line); };
    auto BIN = [&](ir::IrOp op, ir::IrValueId a, ir::IrValueId b) {
        return emit_bin(fn, block, op, a, b, line);
    };
    // Los @p w bits bajos de @p v, zero-extendidos (AND con la mascara).
    auto and_mask = [&](ir::IrValueId v, int w) -> ir::IrValueId {
        if (w >= 64) return v;
        return BIN(ir::IrOp::AND, v, K((int64_t)width_mask(w)));
    };
    // Los @p w bits bajos de @p v, sign-extendidos a 64 (SHL 64-w; SAR 64-w).
    auto sext_low = [&](ir::IrValueId v, int w) -> ir::IrValueId {
        if (w >= 64) return v;
        return BIN(ir::IrOp::SAR, BIN(ir::IrOp::SHL, v, K(64 - w)), K(64 - w));
    };

    // Valor completo de 64 bits de un registro: si esta en cur, ese; si esta
    // ligado, lo carga de su slot al ancho del var (zero-extendido); si no,
    // falla (registro no-ligado leido antes de escribirse).
    auto get_full = [&](const std::string &canon, bool &ok) -> ir::IrValueId {
        ok = true;
        auto it = cur.find(canon);
        if (it != cur.end()) return it->second;
        auto b = bound.find(canon);
        if (b == bound.end()) {
            ok = false;
            return 0;
        }
        // El slot del var register-bound conserva su naturaleza (host/VM) en el
        // flag del valor del ALLOCA: lo respetamos (los register() suelen vivir
        // en memoria host -- alloc + movh).
        const bool slot_host = fn.values[b->second.slot].is_host_ptr;
        const ir::IrValueId v = emit_load(
            fn, block, b->second.slot, b->second.width_bits, slot_host, line);
        cur[canon] = v;
        return v;
    };
    // Lee un registro al ancho @p w (byte-alto @p is_high), con signo si @p
    // sgn.
    auto read_reg = [&](const std::string &canon, int w, bool is_high, bool sgn,
                        bool &ok) -> ir::IrValueId {
        ir::IrValueId full = get_full(canon, ok);
        if (!ok) return 0;
        ir::IrValueId v = is_high ? BIN(ir::IrOp::SHR, full, K(8)) : full;
        if (w >= 64) return v;
        return sgn ? sext_low(v, w) : and_mask(v, w);
    };
    // Lee un OPERANDO (registro o inmediato) al ancho @p w.
    auto read_op = [&](const std::string &op, int w, bool sgn,
                       bool &ok) -> ir::IrValueId {
        int64_t imm = 0;
        if (parse_imm(op, imm)) {
            ok = true;
            return K(imm);
        }
        std::string canon;
        bool is_high = false;
        const int rw = reg_info(op, canon, is_high);
        if (rw == 0) {
            ok = false;
            return 0;
        }
        return read_reg(canon, w, is_high, sgn, ok);
    };
    // Escribe @p r en @p canon al ancho @p w con la semantica x86: 64 pisa
    // todo; 32 pone a cero los altos; 8/16 (y byte-alto) preservan los altos ->
    // necesitan el valor previo.  Devuelve false si un parcial 8/16 no tiene
    // valor previo (registro no-ligado sin escribir) -> el bloque no es
    // liftable.
    auto write_reg = [&](const std::string &canon, int w, bool is_high,
                         ir::IrValueId r, bool &ok) {
        ok = true;
        if (w >= 64) {
            cur[canon] = r;
            mark_write(canon);
            return;
        }
        if (w == 32) {
            cur[canon] = and_mask(r, 32);
            mark_write(canon);
            return;
        }
        // 8/16: combinar con los bits altos previos.
        bool have = true;
        const ir::IrValueId old = get_full(canon, have);
        if (!have) {
            ok = false;
            return;
        } // sin previo -> no modelable
        ir::IrValueId nv;
        if (is_high) { // ah/bh/ch/dh -> bits 8..15
            const ir::IrValueId lo = BIN(ir::IrOp::SHL, and_mask(r, 8), K(8));
            const ir::IrValueId keep =
                BIN(ir::IrOp::AND, old, K((int64_t)~0xFF00ull));
            nv = BIN(ir::IrOp::OR, keep, lo);
        } else {
            const ir::IrValueId lo = and_mask(r, w);
            const ir::IrValueId keep =
                BIN(ir::IrOp::AND, old, K((int64_t)~width_mask(w)));
            nv = BIN(ir::IrOp::OR, keep, lo);
        }
        cur[canon] = nv;
        mark_write(canon);
    };

    // Direccion (SSA) de un operando de memoria [base + index*scale + disp]. El
    // asm SIEMPRE usa memoria HOST; el consumidor (lea/mov/movzx/movsx) emite
    // el load/store HOST con esta direccion.  @p okr=false si algun termino no
    // es GP.
    auto mem_addr_of = [&](const MemAddr &ma, bool &okr) -> ir::IrValueId {
        okr = true;
        ir::IrValueId acc = 0;
        bool have = false;
        if (!ma.base.empty()) {
            acc = get_full(ma.base, okr);
            if (!okr) return 0;
            have = true;
        }
        if (!ma.index.empty()) {
            ir::IrValueId idx = get_full(ma.index, okr);
            if (!okr) return 0;
            if (ma.scale != 1) idx = BIN(ir::IrOp::MUL, idx, K(ma.scale));
            acc = have ? BIN(ir::IrOp::ADD, acc, idx) : idx;
            have = true;
        }
        if (ma.disp != 0 || !have) {
            const ir::IrValueId d = K(ma.disp);
            acc = have ? BIN(ir::IrOp::ADD, acc, d) : d;
        }
        return acc;
    };

    // === FLAGS como pseudo-registro SSA ===
    // Modelamos EFLAGS como estado del register-file: cmp/test las DEFINEN
    // (capturan sus operandos); setcc/cmovcc/jCC las LEEN.  Asi el consumidor
    // no tiene que ir ADYACENTE al cmp (las instrucciones flag-neutral entre
    // medias no las tocan) y el MISMO modelo sirve para setcc, cmov y las ramas
    // del CFG
    // -- sin patrones especificos.  Bloque-local (se resetean por bloque).
    struct FlagsInfo {
        bool valid = false;
        bool is_test = false;     // flags de un `test` (a&b vs 0)
        bool from_result = false; // flags de una ALU: solo ZF (result==0)
        ir::IrValueId a = 0,
                      b = 0; // valores FULL 64b capturados en el cmp/test
        int width = 64;
        bool a_high = false, b_high = false;
        // Carry-flag (CF) modelado APARTE, para adc/sbb (aritmetica
        // multi-palabra 64-bit).  has_cf=true si @c cf (SSA 0/1) es el CF que
        // dejo un add/sub/ adc/sbb de 64 bits inmediatamente antes en la
        // cadena.
        bool has_cf = false;
        ir::IrValueId cf = 0;
    };
    FlagsInfo flags;

    // ALU (no-shift) que definen ZF=result==0 de forma incondicional -> un
    // jz/jnz/setz posterior las lee.  (add/sub/and/or/xor/inc/dec/neg; las
    // magnitudes/carry no las modelamos -> flags_cond hace bail en esos cc.)
    auto sets_result_flags = [](const std::string &m) -> bool {
        return m == "add" || m == "sub" || m == "and" || m == "or" ||
               m == "xor" || m == "inc" || m == "dec" || m == "neg" ||
               m == "adc" || m == "sbb";
    };
    // Parte ALTA de un producto 64x64->128 SIN SIGNO, via descomposicion en
    // mitades de 32 bits (multiplicacion escolar).  Solo ops existentes
    // (MUL/AND/ SHR/ADD) -> sin op de IR nueva; el DCE la elimina si el
    // resultado (rdx) no se usa.  hi = a*b >> 64.
    auto umulhi = [&](ir::IrValueId a, ir::IrValueId b) -> ir::IrValueId {
        const ir::IrValueId M = K(0xFFFFFFFFll);
        const ir::IrValueId alo = BIN(ir::IrOp::AND, a, M);
        const ir::IrValueId ahi = BIN(ir::IrOp::SHR, a, K(32));
        const ir::IrValueId blo = BIN(ir::IrOp::AND, b, M);
        const ir::IrValueId bhi = BIN(ir::IrOp::SHR, b, K(32));
        const ir::IrValueId ll = BIN(ir::IrOp::MUL, alo, blo);
        const ir::IrValueId lh = BIN(ir::IrOp::MUL, alo, bhi);
        const ir::IrValueId hl = BIN(ir::IrOp::MUL, ahi, blo);
        const ir::IrValueId hh = BIN(ir::IrOp::MUL, ahi, bhi);
        // mid = (ll>>32) + (lh & 0xFFFFFFFF) + (hl & 0xFFFFFFFF).
        const ir::IrValueId mid =
            BIN(ir::IrOp::ADD,
                BIN(ir::IrOp::ADD, BIN(ir::IrOp::SHR, ll, K(32)),
                    BIN(ir::IrOp::AND, lh, M)),
                BIN(ir::IrOp::AND, hl, M));
        // hi = hh + (lh>>32) + (hl>>32) + (mid>>32).
        return BIN(ir::IrOp::ADD,
                   BIN(ir::IrOp::ADD,
                       BIN(ir::IrOp::ADD, hh, BIN(ir::IrOp::SHR, lh, K(32))),
                       BIN(ir::IrOp::SHR, hl, K(32))),
                   BIN(ir::IrOp::SHR, mid, K(32)));
    };
    // Parte ALTA de un producto 64x64->128 CON SIGNO: umulhi con la correccion
    // de Karatsuba/Warren  hi_s = hi_u - (a<0 ? b : 0) - (b<0 ? a : 0).
    auto smulhi = [&](ir::IrValueId a, ir::IrValueId b) -> ir::IrValueId {
        const ir::IrValueId uh = umulhi(a, b);
        const ir::IrValueId ta = BIN(ir::IrOp::SAR, a, K(63)); // 0 o -1
        const ir::IrValueId tb = BIN(ir::IrOp::SAR, b, K(63));
        const ir::IrValueId corr = BIN(ir::IrOp::ADD, BIN(ir::IrOp::AND, ta, b),
                                       BIN(ir::IrOp::AND, tb, a));
        return BIN(ir::IrOp::SUB, uh, corr);
    };

    // Siembra las flags "ZF de @p res al ancho @p w" (result==0) tras una ALU.
    auto flag_from_result = [&](ir::IrValueId res, int w) {
        flags.valid = true;
        flags.is_test = false;
        flags.from_result = true;
        flags.a = res;
        flags.b = 0;
        flags.width = w;
        flags.a_high = false;
        flags.b_high = false;
        flags.has_cf = false; // el CF lo fija el emisor (add/sub) si aplica
    };

    // ¿el mnemonico PRESERVA las flags? (no las escribe).  cmp/test las definen
    // aparte; setcc/cmov las leen pero no escriben; el resto de la ALU las
    // pisa.
    auto preserves_flags = [](const std::string &m) -> bool {
        if (m == "mov" || m == "movq" || m == "lea" || m == "movzx" ||
            m == "movsx" || m == "movsxd" || m == "nop" || m == "bswap" ||
            m == "xchg" || m == "cqo" || m == "cqto" || m == "cdq" ||
            m == "cdqe" || m == "cwde" || m == "cbw")
            return true;
        return (m.size() >= 3 && m.rfind("set", 0) == 0) ||
               (m.size() >= 4 && m.rfind("cmov", 0) == 0);
    };

    // Calcula la SSA (0/1) de la condicion @p cop (signo @p csigned) a partir
    // de las flags pendientes; @c IR_NO_VALUE si no hay flags usables.
    auto flags_cond = [&](ir::IrOp cop, bool csigned) -> ir::IrValueId {
        if (!flags.valid) return ir::IR_NO_VALUE;
        auto ext = [&](ir::IrValueId v, bool high, bool sgn) -> ir::IrValueId {
            ir::IrValueId x = high ? BIN(ir::IrOp::SHR, v, K(8)) : v;
            if (flags.width >= 64) return x;
            return sgn ? sext_low(x, flags.width) : and_mask(x, flags.width);
        };
        if (flags.from_result) {
            // ALU: ZF (result==0) via eq/ne siempre; jc/jnc (CF) si lo
            // modelamos (add/adc dejan flags.cf).  El resto (signo/magnitud,
            // OF) -> bail.
            if (cop == ir::IrOp::CMP_EQ || cop == ir::IrOp::CMP_NE) {
                const ir::IrValueId t = ext(flags.a, flags.a_high, false);
                return BIN(cop, t, K(0));
            }
            if (flags.has_cf && cop == ir::IrOp::CMP_ULT) // jc/jb = CF
                return flags.cf;
            if (flags.has_cf && cop == ir::IrOp::CMP_UGE) // jnc/jae = !CF
                return BIN(ir::IrOp::XOR, flags.cf, K(1));
            return ir::IR_NO_VALUE;
        }
        if (flags.is_test) {
            // test: flags de (a & b).  CF=OF=0 -> las cc sin signo no aplican;
            // eq/ne/l/g/le/ge -> (a&b) al ancho, con signo, comparado con 0.
            if (cop == ir::IrOp::CMP_ULT || cop == ir::IrOp::CMP_UGT ||
                cop == ir::IrOp::CMP_ULE || cop == ir::IrOp::CMP_UGE)
                return ir::IR_NO_VALUE;
            const ir::IrValueId ta = ext(flags.a, flags.a_high, false);
            const ir::IrValueId tb = ext(flags.b, flags.b_high, false);
            ir::IrValueId t = BIN(ir::IrOp::AND, ta, tb);
            if (flags.width < 64) t = sext_low(t, flags.width);
            return BIN(cop, t, K(0));
        }
        const ir::IrValueId av = ext(flags.a, flags.a_high, csigned);
        const ir::IrValueId bv = ext(flags.b, flags.b_high, csigned);
        return BIN(cop, av, bv);
    };

    // Condicion (SSA 0/1) de un SUFIJO de cc (setcc/cmov/jCC) leyendo las
    // flags. Centraliza a los 3 consumidores.  Cubre e/ne/z/nz +
    // l/g/le/ge/b/a/be/ae/ c/nc (via flags_cond) y s/ns (SF): el signo solo es
    // sound desde una ALU (result<0) o un test (a&b<0), NO desde un cmp/sub (SF
    // depende de OF ahi).
    auto cc_cond = [&](const std::string &cc) -> ir::IrValueId {
        if (cc == "s" || cc == "ns") {
            if (!flags.valid) return ir::IR_NO_VALUE;
            ir::IrValueId t;
            if (flags.from_result) {
                ir::IrValueId x =
                    flags.a_high ? BIN(ir::IrOp::SHR, flags.a, K(8)) : flags.a;
                t = (flags.width >= 64) ? x : sext_low(x, flags.width);
            } else if (flags.is_test) {
                auto e = [&](ir::IrValueId v, bool hi) -> ir::IrValueId {
                    ir::IrValueId x = hi ? BIN(ir::IrOp::SHR, v, K(8)) : v;
                    return (flags.width >= 64) ? x : and_mask(x, flags.width);
                };
                ir::IrValueId tt = BIN(ir::IrOp::AND, e(flags.a, flags.a_high),
                                       e(flags.b, flags.b_high));
                t = (flags.width >= 64) ? tt : sext_low(tt, flags.width);
            } else {
                return ir::IR_NO_VALUE; // cmp/sub: SF ambiguo sin OF
            }
            const ir::IrValueId neg = BIN(ir::IrOp::CMP_LT, t, K(0));
            return (cc == "s") ? neg : BIN(ir::IrOp::XOR, neg, K(1));
        }
        ir::IrOp cop;
        bool sgn = false;
        if (!setcc_to_cmp(cc, cop, sgn)) return ir::IR_NO_VALUE;
        return flags_cond(cop, sgn);
    };

    // HOOK x86: lifta las instrucciones insns[from, to) en c.block.  Cualquier
    // forma no soportada -> false.  El look-ahead ya no hace falta: las flags
    // fluyen por el pseudo-registro (arriba).
    auto lift_range = [&](size_t from, size_t to) -> bool {
        flags.valid = false; // register-file de flags: bloque-local
        for (size_t ii = from; ii < to; ++ii) {
            const std::string &insn = insns[ii];
            std::string m;
            std::vector<std::string> ops;
            split_insn(insn, m, ops);
            ir::IrOp bop;
            bool ok = true;

            // cmp/test a,b: DEFINEN las flags (capturan sus operandos FULL); no
            // emiten nada todavia.  El consumidor (setcc/cmov/jCC) las leera.
            if ((m == "cmp" || m == "test") && ops.size() == 2) {
                std::string ac;
                bool ah = false;
                const int aw = reg_info(ops[0], ac, ah);
                if (aw == 0)
                    return lift_no(insn, __LINE__); // 1o debe ser registro
                const ir::IrValueId a_full = get_full(ac, ok);
                if (!ok) return lift_no(insn, __LINE__);
                ir::IrValueId b_full;
                bool bh = false;
                int64_t imm = 0;
                if (parse_imm(ops[1], imm)) {
                    b_full = K(imm);
                } else {
                    std::string bc;
                    if (reg_info(ops[1], bc, bh) == 0)
                        return lift_no(insn, __LINE__); // solo reg/imm
                    b_full = get_full(bc, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                }
                flags.valid = true;
                flags.is_test = (m == "test");
                flags.from_result = false;
                flags.a = a_full;
                flags.b = b_full;
                flags.width = aw;
                flags.a_high = ah;
                flags.b_high = bh;
                // (no invalidar abajo: cmp/test SoLO definen)
            } else if (m.size() >= 4 && m.rfind("set", 0) == 0 &&
                       ops.size() == 1) {
                // setcc rd: LEE las flags -> byte 0/1; resto del registro
                // preservado.
                const ir::IrValueId cond = cc_cond(m.substr(3));
                if (cond == ir::IR_NO_VALUE) return lift_no(insn, __LINE__);
                std::string dc;
                bool dh = false;
                if (reg_info(ops[0], dc, dh) == 0)
                    return lift_no(insn, __LINE__);
                write_reg(dc, 8, dh, cond, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if (m.size() > 4 && m.rfind("cmov", 0) == 0 &&
                       ops.size() == 2) {
                // cmovcc rd, rs: LEE las flags.  rd = cond ? (rs al ancho) : rd
                // via SELECT branchless (mask = -(cond); rd = rd_old ^ ((rd_old
                // ^ taken) & mask)).  Respeta la asimetria (taken 32b
                // zero-extiende; not-taken preserva TODO).
                const ir::IrValueId cond = cc_cond(m.substr(4));
                if (cond == ir::IR_NO_VALUE) return lift_no(insn, __LINE__);
                if (is_mem(ops[1])) return lift_no(insn, __LINE__);
                std::string dc, sc;
                bool dh = false, sh = false;
                const int dw = reg_info(ops[0], dc, dh);
                const int sw = reg_info(ops[1], sc, sh);
                if (dw == 0 || sw == 0 || dw != sw)
                    return lift_no(insn, __LINE__);
                const ir::IrValueId rd_old = get_full(dc, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId rs = read_reg(sc, dw, sh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                ir::IrValueId taken;
                if (dw >= 32) {
                    taken = rs;
                } else {
                    taken = BIN(
                        ir::IrOp::OR,
                        BIN(ir::IrOp::AND, rd_old, K((int64_t)~width_mask(dw))),
                        rs);
                }
                const ir::IrValueId mask =
                    emit_un(fn, block, ir::IrOp::NEG, cond, line);
                const ir::IrValueId diff = BIN(ir::IrOp::XOR, rd_old, taken);
                cur[dc] =
                    BIN(ir::IrOp::XOR, rd_old, BIN(ir::IrOp::AND, diff, mask));
                mark_write(dc);
            } else if (m == "mov" && ops.size() == 2) {
                const bool dstm = is_mem(ops[0]);
                const bool srcm = is_mem(ops[1]);
                if (dstm && srcm)
                    return lift_no(insn, __LINE__); // no existe en x86
                if (dstm) { // mov [base+idx*sc+disp], src  (memoria HOST)
                    const MemAddr ma = parse_mem(ops[0]);
                    if (!ma.ok) return lift_no(insn, __LINE__);
                    std::string sc;
                    bool sh = false;
                    const int srw = reg_info(ops[1], sc, sh);
                    int w = mem_hint_width(ops[0]);
                    if (w == 0) w = srw; // ancho del store = registro fuente
                    if (w == 0)
                        return lift_no(insn,
                                       __LINE__); // sin size-hint: ambiguo
                    const ir::IrValueId a = mem_addr_of(ma, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                    const ir::IrValueId v = read_op(ops[1], w, false, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                    emit_store(fn, block, v, a, w, /*host=*/true, line);
                } else if (srcm) { // mov rd, [base+idx*sc+disp]  (memoria HOST)
                    const MemAddr ma = parse_mem(ops[1]);
                    if (!ma.ok) return lift_no(insn, __LINE__);
                    std::string rc;
                    bool rh = false;
                    const int rw = reg_info(ops[0], rc, rh);
                    if (rw == 0) return lift_no(insn, __LINE__);
                    int w = mem_hint_width(ops[1]);
                    if (w == 0) w = rw; // ancho del load = registro destino
                    const ir::IrValueId a = mem_addr_of(ma, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                    const ir::IrValueId ld =
                        emit_load(fn, block, a, w, /*host=*/true, line);
                    write_reg(rc, rw, rh, ld, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                } else { // mov rd, (reg|imm)
                    std::string rc;
                    bool rh = false;
                    const int rw = reg_info(ops[0], rc, rh);
                    if (rw == 0) return lift_no(insn, __LINE__);
                    const ir::IrValueId v = read_op(ops[1], rw, false, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                    write_reg(rc, rw, rh, v, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                }
            } else if (m == "lea" && ops.size() == 2) {
                // lea rd, [base + index*scale + disp]: NO desreferencia --
                // calcula la DIRECCION (aritmetica de 64 bits) y la deja en rd.
                // Idioma clasico de aritmetica rapida (rd = base + index*scale
                // + disp en 1 instr).
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw == 0) return lift_no(insn, __LINE__);
                const MemAddr ma = parse_mem(ops[1]);
                if (!ma.ok) return lift_no(insn, __LINE__);
                const ir::IrValueId acc = mem_addr_of(ma, ok);
                if (!ok) return lift_no(insn, __LINE__);
                write_reg(rc, rw, rh, acc, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if ((m == "movzx" || m == "movsx" || m == "movsxd") &&
                       ops.size() == 2 && is_mem(ops[1])) {
                // movzx/movsx/movsxd rd, [mem]: carga de src_w bytes de memoria
                // HOST + extension (zero para movzx, signo para movsx/movsxd)
                // al ancho de rd. El size-hint del operando de memoria da src_w
                // (movsxd -> dword).
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw == 0) return lift_no(insn, __LINE__);
                int sw = mem_hint_width(ops[1]);
                if (sw == 0 && m == "movsxd") sw = 32; // movsxd implica dword
                if (sw == 0) return lift_no(insn, __LINE__); // sin size-hint
                const MemAddr ma = parse_mem(ops[1]);
                if (!ma.ok) return lift_no(insn, __LINE__);
                const ir::IrValueId a = mem_addr_of(ma, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId ld =
                    emit_load(fn, block, a, sw, /*host=*/true, line);
                // El load HOST zero-extiende los sw bytes; movsx/movsxd
                // sign-extienden.
                const ir::IrValueId v = (m == "movzx") ? ld : sext_low(ld, sw);
                write_reg(rc, rw, rh, v, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if (binop_of(m, bop) && ops.size() == 2) {
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw == 0)
                    return lift_no(insn, __LINE__); // dst debe ser registro
                const bool is_shift =
                    (bop == ir::IrOp::SHL || bop == ir::IrOp::SHR ||
                     bop == ir::IrOp::SAR);
                // dst leido: con signo solo para SAR (necesita el bit de signo
                // al ancho); el resto sin signo (los bits altos se enmascaran
                // al escribir).
                const ir::IrValueId a =
                    read_reg(rc, rw, rh, bop == ir::IrOp::SAR, ok);
                if (!ok) return lift_no(insn, __LINE__);
                // `sub` fija TODAS las flags como `cmp a,b` (x86: sub == cmp en
                // flags)
                // -> soporta CUALQUIER cc posterior (jl/jg/jb/ja, no solo
                // jz/jnz). Capturamos los operandos FULL AQUi (antes de pisar
                // el dst).
                const bool is_sub = (bop == ir::IrOp::SUB);
                ir::IrValueId sub_a = 0, sub_b = 0;
                bool sub_bh = false;
                if (is_sub) {
                    sub_a = get_full(rc, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                    int64_t si = 0;
                    if (parse_imm(ops[1], si)) {
                        sub_b = K(si);
                    } else {
                        std::string sbc;
                        if (reg_info(ops[1], sbc, sub_bh) == 0)
                            return lift_no(insn, __LINE__);
                        sub_b = get_full(sbc, ok);
                        if (!ok) return lift_no(insn, __LINE__);
                    }
                }
                ir::IrValueId b;
                if (is_shift) {
                    // La cuenta se enmascara por el ancho (x86: & 0x1F para
                    // <=32 bits, & 0x3F para 64).  Si es INMEDIATA, la plegamos
                    // a una constante (evita un shift-por-valor y da mejor IR);
                    // si es un registro (cl), enmascaramos en runtime.
                    const int64_t cmask = (rw >= 64 ? 63 : 31);
                    int64_t cimm = 0;
                    if (parse_imm(ops[1], cimm)) {
                        b = K(cimm & cmask);
                    } else {
                        b = read_op(ops[1], 64, false, ok);
                        if (!ok) return lift_no(insn, __LINE__);
                        b = BIN(ir::IrOp::AND, b, K(cmask));
                    }
                } else {
                    b = read_op(ops[1], rw, false, ok);
                    if (!ok) return lift_no(insn, __LINE__);
                }
                const ir::IrValueId res = BIN(bop, a, b);
                write_reg(rc, rw, rh, res, ok);
                if (!ok) return lift_no(insn, __LINE__);
                // sub -> flags de comparacion completa (cualquier cc); el resto
                // de ALU no-shift (add/and/or/xor) solo ZF; los shift no se
                // modelan.
                if (is_sub) {
                    flags.valid = true;
                    flags.is_test = false;
                    flags.from_result = false;
                    flags.a = sub_a;
                    flags.b = sub_b;
                    flags.width = rw;
                    flags.a_high = rh;
                    flags.b_high = sub_bh;
                    flags.has_cf = false;
                    // CF (borrow) de un sub 64-bit -> sbb posterior: cf = (a <u
                    // b).
                    if (rw == 64) {
                        flags.has_cf = true;
                        flags.cf = BIN(ir::IrOp::CMP_ULT, sub_a, sub_b);
                    }
                } else if (!is_shift) {
                    flag_from_result(res, rw);
                    // CF (carry-out) de un add 64-bit -> adc posterior: hubo
                    // carry si el resultado (envuelto) es menor que un sumando
                    // (unsigned).
                    if (bop == ir::IrOp::ADD && rw == 64) {
                        flags.has_cf = true;
                        flags.cf = BIN(ir::IrOp::CMP_ULT, res, a);
                    }
                }
            } else if ((m == "adc" || m == "sbb") && ops.size() == 2) {
                // Aritmetica multi-palabra 64-bit: adc rd,rs = rd + rs + CF;
                // sbb rd,rs = rd - rs - CF.  Consume el CF que dejo el
                // add/sub/adc/sbb anterior (flags.cf) y produce el CF nuevo
                // (cadena de dos pasos). Solo 64-bit (donde CF es exactamente
                // el acarreo del bit 63).
                if (!flags.valid || !flags.has_cf)
                    return lift_no(insn, __LINE__); // sin CF modelado
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw != 64) return lift_no(insn, __LINE__);
                const ir::IrValueId a = read_reg(rc, 64, rh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId b = read_op(ops[1], 64, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId cin = flags.cf;
                ir::IrValueId res, cout;
                if (m == "adc") {
                    const ir::IrValueId t1 = BIN(ir::IrOp::ADD, a, b);
                    const ir::IrValueId c1 = BIN(ir::IrOp::CMP_ULT, t1, a);
                    const ir::IrValueId t2 = BIN(ir::IrOp::ADD, t1, cin);
                    const ir::IrValueId c2 = BIN(ir::IrOp::CMP_ULT, t2, t1);
                    res = t2;
                    cout = BIN(ir::IrOp::OR, c1, c2);
                } else { // sbb
                    const ir::IrValueId t1 = BIN(ir::IrOp::SUB, a, b);
                    const ir::IrValueId b1 = BIN(ir::IrOp::CMP_ULT, a, b);
                    const ir::IrValueId t2 = BIN(ir::IrOp::SUB, t1, cin);
                    const ir::IrValueId b2 = BIN(ir::IrOp::CMP_ULT, t1, cin);
                    res = t2;
                    cout = BIN(ir::IrOp::OR, b1, b2);
                }
                write_reg(rc, 64, rh, res, ok);
                if (!ok) return lift_no(insn, __LINE__);
                flag_from_result(res, 64); // ZF del resultado
                flags.has_cf = true; // + CF nuevo para el siguiente adc/sbb
                flags.cf = cout;
            } else if ((m == "neg" || m == "not") && ops.size() == 1) {
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw == 0) return lift_no(insn, __LINE__);
                const ir::IrValueId a = read_reg(rc, rw, rh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId res = emit_un(
                    fn, block, m == "neg" ? ir::IrOp::NEG : ir::IrOp::NOT, a,
                    line);
                write_reg(rc, rw, rh, res, ok);
                if (!ok) return lift_no(insn, __LINE__);
                // neg define ZF; not NO toca flags (x86) -> no las siembra.
                if (m == "neg") flag_from_result(res, rw);
            } else if ((m == "inc" || m == "dec") && ops.size() == 1) {
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw == 0) return lift_no(insn, __LINE__);
                const ir::IrValueId a = read_reg(rc, rw, rh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId res =
                    BIN(m == "inc" ? ir::IrOp::ADD : ir::IrOp::SUB, a, K(1));
                write_reg(rc, rw, rh, res, ok);
                if (!ok) return lift_no(insn, __LINE__);
                flag_from_result(res, rw); // inc/dec definen ZF (jnz posterior)
            } else if ((m == "popcnt" || m == "lzcnt" || m == "tzcnt") &&
                       ops.size() == 2) {
                /* popcnt/lzcnt/tzcnt rd, rs -> POPCNT/CLZ/CTZ.  Solo 64 bits
                 * (donde el mapeo es EXACTO; a 32/16 el resultado depende del
                 * ancho -> incremento posterior, hoy cae a ASM_MICRO). */
                std::string rc, sc;
                bool rh = false, sh = false;
                const int rw = reg_info(ops[0], rc, rh);
                const int sw = reg_info(ops[1], sc, sh);
                if (rw != 64 || sw != 64) return lift_no(insn, __LINE__);
                const ir::IrValueId a = read_reg(sc, 64, sh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrOp uop = (m == "popcnt")  ? ir::IrOp::POPCNT
                                     : (m == "lzcnt") ? ir::IrOp::CLZ
                                                      : ir::IrOp::CTZ;
                const ir::IrValueId res = emit_un(fn, block, uop, a, line);
                write_reg(rc, 64, rh, res, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if (m == "bswap" && ops.size() == 1) {
                /* bswap rd -> BYTESWAP (in-place).  Solo 64 bits (bswap de 32
                 * bits invertiria 4 bytes, distinto ancho). */
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw != 64) return lift_no(insn, __LINE__);
                const ir::IrValueId a = read_reg(rc, 64, rh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId res =
                    emit_un(fn, block, ir::IrOp::BYTESWAP, a, line);
                write_reg(rc, 64, rh, res, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if ((m == "movzx" || m == "movsx" || m == "movsxd") &&
                       ops.size() == 2) {
                /* Extension de ancho: lee rs a SU ancho (zero-extend en movzx,
                 * sign-extend en movsx/movsxd) y lo escribe en rd.  El modelo
                 * de anchos ya cubre exactamente la semantica x86.  Solo
                 * reg-reg (memoria -> host, camino opaco). */
                if (is_mem(ops[1])) return lift_no(insn, __LINE__);
                std::string rc, sc;
                bool rh = false, sh = false;
                const int rw = reg_info(ops[0], rc, rh);
                const int sw = reg_info(ops[1], sc, sh);
                if (rw == 0 || sw == 0) return lift_no(insn, __LINE__);
                const bool sgn = (m != "movzx");
                const ir::IrValueId v = read_reg(sc, sw, sh, sgn, ok);
                if (!ok) return lift_no(insn, __LINE__);
                write_reg(rc, rw, rh, v, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if ((m == "rol" || m == "ror") && ops.size() == 2) {
                // Rotacion 64-bit -> ROTL/ROTR (el backend la emite nativa:
                // cuenta constante -> rol/ror imm; en registro -> rol/ror CL).
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw != 64) return lift_no(insn, __LINE__); // solo 64 bits
                const ir::IrValueId a = read_reg(rc, 64, rh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId cnt = read_op(ops[1], 64, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId res =
                    BIN(m == "rol" ? ir::IrOp::ROTL : ir::IrOp::ROTR, a, cnt);
                write_reg(rc, 64, rh, res, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if (m == "cqo" || m == "cqto" || m == "cdq") {
                // Extension del DIVIDENDO a rdx:rax (edx:eax) previa a
                // idiv/div.  El patron div/idiv de abajo la ABSORBE (la
                // division 64/64 modela el dividendo alto): aqui es un no-op.
                // OJO: cdqe/cwde/cbw NO van aqui
                // -- esos EXTIENDEN EL ACUMULADOR (eax->rax, ax->eax, al->ax),
                // no preparan rdx; tienen su propio caso abajo.
            } else if (m == "cdqe" || m == "cwde" || m == "cbw") {
                // Extension con signo del ACUMULADOR a su ancho mayor: cdqe
                // eax->rax, cwde ax->eax, cbw al->ax.  rax = sext(rax_low_src,
                // src_bits).
                const int src_bits = (m == "cdqe")   ? 32
                                     : (m == "cwde") ? 16
                                                     : 8;
                const int dst_bits = (m == "cdqe")   ? 64
                                     : (m == "cwde") ? 32
                                                     : 16;
                const ir::IrValueId cur_rax = get_full("rax", ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId ext = sext_low(cur_rax, src_bits);
                // Escribir al ancho destino (write_reg enmascara/zero-extiende
                // los bits altos de rax por encima de dst_bits segun las reglas
                // x86).
                write_reg("rax", dst_bits, false, ext, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if ((m == "div" || m == "idiv") && ops.size() == 1) {
                // Division 64/64: rax = cociente, rdx = resto.  Exige el setup
                // del dividendo alto INMEDIATAMENTE antes -- `xor rdx,rdx`
                // (div, sin signo) o `cqo/cdq` (idiv, con signo) -- para
                // garantizar que el dividendo es rax de 64 bits (no rdx:rax de
                // 128).  El divisor debe ser un registro de 64 bits.
                if (is_mem(ops[0])) return lift_no(insn, __LINE__);
                std::string dc;
                bool dh = false;
                const int dw = reg_info(ops[0], dc, dh);
                if (dw != 64) return lift_no(insn, __LINE__);
                if (ii <= from)
                    return lift_no(insn, __LINE__); // sin instruccion previa
                std::string pm;
                std::vector<std::string> pops;
                split_insn(insns[ii - 1], pm, pops);
                const bool is_signed = (m == "idiv");
                bool setup_ok = false;
                if (is_signed) {
                    setup_ok = (pm == "cqo" || pm == "cqto" || pm == "cdq");
                } else if (pm == "xor" && pops.size() == 2) {
                    // xor rdx,rdx | xor edx,edx (rdx = 0).
                    const std::string p0 = asm_canonical_reg(pops[0]);
                    const std::string p1 = asm_canonical_reg(pops[1]);
                    setup_ok = (p0 == "rdx" && p1 == "rdx");
                }
                if (!setup_ok)
                    return lift_no(insn,
                                   __LINE__); // dividendo alto desconocido
                const ir::IrValueId dvd = read_reg("rax", 64, false, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId dsr = read_reg(dc, 64, dh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrType ty =
                    is_signed ? ir::IrType::I64 : ir::IrType::U64;
                // Leer el dividendo UNA vez y sacar cociente + resto de el
                // (antes de pisar rax).
                const ir::IrValueId q =
                    emit_bin_ty(fn, block, ir::IrOp::DIV, dvd, dsr, ty, line);
                const ir::IrValueId r =
                    emit_bin_ty(fn, block, ir::IrOp::MOD, dvd, dsr, ty, line);
                write_reg("rax", 64, false, q, ok);
                if (!ok) return lift_no(insn, __LINE__);
                write_reg("rdx", 64, false, r, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if (m == "imul" && ops.size() == 3) {
                // imul rd, rs, imm/reg (3-op, single-def): rd = rs * op3.  La
                // parte baja del producto es identica con/sin signo
                // (complemento a dos).
                std::string rc;
                bool rh = false;
                const int rw = reg_info(ops[0], rc, rh);
                if (rw == 0) return lift_no(insn, __LINE__);
                const ir::IrValueId s1 = read_op(ops[1], rw, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId s2 = read_op(ops[2], rw, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                write_reg(rc, rw, rh, BIN(ir::IrOp::MUL, s1, s2), ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if (m == "xchg" && ops.size() == 2 && !is_mem(ops[0]) &&
                       !is_mem(ops[1])) {
                // xchg r1, r2 (registro-registro, sin LOCK ni memoria):
                // intercambio de valores.  En el register-file es un simple
                // SWAP de los valores SSA actuales (cero IR: puro renombrado);
                // el flush escribe cada slot con el valor cruzado.  Solo 64-bit
                // (mapeo exacto sin sub-registros).
                std::string c1, c2;
                bool h1 = false, h2 = false;
                const int w1 = reg_info(ops[0], c1, h1);
                const int w2 = reg_info(ops[1], c2, h2);
                if (w1 != 64 || w2 != 64) return lift_no(insn, __LINE__);
                const ir::IrValueId v1 = get_full(c1, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId v2 = get_full(c2, ok);
                if (!ok) return lift_no(insn, __LINE__);
                cur[c1] = v2;
                mark_write(c1);
                cur[c2] = v1;
                mark_write(c2);
            } else if ((m == "mul" || m == "imul") && ops.size() == 1) {
                // Multiplicacion 64x64->128: rax = parte BAJA (= mul, igual
                // con/sin signo en complemento a dos), rdx = parte ALTA
                // (umulhi/smulhi).  El operando es el multiplicador; rax es el
                // multiplicando implicito. Solo 64 bits (donde el mapeo a
                // rdx:rax es exacto).  Si rdx no se usa, el DCE elimina la
                // descomposicion de la parte alta.
                if (is_mem(ops[0])) return lift_no(insn, __LINE__);
                std::string mc;
                bool mh = false;
                const int mw = reg_info(ops[0], mc, mh);
                if (mw != 64) return lift_no(insn, __LINE__);
                const bool is_signed = (m == "imul");
                const ir::IrValueId mplr = read_reg(mc, 64, mh, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId mpld =
                    read_reg("rax", 64, false, false, ok);
                if (!ok) return lift_no(insn, __LINE__);
                const ir::IrValueId lo = BIN(ir::IrOp::MUL, mpld, mplr);
                const ir::IrValueId hi =
                    is_signed ? smulhi(mpld, mplr) : umulhi(mpld, mplr);
                write_reg("rax", 64, false, lo, ok);
                if (!ok) return lift_no(insn, __LINE__);
                write_reg("rdx", 64, false, hi, ok);
                if (!ok) return lift_no(insn, __LINE__);
            } else if (m == "nop") {
                // no-op (incluido el centinela de etiqueta final): no emite IR.
            } else {
                // No esta en el subconjunto que se sabe elevar.
                return lift_no(insn, __LINE__);
            }
            // Register-file de flags: toda instruccion que las PISE sin
            // dejarlas en un estado modelable invalida el pseudo-registro.
            // cmp/test lo definen; las ALU con result-flags
            // (add/sub/.../inc/dec/neg) tambien lo definen (ZF);
            // setcc/cmov/flag-neutral lo preservan.  Asi un consumidor no-
            // adyacente sigue viendo la definicion mientras no haya un
            // flag-writer no-modelado (shift, mul, ...) entre medias.
            if (m != "cmp" && m != "test" && !preserves_flags(m) &&
                !sets_result_flags(m))
                flags.valid = false;
        }
        return true;
    }; // fin del hook lift_range

    // --- 1 bloque (straight-line, sin ramas): liftar todo + flush final. ---
    if (cfg.blocks.size() <= 1) {
        if (!lift_range(0, insns.size())) return lift_no("<bloque>", __LINE__);
        for (const std::string &r : wrote) {
            auto b = bound.find(r);
            auto v = cur.find(r);
            if (b != bound.end() && v != cur.end()) {
                const bool slot_host = fn.values[b->second.slot].is_host_ptr;
                emit_store(fn, block, v->second, b->second.slot,
                           b->second.width_bits, slot_host, line);
            }
        }
        if (out_exit) *out_exit = block;
        return true;
    }

    // --- Con RAMAS: CFG del asm -> IR-CFG via el driver NEUTRO + hooks x86.
    // ---
    LiftCtx ctx{fn, block, line, bound, cur, wrote};
    CfgHooks hooks;
    hooks.lift_range = [&](size_t from, size_t to) {
        return lift_range(from, to);
    };
    hooks.term_start = [&](const vx::AsmBasicBlock &bb) -> uint32_t {
        // x86: CondBranch/UncondJump -> solo el jCC/jmp (last) es terminador;
        // el cmp que define las flags queda en el CUERPO (lift_range lo procesa
        // y deja las flags pendientes que branch_cond lee).  Resto -> todo
        // cuerpo.
        if (bb.term == vx::AsmTerm::CondBranch ||
            bb.term == vx::AsmTerm::UncondJump)
            return bb.last;
        return bb.last + 1u;
    };
    hooks.branch_cond = [&](const vx::AsmBasicBlock &bb) -> ir::IrValueId {
        // El cuerpo del bloque (ya liftado por lift_range) dejo las flags
        // pendientes en el pseudo-registro; aqui solo leemos la cc del jCC.  No
        // exige adyacencia cmp/jCC: cualquier instruccion flag-neutral entre
        // medias esta permitida (test asm_branch/asm_loop con calculo
        // intermedio).
        std::string jm;
        std::vector<std::string> jops;
        split_insn(insns[bb.last], jm, jops);
        if (jm.size() < 2 || jm[0] != 'j') return ir::IR_NO_VALUE;
        return cc_cond(jm.substr(1)); // lee las flags dejadas por el cuerpo
    };
    uint32_t exit_blk = block;
    if (!lift_cfg_neutral(ctx, cfg, hooks, exit_blk))
        return lift_no("<bloque>", __LINE__);
    if (out_exit) *out_exit = exit_blk;
    return true;
}

} // namespace vx
