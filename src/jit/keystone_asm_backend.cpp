/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file keystone_asm_backend.cpp
 * @brief  AS inc.4b: impl de @c vx::AsmBackend con Keystone.
 *
 * UNICO fichero del proyecto que incluye @c keystone.h para  AS (la
 * decision de diseno exige aislar la dependencia tras la interfaz pura
 * @c vx::AsmBackend).  Ensambla texto NASM Intel a bytes; usado hoy para
 * validar la sintaxis del body en compile-time (inc.4b) y, en inc.5, para
 * producir los bytes que van al code-cache del JIT.
 */

#include "util/env_flags.h"
#include "util/thread_slot.h" // el estado de simbolos, sin `thread_local`
#include "jit/keystone_asm_backend.h"
#include "vx/asm/asm_backend.h"

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <cstdio>
#include <mutex>

namespace jit {

namespace {

// --- Resolucion de SIMBOLOS propios desde el asm (`jmp [sym]`, `mov rax,sym`)
// Keystone llama al sym-resolver para cada simbolo que NO puede resolver el
// mismo (las etiquetas locales `.loop` SI las resuelve).  Le devolvemos un
// SENTINELA unico por simbolo, < 2GB (asi un disp32 rip-relativo cabe en int32
// al ensamblar en addr=0).  Tras ensamblar, desensamblamos con Capstone para
// localizar el campo (imm o disp rip-rel) cuyo valor/target == sentinela y
// emitir un SymRef (offset+size+tipo+nombre).  Estado por-assemble via
// thread_local (el resolver de Keystone no lleva user-data).
// Base de ensamblado (addr pasado a ks_asm/cs_disasm).  0: los sentinelas y
// los offsets coinciden 1:1.  Keystone solo soporta fixups de 32 bits (rel32 /
// disp32 / imm32), por eso los sentinelas caben en int32 -- un `mov r64, imm64`
// con simbolo NO es soportado por Keystone (FIXUP_INVALID); la forma PIC para
// meter la direccion de un simbolo en un registro es `lea rax, [rel sym]`.
static constexpr uint64_t kAsmBase = 0ULL;

struct SymState {
    std::vector<std::pair<std::string, uint64_t>> syms; // (nombre, sentinela)
    uint64_t next = kBase;
    static constexpr uint64_t kBase = 0x5E100000ULL; // ~1.58GB, cabe en int32
    uint64_t intern(const char *name) {
        for (auto &s : syms)
            if (s.first == name) return s.second;
        const uint64_t v = next;
        next += 0x10; // separacion holgada entre sentinelas
        syms.emplace_back(name, v);
        return v;
    }
    const std::string *symbol_for(uint64_t v) const {
        for (auto &s : syms)
            if (s.second == v) return &s.first;
        return nullptr;
    }
};
/* En una RANURA propia, no en `thread_local`: en MinGW la TLS es emulada y cada
 * acceso es una llamada.  Lo que se guarda es un puntero, asi que cabe tal cual
 * y no hay nada que reservar.  Ver `util/thread_slot.h`. */
util::ThreadSlot g_sym_state_slot;
/// El estado de simbolos de ESTE hilo, o nulo si no hay ensamblado en curso.
inline SymState *g_sym_state() {
    return static_cast<SymState *>(g_sym_state_slot.get());
}
/// Fija el estado de ESTE hilo.
inline void set_g_sym_state(SymState *s) {
    g_sym_state_slot.ensure();
    g_sym_state_slot.set(s);
}

bool vx_sym_resolver(const char *symbol, uint64_t *value) {
    SymState *const st = g_sym_state();
    if (st == nullptr || symbol == nullptr) return false;
    // Un SIMBOLO de asm es un identificador (empieza por letra, '_' o '.').  Un
    // LITERAL numerico empieza por digito -> NO es simbolo: devolver false para
    // que Keystone lo parsee el mismo.  Sin esto, en AArch64 (donde Keystone
    // consulta el resolver para los inmediatos `#N`) un `#42` se interceptaria
    // y corromperia el valor.  Cubre decimal, 0x..., 0b..., etc.
    if (symbol[0] >= '0' && symbol[0] <= '9') return false;
    *value = st->intern(symbol);
    return true;
}

// ---------------------------------------------------------------------------
// Routing del ensamblado: Keystone NO sabe hacer un fixup de 64 bits.  Un
// `mov r64, simbolo` con el resolver da KS_ERR_ASM_FIXUP_INVALID (el sentinela
// de 64 bits no cabe en el campo imm que Keystone reserva para un simbolo).
// PERO Keystone SI encodea `mov r64, <literal 64-bit>` (forma REX.W + B8, 10
// bytes) cuando el inmediato es un literal que no cabe en int32.  Asi
// enrutamos: los `mov r64, simbolo` (cargar la DIRECCION ABSOLUTA de un simbolo
// propio en un registro) los "ensamblamos nosotros" sustituyendo el simbolo por
// un literal placeholder unico de 64 bits ANTES de Keystone; Keystone ensambla
// TODO el bloque (labels/saltos/offsets correctos) con ese literal, y tras
// ensamblar localizamos los 8 bytes LE del placeholder en la salida y emitimos
// un SymRef Abs64 -- el resto de formas (rel32/disp32) las sigue resolviendo
// Keystone via el sym-resolver.  El reloc ABS64 lo materializa el driver contra
// la VA real (PE con base fija sin DYNAMIC_BASE, o ELF no-pie).
struct Imm64SymPatch {
    uint64_t placeholder; ///< literal de 64 bits inyectado en el texto.
    std::string symbol;   ///< simbolo original (__vxf_* / __vxg_*).
};

/// Es @p t un registro GPR de 64 bits (rax..r15)?
inline bool is_reg64_token(const std::string &t) {
    static const char *kR64[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                 "rbp", "rsp", "r8",  "r9",  "r10", "r11",
                                 "r12", "r13", "r14", "r15"};
    std::string s;
    s.reserve(t.size());
    for (char c : t)
        s += static_cast<char>(std::tolower((unsigned char)c));
    for (const char *r : kR64)
        if (s == r) return true;
    return false;
}

/// Reescribe el texto NASM enrutando cada `mov r64, __vxf_*|__vxg_*` a un
/// literal placeholder de 64 bits; rellena @p patches con (placeholder,
/// simbolo). El resto del texto queda verbatim (Keystone lo ensambla igual).
std::string route_imm64_syms(const std::string &nasm,
                             std::vector<Imm64SymPatch> &patches) {
    std::string out;
    out.reserve(nasm.size() + 32);
    size_t line_start = 0;
    while (true) {
        size_t nl = nasm.find('\n', line_start);
        const bool last = (nl == std::string::npos);
        const size_t end = last ? nasm.size() : nl;
        std::string line = nasm.substr(line_start, end - line_start);

        // Parte de codigo (sin comentario `;` ni `//`).
        std::string code = line;
        size_t cpos = code.find(';');
        size_t spos = code.find("//");
        size_t cut = std::min(cpos == std::string::npos ? code.size() : cpos,
                              spos == std::string::npos ? code.size() : spos);
        std::string codepart = code.substr(0, cut);

        // Tokenizar por espacios y comas.
        std::vector<std::string> tok;
        std::string cur;
        for (char c : codepart) {
            if (c == ' ' || c == '\t' || c == ',') {
                if (!cur.empty()) {
                    tok.push_back(cur);
                    cur.clear();
                }
            } else {
                cur += c;
            }
        }
        if (!cur.empty()) tok.push_back(cur);

        // Patron exacto: `mov <r64>, <__vxf_*|__vxg_*>` (3 tokens).
        bool routed = false;
        if (tok.size() == 3) {
            std::string mnem;
            for (char c : tok[0])
                mnem += static_cast<char>(std::tolower((unsigned char)c));
            const std::string &sym = tok[2];
            const bool is_sym =
                (sym.rfind("__vxf_", 0) == 0 || sym.rfind("__vxg_", 0) == 0);
            if (mnem == "mov" && is_reg64_token(tok[1]) && is_sym) {
                // Placeholder unico > int32 (fuerza imm64) y patron de 8 bytes
                // distintivo en la salida.
                const uint64_t ph =
                    0x00C0FFEE00000001ULL +
                    static_cast<uint64_t>(patches.size()) * 0x100ULL;
                patches.push_back({ph, sym});
                char buf[64];
                std::snprintf(buf, sizeof(buf), "\tmov %s, 0x%llx",
                              tok[1].c_str(), (unsigned long long)ph);
                out += buf;
                routed = true;
            }
        }
        if (!routed) out += line;
        if (last) break;
        out += '\n';
        line_start = nl + 1;
    }
    return out;
}

/// Traduce @c vx::AsmArch a (ks_arch, mode) de Keystone.
bool arch_to_ks(vx::AsmArch a, ks_arch &arch, ks_mode &mode) {
    switch (a) {
    case vx::AsmArch::X86_64:
        arch = KS_ARCH_X86;
        mode = KS_MODE_64;
        return true;
    case vx::AsmArch::X86_32:
        arch = KS_ARCH_X86;
        mode = KS_MODE_32;
        return true;
    case vx::AsmArch::X86_16:
        arch = KS_ARCH_X86;
        mode = KS_MODE_16;
        return true;
    case vx::AsmArch::ARM64:
        arch = KS_ARCH_ARM64;
        mode = KS_MODE_LITTLE_ENDIAN;
        return true;
    case vx::AsmArch::ARM32:
        arch = KS_ARCH_ARM;
        mode = KS_MODE_ARM;
        return true;
    }
    return false;
}

/// Impl concreta: abre un @c ks_engine por cada @c assemble.  El engine es
/// LOCAL a la llamada, pero Keystone/LLVM mantiene ESTADO GLOBAL mutable
/// (registro de targets + capa MC) que NO es thread-safe: dos @c ks_asm
/// concurrentes (p.ej. dos modulos con inline-asm compilados en paralelo por
/// M8) corren sobre ese estado -> corrupcion/crash.  Serializamos toda la
/// operacion con un mutex global.  Ensamblar es un camino RARO (un bloque `asm
/// { }` puntual), asi que la serializacion tiene coste despreciable frente al
/// resto del compile paralelo.
struct KeystoneAsmBackend final : vx::AsmBackend {
    vx::AsmAssembleResult assemble(const std::string &nasm,
                                   vx::AsmArch arch) override {
        // Keystone/LLVM no es thread-safe: un unico assemble a la vez.
        static std::mutex ks_global_mtx;
        std::lock_guard<std::mutex> ks_lock(ks_global_mtx);
        // Cache de ensamblado: (arch, nasm) es DETERMINISTA -> mismo texto =
        // mismos bytes/sym_refs/insn_offsets.  Muchos bloques asm (y las
        // instrucciones ASM_MICRO liftadas) repiten el mismo fragmento; sin
        // cache re-invocariamos Keystone (abrir engine + ensamblar + Capstone)
        // por cada ocurrencia.  Bajo el mismo mutex global -> thread-safe.
        static std::unordered_map<std::string, vx::AsmAssembleResult> ks_cache;
        std::string cache_key(1, static_cast<char>(arch));
        cache_key += nasm;
        {
            auto it = ks_cache.find(cache_key);
            if (it != ks_cache.end()) return it->second;
        }
        vx::AsmAssembleResult r;
        ks_arch ka;
        ks_mode km;
        if (!arch_to_ks(arch, ka, km)) {
            r.error = "arquitectura no soportada por el backend Keystone";
            return r;
        }
        ks_engine *ks = nullptr;
        if (ks_open(ka, km, &ks) != KS_ERR_OK || ks == nullptr) {
            r.error = "ks_open fallo";
            return r;
        }
        // Sintaxis NASM Intel SOLO para x86 (copy-paste de docs Intel).  En
        // AArch64/ARM esta opcion es incorrecta y hace que Keystone lea los
        // inmediatos bare como HEX (p.ej. `#42` -> 0x42=66, `#16` -> 0x16=22),
        // corrompiendo el codigo; alli se usa la sintaxis OFICIAL ESTANDAR de
        // ARM (la que Keystone aplica por defecto para AArch64).
        if (arch == vx::AsmArch::X86_64 || arch == vx::AsmArch::X86_32 ||
            arch == vx::AsmArch::X86_16)
            ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
        // Resolver de simbolos propios (SOLO x86: la maquinaria de asm-inline).
        // En AArch64 la mera presencia del resolver altera el parser de
        // Keystone y corrompe los inmediatos; alli se usa Keystone plano
        // (sintaxis oficial de ARM), como el ensamblador general.  Los simbolos
        // cross-funcion arm64 se resuelven por relocs (R_AARCH64_CALL26), no
        // por este resolver.
        const bool ks_is_x86 =
            (arch == vx::AsmArch::X86_64 || arch == vx::AsmArch::X86_32 ||
             arch == vx::AsmArch::X86_16);
        SymState sym_state;
        if (ks_is_x86) {
            set_g_sym_state(&sym_state);
            ks_option(ks, KS_OPT_SYM_RESOLVER,
                      reinterpret_cast<size_t>(&vx_sym_resolver));
        }

        // x86-64: `DEFAULT REL` -> `[sym]` (operando de memoria a un simbolo,
        // sin registro base) se ensambla RIP-RELATIVO (ff 25 disp32) en vez de
        // absoluto (ff 24 25 disp32), que es la convencion correcta para codigo
        // de 64 bits PIC y la unica que un reloc REL32 puede parchear.  NO
        // afecta a `[reg]`/`[reg+off]` ni a los imm (`mov rax, sym`).  Para un
        // acceso absoluto explicito el usuario escribe `[abs sym]`.
        // Routing imm64: solo x86-64 (es el unico modo con `mov r64, imm64`).
        // Sustituye los `mov r64, simbolo` por literales placeholder ANTES de
        // Keystone (que no sabe el fixup de 64 bits) y registra los patches.
        std::vector<Imm64SymPatch> imm64_patches;
        std::string src;
        if (arch == vx::AsmArch::X86_64) {
            src = "default rel\n";
            src += route_imm64_syms(nasm, imm64_patches);
        }
        const char *asm_text =
            (arch == vx::AsmArch::X86_64) ? src.c_str() : nasm.c_str();
        unsigned char *enc = nullptr;
        size_t enc_size = 0, stat_count = 0;
        const int rc =
            ks_asm(ks, asm_text, kAsmBase, &enc, &enc_size, &stat_count);
        set_g_sym_state(nullptr);
        if (rc != 0) {
            const ks_err e = ks_errno(ks);
            r.ok = false;
            r.error = ks_strerror(e);
        } else {
            r.ok = true;
            r.bytes.assign(enc, enc + enc_size);
        }
        if (enc) ks_free(enc);
        ks_close(ks);
        // CONTRATO insn_offsets: el offset de cada instruccion emitida, en
        // orden.  Lo obtenemos descodificando NUESTRA salida con Capstone --
        // detalle ENCAPSULADO de este backend (Keystone+Capstone van juntos);
        // la inspeccion solo consume insn_offsets.  Un backend hand-rolled lo
        // rellenaria nativo sin Capstone.  Solo x86 por ahora.
        if (r.ok && !r.bytes.empty() &&
            (arch == vx::AsmArch::X86_64 || arch == vx::AsmArch::X86_32 ||
             arch == vx::AsmArch::X86_16)) {
            cs_mode cm = arch == vx::AsmArch::X86_64   ? CS_MODE_64
                         : arch == vx::AsmArch::X86_32 ? CS_MODE_32
                                                       : CS_MODE_16;
            csh h;
            if (cs_open(CS_ARCH_X86, cm, &h) == CS_ERR_OK) {
                // Detalle ON solo si hay simbolos por resolver (para localizar
                // el campo imm/disp del sentinela).  Sin simbolos, cero coste
                // extra: solo insn_offsets como antes.
                const bool need_detail = !sym_state.syms.empty();
                if (need_detail) cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
                if (need_detail && util::flag_on(util::FlagId::VxAsmDebug))
                    for (auto &sp : sym_state.syms)
                        std::fprintf(stderr, "[asmdbg] sym '%s' -> %llx\n",
                                     sp.first.c_str(),
                                     (unsigned long long)sp.second);
                cs_insn *insn = nullptr;
                size_t n = cs_disasm(h, r.bytes.data(), r.bytes.size(),
                                     kAsmBase, 0, &insn);
                r.insn_offsets.reserve(n);
                for (size_t i = 0; i < n; ++i) {
                    // address absoluta (kAsmBase + offset) -> offset relativo.
                    r.insn_offsets.push_back(
                        static_cast<uint32_t>(insn[i].address - kAsmBase));
                    if (!need_detail || insn[i].detail == nullptr) continue;
                    const cs_x86 &x = insn[i].detail->x86;
                    const uint64_t ia = insn[i].address;   // absoluta
                    const uint64_t ia_rel = ia - kAsmBase; // offset bloque
                    const uint64_t il = insn[i].size;
                    // Es un salto/llamada DIRECTO (jmp/call/jcc rel)?  Su imm
                    // operand es el TARGET absoluto (Capstone lo resuelve); el
                    // campo es un rel32 -> reloc tipo BranchRel32.
                    bool is_branch = false;
                    for (uint8_t g = 0; g < insn[i].detail->groups_count; ++g) {
                        const uint8_t gr = insn[i].detail->groups[g];
                        if (gr == X86_GRP_JUMP || gr == X86_GRP_CALL ||
                            gr == X86_GRP_BRANCH_RELATIVE) {
                            is_branch = true;
                            break;
                        }
                    }
                    using K = vx::AsmAssembleResult::SymRefKind;
                    for (uint8_t k = 0; k < x.op_count; ++k) {
                        const cs_x86_op &op = x.operands[k];
                        if (op.type == X86_OP_IMM) {
                            // Branch directo (jmp/call rel32): el campo es
                            // rip-relativo -> mismo bug off-by-disp_size de
                            // Keystone (el target efectivo = sym + imm_size).
                            // imm64/imm32 absolutos NO tienen el offset.
                            uint64_t sym_val = static_cast<uint64_t>(op.imm);
                            if (is_branch && x.encoding.imm_size == 4)
                                sym_val -= x.encoding.imm_size;
                            const std::string *s =
                                sym_state.symbol_for(sym_val);
                            if (!s || !x.encoding.imm_size) continue;
                            vx::AsmAssembleResult::SymRef ref;
                            ref.offset = static_cast<uint32_t>(
                                ia_rel + x.encoding.imm_offset);
                            ref.size = x.encoding.imm_size;
                            ref.symbol = *s;
                            // jmp/call sym (directo, rel32) -> BranchRel32;
                            // mov reg,imm64 -> Abs64; push/mov r32,imm32 ->
                            // Abs32.
                            if (is_branch && x.encoding.imm_size == 4)
                                ref.kind = K::BranchRel32;
                            else if (x.encoding.imm_size == 8)
                                ref.kind = K::Abs64;
                            else
                                ref.kind = K::Abs32;
                            r.sym_refs.push_back(std::move(ref));
                        } else if (op.type == X86_OP_MEM &&
                                   op.mem.base == X86_REG_RIP) {
                            // [rip+sym] (indirecto / lea).  Bug de Keystone con
                            // KS_OPT_SYM_RESOLVER: computa el disp relativo al
                            // INICIO del campo disp (ia+disp_offset) en vez del
                            // fin de instruccion (ia+il), asi el disp escrito
                            // es sym - (ia + disp_offset) y el sentinela
                            // original se recupera como disp + ia +
                            // disp_offset.  Usamos disp_offset DIRECTAMENTE (no
                            // il - disp_size): en instrucciones con inmediato
                            // despues del disp (p.ej. `mov [rip+sym], imm32`)
                            // el disp NO es el ultimo campo, asi que `il -
                            // disp_size` apuntaria al imm y el lookup del
                            // sentinela fallaria -> disp sin relocar
                            // -> escritura a direccion basura.  (El reloc
                            // DATA_REL32 que emitimos abajo sobrescribe el disp
                            // con el valor correcto via el driver.)
                            const uint64_t target =
                                ia + x.encoding.disp_offset + op.mem.disp;
                            const std::string *s = sym_state.symbol_for(target);
                            if (util::flag_on(util::FlagId::VxAsmDebug))
                                std::fprintf(stderr,
                                             "[asmdbg] rip-mem ia=%llx il=%llx "
                                             "disp=%lld target=%llx match=%d "
                                             "disp_off=%u disp_sz=%u\n",
                                             (unsigned long long)ia,
                                             (unsigned long long)il,
                                             (long long)op.mem.disp,
                                             (unsigned long long)target,
                                             s ? 1 : 0, x.encoding.disp_offset,
                                             x.encoding.disp_size);
                            if (!s || !x.encoding.disp_size) continue;
                            vx::AsmAssembleResult::SymRef ref;
                            ref.offset = static_cast<uint32_t>(
                                ia_rel + x.encoding.disp_offset);
                            ref.size = x.encoding.disp_size; // 4
                            // Bytes tras el disp dentro de la instruccion (imm
                            // en `mov [rip+disp32], imm32`): el disp rip-rel se
                            // mide desde el FIN de instruccion, no desde el fin
                            // del disp; el consumidor resta esto al addend.
                            ref.pcrel_trailing = static_cast<uint8_t>(
                                il - (x.encoding.disp_offset +
                                      x.encoding.disp_size));
                            ref.kind = K::DataRel32;
                            ref.symbol = *s;
                            r.sym_refs.push_back(std::move(ref));
                        }
                    }
                }
                if (n) cs_free(insn, n);
                cs_close(&h);
            }
        }

        // Escaneo de placeholders del routing imm64: por cada patch, localiza
        // sus 8 bytes LE en la salida y emite un SymRef Abs64.  Independiente
        // de Capstone (estos simbolos no pasaron por el sym-resolver).
        if (r.ok && !imm64_patches.empty()) {
            for (const auto &p : imm64_patches) {
                uint8_t pat[8];
                for (int i = 0; i < 8; ++i)
                    pat[i] =
                        static_cast<uint8_t>((p.placeholder >> (i * 8)) & 0xFF);
                for (size_t off = 0; off + 8 <= r.bytes.size(); ++off) {
                    if (std::memcmp(r.bytes.data() + off, pat, 8) == 0) {
                        vx::AsmAssembleResult::SymRef ref;
                        ref.offset = static_cast<uint32_t>(off);
                        ref.size = 8;
                        ref.kind = vx::AsmAssembleResult::SymRefKind::Abs64;
                        ref.symbol = p.symbol;
                        r.sym_refs.push_back(std::move(ref));
                        break; // un solo match por placeholder unico
                    }
                }
            }
        }
        ks_cache.emplace(std::move(cache_key), r);
        return r;
    }
};
} // namespace

void register_keystone_asm_backend() {
    static std::once_flag once;
    static KeystoneAsmBackend backend;
    std::call_once(once, [] {
        /* Se puede pedir que NO haya ensamblador.
         *
         * No es un interruptor de conveniencia: es la unica forma de probar
         * aqui lo que pasa en una maquina donde no lo hay -- la VM tiene que
         * poder correr en cualquier arquitectura, y ahi un bloque `asm` escrito
         * para otra no se puede ejecutar de ninguna manera.  Ese camino existia
         * sin poder ejercitarse, y por eso llevaba tiempo haciendo lo contrario
         * de lo correcto: avisar y seguir con los valores sin tocar.
         *
         * Con esto se comprueba que ahora para. */
        if (util::flag_on(util::FlagId::NoAsmBackend)) return;
        vx::g_asm_backend = &backend;
    });
}

} // namespace jit
