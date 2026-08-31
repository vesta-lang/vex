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
 * @file asm_effects.cpp
 * @brief  AS inc.4: implementacion de la inferencia PROPIA de clobbers.
 *
 * Sin dependencias de Keystone/Capstone.  Tabla plana mnemonic->efectos +
 * tokenizador ligero del cuerpo NASM Intel.
 */

#include "vx/asm/asm_effects.h"
#include "vx/asm/instr_db.h" // ancho de un operando, por ISA
#include "vx/parser.h" // get_aot_condcomp_target: el arch del TARGET, no del host

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace vx {

std::string asm_normalize_numbers(const std::string &body) {
    std::string out;
    out.reserve(body.size());
    const size_t n = body.size();
    auto is_id = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_';
    };
    size_t i = 0;
    while (i < n) {
        const char c = body[i];
        /* Placeholder $N (: operando `reg` auto, rellenado por el
         * backend post-regalloc) o referencia a la direccion actual ($): el
         * numero que sigue a '$' NO es un literal a normalizar -> copiar '$' +
         * sus digitos verbatim. */
        if (c == '$') {
            out.push_back('$');
            size_t j = i + 1;
            while (j < n && body[j] >= '0' && body[j] <= '9')
                out.push_back(body[j++]);
            i = j;
            continue;
        }
        /* Identificador (incl. registros r8/r15/xmm0): copiar el token
         * entero -> sus digitos NO son un literal numerico. */
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_') {
            size_t j = i;
            while (j < n && is_id(body[j]))
                ++j;
            out.append(body, i, j - i);
            i = j;
            continue;
        }
        /* Literal numerico: empieza por digito (char previo no-identificador).
         */
        if (c >= '0' && c <= '9') {
            int base = 10;
            size_t j = i;
            if (c == '0' && i + 1 < n) {
                const char p = body[i + 1];
                if (p == 'x' || p == 'X') {
                    base = 16;
                    j = i + 2;
                } else if (p == 'b' || p == 'B') {
                    base = 2;
                    j = i + 2;
                } else if (p == 'o' || p == 'O') {
                    base = 8;
                    j = i + 2;
                }
            }
            unsigned long long val = 0;
            bool any = false;
            while (j < n) {
                const char d = body[j];
                int dv;
                if (d == '_') {
                    ++j;
                    continue;
                } // separador de digitos
                if (d >= '0' && d <= '9')
                    dv = d - '0';
                else if (d >= 'a' && d <= 'f')
                    dv = d - 'a' + 10;
                else if (d >= 'A' && d <= 'F')
                    dv = d - 'A' + 10;
                else
                    break;
                if (dv >= base) break;
                val = val * static_cast<unsigned long long>(base) +
                      static_cast<unsigned long long>(dv);
                any = true;
                ++j;
            }
            if (!any) {
                out.push_back(c);
                ++i;
                continue;
            } // "0" suelto
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", val);
            out += buf;
            i = j;
            continue;
        }
        out.push_back(c);
        ++i;
    }
    return out;
}

// ---------------------------------------------------------------------------
//  Canonicalizacion de registros: UNA por arquitectura.
//
//  Cada arquitectura tiene sus nombres y sus reglas de alias, y no se parecen
//  en nada: mezclarlas en una sola funcion hace que anadir la tercera sea un
//  suplicio y que los nombres de una se cuelen en otra (`x0` no existe en x86,
//  `rax` no existe en ARM, y aceptar el ajeno es un error que hay que dar, no
//  tragarse).  Aqui cada una tiene su funcion, y @ref kArchRegs las asocia con
//  el valor de `arch:` del target.  Anadir RISC-V es anadir su funcion y su
//  fila; no se toca nada de lo demas.
//
//  El criterio comun -- lo unico que comparten -- es que los alias de ANCHO
//  colapsan al registro FISICO: `eax`->`rax` y `w3`->`x3` son la misma idea.
// ---------------------------------------------------------------------------

namespace {

/// Registros de x86-64.  Canonico: el nombre de 64 bits (`rax`, `r10`) y `vN`
/// para el banco vectorial (xmm/ymm/zmm N son la misma pista).
std::string canon_x86_64(const std::string &r) {
    // Registros de proposito general: cada entrada lista todos los alias
    // de ancho que mapean al mismo fisico de 64 bits.
    struct GpEntry {
        const char *canon;
        const char *aliases[6];
    };
    static const GpEntry gp[] = {
        {"rax", {"rax", "eax", "ax", "al", "ah", nullptr}},
        {"rbx", {"rbx", "ebx", "bx", "bl", "bh", nullptr}},
        {"rcx", {"rcx", "ecx", "cx", "cl", "ch", nullptr}},
        {"rdx", {"rdx", "edx", "dx", "dl", "dh", nullptr}},
        {"rsi", {"rsi", "esi", "si", "sil", nullptr}},
        {"rdi", {"rdi", "edi", "di", "dil", nullptr}},
        {"rbp", {"rbp", "ebp", "bp", "bpl", nullptr}},
        {"rsp", {"rsp", "esp", "sp", "spl", nullptr}},
    };
    for (const auto &e : gp) {
        for (const char *const *a = e.aliases; *a; ++a) {
            if (r == *a) return e.canon;
        }
    }
    // r8..r15 con sufijos d/w/b (32/16/8 bits) -> canonico rN.
    if (r.size() >= 2 && r[0] == 'r' && std::isdigit((unsigned char)r[1])) {
        std::string num;
        size_t i = 1;
        while (i < r.size() && std::isdigit((unsigned char)r[i]))
            num.push_back(r[i++]);
        std::string suf = r.substr(i);
        if (!num.empty() &&
            (suf.empty() || suf == "d" || suf == "w" || suf == "b")) {
            int n = std::atoi(num.c_str());
            if (n >= 8 && n <= 15) return "r" + num;
        }
    }
    // Vectoriales xmm/ymm/zmm N (0..31) -> canonico vN (mismo banco).
    for (const char *pfx : {"xmm", "ymm", "zmm"}) {
        const size_t plen = std::strlen(pfx);
        if (r.size() > plen && r.compare(0, plen, pfx) == 0) {
            std::string num = r.substr(plen);
            bool all_dig = !num.empty();
            for (char c : num) {
                if (!std::isdigit((unsigned char)c)) {
                    all_dig = false;
                    break;
                }
            }
            if (all_dig) {
                int n = std::atoi(num.c_str());
                if (n >= 0 && n <= 31) return "v" + num;
            }
        }
    }
    return std::string();
}

/// Todos los digitos y no vacio.
bool solo_digitos(const std::string &s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!std::isdigit((unsigned char)c)) return false;
    return true;
}

/// Registros de AArch64.  Canonico: el nombre de 64 bits (`x3`) y `vN` para el
/// banco SIMD/FP.  Nada que ver con los de x86: aqui `w3` es la mitad baja de
/// `x3` (como `eax` de `rax`) y `b0`/`h0`/`s0`/`d0`/`q0`/`v0` son la misma
/// pista SIMD vista con distinto ancho.
std::string canon_arm64(const std::string &r) {
    if (r == "xzr" || r == "wzr") return "xzr";              // registro cero
    if (r == "sp" || r == "wsp") return "sp";                // stack pointer
    if (r == "lr" || r == "x30" || r == "w30") return "x30"; // link register
    if (r == "fp" || r == "x29" || r == "w29") return "x29"; // frame pointer

    // x0..x30 / w0..w30 -> xN.
    if (r.size() >= 2 && (r[0] == 'x' || r[0] == 'w')) {
        const std::string num = r.substr(1);
        if (solo_digitos(num)) {
            const int n = std::atoi(num.c_str());
            if (n >= 0 && n <= 30) return "x" + num;
        }
    }
    // Banco SIMD/FP: b/h/s/d/q/v N (0..31) -> vN.  Se admite la forma con lane
    // (`v0.4s`), que nombra al mismo fisico.
    if (r.size() >= 2 && (r[0] == 'b' || r[0] == 'h' || r[0] == 's' ||
                          r[0] == 'd' || r[0] == 'q' || r[0] == 'v')) {
        std::string num = r.substr(1);
        const size_t punto = num.find('.');
        if (punto != std::string::npos) num = num.substr(0, punto);
        if (solo_digitos(num)) {
            const int n = std::atoi(num.c_str());
            if (n >= 0 && n <= 31) return "v" + num;
        }
    }
    return std::string();
}

/// Que canonicalizador usa cada valor de `arch:`.  Anadir una arquitectura es
/// anadir su funcion y su fila aqui.
struct ArchRegs {
    const char *arch;
    std::string (*canon)(const std::string &);
};
const ArchRegs kArchRegs[] = {
    {"x86_64", &canon_x86_64},
    {"x86", &canon_x86_64}, // mismo banco (los de 64 bits sobran, y el
                            // ensamblador ya los rechaza por su cuenta)
    {"arm64", &canon_arm64},
};

// ---------------------------------------------------------------------------
//  Como propaga cada instruccion un puntero.  Mismo reparto que los registros:
//  cada arquitectura declara los SUYOS y quien sigue el puntero no conoce
//  ninguno -- pregunta por la clase.  Anadir RISC-V es anadir su funcion y su
//  fila, sin tocar el analisis.
// ---------------------------------------------------------------------------

/// x86: mover, calcular direcciones y aritmetica de desplazamiento.
AsmTransferencia transferencia_x86(const std::string &m) {
    if (m == "mov" || m == "movq" || m == "movabs")
        return AsmTransferencia::Transfiere;
    if (m == "lea") return AsmTransferencia::Direccion;
    if (m == "add") return AsmTransferencia::Suma;
    if (m == "sub") return AsmTransferencia::Resta;
    return AsmTransferencia::Ninguna;
}

/// arm64: las cargas son instrucciones propias, y la direccion se calcula con
/// `add` o se toma con `adr`.
AsmTransferencia transferencia_arm64(const std::string &m) {
    if (m == "mov" || m == "ldr" || m == "ldur")
        return AsmTransferencia::Transfiere;
    if (m == "adr" || m == "adrp") return AsmTransferencia::Direccion;
    if (m == "add") return AsmTransferencia::Suma;
    if (m == "sub") return AsmTransferencia::Resta;
    return AsmTransferencia::Ninguna;
}

/// Asocia cada arquitectura con su tabla de transferencia.
struct ArchTransfer {
    const char *arch;
    AsmTransferencia (*fn)(const std::string &);
};
const ArchTransfer kArchTransfer[] = {
    {"x86_64", &transferencia_x86},
    {"x86", &transferencia_x86},
    {"arm64", &transferencia_arm64},
};

/// Pistas de tamano de la sintaxis Intel (`qword ptr [rdi]`).  ARM no tiene:
/// alli el ancho lo dicen el registro y el mnemonico.
uint32_t pista_x86(const std::string &pre) {
    static const struct {
        const char *nombre;
        uint32_t bytes;
    } kPistas[] = {{"byte", 1},     {"word", 2},     {"dword", 4},
                   {"qword", 8},    {"xmmword", 16}, {"oword", 16},
                   {"ymmword", 32}, {"zmmword", 64}};
    /* De mas larga a mas corta no hace falta: los nombres largos CONTIENEN a
     * los cortos (`dword` lleva `word` dentro), asi que se busca el mas largo
     * que encaje y se devuelve ese. */
    uint32_t mejor = 0;
    size_t largo = 0;
    for (const auto &p : kPistas) {
        const size_t n = std::strlen(p.nombre);
        if (pre.find(p.nombre) != std::string::npos && n > largo) {
            largo = n;
            mejor = p.bytes;
        }
    }
    return mejor;
}

struct ArchPista {
    const char *arch;
    uint32_t (*fn)(const std::string &);
};
const ArchPista kArchPistas[] = {
    {"x86_64", &pista_x86},
    {"x86", &pista_x86},
};

} // namespace

/* Sale del anonimato porque ya no la usa solo este fichero: el JIT tiene que
 * preguntar para QUE maquina genera codigo, y la respuesta no es el objetivo
 * declarado -- ese es el del AOT -- sino donde se va a ejecutar. */
const char *arch_host() {
#if defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "x86_64";
#endif
}

std::string asm_canonical_reg(const std::string &raw, const std::string &arch) {
    std::string r;
    r.reserve(raw.size());
    for (char c : raw)
        r.push_back((char)std::tolower((unsigned char)c));
    for (const auto &a : kArchRegs)
        if (arch == a.arch) return a.canon(r);
    return std::string();
}

std::string asm_arch_actual() {
    std::string os, arch;
    get_aot_condcomp_target(os, arch);
    if (arch.empty()) arch = arch_host();
    return arch;
}

instr_db::Isa isa_host() {
    return isa_of_arch(arch_host());
}

std::string asm_canonical_reg(const std::string &raw) {
    return asm_canonical_reg(raw, asm_arch_actual());
}

/// ISA del objetivo activo, para preguntarle a la base de instrucciones.  Sale
/// del MISMO sitio que los registros: el target que se compila, no el host.
/// La ISA de un nombre de arquitectura CUALQUIERA, no solo del objetivo activo.
///
/// Estaba solo dentro de `isa_actual`, asi que quien analizaba un bloque para
/// una arquitectura dada -- que es lo normal: el analisis recibe la suya -- no
/// tenia a quien preguntarle y habria tenido que repetir la correspondencia.
/// Dos copias de la misma tabla se separan, y el sintoma seria leer la base de
/// otra ISA.
instr_db::Isa isa_of_arch(const std::string &arch) {
    if (arch == "arm64" || arch == "aarch64") return instr_db::Isa::ARM64;
    if (arch == "arm" || arch == "arm32") return instr_db::Isa::ARM32;
    if (arch == "riscv" || arch == "riscv64") return instr_db::Isa::RISCV;
    return instr_db::Isa::X86;
}

instr_db::Isa isa_actual() {
    return isa_of_arch(asm_arch_actual());
}

// -----------------------------------------------------------------------
// Tabla plana mnemonic -> AsmEffects.  Subset comun, extensible.  Los
// registros van en forma canonica.  Construida una vez (lazy) en un
// unordered_map; el lookup es compile-time (no hot path runtime).
// -----------------------------------------------------------------------
namespace {

/// Tipo de una tabla de efectos por-mnemonico (en forma canonica-minuscula).
using EffTable = std::unordered_map<std::string, AsmEffects>;

/// Tabla de efectos x86 (16/32/64 comparten mnemonicos; el efecto de @c add /
/// @c mov / @c cmp no cambia con el ancho).  Lazy-init, se construye una vez.
const EffTable &x86_effects_table() {
    static const EffTable table = [] {
        EffTable t;
        auto add = [&t](const char *m, AsmEffects e) {
            e.known = true;
            t[m] = std::move(e);
        };
        // Helpers de construccion.  wmask = bitmask de operandos escritos
        // (bit0=op1, bit1=op2, ...); un `true`/`false` viejo cuenta como
        // 0x1/0x0 (escribe/no el 1er operando).
        auto E = [](std::initializer_list<const char *> wr, uint8_t wmask,
                    bool mem, bool flags, bool call = false,
                    std::initializer_list<const char *> rd = {}) {
            AsmEffects e;
            for (const char *w : wr)
                e.implicit_write.emplace_back(w);
            for (const char *r : rd)
                e.implicit_read.emplace_back(r);
            e.operand_write_mask = wmask;
            e.touches_mem = mem;
            e.writes_flags = flags;
            e.is_call = call;
            return e;
        };
        // --- Instrucciones con efectos IMPLICITOS sobre registros ---
        add("rdtsc", E({"rax", "rdx"}, false, false, false));
        add("rdtscp", E({"rax", "rdx", "rcx"}, false, false, false));
        add("cpuid", E({"rax", "rbx", "rcx", "rdx"}, false, false, false));
        add("rdpmc", E({"rax", "rdx"}, false, false, false));
        add("rdrand", E({}, true, false, true)); // escribe dest + CF
        add("rdseed", E({}, true, false, true));
        /* --- Barreras y espera activa ---
         * Las usa la stdlib (atomicos, canales, mutex, pool) y no estaban
         * tabuladas: dejaban el bloque como desconocido, o sea una caja negra
         * en el corazon de la concurrencia. */
        for (const char *m : {"mfence", "lfence", "sfence"}) {
            AsmEffects f = E({}, 0x0, false, false);
            f.barrier = true; // no toca nada, pero ORDENA lo de alrededor
            add(m, f);
        }
        // `pause` es una PISTA para la espera activa: no hace nada observable.
        add("pause", E({}, 0x0, false, false));
        /* --- Operaciones de cadena ---
         * No llevan corchetes, pero se sabe EXACTAMENTE por donde acceden: la
         * arquitectura fija que la fuente va por `rsi` y el destino por `rdi`.
         * Se declara asi, con sus registros, en vez de decir "toca memoria en
         * algun sitio": lo segundo no seria conservador sino incompleto -- el
         * dato esta, solo habia que ponerlo --, y ademas apagaria todo lo que
         * haya alrededor.
         *
         * `cmps`/`scas` ademas comparan, asi que tocan flags. */
        auto cadena = [&](const char *m, bool lee_rsi, bool escribe_rdi,
                          bool lee_rdi, bool flags, uint16_t bytes) {
            AsmEffects s = E({}, 0x0, /*mem=*/true, flags);
            if (lee_rsi) s.implicit_mem_read.emplace_back("rsi");
            if (lee_rdi) s.implicit_mem_read.emplace_back("rdi");
            if (escribe_rdi) s.implicit_mem_write.emplace_back("rdi");
            /* Cuanto toca CADA paso.  Lo dice el sufijo, y por eso se declara
             * aqui: quien analiza el bloque no tiene por que saber que una `q`
             * al final significa ocho bytes en esta arquitectura. */
            s.mem_bytes_implicito = bytes;
            add(m, s);
        };
        // El sufijo b/w/d/q es el ancho de cada paso: 1, 2, 4 y 8 bytes.
        static const uint16_t kAnchoSufijo[4] = {1, 2, 4, 8};
        {
            const char *movs[4] = {"movsb", "movsw", "movsd", "movsq"};
            const char *stos[4] = {"stosb", "stosw", "stosd", "stosq"};
            const char *lods[4] = {"lodsb", "lodsw", "lodsd", "lodsq"};
            const char *cmps[4] = {"cmpsb", "cmpsw", "cmpsd", "cmpsq"};
            const char *scas[4] = {"scasb", "scasw", "scasd", "scasq"};
            for (int k = 0; k < 4; ++k) {
                const uint16_t w = kAnchoSufijo[k];
                cadena(movs[k], true, true, false, false, w); // [rdi] <- [rsi]
                cadena(stos[k], false, true, false, false,
                       w); // [rdi] <- al/...
                cadena(lods[k], true, false, false, false,
                       w);                                    // al/... <- [rsi]
                cadena(cmps[k], true, false, true, true, w);  // [rsi] vs [rdi]
                cadena(scas[k], false, false, true, true, w); // al/... vs [rdi]
            }
        }

        /* --- Entrada/salida por PUERTO ---
         * Las usa cualquier sistema operativo (teclado, reloj, consola serie) y
         * no estaban tabuladas: un `in`/`out` dejaba el bloque entero como
         * desconocido, o sea una caja negra en mitad del kernel.
         *
         * No tocan memoria, pero NO son puras: hablan con el exterior.  Van
         * marcadas como tales para que nadie las trate como aritmetica -- ni
         * las borre por "no hacer nada" ni las reordene -- y para que quien las
         * use no pase por codigo autonomo.
         *   in  dst, puerto  -> escribe el 1er operando (al/ax/eax)
         *   out puerto, src  -> no escribe ningun registro */
        {
            AsmEffects in_e = E({}, 0x1, false, false);
            in_e.port_io = true;
            add("in", in_e);
            AsmEffects out_e = E({}, 0x0, false, false);
            out_e.port_io = true;
            add("out", out_e);
            // Variantes de cadena: mueven un bloque entre puerto y memoria.
            for (const char *m :
                 {"insb", "insw", "insd", "outsb", "outsw", "outsd"}) {
                AsmEffects s = E({}, 0x0, /*mem=*/true, false);
                s.port_io = true;
                add(m, s);
            }
        }
        /* mul/imul de UN operando + div/idiv: el otro factor es el acumulador y
         * el resultado va a `rdx:rax`, sin que ninguno aparezca en el texto. */
        add("mul", E({"rax", "rdx"}, false, false, true));
        add("imul", E({"rax", "rdx"}, false, false, true));
        add("div", E({"rax", "rdx"}, false, false, true));
        add("idiv", E({"rax", "rdx"}, false, false, true));
        /* Y la forma de DOS o tres operandos de `imul`, que deja el producto
         * solo en su destino y no toca `rdx`.  Vive con un sufijo porque la
         * tabla se indexa por mnemonico y el mnemonico es el mismo; quien
         * conoce los operandos -- el analisis de la linea -- elige cual de las
         * dos.  Es la misma solucion que `movsd_sse`, por el mismo motivo.
         *
         * El nombre con sufijo no lo escribe nadie: no es sintaxis. */
        add("imul_2op", E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/true));
        add("cqo", E({"rdx"}, false, false, false));
        add("cdq", E({"rdx"}, false, false, false));
        // syscall (Linux x64 + Windows x64 NT): escribe RAX (valor de retorno)
        // + clobber rcx, r11 + caller-saved via is_call.  RAX en implicit_write
        // hace que un param `register("rax")` leido tras el asm (read-back del
        // resultado) se clasifique INOUT (el asm lo define).  La MISMA
        // instruccion cubre Linux y Windows x64 (el numero de servicio y los
        // arg-regs son convencion del usuario via register(), no del opcode).
        // LEE el numero de servicio (RAX) + los args.  Conservador: la union de
        // las convenciones Linux (RDI/RSI/RDX/R10/R8/R9) y Windows NT (R10/RDX/
        // R8/R9) -- asi un `register("rdi")`/`register("r10")` vive HASTA el
        // syscall y el arg se coloca en su registro (sin esto el DCE lo
        // borraba).
        add("syscall",
            E({"rax", "rcx", "r11"}, false, true, true, /*call=*/true,
              {"rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"}));
        add("sysenter", E({"rax"}, false, true, true, true,
                          {"rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"}));
        // int (Linux x86-32 `int 0x80`): escribe EAX con el valor de retorno y
        // LEE EAX (num) + EBX/ECX/EDX/ESI/EDI/EBP (args).  Canonicos
        // (rax/rbx/...).
        add("int", E({"rax"}, false, true, true, /*call=*/true,
                     {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp"}));
        // call/ret: call clobbera caller-saved (is_call).
        add("call", E({}, false, true, true, /*call=*/true));
        // --- Aritmetica/bitwise que escribe el 1er operando + flags ---
        add("add", E({}, true, false, true));
        add("sub", E({}, true, false, true));
        add("and", E({}, true, false, true));
        add("or", E({}, true, false, true));
        add("xor", E({}, true, false, true));
        add("neg", E({}, true, false, true));
        add("inc", E({}, true, false, true)); // no CF, pero conservador
        add("dec", E({}, true, false, true));
        add("shl", E({}, true, false, true));
        add("shr", E({}, true, false, true));
        add("sar", E({}, true, false, true));
        add("rol", E({}, true, false, true));
        add("ror", E({}, true, false, true));
        add("popcnt", E({}, true, false, true));
        add("lzcnt", E({}, true, false, true));
        add("tzcnt", E({}, true, false, true));
        add("bsf", E({}, true, false, true));
        add("bsr", E({}, true, false, true));
        add("bswap", E({}, true, false, false));
        /* --- Las que ademas CONSUMEN una bandera ----------------------------
         *
         * Estas cuatro leen el acarreo Y lo vuelven a escribir: `adc` suma con
         * acarreo, `rcl` rota a traves de el.  Declarar solo la escritura las
         * hacia parecer productoras puras, y entonces una `add` que produjo el
         * acarreo se podia mover por debajo de la `adc` que lo consume -- que
         * es como se rompe una suma de 128 bits, y el sintoma seria un bit
         * perdido en el resultado, sin nada que cascara. */
        {
            auto lee_y_escribe_banderas = [&](const char *m) {
                AsmEffects e = E({}, /*wmask=*/0x1, /*mem=*/false,
                                 /*flags=*/true);
                e.reads_flags = true;
                add(m, std::move(e));
            };
            for (const char *m : {"adc", "sbb", "rcl", "rcr", "adcx", "adox"})
                lee_y_escribe_banderas(m);
            /* Y las que SOLO las leen o SOLO las escriben, sin operandos.  No
             * estaban, con lo que un `stc` seguido de una `adc` dejaba al
             * planificador libre para separarlos. */
            {
                AsmEffects e = E({}, /*wmask=*/0x0, /*mem=*/false,
                                 /*flags=*/false);
                e.reads_flags = true;
                add("lahf", std::move(e)); // las lleva a AH: las lee
            }
            /* `pushf`/`popf` las mueven a la PILA, asi que ademas de banderas
             * tocan memoria por `rsp` -- y se dice por donde, que es la
             * diferencia entre saberlo y dar la memoria entera por tocada. */
            for (const char *m : {"pushf", "pushfq"}) {
                /* Y MUEVEN `rsp`, igual que cualquier `push`: se lee para saber
                 * donde escribir y se escribe al bajarlo.  Sin declarar la
                 * escritura, quien crea que `rsp` sigue donde estaba calcula
                 * mal cualquier direccion que salga de el. */
                AsmEffects e = E({"rsp"}, 0x0, /*mem=*/true, /*flags=*/false,
                                 /*call=*/false, {"rsp"});
                e.reads_flags = true;
                e.implicit_mem_write.emplace_back("rsp");
                add(m, std::move(e));
            }
            for (const char *m : {"popf", "popfq"}) {
                AsmEffects e = E({"rsp"}, 0x0, /*mem=*/true, /*flags=*/true,
                                 /*call=*/false, {"rsp"});
                e.implicit_mem_read.emplace_back("rsp");
                add(m, std::move(e));
            }
            // `cmc` complementa el acarreo: lo lee y lo escribe.
            {
                AsmEffects e = E({}, 0x0, false, /*flags=*/true);
                e.reads_flags = true;
                add("cmc", std::move(e));
            }
            // Poner/quitar una bandera a mano: solo escriben.
            for (const char *m :
                 {"stc", "clc", "std", "cld", "sti", "cli", "sahf"})
                add(m, E({}, 0x0, false, /*flags=*/true));
        }
        /* --- Movimientos del banco VECTORIAL --------------------------------
         *
         * Todos escriben su primer operando y ninguno toca flags; lo que los
         * distingue -- y lo unico que hace falta saber para no escribir un
         * programa que casca -- es cual EXIGE que la direccion este alineada.
         *
         * La arquitectura los separa en dos familias con nombres casi iguales,
         * y ahi esta la trampa: una letra.  `movdqa` con una direccion que no
         * es multiplo de 16 lanza una excepcion; `movdqu` con la misma
         * direccion funciona.  Sin tabular esa diferencia, escribir la
         * equivocada no da ningun aviso al compilar y el programa cae en
         * ejecucion -- que es exactamente lo que paso.
         *
         * Las no temporales (`movntdq` y companeras) exigen igual que las
         * alineadas: la escritura se salta la cache, pero la direccion tiene
         * que estar igual de alineada.
         */
        {
            // Sin exigencia: la `u` de "unaligned" es lo que las distingue.
            for (const char *m :
                 {"movdqu", "movups", "movupd", "vmovdqu", "vmovups", "vmovupd",
                  "vmovdqu8", "vmovdqu16", "vmovdqu32", "vmovdqu64"})
                add(m, E({}, true, false, false));
            // Exigen que la direccion sea multiplo del ancho de su operando.
            auto alineada = [&](const char *m) {
                /* `mem` es memoria IMPLICITA -- la que la instruccion toca sin
                 * que aparezca en el texto, como el `rdi` de una `stosb` --, y
                 * estas no tienen ninguna: acceden por un operando EXPLICITO,
                 * con sus corchetes, y de eso ya se encarga el analisis del
                 * texto.
                 *
                 * Estuvo a `true` un rato, y eso era peor que el problema que
                 * pretendia arreglar: con ese bit, un `movdqa xmm0, xmm1` --
                 * una copia entre registros, sin un corchete a la vista --
                 * salia leyendo Y escribiendo memoria, o sea que cada
                 * movimiento vectorial se convertia en una barrera para todo lo
                 * que le rodeaba.  Y ademas por partida doble: quien lo consume
                 * no puede saber por donde accede, asi que tiene que dar la
                 * memoria entera por tocada.
                 *
                 * Lo unico propio de esta familia es lo que EXIGEN: que la
                 * direccion sea multiplo del ancho de su operando.  `movdqa`
                 * con una direccion que no lo es lanza una excepcion y `movdqu`
                 * con la misma direccion funciona, y esa letra de diferencia no
                 * da ningun aviso al compilar. */
                AsmEffects e = E({}, /*wmask=*/0x1, /*mem=*/false,
                                 /*flags=*/false);
                e.align_req = kAlignAnchoOperando;
                add(m, std::move(e));
            };
            for (const char *m :
                 {"movdqa", "movaps", "movapd", "vmovdqa", "vmovaps", "vmovapd",
                  "vmovdqa32", "vmovdqa64",
                  // No temporales: se saltan la cache, no la alineacion.
                  "movntdq", "movntps", "movntpd", "vmovntdq", "vmovntps",
                  "vmovntpd", "vmovntdqa"})
                alineada(m);
            // Movimientos escalares entre bancos y difusiones: sin exigencia
            // de alineacion (acceden a 4 u 8 bytes, que la arquitectura no
            // obliga a alinear en estas formas).
            for (const char *m :
                 {"movq",         "movd",         "vmovq",
                  "vmovd",        "movss",        "movsd_sse",
                  "vmovss",       "vmovsd",       "pinsrq",
                  "pinsrd",       "vpinsrq",      "vpinsrd",
                  "punpcklqdq",   "vpunpcklqdq",  "vpbroadcastq",
                  "vpbroadcastd", "vpbroadcastb", "vbroadcastss",
                  "vbroadcastsd", "pshufd",       "vpshufd",
                  "pxor",         "vpxor",        "xorps",
                  "vxorps"})
                add(m, E({}, true, false, false));
            // Cierre del modo ancho: ni escribe operandos ni toca memoria,
            // pero no es una instruccion cualquiera -- deshace la penalizacion
            // de mezclar codificaciones, asi que quien la quite cambia el
            // rendimiento sin cambiar el resultado.
            add("vzeroupper", E({}, 0x0, false, false));
            add("vzeroall", E({}, 0x0, false, false));
        }

        // --- Movimientos / direcciones (escriben 1er operando, sin flags) ---
        add("mov", E({}, true, false, false));
        add("movzx", E({}, true, false, false));
        add("movsx", E({}, true, false, false));
        add("movsxd", E({}, true, false, false));
        add("lea", E({}, true, false, false));

        /* Probar un bit: no estaban, y su efecto es precisamente dejar el bit
         * probado en el acarreo.  Sin declararlo, un `bt` seguido de un `jc`
         * puede reordenarse y el salto decide con una bandera de otra
         * instruccion. */
        add("bt", E({}, /*wmask=*/0x0, /*mem=*/false, /*flags=*/true));
        /* Las tres que ademas MODIFICAN el bit escriben su primer operando. */
        add("bts", E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/true));
        add("btr", E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/true));
        add("btc", E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/true));
        /* Y las de buscar un bit: dejan cero si no habia ninguno. */
        add("bsf", E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/true));
        add("bsr", E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/true));

        /* --- Aritmetica y logica EMPAQUETADA (SIMD) ---
         *
         * No estaba ninguna, asi que un `paddd $1, [$0]` -- sumar contra
         * memoria, que es el patron de cualquier bucle vectorizado a mano -- no
         * declaraba ni la lectura.  Y un acceso que no se declara es una
         * escritura ajena que se puede mover por encima de el.
         *
         * Escriben su primer operando y NO tocan banderas: eso las distingue de
         * la aritmetica entera, y es la diferencia que permite mover una
         * comparacion a traves de ellas.  Que su operando pueda ser memoria lo
         * dice el propio texto, con sus corchetes; aqui solo se declara la
         * forma.
         */
        auto empaquetada = [&](const char *m) {
            add(m, E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/false));
        };
        for (const char *m :
             {// Enteras: suma, resta, producto, y sus formas AVX.
              "paddb", "paddw", "paddd", "paddq", "psubb", "psubw", "psubd",
              "psubq", "pmullw", "pmulld", "pmuludq", "pmaddwd", "vpaddb",
              "vpaddw", "vpaddd", "vpaddq", "vpsubb", "vpsubw", "vpsubd",
              "vpsubq", "vpmulld", "vpmuludq",
              // Con saturacion: las de tratamiento de senal y de imagen.
              "paddsb", "paddsw", "paddusb", "paddusw", "psubsb", "psubsw",
              "psubusb", "psubusw", "vpaddusb", "vpaddusw",
              // Logica empaquetada.
              "pand", "pandn", "por", "pxor", "vpand", "vpandn", "vpor",
              "vpxor",
              // Desplazamientos empaquetados.
              "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw",
              "psrad", "vpsllw", "vpslld", "vpsllq", "vpsrlw", "vpsrld",
              "vpsrlq",
              // Comparacion empaquetada: deja una MASCARA en el destino, no
              // banderas -- por eso no lleva `flags`.
              "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd",
              "vpcmpeqb", "vpcmpeqd", "vpcmpgtd",
              // Minimos, maximos y promedios.
              "pminub", "pminsw", "pmaxub", "pmaxsw", "pavgb", "pavgw",
              // Empaquetar y desempaquetar.
              "packuswb", "packsswb", "packssdw", "punpckhbw", "punpckhwd",
              "punpckhdq", "punpckhqdq",
              // Flotante empaquetado, simple y doble, con sus formas AVX.
              "addps", "addpd", "subps", "subpd", "mulps", "mulpd", "divps",
              "divpd", "minps", "minpd", "maxps", "maxpd", "sqrtps", "sqrtpd",
              "andps", "andpd", "orps", "orpd", "xorps", "xorpd", "vaddps",
              "vaddpd", "vsubps", "vsubpd", "vmulps", "vmulpd", "vdivps",
              "vdivpd", "vminps", "vmaxps", "vsqrtps", "vxorps",
              // Multiplicar y acumular en una: la base del producto de
              // matrices.
              "vfmadd231ps", "vfmadd231pd", "vfmadd213ps", "vfmadd132ps",
              // Escalares flotantes: mismas reglas, un solo elemento.
              "addss", "addsd", "subss", "subsd", "mulss", "mulsd", "divss",
              "divsd", "sqrtss", "sqrtsd", "vaddss", "vaddsd", "vmulss",
              "vmulsd"})
            empaquetada(m);
        /* Las que SI dejan banderas: comparar escalares las escribe de verdad,
         * y de ahi que sean las unicas de la familia con las que se puede
         * saltar directamente. */
        for (const char *m :
             {"comiss", "comisd", "ucomiss", "ucomisd", "vcomiss", "vucomisd"})
            add(m, E({}, /*wmask=*/0x0, /*mem=*/false, /*flags=*/true));
        add("xchg", E({}, 0x3, false, false)); // escribe AMBOS operandos
        // --- Atomicas RMW x86 (siempre con prefijo lock salvo xchg): tocan
        //     memoria + flags; cmpxchg compara/escribe rax.  cmpxchg16b usa
        //     rdx:rax (esperado) y rcx:rbx (deseado) -> DWCAS lock-free real.
        //     ---
        add("cmpxchg", E({"rax"}, 0x1, true, true)); // dest(op1) + rax + mem
        add("cmpxchg8b", E({"rax", "rdx"}, false, true, true));
        add("cmpxchg16b", E({"rax", "rdx"}, false, true, true));
        add("xadd", E({}, true, true, true)); // 1er op + mem + flags
        add("cmov", E({}, true, false, false));
        add("not", E({}, true, false, false)); // not no toca flags
        add("set", E({}, true, false, false)); // setcc: escribe 1er op (byte)
        // --- Comparaciones / test: solo flags ---
        add("cmp", E({}, false, false, true));
        add("test", E({}, false, false, true));
        /* --- Pila: tocan memoria + rsp ---
         *
         * Y se dice POR DONDE: la arquitectura fija que se accede por `rsp`,
         * igual de fijo que si estuviera escrito entre corchetes.  Sin
         * declararlo, el bloque quedaba marcado como que toca memoria que no
         * sabe nombrar, y eso obliga a suponer lo peor de TODA la memoria --
         * cuando lo unico que se toca es la cima de la pila --.
         *
         * `mem_bytes_implicito` se queda a cero a proposito: cuanto se apila
         * depende del modo (ocho bytes en 64, cuatro en 32) y esta tabla es la
         * misma para los tres anchos de x86.  No saber la extension no impide
         * saber la base, y afirmar una extension equivocada si haria dano. */
        {
            AsmEffects e = E({"rsp"}, /*wmask=*/0x0, /*mem=*/true,
                             /*flags=*/false, /*call=*/false, {"rsp"});
            e.implicit_mem_write.emplace_back("rsp");
            add("push", std::move(e));
        }
        {
            AsmEffects e = E({"rsp"}, /*wmask=*/0x1, /*mem=*/true,
                             /*flags=*/false, /*call=*/false, {"rsp"});
            e.implicit_mem_read.emplace_back("rsp");
            add("pop", std::move(e));
        }
        // --- Control de flujo / no-ops: sin clobbers ---
        add("nop", E({}, false, false, false));
        /* Trampas de depuracion: no tocan memoria ni registros; ceden el
         * control al depurador (o abortan si no hay).  Salian como mnemonico
         * sin tabular en cuanto se analizaba `vx_io.vx` para nativo, que usa
         * `int3` en su ruta de fallo. */
        add("int3", E({}, false, false, false));
        add("ud2", E({}, false, false, false));
        /* `ret` saca la direccion de retorno de la PILA -- al contrario que en
         * arm, donde vive en un registro --, asi que lee memoria por `rsp` y lo
         * mueve.  Se dice por donde: sin eso, cualquier bloque con un `ret`
         * queda tocando memoria que no sabe nombrar. */
        {
            AsmEffects e =
                E({"rsp"}, /*wmask=*/0x0, /*mem=*/true, /*flags=*/false,
                  /*call=*/false, {"rsp"});
            e.implicit_mem_read.emplace_back("rsp");
            add("ret", std::move(e));
        }
        add("jmp", E({}, false, false, false));
        {
            AsmEffects e = E({"rsp", "rbp"}, /*wmask=*/0x0, /*mem=*/true,
                             /*flags=*/false, /*call=*/false, {"rbp"});
            e.implicit_mem_read.emplace_back("rbp");
            add("leave", std::move(e));
        }
        /* Saltos condicionales: solo LEEN las banderas.
         *
         * Lo decia el comentario y no lo decia el codigo, que declaraba un
         * efecto vacio.  Con eso el salto no dependia de nada, y la comparacion
         * que lo decide se quedaba sin nadie que la use: se puede mover por
         * debajo del salto o eliminarse por muerta.  El mismo hueco estaba en
         * `b.CC` de arm64 y en `setcc`/`cmovcc`. */
        for (const char *j :
             {"je",  "jne",  "jz",  "jnz",  "jg",  "jge",  "jl",  "jle",
              "ja",  "jae",  "jb",  "jbe",  "jo",  "jno",  "js",  "jns",
              "jc",  "jnc",  "jp",  "jnp",  "jpe", "jpo",  "jna", "jnae",
              "jnb", "jnbe", "jng", "jnge", "jnl", "jnle", "jeq"}) {
            AsmEffects e = E({}, 0x0, false, false);
            e.reads_flags = true;
            add(j, std::move(e));
        }
        /* `jcxz`/`jecxz`/`jrcxz` miran el REGISTRO contador, no las banderas:
         * es lo que las separa del resto de los saltos condicionales. */
        for (const char *j : {"jcxz", "jecxz", "jrcxz"})
            add(j, E({}, 0x0, false, false, false, {"rcx"}));
        /* `mulx` (BMI2) multiplica sin tocar banderas y con destino EXPLICITO:
         * escribe sus dos primeros operandos y lee `rdx` sin nombrarlo.  Ese
         * operando implicito es lo que impide que la base la modele por si
         * sola, asi que aqui se declara. */
        add("mulx", E({}, /*wmask=*/0x3, /*mem=*/false, /*flags=*/false,
                      /*call=*/false, {"rdx"}));
        return t;
    }();
    return table;
}

/// Tabla de efectos AArch64 (arm64).  A diferencia de x86, la aritmetica base
/// NO toca flags (solo las formas con sufijo @c s: @c adds/@c subs/@c ands);
/// @c cmp/@c cmn/@c tst comparan sin escribir registro.  Las cargas/almacenes
/// LL/SC (@c ldaxr/@c stlxr...) y las CAS/RMW atomicas (@c cas*/@c ldadd*/
/// @c swp*) tocan memoria; el modulo de bloque las marca ademas como atomicas.
const EffTable &arm64_effects_table() {
    static const EffTable table = [] {
        EffTable t;
        auto add = [&t](const char *m, AsmEffects e) {
            e.known = true;
            t[m] = std::move(e);
        };
        // wr=implicit_write, wmask=bitmask de operandos escritos, mem, flags,
        // call (un `true`/`false` viejo = 0x1/0x0, escribe/no el 1er operando).
        auto E = [](std::initializer_list<const char *> wr, uint8_t wmask,
                    bool mem, bool flags, bool call = false,
                    std::initializer_list<const char *> rd = {}) {
            AsmEffects e;
            for (const char *w : wr)
                e.implicit_write.emplace_back(w);
            for (const char *r : rd)
                e.implicit_read.emplace_back(r);
            e.operand_write_mask = wmask;
            e.touches_mem = mem;
            e.writes_flags = flags;
            e.is_call = call;
            return e;
        };
        // --- Aritmetica/logica (escriben 1er operando; NO flags salvo `s`) ---
        for (const char *m :
             {"add",  "sub",  "mul",  "madd", "msub", "and",   "orr",
              "eor",  "bic",  "orn",  "eon",  "lsl",  "lsr",   "asr",
              "ror",  "neg",  "mvn",  "udiv", "sdiv", "smull", "umull",
              "sxtw", "uxtw", "sxth", "uxth", "sxtb", "uxtb"})
            add(m, E({}, true, false, false));
        // Formas que SI actualizan flags (sufijo `s`).
        for (const char *m : {"adds", "subs", "ands", "bics", "negs"})
            add(m, E({}, true, false, true));
        // cmp/cmn/tst: comparan (solo flags, sin escribir registro).
        add("cmp", E({}, false, false, true));
        add("cmn", E({}, false, false, true));
        add("tst", E({}, false, false, true));
        // --- Movimientos / carga de inmediato / direccion ---
        for (const char *m :
             {"mov", "movz", "movk", "movn", "adr", "adrp", "fmov"})
            add(m, E({}, true, false, false));
        /* --- Seleccion condicional: CONSUMEN las banderas ---
         *
         * El comentario ya decia "leen flags" y el codigo no lo declaraba: es
         * el mismo hueco que tenian `setcc`/`cmovcc` en x86.  Sin la lectura,
         * el bloque se puede mover por encima del `cmp` que produjo la bandera
         * con la que decide, y entonces decide con la de otra comparacion -- un
         * fallo que depende de si al planificador le convino reordenar. */
        for (const char *m : {"csel", "cset", "csetm", "csinc", "csinv",
                              "csneg", "cinc", "cinv", "cneg"}) {
            AsmEffects e = E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/false);
            e.reads_flags = true;
            add(m, std::move(e));
        }
        /* Y la comparacion CONDICIONAL hace las dos cosas y no escribe ningun
         * registro: lee las banderas para decidir si compara, y las escribe con
         * el resultado.  Estaba declarada como que escribe su primer operando,
         * que es el valor que compara: se daba por destruido. */
        for (const char *m : {"ccmp", "ccmn"}) {
            AsmEffects e = E({}, /*wmask=*/0x0, /*mem=*/false, /*flags=*/true);
            e.reads_flags = true;
            add(m, std::move(e));
        }
        // --- Bit / rev / bitfield (escriben 1er operando) ---
        for (const char *m :
             {"clz", "cls", "rbit", "rev", "rev16", "rev32", "ubfx", "sbfx",
              "ubfm", "sbfm", "bfi", "bfxil", "extr"})
            add(m, E({}, true, false, false));
        // --- Cargas: escriben 1er operando + memoria ---
        for (const char *m :
             {"ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh", "ldur"})
            add(m, E({}, true, true, false));
        /* `ldp` carga un PAR: escribe DOS destinos.  Con la mascara a 0x1 el
         * segundo se daba por intacto, y quien creyera que sigue valiendo lo de
         * antes se equivoca en la mitad de los casos. */
        add("ldp", E({}, /*wmask=*/0x3, /*mem=*/true, /*flags=*/false));
        /* --- Almacenes: el operando ESCRITO es el de memoria ---
         * La mascara dice "que operandos escribe", y eso incluye el de
         * memoria: es lo mismo que ya hacia x86 (`mov [rdi], rax` marca el
         * primero).  Tenerlo a cero aqui hacia que la misma mascara
         * significara cosas distintas segun la tabla, y con ello un `str`
         * parecia una LECTURA.
         * Quien la consume para deducir clobbers solo mira los operandos que
         * son registros -- `[x0]` no canonicaliza --, asi que esto no le
         * afecta.  La posicion cambia con la forma: `str x1, [x0]` escribe el
         * segundo; `stp x1, x2, [x0]`, el tercero. */
        for (const char *m : {"str", "strb", "strh", "stur"})
            add(m, E({}, 0x2, true, false));
        add("stp", E({}, 0x4, true, false));
        // --- LL/SC atomicas: load-acquire escribe 1er op; store-cond escribe
        //     el registro de estado (1er op) -- ambas tocan memoria. ---
        for (const char *m : {"ldaxr", "ldxr", "ldar", "ldaxrb", "ldxrb",
                              "ldarb", "ldaxrh", "ldxrh", "ldarh"})
            add(m, E({}, 0x1, true, false));
        // ldaxp/ldxp cargan un PAR -> escriben op1 Y op2.
        for (const char *m : {"ldaxp", "ldxp"})
            add(m, E({}, 0x3, true, false));
        /* Los almacenes atomicos escriben MEMORIA, y la mascara tiene que
         * decirlo en la posicion donde esta el operando de memoria: quien la
         * consume mira ese bit para saber si el acceso es lectura o escritura.
         * Con la mascara solo en el registro de estado, un `stxr w0, x1, [x2]`
         * -- que GUARDA -- salia declarando una LECTURA de `[x2]`, y con eso
         * una escritura muerta a esa direccion se puede eliminar y una carga se
         * puede subir por encima.
         *
         * La posicion cambia con la forma, y por eso van por grupos en vez de
         * una mascara para todos: stxr  w0, x1, [x2]        -> estado op0 +
         * memoria op2  = 0x5 stxp  w0, x1, x2, [x3]    -> estado op0 + memoria
         * op3  = 0x9 stlr  x1, [x0]            -> SIN estado, memoria op1   =
         * 0x2 */
        for (const char *m :
             {"stlxr", "stxr", "stlxrb", "stxrb", "stlxrh", "stxrh"})
            add(m, E({}, /*wmask=*/0x5, /*mem=*/true, /*flags=*/false));
        for (const char *m : {"stlxp", "stxp"})
            add(m, E({}, /*wmask=*/0x9, /*mem=*/true, /*flags=*/false));
        /* Los de LIBERACION no llevan registro de estado -- no pueden fallar
         * --, asi que su unico efecto es la memoria.  Estaban en el mismo grupo
         * que los condicionales, lo que les atribuia una escritura al registro
         * que guardan: justo el valor que hay que dar por vivo. */
        for (const char *m : {"stlr", "stlrb", "stlrh"})
            add(m, E({}, /*wmask=*/0x2, /*mem=*/true, /*flags=*/false));
        // --- CAS / RMW atomicas (armv8.1): escriben el destino + memoria ---
        for (const char *m :
             {"cas",    "casa",    "casl",   "casal",   "casb",   "casab",
              "caslb",  "casalb",  "cash",   "casah",   "caslh",  "casalh",
              "swp",    "swpa",    "swpl",   "swpal",   "ldadd",  "ldadda",
              "ldaddl", "ldaddal", "ldset",  "ldseta",  "ldsetl", "ldsetal",
              "ldclr",  "ldclra",  "ldclrl", "ldclral", "ldeor",  "ldeora",
              "ldeorl", "ldeoral"})
            /* `casal x0, x1, [x2]`: deja el valor ANTERIOR en op0 -- el dato
             * con el que se decide si reintentar -- y ESCRIBE la memoria de
             * op2. */
            add(m, E({}, /*wmask=*/0x5, /*mem=*/true, /*flags=*/false));
        /* casp* comparan/escriben un PAR de registros, y la memoria se va al
         * quinto operando: `caspal x0, x1, x2, x3, [x4]` -> 0x3 | 0x10. */
        for (const char *m : {"casp", "caspa", "caspl", "caspal"})
            add(m, E({}, /*wmask=*/0x13, /*mem=*/true, /*flags=*/false));
        /* --- Barreras de memoria ---
         *
         * ORDENAN; no leen ni escriben nada.  Estaban declaradas como que tocan
         * memoria, y como no nombran por donde, el bloque entero quedaba con
         * memoria sin atribuir -- o sea suponiendo lo peor de TODA --.  Ordenar
         * y acceder son cosas distintas, y en x86 ya se distinguian: es la
         * misma `barrier` de `mfence`. */
        for (const char *m : {"dmb", "dsb", "isb"}) {
            AsmEffects e = E({}, /*wmask=*/0x0, /*mem=*/false, /*flags=*/false);
            e.barrier = true;
            add(m, std::move(e));
        }
        /* --- Control de flujo ---
         *
         * En arm la direccion de retorno va en un REGISTRO (`x30`, el de
         * enlace), no en la pila: una llamada lo ESCRIBE y `ret` lo LEE, y
         * ninguna de las dos toca memoria por eso.  Estaban las tres declaradas
         * como que si, con lo que cualquier bloque con un `ret` o un `bl`
         * pasaba a tocar memoria que no sabe nombrar. */
        add("ret", E({}, /*wmask=*/0x0, /*mem=*/false, /*flags=*/false,
                     /*call=*/false, {"x30"}));
        add("br", E({}, 0x0, false, false));
        add("blr",
            E({"x30"}, 0x0, /*mem=*/false, /*flags=*/false, /*call=*/true));
        add("bl",
            E({"x30"}, 0x0, /*mem=*/false, /*flags=*/false, /*call=*/true));
        add("b", E({}, false, false, false));
        for (const char *m : {"cbz", "cbnz", "tbz", "tbnz"})
            add(m, E({}, false, false, false));
        // b.CC (condicionales) -> las reconoce el postfijo de asm_effects_for.
        // --- No-ops / hint ---
        for (const char *m :
             {"nop", "yield", "wfe", "wfi", "sev", "sevl", "hint"})
            add(m, E({}, false, false, false));
        // svc #0 (ARM64/Linux syscall): LEE el numero de servicio en X8 y los
        // argumentos en X0..X7; ESCRIBE el resultado en X0.  Sin declarar los
        // reads, un `register("x0")` no viviria hasta el svc y el arg no se
        // colocaria en su registro (mismo analisis que `syscall`/`int` en x86).
        add("svc", E({"x0"}, false, true, true, /*call=*/true,
                     {"x8", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}));
        return t;
    }();
    return table;
}

/**
 * @brief Tabla de efectos A32 (arm32), por mnemonico BASE.
 *
 * A32 no es "arm64 con otros nombres", y tratarlo asi era peor que no tratarlo:
 * un `casal` -- que solo existe en A64 -- salia conocido al compilar para A32.
 *
 * Lo que lo separa es que el mnemonico LLEVA DENTRO parte del efecto:
 *
 *   - un sufijo de CONDICION (`addeq`, `blne`, `movcs`) hace que la instruccion
 *     dependa de las banderas.  Sin sufijo es incondicional y no depende de
 *     nada: casi toda instruccion A32 admite condicion, asi que decir que todas
 *     las leen -- que es lo que sale de modelar la clase entera -- convierte
 *     cualquier bloque en dependiente de la ultima comparacion;
 *   - un sufijo `s` (`adds`, `movs`) es lo que hace que ESCRIBA las banderas.
 *     Sin el no las toca, y esa letra es toda la diferencia.
 *
 * Por eso aqui van solo las BASES y el resto se descompone: enumerar
 * base x condicion x `s` serian miles de entradas que ademas se separarian
 * entre si en cuanto una se quedase atras.
 */
const EffTable &arm32_effects_table() {
    static const EffTable table = [] {
        EffTable t;
        auto add = [&t](const char *m, AsmEffects e) {
            e.known = true;
            t[m] = std::move(e);
        };
        auto E = [](std::initializer_list<const char *> wr, uint8_t wmask,
                    bool mem, bool flags, bool call = false,
                    std::initializer_list<const char *> rd = {}) {
            AsmEffects e;
            for (const char *w : wr)
                e.implicit_write.emplace_back(w);
            for (const char *r : rd)
                e.implicit_read.emplace_back(r);
            e.operand_write_mask = wmask;
            e.touches_mem = mem;
            e.writes_flags = flags;
            e.is_call = call;
            return e;
        };
        /* Proceso de datos: escriben su primer operando y NO tocan banderas.
         * Las formas que si lo hacen son las del sufijo `s`, y las construye el
         * descomponedor a partir de estas mismas. */
        for (const char *m :
             {"mov",   "mvn",   "movw", "movt", "add",  "sub",   "rsb",
              "and",   "orr",   "eor",  "bic",  "orn",  "lsl",   "lsr",
              "asr",   "ror",   "mul",  "mla",  "mls",  "umull", "smull",
              "umlal", "smlal", "sdiv", "udiv", "clz",  "rev",   "rev16",
              "rbit",  "uxtb",  "uxth", "sxtb", "sxth", "ubfx",  "sbfx",
              "bfi",   "bfc",   "adr"})
            add(m, E({}, /*wmask=*/0x1, /*mem=*/false, /*flags=*/false));
        /* Las que CONSUMEN el acarreo: es su razon de ser -- encadenar sumas de
         * mas bits de los que caben en un registro --, y sin declararlo la suma
         * que lo produjo se puede mover por debajo de la que lo usa. */
        for (const char *m : {"adc", "sbc", "rsc", "rrx"}) {
            AsmEffects e = E({}, 0x1, false, false);
            e.reads_flags = true;
            add(m, std::move(e));
        }
        // Comparar: escriben banderas sin sufijo `s` y no tocan sus operandos.
        for (const char *m : {"cmp", "cmn", "tst", "teq"})
            add(m, E({}, /*wmask=*/0x0, /*mem=*/false, /*flags=*/true));
        // Cargas: escriben su destino y leen memoria (siempre con corchetes).
        for (const char *m :
             {"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd", "ldrt", "ldrbt"})
            add(m, E({}, /*wmask=*/0x1, /*mem=*/true, /*flags=*/false));
        /* Almacenes: el operando ESCRITO es el de memoria, que en A32 es el
         * segundo (`str r0, [r1]`) igual que en A64. */
        for (const char *m : {"str", "strb", "strh", "strd", "strt", "strbt"})
            add(m, E({}, /*wmask=*/0x2, /*mem=*/true, /*flags=*/false));
        /* Transferencia MULTIPLE y pila.  Acceden por el registro base, que
         * aqui es un OPERANDO y no uno fijo, asi que de momento se declara el
         * acceso sin poder atribuirlo: decir que tocan memoria es cierto, decir
         * por donde requiere nombrar operandos y eso todavia no se puede. */
        for (const char *m : {"ldm", "ldmia", "ldmib", "ldmda", "ldmdb", "pop"})
            add(m, E({}, /*wmask=*/0x0, /*mem=*/true, /*flags=*/false));
        for (const char *m :
             {"stm", "stmia", "stmib", "stmda", "stmdb", "push"})
            add(m, E({}, /*wmask=*/0x0, /*mem=*/true, /*flags=*/false));
        /* Control.  Como en A64, la direccion de retorno va a un REGISTRO
         * (`lr`), no a la pila: `bl`/`blx` lo escriben y no tocan memoria por
         * eso. */
        add("b", E({}, 0x0, false, false));
        add("bx", E({}, 0x0, false, false));
        add("bl",
            E({"x30"}, 0x0, /*mem=*/false, /*flags=*/false, /*call=*/true));
        add("blx",
            E({"x30"}, 0x0, /*mem=*/false, /*flags=*/false, /*call=*/true));
        // Barreras: ORDENAN y no mueven datos.
        for (const char *m : {"dmb", "dsb", "isb"}) {
            AsmEffects e = E({}, 0x0, false, false);
            e.barrier = true;
            add(m, std::move(e));
        }
        // Sin efecto observable.
        for (const char *m : {"nop", "yield", "wfe", "wfi", "sev"})
            add(m, E({}, 0x0, false, false));
        /* `svc` (Linux A32): LEE el numero de servicio en `r7` y los argumentos
         * en `r0`..`r6`; ESCRIBE el resultado en `r0`.  Sin los reads, un
         * `register("r0")` no viviria hasta aqui y el argumento no se
         * colocaria. */
        add("svc", E({"r0"}, 0x0, /*mem=*/true, /*flags=*/false, /*call=*/true,
                     {"r7", "r0", "r1", "r2", "r3", "r4", "r5", "r6"}));
        // Estado del procesador.
        add("mrs", E({}, 0x1, false, false));
        add("msr", E({}, 0x0, false, true)); // puede reescribir las banderas
        return t;
    }();
    return table;
}

/**
 * @brief Separa un mnemonico A32 en su base, su sufijo `s` y su condicion.
 *
 * `addeqs` no existe: el orden es base + `s` + condicion (`addseq`).  Y hay
 * bases que TERMINAN en una condicion -- `teq` acaba en `eq` -- o en `s` --
 * `bics`, `movs` --, asi que primero se prueba el mnemonico ENTERO contra la
 * tabla: si ya es una base, no hay nada que separar.  Sin ese primer intento,
 * `teq` se leeria como una `t` condicional que no existe.
 *
 * @param m         Mnemonico en minusculas.
 * @param base      Sale con la base reconocida.
 * @param con_s     Sale a true si llevaba el sufijo que actualiza banderas.
 * @param con_cond  Sale a true si llevaba condicion (o sea, si DEPENDE de
 * ellas).
 * @return false si la base no esta en la tabla.
 */
bool arm32_decompose(const std::string &m, std::string &base, bool &con_s,
                     bool &con_cond) {
    const EffTable &t = arm32_effects_table();
    con_s = false;
    con_cond = false;
    if (t.find(m) != t.end()) { // ya es una base: `teq`, `bl`, `push`...
        base = m;
        return true;
    }
    static const char *kCond[] = {"eq", "ne", "cs", "hs", "cc", "lo",
                                  "mi", "pl", "vs", "vc", "hi", "ls",
                                  "ge", "lt", "gt", "le", "al"};
    std::string resto = m;
    for (const char *c : kCond) {
        const size_t n = std::strlen(c);
        if (resto.size() > n && resto.compare(resto.size() - n, n, c) == 0) {
            resto.resize(resto.size() - n);
            con_cond = true;
            break;
        }
    }
    if (t.find(resto) != t.end()) { // base + condicion
        base = resto;
        return true;
    }
    if (!resto.empty() && resto.back() == 's') { // base + `s` [+ condicion]
        resto.pop_back();
        if (t.find(resto) != t.end()) {
            base = resto;
            con_s = true;
            return true;
        }
    }
    return false;
}

/**
 * @brief Tabla de efectos RISC-V (RV64I + M + A).
 *
 * La que mas separa el modelo del de x86, y por eso es la que mejor comprueba
 * que no se le ha escrito encima: RISC-V **no tiene registro de banderas**. Una
 * rama compara dos registros y salta; no hay nada que leer ni que destruir, asi
 * que ninguna entrada de aqui toca banderas -- y un modelo que diera por hecho
 * que una rama condicional las lee se inventaria una dependencia que no existe.
 *
 * La memoria tambien se escribe distinto: `desplazamiento(base)`, sin
 * corchetes. De reconocerla se encarga @ref asm_is_memory, que pregunta por la
 * sintaxis de la arquitectura en vez de buscar la de otra.
 */
const EffTable &riscv_effects_table() {
    static const EffTable table = [] {
        EffTable t;
        auto add = [&t](const char *m, AsmEffects e) {
            e.known = true;
            t[m] = std::move(e);
        };
        auto E = [](std::initializer_list<const char *> wr, uint8_t wmask,
                    bool mem, bool call = false,
                    std::initializer_list<const char *> rd = {}) {
            AsmEffects e;
            for (const char *w : wr)
                e.implicit_write.emplace_back(w);
            for (const char *r : rd)
                e.implicit_read.emplace_back(r);
            e.operand_write_mask = wmask;
            e.touches_mem = mem;
            e.is_call = call;
            return e; // sin banderas: la arquitectura no las tiene
        };
        /* Aritmetica, logica y desplazamiento: escriben su primer operando. Las
         * formas `w` operan sobre 32 bits en RV64; el efecto es el mismo. */
        for (const char *m :
             {"add", "addi", "addw", "addiw", "sub", "subw", "and", "andi",
              "or", "ori", "xor", "xori", "sll", "slli", "sllw", "slliw", "srl",
              "srli", "srlw", "srliw", "sra", "srai", "sraw", "sraiw", "slt",
              "slti", "sltu", "sltiu", "lui", "auipc", "mul", "mulh", "mulhu",
              "mulhsu", "mulw", "div", "divu", "divw", "divuw", "rem", "remu",
              "remw", "remuw",
              // Pseudoinstrucciones de uso corriente.
              "li", "mv", "not", "neg", "negw", "seqz", "snez", "sltz", "sgtz",
              "sext.w", "zext.b"})
            add(m, E({}, /*wmask=*/0x1, /*mem=*/false));
        // Cargas: escriben su destino y leen memoria.
        for (const char *m :
             {"lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "flw", "fld"})
            add(m, E({}, /*wmask=*/0x1, /*mem=*/true));
        /* Almacenes: el operando ESCRITO es el de memoria, que aqui es el
         * segundo (`sd a0, 8(a1)`). */
        for (const char *m : {"sb", "sh", "sw", "sd", "fsw", "fsd"})
            add(m, E({}, /*wmask=*/0x2, /*mem=*/true));
        /* Ramas: comparan DOS REGISTROS y no miran ninguna bandera.  Que no
         * declaren nada no es que falte informacion -- es el hecho. */
        for (const char *m : {"beq", "bne", "blt", "bge", "bltu", "bgeu",
                              "beqz", "bnez", "blez", "bgez", "bltz", "bgtz"})
            add(m, E({}, /*wmask=*/0x0, /*mem=*/false));
        /* Saltos con enlace: guardan la direccion de retorno en un REGISTRO
         * (`ra`), no en la pila, igual que ARM. */
        add("jal", E({"ra"}, 0x0, /*mem=*/false, /*call=*/true));
        add("jalr", E({"ra"}, 0x0, /*mem=*/false, /*call=*/true));
        add("call", E({"ra"}, 0x0, /*mem=*/false, /*call=*/true));
        add("j", E({}, 0x0, false));
        add("jr", E({}, 0x0, false));
        add("ret", E({}, 0x0, /*mem=*/false, /*call=*/false, {"ra"}));
        // Barreras: ORDENAN y no mueven datos.
        for (const char *m : {"fence", "fence.i", "fence.tso"}) {
            AsmEffects e = E({}, 0x0, false);
            e.barrier = true;
            add(m, std::move(e));
        }
        /* Atomicas: reserva/condicional y las AMO.  Escriben su destino, tocan
         * memoria y ORDENAN.  La memoria va en el ultimo operando. */
        for (const char *m : {"lr.w", "lr.d"}) {
            AsmEffects e = E({}, /*wmask=*/0x1, /*mem=*/true);
            e.barrier = true;
            add(m, std::move(e));
        }
        for (const char *m : {"sc.w", "sc.d"}) {
            // `sc.d rd, rs2, (rs1)`: estado en op0 + memoria en op2.
            AsmEffects e = E({}, /*wmask=*/0x5, /*mem=*/true);
            e.barrier = true;
            add(m, std::move(e));
        }
        for (const char *m :
             {"amoadd.w", "amoadd.d", "amoswap.w", "amoswap.d", "amoand.w",
              "amoand.d", "amoor.w", "amoor.d", "amoxor.w", "amoxor.d",
              "amomax.w", "amomax.d", "amomin.w", "amomin.d", "amomaxu.w",
              "amomaxu.d", "amominu.w", "amominu.d"}) {
            AsmEffects e = E({}, /*wmask=*/0x5, /*mem=*/true);
            e.barrier = true;
            add(m, std::move(e));
        }
        /* Llamada al sistema: LEE el numero de servicio en `a7` y los
         * argumentos en `a0`..`a5`; ESCRIBE el resultado en `a0`. */
        add("ecall", E({"a0"}, 0x0, /*mem=*/true, /*call=*/true,
                       {"a7", "a0", "a1", "a2", "a3", "a4", "a5"}));
        add("ebreak", E({}, 0x0, false, /*call=*/true));
        // Sin efecto observable.
        add("nop", E({}, 0x0, false));
        return t;
    }();
    return table;
}

/// @c true si @p arch es una variante x86 (16/32/64 comparten tabla).
bool is_x86(const std::string &arch) {
    return arch.rfind("x86", 0) == 0 || arch.empty();
}

/**
 * @brief La tabla escrita a mano de @p arch, o @c nullptr si no hay ninguna.
 *
 * Devolver @c nullptr es una respuesta, y es la correcta para una ISA sin
 * tabla. Lo que habia antes era un `x86 ? x86 : arm64`, o sea que arm32 y
 * RISC-V se contestaban con la tabla de arm64: un `casal` -- que solo existe en
 * arm64 -- salia CONOCIDO al compilar para RISC-V, con los efectos de otra
 * arquitectura dados por ciertos.  Y de paso tapaba el camino bueno: sin tabla,
 * quien pregunta cae en la BASE DE INSTRUCCIONES, que si es multi-ISA y
 * contesta por forma para la arquitectura de verdad.
 */
const EffTable *table_for_arch(const std::string &arch) {
    if (is_x86(arch)) return &x86_effects_table();
    if (arch == "arm64" || arch == "aarch64") return &arm64_effects_table();
    if (arch == "arm" || arch == "arm32") return &arm32_effects_table();
    if (arch.rfind("riscv", 0) == 0) return &riscv_effects_table();
    return nullptr; // lo que venga: sin tabla no se afirma, contesta la base.
}

/// @c true si @p arch es A32 (donde el mnemonico lleva dentro parte del
/// efecto).
bool is_arm32(const std::string &arch) {
    return arch == "arm" || arch == "arm32";
}

} // namespace

/**
 * @brief Nombre CANONICO de un mnemonico que la base escribe fusionado.
 *
 * La base nombra por separado cada combinacion de prefijo -- `rep_movsb`,
 * `repne_scasb`, `cmpxchg_lock` -- y de alcance -- `ret_near`, `call_far` --,
 * porque son codificaciones distintas.  Nadie escribe eso: en un fuente se pone
 * `rep movsb`, y el analisis separa el prefijo antes de preguntar.
 *
 * Traducirlo aqui sirve para dos cosas.  Una, que preguntar por el nombre de la
 * base devuelva la respuesta que corresponde en vez de "no se sabe" -- eran 45
 * de las 271 que parecian sin cubrir, o sea trabajo que no existia --.  Y dos,
 * que quien escriba el nombre fusionado obtenga lo mismo que quien escriba el
 * separado, que es lo unico coherente.
 *
 * El prefijo no cambia QUE se toca: `rep movsb` accede a lo mismo que `movsb`,
 * mas veces.  Cuantas, lo dice el contador, y de eso se encarga el analisis de
 * la linea, que es quien ve el prefijo.
 */
std::string x86_canonical_mnemonic(const std::string &m) {
    static const char *kPrefijos[] = {"rep_", "repe_", "repne_", "repz_",
                                      "repnz_"};
    for (const char *p : kPrefijos) {
        const size_t n = std::strlen(p);
        if (m.size() > n && m.compare(0, n, p) == 0) return m.substr(n);
    }
    static const struct {
        const char *sufijo, *nada;
    } kSufijos[] = {
        {"_lock", ""},
        {"_near", ""},
        {"_far", ""},
    };
    for (const auto &s : kSufijos) {
        const size_t n = std::strlen(s.sufijo);
        if (m.size() > n && m.compare(m.size() - n, n, s.sufijo) == 0)
            return m.substr(0, m.size() - n);
    }
    return m;
}

AsmEffects asm_effects_for(const std::string &mnemonic,
                           const std::string &arch) {
    std::string m;
    m.reserve(mnemonic.size());
    for (char c : mnemonic)
        m.push_back((char)std::tolower((unsigned char)c));
    /* El prefijo de repeticion SI cambia lo que se toca, en una cosa: el
     * contador.  `movsb` copia un elemento y no mira `rcx`; `rep movsb` lo lee
     * en cada vuelta y lo deja a cero.  Al quitar el prefijo para preguntar por
     * la instruccion, eso se perdia -- y sin saber que `rcx` se lee, quien
     * asigna registros da por muerta la ligadura `register("rcx")` y no llega a
     * colocar el valor: `rep movsb` arrancaba con lo que hubiera en `rcx`.  Se
     * veia como `memcpy_erms` copiando basura o sin terminar nunca.
     *
     * `rcx` se anota como leido Y escrito porque las dos cosas son ciertas, y
     * la segunda importa igual: quien lea `rcx` despues del bloque no puede
     * quedarse con el valor de antes. */
    bool es_repeticion = false;
    if (is_x86(arch)) {
        for (const char *p : {"rep_", "repe_", "repne_", "repz_", "repnz_",
                              "rep ", "repe ", "repne ", "repz ", "repnz "})
            if (m.compare(0, std::strlen(p), p) == 0) {
                es_repeticion = true;
                break;
            }
        m = x86_canonical_mnemonic(m);
    }
    auto con_contador = [&](AsmEffects e) {
        if (es_repeticion) {
            e.implicit_read.emplace_back("rcx");
            e.implicit_write.emplace_back("rcx");
        }
        return e;
    };

    const bool x86 = is_x86(arch);
    const EffTable *tabla = table_for_arch(arch);
    if (tabla == nullptr) {
        /* Sin tabla para esta ISA no se afirma nada: el `known=false` es lo que
         * hace que quien pregunta consulte la base de instrucciones por la ISA
         * correcta en vez de quedarse con una respuesta de otra. */
        AsmEffects sin_tabla;
        return sin_tabla;
    }
    const EffTable &table = *tabla;
    /* En A32 el mnemonico lleva dentro parte del efecto: la condicion dice que
     * DEPENDE de las banderas y el sufijo `s` que las ESCRIBE.  Se descompone
     * en vez de tabular base x condicion x `s`, que serian miles de entradas.
     */
    if (is_arm32(arch)) {
        std::string base;
        bool con_s = false, con_cond = false;
        if (arm32_decompose(m, base, con_s, con_cond)) {
            AsmEffects e = table.find(base)->second;
            if (con_s) e.writes_flags = true;
            if (con_cond) e.reads_flags = true;
            return e;
        }
        AsmEffects unknown;
        return unknown;
    }
    auto it = table.find(m);
    if (it != table.end()) return con_contador(it->second);

    if (x86) {
        // setcc (sete/setne/...) y cmovcc se reconocen por prefijo: escriben
        // el 1er operando.
        /* Las dos LEEN las banderas -- es su razon de existir: `setz` convierte
         * una bandera en un valor y `cmovz` decide con ella --, y no lo
         * declaraban.
         *
         * Que falte no da un resultado falso por si solo, pero deja mover el
         * bloque por encima de la comparacion que produjo la bandera que lee, y
         * entonces decide con la de otra: un fallo que depende de si al
         * planificador le convino reordenar, o sea intermitente. */
        if (m.rfind("set", 0) == 0 && m.size() > 3) {
            AsmEffects e;
            e.operand_write_mask = 0x1;
            e.reads_flags = true; // las LEE, no las escribe
            e.known = true;
            return e;
        }
        if (m.rfind("cmov", 0) == 0 && m.size() > 4) {
            AsmEffects e;
            e.operand_write_mask = 0x1;
            e.reads_flags = true; // las LEE para decidir, no las escribe
            e.known = true;
            return e;
        }
        /* Y los SALTOS condicionales, por el mismo motivo y con la misma
         * consecuencia: un `je` depende de la bandera que dejo el `cmp`, y si
         * no lo declara, la comparacion no tiene quien la use -- se puede mover
         * por debajo del salto, o eliminarse por muerta --.  Es el mismo hueco
         * que tenia `b.CC` en arm64.
         *
         * `jmp` no: no mira nada.  Y `jcxz`/`jecxz`/`jrcxz` miran el REGISTRO
         * contador, no las banderas; meterlas en el mismo saco les atribuiria
         * una dependencia que no tienen. */
        if (m.size() > 1 && m[0] == 'j' && m != "jmp" && m != "jcxz" &&
            m != "jecxz" && m != "jrcxz") {
            AsmEffects e;
            e.reads_flags = true;
            e.known = true;
            return e;
        }
        /* `loop` cuenta con `rcx`; sus formas condicionales miran ADEMAS la
         * bandera de cero.  Las tres escriben `rcx` al decrementarlo. */
        if (m == "loop" || m == "loope" || m == "loopne" || m == "loopz" ||
            m == "loopnz") {
            AsmEffects e;
            e.implicit_read.emplace_back("rcx");
            e.implicit_write.emplace_back("rcx");
            e.reads_flags = m != "loop";
            e.known = true;
            return e;
        }
    } else {
        /* arm64: b.CC (b.eq/b.ne/...) es una rama que solo LEE las banderas.
         *
         * Lo decia el comentario y no lo decia el codigo: devolvia un efecto
         * vacio.  Con eso, el salto no dependia de nada y la comparacion que lo
         * decide se podia mover por debajo de el, o eliminarse por no tener
         * quien la use.  Es la diferencia con `cbz`, que mira un REGISTRO. */
        if (m.rfind("b.", 0) == 0 && m.size() > 2) {
            AsmEffects e;
            e.reads_flags = true;
            e.known = true;
            return e;
        }
    }
    AsmEffects unknown; // known=false
    return unknown;
}

AsmEffects asm_effects_for(const std::string &mnemonic) {
    return asm_effects_for(mnemonic, "x86_64");
}

namespace {
// Convierte un canonico (rax.., vN) al nombre que GCC espera en la
// clobber-list.  GP: tal cual (rax..r15).  Vectorial vN -> xmmN.
std::string canon_to_gcc(const std::string &canon) {
    if (!canon.empty() && canon[0] == 'v' && canon.size() > 1 &&
        std::isdigit((unsigned char)canon[1])) {
        return "xmm" + canon.substr(1);
    }
    return canon;
}

// Trocea una linea en tokens separados por espacios/comas/tabs.  Los
// corchetes y su contenido se conservan como parte del token (para
// detectar [mem]); aqui solo necesitamos el 1er token (mnemonico) y
// saber si el resto contiene un registro como primer operando.
std::vector<std::string> tokenize_line(const std::string &line) {
    std::vector<std::string> toks;
    std::string cur;
    for (char c : line) {
        /* El RETORNO DE CARRO separa como cualquier otro blanco.  Un fuente
         * guardado en Windows lleva `\r\n`, asi que al partir por `\n` cada
         * linea acaba en `\r`: sin esto, el ultimo operando de cada
         * instruccion se llamaba `v0\r` -- que no es ningun registro -- y una
         * linea en blanco dentro del asm era un mnemonico desconocido cuyo
         * nombre no se podia ni imprimir.  Se veia como un aviso que decia
         * "mnemonico(s) no reconocido(s) ()", con la lista vacia. */
        if (c == ' ' || c == '\t' || c == '\r' || c == ',') {
            if (!cur.empty()) {
                toks.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) toks.push_back(cur);
    return toks;
}
} // namespace

std::string asm_base_de_memoria(const std::string &operando,
                                const std::string &arch) {
    return asm_parse_memoria(operando, arch).base;
}

bool asm_is_memory(const std::string &operando, const std::string &arch) {
    if (operando.find('[') != std::string::npos) return true;
    /* RISC-V escribe el acceso `desplazamiento(base)`: `0(a0)`, `-8(sp)`,
     * `8($1)`.  El parentesis solo cuenta como acceso en esa sintaxis; en x86
     * un parentesis no aparece en un operando de memoria. */
    if (arch.rfind("riscv", 0) != 0) return false;
    const size_t p = operando.find('(');
    return p != std::string::npos && operando.find(')', p) != std::string::npos;
}

AsmMemOperando asm_parse_memoria(const std::string &operando,
                                 const std::string &arch) {
    AsmMemOperando m;
    const size_t a = operando.find('[');
    if (a == std::string::npos) {
        /* La forma de RISC-V: `desplazamiento(base)`.  El desplazamiento es
         * siempre una constante -- no hay indice ni escala, la arquitectura no
         * los tiene --, asi que se lee entero y queda RECONOCIDO: decir que no
         * se pudo leer obligaria a suponer lo peor de toda la memoria cuando lo
         * que hay delante es un acceso perfectamente acotado. */
        const size_t p = operando.find('(');
        const size_t q = p == std::string::npos ? p : operando.find(')', p);
        if (!asm_is_memory(operando, arch) || q == std::string::npos) return m;
        std::string disp = operando.substr(0, p);
        while (!disp.empty() && std::isspace((unsigned char)disp.front()))
            disp.erase(0, 1);
        while (!disp.empty() && std::isspace((unsigned char)disp.back()))
            disp.pop_back();
        if (!disp.empty()) {
            try {
                m.desplazamiento = std::stoll(disp, nullptr, 0);
            } catch (...) {
                return m; // desplazamiento que no es una constante: no se
                          // afirma
            }
        }
        std::string base = operando.substr(p + 1, q - p - 1);
        while (!base.empty() && std::isspace((unsigned char)base.front()))
            base.erase(0, 1);
        while (!base.empty() && std::isspace((unsigned char)base.back()))
            base.pop_back();
        if (base.empty()) return m;
        /* Un marcador `$N` se devuelve tal cual -- el registro aun no esta
         * elegido, pero el marcador ya identifica de que operando se trata --;
         * un nombre de registro se canonicaliza. */
        m.base = base[0] == '$' ? base : asm_canonical_reg(base, arch);
        if (m.base.empty()) return m;
        m.reconocido = true;
        return m;
    }
    size_t i = a + 1;
    while (i < operando.size() && std::isspace((unsigned char)operando[i]))
        ++i;
    /* Marcador `$N`: el registro aun no esta elegido -- lo elige el asignador
     * despues --, pero el marcador YA identifica de que operando se trata, que
     * es justo lo que hace falta.  Se devuelve tal cual.
     *
     * Es ademas el camino MEJOR de los dos: no depende de nombres de registro,
     * asi que vale igual en cualquier arquitectura, y no puede confundirse con
     * otra variable que use el mismo registro.  Y es la forma que usa la
     * stdlib, o sea que sin esto la parte que mas importa quedaba fuera. */
    if (i < operando.size() && operando[i] == '$') {
        std::string ph = "$";
        for (++i;
             i < operando.size() && std::isdigit((unsigned char)operando[i]);
             ++i)
            ph.push_back(operando[i]);
        if (ph.size() <= 1) return m;
        m.base = std::move(ph);
    } else {
        std::string ident;
        for (; i < operando.size(); ++i) {
            const char c = operando[i];
            if (std::isalnum((unsigned char)c) || c == '_')
                ident.push_back(c);
            else
                break;
        }
        if (ident.empty()) return m;
        m.base = asm_canonical_reg(ident, arch);
        if (m.base.empty()) return m;
    }

    /* Lo que queda hasta el corchete de cierre: a que distancia de la base cae
     * el acceso.  Puede tener tres partes y las tres se describen:
     *
     *   `[rdi]`                 -> distancia 0
     *   `[rdi+8]`  `[x0, #8]`   -> distancia 8      `[rdi-8]` -> -8
     *   `[rbx+rcx*8]`           -> indice `rcx`, escala 8
     *   `[rbx+rcx*8+16]`        -> las dos cosas
     *   `[x0, x1, lsl #3]`      -> indice `x1`, escala 8
     *
     * Lo que NO se reconozca deja @c reconocido en false, y entonces no se
     * afirma distancia ninguna: decir `[p, p+16)` de un acceso que cae en otra
     * parte no es menos preciso, es falso -- quien pregunte por solapes
     * concluira que no los hay. */
    const size_t cierre = operando.find(']', i);
    if (cierre == std::string::npos) return m;
    const std::string resto = operando.substr(i, cierre - i);

    int signo = 1;              // signo del termino que se este leyendo
    bool esperando_lsl = false; // el siguiente numero es un desplazamiento log2
    size_t k = 0;
    auto salta_espacios = [&] {
        while (k < resto.size() && (std::isspace((unsigned char)resto[k]) ||
                                    resto[k] == ',' || resto[k] == '#'))
            ++k;
    };
    while (true) {
        salta_espacios();
        if (k >= resto.size()) break;
        const char c = resto[k];
        if (c == '+') {
            signo = 1;
            ++k;
            continue;
        }
        if (c == '-') {
            signo = -1;
            ++k;
            continue;
        }
        if (c == '*') {
            // La escala del indice: `rcx*8`.
            ++k;
            salta_espacios();
            std::string num;
            while (k < resto.size() && std::isalnum((unsigned char)resto[k]))
                num.push_back(resto[k++]);
            if (num.empty()) return m;
            m.escala = std::strtoll(num.c_str(), nullptr, 0);
            continue;
        }
        if (c == '$' || std::isalpha((unsigned char)c) || c == '_') {
            // Un operando: marcador, registro, o la palabra `lsl`/`uxtw`.
            std::string ident;
            if (c == '$') {
                ident.push_back(resto[k++]);
                while (k < resto.size() &&
                       std::isdigit((unsigned char)resto[k]))
                    ident.push_back(resto[k++]);
            } else {
                while (
                    k < resto.size() &&
                    (std::isalnum((unsigned char)resto[k]) || resto[k] == '_'))
                    ident.push_back(resto[k++]);
            }
            std::string bajo;
            for (char ch : ident)
                bajo.push_back((char)std::tolower((unsigned char)ch));
            if (bajo == "lsl") {
                esperando_lsl = true;
                continue;
            }
            if (bajo == "uxtw" || bajo == "sxtw" || bajo == "sxtx") continue;
            // Un segundo operando dentro de los corchetes es el INDICE.
            const std::string canon =
                (ident[0] == '$') ? ident : asm_canonical_reg(ident, arch);
            if (canon.empty()) return m; // ni registro ni marcador: no se lee.
            if (!m.indice.empty()) return m; // dos indices: fuera del modelo.
            m.indice = canon;
            continue;
        }
        if (std::isdigit((unsigned char)c)) {
            std::string num;
            while (k < resto.size() &&
                   (std::isxdigit((unsigned char)resto[k]) || resto[k] == 'x' ||
                    resto[k] == 'X'))
                num.push_back(resto[k++]);
            const long long v = std::strtoll(num.c_str(), nullptr, 0);
            if (esperando_lsl) {
                // `lsl #3` escala por 2^3: es la misma idea que `*8`.
                esperando_lsl = false;
                if (v < 0 || v > 63) return m;
                m.escala = (int64_t)1 << v;
            } else {
                m.desplazamiento += (int64_t)signo * (int64_t)v;
            }
            continue;
        }
        return m; // parentesis, aritmetica rara: no se lee.
    }
    m.reconocido = true;
    return m;
}

AsmTransferencia asm_transferencia(const std::string &mnem,
                                   const std::string &arch) {
    for (const auto &a : kArchTransfer)
        if (arch == a.arch) return a.fn(mnem);
    return AsmTransferencia::Ninguna;
}

uint32_t asm_pista_de_tamano(const std::string &operando,
                             const std::string &arch) {
    // Solo lo que va DELANTE de los corchetes: dentro estan los registros.
    std::string pre;
    for (char c : operando) {
        if (c == '[') break;
        pre.push_back((char)std::tolower((unsigned char)c));
    }
    if (pre.empty()) return 0;
    for (const auto &a : kArchPistas)
        if (arch == a.arch) return a.fn(pre);
    return 0;
}

std::string asm_contador_de_repeticion(const std::string &arch) {
    // Las repeticiones por prefijo son cosa de x86; en su forma canonica el
    // contador es `rcx` sea cual sea el ancho del modo.
    if (arch.rfind("x86", 0) == 0) return "rcx";
    return std::string();
}

uint32_t asm_ancho_acceso_bytes(
    const std::vector<std::string> &ops, size_t idx_mem,
    const std::vector<std::pair<std::string, std::string>> &clases_operando,
    const std::string &arch) {
    if (idx_mem >= ops.size()) return 0;

    /* Primero, la pista de tamano si el fuente la escribio (`qword ptr [rdi]`).
     * Cuando esta, MANDA: es justo lo que se escribe para desambiguar cuando
     * los operandos no bastan.  Que pistas existen lo dice cada arquitectura.
     */
    if (const uint32_t pista = asm_pista_de_tamano(ops[idx_mem], arch))
        return pista;

    /* Y si no, lo dice el OTRO operando: `mov [rdi], rax` mueve 8 y
     * `mov [rdi], eax` mueve 4, con los mismos corchetes.  Se recorren todos
     * por si el de memoria no es el primero. */
    for (size_t k = 0; k < ops.size(); ++k) {
        if (k == idx_mem || ops[k].empty()) continue;
        if (ops[k].find('[') != std::string::npos) continue;
        uint32_t bits = 0;
        if (ops[k][0] == '$') {
            // Lo eligio el compilador: su ancho es el de la clase declarada.
            for (const auto &co : clases_operando)
                if (co.first == ops[k]) {
                    bits = asm_ancho_bits_de_clase(co.second);
                    break;
                }
        } else {
            bits = asm_ancho_bits_de_clase(ops[k]);
        }
        if (bits != 0) return bits / 8;
    }
    return 0; // no se afirma cuantos bytes; NO significa cero.
}

uint32_t asm_ancho_bits_de_clase(const std::string &clase) {
    if (clase.empty()) return 0;
    /* Un registro CONCRETO se pregunta tal cual.  Una clase sin numero
     * (`xmm`, `reg`) no es un registro, asi que se pregunta por uno de esa
     * clase: el ancho es de la clase entera, no del que toque.  `reg` es el
     * caso especial -- no es un nombre de ninguna arquitectura --, y significa
     * "un registro de proposito general del objetivo". */
    const instr_db::Isa isa = isa_actual();
    instr_db::ParsedOp po = instr_db::parse_operand(isa, clase);
    if (po.kind == instr_db::OP_REG && po.width > 0) return (uint32_t)po.width;
    po = instr_db::parse_operand(isa, clase + "0");
    if (po.kind == instr_db::OP_REG && po.width > 0) return (uint32_t)po.width;
    if (clase == "reg") {
        // El entero del objetivo: se pregunta por su acumulador, que existe en
        // todas y cuyo ancho ES el del banco general.
        for (const char *rep : {"rax", "x0", "r0"}) {
            po = instr_db::parse_operand(isa, rep);
            if (po.kind == instr_db::OP_REG && po.width > 0)
                return (uint32_t)po.width;
        }
    }
    return 0;
}

AsmInferResult asm_infer_clobbers(const std::string &nasm_body,
                                  const std::vector<std::string> &bound_canon) {
    return asm_infer_clobbers(nasm_body, bound_canon, {});
}

AsmInferResult asm_infer_clobbers(
    const std::string &nasm_body, const std::vector<std::string> &bound_canon,
    const std::vector<std::pair<std::string, std::string>> &clases_operando) {
    AsmInferResult res;
    // Set de regs ligados (canonicos) a EXCLUIR de los clobbers.
    std::unordered_set<std::string> bound(bound_canon.begin(),
                                          bound_canon.end());
    // Acumulador canonico de clobbers (despues -> GCC names + filtrado).
    std::unordered_set<std::string> clob;

    // Caller-saved conservador (union SysV + Win64) para call/syscall.
    static const char *caller_saved[] = {"rax", "rcx", "rdx", "rsi", "rdi",
                                         "r8",  "r9",  "r10", "r11"};

    // Procesar linea a linea.
    size_t i = 0;
    const std::string &b = nasm_body;
    while (i <= b.size()) {
        // Extraer una linea [start, eol).
        size_t eol = b.find('\n', i);
        if (eol == std::string::npos) eol = b.size();
        std::string line = b.substr(i, eol - i);
        i = eol + 1;

        // Quitar comentarios ';' y '//'.
        size_t cpos = line.find(';');
        if (cpos != std::string::npos) line = line.substr(0, cpos);
        size_t slpos = line.find("//");
        if (slpos != std::string::npos) line = line.substr(0, slpos);

        // Detectar memoria: cualquier '[' en operandos.
        const bool line_has_mem = line.find('[') != std::string::npos;

        auto toks = tokenize_line(line);
        if (toks.empty()) continue;

        // Saltar labels iniciales ("name:" como token aislado) y prefijos.
        size_t ti = 0;
        while (ti < toks.size()) {
            const std::string &t = toks[ti];
            // Label: token que termina en ':'.
            if (!t.empty() && t.back() == ':') {
                ++ti;
                continue;
            }
            // Prefijos de instruccion.
            std::string lt;
            for (char c : t)
                lt.push_back((char)std::tolower((unsigned char)c));
            if (lt == "lock" || lt == "rep" || lt == "repe" || lt == "repz" ||
                lt == "repne" || lt == "repnz" || lt == "bnd") {
                ++ti;
                continue;
            }
            break;
        }
        if (ti >= toks.size()) continue; // linea solo-label/prefijo

        const std::string mnem = toks[ti];

        /* La BASE DE INSTRUCCIONES primero.  Es la fuente generada por ISA, y
         * de una linea emparejada sabe mas que ninguna tabla escrita a mano:
         * que registros lee y escribe, si toca memoria y flags, si es barrera
         * y hasta su latencia.  Preguntarle a ella y dejar la tabla para lo
         * que no cubra es lo que evita tener dos versiones del mismo saber --
         * que es como `vmovq` acabo siendo un "mnemonico desconocido" teniendo
         * la DB su forma desde el principio.
         *
         * `modeled=false` significa que la linea no se pudo emparejar (forma
         * con operandos implicitos, sintaxis que la DB no cubre); entonces se
         * cae a la tabla, que es exactamente lo que era antes. */
        const instr_db::AsmInsnSem sem =
            instr_db::asm_insn_sem(isa_actual(), line, 0);
        AsmEffects eff;
        if (sem.modeled) {
            eff.known = true;
            eff.implicit_write = sem.writes;
            eff.implicit_read = sem.reads;
            eff.touches_mem = sem.reads_mem || sem.writes_mem;
            /* Los dos sentidos, que la base tiene separados: quedarse solo con
             * la escritura hacia que un `setz` -- que las LEE -- pasara por no
             * tener nada que ver con las banderas. */
            eff.writes_flags = sem.writes_flags;
            eff.reads_flags = sem.reads_flags;
            eff.barrier = sem.barrier;
            /* Lo que la DB NO modela y la tabla si: la exigencia de
             * alineacion, que es una precondicion y no un efecto.  Se toma de
             * la tabla cuando alli consta, en vez de perderla por venir por
             * el otro camino. */
            const AsmEffects tab = asm_effects_for(mnem);
            if (tab.known) {
                eff.align_req = tab.align_req;
                eff.operand_write_mask = tab.operand_write_mask;
                eff.is_call = eff.is_call || tab.is_call;
                eff.port_io = tab.port_io;
                for (const auto &r : tab.implicit_mem_read)
                    eff.implicit_mem_read.push_back(r);
                for (const auto &r : tab.implicit_mem_write)
                    eff.implicit_mem_write.push_back(r);
            }
        } else {
            eff = asm_effects_for(mnem);
        }

        if (!eff.known) {
            res.unknown_mnemonics.push_back(mnem);
            // Conservador: marcar memoria + flags para no perder un efecto.
            res.clobber_memory = true;
            res.clobber_flags = true;
            /* Y la lista de LECTURAS queda incompleta: de esta linea no se sabe
             * que lee.  Se dice, en vez de dejar que una lista corta pase por
             * una lista completa. */
            res.reads_completos = false;
            continue;
        }

        /* Lo que la linea LEE.  Sale de la misma fuente que lo que escribe --
         * la base, para una linea emparejada -- y hasta ahora se calculaba y se
         * tiraba: solo se acumulaban los clobbers.  Se acumula TAL CUAL, sin
         * excluir los ligados por `register()`: un operando ligado que el
         * cuerpo lee es precisamente una lectura, al reves que en los clobbers
         * (donde se excluye porque es un operando y no un destrozo). */
        for (const std::string &r : eff.implicit_read) {
            const std::string canon = asm_canonical_reg(r);
            if (canon.empty()) continue;
            bool dup = false;
            for (const std::string &e : res.read_regs)
                if (e == canon) {
                    dup = true;
                    break;
                }
            if (!dup) res.read_regs.push_back(canon);
        }

        // Registros escritos implicitamente.
        for (const auto &w : eff.implicit_write)
            clob.insert(w);

        // Operandos escritos segun el bitmask: bit i -> operando i+1 (los
        // operandos son los tokens tras el mnemonico).  Si el operando es un
        // registro, es un clobber.  Generaliza el "1er operando" a xchg
        // (ambos), casp/ldxp (pares), etc.
        for (int bit = 0; bit < 8; ++bit) {
            if (!(eff.operand_write_mask & (1u << bit))) continue;
            const size_t opi = ti + 1 + static_cast<size_t>(bit);
            if (opi >= toks.size()) break;
            const std::string canon = asm_canonical_reg(toks[opi]);
            if (!canon.empty()) clob.insert(canon);
        }

        /* Exigencia de alineacion.  El ancho, cuando es "el de su operando",
         * lo resuelve @ref instr_db::parse_operand, que conoce los registros
         * de CADA ISA -- x86 xmm/ymm/zmm, ARM v/q, RISC-V -- y devuelve su
         * ancho en bits.  Compararlo aqui contra los nombres de x86 seria
         * meter conocimiento de una arquitectura dentro de un bucle que sirve
         * para todas, y dejaria a las demas sin comprobacion el dia que la
         * pidan. */
        if (eff.align_req != 0) {
            AsmAlignReq req;
            req.mnemonic = mnem;
            if (eff.align_req == kAlignAnchoOperando) {
                for (size_t k = ti + 1; k < toks.size(); ++k) {
                    if (toks[k] == "," || toks[k].empty()) continue;
                    /* Si el operando lo eligio el compilador, en el cuerpo se
                     * llama `$N` y ningun analisis del texto puede decir cuanto
                     * mide.  Lo dice su CLASE, que es lo que escribio el
                     * programador, y llega en el diccionario de quien tiene las
                     * ligaduras.  Sin esto, justo la forma que usa la stdlib se
                     * quedaba sin poder comprobarse. */
                    uint32_t bits = 0;
                    for (const auto &co : clases_operando)
                        if (co.first == toks[k]) {
                            bits = asm_ancho_bits_de_clase(co.second);
                            break;
                        }
                    if (bits == 0) {
                        const instr_db::ParsedOp po =
                            instr_db::parse_operand(isa_actual(), toks[k]);
                        if (po.kind == instr_db::OP_REG)
                            bits = (uint32_t)po.width;
                    }
                    if (bits >= 128) {
                        req.bytes = (uint16_t)(bits / 8);
                        break;
                    }
                }
            } else {
                req.bytes = eff.align_req;
            }
            for (size_t k = ti + 1; k < toks.size(); ++k)
                if (toks[k].find('[') != std::string::npos) {
                    req.operando = toks[k];
                    // De donde sale la direccion, por el mismo camino que los
                    // accesos del bloque: leer dentro de los corchetes es la
                    // misma operacion, y aqui se hace una sola vez.
                    req.base = asm_base_de_memoria(toks[k], asm_arch_actual());
                    break;
                }
            res.align_reqs.push_back(std::move(req));
        }

        // Memoria: implicita del mnemonico o '[' en la linea.
        if (eff.touches_mem || line_has_mem) res.clobber_memory = true;
        if (eff.writes_flags) res.clobber_flags = true;

        // call/syscall: clobber conservador de TODO el caller-saved.
        if (eff.is_call) {
            for (const char *cs : caller_saved)
                clob.insert(cs);
        }
    }

    // Excluir los regs ligados por register() (son operandos) + rsp/rbp
    // (nunca se pueden clobrear en GCC) y convertir a nombres GCC.
    for (const auto &c : clob) {
        if (bound.count(c)) continue;
        if (c == "rsp" || c == "rbp") continue;
        res.clobber_regs.push_back(canon_to_gcc(c));
    }
    std::sort(res.clobber_regs.begin(), res.clobber_regs.end());
    return res;
}

} // namespace vx
