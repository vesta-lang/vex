/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/asm.cpp
 * @brief Bajada del ensamblador escrito a mano, y el mini-ensamblador que la
 *        sostiene.
 *
 * Dos cosas que van juntas y solo se usan aqui:
 *
 *   - el MINI-ENSAMBLADOR de bloques `asm` a nivel de datos: normaliza los
 *     literales (Keystone en modo NASM lee los enteros desnudos como
 *     hexadecimal, contra la semantica de NASM), evalua las directivas propias
 *     -- db/dw/dd/dq, times, $ y $$ -- y deja que Keystone ensamble las
 *     instrucciones, todo intercalado en el orden en que se escribio;
 *   - `lower_asm`, la bajada de un bloque `asm { }` dentro de una funcion.
 *
 * Estaban en lowering.cpp, y de sus dieciocho helpers solo UNO se usaba fuera
 * -- `asmblk_assemble`, para los bloques de datos --, asi que el tema estaba
 * cerrado y solo faltaba darle fichero.  Ese unico punto de contacto se declara
 * en `lowering_internal.h`; el resto se queda aqui dentro, sin salir.
 */
#include "vx/lowering.h"
#include "vx/asm/asm_backend.h"
#include "vx/asm/asm_diag.h"
#include "vx/asm/asm_effects.h"
#include "vx/asm/asm_lift_emit.h"
#include "vx/asm/asm_lift_general.h"
#include "vx/asm/asm_lift_micro.h"
#include "vx/asm/asm_lift_registro.h"
#include "vx/asm/asm_phys_reg.h"
#include "vx/asm/instr_db.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {

namespace {
/**
 * @brief Normaliza literales enteros DECIMALES a hexadecimal (0x...) en una
 *        linea de ensamblador.
 *
 * Keystone en modo NASM interpreta los enteros desnudos como HEXADECIMAL
 * (`127` -> 0x127), contra la semantica NASM (decimal).  Para que `mov ax,
 * 127` valga 127 y no 0x127, reescribimos cada literal decimal a `0x<hex>`
 * antes de pasarlo a Keystone (que SI parsea 0x correctamente).  Se respetan:
 *   - literales ya en 0x / 0b / 0o (se dejan tal cual).
 *   - digitos que forman parte de un identificador/registro (r8, xmm15,
 *     etiquetas .loop1): el digito va precedido de letra/_/'.', no se toca.
 *   - el contenido de cadenas entre comillas.
 */
std::string asmblk_dec_to_hex(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    const size_t n = s.size();
    size_t i = 0;
    bool in_str = false;
    char qc = 0;
    while (i < n) {
        char c = s[i];
        if (in_str) {
            out.push_back(c);
            if (c == qc) in_str = false;
            ++i;
            continue;
        }
        if (c == '"' || c == '\'') {
            in_str = true;
            qc = c;
            out.push_back(c);
            ++i;
            continue;
        }
        // Posible inicio de un literal numerico: un digito cuyo char previo
        // NO sea alfanumerico / '_' / '.' (eso seria parte de un identificador
        // o etiqueta, p.ej. r8, .loop1).
        const bool prev_ident =
            !out.empty() && (std::isalnum((unsigned char)out.back()) ||
                             out.back() == '_' || out.back() == '.');
        if (std::isdigit((unsigned char)c) && !prev_ident) {
            // Leer el token numerico completo.
            size_t j = i;
            while (j < n && (std::isalnum((unsigned char)s[j])))
                ++j;
            std::string tok = s.substr(i, j - i);
            // 0x / 0b / 0o: dejar tal cual (Keystone los parsea bien).
            bool is_prefixed =
                tok.size() >= 2 && tok[0] == '0' &&
                (tok[1] == 'x' || tok[1] == 'X' || tok[1] == 'b' ||
                 tok[1] == 'B' || tok[1] == 'o' || tok[1] == 'O');
            bool all_dec = !is_prefixed && !tok.empty();
            for (char d : tok)
                if (!std::isdigit((unsigned char)d)) all_dec = false;
            if (all_dec) {
                unsigned long long v = 0;
                bool ok = true;
                for (char d : tok) {
                    v = v * 10ull + (unsigned long long)(d - '0');
                }
                (void)ok;
                char buf[32];
                std::snprintf(buf, sizeof(buf), "0x%llx", v);
                out += buf;
            } else {
                out += tok; // 0x.../identificador-con-digitos: verbatim
            }
            i = j;
            continue;
        }
        out.push_back(c);
        ++i;
    }
    return out;
}

std::string asmblk_trim(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b &&
           (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n'))
        ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' ||
                     s[b - 1] == '\n'))
        --b;
    return s.substr(a, b - a);
}

// Quita un comentario de linea (; o //) respetando comillas.
std::string asmblk_strip_comment(const std::string &s) {
    bool inq = false;
    char q = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (inq) {
            if (c == q && (i == 0 || s[i - 1] != '\\')) inq = false;
            continue;
        }
        if (c == '\'' || c == '"') {
            inq = true;
            q = c;
            continue;
        }
        if (c == ';') return s.substr(0, i);
        if (c == '/' && i + 1 < s.size() && s[i + 1] == '/')
            return s.substr(0, i);
    }
    return s;
}

bool asmblk_is_idchar(char c, bool first) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' ||
        c == '.')
        return true;
    if (!first && c >= '0' && c <= '9') return true;
    return false;
}

// Quita un "label:" inicial si lo hay; devuelve el resto (trim).
std::string asmblk_strip_label(const std::string &s, bool &had_label) {
    had_label = false;
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
        ++i;
    if (i < s.size() && asmblk_is_idchar(s[i], true)) {
        size_t j = i + 1;
        while (j < s.size() && asmblk_is_idchar(s[j], false))
            ++j;
        if (j < s.size() && s[j] == ':') {
            had_label = true;
            return asmblk_trim(s.substr(j + 1));
        }
    }
    return asmblk_trim(s);
}

std::string asmblk_first_word(const std::string &s) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
        ++i;
    size_t j = i;
    while (j < s.size() && s[j] != ' ' && s[j] != '\t')
        ++j;
    std::string w = s.substr(i, j - i);
    for (auto &c : w)
        if (c >= 'A' && c <= 'Z') c += 32;
    return w;
}

int asmblk_data_width(const std::string &w) {
    if (w == "db") return 1;
    if (w == "dw") return 2;
    if (w == "dd") return 4;
    if (w == "dq") return 8;
    return 0;
}

void asmblk_skip_ws(const std::string &s, size_t &p) {
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t'))
        ++p;
}

// Parsea un entero (con signo opcional, bases 0x/0b/0o/decimal).
bool asmblk_parse_number(const std::string &s, size_t &p, int64_t &out) {
    asmblk_skip_ws(s, p);
    bool neg = false;
    if (p < s.size() && (s[p] == '+' || s[p] == '-')) {
        neg = (s[p] == '-');
        ++p;
        asmblk_skip_ws(s, p);
    }
    if (p >= s.size() || !(s[p] >= '0' && s[p] <= '9')) return false;
    uint64_t v = 0;
    int base = 10;
    size_t start = p;
    if (s[p] == '0' && p + 1 < s.size() &&
        (s[p + 1] == 'x' || s[p + 1] == 'X')) {
        base = 16;
        p += 2;
        start = p;
    } else if (s[p] == '0' && p + 1 < s.size() &&
               (s[p + 1] == 'b' || s[p + 1] == 'B')) {
        base = 2;
        p += 2;
        start = p;
    } else if (s[p] == '0' && p + 1 < s.size() &&
               (s[p + 1] == 'o' || s[p + 1] == 'O')) {
        base = 8;
        p += 2;
        start = p;
    }
    while (p < s.size()) {
        char c = s[p];
        int d;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
            break;
        if (d >= base) break;
        v = v * (uint64_t)base + (uint64_t)d;
        ++p;
    }
    if (p == start) return false;
    out = neg ? -(int64_t)v : (int64_t)v;
    return true;
}

// Evalua la cuenta de `times`: expr con enteros, $ (=cur_off), $$ (=0),
// + - * / y parentesis.  Recursivo sobre el string; deja p tras la expr.
int64_t asmblk_eval_expr(const std::string &s, size_t &p, int64_t cur_off,
                         bool &ok);

int64_t asmblk_eval_primary(const std::string &s, size_t &p, int64_t cur_off,
                            bool &ok) {
    asmblk_skip_ws(s, p);
    if (p < s.size() && s[p] == '$') {
        ++p;
        if (p < s.size() && s[p] == '$') {
            ++p;
            return 0;
        } // $$
        return cur_off; // $
    }
    if (p < s.size() && s[p] == '(') {
        ++p;
        int64_t v = asmblk_eval_expr(s, p, cur_off, ok);
        asmblk_skip_ws(s, p);
        if (p < s.size() && s[p] == ')')
            ++p;
        else
            ok = false;
        return v;
    }
    if (p < s.size() && (s[p] == '+' || s[p] == '-')) {
        bool neg = s[p] == '-';
        ++p;
        int64_t v = asmblk_eval_primary(s, p, cur_off, ok);
        return neg ? -v : v;
    }
    int64_t n;
    if (!asmblk_parse_number(s, p, n)) {
        ok = false;
        return 0;
    }
    return n;
}

int64_t asmblk_eval_term(const std::string &s, size_t &p, int64_t cur_off,
                         bool &ok) {
    int64_t v = asmblk_eval_primary(s, p, cur_off, ok);
    for (;;) {
        asmblk_skip_ws(s, p);
        if (p < s.size() && (s[p] == '*' || s[p] == '/')) {
            bool mul = s[p] == '*';
            ++p;
            int64_t r = asmblk_eval_primary(s, p, cur_off, ok);
            if (!ok) return 0;
            if (mul)
                v *= r;
            else {
                if (r == 0) {
                    ok = false;
                    return 0;
                }
                v /= r;
            }
        } else
            break;
    }
    return v;
}

int64_t asmblk_eval_expr(const std::string &s, size_t &p, int64_t cur_off,
                         bool &ok) {
    int64_t v = asmblk_eval_term(s, p, cur_off, ok);
    for (;;) {
        asmblk_skip_ws(s, p);
        if (p < s.size() && (s[p] == '+' || s[p] == '-')) {
            bool add = s[p] == '+';
            ++p;
            int64_t r = asmblk_eval_term(s, p, cur_off, ok);
            if (!ok) return 0;
            if (add)
                v += r;
            else
                v -= r;
        } else
            break;
    }
    return v;
}

// Evalua los operandos de db/dw/dd/dq desde p, anchos de @c width bytes.
bool asmblk_eval_operands(const std::string &s, size_t &p, int width,
                          std::vector<uint8_t> &out, std::string &err) {
    for (;;) {
        asmblk_skip_ws(s, p);
        if (p >= s.size()) break;
        if (s[p] == '"' || s[p] == '\'') {
            char q = s[p++];
            std::string val;
            while (p < s.size() && s[p] != q) {
                char c = s[p++];
                if (c == '\\' && p < s.size()) {
                    char e = s[p++];
                    c = (e == 'n'   ? '\n'
                         : e == 't' ? '\t'
                         : e == 'r' ? '\r'
                         : e == '0' ? '\0'
                                    : e);
                }
                val.push_back(c);
            }
            if (p < s.size()) ++p; // comilla de cierre
            if (q == '"') {
                if (width != 1) {
                    err = "cadena solo valida en db";
                    return false;
                }
                for (unsigned char c : val)
                    out.push_back(c);
            } else {
                uint64_t v = val.empty() ? 0 : (unsigned char)val[0];
                for (int i = 0; i < width; ++i)
                    out.push_back((uint8_t)(v >> (8 * i)));
            }
        } else {
            int64_t v;
            if (!asmblk_parse_number(s, p, v)) {
                err = "operando invalido en directiva de datos del bloque asm";
                return false;
            }
            uint64_t u = (uint64_t)v;
            for (int i = 0; i < width; ++i)
                out.push_back((uint8_t)(u >> (8 * i)));
        }
        asmblk_skip_ws(s, p);
        if (p < s.size() && s[p] == ',') {
            ++p;
            continue;
        }
        break;
    }
    return true;
}

// Evalua una linea de directiva de datos (db/dw/dd/dq o times <expr> <dir>).
bool asmblk_eval_data_line(const std::string &line, std::vector<uint8_t> &out,
                           std::string &err) {
    size_t p = 0;
    std::string w = asmblk_first_word(line);
    p = line.find(w);
    p = (p == std::string::npos ? 0 : p + w.size());
    if (w == "times") {
        bool ok = true;
        int64_t cnt = asmblk_eval_expr(line, p, (int64_t)out.size(), ok);
        if (!ok) {
            err = "expresion invalida en 'times' del bloque asm";
            return false;
        }
        if (cnt < 0) {
            err = "'times' negativo en el bloque asm (revisa $-$$)";
            return false;
        }
        asmblk_skip_ws(line, p);
        // Directiva interna (db/dw/dd/dq).
        size_t ws_start = p;
        while (p < line.size() && line[p] != ' ' && line[p] != '\t')
            ++p;
        std::string dw = line.substr(ws_start, p - ws_start);
        for (auto &c : dw)
            if (c >= 'A' && c <= 'Z') c += 32;
        int width = asmblk_data_width(dw);
        if (width == 0) {
            err = "'times' espera db/dw/dd/dq en el bloque asm";
            return false;
        }
        std::vector<uint8_t> tmp;
        if (!asmblk_eval_operands(line, p, width, tmp, err)) return false;
        for (int64_t k = 0; k < cnt; ++k)
            out.insert(out.end(), tmp.begin(), tmp.end());
        return true;
    }
    int width = asmblk_data_width(w);
    if (width == 0) {
        err = "directiva de datos invalida en el bloque asm: " + w;
        return false;
    }
    return asmblk_eval_operands(line, p, width, out, err);
}

// Ensambla el cuerpo de un bloque `asm` mezclando codigo (Keystone) y
// directivas de datos (propio).  Devuelve false + err en fallo.
/// @brief True si @p w es un nombre de registro x86 (no un simbolo).
bool asmblk_is_register(const std::string &w) {
    static const std::set<std::string> regs = {
        "al",  "bl",  "cl",  "dl",  "ah",  "bh",  "ch",  "dh",  "spl", "bpl",
        "sil", "dil", "ax",  "bx",  "cx",  "dx",  "si",  "di",  "sp",  "bp",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "rax", "rbx",
        "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8",  "r9",  "r10", "r11",
        "r12", "r13", "r14", "r15", "cs",  "ds",  "es",  "fs",  "gs",  "ss"};
    std::string l;
    l.reserve(w.size());
    for (char c : w)
        l.push_back((char)std::tolower((unsigned char)c));
    return regs.count(l) > 0;
}

} // namespace

/* El unico de la familia que se usa fuera de este fichero: los bloques `asm`
 * a nivel de DATOS los ensambla `Lowering::run` al montar el modulo.  Por eso
 * este sale del anonimato y se declara en la cocina compartida; los otros
 * diecisiete no salen de aqui. */
/// @brief Ensambla un bloque @c asm.  @p sym_refs (opcional) recibe las
/// referencias a SiMBOLOS externos (funciones Vesta) que aparecen como
/// @c call/jmp @c <ident>: se emite @c E8/@c E9 + placeholder rel32 y el
/// driver las resuelve (REL32) contra la funcion -> un trampolin asm
/// puede invocar codigo generado (p.ej. un kernel multiboot que llama a
/// @c main).  Un @c call/jmp a un label LOCAL (definido en el bloque) o
/// a un registro/memoria lo sigue ensamblando Keystone.
bool asmblk_assemble(
    const std::string &body, uint8_t bits, std::vector<uint8_t> &out,
    std::string &err,
    std::vector<ir::IrModule::StaticDataMeta::SymRef> *sym_refs) {
    // El arch lo decide el TARGET (una variante @Target("arch:arm64") ensambla
    // en ARM aunque el build corra en x86); los bits solo mandan en x86.
    vx::AsmArch arch = vx::asm_arch_for_target(bits);
    /* Pre-pase: recolectar los labels LOCALes (def `ident:`) para no
     * confundirlos con simbolos externos en call/jmp. */
    std::set<std::string> local_labels;
    {
        std::istringstream ls(body);
        std::string line;
        while (std::getline(ls, line)) {
            std::string t = asmblk_trim(asmblk_strip_comment(line));
            bool had = false;
            std::string before = t;
            asmblk_strip_label(t, had);
            if (had) {
                /* extraer el nombre del label (antes del ':') */
                size_t c = before.find(':');
                if (c != std::string::npos)
                    local_labels.insert(asmblk_trim(before.substr(0, c)));
            }
        }
    }
    std::string instr_buf;
    auto flush = [&]() -> bool {
        std::string t = asmblk_trim(instr_buf);
        instr_buf.clear();
        if (t.empty()) return true;
        if (vx::g_asm_backend == nullptr) {
            err = "no hay backend de ensamblado (Keystone) disponible";
            return false;
        }
        t = asmblk_dec_to_hex(t);
        vx::AsmAssembleResult r = vx::g_asm_backend->assemble(t, arch);
        if (!r.ok) {
            err = "error de ensamblado: " + r.error;
            return false;
        }
        out.insert(out.end(), r.bytes.begin(), r.bytes.end());
        return true;
    };
    std::istringstream is(body);
    std::string line;
    while (std::getline(is, line)) {
        std::string t = asmblk_trim(asmblk_strip_comment(line));
        if (t.empty()) continue;
        bool had_label = false;
        std::string rest = asmblk_strip_label(t, had_label);
        std::string w = asmblk_first_word(rest);
        const bool is_data = (asmblk_data_width(w) > 0) || (w == "times");
        /* call/jmp a un simbolo externo (funcion Vesta): emitir E8/E9 +
         * placeholder rel32 + sym_ref REL32 (lo resuelve el driver). */
        std::string wl;
        for (char c : w)
            wl.push_back((char)std::tolower((unsigned char)c));
        if (sym_refs && (wl == "call" || wl == "jmp")) {
            std::string operand = asmblk_trim(rest.substr(w.size()));
            /* El criterio de "esto es un simbolo de fuera" vive en un solo
             * sitio (@c asm_is_external_symbol): aqui se decide si se emite la
             * referencia a resolver, y el analisis decide con el mismo si
             * avisar de una etiqueta inexistente.  Con dos copias, una emitia
             * la referencia y la otra avisaba de que no existia. */
            const bool bare_ident = vx::asm_is_external_symbol(operand) &&
                                    !asmblk_is_register(operand) &&
                                    !local_labels.count(operand);
            if (bare_ident) {
                if (!flush()) return false;
                out.push_back(wl == "call" ? 0xE8 : 0xE9);
                ir::IrModule::StaticDataMeta::SymRef sr;
                sr.offset = (uint32_t)out.size(); // rel32 justo tras E8/E9
                sr.sym = operand;
                sr.width = 4;
                sr.is_rel = 1;
                sym_refs->push_back(std::move(sr));
                for (int i = 0; i < 4; ++i)
                    out.push_back(0);
                continue;
            }
            // Far jump/call SIMBOLICO `jmp SEG:symbol` (cambio de modo en un
            // dev-OS: `jmp 0x08:pm32`).  Se emite con offset de 32 bits (en
            // 16-bit via prefijo 0x66) -> el campo offset es un sym_ref IMM32
            // (VA absoluta del bloque destino, resuelta por el emisor AOT).
            // No valido en 64-bit (no hay far jmp ptr:off directo).
            size_t colon = operand.find(':');
            if (colon != std::string::npos && bits != 64) {
                std::string segs = asmblk_trim(operand.substr(0, colon));
                std::string offs = asmblk_trim(operand.substr(colon + 1));
                bool seg_ok = true;
                size_t sp = 0;
                int64_t selv = asmblk_eval_expr(segs, sp, 0, seg_ok);
                const bool far_ident =
                    seg_ok && !offs.empty() &&
                    (std::isalpha((unsigned char)offs[0]) || offs[0] == '_') &&
                    offs.find_first_of(" \t[]+-*,:") == std::string::npos &&
                    !asmblk_is_register(offs) && !local_labels.count(offs) &&
                    selv >= 0 && selv <= 0xFFFF;
                if (far_ident) {
                    if (!flush()) return false;
                    // 16-bit: 0x66 (operand-size) fuerza offset de 32 bits.
                    if (bits == 16) out.push_back(0x66);
                    out.push_back(0xEA); // far jmp/call ptr16:32 (EA = jmp)
                    // (call far simbolico no se usa en boot; EA = jmp far).
                    ir::IrModule::StaticDataMeta::SymRef sr;
                    sr.offset = (uint32_t)out.size(); // imm32 (offset) tras EA
                    sr.sym = offs;
                    sr.width = 4;
                    sr.is_rel = 0; // ABS (IMM32: VA absoluta del destino)
                    sym_refs->push_back(std::move(sr));
                    for (int i = 0; i < 4; ++i)
                        out.push_back(0); // placeholder offset32
                    out.push_back((uint8_t)(selv & 0xFF));        // selector lo
                    out.push_back((uint8_t)((selv >> 8) & 0xFF)); // selector hi
                    continue;
                }
            }
        }
        if (is_data) {
            if (!flush()) return false;
            if (!asmblk_eval_data_line(rest, out, err)) return false;
        } else {
            // Instruccion (o linea solo-label): acumular el texto ORIGINAL
            // (con label + comentario) para que Keystone vea los labels.
            instr_buf += line;
            instr_buf += "\n";
        }
    }
    return flush();
}

void Lowering::lower_asm(ast::AsmStmt *s) {
    // Orden de la pipeline (importante): NO se reordena el TEXTO del asm
    // todavia. El reordenamiento por latencia/puertos/ILP se aplica a TODO el
    // codigo generado -- asm liftado Y codigo normal del lenguaje -- en el
    // backend de JIT/AOT, via el scheduler machine-level (arch-data).  Por eso
    // primero se intenta LIFTAR el bloque a IR (mas abajo): una vez es IR, se
    // reordena como cualquier otra instruccion, junto con el resto del codigo.
    // El unico caso que el scheduler machine-level NO puede reordenar es el
    // INLINE_ASM OPACO (no ve dentro): para que ese tampoco se quede sin
    // reordenar, se le aplica un reschedule a nivel de TEXTO asm justo antes de
    // emitirlo (mas abajo). Reordenar aqui, antes del lift, rompia patrones
    // liftables de varias instrucciones (p.ej. cmp+cmov: colaba una mov entre
    // el cmp y el cmov).

    // ABI custom + salida manual: si la funcion tiene register() en sus params
    // (es candidata a inline por el cast a un cfn de menor aridad) y su asm
    // lleva una salida manual (`ret`/`iret`), NO se puede inlinar (el `ret`
    // retornaria en medio del caller) -> se queda como funcion real.  Avisamos
    // para que el usuario decida: quitar el `ret` (y usar `return`) permite el
    // inline optimo (solo los movs de los args del cast).  No es magia:
    // respetamos su `ret`.
    if (fn_ && !fn_->param_abi_regs.empty()) {
        const std::string &b = s->body;
        size_t p = 0;
        bool has_ret = false;
        while (p <= b.size() && !has_ret) {
            size_t nl = b.find('\n', p);
            std::string ln = b.substr(
                p, nl == std::string::npos ? std::string::npos : nl - p);
            size_t cm = ln.find(';');
            if (cm != std::string::npos) ln.resize(cm);
            cm = ln.find("//");
            if (cm != std::string::npos) ln.resize(cm);
            size_t a = ln.find_first_not_of(" \t");
            if (a != std::string::npos) {
                size_t e = ln.find_first_of(" \t", a);
                std::string tok = ln.substr(
                    a, e == std::string::npos ? std::string::npos : e - a);
                if (tok == "ret" || tok == "iret" || tok == "iretq" ||
                    tok == "retf" || tok == "sysret")
                    has_ret = true;
            }
            if (nl == std::string::npos) break;
            p = nl + 1;
        }
        if (has_ret)
            diags_.warning(
                s->loc,
                "el 'ret' en el asm impide inlinar esta funcion con ABI a "
                "medida"
                " (register en params); se mantiene como llamada real.  Quita "
                "el"
                " 'ret' y usa 'return' para permitir el inline optimo (solo los"
                " movimientos de los argumentos que el cast pasa).");
    }
    emit_asm_diagnostics(s);

    ir::IrInstr ia{};
    ia.op = ir::IrOp::INLINE_ASM;
    ia.type = ir::IrType::VOID;
    ia.dst = ir::IR_NO_VALUE;
    ia.source_line = s->loc.line;

    //  AS inc.7: crear las variables register-bound de la lista de
    // operandos `( <clase> <nombre> [= init] )` ANTES de tokenizar el body
    // (para sustituir los placeholders por el registro).  Clase concreta ->
    // el registro se conoce aqui: se crea el mismo AsmRegBinding que inc.5 y
    // se sustituye el placeholder por el nombre del registro en el body ->
    // queda IDENTICO al modelo register().  Clase `reg` (allocator elige) ->
    // requiere sustitucion POST-regalloc en el backend (en desarrollo).
    std::vector<std::pair<std::string, std::string>> ph_subst; // nombre -> reg
    // Registros YA reservados: los operandos con clase CONCRETA + los clobbers
    // explicitos.  Los operandos `reg` (allocator) eligen entre los libres.
    std::set<std::string> used_regs;
    /// Clases sin numero: el compilador elige el registro.  Ademas de `reg`
    /// (enteros) estan las vectoriales, que antes obligaban a escribir el
    /// registro fisico -- y con el escrito a mano el asignador no puede usar
    /// los que estan libres.
    auto clase_automatica = [](const std::string &c) -> bool {
        return c == "reg" || c == "xmm" || c == "ymm" || c == "zmm";
    };
    for (const auto &op : s->operands) {
        if (!clase_automatica(op.reg_class) && op.reg_class != "mem") {
            const std::string c = vx::asm_canonical_reg(op.reg_class);
            if (!c.empty()) used_regs.insert(c);
        }
    }
    for (const auto &cb : s->clobbers) {
        const std::string c = vx::asm_canonical_reg(cb);
        if (!c.empty()) used_regs.insert(c);
    }
    // Preferencia de eleccion para `reg`: caller-saved primero (menos coste de
    // salvado), rsp/rbp excluidos siempre.  El compilador elige el primero
    // libre (no reservado por concretos/clobbers ni por otro `reg` previo).
    static const char *kRegPref[] = {"r10", "r11", "r8",  "r9",  "rcx",
                                     "rdx", "rsi", "rdi", "rax", "rbx",
                                     "r12", "r13", "r14", "r15"};
    /* Indice $N de cada operando que elige el compilador.  Es unico por
     * FUNCION, no por bloque: los bindings de todos los bloques de una funcion
     * viven en una sola lista y se buscan por este numero, asi que empezar de
     * cero en cada bloque hacia que el segundo pisara al primero.  Se nota
     * cuando dos bloques acaban en la misma funcion, que es lo normal en
     * cuanto el optimizador inlinea. */
    int reg_auto_count = 0;
    for (const ir::AsmRegBinding &prev : fn_->asm_reg_bindings)
        if (prev.reg_auto && prev.ph_index >= reg_auto_count)
            reg_auto_count = prev.ph_index + 1;
    for (auto &op : s->operands) {
        std::string reg;
        bool reg_auto = false;
        int ph_index = -1;
        if (op.reg_class == "xmm" || op.reg_class == "ymm" ||
            op.reg_class == "zmm") {
            /* Vectorial AUTO: mismo trato que `reg`.  El cuerpo lo referencia
             * por el marcador $N y quien pone el registro es el ASIGNADOR.
             *
             * Elegirlo aqui era lo que rompia: el numero quedaba horneado en el
             * texto y el asignador no se enteraba de que esa ranura estaba
             * ocupada, asi que podia dejar OTRO valor vivo en ella mientras el
             * bloque la pisaba.  Con pocos operandos rara vez coincidian; a
             * partir de una docena, casi siempre.  Ademas el tope lo ponia este
             * bucle (16 a secas) en vez del banco real del objetivo.
             *
             * Se conserva un pick GREEDY en @c binding.reg como asignacion por
             * defecto para el INTERPRETE, que no tiene asignador: ahi el $N se
             * sustituye por ese registro.  Mismo reparto que en `reg`. */
            reg_auto = true;
            ph_index = reg_auto_count++;
            /* 32 y no 16: con AVX-512 el banco ancho tiene el doble.  Este
             * pick es el que usa el INTERPRETE, que no tiene asignador; quien
             * decide de verdad cuantos hay es el objetivo, y si se piden mas de
             * los que tenga, lo dice al asignar. */
            static const int kNumVec = 32;
            for (int i = 0; i < kNumVec; ++i) {
                const std::string cand = op.reg_class + std::to_string(i);
                if (used_regs.count(cand) == 0) {
                    reg = cand;
                    break;
                }
            }
            if (reg.empty()) {
                diags_.error(op.loc,
                             "asm: sin registros vectoriales libres para el "
                             "operando '" +
                                 op.reg_class +
                                 "' (demasiados operandos/clobbers)");
                continue;
            }
            used_regs.insert(reg);
        } else if (op.reg_class == "reg") {
            // operando `reg` AUTO.  El cuerpo lo referencia por el
            // placeholder $N; el JIT/AOT lo rellenan POST-regalloc con el
            // registro OPTIMO que elige el RA (constraint register-required,
            // ensamblado diferido).  Se conserva un pick GREEDY (kRegPref) en
            // @c binding.reg como asignacion por defecto para el INTERP (que no
            // tiene RA): ahi el $N se sustituye por este registro.
            reg_auto = true;
            ph_index = reg_auto_count++;
            for (const char *cand : kRegPref) {
                if (used_regs.count(cand) == 0) {
                    reg = cand;
                    break;
                }
            }
            if (reg.empty()) {
                diags_.error(op.loc, "asm: sin registros GP libres para el "
                                     "operando 'reg' (demasiados operandos/"
                                     "clobbers)");
                continue;
            }
            used_regs.insert(reg);
        } else if (op.reg_class == "mem") {
            continue; // ya reportado
        } else {
            reg = vx::asm_canonical_reg(op.reg_class);
            if (reg.empty()) continue; // clase invalida (ya reportada)
        }
        // Lower del inicializador (entrada) para deducir el tipo del slot.
        ir::IrType vt = ir::IrType::I64;
        ir::IrValueId v0 = ir::IR_NO_VALUE;
        if (op.init) {
            v0 = lower_expr(op.init.get());
            if (v0 != ir::IR_NO_VALUE) vt = fn_->values[v0].type;
        }
        /* El tamano lo manda la CLASE cuando la hay: una variable ligada a
         * `xmm` mide 16 bytes aunque su tipo Vesta sea de 8.  Con el del tipo,
         * el valor solo conservaba su mitad baja al cruzar de un bloque asm a
         * otro y la alta pasaba a ser lo que hubiera en la pila -- basura
         * dentro del resultado, sin un solo aviso. */
        const uint32_t bytes_clase =
            vx::asm_bytes_de_clase((uint8_t)vx::isa_actual(), op.reg_class);
        const size_t bytes =
            bytes_clase != 0 ? (size_t)bytes_clase : ir::type_access_bytes(vt);
        const ir::IrValueId addr =
            stack_alloc_buf((uint64_t)bytes, s->loc.line);
        bind(op.name, addr);
        address_taken_locals_.insert(op.name);
        /* De que banco es lo decide quien conoce los bancos de cada ISA, no
         * este fichero.  Y se le pregunta por la CLASE DECLARADA, no por el
         * registro de arriba: cuando la ligadura es automatica ese registro es
         * uno elegido a la primera para tener algo que sustituir, y deducir de
         * el la clase daba la respuesta contraria -- un `xmm v0` salia marcado
         * como entero, y sin ruido: cada capa quedaba coherente consigo misma y
         * el valor acababa en `rax` donde el `movdqa` lo espera en `xmm0`. */
        const bool is_vec =
            vx::asm_clase_de_banco((uint8_t)vx::isa_actual(), op.reg_class) ==
            vx::ASM_RC_VEC;
        ir::AsmRegBinding b{addr, reg, vt, is_vec, op.name};
        b.reg_auto = reg_auto;
        b.ph_index = ph_index;
        /* La clase TAL COMO SE ESCRIBIO.  El registro de arriba es el que se
         * eligio a la primera para que el interprete tenga algo que sustituir;
         * la clase es lo que dijo el programador, y es lo unico que sigue
         * diciendo cuanto mide el operando cuando el cuerpo ya solo lleva
         * `$N`. */
        b.reg_class = op.reg_class;
        fn_->asm_reg_bindings.push_back(std::move(b));
        /* Operando SIN inicializador: es un borrador, no entra ningun valor.
         * Meterle un cero era peor que inutil -- creaba un valor vivo desde ese
         * punto hasta el bloque, y si por medio habia una llamada el asignador
         * lo daba por vivo a traves de ella y exigia una ranura preservada.  En
         * System V ninguna ranura ancha lo es, asi que no habia ninguna
         * admisible y el operando acababa en memoria: el bloque salia con el
         * mismo registro repetido.  Eso explicaba que fallara en Linux y no en
         * Windows, donde xmm6-15 si se preservan. */
        if (v0 != ir::IR_NO_VALUE) {
            emit_store_typed(addr, v0, vt, s->loc.line);
        }
        // Placeholder en el cuerpo: reg concreto -> su nombre; reg AUTO -> $N
        // (lo rellena el backend post-regalloc con el fisico que elija el RA).
        ph_subst.emplace_back(
            op.name, reg_auto ? ("$" + std::to_string(ph_index)) : reg);
    }

    //  AS inc.5g (metaprogramacion): sustituir las `comptime` consts
    // ENTERAS por su literal en el cuerpo del asm ANTES de ensamblar, igual
    // que una macro textual (evita hardcodear el valor + mantiene el asm
    // legible).  Tokenizamos por identificadores [A-Za-z_][A-Za-z0-9_]*; un
    // identificador que resuelve a una comptime const entera (no str/array/
    // struct/type) se reemplaza por @c 0x<hex>.  Registros y mnemonicos no
    // colisionan (el usuario no nombra una const "rax"/"mov").
    std::string body_sub;
    {
        const auto &cmap = tc_.comptime_const_values();
        /* Pre-pase: empalmar las constantes comptime de TEXTO antes de nada.
         *
         * Es lo que permite GENERAR el cuerpo en compilacion en vez de
         * escribirlo repetido -- una copia ancha es la misma pareja
         * carga/guardado N veces, cambiando solo el mnemonico y el
         * desplazamiento.
         *
         * Va ANTES del escaneo, no dentro: el texto insertado tiene que pasar
         * por la misma sustitucion de operandos que el escrito a mano.  Si se
         * empalmara durante el escaneo, sus nombres (`v`, `s`, `d`) llegarian
         * crudos al ensamblador. */
        std::string cuerpo_expandido;
        {
            const std::string &orig = s->body;
            size_t p = 0;
            while (p < orig.size()) {
                const char c0 = orig[p];
                const bool ini = (c0 >= 'A' && c0 <= 'Z') ||
                                 (c0 >= 'a' && c0 <= 'z') || c0 == '_';
                if (!ini) {
                    cuerpo_expandido.push_back(c0);
                    ++p;
                    continue;
                }
                size_t q = p + 1;
                while (q < orig.size()) {
                    const char d0 = orig[q];
                    if ((d0 >= 'A' && d0 <= 'Z') || (d0 >= 'a' && d0 <= 'z') ||
                        (d0 >= '0' && d0 <= '9') || d0 == '_')
                        ++q;
                    else
                        break;
                }
                const std::string t0 = orig.substr(p, q - p);
                /* Las locales primero (el ambito mas cercano gana), luego las
                 * del modulo: una `comptime string` declarada dentro de la
                 * funcion es justo el caso normal al generar el cuerpo. */
                const std::string *texto = nullptr;
                const auto &locales = tc_.comptime_const_locals();
                for (auto sc = locales.rbegin(); sc != locales.rend(); ++sc) {
                    auto hit = sc->find(t0);
                    if (hit != sc->end()) {
                        if (hit->second.is_str) texto = &hit->second.str_value;
                        break;
                    }
                }
                if (texto == nullptr) {
                    auto itc = cmap.find(t0);
                    if (itc != cmap.end() && itc->second.is_str)
                        texto = &itc->second.str_value;
                }
                if (texto != nullptr)
                    cuerpo_expandido += *texto;
                else
                    cuerpo_expandido += t0;
                p = q;
            }
        }
        const std::string &b = cuerpo_expandido;
        body_sub.reserve(b.size());
        // Resolucion NAMESPACE-RELATIVA de simbolos propios en el asm.  El
        // cuerpo asm es texto opaco que el aplanador de namespaces NO
        // reescribe, asi que lleva el nombre CRUDO (p.ej. `call fiber_switch`).
        // Pero si la funcion ACTUAL esta en un namespace, el simbolo hermano
        // real es <prefijo>__fiber_switch.  Probamos primero el nombre crudo
        // (simbolo global) y, si no existe, el cualificado con el prefijo del
        // namespace de la funcion actual (scoping normal: el local sombrea al
        // global). Sin esto, un @Naked que llama a otro @Naked hermano por
        // nombre no resolveria bajo un namespace -> el asm saltaria a basura
        // (SIGSEGV).
        std::string ns_prefix;
        if (fn_) {
            const std::string &cur = fn_->name;
            const size_t sep = cur.rfind("__");
            if (sep != std::string::npos) ns_prefix = cur.substr(0, sep + 2);
        }
        // Devuelve el label REAL (mangled) a decorar con __vxf_, o "" si @p nm
        // no es una funcion (ni cruda ni cualificada por el namespace actual).
        auto asm_fn_label = [&](const std::string &nm) -> std::string {
            const FunctionSig *fs = tc_.function_sig_by_name(nm);
            std::string key = nm;
            if (fs == nullptr && !ns_prefix.empty()) {
                const std::string cand = ns_prefix + nm;
                fs = tc_.function_sig_by_name(cand);
                if (fs) key = cand;
            }
            if (fs == nullptr) return {};
            return fs->mangled_label.empty() ? key : fs->mangled_label;
        };
        // Devuelve el slot del global (crudo o cualificado), o -1 si no lo es.
        auto asm_gslot = [&](const std::string &nm) -> long long {
            auto it = runtime_global_slots_.find(nm);
            if (it != runtime_global_slots_.end())
                return static_cast<long long>(it->second);
            if (!ns_prefix.empty()) {
                auto it2 = runtime_global_slots_.find(ns_prefix + nm);
                if (it2 != runtime_global_slots_.end())
                    return static_cast<long long>(it2->second);
            }
            return -1;
        };
        size_t i = 0;
        while (i < b.size()) {
            const char c = b[i];
            const bool id_start =
                (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
            if (!id_start) {
                body_sub.push_back(c);
                ++i;
                continue;
            }
            size_t j = i + 1;
            while (j < b.size()) {
                const char d = b[j];
                if ((d >= 'A' && d <= 'Z') || (d >= 'a' && d <= 'z') ||
                    (d >= '0' && d <= '9') || d == '_')
                    ++j;
                else
                    break;
            }
            const std::string tok = b.substr(i, j - i);
            //  AS inc.7: si el token es el NOMBRE de un operando de la
            // lista `( ... )`, sustituirlo por su REGISTRO (los concretos ya
            // conocen el registro; los `reg` allocator se haran POST-regalloc
            // en el backend).  Tiene prioridad sobre comptime/decoracion.
            {
                bool ph_done = false;
                for (const auto &pr : ph_subst) {
                    if (pr.first == tok) {
                        body_sub += pr.second;
                        i = j;
                        ph_done = true;
                        break;
                    }
                }
                if (ph_done) continue;
            }
            // Bug/feature 198: la decoracion de simbolos propios (__vxf_ fn /
            // __vxg_ global) solo debe aplicarse a tokens en posicion de
            // OPERANDO, NUNCA a un mnemonico ni a un registro.  Critico porque
            // hay builtins del lenguaje cuyo nombre coincide con un mnemonico
            // x86 (`bswap`, `not`, `and`, `or`, `add`, ...); sin este guard,
            // `bswap rax` se reescribia a `__vxf_bswap rax` y Keystone lo
            // rechazaba como mnemonico invalido.
            //
            // Detectamos la posicion de mnemonico mirando hacia atras hasta el
            // inicio de la linea: si solo hay espacios/tabs antes, este token
            // es el primero (mnemonico).
            bool is_mnemonic_pos = true;
            {
                size_t k = i;
                while (k > 0) {
                    const char pc = b[k - 1];
                    if (pc == '\n') break; // inicio de linea
                    if (pc == ' ' || pc == '\t' || pc == '\r') {
                        --k;
                        continue;
                    }
                    is_mnemonic_pos = false; // hay codigo antes
                    break;
                }
            }
            // Un registro tampoco es un simbolo aunque su nombre coincidiera.
            const bool is_reg = asmblk_is_register(tok);
            auto it = cmap.find(tok);
            if (it != cmap.end() && !it->second.is_str &&
                !it->second.is_array && !it->second.is_struct &&
                !it->second.is_type) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "0x%llx",
                              static_cast<unsigned long long>(
                                  static_cast<uint64_t>(it->second.value)));
                body_sub += buf;
            } else if (!is_mnemonic_pos && !is_reg &&
                       !asm_fn_label(tok).empty()) {
                // Referencia a una FUNCION del modulo -> nombre canonico
                // __vxf_<label>.  El backend lo resuelve a un sentinela; el
                // encoder lo decodifica al reloc (CALL_REL32 bare / fnsym: abs)
                // segun la forma de la instruccion (jmp/call/mov/lea).
                //
                // Bug/feature 198: la decoracion se hace en TODOS los modos (no
                // solo native_poo_/AOT).  En interp/JIT el resolver de
                // naked_native mapea __vxf_<label> a la direccion NATIVA de la
                // funcion (native-compilada al vuelo).  Sin decorar, el token
                // quedaba bare y Keystone lo resolvia a un sentinela que nadie
                // parchea -> SIGSEGV al ejecutar el asm.  El label ya viene
                // resuelto namespace-relativo (crudo o <prefijo>__crudo).
                body_sub += "__vxf_" + asm_fn_label(tok);
            } else if (!is_mnemonic_pos && !is_reg && asm_gslot(tok) >= 0) {
                // Referencia a un GLOBAL del modulo -> __vxg_<slot>.  En AOT el
                // encoder lo resuelve a rodata.<slot> (.data del global); en
                // interp/JIT el resolver de naked_native lo mapea a la
                // direccion HOST del slot en vm_mem (donde el codigo VM_ABI
                // escribe/lee el global).  Slot resuelto namespace-relativo.
                body_sub += "__vxg_" + std::to_string(asm_gslot(tok));
            } else {
                body_sub += tok;
            }
            i = j;
        }
    }
    //  AS inc.5g: normalizar los literales numericos del body a hex
    // explicito detectando su base (0x/0b/0o/decimal).  Keystone interpreta
    // los enteros BARE como HEX, asi que sin esto `shl rdx, 32` seria un
    // shift de 0x32=50.  Tras esto, los 4 bases se soportan correctamente.
    body_sub = vx::asm_normalize_numbers(body_sub);
    ia.func_name = body_sub; // cuerpo NASM (consts + bases ya normalizadas)

    if (!validate_asm_syntax(s, body_sub)) return;

    // ASA.3: intentar el LIFT del bloque ANALIZABLE a IR ANTES de los warnings
    // y del INLINE_ASM.  Si liftea, hace return: los diagnosticos de abajo
    // (VXA009 rbx-reservado, VXA010 rsp-reasignado) NO deben dispararse porque
    // solo aplican al bloque que se queda OPACO (INLINE_ASM); un bloque
    // lifteado SI compila nativo aunque use rbx.  El mapa registro-canonico ->
    // slot ALLOCA se construye aqui porque necesita el `lookup` de scope; la
    // deteccion/emision vive en el modulo.
    /* Por que se queda opaco, si se queda.  Lo rellena el ultimo elevado de la
     * cadena, que es el que decide: sin ese dato el aviso de mas abajo no se
     * puede atender, y un aviso que no se puede atender solo ensena a ignorar
     * los avisos. */
    vx::AsmMotivoOpaco motivo_opaco;
    if (try_lift_asm_block(s, ia.func_name, motivo_opaco)) return;

    //  AS inc.3: listar como operandos los slots ALLOCA de las
    // variables register-bound EN SCOPE en este punto.  Esto (a) impide
    // que el optimizer las elimine (INLINE_ASM es op no-safe -> sus
    // operandos "escapan"), y (b) le dice al backend que vars poner en la
    // lista de operandos GCC del bloque asm.  Filtro por scope: una
    // binding esta activa si su nombre resuelve EXACTAMENTE a su alloca en
    // la cadena de scopes actual (descarta vars de scopes hermanos ya
    // cerrados y las sombreadas por una declaracion mas interna).  El
    // type checker garantiza que dos register-bound vivas a la vez nunca
    // comparten el mismo registro fisico, asi que no hay colision GCC.
    // De paso recolectamos sus registros canonicos para EXCLUIRLOS de los
    // clobbers inferidos (son operandos, no clobbers).
    std::vector<std::string> bound_canon;
    for (const auto &b : fn_->asm_reg_bindings) {
        if (lookup(b.name) == b.alloca_value) {
            ia.operands.push_back(b.alloca_value);
            std::string c = asm_canonical_reg(b.reg);
            if (!c.empty()) bound_canon.push_back(c);
            // validar el PIN.  Manipular la pila desde el asm SI esta
            // permitido -- pero en el CUERPO (push/pop, sub rsp, mov rax,rsp;
            // todo eso funciona y el compilador lo entiende), NO pineando un
            // valor Vesta a rsp/rbp (no puede vivir en el puntero de pila sin
            // romper la pila; el marshalling no lo soporta) -> ERROR que GUiA a
            // la forma correcta.  rbx esta reservado por el runtime en modo VM
            // -> el JIT no compila el bloque (cae al interprete) -> WARNING.
            // Los `reg` auto (b.reg_auto) NO se validan: el RA elige usable.
            if (!b.reg_auto) {
                if (c == "rsp" || c == "rbp")
                    // Pinear un valor Vesta a rsp/rbp PUEDE romper la pila,
                    // pero el ABI de algunos syscalls lo exige (Linux x86-32
                    // pasa el 6o arg en ebp).  Se permite bajo responsabilidad
                    // del programador (WARN, no ERROR): el regalloc lo pinea
                    // (for_pin) y el codigo debe salvar/restaurar el registro.
                    diags_.diag(s->body_loc, DiagLevel::WARN, "VXA008",
                                {b.name, c});
                else if (c == "rbx")
                    diags_.diag(s->body_loc, DiagLevel::WARN, "VXA009",
                                {b.name, c});
            }
        }
    }

    // Reasignacion de rsp en una funcion NORMAL: el JIT lo compila (no cae al
    // interprete), pero el epilogue de la funcion gestiona la pila, asi
    // que un cambio de pila PERSISTENTE (corrutinas/fibras) no sobrevive al
    // retorno.  Avisamos (no auto-corregimos): el usuario decide entre marcar
    // la funcion @Naked (dueno de la pila) o equilibrar el cambio antes de
    // cerrar el bloque.  Solo cuenta la REASIGNACION (mov/xchg/lea/pop de
    // rsp/esp), no el ajuste balanceado (sub/add rsp, push/pop de datos), que
    // es uso local legitimo del marco.
    if (!fn_->is_naked) {
        std::string sp_reassigned;
        size_t p = 0;
        while (p < body_sub.size()) {
            size_t nl = body_sub.find('\n', p);
            std::string ln = body_sub.substr(
                p, nl == std::string::npos ? std::string::npos : nl - p);
            p = (nl == std::string::npos) ? body_sub.size() : nl + 1;
            // Trocear mnemonico + primer operando (minusculas).
            size_t i = 0;
            while (i < ln.size() && std::isspace((unsigned char)ln[i]))
                ++i;
            size_t ms = i;
            while (i < ln.size() && !std::isspace((unsigned char)ln[i]))
                ++i;
            std::string mnem = ln.substr(ms, i - ms);
            for (char &ch : mnem)
                ch = (char)std::tolower((unsigned char)ch);
            const bool dest_op = (mnem == "mov" || mnem == "movq" ||
                                  mnem == "lea" || mnem == "pop");
            const bool xchg_op = (mnem == "xchg");
            if (!dest_op && !xchg_op) continue;
            // Operandos tras el mnemonico (sintaxis Intel: DEST primero).
            // Cortar en un comentario `//` o `;` para no mirar el texto de la
            // nota.
            std::string rest = ln.substr(i);
            size_t cm = rest.find("//");
            if (cm != std::string::npos) rest.resize(cm);
            cm = rest.find(';');
            if (cm != std::string::npos) rest.resize(cm);
            for (char &ch : rest)
                ch = (char)std::tolower((unsigned char)ch);
            // Devuelve el operando #n (0=DEST) recortado de espacios.
            auto operand = [&](int n) {
                size_t a = 0;
                for (int k = 0; k < n; ++k) {
                    a = rest.find(',', a);
                    if (a == std::string::npos) return std::string();
                    ++a;
                }
                size_t b = rest.find(',', a);
                std::string t = rest.substr(
                    a, b == std::string::npos ? std::string::npos : b - a);
                size_t s0 = t.find_first_not_of(" \t");
                size_t s1 = t.find_last_not_of(" \t");
                return (s0 == std::string::npos) ? std::string()
                                                 : t.substr(s0, s1 - s0 + 1);
            };
            // reasignacion: rsp/esp es el DESTINO (mov/lea/pop) o CUALQUIER
            // operando de un xchg.  `mov rcx, rsp` (leer rsp) NO cuenta.
            auto is_sp = [](const std::string &o, const char *r) {
                return o == r;
            };
            std::string d0 = operand(0), d1 = operand(1);
            if (is_sp(d0, "rsp") || (xchg_op && is_sp(d1, "rsp"))) {
                sp_reassigned = "rsp";
                break;
            }
            if (is_sp(d0, "esp") || (xchg_op && is_sp(d1, "esp"))) {
                sp_reassigned = "esp";
                break;
            }
        }
        if (!sp_reassigned.empty())
            diags_.diag(s->body_loc, DiagLevel::WARN, "VXA010",
                        {sp_reassigned});
    }

    /* El bloque NO lifto, y eso SE DICE.
     *
     * Un `asm` que se queda opaco no es un detalle interno: deja de optimizarse
     * y, sobre todo, de lo que hace solo se sabe lo que diga su tabla de
     * instrucciones -- ni que memoria toca con que extension, ni que forma
     * tiene su control.  Callarselo hace que todo lo que venga despues de por
     * bueno un analisis que no llego, y eso no se manifiesta como un error sino
     * como una respuesta tranquila y equivocada mucho mas tarde y en otro
     * sitio.
     *
     * Se nombra la primera instruccion que el elevado no supo pasar a IR, que
     * es lo unico accionable: casi siempre es una sola y con reescribirla el
     * bloque entero pasa a ser IR normal. */
    {
        const vx::AsmCfg cfg_op =
            vx::build_asm_cfg(vx::instr_db::Isa::X86, ia.func_name);
        std::string culpable;
        for (const vx::AsmInsn &in : cfg_op.insns) {
            if (in.sintetica) continue;
            if (in.term == vx::AsmTerm::Ret || in.term == vx::AsmTerm::Call ||
                in.term == vx::AsmTerm::Indirect ||
                in.term == vx::AsmTerm::Unknown) {
                culpable = in.text;
                break;
            }
        }
        if (culpable.empty() && !cfg_op.unknown_terminators.empty())
            culpable = cfg_op.unknown_terminators.front();
        /* Lo que dijo el elevado manda sobre lo que se deduzca del grafo: el
         * elevado sabe en que se atasco, el grafo solo ve el control. */
        std::string detalle;
        if (motivo_opaco.consta()) {
            culpable = motivo_opaco.instruccion;
            // El motivo viene como entrada del catalogo con sus parametros, no
            // como frase hecha: asi sale en el mismo idioma que el aviso que lo
            // envuelve, y no media linea en uno dentro de una linea en otro.
            if (!motivo_opaco.id.empty())
                detalle = vx::diag::format(motivo_opaco.id, motivo_opaco.args);
        }
        /* Se avisa SIEMPRE... salvo cuando la opacidad se PIDIO.
         *
         * `volatile` y `raw` significan "no me optimices", y eso es una
         * decision del programador, no una laguna del compilador: avisar ahi es
         * un falso positivo, y un falso positivo repetido ensena a ignorar el
         * aviso de verdad.  Ojo con lo que NO significan: seguir sabiendo QUE
         * HACE el bloque -- sus efectos, que memoria toca, que le exige al
         * procesador -- vale igual, y el informe lo sigue contando.  Lo que se
         * respeta es que no se toque, no que no se mire.
         *
         * En los demas el aviso va: un bloque opaco SIN QUERER es inseguro por
         * definicion, porque todo lo que venga despues da por bueno un analisis
         * que no llego, y eso no sale como un error sino como una respuesta
         * tranquila y equivocada mas tarde y en otro sitio. */
        const bool opacidad_pedida = (s->level != ast::AsmLevel::Analyzable);
        /* De QUE clase es la instruccion, preguntandoselo a la base.  Son tres
         * cosas distintas y confundirlas ensena a ignorar el aviso:
         *
         *   - de proposito general -> se puede modelar en IR y falta hacerlo;
         *   - especifica de la ISA (AES, vectorial...) -> nunca sera IR, y esta
         *     bien: lo que tiene que hacer es quedarse como micro asm que el IR
         *     pueda analizar, con sus efectos de la base;
         *   - desconocida por la base -> no se sabe ni lo que hace.  Eso si es
         *     una caja negra, y es lo unico que hay que arreglar en la base.
         *
         * La clasificacion sale de la propia base, asi que vale para cualquier
         * ISA sin escribir aqui ni un nombre de instruccion. */
        std::string clase;
        if (!culpable.empty()) {
            const vx::instr_db::Isa isa_db = vx::isa_actual();
            const int32_t fid = vx::instr_db::match_asm_line(isa_db, culpable);
            if (fid < 0) {
                clase = vx::diag::format("VXA021", {});
            } else {
                const std::string rasgo = vx::instr_db::nombre_de_rasgo(
                    vx::instr_db::isa_set_of(isa_db, fid));
                clase = rasgo.empty() ? vx::diag::format("VXA019", {})
                                      : vx::diag::format("VXA020", {rasgo});
            }
        }
        if (!opacidad_pedida)
            diags_.diag(
                s->body_loc, DiagLevel::WARN, "VXA018",
                {culpable.empty() ? vx::diag::format("VXA032", {}) : culpable,
                 clase.empty() ? vx::diag::format("VXA033", {}) : clase,
                 detalle.empty() ? vx::diag::format("VXA034", {}) : detalle});
    }

    // El bloque NO lifto (cualquier lift habria hecho return arriba) -> se
    // emite como INLINE_ASM OPACO.  El scheduler machine-level del backend
    // reordena todo el codigo generado, pero NO ve dentro de un INLINE_ASM
    // opaco; para que este tampoco se quede sin reordenar, se le aplica aqui el
    // reschedule a nivel de TEXTO asm (mismo modelo de latencias/puertos).
    // Conservador: reschedule_asm solo reordena si es seguro (sin labels, deps
    // + barreras respetadas, invariante valido); si no, devuelve el body
    // intacto.  Solo modelo register() clasico (sin operandos inc.7 con
    // placeholders $N).
    if (s->level == ast::AsmLevel::Analyzable && s->operands.empty()) {
        const int32_t ua = vx::instr_db::microarch_by_name(
            vx::instr_db::Isa::X86, "intel-skylake");
        body_sub = vx::instr_db::reschedule_asm(
            vx::instr_db::Isa::X86, body_sub,
            static_cast<uint32_t>(ua < 0 ? 0 : ua));
        ia.func_name = body_sub; // el INLINE_ASM emitido usa el body reordenado
    }

    //  AS inc.4: INFERENCIA PROPIA de clobbers (sin Keystone).  Salvo
    // `noinfer`, analizamos el cuerpo y unimos los clobbers inferidos con
    // los explicitos.  `nomem`/`preserves_flags`/`pure` QUITAN memory/flags
    // del set; `clobbers(...)` añaDE.  Resultado final -> asm_clobber_lists
    // + bits 4/5 de imm (memory/flags).
    std::vector<std::string> final_clobbers = s->clobbers; // explicitos primero
    bool final_mem = s->clobbers_memory;
    bool final_flags = s->clobbers_flags;
    /* Lo que el cuerpo LEE, que sale de la misma inferencia.  Con `noinfer` no
     * se infiere nada, asi que la lista queda vacia Y marcada como incompleta:
     * "no se sabe", que no es lo mismo que "no lee nada". */
    std::vector<std::string> final_reads;
    bool final_reads_ok = !s->q_noinfer;
    if (!s->q_noinfer) {
        vx::AsmInferResult inf = vx::asm_infer_clobbers(body_sub, bound_canon);
        final_reads = inf.read_regs;
        final_reads_ok = inf.reads_completos;
        // Union de regs (dedup simple: skip si ya esta).
        for (const auto &c : inf.clobber_regs) {
            bool dup = false;
            for (const auto &e : final_clobbers)
                if (e == c) {
                    dup = true;
                    break;
                }
            if (!dup) final_clobbers.push_back(c);
        }
        final_mem = final_mem || inf.clobber_memory;
        final_flags = final_flags || inf.clobber_flags;
        // Warning si hubo mnemonicos desconocidos: la inferencia no pudo
        // razonar sobre ellos (marco memory+flags conservador), pero el
        // usuario deberia declarar clobbers explicitos para precision.
        if (!inf.unknown_mnemonics.empty()) {
            std::string list;
            for (size_t i = 0; i < inf.unknown_mnemonics.size(); ++i) {
                if (i) list += ", ";
                list += inf.unknown_mnemonics[i];
            }
            diags_.warning(
                s->loc,
                "inline asm: mnemonico(s) no reconocido(s) por la inferencia "
                "de clobbers (" +
                    list +
                    "); declara clobbers(...) explicitos "
                    "para precision o usa 'noinfer'");
        }
    } else if (s->level != ast::AsmLevel::Raw) {
        // ASA.2 (VXA006): con `noinfer`, la lista clobbers(...) es la que ve el
        // regalloc EXACTAMENTE (no se infiere).  Si el asm MODIFICA un registro
        // o las flags que no estan ni ligados por register() ni declarados, el
        // backend los cree preservados -> miscompilacion.  Lo avisamos.  (`raw`
        // es cero-analisis por diseno: no entra.)
        vx::AsmInferResult inf = vx::asm_infer_clobbers(body_sub, bound_canon);
        for (const auto &c : inf.clobber_regs) {
            const std::string cc = vx::asm_canonical_reg(c);
            bool declared = false;
            for (const auto &d : s->clobbers)
                if (vx::asm_canonical_reg(d) == cc) {
                    declared = true;
                    break;
                }
            if (!declared)
                diags_.diag(s->body_loc, DiagLevel::WARN, "VXA006", {c});
        }
        if (inf.clobber_flags && !s->clobbers_flags && !s->q_preserves_flags &&
            !s->q_pure)
            diags_.diag(s->body_loc, DiagLevel::WARN, "VXA007", {});
    }
    // `nomem`/`preserves_flags`/`pure` afirman que NO se toca: override.
    if (s->q_nomem || s->q_pure) final_mem = false;
    if (s->q_preserves_flags || s->q_pure) final_flags = false;

    // Bitfield de calificadores/efectos en imm.
    uint64_t q = 0;
    if (s->q_volatile) q |= 1ull << 0;
    if (s->q_nomem) q |= 1ull << 1;
    if (s->q_preserves_flags) q |= 1ull << 2;
    if (s->q_pure) q |= 1ull << 3;
    if (final_mem) q |= 1ull << 4;
    if (final_flags) q |= 1ull << 5;
    /* bit 32: la lista de clobbers es AUTORITATIVA -- la inferencia corrio
     * sobre el cuerpo, asi que una lista VACIA significa "no destruye nada mas
     * que sus operandos", no "no se sabe".  Con `noinfer` no se promete nada y
     * el backend sigue siendo conservador.
     *
     * Va en el bit 32 y no en el 6 porque los bits 6-7 son el NIVEL del asm y
     * los 8-31 el asm-id; los altos de un imm de 64 bits estan libres. */
    if (!s->q_noinfer) q |= 1ull << 32;
    /* Y el NIVEL, en los dos bits que quedaban libres.
     *
     * `q_volatile` no distingue nada: vale true por defecto, o sea en todos los
     * bloques.  Lo que de verdad separa los casos es el nivel -- `analyzable`
     * es "puedes analizarme y optimizarme", `volatile`/`raw` son "no me
     * toques", que NO es "no me mires" --.  Sin ese dato en el IR, quien lee no
     * puede distinguir un bloque que quedo opaco porque el compilador no supo
     * de uno que esta opaco porque asi se pidio. */
    q |= (static_cast<uint64_t>(s->level) & 3ull) << 6;
    //  AS inc.3/4: empaquetar el "asm-id" (indice en asm_clobber_lists)
    // en los bits altos de imm (8..31).  El backend port-C lo lee para
    // recuperar la lista de clobbers (explicitos + inferidos) de ESTE bloque.
    const uint64_t asm_id = (uint64_t)fn_->asm_clobber_lists.size();
    fn_->asm_clobber_lists.push_back(std::move(final_clobbers));
    /* Y lo que el cuerpo LEE, por el mismo id.  Va en paralelo a los clobbers
     * porque es la otra mitad de la misma pregunta, y quien razone despues
     * sobre lo que sigue vivo la necesita: en los operandos no esta. */
    fn_->asm_read_lists.push_back(std::move(final_reads));
    fn_->asm_reads_completos.push_back(final_reads_ok ? 1u : 0u);
    q |= (asm_id & 0xFFFFFFull) << 8;
    ia.imm = q;

    // volatile por defecto: el bloque nunca debe eliminarse ni
    // reordenarse por el optimizer del IR.
    ia.preserve = true;
    /* El tercer destino posible: no se elevo.  Se anota igual que los otros dos
     * para que el volcado pueda decir cuantos bloques hubo y que fue de cada
     * uno, en vez de ensenar solo los que quedaron. */
    vx::anotar_bloque_asm(fn_->name, s->loc.line, ia.func_name,
                          vx::DestinoAsm::SinElevar);
    emit(current_block_, std::move(ia));

    //  AS inc.6: registrar el import nativo del helper runner para que
    // el linker resuelva el `calln @Method("vrt:inline_asm_exec")` que
    // ir_emitter emite en el backend bytecode (interp puro, sin JIT).
    // Idempotente (register_native_import dedup).
    out_mod_->register_native_import("vrt", "inline_asm_exec");
    /* Y el de la salida por fallo: si el bloque lleva operandos del banco ancho
     * no hay forma de pasarlos por esa via, y el emisor llama a esta otra en su
     * lugar para PARARLO DICIENDOLO.  Se declara aqui porque el bloque
     * `@Import` se escribe antes que los cuerpos: al emitir ya es tarde. */
    out_mod_->register_native_import("vrt", "asm_wide_operand_unsupported");
}

/**
 * @brief Avisa de lo que el compilador ve mal en un bloque `asm`.
 *
 * Solo de los bloques que el compilador debe ENTENDER: un bloque crudo es
 * cero-analisis por diseno, y avisar de el seria hablar de codigo sobre el que
 * no se prometio nada.
 *
 * Los avisos salen CATALOGADOS -- codigo mas argumentos, nunca una frase
 * hecha -- para que el texto pueda darse en el idioma que toque.  Y hay uno
 * que solo aplica al modelo clasico, el que no lista operandos: donde SI se
 * listan, lo que el aviso denuncia no es un fallo sino lo declarado.
 *
 * @param s El bloque.
 */
void Lowering::emit_asm_diagnostics(ast::AsmStmt *s) {
    // ASA.2: diagnosticos del bloque.  Solo para bloques que el compilador debe
    // entender (Analyzable/Volatile; `raw` es cero-analisis por diseno).  Se
    // emiten como WARNINGS; la linea se mapea con body_loc.
    if (s->level != ast::AsmLevel::Raw) {
        auto emit = [&](const std::vector<vx::AsmDiag> &ds) {
            for (const vx::AsmDiag &d : ds) {
                SourceLoc dl = s->body_loc;
                if (d.line_no > 0) dl.line = s->body_loc.line + (d.line_no - 1);
                // Diagnostico CATALOGADO: solo codigo + args; el texto (y su
                // idioma) los resuelve el catalogo al imprimir.
                const DiagLevel lvl =
                    (d.severity == vx::AsmDiagSeverity::Error) ? DiagLevel::ERR
                    : (d.severity == vx::AsmDiagSeverity::Info)
                        ? DiagLevel::NOTE
                        : DiagLevel::WARN;
                diags_.diag(dl, lvl, d.code, d.args);
            }
        };
        vx::AsmCfg cfg = vx::build_asm_cfg(vx::instr_db::Isa::X86, s->body);
        // ESTRUCTURALES (codigo muerto, salto no resuelto, bucle sin salida):
        // solidos, sin dependencias.
        emit(vx::asm_diagnose_cfg(cfg));
        // DATAFLOW.  defined_in = registros ligados por register() EN SCOPE
        // (los que el `lookup` sigue resolviendo a su ALLOCA).  Solo lo
        // computamos para el modelo CLASICO (sin operandos inc.7): el inc.7 usa
        // placeholders %name en el body -> las lecturas/escrituras de registro
        // no son fiables ahi, asi que en ese caso solo emitimos VXA005 (flags,
        // basado en el mnemonico/rama, no en los operandos).  Tratar TODAS las
        // bindings como definidas es un SUPERSET seguro: puede infra-avisar
        // (output leido antes de escribirse) pero nunca da un falso positivo.
        const bool classic_model = s->operands.empty();
        std::vector<std::string> defined_in;
        if (classic_model) {
            for (const auto &b : fn_->asm_reg_bindings)
                if (lookup(b.name) == b.alloca_value) {
                    std::string c = vx::asm_canonical_reg(b.reg);
                    if (!c.empty()) defined_in.push_back(std::move(c));
                }
        }
        int32_t ua = vx::instr_db::microarch_by_name(vx::instr_db::Isa::X86,
                                                     "intel-skylake");
        std::vector<vx::AsmDiag> df =
            vx::asm_diagnose_uninit(cfg, vx::instr_db::Isa::X86, defined_in,
                                    static_cast<uint32_t>(ua < 0 ? 0 : ua));
        std::vector<vx::AsmDiag> keep;
        for (auto &d : df)
            if (classic_model || d.code == "VXA005") // VXA004 solo en clasico.
                keep.push_back(std::move(d));
        emit(keep);
    }
}

/**
 * @brief Comprueba que el cuerpo del bloque `asm` ensambla.
 *
 * Se ensambla ENTERO y no linea a linea, porque una linea sola no ve el resto:
 * un salto a una etiqueta necesita la definicion de esa etiqueta, que esta en
 * otra.  Se ensambla ademas para el OBJETIVO, no para la maquina donde corre
 * el compilador, que puede no ser la misma.
 *
 * Los bytes que salen se tiran: esto es solo la comprobacion.  Y si no hay
 * ensamblador registrado se omite -- que no lo haya es una situacion legitima,
 * no un fallo del programa que se compila.
 *
 * @param s        El bloque.
 * @param body_sub El cuerpo con los sustitutos ya resueltos.
 * @return @c false si no ensambla, con el error ya dado.
 */
bool Lowering::validate_asm_syntax(ast::AsmStmt *s,
                                   const std::string &body_sub) {
    //  AS inc.4b: validacion de sintaxis en compile-time via el
    // backend de ensamblado (Keystone).  Si esta registrado y rechaza el
    // body, emitimos un error con la linea Vesta (mejor que esperar a que
    // GCC falle al compilar el .c).  Si no hay backend (tests sin main),
    // se omite: GCC valida en port-C.  Solo es validacion -- los bytes se
    // descartan (se usaran en inc.5 JIT).
    if (vx::g_asm_backend && !body_sub.empty()) {
        // Ensamblar el cuerpo COMPLETO (preserva el contexto de etiquetas: un
        // `jmp .loop` necesita ver la definicion `.loop:` de otra linea).
        // Arch del TARGET (no del host): ARM si @Target lo pide, o 32/16 en x86
        // segun @bits / --aot-arch.
        const vx::AsmArch asm_arch = vx::asm_arch_for_target(asm_target_bits_);
        // el cuerpo puede llevar placeholders $N (operandos `reg`
        // auto).  Para VALIDAR la sintaxis con Keystone hay que darle un cuerpo
        // concreto -> sustituimos $N por el pick greedy del binding (el
        // ensamblado real usa el registro OPTIMO del RA post-regalloc en el
        // JIT/AOT, o este mismo greedy en el interp).
        const std::string vbody =
            vx::asm_body_subst_greedy(body_sub, fn_->asm_reg_bindings);
        vx::AsmAssembleResult ar = vx::g_asm_backend->assemble(vbody, asm_arch);
        if (!ar.ok) {
            // Traducir el codigo de Keystone a un mensaje claro en espanol.
            auto human_asm_error = [](const std::string &e) -> std::string {
                auto has = [&](const char *s) {
                    return e.find(s) != std::string::npos;
                };
                if (has("mnemonic") || has("Mnemonic"))
                    return "instruccion desconocida (mnemonico no valido)";
                if (has("operand") || has("Operand"))
                    return "operando no valido para esta instruccion";
                if (has("ymbol") || has("ndefined") || has("elocation"))
                    return "simbolo o etiqueta no definido";
                if (has("token") || has("Token") || has("xpression") ||
                    has("expr"))
                    return "token no reconocido (no es una instruccion valida)";
                if (has("mmediate"))
                    return "valor inmediato no valido o fuera de rango";
                if (has("egister")) return "registro no valido";
                if (has("refix")) return "prefijo de instruccion no valido";
                // Sin traduccion conocida: generico en espanol (el detalle de
                // Keystone se anexa aparte, asi no se duplica).
                return "instruccion o sintaxis no valida";
            };

            // Localizar la LINEA del fallo: re-ensamblar cada linea por
            // separado y quedarnos con la primera que falla por un motivo que
            // NO sea "simbolo no definido" (en una linea aislada, un salto a
            // una etiqueta de otra linea daria un falso positivo de simbolo).
            SourceLoc eloc = s->body_loc;
            std::string detail = ar.error;
            {
                size_t start = 0;
                uint32_t line_rel = 0; // lineas desde el inicio del cuerpo
                bool located = false;
                for (size_t k = 0; k <= body_sub.size() && !located; ++k) {
                    if (k == body_sub.size() || body_sub[k] == '\n') {
                        // contenido util de la linea [a, e2) tras recortar
                        size_t a = start, e2 = k;
                        while (a < e2 &&
                               (body_sub[a] == ' ' || body_sub[a] == '\t' ||
                                body_sub[a] == '\r'))
                            ++a;
                        while (e2 > a && (body_sub[e2 - 1] == ' ' ||
                                          body_sub[e2 - 1] == '\t' ||
                                          body_sub[e2 - 1] == '\r'))
                            --e2;
                        std::string ln = vx::asm_body_subst_greedy(
                            body_sub.substr(a, e2 - a), fn_->asm_reg_bindings);
                        const bool is_comment =
                            ln.empty() || ln[0] == ';' ||
                            (ln.size() >= 2 && ln[0] == '/' && ln[1] == '/');
                        if (!is_comment) {
                            vx::AsmAssembleResult lr =
                                vx::g_asm_backend->assemble(ln, asm_arch);
                            if (!lr.ok &&
                                lr.error.find("ymbol") == std::string::npos &&
                                lr.error.find("ndefined") ==
                                    std::string::npos &&
                                lr.error.find("elocation") ==
                                    std::string::npos) {
                                eloc.line = s->body_loc.line + line_rel;
                                eloc.column = (line_rel == 0)
                                                  ? s->body_loc.column +
                                                        (uint32_t)(a - start)
                                                  : (uint32_t)(a - start) + 1;
                                detail = lr.error;
                                located = true;
                            }
                        }
                        ++line_rel;
                        start = k + 1;
                    }
                }
            }
            error_at(eloc, "inline asm: " + human_asm_error(detail) + " -- " +
                               detail);
            return false;
        }
    }
    return true;
}

/**
 * @brief Intenta traducir el bloque `asm` a IR en vez de dejarlo opaco.
 *
 * Un bloque que el compilador entiende puede convertirse en instrucciones del
 * IR, y entonces deja de ser una caja negra: el optimizador lo ve, el
 * asignador de registros reparte los suyos, y el resto del programa se puede
 * razonar a traves de el.
 *
 * Si sale, se acabo: el bloque NO se emite ademas como opaco.
 *
 * @param s             El bloque.
 * @param asm_name      El cuerpo ya normalizado, que identifica al bloque.
 * @param motivo_opaco  Donde el ultimo elevado deja POR QUE no pudo, que es lo
 *                      que hace atendible el aviso de mas abajo.
 * @return @c true si quedo traducido y no hay que emitir nada mas.
 */
bool Lowering::try_lift_asm_block(ast::AsmStmt *s, const std::string &asm_name,
                                  vx::AsmMotivoOpaco &motivo_opaco) {
    /* Interruptor para PODER COMPARAR: con `VESTA_ASM_NO_LIFT=1` no se eleva
     * ningun bloque y todos se emiten opacos.
     *
     * Elevar un `asm` es una transformacion como cualquier otra, y una
     * transformacion se comprueba comparando el antes con el despues.  Sin
     * poder apagarla, la unica manera de saber si cambio el comportamiento era
     * reescribir el programa a mano con `volatile` -- que ademas cambia OTRA
     * cosa (la optimizacion), asi que ni siquiera era la misma comparacion.
     * Esto ya se pago: un elevado que producia un IR de aspecto impecable hacia
     * que el programa devolviera otro numero, y solo se vio escribiendo el caso
     * a mano.  Que el IR tenga buena pinta no es que este bien. */
    static const bool sin_elevado = util::flag_on(util::FlagId::AsmNoLift);
    if (!sin_elevado && s->level == ast::AsmLevel::Analyzable) {
        std::unordered_map<std::string, ir::IrValueId> slot_of;
        for (const auto &b : fn_->asm_reg_bindings)
            if (lookup(b.name) == b.alloca_value) {
                std::string c = asm_canonical_reg(b.reg);
                if (!c.empty()) slot_of[c] = b.alloca_value;
            }
        if (vx::asm_lift_emit(*fn_, current_block_, vx::instr_db::Isa::X86,
                              asm_name, slot_of, s->loc.line))
            return true; // patron liftado -> NO se emite el INLINE_ASM.

        // Lift GENERAL instruccion-a-instruccion: el asm entero straight-line
        // (mov/lea/ALU/neg-not/inc-dec, [reg]) pasa a IR SSA real (ADD, LOAD,
        // STORE...) que participa del optimizador -> del asm del usuario sale
        // codigo mas eficiente.  Los registros ligados por register() se cargan
        // de su slot (al ancho de su tipo) y se escriben de vuelta.  Cualquier
        // forma fuera del subset -> false y cae al ASM_MICRO / INLINE_ASM.
        {
            std::unordered_map<std::string, vx::AsmBoundReg> bound;
            for (const auto &b : fn_->asm_reg_bindings)
                if (lookup(b.name) == b.alloca_value) {
                    /* Una ligadura sin nombre de registro es la forma NORMAL
                     * de escribir: `reg d = p` deja que el compilador elija, y
                     * el cuerpo la nombra con su marcador.  Descartarla dejaba
                     * al lift general ciego justo a lo que mas se usa -- un
                     * `mov [d], b`, que en el IR es un almacenamiento de toda
                     * la vida, acababa como instruccion sin representar. */
                    const std::string c = asm_canonical_reg(b.reg);
                    if (c.empty()) continue;
                    // Ancho en bits desde el eje de RANURA del vocabulario
                    // unico: aqui habia otra copia de esa tabla.
                    const int wbits =
                        static_cast<int>(ir::type_slot_bytes(b.type) * 8u);
                    bound[c] = vx::AsmBoundReg{b.alloca_value, wbits};
                    /* Y por su MARCADOR.  Una ligadura automatica lleva
                     * ademas un registro elegido por defecto para el
                     * interprete, asi que el mapa quedaba indexado por ese
                     * nombre mientras el cuerpo la nombra con su marcador:
                     * no se encontraban, y la instruccion se quedaba sin
                     * representar aunque el IR la tenga. */
                    if (b.reg_auto && b.ph_index >= 0)
                        bound["$" + std::to_string(b.ph_index)] =
                            vx::AsmBoundReg{b.alloca_value, wbits};
                }
            uint32_t asm_exit = current_block_;
            if (vx::asm_lift_general(*fn_, current_block_,
                                     vx::instr_db::Isa::X86, asm_name, bound,
                                     s->loc.line, &asm_exit)) {
                // Si el asm tenia ramas, el lift creo un CFG y devuelve el
                // bloque de CONTINUACION: el codigo siguiente se baja ahi.
                current_block_ = asm_exit;
                /* Y queda anotado que se elevo.  Es el UNICO momento en que se
                 * sabe: a partir de aqui son operaciones normales y nada las
                 * distingue de las que escribio el programador. */
                vx::anotar_bloque_asm(fn_->name, s->loc.line, asm_name,
                                      vx::DestinoAsm::ElevadoAIr);
                return true; // bloque liftado a IR real -> NO se emite el
                             // INLINE_ASM.
            }
        }

        // Si no encaja un patron tipado, intentar el lift GENERAL a ASM_MICRO:
        // instrucciones opacas SIN operandos de registro (mfence/pause/...)
        // pasan a ser IR (una ASM_MICRO por instruccion) que lleva sus efectos
        // de la DB, en vez de la caja opaca INLINE_ASM.  Solo si TODO el bloque
        // encaja (transaccional); si no, cae al INLINE_ASM de abajo.
        if (vx::asm_lift_micro(*fn_, current_block_, vx::instr_db::Isa::X86,
                               asm_name, s->loc.line, slot_of, &motivo_opaco)) {
            // El interp ejecuta la ASM_MICRO via vrt:asm_micro_exec (trampoline
            // nativo si hay ensamblador, o emulacion portable del efecto).
            // Registrar el import para que el linker lo resuelva.  Idempotente.
            out_mod_->register_native_import("vrt", "asm_micro_exec");
            /* Y el que enhebra los valores: el interprete no reparte registros,
             * asi que un bloque cuyos operandos son valores del programa se
             * ejecuta metiendolos antes y sacandolos despues. */
            out_mod_->register_native_import("vrt", "asm_micro_ops");
            vx::anotar_bloque_asm(fn_->name, s->loc.line, asm_name,
                                  vx::DestinoAsm::MicroAsm);
            return true; // bloque liftado a ASM_MICRO -> NO se emite el
                         // INLINE_ASM.
        }
    }
    return false;
}

} // namespace vx
