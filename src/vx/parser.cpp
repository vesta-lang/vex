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
 * @file parser.cpp
 * @brief Implementacion del parser recursivo descendente de Vesta.
 *
 * Notas de rendimiento:
 *  - Cada nivel de precedencia se inlinea bien porque las funciones son
 *    pequenyas y se llaman desde un unico llamador (la siguiente capa).
 *  - El loop tipico es del estilo:
 *        auto lhs = parse_lower();
 *        while (binop matches) lhs = combine(lhs, parse_lower());
 *    Esto evita recursion profunda en expresiones largas como
 *    a + b + c + d + ...  (aprovecha la asociatividad por la izquierda).
 *  - synchronize() avanza tokens hasta el siguiente sentinel para
 *    evitar avalanchas de errores tras un fallo.
 */

#include "util/env_flags.h"
#include "vx/parser.h"

#include "vx/contract_when.h"

#include <algorithm> // std::find sobre los vectores de nombres (lo arrastraba
// otra cabecera en MinGW, pero no en la libreria estandar
// de Linux: alli el fichero no compilaba)
#include <iostream>
#include <string>
#include <unordered_set>
#include <utility>
#include <cctype>
#include <cstdint>
#include <functional>
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <cpuid.h>
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace vx {

/**
 * @brief Traduce el sufijo de tipo de un literal a su categoria primitiva.
 *
 * El lexer guarda el sufijo como el `KW_*` del tipo que nombra (`42i8` ->
 * @c KW_INT8), porque el sufijo ES el nombre de un tipo y esa tabla ya
 * existia.  El puente hasta @c PrimitiveKind es el nombre canonico, que las
 * dos tablas saben producir: asi no hay una tercera que mantener a mano ni
 * forma de que discrepen.
 *
 * @param t Token del literal.
 * @return La categoria del sufijo, o @c VOID si el literal va desnudo.
 */
static PrimitiveKind suffix_primitive(const Token &t) {
    if (!is_numeric_type_keyword(t.suffix)) return PrimitiveKind::VOID;
    return numeric_primitive_from_name(token_kind_name(t.suffix));
}

/**
 * @brief Reconoce nombres de builtins comptime de introspection.
 *
 * Solo cuando el parser ve un IdentExpr cuyo nombre esta en este set
 * y va seguido de @c <, consume los type args como parte de un
 * CallExpr generico.  Sin esta restriccion, @c LT en posicion postfix
 * seria ambiguo con operadores de comparacion (@c foo < bar).
 *
 * Para añadir nuevos builtins comptime: insertar el nombre aqui y en
 * el dispatcher del type checker.  El parser solo necesita el set
 * (un name no listado se trata como llamada normal sin type args, lo
 * cual no rompe codigo existente -- LT pasa al binary expr parser).
 */
static bool is_comptime_builtin_name(const std::string &name) {
    static const std::unordered_set<std::string> set = {
        /* queries atomicas */
        "sizeof",
        "alignof",
        "typename",
        "type_id",
        "kind",
        /* `bitcast<T>(v)`: RUNTIME (no comptime), pero lleva type-arg y el
         * parser necesita saberlo para no tratar el `<` como comparacion. */
        "bitcast",
        /* queries de fields/methods */
        "offsetof",
        "has_field",
        "has_method",
        "field_count",
        "method_count",
        "field_name",
        "field_type",
        "is_subtype",
        "is_same",
        "is_class",
        "is_struct",
        "is_primitive",
        "is_newtype",
        "is_opaque",
        "underlying_of",
        /* #6: predicados de tipo, base de los conceptos built-in */
        "is_integer",
        "is_signed",
        "is_unsigned",
        "is_float",
        "is_numeric",
        "is_bool",
        "is_char",
        "is_pointer",
        "is_string",
        /* iteracion + acceso directo */
        "field_get",
        "field_set",
        "for_each_field",
        "for_each_method",
        /* Type-as-first-class-value + builtins composables */
        "comptime_type",
        "parent_class",
        "element_type",
        "error_type",
        "field_type_at",
        "method_name",
        "method_return_type",
        /* string ops comptime (sin <T>) */
        /* Estos NO toman type_args, pero los meto aqui solo para
         * documentar que son builtins reconocidos.  El parser no los
         * usa para nada especial (no consume LT). */
    };
    return set.count(name) > 0;
}

// ---------------------------------------------------------------------
// Constructor.
// ---------------------------------------------------------------------

Parser::Parser(Lexer &lex, Diagnostics &diags)
    : lex_(lex), diags_(diags), current_(lex.next()) {
    // current_ se carga con el primer token al construir.  A partir
    // de aqui consume() avanza siempre.
}

//  M.L24: skip una decl top-level cuando @Target no matchea.
// Consume tokens hasta el final natural de la decl: para decls con
// cuerpo `{ ... }`, hasta cerrar el `}` matching; para decls simples
// (typedef, using, global var), hasta el siguiente `;` top-level.
void Parser::skip_target_skipped_decl(const std::string &spec) {
    int brace_depth = 0;
    bool entered_body = false;
    // Nombre de lo que se esta descartando.  No se parsea la decl, asi que se
    // deduce del flujo de tokens con las mismas reglas de siempre: el
    // identificador que precede al primer `(` es el de una funcion; el que
    // sigue a class/struct/enum es el del tipo; y para un typedef vale el
    // ultimo identificador antes del `;`, que es donde va el nombre en las
    // tres formas.  Sirve para que quien luego use ese simbolo reciba "existe
    // pero para otro objetivo" en vez de "no declarado".
    std::string nombre;
    std::string ult_ident;
    bool esperando_tipo = false;
    bool cerrado = false;
    while (current_.kind != TokenKind::END_OF_FILE) {
        const auto k = current_.kind;
        if (!cerrado && brace_depth == 0) {
            if (esperando_tipo) {
                if (k == TokenKind::IDENTIFIER) {
                    nombre = current_.lexeme;
                    cerrado = true;
                }
                esperando_tipo = false;
            } else if (k == TokenKind::KW_CLASS || k == TokenKind::KW_STRUCT ||
                       k == TokenKind::KW_ENUM) {
                esperando_tipo = true;
            } else if (k == TokenKind::IDENTIFIER) {
                ult_ident = current_.lexeme;
            } else if (k == TokenKind::LPAREN && !ult_ident.empty()) {
                nombre = ult_ident; // funcion: el ident antes del '('
                cerrado = true;
            }
        }
        if (k == TokenKind::LBRACE) {
            ++brace_depth;
            entered_body = true;
            (void)consume();
        } else if (k == TokenKind::RBRACE) {
            if (brace_depth > 0) --brace_depth;
            (void)consume();
            if (entered_body && brace_depth == 0) {
                // Hay declaraciones que cierran con cuerpo Y punto y coma
                // (`typedef X Y new { ... };`, `struct S { ... };` al estilo
                // C).  Sin consumirlo aqui, ese `;` quedaba suelto y el
                // siguiente parse fallaba con un "se esperaba un tipo al
                // inicio de la declaracion" que no tenia nada que ver.
                if (current_.kind == TokenKind::SEMICOLON) (void)consume();
                break;
            }
        } else if (k == TokenKind::SEMICOLON && brace_depth == 0 &&
                   !entered_body) {
            (void)consume();
            break;
        } else {
            (void)consume();
        }
    }
    // Sin `(` ni keyword de tipo (typedef, using, global): el nombre es el
    // ultimo identificador que se vio.
    if (!cerrado) nombre = ult_ident;
    if (!nombre.empty()) {
        auto &v = target_skipped_[nombre];
        if (std::find(v.begin(), v.end(), spec) == v.end()) v.push_back(spec);
    }
}

//  M.condcomp: evaluador completo de @Target.  Soporta una
// expresion booleana sobre atomos de build:
//   - os:windows / os:linux / os:macos / os:posix
//   - arch:x86_64 / arch:arm64 / arch:x86
//   - cpu:sse2 / cpu:sse / cpu:avx / cpu:avx2 / cpu:avx512f / cpu:neon
//   - compiler OP M.m   (OP en >= > <= < == =) -> version del compilador
//   - vm OP M.m         -> version de la VM
//   - mode:auto / mode:jit / mode:vm / mode:jit-required
// Operadores: ! (NOT), && (AND), || (OR), parentesis.  Precedencia
// estandar: ! > && > ||.  Mapea directo a `#if defined(...)` (C),
// `#[cfg(...)]` (Rust), `static if (...)` (D).

// Version del compilador / VM expuesta a @Target (M.m).  Bump al
// publicar releases con semver.  El test M.condcomp espera
// compiler>=1.0 y vm>=1.0 -> true; compiler>=99.0 -> false.
static constexpr double VX_TARGET_COMPILER_VERSION = 1.0;
static constexpr double VX_TARGET_VM_VERSION = 1.0;

// Override del TARGET para @Target en compilacion AOT cross-target.  El AOT
// genera codigo para un (os, arch) que puede NO ser el host de build (p.ej.
// ELF/SysV desde Windows, o x86-32 desde x86-64).  Cuando el driver lo setea,
// los atomos `os:`/`arch:` de @Target se evaluan contra el TARGET del binario,
// no contra el host -> las variantes @Target("os:linux && arch:x86_64") del
// runtime seleccionan la correcta para lo que se esta generando.  Vacio =
// usar el host de build (ruta normal --vx/--run).  thread_local por el
// compile paralelo (M8).
static thread_local std::string g_cc_target_os;   // "windows"/"linux"/"macos"
static thread_local std::string g_cc_target_arch; // "x86_64"/"x86"/"arm64"
/// Camino de compilacion activo: "aot" cuando se genera codigo nativo, vacio
/// en la ruta de bytecode.  Es lo que hace utilizable `@Target("mode:aot")`.
///
/// OJO con lo que este eje PUEDE y NO PUEDE decir: separa AOT de bytecode,
/// porque son compilaciones distintas.  NO separa interprete de JIT: los dos
/// ejecutan el MISMO .velb y quien decide es un flag de ejecucion, asi que
/// eso no es una propiedad del codigo emitido y no se puede resolver aqui.
static thread_local std::string g_cc_target_mode;
/// Tier del binario nativo (`full`/`embed`/`bare`) y si va SIN libc.  Es lo que
/// contesta a `@Target("tier:...")`.  Vacio = ruta de bytecode: no hay binario,
/// asi que ningun tier vale.
static thread_local std::string g_cc_target_tier;
static thread_local bool g_cc_target_sin_libc = false;

void set_aot_condcomp_target(const std::string &os,
                             const std::string &arch) noexcept {
    g_cc_target_os = os;
    g_cc_target_arch = arch;
}

void set_aot_condcomp_mode(const std::string &mode) noexcept {
    g_cc_target_mode = mode;
}

void get_aot_condcomp_mode(std::string &mode) noexcept {
    mode = g_cc_target_mode;
}

void set_aot_condcomp_tier(const std::string &tier, bool sin_libc) noexcept {
    g_cc_target_tier = tier;
    g_cc_target_sin_libc = sin_libc;
}

void get_aot_condcomp_tier(std::string &tier, bool &sin_libc) noexcept {
    tier = g_cc_target_tier;
    sin_libc = g_cc_target_sin_libc;
}

// Lee el override actual del target de @Target.  Necesario para propagar el
// thread_local a los workers del compile paralelo (M8): estos parsean los
// modulos en threads distintos, donde @c g_cc_target_os arranca vacio y las
// variantes @Target("os:...") caerian al HOST -> HALLAZGO-2 (cross-compile
// modular seleccionaba la rama del host, p.ej. kernel32 al emitir ELF desde
// Windows).  El dispatcher captura estos valores en el main thread y los
// re-aplica en cada worker antes de parsear.
void get_aot_condcomp_target(std::string &os, std::string &arch) noexcept {
    os = g_cc_target_os;
    arch = g_cc_target_arch;
}

// Deteccion de features de CPU.  En x86 usa cpuid; en arm64 NEON es
// baseline.  SSE/SSE2 son baseline garantizado del ABI x86_64.
static bool target_cpu_has_(const std::string &feat) noexcept {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
    if (feat == "sse" || feat == "sse2") return true; // baseline x86_64
    uint32_t a = 0, b = 0, c = 0, d = 0;
    auto cpuid_count = [](uint32_t leaf, uint32_t sub, uint32_t &ea,
                          uint32_t &eb, uint32_t &ec, uint32_t &ed) noexcept {
#if defined(_MSC_VER)
        int regs[4];
        __cpuidex(regs, (int)leaf, (int)sub);
        ea = (uint32_t)regs[0];
        eb = (uint32_t)regs[1];
        ec = (uint32_t)regs[2];
        ed = (uint32_t)regs[3];
#elif defined(__GNUC__)
        __cpuid_count(leaf, sub, ea, eb, ec, ed);
#else
        ea = eb = ec = ed = 0;
#endif
    };
    if (feat == "avx") {
        cpuid_count(1, 0, a, b, c, d);
        return (c & (1u << 28)) != 0;
    }
    if (feat == "avx2") {
        cpuid_count(7, 0, a, b, c, d);
        return (b & (1u << 5)) != 0;
    }
    if (feat == "avx512f") {
        cpuid_count(7, 0, a, b, c, d);
        return (b & (1u << 16)) != 0;
    }
    if (feat == "neon") return false; // no aplica en x86
    return false;
#elif defined(__aarch64__) || defined(_M_ARM64)
    if (feat == "neon") return true; // NEON baseline en arm64
    return false;
#else
    (void)feat;
    return false;
#endif
}

// Compara la version `have` (M.m) contra `want` segun el operador.
static bool target_ver_cmp_(double have, const std::string &op,
                            double want) noexcept {
    if (op == ">=") return have >= want;
    if (op == ">") return have > want;
    if (op == "<=") return have <= want;
    if (op == "<") return have < want;
    if (op == "==" || op == "=") return have == want;
    return false;
}

// Evalua un atomo simple (sin operadores logicos).  Reconoce las
// formas `k:v` y `k OP version`.
static bool target_atom_eval_(const std::string &atom) noexcept {
    if (atom.empty()) return true;
    // Forma `clave OP version` (compiler / vm).  Buscar el operador
    // de comparacion.
    static const char *OPS[] = {">=", "<=", "==", ">", "<", "="};
    for (const char *opc : OPS) {
        const size_t pos = atom.find(opc);
        if (pos != std::string::npos) {
            std::string key = atom.substr(0, pos);
            std::string op = opc;
            std::string ver = atom.substr(pos + op.size());
            // trim espacios
            auto trim = [](std::string &s) {
                while (!s.empty() && std::isspace((unsigned char)s.front()))
                    s.erase(0, 1);
                while (!s.empty() && std::isspace((unsigned char)s.back()))
                    s.pop_back();
            };
            trim(key);
            trim(ver);
            double want = 0.0;
            try {
                want = std::stod(ver);
            } catch (...) {
                return false;
            }
            if (key == "compiler")
                return target_ver_cmp_(VX_TARGET_COMPILER_VERSION, op, want);
            if (key == "vm")
                return target_ver_cmp_(VX_TARGET_VM_VERSION, op, want);
            return false;
        }
    }
    // Forma `clave:valor`.
    const size_t colon = atom.find(':');
    if (colon == std::string::npos) return false;
    std::string key = atom.substr(0, colon);
    std::string val = atom.substr(colon + 1);
    if (key == "os") {
        // AOT cross-target: evaluar contra el OS del binario generado.
        if (!g_cc_target_os.empty()) {
            if (val == g_cc_target_os) return true;
            if (val == "posix")
                return g_cc_target_os == "linux" || g_cc_target_os == "macos";
            return false;
        }
#if defined(_WIN32)
        return val == "windows";
#elif defined(__APPLE__)
        return val == "macos" || val == "posix";
#elif defined(__linux__)
        return val == "linux" || val == "posix";
#else
        return false;
#endif
    }
    if (key == "arch") {
        // AOT cross-target: evaluar contra la arch del binario generado.
        if (!g_cc_target_arch.empty()) return val == g_cc_target_arch;
#if defined(__x86_64__) || defined(_M_X64)
        return val == "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
        return val == "arm64";
#elif defined(__i386__) || defined(_M_IX86)
        return val == "x86";
#else
        return false;
#endif
    }
    if (key == "cpu") return target_cpu_has_(val);
    if (key == "mode") {
        // `auto` = codigo agnostico: siempre vale.
        if (val == "auto") return true;
        // `aot` / `bytecode`: SI se sabe al compilar, porque son caminos de
        // compilacion distintos.  Antes `mode:aot` caia al `false` de abajo y
        // la declaracion se borraba EN SILENCIO -- el mismo fallo que ya se
        // habia arreglado para `jit`/`vm` con un error explicito.
        if (val == "aot") return g_cc_target_mode == "aot";
        if (val == "bytecode") return g_cc_target_mode != "aot";
        // `jit`/`vm` no llegan aqui (el parser los rechaza antes): el mismo
        // .velb corre en los dos y el modo no es propiedad del codigo emitido.
        // `jit-required` exige JIT, que en compile time no se garantiza.
        return false;
    }
    if (key == "tier") {
        /* Cuanto runtime hay debajo del binario.  Los tres nombres son los del
         * proyecto (@c aot::Tier), no unos inventados aqui.
         *
         * En la ruta de BYTECODE no hay binario nativo del que hablar, asi que
         * ningun `tier:` vale -- y eso es lo correcto: una variante marcada
         * para un tier no debe colarse donde ese tier no existe. */
        if (g_cc_target_tier.empty()) return false;
        /* `sin_libc` es un eje APARTE del tier, aunque se pregunte por la misma
         * clave: es `--freestanding`, y lo que dice es que reservar memoria y
         * el panico pasan a exigir ganchos del usuario en vez de resolverse
         * solos. */
        if (val == "sin_libc") return g_cc_target_sin_libc;
        return val == g_cc_target_tier;
    }
    return false;
}

// Parser recursivo-descendente de la expresion @Target.  Gramatica:
//   or   := and ('||' and)*
//   and  := not ('&&' not)*
//   not  := '!' not | primary
//   primary := '(' or ')' | atom
struct TargetExprParser {
    const std::string &s;
    size_t i = 0;
    explicit TargetExprParser(const std::string &str) : s(str) {}

    void skip_ws() {
        while (i < s.size() && std::isspace((unsigned char)s[i]))
            ++i;
    }

    bool parse_or() {
        bool v = parse_and();
        for (;;) {
            skip_ws();
            if (i + 1 < s.size() && s[i] == '|' && s[i + 1] == '|') {
                i += 2;
                bool r = parse_and();
                v = v || r;
            } else
                break;
        }
        return v;
    }

    bool parse_and() {
        bool v = parse_not();
        for (;;) {
            skip_ws();
            if (i + 1 < s.size() && s[i] == '&' && s[i + 1] == '&') {
                i += 2;
                bool r = parse_not();
                v = v && r;
            } else
                break;
        }
        return v;
    }

    bool parse_not() {
        skip_ws();
        if (i < s.size() && s[i] == '!') {
            ++i;
            return !parse_not();
        }
        return parse_primary();
    }

    bool parse_primary() {
        skip_ws();
        if (i < s.size() && s[i] == '(') {
            ++i;
            bool v = parse_or();
            skip_ws();
            if (i < s.size() && s[i] == ')') ++i; // consumir ')'
            return v;
        }
        // Atomo: leer hasta el siguiente operador logico o parentesis.
        const size_t start = i;
        while (i < s.size()) {
            char c = s[i];
            if (c == '(' || c == ')') break;
            if (c == '|' && i + 1 < s.size() && s[i + 1] == '|') break;
            if (c == '&' && i + 1 < s.size() && s[i + 1] == '&') break;
            if (c == '!') break;
            ++i;
        }
        std::string atom = s.substr(start, i - start);
        // trim
        while (!atom.empty() && std::isspace((unsigned char)atom.front()))
            atom.erase(0, 1);
        while (!atom.empty() && std::isspace((unsigned char)atom.back()))
            atom.pop_back();
        return target_atom_eval_(atom);
    }
};

/**
 * @brief Quita los atomos `mode:` de una expresion de @Target.
 *
 * Cuando una declaracion lleva una variante de modo, ese eje ya se ha tenido
 * en cuenta al marcarla y no debe volver a decidir si se descarta.  El resto
 * de la expresion (os / arch / cpu) SI sigue condicionando, asi que
 * `@Target("mode:jit && arch:x86_64")` sigue siendo solo para x86-64.
 *
 * Cada atomo de modo se sustituye por `mode:auto` -- que ya evalua a cierto --
 * en vez de borrarlo, para no romper la sintaxis de la expresion (`&&` / `||`
 * / parentesis).
 *
 * @param spec Expresion original.
 * @return La expresion con los atomos de modo neutralizados.
 */
static std::string strip_mode_atoms_(const std::string &spec) {
    std::string out;
    out.reserve(spec.size());
    size_t i = 0;
    while (i < spec.size()) {
        // Un atomo empieza por letra; se lee entero para no partir nombres.
        if (std::isalpha((unsigned char)spec[i]) != 0) {
            size_t j = i;
            while (j < spec.size() &&
                   (std::isalnum((unsigned char)spec[j]) != 0 ||
                    spec[j] == '_' || spec[j] == ':' || spec[j] == '-')) {
                ++j;
            }
            const std::string atomo = spec.substr(i, j - i);
            if (atomo.rfind("mode:", 0) == 0) {
                // `mode:auto` ya evalua a cierto, asi que sirve de neutro sin
                // inventar un atomo nuevo.
                out += "mode:auto";
            } else {
                out += atomo;
            }
            i = j;
            continue;
        }
        out += spec[i];
        ++i;
    }
    return out;
}

static bool target_matches_(const std::string &spec_in) noexcept {
    if (spec_in.empty()) return true;
    TargetExprParser p(spec_in);
    return p.parse_or();
}

bool target_expr_matches(const std::string &spec) noexcept {
    return target_matches_(spec);
}

//  M6.a L.3: aplica @c pending_visibility_ al nodo si soporta
// @c is_public.  Limpia el flag al final para que sub-decls nested
// no hereden la visibilidad del top-level que los envuelve.
void Parser::apply_pending_visibility(ast::Node *n) noexcept {
    if (n == nullptr || pending_visibility_ == 0) return;
    // NS.3: internal (3) es EXPORTABLE (visible en el paquete) ->
    // is_public=true ademas de is_internal=true.  public (1) e internal (3)
    // exportan; private (2) no.
    const bool is_public =
        (pending_visibility_ == 1 || pending_visibility_ == 3);
    const bool is_internal = (pending_visibility_ == 3);
    switch (n->kind) {
    case ast::NodeKind::FunctionDecl:
        static_cast<ast::FunctionDecl *>(n)->is_public = is_public;
        static_cast<ast::FunctionDecl *>(n)->is_internal = is_internal;
        break;
    case ast::NodeKind::GlobalVarDecl:
        static_cast<ast::GlobalVarDecl *>(n)->is_public = is_public;
        static_cast<ast::GlobalVarDecl *>(n)->is_internal = is_internal;
        break;
    case ast::NodeKind::TypeAliasDecl:
        static_cast<ast::TypeAliasDecl *>(n)->is_public = is_public;
        break;
    case ast::NodeKind::StructDecl:
        static_cast<ast::StructDecl *>(n)->is_public = is_public;
        break;
    case ast::NodeKind::EnumDecl:
        static_cast<ast::EnumDecl *>(n)->is_public = is_public;
        break;
    case ast::NodeKind::ClassDecl:
        static_cast<ast::ClassDecl *>(n)->is_public = is_public;
        break;
    case ast::NodeKind::BytesDecl:
        static_cast<ast::BytesDecl *>(n)->is_public = is_public;
        break;
    case ast::NodeKind::ConceptDecl:
        static_cast<ast::ConceptDecl *>(n)->is_public = is_public;
        break;
    default: break;
    }
    // Limpiar para no propagar a nested decls.
    pending_visibility_ = 0;
}

// ---------------------------------------------------------------------
// Helpers basicos.
// ---------------------------------------------------------------------

Token Parser::consume() {
    Token t = std::move(current_);
    current_ = lex_.next();
    return t;
}

bool Parser::match(TokenKind k) {
    if (current_.kind == k) {
        (void)consume();
        return true;
    }
    return false;
}

Token Parser::expect(TokenKind k, const char *msg) {
    if (current_.kind == k) return consume();
    // Reportar y devolver un placeholder (UNKNOWN) sin avanzar:
    // dejamos que el caller decida si quiere sincronizar o seguir.
    error_here(msg);
    Token bad;
    bad.kind = TokenKind::UNKNOWN;
    bad.loc = current_.loc;
    return bad;
}

Token Parser::expect_close_angle(const char *msg) {
    // Caso comun: el token actual es ya un `>` (GT).  Consumir y
    // listo.
    if (current_.kind == TokenKind::GT) return consume();
    // Caso del lexer: `>>` se tokeniza como un solo SHR.  Cuando
    // aparece cerrando un argumento de tipo anidado (e.g.
    // `VirtualPtr<VirtualPtr<i64>>`), el parser quiere cerrar UN
    // solo `>` y dejar el otro disponible para el caller exterior.
    // Partimos el token: devolvemos un GT sintetico y mutamos
    // current_ para que sea un GT con loc avanzada un caracter.
    if (current_.kind == TokenKind::SHR) {
        Token first;
        first.kind = TokenKind::GT;
        first.lexeme = ">";
        first.loc = current_.loc;
        // Avanzar la columna del token restante.  El campo de linea
        // no cambia: `>>` siempre cabe en una linea.
        current_.kind = TokenKind::GT;
        current_.lexeme = ">";
        ++current_.loc.column;
        ++current_.loc.offset;
        current_.loc.length = 1;
        return first;
    }
    error_here(msg);
    Token bad;
    bad.kind = TokenKind::UNKNOWN;
    bad.loc = current_.loc;
    return bad;
}

void Parser::error_here(const char *msg) {
    diags_.error(current_.loc, msg);
}

void Parser::error_at(const Token &tok, const char *msg) {
    diags_.error(tok.loc, msg);
}

// -----------------------------------------------------------------------
// Palabras reservadas usadas como nombre: diagnostico especifico.
//
// El enum TokenKind agrupa TODAS las palabras reservadas en un rango
// CONTIGUO (categorias 4..7 de token.h: tipos primitivos, declaracion,
// control de flujo, concurrencia/meta).  Eso permite clasificarlas con
// un par de comparaciones en lugar de una tabla o un switch gigante.
// Si se anaden keywords nuevas DENTRO de esas categorias, esto sigue
// funcionando sin tocar nada.
// -----------------------------------------------------------------------

/**
 * @brief True si @p k es una palabra reservada del lenguaje.
 */
static bool is_reserved_keyword(TokenKind k) noexcept {
    // Categorias 4..7: desde el primer tipo primitivo hasta la ultima
    // keyword de meta.  Un rango, dos comparaciones.
    if (k >= TokenKind::KW_VOID && k <= TokenKind::KW_CASE) return true;
    // Los literales-palabra viven en la categoria de literales (1), fuera
    // del rango anterior, pero tampoco pueden ser nombres.
    return k == TokenKind::TRUE_KW || k == TokenKind::FALSE_KW ||
           k == TokenKind::NULL_KW;
}

/**
 * @brief Rol de la palabra reservada, para enriquecer el diagnostico.
 *
 * Se deriva del rango del enum (barato: comparaciones, sin tabla).  El
 * objetivo es que el mensaje diga POR QUE el termino esta reservado.
 *
 * @param k Palabra reservada (precondicion: is_reserved_keyword(k)).
 * @return Cadena estatica descriptiva (no liberar).
 */
static const char *keyword_role(TokenKind k) noexcept {
    // Casos con un rol mas util que el de su categoria.
    switch (k) {
    case TokenKind::KW_GET:
    case TokenKind::KW_SET: return "accesor de propiedad";
    default: break;
    }
    if (k >= TokenKind::KW_VOID && k <= TokenKind::KW_BORROW_MUT)
        return "tipo primitivo";
    if (k >= TokenKind::KW_CONST && k <= TokenKind::KW_SET)
        return "palabra clave de declaracion";
    if (k >= TokenKind::KW_IF && k <= TokenKind::KW_SUPER)
        return "palabra clave de control de flujo";
    if (k >= TokenKind::KW_SYNCHRONIZED && k <= TokenKind::KW_CASE)
        return "palabra clave de concurrencia/meta";
    // TRUE_KW / FALSE_KW / NULL_KW.
    return "literal del lenguaje";
}

bool Parser::is_name_token(TokenKind k) noexcept {
    // `get`/`set` son CONTEXTUALES: solo son keywords en la forma
    // property dentro de una clase (`get n => e;`, `set n(T v) {...}`),
    // que se detecta ANTES de llegar aqui y siempre SIN tipo previo.
    // En cualquier otra posicion (y en todas las que llaman a este
    // helper ya hemos parseado un tipo, o venimos de un '.') son
    // nombres corrientes, sin ambiguedad posible.
    return k == TokenKind::IDENTIFIER || k == TokenKind::KW_GET ||
           k == TokenKind::KW_SET;
}

void Parser::error_expected_name(const char *what, const char *generic_msg) {
    const TokenKind k = current_.kind;
    if (!is_reserved_keyword(k)) {
        // No es palabra reservada: conservar el mensaje historico del
        // sitio (otro tipo de error: un simbolo, un literal, EOF...).
        error_here(generic_msg);
        return;
    }
    // Palabra reservada: decir cual es, por que lo esta y como salir.
    const char *kw = token_kind_name(k);
    std::string m;
    m.reserve(160);
    m += '\'';
    m += kw;
    m += "' es una palabra reservada del lenguaje (";
    m += keyword_role(k);
    m += "); no puede usarse como ";
    m += what;
    m += ".  Sugerencia: renombralo (p.ej. '";
    m += kw;
    m += "_').";
    diags_.error(current_.loc, std::move(m));
}

void Parser::synchronize() {
    // Avanza hasta el siguiente punto de "respiracion": fin de
    // statement, cierre de bloque, o el inicio de una declaracion
    // de top-level.  Esto evita reportar 50 errores cuando solo hubo 1.
    //
    // GARANTIA DE PROGRESO: consume SIEMPRE al menos un token antes
    // de chequear sync points.  Sin esto, si el parser fallo
    // dejando current_ sobre un sync-point keyword (e.g. KW_FN),
    // parse_program quedaria en bucle infinito: parse_top_level_decl
    // falla -> synchronize ve KW_FN -> retorna sin consumir -> retry.
    // Bug observado: `fn my_release(p: i64) { }` con sintaxis Rust-style
    // a nivel top-level (Vesta usa C-style `T name(T param)`) causaba
    // 5+ GB de RAM al crecer indefinidamente el AST.
    if (current_.kind == TokenKind::END_OF_FILE) return;
    (void)consume(); // forzar progreso
    while (current_.kind != TokenKind::END_OF_FILE) {
        if (current_.kind == TokenKind::SEMICOLON) {
            (void)consume();
            return;
        }
        switch (current_.kind) {
        case TokenKind::RBRACE:
        case TokenKind::KW_IF:
        case TokenKind::KW_WHILE:
        case TokenKind::KW_DO:
        case TokenKind::KW_FOR:
        case TokenKind::KW_RETURN:
        case TokenKind::KW_BREAK:
        case TokenKind::KW_CONTINUE:
        case TokenKind::KW_CLASS:
        case TokenKind::KW_STRUCT:
        case TokenKind::KW_IMPORT:
        case TokenKind::KW_NAMESPACE:
        case TokenKind::KW_CONST:
        case TokenKind::KW_FN: return;
        default: (void)consume();
        }
    }
}

// ---------------------------------------------------------------------
// #cross-module-generics: si @p decl es una plantilla generica o un concepto,
// captura su texto fuente [decl_start_off, current) y lo apila en
// @c generic_template_exports para exportarlo via `.vxi`.  Compartido por el
// top-level (parse_program) y las decls dentro de un `namespace` (para que las
// plantillas/concepts namespaced tambien se exporten cross-module).
// ---------------------------------------------------------------------
void Parser::collect_template_export_(ast::ModuleNode *mod, ast::Node *decl,
                                      uint32_t decl_start_off) {
    if (!mod || !decl) return;
    ast::GenericTemplateExport tex;
    bool is_template = false;
    switch (decl->kind) {
    case ast::NodeKind::StructDecl: {
        auto *sd = static_cast<ast::StructDecl *>(decl);
        if (!sd->type_params.empty() || sd->is_specialization) {
            tex.name = sd->name;
            tex.is_public = sd->is_public;
            is_template = true;
        }
        break;
    }
    case ast::NodeKind::ClassDecl: {
        auto *cd = static_cast<ast::ClassDecl *>(decl);
        if (!cd->type_params.empty() || cd->is_specialization) {
            tex.name = cd->name;
            tex.is_public = cd->is_public;
            is_template = true;
        }
        break;
    }
    case ast::NodeKind::FunctionDecl: {
        auto *fd = static_cast<ast::FunctionDecl *>(decl);
        if ((!fd->type_params.empty() || fd->is_specialization) &&
            !fd->is_comptime && !fd->is_macro) {
            tex.name = fd->name;
            tex.is_public = fd->is_public;
            is_template = true;
        } else if (fd->is_comptime || fd->is_macro) {
            // NS.2/MC: exportar el TEXTO de una fn comptime/macro para que el
            // consumidor la inyecte, la lowere a IR (__macro_<name>) y la
            // evalue en compile-time con su ComptimeRuntime (JIT) -- cross-
            // modulo + explota el cache de IR del consumidor.
            tex.name = fd->name;
            tex.is_public = fd->is_public;
            is_template = true;
        }
        break;
    }
    case ast::NodeKind::EnumDecl: {
        auto *en = static_cast<ast::EnumDecl *>(decl);
        if (!en->type_params.empty()) {
            tex.name = en->name;
            tex.is_public = en->is_public;
            is_template = true;
        }
        break;
    }
    case ast::NodeKind::ConceptDecl: {
        auto *cn = static_cast<ast::ConceptDecl *>(decl);
        tex.name = cn->name;
        tex.is_public = cn->is_public;
        is_template = true;
        break;
    }
    default: break;
    }
    if (!is_template) return;
    const std::string &src = lex_.source_buffer();
    uint32_t end_off = current_.loc.offset; // inicio del sig. token
    if (end_off > src.size()) end_off = static_cast<uint32_t>(src.size());
    if (decl_start_off < end_off && end_off <= src.size()) {
        tex.kind = static_cast<uint8_t>(decl->kind);
        tex.source = src.substr(decl_start_off, end_off - decl_start_off);
        mod->generic_template_exports.push_back(std::move(tex));
    }
}

// ---------------------------------------------------------------------
// Punto de entrada: parse_program.
// ---------------------------------------------------------------------

std::unique_ptr<ast::ModuleNode> Parser::parse_program() {
    auto mod = std::make_unique<ast::ModuleNode>();
    mod->loc.file = lex_.filename();
    mod->loc.line = 1;
    mod->loc.column = 1;

    while (current_.kind != TokenKind::END_OF_FILE) {
        // bloque `extern "lib.dll" { fn ...; fn ...; }` produce
        // N decls (uno por funcion).  Caso especial porque el resto de
        // top-level decls produce 1 nodo y parse_top_level_decl tiene
        // esa firma.
        if (current_.kind == TokenKind::KW_EXTERN) {
            parse_extern_block(*mod);
            continue;
        }
        // #cross-module-generics: capturar el span fuente del decl para poder
        // exportar las plantillas genericas (struct/clase/fn/enum con
        // type_params) y los conceptos a otros modulos via `.vxi`.
        tpl_export_mod_ = mod.get();
        const uint32_t decl_start_off = current_.loc.offset;
        auto decl = parse_top_level_decl();
        if (decl) {
            // #cross-module-generics: capturar el span fuente si es plantilla/
            // concepto (para el `.vxi`).  Helper compartido con
            // parse_namespace_decl (decls dentro de un namespace).
            // Agregados anonimos sintetizados durante el parseo de este decl
            // van ANTES (el decl los referencia por nombre).
            /* Las sintetizadas comparten el tramo de la decl que las genero:
             * salen del MISMO texto (un `typedef` con varios declaradores, un
             * agregado anonimo).  Sin tramo, quien necesita su fuente las
             * descarta -- y un modulo que solo aporta tipos se quedaba en nada,
             * dejando sin declarar lo que otros usaban. */
            for (auto &b : pending_before_decls_) {
                if (current_.loc.offset > decl_start_off) {
                    b->span_start = decl_start_off;
                    b->span_end = current_.loc.offset;
                }
                mod->decls.push_back(std::move(b));
            }
            pending_before_decls_.clear();
            collect_template_export_(mod.get(), decl.get(), decl_start_off);
            /* Donde ACABA esta decl.  Al volver de parsearla el token actual ya
             * es el siguiente, asi que su offset marca el final -- arrastrando
             * como mucho los espacios y comentarios de en medio, que no
             * estorban a nadie.  Deducirlo despues, desde el texto, cortaba
             * funciones por la mitad. */
            /* Solo si el tramo tiene sentido.  Al final del fichero, o tras
             * recuperarse de un error, el token actual puede quedar ANTES del
             * inicio; anotarlo daria un tramo de longitud negativa. */
            if (current_.loc.offset > decl_start_off) {
                decl->span_start = decl_start_off;
                decl->span_end = current_.loc.offset;
            }
            mod->decls.push_back(std::move(decl));
            // Drenar los aliases extra de un typedef C-style multi-declarador.
            /// @copydoc pending_before_decls_ (mismo criterio)
            for (auto &e : pending_extra_decls_) {
                if (current_.loc.offset > decl_start_off) {
                    e->span_start = decl_start_off;
                    e->span_end = current_.loc.offset;
                }
                mod->decls.push_back(std::move(e));
            }
            pending_extra_decls_.clear();
        } else if (last_decl_was_target_skip_) {
            // L.24: skip intencional via @Target no matcheado.
            // El skip_target_skipped_decl ya consumio la decl
            // completa.  NO sincronizar (el siguiente token ya es
            // el inicio de la siguiente decl valida).
        } else {
            // El parser ya reporto el error; intentar seguir.
            synchronize();
        }
    }
    // @NoExceptions (sticky) se aplica a todo el modulo.
    mod->no_exceptions = module_no_exceptions_;
    mod->uses_conditional_target = module_uses_target_;
    mod->target_skipped = target_skipped_;
    return mod;
}

// ---------------------------------------------------------------------
// extern "lib.dll" { fn name(params) -> ret; ... }
//
// Cada `fn` se traduce a un ExternFnDecl independiente con el campo
// @c lib copiado del bloque.  El type checker los registra como
// Symbol::Function con @c FunctionSig::extern_lib = lib; el lowering
// emite @c CALLN @Method("<lib>:<name>") en vez de CALLVM.
// ---------------------------------------------------------------------
void Parser::parse_extern_block(ast::ModuleNode &mod) {
    const SourceLoc block_loc = current_.loc;
    if (expect(TokenKind::KW_EXTERN, "se esperaba 'extern'").kind ==
        TokenKind::UNKNOWN)
        return;

    if (current_.kind != TokenKind::STRING_LIT &&
        current_.kind != TokenKind::RAW_STRING_LIT) {
        error_here("se esperaba el nombre de la libreria como string literal "
                   "tras 'extern' (e.g. \"user32.dll\")");
        synchronize();
        return;
    }
    const std::string lib = current_.str_val; // sin comillas, escapes resueltos
    (void)consume();

    if (expect(TokenKind::LBRACE, "se esperaba '{' tras el nombre de libreria")
            .kind == TokenKind::UNKNOWN)
        return;

    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        // Cada fn: `[@efecto...] fn <name>(<params>) -> <ret>;`
        ast::ExternEffects fx_decl;
        parse_extern_effects_(fx_decl);
        const SourceLoc fn_loc = current_.loc;
        if (expect(TokenKind::KW_FN,
                   "se esperaba 'fn' al inicio de declaracion extern")
                .kind == TokenKind::UNKNOWN) {
            synchronize();
            continue;
        }
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba el nombre de la funcion tras 'fn'");
            synchronize();
            continue;
        }
        const std::string fn_name = current_.lexeme;
        (void)consume();

        if (expect(TokenKind::LPAREN,
                   "se esperaba '(' tras el nombre de la funcion")
                .kind == TokenKind::UNKNOWN) {
            synchronize();
            continue;
        }
        std::vector<std::unique_ptr<ast::ParamDecl>> params;
        if (current_.kind != TokenKind::RPAREN) {
            while (true) {
                // Param: `[in|out|inout] <type> [<name>]` (el nombre es
                // opcional, para parecerse a una declaracion C de cabecera).
                //
                // Aqui la direccion no es un contrato sino una DEFINICION: no
                // hay cuerpo que mirar, asi que lo unico que hay es la palabra
                // de quien lo escribe.  De ella salen las mascaras por
                // argumento de `IrNativeEffects`, que es lo que permite decir
                // "escribe lo apuntado por su primer argumento" y que el
                // analisis lo resuelva en cada sitio de llamada.
                const ParamDir p_dir = parse_opt_param_dir_();
                auto p_type = parse_type_node();
                if (!p_type) {
                    synchronize();
                    break;
                }
                auto pd = std::make_unique<ast::ParamDecl>();
                pd->loc = current_.loc;
                pd->dir = p_dir;
                pd->type = std::move(p_type);
                if (current_.kind == TokenKind::IDENTIFIER) {
                    pd->name = current_.lexeme;
                    (void)consume();
                } else {
                    // Sin nombre explicito: sintetizamos uno para que
                    // el resto del frontend (type checker, lowering)
                    // pueda referirlo.  Los externs no se ejecutan en
                    // Vesta (solo son marcas), asi que el nombre interno
                    // no aparece nunca.
                    pd->name = "__arg" + std::to_string(params.size());
                }
                params.push_back(std::move(pd));
                if (!match(TokenKind::COMMA)) break;
            }
        }
        if (expect(TokenKind::RPAREN, "se esperaba ')' tras los parametros")
                .kind == TokenKind::UNKNOWN) {
            synchronize();
            continue;
        }
        // Tipo de retorno: `-> <type>` o ausencia (= void).
        std::unique_ptr<ast::TypeNode> ret_type;
        if (match(TokenKind::ARROW)) {
            ret_type = parse_type_node();
            if (!ret_type) {
                synchronize();
                continue;
            }
        } else {
            // Sin '->': retorno void.
            auto pn = std::make_unique<ast::PrimitiveTypeNode>();
            pn->loc = fn_loc;
            pn->prim = PrimitiveKind::VOID;
            ret_type = std::move(pn);
        }
        if (expect(TokenKind::SEMICOLON, "se esperaba ';' tras la firma extern")
                .kind == TokenKind::UNKNOWN) {
            synchronize();
            continue;
        }
        auto efd = std::make_unique<ast::ExternFnDecl>();
        efd->loc = fn_loc;
        efd->lib = lib;
        efd->return_type = std::move(ret_type);
        efd->name = fn_name;
        efd->params = std::move(params);
        efd->effects = fx_decl;
        mod.decls.push_back(std::move(efd));
    }
    if (expect(TokenKind::RBRACE, "se esperaba '}' al final del bloque extern")
            .kind == TokenKind::UNKNOWN) {
        (void)block_loc;
        return;
    }
}

// ---------------------------------------------------------------------
// Top-level: distinguir entre funcion y variable global.
//
// Forma:
//   [const]? <type> <ident>  '(' params ')' '{' ... '}'    -> FunctionDecl
//   [const]? <type> <ident>  ('=' expr)? ';'               -> GlobalVarDecl
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------------
//  Contratos de huella sobre un METODO de struct/clase.
//
//  Los mismos que admite una funcion libre -- un metodo hace lo mismo con un
//  argumento mas.  Sin esto, un tipo cuya API son METODOS (`atomic<T>`, las
//  colecciones, ...) no podia declarar sus propiedades aunque el compilador
//  supiera verificarlas; y una libreria estandar que no usa los contratos que
//  el lenguaje ofrece esta diciendo lo contrario de lo que hace.
// ---------------------------------------------------------------------------
void Parser::parse_member_contracts_(MemberContracts &out) {
    while (current_.kind == TokenKind::AT) {
        // Solo se consume si el nombre ES un contrato: cualquier otra anotacion
        // (@Override, @Sync, ...) la maneja quien ya la manejaba.
        const Token &nx = lex_.peek_at(0);
        if (nx.kind != TokenKind::IDENTIFIER) return;
        // COPIA, no referencia: los `consume()` de abajo invalidan el token
        // peekeado, y las ramas que eligen por el nombre corren despues.
        const std::string nm = nx.lexeme;
        const bool es_flag =
            (nm == "pure" || nm == "nothrow" || nm == "nopanic");
        const bool es_num = (nm == "alloc" || nm == "stack");
        const bool es_cx = (nm == "complexity");
        if (!es_flag && !es_num && !es_cx) return;
        (void)consume(); // '@'
        (void)consume(); // el nombre
        out.any = true;
        if (es_flag) {
            // Flag con `when:` opcional (`@pure(when: arch:x86_64)`).  Con when
            // a la lista pending; sin when al campo directo (el default).
            if (current_.kind == TokenKind::LPAREN) {
                (void)consume(); // '('
                ast::PendingFootprint pf;
                pf.when = read_footprint_when_();
                if (nm == "pure")
                    pf.pure = 1;
                else if (nm == "nothrow")
                    pf.nothrow_ = 1;
                else
                    pf.nopanic = 1;
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras el `when:`");
                out.footprint_pending.push_back(std::move(pf));
            } else if (nm == "pure") {
                out.pure = true;
            } else if (nm == "nothrow") {
                out.nothrow_ = true;
            } else {
                out.nopanic = true;
            }
        } else if (es_num) {
            const std::string abre =
                "se esperaba '(' tras @" + nm + " (usa @" + nm + "(N))";
            (void)expect(TokenKind::LPAREN, abre.c_str());
            const FootprintDims d = parse_footprint_dims_(nm);
            const std::string cierra = "se esperaba ')' al cerrar @" + nm;
            (void)expect(TokenKind::RPAREN, cierra.c_str());
            const bool es_alloc = (nm == "alloc");
            if (d.when.empty()) {
                if (d.total >= 0) (es_alloc ? out.alloc : out.stack) = d.total;
                if (d.partial >= 0)
                    (es_alloc ? out.alloc_partial : out.stack_partial) =
                        d.partial;
            } else {
                ast::PendingFootprint pf;
                pf.when = d.when;
                if (es_alloc) {
                    pf.alloc = d.total;
                    pf.alloc_partial = d.partial;
                } else {
                    pf.stack = d.total;
                    pf.stack_partial = d.partial;
                }
                out.footprint_pending.push_back(std::move(pf));
            }
        } else {
            // TODOS los @complexity van a la lista, tambien el que no lleva
            // `when:` -- resolver aqui el primero y dejar que el siguiente lo
            // pise es lo que hacia que ganase el ultimo TEXTUALMENTE.  Se
            // resuelven todos juntos y por especificidad cuando se conoce el
            // ultimo, que para un generico es al monomorphizar.
            ast::PendingComplexity pc;
            bool aplica = true;
            parse_complexity_args_(pc.expr, pc.vars, pc.partial_pre,
                                   pc.partial_post, pc.total_pre, pc.total_post,
                                   &pc.when, &aplica);
            if (aplica) out.pending.push_back(std::move(pc));
        }
    }
}

void Parser::apply_member_contracts_(const MemberContracts &mc,
                                     ast::ClassMethodDecl &m) {
    if (!mc.any) return;
    m.contract_pure = mc.pure;
    m.contract_nothrow = mc.nothrow_;
    m.contract_nopanic = mc.nopanic;
    m.contract_alloc = mc.alloc;
    m.contract_alloc_partial = mc.alloc_partial;
    m.contract_stack = mc.stack;
    m.contract_stack_partial = mc.stack_partial;
    // Los @complexity van sin resolver: hay que verlos TODOS a la vez para
    // aplicar la prioridad por especificidad, y para un metodo generico el
    // ultimo dato (T) no llega hasta la monomorphizacion.  Los campos resueltos
    // los rellena el type checker.
    m.complexity_pending = mc.pending;
    m.footprint_pending = mc.footprint_pending;
}

// ---------------------------------------------------------------------------
//  @complexity(...): parseo compartido.
//
//  Extraido del bucle de anotaciones top-level para que lo usen TAMBIEN los
//  metodos de struct/clase: es el mismo contrato sobre lo mismo, y duplicar 100
//  lineas de troceado de texto para decir eso seria pedir que se separen.
//  Se entra con el token de `complexity` ya consumido (el siguiente debe ser
//  '('), y se sale tras el ')' de cierre.
//
//  Campo `when: <expr>` -- contrato CONDICIONAL.  El coste TOTAL de una
//  funcion depende del target cuando algun callee tiene cuerpos por-arch de
//  coste distinto: `atomic<T>::exchange` llama a `atomic_swap64`, que en
//  x86-64 es un bucle CAS escrito en Vesta (O(n)) y en arm64 el LL/SC nativo
//  (O(1)).  Sin `when:` no habria ningun valor declarable correcto en las dos.
//  La expresion es la MISMA de @Target (os/arch/cpu/semver/mode con &&/||/! y
//  parentesis) y la evalua el MISMO `target_matches_`, asi que hereda gratis
//  todo lo que @Target soporte hoy y manana.  Como @Target se resuelve al
//  compilar (el target ya se conoce aqui), un `when:` que no case DESCARTA la
//  anotacion en el sitio: aguas abajo (AST, huella, verificador) todo sigue
//  viendo un solo contrato, el que aplica.  Sin `when:` -> aplica siempre.
// ---------------------------------------------------------------------------
Parser::FootprintDims Parser::parse_footprint_dims_(const std::string &nm) {
    // Se entra TRAS el `(`; se sale con current_ en el `)` (el caller lo
    // cierra).
    FootprintDims d;
    auto leer_int = [&](const char *que) -> int64_t {
        if (current_.kind != TokenKind::INT_LIT) {
            error_here((std::string("@") + nm + ": " + que +
                        " requiere un entero literal")
                           .c_str());
            return -1;
        }
        const int64_t v = static_cast<int64_t>(consume().int_val);
        if (v < 0) {
            error_here((std::string("@") + nm + ": N debe ser >= 0").c_str());
            return -1;
        }
        return v;
    };
    // Forma corta: un entero suelto -> TOTAL (el peor caso que importa fuera).
    if (current_.kind == TokenKind::INT_LIT) {
        d.total = leer_int("N");
    } else {
        // Forma nombrada: uno o mas `partial: N` / `total: N` por coma.
        while (current_.kind == TokenKind::IDENTIFIER &&
               (current_.lexeme == "partial" || current_.lexeme == "total")) {
            const std::string campo = current_.lexeme;
            (void)consume(); // 'partial'/'total'
            (void)expect(
                TokenKind::COLON,
                (std::string("se esperaba ':' tras '") + campo + "' en @" + nm)
                    .c_str());
            const int64_t v = leer_int(campo.c_str());
            if (campo == "partial")
                d.partial = v;
            else
                d.total = v;
            if (current_.kind == TokenKind::COMMA) {
                // Puede ser separador entre dims O el inicio del `when:`.  Si
                // lo que sigue NO es otra dim, se deja la coma para el `when:`.
                // Peek: consumir la coma solo si tras ella hay otra dim.
                (void)consume(); // ','
            } else {
                break;
            }
        }
    }
    // `when:` opcional (tras una coma ya consumida en la forma nombrada, o una
    // coma nueva en la forma corta).
    if (current_.kind == TokenKind::COMMA) {
        (void)consume(); // ','
        d.when = read_footprint_when_();
    } else if (current_.kind == TokenKind::IDENTIFIER &&
               current_.lexeme == "when") {
        d.when = read_footprint_when_();
    }
    if (d.partial < 0 && d.total < 0)
        error_here(
            (std::string("@") + nm +
             ": declara al menos una dimension (N, partial: N o total: N)")
                .c_str());
    return d;
}

std::string Parser::read_footprint_when_() {
    // current_ debe ser el identificador `when`.
    if (current_.kind != TokenKind::IDENTIFIER || current_.lexeme != "when") {
        error_here("se esperaba `when:` en el contrato de huella");
        return std::string();
    }
    (void)consume(); // when
    if (expect(TokenKind::COLON, "se esperaba ':' tras `when`").kind !=
        TokenKind::COLON)
        return std::string();
    // El valor va SIN comillas, como en @complexity (para que un editor lo vea
    // como expresion y no como cadena).
    if (current_.kind == TokenKind::STRING_LIT) {
        error_here("el `when:` va SIN comillas (when: arch:arm64)");
    }
    const std::string &src = lex_.source_buffer();
    const uint32_t start = current_.loc.offset;
    uint32_t end = start;
    int depth = 0;
    while (current_.kind != TokenKind::END_OF_FILE) {
        if (current_.kind == TokenKind::LPAREN) {
            ++depth;
        } else if (current_.kind == TokenKind::RPAREN) {
            if (depth == 0) {
                end = current_.loc.offset;
                break; // NO se consume: lo cierra el caller
            }
            --depth;
        }
        (void)consume();
    }
    std::string spec =
        (start <= src.size() && end >= start && end <= src.size())
            ? src.substr(start, end - start)
            : std::string();
    const size_t a = spec.find_first_not_of(" \t\r\n");
    const size_t b = spec.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return std::string();
    return spec.substr(a, b - a + 1);
}

void Parser::parse_complexity_args_(
    std::string &top_complexity_expr,
    std::vector<std::string> &top_complexity_vars,
    std::string &top_complexity_partial_pre,
    std::string &top_complexity_partial_post,
    std::string &top_complexity_total_pre,
    std::string &top_complexity_total_post, std::string *out_when,
    bool *out_aplica) {
    if (out_aplica) *out_aplica = true;
    if (current_.kind != TokenKind::LPAREN) {
        error_here("@complexity requiere '(O(...))'");
    } else {
        (void)consume(); // '('
        const std::string &csrc = lex_.source_buffer();
        const uint32_t cstart = current_.loc.offset;
        uint32_t cend = cstart;
        int pdepth = 1;
        while (current_.kind != TokenKind::END_OF_FILE) {
            if (current_.kind == TokenKind::LPAREN) {
                ++pdepth;
            } else if (current_.kind == TokenKind::RPAREN) {
                if (--pdepth == 0) {
                    cend = current_.loc.offset;
                    (void)consume(); // ')' de cierre
                    break;
                }
            }
            (void)consume();
        }
        if (pdepth != 0) {
            error_here("se esperaba ')' al cerrar @complexity(...)");
        } else if (cstart <= csrc.size() && cend >= cstart &&
                   cend <= csrc.size()) {
            std::string raw = csrc.substr(cstart, cend - cstart);
            auto trim = [](std::string s) {
                size_t a = s.find_first_not_of(" \t\r\n");
                size_t b = s.find_last_not_of(" \t\r\n");
                if (a == std::string::npos) return std::string();
                return s.substr(a, b - a + 1);
            };
            // Partir TODO el contenido por comas de NIVEL SUPERIOR
            // (las comas dentro de O(...) -- p.ej. O(n, m) -- no
            // cuentan).  Cada segmento es uno de:
            //   - "dimension: O(...)" -> contrato por dimension
            //     (partial_pre/partial_post/total_pre/total_post);
            //   - "var = <expr>"      -> binding de tamano de input;
            //   - "O(...)" posicional -> azucar de total_post (1ra).
            std::vector<std::string> segs;
            {
                int d = 0;
                size_t seg = 0;
                for (size_t k = 0; k <= raw.size(); ++k) {
                    char c = (k < raw.size()) ? raw[k] : ',';
                    if (c == '(')
                        ++d;
                    else if (c == ')')
                        --d;
                    else if (c == ',' && d == 0) {
                        std::string s = trim(raw.substr(seg, k - seg));
                        if (!s.empty()) segs.push_back(s);
                        seg = k + 1;
                    }
                }
            }
            // Helper: localizar el ':' de nivel superior (separador
            // del nombre de dimension), ignorando los ':' que
            // pudieran aparecer dentro de O(...).
            auto top_colon = [](const std::string &s) -> size_t {
                int d = 0;
                for (size_t k = 0; k < s.size(); ++k) {
                    char c = s[k];
                    if (c == '(')
                        ++d;
                    else if (c == ')')
                        --d;
                    else if (c == ':' && d == 0)
                        return k;
                }
                return std::string::npos;
            };
            // Primera pasada: el `when:`.  Se mira ANTES de asignar
            // nada porque decide si esta anotacion aplica siquiera,
            // y el campo puede venir en cualquier posicion.
            bool aplica = true;
            for (const std::string &s : segs) {
                size_t col = top_colon(s);
                if (col == std::string::npos) continue;
                if (trim(s.substr(0, col)) != "when") continue;
                std::string spec = trim(s.substr(col + 1));
                // SIN comillas: entrecomillado, un IDE lo ve como
                // una cadena y no puede completar ni validar los
                // atomos.  El troceo lo permite sin ambiguedad
                // porque el separador del campo es el PRIMER ':' de
                // nivel superior: `when: arch:x86_64` da clave
                // `when` y valor `arch:x86_64`.
                if (spec.size() >= 2 && spec.front() == '"') {
                    error_here("@complexity: el `when:` va SIN "
                               "comillas (when: arch:arm64)");
                }
                if (out_when) *out_when = spec;
                if (!cwhen::only_target(spec)) {
                    // Habla del parametro de tipo: aqui T aun no es
                    // nada.  Se deja SIN evaluar; lo resuelve el
                    // clon de la monomorphizacion.
                    if (!out_when) {
                        error_here("@complexity: el `when:` solo puede "
                                   "hablar del parametro de tipo "
                                   "(is_float<T>(), sizeof<T>()...) en un "
                                   "metodo de un tipo generico");
                        return;
                    }
                    continue;
                }
                // Solo target: se puede decidir ya si el contrato
                // es de esta compilacion.  El que NO casa se tira;
                // el que casa SOBREVIVE con su `when:` intacto,
                // porque hara falta para compararlo por
                // especificidad con los otros que tambien casen.
                if (!target_matches_(spec)) aplica = false;
            }
            // Contrato de otro target: fuera.  (Un `when:` sobre T
            // no llega aqui con aplica=false: no se evalua.)
            if (!aplica) {
                if (out_aplica) *out_aplica = false;
                return;
            }

            bool got_positional = false;
            for (const std::string &s : segs) {
                size_t col = top_colon(s);
                if (col != std::string::npos) {
                    // Campo nombrado "dimension: O(...)".
                    std::string key = trim(s.substr(0, col));
                    std::string val = trim(s.substr(col + 1));
                    if (key == "when")
                        continue; // ya tratado en la pasada de arriba
                    if (key == "partial_pre")
                        top_complexity_partial_pre = val;
                    else if (key == "partial_post")
                        top_complexity_partial_post = val;
                    else if (key == "total_pre")
                        top_complexity_total_pre = val;
                    else if (key == "total_post")
                        top_complexity_total_post = val;
                    else
                        error_here(("@complexity: campo desconocido "
                                    "'" +
                                    key +
                                    "' (dimensiones: "
                                    "partial_pre, partial_post, total_pre, "
                                    "total_post; condicion: when)")
                                       .c_str());
                    continue;
                }
                // Sin ':' -> binding "var = ..." o expr posicional.
                if (s.find('=') != std::string::npos) {
                    top_complexity_vars.push_back(s);
                } else if (!got_positional) {
                    // Primera expr posicional = azucar de total_post.
                    top_complexity_expr = s;
                    got_positional = true;
                } else {
                    error_here("@complexity: expresion posicional "
                               "duplicada (solo se admite una; usa los "
                               "campos nombrados para las 4 dimensiones)");
                }
            }
        }
    }
}

std::unique_ptr<ast::Node> Parser::parse_top_level_decl() {
    // namespace foo { ... }  ( M.7.c, inline namespace estilo C++).
    if (current_.kind == TokenKind::KW_NAMESPACE) {
        return parse_namespace_decl();
    }
    // import "path" [as alias] [only A, B];  ( M sistema de modulos).
    if (current_.kind == TokenKind::KW_IMPORT) {
        return parse_import_decl(/*is_public_reexport=*/false);
    }
    // public import "x";  (re-export transitivo).
    if (current_.kind == TokenKind::KW_PUBLIC &&
        lex_.peek_at(0).kind == TokenKind::KW_IMPORT) {
        (void)consume(); // 'public'
        return parse_import_decl(/*is_public_reexport=*/true);
    }
    //  M6.a L.3: visibilidad de top-level decl.  Capturamos
    // `public`/`private` y guardamos en pending_visibility_; cada
    // sub-parser que produzca un decl top-level consulta el flag al
    // final (helper @c apply_pending_visibility_) y lo limpia.  Sin
    // keyword: el nodo conserva su default (is_public=true) -- compat
    // con codigo existente.  Un futuro sprint M.future flipeara el
    // default a privado tras migrar stdlib + editor.
    if (current_.kind == TokenKind::KW_PUBLIC) {
        (void)consume();
        pending_visibility_ = 1; // 1 = public explicito
    } else if (current_.kind == TokenKind::KW_PRIVATE) {
        (void)consume();
        pending_visibility_ = 2; // 2 = private explicito
    } else if (current_.kind == TokenKind::IDENTIFIER &&
               current_.lexeme == "internal") {
        //  NS.3: `internal` (keyword contextual) -- package-scoped.
        (void)consume();
        pending_visibility_ = 3; // 3 = internal explicito
    }
    /* `final class C { ... }`: la clase no se puede extender.  Se recoge aqui
     * -- como la visibilidad -- porque el modificador va DELANTE de la palabra
     * `class`, igual que en Java y en C#, y quien parsea la clase ya empieza en
     * la palabra `class`.  El orden con la visibilidad da igual: `public final
     * class` y `final public class` son lo mismo. */
    if (current_.kind == TokenKind::KW_FINAL) {
        (void)consume();
        pending_final_ = true;
        if (current_.kind == TokenKind::KW_PUBLIC) {
            (void)consume();
            pending_visibility_ = 1;
        } else if (current_.kind == TokenKind::KW_PRIVATE) {
            (void)consume();
            pending_visibility_ = 2;
        }
    }
    // Cleanup garantizado al salir de parse_top_level_decl.
    struct VisGuard {
        uint8_t &flag;
        bool &fin;

        ~VisGuard() {
            flag = 0;
            fin = false;
        }
    } guard{pending_visibility_, pending_final_};
    // concept Name<T> = pred; | { ... }  (#6, keyword contextual).  Se exige
    // que tras `concept` venga un identificador (el nombre) para no chocar con
    // un hipotetico uso de `concept` como identificador normal.
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "concept" &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
        auto n = parse_concept_decl();
        apply_pending_visibility(n.get());
        return n;
    }
    /* `extension Tipo { ... }` fue una segunda forma de anadir metodos a un
     * tipo, y se retiro: hacia exactamente lo que hace `impl Tipo { ... }`.
     * Tener dos palabras para lo mismo no es dar opciones, es partir en dos
     * todo lo que hay detras -- resolucion, comprobacion, bajada -- y que una
     * de las dos mitades se quede corta sin que nadie lo note. */
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "extension" &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
        error_here("'extension' ya no existe: usa 'impl Tipo { ... }' para "
                   "anadir metodos, o 'impl Concepto for Tipo { ... }' si "
                   "ademas quieres declarar que lo cumple");
        return nullptr;
    }
    // NS.6-ext: impl Concept for Tipo { ... }  (keyword contextual).
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "impl" &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
        auto n = parse_impl_decl();
        apply_pending_visibility(n.get());
        return n;
    }
    // typedef <tipo> <nombre> ;
    if (current_.kind == TokenKind::KW_TYPEDEF) {
        // typedef struct/enum C-style.
        // Si tras typedef viene `struct` o `enum`, parseamos como
        // StructDecl/EnumDecl con name al final.  Sin esto solo se
        // soportaba `typedef i32 Foo;` (alias de tipo basico).
        const TokenKind nk = lex_.peek_at(0).kind;
        if (nk == TokenKind::KW_STRUCT || nk == TokenKind::KW_ENUM ||
            nk == TokenKind::KW_UNION) {
            auto n = parse_typedef_struct_or_enum();
            apply_pending_visibility(n.get());
            return n;
        }
        auto n = parse_typedef_decl();
        apply_pending_visibility(n.get());
        return n;
    }
    // using <nombre> = <tipo> ;
    if (current_.kind == TokenKind::KW_USING) {
        auto n = parse_using_decl();
        apply_pending_visibility(n.get());
        return n;
    }
    // Anotaciones top-level que preceden a una clase o funcion:
    //   @Aspect:     clase de aspectos
    //   @Async:      funcion async, transformada a wrapper future + spawn
    //   @Introspect: clase/struct/enum runtime-introspectable (Sprint 4
    //   A.37.s4)
    //   @Target("os:linux"):  M.L24 - compilacion condicional;
    //                la decl se descarta si no matchea el target actual.
    //   Otras se aceptan y se ignoran silenciosamente.
    bool top_is_final = false;
    bool top_is_aspect = false;
    bool top_is_async = false;
    bool top_fp_contract =
        true; /* @fp(strict|fast): default fast (contrae FMA) */
    bool top_is_alloc_override = false; /* AOT.2.d: @AllocatorOverride */
    bool top_is_panic_handler = false;  /* AOT.2.d: @PanicHandler */
    bool top_is_naked = false;          /*  NR: @Naked (ISRs/stubs) */
    bool top_is_no_idiom = false; /* @NoIdiom: sin reconocimiento de idiomas */
    bool top_is_noexcept = false; /* @NoExcept: fn sin excepciones */
    bool top_is_string_concat = false; /* C-3: @StringConcat */
    bool top_is_string_eq = false;     /* C-3: @StringEq */
    bool top_is_sync_impl = false;     /* @SyncImpl: override de monitor */
    /* CPU dispatch Inc 4: @HelperOverride(<helper>).  Guarda el nombre del
       helper objetivo (hoy "memcpy"); vacio => no es override. */
    std::string top_helper_override_target;
    bool top_is_introspect = false;
    bool top_is_abstract =
        false; /* @Abstract struct: no instanciable, solo base */
    bool top_is_overlay = false;  /* overlay F1: @overlay struct (vista) */
    bool top_is_macro = false;    /* A.43.16: @Macro */
    bool top_is_pure = false;     /* A.43.20: @Pure -- memoizable */
    bool top_target_skip = false; /* L.24: @Target no matchea */
    /* Variante por modo de ejecucion: 0 ninguna, 1 para el JIT, 2 para el
     * interprete.  No descarta la decl -- las dos viajan en el `.velb`. */
    int top_mode_variant = 0;
    std::string top_target_spec; /* la condicion que no se cumplio */
    // Subsistema de coste (modo --analyze): @complexity(O(...)[, n=...]).
    std::string top_complexity_expr;              // expr de coste normalizada
    std::vector<std::string> top_complexity_vars; // bindings `n = <expr>`
    // Contratos por dimension PARCIAL/TOTAL x PRE/POST (campos nombrados).
    std::string top_complexity_partial_pre;
    std::string top_complexity_partial_post;
    std::string top_complexity_total_pre;
    std::string top_complexity_total_post;
    // TODOS los @complexity de la funcion, sin resolver: hay que verlos juntos
    // para la regla de prioridad (por especificidad), igual que en los metodos.
    // Sin esto ganaba el ultimo textualmente tambien en las funciones libres.
    std::vector<ast::PendingComplexity> top_complexity_pending;
    // Sprint lombok (2026-06-03): anotaciones tipo Lombok a nivel
    // de clase.  El TypeChecker pre-pase las consume y genera
    // ClassMethodDecls sinteticos (getters, setters, toString, etc.).
    bool top_lk_getter = false;
    bool top_lk_setter = false;
    bool top_lk_tostring = false;
    bool top_lk_equals_hash = false;
    bool top_lk_no_args_ctor = false;
    bool top_lk_all_args_ctor = false;
    bool top_lk_required_ctor = false;
    bool top_lk_data = false;
    bool top_lk_value = false;
    bool top_lk_builder = false;
    bool top_lk_with_all = false;
    bool top_lk_log = false;
    bool top_lk_sync_methods = false;
    // v4: atributos para comptime const a nivel modulo.
    bool top_attr_hot = false;
    bool top_attr_cold = false;
    uint16_t top_attr_align = 0;
    // Contratos comprobables de recurso/efecto (huella computacional).
    bool top_c_pure = false, top_c_nothrow = false, top_c_nopanic = false;
    // Contratos de huella CON `when:` (por arch/os/T): se resuelven aparte, por
    // especificidad, en el type checker.  Los SIN when siguen en los campos de
    // arriba (el default).
    std::vector<ast::PendingFootprint> top_footprint_pending;
    int64_t top_c_alloc = -1, top_c_stack = -1;
    int64_t top_c_alloc_partial = -1, top_c_stack_partial = -1;
    // Contratos de TIPO (struct/clase/enum): @pod / @no_heap / @size(N).
    bool top_t_pod = false, top_t_no_heap = false;
    int64_t top_t_size = -1;
    std::string top_attr_section;
    std::string top_attr_section_perms;  // AOT 2b: @section(".x","rwx")
    int64_t top_attr_at = -1;            // AOT: @at(N) offset/VA fijo (.bin)
    int32_t top_attr_order = 0x7fffffff; // AOT: @order(N) orden de seccion
    uint8_t top_attr_bits = 64; // AOT: @bits(16|32|64) para bloques asm
    while (current_.kind == TokenKind::AT) {
        (void)consume();
        if (current_.kind == TokenKind::IDENTIFIER) {
            const bool is_target = (current_.lexeme == "Target");
            if (current_.lexeme == "Final")
                top_is_final = true;
            else if (current_.lexeme == "Aspect")
                top_is_aspect = true;
            else if (current_.lexeme == "Async")
                top_is_async = true;
            else if (current_.lexeme == "Introspect")
                top_is_introspect = true;
            else if (current_.lexeme == "Abstract")
                top_is_abstract = true;
            else if (current_.lexeme == "overlay")
                top_is_overlay = true;
            else if (current_.lexeme == "Macro")
                top_is_macro = true;
            else if (current_.lexeme == "Pure")
                top_is_pure = true;
            else if (current_.lexeme == "AllocatorOverride")
                top_is_alloc_override = true;
            else if (current_.lexeme == "PanicHandler")
                top_is_panic_handler = true;
            else if (current_.lexeme == "Naked")
                top_is_naked = true;
            else if (current_.lexeme == "NoIdiom")
                top_is_no_idiom = true;
            else if (current_.lexeme == "NoExcept")
                top_is_noexcept = true;
            else if (current_.lexeme == "NoExceptions")
                module_no_exceptions_ = true; // sticky: modulo entero
            else if (current_.lexeme == "StringConcat")
                top_is_string_concat = true;
            else if (current_.lexeme == "StringEq")
                top_is_string_eq = true;
            else if (current_.lexeme == "SyncImpl")
                top_is_sync_impl = true;
            // Sprint lombok (2026-06-03): anotaciones class-level.
            // El parser solo marca los flags; el pre-pase del
            // TypeChecker (expand_lombok_annotations) genera los
            // ClassMethodDecls correspondientes.  Combos: @Data y
            // @Value se descomponen en sus partes en el pre-pase.
            else if (current_.lexeme == "Getter")
                top_lk_getter = true;
            else if (current_.lexeme == "Setter")
                top_lk_setter = true;
            else if (current_.lexeme == "ToString")
                top_lk_tostring = true;
            else if (current_.lexeme == "EqualsAndHashCode")
                top_lk_equals_hash = true;
            else if (current_.lexeme == "NoArgsConstructor")
                top_lk_no_args_ctor = true;
            else if (current_.lexeme == "AllArgsConstructor")
                top_lk_all_args_ctor = true;
            else if (current_.lexeme == "RequiredArgsConstructor")
                top_lk_required_ctor = true;
            else if (current_.lexeme == "Data")
                top_lk_data = true;
            else if (current_.lexeme == "Value")
                top_lk_value = true;
            else if (current_.lexeme == "Builder")
                top_lk_builder = true;
            else if (current_.lexeme == "With")
                top_lk_with_all = true;
            else if (current_.lexeme == "Log")
                top_lk_log = true;
            else if (current_.lexeme == "Synchronized")
                top_lk_sync_methods = true;
            // v4: atributos para comptime const.
            const bool is_align = (current_.lexeme == "align");
            const bool is_hot = (current_.lexeme == "hot");
            const bool is_cold = (current_.lexeme == "cold");
            const bool is_fp = (current_.lexeme == "fp");
            const bool is_section = (current_.lexeme == "section");
            const bool is_at = (current_.lexeme == "at");
            const bool is_order = (current_.lexeme == "order");
            const bool is_bits = (current_.lexeme == "bits");
            const bool is_complexity = (current_.lexeme == "complexity");
            // Contratos de huella (recurso/efecto): flags + con-arg.
            const bool is_c_pure = (current_.lexeme == "pure");
            const bool is_c_nothrow = (current_.lexeme == "nothrow");
            const bool is_c_nopanic = (current_.lexeme == "nopanic");
            const bool is_c_alloc = (current_.lexeme == "alloc");
            const bool is_c_stack = (current_.lexeme == "stack");
            // Contratos de TIPO (layout/recurso): flags @pod/@no_heap +
            // @size(N).
            const bool is_t_pod = (current_.lexeme == "pod");
            const bool is_t_no_heap = (current_.lexeme == "no_heap");
            const bool is_t_size = (current_.lexeme == "size");
            // CPU dispatch Inc 4: @HelperOverride(<helper>).
            const bool is_helper_override =
                (current_.lexeme == "HelperOverride");
            (void)consume();
            // @complexity(O(...)[, n = <expr>]): contrato de coste para el
            // modo --analyze.  Se captura el texto RAW entre los parens y se
            // parte por la primera coma (la sub-expr de coste va antes; los
            // bindings `var = ...` despues).  Metadata pura: el codegen la
            // ignora.  Tolerante a errores: si falta '(' se omite sin abortar.
            if (is_complexity) {
                // A la lista, tambien el que no lleva `when:`: resolver el
                // primero al vuelo y dejar que el siguiente lo pise es lo que
                // hacia ganar al ultimo textualmente.  Los de una funcion libre
                // no tienen T, asi que todos sus atomos son de target; el
                // type checker los resuelve por especificidad.
                ast::PendingComplexity pc;
                bool aplica = true;
                parse_complexity_args_(pc.expr, pc.vars, pc.partial_pre,
                                       pc.partial_post, pc.total_pre,
                                       pc.total_post, &pc.when, &aplica);
                if (aplica) top_complexity_pending.push_back(std::move(pc));
                continue;
            }
            if (is_hot) {
                top_attr_hot = true;
                continue;
            }
            if (is_cold) {
                top_attr_cold = true;
                continue;
            }
            // @fp(strict|fast): politica de contraccion FMA por-funcion.
            // strict -> IEEE (2 redondeos, sin FMA); fast (default) -> contrae.
            if (is_fp) {
                if (current_.kind == TokenKind::LPAREN) {
                    (void)consume(); // '('
                    if (current_.lexeme == "strict")
                        top_fp_contract = false;
                    else if (current_.lexeme == "fast")
                        top_fp_contract = true;
                    (void)consume(); // strict|fast
                    if (current_.kind == TokenKind::RPAREN)
                        (void)consume(); // ')'
                }
                continue;
            }
            // Contratos de huella: flags, con `when:` opcional
            // (`@pure(when: arch:x86_64)`).  Con when -> a la lista pending;
            // sin when -> el campo directo (el default).
            if (is_c_pure || is_c_nothrow || is_c_nopanic) {
                const int8_t v_pure = is_c_pure ? 1 : -1;
                const int8_t v_nothrow = is_c_nothrow ? 1 : -1;
                const int8_t v_nopanic = is_c_nopanic ? 1 : -1;
                if (current_.kind == TokenKind::LPAREN) {
                    (void)consume(); // '('
                    ast::PendingFootprint pf;
                    pf.when = read_footprint_when_();
                    pf.pure = v_pure;
                    pf.nothrow_ = v_nothrow;
                    pf.nopanic = v_nopanic;
                    (void)expect(TokenKind::RPAREN,
                                 "se esperaba ')' tras el `when:`");
                    top_footprint_pending.push_back(std::move(pf));
                } else {
                    top_c_pure = top_c_pure || is_c_pure;
                    top_c_nothrow = top_c_nothrow || is_c_nothrow;
                    top_c_nopanic = top_c_nopanic || is_c_nopanic;
                }
                continue;
            }
            // Contratos de TIPO sin argumento: @pod / @no_heap.
            if (is_t_pod) {
                top_t_pod = true;
                continue;
            }
            if (is_t_no_heap) {
                top_t_no_heap = true;
                continue;
            }
            // Contrato de TIPO con argumento entero: @size(N) (tamano exacto).
            if (is_t_size) {
                (void)expect(TokenKind::LPAREN, "se esperaba '(' tras @size");
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here("@size(N) requiere un entero literal");
                } else {
                    const int64_t n = current_.int_val;
                    (void)consume();
                    if (n < 0) {
                        error_here("@size(N): N debe ser >= 0");
                    } else {
                        top_t_size = n;
                    }
                }
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras N en @size(N)");
                continue;
            }
            // Contratos con argumento entero: @alloc(N) / @stack(N), con un
            // `when:` opcional tras el N (`@alloc(0, when: arch:x86_64)`).
            if (is_c_alloc || is_c_stack) {
                const std::string nm = is_c_alloc ? "alloc" : "stack";
                (void)expect(TokenKind::LPAREN,
                             is_c_alloc ? "se esperaba '(' tras @alloc"
                                        : "se esperaba '(' tras @stack");
                const FootprintDims d = parse_footprint_dims_(nm);
                (void)expect(TokenKind::RPAREN,
                             ("se esperaba ')' al cerrar @" + nm).c_str());
                if (d.when.empty()) {
                    if (d.total >= 0)
                        (is_c_alloc ? top_c_alloc : top_c_stack) = d.total;
                    if (d.partial >= 0)
                        (is_c_alloc ? top_c_alloc_partial
                                    : top_c_stack_partial) = d.partial;
                } else {
                    ast::PendingFootprint pf;
                    pf.when = d.when;
                    if (is_c_alloc) {
                        pf.alloc = d.total;
                        pf.alloc_partial = d.partial;
                    } else {
                        pf.stack = d.total;
                        pf.stack_partial = d.partial;
                    }
                    top_footprint_pending.push_back(std::move(pf));
                }
                continue;
            }
            if (is_align) {
                (void)expect(TokenKind::LPAREN, "se esperaba '(' tras @align");
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here("@align(N) requiere un entero literal");
                } else {
                    const int64_t n = current_.int_val;
                    (void)consume();
                    if (n <= 0 || n > 4096 || (n & (n - 1)) != 0) {
                        error_here(
                            "@align(N): N debe ser potencia de 2 en [1,4096]");
                    } else {
                        top_attr_align = static_cast<uint16_t>(n);
                    }
                }
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras N en @align(N)");
                continue;
            }
            if (is_section) {
                (void)expect(TokenKind::LPAREN,
                             "se esperaba '(' tras @section");
                if (current_.kind != TokenKind::STRING_LIT) {
                    error_here("@section requiere un string literal");
                } else {
                    top_attr_section = current_.str_val;
                    (void)consume();
                    // AOT 2b: 2do string opcional = permisos "rwx" (dev OS).
                    if (current_.kind == TokenKind::COMMA) {
                        (void)consume();
                        if (current_.kind != TokenKind::STRING_LIT) {
                            error_here("@section: el 2do argumento (permisos) "
                                       "debe ser un string literal \"rwx\"");
                        } else {
                            top_attr_section_perms = current_.str_val;
                            (void)consume();
                        }
                    }
                }
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras @section");
                continue;
            }
            if (is_at) {
                // @at(N): offset/VA fijo de la seccion en la imagen (AOT .bin).
                (void)expect(TokenKind::LPAREN, "se esperaba '(' tras @at");
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here("@at requiere un offset entero");
                } else {
                    top_attr_at = (int64_t)current_.int_val;
                    (void)consume();
                }
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras N en @at(N)");
                continue;
            }
            if (is_order) {
                // @order(N): orden relativo de la seccion en la imagen.
                (void)expect(TokenKind::LPAREN, "se esperaba '(' tras @order");
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here("@order requiere un entero");
                } else {
                    top_attr_order = (int32_t)current_.int_val;
                    (void)consume();
                }
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras N en @order(N)");
                continue;
            }
            if (is_bits) {
                // @bits(16|32|64): bitness de un bloque `asm` (Keystone).
                (void)expect(TokenKind::LPAREN, "se esperaba '(' tras @bits");
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here("@bits requiere 16, 32 o 64");
                } else {
                    const uint64_t b = current_.int_val;
                    if (b != 16 && b != 32 && b != 64)
                        error_here("@bits solo admite 16, 32 o 64");
                    else
                        top_attr_bits = (uint8_t)b;
                    (void)consume();
                }
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras N en @bits(N)");
                continue;
            }
            if (is_helper_override) {
                // @HelperOverride(<helper>): el usuario reemplaza el helper
                // multi-versionado del build (hoy "memcpy").  El argumento es
                // un identificador (no string) por consistencia con el nombre
                // del helper.  Disenado para escalar a strcmp/strlen/itoa.
                (void)expect(TokenKind::LPAREN,
                             "se esperaba '(' tras @HelperOverride");
                if (current_.kind != TokenKind::IDENTIFIER) {
                    error_here("@HelperOverride(<helper>) requiere el nombre "
                               "del helper (p.ej. memcpy)");
                } else {
                    top_helper_override_target = current_.lexeme;
                    (void)consume();
                }
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras el helper en "
                             "@HelperOverride(...)");
                continue;
            }
            if (is_target) {
                // Lo que este modulo declara depende del objetivo, asi que su
                // `.vxi` no puede compartirse entre targets (lo ata el emisor
                // via VxiHeader::target_offset).  Se marca ANTES de evaluar la
                // condicion a proposito: el modulo depende del objetivo tanto
                // si la variante casa como si no.
                module_uses_target_ = true;
                // L.24: @Target("os:linux"|"arch:x86_64"|...).  Si la
                // condicion NO matchea con los build tags actuales,
                // marcamos top_target_skip para descartar la decl.
                (void)expect(TokenKind::LPAREN, "se esperaba '(' tras @Target");
                std::string spec;
                if (current_.kind == TokenKind::STRING_LIT) {
                    spec = current_.str_val;
                    (void)consume();
                } else {
                    error_here("@Target requiere un string literal");
                }
                (void)expect(TokenKind::RPAREN, "se esperaba ')' tras @Target");
                // `mode:jit` / `mode:vm` SI condicionan, pero no descartando:
                // el mismo `.velb` sirve al interprete y al JIT, asi que las
                // DOS variantes viajan dentro y se elige al ejecutar.  La de
                // VM conserva el nombre; la de JIT sale con sufijo, y el JIT
                // la sustituye al compilar la funcion.
                {
                    std::vector<std::string> ats;
                    cwhen::atoms(spec, ats);
                    for (const auto &a : ats) {
                        // Un valor de `mode` que nadie conoce evaluaba a false
                        // y BORRABA la declaracion sin decir nada.  Se avisa.
                        if (a.rfind("mode:", 0) == 0 && a != "mode:auto" &&
                            a != "mode:aot" && a != "mode:bytecode" &&
                            a != "mode:jit" && a != "mode:vm" &&
                            a != "mode:jit-required") {
                            error_here(("@Target: modo '" + a.substr(5) +
                                        "' desconocido; los que hay son "
                                        "'auto', 'aot', 'bytecode' y "
                                        "'jit-required'")
                                           .c_str());
                            break;
                        }
                        if (a == "mode:jit") {
                            top_mode_variant = 1; // variante para el JIT
                        } else if (a == "mode:vm") {
                            top_mode_variant = 2; // variante para el interprete
                        }
                    }
                }
                // Con una variante de modo, los atomos `mode:` ya se han
                // tenido en cuenta y no deben descartar nada; el resto de la
                // expresion (os/arch/cpu) SI sigue condicionando.
                std::string spec_eval = spec;
                if (top_mode_variant != 0) {
                    spec_eval = strip_mode_atoms_(spec);
                    // `mode:vm` y `mode:jit` distinguen dos motores que solo
                    // existen ejecutando bytecode.  Compilando a nativo no hay
                    // tal eleccion -- ahi la variante que vale es `mode:aot` --
                    // asi que estas se descartan; si se emitieran, la de `vm`
                    // conserva el nombre desnudo y chocaria con la nativa.
                    //
                    // Salvo que la expresion mencione `mode:aot`: entonces esa
                    // misma version vale tambien para nativo, y se queda como
                    // funcion normal (sin sufijo).  Asi una implementacion que
                    // sirve a JIT y a nativo se escribe UNA vez.
                    std::string modo_compilacion;
                    get_aot_condcomp_mode(modo_compilacion);
                    if (modo_compilacion == "aot") {
                        std::vector<std::string> ats_modo;
                        cwhen::atoms(spec, ats_modo);
                        bool vale_en_nativo = false;
                        for (const auto &a : ats_modo)
                            if (a == "mode:aot") vale_en_nativo = true;
                        if (vale_en_nativo) {
                            top_mode_variant = 0; // sin sufijo: es LA funcion
                        } else {
                            top_target_skip = true;
                            top_target_spec = spec;
                        }
                    }
                }
                if (!spec_eval.empty() && !target_matches_(spec_eval)) {
                    top_target_skip = true;
                    top_target_spec = spec;
                }
            } else if (current_.kind == TokenKind::LPAREN) {
                int depth = 0;
                do {
                    if (current_.kind == TokenKind::LPAREN)
                        ++depth;
                    else if (current_.kind == TokenKind::RPAREN)
                        --depth;
                    (void)consume();
                } while (depth > 0 && current_.kind != TokenKind::END_OF_FILE);
            }
        } else {
            error_here("se esperaba el nombre de la anotacion tras '@'");
            break;
        }
    }
    //  M.L24: si @Target no matcheo, descartar la decl completa
    // SIN parsearla.  Esto evita diagnosticos espurios por simbolos
    // que solo existen en el otro target.  La pending_visibility se
    // limpia automaticamente via VisGuard al salir.
    if (top_target_skip) {
        // L.24: indicamos "skip intencional" para que parse_program no
        // ejecute synchronize() (que descartaria tokens validos de la
        // siguiente decl).
        last_decl_was_target_skip_ = true;
        skip_target_skipped_decl(top_target_spec);
        return nullptr;
    }
    last_decl_was_target_skip_ = false;
    //  M.condcomp: @Target sobre un `import`.  El path normal
    // maneja import ANTES del loop de annotations, pero cuando hay
    // `@Target("...") import "..."` el @Target ya se consumio aqui;
    // si la condicion matcheo (top_target_skip == false), parseamos
    // el import en este punto.  Si NO matcheo, el bloque top_target_skip
    // de arriba ya lo descarto via skip_target_skipped_decl (que salta
    // hasta el `;`).
    if (current_.kind == TokenKind::KW_IMPORT) {
        return parse_import_decl(/*is_public_reexport=*/false);
    }
    if (current_.kind == TokenKind::KW_PUBLIC &&
        lex_.peek_at(0).kind == TokenKind::KW_IMPORT) {
        (void)consume(); // 'public'
        return parse_import_decl(/*is_public_reexport=*/true);
    }
    // L.24: si las annotations consumieron tokens y el siguiente
    // token es `public`/`private` (caso `@Target("..") public i32 fn`),
    // re-chequear visibilidad aqui.  El bloque de KW_PUBLIC original
    // esta ANTES del while AT, por lo que las decls con annotations
    // +visibility necesitan este segundo chequeo.
    if (pending_visibility_ == 0 && (current_.kind == TokenKind::KW_PUBLIC ||
                                     current_.kind == TokenKind::KW_PRIVATE)) {
        pending_visibility_ = (current_.kind == TokenKind::KW_PUBLIC) ? 1 : 2;
        (void)consume();
    } else if (pending_visibility_ == 0 &&
               current_.kind == TokenKind::IDENTIFIER &&
               current_.lexeme == "internal") {
        pending_visibility_ = 3; // NS.3: internal tras annotations
        (void)consume();
    }
    // Un `concept` con anotaciones.  La comprobacion original esta ANTES
    // del bucle que consume las anotaciones, asi que sin esta segunda un
    // `@Target("arch:...") concept C<T> = ...;` caia al camino de las
    // funciones y fallaba pidiendo un parentesis.  Es el mismo caso que
    // el `import` de arriba: la decl es valida, pero quien la reconoce
    // ya quedo atras.
    //
    // Anotar un concepto tiene sentido justamente porque un concepto dice
    // QUE puede hacer un tipo, y eso puede depender del objetivo: la misma
    // operacion existe empaquetada en una maquina y no en otra.  Con esto
    // se declara una vez por arquitectura en el mismo fichero, en vez de
    // partir el modulo entero en dos por una sola diferencia.
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "concept" &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
        auto cn = parse_concept_decl();
        apply_pending_visibility(cn.get());
        return cn;
    }
    // bytes <nombre> { db/dw/dd/dq/times ... }  (datos crudos estilo NASM)
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "bytes" &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
        lex_.peek_at(1).kind == TokenKind::LBRACE) {
        auto bd = parse_bytes_decl();
        if (bd) {
            bd->attr_section = std::move(top_attr_section);
            bd->attr_section_perms = std::move(top_attr_section_perms);
            bd->attr_at = top_attr_at;
            bd->attr_order = top_attr_order;
        }
        apply_pending_visibility(bd.get());
        return bd;
    }
    // asm <nombre> { <nasm 16/32/64> }  (codigo ensamblado por Keystone)
    if (current_.kind == TokenKind::KW_ASM &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
        lex_.peek_at(1).kind == TokenKind::LBRACE) {
        auto bd = parse_asm_block_decl();
        if (bd) {
            bd->attr_section = std::move(top_attr_section);
            bd->attr_section_perms = std::move(top_attr_section_perms);
            bd->attr_at = top_attr_at;
            bd->attr_order = top_attr_order;
            bd->asm_bits = top_attr_bits;
        }
        apply_pending_visibility(bd.get());
        return bd;
    }
    // typedef / using tras anotaciones (`@Target("arch:x86_64") public
    // typedef u64 uintptr new;`).  El caso SIN anotaciones se maneja arriba
    // (~L859) ANTES del loop de `@`; aqui cubrimos el caso post-anotacion,
    // que antes caia a "se esperaba un tipo" (typedef no estaba en el
    // dispatch post-@).  Habilita @Target por typedef (tipos por arquitectura).
    if (current_.kind == TokenKind::KW_TYPEDEF) {
        const auto nk = lex_.peek_at(0).kind;
        std::unique_ptr<ast::Node> n;
        if (nk == TokenKind::KW_STRUCT || nk == TokenKind::KW_ENUM ||
            nk == TokenKind::KW_UNION) {
            n = parse_typedef_struct_or_enum();
            // `@align(N)` sobre un `typedef struct { ... } Name;`.
            if (n && n->kind == ast::NodeKind::StructDecl && top_attr_align > 0)
                static_cast<ast::StructDecl *>(n.get())->attr_align =
                    top_attr_align;
        } else {
            n = parse_typedef_decl();
        }
        apply_pending_visibility(n.get());
        return n;
    }
    if (current_.kind == TokenKind::KW_USING) {
        auto n = parse_using_decl();
        apply_pending_visibility(n.get());
        return n;
    }
    // struct C-tagless: `struct { ... } Name, *PName;` (nombre al final, sin
    // `typedef`).  Se trata igual que `typedef struct { ... } Name;`.
    if ((current_.kind == TokenKind::KW_STRUCT ||
         current_.kind == TokenKind::KW_UNION) &&
        lex_.peek_at(0).kind == TokenKind::LBRACE) {
        auto n = parse_typedef_struct_or_enum(/*leading_typedef=*/false);
        if (n && n->kind == ast::NodeKind::StructDecl && top_attr_align > 0)
            static_cast<ast::StructDecl *>(n.get())->attr_align =
                top_attr_align;
        apply_pending_visibility(n.get());
        return n;
    }
    // struct <nombre> { ... }
    if (current_.kind == TokenKind::KW_STRUCT) {
        auto sd = parse_struct_decl(top_is_overlay);
        if (sd && top_is_introspect) sd->is_introspect = true;
        if (sd && top_is_abstract) sd->is_abstract = true;
        if (sd && top_is_overlay) sd->is_overlay = true;
        if (sd) {
            sd->contract_pod = top_t_pod;
            sd->contract_no_heap = top_t_no_heap;
            sd->contract_size = top_t_size;
            sd->attr_align = top_attr_align;
        }
        if (current_.kind == TokenKind::SEMICOLON) (void)consume();
        apply_pending_visibility(sd.get());
        return sd;
    }
    // union <nombre> { ... }  (struct con todos los campos en offset 0)
    if (current_.kind == TokenKind::KW_UNION) {
        auto sd = parse_struct_decl(/*is_overlay=*/false);
        if (sd) {
            sd->is_union = true;
            sd->contract_pod = top_t_pod;
            sd->contract_no_heap = top_t_no_heap;
            sd->contract_size = top_t_size;
        }
        if (current_.kind == TokenKind::SEMICOLON) (void)consume();
        apply_pending_visibility(sd.get());
        return sd;
    }
    // class <nombre> { ... }
    if (current_.kind == TokenKind::KW_CLASS) {
        auto cd = parse_class_decl();
        // `final class C` y `@Final class C` dicen lo mismo, como promete la
        // documentacion del lenguaje.
        if (cd && (pending_final_ || top_is_final)) cd->is_final = true;
        if (cd && top_is_aspect) cd->is_aspect = true;
        if (cd && top_is_introspect) cd->is_introspect = true;
        // Sprint lombok: propagar flags class-level.
        if (cd) {
            cd->lombok_getter = top_lk_getter;
            cd->lombok_setter = top_lk_setter;
            cd->lombok_tostring = top_lk_tostring;
            cd->lombok_equals_hash = top_lk_equals_hash;
            cd->lombok_no_args_ctor = top_lk_no_args_ctor;
            cd->lombok_all_args_ctor = top_lk_all_args_ctor;
            cd->lombok_required_ctor = top_lk_required_ctor;
            cd->lombok_data = top_lk_data;
            cd->lombok_value = top_lk_value;
            cd->lombok_builder = top_lk_builder;
            cd->lombok_with_all = top_lk_with_all;
            cd->lombok_log = top_lk_log;
            cd->lombok_sync_methods = top_lk_sync_methods;
            cd->contract_pod = top_t_pod;
            cd->contract_no_heap = top_t_no_heap;
            cd->contract_size = top_t_size;
        }
        if (current_.kind == TokenKind::SEMICOLON) (void)consume();
        apply_pending_visibility(cd.get());
        return cd;
    }
    // interface <nombre> { metodos abstractos }
    // Reusa parse_class_decl marcando is_interface=true; el parser de
    // metodos acepta `;` en lugar de body para metodos abstractos.
    if (current_.kind == TokenKind::KW_INTERFACE) {
        auto cd = parse_interface_decl();
        if (cd && top_is_introspect) cd->is_introspect = true;
        apply_pending_visibility(cd.get());
        return cd;
    }
    // ADTs: enum <nombre> { Variante1, Variante2(T1, T2), ... }
    if (current_.kind == TokenKind::KW_ENUM) {
        auto ed = parse_enum_decl();
        if (ed && top_is_introspect) ed->is_introspect = true;
        if (ed) {
            ed->contract_pod = top_t_pod;
            ed->contract_no_heap = top_t_no_heap;
            ed->contract_size = top_t_size;
        }
        // `;` final opcional estilo C: `enum E { ... };`.
        if (current_.kind == TokenKind::SEMICOLON) (void)consume();
        apply_pending_visibility(ed.get());
        return ed;
    }

    // Sintaxis canonica (post-hard-break v4):
    //   comptime T NAME = expr;          -- const inmutable comptime
    //   comptime var T NAME = init;      -- mutable (solo usable en eval AST)
    //   comptime auto NAME = expr;       -- inferido inmutable
    //   comptime <T,U> RET fn(...) {...} -- funcion comptime generica
    //   comptime T fn(...) {...}         -- funcion comptime no generica
    //
    // `comptime const T X = ...;` (forma vieja con `const` redundante)
    // se REJECTA con error claro -- el const sobra porque comptime
    // implica constancia.  Hard break v4.
    bool is_comptime_const = false; // canonico: `comptime T X = ...`
    bool is_comptime_var = false;
    bool is_comptime_fn = false;
    std::vector<std::string> comptime_type_params;
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "comptime") {
        Lexer &mut_lex = const_cast<Lexer &>(lex_);
        // LANG.fix-2: `comptime { stmts }` a nivel modulo.  Permite
        // metaprogramacion que muta `comptime var` globales, llena
        // arrays con loops, etc.  Antes solo se aceptaba dentro de
        // funciones (parse_statement).  El cuerpo se ejecuta en el
        // TypeChecker via comptime_eval_stmt sobre los globales.
        if (mut_lex.peek_at(0).kind == TokenKind::LBRACE) {
            const SourceLoc cb_loc = current_.loc;
            (void)consume(); // 'comptime'
            (void)expect(TokenKind::LBRACE, "se esperaba '{' tras 'comptime'");
            auto cb = std::make_unique<ast::ComptimeBlockStmt>();
            cb->loc = cb_loc;
            while (current_.kind != TokenKind::RBRACE &&
                   current_.kind != TokenKind::END_OF_FILE) {
                /* sugar: `NAME = expr;` dentro del bloque NO se
                 * trata como decl comptime const (a nivel modulo el
                 * usuario raramente quiere eso, suele querer mutar
                 * un global existente).  Solo parse_statement
                 * normal.  Si quieres una const local al bloque,
                 * escribe `comptime T NAME = expr;` explicito. */
                auto inner = parse_statement();
                if (inner)
                    cb->stmts.push_back(std::move(inner));
                else
                    synchronize();
            }
            (void)expect(TokenKind::RBRACE,
                         "se esperaba '}' al cerrar comptime block");
            return cb;
        }
        if (mut_lex.peek_at(0).kind == TokenKind::KW_CONST) {
            // Forma vieja `comptime const T X = ...`: hard error v4.
            const SourceLoc bad_loc = current_.loc;
            (void)consume(); /* 'comptime' */
            (void)consume(); /* 'const' redundante */
            diags_.error(
                bad_loc,
                "'comptime const' es redundante; usa 'comptime T X = ...' "
                "(comptime ya implica const, salvo 'comptime var')");
            is_comptime_const = true;
        } else if (mut_lex.peek_at(0).kind == TokenKind::IDENTIFIER &&
                   mut_lex.peek_at(0).lexeme == "var") {
            /* Hard break v4: `comptime var` ELIMINADO.  La mutabilidad es
             * el comportamiento por defecto en compile-time -- todo
             * `comptime`/`const` es mutable DURANTE la compilacion y se
             * congela al terminar -- asi que el marcador `var` es
             * redundante y confuso.  Usa `comptime X` (tipo explicito) o
             * `comptime auto X` (inferencia). */
            const SourceLoc bad_loc = current_.loc;
            (void)consume(); /* 'comptime' */
            (void)consume(); /* 'var' */
            diags_.error(
                bad_loc,
                "'comptime var' fue eliminado: usa 'comptime X' o "
                "'comptime auto X' (comptime ya es mutable en compile-time)");
            /* Consumir hasta ';' para no encadenar errores. */
            while (current_.kind != TokenKind::SEMICOLON &&
                   current_.kind != TokenKind::END_OF_FILE)
                (void)consume();
            (void)match(TokenKind::SEMICOLON);
            return nullptr;
        } else if (mut_lex.peek_at(0).kind == TokenKind::IDENTIFIER &&
                   mut_lex.peek_at(0).lexeme == "auto") {
            /* `comptime auto NAME = init;` -- inferencia de tipo.  `auto`
             * (inferencia; valido en comptime y en runtime) es DISTINTO de
             * `var` (marcador de mutabilidad, eliminado).  El tipo se
             * deduce del init; mutable en compile-time por el pre-pase
             * (is_mutable=true), congelado tras compilar. */
            const SourceLoc sugar_loc = current_.loc;
            (void)consume(); /* 'comptime' */
            (void)consume(); /* 'auto' */
            auto gv = std::make_unique<ast::GlobalVarDecl>();
            gv->loc = sugar_loc;
            gv->name = consume().lexeme;
            /* is_const=true -> INMUTABLE en runtime (reasignarlo en runtime es
             * error).  La mutabilidad comptime la da is_mutable=true en el
             * pre-pase (todo global const/comptime es mutable en compile-time,
             * congelado despues). */
            gv->is_const = true;
            gv->is_comptime = true;
            gv->type = nullptr; /* infer desde init */
            (void)expect(TokenKind::ASSIGN,
                         "se esperaba '=' tras 'comptime auto' + nombre");
            gv->init = parse_expr();
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' al final de la decl comptime auto");
            return gv;
        } else if (mut_lex.peek_at(0).kind == TokenKind::IDENTIFIER &&
                   mut_lex.peek_at(1).kind == TokenKind::ASSIGN) {
            /* sugar: `comptime NAME = expr;` -> equivale a
             * `comptime const auto NAME = expr;` con inferencia.
             * Reduce el ruido al construir cadenas de macros + types
             * en compile-time (que repetian `comptime const ...` por
             * todas partes).  Solo aplica cuando el siguiente al
             * IDENT es `=` (sin tipo entre medias). */
            const SourceLoc sugar_loc = current_.loc;
            (void)consume();                   /* 'comptime' */
            std::string nm = consume().lexeme; /* NAME */
            (void)expect(TokenKind::ASSIGN,
                         "se esperaba '=' tras 'comptime' + nombre");
            auto gv = std::make_unique<ast::GlobalVarDecl>();
            gv->loc = sugar_loc;
            gv->name = std::move(nm);
            /* is_const=true -> INMUTABLE en runtime; mutable SOLO en
             * compile-time (is_mutable=true en el pre-pase). */
            gv->is_const = true;
            gv->is_comptime = true;
            gv->type = nullptr; /* infer desde init */
            gv->init = parse_expr();
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' al final de la decl comptime");
            return gv;
        } else {
            /* `comptime <TYPE> ...` -- puede ser:
             *   (a) `comptime T NAME = expr;`  -> comptime const var (v4
             * canonico) (b) `comptime T fn(args) {...}` -> comptime function
             *   (c) `comptime <T,U> RET fn(args) {...}` -> generic comptime fn
             *
             * El parser consume `comptime`, captura type-params opcionales,
             * y deja que el flujo regular (type + name + `=` vs `(`) decida
             * si es var o fn.  Si es var, marcamos como comptime const en
             * el cierre.  Si es fn, ya marcamos `is_comptime_fn`. */
            (void)consume(); /* 'comptime' */
            /* A.41: type params opcionales `<T, U, ...>` para
             * comptime fn genericos.  Solo aplica a funciones; si
             * aparecen tras `comptime` directamente, marcamos como fn
             * temprano porque solo funciones tienen type params. */
            if (current_.kind == TokenKind::LT) {
                is_comptime_fn = true;
                (void)consume(); /* '<' */
                while (current_.kind == TokenKind::IDENTIFIER) {
                    comptime_type_params.push_back(consume().lexeme);
                    if (current_.kind == TokenKind::COMMA) {
                        (void)consume();
                        continue;
                    }
                    break;
                }
                (void)expect_close_angle(
                    "se esperaba '>' al cerrar type params");
            } else {
                /* Sin `<>`: la diferencia entre var y fn la decide la
                 * forma posterior (`= expr;` vs `(args) {...}`).  Marcamos
                 * tentativamente como comptime_const; si luego resulta
                 * que es funcion (`(` tras el nombre), revertimos el flag
                 * antes de devolver el FunctionDecl. */
                is_comptime_const = true;
            }
        }
    }

    // `thread_local <T> NAME = init;` -- almacenamiento por-hilo (TLS).  Se
    // permite antes del tipo (estilo C/C++).  El init debe ser comptime-const.
    bool is_thread_local = false;
    if (match(TokenKind::KW_THREAD_LOCAL)) is_thread_local = true;

    // Manejar 'const' opcional al principio.  En v4, comptime ya implica
    // const, asi que el `const` aparece solo en declaraciones runtime.
    bool is_const = false;
    if (match(TokenKind::KW_CONST)) is_const = true;

    // `static_assert(cond, "msg");` a nivel modulo.  Lo
    // parseamos como una ExprStmt envuelto en un GlobalVarDecl
    // dummy con type=void + init=ese CallExpr.  El type checker lo
    // procesa en la pasada de globales y emite error si la cond es
    // false; el lowering lo trata como void global (no genera codigo).
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "static_assert") {
        Lexer &mut_lex = const_cast<Lexer &>(lex_);
        if (mut_lex.peek_at(0).kind == TokenKind::LPAREN) {
            const SourceLoc sa_loc = current_.loc;
            auto call_expr = parse_expr(); /* static_assert(...) */
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' tras static_assert(...)");
            auto gv = std::make_unique<ast::GlobalVarDecl>();
            gv->loc = sa_loc;
            gv->name = std::string("__static_assert_") +
                       std::to_string(static_assert_counter_++);
            auto tn = std::make_unique<ast::PrimitiveTypeNode>();
            tn->prim = PrimitiveKind::VOID;
            gv->type = std::move(tn);
            gv->init = std::move(call_expr);
            return gv;
        }
    }

    // allow_reserved_name: a nivel top-level no hay expression-statements,
    // asi que `T <palabra_reservada>` solo puede ser un intento de declarar
    // algo con un nombre invalido.  Aceptarlo aqui permite que el error se
    // reporte sobre el nombre (con el motivo) en lugar de degenerar en un
    // "se esperaba un tipo" apuntando al inicio de la linea.
    if (!starts_type(/*allow_reserved_name=*/true)) {
        error_here("se esperaba un tipo al inicio de la declaracion top-level");
        return nullptr;
    }

    const SourceLoc loc = current_.loc;
    auto type_node = parse_type_node();
    if (!type_node) return nullptr;

    // El nombre puede ser IDENTIFIER o un keyword CONTEXTUAL (`get`/`set`):
    // a nivel top-level no existe la sintaxis de property, asi que tras un
    // tipo ya parseado `Optional<u64> get(i64 x)` es inequivocamente
    // "tipo + nombre".  Mismo criterio que ya aplicaban los miembros de
    // clase y el acceso `obj.get(...)`.
    if (!is_name_token(current_.kind)) {
        error_expected_name("nombre de funcion o variable global",
                            "se esperaba un nombre tras el tipo");
        return nullptr;
    }
    std::string name = consume().lexeme;

    if (current_.kind == TokenKind::LPAREN || current_.kind == TokenKind::LT) {
        // Es una funcion (`T name(...)` o generica `T name<T>(...)`).  Las
        // funciones no admiten 'const' delante; si lo hubo, warning pero sigue.
        if (is_const) {
            diags_.warning(loc, "'const' ignorado en declaracion de funcion");
        }
        // v4: si veniamos marcados como `comptime const` (caso tentativo
        // sin type-params) y resulto ser una funcion, promocionar a
        // comptime fn.
        if (is_comptime_const && !is_comptime_fn) {
            is_comptime_fn = true;
            is_comptime_const = false;
        }
        auto fd =
            parse_function_decl(std::move(type_node), std::move(name), loc);
        // propagar @Async leida en el bucle de annotations.
        // El lowering trata estas funciones distinto: las envuelve en
        // future_alloc + spawn { msgrecv handle + body + fulfill } y
        // devuelve el handle del future al caller.
        if (fd && top_is_async) fd->is_async = true;
        if (fd) fd->fp_contract = top_fp_contract; // @fp(strict|fast)
        if (fd && top_is_noexcept) fd->is_noexcept = true;
        if (fd && is_comptime_fn) fd->is_comptime = true;
        if (fd && top_is_macro) fd->is_macro = true;
        if (fd && top_is_pure) fd->is_pure = true;
        if (fd && top_is_alloc_override) fd->is_alloc_override = true;
        if (fd && top_is_panic_handler) fd->is_panic_handler = true;
        if (fd && top_is_naked) fd->is_naked = true;
        if (fd && top_is_no_idiom) fd->is_no_idiom = true;
        // Variante por modo: la del interprete conserva el nombre para que los
        // puntos de llamada no cambien; la del JIT sale con sufijo, y el JIT
        // la sustituye al compilar.  Asi las dos conviven en el mismo `.velb`
        // sin tocar el formato.
        if (fd && top_mode_variant == 1) {
            fd->name += ast::kSufijoVarianteJit;
            fd->mode_variant_jit = true;
        }
        if (fd && top_is_string_concat) fd->is_string_concat_override = true;
        if (fd && top_is_string_eq) fd->is_string_eq_override = true;
        if (fd && top_is_sync_impl) fd->is_sync_impl = true;
        if (fd && !top_helper_override_target.empty())
            fd->helper_override_target = top_helper_override_target;
        // Subsistema de coste: propagar el contrato @complexity al AST.
        // Sin resolver: el type checker aplica la regla de prioridad sobre
        // todos juntos.  Los campos resueltos los rellena el.
        if (fd) {
            fd->complexity_pending = std::move(top_complexity_pending);
            // Contratos de huella (recurso/efecto).  Los SIN `when:` van a los
            // campos directos (el default); los CON when a la lista, que el
            // type checker resuelve por especificidad.
            fd->contract_pure = top_c_pure;
            fd->contract_nothrow = top_c_nothrow;
            fd->contract_nopanic = top_c_nopanic;
            fd->contract_alloc = top_c_alloc;
            fd->contract_alloc_partial = top_c_alloc_partial;
            fd->contract_stack = top_c_stack;
            fd->contract_stack_partial = top_c_stack_partial;
            fd->footprint_pending = std::move(top_footprint_pending);
        }
        // AOT 2b (dev OS): seccion de salida del codigo + permisos.
        if (fd && !top_attr_section.empty()) {
            fd->attr_section = top_attr_section;
            fd->attr_section_perms = top_attr_section_perms;
        }
        if (fd) {
            fd->attr_at = top_attr_at;
            fd->attr_order = top_attr_order;
        }
        if (fd && is_comptime_fn)
            fd->type_params = std::move(comptime_type_params);
        // Registrar posiciones de params @c expr para que el parser sepa
        // hacer raw-text capture en los call sites de esta funcion.  Se honra
        // para CUALQUIER funcion con params @c expr (no solo @Macro): permite
        // helpers comptime como `comptime string source(expr code)` que
        // capturan el texto crudo del argumento (p.ej. un bloque `asm`) sin
        // parsearlo como expresion.
        if (fd && !fd->params.empty()) {
            std::vector<int> positions;
            for (size_t i = 0; i < fd->params.size(); ++i) {
                if (fd->params[i] && fd->params[i]->is_expr_capture) {
                    positions.push_back(static_cast<int>(i));
                }
            }
            if (!positions.empty()) {
                macro_expr_params_[fd->name] = std::move(positions);
            }
        }
        apply_pending_visibility(fd.get());
        return fd;
    }
    // `comptime T NAME = expr;` (forma canonica v4) -> comptime const
    // (inmutable, exportable, va al .vxi).
    // `comptime var T NAME = init;` -> comptime mutable (local al eval AST).
    // v4: un `comptime X` (var-decl top-level) es INMUTABLE en runtime
    // (is_const=true) pero MUTABLE en compile-time (is_mutable=true en el
    // pre-pase).  Reasignarlo en runtime es error; el codigo comptime SI lo
    // puede alterar durante la compilacion.  Ya no existe `comptime var`.
    if (is_comptime_const) {
        is_const = true;
    }
    auto gv = parse_global_var_decl(std::move(type_node), std::move(name), loc,
                                    is_const);
    if (gv && (is_comptime_const || is_comptime_var)) gv->is_comptime = true;
    if (gv && is_thread_local) gv->is_thread_local = true;
    if (gv) {
        // v4: propagar atributos de usuario (@hot, @cold, @align, @section).
        gv->attr_hot = top_attr_hot;
        gv->attr_cold = top_attr_cold;
        gv->attr_align = top_attr_align;
        gv->attr_section = std::move(top_attr_section);
        gv->attr_section_perms = std::move(top_attr_section_perms);
    }
    apply_pending_visibility(gv.get());
    return gv;
}

// ---------------------------------------------------------------------
// FunctionDecl: '(' params? ')' block
// ---------------------------------------------------------------------

std::unique_ptr<ast::FunctionDecl>
Parser::parse_function_decl(std::unique_ptr<ast::TypeNode> ret_type,
                            std::string name, SourceLoc loc) {
    auto fn = std::make_unique<ast::FunctionDecl>();
    fn->loc = loc;
    fn->return_type = std::move(ret_type);
    fn->name = std::move(name);

    // Parametros de tipo opcionales (funcion generica `T id<T>(T x)`).  Mismo
    // patron que struct/clase/enum: `<T1, T2>` tras el nombre, antes de '('.
    // #6: cada param puede llevar un bound inline `<T: Concepto>`.
    // #7: la PRIMERA `id<...>` es el primario; las siguientes con el mismo
    // nombre son especializaciones (total/parcial).
    if (current_.kind == TokenKind::LT) {
        if (generic_fn_names_seen_.count(fn->name)) {
            fn->is_specialization = true;
            parse_specialization_pattern(fn->spec_pattern, fn->type_params);
        } else {
            parse_type_params_with_bounds(fn->type_params, fn->type_bounds);
            generic_fn_names_seen_.insert(fn->name);
        }
    }

    (void)expect(TokenKind::LPAREN,
                 "se esperaba '(' tras el nombre de la funcion");

    // Lista de parametros vacia o coma-separada.
    if (current_.kind != TokenKind::RPAREN) {
        // Cota dura para evitar loops infinitos por bugs en parse_param.
        // En la practica nunca se declara >256 params; 1024 es defensivo.
        constexpr size_t MAX_PARAMS = 1024;
        size_t param_count = 0;
        while (true) {
            if (current_.kind == TokenKind::END_OF_FILE ||
                current_.kind == TokenKind::LBRACE ||
                current_.kind == TokenKind::RBRACE) {
                error_here("se esperaba ')' antes de fin de archivo o '{'");
                break;
            }
            if (++param_count > MAX_PARAMS) {
                error_here("demasiados parametros (>1024); error de sintaxis "
                           "no recuperable");
                break;
            }
            auto p = parse_param();
            if (p) fn->params.push_back(std::move(p));
            if (!match(TokenKind::COMMA)) break;
        }
    }
    (void)expect(TokenKind::RPAREN,
                 "se esperaba ')' al cerrar la lista de parametros");

    // #6: clausula `where T: A + B` opcional tras los params (estilo Rust).
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "where") {
        parse_where_clause(fn->type_bounds);
    }

    // Cuerpo: bloque obligatorio para funciones Vesta; las funciones
    // sin cuerpo (FFI extern) se modelan via @c ExternFnDecl aparte.
    // Bug fix 2026-05-23: forward declaration `i32 fn(args);` -- si
    // vemos `;` en lugar de `{`, registramos la firma sin body.  El
    // type checker debe ver una definicion (con body) mas adelante o
    // reportar error de simbolo sin definicion.
    if (current_.kind == TokenKind::SEMICOLON) {
        (void)consume(); // ';'
        fn->body = nullptr;
        fn->is_forward_decl = true;
        return fn;
    }
    if (current_.kind != TokenKind::LBRACE) {
        error_here("se esperaba '{' para abrir el cuerpo de la funcion");
        return fn;
    }
    // Forwarding de expr-capture anidado: registrar los nombres de params
    // `expr` de ESTA funcion mientras se parsea su cuerpo, para que una llamada
    // interna `otra(code)` con `code` = param expr no re-capture el
    // identificador como texto sino que lo forwardee (ver parse_postfix).
    auto saved_expr_params = std::move(current_expr_param_names_);
    current_expr_param_names_.clear();
    for (const auto &p : fn->params)
        if (p && p->is_expr_capture) current_expr_param_names_.insert(p->name);
    fn->body = parse_block();
    current_expr_param_names_ = std::move(saved_expr_params);
    return fn;
}

std::unique_ptr<ast::ParamDecl> Parser::parse_param() {
    // Caso especial `expr name`: tipo contextual valido SOLO en params
    // de @Macro.  Lo materializamos como STRING para el body del macro;
    // la captura raw se hace en el call site (parse_postfix con
    // raw-text slicing).  Marcamos @c is_expr_capture para que el
    // registro posterior (en parse_function_decl) lo recolecte.
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "expr") {
        auto p = std::make_unique<ast::ParamDecl>();
        p->loc = current_.loc;
        (void)consume(); // consume 'expr'
        auto tn = std::make_unique<ast::PrimitiveTypeNode>();
        tn->loc = p->loc;
        tn->prim = PrimitiveKind::STRING;
        p->type = std::move(tn);
        p->is_expr_capture = true;
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here(
                "se esperaba un nombre tras el tipo 'expr' del parametro");
            return p;
        }
        p->name = consume().lexeme;
        return p;
    }
    // Variadico CRUDO estilo C: `...` pelado (sin tipo ni nombre).  Acepta N
    // args de CUALQUIER tipo; cada uno se coloca segun su ABI en el call site.
    // El callee (para @Naked) los lee de los registros ABI en su asm; no hay
    // empaquetado ni vacount().  Debe ser el ultimo parametro.
    if (current_.kind == TokenKind::DOTDOTDOT) {
        auto p = std::make_unique<ast::ParamDecl>();
        p->loc = current_.loc;
        (void)consume(); // '...'
        p->is_variadic = true;
        p->is_raw_variadic = true;
        // Sin tipo ni nombre: el type checker valida que sea el ultimo y que la
        // funcion sea @Naked.
        return p;
    }
    // Direccion: `in T* p` / `out T* p` / `inout T* p`.  Va la PRIMERA, delante
    // de `register(...)` y del tipo.  Como esto es el lector de parametros que
    // comparten los siete contextos donde se declaran -- funcion suelta,
    // metodo, constructor, metodo de interfaz, funcion comptime, lambda con
    // tipos y bloque extern --, la marca vale en todos ellos por construccion,
    // que es justo la propiedad que el lenguaje promete de sus parametros.
    const ParamDir param_dir = parse_opt_param_dir_();
    // ABI custom por funcion: `register("rXX") T name` fija el registro fisico
    // en el que este parametro se recibe (y donde el caller lo coloca).  Mismo
    // patron que la storage-class de var-decls; aqui el nombre se guarda en
    // ParamDecl::abi_reg y lo valida el type checker.  Cero shift para wrappers
    // de syscall/FFI (`register("rax") id, register("rdi") a1, ...`).
    std::string param_abi_reg = parse_opt_param_reg();
    // Z.6: aceptar `shared T name` en params (con disambiguation vs
    // `shared<T>` smart pointer).  Hoy es sugar documental; el type
    // system trata `T` y `shared T` como mismo tipo en parametros
    // (la sharing-ness vive en el HANDLE, no en el TIPO referenciado).
    // Util para que el autor de la libreria documente intent.
    if (current_.kind == TokenKind::KW_SHARED &&
        lex_.peek_at(0).kind != TokenKind::LT) {
        (void)consume(); // 'shared' modificador documental
        // No registramos un flag en ParamDecl: la sharing-ness se
        // determina dinamicamente del bit 31 del handle en runtime.
    }
    if (!starts_type()) {
        error_here("se esperaba un tipo en parametro");
        return nullptr;
    }
    auto p = std::make_unique<ast::ParamDecl>();
    p->loc = current_.loc;
    p->dir = param_dir;
    p->abi_reg = std::move(param_abi_reg);
    p->type = parse_type_node();
    // Parametro puntero a funcion estilo C: `R (*name)(params)`.
    {
        std::string fp_name;
        std::unique_ptr<ast::TypeNode> fp_type;
        if (try_parse_c_func_ptr_(p->type, fp_name, fp_type)) {
            p->type = std::move(fp_type);
            p->name = std::move(fp_name);
            return p;
        }
    }
    // Parametro VARIADICO: `T... name`.  El `...` tras el tipo del elemento
    // marca el param como rest (debe ser el ultimo; la validacion de posicion
    // la hace el type checker).  El callee lo recibe como `T*` + un count
    // oculto leido con `vacount()`.
    if (current_.kind == TokenKind::DOTDOTDOT) {
        (void)consume();
        p->is_variadic = true;
    }
    // `T !!name` en posicion de parametro fuerza no-null en
    // entry: el lowering inyecta un `unwrap r_param, r_param` al
    // inicio del cuerpo para que la funcion falle pronto si se le
    // pasa null.  El type checker puede confiar en que el param
    // es no-null en el body.
    if (current_.kind == TokenKind::BANG_BANG) {
        (void)consume();
        if (p->type) p->type->is_nonnull = true;
    }
    if (!is_name_token(current_.kind)) {
        error_expected_name("nombre de parametro",
                            "se esperaba un nombre tras el tipo del parametro");
        return p;
    }
    p->name = consume().lexeme;
    return p;
}

/**
 * @copydoc vx::Parser::parse_param_list
 */
void Parser::parse_param_list(std::vector<std::unique_ptr<ast::ParamDecl>> &out,
                              const char *what) {
    while (current_.kind != TokenKind::RPAREN &&
           current_.kind != TokenKind::END_OF_FILE) {
        auto p = parse_param();
        if (!p) {
            /* @c parse_param ya dijo que pasaba; aqui solo hay que llegar a un
             * punto desde el que se pueda seguir leyendo el fichero. */
            synchronize();
            break;
        }
        if (p->name.empty() && !p->is_raw_variadic) {
            /* Sin nombre y sin ser el `...` pelado -- el unico que no lo
             * lleva -- no hay parametro que declarar. */
            const std::string msg =
                std::string("se esperaba el nombre del parametro del ") + what;
            error_here(msg.c_str());
            synchronize();
            break;
        }
        out.push_back(std::move(p));
        if (!match(TokenKind::COMMA)) break;
    }
}

// ---------------------------------------------------------------------
// GlobalVarDecl: ('=' expr)? ';'
// ---------------------------------------------------------------------

std::unique_ptr<ast::GlobalVarDecl>
Parser::parse_global_var_decl(std::unique_ptr<ast::TypeNode> type,
                              std::string name, SourceLoc loc, bool is_const) {
    auto gv = std::make_unique<ast::GlobalVarDecl>();
    gv->loc = loc;
    gv->type = std::move(type);
    gv->name = std::move(name);
    gv->is_const = is_const;
    if (match(TokenKind::ASSIGN)) {
        gv->init = parse_expr();
    }
    (void)expect(TokenKind::SEMICOLON,
                 "se esperaba ';' al final de la declaracion");
    return gv;
}

// ---------------------------------------------------------------------
// Tipos.
//
// Cobertura actual: primitivos, punteros @c T*, arrays @c T[N] y
// @c T[], @c VirtualPtr<T>, generics @c Cls<T1, T2>, tipos de
// funcion @c fn(T) -> R, y @c nonnull T.  La rama del switch que
// no matche cae al case por defecto, que reporta error claro.
// ---------------------------------------------------------------------

bool Parser::looks_like_cast() const noexcept {
    // Precondition: current_ es LPAREN.  Comprobamos si la
    // secuencia tras `(` forma un type-node valido seguido de `)`.
    // Para evitar conflictos con expresiones agrupadas, exigimos
    // que el PRIMER token sea un type-starter inequivoco:
    // primitivo (i32, u8, ...), VirtualPtr, fn, nonnull.  Tipos
    // nombrados via identifier (typedef sin marca clara) requieren
    // que el usuario escriba `(VirtualPtr<...>)x` o `(T*)x` para
    // desambiguar.
    Lexer &mut_lex = const_cast<Lexer &>(lex_);

    size_t off = 0;
    // Prefijo opcional `nonnull`.
    if (mut_lex.peek_at(off).kind == TokenKind::KW_NONNULL) ++off;

    const Token &first = mut_lex.peek_at(off);
    const TokenKind first_kind = first.kind;
    // Tipo CUALIFICADO `ns.Tipo` donde `ns` es un namespace importado
    // (p.ej. `(types.size_t) 40`).  Simetrico con `looks_like_var_decl`,
    // que ya acepta `ns.Tipo name`.  El resto de la validacion (cierre `)`
    // + expr-starter tras el `)`) desambigua de `(obj.field) - x`.
    const bool is_qualified_ns =
        first_kind == TokenKind::IDENTIFIER &&
        imported_namespaces_.count(first.lexeme) > 0 &&
        mut_lex.peek_at(off + 1).kind == TokenKind::DOT &&
        mut_lex.peek_at(off + 2).kind == TokenKind::IDENTIFIER;
    const bool is_type_starter =
        primitive_kind_from_token(first_kind) != PrimitiveKind::COUNT ||
        first_kind == TokenKind::KW_FN || first_kind == TokenKind::KW_CFN ||
        (first_kind == TokenKind::IDENTIFIER && first.lexeme == "VirtualPtr")
        // Item 19: identifier declarado como typedef/using
        // tambien es un type-starter valido para casts.
        // Single-pass: el alias debe estar declarado antes
        // del cast en el archivo.
        || (first_kind == TokenKind::IDENTIFIER &&
            declared_aliases_.count(first.lexeme) > 0) ||
        is_qualified_ns;
    if (!is_type_starter) return false;
    ++off;
    // Tipo cualificado: saltar los pares `DOT IDENT` (`.Tipo`, `.Sub.Tipo`).
    if (is_qualified_ns) {
        while (mut_lex.peek_at(off).kind == TokenKind::DOT &&
               mut_lex.peek_at(off + 1).kind == TokenKind::IDENTIFIER)
            off += 2;
    }

    // Tipo funcion `fn(params) -> ret`: saltar `(...)` balanceado + el
    // `-> tipo_retorno` para reconocer `(fn(...)->R) expr` como cast.
    if (first_kind == TokenKind::KW_FN || first_kind == TokenKind::KW_CFN) {
        if (mut_lex.peek_at(off).kind == TokenKind::LPAREN) {
            int d = 1;
            ++off;
            const size_t MAXP = 128;
            while (d > 0 && off < MAXP) {
                TokenKind k = mut_lex.peek_at(off).kind;
                if (k == TokenKind::END_OF_FILE) return false;
                if (k == TokenKind::LPAREN)
                    ++d;
                else if (k == TokenKind::RPAREN)
                    --d;
                ++off;
            }
            if (d != 0) return false;
        }
        if (mut_lex.peek_at(off).kind == TokenKind::ARROW) {
            ++off;
            TokenKind rk = mut_lex.peek_at(off).kind;
            if (primitive_kind_from_token(rk) != PrimitiveKind::COUNT ||
                rk == TokenKind::IDENTIFIER || rk == TokenKind::KW_NONNULL) {
                ++off;
                while (mut_lex.peek_at(off).kind == TokenKind::STAR)
                    ++off;
            }
        }
    }

    // Saltar argumentos genericos `<...>` con balance, tratando
    // `>>` (SHR) como dos GTs.
    if (mut_lex.peek_at(off).kind == TokenKind::LT) {
        int depth = 1;
        ++off;
        const size_t MAX_LOOKAHEAD = 64;
        while (depth > 0 && off < MAX_LOOKAHEAD) {
            TokenKind k = mut_lex.peek_at(off).kind;
            if (k == TokenKind::END_OF_FILE) return false;
            if (k == TokenKind::LT)
                ++depth;
            else if (k == TokenKind::GT)
                --depth;
            else if (k == TokenKind::SHR)
                depth -= 2;
            ++off;
        }
        if (depth != 0) return false;
    }
    // Saltar `*`s (punteros).
    while (mut_lex.peek_at(off).kind == TokenKind::STAR)
        ++off;
    // Saltar `[N]` o `[]` (arrays nativos).  Cierre exacto con `]`.
    while (mut_lex.peek_at(off).kind == TokenKind::LBRACKET) {
        int depth = 1;
        ++off;
        const size_t MAX = 64;
        while (depth > 0 && off < MAX) {
            TokenKind k = mut_lex.peek_at(off).kind;
            if (k == TokenKind::END_OF_FILE) return false;
            if (k == TokenKind::LBRACKET)
                ++depth;
            else if (k == TokenKind::RBRACKET)
                --depth;
            ++off;
        }
        if (depth != 0) return false;
    }
    // Tras todo, debe haber `)`.
    if (mut_lex.peek_at(off).kind != TokenKind::RPAREN) return false;
    // El siguiente token debe poder iniciar una expresion (de lo
    // contrario `(i32)` aislado seria ambiguo y la heuristica
    // genera un cast espureo).  Excluye operadores binarios (que
    // empezarian una expresion infix sin operando izquierdo).
    ++off;
    const TokenKind after = mut_lex.peek_at(off).kind;
    switch (after) {
    case TokenKind::IDENTIFIER:
    // Keywords contextuales que en posicion de expresion son nombres:
    // permite `(u64) get(x)` (cast del retorno de una funcion `get`).
    case TokenKind::KW_GET:
    case TokenKind::KW_SET:
    case TokenKind::INT_LIT:
    case TokenKind::FLOAT_LIT:
    case TokenKind::CHAR_LIT:
    case TokenKind::STRING_LIT:
    case TokenKind::RAW_STRING_LIT:
    case TokenKind::TRUE_KW:
    case TokenKind::FALSE_KW:
    case TokenKind::NULL_KW:
    case TokenKind::KW_THIS:
    case TokenKind::KW_NEW:
    case TokenKind::KW_AWAIT:
    case TokenKind::ISTR_BEGIN:
    case TokenKind::LPAREN:
    case TokenKind::AMP:
    case TokenKind::STAR:
    case TokenKind::PLUS:
    case TokenKind::MINUS:
    case TokenKind::BANG:
    case TokenKind::BANG_BANG:
    case TokenKind::TILDE:
    case TokenKind::PLUS_PLUS:
    case TokenKind::MINUS_MINUS: return true;
    default: return false;
    }
}

bool Parser::looks_like_compound_literal() const noexcept {
    // Precondicion: current_ es '('.  Patron inequivoco: `( IDENT [<...>] ) {`.
    Lexer &mut_lex = const_cast<Lexer &>(lex_);
    size_t off = 0;
    const Token &name_tok = mut_lex.peek_at(off);
    if (name_tok.kind != TokenKind::IDENTIFIER) return false;
    // Solo un NOMBRE DE STRUCT declarado dispara el compound literal; asi
    // `match (val) {` / `(x) {` con `x`/`val` no-struct NO se confunden.
    if (declared_structs_.count(name_tok.lexeme) == 0) return false;
    ++off;
    // Argumentos genericos opcionales `<...>` balanceados (>> = dos >).
    if (mut_lex.peek_at(off).kind == TokenKind::LT) {
        int depth = 1;
        ++off;
        const size_t MAXL = 64;
        while (depth > 0 && off < MAXL) {
            TokenKind k = mut_lex.peek_at(off).kind;
            if (k == TokenKind::END_OF_FILE) return false;
            if (k == TokenKind::LT)
                ++depth;
            else if (k == TokenKind::GT)
                --depth;
            else if (k == TokenKind::SHR) {
                depth -= 2;
                if (depth < 0) return false;
            }
            ++off;
        }
        if (depth != 0) return false;
    }
    // Debe seguir ')' y despues '{'.
    if (mut_lex.peek_at(off).kind != TokenKind::RPAREN) return false;
    ++off;
    return mut_lex.peek_at(off).kind == TokenKind::LBRACE;
}

// ---------------------------------------------------------------------------
// Direccion de un parametro: `in` / `out` / `inout` delante del tipo.
//
// `in` ya es palabra reservada (KW_IN, del `for (x in col)`), asi que ahi no
// hay nada que decidir.  `out` e `inout` NO pueden serlo: `out` aparece en el
// corpus como nombre de variable (`register("rax") i64 out`), como nombre de
// parametro (`void set_to(i32* out, i32 v)`) y -- lo que zanja la cuestion --
// como INSTRUCCION x86 dentro de un bloque `asm` (`out 0xE9, al`).  Reservarla
// romperia los tres.
//
// Por eso se reconocen SOLO al inicio de un parametro y solo si detras viene
// algo que empieza un tipo.  Un `out` en cualquier otra posicion sigue siendo
// un identificador corriente, que es lo que era ayer.
// ---------------------------------------------------------------------------

/**
 * @brief El token puede ABRIR un tipo (mirando solo el token, sin contexto).
 *
 * Es la misma pregunta que responde @c starts_type, pero sobre un token del
 * lookahead: @c starts_type opera sobre @c current_ y aqui hay que decidir
 * mirando lo que viene DESPUES de la marca sin haberla consumido todavia.
 */
static bool token_opens_type(const Token &t) noexcept {
    if (primitive_kind_from_token(t.kind) != PrimitiveKind::COUNT) return true;
    switch (t.kind) {
    case TokenKind::KW_NONNULL:
    case TokenKind::KW_FN:
    case TokenKind::KW_CFN:
    case TokenKind::KW_CONST:
    case TokenKind::KW_UNIQUE:
    case TokenKind::KW_SHARED:
    case TokenKind::KW_BORROW:
    case TokenKind::KW_BORROW_MUT:
    case TokenKind::IDENTIFIER: // tipo nombrado, typedef, `register(...)`
        return true;
    default: return false;
    }
}

// ---------------------------------------------------------------------------
// Los efectos DEFINIDOS de una funcion externa, con `when:` opcional.
//
// Mismas palabras que los contratos, y el sitio decide si se comprueba o se
// cree: en una funcion Vesta `@nopanic` es un contrato que el compilador
// VERIFICA contra el codigo; aqui no hay codigo que leer, asi que es la palabra
// de quien lo escribe.  Una palabra, dos sitios; cambia quien responde por
// ella.
//
// El vocabulario suma formas POSITIVAS que un contrato no necesita.  Un
// contrato ACOTA, y por eso le bastan las negativas; una descripcion COMPLETA
// -- lo que no se escribe, no ocurre -- tiene que poder decir que SI, o el
// silencio se leeria como una demostracion.
//
// El `when:` se resuelve AQUI.  El objetivo se conoce al compilar -- es lo
// mismo que ya hace `@Target` sobre una declaracion --, asi que mas abajo llega
// un conjunto para EL objetivo activo y nadie tiene que arrastrar ambitos.  Y
// es la pieza que hace que esto sea distinto de repetir la declaracion con
// `@Target`: alli lo que cambia es QUE SIMBOLO existe; aqui la funcion es una
// sola y lo que varia es lo que hace.
//
// Lo escrito SIN `when:` vale en todos los objetivos y lo condicionado se SUMA
// donde case, que es como ya se comporta un contrato sin `when:`.
// ---------------------------------------------------------------------------
void Parser::parse_extern_effects_(ast::ExternEffects &out) {
    while (current_.kind == TokenKind::AT) {
        const Token &nx = lex_.peek_at(0);
        if (nx.kind != TokenKind::IDENTIFIER) return;
        const std::string nm = nx.lexeme; // COPIA: los consume() lo invalidan
        // Solo se consume si el nombre ES un efecto; cualquier otra anotacion
        // la maneja quien ya la manejaba.
        const bool conocido =
            (nm == "pure" || nm == "io" || nm == "throws" || nm == "panics" ||
             nm == "alloc" || nm == "nondet" || nm == "keeps_state" ||
             nm == "reads_env" || nm == "writes_env" || nm == "nothrow" ||
             nm == "nopanic" || nm == "det" || nm == "allocator" ||
             nm == "maps" || nm == "frees" || nm == "blocks" || nm == "traps" ||
             nm == "noblock" || nm == "notrap");
        if (!conocido) return;
        (void)consume(); // '@'
        (void)consume(); // el nombre
        /* Los parentesis llevan DOS cosas que se mezclan: el `when:` que ya
         * existia, y el REFINAMIENTO de la palabra -- de quien es lo que sale
         * (`@throws(native)`) y que puede fallar (`@traps(div0, access)`) --.
         *
         * Van en la misma palabra y no en palabras aparte porque son la MISMA
         * afirmacion mas precisa, no otra distinta: `@throws(native)` sigue
         * siendo "puede lanzar".  Y asi el vocabulario de dentro crece sin
         * tocar la gramatica. */
        std::string when;
        ir::UnwindOrigin origen = ir::UnwindOrigin::Any;
        ir::TrapKinds traps = ir::TRAP_NONE;
        ir::WorldKinds mundo = ir::WORLD_NONE;
        uint32_t libera = 0;
        if (current_.kind == TokenKind::LPAREN) {
            (void)consume(); // '('
            for (;;) {
                if (current_.kind == TokenKind::IDENTIFIER &&
                    current_.lexeme == "when") {
                    when = read_footprint_when_();
                } else if (current_.kind == TokenKind::IDENTIFIER) {
                    const std::string w = current_.lexeme;
                    if (nm == "traps") {
                        const ir::TrapKinds b =
                            ir::trap_kind_from_name(w.c_str());
                        if (b == ir::TRAP_NONE)
                            error_here(
                                ("`@traps(...)` no conoce '" + w +
                                 "'; los que hay son div0, access, align, "
                                 "illegal, stack_overflow y fp")
                                    .c_str());
                        traps = static_cast<ir::TrapKinds>(traps | b);
                    } else if (nm == "reads_env" || nm == "writes_env") {
                        const ir::WorldKinds b =
                            ir::world_kind_from_name(w.c_str());
                        if (b == ir::WORLD_NONE)
                            error_here(
                                ("`@" + nm + "(...)` no conoce '" + w +
                                 "'; los que hay son file, net, clock, "
                                 "random, env, config, process, console y "
                                 "device")
                                    .c_str());
                        mundo = static_cast<ir::WorldKinds>(mundo | b);
                    } else if (nm == "throws" || nm == "panics") {
                        if (w == "vesta")
                            origen = ir::UnwindOrigin::Vesta;
                        else if (w == "native")
                            origen = ir::UnwindOrigin::Native;
                        else
                            error_here(("`@" + nm +
                                        "(...)` espera `vesta` o `native`, "
                                        "no '" +
                                        w + "'")
                                           .c_str());
                    } else {
                        error_here(("`@" + nm +
                                    "` no admite argumentos aparte del "
                                    "`when:`")
                                       .c_str());
                    }
                    (void)consume();
                } else if (current_.kind == TokenKind::INT_LIT &&
                           nm == "frees") {
                    /* `@frees(0)` toma la POSICION y no el nombre: los
                     * parametros aun no se han leido cuando se parsea esto, y
                     * inventar un segundo pase para poder escribir el nombre
                     * seria pagar mucho por poco. */
                    const long long i = current_.int_val;
                    if (i < 0 || i >= 32)
                        error_here("`@frees(...)` toma la POSICION de un "
                                   "argumento, de 0 a 31");
                    else
                        libera |= (1u << static_cast<unsigned>(i));
                    (void)consume();
                } else {
                    break;
                }
                if (current_.kind != TokenKind::COMMA) break;
                (void)consume(); // ','
            }
            (void)expect(TokenKind::RPAREN, "se esperaba ')' tras el `when:`");
        }
        out.any = true; // alguien hablo, aunque su `when:` no case aqui
        if (!when.empty() && !target_expr_matches(when))
            continue; // cierto en otro objetivo, no en este
        // `pure`, `nothrow` y `nopanic` no ponen nada: bajo descripcion
        // completa el default ya es que no pasa nada.  Se aceptan porque
        // escribirlo es mas claro que dejar la linea en blanco, y porque son
        // las palabras que el usuario ya conoce.
        if (nm == "io")
            out.io = true;
        else if (nm == "throws") {
            out.may_throw = true;
            /* El origen se ESTRECHA, nunca se ensancha: dos `@throws` con
             * origenes distintos dejan `Any`, que es lo conservador.  Al reves
             * -- quedarse con el ultimo -- dejaria que una segunda linea
             * borrara la advertencia de la primera. */
            out.throw_origin = (out.throw_origin == ir::UnwindOrigin::Any ||
                                out.throw_origin == origen)
                                   ? origen
                                   : ir::UnwindOrigin::Any;
        } else if (nm == "panics") {
            out.may_panic = true;
            out.panic_origin = (out.panic_origin == ir::UnwindOrigin::Any ||
                                out.panic_origin == origen)
                                   ? origen
                                   : ir::UnwindOrigin::Any;
        } else if (nm == "alloc")
            out.allocates = true;
        /* RESERVAR y MAPEAR se parecen y NO son lo mismo, y confundirlos
         * cuesta caro en las dos direcciones.
         *
         *   - `allocator` da memoria FRESCA: nadie mas la apunta y quien llama
         *     se queda con ella.  Eso es una GARANTIA, no un coste, y es lo
         *     que permite tratar el resultado como una localizacion propia --
         *     igual que la de un `malloc` nuestro -- en vez de como "puede
         *     apuntar a cualquier cosa".
         *
         *   - `maps` reserva ESPACIO DE DIRECCIONES, que es otro recurso.  Un
         *     `mmap` o un `MapViewOfFile` pueden mapear algo que YA EXISTE y
         *     esta COMPARTIDO -- un fichero, un dispositivo, la memoria de
         *     otro proceso --, asi que lo que devuelven puede aliasar el mundo
         *     de fuera.  Decir `allocator` de un `mmap` seria prometer que no,
         *     y eso no da un error: da otro resultado cuando el optimizador se
         *     lo crea.
         *
         * El mismo `mmap` ES un asignador si se le pasa anonimo y privado.  Eso
         * se decide en la LLAMADA y no en la declaracion, asi que lo que se
         * declara es lo conservador y quien conozca su caso envuelve. */
        else if (nm == "allocator") {
            out.allocates = true;
            out.returns_fresh = true;
        } else if (nm == "maps") {
            out.allocates = true;     // consume memoria del sistema
            out.writes_global = true; // el espacio de direcciones es del SO
            out.writes_world =
                ir::WORLD_NONE; // sin acotar: puede ser cualquiera
            out.writes_env_visto = true;
            out.io = true;
        } else if (nm == "frees") {
            /* Liberar es ESCRIBIR lo apuntado, y de la peor forma: lo que
             * habia deja de valer.  Se dice como escritura para que los pases
             * que ya miran eso no tengan que aprender nada nuevo, y ademas se
             * apunta cual, que es lo que hace falta para poder avisar de un uso
             * despues de liberar. */
            out.frees_pointee |= libera;
        } else if (nm == "nondet")
            out.nondeterministic = true;
        /* Las tres formas de tener estado que no se ve desde la llamada.
         *
         * Antes esto eran `@reads_global` y `@writes_global`, y decian "estado
         * global del PROCESO" -- que no es lo mismo en la maquina virtual,
         * donde el proceso es uno de los nuestros, que en un binario nativo,
         * donde es el del sistema --.  Una palabra cuyo significado cambia con
         * el modo no describe nada, asi que se dividieron por DE QUIEN es el
         * estado, que es una frontera y no depende del modo:
         *
         *   - `keeps_state`: suyo.  `strtok` recuerda entre llamadas, `errno`
         *     queda escrito, un manejador se cachea.  Lo que aporta es que dos
         *     llamadas INTERACTUAN: no se pueden fundir ni reordenar entre si.
         *   - `reads_env` / `writes_env`: el mundo del SO.  Ficheros, registro,
         *     variables de entorno, reloj.
         *
         * Lo NUESTRO no esta: a nuestros datos una externa solo llega por un
         * puntero que le pasamos, y eso ya lo dice `in`/`out` en el parametro
         * -- con su localizacion concreta, que es mucho mas de lo que un
         * booleano podria decir --. */
        else if (nm == "keeps_state") {
            out.reads_global = true;
            out.writes_global = true;
            out.nondeterministic = true; // dos llamadas iguales interactuan
        } else if (nm == "reads_env") {
            out.reads_global = true;
            out.reads_world = static_cast<ir::WorldKinds>(
                (mundo == ir::WORLD_NONE || out.reads_world == ir::WORLD_NONE)
                    ? ir::WORLD_NONE
                    : (out.reads_world | mundo));
            if (out.reads_world == ir::WORLD_NONE && mundo != ir::WORLD_NONE &&
                !out.reads_env_visto)
                out.reads_world = mundo;
            out.reads_env_visto = true;
            /* Solo lo que CAMBIA por su cuenta hace no-determinista: leer el
             * reloj o la entropia no da lo mismo dos veces, leer la
             * configuracion si.  Con un unico "lee el mundo" habia que suponer
             * lo primero SIEMPRE, o sea tratar a la mayoria por el peor caso.
             *
             * Sin acotar tambien lo hace: quien no dice que lee, no se
             * beneficia de haberlo acotado. */
            if (mundo == ir::WORLD_NONE || (mundo & ir::WORLD_CAMBIANTE) != 0)
                out.nondeterministic = true;
        } else if (nm == "writes_env") {
            out.writes_global = true;
            out.writes_world = static_cast<ir::WorldKinds>(
                (mundo == ir::WORLD_NONE || out.writes_world == ir::WORLD_NONE)
                    ? ir::WORLD_NONE
                    : (out.writes_world | mundo));
            if (out.writes_world == ir::WORLD_NONE && mundo != ir::WORLD_NONE &&
                !out.writes_env_visto)
                out.writes_world = mundo;
            out.writes_env_visto = true;
            out.io = true; // cambiar el mundo se ve desde fuera
        }
        /* Los dos ejes que el modelo interno ya tenia y una `extern` no podia
         * decir.  Sin ellos, un `WaitForSingleObject` entraba como "no
         * bloquea" y una division nativa como "no falla", que bajo DESCRIPCION
         * COMPLETA no es no saberlo: es afirmar que no pasa. */
        else if (nm == "blocks")
            out.may_block = true;
        else if (nm == "traps") {
            out.may_trap = true;
            /* Los fallos se SUMAN entre lineas: `@traps(div0)` y
             * `@traps(access, when: ...)` describen la misma funcion en dos
             * frases.
             *
             * Pero un `@traps` SIN acotar vale por todos, y entonces ya no hay
             * conjunto que valga: una linea que no acota se lleva por delante
             * lo que acotaron las otras.  Al reves seria peor -- acotar de
             * menos hace creer que un fallo no puede pasar --. */
            if (traps == ir::TRAP_NONE)
                out.traps_sin_acotar = true;
            else
                out.trap_kinds =
                    static_cast<ir::TrapKinds>(out.trap_kinds | traps);
            if (out.traps_sin_acotar) out.trap_kinds = ir::TRAP_NONE;
        }
        /* `noblock` y `notrap` no ponen nada, como `nothrow` y `nopanic`: bajo
         * descripcion completa el default ya es que no pasa.  Se aceptan porque
         * escribirlo dice que se penso, y dejarlo en blanco no. */
    }
}

bool Parser::looks_like_param_dir_storage() const noexcept {
    Lexer &ml = const_cast<Lexer &>(lex_);
    if (current_.kind == TokenKind::KW_IN)
        return token_opens_type(ml.peek_at(0));
    if (current_.kind == TokenKind::IDENTIFIER &&
        (current_.lexeme == "out" || current_.lexeme == "inout"))
        return token_opens_type(ml.peek_at(0));
    return false;
}

ParamDir Parser::parse_opt_param_dir_() {
    // `in`: reservada, no hay ambiguedad posible.
    if (current_.kind == TokenKind::KW_IN) {
        (void)consume();
        return ParamDir::In;
    }
    // `out` / `inout`: contextuales.  Solo cuentan si detras abre un tipo; si
    // no, se dejan intactas para que las lea quien las leia antes.
    if (current_.kind == TokenKind::IDENTIFIER &&
        (current_.lexeme == "out" || current_.lexeme == "inout") &&
        token_opens_type(lex_.peek_at(0))) {
        const bool both = (current_.lexeme == "inout");
        (void)consume();
        return both ? ParamDir::InOut : ParamDir::Out;
    }
    return ParamDir::None;
}

std::string Parser::parse_opt_param_reg() {
    // Patron exacto `register ( "reg" )`; cualquier otra cosa se deja intacta.
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "register" &&
        lex_.peek_at(0).kind == TokenKind::LPAREN &&
        lex_.peek_at(1).kind == TokenKind::STRING_LIT &&
        lex_.peek_at(2).kind == TokenKind::RPAREN) {
        (void)consume();                    // 'register'
        (void)consume();                    // '('
        std::string reg = current_.str_val; // nombre del registro
        (void)consume();                    // STRING_LIT
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' tras register(\"reg\")");
        return reg;
    }
    return std::string();
}

bool Parser::looks_like_register_storage() const noexcept {
    // Patron exacto: register ( "reg" ) <type-starter>.
    //   current_     = IDENTIFIER "register"
    //   peek_at(0)   = '('
    //   peek_at(1)   = STRING_LIT (nombre del registro)
    //   peek_at(2)   = ')'
    //   peek_at(3)   = inicio de tipo (primitivo / IDENT / nonnull / fn)
    if (current_.kind != TokenKind::IDENTIFIER || current_.lexeme != "register")
        return false;
    Lexer &mut_lex = const_cast<Lexer &>(lex_);
    if (mut_lex.peek_at(0).kind != TokenKind::LPAREN) return false;
    if (mut_lex.peek_at(1).kind != TokenKind::STRING_LIT) return false;
    if (mut_lex.peek_at(2).kind != TokenKind::RPAREN) return false;
    const Token &t = mut_lex.peek_at(3);
    // Type-starter a nivel de token (no podemos llamar starts_type aqui
    // porque opera sobre current_, no sobre el lookahead).
    if (primitive_kind_from_token(t.kind) != PrimitiveKind::COUNT) return true;
    if (t.kind == TokenKind::KW_NONNULL) return true;
    if (t.kind == TokenKind::KW_FN) return true;
    if (t.kind == TokenKind::KW_CFN) return true;
    if (t.kind == TokenKind::IDENTIFIER) return true; // tipo nombrado / typedef
    return false;
}

bool Parser::starts_type(bool allow_reserved_name) const noexcept {
    // Cualquier keyword que sea tipo primitivo, o un identificador
    // seguido de uno o mas '*' (cero permitidos) y luego otro
    // identificador (caso "Edad x = ..." o "Punto* p = ...").  Si el
    // siguiente token tras la cadena de '*' no es IDENTIFIER (e.g.
    // 'x = 2' o 'a * b + c'), tratamos esto como expresion.
    //
    // Generics: tambien aceptamos `Cls<T> name` y
    // `Cls<T1, T2> name`.  Lookahead saltando un par balanceado de
    // angle brackets, luego `*`* y un IDENT.
    if (primitive_kind_from_token(current_.kind) != PrimitiveKind::COUNT)
        return true;
    // nonnull: `nonnull T name = ...` empieza un type-decl.
    if (current_.kind == TokenKind::KW_NONNULL) return true;
    // closures: `fn(T...) -> R name = ...` empieza un type-decl.
    // Solo reconocemos `fn` seguido de `(` para no chocar con un
    // hipotetico identificador que empezara por "fn"; KW_FN siempre
    // es el keyword reservado.
    if (current_.kind == TokenKind::KW_FN) return true;
    if (current_.kind == TokenKind::KW_CFN) return true;
    // Qualifier C `const T` / `volatile T` en posicion de TIPO (campo/param):
    // cuenta como inicio de tipo SOLO si lo que sigue empieza un tipo.  (El
    // `const`/`volatile` de un const-var-decl lo detecta el statement parser
    // antes, por su cuenta; esto solo aplica donde se consulta starts_type para
    // decidir "campo o metodo" dentro de un struct/param.)
    if (current_.kind == TokenKind::KW_CONST ||
        (current_.kind == TokenKind::IDENTIFIER &&
         current_.lexeme == "volatile")) {
        Lexer &ml = const_cast<Lexer &>(lex_);
        const Token &nx = ml.peek_at(0);
        if (primitive_kind_from_token(nx.kind) != PrimitiveKind::COUNT)
            return true;
        if (nx.kind == TokenKind::IDENTIFIER) return true;
        if (nx.kind == TokenKind::KW_STRUCT || nx.kind == TokenKind::KW_UNION ||
            nx.kind == TokenKind::KW_ENUM || nx.kind == TokenKind::KW_FN ||
            nx.kind == TokenKind::KW_CFN || nx.kind == TokenKind::KW_NONNULL)
            return true;
        return false;
    }
    // Especificador elaborado C `struct Tag` / `union Tag` / `enum Tag` como
    // REFERENCIA de tipo (seguido de IDENT, no de `{` que es definicion
    // inline).
    if ((current_.kind == TokenKind::KW_STRUCT ||
         current_.kind == TokenKind::KW_UNION ||
         current_.kind == TokenKind::KW_ENUM)) {
        Lexer &ml = const_cast<Lexer &>(lex_);
        return ml.peek_at(0).kind == TokenKind::IDENTIFIER;
    }
    if (current_.kind != TokenKind::IDENTIFIER) return false;
    /* `auto NAME = init;` y `var NAME = init;` cuentan como
     * inicio de var-decl (con inferencia local de tipo).  `auto`/`var`
     * NO son keywords reservadas; solo se interpretan asi cuando van
     * seguidas inmediatamente por otro IDENTIFIER (el nombre). */
    if ((current_.lexeme == "auto" || current_.lexeme == "var")) {
        Lexer &mut_lex = const_cast<Lexer &>(lex_);
        // peek_at(0) es el SIGUIENTE token, no el actual.  El check es
        // "el token despues de `auto`/`var` debe ser IDENT (el nombre)".
        const Token &nx = mut_lex.peek_at(0);
        if (nx.kind == TokenKind::IDENTIFIER) {
            return true;
        }
    }

    Lexer &mut_lex = const_cast<Lexer &>(lex_);
    size_t off = 0;
    //  M.7.c: namespace qualified type `ui.Button name`.
    // Saltar pares `DOT IDENT` antes del check de generics.
    while (mut_lex.peek_at(off).kind == TokenKind::DOT &&
           mut_lex.peek_at(off + 1).kind == TokenKind::IDENTIFIER) {
        off += 2;
    }
    // Optional: skip generic angle-brackets `<...>` con balance.
    // El lexer tokeniza `>>` como un solo SHR (mismo problema que en
    // C++ <17): aqui tratamos SHR como dos GTs cerrados a la vez.
    // Sin esto, `Cls<Inner<T>>` no se reconoce como tipo y el parser
    // bajaria a expr-stmt, fallando al ver el nombre de la variable.
    if (mut_lex.peek_at(off).kind == TokenKind::LT) {
        int depth = 1;
        ++off;
        const size_t MAX_LOOKAHEAD = 64; // cota dura
        while (depth > 0 && off < MAX_LOOKAHEAD) {
            TokenKind k = mut_lex.peek_at(off).kind;
            if (k == TokenKind::END_OF_FILE) return false;
            if (k == TokenKind::LT)
                ++depth;
            else if (k == TokenKind::GT)
                --depth;
            else if (k == TokenKind::SHR)
                depth -= 2;
            ++off;
        }
        if (depth != 0) return false;
    }
    // Saltar `*`s.
    while (mut_lex.peek_at(off).kind == TokenKind::STAR)
        ++off;
    /* saltar `[N]` o `[]` -- postfix de arrays nativos.
     * Permite que `Point[3] arr = ...` y `Cls<T>[5] v = ...` se
     * reconozcan como type-decl. */
    const size_t MAX_LOOKAHEAD = 64;
    while (mut_lex.peek_at(off).kind == TokenKind::LBRACKET) {
        ++off;
        int b_depth = 1;
        size_t guard = 0;
        while (b_depth > 0 && off < MAX_LOOKAHEAD && guard++ < MAX_LOOKAHEAD) {
            TokenKind k = mut_lex.peek_at(off).kind;
            if (k == TokenKind::END_OF_FILE) return false;
            if (k == TokenKind::LBRACKET)
                ++b_depth;
            else if (k == TokenKind::RBRACKET)
                --b_depth;
            ++off;
        }
        if (b_depth != 0) return false;
        /* Permitir tambien `*` o mas `[]` tras el array. */
        while (mut_lex.peek_at(off).kind == TokenKind::STAR)
            ++off;
    }
    // aceptar `T !!name` (BANG_BANG entre tipo y nombre).
    if (mut_lex.peek_at(off).kind == TokenKind::BANG_BANG) ++off;
    const TokenKind nm = mut_lex.peek_at(off).kind;
    // El nombre del campo/metodo/var puede ser un IDENTIFIER o un
    // keyword contextual usado como nombre.  `get` y `set` son
    // contextuales (solo aplican a properties), asi que tambien pueden
    // ser nombres de metodo normales (ej. `HashMap.get`, `Queue.set`).
    // Sin esto, `public V get(K key)` no se reconocia como inicio de
    // metodo porque `get` no era IDENTIFIER.
    if (is_name_token(nm)) return true;
    // Modo diagnostico (solo top-level, donde no hay expression-stmts con
    // los que confundirse): una palabra reservada en posicion de nombre
    // sigue "pareciendo" una declaracion.  Devolver true deja que el
    // caller parsee el tipo y falle sobre el NOMBRE, con el mensaje que
    // explica que el termino esta reservado, en vez de reportar un
    // "se esperaba un tipo" al principio de la linea.
    return allow_reserved_name && is_reserved_keyword(nm);
}

std::unique_ptr<ast::TypeNode> Parser::parse_type_node() {
    // nonnull: prefijo opcional `nonnull T` que marca el tipo
    // como no-null.  Solo afecta semantica del type checker
    // (rechazo de null literal); el lowering trata el tipo igual
    // que una referencia normal.
    // Qualifiers C que preceden al tipo base (`const T`, `volatile T`).  El
    // `const` de un const-var-decl se consume ANTES (statement/decl parser),
    // asi que aqui solo aparece como qualifier DE TIPO.  `const` marca el nivel
    // base como inmutable (const-correctness A); `volatile` se parsea pero se
    // ignora.
    bool base_const = false;
    while (current_.kind == TokenKind::KW_CONST ||
           (current_.kind == TokenKind::IDENTIFIER &&
            current_.lexeme == "volatile")) {
        if (current_.kind == TokenKind::KW_CONST) base_const = true;
        (void)consume();
    }
    bool nonnull = false;
    if (current_.kind == TokenKind::KW_NONNULL) {
        nonnull = true;
        (void)consume();
    }
    // Especificador de tipo ELABORADO estilo C: `struct Tag`, `union Tag`,
    // `enum Tag` como REFERENCIA a un tipo (no definicion inline).  Vesta usa
    // solo el nombre, asi que descartamos el keyword y seguimos con el IDENT.
    // (La forma con `{` -- definicion inline -- la maneja el caller antes.)
    if ((current_.kind == TokenKind::KW_STRUCT ||
         current_.kind == TokenKind::KW_UNION ||
         current_.kind == TokenKind::KW_ENUM) &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
        (void)consume(); // 'struct' / 'union' / 'enum'
    }
    std::unique_ptr<ast::TypeNode> base;
    // closures: `fn(T1, T2, ...) -> R` produce un FunctionTypeNode.
    // Si el usuario omite la flecha @c -> el return_type queda como
    // PrimitiveTypeNode(VOID) para mantener un tipo siempre presente
    // (simplifica el type checker, que no tiene que manejar null).
    if (current_.kind == TokenKind::KW_FN ||
        current_.kind == TokenKind::KW_CFN) {
        const bool is_raw = (current_.kind == TokenKind::KW_CFN);
        const SourceLoc loc = current_.loc;
        (void)consume(); // 'fn' / 'cfn'
        (void)expect(TokenKind::LPAREN,
                     is_raw ? "se esperaba '(' tras 'cfn' en puntero a funcion"
                            : "se esperaba '(' tras 'fn' en tipo de funcion");
        auto fn = std::make_unique<ast::FunctionTypeNode>();
        fn->loc = loc;
        fn->is_raw = is_raw; // cfn(...) -> puntero a funcion crudo (8 bytes)
        // Parametros: lista de tipos separados por coma.  Vacio para
        // `fn() -> R`.  No se admiten nombres aqui (un type-node solo
        // describe la firma, no introduce parametros con nombre).  Cada tipo
        // puede llevar `register("rXX")` delante: la ABI custom forma parte del
        // tipo (dos cfn con ABIs distintas son tipos incompatibles).
        bool any_abi = false;
        bool any_dir = false;
        while (current_.kind != TokenKind::RPAREN &&
               current_.kind != TokenKind::END_OF_FILE) {
            /* La direccion tambien va DENTRO del tipo: `cfn(in T*) -> R`.
             * Se lee antes que la ABI porque va delante, igual que en una
             * declaracion. */
            const ParamDir dir = parse_opt_param_dir_();
            if (dir != ParamDir::None) any_dir = true;
            std::string abi = parse_opt_param_reg();
            if (!abi.empty()) any_abi = true;
            auto pt = parse_type_node();
            if (!pt) break;
            /* `fn(T...) -> R`: el ultimo recoge los que sobren.  Se escribe
             * igual que en una declaracion de parametros, para que el tipo se
             * lea como lo que nombra. */
            if (current_.kind == TokenKind::DOTDOTDOT) {
                (void)consume();
                fn->is_variadic = true;
            }
            fn->param_types.push_back(std::move(pt));
            fn->param_abi_regs.push_back(std::move(abi));
            fn->param_dirs.push_back(dir);
            if (!match(TokenKind::COMMA)) break;
        }
        // Normalizar: si ningun param declaro ABI custom, dejar el vector vacio
        // (== ABI estandar; el operator== de Type ya trata vacio == todo-"").
        if (!any_abi) fn->param_abi_regs.clear();
        if (!any_dir) fn->param_dirs.clear();
        (void)expect(
            TokenKind::RPAREN,
            "se esperaba ')' al cerrar los parametros del tipo funcion");
        // Flecha de retorno opcional.  Si no esta, asumimos void.
        if (current_.kind == TokenKind::ARROW) {
            (void)consume(); // '->'
            fn->return_type = parse_type_node();
            if (!fn->return_type) {
                error_here("se esperaba un tipo tras '->' en tipo funcion");
                return nullptr;
            }
        } else {
            // Insertar VOID por defecto para no propagar nulls al type checker.
            auto v = std::make_unique<ast::PrimitiveTypeNode>();
            v->loc = loc;
            v->prim = PrimitiveKind::VOID;
            fn->return_type = std::move(v);
        }
        base = std::move(fn);
    }
    // Caso 1: tipo primitivo via keyword (i32, u8, f64, ...).
    else if (const PrimitiveKind k = primitive_kind_from_token(current_.kind);
             k != PrimitiveKind::COUNT) {
        auto pt = std::make_unique<ast::PrimitiveTypeNode>();
        pt->loc = current_.loc;
        pt->prim = k;
        (void)consume();
        // generics para colecciones primitivas.  Aceptamos
        // type args opcionales tras el keyword de tipo coleccion:
        //   ArrayList<T>     prim=ARRAYLIST, type_args=[T]
        //   HashMap<K,V>     prim=HASHMAP,   type_args=[K,V]
        //   etc.
        // El type checker propaga estos type args al `Type` semantico
        // como `pointee` (1er arg) y `pointee2` (2do arg) -- mismo
        // mecanismo que Optional<T> y Result<V,E>.
        if (current_.kind == TokenKind::LT) {
            // Solo aceptamos type args para tipos de coleccion o smart
            // pointers (unique<T> / shared<T>).
            const bool is_col =
                (k == PrimitiveKind::ARRAYLIST || k == PrimitiveKind::HASHMAP ||
                 k == PrimitiveKind::HASHSET || k == PrimitiveKind::QUEUE ||
                 k == PrimitiveKind::DEQUE || k == PrimitiveKind::TREEMAP ||
                 k == PrimitiveKind::TREESET || k == PrimitiveKind::STACK);
            const bool is_smart_ptr =
                (k == PrimitiveKind::UNIQUE_PTR ||
                 k == PrimitiveKind::SHARED_PTR || k == PrimitiveKind::GC_PTR);
            const bool is_borrow =
                (k == PrimitiveKind::BORROW || k == PrimitiveKind::BORROW_MUT);
            if (is_col || is_smart_ptr || is_borrow) {
                (void)consume(); // '<'
                while (current_.kind != TokenKind::GT &&
                       current_.kind != TokenKind::END_OF_FILE) {
                    auto ta = parse_type_node();
                    if (!ta) break;
                    pt->type_args.push_back(std::move(ta));
                    if (!match(TokenKind::COMMA)) break;
                }
                (void)expect_close_angle(
                    "se esperaba '>' al cerrar argumentos de tipo");
            }
            // Si no es coleccion, dejamos el '<' para que el caller
            // lo trate como BinaryOp comparison (ej. en `i32 a = ...; a < b`).
        }
        base = std::move(pt);
    } else if (current_.kind == TokenKind::IDENTIFIER &&
               current_.lexeme == "VirtualPtr") {
        // Caso especial: VirtualPtr<T> es una direccion VM al contenido T.
        // Lo desazucaramos a PointerTypeNode con `is_virtual=true`.  Sin
        // añadir keyword nuevo: el lexer trata VirtualPtr como un
        // identificador comun, y parse_type lo intercepta aqui antes de
        // la rama generica de NamedTypeNode.
        const SourceLoc vloc = current_.loc;
        (void)consume(); // VirtualPtr
        (void)expect(TokenKind::LT, "se esperaba '<' tras VirtualPtr");
        auto inner = parse_type_node();
        if (!inner) {
            error_here("se esperaba un tipo dentro de VirtualPtr<...>");
            return nullptr;
        }
        (void)expect_close_angle("se esperaba '>' al cerrar VirtualPtr<...>");
        auto pn = std::make_unique<ast::PointerTypeNode>();
        pn->loc = vloc;
        pn->pointee = std::move(inner);
        pn->is_virtual = true;
        base = std::move(pn);
    } else if (current_.kind == TokenKind::IDENTIFIER) {
        // Caso 2: tipo nombrado via identificador (alias de typedef/using
        // o struct).  La resolucion al tipo subyacente la hace el type
        // checker; aqui solo guardamos el nombre tal cual.
        auto nt = std::make_unique<ast::NamedTypeNode>();
        nt->loc = current_.loc;
        nt->name = consume().lexeme;
        //  M.7.c: namespace qualified type (`ui.Button`).
        // Si seguidos vienen `.IDENT`, concatenamos al nombre con
        // separador `.` que el type checker traduce a mangled
        // `ui__Button` al resolver via imported_namespaces_.
        while (current_.kind == TokenKind::DOT &&
               lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
            (void)consume(); // '.'
            nt->name += ".";
            nt->name += consume().lexeme;
        }
        // si despues del nombre viene `<`, parseamos
        // type args.  En contexto de tipo no hay ambiguedad: `<` solo
        // puede iniciar argumentos de tipo aqui.  Aceptamos uno o mas
        // tipos separados por coma, terminados en `>`.
        if (current_.kind == TokenKind::LT) {
            (void)consume(); // '<'
            while (current_.kind != TokenKind::GT &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto ta = parse_type_node();
                if (!ta) break;
                nt->type_args.push_back(std::move(ta));
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect_close_angle(
                "se esperaba '>' al cerrar argumentos de tipo");
        }
        base = std::move(nt);
    } else {
        error_here("se esperaba un tipo");
        // Sincronizacion: consumir el token de error para que el caller
        // no vuelva a procesarlo y entre en bucle infinito (caso clasico:
        // `fn name(p: i64)` con sintaxis Rust-style en params).  Sin
        // esto, parse_param/etc llaman a parse_type_node repetidamente
        // sobre el mismo token y el vector de params crece sin limite
        // -> RAM exhaustion.
        if (current_.kind != TokenKind::END_OF_FILE &&
            current_.kind != TokenKind::RBRACE &&
            current_.kind != TokenKind::RPAREN &&
            current_.kind != TokenKind::SEMICOLON &&
            current_.kind != TokenKind::COMMA) {
            (void)consume();
        }
        return nullptr;
    }
    // const del nivel BASE (`const char`): marca el nodo del tipo apuntado.
    if (base && base_const) base->is_const = true;
    // Postfix: cada '*' apila un PointerTypeNode adicional.
    // Ejemplo: 'i32**' -> Pointer(Pointer(Primitive(i32))).
    // C permite `const`/`volatile` TRAS cada '*' (`char * const * const`):
    // marca ESE nivel de puntero como const (puntero inmutable).
    while (current_.kind == TokenKind::STAR) {
        const SourceLoc loc = current_.loc;
        (void)consume(); // '*'
        auto pn = std::make_unique<ast::PointerTypeNode>();
        pn->loc = loc;
        pn->pointee = std::move(base);
        while (current_.kind == TokenKind::KW_CONST ||
               (current_.kind == TokenKind::IDENTIFIER &&
                current_.lexeme == "volatile")) {
            if (current_.kind == TokenKind::KW_CONST) pn->is_const = true;
            (void)consume();
        }
        base = std::move(pn);
    }
    // Postfix '[N]' o '[]': arrays nativos.  Aceptamos solo literales
    // enteros (positivos) como tamano fijo; expresiones constantes mas
    // generales llegaran cuando exista un evaluador de constantes.
    // T[] (sin numero) representa un array sin tamano (decay-to-ptr,
    // tipico de parametros de funcion).  Permitimos encadenar para
    // formar i32[3][4] (matriz de 4 filas de 3 columnas... C-style).
    while (current_.kind == TokenKind::LBRACKET) {
        const SourceLoc loc = current_.loc;
        (void)consume(); // '['
        auto an = std::make_unique<ast::ArrayTypeNode>();
        an->loc = loc;
        an->element_type = std::move(base);
        if (current_.kind != TokenKind::RBRACKET) {
            an->size_expr = parse_expr();
        }
        (void)expect(TokenKind::RBRACKET,
                     "se esperaba ']' al cerrar el tamano del array");
        base = std::move(an);
    }
    /* Declarador ABSTRACTO de puntero a funcion al estilo de C: `R (*)(T)`, o
     * sea el mismo `R (*f)(T)` sin nombre.  Nombra un TIPO, no declara nada, y
     * hace falta para escribirlo dentro de otro tipo -- un parametro de un tipo
     * funcion, un cast --.  Solo se toma la forma SIN nombre: la que lo lleva
     * la leen quienes ademas declaran algo, que son los que tienen donde
     * guardarlo. */
    if (base && current_.kind == TokenKind::LPAREN) {
        Lexer &ml = const_cast<Lexer &>(lex_);
        size_t off = 0;
        while (ml.peek_at(off).kind == TokenKind::STAR)
            ++off;
        const bool abstracto = off > 0 &&
                               ml.peek_at(off).kind == TokenKind::RPAREN &&
                               ml.peek_at(off + 1).kind == TokenKind::LPAREN;
        if (abstracto) {
            std::string sin_nombre;
            std::unique_ptr<ast::TypeNode> fp;
            if (try_parse_c_func_ptr_(base, sin_nombre, fp))
                base = std::move(fp);
        }
    }
    if (base) base->is_nonnull = nonnull;
    return base;
}

// -----------------------------------------------------------------
// typedef y using: alias de tipos.
//
// typedef:  typedef <tipo> <nombre> ;     (estilo C clasico)
// using:    using   <nombre> = <tipo> ;   (estilo C++ moderno)
//
// Ambos producen el mismo AST node TypeAliasDecl.  La forma se
// preserva en is_using_form solo para diagnosticos.
// -----------------------------------------------------------------

// Deep-clone minimal de un TypeNode (Named/Primitive/Pointer/Array). Suficiente
// para replicar el tipo base de un typedef C-style en cada declarador extra.
static std::unique_ptr<ast::TypeNode>
clone_type_node_td_(const ast::TypeNode *t) {
    if (!t) return nullptr;
    switch (t->kind) {
    case ast::NodeKind::PrimitiveTypeNode: {
        auto *s = static_cast<const ast::PrimitiveTypeNode *>(t);
        auto p = std::make_unique<ast::PrimitiveTypeNode>();
        p->loc = s->loc;
        p->prim = s->prim;
        for (auto &ta : s->type_args)
            p->type_args.push_back(clone_type_node_td_(ta.get()));
        return p;
    }
    case ast::NodeKind::NamedTypeNode: {
        auto *s = static_cast<const ast::NamedTypeNode *>(t);
        auto p = std::make_unique<ast::NamedTypeNode>();
        p->loc = s->loc;
        p->name = s->name;
        for (auto &ta : s->type_args)
            p->type_args.push_back(clone_type_node_td_(ta.get()));
        return p;
    }
    case ast::NodeKind::PointerTypeNode: {
        auto *s = static_cast<const ast::PointerTypeNode *>(t);
        auto p = std::make_unique<ast::PointerTypeNode>();
        p->loc = s->loc;
        p->pointee = clone_type_node_td_(s->pointee.get());
        p->is_virtual = s->is_virtual;
        return p;
    }
    case ast::NodeKind::ArrayTypeNode: {
        auto *s = static_cast<const ast::ArrayTypeNode *>(t);
        auto p = std::make_unique<ast::ArrayTypeNode>();
        p->loc = s->loc;
        p->element_type = clone_type_node_td_(s->element_type.get());
        return p;
    }
    default: return nullptr;
    }
}

// Quita todos los niveles de puntero envolventes de un TypeNode: `LONG**` ->
// `LONG`.  Devuelve un puntero al nodo base interno (no toma ownership).
static const ast::TypeNode *strip_pointers_td_(const ast::TypeNode *t) {
    while (t && t->kind == ast::NodeKind::PointerTypeNode)
        t = static_cast<const ast::PointerTypeNode *>(t)->pointee.get();
    return t;
}

bool Parser::try_parse_c_func_ptr_(std::unique_ptr<ast::TypeNode> &ret,
                                   std::string &out_name,
                                   std::unique_ptr<ast::TypeNode> &out_type) {
    // Patron: `( '*'+ IDENT ) (`.  Lookahead sin consumir hasta confirmarlo.
    if (current_.kind != TokenKind::LPAREN) return false;
    Lexer &ml = const_cast<Lexer &>(lex_);
    size_t off = 0;
    int stars = 0;
    while (ml.peek_at(off).kind == TokenKind::STAR) {
        ++off;
        ++stars;
    }
    if (stars == 0)
        return false; // `(algo` que no empieza por '*' no es func-ptr
    /* El nombre es OPCIONAL: con el, `R (*f)(T)` DECLARA algo; sin el,
     * `R (*)(T)` NOMBRA un tipo -- el declarador abstracto de C --, que es lo
     * que hace falta para escribirlo dentro de otro tipo, en un cast o como
     * parametro de un tipo funcion.  Sin esta rama, un puntero a funcion al
     * estilo de C solo se podia escribir donde ademas se le daba nombre. */
    const bool has_name = (ml.peek_at(off).kind == TokenKind::IDENTIFIER);
    if (has_name) ++off; // el nombre
    if (ml.peek_at(off).kind != TokenKind::RPAREN) return false;
    ++off; // ')'
    if (ml.peek_at(off).kind != TokenKind::LPAREN)
        return false; // '(' de params
    // Confirmado.  Consumir: '(' '*'... [IDENT] ')'.
    (void)consume(); // '('
    for (int i = 0; i < stars; ++i)
        (void)consume(); // '*'...
    if (has_name) out_name = consume().lexeme;
    (void)expect(TokenKind::RPAREN,
                 "se esperaba ')' en el declarador de puntero a funcion");
    (void)expect(TokenKind::LPAREN,
                 "se esperaba '(' con los parametros del puntero a funcion");
    auto fn = std::make_unique<ast::FunctionTypeNode>();
    fn->loc = ret ? ret->loc : SourceLoc{};
    fn->is_raw = true; // puntero a funcion crudo (cfn, 8 bytes)
    fn->return_type = std::move(ret);
    // Lista de parametros: tipos separados por coma.  Aceptamos `void` solo
    // (C: sin parametros) descartandolo.  Nombres de parametro opcionales
    // (estilo C `R (*f)(int a, int b)`) se ignoran.
    if (!(current_.kind == TokenKind::KW_VOID &&
          ml.peek_at(0).kind == TokenKind::RPAREN)) {
        bool any_abi = false;
        bool any_dir = false;
        while (current_.kind != TokenKind::RPAREN &&
               current_.kind != TokenKind::END_OF_FILE) {
            /* La direccion tambien va DENTRO del tipo: `cfn(in T*) -> R`.
             * Se lee antes que la ABI porque va delante, igual que en una
             * declaracion. */
            const ParamDir dir = parse_opt_param_dir_();
            if (dir != ParamDir::None) any_dir = true;
            std::string abi = parse_opt_param_reg();
            if (!abi.empty()) any_abi = true;
            auto pt = parse_type_node();
            if (!pt) break;
            // Nombre de parametro opcional (se descarta).
            if (current_.kind == TokenKind::IDENTIFIER) (void)consume();
            fn->param_types.push_back(std::move(pt));
            fn->param_abi_regs.push_back(std::move(abi));
            fn->param_dirs.push_back(dir);
            if (!match(TokenKind::COMMA)) break;
        }
        if (!any_abi) fn->param_abi_regs.clear();
        if (!any_dir) fn->param_dirs.clear();
    } else {
        (void)consume(); // 'void'
    }
    (void)expect(TokenKind::RPAREN,
                 "se esperaba ')' al cerrar los parametros del puntero a "
                 "funcion");
    out_type = std::move(fn);
    return true;
}

std::unique_ptr<ast::StructDecl> Parser::parse_inline_anon_aggregate_() {
    const bool is_union = (current_.kind == TokenKind::KW_UNION);
    const SourceLoc loc = current_.loc;
    (void)consume(); // 'struct' / 'union'
    // Tag opcional (ignorado): `struct _FOO { ... }`.
    if (current_.kind == TokenKind::IDENTIFIER &&
        lex_.peek_at(0).kind == TokenKind::LBRACE) {
        (void)consume();
    }
    (void)expect(TokenKind::LBRACE, "se esperaba '{' en el agregado anonimo");
    auto s = std::make_unique<ast::StructDecl>();
    s->loc = loc;
    s->is_union = is_union;
    s->name = "__anon" + std::to_string(anon_aggr_counter_++);
    declared_structs_.insert(s->name);
    // Cuerpo: campos `T name [array] [: bits] ;` + agregados anidados.
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        // Agregado anonimo anidado.
        if ((current_.kind == TokenKind::KW_STRUCT ||
             current_.kind == TokenKind::KW_UNION) &&
            (lex_.peek_at(0).kind == TokenKind::LBRACE ||
             (lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
              lex_.peek_at(1).kind == TokenKind::LBRACE))) {
            auto nested = parse_inline_anon_aggregate_();
            const std::string nname = nested->name;
            pending_before_decls_.push_back(std::move(nested));
            ast::StructFieldDecl f;
            f.loc = current_.loc;
            auto nt = std::make_unique<ast::NamedTypeNode>();
            nt->loc = f.loc;
            nt->name = nname;
            f.type = std::move(nt);
            if (current_.kind == TokenKind::IDENTIFIER) {
                f.name = consume().lexeme;
                if (current_.kind == TokenKind::LBRACKET)
                    f.type = wrap_c_array_dims_(std::move(f.type));
            } else {
                f.is_anonymous = true;
                f.name = nname;
            }
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' tras el agregado anonimo");
            s->fields.push_back(std::move(f));
            continue;
        }
        if (!starts_type()) {
            error_here("se esperaba un tipo de campo dentro del agregado");
            synchronize();
            continue;
        }
        ast::StructFieldDecl f;
        f.loc = current_.loc;
        // La direccion va delante del tipo, con el MISMO lector que en un
        // parametro o una variable: si tuviera uno propio, la marca acabaria
        // significando una cosa aqui y otra alli.
        f.dir = parse_opt_param_dir_();
        f.type = parse_type_node();
        if (!f.type) {
            synchronize();
            continue;
        }
        {
            std::string fp_name;
            std::unique_ptr<ast::TypeNode> fp_type;
            if (try_parse_c_func_ptr_(f.type, fp_name, fp_type)) {
                f.type = std::move(fp_type);
                f.name = std::move(fp_name);
                if (current_.kind == TokenKind::LBRACKET)
                    f.type = wrap_c_array_dims_(std::move(f.type));
                (void)expect(TokenKind::SEMICOLON,
                             "se esperaba ';' tras el campo puntero a funcion");
                s->fields.push_back(std::move(f));
                continue;
            }
        }
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un nombre de campo tras el tipo");
            synchronize();
            continue;
        }
        // Clon del tipo BASE para el multi-declarador C `T a, b, c;`.
        auto anon_base_clone = clone_type_node_td_(f.type.get());
        f.name = consume().lexeme;
        if (current_.kind == TokenKind::LBRACKET)
            f.type = wrap_c_array_dims_(std::move(f.type));
        if (current_.kind == TokenKind::COLON) {
            (void)consume();
            if (current_.kind == TokenKind::INT_LIT) {
                f.bit_width = (uint8_t)current_.int_val;
                (void)consume();
            }
        }
        s->fields.push_back(std::move(f));
        // Multi-declarador C `T a, b, c;` dentro del agregado anonimo inline.
        while (current_.kind == TokenKind::COMMA) {
            (void)consume(); // ','
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here("se esperaba el nombre del campo tras ','");
                break;
            }
            ast::StructFieldDecl g;
            g.loc = current_.loc;
            g.type = clone_type_node_td_(anon_base_clone.get());
            g.name = consume().lexeme;
            if (current_.kind == TokenKind::LBRACKET)
                g.type = wrap_c_array_dims_(std::move(g.type));
            if (current_.kind == TokenKind::COLON) {
                (void)consume();
                if (current_.kind == TokenKind::INT_LIT) {
                    g.bit_width = (uint8_t)current_.int_val;
                    (void)consume();
                }
            }
            s->fields.push_back(std::move(g));
        }
        (void)expect(TokenKind::SEMICOLON,
                     "se esperaba ';' al final del campo");
    }
    (void)expect(TokenKind::RBRACE,
                 "se esperaba '}' al cerrar el agregado anonimo");
    return s;
}

std::unique_ptr<ast::TypeNode>
Parser::wrap_c_array_dims_(std::unique_ptr<ast::TypeNode> base) {
    std::vector<std::unique_ptr<ast::Expr>> dims; // null => [] sin acotar
    while (current_.kind == TokenKind::LBRACKET) {
        (void)consume(); // '['
        std::unique_ptr<ast::Expr> n;
        if (current_.kind != TokenKind::RBRACKET) n = parse_expr();
        (void)expect(TokenKind::RBRACKET,
                     "se esperaba ']' en la dimension del array");
        dims.push_back(std::move(n));
    }
    // Envolver de la ULTIMA dimension a la PRIMERA (el primer `[` = mas
    // externo).
    for (auto it = dims.rbegin(); it != dims.rend(); ++it) {
        auto arr = std::make_unique<ast::ArrayTypeNode>();
        arr->loc = base ? base->loc : SourceLoc{};
        arr->element_type = std::move(base);
        arr->size_expr = std::move(*it);
        base = std::move(arr);
    }
    return base;
}

void Parser::parse_c_typedef_ptr_aliases_(const ast::TypeNode *base) {
    // Se entra con current_ == ','.  Cada iteracion: `, [*]* NOMBRE`.
    while (current_.kind == TokenKind::COMMA) {
        (void)consume(); // ','
        int stars = 0;
        while (current_.kind == TokenKind::STAR) {
            (void)consume();
            ++stars;
        }
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un nombre de alias tras ',' en el typedef");
            break;
        }
        const SourceLoc nloc = current_.loc;
        const std::string alias_name = consume().lexeme;
        // Construir el tipo: base clonado + `stars` niveles de puntero.
        std::unique_ptr<ast::TypeNode> ty = clone_type_node_td_(base);
        if (!ty) {
            error_here("typedef C-style: tipo base no clonable para el alias");
            break;
        }
        for (int i = 0; i < stars; ++i) {
            auto p = std::make_unique<ast::PointerTypeNode>();
            p->loc = nloc;
            p->pointee = std::move(ty);
            ty = std::move(p);
        }
        auto a = std::make_unique<ast::TypeAliasDecl>();
        a->loc = nloc;
        a->is_using_form = false;
        a->name = alias_name;
        a->aliased = std::move(ty);
        // Misma visibilidad que el typedef primario (pending_visibility_ sigue
        // vigente; apply_pending_visibility no lo limpia).
        apply_pending_visibility(a.get());
        declared_aliases_.insert(alias_name);
        pending_extra_decls_.push_back(std::move(a));
    }
}

std::unique_ptr<ast::Node>
Parser::parse_typedef_struct_or_enum(bool leading_typedef) {
    // Sintaxis C: `typedef struct { ... } Name;` y
    // `typedef enum { ... } Name;`.  Tag opcional tras struct/enum:
    // `typedef struct Tag { ... } Name;` (Tag se ignora; usamos Name).
    // Cuando leading_typedef=false se acepta la forma sin la palabra `typedef`:
    // `struct { ... } Name, *PName;` (struct C-tagless con el nombre al final).
    const SourceLoc loc_td = current_.loc;
    if (leading_typedef) (void)consume(); // 'typedef'

    const bool is_union = (current_.kind == TokenKind::KW_UNION);
    const bool is_struct = (current_.kind == TokenKind::KW_STRUCT) || is_union;
    const bool is_enum = !is_struct;
    (void)consume(); // 'struct' / 'union' / 'enum'

    // Struct OPACO (forward-decl sin cuerpo): `typedef struct Tag *P, *LP;`.
    // Idioma C de handle opaco.  Se registra `Tag` como un struct INCOMPLETO
    // (sin campos; completable mas tarde definiendo `struct Tag { ... }` que
    // sobrescribe el layout) y se crean los typedefs de puntero (`P = Tag*`).
    // Un puntero a incompleto es valido (8 bytes); derefenciarlo sin completar
    // falla naturalmente (no tiene campos).
    if (is_struct && current_.kind == TokenKind::IDENTIFIER &&
        lex_.peek_at(0).kind == TokenKind::STAR) {
        const SourceLoc tag_loc = current_.loc;
        const std::string tag = consume().lexeme;
        declared_structs_.insert(tag);
        auto incomplete = std::make_unique<ast::StructDecl>();
        incomplete->loc = loc_td;
        incomplete->name = tag;
        incomplete->is_incomplete = true;
        // Base = `Tag`; parsear el PRIMER alias `[*]+ NAME` (empieza con `*`) y
        // luego el resto `, *NAME` con el helper compartido.
        auto base = std::make_unique<ast::NamedTypeNode>();
        base->loc = tag_loc;
        base->name = tag;
        int stars = 0;
        while (current_.kind == TokenKind::STAR) {
            (void)consume();
            ++stars;
        }
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba el nombre del alias de puntero tras "
                       "'typedef struct Tag *'");
        } else {
            const SourceLoc nloc = current_.loc;
            const std::string alias_name = consume().lexeme;
            std::unique_ptr<ast::TypeNode> ty = clone_type_node_td_(base.get());
            for (int i = 0; i < stars; ++i) {
                auto p = std::make_unique<ast::PointerTypeNode>();
                p->loc = nloc;
                p->pointee = std::move(ty);
                ty = std::move(p);
            }
            auto a = std::make_unique<ast::TypeAliasDecl>();
            a->loc = nloc;
            a->is_using_form = false;
            a->name = alias_name;
            a->aliased = std::move(ty);
            apply_pending_visibility(a.get());
            declared_aliases_.insert(alias_name);
            pending_extra_decls_.push_back(std::move(a));
        }
        if (current_.kind == TokenKind::COMMA)
            parse_c_typedef_ptr_aliases_(base.get());
        (void)expect(TokenKind::SEMICOLON,
                     "se esperaba ';' al final del typedef de struct opaco");
        return incomplete;
    }

    // Tag opcional (ignorado; el name real va al final).  En un enum C-style
    // el tag puede ir seguido de `{` o de `:` (tipo base): `typedef enum Tag :
    // int { ... } Name;`.
    if (current_.kind == TokenKind::IDENTIFIER &&
        (lex_.peek_at(0).kind == TokenKind::LBRACE ||
         (is_enum && lex_.peek_at(0).kind == TokenKind::COLON))) {
        (void)consume(); // skip tag
    }

    // Tipo base opcional del enum C-style: `typedef enum : u8 { ... } Name;`.
    // Si no se especifica un `: tipo`, el enum sigue siendo un conjunto de
    // constantes enteras (NO una tagged union), pero su ancho se INFIERE del
    // rango de valores en el type checker (marca c_style_auto_backing),
    // imitando C: `int`/i32 si todo cabe, ensanchando a u32/i64/u64 si algun
    // valor no cabe.  Esto evita el desbordamiento silencioso de fijar i32
    // (p.ej. valores 0xFFFFFFFF o de 64 bits).
    std::string enum_backing;
    bool enum_auto_backing = false;
    if (is_enum) {
        if (current_.kind == TokenKind::COLON) {
            (void)consume(); // ':'
            auto bt = parse_type_node();
            if (bt && bt->kind == ast::NodeKind::PrimitiveTypeNode) {
                auto *pt = static_cast<ast::PrimitiveTypeNode *>(bt.get());
                enum_backing = primitive_name(pt->prim);
            } else if (bt && bt->kind == ast::NodeKind::NamedTypeNode) {
                enum_backing =
                    static_cast<ast::NamedTypeNode *>(bt.get())->name;
            } else {
                error_here("el tipo base de un enum debe ser un entero "
                           "(u8/.../i64)");
            }
        } else {
            enum_auto_backing = true;
        }
    }

    if (current_.kind != TokenKind::LBRACE) {
        error_here("se esperaba '{' tras typedef struct/enum");
        return nullptr;
    }
    (void)consume(); // '{'

    if (is_struct) {
        auto s = std::make_unique<ast::StructDecl>();
        s->loc = loc_td;
        s->is_union = is_union;
        /* El cuerpo lo analiza el MISMO sitio que la forma con nombre.  Aqui
         * habia una copia -- el comentario decia "reusar" y copiaba -- que se
         * habia quedado en los campos a secas: un metodo, un `private`, un
         * `static` o un destructor escritos asi se rechazaban con un "se
         * esperaba un tipo de campo", sin que nada dijera que esta forma
         * admitia menos que la otra. */
        parse_struct_body_(*s, /*is_overlay=*/false);
        (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar el struct");
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba el nombre del typedef tras '}'");
            return nullptr;
        }
        s->name = consume().lexeme;
        // `typedef struct {...} FOO, *PFOO;`: alias de puntero a la estructura.
        if (current_.kind == TokenKind::COMMA) {
            auto base = std::make_unique<ast::NamedTypeNode>();
            base->loc = s->loc;
            base->name = s->name;
            parse_c_typedef_ptr_aliases_(base.get());
        }
        (void)expect(TokenKind::SEMICOLON,
                     "se esperaba ';' al final del typedef");
        return s;
    }
    // typedef enum { ... } Name;
    auto e = std::make_unique<ast::EnumDecl>();
    e->loc = loc_td;
    e->backing_type = enum_backing;              // vacio si se infiere.
    e->c_style_auto_backing = enum_auto_backing; // C-style: infiere el ancho.
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        ast::EnumVariantDecl v;
        v.loc = current_.loc;
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba el nombre de una variante de enum");
            synchronize();
            continue;
        }
        v.name = consume().lexeme;
        if (current_.kind == TokenKind::LPAREN) {
            (void)consume();
            while (current_.kind != TokenKind::RPAREN &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto pt = parse_type_node();
                if (!pt) break;
                v.field_types.push_back(std::move(pt));
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' al cerrar payload");
        } else if (current_.kind == TokenKind::ASSIGN) {
            // C-style: valor entero explicito `A = 0x01`.  El checker lo pliega
            // a constante del tipo base y auto-incrementa los siguientes.
            (void)consume(); // '='
            v.value_expr = parse_expr();
        }
        e->variants.push_back(std::move(v));
        if (!match(TokenKind::COMMA)) break;
    }
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar el enum");
    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba el nombre del typedef tras '}'");
        return nullptr;
    }
    e->name = consume().lexeme;
    // `typedef enum {...} FOO, *PFOO;`: alias de puntero al enum.
    if (current_.kind == TokenKind::COMMA) {
        auto base = std::make_unique<ast::NamedTypeNode>();
        base->loc = e->loc;
        base->name = e->name;
        parse_c_typedef_ptr_aliases_(base.get());
    }
    (void)expect(TokenKind::SEMICOLON, "se esperaba ';' al final del typedef");
    return e;
}

std::unique_ptr<ast::TypeAliasDecl> Parser::parse_typedef_decl() {
    auto a = std::make_unique<ast::TypeAliasDecl>();
    a->loc = current_.loc;
    a->is_using_form = false;
    (void)consume(); // 'typedef'

    if (!starts_type()) {
        error_here("se esperaba un tipo tras 'typedef'");
        return nullptr;
    }
    a->aliased = parse_type_node();
    if (!a->aliased) return nullptr;

    // typedef de PUNTERO A FUNCION C: `typedef R (*NAME)(params);`.
    {
        std::string fp_name;
        std::unique_ptr<ast::TypeNode> fp_type;
        if (try_parse_c_func_ptr_(a->aliased, fp_name, fp_type)) {
            a->name = std::move(fp_name);
            a->aliased = std::move(fp_type);
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' al final del typedef de puntero a "
                         "funcion");
            declared_aliases_.insert(a->name);
            return a;
        }
    }

    if (!is_name_token(current_.kind)) {
        error_expected_name("nombre de tipo en 'typedef'",
                            "se esperaba un nombre tras el tipo en 'typedef'");
        return nullptr;
    }
    a->name = consume().lexeme;
    // Newtype + opaque + align + explicit from/to (extension 2026-05-23):
    //   typedef u64 ptr new;
    //   typedef u64 ptr new @opaque;
    //   typedef u8  v   new @align(16);            // SIMD alignment
    //   typedef u64 fd  new @opaque {              // bloque de conversiones
    //       explicit from u64;                     // cast (fd) raw -- privado
    //       al fichero public explicit to u64;                // cast (u64) f
    //       -- cross-file ok
    //   }
    // El `new` reutiliza el keyword existente.  `@opaque` y `@align(N)`
    // se parsean como anotaciones contextuales en cualquier orden.
    if (current_.kind == TokenKind::KW_NEW) {
        (void)consume();
        a->is_newtype = true;
        // Loop sobre anotaciones contextuales @opaque / @align(N).
        while (current_.kind == TokenKind::AT) {
            (void)consume(); // '@'
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here("se esperaba nombre de anotacion tras '@'");
                break;
            }
            const std::string ann = current_.lexeme;
            (void)consume();
            if (ann == "opaque") {
                a->is_opaque = true;
            } else if (ann == "align") {
                (void)expect(TokenKind::LPAREN,
                             "se esperaba '(' tras '@align'");
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here("@align(N) requiere un entero literal");
                    break;
                }
                const uint64_t n = current_.int_val;
                (void)consume();
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras N en @align(N)");
                // Validar potencia de 2 en [1, 4096].
                if (n == 0 || n > 4096 || (n & (n - 1)) != 0) {
                    error_here(
                        "@align(N): N debe ser potencia de 2 en [1, 4096]");
                } else {
                    a->align_override = static_cast<uint16_t>(n);
                }
            } else {
                error_here(("anotacion desconocida tras 'new': '@" + ann +
                            "'; esperaba '@opaque' o '@align(N)'")
                               .c_str());
                break;
            }
        }
        // Bloque opcional de conversiones explicit from/to.
        if (current_.kind == TokenKind::LBRACE) {
            (void)consume(); // '{'
            while (current_.kind != TokenKind::RBRACE &&
                   current_.kind != TokenKind::END_OF_FILE) {
                bool is_public = false;
                if (current_.kind == TokenKind::KW_PUBLIC) {
                    (void)consume();
                    is_public = true;
                }
                if (current_.kind != TokenKind::IDENTIFIER ||
                    (current_.lexeme != "explicit" &&
                     current_.lexeme != "implicit")) {
                    error_here(
                        "se esperaba 'explicit' o 'implicit' [from|to] T;"
                        " dentro del bloque de typedef");
                    break;
                }
                const bool es_implicita = (current_.lexeme == "implicit");
                (void)consume(); // 'explicit' | 'implicit'
                if (current_.kind != TokenKind::IDENTIFIER ||
                    (current_.lexeme != "from" && current_.lexeme != "to")) {
                    error_here("se esperaba 'from' o 'to' tras "
                               "'explicit'/'implicit'");
                    break;
                }
                const bool is_from = (current_.lexeme == "from");
                (void)consume(); // 'from'|'to'
                if (!starts_type()) {
                    error_here("se esperaba un tipo tras 'from'/'to'");
                    break;
                }
                auto tn = parse_type_node();
                (void)expect(
                    TokenKind::SEMICOLON,
                    "se esperaba ';' al final de 'explicit from/to T'");
                ast::TypeAliasDecl::ExplicitConv ec;
                ec.type = std::move(tn);
                ec.is_public = is_public;
                if (es_implicita) {
                    if (is_from)
                        a->implicit_from.push_back(std::move(ec));
                    else
                        a->implicit_to.push_back(std::move(ec));
                } else if (is_from) {
                    a->explicit_from.push_back(std::move(ec));
                } else {
                    a->explicit_to.push_back(std::move(ec));
                }
            }
            (void)expect(TokenKind::RBRACE,
                         "se esperaba '}' tras el bloque del typedef");
            // Bloque sin punto y coma final: la sintaxis es similar
            // a class/struct.  Aceptar `}` solo sin ';' obligatorio.
            if (current_.kind == TokenKind::SEMICOLON) {
                (void)consume();
            }
            // Item 19 + extension: registrar el alias antes del return
            declared_aliases_.insert(a->name);
            return a;
        }
    }
    // typedef C-style multi-declarador: `typedef LONG *PLONG, *LPLONG;`.
    // El primer alias (a) ya esta parseado (aliased puede incluir sus '*').
    // Para los siguientes el tipo base es `aliased` SIN sus punteros.
    if (current_.kind == TokenKind::COMMA) {
        parse_c_typedef_ptr_aliases_(strip_pointers_td_(a->aliased.get()));
    }
    (void)expect(TokenKind::SEMICOLON, "se esperaba ';' al final de 'typedef'");
    // Item 19: registrar alias para que `looks_like_cast` lo reconozca
    // en `(MyTypedef) x`.
    declared_aliases_.insert(a->name);
    return a;
}

std::unique_ptr<ast::TypeAliasDecl> Parser::parse_using_decl() {
    auto a = std::make_unique<ast::TypeAliasDecl>();
    a->loc = current_.loc;
    a->is_using_form = true;
    (void)consume(); // 'using'

    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba un nombre tras 'using'");
        return nullptr;
    }
    a->name = consume().lexeme;
    (void)expect(TokenKind::ASSIGN,
                 "se esperaba '=' tras el nombre en 'using'");
    if (!starts_type()) {
        error_here("se esperaba un tipo tras '=' en 'using'");
        return nullptr;
    }
    a->aliased = parse_type_node();
    if (!a->aliased) return nullptr;

    (void)expect(TokenKind::SEMICOLON, "se esperaba ';' al final de 'using'");
    declared_aliases_.insert(a->name);
    return a;
}

// -----------------------------------------------------------------
// import: declaracion de importacion de modulo ( M).
//
// Sintaxis aceptada:
//   import "path";
//   import "path" as alias;
//   import "path" only A, B;
//   import "path" only A as A2, B;
//   import "path" as alias only A, B;     <- alias para namespace y only
//                                            para seleccion no se añaden
//                                            al mismo namespace; el alias
//                                            queda inactivo si hay only
//   public import "path" [as alias] [only ...];
//
// El path es siempre un string literal sin interpolacion.  Por
// consistencia con extern "lib.dll", loadmodule(path), y @Method.
// El sufijo .vx se añade automaticamente al resolver.
// -----------------------------------------------------------------
std::unique_ptr<ast::ImportDecl>
Parser::parse_import_decl(bool is_public_reexport) {
    auto im = std::make_unique<ast::ImportDecl>();
    im->loc = current_.loc;
    im->is_public_reexport = is_public_reexport;

    (void)consume(); // 'import'

    //  NS.2-full: dos formas de import.
    //   (a) por-PATH:      import "editor/buffer";   (literal string)
    //   (b) por-NAMESPACE: import a.b.c;             (identificadores
    //   punteados)
    // La forma (b) resuelve el namespace a fichero via el indice de
    // namespaces (escaneo de las cabeceras `namespace` de las source roots).
    if (current_.kind == TokenKind::STRING_LIT ||
        current_.kind == TokenKind::RAW_STRING_LIT) {
        // Forma (a) por-path.  Strings interpolados arrancan con ISTR_BEGIN
        // (no STRING_LIT), asi que el check garantiza que no hay interpolacion.
        im->path = current_.str_val;
        (void)consume();
    } else if (current_.kind == TokenKind::IDENTIFIER) {
        // Forma (b) por-namespace: recolectar el path punteado a.b.c.
        im->by_namespace = true;
        std::string ns = consume().lexeme;
        while (current_.kind == TokenKind::DOT) {
            // `a.b.c.{A, B}` -> el `.{` cierra el path y abre la lista
            // selectiva.
            if (lex_.peek_at(0).kind == TokenKind::LBRACE) break;
            (void)consume(); // '.'
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here("se esperaba un identificador tras '.' en el "
                           "namespace del import");
                return nullptr;
            }
            ns += ".";
            ns += consume().lexeme;
        }
        im->path = std::move(ns);
        // Forma selectiva `.{A, B as C}` (equivalente a `only`).
        if (current_.kind == TokenKind::DOT &&
            lex_.peek_at(0).kind == TokenKind::LBRACE) {
            (void)consume(); // '.'
            (void)consume(); // '{'
            for (;;) {
                if (current_.kind != TokenKind::IDENTIFIER) {
                    error_here("se esperaba un identificador en la lista "
                               "selectiva '.{ ... }' del import");
                    return nullptr;
                }
                ast::ImportDecl::OnlySymbol os;
                os.name = consume().lexeme;
                if (current_.kind == TokenKind::IDENTIFIER &&
                    current_.lexeme == "as") {
                    (void)consume(); // 'as'
                    if (current_.kind != TokenKind::IDENTIFIER) {
                        error_here("se esperaba un identificador tras 'as' en "
                                   "la lista selectiva del import");
                        return nullptr;
                    }
                    os.rename = consume().lexeme;
                }
                // Registrar el nombre efectivo (rename o name) como posible
                // type-alias para que `looks_like_cast` reconozca `(T) x`
                // cuando T es un typedef importado de otro modulo (p.ej.
                // `uintptr` de std.types).  El guard de looks_like_cast (el
                // token tras `)` debe iniciar una expresion) evita misparsear
                // `(fn_importada)(args)`.
                declared_aliases_.insert(os.rename.empty() ? os.name
                                                           : os.rename);
                im->only_symbols.push_back(std::move(os));
                if (current_.kind == TokenKind::COMMA) {
                    (void)consume();
                    continue;
                }
                break;
            }
            (void)expect(TokenKind::RBRACE,
                         "se esperaba '}' al final de la lista selectiva "
                         "'.{ ... }' del import");
        }
    } else {
        error_here("se esperaba un literal string (import \"a/b\";) o un "
                   "namespace punteado (import a.b.c;) tras 'import'");
        return nullptr;
    }

    // Opcional: as alias  (contextual 'as').
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "as") {
        (void)consume(); // 'as'
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un identificador para el alias tras 'as'");
            return nullptr;
        }
        im->alias = consume().lexeme;
    }

    // Opcional: only A [as A2], B [as B2], ...  (contextual 'only').
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "only") {
        (void)consume(); // 'only'
        // `only *` -- glob import: trae TODOS los simbolos publicos del modulo
        // al scope (estilo Rust `use ns::*;`).  Con `public import` ademas los
        // re-exporta (`pub use ns::*;`).  Evita listar decenas de simbolos
        // (p.ej. los 400+ __NR_* de una tabla de syscalls).
        if (current_.kind == TokenKind::STAR) {
            (void)consume(); // '*'
            im->only_all = true;
        } else
            for (;;) {
                if (current_.kind != TokenKind::IDENTIFIER) {
                    error_here("se esperaba un identificador o '*' en la lista "
                               "'only'");
                    return nullptr;
                }
                ast::ImportDecl::OnlySymbol os;
                os.name = consume().lexeme;
                if (current_.kind == TokenKind::IDENTIFIER &&
                    current_.lexeme == "as") {
                    (void)consume(); // 'as'
                    if (current_.kind != TokenKind::IDENTIFIER) {
                        error_here(
                            "se esperaba un identificador tras 'as' en 'only'");
                        return nullptr;
                    }
                    os.rename = consume().lexeme;
                }
                // Ver nota en la forma selectiva `.{...}`: el nombre efectivo
                // se registra como posible type-alias para reconocer `(T) x`
                // con T importado (typedef cross-modulo, p.ej. `uintptr`).
                declared_aliases_.insert(os.rename.empty() ? os.name
                                                           : os.rename);
                im->only_symbols.push_back(std::move(os));
                if (current_.kind == TokenKind::COMMA) {
                    (void)consume();
                    continue;
                }
                break;
            }
    }

    (void)expect(TokenKind::SEMICOLON, "se esperaba ';' al final de 'import'");

    // Registrar el segmento accesor del namespace para que `looks_like_cast`
    // reconozca un cast al tipo cualificado `(ns.Tipo) x`.  El accesor es el
    // alias (`import a.b.c as x;` -> `x`) o el ultimo segmento del path
    // (`import a.b.c;` -> `c`; forma por-path `import "a/b/c";` -> `c`).  Se
    // registra para AMBAS formas (with/without `only`): el acceso cualificado
    // `ns.Tipo` es valido aunque el import traiga tambien simbolos desnudos.
    {
        std::string accessor = im->alias;
        if (accessor.empty()) {
            const std::string &p = im->path;
            // Ultimo segmento tras '.' (namespace) o '/' (path).
            size_t cut = p.find_last_of("./");
            accessor = (cut == std::string::npos) ? p : p.substr(cut + 1);
        }
        if (!accessor.empty()) imported_namespaces_.insert(accessor);
    }
    return im;
}

// -----------------------------------------------------------------
// namespace: agrupacion inline estilo C++ ( M.7.c).
//
//   namespace foo {
//       class Button { ... }
//       struct Point { ... }
//       i32 helper() { ... }
//   }
//
// Soporta anidamiento:
//   namespace a { namespace b { class C {} } }
//
// El contenido se parsea con parse_top_level_decl recursivamente; el
// pre-pass de mangling (compiler_project.cpp::mangle_top_level_)
// recorrera el AST añadiendo el prefijo `foo__` a todos los nombres.
// -----------------------------------------------------------------
std::unique_ptr<ast::NamespaceDecl> Parser::parse_namespace_decl() {
    auto ns = std::make_unique<ast::NamespaceDecl>();
    ns->loc = current_.loc;
    (void)consume(); // 'namespace'

    //  NS.1: nombre con PATH punteado (a.b.c).  Se almacena como texto
    // punteado en @c name; el mangling posterior lo parte por '.' y une con
    // '__' (std.collections -> std__collections).
    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba el nombre del namespace tras 'namespace'");
        return nullptr;
    }
    std::string path = consume().lexeme;
    while (current_.kind == TokenKind::DOT) {
        (void)consume(); // '.'
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un identificador tras '.' en el path del "
                       "namespace");
            return nullptr;
        }
        path += ".";
        path += consume().lexeme;
    }
    ns->name = path;

    //  NS.3: override opcional de PackageId: `namespace X @id("...")`.
    // Permite renombrar el namespace manteniendo la identidad ABI.
    if (current_.kind == TokenKind::AT &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
        lex_.peek_at(0).lexeme == "id") {
        (void)consume(); // '@'
        (void)consume(); // 'id'
        (void)expect(TokenKind::LPAREN, "se esperaba '(' tras '@id'");
        if (current_.kind != TokenKind::STRING_LIT &&
            current_.kind != TokenKind::RAW_STRING_LIT) {
            error_here("se esperaba un literal string en '@id(\"...\")'");
            return nullptr;
        }
        ns->package_id_override = current_.str_val;
        (void)consume();
        (void)expect(TokenKind::RPAREN, "se esperaba ')' tras el id de '@id'");
    }

    //  NS.1: forma STATEMENT `namespace a.b.c;` -- aplica al RESTO del
    // fichero (recoge las decls top-level siguientes hasta el proximo
    // `namespace` statement o EOF).  La forma BLOQUE `namespace a.b.c { ... }`
    // acota las decls con llaves (permite varios namespaces por fichero y
    // anidamiento).  Ambas producen un @c NamespaceDecl con @c decls anidadas.
    if (current_.kind == TokenKind::SEMICOLON) {
        (void)consume(); // ';'
        ns->is_statement_form = true;
        while (current_.kind != TokenKind::END_OF_FILE &&
               current_.kind != TokenKind::KW_NAMESPACE) {
            // extern "lib" { fn ...; } produce N decls (una por fn);
            // parse_program lo maneja como caso especial y parse_top_level_decl
            // NO -> replicarlo aqui para que un `extern` dentro de un namespace
            // funcione.
            if (current_.kind == TokenKind::KW_EXTERN) {
                ast::ModuleNode tmp;
                parse_extern_block(tmp);
                for (auto &d : tmp.decls)
                    ns->decls.push_back(std::move(d));
                continue;
            }
            const uint32_t inner_start = current_.loc.offset;
            auto inner = parse_top_level_decl();
            if (!inner) {
                // L.24: skip intencional via @Target no matcheado -- la decl ya
                // fue consumida por skip_target_skipped_decl; NO sincronizar
                // (igual que parse_program), o nos comeriamos la siguiente
                // decl.
                if (last_decl_was_target_skip_) continue;
                synchronize();
                // synchronize se para en KW_NAMESPACE/EOF (fin de este ns) o en
                // el siguiente keyword aprovechable; el bucle re-evalua.
                if (current_.kind == TokenKind::KW_NAMESPACE ||
                    current_.kind == TokenKind::END_OF_FILE)
                    break;
                continue;
            }
            // NS.2: exportar plantillas/concepts namespaced cross-module.
            /* Las sintetizadas, con el tramo de la decl que las genero.  Va
             * tambien aqui: la mitad de la stdlib vive dentro de un
             * `namespace`, y sin esto sus `typedef` se quedaban sin fuente. */
            for (auto &b : pending_before_decls_) {
                if (current_.loc.offset > inner_start) {
                    b->span_start = inner_start;
                    b->span_end = current_.loc.offset;
                }
                ns->decls.push_back(std::move(b));
            }
            pending_before_decls_.clear();
            collect_template_export_(tpl_export_mod_, inner.get(), inner_start);
            /* @copydoc ModuleNode::decl_end_offset -- tambien dentro de un
             * `namespace`, que es donde vive la mitad de la stdlib. */
            if (current_.loc.offset > inner_start) {
                inner->span_start = inner_start;
                inner->span_end = current_.loc.offset;
            }
            ns->decls.push_back(std::move(inner));
            // Drenar aliases extra de un typedef C-style multi-declarador.
            /// @copydoc pending_before_decls_ (mismo criterio)
            for (auto &e : pending_extra_decls_) {
                if (current_.loc.offset > inner_start) {
                    e->span_start = inner_start;
                    e->span_end = current_.loc.offset;
                }
                ns->decls.push_back(std::move(e));
            }
            pending_extra_decls_.clear();
        }
        return ns;
    }

    (void)expect(TokenKind::LBRACE,
                 "se esperaba '{' o ';' tras el nombre del namespace");

    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        // extern "lib" { ... } dentro del namespace (ver forma statement
        // arriba).
        if (current_.kind == TokenKind::KW_EXTERN) {
            ast::ModuleNode tmp;
            parse_extern_block(tmp);
            for (auto &d : tmp.decls)
                ns->decls.push_back(std::move(d));
            continue;
        }
        const uint32_t inner_start = current_.loc.offset;
        auto inner = parse_top_level_decl();
        if (!inner) {
            // L.24: skip intencional via @Target no matcheado (ver forma
            // statement arriba) -- NO sincronizar.
            if (last_decl_was_target_skip_) continue;
            // Error de parse en una decl interna -- skipear hasta el
            // siguiente token aprovechable para no quedarnos en bucle.
            synchronize();
            continue;
        }
        // NS.2: exportar plantillas/concepts namespaced cross-module.
        collect_template_export_(tpl_export_mod_, inner.get(), inner_start);
        /// @copydoc ModuleNode::decl_end_offset
        if (current_.loc.offset > inner_start) {
            inner->span_start = inner_start;
            inner->span_end = current_.loc.offset;
        }
        ns->decls.push_back(std::move(inner));
    }
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al final del namespace");
    return ns;
}

// -----------------------------------------------------------------
// bytes: bloque de datos crudos estilo NASM ( AOT).
//
//   bytes name {
//       db 0x55, 'A', "texto"     ; 1 byte por operando (string -> bytes)
//       dw 0x1234                  ; 2 bytes LE
//       dd 0xDEADBEEF              ; 4 bytes LE
//       dq 0x1122334455667788      ; 8 bytes LE
//       times 16 db 0             ; repite la directiva N veces
//   }
//
// v1 (Inc 1): solo literales (enteros, char, string en db).  Las
// referencias a simbolos (relocs) llegan en un incremento posterior.
// Los operandos de una misma directiva se separan con coma; las
// directivas entre si no necesitan separador (el lexer ignora saltos
// de linea, asi que se delimitan por el siguiente keyword db/dw/...).
// -----------------------------------------------------------------
std::unique_ptr<ast::BytesDecl> Parser::parse_bytes_decl() {
    auto bd = std::make_unique<ast::BytesDecl>();
    bd->loc = current_.loc;
    (void)consume(); // 'bytes'

    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba el nombre del bloque tras 'bytes'");
        return nullptr;
    }
    bd->name = consume().lexeme;
    (void)expect(TokenKind::LBRACE,
                 "se esperaba '{' tras el nombre del bloque bytes");

    // Ancho en bytes de una directiva de datos.  0 = no es db/dw/dd/dq.
    auto width_of = [](const std::string &d) -> int {
        if (d == "db") return 1;
        if (d == "dw") return 2;
        if (d == "dd") return 4;
        if (d == "dq") return 8;
        return 0;
    };

    // Emite una directiva de datos (db/dw/dd/dq) hacia @c out.  El token
    // actual es el identificador de la directiva.  @c refs (si no es nullptr)
    // recibe las referencias a simbolos (operandos identificador, p.ej.
    // `dq main`); su offset se calcula relativo a @c base_off (= inicio del
    // blob).  En el contexto @c times no se permiten refs (refs==nullptr).
    // Devuelve false si hay un error de sintaxis.
    auto emit_data_dir = [&](std::vector<uint8_t> &out, uint32_t base_off,
                             std::vector<ast::BytesSymRef> *refs) -> bool {
        const int w = width_of(current_.lexeme);
        if (w == 0) {
            error_here("se esperaba una directiva de datos (db/dw/dd/dq)");
            return false;
        }
        (void)consume(); // db/dw/dd/dq
        // Al menos un operando.
        for (;;) {
            if (current_.kind == TokenKind::INT_LIT ||
                current_.kind == TokenKind::CHAR_LIT) {
                const uint64_t v = current_.int_val;
                (void)consume();
                for (int i = 0; i < w; ++i)
                    out.push_back((uint8_t)(v >> (8 * i)));
            } else if (current_.kind == TokenKind::MINUS) {
                (void)consume();
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here("se esperaba un entero tras '-' en bytes");
                    return false;
                }
                const uint64_t v = (uint64_t)(-(int64_t)current_.int_val);
                (void)consume();
                for (int i = 0; i < w; ++i)
                    out.push_back((uint8_t)(v >> (8 * i)));
            } else if (current_.kind == TokenKind::STRING_LIT ||
                       current_.kind == TokenKind::RAW_STRING_LIT) {
                if (w != 1) {
                    error_here("un literal de cadena solo es valido en 'db'");
                    return false;
                }
                for (unsigned char c : current_.str_val)
                    out.push_back((uint8_t)c);
                (void)consume();
            } else if (current_.kind == TokenKind::IDENTIFIER) {
                // Operando identificador.  El lowering decide su naturaleza:
                //   - comptime const entero  -> literal del ancho de la
                //   directiva.
                //   - comptime array         -> expande sus elementos (width
                //   c/u).
                //   - simbolo de funcion      -> reloc ABS64 (requiere dq).
                // El parser solo registra el nombre + el ancho de la directiva.
                if (refs == nullptr) {
                    error_here("una referencia a simbolo no es valida dentro "
                               "de 'times'");
                    return false;
                }
                ast::BytesSymRef sr;
                sr.offset = base_off + (uint32_t)out.size();
                sr.sym = current_.lexeme;
                sr.width = (uint8_t)w; // 1/2/4/8 segun db/dw/dd/dq
                sr.is_rel = false;
                refs->push_back(std::move(sr));
                (void)consume();
                // Placeholder del ancho de la directiva (el lowering/emisor
                // lo reemplaza por el valor o lo deja para reloc).
                for (int i = 0; i < w; ++i)
                    out.push_back(0);
            } else {
                error_here("se esperaba un operando (entero, char, cadena o "
                           "simbolo) en bytes");
                return false;
            }
            if (current_.kind == TokenKind::COMMA) {
                (void)consume();
                continue;
            }
            break;
        }
        return true;
    };

    // Evaluador de la cuenta de `times`: expresion aritmetica con enteros,
    // `$` (offset actual del bloque), `$$` (inicio del bloque = 0), los
    // operadores + - * / y parentesis.  Permite el idioma NASM
    // `times 510-($-$$) db 0` (rellenar HASTA una posicion).  `$`/`$$` son
    // relativos al bloque (no a la seccion): para un boot sector de un
    // solo bloque coincide con el offset de imagen.
    std::function<int64_t(bool &)> ev_primary, ev_term, ev_expr;
    ev_primary = [&](bool &ok) -> int64_t {
        if (current_.kind == TokenKind::DOLLAR) {
            (void)consume();
            if (current_.kind == TokenKind::DOLLAR) {
                (void)consume();
                return 0;
            } // $$
            return (int64_t)bd->data.size(); // $
        }
        if (current_.kind == TokenKind::MINUS) {
            (void)consume();
            return -ev_primary(ok);
        }
        if (current_.kind == TokenKind::PLUS) {
            (void)consume();
            return ev_primary(ok);
        }
        if (current_.kind == TokenKind::LPAREN) {
            (void)consume();
            int64_t v = ev_expr(ok);
            if (current_.kind != TokenKind::RPAREN) {
                error_here("se esperaba ')' en la cuenta de 'times'");
                ok = false;
                return 0;
            }
            (void)consume();
            return v;
        }
        if (current_.kind == TokenKind::INT_LIT) {
            int64_t v = (int64_t)current_.int_val;
            (void)consume();
            return v;
        }
        error_here(
            "operando invalido en 'times' (use entero, $, $$ o parentesis)");
        ok = false;
        return 0;
    };
    ev_term = [&](bool &ok) -> int64_t {
        int64_t v = ev_primary(ok);
        while (ok && (current_.kind == TokenKind::STAR ||
                      current_.kind == TokenKind::SLASH)) {
            const bool mul = current_.kind == TokenKind::STAR;
            (void)consume();
            const int64_t r = ev_primary(ok);
            if (!ok) return 0;
            if (mul)
                v *= r;
            else {
                if (r == 0) {
                    error_here("division por cero en 'times'");
                    ok = false;
                    return 0;
                }
                v /= r;
            }
        }
        return v;
    };
    ev_expr = [&](bool &ok) -> int64_t {
        int64_t v = ev_term(ok);
        while (ok && (current_.kind == TokenKind::PLUS ||
                      current_.kind == TokenKind::MINUS)) {
            const bool add = current_.kind == TokenKind::PLUS;
            (void)consume();
            const int64_t r = ev_term(ok);
            if (!ok) return 0;
            if (add)
                v += r;
            else
                v -= r;
        }
        return v;
    };

    // Bucle principal de directivas.
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        if (current_.kind == TokenKind::IDENTIFIER &&
            current_.lexeme == "times") {
            (void)consume(); // 'times'
            bool cok = true;
            const int64_t cnt_s = ev_expr(cok);
            if (!cok) break;
            if (cnt_s < 0) {
                error_here("la cuenta de 'times' es negativa (revisa el "
                           "relleno '$-$$')");
                break;
            }
            const uint64_t cnt = (uint64_t)cnt_s;
            std::vector<uint8_t> tmp;
            // refs==nullptr: dentro de 'times' no se admiten refs a simbolos.
            if (!emit_data_dir(tmp, 0, nullptr)) break;
            for (uint64_t k = 0; k < cnt; ++k)
                bd->data.insert(bd->data.end(), tmp.begin(), tmp.end());
        } else if (current_.kind == TokenKind::IDENTIFIER &&
                   width_of(current_.lexeme) > 0) {
            // base_off=0: `out` ES bd->data, asi out.size() ya da el offset
            // absoluto del operando dentro del blob (no sumar de nuevo).
            if (!emit_data_dir(bd->data, 0, &bd->sym_refs)) break;
        } else {
            error_here("se esperaba db/dw/dd/dq/times o '}' en bloque bytes");
            break;
        }
    }
    (void)expect(TokenKind::RBRACE,
                 "se esperaba '}' al final del bloque bytes");
    return bd;
}

// -----------------------------------------------------------------
// asm: bloque de codigo NASM ensamblado por Keystone ( AOT 16/32-bit).
//
//   @bits(16) @section(".boot","rx")
//   asm boot {
//       cli
//       xor ax, ax
//       hang: hlt
//             jmp hang        ; labels intra-bloque (Keystone los resuelve)
//   }
//
// El cuerpo se captura VERBATIM (raw-slice del buffer fuente, preservando
// saltos de linea que NASM necesita) y el lowering lo ensambla a @c asm_bits
// via @c g_asm_backend.  Las directivas $/$$/times NO las soporta Keystone;
// para padding/firma se usa un bloque `bytes` con @at/times.  Reusa toda la
// maquinaria de placement de @c bytes (@section/@at/@order).
// -----------------------------------------------------------------
std::unique_ptr<ast::BytesDecl> Parser::parse_asm_block_decl() {
    auto bd = std::make_unique<ast::BytesDecl>();
    bd->loc = current_.loc;
    bd->is_asm = true;
    (void)consume(); // 'asm'

    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba el nombre del bloque tras 'asm'");
        return nullptr;
    }
    bd->name = consume().lexeme;
    if (current_.kind != TokenKind::LBRACE) {
        error_here("se esperaba '{' tras el nombre del bloque asm");
        return nullptr;
    }
    (void)consume(); // '{'

    // Raw-slice del cuerpo (mismo patron que parse_asm_stmt): preserva los
    // saltos de linea entre instrucciones que el ensamblador necesita.
    const std::string &src = lex_.source_buffer();
    const uint32_t start_off = current_.loc.offset;
    uint32_t end_off = start_off;
    int brace_depth = 1;
    while (current_.kind != TokenKind::END_OF_FILE) {
        if (current_.kind == TokenKind::RBRACE) {
            if (--brace_depth == 0) {
                end_off = current_.loc.offset;
                (void)consume();
                break;
            }
        } else if (current_.kind == TokenKind::LBRACE) {
            ++brace_depth;
        }
        (void)consume();
    }
    if (brace_depth != 0) {
        error_here("se esperaba '}' al cerrar el bloque 'asm'");
        return nullptr;
    }
    while (end_off > start_off && end_off <= src.size() &&
           (src[end_off - 1] == ' ' || src[end_off - 1] == '\t' ||
            src[end_off - 1] == '\n' || src[end_off - 1] == '\r'))
        --end_off;
    if (start_off <= src.size() && end_off >= start_off &&
        end_off <= src.size())
        bd->asm_body = src.substr(start_off, end_off - start_off);
    return bd;
}

// -----------------------------------------------------------------
// struct: declaracion de tipo agregado (value type, sin metodos).
//
// Forma:  struct <nombre> { <tipo> <campo>; <tipo> <campo>; ... }
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// parse_enum_decl + parse_match_expr.
//
// Forma del enum:
//   enum Name {
//       Variant1,
//       Variant2(T),
//       Variant3(T1, T2),
//       ...                   (coma trailing opcional)
//   }
//
// No se admiten valor por defecto ni herencia: los enums Vesta son
// tipos de datos algebraicos planos.  Los tags se asignan
// implicitamente como el indice 0..N-1 de la variante en el bloque.
// -----------------------------------------------------------------

std::unique_ptr<ast::EnumDecl> Parser::parse_enum_decl() {
    auto e = std::make_unique<ast::EnumDecl>();
    e->loc = current_.loc;
    (void)consume(); // 'enum'

    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba un nombre tras 'enum'");
        return nullptr;
    }
    e->name = consume().lexeme;

    // L2.3: generics opcionales `<T>`, `<K, V>` tras el nombre del enum.
    // Mismo patron que parse_class_decl: cada parametro es un identificador
    // simple; el enum se trata como plantilla y se monomorphiza en cada
    // uso `Maybe<i32>` en el type checker.
    if (current_.kind == TokenKind::LT) {
        // #6: cada param puede llevar un bound inline `<T: Concepto>`.
        parse_type_params_with_bounds(e->type_params, e->type_bounds);
    }
    // #6: clausula `where T: A + B` opcional tras los params.
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "where") {
        parse_where_clause(e->type_bounds);
    }

    // C-style: tipo base opcional `enum Op : u8 { ... }` -> enum con VALOR
    // entero (las variantes son constantes del tipo base, no una tagged union).
    if (current_.kind == TokenKind::COLON) {
        (void)consume(); // ':'
        auto bt = parse_type_node();
        if (bt && bt->kind == ast::NodeKind::PrimitiveTypeNode) {
            auto *pt = static_cast<ast::PrimitiveTypeNode *>(bt.get());
            e->backing_type = primitive_name(pt->prim);
        } else if (bt && bt->kind == ast::NodeKind::NamedTypeNode) {
            // Backing de tipo de USUARIO (struct/clase): cada variante es una
            // constante de ese tipo.  El checker valida que exista.
            e->backing_type = static_cast<ast::NamedTypeNode *>(bt.get())->name;
        } else {
            error_here("el tipo base de un enum debe ser un entero, float, "
                       "string, o un struct/clase (u8/.../f64/string/Nombre)");
        }
    }

    (void)expect(TokenKind::LBRACE,
                 "se esperaba '{' al abrir el cuerpo del enum");

    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        ast::EnumVariantDecl v;
        v.loc = current_.loc;
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba el nombre de una variante de enum");
            synchronize();
            continue;
        }
        v.name = consume().lexeme;
        // Payload opcional: lista de tipos entre parentesis.
        if (current_.kind == TokenKind::LPAREN) {
            (void)consume(); // '('
            while (current_.kind != TokenKind::RPAREN &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto pt = parse_type_node();
                if (!pt) break;
                v.field_types.push_back(std::move(pt));
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' al cerrar payload de variante");
        } else if (current_.kind == TokenKind::ASSIGN) {
            // C-style: valor entero explicito `A = 0x01`.  Solo para enums con
            // tipo base; el checker lo pliega a constante y valida.
            (void)consume(); // '='
            v.value_expr = parse_expr();
        }
        e->variants.push_back(std::move(v));
        // Coma separadora (con coma trailing opcional gracias al check
        // de RBRACE en la condicion del while).
        if (!match(TokenKind::COMMA)) break;
    }
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar el enum");
    // C-style directo `enum Name { A = 0, B }` (sin `: tipo`, sin payloads):
    // si alguna variante lleva valor entero explicito, es un enum de valores
    // (no una tagged union).  Se marca c_style_auto_backing para que el checker
    // infiera el ancho del backing (i32/u32/i64) igual que en `typedef enum`.
    // Un `enum Color { Red, Green }` SIN valores sigue siendo ADT.
    if (e->backing_type.empty() && e->type_params.empty()) {
        bool any_value = false, any_payload = false;
        for (const auto &v : e->variants) {
            if (v.value_expr) any_value = true;
            if (!v.field_types.empty()) any_payload = true;
        }
        if (any_value && !any_payload) e->c_style_auto_backing = true;
    }
    return e;
}

// ------------------------------------------------------------------
// parse_match_expr: punto de entrada cuando el parser ve KW_MATCH.
//
//   match scrutinee {
//       case Variant            => stmt
//       case Variant(a, b)      => { stmts; }
//       case _                  => default_stmt
//   }
//
// Cada arm termina con `;` (o con `}` final para la ultima arm de
// bloque); las arms se consumen hasta encontrar `}` del match.
// ------------------------------------------------------------------
std::unique_ptr<ast::Expr> Parser::parse_match_expr() {
    const SourceLoc loc = current_.loc;
    (void)consume(); // 'match'
    auto m = std::make_unique<ast::MatchExpr>();
    m->loc = loc;

    // Scrutinee: aceptamos cualquier expresion.  No requerimos
    // parentesis (estilo Rust).  Esto permite tanto:
    //   match x { ... }
    //   match (x + 1) { ... }
    // Es el UNICO sitio del lenguaje donde una expresion no parentizada lleva
    // un `{` pegado, asi que aqui el postfijo `{}` (sobrecarga de `__braces__`)
    // se suprime: ese `{` abre el cuerpo del match.  Quien quiera un
    // `a{...}` como scrutinee lo parentiza: `match (a{1,2}) { ... }`.
    {
        const bool prev_nb = no_braces_call_;
        no_braces_call_ = true;
        m->scrutinee = parse_expr();
        no_braces_call_ = prev_nb;
    }
    if (!m->scrutinee) return nullptr;

    (void)expect(TokenKind::LBRACE,
                 "se esperaba '{' tras el scrutinee del match");
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        if (current_.kind != TokenKind::KW_CASE) {
            error_here("se esperaba 'case' al iniciar una arm del match");
            synchronize();
            continue;
        }
        (void)consume(); // 'case'
        ast::MatchArm arm;
        arm.loc = current_.loc;
        // Patron del arm.  Aceptamos:
        //   - Identificador "_" (catchall).
        //   - Identificador (variant simple, p.ej. "Red").
        //   - Identificador "(" bind1, bind2, ... ")" (variant con bindings).
        // Para variantes calificadas tipo `Color.Red` aceptamos tambien
        // el patron `Color.Red(...)`, pero internamente almacenamos solo
        // la parte tras el ultimo `.` ya que el match scrutinee fija el
        // tipo enum y el variant_name es suficiente.
        //
        // Patron de VALOR escalar (match sobre enteros/chars): `case 1 =>`,
        // `case 'a' =>`, `case -3 =>`.  Se guarda en @c value_pattern y el arm
        // NO lleva variant_name (queda vacio).  El type checker exige scrutinee
        // entero/char.
        const bool is_neg_int = (current_.kind == TokenKind::MINUS &&
                                 lex_.peek_at(0).kind == TokenKind::INT_LIT);
        const bool is_str_pat = (current_.kind == TokenKind::STRING_LIT ||
                                 current_.kind == TokenKind::RAW_STRING_LIT);
        const bool is_value_pat =
            (current_.kind == TokenKind::INT_LIT ||
             current_.kind == TokenKind::CHAR_LIT || is_neg_int || is_str_pat);
        if (is_value_pat) {
            if (is_str_pat) {
                auto lit = std::make_unique<ast::StringLitExpr>();
                lit->loc = current_.loc;
                lit->is_raw = (current_.kind == TokenKind::RAW_STRING_LIT);
                lit->value = current_.str_val;
                (void)consume();
                arm.value_pattern = std::move(lit);
            } else if (is_neg_int) {
                SourceLoc mloc = current_.loc;
                (void)consume(); // '-'
                auto lit = std::make_unique<ast::IntLitExpr>();
                lit->loc = current_.loc;
                lit->value = current_.int_val;
                (void)consume(); // INT_LIT
                auto neg = std::make_unique<ast::UnaryExpr>();
                neg->loc = mloc;
                neg->op = ast::UnOp::Neg;
                neg->operand = std::move(lit);
                arm.value_pattern = std::move(neg);
            } else if (current_.kind == TokenKind::INT_LIT) {
                auto lit = std::make_unique<ast::IntLitExpr>();
                lit->loc = current_.loc;
                lit->value = current_.int_val;
                (void)consume();
                arm.value_pattern = std::move(lit);
            } else {
                // CHAR_LIT
                auto lit = std::make_unique<ast::CharLitExpr>();
                lit->loc = current_.loc;
                lit->codepoint = (uint32_t)current_.int_val;
                (void)consume();
                arm.value_pattern = std::move(lit);
            }
            // Rango `case a..b =>` (exclusivo) / `case a..=b =>` (inclusivo).
            // Solo enteros/chars (no strings).  El literal alto se parsea
            // igual.
            if (!is_str_pat && (current_.kind == TokenKind::DOTDOT ||
                                current_.kind == TokenKind::DOTDOTEQ)) {
                arm.range_inclusive = (current_.kind == TokenKind::DOTDOTEQ);
                (void)consume(); // '..' o '..='
                if (current_.kind == TokenKind::MINUS &&
                    lex_.peek_at(0).kind == TokenKind::INT_LIT) {
                    SourceLoc mloc = current_.loc;
                    (void)consume();
                    auto lit = std::make_unique<ast::IntLitExpr>();
                    lit->loc = current_.loc;
                    lit->value = current_.int_val;
                    (void)consume();
                    auto neg = std::make_unique<ast::UnaryExpr>();
                    neg->loc = mloc;
                    neg->op = ast::UnOp::Neg;
                    neg->operand = std::move(lit);
                    arm.value_pattern_hi = std::move(neg);
                } else if (current_.kind == TokenKind::INT_LIT) {
                    auto lit = std::make_unique<ast::IntLitExpr>();
                    lit->loc = current_.loc;
                    lit->value = current_.int_val;
                    (void)consume();
                    arm.value_pattern_hi = std::move(lit);
                } else if (current_.kind == TokenKind::CHAR_LIT) {
                    auto lit = std::make_unique<ast::CharLitExpr>();
                    lit->loc = current_.loc;
                    lit->codepoint = (uint32_t)current_.int_val;
                    (void)consume();
                    arm.value_pattern_hi = std::move(lit);
                } else {
                    error_here("se esperaba un literal entero/char tras "
                               "'..' / '..=' en el rango del case");
                }
            }
            // Cae al flujo compartido de guard + `=>` + body (variant_name
            // queda vacio: es un arm de VALOR, no de variante ni default).
        } else {
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here(
                    "se esperaba un nombre de variante o '_' tras 'case'");
                synchronize();
                continue;
            }
            std::string ident = consume().lexeme;
            // Forma calificada `Color.Red`: descartamos el qualifier.
            while (current_.kind == TokenKind::DOT) {
                (void)consume();
                if (current_.kind != TokenKind::IDENTIFIER) {
                    error_here("se esperaba un identificador tras '.' en "
                               "patron de match");
                    break;
                }
                ident = consume().lexeme;
            }
            arm.variant_name = ident;
            // Payload bindings opcionales.
            if (current_.kind == TokenKind::LPAREN) {
                (void)consume(); // '('
                while (current_.kind != TokenKind::RPAREN &&
                       current_.kind != TokenKind::END_OF_FILE) {
                    if (current_.kind != TokenKind::IDENTIFIER) {
                        error_here(
                            "se esperaba un nombre de binding o '_' en patron");
                        break;
                    }
                    arm.bindings.push_back(consume().lexeme);
                    if (!match(TokenKind::COMMA)) break;
                }
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' al cerrar bindings del patron");
            }
        } // fin del path de variante ADT (else del patron de valor)
        // Bug fix 2026-05-23: match guards `case Pat if cond =>`.
        // Tras parsear el patron (con o sin bindings), aceptar `if expr`
        // opcional antes del `=>`.  La expr se guarda en @c arm.guard
        // y se evalua DESPUES del tag match en runtime.
        if (current_.kind == TokenKind::KW_IF) {
            (void)consume(); // 'if'
            arm.guard = parse_expr();
            if (!arm.guard) {
                error_here("se esperaba una expresion para el guard del case");
            }
        }
        (void)expect(TokenKind::FAT_ARROW,
                     "se esperaba '=>' tras el patron del case");
        // Body del arm: aceptamos cualquier statement (bloque,
        // return, throw, asignacion, expression, ...).  Esto
        // permite `case Red => return 10;` igual que `case Red => { ... }`.
        // parse_statement consume el `;` cuando aplica (returns,
        // expression-stmts), por lo que NO comemos un `;` extra aqui.
        // Para uniformidad, todas las arms se almacenan envueltas en
        // un BlockStmt: simplifica el lowering ya que siempre tiene
        // un solo punto de entrada.
        if (current_.kind == TokenKind::LBRACE) {
            arm.body = parse_block();
        } else {
            auto stmt = parse_statement();
            if (!stmt) {
                synchronize();
                continue;
            }
            auto blk = std::make_unique<ast::BlockStmt>();
            blk->loc = arm.loc;
            blk->body.push_back(std::move(stmt));
            arm.body = std::move(blk);
        }
        m->arms.push_back(std::move(arm));
    }
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar el match");
    return m;
}

/**
 * @copydoc vx::Parser::parse_struct_body_
 */
void Parser::parse_struct_body_(ast::StructDecl &sd, bool is_overlay) {
    ast::StructDecl *const s = &sd;
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        // Contratos de huella declarados sobre el metodo, antes del acceso:
        //
        //     @pure @nothrow @nopanic @alloc(0) @stack(0) @complexity(O(1))
        //     public i64 leer() { ... }
        //
        // Un metodo hace lo mismo que una funcion libre con un argumento mas.
        // Sin esto, un tipo cuya API son METODOS no podia declarar sus
        // propiedades aunque el compilador supiera verificarlas -- y una
        // libreria estandar que no declara los contratos que el lenguaje ofrece
        // esta diciendo lo contrario de lo que hace.
        MemberContracts mc;
        // Anotaciones de metodo en cualquier orden: contratos de huella
        // (@pure/@nothrow/...) mezclables con `@Virtual` (dispatch dinamico
        // opt-in por metodo).  parse_member_contracts_ hace return al ver una
        // anotacion que no es contrato, asi que alternamos hasta agotar ambos.
        bool annot_virtual = false;
        bool annot_override = false;
        for (;;) {
            parse_member_contracts_(mc);
            if (current_.kind == TokenKind::AT &&
                lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
                (lex_.peek_at(0).lexeme == "Virtual" ||
                 lex_.peek_at(0).lexeme == "Override")) {
                (void)consume(); // '@'
                const std::string an = consume().lexeme;
                if (an == "Virtual")
                    annot_virtual = true;
                else
                    annot_override = true; // @Override en un metodo de struct
                continue;
            }
            break;
        }
        // Modificadores de acceso opcionales en el miembro.  Los
        // structs son flat: aceptamos public/private (informativo; sin
        // enforcement por ahora) y `static` en METODOS (constructores/factorias
        // tipo `Box.zero()`: no toman `this`, se llaman via
        // `Struct.metodo(...)`).
        uint8_t access = 0; // 0 = public/default, 1 = private
        bool is_static = false;
        bool is_comptime_member = false;
        for (;;) {
            if (current_.kind == TokenKind::KW_PUBLIC) {
                access = 0;
                (void)consume();
            } else if (current_.kind == TokenKind::KW_PRIVATE) {
                access = 1;
                (void)consume();
            } else if (current_.kind == TokenKind::KW_STATIC) {
                is_static = true;
                (void)consume();
            } else if (current_.kind == TokenKind::IDENTIFIER &&
                       current_.lexeme == "comptime") {
                // `comptime` miembro: campo solo-compile-time o
                // constructor/metodo comptime.  IDENTIFIER contextual (no
                // keyword global) para no reservar el nombre.
                is_comptime_member = true;
                (void)consume();
            } else {
                break;
            }
        }

        // Destructor `~Struct()` opcional (RAII).  Mismo patron que en
        // class pero sin polimorfismo: baja a `<Struct>__dtor(this)`.
        if (current_.kind == TokenKind::TILDE &&
            lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
            lex_.peek_at(0).lexeme == s->name &&
            lex_.peek_at(1).kind == TokenKind::LPAREN) {
            (void)consume(); // '~'
            auto m = std::make_unique<ast::ClassMethodDecl>();
            m->loc = current_.loc;
            (void)consume(); // nombre del struct
            m->name = "__dtor";
            m->is_destructor = true;
            m->return_type = nullptr; // void implicito
            m->access = access;
            (void)expect(TokenKind::LPAREN,
                         "se esperaba '(' tras nombre del destructor");
            if (current_.kind != TokenKind::RPAREN) {
                error_here("destructor de struct no acepta parametros");
                synchronize();
                continue;
            }
            (void)expect(TokenKind::RPAREN, "se esperaba ')' tras destructor");
            m->body = parse_method_body(/*is_void=*/true);
            s->methods.push_back(std::move(m));
            continue;
        }

        // Constructor del struct: el nombre del miembro coincide con el del
        // struct y va inmediatamente seguido de '('.  Mismo patron que en clase
        // (parser.cpp caso 1 de parse_class_decl); baja a `<Struct>__ctor(this,
        // args...)` con SRET (value-type: `this` es un PTR al buffer del
        // struct, sin GC ni calloc).  Debe detectarse ANTES del caso
        // campo/metodo porque `u128(...)` empieza por el propio nombre de tipo.
        // F1b: constructor `comptime T(expr e) { ... }` -- se ejecuta en
        // compile-time (ComptimeVM) y materializa el struct; base de los
        // literales de tipo usuario.  El `comptime` es opcional y precede al
        // nombre del ctor.  Se detecta con peek para no consumirlo si lo que
        // sigue no es realmente un ctor de este struct.
        bool ctor_is_comptime = false;
        if (current_.kind == TokenKind::IDENTIFIER &&
            current_.lexeme == "comptime" &&
            lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
            lex_.peek_at(0).lexeme == s->name &&
            lex_.peek_at(1).kind == TokenKind::LPAREN) {
            (void)consume(); // 'comptime'
            ctor_is_comptime = true;
        }
        if (current_.kind == TokenKind::IDENTIFIER &&
            current_.lexeme == s->name &&
            lex_.peek_at(0).kind == TokenKind::LPAREN) {
            auto m = std::make_unique<ast::ClassMethodDecl>();
            m->loc = current_.loc;
            m->name = consume().lexeme;
            m->is_constructor = true;
            // El `comptime` puede venir inline (`comptime T(`) o como
            // modificador consumido por el loop de arriba (`public comptime
            // T(`).
            m->is_comptime = ctor_is_comptime || is_comptime_member;
            m->return_type = nullptr; // void implicito
            m->access = access;
            (void)expect(TokenKind::LPAREN,
                         "se esperaba '(' tras nombre del constructor");
            // Usar parse_param() (no parse_type_node directo) para reconocer un
            // parametro `expr` (captura el texto crudo del literal en el call
            // site), necesario para el ctor comptime de literales.
            while (current_.kind != TokenKind::RPAREN &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto p = parse_param();
                if (!p) {
                    synchronize();
                    break;
                }
                m->params.push_back(std::move(p));
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect(
                TokenKind::RPAREN,
                "se esperaba ')' al cerrar parametros del constructor");
            // F1b: registrar las posiciones de los params `expr` bajo el nombre
            // del struct, para que el call site `T(literal)` capture el texto
            // crudo del literal (misma tabla que usan los @Macro con `expr`).
            {
                std::vector<int> positions;
                for (size_t i = 0; i < m->params.size(); ++i)
                    if (m->params[i] && m->params[i]->is_expr_capture)
                        positions.push_back((int)i);
                if (!positions.empty())
                    macro_expr_params_[s->name] = std::move(positions);
            }
            m->body = parse_method_body(/*is_void=*/true);
            s->methods.push_back(std::move(m));
            continue;
        }

        // Agregado ANONIMO inline (`struct { ... } campo;` o miembro C11
        // `union { ... };`).  Se emite como struct sintetico top-level y el
        // campo lo referencia; sin nombre de campo -> miembro anonimo
        // (aplanado).
        if ((current_.kind == TokenKind::KW_STRUCT ||
             current_.kind == TokenKind::KW_UNION) &&
            (lex_.peek_at(0).kind == TokenKind::LBRACE ||
             (lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
              lex_.peek_at(1).kind == TokenKind::LBRACE))) {
            auto anon = parse_inline_anon_aggregate_();
            const std::string anon_name = anon->name;
            pending_before_decls_.push_back(std::move(anon));
            ast::StructFieldDecl f;
            f.loc = current_.loc;
            auto nt = std::make_unique<ast::NamedTypeNode>();
            nt->loc = f.loc;
            nt->name = anon_name;
            f.type = std::move(nt);
            if (current_.kind == TokenKind::IDENTIFIER) {
                f.name = consume().lexeme;
                if (current_.kind == TokenKind::LBRACKET)
                    f.type = wrap_c_array_dims_(std::move(f.type));
            } else {
                // Miembro anonimo C11: sus campos se aplanan en este struct.
                f.is_anonymous = true;
                f.name = anon_name;
            }
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' tras el agregado anonimo");
            s->fields.push_back(std::move(f));
            continue;
        }

        const SourceLoc mloc = current_.loc;
        /* La direccion se lee ANTES de comprobar que hay un tipo, porque va
         * DELANTE de el: preguntando primero, `in i64* p;` no pasaria la puerta
         * -- `starts_type()` mira el token de ahora, y ahora hay una marca --.
         * Es el mismo caso que el enrutado de un statement con
         * `register("reg")`.
         *
         * Y todavia no se sabe si lo que viene es un campo o un metodo: el
         * mismo tipo hace de tipo de campo o de tipo de RETORNO segun lo que
         * haya detras.  Si acaba siendo un metodo se rechaza mas abajo, porque
         * sobre un retorno la marca no tiene a quien dar el permiso. */
        const ParamDir campo_dir = parse_opt_param_dir_();
        if (!starts_type()) {
            error_here("se esperaba un tipo de campo o metodo dentro del "
                       "struct");
            synchronize();
            continue;
        }
        auto type_node = parse_type_node();
        if (!type_node) {
            synchronize();
            continue;
        }
        // Puntero a funcion estilo C como campo: `R (*name)(params);`.
        {
            std::string fp_name;
            std::unique_ptr<ast::TypeNode> fp_type;
            if (try_parse_c_func_ptr_(type_node, fp_name, fp_type)) {
                ast::StructFieldDecl f;
                f.loc = mloc;
                f.dir = campo_dir;
                f.type = std::move(fp_type);
                f.name = std::move(fp_name);
                if (current_.kind == TokenKind::LBRACKET)
                    f.type = wrap_c_array_dims_(std::move(f.type));
                (void)expect(TokenKind::SEMICOLON,
                             "se esperaba ';' tras el campo puntero a funcion");
                s->fields.push_back(std::move(f));
                continue;
            }
        }
        // El nombre del miembro puede ser un IDENTIFIER o los keywords
        // contextuales `get`/`set`: aqui YA parseamos un tipo, asi que esto es
        // la forma `<tipo> <nombre>(...)` (campo o metodo), nunca una property
        // (que se detecta ANTES, sin tipo previo).  Permitir `get`/`set` como
        // nombre de metodo/campo (p.ej. `T get()`) evita rechazarlos por
        // colisionar con los keywords de property.
        if (!is_name_token(current_.kind)) {
            error_expected_name(
                "nombre de campo o metodo",
                "se esperaba un nombre de campo o metodo tras el tipo");
            synchronize();
            continue;
        }
        std::string member_name = consume().lexeme;

        // Type-params de metodo generico: `R metodo<U>(...)` (#4) con
        // bounds opcionales `<U: Concepto>` (#6).  Un campo nunca lleva `<`,
        // asi que ver `<` aqui implica metodo generico.
        std::vector<std::string> method_tparams;
        std::vector<ast::TypeBound> method_tbounds;
        if (current_.kind == TokenKind::LT)
            parse_type_params_with_bounds(method_tparams, method_tbounds);

        // Distinguir metodo (siguiente '(') vs campo (':' bit-width o ';').
        if (current_.kind == TokenKind::LPAREN) {
            // Metodo de instancia: dispatch estatico.  Cuerpo de bloque
            // o expression-bodied `=>`.  Sin static/virtual/override.
            auto m = std::make_unique<ast::ClassMethodDecl>();
            m->loc = mloc;
            m->name = std::move(member_name);
            m->return_type = std::move(type_node);
            if (campo_dir != ParamDir::None)
                diags_.diag(mloc, DiagLevel::ERR, "VXT010",
                            {m->name, param_dir_name(campo_dir)});
            m->access = access;
            m->is_static = is_static; // `static`: factoria/constructor sin this
            m->is_comptime = is_comptime_member; // `comptime` metodo
            m->is_virtual = annot_virtual; // `@Virtual`: dispatch dinamico
            m->is_override = annot_override;
            m->method_type_params = method_tparams;
            m->type_bounds = method_tbounds;
            (void)consume(); // '('
            parse_param_list(m->params, "metodo");
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' al cerrar parametros del metodo");
            // #6: clausula `where U: A + B` opcional tras los params.
            if (current_.kind == TokenKind::IDENTIFIER &&
                current_.lexeme == "where") {
                parse_where_clause(m->type_bounds);
            }
            // Registrar los type-params del contenedor (T) y del metodo
            // (U) como aliases temporales para que `(T)x`/`(U)x` se
            // reconozcan como cast dentro del body.  Se retiran al salir.
            std::vector<std::string> all_tp = s->type_params;
            all_tp.insert(all_tp.end(), method_tparams.begin(),
                          method_tparams.end());
            const auto temp_aliases = register_temp_type_aliases(all_tp);
            m->body = parse_method_body(/*is_void=*/false);
            unregister_temp_type_aliases(temp_aliases);
            apply_member_contracts_(mc, *m);
            s->methods.push_back(std::move(m));
            continue;
        }

        // Campo.  Reusa el manejo de bit fields del codigo previo.
        ast::StructFieldDecl f;
        f.loc = mloc;
        f.dir = campo_dir;
        f.is_static = is_static; // `static <T> nombre;` -> storage por-tipo
        f.is_comptime =
            is_comptime_member; // `comptime T campo` -> solo compile-time
        // Clon del tipo BASE (sin dims de array) para el multi-declarador C
        // `T a, b, c;`: cada declarador extra reutiliza el mismo tipo base.
        auto base_type_clone = clone_type_node_td_(type_node.get());
        f.type = std::move(type_node);
        f.name = std::move(member_name);
        // Overlay F3b ARRAY: `T Name[count] ...`.  El `[count]` va tras el
        // nombre (estilo C).  El tipo del campo es el tipo del ELEMENTO.
        if (s->is_overlay && current_.kind == TokenKind::LBRACKET) {
            (void)consume(); // '['
            f.is_array = true;
            // Count OPCIONAL: `T Name[]` (no acotado; el usuario termina el
            // bucle, p.ej. al leer una entrada nula) o `T Name[count]`.
            if (current_.kind != TokenKind::RBRACKET) {
                f.array_count = parse_expr();
            }
            (void)expect(TokenKind::RBRACKET,
                         "se esperaba ']' tras el count del array de overlay");
        } else if (current_.kind == TokenKind::LBRACKET) {
            // Array de campo C-style `T name[N][M]` (uni/multidimensional):
            // el tipo del campo pasa a ser `T[N][M]`.
            f.type = wrap_c_array_dims_(std::move(f.type));
        }
        // Bit field width: `i32 flag : 3;`.  El bit_width
        // se guarda en el AST y el type checker calcula el packing.
        if (current_.kind == TokenKind::COLON) {
            (void)consume();
            if (current_.kind != TokenKind::INT_LIT) {
                error_here(
                    "se esperaba un literal entero tras ':' (bit width)");
            } else {
                const int64_t w = (int64_t)current_.int_val;
                if (w <= 0 || w > 64) {
                    error_here("bit width debe estar en rango 1..64");
                } else {
                    f.bit_width = (uint8_t)w;
                }
                (void)consume();
            }
        }
        // Overlay: offset del campo.  `@0x30` (atajo constante),
        // `@offset(0x30)` (constante) o `@offset(expr)` (F2: expresion que
        // puede referenciar campos hermanos, `@offset(prev + 0x10)`).  El caso
        // puramente constante se pliega a explicit_offset; el resto va a
        // offset_expr.
        while (current_.kind == TokenKind::AT) {
            (void)consume(); // '@'
            if (current_.kind == TokenKind::IDENTIFIER &&
                current_.lexeme == "endian") {
                // Overlay ENDIANNESS (F5): `@endian(expr)` -- la expr (nonzero
                // = big-endian) decide el orden de bytes.  Es la UNICA forma:
                //   fijo big:     @endian(true)
                //   fijo little:  @endian(false)   (o sin @endian = nativo)
                //   por contexto: @endian(self.ei_data == 2)  (ELF), comptime,
                //   ...
                // Si la expr es comptime, el swap condicional se pliega (cero
                // coste); si es runtime, es un select sin ramas.
                (void)consume(); // 'endian'
                (void)expect(TokenKind::LPAREN, "se esperaba '(' tras @endian");
                f.endian_expr = parse_expr();
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras @endian(expr)");
            } else if (current_.kind == TokenKind::IDENTIFIER &&
                       current_.lexeme == "element") {
                // Overlay array POR-ELEMENTO: `T Name[c] @element { ...; return
                // <dir del elemento index>; }`.  Solo valido en un array.
                (void)consume(); // 'element'
                if (!f.is_array) {
                    error_here("@element solo es valido en un campo array "
                               "(`T Name[] @element { ... }`)");
                }
                if (current_.kind == TokenKind::LBRACE) {
                    f.element_block = parse_block();
                } else {
                    error_here("se esperaba '{' tras @element");
                }
            } else if (current_.kind == TokenKind::IDENTIFIER &&
                       current_.lexeme == "offset") {
                (void)consume(); // 'offset'
                if (current_.kind == TokenKind::LBRACE) {
                    // F3: resolver de BLOQUE `@offset { ...; return <dir>; }`.
                    // Puede tener `let` locales + referenciar campos hermanos y
                    // `base`; devuelve la DIRECCION final.
                    f.offset_block = parse_block();
                } else {
                    (void)expect(TokenKind::LPAREN,
                                 "se esperaba '(' o '{' tras @offset");
                    auto oe = parse_expr();
                    (void)expect(TokenKind::RPAREN,
                                 "se esperaba ')' tras @offset(expr)");
                    if (oe && oe->kind == ast::NodeKind::IntLitExpr) {
                        f.explicit_offset =
                            (int64_t)static_cast<ast::IntLitExpr *>(oe.get())
                                ->value;
                    } else {
                        f.offset_expr = std::move(oe);
                    }
                }
            } else {
                // Atajo `@0x30`: solo constante entera.
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here("@<offset> requiere un entero constante (o usa "
                               "@offset(expr))");
                } else {
                    f.explicit_offset = (int64_t)current_.int_val;
                    (void)consume();
                }
            }
        }
        // Overlay F3b: `stride(s)` tras @offset -- bytes entre elementos del
        // array (fijo).  `T Name[count] @offset(pos) stride(s)`.
        if (s->is_overlay && current_.kind == TokenKind::IDENTIFIER &&
            current_.lexeme == "stride") {
            (void)consume(); // 'stride'
            (void)expect(TokenKind::LPAREN, "se esperaba '(' tras stride");
            f.array_stride = parse_expr();
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' tras stride(expr)");
        }
        // Valor por defecto del campo: `u8 a = 0x10;`.  Debe ser una expresion
        // comptime-constante (se valida en el type checker); se aplica al crear
        // el struct con `= {}` / campos no listados y por `default()`.
        if (current_.kind == TokenKind::ASSIGN) {
            (void)consume(); // '='
            f.default_init = parse_expr();
        }
        // Campo `static`: sintetizar su storage como global `<Struct>__<campo>`
        // (una sola por tipo).  El campo queda en s->fields con is_static para
        // que el type checker lo registre en static_fields y NO lo cuente en el
        // layout de instancia; `Struct.campo` resuelve a esta global.
        if (f.is_static) {
            auto gvar = std::make_unique<ast::GlobalVarDecl>();
            gvar->loc = f.loc;
            gvar->name = s->name + "__" + f.name;
            gvar->type = clone_type_node_td_(f.type.get());
            gvar->is_public = s->is_public;
            pending_before_decls_.push_back(std::move(gvar));
        }
        s->fields.push_back(std::move(f));
        // Multi-declarador C `T a, b, c;`: cada declarador extra reutiliza el
        // tipo BASE (clon), con sus propias dims de array y bit-width
        // opcionales.
        while (current_.kind == TokenKind::COMMA) {
            (void)consume(); // ','
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here("se esperaba el nombre del campo tras ','");
                break;
            }
            ast::StructFieldDecl g;
            g.loc = current_.loc;
            g.type = clone_type_node_td_(base_type_clone.get());
            g.name = consume().lexeme;
            // Array C-style por-declarador: `T a, b[4];`.
            if (current_.kind == TokenKind::LBRACKET) {
                g.type = wrap_c_array_dims_(std::move(g.type));
            }
            // Bit-width por-declarador: `u32 a : 3, b : 5;`.
            if (current_.kind == TokenKind::COLON) {
                (void)consume();
                if (current_.kind != TokenKind::INT_LIT) {
                    error_here(
                        "se esperaba un literal entero tras ':' (bit width)");
                } else {
                    const int64_t w = (int64_t)current_.int_val;
                    if (w <= 0 || w > 64)
                        error_here("bit width debe estar en rango 1..64");
                    else
                        g.bit_width = (uint8_t)w;
                    (void)consume();
                }
            }
            // Valor por defecto por-declarador: `T a, b = 0;`.
            if (current_.kind == TokenKind::ASSIGN) {
                (void)consume();
                g.default_init = parse_expr();
            }
            // `static` aplica a toda la linea del declarador.
            g.is_static = is_static;
            if (g.is_static) {
                auto gvar = std::make_unique<ast::GlobalVarDecl>();
                gvar->loc = g.loc;
                gvar->name = s->name + "__" + g.name;
                gvar->type = clone_type_node_td_(g.type.get());
                gvar->is_public = s->is_public;
                pending_before_decls_.push_back(std::move(gvar));
            }
            s->fields.push_back(std::move(g));
        }
        (void)expect(TokenKind::SEMICOLON,
                     "se esperaba ';' al final del campo");
    }
}

std::unique_ptr<ast::StructDecl> Parser::parse_struct_decl(bool is_overlay) {
    auto s = std::make_unique<ast::StructDecl>();
    s->loc = current_.loc;
    // Overlay: fijarlo YA (antes de los campos) para que el parseo de campos
    // vea `s->is_overlay` (arrays `[count]` + `stride(...)`).  El call site
    // tambien lo re-asegura tras el return.
    s->is_overlay = is_overlay;
    (void)consume(); // 'struct'

    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba un nombre tras 'struct'");
        return nullptr;
    }
    s->name = consume().lexeme;
    // Registrar el nombre para que `looks_like_compound_literal` distinga
    // `(Struct){...}` de un scrutinee `match (val) {`.
    declared_structs_.insert(s->name);
    // Genericos opcionales `<T>`, `<K, V>` tras el nombre.  Mismo patron que
    // parse_class_decl / parse_enum_decl: cada parametro es un identificador;
    // el struct se trata como plantilla y se monomorphiza en cada uso
    // `Box<i32>` en el type checker.
    if (current_.kind == TokenKind::LT) {
        // #7: la PRIMERA `struct Caja<...>` es el template primario; las
        // siguientes con el mismo nombre son ESPECIALIZACIONES (total/parcial).
        if (generic_struct_names_seen_.count(s->name)) {
            s->is_specialization = true;
            parse_specialization_pattern(s->spec_pattern, s->type_params);
        } else {
            // #6: cada param puede llevar un bound inline `<T: Concepto>`.
            parse_type_params_with_bounds(s->type_params, s->type_bounds);
            generic_struct_names_seen_.insert(s->name);
        }
    }
    // #6: clausula `where T: A + B` opcional tras los params.
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "where") {
        parse_where_clause(s->type_bounds);
    }
    // Herencia estatica opcional via ':' (mismo patron que parse_class_decl):
    // `struct D : Base` (base) + lista opcional de interfaces `, IFoo, IBar`.
    // El type checker distingue cual es el struct base y cuales interfaces.
    if (current_.kind == TokenKind::COLON) {
        (void)consume();
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here(
                "se esperaba un nombre de struct base o interface tras ':'");
            return nullptr;
        }
        s->super_name = consume().lexeme;
        while (current_.kind == TokenKind::COMMA) {
            (void)consume();
            if (current_.kind == TokenKind::IDENTIFIER)
                s->interface_names.push_back(consume().lexeme);
            else
                break;
        }
    }
    (void)expect(TokenKind::LBRACE,
                 "se esperaba '{' al abrir el cuerpo del struct");

    parse_struct_body_(*s, is_overlay);
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar el struct");
    return s;
}

// -----------------------------------------------------------------
// NS.6-ext: extension / impl -- anyaden metodos a un tipo existente.
//
//   extension Tipo { metodos }
//   impl Concept for Tipo { metodos }
//
// El cuerpo solo contiene METODOS (no campos): `[ret] name(params) body`.
// Dispatch estatico (CALL directo a Tipo__metodo), inline-able.
// -----------------------------------------------------------------

std::unique_ptr<ast::ClassMethodDecl>
Parser::parse_extension_method(uint8_t access) {
    if (!starts_type()) {
        error_here("se esperaba un tipo de retorno de metodo dentro de la "
                   "extension/impl");
        return nullptr;
    }
    const SourceLoc mloc = current_.loc;
    auto type_node = parse_type_node();
    if (!type_node) return nullptr;
    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba el nombre del metodo tras el tipo de retorno");
        return nullptr;
    }
    std::string member_name = consume().lexeme;
    // Type-params de metodo generico `<U>` opcionales.
    std::vector<std::string> method_tparams;
    std::vector<ast::TypeBound> method_tbounds;
    if (current_.kind == TokenKind::LT)
        parse_type_params_with_bounds(method_tparams, method_tbounds);
    if (current_.kind != TokenKind::LPAREN) {
        error_here("una extension/impl solo puede contener metodos "
                   "(se esperaba '(' tras el nombre)");
        return nullptr;
    }
    auto m = std::make_unique<ast::ClassMethodDecl>();
    m->loc = mloc;
    m->name = std::move(member_name);
    m->return_type = std::move(type_node);
    m->access = access;
    m->method_type_params = method_tparams;
    m->type_bounds = method_tbounds;
    (void)consume(); // '('
    parse_param_list(m->params, "metodo");
    (void)expect(TokenKind::RPAREN,
                 "se esperaba ')' al cerrar parametros del metodo");
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "where") {
        parse_where_clause(m->type_bounds);
    }
    const auto temp_aliases = register_temp_type_aliases(method_tparams);
    m->body = parse_method_body(/*is_void=*/false);
    unregister_temp_type_aliases(temp_aliases);
    return m;
}

std::unique_ptr<ast::ExtensionDecl> Parser::parse_extension_decl() {
    auto e = std::make_unique<ast::ExtensionDecl>();
    e->loc = current_.loc;
    (void)consume(); // 'extension'
    // Tipo destino: identificador (posiblemente cualificado a.b.C via '.').
    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba el nombre del tipo tras 'extension'");
        return nullptr;
    }
    std::string tgt = consume().lexeme;
    while (current_.kind == TokenKind::DOT) {
        (void)consume();
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un identificador tras '.' en el tipo de "
                       "la extension");
            return nullptr;
        }
        tgt += ".";
        tgt += consume().lexeme;
    }
    e->target_type = std::move(tgt);
    (void)expect(TokenKind::LBRACE,
                 "se esperaba '{' al abrir el cuerpo de la extension");
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        uint8_t access = 0;
        if (current_.kind == TokenKind::KW_PUBLIC) {
            (void)consume();
        } else if (current_.kind == TokenKind::KW_PRIVATE) {
            access = 1;
            (void)consume();
        }
        auto m = parse_extension_method(access);
        if (!m) {
            synchronize();
            if (current_.kind == TokenKind::RBRACE ||
                current_.kind == TokenKind::END_OF_FILE)
                break;
            continue;
        }
        e->methods.push_back(std::move(m));
    }
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar la extension");
    return e;
}

std::unique_ptr<ast::ImplDecl> Parser::parse_impl_decl() {
    auto im = std::make_unique<ast::ImplDecl>();
    im->loc = current_.loc;
    (void)consume(); // 'impl'
    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba el nombre del concept tras 'impl'");
        return nullptr;
    }
    std::string primero = consume().lexeme;
    while (current_.kind == TokenKind::DOT) {
        (void)consume();
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un identificador tras '.' en el impl");
            return nullptr;
        }
        primero += ".";
        primero += consume().lexeme;
    }

    /* Dos formas, y lo que las separa es el `for`:
     *
     *   impl Tipo { ... }              anade metodos al tipo, sin mas;
     *   impl Concepto for Tipo { ... } ademas declara que lo cumple.
     *
     * Sin la primera hacia falta inventarse un concepto para anadir un par de
     * ayudantes, o usar OTRA palabra distinta que hiciera justo eso -- que es
     * lo que habia, y por eso habia dos formas de escribir lo mismo. */
    const bool con_concepto =
        (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "for") ||
        current_.kind == TokenKind::KW_FOR;

    std::string tgt;
    if (!con_concepto) {
        im->concept_name.clear();
        tgt = std::move(primero);
    } else {
        im->concept_name = std::move(primero);
        (void)consume(); // 'for'
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba el nombre del tipo tras 'for'");
            return nullptr;
        }
        tgt = consume().lexeme;
    }
    while (current_.kind == TokenKind::DOT) {
        (void)consume();
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un identificador tras '.' en el tipo del "
                       "impl");
            return nullptr;
        }
        tgt += ".";
        tgt += consume().lexeme;
    }
    im->target_type = std::move(tgt);
    if (current_.kind != TokenKind::LBRACE) {
        error_here("se esperaba '{' al abrir el cuerpo del impl, o 'for' si lo "
                   "que va delante es un concepto");
        return nullptr;
    }
    (void)consume(); // '{'
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        uint8_t access = 0;
        if (current_.kind == TokenKind::KW_PUBLIC) {
            (void)consume();
        } else if (current_.kind == TokenKind::KW_PRIVATE) {
            access = 1;
            (void)consume();
        }
        auto m = parse_extension_method(access);
        if (!m) {
            synchronize();
            if (current_.kind == TokenKind::RBRACE ||
                current_.kind == TokenKind::END_OF_FILE)
                break;
            continue;
        }
        im->methods.push_back(std::move(m));
    }
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar el impl");
    return im;
}

// -----------------------------------------------------------------
// class: declaracion de tipo POO (reference type con vtable).
//
// Forma minima
//   class <nombre> [':' <super>]? '{'
//       <tipo> <campo> ';'
//       ...
//       <tipo> <metodo>(<params>) '{' <body> '}'   // metodo
//       <nombre>(<params>) '{' <body> '}'           // constructor
//   '}'
//
// -----------------------------------------------------------------

std::unique_ptr<ast::ClassDecl> Parser::parse_class_decl() {
    auto c = std::make_unique<ast::ClassDecl>();
    c->loc = current_.loc;
    (void)consume(); // 'class'

    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba un nombre tras 'class'");
        return nullptr;
    }
    c->name = consume().lexeme;

    // Generics: parametros de tipo opcionales `<T>`, `<K, V>`.
    // Cada parametro es un identificador simple; la clase se trata
    // como plantilla y no se procesa como clase concreta hasta que
    // se instancie via `Box<i32>`.
    if (current_.kind == TokenKind::LT) {
        // #7: la PRIMERA `class Caja<...>` es el primario; las siguientes con
        // el mismo nombre son especializaciones (total/parcial).
        if (generic_class_names_seen_.count(c->name)) {
            c->is_specialization = true;
            parse_specialization_pattern(c->spec_pattern, c->type_params);
        } else {
            // #6: cada param puede llevar un bound inline `<T: Concepto>`.  El
            // `:` de la superclase (`class C : Base`) queda FUERA de `<>` y no
            // colisiona con el `:` del bound (que va dentro de los angulos).
            parse_type_params_with_bounds(c->type_params, c->type_bounds);
            generic_class_names_seen_.insert(c->name);
        }
    }

    // Superclase opcional via ':'.
    if (current_.kind == TokenKind::COLON) {
        (void)consume();
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un nombre de superclase tras ':'");
            return nullptr;
        }
        c->super_name = consume().lexeme;
        // Despues de la superclase, una lista opcional de interfaces
        // separadas por coma: @c class X : Base, IFoo, IBar.  El type
        // checker valida que sean efectivamente interfaces.
        while (current_.kind == TokenKind::COMMA) {
            (void)consume();
            if (current_.kind == TokenKind::IDENTIFIER) {
                c->interface_names.push_back(consume().lexeme);
            } else
                break;
        }
    }

    // #6: clausula `where T: A + B` opcional tras la superclase/interfaces.
    if (current_.kind == TokenKind::IDENTIFIER && current_.lexeme == "where") {
        parse_where_clause(c->type_bounds);
    }

    (void)expect(TokenKind::LBRACE,
                 "se esperaba '{' al abrir el cuerpo de la clase");

    // Cuerpo: secuencia de campos y metodos hasta '}'.  Cada miembro
    // puede llevar modificadores opcionales en cualquier orden:
    //   public | private | protected | static | final
    // Se aceptan combinaciones razonables; no se valida que tengan
    // sentido (eso lo hace el type checker en hitos posteriores).
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        // Parsear anotaciones prefijas (@Name o @Name(args...)).
        // Reconocidas con efecto semantico:
        //   @Override                -> marca el metodo como override
        //   @Inline                  -> marca el metodo para inlining en call
        //   sites
        //   @Before("Cls.metodo")    -> registra advice BEFORE en __module_init
        //   @After("Cls.metodo")     -> registra advice AFTER
        //   @Around("Cls.metodo")    -> registra advice AROUND (no implementado
        //   en exec)
        // El resto se aceptan silenciosamente.
        bool annot_override = false;
        bool annot_inline = false;
        bool annot_final = false; ///< @Final: alias de la palabra clave `final`
        uint8_t annot_advice_kind = 0; // 0=ninguno, 1=BEFORE, 2=AFTER, 3=AROUND
        std::string annot_advice_target;
        // Sprint lombok (2026-06-03): anotaciones de campo Lombok.
        bool lk_getter = false;      ///< @Getter
        bool lk_setter = false;      ///< @Setter
        bool lk_nonnull = false;     ///< @NonNull
        bool lk_with = false;        ///< @With
        bool lk_getter_lazy = false; ///< @Getter(lazy=true)
        while (current_.kind == TokenKind::AT) {
            (void)consume(); // '@'
            if (current_.kind == TokenKind::IDENTIFIER) {
                const std::string aname = current_.lexeme;
                (void)consume();
                uint8_t this_kind = 0;
                if (aname == "Before")
                    this_kind = 1;
                else if (aname == "After")
                    this_kind = 2;
                else if (aname == "Around")
                    this_kind = 3;
                else if (aname == "AfterReturning")
                    this_kind = 4;
                if (aname == "Override") annot_override = true;
                if (aname == "Inline") annot_inline = true;
                if (aname == "Final") annot_final = true;
                // Sprint lombok: marcas de campo.
                if (aname == "Getter") lk_getter = true;
                if (aname == "Setter") lk_setter = true;
                if (aname == "NonNull") lk_nonnull = true;
                if (aname == "With") lk_with = true;

                if (current_.kind == TokenKind::LPAREN) {
                    (void)consume(); // '('
                    if (this_kind != 0 &&
                        current_.kind == TokenKind::STRING_LIT) {
                        annot_advice_kind = this_kind;
                        annot_advice_target = current_.str_val;
                        (void)consume();
                    }
                    // Sprint lombok: detectar `@Getter(lazy=true)`.
                    if (aname == "Getter" &&
                        current_.kind == TokenKind::IDENTIFIER &&
                        current_.lexeme == "lazy") {
                        (void)consume();
                        if (current_.kind == TokenKind::ASSIGN) (void)consume();
                        if (current_.kind == TokenKind::TRUE_KW) {
                            lk_getter_lazy = true;
                            (void)consume();
                        } else if (current_.kind == TokenKind::FALSE_KW) {
                            (void)consume();
                        }
                    }
                    int depth = 1;
                    while (depth > 0 &&
                           current_.kind != TokenKind::END_OF_FILE) {
                        if (current_.kind == TokenKind::LPAREN)
                            ++depth;
                        else if (current_.kind == TokenKind::RPAREN) {
                            --depth;
                            if (depth == 0) {
                                (void)consume();
                                break;
                            }
                        }
                        (void)consume();
                    }
                }
            } else {
                error_here("se esperaba el nombre de la anotacion tras '@'");
                break;
            }
        }

        // Parsear modificadores prefijos.
        uint8_t access = 0; // 0 = default/public, 1 = private, 2 = protected
        bool is_static = false;
        /* `final i32 f()` y `@Final i32 f()` dicen lo mismo, como promete la
         * documentacion del lenguaje: la anotacion se leyo arriba. */
        bool is_final = annot_final;
        bool saw_access = false;
        for (;;) {
            if (current_.kind == TokenKind::KW_PUBLIC) {
                if (saw_access) error_here("modificador de acceso duplicado");
                access = 0;
                saw_access = true;
                (void)consume();
            } else if (current_.kind == TokenKind::KW_PRIVATE) {
                if (saw_access) error_here("modificador de acceso duplicado");
                access = 1;
                saw_access = true;
                (void)consume();
            } else if (current_.kind == TokenKind::KW_PROTECTED) {
                if (saw_access) error_here("modificador de acceso duplicado");
                access = 2;
                saw_access = true;
                (void)consume();
            } else if (current_.kind == TokenKind::KW_STATIC) {
                is_static = true;
                (void)consume();
            } else if (current_.kind == TokenKind::KW_FINAL) {
                is_final = true;
                (void)consume();
            } else {
                break;
            }
        }

        // Caso 0: setter de propiedad: `set name(T v) { ... }`.  No
        // lleva tipo de retorno (void implicito).  Se detecta primero
        // porque KW_SET no es un tipo.  El metodo se almacena con
        // nombre `set_<name>` y `property_kind=2` para que el frontend
        // reescriba luego `obj.name = X` a `obj.set_name(X)`.
        if (current_.kind == TokenKind::KW_SET) {
            const SourceLoc sloc = current_.loc;
            (void)consume(); // 'set'
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_expected_name(
                    "nombre de propiedad",
                    "se esperaba el nombre de la propiedad tras 'set'");
                synchronize();
                continue;
            }
            std::string prop = consume().lexeme;
            auto m = std::make_unique<ast::ClassMethodDecl>();
            m->loc = sloc;
            m->name = std::string("set_") + prop;
            m->return_type = nullptr; // void implicito
            m->access = access;
            m->is_static = is_static;
            m->is_final = is_final;
            m->is_override = annot_override;
            m->is_inline = annot_inline;
            m->property_kind = 2;
            m->property_name = prop;
            (void)expect(TokenKind::LPAREN,
                         "se esperaba '(' tras nombre del setter");
            if (current_.kind != TokenKind::RPAREN) {
                auto p = std::make_unique<ast::ParamDecl>();
                p->loc = current_.loc;
                p->type = parse_type_node();
                if (!p->type) {
                    synchronize();
                    continue;
                }
                if (current_.kind != TokenKind::IDENTIFIER) {
                    error_here(
                        "se esperaba el nombre del parametro del setter");
                    synchronize();
                    continue;
                }
                p->name = consume().lexeme;
                m->params.push_back(std::move(p));
            }
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' al cerrar parametros del setter");
            m->body = parse_method_body(/*is_void=*/true);
            c->methods.push_back(std::move(m));
            continue;
        }

        // destructor: `~ClassName() { ... }`.  El parser detecta
        // TILDE seguido del nombre de la clase + '('.  Sin parametros.
        // Sin tipo de retorno (void implicito).
        if (current_.kind == TokenKind::TILDE &&
            lex_.peek_at(0).kind == TokenKind::IDENTIFIER &&
            lex_.peek_at(0).lexeme == c->name &&
            lex_.peek_at(1).kind == TokenKind::LPAREN) {
            (void)consume(); // '~'
            auto m = std::make_unique<ast::ClassMethodDecl>();
            m->loc = current_.loc;
            // Nombre interno: __dtor (sin '~' para que el label
            // emitido por el lowering -- ClassName__<name> -- sea
            // valido en el ensamblador, que rechaza '~' en symbol).
            // El campo @c is_destructor permite reidentificar.
            (void)consume(); // class name
            m->name = "__dtor";
            m->is_destructor = true;
            m->return_type = nullptr; // void implicito
            m->access = access;
            m->is_static = false;
            m->is_final = is_final;
            m->is_override = annot_override;
            (void)expect(TokenKind::LPAREN,
                         "se esperaba '(' tras nombre del destructor");
            if (current_.kind != TokenKind::RPAREN) {
                error_here("destructor no acepta parametros");
                synchronize();
                continue;
            }
            (void)expect(TokenKind::RPAREN, "se esperaba ')' tras destructor");
            m->body = parse_method_body(/*is_void=*/true);
            c->methods.push_back(std::move(m));
            continue;
        }

        // Caso 1: constructor - el nombre del miembro coincide con el
        // de la clase y va inmediatamente seguido de '('.  Los
        // modificadores `static` no aplican al constructor; el type
        // checker reporta luego.
        if (current_.kind == TokenKind::IDENTIFIER &&
            current_.lexeme == c->name &&
            lex_.peek_at(0).kind == TokenKind::LPAREN) {
            auto m = std::make_unique<ast::ClassMethodDecl>();
            m->loc = current_.loc;
            m->name = consume().lexeme;
            m->is_constructor = true;
            m->return_type = nullptr; // void implicito
            m->access = access;
            m->is_static = is_static;
            m->is_final = is_final;
            m->is_override = annot_override;
            (void)expect(TokenKind::LPAREN,
                         "se esperaba '(' tras nombre del constructor");
            parse_param_list(m->params, "constructor");
            (void)expect(
                TokenKind::RPAREN,
                "se esperaba ')' al cerrar parametros del constructor");
            // Constructor admite cuerpo de bloque o expression-bodied
            // (=> expr ;) que se traduce a `{ this(args via expr); }` no es
            // util para ctor; lo permitimos solo para metodos no-ctor.
            m->body = parse_method_body(/*is_void=*/true);
            c->methods.push_back(std::move(m));
            continue;
        }

        // Caso 2: campo o metodo normal.  Ambos comienzan con un tipo -- o con
        // la direccion, que va delante de el (ver la nota en el cuerpo del
        // struct: se lee ANTES de la puerta, o `in i64* p;` no la pasaria).
        const SourceLoc mloc = current_.loc;
        const ParamDir campo_dir = parse_opt_param_dir_();
        if (!starts_type()) {
            error_here(
                "se esperaba un tipo de campo o metodo dentro de la clase");
            synchronize();
            continue;
        }
        auto type_node = parse_type_node();
        if (!type_node) {
            synchronize();
            continue;
        }

        // Caso 2.5: getter de propiedad: `T get name => expr;` o
        // `T get name { return expr; }`.  No lleva parametros; el
        // metodo se almacena con nombre `get_<name>` y
        // `property_kind=1`.
        //
        // Distinguir contextualmente entre property getter y un
        // metodo llamado "get": si tras 'get' viene un IDENTIFIER es
        // property getter (`T get name => ...`); si viene '(' es un
        // metodo normal (`T get(args) { body }`).  Sin esto el
        // parser entraba en bucle al encontrar `i32 get() {...}`
        // (consume 'get', falla en IDENTIFIER, synchronize avanza
        // dentro del body y luego no podia recuperar al inicio del
        // siguiente miembro).  El parser ya consume 'get' como
        // KW_GET aunque sea nombre de metodo: hay que mirar el
        // segundo token sin consumir antes de decidir.
        if (current_.kind == TokenKind::KW_GET &&
            lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
            (void)consume(); // 'get'
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_expected_name(
                    "nombre de propiedad",
                    "se esperaba el nombre de la propiedad tras 'get'");
                synchronize();
                continue;
            }
            std::string prop = consume().lexeme;
            auto m = std::make_unique<ast::ClassMethodDecl>();
            m->loc = mloc;
            m->name = std::string("get_") + prop;
            m->return_type = std::move(type_node);
            if (campo_dir != ParamDir::None)
                diags_.diag(mloc, DiagLevel::ERR, "VXT010",
                            {m->name, param_dir_name(campo_dir)});
            m->access = access;
            m->is_static = is_static;
            m->is_final = is_final;
            m->is_override = annot_override;
            m->is_inline = annot_inline;
            m->property_kind = 1;
            m->property_name = prop;
            m->body = parse_method_body(/*is_void=*/false);
            c->methods.push_back(std::move(m));
            continue;
        }

        // Aceptar KW_GET / KW_SET como nombres de miembro normales:
        // si llegamos aqui es porque NO seguia el patron de property
        // (`get name => ...` o `set name(T v) ...`), por tanto el
        // usuario quiere un metodo/campo llamado literalmente "get"
        // o "set".  Sin esto el parser entraba en bucle eterno al
        // ver `i32 get() { ... }` (KW_GET no es IDENTIFIER asi que
        // error_here + synchronize, y synchronize re-entraba en el
        // siguiente miembro produciendo el mismo error).
        if (!is_name_token(current_.kind)) {
            error_expected_name("nombre de miembro",
                                "se esperaba el nombre del miembro");
            synchronize();
            continue;
        }
        std::string member_name = consume().lexeme;

        // Type-params de metodo generico: `R metodo<U>(...)` (#4) con
        // bounds opcionales `<U: Concepto>` (#6).  Un campo nunca lleva `<`,
        // asi que ver `<` aqui implica metodo generico.
        std::vector<std::string> method_tparams;
        std::vector<ast::TypeBound> method_tbounds;
        if (current_.kind == TokenKind::LT)
            parse_type_params_with_bounds(method_tparams, method_tbounds);

        // Distinguir campo (siguiente '=' o ';') vs metodo (siguiente '(').
        if (current_.kind == TokenKind::LPAREN) {
            // Metodo de instancia o estatico.
            auto m = std::make_unique<ast::ClassMethodDecl>();
            m->loc = mloc;
            m->name = std::move(member_name);
            m->return_type = std::move(type_node);
            if (campo_dir != ParamDir::None)
                diags_.diag(mloc, DiagLevel::ERR, "VXT010",
                            {m->name, param_dir_name(campo_dir)});
            m->access = access;
            m->is_static = is_static;
            m->is_final = is_final;
            m->is_override = annot_override;
            m->is_inline = annot_inline;
            m->advice_kind = annot_advice_kind;
            m->advice_target = annot_advice_target;
            m->method_type_params = method_tparams;
            m->type_bounds = method_tbounds;
            (void)consume(); // '('
            parse_param_list(m->params, "metodo");
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' al cerrar parametros del metodo");
            // #6: clausula `where U: A + B` opcional tras los params.
            if (current_.kind == TokenKind::IDENTIFIER &&
                current_.lexeme == "where") {
                parse_where_clause(m->type_bounds);
            }
            // Registrar los type-params del contenedor (T) y del metodo
            // (U) como aliases temporales para que `(T)x`/`(U)x` se
            // reconozcan como cast dentro del body.  Se retiran al salir.
            std::vector<std::string> all_tp = c->type_params;
            all_tp.insert(all_tp.end(), method_tparams.begin(),
                          method_tparams.end());
            const auto temp_aliases = register_temp_type_aliases(all_tp);
            m->body = parse_method_body(/*is_void=*/false);
            unregister_temp_type_aliases(temp_aliases);
            c->methods.push_back(std::move(m));
        } else {
            // Campo.  Init opcional con '='.
            ast::ClassFieldDecl f;
            f.loc = mloc;
            f.dir = campo_dir;
            f.type = std::move(type_node);
            f.name = std::move(member_name);
            f.access = access;
            f.is_static = is_static;
            f.is_final = is_final;
            // Sprint lombok: propagar flags del field.
            f.lombok_getter = lk_getter;
            f.lombok_setter = lk_setter;
            f.lombok_nonnull = lk_nonnull;
            f.lombok_with = lk_with;
            f.lombok_getter_lazy = lk_getter_lazy;
            if (match(TokenKind::ASSIGN)) {
                f.init = parse_expr();
            }
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' al final del campo");
            c->fields.push_back(std::move(f));
        }
    }
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar la clase");
    return c;
}

// -----------------------------------------------------------------
// parse_interface_decl
//
// Sintaxis:
//   interface IFoo {
//       i32 metodo(i32 arg);
//       void otro();
//   }
//
// Cada metodo termina en `;` (sin body); no se permiten campos.  El
// type checker valida que ninguna clase implementadora deje fuera
// ningun metodo y que las firmas sean compatibles.  El lowering
// emite defclass para la interfaz (sin defmethod en __module_init,
// ya que no hay code_vaddr) para que sea localizable via findclass.
// -----------------------------------------------------------------
std::unique_ptr<ast::ClassDecl> Parser::parse_interface_decl() {
    auto c = std::make_unique<ast::ClassDecl>();
    c->loc = current_.loc;
    c->is_interface = true;
    (void)consume(); // 'interface'

    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba un nombre tras 'interface'");
        return nullptr;
    }
    c->name = consume().lexeme;

    // Una interfaz puede extender otras interfaces via `:`.  Aceptamos
    // la misma sintaxis que class para uniformidad: `interface I : J, K`.
    if (current_.kind == TokenKind::COLON) {
        (void)consume();
        if (current_.kind == TokenKind::IDENTIFIER) {
            c->super_name = consume().lexeme;
        }
        while (current_.kind == TokenKind::COMMA) {
            (void)consume();
            if (current_.kind == TokenKind::IDENTIFIER) {
                c->interface_names.push_back(consume().lexeme);
            } else
                break;
        }
    }

    (void)expect(TokenKind::LBRACE,
                 "se esperaba '{' al abrir el cuerpo de la interfaz");

    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        // Las interfaces solo declaran metodos (no fields, no init).
        // Modificadores de acceso: aceptamos `public` (default) por
        // claridad, pero todos los metodos son implicitamente publicos.
        if (current_.kind == TokenKind::KW_PUBLIC) (void)consume();
        // Tipo de retorno.
        if (!starts_type()) {
            error_here("se esperaba un tipo de retorno en metodo de interfaz");
            synchronize();
            continue;
        }
        const SourceLoc mloc = current_.loc;
        auto rettype = parse_type_node();
        if (!rettype) {
            synchronize();
            continue;
        }
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba el nombre del metodo de interfaz");
            synchronize();
            continue;
        }
        std::string mname = consume().lexeme;
        if (current_.kind != TokenKind::LPAREN) {
            error_here("se esperaba '(' tras nombre del metodo de interfaz");
            synchronize();
            continue;
        }
        auto m = std::make_unique<ast::ClassMethodDecl>();
        m->loc = mloc;
        m->name = std::move(mname);
        m->return_type = std::move(rettype);
        m->access = 0;
        m->is_static = false;
        m->is_final = false;
        m->is_constructor = false;
        (void)consume(); // '('
        parse_param_list(m->params, "metodo");
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' al cerrar parametros del metodo");
        (void)expect(TokenKind::SEMICOLON,
                     "se esperaba ';' al final del metodo abstracto");
        // body queda nullptr -> metodo abstracto.
        c->methods.push_back(std::move(m));
    }
    (void)expect(TokenKind::RBRACE,
                 "se esperaba '}' al cerrar el cuerpo de la interfaz");
    return c;
}

/**
 * @brief Parsea el cuerpo de un metodo (cuerpo de bloque o
 *        expression-bodied @c => expr ;).
 *
 * - Bloque: @c { stmts... }, retorno explicito en stmts.
 * - Expression-bodied: @c => expr ; equivale a @c { return expr; }
 *   (o solo @c expr; si @p is_void).  Util para metodos cortos.
 */
void Parser::parse_method_type_params(std::vector<std::string> &out) {
    // Precondicion: current_ es '<'.  Mismo patron que parse_struct_decl /
    // parse_class_decl para los type-params del contenedor.
    (void)consume(); // '<'
    while (current_.kind == TokenKind::IDENTIFIER) {
        out.push_back(consume().lexeme);
        if (!match(TokenKind::COMMA)) break;
    }
    (void)expect_close_angle(
        "se esperaba '>' al cerrar parametros de tipo del metodo");
}

void Parser::parse_type_params_with_bounds(
    std::vector<std::string> &params, std::vector<ast::TypeBound> &bounds) {
    // Precondicion: current_ es '<'.  Cada param puede llevar un bound
    // inline `: Concepto` (o `Concepto + Otro`).
    (void)consume(); // '<'
    while (current_.kind == TokenKind::IDENTIFIER) {
        const SourceLoc bl = current_.loc;
        const std::string pname = consume().lexeme;
        params.push_back(pname);
        if (current_.kind == TokenKind::COLON) {
            (void)consume(); // ':'
            ast::TypeBound tb;
            tb.type_param = pname;
            tb.loc = bl;
            while (current_.kind == TokenKind::IDENTIFIER) {
                // NS.2: concepto opcionalmente cualificado (`mat.Numerico`).
                std::string cname = consume().lexeme;
                while (current_.kind == TokenKind::DOT) {
                    (void)consume(); // '.'
                    if (current_.kind != TokenKind::IDENTIFIER) break;
                    cname += "." + consume().lexeme;
                }
                tb.concepts.push_back(std::move(cname));
                if (current_.kind == TokenKind::PLUS) {
                    (void)consume(); // '+' : otro concepto exigido
                    continue;
                }
                break;
            }
            bounds.push_back(std::move(tb));
        }
        if (!match(TokenKind::COMMA)) break;
    }
    (void)expect_close_angle("se esperaba '>' al cerrar parametros de tipo");
}

// Recoge los identificadores que son params FRESCOS de un patron de
// especializacion: los que aparecen DENTRO de un puntero/array (`T*`, `T[]`).
// Un NamedTypeNode al nivel TOP (no anidado) es un tipo CONCRETO (total spec),
// no un param fresco.  Los primitivos nunca son frescos.
static void collect_fresh_spec_params(const ast::TypeNode *t,
                                      bool inside_compound,
                                      std::vector<std::string> &out) {
    if (!t) return;
    switch (t->kind) {
    case ast::NodeKind::NamedTypeNode: {
        auto *n = static_cast<const ast::NamedTypeNode *>(t);
        if (inside_compound) {
            // Param fresco (e.g. T en `T*`).  Evitar duplicados.
            for (const auto &e : out)
                if (e == n->name) return;
            out.push_back(n->name);
        }
        // Recorrer type-args anidados (`Inner<T>`): tambien compuesto.
        for (const auto &ta : n->type_args)
            collect_fresh_spec_params(ta.get(), true, out);
        return;
    }
    case ast::NodeKind::PointerTypeNode: {
        auto *p = static_cast<const ast::PointerTypeNode *>(t);
        collect_fresh_spec_params(p->pointee.get(), true, out);
        return;
    }
    case ast::NodeKind::ArrayTypeNode: {
        auto *a = static_cast<const ast::ArrayTypeNode *>(t);
        collect_fresh_spec_params(a->element_type.get(), true, out);
        return;
    }
    default: return; // primitivos, fn, etc.: sin params frescos
    }
}

void Parser::parse_specialization_pattern(
    std::vector<std::unique_ptr<ast::TypeNode>> &pattern,
    std::vector<std::string> &fresh_params) {
    (void)consume(); // '<'
    while (current_.kind != TokenKind::GT && current_.kind != TokenKind::SHR &&
           current_.kind != TokenKind::END_OF_FILE) {
        auto tn = parse_type_node();
        if (!tn) break;
        collect_fresh_spec_params(tn.get(), /*inside_compound=*/false,
                                  fresh_params);
        pattern.push_back(std::move(tn));
        if (!match(TokenKind::COMMA)) break;
    }
    (void)expect_close_angle(
        "se esperaba '>' al cerrar el patron de especializacion");
}

void Parser::parse_where_clause(std::vector<ast::TypeBound> &bounds) {
    // Precondicion: current_ es el identificador contextual `where`.
    (void)consume(); // 'where'
    while (current_.kind == TokenKind::IDENTIFIER) {
        const SourceLoc bl = current_.loc;
        const std::string pname = consume().lexeme;
        ast::TypeBound tb;
        tb.type_param = pname;
        tb.loc = bl;
        if (current_.kind == TokenKind::COLON) {
            (void)consume(); // ':'
            while (current_.kind == TokenKind::IDENTIFIER) {
                // NS.2: concepto opcionalmente cualificado (`mat.Numerico`).
                std::string cname = consume().lexeme;
                while (current_.kind == TokenKind::DOT) {
                    (void)consume(); // '.'
                    if (current_.kind != TokenKind::IDENTIFIER) break;
                    cname += "." + consume().lexeme;
                }
                tb.concepts.push_back(std::move(cname));
                if (current_.kind == TokenKind::PLUS) {
                    (void)consume();
                    continue;
                }
                break;
            }
        } else {
            error_here(
                "se esperaba ':' tras el type-param en la clausula where");
        }
        bounds.push_back(std::move(tb));
        if (!match(TokenKind::COMMA)) break;
    }
}

std::unique_ptr<ast::ConceptDecl> Parser::parse_concept_decl() {
    auto c = std::make_unique<ast::ConceptDecl>();
    c->loc = current_.loc;
    (void)consume(); // 'concept' (identificador contextual)
    if (current_.kind != TokenKind::IDENTIFIER) {
        error_here("se esperaba el nombre del concepto tras 'concept'");
        return nullptr;
    }
    c->name = consume().lexeme;
    // Type-params opcionales `<T>` / `<K, V>`.
    if (current_.kind == TokenKind::LT) {
        (void)consume(); // '<'
        while (current_.kind == TokenKind::IDENTIFIER) {
            c->type_params.push_back(consume().lexeme);
            if (!match(TokenKind::COMMA)) break;
        }
        (void)expect_close_angle(
            "se esperaba '>' al cerrar los parametros del concepto");
    }

    if (current_.kind == TokenKind::ASSIGN) {
        // Forma predicado: `concept N<T> = <bool-expr>;`.
        (void)consume(); // '='
        c->ckind = ast::ConceptKind::Predicate;
        // Registrar T como alias temporal para `(T)x` / `is_x<T>()`.
        const auto temp = register_temp_type_aliases(c->type_params);
        c->predicate = parse_expr();
        unregister_temp_type_aliases(temp);
        (void)expect(TokenKind::SEMICOLON,
                     "se esperaba ';' tras el predicado del concepto");
        return c;
    }

    if (current_.kind != TokenKind::LBRACE) {
        error_here("se esperaba '=' o '{' tras el nombre del concepto");
        return c;
    }

    // Disambiguar BLOQUE (stmts comptime) vs ESTRUCTURAL (firmas de metodo).
    // Estructural: el primer miembro es `<tipo> <ident> ( ... ) ;`.
    Lexer &ml = const_cast<Lexer &>(lex_);
    const Token &a0 = ml.peek_at(0); // primer token del cuerpo
    const Token &a1 = ml.peek_at(1);
    const Token &a2 = ml.peek_at(2);
    const bool a0_type_start =
        (primitive_kind_from_token(a0.kind) != PrimitiveKind::COUNT) ||
        a0.kind == TokenKind::KW_VOID || a0.kind == TokenKind::IDENTIFIER;
    const bool is_structural = a0_type_start &&
                               a1.kind == TokenKind::IDENTIFIER &&
                               a2.kind == TokenKind::LPAREN;
    (void)consume(); // '{'

    if (is_structural) {
        c->ckind = ast::ConceptKind::Structural;
        while (current_.kind != TokenKind::RBRACE &&
               current_.kind != TokenKind::END_OF_FILE) {
            ast::StructuralMethod sm;
            sm.return_type = parse_type_node(); // tipo de retorno
            if (!sm.return_type) {
                synchronize();
                break;
            }
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here("se esperaba el nombre del metodo en el concepto "
                           "estructural");
                synchronize();
                break;
            }
            sm.name = consume().lexeme;
            // Firma de parametros: `(T1, T2, ...)` -- solo los TIPOS (los
            // nombres de param son opcionales y se ignoran).
            (void)expect(TokenKind::LPAREN,
                         "se esperaba '(' tras el nombre del metodo");
            while (current_.kind != TokenKind::RPAREN &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto pt = parse_type_node();
                if (!pt) {
                    synchronize();
                    break;
                }
                sm.param_types.push_back(std::move(pt));
                // Nombre de param opcional (e.g. `i64 x`): consumirlo.
                if (current_.kind == TokenKind::IDENTIFIER) (void)consume();
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' al cerrar la firma del metodo");
            (void)match(TokenKind::SEMICOLON);
            c->structural_methods.push_back(std::move(sm));
        }
        (void)expect(TokenKind::RBRACE,
                     "se esperaba '}' al cerrar el concepto estructural");
        return c;
    }

    // Forma bloque: `concept N<T> { <stmts comptime>; return <bool>; }`.
    c->ckind = ast::ConceptKind::Block;
    auto blk = std::make_unique<ast::BlockStmt>();
    blk->loc = c->loc;
    const auto temp = register_temp_type_aliases(c->type_params);
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        auto st = parse_statement();
        if (!st) break;
        blk->body.push_back(std::move(st));
    }
    unregister_temp_type_aliases(temp);
    (void)expect(TokenKind::RBRACE,
                 "se esperaba '}' al cerrar el cuerpo del concepto");
    c->body = std::move(blk);
    return c;
}

std::vector<std::string>
Parser::register_temp_type_aliases(const std::vector<std::string> &names) {
    std::vector<std::string> inserted;
    inserted.reserve(names.size());
    for (const auto &n : names) {
        // insert().second == true solo si NO existia previamente: asi
        // no retiramos por error un typedef real con el mismo nombre.
        if (declared_aliases_.insert(n).second) inserted.push_back(n);
    }
    return inserted;
}

void Parser::unregister_temp_type_aliases(
    const std::vector<std::string> &inserted) {
    for (const auto &n : inserted)
        declared_aliases_.erase(n);
}

std::unique_ptr<ast::BlockStmt> Parser::parse_method_body(bool is_void) {
    if (current_.kind == TokenKind::FAT_ARROW) {
        const SourceLoc loc = current_.loc;
        (void)consume(); // '=>'
        auto block = std::make_unique<ast::BlockStmt>();
        block->loc = loc;
        auto expr = parse_expr();
        if (is_void) {
            // Tratar como ExprStmt: ejecutar la expresion y descartar.
            auto es = std::make_unique<ast::ExprStmt>();
            es->loc = loc;
            es->expr = std::move(expr);
            block->body.push_back(std::move(es));
        } else {
            // Wrap como `return expr;`.
            auto rs = std::make_unique<ast::ReturnStmt>();
            rs->loc = loc;
            rs->value = std::move(expr);
            block->body.push_back(std::move(rs));
        }
        (void)expect(TokenKind::SEMICOLON,
                     "se esperaba ';' tras expression-bodied '=>'");
        return block;
    }
    return parse_block();
}

// ---------------------------------------------------------------------
// Bloques y statements.
// ---------------------------------------------------------------------

std::unique_ptr<ast::BlockStmt> Parser::parse_block() {
    auto b = std::make_unique<ast::BlockStmt>();
    b->loc = current_.loc;
    (void)expect(TokenKind::LBRACE, "se esperaba '{' al abrir bloque");
    while (current_.kind != TokenKind::RBRACE &&
           current_.kind != TokenKind::END_OF_FILE) {
        auto s = parse_statement();
        if (s)
            b->body.push_back(std::move(s));
        else
            synchronize();
    }
    (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar bloque");
    return b;
}

/**
 * @brief Parsea una sentencia y le pone su EXTENSION real.
 *
 * El nodo se queda con la posicion de su primer token, cuya longitud es la de
 * ESE TOKEN y no la de la sentencia: una que empiece por `return` media seis
 * caracteres, los de la palabra clave.  Al subrayar un fallo se marcaba la
 * palabra clave en vez de lo que se estaba evaluando.
 *
 * Aqui se mide de verdad: del primer byte de la sentencia al ultimo consumido.
 * Se hace en el envoltorio y no en cada rama porque son decenas y bastaria
 * olvidar una para que volviera a mentir en ese caso concreto.
 *
 * @return La sentencia.
 */
std::unique_ptr<ast::Stmt> Parser::parse_statement() {
    const uint32_t ini = current_.loc.offset;
    auto st = parse_statement_inner();
    if (st && st->loc.offset >= ini) {
        // El final es donde empieza el token que YA no es de la sentencia.
        const uint32_t fin = current_.loc.offset;
        if (fin > st->loc.offset) st->loc.length = fin - st->loc.offset;
    }
    return st;
}

std::unique_ptr<ast::Stmt> Parser::parse_statement_inner() {
    // `label:` -- declaracion de etiqueta para `goto`.  Detectada
    // como IDENT seguido inmediatamente de COLON (sin espacio
    // semantico en medio).  La etiqueta se modela como un statement
    // separado; el siguiente statement se procesa normalmente.
    if (current_.kind == TokenKind::IDENTIFIER) {
        Lexer &mut_lex = const_cast<Lexer &>(lex_);
        if (mut_lex.peek_at(0).kind == TokenKind::COLON) {
            auto lab = std::make_unique<ast::LabelStmt>();
            lab->loc = current_.loc;
            lab->name = consume().lexeme; // IDENT
            (void)consume();              // ':'
            return lab;
        }
        // `comptime if (cond) { ... }` -- el if se evalua
        // 100% en compile-time y solo la rama tomada se baja a IR.
        // Detectamos contextualmente para no reservar `comptime` como
        // keyword global (puede usarse como nombre de variable).
        if (current_.lexeme == "comptime" &&
            mut_lex.peek_at(0).kind == TokenKind::KW_IF) {
            (void)consume();          // 'comptime' (IDENT)
            auto s = parse_if_stmt(); // parsea como if normal
            if (s && s->kind == ast::NodeKind::IfStmt) {
                static_cast<ast::IfStmt *>(s.get())->is_comptime = true;
            }
            return s;
        }
        // A.39: `comptime const T NAME = expr;` local.
        if (current_.lexeme == "comptime" &&
            mut_lex.peek_at(0).kind == TokenKind::KW_CONST) {
            (void)consume(); // 'comptime'
            (void)consume(); // 'const'
            auto vd = parse_var_decl_stmt(true, /*from_comptime=*/true);
            if (vd && vd->kind == ast::NodeKind::VarDeclStmt) {
                auto *v = static_cast<ast::VarDeclStmt *>(vd.get());
                v->is_comptime = true;
            }
            return vd;
        }
        /* sugar local: `comptime NAME = expr;` ->
         * equivale a `comptime const auto NAME = expr;` con
         * inferencia.  Reduce el ruido en cadenas largas de
         * macros + concat de strings comptime. */
        if (current_.lexeme == "comptime" &&
            mut_lex.peek_at(0).kind == TokenKind::IDENTIFIER &&
            mut_lex.peek_at(0).lexeme != "var" &&
            mut_lex.peek_at(1).kind == TokenKind::ASSIGN) {
            const SourceLoc sugar_loc = current_.loc;
            (void)consume(); /* 'comptime' */
            auto vd = std::make_unique<ast::VarDeclStmt>();
            vd->loc = sugar_loc;
            vd->name = consume().lexeme; /* NAME */
            vd->is_const = true;
            vd->is_comptime = true;
            vd->infer_type = true;
            vd->type = nullptr;
            (void)expect(TokenKind::ASSIGN,
                         "se esperaba '=' tras 'comptime' + nombre");
            vd->init = parse_expr();
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' al final de la decl comptime");
            return vd;
        }
        // `comptime var T NAME = expr;` local mutable.
        // Convencion: el modificador `var` (IDENT contextual) hace
        // explicito que la variable es comptime-mutable, paralelo a
        // `comptime const` para inmutable.
        // : `comptime auto X` aceptado como alias.  Tambien
        // soporta `comptime var/auto NAME = init;` (sin tipo) con
        // inferencia local.
        if (current_.lexeme == "comptime" &&
            mut_lex.peek_at(0).kind == TokenKind::IDENTIFIER &&
            (mut_lex.peek_at(0).lexeme == "var" ||
             mut_lex.peek_at(0).lexeme == "auto")) {
            const SourceLoc sugar_loc = current_.loc;
            (void)consume(); // 'comptime'
            (void)consume(); // 'var' o 'auto'
            /* Modo inferencia: `comptime var NAME = init;` sin tipo. */
            if (current_.kind == TokenKind::IDENTIFIER &&
                mut_lex.peek_at(0).kind == TokenKind::ASSIGN) {
                auto vd = std::make_unique<ast::VarDeclStmt>();
                vd->loc = sugar_loc;
                vd->name = consume().lexeme;
                vd->is_const = false; /* mutable */
                vd->is_comptime = true;
                vd->infer_type = true;
                vd->type = nullptr;
                (void)expect(
                    TokenKind::ASSIGN,
                    "se esperaba '=' tras 'comptime var/auto' + nombre");
                vd->init = parse_expr();
                (void)expect(
                    TokenKind::SEMICOLON,
                    "se esperaba ';' al final de la decl comptime var");
                return vd;
            }
            auto vd = parse_var_decl_stmt(false);
            if (vd && vd->kind == ast::NodeKind::VarDeclStmt) {
                auto *v = static_cast<ast::VarDeclStmt *>(vd.get());
                v->is_comptime = true;
            }
            return vd;
        }
        // v4 canonico (hard-break): `comptime T NAME = expr;` local con
        // tipo EXPLICITO (sin `const`).  El parser top-level ya lo soporta;
        // parse_statement faltaba -> `comptime i64 X = fact(6);` dentro de
        // una funcion fallaba con "se esperaba ';'" (bug 138/148).  Las
        // formas const/var/auto/sugar-NAME=/{/for ya se descartaron arriba
        // o lo haran abajo (excluimos `{` y `for` del peek).
        if (current_.lexeme == "comptime" &&
            mut_lex.peek_at(0).kind != TokenKind::LBRACE &&
            mut_lex.peek_at(0).kind != TokenKind::KW_FOR &&
            mut_lex.peek_at(0).kind != TokenKind::KW_IF) {
            (void)consume(); // 'comptime'
            if (!starts_type()) {
                error_here("se esperaba un tipo tras 'comptime' "
                           "(comptime T NAME = expr;)");
                synchronize();
                return nullptr;
            }
            auto vd = parse_var_decl_stmt(true, /*from_comptime=*/true);
            if (vd && vd->kind == ast::NodeKind::VarDeclStmt) {
                auto *v = static_cast<ast::VarDeclStmt *>(vd.get());
                v->is_comptime = true;
            }
            return vd;
        }
        // `comptime { stmts }` bloque scope para comptime const +
        // comptime for + static_assert.  El bloque NO emite codigo
        // runtime.
        // sugar: dentro del bloque, `NAME = expr;` (sin
        // 'comptime const' explicito) cuenta como nueva decl
        // `comptime const NAME = expr;` con inferencia.  Reduce
        // ruido en macros donde cada decl repetia `comptime const`.
        if (current_.lexeme == "comptime" &&
            mut_lex.peek_at(0).kind == TokenKind::LBRACE) {
            const SourceLoc loc = current_.loc;
            (void)consume(); // 'comptime'
            (void)expect(TokenKind::LBRACE, "se esperaba '{' tras 'comptime'");
            auto cb = std::make_unique<ast::ComptimeBlockStmt>();
            cb->loc = loc;
            while (current_.kind != TokenKind::RBRACE &&
                   current_.kind != TokenKind::END_OF_FILE) {
                /* sugar: detectar `NAME = expr;` directo
                 * antes del parse_statement normal.  Solo aplica
                 * cuando el siguiente al IDENT es ASSIGN -- otros
                 * IdentExpr (e.g., expr-stmt funcional) caen al
                 * parser normal. */
                if (current_.kind == TokenKind::IDENTIFIER &&
                    mut_lex.peek_at(0).kind == TokenKind::ASSIGN) {
                    const SourceLoc decl_loc = current_.loc;
                    auto vd = std::make_unique<ast::VarDeclStmt>();
                    vd->loc = decl_loc;
                    vd->name = consume().lexeme;
                    vd->is_const = true;
                    vd->is_comptime = true;
                    vd->infer_type = true;
                    vd->type = nullptr;
                    (void)expect(
                        TokenKind::ASSIGN,
                        "se esperaba '=' tras nombre en comptime block");
                    vd->init = parse_expr();
                    (void)expect(
                        TokenKind::SEMICOLON,
                        "se esperaba ';' al final de la decl comptime");
                    cb->stmts.push_back(std::move(vd));
                    continue;
                }
                auto inner = parse_statement();
                if (inner)
                    cb->stmts.push_back(std::move(inner));
                else
                    synchronize();
            }
            (void)expect(TokenKind::RBRACE,
                         "se esperaba '}' al cerrar comptime block");
            return cb;
        }
        // `comptime for (i in lo..hi) { body }` unrolled.
        // Sintaxis: `comptime for (IDENT in EXPR `..` EXPR) { body }`
        // o `..=` para rango inclusivo.
        if (current_.lexeme == "comptime" &&
            mut_lex.peek_at(0).kind == TokenKind::KW_FOR) {
            const SourceLoc loc = current_.loc;
            (void)consume(); // 'comptime'
            (void)consume(); // 'for'
            (void)expect(TokenKind::LPAREN,
                         "se esperaba '(' tras 'comptime for'");
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here(
                    "se esperaba nombre del index tras 'comptime for ('");
                synchronize();
                return nullptr;
            }
            auto cf = std::make_unique<ast::ComptimeForStmt>();
            cf->loc = loc;
            cf->var_name = consume().lexeme;
            if (current_.kind != TokenKind::KW_IN) {
                error_here("se esperaba 'in' tras el nombre del index");
            } else {
                (void)consume();
            }
            cf->lo_expr = parse_expr();
            /* `..` o `..=` para rango. */
            if (current_.kind == TokenKind::DOTDOT) {
                (void)consume();
                cf->inclusive = false;
            } else if (current_.kind == TokenKind::DOTDOTEQ) {
                (void)consume();
                cf->inclusive = true;
            } else {
                error_here(
                    "se esperaba '..' o '..=' en el rango de comptime for");
            }
            cf->hi_expr = parse_expr();
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' tras el rango de comptime for");
            cf->body = parse_statement();
            return cf;
        }
        // BugFix R6: `foreach (T x : col) body` como alias de
        // `for (T x : col) body`.  `foreach` no es keyword reservada;
        // se reconoce contextualmente solo cuando aparece en posicion
        // de statement seguido de `(`.  parse_for_stmt acepta ambos
        // tokens (KW_FOR o IDENT("foreach")) al inicio.
        if (current_.lexeme == "foreach" &&
            mut_lex.peek_at(0).kind == TokenKind::LPAREN) {
            return parse_for_stmt();
        }
    }
    switch (current_.kind) {
    case TokenKind::LBRACE: return parse_block();
    case TokenKind::KW_IF: return parse_if_stmt();
    case TokenKind::KW_WHILE: return parse_while_stmt();
    case TokenKind::KW_DO: return parse_do_while_stmt();
    case TokenKind::KW_FOR: return parse_for_stmt();
    case TokenKind::KW_RETURN: return parse_return_stmt();
    case TokenKind::KW_CONST: {
        (void)consume();
        return parse_var_decl_stmt(true);
    }
    case TokenKind::KW_STATIC: {
        // `static [const]? <T> <n> = init;` local: var-decl con duracion
        // ESTATICA (una instancia, init-once).  Persiste entre llamadas.
        (void)consume(); // 'static'
        bool sc = false;
        if (current_.kind == TokenKind::KW_CONST) {
            (void)consume();
            sc = true;
        }
        auto vd = parse_var_decl_stmt(sc);
        if (vd && vd->kind == ast::NodeKind::VarDeclStmt)
            static_cast<ast::VarDeclStmt *>(vd.get())->is_static = true;
        return vd;
    }
    case TokenKind::KW_BREAK: {
        auto s = std::make_unique<ast::BreakStmt>();
        s->loc = current_.loc;
        (void)consume();
        (void)expect(TokenKind::SEMICOLON, "se esperaba ';' tras 'break'");
        return s;
    }
    case TokenKind::KW_CONTINUE: {
        auto s = std::make_unique<ast::ContinueStmt>();
        s->loc = current_.loc;
        (void)consume();
        (void)expect(TokenKind::SEMICOLON, "se esperaba ';' tras 'continue'");
        return s;
    }
    case TokenKind::KW_GOTO: {
        auto s = std::make_unique<ast::GotoStmt>();
        s->loc = current_.loc;
        (void)consume(); // 'goto'
        if (current_.kind != TokenKind::IDENTIFIER) {
            error_here("se esperaba un identificador (label) tras 'goto'");
            return nullptr;
        }
        s->label = consume().lexeme;
        (void)expect(TokenKind::SEMICOLON, "se esperaba ';' tras 'goto label'");
        return s;
    }
    case TokenKind::KW_TRY: return parse_try_stmt();
    case TokenKind::KW_THROW: return parse_throw_stmt();
    case TokenKind::KW_SYNCHRONIZED: return parse_synchronized_stmt();
    case TokenKind::KW_ASM: return parse_asm_stmt();
    case TokenKind::KW_MATCH: {
        // Match como statement (destructuring de ADT como
        // sentencia de control de flujo).  El parser de
        // expresion ya sabe parsear MatchExpr (rama en
        // parse_primary), pero como statement queremos que NO
        // exija un `;` final (igual que if/while/for).
        auto e = parse_match_expr();
        if (!e) return nullptr;
        auto es = std::make_unique<ast::ExprStmt>();
        es->loc = e->loc;
        es->expr = std::move(e);
        // `;` opcional tras `}`.
        if (current_.kind == TokenKind::SEMICOLON) (void)consume();
        return es;
    }
    default:
        //  AS inc.2: `register("reg") T name;` es un var-decl con
        // storage-class; se enruta a parse_var_decl_stmt aunque
        // `register` sea un IDENTIFIER (no keyword) y starts_type() lo
        // ignore.
        if (looks_like_register_storage()) return parse_var_decl_stmt(false);
        /* `in i64* p = ...;` / `out T* q;`: la direccion va DELANTE del tipo,
         * asi que `starts_type()` -- que mira el token de ahora -- no la ve.
         * Mismo caso que `register("reg")`, y se resuelve igual.
         *
         * No puede confundirse con una expresion: `out` como variable va
         * seguido de `=`, `.`, `[`, `(` o un operador, y ninguno de esos abre
         * un tipo.  Y el `in` del `for (x in col)` no esta al principio de un
         * statement. */
        if (looks_like_param_dir_storage()) return parse_var_decl_stmt(false);
        if (starts_type()) return parse_var_decl_stmt(false);
        return parse_expr_stmt();
    }
}

std::unique_ptr<ast::Stmt> Parser::parse_var_decl_stmt(bool is_const,
                                                       bool from_comptime) {
    auto vd = std::make_unique<ast::VarDeclStmt>();
    vd->loc = current_.loc;
    vd->is_const = is_const;
    /* Direccion: `in i64* vista = null;`.  El MISMO lector que en un
     * parametro, para que la marca no signifique una cosa aqui y otra alli.
     * Lo que cambia es lo que queda de ella: en un parametro dice ademas que
     * hace la funcion; en una variable solo el permiso. */
    vd->dir = parse_opt_param_dir_();
    /*  AS inc.2: storage-class `register("reg")` antes del tipo.
     * El patron ya fue validado por looks_like_register_storage() en el
     * router, pero KW_CONST / for-init tambien llaman aqui; reconsumimos
     * de forma defensiva solo cuando el patron `register ( "reg" )`
     * aparece literalmente, dejando intacto cualquier otro caso. */
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "register" &&
        lex_.peek_at(0).kind == TokenKind::LPAREN &&
        lex_.peek_at(1).kind == TokenKind::STRING_LIT &&
        lex_.peek_at(2).kind == TokenKind::RPAREN) {
        (void)consume();                    /* 'register' */
        (void)consume();                    /* '(' */
        vd->reg_binding = current_.str_val; /* nombre del registro */
        (void)consume();                    /* STRING_LIT */
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' tras register(\"reg\")");
    }
    /* Z.6: modificador `shared` en var-decl marca el storage class.
     * Disambiguacion con el smart pointer `shared<T>`: si tras `shared`
     * viene `<`, NO es modificador (es el tipo smart pointer); si
     * viene cualquier otro starter de tipo (identificador, keyword
     * primitivo, etc.), SI es modificador y consumimos.  El parser
     * de @c parse_type_node luego ve el tipo "limpio" sin shared. */
    if (current_.kind == TokenKind::KW_SHARED &&
        lex_.peek_at(0).kind != TokenKind::LT) {
        (void)consume(); /* descartar 'shared' modifier */
        vd->is_shared = true;
    }
    /* `auto NAME = init;` o `var NAME = init;` -- inferencia
     * local de tipo desde el init.  `auto`/`var` se reconocen como
     * IDENTIFIER contextual seguido de OTRO IDENTIFIER (el nombre);
     * asi NO los reservamos como keywords y codigo existente con
     * variables llamadas `auto`/`var` sigue funcionando salvo en
     * posicion de tipo en var-decl. */
    if (current_.kind == TokenKind::IDENTIFIER &&
        (current_.lexeme == "auto" || current_.lexeme == "var") &&
        lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
        (void)consume(); /* descartar 'auto' o 'var' */
        vd->type = nullptr;
        vd->infer_type = true;
    } else {
        vd->type = parse_type_node();
    }
    // const-correctness C-style: un `const` LIDER sobre un tipo PUNTERO
    // qualifica el APUNTADO (`const char *p` = puntero a const char, puntero
    // MUTABLE), no el binding.  Sobre un tipo no-puntero, `const` sigue siendo
    // binding const (valor inmutable -- semantica Vesta existente + comptime).
    // No aplica a comptime (su `const` es "compile-time", no del pointee).
    if (is_const && !from_comptime && vd->type &&
        vd->type->kind == ast::NodeKind::PointerTypeNode) {
        ast::TypeNode *inner = vd->type.get();
        while (inner->kind == ast::NodeKind::PointerTypeNode)
            inner = static_cast<ast::PointerTypeNode *>(inner)->pointee.get();
        if (inner) inner->is_const = true;
        vd->is_const = false; // el puntero/binding es mutable (C)
    }
    // Puntero a funcion estilo C como variable: `R (*name)(params) = init;`.
    bool got_fp_name = false;
    {
        std::string fp_name;
        std::unique_ptr<ast::TypeNode> fp_type;
        if (vd->type && try_parse_c_func_ptr_(vd->type, fp_name, fp_type)) {
            vd->type = std::move(fp_type);
            vd->name = std::move(fp_name);
            got_fp_name = true;
        }
    }
    // azucar: `T !!name = init;` equivale a
    // `nonnull T name = !!init;`.  El `!!` entre tipo y nombre
    // marca el tipo como no-null y envuelve el inicializador con
    // unwrap para insertar el check runtime + assert compile-time.
    bool inline_nonnull = false;
    if (!got_fp_name && current_.kind == TokenKind::BANG_BANG) {
        inline_nonnull = true;
        (void)consume();
        if (vd->type) vd->type->is_nonnull = true;
    }
    if (!got_fp_name) {
        if (!is_name_token(current_.kind)) {
            error_expected_name("nombre de variable",
                                "se esperaba un nombre tras el tipo");
            return nullptr;
        }
        vd->name = consume().lexeme;
    }
    // Sintaxis C-style: `T name[N]` -> wrappear el tipo base en
    // ArrayTypeNode(N).  Acepta tambien `T name[]` (sin tamano,
    // tipico de parametros con decay-to-ptr).  Cadena permitida
    // para matrices: `T name[N][M]`.
    //
    // Bug fix 2026-05-23: para matrices `T name[N][M][K]`, la dimension
    // MAS A LA IZQUIERDA es la EXTERIOR (igual que C).  Sea result =
    // T[N][M][K] significa: array de N de array de M de array de K de T.
    // El orden de los `[N]`, `[M]`, `[K]` en el wrap es:
    //   outer = N -> element = (array M de (array K de T)).
    // El wrap NAIVE (siguiente bracket envuelve al previo) invierte el
    // orden y produce T[K][M][N].  Coleccionamos los tamanyos en
    // vector y wrappeamos de DERECHA a IZQUIERDA.
    if (current_.kind == TokenKind::LBRACKET) {
        std::vector<std::pair<SourceLoc, std::unique_ptr<ast::Expr>>> dims;
        while (current_.kind == TokenKind::LBRACKET) {
            const SourceLoc abr_loc = current_.loc;
            (void)consume(); // '['
            std::unique_ptr<ast::Expr> sz;
            if (current_.kind != TokenKind::RBRACKET) {
                sz = parse_expr();
            }
            (void)expect(TokenKind::RBRACKET,
                         "se esperaba ']' al cerrar el tamano del array");
            dims.emplace_back(abr_loc, std::move(sz));
        }
        // Wrap de derecha a izquierda: la ULTIMA dimension envuelve al
        // tipo base; cada dimension anterior envuelve la previa.  Asi
        // T[N][M][K] -> ArrayType(N, ArrayType(M, ArrayType(K, T))).
        for (auto it = dims.rbegin(); it != dims.rend(); ++it) {
            auto an = std::make_unique<ast::ArrayTypeNode>();
            an->loc = it->first;
            an->element_type = std::move(vd->type);
            an->size_expr = std::move(it->second);
            vd->type = std::move(an);
        }
    }
    if (match(TokenKind::ASSIGN)) {
        vd->init = parse_expr();
        // Si la sintaxis fue `T !!name = init`, envolvemos el init
        // con un `!!` automatico para que el runtime falle pronto si
        // init resulta null.  Si el usuario ya escribio `!!init`, el
        // doble unwrap es idempotente (segundo unwrap sobre valor no
        // null = valor mismo).
        if (inline_nonnull && vd->init) {
            auto un = std::make_unique<ast::UnaryExpr>();
            un->loc = vd->init->loc;
            un->op = ast::UnOp::Unwrap;
            un->operand = std::move(vd->init);
            vd->init = std::move(un);
        }
    }
    (void)expect(TokenKind::SEMICOLON,
                 "se esperaba ';' al final de la declaracion");
    return vd;
}

std::unique_ptr<ast::Stmt> Parser::parse_if_stmt() {
    auto s = std::make_unique<ast::IfStmt>();
    s->loc = current_.loc;
    (void)consume(); // 'if'
    (void)expect(TokenKind::LPAREN, "se esperaba '(' tras 'if'");
    s->cond = parse_expr();
    (void)expect(TokenKind::RPAREN, "se esperaba ')' tras la condicion");
    s->then_branch = parse_statement();
    if (match(TokenKind::KW_ELSE)) {
        s->else_branch = parse_statement();
    }
    return s;
}

std::unique_ptr<ast::Stmt> Parser::parse_while_stmt() {
    auto s = std::make_unique<ast::WhileStmt>();
    s->loc = current_.loc;
    (void)consume(); // 'while'
    (void)expect(TokenKind::LPAREN, "se esperaba '(' tras 'while'");
    s->cond = parse_expr();
    (void)expect(TokenKind::RPAREN, "se esperaba ')' tras la condicion");
    s->body = parse_statement();
    return s;
}

std::unique_ptr<ast::Stmt> Parser::parse_do_while_stmt() {
    // Forma: do <stmt> while ( <expr> ) ;
    // En el lowering tiene un manejador dedicado (lower_do_while)
    // que baja directamente el patron CFG sin duplicar el body en el AST.
    auto s = std::make_unique<ast::DoWhileStmt>();
    s->loc = current_.loc;
    (void)consume(); // 'do'
    s->body = parse_statement();
    (void)expect(TokenKind::KW_WHILE,
                 "se esperaba 'while' tras el cuerpo de 'do'");
    (void)expect(TokenKind::LPAREN, "se esperaba '(' tras 'while'");
    s->cond = parse_expr();
    (void)expect(TokenKind::RPAREN, "se esperaba ')' tras la condicion");
    (void)expect(TokenKind::SEMICOLON,
                 "se esperaba ';' al final de 'do-while'");
    return s;
}

std::unique_ptr<ast::Stmt> Parser::parse_for_stmt() {
    const SourceLoc for_loc = current_.loc;
    // Aceptar tanto KW_FOR como IDENT("foreach") contextual.  Ambos
    // delegan al mismo handler que detecta automaticamente la
    // sintaxis foreach (`T x : col`) vs counted-for (`init; cond; step`).
    (void)consume(); // 'for' o 'foreach'
    (void)expect(TokenKind::LPAREN, "se esperaba '(' tras 'for'/'foreach'");

    // aceptar `comptime const/var T NAME = expr` como init del for.
    // Esto permite usar el counter como comptime value dentro del body
    // si el resto del for esta en contexto comptime (e.g. dentro de
    // comptime fn body).  Sintaxis: `for (comptime var i64 i = 0; ...)`.
    // El parser detecta `comptime` aqui y construye un VarDeclStmt con
    // is_comptime=true; el resto del for se procesa normalmente.
    bool init_is_comptime = false;
    bool init_is_comptime_const = false;
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "comptime") {
        Lexer &mut_lex = const_cast<Lexer &>(lex_);
        if (mut_lex.peek_at(0).kind == TokenKind::KW_CONST) {
            (void)consume(); /* comptime */
            (void)consume(); /* const */
            init_is_comptime = true;
            init_is_comptime_const = true;
        } else if (mut_lex.peek_at(0).kind == TokenKind::IDENTIFIER &&
                   mut_lex.peek_at(0).lexeme == "var") {
            (void)consume(); /* comptime */
            (void)consume(); /* var */
            init_is_comptime = true;
        }
    }

    // Disambiguacion entre foreach y counted-for.
    //   foreach: `for (T NAME : EXPR) body`
    //   counted: `for (init? ; cond? ; step?) body`
    // Ambos empiezan con un tipo opcional; la diferencia es lo que
    // viene tras el primer identificador.  Hacemos lookahead: si
    // encontramos `:` despues de `T NAME`, vamos por la rama
    // foreach; de lo contrario reusamos parse_var_decl_stmt.
    if (starts_type()) {
        // Save state to allow rollback if not foreach.
        // Parseamos el tipo (ya valido por starts_type).
        auto type_node = parse_type_node();
        if (!type_node) {
            error_here("tipo invalido en for");
            return nullptr;
        }
        // Tras el tipo: identificador.
        if (current_.kind == TokenKind::IDENTIFIER) {
            std::string name = consume().lexeme;
            if (current_.kind == TokenKind::COLON) {
                // foreach
                (void)consume(); // ':'
                auto fe = std::make_unique<ast::ForEachStmt>();
                fe->loc = for_loc;
                fe->iter_type = std::move(type_node);
                fe->iter_name = std::move(name);
                fe->iter_expr = parse_expr();
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' tras for-each");
                fe->body = parse_statement();
                return fe;
            }
            // No es foreach: reconstruimos el VarDeclStmt manualmente
            // (no podemos retroceder tokens facilmente).
            auto s = std::make_unique<ast::ForStmt>();
            s->loc = for_loc;
            auto vd = std::make_unique<ast::VarDeclStmt>();
            vd->loc = for_loc;
            vd->type = std::move(type_node);
            vd->name = std::move(name);
            /* `for (comptime var/const T NAME = expr; ...)` */
            vd->is_comptime = init_is_comptime;
            vd->is_const = init_is_comptime_const;
            if (match(TokenKind::ASSIGN)) {
                vd->init = parse_expr();
            }
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' tras init del 'for'");
            s->init = std::move(vd);
            if (current_.kind != TokenKind::SEMICOLON) s->cond = parse_expr();
            (void)expect(TokenKind::SEMICOLON,
                         "se esperaba ';' tras la condicion del 'for'");
            if (current_.kind != TokenKind::RPAREN) s->step = parse_expr();
            (void)expect(TokenKind::RPAREN, "se esperaba ')' al cerrar 'for'");
            s->body = parse_statement();
            return s;
        }
        error_expected_name("nombre de variable del 'for'",
                            "se esperaba un identificador tras el tipo en for");
        return nullptr;
    }

    // No tipo al inicio: counted-for sin init de tipo o vacio.
    auto s = std::make_unique<ast::ForStmt>();
    s->loc = for_loc;
    if (!match(TokenKind::SEMICOLON)) {
        s->init = parse_expr_stmt();
    }
    if (current_.kind != TokenKind::SEMICOLON) s->cond = parse_expr();
    (void)expect(TokenKind::SEMICOLON,
                 "se esperaba ';' tras la condicion del 'for'");
    if (current_.kind != TokenKind::RPAREN) s->step = parse_expr();
    (void)expect(TokenKind::RPAREN, "se esperaba ')' al cerrar 'for'");
    s->body = parse_statement();
    return s;
}

std::unique_ptr<ast::Stmt> Parser::parse_return_stmt() {
    auto s = std::make_unique<ast::ReturnStmt>();
    s->loc = current_.loc;
    (void)consume(); // 'return'
    if (current_.kind != TokenKind::SEMICOLON) {
        s->value = parse_expr();
    }
    (void)expect(TokenKind::SEMICOLON, "se esperaba ';' tras 'return'");
    return s;
}

std::unique_ptr<ast::Stmt> Parser::parse_expr_stmt() {
    auto s = std::make_unique<ast::ExprStmt>();
    s->loc = current_.loc;
    s->expr = parse_expr();
    (void)expect(TokenKind::SEMICOLON,
                 "se esperaba ';' al final del statement");
    return s;
}

// -----------------------------------------------------------------
// try { ... } catch (T e) { ... } catch (...) { ... } finally { ... }
//
// Sintaxis
//   - El catch puede omitir el binding: `catch (T) { ... }`.
//   - El catch sin tipo `catch { ... }` o `catch (e) { ... }` es
//     catch-all (el tipo se trata como nullptr en bytecode).
//   - finally es opcional (en MVP se acepta sintacticamente y se
//     emite como bloque post-catch).
// -----------------------------------------------------------------
std::unique_ptr<ast::Stmt> Parser::parse_try_stmt() {
    auto s = std::make_unique<ast::TryStmt>();
    s->loc = current_.loc;
    (void)consume(); // 'try'
    s->body = parse_block();
    if (!s->body) return nullptr;
    while (current_.kind == TokenKind::KW_CATCH) {
        ast::CatchClause cc;
        cc.loc = current_.loc;
        (void)consume(); // 'catch'
        (void)expect(TokenKind::LPAREN, "se esperaba '(' tras 'catch'");
        // Aceptamos: `catch (T e)`, `catch (T)`, `catch ()`.  El primer
        // identificador es el tipo si hay dos, o el binding si hay uno.
        if (current_.kind == TokenKind::IDENTIFIER) {
            std::string first = consume().lexeme;
            if (current_.kind == TokenKind::IDENTIFIER) {
                cc.exc_class_name = std::move(first);
                cc.var_name = consume().lexeme;
            } else {
                // Una sola identifier: la tratamos como tipo (sin binding).
                cc.exc_class_name = std::move(first);
            }
        }
        (void)expect(TokenKind::RPAREN, "se esperaba ')' tras catch parametro");
        cc.body = parse_block();
        if (!cc.body) return nullptr;
        s->catches.push_back(std::move(cc));
    }
    if (current_.kind == TokenKind::KW_FINALLY) {
        (void)consume();
        s->finally_body = parse_block();
    }
    if (s->catches.empty() && !s->finally_body) {
        error_here("'try' requiere al menos un 'catch' o 'finally'");
    }
    return s;
}

std::unique_ptr<ast::Stmt> Parser::parse_throw_stmt() {
    auto s = std::make_unique<ast::ThrowStmt>();
    s->loc = current_.loc;
    (void)consume(); // 'throw'
    s->value = parse_expr();
    (void)expect(TokenKind::SEMICOLON, "se esperaba ';' tras 'throw <expr>'");
    return s;
}

/**
 * @brief Parsea @c synchronized @c (expr) @c { @c body @c }.
 *
 * Sintaxis: paren obligatorios alrededor de la expresion-target,
 * llaves obligatorias alrededor del body (no admitimos el body
 * como statement suelto, porque querramos ejecutar mas de una
 * instruccion casi siempre).
 */
std::unique_ptr<ast::Stmt> Parser::parse_synchronized_stmt() {
    auto s = std::make_unique<ast::SynchronizedStmt>();
    s->loc = current_.loc;
    (void)consume(); // 'synchronized'
    (void)expect(TokenKind::LPAREN, "se esperaba '(' tras 'synchronized'");
    s->target = parse_expr();
    (void)expect(TokenKind::RPAREN,
                 "se esperaba ')' tras 'synchronized (expr'");
    if (current_.kind != TokenKind::LBRACE) {
        error_here("se esperaba '{' tras 'synchronized (expr)'");
        return nullptr;
    }
    s->body = parse_block();
    if (!s->body) return nullptr;
    return s;
}

// ---------------------------------------------------------------------
//  AS: inline asm nativo.
//
//   asm [volatile|nomem|preserves_flags|pure] {
//       <NASM Intel verbatim>
//   } [clobbers("rdx", "memory", "flags")] ;
//
// El cuerpo se captura por RAW-SLICING del source (no se tokeniza
// semanticamente): tras el '{' guardamos el offset del primer token y
// avanzamos consumiendo tokens contando profundidad de llaves hasta el
// '}' de cierre, capturando su offset.  Es el mismo patron que el
// parametro `expr` de macros (MC.25).  Asi un comentario NASM `;` o un
// operando `[rax]` no rompen la captura (solo se cuentan offsets).
// ---------------------------------------------------------------------
std::unique_ptr<ast::Stmt> Parser::parse_asm_stmt() {
    auto s = std::make_unique<ast::AsmStmt>();
    s->loc = current_.loc;
    (void)consume(); // 'asm'

    // Calificadores contextuales (IDENTIFIER, no keywords): se aceptan
    // en cualquier orden antes del '{'.  `volatile` es el default; los
    // demas refinan la semantica que vera el optimizador en backends
    // nativos.  `pure` implica nomem + preserves_flags.
    while (current_.kind == TokenKind::IDENTIFIER) {
        const std::string &q = current_.lexeme;
        if (q == "volatile") {
            // Nivel VOLATILE: se analiza para contratos pero se emite verbatim.
            s->q_volatile = true;
            s->level = ast::AsmLevel::Volatile;
        } else if (q == "raw") {
            // Nivel RAW: caja negra, verbatim, CERO analisis -> tambien implica
            // noinfer (el usuario declara sus clobbers a mano; nada se
            // infiere).
            s->q_volatile = true;
            s->q_noinfer = true;
            s->level = ast::AsmLevel::Raw;
        } else if (q == "nomem") {
            s->q_nomem = true;
        } else if (q == "preserves_flags") {
            s->q_preserves_flags = true;
        } else if (q == "pure") {
            s->q_pure = true;
            s->q_nomem = true;
            s->q_preserves_flags = true;
        } else if (q == "noinfer") {
            s->q_noinfer = true;
        } else {
            break; // identificador desconocido -> debe seguir el '{'
        }
        (void)consume();
    }

    //  AS inc.7: lista opcional de operandos `( <clase> <nombre> [= expr],
    // ... )` ANTES del '{'.  El '{' queda como asm 100% real.  Cada enlace es
    // `<clase-de-registro> <nombre> [= <expr-de-entrada>]`; la clase es el
    // "tipo" (reg = el compilador elige; rax/... = fijo; xmm/ymm = vector;
    // mem = memoria).  Coma final permitida.
    if (current_.kind == TokenKind::LPAREN) {
        (void)consume(); // '('
        while (current_.kind != TokenKind::RPAREN &&
               current_.kind != TokenKind::END_OF_FILE) {
            ast::AsmOperand op;
            op.loc = current_.loc;
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here("se esperaba la clase de registro (reg, rax, xmm, "
                           "mem, ...) en el operando del asm");
                return nullptr;
            }
            op.reg_class = current_.lexeme;
            (void)consume();
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here("se esperaba el nombre del operando tras la clase "
                           "de registro");
                return nullptr;
            }
            op.name = current_.lexeme;
            (void)consume();
            // Inicializador opcional `= <expr>` (entrada).  Sin el =
            // scratch/out.
            if (current_.kind == TokenKind::ASSIGN) {
                (void)consume(); // '='
                op.init = parse_expr();
            }
            s->operands.push_back(std::move(op));
            if (current_.kind == TokenKind::COMMA) {
                (void)consume(); // ',' (coma final permitida)
            } else {
                break;
            }
        }
        if (current_.kind != TokenKind::RPAREN) {
            error_here(
                "se esperaba ')' al cerrar la lista de operandos del asm");
            return nullptr;
        }
        (void)consume(); // ')'
    }

    // Clausula opcional `clobber(...)` o `clobbers(...)` ANTES del '{' (modelo
    // inc.7).  Mismo parseo que la clausula legacy tras '}'.
    if (current_.kind == TokenKind::IDENTIFIER &&
        (current_.lexeme == "clobber" || current_.lexeme == "clobbers")) {
        (void)consume(); // 'clobber'/'clobbers'
        (void)expect(TokenKind::LPAREN, "se esperaba '(' tras 'clobber'");
        // Acepta IDENTIFICADORES desnudos (modelo inc.7: `clobber(flags,
        // memory)`) o strings (legacy `clobbers("flags")`).
        while (current_.kind == TokenKind::STRING_LIT ||
               current_.kind == TokenKind::RAW_STRING_LIT ||
               current_.kind == TokenKind::IDENTIFIER) {
            const std::string c = (current_.kind == TokenKind::IDENTIFIER)
                                      ? current_.lexeme
                                      : current_.str_val;
            (void)consume();
            if (c == "memory")
                s->clobbers_memory = true;
            else if (c == "flags" || c == "cc")
                s->clobbers_flags = true;
            else if (!c.empty())
                s->clobbers.push_back(c);
            if (current_.kind == TokenKind::COMMA) {
                (void)consume();
                continue;
            }
            break;
        }
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' al cerrar 'clobber(...)'");
    }

    if (current_.kind != TokenKind::LBRACE) {
        error_here("se esperaba '{' tras 'asm' (y calificadores/operandos "
                   "opcionales)");
        return nullptr;
    }
    (void)consume(); // '{'

    // Raw-slice del cuerpo: desde el primer token tras '{' hasta el '}'
    // de cierre a profundidad 0.
    const std::string &src = lex_.source_buffer();
    const uint32_t start_off = current_.loc.offset;
    s->body_loc = current_.loc; // inicio del cuerpo: base para mapear errores
    uint32_t end_off = start_off;
    int brace_depth = 1; // ya consumimos el '{' de apertura
    while (current_.kind != TokenKind::END_OF_FILE) {
        if (current_.kind == TokenKind::RBRACE) {
            --brace_depth;
            if (brace_depth == 0) {
                end_off = current_.loc.offset; // offset del '}' de cierre
                (void)consume();               // consumir '}'
                break;
            }
        } else if (current_.kind == TokenKind::LBRACE) {
            ++brace_depth;
        }
        (void)consume();
    }
    if (brace_depth != 0) {
        error_here("se esperaba '}' al cerrar el bloque 'asm'");
        return nullptr;
    }
    // Trim de whitespace final del span capturado.
    while (end_off > start_off && end_off <= src.size() &&
           (src[end_off - 1] == ' ' || src[end_off - 1] == '\t' ||
            src[end_off - 1] == '\n' || src[end_off - 1] == '\r')) {
        --end_off;
    }
    if (start_off <= src.size() && end_off >= start_off &&
        end_off <= src.size()) {
        s->body = src.substr(start_off, end_off - start_off);
    }

    // Clausula opcional `clobbers("rdx", "memory", "flags")`.  `clobbers`
    // es IDENTIFIER contextual (no keyword).  "memory" y "flags"/"cc"
    // son efectos especiales; el resto son registros.
    if (current_.kind == TokenKind::IDENTIFIER &&
        current_.lexeme == "clobbers") {
        (void)consume(); // 'clobbers'
        (void)expect(TokenKind::LPAREN, "se esperaba '(' tras 'clobbers'");
        while (current_.kind == TokenKind::STRING_LIT ||
               current_.kind == TokenKind::RAW_STRING_LIT) {
            const std::string c = current_.str_val;
            (void)consume();
            if (c == "memory")
                s->clobbers_memory = true;
            else if (c == "flags" || c == "cc")
                s->clobbers_flags = true;
            else if (!c.empty())
                s->clobbers.push_back(c);
            if (current_.kind == TokenKind::COMMA) {
                (void)consume();
                continue;
            }
            break;
        }
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' al cerrar 'clobbers(...)'");
    }

    // `;` opcional tras el bloque (igual que if/while/synchronized).
    if (current_.kind == TokenKind::SEMICOLON) (void)consume();
    return s;
}

// ---------------------------------------------------------------------
// Expresiones (cascada de precedencias).
// ---------------------------------------------------------------------

std::unique_ptr<ast::Expr> Parser::parse_expr() {
    /* Misma medida que en las sentencias: el nodo se queda con la posicion de
     * su primer token y la longitud de ESE token, no la de la expresion.  Aqui
     * se mide lo que de verdad ocupa, que es lo que permite subrayar `x / y` y
     * no solo la `x`.  En el envoltorio para que valga para todas las formas de
     * expresion sin tener que acordarse en cada una. */
    const vx::SourceLoc ini = current_.loc;
    auto e = parse_assignment();
    if (e && e->loc.offset >= ini.offset) {
        /* Una expresion EMPIEZA donde empieza su primer token.  El nodo de una
         * operacion binaria se situa donde se creo -- en el operando derecho --
         * asi que tomar su posicion dejaba fuera todo lo de la izquierda:
         * `x / this.valor` se subrayaba desde `this`. */
        const uint32_t fin = current_.loc.offset;
        if (fin > ini.offset) {
            e->loc.line = ini.line;
            e->loc.column = ini.column;
            e->loc.offset = ini.offset;
            e->loc.length = fin - ini.offset;
        }
    }
    return e;
}

std::unique_ptr<ast::Expr> Parser::parse_assignment() {
    // Asociatividad por la derecha.  Parseamos el lado izquierdo
    // como una expresion ternaria y, si vemos un operador de
    // asignacion, recursamos para el lado derecho.
    auto lhs = parse_ternary();
    ast::AssignOp op;
    if (ast::assignop_from_token(current_.kind, op)) {
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_assignment();
        auto a = std::make_unique<ast::AssignExpr>();
        a->loc = loc;
        a->op = op;
        a->target = std::move(lhs);
        a->value = std::move(rhs);
        return a;
    }
    return lhs;
}

/**
 * @brief operador ternario `cond ? then : else`.
 *
 * Precedencia: entre assignment (mas baja) y logical_or (mas alta).
 * Asociatividad por la derecha (igual que C/C++/Java).  El COLON
 * separa las dos ramas; ambas se parsean como `parse_assignment`
 * para que se acepten asignaciones en las ramas:
 *   `flag ? x = 1 : x = 2`  -- legal aunque inusual
 *
 * Cuidado con `match`: el COLON tambien aparece en arms de match
 * y en labels.  Pero parse_ternary solo consume `?` -> cualquier
 * COLON sin `?` previo no afecta a este path.
 */
std::unique_ptr<ast::Expr> Parser::parse_ternary() {
    auto cond = parse_logical_or();
    if (current_.kind != TokenKind::QUESTION) return cond;
    const SourceLoc loc = current_.loc;
    (void)consume(); /* '?' */
    auto then_expr = parse_assignment();
    (void)expect(TokenKind::COLON, "se esperaba ':' en la expresion ternaria");
    auto else_expr = parse_assignment();
    auto t = std::make_unique<ast::TernaryExpr>();
    t->loc = loc;
    t->cond = std::move(cond);
    t->then_expr = std::move(then_expr);
    t->else_expr = std::move(else_expr);
    return t;
}

/**
 * @brief Hace que un tramo abarque desde donde empieza @c ini hasta donde
 *        acaba el token @c fin.
 *
 * Los postfijos (`a.b`, `a->b`) guardaban como posicion la del OPERADOR, que
 * dice donde esta el punto pero no donde empieza ni acaba la expresion.  Sin
 * eso no se puede recortar el fuente para nombrarla, y al intentarlo salia el
 * propio punto.  Como cada nivel vuelve a construir sobre el anterior, el
 * tramo crece solo y una cadena `a.b.c` acaba sabiendo lo que ocupa.
 *
 * @param dst Tramo a corregir (se modifica).
 * @param ini Tramo del operando por el que empieza la expresion.
 * @param fin Ultimo token que forma parte de ella.
 */
static void extender_tramo(SourceLoc &dst, const SourceLoc &ini,
                           const Token &fin) {
    if (ini.offset == 0 || ini.offset > dst.offset) return;
    const uint32_t final_ = fin.loc.offset + (uint32_t)fin.lexeme.size();
    dst.line = ini.line;
    dst.column = ini.column;
    dst.offset = ini.offset;
    if (final_ > dst.offset) dst.length = final_ - dst.offset;
}

// Helper: macro-like factory para los niveles binarios izquierda-asociativos.
// Lo escribimos a mano en cada nivel en lugar de via macro/template para que
// el optimizador inlinee con visibilidad completa.
static std::unique_ptr<ast::Expr> make_binop(ast::BinOp op,
                                             std::unique_ptr<ast::Expr> lhs,
                                             std::unique_ptr<ast::Expr> rhs,
                                             SourceLoc loc) {
    auto b = std::make_unique<ast::BinaryExpr>();
    b->loc = loc;
    b->op = op;
    /* Una operacion binaria EMPIEZA donde empieza su operando izquierdo y
     * ACABA donde acaba el derecho.  Se le pasaba la posicion del OPERADOR, con
     * lo que al subrayar un fallo se marcaba desde el signo -- o desde el
     * operando derecho -- en vez de la operacion entera.  Como el nivel de
     * arriba vuelve a construir con el resultado de este, la extension crece
     * sola y cada subexpresion acaba sabiendo lo que ocupa. */
    if (lhs && lhs->loc.offset > 0 && lhs->loc.offset <= b->loc.offset) {
        const uint32_t fin = (rhs && rhs->loc.offset >= lhs->loc.offset)
                                 ? (rhs->loc.offset + rhs->loc.length)
                                 : (b->loc.offset + b->loc.length);
        b->loc.line = lhs->loc.line;
        b->loc.column = lhs->loc.column;
        b->loc.offset = lhs->loc.offset;
        if (fin > b->loc.offset) b->loc.length = fin - b->loc.offset;
    }
    b->lhs = std::move(lhs);
    b->rhs = std::move(rhs);
    return b;
}

std::unique_ptr<ast::Expr> Parser::parse_logical_or() {
    auto lhs = parse_logical_and();
    while (current_.kind == TokenKind::OR_OR) {
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_logical_and();
        lhs = make_binop(ast::BinOp::LogicalOr, std::move(lhs), std::move(rhs),
                         loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_logical_and() {
    auto lhs = parse_bitwise_or();
    while (current_.kind == TokenKind::AND_AND) {
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_bitwise_or();
        lhs = make_binop(ast::BinOp::LogicalAnd, std::move(lhs), std::move(rhs),
                         loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_bitwise_or() {
    auto lhs = parse_bitwise_xor();
    while (current_.kind == TokenKind::PIPE) {
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_bitwise_xor();
        lhs =
            make_binop(ast::BinOp::BitOr, std::move(lhs), std::move(rhs), loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_bitwise_xor() {
    auto lhs = parse_bitwise_and();
    while (current_.kind == TokenKind::CARET) {
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_bitwise_and();
        lhs =
            make_binop(ast::BinOp::BitXor, std::move(lhs), std::move(rhs), loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_bitwise_and() {
    auto lhs = parse_equality();
    while (current_.kind == TokenKind::AMP) {
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_equality();
        lhs =
            make_binop(ast::BinOp::BitAnd, std::move(lhs), std::move(rhs), loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_equality() {
    auto lhs = parse_relational();
    while (current_.kind == TokenKind::EQ || current_.kind == TokenKind::NEQ) {
        const ast::BinOp op =
            (current_.kind == TokenKind::EQ) ? ast::BinOp::Eq : ast::BinOp::Neq;
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_relational();
        lhs = make_binop(op, std::move(lhs), std::move(rhs), loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_relational() {
    auto lhs = parse_shift();
    while (current_.kind == TokenKind::LT || current_.kind == TokenKind::LE ||
           current_.kind == TokenKind::GT || current_.kind == TokenKind::GE) {
        ast::BinOp op = ast::BinOp::Lt;
        switch (current_.kind) {
        case TokenKind::LT: op = ast::BinOp::Lt; break;
        case TokenKind::LE: op = ast::BinOp::Le; break;
        case TokenKind::GT: op = ast::BinOp::Gt; break;
        case TokenKind::GE: op = ast::BinOp::Ge; break;
        default: break;
        }
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_shift();
        lhs = make_binop(op, std::move(lhs), std::move(rhs), loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_shift() {
    auto lhs = parse_additive();
    while (current_.kind == TokenKind::SHL || current_.kind == TokenKind::SHR) {
        const ast::BinOp op = (current_.kind == TokenKind::SHL)
                                  ? ast::BinOp::Shl
                                  : ast::BinOp::Shr;
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_additive();
        lhs = make_binop(op, std::move(lhs), std::move(rhs), loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_additive() {
    auto lhs = parse_multiplicative();
    while (current_.kind == TokenKind::PLUS ||
           current_.kind == TokenKind::MINUS) {
        const ast::BinOp op = (current_.kind == TokenKind::PLUS)
                                  ? ast::BinOp::Add
                                  : ast::BinOp::Sub;
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_multiplicative();
        lhs = make_binop(op, std::move(lhs), std::move(rhs), loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_multiplicative() {
    auto lhs = parse_unary();
    while (current_.kind == TokenKind::STAR ||
           current_.kind == TokenKind::SLASH ||
           current_.kind == TokenKind::PERCENT) {
        ast::BinOp op = ast::BinOp::Mul;
        switch (current_.kind) {
        case TokenKind::STAR: op = ast::BinOp::Mul; break;
        case TokenKind::SLASH: op = ast::BinOp::Div; break;
        case TokenKind::PERCENT: op = ast::BinOp::Mod; break;
        default: break;
        }
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto rhs = parse_unary();
        lhs = make_binop(op, std::move(lhs), std::move(rhs), loc);
    }
    return lhs;
}

std::unique_ptr<ast::Expr> Parser::parse_unary() {
    // Cast C-style `(T) expr`.  Comprobamos antes de los demas
    // unarios porque el cast tambien empieza con `(` y queremos
    // reconocerlo antes de caer al patron `(expr)`.
    // Compound literal C99: `(Tipo){...}` / `(Tipo<args>){...}`.  Construye un
    // valor struct anonimo inline (usable como arg, en un return, etc.) sin una
    // variable intermedia.  Se representa como un CastExpr con operando
    // InitListExpr; el type checker y el lowering lo tratan como construccion
    // de struct.  Debe comprobarse ANTES del cast (un nombre de struct plano no
    // pasa looks_like_cast, pero `(Nombre){` es inequivoco).
    if (current_.kind == TokenKind::LPAREN && looks_like_compound_literal()) {
        const SourceLoc loc = current_.loc;
        (void)consume(); // '('
        auto type_node = parse_type_node();
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' tras el tipo del compound literal");
        auto init = parse_primary(); // el '{...}' -> InitListExpr
        auto ce = std::make_unique<ast::CastExpr>();
        ce->loc = loc;
        ce->target_type = std::move(type_node);
        ce->operand = std::move(init);
        return ce;
    }
    if (current_.kind == TokenKind::LPAREN && looks_like_cast()) {
        const SourceLoc loc = current_.loc;
        (void)consume(); // '('
        auto type_node = parse_type_node();
        (void)expect(TokenKind::RPAREN, "se esperaba ')' al cerrar el cast");
        auto operand = parse_unary();
        auto ce = std::make_unique<ast::CastExpr>();
        ce->loc = loc;
        ce->target_type = std::move(type_node);
        ce->operand = std::move(operand);
        return ce;
    }
    // Unarios prefijo: ! ~ - + ++ -- & * await
    // El '&' produce AddrOf (toma direccion) y el '*' produce Deref
    // (lectura via puntero).  'await' (KW_AWAIT) bloquea hasta que el
    // future operando se resuelva.  Todos comparten precedencia.
    if (current_.kind == TokenKind::KW_AWAIT) {
        const SourceLoc loc = current_.loc;
        (void)consume();
        auto operand = parse_unary();
        auto u = std::make_unique<ast::UnaryExpr>();
        u->loc = loc;
        u->op = ast::UnOp::Await;
        u->operand = std::move(operand);
        return u;
    }
    switch (current_.kind) {
    case TokenKind::BANG:
    case TokenKind::BANG_BANG:
    case TokenKind::TILDE:
    case TokenKind::MINUS:
    case TokenKind::PLUS:
    case TokenKind::PLUS_PLUS:
    case TokenKind::MINUS_MINUS:
    case TokenKind::AMP:
    case TokenKind::STAR: {
        const SourceLoc loc = current_.loc;
        ast::UnOp op = ast::UnOp::Neg;
        switch (current_.kind) {
        case TokenKind::BANG: op = ast::UnOp::LogicalNot; break;
        case TokenKind::BANG_BANG: op = ast::UnOp::Unwrap; break;
        case TokenKind::TILDE: op = ast::UnOp::BitNot; break;
        case TokenKind::MINUS: op = ast::UnOp::Neg; break;
        case TokenKind::PLUS: op = ast::UnOp::Pos; break;
        case TokenKind::PLUS_PLUS: op = ast::UnOp::PreInc; break;
        case TokenKind::MINUS_MINUS: op = ast::UnOp::PreDec; break;
        case TokenKind::AMP: op = ast::UnOp::AddrOf; break;
        case TokenKind::STAR: op = ast::UnOp::Deref; break;
        default: break;
        }
        (void)consume();
        auto operand = parse_unary();
        // `-128i8` es valido y `128i8` no: el rango de un literal con signo
        // depende de si lleva el menos delante, asi que se marca aqui, que es
        // donde se sabe.
        if (op == ast::UnOp::Neg && operand &&
            operand->kind == ast::NodeKind::IntLitExpr)
            static_cast<ast::IntLitExpr *>(operand.get())->negated = true;
        auto u = std::make_unique<ast::UnaryExpr>();
        u->loc = loc;
        u->op = op;
        u->operand = std::move(operand);
        return u;
    }
    default: return parse_postfix();
    }
}

std::unique_ptr<ast::Expr> Parser::parse_postfix() {
    // Operadores postfix soportados: x++, x--, x(args), x[i],
    // x.field, x?.field, x?.[i], x?
    auto expr = parse_primary();
    while (true) {
        switch (current_.kind) {
        case TokenKind::PLUS_PLUS:
        case TokenKind::MINUS_MINUS: {
            const SourceLoc loc = current_.loc;
            const ast::UnOp op = (current_.kind == TokenKind::PLUS_PLUS)
                                     ? ast::UnOp::PostInc
                                     : ast::UnOp::PostDec;
            (void)consume();
            auto u = std::make_unique<ast::UnaryExpr>();
            u->loc = loc;
            u->op = op;
            u->operand = std::move(expr);
            expr = std::move(u);
            break;
        }

        case TokenKind::QUESTION: {
            // P2: operador postfix `?` para Result -- early-return.
            // Disambiguacion con el ternario `cond ? a : b`:
            //   - ternario: '?' seguido de algo que empieza una
            //     expresion (ident, literal, '(', '!', '-', etc.).
            //   - postfix-?: '?' seguido de un token que no puede
            //     empezar una expresion (';', ',', ')', ']', '}',
            //     binop, etc.).
            // Si NO es postfix-?, retornamos sin consumir el '?'
            // para que parse_ternary lo procese arriba.
            Lexer &mut_lex = const_cast<Lexer &>(lex_);
            // peek_at(0) es el token DESPUES del actual (current_ ya
            // contiene el `?`, asi que peek_at(0) es lo que viene
            // tras el `?`).
            const Token &next = mut_lex.peek_at(0);
            bool is_postfix_q = false;
            switch (next.kind) {
            case TokenKind::SEMICOLON:
            case TokenKind::COMMA:
            case TokenKind::RPAREN:
            case TokenKind::RBRACKET:
            case TokenKind::RBRACE:
            // binops + asignacion + comparacion + dot (chain)
            case TokenKind::PLUS:
            // STAR y AMP NO van aqui: son tambien unarios prefijo (deref `*p`
            // y addr-of `&x`), asi que `cond ? *ptr : x` / `cond ? &v : w`
            // deben leerse como TERNARIO (rama then = deref/addr-of), no como
            // postfix-? seguido de mul/and.  Mismo criterio que MINUS/LT/GT
            // (default = ternario); para el postfix-? con `*`/`&` agrupar
            // explicitamente: `(expr?) * x`.
            case TokenKind::SLASH:
            case TokenKind::PERCENT:
            case TokenKind::PIPE:
            case TokenKind::CARET:
            case TokenKind::AND_AND:
            case TokenKind::OR_OR:
            case TokenKind::SHL:
            case TokenKind::SHR:
            case TokenKind::ASSIGN:
            case TokenKind::EQ:
            case TokenKind::NEQ:
            case TokenKind::LE:
            case TokenKind::GE:
            case TokenKind::PLUS_ASSIGN:
            case TokenKind::MINUS_ASSIGN:
            case TokenKind::STAR_ASSIGN:
            case TokenKind::SLASH_ASSIGN:
            case TokenKind::DOT:
            case TokenKind::QUESTION: // chain a?b? -> primero postfix
            case TokenKind::END_OF_FILE: is_postfix_q = true; break;
            default:
                // MINUS y LT/GT son ambiguos pero por defecto
                // se quedan como ternario (mas comun el ternario).
                // Si el usuario quiere postfix-? en estos casos,
                // puede agrupar: (expr?) + x.
                is_postfix_q = false;
                break;
            }
            if (!is_postfix_q) {
                return expr; // dejar el '?' para parse_ternary
            }
            const SourceLoc loc = current_.loc;
            (void)consume(); // consume '?'
            auto t = std::make_unique<ast::TryExpr>();
            t->loc = loc;
            t->operand = std::move(expr);
            expr = std::move(t);
            break;
        }
        case TokenKind::LT: {
            /* Soporte para type-args en posicion postfix:
             *   - builtins comptime: @c sizeof<T>(), @c offsetof<T>(..)
             *   - funciones libres genericas: @c id<i64>(x)
             *   - METODOS genericos (#4): @c obj.metodo<U>(args), donde
             *     @c expr es un FieldAccessExpr (`obj.metodo`).
             * Para evitar el conflicto con el operador de comparacion
             * (@c foo < bar / @c obj.f < x) hacemos un lookahead: solo se
             * trata como type-args si el patron es `... < TIPOS > (`.
             * Un nombre builtin comptime conocido salta el lookahead. */
            const bool is_ident = (expr->kind == ast::NodeKind::IdentExpr);
            const bool is_field =
                (expr->kind == ast::NodeKind::FieldAccessExpr);
            if (!is_ident && !is_field) {
                return expr;
            }
            /* Builtins comptime (`sizeof<T>`) no requieren lookahead; el
             * resto (fns genericas de usuario y metodos genericos) si. */
            bool need_lookahead = true;
            if (is_ident) {
                const auto *id_chk =
                    static_cast<const ast::IdentExpr *>(expr.get());
                if (is_comptime_builtin_name(id_chk->name))
                    need_lookahead = false;
            }
            if (need_lookahead) {
                /* Lookahead: tras `<` esperamos tokens de tipo y
                 * eventualmente `>` (o `>>`) seguido de `(`.  Si no, es
                 * una comparacion -> fallback al binary_expr. */
                Lexer &mut_lex = const_cast<Lexer &>(lex_);
                bool looks_like_type_args = false;
                int depth = 0;
                for (size_t k = 0; k < 32; ++k) {
                    const auto &tk = mut_lex.peek_at(k);
                    if (tk.kind == TokenKind::LT) {
                        depth++;
                        continue;
                    }
                    if (tk.kind == TokenKind::GT) {
                        if (depth == 0) {
                            const auto &after = mut_lex.peek_at(k + 1);
                            looks_like_type_args =
                                (after.kind == TokenKind::LPAREN);
                            break;
                        }
                        depth--;
                        continue;
                    }
                    if (tk.kind == TokenKind::SHR) {
                        if (depth <= 1) {
                            const auto &after = mut_lex.peek_at(k + 1);
                            looks_like_type_args =
                                (after.kind == TokenKind::LPAREN);
                            break;
                        }
                        depth -= 2;
                        continue;
                    }
                    if (tk.kind == TokenKind::SEMICOLON ||
                        tk.kind == TokenKind::LBRACE ||
                        tk.kind == TokenKind::RBRACE ||
                        tk.kind == TokenKind::END_OF_FILE)
                        break;
                }
                if (!looks_like_type_args) {
                    return expr;
                }
            }
            const SourceLoc loc = current_.loc;
            (void)consume(); /* '<' */
            std::vector<std::unique_ptr<ast::TypeNode>> tas;
            while (current_.kind != TokenKind::GT &&
                   current_.kind != TokenKind::SHR &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto ta = parse_type_node();
                if (!ta) break;
                tas.push_back(std::move(ta));
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect_close_angle(
                "se esperaba '>' al cerrar type args de la llamada generica");
            /* Tras los type args DEBE venir '(' para los args runtime. */
            if (current_.kind != TokenKind::LPAREN) {
                error_here(
                    "se esperaba '(' tras type args de la llamada generica");
                break;
            }
            (void)consume(); /* '(' */
            auto call = std::make_unique<ast::CallExpr>();
            call->loc = loc;
            call->callee = std::move(expr);
            call->type_args = std::move(tas);
            if (current_.kind != TokenKind::RPAREN) {
                while (true) {
                    auto arg = parse_expr();
                    if (arg) call->args.push_back(std::move(arg));
                    if (!match(TokenKind::COMMA)) break;
                }
            }
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' al cerrar la llamada");
            expr = std::move(call);
            break;
        }
        case TokenKind::LPAREN: {
            const SourceLoc loc = current_.loc;
            (void)consume();
            auto call = std::make_unique<ast::CallExpr>();
            call->loc = loc;
            /* Detectar @Macro con params @c expr: si el callee es un
             * IdentExpr cuyo nombre esta en @c macro_expr_params_,
             * para cada arg en posicion marcada hacemos raw-text
             * capture en lugar de parsear como expresion.  Las demas
             * posiciones siguen el flujo normal. */
            const std::vector<int> *expr_positions = nullptr;
            if (expr && expr->kind == ast::NodeKind::IdentExpr) {
                const auto *id =
                    static_cast<const ast::IdentExpr *>(expr.get());
                auto it = macro_expr_params_.find(id->name);
                if (it != macro_expr_params_.end()) {
                    expr_positions = &it->second;
                }
            }
            call->callee = std::move(expr);
            if (current_.kind != TokenKind::RPAREN) {
                int arg_idx = 0;
                while (true) {
                    bool is_raw = false;
                    if (expr_positions) {
                        for (int pos : *expr_positions) {
                            if (pos == arg_idx) {
                                is_raw = true;
                                break;
                            }
                        }
                    }
                    if (is_raw) {
                        /* Raw-text capture: leer source desde el
                         * offset del token actual hasta el siguiente
                         * COMMA o RPAREN a depth 0.  El lexer ya tiene
                         * el offset absoluto en current_.loc.offset. */
                        const std::string &src = lex_.source_buffer();
                        const uint32_t start_off = current_.loc.offset;
                        int paren_depth = 0;
                        int brack_depth = 0;
                        int brace_depth = 0;
                        uint32_t end_off = start_off;
                        /* Consumir tokens hasta el siguiente COMMA
                         * o RPAREN a depth 0.  Tracking paren/bracket/
                         * brace para no cortar dentro de subexprs. */
                        while (current_.kind != TokenKind::END_OF_FILE) {
                            if (paren_depth == 0 && brack_depth == 0 &&
                                brace_depth == 0) {
                                if (current_.kind == TokenKind::COMMA ||
                                    current_.kind == TokenKind::RPAREN) {
                                    end_off = current_.loc.offset;
                                    break;
                                }
                            }
                            switch (current_.kind) {
                            case TokenKind::LPAREN: ++paren_depth; break;
                            case TokenKind::RPAREN: --paren_depth; break;
                            case TokenKind::LBRACKET: ++brack_depth; break;
                            case TokenKind::RBRACKET: --brack_depth; break;
                            case TokenKind::LBRACE: ++brace_depth; break;
                            case TokenKind::RBRACE: --brace_depth; break;
                            default: break;
                            }
                            (void)consume();
                        }
                        if (end_off == start_off) {
                            /* No avanzamos: arg vacio.  Construimos
                             * un StringLit vacio. */
                            end_off = start_off;
                        }
                        /* Trim trailing whitespace del span. */
                        while (end_off > start_off && end_off <= src.size() &&
                               (src[end_off - 1] == ' ' ||
                                src[end_off - 1] == '\t' ||
                                src[end_off - 1] == '\n' ||
                                src[end_off - 1] == '\r')) {
                            --end_off;
                        }
                        std::string captured;
                        if (start_off < src.size() && end_off >= start_off &&
                            end_off <= src.size()) {
                            captured =
                                src.substr(start_off, end_off - start_off);
                        }
                        // Forwarding de expr-capture anidado: si el arg es
                        // EXACTAMENTE un identificador que es un param `expr`
                        // de la funcion actual, emitir un IdentExpr
                        // (referencia) en vez del texto crudo -- asi en
                        // AST-eval `code` resuelve al texto ya capturado por el
                        // macro externo, no al literal "code".
                        auto is_ident = [](const std::string &s) -> bool {
                            if (s.empty()) return false;
                            if (!(std::isalpha((unsigned char)s[0]) ||
                                  s[0] == '_'))
                                return false;
                            for (char c : s)
                                if (!(std::isalnum((unsigned char)c) ||
                                      c == '_'))
                                    return false;
                            return true;
                        };
                        if (is_ident(captured) &&
                            current_expr_param_names_.count(captured)) {
                            auto id = std::make_unique<ast::IdentExpr>();
                            id->loc = loc;
                            id->name = std::move(captured);
                            call->args.push_back(std::move(id));
                        } else {
                            auto slit = std::make_unique<ast::StringLitExpr>();
                            slit->loc = loc;
                            /* Huecos de interpolacion `${expr}` en el texto
                             * capturado: `source(...)` funciona como
                             * quasi-quote
                             * -- el argumento se escribe como CODIGO legible
                             * (el IDE lo resalta) y los `${expr}` se evaluan y
                             * splicean.  Escaneamos el texto crudo: cada
                             * `${...}` (con tracking de profundidad de llaves)
                             * se lex+parsea como una expresion y va a @c
                             * interp_exprs; el texto entre huecos va a @c
                             * interp_parts (layout N exprs -> N+1 parts).  Sin
                             * huecos, es un StringLit simple. */
                            std::string cur_part;
                            bool has_interp = false;
                            size_t sp = 0;
                            while (sp < captured.size()) {
                                /* Escape `\${...}`: hueco de interpolacion
                                 * RUNTIME que ATRAVIESA hasta el codigo
                                 * generado (no se evalua en comptime). Emitimos
                                 * `${` literal y seguimos -- el `${...}` queda
                                 * en el texto de salida para que la
                                 * interpolacion del lambda generado lo resuelva
                                 * en runtime.  Asi `source(
                                 * print("\${tape[p]:char}"); )` produce
                                 * `print("${tape[p]:char}")` en el codigo. */
                                if (sp + 1 < captured.size() &&
                                    captured[sp] == '\\' &&
                                    captured[sp + 1] == '$') {
                                    cur_part.push_back('$');
                                    sp += 2; /* saltar `\$`; el `{` queda
                                                literal */
                                    continue;
                                }
                                if (sp + 1 < captured.size() &&
                                    captured[sp] == '$' &&
                                    captured[sp + 1] == '{') {
                                    has_interp = true;
                                    slit->interp_parts.push_back(cur_part);
                                    cur_part.clear();
                                    sp += 2; /* saltar `${` */
                                    const size_t estart = sp;
                                    int bdepth = 1;
                                    while (sp < captured.size() && bdepth > 0) {
                                        if (captured[sp] == '{')
                                            ++bdepth;
                                        else if (captured[sp] == '}') {
                                            --bdepth;
                                            if (bdepth == 0) break;
                                        }
                                        ++sp;
                                    }
                                    std::string expr_txt =
                                        captured.substr(estart, sp - estart);
                                    if (sp < captured.size())
                                        ++sp; /* saltar `}` de cierre */
                                    /* lex+parse el texto del hueco como expr.
                                     */
                                    Lexer hole_lex(expr_txt, "<source-interp>",
                                                   diags_);
                                    Parser hole_par(hole_lex, diags_);
                                    std::unique_ptr<ast::Expr> he =
                                        hole_par.parse_one_expr();
                                    slit->interp_exprs.push_back(std::move(he));
                                    slit->interp_formats.emplace_back();
                                } else {
                                    cur_part.push_back(captured[sp]);
                                    ++sp;
                                }
                            }
                            if (has_interp) {
                                slit->interp_parts.push_back(cur_part);
                            } else {
                                /* Sin huecos: el texto va en @c value.  Usamos
                                 * @c cur_part (procesado -- con los escapes
                                 * `\$` ya resueltos a `$`), NO @c captured
                                 * (crudo), para que `\${...}` se emita como
                                 * `${...}`. */
                                slit->value = std::move(cur_part);
                            }
                            call->args.push_back(std::move(slit));
                        }
                    } else {
                        auto arg = parse_expr();
                        if (arg) call->args.push_back(std::move(arg));
                    }
                    ++arg_idx;
                    if (!match(TokenKind::COMMA)) break;
                }
            }
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' al cerrar la llamada");
            expr = std::move(call);
            break;
        }
        case TokenKind::LBRACE: {
            /* `no_braces_call_`: el scrutinee de un `match` va sin parentesis y
             * lleva el `{` del cuerpo pegado -> ahi este postfijo no aplica. */
            if (no_braces_call_) return expr;
            /* Sobrecarga de `{}`: postfijo `a{3,4,5}` -> CallExpr con
             * `is_braces_call`, que el checker resuelve a `a.__braces__(...)`.
             * Operador DISTINTO de `()`: un tipo puede definir uno, el otro o
             * los dos.  No colisiona con nada: `T a = {2,3,3}` es un
             * InitListExpr (el `{` va tras `=`, lo ve parse_primary), el
             * compound literal lleva parentesis (`(T){...}`), `T{...}` desnudo
             * no es sintaxis valida, y toda condicion del lenguaje va
             * parentizada -- un `{` pegado a una expresion no puede ser un
             * bloque.  Si el tipo no declara `__braces__`, el checker lo
             * rechaza: la sintaxis solo existe si el tipo la define. */
            const SourceLoc loc = current_.loc;
            (void)consume(); // '{'
            auto call = std::make_unique<ast::CallExpr>();
            call->loc = loc;
            call->callee = std::move(expr);
            call->is_braces_call = true;
            if (current_.kind != TokenKind::RBRACE) {
                while (true) {
                    auto arg = parse_expr();
                    if (arg) call->args.push_back(std::move(arg));
                    if (!match(TokenKind::COMMA)) break;
                }
            }
            (void)expect(TokenKind::RBRACE,
                         "se esperaba '}' al cerrar los argumentos de '{}'");
            expr = std::move(call);
            break;
        }
        case TokenKind::DOT: {
            const SourceLoc loc = current_.loc;
            (void)consume(); // '.'
            // Aceptar tambien KW_GET / KW_SET como nombres de
            // campo o metodo: el usuario puede haber definido
            // un metodo llamado 'get' o 'set' (no son property
            // accessors aqui, son nombres normales).  Sin esto
            // `obj.get(...)` fallaba al ver KW_GET tras DOT.
            if (!is_name_token(current_.kind)) {
                error_expected_name("nombre de campo o metodo tras '.'",
                                    "se esperaba un nombre de campo tras '.'");
                return expr;
            }
            auto fa = std::make_unique<ast::FieldAccessExpr>();
            fa->loc = loc;
            const SourceLoc ini_fa = expr ? expr->loc : loc;
            fa->base = std::move(expr);
            const Token tk_campo = consume();
            fa->field_name = tk_campo.lexeme;
            /* El tramo de `a.b` es `a.b` entero, no el punto.  Guardar solo
             * el operador dejaba la expresion sin donde empieza ni cuanto
             * ocupa, y al recortar el fuente para nombrarla salia ".". */
            extender_tramo(fa->loc, ini_fa, tk_campo);
            expr = std::move(fa);
            break;
        }
        case TokenKind::ARROW: {
            // `a->b` es azucar estilo C de `(*a).b`: deref del puntero +
            // acceso al miembro.  Para `a->m(args)`, el LPAREN de la
            // siguiente iteracion construye el CallExpr sobre el
            // FieldAccessExpr (igual que `(*a).m(args)`).  El type checker
            // y el lowering reusan el path de `(*a).b` sin cambios.
            const SourceLoc loc = current_.loc;
            (void)consume(); // '->'
            if (!is_name_token(current_.kind)) {
                error_expected_name("nombre de campo o metodo tras '->'",
                                    "se esperaba un nombre de campo tras '->'");
                return expr;
            }
            auto deref = std::make_unique<ast::UnaryExpr>();
            deref->loc = loc;
            deref->op = ast::UnOp::Deref;
            const SourceLoc ini_fa = expr ? expr->loc : loc;
            deref->operand = std::move(expr);
            auto fa = std::make_unique<ast::FieldAccessExpr>();
            fa->loc = loc;
            fa->base = std::move(deref);
            const Token tk_campo = consume();
            fa->field_name = tk_campo.lexeme;
            // Igual que `a.b`: el tramo es `a->b` entero (ver arriba).
            extender_tramo(fa->loc, ini_fa, tk_campo);
            expr = std::move(fa);
            break;
        }
        case TokenKind::LBRACKET: {
            // Subscript: base[index].  El type checker restringe la
            // base a tipo puntero o array (operacion de indexacion).
            const SourceLoc loc = current_.loc;
            (void)consume(); // '['
            auto idx = std::make_unique<ast::IndexExpr>();
            idx->loc = loc;
            idx->base = std::move(expr);
            idx->index = parse_expr();
            // String Inc 3: slice `base[a..b]` o `base[a..=b]`.  Cuando
            // tras el limite inferior aparece `..` / `..=`, parseamos el
            // limite superior y marcamos el IndexExpr como rango.  El
            // type checker valida que la base sea `string` (native_poo_).
            if (current_.kind == TokenKind::DOTDOT ||
                current_.kind == TokenKind::DOTDOTEQ) {
                idx->is_range = true;
                idx->range_inclusive = (current_.kind == TokenKind::DOTDOTEQ);
                (void)consume(); // '..' o '..='
                idx->range_hi = parse_expr();
            }
            (void)expect(TokenKind::RBRACKET,
                         "se esperaba ']' al cerrar el subindice");
            expr = std::move(idx);
            break;
        }
        default: return expr;
        }
    }
}

std::unique_ptr<ast::Expr> Parser::parse_primary() {
    const SourceLoc loc = current_.loc;

    // InitListExpr: `{ e0, e1, ... }` o
    // `{ .field = e0, ... }`.  Solo se acepta como expr en contexto
    // de inicializador (var-decl init y campos anidados).  El parser
    // no distingue contexto aqui -- el type checker valida que solo
    // aparezca en init list correctos.
    if (current_.kind == TokenKind::LBRACE) {
        auto e = std::make_unique<ast::InitListExpr>();
        e->loc = loc;
        (void)consume(); // '{'
        // Lista vacia: { } valida.
        while (current_.kind != TokenKind::RBRACE &&
               current_.kind != TokenKind::END_OF_FILE) {
            std::string fname;
            bool desig = false;
            if (current_.kind == TokenKind::DOT) {
                desig = true;
                e->is_designated = true;
                (void)consume(); // '.'
                if (current_.kind != TokenKind::IDENTIFIER) {
                    error_here("se esperaba el nombre del campo tras '.'");
                    synchronize();
                    continue;
                }
                fname = consume().lexeme;
                if (!match(TokenKind::ASSIGN)) {
                    error_here("se esperaba '=' tras '.field'");
                    synchronize();
                    continue;
                }
            }
            auto val = parse_expr();
            if (!val) {
                synchronize();
                continue;
            }
            if (desig)
                e->field_names.push_back(std::move(fname));
            else if (e->is_designated) {
                error_here("no se puede mezclar '.field=' y posicional");
            }
            e->elements.push_back(std::move(val));
            if (!match(TokenKind::COMMA)) break;
        }
        (void)expect(TokenKind::RBRACE, "se esperaba '}' al cerrar init list");
        // Si is_designated, field_names debe tener N entradas.
        if (e->is_designated && e->field_names.size() != e->elements.size()) {
            diags_.error(loc, "init list designado debe usar '.field=' en "
                              "TODOS los elementos");
        }
        return e;
    }

    switch (current_.kind) {
    case TokenKind::INT_LIT: {
        auto e = std::make_unique<ast::IntLitExpr>();
        e->loc = loc;
        e->value = current_.int_val;
        e->suffix = suffix_primitive(current_);
        (void)consume();
        return e;
    }
    case TokenKind::FLOAT_LIT: {
        auto e = std::make_unique<ast::FloatLitExpr>();
        e->loc = loc;
        e->value = current_.flt_val;
        e->suffix = suffix_primitive(current_);
        (void)consume();
        return e;
    }
    case TokenKind::TRUE_KW:
    case TokenKind::FALSE_KW: {
        auto e = std::make_unique<ast::BoolLitExpr>();
        e->loc = loc;
        e->value = current_.kind == TokenKind::TRUE_KW;
        (void)consume();
        return e;
    }
    case TokenKind::NULL_KW: {
        auto e = std::make_unique<ast::NullLitExpr>();
        e->loc = loc;
        (void)consume();
        return e;
    }
    case TokenKind::CHAR_LIT: {
        auto e = std::make_unique<ast::CharLitExpr>();
        e->loc = loc;
        e->codepoint = (uint32_t)current_.int_val;
        (void)consume();
        return e;
    }
    case TokenKind::STRING_LIT:
    case TokenKind::RAW_STRING_LIT: {
        auto e = std::make_unique<ast::StringLitExpr>();
        e->loc = loc;
        e->is_raw = (current_.kind == TokenKind::RAW_STRING_LIT);
        e->value = consume().str_val;
        /* Literales ADYACENTES se funden en uno, como en C:
         *
         *     string m = "primera parte "
         *                "segunda parte";     // -> UN literal
         *
         * Es lo normal para partir un mensaje largo sin pasarse de ancho.  Y no
         * es solo comodidad: con `+` hay que decidir, y sobre un `string` de
         * runtime `"a" + "b"` emite un STRCAT para juntar dos cosas que ya se
         * conocian al compilar.  Aqui no queda nada que ejecutar: es un
         * literal.
         *
         * Un literal interpolado (`${...}`) NO entra: lo produce el lexer como
         * una secuencia de tokens, no como un STRING_LIT suelto.  Pegar uno
         * simple a uno interpolado no se funde, y el `+` lo cubre. */
        while (current_.kind == TokenKind::STRING_LIT ||
               current_.kind == TokenKind::RAW_STRING_LIT) {
            /* Mezclar crudo y normal cambiaria el significado de los escapes de
             * una de las dos mitades -> se pide que sean del mismo tipo. */
            const bool nxt_raw = (current_.kind == TokenKind::RAW_STRING_LIT);
            if (nxt_raw != e->is_raw) {
                error_here("no se pueden pegar un literal normal y uno crudo "
                           "(r\"...\"): sus escapes no significan lo mismo; "
                           "usa '+' si es lo que quieres");
                break;
            }
            e->value += consume().str_val;
        }
        return e;
    }
    case TokenKind::ISTR_BEGIN: {
        // Interpolacion ${expr}: consumir secuencia de tokens
        // ISTR_BEGIN, [ISTR_TEXT, [ISTR_EXPR_BEGIN ... ISTR_EXPR_END,
        // [ISTR_TEXT,]]*]?  ISTR_END.  Construir un StringLitExpr
        // con interp_parts + interp_exprs.  Garantia del lexer:
        // las parts y exprs estan intercaladas correctamente y
        // siempre cierra con ISTR_END.
        auto e = std::make_unique<ast::StringLitExpr>();
        e->loc = loc;
        e->is_raw = false;
        (void)consume(); // ISTR_BEGIN

        // Acumulador del proximo "part" literal.  Si no hay texto
        // antes de la primera expresion, se anade "" para mantener
        // el invariante parts.size() == exprs.size() + 1.
        std::string pending_text;
        bool has_pending_text = false;

        while (current_.kind != TokenKind::ISTR_END &&
               current_.kind != TokenKind::END_OF_FILE) {
            if (current_.kind == TokenKind::ISTR_TEXT) {
                pending_text += current_.str_val;
                has_pending_text = true;
                (void)consume();
                continue;
            }
            if (current_.kind == TokenKind::ISTR_EXPR_BEGIN) {
                // Consolidar el texto pendiente como part anterior.
                e->interp_parts.push_back(std::move(pending_text));
                pending_text.clear();
                has_pending_text = false;
                (void)consume(); // ISTR_EXPR_BEGIN

                // Parsear UNA expresion (asignaciones permitidas).
                auto expr = parse_expr();
                if (!expr) {
                    diags_.error(current_.loc,
                                 "expresion vacia dentro de ${...}");
                    // Insertar placeholder para mantener layout valido.
                    auto placeholder = std::make_unique<ast::IntLitExpr>();
                    placeholder->loc = current_.loc;
                    placeholder->value = 0;
                    e->interp_exprs.push_back(std::move(placeholder));
                } else {
                    e->interp_exprs.push_back(std::move(expr));
                }

                // Formato opcional `${expr:fmt}` (lexer emite
                // ISTR_EXPR_FMT con la cadena de formato en
                // str_val).  Capturar y guardar; si no existe,
                // insertar string vacio para mantener
                // interp_formats[i] paralelo a interp_exprs[i].
                std::string fmt;
                if (current_.kind == TokenKind::ISTR_EXPR_FMT) {
                    fmt = std::move(current_.str_val);
                    (void)consume();
                }
                e->interp_formats.push_back(std::move(fmt));

                // Consumir ISTR_EXPR_END (cierre del lexer).
                if (current_.kind == TokenKind::ISTR_EXPR_END) {
                    (void)consume();
                } else {
                    diags_.error(current_.loc,
                                 "esperado '}' al cerrar interpolacion ${...}");
                }
                continue;
            }
            // Token inesperado dentro del string interpolado: error.
            diags_.error(current_.loc,
                         "token inesperado dentro de string interpolado");
            break;
        }
        // Cerrar: ultimo part = pending_text (puede estar vacio).
        e->interp_parts.push_back(std::move(pending_text));

        if (current_.kind == TokenKind::ISTR_END) {
            (void)consume();
        }
        return e;
    }
    // `get`/`set` son keywords CONTEXTUALES (solo property dentro de una
    // clase, y esa forma se detecta en el bucle de miembros, nunca aqui).
    // En posicion de expresion son nombres corrientes, de modo que una
    // funcion libre llamada `get` se puede INVOCAR (`get(x)`) igual que
    // se puede declarar.
    case TokenKind::KW_GET:
    case TokenKind::KW_SET:
    case TokenKind::IDENTIFIER: {
        auto e = std::make_unique<ast::IdentExpr>();
        e->loc = loc;
        e->name = consume().lexeme;
        return e;
    }
    case TokenKind::KW_THIS: {
        // Receptor implicito de un metodo de instancia.  El type
        // checker valida que aparece dentro del cuerpo de un
        // metodo no estatico y resuelve su tipo a la clase
        // contenedora.
        auto e = std::make_unique<ast::ThisExpr>();
        e->loc = loc;
        (void)consume();
        return e;
    }
    case TokenKind::KW_SUPER: {
        // BugFix R1: `super(args)` para delegacion al ctor de la
        // superclase, o `super.method(args)` para llamar al metodo
        // del super sin dispatch virtual.
        (void)consume(); // 'super'
        if (current_.kind == TokenKind::LPAREN) {
            // super(args) -- delegacion ctor
            auto e = std::make_unique<ast::SuperCallExpr>();
            e->loc = loc;
            (void)consume(); // '('
            while (current_.kind != TokenKind::RPAREN &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto arg = parse_expr();
                if (arg) e->args.push_back(std::move(arg));
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' tras args de super(...)");
            return e;
        }
        if (current_.kind == TokenKind::DOT) {
            // super.method(args)
            (void)consume(); // '.'
            if (current_.kind != TokenKind::IDENTIFIER) {
                error_here("se esperaba nombre de metodo tras 'super.'");
                return nullptr;
            }
            auto e = std::make_unique<ast::SuperMethodCallExpr>();
            e->loc = loc;
            e->method_name = consume().lexeme;
            if (current_.kind != TokenKind::LPAREN) {
                error_here("se esperaba '(' tras 'super.<metodo>'");
                return nullptr;
            }
            (void)consume(); // '('
            while (current_.kind != TokenKind::RPAREN &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto arg = parse_expr();
                if (arg) e->args.push_back(std::move(arg));
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect(TokenKind::RPAREN,
                         "se esperaba ')' tras args de super.method(...)");
            return e;
        }
        error_here("'super' debe ir seguido de '(' (delegacion ctor) o "
                   "'.metodo(' (llamada no-virtual)");
        return nullptr;
    }
    case TokenKind::KW_NEW: {
        // Creacion de instancia: 'new' <ClassName> '(' args... ')'.
        // bug4: tambien 'new T[N]' donde T puede ser primitivo
        // (i32/i64/string/bool/etc) o nombre de clase/enum/struct.
        (void)consume();
        auto e = std::make_unique<ast::NewExpr>();
        e->loc = loc;
        // Aceptar IDENTIFIER (clases, enums, structs, typedefs) o
        // primitive_kind_from_token (i32, i64, string, bool, f32...).
        if (current_.kind == TokenKind::IDENTIFIER) {
            e->class_name = consume().lexeme;
            //  M.7.c: namespace qualified `new ui.Button(...)`.
            // Concatenamos con `.` igual que en parse_type_node;
            // el TypeChecker traduce a mangled label.
            while (current_.kind == TokenKind::DOT &&
                   lex_.peek_at(0).kind == TokenKind::IDENTIFIER) {
                (void)consume(); // '.'
                e->class_name += ".";
                e->class_name += consume().lexeme;
            }
        } else if (primitive_kind_from_token(current_.kind) !=
                   PrimitiveKind::COUNT) {
            // Captura lexeme del primitivo para que el lowering
            // pueda mapearlo a IrType correcto.
            e->class_name = consume().lexeme;
        } else {
            error_here("se esperaba un nombre de tipo tras 'new'");
            return nullptr;
        }
        // Argumentos de tipo opcionales `<T1, T2, ...>` para
        // instanciaciones genericas: @c new Box<i32>(42).
        if (current_.kind == TokenKind::LT) {
            (void)consume(); // '<'
            while (current_.kind != TokenKind::GT &&
                   current_.kind != TokenKind::END_OF_FILE) {
                auto ta = parse_type_node();
                if (!ta) break;
                e->type_args.push_back(std::move(ta));
                if (!match(TokenKind::COMMA)) break;
            }
            (void)expect_close_angle(
                "se esperaba '>' al cerrar argumentos de tipo en new");
        }
        // bug4: array allocation `new T[N]`.  En lugar de `(args)`,
        // si vemos `[<expr>]` parseamos como array_size.  Resultado
        // semantico: aloca N * sizeof(T) bytes en host heap y
        // devuelve un host_ptr al primer elemento (decay-to-T*).
        if (current_.kind == TokenKind::LBRACKET) {
            (void)consume(); // '['
            e->array_size = parse_expr();
            if (!e->array_size) {
                error_here(
                    "se esperaba expresion del tamano del array en 'new T[N]'");
            }
            (void)expect(
                TokenKind::RBRACKET,
                "se esperaba ']' al cerrar el tamano del array en 'new T[N]'");
            return e;
        }
        (void)expect(TokenKind::LPAREN,
                     "se esperaba '(' tras el nombre de la clase");
        while (current_.kind != TokenKind::RPAREN &&
               current_.kind != TokenKind::END_OF_FILE) {
            auto arg = parse_expr();
            if (arg) e->args.push_back(std::move(arg));
            if (!match(TokenKind::COMMA)) break;
        }
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' al cerrar argumentos de 'new'");
        return e;
    }
    case TokenKind::KW_SPAWN: {
        // spawn { body } -- arranca proceso hijo, devuelve PID.
        // El body es un bloque sin parametros; se compila como
        // funcion sintetica __spawn_<N> en el lowering.  No hay
        // captura lexica en MVP (closures con captura llegan en B).
        //
        // spawn admite hint de placement opcional:
        //   spawn { body }            -- Auto (round-robin entre schedulers)
        //   spawn here { body }       -- Here (mismo scheduler que el padre)
        //   spawn on(expr) { body }   -- Pinned (scheduler = expr %
        //   num_schedulers)
        // `here` y `on` se reconocen contextualmente como identificadores
        // tras KW_SPAWN para evitar reservar mas keywords globales.
        (void)consume();
        auto e = std::make_unique<ast::SpawnExpr>();
        e->loc = loc;
        if (current_.kind == TokenKind::IDENTIFIER) {
            if (current_.lexeme == "here") {
                (void)consume();
                e->policy = ast::SpawnExpr::Policy::Here;
            } else if (current_.lexeme == "on") {
                (void)consume();
                (void)expect(TokenKind::LPAREN,
                             "se esperaba '(' tras 'on' en spawn on(expr)");
                e->sched_idx = parse_expr();
                if (!e->sched_idx) return nullptr;
                (void)expect(TokenKind::RPAREN,
                             "se esperaba ')' al cerrar 'on(expr)'");
                e->policy = ast::SpawnExpr::Policy::Pinned;
            }
        }
        if (current_.kind != TokenKind::LBRACE) {
            error_here("se esperaba '{' tras 'spawn' (cuerpo del proceso)");
            return nullptr;
        }
        e->body = parse_block();
        if (!e->body) return nullptr;
        return e;
    }
    case TokenKind::KW_RSPAWN: {
        // rspawn(node_idx) { body } -- spawn distribuido.
        // Devuelve i64 (Future handle).  El body se ejecuta en el
        // nodo remoto y su valor de retorno (via `return X`) se
        // captura en R0 + hlt; el runtime remoto envia X de vuelta
        // como fulfill del Future.  El caller hace `await fut` para
        // obtener X.
        (void)consume();
        auto e = std::make_unique<ast::RSpawnExpr>();
        e->loc = loc;
        (void)expect(
            TokenKind::LPAREN,
            "se esperaba '(' tras 'rspawn' para indicar el nodo remoto");
        e->node_idx = parse_expr();
        if (!e->node_idx) return nullptr;
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' al cerrar 'rspawn(node_idx)'");
        if (current_.kind != TokenKind::LBRACE) {
            error_here("se esperaba '{' tras 'rspawn(node)' (cuerpo del "
                       "proceso remoto)");
            return nullptr;
        }
        e->body = parse_block();
        if (!e->body) return nullptr;
        return e;
    }
    case TokenKind::KW_MATCH:
        // match expr { case Variant(b) => body; ... }
        return parse_match_expr();
    case TokenKind::LPAREN: {
        // distinguir entre expresion parentizada y
        // lambda `(args) => expr/{...}`.  Lookahead profundo: contar
        // los parentesis hasta cerrar el grupo y mirar si lo
        // siguiente es FAT_ARROW.  El lexer expone @c peek_at sin
        // consumir, asi que no necesitamos backtracking del parser.
        if (is_lambda_start()) {
            return parse_lambda_expr();
        }
        (void)consume();
        // Dentro de parentesis un `{` ya no puede abrir un bloque del lenguaje,
        // asi que el postfijo `{}` vuelve a estar disponible aunque el grupo
        // este dentro del scrutinee de un match: `match (a{1,2}) { ... }`.
        std::unique_ptr<ast::Expr> inner;
        {
            const bool prev_nb = no_braces_call_;
            no_braces_call_ = false;
            inner = parse_expr();
            no_braces_call_ = prev_nb;
        }
        (void)expect(TokenKind::RPAREN,
                     "se esperaba ')' al cerrar la expresion entre parentesis");
        return inner;
    }
    default:
        error_here("se esperaba una expresion primaria");
        (void)consume();
        return nullptr;
    }
}

// -----------------------------------------------------------------
// closures: parseo de lambdas inline y disambiguacion vs
// expresion parentizada.
// -----------------------------------------------------------------

bool Parser::is_lambda_start() const noexcept {
    // Precondicion: current_ es LPAREN.  Recorremos los tokens
    // siguientes via peek_at hasta cerrar el grupo de parentesis.
    // Si el primer token tras el RPAREN matching es FAT_ARROW
    // (=>), estamos viendo una lambda; si no, es una expresion.
    //
    // Limite duro: 256 tokens de lookahead.  Los argumentos de
    // lambdas reales nunca llegan a tanto, y poner una cota
    // garantiza tiempo lineal acotado en el peor caso (codigo
    // sintacticamente invalido sin RPAREN cerrando).
    Lexer &mut_lex = const_cast<Lexer &>(lex_);
    size_t off = 0; // distancia desde current_+1 (peek_at(0))
    int depth = 1;  // ya estamos dentro del primer LPAREN
    const size_t MAX_LOOKAHEAD = 256;
    while (depth > 0 && off < MAX_LOOKAHEAD) {
        const TokenKind k = mut_lex.peek_at(off).kind;
        if (k == TokenKind::END_OF_FILE) return false;
        if (k == TokenKind::LPAREN)
            ++depth;
        else if (k == TokenKind::RPAREN)
            --depth;
        ++off;
    }
    if (depth != 0) return false;
    // off apunta ahora al primer token TRAS el RPAREN matching.
    // Solo si es FAT_ARROW se trata de una lambda.  Cualquier otra
    // cosa (operador binario, llamada, indexacion, etc.) significa
    // que era una expresion parentizada.
    return mut_lex.peek_at(off).kind == TokenKind::FAT_ARROW;
}

std::unique_ptr<ast::Expr> Parser::parse_lambda_expr() {
    const SourceLoc loc = current_.loc;
    // Consume el LPAREN inicial.  is_lambda_start ya garantizo que
    // existe un FAT_ARROW tras el RPAREN matching.
    (void)expect(TokenKind::LPAREN, "se esperaba '(' al iniciar lambda");
    auto lam = std::make_unique<ast::LambdaExpr>();
    lam->loc = loc;

    // Lista de parametros.  Aceptamos dos formas:
    //   (T1 name1, T2 name2, ...)   ->  con tipos explicitos
    //   (name1, name2, ...)         ->  tipos inferidos del contexto
    // No mezclamos las dos formas en una sola lambda (inferiremos o
    // el usuario tipa todos).  El distinguir se hace en cada elemento:
    // si el primer token del parametro es un tipo (starts_type()),
    // parseamos `tipo nombre`; en caso contrario solo `nombre`.
    while (current_.kind != TokenKind::RPAREN &&
           current_.kind != TokenKind::END_OF_FILE) {
        /* La forma SIN tipo es un nombre a secas, y se reconoce por lo que
         * viene detras: una coma o el cierre.  Cualquier otra cosa lleva tipo,
         * y entonces lo que hay entre los parentesis es la misma gramatica que
         * en cualquier otra declaracion -- se lee con el mismo lector, para que
         * una lambda no acabe siendo el sitio donde no valen las formas que
         * valen en todos los demas. */
        const bool sin_tipo = (current_.kind == TokenKind::IDENTIFIER &&
                               (lex_.peek_at(0).kind == TokenKind::COMMA ||
                                lex_.peek_at(0).kind == TokenKind::RPAREN));
        if (sin_tipo) {
            auto p = std::make_unique<ast::ParamDecl>();
            p->loc = current_.loc;
            // Sin tipo: el comprobador lo deduce del contexto (de la `fn(T)`
            // a la que se asigna).
            p->name = consume().lexeme;
            p->type = nullptr;
            lam->params.push_back(std::move(p));
        } else {
            auto p = parse_param();
            if (!p || p->name.empty()) {
                error_here("se esperaba un parametro en la lambda");
                return nullptr;
            }
            lam->params.push_back(std::move(p));
        }
        if (!match(TokenKind::COMMA)) break;
    }
    (void)expect(TokenKind::RPAREN,
                 "se esperaba ')' al cerrar parametros de lambda");
    (void)expect(TokenKind::FAT_ARROW,
                 "se esperaba '=>' tras los parametros de lambda");

    // Cuerpo: dos formas.
    //   - Block:        () => { stmts; return X; }
    //   - Expression:   () => expr     -> reescribir a { return expr; }
    if (current_.kind == TokenKind::LBRACE) {
        lam->body = parse_block();
        if (!lam->body) return nullptr;
    } else {
        // Expression-bodied: envolvemos en un ReturnStmt + BlockStmt.
        // La SourceLoc del block hereda la posicion de la lambda para
        // mantener buenos diagnosticos.
        auto e = parse_expr();
        if (!e) return nullptr;
        auto ret = std::make_unique<ast::ReturnStmt>();
        ret->loc = e->loc;
        ret->value = std::move(e);
        auto blk = std::make_unique<ast::BlockStmt>();
        blk->loc = loc;
        blk->body.push_back(std::move(ret));
        lam->body = std::move(blk);
    }
    return lam;
}
} // namespace vx
