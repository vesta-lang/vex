/**
 * @file literals.cpp
 * @brief Forma canonica de un literal numerico (`R106`-`R109`).
 *
 * Es la unica parte del formateador que cambia el TEXTO de un token en vez de
 * moverlo.  Se permite porque ninguna de estas reescrituras cambia el valor:
 * rellenar con ceros por la izquierda, pasar los digitos a mayusculas y
 * agrupar con `_` dan exactamente el mismo numero.  La salvaguarda de
 * `fmt.cpp` lo comprueba de todas formas, comparando el valor ya leido por el
 * lexer y no el lexema.
 *
 * Por que agrupar, que es lo que las cuatro reglas tienen en comun: un numero
 * largo no se lee de un vistazo, se CUENTA.  `10000000` obliga a contar ceros
 * para saber si son diez millones o cien; `10_000_000` se lee entero.  Lo
 * mismo con los bits: `0xF` y `0x0F` valen igual, pero solo el segundo deja
 * ver que ocupa un byte.  Cada base se agrupa por lo que significa en ella:
 *
 *   - hexadecimal: de dos en dos, que es un byte, hasta la anchura de un tipo
 *     del lenguaje (2, 4, 8 y 16 digitos son u8, u16, u32 y u64).
 *   - binario: de cuatro en cuatro, que es un digito hexadecimal.
 *   - octal: de tres en tres, que es un byte redondeado hacia arriba, como los
 *     permisos de un fichero (`0o755`).
 *   - decimal: de tres en tres con `_`, la separacion de millares de siempre.
 */

#include "vx/fmt/fmt_internal.h"

#include <cctype>

namespace vx {
namespace fmt {
namespace {

/// @brief A partir de cuantos digitos se agrupa un decimal con `_` (`R109`).
///
/// Cuatro digitos se leen de un vistazo (`1000`, `2026`), y meterles un `_`
/// solo anade ruido; cinco ya no (`10000` puede ser diez mil o cien mil).
constexpr size_t kGroupFrom = 5;

/// @brief Digitos hexadecimales en mayuscula (`R106`).
char upper_digit(char c) {
    return (c >= 'a' && c <= 'f') ? (char)(c - 'a' + 'A') : c;
}

/**
 * @brief Anchura a la que se rellena un literal, o 0 para dejarlo como esta.
 *
 * @param digits Cuantos digitos tiene ya.
 * @param step Tamano del grupo en digitos de esa base.
 * @param max_width Anchura mas alla de la cual no se toca.
 * @param powers Cierto si solo valen las anchuras de un tipo (2, 4, 8, 16).
 */
size_t target_width(size_t digits, size_t step, size_t max_width, bool powers) {
    if (digits == 0 || digits > max_width) return 0;
    if (powers) {
        // Las anchuras que nombran un tipo: 2, 4, 8 y 16 digitos hex son
        // u8, u16, u32 y u64.  Una de 6 no es ningun tipo, y sube a 8.
        for (size_t w = step; w <= max_width; w *= 2)
            if (digits <= w) return w;
        return 0;
    }
    return ((digits + step - 1) / step) * step;
}

/**
 * @brief Agrupa los millares de una tira de digitos con `_`.
 *
 * Solo se aplica a la parte ENTERA.  Detras del punto no hay millares que
 * contar, y agrupar ahi deja restos como `0.123_456_7`, que se lee peor que
 * el numero sin tocar.
 *
 * @param digits Digitos sin separadores.
 */
std::string group_digits(std::string_view digits) {
    if (digits.size() < kGroupFrom) return std::string(digits);
    std::string out;
    out.reserve(digits.size() + digits.size() / 3);
    // El grupo corto va delante: `1_000_000`, no `100_000_0`.
    const size_t head = ((digits.size() - 1) % 3) + 1;
    for (size_t i = 0; i < digits.size(); ++i) {
        if (i >= head && (i - head) % 3 == 0) out += '_';
        out += digits[i];
    }
    return out;
}

/// @brief Copia una tira quitando los `_`, para poder reagruparla.
std::string strip_separators(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const char c : s)
        if (c != '_') out += c;
    return out;
}

/**
 * @brief Forma canonica de un literal con base explicita (`0x`, `0b`, `0o`).
 * @param text Lexema completo.
 * @return El texto canonico, o vacio si no hay nada que cambiar.
 */
std::string canonical_based(std::string_view text) {
    size_t step = 0, max_width = 0;
    bool powers = false, hex = false, octal = false;
    switch (text[1]) {
    case 'x':
    case 'X':
        step = 2; // un byte
        max_width = 16;
        powers = true;
        hex = true;
        break;
    case 'b':
    case 'B':
        step = 4; // un digito hexadecimal
        max_width = 64;
        break;
    case 'o':
    case 'O':
        step = 3; // un byte redondeado hacia arriba (`0o377` = 255)
        max_width = 24;
        octal = true;
        break;
    default: return {};
    }

    // Separar los digitos del sufijo de tipo, que empieza por letra.  Se
    // anota si aparece un `_` ENTRE digitos, que es distinto del que separa
    // el sufijo (`0xFF_u32`): aquel es una agrupacion que eligio el autor.
    size_t end = 2;
    bool grouped = false;
    while (end < text.size()) {
        const char c = text[end];
        const bool is_digit = hex     ? (bool)std::isxdigit((unsigned char)c)
                              : octal ? (c >= '0' && c <= '7')
                                      : (c == '0' || c == '1');
        if (!is_digit) {
            // Un `_` solo sigue siendo parte del numero si detras hay digito.
            if (c == '_' && end + 1 < text.size()) {
                const char n = text[end + 1];
                const bool next_digit =
                    hex     ? (bool)std::isxdigit((unsigned char)n)
                    : octal ? (n >= '0' && n <= '7')
                            : (n == '0' || n == '1');
                if (next_digit) {
                    grouped = true;
                    ++end;
                    continue;
                }
            }
            break;
        }
        ++end;
    }
    // En estas bases un `_` entre digitos marca campos de un formato, no
    // millares (`0xDEAD_BEEF`), y reagrupar seria discutir con el autor.
    if (grouped) return {};

    const std::string_view digits = text.substr(2, end - 2);
    std::string_view suffix = text.substr(end);
    if (!suffix.empty() && suffix.front() == '_') suffix.remove_prefix(1);
    if (digits.empty()) return {}; // literal roto: no es cosa del formateador

    const size_t width = target_width(digits.size(), step, max_width, powers);
    if (width == 0) return {};

    std::string out;
    out.reserve(3 + width + suffix.size());
    out += '0';
    out += hex ? 'x' : (octal ? 'o' : 'b');
    out.append(width - digits.size(), '0');
    for (const char c : digits)
        out += hex ? upper_digit(c) : c;
    // `R108`: el sufijo se separa con `_`.  Pegado al numero se confunde con
    // el, y en hexadecimal hasta con un digito: `0xFFu32` frente a
    // `0xFF_u32`.
    if (!suffix.empty()) {
        out += '_';
        out += suffix;
    }
    return out;
}

/**
 * @brief Forma canonica de un decimal o un flotante (`R109`).
 *
 * Reagrupa de tres en tres con `_` la parte entera; la fraccionaria se deja
 * como esta.  A diferencia de las bases explicitas aqui SI se rehace la
 * agrupacion que hubiera, porque en decimal `_` solo puede significar
 * millares y una separacion distinta seria un error de tecleo.
 *
 * @param text Lexema completo.
 * @return El texto canonico, o vacio si no hay nada que cambiar.
 */
std::string canonical_decimal(std::string_view text) {
    // Trocear en parte entera, fraccionaria, exponente y sufijo.  El exponente
    // no se agrupa: son dos o tres digitos y `_` ahi solo estorba.
    size_t i = 0;
    while (i < text.size() &&
           (std::isdigit((unsigned char)text[i]) || text[i] == '_'))
        ++i;
    const std::string_view int_part = text.substr(0, i);
    if (int_part.empty()) return {};

    bool has_dot = false;
    std::string_view frac_part;
    if (i < text.size() && text[i] == '.') {
        has_dot = true;
        const size_t start = ++i;
        while (i < text.size() &&
               (std::isdigit((unsigned char)text[i]) || text[i] == '_'))
            ++i;
        frac_part = text.substr(start, i - start);
        // El `_` final no es de la fraccion: es el que separa el sufijo de
        // `R108`.  Sin quitarlo, `3.14_f64` acababa con dos.
        while (!frac_part.empty() && frac_part.back() == '_')
            frac_part.remove_suffix(1);
    }
    // Lo que queda puede ser exponente, sufijo o los dos (`1e9_i64`).  Se
    // separan porque el `_` de `R108` va delante del sufijo, no del exponente.
    std::string_view rest = text.substr(i);
    std::string_view exponent;
    if (!rest.empty() && (rest.front() == 'e' || rest.front() == 'E')) {
        size_t j = 1;
        if (j < rest.size() && (rest[j] == '+' || rest[j] == '-')) ++j;
        while (j < rest.size() && std::isdigit((unsigned char)rest[j]))
            ++j;
        exponent = rest.substr(0, j);
        rest = rest.substr(j);
    }
    if (!rest.empty() && rest.front() == '_') rest.remove_prefix(1);

    std::string out = group_digits(strip_separators(int_part));
    if (has_dot) {
        out += '.';
        out += frac_part; // la fraccion se queda tal cual
    }
    out += exponent;
    if (!rest.empty()) {
        out += '_'; // `R108`: el sufijo de tipo va separado
        out += rest;
    }
    return out;
}

/**
 * @brief El nombre de tipo vale como sufijo de literal?
 *
 * Solo los nombres CORTOS de Vesta -- `i8`..`i64`, `u8`..`u64`, `f32`, `f64`
 * --.  Los alias largos (`int32_t`, `double`) nombran el mismo tipo pero no
 * son sufijos validos, y ponerlos dejaria el fichero sin compilar.
 *
 * Se comprueba por la FORMA y no contra una lista: la letra y la anchura.  Una
 * lista escrita a mano se queda corta en cuanto el lenguaje gana un tipo, y se
 * queda corta en silencio.
 *
 * @param nombre Texto del token de tipo.
 * @param flotante [out] cierto si es un tipo de coma flotante.
 * @return Cierto si sirve de sufijo.
 */
/**
 * @brief Lleva ya el literal un sufijo de tipo?
 *
 * Un sufijo empieza por letra, y la unica letra que puede aparecer en un
 * numero sin serlo es la del prefijo de base (`0x`), la de un digito
 * hexadecimal o la `e` del exponente.  Se mira desde el final: si el ultimo
 * caracter es una letra y antes hay un `_`, es un sufijo.
 *
 * @param text Lexema completo.
 * @return Cierto si ya trae sufijo.
 */
bool has_suffix(std::string_view text) {
    for (size_t i = text.size(); i > 0; --i) {
        const char c = text[i - 1];
        if (c == '_') return i < text.size(); // `123_i64`
        if (!std::isalnum((unsigned char)c)) return false;
    }
    return false;
}

/**
 * @brief Lee el valor de un literal entero, sea cual sea su base.
 *
 * @param text Lexema sin sufijo, con o sin `_` de agrupacion.
 * @param valor [out] el numero.
 * @return Cierto si se pudo leer entero y sin desbordar 64 bits.
 */
bool int_value(std::string_view text, unsigned long long &valor) {
    int base = 10;
    size_t i = 0;
    if (text.size() > 2 && text[0] == '0') {
        const char b = text[1];
        if (b == 'x' || b == 'X') {
            base = 16;
            i = 2;
        } else if (b == 'b' || b == 'B') {
            base = 2;
            i = 2;
        } else if (b == 'o' || b == 'O') {
            base = 8;
            i = 2;
        }
    }
    valor = 0;
    bool alguno = false;
    for (; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '_') continue;
        int d;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
            return false;
        if (d >= base) return false;
        const unsigned long long antes = valor;
        valor = valor * (unsigned long long)base + (unsigned long long)d;
        if (valor < antes) return false; // desbordo los 64 bits
        alguno = true;
    }
    return alguno;
}

/**
 * @brief Cabe @p valor en un tipo entero de @p ancho bits?
 *
 * Sin esto, `u8 x = 300;` se convertia en `300_u8`, que no compila: el
 * formateador habria roto el fichero al ponerle un sufijo que el numero no
 * admite.  Un valor que no cabe es un error del programa, pero es del AUTOR
 * -- se dice al compilar --, y el formateador no tiene por que empeorarlo.
 *
 * @param valor Magnitud escrita.
 * @param ancho Bits del tipo.
 * @param con_signo Cierto si el tipo lleva signo.
 * @param negativo Cierto si delante del literal hay un `-`.
 * @return Cierto si cabe.
 */
bool fits(unsigned long long valor, unsigned ancho, bool con_signo,
          bool negativo) {
    if (ancho >= 64) return !negativo || valor <= (1ULL << 63);
    if (!con_signo) return !negativo && valor < (1ULL << ancho);
    const unsigned long long tope = 1ULL << (ancho - 1);
    // Un tipo con signo llega a -2^(n-1) por abajo y a 2^(n-1)-1 por arriba.
    return negativo ? valor <= tope : valor < tope;
}

bool suffix_name(std::string_view nombre, bool &flotante) {
    if (nombre.size() < 2 || nombre.size() > 3) return false;
    const char letra = nombre.front();
    if (letra != 'i' && letra != 'u' && letra != 'f') return false;
    const std::string_view ancho = nombre.substr(1);
    flotante = letra == 'f';
    if (flotante) return ancho == "32" || ancho == "64";
    return ancho == "8" || ancho == "16" || ancho == "32" || ancho == "64";
}

} // namespace

/**
 * @brief Devuelve la forma canonica de un literal, o vacio si ya la tiene.
 *
 * @param text Lexema tal como lo escribio el autor, sufijo incluido.
 * @return El texto canonico, o una cadena vacia si no hay nada que cambiar.
 */
std::string canonical_literal(std::string_view text) {
    if (text.empty()) return {};
    std::string out;
    /* Un literal que empieza por un prefijo de base ES de esa base, mida lo que
     * mida.  Pidiendo mas de dos caracteres, un `0x` pelado -- que es un
     * literal ROTO, sin digitos -- se colaba al camino decimal, que veia el
     * `0` y tomaba la `x` por un sufijo de tipo: lo reescribia como `0_x`, que
     * SI parsea y significa OTRA COSA.
     *
     * Se vio formateando el corpus: `367_literal_sin_digitos.vx` comprueba que
     * `0x` se rechaza, y tras formatearlo fallaba con otro error -- el test
     * habia dejado de comprobar lo que decia.
     *
     * El formateador no arregla ni cambia lo que no parsea.  Lo deja como esta
     * y que lo diga el compilador, que es quien tiene que decirlo. */
    if (text.size() >= 2 && text[0] == '0' &&
        (std::isalpha((unsigned char)text[1]) != 0) && text[1] != 'e' &&
        text[1] != 'E')
        out = canonical_based(text);
    else if (std::isdigit((unsigned char)text[0]))
        out = canonical_decimal(text);
    return out == text ? std::string{} : out;
}

/**
 * @brief Anade a cada literal el sufijo de tipo de su declaracion (`R108`).
 *
 * `R108` decia como se ESCRIBE un sufijo, pero no que hubiera que ponerlo, asi
 * que un `public const u32 PIPE_WAIT = 0x00000000;` se quedaba sin el: el
 * numero no dice de que tipo es y hay que ir a buscar la declaracion, que es
 * justo lo que el sufijo existe para evitar.  Es lo que hace C con `L` y `F`,
 * con los nombres de Vesta.
 *
 * El tipo sale de la propia declaracion -- `TIPO nombre = <literal>;` --, que
 * es el unico sitio donde el formateador lo sabe SIN compilar.  Donde no se
 * puede saber (un argumento, una expresion) no se inventa nada.
 *
 * Dos cosas que NO se tocan, y las dos cambiarian el programa:
 *
 *   - un entero que NO CABE en el tipo declarado: `u8 x = 300;` no puede
 *     decir `300_u8`.  Es un error del autor, pero es suyo y lo dice el
 *     compilador; el formateador no lo empeora dejando el fichero sin
 *     compilar por otro sitio.
 *   - un entero declarado de tipo flotante (`f64 x = 1;`): el sufijo tiene que
 *     ser de la misma familia que el literal.
 *
 * @param pieces [in,out] las piezas; se reescribe el texto de los literales.
 * @param textos [in,out] almacen de los textos nuevos, que las piezas apuntan.
 * @return Las reescrituras hechas, para que `P2` sepa que diferencia esperar.
 */
std::vector<Rewrite> add_type_suffixes(std::vector<Piece> &pieces,
                                       std::vector<std::string> &textos) {
    std::vector<Rewrite> hechas;
    /* Dentro de un bloque `asm` no se toca NADA.
     *
     * Ahi los numeros son operandos de instrucciones de la maquina, no valores
     * de Vesta: `mov rax, 42` no admite un sufijo de tipo, y ponerselo deja el
     * bloque sin ensamblar.  Es la misma linea que `R77` traza para la
     * indentacion -- lo de dentro del `asm` es del autor --, aplicada aqui. */
    int asm_prof = 0;
    bool asm_viene = false;
    for (size_t i = 0; i + 1 < pieces.size(); ++i) {
        const TokenKind aqui = kind_of(pieces[i]);
        if (aqui == TokenKind::KW_ASM) asm_viene = true;
        if (aqui == TokenKind::LBRACE) {
            if (asm_prof > 0)
                ++asm_prof;
            else if (asm_viene)
                asm_prof = 1;
            asm_viene = false;
        } else if (aqui == TokenKind::RBRACE && asm_prof > 0) {
            --asm_prof;
        }
        if (asm_prof > 0) continue;

        /* La forma: `TIPO nombre = [-|+] <literal> ;`, con el literal solo.
         *
         * El signo es un token aparte -- no forma parte del numero --, asi que
         * el literal puede estar una pieza mas alla.  Es lo que decide si
         * `128` cabe en un `i8`: con el `-` delante si, sin el no. */
        if (kind_of(pieces[i]) != TokenKind::ASSIGN) continue;
        const TokenKind signo = kind_of(pieces[i + 1]);
        const bool negativo = signo == TokenKind::MINUS;
        const size_t n = (negativo || signo == TokenKind::PLUS) ? i + 2 : i + 1;
        if (n + 1 >= pieces.size()) continue;
        if (kind_of(pieces[n + 1]) != TokenKind::SEMICOLON) continue;

        Piece &lit = pieces[n];
        const bool entero = kind_of(lit) == TokenKind::INT_LIT;
        const bool real = kind_of(lit) == TokenKind::FLOAT_LIT;
        if (!entero && !real) continue;
        if (lit.in_string || lit.verbatim) continue;
        if (has_suffix(lit.text)) continue;

        // El nombre del tipo esta dos piezas antes del `=`: `TIPO nombre =`.
        if (i < 2) continue;
        if (kind_of(pieces[i - 1]) != TokenKind::IDENTIFIER) continue;
        const TokenKind tk = kind_of(pieces[i - 2]);
        if (!is_type_keyword(tk)) continue;

        bool flotante = false;
        if (!suffix_name(pieces[i - 2].text, flotante)) continue;
        if (flotante != real) continue; // la familia tiene que coincidir

        /* Un entero tiene que CABER en el tipo antes de decir que es de ese
         * tipo.  El signo va aparte del literal, asi que hay que mirarlo: la
         * misma cifra cabe en `i8` con `-` delante (`-128`) y no sin el. */
        if (entero) {
            const std::string_view ancho = pieces[i - 2].text.substr(1);
            unsigned bits = 0;
            for (const char c : ancho)
                bits = bits * 10 + (unsigned)(c - '0');
            const bool con_signo = pieces[i - 2].text.front() == 'i';
            unsigned long long valor = 0;
            if (!int_value(lit.text, valor)) continue;
            if (!fits(valor, bits, con_signo, negativo)) continue;
        }

        std::string nuevo(lit.text);
        nuevo += '_';
        nuevo += pieces[i - 2].text;
        textos.push_back(std::move(nuevo));
        lit.text = textos.back();
        hechas.push_back({RewriteKind::AddTypeSuffix, lit.offset});
    }
    return hechas;
}

} // namespace fmt
} // namespace vx
