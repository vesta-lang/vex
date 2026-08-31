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
 * @file indent.cpp
 * @brief Indentacion y lineas en blanco: `R1`, `R4`, `R5`, `R7` y `R8`.
 *
 * Es la primera regla que MUEVE codigo, y por eso va en su propio fichero: el
 * resto del formateador puede leerse sin ella y ella sin el resto.
 *
 * El nivel sale de contar llaves, y contar llaves es fiable aqui por una razon
 * que no es obvia: las llaves de dentro de una cadena NUNCA llegan.  El lexer
 * ya entrego la cadena entera como UN token, asi que un `"}"` es texto y no una
 * llave.  Deducirlo a mano sobre el texto crudo -- que es lo que hace un
 * formateador basado en expresiones regulares -- es justo donde esos fallan.
 *
 * LO QUE NO SE TOCA: el interior de un bloque `asm` (`R77`).  Ahi la
 * indentacion la puso el autor y significa algo; solo se reindenta el bloque
 * como un todo, conservando la forma relativa de dentro (`R78`).
 */

#include "vx/fmt/fmt_internal.h"

#include "vx/fmt/width.h"
#include "vx/token.h"

namespace vx {
namespace fmt {
namespace {

/// @brief Indica si la pieza es el token @p kind.
inline bool is(const Piece &p, TokenKind kind) {
    return p.kind == static_cast<int>(kind);
}

/**
 * @brief Los comentarios de un tramo de trivia, ya recortados.
 *
 * La trivia entre dos tokens puede llevar varios comentarios y saltos
 * mezclados.  Para reindentar hace falta saber COMO estaban repartidos: cuantos
 * saltos van antes de cada comentario y cuantos despues.
 *
 * @param trivia Texto entre dos tokens.
 * @param opaque [out] cierto si aparecio algo que NO es blanco ni comentario.
 * @return Los trozos con contenido, en orden, con los saltos que los preceden.
 */
std::vector<TriviaChunk> split_trivia(std::string_view trivia, bool &opaque) {
    std::vector<TriviaChunk> chunks;
    size_t i = 0;
    uint32_t newlines = 0;
    while (i < trivia.size()) {
        const char c = trivia[i];
        if (c == '\n') {
            ++newlines;
            ++i;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\r') {
            ++i;
            continue;
        }
        /* Aqui empieza un comentario: de linea hasta el salto, de bloque hasta
         * el cierre.
         *
         * Y si NO es un comentario, es que en la trivia hay algo del programa
         * -- la comilla que cierra una cadena interpolada, por ejemplo, que el
         * lexer no cubre con ningun token porque su marcador de fin es
         * sintetico --.  Eso no se toca: se avisa y quien llama copia el tramo
         * literal.  Es la salvaguarda general, la que ahorra perseguir cada
         * caso raro del lexer de uno en uno. */
        const size_t start = i;
        if (c != '/') {
            opaque = true;
            return chunks;
        }
        if (i + 1 >= trivia.size()) {
            opaque = true; // una barra suelta al final no es un comentario
            return chunks;
        }
        if (trivia[i + 1] == '*') {
            i += 2;
            while (i + 1 < trivia.size() &&
                   !(trivia[i] == '*' && trivia[i + 1] == '/'))
                ++i;
            i = (i + 2 <= trivia.size()) ? i + 2 : trivia.size();
        } else if (trivia[i + 1] == '/') {
            while (i < trivia.size() && trivia[i] != '\n')
                ++i;
        } else {
            /* Una barra que no abre comentario.  Pasa de verdad: el fragmento
             * de cadena que sigue a una interpolacion puede empezar por `/`
             * -- `"${ok}/11 checks"` --, y el lexer lo entrega sin longitud,
             * con lo que su texto acaba aqui.  Tomarlo por un comentario lo
             * movia de sitio y cambiaba la cadena. */
            opaque = true;
            return chunks;
        }
        TriviaChunk chunk;
        chunk.newlines_before = newlines;
        chunk.text = trivia.substr(start, i - start);
        // Un comentario de bloque puede acabar en espacios; se recortan porque
        // `R9` los quitaria igual.
        while (!chunk.text.empty() &&
               (chunk.text.back() == ' ' || chunk.text.back() == '\t'))
            chunk.text.remove_suffix(1);
        chunks.push_back(chunk);
        newlines = 0;
    }
    TriviaChunk last; // lo que queda tras el ultimo comentario
    last.newlines_before = newlines;
    chunks.push_back(last);
    return chunks;
}

/**
 * @brief Escribe un comentario, reindentando el de bloque con asteriscos.
 *
 * `R21`: si TODAS las lineas de continuacion empiezan por `*`, es la forma
 * habitual del comentario de bloque y sus asteriscos se alinean bajo el del
 * `/ *` de apertura.  Ahi la indentacion no es del autor: es una columna, y
 * dejarla sin mover la descuadra en cuanto el codigo cambia de nivel.
 *
 * `R21b`: si NO siguen ese patron -- arte ASCII, una tabla, un trozo de otro
 * lenguaje pegado --, el texto es del autor y se copia tal cual.
 *
 * @param out    [in,out] salida.
 * @param text   Texto completo del comentario.
 * @param levels Niveles de indentacion de la linea donde empieza.
 * @return Cuantos saltos de linea se escribieron (0 si es de una sola).
 */
uint32_t append_comment(std::string &out, std::string_view text, int levels) {
    const size_t nl = text.find('\n');
    if (nl == std::string_view::npos || text.size() < 2 || text[0] != '/' ||
        text[1] != '*') {
        out.append(text); // de una linea, o no es de bloque
        return 0;
    }
    // Todas las lineas de continuacion tienen que empezar por `*`.
    std::vector<std::string_view> lineas;
    size_t i = 0;
    while (i <= text.size()) {
        const size_t j = text.find('\n', i);
        const size_t end = (j == std::string_view::npos) ? text.size() : j;
        lineas.push_back(text.substr(i, end - i));
        if (j == std::string_view::npos) break;
        i = j + 1;
    }
    for (size_t k = 1; k < lineas.size(); ++k) {
        std::string_view l = lineas[k];
        while (!l.empty() && (l.front() == ' ' || l.front() == '\t'))
            l.remove_prefix(1);
        if (l.empty() || l.front() != '*') {
            out.append(text); // `R21b`: no sigue el patron, no se toca
            return static_cast<uint32_t>(lineas.size() - 1);
        }
    }
    out.append(lineas[0]);
    for (size_t k = 1; k < lineas.size(); ++k) {
        std::string_view l = lineas[k];
        while (!l.empty() && (l.front() == ' ' || l.front() == '\t'))
            l.remove_prefix(1);
        out.push_back('\n');
        for (int t = 0; t < levels; ++t)
            out.push_back('\t');
        // Un espacio para que el `*` caiga bajo el del `/ *` de apertura.
        out.push_back(' ');
        out.append(l);
    }
    return static_cast<uint32_t>(lineas.size() - 1);
}

} // namespace

std::string reindent(const std::vector<Piece> &pieces, std::string_view tail,
                     const FormatOptions &options,
                     const std::vector<uint32_t> *pad, Layout *out,
                     const std::vector<Break> *breaks,
                     const std::vector<uint32_t> *cpad,
                     std::vector<Rewrite> *added) {
    /* Primero se anota QUE es cada simbolo ambiguo, con el contexto que hace
     * falta; luego el espaciado se decide token a token sin volver a dudar. */
    const std::vector<Role> roles = annotate_roles(pieces);

    std::string text;
    text.reserve(tail.size() + 64);
    if (out != nullptr) {
        out->column.assign(pieces.size(), 0);
        out->comment_column.assign(pieces.size(), 0);
        out->comment_line.assign(pieces.size(), 0);
        out->line.assign(pieces.size(), 0);
        out->level.assign(pieces.size(), 0);
        out->cont.assign(pieces.size(), 0);
    }
    bool cerro_do = false; // la llave anterior cerraba un bloque de `do`
    uint32_t cur_line = 0; // linea logica en curso
    size_t line_start = 0; // byte donde empieza la linea actual

    int level = 0;         // nivel de anidamiento actual
    int asm_depth = 0;     // profundidad de llaves dentro de un `asm`
    bool in_asm = false;   // dentro de un bloque `asm`
    bool asm_next = false; // el proximo `{` abre un bloque `asm`
    /// Indentacion de la PRIMERA linea del cuerpo de un `asm`, en columnas.
    /// Es la referencia contra la que se mide el resto (`R78`).
    uint32_t asm_base = UINT32_MAX;
    /* Que bloques abrio un `do`.  Hace falta para `R53`: el `while` de un
     * `do` continua su llave y va pegado, pero uno corriente empieza una
     * sentencia nueva y no.  Los dos se escriben igual, asi que la unica forma
     * de distinguirlos es recordar quien abrio el bloque que se acaba de
     * cerrar. */
    std::vector<bool> block_do;
    bool do_next = false;
    /* Nivel de llave del `enum` en el que estamos, o -1.  Dentro, cada valor
     * va en su linea (`R48`): es lo que `R47` da por hecho al alinearlos por
     * su `=`, y lo que permite comentar uno sin arrastrar a los demas. */
    int enum_level = -1;
    bool enum_next = false;
    /* Un cuerpo de UNA sentencia sin llaves que no cupo en su linea.
     *
     * `R6` dice que ese caso lleva llaves, pero ponerlas cambiaria la lista de
     * tokens y `P2` no lo permite (ver `D0`).  Lo minimo mientras tanto es que
     * se INDENTE: al nivel de su `if` se lee como la sentencia siguiente, que
     * es exactamente el enganio del `goto fail`. */
    int cuerpo_suelto = 0;
    /// El `)` que cierra la cabecera de control en curso.  Arranca FUERA de
    /// rango: con cero, el token de indice uno lo cumplia y sangraba el
    /// fichero entero.
    size_t ctrl_close = static_cast<size_t>(-1);
    bool cierra_cuerpo = false;   // hay una llave de `R6` esperando su pareja
    bool llave_pendiente = false; // un cuerpo suelto pendiente de decidir
    int nivel_cuerpo = 0;         // nivel de la cabecera de ese cuerpo
    bool at_line_start = true;

    /// Escribe la indentacion de un nivel (`R1`: un tabulador por nivel).
    const auto put_indent = [&text](int n) {
        for (int i = 0; i < n; ++i)
            text.push_back('\t');
    };

    /* `R57`: una etiqueta de `goto` va un nivel MENOS, a la altura de la llave.
     *
     * Es lo mismo que hace C, y por la misma razon: una etiqueta no pertenece
     * al bloque, es un punto de ENTRADA a el.  Indentada como el codigo se lee
     * como una sentencia mas y deja de saltar a la vista, que es justo lo que
     * tiene que hacer.
     *
     * Se reconoce por la forma -- un nombre y unos dos puntos que el anotador
     * marco como etiqueta -- y no adivinando. */
    const auto is_label = [&pieces, &roles](size_t idx) {
        if (idx + 1 >= pieces.size()) return false;
        if (static_cast<TokenKind>(pieces[idx].kind) != TokenKind::IDENTIFIER)
            return false;
        if (static_cast<TokenKind>(pieces[idx + 1].kind) != TokenKind::COLON)
            return false;
        if (roles[idx + 1] != Role::TightLeft) return false;
        /* Y va SOLA en su linea.
         *
         * Un `nombre:` con algo detras no es una etiqueta: es la etiqueta de un
         * contrato (`partial_pre: O(n)`), que lleva su valor al lado y se
         * indenta como cualquier otra linea.  Sin esta comprobacion se le
         * restaba un nivel y el contenido de un `@complexity` repartido salia
         * a la altura de la anotacion en vez de dentro. */
        if (idx + 2 < pieces.size() &&
            pieces[idx + 2].trivia.find('\n') == std::string_view::npos)
            return false;
        return true;
    };

    /* Indice de la pieza que se emitio por ULTIMA vez.  No es siempre `idx-1`:
     * las de dentro de un `asm` o de una cadena salen por otro camino, y
     * preguntarle a la de al lado en el vector daria una respuesta sobre dos
     * tokens que no llegaron a quedar juntos. */
    size_t last_index = 0;

    /* Listas abiertas (parentesis, corchetes, llaves de inicializacion).
     *
     * De aqui sale la indentacion de CONTINUACION: lo que va dentro de una
     * lista que se quedo abierta lleva un nivel mas.  Y sale de la ESTRUCTURA,
     * no de quien puso el salto, que es lo que la hace idempotente: al
     * formatear un fichero que ya venia repartido, los saltos ya estan en el
     * texto y nadie pide el nivel extra -- si dependiera del reparto, cada
     * pasada quitaria un tabulador.  Se veia en 21 ficheros del corpus. */
    std::vector<uint32_t> open_lists;

    /* Apunta donde cayo una pieza.  Lo llaman TODOS los caminos, incluidos los
     * rapidos -- dentro de un `asm`, dentro de una cadena, trivia opaca --: si
     * uno se lo salta, esas piezas se quedan en la linea cero y quien alinea
     * cree que van todas juntas.  Costo un desbordamiento de memoria
     * descubrirlo. */
    const auto mark = [&](size_t idx) {
        if (out == nullptr) return;
        out->line[idx] = cur_line;
        out->level[idx] = static_cast<uint32_t>(level < 0 ? 0 : level);
        out->cont[idx] = static_cast<uint32_t>(open_lists.size());
        // En COLUMNAS DE PANTALLA: un ideograma ocupa dos y un tabulador salta
        // a su parada.
        out->column[idx] = display_width(
            std::string_view(text).substr(line_start), options.tab_width);
    };

    // El salto de linea, sin escapes en el fuente (que este fichero se edita
    // con guiones y los escapes no siempre sobreviven).
    constexpr char kSalto = 0x0A;

    /* `R5`: en un bloque repartido en varias lineas, la llave de cierre va
     * SOLA y la de apertura no se lleva nada detras.
     *
     * Lo que se veia era el reparto a medias -- `struct Grande { i64 a;` y el
     * `} ` colgando del ultimo campo, o un `i32 main() { print(x);` --: la
     * llave deja de marcar donde empieza y donde acaba el cuerpo, que es para
     * lo que esta.  Un bloque que SI cabe entero en una linea se queda como
     * esta; el reparto a medias es el que no vale.
     *
     * Se marcan las dos llaves de cada pareja que abarca mas de una linea. */
    std::vector<uint8_t> llave_partida(pieces.size(), 0);
    {
        std::vector<size_t> abiertas;
        /* Por cada llave abierta, si lo de dentro se va a repartir en esta
         * MISMA pasada.
         *
         * Sin esto, un cuerpo escrito en una linea salia a medias: la pasada
         * repartia sus sentencias -- por `R26`, que corta tras un `;` que
         * cierra -- pero las llaves seguian pegadas, porque este barrido solo
         * miraba los saltos que YA HABIA.  Hacia falta una segunda pasada, y
         * el mismo programa tenia dos formas segun cuantas veces se hubiera
         * formateado.  Asi se colaron 66 ficheros de `tests/`. */
        std::vector<uint8_t> reparte_dentro;
        int prof_par = 0; // parentesis y corchetes abiertos
        for (size_t k = 0; k < pieces.size(); ++k) {
            const TokenKind tk = static_cast<TokenKind>(pieces[k].kind);
            if (tk == TokenKind::LPAREN || tk == TokenKind::LBRACKET) {
                ++prof_par;
            } else if (tk == TokenKind::RPAREN || tk == TokenKind::RBRACKET) {
                if (prof_par > 0) --prof_par;
            } else if (tk == TokenKind::SEMICOLON && prof_par == 0 &&
                       k + 1 < pieces.size() && !reparte_dentro.empty()) {
                /* La MISMA condicion que usa el corte de `R26` mas abajo: un
                 * `;` a nivel cero que no cierra el bloque.  Los de la cabecera
                 * de un `for` van dentro de parentesis, asi que no cuentan. */
                const TokenKind sig =
                    static_cast<TokenKind>(pieces[k + 1].kind);
                if (sig != TokenKind::RBRACE && sig != TokenKind::RPAREN &&
                    sig != TokenKind::RBRACKET)
                    reparte_dentro.back() = 1;
            }
            if (tk == TokenKind::LBRACE) {
                abiertas.push_back(k);
                reparte_dentro.push_back(0);
            } else if (tk == TokenKind::RBRACE && !abiertas.empty()) {
                const size_t open = abiertas.back();
                abiertas.pop_back();
                const bool dentro = reparte_dentro.back() != 0;
                reparte_dentro.pop_back();
                bool multilinea = false;
                for (size_t j = open + 1; j <= k && !multilinea; ++j)
                    multilinea =
                        pieces[j].trivia.find(kSalto) != std::string_view::npos;
                if (multilinea || dentro) {
                    llave_partida[open] = 1;
                    llave_partida[k] = 1;
                    /* Un bloque repartido reparte al que lo contiene: sus
                     * llaves ya no caben en la linea de fuera. */
                    if (!reparte_dentro.empty()) reparte_dentro.back() = 1;
                }
            }
        }
    }

    for (size_t idx = 0; idx < pieces.size(); ++idx) {
        const Piece &p = pieces[idx];
        // Una pieza que alguna regla retiro (`R29`, `R74`) no se emite.  Su
        // trivia tampoco: pertenecia a un token que ya no esta.
        if (p.drop) continue;

        /* `R5`: la llave de cierre baja un nivel ANTES de escribirse, para que
         * quede a la altura de quien abrio y no de lo que hay dentro. */
        const bool closes = is(p, TokenKind::RBRACE);
        /* Si esta llave cierra el `enum`, se anota AQUI: mas abajo el nivel ya
         * habra bajado y la marca estara limpia, y entonces no habria forma de
         * saber que el `}` era suyo. */
        const bool cierra_enum =
            closes && enum_level >= 0 && level - 1 == enum_level;
        if (cierra_enum) enum_level = -1;
        if (closes) {
            cerro_do = !block_do.empty() && block_do.back();
            if (!block_do.empty()) block_do.pop_back();
        }
        if (closes && level > 0) --level;

        /* Un cierre sale de la pila ANTES de indentarse, para quedar a la
         * altura de quien abrio -- lo mismo que hace `R5` con las llaves. */
        const TokenKind pk = static_cast<TokenKind>(p.kind);
        /* Solo los parentesis y los corchetes: una llave de bloque ya sube el
         * nivel por su cuenta (`R4`/`R5`), y contarla aqui la indentaria dos
         * veces.  Una llave de lista de inicializacion tambien sube el nivel,
         * asi que sale bien igual. */
        const bool closes_any =
            (pk == TokenKind::RPAREN || pk == TokenKind::RBRACKET);
        if (closes_any && !open_lists.empty()) open_lists.pop_back();
        const int cont = static_cast<int>(open_lists.size());

        /* Tras la cabecera de un `if`/`for`/`while` sin llaves, lo que venga
         * en OTRA linea es su cuerpo y va un nivel adentro.
         *
         * El `)` tiene que ser el de la CABECERA y no el de una llamada, asi
         * que se apunta cual es al ver la palabra clave.  Sin esa
         * comprobacion, `(a + b)
         * c` tambien se habria sangrado. */
        if (idx > 0 && ctrl_close == idx - 1 && !is(p, TokenKind::LBRACE) &&
            !is(p, TokenKind::SEMICOLON) && !is(p, TokenKind::RBRACE)) {
            ++cuerpo_suelto;
            /* Se APUNTA que este cuerpo puede necesitar llaves (`R6`); se
             * decide mas abajo, cuando el salto de linea ya este escrito o no.
             * Solo las necesita el que acabo en otra linea: uno que cupo junto
             * a su cabecera vale sin ellas, y es la forma que `R6b` deja. */
            llave_pendiente = true;
        }

        /* Al llegar al `;` que cierra ese cuerpo, se deshace la sangria.  Va
         * antes de escribirlo para que el `;` salga en la misma linea. */
        if (cuerpo_suelto > 0 && idx > 0 &&
            is(pieces[idx - 1], TokenKind::SEMICOLON) && cont == 0) {
            --cuerpo_suelto;
            // Y la llave que cierra, a la altura de la cabecera.
            if (cierra_cuerpo) {
                cierra_cuerpo = false;
                text.push_back('\n');
                ++cur_line;
                /* Al nivel de la CABECERA, guardado al abrir: aqui `level` ya
                 * pudo bajar por la llave del bloque que envuelve, y entonces
                 * la de cierre saldria a otra altura que la suya. */
                put_indent(nivel_cuerpo);
                text.push_back('}');
                if (added != nullptr)
                    added->push_back(
                        {RewriteKind::AddBraces, pieces[idx].offset});
                at_line_start = false;
            }
        }

        /* `R77`: dentro de un `asm`, la indentacion es del autor.  Se copia la
         * trivia tal cual y no se reindenta nada -- ahi las columnas y los
         * niveles significan algo que este modulo no sabe leer.  Alinear sus
         * columnas (`R90`) es trabajo de un modulo aparte, que conoce la forma
         * de una instruccion. */
        if (in_asm && !closes) {
            /* `R78`: el bloque se reindenta COMO UN TODO, conservando la forma
             * relativa de dentro.
             *
             * Copiar la trivia tal cual dejaba el cuerpo con la indentacion
             * que tuviera el fichero antes -- espacios, mientras el resto pasa
             * a tabuladores --, y entonces el bloque se quedaba flotando a una
             * altura que ya no era la suya.  Lo que es del autor es la forma
             * RELATIVA (`R77`): que una linea vaya mas adentro que otra.  Eso
             * se conserva midiendo cada una contra la primera del cuerpo. */
            const size_t nl_pos = p.trivia.rfind('\n');
            if (nl_pos != std::string_view::npos) {
                const std::string_view sangria = p.trivia.substr(nl_pos + 1);
                const uint32_t col = display_width(sangria, options.tab_width);
                if (asm_base == UINT32_MAX) asm_base = col;
                if (col < asm_base) asm_base = col; // por si acaso
                // Los saltos que hubiera, con el tope de lineas en blanco.
                uint32_t saltos = 0;
                for (const char c : p.trivia)
                    if (c == '\n') ++saltos;
                cur_line +=
                    emit_newlines(text, saltos, options.blank_lines_inside);
                put_indent(level);
                // Lo que esta linea iba MAS adentro que la primera del cuerpo.
                for (uint32_t k = asm_base; k < col; ++k)
                    text.push_back(' ');
                const size_t nl2 = text.rfind('\n');
                line_start = (nl2 == std::string::npos) ? 0 : nl2 + 1;
            } else {
                text.append(p.trivia);
            }
            mark(idx);
            text.append(p.glued.empty() ? p.text : p.glued);
            at_line_start = false;
            if (is(p, TokenKind::LBRACE)) {
                ++level;
                ++asm_depth;
            }
            continue;
        }

        /* `R69`: DENTRO de una cadena interpolada no se toca nada.
         *
         * `"total: ${n}"` no llega como un token, sino como una tira -- texto,
         * apertura, la expresion, cierre, texto --, y lo que hay entre esas
         * piezas ES el contenido de la cadena, no trivia.  Meter ahi un espacio
         * o un salto CAMBIA EL PROGRAMA: la cadena pasa a decir otra cosa.  Se
         * descubrio asi, con la comprobacion de que el programa no cambia
         * fallando en 125 ficheros del corpus. */
        /* `R110`: dentro de una llamada que captura el TEXTO de su argumento
         * (un parametro `expr`), los espacios son contenido y no formato.
         * Vale el mismo camino que para una cadena interpolada: copiar la
         * trivia tal cual. */
        if (p.in_string || p.verbatim) {
            text.append(p.trivia);
            mark(idx);
            text.append(p.glued.empty() ? p.text : p.glued);
            at_line_start = false;
            continue;
        }

        /* `R12`: el reparto puede pedir un corte JUSTO antes de esta pieza.
         * Va delante de todo lo demas porque cambia la linea en la que cae, y
         * con ella su indentacion y sus columnas. */
        /* Y solo si NO habia ya un salto ahi.  El corte es "pon uno si falta",
         * no "pon uno mas": al formatear un fichero que ya venia repartido, la
         * trivia trae su salto y sumarle el del corte dejaba una linea en
         * blanco por elemento, que crecia en cada pasada. */
        /* `R26` y `R43`: una declaracion -- o un miembro -- por linea.
         *
         * Dos sentencias en la misma linea esconden la segunda: el ojo lee
         * una linea como una cosa.  Se parte SIEMPRE tras un `;` que cierra
         * sentencia.  Los que NO cierran sentencia son los de la cabecera de
         * un `for`: los de en medio van dentro de parentesis (`cont > 0`), y
         * el ultimo -- el de `for (;;)` -- se reconoce porque lo que sigue es
         * el cierre, que ya salio de la pila y por eso no lo delata `cont`. */
        /* `R48`: dentro de un `enum`, cada valor en su linea.  Se corta tras
         * la coma que los separa, y solo la del nivel exterior: la de dentro
         * de `Some(A, B)` pertenece a la carga. */
        const bool dentro_enum =
            enum_level >= 0 && level - 1 == enum_level && cont == 0 && idx > 0;
        const bool parte_valor_enum =
            dentro_enum &&
            // tras la coma que separa dos valores...
            ((is(pieces[idx - 1], TokenKind::COMMA) &&
              !is(p, TokenKind::RBRACE)) ||
             // ...y tambien al abrir y al cerrar, para que el enum entero
             // quede repartido y no medio dentro de su linea.
             (is(pieces[idx - 1], TokenKind::LBRACE) &&
              !is(p, TokenKind::RBRACE)));

        /* Una linea que CONTINUA la sentencia anterior va un nivel adentro.
         *
         * `R15` dice que donde partiste una expresion no se toca -- ahi esta
         * tu articulacion --, pero eso es DONDE, no a que altura: sin sangrar,
         * la continuacion queda al mismo nivel que la sentencia y se lee como
         * una sentencia nueva.
         *
         * Se reconoce por lo que hay DETRAS: si el token anterior no cierra
         * nada -- no es `;`, `{`, `}` ni `,` --, lo que viene es continuacion.
         * Sale de la estructura y no de quien puso el salto, que es lo que la
         * hace idempotente. */
        constexpr char kNewline = 0x0A; // '\n', sin escapes en el fuente

        /* La linea a la que pertenece una pieza, empieza por `@`?
         *
         * Se retrocede hasta el salto de linea anterior; la primera pieza tras
         * el es la que abre la linea. */
        const auto linea_es_anotacion = [&](size_t fin) {
            size_t k = fin;
            while (k > 0 &&
                   pieces[k].trivia.find(kSalto) == std::string_view::npos)
                --k;
            return is(pieces[k], TokenKind::AT);
        };

        int continuacion = 0;
        if (idx > 0 && cont == 0 &&
            p.trivia.find('\n') != std::string_view::npos) {
            const TokenKind ant = static_cast<TokenKind>(pieces[idx - 1].kind);
            const bool cierra =
                ant == TokenKind::SEMICOLON || ant == TokenKind::LBRACE ||
                ant == TokenKind::RBRACE || ant == TokenKind::COMMA ||
                ant == TokenKind::COLON;
            /* Una ANOTACION es una unidad entera, no media sentencia.
             *
             * `@Target("...")` acaba en `)`, que no cierra sentencia, asi que
             * todo lo que venia detras -- las demas anotaciones y la propia
             * firma de la funcion -- se tomaba por continuacion y entraba un
             * nivel, y ya no salia.  Ni una anotacion continua lo de arriba ni
             * lo de abajo continua una anotacion. */
            const bool tras_anotacion = linea_es_anotacion(idx - 1);

            // Ni una llave, ni una etiqueta, ni lo que ya lleva su propio
            // nivel: eso se indenta por su cuenta.
            /* Un CIERRE tampoco continua nada: vuelve a la altura de quien
             * abrio, y de eso ya se ocupa la pila de listas.  Sin excluirlo,
             * el `);` de una expresion repartida en varias lineas se iba un
             * tabulador a la derecha de la sentencia que cerraba. */
            const bool es_cierre = is(p, TokenKind::RPAREN) ||
                                   is(p, TokenKind::RBRACKET) ||
                                   is(p, TokenKind::RBRACE);

            if (!cierra && !tras_anotacion && !es_cierre &&
                !is(p, TokenKind::AT) && !is(p, TokenKind::LBRACE) &&
                !is_label(idx))
                continuacion = 1;

            /* Salvo que sea el cuerpo suelto de un `if`/`for`/`while`.
             *
             * Ahi el `)` de la cabecera tampoco cierra sentencia, asi que la
             * primera linea del cuerpo cumplia las dos cosas y entraba DOS
             * niveles: uno por ser cuerpo y otro por parecer continuacion.  Es
             * el mismo hecho contado dos veces, y lo cuenta `cuerpo_suelto`,
             * que ademas sabe cuando deshacerlo. */
            if (ctrl_close == idx - 1) continuacion = 0;
        }

        const bool parte_sentencia =
            idx > 0 && is(pieces[idx - 1], TokenKind::SEMICOLON) && cont == 0 &&
            !is(p, TokenKind::RBRACE) && !is(p, TokenKind::RPAREN) &&
            !is(p, TokenKind::RBRACKET);

        const bool trivia_breaks =
            p.trivia.find('\n') != std::string_view::npos;
        /* `R5`: en un bloque de varias lineas, la de apertura no arrastra el
         * primer enunciado y la de cierre empieza linea.  Dentro de un `asm`
         * no se toca: ahi el reparto es del autor. */
        const bool parte_llave =
            !in_asm && ((idx > 0 && is(pieces[idx - 1], TokenKind::LBRACE) &&
                         llave_partida[idx - 1]) ||
                        (is(p, TokenKind::RBRACE) && llave_partida[idx]));

        const bool corta_aqui = parte_sentencia || parte_valor_enum ||
                                parte_llave ||
                                (cierra_enum && idx > 0 &&
                                 !is(pieces[idx - 1], TokenKind::LBRACE)) ||
                                (breaks != nullptr && idx < breaks->size() &&
                                 (*breaks)[idx].before);
        if (corta_aqui && !at_line_start && !trivia_breaks) {
            text.push_back('\n');
            ++cur_line;
            const size_t nl2 = text.rfind('\n');
            line_start = (nl2 == std::string::npos) ? 0 : nl2 + 1;
            /* La sangria extra que pidio el reparto.  La usa `R94`: los
             * eslabones de una cadena van un nivel dentro del receptor, y ahi
             * no hay ningun parentesis abierto que lo diga por si solo. */
            const int extra =
                (breaks != nullptr && idx < breaks->size())
                    ? static_cast<int>((*breaks)[idx].extra_indent)
                    : 0;
            put_indent(level + cont + cuerpo_suelto + continuacion + extra);
            at_line_start = true;
        }

        bool opaque = false;
        const std::vector<TriviaChunk> chunks = split_trivia(p.trivia, opaque);
        if (opaque) {
            // Hay programa en la trivia: se copia tal cual y no se reindenta.
            text.append(p.trivia);
            mark(idx);
            text.append(p.glued.empty() ? p.text : p.glued);
            at_line_start = false;
            if (is(p, TokenKind::LBRACE)) ++level;
            continue;
        }
        for (size_t c = 0; c + 1 < chunks.size(); ++c) {
            const TriviaChunk &chunk = chunks[c];
            // `R18`: un comentario en su propia linea se indenta como lo que
            // sigue; uno de fin de linea se queda donde estaba.
            if (chunk.newlines_before == 0 && !at_line_start) {
                text.push_back(' '); // `R19`
                /* `R20`: y el relleno que lo lleva a su columna, para que los
                 * comentarios de lineas seguidas queden alineados entre si. */
                if (cpad != nullptr && idx < cpad->size())
                    text.append((*cpad)[idx], ' ');
                if (out != nullptr) out->comment_line[idx] = cur_line;
                if (out != nullptr)
                    out->comment_column[idx] =
                        display_width(std::string_view(text).substr(line_start),
                                      options.tab_width);
            } else {
                /* Los saltos CUENTAN.  Sin sumarlos, la linea que se apunta
                 * para cada pieza no avanzaba al pasar un comentario, y el
                 * alineado -- que corta el bloque cuando dos lineas no son
                 * seguidas (`R83`) -- veia pegado lo que tenia un comentario
                 * en medio: una declaracion de mas abajo se metia en un bloque
                 * al que no pertenece y le robaba una columna a las que si. */
                cur_line +=
                    emit_newlines(text, chunk.newlines_before,
                                  level == 0 ? options.blank_lines_between
                                             : options.blank_lines_inside);
                put_indent(level + cont + cuerpo_suelto + continuacion);
            }
            // Y las que ocupe el comentario mismo, si es de varias lineas.
            cur_line +=
                append_comment(text, chunk.text, level + cont + cuerpo_suelto);
            at_line_start = false;
        }

        /* `R12` en su otra direccion: si el reparto dijo que esta lista cabe
         * entera, el salto que venia aqui se quita y la pieza sigue en la misma
         * linea.  Sin esto, una lista partida a mano se quedaria partida
         * aunque cupiera, y el mismo programa tendria dos formas validas. */
        /* `R53`: los cierres que CONTINUAN van pegados a la llave.
         *
         * `}` y `else` en lineas distintas parten en dos lo que es una sola
         * decision; juntos se lee la estructura entera de un vistazo.  Vale
         * igual para `catch`, `finally` y el `while` de un `do`. */
        const bool continua =
            idx > 0 && is(pieces[idx - 1], TokenKind::RBRACE) &&
            /* ...y sin nada escrito por medio.  Si el `}` lleva detras un
             * comentario de linea, juntarlos meteria el `else` DENTRO del
             * comentario y se llevaria por delante la otra rama.  Salio en el
             * corpus: `{ e = n; }  // fin del directorio` con su `else`
             * debajo. */
            p.trivia.find("/") == std::string_view::npos &&
            (is(p, TokenKind::KW_ELSE) || is(p, TokenKind::KW_CATCH) ||
             is(p, TokenKind::KW_FINALLY) ||
             (is(p, TokenKind::KW_WHILE) && cerro_do));
        /* `R4`: la llave de apertura sube al final de la linea anterior.
         *
         * Es la otra direccion de la regla, la que faltaba: el formateador ya
         * la ponia ahi al escribir, pero una que viniera en su propia linea se
         * quedaba abajo, y entonces el mismo programa tenia dos formas.  No se
         * sube si por medio hay un comentario, por lo mismo que `R53`. */
        const bool sube_llave = idx > 0 && is(p, TokenKind::LBRACE) &&
                                p.trivia.find("/") == std::string_view::npos &&
                                !is(pieces[idx - 1], TokenKind::LBRACE) &&
                                !is(pieces[idx - 1], TokenKind::RBRACE) &&
                                !is(pieces[idx - 1], TokenKind::SEMICOLON) &&
                                !is(pieces[idx - 1], TokenKind::COMMA);

        const bool drop_break =
            continua || sube_llave ||
            (breaks != nullptr && idx < breaks->size() && (*breaks)[idx].join);

        const TriviaChunk &rest = chunks.back();
        if (rest.newlines_before > 0 && !drop_break) {
            // `R7`/`R8`: como mucho una linea en blanco dentro de un bloque,
            // dos entre declaraciones de nivel superior.
            cur_line += emit_newlines(text, rest.newlines_before,
                                      level == 0 ? options.blank_lines_between
                                                 : options.blank_lines_inside);
            put_indent((is_label(idx) && level > 0 ? level - 1 : level) + cont +
                       cuerpo_suelto + continuacion);
            at_line_start = true;
            // Donde empieza la linea nueva, para medir columnas desde ahi.
            const size_t nl = text.rfind('\n');
            line_start = (nl == std::string::npos) ? 0 : nl + 1;
        } else if (!at_line_start || drop_break) {
            /* Misma linea: la separacion la decide el estandar (`R33`-`R35`,
             * `R52`, `R61`+), no lo que hubiera antes.  `Keep` es la respuesta
             * para lo ambiguo -- `*`, `&`, `<`, `>` --: ahi se conserva lo que
             * escribio el autor, porque sin el arbol `Caja<i64>` y `a < b` son
             * indistinguibles y equivocarse estropea. */
            const Piece *before =
                (last_index >= 2) ? &pieces[last_index - 2] : nullptr;
            const Spacing sp = space_between(before, pieces[last_index - 1], p,
                                             roles[last_index - 1], roles[idx]);
            if (sp == Spacing::Space) {
                text.push_back(' ');
            } else if (sp == Spacing::Keep && !p.trivia.empty()) {
                text.push_back(' ');
            }
        }

        /* El relleno de la alineacion va JUSTO antes del token, despues de que
         * el espaciado haya decidido lo suyo: primero se separa segun la regla
         * y luego se estira hasta la columna del bloque. */
        if (pad != nullptr && idx < pad->size()) text.append((*pad)[idx], ' ');

        /* `R6`: si el cuerpo acabo en otra linea, recibe sus llaves.
         *
         * Sin ellas la indentacion puede MENTIR sobre lo que hay dentro, y eso
         * no es una mania de estilo: es el fallo de TLS de Apple de 2014, dos
         * `goto fail` seguidos donde solo uno estaba dentro del `if`.  Con la
         * llave puesta, ese fallo no se puede escribir.
         *
         * La llave va al final de la linea ANTERIOR (`R4`), y para cuando se
         * sabe que hace falta ese salto ya esta escrito: se cuela delante. */
        if (llave_pendiente) {
            llave_pendiente = false;
            if (at_line_start) {
                const size_t nl = text.rfind('\n');
                if (nl != std::string::npos) {
                    text.insert(nl, " {");
                    line_start += 2;
                    if (added != nullptr)
                        added->push_back(
                            {RewriteKind::AddBraces, pieces[idx].offset});
                    cierra_cuerpo = true;
                    nivel_cuerpo = level + cont + cuerpo_suelto - 1;
                }
            }
        }

        mark(idx);
        text.append(p.glued.empty() ? p.text : p.glued);
        at_line_start = false;
        last_index = idx + 1;

        // Contabilidad de bloques.
        if (pk == TokenKind::LPAREN || pk == TokenKind::LBRACKET)
            open_lists.push_back(cur_line);
        if (is(p, TokenKind::KW_ASM)) asm_next = true;
        /* Al ver una palabra clave de control, se busca el `)` que cierra su
         * condicion: es el unico `)` tras el que puede empezar un cuerpo. */
        if (is(p, TokenKind::KW_IF) || is(p, TokenKind::KW_FOR) ||
            is(p, TokenKind::KW_WHILE)) {
            int d = 0;
            for (size_t k = idx + 1; k < pieces.size(); ++k) {
                if (is(pieces[k], TokenKind::LPAREN))
                    ++d;
                else if (is(pieces[k], TokenKind::RPAREN)) {
                    if (--d == 0) {
                        ctrl_close = k;
                        break;
                    }
                } else if (d == 0)
                    break; // no venia un `(` detras: no es una cabecera
            }
        }
        if (is(p, TokenKind::KW_DO)) do_next = true;
        if (is(p, TokenKind::KW_ENUM)) enum_next = true;
        if (is(p, TokenKind::LBRACE)) {
            block_do.push_back(do_next);
            do_next = false;
            if (enum_next && enum_level < 0) enum_level = level;
            enum_next = false;
            ++level;
            if (in_asm) {
                ++asm_depth;
            } else if (asm_next) {
                in_asm = true;
                asm_depth = 1;
                asm_next = false;
                /* La referencia es la linea MENOS indentada del cuerpo, no la
                 * primera: una etiqueta suele ir mas a la izquierda que las
                 * instrucciones, y tomando la primera como base esa etiqueta
                 * se quedaba sin sitio hacia donde salir -- la sangria de un
                 * bloque son tabuladores y no se puede restar de ellos. */
                asm_base = UINT32_MAX;
                int d = 0;
                for (size_t k = idx; k < pieces.size(); ++k) {
                    if (is(pieces[k], TokenKind::LBRACE))
                        ++d;
                    else if (is(pieces[k], TokenKind::RBRACE)) {
                        if (--d == 0) break;
                    }
                    if (k == idx) continue;
                    const size_t nl = pieces[k].trivia.rfind('\n');
                    if (nl == std::string_view::npos) continue;
                    const uint32_t c = display_width(
                        pieces[k].trivia.substr(nl + 1), options.tab_width);
                    if (c < asm_base) asm_base = c;
                }
            }
        }
        if (closes && in_asm) {
            --asm_depth;
            if (asm_depth <= 0) in_asm = false;
        }
    }

    // `R10`: el fichero acaba en un unico salto de linea.
    while (!text.empty() &&
           (text.back() == '\n' || text.back() == '\t' || text.back() == ' '))
        text.pop_back();
    if (!text.empty()) text.push_back('\n');
    return text;
}

} // namespace fmt
} // namespace vx
