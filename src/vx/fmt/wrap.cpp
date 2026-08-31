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
 * @file wrap.cpp
 * @brief El reparto de las listas que no caben: `R12`, `R14`, `R15`, `R16`.
 *
 * La regla es la de Black, y su virtud no es como queda sino como CAMBIA:
 * **o cabe entera en una linea, o va un elemento por linea**.  Sin estados
 * intermedios.
 *
 *     i32 procesar(
 *         HashMap cache,
 *         unique<Buffer> entrada,
 *         borrow_mut<Estado> estado
 *     ) {
 *
 * "Algunos argumentos aqui y el resto abajo" es lo que produce diffs
 * ilegibles: se anade un argumento y se reordenan cinco lineas porque cambia
 * donde cabe el corte.  Con esta regla ese estado no existe.
 *
 * SOLO SE REPARTEN LISTAS (`R14`).  Los parametros, los argumentos y las listas
 * de inicializacion se parten por sus comas, que es un sitio mecanico y sin
 * ambiguedad.  Una expresion aritmetica o una condicion compuesta NO se tocan
 * (`R15`): ahi el salto marca la articulacion del pensamiento y lo pone quien
 * escribe.  Y una linea larga que no tiene ninguna lista se queda como esta
 * (`R16`): el formateador no rompe nada por la fuerza.
 */

#include "vx/fmt/fmt_internal.h"

#include "vx/fmt/width.h"
#include "vx/token.h"

namespace vx {
namespace fmt {
namespace {

/// @brief Indica si el token abre una lista repartible.
inline bool opens_list(TokenKind k) {
    return k == TokenKind::LPAREN || k == TokenKind::LBRACKET ||
           k == TokenKind::LBRACE;
}

/// @brief Indica si el token cierra una lista repartible.
inline bool closes_list(TokenKind k) {
    return k == TokenKind::RPAREN || k == TokenKind::RBRACKET ||
           k == TokenKind::RBRACE;
}

/**
 * @brief Junta una lista que se partio a mano pero que cabe entera (`R12`).
 *
 * Se mide lo que ocuparia aplanada -- desde donde empieza la linea de la
 * apertura hasta el final de la linea del cierre -- y, si entra en el limite,
 * se marcan sus saltos para quitarlos.
 *
 * @param pieces  Piezas del fuente.
 * @param layout  Donde cayo cada pieza.
 * @param options Ajustes del estandar.
 * @param first   Primera pieza de la linea que se mira.
 * @param last    Ultima pieza de esa linea.
 * @param breaks  [in,out] donde se anotan los saltos a quitar.
 */
void try_join(const std::vector<Piece> &pieces, const Layout &layout,
              const FormatOptions &options, size_t first, size_t last,
              std::vector<Break> &breaks) {
    /* Aqui las LLAVES no cuentan.  Una llave abre un bloque, y un bloque no se
     * junta nunca: `i32 main() { ... }` con dos sentencias dentro tiene que
     * seguir ocupando varias lineas por mucho que quepa.  Tratarla como una
     * lista mas juntaba el cuerpo entero de las funciones cortas en un renglon.
     *
     * Lo que si se junta es lo que va entre parentesis o corchetes: argumentos,
     * parametros e indices. */
    const auto opens = [](TokenKind k) {
        return k == TokenKind::LPAREN || k == TokenKind::LBRACKET;
    };
    const auto closes = [](TokenKind k) {
        return k == TokenKind::RPAREN || k == TokenKind::RBRACKET;
    };

    // Solo interesa si la linea acaba dejando una lista ABIERTA.
    int depth = 0;
    size_t open = 0;
    bool found = false;
    for (size_t k = first; k <= last; ++k) {
        const TokenKind kind = kind_of(pieces[k]);
        if (opens(kind)) {
            if (depth == 0) {
                open = k;
                found = true;
            }
            ++depth;
        } else if (closes(kind)) {
            --depth;
        }
    }
    if (!found || depth <= 0) return; // no queda nada abierto: nada que juntar

    // Buscar su cierre, que esta en una linea posterior.
    size_t close = 0;
    depth = 0;
    for (size_t k = open; k < pieces.size(); ++k) {
        const TokenKind kind = kind_of(pieces[k]);
        if (opens(kind)) {
            ++depth;
        } else if (closes(kind)) {
            if (--depth == 0) {
                close = k;
                break;
            }
        }
    }
    if (close == 0 || layout.line[close] == layout.line[open]) return;

    /* Cuanto ocuparia junta: lo que ya hay hasta la apertura, mas cada token de
     * dentro con su separacion, mas lo que sigue al cierre en su linea. */
    uint32_t flat = layout.column[open] +
                    display_width(pieces[open].text, options.tab_width);
    for (size_t k = open + 1; k <= close; ++k) {
        flat += display_width(pieces[k].text, options.tab_width);
        // Una coma lleva un espacio detras (`R35`); lo demas va pegado o casi.
        if (kind_of(pieces[k]) == TokenKind::COMMA) ++flat;
    }
    // Y el resto de la linea del cierre, que se viene con ella.
    size_t tail_end = close;
    while (tail_end + 1 < pieces.size() &&
           layout.line[tail_end + 1] == layout.line[close])
        ++tail_end;
    for (size_t k = close + 1; k <= tail_end; ++k)
        flat += display_width(pieces[k].text, options.tab_width) + 1;

    if (flat > options.width) return; // junta tampoco cabe: se queda repartida

    /* Y NO se junta si dentro hay un comentario de linea.
     *
     * Un `//` llega hasta el final de la linea: al juntar, se come todo lo que
     * viniera detras -- el resto de los argumentos, el parentesis de cierre, la
     * sentencia entera --.  Se descubrio asi, con la comprobacion de que el
     * programa no cambia: seis tokens que desaparecian sin dejar rastro.
     *
     * Un comentario de bloque tampoco: puesto en medio de una lista ya junta
     * queda ilegible, y moverlo de sitio es peor que no juntar. */
    for (size_t k = open + 1; k <= close; ++k)
        if (pieces[k].trivia.find('/') != std::string_view::npos) return;

    // Cabe: se quitan todos los saltos de dentro.
    for (size_t k = open + 1; k <= close; ++k)
        if (layout.line[k] != layout.line[k - 1]) breaks[k].join = true;
}

/**
 * @brief `R6b`: junta un cuerpo de UNA sentencia que cabe en la linea.
 *
 * `R6` deja escribir `if (n < 2) return n;` sin llaves, pero solo en una
 * linea: partido en dos, la indentacion puede mentir sobre lo que hay dentro
 * -- es el `goto fail` de Apple -- y entonces las llaves son obligatorias.
 * Para que haya UNA sola forma (`P1`) hace falta tambien la otra direccion:
 * uno que venga partido y quepa junto, se junta.
 *
 * @param pieces  Piezas del fuente.
 * @param layout  Donde cayo cada una al emitirla sin juntar.
 * @param options Ajustes del estandar.
 * @param breaks  [in,out] donde se anotan los saltos que hay que quitar.
 */
void join_single_statement(const std::vector<Piece> &pieces,
                           const Layout &layout, const FormatOptions &options,
                           std::vector<Break> &breaks) {
    const auto kind = [&pieces](size_t i) {
        return static_cast<TokenKind>(pieces[i].kind);
    };
    for (size_t i = 0; i + 1 < pieces.size(); ++i) {
        // Un cuerpo sin llaves empieza tras el `)` de la cabecera...
        if (kind(i) != TokenKind::RPAREN) continue;
        const size_t body = i + 1;
        if (kind(body) == TokenKind::LBRACE) continue;     // lleva llaves
        if (layout.line[body] == layout.line[i]) continue; // ya esta junto
        // ...y esa cabecera tiene que ser de `if`, `for` o `while`.
        int depth = 0;
        size_t open = i;
        while (open > 0) {
            if (kind(open) == TokenKind::RPAREN)
                ++depth;
            else if (kind(open) == TokenKind::LPAREN && --depth == 0)
                break;
            --open;
        }
        if (open == 0 || depth != 0) continue;
        const TokenKind head = kind(open - 1);
        if (head != TokenKind::KW_IF && head != TokenKind::KW_FOR &&
            head != TokenKind::KW_WHILE)
            continue;

        // El cuerpo llega hasta su `;`, y tiene que ser UNA sentencia sola.
        size_t end = body;
        int d = 0;
        bool ok = true;
        while (end < pieces.size()) {
            const TokenKind k = kind(end);
            if (k == TokenKind::LBRACE || k == TokenKind::RBRACE) {
                ok = false;
                break;
            }
            if (k == TokenKind::LPAREN || k == TokenKind::LBRACKET)
                ++d;
            else if (k == TokenKind::RPAREN || k == TokenKind::RBRACKET)
                --d;
            else if (k == TokenKind::SEMICOLON && d == 0)
                break;
            ++end;
        }
        if (!ok || end >= pieces.size()) continue;

        // Y tiene que caber: la columna donde acaba la cabecera mas el cuerpo.
        uint32_t ancho =
            layout.column[i] + display_width(pieces[i].text, options.tab_width);
        for (size_t k = body; k <= end; ++k)
            ancho += display_width(pieces[k].text, options.tab_width) + 1;
        if (ancho > options.width) continue;

        /* Un comentario por medio lo impide, por lo mismo que en `try_join`:
         * un `//` se comeria la sentencia entera. */
        bool comentado = false;
        for (size_t k = body; k <= end && !comentado; ++k)
            comentado = pieces[k].trivia.find('/') != std::string_view::npos;
        if (comentado) continue;

        for (size_t k = body; k <= end; ++k)
            if (layout.line[k] != layout.line[k - 1]) breaks[k].join = true;
    }
}

/**
 * @brief `R12`/`R95`: una lista partida A MEDIAS se reparte del todo.
 *
 * El reparto normal solo mira las lineas que NO caben, y ahi se le escapa este
 * caso: una lista que alguien dejo con dos elementos arriba y el resto abajo.
 * Ninguna de sus lineas se pasa de ochenta -- por eso el reparto no entra -- y
 * juntarla tampoco cabe -- por eso `try_join` no la toca --, asi que se
 * quedaba en el estado intermedio para siempre.
 *
 * Y es justo el estado que `R12` prohibe: es el que produce diffs ilegibles,
 * porque anadir un elemento reordena las lineas de alrededor.  O todo junto, o
 * uno por linea.
 *
 * @param pieces  Piezas del fuente.
 * @param layout  Donde cayo cada una.
 * @param breaks  [in,out] donde se anotan los cortes.
 */
void split_half_wrapped(const std::vector<Piece> &pieces, const Layout &layout,
                        std::vector<Break> &breaks) {
    for (size_t i = 0; i < pieces.size(); ++i) {
        /* Solo los parentesis de una ANOTACION.
         *
         * En una lista corriente, donde partio quien escribe puede tener un
         * motivo (`R15`), y rehacerlo empeoraba mas de lo que arreglaba: una
         * llamada partida a mano acababa con los argumentos peor repartidos
         * que como estaban.  Un contrato no: lo que lleva dentro son pares
         * `etiqueta: valor` que se leen en columna (`R112`), y ahi el estado
         * intermedio no ayuda a nadie. */
        const TokenKind k = kind_of(pieces[i]);
        if (k != TokenKind::LPAREN) continue;
        if (i < 2 || kind_of(pieces[i - 1]) != TokenKind::IDENTIFIER ||
            kind_of(pieces[i - 2]) != TokenKind::AT)
            continue;

        // Buscar el cierre de esta lista.
        int depth = 0;
        size_t close = 0;
        for (size_t j = i; j < pieces.size(); ++j) {
            const TokenKind kj = kind_of(pieces[j]);
            if (kj == TokenKind::LPAREN || kj == TokenKind::LBRACKET)
                ++depth;
            else if (kj == TokenKind::RPAREN || kj == TokenKind::RBRACKET) {
                if (--depth == 0) {
                    close = j;
                    break;
                }
            }
        }
        if (close == 0) continue;
        // Solo las que YA estan repartidas: si cabe en una linea, de eso se
        // encarga `try_join`.
        if (layout.line[close] == layout.line[i]) continue;

        /* Donde empieza cada elemento, y si dos comparten linea.  Un elemento
         * empieza tras la apertura y tras cada coma del nivel exterior. */
        std::vector<size_t> starts;
        starts.push_back(i + 1);
        int d = 0;
        for (size_t j = i + 1; j < close; ++j) {
            const TokenKind kj = kind_of(pieces[j]);
            if (opens_list(kj))
                ++d;
            else if (closes_list(kj))
                --d;
            else if (d == 0 && kj == TokenKind::COMMA && j + 1 < close)
                starts.push_back(j + 1);
        }
        if (starts.size() < 2) continue;

        bool a_medias = false;
        for (size_t e = 1; e < starts.size() && !a_medias; ++e)
            a_medias = layout.line[starts[e]] == layout.line[starts[e - 1]];
        if (!a_medias) continue;

        /* Repartida a medias: se JUNTA, y del reparto se encarga el camino
         * normal en la vuelta siguiente.
         *
         * Repartirla aqui seria tener dos caminos que producen la misma forma,
         * y no la producian igual: la indentacion salia de un sitio distinto y
         * el fichero cambiaba entre dos pasadas.  Juntando, la lista pasa a no
         * caber -- que es lo que era -- y la reparte quien ya sabe hacerlo.
         * Por eso el reparto corre en punto fijo. */
        for (size_t j = i + 1; j <= close; ++j)
            if (layout.line[j] != layout.line[j - 1]) breaks[j].join = true;
        i = close;
    }
}

} // namespace

std::vector<Break> compute_breaks(const std::vector<Piece> &pieces,
                                  const Layout &layout,
                                  const FormatOptions &options) {
    std::vector<Break> breaks(pieces.size());
    if (pieces.empty() || layout.line.size() != pieces.size()) return breaks;

    join_single_statement(pieces, layout, options, breaks);
    split_half_wrapped(pieces, layout, breaks);

    // Partir las piezas en lineas logicas, como hace la alineacion.
    for (size_t i = 0; i < pieces.size();) {
        const uint32_t ln = layout.line[i];
        size_t last = i;
        while (last + 1 < pieces.size() && layout.line[last + 1] == ln)
            ++last;

        /* `R72`: una ANOTACION va en su propia linea, encima de lo que anota.
         *
         *     @overlay
         *     struct PeImage {
         *
         * Y solo la que ABRE la linea: el `@offset(...)` de un campo va en
         * medio de su declaracion y forma parte de ella (`R76`), asi que
         * romperlo ahi partiria el campo por la mitad. */
        if (kind_of(pieces[i]) == TokenKind::AT && i + 1 <= last) {
            size_t after = i + 1; // el nombre de la anotacion
            if (after + 1 <= last &&
                kind_of(pieces[after + 1]) == TokenKind::LPAREN) {
                // Saltar sus argumentos.
                int d = 0;
                size_t k = after + 1;
                for (; k <= last; ++k) {
                    if (kind_of(pieces[k]) == TokenKind::LPAREN)
                        ++d;
                    else if (kind_of(pieces[k]) == TokenKind::RPAREN &&
                             --d == 0)
                        break;
                }
                after = k;
            }
            if (after + 1 <= last) breaks[after + 1].before = true;
        }

        // Ancho real de la linea, en columnas de pantalla.
        const uint32_t width =
            layout.column[last] +
            display_width(pieces[last].text, options.tab_width);
        if (width <= options.width) {
            /* Cabe.  Pero puede que esta linea sea el PRINCIPIO de una lista
             * que alguien partio a mano y que cabria entera: entonces hay que
             * juntarla (`R12` en su otra direccion).  Sin esto, un
             * `sumar(i32 a, i32 b)` repartido en cuatro lineas se quedaria
             * repartido, y el mismo programa tendria dos formas. */
            try_join(pieces, layout, options, i, last, breaks);
            i = last + 1;
            continue;
        }

        /* `R94`: si la linea es una CADENA DE LLAMADAS, se reparte por sus
         * eslabones antes que por sus listas.
         *
         * Es la excepcion a `R15`, y mira hacia adelante: cuando Vesta tenga
         * UFCS (`f(x, y)` escrito `x.f(y)`), encadenar sera la forma normal de
         * trabajar sobre un valor.  El punto va al PRINCIPIO de cada linea, no
         * al final de la anterior: asi cada una empieza diciendo QUE hace y se
         * leen en columna.
         *
         * `R96`: con un solo eslabon no hay cadena que repartir -- lo que se
         * reparte son sus ARGUMENTOS --, asi que hacen falta dos o mas. */
        {
            std::vector<size_t> eslabones;
            int d = 0;
            bool hay_llaves = false;
            for (size_t k = i; k <= last; ++k) {
                const TokenKind kind = kind_of(pieces[k]);
                /* Una cadena es una EXPRESION.  Si en la linea hay llaves, lo
                 * que hay son sentencias -- varias, incluso -- y el punto que
                 * se vea pertenece a una de ellas, no a una cadena que abarque
                 * la linea entera. */
                if (kind == TokenKind::LBRACE || kind == TokenKind::RBRACE)
                    hay_llaves = true;
                if (opens_list(kind))
                    ++d;
                else if (closes_list(kind))
                    --d;
                else if (d == 0 && kind == TokenKind::DOT && k > i &&
                         k + 2 <= last &&
                         kind_of(pieces[k + 1]) == TokenKind::IDENTIFIER &&
                         kind_of(pieces[k + 2]) == TokenKind::LPAREN)
                    eslabones.push_back(k);
            }
            if (eslabones.size() >= 2 && !hay_llaves) {
                // `R95`: o todos, o ninguno.  Nunca dos arriba y el resto
                // abajo, que es el reparto que produce diffs ilegibles.
                for (const size_t k : eslabones) {
                    breaks[k].before = true;
                    breaks[k].extra_indent = 1;
                }
                i = last + 1;
                continue;
            }
        }

        /* No cabe.  Se recogen TODAS las listas del nivel exterior y se elige
         * la primera que sirva para partir.
         *
         * Mirar solo la primera y rendirse era el fallo: en
         * `Section S[n] @offset(...) stride(40);` la primera es el `[n]` del
         * array, que no tiene por donde cortarse, y la buena -- el parentesis
         * del `@offset` -- viene despues.  Con una sola candidata esa linea se
         * quedaba larga para siempre. */
        std::vector<std::pair<size_t, size_t>> candidatas;
        int depth = 0;
        size_t open_at = 0;
        for (size_t k = i; k <= last; ++k) {
            const TokenKind kind = kind_of(pieces[k]);
            if (opens_list(kind)) {
                if (depth == 0) open_at = k;
                ++depth;
            } else if (closes_list(kind)) {
                if (--depth == 0) candidatas.push_back({open_at, k});
            }
        }

        size_t open = 0, close = 0;
        bool found = false;
        for (const auto &c : candidatas) {
            if (c.second <= c.first + 1) continue; // vacia: nada que repartir
            // Comas del nivel exterior de ESTA lista.
            bool has_comma = false;
            int d = 0;
            for (size_t k = c.first + 1; k < c.second; ++k) {
                const TokenKind kind = kind_of(pieces[k]);
                if (opens_list(kind))
                    ++d;
                else if (closes_list(kind))
                    --d;
                else if (d == 0 && kind == TokenKind::COMMA)
                    has_comma = true;
            }
            /* Sin comas no hay por donde partir sin inventar un criterio
             * (`R15`), con UNA excepcion: los parentesis de una anotacion.
             *
             *     Section Sections[n] @offset(
             *         e_lfanew + 24 + opt_size
             *     ) stride(40);
             *
             * Ahi dentro va una expresion, no una lista, pero es el unico sitio
             * por donde esa linea se acorta sin tocar la logica: el campo, su
             * tipo y su `stride` tienen que seguir juntos para leerse.  La
             * condicion de un `if` NO entra: ahi el salto lo pone quien
             * escribe. */
            const bool anotacion =
                c.first >= 2 && kind_of(pieces[c.first]) == TokenKind::LPAREN &&
                kind_of(pieces[c.first - 2]) == TokenKind::AT;
            if (!has_comma && !anotacion) continue;
            open = c.first;
            close = c.second;
            found = true;
            break;
        }
        if (!found) {
            i = last + 1;
            continue;
        }

        /* `R112`: una ANOTACION se reparte de otra manera.
         *
         * Un contrato es una lista de datos, no de sentencias: `@complexity`
         * con cuatro campos no gana nada ocupando seis lineas, y ademas separa
         * la funcion de su firma.  Se llenan lineas hasta las 80 y la
         * continuacion se alinea con el primer argumento, que es donde el ojo
         * ya esta leyendo:
         *
         *     @complexity(partial_pre: O(1), partial_post: O(1),
         *                 total_pre: O(n), total_post: O(n))
         *
         * El resto de listas siguen con `R12` -- uno por linea --, que es lo
         * que se acordo para argumentos y parametros. */
        /* `R12`: TODOS los elementos, uno por linea.  Se corta tras la
         * apertura, tras cada coma del nivel exterior, y antes del cierre. */
        breaks[open + 1].before = true;
        // Sin `extra_indent`: dentro de una lista la sangria la da la
        // ESTRUCTURA -- la pila de parentesis abiertos --, y pedirla tambien
        // aqui la sumaba dos veces y rompia la idempotencia.
        depth = 0;
        for (size_t k = open + 1; k < close; ++k) {
            const TokenKind kind = kind_of(pieces[k]);
            if (opens_list(kind)) {
                ++depth;
            } else if (closes_list(kind)) {
                --depth;
            } else if (depth == 0 && kind == TokenKind::COMMA &&
                       k + 1 < close) {
                breaks[k + 1].before = true;
            }
        }
        // El cierre vuelve al nivel de quien abrio, como una llave (`R5`).
        breaks[close].before = true;

        i = last + 1;
    }
    return breaks;
}

} // namespace fmt
} // namespace vx
