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
 * @file align.cpp
 * @brief Las columnas: `R83`-`R88`.
 *
 * Vesta alinea, y es la diferencia mas visible respecto a Go y a Rust:
 *
 *     u8             contador = 0;
 *     i32            total    = 0;
 *     unique<Buffer> datos    = unique_box(buffer(4096));
 *
 * La regla es simple de decir y de hacer: las lineas CONSECUTIVAS que estan al
 * mismo nivel y tienen la misma FORMA se agrupan, y cada campo del grupo se
 * estira hasta el mas largo (`R83`, `R84`).  El bloque se rompe con una linea
 * en blanco, un comentario suelto o una linea de otra forma -- que es lo que
 * deja el control en manos de quien escribe: para que dos cosas no se alineen,
 * se separan con una linea en blanco.
 *
 * DOS FRENOS, y los dos importan:
 *
 *   - `R86`: si alinear empujara alguna linea por encima de las 80 columnas, el
 *     bloque NO se alinea.  Un nombre larguisimo no puede sacar a sus vecinos
 *     fuera del limite.
 *   - Se mide en COLUMNAS DE PANTALLA (@ref display_width), no en bytes: un
 *     comentario en chino desalinearia la columna entera si se contaran bytes.
 *
 * Y el coste, que esta medido y dicho en el estandar: alinear al mas largo hace
 * que la forma de una linea dependa de sus vecinas, asi que anadir un campo
 * largo reescribe el bloque.  Ocurre en el 48% de las altas sobre el corpus.
 * Se acepta a cambio de que el codigo se lea como una tabla; `git blame -w` y
 * `git diff -w` descuentan ese ruido, que por construccion es solo espacio.
 */

#include "vx/fmt/fmt_internal.h"

#include "vx/fmt/width.h"
#include "vx/token.h"

#include <algorithm>

namespace vx {
namespace fmt {
namespace {

/**
 * @brief La forma de una linea, para saber con cuales se puede alinear.
 *
 * `R87`: solo comparten columnas las lineas con los MISMOS campos.  Un
 * `typedef u32 Edad;` y un `using MyInt = i64;` no tienen la misma estructura
 * -- uno es `tipo nombre` y el otro `nombre = tipo` --, asi que forman bloques
 * distintos aunque esten pegados.
 */
enum class Shape : uint8_t {
    None,     ///< no se alinea con nadie
    Decl,     ///< `[mod] TIPO NOMBRE = valor;`
    Assign,   ///< `algo = valor;` sin tipo delante
    Overlay,  ///< `TIPO NOMBRE @offset;` -- campo de una vista
    BitField, ///< `TIPO NOMBRE : bits;` -- campo de bits
    TableRow, ///< una FILA de valores dentro de un `{ ... }` de inicializacion
    Label,    ///< `etiqueta: valor,` dentro de una anotacion (`R112`)
    Case,     ///< `case <patron> => <cuerpo>` de un `match` (`R113`)
    Trailing  ///< una expresion partida cuyas lineas ACABAN en el operador
};

/// Una linea reducida a lo que hace falta para alinearla.
struct Line {
    Shape shape = Shape::None;
    uint32_t level = 0;
    /// Indices de las piezas donde empieza cada campo que se alinea.
    std::vector<size_t> anchors;
    /// Ultima pieza de la linea, para saber cuanto mide entera.
    size_t last = 0;
    /**
     * Cierto si los campos se alinean por su FINAL y no por su principio.
     *
     * Es como se leen los numeros: con las unidades en la misma columna.  Una
     * tabla de valores con `1`, `40` y `600` alineados por la izquierda no se
     * puede comparar de un vistazo; alineados por la derecha, si.
     */
    bool right = false;
    /// Pieza donde empieza el valor, si es un literal numerico (`R111`).  Cero
    /// si el valor es otra cosa: una llamada no tiene signo que alinear.
    size_t value = 0;
    /// Cierto si ese valor lleva un `-` delante.
    bool value_signed = false;
};

/**
 * @brief Reduce una linea a su forma y sus puntos de alineacion.
 *
 * @param pieces Piezas del fuente.
 * @param from   Primera pieza de la linea.
 * @param to     Ultima pieza de la linea (inclusive).
 * @return La linea clasificada.
 */
/**
 * @brief Indica si el token es un VALOR suelto de una tabla.
 * @param k Categoria del token.
 * @return Cierto si puede ser un elemento de una lista de valores.
 */
bool is_value(TokenKind k) {
    switch (k) {
    case TokenKind::INT_LIT:
    case TokenKind::FLOAT_LIT:
    case TokenKind::CHAR_LIT:
    case TokenKind::STRING_LIT:
    case TokenKind::TRUE_KW:
    case TokenKind::FALSE_KW:
    case TokenKind::NULL_KW:
    case TokenKind::IDENTIFIER:
    case TokenKind::MINUS: return true;
    default: return false;
    }
}

Line classify(const std::vector<Piece> &pieces, size_t from, size_t to,
              bool in_table, bool in_annotation) {
    Line line;
    line.last = to;

    /* Una FILA de una tabla de valores.
     *
     *     i64 mat[9] = {
     *           1,   2,   3,
     *          40,   5, 600,
     *           7,   8,   9
     *     };
     *
     * Las filas las decidio quien escribio -- son la forma de la tabla, y
     * ninguna regla de ancho sabe mejor que el como se agrupan sus datos --,
     * pero las COLUMNAS son cosa del formateador.  Y se alinean por la derecha,
     * que es como se leen los numeros: con las unidades en la misma columna.
     *
     * Se reconoce por estar dentro de un `{ ... }` de inicializacion y constar
     * solo de valores y comas: nada de llamadas ni de expresiones, donde la
     * columna no significaria nada. */
    if (in_table) {
        std::vector<size_t> cols;
        bool solo_valores = true;
        for (size_t k = from; k <= to; ++k) {
            const TokenKind kind = kind_of(pieces[k]);
            if (kind == TokenKind::COMMA) continue;
            if (!is_value(kind)) {
                solo_valores = false;
                break;
            }
            // Un signo va pegado a su numero: cuenta como un solo campo.
            if (kind == TokenKind::MINUS) continue;
            cols.push_back(k);
        }
        /* Y NO se alinea si la fila lleva COMENTARIOS.
         *
         * Un array de datos con comentarios no es una tabla de numeros: es una
         * EXPLICACION.  Los opcodes de un trozo de codigo maquina, una tabla de
         * saltos, una cabecera binaria -- ahi los valores se agrupan y se
         * comentan a mano para que se entienda que hace cada tramo, y las
         * columnas las decidio quien lo escribio.  Moverlas rompe justo lo que
         * el comentario estaba explicando.
         *
         *     u8 code[] = {
         *         0x48, 0x89, 0xE5,        // mov rbp, rsp
         *         0x48, 0x83, 0xEC, 0x20,  // sub rsp, 32
         *         0xC3                     // ret
         *     };
         *
         * Se mira tambien la trivia de la pieza SIGUIENTE, porque el comentario
         * de fin de linea vive ahi: entre el ultimo token de esta fila y el
         * primero de la que viene. */
        bool con_comentario = false;
        for (size_t k = from; k <= to + 1 && k < pieces.size(); ++k)
            if (pieces[k].trivia.find('/') != std::string_view::npos)
                con_comentario = true;

        if (solo_valores && !con_comentario && cols.size() >= 2) {
            line.shape = Shape::TableRow;
            line.anchors = std::move(cols);
            line.right = true;
            return line;
        }
    }

    /* `R113`: las ramas de un `match` se alinean por su `=>`.
     *
     * Un `match` es una TABLA: a la izquierda lo que se reconoce, a la derecha
     * lo que se hace.  Con las flechas en columna las dos mitades se leen por
     * separado, y un patron mas corto que los demas -- el `_` del final suele
     * serlo -- deja de romper la vertical.
     *
     * Se busca el `=>` del nivel exterior: el de una lambda dentro del cuerpo
     * de la rama esta mas adentro y no cuenta. */
    if (kind_of(pieces[from]) == TokenKind::KW_CASE) {
        int d = 0;
        for (size_t k = from + 1; k <= to; ++k) {
            const TokenKind kk = kind_of(pieces[k]);
            if (kk == TokenKind::LPAREN || kk == TokenKind::LBRACKET)
                ++d;
            else if (kk == TokenKind::RPAREN || kk == TokenKind::RBRACKET)
                --d;
            else if (d == 0 && kk == TokenKind::FAT_ARROW) {
                line.shape = Shape::Case;
                line.anchors = {k}; // el `=>`
                return line;
            }
        }
    }

    /* `R112`: `etiqueta: valor` dentro de una anotacion.
     *
     * Un contrato repartido es una tabla de dos columnas, y se lee como tal:
     *
     *     @complexity(
     *         partial_pre:  O(1),
     *         partial_post: O(1),
     *         total_pre:    O(n),
     *         total_post:   O(n)
     *     )
     *
     * Se reconoce por estar dentro de los parentesis de una anotacion y
     * empezar por un nombre y unos dos puntos.  El `:` de un campo de bits no
     * se confunde: aquel va detras de un TIPO y un nombre, y este abre la
     * linea. */
    if (in_annotation && from + 2 <= to &&
        kind_of(pieces[from]) == TokenKind::IDENTIFIER &&
        kind_of(pieces[from + 1]) == TokenKind::COLON) {
        line.shape = Shape::Label;
        line.anchors = {from, from + 2}; // etiqueta, valor
        return line;
    }

    /* Solo se alinean SENTENCIAS ENTERAS.  Una linea que acaba en `{`, o que
     * es parte de una expresion partida, no tiene columnas que cuadrar con
     * nadie.
     *
     * Acaban en `;` o `,` ... salvo la ULTIMA de una lista, que no lleva coma
     * porque `R13` no la admite.  Sin contarla, el ultimo valor de todo enum
     * se quedaba fuera de la columna que compartian sus hermanos -- y era
     * justo el que mas cantaba, por ser el que cierra el bloque. */
    const TokenKind end = kind_of(pieces[to]);

    /* Una expresion partida DEJANDO el operador al final de cada linea.
     *
     * Es como se escribe una mascara de bits larga, y los operadores puestos
     * en columna son lo que deja ver que la lista esta completa -- falta uno y
     * salta a la vista --.  Sin alinearlos, cada `|` queda pegado a su operando
     * y la lista se convierte en un parrafo.
     *
     * Se reconoce por la forma: la linea acaba en un operador, asi que lo que
     * hay es media expresion y la otra mitad viene debajo. */
    switch (end) {
    case TokenKind::PIPE:
    case TokenKind::AMP:
    case TokenKind::CARET:
    case TokenKind::PLUS:
    case TokenKind::MINUS:
    case TokenKind::STAR:
    case TokenKind::SLASH:
    case TokenKind::PERCENT:
    case TokenKind::OR_OR:
    case TokenKind::AND_AND:
    case TokenKind::SHL:
    case TokenKind::SHR:
        if (to > from) {
            line.shape = Shape::Trailing;
            line.anchors = {to}; // el operador, que es lo que va en columna
            return line;
        }
        break;
    default: break;
    }

    const bool cierra_lista = to + 1 < pieces.size() &&
                              (kind_of(pieces[to + 1]) == TokenKind::RBRACE ||
                               kind_of(pieces[to + 1]) == TokenKind::RPAREN ||
                               kind_of(pieces[to + 1]) == TokenKind::RBRACKET);
    if (end != TokenKind::SEMICOLON && end != TokenKind::COMMA && !cierra_lista)
        return line;

    // Saltar los modificadores: son un campo aparte que puede faltar (`R84`).
    size_t i = from;
    while (i <= to && precedes_type(kind_of(pieces[i])))
        ++i;

    /* Un campo de BITS lleva su anchura tras dos puntos:
     *
     *     u32 a    : 3;
     *     u32 rest : 16;
     *
     * Se alinea por el `:` porque lo que se compara de un vistazo es cuantos
     * bits ocupa cada campo y si suman lo que tienen que sumar.  La forma es
     * inconfundible -- tipo, nombre, dos puntos, un entero y punto y coma --,
     * asi que no se cruza con los otros seis usos de los dos puntos. */
    if (to >= i + 4 && kind_of(pieces[to]) == TokenKind::SEMICOLON &&
        kind_of(pieces[to - 1]) == TokenKind::INT_LIT &&
        kind_of(pieces[to - 2]) == TokenKind::COLON &&
        kind_of(pieces[to - 3]) == TokenKind::IDENTIFIER) {
        line.shape = Shape::BitField;
        line.anchors = {i, to - 3, to - 2}; // tipo, nombre, `:`
        return line;
    }

    /* Un campo de un `@overlay struct` no lleva `=`: lleva su DESPLAZAMIENTO.
     *
     *     u16 e_magic  @0x00;
     *     i32 e_lfanew @0x3C;
     *
     * Ahi el `@` es el ancla, y alinearlo importa mas que en otros sitios: una
     * vista describe la disposicion de un formato binario, y los offsets en
     * columna son justo lo que se lee para comprobarla contra la
     * especificacion.
     *
     * El `@` de una ANOTACION no se confunde con este: aquel abre la linea y
     * este va detras de un nombre que va detras de un tipo. */
    for (size_t k = i + 1; k < to; ++k) {
        if (kind_of(pieces[k]) != TokenKind::AT) continue;
        if (k <= i + 1) break; // no hay sitio para tipo Y nombre delante
        if (kind_of(pieces[k - 1]) != TokenKind::IDENTIFIER) break;
        line.shape = Shape::Overlay;
        line.anchors = {i, k - 1, k}; // tipo, nombre, `@`
        return line;
    }

    /* Buscar el `=` de la linea, que es el ancla principal.
     *
     * Tiene que ser el de la SENTENCIA: uno dentro de parentesis o corchetes
     * pertenece a otra cosa (`f(a = 1)`), y anclar ahi alinearia por un sitio
     * que no significa nada. */
    size_t assign = 0;
    bool found = false;
    int prof = 0;
    for (size_t k = i; k <= to; ++k) {
        const TokenKind kk = kind_of(pieces[k]);
        if (kk == TokenKind::LPAREN || kk == TokenKind::LBRACKET)
            ++prof;
        else if (kk == TokenKind::RPAREN || kk == TokenKind::RBRACKET)
            --prof;
        else if (kk == TokenKind::ASSIGN && prof == 0) {
            assign = k;
            found = true;
            break;
        }
    }
    /* Una declaracion SIN valor inicial sigue siendo una declaracion.
     *
     * `T val;` no tiene `=`, asi que se caia del reparto y no se alineaba con
     * el `u8 tag = 0x07;` de al lado, aunque los dos son campos del mismo
     * struct y sus dos primeras columnas son las mismas.  Se le dan sus dos
     * anclas -- tipo y nombre -- y el bloque alinea lo que tengan en comun. */
    if (!found) {
        if (to < i + 1) return line;
        if (kind_of(pieces[to]) != TokenKind::SEMICOLON) return line;
        const size_t solo = to - 1;
        if (solo <= i) return line; // `x;` no declara nada
        if (kind_of(pieces[solo]) != TokenKind::IDENTIFIER) return line;
        /* Y lo de delante tiene que poder ser un TIPO.  `return *local;` tiene
         * la misma forma -- palabra, nombre, `;` -- y se colaba como
         * declaracion: entonces `return` hacia de tipo y se alineaba en
         * columna con los `i64*` de al lado, separando el `return` de lo que
         * devuelve. */
        const TokenKind primero = kind_of(pieces[i]);
        if (primero != TokenKind::IDENTIFIER && !is_type_keyword(primero))
            return line;
        line.shape = Shape::Decl;
        /* Las MISMAS columnas que la que si lleva `=`, menos la del `=`:
         * calificadores, tipo y nombre.
         *
         * Tienen que corresponderse una a una porque las dos formas se agrupan
         * juntas -- un `T val;` se alinea con el `u8 tag = 0;` de al lado --, y
         * el reparto alinea la columna k de cada linea con la k de las demas.
         * Si aqui hubiera una columna menos, la k-esima de una seria el nombre
         * y la de la otra el tipo, y el bloque se descuadraria entero. */
        const size_t tipo = skip_decl_qualifiers(pieces, i);
        line.anchors = {i, tipo, solo}; // calificadores, tipo, nombre
        return line;
    }

    /* El NOMBRE es la pieza justo antes del `=`.  Si entre el principio y el
     * nombre hay algo mas, eso es el TIPO y la linea es una declaracion; si no,
     * es una asignacion a secas. */
    if (assign == 0 || assign - 1 < i) return line;
    const size_t name = assign - 1;
    /* Si lo de delante del `=` no es un nombre, sigue siendo una asignacion:
     * `*(u32*)(buf + 0) = 0xCAFE;` acaba en `)`.  Lo que hay a la izquierda es
     * un lvalue entero y se alinea por donde EMPIEZA, no partido en columnas.
     *
     * Antes se descartaba la linea entera, asi que un bloque de escrituras por
     * puntero -- que es justo donde importa ver los desplazamientos en
     * columna -- no se alineaba nunca. */
    if (kind_of(pieces[name]) != TokenKind::IDENTIFIER) {
        line.shape = Shape::Assign;
        line.anchors = {i, assign};
        return line;
    }

    /* Salvo que haya un PUNTO de por medio: entonces la izquierda es un acceso
     * a campo -- `c.handle = ...` -- y no un `TIPO NOMBRE`.
     *
     * Sin mirarlo, `c` pasaba por tipo y `handle` por nombre, y alinearlos como
     * dos columnas PARTIA el acceso: `c.          handle      = ...`, que ya no
     * se lee como el campo de nada.  Comprobado formateando el corpus: salia en
     * 147 sitios. */
    bool qualified = false;
    for (size_t k = i; k < assign; ++k) {
        if (kind_of(pieces[k]) == TokenKind::DOT) {
            qualified = true;
            break;
        }
    }

    if (name > i && !qualified) {
        line.shape = Shape::Decl;
        /* CUATRO columnas: calificadores, tipo, nombre y `=`.
         *
         * Con tres -- los calificadores DENTRO de la columna del tipo -- el
         * tipo no quedaba a la misma altura en cuanto unas lineas del bloque
         * llevaban calificador y otras no:
         *
         *     in i64*         solo_lee = &a;      <- el `i64*` baila
         *     in nonnull i64* firme    = &a;
         *
         * Se emiten SIEMPRE las cuatro, aunque no haya calificador y la
         * primera quede vacia: el reparto agrupa lineas con el mismo numero de
         * anclas, asi que emitir tres unas veces y cuatro otras partiria en dos
         * un bloque que se lee como uno.
         *
         * Lo que evita que una linea SIN calificador salga empujada a la
         * derecha no es contar aqui, es la regla de "ningun campo se estira si
         * alguna linea lo tiene pegado al margen", que ya existia y ahora
         * pregunta por cada campo y no solo por el primero. */
        const size_t tipo = skip_decl_qualifiers(pieces, i);
        line.anchors = {i, tipo, name, assign};
    } else {
        line.shape = Shape::Assign;
        // Toda la izquierda cuenta como UN campo: `c.handle` no se parte.
        line.anchors = {i, assign};
    }

    /* `R111`: reservar la columna del SIGNO.
     *
     * Un `-` delante del valor lo corre una columna respecto a los de al lado,
     * y entonces las cifras ya no se pueden comparar de un vistazo, que es
     * para lo que estan en columna:
     *
     *     i8 minimo = -128_i8;        i8 minimo = -128_i8;
     *     i8 maximo = 127_i8;         i8 maximo =  127_i8;
     *
     * Vale para CUALQUIER valor y no solo para un literal: una funcion que
     * devuelve un numero se puede negar igual (`-suma(1, 2)`), asi que su
     * columna cuenta lo mismo.
     *
     * Se apunta aparte y NO como un campo mas para que el bloque no se parta:
     * los campos que se alinean tienen que ser los mismos en todas las lineas
     * del bloque, y esto es una sola columna que unas usan y otras no. */
    const size_t value = assign + 1;
    if (value < to) {
        const TokenKind sign = kind_of(pieces[value]);
        line.value = value;
        line.value_signed = sign == TokenKind::MINUS || sign == TokenKind::PLUS;
    }
    return line;
}

} // namespace

std::vector<uint32_t> compute_alignment(const std::vector<Piece> &pieces,
                                        const std::vector<Role> &roles,
                                        const Layout &layout,
                                        const FormatOptions &options) {
    (void)roles; // la forma sale de los tokens; el papel aqui no hace falta
    std::vector<uint32_t> pad(pieces.size(), 0);
    if (pieces.empty() || layout.line.size() != pieces.size()) return pad;

    // 1) Partir las piezas en lineas logicas.
    std::vector<std::pair<size_t, size_t>> spans; // [primera, ultima]
    for (size_t i = 0; i < pieces.size();) {
        const uint32_t ln = layout.line[i];
        size_t j = i;
        while (j + 1 < pieces.size() && layout.line[j + 1] == ln)
            ++j;
        spans.push_back({i, j});
        i = j + 1;
    }

    /* 2) Clasificar cada linea, sabiendo si cae dentro de una TABLA.
     *
     * Una tabla es un `{ ... }` que sigue a un `=`: una lista de valores, no un
     * bloque de codigo.  Se lleva la cuenta al vuelo porque la forma de una
     * fila -- valores y comas -- solo significa algo ahi dentro; en cualquier
     * otro sitio esos mismos tokens son una expresion. */
    std::vector<Line> lines;
    lines.reserve(spans.size());
    int table_depth = 0;
    int brace_depth = 0;
    int paren_depth = 0;
    int annot_at = -1;         // profundidad de parentesis de la anotacion
    std::vector<int> table_at; // profundidades de llave que son tabla
    for (const auto &sp : spans) {
        Line l = classify(pieces, sp.first, sp.second, table_depth > 0,
                          annot_at >= 0);
        l.level = layout.level[sp.first];
        lines.push_back(std::move(l));
        // Recorrer la linea para actualizar la cuenta de llaves.
        for (size_t k = sp.first; k <= sp.second; ++k) {
            const TokenKind kind = kind_of(pieces[k]);
            if (kind == TokenKind::LBRACE) {
                ++brace_depth;
                if (k > 0 && (kind_of(pieces[k - 1]) == TokenKind::ASSIGN ||
                              kind_of(pieces[k - 1]) == TokenKind::LBRACE ||
                              kind_of(pieces[k - 1]) == TokenKind::COMMA)) {
                    table_at.push_back(brace_depth);
                    ++table_depth;
                }
            } else if (kind == TokenKind::RBRACE) {
                if (!table_at.empty() && table_at.back() == brace_depth) {
                    table_at.pop_back();
                    --table_depth;
                }
                if (brace_depth > 0) --brace_depth;
            } else if (kind == TokenKind::LPAREN) {
                ++paren_depth;
                // `@Nombre(`: dentro van etiquetas, no expresiones.
                if (annot_at < 0 && k >= 2 &&
                    kind_of(pieces[k - 1]) == TokenKind::IDENTIFIER &&
                    kind_of(pieces[k - 2]) == TokenKind::AT)
                    annot_at = paren_depth;
            } else if (kind == TokenKind::RPAREN) {
                if (annot_at == paren_depth) annot_at = -1;
                if (paren_depth > 0) --paren_depth;
            }
        }
    }

    // 3) Agrupar las consecutivas de la misma forma y nivel, y alinear.
    for (size_t start = 0; start < lines.size();) {
        if (lines[start].shape == Shape::None) {
            ++start;
            continue;
        }
        size_t end = start;
        while (end + 1 < lines.size() &&
               lines[end + 1].shape == lines[start].shape &&
               lines[end + 1].level == lines[start].level &&
               /* Mismo numero de columnas... salvo entre declaraciones, donde
                * la que no tiene valor inicial trae una menos y se alinea
                * igual por las que comparten (`T val;` con `u8 tag = 0;`). */
               (lines[end + 1].anchors.size() == lines[start].anchors.size() ||
                lines[start].shape == Shape::Decl) &&
               /* Consecutivas de verdad: si el emisor dejo una linea en blanco
                * o un comentario entre medias, el bloque se rompe (`R83`).
                * Eso es lo que le da el control a quien escribe. */
               layout.line[spans[end + 1].first] ==
                   layout.line[spans[end].first] + 1)
            ++end;

        if (end > start) { // un bloque de una sola linea no se alinea con nadie
            /* Desplazamiento acumulado de cada linea.  Hace falta porque
             * rellenar el campo k CORRE todos los campos siguientes de esa
             * misma linea: sin llevar la cuenta, el segundo campo se calcula
             * sobre columnas que ya no son las que van a salir. */
            std::vector<uint32_t> shift(end - start + 1, 0);

            // Solo se alinean las columnas que TODAS tienen.
            size_t n = lines[start].anchors.size();
            for (size_t l = start; l <= end; ++l)
                if (lines[l].anchors.size() < n) n = lines[l].anchors.size();
            for (size_t k = 0; k < n; ++k) {
                /* Un campo NO se estira si alguna linea del bloque lo tiene
                 * pegado al margen.
                 *
                 * `R84` le da columna propia a los modificadores para que los
                 * tipos cuadren aunque solo algunas lineas lleven `const`.
                 * Pero cuando la que no lo lleva es la que manda, estirar ese
                 * campo mete espacios DELANTE del primer token, y entonces la
                 * linea ya no empieza donde dice su sangria:
                 *
                 *           i64          x  = 40;
                 *           nonnull i64 *p1 = &x;
                 *     const i64          a  = *p1;
                 *
                 * La sangria es lo que dice el nivel de anidamiento, y eso
                 * pesa mas que cuadrar una columna.  Los demas campos se
                 * siguen alineando: los nombres y el `=` quedan igual.
                 *
                 * La comprobacion era solo para el campo 0, y esa era una
                 * suposicion sobre la FORMA de las anclas, no sobre lo que la
                 * regla dice.  Al partir la declaracion en calificador y tipo,
                 * quien queda pegado al margen en una linea sin calificador es
                 * el campo 1 -- su ancla y el inicio de la linea son la misma
                 * pieza --, asi que el relleno volvia a entrar delante del
                 * primer token por otra puerta.  Se pregunta por CADA campo,
                 * que es lo que la regla queria decir desde el principio. */
                {
                    bool alguna_al_margen = false;
                    for (size_t l = start; l <= end && !alguna_al_margen; ++l)
                        alguna_al_margen =
                            lines[l].anchors[k] == spans[l].first;
                    if (alguna_al_margen) continue;
                }

                /* La columna del campo = la mayor de las que salen por si
                 * solas.  Alineando por la DERECHA, lo que se iguala es donde
                 * ACABA cada valor, no donde empieza: es como se leen los
                 * numeros, con las unidades en la misma columna. */
                const bool right = lines[start].right;
                uint32_t target = 0;
                for (size_t l = start; l <= end; ++l) {
                    const size_t idx = lines[l].anchors[k];
                    uint32_t col = layout.column[idx] + shift[l - start];
                    if (right)
                        col +=
                            display_width(pieces[idx].text, options.tab_width);
                    if (col > target) target = col;
                }

                /* `R86`: si estirar sacara ALGUNA linea de las 80 columnas, el
                 * campo entero se deja sin alinear.  Un nombre larguisimo no
                 * puede empujar a sus vecinos fuera del limite. */
                bool fits = true;
                for (size_t l = start; l <= end && fits; ++l) {
                    const size_t ai = lines[l].anchors[k];
                    uint32_t col = layout.column[ai] + shift[l - start];
                    if (right)
                        col +=
                            display_width(pieces[ai].text, options.tab_width);
                    const size_t last = lines[l].last;
                    const uint32_t end_col =
                        layout.column[last] + shift[l - start] +
                        display_width(pieces[last].text, options.tab_width);
                    if (end_col + (target - col) > options.width) fits = false;
                }
                if (!fits) continue;

                for (size_t l = start; l <= end; ++l) {
                    const size_t idx = lines[l].anchors[k];
                    uint32_t col = layout.column[idx] + shift[l - start];
                    if (right)
                        col +=
                            display_width(pieces[idx].text, options.tab_width);
                    // Nunca restar por debajo de cero: `target` es el maximo,
                    // pero una columna mal medida no puede convertirse en un
                    // relleno de cuatro mil millones de espacios.
                    if (col >= target) continue;
                    const uint32_t extra = target - col;
                    pad[idx] += extra;
                    shift[l - start] += extra;
                }
            }

            /* `R111`: la columna del signo.
             *
             * Va aparte de los campos porque no ES un campo: es una sola
             * columna que se reserva cuando en el bloque conviven valores con
             * signo (`-` o `+`) y sin el, para que empiecen todos igual.  Si
             * ninguno lleva signo, o si lo llevan todos, ya estan alineados y
             * no hay nada que hacer. */
            bool any_signed = false, any_bare = false;
            for (size_t l = start; l <= end; ++l) {
                if (lines[l].value == 0) continue; // no es un numero
                if (lines[l].value_signed)
                    any_signed = true;
                else
                    any_bare = true;
            }
            if (any_signed && any_bare) {
                for (size_t l = start; l <= end; ++l) {
                    if (lines[l].value == 0 || lines[l].value_signed) continue;
                    const size_t idx = lines[l].value;
                    /* `R86`: si el hueco del signo sacara la linea de las 80
                     * columnas, se deja sin alinear.  Una sola columna, pero
                     * la regla es la misma que para los campos. */
                    const size_t fin = lines[l].last;
                    const uint32_t end_col =
                        layout.column[fin] + shift[l - start] +
                        display_width(pieces[fin].text, options.tab_width);
                    if (end_col + 1 > options.width) continue;
                    pad[idx] += 1;
                    shift[l - start] += 1;
                }
            }
        }
        start = end + 1;
    }
    return pad;
}

std::vector<uint32_t>
compute_comment_alignment(const std::vector<Piece> &pieces,
                          const Layout &layout, const FormatOptions &options) {
    std::vector<uint32_t> cpad(pieces.size(), 0);
    if (layout.comment_column.size() != pieces.size() ||
        layout.comment_line.size() != pieces.size())
        return cpad;

    /* Un comentario de fin de linea "pertenece" a la linea del token ANTERIOR,
     * porque vive en la trivia del siguiente.  Se agrupan los de lineas
     * seguidas y se llevan todos a la columna del que mas lejos empieza.
     *
     * El bloque se rompe en cuanto una linea no lleva comentario, que es lo que
     * separa un grupo de otro sin tener que decir nada. */
    /* Se recogen PRIMERO todos los que hay, y luego se agrupan por lineas
     * seguidas.  Recorrer las piezas buscando la de al lado no vale: entre el
     * comentario de una linea y el de la siguiente hay todos los tokens de esa
     * linea, asi que nunca son piezas contiguas.  Con eso, el primer
     * comentario de cada grupo se quedaba siempre fuera. */
    std::vector<size_t> con_comentario;
    for (size_t i = 0; i < pieces.size(); ++i)
        if (layout.comment_column[i] > 0) con_comentario.push_back(i);

    for (size_t a = 0; a < con_comentario.size();) {
        size_t b = a;
        while (b + 1 < con_comentario.size() &&
               layout.comment_line[con_comentario[b + 1]] ==
                   layout.comment_line[con_comentario[b]] + 1)
            ++b;

        if (b > a) { // un comentario suelto no se alinea con nadie
            uint32_t target = 0;
            for (size_t k = a; k <= b; ++k)
                if (layout.comment_column[con_comentario[k]] > target)
                    target = layout.comment_column[con_comentario[k]];
            for (size_t k = a; k <= b; ++k) {
                const size_t idx = con_comentario[k];
                const uint32_t extra = target - layout.comment_column[idx];

                /* `R86` tambien aqui, y midiendo donde ACABA, no donde empieza.
                 *
                 * Mirar solo el inicio dejaba pasar el caso que importa: un
                 * comentario que ya se sale de las 80 columnas se alineaba
                 * igual, empujandolo aun mas lejos.  Lo que hay que preguntar
                 * es si la linea ENTERA sigue cabiendo despues de estirar.
                 *
                 * Y si el comentario ya se pasaba POR SI SOLO, alinearlo no lo
                 * empeora ni lo arregla: se deja como estaba, que es lo unico
                 * que no sorprende a quien lo escribio. */
                /* El ancho del COMENTARIO, no el de la trivia.
                 *
                 * La trivia trae delante los espacios que lo separaban del
                 * codigo -- incluidos los que puso la alineacion de la pasada
                 * anterior --, y contarlos hacia que el ancho creciera cada
                 * vez: la guarda cambiaba de opinion y el comentario iba y
                 * venia.  Se veia como 83 ficheros que no se estabilizaban. */
                std::string_view first = pieces[idx].trivia;
                const size_t nl = first.find('\n');
                if (nl != std::string_view::npos) first = first.substr(0, nl);
                while (!first.empty() &&
                       (first.front() == ' ' || first.front() == '\t'))
                    first.remove_prefix(1);
                const uint32_t comment_width =
                    display_width(first, options.tab_width);
                const uint32_t end_col =
                    layout.comment_column[idx] + comment_width;
                if (end_col > options.width)
                    continue; // ya se salia: no se toca
                /* Y si es ESTIRARLO lo que lo saca de las 80, se estira igual.
                 *
                 * Aqui `R20` pesa mas que `R86`: la columna es lo que hace que
                 * ocho comentarios de campo se lean como una tabla, y basta
                 * que UNO se quede atras para que deje de haber tabla -- no se
                 * gana la linea corta y se pierde la columna --.  El limite de
                 * ancho protege el CODIGO, y detras del comentario ya no viene
                 * codigo.
                 *
                 * Se veia en `vx_async.vx`: siete campos en columna y el
                 * primero pegado a su `;`, que era justo el que mas cantaba
                 * por ir arriba. */
                cpad[idx] = extra;
            }
        }
        a = b + 1;
    }
    return cpad;
}

} // namespace fmt
} // namespace vx
