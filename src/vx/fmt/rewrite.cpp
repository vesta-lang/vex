/**
 * @file rewrite.cpp
 * @brief Las reglas que cambian TOKENS, no solo espacio (`R29`, `R42`, `R74`).
 *
 * Todo lo demas del formateador mueve blancos.  Estas tres no: funden dos
 * tokens en uno, quitan un par vacio o intercambian dos palabras.  Ninguna
 * cambia el programa -- se comprobo ejecutando las dos formas y comparando el
 * resultado --, pero `P2` no puede verlo por si mismo, porque compara la lista
 * de tokens y esa lista cambia.
 *
 * Por eso cada una DECLARA lo que hace: deja un @c Rewrite anclado al token
 * del original donde ocurre, y la comprobacion de `fmt.cpp` exige que la
 * diferencia entre el antes y el despues sea exactamente esa.  Una diferencia
 * que nadie declaro sigue siendo un fallo.  Asi se abren solo las puertas
 * medidas una a una, y la red se queda igual de fina para todo lo demas.
 */

#include "vx/fmt/fmt_internal.h"

#include "vx/token.h"

namespace vx {
namespace fmt {
namespace {

/**
 * @brief Orden canonico de un modificador (`R42`): acceso, `static`, `final`.
 *
 * El acceso primero porque es lo que se busca al leer una clase por encima;
 * `static` despues, que dice si hace falta una instancia; y `final` al lado
 * del tipo, que es a lo que se refiere.
 *
 * @param k Categoria del token.
 * @return Su puesto, o cero si no es un modificador.
 */
int modifier_rank(TokenKind k) {
    switch (k) {
    case TokenKind::KW_PUBLIC:
    case TokenKind::KW_PRIVATE:
    case TokenKind::KW_PROTECTED: return 1;
    case TokenKind::KW_STATIC: return 2;
    case TokenKind::KW_FINAL: return 3;
    case TokenKind::KW_CONST: return 4;
    default: return 0;
    }
}

} // namespace

std::vector<Rewrite> apply_token_rules(std::vector<Piece> &pieces) {
    std::vector<Rewrite> hechas;
    /* Los papeles dicen cual de los dos `>` cierra un generico y cual compara.
     * Sin ellos habria que fiarse de que no hubiera un espacio por medio, que
     * es justo el caso que `R29` viene a arreglar. */
    const std::vector<Role> roles = annotate_roles(pieces);

    for (size_t i = 0; i < pieces.size(); ++i) {
        if (pieces[i].drop) continue;

        /* `R74`: una anotacion sin argumentos se escribe sin parentesis.
         *
         * `@Override()` y `@Override` son la misma anotacion -- comprobado
         * ejecutando las dos --, y los parentesis vacios solo anaden ruido en
         * la linea que mas se lee de un metodo. */
        if (kind_of(pieces[i]) == TokenKind::LPAREN && i >= 2 &&
            i + 1 < pieces.size() &&
            kind_of(pieces[i + 1]) == TokenKind::RPAREN &&
            kind_of(pieces[i - 1]) == TokenKind::IDENTIFIER &&
            kind_of(pieces[i - 2]) == TokenKind::AT) {
            pieces[i].drop = true;
            pieces[i + 1].drop = true;
            hechas.push_back({RewriteKind::DropEmptyParens, pieces[i].offset});
            ++i;
            continue;
        }

        /* `R29`: dos `>` que cierran genericos anidados se escriben `>>`.
         *
         * El lenguaje acepta las dos formas -- el parser parte el `>>` cuando
         * toca --, y `Caja<Caja<i64>>` es como se escribe en cualquier sitio.
         * Solo cuando el anotador marco los dos como cierre de tipo: dos `>`
         * de comparacion seguidos no existen, pero mas vale no fiarse. */
        if (kind_of(pieces[i]) == TokenKind::GT && i + 1 < pieces.size() &&
            kind_of(pieces[i + 1]) == TokenKind::GT &&
            roles[i] == Role::TightLeft && roles[i + 1] == Role::TightLeft) {
            pieces[i].glued = ">>";
            pieces[i + 1].drop = true;
            hechas.push_back({RewriteKind::GlueGenericClose, pieces[i].offset});
            ++i;
            continue;
        }

        /* `R42`: los modificadores van en orden -- acceso, `static`, `final`.
         *
         * Se ordenan por intercambios de vecinos, y cada intercambio se
         * declara: asi la comprobacion los sigue uno a uno en vez de tener que
         * entender la ordenacion entera. */
        if (is_modifier(kind_of(pieces[i])) && i + 1 < pieces.size() &&
            is_modifier(kind_of(pieces[i + 1]))) {
            const int a = modifier_rank(kind_of(pieces[i]));
            const int b = modifier_rank(kind_of(pieces[i + 1]));
            if (a > b) {
                // Se intercambia lo que ES cada pieza, no su hueco: la trivia
                // que las precede pertenece a la linea, no a la palabra.
                std::swap(pieces[i].kind, pieces[i + 1].kind);
                std::swap(pieces[i].text, pieces[i + 1].text);
                hechas.push_back(
                    {RewriteKind::SwapModifiers, pieces[i].offset});
            }
        }
    }
    return hechas;
}

} // namespace fmt
} // namespace vx
