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
 * @file fmt_internal.h
 * @brief Lo que comparten los modulos del formateador, y nadie mas.
 *
 * No forma parte del API: `fmt.h` es lo que ve quien lo usa.  Aqui viven las
 * piezas que se pasan entre `trivia.cpp`, `indent.cpp` y los modulos de reglas
 * que vengan despues.
 */

#ifndef VX_FMT_FMT_INTERNAL_H
#define VX_FMT_FMT_INTERNAL_H

#include "vx/fmt/fmt.h"
#include "vx/token.h" // TokenKind, que aparece en las firmas de abajo

namespace vx {
namespace fmt {

/**
 * @brief Un trozo con contenido de la trivia, con los saltos que lo preceden.
 *
 * La trivia entre dos tokens puede llevar varios comentarios y saltos
 * mezclados.  Para reindentar hace falta saber COMO estaban repartidos: si un
 * comentario iba pegado al codigo anterior (cero saltos delante) es de fin de
 * linea, y si iba tras un salto es un comentario suelto que se indenta con lo
 * que viene detras.  Confundirlos mueve los comentarios de sitio, que es la
 * forma mas rapida de que un formateador pierda la confianza de quien lo usa.
 */
struct TriviaChunk {
    /// Saltos de linea que hay antes de este trozo.
    uint32_t newlines_before = 0;
    /// El texto del comentario, sin el blanco de los extremos.  Vacio en el
    /// ultimo trozo, que solo lleva los saltos que quedan tras el final.
    std::string_view text;
};

/**
 * @brief Escribe saltos de linea respetando el tope de lineas en blanco.
 *
 * @param out   [in,out] salida.
 * @param count Saltos que habia en el original.
 * @param limit Lineas en blanco permitidas (`R7` dentro, `R8` fuera).
 * @return Cuantos saltos se escribieron.  Lo necesita la alineacion: una linea
 *         EN BLANCO rompe el bloque (`R83`), y sin contarla dos grupos
 *         separados a proposito acababan compartiendo columnas.
 */
inline uint32_t emit_newlines(std::string &out, uint32_t count,
                              uint32_t limit) {
    // `count` saltos dejan `count - 1` lineas en blanco.  Nunca menos de uno:
    // si habia salto, la linea se parte igual.
    const uint32_t max_newlines = limit + 1;
    const uint32_t n = count > max_newlines ? max_newlines : count;
    for (uint32_t i = 0; i < n; ++i)
        out.push_back('\n');
    return n;
}

/**
 * @brief Que PAPEL juega un token ambiguo.
 *
 * El mismo simbolo significa cosas distintas segun donde este, y el espaciado
 * depende de cual sea.  Anotarlo antes -- en una pasada que si lleva contexto
 * -- permite que la decision del espacio sea despues local y sin dudas.
 */
enum class Role : uint8_t {
    Plain,      ///< nada que decidir
    Binary,     ///< espacios a los dos lados (`a * b`, `c ? a : b`)
    TightBoth,  ///< pegado por los dos lados (`Caja<`)
    TightLeft,  ///< pegado delante, separado detras (`i64*`, `i64>`, `case X:`)
    TightRight, ///< separado delante, pegado detras (`*p`, `&x`, `-a`)
    Unknown,    ///< no se pudo decidir: se conserva lo que habia
};

/**
 * @brief Anota el papel de cada token de un fuente ya troceado.
 *
 * @param pieces Piezas del fuente.
 * @return Un papel por pieza, en el mismo orden.
 */
/**
 * @brief Aplica las reglas que cambian tokens y declara lo que hizo.
 *
 * @param pieces [in,out] piezas del fuente; se les pone @c drop y @c glued.
 * @return Las reescrituras hechas, para que la comprobacion de `P2` sepa que
 *         diferencias esperar.
 */
std::vector<Rewrite> apply_token_rules(std::vector<Piece> &pieces);

std::vector<Role> annotate_roles(const std::vector<Piece> &pieces);

/**
 * @brief Indica si la categoria de token nombra un tipo del lenguaje.
 * @param k Categoria del token.
 * @return Cierto si es una palabra clave de tipo (`i64`, `bool`, `string`...).
 */
/**
 * @brief Convierte el campo @c kind de una pieza a su enum.
 *
 * La pieza guarda un `int` para no arrastrar `token.h` por todo el
 * formateador; esto lo devuelve a su tipo.
 *
 * @param p Pieza.
 * @return Su categoria de token.
 */
inline TokenKind kind_of(const Piece &p) {
    return static_cast<TokenKind>(p.kind);
}

bool is_type_keyword(TokenKind k);

/**
 * @brief Indica si el token es un modificador de declaracion (`R42`).
 *
 * Los que ese reparto REORDENA: acceso, `static`, `final`, `const`.  Es la
 * pregunta estrecha; para saber si algo puede ir DELANTE de un tipo esta
 * @ref precedes_type, que ademas cuenta `typedef` y `using`.  Eran la misma
 * funcion copiada tres veces, y al separarlas se vio que respondian a dos
 * preguntas distintas: reordenar un `typedef` no significa nada.
 *
 * @param k Categoria del token.
 * @return Cierto si es `public`, `private`, `protected`, `static`, `final` o
 *         `const`.
 */
bool is_modifier(TokenKind k);

/**
 * @brief Indica si el token puede aparecer DELANTE del tipo de una declaracion.
 *
 * Los modificadores de @ref is_modifier mas `typedef` y `using`.  Quien busca
 * donde empieza el tipo tiene que saltarlos todos: sin contar el `typedef`,
 * `typedef LONG *PLONG;` no se leia como declaracion y su `*` acababa de
 * producto.
 *
 * @param k Categoria del token.
 * @return Cierto si puede preceder al tipo.
 */
bool precedes_type(TokenKind k);

/**
 * @brief Salta los calificadores que van DELANTE del tipo en una declaracion.
 * @param pieces Las piezas de la linea.
 * @param i      Donde empieza la declaracion.
 * @return El indice donde empieza el TIPO (== @p i si no habia calificadores).
 *
 * Lo usa quien decide roles, para saber si un `*` va pegado al tipo o al
 * nombre.  Esta aparte -- y no metido en su bucle -- porque quien ALINEA lo
 * necesitaria igual el dia que el tipo pase a ser columna propia (ver la nota
 * en @c align.cpp), y entonces la lista de calificadores tiene que ser UNA: con
 * dos copias, el dia que se anada uno se anadiria a una y la otra lo colocaria
 * mal, que es un fallo mudo -- sale bien formateado y en el sitio equivocado --.
 */
size_t skip_decl_qualifiers(const std::vector<Piece> &pieces, size_t i);

/**
 * @brief Que separacion pide el estandar entre dos tokens.
 */
enum class Spacing {
    None,  ///< van pegados
    Space, ///< va un espacio
    Keep,  ///< no se sabe: se deja lo que habia
};

/**
 * @brief Decide la separacion entre dos tokens (`R33`-`R35`, `R52`, `R61`+).
 *
 * @param before Token anterior a @p prev, o nulo si no hay.  Hace falta para
 *               los operadores que cambian de significado: para saber si va
 *               espacio DETRAS de un `-` hay que saber si era resta o signo, y
 *               eso lo dice el token de antes.
 * @param prev      Token de la izquierda.
 * @param cur       Token de la derecha.
 * @param prev_role Papel del token de la izquierda (@ref annotate_roles).
 * @param cur_role  Papel del token de la derecha.
 * @return Que poner entre los dos.
 */
Spacing space_between(const Piece *before, const Piece &prev, const Piece &cur,
                      Role prev_role, Role cur_role);

/**
 * @brief Indica si dos textos son el MISMO programa escrito distinto.
 *
 * Es LA definicion de `P2`, y vive en un solo sitio a proposito: el test tenia
 * la suya y era mas debil -- comparaba clase y lexema, y el contenido de un
 * fragmento de cadena interpolada no va en el lexema sino en su valor ya
 * resuelto --, asi que daba por bueno lo que el codigo rechazaba.  Dos ideas de
 * lo mismo, y la del test era la floja.
 *
 * @param before Texto original.
 * @param after  Texto formateado.
 * @return Cierto si los dos dan la misma tira de tokens.
 */

/**
 * @brief Donde acabo cada pieza al emitirla.
 *
 * Lo necesita la alineacion: para saber cuanto rellenar hay que saber primero
 * en que columna cae cada cosa POR SI SOLA.  Por eso el texto se emite dos
 * veces -- una para medir y otra para rellenar --, que es lo que cuesta hacer
 * columnas de verdad.
 */
struct Layout {
    /// Columna (en columnas de pantalla) donde empieza cada pieza.
    std::vector<uint32_t> column;
    /**
     * Columna donde cae el comentario de FIN DE LINEA que precede a la pieza.
     *
     * Un comentario no es un token: vive en la trivia, entre el ultimo token de
     * su linea y el primero de la siguiente.  Por eso su posicion se apunta
     * aparte -- indexada por la pieza que viene DETRAS --, y por eso alinearlos
     * (`R20`) necesita su propio relleno.  Cero = esa pieza no lleva ninguno
     * delante.
     */
    std::vector<uint32_t> comment_column;
    /**
     * @brief Linea donde CAE ese comentario de fin de linea.
     *
     * No es la de la pieza que lo lleva: esa es la primera de la linea
     * SIGUIENTE, y entre las dos puede haber lineas en blanco y comentarios
     * sueltos.  Alinear los comentarios de lineas seguidas (`R20`) pregunta si
     * dos van uno detras de otro, y preguntandoselo a la pieza el bloque se
     * partia en cuanto debajo habia un hueco -- el ultimo comentario se
     * quedaba fuera de la columna de sus hermanos --.
     */
    std::vector<uint32_t> comment_line;
    /// Linea logica en la que cae cada pieza, contando desde cero.
    std::vector<uint32_t> line;
    /// Nivel de indentacion de cada pieza.
    std::vector<uint32_t> level;
    /// Niveles de CONTINUACION (listas abiertas) de cada pieza.
    std::vector<uint32_t> cont;
};

/**
 * @brief Un corte de linea decidido por el reparto (`R12`).
 */
struct Break {
    /// Cierto si hay que cortar la linea JUSTO antes de esta pieza.
    bool before = false;
    /**
     * Cierto si hay que QUITAR el salto que venia antes de esta pieza.
     *
     * Es la otra mitad de `R12`, y sin ella no hay una sola forma (`P1`): una
     * lista que cabe pero que alguien partio a mano se quedaria partida, y el
     * mismo programa tendria dos formas validas.  Repartir sin juntar es
     * la mitad del trabajo.
     */
    bool join = false;
    /// Niveles de indentacion extra respecto al de la linea que se parte.
    uint32_t extra_indent = 0;
};

/**
 * @brief Reindenta un fuente ya troceado (`R1`, `R4`, `R5`, `R7`, `R8`).
 *
 * @param pieces  Piezas del fuente, de @ref scan_pieces.
 * @param tail    Lo que quedaba tras el ultimo token.
 * @param options Ajustes del estandar.
 * @param pad     Relleno extra delante de cada pieza (@ref compute_alignment),
 *                o nulo en la pasada de medir.
 * @param cpad    Relleno delante del comentario de fin de linea, o nulo.
 * @param out     [out] donde cayo cada pieza, o nulo si no interesa.
 * @param breaks  Donde cortar las lineas largas (@ref compute_breaks), o nulo.
 * @return El texto reindentado.
 */
std::string reindent(const std::vector<Piece> &pieces, std::string_view tail,
                     const FormatOptions &options,
                     const std::vector<uint32_t> *pad = nullptr,
                     Layout *out = nullptr,
                     const std::vector<Break> *breaks = nullptr,
                     const std::vector<uint32_t> *cpad = nullptr,
                     std::vector<Rewrite> *added = nullptr);

/**
 * @brief Donde hay que cortar las lineas que no caben (`R12`, `R14`-`R16`).
 *
 * @param pieces  Piezas del fuente.
 * @param layout  Donde cayo cada pieza al emitirla sin repartir.
 * @param options Ajustes del estandar.
 * @return Un corte por pieza; la mayoria sin nada.
 */
std::vector<Break> compute_breaks(const std::vector<Piece> &pieces,
                                  const Layout &layout,
                                  const FormatOptions &options);

/**
 * @brief Cuanto relleno lleva cada pieza para que las columnas cuadren.
 *
 * Implementa `R83`-`R88`: agrupa las lineas consecutivas de la misma forma y
 * alinea sus campos al mas largo del grupo.
 *
 * @param pieces  Piezas del fuente.
 * @param roles   Papel de cada pieza (@ref annotate_roles).
 * @param layout  Donde cayo cada pieza al emitirla sin rellenar.
 * @param options Ajustes del estandar.
 * @return Espacios extra delante de cada pieza; cero para la mayoria.
 */
std::vector<uint32_t> compute_alignment(const std::vector<Piece> &pieces,
                                        const std::vector<Role> &roles,
                                        const Layout &layout,
                                        const FormatOptions &options);

/**
 * @brief Cuanto relleno lleva cada comentario de fin de linea (`R20`).
 *
 * Los comentarios seguidos se alinean entre si, que es lo que convierte una
 * tabla de opcodes comentada en algo legible.  Van aparte de
 * @ref compute_alignment porque un comentario no es un token.
 *
 * @param pieces  Piezas del fuente.
 * @param layout  Donde cayo cada cosa al emitirla sin rellenar.
 * @param options Ajustes del estandar.
 * @return Espacios extra delante de cada comentario de fin de linea.
 */
std::vector<uint32_t>
compute_comment_alignment(const std::vector<Piece> &pieces,
                          const Layout &layout, const FormatOptions &options);

/**
 * @brief Forma canonica de un literal numerico (`R106`, `R107`).
 *
 * Rellena con ceros por la izquierda hasta una anchura que nombre un tipo y
 * pone los digitos hexadecimales en mayuscula.  Ninguna de las dos cosas
 * cambia el valor del literal.
 *
 * @param text Lexema tal como lo escribio el autor, sufijo incluido.
 * @return El texto canonico, o vacio si el literal ya lo esta.
 */
std::string canonical_literal(std::string_view text);

/**
 * @brief Pone a cada literal el sufijo de tipo de su declaracion (`R108`).
 *
 * Solo donde el tipo se puede saber sin compilar: `TIPO nombre = <literal>;`.
 *
 * @param pieces [in,out] las piezas.
 * @param textos [in,out] almacen de los textos nuevos que las piezas apuntan.
 */
std::vector<Rewrite> add_type_suffixes(std::vector<Piece> &pieces,
                                       std::vector<std::string> &textos);

/**
 * @brief Marca como literal el interior de las llamadas que capturan texto.
 *
 * @param pieces Piezas del fichero; se les pone @c Piece::verbatim.
 * @param extra Nombres importados que el llamador sabe que capturan.
 */
void mark_verbatim_calls(std::vector<Piece> &pieces,
                         const std::vector<std::string> &extra);

/**
 * @brief Nombres declarados en un fichero que capturan el texto del argumento.
 *
 * @param pieces Piezas del fichero, de @ref scan_pieces.
 * @return Los nombres, en el orden en que aparecen.
 */
std::vector<std::string> capture_names_in(const std::vector<Piece> &pieces);

} // namespace fmt
} // namespace vx

#endif // VX_FMT_FMT_INTERNAL_H
