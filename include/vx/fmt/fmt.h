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
 * @file fmt.h
 * @brief Formateador de Vesta: texto entra, texto sale.
 *
 * Implementa el estandar de `doc/VMdoc/Vesta/EstiloYFormato.md`.  Cada regla
 * del codigo cita el numero que aplica (`R1`, `R12`, ...) para poder ir del
 * codigo al documento y al reves.
 *
 * TRES DECISIONES QUE EXPLICAN TODO LO DEMAS:
 *
 * **Solo depende del LEXER.**  Ni del parser, ni del type checker.  Eso le
 * permite formatear codigo A MEDIO ESCRIBIR -- el caso normal en un editor,
 * donde se formatea mientras se teclea y el arbol todavia no existe -- y deja
 * el modulo lo bastante suelto como para que extraerlo a una libreria aparte
 * sea mecanico el dia que haga falta.
 *
 * **No le cuesta nada al compilador.**  No se anade nada al camino de compilar:
 * el lexer sigue tirando los comentarios como siempre.  La trivia -- espacios,
 * saltos y comentarios -- se recupera del propio texto, porque cada token lleva
 * su `offset` y su `length` y por tanto lo que hay ENTRE dos tokens es
 * exactamente lo que se escribio ahi.  Comprobado sobre los 502 ficheros del
 * corpus: reconstruir asi devuelve el original byte a byte.
 *
 * **Los fallos son CODIGOS, no frases.**  Como en todo el compilador: el modulo
 * devuelve un codigo del catalogo y sus argumentos, y quien lo muestre lo
 * traduce al idioma activo.  Aqui no se escribe ni una frase para el usuario.
 *
 * La garantia que hace fiable todo esto no es una promesa, es una comprobacion
 * (ver `tests/vx/fmt_test.cpp`):
 *
 *     format(format(x)) == format(x)      idempotente
 *     tokens(format(x)) == tokens(x)      el programa NO cambia, solo su forma
 */

#ifndef VX_FMT_FMT_H
#define VX_FMT_FMT_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace vx {
namespace fmt {

/**
 * @brief Ajustes del formateador.
 *
 * Son POCOS y no se exponen al usuario: el estandar es uno solo (`P1`).  Estan
 * aqui para que las reglas del documento tengan UN sitio en el codigo donde
 * vivir, en vez de repartidas como numeros sueltos.
 */
struct FormatOptions {
    /// `R3`: ancho maximo de linea, midiendo cada tabulador como @c tab_width.
    uint32_t width = 80;
    /// `R1`/`R3`: cuanto mide un tabulador al contar columnas.
    uint32_t tab_width = 4;
    /// `R85`: separacion minima entre columnas alineadas.
    uint32_t min_gap = 1;
    /// `R7`: lineas en blanco seguidas que se permiten dentro de un bloque.
    uint32_t blank_lines_inside = 1;
    /// `R8`: lineas en blanco entre declaraciones de nivel superior.
    uint32_t blank_lines_between = 2;
    /// Funciones IMPORTADAS cuyo argumento se captura como texto (`R110`).  El
    /// formateador detecta solo las declaradas en el propio fichero; resolver
    /// un import es trabajo del compilador, asi que quien lo tenga resuelto
    /// -- el compilador o el LSP -- pasa aqui los nombres que falten.
    std::vector<std::string> raw_capture_names;
};

/**
 * @brief Resultado de formatear.
 *
 * El fallo viaja en el resultado y no como excepcion: quien formatea suele ser
 * un editor, y ahi un fuente a medio escribir es lo NORMAL, no algo
 * excepcional.  Y viaja como CODIGO del catalogo, nunca como frase.
 */
/**
 * @brief Una reescritura que el formateador declara haber hecho.
 *
 * `P2` se comprueba comparando la lista de TOKENS, que es una aproximacion
 * conservadora a "el programa no cambia" y no necesita el parser.  El precio
 * es que prohibe cualquier regla que anada, quite o mueva un token, aunque el
 * programa siga siendo el mismo -- y eso dejaba fuera cinco reglas del
 * estandar (ver `D0`).
 *
 * La salida no es relajar la comprobacion, sino hacerla por INTENCION: el
 * formateador apunta cada transformacion que aplica, y la comprobacion exige
 * que la diferencia entre el antes y el despues sea EXACTAMENTE la declarada.
 * Una diferencia que nadie declaro sigue siendo un fallo, aunque caiga en una
 * regla conocida.  La red se queda igual de fina; solo se abren las puertas
 * que se han medido una a una.
 */

enum class RewriteKind : uint8_t {
    GlueGenericClose, ///< `R29`: dos `>` de cierre pasan a ser un `>>`
    DropEmptyParens,  ///< `R74`: `@X()` pierde sus parentesis vacios
    SwapModifiers,    ///< `R42`: dos modificadores cambian de orden
    AddBraces,        ///< `R6`: un cuerpo suelto recibe sus llaves
    AddTypeSuffix,    ///< `R108`: un literal recibe el sufijo de su tipo
};

/// @brief Una reescritura, anclada al token del texto ORIGINAL donde ocurre.
struct Rewrite {
    RewriteKind kind = RewriteKind::DropEmptyParens;
    /**
     * @brief Offset en BYTES del token dentro del fuente original.
     *
     * No el indice de la pieza.  Las piezas y los tokens no van a la par: una
     * cadena interpolada llega como una tira de piezas y sus marcadores de
     * apertura y cierre son SINTETICOS -- el lexer los fabrica y no aparecen
     * entre las piezas --, asi que a partir de la primera interpolacion los
     * dos indices se separan y la reescritura quedaba anclada donde no era.
     * El offset SI significa lo mismo en los dos lados.
     */
    size_t at = 0;
};

struct FormatResult {
    /// El texto formateado.  Si @c ok es falso, el original sin tocar.
    std::string text;
    /// Falso si el fuente no se pudo procesar entero.
    bool ok = true;
    /// Codigo del catalogo si @c ok es falso (p.ej. "VXF001"); vacio si no.
    std::string code;
    /// Argumentos para los placeholders del mensaje.
    std::vector<std::string> args;
    /// Cierto si el texto de salida difiere del de entrada.
    bool changed = false;
    /**
     * @brief Lo que el formateador DECLARA haber cambiado del programa.
     *
     * Casi todo lo que hace es mover texto, y eso no cambia la tira de tokens.
     * Unas pocas reglas SI la cambian -- juntar dos `>`, quitar unos
     * parentesis vacios, poner unas llaves, poner el sufijo de tipo a un
     * literal --, y cada una se anota aqui.  Comprobar que el programa no
     * cambio es entonces exigir que la unica diferencia entre las dos tiras
     * sea la que esta lista dice, ni una mas.
     */
    std::vector<Rewrite> rewrites;
};

bool same_program(std::string_view before, std::string_view after,
                  const std::vector<Rewrite> &rewrites = {});

/**
 * @brief Un token con la trivia que lo precede.
 *
 * La trivia -- espacios, saltos y comentarios -- no la guarda el lexer: se
 * recorta del fuente con los offsets, que es lo que permite que el compilador
 * no pague nada por tenerla.
 *
 * Los dos campos son VISTAS sobre el fuente, no copias: trocear un fichero de
 * 30.000 lineas no debe duplicarlo en memoria.  Valen mientras viva el texto
 * del que salieron.
 */
struct Piece {
    /// Lo que hay entre el token anterior y este, tal cual se escribio.
    std::string_view trivia;
    /// El texto del token, tal cual se escribio.
    std::string_view text;
    /// Offset del token dentro del fuente.
    uint32_t offset = 0;
    /// Categoria del token (@c TokenKind), para no reclasificar despues.
    int kind = 0;
    /**
     * Cierto si la pieza es parte de una cadena interpolada.
     *
     * `"total: ${n}"` no llega como un token, sino como una tira -- texto,
     * apertura, la expresion, cierre, texto --, y lo que hay entre sus piezas
     * ES el contenido de la cadena, no trivia: tocarlo cambia el programa.
     *
     * Lo marca @ref scan_pieces y no quien formatea, porque los marcadores que
     * abren y cierran la tira son SINTETICOS -- el lexer los fabrica, no salen
     * de ningun texto -- y por eso no aparecen entre las piezas.  Quien no ve
     * todos los tokens no puede saberlo, y esa fue exactamente la causa de que
     * la primera version rompiera 125 ficheros del corpus.
     */
    bool in_string = false;
    /// Cierto si la pieza cae dentro de una llamada que captura el TEXTO de su
    /// argumento (`R110`): ahi los espacios son contenido, no formato.
    bool verbatim = false;
    /// Cierto si la pieza NO se emite: un parentesis vacio de anotacion
    /// (`R74`) o el segundo `>` que se fundio en un `>>` (`R29`).
    bool drop = false;
    /// Texto que sustituye al del token, si alguna regla lo reescribio.  Vacio
    /// -- lo normal -- quiere decir que se emite @c text tal cual.
    std::string_view glued;
};

/**
 * @brief Trocea un fuente en piezas: cada token con la trivia que lo precede.
 *
 * Es la base del formateador y tambien la de su comprobacion: concatenar las
 * piezas en orden, mas @p tail, devuelve el fuente ORIGINAL byte a byte.
 *
 * @param source   Texto completo; debe seguir vivo mientras se usen las piezas.
 * @param filename Nombre logico, solo para los diagnosticos del lexer.
 * @param tail     [out] lo que queda tras el ultimo token (el salto final).
 * @param code     [out] codigo del catalogo si el troceado no se completo.
 * @return Las piezas en orden, o vacio si hubo error.
 */
std::vector<Piece> scan_pieces(std::string_view source,
                               const std::string &filename,
                               std::string_view &tail, std::string &code);

/**
 * @brief Formatea un fuente Vesta.
 *
 * @param source   Texto completo del fichero.
 * @param filename Nombre logico, solo para los diagnosticos.
 * @param options  Ajustes; por defecto, el estandar.
 * @return El texto formateado y si hubo cambio.
 */
FormatResult format(const std::string &source, const std::string &filename,
                    const FormatOptions &options = FormatOptions{});

} // namespace fmt
} // namespace vx

#endif // VX_FMT_FMT_H
