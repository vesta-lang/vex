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
 * @file lexer.h
 * @brief Analizador lexico (tokenizador) del lenguaje Vesta.
 *
 * Convierte el codigo fuente .vx en una secuencia de tokens (vx::Token)
 * que el parser consume.  Se ejecuta DESPUES del preprocesador VPP (cuando
 * este se aplica), por lo que el flujo de bytes que ve es ya plano.
 *
 * Caracteristicas:
 *  - Reporta errores via vx::Diagnostics (no lanza excepciones).
 *  - Lookahead de 1 token con un buffer interno (mas barato que clonar
 *    todo el estado como hace el lexer .vel original).
 *  - Reconoce TODOS los tokens cerrados de Vesta, incluyendo interpolacion
 *    @c ${...} (emite secuencia ISTR_BEGIN/TEXT/EXPR_BEGIN/.../END), strings
 *    triple-quoted @c """...""" y raw @c r"...".
 *  - Comentarios //... y bloque slash-asterisco se descartan (no se emiten
 *    como tokens), salvo que en el futuro queramos reaprovecharlos para
 *    documentacion (en cuyo caso habra que cambiar la politica).
 *
 * Hot path:
 *  - next() es O(N) donde N = bytes del fuente.  El dispatch por primer
 *    caracter usa un switch que el compilador convierte en jump table.
 *  - Las palabras reservadas se clasifican con un dispatch por primera
 *    letra + longitud + memcmp directo sobre el lexema (no hay hashing
 *    ni busqueda lineal sobre tabla); esta es la ruta caliente del
 *    lexer y es el motivo por el que se evita std::unordered_map aqui.
 */

#ifndef VX_LEXER_H
#define VX_LEXER_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <utility>

#include "vx/diagnostic.h"
#include "vx/token.h"

namespace vx {

/**
 * @class Lexer
 * @brief Tokenizador hot-path para .vx.
 *
 * Posee internamente el codigo fuente (mover-in en el constructor) y
 * un cursor (pos, line, column).  El tokenizado funciona "on demand":
 * cada llamada a next() avanza el cursor justo lo necesario para
 * producir un token nuevo.  No se construye una lista completa de
 * tokens en memoria, lo que reduce la presion de cache cuando el
 * fichero fuente es grande.
 */
class Lexer {
  public:
    /**
     * @brief Construye el lexer con su buffer y diagnostico asociados.
     *
     * @param source   Codigo fuente .vx completo (se mueve, sin copia).
     * @param filename Nombre logico del fichero para los diagnosticos.
     * @param diags    Sumidero de errores y warnings.  Vivo durante toda
     *                 la vida del lexer.
     */
    Lexer(std::string source, std::string filename, Diagnostics &diags,
          const ExpansionInfo *expansion = nullptr);

    /**
     * @brief Produce y consume el siguiente token.
     *
     * Devuelve END_OF_FILE indefinidamente al llegar al final del
     * fuente.  No lanza; los problemas se reportan en @c diags.
     *
     * @return Token consumido.
     */
    Token next();

    /**
     * @brief Devuelve una referencia al siguiente token sin consumirlo.
     *
     * El primer peek() despues de un next() llena el buffer interno;
     * llamadas sucesivas devuelven el mismo token sin trabajo extra.
     *
     * @return Referencia const al token cacheado (valido hasta el
     *         proximo next()).
     */
    const Token &peek();

    /**
     * @brief Devuelve el token a una distancia @p offset del cursor sin
     * consumir.
     *
     * @c peek_at(0) equivale a @c peek(); @c peek_at(1) devuelve el token
     * que vendria DESPUES del actual peek().  Util para resolver
     * ambiguedades sintacticas como `Punto* p` (necesita ver IDENT STAR
     * IDENT) sin parsear especulativamente.
     *
     * Internamente mantiene una cola FIFO de tokens precargados; cada
     * @c next() / @c peek_at(n) la rellena solo lo justo.
     *
     * @param offset Distancia desde el cursor (0 = el siguiente token).
     */
    const Token &peek_at(size_t offset);

    /**
     * @brief @c true si el cursor ha llegado al final del fuente.
     */
    [[nodiscard]] bool at_end() const noexcept {
        return pos_ >= source_.size();
    }

    /**
     * @brief Acceso al fichero asociado (para construir SourceLoc fuera).
     */
    [[nodiscard]] const std::string &filename() const noexcept {
        return *file_name_;
    }

    /**
     * @brief El nombre ya compartido, para quien produzca muchas posiciones.
     * @return Puntero al nombre del pozo; nunca nulo.
     */
    [[nodiscard]] const std::string *file_name_ptr() const noexcept {
        return file_name_;
    }

    /**
     * @brief Acceso de solo lectura al codigo fuente completo.
     *
     * Usado por @c Parser para realizar @c expr-capture en macros:
     * extrae texto raw entre dos offsets de @c SourceLoc.
     */
    [[nodiscard]] const std::string &source_buffer() const noexcept {
        return source_;
    }

  private:
    /**
     * @brief Avanza un caracter y actualiza linea/columna.
     *
     * Inline en el .cpp porque solo lo usa el propio lexer; no se
     * expone para evitar dependencias del API publica.
     */
    char advance();

    /**
     * @brief Devuelve el caracter en pos_ + offset sin avanzar.
     * @param offset Distancia desde el cursor (0 = caracter actual).
     */
    [[nodiscard]] char peek_char(size_t offset = 0) const noexcept;

    /**
     * @brief Salta espacios, tabuladores, saltos de linea y comentarios.
     */
    void skip_trivia();

    /**
     * @brief Construye un Token con la posicion actual del cursor.
     */
    Token make_token(TokenKind kind, std::string lexeme, SourceLoc loc) const;

    /**
     * @brief Lee un literal numerico (decimal, hex, bin, oct, float).
     */
    Token lex_number();

    /**
     * @brief Lee un identificador o palabra reservada.
     */
    Token lex_identifier();

    /**
     * @brief Lee un literal de caracter '...'.
     */
    Token lex_char();

    /**
     * @brief Lee un string literal "..." (estandar) o r"..." (raw).
     *
     * Soporta tres variantes:
     *   - @c "..."     string normal con escapes y posibles @c ${expr}.
     *   - @c r"..."    raw: sin escapes, sin interpolacion.
     *   - @c """..."""  triple-quoted: multilinea con escapes y @c ${expr}.
     *
     * Cuando detecta interpolacion, deposita en @c string_emit_queue_
     * una secuencia ISTR_BEGIN, ISTR_TEXT*, ISTR_EXPR_BEGIN/END pairs,
     * e ISTR_END.  Las siguientes llamadas a @c lex_one_raw drenan
     * la cola antes de tocar @c source_ otra vez.
     *
     * @param raw Si es true, no procesa escapes ni interpolacion.
     */
    Token lex_string(bool raw);

    /**
     * @brief Despacha sobre simbolos y operadores (primer caracter no
     *        alfanumerico).
     */
    Token lex_symbol();

    /**
     * @brief Lee un token nuevo desde el fuente sin consultar ningun cache.
     *
     * Es la primitiva de lectura usada por @c next() y @c peek_at();
     * permite evitar recursion accidental entre los buffers internos.
     */
    Token lex_one_raw();
    /// Cuerpo real; @ref lex_one_raw lo envuelve para estampar la procedencia.
    Token lex_one_raw_inner();

    /**
     * @brief Reporta un error de lexer en la posicion actual.
     */
    void error_at(SourceLoc loc, std::string msg);

    std::string source_; ///< Codigo fuente completo (owner).
    /// Nombre logico para diagnosticos, COMPARTIDO (@c util::intern_name).
    ///
    /// Se interna UNA vez al construir el lexer y desde ahi cada token copia
    /// solo el puntero.  Por valor, cada `SourceLoc` que sale de aqui reservaba
    /// memoria -- y de aqui sale una por token.
    const std::string *file_name_;
    Diagnostics &diags_;   ///< Sumidero de diagnosticos (no-owner).

    size_t pos_ = 0; ///< Indice de byte en source_.
    /// De que expansion viene lo que se esta leyendo, o @c nullptr si es
    /// codigo que alguien escribio.  No propietario.
    const ExpansionInfo *expansion_ = nullptr;
    uint32_t line_ = 1;   ///< Linea actual (1-based).
    uint32_t column_ = 1; ///< Columna actual (1-based, en bytes).

    Token peeked_;            ///< Buffer de lookahead 0 (compat retro).
    bool has_peeked_ = false; ///< true si peeked_ contiene dato valido.
    /// Cola FIFO de tokens adicionales para peek_at(n>=1).  Se rellena
    /// bajo demanda y se vacia con cada next().  Tipicamente queda casi
    /// vacia (1-2 tokens) por lo que std::deque es eficiente.
    std::deque<Token> extra_lookahead_;
    /// interpolacion: cola de tokens pre-emitidos por
    /// @c lex_string al detectar @c "${...}".  El lexer parsea TODO el
    /// string interpolado de una pasada y deposita ISTR_BEGIN +
    /// ISTR_TEXT + ISTR_EXPR_BEGIN + (tokens internos de la expr) +
    /// ISTR_EXPR_END + ... + ISTR_END en este buffer.  @c lex_one_raw
    /// drena este buffer antes de tocar @c source_, asi cada @c next()
    /// recibe los tokens en orden sin re-parsing.
    std::deque<Token> string_emit_queue_;
};

/**
 * @brief Clasifica un identificador como palabra reservada o IDENTIFIER.
 *
 * Esta funcion encapsula el dispatch por primera letra + longitud que
 * el lexer usa internamente.  Se exporta porque el parser y los tests
 * la pueden necesitar para chequear "es esta cadena un keyword?" sin
 * pasar por el lexer.
 *
 * @param lexeme Cadena ASCII a clasificar.
 * @return TokenKind correspondiente (KW_* si es keyword, IDENTIFIER si no).
 */
TokenKind classify_identifier(const std::string &lexeme) noexcept;

} // namespace vx

#endif // VX_LEXER_H
