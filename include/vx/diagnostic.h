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
 * @file diagnostic.h
 * @brief Sistema de diagnosticos para el frontend Vesta.
 *
 * Define la representacion de un diagnostico (error, warning, nota), el
 * contenedor que los acumula durante la compilacion y la plantilla
 * Result<T> que envuelve "valor de exito o lista de diagnosticos" sin
 * usar excepciones.  Esta decision (Result + diagnosticos colectables)
 * se eligio en lugar de excepciones C++ por dos razones de hardware:
 *
 *   1. Evita el coste de unwinding en la ruta caliente del compilador
 *      (cada llamada al lexer / parser / type checker se vuelve previsible).
 *   2. Permite reportar varios errores en una sola compilacion sin abortar
 *      tras el primero, mejorando la experiencia de usuario.
 *
 * Patron de uso:
 * @code
 *   vx::Diagnostics diags;
 *   auto r = parse_program(source, diags);
 *   if (!r.ok()) { for (auto &d : diags.all()) print_diag(d); return 1; }
 * @endcode
 */

#ifndef VX_DIAGNOSTIC_H
#define VX_DIAGNOSTIC_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "util/name_pool.h"       // la ruta del fichero, compartida
#include "vx/diag/diag_catalog.h" // catalogo multi-idioma (formateo por codigo)

namespace vx {

/**
 * @brief Severidad del diagnostico.
 *
 * - ERR  : impide la generacion de codigo correcto; el compilador no
 *          emitira un .velb final aunque siga procesando para listar
 *          mas errores.
 * - WARN : codigo sospechoso pero compilable (p.ej. variable sin uso).
 * - NOTE : informacion adyacente a un error o warning anterior
 *          (p.ej. "definida aqui").
 *
 * Nota: ERROR / WARNING serian nombres mas naturales pero MinGW
 * (windef.h) los define como macros de WinAPI, lo que rompe
 * cualquier enum class con esos identificadores.  Usamos ERR / WARN
 * por consistencia con el preprocesador VPP del propio proyecto.
 */
enum class DiagLevel : uint8_t {
    ERR = 0,  ///< Error fatal a nivel de compilacion.
    WARN = 1, ///< Aviso sin abortar la compilacion.
    NOTE = 2  ///< Nota informativa adjunta a un mensaje principal.
};

/**
 * @brief Localizacion de un fragmento de codigo en el fichero fuente.
 *
 * Lineas y columnas comienzan en 1; offset es el indice de byte dentro
 * del fichero (comenzando en 0).  Se almacena ademas la longitud en
 * bytes para que el reportador pueda subrayar el span exacto.
 */
struct SourceLoc;

/**
 * @brief De donde salio un trozo de codigo que nadie escribio.
 *
 * Una `@Macro` genera texto y ese texto se parsea: lo que sale de ahi no esta
 * en ningun fichero, asi que su posicion -- linea 3 de `<macro:X>` -- no lleva
 * a ninguna parte.  Lo que hace falta saber es DE QUE expansion vino y DESDE
 * DONDE se invoco, y contarlo encadenado:
 *
 *     ... en el codigo generado
 *       expandido por la macro FOO
 *       invocada en prog.vx:12
 *
 * Se apunta con puntero no-propietario porque una posicion se copia
 * constantemente y esto es raro: la inmensa mayoria valen @c nullptr y no pagan
 * nada.  Lo posee quien hizo la expansion, que vive mas que el arbol.
 */
struct ExpansionInfo {
    std::string macro;               ///< Que la genero.
    std::shared_ptr<SourceLoc> site; ///< Donde se invoco.
};

struct SourceLoc {
    /// Ruta o nombre logico del fichero (puede ser "<stdin>"), COMPARTIDA.
    ///
    /// No se guarda por valor: una posicion va en cada nodo del arbol, en cada
    /// token y en cada instruccion del intermedio, y una ruta no cabe en el
    /// buffer pequeno de `std::string`, asi que por valor reservaba memoria en
    /// cada COPIA -- y copiar posiciones es de lo que mas hace el compilador.
    /// El pozo la reparte una vez (@c util::intern_name) y aqui solo viaja el
    /// puntero.  Nunca nulo: sin fichero apunta a la cadena vacia compartida.
    ///
    /// Es el mismo arreglo que el preprocesador ya tenia en su
    /// `vpp::SourceLocation`, por el mismo motivo y con los mismos numeros.
    const std::string *file_name = util::empty_name();
    uint32_t line = 1;   ///< Numero de linea (1-based).
    uint32_t column = 1; ///< Numero de columna (1-based, en bytes).
    uint32_t offset =
        0; ///< Offset absoluto en bytes desde el inicio del fichero.
    uint32_t length = 1; ///< Longitud del span en bytes.
    /// De que expansion vino, o @c nullptr si se escribio tal cual.  No
    /// propietario: lo posee quien expandio.
    const ExpansionInfo *expansion = nullptr;

    /// @brief La ruta del fichero.  @return El nombre; vacio si no consta.
    const std::string &file() const noexcept { return *file_name; }

    /**
     * @brief Apunta a un fichero por su nombre, internandolo.
     *
     * Toma el cerrojo del pozo, asi que NO vale por nodo: quien produce muchas
     * posiciones interna una vez y copia @c file_name.
     *
     * @param f Ruta o nombre logico.
     */
    void set_file(const std::string &f) { file_name = util::intern_name(f); }
};

/**
 * @brief Un diagnostico completo: nivel + localizacion + mensaje.
 *
 * El campo @c code es opcional; permite asociar codigos de error
 * estables (estilo "VX0001") para documentacion y herramientas.
 */
struct Diagnostic {
    DiagLevel level = DiagLevel::ERR; ///< Severidad.
    SourceLoc loc;                    ///< Posicion en el fuente.
    std::string message; ///< Texto crudo (ruta LEGADA sin catalogo).
    std::string code;    ///< Codigo estable (p.ej. "VXA001").
    /// ARGS (datos) para los placeholders {0},{1},... del mensaje del catalogo.
    /// El texto se formatea al IMPRIMIR, en el idioma activo -> el mismo
    /// diagnostico se reformatea en cualquier idioma o se vuelca a JSON/SARIF.
    /// Solo se usa cuando @c code esta en el catalogo; si no, se imprime
    /// @c message crudo (compatibilidad con los diagnosticos aun no migrados).
    std::vector<std::string> args;
};

/**
 * @class Diagnostics
 * @brief Contenedor mutable que acumula diagnosticos durante la compilacion.
 *
 * Optimizado para el patron tipico del compilador:
 *  - Se añaden diagnosticos linealmente (push back O(1) amortizado).
 *  - Se consulta @c has_errors() muchas veces para decidir si abortar.
 *  - Se itera al final con @c all() para emitir el reporte unificado.
 *
 * Internamente usa std::vector (memoria contigua, cache-friendly) en
 * lugar de std::list para minimizar pointer chasing al reportar.
 */
class Diagnostics {
  public:
    Diagnostics() = default;

    /**
     * @brief añade un diagnostico copiando el objeto.
     * @param d Diagnostico a añadir.
     */
    void emit(Diagnostic d) {
        // Supresion: durante el type-check "solo-anotacion" del cuerpo de un
        // @Macro, queremos que check_expr rellene los result_type SIN emitir
        // diagnosticos (los patrones comptime -- macro-a-macro, comptime
        // globals, introspect -- no son errores reales; se manejan en el
        // lowering / AST-eval).  Con suppress_ activo emit() es no-op.
        if (suppress_) return;
        // Actualizar el contador de errores antes de mover el diagnostico.
        if (d.level == DiagLevel::ERR) ++error_count_;
        // Mover al vector evita una copia de message/code/file.
        entries_.push_back(std::move(d));
    }

    /// Activa/desactiva la supresion de diagnosticos.  Devuelve el estado
    /// anterior (para restaurar con RAII/guard).
    bool set_suppressed(bool on) {
        bool prev = suppress_;
        suppress_ = on;
        return prev;
    }

    /**
     * @brief Helper para emitir un error con localizacion y mensaje.
     * @param loc     Posicion en el fuente.
     * @param message Texto descriptivo.
     */
    void error(SourceLoc loc, std::string message) {
        // Construir directamente in-place evita una copia de Diagnostic.
        Diagnostic d;
        d.level = DiagLevel::ERR;
        d.loc = std::move(loc);
        d.message = std::move(message);
        emit(std::move(d));
    }

    /**
     * @brief Helper para emitir un warning con localizacion y mensaje.
     * @param loc     Posicion en el fuente.
     * @param message Texto descriptivo.
     */
    void warning(SourceLoc loc, std::string message) {
        // Mismo patron que error() pero con nivel WARNING.
        Diagnostic d;
        d.level = DiagLevel::WARN;
        d.loc = std::move(loc);
        d.message = std::move(message);
        emit(std::move(d));
    }

    /**
     * @brief Emite un diagnostico CATALOGADO: solo el codigo estable + los args
     *        (datos).  El texto se resuelve del catalogo, en el idioma activo,
     * al imprimir.  Es la ruta preferida para todo diagnostico nuevo (deja el
     *        texto fuera del compilador -> multi-idioma + salida maquina).
     * @param loc   Posicion en el fuente.
     * @param level Severidad.
     * @param code  Codigo del catalogo (p.ej. "VXA001").
     * @param args  Valores para los placeholders {0},{1},...
     */
    void diag(SourceLoc loc, DiagLevel level, std::string code,
              std::vector<std::string> args = {}) {
        Diagnostic d;
        d.level = level;
        d.loc = std::move(loc);
        d.code = std::move(code);
        d.args = std::move(args);
        emit(std::move(d));
    }

    /**
     * @brief Helper para emitir una nota adjunta a un diagnostico anterior.
     * @param loc     Posicion en el fuente.
     * @param message Texto descriptivo.
     */
    void note(SourceLoc loc, std::string message) {
        // Las notas no incrementan error_count_.
        Diagnostic d;
        d.level = DiagLevel::NOTE;
        d.loc = std::move(loc);
        d.message = std::move(message);
        emit(std::move(d));
    }

    /**
     * @brief @c true si al menos un diagnostico es ERROR.
     *
     * Marcado [[nodiscard]] para evitar olvidos en el call site
     * y cacheado en @c error_count_ para que sea O(1).
     */
    [[nodiscard]] bool has_errors() const noexcept { return error_count_ > 0; }

    /**
     * @brief Numero total de errores acumulados.
     */
    [[nodiscard]] size_t error_count() const noexcept { return error_count_; }

    /**
     * @brief Numero total de diagnosticos (errores + warnings + notas).
     */
    [[nodiscard]] size_t size() const noexcept { return entries_.size(); }

    /**
     * @brief Acceso de solo lectura a todos los diagnosticos.
     * @return Vector contiguo con los diagnosticos en orden de emision.
     */
    [[nodiscard]] const std::vector<Diagnostic> &all() const noexcept {
        return entries_;
    }

    /**
     * @brief Vacia el contenedor reutilizando capacidad.
     *
     * Util cuando el mismo objeto se reusa en varios pases
     * (por ejemplo: lex/parse de varios ficheros con la misma instancia).
     */
    void clear() noexcept {
        entries_.clear();
        error_count_ = 0;
    }

  private:
    std::vector<Diagnostic> entries_; ///< Almacenamiento contiguo.
    size_t error_count_ = 0;          ///< Cache O(1) para has_errors().
    bool suppress_ = false;           ///< No-op emit() mientras este activo.
};

/**
 * @brief Imprime un diagnostico en formato gcc-like en el stream dado.
 *
 * Formato: @code file:line:col: level: mensaje [code] @endcode
 *
 * @param os Stream de salida (std::cerr habitualmente).
 * @param d  Diagnostico a imprimir.
 */
inline void print_diagnostic(std::ostream &os, const Diagnostic &d) {
    // Prefijo file:line:col compatible con la salida gcc/clang
    // para que editores como VSCode reconozcan el "click-to-jump".
    os << d.loc.file() << ":" << d.loc.line << ":" << d.loc.column << ": ";
    // Etiqueta de severidad legible.
    switch (d.level) {
    case DiagLevel::ERR: os << "error: "; break;
    case DiagLevel::WARN: os << "warning: "; break;
    case DiagLevel::NOTE: os << "note: "; break;
    }
    // Mensaje: del CATALOGO (idioma activo) si el codigo esta catalogado; si
    // no, el @c message crudo (diagnosticos aun no migrados).
    if (!d.code.empty() && diag::has_code(d.code))
        os << diag::format(d.code, d.args);
    else
        os << d.message;
    // Si hay codigo de error estable, incluirlo entre corchetes al final.
    if (!d.code.empty()) os << " [" << d.code << "]";
    os << "\n";
    /* Y de donde salio el codigo, si no lo escribio nadie.  Una posicion dentro
     * de lo que genero una macro no lleva a ningun sitio por si sola: el
     * fichero no existe.  Lo que hace falta es el camino hasta el sitio que si
     * esta escrito.  Se recorre la cadena entera porque una macro puede haber
     * salido de otra. */
    for (const ExpansionInfo *ex = d.loc.expansion; ex != nullptr;) {
        std::string sitio = "?";
        if (ex->site)
            sitio = ex->site->file() + ":" + std::to_string(ex->site->line) +
                    ":" + std::to_string(ex->site->column);
        os << "  " << diag::format("VX7015", {ex->macro, sitio}) << "\n";
        ex = ex->site ? ex->site->expansion : nullptr;
    }
}

/**
 * @brief Imprime todos los diagnosticos acumulados en un Diagnostics.
 * @param os    Stream de salida.
 * @param diags Contenedor con los diagnosticos a imprimir.
 */
inline void print_all_diagnostics(std::ostream &os, const Diagnostics &diags) {
    // Iterar en orden de emision; el orden ya respeta la secuencia logica.
    for (const auto &d : diags.all())
        print_diagnostic(os, d);
}

/**
 * @brief Plantilla Result<T> que evita excepciones en las APIs publicas.
 *
 * Representa "exito con valor T" o "fallo".  Los diagnosticos asociados
 * al fallo se acumulan en el contenedor Diagnostics que se pasa por
 * referencia al productor, no se transportan dentro de Result; esto
 * permite que warnings de un Result exitoso tambien lleguen al usuario.
 *
 * Diseno tomado de absl::StatusOr y std::expected (no usado aun por
 * compatibilidad con C++17).  Layout: bool + T (sin alocacion extra).
 *
 * @tparam T Tipo del valor de exito.  Debe ser move-constructible.
 */
template <typename T> class Result {
  public:
    /**
     * @brief Construye un Result que representa exito con el valor dado.
     */
    static Result ok(T value) {
        // Construir explicitamente para mover el valor sin copia.
        Result r;
        r.has_value_ = true;
        r.value_ = std::move(value);
        return r;
    }

    /**
     * @brief Construye un Result que representa fallo (sin valor).
     */
    static Result fail() {
        // El valor por defecto T() no se observa cuando has_value_ == false.
        return Result{};
    }

    /**
     * @brief @c true si el Result lleva un valor valido.
     */
    [[nodiscard]] bool ok() const noexcept { return has_value_; }

    /**
     * @brief Acceso al valor.  Comportamiento indefinido si @c !ok().
     *
     * No se chequea en runtime para evitar coste; el usuario debe
     * llamar antes a @c ok().  El compilador suele inlinear todo.
     */
    [[nodiscard]] T &value() & noexcept { return value_; }

    /**
     * @brief Acceso const al valor.  Comportamiento indefinido si @c !ok().
     */
    [[nodiscard]] const T &value() const & noexcept { return value_; }

    /**
     * @brief Mueve el valor fuera del Result.  Comportamiento indefinido si @c
     * !ok().
     */
    [[nodiscard]] T &&value() && noexcept { return std::move(value_); }

  private:
    bool has_value_ = false; ///< Discriminador: true si value_ es valido.
    T value_{};              ///< Valor por defecto si no hay exito.
};

} // namespace vx

#endif // VX_DIAGNOSTIC_H
