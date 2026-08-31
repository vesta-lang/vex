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
 * @file borrow_checker.h
 * @brief Borrow checker compile-time estilo Rust para Vesta.
 *
 * El borrow checker valida en tiempo de compilacion que los punteros
 * (borrows) cumplen las reglas de aliasing y lifetime de Rust:
 *
 *   R1 - Exclusividad mutable:
 *        Si existe un @c borrow_mut<T> activo de @c X, NO se pueden
 *        crear mas borrows (ni shared ni mut) de @c X.
 *
 *   R2 - Inmutables compatibles:
 *        Pueden coexistir N @c borrow<T> de @c X mientras NINGUN
 *        @c borrow_mut<T> de @c X este activo.
 *
 *   R3 - No-uso-mientras-prestado:
 *        El owner @c X no se puede:
 *          - mover (@c move(X)) mientras tenga borrows activos.
 *          - mutar directamente (@c X = value) mientras este prestado.
 *          - leer directamente (use de @c X en expresion) mientras
 *            tenga un @c borrow_mut activo.
 *
 *   R4 - Lifetime:
 *        Un borrow no puede sobrevivir a su owner.  Especificamente:
 *          - return de un borrow de un local del callee = error.
 *          - asignacion a campo/slot/global de un borrow local = error.
 *
 * Los borrows son @c host_ptr en runtime (8 bytes, identico a @c T*).
 * Toda la seguridad es compile-time -> cero overhead vs un raw pointer.
 *
 * Mensajes de error: el borrow checker mantiene SourceLoc de cada
 * "evento" (creacion del borrow, ultimo uso) para producir mensajes
 * con multiples puntos referenciados, igual que rustc.
 */

#ifndef VX_BORROW_CHECKER_H
#define VX_BORROW_CHECKER_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "vx/ast.h"
#include "vx/diagnostic.h"
#include "vx/token.h"
#include "vx/types.h"

namespace vx {

/**
 * @enum BorrowKind
 * @brief Tipo de prestamo activo sobre una variable.
 */
enum class BorrowKind : uint8_t {
    /// No hay borrows activos.  El owner puede leer, mutar, mover.
    None = 0,
    /// Uno o mas @c borrow<T> activos.  El owner puede leer pero NO
    /// mutar/mover.  Otros borrows shared se pueden crear.
    Shared,
    /// Un @c borrow_mut<T> activo.  El owner NO puede leer/mutar/mover.
    /// No se pueden crear mas borrows.
    Mutable,
    /// El owner ha sido reborrowed (otro borrow_mut deriva de el).
    /// El owner NO puede ser usado mientras el reborrow este vivo;
    /// cuando el reborrow dropea, vuelve a Mutable.  Estado intermedio
    /// usado para soportar "two- borrows" estilo Rust.
    SuspendedByReborrow,
};

/**
 * @enum OwnerKind
 * @brief Categoria de la variable que es objeto de prestamo.
 *
 * El borrow checker usa esta info para decidir si un borrow puede
 * escapar de la funcion via return.  Local -> NO; Param/Global ->
 * SI (su lifetime cubre la funcion completa).
 */
enum class OwnerKind : uint8_t {
    Local = 0, ///< Declarada con var-decl en el body de la funcion.
    Param,     ///< Parametro de la funcion (vive durante toda la funcion).
    Global,    ///< Variable global del modulo.
    Field,     ///< Campo accedido via `this.field`.
};

/**
 * @struct BorrowRecord
 * @brief Estado de borrows activos para un local.
 *
 * Almacena la informacion necesaria para emitir mensajes de error
 * expresivos: que tipo de borrow esta activo, en cual SourceLoc se
 * tomo, y cuantos shared coexisten (para shared con N>1, citamos el
 * mas reciente).
 */
struct BorrowRecord {
    BorrowKind kind = BorrowKind::None;
    /// Numero de borrows shared activos (>=1 cuando kind==Shared, 0 sino).
    uint32_t shared_count = 0;
    /// Localizacion del primer (y unico, si Mutable) borrow activo.
    /// Para Shared con N>1 guarda el primero - los siguientes se citan
    /// secundariamente en el diagnostic note.
    SourceLoc loc_taken{};
    /// Si Mutable: nombre de la variable que captura el borrow_mut
    /// (para citar en errores).  Si Shared: nombre del primer borrow.
    std::string borrower_name;
    /// Categoria del owner.  Por defecto Local.
    OwnerKind owner_kind = OwnerKind::Local;
    /// F3 ext - Pila de estados suspendidos por cadenas de reborrows.
    /// Cada vez que un nuevo borrow se "reborrowea" desde otro borrow
    /// del mismo owner, el estado activo se push aqui y el owner queda
    /// en estado None temporalmente para que @c on_lend pueda registrar
    /// el reborrow nuevo.  Al hacer @c on_borrow_drop de un reborrow,
    /// si su @c reborrow_source no esta vacio, se hace pop aqui y se
    /// restaura el estado anterior.
    ///
    /// Soporta cadenas arbitrarias: m1 -> m2 -> m3 -> ...; cuando m3
    /// dropea, m2 vuelve a ser el activo; cuando m2 dropea, m1 vuelve;
    /// cuando m1 dropea, el owner vuelve a None.
    struct SuspendedState {
        BorrowKind kind = BorrowKind::None;
        uint32_t shared_count = 0;
        SourceLoc loc_taken{};
        std::string borrower_name;
    };
    std::vector<SuspendedState> suspend_stack;
};

/**
 * @class BorrowChecker
 * @brief Validador compile-time de las reglas de borrow.
 *
 * Una instancia se crea por funcion en analisis.  El TypeChecker
 * la invoca en el lugar oportuno durante el segundo pase (cuerpos
 * de funciones).  La interfaz publica refleja eventos de alto nivel:
 *
 *   on_lend(owner, borrower_name, loc, is_mut)
 *   on_borrow_drop(borrower_name, loc)
 *   on_owner_use(owner, loc, is_mutation)
 *   on_owner_move(owner, loc)
 *   on_borrow_escape(borrower_name, loc, kind)   -- return / field=
 *
 * Cada evento valida las reglas R1-R4 y, si encuentra violacion,
 * emite el error en @c diags_ con mensajes que incluyen ambas
 * localizaciones (la creacion del borrow + el uso conflictivo).
 */
class BorrowChecker {
  public:
    explicit BorrowChecker(Diagnostics &diags) : diags_(diags) {}

    /// Restaura el estado para empezar a chequear una nueva funcion.
    void reset();

    /// Registra que @p owner es una variable que puede ser prestada.
    /// Llamar al ver `VarDeclStmt` para variables que el usuario
    /// pueda decidir prestar.  No es estrictamente necesario:
    /// @c on_lend implicitamente registra el owner si no existe.
    void declare_owner(const std::string &owner_name,
                       OwnerKind kind = OwnerKind::Local);

    /// Procesa la creacion de un borrow.  Valida R1/R2 y actualiza
    /// el estado.  @p is_mut indica si es @c borrow_mut<T>.
    /// @return true si el borrow es valido; false si se reporto error.
    bool on_lend(const std::string &owner_name,
                 const std::string &borrower_name, SourceLoc loc_borrow,
                 bool is_mut);

    /// Procesa la destruccion (scope exit) de un borrow.  Decrementa
    /// el contador shared o resetea Mutable -> None.
    void on_borrow_drop(const std::string &borrower_name, SourceLoc loc_drop);

    /// Procesa un uso directo del owner (lectura o mutacion).
    /// @p is_mutation = false (lectura) -> solo prohibido si Mutable.
    /// @p is_mutation = true  (escritura) -> prohibido si Shared o Mutable.
    /// @return true si el uso es valido.
    bool on_owner_use(const std::string &owner_name, SourceLoc loc_use,
                      bool is_mutation);

    /// Procesa @c move(owner).  Prohibido si tiene cualquier borrow
    /// activo (Shared o Mutable).
    /// @return true si el move es valido.
    bool on_owner_move(const std::string &owner_name, SourceLoc loc_move);

    /// Procesa el escape de un borrow (return, asignacion a field,
    /// asignacion a slot via deref).  Internamente consulta el
    /// @c OwnerKind del owner del borrow para decidir: borrow de
    /// param/global -> permitido (lifetime cubre la funcion); borrow
    /// de local -> error.
    /// @return true si el escape es valido.
    bool on_borrow_escape(const std::string &borrower_name,
                          SourceLoc loc_escape, const std::string &escape_kind);

    /// Busca el OwnerKind de un owner registrado.  Devuelve Local si
    /// no esta registrado (caso defensivo).
    OwnerKind owner_kind_of(const std::string &owner_name) const noexcept;

    /// F3 - resuelve el owner ROOT de @p borrower_name siguiendo la
    /// cadena de reborrows.  Devuelve "" si no es un borrower
    /// registrado.  Util para reborrow: `lend(b)` donde b es borrow_var
    /// produce un nuevo borrow sobre el root owner de b.
    std::string root_owner_of(const std::string &borrower_name) const;

    /// F1 - registra @p last_use_idx como el ultimo indice de stmt
    /// en el que @p borrower_name aparece referenciado.  El type
    /// checker computa esto via pre-pase y lo entrega antes de empezar
    /// el chequeo del body.  El borrow checker usa este info en
    /// @c advance_stmt para liberar borrows cuyo last_use ya paso.
    void set_last_use(const std::string &borrower_name, uint32_t last_use_idx);

    /// F1 - notifica al borrow checker que el chequeo avanzo al
    /// stmt @p current_stmt_idx.  Para cada borrow activo cuyo
    /// last_use_idx < current_stmt_idx, simula on_borrow_drop
    /// automaticamente (NLL: el borrow esta efectivamente muerto
    /// tras su ultimo uso, aunque el var aun este en scope).
    void advance_stmt(uint32_t current_stmt_idx);

    /// Asocia un borrow recien creado con su owner para que el
    /// drop pueda decrementar el contador correcto.  Llamado por
    /// @c on_lend internamente; expuesto para casos especiales.
    void register_borrow(const std::string &borrower_name,
                         const std::string &owner_name, bool is_mut);

    /// F3 ext - Suspend reborrow.  Si @p source_borrower_name es un
    /// borrow_mut activo, se push su estado al @c suspend_stack del
    /// owner y se deja el owner en estado None para que @c on_lend
    /// posterior pueda registrar el reborrow.  El siguiente
    /// @c on_borrow_drop sobre el reborrow restaurara el estado.
    ///
    /// Tras esta llamada, el caller debe llamar @c on_lend con el
    /// root_owner y, a continuacion, marcar el reborrow recien
    /// creado con @c mark_as_reborrow para enlazar source <-> reborrow.
    ///
    /// @return true si suspendio efectivamente (origen era borrow_mut
    ///         activo); false si el origen no necesita suspend (e.g.
    ///         era borrow shared, donde el reborrow shared simplemente
    ///         incrementa el contador).
    bool suspend_for_reborrow(const std::string &source_borrower_name);

    /// F3 ext - Marca el borrow @p reborrower_name como reborrow del
    /// @p source_borrower_name.  Esto guarda el enlace en
    /// @c BorrowMeta::reborrow_source para que @c on_borrow_drop sepa
    /// si tras dropear este reborrow debe restaurar (pop) el estado
    /// suspendido del owner.
    void mark_as_reborrow(const std::string &reborrower_name,
                          const std::string &source_borrower_name);

  private:
    Diagnostics &diags_;
    std::unordered_map<std::string, BorrowRecord> owners_;
    /// Mapa borrower_name -> owner_name + is_mut, para que
    /// @c on_borrow_drop sepa que owner actualizar.
    struct BorrowMeta {
        std::string owner;
        bool is_mut;
        uint32_t last_use_idx = 0; // F1 - poblado por set_last_use
        bool already_dropped = false;
        /// F3 ext - si no esta vacio, este borrow es un reborrow del
        /// borrow llamado @c reborrow_source.  Al dropear este borrow
        /// hacemos pop del @c suspend_stack del owner y restauramos
        /// el estado anterior.
        std::string reborrow_source;
    };
    std::unordered_map<std::string, BorrowMeta> borrows_;
    /// F1 - pre-pase de NLL: last_use_idx por NOMBRE de variable.
    /// Poblado por @c set_last_use antes de empezar el chequeo.
    /// Consultado por @c register_borrow al crear cada borrow.
    std::unordered_map<std::string, uint32_t> pending_last_use_;

    /// Emite la nota que cita DONDE se tomo el prestamo que estorba.
    ///
    /// La ponen los tres errores -- prestar encima, usar al dueno prestado y
    /// moverlo --, asi que vive en un sitio: con tres copias, el dia que la
    /// nota cambie cambiaria en dos.
    void note_previous_borrow_(const BorrowRecord &rec);

    /// Helper: emite error de R1 (exclusividad mutable) con dos puntos
    /// citados (toma original + toma conflictiva).
    void error_aliasing(SourceLoc loc_conflict, const std::string &owner_name,
                        const BorrowRecord &rec, bool trying_mut);
    /// Helper: emite error de R3 (use-while-borrowed).
    void error_use_while_borrowed(SourceLoc loc_use,
                                  const std::string &owner_name,
                                  const BorrowRecord &rec, bool is_mutation);
    /// Helper: emite error de R3 (move-while-borrowed).
    void error_move_while_borrowed(SourceLoc loc_move,
                                   const std::string &owner_name,
                                   const BorrowRecord &rec);
};

} // namespace vx

#endif // VX_BORROW_CHECKER_H
