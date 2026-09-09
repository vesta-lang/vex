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
#include "vx/borrow/place.h" // EL LUGAR prestado, que sustituye al nombre
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
 * @brief Un prestamo vivo sobre UN LUGAR.
 *
 * Antes habia uno por NOMBRE de variable, y ahi estaba el fallo: `p.a` y `p.b`
 * compartian registro -- se rechazaban entre si sin tocarse -- mientras que dos
 * nombres de la misma region tenian registros distintos y no chocaban.  Los dos
 * errores, opuestos, salian de la misma causa.
 *
 * Ahora el registro es del LUGAR (@ref borrow::Place), y de una raiz puede
 * haber varios vivos a la vez.  Guarda ademas lo que hace falta para un mensaje
 * expresivo: que clase de prestamo es, donde se tomo, y cuantos compartidos
 * coexisten sobre ese mismo lugar.
 */
struct BorrowRecord {
    /// El lugar prestado.  Con camino vacio es la variable entera.
    borrow::Place place;
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
 * @struct OwnerState
 * @brief Lo que se sabe de una RAIZ: su categoria y lo que hay prestado de ella.
 *
 * La raiz es el indice, no la unidad: de `p` pueden estar vivos a la vez un
 * prestamo de `p.a` y otro de `p.b`, que no se estorban.  Por eso la categoria
 * -- si es local, parametro, global o campo -- vive aqui, que es de quien se
 * predica, y el estado del prestamo vive en cada @ref BorrowRecord.
 *
 * @par Y por eso el coste no crece con el programa
 * Buscar es O(1) por la raiz, y lo que se recorre despues son solo los
 * prestamos VIVOS de ESA raiz -- se borran al soltarlos --, que son los que el
 * programa tenga a la vez sobre una variable: un punyado.  Nunca un barrido de
 * todos los duenos de la funcion, que es lo que habria costado guardar los
 * lugares en una lista plana.
 */
struct OwnerState {
    /// Categoria de la raiz.  Decide si un prestamo puede escapar por `return`.
    OwnerKind owner_kind = OwnerKind::Local;
    /// Los prestamos VIVOS sobre esta raiz, uno por lugar.
    std::vector<BorrowRecord> live;
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

    /**
     * @brief Procesa la creacion de un prestamo sobre @p place.
     *
     * Valida R1/R2 contra todo lo que ya este prestado de esa raiz y PUEDA
     * pisarse con @p place -- que no es lo mismo que llamarse igual: `p.a` y
     * `p.b` conviven, `p` y `p.a` no --, y actualiza el estado.
     *
     * @param place        La memoria que se presta.
     * @param borrower_name Como se llama quien se la queda, para citarlo.
     * @param loc_borrow   Donde se toma.
     * @param is_mut       Si es exclusivo (@c borrow_mut<T>).
     * @return @c true si el prestamo es valido; @c false si se reporto error.
     */
    bool on_lend(const borrow::Place &place, const std::string &borrower_name,
                 SourceLoc loc_borrow, bool is_mut);

    /// @brief La variable ENTERA, que es el lugar sin camino.
    ///
    /// Existe porque hay sitios donde lo prestado es de verdad la variable
    /// entera -- `lend(x)` --, y obligarles a construir un lugar vacio solo
    /// serviria para que cada uno lo construyera a su manera.
    bool on_lend(const std::string &owner_name,
                 const std::string &borrower_name, SourceLoc loc_borrow,
                 bool is_mut);

    /// Procesa la destruccion (scope exit) de un borrow.  Decrementa
    /// el contador shared o resetea Mutable -> None.
    void on_borrow_drop(const std::string &borrower_name, SourceLoc loc_drop);

    /// Procesa un uso directo del owner (lectura o mutacion).
    /// @p is_mutation = false (lectura) -> solo prohibido si Mutable.
    /// @p is_mutation = true  (escritura) -> prohibido si Shared o Mutable.
    ///
    /// Mira todo lo prestado de esa raiz que pueda pisarse con el lugar usado,
    /// no solo lo que se llame igual: leer `p` con `p.a` prestado en exclusiva
    /// es leer memoria prestada, y escribir `p.b` con `p.a` prestado no lo es.
    /// @return true si el uso es valido.
    bool on_owner_use(const borrow::Place &place, SourceLoc loc_use,
                      bool is_mutation);
    /// @brief La variable entera.  @see on_lend(const std::string&,...)
    bool on_owner_use(const std::string &owner_name, SourceLoc loc_use,
                      bool is_mutation);

    /// Procesa @c move(owner).  Prohibido si tiene cualquier borrow
    /// activo (Shared o Mutable) que pueda pisarse con lo que se mueve.
    /// @return true si el move es valido.
    bool on_owner_move(const borrow::Place &place, SourceLoc loc_move);
    /// @brief La variable entera.  @see on_lend(const std::string&,...)
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

    /// @brief El LUGAR del que salio @p borrower_name, no solo su raiz.
    ///
    /// Es lo que hace que un `*p` deje de ser un agujero: quien construye un
    /// lugar sobre un prestamo pregunta aqui y sustituye por la memoria del
    /// dueno, en vez de anyadir un paso sin resolver.  Devuelve un lugar sin
    /// raiz -- @c Place::valid() falso -- si no es un prestamo registrado.
    borrow::Place owner_place_of(const std::string &borrower_name) const;

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
    /// @brief La misma, con el LUGAR completo del que sale el prestamo.
    void register_borrow(const std::string &borrower_name,
                         const borrow::Place &owner, bool is_mut);

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
    /// Por RAIZ, no por lugar: buscar es O(1) y lo que se recorre despues son
    /// los prestamos vivos de esa raiz.  @see OwnerState
    std::unordered_map<std::string, OwnerState> owners_;

    /// @brief El prestamo vivo de @p place en @p st, si lo hay.
    ///
    /// EXACTAMENTE ese lugar, no uno que se le parezca: sirve para acumular
    /// compartidos del mismo sitio, y sumar ahi dos que solo se SOLAPAN daria
    /// un recuento que no corresponde a nada.
    static BorrowRecord *find_same_place_(OwnerState &st,
                                          const borrow::Place &place) noexcept;

    /// @brief El primer prestamo vivo de @p st que puede pisarse con @p place.
    ///
    /// Devuelve tambien POR QUE, cuando el solape no se pudo descartar en vez
    /// de demostrarse: es lo que separa "estos dos son la misma memoria" de
    /// "no he podido separarlos", y el diagnostico dice cosas distintas.
    static const BorrowRecord *
    find_overlapping_(const OwnerState &st, const borrow::Place &place,
                      borrow::PlaceUnknown *why) noexcept;

    /// Mapa borrower_name -> lugar prestado + is_mut, para que
    /// @c on_borrow_drop sepa que prestamo actualizar.
    struct BorrowMeta {
        /// El LUGAR del que salio, no solo su raiz: es lo que permite volver a
        /// encontrar el registro exacto al soltarlo.
        borrow::Place owner;
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

    /// @brief Dice POR QUE no se pudieron separar dos lugares, si es el caso.
    ///
    /// Va detras de los tres errores y solo aparece cuando el choque NO se
    /// demostro: entonces el mensaje principal seria una acusacion mas dura de
    /// lo que se sabe, y esta nota lo coloca en su sitio diciendo que pieza
    /// falta -- el valor del indice, o la region del puntero -- y quien la
    /// pone.  Sin ella, "estos dos se pisan" y "no he podido separarlos" se
    /// leen igual, y solo el segundo se arregla escribiendo otra cosa.
    void note_unproven_overlap_(SourceLoc loc, borrow::PlaceUnknown why);

    /// Helper: emite error de R1 (exclusividad mutable) con dos puntos
    /// citados (toma original + toma conflictiva).  Cita el LUGAR, no la raiz:
    /// con `p.a` prestado, decir que el problema es `p` manda a mirar donde no
    /// es.
    void error_aliasing(SourceLoc loc_conflict, const borrow::Place &place,
                        const BorrowRecord &rec, bool trying_mut,
                        borrow::PlaceUnknown why);
    /// Helper: emite error de R3 (use-while-borrowed).
    void error_use_while_borrowed(SourceLoc loc_use, const borrow::Place &place,
                                  const BorrowRecord &rec, bool is_mutation,
                                  borrow::PlaceUnknown why);
    /// Helper: emite error de R3 (move-while-borrowed).
    void error_move_while_borrowed(SourceLoc loc_move,
                                   const borrow::Place &place,
                                   const BorrowRecord &rec,
                                   borrow::PlaceUnknown why);
};

} // namespace vx

#endif // VX_BORROW_CHECKER_H
