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
 * @file borrow_checker.cpp
 * @brief Implementacion del borrow checker compile-time de Vesta.
 *
 * Mantiene un mapa por funcion de @c owner -> BorrowRecord (estado del
 * prestamo) y un mapa @c borrower -> BorrowMeta (referencia al owner).
 * Cada evento del lowering/type_checker valida las reglas R1-R4 y, si
 * detecta violacion, emite uno o mas diagnosticos en la instancia
 * @c Diagnostics asociada.
 *
 * Los mensajes citan AMBOS sitios (el origen del borrow conflictivo y
 * la operacion que viola la regla), igual que el output de @c rustc:
 *
 *   error: no se puede mover 'p' porque ya esta prestado
 *      --> foo.vx:5:12
 *       | 5 |     unique<i32> q = move(p);
 *       |   |                     ^^^^^^^ movido aqui
 *       | 3 |     borrow<i32> r = lend(p);
 *       |   |                     ------- prestamo activo desde aqui
 */

#include "vx/borrow_checker.h"

#include "vx/diag/diag_catalog.h" // las palabras del mensaje, por idioma

#include <utility>

namespace vx {

namespace {
/**
 * @brief El codigo de catalogo que nombra una clase de prestamo.
 * @param k La clase.
 * @return El codigo, para resolverlo al idioma activo.
 *
 * Devuelve un CODIGO y no una palabra porque "compartido" y "exclusivo" son
 * parte de la frase, y una frase a medio traducir es peor que una sin traducir.
 * No son palabras clave del lenguaje -- esas son `borrow<T>` y `borrow_mut<T>`,
 * y no se traducen nunca --, son la descripcion de lo que hace cada una.
 */
const char *kind_code(BorrowKind k) noexcept {
    return k == BorrowKind::Mutable ? "VX2040" : "VX2039";
}

/// La clase de prestamo, ya en el idioma activo.
std::string kind_word(BorrowKind k) {
    return diag::format(kind_code(k), {});
}
} // namespace

// -----------------------------------------------------------------------
// API basica.
// -----------------------------------------------------------------------

void BorrowChecker::reset() {
    owners_.clear();
    borrows_.clear();
    pending_last_use_.clear();
}

void BorrowChecker::declare_owner(const std::string &owner_name,
                                  OwnerKind kind) {
    // Insertamos un record en estado None si no existia.  Si ya
    // existia, actualizamos solo el owner_kind (puede haber sido
    // registrado implicitamente por on_lend como Local-default).
    auto it = owners_.find(owner_name);
    if (it == owners_.end()) {
        BorrowRecord rec;
        rec.owner_kind = kind;
        owners_.emplace(owner_name, rec);
    } else {
        it->second.owner_kind = kind;
    }
}

OwnerKind
BorrowChecker::owner_kind_of(const std::string &owner_name) const noexcept {
    auto it = owners_.find(owner_name);
    if (it == owners_.end()) return OwnerKind::Local; // defensivo
    return it->second.owner_kind;
}

std::string
BorrowChecker::root_owner_of(const std::string &borrower_name) const {
    // Caminamos la cadena borrower->owner hasta llegar a un nombre
    // que NO esta en borrows_ (es un owner final, no un borrow).
    // Cota dura para evitar bucles si hubiera self-referencias.
    std::string cur = borrower_name;
    for (int depth = 0; depth < 64; ++depth) {
        auto it = borrows_.find(cur);
        if (it == borrows_.end()) return cur;
        // Caso self-referencial (param borrow registrado como
        // borrow de si mismo); su owner es el mismo nombre y aqui
        // paramos.
        if (it->second.owner == cur) return cur;
        cur = it->second.owner;
    }
    return cur;
}

void BorrowChecker::set_last_use(const std::string &borrower_name,
                                 uint32_t last_use_idx) {
    // F1 - el pre-pase llama aqui ANTES de que los borrows existan
    // en borrows_; los almacenamos en pending_last_use_ y los
    // consume register_borrow al crear cada borrow.  Si el borrow
    // ya existe (caso de param borrows pre-registrados), actualizamos
    // tambien la entrada activa.
    pending_last_use_[borrower_name] = last_use_idx;
    auto it = borrows_.find(borrower_name);
    if (it != borrows_.end()) {
        it->second.last_use_idx = last_use_idx;
    }
}

void BorrowChecker::advance_stmt(uint32_t current_stmt_idx) {
    // F1 NLL: para cada borrow activo cuyo last_use < current_stmt_idx,
    // simular un drop (NLL: el borrow esta muerto tras su ultimo uso).
    //
    // Recolectamos las entradas a dropear primero para no invalidar
    // iteradores al modificar borrows_.
    std::vector<std::string> to_drop;
    for (const auto &kv : borrows_) {
        // Param borrows self-referenciales (owner == borrower) NO
        // se dropean por NLL porque su lifetime cubre la funcion
        // entera y el "uso" es implicito al final.
        if (kv.second.owner == kv.first) continue;
        if (kv.second.last_use_idx > 0 &&
            current_stmt_idx > kv.second.last_use_idx) {
            to_drop.push_back(kv.first);
        }
    }
    for (const auto &nm : to_drop) {
        // No emitimos diagnostico aqui (silent drop por NLL).
        // @c on_borrow_drop erase el entry de borrows_ y actualiza
        // el owner record.
        on_borrow_drop(nm, SourceLoc{});
    }
}

void BorrowChecker::register_borrow(const std::string &borrower_name,
                                    const std::string &owner_name,
                                    bool is_mut) {
    BorrowMeta m{owner_name, is_mut, 0, false, ""};
    // F1 - consultar pending_last_use_ poblado por el pre-pase.
    // Si no hay info, last_use_idx queda en 0 -> NLL no dropea
    // (conservador: borrow vive hasta el RET de la funcion).
    auto plu = pending_last_use_.find(borrower_name);
    if (plu != pending_last_use_.end()) {
        m.last_use_idx = plu->second;
    }
    borrows_[borrower_name] = m;
}

bool BorrowChecker::suspend_for_reborrow(
    const std::string &source_borrower_name) {
    // El source es la variable borrow intermedia (e.g. m1).  Su owner
    // raiz es donde tenemos que aplicar el suspend (porque el record
    // se mantiene en el OWNER, no en el borrow intermedio).
    auto it = borrows_.find(source_borrower_name);
    if (it == borrows_.end()) return false;
    const std::string root = root_owner_of(source_borrower_name);
    auto orec = owners_.find(root);
    if (orec == owners_.end()) return false;
    BorrowRecord &rec = orec->second;
    // Solo suspendemos si el owner esta efectivamente en estado
    // Mutable.  Si esta Shared o None, el reborrow normal funciona
    // sin necesidad de suspend (shared puede coexistir mas de uno).
    if (rec.kind != BorrowKind::Mutable) return false;
    BorrowRecord::SuspendedState s;
    s.kind = rec.kind;
    s.shared_count = rec.shared_count;
    s.loc_taken = rec.loc_taken;
    s.borrower_name = rec.borrower_name;
    rec.suspend_stack.push_back(std::move(s));
    // Limpiar para que @c on_lend pueda registrar el reborrow nuevo
    // sin violar R1.
    rec.kind = BorrowKind::None;
    rec.shared_count = 0;
    rec.borrower_name.clear();
    return true;
}

void BorrowChecker::mark_as_reborrow(const std::string &reborrower_name,
                                     const std::string &source_borrower_name) {
    auto it = borrows_.find(reborrower_name);
    if (it == borrows_.end()) return;
    it->second.reborrow_source = source_borrower_name;
}

// -----------------------------------------------------------------------
// Eventos: on_lend, on_borrow_drop, on_owner_use, on_owner_move,
//          on_borrow_escape.
// -----------------------------------------------------------------------

bool BorrowChecker::on_lend(const std::string &owner_name,
                            const std::string &borrower_name,
                            SourceLoc loc_borrow, bool is_mut) {
    auto &rec = owners_[owner_name]; // crea si no existe (estado None).

    // R1: si hay un mutable activo, prohibir cualquier nuevo borrow.
    if (rec.kind == BorrowKind::Mutable) {
        error_aliasing(loc_borrow, owner_name, rec, is_mut);
        return false;
    }
    // R2 (caso mut): si hay shared activos, prohibir borrow_mut.
    if (rec.kind == BorrowKind::Shared && is_mut) {
        error_aliasing(loc_borrow, owner_name, rec, /*trying_mut=*/true);
        return false;
    }

    // Validacion OK; actualizar estado.
    if (is_mut) {
        rec.kind = BorrowKind::Mutable;
        rec.shared_count = 0;
        rec.loc_taken = loc_borrow;
        rec.borrower_name = borrower_name;
    } else {
        if (rec.kind == BorrowKind::None) {
            rec.kind = BorrowKind::Shared;
            rec.shared_count = 1;
            rec.loc_taken = loc_borrow;
            rec.borrower_name = borrower_name;
        } else {
            // Ya hay Shared; solo incrementamos el contador.  Mantenemos
            // loc_taken del primero (suficiente para errores; los
            // siguientes se pueden citar dinamicamente si fuera necesario).
            rec.shared_count++;
        }
    }
    register_borrow(borrower_name, owner_name, is_mut);
    return true;
}

void BorrowChecker::on_borrow_drop(const std::string &borrower_name,
                                   SourceLoc /*loc_drop*/) {
    auto it = borrows_.find(borrower_name);
    if (it == borrows_.end()) {
        // El borrow no estaba registrado (puede ser un borrow de
        // expresion temporal, no de variable nombrada).  No error.
        return;
    }
    const std::string owner = it->second.owner;
    const bool is_mut = it->second.is_mut;
    const std::string reborrow_source = it->second.reborrow_source;
    borrows_.erase(it);

    auto orec = owners_.find(owner);
    if (orec == owners_.end()) return; // defensive
    BorrowRecord &rec = orec->second;
    if (is_mut) {
        rec.kind = BorrowKind::None;
        rec.shared_count = 0;
        rec.borrower_name.clear();
    } else {
        if (rec.shared_count > 0) rec.shared_count--;
        if (rec.shared_count == 0) {
            rec.kind = BorrowKind::None;
            rec.borrower_name.clear();
        }
    }

    // F3 ext - si este borrow era un reborrow (tiene reborrow_source),
    // restauramos el estado suspendido del owner desde el tope del
    // suspend_stack.  Solo si el owner quedo en None tras el drop
    // (caso normal: el reborrow era el unico activo).  Si hay otros
    // borrows activos del mismo owner (raro pero posible si el frontend
    // crea reborrows multiples concurrentes), no restauramos para no
    // colisionar; el estado se restaurara cuando todos sean dropeados.
    if (!reborrow_source.empty() && !rec.suspend_stack.empty() &&
        rec.kind == BorrowKind::None) {
        BorrowRecord::SuspendedState s = std::move(rec.suspend_stack.back());
        rec.suspend_stack.pop_back();
        rec.kind = s.kind;
        rec.shared_count = s.shared_count;
        rec.loc_taken = s.loc_taken;
        rec.borrower_name = std::move(s.borrower_name);
    }
}

bool BorrowChecker::on_owner_use(const std::string &owner_name,
                                 SourceLoc loc_use, bool is_mutation) {
    auto it = owners_.find(owner_name);
    if (it == owners_.end()) return true; // no borrows -> OK
    const BorrowRecord &rec = it->second;
    if (rec.kind == BorrowKind::None) return true;
    // Lectura del owner: prohibida si hay Mutable activo.
    if (!is_mutation) {
        if (rec.kind == BorrowKind::Mutable) {
            error_use_while_borrowed(loc_use, owner_name, rec,
                                     /*is_mutation=*/false);
            return false;
        }
        return true; // Shared + lectura: permitido (lectura coexiste).
    }
    // Mutacion del owner: prohibida si hay cualquier borrow activo.
    error_use_while_borrowed(loc_use, owner_name, rec, /*is_mutation=*/true);
    return false;
}

bool BorrowChecker::on_owner_move(const std::string &owner_name,
                                  SourceLoc loc_move) {
    auto it = owners_.find(owner_name);
    if (it == owners_.end()) return true;
    const BorrowRecord &rec = it->second;
    if (rec.kind == BorrowKind::None) return true;
    error_move_while_borrowed(loc_move, owner_name, rec);
    return false;
}

bool BorrowChecker::on_borrow_escape(const std::string &borrower_name,
                                     SourceLoc loc_escape,
                                     const std::string &escape_kind) {
    // F2 - el OwnerKind decide si el escape es valido.
    // Buscamos el owner via borrows_; si no esta registrado, hay
    // un bug de ordering -> conservador: tratar como Local.
    auto it = borrows_.find(borrower_name);
    std::string owner = "?";
    OwnerKind ok = OwnerKind::Local;
    if (it != borrows_.end()) {
        owner = it->second.owner;
        ok = owner_kind_of(owner);
    }
    // Param, Global, Field -> lifetime cubre la funcion -> escape valido.
    if (ok == OwnerKind::Param || ok == OwnerKind::Global ||
        ok == OwnerKind::Field) {
        return true;
    }
    // Owner es local -> el borrow no puede sobrevivir a la funcion.
    diags_.diag(loc_escape, DiagLevel::ERR, "VX2037",
                {owner, borrower_name, escape_kind});
    diags_.diag(loc_escape, DiagLevel::NOTE, "VX2038", {});
    return false;
}

// -----------------------------------------------------------------------
// Helpers de error.
// -----------------------------------------------------------------------

void BorrowChecker::note_previous_borrow_(const BorrowRecord &rec) {
    // En un sitio porque la ponen los TRES errores: quien presta encima, quien
    // usa al dueno prestado y quien lo mueve.  Con tres copias, el dia que la
    // nota cambie cambiaria en dos.
    const std::string clase = kind_word(rec.kind);
    if (!rec.borrower_name.empty())
        diags_.diag(rec.loc_taken, DiagLevel::NOTE, "VX2028",
                    {clase, rec.borrower_name});
    else
        diags_.diag(rec.loc_taken, DiagLevel::NOTE, "VX2029", {clase});
}

void BorrowChecker::error_aliasing(SourceLoc loc_conflict,
                                   const std::string &owner_name,
                                   const BorrowRecord &rec, bool trying_mut) {
    const std::string quiere =
        diag::format(trying_mut ? "VX2040" : "VX2039", {});
    if (rec.kind == BorrowKind::Mutable)
        diags_.diag(loc_conflict, DiagLevel::ERR, "VX2026",
                    {owner_name, quiere, kind_word(rec.kind)});
    else
        diags_.diag(loc_conflict, DiagLevel::ERR, "VX2027",
                    {owner_name, quiere, std::to_string(rec.shared_count)});
    note_previous_borrow_(rec);
    diags_.diag(loc_conflict, DiagLevel::NOTE, "VX2030", {quiere});
}

void BorrowChecker::error_use_while_borrowed(SourceLoc loc_use,
                                             const std::string &owner_name,
                                             const BorrowRecord &rec,
                                             bool is_mutation) {
    if (is_mutation)
        diags_.diag(loc_use, DiagLevel::ERR, "VX2031",
                    {owner_name, kind_word(rec.kind)});
    else
        diags_.diag(loc_use, DiagLevel::ERR, "VX2032", {owner_name});
    note_previous_borrow_(rec);
    diags_.diag(loc_use, DiagLevel::NOTE, "VX2033",
                {diag::format(is_mutation ? "VX2041" : "VX2042", {})});
}

void BorrowChecker::error_move_while_borrowed(SourceLoc loc_move,
                                              const std::string &owner_name,
                                              const BorrowRecord &rec) {
    diags_.diag(loc_move, DiagLevel::ERR, "VX2034",
                {owner_name, kind_word(rec.kind)});
    note_previous_borrow_(rec);
    diags_.diag(loc_move, DiagLevel::NOTE, "VX2035", {});
    diags_.diag(loc_move, DiagLevel::NOTE, "VX2036", {});
}

} // namespace vx
