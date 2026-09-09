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

#include "vx/borrow/borrow_checker.h"

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
    // La categoria es de la RAIZ, no de cada lugar: que `p` sea un parametro
    // no cambia porque se preste `p.a`.  Si ya estaba (registrada al vuelo por
    // un prestamo), solo se corrige la categoria.
    owners_[owner_name].owner_kind = kind;
}

OwnerKind
BorrowChecker::owner_kind_of(const std::string &owner_name) const noexcept {
    auto it = owners_.find(owner_name);
    if (it == owners_.end()) return OwnerKind::Local; // defensivo
    return it->second.owner_kind;
}

BorrowRecord *
BorrowChecker::find_same_place_(OwnerState &st,
                                const borrow::Place &place) noexcept {
    for (BorrowRecord &r : st.live)
        if (borrow::places_same(r.place, place)) return &r;
    return nullptr;
}

const BorrowRecord *
BorrowChecker::find_overlapping_(const OwnerState &st,
                                 const borrow::Place &place,
                                 borrow::PlaceUnknown *why) noexcept {
    /* Solo los VIVOS, que es lo que hay en la lista: los soltados se borran.
     * Por eso esto es un punyado de comparaciones y no un barrido. */
    for (const BorrowRecord &r : st.live) {
        if (r.kind == BorrowKind::None) continue;
        borrow::PlaceUnknown w = borrow::PlaceUnknown::None;
        if (borrow::places_may_overlap(r.place, place, &w)) {
            if (why != nullptr) *why = w;
            return &r;
        }
    }
    if (why != nullptr) *why = borrow::PlaceUnknown::None;
    return nullptr;
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
        if (it->second.owner.root == cur) return cur;
        cur = it->second.owner.root;
    }
    return cur;
}

borrow::Place
BorrowChecker::owner_place_of(const std::string &borrower_name) const {
    auto it = borrows_.find(borrower_name);
    if (it == borrows_.end()) return borrow::Place();
    return it->second.owner;
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
        if (kv.second.owner.root == kv.first) continue;
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
    borrow::Place p;
    p.root = owner_name;
    register_borrow(borrower_name, p, is_mut);
}

void BorrowChecker::register_borrow(const std::string &borrower_name,
                                    const borrow::Place &owner, bool is_mut) {
    BorrowMeta m{owner, is_mut, 0, false, ""};
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
    /* El estado se suspende en el LUGAR del que salio el prestamo fuente, que
     * es donde esta el registro -- no en la raiz --: con `p.a` represtado, lo
     * que hay que apartar es el de `p.a` y no lo que hubiera de `p`. */
    const borrow::Place src = it->second.owner;
    auto ost = owners_.find(src.root);
    if (ost == owners_.end()) return false;
    BorrowRecord *found = find_same_place_(ost->second, src);
    if (found == nullptr) return false;
    BorrowRecord &rec = *found;
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
    borrow::Place p;
    p.root = owner_name;
    return on_lend(p, borrower_name, loc_borrow, is_mut);
}

bool BorrowChecker::on_lend(const borrow::Place &place,
                            const std::string &borrower_name,
                            SourceLoc loc_borrow, bool is_mut) {
    if (!place.valid()) return true; // no hay memoria que registrar
    OwnerState &st = owners_[place.root]; // crea la raiz si no existia

    /* R1 y R2 se preguntan contra lo que PUEDE PISARSE, no contra lo que se
     * llame igual.  Ese es todo el cambio: `p.a` y `p.b` conviven, `p` y `p.a`
     * no, y dos nombres de la misma region chocan aunque sean dos nombres. */
    borrow::PlaceUnknown why = borrow::PlaceUnknown::None;
    if (const BorrowRecord *hit = find_overlapping_(st, place, &why)) {
        // R1: con un exclusivo vivo encima, no cabe ningun prestamo mas.
        if (hit->kind == BorrowKind::Mutable) {
            error_aliasing(loc_borrow, place, *hit, is_mut, why);
            return false;
        }
        // R2: los compartidos conviven entre si, pero no con un exclusivo.
        if (hit->kind == BorrowKind::Shared && is_mut) {
            error_aliasing(loc_borrow, place, *hit, /*trying_mut=*/true, why);
            return false;
        }
    }

    /* Validado.  Un compartido MAS del mismo lugar solo suma al que ya hay --
     * por eso se busca el lugar exacto y no uno que se le parezca: sumar sobre
     * uno que solo se solapa daria un recuento que no corresponde a nada. */
    BorrowRecord *same = find_same_place_(st, place);
    if (same == nullptr) {
        BorrowRecord fresh;
        fresh.place = place;
        st.live.push_back(std::move(fresh));
        same = &st.live.back();
    }
    if (is_mut) {
        same->kind = BorrowKind::Mutable;
        same->shared_count = 0;
        same->loc_taken = loc_borrow;
        same->borrower_name = borrower_name;
    } else if (same->kind == BorrowKind::None) {
        same->kind = BorrowKind::Shared;
        same->shared_count = 1;
        same->loc_taken = loc_borrow;
        same->borrower_name = borrower_name;
    } else {
        // Ya hay Shared sobre ESTE lugar; solo sube el contador.  Se conserva
        // loc_taken del primero, que es el que se cita.
        same->shared_count++;
    }
    register_borrow(borrower_name, place, is_mut);
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
    const borrow::Place owner = it->second.owner;
    const bool is_mut = it->second.is_mut;
    const std::string reborrow_source = it->second.reborrow_source;
    borrows_.erase(it);

    auto ost = owners_.find(owner.root);
    if (ost == owners_.end()) return; // defensive
    BorrowRecord *found = find_same_place_(ost->second, owner);
    if (found == nullptr) return;     // defensive
    BorrowRecord &rec = *found;
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

    /* Y si ya no queda nada vivo de ese lugar, fuera de la lista.  No es
     * limpieza cosmetica: es lo que mantiene el recorrido de
     * @ref find_overlapping_ proporcional a los prestamos VIVOS y no al numero
     * de lugares que la funcion haya prestado alguna vez. */
    if (rec.kind == BorrowKind::None && rec.suspend_stack.empty()) {
        OwnerState &st = ost->second;
        for (size_t i = 0; i < st.live.size(); ++i) {
            if (&st.live[i] != &rec) continue;
            st.live.erase(st.live.begin() + static_cast<long>(i));
            break;
        }
    }
}

bool BorrowChecker::on_owner_use(const std::string &owner_name,
                                 SourceLoc loc_use, bool is_mutation) {
    borrow::Place p;
    p.root = owner_name;
    return on_owner_use(p, loc_use, is_mutation);
}

bool BorrowChecker::on_owner_use(const borrow::Place &place, SourceLoc loc_use,
                                 bool is_mutation) {
    if (!place.valid()) return true;
    auto it = owners_.find(place.root);
    if (it == owners_.end()) return true; // nada prestado de esa raiz
    /* Lo que estorba es lo que PUEDE PISARSE con lo que se usa.  Escribir en
     * `p.b` con `p.a` prestado no toca memoria prestada; leer `p` con `p.a`
     * prestado en exclusiva, si. */
    borrow::PlaceUnknown why = borrow::PlaceUnknown::None;
    const BorrowRecord *rec = find_overlapping_(it->second, place, &why);
    if (rec == nullptr) return true;
    // Lectura del owner: prohibida si hay Mutable activo.
    if (!is_mutation) {
        if (rec->kind == BorrowKind::Mutable) {
            error_use_while_borrowed(loc_use, place, *rec,
                                     /*is_mutation=*/false, why);
            return false;
        }
        return true; // Shared + lectura: permitido (lectura coexiste).
    }
    // Mutacion del owner: prohibida si hay cualquier borrow activo.
    error_use_while_borrowed(loc_use, place, *rec, /*is_mutation=*/true, why);
    return false;
}

bool BorrowChecker::on_owner_move(const std::string &owner_name,
                                  SourceLoc loc_move) {
    borrow::Place p;
    p.root = owner_name;
    return on_owner_move(p, loc_move);
}

bool BorrowChecker::on_owner_move(const borrow::Place &place,
                                  SourceLoc loc_move) {
    if (!place.valid()) return true;
    auto it = owners_.find(place.root);
    if (it == owners_.end()) return true;
    borrow::PlaceUnknown why = borrow::PlaceUnknown::None;
    const BorrowRecord *rec = find_overlapping_(it->second, place, &why);
    if (rec == nullptr) return true;
    error_move_while_borrowed(loc_move, place, *rec, why);
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
        /* La categoria es de la RAIZ -- que `p` sea un parametro no cambia
         * porque lo prestado sea `p.a` --, pero al usuario se le cita el LUGAR,
         * que es lo que escribio. */
        ok = owner_kind_of(it->second.owner.root);
        owner = it->second.owner.text();
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
    const std::string kind_text = kind_word(rec.kind);
    if (!rec.borrower_name.empty())
        diags_.diag(rec.loc_taken, DiagLevel::NOTE, "VX2028",
                    {kind_text, rec.borrower_name});
    else
        diags_.diag(rec.loc_taken, DiagLevel::NOTE, "VX2029", {kind_text});
}

void BorrowChecker::note_unproven_overlap_(SourceLoc loc,
                                           borrow::PlaceUnknown why) {
    /* Solo cuando el choque NO se demostro.  El mensaje de arriba dice "estos
     * dos son la misma memoria"; si en realidad es "no he podido separarlos",
     * hay que decirlo, porque lo primero se arregla cambiando el programa y lo
     * segundo puede que no haya nada que arreglar. */
    switch (why) {
    case borrow::PlaceUnknown::RuntimeIndex:
        diags_.diag(loc, DiagLevel::NOTE, "VX2057", {});
        break;
    case borrow::PlaceUnknown::RegionNotResolvedHere:
        diags_.diag(loc, DiagLevel::NOTE, "VX2058", {});
        break;
    case borrow::PlaceUnknown::None:
        break;
    }
}

void BorrowChecker::error_aliasing(SourceLoc loc_conflict,
                                   const borrow::Place &place,
                                   const BorrowRecord &rec, bool trying_mut,
                                   borrow::PlaceUnknown why) {
    const std::string wanted =
        diag::format(trying_mut ? "VX2040" : "VX2039", {});
    /* El LUGAR, no la raiz: con `p.a` prestado, decir que el problema es `p`
     * manda a mirar donde no esta. */
    const std::string place_text = place.text();
    if (rec.kind == BorrowKind::Mutable)
        diags_.diag(loc_conflict, DiagLevel::ERR, "VX2026",
                    {place_text, wanted,kind_word(rec.kind)});
    else
        diags_.diag(loc_conflict, DiagLevel::ERR, "VX2027",
                    {place_text, wanted,std::to_string(rec.shared_count)});
    note_previous_borrow_(rec);
    /* Y CUAL es el prestamo que estorba, cuando no es el mismo lugar: `p`
     * bloqueando a `p.a` se lee de otra manera si se dice. */
    if (!borrow::places_same(rec.place, place))
        diags_.diag(rec.loc_taken, DiagLevel::NOTE, "VX2059",
                    {rec.place.text(), place_text});
    note_unproven_overlap_(loc_conflict, why);
    diags_.diag(loc_conflict, DiagLevel::NOTE, "VX2030", {wanted});
}

void BorrowChecker::error_use_while_borrowed(SourceLoc loc_use,
                                             const borrow::Place &place,
                                             const BorrowRecord &rec,
                                             bool is_mutation,
                                             borrow::PlaceUnknown why) {
    const std::string place_text = place.text();
    if (is_mutation)
        diags_.diag(loc_use, DiagLevel::ERR, "VX2031",
                    {place_text,kind_word(rec.kind)});
    else
        diags_.diag(loc_use, DiagLevel::ERR, "VX2032", {place_text});
    note_previous_borrow_(rec);
    if (!borrow::places_same(rec.place, place))
        diags_.diag(rec.loc_taken, DiagLevel::NOTE, "VX2059",
                    {rec.place.text(), place_text});
    note_unproven_overlap_(loc_use, why);
    diags_.diag(loc_use, DiagLevel::NOTE, "VX2033",
                {diag::format(is_mutation ? "VX2041" : "VX2042", {})});
}

void BorrowChecker::error_move_while_borrowed(SourceLoc loc_move,
                                              const borrow::Place &place,
                                              const BorrowRecord &rec,
                                              borrow::PlaceUnknown why) {
    const std::string place_text = place.text();
    diags_.diag(loc_move, DiagLevel::ERR, "VX2034",
                {place_text,kind_word(rec.kind)});
    note_previous_borrow_(rec);
    if (!borrow::places_same(rec.place, place))
        diags_.diag(rec.loc_taken, DiagLevel::NOTE, "VX2059",
                    {rec.place.text(), place_text});
    note_unproven_overlap_(loc_move, why);
    diags_.diag(loc_move, DiagLevel::NOTE, "VX2035", {});
    diags_.diag(loc_move, DiagLevel::NOTE, "VX2036", {});
}

} // namespace vx
