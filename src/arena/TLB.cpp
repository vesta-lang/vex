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
 * @file TLB.cpp
 * @brief Lo que NO corre en cada acceso: insertar, crecer, invalidar, volcar.
 *
 * La consulta -- `get_entry` -- vive en la cabecera y en linea, porque se
 * llama en cada acceso a la memoria de la VM.  Aqui queda el lado del
 * ESCRITOR, que corre cuando aparece una pagina nueva, y los volcados de
 * diagnostico.
 *
 * El porque del disenyo -- tabla plana en vez de arbol de tres niveles, y como
 * se publica para que un segundo hilo pueda leer sin candados -- esta en la
 * cabecera de la clase.
 */
#include "arena/TLB.h"

#include "arena/arena.h"

#include <cstdio>
#include <cstdlib>

namespace tlb {

TLBEntryData *LazyHybridTLB::probe(const Table *t, uint64_t page, uint32_t i) {
    /* Se entra aqui con la primera ranura ya mirada y descartada, y sabiendo
     * que NO estaba vacia -- si lo estuviera, la pagina no estaria en la
     * tabla y quien llama ya habria devuelto null --. */
    const uint64_t want = page + 1u;
    for (;;) {
        i = (i + 1) & t->mask;
        const uint64_t tag = t->slot[i].tag.load(std::memory_order_acquire);
        if (tag == want) return const_cast<TLBEntryData *>(&t->slot[i].entry);
        // Vacia: si estuviera, el sondeo la habria encontrado ya.
        if (tag == 0) return nullptr;
        // Invalidada: pudo haber otra detras suya, asi que se sigue.
    }
}

LazyHybridTLB::Table *LazyHybridTLB::make_table(uint32_t slots, Table *older) {
    /* `slots` es siempre potencia de dos, asi que el desplazamiento sale de
     * contar sus ceros a la derecha: con 64 ranuras son 6 bits de indice y el
     * desplazamiento es 58.  Se guarda para que @ref mix no tenga que
     * calcularlo en cada consulta. */
    Table *t = new (std::nothrow) Table;
    if (t == nullptr) return nullptr;
    t->slot = new (std::nothrow) Slot[slots];
    if (t->slot == nullptr) {
        delete t;
        return nullptr;
    }
    t->mask = slots - 1u;
    t->shift = 64u - (uint32_t)__builtin_ctz(slots);
    t->used = 0;
    t->older = older;
    return t;
}

LazyHybridTLB::LazyHybridTLB() {
    table.store(make_table(kInitialSlots, nullptr), std::memory_order_release);
}

LazyHybridTLB::~LazyHybridTLB() {
    /* Se recorre la cadena entera: las tablas viejas se guardan vivas
     * MIENTRAS la TLB exista, porque un lector rezagado puede estar dentro de
     * cualquiera de ellas.  Cuando se destruye la TLB ya no queda nadie. */
    Table *t = table.load(std::memory_order_acquire);
    while (t != nullptr) {
        Table *prev = t->older;
        delete[] t->slot;
        delete t;
        t = prev;
    }
}

void LazyHybridTLB::reclaim_older() {
    Table *t = table.load(std::memory_order_acquire);
    if (t == nullptr) return;

    /* Se corta la cadena ANTES de liberar nada.  Asi, si alguien mirase la
     * tabla en medio de esto, veria una lista vacia en vez de un puntero a
     * memoria que se esta soltando. */
    Table *old = t->older;
    t->older = nullptr;
    while (old != nullptr) {
        Table *prev = old->older;
        delete[] old->slot;
        delete old;
        old = prev;
    }
}

void LazyHybridTLB::grow() {
    Table *old = table.load(std::memory_order_relaxed);
    const uint32_t slots = (old->mask + 1u) * 2u;
    Table *fresh = make_table(slots, old);
    if (fresh == nullptr) return; // sin sitio: se sigue con la de ahora

    /* Se REHACEN las entradas vivas.  Las invalidadas no se copian, que es de
     * paso la unica forma que tiene esta tabla de deshacerse de ellas: en
     * direccionamiento abierto una marca de borrado no se puede quitar sin
     * mover lo que hay detras. */
    for (uint32_t i = 0; i <= old->mask; ++i) {
        const uint64_t tag = old->slot[i].tag.load(std::memory_order_relaxed);
        if (tag == 0 || tag == kTombstone) continue;
        const uint64_t page = tag - 1u;
        uint32_t j = mix(page, fresh->shift);
        while (fresh->slot[j].tag.load(std::memory_order_relaxed) != 0)
            j = (j + 1) & fresh->mask;
        fresh->slot[j].entry = old->slot[i].entry;
        fresh->slot[j].tag.store(tag, std::memory_order_relaxed);
        ++fresh->used;
    }

    /* Y AHORA se publica.  Hasta esta linea nadie ha visto la tabla nueva, asi
     * que rehacerla no se pisa con ninguna consulta en curso.  La vieja se
     * queda colgando de `older`: quien la tenga cogida sigue leyendo memoria
     * valida. */
    table.store(fresh, std::memory_order_release);
}

LazyHybridTLB::Slot *LazyHybridTLB::slot_for_write(uint64_t page) {
    Table *t = table.load(std::memory_order_relaxed);
    if (t == nullptr) return nullptr;

    /* Se crece ANTES de insertar, no despues: con la tabla ya al limite el
     * sondeo de esta misma insercion seria el mas largo de todos. */
    if ((t->used + 1u) * kMaxLoadDen > (t->mask + 1u) * kMaxLoadNum) {
        grow();
        t = table.load(std::memory_order_relaxed);
        if (t == nullptr) return nullptr;
    }

    const uint64_t want = page + 1u;
    uint32_t i = mix(page, t->shift);
    Slot *reuse = nullptr; // la primera invalidada que se encuentre
    for (;;) {
        const uint64_t tag = t->slot[i].tag.load(std::memory_order_relaxed);
        if (tag == want) return &t->slot[i]; // ya estaba: se actualiza
        if (tag == kTombstone) {
            /* Se apunta y se SIGUE buscando: la pagina puede estar mas
             * adelante, y meterla aqui la duplicaria.  Solo se usa esta ranura
             * si el sondeo llega a una vacia sin haberla encontrado. */
            if (reuse == nullptr) reuse = &t->slot[i];
        } else if (tag == 0) {
            if (reuse != nullptr) return reuse; // se reaprovecha el hueco
            ++t->used;
            return &t->slot[i];
        }
        i = (i + 1) & t->mask;
    }
}

void LazyHybridTLB::translate(uint64_t ptr_, vm::type_ptr_mapped type,
                              vm::ptr_mapped ptr_mapped) {
    const uint64_t page = GET_PAGE(ptr_);
    Slot *s = slot_for_write(page);
    if (s == nullptr) return; // sin memoria: la pagina se queda sin traducir

    /* El contenido PRIMERO y la etiqueta DESPUES, con `release`.
     *
     * Es lo que permite que otro hilo consulte sin candados: quien lea la
     * etiqueta con `acquire` y la reconozca, ve la traduccion ya escrita
     * entera.  Al reves -- etiqueta primero -- habria un instante en el que la
     * ranura dice ser de esta pagina y todavia tiene la traduccion de otra, y
     * eso no da un error: da otra direccion. */
    s->entry.type_address = type;
    s->entry.address = ptr_mapped;
    s->tag.store(page + 1u, std::memory_order_release);
}

void LazyHybridTLB::clear_tlb_entry(uint64_t page_vaddr) {
    /* Se marca la ranura como INVALIDADA, no como vacia.
     *
     * Con sondeo lineal, dejarla vacia cortaria la busqueda de cualquier
     * pagina que hubiera aterrizado detras suya por colision: seguiria en la
     * tabla y nadie la encontraria.  La marca dice "aqui no hay nada, pero
     * sigue buscando". */
    Table *t = table.load(std::memory_order_relaxed);
    if (t == nullptr) return;

    const uint64_t page = GET_PAGE(page_vaddr);
    const uint64_t want = page + 1u;
    uint32_t i = mix(page, t->shift);
    for (;;) {
        const uint64_t tag = t->slot[i].tag.load(std::memory_order_relaxed);
        if (tag == want) {
            t->slot[i].tag.store(kTombstone, std::memory_order_release);
            t->slot[i].entry = TLBEntryData{};
            return;
        }
        if (tag == 0) return; // no estaba
        i = (i + 1) & t->mask;
    }
}

void *LazyHybridTLB::get_real_host_ptr_of_vptr(uint64_t vptr_) const {
    const TLBEntryData *entry = get_entry(vptr_);
    if (entry == nullptr) return nullptr; // pagina no mapeada

    // rechazar entradas que no apunten a memoria del host
    if (vm::MAPPED_PTR_HOST != entry->type_address) return nullptr;

    return entry->address.ptr_host; // devolver el puntero de host almacenado
}

#if !defined(VESTA_GC_FREESTANDING)

void LazyHybridTLB::dump_tree(uint64_t vpn_) const {
    const Table *t = table.load(std::memory_order_acquire);
    const uint64_t page = GET_PAGE(vpn_);
    std::printf("vaddr 0x%llx -> pagina 0x%llx, offset 0x%llx\n",
                (unsigned long long)vpn_, (unsigned long long)page,
                (unsigned long long)GET_OFFSET(vpn_));
    if (t == nullptr) {
        std::printf("  (sin tabla)\n");
        return;
    }

    /* Se ensena el CAMINO de sondeo, no solo el resultado: con
     * direccionamiento abierto, cuantas ranuras hay que mirar es la mitad de
     * la historia -- un sondeo largo es lo que delata una tabla mal
     * repartida --. */
    const uint64_t want = page + 1u;
    uint32_t i = mix(page, t->shift);
    for (uint32_t probes = 0;; ++probes) {
        const uint64_t tag = t->slot[i].tag.load(std::memory_order_acquire);
        if (tag == want) {
            std::printf("  ranura %u tras %u sondeos: %s\n", i, probes,
                        t->slot[i].entry.to_string().c_str());
            return;
        }
        if (tag == 0) {
            std::printf("  no mapeada (%u sondeos hasta un hueco)\n", probes);
            return;
        }
        i = (i + 1) & t->mask;
    }
}

void LazyHybridTLB::dump_stats() const {
    const Table *t = table.load(std::memory_order_acquire);
    if (t == nullptr) {
        std::printf("TLB: sin tabla\n");
        return;
    }

    const uint32_t slots = t->mask + 1u;
    uint32_t live = 0, dead = 0;
    for (uint32_t i = 0; i < slots; ++i) {
        const uint64_t tag = t->slot[i].tag.load(std::memory_order_relaxed);
        if (tag == kTombstone)
            ++dead;
        else if (tag != 0)
            ++live;
    }

    /* El sondeo MEDIO, que es lo unico que dice si la tabla esta sana: el
     * numero de entradas no lo dice -- una tabla puede estar medio vacia y
     * sondear fatal si el reparto es malo --. */
    uint64_t total_probes = 0;
    for (uint32_t i = 0; i < slots; ++i) {
        const uint64_t tag = t->slot[i].tag.load(std::memory_order_relaxed);
        if (tag == 0 || tag == kTombstone) continue;
        const uint64_t page = tag - 1u;
        uint32_t j = mix(page, t->shift);
        while (j != i) {
            ++total_probes;
            j = (j + 1) & t->mask;
        }
    }

    uint32_t chained = 0;
    for (Table *o = t->older; o != nullptr; o = o->older) ++chained;

    std::printf("TLB: %u ranuras, %u vivas, %u invalidadas (carga %.2f)\n",
                slots, live, dead, (double)live / (double)slots);
    std::printf("     sondeo medio %.2f, %u tablas viejas vivas\n",
                live ? (double)total_probes / (double)live + 1.0 : 1.0,
                chained);
}

#endif // !VESTA_GC_FREESTANDING

} // namespace tlb
