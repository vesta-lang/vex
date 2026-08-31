/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/win_unwind.cpp
 * @brief Implementacion de @ref jit/win_unwind.h.
 */

#include "jit/win_unwind.h"

#include "jit/code_cache.h"
#include "jit/machine_ir.h"

#include <cstring>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace jit {

#if !defined(_WIN32) || !(defined(_M_X64) || defined(__x86_64__))

bool register_jit_unwind(uint8_t *, size_t, const MFunction &,
                         CodeCache &) noexcept {
    return false; // solo Windows x64 desenrolla por tablas.
}

#else

namespace {

/// Codigos de operacion del desenrollado.  `winnt.h` no los expone como enum.
enum : uint8_t {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE = 1,
    UWOP_ALLOC_SMALL = 2,
    UWOP_SET_FPREG = 3,
};

/// Una entrada de la tabla, con su descripcion detras.  Van juntas porque el
/// sistema guarda el PUNTERO a las dos y tienen que vivir lo mismo.
struct EntradaDesenrollado {
    RUNTIME_FUNCTION funcion;
    /* Cabecera de UNWIND_INFO (4 bytes) + los codigos.  Se escribe a mano
     * porque la definicion de `winnt.h` lleva un array flexible.  El tope de
     * codigos cubre: el `sub rsp` grande (3 ranuras), `mov rbp,rsp`, los push
     * de RBP y RBX, y los callee-saved que el asignador llegue a usar. */
    uint8_t info[4 + 2 * 32];
};

/// Un codigo del desenrollado, tal como se va a escribir.
struct Codigo {
    uint8_t offset; ///< donde, dentro del prologo, ya ha surtido efecto.
    uint8_t op;     ///< UWOP_*.
    uint8_t info;   ///< registro, o tamano segun el op.
    uint16_t extra0 = 0;
    uint16_t extra1 = 0;
    uint8_t n_extra = 0; ///< ranuras adicionales que ocupa (0, 1 o 2).
};

} // namespace

bool register_jit_unwind(uint8_t *code, size_t bytes, const MFunction &fn,
                         CodeCache &cc) noexcept {
    if (code == nullptr || bytes == 0) return false;
    const MFunction::UnwindDesc &u = fn.unwind;
    /* Una funcion `@Naked` es duena de su pila y no hay prologo que describir;
     * mentirle al desenrollador es peor que no decirle nada. */
    if (u.naked) return false;
    /* Sin prologo medido no hay nada que decir.  Pasa si la funcion no emitio
     * ninguno (hoja sin marco): ahi la suposicion de hoja del sistema ES la
     * correcta, asi que no registrar es lo acertado. */
    if (fn.prologue_instrs == 0 || fn.prologue_bytes == 0) return false;
    if (fn.prologue_bytes > 255)
        return false; // no cabe en el campo del sistema

    const uint8_t fin = static_cast<uint8_t>(fn.prologue_bytes);

    /* Los codigos van en orden DESCENDENTE de posicion: el desenrollador los
     * aplica de atras hacia delante para deshacer el prologo.  Todos llevan la
     * posicion del FINAL del prologo, no la suya propia.
     *
     * Eso es deliberado y hay que entenderlo: un codigo solo se aplica cuando
     * la ejecucion ya paso su posicion, asi que con esta descripcion un fallo
     * OCURRIDO DENTRO DEL PROLOGO no aplica ninguno -- y el sistema hace
     * exactamente lo mismo que hacia sin tabla, dar el trozo por hoja.  O sea
     * que en ese caso no se gana nada, pero tampoco se pierde; y en el caso que
     * importa -- el fallo en el CUERPO, que es donde ocurre todo -- la
     * descripcion es exacta.  Dar la posicion real de cada instruccion del
     * prologo exigiria que el codificador las fuera anotando una a una; se hara
     * si algun dia hace falta desenrollar desde dentro del prologo. */
    std::vector<Codigo> codigos;
    codigos.reserve(8 + u.callee_saved.size());

    if (u.spill_bytes > 0) {
        const uint32_t n = u.spill_bytes;
        if (n % 8 == 0 && n / 8 >= 1 && n / 8 <= 16) {
            // Hasta 128 bytes cabe en el propio codigo: info = n/8 - 1.
            codigos.push_back(
                {fin, UWOP_ALLOC_SMALL, static_cast<uint8_t>(n / 8 - 1)});
        } else if (n % 8 == 0 && n / 8 < 0x10000u) {
            // Hasta 512 KiB: una ranura mas, con el tamano en ranuras.
            Codigo c{fin, UWOP_ALLOC_LARGE, 0};
            c.extra0 = static_cast<uint16_t>(n / 8);
            c.n_extra = 1;
            codigos.push_back(c);
        } else {
            // Cualquier tamano: dos ranuras mas, con el tamano en BYTES.
            Codigo c{fin, UWOP_ALLOC_LARGE, 1};
            c.extra0 = static_cast<uint16_t>(n & 0xFFFFu);
            c.extra1 = static_cast<uint16_t>(n >> 16);
            c.n_extra = 2;
            codigos.push_back(c);
        }
    }
    // Los callee-saved, al reves de como se empujaron.
    for (size_t i = u.callee_saved.size(); i-- > 0;) {
        const uint8_t r = u.callee_saved[i];
        if (r > 15) continue; // solo GP: un XMM se salva de otra forma.
        codigos.push_back({fin, UWOP_PUSH_NONVOL, r});
    }
    if (u.push_rbx)
        codigos.push_back(
            {fin, UWOP_PUSH_NONVOL, static_cast<uint8_t>(MReg::RBX)});
    if (u.frame_ptr) codigos.push_back({fin, UWOP_SET_FPREG, 0});
    if (u.push_rbp)
        codigos.push_back(
            {fin, UWOP_PUSH_NONVOL, static_cast<uint8_t>(MReg::RBP)});

    if (codigos.empty()) return false; // nada que describir

    // Cuantas ranuras de dos bytes ocupan en total.
    size_t ranuras = 0;
    for (const Codigo &c : codigos)
        ranuras += 1u + c.n_extra;
    if (ranuras > 32) return false; // no cabe en el bufer reservado

    auto *d = reinterpret_cast<EntradaDesenrollado *>(
        cc.alloc(sizeof(EntradaDesenrollado), 16));
    if (d == nullptr) return false;
    std::memset(d, 0, sizeof(*d));

    d->info[0] = 1; // version 1, sin banderas
    d->info[1] = fin;
    d->info[2] = static_cast<uint8_t>(ranuras);
    /* El registro de marco, si lo hay: nibble bajo el registro, nibble alto el
     * desplazamiento en unidades de 16 bytes.  Nuestro `mov rbp, rsp` no suma
     * nada, asi que el desplazamiento es 0. */
    d->info[3] = u.frame_ptr ? static_cast<uint8_t>(MReg::RBP) : 0u;

    size_t k = 4;
    for (const Codigo &c : codigos) {
        d->info[k++] = c.offset;
        d->info[k++] = static_cast<uint8_t>(c.op | (c.info << 4));
        if (c.n_extra >= 1) {
            d->info[k++] = static_cast<uint8_t>(c.extra0 & 0xFFu);
            d->info[k++] = static_cast<uint8_t>(c.extra0 >> 8);
        }
        if (c.n_extra >= 2) {
            d->info[k++] = static_cast<uint8_t>(c.extra1 & 0xFFu);
            d->info[k++] = static_cast<uint8_t>(c.extra1 >> 8);
        }
    }

    /* Las direcciones de la tabla son RELATIVAS a una base que elegimos.  Se
     * toma el propio codigo, asi que todos los desplazamientos son pequenos. */
    const DWORD64 base = (DWORD64)(uintptr_t)code;
    d->funcion.BeginAddress = 0;
    d->funcion.EndAddress = (DWORD)bytes;
    d->funcion.UnwindData = (DWORD)((DWORD64)(uintptr_t)d->info - base);
    return RtlAddFunctionTable(&d->funcion, 1, base) != FALSE;
}

#endif // Windows x64

} // namespace jit
