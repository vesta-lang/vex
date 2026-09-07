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

#include "codegen/unwind/pe_x86_64.h"
#include "jit/code_cache.h"
#include "jit/machine_ir.h"
#include "jit/mfunction_unwind.h"

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

/// Una entrada de la tabla, con su descripcion detras.  Van juntas porque el
/// sistema guarda el PUNTERO a las dos y tienen que vivir lo mismo.
struct UnwindEntry {
    RUNTIME_FUNCTION function;
    /* Cabecera de UNWIND_INFO (4 bytes) + los codigos.  Se escribe a mano
     * porque la definicion de `winnt.h` lleva un array flexible.  El tope de
     * codigos cubre: el `sub rsp` grande (3 ranuras), `mov rbp,rsp`, los push
     * de RBP y RBX, y los callee-saved que el asignador llegue a usar.  El
     * numero sale del codificador para que el bufer y su limite no se puedan
     * separar. */
    uint8_t info[4 + 2 * codegen::unwind::PE_X86_64_MAX_SLOTS];
};

} // namespace

bool register_jit_unwind(uint8_t *code, size_t bytes, const MFunction &fn,
                         CodeCache &cc) noexcept {
    if (code == nullptr || bytes == 0) return false;

    /* Que describir lo decide el codificador, que ya sabe cuando NO hay que
     * decir nada -- funcion duena de su pila, prologo sin medir, o mas grande
     * de lo que cabe en el formato --.  Aqui solo queda registrarlo. */
    std::vector<uint8_t> info;
    if (!codegen::unwind::build_pe_x86_64(frame_unwind_of(fn), info))
        return false;
    if (info.size() > sizeof(UnwindEntry::info)) return false;

    auto *d = reinterpret_cast<UnwindEntry *>(
        cc.alloc(sizeof(UnwindEntry), 16));
    if (d == nullptr) return false;
    std::memset(d, 0, sizeof(*d));
    std::memcpy(d->info, info.data(), info.size());

    /* Las direcciones de la tabla son RELATIVAS a una base que elegimos.  Se
     * toma el propio codigo, asi que todos los desplazamientos son pequenos. */
    const DWORD64 base = (DWORD64)(uintptr_t)code;
    d->function.BeginAddress = 0;
    d->function.EndAddress = (DWORD)bytes;
    d->function.UnwindData = (DWORD)((DWORD64)(uintptr_t)d->info - base);
    return RtlAddFunctionTable(&d->function, 1, base) != FALSE;
}

#endif // Windows x64

} // namespace jit
