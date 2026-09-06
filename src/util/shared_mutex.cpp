/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/shared_mutex.cpp
 * @brief Implementacion del cerrojo de lector/escritor.
 *
 * Aqui SI se puede incluir `windows.h`: es una unidad de traduccion suelta y
 * las macros que define esa cabecera (`VOID` entre ellas) no salen de aqui.  La
 * cabecera del cerrojo no la incluye a proposito -- ver la nota de
 * `util/shared_mutex.h`.
 */

#include "util/shared_mutex.h"

#if defined(_WIN32)
// Recorta lo que arrastra `windows.h`.  Los `SRWLOCK` estan en la parte basica,
// asi que no hace falta nada de lo que quita.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
/* `SRWLOCK` existe desde Windows Vista, y las cabeceras solo lo declaran si se
 * pide esa version como minimo.  Se fija AQUI y no se deja al que compile: sin
 * esto, el fallo no es "no existe", es que la funcion no se declara y el
 * mensaje habla de un nombre desconocido.  El proyecto ya pide 0x0A00; esto
 * solo cubre a quien compile este fichero suelto. */
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>

namespace util {

/* El estado guardado es EL `SRWLOCK`, no un puntero a el: cabe en el hueco.
 * Si alguna version del sistema lo cambiara, esto deja de compilar en vez de
 * pisar memoria de al lado. */
static_assert(sizeof(SRWLOCK) == sizeof(void *),
              "SRWLOCK ya no cabe en un puntero: revisar SharedMutex");
static_assert(alignof(SRWLOCK) <= alignof(void *),
              "SRWLOCK pide mas alineacion de la que da un puntero");

/// El estado del objeto, visto como lo que es.  Los bytes son almacenamiento
/// en bruto -- ver la nota de la cabecera --, asi que aqui no hay dos tipos
/// pisandose: solo uno, el que el sistema maneja.
static inline PSRWLOCK as_srwlock(unsigned char *state) noexcept {
    return reinterpret_cast<PSRWLOCK>(state);
}

void SharedMutex::lock() noexcept { AcquireSRWLockExclusive(as_srwlock(state_)); }

bool SharedMutex::try_lock() noexcept {
    return TryAcquireSRWLockExclusive(as_srwlock(state_)) != 0;
}

void SharedMutex::unlock() noexcept { ReleaseSRWLockExclusive(as_srwlock(state_)); }

void SharedMutex::lock_shared() noexcept {
    AcquireSRWLockShared(as_srwlock(state_));
}

bool SharedMutex::try_lock_shared() noexcept {
    return TryAcquireSRWLockShared(as_srwlock(state_)) != 0;
}

void SharedMutex::unlock_shared() noexcept {
    ReleaseSRWLockShared(as_srwlock(state_));
}

} // namespace util

#else // ---------------------------------------------------------------- POSIX

namespace util {

/* Fuera de Windows se delega en `std::shared_mutex`, que ahi se apoya en un
 * `pthread_rwlock_t` de verdad y no en la emulacion que rompe en MinGW. */
void SharedMutex::lock() noexcept { impl_.lock(); }
bool SharedMutex::try_lock() noexcept { return impl_.try_lock(); }
void SharedMutex::unlock() noexcept { impl_.unlock(); }
void SharedMutex::lock_shared() noexcept { impl_.lock_shared(); }
bool SharedMutex::try_lock_shared() noexcept { return impl_.try_lock_shared(); }
void SharedMutex::unlock_shared() noexcept { impl_.unlock_shared(); }

} // namespace util

#endif
