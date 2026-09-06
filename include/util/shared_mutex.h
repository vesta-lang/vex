/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/shared_mutex.h
 * @brief Cerrojo de lector/escritor que NO pasa por la emulacion de pthreads.
 *
 * POR QUE NO `std::shared_mutex`.  En MinGW se implementa sobre
 * `pthread_rwlock_t` de winpthreads, y esa pieza SE ROMPE cuando hay hilos que
 * nacen y mueren -- que es exactamente lo que hace el compilador, un lote de
 * hilos por nivel de modulos.  Medido con una sonda de sesenta lineas, sin nada
 * de Vesta dentro: el MISMO programa, cambiando solo el tipo del cerrojo,
 *
 *     std::shared_mutex   5 de 5 corridas mueren (violacion de segmento o
 *                         cuelgue con los 23 hilos parados y NINGUNO dentro)
 *     std::mutex          5 de 5 correctas
 *
 * En el compilador se veia igual: 8 escritores esperando el exclusivo, 8
 * esperando el de despues de la fabrica y 8 lectores, con la seccion critica
 * VACIA.  Un cerrojo correcto no puede dejar eso.
 *
 * QUE SE USA EN SU LUGAR.  En Windows, `SRWLOCK`: es el cerrojo de
 * lector/escritor del sistema, del tamano de un puntero, sin reservar memoria y
 * sin nada que destruir.  Fuera de Windows, `std::shared_mutex`, que ahi si se
 * apoya en un `pthread_rwlock_t` de verdad.
 *
 * INTERFAZ ESTaNDAR a proposito: ofrece `lock`/`try_lock`/`unlock` y
 * `lock_shared`/`try_lock_shared`/`unlock_shared`, que es lo que piden
 * `std::unique_lock`, `std::shared_lock` y `std::lock_guard`.  Asi cambiar de
 * cerrojo es cambiar UN tipo, no reescribir cada sitio que lo toma.
 *
 * NO ES REENTRANTE ni se puede ascender de lectura a escritura, igual que
 * `std::shared_mutex` y que `SRWLOCK`.  Pedir dos veces desde el mismo hilo
 * cuelga.
 *
 * NO INCLUYE `windows.h`.  Esa cabecera define `VOID` como macro y rompe
 * cualquier `enum class` que use ese nombre -- ya obligo a aislar
 * `ThreadPool.h` en su propio `.cpp` --, asi que el estado se guarda como un
 * puntero opaco y la implementacion vive en el `.cpp`.
 */
#ifndef VESTA_UTIL_SHARED_MUTEX_H
#define VESTA_UTIL_SHARED_MUTEX_H

#if !defined(_WIN32)
#include <shared_mutex>
#endif

namespace util {

/**
 * @brief Cerrojo de lector/escritor.
 *
 * Muchos lectores a la vez, o un escritor solo.  Se declara como cualquier
 * miembro; no hay que inicializarlo ni destruirlo a mano.
 */
class SharedMutex {
  public:
    SharedMutex() noexcept = default;
    SharedMutex(const SharedMutex &) = delete;
    SharedMutex &operator=(const SharedMutex &) = delete;

    /// Toma el cerrojo en EXCLUSIVA.  Espera a que no haya nadie dentro.
    void lock() noexcept;
    /// Intenta la exclusiva sin esperar.  @return false si no pudo.
    bool try_lock() noexcept;
    /// Suelta la exclusiva.
    void unlock() noexcept;

    /// Toma el cerrojo COMPARTIDO.  Otros lectores pueden entrar a la vez.
    void lock_shared() noexcept;
    /// Intenta el compartido sin esperar.  @return false si no pudo.
    bool try_lock_shared() noexcept;
    /// Suelta el compartido.
    void unlock_shared() noexcept;

  private:
#if defined(_WIN32)
    /* Es un `SRWLOCK`.  En la cabecera del sistema es una estructura con UN
     * puntero, y su valor inicial -- `SRWLOCK_INIT` -- es ese puntero a nulo,
     * asi que inicializarlo aqui es exacto.  Se declara como `void *` para no
     * arrastrar `windows.h`; el `.cpp` comprueba con `static_assert` que los
     * tamanos coinciden. */
    void *state_ = nullptr;
#else
    std::shared_mutex impl_;
#endif
};

} // namespace util

#endif // VESTA_UTIL_SHARED_MUTEX_H
