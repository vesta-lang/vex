/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/thread_owned.h
 * @brief Un OBJETO por hilo, sin `thread_local`.
 *
 * `util::ThreadSlot` ya da un PUNTERO por hilo, y con eso basta cuando el valor
 * cabe en el propio puntero -- una bandera, un contador, una enumeracion --.
 * Lo que falta es el otro caso: un `std::vector`, una `std::string`, un struct.
 * Eso hay que reservarlo en algun sitio, y quien lo reserve tiene que poder
 * liberarlo.
 *
 * POR QUE NO `thread_local`.  Dos razones, y la segunda es la grave:
 *
 *  - En MinGW la TLS es EMULADA: cada acceso es una llamada a
 *    `__emutls_get_address`, 10,83 ns frente a los 0,85 de leer el TEB.  Ver
 *    `util/thread_slot.h`, que trae la medicion.
 *  - Una variable de hilo con inicializador DINaMICO -- que es justo lo que es
 *    un `vector` o una `string` -- genera una variable de guarda, y esa guarda
 *    se bloquea en MinGW cuando hay hilos que nacen y mueren.  El compilador
 *    lanza un lote de hilos por nivel de modulos, asi que es exactamente
 *    nuestro caso.
 *
 * QUIEN LIBERA.  Cada objeto creado queda apuntado ADEMAS por este dueno, asi
 * que al destruirse se lleva todos por delante.  Sin ese registro, lo que
 * quedara en la ranura de un hilo que muere no lo suelta nadie -- y en el
 * gestor de analisis eso no seria un vector perdido, seria mantener VIVOS los
 * resultados que ese vector respalda.
 *
 * COSTE.  El camino normal es leer la ranura y comprobar que no es nula: una
 * lectura del TEB.  El cerrojo solo se toca al crear, una vez por hilo.
 *
 * EJEMPLO
 * @code
 * static util::ThreadOwned<std::vector<int>> g_pila;
 * g_pila.get().push_back(7);   // el vector de ESTE hilo
 * @endcode
 */
#ifndef VESTA_UTIL_THREAD_OWNED_H
#define VESTA_UTIL_THREAD_OWNED_H

#include "util/thread_slot.h"

#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace util {

/**
 * @brief Un objeto de tipo @p T por hilo, con dueno explicito.
 *
 * @tparam T Tipo del objeto.  Se construye por defecto la primera vez que
 *           cada hilo lo pide.
 *
 * Se declara como variable global normal o como MIEMBRO de quien lo use; no
 * como variable de hilo.  Lo que cambia por hilo es el contenido de la ranura,
 * no el objeto que la gestiona, asi que no hay inicializador dinamico por hilo
 * ni variable de guarda -- que es de donde venian los cuelgues.
 */
template <class T> class ThreadOwned {
  public:
    ThreadOwned() = default;
    ThreadOwned(const ThreadOwned &) = delete;
    ThreadOwned &operator=(const ThreadOwned &) = delete;

    /**
     * @brief El objeto de ESTE hilo, creandolo la primera vez.
     * @return Referencia estable mientras viva este dueno.
     */
    T &get() {
        // Camino normal: una lectura de la ranura y una comparacion.
        if (void *p = slot_.get()) return *static_cast<T *>(p);
        return create();
    }

    /**
     * @brief Aplica @p f a los objetos de TODOS los hilos.
     *
     * Para sumar contadores repartidos por hilo sin que cada uno tenga que
     * darse de alta por su cuenta en otra lista.
     *
     * @tparam F Invocable con `T &`.
     * @param f  Que hacer con cada uno.
     */
    template <class F> void for_each(F &&f) {
        std::lock_guard<std::mutex> lk(m_);
        for (const std::unique_ptr<Entry> &e : all_)
            f(e->value);
    }

  private:
    /// Lo creado por un hilo, mas de QUIEN es -- solo hace falta saberlo si el
    /// sistema se queda sin ranuras y hay que buscar por identidad de hilo.
    struct Entry {
        T value;
        std::thread::id owner;
    };

    /// Fuera del camino normal a proposito: se pasa por aqui una vez por hilo.
    T &create() {
        const std::thread::id me = std::this_thread::get_id();
        const bool has_slot = slot_.ensure();
        {
            std::lock_guard<std::mutex> lk(m_);
            /* SIN RANURAS.  El sistema no da mas, asi que no hay donde
             * apuntar "el mio": se busca por identidad de hilo.  Es lento y
             * pasa a ser O(hilos), pero es CORRECTO -- devolver otro objeto, o
             * uno nuevo cada vez, seria perder el estado sin decirlo.  No se
             * ha visto ocurrir: Windows reparte mas de mil ranuras y aqui se
             * usan unas pocas. */
            if (!has_slot) {
                for (const std::unique_ptr<Entry> &e : all_)
                    if (e->owner == me) return e->value;
            }
            all_.push_back(std::unique_ptr<Entry>(new Entry{T(), me}));
            Entry *created = all_.back().get();
            if (has_slot) slot_.set(&created->value);
            return created->value;
        }
    }

    ThreadSlot slot_;
    std::mutex m_;
    /* Por punteros y no por valor: el vector REUBICA al crecer, y las
     * referencias ya entregadas -- y lo que haya en las ranuras -- tienen que
     * seguir valiendo. */
    std::vector<std::unique_ptr<Entry>> all_;
};

} // namespace util

#endif // VESTA_UTIL_THREAD_OWNED_H
