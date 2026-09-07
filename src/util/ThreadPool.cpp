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
 * @file ThreadPool.cpp
 * @brief Implementacion del pool de hilos de VestaVM.
 *
 * Implementa el constructor, destructor, shutdown(), idle() y worker_loop()
 * de la clase @c ThreadPool.  La notificacion de tareas usa futex en Linux
 * y WaitOnAddress/WakeByAddressAll en Windows.
 */
#include "util/ThreadPool.h"
#include <algorithm> // UCRT64: no transitivo

#include <iostream>
#include <utility>

ThreadPool::ThreadPool(size_t n) {
    /* si n==0 usar todos los nucleos disponibles; garantizar al menos 1 */
    if (n == 0) {
        n = std::max<size_t>(1, std::thread::hardware_concurrency());
    }
    workers_.reserve(n);
    /* lanzar cada hilo worker apuntando a worker_loop() */
    for (size_t i = 0; i < n; ++i) {
        workers_.emplace_back([this] { this->worker_loop(); });
    }
}

ThreadPool::~ThreadPool() {
    shutdown(); /* espera que todos los workers terminen antes de destruir */
}

void ThreadPool::shutdown() {
    {
        std::lock_guard lk(tasks_m_);
        stopping_.store(true); /* señal de parada a todos los workers */
    }
    /* despertar a todos los workers para que noten stopping_==true */
    wake_flag_.fetch_add(1, std::memory_order_release);

#ifdef _WIN32
    WakeByAddressAll(&wake_flag_); /* Windows: despertar todos */
#else
    futex_wake(&wake_flag_, workers_.size()); /* Linux: despertar N hilos */
#endif

    /* esperar a que cada hilo termine su iteracion actual */
    for (auto &t : workers_) {
        if (t.joinable()) t.join();
    }
}

bool ThreadPool::idle() {
    std::lock_guard lk(tasks_m_);
    return tasks_.empty(); /* true solo si no hay tareas pendientes en cola */
}

void ThreadPool::worker_loop() {
    while (true) {
        QueuedTask task;

        /* bucle de espera: bloquear hasta que haya tarea o se deba parar */
        while (true) {
            /* El ticket se lee ANTES de mirar la cola, y el orden importa:
             * quien encole a partir de aqui lo incrementara, asi que la espera
             * de abajo vuelve sola porque el valor ya no coincidira.
             *
             * Antes se ponia la bandera a cero justo antes de dormir, y eso
             * BORRABA un aviso ya emitido: encolar -> avisar -> el worker pone
             * el cero -> se duerme para siempre con la tarea en la cola.  Un
             * bloqueo con 0% de CPU, que aparecia al encolar varias tareas
             * nada mas construir el pool -- justo cuando los workers estan
             * pasando por esta ventana. */
            int expected = wake_flag_.load(std::memory_order_acquire);

            /* comprobar cola SIN dormir, con mutex */
            {
                std::lock_guard lk(tasks_m_);
                if (!tasks_.empty())
                    break; /* hay tarea: salir del bucle interno */
                if (stopping_.load())
                    return; /* pool parando: terminar el hilo */
            }

#ifdef _WIN32
            WaitOnAddress(&wake_flag_, &expected, sizeof(int), INFINITE);
#else
            futex_wait(&wake_flag_, expected);
#endif
        }

        /* extraer la tarea del frente de la cola */
        {
            std::lock_guard lk(tasks_m_);
            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
            }
        }

        if (task.fn) {
            /* La etiqueta de quien encolo, mientras dura la tarea.  Sin esto,
             * una fase etiquetada cuyo trabajo se reparta contaria como "no se"
             * todo lo que reserven los trabajadores: un dato falso, no un dato
             * que falta.  Cuesta dos escrituras a la linea de cache que el
             * camino de reserva ya carga de todas formas. */
            const util::AllocScope inherited(task.tag);
            task.fn(); /* ejecutar la tarea; las excepciones se capturan si usa
                          packaged_task */
        }
    }
}
