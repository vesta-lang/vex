/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/jit_timing.h
 * @brief Telemetria de COMPILACION del JIT: cuanto tiempo se dedica a compilar,
 * y a compilar QUE.
 *
 * POR QUE EXISTE.  El JIT compila DURANTE la ejecucion, asi que el reloj de
 * pared de un programa mezcla dos cosas que se optimizan en direcciones
 * opuestas:
 *
 *     tiempo total  =  compilar  +  ejecutar lo compilado
 *
 * Una optimizacion del codigo generado mejora el segundo sumando y empeora el
 * primero. Sin separarlos no se puede afirmar nada: en un programa de carga
 * corta, una pasada mas del backend puede dominar el cronometro y esconder por
 * completo la ganancia real. Medirlo convierte "creo que el programa es corto"
 * en un dato -- la FRACCION del tiempo que se va en compilar -- y evita el
 * unico criterio que no seria reproducible: umbrales en milisegundos absolutos,
 * que dependen de la CPU, del build y de la carga.
 *
 * COSTE.  Dos lecturas de reloj por FUNCION COMPILADA (no por instruccion
 * ejecutada): decenas de nanosegundos frente a una compilacion de microsegundos
 * o milisegundos.  Es ruido de fondo del propio evento que mide, asi que el
 * total se acumula SIEMPRE y no hace falta un gate para el agregado.  Lo que si
 * es opt-in es guardar el desglose POR FUNCION (@c VESTA_JIT_TIME=1), que si
 * crece con el numero de funciones.
 *
 * i18n: produce DATOS (numeros), no diagnosticos -> sin catalogo.
 */

#ifndef VESTA_JIT_JIT_TIMING_H
#define VESTA_JIT_JIT_TIMING_H

#include "util/env_flags.h"
#include "util/thread_slot.h" // la profundidad por hilo, sin `thread_local`

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

namespace jit {

/**
 * @struct JitCompileSample
 * @brief Una compilacion: que funcion, cuanto tardo y cuanto codigo produjo.
 */
struct JitCompileSample {
    std::string name;
    uint64_t ns = 0;
    uint32_t code_bytes = 0;
    uint32_t seq =
        0; ///< orden de compilacion (1 = la primera de la ejecucion).
    uint16_t depth = 0; ///< 0 = compilacion raiz; >0 = anidada dentro de otra.

    /* @c seq no es redundante con la posicion en el vector: el vector se
     * REORDENA para los informes (por coste) y, con compilacion en varios
     * hilos, el orden de insercion ya no seria el orden real.  Guardarlo
     * permite reconstruir la SECUENCIA -- que se compilo primero, si el grueso
     * del coste esta al arrancar o repartido -- sin depender de como quede
     * almacenado.
     *
     * EVOLUCION PREVISTA (no ahora): cuando interese el desglose POR FASE
     * (seleccion, regalloc, scheduling, encoding...), esto crece con un @c
     * vector<PhaseTiming> sin romper la API -- los consumidores actuales solo
     * leen name/ns/code_bytes. */
};

/**
 * @class JitTiming
 * @brief Acumulador global del tiempo de compilacion.  Thread-safe.
 *
 * El AGREGADO (total + numero de funciones) esta siempre disponible -- lo
 * consume
 * @c --stats.  El DESGLOSE por funcion solo se guarda con @c VESTA_JIT_TIME=1,
 * porque su coste en memoria si escala con el programa.
 */
class JitTiming {
  public:
    static JitTiming &instance() {
        /* INMORTAL a proposito (se filtra una vez, al salir del proceso).
         *
         * El resumen se imprime desde un @c atexit, y ese handler se registra
         * ANTES de que exista el singleton -> con un `static JitTiming t;` el
         * destructor del estatico correria PRIMERO y el handler leeria un
         * objeto ya destruido: nombres vacios, tiempos a cero, basura.
         * (Ocurrio: el desglose salia con `#0` y 0 us.) Un objeto que nunca se
         * destruye no puede observarse destruido. */
        static JitTiming *t = new JitTiming();
        return *t;
    }

    /// ¿Guardar el desglose por funcion?  Opt-in via @c VESTA_JIT_TIME=1.
    static bool detail_enabled() {
        static const bool on = util::flag_on(util::FlagId::JitTime);
        return on;
    }

    /// Registra una compilacion.  @p name puede ir vacio si no se guarda el
    /// detalle.
    void record(const char *name, uint64_t ns, uint32_t code_bytes,
                uint16_t depth) {
        /* Al TOTAL solo suma la compilacion RAIZ.  Compilar una funcion compila
         * recursivamente sus callees DENTRO de su propio cronometro, asi que el
         * tiempo por funcion es INCLUSIVO: sumar todos daria el mismo trabajo
         * contado varias veces (se vio: porcentajes de "compilar" por encima
         * del 100% del tiempo de pared).  El tiempo real de compilacion es el
         * de los arboles raiz. */
        if (depth == 0) total_ns_.fetch_add(ns, std::memory_order_relaxed);
        const uint64_t seq = count_.fetch_add(1, std::memory_order_relaxed) + 1;
        total_bytes_.fetch_add(code_bytes, std::memory_order_relaxed);
        /* MAXIMO, no solo la media: una media de decenas de microsegundos junto
         * a un maximo de milisegundos delata una funcion monstruosa que la
         * media esconde por completo.  CAS en bucle -- solo reintenta si otro
         * hilo subio el maximo a la vez. */
        uint64_t prev = max_ns_.load(std::memory_order_relaxed);
        while (ns > prev && !max_ns_.compare_exchange_weak(
                                prev, ns, std::memory_order_relaxed)) {
        }
        if (!detail_enabled()) return;
        /* El mutex solo se toca con el detalle ACTIVO (opt-in).  Si el JIT
         * llegara a compilar en muchos hilos a la vez habria contencion aqui:
         * la salida natural es un buffer thread_local fusionado al final, no un
         * lock mas fino. */
        std::lock_guard<std::mutex> lk(mtx_);
        samples_.push_back({name ? name : "", ns, code_bytes,
                            static_cast<uint32_t>(seq), depth});
    }

    uint64_t total_ns() const noexcept {
        return total_ns_.load(std::memory_order_relaxed);
    }
    uint64_t count() const noexcept {
        return count_.load(std::memory_order_relaxed);
    }
    uint64_t total_bytes() const noexcept {
        return total_bytes_.load(std::memory_order_relaxed);
    }
    /// La compilacion mas cara.  Disponible SIN el gate de detalle: la media
    /// sola engana, y saber que existe un caso extremo no deberia costar
    /// activar nada.
    uint64_t max_ns() const noexcept {
        return max_ns_.load(std::memory_order_relaxed);
    }

    /// Copia del desglose (vacio si el detalle no esta activo).
    std::vector<JitCompileSample> samples() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return samples_;
    }

  private:
    JitTiming() = default;
    std::atomic<uint64_t> total_ns_{0};
    std::atomic<uint64_t> count_{0};
    std::atomic<uint64_t> total_bytes_{0};
    std::atomic<uint64_t> max_ns_{0};
    mutable std::mutex mtx_;
    std::vector<JitCompileSample> samples_;
};

/**
 * @class ScopedJitTimer
 * @brief Cronometra una compilacion con RAII: registra al salir del ambito,
 * tambien si se sale por una rama de error o por excepcion.  Asi ninguna
 * compilacion se queda sin contabilizar por un @c return temprano.
 */
class ScopedJitTimer {
  public:
    explicit ScopedJitTimer(const char *name) noexcept
        : name_(name), t0_(std::chrono::steady_clock::now()),
          depth_(depth()) {
        set_depth(static_cast<uint16_t>(depth_ + 1));
    }

    /// El tamano se conoce al final; se informa antes de que el objeto muera.
    void set_code_bytes(uint32_t n) noexcept { code_bytes_ = n; }

    ~ScopedJitTimer() {
        set_depth(static_cast<uint16_t>(depth() - 1));
        const auto dt = std::chrono::steady_clock::now() - t0_;
        JitTiming::instance().record(
            name_,
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(dt)
                    .count()),
            code_bytes_, depth_);
    }

  private:
    /* Profundidad de anidamiento POR HILO (el JIT puede compilar en varios).
     *
     * En una RANURA y no en `thread_local`: en MinGW la TLS es emulada y cada
     * acceso es una llamada.  El contador cabe en el propio puntero, asi que
     * no hay nada que reservar.  Ver `util/thread_slot.h`. */
    static util::ThreadSlot &depth_slot() noexcept {
        static util::ThreadSlot s;
        return s;
    }
    /// La profundidad de ESTE hilo.
    static uint16_t depth() noexcept {
        return static_cast<uint16_t>(
            reinterpret_cast<uintptr_t>(depth_slot().get()));
    }
    /// Fija la profundidad de ESTE hilo.
    static void set_depth(uint16_t d) noexcept {
        depth_slot().ensure();
        depth_slot().set(reinterpret_cast<void *>(static_cast<uintptr_t>(d)));
    }

    const char *name_ = nullptr;
    std::chrono::steady_clock::time_point t0_;
    uint32_t code_bytes_ = 0;
    uint16_t depth_ = 0;
};

/**
 * @brief Resumen del tiempo de compilacion a stderr.  Lo invoca @c --stats
 * (siempre) y el gate @c VESTA_JIT_TIME=1 al terminar el proceso (con desglose
 * por funcion).
 * @param detail  si true, lista las funciones mas caras de compilar.
 *
 * El dato que hay que leer no es el total en si, sino su relacion con el tiempo
 * de pared: si compilar se lleva una fraccion grande, cualquier medida de "que
 * tan rapido corre el codigo generado" esta contaminada y hay que interpretarla
 * con eso delante.
 */
inline void print_jit_timing(bool detail) {
    const JitTiming &t = JitTiming::instance();
    if (t.count() == 0) return;
    const double ms = t.total_ns() / 1e6;
    std::fprintf(
        stderr,
        "\n=== [jit] tiempo de COMPILACION ===\n"
        "  funciones compiladas ... %llu\n"
        "  tiempo total ........... %.3f ms  (media %.1f us/funcion)\n"
        "  la mas cara ............ %.1f us"
        "   [si dista mucho de la media, hay una funcion monstruosa]\n"
        "  codigo emitido ......... %llu bytes  (%.0f bytes/funcion)\n",
        (unsigned long long)t.count(), ms,
        t.count() ? (t.total_ns() / 1000.0) / t.count() : 0.0,
        t.max_ns() / 1000.0, (unsigned long long)t.total_bytes(),
        t.count() ? 1.0 * t.total_bytes() / t.count() : 0.0);
    if (!detail) return;
    std::vector<JitCompileSample> s = t.samples();
    if (s.empty()) {
        std::fprintf(stderr, "  (sin desglose: exporta VESTA_JIT_TIME=1)\n");
        return;
    }
    std::sort(s.begin(), s.end(),
              [](const JitCompileSample &a, const JitCompileSample &b) {
                  return a.ns > b.ns;
              });
    std::fprintf(stderr, "  --- las mas caras de compilar ---\n");
    const size_t n = s.size() < 15 ? s.size() : 15;
    for (size_t i = 0; i < n; ++i)
        std::fprintf(stderr, "    #%-5u %-40s %8.1f us  %6u bytes\n", s[i].seq,
                     s[i].name.c_str(), s[i].ns / 1000.0, s[i].code_bytes);
}

} // namespace jit

#endif // VESTA_JIT_JIT_TIMING_H
