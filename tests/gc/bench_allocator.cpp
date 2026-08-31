/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/gc/bench_allocator.cpp
 * @brief Compara el asignador del proyecto con el `malloc` del sistema.
 *
 * La pregunta que responde: al compilar, `malloc`+`free` son el 18,5% del
 * tiempo y estan REPARTIDOS -- ningun sitio domina --, asi que lo que moveria
 * la aguja es cambiar el asignador, no un sitio concreto.  Antes de hacer eso
 * hay que saber si el nuestro gana de verdad AL DEL SISTEMA.
 *
 * Ojo con la cifra que se suele citar: el "20 s -> 50-100 ms" del slab es
 * frente a pedir una pagina al SO por reserva, NO frente a `malloc`.  Eso no
 * dice nada sobre esta pregunta.
 *
 * El patron imita al del compilador, que es lo que importa: rafagas de
 * reservas pequenas que viven poco y se sueltan juntas (los vectores de un
 * estado, los nodos de una tabla), no un alloc/free alterno.
 */
#include "gc/raw_allocator.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

/// Tamanos vistos en el perfil del compilador: pares de 32 bytes, nodos de
/// tabla, vectores pequenos que crecen.
constexpr size_t kSizes[] = {24, 32, 48, 64, 96, 128, 192, 256, 512};
constexpr size_t kSizeCount = sizeof(kSizes) / sizeof(kSizes[0]);

/// Reservas vivas a la vez antes de soltarlas todas.
constexpr size_t kBatch = 512;
constexpr int kRounds = 4000;

double elapsed_ms(std::chrono::steady_clock::time_point a,
                  std::chrono::steady_clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

} // namespace

int main() {
    std::vector<void *> live(kBatch);
    std::vector<uint64_t> live_raw(kBatch);

    // --- malloc del sistema ---------------------------------------------
    const auto t0 = std::chrono::steady_clock::now();
    uint64_t sink = 0;
    for (int r = 0; r < kRounds; ++r) {
        for (size_t i = 0; i < kBatch; ++i) {
            void *p = std::malloc(kSizes[(i + r) % kSizeCount]);
            live[i] = p;
            sink += reinterpret_cast<uintptr_t>(p);
        }
        for (size_t i = 0; i < kBatch; ++i)
            std::free(live[i]);
    }
    const auto t1 = std::chrono::steady_clock::now();

    // --- asignador del proyecto -----------------------------------------
    gc::RawAllocator raw;
    const auto t2 = std::chrono::steady_clock::now();
    for (int r = 0; r < kRounds; ++r) {
        for (size_t i = 0; i < kBatch; ++i) {
            const uint64_t p = raw.alloc(kSizes[(i + r) % kSizeCount]);
            live_raw[i] = p;
            sink += p;
        }
        for (size_t i = 0; i < kBatch; ++i)
            raw.free(live_raw[i]);
    }
    const auto t3 = std::chrono::steady_clock::now();

    const double sys_ms = elapsed_ms(t0, t1);
    const double raw_ms = elapsed_ms(t2, t3);
    const double ops = static_cast<double>(kRounds) * kBatch;
    std::printf("reservas: %.0f  (lote=%zu, rondas=%d)\n", ops, kBatch,
                kRounds);
    std::printf("  malloc del sistema : %8.1f ms  (%.1f ns/op)\n", sys_ms,
                sys_ms * 1e6 / ops);
    std::printf("  RawAllocator       : %8.1f ms  (%.1f ns/op)\n", raw_ms,
                raw_ms * 1e6 / ops);
    std::printf("  relacion           : %.2fx %s\n",
                sys_ms > raw_ms ? sys_ms / raw_ms : raw_ms / sys_ms,
                sys_ms > raw_ms ? "a favor del nuestro"
                                : "a favor del sistema");
    // Que el optimizador no borre el trabajo.
    if (sink == 0x1234567) std::printf("(imposible)\n");
    return 0;
}
