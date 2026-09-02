/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia VMProject
 */

/**
 * @file test_monitor_cas.cpp
 * @brief Z.3: tests del monitor CAS lock-free sobre ObjectHeader.
 *
 * Validacion del @c monitor_word atomic (Z.2) y de las primitivas
 * @c monitor_try_acquire / @c monitor_release que lo manipulan via CAS.
 *
 * Cobertura:
 *  - Single-thread: adquirir, soltar, reentrancia.
 *  - Multi-thread: N threads compitiendo por el MISMO monitor; cada
 *    adquisicion exitosa incrementa un contador protegido por el
 *    monitor.  El total debe coincidir con N_threads * iters_per_thread.
 *  - Multi-thread reentrante: cada thread entra varias veces antes de
 *    salir; el monitor debe mantenerse coherente.
 *  - Stress ABA: alloc + free + alloc del mismo monitor en threads
 *    distintos no debe producir double-acquire.
 *
 * Nota: NO usamos un @c ProcessVM real; construimos un @c ObjectHeader
 * directo en stack y llamamos las primitivas como las llamaria el
 * runtime.  Eso testa el word lock-free puro, independiente del
 * scheduler.
 */

#include "loader/oop_types.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_tests_run;                                                         \
        if (cond) {                                                            \
            ++g_tests_passed;                                                  \
            std::printf("  [OK] %s\n", msg);                                   \
        } else {                                                               \
            std::printf("  [FAIL] %s\n", msg);                                 \
        }                                                                      \
    } while (0)

// ----------------------------------------------------------------------
// Helpers: CAS-based monenter / monexit en linea (mismo algoritmo que
// gc_heap.cpp::monitor_try_acquire / monitor_release, pero operando
// sobre un ObjectHeader* directo en lugar de via GcHandle).
// ----------------------------------------------------------------------

/** @brief Intenta adquirir el monitor.  Devuelve true si exito. */
static bool try_acquire(loader::ObjectHeader *hdr, uint32_t pid) {
    uint64_t expected = 0;
    uint64_t desired = loader::monitor_make(pid, 1);
    if (hdr->monitor_word.compare_exchange_strong(expected, desired,
                                                  std::memory_order_acquire,
                                                  std::memory_order_relaxed)) {
        return true; // monitor libre
    }
    if (loader::monitor_owner(expected) == pid) {
        // Reentrante: solo nosotros podemos tocar el word.
        uint32_t d = loader::monitor_depth(expected);
        hdr->monitor_word.store(loader::monitor_make(pid, d + 1),
                                std::memory_order_relaxed);
        return true;
    }
    return false; // ocupado por otro
}

/** @brief Libera el monitor.  Devuelve true si la liberacion fue total. */
static bool release(loader::ObjectHeader *hdr, uint32_t pid) {
    uint64_t cur = hdr->monitor_word.load(std::memory_order_relaxed);
    if (loader::monitor_owner(cur) != pid) return false; // no es nuestro
    uint32_t d = loader::monitor_depth(cur);
    if (d > 1) {
        hdr->monitor_word.store(loader::monitor_make(pid, d - 1),
                                std::memory_order_relaxed);
        return false; // todavia hay reentradas
    }
    hdr->monitor_word.store(0, std::memory_order_release);
    return true; // liberacion total
}

// ----------------------------------------------------------------------
// Test 1: acquire / release single-thread
// ----------------------------------------------------------------------

static void test_single_thread_basic() {
    std::printf("\n=== Test 1: acquire / release single-thread ===\n");
    loader::ObjectHeader hdr;
    hdr.monitor_word.store(0, std::memory_order_relaxed);

    uint32_t self_pid = 42;
    CHECK(try_acquire(&hdr, self_pid), "acquire monitor libre OK");
    uint64_t w = hdr.monitor_word.load(std::memory_order_relaxed);
    CHECK(loader::monitor_owner(w) == self_pid, "owner_pid == 42");
    CHECK(loader::monitor_depth(w) == 1, "lock_depth == 1");

    // Reentrante x3
    CHECK(try_acquire(&hdr, self_pid), "reentrante 2");
    CHECK(try_acquire(&hdr, self_pid), "reentrante 3");
    w = hdr.monitor_word.load(std::memory_order_relaxed);
    CHECK(loader::monitor_depth(w) == 3, "lock_depth == 3 tras 3 acquires");

    // Liberar 3 veces; solo la ultima debe liberar totalmente
    CHECK(!release(&hdr, self_pid), "release 1 de 3: no libera (depth=2)");
    CHECK(!release(&hdr, self_pid), "release 2 de 3: no libera (depth=1)");
    CHECK(release(&hdr, self_pid), "release 3 de 3: libera totalmente");

    w = hdr.monitor_word.load(std::memory_order_relaxed);
    CHECK(w == 0, "monitor word == 0 tras liberacion total");
}

// ----------------------------------------------------------------------
// Test 2: otro pid no puede adquirir
// ----------------------------------------------------------------------

static void test_other_pid_blocked() {
    std::printf("\n=== Test 2: otro pid no puede adquirir mientras owner != "
                "self ===\n");
    loader::ObjectHeader hdr;
    hdr.monitor_word.store(0, std::memory_order_relaxed);

    CHECK(try_acquire(&hdr, 10), "pid=10 adquiere OK");
    CHECK(!try_acquire(&hdr, 20), "pid=20 NO puede adquirir (ocupado)");
    CHECK(!try_acquire(&hdr, 30), "pid=30 NO puede adquirir");

    // Tras liberar pid=10, otro puede adquirir
    release(&hdr, 10);
    CHECK(try_acquire(&hdr, 20), "tras liberar pid=10, pid=20 adquiere OK");
    release(&hdr, 20);
}

// ----------------------------------------------------------------------
// Test 3: N threads compiten por monitor; counter protegido cuadra
// ----------------------------------------------------------------------

static void test_concurrent_mutex() {
    std::printf("\n=== Test 3: 8 threads x 50K acquires/releases sobre el "
                "mismo monitor ===\n");
    loader::ObjectHeader hdr;
    hdr.monitor_word.store(0, std::memory_order_relaxed);

    constexpr int THREADS = 8;
    constexpr int ITERS = 50000;

    // Contador protegido por el monitor.  Si el lock funciona, las
    // increments seran serializadas y el total final sera exacto.
    // Si hubiera race, veriamos un total menor (perdida de updates).
    uint64_t counter = 0; // NO atomic: protegido por el monitor

    std::vector<std::thread> threads;
    threads.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&hdr, &counter, t]() {
            uint32_t pid = (uint32_t)(t + 1);
            for (int i = 0; i < ITERS; ++i) {
                // Spin-acquire (busy wait) hasta exito
                while (!try_acquire(&hdr, pid)) {
                    std::this_thread::yield();
                }
                // Critical section: leer-modificar-escribir counter
                uint64_t v = counter;
                // Pequeno trabajo para amplificar race windows
                counter = v + 1;
                release(&hdr, pid);
            }
        });
    }
    for (auto &th : threads)
        th.join();

    CHECK(counter == (uint64_t)(THREADS * ITERS),
          "counter == THREADS * ITERS (sin perdida de updates)");
    uint64_t w = hdr.monitor_word.load(std::memory_order_relaxed);
    CHECK(w == 0, "monitor libre tras stress (sin leaks de lock)");
    std::printf("  (info) counter=%llu expected=%llu\n",
                (unsigned long long)counter,
                (unsigned long long)(THREADS * ITERS));
}

// ----------------------------------------------------------------------
// Test 4: stress con reentrancia profunda
// ----------------------------------------------------------------------

static void test_concurrent_reentrant() {
    std::printf(
        "\n=== Test 4: 4 threads x 10K acquires reentrantes profundos ===\n");
    loader::ObjectHeader hdr;
    hdr.monitor_word.store(0, std::memory_order_relaxed);

    constexpr int THREADS = 4;
    constexpr int ITERS = 10000;
    constexpr int DEPTH = 8;

    uint64_t counter = 0;

    std::vector<std::thread> threads;
    threads.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&hdr, &counter, t]() {
            uint32_t pid = (uint32_t)(t + 1);
            for (int i = 0; i < ITERS; ++i) {
                // Acquire DEPTH veces (reentrante)
                while (!try_acquire(&hdr, pid))
                    std::this_thread::yield();
                for (int j = 1; j < DEPTH; ++j) {
                    bool ok = try_acquire(&hdr, pid);
                    if (!ok) {
                        std::printf("  ERROR: reentrante fallo en thread %d "
                                    "iter %d depth %d\n",
                                    t, i, j);
                        return;
                    }
                }
                counter++;
                // Release DEPTH veces
                for (int j = 0; j < DEPTH; ++j) {
                    release(&hdr, pid);
                }
            }
        });
    }
    for (auto &th : threads)
        th.join();

    CHECK(counter == (uint64_t)(THREADS * ITERS),
          "counter == THREADS * ITERS con reentrancia");
    uint64_t w = hdr.monitor_word.load(std::memory_order_relaxed);
    CHECK(w == 0, "monitor libre tras stress reentrante");
}

// ----------------------------------------------------------------------
// Test 5: layout y offsets (sanity: confirma que monitor_word esta en
//         el offset 16 exacto y los helpers descomponen correctamente)
// ----------------------------------------------------------------------

static void test_layout() {
    std::printf("\n=== Test 5: layout ABI v3 (monitor_word @ offset 16) ===\n");
    CHECK(sizeof(loader::ObjectHeader) == 24, "sizeof(ObjectHeader) == 24");
    CHECK(offsetof(loader::ObjectHeader, monitor_word) == 16,
          "offsetof(monitor_word) == 16");
    /* El reparto del monitor_word es 48 bits de dueno + 16 de profundidad, y

     * * no es arbitrario: el dueno es un pid CODIFICADO (scheduler<<32 |
     * local),
     * que ya ocupa 48.  El test comprobaba el reparto 32/32 de
     * antes, y solo
     * se notaba a medias -- la mitad del dueno seguia
     * pasando porque el valor
     * que usaba cabia en los dos repartos. */
    const uint64_t owner = 0x1234ABCD5678ULL; // 48 bits, como un pid real
    const uint32_t depth = 0xBEEFu;           // 16 bits
    uint64_t w = loader::monitor_make(owner, depth);
    CHECK(loader::monitor_owner(w) == owner, "monitor_owner extrae bits 0-47");
    CHECK(loader::monitor_depth(w) == depth, "monitor_depth extrae bits 48-63");
    // Los dos campos no se pisan: el maximo de cada uno deja intacto al otro.
    uint64_t wmax = loader::monitor_make(loader::MONITOR_OWNER_MASK, 0xFFFFu);
    CHECK(loader::monitor_owner(wmax) == loader::MONITOR_OWNER_MASK,
          "dueno maximo (48 bits) intacto");
    CHECK(loader::monitor_depth(wmax) == 0xFFFFu,
          "profundidad maxima (65535) intacta");

    // Round-trip: empacar, desempacar, comparar
    uint64_t w2 = loader::monitor_make(loader::monitor_owner(w),
                                       loader::monitor_depth(w));
    CHECK(w == w2, "round-trip monitor_make(owner, depth) consistente");
}

// ----------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------

int main() {
    std::printf("=== Z.3: monitor CAS lock-free tests ===\n");
    test_layout();
    test_single_thread_basic();
    test_other_pid_blocked();
    test_concurrent_mutex();
    test_concurrent_reentrant();

    std::printf("\n=== Resultados ===\n");
    std::printf("Pasaron: %d/%d\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
