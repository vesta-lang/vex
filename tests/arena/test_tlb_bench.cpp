/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/arena/test_tlb_bench.cpp
 * @brief Banco de la TLB: coste de consulta, memoria, construccion y CARRERA.
 *
 * POR QUE EXISTE
 * --------------
 * Se propuso rehacer la TLB -- nodos de tamano fijo y publicacion atomica en
 * vez de `std::vector` que se realoca --, y un cambio asi no se hace a ciegas:
 * hay que poder decir DESPUES si de verdad quedo mejor, y en que.
 *
 * Los cuatro ejes miden cosas distintas y hay que leerlos por separado:
 *
 *   1. CONSULTA   cuanto cuesta traducir una direccion ya mapeada.  Es el
 *                 camino de FALLO de la cache de pagina, no el comun.
 *   2. MEMORIA    cuanto reserva el arbol.  Es DETERMINISTA -- ni ruido ni
 *                 termica --, asi que es la cifra mas solida de las cuatro.
 *   3. CONSTRUIR  cuanto cuesta crear las paginas, que es donde el `resize`
 *                 del disenyo actual duele.
 *   4. CARRERA    si un lector puede leer mientras otro hilo crea paginas.
 *                 Esto no es una medida: es una PRUEBA.
 *
 *                 Y HOY NO CONCLUYE.  El disenyo actual TIENE la carrera --
 *                 `translate` realoja los vectores que `get_entry` recorre, y
 *                 eso es una carrera de datos por definicion --, pero este
 *                 banco no consigue observarla: cero incoherencias en tres
 *                 millones de lecturas.  El motivo es que en x86-64 el buffer
 *                 viejo sigue mapeado tras liberarse y las cargas son de ocho
 *                 bytes alineados, asi que el lector suele salirse con la
 *                 suya.  Que no se vea no la hace segura, pero tampoco
 *                 autoriza a decir que esta probada: la linea se queda para
 *                 que el rediseno tenga que seguir dandola en cero, no como
 *                 evidencia de nada.
 *
 * LO QUE YA SE SABE Y ESTE BANCO TIENE QUE ENSENYAR
 * ------------------------------------------------
 * El reparto de la direccion es 12 / 12 / 16 / 24 bits, asi que `translate`
 * hace `root.resize(pt2 + 1)` y `children.resize(pt1 + 1)`.  Con un indice
 * alto eso reserva un vector enorme por UNA sola pagina, y ademas lo MUEVE --
 * que es la carrera del eje 4 --.
 *
 * COMO SE USA
 * -----------
 * Sin argumentos imprime los cuatro ejes.  `--csv` los saca en una linea por
 * medida para poder comparar dos commits sin leer a ojo.
 */

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <thread>
#include <vector>

#include "arena/TLB.h"
#include "util/reloj.h"

namespace {

/// Paginas de 4 KB: es el tamano que la TLB indexa.
constexpr uint64_t kPage = 4096;

/// Cuantas paginas se usan en los ejes de consulta y construccion.  Bastantes
/// para que el arbol tenga varios nodos por nivel y pocas para que el banco
/// termine en segundos.
constexpr uint32_t kPages = 4096;

/// Vueltas del eje de consulta.  Suficientes para que el reloj tenga
/// resolucion de sobra frente a una traduccion, que son nanosegundos.
constexpr uint32_t kLookups = 2000000;

/// Un destino cualquiera: lo que importa es que la entrada exista y que el
/// valor leido se pueda comprobar, no a donde apunte.
vm::ptr_mapped host_target(uint64_t page) {
    vm::ptr_mapped pm{};
    pm.ptr_host = reinterpret_cast<void *>(static_cast<uintptr_t>(page));
    return pm;
}

/**
 * @brief Los tres patrones de direcciones, y por que son tres.
 *
 * El coste de la TLB no depende de CUANTAS paginas hay sino de COMO estan
 * repartidas: el arbol tiene un nivel por tramo de bits, asi que dos paginas
 * que solo difieren en los bits bajos comparten los dos nodos de arriba, y dos
 * que difieren en los altos no comparten ninguno.
 */
enum class Pattern {
    Contiguous, ///< paginas seguidas desde 0: el caso comun de un programa
    ScatteredMid, ///< separadas 16 MB: cambia PT1 en cada una
    ScatteredHigh, ///< separadas 1 TB: cambia PT2, que es el nivel de 24 bits
};

const char *pattern_name(Pattern p) {
    switch (p) {
    case Pattern::Contiguous: return "contiguo";
    case Pattern::ScatteredMid: return "disperso-medio";
    default: return "disperso-alto";
    }
}

/// La direccion de la pagina @p i segun el patron.
uint64_t address_of(Pattern p, uint32_t i) {
    switch (p) {
    case Pattern::Contiguous: return (uint64_t)i * kPage;
    // 16 MB = 2^24, justo el bit donde empieza PT1.
    case Pattern::ScatteredMid: return (uint64_t)i << 24;
    // 1 TB = 2^40, justo el bit donde empieza PT2.
    default: return (uint64_t)i << 40;
    }
}

/* La memoria la dice la PROPIA TLB (`memory_bytes`), no un contador de fuera.
 *
 * Se intento interceptando `operator new` y estaba mal por dos motivos.  Uno
 * practico: ese asignador ya lo sustituye el proyecto -- `util/host_allocator`
 * --, asi que ni enlazaba.  Y otro de fondo, que es el que importa: `new` es
 * la memoria del ANFITRION, y la TLB es el mapa de la VM.  Contar una con la
 * otra mezcla dos capas distintas y ademas se traga las reservas de todo lo
 * demas que corra en el proceso. */

bool g_csv = false;

/// Una medida, en el formato que toque.
void report(const char *axis, const char *variant, double value,
            const char *unit) {
    if (g_csv)
        std::printf("%s;%s;%.3f;%s\n", axis, variant, value, unit);
    else
        std::printf("  %-14s %-16s %12.3f %s\n", axis, variant, value, unit);
}

// --- 1. CONSULTA ----------------------------------------------------------

/**
 * @brief Cuanto cuesta traducir una direccion YA mapeada.
 *
 * Se recorren las paginas dando saltos de un numero primo de posiciones para
 * que el predictor no adivine cual toca -- recorrerlas en orden mediria el
 * prefetch del anfitrion, no el arbol --.
 */
void bench_lookup(Pattern p) {
    tlb::LazyHybridTLB t;
    for (uint32_t i = 0; i < kPages; ++i)
        t.translate(address_of(p, i), vm::MAPPED_PTR_HOST, host_target(i));

    // Primo mayor que ningun divisor de kPages: recorre TODAS sin repetir.
    constexpr uint32_t kStride = 1789;
    uint32_t idx = 0;
    uint64_t sink = 0; // acumula para que nadie borre el bucle

    const uint64_t t0 = ::util::reloj::ahora();
    for (uint32_t n = 0; n < kLookups; ++n) {
        idx = (idx + kStride) % kPages;
        const tlb::TLBEntryData *e = t.get_entry(address_of(p, idx));
        sink += (e != nullptr) ? (uintptr_t)e->address.ptr_host : 0u;
    }
    const double ns =
        (double)::util::reloj::a_ns(::util::reloj::ahora() - t0) /
        (double)kLookups;

    if (sink == 0) std::printf("  (sink vacio: el bucle se borro)\n");
    report("consulta", pattern_name(p), ns, "ns/consulta");
}

// --- 2. MEMORIA -----------------------------------------------------------

/**
 * @brief Cuanto reserva el arbol para @p pages paginas de cada patron.
 *
 * Es el eje mas solido: no depende del reloj ni de la maquina, asi que dos
 * commits se comparan sin margen de ruido.  Y es donde el disenyo actual se
 * cae: `root.resize(pt2 + 1)` con `pt2` de 24 bits reserva hasta 134 MB de
 * punteros por UNA pagina.
 */
void bench_memory(Pattern p, uint32_t pages) {
    tlb::LazyHybridTLB t;
    for (uint32_t i = 0; i < pages; ++i)
        t.translate(address_of(p, i), vm::MAPPED_PTR_HOST, host_target(i));
    /* Dos cifras, y son distintas a proposito.  La tabla crece duplicandose y
     * guarda la anterior viva por si algun lector se quedo dentro, asi que el
     * PICO incluye esa cadena; el runtime la suelta en cuanto sabe que no hay
     * lectores.  Ensenyar solo una de las dos enganaria en un sentido o en el
     * otro. */
    const double peak = (double)t.memory_bytes() / 1024.0;
    t.reclaim_older();
    const double kept = (double)t.memory_bytes() / 1024.0;
    char name[48];
    std::snprintf(name, sizeof(name), "%s-pico", pattern_name(p));
    report("memoria", name, peak, "KB");
    std::snprintf(name, sizeof(name), "%s-tras-soltar", pattern_name(p));
    report("memoria", name, kept, "KB");
}

/**
 * @brief El caso extremo: UNA sola pagina, en una direccion alta.
 *
 * Separado del anterior porque contesta otra pregunta.  El de arriba dice lo
 * que cuesta un mapa disperso; este dice si el coste es del MAPA o del INDICE:
 * con nodos de tamano fijo, una pagina cuesta un nodo por nivel y ya.
 */
void bench_memory_single_high() {
    tlb::LazyHybridTLB t;
    // Los bits altos puestos: la direccion mas alta que el mapa admite.
    t.translate(0xFFFFFF0000000000ull, vm::MAPPED_PTR_HOST, host_target(1));
    report("memoria", "1-pagina-alta", (double)t.memory_bytes() / 1024.0, "KB");
}

// --- 3. CONSTRUIR ---------------------------------------------------------

/// Cuanto cuesta CREAR las paginas, que es donde el `resize` se paga.
void bench_build(Pattern p) {
    const uint64_t t0 = ::util::reloj::ahora();
    {
        tlb::LazyHybridTLB t;
        for (uint32_t i = 0; i < kPages; ++i)
            t.translate(address_of(p, i), vm::MAPPED_PTR_HOST, host_target(i));
    }
    const double us =
        (double)::util::reloj::a_ns(::util::reloj::ahora() - t0) / 1000.0;
    report("construir", pattern_name(p), us, "us");
}

// --- 4. CARRERA -----------------------------------------------------------

/**
 * @brief Puede un lector leer mientras otro hilo crea paginas?
 *
 * NO es una medida: es una prueba, y con el disenyo de hoy tiene que FALLAR.
 * `translate` hace `resize` sobre los vectores del arbol, o sea que los MUEVE,
 * y el lector se queda indexando memoria liberada.
 *
 * Se monta para que el hueco sea grande a proposito -- el escritor no para de
 * ampliar la raiz mientras los lectores machacan paginas que YA existen --,
 * porque una carrera que solo sale una vez de cada mil no sirve de prueba de
 * regresion: pasaria por suerte.
 *
 * Lo que se comprueba es CONSISTENCIA, no ausencia de fallo: cada consulta que
 * devuelva algo tiene que devolver lo que se guardo.  Un valor distinto es la
 * prueba de que se leyo memoria que ya no era del arbol.
 *
 * @return true si no se detecto ninguna incoherencia.
 */
bool test_race() {
    tlb::LazyHybridTLB t;

    /* Las paginas que los lectores van a mirar.  Se crean ANTES y no se tocan
     * mas: si el arbol fuera estable, leerlas siempre daria lo mismo. */
    constexpr uint32_t kStable = 512;
    for (uint32_t i = 0; i < kStable; ++i)
        t.translate((uint64_t)i * kPage, vm::MAPPED_PTR_HOST, host_target(i));

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> mismatches{0};
    std::atomic<uint64_t> reads{0};

    auto reader = [&] {
        uint64_t local_bad = 0, local_n = 0;
        while (!stop.load(std::memory_order_relaxed)) {
            for (uint32_t i = 0; i < kStable; ++i) {
                const tlb::TLBEntryData *e = t.get_entry((uint64_t)i * kPage);
                ++local_n;
                /* Estas paginas se crearon ANTES de arrancar los lectores y
                 * nadie las vuelve a tocar, asi que la respuesta correcta
                 * SIEMPRE es la misma.  Null tambien es un fallo: significa
                 * que el arbol perdio una entrada que tenia -- `resize` mueve
                 * los `unique_ptr` y deja el origen vacio --.
                 *
                 * Aceptar el null fue el error de la primera version: se
                 * tragaba justo la unica forma en que esta carrera se
                 * manifiesta sin reventar. */
                if (e == nullptr ||
                    (uintptr_t)e->address.ptr_host != (uintptr_t)i)
                    ++local_bad;
            }
        }
        mismatches.fetch_add(local_bad, std::memory_order_relaxed);
        reads.fetch_add(local_n, std::memory_order_relaxed);
    };

    std::thread r1(reader), r2(reader);

    /* El escritor amplia el vector que los lectores SI recorren.
     *
     * Es la diferencia entre una prueba y un adorno.  La primera version
     * ampliaba la RAIZ (bits 40+), que los lectores indexan UNA vez en la
     * posicion cero: salieron cero incoherencias de 34.304 lecturas, o sea que
     * no probaba nada.  Creciendo por `1 << 24` se amplia `children` del nodo
     * raiz -- el nivel PT1 --, que es justo el array que cada consulta indexa
     * en su segundo salto.
     *
     * Y `resize` sobre un vector de `unique_ptr` no solo mueve el array: MUEVE
     * los punteros, dejando el origen a null.  Asi que el lector puede ver un
     * hueco donde habia una pagina, que es lo que se detecta abajo. */
    for (uint32_t round = 0; round < 64; ++round)
        for (uint32_t i = 1; i <= 512; ++i)
            t.translate(((uint64_t)i << 24) | ((uint64_t)round << 12),
                        vm::MAPPED_PTR_HOST, host_target(i));

    stop.store(true, std::memory_order_relaxed);
    r1.join();
    r2.join();

    const uint64_t bad = mismatches.load();
    const uint64_t n = reads.load();
    if (g_csv) {
        std::printf("carrera;incoherencias;%llu;de %llu lecturas\n",
                    (unsigned long long)bad, (unsigned long long)n);
    } else {
        std::printf("  %-14s %-16s %12llu de %llu lecturas\n", "carrera",
                    "incoherencias", (unsigned long long)bad,
                    (unsigned long long)n);
    }
    return bad == 0;
}

} // namespace


// --- Memoria del proceso, por plataforma ----------------------------------

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
namespace {
size_t rss_bytes() {
    PROCESS_MEMORY_COUNTERS pmc{};
    if (!GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) return 0;
    return (size_t)pmc.WorkingSetSize;
}
} // namespace
#else
namespace {
size_t rss_bytes() {
    // `statm` da paginas residentes; el segundo campo es el conjunto residente.
    std::FILE *f = std::fopen("/proc/self/statm", "r");
    if (f == nullptr) return 0;
    unsigned long total = 0, resident = 0;
    const int got = std::fscanf(f, "%lu %lu", &total, &resident);
    std::fclose(f);
    if (got != 2) return 0;
    return (size_t)resident * 4096u;
}
} // namespace
#endif

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--csv") == 0) g_csv = true;

    if (!g_csv) {
        std::printf("\nTLB: coste, memoria y seguridad\n");
        std::printf("  Reparto de la direccion HOY: 12 offset / 12 PT / "
                    "16 PT1 / 24 PT2\n");
        std::printf("  Los vectores de cada nivel CRECEN con `resize`, o sea "
                    "que se mueven.\n\n");
    }

    bench_lookup(Pattern::Contiguous);
    bench_lookup(Pattern::ScatteredMid);
    bench_lookup(Pattern::ScatteredHigh);

    bench_build(Pattern::Contiguous);
    bench_build(Pattern::ScatteredMid);
    bench_build(Pattern::ScatteredHigh);

    bench_memory(Pattern::Contiguous, kPages);
    bench_memory(Pattern::ScatteredMid, kPages);
    bench_memory(Pattern::ScatteredHigh, 256);
    bench_memory_single_high();

    const bool race_ok = test_race();

    if (!g_csv) {
        std::printf("\n  La linea de CARRERA es la que decide si el disenyo es "
                    "seguro:\n  con el de hoy tiene que salir distinta de "
                    "cero.\n");
        std::printf("\n=== test_tlb_bench: %s ===\n",
                    race_ok ? "sin incoherencias" : "HAY INCOHERENCIAS");
    }
    /* Se sale con CERO aunque la carrera aparezca: hoy es el comportamiento
     * ESPERADO y este binario es un banco, no una guardia.  Cuando la TLB sea
     * segura, esta linea pasa a ser un fallo de verdad. */
    return 0;
}
