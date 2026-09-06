/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/arena/test_vmem_stress.cpp
 * @brief Estres de la memoria virtual: lo que el interprete usa DE VERDAD.
 *
 * POR QUE ESTE Y NO SOLO `test_tlb_bench`
 * ---------------------------------------
 * Aquel mide el ARBOL -- `translate` y `get_entry` a pelo --, y con eso no se
 * puede juzgar un rediseno de la TLB, porque casi ningun acceso del interprete
 * llega al arbol: delante hay una cache de pagina que se los come.  Conectarla
 * a `operator[]` dio un -20,6%, asi que la pregunta no es "cuanto cuesta el
 * recorrido" sino "cuantas veces se paga".
 *
 * Y hay un detalle que lo decide todo: **la cache de pagina tiene UNA
 * entrada**.  Con un conjunto de trabajo de una pagina acierta siempre; con
 * dos, alternar entre ellas falla el 100% de las veces y paga el recorrido
 * entero.  O sea que el peso de la TLB no depende del programa en abstracto,
 * sino de cuantas paginas toca en el bucle -- y eso es justo lo que este banco
 * barre.
 *
 * LOS EJES
 * --------
 *   1. CONJUNTO   ns por acceso segun cuantas paginas distintas se tocan.  Es
 *                 el eje principal: dice a partir de que punto la cache deja
 *                 de servir y empieza a mandar la TLB.
 *   2. PATRON     secuencial contra aleatorio con el mismo conjunto.  Separa
 *                 el acierto de cache del prefetch del anfitrion.
 *   3. BLOQUE     `read_bytes` / `write_bytes` de 8 a 8192 bytes.  A partir de
 *                 4096 cruza pagina, que es otro camino.
 *   4. PRIMER     coste de TOCAR paginas nuevas (asignacion perezosa), que es
 *      TOQUE      donde el `resize` del arbol se paga.
 *   5. MEMORIA    bytes que el mapa pide al monton, contados exacto.
 *
 * COMO SE LEE PARA JUZGAR EL REDISENO
 * -----------------------------------
 * Un cambio en la TLB que mejore el recorrido pero no mueva el eje 1 en el
 * tramo de una o dos paginas NO sirve de nada para el interprete: ahi no se
 * recorre.  Donde tiene que verse es de cuatro paginas en adelante.
 */

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

#include "arena/TLB.h"
#include "arena/VirtualMemory.h"
#include "arena/arena_manager.h"
#include "util/reloj.h"

namespace {

constexpr uint64_t kPage = 4096;

/// Base del mapa.  Lejos de cero para no coincidir con nada que el resto del
/// sistema mapee por su cuenta.
constexpr uint64_t kBase = 0x400000;

/// Accesos por medida.  Bastantes para que el reloj no sea el que manda: un
/// acceso son unidades de nanosegundo.
constexpr uint32_t kAccesses = 4000000;

/// Bytes pedidos al monton, contados interceptando `operator new`.  Es
/// DETERMINISTA, al contrario que el conjunto residente, que no tiene
/// resolucion para unos pocos KB.
std::atomic<size_t> g_alloc_bytes{0};

bool g_csv = false;

void report(const char *axis, const char *variant, double value,
            const char *unit) {
    if (g_csv)
        std::printf("%s;%s;%.3f;%s\n", axis, variant, value, unit);
    else
        std::printf("  %-12s %-18s %12.3f %s\n", axis, variant, value, unit);
}

/// Todo lo que hace falta para tener una memoria virtual viva.
struct Vm {
    tlb::LazyHybridTLB tlb;
    vm::ArenaManager arena;
    vm::VirtualMemory mem{tlb, arena};

    /// Toca @p pages paginas desde la base para que existan antes de medir.
    ///
    /// Escribe en el byte 8, que es el MISMO que despues se lee: si se
    /// escribiera en otro, el acumulador saldria cero y la guarda de "el bucle
    /// se borro" daria una falsa alarma en todas las medidas.
    void touch(uint32_t pages) {
        for (uint32_t i = 0; i < pages; ++i)
            mem[kBase + (uint64_t)i * kPage + 8] = 1;
    }
};

// --- 1 y 2. CONJUNTO DE TRABAJO Y PATRON ----------------------------------

/**
 * @brief ns por acceso tocando @p pages paginas distintas en el bucle.
 *
 * El eje que decide si un cambio en la TLB le importa al interprete.  Con
 * `pages == 1` la cache de pagina acierta siempre y el arbol no se toca; a
 * partir de dos, cada acceso que cambie de pagina lo recorre entero.
 *
 * @param random Si se salta de pagina en pagina en orden o dando saltos.  En
 *        orden, el anfitrion prefetchea y se mide otra cosa.
 */
void bench_working_set(uint32_t pages, bool random) {
    Vm v;
    v.touch(pages);

    /* Un salto primo respecto al numero de paginas recorre TODAS sin repetir y
     * sin que el predictor acierte cual toca.
     *
     * Y el indice se cierra con un AND, no con un resto: `pages` es una
     * variable, asi que `%` baja a una DIVISION y son varios nanosegundos --
     * mas que el acceso que se quiere medir --.  La primera version de este
     * banco salia plana de 1 a 1024 paginas por eso: estaba midiendo la
     * division.  Por eso todos los tamanos son potencias de dos. */
    const uint32_t mask = pages - 1u;
    const uint32_t stride = random ? 1789u : 1u;
    uint32_t idx = 0;
    uint64_t sink = 0;

    const uint64_t t0 = ::util::reloj::ahora();
    for (uint32_t n = 0; n < kAccesses; ++n) {
        idx = (idx + stride) & mask;
        // Byte 8: el mismo que `touch` dejo escrito, para que el acumulador
        // signifique algo y la guarda de abajo no mienta.
        sink += v.mem[kBase + (uint64_t)idx * kPage + 8];
    }
    const double ns =
        (double)::util::reloj::a_ns(::util::reloj::ahora() - t0) /
        (double)kAccesses;

    if (sink == 0) std::printf("  (sink vacio: el bucle se borro)\n");

    char name[32];
    std::snprintf(name, sizeof(name), "%u-pag-%s", pages,
                  random ? "salteado" : "seguido");
    report("conjunto", name, ns, "ns/acceso");
}

// --- 3. BLOQUE ------------------------------------------------------------

/// ns por byte leyendo bloques de @p size.  A partir de 4096 cruza pagina.
void bench_block(size_t size) {
    Vm v;
    // Cuatro paginas de sobra por encima del bloque mayor, para que quepa.
    v.touch((uint32_t)(size / kPage) + 4);

    std::vector<uint8_t> dst(size);
    const uint32_t rounds = (uint32_t)(64u * 1024u * 1024u / size);

    const uint64_t t0 = ::util::reloj::ahora();
    for (uint32_t n = 0; n < rounds; ++n) {
        /* Se desplaza el origen para que no sea siempre la misma pagina: con
         * un origen fijo se mediria el acierto de cache, no la lectura. */
        v.mem.read_bytes(kBase + (n % 3) * 8, dst.data(), size);
    }
    const double ns_per_byte =
        (double)::util::reloj::a_ns(::util::reloj::ahora() - t0) /
        ((double)rounds * (double)size);

    char name[32];
    std::snprintf(name, sizeof(name), "leer-%zu", size);
    report("bloque", name, ns_per_byte * 1000.0, "ps/byte");
}

// --- 4. PRIMER TOQUE ------------------------------------------------------

/**
 * @brief Cuanto cuesta tocar @p pages paginas NUEVAS, una a una.
 *
 * Es el camino de asignacion perezosa: cada pagina que no existe obliga a
 * reservar y a registrar la traduccion, y ahi es donde el `resize` del arbol
 * se paga.  Con el reparto de bits de hoy -- PT1 de 16 y PT2 de 24 -- una
 * direccion alta amplia un vector enorme por una sola pagina.
 */
void bench_first_touch(uint32_t pages, uint64_t stride, const char *name) {
    Vm v;
    const uint64_t t0 = ::util::reloj::ahora();
    const uint32_t first = (stride > kPage) ? 1u : 0u;
    for (uint32_t i = first; i < pages + first; ++i)
        v.mem[kBase + (uint64_t)i * stride] = 1;
    const double us =
        (double)::util::reloj::a_ns(::util::reloj::ahora() - t0) / 1000.0;
    report("1er-toque", name, us, "us");
}

// --- 5. MEMORIA -----------------------------------------------------------

/// Bytes que el mapa pide al monton para @p pages paginas separadas @p stride.
void bench_memory(uint32_t pages, uint64_t stride, const char *name) {
    const size_t before = g_alloc_bytes.load(std::memory_order_relaxed);
    {
        Vm v;
        /* El indice arranca en UNO cuando el salto es grande: con `i == 0` la
         * direccion se queda en la base y el caso "pagina alta" no tendria
         * nada de alto -- que es lo que le pasaba a la primera version, y por
         * eso daba 8 KB donde el banco del arbol daba 128 MB --. */
        const uint32_t first = (stride > kPage) ? 1u : 0u;
        for (uint32_t i = first; i < pages + first; ++i)
            v.mem[kBase + (uint64_t)i * stride] = 1;
        const size_t after = g_alloc_bytes.load(std::memory_order_relaxed);
        report("memoria", name, (double)(after - before) / 1024.0, "KB");
    }
}

/// Lo que reserva el mapa por UNA pagina en la direccion @p addr.
void bench_memory_at(uint64_t addr, const char *name) {
    const size_t before = g_alloc_bytes.load(std::memory_order_relaxed);
    {
        Vm v;
        v.mem[addr] = 1;
        const size_t after = g_alloc_bytes.load(std::memory_order_relaxed);
        report("memoria", name, (double)(after - before) / 1024.0, "KB");
    }
}

} // namespace

/* El monton, interceptado para contar exacto.  Global porque el mapa reserva
 * por varias vias -- los nodos del arbol, el buffer de cada vector y su
 * realojo -- y solo aqui pasan todas. */
void *operator new(size_t n) {
    g_alloc_bytes.fetch_add(n, std::memory_order_relaxed);
    void *p = std::malloc(n);
    if (p == nullptr) throw std::bad_alloc();
    return p;
}
void operator delete(void *p) noexcept { std::free(p); }
void operator delete(void *p, size_t) noexcept { std::free(p); }

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--csv") == 0) g_csv = true;

    if (!g_csv) {
        std::printf("\nMemoria virtual: estres de la capa que usa el "
                    "interprete\n");
        std::printf("  La cache de pagina tiene UNA entrada: con 1 pagina "
                    "acierta siempre,\n  y de 2 en adelante cada cambio de "
                    "pagina recorre el arbol entero.\n\n");
    }

    // 1 y 2. El barrido que decide si la TLB le importa al interprete.
    for (uint32_t pages : {1u, 2u, 4u, 16u, 64u, 256u, 1024u})
        bench_working_set(pages, /*random=*/false);
    for (uint32_t pages : {2u, 16u, 256u, 1024u})
        bench_working_set(pages, /*random=*/true);

    // 3. Bloques, incluido el que cruza pagina.
    for (size_t size : {(size_t)8, (size_t)64, (size_t)4096, (size_t)8192})
        bench_block(size);

    // 4. Primer toque: contiguo, y separado para forzar niveles altos.
    bench_first_touch(4096, kPage, "4096-contiguo");
    bench_first_touch(4096, 1ull << 24, "4096-disperso");
    bench_first_touch(256, 1ull << 40, "256-muy-alto");

    // 5. Memoria del mapa.
    bench_memory(4096, kPage, "4096-contiguo");
    bench_memory(4096, 1ull << 24, "4096-disperso");
    /* Y el extremo, con una direccion ALTA de verdad.
     *
     * Va con la direccion escrita y no con un salto: con `1 << 40` el indice
     * del nivel alto sale UNO, o sea que de alto no tiene nada -- daba 8 KB
     * donde el banco del arbol da 128 MB, y la etiqueta mentia --.  Lo que
     * hace grande al vector raiz es el INDICE, que son los bits 40 en
     * adelante. */
    bench_memory_at(0xFFFFFF0000000000ull, "1-pagina-muy-alta");

    if (!g_csv)
        std::printf("\n  Para juzgar un rediseno de la TLB: si el eje "
                    "`conjunto` no se mueve\n  de 4 paginas en adelante, el "
                    "cambio no le llega al interprete.\n");
    return 0;
}
