/**
 * @file tests/gc/test_gc_lib.cpp
 * @brief Inc 0 de libvesta_gc: valida la C-ABI del GC global sin ProcessVM.
 *
 * Comprueba que el GcHeap opera ProcessVM-less: alloc devuelve handles
 * distintos, deref es estable (sin GC), el payload es escribible, collect no
 * crashea y conserva los objetos (Inc 0 = owner_proc_ null -> no colecta aun),
 * y un alloc masivo (que dispara minor_gc interno) no rompe.
 *
 * CADA FASE SE ANUNCIA ANTES DE EJECUTARSE, y con vaciado inmediato.  No es
 * adorno: este test comprueba un recolector, o sea que su modo de fallo
 * natural NO es una asercion incumplida sino una caida.  Sin la traza, una
 * caida deja la salida VACIA -- ni el paso, ni el codigo, nada -- y lo unico
 * que queda es un codigo de salida que no dice donde.  Con ella, la ultima
 * linea impresa ES el sitio.
 */

#include "vesta_gc/gc_lib.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

/// Anuncia la fase que va a EMPEZAR, y vacia en el acto: si la siguiente
/// instruccion se lleva el proceso por delante, esta linea ya esta fuera.
void step(const char *what) {
    std::printf("  [.] %s\n", what);
    std::fflush(stdout);
}

} // namespace

int main() {
    int fails = 0;
    auto check = [&](bool cond, const char *msg) {
        if (!cond) {
            std::printf("  FAIL: %s\n", msg);
            std::fflush(stdout);
            ++fails;
        }
    };

    step("vx_gc_init");
    vx_gc_init();

    // 1) alloc da handles distintos con punteros de payload distintos.
    //    En modo AOT los objetos NO rooteados se colectan; el frame C++ de este
    //    test no se escanea (sin stackmaps) -> pinnar lo que queramos
    //    conservar.
    step("1: alloc + pin + deref");
    uint32_t h1 = vx_gc_alloc(16);
    uint32_t h2 = vx_gc_alloc(32);
    vx_gc_pin(h1);
    vx_gc_pin(h2);
    uint8_t *p1 = vx_gc_deref(h1);
    uint8_t *p2 = vx_gc_deref(h2);
    check(p1 != nullptr && p2 != nullptr,
          "deref de handle recien alocado es NULL");
    check(p1 != p2, "dos allocs distintos comparten payload");

    // 2) el payload es escribible y deref es estable (sin GC entre medias).
    step("2: payload escribible, deref estable");
    std::memset(p1, 0xAB, 16);
    std::memset(p2, 0xCD, 32);
    check(vx_gc_deref(h1) == p1, "deref no estable sin GC");
    check(p1[0] == 0xAB && p1[15] == 0xAB, "payload p1 corrupto");
    check(p2[0] == 0xCD && p2[31] == 0xCD, "payload p2 corrupto");

    // 3) live_count refleja al menos los 2 vivos.
    step("3: live_count >= 2");
    check(vx_gc_live_count() >= 2, "live_count < 2 tras 2 allocs");

    // 4) collect no crashea y (Inc 0, sin raices precisas) conserva los
    // objetos.
    step("4: collect conserva los pinnados");
    vx_gc_collect();
    check(vx_gc_deref(h1) != nullptr, "objeto colectado por error en Inc 0");

    // 5) alloc masivo: dispara minor_gc interno; no debe romper.
    step("5: alloc masivo (200000 x 24 bytes)");
    for (int i = 0; i < 200000; ++i) {
        uint32_t h = vx_gc_alloc(24);
        uint8_t *p = vx_gc_deref(h);
        if (p) p[0] = static_cast<uint8_t>(i);
    }
    check(true,
          "alloc masivo (placeholder, llegar aqui sin crash ya es exito)");

    // 6) Inc 2: el modo AOT COLECTA de verdad.  Aloca N objetos, pinna 1 como
    //    raiz externa, colecta -> SOLO el pinnado (+ los 2 iniciales pinnados?
    //    no, h1/h2 no estan pinnados) sobreviven.  Sin raices precisas de
    //    frames nativos en este test, todo lo NO pinnado debe colectarse.
    {
        // h1/h2 ya estan pinnados (paso 1).  Alocar un 'keep' pinnado + basura.
        step("6a: keep pinnado + 5000 de basura");
        uint32_t keep = vx_gc_alloc(40);
        vx_gc_pin(keep);
        uint8_t *kp = vx_gc_deref(keep);
        if (kp) std::memset(kp, 0x5A, 40);
        // Basura: 5000 objetos sin pin -> deben colectarse.
        for (int i = 0; i < 5000; ++i) {
            uint32_t g = vx_gc_alloc(32);
            uint8_t *p = vx_gc_deref(g);
            if (p) p[0] = static_cast<uint8_t>(i);
        }
        step("6b: collect y comprobar que la basura se fue");
        uint64_t before = vx_gc_live_count();
        vx_gc_collect();
        uint64_t after = vx_gc_live_count();
        check(after < before, "el modo AOT colecto basura no alcanzable");
        // Los pinnados sobreviven y su payload sigue intacto.
        check(vx_gc_deref(keep) != nullptr, "objeto pinnado 'keep' sobrevive");
        uint8_t *kp2 = vx_gc_deref(keep);
        check(kp2 && kp2[0] == 0x5A && kp2[39] == 0x5A,
              "payload de 'keep' intacto tras colectar");
        check(vx_gc_deref(h1) != nullptr && vx_gc_deref(h2) != nullptr,
              "h1/h2 pinnados sobreviven");
        // Tras despinnar y colectar, 'keep' tambien se colecta.
        step("6c: unpin de 'keep' y colectar");
        vx_gc_unpin(keep);
        vx_gc_collect();
        check(vx_gc_live_count() < after, "tras unpin, 'keep' se colecta");
        std::printf("  [aot-collect] before=%llu after=%llu final=%llu\n",
                    (unsigned long long)before, (unsigned long long)after,
                    (unsigned long long)vx_gc_live_count());
    }

    if (fails == 0)
        std::printf("GC LIB Inc 0+2: OK (collect AOT preciso, %llu vivos)\n",
                    (unsigned long long)vx_gc_live_count());
    else
        std::printf("GC LIB: %d FALLOS\n", fails);
    std::fflush(stdout);
    return fails;
}
