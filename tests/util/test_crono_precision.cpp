/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/test_crono_precision.cpp
 * @brief Hasta donde se puede creer al cronometro.
 *
 * Un instrumento sin comprobar es una promesa, y este ya ha mentido tres veces
 * en un dia: se medía a si mismo por el cerrojo, truncaba a microsegundos los
 * tramos cortos, y se sumaba su propio coste.  Los tres daban cifras creibles y
 * equivocadas -- la peor clase --, asi que aqui no se comprueba que "funcione"
 * sino DONDE DEJA DE SER FIABLE, que es el dato que hace falta para no creerse
 * un numero que no significa nada.
 *
 * Lo que se exige:
 *
 *  - Que un tramo de duracion conocida se mida con error acotado, y se informe
 *    del error a cada orden de magnitud (100 ns, 1 us, 10 us, 100 us, 1 ms).
 *  - Que sumar muchos tramos CORTOS de al total lo que deberia: es el caso que
 *    interesa descubrir y el que fallaba al truncar.
 *  - Que jamas salga negativo ni se coma un tramo real al descontar su coste.
 *  - Que varios hilos anotando la misma etiqueta sumen bien.
 *  - Y que el propio reloj diga que es y con que resolucion, para que ninguna
 *    conclusion se apoye en cifras mas finas de las que puede dar.
 *
 * VA CONTANDO LO QUE HACE, con barra que avanza.  Hace esperas activas de
 * segundos: sin verlo avanzar no se distingue "trabajando" de "colgado", y con
 * la salida por una tuberia el buffer se lo tragaria todo hasta el final, que
 * es justo cuando ya no sirve.
 */

#include "util/crono_tramo.h"
#include "util/reloj.h"

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

static int g_checks = 0;
static int g_fail = 0;

/// Escribe y VACIA el buffer.  Sin vaciar, nada de esto se ve mientras corre.
static void traza(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stdout, fmt, ap);
    va_end(ap);
    std::fflush(stdout);
}

/**
 * @brief Barra que avanza en la MISMA linea.
 *
 * Se reescribe con retorno de carro en vez de anadir lineas: lo que interesa es
 * ver que avanza, no llenar la pantalla.  Quien la use cierra con un salto.
 *
 * @param titulo Que se esta midiendo.
 * @param hecho  Cuanto se lleva.
 * @param total  Cuanto hay.
 */
static void barra(const char *titulo, long long hecho, long long total) {
    constexpr int kAncho = 24;
    const int lleno =
        total > 0 ? static_cast<int>((hecho * kAncho) / total) : kAncho;
    char buf[kAncho + 1];
    for (int i = 0; i < kAncho; ++i)
        buf[i] = (i < lleno) ? '#' : '.';
    buf[kAncho] = '\0';
    traza("\r      %-12s [%s] %7lld/%-7lld", titulo, buf, hecho, total);
}

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            traza("  [FALLO] %s (linea %d)\n", (msg), __LINE__);               \
        }                                                                      \
    } while (0)

/// Espera activa de @p ns nanosegundos segun el reloj del sistema, que aqui
/// hace de oraculo: el cronometro se compara contra algo que no es el mismo.
static void esperar_ns(long long ns) {
    const auto fin =
        std::chrono::steady_clock::now() + std::chrono::nanoseconds(ns);
    while (std::chrono::steady_clock::now() < fin) {
    }
}

/// Lo acumulado bajo @p etiqueta, en microsegundos.
static long long leer(const char *etiqueta) {
    for (const util::Tramo &t : util::tramos_medidos())
        if (std::string(t.nombre) == etiqueta) return t.us;
    return -1;
}

/// Cuantas tomas se anotaron bajo @p etiqueta.
static long long veces(const char *etiqueta) {
    for (const util::Tramo &t : util::tramos_medidos())
        if (std::string(t.nombre) == etiqueta) return t.veces;
    return -1;
}

// ===========================================================================
// 1. El reloj dice que es y cuanto puede afinar
// ===========================================================================
static void probar_identidad_del_reloj() {
    traza("\n[1/5] identidad del reloj\n");
    const util::reloj::Info &i = util::reloj::info();
    traza("      fuente %s | resolucion %.3f ns | leerlo %lld ns | tsc "
          "invariante: %s\n",
          i.fuente, i.resolucion_ns, i.coste_ns,
          i.tsc_invariante ? "si" : "no");
    CHECK(i.resolucion_ns > 0.0, "el reloj declara su resolucion");
    /* Un reloj que no distingue menos de un microsegundo no sirve para lo que
     * se le pide: tramos de decenas de nanosegundos repetidos cien mil veces.
     */
    CHECK(i.resolucion_ns <= 1000.0,
          "la resolucion basta para tramos de menos de un microsegundo");
    CHECK(i.coste_ns >= 0 && i.coste_ns < 10000,
          "leer el reloj cuesta algo razonable");
}

// ===========================================================================
// 2. Error por orden de magnitud: HASTA DONDE se le puede creer
// ===========================================================================
static void probar_por_orden_de_magnitud() {
    traza("\n[2/5] error por orden de magnitud\n");
    /* Cada duracion se mide REPETIDA: un tramo suelto de 100 ns cae por debajo
     * de la resolucion del reloj, y lo que hay que saber es si el TOTAL de
     * muchos sale bien, que es como se usa de verdad. */
    struct Caso {
        const char *etiqueta;
        const char *titulo;
        long long ns;
        int repeticiones;
        double tolerancia; ///< error relativo admitido POR ARRIBA.
    };
    static const Caso kCasos[] = {
        {"  prueba:100ns", "100 ns", 100, 20000, 1.00},
        {"  prueba:1us", "1 us", 1000, 5000, 0.50},
        {"  prueba:10us", "10 us", 10000, 1000, 0.25},
        {"  prueba:100us", "100 us", 100000, 200, 0.15},
        {"  prueba:1ms", "1 ms", 1000000, 30, 0.10},
    };
    for (const Caso &c : kCasos) {
        const int paso = c.repeticiones / 100 + 1;

        /* EL ORACULO ES EL MISMO BUCLE SIN INSTRUMENTAR.
         *
         * No la duracion nominal -- la espera activa se pasa siempre un poco --
         * ni el bucle CON el cronometro dentro: ahi el oraculo incluiria el
         * coste del propio instrumento, que queda fuera del tramo medido, y la
         * diferencia se leeria como error de medida cuando es otra cosa.  Con
         * esto se compara lo mismo contra lo mismo y el numero que sale es el
         * error del cronometro, no la huella de haberlo puesto. */
        const auto r0 = std::chrono::steady_clock::now();
        for (int i = 0; i < c.repeticiones; ++i) {
            if (i % paso == 0) barra(c.titulo, i, 2 * c.repeticiones);
            esperar_ns(c.ns);
        }
        const auto r1 = std::chrono::steady_clock::now();
        const long long real_us =
            std::chrono::duration_cast<std::chrono::microseconds>(r1 - r0)
                .count();

        for (int i = 0; i < c.repeticiones; ++i) {
            /* La barra se refresca cada centesima parte: pintarla en cada
             * vuelta costaria mas que el tramo que se mide. */
            if (i % paso == 0)
                barra(c.titulo, c.repeticiones + i, 2 * c.repeticiones);
            // La prueba SIEMPRE mide: es lo que esta comprobando.
        util::CronoTramo crono(c.etiqueta, true);
            esperar_ns(c.ns);
        }
        barra(c.titulo, 2 * c.repeticiones, 2 * c.repeticiones);
        const long long medido_us = leer(c.etiqueta);
        const double err = real_us > 0
                               ? static_cast<double>(medido_us - real_us) /
                                     static_cast<double>(real_us)
                               : 0.0;
        traza("  sin medir %8lld us | medido %8lld us | error %+6.1f %%\n",
              real_us, medido_us, err * 100.0);
        ++g_checks;
        /* Ahora la comparacion es justa, asi que el error se mira en LOS DOS
         * sentidos: pasarse seria medir de mas, y quedarse corto seria perder
         * tiempo real -- que es como se pierde de vista un tramo caro. */
        if (err > c.tolerancia || -err > c.tolerancia) {
            ++g_fail;
            traza("      [FALLO] %s: %+.1f %% de error (limite +-%.0f %%)\n",
                  c.titulo, err * 100.0, c.tolerancia * 100.0);
        }
        CHECK(veces(c.etiqueta) == c.repeticiones,
              "se cuentan todas las tomas");
    }
}

// ===========================================================================
// 3. Muchos tramos CORTOS suman: el caso que fallaba al truncar
// ===========================================================================
static void probar_acumulacion_de_cortos() {
    traza("\n[3/5] doscientos mil tramos cortos (el caso que fallaba)\n");
    /* Con truncamiento a microsegundos esto daba CERO: cada tramo medía menos
     * de 1 us y se redondeaba.  Doscientas mil veces cero siguen siendo cero, y
     * asi un tramo que costaba decenas de milisegundos parecia gratis. */
    constexpr int kN = 200000;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kN; ++i) {
        if (i % 2000 == 0) barra("cortos", i, kN);
        util::CronoTramo crono("  prueba:cortos", true);
        esperar_ns(200);
    }
    const auto t1 = std::chrono::steady_clock::now();
    barra("cortos", kN, kN);
    const long long real_us =
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    const long long medido_us = leer("  prueba:cortos");
    traza("  real %lld us | medido %lld us\n", real_us, medido_us);
    CHECK(medido_us > 0, "doscientos mil tramos cortos NO suman cero");
    /* Al menos la mitad de lo real: por debajo, el instrumento estaria
     * perdiendo la mayor parte de lo que mide. */
    CHECK(medido_us * 2 >= real_us,
          "y suman del orden de lo que de verdad costaron");
}

// ===========================================================================
// 4. Nunca negativo, y descontar el coste no se come un tramo real
// ===========================================================================
static void probar_no_negativo() {
    traza("\n[4/5] tramos vacios y descuento del coste\n");
    /* Tramos VACIOS: dentro solo esta el propio instrumento, asi que tras
     * descontar su coste esto tiene que quedar en cero -- nunca en negativo ni
     * en un numero grande, que seria medirse a si mismo. */
    constexpr int kVacios = 50000;
    for (int i = 0; i < kVacios; ++i) {
        if (i % 500 == 0) barra("vacios", i, kVacios);
        util::CronoTramo crono("  prueba:vacio", true);
    }
    barra("vacios", kVacios, kVacios);
    const long long v = leer("  prueba:vacio");
    traza("  %d vacios -> %lld us tras descontar el coste\n", kVacios, v);
    CHECK(v >= 0, "nunca sale negativo");
    CHECK(v < 5000, "un tramo vacio no puede costar milisegundos");

    /* Y el descuento no puede borrar algo real: un tramo con trabajo dentro
     * tiene que seguir viendose muy por encima del ruido. */
    constexpr int kCon = 1000;
    for (int i = 0; i < kCon; ++i) {
        if (i % 10 == 0) barra("con trabajo", i, kCon);
        util::CronoTramo crono("  prueba:con-trabajo", true);
        esperar_ns(5000);
    }
    barra("con trabajo", kCon, kCon);
    const long long t = leer("  prueba:con-trabajo");
    traza("  %d x 5 us -> %lld us\n", kCon, t);
    CHECK(t > 1000, "descontar el coste no borra un tramo que si costo");
}

// ===========================================================================
// 5. Varios hilos anotando la misma etiqueta
// ===========================================================================
static void probar_hilos() {
    traza("\n[5/5] cuatro hilos anotando la misma etiqueta\n");
    constexpr int kHilos = 4;
    constexpr int kPorHilo = 10000;
    std::vector<std::thread> hilos;
    barra("hilos", 0, kHilos);
    for (int h = 0; h < kHilos; ++h) {
        hilos.emplace_back([] {
            for (int i = 0; i < kPorHilo; ++i) {
                util::CronoTramo crono("  prueba:hilos", true);
                esperar_ns(300);
            }
        });
    }
    for (int h = 0; h < kHilos; ++h) {
        hilos[static_cast<size_t>(h)].join();
        barra("hilos", h + 1, kHilos);
    }
    const long long n = veces("  prueba:hilos");
    traza("  %lld tomas de %d esperadas\n", n, kHilos * kPorHilo);
    /* El acumulador es uno por hilo y se suman al consultar: si esa suma
     * fallara faltarian tomas, y el sintoma seria un tramo que parece barato
     * porque tres de cada cuatro medidas se perdieron. */
    CHECK(n == kHilos * kPorHilo, "se suman las tomas de todos los hilos");
    CHECK(leer("  prueba:hilos") > 0, "y su tiempo");
}

int main() {
    traza("=== El cronometro: hasta donde se le puede creer ===\n");
    probar_identidad_del_reloj();
    probar_por_orden_de_magnitud();
    probar_acumulacion_de_cortos();
    probar_no_negativo();
    probar_hilos();
    traza("\n%d comprobaciones, %d fallos\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
