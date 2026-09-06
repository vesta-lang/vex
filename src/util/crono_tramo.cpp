/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/crono_tramo.cpp
 * @brief El acumulador de tramos (ver @c util/crono_tramo.h).
 */

#include "util/crono_tramo.h"

#include "util/reloj.h"
#include "util/thread_owned.h" // un acumulador por hilo, sin `thread_local`

#include <algorithm>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace util {

namespace {
/* UNO POR HILO, sin cerrojo.  Lo habia con cerrojo, y eso vale mientras se
 * cronometren tramos gruesos; en cuanto se mide algo que ocurre CIEN MIL veces
 * con los modulos compilando en paralelo, la contencion del propio cerrojo se
 * cobra dentro del tramo que envuelve -- y entonces el instrumento mide sobre
 * todo a si mismo.  Paso de verdad: un tramo dio 20 s cuyo cuerpo medido por
 * dentro costaba 219 us.
 *
 * Con uno por hilo, medir cuesta dos lecturas de reloj y una busqueda en una
 * tabla que nadie mas toca.  Los hilos se suman al consultar, que ocurre una
 * vez. */
struct Acumulador {
    std::unordered_map<const char *, std::pair<long long, long long>> t;
};

/* Los de todos los hilos, para poder sumarlos.  El cerrojo se toma SOLO al
 * darse de alta un hilo (una vez por hilo) y al consultar.
 *
 * NADA de `thread_local`: en MinGW la TLS es emulada y ademas una variable de
 * hilo con inicializador dinamico genera una guarda que CUELGA cuando hay hilos
 * que nacen y mueren -- justo lo que hace el reparto del compilador --.  Ya se
 * vio en una pila, bloqueado dentro de esta misma funcion.  `ThreadOwned` da la
 * ranura y se queda con lo creado, que es lo que permite sumarlo todo. */
util::ThreadOwned<Acumulador> g_accumulators;

/// El acumulador de ESTE hilo.
Acumulador &mio() { return g_accumulators.get(); }
} // namespace

void acumular_tramo_ns(const char *etiqueta, long long ns) {
    auto &e = mio().t[etiqueta];
    e.first += ns;
    e.second += 1;
}

namespace {
/**
 * @brief Lo que cuesta MEDIR, y lo fino que es el reloj.
 *
 * Un cronometro se suma a lo que mide: dos lecturas de reloj y una anotacion.
 * En un tramo de decenas de nanosegundos repetido cien mil veces, eso ya no es
 * despreciable -- es un sesgo SIEMPRE hacia arriba, y proporcional al numero de
 * llamadas, que es justo el caso que interesa descubrir.  Se mide una vez y se
 * descuenta al informar.
 *
 * La granularidad se mide aparte porque si el reloj salta de a 100 ns, nada mas
 * fino que eso significa nada, y conviene que se vea en vez de creerselo.
 */
struct Calibracion {
    long long coste_ns = 0;      ///< lo que cuesta una toma completa.
    long long resolucion_ns = 0; ///< salto minimo observable del reloj.
};

Calibracion medir_calibracion() {
    Calibracion c;
    /* Coste: se toma el tiempo de N anotaciones a una etiqueta de descarte y se
     * reparte.  Se usa la misma ruta que el uso real -- reloj, acceso al
     * acumulador del hilo y anotacion -- para no medir una version mas barata
     * que la que se paga. */
    constexpr int kN = 20000;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kN; ++i) {
        const auto a = std::chrono::steady_clock::now();
        acumular_tramo_ns("  <calibracion>",
                          std::chrono::duration_cast<std::chrono::nanoseconds>(
                              std::chrono::steady_clock::now() - a)
                              .count());
    }
    const auto t1 = std::chrono::steady_clock::now();
    c.coste_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count() /
        kN;
    /* Resolucion: el primer salto distinto de cero que da el reloj. */
    for (int i = 0; i < 1000 && c.resolucion_ns == 0; ++i) {
        const auto a = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point b;
        do {
            b = std::chrono::steady_clock::now();
        } while (b == a);
        c.resolucion_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count();
    }
    return c;
}

const Calibracion &calibracion() {
    static const Calibracion c = medir_calibracion();
    return c;
}
} // namespace

Calibracion_ calibracion_del_cronometro() {
    /* El coste de una TOMA (dos lecturas + la anotacion) sale de medirlo aqui;
     * la resolucion es la del reloj, que la sabe el.  Los dos se ensenan porque
     * ninguna cifra puede ser mas fina que su reloj ni menor que su ruido. */
    Calibracion_ c;
    c.coste_ns = calibracion().coste_ns;
    c.resolucion_ns = reloj::info().resolucion_ns;
    c.fuente = reloj::info().fuente;
    return c;
}

std::vector<Tramo> tramos_medidos() {
    /* La calibracion se pide ANTES del cerrojo, nunca dentro.
     *
     * Medirla recorre la ruta REAL -- acumular_tramo_ns() -> mio() -- y, si
     * este hilo todavia no se habia dado de alta, mio() pide ESTE MISMO
     * cerrojo.  Un std::mutex no es reentrante, asi que el hilo se bloqueaba
     * contra si mismo y el proceso se quedaba colgado al ir a informar.
     *
     * Solo se veia al repartir el trabajo entre hilos, y por eso costo dar con
     * ello: en secuencial el hilo principal ya habia anotado tramos y estaba
     * dado de alta, asi que mio() ni llegaba a pedir el cerrojo.  Al repartir,
     * quien anota son los workers y el principal llega virgen al informe. */
    const long long coste = calibracion().coste_ns;

    std::unordered_map<const char *, std::pair<long long, long long>> total;
    g_accumulators.for_each([&total](const Acumulador &a) {
        for (const auto &kv : a.t) {
            auto &e = total[kv.first];
            e.first += kv.second.first;
            e.second += kv.second.second;
        }
    });
    std::vector<Tramo> v;
    v.reserve(total.size());
    for (const auto &kv : total) {
        /* Se acumula en NANOSEGUNDOS para que un tramo corto y repetido no se
         * pierda por truncamiento, y se informa en microsegundos, que es la
         * unidad del resto de la telemetria.
         *
         * Y se descuenta lo que costo MEDIR: es un sesgo hacia arriba
         * proporcional al numero de tomas, asi que sin quitarlo un tramo corto
         * y muy repetido parece caro cuando lo caro era mirarlo.  Nunca por
         * debajo de cero: si el descuento se lo come, es que ahi no habia
         * nada. */
        long long ns = kv.second.first - kv.second.second * coste;
        if (ns < 0) ns = 0;
        v.push_back({kv.first, ns / 1000, kv.second.second});
    }
    std::sort(v.begin(), v.end(),
              [](const Tramo &x, const Tramo &y) { return x.us > y.us; });
    return v;
}

void reiniciar_tramos() {
    g_accumulators.for_each([](Acumulador &a) { a.t.clear(); });
}

} // namespace util
