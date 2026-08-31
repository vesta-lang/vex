/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_asa_fact_file_lnx.cpp
 * @brief El fichero de hechos, comprobado en LAS DOS plataformas.
 *
 * Una cache se escribe en una maquina y se lee en otra -- un repositorio
 * compartido, un contenedor, un compilador cruzado --, asi que "funciona en mi
 * sistema" no dice nada del formato.  Lo que aqui se comprueba es lo que se
 * rompe al cruzar y en ningun otro sitio:
 *
 *   - que los MISMOS hechos den los MISMOS bytes en Windows y en Linux.  Se
 *     imprime su huella para poder compararla entre las dos; si el formato se
 *     colara el orden de bytes de la maquina o el relleno de una estructura,
 *     esa cifra dejaria de coincidir y no se veria de ninguna otra forma;
 *   - que lo escrito en una plataforma se lea en la otra (el mismo fichero se
 *     lleva y se vuelve a leer);
 *   - que los tamanos no dependan de si @c long mide 4 u 8 bytes;
 *   - y que escribir y leer por disco funcione con las rutas de cada sistema.
 *
 * A PROPOSITO no depende de nada del compilador ni del IR: se compila suelto
 * con cuatro ficheros, que es lo que permite correrlo en un sistema donde no
 * este construido el proyecto entero.  Se compila asi:
 *
 *   g++ -std=gnu++17 -O2 -Iinclude -o /tmp/t \
 *       tests/analysis/test_asa_fact_file_lnx.cpp \
 *       src/analysis/asa/fact_file.cpp src/analysis/asa/fact_store.cpp \
 *       src/util/serialize.cpp
 */

#include "analysis/asa/fact_file.h"
#include "analysis/asa/fact_store.h"
#include "util/fnv.h"
#include "util/fs_utils.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace analysis::asa;

static int g_checks = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  [FALLO] %s (linea %d)\n", (msg), __LINE__);         \
        }                                                                      \
    } while (0)

/* Literales propios: este test no enlaza con la base de hechos a proposito, y
 * los nombres canonicos se dan de alta a mano.  Tienen que ser variables y no
 * literales sueltos porque ASA los compara por DIRECCION. */
static const char *const kDomA = "prueba.alfa";
static const char *const kDomB = "prueba.beta";

/// Un almacen con contenido que exprime lo que se estropea al cruzar de
/// plataforma: negativos, el extremo de 64 bits, cadenas repetidas y apoyos.
static void poblar(FactStore &a) {
    FactId anterior = kNoFact;
    for (int i = 0; i < 12; ++i) {
        Fact f;
        f.what.domain = (i % 2 == 0) ? kDomA : kDomB;
        f.what.code = "prueba.codigo";
        f.what.a = -1234567890123456789ll + i;
        f.what.b = 0x7FFFFFFFFFFFFFFFll;
        f.what.detail = a.intern("detalle que se repite");
        f.about.kind = Subject::Kind::Value;
        f.about.function = a.intern("f" + std::to_string(i % 3));
        f.about.id = 0xFFFFFFFFu - static_cast<uint32_t>(i);
        f.seal.certainty = Certainty::Inferred;
        f.seal.origin.source = Source::Profile;
        f.seal.origin.producer = (i % 2 == 0) ? kDomA : kDomB;
        f.seal.origin.site = static_cast<uint32_t>(i);
        f.seal.support.add(kDomA);
        f.proof.rule = "regla";
        if (anterior != kNoFact) f.proof.from.push_back(anterior);
        anterior = a.add(std::move(f));
    }
}

int main(int argc, char **argv) {
    std::printf("=== ASA: el fichero de hechos, entre plataformas ===\n");
    register_canonical_name(kDomA);
    register_canonical_name(kDomB);

    FactStore origen;
    poblar(origen);
    const std::vector<uint8_t> bytes =
        serialize(origen, 0xABCDEF0123456789ull, CacheLevel::All, {},
                  0x1122334455667788ull);
    CHECK(!bytes.empty(), "se escribe");

    /* LA CIFRA QUE IMPORTA.  Si el formato se colara el orden de bytes de la
     * maquina, el relleno de una estructura o el ancho de un `long`, esto
     * cambiaria de una plataforma a otra y no se notaria de ninguna otra
     * forma: los dos sistemas leerian lo suyo tan contentos y ninguno el del
     * otro. */
    const uint64_t huella_bytes =
        util::fnv_bytes(util::kFnvOffset, bytes.data(), bytes.size());
    std::printf("  bytes=%zu  huella=%016llx\n", bytes.size(),
                static_cast<unsigned long long>(huella_bytes));

    FactStore d;
    const ReadResult r =
        read_facts(bytes.data(), bytes.size(), 0xABCDEF0123456789ull, d, {},
                   0x1122334455667788ull);
    CHECK(r.ok && r.facts == 12, "y se lee entero");
    CHECK(d.at(0).what.a == -1234567890123456789ll,
          "un negativo grande cruza sin estropearse");
    CHECK(d.at(0).what.b == 0x7FFFFFFFFFFFFFFFll, "y el extremo de 64 bits");
    CHECK(d.at(0).about.id == 0xFFFFFFFFu,
          "y un entero sin signo en su valor mas alto");
    CHECK(d.at(0).what.domain == kDomA,
          "los nombres vuelven a su literal en cualquier plataforma");

    /* El grafo, que es lo unico que el fichero promete conservar. */
    bool grafo = true;
    for (FactId i = 0; i < d.size(); ++i)
        for (FactId p : d.at(i).proof.from)
            if (p >= d.size()) grafo = false;
    CHECK(grafo, "ningun apoyo apunta fuera");
    CHECK(r.lost_proofs == 0, "no se pierde ningun apoyo al cruzar");

    /* Invalidacion, tambien aqui: si una plataforma anulara distinto, la cache
     * compartida haria cosas distintas segun quien la lea. */
    CHECK(
        read_facts(bytes.data(), bytes.size(), 1, d, {}, 0x1122334455667788ull)
                .reason == ReadReason::OtherModule,
        "otro modulo se rechaza igual");
    CHECK(
        read_facts(bytes.data(), bytes.size(), 0xABCDEF0123456789ull, d, {}, 7)
                .reason == ReadReason::OtherCompiler,
        "otro compilador tambien");
    {
        std::vector<uint8_t> malo = bytes;
        malo[malo.size() / 2] ^= 0xFF;
        FactStore dc;
        const ReadResult rc =
            read_facts(malo.data(), malo.size(), 0xABCDEF0123456789ull, dc, {},
                       0x1122334455667788ull);
        CHECK(!rc.ok || rc.corrupt > 0, "un byte estropeado se detecta igual");
    }

    /* Por disco, con las rutas de este sistema. */
    {
        /* En el directorio de trabajo: el test se corre desde la raiz del
         * proyecto en los dos sistemas, y asi no depende de donde cada uno
         * ponga sus temporales. */
        const std::string ruta = "asa_hechos_prueba.bin";
        CHECK(::fs::write_file_atomic(ruta, bytes), "se escribe en disco");
        FactStore dd;
        const ReadResult rd = read_facts_file(ruta, 0xABCDEF0123456789ull, dd,
                                              {}, 0x1122334455667788ull);
        CHECK(rd.ok && dd.size() == 12, "y se lee de disco");
        std::remove(ruta.c_str());
    }

    /* Si se pasa una huella por la linea de ordenes, se compara con la de esta
     * plataforma: asi la comparacion entre sistemas la hace el propio test y no
     * hay que leer dos numeros a ojo. */
    if (argc > 1) {
        const uint64_t esperada = std::strtoull(argv[1], nullptr, 16);
        CHECK(esperada == huella_bytes,
              "los mismos hechos dan los mismos bytes en las dos plataformas");
    }

    std::printf("%d comprobaciones, %d fallos\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
