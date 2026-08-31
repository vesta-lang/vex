/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_asa_fact_file_robusto.cpp
 * @brief Un fichero de cache es una ENTRADA HOSTIL, y se prueba como tal.
 *
 * No porque haya un atacante: porque un corte de luz a mitad de la escritura,
 * un sector malo, un disco lleno o dos procesos pisandose producen exactamente
 * los mismos bytes que produciria uno.  Y esto se lee en cada compilacion, asi
 * que un desbordamiento aqui es un fallo del compilador sobre el codigo de
 * cualquiera.
 *
 * La promesa que se comprueba es UNA y no admite matices: pase lo que pase con
 * los bytes, leer termina, no se sale del buffer, no reserva memoria a lo loco,
 * y contesta -- bien con hechos, bien con un motivo.  Nunca con un cuelgue.
 *
 * Como se ataca:
 *
 *  1. TRUNCADO en cada byte posible.  Cubre el corte de luz.
 *  2. CORRUPCION de cada byte del fichero, con varios valores.  Cubre el sector
 *     malo y, de paso, todos los campos: no hay campo que no toque.
 *  3. CAMPOS ADVERSARIOS a mano (cuentas y longitudes enormes).  Es lo que
 *     distingue "no se cae" de "no intenta reservar cuatro mil millones de
 *     hechos porque lo dice el fichero": lo primero lo daria un buffer grande,
 *     lo segundo hay que programarlo.
 *  4. CICLOS en la derivacion.  Un fichero puede decir que A se apoya en B y B
 *     en A; explicar tiene que terminar igual.
 *  5. VOLUMEN, para que lo anterior no se demuestre solo sobre juguetes.
 */

#include "analysis/asa/fact_base.h"
#include "analysis/asa/fact_file.h"
#include "analysis/asa/fact_store.h"

#include <cstdio>
#include <cstring>

#include "util/fs_utils.h"
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

/// Un almacen con varios dominios, cadenas repetidas y una derivacion.
static std::vector<uint8_t> fichero_de_muestra(uint32_t n_por_dominio = 8) {
    static const char *const kDominios[] = {"asa.structure", "asa.ranges",
                                            "asa.memory"};
    FactStore a;
    FactId anterior = kNoFact;
    for (const char *dom : kDominios) {
        for (uint32_t i = 0; i < n_por_dominio; ++i) {
            Fact f;
            f.what.domain = dom;
            f.what.code = "codigo.estable";
            f.what.a = static_cast<int64_t>(i) - 3;
            f.what.b = 0x7FFFFFFFFFFFFFFFll;
            f.what.detail = a.intern("un detalle que se repite mucho");
            f.about.kind = Subject::Kind::Value;
            f.about.function = a.intern("funcion_" + std::to_string(i % 3));
            f.about.id = i;
            f.seal.certainty = Certainty::Inferred;
            f.seal.origin.producer = dom;
            f.seal.support.add(dom);
            f.proof.rule = "regla";
            if (anterior != kNoFact) f.proof.from.push_back(anterior);
            anterior = a.add(std::move(f));
        }
    }
    return serialize(a, 0x1234ull, CacheLevel::All, {});
}

// ===========================================================================
// 1. Truncado en cada byte: nunca revienta, nunca deposita a medias
// ===========================================================================
static void probar_truncado_exhaustivo() {
    const std::vector<uint8_t> bueno = fichero_de_muestra();
    bool todo_bien = true;
    for (size_t corte = 0; corte < bueno.size(); ++corte) {
        FactStore d;
        const ReadResult r = read_facts(bueno.data(), corte, 0x1234ull, d);
        /* Un prefijo NUNCA puede darse por bueno: los hechos que faltan no se
         * distinguirian de hechos que no existen, y eso es peor que no leer. */
        if (r.ok || d.size() != 0) {
            todo_bien = false;
            std::printf("  [FALLO] prefijo de %zu bytes aceptado\n", corte);
            break;
        }
    }
    CHECK(todo_bien, "ningun prefijo del fichero se acepta");

    /* Y el fichero entero si. */
    FactStore d;
    CHECK(read_facts(bueno.data(), bueno.size(), 0x1234ull, d).ok,
          "el fichero completo se lee");
}

// ===========================================================================
// 2. Corromper cada byte con varios valores: leer siempre termina y contesta
// ===========================================================================
static void probar_corrupcion_exhaustiva() {
    const std::vector<uint8_t> bueno = fichero_de_muestra();
    static const uint8_t kValores[] = {0x00, 0x01, 0x7F, 0x80, 0xFF};
    size_t detectados = 0, colados = 0;
    FactStore limpio;
    const uint32_t hechos_buenos =
        read_facts(bueno.data(), bueno.size(), 0x1234ull, limpio).facts;
    for (size_t i = 0; i < bueno.size(); ++i) {
        for (uint8_t v : kValores) {
            if (bueno[i] == v) continue;
            std::vector<uint8_t> malo = bueno;
            malo[i] = v;
            FactStore d;
            const ReadResult r =
                read_facts(malo.data(), malo.size(), 0x1234ull, d);
            /* Se exige DETECTARLO, no solo sobrevivir.  Un byte cambiado
             * dentro de un numero da otro numero igual de valido, asi que sin
             * suma de comprobacion el compilador razonaria sobre hechos falsos
             * y nadie se enteraria -- peor que no tener cache.  Cuenta como
             * detectado tanto rechazar el fichero como descartar el registro.
             */
            const bool detectado =
                !r.ok || r.corrupt > 0 || r.facts != hechos_buenos;
            if (detectado)
                ++detectados;
            else
                ++colados;
            if (r.ok) {
                /* Y si lo acepta, lo que deposito tiene que ser coherente: los
                 * apoyos apuntan a hechos que existen de verdad. */
                for (size_t k = 0; k < d.size(); ++k) {
                    for (FactId p : d.at(static_cast<FactId>(k)).proof.from) {
                        if (p >= d.size()) {
                            ++g_fail;
                            std::printf("  [FALLO] apoyo colgando tras "
                                        "corromper el byte %zu\n",
                                        i);
                            return;
                        }
                    }
                }
            }
        }
    }
    std::printf("  corrupcion: %zu variantes detectadas, %zu coladas, "
                "0 cuelgues\n",
                detectados, colados);
    /* Ni un solo byte del fichero puede cambiarse sin que se note.  Es una
     * exigencia absoluta a proposito: "casi siempre" aqui significa que de vez
     * en cuando el compilador se cree algo falso, y eso no se puede depurar. */
    CHECK(colados == 0, "no se cuela ni un byte cambiado");
}

/// Escribe un @c u32 en little-endian dentro de @p b.
static void poner_u32(std::vector<uint8_t> &b, size_t pos, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        b[pos + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

// ===========================================================================
// 3. Cuentas enormes: lo que separa "no se cae" de "no se cree lo que le dicen"
// ===========================================================================
static void probar_cuentas_absurdas() {
    /* La cabecera es magia(4) + version(2) + reservado(2) + huella(8) +
     * total_hechos(4) + n_registros(4) = 24 bytes.  Dentro de ella, los dos
     * ultimos campos son los que un fichero roto puede usar para pedir memoria:
     * "tengo cuatro mil millones de hechos" es una peticion de 16 GB si alguien
     * se la cree. */
    const std::vector<uint8_t> bueno = fichero_de_muestra(4);

    {
        std::vector<uint8_t> malo = bueno;
        poner_u32(malo, 16, 0xFFFFFFFFu); // total de hechos original
        FactStore d;
        const ReadResult r = read_facts(malo.data(), malo.size(), 0x1234ull, d);
        CHECK(!r.ok || d.size() <= malo.size(),
              "un total de hechos absurdo no se cree ni reserva por el");
    }
    {
        std::vector<uint8_t> malo = bueno;
        poner_u32(malo, 20, 0xFFFFFFFFu); // numero de registros
        FactStore d;
        const ReadResult r = read_facts(malo.data(), malo.size(), 0x1234ull, d);
        CHECK(!r.ok, "mas registros de los que caben es un fichero roto");
        CHECK(d.size() == 0, "y no deposita nada");
    }

    /* Y dentro del primer registro: el nombre del dominio va justo detras de la
     * cabecera, con su longitud delante. */
    {
        std::vector<uint8_t> malo = bueno;
        poner_u32(malo, 24, 0xFFFFFFFFu); // longitud del nombre del dominio
        FactStore d;
        const ReadResult r = read_facts(malo.data(), malo.size(), 0x1234ull, d);
        CHECK(!r.ok && d.size() == 0,
              "un nombre de dominio mas largo que el fichero se rechaza");
    }
}

// ===========================================================================
// 4. Ciclos en la derivacion: explicar termina igual
// ===========================================================================
static void probar_ciclos() {
    FactStore a;
    Fact x;
    x.what.domain = "asa.ranges";
    x.what.code = "a";
    const FactId ix = a.add(std::move(x));
    Fact y;
    y.what.domain = "asa.ranges";
    y.what.code = "b";
    y.proof.from.push_back(ix);
    const FactId iy = a.add(std::move(y));
    /* Un ciclo no se puede construir con la API (un hecho solo puede apoyarse
     * en otro anterior), asi que se fabrica en los BYTES -- que es justo de
     * donde vendria: un fichero puede decir lo que quiera. */
    std::vector<uint8_t> bytes = serialize(a, 9, CacheLevel::All, {});
    bool tocado = false;
    for (size_t i = 0; i + 4 <= bytes.size(); ++i) {
        uint32_t v = 0;
        for (int k = 0; k < 4; ++k)
            v |= static_cast<uint32_t>(bytes[i + static_cast<size_t>(k)])
                 << (8 * k);
        if (v == ix) { // el apoyo de y, que apunta a x
            poner_u32(bytes, i, iy);
            tocado = true;
            break;
        }
    }
    CHECK(tocado, "se pudo fabricar el ciclo en los bytes");

    FactStore d;
    const ReadResult r = read_facts(bytes.data(), bytes.size(), 9, d);
    if (r.ok && d.size() > 0) {
        /* Lo unico que importa: TERMINA.  Si no, aqui se cuelga el test. */
        const size_t pasos =
            d.explain(static_cast<FactId>(d.size() - 1)).size();
        CHECK(pasos <= d.size(), "explicar un ciclo termina y no repite");
    } else {
        ++g_checks; // rechazarlo tambien es una respuesta valida.
    }
}

// ===========================================================================
// 5. Volumen: lo de arriba tiene que valer tambien fuera del juguete
// ===========================================================================
static void probar_volumen() {
    FactStore a;
    a.reserve(20000);
    for (uint32_t i = 0; i < 20000; ++i) {
        Fact f;
        f.what.domain = (i % 2 == 0) ? "asa.ranges" : "asa.memory";
        f.what.code = "codigo.estable";
        f.what.a = i;
        f.what.detail = a.intern("detalle " + std::to_string(i % 50));
        f.about.kind = Subject::Kind::Value;
        f.about.function = a.intern("f" + std::to_string(i % 100));
        f.about.id = i;
        f.seal.certainty = Certainty::Proven;
        if (i > 0) f.proof.from.push_back(i - 1);
        a.add(std::move(f));
    }
    const std::vector<uint8_t> bytes = serialize(a, 11, CacheLevel::All, {});
    CHECK(!bytes.empty(), "veinte mil hechos se escriben");

    FactStore d;
    const ReadResult r = read_facts(bytes.data(), bytes.size(), 11, d);
    CHECK(r.ok && d.size() == 20000, "y vuelven todos");
    CHECK(r.lost_proofs == 0, "sin perder un solo apoyo");
    /* Los apoyos cruzan de un registro a otro (los dominios se alternan), asi
     * que esto comprueba de verdad el recolocado ENTRE registros.
     *
     * Y se comprueba el GRAFO, no las posiciones: agrupar por dominio reordena
     * los hechos, asi que el que estaba en el sitio i ya no esta ahi.  Lo que
     * el fichero promete conservar es de que se sigue cada hecho, no en que
     * orden estaban -- y eso es justo lo que hay que exigir. */
    bool grafo_intacto = true;
    for (FactId i = 0; i < d.size(); ++i) {
        const Fact &f = d.at(i);
        const int64_t yo = f.what.a;
        if (yo == 0) {
            if (!f.proof.from.empty()) {
                grafo_intacto = false;
                break;
            }
            continue;
        }
        if (f.proof.from.size() != 1 ||
            d.at(f.proof.from[0]).what.a != yo - 1) {
            grafo_intacto = false;
            break;
        }
    }
    CHECK(grafo_intacto, "cada hecho sigue apoyandose EN EL MISMO de antes");

    /* Y escribir dos veces lo mismo da los mismos bytes: sin esto no se pueden
     * comparar dos caches ni fiarse de que el fichero no cambia solo. */
    CHECK(serialize(a, 11, CacheLevel::All, {}) == bytes,
          "escribir es determinista");
}

// ===========================================================================
// 6. Ida y vuelta por disco de verdad
// ===========================================================================
static void probar_por_disco() {
    const std::vector<uint8_t> bytes = fichero_de_muestra();
    const std::string ruta = "asa_hechos_prueba.bin";
    CHECK(::fs::write_file_atomic(ruta, bytes), "se escribe el fichero");

    FactStore d;
    const ReadResult r = read_facts_file(ruta, 0x1234ull, d);
    CHECK(r.ok && d.size() == 24, "y se lee lo mismo que se escribio");

    FactStore d2;
    const ReadResult r2 = read_facts_file(ruta, 0x9999ull, d2);
    CHECK(!r2.ok && r2.reason == ReadReason::OtherModule,
          "con otra huella no se lee");

    FactStore d3;
    const ReadResult r3 = read_facts_file("no_existe_este_fichero.bin", 1, d3);
    CHECK(!r3.ok && r3.reason == ReadReason::NoFile,
          "y no haber fichero se distingue de que este roto");
    std::remove(ruta.c_str());
}

// ===========================================================================
// 7. LA ANULACION: cuando invalida, cuanto invalida, y que sobrevive
// ===========================================================================

/// Un almacen con los dominios de @p doms, @p por_dominio hechos cada uno, y
/// una cadena de apoyos que CRUZA de un dominio al siguiente -- que es lo que
/// permite ver que se pierde cuando uno cae.
static std::vector<uint8_t> con_dominios(const std::vector<const char *> &doms,
                                         uint32_t por_dominio,
                                         const std::vector<uint64_t> &huellas,
                                         FactStore &a) {
    FactId anterior = kNoFact;
    for (const char *dom : doms) {
        for (uint32_t i = 0; i < por_dominio; ++i) {
            Fact f;
            f.what.domain = dom;
            f.what.code = "c";
            f.what.a = static_cast<int64_t>(i);
            f.about.kind = Subject::Kind::Function;
            f.about.function = a.intern("f");
            f.seal.certainty = Certainty::Proven;
            if (anterior != kNoFact) f.proof.from.push_back(anterior);
            anterior = a.add(std::move(f));
        }
    }
    std::vector<DomainCost> costes;
    for (size_t i = 0; i < doms.size(); ++i)
        costes.push_back({doms[i], 0, true, huellas[i]});
    return serialize(a, 0x5150ull, CacheLevel::All, costes);
}

static void probar_anulacion() {
    const std::vector<const char *> doms = {"asa.structure", "asa.ranges",
                                            "asa.memory", "asa.loops"};
    const std::vector<uint64_t> originales = {11, 22, 33, 44};
    FactStore origen;
    const std::vector<uint8_t> bytes =
        con_dominios(doms, 5, originales, origen);

    std::vector<DomainCost> igual;
    for (size_t i = 0; i < doms.size(); ++i)
        igual.push_back({doms[i], 0, true, originales[i]});

    /* (a) Si no cambia nada, no se anula nada.  Esta es la comprobacion que
     * caza el fallo silencioso de invalidar siempre: una cache que se tira
     * sola pasa todos los tests de correccion y no sirve para nada. */
    {
        FactStore d;
        const ReadResult r =
            read_facts(bytes.data(), bytes.size(), 0x5150ull, d, igual);
        CHECK(r.ok && r.stale == 0 && r.facts == 20,
              "si no cambia nada, no se anula nada");
        CHECK(r.lost_proofs == 0, "y no se pierde ningun apoyo");
    }

    /* (b) Cambia UNO: cae UNO.  Y se mide CUANTO cuesta: los cinco hechos de
     * ese dominio, ni uno mas.  "Invalida poco" sin un numero no es nada. */
    {
        std::vector<DomainCost> v = igual;
        v[1].fingerprint = 0xDEADull;
        FactStore d;
        const ReadResult r =
            read_facts(bytes.data(), bytes.size(), 0x5150ull, d, v);
        CHECK(r.stale == 1, "cae exactamente un registro");
        CHECK(r.facts == 15, "y exactamente los cinco hechos que eran suyos");
        CHECK(r.domains == 3, "los otros tres dominios se leen enteros");
        /* El apoyo que cruzaba al dominio caido se PIERDE y se cuenta: una
         * derivacion mas corta es aceptable, una que apunta a un hecho que no
         * existe no lo es. */
        CHECK(r.lost_proofs == 1,
              "se cuenta el apoyo que se quedo sin destino");
        bool sanos = true;
        for (FactId i = 0; i < d.size(); ++i)
            for (FactId pr : d.at(i).proof.from)
                if (pr >= d.size()) sanos = false;
        CHECK(sanos, "y ningun apoyo apunta fuera del almacen");
    }

    /* (c) Cambian todos: cae todo, pero el fichero SIGUE siendo legible.  No
     * quedarse con nada valido no es lo mismo que estar roto. */
    {
        std::vector<DomainCost> v = igual;
        for (size_t i = 0; i < v.size(); ++i)
            v[i].fingerprint = 0x9000ull + i;
        FactStore d;
        const ReadResult r =
            read_facts(bytes.data(), bytes.size(), 0x5150ull, d, v);
        CHECK(r.ok, "quedarse sin nada valido no es un fichero roto");
        CHECK(r.stale == 4 && r.facts == 0, "caen los cuatro registros");
    }

    /* (d) Cambia el MODULO: no se lee nada, y por OTRO motivo.  La huella del
     * modulo y la del dominio contestan preguntas distintas, y confundirlas
     * seria no poder distinguir "esto es de otro programa" de "esto envejecio".
     */
    {
        FactStore d;
        const ReadResult r =
            read_facts(bytes.data(), bytes.size(), 0x5151ull, d);
        CHECK(!r.ok && r.reason == ReadReason::OtherModule && d.size() == 0,
              "otro modulo no se lee, y se distingue de un dominio caducado");
    }

    /* (e) De lo que no se dice nada, no se anula nada.  Es la diferencia entre
     * "se que cambio" y "no lo se". */
    {
        std::vector<DomainCost> v = {{doms[0], 0, true, 0xBEEFull}};
        FactStore d;
        const ReadResult r =
            read_facts(bytes.data(), bytes.size(), 0x5150ull, d, v);
        CHECK(r.stale == 1 && r.facts == 15,
              "solo se anula aquello de lo que se dijo algo");
    }

    /* (f) Hablar de un dominio que no esta en el fichero no molesta. */
    {
        std::vector<DomainCost> v = igual;
        v.push_back({"asa.no.existe", 0, true, 1});
        FactStore d;
        const ReadResult r =
            read_facts(bytes.data(), bytes.size(), 0x5150ull, d, v);
        CHECK(r.ok && r.stale == 0 && r.facts == 20,
              "hablar de un dominio que no esta no anula nada");
    }

    /* (g) Una huella a cero -- de un lado o del otro -- no anula: significa
     * "no se de que depende esto", y eso no es lo mismo que "cambio". */
    {
        std::vector<DomainCost> escritos;
        for (size_t i = 0; i < doms.size(); ++i)
            escritos.push_back({doms[i], 0, true, 0});
        const std::vector<uint8_t> sin_huella =
            serialize(origen, 0x5150ull, CacheLevel::All, escritos);
        FactStore d;
        const ReadResult r = read_facts(sin_huella.data(), sin_huella.size(),
                                        0x5150ull, d, igual);
        CHECK(r.ok && r.stale == 0,
              "sin huella guardada no hay nada que comparar");

        std::vector<DomainCost> v = igual;
        for (size_t i = 0; i < v.size(); ++i)
            v[i].fingerprint = 0;
        FactStore d2;
        const ReadResult r2 =
            read_facts(bytes.data(), bytes.size(), 0x5150ull, d2, v);
        CHECK(r2.ok && r2.stale == 0, "ni sin huella vigente tampoco");
    }

    /* (h) EL NIVEL NO ANULA.  Se escribe con uno y se lee con otro: el nivel
     * decide cuanto se PRODUCE, no que valga lo ya escrito.  Si entrara en la
     * identidad, cambiar de nivel tiraria caches buenas. */
    {
        std::vector<DomainCost> costes;
        for (size_t i = 0; i < doms.size(); ++i)
            costes.push_back({doms[i], 0, false, originales[i]});
        const std::vector<uint8_t> b_min =
            serialize(origen, 0x5150ull, CacheLevel::Minimum, costes);
        FactStore d;
        const ReadResult r =
            read_facts(b_min.data(), b_min.size(), 0x5150ull, d, igual);
        CHECK(r.ok && r.stale == 0,
              "lo escrito con un nivel se lee con cualquier otro");
    }

    /* (i) Cambiar la version del CONTENEDOR tira el fichero entero; la del
     * HECHO solo salta sus registros.  Son dos alcances distintos, y esa
     * diferencia es toda la razon de que la version este en dos sitios. */
    {
        std::vector<uint8_t> malo = bytes;
        malo[4] = static_cast<uint8_t>(kContainerVersion + 7);
        FactStore d;
        const ReadResult r = read_facts(malo.data(), malo.size(), 0x5150ull, d);
        CHECK(!r.ok && r.reason == ReadReason::OtherVersion,
              "otra version del contenedor descarta el fichero entero");
    }
}

/// Cambiar de compilador invalida: los hechos son conclusiones del analisis, y
/// otro analisis puede concluir otra cosa del mismo programa.
static void probar_version_del_compilador() {
    FactStore a;
    const std::vector<uint8_t> bytes = con_dominios({"asa.ranges"}, 4, {5}, a);
    const std::vector<uint8_t> con_v =
        serialize(a, 0x5150ull, CacheLevel::All, {}, 0xC0FFEEull);

    FactStore d;
    const ReadResult r =
        read_facts(con_v.data(), con_v.size(), 0x5150ull, d, {}, 0xC0FFEEull);
    CHECK(r.ok && r.facts == 4, "el mismo compilador lee lo suyo");

    FactStore d2;
    const ReadResult r2 =
        read_facts(con_v.data(), con_v.size(), 0x5150ull, d2, {}, 0xB00Bull);
    CHECK(!r2.ok && r2.reason == ReadReason::OtherCompiler,
          "otro compilador no se cree las conclusiones del anterior");
    CHECK(d2.size() == 0, "y no deposita nada");
    /* Y se distingue de "otro modulo": son dos cosas que se arreglan de forma
     * distinta, asi que contarlas igual seria perder la unica pista util. */
    FactStore d3;
    const ReadResult r3 =
        read_facts(con_v.data(), con_v.size(), 0x9999ull, d3, {}, 0xC0FFEEull);
    CHECK(r3.reason == ReadReason::OtherModule,
          "otro modulo se cuenta distinto que otro compilador");
    (void)bytes;
}

// ===========================================================================
// 8. Anular no puede depender de en que orden se pregunte
// ===========================================================================
static void probar_anulacion_estable() {
    const std::vector<const char *> doms = {"asa.structure", "asa.ranges",
                                            "asa.memory"};
    const std::vector<uint64_t> hu = {7, 8, 9};
    FactStore origen;
    const std::vector<uint8_t> bytes = con_dominios(doms, 3, hu, origen);

    std::vector<DomainCost> v1 = {
        {doms[0], 0, true, 7}, {doms[1], 0, true, 0xFF}, {doms[2], 0, true, 9}};
    std::vector<DomainCost> v2 = {
        {doms[2], 0, true, 9}, {doms[1], 0, true, 0xFF}, {doms[0], 0, true, 7}};
    FactStore d1, d2;
    const ReadResult r1 =
        read_facts(bytes.data(), bytes.size(), 0x5150ull, d1, v1);
    const ReadResult r2 =
        read_facts(bytes.data(), bytes.size(), 0x5150ull, d2, v2);
    CHECK(r1.stale == r2.stale && r1.facts == r2.facts,
          "el resultado no depende del orden en que se pregunte");
    CHECK(d1.size() == d2.size(), "ni lo que queda depositado");
}

int main() {
    std::printf("=== ASA: el fichero de hechos como entrada hostil ===\n");
    probar_truncado_exhaustivo();
    probar_corrupcion_exhaustiva();
    probar_cuentas_absurdas();
    probar_ciclos();
    probar_volumen();
    probar_anulacion();
    probar_version_del_compilador();
    probar_anulacion_estable();
    probar_por_disco();
    std::printf("%d comprobaciones, %d fallos\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
